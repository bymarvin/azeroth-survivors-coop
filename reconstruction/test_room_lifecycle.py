"""Directory membership and local shutdown races, without launching the game."""
import tempfile
from pathlib import Path
import os
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from lobby_server import server
from room_client import RoomClient


class RoomLifecycleTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop('COOP_EXECUTABLE', None)
        profile = self.enterContext(tempfile.TemporaryDirectory())
        self.app = server(('127.0.0.1', 0))
        self.thread = threading.Thread(target=self.app.serve_forever, daemon=True)
        self.thread.start()
        self.client = RoomClient(f'http://127.0.0.1:{self.app.server_port}', profile_folder=profile)
        self.host = self.app.rooms.create('Party', 'Host', False, self.client.build)
        self.room_id = self.host['room']['id']

    def tearDown(self):
        self.app.shutdown()
        self.thread.join(3)
        self.app.server_close()

    def start(self):
        room = self.app.rooms.poll(self.room_id, self.host['token'])
        return self.app.rooms.action(self.room_id, self.host['token'], 'start', room['revision'])

    def test_stale_guest_leave_preserves_playing_slots_and_rejects_rejoin(self):
        guests = [self.app.rooms.join(self.room_id, f'Guest {n}', self.client.build) for n in range(3)]
        self.start()
        for guest in guests[:2]:
            self.app.rooms.action(self.room_id, guest['token'], 'leave', 0)
        room = self.app.rooms.poll(self.room_id, guests[2]['token'])
        self.assertEqual(room['phase'], 'playing')
        self.assertEqual([p['slot'] for p in room['players']], [1, 4])
        with self.assertRaises(ValueError):
            self.app.rooms.join(self.room_id, 'Replacement', self.client.build)
        with self.assertRaises(ValueError):
            self.app.rooms.action(self.room_id, 'invalid', 'leave', 0)

    def test_host_departure_stops_guest_without_failure(self):
        self.client.join('Guest', self.room_id)
        self.start()
        self.app.rooms.action(self.room_id, self.host['token'], 'leave', 0)
        self.assertFalse(self.client.poll_room())
        self.assertTrue(self.client.cancel.is_set())
        self.assertIsNone(self.client.room)
        self.assertIsNone(self.client.membership)
        self.assertIsNone(self.client.error)
        self.assertEqual(self.client.status, 'The host ended the room.')

    def test_lost_room_listing_keeps_running_game(self):
        # Live 15.10.2026: the listing vanished and both running games were closed.
        self.client.join('Guest', self.room_id)
        self.start()
        routes = Mock()
        self.client.routes, self.client.bridge = routes, SimpleNamespace()
        self.app.rooms.action(self.room_id, self.host['token'], 'leave', 0)
        self.assertFalse(self.client.poll_room())
        self.assertFalse(self.client.cancel.is_set())
        self.assertTrue(self.client.room_detached)
        self.assertIsNotNone(self.client.membership)
        routes.close.assert_not_called()  # The game channels stay open.
        self.assertIsNone(self.client.error)
        self.assertIn('continues', self.client.status)
        self.client.bridge = None  # Game over: normal cleanup closes the routes.
        self.client.leave_membership(self.room_id, 'The game session ended.')
        routes.close.assert_called_once()
        self.assertIsNone(self.client.membership)

    def test_detached_victory_choice_uses_game_channel_and_events_never_raise(self):
        self.client.join('Guest', self.room_id)
        self.start()
        self.client.routes, self.client.bridge = Mock(), SimpleNamespace()
        self.app.rooms.action(self.room_id, self.host['token'], 'leave', 0)
        self.assertFalse(self.client.poll_room())
        self.assertTrue(self.client.room_detached)
        # The listing is deleted: the choice must not need /action.
        self.client.action('keep_fighting')
        self.client.action('new_hero')
        self.assertEqual([self.client.commands.get_nowait() for _ in range(2)], [8, 9])
        self.assertIn('Victory choices still work', self.client.status)
        # Game-thread bookkeeping events are skipped once detached, never queued.
        for _ in range(100):
            self.client.game_event('victory')
        self.assertTrue(self.client.events.empty())
        # Attached: a full queue drops instead of raising on the game thread.
        self.client.room_detached = False
        for _ in range(100):
            self.client.game_event(8)
        self.assertEqual(self.client.events.qsize(), 32)
        self.assertEqual(self.client.dropped_events, 68)
        for _ in range(32):
            self.client.commands.put_nowait('stop')
        with self.assertRaisesRegex(ValueError, 'busy'):
            self.client.queue_game_command(8)
        self.client.room_detached = True
        self.client.bridge = None
        with self.assertRaisesRegex(ValueError, 'already ended'):
            self.client.action('keep_fighting')

    def test_victory_revision_race_retries_without_cancelling_host(self):
        guest = self.app.rooms.join(self.room_id, 'Guest', self.client.build)
        self.client.membership = self.host
        self.client.room = self.start()
        self.client.launched = True
        self.client.events.put('victory')
        request = self.client.request
        raced = False

        def racing_request(path, data=None, authenticated=False):
            nonlocal raced
            if path == '/action' and data['action'] == 'victory' and not raced:
                raced = True
                self.app.rooms.action(self.room_id, guest['token'], 'leave', 0)
            return request(path, data, authenticated)

        with patch.object(self.client, 'request', side_effect=racing_request), patch.object(
                self.client.stopped, 'wait', side_effect=[False, False, True]):
            self.client.heartbeat()
        self.assertTrue(raced)
        self.assertEqual(self.client.room['phase'], 'victory')
        self.assertFalse(self.client.cancel.is_set())
        self.assertTrue(self.client.events.empty())
        self.assertIsNone(self.client.error)

    def test_cleanup_does_not_clear_new_membership_and_preserves_save_errors(self):
        self.client.join('Guest', self.room_id)
        self.client.leave_membership('old-room', 'Old game ended')
        self.assertIsNotNone(self.client.membership)
        self.client.error = 'Save conflict; original preserved'
        with patch.object(self.client, 'request', side_effect=OSError('offline')):
            self.client.leave_membership(self.room_id, 'Game ended')
        self.assertIsNone(self.client.membership)
        self.assertIn('Save conflict', self.client.error)
        self.assertIn('expire automatically', self.client.error)

    def test_native_exit_commits_save_then_removes_membership(self):
        self.client.membership = self.host
        room = self.start()
        room['connection'] = dict(port=1)
        self.client.room = room
        order = []
        save = SimpleNamespace(folder='disposable', commit=lambda: order.append('commit'),
                               close=lambda: order.append('close'))

        class Bridge:
            def __init__(self, output):
                self.counts = {}
            def record(self, **event):
                pass

        def run(*args, **kwargs):
            order.append('native_exit')

        modules = dict(group_online=SimpleNamespace(GroupOnlineBridge=Bridge),
                       native_guest_combat=SimpleNamespace(NativeCombatBridge=Bridge),
                       party_menu=SimpleNamespace(PartyMenu=type('PartyMenu', (), {})),
                       native_probe=SimpleNamespace(ACTIVE_HASH=self.client.build, run=run),
                       personal_save=SimpleNamespace(PersonalSave=lambda path: save))
        with patch.dict(os.environ, {}, clear=True), patch.dict('sys.modules', modules), patch.object(self.client, 'check_compatibility',
                return_value={'sha256': self.client.build}):
            self.client.play(room)
        self.assertEqual(order, ['native_exit', 'commit', 'close'])
        self.assertIsNone(self.client.error)
        self.assertIsNone(self.client.membership)
        self.assertNotIn(self.room_id, self.app.rooms.rooms)

    def lost_link_session(self, after_run):
        """play() with a game whose host link failed; returns the report diagnostics (or None)."""
        self.client.membership = self.host
        room = self.start()
        room['connection'] = dict(port=1)
        self.client.room = room
        reports = []
        save = SimpleNamespace(folder='disposable', commit=lambda: None, close=lambda: None)

        class Bridge:
            def __init__(self, output):
                self.counts = {}
            def record(self, **event):
                pass
            def diagnostic_summary(self):
                return dict(states={})

        def run(seconds, players, bridge, **kwargs):
            bridge.connection_failure = ConnectionError('Co-op connection failed')
            bridge.connection_after_run = after_run

        def upload_report(directory, permit, log, gameplay, framework, private_values=(), diagnostics=None):
            reports.append(dict(log=Path(log), diagnostics=diagnostics))
            return 'Crash report saved locally; this lobby does not support uploads.'
        modules = dict(group_online=SimpleNamespace(GroupOnlineBridge=Bridge),
                       native_guest_combat=SimpleNamespace(NativeCombatBridge=Bridge),
                       party_menu=SimpleNamespace(PartyMenu=type('PartyMenu', (), {})),
                       native_probe=SimpleNamespace(ACTIVE_HASH=self.client.build, run=run),
                       personal_save=SimpleNamespace(PersonalSave=lambda path: save),
                       crash_reports=SimpleNamespace(upload_report=upload_report))
        with patch.dict(os.environ, {}, clear=True), patch.dict('sys.modules', modules), patch.object(
                self.client, 'check_compatibility', return_value={'sha256': self.client.build}):
            self.client.play(room)
        return reports

    def test_link_lost_after_the_run_is_reported_but_not_shown_as_an_error(self):
        reports = self.lost_link_session(after_run=True)
        self.assertIsNone(self.client.error)  # No error look: the room browser shows the status only.
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]['diagnostics'], dict(states={}, after_run=True))
        self.assertIn('lost after the finished run', reports[0]['log'].read_text(encoding='utf-8'))

    def test_link_lost_during_the_run_is_an_error_and_a_report(self):
        reports = self.lost_link_session(after_run=False)
        self.assertIn('Game session failed: Co-op host connection lost', self.client.error)
        self.assertEqual(reports[0]['diagnostics'], dict(states={}))

    def test_browser_shutdown_waits_for_worker_before_directory_cleanup(self):
        self.client.join('Guest', self.room_id)
        self.client.worker = Mock()
        self.client.worker.is_alive.return_value = True
        self.client.shutdown()
        self.client.worker.join.assert_called_once_with(15)
        self.assertTrue(self.client.cancel.is_set())
        self.assertTrue(self.client.stopped.is_set())
        self.assertIsNone(self.client.membership)
        self.assertEqual(len(self.app.rooms.poll(self.room_id, self.host['token'])['players']), 1)

    def test_update_check_reports_failure_before_native_launch(self):
        states = []
        def resolve(binary, **kwargs):
            for stage in ('checking', 'discovering', 'failure'):
                kwargs['progress'](stage, '')
                states.append(self.client.status)
            raise ValueError('Unresolved game-state owner')
        with patch.dict(os.environ, {}, clear=True), patch('build_hooks.resolve_reviewed_profile', side_effect=resolve):
            with self.assertRaisesRegex(ValueError, 'Unresolved game-state owner'):
                self.client.check_compatibility()
        self.assertIn('Update detected', states[1])
        self.assertIn('stopped', states[-1])
        self.assertFalse(any('ready' in state for state in states))

    def test_update_after_join_rejects_mixed_build_room_before_resolution(self):
        self.client.build = '0' * 64
        with patch.dict(os.environ, {}, clear=True), patch('build_hooks.resolve_reviewed_profile') as resolve:
            with self.assertRaisesRegex(ValueError, 'changed after joining'):
                self.client.check_compatibility()
            resolve.assert_not_called()


if __name__ == '__main__':
    unittest.main()
