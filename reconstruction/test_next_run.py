"""'Next run' without a new lobby phase (0.0.16): the host opens the following room and invites the party over the
pinned game channels; guests join it after their game closed, only if it is their host's room (same fingerprint).

Offline: the unchanged local directory (lobby_server over loopback HTTP), real RoomClients without game or routes.
"""
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import room_client
from group_online import GroupOnlineBridge
from room_client import RoomClient, next_run_closing

FINGERPRINT = 'ab' * 32


class Bridge(SimpleNamespace):
    """The parts of GroupOnlineBridge the launcher uses between runs."""

    def __init__(self, number, members=(1, 2, 3, 4), over=True):
        super().__init__(number=number, members=list(members), departed=set(), events=[], over=over,
                         next_run_offer=None, next_run_acks=set(), next_run_received=None, ready=set(), menu_players=set())

    def record(self, **event):
        self.events.append(event)

    def run_over(self):
        return self.over

    def offer_next_run(self, room, invite):
        GroupOnlineBridge.offer_next_run(self, room, invite)

    def next_run_offered(self, offer):
        self.offered = offer

    def receive(self, peer, message):
        GroupOnlineBridge.receive_next_run(self, peer, message)


class NextRunTests(unittest.TestCase):
    def setUp(self):
        from lobby_server import server
        self.app = server(('127.0.0.1', 0))
        threading.Thread(target=self.app.serve_forever, daemon=True).start()
        self.addCleanup(self.app.server_close)
        self.addCleanup(self.app.shutdown)
        self.url = f'http://127.0.0.1:{self.app.server_port}'
        for target in (patch.object(RoomClient, 'start_routes', lambda self: None),
                       patch.object(RoomClient, 'release_mapping', lambda self: None)):
            target.start()
            self.addCleanup(target.stop)
        self.folder = Path(tempfile.mkdtemp(prefix='next-run '))

    def client(self, name):
        return RoomClient(self.url, profile_folder=self.folder / name)

    def party(self, guests=3, private=False):
        """A started room: host + guests, connection published, the run just ended (bridges in the menu)."""
        host = self.client('host')
        host.membership = host.request('/create', dict(name='Friday raid', player='Host', private=private,
                                                       build=host.build, region='eu', version='0.95.0'))
        host.room = host.membership['room']
        host.room = host.request('/connection', dict(room=host.room['id'], address='127.0.0.1', port=47999,
                                                     fingerprint=FINGERPRINT), True)
        members = []
        for n in range(guests):
            guest = self.client(f'guest-{n}')
            guest.join(f'Guest {n + 2}', host.room['id'], code=f'{host.room["id"]}:{host.room["invite"]}' if private else None,
                       region='eu')
            members.append(guest)
        host.room = host.request('/action', dict(room=host.room['id'], action='start', revision=host.request(
            '/poll', dict(room=host.room['id']), True)['revision'], build=host.build), True)
        for guest in members:
            guest.room = guest.request('/poll', dict(room=guest.room['id']), True)
        host.bridge = Bridge(1, range(1, guests + 2))
        return host, members

    def invite(self, host, guests):
        """The bridges carry the offer: host decorate -> guest receive_peer (peer 1) -> launcher."""
        offer = host.bridge.next_run_offer
        for guest in guests:
            bridge = Bridge(guest.room['slot'])
            bridge.next_run_offered = lambda offer, guest=guest: guest.invited(offer, guest.room)
            bridge.receive(1, dict(next_run=offer))
            host.bridge.receive(guest.room['slot'], dict(next_run_seen=bridge.next_run_received['room']))
        return offer

    def close_games(self, host, guests, rejoin=None):
        """Every game closed: launcher cleanup as at the end of play(), then the guests' heartbeat joins."""
        old = host.room['id']
        self.assertTrue(next_run_closing(host.bridge, host.next_room, time.monotonic()))
        next_room = host.next_room
        host.leave_membership(old, 'closed', keep_mapping=True)
        host.switch_to_next_room(next_room)
        for guest in guests if rejoin is None else rejoin:
            guest.leave_membership(old, 'closed')
            if guest.next_invite:
                guest.join_next_run()

    def test_victory_next_run_rejoins_and_starts_with_the_same_host_connection(self):
        host, guests = self.party()
        old = dict(host.room)
        self.assertTrue(host.state()['next_run']['available'])
        host.action('next_run')
        self.assertTrue(host.state()['next_run']['preparing'])
        self.invite(host, guests)
        self.assertTrue(all(g.state()['next_run']['invited'] for g in guests))
        self.close_games(host, guests)
        room = host.room
        self.assertNotEqual(room['id'], old['id'])
        self.assertEqual((room['name'], room['region'], room['private'], room['connection']['fingerprint'],
                          room['connection']['port']), ('Friday raid', 'eu', True, FINGERPRINT, 47999))
        self.assertTrue(all(g.room['id'] == room['id'] for g in guests))
        host.room = host.request('/poll', dict(room=room['id']), True)
        host.next_run_due()
        self.assertEqual((host.room['phase'], len(host.room['players'])), ('playing', 4))
        self.assertEqual(host.status, 'Next run started.')
        with self.assertRaises(Exception):  # The old room is gone.
            guests[0].request('/poll', dict(room=old['id']), token='x')

    def test_invitation_only_from_the_host_and_only_its_room(self):
        bridge = Bridge(2)
        bridge.receive(3, dict(next_run=dict(room='a' * 24, invite='b' * 24)))  # From another guest: ignored.
        self.assertEqual(bridge.events[-1], dict(event='next_run_rejected', player=2, sender=3))
        for bad in (dict(room='a' * 24), dict(room='../x', invite='b' * 24), dict(room='a' * 24, invite='b c'),
                    dict(room='a' * 24, invite='b' * 24, extra=1), 'room:invite'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                bridge.receive(1, dict(next_run=bad))
        self.assertIsNone(bridge.next_run_received)
        host = Bridge(1)
        host.receive(2, dict(next_run_seen='a' * 24))
        self.assertFalse(host.next_run_acks)  # No offer yet: a stray confirmation counts for nothing.
        # A room that does not carry the host's connection fingerprint is left again.
        host_client, guests = self.party(guests=1)
        other = host_client.request('/create', dict(name='Other', player='Stranger', private=True,
                                                    build=host_client.build, region='eu', version='0.95.0'))
        host_client.request('/connection', dict(room=other['room']['id'], address='127.0.0.1', port=48000,
                                                fingerprint='cd' * 32), token=other['token'])
        guest = guests[0]
        guest.invited(dict(room=other['room']['id'], invite=other['room']['invite']), guest.room)
        guest.leave_membership(guest.room['id'], 'closed')
        guest.join_next_run()
        self.assertIsNone(guest.room)
        self.assertIn("did not lead to your host's room", guest.error)

    def test_guest_who_leaves_between_runs_stays_out(self):
        host, guests = self.party()
        host.action('next_run')
        self.invite(host, guests)
        guests[2].action('leave')
        self.assertIsNone(guests[2].next_invite)
        host.bridge.departed.add(4)
        self.close_games(host, guests[:2])
        self.assertEqual(host.next_room['expected'], [2, 3])
        host.room = host.request('/poll', dict(room=host.room['id']), True)
        host.next_run_due()
        self.assertEqual((host.room['phase'], len(host.room['players'])), ('playing', 3))

    def test_host_who_leaves_between_runs_closes_both_rooms(self):
        host, guests = self.party()
        host.action('next_run')
        offer = self.invite(host, guests)
        host.action('leave')
        self.assertIsNone(host.next_room)
        guest = guests[0]
        guest.leave_membership(guest.room['id'], 'closed')
        guest.join_next_run()
        self.assertIsNone(guest.room)
        self.assertTrue(guest.error.startswith('Next run:'), guest.error)
        self.assertEqual(guest.status, 'Could not join the next run. Choose a room or host your own.')
        self.assertNotIn(offer['room'], {r['id'] for r in host.request('/rooms')['rooms']})

    def test_hung_guest_is_not_waited_for_beyond_the_limit(self):
        host, guests = self.party()
        host.action('next_run')
        self.invite(host, guests)
        self.close_games(host, guests, rejoin=guests[:2])  # Guest 4's game hangs and never closes.
        host.room = host.request('/poll', dict(room=host.room['id']), True)
        host.next_run_due()
        self.assertEqual(host.room['phase'], 'lobby')  # Still waiting.
        host.next_room['since'] -= room_client.NEXT_RUN_WAIT + 1
        host.next_run_due()
        self.assertEqual((host.room['phase'], len(host.room['players'])), ('playing', 3))
        self.assertEqual(host.status, 'Next run started without 1 player who did not rejoin in time.')

    def test_nobody_back_in_time_does_not_start_alone(self):
        host, guests = self.party(guests=2)
        host.action('next_run')
        self.invite(host, guests)
        self.close_games(host, guests, rejoin=[])
        host.next_room['since'] -= room_client.NEXT_RUN_WAIT + 1
        host.room = host.request('/poll', dict(room=host.room['id']), True)
        host.next_run_due()
        self.assertEqual(host.room['phase'], 'lobby')
        self.assertTrue(host.status.startswith('Nobody rejoined in time.'))

    def test_old_launcher_without_confirmation_is_not_waited_for(self):
        host, guests = self.party(guests=2)
        host.action('next_run')
        self.invite(host, guests[:1])                       # Guest 3 runs 0.0.15: it ignores next_run.
        self.assertFalse(next_run_closing(host.bridge, host.next_room, time.monotonic()))
        host.next_room['offered'] -= room_client.NEXT_RUN_CONFIRM + 1
        self.assertTrue(next_run_closing(host.bridge, host.next_room, time.monotonic()))
        self.assertEqual(host.next_room['expected'], [2])
        self.assertEqual(host.bridge.events[-1]['missing'], [3])

    def test_next_run_only_for_the_host_after_the_run(self):
        host, guests = self.party(guests=1)
        host.bridge.over = False
        self.assertFalse(host.state()['next_run']['available'])
        with self.assertRaises(ValueError):
            host.action('next_run')
        guests[0].bridge = Bridge(2)
        with self.assertRaises(ValueError):
            guests[0].action('next_run')
        host.bridge.over = True
        host.action('next_run')
        with self.assertRaises(ValueError):
            host.action('next_run')                          # Only once.

    def test_prepared_room_is_kept_alive_while_the_old_game_closes(self):
        host, _ = self.party(guests=1)
        host.action('next_run')
        room = host.next_room['membership']['room']['id']
        with patch.object(host, 'request', wraps=host.request) as request:
            host.next_run_due()
            host.next_run_due()                              # Polled at most every 10 s.
        self.assertEqual([c.args[0] for c in request.call_args_list], ['/poll'])
        self.assertEqual(request.call_args_list[0].args[1], dict(room=room))


class AcceptanceVerifyTests(unittest.TestCase):
    """verify_next_run.verify on synthetic launcher logs: what the four-client case requires."""

    def logs(self, defeat=False):
        first, second = [], []
        for n in range(1, 5):
            run1 = [dict(event='team_defeat_shown', player=n)] if defeat else [
                dict(event='network_boss_result', player=n, class_id=1),
                dict(event='victory_action_applied', player=n, command=9)]
            if n == 1:
                run1 += [dict(event='next_run_offered', room='r2'), dict(event='next_run_closing', confirmed=[2, 3, 4])]
            else:
                run1.append(dict(event='next_run_invited', player=n, room='r2'))
            zone = 'elwynn' if defeat else 'duskwood'
            second.append([dict(event='native_progression_baseline', player=n, run=2, classes={'1': 1 if defeat else 2}),
                           dict(event='party_map_loaded', player=n, zone=zone),
                           dict(event='network_boss_result', player=n, class_id=1),
                           dict(event='summary', world_captured=30 if n == 1 else 0, world_delivered=30 if n == 1 else 10)])
            first.append(run1)
        return first, second

    def check(self, first, second, defeat=False, results=None):
        import native_probe
        import verify_next_run
        results = results or [dict(passed=True, rooms=['r1', 'r2'], slot=n) for n in range(1, 5)]
        home = Path(tempfile.mkdtemp(prefix='next-run-verify '))
        for n in range(1, 5):
            (home / f'player-{n}').mkdir()

        def staging(command, stdout, **kwargs):
            stdout.write(json.dumps(dict(event='disposable_staging_complete', native_unlock_reload_verified=True,
                                         expected_unlock_verified=True, newly_awarded_progression_verified=True)) + '\n')
            self.assertEqual(command[-2:], ['1', '2' if defeat else '3'])  # The next map of run 2.
        with patch.object(verify_next_run, 'rows', lambda n, run: (first, second)[run][n - 1]), \
                patch.object(native_probe, '_candidate_home', home), patch('subprocess.run', side_effect=staging):
            return verify_next_run.verify(defeat, results)

    def test_both_variants_pass(self):
        self.assertEqual(self.check(*self.logs())['run2_zone'], 'duskwood')
        self.assertEqual(self.check(*self.logs(True), defeat=True)['variant'], 'team_defeat')

    def test_failures_are_detected(self):
        for change in ('missing_guest', 'other_map', 'no_unlock_from_run_1', 'not_won', 'other_slots', 'same_room'):
            first, second = self.logs()
            results = None
            if change == 'missing_guest':
                first[0][-1]['confirmed'] = [2, 3]
            elif change == 'other_map':
                second[2][1]['zone'] = 'elwynn'
            elif change == 'no_unlock_from_run_1':
                second[1][0]['classes'] = {'1': 1}
            elif change == 'not_won':
                del second[3][2]
            elif change == 'other_slots':
                results = [dict(passed=True, rooms=['r1', 'r2'], slot=s) for s in (1, 3, 2, 4)]
            else:
                results = [dict(passed=True, rooms=['r1', 'r1'], slot=n) for n in range(1, 5)]
            with self.subTest(change=change), self.assertRaises((AssertionError, StopIteration)):
                self.check(first, second, results=results)


if __name__ == '__main__':
    unittest.main()
