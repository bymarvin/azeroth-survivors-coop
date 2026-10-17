"""Completion uploads keep the finished run immutable and separate from crashes."""
import contextlib
import http.client
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.request
from urllib.error import HTTPError
from unittest.mock import patch

from crash_reports import MAX_REPORT, upload_completed, upload_report
from lobby_server import server


class CompletedReportTests(unittest.TestCase):
    def test_launcher_captures_old_run_for_host_and_guest_before_live_state_changes(self):
        import native_probe
        from room_client import RoomClient
        from types import SimpleNamespace
        for slot, action in ((1, 9), (3, 6)):
            with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
                root = Path(directory)
                (root / 'AzerothSurvivors.exe').write_bytes(b'test')
                (root / 'COOP-VERSION.txt').write_text('0.0.10')
                (root / 'analysis').mkdir()
                with patch('room_client.ROOT', root):
                    client = RoomClient('https://example.test', isolated_profile=True, profile_folder=root / 'profile')
                room = dict(id='b'*24, run=7, slot=slot, build=client.build, version='0.84.3',
                            players=[1, 2, 3] if slot == 3 else [1], connection={'test': True},
                            crash_upload_permit='private-permit')
                client.room = room
                client.check_compatibility = lambda: {'sha256': client.build}
                client.poll_room = lambda: True
                client.leave_membership = lambda *args: None
                channel = SimpleNamespace(closed=False, check=lambda: None, finish=lambda: None, close=lambda: None)
                client.routes = SimpleNamespace(prepare=lambda *args: {1: channel}) if slot == 3 else None
                def fake_run(seconds, count, bridge, **kwargs):
                    bridge.native_states = {n: (5, 10, 50, 0) for n in bridge.members}
                    bridge.host_clock = 300
                    bridge.completed_transition(slot, action)
                    bridge.native_states.clear()
                    bridge.host_clock = 0
                    room['run'] = 8
                    bridge.completed_transition(slot, action)
                contract = dict(native_probe.MENU_CONTRACT, sha256=client.build)
                workers = []
                original_upload = upload_completed
                def capture(*args, **kwargs):
                    worker = original_upload(*args, **kwargs); workers.append(worker); return worker
                with patch('room_client.ROOT', root), patch('native_probe.ACTIVE_HASH', client.build), \
                        patch('native_probe.MENU_CONTRACT', contract), patch('native_probe.run', side_effect=fake_run), \
                        patch('crash_reports.upload_completed', side_effect=capture), \
                        patch('crash_reports.send_report', side_effect=TimeoutError('offline')):
                    client.play(room)
                    for worker in workers:
                        worker.join(3)
                self.assertFalse(client.error, client.error)
                paths = list((root / 'profile/logs').glob('*.completed.json'))
                self.assertEqual(len(paths), 1)
                report = json.loads(paths[0].read_text())
                self.assertEqual((report['run'], report['slot'], report['duration_seconds']), (7, slot, 300))
                self.assertEqual(report['diagnostics']['states'][str(slot)][0], 5)

    def test_host_and_guests_both_actions_old_run_auth_dedup_and_crash_separation(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            app = server(('127.0.0.1', 0), collected_logs=root / 'collected')
            service = threading.Thread(target=app.serve_forever, daemon=True)
            service.start()
            url = f'http://127.0.0.1:{app.server_port}'
            def post(path, value, token=''):
                request = urllib.request.Request(url + path, json.dumps(value).encode(),
                    {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
                with urllib.request.urlopen(request, timeout=3) as response:
                    return json.load(response)
            try:
                host = post('/create', dict(name='room', player='Host', private=False, build='a'*64, version='0.84.3'))
                members = [host]
                for n in (2, 3):
                    members.append(post('/join', dict(room=host['room']['id'], player=f'Guest{n}', build='a'*64)))
                current = post('/poll', dict(room=host['room']['id']), host['token'])
                post('/action', dict(room=current['id'], revision=current['revision'], action='start'), host['token'])
                rooms = [post('/poll', dict(room=current['id']), m['token']) for m in members]
                # Advance live room state before upload: the permit must still
                # authorize the exact captured previous run, never the new run.
                app.rooms.rooms[current['id']]['run'] = 2
                for room, action in zip(rooms, ('again', 'new_hero', 'again')):
                    identifier = f"{room['id']}-1-{room['slot']}"
                    summary = dict(incoming_hits=[dict(queue='hits', high_water=127, applied=300)], token='private')
                    thread = upload_completed(url, room['crash_upload_permit'], room, action, 300,
                        '0.0.10', '{"event":"native_state","ticket":"private"}', summary, root / 'local', ['private'])
                    summary['incoming_hits'].clear()
                    room['run'] = 99
                    thread.join(3)
                    self.assertFalse(thread.is_alive())
                    target = root / 'collected/completed' / (identifier + '.json')
                    saved = target.read_bytes()
                    document = json.loads(saved)
                    self.assertEqual((document['run'], document['slot'], document['action'], document['outcome']),
                                     (1, room['slot'], action, 'completed'))
                    self.assertEqual(document['diagnostics']['incoming_hits'][0]['high_water'], 127)
                    self.assertEqual((document['version'], document['framework']), ('0.84.3', '0.0.10'))
                    self.assertNotIn('private', saved.decode())
                    self.assertNotIn(room['crash_upload_permit'], saved.decode())
                    body = json.loads((root / 'local' / (identifier + '.completed.json')).read_text())
                    post('/completed-report', body, room['crash_upload_permit'])
                    self.assertEqual(target.read_bytes(), saved)
                    changed = dict(body, action='new_hero' if action == 'again' else 'again')
                    post('/completed-report', changed, room['crash_upload_permit'])
                    self.assertEqual(target.read_bytes(), saved)
                    with self.assertRaises(HTTPError):
                        post('/completed-report', dict(body, run=99), room['crash_upload_permit'])
                    with self.assertRaises(HTTPError):
                        post('/completed-report', body)
                    log = root / f"crash-{room['slot']}.log"
                    log.write_text('a separate crash')
                    upload_report(url, room['crash_upload_permit'], log, None, '0.0.10')
                    self.assertIn('a separate crash', (root / 'collected' / (identifier + '.json')).read_text())
                    self.assertEqual(target.read_bytes(), saved)
                # Send only headers: rejection must precede reading an oversized
                # body, avoiding the client's expected broken-pipe write race.
                connection = http.client.HTTPConnection('127.0.0.1', app.server_port, timeout=3)
                try:
                    connection.putrequest('POST', '/completed-report')
                    connection.putheader('Content-Type', 'application/json')
                    connection.putheader('Authorization', 'Bearer ' + rooms[0]['crash_upload_permit'])
                    connection.putheader('Content-Length', str(MAX_REPORT + 1))
                    connection.endheaders()
                    response = connection.getresponse()
                    self.assertEqual(response.status, 400)
                    response.read()
                finally:
                    connection.close()
            finally:
                app.shutdown(); service.join(3); app.server_close()

    def test_async_failure_keeps_exact_local_snapshot_and_retry_reuses_it(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            room = dict(id='a'*24, run=7, slot=3, build='a'*64, version='0.84.3')
            entered, release = threading.Event(), threading.Event()
            def blocked(*args, **kwargs):
                entered.set(); release.wait(3); raise TimeoutError('offline')
            with patch('crash_reports.urllib.request.urlopen', side_effect=blocked):
                started = time.monotonic()
                worker = upload_completed('https://example.test', 'permit', room, 'again', 200,
                    '0.0.10', 'finished', {'old_run': 7}, directory)
                self.assertLess(time.monotonic() - started, .5)
                self.assertTrue(entered.wait(1))
                path = Path(directory) / ('a'*24 + '-7-3.completed.json')
                saved = path.read_bytes()
                room['run'] = 8
                release.set(); worker.join(3)
                self.assertEqual(path.read_bytes(), saved)
            room['run'] = 7
            with patch('crash_reports.send_report', return_value='a'*24 + '-7-3') as send:
                worker = upload_completed('https://example.test', 'permit', room, 'new_hero', 0,
                    'changed', 'new state', {}, directory)
                worker.join(3)
                self.assertEqual(send.call_args.args[2], saved)


if __name__ == '__main__':
    unittest.main()
