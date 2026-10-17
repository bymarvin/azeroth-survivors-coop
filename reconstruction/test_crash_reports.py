"""Real HTTP crash upload, bounded storage, redaction and launcher fallback."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.request
from urllib.error import HTTPError
from unittest.mock import patch

from crash_reports import MAX_REPORT, TAIL_BYTES, scrub, upload_report
from lobby_server import server
from room_client import RoomClient


class CrashReportTests(unittest.TestCase):
    def test_scrub_preserves_diagnostics_with_short_names_and_escaped_paths(self):
        row = dict(event='shutdown_drain_finished', name='a', character_name='1', ready=False,
                   path=r'C:\Users\Private User\Game\log.jsonl', ticket='secret')
        cleaned = json.loads(scrub(json.dumps(row)))
        self.assertEqual(cleaned['event'], row['event'])
        self.assertFalse(cleaned['ready'])
        self.assertEqual(cleaned['name'], '[redacted]')
        self.assertEqual(cleaned['character_name'], '[redacted]')
        self.assertNotIn('Private User', cleaned['path'])
        self.assertNotIn('secret', cleaned['ticket'])

    def test_http_upload_after_room_closes_is_private_bounded_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = server(('127.0.0.1', 0), collected_logs=root / 'collected-logs')
            worker = threading.Thread(target=app.serve_forever, daemon=True)
            worker.start()
            url = f'http://127.0.0.1:{app.server_port}'

            def post(path, value, token=''):
                request = urllib.request.Request(url + path, json.dumps(value).encode(),
                    {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
                with urllib.request.urlopen(request, timeout=3) as response:
                    return json.load(response)

            try:
                host = post('/create', dict(name='Private room', player='Host', private=True, build='a'*64))
                room = host['room']
                permit = room['crash_upload_permit']
                self.assertNotIn('crash_upload_permit', app.rooms.view(app.rooms.rooms[room['id']]))
                post('/action', dict(room=room['id'], action='leave', revision=room['revision']), host['token'])
                log = root / 'crash.log'
                log.write_text('File "C:\\Users\\UwU\\Game\\native_probe.py"\nBearer secret-token\nTimeoutError')
                gameplay = root / 'gameplay.jsonl'
                gameplay.write_text('x' * (TAIL_BYTES + 10) + '\n{"event":"shutdown_drain_finished","ready":false,"ticket":"private-ticket"}')
                result = upload_report(url, permit, log, gameplay, '1.0.0', ['secret-token'])
                identifier = room['id'] + '-0-1'
                self.assertIn(identifier, result)
                target = root / 'collected-logs' / (identifier + '.json')
                saved = target.read_text()
                document = json.loads(saved)
                self.assertEqual(document['slot'], 1)
                self.assertTrue(document['gameplay_truncated'])
                self.assertIn('shutdown_drain_finished', document['gameplay'])
                for secret in ('UwU', 'secret-token', 'private-ticket', host['token'], permit):
                    self.assertNotIn(secret, saved)
                self.assertTrue(log.with_suffix('.report.json').exists())
                log.write_text('different')
                upload_report(url, permit, log, gameplay, '1.0.0')
                self.assertEqual(target.read_text(), saved)
                for token in ('', permit + '0'):
                    with self.assertRaises(HTTPError) as failure:
                        post('/crash-report', {}, token)
                    self.assertEqual(failure.exception.code, 400)
                with self.assertRaises(HTTPError) as failure:
                    post('/crash-report', {'traceback': 'x' * MAX_REPORT}, permit)
                self.assertEqual(failure.exception.code, 400)
                with self.assertRaises(HTTPError):
                    urllib.request.urlopen(url + '/collected-logs/' + identifier + '.json', timeout=3)
                with patch('crash_reports.time.time', return_value=10**12):
                    with self.assertRaises(ValueError):
                        app.reports.authorize('Bearer ' + permit)
                other = dict(room, id='b'*24)
                metadata = app.reports.authorize('Bearer ' + app.reports.permit(other))
                report = json.loads(log.with_suffix('.report.json').read_text())
                with patch('crash_reports.Path.mkdir', side_effect=OSError('disk full')):
                    with self.assertRaises(HTTPError) as failure:
                        post('/crash-report', report, app.reports.permit(other))
                self.assertEqual(failure.exception.code, 503)
                with patch('crash_reports.Path.glob', return_value=[target] * 1024):
                    with self.assertRaises(OSError):
                        app.reports.collect(metadata, report)
                self.assertEqual(len(list(target.parent.glob('*.json'))), 1)
            finally:
                app.shutdown()
                worker.join(3)
                app.server_close()

    def test_launcher_preserves_original_error_when_upload_fails(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            (root / 'AzerothSurvivors.exe').write_bytes(b'test')
            with patch('room_client.ROOT', root):
                client = RoomClient('https://example.test', profile_folder=root / 'profile')
                client.check_compatibility = lambda: (_ for _ in ()).throw(TimeoutError('original failure'))
                room = dict(id='a'*24, slot=2, crash_upload_permit='permit')
                with patch('crash_reports.urllib.request.urlopen', side_effect=TimeoutError('offline')) as request:
                    client.play(room)
                self.assertIn('original failure', client.error)
                self.assertIn('upload failed', client.error)
                self.assertEqual(request.call_args.kwargs['timeout'], 5)
                report = next((root / 'profile/logs').glob('*.report.json'))
                self.assertEqual(json.loads(report.read_text())['gameplay'], '')
                self.assertEqual(len(list(report.parent.glob('*.log'))), 1)


if __name__ == '__main__':
    unittest.main()
