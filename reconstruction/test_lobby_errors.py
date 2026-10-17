import json
import socket
import ssl
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

from room_client import UI, RoomClient, failure_description


class LobbyErrorTests(unittest.TestCase):
    def test_network_categories_and_safe_diagnostics(self):
        certificate = ssl.SSLCertVerificationError(1, 'certificate has expired')
        certificate.verify_code = 10
        cases = [(URLError(certificate), 'certificate has expired'),
                 (certificate, 'verify code 10'),
                 (URLError(socket.gaierror(-2, 'private details')), 'DNS lookup failed'),
                 (URLError(TimeoutError()), 'timed out'),
                 (URLError(ConnectionRefusedError()), 'Connection refused'),
                 (ssl.SSLError(1, 'private details'), 'TLS handshake failed'),
                 (HTTPError('https://user:secret@host/path?token=secret', 503, 'secret', {}, None), 'HTTP 503'),
                 (HTTPError('https://host/', 401, 'secret', {}, None), 'HTTP 401'),
                 (json.JSONDecodeError('secret', 'secret', 0), 'invalid JSON'),
                 (URLError('secret'), 'Network request failed')]
        for error, expected in cases:
            with self.subTest(expected=expected):
                result = failure_description(error, 'https://user:secret@example.test:443/private?token=secret')
                self.assertIn(expected, result)
                self.assertIn('https://example.test:443', result)
                self.assertNotIn('secret', result)
                self.assertNotIn('private', result)
        self.assertIn('PC time (UTC):', failure_description(certificate, 'https://example.test'))
        occupied = failure_description(OSError(10048, 'secret'), 'https://example.test')
        self.assertIn('local host port is already in use', occupied)
        self.assertNotIn('Directory', occupied)
        self.assertNotIn('secret', occupied)
        self.assertIn('Access denied', failure_description(PermissionError(13, 'secret'), 'https://example.test'))
        self.assertIn('Local system operation failed', failure_description(FileNotFoundError(2, 'secret'), 'https://example.test'))
        for directory in ('https://example.test:bad', 'https://example.test:70000'):
            self.assertIn('certificate has expired', failure_description(certificate, directory))
        self.assertEqual(failure_description(ValueError('Leave the current room first'), ''), 'Leave the current room first')
        self.assertNotIn('secret', failure_description(RuntimeError('secret'), ''))

    def test_heartbeat_keeps_the_underlying_connection_reason(self):
        client = SimpleNamespace(directory='https://example.test', membership=True,
            lock=threading.RLock(), stopped=SimpleNamespace(wait=Mock(side_effect=[False, True])),
            poll_room=Mock(side_effect=URLError(socket.gaierror(-2, 'details'))))
        RoomClient.heartbeat(client)
        self.assertIn('Room connection failed:', client.error)
        self.assertIn('DNS lookup failed', client.error)

    def test_refresh_and_create_display_same_expired_certificate_details(self):
        error = ssl.SSLCertVerificationError(1, 'certificate has expired')
        error.verify_code = 10
        client = SimpleNamespace(directory='https://example.test',
            request=Mock(side_effect=URLError(error)), create=Mock(side_effect=URLError(error)))
        app = ThreadingHTTPServer(('127.0.0.1', 0), UI)
        app.client, app.secret = client, 'local-test-secret'
        worker = threading.Thread(target=app.serve_forever, daemon=True)
        worker.start()
        try:
            for path, payload, status in [('/rooms', None, 503),
                    ('/create', dict(name='Test', player='Hero', private=False, address='127.0.0.1', port=47773), 400)]:
                request = urllib.request.Request(f'http://127.0.0.1:{app.server_port}{path}',
                    json.dumps(payload).encode() if payload else None,
                    {'Content-Type': 'application/json', 'X-Coop-Client': app.secret})
                with self.assertRaises(HTTPError) as caught:
                    urllib.request.urlopen(request, timeout=3)
                with caught.exception as response:
                    self.assertEqual(response.code, status)
                    message = json.load(response)['error']
                self.assertIn('certificate has expired', message)
                self.assertIn('verify code 10', message)
                self.assertIn('Windows date, time and time zone', message)
                self.assertIn('https://example.test', message)
                self.assertNotIn(app.secret, message)
        finally:
            app.shutdown()
            worker.join(3)
            app.server_close()


if __name__ == '__main__':
    unittest.main()
