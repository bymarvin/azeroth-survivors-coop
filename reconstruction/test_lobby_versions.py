import json
import threading
import unittest
import urllib.request
from urllib.error import HTTPError
from lobby_server import server


class VersionTests(unittest.TestCase):
    def test_server_hash_check_cannot_be_bypassed_by_matching_labels_or_start(self):
        app = server(('127.0.0.1', 0))
        worker = threading.Thread(target=app.serve_forever, daemon=True)
        worker.start()
        def post(path, data, token=None):
            headers = {'Content-Type':'application/json'}
            if token:
                headers['Authorization'] = 'Bearer ' + token
            request = urllib.request.Request(f'http://127.0.0.1:{app.server_port}{path}', json.dumps(data).encode(), headers)
            with urllib.request.urlopen(request, timeout=3) as response:
                return json.load(response)
        try:
            host = post('/create', dict(name='Room', player='Host', private=False, build='a'*64, version='0.84.3'))
            room = host['room']
            self.assertEqual(app.rooms.listing()[0]['version'], '0.84.3')
            self.assertEqual(app.rooms.listing()[0]['build'], 'a'*64)
            with self.assertRaises(HTTPError):
                post('/join', dict(room=room['id'], player='Guest', build='b'*64, version='0.84.3'))
            guest = post('/join', dict(room=room['id'], player='Guest', build='a'*64, version='0.77.6'))
            current = app.rooms.rooms[room['id']]
            action = dict(room=room['id'], action='start', revision=current['revision'], build='b'*64)
            with self.assertRaises(HTTPError):
                post('/action', action, host['token'])
            action['build'] = 'a'*64
            current['players'][guest['token']]['build'] = 'b'*64
            with self.assertRaises(HTTPError):
                post('/action', action, host['token'])
            self.assertEqual(current['phase'], 'lobby')
            current['players'][guest['token']]['build'] = 'a'*64
            self.assertEqual(post('/action', action, host['token'])['phase'], 'playing')
        finally:
            app.shutdown()
            worker.join(3)
            app.server_close()


if __name__ == '__main__':
    unittest.main()
