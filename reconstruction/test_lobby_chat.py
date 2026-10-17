"""Room-private, authenticated and bounded chat; run with unittest."""
import json
import threading
import unittest
import urllib.request
from unittest.mock import patch

from lobby import Rooms
from lobby_server import server


class ChatTests(unittest.TestCase):
    def test_history_identity_privacy_limits_and_lifecycle(self):
        rooms = Rooms()
        host = rooms.create('Chat', 'Host', False, 'a' * 64)
        room = host['room']['id']
        guest = rooms.join(room, 'Guest', 'a' * 64)
        other = rooms.create('Other', 'Other host', False, 'a' * 64)
        revision = rooms.poll(room, host['token'])['revision']
        with self.assertRaises(ValueError):
            rooms.chat(room, other['token'], 'Wrong room')
        for text in ['', ' ', 'x' * 501, '\nhi', '\ud800', None, 123]:
            with self.assertRaises(ValueError):
                rooms.chat(room, guest['token'], text)
        with patch('lobby.time.monotonic', return_value=100):
            result = rooms.chat(room, guest['token'], '<script>hello</script>')
            with self.assertRaises(ValueError):
                rooms.chat(room, guest['token'], 'Too fast')
        self.assertEqual(result['revision'], revision)
        self.assertEqual(result['chat'][0]['name'], 'Guest')
        self.assertNotIn('chat', rooms.listing()[0])
        self.assertEqual(rooms.poll(other['room']['id'], other['token'])['chat'], [])
        rooms.action(room, host['token'], 'start', revision)
        for n in range(105):
            with patch('lobby.time.monotonic', return_value=102 + n):
                rooms.chat(room, guest['token'], f'Message {n}')
        history = rooms.poll(room, host['token'])['chat']
        self.assertEqual(len(history), 100)
        self.assertEqual(history[-1]['id'], 106)
        self.assertEqual(history[-1]['text'], 'Message 104')
        rooms.action(room, guest['token'], 'leave', 0)
        with self.assertRaises(ValueError):
            rooms.chat(room, guest['token'], 'Left')
        rooms.action(room, host['token'], 'leave', 0)
        self.assertNotIn(room, rooms.rooms)

    def test_http_and_local_controller_chat(self):
        from room_client import RoomClient
        app = server(('127.0.0.1', 0))
        worker = threading.Thread(target=app.serve_forever, daemon=True)
        worker.start()
        client = RoomClient(f'http://127.0.0.1:{app.server_port}')
        host = app.rooms.create('Chat', 'Host', True, client.build)
        try:
            client.join('Guest', code=host['room']['id'] + ':' + host['room']['invite'])
            client.chat('Hello party')
            self.assertEqual(client.state()['room']['chat'][-1]['text'], 'Hello party')
            request = urllib.request.Request(client.directory + '/chat',
                json.dumps(dict(room=host['room']['id'], text='Spoof')).encode(),
                {'Content-Type': 'application/json'})
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(request, timeout=3)
        finally:
            app.shutdown(); worker.join(3); app.server_close()


if __name__ == '__main__':
    unittest.main()
