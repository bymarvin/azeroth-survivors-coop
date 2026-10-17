import concurrent.futures
import unittest
import json
import threading
import urllib.request

from lobby import Rooms


class LobbyTests(unittest.TestCase):
    def test_guest_entry_indicator_tracks_confirmed_map_and_native_entry(self):
        from room_client import RoomClient
        from types import SimpleNamespace
        client = RoomClient('http://127.0.0.1:47770')
        client.room = dict(slot=2, phase='playing')
        self.assertEqual(client.state()['guest_entry'], dict(ready=False, map=None, starting=True))
        client.launched = True
        client.worker = SimpleNamespace(is_alive=lambda: True)
        self.assertTrue(client.state()['guest_entry']['starting'])
        client.worker = SimpleNamespace(is_alive=lambda: False)
        self.assertIsNone(client.state()['guest_entry'])
        client.bridge = SimpleNamespace(host_map=None, ready=set(), menu_players=set())
        self.assertEqual(client.state()['guest_entry'], dict(ready=False, map=None))
        client.bridge.host_map = 'duskwood'
        self.assertEqual(client.state()['guest_entry'], dict(ready=True, map='duskwood'))
        client.bridge.ready.add(2)
        self.assertIsNone(client.state()['guest_entry'])
        client.bridge.ready.clear()
        client.error = 'Disconnected'
        self.assertIsNone(client.state()['guest_entry'])
        client.error = None
        client.room['slot'] = 1
        self.assertIsNone(client.state()['guest_entry'])

    def test_local_controller_can_leave_and_rejoin_without_stale_stop(self):
        from room_client import RoomClient
        from lobby_server import server
        app = server(('127.0.0.1', 0))
        threading.Thread(target=app.serve_forever, daemon=True).start()
        client = RoomClient(f'http://127.0.0.1:{app.server_port}')
        host = app.rooms.create('Test', 'Host', False, client.build)
        try:
            client.join('Guest', host['room']['id'])
            client.launched = True
            client.action('leave')
            self.assertTrue(client.cancel.is_set())
            client.join('Guest again', host['room']['id'])
            self.assertFalse(client.cancel.is_set())
            self.assertFalse(client.launched)
            self.assertTrue(client.commands.empty())
        finally:
            app.shutdown()
            app.server_close()

    def test_four_clients_over_loopback_http(self):
        from lobby_server import server
        app = server(('127.0.0.1', 0))
        worker = threading.Thread(target=app.serve_forever, daemon=True)
        worker.start()
        url = f'http://127.0.0.1:{app.server_port}'
        def post(path, data, token=None):
            headers = {'Content-Type': 'application/json'}
            if token:
                headers['Authorization'] = 'Bearer ' + token
            request = urllib.request.Request(url + path, json.dumps(data).encode(), headers)
            with urllib.request.urlopen(request, timeout=3) as response:
                return json.load(response)
        try:
            host = post('/create', dict(name='Local test', player='Host', private=False, build='a' * 64))
            room_id = host['room']['id']
            guests = [post('/join', dict(room=room_id, player=f'Guest {n}', build='a' * 64)) for n in range(3)]
            state = post('/poll', dict(room=room_id), host['token'])
            state = post('/action', dict(room=room_id, action='start', revision=state['revision']), host['token'])
            for guest in guests:
                observed = post('/poll', dict(room=room_id), guest['token'])
                self.assertEqual(observed['phase'], 'playing')
                self.assertEqual(len(observed['players']), 4)
        finally:
            app.shutdown()
            worker.join(3)
            app.server_close()

    def test_capacity_privacy_host_controls_and_expiry(self):
        rooms = Rooms()
        build = 'a' * 64
        host = rooms.create('Friends', 'Host', True, build)
        room_id = host['room']['id']
        self.assertEqual(rooms.listing(), [])
        with self.assertRaises(ValueError):
            rooms.join(room_id, 'Guest', build)
        with self.assertRaises(ValueError):
            rooms.join(room_id, 'Guest', 'b' * 64, host['room']['invite'])
        def join(n):
            try:
                return rooms.join(room_id, f'Guest {n}', build, host['room']['invite'])
            except ValueError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            guests = [p for p in pool.map(join, range(8)) if p]
        self.assertEqual(sorted(g['room']['slot'] for g in guests), [2, 3, 4])
        current = rooms.poll(room_id, host['token'])
        with self.assertRaises(ValueError):
            rooms.action(room_id, guests[0]['token'], 'start', current['revision'])
        for action, phase in [('start', 'playing'), ('victory', 'victory'),
                              ('keep_fighting', 'playing'), ('victory', 'victory'), ('new_hero', 'menu')]:
            current = rooms.action(room_id, host['token'], action, current['revision'])
            self.assertEqual(current['phase'], phase)
            for guest in guests:
                observed = rooms.poll(room_id, guest['token'])
                self.assertEqual(observed['phase'], phase)
                self.assertNotIn('invite', observed)
        with self.assertRaises(ValueError):
            rooms.action(room_id, host['token'], 'start', 1)
        rooms.expire(float('inf'))
        self.assertEqual(rooms.rooms, {})
        public = rooms.create('Public', 'Host', False, build)
        self.assertEqual(len(rooms.listing()), 1)
        self.assertNotIn('invite', rooms.listing()[0])
        rooms.join(public['room']['id'], 'Guest', build)


if __name__ == '__main__':
    unittest.main()
