"""Relay guests stay connected after the run (user report 0.0.16, guest 2 over the EU relay).

relay/server.py re-checks every tunnel's room every AUTH_SECONDS and closes it once the room phase is not lobby,
playing or victory. The host's "New hero" used to move the room to "menu": within 15 s every relay guest lost
its channel ("Co-op peer disconnected") while the host played on, and Next run could not reach them. New hero is
no longer told to the directory; the room stays in "victory". The relay itself is unchanged (not ours in the EU).
Real local directory (lobby_server), real relay monitor, real RoomClient.
"""
import asyncio
import os
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from relay import server as relay  # noqa: E402
from room_client import RoomClient  # noqa: E402


class RelayAfterRunTests(unittest.TestCase):
    def setUp(self):
        from lobby_server import server
        self.app = server(('127.0.0.1', 0))
        threading.Thread(target=self.app.serve_forever, daemon=True).start()
        self.addCleanup(self.app.server_close)
        self.addCleanup(self.app.shutdown)
        self.url = f'http://127.0.0.1:{self.app.server_port}'
        start_routes = patch.object(RoomClient, 'start_routes', lambda self: None)
        start_routes.start()
        self.addCleanup(start_routes.stop)

    def won_room(self):
        """Host + guest, started and won: the directory is in 'victory', the host's game is at the victory screen."""
        host = RoomClient(self.url)
        host.membership = host.request('/create', dict(name='Relay run', player='Host', private=False,
                                                       build=host.build, region='eu', version='0.95.0'))
        host.room = host.membership['room']
        guest = self.app.rooms.join(host.room['id'], 'Guest', host.build)
        for action in ('start', 'victory'):
            fresh = host.request('/poll', dict(room=host.room['id']), True)
            host.room = host.request('/action', dict(room=fresh['id'], action=action, revision=fresh['revision']), True)
        host.bridge = SimpleNamespace()
        host.launched = True
        return host, guest

    def tunnel_survives(self, host, guest):
        """The relay's own monitor for this host-guest tunnel, three re-checks long."""
        endpoints = [dict(room=host.room['id'], token=host.membership['token'], slot=1),
                     dict(room=host.room['id'], token=guest['token'], slot=2)]

        async def watch():
            with patch.object(relay, 'AUTH_SECONDS', .05):
                try:
                    await asyncio.wait_for(relay.Relay(self.url).monitor(endpoints), .5)
                except TimeoutError:
                    return True   # Still watching: the tunnel stays open.
                return False      # The monitor returned: the relay closes the tunnel.
        return asyncio.run(watch())

    def test_new_hero_from_the_room_browser_keeps_relay_tunnels(self):
        host, guest = self.won_room()
        host.action('new_hero')
        self.assertEqual(host.commands.get_nowait(), 9)          # Over the game channel to every guest.
        self.assertEqual(host.request('/poll', dict(room=host.room['id']), True)['phase'], 'victory')
        self.assertTrue(self.tunnel_survives(host, guest))

    def test_new_hero_from_the_game_keeps_relay_tunnels(self):
        host, guest = self.won_room()
        host.events.put(9)                                       # Native choice in the host's game window.
        with patch.object(host.stopped, 'wait', side_effect=[False, True]):
            host.heartbeat()
        self.assertIsNone(host.error)
        self.assertTrue(host.events.empty())
        self.assertEqual(host.room['phase'], 'victory')
        self.assertTrue(self.tunnel_survives(host, guest))

    def test_what_the_relay_did_before(self):
        host, guest = self.won_room()
        fresh = host.request('/poll', dict(room=host.room['id']), True)
        host.request('/action', dict(room=fresh['id'], action='new_hero', revision=fresh['revision']), True)
        self.assertFalse(self.tunnel_survives(host, guest))      # 0.0.16: the "menu" phase ends the tunnel.

    def test_keep_fighting_still_uses_the_directory(self):
        host, guest = self.won_room()
        host.action('keep_fighting')
        self.assertEqual(host.commands.get_nowait(), 8)
        self.assertEqual(host.room['phase'], 'playing')
        self.assertTrue(self.tunnel_survives(host, guest))


class RelayChannelAfterNewHeroTests(unittest.TestCase):
    """The user's path without a game: two real RoomClients with real routes, the guest over a real relay
    (relay/server.py in this process, check interval shortened), victory, New hero, several relay re-checks."""
    RELAY_PORT = 47771  # relay/routing.Routes default; the directory URL gives the host (localhost).

    def setUp(self):
        import socket
        import ssl
        import tempfile
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'coop-lab/server'))
        from test_us_lobby import make_certificate
        from lobby_server import server
        with socket.socket() as probe:
            if probe.connect_ex(('127.0.0.1', self.RELAY_PORT)) == 0:
                self.skipTest(f'port {self.RELAY_PORT} is in use')
        work = Path(tempfile.mkdtemp(prefix='relay-after-run '))
        make_certificate(work)
        environment = patch.dict(os.environ, SSL_CERT_FILE=str(work / 'ca.pem'))
        environment.start()
        self.addCleanup(environment.stop)
        self.app = server(('127.0.0.1', 0))
        threading.Thread(target=self.app.serve_forever, daemon=True).start()
        self.addCleanup(self.app.server_close)
        self.addCleanup(self.app.shutdown)
        self.loop = asyncio.new_event_loop()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(work / 'fullchain.pem', work / 'key.pem')
        relay_server = relay.Relay(f'http://127.0.0.1:{self.app.server_port}')
        started = threading.Event()

        def run():
            asyncio.set_event_loop(self.loop)
            listener = self.loop.run_until_complete(asyncio.start_server(
                relay_server.handle, '127.0.0.1', self.RELAY_PORT, ssl=context, ssl_handshake_timeout=5, limit=2048))
            started.set()
            self.loop.run_forever()
            listener.close()
        threading.Thread(target=run, daemon=True).start()
        started.wait(10)
        self.addCleanup(lambda: self.loop.call_soon_threadsafe(self.loop.stop))
        interval = patch.object(relay, 'AUTH_SECONDS', .5)
        interval.start()
        self.addCleanup(interval.stop)

    def party(self):
        import socket
        url = f'http://localhost:{self.app.server_port}'
        host, guest = RoomClient(url), RoomClient(url)
        self.addCleanup(lambda: [c.routes and c.routes.close() for c in (host, guest)])
        with socket.create_server(('127.0.0.1', 0)) as free:
            port = free.getsockname()[1]
        host.create('Relay test', 'Host', False, '192.0.2.1', port, 'eu')  # Unreachable: the guest uses the relay.
        guest.join('Guest', host.room['id'], region='eu')
        host.action('start')
        for client in (host, guest):
            client.poll_room()
        prepared = {}
        threads = [threading.Thread(target=lambda c=c: prepared.update({c: c.routes.prepare(dict(c.room), c.cancel, 60)}))
                   for c in (host, guest)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(70)
        self.assertEqual(guest.routes.labels.get(2), 'Relay', guest.routes.labels)
        return host, guest, prepared[host][2], prepared[guest][1]

    def alive(self, a, b, seconds):
        """Messages both ways for a while: the relay must keep the tunnel through its re-checks."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            a.send(dict(kind='probe'))
            b.send(dict(kind='probe'))
            time.sleep(.2)
            a.drain()
            b.drain()

    def won(self, host):
        for action in ('victory',):
            fresh = host.request('/poll', dict(room=host.room['id']), True)
            host.room = host.request('/action', dict(room=fresh['id'], action=action, revision=fresh['revision']), True)
        host.bridge = SimpleNamespace()

    def test_relay_channel_survives_new_hero(self):
        host, guest, to_guest, to_host = self.party()
        self.won(host)
        host.action('new_hero')                              # 0.0.17: game channel only.
        self.alive(to_guest, to_host, 3)                     # Six relay re-checks of the room.
        self.assertEqual(host.request('/poll', dict(room=host.room['id']), True)['phase'], 'victory')

    def test_old_new_hero_cut_the_relay_channel(self):
        host, guest, to_guest, to_host = self.party()
        self.won(host)
        fresh = host.request('/poll', dict(room=host.room['id']), True)
        host.request('/action', dict(room=fresh['id'], action='new_hero', revision=fresh['revision']), True)  # 0.0.16
        with self.assertRaises(ConnectionError):
            self.alive(to_guest, to_host, 5)                  # The user's "Co-op peer disconnected".


if __name__ == '__main__':
    unittest.main()
