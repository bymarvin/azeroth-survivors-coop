import contextlib
import io
import os
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

from launcher_profile import LauncherProfile, game_version
from room_client import RoomClient


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ))
        os.environ.pop('COOP_EXECUTABLE', None)
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / 'AzerothSurvivors.exe').write_bytes(b'test build')
        self.enterContext(patch('room_client.ROOT', self.root))

    def client(self, profile='one'):
        return RoomClient('https://example.test', profile_folder=self.root / profile)

    def test_successful_create_join_and_failures_preserve_room_name(self):
        client = self.client()
        room = dict(id='room', slot=1, players=[], phase='lobby', name='Room')
        client.start_routes = Mock()
        client.request = Mock(side_effect=[dict(token='test', room=room), room])
        with patch('coop_transport.create_pairing', return_value={'fingerprint':'a'*64}):
            client.create('My room', 'Host', False, '127.0.0.1', 47773, 'eu')
        self.assertEqual(self.client().profile.preferences, dict(name='My room', player='Host', region='eu'))
        client.membership = client.room = None
        client.request = Mock(return_value=dict(token='test', room=dict(room, slot=2)))
        client.join('Guest', 'room', region='na')
        self.assertEqual(self.client().profile.preferences, dict(name='My room', player='Guest', region='na'))
        self.assertEqual(self.client('two').profile.preferences, {})
        client.membership = client.room = None
        client.request = Mock(side_effect=ValueError('failed join'))
        with self.assertRaises(ValueError):
            client.join('Wrong name', 'room', region='eu')
        self.assertEqual(self.client().profile.preferences['player'], 'Guest')
        with patch('coop_transport.create_pairing', return_value={'fingerprint':'a'*64}), self.assertRaises(ValueError):
            client.create('Overwrite', 'Wrong', False, '127.0.0.1', 47773, 'eu')
        self.assertEqual(self.client().profile.preferences['name'], 'My room')
        client.request = Mock(return_value=dict(token='test', room=room))
        client.start_routes = Mock(side_effect=OSError('cannot bind'))
        with self.assertRaises(OSError):
            client.join('Do not save', 'room', region='eu')
        self.assertEqual(self.client().profile.preferences['player'], 'Guest')

    def test_settings_validation_and_atomic_write_failure(self):
        profile = LauncherProfile(self.root / 'settings')
        self.assertEqual(profile.preferences, {})
        profile.save(player='A', region='eu', name='Saved')
        path = profile.folder / 'preferences.json'
        original = path.read_bytes()
        with patch('launcher_profile.os.replace', side_effect=PermissionError()), contextlib.redirect_stderr(io.StringIO()):
            profile.save(player='B')
        self.assertEqual(path.read_bytes(), original)
        self.assertTrue(profile.warning)
        self.assertFalse(list(profile.folder.glob('*.tmp')))
        for raw in (b'not json', b'[]', b'\xff', b'x'*8193):
            path.write_bytes(raw)
            self.assertEqual(LauncherProfile(profile.folder).preferences, {})
        path.write_text(json.dumps(dict(player='A', region='invalid', name='x'*49)))
        self.assertEqual(LauncherProfile(profile.folder).preferences, {'player':'A'})
        a = RoomClient('https://example.test', isolated_profile=True)
        b = RoomClient('https://example.test', isolated_profile=True)
        self.assertNotEqual(a.profile.folder, b.profile.folder)

    def test_full_chained_session_traceback_and_console_location_per_role(self):
        for slot in (1, 2):
            client = self.client(f'profile-{slot}')
            def fail():
                try:
                    raise ValueError('original detail')
                except ValueError as cause:
                    raise RuntimeError('session broke') from cause
            client.check_compatibility = fail
            console = io.StringIO()
            with contextlib.redirect_stderr(console):
                client.play(dict(id='test', slot=slot))
            logs = list((client.profile.folder / 'logs').glob('*.log'))
            self.assertEqual(len(logs), 1)
            self.assertIn('host' if slot == 1 else 'guest', logs[0].name)
            contents = logs[0].read_text()
            self.assertIn('Traceback (most recent call last)', contents)
            self.assertIn('ValueError: original detail', contents)
            self.assertIn('RuntimeError: session broke', contents)
            self.assertIn(str(logs[0]), console.getvalue())
            self.assertIn(str(logs[0]), client.error)
            self.assertIn('Game session failed', client.error)
        with patch('pathlib.Path.mkdir', side_effect=PermissionError()), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertIsNone(self.client().profile.log_exception(ValueError('original error'), 2))
        self.assertIn('original error', output.getvalue())
        self.assertIn('could not save traceback', output.getvalue())

    def test_html_defaults_roundtrip_without_script_injection(self):
        from room_client import UI
        original = Path(__file__).with_name('lobby.html').read_bytes()
        (self.root / 'reconstruction').mkdir()
        (self.root / 'reconstruction/lobby.html').write_bytes(original)
        client = self.client()
        value = '</script><>&'
        client.profile.save(player=value)
        handler = Mock()
        handler.headers = {'Host':'127.0.0.1:1234'}
        handler.server.server_port = 1234
        handler.server.secret = 'test-secret'
        handler.server.client = client
        handler.path = '/'
        UI.do_GET(handler)
        status, body, content_type = handler.reply.call_args.args
        self.assertEqual(status, 200)
        line = next(line for line in body.decode().splitlines() if line.startswith('restoreLobbyPreferences('))
        defaults = json.loads(line[len('restoreLobbyPreferences('):-2])
        self.assertEqual(defaults['player'], value)
        self.assertNotIn(value, line)

    def test_override_identity_and_room_cleanup_log(self):
        alternate = self.root / 'alternate.exe'
        alternate.write_bytes(b'override build')
        os.environ['COOP_EXECUTABLE'] = str(alternate)
        client = self.client()
        self.assertEqual(client.build, hashlib.sha256(alternate.read_bytes()).hexdigest())
        client.reset_session()
        self.assertEqual(client.build, hashlib.sha256(alternate.read_bytes()).hexdigest())
        client.membership = {'token':'test'}
        client.room = dict(id='r', slot=2, revision=1)
        client.routes = Mock()
        client.routes.close.side_effect = OSError('route close failed')
        client.request = Mock()
        client.check_compatibility = Mock(side_effect=ValueError('stop before launch'))
        with contextlib.redirect_stderr(io.StringIO()):
            client.play(dict(client.room))
        logs = list((client.profile.folder / 'logs').glob('*.log'))
        self.assertEqual(len(logs), 2)
        self.assertTrue(any('route close failed' in p.read_text() for p in logs))
        self.assertIsNone(client.room)
        self.assertIsNone(client.routes)
        alternate.write_bytes(b'changed override')
        with self.assertRaisesRegex(ValueError, 'game changed'):
            RoomClient.check_compatibility(client)

    def test_version_label_and_changed_executable_start_guard(self):
        client = self.client()
        (self.root / '.version').write_text('0.84.3')
        self.assertEqual(game_version(self.root/'AzerothSurvivors.exe', client.build), '0.84.3')
        (self.root / '.version').write_text('<invalid>')
        self.assertEqual(game_version(self.root/'AzerothSurvivors.exe', client.build), 'Unknown')
        client.room = dict(id='r', build=client.build)
        client.request = Mock()
        (self.root/'AzerothSurvivors.exe').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'Game build changed'):
            client.action('start')
        client.request.assert_not_called()


if __name__ == '__main__':
    unittest.main()
