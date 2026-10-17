"""Candidate room/save entrypoints remain disposable and never recurse discovery."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_hooks
import room_client
import verify_save_staging


class CandidateRoomTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'AzerothSurvivors.exe').write_bytes(b'game fixture')
        self.home = self.root / 'coop-lab/compatibility-tests/test'
        self.home.mkdir(parents=True)
        self.environment = patch.dict(os.environ, {
            'COOP_CANDIDATE_PROFILE': str(self.home / 'candidate.json'),
            'COOP_CANDIDATE_HOME': str(self.home)}, clear=False)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        os.environ.pop('COOP_EXECUTABLE', None)
        for module in (room_client, verify_save_staging):
            patched = patch.object(module, 'ROOT', self.root)
            patched.start()
            self.addCleanup(patched.stop)

    def test_isolated_room_loads_existing_candidate_without_resolver(self):
        client = room_client.RoomClient('http://127.0.0.1:1', isolated_profile=True)
        profile = {'sha256': hashlib.sha256(b'game fixture').hexdigest()}
        with patch.object(build_hooks, 'load_isolated_adapter_profile', return_value=profile) as load, \
                patch.object(build_hooks, 'resolve_reviewed_profile', side_effect=AssertionError('recursive discovery')):
            self.assertIs(client.check_compatibility(), profile)
        load.assert_called_once_with(self.root / 'AzerothSurvivors.exe', str(self.home / 'candidate.json'))

    def test_personal_room_rejects_candidate_before_loading(self):
        client = room_client.RoomClient('http://127.0.0.1:1')
        with patch.object(build_hooks, 'load_isolated_adapter_profile') as load:
            with self.assertRaisesRegex(ValueError, 'restricted to isolated'):
                client.check_compatibility()
            load.assert_not_called()

    def test_disposable_home_is_required_and_must_be_a_child(self):
        client = room_client.RoomClient('http://127.0.0.1:1', isolated_profile=True)
        for value in ('', str(self.root), str(self.home.parent), str(self.home / 'missing')):
            with self.subTest(home=value), patch.dict(os.environ, COOP_CANDIDATE_HOME=value):
                with self.assertRaisesRegex(ValueError, 'disposable'):
                    client.check_compatibility()
                with self.assertRaisesRegex(ValueError, 'disposable'):
                    verify_save_staging.staging_directory()

    def test_changed_room_build_is_rejected_even_for_candidate(self):
        client = room_client.RoomClient('http://127.0.0.1:1', isolated_profile=True)
        (self.root / 'AzerothSurvivors.exe').write_bytes(b'changed fixture')
        with self.assertRaisesRegex(ValueError, 'game changed'):
            client.check_compatibility()

    def test_candidate_save_staging_stays_under_disposable_home(self):
        first = verify_save_staging.staging_directory()
        second = verify_save_staging.staging_directory()
        self.assertEqual(first.parent, self.home)
        self.assertEqual(second.parent, self.home)
        self.assertNotEqual(first, second)
        self.assertTrue(first.is_dir())

    def test_normal_room_still_uses_the_verified_resolver(self):
        os.environ.pop('COOP_CANDIDATE_PROFILE')
        client = room_client.RoomClient('http://127.0.0.1:1')
        profile = {'verified': True, 'sha256': client.build}
        with patch.object(build_hooks, 'resolve_reviewed_profile', return_value=profile) as resolve, \
                patch.object(build_hooks, 'load_isolated_adapter_profile') as load:
            self.assertEqual(client.check_compatibility(), profile)
            resolve.assert_called_once()
            load.assert_not_called()

    def test_game_update_during_resolver_wait_rejects_party_connection(self):
        os.environ.pop('COOP_CANDIDATE_PROFILE')
        client = room_client.RoomClient('http://127.0.0.1:1')
        def resolve(*args, **kwargs):
            (self.root / 'AzerothSurvivors.exe').write_bytes(b'updated during wait')
            return {'sha256': client.build}
        with patch.object(build_hooks, 'resolve_reviewed_profile', side_effect=resolve):
            with self.assertRaisesRegex(ValueError, 'changed during compatibility'):
                client.check_compatibility()

    def test_mismatched_resolver_result_rejects_party_connection(self):
        os.environ.pop('COOP_CANDIDATE_PROFILE')
        client = room_client.RoomClient('http://127.0.0.1:1')
        with patch.object(build_hooks, 'resolve_reviewed_profile', return_value={'sha256': 'wrong'}):
            with self.assertRaisesRegex(ValueError, 'changed during compatibility'):
                client.check_compatibility()


if __name__ == '__main__':
    unittest.main()
