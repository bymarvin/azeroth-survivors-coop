"""Exact-release regression checks; gameplay acceptance remains a separate gate."""
import copy
import json
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import native_probe as native
import updated_layout as layout
from build_hooks import ROOT, probe_identity, resolve_reviewed_profile
from runtime_addresses import RuntimeAddresses


class Release0843Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release = json.loads((ROOT / 'reconstruction/release-0.84.3.json').read_text())

    def test_native_gear_observation_keeps_record_and_consumer_contract(self):
        from build_hooks import UPDATED_HASH
        from menu_contracts import discover_gear_observation
        binary = ROOT / 'AzerothSurvivors.exe'
        if probe_identity(binary)['sha256'] != self.release['adapter_profile']['sha256']:
            self.skipTest('0.84.3 executable is not installed')
        menu = copy.deepcopy(self.release['menu_contract'])
        result = discover_gear_observation(
            ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe', binary, menu)
        self.assertEqual(result['schema']['slots'], 19)
        self.assertEqual(result['schema']['items'], 0x98)
        self.assertFalse(result['native_call_allowed'])
        self.assertEqual(result['equipment_stat_consumer']['item_candidate'], 0x53cca10)
        menu['sha256'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'matching menu proof'):
            discover_gear_observation(
                ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe', binary, menu)

    def test_previous_release_validates_cached_profile_without_discovery(self):
        import tempfile
        from build_hooks import _resolve_reviewed_profile
        binary = ROOT / '_Backup/0.77.6/AzerothSurvivors.exe'
        if not binary.is_file():
            self.skipTest('0.77.6 backup is not installed')
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'active-hooks.json').write_text('{"adapter_profile": {}}')
            with patch('build_hooks.adapter_launch_profile', return_value='validated') as validate, \
                    patch('build_hooks.compatibility_report', return_value={'sha256':
                        '72b51b222171059029eb762ce800c97614ea94f88de7c14543c5236a6fc34743'}) as discovery:
                self.assertEqual(_resolve_reviewed_profile(binary, report_directory=folder), 'validated')
                validate.assert_called_once_with(binary, {'adapter_profile': {}}, isolated=False)
                discovery.assert_called_once()

    def test_unknown_player_build_never_starts_developer_discovery(self):
        with patch('build_hooks.probe_identity', return_value={'sha256': 'unknown'}), \
                patch('build_hooks._resolve_reviewed_profile') as discover:
            with self.assertRaisesRegex(ValueError, 'matching co-op update'):
                resolve_reviewed_profile('unknown.exe')
            discover.assert_not_called()

    def test_batch_connection_is_found_by_owned_queue_not_reused_rsi(self):
        contracts = self.release['adapter_profile']['native_live_contracts']
        memory, context = bytearray(0x10000), bytearray(1232)
        server, frame, connection, queue, buffer = 0x1000, 0x3000, 0x5000, 0x6000, 0x7000
        put = lambda a, v: struct.pack_into('<Q', memory, a, v)
        client = SimpleNamespace(server=server, base=0x140000000,
                                 memory=lambda a, n: bytes(memory[a:a+n]))
        for key, value in [('capacity_field', 2), ('count_field', 1), ('pointer_field', connection)]:
            put(server + contracts['connection'][key], value)
        put(connection + 0x90, queue)
        put(frame + 0x298, server)
        put(frame + 0x128, buffer)
        put(frame + 0x130, 23)
        put(0x8000, client.base + int(contracts['batch']['return_rva'], 16))
        for slot, value in [(128, queue+16), (136, buffer), (152, 0x8000),
                            (160, frame), (176, buffer), (184, 23)]:
            struct.pack_into('<Q', context, slot, value)
        native.validate_bootstrap_owner(client, native.WRITE, context, contracts)
        put(server + contracts['connection']['count_field'], 2)
        put(connection + 176 + 0x90, queue)
        with self.assertRaisesRegex(ValueError, 'unique owned connection'):
            native.validate_bootstrap_owner(client, native.WRITE, context, contracts)
        put(server + contracts['connection']['count_field'], 1)
        put(frame + 0x298, server+16)
        with self.assertRaisesRegex(ValueError, 'server owner'):
            native.validate_bootstrap_owner(client, native.WRITE, context, contracts)

    def test_exact_release_patch_spans_and_generated_continuations(self):
        binary = ROOT / 'AzerothSurvivors.exe'
        identity = probe_identity(binary)
        profile = copy.deepcopy(self.release['adapter_profile'])
        if identity['sha256'] != profile['sha256']:
            self.skipTest('0.84.3 executable is not installed')
        profile['identity'] = identity
        runtime = RuntimeAddresses.from_adapter_profile(
            ROOT / 'reconstruction/reference-metadata.json', binary, profile, isolated=True)
        import capstone
        from visibility_bridge import guest_damage_patches, world_containers_code, downed_world_code
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for row in profile['patches']:
            raw = bytes.fromhex(row['candidate_bytes'])
            self.assertEqual(sum(i.size for i in decoder.disasm(raw, runtime.rva(row['reference']))), len(raw))
        with patch.object(layout, '_runtime', runtime):
            for address, original, replacement in guest_damage_patches():
                self.assertEqual(len(original), len(replacement), hex(address))
            containers = list(decoder.disasm(world_containers_code(), 0))
            self.assertTrue(all('[r12 +' in i.op_str for i in containers if i.mnemonic == 'lea'))
            self.assertIn(bytes.fromhex('f3410f10bc247c080000'), downed_world_code(0x140000000, 0x10000))
        with self.assertRaisesRegex(ValueError, 'acceptance'):
            RuntimeAddresses.from_adapter_profile(
                ROOT / 'reconstruction/reference-metadata.json', binary, profile)
        profile['patches'][0]['candidate_bytes'] = '90'
        with self.assertRaisesRegex(ValueError, 'patch precondition'):
            RuntimeAddresses.from_adapter_profile(
                ROOT / 'reconstruction/reference-metadata.json', binary, profile, isolated=True)


if __name__ == '__main__':
    unittest.main()
