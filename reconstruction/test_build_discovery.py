"""Discovery must retain ambiguity and never authorize an unverified build."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
import tempfile
import tomllib
import struct
import json

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'analysis'))
from check_build_hooks import candidate_offsets, cache_matches


class BuildDiscoveryTests(unittest.TestCase):
    def test_gear_fixture_requires_actual_award_and_save(self):
        from build_hooks import earned_gear_fixture
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            for number in range(2, 5):
                (home / f'group-online-{number}.jsonl').write_text('')
            with self.assertRaisesRegex(ValueError, 'No Warrior weapon'):
                earned_gear_fixture(home)
            row = dict(event='independent_boss_reward', player=3, class_id=1, items=[101800])
            (home / 'group-online-3.jsonl').write_text(json.dumps(row))
            with self.assertRaises(ValueError):
                earned_gear_fixture(home)
            save = home / 'player-3/characters.txt'
            save.parent.mkdir()
            save.write_bytes(b'RSE1:test fixture')
            self.assertEqual(earned_gear_fixture(home), save)

    def test_optimized_python_cannot_run_compatibility_checks(self):
        import subprocess
        result = subprocess.run([sys.executable, '-O', '-c',
            "import sys;sys.path.insert(0,'reconstruction');from build_hooks import resolve_reviewed_profile;"
            "resolve_reviewed_profile('nonexistent.exe')"],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Compatibility checks require assertions', result.stderr)

    def test_party_failure_retains_other_results_but_timeout_stops_launches(self):
        from build_hooks import test_adapter_candidate
        from types import SimpleNamespace
        import subprocess
        for first, expected in ((SimpleNamespace(returncode=1), 13),
                                (subprocess.TimeoutExpired('test', 420), 1)):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                reports = root / 'analysis'
                reports.mkdir()
                candidate = root / 'candidate.json'
                candidate.write_text('{}')
                with patch('build_hooks.ROOT', root), \
                        patch('build_hooks.load_isolated_adapter_profile'), \
                        patch('build_hooks.probe_identity', return_value={'source': 'same'}), \
                        patch('build_hooks.earned_gear_fixture', return_value=root / 'earned.txt'), \
                        patch('coop_transport.create_pairing'), \
                        patch('native_test_process.run_verifier', side_effect=[first] +
                              [SimpleNamespace(returncode=0)] * 12) as launch:
                    result = test_adapter_candidate('game.exe', candidate, reports)
                self.assertEqual(launch.call_count, expected)
                self.assertEqual(result['status'], 'failed')
                self.assertNotIn('pause_resume', result['cases'])
                self.assertEqual('shared_gold' in result['cases'], expected == 13)
                self.assertEqual('fall_revival_unlock' in result['cases'], expected == 13)
                self.assertEqual('next_run_after_defeat' in result['cases'], expected == 13)
                self.assertEqual('victory_new_hero_relay' in result['cases'], expected == 13)
                if expected == 13:
                    room = launch.call_args_list[2]
                    self.assertIn('--automatic-menus', room.args[0])
                    self.assertIn('--guest-request-map', room.args[0])
                    boss_home = launch.call_args_list[1].kwargs['env']['COOP_CANDIDATE_HOME']
                    self.assertIn(f'1:{Path(boss_home) / "player-1/characters.txt"}', room.args[0])
                    self.assertIn('--automatic-gear', launch.call_args_list[3].args[0])
                    self.assertIn('--automatic', launch.call_args_list[4].args[0])
                self.assertEqual(json.loads((reports / 'native-adapter-acceptance.json').read_text()), result)

    def test_complete_static_proof_reports_actual_native_failure(self):
        from build_hooks import candidate_failures
        candidate = dict(adapter_profile=dict(adapter_contracts_verified=True),
                         native_observation=dict(status='passed'),
                         native_acceptance=dict(failures=['Serializer ownership check failed']))
        self.assertEqual(candidate_failures(candidate), ['Serializer ownership check failed'])

    def test_party_acceptance_does_not_launch_without_complete_static_admission(self):
        from build_hooks import test_adapter_candidate
        with patch('build_hooks.load_isolated_adapter_profile', side_effect=ValueError('Unresolved effect ownership')), \
                patch('build_hooks.subprocess.run') as launch:
            with self.assertRaisesRegex(ValueError, 'effect ownership'):
                test_adapter_candidate('unverified.exe', 'candidate.json', 'unused')
            launch.assert_not_called()

    def test_candidate_launch_rejects_non_disposable_save_before_process_creation(self):
        import native_probe
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(native_probe, '_candidate_home', root / 'isolated'), \
                    patch.object(native_probe.subprocess, 'Popen') as launch:
                with self.assertRaisesRegex(ValueError, 'disposable test directory'):
                    native_probe.Native(1, profile_folder=root / 'personal')
                launch.assert_not_called()
                self.assertFalse((root / 'personal').exists())

    def test_structural_candidates_do_not_hide_changed_contracts(self):
        from build_hooks import structural_hook_summary, candidate_failures
        manifest = dict(hooks={'MOVE': dict(reference_rva=0x1000), 'DAMAGE': dict(reference_rva=0x2000)})
        functions = {'0x1000': dict(targets=['0x1000'], unique_structure=True,
                         interior_candidates={'0x1000': dict(candidates=['0x3000'])}),
                     '0x2000': dict(targets=['0x2000'], unique_structure=False,
                         interior_candidates={'0x2000': dict(candidates=['0x4000'])})}
        hooks = structural_hook_summary(manifest, functions)
        self.assertFalse(any(row['gameplay_verified'] for row in hooks.values()))
        failures = candidate_failures(dict(hook_discovery=hooks,
            game_fields={'0x4b8': dict(unique=False)}, unresolved_contracts=['Enemy ownership']))
        self.assertIn('DAMAGE', failures[1])
        self.assertNotIn('MOVE', failures[1])
        self.assertIn('0x4b8', failures[0])
        self.assertEqual(failures[-1], 'Enemy ownership')

    def test_scoped_hook_addresses_do_not_claim_gameplay_compatibility(self):
        from build_hooks import structural_hook_summary
        manifest = dict(hooks={'HUD_DELIVER': dict(reference_rva=0x1000),
                               'UI_COMMAND': dict(reference_rva=0x2000)})
        functions = {'tick': dict(targets=['0x1000'], unique_structure=False,
                     hud_contracts=[dict(rva='0x3000', local_abi_roles=True)])}
        menu = dict(menu_contract_verified=True, ui_command=0x4000)
        result = structural_hook_summary(manifest, functions, menu=menu)
        self.assertEqual(result['HUD_DELIVER']['candidates'], ['0x3000'])
        self.assertEqual(result['UI_COMMAND']['candidates'], ['0x4000'])
        self.assertFalse(any(row['gameplay_verified'] for row in result.values()))
        functions['tick']['hud_contracts'] *= 2
        menu['menu_contract_verified'] = False
        result = structural_hook_summary(manifest, functions, menu=menu)
        self.assertFalse(any(row['candidates'] for row in result.values()))

    def test_native_launch_rejects_32bit_python_before_process_creation(self):
        from native_probe import Native
        with patch('native_probe.C.sizeof', return_value=4), patch('native_probe.subprocess.Popen') as launch:
            with self.assertRaisesRegex(RuntimeError, '64-bit Python'):
                Native(1)
            launch.assert_not_called()

    def test_coherent_image_rebase_preserves_runtime_but_changed_pointer_does_not(self):
        from build_hooks import ROOT, runtime_fingerprint, pefile
        data = bytearray((ROOT / 'AzerothSurvivors.exe').read_bytes())
        pe = pefile.PE(data=bytes(data), fast_load=True)
        original = runtime_fingerprint(data)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
        delta, changed = 0x10000000, []
        for block in pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in block.entries:
                if entry.type == 0:
                    continue
                self.assertEqual(entry.type, 10)
                offset = pe.get_offset_from_rva(entry.rva)
                struct.pack_into('<Q', data, offset, struct.unpack_from('<Q', data, offset)[0] + delta)
                changed.append(offset)
        struct.pack_into('<Q', data, pe.OPTIONAL_HEADER.get_field_absolute_offset('ImageBase'),
                         pe.OPTIONAL_HEADER.ImageBase + delta)
        self.assertTrue(changed)
        self.assertEqual(runtime_fingerprint(data), original)
        data[changed[0]] ^= 1
        self.assertNotEqual(runtime_fingerprint(data), original)

    def test_activation_requires_runtime_equivalence_and_every_exact_hook(self):
        from build_hooks import UPDATED_HASH, compatibility_report
        manifest = dict(reference_sha256=UPDATED_HASH, runtime_fingerprint='reviewed',
                        hooks={'TICK': dict(reference_rva=100)})
        candidate = dict(sha256='future', hooks={'TICK': dict(candidates=[100], unique=True)})
        with patch('build_hooks.discover_manifest', return_value=candidate), \
                patch('build_hooks.runtime_fingerprint', return_value='reviewed'), \
                patch('pathlib.Path.read_bytes', return_value=b'future'):
            self.assertTrue(compatibility_report('future.exe', manifest)['automatic_activation_allowed'])
            candidate['hooks']['TICK']['candidates'] = [101]
            self.assertFalse(compatibility_report('future.exe', manifest)['automatic_activation_allowed'])
            candidate['hooks']['TICK']['candidates'] = [100]
            with patch('build_hooks.runtime_fingerprint', return_value='changed-layout'):
                self.assertFalse(compatibility_report('future.exe', manifest)['automatic_activation_allowed'])

    def test_rejected_update_preserves_verified_profile_and_reports_missing_hooks(self):
        from build_hooks import resolve_reviewed_profile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'reconstruction').mkdir()
            (root / 'analysis').mkdir()
            (root / 'reconstruction/reviewed-hooks.json').write_text('{}')
            active = root / 'analysis/active-hooks.json'
            active.write_text('{"automatic_activation_allowed": true}')
            blocked = dict(automatic_activation_allowed=False, sha256='new-unverified',
                           hooks={'TICK': dict(candidates=[]), 'WRITE': dict(candidates=[1, 2])},
                           dependency_error='Mapped image size changed')
            stages = []
            with patch('build_hooks.ROOT', root), patch('build_hooks.compatibility_report', return_value=blocked), patch('build_hooks.probe_identity', return_value={}):
                with self.assertRaisesRegex(ValueError, 'TICK, WRITE.*Mapped image size changed'):
                    resolve_reviewed_profile('future.exe', developer_discovery=True, progress=lambda stage, detail: stages.append(stage))
            self.assertEqual(stages, ['checking', 'discovering', 'failure'])
            self.assertEqual(json.loads(active.read_text()), dict(automatic_activation_allowed=True))
            self.assertEqual(json.loads((root / 'analysis/updated-hook-discovery.json').read_text()), blocked)

    def test_verified_activation_retains_previous_profile_and_failed_write_is_atomic(self):
        from build_hooks import resolve_reviewed_profile, write_report
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'reconstruction').mkdir()
            (root / 'analysis').mkdir()
            (root / 'reconstruction/reviewed-hooks.json').write_text('{}')
            active = root / 'analysis/active-hooks.json'
            before = dict(automatic_activation_allowed=True, sha256='old-verified')
            after = dict(automatic_activation_allowed=True, sha256='new-verified')
            stages = []
            active.write_text(json.dumps(before))
            def fail_active(path, report):
                if path == active:
                    raise OSError('disk unavailable')
                write_report(path, report)
            with patch('build_hooks.ROOT', root), patch('build_hooks.compatibility_report', return_value=after), patch('build_hooks.probe_identity', return_value={}):
                with patch('build_hooks.write_report', side_effect=fail_active):
                    with self.assertRaises(OSError):
                        resolve_reviewed_profile('future.exe', developer_discovery=True)
                self.assertEqual(json.loads(active.read_text()), before)
                self.assertEqual(resolve_reviewed_profile('future.exe', developer_discovery=True,
                                 progress=lambda stage, detail: stages.append(stage)), after)
            self.assertEqual(stages, ['checking', 'ready'])
            self.assertEqual(json.loads(active.read_text()), after)
            self.assertEqual(json.loads((root / 'analysis/previous-verified-hooks.json').read_text()), before)

    def test_adapter_revision_preserves_profile_for_same_executable(self):
        from build_hooks import resolve_reviewed_profile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'reconstruction').mkdir()
            (root / 'analysis').mkdir()
            (root / 'reconstruction/reviewed-hooks.json').write_text('{}')
            active = root / 'analysis/active-hooks.json'
            before = dict(automatic_activation_allowed=True, sha256='same-game', adapter_revision='old')
            after = dict(before, adapter_revision='new')
            active.write_text(json.dumps(before))
            with patch('build_hooks.ROOT', root), patch('build_hooks.compatibility_report', return_value=after), \
                    patch('build_hooks.probe_identity', return_value={}):
                self.assertEqual(resolve_reviewed_profile('same.exe', developer_discovery=True), after)
                self.assertEqual(resolve_reviewed_profile('same.exe', developer_discovery=True), after)
            self.assertEqual(json.loads(active.read_text()), after)
            self.assertEqual(json.loads((root / 'analysis/previous-verified-hooks.json').read_text()), before)

    def test_cached_adapter_keeps_discovery_metadata_and_previous_backup_bytes(self):
        from build_hooks import UPDATED_HASH, adapter_launch_profile, resolve_reviewed_profile
        from types import SimpleNamespace
        runtime = SimpleNamespace(
            candidate=SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=4096)),
            rva=lambda address: address + 16)
        candidate = dict(adapter_profile=dict(sha256='same-game'),
                         menu_contract=dict(sha256='same-game', reference_sha256=UPDATED_HASH,
                                            menu_contract_verified=True))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'reconstruction').mkdir()
            (root / 'analysis').mkdir()
            (root / 'reconstruction/reviewed-hooks.json').write_text(
                json.dumps(dict(hooks=dict(TICK=dict(reference_rva=32)))))
            active = root / 'analysis/active-hooks.json'
            backup = root / 'analysis/previous-verified-hooks.json'
            backup_bytes = b'{ "automatic_activation_allowed": true, "sha256": "older-game" }\n'
            backup.write_bytes(backup_bytes)
            with patch('build_hooks.ROOT', root), \
                    patch('build_hooks.compatibility_report', return_value=dict(automatic_activation_allowed=False)), \
                    patch('build_hooks.probe_identity', return_value={}), \
                    patch('runtime_addresses.RuntimeAddresses.from_adapter_profile', return_value=runtime) as validate:
                initial = dict(adapter_launch_profile('same.exe', candidate, isolated=False),
                               candidate_profile='analysis/structural-hook-candidate.json',
                               structurally_matched_functions=26, static_adapter_verified=True,
                               contract_failures=[])
                active.write_text(json.dumps(initial))
                self.assertEqual(resolve_reviewed_profile('same.exe', developer_discovery=True), initial)
                self.assertEqual(resolve_reviewed_profile('same.exe', developer_discovery=True), initial)
                self.assertEqual(validate.call_count, 3)  # Initial construction plus both cache validations.
                self.assertEqual(backup.read_bytes(), backup_bytes)
                self.assertEqual(json.loads(active.read_text()), initial)
                # A genuinely revalidated mapping change still rotates the prior profile.
                runtime.rva = lambda address: address + 32
                revised = resolve_reviewed_profile('same.exe', developer_discovery=True)
                self.assertEqual(revised['hooks']['TICK']['candidates'], [64])
                self.assertEqual(json.loads(backup.read_text()), initial)
                revised_backup = backup.read_bytes()
                self.assertEqual(resolve_reviewed_profile('same.exe', developer_discovery=True), revised)
                self.assertEqual(backup.read_bytes(), revised_backup)

    def test_packaging_only_update_requires_identical_mapped_game(self):
        from build_hooks import ROOT, runtime_fingerprint, pefile
        data = bytearray((ROOT / 'AzerothSurvivors.exe').read_bytes())
        pe = pefile.PE(data=bytes(data), fast_load=True)
        original = runtime_fingerprint(data)
        offset = pe.FILE_HEADER.get_field_absolute_offset('TimeDateStamp')
        data[offset] ^= 1
        self.assertEqual(runtime_fingerprint(data + b'unmapped certificate overlay'), original)
        code = next(section for section in pe.sections if section.Characteristics & 0x20000000)
        data[code.PointerToRawData] ^= 1
        self.assertNotEqual(runtime_fingerprint(data), original)

    def test_relocation_masks_keep_game_fields_and_reject_ambiguity(self):
        from build_hooks import instruction_signature, signature_candidates
        code = bytes.fromhex('488b8198040000 e801000000') + b'\x90' * 220
        pattern, mask = instruction_signature(code, 0x1000)
        moved = bytearray(pattern)
        moved[8:12] = b'\x10\x20\x30\x40'  # Only the relative CALL operand changes.
        self.assertEqual(signature_candidates([(0x2000, moved)], pattern, mask), [0x2000])
        self.assertEqual(signature_candidates([(0, moved + moved)], pattern, mask), [0, len(moved)])
        moved[3] ^= 0x10  # A different game-object field must not match.
        self.assertEqual(signature_candidates([(0, moved)], pattern, mask), [])

    def test_research_mapper_distinguishes_field_changes_from_relocations(self):
        from map_build_functions import instruction_pattern, capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        code = bytes.fromhex('488b8198040000 e801000000')
        instructions = list(md.disasm(code, 0x1000))
        moved = bytearray(code)
        moved[8:12] = b'\x10\x20\x30\x40'
        strict = instruction_pattern(instructions, relocation_only=True)
        self.assertIsNotNone(strict.fullmatch(moved))
        moved[3] ^= 0x10
        self.assertIsNone(strict.fullmatch(moved))
        self.assertIsNotNone(instruction_pattern(instructions).fullmatch(moved))

    def test_whole_function_move_requires_known_call_and_data_targets(self):
        from map_build_functions import verify_function_relocation
        def function(base, data, helper):
            return (b'\x48\x8b\x05' + struct.pack('<i', data - base - 7)
                    + b'\xe8' + struct.pack('<i', helper - base - 12)
                    + bytes.fromhex('83b99804000001 c3'))
        before = function(0x1000, 0x6000, 0x3000)
        after = function(0x2000, 0x8000, 0x5000)
        mapping = {0x6000: 0x8000, 0x3000: 0x5000}
        self.assertTrue(verify_function_relocation(before, 0x1000, after, 0x2000, mapping)['references_verified'])
        result = verify_function_relocation(before, 0x1000, after, 0x2000, {})
        self.assertTrue(result['instructions_equivalent'])
        self.assertFalse(result['references_verified'])
        self.assertEqual(len(result['unresolved']), 2)
        wrong = verify_function_relocation(before, 0x1000, after, 0x2000, {0x6000: 0x8001, 0x3000: 0x5000})
        self.assertFalse(wrong['references_verified'])
        self.assertTrue(wrong['mismatched'])
        changed_field = bytearray(after)
        changed_field[14] ^= 0x10
        self.assertFalse(verify_function_relocation(before, 0x1000, changed_field, 0x2000, mapping)['instructions_equivalent'])
        self.assertFalse(verify_function_relocation(b'\x90', 0x1000, b'\x90', 0x2000, {})['references_verified'])
        self.assertFalse(verify_function_relocation(b'\x90', 0x1000, b'\x90', 0x2000,
                                                   {0x1001: 0x3000})['references_verified'])
        self.assertTrue(verify_function_relocation(b'\x90', 0x1000, b'\x90', 0x2000,
                                                  {0x1001: 0x2001})['references_verified'])

    def test_updated_layout_refuses_unreviewed_offsets(self):
        from native_probe import game_field
        from updated_layout import rva
        with patch('native_probe.BUILD', 'updated'), patch('updated_layout.UPDATED', True):
            self.assertEqual(game_field(0x498), 0x4A8)
            self.assertEqual(game_field(0x8BF), 0x8CF)
            self.assertEqual(rva(0x53DC9F5), 0x53E7625)
            with self.assertRaises(ValueError):
                game_field(0x123)
            with self.assertRaises(ValueError):
                rva(0x123456)

    def test_signature_resolution_refuses_missing_or_ambiguous_hooks(self):
        from build_hooks import unique_entry
        signature = bytes(range(48))
        self.assertEqual(unique_entry([(0x1000, b'prefix' + signature)], signature), 0x1006)
        for sections in ([(0, b'absent')], [(0, signature + signature)],
                         [(0, signature), (0x1000, signature)]):
            with self.assertRaises(ValueError):
                unique_entry(sections, signature)
        with self.assertRaises(ValueError):
            unique_entry([(0, b'abc')], b'abc')

    def test_lab_windowed_defaults_preserve_other_settings(self):
        from native_probe import ensure_windowed
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            ensure_windowed(folder)
            path = folder / 'config.toml'
            self.assertEqual(tomllib.loads(path.read_text())['cvars']['gxWindow'], '1')
            path.write_text('[cvars]\ngxWindow = "0"\ngxResolution = "900x600"\ngameTip = "7"\n[audio]\nvolume = 0.5\n')
            ensure_windowed(folder)
            settings = tomllib.loads(path.read_text())
            self.assertEqual(settings['cvars'], dict(gxWindow='1', gxResolution='900x600', gameTip='7'))
            self.assertEqual(settings['audio']['volume'], .5)
            before = path.read_text()
            ensure_windowed(folder)
            self.assertEqual(path.read_text(), before)

    def test_candidates_keep_ambiguous_and_overlapping_matches(self):
        self.assertEqual(candidate_offsets(b'aaaa', b'aa'), [0, 1, 2])
        self.assertEqual(candidate_offsets(b'abc', b'def'), [])
        self.assertEqual(candidate_offsets(b'abc', b'bc'), [1])
        with self.assertRaises(ValueError):
            candidate_offsets(b'abc', b'')

    def test_cache_requires_every_input_and_never_activation(self):
        identity = dict(old_sha256='old', new_sha256='new',
                        adapter_sha256='adapter', scanner_sha256='scanner')
        report = dict(audit_identity=identity, automatic_activation_allowed=False)
        self.assertTrue(cache_matches(report, identity))
        for key in identity:
            self.assertFalse(cache_matches(report, dict(identity, **{key: 'changed'})))
        self.assertFalse(cache_matches(dict(report, automatic_activation_allowed=True), identity))
        self.assertFalse(cache_matches({}, identity))


if __name__ == '__main__':
    unittest.main()
