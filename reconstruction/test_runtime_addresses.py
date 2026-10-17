"""Real PE fixtures: move functions, their caller and loader-owned function pointer."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from runtime_addresses import AddressMap, RuntimeAddresses, candidate_profile, verify_runtime_moves


def executable():
    data = bytearray(0xC00)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664, 4, 0, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x20B)
    struct.pack_into('<IIQII', data, optional + 16, 0x1020, 0x1000, 0x140000000, 0x1000, 0x200)
    struct.pack_into('<II', data, optional + 56, 0x5000, 0x400)
    struct.pack_into('<H', data, optional + 68, 3)
    struct.pack_into('<I', data, optional + 108, 16)
    struct.pack_into('<II', data, optional + 112 + 3 * 8, 0x3000, 36)
    struct.pack_into('<II', data, optional + 112 + 5 * 8, 0x4000, 12)
    for index, name in enumerate((b'.text', b'.rdata', b'.pdata', b'.reloc')):
        section = optional + 240 + index * 40
        data[section:section + len(name)] = name
        struct.pack_into('<IIII', data, section + 8, 0x200, (index + 1) * 0x1000, 0x200, 0x400 + index * 0x200)
        struct.pack_into('<I', data, section + 36, 0x60000020 if index == 0 else 0x40000040)
    data[0x400:0x410] = bytes.fromhex('b801000000c3') + b'\x90' * 10
    data[0x410:0x420] = bytes.fromhex('b802000000c3') + b'\x90' * 10
    data[0x420:0x426] = b'\xe8' + struct.pack('<i', 0x1000 - 0x1025) + b'\xc3'
    struct.pack_into('<Q', data, 0x600, 0x140001000)
    data[0x608:0x60C] = b'\x01\x00\x00\x00'
    for index, begin in enumerate((0x1000, 0x1010, 0x1020)):
        struct.pack_into('<III', data, 0x800 + index * 12, begin, begin + 6, 0x2008)
    struct.pack_into('<IIHH', data, 0xA00, 0x2000, 12, 0xA000, 0)
    return bytes(data)


MOVES = [(0x1000, 0x1010, 16, 'code'), (0x1010, 0x1000, 16, 'code')]


def moved_executable():
    data = bytearray(executable())
    data[0x400:0x410], data[0x410:0x420] = data[0x410:0x420], data[0x400:0x410]
    struct.pack_into('<i', data, 0x421, 0x1010 - 0x1025)
    struct.pack_into('<Q', data, 0x600, 0x140001010)
    return data


class RuntimeAddressTests(unittest.TestCase):
    def test_new_scalar_gap_rejects_a_preceding_field_that_spans_into_it(self):
        from runtime_addresses import scalar_gap_is_unused
        adjacent = [dict(new_offset=0x490, width=8), dict(new_offset=0x4a0, width=8)]
        self.assertTrue(scalar_gap_is_unused(0x498, 8, adjacent))
        self.assertFalse(scalar_gap_is_unused(0x498, 8, [dict(new_offset=0x494, width=8)]))
        self.assertTrue(scalar_gap_is_unused(0x498, 8, [dict(new_offset=0x494, width=8, address_only=True)]))

    def test_dynamic_input_coverage_rejects_new_sites_and_missing_finite_values(self):
        from runtime_addresses import dynamic_input_coverage
        from updated_layout import ADDRESSES
        row = dict(file='native_guest_combat.py', function='__call__', line=1,
                   expression='relocated(destinations[0 if below else 1])')
        inputs = dict(addresses=list(ADDRESSES.values()), fields=[], dynamic_source_inputs=[row])
        self.assertEqual(dynamic_input_coverage(inputs)[1], [])
        self.assertTrue(dynamic_input_coverage(dict(inputs, addresses=[]))[1])
        self.assertTrue(dynamic_input_coverage(dict(inputs, dynamic_source_inputs=[dict(row, function='new_path')]))[1])
        self.assertTrue(dynamic_input_coverage(dict(inputs, dynamic_source_inputs=[dict(row, expression='relocated(user_value)')]))[1])

    def test_caller_enum_conditions_need_every_site_or_exact_persistent_guard(self):
        import copy
        from runtime_addresses import caller_conditions_discharged
        condition = dict(register='edx', minimum=0, maximum=6)
        calls = [dict(reference=1, candidate=2), dict(reference=3, candidate=4)]
        row = dict(caller_enum_obligations=[condition], calls=calls,
                   caller_condition_proofs=[dict(condition=condition, call=c, values=[2],
                                                 statically_discharged=True) for c in calls])
        self.assertTrue(caller_conditions_discharged(row, None))
        bad = copy.deepcopy(row)
        bad['caller_condition_proofs'].pop()
        self.assertFalse(caller_conditions_discharged(bad, None))
        bad = copy.deepcopy(row)
        bad['caller_condition_proofs'][0]['values'] = [7]
        self.assertFalse(caller_conditions_discharged(bad, None))
        bound = dict(kind='game_unsigned_bound', width=1, maximum=3, new_offset=248,
                     register='rsi', new_rva='0x1234')
        row = dict(caller_enum_obligations=[bound])
        guard = dict(mandatory=True, width=1, maximum=3, offset=248, base='rsi', rva=0x1234)
        self.assertTrue(caller_conditions_discharged(row, guard))
        self.assertFalse(caller_conditions_discharged(row, dict(guard, rva=0x1235)))
        self.assertFalse(caller_conditions_discharged(row, dict(guard, mandatory=False)))
        bound = dict(kind='native_effect_enum_bound', register='r8', width=4,
                     maximum=10, borrowed_size=12, new_rva='0x5678')
        row = dict(caller_enum_obligations=[bound])
        guard = dict(mandatory=True, base='r8', width=4, maximum=10, borrowed_size=12, rva=0x5678)
        self.assertTrue(caller_conditions_discharged(row, None, guard))
        self.assertFalse(caller_conditions_discharged(row, None, dict(guard, borrowed_size=8)))

    def test_bootstrap_mapping_rejects_ambiguous_entry_and_changed_record_extent(self):
        import copy
        import json
        from runtime_addresses import ROOT, UPDATED_HASH, bootstrap_adapter_inputs
        inputs = json.loads((ROOT / 'analysis/native-runtime-inputs.json').read_text())
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        candidate = ROOT / '_Backup/0.77.6/AzerothSurvivors.exe'
        if not candidate.is_file():
            self.skipTest('0.77.6 regression fixture is not installed')
        from map_build_functions import structural_profile
        structural = structural_profile(reference, candidate)
        from native_helper_contracts import adapter_data_contracts, REVIEWED_START_BUILD
        import pefile
        data = adapter_data_contracts(pefile.PE(str(reference), fast_load=True),
                                      pefile.PE(str(candidate), fast_load=True), structural)
        self.assertEqual(data['0x6664b18']['classes'], list(range(2, 12)))
        if hashlib.sha256(candidate.read_bytes()).hexdigest() == REVIEWED_START_BUILD:
            from enemy_contracts import conditional_update_regions
            contract = conditional_update_regions(reference, candidate, structural, inputs['addresses'], inputs['patches'])
            self.assertTrue(contract['static_verified'])
            self.assertEqual(len(contract['retained_native_regions']), 1)
            owner = next(k for k, row in structural.items() if 'changed_store_owners' in row)
            # Reuse independently discovered Enemy proof; every region and caller
            # is still re-read from the executable by the collector on each check.
            with patch('enemy_contracts.discover_enemy_contract', return_value=contract['enemy']):
                for addresses, patches in (([0x53f3e61], []), ([], [(0x53f3e60, '9090')])):
                    with self.assertRaisesRegex(ValueError, 'intersects'):
                        conditional_update_regions(reference, candidate, structural, addresses, patches)
                for key, value in (('sha256', 'unknown'), ('old_end', 0x53f56e1),
                                   ('hooked_callees', ['SPAWN'])):
                    bad = copy.deepcopy(structural)
                    bad[owner]['guest_controlled_regions']['world_and_loot']['retained_native_suffix'][key] = value
                    with self.assertRaisesRegex(ValueError, 'Retained'):
                        conditional_update_regions(reference, candidate, bad, [], [])
        result = bootstrap_adapter_inputs(reference, candidate, structural, inputs['addresses'], inputs['patches'])
        self.assertEqual(len(result['mandatory_live_contracts']), 4)
        self.assertFalse(result['automatic_activation_allowed'])
        tick_key = next(k for k, v in structural.items() if 'entry_contract_candidates' in v)
        bad = copy.deepcopy(structural)
        row = next(v for v in bad[tick_key]['entry_contract_candidates'] if v['verified_header'])
        bad[tick_key]['entry_contract_candidates'].append(row)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            bootstrap_adapter_inputs(reference, candidate, bad, [], [])
        bad = copy.deepcopy(structural)
        bad[tick_key]['connection_vectors'][0]['element_size'] += 8
        with self.assertRaisesRegex(ValueError, 'Connection record'):
            bootstrap_adapter_inputs(reference, candidate, bad, [], [])
        for section, key, value, error in (
                ('game_contracts', 'game_offset', 24, 'embedded offset'),
                ('connection_vectors', 'count_field', 0, 'adjacent')):
            bad = copy.deepcopy(structural)
            bad[tick_key][section][0][key] = value
            with self.assertRaisesRegex(ValueError, error):
                bootstrap_adapter_inputs(reference, candidate, bad, [], [])
        bad = copy.deepcopy(structural)
        bad[tick_key]['batch_contracts'][0]['ui_vector']['stack_register'] = 'rsp'
        with self.assertRaisesRegex(ValueError, 'RBP frame'):
            bootstrap_adapter_inputs(reference, candidate, bad, [], [])
        hooks = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
        for name in ('SERIALIZE', 'WRITE'):
            bad = copy.deepcopy(structural)
            row = next(v for v in bad[hex(hooks[name]['reference_rva'])]['candidates'] if v['structure_equivalent'])
            row['field_changes'] = [dict(old_offset=8, new_offset=16)]
            with self.assertRaisesRegex(ValueError, 'record fields changed'):
                bootstrap_adapter_inputs(reference, candidate, bad, [], [])

    def test_scoped_fields_require_identity_and_preserve_conflicts(self):
        from runtime_addresses import UPDATED_HASH, scoped_game_field_candidates
        rows = {'0x2d0': dict(candidates=[], unique=False, evidence=[]),
                '0x2d1': dict(candidates=[], unique=False, evidence=[])}
        contract = dict(reference_sha256=UPDATED_HASH, sha256='candidate', entries={'DAMAGE': {}},
                        fields={'luck': dict(reviewed_offset=0x2d0, offset=0x2d0, width=4)})
        result = scoped_game_field_candidates(rows, {'damage': contract}, 'candidate')
        self.assertTrue(result['0x2d0']['unique'])
        self.assertFalse(result['0x2d1']['unique'])
        self.assertFalse(rows['0x2d0']['unique'])
        contract['fields']['luck']['offset'] += 8
        self.assertFalse(scoped_game_field_candidates(result, {'damage': contract}, 'candidate')['0x2d0']['unique'])
        with self.assertRaises(ValueError):
            scoped_game_field_candidates(rows, {'damage': contract}, 'other')

    def test_typed_adapter_map_has_no_identity_fallback_or_gameplay_promotion(self):
        before, after = executable(), moved_executable()
        digest = hashlib.sha256(before).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            reference, candidate = Path(folder) / 'old.exe', Path(folder) / 'new.exe'
            reference.write_bytes(before)
            candidate.write_bytes(after)
            identity = {'sha256': hashlib.sha256(after).hexdigest(), 'sources': {'adapter.py': 'fixture'}}
            expected = before[0x400:0x406].hex()
            profile = dict(reference_sha256=digest, sha256=identity['sha256'], identity=identity,
                adapter_contracts_verified=True, runtime_equivalent=False, unresolved_contracts=[],
                addresses=[dict(reference=0x1000, candidate=0x1010)],
                fields=[dict(domain='game', reference=0x100, candidate=0x108)],
                patches=[dict(reference=0x1000, expected=expected, candidate_bytes=expected)],
                required_inputs=dict(addresses=[0x1000], fields=[['game', 0x100]], patches=[[0x1000, expected]]))
            with patch('runtime_addresses.UPDATED_HASH', digest), patch('build_hooks.probe_identity', return_value=identity):
                with self.assertRaisesRegex(ValueError, 'native party acceptance'):
                    RuntimeAddresses.from_adapter_profile(reference, candidate, profile)
                for acceptance in (
                        dict(identity=identity, failures=['boss failed'], runs=[dict(passed=True)]),
                        dict(identity=identity, failures=[], runs=[dict(passed=False)]),
                        dict(identity=identity, failures=[], runs=[])):
                    with self.assertRaisesRegex(ValueError, 'failed or missing test runs'):
                        RuntimeAddresses.from_adapter_profile(reference, candidate,
                            dict(profile, native_acceptance=acceptance))
                runtime = RuntimeAddresses.from_adapter_profile(reference, candidate, profile, isolated=True)
                import updated_layout
                with patch.object(updated_layout, '_runtime', None):
                    updated_layout.configure(runtime)
                    self.assertIs(updated_layout._runtime, runtime)
                self.assertFalse(runtime.profile['runtime_equivalent'])
                self.assertEqual(runtime.rva(0x1000), 0x1010)
                self.assertEqual(runtime.field('game', 0x100), 0x108)
                self.assertEqual(runtime.expected_bytes(0x1000, bytes.fromhex(expected)), bytes.fromhex(expected))
                for invoke in (lambda: runtime.rva(0x1001), lambda: runtime.field('game', 0x101),
                               lambda: runtime.field('enemy', 0x100),
                               lambda: runtime.expected_bytes(0x1000, bytes.fromhex(expected)[:2])):
                    with self.assertRaisesRegex(ValueError, 'Unresolved adapter'):
                        invoke()
                with self.assertRaisesRegex(ValueError, 'incomplete'):
                    RuntimeAddresses.from_adapter_profile(reference, candidate,
                        dict(profile, unresolved_contracts=['Enemy ownership']), isolated=True)
                with self.assertRaisesRegex(ValueError, 'ambiguous'):
                    RuntimeAddresses.from_adapter_profile(reference, candidate,
                        dict(profile, addresses=profile['addresses'] * 2), isolated=True)
                with self.assertRaisesRegex(ValueError, 'precondition'):
                    RuntimeAddresses.from_adapter_profile(reference, candidate,
                        dict(profile, patches=[dict(profile['patches'][0], candidate_bytes='90' * 6)]), isolated=True)

    def test_readonly_table_move_updates_rip_reference_and_loader_site(self):
        before = bytearray(executable())
        # Move a native pointer table and an equal-size immutable value block.
        before[0x610:0x620] = struct.pack('<QQ', 0x140001000, 17)
        before[0x620:0x630] = b'Other table data'
        struct.pack_into('<IIHHHH', before, 0xA00, 0x2000, 16, 0xA000, 0xA010, 0, 0)
        struct.pack_into('<I', before, 0x98 + 112 + 5 * 8 + 4, 16)
        before[0x430:0x438] = b'\x48\x8b\x05' + struct.pack('<i', 0x2010 - 0x1037) + b'\xc3'
        struct.pack_into('<III', before, 0x824, 0x1030, 0x1038, 0x2008)
        struct.pack_into('<I', before, 0x98 + 112 + 3 * 8 + 4, 48)
        after = bytearray(before)
        after[0x610:0x620], after[0x620:0x630] = after[0x620:0x630], after[0x610:0x620]
        struct.pack_into('<i', after, 0x433, 0x2020 - 0x1037)
        struct.pack_into('<H', after, 0xA0A, 0xA020)
        moves = [(0x2010, 0x2020, 16, 'data'), (0x2020, 0x2010, 16, 'data')]
        extents = [(0x2010, 16), (0x2020, 16)]
        with self.assertRaises(ValueError):
            verify_runtime_moves(before, after, moves)
        self.assertTrue(verify_runtime_moves(before, after, moves, reviewed_data_spans=extents)['runtime_equivalent'])
        after[0x628] ^= 1
        with self.assertRaises(ValueError):
            verify_runtime_moves(before, after, moves, reviewed_data_spans=extents)

    def test_full_image_proof_accepts_only_complete_semantics_preserving_move(self):
        original, moved = executable(), moved_executable()
        profile = verify_runtime_moves(original, moved, MOVES)
        self.assertTrue(profile['runtime_equivalent'])
        self.assertTrue(profile['adapter_translation_required'])
        self.assertEqual(profile['verified_functions'], 3)
        for offset in (0x411, 0x421, 0x600, 0x60F, 0x808):
            changed = bytearray(moved)
            changed[offset] ^= 1
            with self.subTest(offset=hex(offset)), self.assertRaises(ValueError):
                verify_runtime_moves(original, changed, MOVES)
        with self.assertRaises(ValueError):
            verify_runtime_moves(original, moved, [])

    def test_runtime_patch_preconditions_translate_operands_only_after_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            reference, candidate = Path(directory) / 'before.exe', Path(directory) / 'after.exe'
            reference.write_bytes(executable())
            candidate.write_bytes(moved_executable())
            with patch('runtime_addresses.UPDATED_HASH', hashlib.sha256(reference.read_bytes()).hexdigest()):
                addresses = RuntimeAddresses(reference, candidate, MOVES)
            self.assertEqual(addresses.rva(0x1002), 0x1012)
            self.assertEqual(addresses.rva(0x2000), 0x2000)
            self.assertEqual(addresses.expected_bytes(0x1020, executable()[0x420:0x426]),
                             moved_executable()[0x420:0x426])
            self.assertEqual(addresses.relative_branch(0x1020, 0x1000, opcode=b'\xe8'),
                             moved_executable()[0x420:0x425])
            self.assertEqual(addresses.pointer(0x140000000, 0x1000), struct.pack('<Q', 0x140001010))
            self.assertEqual(addresses.relative_branch(0x1000, 0x1010, opcode=b'\xeb', size=2), b'\xeb\xee')
            with self.assertRaises(ValueError):
                addresses.expected_bytes(0x1020, b'wrong')
            with self.assertRaises(ValueError):
                addresses.rva(0xFFFFFFFF)

    def test_candidate_profile_is_hash_bound_and_checks_the_entire_image(self):
        with tempfile.TemporaryDirectory() as directory:
            reference, candidate = Path(directory) / 'before.exe', Path(directory) / 'after.exe'
            reference.write_bytes(executable())
            candidate.write_bytes(moved_executable())
            known_hash = hashlib.sha256(reference.read_bytes()).hexdigest()
            evidence = dict(reference_sha256=known_hash, sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
                            dependencies={'0x1000': dict(function=0x1000, candidates=[0x1010]),
                                          '0x1010': dict(function=0x1010, candidates=[0x1000])})
            with patch('runtime_addresses.UPDATED_HASH', known_hash):
                self.assertTrue(candidate_profile(reference, candidate, evidence)['runtime_equivalent'])
                evidence['sha256'] = 'stale'
                with self.assertRaises(ValueError):
                    candidate_profile(reference, candidate, evidence)

    def test_invalid_or_overlapping_moves_fail(self):
        for moves in ([(10, 20, 0, 'code')], [(10, 20, 8, 'code'), (15, 30, 8, 'code')],
                      [(10, 20, 8, 'code'), (30, 25, 8, 'code')]):
            with self.assertRaises(ValueError):
                AddressMap(moves)


if __name__ == '__main__':
    unittest.main()
