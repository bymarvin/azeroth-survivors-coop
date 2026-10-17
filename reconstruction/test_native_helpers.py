from pathlib import Path
import struct
import sys
import unittest
import json

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'analysis'), str(ROOT / '.tools/python')]
import pefile
from build_hooks import UPDATED_HASH
from native_helper_contracts import HelperProof, map_table_identity, referenced_data_candidate, REVIEWED_ALLOCATION_FAILURE, adapter_data_contracts, terminal_continuation, class_definition, discover_pause_call_contracts
from enemy_contracts import drop_fields, REVIEWED_ENEMY_VECTOR_DROP, game_drop_link
from menu_contracts import instructions
from native_helper_contracts import (discover_progression_call_contracts, scalar_pair_packet_contract,
                                     REVIEWED_SCALAR_PAIR_PACKET, REVIEWED_SPELL_DEFINITIONS)


class NativeHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = (ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe').read_bytes()

    def proof(self):
        return HelperProof(pefile.PE(data=self.reference, fast_load=True),
                           pefile.PE(data=self.reference, fast_load=True))

    def test_command_drop_switch_preserves_owned_strings_and_all_tags(self):
        from menu_contracts import command_destructor, command_drop_paths, equivalent_command_drop
        old = pefile.PE(data=self.reference, fast_load=True)
        current = (ROOT / 'AzerothSurvivors.exe').read_bytes()
        new = pefile.PE(data=current, fast_load=True)
        entry = command_destructor(old, new, 0x546f050)['entry']
        proof = equivalent_command_drop(old, 0x546f050, new, entry)
        self.assertEqual(proof['tags'], list(range(18)))
        stream, cases = command_drop_paths(new, entry)
        load = next(i for i in stream.values() if i.address >= cases[10]
                    and (i.mnemonic, i.op_str) == ('mov', 'rdx, qword ptr [rsi + 8]'))
        changed = bytearray(current)
        changed[new.get_offset_from_rva(load.address) + load.disp_offset] = 0x10
        with self.assertRaisesRegex(ValueError, 'owned fields'):
            equivalent_command_drop(old, 0x546f050, pefile.PE(data=bytes(changed), fast_load=True), entry)
        call = next(i for i in stream.values() if i.mnemonic == 'call')
        changed = bytearray(current)
        changed[new.get_offset_from_rva(call.address) + call.imm_offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'deallocator'):
            equivalent_command_drop(old, 0x546f050, pefile.PE(data=bytes(changed), fast_load=True), entry)

    def test_enemy_discovery_reports_missing_or_ambiguous_update_ownership(self):
        from enemy_contracts import discover_enemy_contract
        # 0.84.3 reaches this state when the native cast dispatch no longer maps.
        failed = {'0x53e7570': {'guarded_dispatches': {
            'error': 'Ambiguous guarded native dispatch anchor 53f09c4'}}}
        with self.assertRaisesRegex(ValueError, 'ownership.*53f09c4'):
            discover_enemy_contract('unused-reference', 'unused-candidate', failed)
        for structural in ({}, {'a': {'changed_store_owners': {}},
                                'b': {'changed_store_owners': {}}}):
            with self.subTest(structural=structural), self.assertRaisesRegex(
                    ValueError, 'ownership is missing or ambiguous'):
                discover_enemy_contract('unused-reference', 'unused-candidate', structural)

    def test_choice_filter_tables_preserve_every_target(self):
        from native_helper_contracts import choice_switch_edges
        helper = self.proof()
        entry = 0x5398e10
        streams = [instructions(image, entry, helper.bounds[side][entry])
                   for side, image in enumerate((helper.old, helper.new))]
        edges, paired, tables = choice_switch_edges(helper.old, helper.new, *streams)
        self.assertEqual(sorted(row['cases'] for row in tables.values()), [6, 7])
        self.assertEqual(edges, paired)
        self.assertTrue(helper.pair(entry, entry)['complete_helper_verified'])
        for table, row in tables.items():
            # Corrupt the final entry, including a mid-instruction destination.
            site = table + (row['cases'] - 1) * 4
            original = bytes(helper.new.get_data(site, 4))
            for delta in (1, 0x100000):
                helper.new.set_bytes_at_rva(site, struct.pack('<i', struct.unpack('<i', original)[0] + delta))
                with self.assertRaisesRegex(ValueError, 'enum target changed'):
                    choice_switch_edges(helper.old, helper.new, *streams)
            helper.new.set_bytes_at_rva(site, original)
        original_read = helper.new.get_data
        helper.new.get_data = lambda address, size: (original_read(address, size)[:-4]
            if address in tables else original_read(address, size))
        with self.assertRaisesRegex(ValueError, 'Truncated'):
            choice_switch_edges(helper.old, helper.new, *streams)

    def test_gear_definitions_cover_last_record_strings_and_scalar_tail(self):
        from native_helper_contracts import REVIEWED_GEAR_DEFINITIONS
        helper = self.proof()
        rows = helper.gear_definitions(0, REVIEWED_GEAR_DEFINITIONS)
        self.assertEqual(len(rows), 22)
        self.assertEqual(rows[-1]['strings'][0], 'soulstone')
        self.assertEqual(rows, helper.gear_definitions(1, REVIEWED_GEAR_DEFINITIONS))
        last = REVIEWED_GEAR_DEFINITIONS + 21 * 0x48
        sites = [last + 71]
        for field in (0, 16, 32, 48):
            pointer, length = struct.unpack('<QQ', helper.new.get_data(last + field, 16))
            sites.append(pointer - helper.new.OPTIONAL_HEADER.ImageBase + length - 1)
        for site in sites:
            altered = self.proof()
            byte = altered.new.get_data(site, 1)[0]
            altered.new.set_bytes_at_rva(site, bytes([byte ^ 1]))
            altered.game_roots[0x541e6a0] = 'rdx'
            with self.assertRaisesRegex(ValueError, 'gear definition contents changed'):
                altered.pair(0x541e6a0, 0x541e6a0)

    def test_installed_map_definitions_follow_proved_selection_layout(self):
        from map_build_functions import structural_relocations
        from native_helper_contracts import map_enemy_contracts, REVIEWED_MAP_TABLE
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        binary = ROOT / 'AzerothSurvivors.exe'
        structural = structural_relocations(reference, binary, [0x539a680])
        helper = HelperProof(pefile.PE(str(reference), fast_load=True), pefile.PE(str(binary), fast_load=True))
        table = referenced_data_candidate(helper.old, helper.new, structural, REVIEWED_MAP_TABLE)
        layout = table['candidate_layout']
        identity = map_table_identity(helper.old, helper.new, REVIEWED_MAP_TABLE,
                                      table['candidate'], candidate_layout=layout)
        import hashlib
        if hashlib.sha256(binary.read_bytes()).hexdigest() == 'dc165e348d0a15062f58d83530619b0f57479028a28507f449c8bcffea0fb306':
            # This release deliberately changes native definitions; automatic
            # equivalence must reject it. Its exact profile has gameplay gates.
            self.assertEqual(identity['row_stride'], 184)
            self.assertEqual(len(identity['rows']), 9)
            with self.assertRaisesRegex(ValueError, 'definition contents changed'):
                map_enemy_contracts(helper, REVIEWED_MAP_TABLE, table['candidate'],
                                    definitions_only=True, candidate_layout=layout)
            return
        definitions = map_enemy_contracts(helper, REVIEWED_MAP_TABLE, table['candidate'],
                                          definitions_only=True, candidate_layout=layout)
        self.assertTrue(definitions['definition_arrays_verified'])
        self.assertEqual(identity['row_stride'], layout['stride'])
        self.assertEqual(len(identity['rows']), 9)
        if layout['stride'] != 160:
            self.assertFalse(definitions['entire_map_equivalent'])
            with self.assertRaisesRegex(ValueError, 'separate native consumer'):
                map_enemy_contracts(helper, REVIEWED_MAP_TABLE, table['candidate'], candidate_layout=layout)
        site = identity['rows'][-1]['candidate_bosses'] + 4 * 0x58 + 0x44
        helper.new.set_bytes_at_rva(site, bytes([helper.new.get_data(site, 1)[0] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'definition contents changed'):
            map_enemy_contracts(helper, REVIEWED_MAP_TABLE, table['candidate'],
                                definitions_only=True, candidate_layout=layout)

    def test_reviewed_start_admits_only_exact_build_entry(self):
        import hashlib
        from native_helper_contracts import (reviewed_start_entry_contract, REVIEWED_START_BUILD,
                                             collect_helper_inputs, discover_state_call_contracts)
        binary = ROOT / 'AzerothSurvivors.exe'
        if hashlib.sha256(binary.read_bytes()).hexdigest() != REVIEWED_START_BUILD:
            self.skipTest('Exact reviewed START release is not installed')
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        old, new = pefile.PE(str(reference), fast_load=True), pefile.PE(str(binary), fast_load=True)
        row = reviewed_start_entry_contract(old, new, REVIEWED_START_BUILD, 0x5407340)
        self.assertFalse(row['automatic_activation_allowed'])
        self.assertNotIn('complete_helper_verified', row)
        report = discover_state_call_contracts(reference, binary,
            {'0x53fce50': dict(candidates=[dict(rva='0x5407340')])})
        self.assertEqual(report['entries']['START']['expected'], '55')
        self.assertTrue(report['unresolved'])
        mapping = collect_helper_inputs(reference, binary, {'state': report},
                                         [0x53fce50, 0x53fce51], [(0x53fce50, '55')])
        self.assertEqual([r['reference'] for r in mapping['addresses']], [0x53fce50])
        self.assertEqual(mapping['patches'][0]['candidate_bytes'], '55')
        self.assertEqual(mapping['unresolved_inputs'], [dict(kind='address', reference=0x53fce51)])
        new.set_bytes_at_rva(0x54073b4, b'\x90')
        with self.assertRaisesRegex(ValueError, 'No reviewed'):
            reviewed_start_entry_contract(old, new, REVIEWED_START_BUILD, 0x5407340)

    def test_reviewed_map_calls_preserve_exact_adapter_inputs(self):
        import hashlib
        from native_helper_contracts import REVIEWED_START_BUILD, collect_helper_inputs
        from inventory_native_contracts import runtime_inputs
        binary = ROOT / 'AzerothSurvivors.exe'
        if hashlib.sha256(binary.read_bytes()).hexdigest() != REVIEWED_START_BUILD:
            self.skipTest('Exact reviewed map-layout release is not installed')
        old, new = pefile.PE(data=self.reference, fast_load=True), pefile.PE(str(binary), fast_load=True)
        entries = {}
        pairs = [(0x540ac40, 0x5415330), (0x53e05d0, 0x53ea670),
                 (0x5409f40, 0x5414630), (0x5408300, 0x54129f0), (0x540a8f0, 0x5414fe0),
                 (0x542b2e0, 0x5435af0), (0x542b6d0, 0x5435ee0), (0x5401190, 0x540b880)]
        for source, target in pairs:
            proof = HelperProof(old, new, game_roots={source: 'rdx' if source in (0x540a8f0, 0x5401190) else 'rcx'})
            entries[hex(source)] = proof.pair(source, target, candidate_call=True)
            self.assertFalse(entries[hex(source)]['complete_helper_verified'])
            self.assertIn('instruction_pairs', entries[hex(source)]['reviewed_map_layout'])
        damage = entries['0x540ac40']
        self.assertEqual(len(damage['frame_borrow_proofs']), 3)
        self.assertEqual(damage['preconditions'][0]['maximum'], 3)
        self.assertTrue(damage['preconditions'][0]['mandatory_before_every_adapter_call'])
        report = dict(reference_sha256=UPDATED_HASH, sha256=REVIEWED_START_BUILD, entries=entries)
        inputs = runtime_inputs()
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        mapped = collect_helper_inputs(reference, binary, {'maps': report}, inputs['addresses'], inputs['patches'])
        addresses = {r['reference']: r['candidate'] for r in mapped['addresses']}
        for source, target in pairs:
            if source in inputs['addresses']:
                self.assertEqual(addresses[source], target)
        self.assertEqual(addresses[0x540aa6f], 0x541515f)
        self.assertEqual(addresses[0x540c39a], 0x5416a8a)
        patches = {r['reference']: r for r in mapped['patches']}
        self.assertEqual(patches[0x540aa6f]['candidate_bytes'], 'f2410f1086980000000f28ce0f5cc8')
        self.assertNotIn(0x540a963, addresses)  # Changed stride arithmetic is never an admitted patch region.
        from menu_contracts import discover_menu_contract
        from map_build_functions import structural_relocations
        hooks = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
        menu_structure = structural_relocations(reference, binary,
            [hooks[name]['reference_rva'] for name in ('MAP_SELECT', 'UI_COMMAND')])
        menu = discover_menu_contract(reference, binary, menu_structure)
        mapped_menu = collect_helper_inputs(reference, binary, {'menu': menu},
            [0x539a680, 0x539a6b9, 0x539a750, 0x539a751], [(0x539a750, old.get_data(0x539a750, 4).hex())])
        names = {r['reference']: r['candidate'] for r in mapped_menu['addresses']}
        self.assertEqual(names[0x539a750], 0x53b8b00)
        self.assertNotIn(0x539a751, names)
        self.assertFalse(mapped_menu['patches'])


    def test_reviewed_map_constructors_keep_owned_field_and_branch_mapping(self):
        import hashlib
        from native_helper_contracts import REVIEWED_START_BUILD
        from enemy_contracts import reviewed_map_constructor_layout
        binary = ROOT / 'AzerothSurvivors.exe'
        if hashlib.sha256(binary.read_bytes()).hexdigest() != REVIEWED_START_BUILD:
            self.skipTest('Exact reviewed constructor release is not installed')
        helper = HelperProof(pefile.PE(data=self.reference, fast_load=True), pefile.PE(str(binary), fast_load=True))
        for source, target, fields in ((0x5409f40, 0x5414630, 2), (0x5408300, 0x54129f0, 1)):
            row = reviewed_map_constructor_layout(helper, source, target, REVIEWED_START_BUILD)
            self.assertTrue(row['reviewed_constructor_layout_verified'])
            self.assertFalse(row['structure_equivalent'])
            self.assertEqual(len(row['map_field_changes']), fields)
            self.assertTrue(all(r['new_offset'] == r['old_offset'] + 8 for r in row['field_changes']))
        helper.new.set_bytes_at_rva(0x5414809, b'\x90')
        with self.assertRaisesRegex(ValueError, 'No reviewed'):
            reviewed_map_constructor_layout(helper, 0x5409f40, 0x5414630, REVIEWED_START_BUILD)

    def test_upgrade_rank_uses_selected_stat_count_and_rejects_changed_loop(self):
        from native_helper_contracts import upgrade_rank_contract
        entry = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']['CHOOSE']['reference_rva']
        helper = self.proof()
        contract = upgrade_rank_contract(helper, entry, entry)
        self.assertEqual(contract['choice_capacity_offset'], 0x48)
        self.assertEqual(contract['choice_count_offset'], 0x58)
        self.assertEqual(contract['ability_index_offset'], 0x60)
        self.assertEqual(contract['formula'], 'previous_native_rank + selected_choice_tag_count')
        for mutate_count in (True, False):
            helper = self.proof()
            stream = instructions(helper.new, entry, helper.bounds[1][entry])
            if mutate_count:
                target = next(ins for ins in stream if ins.address == contract['sites'][1]['candidate'])
                replacement = b'\x50'  # Wrong Vec member instead of count+58.
            else:
                target = next(ins for i, ins in enumerate(stream[:-1])
                              if ins.mnemonic == 'inc' and ins.op_str == 'r14d'
                              and stream[i+1].op_str == 'dword ptr [rbx + 0x20], r14d')
                replacement = bytes([target.bytes[-1] ^ 8])  # DEC instead of INC.
            helper.new.set_bytes_at_rva(target.address + target.size - 1, replacement)
            with self.assertRaises(ValueError):
                upgrade_rank_contract(helper, entry, entry)

    def test_added_bounds_call_keeps_scalar_provenance_obligation(self):
        import capstone
        from native_helper_contracts import terminal_bounds_call, REVIEWED_BOUNDS_FAILURE, REVIEWED_REMOVE_LOCATION
        proof = self.proof()
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        start = 0x1000
        prefix = b'\x4c\x8d\x05' + struct.pack('<i', REVIEWED_REMOVE_LOCATION - start - 7)
        for extra, ending, accepted in ((b'', b'\x0f\x0b', True),
                                         (b'\x45\x31\xc0', b'\x0f\x0b', False),
                                         (b'', b'\xc3', False)):
            code = prefix + extra
            code += b'\xe8' + struct.pack('<i', REVIEWED_BOUNDS_FAILURE - start - len(code) - 5) + ending
            stream = list(decoder.disasm(code, start))
            index = next(i for i, ins in enumerate(stream) if ins.mnemonic == 'call')
            if accepted:
                row = terminal_bounds_call(proof, stream, index)
                self.assertEqual(row['classification'], 'terminal-native-failure')
                self.assertFalse(row['caller_scalar_provenance_verified'])
                self.assertEqual(set(row['scalar_argument_obligations']), {'rcx', 'rdx'})
            else:
                with self.assertRaises(ValueError):
                    terminal_bounds_call(proof, stream, index)

    def test_state_call_envelope_preserves_typed_abi_and_input_guard(self):
        from native_helper_contracts import discover_state_call_contracts
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        hooks = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
        structural = {hex(hooks[n]['reference_rva']): dict(candidates=[dict(rva=hex(hooks[n]['reference_rva']))])
                      for n in ('START', 'HURT', 'OFFER_CHOICES', 'DEFEAT_UI', 'SPAWN_LOOT', 'MOVE', 'FIND_SPAWN')}
        report = discover_state_call_contracts(reference, reference, structural)
        self.assertFalse(report['automatic_activation_allowed'])
        self.assertEqual(report['entries']['DEFEAT_UI']['abi']['rdx'], 'owned-live-Game')
        self.assertEqual(report['entries']['OFFER_CHOICES']['preconditions'][0]['maximum'], 2)
        self.assertEqual(report['entries']['SPAWN_LOOT']['preconditions'][0]['adapter_allowed_values'], [0, 1, 2])
        self.assertTrue(all(row['runtime_obligations'] for row in report['entries'].values()))

    def test_choice_kind_length_mutation_is_rejected(self):
        from native_helper_contracts import REVIEWED_CHOICE_KIND_LENGTHS
        proof = self.proof()
        data = bytearray(self.reference)
        offset = proof.old.get_offset_from_rva(REVIEWED_CHOICE_KIND_LENGTHS)
        data[offset:offset + 8] = struct.pack('<Q', 9999)
        altered = HelperProof(proof.old, pefile.PE(data=bytes(data), fast_load=True), game_roots={0x5418ca0: 'rcx'})
        with self.assertRaisesRegex(ValueError, 'kind lengths changed'):
            altered.pair(0x5418ca0, 0x5418ca0, candidate_call=True)

    def test_helper_input_mapping_rejects_foreign_report_identity(self):
        from native_helper_contracts import collect_helper_inputs
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            collect_helper_inputs(reference, reference, {'bad': {'sha256': 'wrong'}}, [], [])

    def test_region_calls_reject_mismatched_game_receiver(self):
        from native_helper_contracts import discover_region_call_contracts
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        entry = 0x53dbfd0
        dependencies = {'unresolved': [{'reference': entry, 'candidate': entry,
                                        'calls': [{'reference': 1, 'candidate': 2}]}]}
        owners = {'reference': [{'site': 1, 'target': entry, 'args': {'rcx': 0}}],
                  'candidate': [{'site': 2, 'target': entry, 'args': {'rdx': 0}}]}
        row = discover_region_call_contracts(reference, reference, dependencies, owners)
        self.assertFalse(row['verified'])
        self.assertIn('No unique paired Game receiver', row['unresolved'][0]['reason'])
        owners['candidate'][0]['args'] = {'rcx': 0}
        dependencies['unresolved'][0]['calls'].append({'reference': 3, 'candidate': 4})
        row = discover_region_call_contracts(reference, reference, dependencies, owners)
        self.assertFalse(row['verified'])
        self.assertIn('no matching Game receiver evidence', row['unresolved'][0]['reason'])

    def test_incomplete_structure_comparison_is_rejected(self):
        from unittest.mock import patch
        proof = self.proof()
        proof.game_roots[0x53dbfd0] = 'rcx'
        with patch('native_helper_contracts.compare_function_layout', return_value={'structure_equivalent': False}):
            with self.assertRaisesRegex(ValueError, 'structure changed'):
                proof.pair(0x53dbfd0, 0x53dbfd0, candidate_call=True)

    def test_formatter_closes_only_typed_string_vtable(self):
        from native_helper_contracts import REVIEWED_FORMAT_WRITER, REVIEWED_STRING_FORMAT_VTABLE
        proof = self.proof()
        self.assertTrue(proof.pair(REVIEWED_FORMAT_WRITER, REVIEWED_FORMAT_WRITER)['complete_helper_verified'])
        data = bytearray(self.reference)
        offset = proof.old.get_offset_from_rva(REVIEWED_STRING_FORMAT_VTABLE) + 16
        struct.pack_into('<Q', data, offset, 16)
        altered = HelperProof(proof.old, pefile.PE(data=bytes(data), fast_load=True))
        with self.assertRaisesRegex(ValueError, 'size/alignment changed'):
            altered.pair(REVIEWED_FORMAT_WRITER, REVIEWED_FORMAT_WRITER)

    def test_native_enum_boolean_selection_requires_zeroed_upper_bits(self):
        import capstone
        from native_helper_contracts import native_enum_call_values
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        code = bytes.fromhex('31c04883ff010f94c083f0054885ffba030000000f45d0e800000000')
        stream = list(decoder.disasm(code, 0x1000))
        self.assertEqual(native_enum_call_values(stream, stream[-1].address, 'edx', 4), [3, 4, 5])
        altered = list(decoder.disasm(b'\x31\xc8' + code[2:], 0x1000))
        with self.assertRaisesRegex(ValueError, 'bounded scalar producer'):
            native_enum_call_values(altered, altered[-1].address, 'edx', 4)

    def test_loot_switch_rejects_changed_branch_target(self):
        proof = self.proof()
        data = bytearray(self.reference)
        at = proof.old.get_offset_from_rva(0x6664e6c)
        struct.pack_into('<i', data, at, struct.unpack_from('<i', data, at)[0] + 1)
        altered = HelperProof(proof.old, pefile.PE(data=bytes(data), fast_load=True), game_roots={0x5410160: 'rcx'})
        with self.assertRaisesRegex(ValueError, 'enum target changed'):
            altered.pair(0x5410160, 0x5410160, candidate_call=True)

    def test_map_radius_tuning_preserves_native_scalar_but_rejects_nonfinite(self):
        from native_helper_contracts import map_enemy_contracts, REVIEWED_MAP_TABLE
        for value, accepted in ((32.0, True), (float('nan'), False), (-1.0, False)):
            proof = self.proof()
            data = bytearray(self.reference)
            address = REVIEWED_MAP_TABLE + 5 * 0xa0 + 0x90
            offset = proof.old.get_offset_from_rva(address)
            data[offset:offset + 4] = struct.pack('<f', value)
            changed = HelperProof(proof.old, pefile.PE(data=bytes(data), fast_load=True))
            if accepted:
                row = map_enemy_contracts(changed, REVIEWED_MAP_TABLE, REVIEWED_MAP_TABLE)
                self.assertTrue(row['definition_arrays_verified'])
                self.assertFalse(row['entire_map_equivalent'])
                self.assertEqual(row['map_parameter_changes'][0]['after_value'], value)
            else:
                with self.assertRaisesRegex(ValueError, 'finite and positive'):
                    map_enemy_contracts(changed, REVIEWED_MAP_TABLE, REVIEWED_MAP_TABLE)

    def test_scoped_boss_call_binds_definition_pointer_without_activation(self):
        from native_helper_contracts import discover_boss_call_contract
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        hooks = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
        source = hooks['SPAWN_BOSS']['reference_rva']
        structural = {hex(source): dict(candidates=[dict(rva=hex(source))])}
        for name in ('PAUSE', 'RESUME'):
            rva = hooks[name]['reference_rva']
            structural[hex(rva)] = dict(candidates=[dict(rva=hex(rva))])
        row = discover_boss_call_contract(reference, reference, structural)
        self.assertFalse(row['automatic_activation_allowed'])
        self.assertEqual(row['boss_argument']['count'], 5)
        self.assertIn('pointer', row['entries']['SPAWN_BOSS']['abi']['rdx'])
        self.assertFalse(row['entries']['SPAWN_BOSS']['complete_helper_verified'])
        structural[hex(source)]['candidates'] *= 2
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            discover_boss_call_contract(reference, reference, structural)

    def test_damage_admission_requires_guarded_enum_and_native_frame_borrows(self):
        from native_helper_contracts import discover_damage_call_contract
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        hooks = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
        source = hooks['DAMAGE']['reference_rva']
        structural = {hex(source): dict(candidates=[dict(rva=hex(source))])}
        row = discover_damage_call_contract(reference, reference, structural)
        self.assertFalse(row['automatic_activation_allowed'])
        self.assertEqual(row['guard_instruction']['destination'], 'ebx')
        self.assertTrue(row['guard_instruction']['mandatory'])
        self.assertEqual(row['fields']['luck']['offset'], 0x2d0)
        self.assertEqual([r['extent'] for r in row['entries']['DAMAGE']['frame_borrow_proofs']], [8, 12, 12])
        self.assertFalse(row['entries']['DAMAGE']['complete_helper_verified'])
        self.assertEqual(row['preconditions'][0]['maximum'], 3)

    def test_native_origin_borrow_rejects_a_write_through_borrowed_pointer(self):
        from native_helper_contracts import damage_frame_borrows
        proof = self.proof()
        data = bytearray(self.reference)
        at = proof.old.get_offset_from_rva(0x547298a)
        self.assertEqual(data[at:at+4], bytes.fromhex('f20f101b'))
        data[at+2] = 0x11
        changed = HelperProof(proof.old, pefile.PE(data=bytes(data), fast_load=True))
        entry = 0x540ac40
        before = instructions(proof.old, entry, proof.bounds[0][entry])
        after = instructions(changed.new, entry, changed.bounds[1][entry])
        with self.assertRaises(ValueError):
            damage_frame_borrows(changed, before, after)

    def test_boss_hud_uses_native_hpmax_spelling_and_rejects_key_change(self):
        from native_helper_contracts import boss_hud_health_contract
        proof = self.proof()
        row = boss_hud_health_contract(proof)
        self.assertEqual(row['max_hp'], 'hpMax')
        data = bytearray(self.reference)
        at = proof.old.get_offset_from_rva(0x66633b0)
        self.assertEqual(data[at:at+5], b'hpMax')
        data[at:at+5] = b'maxHp'
        changed = HelperProof(proof.old, pefile.PE(data=bytes(data), fast_load=True))
        with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
            boss_hud_health_contract(changed)

    def test_free_thunk_closes_through_actual_windows_imports(self):
        proof = self.proof()
        row = proof.pair(0x21d0, 0x21d0)
        imports = row['dependencies'][0]['dependencies']
        self.assertEqual([d['identity'][1] for d in imports], ['GetProcessHeap', 'HeapFree'])
        self.assertEqual(row['size'], 5)

    def test_terminal_continuation_rejects_any_success_or_store_path(self):
        import capstone
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        for code, accepted in [('90eb000f0b', True), ('c3', False), ('4889010f0b', False), ('ebfe', False)]:
            self.assertEqual(terminal_continuation(list(decoder.disasm(bytes.fromhex(code), 0x100)), 0x100), accepted)

    def test_native_packet_string_mutation_is_rejected(self):
        proof = self.proof()
        entry = 0x53fcc80
        literal = next(ins for ins in instructions(proof.old, entry, proof.bounds[0][entry])
                       if ins.mnemonic == 'lea' and ins.op_str.startswith('rax, [rip'))
        address = literal.address + literal.size + literal.operands[1].mem.disp
        data = bytearray(self.reference)
        data[proof.old.get_offset_from_rva(address)] ^= 1
        changed = HelperProof(proof.old, pefile.PE(data=bytes(data), fast_load=True), game_roots={entry: 'rcx'})
        with self.assertRaisesRegex(ValueError, 'packet string changed'):
            changed.pair(entry, entry)

    def test_isolated_pause_call_contract_is_not_activation_or_full_closure(self):
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        entries = (0x53fcc80, 0x5401520)
        structural = {hex(entry): dict(candidates=[dict(rva=hex(entry))]) for entry in entries}
        row = discover_pause_call_contracts(reference, reference, structural)
        self.assertFalse(row['automatic_activation_allowed'])
        self.assertTrue(row['isolated_candidate_calls_only'])
        self.assertEqual(row['entries']['PAUSE']['game_phase_offset'], 0x8cf)
        self.assertEqual(row['entries']['PAUSE']['final_phase'], 3)
        self.assertEqual(row['entries']['RESUME']['output_json'], {'type': 'unpaused'})
        self.assertFalse(row['entries']['PAUSE']['complete_helper_verified'])
        structural[hex(entries[0])]['candidates'] *= 2
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            discover_pause_call_contracts(reference, reference, structural)

    def test_progression_contract_proves_real_ability_and_pending_choice_fields(self):
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        hooks = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
        structural = {hex(hooks[name]['reference_rva']): dict(candidates=[dict(rva=hex(hooks[name]['reference_rva']))])
                      for name in ('CHOOSE', 'AWARD_XP')}
        row = discover_progression_call_contracts(reference, reference, structural)
        self.assertFalse(row['automatic_activation_allowed'])
        self.assertEqual(row['fields']['abilities_pointer']['offset'], 0x360)
        self.assertEqual(row['fields']['pending_chests']['offset'], 0x874)
        self.assertEqual(row['ability_contract']['rank_offset'], 0x20)
        self.assertFalse(row['entries']['CHOOSE']['complete_helper_verified'])
        self.assertTrue(row['choice_consumption']['candidate_call_only'])

    def test_scalar_pair_packet_has_no_borrowed_input_mutation(self):
        proof = self.proof()
        row = scalar_pair_packet_contract(proof.old, proof.new, REVIEWED_SCALAR_PAIR_PACKET)
        self.assertTrue(row['proof']['complete_helper_verified'])
        self.assertFalse(row['retains_source_pointer'])
        self.assertEqual(row['packet_opcode'], 0x134)
        self.assertEqual(row['source_element_size'], 8)

    def test_compact_native_format_program_tracks_embedded_zeroes(self):
        proof = self.proof()
        data = proof.format_program(0, 0x6663480)
        self.assertEqual(len(data), 87)
        self.assertIn(b'health per second', data)
        self.assertGreater(len(data), data.index(b'\0') + 1)

    def test_spell_definition_rank_tags_cannot_exceed_proven_dispatch(self):
        proof = self.proof()
        data = bytearray(self.reference)
        pointer = struct.unpack('<Q', proof.old.get_data(REVIEWED_SPELL_DEFINITIONS + 48, 8))[0]
        data[proof.old.get_offset_from_rva(pointer - proof.old.OPTIONAL_HEADER.ImageBase)] = 5
        changed = HelperProof(proof.old, pefile.PE(data=bytes(data), fast_load=True))
        with self.assertRaisesRegex(ValueError, 'five-case enum'):
            changed.choice_data(1, REVIEWED_SPELL_DEFINITIONS, REVIEWED_SPELL_DEFINITIONS)

    def test_enemy_dot_closes_without_inventing_game_alias(self):
        proof = self.proof()
        row = proof.pair(0x5478540, 0x5478540)
        self.assertTrue(row['complete_helper_verified'])
        self.assertEqual(row['game_fields'], [])
        self.assertNotIn(0x5478540, proof.game_roots)

    def test_native_class_definition_has_distinct_extent_and_borrowed_abilities(self):
        proof = self.proof()
        row = class_definition(proof, 0, 0x6638ce0)
        self.assertEqual(row['identifier'], 'warrior')
        self.assertEqual(row['label'], 'Warrior')
        self.assertEqual(row['consumed_size'], 0x40)
        self.assertIn('cleave', row['ability_names'])
        data = bytearray(self.reference)
        struct.pack_into('<Q', data, proof.old.get_offset_from_rva(0x6638ce0 + 0x38), 129)
        bad = HelperProof(proof.old, pefile.PE(data=bytes(data), fast_load=True))
        with self.assertRaisesRegex(ValueError, 'ability slice length'):
            class_definition(bad, 1, 0x6638ce0)

    def test_map_index_switch_closes_and_rejects_changed_case(self):
        proof = self.proof()
        entry = 0x5399d60
        proof.switch_roots[entry] = 7
        row = proof.pair(entry, entry)
        self.assertEqual(row['dependencies'][0]['cases'], 7)
        from map_build_functions import function_references
        table = next(r[3] for r in function_references(proof.code(0, entry), entry)[1] if r[2] == 'rip')
        changed = bytearray(self.reference)
        offset = proof.old.get_offset_from_rva(table)
        changed[offset] ^= 1
        bad = HelperProof(proof.old, pefile.PE(data=bytes(changed), fast_load=True), switch_roots={entry: 7})
        with self.assertRaisesRegex(ValueError, 'switch table changed'):
            bad.pair(entry, entry)

    def test_changed_import_identity_rejected_without_top_level_certificate(self):
        proof = self.proof()
        imported = next(address for address, name in proof.imports[1].items() if name[1] == 'HeapFree')
        proof.imports[1][imported] = ('kernel32.dll', 'HeapAlloc')
        with self.assertRaisesRegex(ValueError, 'import identity changed'):
            proof.pair(0x21d0, 0x21d0)
        self.assertNotIn((0x21d0, 0x21d0), proof.proved)

    def test_difficulty_scalar_change_rejected(self):
        proof = self.proof()
        row = proof.pair(0x53b1dd0, 0x53b1dd0)
        dependency = row['dependencies'][0]
        data = bytearray(self.reference)
        offset = proof.new.get_offset_from_rva(dependency['candidate'])
        data[offset] ^= 1
        changed = HelperProof(proof.old, pefile.PE(data=bytes(data), fast_load=True))
        with self.assertRaisesRegex(ValueError, 'scalar data changed'):
            changed.pair(0x53b1dd0, 0x53b1dd0)

    def test_map_table_reference_and_array_contract(self):
        proof = self.proof()
        source = 0x539a680
        structural = {hex(source): dict(candidates=[dict(rva=hex(source), structure_equivalent=True)])}
        target = referenced_data_candidate(proof.old, proof.new, structural, 0x6636f60)
        row = map_table_identity(proof.old, proof.new, target['reference'], target['candidate'])
        self.assertEqual([m['name'] for m in row['rows']][:2], ['elwynn', 'duskwood'])
        data = bytearray(self.reference)
        struct.pack_into('<Q', data, proof.new.get_offset_from_rva(target['candidate'] + 0x48), 6)
        with self.assertRaisesRegex(ValueError, 'array shape changed'):
            map_table_identity(proof.old, pefile.PE(data=bytes(data), fast_load=True), target['reference'], target['candidate'])
        with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
            referenced_data_candidate(proof.old, proof.new, {}, 0x6636f60)

    def test_reserve_has_native_terminal_failure_without_claiming_panic_equivalence(self):
        proof = self.proof()
        row = proof.pair(0x568de90, 0x568de90)
        failure = next(d for d in row['dependencies'] if d.get('classification') == 'terminal-native-failure')
        self.assertTrue(failure['no_adapter_success_continuation'])
        self.assertNotIn('complete_helper_verified', failure)
        self.assertEqual(failure['diagnostics'][0]['diagnostic'], 'capacity overflow')

    def test_malformed_native_failure_location_rejected(self):
        proof = self.proof()
        wrapper = instructions(proof.old, REVIEWED_ALLOCATION_FAILURE, proof.bounds[0][REVIEWED_ALLOCATION_FAILURE])
        panic = next(i.operands[0].imm for i in wrapper if i.mnemonic == 'call')
        location = next(i for i in instructions(proof.old, panic, proof.bounds[0][panic])
                        if i.mnemonic == 'lea' and i.op_str.startswith('r8, [rip'))
        address = location.address + location.size + location.operands[1].mem.disp
        data = bytearray(self.reference)
        struct.pack_into('<Q', data, proof.new.get_offset_from_rva(address + 8), 0x1000000)
        changed = HelperProof(proof.old, pefile.PE(data=bytes(data), fast_load=True))
        with self.assertRaisesRegex(ValueError, 'immutable extent'):
            changed.pair(0x568de90, 0x568de90)

    def test_enemy_destructor_owned_fields_cannot_move_into_copied_tail(self):
        proof = self.proof()
        entry = REVIEWED_ENEMY_VECTOR_DROP
        report = drop_fields(proof.old, entry, proof.bounds[0][entry])
        self.assertEqual(report['owned_pointer_offsets'], [8, 0x20, 0x48])
        access = next(i for i in instructions(proof.old, entry, proof.bounds[0][entry])
                      if i.op_str == 'rcx, qword ptr [r14 - 0x28]')
        data = bytearray(self.reference)
        data[proof.old.get_offset_from_rva(access.address) + access.disp_offset] = 0x28
        changed = pefile.PE(data=bytes(data), fast_load=True)
        with self.assertRaisesRegex(ValueError, 'copied tail'):
            drop_fields(changed, entry, proof.bounds[0][entry])

    def test_native_game_replacement_links_enemy_destructor_to_game_header(self):
        proof = self.proof()
        manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
        link = game_drop_link(proof.old, manifest['hooks']['UI_COMMAND']['reference_rva'], proof, 0)
        self.assertEqual((link['loop']['game_pointer'], link['loop']['game_count']), (0x578, 0x580))
        self.assertEqual(link['loop']['owned_fields'], [0, 8, 0x18, 0x20, 0x40, 0x48])

    def test_typed_melee_pointer_table_rejects_executable_profile_pointer(self):
        proof = self.proof()
        manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
        structural = {hex(row['reference_rva']): dict(candidates=[dict(rva=hex(row['reference_rva']), structure_equivalent=True)])
                      for row in manifest['hooks'].values() if row['reference_rva'] in proof.bounds[0]}
        report = adapter_data_contracts(proof.old, proof.new, structural)
        table = report[hex(0x6664b18)]
        self.assertEqual(table['classes'], list(range(2, 12)))
        data = bytearray(self.reference)
        struct.pack_into('<Q', data, proof.new.get_offset_from_rva(table['candidate']),
                         proof.new.OPTIONAL_HEADER.ImageBase + 0x21d0)
        with self.assertRaisesRegex(ValueError, 'immutable extent'):
            adapter_data_contracts(proof.old, pefile.PE(data=bytes(data), fast_load=True), structural)


if __name__ == '__main__':
    unittest.main()
