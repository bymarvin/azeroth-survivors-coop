"""Field-change discovery must never mistake a structural match for activation."""
import sys
from pathlib import Path
import unittest
import struct
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'analysis'))
from build_hooks import capstone, displacement_size, instruction_signature, signature_candidates
from map_build_functions import (compare_function_layout, function_references, tick_entry_contract,
                                 game_field_uses, interior_relocations, hud_delivery_contracts)
from map_build_functions import typed_reviewed_references
from map_build_functions import stable_game_field_uses, batch_write_contracts, server_vector_contracts, embedded_game_contracts
from map_build_functions import saved_game_frame_contracts
from map_build_functions import pointer_offset_candidates
from map_build_functions import object_frame_stores, restore_game_frame_contract
from map_build_functions import region_instruction_contract
from map_build_functions import stack_field_pairs, anchored_trap_contract
from map_build_functions import conditional_game_accesses
from map_build_functions import mutation_footprint
from map_build_functions import pursuit_live_contract
from map_build_functions import return_tag_values
from map_build_functions import ability_cast_copies, ability_source_bounds, conditional_damage_switch
from map_build_functions import changed_store_owners, collect_region_inputs, paired_store_fields, frame_value_reads


class StructuralMappingTests(unittest.TestCase):
    def test_discovery_recovers_changed_sample_windows_without_activating(self):
        from map_build_functions import structural_relocations
        before = b''.join(b'\xb8' + struct.pack('<I', n) for n in range(200)) + b'\xc3'
        after = bytearray(before)
        for index in (0, 50, 100, 150):
            struct.pack_into('<I', after, index * 5 + 1, 1000 + index)
        def image(base, code):
            return SimpleNamespace(bounds=[(base, base + len(code))],
                sections=[SimpleNamespace(VirtualAddress=base, Characteristics=0x20000000,
                                          get_data=lambda: code)],
                get_data=lambda address, size: code[address-base:address-base+size])
        old, new = image(0x1000, before), image(0x4000, bytes(after))
        with patch('map_build_functions.pefile.PE', side_effect=[old, new]), patch(
                'map_build_functions.unwind_ranges', side_effect=lambda p: p.bounds):
            result = structural_relocations('reference', 'candidate', [0x1000])['0x1000']
        self.assertEqual([c['rva'] for c in result['candidates']], ['0x4000'])
        self.assertGreaterEqual(result['candidates'][0]['matching_windows'], 2)
        self.assertFalse(result['candidates'][0]['structure_equivalent'])
        self.assertFalse(result['unique_structure'])
        self.assertFalse(result['automatic_activation_allowed'])

    def test_repeated_copies_of_one_window_do_not_count_as_two_anchors(self):
        from map_build_functions import structural_relocations
        before = b''.join(b'\xb8' + struct.pack('<I', n) for n in range(80)) + b'\xc3'
        after = before[:100] * 2 + b'\xc3'
        def image(base, code):
            return SimpleNamespace(bounds=[(base, base + len(code))],
                sections=[SimpleNamespace(VirtualAddress=base, Characteristics=0x20000000,
                                          get_data=lambda: code)],
                get_data=lambda address, size: code[address-base:address-base+size])
        old, new = image(0x1000, before), image(0x4000, after)
        with patch('map_build_functions.pefile.PE', side_effect=[old, new]), patch(
                'map_build_functions.unwind_ranges', side_effect=lambda p: p.bounds):
            result = structural_relocations('reference', 'candidate', [0x1000])['0x1000']
        self.assertEqual(result['candidates'], [])
        self.assertFalse(result['automatic_activation_allowed'])

    def test_effect_vector_ownership_rejects_changed_element_extent(self):
        import json
        import pefile
        from build_hooks import ROOT, UPDATED_HASH
        from enemy_contracts import effect_vector_contract
        from native_helper_contracts import HelperProof
        old = pefile.PE(str(ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'), fast_load=True)
        fixture = ROOT / '_Backup/0.77.6/AzerothSurvivors.exe'
        if not fixture.is_file():
            self.skipTest('0.77.6 regression fixture is not installed')
        new = pefile.PE(str(fixture), fast_load=True)
        structural = json.loads((ROOT / 'analysis/structural-hook-candidates.json').read_text())
        old_ui = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']['UI_COMMAND']['reference_rva']
        from map_build_functions import structural_relocations
        structural = structural_relocations(ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe', fixture, [old_ui])
        new_ui = int(structural[hex(old_ui)]['candidates'][0]['rva'], 16)
        helper = HelperProof(old, new)
        proof = effect_vector_contract(helper, old_ui, new_ui)
        self.assertTrue(proof['scalar_vector_verified'])
        self.assertEqual(proof['candidate_header'], dict(capacity=0x3b8, pointer=0x3c0, count=0x3c8))
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        body = list(decoder.disasm(helper.code(1, proof['candidate']), proof['candidate']))
        i = next(n for n, ins in enumerate(body) if ins.op_str == 'rax, qword ptr [rsi + 0x60]')
        multiply = body[i + 4]
        self.assertEqual((multiply.mnemonic, multiply.op_str), ('shl', 'rax, 3'))
        new.set_bytes_at_rva(multiply.address + multiply.size - 1, b'\x04')
        with self.assertRaises(ValueError):
            effect_vector_contract(HelperProof(old, new), old_ui, new_ui)

    def test_enemy_leaf_uses_reachable_cfg_not_neighbor_function_bytes(self):
        from enemy_contracts import enemy_leaf_contract
        code=bytes.fromhex('80796000 740f 80796001 740c 80796002 7409 b003c3 31c0c3 b001c3 b002c3')
        def image(base,data):
            return SimpleNamespace(get_data=lambda address,size:data[address-base:address-base+size])
        # Adjacent functions differ, but no path from this leaf reaches them.
        old=image(0x1000,code+bytes.fromhex('e800000000c3'))
        new=image(0x2000,code+bytes.fromhex('0f0bc3'))
        proof=enemy_leaf_contract(old,new,0x1000,0x2000)
        self.assertTrue(proof['native_leaf_verified'])
        self.assertEqual(proof['old_end'],0x1000+len(code))
        unsafe=bytes.fromhex('48899188000000')+code
        with self.assertRaisesRegex(ValueError,'unclassified value'):
            enemy_leaf_contract(image(0x1000,unsafe),image(0x2000,unsafe),0x1000,0x2000)

    def test_frame_pointer_liveness_retains_partial_overwrite_bytes(self):
        code=bytes.fromhex('488b5540 c7454000000000 488b4540 0f114540 c3')
        report=frame_value_reads(code,0x1000,0x1000,0x40,8,{})
        self.assertEqual(report['reads'],[{'rva':0x1000,'byte_mask':255},
                                         {'rva':0x100b,'byte_mask':240}])
        self.assertEqual(report['overwrites'],[0x1004,0x100f])

    def test_frame_pointer_liveness_exposes_address_escape(self):
        code=bytes.fromhex('488d4d40 c3')
        report=frame_value_reads(code,0x1000,0x1000,0x40,8,{})
        self.assertEqual(report['address_escapes'],[0x1000])

    def test_simd_overlap_invalidates_private_game_spill(self):
        from map_build_functions import private_frame_slots
        md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
        prefix=bytes.fromhex('55 4881ec00010000 488dac2480000000 48894d40')
        suffix=bytes.fromhex('4881c400010000 5d c3')
        self.assertIn(0x40,private_frame_slots(list(md.disasm(prefix+suffix,0x1000))))
        self.assertNotIn(0x40,private_frame_slots(list(md.disasm(prefix+bytes.fromhex('0f114540')+suffix,0x1000))))

    def test_frame_pointer_liveness_includes_rsp_alias(self):
        code=bytes.fromhex('488dac2480000000 488b8424c0000000 0f118424c0000000 c3')
        report=frame_value_reads(code,0x1000,0x1008,0x40,8,{})
        self.assertEqual(report['reads'],[{'rva':0x1008,'byte_mask':255}])
        self.assertEqual(report['overwrites'],[0x1010])

    def test_paired_store_changes_require_both_game_owners(self):
        old=bytes.fromhex('48898900010000 c3')
        new=bytes.fromhex('48898908010000 c3')
        report=paired_store_fields(old,0x1000,new,0x2000,{}, {})
        self.assertEqual(report['unresolved'],[])
        self.assertEqual(report['changed_game_stores'][0]['candidate_field'],0x108)
        report=paired_store_fields(bytes.fromhex('48898300010000c3'),0x1000,
            bytes.fromhex('48898308010000c3'),0x2000,{}, {})
        self.assertEqual(len(report['unresolved']),1)

    def test_changed_simd_stores_are_inventoried_without_access_metadata(self):
        report=mutation_footprint(bytes.fromhex('c3'),0x1000,
            bytes.fromhex('0f11440810 0f110408 0f100408 c3'),0x2000)
        self.assertEqual([(s['rva'],s['width']) for s in report['stores']],
                         [('0x2000',16),('0x2005',16)])

    def test_ability_copy_preserves_tag_offset_and_complete_payload(self):
        code = bytes.fromhex('488b85a80000004889f948c1e105488b956803000048891408'
            '0f2885900100000f11440808488b95a0010000488954081848ffc74889bdb0000000')
        row, = ability_cast_copies(code, 0x1000)
        self.assertEqual((row['definition_tag_offset'], row['cast_tag_offset'], row['source_bytes']), (0, 8, 24))
        self.assertFalse(row['source_domain_verified'])
        self.assertEqual(ability_cast_copies(code.replace(bytes.fromhex('0f11440808'), bytes.fromhex('0f1144080c')), 0x1000), [])
        self.assertEqual(ability_cast_copies(code.replace(bytes.fromhex('488b95a0010000'), bytes.fromhex('488b95a8010000')), 0x1000), [])

    def test_leaf_return_tag_domain_requires_all_paths(self):
        self.assertEqual(return_tag_values(bytes.fromhex('85c9 7403 b003 c3 31c0 c3'), 0x1000), [0, 3])
        self.assertIsNone(return_tag_values(bytes.fromhex('85c9 7402 b003 c3'), 0x1000))
        self.assertIsNone(return_tag_values(bytes.fromhex('e800000000 b003 c3'), 0x1000))
        self.assertIsNone(return_tag_values(bytes.fromhex('ffe0'), 0x1000))

    def test_pursuit_slice_requires_same_enemy_fields_and_simd_roles(self):
        code = bytes.fromhex('4c8bade0030000f30f108618010000440f2ef073640f28cff30f5c8e14010000'
            'f30f5ec80f57c0f30f5fc1f30f100d4ad94200f30f5dc8f20f1086fc000000f20f109608010000'
            '0f5cd0f3440f12f9440f59fa440f58f8f30f108604010000f3440f10a610010000f3440f5ce0'
            'f3440f59e1f3440f58e0eb12f2440f10be08010000f3440f10a610010000')
        # Include the hook instruction so the boundary is represented.
        suffix = bytes.fromhex('450f28cf440f5c8dd0000000f3450f16e9')
        result = pursuit_live_contract(code+suffix, 0x1000, code+suffix, 0x1000,
            0x1000+len(code), 0x1000+len(code), 0x3e0)
        self.assertTrue(result['local_roles_verified'])
        changed = code.replace(bytes.fromhex('f20f1086fc000000'), bytes.fromhex('f20f1086f4000000'))
        rejected = pursuit_live_contract(code+suffix, 0x1000, changed+suffix, 0x1000,
            0x1000+len(code), 0x1000+len(code), 0x3e0)
        self.assertFalse(rejected['local_roles_verified'])

    def test_mutation_inventory_does_not_invent_heap_ownership(self):
        old = bytes.fromhex('c3')
        # Game-like load followed by a heap pointer store is only a lexical role.
        new = bytes.fromhex('498b85f805000048895008c3')
        report = mutation_footprint(old, 0x1000, new, 0x2000)
        self.assertEqual(report['pointer_width_store_count'], 1)
        self.assertEqual(report['stores'][0]['lexical_base_definition']['rva'], '0x2000')
        self.assertEqual(report['stores'][0]['destination'], 'unproven_heap_owner')
        self.assertFalse(report['complete_owner_proof'])
        self.assertFalse(report['automatic_activation_allowed'])

    def test_mutation_inventory_keeps_call_escape_and_scalar_changes(self):
        old = bytes.fromhex('b901000000c3')
        new = bytes.fromhex('b902000000e800000000f30f114008c3')
        report = mutation_footprint(old, 0x1000, new, 0x2000)
        self.assertEqual(report['calls'][0]['arguments']['rcx']['rva'], '0x2000')
        self.assertEqual(report['stores'][0]['source_kind'], 'scalar_simd')
        self.assertFalse(report['stores'][0]['full_pointer_width'])
        self.assertFalse(report['complete_owner_proof'])

    def test_sse_prefix_does_not_shrink_encoded_address_displacement(self):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        original = bytes.fromhex('660f6f0d1a292501')
        moved = bytes.fromhex('660f6f0ddaea2301')
        self.assertEqual(displacement_size(next(md.disasm(original, 0x1000))), 4)
        self.assertEqual(function_references(original, 0x1000)[0],
                         function_references(moved, 0x2000)[0])
        pattern, mask = instruction_signature(original + b'\x90' * 200, 0x1000)
        self.assertEqual(signature_candidates([(0x2000, moved + b'\x90' * 200)], pattern, mask), [0x2000])

    def test_layout_discovery_exposes_fields_but_does_not_activate(self):
        old = bytes.fromhex('488b8198040000 c3')
        new = bytes.fromhex('488b81a0040000 c3')
        row = compare_function_layout(old, 0x1000, new, 0x2000)
        self.assertTrue(row['structure_equivalent'])
        self.assertFalse(row['automatic_activation_allowed'])
        self.assertEqual([(c['old_offset'], c['new_offset'], c['base']) for c in row['field_changes']],
                         [(0x498, 0x4a0, 'rcx')])

    def test_gameplay_immediates_and_instruction_changes_remain_visible(self):
        old = bytes.fromhex('83b99804000001 c3')
        new = bytes.fromhex('83b9a004000002 c3')
        row = compare_function_layout(old, 0x1000, new, 0x2000)
        self.assertFalse(row['structure_equivalent'])
        self.assertEqual(len(row['instruction_changes']), 1)

    def test_stack_changes_are_marked_separately(self):
        row = compare_function_layout(bytes.fromhex('488b442420c3'), 0x1000,
                                      bytes.fromhex('488b442428c3'), 0x2000)
        self.assertTrue(row['field_changes'][0]['stack'])

    def test_tick_contract_requires_original_server_and_time_arguments(self):
        code = bytes.fromhex('833901 660f28f1 f20f5c4108 f20f117108 '
            '48c781e008000000000000 48c781e808000008000000 48c781f008000000000000 c3')
        self.assertTrue(tick_entry_contract(code, 0x1000)['verified_header'])
        # Same instructions on an unrelated RDX object must not identify TICK.
        changed = bytes.fromhex('488bca') + code
        self.assertFalse(tick_entry_contract(changed, 0x2000)['verified_header'])

    def test_game_alias_survives_in_nonvolatile_register_but_not_rcx_after_call(self):
        code = bytes.fromhex('4889ce e800000000 488b8198040000 488b9698040000 c3')
        uses = list(game_field_uses(code, 0x1000).values())
        self.assertEqual([(u['offset'], u['base']) for u in uses], [(0x498, 'rsi')])

    def test_game_alias_join_requires_every_path_to_agree(self):
        code = bytes.fromhex('4889ce 85c0 7403 4889d6 488b8698040000 c3')
        self.assertEqual(game_field_uses(code, 0x1000), {})

    def test_game_alias_is_lost_on_partial_register_write(self):
        code = bytes.fromhex('4889ce 89c6 488b8698040000 c3')
        self.assertEqual(game_field_uses(code, 0x1000), {})

    def test_unknown_indirect_predecessors_do_not_prove_fields(self):
        code = bytes.fromhex('488b8198040000 ffe2')
        self.assertEqual(game_field_uses(code, 0x1000), {})

    def test_entry_prefix_fields_must_dominate_every_unknown_jump(self):
        code = bytes.fromhex('488b8198040000 ffe2')
        use, = game_field_uses(code, 0x1000, entry_prefix=True).values()
        self.assertTrue(use['entry_prefix'])
        # This field read is skipped on a direct path into the unknown jump.
        conditional = bytes.fromhex('85c0 7407 488b8198040000 ffe2')
        self.assertEqual(game_field_uses(conditional, 0x1000, entry_prefix=True), {})

    def test_lea_proves_only_an_address_not_eight_neighboring_bytes(self):
        use = next(iter(game_field_uses(bytes.fromhex('488d8198040000c3'), 0x1000).values()))
        self.assertTrue(use['address_only'])
        self.assertEqual(use['width'], 1)

    def test_interior_displacement_encoding_shrink_keeps_instruction_roles(self):
        before = bytes.fromhex('488b8598090000') * 18 + b'\xc3'
        after = bytes.fromhex('488b4518') * 18 + b'\xc3'
        row = interior_relocations(before, 0x1000, [(0x2000, after)], [0x1000 + 6 * 7])
        candidate, = row[hex(0x1000 + 6 * 7)]['candidates']
        self.assertEqual(candidate['rva'], hex(0x2000 + 6 * 4))
        self.assertEqual(candidate['supporting_windows'], 2)
        self.assertTrue(candidate['decoded_operands'])
        self.assertTrue(all(c['stack'] for c in candidate['field_changes']))

    def test_hud_local_abi_does_not_claim_server_pointer_ownership(self):
        code = bytes.fromhex('488b95f8000000 4c8b8500010000 '
                             '498b8c24200d0000 498b8424280d0000 ff5020')
        contract, = hud_delivery_contracts(code, 0x1000)
        self.assertEqual(contract['server_register'], 'r12')
        self.assertEqual(contract['receiver_field'], 0xd20)
        self.assertFalse(contract['heap_ownership_verified'])
        self.assertTrue(contract['local_abi_roles'])

    def test_generated_branch_source_inside_original_operand_keeps_explicit_byte_offset(self):
        before = bytes.fromhex('488b8198040000') * 18 + b'\xc3'
        after = bytes.fromhex('488b81a0040000') * 18 + b'\xc3'
        target = 0x1000 + 6 * 7 + 4
        row = interior_relocations(before, 0x1000, [(0x2000, after)], [target])
        candidate, = row[hex(target)]['candidates']
        self.assertEqual(candidate['rva'], hex(0x2000 + 6 * 7 + 4))
        self.assertEqual(candidate['instruction_byte_offset'], 4)

    def test_typed_inventory_includes_small_native_helper_not_game_fields_or_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'boss_rewards.py').write_text('FREE=0x21d0\nRNG=0x818\n')
            (folder / 'party_menu.py').write_text('legacy=0x5390000\nreviewed_rva(0x546f050)\n')
            (folder / 'visibility_bridge.py').write_text(
                'def guest_damage_patches():\n    if UPDATED:\n        return [(0x540b15f, b"x", b"y")]\n'
                '    return [(0x53ff9cf,b"x",b"y")]\n')
            image = SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x8000000))
            rows = typed_reviewed_references(folder, image)
            self.assertEqual({r['rva'] for r in rows}, {0x21d0, 0x546f050, 0x540b15f})

    def test_invariant_nonvolatile_game_copy_covers_indirect_cases(self):
        code = bytes.fromhex('4889cf ffe0 488b8798040000 5f c3')
        use, = stable_game_field_uses(code, 0x1000).values()
        self.assertTrue(use['invariant_nonvolatile'])
        self.assertEqual(use['offset'], 0x498)

    def test_reassigned_or_partially_overwritten_game_copy_is_not_invariant(self):
        for change in ('4889d7', '89c7'):
            code = bytes.fromhex('4889cf ffe0 ' + change + ' 488b8798040000 5f c3')
            self.assertEqual(stable_game_field_uses(code, 0x1000), {})

    def test_pop_then_reuse_does_not_qualify_as_terminal_epilogue(self):
        code = bytes.fromhex('4889cf ffe0 5f 488b8798040000 c3')
        self.assertEqual(stable_game_field_uses(code, 0x1000), {})


    def test_batch_contract_requires_serializer_and_preserves_ui_vector(self):
        code = bytearray()
        def call(target):
            code.extend(b'\xe8' + struct.pack('<i', target - (0x1000 + len(code) + 5)))
        call(0x2000)
        code.extend(bytes.fromhex('488b8e90000000 4883c110 488b95f8000000 4c8b8500010000'))
        call(0x3000)
        code.extend(bytes.fromhex('488b4510 488b7518 488b7d20 488d147f 488d0cd6 c3'))
        row, = batch_write_contracts(code, 0x1000, 0x2000, 0x3000)
        self.assertEqual(row['ui_vector']['element_size'], 24)
        self.assertEqual(row['packet_buffer_stack_offset'], 0xf8)
        self.assertEqual(batch_write_contracts(code, 0x1000, 0x2001, 0x3000), [])

    def test_server_vector_requires_unsigned_bound_and_matching_header(self):
        code = bytes.fromhex('498d8c2418090000 493b842428090000 7300 498b942420090000 '
                             '4869c0b0000000 488b940288000000 4883c210 90 90 c3')
        row, = server_vector_contracts(code, 0x1000)
        self.assertEqual((row['pointer_field'], row['element_size']), (0x920, 0xb0))
        self.assertFalse(row['heap_ownership_verified'])
        self.assertEqual(server_vector_contracts(code.replace(b'\x73\x00', b'\x72\x00'), 0x1000), [])

    def test_embedded_game_requires_unique_frame_slot_writer(self):
        code = bytearray.fromhex('498d442410 48898530020000 4c8bbd30020000 4c89f9 0f28c8')
        code.extend(b'\xe8' + struct.pack('<i', 0x4000 - (0x1000 + len(code) + 5)))
        row, = embedded_game_contracts(code, 0x1000, 0x4000)
        self.assertEqual((row['game_offset'], row['server_register']), (0x10, 'r12'))
        self.assertFalse(row['heap_ownership_verified'])
        code.extend(bytes.fromhex('48898530020000'))
        self.assertEqual(embedded_game_contracts(code, 0x1000, 0x4000), [])

    def test_saved_game_frame_keeps_reload_fields_conditional(self):
        code = bytes.fromhex('488d6c2480 4989cd 4c89ad e0030000 '
                             '488bb5 e0030000 8b86 b8040000 c3')
        frame, = saved_game_frame_contracts(code, 0x1000)
        self.assertEqual(frame['stack_offset'], 0x3e0)
        self.assertEqual(frame['reloads'][0]['fields'][0]['offset'], 0x4b8)
        self.assertIn('each field use', frame['reloads'][0]['runtime_precondition'])
        self.assertFalse(frame['automatic_activation_allowed'])
        self.assertEqual(saved_game_frame_contracts(code + bytes.fromhex('488985 e0030000'), 0x1000), [])

    def test_saved_game_frame_rejects_entry_bypass_or_owner_overwrite(self):
        prefix = bytes.fromhex('488d6c2480 4989cd')
        spill = bytes.fromhex('4c89ad e0030000 c3')
        self.assertEqual(saved_game_frame_contracts(prefix + bytes.fromhex('eb07') + spill, 0x1000), [])
        self.assertEqual(saved_game_frame_contracts(prefix + bytes.fromhex('4589c5') + spill, 0x1000), [])

    def test_private_game_spill_survives_call_and_restores_typed_alias(self):
        code = bytes.fromhex('488dac2480000000 48894db8 e800000000 488b75b8 488b8640070000 c3')
        uses = game_field_uses(code, 0x1000)
        self.assertIn(0x740, {u['offset'] for u in uses.values()})
        # Address-taking permits a callee to overwrite the spill, so reject it.
        escaped = code.replace(bytes.fromhex('e800000000'), bytes.fromhex('488d4db8 e800000000'))
        self.assertNotIn(0x740, {u['offset'] for u in game_field_uses(escaped, 0x1000).values()})

    def test_spill_alias_requires_all_paths_and_one_unaliased_write(self):
        prefix = bytes.fromhex('488dac2480000000')
        spill = bytes.fromhex('48894db8')
        load = bytes.fromhex('488b75b8 488b8640070000 c3')
        for code in (prefix + bytes.fromhex('85c0 7404') + spill + load,
                     prefix + spill + bytes.fromhex('488955b8') + load,
                     prefix + spill + bytes.fromhex('50') + load):
            self.assertNotIn(0x740, {u['offset'] for u in game_field_uses(code, 0x1000).values()})

    def test_indexed_frame_read_does_not_clobber_private_spill(self):
        prefix = bytes.fromhex('488dac2480000000 48894db8')
        tail = bytes.fromhex('e800000000 488b75b8 488b8640070000 c3')
        read = bytes.fromhex('488b5ccdb8')
        self.assertIn(0x740, {u['offset'] for u in game_field_uses(prefix + read + tail, 0x1000).values()})
        for unsafe in (bytes.fromhex('48895ccdb8'), bytes.fromhex('488d5ccdb8')):
            self.assertNotIn(0x740, {u['offset'] for u in game_field_uses(prefix + unsafe + tail, 0x1000).values()})

    def test_ability_source_bounds_keeps_exact_stride_and_tag_payload(self):
        builtin = bytes.fromhex('4883f9020f870e700000488d14c9488d3c524801cf488d0d2f022601f30f10443918f3410f59c1')
        boss = bytes.fromhex('4c8d04c94f8d04404901c8f3420f59440218f30f1100488b4630488b50184839d10f83906d0000488b40104a8b4c001048898da0010000420f1004000f298590010000')
        fixed, = ability_source_bounds(builtin, 0x1000)
        variable, = ability_source_bounds(boss, 0x2000)
        self.assertEqual((fixed['count'], fixed['stride']), (3, 28))
        self.assertEqual((variable['payload_slot'], variable['payload_bytes']), (0x190, 24))
        self.assertFalse(variable['producer_control_flow_verified'])
        self.assertEqual(ability_source_bounds(builtin.replace(bytes.fromhex('83f902'), bytes.fromhex('83f903')), 0x1000), [])
        self.assertEqual(ability_source_bounds(boss.replace(bytes.fromhex('4f8d0440'), bytes.fromhex('4f8d0448')), 0x2000), [])
        self.assertEqual(ability_source_bounds(boss.replace(bytes.fromhex('a0010000'), bytes.fromhex('a8010000')), 0x2000), [])

    def test_damage_dispatch_requires_guard_and_exact_paired_targets(self):
        code = bytes.fromhex('0fb69ef800000085db410f94c648837e40000f94c083beec000000000f94c120c10fb686dc010000340120c80f57c0410f2ec2721d89d9488d15367e250148630c8a4801d189c2ffe1c3')
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        def fixture(base, raw=code, bad_target=False):
            ins = list(md.disasm(raw, base))
            lea = next(i for i in ins if i.mnemonic == 'lea')
            table = lea.address + lea.size + lea.operands[1].mem.disp
            target = ins[-1].address + int(bad_target)
            data = struct.pack('<4i', *([target-table]*4))
            section = SimpleNamespace(Characteristics=0x40000000, VirtualAddress=table, Misc_VirtualSize=16)
            return SimpleNamespace(get_section_by_rva=lambda _: section, get_data=lambda a,n:data[:n]), ins
        a, before = fixture(0x540cfe8)
        b, after = fixture(0x540cfe8+0x2000)
        old_edges, new_edges, tables, guards = conditional_damage_switch(a,b,before,after)
        self.assertEqual((len(old_edges),len(new_edges),len(tables)), (1,1,1))
        self.assertEqual((guards[0]['new_offset'],guards[0]['maximum']), (0xf8,3))
        self.assertTrue(guards[0]['mandatory_before_every_adapter_call'])
        self.assertFalse(guards[0]['native_global_domain_proven'])
        changed, decoded = fixture(0x540cfe8+0x2000, bad_target=True)
        with self.assertRaisesRegex(ValueError, 'branches changed'):
            conditional_damage_switch(a,changed,before,decoded)
        changed, decoded = fixture(0x540cfe8+0x2000, code.replace(bytes.fromhex('85db'),bytes.fromhex('31db')))
        with self.assertRaisesRegex(ValueError, 'tag is modified'):
            conditional_damage_switch(a,changed,before,decoded)

    def test_private_game_spill_requires_proved_disjoint_frame_borrow(self):
        code = bytes.fromhex('488dac2480000000 48898d78010000 4989e8 e800000000 488bb578010000 0fb69ef8000000 c3')
        copy = 0x1000 + 15
        self.assertNotIn(0xf8, {u['offset'] for u in game_field_uses(code, 0x1000).values()})
        uses = game_field_uses(code, 0x1000, frame_borrows={copy: 12})
        self.assertIn(0xf8, {u['offset'] for u in uses.values()})
        overlapping = game_field_uses(code, 0x1000, frame_borrows={copy: 0x180})
        self.assertNotIn(0xf8, {u['offset'] for u in overlapping.values()})
        with self.assertRaisesRegex(ValueError, 'frame-borrow'):
            game_field_uses(code, 0x1000, frame_borrows={copy+1:12})
        with self.assertRaisesRegex(ValueError, 'frame-borrow'):
            game_field_uses(code, 0x1000, frame_borrows={copy:0})

    def test_private_spill_survives_restored_external_tail_exit_only(self):
        code=bytes.fromhex('554883ec20488d6c242048894d08e800000000488b7508488b86100200004883c4205de900100000')
        uses=game_field_uses(code,0x1000)
        self.assertIn(0x210,{u['offset'] for u in uses.values()})
        # An internal branch after POP RBP can re-enter live code with a changed
        # frame pointer, so it cannot validate private spills.
        bad=code[:-4]+struct.pack('<i',0x1000-(0x1000+len(code)))
        self.assertNotIn(0x210,{u['offset'] for u in game_field_uses(bad,0x1000).values()})

    def test_changed_store_owner_requires_all_predecessor_definitions(self):
        def proof(code):
            md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
            md.detail=True
            ins=list(md.disasm(code,0x1000))
            stores=[dict(rva=hex(i.address),destination='unproven_heap_owner',width=i.operands[0].size)
                    for i in ins if i.mnemonic=='mov' and i.operands[0].type==capstone.x86.X86_OP_MEM]
            return changed_store_owners(code,0x1000,{},stores)
        owner=bytes.fromhex('4889ce 488b8600030000')
        store=bytes.fromhex('c7402400000000 c3')
        row,=proof(owner+store)['stores']
        self.assertEqual((row['kind'],row['pointer_field'],row['member_offset']),('game_vector_member',0x300,0x24))
        changed=proof(owner+bytes.fromhex('85d274034889d0')+store)
        self.assertFalse(changed['all_destinations_classified'])
        self.assertEqual(changed['stores'][0]['kind'],'unresolved')
        allocated=proof(bytes.fromhex('b920000000ba01000000e800000000c7400400000000c3'))
        self.assertEqual(allocated['stores'][0]['kind'],'allocation_body')
        self.assertTrue(allocated['stores'][0]['requires_allocator_return_contract'])

    def test_region_collection_never_falls_back_or_covers_gaps(self):
        old=SimpleNamespace(get_data=lambda a,n:bytes.fromhex('90909090c3')[a-0x1000:a-0x1000+n])
        new=SimpleNamespace(get_data=lambda a,n:bytes.fromhex('90909090c3')[a-0x2000:a-0x2000+n])
        region=dict(old_start=0x1000,old_end=0x1005,new_start=0x2000,new_end=0x2005,
                    admitted=True,contract_id='guarded-native-region')
        proof=collect_region_inputs(old,new,[region],[0x1001,0x3000],[(0x1000,'90909090c3')])
        self.assertEqual(proof['addresses'][0]['candidate'],0x2001)
        self.assertEqual(proof['patches'][0]['candidate_bytes'],'90909090c3')
        self.assertEqual(proof['unresolved_inputs'],[dict(kind='address',reference=0x3000)])
        fragments=[dict(region,old_end=0x1002,new_end=0x2002),
                   dict(region,old_start=0x1003,new_start=0x2003)]
        proof=collect_region_inputs(old,new,fragments,[],[(0x1000,'90909090c3')])
        self.assertEqual(proof['patches'],[])
        self.assertEqual(proof['unresolved_inputs'][0]['kind'],'patch')
        with self.assertRaisesRegex(ValueError,'admitted'):
            collect_region_inputs(old,new,[dict(region,admitted=False)],[],[])

    def test_pointer_immediate_needs_owned_full_width_base(self):
        code = bytes.fromhex('4989ce 4981c640080000 4881c218080000 c3')
        uses = game_field_uses(code, 0x1000, pointer_immediates=True)
        pointer, = [u for u in uses.values() if u.get('pointer_immediate')]
        self.assertEqual((pointer['offset'], pointer['base'], pointer['width']), (0x840, 'r14', 1))
        self.assertTrue(pointer['address_only'])

    def test_conditional_pointer_offset_does_not_claim_ownership(self):
        rows = pointer_offset_candidates(bytes.fromhex('4981c640080000'), 0x1000,
                                         bytes.fromhex('4981c648080000'), 0x2000)
        row, = rows
        self.assertEqual((row['register'], row['old_offset'], row['new_offset']), ('r14', 0x840, 0x848))
        self.assertFalse(row['heap_ownership_verified'])
        self.assertFalse(row['automatic_activation_allowed'])
        self.assertEqual(pointer_offset_candidates(bytes.fromhex('4181c640080000'), 0x1000,
                                                   bytes.fromhex('4181c648080000'), 0x2000), [])

    def test_explicit_rdx_game_contract_does_not_mark_output_rcx(self):
        code = bytes.fromhex('4889d7 488b8fdc060000 488b8120070000 c3')
        fields = game_field_uses(code, 0x1000, entry_register='rdx')
        self.assertEqual({u['offset'] for u in fields.values()}, {0x6dc})

    def test_object_frame_store_requires_same_address_register(self):
        code = bytes.fromhex('498d85e8050000 488985c8030000')
        row, = object_frame_stores(code, 0x1000).values()
        self.assertEqual((row['object_register'], row['field_offset'], row['stack_offset']), ('r13', 0x5e8, 0x3c8))
        self.assertEqual(object_frame_stores(bytes.fromhex('498d85e8050000 488995c8030000'), 0x1000), {})

    def test_generated_restore_dependencies_require_both_paired_vector_slots(self):
        old = [dict(stack_register='rbp', stack_offset=0x3e0)]
        new = [dict(stack_register='rbp', stack_offset=0x3f0)]
        stores = [dict(old=dict(field_offset=member, stack_offset=slot, stack_register='rbp'),
                       new=dict(field_offset=member + 8, stack_offset=slot + 16, stack_register='rbp'))
                  for member, slot in ((0x5e8, 0x3c8), (0x600, 0x80))]
        result = restore_game_frame_contract(old, new, stores)
        self.assertTrue(result['local_dependencies_complete'])
        self.assertFalse(result['automatic_activation_allowed'])
        self.assertFalse(restore_game_frame_contract(old, new, stores[:1])['local_dependencies_complete'])
        self.assertFalse(restore_game_frame_contract(old, new, stores,
            ((0x5e8, 0x3c8), (0x5a0, 0x120)))['local_dependencies_complete'])

    def test_region_rejects_changed_internal_branch_even_when_masked_bytes_match(self):
        old = bytes.fromhex('85c0 7401 90 c3')
        result = region_instruction_contract(old, 0x1000, old, 0x2000)
        self.assertTrue(result['internal_control_flow'])
        changed = region_instruction_contract(old, 0x1000, bytes.fromhex('85c0 7400 90 c3'), 0x2000)
        self.assertTrue(changed['instruction_roles'])
        self.assertFalse(changed['internal_control_flow'])

    def test_region_scalar_change_is_not_a_relocation(self):
        result = region_instruction_contract(bytes.fromhex('83c001 c3'), 0x1000,
                                             bytes.fromhex('83c002 c3'), 0x2000)
        self.assertFalse(result['instruction_roles'])

    def test_region_pointer_change_remains_conditional_until_owner_probe(self):
        result = region_instruction_contract(bytes.fromhex('4881c0e8050000 c3'), 0x1000,
                                             bytes.fromhex('4881c0f0050000 c3'), 0x2000)
        self.assertFalse(result['instruction_roles'])
        self.assertTrue(result['conditional_instruction_roles'])
        self.assertTrue(result['internal_control_flow'])
        self.assertEqual(result['conditional_pointer_immediates'][0]['register'], 'rax')

    def test_stack_pairs_keep_base_and_access_width(self):
        rows = stack_field_pairs(bytes.fromhex('488b8530010000 488d8580000000'), 0x1000,
                                 bytes.fromhex('488b8540010000 488d8590000000'), 0x2000)
        self.assertEqual([(r['old_offset'], r['new_offset'], r['width']) for r in rows],
                         [(0x130, 0x140, 8), (0x80, 0x90, 1)])

    def test_anchored_failure_block_keeps_callee_explicit_and_requires_trap(self):
        def image(base, size=32, terminal=b'\x0f\x0b'):
            data = bytearray(b'\x90' * 96)
            code = bytes.fromhex('b901000000 ba') + struct.pack('<I', size)
            code += b'\xe8' + struct.pack('<i', base + 0x1000 - (base + 15)) + bytes.fromhex('90 eb2e')
            data[:len(code)] = code
            data[64:64 + len(terminal)] = terminal
            return SimpleNamespace(get_data=lambda rva, count: bytes(data[rva-base:rva-base+count]))
        proof = anchored_trap_contract(image(0x1000), 0x1000, image(0x2000), 0x2000)
        self.assertTrue(proof['terminal_trap'])
        self.assertEqual(proof['call_dependencies'][0]['new_target'], '0x3000')
        self.assertIsNone(anchored_trap_contract(image(0x1000), 0x1000, image(0x2000, size=33), 0x2000))
        self.assertIsNone(anchored_trap_contract(image(0x1000), 0x1000, image(0x2000, terminal=b'\xc3'), 0x2000))

    def test_conditional_memory_site_is_declared_and_does_not_claim_live_owner(self):
        old = bytes.fromhex('f30f1086d0020000')
        new = bytes.fromhex('f30f1086d8020000')
        row, = conditional_game_accesses(old, 0x1000, new, 0x2000, {0x2d0})
        self.assertEqual((row['register'], row['old_offset'], row['new_offset'], row['width']), ('rsi', 0x2d0, 0x2d8, 4))
        self.assertFalse(row['heap_ownership_verified'])
        self.assertEqual(conditional_game_accesses(old, 0x1000, new, 0x2000, {0x4b8}), [])
        self.assertEqual(conditional_game_accesses(old, 0x1000, bytes.fromhex('f30f1087d8020000'), 0x2000, {0x2d0}), [])

if __name__ == '__main__':
    unittest.main()

