import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'analysis'), str(ROOT / '.tools/python')]
import capstone
import pefile
from build_hooks import UPDATED_HASH
from effect_contracts import dispatch, compare_effect_paths, shield_stack_branch, native_effect_contract
from map_build_functions import game_field_uses


class EffectContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe').read_bytes()
        cls.entry = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']['APPLY_EFFECT']['reference_rva']

    def test_changed_unforwarded_case_is_outside_contract(self):
        old = pefile.PE(data=self.data, fast_load=True)
        before = dispatch(old, self.entry)
        proof = compare_effect_paths(old, old, before, before)
        instruction = next(i for i in before['decoded'].values() if hex(i.address) not in proof['instruction_map']
                           and i.mnemonic == 'cmp' and i.imm_size == 1)
        data = bytearray(self.data)
        data[old.get_offset_from_rva(instruction.address) + instruction.imm_offset] ^= 1
        new = pefile.PE(data=bytes(data), fast_load=True)
        changed = compare_effect_paths(old, new, before, dispatch(new, self.entry))
        self.assertTrue(changed['called_paths_equivalent'])
        self.assertLess(changed['reachable_instructions'], len(before['decoded']))

    def test_changed_reachable_constant_is_rejected(self):
        old = pefile.PE(data=self.data, fast_load=True)
        before = dispatch(old, self.entry)
        proof = compare_effect_paths(old, old, before, before)
        instruction = next(i for i in before['decoded'].values() if hex(i.address) in proof['instruction_map']
                           and i.mnemonic == 'cmp' and i.imm_size == 1)
        data = bytearray(self.data)
        data[old.get_offset_from_rva(instruction.address) + instruction.imm_offset] ^= 1
        new = pefile.PE(data=bytes(data), fast_load=True)
        with self.assertRaisesRegex(ValueError, 'constant or enum changed'):
            compare_effect_paths(old, new, before, dispatch(new, self.entry))

    def test_enum_target_change_is_rejected(self):
        old = pefile.PE(data=self.data, fast_load=True)
        before = dispatch(old, self.entry)
        data = bytearray(self.data)
        struct.pack_into('<i', data, old.get_offset_from_rva(before['table'] + 2 * 4),
                         before['cases'][1] - before['table'])
        new = pefile.PE(data=bytes(data), fast_load=True)
        with self.assertRaises(ValueError):
            compare_effect_paths(old, new, before, dispatch(new, self.entry))

    def test_game_alias_flow_requires_proved_case_edges(self):
        code = bytes.fromhex('4889ceffe0f30f104610c3')  # RSI=Game, dispatch, read Game+10.
        self.assertEqual(game_field_uses(code, 0x100), {})
        uses = game_field_uses(code, 0x100, indirect_edges={0x103: [0x105]})
        self.assertEqual(uses[(0x105, 1)]['offset'], 0x10)
        with self.assertRaisesRegex(ValueError, 'Invalid proved'):
            game_field_uses(code, 0x100, indirect_edges={0x103: [0x106]})

    def test_nested_call_arguments_only_report_proven_game_aliases(self):
        arguments = {}
        # RDX borrows Game, RCX becomes a scalar before the native call.
        code = bytes.fromhex('4889ca31c9e800000000c3')
        game_field_uses(code, 0x100, call_arguments=arguments)
        self.assertEqual(arguments[0x105], {'rdx': 0})
        # An interior pointer is retained as an offset, never promoted to Game.
        game_field_uses(bytes.fromhex('488d5110e800000000c3'), 0x200, call_arguments=arguments)
        self.assertEqual(arguments[0x204]['rdx'], 0x10)

    def test_native_shield_contract_covers_all_cases_and_owned_vector(self):
        # Locate the changed entry through the same structural resolver used by
        # production; this test never embeds a candidate-build address.
        from map_build_functions import structural_relocations
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        binary = ROOT / '_Backup/0.77.6/AzerothSurvivors.exe'
        if not binary.is_file():
            self.skipTest('0.77.6 regression fixture is not installed')
        candidates = structural_relocations(reference, binary, [self.entry])[hex(self.entry)]['candidates']
        self.assertEqual(len(candidates), 1)
        candidate = int(candidates[0]['rva'], 16)
        proof = native_effect_contract(reference, binary, self.entry, candidate)
        self.assertTrue(proof['native_effect_contract_verified'])
        self.assertEqual(proof['native_tags'], list(range(11)))
        self.assertEqual(proof['guard_instruction']['borrowed_size'], 12)
        self.assertTrue(proof['guard_instruction']['mandatory'])
        self.assertEqual(proof['shield']['scalar_vector_stride'], 24)
        self.assertFalse(proof['vector']['element_destructors'])
        self.assertTrue(proof['new_scalar_layout_obligations'])
        image = pefile.PE(str(binary), fast_load=True)
        model = dispatch(image, candidate, range(11))
        owner = {'vector_' + key: value for key, value in proof['vector']['candidate_header'].items()}
        # An arbitrary pointer-sized publication must not masquerade as copying
        # the scalar effect's last four bytes into the native element.
        store = next(ins for ins in model['decoded'].values()
                     if ins.mnemonic == 'mov' and ins.op_str == 'dword ptr [rax + rdx*8 + 8], r9d')
        changed = bytearray(binary.read_bytes())
        offset = image.get_offset_from_rva(store.address)
        changed[offset] |= 8  # REX.W changes this store into an eight-byte write.
        mutated = pefile.PE(data=bytes(changed), fast_load=True)
        with self.assertRaisesRegex(ValueError, 'Unclassified shield instruction'):
            shield_stack_branch(mutated, dispatch(mutated, candidate, range(11)), owner)
        # A duplicate branch that bypasses the capacity/reserve path is rejected.
        model['decoded'] = dict(model['decoded'])
        search = next(ins for ins in model['decoded'].values()
                      if ins.mnemonic == 'jne' and ins.address in proof['shield']['instructions'])
        changed = bytearray(binary.read_bytes())
        changed[image.get_offset_from_rva(search.address) + search.imm_offset] ^= 1
        mutated = pefile.PE(data=bytes(changed), fast_load=True)
        with self.assertRaises(ValueError):
            shield_stack_branch(mutated, dispatch(mutated, candidate, range(11)), owner)


if __name__ == '__main__':
    unittest.main()
