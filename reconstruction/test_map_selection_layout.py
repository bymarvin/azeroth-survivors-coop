"""Offline regressions: moved map fields are evidence, never activation."""
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'analysis'))
from menu_contracts import map_selection_contract


def image(entry, stride, name_offset):
    table = entry + 0x1000
    prefix = bytes.fromhex('b9090000004839c87318')
    multiply = (bytes.fromhex('488d048048c1e005') if stride == 160
                else bytes.fromhex('4869c0') + struct.pack('<I', stride))
    lea = bytes.fromhex('488d0d') + struct.pack('<i', table - (entry + len(prefix) + len(multiply) + 7))
    loads = (bytes.fromhex('4c8b3c08488b5c0808') if name_offset == 0
             else bytes.fromhex('4c8b7c0808488b5c0810'))
    code = prefix + multiply + lea + loads + b'\xc3'
    data = bytearray(0x1000)
    for index in range(9):
        name = f'map{index}'.encode()
        offset = 0x900 + 8 * index
        data[offset:offset + len(name)] = name
        struct.pack_into('<QQ', data, index * stride + name_offset, table + offset, len(name))
    section = SimpleNamespace(VirtualAddress=table, Misc_VirtualSize=len(data), Characteristics=0)
    result = SimpleNamespace(entry=entry, code=bytearray(code), table=table, data=data,
                             section=section, OPTIONAL_HEADER=SimpleNamespace(ImageBase=0))
    result.get_data = lambda a, n: bytes(result.code[a-entry:a-entry+n] if entry <= a < entry + len(code)
                                       else result.data[a-table:a-table+n])
    result.get_section_by_rva = lambda a: section if table <= a < table + len(data) else None
    return result


class MapSelectionLayoutTests(unittest.TestCase):
    def prove(self, before, after):
        with patch('menu_contracts.unwind_ranges', side_effect=lambda p: [(p.entry, p.entry + len(p.code))]):
            return map_selection_contract(before, before.entry, after, after.entry)

    def test_changed_stride_and_name_offsets_require_all_nine_names(self):
        old, new = image(0x1000, 160, 0), image(0x4000, 184, 8)
        proof = self.prove(old, new)
        self.assertTrue(proof['map_name_lookup_verified'])
        self.assertFalse(proof['automatic_activation_allowed'])
        self.assertEqual(proof['candidate_layout']['stride'], 184)
        self.assertEqual(proof['candidate_layout']['name_pointer'], 8)
        new.data[0x900 + 8 * 8] = ord('X')
        with self.assertRaisesRegex(ValueError, 'identity or order'):
            self.prove(old, new)

    def test_unchanged_layout_still_passes(self):
        self.assertTrue(self.prove(image(0x1000, 160, 0), image(0x4000, 160, 0))['map_name_lookup_verified'])

    def test_rule_branch_and_record_extent_mutations_fail(self):
        old = image(0x1000, 160, 0)
        for offset, value in ((1, 10), (9, 23), (13, 192), (28, 16)):
            new = image(0x4000, 184, 8)
            new.code[offset] = value
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.prove(old, new)

    def test_writable_or_truncated_map_records_fail(self):
        for attribute, value in (('Characteristics', 0x80000000), ('Misc_VirtualSize', 9 * 184 - 1)):
            new = image(0x4000, 184, 8)
            setattr(new.section, attribute, value)
            with self.subTest(attribute=attribute), self.assertRaises(ValueError):
                self.prove(image(0x1000, 160, 0), new)

    def test_branch_into_rewritten_lookup_cannot_be_hidden_by_normalization(self):
        old, new = image(0x1000, 160, 0), image(0x4000, 184, 8)
        old.code[9] = new.code[9] = 4  # Old SHL boundary is inside the new IMUL.
        with self.assertRaisesRegex(ValueError, 'interior'):
            self.prove(old, new)


if __name__ == '__main__':
    unittest.main()
