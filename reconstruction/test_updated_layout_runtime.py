"""Adapter generators must use the configured address map, not reviewed literals."""
import struct
import unittest
from unittest.mock import patch

import updated_layout as layout
from visibility_bridge import downed_world_code, guest_damage_patches


class MappedRuntime:
    profile = dict(runtime_equivalent=True)

    def __init__(self):
        self.preconditions = []

    def rva(self, address):
        return address + (0x1000 if address < 0x5400000 else 0x2000)

    def expected_bytes(self, address, expected):
        self.preconditions.append((address, expected))
        return b'\xcc' * len(expected)

    def relative_branch(self, source, target, *, opcode=b'\xe9', size=5):
        return layout.branch_bytes(self.rva(source), self.rva(target), opcode=opcode, size=size)


class LayoutRuntimeTests(unittest.TestCase):
    def test_short_branches_keep_exact_range_and_fail_without_a_trampoline(self):
        self.assertEqual(layout.branch_bytes(0x53BEAD1, 0x53BEB4A, opcode=b'\xeb', size=2), b'\xeb\x77')
        self.assertEqual(layout.branch_bytes(0x1000, 0x1081, opcode=b'\x75', size=2), b'\x75\x7f')
        self.assertEqual(layout.branch_bytes(0x1000, 0xF82, opcode=b'\xeb', size=2), b'\xeb\x80')
        for target in (0x1082, 0xF81):
            with self.assertRaises(ValueError):
                layout.branch_bytes(0x1000, target, opcode=b'\xeb', size=2)

    def test_configured_addresses_reach_generated_operands_and_patch_guards(self):
        runtime = MappedRuntime()
        with patch.object(layout, 'UPDATED', True), patch.object(layout, '_runtime', None):
            layout.configure(runtime)
            self.assertEqual(layout.rva(0x53DC9F5), runtime.rva(0x53E7625))
            self.assertEqual(layout.phase_gate(), b'\xcc' * 6)
            code = downed_world_code(0x140000000, 0xDEADBEEF)
            self.assertIn(struct.pack('<Q', 0x140000000 + runtime.rva(0x53F5808)), code)
            self.assertIn(struct.pack('<Q', 0x140000000 + runtime.rva(0x581C4AC)), code)
            # visibility_bridge keeps its own imported build flag.
            with patch('visibility_bridge.UPDATED', True):
                patches = guest_damage_patches()
            self.assertEqual([row[0] for row in patches],
                             [runtime.rva(address) for address in (0x540B73A, 0x540B15F, 0x540BA5C, 0x540C2C7, 0x540CFAC)])
            self.assertTrue(all(original == b'\xcc' * len(original) for _, original, _ in patches))
            self.assertEqual(patches[2][2][4:], runtime.relative_branch(0x540BA60, 0x540BDD7))
            self.assertEqual(layout.branch(0x53FF52B, 0x5402BF3, opcode=b'\x0f\x85', size=6),
                             runtime.relative_branch(0x540ACBB, 0x540E4CD, opcode=b'\x0f\x85', size=6))
            self.assertTrue(runtime.preconditions)

    def test_legacy_stays_identity_and_unverified_configuration_fails(self):
        runtime = MappedRuntime()
        with patch.object(layout, 'UPDATED', False), patch.object(layout, '_runtime', runtime):
            self.assertEqual(layout.rva(0x53DC9F5), 0x53DC9F5)
            self.assertEqual(layout.phase_gate(), bytes.fromhex('0f85add90000'))
            self.assertEqual(runtime.preconditions, [])
        runtime.profile = dict(runtime_equivalent=False)
        with self.assertRaises(ValueError):
            layout.configure(runtime)


if __name__ == '__main__':
    unittest.main()
