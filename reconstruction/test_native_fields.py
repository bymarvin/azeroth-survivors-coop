"""Typed native fields must never rewrite stack, enemy or wire offsets."""
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import updated_layout as layout


class NativeFieldTests(unittest.TestCase):
    def test_bootstrap_progress_never_reads_unconstructed_game(self):
        from visibility_bridge import native_progress_state
        from unittest.mock import Mock
        client = SimpleNamespace(server=0x1000, memory=Mock(side_effect=AssertionError('Uninitialized Game')))
        self.assertEqual(native_progress_state(client, False), (0, 1, 0, 0))
        client.memory.assert_not_called()
        client.memory.side_effect = [struct.pack('<II', 7, 12), b'\x02', struct.pack('<I', 3)]
        self.assertEqual(native_progress_state(client, True), (2, 7, 12, 3))

    def test_configure_rejects_unconstructed_typed_profiles(self):
        with patch.object(layout, '_runtime', None):
            for profile in ({}, {'adapter_contracts_verified': True}):
                with self.assertRaisesRegex(ValueError, 'verified profile'):
                    layout.configure(SimpleNamespace(profile=profile, exact_addresses={}))
            self.assertIsNone(layout._runtime)

    def test_real_builders_inventory_requires_runtime_only_dependencies(self):
        from analysis.inventory_native_contracts import runtime_inputs
        report = runtime_inputs()
        self.assertFalse(report['automatic_activation_allowed'])
        self.assertIn(0x540AC40, report['addresses'])  # Injected DAMAGE callee.
        self.assertIn(0x6664B18, report['addresses'])  # Runtime melee lookup.
        self.assertIn(('game', 0x4B8), report['fields'])  # Runtime shared gold.
        self.assertIn(('server', 0x918), report['fields'])
        self.assertTrue(report['patches'])
        self.assertTrue(report['identity'])
        self.assertTrue(report['dynamic_source_inputs'])  # Never claim total coverage.

    def test_source_inventory_includes_typed_fields_generated_code_and_addresses(self):
        from analysis.inventory_native_contracts import inventory
        report = inventory()
        kinds = {row['kind'] for row in report['occurrences']}
        self.assertTrue({'typed_field', 'typed_code', 'reviewed_address'} <= kinds)
        self.assertFalse(report['automatic_activation_allowed'])
        self.assertTrue(all(row['status'] == 'classification_required' for row in report['occurrences']))

    def test_missing_field_evidence_is_rejected_except_full_image_equivalence(self):
        with patch.object(layout, 'UPDATED', True):
            with patch.object(layout, '_runtime', SimpleNamespace(profile={})), self.assertRaises(ValueError):
                layout.field('game', 0x818)
            with patch.object(layout, '_runtime', SimpleNamespace(profile={'runtime_equivalent': True})):
                self.assertEqual(layout.field('game', 0x818), 0x818)
            with patch.object(layout, '_runtime', SimpleNamespace(profile={}, field=lambda *args: None)), self.assertRaises(ValueError):
                layout.field('game', 0x818)

    def test_game_displacement_changes_but_equal_stack_displacement_does_not(self):
        code = bytes.fromhex('488b8618080000 488b8518080000 c3')
        resolver = lambda domain, offset: {('game', 0x818): 0x848}[domain, offset]
        with patch.object(layout, 'UPDATED', True), patch.object(layout, '_runtime', SimpleNamespace(field=resolver)):
            after = layout.code_fields(code, 'game', {'rsi'})
        self.assertEqual(after, bytes.fromhex('488b8648080000 488b8518080000 c3'))

    def test_changed_instruction_width_and_incomplete_code_fail_closed(self):
        with patch.object(layout, 'UPDATED', True), patch.object(layout, '_runtime', SimpleNamespace(field=lambda *args: 0x100)):
            with self.assertRaises(ValueError):
                layout.code_fields(bytes.fromhex('488b4608'), 'game', {'rsi'})
            with self.assertRaises(ValueError):
                layout.code_fields(bytes.fromhex('488b'), 'game', {'rsi'})

    def test_sse_prefix_keeps_full_encoded_displacement_width(self):
        code = bytes.fromhex('660f6f8618080000')  # movdqa xmm0,[rsi+818h]
        with patch.object(layout, 'UPDATED', True), patch.object(layout, '_runtime', SimpleNamespace(field=lambda *args: 0x123456)):
            after = layout.code_fields(code, 'game', {'rsi'})
        self.assertEqual(after, bytes.fromhex('660f6f8656341200'))

    def test_baseline_generated_code_identical_and_typed_changes_are_selective(self):
        from boss_rewards import reward_code
        from visibility_bridge import downed_world_code, downed_hazards_code, pursuit_code, world_containers_code
        builders = [lambda: reward_code(0x140000000), lambda: downed_world_code(0x140000000, 0x100000),
                    lambda: downed_hazards_code(0x140000000), lambda: pursuit_code(0x140000000, 0x100000, 3),
                    world_containers_code]
        with patch.object(layout, 'UPDATED', True), patch.object(layout, '_runtime', None):
            before = [build() for build in builders]
        runtime = SimpleNamespace(profile={'runtime_equivalent': True}, rva=lambda address: address)
        with patch.object(layout, 'UPDATED', True), patch.object(layout, '_runtime', runtime):
            self.assertEqual([build() for build in builders], before)
        fields = {}
        # Use identity for this synthetic manifest except one exact typed field.
        def field(domain, offset):
            fields[domain, offset] = True
            return 0x8df if (domain, offset) == ('game', 0x8cf) else offset
        runtime.field = field
        with patch.object(layout, 'UPDATED', True), patch.object(layout, '_runtime', runtime):
            after = [build() for build in builders]
        self.assertEqual(after[0], before[0])  # Boss RNG/rewards have no phase operand.
        self.assertEqual(after[1], before[1])
        self.assertNotEqual(after[2], before[2])
        self.assertNotEqual(after[3], before[3])
        self.assertEqual(after[4], before[4])
        self.assertIn(('game', 0x818), fields)
        self.assertIn(('game', 0x648), fields)
        self.assertIn(('game', 0x8cf), fields)
        self.assertNotIn(('game', 0x3e0), fields)  # Native TICK frame, not Game.
        self.assertNotIn(('game', 0x340), fields)  # Native frame delta-time local.
        self.assertIn(('game_update_frame', 0x3e0), fields)
        self.assertIn(('game_update_frame', 0x340), fields)


if __name__ == '__main__':
    unittest.main()
