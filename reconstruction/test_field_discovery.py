"""Typed field evidence must not turn into a blanket displacement shift."""
import unittest
from runtime_addresses import game_field_candidates, observed_game_field_candidates


class FieldDiscoveryTests(unittest.TestCase):
    def test_access_spans_address_only_ambiguity_and_unobserved_fields(self):
        def method(offset, destination, access):
            return {'game_field_evidence': {'method': 'test', 'fields': [dict(
                old_offset=offset, new_offset=destination, width=16,
                memory_access=access, old_rva='0x100', new_rva='0x200')]}}
        rows = game_field_candidates({'a': method(100, 108, True),
                                      'b': method(120, 128, False)}, [100, 108, 116, 120, 121])
        self.assertEqual(rows['0x6c']['candidates'], [116])
        self.assertEqual(rows['0x74']['candidates'], [])
        self.assertEqual(rows['0x78']['candidates'], [128])
        self.assertEqual(rows['0x79']['candidates'], [])
        ambiguous = game_field_candidates({'a': method(100, 108, True),
                                           'b': method(100, 116, True)}, [100])
        self.assertFalse(ambiguous['0x64']['unique'])
        self.assertEqual(ambiguous['0x64']['candidates'], [108, 116])

    def test_owned_operands_in_changed_function_map_fields_not_gameplay(self):
        proof = {'candidate_game_field_evidence': {'method': 'changed', 'fields': [dict(
            old_offset=100, new_offset=108, width=8, address_only=False, access=1,
            old_rva='0x100', new_rva='0x200')]},
            'conditional_pointer_immediates': [dict(old_offset=120, new_offset=128)]}
        rows = game_field_candidates({'changed': proof}, [100, 120])
        self.assertEqual(rows['0x64']['candidates'], [108])
        self.assertEqual(rows['0x78']['candidates'], [])
        self.assertNotIn('automatic_activation_allowed', rows['0x64'])

    def test_observation_must_match_exact_operand_and_keep_conflicts(self):
        use = dict(old_rva='0x100', new_rva='0x200', old_offset=100, new_offset=108,
                   width=4, address_only=False)
        functions = {'a': dict(reload_game_field_candidates=[use])}
        observation = dict(status='passed', field_observations=[dict(use, owner_verified=True)])
        self.assertEqual(observed_game_field_candidates(functions, [101], observation)['0x65']['candidates'], [109])
        for key, value in [('new_rva', '0x201'), ('width', 8), ('owner_verified', False)]:
            changed = dict(status='passed', field_observations=[dict(observation['field_observations'][0], **{key:value})])
            self.assertFalse(observed_game_field_candidates(functions, [100], changed)['0x64']['unique'])
        functions['b'] = dict(game_field_evidence=dict(method='static', fields=[dict(use, new_offset=116)]))
        self.assertFalse(observed_game_field_candidates(functions, [100], observation)['0x64']['unique'])


if __name__ == '__main__':
    unittest.main()
