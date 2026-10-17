"""Candidate calls require native return, native UI output and normal exit."""
import io
import json
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import native_probe as native


class UpdateCallTests(unittest.TestCase):
    def test_effect_guard_bounds_borrowed_argument_without_changing_flags(self):
        guard = dict(rva=0x200, expected='418b00', base='r8', destination='eax',
                     offset=0, width=4, maximum=10, mandatory=True)
        context = bytearray(1232)
        struct.pack_into('<Q', context, 184, 0x6000)
        struct.pack_into('<Q', context, 120, 0xffffffffffffffff)
        struct.pack_into('<I', context, 68, 0x246)
        client = SimpleNamespace(base=0x1000, memory=Mock(return_value=struct.pack('<I', 7) + bytes(8)))
        self.assertEqual(native.emulate_effect_tag_guard(client, context, guard), 7)
        client.memory.assert_called_once_with(0x6000, 12)
        self.assertEqual(native.q(context, 120), 7)
        self.assertEqual(native.q(context, 248), 0x1203)
        self.assertEqual(struct.unpack_from('<I', context, 68)[0], 0x246)
        client.memory.return_value = struct.pack('<I', 11) + bytes(8)
        with self.assertRaisesRegex(ValueError, 'unverified effect tag'):
            native.emulate_effect_tag_guard(client, context, guard)
        with self.assertRaisesRegex(ValueError, 'instruction roles'):
            native.emulate_effect_tag_guard(client, context, dict(guard, expected='418b08'))

    def test_production_bootstrap_guards_reject_wrong_hud_and_connection_owners(self):
        context = bytearray(1232)
        memory = {0x6010: 0x9000, 0x6018: 0xa000, 0x6020: 0xb000, 0x6028: 1, 0x6030: 1}
        client = SimpleNamespace(server=0x6000, base=0x1000,
                                 memory=lambda address, size: struct.pack('<Q', memory[address]))
        contracts = dict(hud=dict(server_register='r12', receiver_field=16, vtable_field=24),
                         batch={}, connection=dict(pointer_field=32, count_field=40,
                                                    capacity_field=48, element_size=176))
        for offset, value in ((216, 0x6000), (128, 0x9000), (120, 0xa000)):
            struct.pack_into('<Q', context, offset, value)
        native.validate_bootstrap_owner(client, native.HUD_DELIVER, context, contracts)
        struct.pack_into('<Q', context, 216, 0x6008)
        with self.assertRaisesRegex(ValueError, 'HUD receiver'):
            native.validate_bootstrap_owner(client, native.HUD_DELIVER, context, contracts)
        struct.pack_into('<Q', context, 128, 0xb000)
        native.validate_bootstrap_owner(client, native.SERIALIZE, context, contracts)
        struct.pack_into('<Q', context, 128, 0xb001)
        self.assertFalse(native.validate_bootstrap_owner(client, native.SERIALIZE, context, contracts))
        memory[0x6028] = 0  # A login-local connection is not in the vector yet.
        self.assertFalse(native.validate_bootstrap_owner(client, native.SERIALIZE, context, contracts))
        memory[0x6028] = 2
        with self.assertRaisesRegex(ValueError, 'allocation bounds'):
            native.validate_bootstrap_owner(client, native.SERIALIZE, context, contracts)

    def test_damage_preparation_uses_bounded_native_xp_until_trigger_is_learned(self):
        observer = native.UpdateCallTest.__new__(native.UpdateCallTest)
        observer.damage_contract = {'guard_trigger': {'abilities': [{'title': 'Bloodrage'}]}}
        observer.entries = {'AWARD_XP': {'entry': 123}}
        observer.damage_preparation_awards = 0
        observer.record = Mock()
        state = dict(phase=1, pending_talents=0, level=3, xp=6)
        observer.progression_state = Mock(return_value=state)
        observer.progression_abilities = Mock(return_value={})
        client = SimpleNamespace(call_before=Mock())
        self.assertFalse(observer.prepare_damage_guard(client, None, 0x6000))
        self.assertEqual(client.call_before.call_args.args, (None, 123, 0x6000, 100))
        observer.progression_state.return_value = dict(state, level=4)
        client.call_before.call_args.kwargs['after']()
        self.assertIsNone(observer.pending)
        observer.progression_abilities.return_value = {'Bloodrage': 1}
        self.assertTrue(observer.prepare_damage_guard(client, None, 0x6000))
        self.assertEqual(client.call_before.call_count, 1)
        observer.progression_abilities.return_value = {}
        observer.damage_preparation_awards = 16
        with self.assertRaisesRegex(ValueError, 'within16'):
            observer.prepare_damage_guard(client, None, 0x6000)

    def test_persistent_damage_guard_emulates_only_owned_bounded_movzx(self):
        contract = dict(rva=0x200, expected='0fb69ef8000000', base='rsi', destination='ebx',
                        offset=0xf8, mandatory=True, maximum=3)
        client = SimpleNamespace(base=0x1000, observed_game=0x6000,
                                 memory=Mock(return_value=b'\x03'))
        context = bytearray(1232)
        struct.pack_into('<Q', context, 168, 0x6000)
        struct.pack_into('<Q', context, 144, 0xffffffffffffffff)
        struct.pack_into('<I', context, 68, 0x246)
        self.assertEqual(native.emulate_damage_tag_guard(client, context, contract), 3)
        self.assertEqual(native.q(context, 144), 3)
        self.assertEqual(native.q(context, 248), 0x1207)
        self.assertEqual(struct.unpack_from('<I', context, 68)[0], 0x246)
        client.memory.assert_called_once_with(0x60f8, 1)
        client.memory.return_value = b'\x04'
        before = bytes(context)
        with self.assertRaisesRegex(ValueError, 'unverified source tag'):
            native.emulate_damage_tag_guard(client, context, contract)
        self.assertEqual(bytes(context), before)
        struct.pack_into('<Q', context, 168, 0x6008)
        with self.assertRaisesRegex(ValueError, 'captured Game'):
            native.emulate_damage_tag_guard(client, context, contract)
        with self.assertRaisesRegex(ValueError, 'roles changed'):
            native.emulate_damage_tag_guard(client, context, dict(contract, expected='8b9ef8000000'))

    def test_boss_argument_comes_from_current_map_and_bounded_native_array(self):
        contract = dict(fields=dict(map_pointer=dict(offset=8, width=8), map_length=dict(offset=16, width=8)),
            map_table=dict(candidate=0x100, map_count=1, rows=[dict(names=['elwynn'], bosses=[dict(name='Boss')])]),
            boss_argument=dict(map_stride=160, array_pointer=64, array_count=72, count=5, stride=88, ordinal=0),
            boss_definition=dict(name_pointer=0, name_length=8, entry_id=48, display_id=52))
        memory = {0x6008:struct.pack('<Q', 0x8000), 0x6010:struct.pack('<Q', 6), 0x8000:b'elwynn',
                  0x1140:struct.pack('<Q', 0x2000), 0x1148:struct.pack('<Q', 5),
                  0x2000:struct.pack('<Q', 0x3000), 0x2008:struct.pack('<Q', 4), 0x3000:b'Boss',
                  0x2030:struct.pack('<I', 123), 0x2034:struct.pack('<I', 456)}
        client = SimpleNamespace(base=0x1000, memory=lambda address, size: memory[address])
        boss = native.candidate_boss_definition(client, 0x6000, contract)
        self.assertEqual(boss, dict(pointer=0x2000, name='Boss', map='elwynn', entry=123, display=456))
        memory[0x1148] = struct.pack('<Q', 6)
        with self.assertRaisesRegex(ValueError, 'immutable bounds'):
            native.candidate_boss_definition(client, 0x6000, contract)
        memory[0x8000] = b'unknown'
        with self.assertRaisesRegex(ValueError, 'unique proved'):
            native.candidate_boss_definition(client, 0x6000, contract)

    def test_pause_pair_requires_both_outputs_and_normal_exit(self):
        entries = {name: dict(entry=entry, game_phase_offset=100, initial_phase=initial,
                    final_phase=final, output_json={'type': message})
                   for name, entry, initial, final, message in
                   [('PAUSE', 10, 1, 3, 'paused'), ('RESUME', 20, 3, 1, 'unpaused')]}
        with patch.object(native, '_profile', dict(candidate_call_contract=dict(entries=entries))):
            observer = native.UpdateCallTest(io.StringIO(), 'disposable')
        observer.batch_hits = 1
        observer.batch = dict(return_rva='0x80', ui_vector=dict(stack_register='rbp', element_size=24, pointer=8, count=16))
        observer.game_contract = dict(game_offset=16)
        context = bytearray(1232)
        struct.pack_into('<Q', context, 152, 0x1000)
        struct.pack_into('<Q', context, 160, 0x2000)
        state = dict(phase=1, body=b'')
        def memory(address, size):
            values = {0x1000:struct.pack('<Q', 0x4080), 0x2008:struct.pack('<Q', 0x3000),
                      0x2010:struct.pack('<Q', int(bool(state['body']))),
                      0x3000:struct.pack('<QQQ', len(state['body']), 0x5000, len(state['body'])),
                      0x5000:state['body'], 0x6064:bytes([state['phase']])}
            self.assertEqual(len(values[address]), size)
            return values[address]
        def call(context, entry, game, after):
            self.assertEqual(game, 0x6000)
            state['phase'] = 3 if entry == 10 else 1
            after()
        client = SimpleNamespace(base=0x4000, server=0x5ff0, observed_game=0x6000,
                                 memory=memory, call_before=Mock(side_effect=call))
        with patch.object(native.UpdateObservation, '__call__'):
            observer(client, native.WRITE, context)
            self.assertEqual(observer.returned, {'PAUSE'})
            self.assertFalse(observer.calls_complete)
            observer(client, native.WRITE, context)
            self.assertEqual(client.call_before.call_count, 1)
            state['body'] = json.dumps({'type':'paused'}).encode()
            observer(client, native.WRITE, context)
            self.assertEqual(observer.returned, {'PAUSE', 'RESUME'})
            self.assertFalse(observer.calls_complete)
            state['body'] = json.dumps({'type':'unpaused'}).encode()
            observer(client, native.WRITE, context)
            self.assertTrue(observer.calls_complete)
            self.assertFalse(observer.clean_exit)
            observer.native_exited(client, 0)
            self.assertTrue(observer.clean_exit)

    def test_candidate_mode_rejects_unadmitted_call_and_nonowned_argument(self):
        client = native.Native.__new__(native.Native)
        client.observed_game = 0x6000
        client.memory = Mock()
        profile = dict(candidate_call_contract=dict(entries={'PAUSE':dict(entry=10)}))
        with patch.object(native, 'TEST_UPDATE_CALLS', True), patch.object(native, '_profile', profile):
            for entry, argument in [(11, 0x6000), (10, 0x6008)]:
                with self.assertRaisesRegex(ValueError, 'outside the isolated'):
                    client.call_before(bytearray(1232), entry, argument)
        client.memory.assert_not_called()

    def test_progression_requires_native_ability_matching_the_ui_offer(self):
        progression = dict(fields={}, choice_stride=112,
            choice_title=dict(capacity=0, pointer=8, length=16, max_bytes=1024),
            pending_by_choice_kind={0:'pending_talents'}, ability_contract=dict(
            new_rank=1, offered_ui=dict(kind='new', title_prefix='New: ')))
        with patch.object(native, '_profile', dict(candidate_call_contract=dict(entries={
                'CHOOSE': dict(entry=20)}), progression_call_contract=progression)):
            observer = native.UpdateCallTest(io.StringIO(), 'disposable')
        state = dict(phase=2, choices_count=1, choices_pointer=0x1000, choice_kind=0, pending_talents=1)
        after = dict(state, phase=1, choices_count=0, pending_talents=0)
        label = b'New: Whirlwind'
        offer = struct.pack('<QQQ', len(label), 0x3000, len(label)) + bytes(88)
        client = SimpleNamespace(memory=Mock(side_effect=lambda address, size: label if address == 0x3000 else offer))
        client.call_before = Mock(side_effect=lambda context, entry, game, index, after: after())
        for actual, succeeds in [({'Wrong ability': 1}, False), ({'Whirlwind': 1}, True)]:
            observer.offered_ui = [dict(kind='new', title='New: Whirlwind')]
            with patch.object(observer, 'progression_state', side_effect=[state, after]), \
                    patch.object(observer, 'progression_abilities', side_effect=[{}, actual]):
                if succeeds:
                    observer.check_progression(client, bytearray(1232), 0x6000)
                else:
                    with self.assertRaisesRegex(ValueError, 'does not match'):
                        observer.check_progression(client, bytearray(1232), 0x6000)
        self.assertEqual(len(observer.progression_choices), 1)
        self.assertTrue(observer.progression_choices[0]['output_verified'])
        self.assertFalse(observer.progression_complete)

    def test_upgrade_rank_counts_native_stats_instead_of_displayed_rank(self):
        progression = dict(fields={}, choice_stride=112,
            choice_title=dict(capacity=0, pointer=8, length=16, max_bytes=1024),
            pending_by_choice_kind={0: 'pending_talents'}, ability_contract=dict(
                new_rank=1, offered_ui=dict(kind='new', title_prefix='New: '),
                upgrade_ui=dict(kind='upgrade', title_format='{name} rank {rank}', rank_delta=1,
                    rank_delta_source=dict(choice_capacity_offset=72, choice_pointer_offset=80, choice_count_offset=88,
                        ability_index_offset=96, element_size=1, allowed_tags=list(range(5))))))
        with patch.object(native, '_profile', dict(candidate_call_contract=dict(entries={
                'CHOOSE': dict(entry=20)}), progression_call_contract=progression)):
            observer = native.UpdateCallTest(io.StringIO(), 'disposable')
        state = dict(phase=2, choices_count=1, choices_pointer=0x1000, choice_kind=0, pending_talents=1)
        after = dict(state, phase=1, choices_count=0, pending_talents=0)
        label = b'Shield Slam rank 2'
        offer = bytearray(112)
        struct.pack_into('<QQQ', offer, 0, len(label), 0x3000, len(label))
        struct.pack_into('<QQQ', offer, 80, 0x4000, 2, 0)
        struct.pack_into('<Q', offer, 72, 8)
        client = SimpleNamespace(memory=lambda address, size:
            label if address == 0x3000 else b'\x00\x01' if address == 0x4000 else offer)
        client.call_before = Mock(side_effect=lambda context, entry, game, index, after: after())
        for actual, succeeds in [(2, False), (3, True)]:
            observer.offered_ui = [dict(kind='upgrade', title=label.decode(), rank=2)]
            with patch.object(observer, 'progression_state', side_effect=[state, after]), \
                    patch.object(observer, 'progression_abilities', side_effect=[{'Shield Slam': 1}, {'Shield Slam': actual}]):
                if succeeds:
                    observer.check_progression(client, bytearray(1232), 0x6000)
                else:
                    with self.assertRaisesRegex(ValueError, 'does not match'):
                        observer.check_progression(client, bytearray(1232), 0x6000)
        self.assertEqual(observer.progression_choices[0]['expected_rank'], 3)


if __name__ == '__main__':
    unittest.main()
