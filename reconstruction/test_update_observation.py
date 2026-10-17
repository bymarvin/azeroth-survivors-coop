"""Observation candidates cannot activate co-op or call gameplay code."""
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import build_hooks
import native_probe
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'analysis'))


class UpdateObservationTests(unittest.TestCase):
    def test_discovery_only_publishes_nonactivating_observation_report(self):
        self.discovery_case()

    def test_ambiguous_entry_does_not_publish_or_activate(self):
        self.discovery_case(ambiguous=True)

    def test_missing_tick_contract_does_not_publish_or_activate(self):
        self.discovery_case(header=False)

    def discovery_case(self, ambiguous=False, header=True):
        import map_build_functions
        reference, candidate = b'reference', b'candidate'
        reference_hash = hashlib.sha256(reference).hexdigest()
        targets = {'TICK': 0x1000, 'SERIALIZE': 0x2000, 'WRITE': 0x3000}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            baseline = root / '.coop-builds' / reference_hash
            baseline.mkdir(parents=True)
            (baseline / 'AzerothSurvivors.exe').write_bytes(reference)
            binary = root / 'new.exe'
            binary.write_bytes(candidate)
            (root / 'reconstruction').mkdir()
            (root / 'reconstruction/reviewed-hooks.json').write_text(json.dumps(
                dict(hooks={name: dict(reference_rva=rva) for name, rva in targets.items()})))
            (root / 'analysis').mkdir()
            active = root / 'analysis/active-hooks.json'
            active.write_text('preserve verified profile')
            rows = {hex(rva): dict(candidates=[dict(rva=hex(rva), structure_equivalent=True)])
                    for rva in targets.values()}
            if ambiguous:
                rows['0x2000']['candidates'].append(dict(rva='0x2010', structure_equivalent=True))
            def get_data(address, length):
                return (b'\x41\x57' if address == 0x2000 else b'\x55')[:length]
            image = SimpleNamespace(get_data=get_data, OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x5000))
            with patch.object(build_hooks, 'ROOT', root), patch.object(build_hooks, 'UPDATED_HASH', reference_hash), \
                    patch.object(build_hooks.pefile, 'PE', return_value=image), \
                    patch.object(map_build_functions, 'unwind_ranges', return_value=[(v, v + 16) for v in targets.values()]), \
                    patch.object(map_build_functions, 'structural_relocations', return_value=rows), \
                    patch.object(map_build_functions, 'tick_entry_contract', return_value=dict(verified_header=header)):
                if ambiguous or not header:
                    with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
                        build_hooks.discover_observation_profile(binary)
                    self.assertFalse((root / 'analysis/observation-candidate.json').exists())
                else:
                    result = build_hooks.discover_observation_profile(binary)
                    self.assertFalse(result['automatic_activation_allowed'])
                    self.assertEqual(result['status'], 'observation_only')
                    self.assertEqual(set(result['hooks']), set(targets))
                    self.assertEqual(json.loads((root / 'analysis/observation-candidate.json').read_text()), result)
            self.assertEqual(active.read_text(), 'preserve verified profile')
            self.assertFalse((root / 'analysis/previous-verified-hooks.json').exists())

    def test_observer_rejects_gameplay_calls_and_executable_adapters_before_writes(self):
        native = object.__new__(native_probe.Native)
        native.put = Mock()
        with patch.object(native_probe, 'OBSERVE_UPDATE', True), patch.object(native_probe, 'allocate') as allocate:
            with self.assertRaisesRegex(ValueError, 'cannot invoke'):
                native.call_before(bytearray(1232), native_probe.DAMAGE, 0)
            with self.assertRaisesRegex(ValueError, 'cannot install'):
                native.executable_buffer(b'\xc3')
            allocate.assert_not_called()
            native.put.assert_not_called()

    def test_runner_requires_exact_observer_and_bounded_single_disposable_launch(self):
        observer = native_probe.UpdateObservation(io.StringIO(), 'unused')
        with patch.object(native_probe, 'OBSERVE_UPDATE', True), patch.object(native_probe, 'Native') as launch:
            for seconds, players, callback, numbers in [
                    (25, 1, lambda *args: None, None), (25, 2, observer, None),
                    (301, 1, observer, None), (4, 1, observer, None), (25, 1, observer, [1])]:
                with self.subTest(seconds=seconds, players=players, numbers=numbers):
                    with self.assertRaisesRegex(ValueError, 'bounded disposable'):
                        native_probe.run(seconds, players, callback, player_numbers=numbers)
            launch.assert_not_called()

    def test_observer_only_reads_header_and_keeps_registers_unchanged(self):
        output = io.StringIO()
        observer = native_probe.UpdateObservation(output, 'unused')
        context = bytearray(1232)
        struct.pack_into('<Q', context, 128, 0x100000)
        struct.pack_into('<Q', context, 152, 0x200008)
        before = bytes(context)
        client = SimpleNamespace(memory=Mock(return_value=struct.pack('<I4xd', 1, 10.0)),
                                 put=Mock(), patch=Mock(), call_before=Mock(), executable_buffer=Mock())
        observer(client, native_probe.TICK, context)
        observer(client, native_probe.WRITE, context)
        observer(client, native_probe.SERIALIZE, context)
        client.memory.assert_called_once_with(0x100000, 16)
        for method in (client.put, client.patch, client.call_before, client.executable_buffer):
            method.assert_not_called()
        self.assertEqual(bytes(context), before)
        self.assertEqual(observer.hits, dict(TICK=1, SERIALIZE=1, WRITE=1))
        self.assertNotIn('body', output.getvalue())

    def test_observed_contract_violations_fail_instead_of_counting_as_pass(self):
        for stack, flag, timestamp in [(0x200000, 1, 10.0), (0x200008, 9, 10.0),
                                       (0x200008, 1, float('nan'))]:
            observer = native_probe.UpdateObservation(io.StringIO(), 'unused')
            context = bytearray(1232)
            struct.pack_into('<Q', context, 152, stack)
            client = SimpleNamespace(memory=Mock(return_value=struct.pack('<I4xd', flag, timestamp)))
            with self.subTest(stack=stack, flag=flag, timestamp=timestamp):
                with self.assertRaisesRegex(ValueError, 'contract'):
                    observer(client, native_probe.TICK, context)

    def test_hud_observation_checks_owner_before_emulating_original_call(self):
        observer = native_probe.UpdateObservation(io.StringIO(), 'unused')
        observer.hud = dict(server_register='r12', receiver_field=32, vtable_field=40)
        observer.hits['HUD_DELIVER'] = 0
        context = bytearray(1232)
        for offset, value in {120: 0x3000, 128: 0x4000, 152: 0x5000, 216: 0x1000}.items():
            struct.pack_into('<Q', context, offset, value)
        reads = {0x1020: 0x4000, 0x1028: 0x3000, 0x3020: 0x6000}
        client = SimpleNamespace(server=0x1000, base=0x100000,
            memory=Mock(side_effect=lambda address, size: struct.pack('<Q', reads[address])), put=Mock())
        observer(client, native_probe.HUD_DELIVER, context)
        client.put.assert_called_once_with(0x4ff8, struct.pack('<Q', client.base + native_probe.HUD_DELIVER + 3))
        self.assertEqual(native_probe.q(context, 248), 0x6000)
        client.put.reset_mock()
        struct.pack_into('<Q', context, 152, 0x5000)
        client.server = 0x2000
        with self.assertRaisesRegex(ValueError, 'does not belong'):
            observer(client, native_probe.HUD_DELIVER, context)
        client.put.assert_not_called()

    def test_batch_observation_validates_connection_and_frame_without_writes(self):
        observer = native_probe.UpdateObservation(io.StringIO(), 'unused')
        observer.batch = dict(return_rva='0x100', connection_register='rsi', queue_field=144,
            queue_offset=16, packet_stack_register='rbp', packet_buffer_stack_offset=248,
            packet_length_stack_offset=256, ui_vector=dict(stack_register='rbp', capacity=16, pointer=24, count=32))
        observer.connections = dict(server_register='r12', capacity_field=32, pointer_field=40,
                                    count_field=48, element_size=176)
        context = bytearray(1232)
        for offset, value in {128:0x7010, 136:0x8000, 152:0x5008, 160:0x6000,
                              168:0x4000, 184:40, 216:0x1000}.items():
            struct.pack_into('<Q', context, offset, value)
        memory = {0x5008:0x100100, 0x1020:4, 0x1028:0x4000, 0x1030:1,
                  0x4090:0x7000, 0x60f8:0x8000, 0x6100:40, 0x6010:0, 0x6020:0}
        client = SimpleNamespace(server=0x1000, base=0x100000, put=Mock(),
                                 memory=Mock(side_effect=lambda a,s:struct.pack('<Q',memory[a])))
        original = bytes(context)
        observer(client, native_probe.WRITE, context)
        self.assertEqual(observer.batch_hits, 1)
        self.assertEqual(bytes(context), original)
        client.put.assert_not_called()
        memory[0x1028] = 0x4001
        with self.assertRaisesRegex(ValueError, 'outside'):
            observer(client, native_probe.WRITE, context)

    def test_field_probe_requires_game_and_frame_ownership_and_restores_instruction(self):
        observer = native_probe.UpdateObservation(io.StringIO(), 'unused')
        observer.game_contract = dict(game_offset=16)
        observer.game_frame = dict(stack_register='rbp', stack_offset=40)
        observer.sites = {0x800: dict(kind='game_field', base='rsi', old_rva='0x700', new_rva='0x800',
                                    old_offset=100, new_offset=108, width=4, address_only=False)}
        context = bytearray(1232)
        struct.pack_into('<Q', context, 168, 0x1010)
        struct.pack_into('<Q', context, 160, 0x2000)
        original = bytes(context)
        client = SimpleNamespace(server=0x1000, observed_game=0x1010, disable_hooks=set(), put=Mock(),
                                 memory=Mock(return_value=struct.pack('<Q', 0x1010)))
        observer(client, 0x800, context)
        self.assertEqual(client.disable_hooks, {0x800})
        self.assertEqual(bytes(context), original)
        client.put.assert_not_called()
        client.memory.assert_called_once_with(0x2028, 8)
        client.disable_hooks.clear()
        struct.pack_into('<Q', context, 168, 0x1018)
        with self.assertRaisesRegex(ValueError, 'does not belong'):
            observer(client, 0x800, context)
        self.assertFalse(client.disable_hooks)

    def test_incomplete_cli_observation_explicitly_fails_without_passed_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'analysis').mkdir()
            stdout = io.StringIO()
            with patch.object(native_probe, 'ROOT', root), patch.object(native_probe, 'OBSERVE_UPDATE', True), \
                    patch.object(native_probe, 'run'), patch.object(sys, 'argv', ['native_probe.py', '--observe-update']), \
                    patch('sys.stdout', stdout):
                with self.assertRaisesRegex(RuntimeError, 'observation incomplete'):
                    native_probe.main()
            self.assertNotIn('passed', stdout.getvalue())
            rows = [json.loads(line) for line in (root / 'analysis/update-observation.jsonl').read_text().splitlines()]
            self.assertTrue(rows)
            self.assertTrue(all(row['automatic_activation_allowed'] is False for row in rows))

    def test_pointer_probe_checks_pre_add_owner_without_using_other_functions_frame(self):
        observer = native_probe.UpdateObservation(io.StringIO(), 'unused')
        observer.game_contract = dict(game_offset=16)
        observer.sites = {0x800: dict(kind='game_pointer', base='r14', old_rva='0x700', new_rva='0x800',
                                    old_offset=100, new_offset=108, width=1, address_only=True)}
        context = bytearray(1232)
        struct.pack_into('<Q', context, 232, 0x1010)
        original = bytes(context)
        client = SimpleNamespace(server=0x1000, observed_game=0x1010, disable_hooks=set(), put=Mock(), memory=Mock())
        observer(client, 0x800, context)
        self.assertEqual(client.disable_hooks, {0x800})
        self.assertEqual(bytes(context), original)
        client.memory.assert_not_called()
        client.put.assert_not_called()
        struct.pack_into('<Q', context, 232, 0x1018)
        with self.assertRaisesRegex(ValueError, 'does not belong'):
            observer(client, 0x800, context)

    def test_unproved_operand_on_another_object_is_recorded_as_rejected(self):
        output = io.StringIO()
        observer = native_probe.UpdateObservation(output, 'unused')
        observer.game_contract = dict(game_offset=16)
        observer.sites = {0x800: dict(kind='game_candidate_field', base='r14', old_rva='0x700', new_rva='0x800',
                                    old_offset=100, new_offset=108, width=4, address_only=False)}
        context = bytearray(1232)
        client = SimpleNamespace(server=0x1000, observed_game=0x1010, disable_hooks=set(), put=Mock(), memory=Mock())
        original = bytes(context)
        observer(client, 0x800, context)
        self.assertFalse(json.loads(output.getvalue())['owner_verified'])
        self.assertEqual(bytes(context), original)
        self.assertEqual(client.disable_hooks, {0x800})
        client.memory.assert_not_called()
        client.put.assert_not_called()


if __name__ == '__main__':
    unittest.main()
