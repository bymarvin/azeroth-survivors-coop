import io
import os
import struct
from pathlib import Path
from types import SimpleNamespace
import unittest
import tempfile
from unittest.mock import patch

import build_hooks
import pefile
from native_input_contracts import discover_native_key_diagnostic, native_key_code, key_function, release_cleanup, repeat_press_entry
from verify_native_input import NativeMovementDiagnostic, NativeDepartureDiagnostic, NativeMenuDiagnostic

ROOT = Path(__file__).resolve().parents[1]


class NativeInputTests(unittest.TestCase):
    def test_actual_key_contract_and_inconsistent_decoder_rejected(self):
        reference = ROOT / '.coop-builds' / build_hooks.UPDATED_HASH / 'AzerothSurvivors.exe'
        contract = discover_native_key_diagnostic(reference, ROOT / 'AzerothSurvivors.exe')
        self.assertEqual(contract['expected'], 'bbffffffff41b601')
        self.assertEqual(contract['replacement'], 'bb2a00000041b600')
        self.assertFalse(contract['movement_verified'])
        self.assertEqual(set(contract['probes']), {'entry', 'parsed_key', 'press', 'release'})
        self.assertEqual(len({row['rva'] for row in contract['probes'].values()}), 4)
        self.assertEqual(contract['hold_seconds'], 2.0)
        self.assertEqual(contract['tap_gate']['point_stride'], 8)
        self.assertEqual(contract['tap_gate']['count_stack'], 0x298)
        self.assertEqual(contract['touch_release']['expected'], '49c70700000000')
        self.assertEqual(contract['touch_release']['hold_seconds'], .2)
        image = pefile.PE(str(ROOT / 'AzerothSurvivors.exe'), fast_load=True)
        decoded = key_function(image)[2]
        index, cleanup = release_cleanup(decoded)
        self.assertEqual(cleanup, contract['release_cleanup'])
        press_index, press = repeat_press_entry(decoded)
        self.assertEqual(press, contract['repeat_press'])
        changed_press = list(decoded)
        changed_press[press_index + 8] = SimpleNamespace(mnemonic='mov', op_str='rdi, qword ptr [rbp + 0xe8]', address=decoded[press_index + 8].address)
        with self.assertRaisesRegex(ValueError, 'reloads its window writer'):
            repeat_press_entry(changed_press)
        changed = list(decoded)
        changed[index] = SimpleNamespace(mnemonic='mov', op_str='rdx, qword ptr [rbp + 0x2b0]', address=decoded[index].address)
        with self.assertRaisesRegex(ValueError, 'owned-string cleanup'):
            release_cleanup(changed)
        value, evidence = native_key_code(image)
        self.assertEqual(value, 42)
        self.assertGreaterEqual(len(evidence), 2)
        # Mutate one native named-key scalar store to a different tag.
        site = evidence[0]['store']
        image.set_bytes_at_rva(site + 2, (43).to_bytes(4, 'little'))
        with self.assertRaisesRegex(ValueError, 'inconsistent'):
            native_key_code(image)

    def test_normal_session_cannot_enable_native_input(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'isolated profile'):
                NativeMovementDiagnostic()
            with self.assertRaisesRegex(ValueError, 'isolated exact input'):
                NativeDepartureDiagnostic(None, lambda: True)
            with self.assertRaisesRegex(ValueError, 'isolated exact input'):
                NativeMenuDiagnostic(None, '605,605')

    def test_menu_tap_waits_for_native_picker_and_host_then_stops_on_ack(self):
        driver = object.__new__(NativeMenuDiagnostic)
        events = []
        driver.bridge = SimpleNamespace(host_map=None, record=lambda **event: events.append(event),
                                       poll_network=lambda: None, _menu_enter_observed=False)
        driver.contract = dict(tap_gate=dict(rva=20, cleanup=30, producer=40, count_stack=0x298,
                               points_stack=0x290, point_stride=8, elapsed_xmm=6, scheduled_xmm=7),
                               touch_release=dict(rva=50))
        driver.points = [(605.0, 605.0)]
        driver.installed, driver.ui_ready = True, False
        driver.last_tap = driver.next_readiness_check = 0.0
        driver.last_index, driver.enter_attempts = -1, 0
        driver.exhausted_at = driver.wait_reason = None
        driver.pending_touch = None
        memory = {1000 + 0x298: struct.pack('<Q', 1), 1000 + 0x290: struct.pack('<Q', 2000),
                  2000: struct.pack('<ff', 605, 605)}
        context = bytearray(1232)
        struct.pack_into('<Q', context, 160, 1000)
        struct.pack_into('<f', context, 512, 100)
        struct.pack_into('<f', context, 528, 1)
        original = bytes(context)
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'stderr.log'
            log.write_bytes(b'roster')
            client = SimpleNamespace(number=2, base=100, folder=Path(directory), memory=lambda a, n: memory[a])
            with patch('verify_native_input.time.monotonic', return_value=10):
                driver(client, 20, context)
            self.assertEqual(driver.wait_reason, 'native-picker')
            self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 130)
            log.write_bytes(b'char select: lastCharacterIndex selects row 0 (Hero)')
            with patch('verify_native_input.time.monotonic', return_value=11):
                driver(client, 20, context)
            self.assertEqual(driver.wait_reason, 'host-map')
            self.assertEqual(driver.last_index, -1)
            driver.bridge.host_map = 'duskwood'
            with patch('verify_native_input.time.monotonic', return_value=12):
                driver(client, 20, context)
            self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 140)
            self.assertEqual(driver.enter_attempts, 1)
            self.assertEqual(bytes(context[:248]), original[:248])
            self.assertEqual(bytes(context[256:]), original[256:])
            with patch('verify_native_input.time.monotonic', return_value=21), self.assertRaisesRegex(ValueError, 'retry limit'):
                driver.poll_network()
            driver.bridge._menu_enter_observed = True
            with patch('verify_native_input.time.monotonic', return_value=22):
                driver.poll_network()
                driver(client, 20, context)
            self.assertEqual(driver.wait_reason, 'acknowledged')
            self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 130)
            self.assertEqual(driver.enter_attempts, 1)
            driver.bridge._menu_enter_observed = False
            memory[2000] = struct.pack('<ff', 606, 605)
            with self.assertRaisesRegex(ValueError, 'coordinates/order'):
                driver(client, 20, context)
            memory[2000] = struct.pack('<ff', 605, 605)
            memory[1000 + 0x298] = struct.pack('<Q', 999)
            with self.assertRaisesRegex(ValueError, 'index/count'):
                driver(client, 20, context)

    def test_touch_release_hold_preserves_native_state_then_emulates_only_original_clear(self):
        driver = object.__new__(NativeMenuDiagnostic)
        events, writes = [], []
        driver.bridge = SimpleNamespace(record=lambda **event: events.append(event))
        driver.contract = dict(tap_gate=dict(cleanup=30), touch_release=dict(rva=50, next=57,
            pending_tag=1, coordinates=8, finger_id=16, hold_seconds=.2))
        driver.installed = True
        driver.pending_touch = dict(index=3, point=(605., 605.), finger=10, at=10., state=3000)
        memory = {3000: struct.pack('<Q', 1), 3008: struct.pack('<ff', 605, 605), 3016: struct.pack('<Q', 10)}
        client = SimpleNamespace(number=3, base=100, memory=lambda a, n: memory[a],
                                 put=lambda a, data: writes.append((a, data)))
        context = bytearray(1232)
        for offset, value in ((120, 1), (144, 10), (240, 3000)):
            struct.pack_into('<Q', context, offset, value)
        struct.pack_into('<ff', context, 544, 605, 605)
        original = bytes(context)
        with patch('verify_native_input.time.monotonic', return_value=10.1):
            driver(client, 50, context)
        self.assertEqual(writes, [])
        self.assertIsNotNone(driver.pending_touch)
        self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 130)
        self.assertEqual(context[:248], original[:248])
        with patch('verify_native_input.time.monotonic', return_value=10.2):
            driver(client, 50, context)
        self.assertEqual(writes, [(3000, bytes(8))])
        self.assertIsNone(driver.pending_touch)
        self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 157)
        self.assertEqual(events[0]['finger_id'], 10)
        self.assertEqual(events[0]['index'], 3)
        driver.pending_touch = dict(index=3, point=(605., 605.), finger=10, at=10., state=3000)
        struct.pack_into('<ff', context, 544, 606, 605)
        with self.assertRaisesRegex(ValueError, 'does not match'):
            driver(client, 50, context)
        self.assertEqual(writes, [(3000, bytes(8))])

    def test_path_probe_records_and_restores_without_changing_context(self):
        bridge = object.__new__(NativeMovementDiagnostic)
        bridge.input_pressed = set()
        bridge.input_waiting = {}
        bridge.members = (1,2,3,4)
        bridge.ready = bridge.loaded = {1,2,3,4}
        bridge.native_states = {3: (1,)}
        bridge.input_probes = {123: ('press', {'expected': '90'})}
        events = []
        bridge.record = lambda **event: events.append(event)
        client = SimpleNamespace(number=3, disable_hooks=set())
        context = SimpleNamespace(Rax=99, EFlags=0x202)
        bridge(client, 123, context)
        self.assertEqual(client.disable_hooks, {123})
        self.assertEqual(vars(context), {'Rax': 99, 'EFlags': 0x202})
        self.assertEqual([r['event'] for r in events], ['native_input_ready_press', 'native_input_test_path'])

    def test_movement_press_waits_for_loaded_ready_and_running_without_consuming_input(self):
        bridge = object.__new__(NativeMovementDiagnostic)
        bridge.input_pressed, bridge.input_waiting = set(), {}
        bridge.members = (1,2,3,4)
        bridge.ready, bridge.loaded = {1,2,3,4}, {1,2,3}
        bridge.native_states = {1: (0,)}
        bridge.input_probes = {123: ('press', {})}
        bridge.input_contract = dict(release_cleanup=dict(rva=200))
        events = []
        bridge.record = lambda **event: events.append(event)
        client = SimpleNamespace(number=1, base=1000, disable_hooks=set())
        context = bytearray(1232)
        for loaded, ready, phase in [({1,2,3},{1,2,3,4},1), ({1,2,3,4},{1,2,3},1),
                                      ({1,2,3,4},{1,2,3,4},0)]:
            bridge.loaded, bridge.ready, bridge.native_states[1] = loaded, ready, (phase,)
            bridge(client, 123, context)
            self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 1200)
            self.assertFalse(client.disable_hooks)
            self.assertFalse(bridge.input_pressed)
            self.assertEqual(context[:248]+context[256:], bytes(1224))
        bridge.native_states[1] = (1,)
        bridge(client, 123, context)
        self.assertEqual(client.disable_hooks, {123})
        self.assertEqual(bridge.input_pressed, {1})
        self.assertEqual(sum(r['event']=='native_input_wait' for r in events), 3)

    def test_release_holds_only_two_seconds_then_restores_native_event(self):
        bridge = object.__new__(NativeMovementDiagnostic)
        bridge.input_probes = {123: ('release', {})}
        bridge.input_pressed = {1}
        bridge.input_release_deadlines = {}
        bridge.input_contract = dict(hold_seconds=2.0, repeat_press=dict(rva=200, expected='6641c747380101'))
        bridge.record = lambda **event: None
        client = SimpleNamespace(number=1, base=1000, disable_hooks=set(), memory=lambda a, n: bytes.fromhex('6641c747380101'))
        context = bytearray(1232)
        struct.pack_into('<Q', context, 248, 1123)
        original = bytes(context)
        with patch('verify_native_input.time.monotonic', side_effect=[10.0, 11.9, 12.0]):
            bridge(client, 123, context)
            self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 1200)
            self.assertFalse(client.disable_hooks)
            struct.pack_into('<Q', context, 248, 1123)
            bridge(client, 123, context)
            self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 1200)
            struct.pack_into('<Q', context, 248, 1123)
            bridge(client, 123, context)
            self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 1123)
            self.assertEqual(client.disable_hooks, {123})
            self.assertEqual(bytes(context), original)
        bridge.input_release_deadlines.clear()
        client.memory = lambda a, n: bytes(n)
        with self.assertRaisesRegex(ValueError, 'press producer live instruction'):
            bridge(client, 123, context)
        bridge.input_pressed.clear()
        with self.assertRaisesRegex(ValueError, 'before the observed press'):
            bridge(client, 123, context)

    def test_departure_requires_ready_then_actual_pause_before_native_tap(self):
        driver = object.__new__(NativeDepartureDiagnostic)
        events = []
        driver.bridge = SimpleNamespace(native_states={2: (1, 1, 0, 0)},
                                        record=lambda **event: events.append(event))
        driver.contract = dict(repeat_press=dict(rva=10), tap_gate=dict(rva=20, cleanup=30, producer=45,
                               count_stack=8, points_stack=16, elapsed_xmm=6, scheduled_xmm=7),
                               release_cleanup=dict(rva=40), touch_release=dict(rva=50, next=57,
                               pending_tag=1, coordinates=8, finger_id=16, hold_seconds=.2))
        driver.installed, driver.escaped_at = True, None
        driver.pending_touch = None
        driver.departure_ready = lambda: False
        memory = {1008: struct.pack('<Q', 1), 1016: struct.pack('<Q', 2000),
                  2000: struct.pack('<ff', 549, 521), 3000: struct.pack('<Q', 1),
                  3008: struct.pack('<ff', 549, 521), 3016: struct.pack('<Q', 7)}
        writes = []
        client = SimpleNamespace(number=2, base=100, disable_hooks=set(),
                                 memory=lambda a, n: memory[a], put=lambda a,b: writes.append((a,b)))
        context = bytearray(1232)
        struct.pack_into('<Q', context, 160, 1000)
        struct.pack_into('<Q', context, 240, 3000)
        struct.pack_into('<f', context, 512, 100)
        struct.pack_into('<f', context, 528, 3)
        driver(client, 10, context)
        self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 140)
        self.assertFalse(client.disable_hooks)
        driver.departure_ready = lambda: True
        with patch('verify_native_input.time.monotonic', return_value=10):
            driver(client, 10, context)
        self.assertEqual(client.disable_hooks, {10})
        with patch('verify_native_input.time.monotonic', return_value=11):
            driver(client, 20, context)
        self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 130)
        self.assertNotIn(20, client.disable_hooks)
        driver.bridge.native_states[2] = (3, 1, 0, 0)
        with patch('verify_native_input.time.monotonic', return_value=10.2):
            driver(client, 20, context)
        self.assertNotIn(20, client.disable_hooks)
        with patch('verify_native_input.time.monotonic', return_value=10.5):
            driver(client, 20, context)
        self.assertNotIn(20, client.disable_hooks)
        self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 145)
        self.assertEqual([e['event'] for e in events], ['departure_native_escape', 'departure_native_quit_tap'])
        struct.pack_into('<Q', context, 120, 1)
        struct.pack_into('<Q', context, 144, 7)
        struct.pack_into('<ff', context, 544, 549, 521)
        with patch('verify_native_input.time.monotonic', return_value=10.6):
            driver(client, 50, context)
        self.assertFalse(writes)
        self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 130)
        with patch('verify_native_input.time.monotonic', return_value=10.8):
            driver(client, 50, context)
        self.assertEqual(writes, [(3000, bytes(8))])
        self.assertEqual(events[-1]['event'], 'departure_native_touch_release')
        self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 157)
        struct.pack_into('<Q', context, 120, 0)
        memory[2000] = struct.pack('<ff', 550, 521)
        with patch('verify_native_input.time.monotonic', return_value=11), self.assertRaisesRegex(ValueError, 'coordinates'):
            driver(client, 20, context)

    def test_live_bytes_and_disposable_folder_required(self):
        from native_probe import TICK
        class Base:
            def __call__(self, *args): return 'continued'
        class Driver(NativeMovementDiagnostic, Base):
            def record(self, **event): self.events.append(event)
        bridge = object.__new__(Driver)
        bridge.input_home = ROOT / 'coop-lab/compatibility-tests/unit-input'
        bridge.input_installed, bridge.events = set(), []
        bridge.input_probes = {}
        bridge.input_contract = dict(rva=10, expected='bbffffffff41b601', replacement='bb2a00000041b600', key_spec='w@3',
                                     release_cleanup=dict(rva=20, expected='bbffffffff41b601'))
        writes = []
        client = SimpleNamespace(number=1, base=100, folder=bridge.input_home / 'player-1',
                                 memory=lambda a, n: bytes.fromhex(bridge.input_contract['expected']),
                                 patch=lambda a, b: writes.append((a, b)))
        self.assertEqual(bridge(client, TICK, None), 'continued')
        bridge(client, TICK, None)
        self.assertEqual(writes, [(110, bytes.fromhex('bb2a00000041b600'))])
        bridge.input_installed.clear()
        client.memory = lambda a, n: b'\0' * n
        with self.assertRaisesRegex(ValueError, 'live instruction'):
            bridge(client, TICK, None)
        client.folder = ROOT / 'coop-lab/personal'
        with self.assertRaisesRegex(ValueError, 'personal saves'):
            bridge(client, TICK, None)


if __name__ == '__main__':
    unittest.main()
