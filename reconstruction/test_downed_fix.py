"""A dead guest must not retain hits from its previous life or a live host gate."""
import io
import json
import os
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from group_online import GroupOnlineBridge
from native_guest_combat import NativeCombatBridge
from native_probe import game_field
from sessions import Pose
from test_party_departure import Wire
from visibility_bridge import Bridge
from world_packets import DESTROY


class DownedFixTests(unittest.TestCase):
    def guest(self, number=2):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            result = GroupOnlineBridge(io.StringIO(), number, {1: Wire()})
        result.native_states = {1: (1, 35, 282, 0), number: (4, 35, 282, 4)}
        result.clients = {number: SimpleNamespace(saved_context=None)}
        return result

    def test_reported_disconnect_with_23_hits_and_stale_live_host_finishes(self):
        guest = self.guest()
        guest.guest_hits = [(123, 5, 1.0)] * 23
        guest.connection_ended(1, ConnectionError('Co-op peer disconnected'))
        self.assertTrue(guest.finish_ready())
        self.assertEqual(guest.guest_hits, [])
        self.assertEqual(guest.native_states[2], (4, 35, 282, 4))
        events = [json.loads(line) for line in guest.output.getvalue().splitlines()]
        # 0.0.10 events: transport_failure and incoming_hits_obsolete (merged 15.10.2026).
        obsolete = next(e for e in events if e['event'] == 'incoming_hits_obsolete')
        self.assertEqual((obsolete['count'], obsolete['reason']), (23, 'host_departed'))
        self.assertIn('transport_failure', [e['event'] for e in events])

    def test_downed_cleanup_preserves_world_updates_and_inflight_calls(self):
        guest = self.guest()
        guest.guest_hits = [(123, 5, 1.0)]
        guest.world_pending = [(DESTROY, struct.pack('<Q', 123))]
        guest.connection_ended(1, 'ConnectionError')
        self.assertFalse(guest.finish_ready())
        self.assertEqual(len(guest.world_pending), 1)
        guest.world_pending.clear()  # Simulate completed native packet delivery.
        guest.clients[2].saved_context = b'owned-call'
        self.assertFalse(guest.finish_ready())
        guest.clients[2].saved_context = None
        self.assertTrue(guest.finish_ready())

    def test_dead_cleanup_only_retires_local_hits_in_four_player_session(self):
        for number in (2, 3, 4):
            guest = self.guest(number)
            queue = guest.guest_hits if number == 2 else guest.hit_queues[number]
            queue.append((123, 5, 1.0))
            guest.native_states[3 if number == 2 else 2] = (1,)
            other = guest.hit_queues[3] if number == 2 else guest.guest_hits
            other.append((456, 2, 1.0))
            guest.clear_incoming_hits(number, 'recipient_dead')  # 0.0.10 API
            self.assertEqual(queue, [])
            self.assertEqual(other, [(456, 2, 1.0)])
            guest.native_states[number] = (1, 35, 282, 4)  # Revival.
            self.assertEqual(queue, [])

    def test_departed_host_hits_are_logged_and_cannot_hold_alive_guests(self):
        # Merged v3 semantics: after the host left, its hits can no longer be
        # settled; a choosing or paused guest must still finish (crash 2026-10-14).
        for phase in (1, 2, 3):
            guest = self.guest()
            guest.native_states[2] = (phase, 35, 282, 4)
            guest.guest_hits = [(123, 5, 1.0)]
            guest.connection_ended(1, 'ConnectionError')
            self.assertEqual(guest.finish_ready(), phase != 1)  # Running: own native pause first.
            self.assertEqual(guest.guest_hits, [])
            self.assertIn('incoming_hits_obsolete', guest.output.getvalue())

    def test_live_online_host_does_not_wait_for_stale_guest_playing_state(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            host = GroupOnlineBridge(io.StringIO(), 1, {2: Wire()})
        host.native_states = {1: (3,), 2: (1,)}
        host.clients = {1: SimpleNamespace(saved_context=None)}
        host.quiesced_peers = {2}
        host.peer_finished = True
        self.assertTrue(host.finish_ready())
        host.native_states[1] = (1,)
        self.assertFalse(host.finish_ready())

    def test_online_packet_evidence_is_opt_in_and_state_diagnostics_remain(self):
        with patch.dict(os.environ, COOP_PLAYERS='2', COOP_TRACE_PACKETS='0'):
            host = GroupOnlineBridge(io.StringIO(), 1, {2: Wire()})
        host.capture_world(DESTROY, struct.pack('<Q', 123))
        self.assertEqual(host.counts['world_captured'], 1)
        self.assertEqual(len(host.world_pending), 1)
        self.assertEqual(host.output.getvalue(), '')
        host.trace_packets = True
        host.capture_world(DESTROY, struct.pack('<Q', 456))
        self.assertIn('world_captured', host.output.getvalue())
        self.assertTrue(Bridge(io.StringIO()).trace_packets)

    def test_poll_stalls_are_sampled(self):
        guest = self.guest()
        guest.channels = {}
        guest.last_poll, guest.last_diagnostic = 1, 0
        with patch('group_online.time.monotonic', return_value=3):
            guest.poll_network()
        events = [json.loads(line) for line in guest.output.getvalue().splitlines()]
        self.assertEqual(events[0]['event'], 'network_health')  # 0.0.10 poll diagnostic.
        self.assertEqual(events[0]['poll_gap_seconds'], 2)

    def test_revival_with_23_stale_hits_does_not_damage_the_new_life(self):
        guest = self.guest()
        guest.guest_hits = [(123, 5, 1.0)] * 23
        guest.router.players = {0xFF0101: SimpleNamespace(pose=Pose(1, 0, 0, 0)),
                                0xFF0102: SimpleNamespace(pose=Pose(0, 0, 0, 0))}
        memory = bytearray(0x1000)
        struct.pack_into('<f', memory, game_field(0x4F8), 100)
        memory[game_field(0x8BF)] = 4
        calls = []
        def put(address, data):
            memory[address:address + len(data)] = data
        def call(context, function, game, **kwargs):
            calls.append(function)
            memory[game_field(0x8BF)] = 1
            kwargs['after']()
        client = SimpleNamespace(number=2, server=-0x10, put=put,
            memory=lambda a, n: bytes(memory[a:a+n]), call_before=call)
        # 0.0.10 measures revival in shared game time; it retires dead hits in
        # NativeCombatBridge.before_batch (test_incoming_hits), not in sync_revival.
        guest.host_clock = 1.0
        self.assertFalse(guest.sync_revival(client, None))
        guest.host_clock = 4.1
        self.assertTrue(guest.sync_revival(client, None))
        self.assertEqual(len(calls), 1)
        self.assertEqual(struct.unpack_from('<f', memory, game_field(0x4A0))[0], 50)
        self.assertEqual(memory[game_field(0x8BF)], 1)
        self.assertIn('player_revived', guest.output.getvalue())

    def test_missing_development_exe_still_allows_exact_release_observations(self):
        from build_hooks import ROOT
        from menu_contracts import discover_gear_observation
        from native_input_contracts import discover_native_key_diagnostic
        release = json.loads((ROOT / 'reconstruction/release-0.84.3.json').read_text())
        gear = discover_gear_observation(ROOT / 'missing-reference.exe', ROOT / 'AzerothSurvivors.exe', release['menu_contract'])
        self.assertFalse(gear['native_call_allowed'])
        self.assertEqual(gear['schema']['slots'], 19)
        key = discover_native_key_diagnostic(ROOT / 'missing-reference.exe', ROOT / 'AzerothSurvivors.exe')
        self.assertEqual(key['sha256'], release['adapter_profile']['sha256'])
        self.assertTrue(key['isolated_only'])
        with patch('pathlib.Path.is_file', return_value=False), patch('pathlib.Path.read_bytes', return_value=b'unknown exe'):
            with self.assertRaisesRegex(ValueError, 'reviewed reference'):
                discover_native_key_diagnostic(ROOT / 'missing-reference.exe', ROOT / 'unknown.exe')


class MirrorWriteTests(unittest.TestCase):
    def fixture(self, count=2):
        bridge = NativeCombatBridge(io.StringIO())
        memory = bytearray(0x1000 + count * 0x148)
        struct.pack_into('<QQ', memory, game_field(0x568), 0x1000, count)
        for index in range(count):
            address = 0x1000 + index * 0x148
            memory[address:address + 0x148] = bytes([index % 200 + 1]) * 0x148
            struct.pack_into('<Q', memory, address + 0x18, 0xFFFFFFFFFFFFFFFF)
            guid = 123 + index
            struct.pack_into('<Q', memory, address + 0x78, guid)
            struct.pack_into('<f', memory, address + 0xE0, 80)
            flat = bytes([13]) * 0xE0
            bridge.enemy_snapshot[guid] = (flat, 90, (1, 2, 3))
            bridge.provided_hp[guid] = 80
        writes = []
        def put(address, data):
            writes.append((address, bytes(data)))
            memory[address:address + len(data)] = data
        client = SimpleNamespace(number=2, server=-0x10, base=0x140000000,
            memory=lambda a, n: bytes(memory[a:a+n]), put=put)
        return bridge, client, memory, writes

    def test_batched_writes_preserve_owned_fields_and_pending_effects(self):
        bridge, client, memory, writes = self.fixture(80)
        bridge.effects_pending = [(123, b'pending', 1)]
        before = bytes(memory)
        self.assertFalse(bridge.sync_mirrors(client, None))
        self.assertEqual(len(writes), 80)  # Previously seven writes per enemy.
        for index in range(80):
            address = 0x1000 + index * 0x148
            self.assertEqual(memory[address:address + 0x68], before[address:address + 0x68])
            self.assertEqual(memory[address + 0x6C:address + 0x88], before[address + 0x6C:address + 0x88])
            self.assertEqual(struct.unpack_from('<f', memory, address + 0xE0)[0], 90)
            self.assertEqual(struct.unpack_from('<6f', memory, address + 0xFC), (1, 2, 3, 1, 2, 3))
            self.assertEqual(memory[address + 0x114:address + 0x11C], bytes(8))
            for start, end in ((0x88, 0x98), (0x124, 0x128), (0x130, 0x140)):
                expected = before[address + start:address + end] if index == 0 else bytes([13]) * (end - start)
                self.assertEqual(memory[address + start:address + end], expected)
        writes.clear()
        self.assertFalse(bridge.sync_mirrors(client, None))
        self.assertEqual(writes, [])  # Unchanged snapshots need no native writes.

    def test_reused_slot_keeps_rebased_definition_and_new_guid(self):
        bridge, client, memory, writes = self.fixture(1)
        flat = bytearray(bridge.enemy_snapshot.pop(123)[0])
        struct.pack_into('<Q', flat, 0x10, 456)
        struct.pack_into('<Q', flat, 0x18, 0x100)
        bridge.enemy_snapshot[456] = (bytes(flat), 50, (4, 5, 6))
        self.assertFalse(bridge.sync_mirrors(client, None))
        self.assertEqual(struct.unpack_from('<Q', memory, 0x1000 + 0x78)[0], 456)
        self.assertEqual(struct.unpack_from('<Q', memory, 0x1000 + 0x80)[0], client.base + 0x100)
        self.assertEqual(struct.unpack_from('<f', memory, 0x1000 + 0xE0)[0], 50)
        self.assertEqual(bridge.provided_hp, {456: 50})


if __name__ == '__main__':
    unittest.main()
