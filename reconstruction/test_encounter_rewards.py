"""Regression checks for deferred entitlements and revival's game-time clock."""
import io
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from native_probe import game_field
from native_guest_combat import NativeCombatBridge
from visibility_bridge import Bridge
from visibility_bridge import packed_guid
from world_packets import SELF, DESTROY
from sessions import Pose


class EncounterTests(unittest.TestCase):
    def test_projectile_travel_time_when_caster_stands_on_dead_host(self):
        bridge = NativeCombatBridge(io.StringIO())
        bridge.native_states = {1: (4, 3, 4, 0), 2: (1, 3, 4, 0)}
        bridge.router.players = {0xFF0101: SimpleNamespace(pose=Pose(0, 0, 0, 0)),
                                 0xFF0102: SimpleNamespace(pose=Pose(24, 0, 0, 0))}
        flat = bytearray(0xE0)
        struct.pack_into('<Q', flat, 0x18, 0x1000)
        bridge.enemy_snapshot = {999: (flat, 100, (0, 0, 0))}
        memory = bytearray(0x3000)
        struct.pack_into('<II', memory, 0x1000, 1, 133)
        struct.pack_into('<QQ', memory, 0x5B8, 0x2000, 1)
        struct.pack_into('<QQ', memory, 0x2020, SELF, 999)
        struct.pack_into('<I', memory, 0x2040, 133)
        memory[0x2049] = 1
        struct.pack_into('<f', memory, game_field(0x85C), 10)
        client = SimpleNamespace(base=0, server=-16, memory=lambda a, n: memory[a:a+n],
            put=lambda a, b: memory.__setitem__(slice(a, a+len(b)), b))
        bridge.clients[1] = client
        body = packed_guid(999) * 2 + struct.pack('<IH BQ BH', 133, 0x100, 1, SELF, 0, 2) + packed_guid(SELF)
        with patch('native_guest_combat.release_0843', return_value=True):
            start = packed_guid(999) * 2 + struct.pack('<IHIH', 133, 2, 1500, 2) + packed_guid(SELF)
            bridge.route_projectile(0x131, start)
            bridge.ranged_enemies = dict(bridge.enemy_snapshot)
            bridge.enemy_snapshot.clear()  # Injected lethal damage before queued GO.
            bridge.route_projectile(0x132, body)
        self.assertEqual(struct.unpack_from('<f', memory, 0x203C)[0], 11)
        self.assertEqual(struct.unpack_from('<Q', memory, 0x2020)[0], 0xFF0102)

    def test_ordinary_impact_routes_only_the_verified_caller_and_stored_guest(self):
        bridge = NativeCombatBridge(io.StringIO())
        bridge.native_states[2] = (1, 3, 4, 0)
        context = bytearray(1232)
        struct.pack_into('<Q', context, 152, 0x100)
        struct.pack_into('<Q', context, 160, 0x200)
        struct.pack_into('<Q', context, 184, 999)
        struct.pack_into('<f', context, 432, 12)
        memory = {0x100: struct.pack('<Q', 0x5458E5E), 0x380: struct.pack('<Q', 0xFF0102)}
        memory[game_field(0x85C)] = struct.pack('<f', 10)
        client = SimpleNamespace(base=0, server=-16, memory=lambda a, n: memory[a])
        with patch('native_guest_combat.release_0843', return_value=True):
            bridge.route_enemy_hit(client, context)
            self.assertEqual(bridge.area_hits, [(999, 12)])
            self.assertEqual(struct.unpack_from('<Q', context, 152)[0], 0x108)
            bridge.area_hits.clear()
            struct.pack_into('<Q', context, 152, 0x100)
            memory[0x100] = struct.pack('<Q', 0x1234)
            bridge.route_enemy_hit(client, context)
            self.assertFalse(bridge.area_hits)

    def test_retired_enemy_discards_its_interrupted_cast(self):
        bridge = NativeCombatBridge(io.StringIO())
        bridge.ranged_targets[(999, 133)] = 2
        bridge.ranged_enemies[999] = 'retained metadata'
        with patch.object(Bridge, 'filter_packet', side_effect=lambda n, op, body: body):
            bridge.filter_packet(1, DESTROY, struct.pack('<Q', 999))
        self.assertFalse(bridge.ranged_targets)
        self.assertFalse(bridge.ranged_enemies)

    def test_revival_suspends_menu_time_and_resets_outside_five_yards(self):
        bridge = NativeCombatBridge(io.StringIO())
        bridge.members = (1, 2)
        bridge.native_states = {1: (1, 3, 4, 0), 2: (4, 3, 4, 0)}
        bridge.router.players = {0xFF0100 + n: SimpleNamespace(pose=Pose(n, 0, 0, 0)) for n in (1, 2)}
        memory = bytearray(0x1000)
        struct.pack_into('<f', memory, game_field(0x4F8), 100)
        struct.pack_into('<II', memory, game_field(0x498), 3, 4)
        calls = []
        def call(context, rva, game, **kwargs):
            calls.append(rva)
            memory[game_field(0x8BF)] = 1
            kwargs['after']()
        client = SimpleNamespace(number=2, server=-16, memory=lambda a, n: memory[a:a+n],
            put=lambda a, b: memory.__setitem__(slice(a, a+len(b)), b), call_before=call)
        def tick(clock):
            bridge.host_clock = clock
            return bridge.sync_revival(client, None)
        tick(0); tick(1.25)
        self.assertEqual(bridge.revive_progress[2][0], 1.25)
        bridge.native_states[1] = (2, 3, 4, 0)
        tick(2); tick(12)
        self.assertEqual(bridge.revive_progress[2][0], 1.25)
        bridge.native_states[1] = (1, 3, 4, 0)
        tick(12); tick(13)
        self.assertEqual(bridge.revive_progress[2][0], 2.25)
        bridge.router.players[0xFF0101].pose = Pose(7.01, 0, 0, 0)
        tick(13.1)
        self.assertNotIn(2, bridge.revive_progress)
        bridge.router.players[0xFF0101].pose = Pose(7, 0, 0, 0)
        tick(14); tick(16.9)
        self.assertFalse(calls)
        self.assertTrue(tick(17))
        self.assertEqual(struct.unpack_from('<f', memory, game_field(0x4A0))[0], 50)
        self.assertEqual(struct.unpack_from('<II', memory, game_field(0x498)), (3, 4))

    def test_duplicate_guardian_entitlement_is_native_and_deferred_while_down(self):
        bridge = NativeCombatBridge(io.StringIO())
        bridge.ready = {2}
        bridge.native_states[2] = (4, 3, 4, 0)
        memory = bytearray(0x1000)
        client = SimpleNamespace(number=2, server=-16,
            memory=lambda a, n: memory[a:a+n],
            put=lambda a, b: memory.__setitem__(slice(a, a+len(b)), b))
        event = dict(sequence=1, map=0, boss=-1)
        bridge.receive_boss_rewards(2, [event, event])
        with patch('boss_rewards.release_0843', return_value=True), patch('boss_rewards.native_map', return_value=(0, 0)):
            self.assertFalse(bridge.before_batch(client, None))
        bridge.receive_boss_rewards(2, [event])
        self.assertFalse(bridge.boss_reward_pending[2])
        self.assertEqual(bridge.boss_reward_applied[2], 1)
        self.assertEqual(struct.unpack_from('<I', memory, 0x888)[0], 1)
        self.assertEqual(struct.unpack_from('<I', memory, 0x6E8)[0], 1)


if __name__ == '__main__':
    unittest.main()
