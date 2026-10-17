"""Regression checks against real captured native packets; no EXE launch."""
import json
from pathlib import Path
import struct
import unittest
import io
from types import SimpleNamespace

from sessions import HeaderCipher, Pose
from updated_layout import rva as relocated, UPDATED
from visibility_bridge import Bridge, clone_player, encrypt_packets, packed_guid, decrypt_batch, melee_packet, native_enemies, native_melee_stats, replace_downed_ui, system_message, retarget_monster
from native_probe import emulate_entry_push, Native, PAUSE, RESUME, DAMAGE, AWARD_XP, MOVE, HURT, q, game_field, BUILD


class VisibilityTests(unittest.TestCase):
    def test_victory_does_not_rebuild_guest_combat_storage(self):
        from native_guest_combat import NativeCombatBridge
        bridge = NativeCombatBridge(io.StringIO())
        bridge.ready = {2}
        bridge.native_states = {1: (5,), 2: (5,)}
        bridge.enemy_snapshot[123] = ('stale snapshot', 10, (0, 0, 0))
        bridge.damage_pending[123] = 2
        bridge.provided_hp[123] = 10
        client = SimpleNamespace(number=2)
        self.assertFalse(bridge.before_batch(client, bytearray(1232)))
        self.assertEqual(bridge.provided_hp, {})
        self.assertEqual(bridge.damage_pending, {})

    def test_boss_hud_uses_host_and_preserves_private_fields(self):
        from native_guest_combat import NativeCombatBridge
        from native_probe import HUD_DELIVER
        bridge = NativeCombatBridge(io.StringIO())
        bridge.hud_buffer = 0x9000
        writes = {}
        context = bytearray(1232)
        struct.pack_into('<Q', context, 120, 0x1000)
        struct.pack_into('<Q', context, 152, 0x8000)
        boss = {'name': 'Edwin VanCleef', 'hp': 300, 'maxHp': 500}
        for number, hp, gold in ((1, 300, 40), (2, 250, 20)):
            payload = json.dumps({'boss': dict(boss, hp=hp), 'gold': gold}).encode()
            struct.pack_into('<Q', context, 136, 0x2000)
            struct.pack_into('<Q', context, 184, len(payload))
            client = SimpleNamespace(number=number, base=0x140000000, put=writes.__setitem__,
                memory=lambda a, n: payload if a == 0x2000 else struct.pack('<Q', 0x123456))
            bridge(client, HUD_DELIVER, context)
            self.assertEqual(q(context, 248), 0x123456)
        delivered = json.loads(writes[0x9000])
        self.assertEqual(delivered, {'boss': boss, 'gold': 20})
        self.assertEqual(writes[q(context, 152)], struct.pack('<Q', 0x140000000 + HUD_DELIVER + 3))

    def test_ground_target_uses_guest_but_radial_preserves_host_distance(self):
        from native_guest_combat import NativeCombatBridge
        from native_probe import ENEMY_TARGET
        bridge = NativeCombatBridge(io.StringIO())
        bridge.native_states = {1: (1,), 2: (1,)}
        bridge.router.players[0xFF0102] = SimpleNamespace(pose=Pose(60, 0, 0, 0))
        memory = bytearray(0x3000)
        struct.pack_into('<QQ', memory, game_field(0x568), 0x1000, 1)
        client = SimpleNamespace(number=1, server=-0x10, base=0x140000000,
            memory=lambda a, n: bytes(memory[a:a+n]))
        for phase in range(6):
            bridge.native_states[2] = (phase,)
            target = (60, 0) if phase in (1, 2, 3) else (0, 0)
            for kind, expected in ((0, target), (3, (0, 0)), (4, target)):
                context = bytearray(1232)
                struct.pack_into('<Q', context, 136, kind)
                struct.pack_into('<Q', context, 128, 0x1000)
                struct.pack_into('<Q', context, 160, 0x2000)
                struct.pack_into('<ff', context, 416 + 12 * 16, 62, 0)
                bridge(client, ENEMY_TARGET, context)
                self.assertEqual(struct.unpack_from('<ff', context, 432), expected)
                self.assertEqual(q(context, 248), client.base + relocated(0x53E5580))

    def test_radial_attack_checks_guest_independently_of_host_branch(self):
        from native_guest_combat import NativeCombatBridge
        from native_probe import ENEMY_AOE
        bridge = NativeCombatBridge(io.StringIO())
        bridge.native_states = {1: (1,), 2: (1,)}
        memory = bytearray(0x2000)
        struct.pack_into('<QQ', memory, game_field(0x568), 0x1000, 1)
        struct.pack_into('<Q', memory, 0x1078, 123)
        struct.pack_into('<f', memory, 0x10E0, 100)
        client = SimpleNamespace(number=1, server=-0x10, base=0x140000000,
                                 memory=lambda a, n: bytes(memory[a:a+n]))
        for outside_host, guest_distance, expected in ((0, 0, True), (0, 9, False), (1, 8, True)):
            context = bytearray(1232)
            struct.pack_into('<I', context, 68, outside_host)
            struct.pack_into('<Q', context, 216 if UPDATED else 240, 123)
            for register, value in ((7, 10), (8, 2), (9, 8)):
                struct.pack_into('<f', context, 416 + register * 16, value)
            bridge.router.players[0xFF0102] = SimpleNamespace(pose=Pose(guest_distance, 0, 0, 0))
            bridge.area_hits.clear()
            bridge(client, ENEMY_AOE, context)
            self.assertEqual(bridge.area_hits, [(123, 20)] if expected else [])
            self.assertEqual(q(context, 248), client.base + (relocated(0x53E5430) if outside_host else relocated(0x53E6069)))
            self.assertEqual(struct.unpack_from('<I', context, 68)[0], outside_host)

    def test_boss_mirror_uses_native_boss_storage(self):
        from native_guest_combat import NativeCombatBridge
        from native_probe import SPAWN_BOSS
        bridge = NativeCombatBridge(io.StringIO())
        memory = bytearray(0x3000)
        struct.pack_into('<QQ', memory, game_field(0x568), 0x1000, 0)
        flat = bytearray(0xE0)
        struct.pack_into('<Q', flat, 0x10, 999)
        bridge.enemy_snapshot = {999: (bytes(flat), 500, (1, 2, 3))}
        bridge.boss_definitions = {999: 0x65EFA60}
        client = SimpleNamespace(number=2, server=-0x10, base=0x140000000,
                                 memory=lambda a, n: bytes(memory[a:a+n]),
                                 put=lambda a, data: memory.__setitem__(slice(a, a+len(data)), data))
        def spawn(context, rva, game, definition, position, after):
            self.assertEqual((rva, definition), (SPAWN_BOSS, client.base + 0x65EFA60))
            struct.pack_into('<Q', memory, game_field(0x570), 1)
            struct.pack_into('<QQQQ', memory, 0x1018, 2, 0x2000, 2, definition)
            after()
        client.call_before = spawn
        self.assertTrue(bridge.sync_mirrors(client, None))
        self.assertFalse(bridge.sync_mirrors(client, None))
        self.assertEqual(struct.unpack_from('<QQQQ', memory, 0x1018), (2, 0x2000, 2, client.base + 0x65EFA60))
        self.assertEqual(q(memory, 0x1078), 999)
        self.assertEqual(q(memory, 0x1080), 0)

    def test_guest_native_healing_updates_remote_vitals_without_private_gold(self):
        from native_guest_combat import NativeCombatBridge
        from world_packets import UPDATE, SELF, values_packet, objects
        bridge = NativeCombatBridge(io.StringIO())
        body = values_packet(SELF, {22: 80, 28: 120, 1176: 90000})
        self.assertEqual(bridge.filter_packet(2, UPDATE, body), body)
        opcode, remote = bridge.notice_packets[1].pop()
        block, = objects(remote, remap=False)
        self.assertEqual((opcode, block.guid, block.fields), (UPDATE, 0xFF0102, {22: 80, 28: 120}))

    def test_periodic_native_allocation_abi(self):
        from native_probe import APPLY_DOT
        client = Native.__new__(Native)
        client.base, client.call_return, client.saved_context = 0x140000000, 0x200000, None
        writes = {}
        client.put = writes.__setitem__
        context = bytearray(1232)
        struct.pack_into('<Q', context, 152, 0x100008)
        client.call_before(context, APPLY_DOT, 0x300000, 12721, damage=6, periodic=(3, 3, 10))
        self.assertEqual(q(context, 128), 0x300000)
        self.assertEqual(q(context, 136), 12721)
        self.assertEqual(struct.unpack_from('<f', context, 464)[0], 6)
        self.assertEqual(struct.unpack('<f4xQf4xQQQf4x' if UPDATED else '<f4xQf4xQQf4x', writes[q(context, 152) + 0x28]),
                         (3, 3, 0, 0, 0, 1, 10) if UPDATED else (3, 3, 0, 0, 1, 10))
        client.saved_context = None
        with self.assertRaises(ValueError):
            client.call_before(context, APPLY_DOT, 0x300000, 12721, damage=6, periodic=(3, 0, 10))

    def test_enemy_effect_replay_uses_native_abi_and_excludes_self_healing(self):
        from native_guest_combat import NativeCombatBridge
        from native_probe import APPLY_EFFECT
        bridge = NativeCombatBridge(io.StringIO())
        client = Native.__new__(Native)
        client.number, client.base, client.call_return, client.saved_context = 2, 0x140000000, 0x200000, None
        memory = bytearray(0x2000)
        client.put = lambda a, data: memory.__setitem__(slice(a, a + len(data)), data)
        client.memory = lambda a, n: bytes(memory[a:a+n])
        context = bytearray(1232)
        struct.pack_into('<Q', context, 152, 0x1008)
        effect = struct.pack('<Iff', 1, .5, 8)
        client.call_before(context, APPLY_EFFECT, 0x300000, 123, effect=effect, spell=116)
        self.assertEqual(client.memory(q(context, 184), 12), effect)
        self.assertEqual(q(client.memory(q(context, 152) + 0x28, 8)), 116)
        bridge(client, APPLY_EFFECT, context)
        self.assertEqual(bridge.effects_pending, [(123, effect, 116)])
        client.put(q(context, 184), struct.pack('<Iff', 6, .5, 0))
        bridge(client, APPLY_EFFECT, context)
        self.assertEqual(len(bridge.effects_pending), 1)
        client.saved_context = None
        with self.assertRaises(ValueError):
            client.call_before(context, APPLY_EFFECT, 0x300000, 123, effect=struct.pack('<Iff', 6, .5, 0))

    def test_new_mirror_guid_collision_is_retired_by_slot(self):
        from native_guest_combat import NativeCombatBridge
        bridge = NativeCombatBridge(io.StringIO())
        memory = bytearray(0x3000)
        struct.pack_into('<QQ', memory, game_field(0x568), 0x1000, 1)
        struct.pack_into('<Q', memory, 0x1078, 123)
        struct.pack_into('<Q', memory, 0x1018, 0xFFFFFFFFFFFFFFFF)
        client = SimpleNamespace(number=2, server=-0x10, base=0x140000000,
                                 memory=lambda a, n: bytes(memory[a:a+n]),
                                 put=lambda a, data: memory.__setitem__(slice(a, a+len(data)), data))
        def spawn(context, rva, game, kind, position, after):
            struct.pack_into('<Q', memory, game_field(0x570), 2)
            struct.pack_into('<Q', memory, 0x1000 + 0x148 + 0x78, 123)
            struct.pack_into('<Q', memory, 0x1000 + 0x148 + 0x18, 0xFFFFFFFFFFFFFFFF)
            after()
        client.call_before = spawn
        for guid in (123, 124):
            flat = bytearray(0xE0)
            struct.pack_into('<QQ', flat, 0x10, guid, 0x100)
            bridge.enemy_snapshot[guid] = (bytes(flat), 100, (1, 2, 3))
        self.assertTrue(bridge.sync_mirrors(client, None))
        self.assertFalse(bridge.sync_mirrors(client, None))
        self.assertEqual([q(memory, 0x1000 + i * 0x148 + 0x78) for i in range(2)], [123, 124])

    def test_stale_chest_claim_refunds_only_reserved_guest_cost(self):
        from native_guest_combat import NativeCombatBridge
        bridge = NativeCombatBridge(io.StringIO())
        bridge.native_states = {1: (1,), 2: (1,)}
        bridge.router.players = {0xFF0101: SimpleNamespace(pose=Pose(30, 0, 0, 0)),
                                 0xFF0102: SimpleNamespace(pose=Pose(0, 0, 0, 0))}
        memory = bytearray(0x900)
        struct.pack_into('<I', memory, game_field(0x4A8), 100)
        struct.pack_into('<I', memory, game_field(0x894), 20)
        struct.pack_into('<ff', memory, game_field(0x510), 5, 1)
        struct.pack_into('<f', memory, game_field(0x528), 1)
        guest = SimpleNamespace(number=2, server=-0x10, memory=lambda a, n: memory[a:a+n],
                                put=lambda a, data: memory.__setitem__(slice(a, a+len(data)), data))
        bridge.chests = {99: (0, (0, 0, 0), 2, 1)}
        bridge.sync_chests(guest, None)
        bridge.sync_chests(guest, None)
        self.assertEqual(struct.unpack_from('<I', memory, game_field(0x4A8))[0], 80)
        host = SimpleNamespace(number=1, server=-0x10, memory=lambda a, n: bytes(n))
        bridge.sync_chests(host, None)
        self.assertEqual(bridge.chest_claim['status'], 'refund')
        bridge.sync_chests(guest, None)
        self.assertEqual(struct.unpack_from('<I', memory, game_field(0x4A8))[0], 100)
        self.assertIsNone(bridge.chest_claim)

    def test_spawn_split_distance_bonus_and_survivor(self):
        from native_guest_combat import NativeCombatBridge
        bridge = NativeCombatBridge(io.StringIO())
        bridge.native_states = {1: (1,), 2: (1,)}
        bridge.router.players = {0xFF0101: SimpleNamespace(pose=Pose(0, 0, 0, 0)),
                                 0xFF0102: SimpleNamespace(pose=Pose(0, 0, 0, 0))}
        self.assertEqual([bridge.spawn_owner() for _ in range(8)], [1, 2] * 4)
        for distance, bonus in ((0, 0), (50, .25), (100, .5), (500, .5)):
            bridge.router.players[0xFF0102].pose = Pose(distance, 0, 0, 0)
            self.assertEqual(bridge.spawn_bonus(), bonus)
        bridge.native_states[1] = (4,)
        self.assertEqual([bridge.spawn_owner() for _ in range(9)], [2] * 9)
        self.assertEqual(bridge.spawn_bonus(), 0)
        bridge.native_states[1] = (1,)
        self.assertEqual([bridge.spawn_owner() for _ in range(4)], [1, 2, 1, 2])

    def test_shared_gold_adds_once_without_copying_spending(self):
        from native_guest_combat import NativeCombatBridge
        bridge = NativeCombatBridge(io.StringIO())
        memory = bytearray(0x900)
        struct.pack_into('<I', memory, game_field(0x4A8), 80)
        struct.pack_into('<I', memory, game_field(0x6D0), 100)
        client = SimpleNamespace(number=2, server=-0x10, memory=lambda a, n: memory[a:a+n],
                                 put=lambda a, data: memory.__setitem__(slice(a, a+len(data)), data))
        bridge.gold_pending = 12
        bridge.apply_shared_gold(client)
        bridge.apply_shared_gold(client)
        self.assertEqual(struct.unpack_from('<I', memory, game_field(0x4A8))[0], 92)
        self.assertEqual(struct.unpack_from('<I', memory, game_field(0x6D0))[0], 112)
        self.assertEqual(len(bridge.notice_packets[2]), 1)

    def test_guest_xp_only_allows_direct_authoritative_replay(self):
        from native_guest_combat import NativeCombatBridge
        bridge = NativeCombatBridge(io.StringIO())
        for saved, return_address, allowed in ((None, 0x1234, False),
                                               (b'saved', 0x1234, False),
                                               (b'saved', 0x9000, True)):
            client = SimpleNamespace(number=2, saved_context=saved, call_return=0x9000,
                                     memory=lambda a, n: struct.pack('<Q', return_address))
            context = bytearray(1232)
            struct.pack_into('<Q', context, 152, 0x1000)
            struct.pack_into('<Q', context, 248, AWARD_XP)
            bridge(client, AWARD_XP, context)
            self.assertEqual(q(context, 248), AWARD_XP if allowed else return_address)
            self.assertEqual(q(context, 152), 0x1000 if allowed else 0x1008)

    def test_native_mirror_damage_is_not_counted_twice_during_replication(self):
        from native_guest_combat import NativeCombatBridge
        bridge = NativeCombatBridge(io.StringIO())
        memory = bytearray(0x2000)
        struct.pack_into('<QQ', memory, game_field(0x568), 0x1000, 1)
        struct.pack_into('<Q', memory, 0x1078, 123)
        struct.pack_into('<Q', memory, 0x1018, 0xFFFFFFFFFFFFFFFF)
        struct.pack_into('<f', memory, 0x10E0, 90)
        client = SimpleNamespace(number=2, server=-0x10, base=0x140000000,
                                 memory=lambda a, n: bytes(memory[a:a+n]),
                                 put=lambda a, data: memory.__setitem__(slice(a, a+len(data)), data))
        bridge.enemy_snapshot = {123: (bytes(0xE0), 100, (1, 2, 3))}
        bridge.provided_hp = {123: 100}
        self.assertFalse(bridge.sync_mirrors(client, None))
        self.assertEqual(bridge.damage_pending, {123: 10})
        self.assertFalse(bridge.sync_mirrors(client, None))
        self.assertEqual(bridge.damage_pending, {123: 10})
        # Host independently deals 20 before applying the queued guest hit.
        bridge.enemy_snapshot[123] = (bytes(0xE0), 80, (1, 2, 3))
        bridge.sync_mirrors(client, None)
        self.assertEqual(struct.unpack_from('<f', memory, 0x10E0)[0], 70)
        bridge.sync_mirrors(client, None)
        self.assertEqual(bridge.damage_pending, {123: 10})
        bridge.enemy_snapshot[123] = (bytes(0xE0), 70, (1, 2, 3))
        bridge.damage_pending.clear()
        bridge.sync_mirrors(client, None)
        self.assertFalse(bridge.damage_pending)
        # Reuse a retired mirror without replacing its native-owned DOT storage.
        struct.pack_into('<QQQ', memory, 0x1000, 4, 0x1800, 2)
        flat = bytearray(0xE0)
        struct.pack_into('<QQ', flat, 0x10, 124, 0x100)
        bridge.enemy_snapshot = {124: (bytes(flat), 50, (2, 3, 4))}
        def put(address, data):
            self.assertIsInstance(data, bytes)
            memory[address:address + len(data)] = data
        client.put = put
        bridge.sync_mirrors(client, None)
        self.assertEqual(struct.unpack_from('<QQQ', memory, 0x1000), (4, 0x1800, 0))
        self.assertEqual(struct.unpack_from('<Q', memory, 0x1078)[0], 124)

    def test_mixed_guest_updates_preserve_local_guid_and_discard_mirrors(self):
        from world_packets import UPDATE, SELF, values_packet
        bridge = Bridge(io.StringIO(), shared_world=True)
        local = values_packet(SELF, {0: SELF, 22: 123})
        enemy = values_packet(12345, {22: 20})
        mixed = struct.pack('<IB', 2, 0) + local[5:] + enemy[5:]
        self.assertEqual(bridge.filter_packet(2, UPDATE, mixed), local)
        self.assertIsNone(bridge.filter_packet(2, UPDATE, enemy))

    def test_again_requests_one_shared_restart_before_native_reset(self):
        from native_probe import UI_COMMAND
        bridge = Bridge(io.StringIO(), shared_world=True)
        memory = {0x1000: struct.pack('<I', 6), 0x2008: struct.pack('<Q', 0x3000)}
        client = SimpleNamespace(number=2, memory=lambda a, n: memory[a][:n])
        context = bytearray(1232)
        struct.pack_into('<Q', context, 136, 0x1000)
        struct.pack_into('<Q', context, 152, 0x2008)
        bridge(client, UI_COMMAND, context)
        self.assertTrue(bridge.restart_requested)
        self.assertEqual((q(context, 248), q(context, 152)), (0x3000, 0x2010))

    def test_pursuit_facing_names_the_nearer_living_player(self):
        from world_packets import remap_combat, MONSTER, SELF
        packet = packed_guid(123) + struct.pack('<3fIBQ', 20, 0, 0, 100, 3, SELF) + bytes(12)
        host, guest = Pose(0, 0, 0, 0), Pose(30, 0, 0, 0)
        changed = retarget_monster(packet, host, guest, True, True)
        self.assertEqual(struct.unpack_from('<Q', changed, 19)[0], 0xFF0102)
        self.assertEqual(struct.unpack_from('<Q', remap_combat(MONSTER, changed), 19)[0], SELF)
        self.assertEqual(retarget_monster(packet, host, guest, True, False), packet)
        self.assertEqual(retarget_monster(packet, guest, host, True, True), packet)
        self.assertEqual(retarget_monster(packet, guest, host, False, True), changed)

    def test_dead_pause_ui_preserves_native_phase_and_gameplay(self):
        client = Native.__new__(Native)
        client.base, client.call_return, client.saved_context = 0x140000000, 0x200000, None
        prefix = bytes.fromhex('55 56 57 53 4881ec88000000 488dac2480000000 48c74500feffffff')
        client.memory = lambda address, count: prefix[1:]
        writes, code = {}, []
        client.put = writes.__setitem__
        client.executable_buffer = lambda data: code.append(data) or 0x400000
        context = bytearray(1232)
        struct.pack_into('<Q', context, 152, 0x100008)
        client.call_before(context, PAUSE, 0x300000, ui_only=True)
        self.assertEqual(q(context, 248), 0x400000)
        self.assertEqual(code[0][-8:], struct.pack('<Q', client.base + relocated(0x53F186E)))
        self.assertEqual(set(writes), {0xFFF08})  # Return stack only; no game writes.

    def test_downed_ui_preserves_allocation_and_unrelated_messages(self):
        body = b'{"type":"defeat","level":4}'
        memory = {0x1000: struct.pack('<QQQ', 64, 0x2000, len(body)), 0x2000: body}
        writes = {}
        client = SimpleNamespace(memory=lambda a, n: memory[a][:n], put=writes.__setitem__)
        self.assertEqual(replace_downed_ui(client, 0x1000, 1), 1)
        self.assertEqual(writes, {0x2000: b'{"type":"unpaused"}', 0x1010: struct.pack('<Q', 19)})
        memory[0x2000] = b'{"type":"hud","text":"defeat"}'
        memory[0x1000] = struct.pack('<QQQ', 64, 0x2000, len(memory[0x2000]))
        self.assertEqual(replace_downed_ui(client, 0x1000, 1), 0)
        from play_limits import MAX_QUEUE
        with self.assertRaises(ValueError):
            replace_downed_ui(client, 0x1000, MAX_QUEUE + 1)
        opcode, notice = system_message('Revived')
        self.assertEqual(opcode, 0x96)
        self.assertEqual(struct.unpack_from('<I', notice, 13)[0], 8)
        self.assertEqual(notice[17:], b'Revived\0\0')

    def test_independent_talents_wait_and_reopen_earned_choices(self):
        bridge = Bridge(io.StringIO(), shared_world=True)
        bridge.ready = {1, 2}
        bridge.native_states = {1: (1, 2, 0, 0), 2: (2, 2, 0, 1)}
        calls = []
        client = SimpleNamespace(number=1, server=0x1000, memory=lambda address, size: bytes(size),  # No chest/guardian owed.
                                 call_before=lambda *args: calls.append(args))
        self.assertTrue(bridge.sync_talents(client, None))
        self.assertEqual(calls[-1][1], PAUSE)
        bridge.native_states[1] = (3, 2, 0, 0)
        self.assertFalse(bridge.sync_talents(client, None))
        bridge.native_states[2] = (1, 2, 0, 0)
        self.assertTrue(bridge.sync_talents(client, None))
        self.assertEqual(calls[-1][1], RESUME)
        bridge.native_states[1] = (1, 3, 0, 1)
        self.assertTrue(bridge.sync_talents(client, None))
        self.assertEqual(calls[-1][1:], (AWARD_XP, 0x1010, 0))
        bridge.router.paused = True
        self.assertFalse(bridge.sync_talents(client, None))

    def test_revival_requires_nearby_living_unpaused_teammate(self):
        bridge = Bridge(io.StringIO(), shared_world=True)
        bridge.router.add_player(0xFF0101, '1', Pose(0, 0, 0, 0))
        bridge.router.add_player(0xFF0102, '2', Pose(6, 0, 0, 0))
        bridge.native_states = {1: (4, 2, 3, 0), 2: (1, 2, 3, 0)}
        calls = []
        client = SimpleNamespace(number=1, server=0x1000, call_before=lambda *args: calls.append(args))
        self.assertFalse(bridge.sync_revival(client, None))
        self.assertFalse(bridge.revive_progress)
        bridge.router.players[0xFF0102].pose = Pose(4, 0, 0, 0)
        self.assertFalse(bridge.sync_revival(client, None))
        self.assertIn(1, bridge.revive_progress)
        bridge.router.paused = True
        self.assertFalse(bridge.sync_revival(client, None))
        self.assertFalse(bridge.revive_progress)
        bridge.router.paused = False
        bridge.native_states[2] = (4, 2, 3, 0)
        self.assertTrue(bridge.sync_revival(client, None))
        from native_probe import DEFEAT_UI
        self.assertEqual(calls[-1][1], DEFEAT_UI)
        self.assertFalse(bridge.sync_revival(client, None))
        self.assertFalse(bridge.revive_progress)

    def test_timed_shutdown_waits_for_world_delivery(self):
        bridge = Bridge(io.StringIO(), shared_world=True)
        bridge.clients = {1: SimpleNamespace(saved_context=None), 2: SimpleNamespace(saved_context=None)}
        bridge.native_states = {1: (1,), 2: (1,)}
        bridge.world_pending = [(0xAA, b'pending')]
        self.assertFalse(bridge.finish_ready())
        self.assertEqual(bridge.pause_pending, {1: True, 2: True})
        bridge.native_states = {1: (3,), 2: (3,)}
        self.assertFalse(bridge.finish_ready())
        bridge.world_pending.clear()
        self.assertFalse(bridge.finish_ready())  # The fake phase alone does not consume the queued Pause.
        bridge.pause_pending.clear()  # Emulate the native batch's completed pause synchronization.
        self.assertTrue(bridge.finish_ready())

    def test_nearer_guest_receives_enemy_hit_without_hurting_host(self):
        bridge = Bridge(io.StringIO(), shared_world=True)
        bridge.router.add_player(0xFF0101, '1', Pose(1, 0, 0, 0))
        bridge.router.add_player(0xFF0102, '2', Pose(0, 0, 0, 0))
        bridge.native_states[2] = (1, 1, 0, 0)
        bridge.created = {1: {2}, 2: {1}}
        enemy = bytearray(0x148)
        struct.pack_into('<Q', enemy, 0x78, 123)
        struct.pack_into('<f', enemy, 0xE0, 20)
        body = melee_packet(123, 0xFFFFFE, 5)
        packet = struct.pack('<QQQH6x', len(body), 0x3000, len(body), 0x14A)
        memory = {game_field(0x568): struct.pack('<QQ', 0x1000, 1), 0x1000: enemy,
                  game_field(0x85C): struct.pack('<f', 2), game_field(0x5E0): struct.pack('<QQ', 0x2000, 1),
                  0x2000: packet, 0x3000: body, 0x4008: struct.pack('<Q', 0x5000)}
        writes = {}
        client = SimpleNamespace(memory=lambda a, n: memory[a][:n], put=writes.__setitem__)
        context = bytearray(1232)
        struct.pack_into('<Q', context, 152, 0x4008)
        struct.pack_into('<Q', context, 184, 123)
        struct.pack_into('<Q', context, 192, 1)
        struct.pack_into('<f', context, 432, 5)
        bridge.route_enemy_hit(client, context)
        self.assertEqual(bridge.guest_hits, [(123, 5, 2)])
        self.assertEqual(q(context, 248), 0x5000)
        self.assertEqual(q(context, 152), 0x4010)
        self.assertEqual(writes[0x3006], packed_guid(0xFF0102))
        marked = body[:6] + packed_guid(0xFF0102) + body[10:]
        self.assertIsNone(bridge.filter_packet(1, 0x14A, marked))
        native = Native.__new__(Native)
        native.base, native.call_return, native.saved_context = 0x140000000, 0x200000, None
        native.put = writes.__setitem__
        struct.pack_into('<Q', context, 152, 0x100008)
        native.call_before(context, HURT, 0x300000, 123, damage=5)
        self.assertEqual(q(context, 184), 123)
        self.assertEqual(q(context, 192), 1)
        self.assertEqual(struct.unpack_from('<f', context, 432)[0], 5)

    def test_native_readiness_requires_the_expected_game(self):
        bridge = Bridge(io.StringIO(), shared_world=True)
        client = SimpleNamespace(number=2, server=0x1000, disable_hooks=set())
        context = bytearray(1232)
        self.assertNotIn(2, bridge.ready)
        with self.assertRaises(RuntimeError):
            bridge(client, MOVE, context)
        self.assertNotIn(2, bridge.ready)
        struct.pack_into('<Q', context, 128, 0x1010)
        bridge(client, MOVE, context)
        self.assertIn(2, bridge.ready)
        self.assertIn(MOVE, client.disable_hooks)

    def test_guest_target_interpolation_stats_and_xp_no_echo(self):
        enemy = bytearray(0x148)
        struct.pack_into('<Q', enemy, 0x78, 123)
        struct.pack_into('<f', enemy, 0xE0, 20)
        struct.pack_into('<8f', enemy, 0xFC, 0, 0, 0, 10, 0, 0, 1, 2)
        memory = {game_field(0x568): struct.pack('<QQ', 0x1000, 1), 0x1000: enemy,
                  game_field(0x85C): struct.pack('<f', 2), game_field(0x33C): b'\x01',
                  relocated(0x65F6848): struct.pack('<I3f', 1, 27.5, 1.6, 6),
                  game_field(0x4FC): struct.pack('<ff', 2, 1), game_field(0x730): struct.pack('<QQ', 0, 0)}
        client = SimpleNamespace(base=0, number=1, memory=lambda a, n: memory[a][:n])
        self.assertEqual(native_enemies(client, 0), [(123, 20, (5, 0, 0))])
        stats = native_melee_stats(client, 0, 1)
        self.assertEqual(stats[:2], (1, 82.5))
        self.assertAlmostEqual(stats[2], 1.92)
        self.assertEqual(stats[3], 6)
        bridge = Bridge(io.StringIO(), shared_world=True)
        context = bytearray(1232)
        struct.pack_into('<Q', context, 136, 3)
        bridge(client, AWARD_XP, context)
        client.number = 2
        bridge(client, AWARD_XP, context)
        self.assertEqual(bridge.xp_pending, 3)
        bridge.guest_stats = stats
        bridge.router.paused = True
        client.number = 1
        self.assertFalse(bridge.before_batch(client, context))

    def test_melee_matches_native_capture_and_damage_abi(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/shared-world-first.jsonl'
        from world_packets import Reader
        body = next(bytes.fromhex(p['body']) for p in map(json.loads, path.read_text().splitlines())
                    if p['event'] == 'world_captured' and p['opcode'] == 0x14A and p['body'].startswith('02000000'))
        reader = Reader(body)
        reader.take(4)
        attacker, target = reader.guid(), reader.guid()
        damage = reader.integer(4)
        self.assertEqual(melee_packet(attacker, target, damage), body)
        client = Native.__new__(Native)
        client.base, client.call_return, client.saved_context = 0x140000000, 0x200000, None
        writes = {}
        client.put = writes.__setitem__
        context = bytearray(1232)
        struct.pack_into('<Q', context, 152, 0x100008)
        client.call_before(context, DAMAGE, 0x300000, target, damage=8.5)
        self.assertEqual(q(context, 136), target)
        self.assertEqual(struct.unpack_from('<f', context, 448)[0], 8.5)
        self.assertEqual(q(context, 192), 0)
        self.assertEqual(writes[q(context, 152) + 0x28], struct.pack('<QQQ', 0, 0, 1))

    def test_native_call_preserves_context_and_shadow_space(self):
        client = Native.__new__(Native)
        client.base, client.call_return, client.saved_context = 0x140000000, 0x200000, None
        writes = {}
        client.put = writes.__setitem__
        context = bytearray(1232)
        struct.pack_into('<Q', context, 152, 0x100008)
        context[512:768] = bytes(range(256))  # XMM register area must survive.
        before = bytes(context)
        client.call_before(context, PAUSE, 0x300000)
        self.assertEqual(client.saved_context, before)
        self.assertEqual(q(context, 152), 0xFFF08)
        self.assertEqual(writes[0xFFF08], struct.pack('<Q', client.call_return))
        self.assertEqual(q(context, 128), 0x300000)
        self.assertEqual(q(context, 248), client.base + PAUSE)
        with self.assertRaises(ValueError):
            client.call_before(context, PAUSE, 0x300000)

    def test_batch_filter_and_cipher_continuation(self):
        key = bytes(range(40))
        source = [(0xA9, b'world'), (0xEE, b'move'), (0x132, b'spell')]
        wire, i, p = encrypt_packets(source, key, 39, 173)
        self.assertEqual(decrypt_batch(wire, key, 39, 173), (source, i, p))
        # Filtering a middle packet changes the recipient's cipher history.
        kept = [source[0], source[2], (0xA9, b'XP')]
        edited, i, p = encrypt_packets(kept, key, 39, 173)
        self.assertEqual(decrypt_batch(edited, key, 39, 173), (kept, i, p))
        later, ni, np = encrypt_packets([(0xEE, b'next')], key, i, p)
        self.assertEqual(decrypt_batch(later, key, i, p), ([(0xEE, b'next')], ni, np))
        for invalid in (wire[:3], wire[:-1]):
            with self.assertRaises(ValueError):
                decrypt_batch(invalid, key, 39, 173)

    def test_entry_push_without_thread_suspension(self):
        for instruction, register in ((b'\x55', 160), (b'\x41\x57', 240), (b'\x41\x56', 232)):
            context = bytearray(1232)
            struct.pack_into('<Q', context, 152, 0x1000)
            struct.pack_into('<Q', context, 248, 0x2000)
            struct.pack_into('<Q', context, register, 0x123456789ABCDEF0)
            writes = {}
            emulate_entry_push(context, instruction, writes.__setitem__)
            self.assertEqual(struct.unpack_from('<Q', context, 152)[0], 0xFF8)
            self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 0x2000 + len(instruction))
            self.assertEqual(writes[0xFF8], struct.pack('<Q', 0x123456789ABCDEF0))

    def test_captured_player_clone_and_cipher_continuation(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/native-world-packets.jsonl'
        packets = [json.loads(line) for line in path.read_text().splitlines()]
        template = next(bytes.fromhex(p['body']) for p in packets
                        if p['opcode'] == 0xA9 and p['body'].startswith('01000000000307feffff0471'))
        pose = Pose(-9390, -630, 68.02375, 2)
        copy = clone_player(template, 0xFF0102, pose)
        self.assertEqual(copy[6:10], packed_guid(0xFF0102))
        self.assertEqual(copy[11], 0x70)
        self.assertEqual(struct.unpack_from('<ff', copy, 20), (-9390, -630))
        fields = 69 + copy[68] * 4
        self.assertEqual(struct.unpack_from('<Q', copy, fields)[0], 0xFF0102)
        self.assertEqual(template[11], 0x71)
        with self.assertRaises(ValueError):
            clone_player(template[:-1], 0xFF0102, pose)
        with self.assertRaises(ValueError):
            clone_player(template, 0, pose)
        key = bytes(range(40))
        wire, index, previous = encrypt_packets([(0xA9, copy), (0xEE, b'abc')], key, 39, 173)
        receiver = HeaderCipher(key)
        receiver.index, receiver.previous = 39, 173
        offset = 0
        for opcode, body in [(0xA9, copy), (0xEE, b'abc')]:
            header = receiver.decrypt(wire[offset:offset + 4])
            self.assertEqual(header, struct.pack('>H', len(body) + 2) + struct.pack('<H', opcode))
            self.assertEqual(wire[offset + 4:offset + 4 + len(body)], body)
            offset += 4 + len(body)
        self.assertEqual((index, previous), (receiver.index, receiver.previous))


if __name__ == '__main__':
    unittest.main()
