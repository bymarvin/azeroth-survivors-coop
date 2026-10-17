import ctypes as C
import copy
import io
import os
import struct
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from boss_rewards import BossRewards, DIFFICULTY, FREE, LOOT_TABLE, MAP_TABLE, RESERVE_REWARDS, reward_code


class EmptyBridge:
    def __init__(self):
        self.guests = (2, 3, 4)
        self.extra_hooks = ()


class RewardsTests(unittest.TestCase):
    def test_native_map_uses_verified_record_layout(self):
        from boss_rewards import native_map
        for stride, name_offset, boss_offset in ((160, 0, 64), (184, 8, 88)):
            row = bytearray(boss_offset + 8)
            struct.pack_into('<QQ', row, name_offset, 0x9000, 8)
            struct.pack_into('<Q', row, boss_offset, 0xA000)
            data = {0x2000 + 0x2D8: struct.pack('<QQ', 0x9000, 8), 0x9000: b'duskwood',
                    MAP_TABLE: bytes(len(row)), MAP_TABLE + stride: bytes(row)}
            client = SimpleNamespace(base=0, memory=lambda a, n: data[a][:n])
            offsets = {0: name_offset, 8: name_offset + 8, 64: boss_offset, 160: stride}
            with patch('boss_rewards.reviewed_rva', side_effect=lambda rva: rva), patch('boss_rewards.field', side_effect=lambda domain, offset:
                       offsets[offset] if domain == 'map' else offset):
                self.assertEqual(native_map(client, 0x2000), (1, 0xA000))

    def test_final_boss_pickup_gold_is_shared_after_host_enters_victory(self):
        from native_guest_combat import NativeCombatBridge
        from native_probe import game_field
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.ready = {1, 2, 3, 4}
        bridge.native_states = {n: (5, 5, 21, 0) for n in bridge.members}
        bridge.gold_seen, bridge.gold_counter = 48, 0x9000
        host = SimpleNamespace(number=1, server=-16, memory=lambda a, n: bytes(4) if a == 0x6E8 else struct.pack('<Q', 120))
        bridge.before_batch(host, None)
        bridge.before_batch(host, None)  # Replayed terminal batch must not credit twice.
        for number in bridge.guests:
            memory = bytearray(0x900)
            for offset in (0x4A8, 0x6D0):
                struct.pack_into('<I', memory, game_field(offset), 48)
            guest = SimpleNamespace(number=number, server=-16,
                                    memory=lambda a, n: memory[a:a+n],
                                    put=lambda a, data: memory.__setitem__(slice(a, a+len(data)), data))
            bridge.before_batch(guest, None)
            self.assertEqual(struct.unpack_from('<I', memory, game_field(0x4A8))[0], 120)
            self.assertEqual(struct.unpack_from('<I', memory, game_field(0x6D0))[0], 120)
        self.assertEqual(bridge.gold_seen, 120)

    def test_wrong_native_map_cannot_award_a_boss_item(self):
        class Bridge(BossRewards, EmptyBridge):
            pass
        bridge = Bridge()
        bridge.ready = {2}
        bridge.receive_boss_rewards(2, [dict(sequence=1, map=0, boss=4)])
        row = bytearray(0x48)
        struct.pack_into('<QQ', row, 0, 0x9000, 8)
        struct.pack_into('<Q', row, 0x40, 0xA000)
        data = {0x2000 + 0x2D8: struct.pack('<QQ', 0x9000, 8),
                0x9000: b'duskwood', MAP_TABLE: bytes(0x48), MAP_TABLE + 0xA0: bytes(row)}
        client = SimpleNamespace(number=2, server=0x2000 - 16, base=0, memory=lambda a, n: data[a][:n])
        with patch('boss_rewards.reviewed_rva', side_effect=lambda rva: rva), patch('boss_rewards.field', side_effect=lambda domain, offset: offset), self.assertRaisesRegex(ValueError, 'Guest map differs'):
            bridge.before_batch(client, None)

    def test_four_peer_boss_events_wait_for_every_ack(self):
        from group_online import GroupOnlineBridge
        class Wire:
            def __init__(self):
                self.inbox = []
            def send(self, message):
                self.other.inbox.append(copy.deepcopy(message))
            def drain(self):
                result, self.inbox = self.inbox, []
                return result
        hosts, guests = {}, {}
        for number in (2, 3, 4):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            hosts[number], guests[number] = a, b
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            host = GroupOnlineBridge(io.StringIO(), 1, hosts)
            peers = {n: GroupOnlineBridge(io.StringIO(), n, {1: w}) for n, w in guests.items()}
        event = dict(sequence=1, map=0, boss=-1)
        host.boss_reward_events.append(event)
        host.boss_reward_sequence = 1
        host.poll_network()
        for number, peer in peers.items():
            peer.poll_network()
            self.assertEqual(peer.boss_reward_pending[number], [event])
            peer.boss_reward_applied[number] = 1
            peer.last_network = 0
            peer.poll_network()
            host.poll_network()
            self.assertEqual(bool(host.boss_reward_events), number != 4)
        self.assertEqual(host.boss_reward_sequence, 1)

    def test_reward_delivery_is_ordered_idempotent_and_private(self):
        class Bridge(BossRewards, EmptyBridge):
            pass
        bridge = Bridge()
        event = dict(sequence=1, map=0, boss=4)
        bridge.receive_boss_rewards(2, [event, event])
        self.assertEqual(bridge.boss_reward_pending[2], [event])
        self.assertEqual(bridge.boss_reward_pending[3], [])
        with self.assertRaises(ValueError):
            bridge.receive_boss_rewards(2, [dict(sequence=3, map=0, boss=4)])
        with self.assertRaises(ValueError):
            bridge.receive_boss_rewards(3, [dict(sequence=1, map=9, boss=4)])

    @unittest.skipUnless(os.name == 'nt', 'Exercises the Windows x64 wrapper ABI')
    def test_executable_wrapper_matches_native_rng_and_float_chance_rules(self):
        self.exercise_wrapper(0)

    @unittest.skipUnless(os.name == 'nt', 'Exercises the Windows x64 wrapper ABI')
    def test_executable_wrapper_uses_relocated_native_dependencies(self):
        self.exercise_wrapper(0x2000)

    def exercise_wrapper(self, shift):
        # A private process allocation stands in for the native image. The four
        # called functions are tiny ABI stubs; the real reward wrapper executes
        # unchanged on the CPU, with the game's field layout and RNG state.
        alloc, free = C.windll.kernel32.VirtualAlloc, C.windll.kernel32.VirtualFree
        alloc.argtypes, alloc.restype = [C.c_void_p, C.c_size_t, C.c_uint32, C.c_uint32], C.c_void_p
        free.argtypes, free.restype = [C.c_void_p, C.c_size_t, C.c_uint32], C.c_int
        base = alloc(None, RESERVE_REWARDS + shift + 4096, 0x3000, 0x40)
        self.assertTrue(base)
        try:
            game = C.create_string_buffer(0x900)
            items = C.create_string_buffer(struct.pack('<IfIfIfIf', 101, 0, 102, .2, 103, .5, 104, 1))
            rewards = C.create_string_buffer(64)
            observed = C.create_string_buffer(24)
            # Native table signature: return Vec in RCX, class DL, map R8, boss R9.
            table_stub = (bytes.fromhex('49 bb') + struct.pack('<Q', C.addressof(observed)) +
                          bytes.fromhex('49 89 13 4d 89 43 08 4d 89 4b 10 48 c7 01 04 00 00 00 48 b8') +
                          struct.pack('<Q', C.addressof(items)) + bytes.fromhex('48 89 41 08 48 c7 41 10 04 00 00 00 c3'))
            C.memmove(base + LOOT_TABLE + shift, table_stub, len(table_stub))
            difficulty_stub = bytes.fromhex('b8 00 00 40 3f 66 0f 6e c0 c3')  # .75f
            C.memmove(base + DIFFICULTY + shift, difficulty_stub, len(difficulty_stub))
            C.memmove(base + FREE + shift, b'\xc3', 1)
            C.memmove(base + RESERVE_REWARDS + shift, b'\xcc', 1)  # Capacity sufficient; unexpected reserve fails.
            # This private ABI fixture has the reviewed layout, regardless of
            # which active game profile another test imported first.
            with patch('boss_rewards.reviewed_rva', side_effect=lambda rva: rva + shift), \
                    patch('boss_rewards.code_fields', side_effect=lambda code, *args: code):
                code = reward_code(base)
            C.memmove(base + 0x1000, code, len(code))
            call = C.CFUNCTYPE(None, C.c_void_p, C.c_uint64)(base + 0x1000)
            f32 = lambda x: struct.unpack('<f', struct.pack('<f', x))[0]
            mask = (1 << 64) - 1
            def rol(x, n):
                return ((x << n) | (x >> (64 - n))) & mask
            for seed in ((1, 2, 3, 4), (0x123456789abcdef, 37, 0xfeedface, 0x12345678)):
                game[:] = bytes(len(game))
                struct.pack_into('<QQQ', game, 0x648, 16, C.addressof(rewards), 0)
                struct.pack_into('<QQQQ', game, 0x818, *seed)
                struct.pack_into('<f', game, 0x2D0, .1)
                game[0x34C] = 8
                state, expected = list(seed), []
                for item, chance in ((101, 0), (102, .2), (103, .5), (104, 1)):
                    result = (rol((state[0] + state[3]) & mask, 23) + state[0]) & mask
                    temporary = (state[1] << 17) & mask
                    state[2] ^= state[0]; state[3] ^= state[1]
                    state[1] ^= state[2]; state[0] ^= state[3]
                    state[2] ^= temporary; state[3] = rol(state[3], 45)
                    if f32(f32(f32(chance) + f32(.1)) * .75) > f32((result >> 40) * 2**-24):
                        expected.append(item)
                call(C.addressof(game), (3 << 8) | 4)
                count = struct.unpack_from('<Q', game, 0x658)[0]
                self.assertEqual(list(struct.unpack_from('<' + 'I' * count, rewards)), expected)
                self.assertEqual(struct.unpack_from('<4Q', game, 0x818), tuple(state))
                self.assertEqual(struct.unpack_from('<I', game, 0x6DC)[0], 1)
                args = struct.unpack('<3Q', observed)
                self.assertEqual((args[0] & 255, args[1], args[2]), (8, 3, 4))
        finally:
            self.assertTrue(free(base, 0, 0x8000))


if __name__ == '__main__':
    unittest.main()
