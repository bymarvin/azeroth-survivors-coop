"""Four-peer pickup contention through the real fan-out and economy code."""
import copy
import io
import os
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from group_online import GroupOnlineBridge
from native_guest_combat import NativeCombatBridge
from native_probe import OFFER_CHOICES, REMOVE_LOOT, game_field
from sessions import Pose


class Wire:
    def __init__(self):
        self.inbox = []

    def send(self, message):
        self.other.inbox.append(copy.deepcopy(message))

    def drain(self):
        result, self.inbox = self.inbox, []
        return result


class PartyEconomyTests(unittest.TestCase):
    def test_economy_fixture_avoids_existing_map_loot(self):
        from verify_network_economy import clear_loot_center
        pose = Pose(-9396, -633, 68, 0)
        chest = {1: (0, (-9364.158, -634.224, 68.295), 2, 1)}
        self.assertEqual(clear_loot_center(pose, {}), [-9366, -633, 68])
        center = clear_loot_center(pose, chest)
        self.assertGreater(sum((a-b)**2 for a,b in zip(center, chest[1][1])), 100)
        self.assertNotEqual(center, [-9366, -633, 68])
        crowded = {n: (0, (pose.x+n, pose.y, pose.z), 2, 1) for n in range(30, 171, 10)}
        with self.assertRaisesRegex(ValueError, 'No clear'):
            clear_loot_center(pose, crowded)

    def test_economy_fixture_waits_for_running_loot_snapshot(self):
        # Live 14.10.2026: the native start chest at host +30 was missing from
        # the stale snapshot, the fixture landed on it and one guest opened two chests.
        from verify_network_economy import NetworkEconomyVerification
        from native_probe import SPAWN_LOOT
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            host = NetworkEconomyVerification(io.StringIO(), 1, {n: Wire() for n in (2, 3, 4)})
        host.native_states = {n: (1, 1, 0, 0) for n in host.members}
        host.ready = set(host.members)
        host.router.players = {0xFF0101: SimpleNamespace(pose=Pose(-9396, -633, 68, 0))}
        memory = bytearray(0x2000)
        calls = []

        def loot(*chests):
            struct.pack_into('<QQ', memory, game_field(0x5C8), 0x1000, len(chests))
            for i, (guid, position) in enumerate(chests):
                struct.pack_into('<IIQ', memory, 0x1020 + i * 0x48, 2, 1, guid)
                struct.pack_into('<3f', memory, 0x1034 + i * 0x48, *position)

        client = SimpleNamespace(number=1, server=-16,
            memory=lambda a, size: memory[a:a+size],
            put=lambda a, data: memory.__setitem__(slice(a, a+len(data)), data),
            call_before=lambda context, rva, game, *args, **kwargs: calls.append(rva))

        def batch(self, client, context):
            # GroupOnlineBridge.before_batch refreshes the loot after the fixture step.
            self.sync_chests(client, context)
            return False

        start_chest = (-9366.12, -632.7, 68.3)
        loot((0x10, start_chest))
        with patch.object(GroupOnlineBridge, 'before_batch', batch):
            host.before_batch(client, None)
            self.assertIsNone(host.center)  # No center from the pre-start snapshot.
            host.before_batch(client, None)
            self.assertGreater(sum((a - b) ** 2 for a, b in zip(host.center, start_chest)), 100)
            # Native loot appearing on the fixture before the contested chest moves it.
            first = list(host.center)
            host.snapshots.update({n: [100, 100, 0, 1, False] for n in (2, 3, 4)})
            loot((0x10, start_chest), (0x11, tuple(first)))
            host.sync_chests(client, None)
            host.before_batch(client, None)
            self.assertNotEqual(host.center, first)
            self.assertNotIn(SPAWN_LOOT, calls)
            host.before_batch(client, None)
            self.assertEqual(calls.count(SPAWN_LOOT), 1)

    def test_contested_chest_is_private_then_guest_gold_reaches_everyone(self):
        host_wires, guest_wires = {}, {}
        for n in (2, 3, 4):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host_wires[n], guest_wires[n] = a, b
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            host = GroupOnlineBridge(io.StringIO(), 1, host_wires)
            guests = {n: GroupOnlineBridge(io.StringIO(), n, {1: wire}) for n, wire in guest_wires.items()}
        bridges = {1: host, **guests}
        memories, clients, calls = {}, {}, []
        for n, bridge in bridges.items():
            bridge.native_states = {member: (1, 1, 0, 0) for member in bridge.members}
            bridge.router.players = {0xFF0100 + member: SimpleNamespace(pose=Pose(30 if member == 1 else 0, 0, 0, 0))
                                     for member in bridge.members}
            memory = memories[n] = bytearray(0x2000)
            for offset in (0x4A8, 0x6D0):
                struct.pack_into('<I', memory, game_field(offset), 100)
            struct.pack_into('<I', memory, game_field(0x894), 20)
            for offset, value in ((0x510, 5), (0x514, 1), (0x528, 1)):
                struct.pack_into('<f', memory, game_field(offset), value)
            def call_before(context, rva, game, argument, after=None, number=n):
                calls.append((number, rva, argument))
                if rva == REMOVE_LOOT:
                    struct.pack_into('<Q', memories[number], game_field(0x5C8) + 8, 0)
                if after:
                    after()
            clients[n] = SimpleNamespace(number=n, server=-16,
                memory=lambda a, size, memory=memory: memory[a:a+size],
                put=lambda a, data, memory=memory: memory.__setitem__(slice(a, a+len(data)), data),
                call_before=call_before)

        def loot(guid, kind, amount):
            memory = memories[1]
            struct.pack_into('<QQ', memory, game_field(0x5C8), 0x1000, 1)
            struct.pack_into('<IIQ', memory, 0x1020, kind, amount, guid)
            struct.pack_into('<3f', memory, 0x1034, 0, 0, 0)
            host.sync_chests(clients[1], None)
            for guest in guests.values():
                guest.chests = dict(host.chests)

        def poll():
            for bridge in bridges.values():
                bridge.last_network = 0
                bridge.poll_network()

        loot(99, 2, 1)
        for n, guest in guests.items():
            guest.sync_chests(clients[n], None)
            self.assertEqual(struct.unpack_from('<I', memories[n], game_field(0x4A8))[0], 80)
        poll()  # Send all three reservations before host receives any.
        poll()  # Host accepts2 and refunds3/4; only2 owns the chest.
        host.sync_chests(clients[1], None)
        poll()
        # The removed native object must also disappear from the next snapshot.
        host.sync_chests(clients[1], None)
        poll()
        for n, guest in guests.items():
            guest.sync_chests(clients[n], None)
        poll()
        poll()
        for _ in range(3):
            for n, guest in guests.items():
                guest.sync_chests(clients[n], None)
            poll()
        self.assertEqual([struct.unpack_from('<I', memories[n], game_field(0x4A8))[0] for n in bridges],
                         [100, 80, 100, 100])
        self.assertEqual([(n, arg) for n, rva, arg in calls if rva == OFFER_CHOICES], [(2, 1)])
        self.assertIsNone(host.chest_claim)

        loot(100, 1, 12)
        guests[4].sync_chests(clients[4], None)
        poll()
        poll()
        host.sync_chests(clients[1], None)
        host.sync_chests(clients[1], None)
        poll()
        for n, guest in guests.items():
            guest.apply_shared_gold(clients[n])
            guest.apply_shared_gold(clients[n])
            guest.sync_chests(clients[n], None)
        self.assertEqual([struct.unpack_from('<I', memories[n], game_field(0x4A8))[0] for n in bridges],
                         [112, 92, 112, 112])
        self.assertEqual([struct.unpack_from('<I', memories[n], game_field(0x6D0))[0] for n in bridges], [112] * 4)
        self.assertEqual(len([c for c in calls if c[1] == REMOVE_LOOT]), 2)

    def test_four_spawn_centers_remain_balanced_and_distance_bonus_is_bounded(self):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.native_states = {n: (1,) for n in bridge.members}
        bridge.router.players = {0xFF0100 + n: SimpleNamespace(pose=Pose(0, 0, 0, 0)) for n in bridge.members}
        for distance, bonus in ((0, 0), (25, .125), (50, .25), (100, .5), (1000, .5)):
            bridge.router.players[0xFF0104].pose = Pose(distance, 0, 0, 0)
            self.assertEqual(bridge.spawn_bonus(), bonus)
            owners = [bridge.spawn_owner() for _ in range(400)]
            self.assertEqual([owners.count(n) for n in bridge.members], [100] * 4)
        bridge.native_states[4] = (4,)
        self.assertEqual(bridge.spawn_bonus(), 0)
        owners = [bridge.spawn_owner() for _ in range(300)]
        self.assertEqual([owners.count(n) for n in bridge.members], [100, 100, 100, 0])


if __name__ == '__main__':
    unittest.main()
