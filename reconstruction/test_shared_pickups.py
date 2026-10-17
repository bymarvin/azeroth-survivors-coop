"""Party reward ownership and bounded wire regression checks; no game launch."""
import io
import os
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from native_guest_combat import NativeCombatBridge
from native_probe import REMOVE_LOOT, game_field
from group_online import GroupOnlineBridge
from test_party_economy import Wire


class SharedPickupTests(unittest.TestCase):
    def test_native_and_guest_powerup_collection_have_one_effect_per_recipient(self):
        for injected in (False, True):
            for kind in (3, 4, 5, 6):
                with patch.dict(os.environ, COOP_PLAYERS='4'):
                    bridge = NativeCombatBridge(io.StringIO())
                memory = bytearray(0x3000)
                struct.pack_into('<QQ', memory, game_field(0x5C8), 0x1000, 1)
                struct.pack_into('<I', memory, 0x1020, kind)
                struct.pack_into('<Q', memory, 0x2000, 0x888)
                client = SimpleNamespace(number=1, server=-16, saved_context=object() if injected else None,
                    call_return=0x888, memory=lambda address, size: memory[address:address+size])
                context = bytearray(1232)
                struct.pack_into('<Q', context, 152, 0x2000)
                bridge(client, REMOVE_LOOT, context)
                self.assertEqual(bridge.powerups_pending,
                                 {n: [kind] if injected or n != 1 else [] for n in range(1, 5)})

    def test_party_xp_adds_bonuses_and_departure_removes_only_that_bonus(self):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.xp_multipliers = {1: 1.1, 2: 1.2, 3: 1, 4: 1.5}
        self.assertAlmostEqual(bridge.party_xp_multiplier(), 1.8)
        bridge.members = (1, 2, 3)
        self.assertAlmostEqual(bridge.party_xp_multiplier(), 1.3)
        self.assertEqual(bridge.xp_multipliers[1], 1.1)

    def test_powerup_fanout_is_private_to_each_recipient_and_not_replayed(self):
        hosts, guests = {}, {}
        for n in (2, 3, 4):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            hosts[n], guests[n] = a, b
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            host = GroupOnlineBridge(io.StringIO(), 1, hosts)
            peers = {n: GroupOnlineBridge(io.StringIO(), n, {1: wire}) for n, wire in guests.items()}
        for n in peers:
            host.powerups_pending[n].extend((3, 4, 5, 6))
            peers[n].xp_multipliers[n] = 1 + n / 10
        for _ in range(3):
            for bridge in (host, *peers.values()):
                bridge.last_network = 0
                bridge.poll_network()
        for n, guest in peers.items():
            self.assertEqual(guest.powerups_pending[n], [3, 4, 5, 6])
            self.assertEqual(host.powerups_pending[n], [])
        self.assertAlmostEqual(host.party_xp_multiplier(), 1.9)


if __name__ == '__main__':
    unittest.main()
