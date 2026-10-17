"""Regression checks: native ground spells (Rain of Fire DynamicObjects) are shared.

Layout from the native create RVA 0x5496b20 (0.84.3): GUID 0xF100.. | Game+0x894
counter, create block type 6 with flags 0x50, fields 0/1 GUID, 2 = 0x41,
3 = spell, 4 = scale, 6/7 caster, 8 = 1, 9 = spell, 10 = radius, 11..13 xyz, 14 = 0.
Expiry sends DESTROY 0xAA with the same GUID (RVA 0x54593ba).
"""
import io
import os
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from world_packets import HOST, SELF, UPDATE, DESTROY, objects, object_packet, dynamic_object, dynamic_caster
from visibility_bridge import Bridge, packed_guid
from native_guest_combat import NativeCombatBridge
from group_online import GroupOnlineBridge

RAIN_OF_FIRE = 5740


def ground_spell(counter, caster=SELF, spell=RAIN_OF_FIRE, pos=(-1597.5, -630.0, 69.25), field_type=0x41):
    guid = 0xF100000000000000 | counter
    f = lambda v: struct.unpack('<I', struct.pack('<f', v))[0]
    fields = {0: guid & 0xFFFFFFFF, 1: guid >> 32, 2: field_type, 3: spell, 4: f(1.0),
              6: caster & 0xFFFFFFFF, 7: caster >> 32, 8: 1, 9: spell, 10: f(8.0),
              11: f(pos[0]), 12: f(pos[1]), 13: f(pos[2]), 14: 0}
    mask = sum(1 << k for k in fields).to_bytes(4, 'little')
    return (struct.pack('<IBB', 1, 0, 2) + packed_guid(guid) + bytes([6, 0x50]) +
            struct.pack('<4fI', *pos, 0, 1) + bytes([1]) + mask +
            b''.join(struct.pack('<I', fields[k]) for k in sorted(fields)))


def guest_bridge():
    with patch.dict(os.environ, COOP_PLAYERS='4'):
        bridge = NativeCombatBridge(io.StringIO())
    bridge.native_totem_guids = lambda number: set()
    return bridge


class DynamicObjectTests(unittest.TestCase):
    def test_native_layout_is_parsed_and_malformed_creates_fail_closed(self):
        block, = objects(ground_spell(5), remap=False)
        self.assertTrue(dynamic_object(block))
        self.assertEqual((block.guid, dynamic_caster(block), block.fields[9]), (0xF100000000000005, SELF, RAIN_OF_FIRE))
        tagged, = objects(object_packet(objects(ground_spell(5), guid_map={0xF100000000000005: 0xF100000000400005})), remap=False)
        self.assertTrue(dynamic_object(tagged, native=False))
        for body in (ground_spell(1 << 22), ground_spell(5, field_type=0x21)):
            with self.assertRaises(ValueError):
                dynamic_object(objects(body, remap=False)[0])
        unit = struct.pack('<IBB', 1, 0, 2) + packed_guid(7) + bytes([3, 0, 0])
        self.assertFalse(dynamic_object(objects(unit, remap=False)[0]))

    def test_host_ground_spell_reaches_guests_and_expires(self):
        bridge = Bridge(io.StringIO(), shared_world=True)
        bridge.record = lambda **event: None
        self.assertEqual(bridge.filter_packet(1, UPDATE, ground_spell(5)), ground_spell(5))  # Host keeps its own.
        (opcode, body), = bridge.world_pending
        block, = objects(body, remap=False)
        self.assertEqual((opcode, block.guid, dynamic_caster(block)), (UPDATE, 0xF100000000000005, HOST))
        self.assertIn(block.guid, bridge.world_guids)
        bridge.filter_packet(1, DESTROY, struct.pack('<Q', block.guid))
        self.assertEqual(bridge.world_pending[-1], (DESTROY, struct.pack('<Q', block.guid)))
        self.assertNotIn(block.guid, bridge.world_guids)
        with self.assertRaises(ValueError):
            bridge.capture_world(UPDATE, ground_spell(1 << 22))

    def test_guest_ground_spell_is_local_and_fanned_out_then_destroyed(self):
        bridge = guest_bridge()
        bridge.trace_packets = True  # COOP_TRACE_PACKETS=1 records the extra evidence.
        events = []
        bridge.record = lambda **event: events.append(event)
        for number in (2, 3, 4):
            native = 0xF100000000000009
            network = native | ((number - 1) << 22)
            local, = objects(bridge.filter_packet(number, UPDATE, ground_spell(9)), remap=False)
            self.assertEqual((local.guid, dynamic_caster(local)), (network, SELF))
            self.assertEqual(local.fields[0] | local.fields[1] << 32, network)
            for recipient in bridge.members:
                if recipient == number:
                    self.assertFalse(bridge.attack_packets[recipient])
                    continue
                (opcode, body), = bridge.attack_packets[recipient]
                shown, = objects(body, remap=False)
                self.assertEqual((opcode, shown.guid, dynamic_caster(shown)), (UPDATE, network, 0xFF0100 + number))
                bridge.attack_packets[recipient].clear()
            self.assertEqual(bridge.summons[number], {network})
            dead = bridge.filter_packet(number, DESTROY, struct.pack('<Q', native))
            self.assertEqual(dead, struct.pack('<Q', network))
            for recipient in bridge.members:
                if recipient != number:
                    self.assertEqual(bridge.attack_packets[recipient].pop(), (DESTROY, struct.pack('<Q', network)))
            self.assertFalse(bridge.summons[number] or bridge.summon_maps[number] or bridge.dynamic_guids[number])
            self.assertIsNone(bridge.filter_packet(number, DESTROY, struct.pack('<Q', native)))  # Repeated destroy.
        self.assertEqual(sum(e['event'] == 'guest_ground_spell_created' for e in events), 3)

    def test_equal_native_counters_never_collide(self):
        host = Bridge(io.StringIO(), shared_world=True)
        host.record = lambda **event: None
        host.capture_world(UPDATE, ground_spell(1))
        guids = {objects(host.world_pending[0][1], remap=False)[0].guid}
        bridge = guest_bridge()
        for number in (2, 3, 4):
            guids.add(objects(bridge.filter_packet(number, UPDATE, ground_spell(1)), remap=False)[0].guid)
        self.assertEqual(len(guids), 4)

    def test_mirror_enemy_ground_spell_stays_hidden(self):
        bridge = guest_bridge()
        self.assertIsNone(bridge.filter_packet(2, UPDATE, ground_spell(3, caster=0xF130002329000001)))
        self.assertFalse(any(bridge.attack_packets.values()))

    def test_relayed_ground_spell_validation_and_departure_cleanup(self):
        wire = SimpleNamespace(send=lambda message: None, drain=lambda: [], close=lambda: None)
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            host = GroupOnlineBridge(io.StringIO(), 1, {n: wire for n in (2, 3, 4)})
        guest = guest_bridge()
        relayed = guest.filter_packet(2, UPDATE, ground_spell(4))
        _, packet = guest.attack_packets[1].pop()
        remote = 0xF100000000400004
        with self.assertRaises(ValueError):
            host.receive_summon_packet(UPDATE, packet, 3)  # Claimed by another guest.
        wrong = object_packet(objects(ground_spell(4, caster=0xFF0103), guid_map={0xF100000000000004: remote}))
        with self.assertRaises(ValueError):
            host.receive_summon_packet(UPDATE, wrong, 2)
        host.receive_summon_packet(UPDATE, packet, 2)
        self.assertIn(remote, host.summons[2])
        host.remove_guest(2)
        for n in (1, 3, 4):
            self.assertIn((DESTROY, struct.pack('<Q', remote)), host.notice_packets[n])
        self.assertIsNotNone(relayed)


if __name__ == '__main__':
    unittest.main()
