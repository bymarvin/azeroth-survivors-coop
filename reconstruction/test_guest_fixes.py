"""Regressions from the 0.93.1/0.95.0 player reports: endgame guest damage bounds."""
import io
import json
import os
import struct
import time
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import native_probe as native
from group_online import GroupOnlineBridge
from native_guest_combat import NativeCombatBridge, enemy_offset
from test_party_departure import Wire
from updated_layout import enemy_layout, family

# Crash report 20261016T200926 (guest 2, level 61): two AoE Execute hits of
# 62 279 on one high-health enemy within one mirror batch.
EXECUTE = 62279.0
TARGET = 0xF130000261005ED7


def mirror_client(guid, health):
    stride = enemy_layout()[0]
    enemy = bytearray(stride)
    struct.pack_into('<Q', enemy, enemy_offset(0x78), guid)
    struct.pack_into('<f', enemy, enemy_offset(0xE0), health)
    def memory(address, size):
        return struct.pack('<QQ', 4096, 1) if size == 16 else bytes(enemy)
    return SimpleNamespace(number=2, server=0, memory=memory)


class EndgameDamageBoundTests(unittest.TestCase):
    def guest(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            return NativeCombatBridge(io.StringIO(), shared_world=True)

    def test_two_execute_hits_in_one_batch_are_queued(self):
        bridge = self.guest()
        bridge.provided_hp = {TARGET: 300000.0}
        bridge.enemy_snapshot = {TARGET: None}
        bridge.sync_mirrors(mirror_client(TARGET, 300000.0 - 2 * EXECUTE), None, capture_only=True)
        self.assertAlmostEqual(bridge.damage_pending[TARGET], 2 * EXECUTE, places=0)

    def test_queue_still_rejects_nonsensical_damage(self):
        bridge = self.guest()
        bridge.provided_hp = {TARGET: native.MAX_ENEMY_DAMAGE * 3}
        bridge.enemy_snapshot = {TARGET: None}
        with self.assertRaisesRegex(ValueError, 'Guest damage queue exceeds bound'):
            bridge.sync_mirrors(mirror_client(TARGET, 0.0), None, capture_only=True)

    def test_host_accepts_endgame_delta_from_guest(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host = GroupOnlineBridge(io.StringIO(), 1, {2: a})
            guest = GroupOnlineBridge(io.StringIO(), 2, {1: b})
        for bridge in (host, guest):
            bridge.native_states = {1: (1, 1, 0, 0), 2: (1, 1, 0, 0)}
        host.poll_network()
        guest.poll_network()
        guest.damage_pending[TARGET] = 2 * EXECUTE
        guest.last_network = 0
        guest.poll_network()
        host.poll_network()
        self.assertEqual(host.damage_pending, {TARGET: 2 * EXECUTE})

    def native_call(self, rva, damage):
        context = bytearray(1232)
        struct.pack_into('<Q', context, 152, 0x10108)  # Function-entry alignment.
        client = SimpleNamespace(saved_context=None, base=0x140000000, call_return=0x5000, put=Mock())
        native.Native.call_before(client, context, rva, 0x6000, TARGET, damage=damage)
        return context

    def test_native_damage_call_accepts_endgame_hit(self):
        context = self.native_call(native.DAMAGE, 2 * EXECUTE)
        self.assertEqual(struct.unpack_from('<f', context, 448)[0], 2 * EXECUTE)
        with self.assertRaisesRegex(ValueError, 'Invalid native damage'):
            self.native_call(native.DAMAGE, native.MAX_ENEMY_DAMAGE * 2)

    def test_incoming_hit_bound_is_far_above_endless_play(self):
        from play_limits import MAX_HIT_DAMAGE
        self.native_call(native.HURT, 1e6)  # 10x the old 100 000 is a valid native call.
        with self.assertRaisesRegex(ValueError, 'Invalid native damage'):
            self.native_call(native.HURT, MAX_HIT_DAMAGE * 2)


def exe_bytes(rva, size):
    data = (Path(native.ROOT) / 'AzerothSurvivors.exe').read_bytes()
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    count, optional = struct.unpack_from('<H', data, pe + 6)[0], struct.unpack_from('<H', data, pe + 20)[0]
    for i in range(count):
        size_v, address, _, raw = struct.unpack_from('<IIII', data, pe + 24 + optional + i * 40 + 8)
        if address <= rva < address + size_v:
            return data[raw + rva - address:raw + rva - address + size]
    raise ValueError('RVA outside image')


class RunMeterTests(unittest.TestCase):
    """Injected guest hits must not enter the host's run meter (shown as "Melee")."""

    def test_run_meter_call_is_skipped_with_exact_native_bytes(self):
        from updated_layout import release_47e4
        from visibility_bridge import guest_damage_patches
        if not release_47e4():
            self.skipTest('run meter exists in the 47e4 family only')
        start, resume, meter = family('run_meter')
        offset, original, replacement = guest_damage_patches()[-1]
        self.assertEqual((offset, len(original), len(replacement)), (start, resume - start, resume - start))
        self.assertEqual(original, exe_bytes(start, resume - start))
        self.assertEqual(original[:7], bytes.fromhex('488d8ec8050000'))  # lea rcx,[rsi+0x5C8]: run meter
        self.assertEqual(start + 2 + replacement[1], resume)
        self.assertEqual(replacement[0], 0xEB)
        # The boss meter call that the reviewed patch skips uses the same meter function.
        boss = exe_bytes(resume, 0x200).find(bytes.fromhex('488d8ef8050000'))
        call = exe_bytes(resume + boss + 13, 5)
        self.assertEqual(resume + boss + 18 + struct.unpack('<i', call[1:])[0], meter)


# Captured native unit CREATE (Shaman totem, entry 9500): SUMMONEDBY = CREATEDBY = SELF.
UNIT = ('010000000003d95e1c2530f1037000000000000000002dd012c60ae01dc48e5488420000000000000000000020400000e0400000'
        '9040711c974000002040db0f494001000000051ff040100c40000000000000000000001e0000005e00001c250030f109000000'
        '1c2500000000803ffeffff0000000000feffff00000000000500000005000000110000000200000002000000cdcccc3e0000803f'
        'eb110000eb110000')


class CompanionTests(unittest.TestCase):
    """Guest companions (pets) are not in the native totem vector but name their owner."""

    def bridge(self):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.native_totem_guids = lambda number: set()
        return bridge

    def test_companion_outside_totem_vector_reaches_owner_and_party(self):
        from world_packets import objects, UPDATE, DESTROY, MONSTER
        captured = bytes.fromhex(UNIT)
        guid = objects(captured, remap=False)[0].guid
        bridge = self.bridge()
        for number in (2, 3, 4):
            shown, = objects(bridge.filter_packet(number, UPDATE, captured), remap=False)
            expected = guid | ((number - 1) << 22)
            self.assertEqual(shown.guid, expected)
            for recipient in bridge.members:
                if recipient != number:
                    _, body = bridge.attack_packets[recipient].pop()
                    remote, = objects(body, remap=False)
                    self.assertEqual(remote.guid, expected)
                    self.assertEqual(remote.fields[12], 0xFF0100 + number)  # Owner as seen by the party.
            # Movement and removal follow the identity mapping.
            move = bridge.filter_packet(number, MONSTER, bytes([0xD9, 0x5E, 0x1C, 0x25, 0x30, 0xF1]) + bytes(25))
            self.assertIsNotNone(move)
            dead = bridge.filter_packet(number, DESTROY, struct.pack('<Q', guid))
            self.assertEqual(struct.unpack('<Q', dead)[0], expected)
            self.assertFalse(bridge.summons[number])
            for queue in bridge.attack_packets.values():
                queue.clear()

    def test_pet_guid_namespace_and_receiver_validation(self):
        from world_packets import objects, object_packet, UPDATE, SELF
        pet = bytes.fromhex(UNIT.replace('d95e1c2530f1', 'd95e1c2540f1').replace('5e00001c250030f1', '5e00001c250040f1'))
        guid = objects(pet, remap=False)[0].guid
        self.assertEqual(guid >> 48, 0xF140)
        bridge = self.bridge()
        bridge.filter_packet(2, UPDATE, pet)
        _, body = bridge.attack_packets[1].pop()
        wire = SimpleNamespace(send=lambda message: None, drain=lambda: [], close=lambda: None)
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            host = GroupOnlineBridge(io.StringIO(), 1, {n: wire for n in (2, 3, 4)})
        host.receive_summon_packet(UPDATE, body, 2)
        self.assertIn(guid | (1 << 22), host.summons[2])
        with self.assertRaises(ValueError):
            host.receive_summon_packet(UPDATE, body, 3)

    def test_unowned_units_stay_hidden(self):
        from world_packets import UPDATE
        mirror = bytes.fromhex(UNIT.replace('feffff00', '00000000'))
        self.assertIsNone(self.bridge().filter_packet(2, UPDATE, mirror))

    def test_companion_outside_namespace_is_logged_not_fatal(self):
        from world_packets import objects, UPDATE
        wide = bytes.fromhex(UNIT.replace('d95e1c2530f1', 'dd5e401c2530f1').replace('5e00001c', '5e00401c'))
        self.assertTrue(objects(wide, remap=False)[0].guid & 0xC00000)
        bridge = self.bridge()
        self.assertIsNone(bridge.filter_packet(2, UPDATE, wide))
        self.assertEqual(len(bridge.unmapped_companions), 1)


ENEMY = 0xF13000025800000D
REND, CORRUPTION = 772, 172


def values(guid, fields):
    from world_packets import objects, values_packet
    return objects(values_packet(guid, fields), remap=False)[0]


class GuestAuraTests(unittest.TestCase):
    """Guest debuffs appear in free debuff slots of the shared enemy for everyone."""

    def test_slot_layout_matches_captured_host_debuff(self):
        from guest_auras import slot_auras
        # Captured host update: Rend in field 79, its flags in 99, applications in 121.
        self.assertEqual(slot_auras({79: REND, 99: 0x9, 121: 0x2}), {32: (REND, 0x9, 0, 2)})

    def test_guest_reports_only_changes(self):
        from guest_auras import OwnAuras
        own = OwnAuras()
        own.observe(values(ENEMY, {79: CORRUPTION, 99: 0x9}))
        self.assertEqual(own.take_changes(), [[ENEMY, [[CORRUPTION, 0x9, 0, 0]]]])
        own.observe(values(ENEMY, {22: 50}))  # Health only.
        self.assertEqual(own.take_changes(), [])
        own.destroy(ENEMY)
        self.assertEqual(own.take_changes(), [[ENEMY, []]])

    def test_overlay_uses_free_top_slots_and_keeps_host_debuffs(self):
        from guest_auras import AuraOverlay
        overlay = AuraOverlay()
        overlay.host_block(values(ENEMY, {79: REND, 99: 0x9}))
        overlay.guest_auras(2, {ENEMY: [(CORRUPTION, 0x9, 0, 0), (REND, 0x9, 0, 0)]})
        self.assertEqual(overlay.updates({ENEMY}), [(ENEMY, {94: CORRUPTION, 100: 0x90000000})])
        # The host's own new debuff in slot 40 rewrites the shared flags field.
        overlay.host_block(values(ENEMY, {87: 1160, 100: 0x9}))
        overlay.guest_auras(2, {ENEMY: [(CORRUPTION, 0x9, 0, 0)]})
        self.assertEqual(overlay.updates({ENEMY}), [(ENEMY, {100: 0x90000009})])
        overlay.guest_auras(2, {ENEMY: []})
        self.assertEqual(overlay.updates({ENEMY}), [(ENEMY, {94: 0, 100: 0x9})])

    def test_overlay_waits_for_visible_enemy_and_forgets_out_of_range(self):
        from guest_auras import AuraOverlay
        from world_packets import ObjectBlock
        overlay = AuraOverlay()
        overlay.guest_auras(3, {ENEMY: [(CORRUPTION, 0x9, 0, 0)]})
        self.assertEqual(overlay.updates(set()), [])
        self.assertEqual(overlay.updates({ENEMY}), [(ENEMY, {94: CORRUPTION, 100: 0x90000000})])
        overlay.host_block(ObjectBlock(4, ENEMY, None, b'', {}))
        self.assertNotIn(ENEMY, overlay.guests)

    def test_invalid_guest_auras_are_rejected(self):
        from guest_auras import validate_auras
        for auras in ([[ENEMY, [[CORRUPTION, 0x10, 0, 0]]]], [[0xFF0102, []]], [[ENEMY, [[0, 0, 0, 0]]]], 'x'):
            with self.assertRaises(ValueError):
                validate_auras(auras)

    def test_local_guest_mirror_debuff_reaches_every_client(self):
        from world_packets import objects, values_packet, UPDATE
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.world_guids.add(ENEMY)
        self.assertIsNone(bridge.filter_packet(3, UPDATE, values_packet(ENEMY, {79: CORRUPTION, 99: 0x9})))
        self.assertEqual(bridge.notice_packets[1], [])  # Written with the next host world block.
        bridge.filter_packet(1, UPDATE, values_packet(ENEMY, {22: 40}))
        queues = {1: bridge.notice_packets[1], 2: bridge.world_pending, **bridge.world_queues}
        for recipient in bridge.members:
            *_, (opcode, body) = queues[recipient]
            block, = objects(body, remap=False)
            self.assertEqual((opcode, block.guid, block.fields[94]), (UPDATE, ENEMY, CORRUPTION))
        self.assertEqual(bridge.counts['world_captured'], 2 * len(bridge.guests))  # Host block + overlay.
        # Every queued world packet has its capture evidence (boss/party verifiers resolve deliveries).
        import hashlib
        captured = {(r['recipient'], r['digest']) for r in map(json.loads, bridge.output.getvalue().splitlines())
                    if r['event'] == 'world_captured'}
        for recipient in bridge.guests:
            for _, body in queues[recipient]:
                self.assertIn((recipient, hashlib.sha256(body).hexdigest()), captured)

    def test_overlay_follows_host_write_to_shared_packed_field_in_same_frame(self):
        from world_packets import objects, values_packet, UPDATE, SELF
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.world_guids.add(ENEMY)
        bridge.filter_packet(3, UPDATE, values_packet(ENEMY, {79: CORRUPTION, 99: 0x9}))
        for queue in (bridge.notice_packets[1], bridge.world_pending, *bridge.world_queues.values()):
            queue.clear()
        # The host's native game puts a debuff into slot 40: its write to field 100 also
        # clears the flags of our slot 47 on every client.
        bridge.filter_packet(1, UPDATE, values_packet(ENEMY, {87: 1160, 100: 0x9}))
        for queue in (bridge.world_pending, *bridge.world_queues.values()):
            host, ours = [objects(body, remap=False)[0].fields for _, body in queue]
            self.assertEqual((host[100], ours[100]), (0x9, 0x90000009))  # Host first, then ours.
        (_, body), = bridge.notice_packets[1]  # Host client: after its native batch.
        self.assertEqual(objects(body, remap=False)[0].fields[100], 0x90000009)

    def test_network_guest_debuff_reaches_host_and_guest(self):
        from world_packets import objects
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host = GroupOnlineBridge(io.StringIO(), 1, {2: a})
            guest = GroupOnlineBridge(io.StringIO(), 2, {1: b})
        for bridge in (host, guest):
            bridge.native_states = {1: (1, 1, 0, 0), 2: (1, 1, 0, 0)}
        host.world_guids.add(ENEMY)
        host.poll_network()
        guest.poll_network()
        guest.own_auras[2].observe(values(ENEMY, {79: CORRUPTION, 99: 0x9}))
        from world_packets import values_packet, UPDATE
        guest.last_network = 0
        guest.poll_network()
        host.poll_network()  # Received while the group bridge swaps its world counters.
        host.filter_packet(1, UPDATE, values_packet(ENEMY, {22: 40}))  # Next host world block.
        (_, body), = host.notice_packets[1]
        self.assertEqual(objects(body, remap=False)[0].fields[94], CORRUPTION)
        host.last_network = 0
        host.poll_network()
        guest.poll_network()
        shown = [objects(body, remap=False)[0] for _, body in guest.world_pending]
        self.assertIn((ENEMY, CORRUPTION), [(s.guid, s.fields.get(94)) for s in shown])
        # The guest delivers and acknowledges; the shutdown drain needs equal totals.
        guest.counts['world_delivered'] += len(guest.world_pending)
        guest.world_pending.clear()
        guest.last_network = 0
        guest.poll_network()
        host.poll_network()
        self.assertEqual((host.counts['world_captured'], host.counts['world_delivered']), (2, 2))
        host.remove_guest(2)
        host.filter_packet(1, UPDATE, values_packet(ENEMY, {22: 30}))
        _, body = host.notice_packets[1][-1]  # Departure clears the guest's debuffs.
        self.assertEqual(objects(body, remap=False)[0].fields[94], 0)


def out_of_range(guid):
    from world_packets import ObjectBlock
    return ObjectBlock(4, guid, None, b'', {})


class LongSessionBoundTests(unittest.TestCase):
    """Crash report 20261016T235836 (guest 3, 27 min): accumulated enemy aura state hit its bound.

    Long sessions keep creating new enemy GUIDs. State that only grows with play
    time is forgotten when the enemy leaves, and at its bound drops the oldest
    entries instead of ending the session; wire input stays strict.
    """

    def test_5000_enemies_with_debuff_expiry_and_out_of_range_stay_bounded(self):
        from guest_auras import AuraOverlay, MAX_ENEMIES, OwnAuras, validate_auras
        own, overlay = OwnAuras(), AuraOverlay()
        peak = 0
        for i in range(5000):
            guid = 0xF130000258000000 + i
            own.observe(values(guid, {79: CORRUPTION, 99: 0x9}))
            overlay.host_block(values(guid, {22: 100}))
            overlay.guest_auras(3, validate_auras(own.take_changes()))
            if i % 3 == 0:
                own.observe(values(guid, {79: 0, 99: 0}))   # Expired, flags cleared.
            elif i % 3 == 1:
                own.observe(values(guid, {79: 0}))          # Expired, flags left set.
            else:
                own.observe(out_of_range(guid))             # Gone for the guest.
                overlay.host_block(out_of_range(guid))
            overlay.guest_auras(3, validate_auras(own.take_changes()))
            peak = max(peak, len(own.fields), len(own.sent), len(overlay.guests), len(overlay.host))
        self.assertLessEqual(peak, MAX_ENEMIES)
        self.assertEqual((own.sent, overlay.guests, own.changed), ({}, {}, set()))
        self.assertEqual(len(own.fields), len(own.inactive))  # Only expired enemies with packed flags left.
        self.assertLessEqual(len(own.fields), MAX_ENEMIES)
        self.assertEqual(overlay.host, {})

    def test_active_overflow_drops_the_oldest_instead_of_raising(self):
        from guest_auras import AuraOverlay, OwnAuras
        own = OwnAuras(limit=100)
        guids = [0xF130000258000000 + i for i in range(150)]
        for guid in guids:
            own.observe(values(guid, {79: CORRUPTION, 99: 0x9}))
            own.take_changes()
        self.assertEqual((len(own.fields), own.dropped), (100, 50))
        self.assertEqual(list(own.fields), guids[50:])  # Most recently updated kept.
        self.assertEqual(sorted(own.sent), guids[50:])  # The dropped ones were sent as removed.
        own.observe(values(guids[60], {79: REND}))      # An update makes it the newest.
        own.observe(values(guids[-1] + 1, {79: CORRUPTION}))
        self.assertNotIn(guids[50], own.fields)
        self.assertIn(guids[60], own.fields)
        overlay = AuraOverlay(limit=100)
        overlay.guest_auras(2, {guid: [(CORRUPTION, 0x9, 0, 0)] for guid in guids})
        self.assertEqual((len(overlay.guests), overlay.dropped), (100, 50))
        self.assertTrue(set(guids[:50]) <= overlay.dirty)  # Their overlay slots are cleared next.

    def test_inactive_entries_are_dropped_before_active_ones(self):
        from guest_auras import OwnAuras
        own = OwnAuras(limit=10)
        for i in range(10):
            own.observe(values(ENEMY + i, {79: CORRUPTION, 99: 0x9}))
        own.take_changes()
        own.observe(values(ENEMY + 5, {79: 0}))  # Expired; flags 0x9 remembered.
        own.take_changes()
        own.observe(values(ENEMY + 99, {79: REND}))
        self.assertNotIn(ENEMY + 5, own.fields)
        self.assertIn(ENEMY, own.fields)  # The oldest active one survives.
        self.assertEqual(own.take_changes(), [[ENEMY + 99, [[REND, 0, 0, 0]]]])

    def test_batches_respect_the_wire_bound(self):
        from guest_auras import MAX_ENEMIES, OwnAuras, validate_auras
        own = OwnAuras()
        for i in range(MAX_ENEMIES):
            own.observe(values(0xF130000258000000 + i, {79: CORRUPTION}))
        own.take_changes()
        for i in range(MAX_ENEMIES):  # All leave and as many new ones arrive in one batch.
            own.observe(out_of_range(0xF130000258000000 + i))
            own.observe(values(0xF130000259000000 + i, {79: CORRUPTION}))
        first, second = own.take_changes(), own.take_changes()
        self.assertEqual((len(first), len(second)), (MAX_ENEMIES, MAX_ENEMIES))
        validate_auras(first)
        validate_auras(second)
        self.assertEqual(own.take_changes(), [])

    def test_two_hour_session_keeps_every_bounded_state_small(self):
        """10 Hz for 2 h: 3 guests debuff new enemies, debuffs expire, enemies die or leave."""
        import random
        from guest_auras import AuraOverlay, OwnAuras, validate_auras
        from world_packets import ObjectBlock
        values = lambda guid, fields: ObjectBlock(0, guid, None, b'', fields)  # Parsed VALUES block, no packet.
        rng = random.Random(7)
        guests = {n: OwnAuras() for n in (2, 3, 4)}
        overlay = AuraOverlay()
        alive, visible, expiry, next_guid, peak = [], set(), {}, 0xF130000258000000, 0
        started = time.perf_counter()
        for tick in range(2 * 3600 * 10):
            for _ in range(rng.randint(0, 4)):  # About 2 new enemies per tick.
                alive.append(next_guid)
                visible.add(next_guid)
                overlay.host_block(values(next_guid, {22: 100}))
                next_guid += 1
            for guid in rng.sample(alive, min(len(alive), 3)):
                player = rng.choice((2, 3, 4))
                guests[player].observe(values(guid, {79: CORRUPTION, 99: 0x9, 121: 1}))
                expiry.setdefault(tick + 100, []).append((guid, player))  # Expires after 10 s.
            for guid, player in expiry.pop(tick, ()):
                guests[player].observe(values(guid, {79: 0, 99: 0, 121: 0}))
            while len(alive) > 1500 or alive and rng.random() < .2:
                guid = alive.pop(rng.randrange(len(alive)))
                visible.discard(guid)
                gone = out_of_range(guid) if rng.random() < .5 else None
                for own in guests.values():
                    own.observe(gone) if gone else own.destroy(guid)
                overlay.host_block(gone) if gone else overlay.destroy(guid)
            for player, own in guests.items():
                overlay.guest_auras(player, validate_auras(own.take_changes()))
            overlay.updates(visible)
            peak = max(peak, len(overlay.guests), len(overlay.host),
                       *(len(o.fields) + len(o.sent) for o in guests.values()))
        seconds = time.perf_counter() - started
        print(f'[ INFO ] 2-hour aura simulation: {next_guid - 0xF130000258000000} enemies in {seconds:.1f} s '
              f'({72000 / seconds:.0f} ticks/s), peak entries {peak}', flush=True)
        self.assertLess(peak, 6000)  # Bounded by the living enemies, not by play time.
        self.assertEqual(sum(o.dropped for o in guests.values()) + overlay.dropped, 0)

    def bridge(self):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            return NativeCombatBridge(io.StringIO())

    def events(self, bridge, name):
        return [r for r in map(json.loads, bridge.output.getvalue().splitlines()) if r['event'] == name]

    def test_drops_are_logged_once_a_minute(self):
        bridge = self.bridge()
        bridge.own_auras[3].limit = 10
        from world_packets import UPDATE, values_packet
        for i in range(30):
            bridge.filter_packet(3, UPDATE, values_packet(ENEMY + i, {79: CORRUPTION, 99: 0x9}))
        logged = self.events(bridge, 'bounded_state_dropped')
        self.assertEqual([(r['state'], r['dropped']) for r in logged], [('guest_auras', 1)])
        self.assertEqual(bridge.bound_dropped['guest_auras'], 20)

    def test_summon_identities_drop_destroyed_ones_never_live_ones(self):
        bridge = self.bridge()
        mapping, live = bridge.summon_maps[3], bridge.summons[3]
        for i in range(100):
            mapping[0xF130000001000000 + i] = 0xF130000001000000 + i | 2 << 22
        live.update(mapping[0xF130000001000000 + i] for i in range(0, 100, 10))  # Every tenth still alive.
        bridge.make_summon_room(3, limit=100)
        self.assertLess(len(mapping), 75)
        self.assertTrue(live <= set(mapping.values()))
        live.update(mapping.values())
        for i in range(100, 200):
            mapping[0xF130000001000000 + i] = live_guid = 0xF130000001000000 + i | 2 << 22
            live.add(live_guid)
        bridge.make_summon_room(3, limit=100)  # All alive: nothing to forget, and never fatal.
        self.assertEqual(len(mapping), 174)

    def test_ordinary_enemy_metadata_of_ended_runs_is_dropped(self):
        bridge = self.bridge()
        from play_limits import MAX_ENEMIES
        bridge.ranged_enemies = {0xF130000300000000 + i: None for i in range(2 * MAX_ENEMIES + 1)}
        bridge._enemy_raw = (b'', 0.0, 0)
        self.assertEqual(bridge.enemy_snapshot, {})
        self.assertEqual(len(bridge.ranged_enemies), 3 * MAX_ENEMIES // 2)
        self.assertIn(0xF130000300000000 + 2 * MAX_ENEMIES, bridge.ranged_enemies)  # The newest are kept.


class PlayLimitTests(unittest.TestCase):
    """User decision 17.10.2026: no limit may end a session through real play.

    Every bound sits at least 10x above the old one, u32 rewards saturate or are
    applied in parts, and a long endless session over the wire never raises.
    """
    OLD = dict(MAX_ENEMY_DAMAGE=1e8, MAX_HIT_DAMAGE=1e5, MAX_ENEMY_HP=1e8, MAX_DAMAGE_TOTAL=1e9, MAX_CLOCK=1e7,
               MAX_MULTIPLIER=1000, MAX_COUNTER=1e6, MAX_ENEMIES=3000, MAX_LIVE_SUMMONS=128, SUMMON_HISTORY=10000,
               MAX_QUEUE=4096, MAX_NATIVE_OBJECTS=1e5, MAX_WORLD_OBJECTS=1e4, MAX_NATIVE_READ=1 << 20,
               MAX_MESSAGE=1 << 20)

    def test_every_play_limit_is_at_least_ten_times_the_old_bound(self):
        import play_limits
        for name, old in self.OLD.items():
            with self.subTest(limit=name):
                self.assertGreaterEqual(getattr(play_limits, name), 10 * old)

    def pair(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host = GroupOnlineBridge(io.StringIO(), 1, {2: a})
            guest = GroupOnlineBridge(io.StringIO(), 2, {1: b})
        for bridge in (host, guest):
            bridge.native_states = {1: (1, 1, 0, 0), 2: (1, 1, 0, 0)}
        host.poll_network()
        guest.poll_network()
        return host, guest

    @staticmethod
    def exchange(host, guest):
        guest.last_network = 0
        guest.poll_network()
        host.poll_network()
        host.last_network = 0
        host.poll_network()
        guest.poll_network()

    def test_ten_times_the_old_values_cross_the_wire(self):
        host, guest = self.pair()
        host.host_clock, host.xp_pending, host.gold_pending = 1e8, 10 ** 7, 10 ** 7
        host.guest_hits = [(0xF130000400000001, 1e6, 1e8)]
        guest.damage_pending[TARGET] = 1e9
        guest.effects_pending = [(TARGET, bytes(12), 0)] * 40960  # 10x the old 4096, about 1.8 MB.
        self.exchange(host, guest)
        self.assertEqual(host.damage_pending[TARGET], 1e9)
        self.assertEqual(len(host.effects_pending), 40960)
        self.assertEqual((guest.host_clock, guest.xp_pending, guest.gold_pending), (1e8, 10 ** 7, 10 ** 7))
        self.assertEqual(guest.guest_hits[-1][:2], (0xF130000400000001, 1e6))

    def test_six_hour_endless_session_over_the_wire_never_raises(self):
        """One exchange per 30 s for 6 h; enemy damage, rewards and hits keep growing (endless scaling)."""
        host, guest = self.pair()
        started = time.perf_counter()
        xp = gold = 0
        for round in range(720):
            scale = 1.012 ** round  # x5400 over the session.
            host.host_clock = 30.0 * round
            host.xp_pending, host.gold_pending = int(2e5 * scale), int(1e4 * scale)
            xp, gold = xp + host.xp_pending, gold + host.gold_pending
            host.guest_hits = [(0xF130000400000000 + round, 2e3 * scale, 30.0 * round)] * 3
            guest.damage_pending[0xF130000500000000 + round] = 2e7 * scale
            self.exchange(host, guest)
        seconds = time.perf_counter() - started
        print(f'[ INFO ] 6-hour wire simulation: 720 exchanges in {seconds:.1f} s, final enemy damage '
              f'{2e7 * scale:.3g}, hit {2e3 * scale:.3g}, xp {xp:.3g} (pending, applied in u32 parts)', flush=True)
        self.assertEqual(guest.xp_pending, xp)  # Above u32: kept and applied in parts, never refused.
        self.assertGreater(guest.xp_pending, 0xFFFFFFFF)
        self.assertEqual(guest.gold_pending, gold)
        self.assertEqual(len(host.damage_pending), 720)
        self.assertLessEqual(len(guest.guest_hits), 128)  # The waiting queue folds instead of growing.

    def apply_on_host(self, host, guid):
        amount = host.damage_pending.pop(guid)
        host.record(event='native_guest_damage_applied', target=guid, requested=amount)

    def forget_round(self, host, guest, alive=()):
        host.enemy_snapshot = {g: (None, 1.0, (0.0, 0.0, 0.0)) for g in alive}
        host.receipts_prune_due = 0
        host.last_network = 0
        host.poll_network()
        guest.poll_network()

    def test_receipts_of_gone_enemies_are_forgotten_on_both_sides(self):
        host, guest = self.pair()
        enemy = 0xF130000C00000001
        guest.damage_pending[enemy] = 500.0
        self.exchange(host, guest)
        self.apply_on_host(host, enemy)
        self.exchange(host, guest)
        self.assertEqual((guest.damage_pending, guest.damage_sent, guest.damage_acked), ({}, {}, {enemy: 500.0}))
        self.forget_round(host, guest, alive=(enemy,))  # Still alive: kept.
        self.assertEqual(dict(host.damage_receipts[2]), {enemy: 500.0})
        self.forget_round(host, guest)  # Gone, sent, nothing in flight: forgotten on both sides.
        self.assertEqual((dict(host.damage_receipts[2]), guest.damage_acked, host.damage_owners), ({}, {}, {}))
        guest.damage_pending[enemy] = 70.0  # Late damage from the guest's mirror: receipt restarts at zero.
        self.exchange(host, guest)
        self.apply_on_host(host, enemy)
        self.exchange(host, guest)
        self.assertEqual((guest.damage_pending, guest.damage_sent, guest.damage_acked), ({}, {}, {enemy: 70.0}))

    def test_forget_while_damage_is_in_flight_never_sends_twice(self):
        host, guest = self.pair()
        enemy = 0xF130000C00000002
        guest.damage_pending[enemy] = 500.0
        self.exchange(host, guest)
        self.apply_on_host(host, enemy)
        self.exchange(host, guest)
        guest.damage_pending[enemy] = guest.damage_sent[enemy] = 30.0  # Sent, not yet at the host.
        self.forget_round(host, guest)
        self.assertEqual((guest.damage_acked, guest.damage_sent), ({}, {enemy: 30.0}))
        host.damage_receipts[2][enemy] = 30.0  # The in-flight damage applied: receipt from zero.
        self.forget_round(host, guest, alive=(enemy,))
        self.assertEqual((guest.damage_pending, guest.damage_sent), ({}, {}))
        guest.last_network = 0
        guest.poll_network()
        host.poll_network()
        self.assertNotIn(enemy, host.damage_pending)  # Nothing was sent again.

    def test_receipt_books_stay_small_over_thousands_of_enemies(self):
        host, guest = self.pair()
        for i in range(2000):
            enemy = 0xF130000D00000000 + i
            guest.damage_pending[enemy] = 100.0 + i
            self.exchange(host, guest)
            self.apply_on_host(host, enemy)
            self.exchange(host, guest)
            if i % 100 == 99:
                self.forget_round(host, guest)
        self.assertEqual((len(host.damage_receipts[2]), len(guest.damage_acked), len(guest.damage_sent),
                          len(host.damage_owners)), (0, 0, 0, 0))

    def test_u32_rewards_are_applied_in_parts_or_saturate(self):
        from play_limits import MAX_COUNTER, copper, u32_part
        self.assertEqual(u32_part(3 * MAX_COUNTER + 7), MAX_COUNTER)
        self.assertEqual(u32_part(12), 12)
        self.assertEqual(copper(429496), 4294960000)
        self.assertEqual(copper(10 ** 7), MAX_COUNTER)

    def test_gold_balance_saturates_instead_of_ending_the_run(self):
        from native_probe import game_field
        from play_limits import MAX_COUNTER
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            bridge = NativeCombatBridge(io.StringIO(), shared_world=True)
        for gold, credit, balance in ((10 ** 6, 10 ** 7, 11 * 10 ** 6), (MAX_COUNTER - 5, 10 ** 7, MAX_COUNTER)):
            memory = {0x10 + game_field(0x4A8): gold, 0x10 + game_field(0x6D0): gold}
            writes = {}
            client = SimpleNamespace(number=2, server=0, memory=lambda a, n: struct.pack('<I', memory[a]),
                                     put=writes.__setitem__)
            bridge.gold_pending = credit
            bridge.notice_packets[2].clear()
            bridge.apply_shared_gold(client)
            self.assertEqual(struct.unpack('<I', writes[0x10 + game_field(0x4A8)])[0], balance)
            (_, body), = bridge.notice_packets[2]
            from world_packets import objects
            self.assertEqual(objects(body, remap=False)[0].fields[1176], MAX_COUNTER)  # Copper display saturates.
        self.assertEqual(bridge.bound_dropped['gold_balance'], 10 ** 7 - 5)

    def test_ten_times_the_old_enemy_and_summon_counts(self):
        from guest_auras import AuraOverlay, OwnAuras, validate_auras
        own, overlay = OwnAuras(), AuraOverlay()
        for i in range(30000):
            own.observe(values(0xF130000600000000 + i, {79: CORRUPTION, 99: 0x9}))
        batch = own.take_changes()
        overlay.guest_auras(2, validate_auras(batch))
        self.assertEqual((len(batch), own.dropped, len(overlay.guests), overlay.dropped), (30000, 0, 30000, 0))
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        mapping, live = bridge.summon_maps[3], bridge.summons[3]
        for i in range(1280):
            mapping[0xF130000001000000 + i] = network = 0xF130000001000000 + i | 2 << 22
            live.add(network)
        bridge.make_summon_room(3)
        self.assertEqual(len(mapping), 1280)


class GuardianChoiceTests(unittest.TestCase):
    """Level 99 guardian kill: a paused guest was offered its choice in phase 3 and hung.

    Native 7264: OFFER_CHOICES sets phase 2 without a phase check, RESUME only
    leaves phase 3, and from level 99 a guardian gives no level-up (pending 0).
    """
    GUEST = 2

    def bridge(self, guest_state, host_phase=2):
        from native_probe import PAUSE, RESUME  # noqa: F401
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            bridge = NativeCombatBridge(io.StringIO(), shared_world=True)
        bridge.ready = {1, 2}
        bridge.native_states = {1: (host_phase, 99, 0, 0), 2: guest_state}
        bridge.talent_paused = {2}
        return bridge

    def client(self, guardian=0, chest=0):
        from boss_rewards import guardian_counters
        from native_probe import game_field
        game = 0x10
        memory = {game + guardian_counters()[1]: guardian, game + game_field(0x864): chest}
        calls = []
        client = SimpleNamespace(number=self.GUEST, server=0, memory=lambda a, n: struct.pack('<I', memory.get(a, 0)),
                                 call_before=lambda *args, **kwargs: calls.append(args))
        return client, calls

    def offers(self, bridge, client, calls):
        import native_guest_combat
        with patch.object(native_guest_combat._NativeCombatBridge, 'before_batch', lambda *a: 'native'):
            result = bridge.before_batch(client, None)
        return result is True and calls and calls[-1][1] == native.OFFER_CHOICES

    def test_level_99_guardian_resumes_first_and_offers_only_in_phase_1(self):
        bridge = self.bridge((3, 99, 0, 0))
        client, calls = self.client(guardian=1)
        self.assertFalse(self.offers(bridge, client, calls))  # Phase 3: never offered over the pause menu.
        self.assertTrue(bridge.sync_talents(client, None))
        self.assertEqual(calls[-1][1], native.RESUME)  # Owes a choice: resumed although the host still chooses.
        bridge.native_states[2] = (1, 99, 0, 0)
        calls.clear()
        self.assertFalse(bridge.sync_talents(client, None))  # Not paused again while it owes a choice.
        self.assertTrue(self.offers(bridge, client, calls))
        self.assertEqual(calls[-1][1:], (native.OFFER_CHOICES, 0x10, 2))

    def test_chest_choice_is_owed_like_a_level_up(self):
        bridge = self.bridge((3, 99, 0, 0))
        client, calls = self.client(chest=1)
        self.assertTrue(bridge.sync_talents(client, None))
        self.assertEqual(calls[-1][1], native.RESUME)
        bridge.native_states[2] = (1, 99, 0, 0)
        self.assertFalse(bridge.sync_talents(client, None))

    def test_nothing_owed_still_waits_for_the_choosing_host(self):
        bridge = self.bridge((1, 99, 0, 0))
        bridge.talent_paused = set()
        client, calls = self.client()
        self.assertTrue(bridge.sync_talents(client, None))
        self.assertEqual(calls[-1][1], native.PAUSE)
        bridge.native_states[2] = (3, 99, 0, 0)
        self.assertFalse(bridge.sync_talents(client, None))  # Stays paused while the host chooses.
        bridge.native_states[1] = (1, 99, 0, 0)
        self.assertTrue(bridge.sync_talents(client, None))
        self.assertEqual(calls[-1][1], native.RESUME)

    def test_level_50_level_up_is_unchanged(self):
        bridge = self.bridge((3, 50, 0, 1))
        client, calls = self.client(guardian=1)
        self.assertTrue(bridge.sync_talents(client, None))
        self.assertEqual(calls[-1][1], native.RESUME)
        bridge.native_states[2] = (1, 50, 0, 1)
        self.assertTrue(bridge.sync_talents(client, None))  # Level-up first, as before (AWARD_XP 0).
        self.assertEqual(calls[-1][1:], (native.AWARD_XP, 0x10, 0))


# Display models chosen by the native player-field builder (7264 0x544b6d9).
CAT, CAT_TAUREN, BEAR, BEAR_TAUREN, NIGHT_ELF = 892, 8571, 2281, 2289, 55


class DruidFormTests(unittest.TestCase):
    """Cat/Dire Bear forms are the display model field; every client must see them."""

    def bridge(self):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.template_displays = {n: NIGHT_ELF for n in bridge.members}  # Login models (create blocks).
        return bridge

    def displays(self, bridge, recipient, guid):
        from world_packets import objects, DISPLAY_ID
        return [block.fields[DISPLAY_ID] for _, body in bridge.notice_packets[recipient]
                for block in objects(body, remap=False) if block.guid == guid and DISPLAY_ID in block.fields]

    def test_guest_form_change_and_revert_reach_host_and_other_guests(self):
        from world_packets import values_packet, UPDATE, SELF
        bridge = self.bridge()
        for model in (CAT, NIGHT_ELF, BEAR_TAUREN, NIGHT_ELF):  # Form, revert (new run), other form, revert.
            bridge.filter_packet(3, UPDATE, values_packet(SELF, {131: model, 22: 100}))
        for recipient in (1, 2, 4):
            self.assertEqual(self.displays(bridge, recipient, 0xFF0103), [CAT, NIGHT_ELF, BEAR_TAUREN, NIGHT_ELF])
        self.assertEqual(self.displays(bridge, 3, 0xFF0103), [])  # Its own client renders it natively.

    def test_unexpected_guest_model_is_dropped_and_logged_once(self):
        from world_packets import objects, values_packet, UPDATE, SELF
        bridge = self.bridge()
        for model in (4242, 4243, CAT):
            bridge.filter_packet(3, UPDATE, values_packet(SELF, {131: model, 22: 90}))
        self.assertEqual(self.displays(bridge, 1, 0xFF0103), [CAT])
        health = [objects(body, remap=False)[0].fields[22] for _, body in bridge.notice_packets[1]]
        self.assertEqual(health, [90, 90, 90])  # The rest of the update still arrives.
        rejected = [json.loads(line) for line in bridge.output.getvalue().splitlines()
                    if 'guest_display_rejected' in line]
        self.assertEqual([(r['player'], r['display']) for r in rejected], [(3, 4242)])
        # The host also checks what a guest relays (a modified guest cannot bypass it).
        self.assertIsNone(bridge.sanitize_player_values(2, UPDATE, values_packet(0xFF0102, {131: 1})))
        self.assertEqual(bridge.sanitize_player_values(2, UPDATE, values_packet(0xFF0102, {131: NIGHT_ELF})),
                         values_packet(0xFF0102, {131: NIGHT_ELF}))

    def test_host_form_reaches_every_guest_world(self):
        from world_packets import objects, values_packet, UPDATE, SELF, HOST
        bridge = self.bridge()
        for model in (BEAR, NIGHT_ELF):
            bridge.filter_packet(1, UPDATE, values_packet(SELF, {131: model}))
        for recipient in (2, 3, 4):
            queue = bridge.world_pending if recipient == 2 else bridge.world_queues[recipient]
            shown = [block.fields[131] for _, body in queue for block in objects(body, remap=False)
                     if block.guid == HOST and 131 in block.fields]
            self.assertEqual(shown, [BEAR, NIGHT_ELF])

    def test_late_avatar_creation_replays_latest_form(self):
        from world_packets import values_packet
        bridge = self.bridge()
        bridge.observe_remote_display(values_packet(0xFF0102, {22: 5}))
        self.assertEqual(bridge.remote_display, {})
        for model in (CAT_TAUREN, CAT):
            bridge.observe_remote_display(values_packet(0xFF0102, {131: model}))
        bridge.observe_remote_display(values_packet(0xF13000025800000D, {131: BEAR}))  # Not a player.
        self.assertEqual(bridge.remote_display, {0xFF0102: CAT})


class VersionTests(unittest.TestCase):
    """0.0.11 (protocol 4) and 0.0.12 (protocol 5, play limits) refuse each other with a clear reason."""

    def test_old_and_new_peers_refuse_each_other_by_name(self):
        import socket
        import ssl
        import tempfile
        import threading
        import time
        import coop_transport
        from coop_transport import create_pairing, accept, connect, encode, receive, VersionMismatch
        self.assertEqual(coop_transport.PROTOCOL, 5)
        with tempfile.TemporaryDirectory() as folder:
            invite = create_pairing(folder)
            # A 0.0.11 guest (protocol 4) reaches a new host.
            with socket.create_server(('127.0.0.1', 0)) as listener:
                errors = []
                def serve():
                    try:
                        accept(listener, folder, invite, 'test-build')
                    except Exception as error:
                        errors.append(error)
                thread = threading.Thread(target=serve)
                thread.start()
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
                with context.wrap_socket(socket.create_connection(listener.getsockname()), server_hostname='x') as old:
                    old.sendall(encode(dict(protocol=4, build='test-build', token=invite['token'], slot=2)))
                    self.assertEqual(receive(old, time.monotonic() + 5), dict(accepted=False, reason='protocol', protocol=5))
                thread.join(5)
                self.assertIsInstance(errors[0], VersionMismatch)
                self.assertIn('protocol 5, the other uses 4', str(errors[0]))
            # A new guest reaches a 0.0.11 host, which answers like its accept() with PROTOCOL 4.
            with socket.create_server(('127.0.0.1', 0)) as listener:
                def old_host():
                    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    server.load_cert_chain(str(Path(folder) / 'host-cert.pem'), str(Path(folder) / 'host-key.pem'))
                    raw, _ = listener.accept()
                    with server.wrap_socket(raw, server_side=True) as sock:
                        hello = receive(sock, time.monotonic() + 5)
                        assert hello['protocol'] == 5
                        sock.sendall(encode(dict(accepted=False, reason='protocol', protocol=4)))
                thread = threading.Thread(target=old_host)
                thread.start()
                with self.assertRaisesRegex(VersionMismatch, 'protocol 5, the other uses 4. Both players need the same co-op hotfix'):
                    connect('127.0.0.1', listener.getsockname()[1], invite, 'test-build', 2)
                thread.join(5)

    def test_framework_version_names_the_hotfix(self):
        version = (Path(native.ROOT) / 'COOP-VERSION.txt').read_text(encoding='utf-8').strip()
        self.assertEqual(version, '0.0.12-community+game-7264d50b')
        self.assertLessEqual(len(version), 32)  # Lobby server field limit.


class SurrenderTests(unittest.TestCase):
    """0.95.0 "give up" (menu tag 10): host ends the run for all, a guest leaves alone."""

    def game_client(self, number, flag=1, kind=1):
        memory = {0x10 + 0x941: bytes([flag]), 0x10: struct.pack('<I', kind)}
        return SimpleNamespace(number=number, server=0, base=0x140000000,
                               memory=lambda address, size: memory[address][:size], call_before=Mock())

    def pair(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host = GroupOnlineBridge(io.StringIO(), 1, {2: a})
            guest = GroupOnlineBridge(io.StringIO(), 2, {1: b})
        for bridge in (host, guest):
            bridge.native_states = {1: (1, 1, 0, 0), 2: (1, 1, 0, 0)}
        host.poll_network()
        guest.poll_network()
        return host, guest

    def exchange(self, sender, receiver):
        sender.last_network = 0
        sender.poll_network()
        receiver.poll_network()

    def events(self, bridge, name):
        return [r for r in map(json.loads, bridge.output.getvalue().splitlines()) if r['event'] == name]

    def test_only_the_surrender_flag_distinguishes_giving_up_from_dying(self):
        from updated_layout import release_7264
        if not release_7264():
            self.skipTest('give up exists from 0.95.0 on')
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.native_phase_changed(self.game_client(1, flag=0), 1, (1, 1, 0, 0), (4, 1, 0, 0))  # Native death.
        self.assertFalse(bridge.party_surrender or bridge.surrendered)
        bridge.native_phase_changed(self.game_client(1), 1, (4, 1, 0, 0), (4, 1, 0, 0))  # No transition.
        self.assertFalse(bridge.surrendered)
        bridge.native_phase_changed(self.game_client(1), 1, (1, 1, 0, 0), (4, 1, 0, 0))
        self.assertTrue(bridge.party_surrender)
        self.assertEqual(bridge.surrendered, {1})

    def test_host_surrender_reaches_guest_which_runs_native_surrender_once(self):
        from updated_layout import release_7264
        if not release_7264():
            self.skipTest('give up exists from 0.95.0 on')
        host, guest = self.pair()
        host.player_surrendered(1)
        self.exchange(host, guest)
        self.assertTrue(guest.party_surrender)
        self.assertEqual(guest.surrendered, {1})
        client = self.game_client(2)
        self.assertTrue(guest.apply_party_surrender(client, None))
        (_, rva, game), kwargs = client.call_before.call_args
        self.assertEqual((rva, game), (None, 0x10))
        self.assertIn(struct.pack('<Q', 0x140000000 + 0x546E540), kwargs['entry_code'])
        self.assertFalse(guest.apply_party_surrender(client, None))  # Once only.
        self.assertEqual(client.call_before.call_count, 1)
        # Its own resulting surrender is part of the party's: the guest does not leave.
        guest.native_phase_changed(client, 2, (1, 1, 0, 0), (4, 1, 0, 0))
        self.assertFalse(guest.self_surrendered or getattr(guest, 'stop_requested', False))

    def test_downed_guest_needs_no_native_surrender(self):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.party_surrender = True
        bridge.native_states = {n: (4 if n == 3 else 1, 1, 0, 0) for n in bridge.members}
        client = self.game_client(3)
        self.assertFalse(bridge.apply_party_surrender(client, None))
        client.call_before.assert_not_called()
        self.assertEqual(self.events(bridge, 'party_surrender_applied')[0]['native'], False)

    def test_a_guest_cannot_end_the_run_for_others(self):
        host, guest = self.pair()
        decorate = guest.decorate
        def modified(peer, message):  # A modified guest claims a party surrender.
            decorate(peer, message)
            message['surrender'] = True
        guest.decorate = modified
        for _ in range(2):
            self.exchange(guest, host)
        self.assertFalse(host.party_surrender)
        self.assertEqual([r['player'] for r in self.events(host, 'surrender_broadcast_rejected')], [2])

    def test_guest_surrender_leaves_alone_and_is_not_a_connection_failure(self):
        from updated_layout import release_7264
        if not release_7264():
            self.skipTest('give up exists from 0.95.0 on')
        host, guest = self.pair()
        guest.native_phase_changed(self.game_client(2), 2, (1, 1, 0, 0), (4, 1, 0, 0))
        self.assertTrue(guest.self_surrendered and guest.stop_requested)
        self.assertFalse(guest.party_surrender)
        self.exchange(guest, host)
        self.assertEqual([r['player'] for r in self.events(host, 'guest_surrendered')], [2])
        self.assertFalse(host.party_surrender)  # Host and the other guests keep playing.
        guest.connection_ended(1, ConnectionError('host closed the departed guest'))
        self.assertIsNone(guest.connection_failure)

    def test_a_player_who_gave_up_is_never_revived(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.native_states = {1: (1, 1, 0, 0), 2: (4, 1, 0, 0)}
        bridge.surrendered.add(2)
        client = self.game_client(2)
        self.assertFalse(bridge.sync_revival(client, None))
        client.call_before.assert_not_called()
        self.assertNotIn(2, bridge.downed)  # No "stand within 5 yards" notice either.


class SurrenderAcceptanceTests(unittest.TestCase):
    def test_verification_needs_lone_guest_departure_then_party_defeat(self):
        import verify_surrender as surrender
        def rows(number):
            result = []
            if number == 4:
                result += [dict(event='surrender_requested', player=4), dict(event='player_surrendered', player=4, party=False)]
            if number == 1:
                result += [dict(event='guest_surrendered', player=4), dict(event='guest_departed', player=4),
                           dict(event='surrender_requested', player=1), dict(event='player_surrendered', player=1, party=True)]
            if number in (2, 3):
                result += [dict(event='party_surrender_received'), dict(event='party_surrender_applied', player=number, native=True)]
            if number in (1, 2, 3):
                result.append(dict(event='team_defeat_shown', player=number))
            return result
        recordings = [rows(n) for n in range(1, 5)]
        self.assertEqual(surrender.verify(recordings)['defeated'], [1, 2, 3])
        recordings[2].append(dict(event='player_revived', player=3))
        with self.assertRaises(AssertionError):
            surrender.verify(recordings)
        recordings = [rows(n) for n in range(1, 5)]
        recordings[0] = recordings[0][2:] + recordings[0][:2]  # Host gave up before guest 4 left.
        with self.assertRaises(AssertionError):
            surrender.verify(recordings)


class DruidFormDriverTests(unittest.TestCase):
    """The acceptance driver patches exactly the native display builder of 0.95.0."""

    def test_builder_site_and_patch(self):
        import verify_druid_forms as forms
        from updated_layout import release_7264
        if not release_7264():
            self.skipTest('forms exist from 0.95.0 on')
        self.assertEqual(exe_bytes(forms.SITE, len(forms.ORIGINAL)), forms.ORIGINAL)
        # 0x544b6d9 scans the talent list for Dire Bear (9634) / Cat (768); 0x544b763 inserts field 131.
        self.assertEqual(exe_bytes(0x544B6E4, 7), bytes.fromhex('4181f8a2250000'))
        self.assertEqual(exe_bytes(forms.RESUME + 13, 5), bytes.fromhex('ba83000000'))
        patch = forms.form_patch(forms.CAT)
        self.assertEqual(len(patch), len(forms.ORIGINAL))
        self.assertEqual(struct.unpack_from('<I', patch, 2)[0], forms.CAT)
        self.assertEqual(forms.SITE + 11 + struct.unpack_from('<i', patch, 7)[0], forms.RESUME)

    def test_verification_requires_every_avatar_created_with_its_model(self):
        import verify_druid_forms as forms
        from world_packets import values_packet
        models = {1: forms.CAT, 2: forms.BEAR, 3: NIGHT_ELF, 4: NIGHT_ELF}
        def rows(number):
            own = [dict(event='own_display', display=models[number])]
            created = [dict(event='remote_player_create_written', player=other,
                            body=values_packet(0xFF0100 + other, {131: models[other]}).hex())
                       for other in models if other != number]
            return own + created
        recordings = [rows(n) for n in range(1, 5)]
        self.assertEqual(forms.verify(recordings), models)
        recordings[3][2]['body'] = values_packet(0xFF0102, {131: NIGHT_ELF}).hex()  # Guest 4 sees no bear.
        with self.assertRaises(AssertionError):
            forms.verify(recordings)
        recordings = [rows(n) for n in range(1, 5)]
        recordings[0][0]['display'] = NIGHT_ELF  # The host's own world was built without its form.
        with self.assertRaises(AssertionError):
            forms.verify(recordings)

if __name__ == '__main__':
    unittest.main()
