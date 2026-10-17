"""Debugger-loop relief: the faster host enemy paths give exactly the old results.

The reference functions below are the pre-relief implementations, kept verbatim
in shape so every optimisation is checked byte for byte (same wire messages).
"""
import io
import math
import os
import random
import struct
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import online_bridge
import loop_profile
from group_online import GroupOnlineBridge
from native_guest_combat import _NativeCombatBridge
from native_probe import game_field, IMAGE_SIZE, q
from online_bridge import binary, enemy_parts, enemy_motion, ENEMY_VOLATILE, ENEMY_SPANS
from visibility_bridge import native_enemies, native_enemy

BASE, SERVER, POINTER = 0x140000000, 0x10000000, 0x20000000


def reference_native_enemies(client, game):
    pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x568), 16))
    data = client.memory(pointer, count * 0x148) if count else b''
    now = struct.unpack('<f', client.memory(game + game_field(0x85C), 4))[0]
    result = []
    for offset in range(0, len(data), 0x148):
        if struct.unpack_from('<I', data, offset + 0x68)[0] == 1:
            continue
        hp = struct.unpack_from('<f', data, offset + 0xE0)[0]
        start = struct.unpack_from('<3f', data, offset + 0xFC)
        end = struct.unpack_from('<3f', data, offset + 0x108)
        began, duration = struct.unpack_from('<ff', data, offset + 0x114)
        if not all(math.isfinite(v) for v in (now, hp, *start, *end, began, duration)):
            raise ValueError('Nonfinite native enemy state')
        t = min(1, max(0, (now - began) / duration)) if duration > 0 else 1
        result.append((q(data, offset + 0x78), hp, tuple(a + (b - a) * t for a, b in zip(start, end))))
    return result


def reference_snapshot(client):
    game = client.server + 0x10
    pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x568), 16))
    poses = {guid: (hp, position) for guid, hp, position in reference_native_enemies(client, game)}
    data = client.memory(pointer, count * 0x148) if count else b''
    snapshot, bosses = {}, {}
    for offset in range(0, len(data), 0x148):
        guid = q(data, offset + 0x78)
        if guid in poses:
            flat = bytearray(data[offset + 0x68:offset + 0x148])
            definition = q(flat, 0x18)
            if definition:
                definition -= client.base
            else:
                bosses[guid] = q(data, offset + 0x30) - client.base
            struct.pack_into('<Q', flat, 0x18, definition)
            snapshot[guid] = (bytes(flat), *poses[guid])
    return snapshot, bosses


def reference_parts(flat):
    stable = bytearray(flat)
    for start, size in ENEMY_VOLATILE:
        stable[start:start + size] = bytes(size)
    spans = b''.join(flat[start:end] for start, end in ENEMY_SPANS)
    for start, end in ENEMY_SPANS:
        stable[start:end] = bytes(end - start)
    return bytes(stable), spans


class ReferenceHost:
    """Pre-relief enemy_wire_view/enemy_update (per-peer base64 and sent views)."""
    def __init__(self):
        self.enemy_views, self.enemy_sequences, self.enemy_full_due = {}, {}, {}
        self.enemy_full_requested = set()

    def update(self, snapshot, bosses, peer, now):
        view = {guid: (flat, *reference_parts(flat), enemy_motion(hp, pose), bosses.get(guid))
                for guid, (flat, hp, pose) in snapshot.items()}
        sent = self.enemy_views.get(peer)
        full = sent is None or peer in self.enemy_full_requested or now >= self.enemy_full_due.get(peer, 0)
        entries = []
        for guid, (flat, stable, spans, motion, boss) in view.items():
            old = None if full else sent.get(guid)
            if old is None or old[0] != stable or old[3] != boss:
                entries.append([guid, binary(flat), None, binary(motion), boss])
            elif old[1] != spans or old[2] != motion:
                entries.append([guid, None, binary(spans) if old[1] != spans else None,
                                binary(motion) if old[2] != motion else None, None])
        drop = [] if full else [guid for guid in sent if guid not in view]
        if not full and not entries and not drop:
            return None
        sequence = self.enemy_sequences.get(peer, 0) + 1
        update = dict(seq=sequence, base=None if full else self.enemy_sequences[peer], set=entries)
        if drop:
            update['drop'] = drop
        self.enemy_sequences[peer] = sequence
        self.enemy_views[peer] = {guid: (stable, spans, motion, boss)
                                  for guid, (_, stable, spans, motion, boss) in view.items()}
        if full:
            self.enemy_full_due[peer] = now + 2
            self.enemy_full_requested.discard(peer)
        return update


class Client:
    base, server, number = BASE, SERVER, 1

    def __init__(self, records, now=.75):
        header = bytearray(0x1000)
        struct.pack_into('<QQ', header, game_field(0x568), POINTER, len(records) // 0x148)
        struct.pack_into('<f', header, game_field(0x85C), now)
        self.regions = {SERVER + 0x10: bytes(header), POINTER: bytes(records)}

    def memory(self, address, size):
        for start, blob in self.regions.items():
            if start <= address and address + size <= start + len(blob):
                return blob[address - start:address - start + size]
        raise KeyError(hex(address))


def records(rng, count, *, dead_every=7, boss_every=11, duplicate=True):
    data = bytearray()
    for i in range(count):
        r = bytearray(rng.randbytes(0x148))
        struct.pack_into('<I', r, 0x68, 1 if i % dead_every == 3 else rng.choice((0, 2)))
        struct.pack_into('<Q', r, 0x78, 0x1000 + (i // 2 if duplicate and i % 13 == 5 else i))
        if i % boss_every == 4:
            struct.pack_into('<Q', r, 0x80, 0)
            struct.pack_into('<Q', r, 0x18, 7)
            struct.pack_into('<Q', r, 0x30, BASE + 0x2000 + i)
        else:
            struct.pack_into('<Q', r, 0x80, BASE + 0x100000 + i)
        struct.pack_into('<f', r, 0xE0, rng.uniform(-5, 500))
        struct.pack_into('<3f', r, 0xFC, *(rng.uniform(-900, 900) for _ in range(3)))
        struct.pack_into('<3f', r, 0x108, *(rng.uniform(-900, 900) for _ in range(3)))
        struct.pack_into('<ff', r, 0x114, rng.uniform(0, 2), rng.choice((0.0, -1.0, rng.uniform(.01, 3))))
        data += r
    return data


class Host(_NativeCombatBridge):
    """Only the enemy state of the real bridge (no native session)."""
    def __init__(self):
        self.ranged_enemies = {}  # 0.0.10: ordinary casters retained until DESTROY.
        self.enemy_snapshot, self.boss_definitions = {}, {}


class GroupHost:
    enemy_wire_view = GroupOnlineBridge.enemy_wire_view
    enemy_full_entry = GroupOnlineBridge.enemy_full_entry
    enemy_sent_view = GroupOnlineBridge.enemy_sent_view
    enemy_update = GroupOnlineBridge.enemy_update
    report_enemy_churn = GroupOnlineBridge.report_enemy_churn

    def __init__(self):
        self.enemy_views, self.enemy_sequences, self.enemy_full_due = {}, {}, {}
        self.enemy_full_requested = set()
        self.enemy_view_cache, self.poll_generation = (None, {}), 0
        self.enemy_wire_text, self.enemy_view_sent = {}, None
        self.enemy_churn, self.enemy_churn_compared, self.enemy_churn_patched, self.enemy_churn_due = {}, 0, 0, 0
        self.events = []

    def record(self, **event):
        self.events.append(event)


class EnemyPathTests(unittest.TestCase):
    def test_native_enemies_and_single_lookup_match_reference(self):
        for seed in range(6):
            rng = random.Random(seed)
            client = Client(records(rng, 120), now=rng.uniform(0, 3))
            game = SERVER + 0x10
            expected = reference_native_enemies(client, game)
            self.assertEqual(native_enemies(client, game), expected)
            for guid in {g for g, _, _ in expected} | {0x1000 + i for i in range(130)} | {0xDEAD}:
                old = next(((hp, pose) for g, hp, pose in expected if g == guid), None)
                self.assertEqual(native_enemy(client, game, guid), old)

    def test_unaligned_guid_bytes_are_not_matches(self):
        rng = random.Random(9)
        data = records(rng, 4, dead_every=99, boss_every=99, duplicate=False)
        # Plant guid 0x1002's bytes inside another record's payload.
        struct.pack_into('<Q', data, 0x148 + 0x20, 0x1002)
        struct.pack_into('<I', data, 2 * 0x148 + 0x68, 1)  # The real 0x1002 record is dead.
        client = Client(data)
        self.assertIsNone(native_enemy(client, SERVER + 0x10, 0x1002))

    def test_nonfinite_living_enemy_still_raises(self):
        data = records(random.Random(3), 5, dead_every=99, boss_every=99)
        struct.pack_into('<f', data, 2 * 0x148 + 0xE0, float('nan'))
        client = Client(data)
        with self.assertRaises(ValueError):
            native_enemies(client, SERVER + 0x10)
        with self.assertRaises(ValueError):
            native_enemy(client, SERVER + 0x10, q(data, 2 * 0x148 + 0x78))

    def test_lazy_snapshot_equals_eager_capture(self):
        for seed in range(6):
            rng = random.Random(seed)
            first, second = Client(records(rng, 90)), Client(records(rng, 70))
            host = Host()
            host.snapshot_enemies(first)
            host.snapshot_enemies(second)  # A newer capture replaces the unparsed one.
            snapshot, bosses = reference_snapshot(second)
            self.assertEqual(host.enemy_snapshot, snapshot)
            self.assertEqual(list(host.enemy_snapshot), list(snapshot))  # Same wire order.
            self.assertEqual(host.boss_definitions, bosses)

    def test_setters_keep_eager_semantics(self):
        rng = random.Random(4)
        client = Client(records(rng, 60))
        snapshot, bosses = reference_snapshot(client)
        host = Host()
        host.snapshot_enemies(client)
        host.enemy_snapshot = {}  # Eager: the capture's bosses stay.
        self.assertEqual(host.boss_definitions, bosses)
        host.snapshot_enemies(client)
        host.enemy_snapshot.clear()
        self.assertEqual(host.enemy_snapshot, {})
        host.snapshot_enemies(client)
        host.boss_definitions = {}
        self.assertEqual(host.enemy_snapshot, snapshot)

    def test_lazy_parse_reports_invalid_definitions(self):
        data = records(random.Random(5), 3, dead_every=99, boss_every=99)
        struct.pack_into('<Q', data, 0x80, BASE + IMAGE_SIZE + 8)
        host = Host()
        host.snapshot_enemies(Client(data))
        with self.assertRaises(ValueError):
            host.enemy_snapshot

    def test_enemy_parts_fast_path_matches(self):
        rng = random.Random(6)
        for _ in range(500):
            flat = rng.randbytes(0xE0)
            self.assertEqual(enemy_parts(flat), reference_parts(flat))
            self.assertEqual(enemy_parts(bytearray(flat)), reference_parts(flat))
        self.assertEqual(enemy_parts(b'\x01' * 0x100), reference_parts(b'\x01' * 0x100))

    def test_enemy_updates_round_trip_over_rounds(self):
        """v11 protocol 3 (record patches): every guest equals the host after each update.

        Replaces the v10 byte-for-byte comparison with the pre-relief wire format,
        which protocol 3 intentionally changed.
        """
        from online_bridge import ENEMY_FULL
        from test_uplink_budget import comparable, blob_entries
        rng = random.Random(7)
        snapshot, bosses = reference_snapshot(Client(records(rng, 150)))
        # Guests accept 0 <= hp (since v9); the random fixture also makes dying records.
        snapshot = {g: (flat, max(0.0, hp), pose) for g, (flat, hp, pose) in snapshot.items()}
        host = GroupHost()
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            guests = {n: GroupOnlineBridge(io.StringIO(), n, {1: SimpleNamespace()}) for n in (2, 3, 4)}
        now, fulls = 100.0, {n: 0 for n in guests}
        for round_number in range(40):
            guids = list(snapshot)
            for guid in rng.sample(guids, len(guids) // 3):  # motion/hp changes
                flat, hp, pose = snapshot[guid]
                snapshot[guid] = (flat, max(0.0, hp - 1), (pose[0] + 1, pose[1], pose[2]))
            for guid in rng.sample(guids, 5):  # debuff span and stable changes
                flat = bytearray(snapshot[guid][0])
                flat[0x20 + rng.randrange(16)] ^= 0xFF
                if rng.random() < .5:
                    flat[0x40] ^= 0x01
                snapshot[guid] = (bytes(flat), *snapshot[guid][1:])
            if round_number % 6 == 2:
                del snapshot[guids[0]]
            if round_number % 9 == 4:
                host.enemy_full_requested.add(3)
            snapshot = dict(snapshot)
            host.enemy_snapshot, host.boss_definitions = snapshot, bosses
            host.poll_generation += 1
            now += .1
            for peer, guest in guests.items():
                update = host.enemy_update(peer, now)
                if update is None:
                    continue
                fulls[peer] += update['base'] is None
                if update['base'] is not None:
                    self.assertTrue(all(not e[1] & ENEMY_FULL for e in blob_entries(update)))
                guest.apply_enemy_update(update)
                self.assertEqual(comparable(guest.enemy_snapshot, guest.boss_definitions),
                                 comparable(snapshot, {g: b for g, b in bosses.items() if g in snapshot}))
        self.assertEqual(fulls, {2: 1, 3: 5, 4: 1})  # The first update plus 4 requested fulls.


class LoopProfileTests(unittest.TestCase):
    def test_profiler_counts_stalls_and_sections(self):
        events = []

        class Callback:
            number = 1
            def record(self, **event):
                events.append(event)

        def fake_wait(event, ms):
            struct.pack_into('<I', event, 0, 1)
            return True

        profiler = loop_profile.Profiler(Callback(), fake_wait, lambda *a: True)
        buffer = bytearray(176)

        class Native:
            number = 1
        for delay in (0, .02, 0):
            profiler.wait(buffer, 100)
            profiler.hook(Native(), loop_profile.NAMES and next(iter(loop_profile.NAMES)) or 0x53D59D0)
            started = time.perf_counter()
            while time.perf_counter() - started < delay:
                pass
            profiler.section('work', delay)
            profiler.cont(1, 1, 0x10002)
        summary = profiler.summary()
        self.assertGreaterEqual(summary['stall_max_ms'], 19)
        self.assertEqual(summary['stall_over_ms']['16'], 1)
        self.assertIn('work', summary['top_sections'])
        self.assertEqual(events[-1]['event'], 'loop_profile_final')
        self.assertEqual(events[-1]['player'], 1)

    def test_inactive_wrapper_passes_through(self):
        wrapped = loop_profile.timed('x', lambda a, b=2: a + b)
        self.assertIsNone(loop_profile.ACTIVE)
        self.assertEqual(wrapped(1, b=3), 4)


if __name__ == '__main__':
    unittest.main()
