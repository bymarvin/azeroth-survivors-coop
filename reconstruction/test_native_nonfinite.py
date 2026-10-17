"""Broken native entries (NaN/inf in game memory) are skipped and logged; the run goes on (host crash 0.0.17)."""
import io
import json
import math
import os
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import visibility_bridge
from native_guest_combat import NativeCombatBridge, enemy_offset
from native_probe import IMAGE_SIZE, game_field
from updated_layout import enemy_layout
from visibility_bridge import NATIVE_SKIPS, melee_packet, native_enemy, parse_native_enemies

NAN, INF = float('nan'), float('inf')
FIELDS = ('hp', 'x0', 'y0', 'z0', 'x1', 'y1', 'z1')


def records(*enemies):
    """Enemy vector bytes; each enemy is (guid, dict of float fields to override, definition)."""
    stride, _, layout = enemy_layout()
    record = struct.Struct(layout)
    data = bytearray(stride * len(enemies))
    for i, (guid, values, definition) in enumerate(enemies):
        f = dict(dict(hp=50.0, x0=1.0, y0=2.0, z0=3.0, x1=1.0, y1=2.0, z1=3.0, began=0.0, duration=0.0), **values)
        record.pack_into(data, i * stride + 0x68, 0, guid, *(f[k] for k in (*FIELDS, 'began', 'duration')))
        struct.pack_into('<Q', data, i * stride + enemy_offset(0x80), definition)
    return bytes(data)


def events(output, name):
    return [json.loads(line) for line in output.getvalue().splitlines() if json.loads(line).get('event') == name]


class NonfiniteTests(unittest.TestCase):
    def setUp(self):
        NATIVE_SKIPS['last'].clear()
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            self.bridge = NativeCombatBridge(io.StringIO())
        self.output = self.bridge.output

    def test_nan_and_inf_in_hp_and_position_skip_only_that_enemy(self):
        for field in FIELDS:
            for bad in (NAN, INF, -INF):
                NATIVE_SKIPS['last'].clear()
                data = records((7, {}, 0), (8, {field: bad}, 0), (9, {}, 0))
                got = parse_native_enemies(data, 5.0)
                self.assertEqual([g for g, *_ in got], [7, 9], (field, bad))
        logged = events(self.output, 'enemy_state_nonfinite')
        self.assertEqual(len(logged), len(FIELDS) * 3)
        self.assertTrue(all(e['key'] == 8 for e in logged))
        json.loads(self.output.getvalue().splitlines()[-1], parse_constant=self.fail)  # Valid JSON, no NaN tokens.
        self.assertIn('nan', logged[0]['fields'])

    def test_enemy_is_normal_again_and_logged_once_per_minute(self):
        clock = [1000.0]
        with patch.object(visibility_bridge.time, 'monotonic', lambda: clock[0]):
            for _ in range(5):
                self.assertEqual(parse_native_enemies(records((8, {'x0': NAN}, 0)), 5.0), [])
                clock[0] += 1
            self.assertEqual(len(events(self.output, 'enemy_state_nonfinite')), 1)
            healthy = parse_native_enemies(records((8, {}, 0)), 5.0)
            self.assertEqual(healthy, [(8, 50.0, (1.0, 2.0, 3.0))])
            clock[0] += 60
            parse_native_enemies(records((8, {'hp': INF}, 0)), 5.0)
        self.assertEqual(len(events(self.output, 'enemy_state_nonfinite')), 2)

    def test_nonfinite_game_clock_skips_without_crash(self):
        self.assertEqual(parse_native_enemies(records((7, {}, 0), (8, {}, 0)), NAN), [])

    def test_single_lookup_treats_broken_enemy_as_absent(self):
        memory = bytearray(0x4000)
        array = 0x2000

        def client(data):
            memory[array:array + len(data)] = data
            struct.pack_into('<QQ', memory, game_field(0x568), array, len(data) // enemy_layout()[0])
            struct.pack_into('<f', memory, game_field(0x85C), 5.0)
            return SimpleNamespace(memory=lambda a, n: bytes(memory[a:a + n]))
        self.assertIsNone(native_enemy(client(records((8, {'y1': NAN}, 0))), 0, 8))
        self.assertEqual(native_enemy(client(records((8, {}, 0))), 0, 8), (50.0, (1.0, 2.0, 3.0)))

    def test_bad_definition_skips_one_enemy_but_all_bad_is_structural(self):
        base, good, bad = 0x140000000, 0x140000000 + 0x1000, 0x140000000 + IMAGE_SIZE + 0x10
        self.bridge._enemy_raw = (records((7, {}, good), (8, {}, bad), (9, {'hp': NAN}, good)), 5.0, base)
        snapshot = self.bridge.enemy_snapshot
        self.assertEqual(sorted(snapshot), [7])
        self.assertEqual(len(events(self.output, 'enemy_definition_invalid')), 1)
        self.bridge._enemy_raw = (records(*((g, {}, bad) for g in range(10, 16))), 5.0, base)
        with self.assertRaisesRegex(ValueError, 'not in the verified executable'):
            self.bridge.enemy_snapshot

    def test_invalid_xp_multiplier_keeps_the_last_value(self):
        self.bridge.ready = set(self.bridge.members)
        self.bridge.native_states = {n: (1, 1, 0, 0) for n in self.bridge.members}
        memory = bytearray(0x1000)
        struct.pack_into('<f', memory, game_field(0x4A0), 1000)
        struct.pack_into('<f', memory, game_field(0x85C), 99)
        memory[game_field(0x8BF)] = 1
        client = SimpleNamespace(number=2, server=-16, memory=lambda a, n: memory[a:a + n],
                                 put=lambda a, b: memory.__setitem__(slice(a, a + len(b)), b),
                                 call_before=lambda *a, **k: None)
        with patch.object(self.bridge, 'sync_mirrors', return_value=False), \
                patch.object(self.bridge, 'sync_chests', return_value=False):
            for value, expected in ((1.5, 1.5), (NAN, 1.5), (INF, 1.5), (2.0, 2.0)):
                struct.pack_into('<f', memory, game_field(0x514), value)
                self.bridge.before_batch(client, bytearray(1232))
                self.assertEqual(self.bridge.xp_multipliers[2], expected)
        self.assertEqual(len(events(self.output, 'xp_multiplier_invalid')), 1)

    def test_melee_damage_saturates_instead_of_raising(self):
        self.assertEqual(melee_packet(1, 2, 2 ** 40), melee_packet(1, 2, 0xFFFFFFFF))
        self.assertEqual(melee_packet(1, 2, -5), melee_packet(1, 2, 0))


if __name__ == '__main__':
    unittest.main()
