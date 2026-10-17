"""Native evidence gates reject cleanup, stale unlocks and mixed maps/classes."""
import copy
import json
from pathlib import Path
import tempfile
import struct
import unittest

from verify_room_departure import verify_departures
from verify_room_launch import verify_menu_selection, verify_player_fields, gear_record, verify_selected_gear, native_menu_taps, verify_concurrent_menus
from verify_save_staging import verify_unlock_reload, observed_baseline


class RoomAcceptanceTests(unittest.TestCase):
    def test_new_hero_requires_native_menu_after_victory_logout(self):
        from verify_network_boss import verify_return_to_roster
        messages = [dict(type=value) for value in ('roster', 'victory', 'logout', 'roster')]
        verify_return_to_roster(messages)
        with self.assertRaises(AssertionError):
            verify_return_to_roster(messages[:-1])
        with self.assertRaises(ValueError):
            verify_return_to_roster([dict(type='roster'), dict(type='victory')])

    def test_concurrent_native_menus_require_all_previews_before_any_enter(self):
        rows = [[dict(event='diagnostic_menu_selection', player=n, enter=False, time_ns=n),
                 dict(event='diagnostic_menu_selection', player=n, enter=True, time_ns=100+n)]
                for n in range(1, 5)]
        self.assertTrue(verify_concurrent_menus(rows)['concurrent_native_menus_verified'])
        rows[3][0]['time_ns'] = 102
        with self.assertRaises(AssertionError):
            verify_concurrent_menus(rows)
        rows[3].pop(0)
        with self.assertRaises(AssertionError):
            verify_concurrent_menus(rows)

    def test_native_menu_sequences_keep_host_map_and_guest_class_separate(self):
        tail = ';' + ';'.join(['605,605'] * 20)
        self.assertEqual(native_menu_taps(8), '135,319;908,220' + tail)
        self.assertEqual(native_menu_taps(1, zone='duskwood'), '135,190;908,329' + tail)
        self.assertEqual(native_menu_taps(4, guest=True), '135,254;908,220;135,254' + tail)
        self.assertEqual(native_menu_taps(1, equip_claymore=True, build='0843'),
                         '135,190;464,353;510,80;773,185;874,239;1046,79;908,220' + tail)
        self.assertEqual(native_menu_taps(1, equip_claymore=True, build='47e4'),
                         '135,190;462,390;510,80;773,185;874,239;1046,79;908,220' + tail)
        with self.assertRaises(ValueError):
            native_menu_taps(8, equip_claymore=True)

    def test_native_gear_requires_selected_nondefault_items_and_exact_login_result(self):
        schema = dict(size=232, class_id=228, slots=19, appearance_stride=8,
                      appearance_tag=0, appearance_id=4, items=152)
        raw = bytearray(232)
        raw[228] = 8
        struct.pack_into('<II', raw, 0, 1, 98765)
        struct.pack_into('<I', raw, 152, 12345)
        selected = gear_record(raw, schema)
        self.assertEqual(selected['appearances'][0], 98765)
        self.assertEqual(selected['items'][0], 12345)
        rows = [[dict(event='native_enter_gear', gear=selected), dict(event='native_login_gear', gear=selected)]
                for _ in range(4)]
        expected = [(n, 0, 12345) for n in range(1, 5)]
        self.assertTrue(verify_selected_gear(rows, expected)['gear_selection_verified'])
        self.assertTrue(verify_selected_gear(rows, [(n, None, 12345) for n in range(1, 5)])['gear_selection_verified'])
        duplicated = copy.deepcopy(rows)
        for row in duplicated[0]:
            row['gear']['items'][1] = 12345
        with self.assertRaises(AssertionError):
            verify_selected_gear(duplicated, [(n, None, 12345) for n in range(1, 5)])
        changed = copy.deepcopy(rows)
        changed[2][1]['gear']['items'][0] = None
        with self.assertRaises(AssertionError):
            verify_selected_gear(changed, expected)
        with self.assertRaises(AssertionError):
            verify_selected_gear(rows, expected[:-1])
        with self.assertRaises(AssertionError):
            verify_selected_gear(rows, [(n, 0, 0) for n in range(1, 5)])
        with self.assertRaises(AssertionError):
            verify_selected_gear(rows, [(n, None, 98765) for n in range(1, 5)])
        raw[0] = 2
        with self.assertRaises(AssertionError):
            gear_record(raw, schema)

    def test_complete_native_character_fields_survive_each_recipient(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/native-world-packets.jsonl'
        template = next(bytes.fromhex(r['body']) for r in map(json.loads, path.read_text().splitlines())
                        if r['opcode'] == 0xa9 and r['body'].startswith('01000000000307feffff0471'))
        rows = [[dict(event='native_player_create', player=n, body=template.hex())] for n in range(1, 5)]
        for recipient in range(1, 5):
            for source in range(1, 5):
                if recipient == source:
                    continue
                body = bytearray(template)
                body[6:10] = bytes((7, source, 1, 255))
                body[11] &= ~1
                struct.pack_into('<Q', body, 69 + body[68] * 4, 0xff0100 + source)
                rows[recipient-1].append(dict(event='remote_player_create_written', recipient=recipient,
                                               player=source, body=body.hex()))
        self.assertTrue(verify_player_fields(rows)['gear_replication_verified'])
        changed = copy.deepcopy(rows)
        body = bytearray.fromhex(changed[3][1]['body'])
        body[-1] ^= 1
        changed[3][1]['body'] = body.hex()
        with self.assertRaises(AssertionError):
            verify_player_fields(changed)
        rows[3].pop()
        with self.assertRaises(AssertionError):
            verify_player_fields(rows)

    def test_independent_equipment_choices_require_unequipped_native_baselines(self):
        empty = dict(class_id=1, items=[0] * 19, appearances=[None] * 19)
        equipped = copy.deepcopy(empty)
        equipped['items'][15] = 101800
        rows = []
        for number in range(1, 5):
            selected = copy.deepcopy(equipped if number % 2 else empty)
            rows.append([dict(event='native_initial_gear', player=number, before_enter=True,
                              class_id=1, gear=None, absent_record=True, time_ns=1),
                         dict(event='native_enter_gear', player=number, class_id=1, time_ns=2,
                              gear=selected if number % 2 else None, absent_record=not number % 2),
                         dict(event='native_login_gear', player=number, gear=selected)])
        expected = [(n, None, 101800 if n % 2 else 0) for n in range(1, 5)]
        self.assertTrue(verify_selected_gear(rows, expected, require_baseline=True)['gear_selection_verified'])
        for mutation in ('broadcast', 'pre_equipped', 'late', 'missing', 'default_appearance'):
            changed = copy.deepcopy(rows)
            if mutation == 'broadcast':
                changed[1][1]['gear'] = copy.deepcopy(equipped)
                changed[1][2]['gear'] = copy.deepcopy(equipped)
            elif mutation == 'pre_equipped':
                changed[0][0]['gear'] = equipped
            elif mutation == 'late':
                changed[0][0]['time_ns'] = 3
            elif mutation == 'missing':
                changed[0].pop(0)
            else:
                changed[1][2]['gear']['appearances'][15] = 101800
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                verify_selected_gear(changed, expected, require_baseline=True)

    def departure_rows(self):
        return [[dict(event='guest_departed', player=2),
                 dict(event='departure_world_continued', player=2),
                 dict(event='native_exit', player=1, code=0)],
                [dict(event='native_exit', player=2, code=0)],
                [dict(event='host_departed')], [dict(event='host_departed')]]

    def test_guest_normal_close_then_host_with_survivors(self):
        self.assertTrue(verify_departures(self.departure_rows(), [2], 4)['host_closed_with_survivors'])

    def test_unexpected_guest_departure_cannot_pass(self):
        rows = self.departure_rows()
        rows[0] += [dict(event='guest_departed', player=3), dict(event='departure_world_continued', player=3)]
        rows[2].append(dict(event='native_exit', player=3, code=0))
        with self.assertRaises(AssertionError):
            verify_departures(rows, [2], 4)

    def test_forced_cleanup_cannot_count_as_guest_exit(self):
        rows = self.departure_rows()
        rows[1] = [dict(event='debug_overhead', player=2)]
        with self.assertRaises(AssertionError):
            verify_departures(rows, [2], 4)

    def test_host_close_must_notify_every_survivor(self):
        rows = self.departure_rows()
        rows[3] = []
        with self.assertRaises(AssertionError):
            verify_departures(rows, [2], 4)

    def test_existing_unlock_is_not_new_progress(self):
        with self.assertRaisesRegex(AssertionError, 'already unlocked'):
            verify_unlock_reload([{'1': 2}] * 2, (1, 2), {'1': 2})
        self.assertTrue(verify_unlock_reload([{'1': 2}] * 2, (1, 2), {'1': 1}))
        self.assertFalse(verify_unlock_reload([{'1': 2}] * 2, (1, 2)))

    def test_reload_must_preserve_native_class_unlocks(self):
        with self.assertRaises(AssertionError):
            verify_unlock_reload([{'1': 2}, {'8': 2}], (1, 2), {'1': 1})

    def test_observed_empty_native_account_is_valid_but_wrong_build_or_late_is_not(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'baseline.json'
            baseline = dict(event='native_progression_baseline', player=3, sha256='build',
                            before_gameplay=True, classes={})
            path.write_text(json.dumps(baseline))
            self.assertEqual(observed_baseline(path, 'build'), {})
            self.assertTrue(verify_unlock_reload([{'8': 2}] * 2, (8, 2), observed_baseline(path, 'build')))
            for key, value in (('sha256', 'other'), ('before_gameplay', False), ('classes', {'8': 99})):
                path.write_text(json.dumps(dict(baseline, **{key: value})))
                with self.assertRaises(ValueError):
                    observed_baseline(path, 'build')

    def menu_rows(self, preset=False):
        rows = [[dict(event='diagnostic_menu_selection', player=n, class_id=c, zone='elwynn', enter=not preset),
                 dict(event='guest_map_enforced', player=n, zone='duskwood')]
                for n, c in enumerate((1, 8, 3, 4), 1)]
        for n, c in enumerate((1, 8, 3, 4), 1):
            if preset:
                rows[n-1].append(dict(event='diagnostic_menu_selection', player=n, class_id=c, zone='duskwood', enter=True))
            rows[n-1].extend([dict(event='guest_login_map_verified', player=n, zone='duskwood'),
                              dict(event='party_map_loaded', player=n, zone='duskwood', class_id=c)])
        rows[0].append(dict(event='host_map_selected', zone='duskwood'))
        return rows

    def test_actual_map_and_independent_classes_required(self):
        rows = self.menu_rows()
        result = verify_menu_selection(rows, 'duskwood', (1, 8, 3, 4), 'elwynn')
        self.assertTrue(result['conflicting_guest_selection_verified'])
        self.assertFalse(result['gear_selection_verified'])
        preview = copy.deepcopy(rows)
        preview[1][0]['enter'] = False
        with self.assertRaises(AssertionError):
            verify_menu_selection(preview, 'duskwood', (1, 8, 3, 4), 'elwynn')
        for key, value in (('zone', 'elwynn'), ('class_id', 1)):
            changed = copy.deepcopy(rows)
            changed[1][-1][key] = value
            with self.assertRaises(AssertionError):
                verify_menu_selection(changed, 'duskwood', (1, 8, 3, 4), 'elwynn')

    def test_ordered_native_preset_preserves_selected_class_and_host_map(self):
        rows = self.menu_rows(preset=True)
        result = verify_menu_selection(rows, 'duskwood', (1, 8, 3, 4), 'elwynn')
        self.assertEqual(result['guest_map_routes'], {n: 'preset-before-enter' for n in (2, 3, 4)})
        for left, right in ((0, 1), (1, 2), (3, 4)):
            changed = copy.deepcopy(rows)
            changed[1][left], changed[1][right] = changed[1][right], changed[1][left]
            with self.assertRaises(AssertionError):
                verify_menu_selection(changed, 'duskwood', (1, 8, 3, 4), 'elwynn')
        for index, key, value in ((0, 'class_id', 1), (2, 'class_id', 1), (3, 'zone', 'elwynn')):
            changed = copy.deepcopy(rows)
            changed[1][index][key] = value
            with self.assertRaises(AssertionError):
                verify_menu_selection(changed, 'duskwood', (1, 8, 3, 4), 'elwynn')


if __name__ == '__main__':
    unittest.main()
