import copy
import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from verify_network_boss import verify_boss_replication, delivered_world_packets


class BossAcceptanceTests(unittest.TestCase):
    def packets(self):
        bodies = [(0xA9, '00'), (0x14A, '00000000017b03c801')]
        host = [dict(event='world_captured', recipient=n, opcode=opcode, body=body,
                     digest=hashlib.sha256(bytes.fromhex(body)).hexdigest())
                for n in (2, 3, 4) for opcode, body in bodies]
        return [host] + [[dict(event='world_delivered', opcode=opcode,
                              digest=hashlib.sha256(bytes.fromhex(body)).hexdigest())
                         for opcode, body in bodies] for _ in range(3)]

    def test_delivery_rejects_missing_wrong_recipient_opcode_and_tampered_bodies(self):
        rows = self.packets()
        self.assertEqual(delivered_world_packets(rows)[3][0]['body'], '00')
        for change in ('missing', 'recipient', 'opcode', 'host-body', 'guest-body', 'digest'):
            altered = copy.deepcopy(rows)
            if change == 'missing':
                altered[0].pop(0)
            elif change == 'recipient':
                altered[0][0]['recipient'] = 4
            elif change == 'opcode':
                altered[1][0]['opcode'] = 0x123
            elif change == 'host-body':
                altered[0][0]['body'] = '01'
            elif change == 'guest-body':
                altered[1][0]['body'] = '01'
            else:
                altered[1][0]['digest'] = '0' * 64
            with self.subTest(change=change), self.assertRaises(AssertionError):
                delivered_world_packets(altered)

    def test_requires_entity_attacks_and_host_health_on_every_peer(self):
        recordings = self.packets()
        for rows in recordings:
            rows.extend([
                *[dict(event='boss_hud_delivered', boss=dict(name='Boss', hp=hp, hpMax=100))
                  for hp in (100, 90)],
            ])
        block = SimpleNamespace(guid=123, object_type=3, fields={22: 100, 131: 384})
        with patch('verify_network_boss.objects', return_value=[block]):
            verify_boss_replication(recordings, 123)
            for change in ('attack', 'hp', 'model'):
                altered = copy.deepcopy(recordings)
                if change == 'attack':
                    altered[3].pop(1)
                elif change == 'hp':
                    altered[3][-1]['boss']['hp'] = 80
                else:
                    block.fields[131] = 0
                with self.assertRaises(AssertionError):
                    verify_boss_replication(altered, 123)

    def falls(self):
        rows = []
        for number in range(1, 5):
            rows.append([
                dict(event='network_class_xp', player=number, stage='start', xp={'3': 1000}),
                dict(event='player_revived', player=number),
                dict(event='result_rearmed', player=number, reason='revival', was_locked=1, last_phase=4, xp_taken_back=40),
                dict(event='network_class_xp', player=number, stage='victory', before={'3': 1000}, xp={'3': 1090}),
            ])
        rows[0][:0] = [dict(event='network_fall_revived', player=n) for n in (2, 3, 4, 1)]
        return rows

    def test_fall_acceptance_requires_rearmed_evaluation_and_single_xp_credit(self):
        from verify_network_boss import verify_falls
        self.assertEqual(verify_falls(self.falls())['fall_xp_taken_back'], {1: 40, 2: 40, 3: 40, 4: 40})
        for change in ('order', 'no_rearm', 'not_locked', 'kept', 'double_credit'):
            rows = self.falls()
            guest = rows[2]
            if change == 'order':
                rows[0].pop(0)
            elif change == 'no_rearm':
                guest.pop(5 if guest is rows[0] else 2)
            elif change == 'not_locked':
                guest[2]['was_locked'] = 0
            elif change == 'kept':
                guest.append(dict(event='result_xp_kept', player=3, reason='account_changed_otherwise'))
            else:  # Without the fix: the fall credit is still there before the victory evaluation.
                guest[3]['before'] = {'3': 1040}
            with self.subTest(change=change), self.assertRaises(AssertionError):
                verify_falls(rows)

    def test_fall_acceptance_on_fresh_saves_and_shared_victory_rearm(self):
        # Live 0.0.15 runs: a fresh save has no class entry at the start ({}), the victory
        # evaluation reads {class: 0} right before it credits; guests also re-arm at the
        # shared victory without a lock and without taking XP back.
        from verify_network_boss import verify_falls
        rows = self.falls()
        for number, events in enumerate(rows, 1):
            for event in events:
                if event['event'] == 'network_class_xp':
                    if event['stage'] == 'start':
                        event['xp'] = {}
                    else:
                        event['before'], event['xp'] = ({'1': 0} if number != 2 else {}), {'1': 248}
            if number != 1:
                events.append(dict(event='result_rearmed', player=number, reason='shared_victory',
                                   was_locked=0, last_phase=0, xp_taken_back=0))
        self.assertEqual(verify_falls(rows)['falls'], 4)
        for change in ('locked_victory_rearm', 'victory_rearm_takes_xp', 'unknown_rearm', 'fall_credit_left',
                       'double_victory'):
            altered = copy.deepcopy(rows)
            guest = altered[2]
            extra = guest[-1]
            if change == 'locked_victory_rearm':
                extra['was_locked'] = 1
            elif change == 'victory_rearm_takes_xp':
                extra['xp_taken_back'] = 7
            elif change == 'unknown_rearm':
                extra['reason'] = 'menu'
            elif change == 'fall_credit_left':  # XP twice: the fall credit is still there before the victory.
                next(e for e in guest if e.get('stage') == 'victory')['before'] = {'1': 40}
            else:  # XP twice: the victory evaluation ran a second time.
                guest.append(dict(event='network_class_xp', player=3, stage='victory', before={'1': 248}, xp={'1': 496}))
            with self.subTest(change=change), self.assertRaises(AssertionError):
                verify_falls(altered)

    def test_unlock_must_be_verified_in_every_saved_profile(self):
        from verify_network_boss import check_unlock_records
        good = [dict(event='disposable_staging_complete', native_unlock_reload_verified=True,
                     expected_unlock_verified=True, newly_awarded_progression_verified=True)]
        self.assertEqual(check_unlock_records(2, 1, good), dict(class_id=1, map=2, unlocked=True))
        for change in ('no_reload', 'not_newly_unlocked', 'not_requested', 'reload_failed'):
            records = copy.deepcopy(good)
            if change == 'no_reload':
                records = [dict(event='native_progression_baseline')]
            elif change == 'not_newly_unlocked':  # The next map was not opened by this run.
                records[0]['newly_awarded_progression_verified'] = False
            elif change == 'not_requested':
                records[0]['expected_unlock_verified'] = False
            else:
                records[0]['native_unlock_reload_verified'] = False
            with self.subTest(change=change), self.assertRaises(AssertionError):
                check_unlock_records(2, 1, records)


if __name__ == '__main__':
    unittest.main()
