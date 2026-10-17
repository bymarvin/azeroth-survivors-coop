import hashlib
import json
import struct
import unittest

from verify_party_evidence import verify_party_combat, verify_independent_talents, verify_real_movement, native_pending_field
from world_packets import SELF, HOST, UPDATE, values_packet, remap_combat


def recordings():
    rows = [[] for _ in range(4)]
    update = values_packet(777, {22: 50})
    digest = hashlib.sha256(update).hexdigest()
    for n in range(1, 5):
        rows[n-1] += [dict(event='network_talent_verified', player=n, rank_verified=True,
            pending_before=2, pending_after=1, selected=(n-1)%3, title=f'New: Talent {n}'),
            dict(event='native_talent_spent', player=n, count=1)]
        for x in (float(n), float(n+1)):
            body = struct.pack('<IIffffI', 0, 100, x, 0, 0, 0, 0)
            rows[n-1].append(dict(event='native_movement', player=n, body=body.hex()))
            for recipient in range(1, 5):
                if recipient != n:
                    rows[recipient-1].append(dict(event='remote_pose', player=n,
                        recipient=recipient, pose=[x,0.,0.,0.], synthetic=False))
        if n == 1:
            continue
        body = struct.pack('<QQ', SELF, 777)
        rows[n-1] += [dict(event='native_guest_combat', player=n, opcode=0x143, body=body.hex()),
                      dict(event='native_guest_damage_computed', target=777, damage=10),
                      dict(event='world_delivered', opcode=UPDATE, digest=digest)]
        rows[0] += [dict(event='network_guest_hit_verified', player=n, target=777, applied=10, after=50),
                    dict(event='world_captured', recipient=n, opcode=UPDATE, digest=digest, body=update.hex())]
        host_attack = struct.pack('<QQ', HOST, 777)
        attack_digest = hashlib.sha256(host_attack).hexdigest()
        rows[0].append(dict(event='world_captured', recipient=n, opcode=0x143, digest=attack_digest, body=host_attack.hex()))
        rows[n-1].append(dict(event='world_delivered', opcode=0x143, digest=attack_digest))
        for recipient in range(1, 5):
            if recipient != n:
                rows[recipient-1].append(dict(event='network_attack_written', opcode=0x143,
                    body=remap_combat(0x143, body, player_guid=0xFF0100+n, local_guid=0xFF0100+recipient).hex()))
    return rows


class PartyEvidenceTests(unittest.TestCase):
    def test_cached_json_pending_counter_keys(self):
        proof = {'pending_by_choice_kind': {0: 'pending_talents', 1: 'pending_chests', 2: 'pending_rewards'}}
        cached = json.loads(json.dumps(proof))
        for kind in range(3):
            self.assertEqual(native_pending_field(proof, kind), native_pending_field(cached, kind))
        self.assertIsNone(native_pending_field(cached, 255))

    def test_enemy_attack_targeting_host_is_not_host_attack(self):
        rows = recordings()
        for row in rows[0]:
            if row['event'] == 'world_captured' and row['opcode'] == 0x143:
                row['body'] = struct.pack('<QQ', 777, HOST).hex()
        with self.assertRaisesRegex(AssertionError, 'host attack'):
            verify_party_combat(rows)

    def test_complete_native_evidence(self):
        rows = recordings()
        self.assertTrue(verify_party_combat(rows)['attack_packets'])
        self.assertTrue(verify_independent_talents(rows)['independent_native_talents'])
        self.assertTrue(verify_real_movement(rows)['real_native_movement'])

    def test_send_only_attack_is_not_recipient_delivery(self):
        rows = recordings()
        rows[2] = [r for r in rows[2] if r['event'] != 'network_attack_written']
        with self.assertRaises(AssertionError):
            verify_party_combat(rows)

    def test_damage_receipt_without_native_hp_application_does_not_pass(self):
        rows = recordings()
        rows[0] = [r for r in rows[0] if not (r['event'] == 'network_guest_hit_verified' and r['player'] == 4)]
        with self.assertRaises(AssertionError):
            verify_party_combat(rows)

    def test_missing_shared_hp_at_one_guest_rejects(self):
        rows = recordings()
        rows[3] = [r for r in rows[3] if r['event'] != 'world_delivered']
        with self.assertRaises(AssertionError):
            verify_party_combat(rows)

    def test_pending_spend_without_matching_ability_is_not_talent_acceptance(self):
        rows = recordings()
        next(r for r in rows[1] if r['event'] == 'network_talent_verified')['rank_verified'] = False
        with self.assertRaises(AssertionError):
            verify_independent_talents(rows)

    def test_remote_pose_without_real_native_movement_rejects(self):
        rows = recordings()
        rows[0] = [r for r in rows[0] if r['event'] != 'native_movement']
        with self.assertRaisesRegex(AssertionError, 'operator input'):
            verify_real_movement(rows)

    def test_automatic_movement_requires_ready_press_and_timely_native_displacement(self):
        rows = recordings()
        for source, events in enumerate(rows, 1):
            events += [dict(event='native_input_test_installed', player=source),
                       dict(event='native_input_ready_press', player=source, monotonic=10., phase=1,
                            ready=[1,2,3,4], loaded=[1,2,3,4]),
                       dict(event='native_input_test_path', player=source, stage='release', monotonic=12.)]
            for stamp, row in zip((9.,11.), (r for r in events if r['event']=='native_movement')):
                row['monotonic'] = stamp
        self.assertTrue(verify_real_movement(rows)['gated_native_input'])
        last = [r for r in rows[0] if r['event']=='native_movement'][-1]
        last['monotonic'] = 74.
        with self.assertRaisesRegex(AssertionError, 'no real native movement'):
            verify_real_movement(rows)
        last['monotonic'] = 11.
        next(r for r in rows[0] if r['event']=='native_input_ready_press')['phase'] = 0
        with self.assertRaises(AssertionError):
            verify_real_movement(rows)

    def test_synthetic_renderer_pose_does_not_count(self):
        rows = recordings()
        for row in rows[3]:
            if row['event'] == 'remote_pose':
                row['synthetic'] = True
        with self.assertRaises(AssertionError):
            verify_real_movement(rows)


if __name__ == '__main__':
    unittest.main()
