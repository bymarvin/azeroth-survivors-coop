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


if __name__ == '__main__':
    unittest.main()
