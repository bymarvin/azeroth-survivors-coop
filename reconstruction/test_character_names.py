"""Native identities stay bound to their authenticated owner, including host fanout."""
import io
import json
import os
from pathlib import Path
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from group_online import GroupOnlineBridge
from test_party_departure import Wire
from visibility_bridge import Bridge, character_name
from world_packets import SELF
from native_probe import SERIALIZE


class CharacterNameTests(unittest.TestCase):
    def test_first_serialized_batch_captures_local_identity(self):
        body = bytes.fromhex('feffff0000000000556c6972616e0000030000000000000003000000')
        packet = struct.pack('<QQQH6x', len(body), 0x2000, len(body), 0x51)
        memory = {0x1000: packet, 0x2000: body}
        client = SimpleNamespace(number=1, disable_hooks=set(),
                                 memory=lambda address, size: memory[address][:size])
        context = bytearray(1232)
        struct.pack_into('<Q', context, 136, 0x1000)
        bridge = Bridge(io.StringIO(), shared_world=True)
        bridge(client, SERIALIZE, context)
        self.assertEqual(bridge.name_responses, {1: body})

    def test_native_reply_validation_and_early_remote_query(self):
        # Captured 0.77.6 local Hunter response.
        body = bytes.fromhex('feffff0000000000556c6972616e0000030000000000000003000000')
        self.assertEqual(character_name(body), 'Uliran')
        bridge = Bridge(io.StringIO())
        self.assertEqual(bridge.filter_packet(1, 0x51, body), body)
        wrong = struct.pack('<Q', 0xFF0102) + body[8:]
        self.assertIsNone(bridge.filter_packet(1, 0x51, wrong))
        self.assertEqual(bridge.name_queries[1], {2})
        self.assertNotIn(2, bridge.name_responses)
        for malformed in (body[:8], body[:-1], body + b'\0', body.replace(b'Uliran', b'Ul\x01ran')):
            with self.assertRaises(ValueError):
                bridge.set_name_response(2, malformed)
        with self.assertRaises(ValueError):
            bridge.set_name_response(2, wrong)
        with self.assertRaises(ValueError):
            bridge.set_name_response(1, body.replace(b'Uliran', b'Otherx'))
        self.assertEqual(bridge.name_responses, {1: body})

    def test_four_native_identities_reach_every_peer(self):
        root = Path(__file__).resolve().parents[1]
        rows = map(json.loads, (root/'analysis/native-world-packets.jsonl').read_text().splitlines())
        template = next(bytes.fromhex(r['body']) for r in rows
                        if r['opcode'] == 0xA9 and r['body'].startswith('01000000000307feffff0471'))
        host_wires, guest_wires = {}, {}
        for n in (2, 3, 4):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host_wires[n], guest_wires[n] = a, b
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridges = {1: GroupOnlineBridge(io.StringIO(), 1, host_wires)}
            bridges.update({n: GroupOnlineBridge(io.StringIO(), n, {1: guest_wires[n]}) for n in (2, 3, 4)})
        expected = {}
        for n, bridge in bridges.items():
            body = struct.pack('<Q', SELF) + f'Native{n}'.encode() + b'\0\0' + struct.pack('<III', n, 0, n)
            expected[n] = body
            bridge.filter_packet(n, 0x51, body)
            bridge.templates[n] = template
            bridge.created[n] = set()
        for _ in range(3):
            for bridge in bridges.values():
                bridge.last_network = 0
                bridge.poll_network()
        for n, bridge in bridges.items():
            self.assertEqual(bridge.name_responses, expected)
            self.assertEqual(character_name(bridge.name_responses[n]), f'Native{n}')
        bridges[1].remove_guest(2)
        self.assertNotIn(2, bridges[1].name_responses)


if __name__ == '__main__':
    unittest.main()
