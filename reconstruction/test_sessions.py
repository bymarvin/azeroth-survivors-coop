"""Run: python -m unittest discover -s reconstruction -v (stdlib only)."""
import struct
import unittest

from sessions import ClientFrames, HeaderCipher, HEARTBEAT, LOGIN, Pose, ProtocolError, SessionRouter


def frame(opcode, body=b''):
    return struct.pack('>H', len(body) + 4) + struct.pack('<I', opcode) + body


def move(x, y=-633, z=68.02, facing=1.6, flags=0):
    # Synthetic payload from rounded runtime pose; NOT captured raw packet bytes.
    return frame(HEARTBEAT, struct.pack('<IIffffI', flags, 554, x, y, z, facing, 0))


class ReconstructionCheck(unittest.TestCase):
    def test_rooted_heartbeat_has_the_same_ground_layout(self):
        from sessions import decode_ground_movement
        self.assertEqual(decode_ground_movement(move(1, 2, 3, 4, flags=0x1000)[6:]), Pose(1, 2, 3, 4))

    def test_header_cipher_and_fragmentation(self):
        # Hand-derived encrypted 0020ee000000 with key bytes 0..39.
        key = bytes(range(40))
        self.assertEqual(HeaderCipher(key).decrypt(bytes.fromhex('00210d101419')),
                         bytes.fromhex('0020ee000000'))
        # Independent sender maintains cipher state across packet boundaries.
        index = previous = 0
        encoded = bytearray()
        originals = [frame(LOGIN, struct.pack('<Q', 1))] + [move(n) for n in range(8)]
        for packet in originals:
            for value in packet[:6]:
                previous = ((value ^ key[index]) + previous) & 255
                encoded.append(previous)
                index = (index + 1) % 40
            encoded.extend(packet[6:])
        reader = ClientFrames(key)
        received = []
        for value in encoded:  # Split inside every header and body; wrap the key.
            received.extend(reader.feed(bytes([value])))
        self.assertEqual(received, [(struct.unpack_from('<I', p, 2)[0], p[6:]) for p in originals])
        self.assertEqual(ClientFrames().feed(b''.join(originals)), received)

    def test_two_players_ownership_and_reconnect(self):
        host = SessionRouter()
        start = Pose(-9396, -633, 68.02, 1.6)
        host.add_player(1, 'alice', start)
        host.add_player(2, 'bob', start)
        for connection, account, guid in [('a', 'alice', 1), ('b', 'bob', 2)]:
            host.attach_authenticated(connection, account)
            host.receive(connection, frame(LOGIN, struct.pack('<Q', guid)))
        host.receive('a', move(-9395))
        self.assertEqual(host.snapshot()[2], start)
        host.receive('b', move(-9397))
        self.assertEqual({guid: p.x for guid, p in host.snapshot().items()}, {1: -9395, 2: -9397})
        host.attach_authenticated('intruder', 'alice')
        with self.assertRaises(ProtocolError):
            host.receive('intruder', frame(LOGIN, struct.pack('<Q', 2)))
        host.attach_authenticated('duplicate', 'bob')
        with self.assertRaises(ProtocolError):
            host.receive('duplicate', frame(LOGIN, struct.pack('<Q', 2)))
        host.disconnect('a')
        self.assertEqual(set(host.snapshot()), {2})
        host.attach_authenticated('a-new', 'alice')
        host.receive('a-new', frame(LOGIN, struct.pack('<Q', 1)))
        self.assertEqual(host.snapshot()[1].x, -9395)
        self.assertEqual(host.snapshot()[2].x, -9397)

    def test_reject_invalid_input_without_changing_other_player(self):
        for bad in [move(float('nan')), move(float('inf')), move(0, flags=0x2000),
                    frame(HEARTBEAT, b'bad'), b'\x00\x03\xee\x00\x00\x00',
                    frame(0xFFFF)]:
            host = SessionRouter()
            start = Pose(1, 2, 3, 4)
            host.add_player(1, 'alice', start)
            host.attach_authenticated('a', 'alice')
            host.receive('a', frame(LOGIN, struct.pack('<Q', 1)))
            with self.assertRaises(ProtocolError):
                host.receive('a', bad)
            self.assertEqual(host.players[1].pose, start)
            self.assertNotIn('a', host.sessions)
        host.attach_authenticated('no-login', 'alice')
        with self.assertRaises(ProtocolError):
            host.receive('no-login', move(0))
        with self.assertRaises(ProtocolError):
            ClientFrames().feed(b'x' * 65538)
        with self.assertRaises(ProtocolError):
            HeaderCipher(b'bad key')


if __name__ == '__main__':
    unittest.main()
