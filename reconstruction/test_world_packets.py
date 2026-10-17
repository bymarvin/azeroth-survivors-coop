import io
import json
from pathlib import Path
import struct
import unittest

from world_packets import HOST, SELF, objects, object_packet, remap_combat, values_packet, PROGRESSION
from sessions import Pose, LOGIN, ProtocolError
from visibility_bridge import frame
from native_probe import PAUSE, RESUME
from types import SimpleNamespace
from visibility_bridge import Bridge, packed_guid


class WorldCheck(unittest.TestCase):
    def test_destroyed_world_objects_do_not_consume_lifetime_capacity(self):
        def create(guid):
            return struct.pack('<IBB', 1, 0, 2) + packed_guid(guid) + bytes([3, 0, 0])
        bridge = Bridge(io.StringIO(), shared_world=True)
        bridge.record = lambda **event: None
        for guid in range(1, 129):
            bridge.capture_world(0xA9, create(guid))
        bridge.world_pending.clear()
        bridge.world_bytes = 0
        for guid in range(129, 20129):
            bridge.capture_world(0xA9, create(guid))
            bridge.capture_world(0xAA, struct.pack('<Q', guid))
            self.assertEqual([opcode for opcode, _ in bridge.world_pending], [0xA9, 0xAA])
            self.assertEqual(len(bridge.world_guids), 128)
            bridge.world_pending.clear()  # Simulate a guest draining each ordered batch.
            bridge.world_bytes = 0
        bridge.capture_world(0xAA, struct.pack('<Q', 999999))  # Unknown/repeated destroy is harmless.
        self.assertEqual(len(bridge.world_guids), 128)
        for kind, expected in ((5, True), (4, False)):
            bridge.capture_world(0xA9, struct.pack('<IBBI', 1, 0, kind, 1) + packed_guid(1))
            self.assertEqual(1 in bridge.world_guids, expected)
        bridge.capture_world(0xA9, create(1))  # Re-entry/GUID reuse is tracked again.
        self.assertIn(1, bridge.world_guids)
        with self.assertRaises(ValueError):
            bridge.capture_world(0xAA, b'bad')
        from play_limits import MAX_WORLD_OBJECTS
        bridge.world_guids = set(range(1, MAX_WORLD_OBJECTS + 1))  # Only broken data gets here (0.0.12).
        with self.assertRaisesRegex(RuntimeError, 'active-object limit'):
            bridge.capture_world(0xA9, create(MAX_WORLD_OBJECTS + 1))
        self.assertEqual(len(bridge.world_guids), MAX_WORLD_OBJECTS)
        bridge.world_guids.clear()
        from play_limits import MAX_WORLD_BACKLOG
        bridge.world_bytes = MAX_WORLD_BACKLOG
        with self.assertRaisesRegex(RuntimeError, 'queue backlog'):
            bridge.capture_world(0xAA, struct.pack('<Q', 1))

    def test_guid_lists_and_bounds(self):
        for kind in (4, 5):
            body = struct.pack('<IBBI', 1, 0, kind, 2) + packed_guid(SELF) + packed_guid(123)
            blocks = objects(body)
            self.assertEqual([b.guid for b in blocks], [SELF, 123])
            self.assertEqual([b.guid for b in objects(object_packet(blocks))], [HOST, 123])
            with self.assertRaises(ValueError):
                objects(body[:-1])
            with self.assertRaises(ValueError):
                objects(struct.pack('<IBBI', 1, 0, kind, 4097))

    def test_shared_progress_and_either_player_resume(self):
        bridge = Bridge(io.StringIO(), shared_world=True)
        for number in (1, 2):
            bridge.router.add_player(number, str(number), Pose(0, 0, 0, 0))
            bridge.router.attach_authenticated(str(number), str(number))
            bridge.router.receive(str(number), frame(LOGIN, struct.pack('<Q', number)))
        for level, xp, required in ((1, 0, 5), (1, 2, 5), (2, 0, 10)):
            body = values_packet(SELF, dict(zip(PROGRESSION, (level, xp, required))))
            bridge.capture_world(0xA9, body)
            bridge.capture_world(0xA9, body)  # A repeated snapshot must not award XP twice.
            self.assertEqual(bridge.router.progress, (level, xp, required))
            self.assertEqual(objects(body)[0].fields, dict(zip(PROGRESSION, bridge.router.progress)))
        bridge.capture_world(0xA9, values_packet(SELF, {716: 3}))
        self.assertEqual(bridge.router.progress, (2, 3, 10))
        for first, second in (('1', '2'), ('2', '1')):
            bridge.router.set_paused(first, True)
            bridge.router.set_paused(first, True)
            self.assertTrue(bridge.router.paused)
            bridge.router.set_paused(second, False)
            self.assertFalse(bridge.router.paused)
        with self.assertRaises(ProtocolError):
            bridge.router.set_paused('unknown', True)
        bridge.router.disconnect('2')
        with self.assertRaises(ProtocolError):
            bridge.router.set_paused('2', False)

    def test_native_pause_hook_ignores_echoes_and_talent_state(self):
        bridge = Bridge(io.StringIO(), shared_world=True)
        bridge.router.add_player(1, '1', Pose(0, 0, 0, 0))
        bridge.router.attach_authenticated('1', '1')
        bridge.router.receive('1', frame(LOGIN, struct.pack('<Q', 1)))
        client = SimpleNamespace(number=1, saved_context=None, memory=lambda a, n: b'\x01')
        context = bytearray(1232)
        bridge.clients[2] = object()
        bridge(client, PAUSE, context)
        self.assertEqual(bridge.pause_pending, {1: True, 2: True})
        client.saved_context = b'injected call'
        client.memory = lambda a, n: b'\x03'
        bridge(client, RESUME, context)
        self.assertTrue(bridge.router.paused)
        client.saved_context = None
        client.memory = lambda a, n: b'\x02'
        bridge(client, RESUME, context)
        self.assertTrue(bridge.router.paused)
        client.memory = lambda a, n: b'\x03'
        bridge(client, RESUME, context)
        self.assertEqual(bridge.pause_pending, {1: False, 2: False})

    def test_actual_host_combat_capture_and_order(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/shared-world-first.jsonl'
        events = [json.loads(line) for line in path.read_text().splitlines()]
        captured = [v for v in events if v['event'] == 'world_captured']
        delivered = [v for v in events if v['event'] == 'world_delivered']
        self.assertEqual([(v['opcode'], v['digest']) for v in captured],
                         [(v['opcode'], v['digest']) for v in delivered])
        seen = set()
        for event in captured:
            opcode, body = event['opcode'], bytes.fromhex(event['body'])
            if opcode != 0xA9:
                self.assertEqual(remap_combat(opcode, body), body)
                seen.add(opcode)
        self.assertTrue({0xDD, 0xAA, 0x14A, 0x132, 0x250} <= seen)

    def test_captured_world_updates_and_host_routing(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/native-world-packets.jsonl'
        packets = [json.loads(line) for line in path.read_text().splitlines()]
        bridge = Bridge(io.StringIO(), shared_world=True)
        creatures = set()
        for packet in packets:
            if packet['opcode'] != 0xA9:
                continue
            body = bytes.fromhex(packet['body'])
            decoded = objects(body)
            for block in decoded:
                if block.object_type == 3:
                    creatures.add(block.guid)
                # All selected records are independently parseable after remapping.
                copy = objects(object_packet([block]))[0]
                self.assertEqual(copy.guid, HOST if block.guid == SELF else block.guid)
                if block.object_type in (3, 5):
                    self.assertEqual(copy.fields.get(0), block.fields.get(0))
            bridge.capture_world(0xA9, body)
        self.assertGreater(len(creatures), 0)
        delivered_creatures = {b.guid for _, body in bridge.world_pending
                               for b in objects(body) if b.object_type == 3}
        self.assertEqual(creatures, delivered_creatures)
        self.assertFalse(any(b.object_type in (1, 4) for _, body in bridge.world_pending for b in objects(body)))
        with self.assertRaises(ValueError):
            objects(body[:-1])

    def test_combat_guid_remapping_is_field_aware(self):
        enemy = 0xF13002580000000B
        # A numeric damage field equal to the old GUID must remain unchanged.
        body = struct.pack('<I', 0) + packed_guid(SELF) + packed_guid(enemy) + struct.pack('<I', SELF)
        mapped = remap_combat(0x14A, body)
        self.assertEqual(mapped, struct.pack('<I', 0) + packed_guid(HOST) + packed_guid(enemy) + struct.pack('<I', SELF))
        attack = struct.pack('<QQ', SELF, enemy)
        self.assertEqual(remap_combat(0x143, attack), struct.pack('<QQ', HOST, enemy))
        with self.assertRaises(ValueError):
            remap_combat(0x143, attack[:-1])


if __name__ == '__main__':
    unittest.main()
