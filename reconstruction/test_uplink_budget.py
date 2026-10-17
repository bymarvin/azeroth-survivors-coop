"""Host->guest upload budget for a late-game state (measured 2026-10-15 live log).

The live host log showed ~70-84 KB state messages at 25 Hz (about 14 Mbit/s):
`damage_done` alone grew to 1 106 entries / 46 KB, the rest was mostly the
full enemy snapshot. This scenario reproduces that shape and measures the
bytes the transport actually writes per second.
"""
import io
import json
import os
import random
import struct
import time
import unittest
from unittest.mock import patch

import coop_transport
from group_online import GroupOnlineBridge
from test_party_departure import Wire
from world_packets import UPDATE

ENEMIES, DAMAGE_ENTRIES, CHESTS, WORLD_PER_TICK, TICKS = 120, 1100, 80, 4, 250  # 10 s at 25 Hz


def log(text):
    print(text, flush=True)


def flat_record(rng, guid, kind):
    """A plausible 0xE0-byte enemy record: per-kind template plus per-enemy fields."""
    template = random.Random(kind).randbytes(0xE0)
    flat = bytearray(template)
    struct.pack_into('<I', flat, 0, 0)
    struct.pack_into('<QQ', flat, 0x10, guid, 0x1000 + kind * 0x100)
    struct.pack_into('<f', flat, 0xE0 - 0x68, rng.uniform(50, 500))
    return flat


def frame_bytes(sequence, message):
    """Bytes the transport writes for one gameplay message."""
    encode = getattr(coop_transport, 'frame_bytes', None)
    body = json.dumps(message, separators=(',', ':'), allow_nan=False).encode()
    if encode is not None:
        return len(encode(sequence, body))
    return 4 + len(b'{"seq":' + str(sequence).encode() + b',"payload":' + body + b'}')


class Scenario:
    def __init__(self, seed=7, damage_entries=DAMAGE_ENTRIES):
        self.rng = random.Random(seed)
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            self.host = GroupOnlineBridge(io.StringIO(), 1, {2: a})
            self.guest = GroupOnlineBridge(io.StringIO(), 2, {1: b})
        self.wire = a
        for bridge in (self.host, self.guest):
            bridge.native_states = {1: (1, 30, 0, 0), 2: (1, 30, 0, 0)}
        self.next_guid = 0xF130000000100000
        self.enemies = {}
        for _ in range(ENEMIES):
            self.spawn()
        receipts = self.host.damage_receipts[2]
        for index in range(damage_entries):
            receipts[0xF130000000000000 + index] = self.rng.uniform(1, 400)
        self.host.chests = {0xF150000000000000 + i: (i, (self.rng.uniform(-50, 50), self.rng.uniform(-50, 50), 0.0), 1, 3)
                            for i in range(CHESTS)}

    def spawn(self):
        guid = self.next_guid
        self.next_guid += 1
        flat = flat_record(self.rng, guid, self.rng.randrange(12))
        self.enemies[guid] = [flat, struct.unpack_from('<f', flat, 0xE0 - 0x68)[0],
                              (self.rng.uniform(-60, 60), self.rng.uniform(-60, 60), 0.0)]

    def tick(self, number):
        rng = self.rng
        for guid, entry in list(self.enemies.items()):
            x, y, z = entry[2]
            entry[2] = (x + rng.uniform(-.3, .3), y + rng.uniform(-.3, .3), z)  # Interpolated movement.
            if rng.random() < .1:
                entry[1] = max(0.0, entry[1] - rng.uniform(1, 30))
            if rng.random() < .02:  # A new movement segment rewrites start/end/timer fields.
                struct.pack_into('<6f2f', entry[0], 0xFC - 0x68, *(rng.uniform(-60, 60) for _ in range(8)))
            if rng.random() < .01:  # A debuff applied by a player.
                entry[0][0x88 - 0x68] = rng.randrange(256)
            # Live 15.10.2026: record bytes outside hp/pose change on almost every
            # update (21-49 KB per update with full records). Model a per-tick
            # timer and an occasionally retargeted pointer.
            struct.pack_into('<f', entry[0], 0x40, number * .04)
            if (number + guid) % 8 == 0:
                struct.pack_into('<Q', entry[0], 0x58, rng.getrandbits(48))
        if number % 5 == 0:  # One death and one spawn every 200 ms.
            self.enemies.pop(next(iter(self.enemies)))
            self.spawn()
        self.host.enemy_snapshot = {guid: (bytes(flat), hp, pose) for guid, (flat, hp, pose) in self.enemies.items()}
        receipts = self.host.damage_receipts[2]
        for guid in rng.sample(sorted(receipts), 1):
            receipts[guid] += rng.uniform(1, 20)
        if number % 25 == 0:
            guid = rng.choice(sorted(self.host.chests))
            self.host.chests.pop(guid)
            self.host.chests[guid + 0x10000] = (0, (0.0, 0.0, 0.0), 1, 3)
        for _ in range(WORLD_PER_TICK):
            self.host.world_pending.append((UPDATE, rng.randbytes(90)))

    def run(self, ticks=TICKS):
        fields, total, messages, clock = {}, 0, 0, 1000.0
        updates, update_bytes, poll_seconds = 0, 0, 0.0
        with patch('group_online.time.monotonic', side_effect=lambda: clock):
            for number in range(ticks):
                clock = 1000.0 + number * .04
                self.tick(number)
                self.host.last_network = 0
                before = len(self.wire.sent)
                started = time.perf_counter()
                self.host.poll_network()
                poll_seconds += time.perf_counter() - started
                for message in self.wire.sent[before:]:
                    messages += 1
                    if 'enemy_update' in message:
                        updates += 1
                        update_bytes += len(json.dumps(message['enemy_update'], separators=(',', ':')))
                    total += frame_bytes(messages, message)
                    for key, value in message.items():
                        fields[key] = fields.get(key, 0) + len(json.dumps(value, separators=(',', ':')))
                self.guest.poll_network()
        seconds = ticks * .04
        return dict(messages=messages, bytes_per_message=total / messages, mbit=total * 8 / seconds / 1e6,
                    update_bytes=update_bytes / max(1, updates), poll_ms=poll_seconds * 1000 / ticks,
                    fields={k: v / messages for k, v in sorted(fields.items(), key=lambda i: -i[1])})


def blob_entries(update):
    """(guid, flags, bytes) per entry of a protocol-3 enemy update blob."""
    import base64
    from online_bridge import ENEMY_FULL, ENEMY_PATCH, ENEMY_SPANS_SET, ENEMY_BOSS, ENEMY_MOTION
    data, offset, result = base64.b64decode(update.get('blob', '')), 0, []
    while offset < len(data):
        start = offset
        guid, flags = struct.unpack_from('<QB', data, offset)
        offset += 9
        if flags & ENEMY_FULL:
            offset += 0xE0 + (8 if flags & ENEMY_BOSS else 0)
        if flags & ENEMY_PATCH:
            runs = data[offset]
            offset += 1
            for _ in range(runs):
                offset += 2 + data[offset + 1]
        offset += (36 if flags & ENEMY_SPANS_SET else 0) + (32 if flags & ENEMY_MOTION else 0)
        result.append((guid, flags, offset - start))
    return result


def comparable(snapshot, bosses):
    from online_bridge import enemy_parts
    return ({guid: (enemy_parts(flat), hp, tuple(pose)) for guid, (flat, hp, pose) in snapshot.items()},
            dict(bosses))


class EnemyDeltaTests(unittest.TestCase):
    def run_checked(self, scenario, ticks, lose=()):
        """Run the scenario; after every applied update the guest equals the host."""
        checked = 0
        clock = 1000.0
        with patch('group_online.time.monotonic', side_effect=lambda: clock):
            for number in range(ticks):
                clock = 1000.0 + number * .04
                scenario.tick(number)
                scenario.host.last_network = 0
                before = len(scenario.wire.sent)
                scenario.host.poll_network()
                sent = scenario.wire.sent[before:]
                if number in lose and sent:
                    scenario.guest.channels[1].inbox.clear()  # A lost message: the guest must catch up.
                scenario.guest.poll_network()
                scenario.guest.last_network = 0
                scenario.guest.poll_network()  # Publish the acknowledgment.
                scenario.host.poll_network()  # Receive it (sends nothing new: 40 ms pacing).
                update = next((m['enemy_update'] for m in sent if 'enemy_update' in m), None)
                if update is not None and number not in lose and scenario.guest.enemy_seq == update['seq']:
                    self.assertEqual(comparable(scenario.guest.enemy_snapshot, scenario.guest.boss_definitions),
                                     comparable(scenario.host.enemy_snapshot, scenario.host.boss_definitions))
                    checked += 1
        return checked

    def test_guest_mirrors_host_enemies_through_deltas_gaps_and_full_snapshots(self):
        scenario = Scenario(seed=11)
        boss = 0xF130000000FFFFFF
        flat = flat_record(scenario.rng, boss, 0)
        struct.pack_into('<Q', flat, 0x18, 0)  # Bosses use a separate native definition.
        scenario.enemies[boss] = [flat, 5000.0, (1.0, 2.0, 0.0)]
        scenario.host.boss_definitions = {boss: 0x2000}
        original_tick = scenario.tick
        def tick(number):
            original_tick(number)
            scenario.host.boss_definitions = {boss: 0x2000} if boss in scenario.enemies else {}
        scenario.tick = tick
        checked = self.run_checked(scenario, 200, lose={30, 31, 120})
        self.assertGreater(checked, 40)
        updates = [m['enemy_update'] for m in scenario.wire.sent if 'enemy_update' in m]
        fulls = [u for u in updates if u['base'] is None]
        self.assertGreaterEqual(len(fulls), 3)  # Initial and after each gap (no periodic full).
        self.assertLessEqual(len(fulls), 4)
        deltas = [u for u in updates if u['base'] is not None]
        from online_bridge import ENEMY_FULL, ENEMY_PATCH
        entries = [e for u in deltas for e in blob_entries(u)]
        partial = [e for e in entries if not e[1] & ENEMY_FULL]
        self.assertGreater(len(partial), 10 * len(deltas))  # Known enemies skip the full record.
        patched = [e for e in partial if e[1] & ENEMY_PATCH]
        self.assertGreater(len(patched), len(partial) / 2)  # The churning timer patches every update.
        self.assertLess(sum(e[2] for e in patched) / len(patched), 80)  # Not 0xE0 bytes per enemy.
        self.assertTrue(any(u.get('drop') for u in deltas))
        from group_online import ENEMY_SNAPSHOT_INTERVAL
        expected = 200 * .04 / max(ENEMY_SNAPSHOT_INTERVAL, .04)  # One update per interval of 40 ms ticks.
        self.assertGreater(len(updates), .9 * expected)
        self.assertLess(len(updates), 1.1 * expected + 5)  # Plus full snapshots after gaps.

    def test_delta_without_base_requests_full_snapshot(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            guest = GroupOnlineBridge(io.StringIO(), 2, {1: Wire()})
        from online_bridge import (binary, enemy_entry, enemy_motion, ENEMY_FULL, ENEMY_PATCH,
                                   ENEMY_MOTION, ENEMY_BOSS)
        guest.apply_enemy_update(dict(seq=5, base=4, blob=''))
        self.assertTrue(guest.enemy_full_needed)
        self.assertEqual((guest.enemy_seq, guest.enemy_snapshot), (0, {}))
        message = {}
        guest.decorate(1, message)
        self.assertEqual((message['enemy_ack'], message['enemy_full']), (0, True))
        flat = flat_record(random.Random(1), 7, 3)
        motion = enemy_motion(40.0, (1.0, 2.0, 3.0))
        guest.apply_enemy_update(dict(seq=6, base=None, blob=binary(enemy_entry(7, ENEMY_FULL | ENEMY_MOTION, flat, motion=motion))))
        self.assertFalse(guest.enemy_full_needed)
        self.assertEqual(guest.enemy_snapshot[7], (bytes(flat), 40.0, (1.0, 2.0, 3.0)))
        changed = bytearray(flat)
        changed[0x40:0x44] = b'\x01\x02\x03\x04'
        guest.apply_enemy_update(dict(seq=7, base=6, blob=binary(enemy_entry(7, ENEMY_PATCH, changed, runs=[(0x40, 0x44)]))))
        self.assertEqual(guest.enemy_snapshot[7], (bytes(changed), 40.0, (1.0, 2.0, 3.0)))
        guest.apply_enemy_update(dict(seq=8, base=7, blob=binary(enemy_entry(9, ENEMY_MOTION, b'', motion=motion))))
        self.assertTrue(guest.enemy_full_needed)  # A delta for an unknown enemy asks for a full one.
        self.assertEqual(guest.enemy_seq, 7)
        identity = bytearray(changed)
        identity[0x18] ^= 1
        wrong_guid = bytearray(flat)
        wrong_guid[0x10] ^= 1
        for name, blob in (('header', b'\x07\x00\x00'),
                           ('identity patch', enemy_entry(7, ENEMY_PATCH, identity, runs=[(0x18, 0x19)])),
                           ('patch past record', struct.pack('<QBBBB', 7, ENEMY_PATCH, 1, 0xDE, 4) + b'abcd'),
                           ('full with wrong guid', enemy_entry(7, ENEMY_FULL, wrong_guid)),
                           ('boss without full', struct.pack('<QB', 7, ENEMY_BOSS)),
                           ('truncated motion', enemy_entry(7, ENEMY_MOTION, b'', motion=motion)[:-4])):
            with self.subTest(name=name), self.assertRaises(ValueError):
                guest.apply_enemy_update(dict(seq=8, base=7, blob=binary(blob)))
        self.assertEqual(guest.enemy_snapshot[7][0], bytes(changed))  # Rejected updates change nothing.
        with self.assertRaises(ValueError):
            guest.apply_enemy_update(dict(seq=0, base=None, blob=''))

    def test_damage_receipts_send_only_changes_and_guest_still_settles(self):
        scenario = Scenario(seed=3)
        guest, host = scenario.guest, scenario.host
        guest.damage_pending = {0xF130000000000005: 10.0}
        guest.damage_sent = {0xF130000000000005: 10.0}
        host.damage_receipts[2][0xF130000000000005] = guest.damage_acked.get(0xF130000000000005, 0)
        scenario.run(ticks=2)
        self.assertEqual(len(scenario.wire.sent[0]['damage_done']), 1100)
        self.assertLessEqual(len(scenario.wire.sent[1]['damage_done']), 1)  # One receipt changed per tick.
        host.damage_receipts[2][0xF130000000000005] += 10.0
        scenario.run(ticks=1)
        self.assertIn([0xF130000000000005, 10.0], scenario.wire.sent[-1]['damage_done'])
        self.assertLessEqual(len(scenario.wire.sent[-1]['damage_done']), 2)
        self.assertEqual(guest.damage_pending, {})


class GuestStallTests(unittest.TestCase):
    """v11 stage 1: user report 'a ~100 ms freeze every few seconds' in the late game."""

    def test_full_snapshots_only_on_demand_unless_configured(self):
        import group_online
        for seconds, expected in ((0, 1), (2, 4)):
            with self.subTest(seconds=seconds), patch.object(group_online, 'FULL_SNAPSHOT_SECONDS', seconds):
                scenario = Scenario(seed=5)
                scenario.run(ticks=200)  # 8 s.
                updates = [m['enemy_update'] for m in scenario.wire.sent if 'enemy_update' in m]
                self.assertEqual(sum(u['base'] is None for u in updates), expected)
                self.assertEqual(len(events_named(scenario.host.output, 'enemy_full_snapshot')), expected)

    def test_guest_writes_only_changed_mirrors_and_dead_flags(self):
        from test_downed_fix import MirrorWriteTests
        import native_guest_combat
        bridge, client, memory, writes = MirrorWriteTests.fixture(None, 4)
        retired = 0x1000 + 3 * 0x148
        bridge.enemy_snapshot.pop(126)  # Slot 3 left the host world: retire it once.
        bridge.provided_hp.pop(126)
        self.assertFalse(bridge.sync_mirrors(client, None))
        self.assertEqual(struct.unpack_from('<I', memory, retired + 0x68)[0], 1)
        self.assertEqual(len(writes), 4)  # Three mirrors plus one dead flag.
        writes.clear()
        for _ in range(3):
            self.assertFalse(bridge.sync_mirrors(client, None))
        self.assertEqual(writes, [])  # Nothing changed: no native writes at all.
        bridge.enemy_snapshot[123] = (bridge.enemy_snapshot[123][0], 70, (1, 2, 3))
        self.assertFalse(bridge.sync_mirrors(client, None))
        self.assertEqual([address for address, _ in writes], [0x1000 + 0x68])
        self.assertEqual(bridge.recent_actions[-1][1:], ('mirror_writes', (1, 0)))
        writes.clear()
        with patch.object(native_guest_combat, 'MIRROR_WRITE_ALL', True):  # COOP_MIRROR_WRITE=all
            self.assertFalse(bridge.sync_mirrors(client, None))
        self.assertEqual(len(writes), 4)

    def test_background_log_writer_keeps_order_and_flushes_on_stop(self):
        from visibility_bridge import Bridge
        output = io.StringIO()
        bridge = Bridge(output, shared_world=True)
        bridge.start_log_writer()
        live = {'value': 1}
        for index in range(500):
            bridge.record(event='step', index=index)
        bridge.record(event='broken', value=object())
        bridge.stop_log_writer()
        lines = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([e['index'] for e in lines[:500]], list(range(500)))
        self.assertEqual(lines[500], dict(event='log_event_unserializable', name='broken', error='TypeError'))
        bridge.record(event='after_stop')  # Direct writes again once stopped.
        self.assertIn('after_stop', output.getvalue().splitlines()[-1])
        self.assertTrue(live)

    def test_frame_hitch_reports_gap_our_handling_and_recent_actions(self):
        import loop_profile
        events = []

        class Callback:
            number = 2
            recent_actions = []
            def record(self, **event):
                events.append(event)

        callback = Callback()
        profiler = loop_profile.Profiler(callback, lambda *a: True, lambda *a: True)
        client = type('Native', (), {'number': 2})()
        clock = [10.0]
        with patch.object(loop_profile, 'perf', lambda: clock[0]), \
                patch.dict(loop_profile.NAMES, {0x1234: 'WRITE'}):
            profiler.hook(client, 0x1234)
            callback.recent_actions.extend([(9.5, 'too_old', ()), (9.95, 'enemy_full', (140, 30000)),
                                            (10.01, 'mirror_writes', (140, 0))])
            profiler.handled_total += .012  # Our own hook handling inside the gap.
            clock[0] = 10.14
            profiler.hook(client, 0x1234)
            clock[0] = 10.19
            profiler.hook(client, 0x1234)  # 50 ms: an ordinary frame.
        hitches = [e for e in events if e['event'] == 'frame_hitch']
        self.assertEqual(len(hitches), 1)
        hitch = hitches[0]
        self.assertEqual((hitch['hook'], hitch['gap_ms'], hitch['ours_ms']), ('p2:WRITE', 140.0, 12.0))
        self.assertEqual([a[1] for a in hitch['actions']], ['enemy_full', 'mirror_writes'])


def events_named(output, name):
    return [e for e in map(json.loads, output.getvalue().splitlines()) if e.get('event') == name]


class TransportCompressionTests(unittest.TestCase):
    def test_frames_round_trip_and_reject_bombs_and_garbage(self):
        import zlib
        from coop_transport import frame_bytes, frame_payload, MAX_MESSAGE
        payload = json.dumps(dict(kind='state', enemies='x' * 50000)).encode()
        frame = frame_bytes(7, payload, b'"ping":3')
        self.assertLess(len(frame), len(payload) / 10)
        self.assertEqual(frame_payload(frame[4:]), dict(seq=7, payload=json.loads(payload), ping=3))
        small = frame_bytes(1, b'null')
        self.assertEqual(small[4:5], b'{')  # Keepalives stay plain JSON.
        bomb = b'Z' + zlib.compress(b'{"seq":0,"payload":"' + b'0' * (MAX_MESSAGE + 10) + b'"}', 9)
        self.assertLess(len(bomb), MAX_MESSAGE // 256)  # Tiny on the wire, huge when inflated.
        for body, reason in ((bomb, 'exceeds'), (b'Z' + zlib.compress(b'{}')[:-3], 'Truncated'),
                             (b'Znot zlib', 'Corrupt'), (b'\x00raw', 'Unknown')):
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                frame_payload(body)

    def test_protocol_mismatch_is_named_on_both_sides(self):
        import ssl
        import tempfile
        import socket
        import threading
        from pathlib import Path
        import coop_transport
        from coop_transport import create_pairing, accept, connect, encode, receive, VersionMismatch
        with tempfile.TemporaryDirectory() as folder:
            invite = create_pairing(folder)
            # An older guest (protocol 1) reaches a v9 host: the host names the reason.
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
                    old.sendall(encode(dict(protocol=1, build='test-build', token=invite['token'])))
                    self.assertEqual(receive(old, time.monotonic() + 5),
                                     dict(accepted=False, reason='protocol', protocol=coop_transport.PROTOCOL))
                thread.join(5)
                self.assertIsInstance(errors[0], VersionMismatch)
            # A v9 guest reaches an older host that closes silently.
            with socket.create_server(('127.0.0.1', 0)) as listener:
                def old_host():
                    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    server.load_cert_chain(str(Path(folder) / 'host-cert.pem'), str(Path(folder) / 'host-key.pem'))
                    raw, _ = listener.accept()
                    with server.wrap_socket(raw, server_side=True) as sock:
                        receive(sock, time.monotonic() + 5)
                thread = threading.Thread(target=old_host)
                thread.start()
                with self.assertRaisesRegex(ValueError, 'co-op version'):
                    connect('127.0.0.1', listener.getsockname()[1], invite, 'test-build')
                thread.join(5)

    def test_parallel_channels_decode_like_a_single_channel(self):
        """1 vs N concurrent I/O threads: identical decoded streams."""
        import tempfile
        import socket
        import threading
        from coop_transport import create_pairing, accept, connect
        rng = random.Random(5)
        messages = [dict(kind='state', index=i, blob=rng.randbytes(rng.randrange(10, 3000)).hex(),
                         text='enemy ' * rng.randrange(0, 2000)) for i in range(120)]

        def exchange(count):
            with tempfile.TemporaryDirectory() as folder, socket.create_server(('127.0.0.1', 0), backlog=8) as listener:
                invite = create_pairing(folder)
                hosts = []
                thread = threading.Thread(target=lambda: hosts.extend(
                    accept(listener, folder, invite, 'test-build') for _ in range(count)))
                thread.start()
                guests = [connect('127.0.0.1', listener.getsockname()[1], invite, 'test-build') for _ in range(count)]
                thread.join(10)
                try:
                    senders = [threading.Thread(target=lambda h=h: [h.send(m) or time.sleep(.001) for m in messages])
                               for h in hosts]
                    for sender in senders:
                        sender.start()
                    received = [[] for _ in guests]
                    deadline = time.monotonic() + 20
                    while min(map(len, received)) < len(messages) and time.monotonic() < deadline:
                        for index, guest in enumerate(guests):
                            received[index].extend(guest.drain())
                        time.sleep(.005)
                    for sender in senders:
                        sender.join(5)
                    return received, [h.wire_bytes for h in hosts], [h.payload_bytes for h in hosts]
                finally:
                    for channel in hosts + guests:
                        channel.close()

        single, single_wire, single_payload = exchange(1)
        parallel, parallel_wire, parallel_payload = exchange(4)
        self.assertEqual(single[0], messages)
        for stream in parallel:
            self.assertEqual(stream, single[0])
        self.assertLess(single_wire[0], single_payload[0])  # Compression reached the wire.
        log(f'[ INFO ] 1 vs 4 Kanaele: je {single_payload[0] / 1000:.0f} KB Nutzdaten -> '
            f'{single_wire[0] / 1000:.0f} KB auf dem Draht, Streams identisch')


class UplinkBudgetTests(unittest.TestCase):
    def test_late_game_host_upload_stays_below_two_mbit(self):
        log('[ .... ] Upload-Messung Host->Gast (120 Gegner, 1100 damage_done, 80 Truhen, 10 s)')
        started = time.perf_counter()
        result = Scenario().run()
        for key, size in list(result['fields'].items())[:8]:
            log(f'[ INFO ] Feld {key}: {size / 1000:.1f} KB je Nachricht (JSON, unkomprimiert)')
        log(f"[ INFO ] enemy_update im Mittel {result['update_bytes'] / 1000:.1f} KB (JSON, unkomprimiert), "
            f"Host-Senderunde {result['poll_ms']:.2f} ms")
        log(f"[ INFO ] {result['messages']} Nachrichten, {result['bytes_per_message'] / 1000:.1f} KB je Nachricht "
            f"auf dem Draht, {result['mbit']:.2f} Mbit/s")
        log(f'[  OK  ] Upload-Messung ({time.perf_counter() - started:.1f} s)')
        self.assertLess(result['mbit'], 2.0)
        self.assertLess(result['update_bytes'], 15000)  # Live v10: 21-49 KB per update.

    def test_host_send_cost_does_not_grow_with_run_history(self):
        """Live v10: send_state/thin_snapshot grew ~25x over 24 minutes (all receipts per send)."""
        log('[ .... ] Senderunde mit 1 000 vs 20 000 bisherigen Treffer-Quittungen')
        short = Scenario(seed=4, damage_entries=1000).run(ticks=100)['poll_ms']
        long = Scenario(seed=4, damage_entries=20000).run(ticks=100)['poll_ms']
        log(f'[ INFO ] Host-Senderunde: {short:.2f} ms bei 1 000, {long:.2f} ms bei 20 000 Quittungen')
        log('[  OK  ] Senderunde gemessen')
        self.assertLess(long, short * 2 + .5)


if __name__ == '__main__':
    unittest.main()
