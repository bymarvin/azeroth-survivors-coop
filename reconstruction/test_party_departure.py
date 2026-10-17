import copy
import io
import json
import os
import struct
import unittest
from unittest.mock import patch

from group_online import GroupOnlineBridge
from world_packets import DESTROY, UPDATE, SELF, PROGRESSION, values_packet
from types import SimpleNamespace
from visibility_bridge import Bridge, RESUME


class Wire:
    def __init__(self):
        self.inbox, self.sent, self.closed, self.failed = [], [], False, False
    def send(self, message):
        if self.failed:
            raise ConnectionError('test disconnect')
        self.sent.append(copy.deepcopy(message))
        self.other.inbox.append(copy.deepcopy(message))
    def drain(self):
        if self.failed:
            raise ConnectionError('test disconnect')
        result, self.inbox = self.inbox, []
        return result
    def close(self): self.closed = True


class DepartureTests(unittest.TestCase):
    def test_disconnect_refunds_unawarded_purchase_and_ignores_remote_state(self):
        from native_probe import game_field
        for status in ('reserved', 'removed'):
            with self.subTest(status=status), patch.dict(os.environ, COOP_PLAYERS='2'):
                output = io.StringIO()
                guest = GroupOnlineBridge(output, 2, {1: Wire()})
                guest.native_states = {1: (1, 10, 40, 0), 2: (3, 10, 40, 0)}
                memory = {game_field(0x4A8): struct.pack('<I', 80)}
                client = SimpleNamespace(number=2, server=-0x10, saved_context=None,
                    memory=lambda address, size: memory[address], put=lambda address, data: memory.update({address: data}))
                guest.clients[2] = client
                guest.chest_claim = dict(guid=123, player=2, cost=20, status=status)
                guest.attack_packets[1].append((1, b'outgoing'))
                guest.hurt_packets[2].append((1, b'received'))
                error = ConnectionError('Co-op connection failed')
                error.__cause__ = TimeoutError('Co-op peer stopped responding')
                guest.connection_ended(1, error)
                self.assertIs(guest.connection_failure, error)
                self.assertFalse(guest.finish_ready())
                self.assertEqual(guest.chest_claim['status'], 'refund')
                self.assertEqual(guest.attack_packets[1], [])
                self.assertEqual(guest.hurt_packets[2], [(1, b'received')])
                guest.sync_chests(client, None)
                guest.sync_chests(client, None)
                self.assertEqual(struct.unpack('<I', memory[game_field(0x4A8)])[0], 100)
                self.assertIsNone(guest.chest_claim)
                self.assertFalse(guest.finish_ready())
                guest.hurt_packets[2].clear()  # Native delivery, never abandoned.
                self.assertTrue(guest.finish_ready())
                rows = [json.loads(line) for line in output.getvalue().splitlines()]
                self.assertEqual(sum(r['event'] == 'guest_chest_refunded' for r in rows), 1)
                error_row = next(r for r in rows if r['event'] == 'transport_failure')
                self.assertEqual(error_row['errors'][-1]['message'], 'Co-op peer stopped responding')

    def test_host_world_capture_after_last_guest_leaves(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            host = GroupOnlineBridge(io.StringIO(), 1, {2: Wire()})
        body = struct.pack('<Q', 123)
        host.capture_world(DESTROY, body)
        self.assertEqual(host.world_pending, [(DESTROY, body)])
        # Connected guests still have the original bounded backlog protection.
        from play_limits import MAX_WORLD_BACKLOG
        host.world_bytes = MAX_WORLD_BACKLOG
        with self.assertRaisesRegex(RuntimeError, 'Host-world queue backlog exceeded'):
            host.capture_world(DESTROY, body)
        host.connection_ended(2, 'TimeoutError')
        for _ in range(45000):  # More than 512 KiB of subsequent solo gameplay.
            self.assertEqual(host.filter_packet(1, DESTROY, body), body)
        progress = (32, 77, 100)
        host.capture_world(UPDATE, values_packet(SELF, dict(zip(PROGRESSION, progress))))
        self.assertEqual(host.router.progress, progress)
        self.assertEqual(host.world_bytes, 0)
        self.assertEqual(host.world_pending, [])
        self.assertEqual(host.counts['world_captured'], 1)
        self.assertFalse(host.stop_requested)

    def test_disconnected_guest_retires_outbound_damage_but_drains_received_work(self):
        output = io.StringIO()
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            guest = GroupOnlineBridge(output, 2, {1: Wire()})
        guest.native_states = {1: (2, 13, 2, 0), 2: (3, 13, 2, 0)}
        guest.damage_pending = {123: 89.25}
        guest.effects_pending = [(123, b'effect', 1)]
        self.assertFalse(guest.finish_ready())
        self.assertEqual(guest.damage_pending, {123: 89.25})
        guest.connection_ended(1, 'ConnectionError')
        guest.world_pending.append((DESTROY, struct.pack('<Q', 123)))
        self.assertFalse(guest.finish_ready())
        self.assertEqual(guest.damage_pending, {})
        self.assertEqual(guest.effects_pending, [])
        self.assertEqual(len(guest.world_pending), 1)
        guest.world_pending.clear()  # Represents native delivery, not discarded work.
        self.assertTrue(guest.finish_ready())
        abandoned = [json.loads(line) for line in output.getvalue().splitlines()
                     if json.loads(line)['event'] == 'outbound_combat_abandoned']
        self.assertEqual(abandoned, [dict(event='outbound_combat_abandoned',
                                         damage={'123': 89.25}, effects=1)])
        self.assertEqual(guest.damage_acked, {})

    def test_host_waits_for_personal_boss_reward_ack_after_world_drains(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host = GroupOnlineBridge(io.StringIO(), 1, {2: a})
        host.native_states = {n: (3, 1, 0, 0) for n in host.members}
        host.quiesced_peers = set(host.guests)  # This fixture begins after native quiescence.
        host.boss_reward_events = [dict(sequence=1)]
        self.assertFalse(host.finish_ready())
        host.boss_reward_events.clear()
        self.assertTrue(host.finish_ready())

    def test_host_drain_keeps_guests_until_final_world_acknowledgments(self):
        host_wires, guests = {}, {}
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            for number in (2, 3, 4):
                a, b = Wire(), Wire()
                a.other, b.other = b, a
                host_wires[number] = a
                guests[number] = GroupOnlineBridge(io.StringIO(), number, {1: b})
            host = GroupOnlineBridge(io.StringIO(), 1, host_wires)
        for bridge in (host, *guests.values()):
            bridge.native_states = {n: (3, 1, 0, 0) for n in bridge.members}
        packet = (DESTROY, struct.pack('<Q', 123))
        host.world_pending.append(packet)
        for number in (3, 4):
            host.world_queues[number].append(packet)
        host.counts['world_captured'] = 3
        self.assertFalse(host.finish_ready())
        host.poll_network()
        for guest in guests.values():
            guest.poll_network()
            self.assertTrue(guest.host_closing)
            self.assertTrue(guest.draining)
            self.assertFalse(guest.stop_requested)
            self.assertFalse(guest.finish_ready())
        host.poll_network()
        self.assertEqual(host.departed, set())
        self.assertEqual(host.counts.get('world_abandoned', 0), 0)
        self.assertFalse(host.finish_ready())
        # Simulate the native renderer consuming the last accepted packets.
        for guest in guests.values():
            guest.world_pending.clear()
            for pending in guest.world_queues.values():
                pending.clear()
            guest.world_bytes = 0
            guest.drain_capture_complete = True  # Final native HP comparison completed.
            guest.counts['world_delivered'] = guest.counts['world_captured']
            guest.last_network = 0
            guest.poll_network()
        host.poll_network()
        self.assertEqual(host.counts['world_delivered'], 3)
        self.assertTrue(host.finish_ready())
        self.assertTrue(all(not wire.closed for wire in host_wires.values()))
        for guest in guests.values():
            guest.receive_peer(1, dict(kind='goodbye'))
            self.assertTrue(guest.finish_ready())

    def test_guest_menu_quit_resumes_survivors_and_last_guest_can_leave(self):
        host_wires, guests = {}, {}
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            for n in (2, 3, 4):
                a, b = Wire(), Wire()
                a.other, b.other = b, a
                host_wires[n] = a
                guests[n] = GroupOnlineBridge(io.StringIO(), n, {1: b})
            host = GroupOnlineBridge(io.StringIO(), 1, host_wires)
        for bridge in (host, *guests.values()):
            bridge.router.paused = True
            bridge.native_states = {n: (3, 1, 0, 0) for n in bridge.members}
            bridge.created = {n: set(bridge.members) - {n} for n in bridge.members}
        # The departing guest's paused menu sends closing before goodbye.
        guests[2].draining = True
        guests[2].poll_network()
        host.poll_network()
        for n in (3, 4): guests[n].poll_network()
        for bridge in (host, guests[3], guests[4]):
            self.assertEqual(bridge.members, (1, 3, 4))
            self.assertFalse(bridge.stop_requested)
            self.assertFalse(bridge.router.paused)
            self.assertNotIn(2, bridge.native_states)
            self.assertNotIn(2, bridge.created[bridge.number])
        self.assertIn((DESTROY, struct.pack('<Q', 0xFF0102)), host.notice_packets[1])
        # A dead socket also removes only that authenticated guest.
        host_wires[3].failed = True
        host.last_network = 0
        host.poll_network()
        guests[4].poll_network()
        self.assertEqual(guests[4].members, (1, 4))
        host.receive_peer(4, dict(kind='goodbye'))
        host.poll_network()
        self.assertEqual(host.members, (1,))
        self.assertFalse(host.stop_requested)
        self.assertEqual(host.channels, {})

    def test_closing_rejects_late_peer_and_native_resume_and_preserves_acks(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host = GroupOnlineBridge(io.StringIO(), 1, {2: a})
            guest = GroupOnlineBridge(io.StringIO(), 2, {1: b})
        host.native_states = {1: (3, 1, 0, 0), 2: (3, 1, 0, 0)}
        host.clients[1] = SimpleNamespace(saved_context=None)
        host.quiesced_peers = {2}
        host.router.paused = True
        host.pause_pending[1] = False
        host.counts['world_captured'] = host.world_sent[2] = 1
        self.assertFalse(host.finish_ready())
        self.assertTrue(host.pause_pending[1])
        guest.controls = [dict(paused=False)]
        guest.send_state()
        host.receive_peer(2, a.drain()[0])
        host.quiesced_peers = {2}  # Exercise the post-barrier drain controls in this fixture.
        self.assertTrue(host.router.paused)
        self.assertTrue(host.pause_pending[1])
        self.assertEqual(host.controls, [])
        self.assertFalse(host.finish_ready())  # Missing ACK is still a hard gate.
        Bridge.__call__(host, SimpleNamespace(number=1, saved_context=None), RESUME, None)
        self.assertTrue(host.pause_pending[1])
        self.assertEqual(host.controls, [])
        guest.counts['world_delivered'] = 1
        guest.send_state()
        host.receive_peer(2, a.drain()[0])
        host.quiesced_peers = {2}  # Exercise the post-barrier drain controls in this fixture.
        self.assertEqual(host.counts['world_delivered'], 1)
        self.assertFalse(host.finish_ready())  # Native Resume repair must also finish.
        host.pause_pending.clear()
        self.assertTrue(host.finish_ready())

    def test_departure_while_host_closing_does_not_resume_survivors(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host = GroupOnlineBridge(io.StringIO(), 1, {2: a})
        host.draining = True
        host.router.paused = True
        host.remove_guest(2)
        self.assertTrue(host.router.paused)
        self.assertEqual(host.pause_pending, {1: True})
        self.assertEqual(host.controls, [])

    def test_accepted_hits_block_shutdown_for_living_recipients(self):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            for target in (2, 3, 4):
                for phase in (1, 2, 3):
                    with self.subTest(target=target, phase=phase):
                        host = Bridge(io.StringIO(), shared_world=True)
                        host.native_states = {n: (3, 1, 0, 0) for n in host.members}
                        host.native_states[target] = (phase, 1, 0, 0)
                        hits = host.guest_hits if target == 2 else host.hit_queues[target]
                        hit = (123, 10, 2.0)
                        hits.append(hit)
                        self.assertFalse(host.finish_ready())
                        self.assertEqual(hits, [hit])
                        hits.clear()  # Represents successful native consumption.
                        host.native_states[target] = (3, 1, 0, 0)
                        self.assertTrue(host.finish_ready())

    def test_completed_diagnostic_only_drains_accepted_work(self):
        from verify_network_coop import NetworkCoopVerification
        for stop, draining in ((True, False), (False, True)):
            bridge = object.__new__(NetworkCoopVerification)
            bridge.stop_requested, bridge.draining = stop, draining
            with patch.object(GroupOnlineBridge, 'before_batch', return_value=False) as inherited:
                self.assertFalse(bridge.before_batch(None, None))
                inherited.assert_called_once_with(None, None)

    def test_host_close_ends_guest_without_transport_exception(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            wire = Wire()
            guest = GroupOnlineBridge(io.StringIO(), 2, {1: wire})
        wire.inbox.append(dict(kind='goodbye'))
        guest.poll_network()
        self.assertTrue(guest.stop_requested)
        self.assertTrue(guest.peer_finished)

    def test_host_departure_releases_hits_held_by_guest_menu(self):
        # Crash 2026-10-14: host link dropped while the guest chose talents.
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            guest = GroupOnlineBridge(io.StringIO(), 2, {1: Wire()})
        guest.native_states = {1: (1, 35, 0, 0), 2: (4, 35, 0, 4)}
        guest.guest_hits.extend([(123, 5, 1.0)] * 23)
        guest.connection_ended(1, 'ConnectionError')
        self.assertTrue(guest.finish_ready())  # Host was still running (phase 1).
        self.assertEqual(guest.guest_hits, [])

    def test_host_departure_releases_combat_frames_for_other_members(self):
        # Live test 2026-10-14: queued frames for peers blocked the guest drain.
        output = io.StringIO()
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            guest = GroupOnlineBridge(output, 2, {1: Wire()})
        guest.native_states = {n: (1, 6, 0, 0) for n in guest.members}
        guest.native_states[2] = (4, 6, 0, 0)
        frame = (0x14A, b'frame')
        for n in (1, 3, 4):
            guest.attack_packets[n].append(frame)
            guest.notice_packets[n].append(frame)
        guest.hurt_packets[3].append(frame)
        guest.attack_packets[2].append(frame)  # For this guest's own native game.
        guest.connection_ended(1, 'ConnectionError')
        self.assertFalse(guest.finish_ready())
        self.assertEqual([guest.attack_packets[n] for n in (1, 3, 4)], [[], [], []])
        self.assertEqual(guest.hurt_packets[3], [])
        self.assertEqual(guest.attack_packets[2], [frame])  # Still delivered locally.
        guest.attack_packets[2].clear()  # Native delivery of the own frame.
        self.assertTrue(guest.finish_ready())
        self.assertEqual(events(output, 'outbound_packets_abandoned'),
                         [dict(event='outbound_packets_abandoned', count=7)])  # 0.0.10 event form.

    def test_host_departure_releases_hits_of_guest_slots_three_and_four(self):
        for number in (3, 4):
            with self.subTest(number=number):
                with patch.dict(os.environ, COOP_PLAYERS='4'):
                    guest = GroupOnlineBridge(io.StringIO(), number, {1: Wire()})
                guest.native_states = {n: (1, 35, 0, 0) for n in guest.members}
                guest.native_states[number] = (2, 35, 0, 1)
                guest.hit_queues[number].extend([(123, 5, 1.0)] * 23)
                guest.areas_by_guest[number].append((123, 4.0))
                guest.connection_ended(1, 'ConnectionError')
                self.assertTrue(guest.finish_ready())
                self.assertEqual(guest.hit_queues[number], [])
                self.assertEqual(guest.areas_by_guest[number], [])

    def test_running_guest_still_consumes_hits_during_host_close(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            guest = GroupOnlineBridge(io.StringIO(), 2, {1: Wire()})
        guest.native_states = {1: (3, 1, 0, 0), 2: (1, 1, 0, 0)}
        guest.clients[2] = SimpleNamespace(saved_context=None)
        guest.guest_hits.append((123, 5, 1.0))
        self.assertFalse(guest.finish_ready())
        self.assertEqual(guest.guest_hits, [(123, 5, 1.0)])  # Applied natively, not dropped.

    def test_host_drain_releases_guest_damage_held_by_pause(self):
        for paused, phase in ((True, 3), (False, 2), (True, 4)):
            with self.subTest(paused=paused, phase=phase):
                output = io.StringIO()
                with patch.dict(os.environ, COOP_PLAYERS='2'):
                    a, b = Wire(), Wire()
                    a.other, b.other = b, a
                    host = GroupOnlineBridge(output, 1, {2: a})
                host.native_states = {1: (phase, 1, 0, 0), 2: (3, 1, 0, 0)}
                host.clients[1] = SimpleNamespace(saved_context=None)
                host.quiesced_peers = {2}
                host.router.paused = paused
                host.damage_pending = {123: 50.0}
                host.effects_pending = [(123, bytes(12), 1)]
                self.assertTrue(host.finish_ready())
                self.assertEqual((host.damage_pending, host.effects_pending), ({}, []))
                self.assertEqual(len(events(output, 'guest_combat_abandoned')), 1)

    def test_running_host_still_applies_guest_damage_before_drain(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            host = GroupOnlineBridge(io.StringIO(), 1, {2: Wire()})
        host.native_states = {1: (1, 1, 0, 0), 2: (3, 1, 0, 0)}
        host.clients[1] = SimpleNamespace(saved_context=None)
        host.quiesced_peers = {2}
        host.damage_pending = {123: 50.0}
        self.assertFalse(host.finish_ready())
        self.assertEqual(host.damage_pending, {123: 50.0})

    def test_departed_host_refunds_reserved_chest(self):
        output = io.StringIO()
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            guest = GroupOnlineBridge(output, 2, {1: Wire()})
        guest.native_states = {1: (1, 1, 0, 0), 2: (3, 1, 0, 0)}
        gold = {}
        client = SimpleNamespace(number=2, server=0, saved_context=None,
                                 memory=lambda address, size: struct.pack('<I', 90),
                                 put=lambda address, data: gold.update(value=struct.unpack('<I', data)[0]))
        guest.clients[2] = client
        guest.chest_claim = dict(guid=5, player=2, cost=10, status='reserved', range=3,
                                 multiplier=1, xp_multiplier=1)
        guest.connection_ended(1, 'ConnectionError')
        self.assertFalse(guest.finish_ready())
        self.assertEqual(guest.chest_claim['status'], 'refund')
        self.assertFalse(guest.sync_chests(client, None))  # Next native batch refunds.
        self.assertEqual(gold, dict(value=100))
        self.assertIsNone(guest.chest_claim)
        self.assertTrue(guest.finish_ready())
        self.assertEqual(len(events(output, 'disconnected_purchase_refund_pending')), 1)  # 0.0.10

    def test_host_close_refunds_unawarded_chest_without_echoing_refund(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host = GroupOnlineBridge(io.StringIO(), 1, {2: a})
            guest = GroupOnlineBridge(io.StringIO(), 2, {1: b})
        guest.native_states = {1: (3, 1, 0, 0), 2: (3, 1, 0, 0)}
        guest.clients[2] = SimpleNamespace(saved_context=None)
        claim = dict(guid=5, player=2, cost=10, status='removed', range=3, multiplier=1, xp_multiplier=1)
        guest.chest_claim, guest.claims_sent[1] = claim, dict(claim)  # As received from the host.
        guest.host_closing = guest.draining = True
        guest.poll_network()
        self.assertEqual(guest.chest_claim['status'], 'refund')
        message = a.drain()[-1]
        self.assertNotIn('claim', message)  # The host accepts only reservations.
        host.receive_peer(2, message)

    def test_guest_bounds_waiting_hits_without_ending_session(self):
        output = io.StringIO()
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host = GroupOnlineBridge(io.StringIO(), 1, {2: a})
            guest = GroupOnlineBridge(output, 2, {1: b})
        for round in range(2):
            host.guest_hits = [(123 + round, 5, 1.0)] * 100
            host.last_network = 0
            host.poll_network()
            guest.poll_network()
        self.assertEqual(len(guest.guest_hits), 128)
        self.assertEqual(guest.guest_hits[-1], (124, 5, 1.0))  # Newest hit still last.
        # 0.0.12: same-attacker hits are folded instead of dropped; all 200 x 5 damage stays.
        self.assertEqual(sum(hit[1] for hit in guest.guest_hits), 1000)
        self.assertFalse(events(output, 'hit_queue_overflow'))
        self.assertTrue(events(output, 'hit_queue_merged'))
        from play_limits import MAX_QUEUE
        host.guest_hits = [(1, 5, 1.0)] * (MAX_QUEUE + 1)
        host.last_network = 0
        host.poll_network()
        with self.assertRaisesRegex(ValueError, 'Invalid incoming hit batch'):
            guest.poll_network()  # One message above the bound is still malformed.


class CongestedWire(Wire):
    def __init__(self, backlog):
        super().__init__()
        self.outgoing = SimpleNamespace(qsize=lambda: self.backlog)
        self.backlog, self.queued_bytes, self.error = backlog, backlog * 1000, None
    def latency_ms(self): return 42


def events(output, name):
    return [e for e in map(json.loads, output.getvalue().splitlines()) if e['event'] == name]


class UplinkTests(unittest.TestCase):
    def pair(self, backlog):
        output = io.StringIO()
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            a, b = CongestedWire(backlog), Wire()
            a.other, b.other = b, a
            host = GroupOnlineBridge(output, 1, {2: a})
            guest = GroupOnlineBridge(io.StringIO(), 2, {1: b})
        return output, a, host, guest

    def send(self, host, guest):
        host.last_network = 0
        host.poll_network()
        guest.poll_network()

    def test_congested_host_skips_snapshots_but_delivers_accepted_work(self):
        output, wire, host, guest = self.pair(8)
        guest.enemy_snapshot, guest.chests = {7: 'last snapshot'}, {9: 'last loot'}
        host.chests = {5: (0, (1.0, 2.0, 3.0), 1, 10)}
        host.guest_hits = [(123, 5, 1.0)]
        host.world_pending.append((DESTROY, struct.pack('<Q', 123)))
        host.xp_pending = 7
        self.send(host, guest)
        sent = wire.sent[-1]
        self.assertNotIn('enemy_update', sent)
        self.assertNotIn('chest_update', sent)
        self.assertEqual(guest.guest_hits, [(123, 5, 1.0)])
        self.assertEqual(guest.world_pending, [(DESTROY, struct.pack('<Q', 123))])
        self.assertEqual(guest.xp_pending, 7)
        self.assertEqual((guest.enemy_snapshot, guest.chests), ({7: 'last snapshot'}, {9: 'last loot'}))
        self.assertEqual(events(output, 'host_uplink_congested'),
                         [dict(event='host_uplink_congested', player=2, queued_bytes=8000,
                               queued_messages=8, latency_ms=42, transport_error=None)])
        wire.backlog = 0  # The uplink caught up: the next snapshot is complete again.
        self.send(host, guest)
        self.assertEqual(guest.enemy_snapshot, {})
        self.assertEqual(guest.chests, {5: (0, (1.0, 2.0, 3.0), 1, 10)})
        self.assertEqual(len(events(output, 'host_uplink_recovered')), 1)

    def test_unchanged_loot_is_sent_once(self):
        _, wire, host, guest = self.pair(0)
        host.chests = {5: (0, (1.0, 2.0, 3.0), 1, 10)}
        self.send(host, guest)
        self.assertEqual(wire.sent[-1]['chest_update'], dict(full=True, set=[[5, (0, (1.0, 2.0, 3.0), 1, 10)]]))
        self.send(host, guest)
        self.assertNotIn('chest_update', wire.sent[-1])
        self.assertEqual(guest.chests, {5: (0, (1.0, 2.0, 3.0), 1, 10)})
        host.chests = {6: (1, (0.0, 0.0, 0.0), 0, 3)}
        self.send(host, guest)  # Every change goes out at once: claims depend on it.
        self.assertEqual(wire.sent[-1]['chest_update'], dict(full=False, set=[[6, (1, (0.0, 0.0, 0.0), 0, 3)]], drop=[5]))
        self.assertEqual(guest.chests, {6: (1, (0.0, 0.0, 0.0), 0, 3)})

    def test_party_templates_are_sent_once_per_recipient(self):
        with patch.dict(os.environ, COOP_PLAYERS='3'):
            host = GroupOnlineBridge(io.StringIO(), 1, {2: Wire(), 3: Wire()})
        host.templates[3] = b'template'
        first, second, other = {}, {}, {}
        host.decorate(2, first)
        host.decorate(2, second)
        host.decorate(3, other)
        self.assertIn('template', first['party']['3'])
        self.assertNotIn('template', second['party']['3'])
        self.assertEqual(second['party']['3']['ready'], False)
        self.assertNotIn('3', other['party'])

    def test_guest_departure_logs_transport_backlog(self):
        output, wire, host, _ = self.pair(256)
        host.connection_ended(2, 'TimeoutError')
        self.assertEqual(events(output, 'guest_departed'),
                         [dict(event='guest_departed', player=2, reason='TimeoutError',
                               queued_bytes=256000, queued_messages=256, latency_ms=42,
                               transport_error=None)])


class NativeWorldRestartTests(unittest.TestCase):
    def test_replaced_native_connection_ends_session_without_decrypting(self):
        # Crash 15.10.2026 (v11): a second native world decrypted with the first
        # world's batch state -> ValueError('Truncated server body').
        from native_probe import WRITE, CONNECTIONS
        output = io.StringIO()
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            bridge = Bridge(output, shared_world=True)
        connection = bytearray(0xB0)
        connection[0x30] = 1
        connection[0x31:0x59] = b'\x11' * 40
        connection[0x5B:0x83] = b'\x22' * 40
        memory = {0x1000 + CONNECTIONS: struct.pack('<QQ', 0x2000, 1), 0x2000: bytes(connection)}
        client = SimpleNamespace(number=1, server=0x1000, memory=lambda address, size: memory[address][:size])
        bridge.connection_keys[1] = b'\x33' * 40 + b'\x22' * 40  # The first world's keys.
        bridge.server_states[1] = (5, 7)
        bridge(client, WRITE, bytearray(1248))
        bridge(client, WRITE, bytearray(1248))  # That client is no longer mirrored.
        events = [json.loads(line)['event'] for line in output.getvalue().splitlines()]
        self.assertEqual(events, ['native_world_restarted', 'party_restart_requires_lobby'])
        self.assertTrue(bridge.stop_requested)
        self.assertIn(1, bridge.menu_players)
        # The same connection never counts as a restart.
        for _ in range(3):
            self.assertFalse(bridge.native_connection_replaced(2, connection))


if __name__ == '__main__':
    unittest.main()

