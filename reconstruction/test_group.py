import io
import os
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from native_guest_combat import NativeCombatBridge
from native_probe import game_field, AWARD_XP
from sessions import Pose
from world_packets import UPDATE, SELF, values_packet, objects


class GroupTests(unittest.TestCase):
    def test_guest_progress_updates_only_its_remote_avatar(self):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.router.set_host_progress(9, 10, 100)
        progress = bridge.router.progress
        fields = {22: 100, 34: 9, 716: 10, 717: 100, 36: 1234}
        bridge.filter_packet(3, UPDATE, values_packet(SELF, fields))
        for recipient in (1, 2, 4):
            opcode, body = bridge.notice_packets[recipient][0]
            block, = objects(body, remap=False)
            self.assertEqual(opcode, UPDATE)
            self.assertEqual(block.guid, 0xFF0103)
            self.assertEqual(block.fields, {22: 100, 34: 9, 716: 10, 717: 100})
        self.assertEqual(bridge.notice_packets[3], [])
        self.assertEqual(bridge.router.progress, progress)
        self.assertEqual([bridge.xp_pending, bridge.xp_queues[3], bridge.xp_queues[4]], [0, 0, 0])

    def test_guest_revival_notifications_reach_other_guests(self):
        from verify_network_coop import NetworkCoopVerification as GroupOnlineBridge
        from visibility_bridge import system_message
        class Wire:
            def __init__(self):
                self.inbox = []
            def send(self, message):
                self.other.inbox.append(message)
            def drain(self):
                messages, self.inbox = self.inbox, []
                return messages
        host_channels, guest_channels = {}, {}
        for number in (2, 3, 4):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host_channels[number], guest_channels[number] = a, b
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            host = GroupOnlineBridge(io.StringIO(), 1, host_channels)
            guests = {n: GroupOnlineBridge(io.StringIO(), n, {1: c}) for n, c in guest_channels.items()}
        notifications = [system_message('Player 2 is down.'), system_message('Player 2 revived with 50% health.')]
        for recipient in (1, 3, 4):
            guests[2].notice_packets[recipient].extend(notifications)
        guests[2].poll_network()
        host.poll_network()
        for number in (3, 4):
            guests[number].poll_network()
            self.assertEqual(guests[number].notice_packets[number], notifications)
        self.assertEqual(host.notice_packets[1], notifications)
        self.assertEqual(host.notifications, {(2, 'down'), (2, 'revived')})
        for number in (3, 4):
            self.assertEqual(guests[number].notifications, {(2, 'down'), (2, 'revived')})

    def test_busy_claim_refund_is_not_echoed_as_guest_request(self):
        from group_online import GroupOnlineBridge
        wire = SimpleNamespace(send=lambda message: None, drain=lambda: [])
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            guest = GroupOnlineBridge(io.StringIO(), 4, {1: wire})
        guest.chest_claim = dict(player=4, guid=123, cost=20, status='reserved')
        guest.receive_peer(1, dict(kind='claim_refund', claim=dict(guest.chest_claim, status='refund')))
        self.assertEqual(guest.claims_sent[1], guest.chest_claim)
        self.assertEqual(guest.chest_claim['status'], 'refund')

    def test_host_fanout_preserves_each_guests_rewards_and_damage_ack(self):
        from group_online import GroupOnlineBridge
        class Wire:
            def __init__(self):
                self.inbox = []
            def send(self, message):
                self.other.inbox.append(message)
            def drain(self):
                messages, self.inbox = self.inbox, []
                return messages
        host_channels, guest_channels = {}, {}
        for number in (2, 3, 4):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host_channels[number], guest_channels[number] = a, b
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            host = GroupOnlineBridge(io.StringIO(), 1, host_channels)
            guests = {n: GroupOnlineBridge(io.StringIO(), n, {1: c}) for n, c in guest_channels.items()}
        host.queue_gold(12)
        host.xp_pending = host.xp_queues[3] = host.xp_queues[4] = 17
        host.poll_network()
        for number, guest in guests.items():
            guest.poll_network()
            self.assertEqual(guest.gold_pending if number == 2 else guest.gold_by_guest[number], 12)
            self.assertEqual(guest.xp_pending if number == 2 else guest.xp_queues[number], 17)
            guest.damage_pending[123] = number * 10
            guest.last_network = 0
            guest.poll_network()
        host.poll_network()
        self.assertEqual(host.damage_pending, {123: 90})
        host.damage_pending.clear()
        host.record(event='native_guest_damage_applied', target=123, requested=90)
        host.last_network = 0
        host.poll_network()
        for number, guest in guests.items():
            guest.poll_network()
            self.assertEqual(guest.damage_pending, {})
            self.assertEqual(host.damage_receipts[number], {123: number * 10})

    def test_four_player_rewards_and_world_delivery_are_independent(self):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.native_states = {n: (1, 2, 0, 0) for n in bridge.members}
        bridge.router.players = {0xFF0100 + n: SimpleNamespace(pose=Pose(n * 50, 0, 0, 0)) for n in bridge.members}
        self.assertEqual([bridge.spawn_owner() for _ in range(8)], [1, 2, 3, 4] * 2)
        self.assertEqual(bridge.spawn_bonus(), .5)
        bridge.queue_gold(12)
        for number in bridge.guests:
            memory = bytearray(0x1000)
            struct.pack_into('<I', memory, game_field(0x4A8), number * 10)
            client = SimpleNamespace(number=number, server=-0x10,
                memory=lambda a, n: memory[a:a+n],
                put=lambda a, data: memory.__setitem__(slice(a, a+len(data)), data))
            bridge.apply_shared_gold(client)
            bridge.apply_shared_gold(client)
            self.assertEqual(struct.unpack_from('<I', memory, game_field(0x4A8))[0], number * 10 + 12)
            self.assertEqual(len(bridge.notice_packets[number]), 1)
        context = bytearray(1232)
        struct.pack_into('<Q', context, 136, 17)
        bridge(SimpleNamespace(number=1), AWARD_XP, context)
        self.assertEqual([bridge.xp_pending, bridge.xp_queues[3], bridge.xp_queues[4]], [17, 17, 17])
        bridge.capture_world(UPDATE, values_packet(SELF, {22: 100}))
        self.assertEqual(bridge.counts['world_captured'], 3)
        bridge.world_pending.clear()
        self.assertEqual([len(bridge.world_queues[n]) for n in (3, 4)], [1, 1])


if __name__ == '__main__':
    unittest.main()
