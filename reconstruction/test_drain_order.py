"""Shutdown barriers retain final native damage before the host pauses."""
import io
import os
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from group_online import GroupOnlineBridge
from native_guest_combat import NativeCombatBridge
from test_party_departure import Wire


class DrainOrderTests(unittest.TestCase):
    def pair(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            a, b = Wire(), Wire()
            a.other, b.other = b, a
            host = GroupOnlineBridge(io.StringIO(), 1, {2: a})
            guest = GroupOnlineBridge(io.StringIO(), 2, {1: b})
        for bridge in (host, guest):
            bridge.native_states = {1: (1, 1, 0, 0), 2: (1, 1, 0, 0)}
        return host, guest

    def test_final_guest_damage_precedes_barrier_and_host_pause(self):
        host, guest = self.pair()
        self.assertFalse(host.finish_ready())
        self.assertTrue(host.draining)
        self.assertFalse(host.router.paused)
        host.poll_network()
        guest.poll_network()
        guest.damage_pending[123] = 7
        guest.native_states[2] = (3, 1, 0, 0)  # Native Pause completed.
        guest.drain_capture_complete = True
        self.assertFalse(guest.finish_ready())  # Unacknowledged damage retained.
        self.assertTrue(guest.router.paused)
        guest.last_network = 0
        guest.poll_network()
        host.poll_network()
        self.assertEqual(host.quiesced_peers, {2})
        self.assertEqual(host.damage_pending, {123: 7})
        self.assertFalse(host.finish_ready())
        self.assertFalse(host.router.paused)  # Host can still execute accepted DAMAGE.
        host.damage_pending.clear()  # Native completion produces the receipt.
        host.damage_receipts[2][123] = 7
        host.native_states[1] = (3, 1, 0, 0)
        self.assertTrue(host.finish_ready())
        guest.poll_network()
        self.assertEqual(guest.damage_pending, {})
        self.assertEqual(guest.damage_acked, {123: 7})
        self.assertFalse(guest.finish_ready())  # Still wait for host goodbye.
        guest.receive_peer(1, {'kind': 'goodbye'})
        self.assertTrue(guest.finish_ready())

    def test_nonrunning_phase_does_not_hide_unsettled_incoming_hit(self):
        for phase in (2, 3):
            host, guest = self.pair()
            guest.draining = guest.drain_capture_complete = True
            guest.native_states[2] = (phase, 1, 0, 0)
            guest.guest_hits.append((123, 5, 1.0))
            self.assertFalse(guest.finish_ready())
            message = {}
            guest.decorate(1, message)
            self.assertFalse(message['quiesced'])
            self.assertEqual(guest.guest_hits, [(123, 5, 1.0)])

    def test_native_victory_and_completed_menu_can_quiesce_without_live_enemy_access(self):
        for menu in (False, True):
            _, guest = self.pair()
            guest.draining = True
            guest.native_states[2] = (5, 1, 0, 0)
            if menu:
                guest.menu_players.add(2)
            message = {}
            guest.decorate(1, message)
            self.assertTrue(message['quiesced'])
            guest.clients[2] = SimpleNamespace(saved_context=b'owned-call')
            guest.decorate(1, message)
            self.assertFalse(message['quiesced'])

    def test_final_mirror_capture_records_damage_once_without_reconstruction(self):
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            bridge = NativeCombatBridge(io.StringIO(), shared_world=True)
        bridge.provided_hp = {123: 8}
        bridge.enemy_snapshot = {123: None}
        enemy = bytearray(0x148)
        struct.pack_into('<Q', enemy, 0x78, 123)
        struct.pack_into('<f', enemy, 0xE0, 3)
        calls = []
        def memory(address, size):
            calls.append(size)
            return struct.pack('<QQ', 4096, 1) if size == 16 else bytes(enemy)
        client = SimpleNamespace(number=2, server=0, memory=memory)
        self.assertFalse(bridge.sync_mirrors(client, None, capture_only=True))
        self.assertEqual(bridge.damage_pending, {123: 5})
        self.assertEqual(bridge.provided_hp, {})
        self.assertEqual(calls, [16, 0x148])
        bridge.sync_mirrors(client, None, capture_only=True)
        self.assertEqual(bridge.damage_pending, {123: 5})
