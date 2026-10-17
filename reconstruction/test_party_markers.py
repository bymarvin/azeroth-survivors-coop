import io
import os
import struct
import unittest
from unittest.mock import patch

from party_markers import append_markers, minimap_packet, raid_packet, validate_assignments, reject_remote_marker_packet
from world_packets import SELF, UPDATE, downed_player_values, object_packet, objects, values_packet
from native_guest_combat import NativeCombatBridge
from group_online import GroupOnlineBridge
from sessions import Pose
from test_party_departure import Wire


class PartyMarkersTests(unittest.TestCase):
    def test_remote_peers_cannot_supply_local_overlay_snapshots(self):
        with self.assertRaisesRegex(ValueError, 'local-only'):
            reject_remote_marker_packet(*minimap_packet([]))
        reject_remote_marker_packet(0x96, b'\x0a' + bytes(12) + b'ordinary chat')

    def test_native_board_translates_every_recipient_and_clears(self):
        assignments = {n: n - 1 for n in range(1, 5)}
        for recipient in assignments:
            opcode, body = raid_packet(assignments, recipient, set(assignments) - {recipient})
            self.assertEqual(opcode, 0x321)
            rows = list(struct.iter_unpack('<BQ', body[1:]))
            self.assertEqual(rows, [(n - 1, SELF if n == recipient else 0xFF0100 + n) for n in assignments])
        del assignments[2]
        self.assertEqual(list(struct.iter_unpack('<BQ', raid_packet(assignments, 1, {3, 4})[1][1:])),
                         [(0, SELF), (2, 0xFF0103), (3, 0xFF0104)])
        self.assertEqual(raid_packet({}, 1, set()), (0x321, b'\x01'))
        for bad in ({'1': 0, '2': 0}, {'5': 1}, {'1': True}, {'1': 8}, []):
            with self.assertRaises(ValueError):
                validate_assignments(bad, (1, 2, 3, 4))

    def test_downed_level_up_cannot_resurrect_rendered_body(self):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        for source in (1, 2, 3, 4):
            bridge.native_states[source] = (4, 6, 1, 0)
            body = values_packet(SELF, {22: 55, 28: 275, 34: 6, 716: 1})
            result = bridge.filter_packet(source, UPDATE, body)
            self.assertEqual(objects(result, remap=False)[0].fields[22], 0)
            if source != 1:
                for recipient in set(bridge.members) - {source}:
                    self.assertEqual(objects(bridge.notice_packets[recipient][-1][1], remap=False)[0].fields[22], 0)
            bridge.native_states[source] = (1, 6, 1, 0)
            self.assertEqual(bridge.filter_packet(source, UPDATE, body), body)
        other = values_packet(123, {22: 44})
        mixed = object_packet(objects(body, remap=False) + objects(other, remap=False))
        result = objects(downed_player_values(mixed), remap=False)
        self.assertEqual(result[0].fields, {22: 0, 28: 275, 34: 6, 716: 1})
        self.assertEqual(result[1].fields, {22: 44})

    def test_host_assignments_reach_all_guests_and_survive_departure(self):
        channels, guests = {}, {}
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            for n in (2, 3, 4):
                a, b = Wire(), Wire()
                a.other, b.other = b, a
                channels[n] = a
                guests[n] = GroupOnlineBridge(io.StringIO(), n, {1: b})
            host = GroupOnlineBridge(io.StringIO(), 1, channels)
        host.poll_network()
        for guest in guests.values():
            guest.poll_network()
            self.assertEqual(guest.raid_assignments, {1: 0, 2: 1, 3: 2, 4: 3})
        host.poll_network()
        host.remove_guest(2)
        host.poll_network()
        for n in (3, 4):
            guests[n].poll_network()
            self.assertEqual(guests[n].raid_assignments, {1: 0, 3: 2, 4: 3})
        with self.assertRaisesRegex(ValueError, 'Only the host'):
            host.receive_state(dict(kind='state', raid_assignments={'1': 0}))
        with self.assertRaisesRegex(ValueError, 'changed during'):
            guests[3].receive_state(dict(kind='state', raid_assignments={'1': 1, '3': 2, '4': 3}))

    def test_minimap_full_snapshot_lifecycle_preserves_local_marker(self):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.ready = set(bridge.members)
        bridge.created[1] = {2, 3, 4}
        for n in bridge.members:
            bridge.router.add_player(0xFF0100 + n, str(n), Pose(n * 10, n * -2, 0, 0))
            bridge.native_states[n] = (1, 1, 0, 0)
        def snapshot():
            bridge.minimap_sent.clear()
            packets = []
            append_markers(bridge, 1, packets)
            return packets[-1][1][25:-2].decode('ascii')
        self.assertEqual(snapshot(), 'ATMARK\t0|2,10.000,-2.000,0,506c617965722032;3,20.000,-4.000,0,506c617965722033;4,30.000,-6.000,0,506c617965722034')
        bridge.native_states[2] = (4, 1, 0, 0)
        self.assertIn('2,10.000,-2.000,1,', snapshot())
        bridge.native_states[2] = (1, 1, 0, 0)
        self.assertIn('2,10.000,-2.000,0,', snapshot())
        bridge.members = (1, 3, 4)
        self.assertNotIn('2,10.000', snapshot())
        bridge.native_states[1] = (5, 1, 0, 0)
        self.assertEqual(snapshot(), 'ATMARK\t0|')
        self.assertEqual(bridge.raid_assignments, {})
        self.assertEqual(minimap_packet([(2, 1, 2, True, 'A|é')])[1][25:-2].decode(),
                         'ATMARK\t0|2,1.000,2.000,1,417cc3a9')


if __name__ == '__main__':
    unittest.main()
