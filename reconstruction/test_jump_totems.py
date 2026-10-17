"""Regression checks for native jump packets and player-owned summons."""
import io
import math
import os
import struct
import unittest
from unittest.mock import patch
from sessions import decode_ground_movement, ProtocolError, Pose
from world_packets import Reader, validate_movement_packet, objects, UPDATE, DESTROY, SELF, values_packet, object_packet, remap_combat
from native_guest_combat import NativeCombatBridge
from types import SimpleNamespace
from visibility_bridge import packed_guid
from group_online import GroupOnlineBridge


def jump(flags=0x2000):
    return struct.pack('<IIffffI4f', flags, 123, 1, 2, 3, .5, 20, 7.95, 0, 1, 7)


class JumpTotemTests(unittest.TestCase):
    def test_jump_layout_and_invalid_extensions(self):
        self.assertEqual(decode_ground_movement(jump()), Pose(1, 2, 3, .5))
        for body in (jump()[:-1], jump()+b'x', jump(0x200000),
                     jump()[:28]+struct.pack('<4f', math.nan, 0, 1, 7)):
            with self.assertRaises(ProtocolError):
                decode_ground_movement(body)
        packet = packed_guid(0xFF0102) + jump()
        self.assertEqual(validate_movement_packet(packet, (1,2,3,4), 2), 2)
        with self.assertRaises(ValueError):
            validate_movement_packet(packet, (1,2,3,4), 3)

    def test_jump_then_landing_survive_guest_host_fanout(self):
        class Wire:
            def __init__(self): self.inbox=[]
            def send(self,message): self.other.inbox.append(message)
            def drain(self): result,self.inbox=self.inbox,[]; return result
        channels, peers = {}, {}
        for n in (2,3,4):
            a,b=Wire(),Wire();a.other,b.other=b,a;channels[n],peers[n]=a,b
        with patch.dict(os.environ,COOP_PLAYERS='4'):
            host=GroupOnlineBridge(io.StringIO(),1,channels)
            guests={n:GroupOnlineBridge(io.StringIO(),n,{1:w}) for n,w in peers.items()}
        payload=jump()
        landed=struct.pack('<IIffffI',0,140,1,2,3,.5,0)
        events=[(0xBB,packed_guid(0xFF0102)+payload),(0xC9,packed_guid(0xFF0102)+landed)]
        for n in (1,3,4): guests[2].notice_packets[n].extend(events)
        guests[2].latest_movement[2]=(0xEE,landed)
        guests[2].poll_network();host.poll_network()
        for n in (3,4):
            guests[n].poll_network()
            self.assertEqual(guests[n].notice_packets[n],events)
        self.assertEqual(host.notice_packets[1],events)

    def test_native_totem_capture_collision_lifetime_and_enemy_exclusion(self):
        # Captured Shaman native CREATE (entry 9500); both peers used this GUID.
        captured = bytes.fromhex('010000000003d95e1c2530f1037000000000000000002dd012c60ae01dc48e5488420000000000000000000020400000e04000009040711c974000002040db0f494001000000051ff040100c40000000000000000000001e0000005e00001c250030f1090000001c2500000000803ffeffff0000000000feffff00000000000500000005000000110000000200000002000000cdcccc3e0000803feb110000eb110000')
        block, = objects(captured, remap=False)
        guid = block.guid
        with patch.dict(os.environ,COOP_PLAYERS='4'):
            bridge=NativeCombatBridge(io.StringIO())
        bridge.native_totem_guids=lambda number:{guid}
        for number in (2,3,4):
            local=bridge.filter_packet(number,UPDATE,captured)
            shown,=objects(local,remap=False)
            expected=guid|((number-1)<<22)
            self.assertEqual(shown.guid,expected)
            self.assertEqual(shown.fields[0]|shown.fields[1]<<32,expected)
            for recipient in bridge.members:
                if recipient!=number:
                    op,body=bridge.attack_packets[recipient].pop()
                    self.assertEqual(objects(body,remap=False)[0].guid,expected)
            dead=bridge.filter_packet(number,DESTROY,struct.pack('<Q',guid))
            self.assertEqual(struct.unpack('<Q',dead)[0],expected)
            self.assertFalse(bridge.summons[number])
            for queue in bridge.attack_packets.values():queue.clear()
        bridge.native_totem_guids=lambda number:{guid}
        bridge.progress_sent[2]=(1,0,5)
        mixed=object_packet([block, *objects(values_packet(SELF,{716:123}),remap=False)])
        bridge.filter_packet(2,UPDATE,mixed)
        self.assertNotIn(2,bridge.progress_sent)
        bridge.native_totem_guids=lambda number:set()
        bridge.summon_maps[2].clear()
        # Units outside the totem vector are forwarded only when they name this player
        # as summoner/creator (companions); mirrored enemies have no owner.
        self.assertIsNone(bridge.filter_packet(2,UPDATE,captured.replace(bytes.fromhex('feffff00'),bytes(4))))

    def test_summon_namespace_validation_and_departure(self):
        wire=SimpleNamespace(send=lambda message:None,drain=lambda:[],close=lambda:None)
        with patch.dict(os.environ,COOP_PLAYERS='4'):
            bridge=GroupOnlineBridge(io.StringIO(),1,{n:wire for n in (2,3,4)})
        raw=bytes.fromhex('010000000003d95e1c2530f1037000000000000000002dd012c60ae01dc48e5488420000000000000000000020400000e04000009040711c974000002040db0f494001000000051ff040100c40000000000000000000001e0000005e00001c250030f1090000001c2500000000803ffeffff0000000000feffff00000000000500000005000000110000000200000002000000cdcccc3e0000803feb110000eb110000')
        guid=objects(raw,remap=False)[0].guid
        remote=guid|(1<<22)
        packet=object_packet(objects(raw,guid_map={guid:remote,SELF:0xFF0102}))
        bridge.receive_summon_packet(UPDATE,packet,2)
        with self.assertRaises(ValueError):bridge.receive_summon_packet(UPDATE,packet,3)
        bridge.remove_guest(2)
        for n in (1,3,4):self.assertIn((DESTROY,struct.pack('<Q',remote)),bridge.notice_packets[n])

    def test_return_to_menu_does_not_wait_for_cosmetic_notices(self):
        bridge=NativeCombatBridge(io.StringIO())
        bridge.native_states={n:(5,1,0,0) for n in bridge.members}
        bridge.notice_packets[1].append((0xBB,packed_guid(0xFF0102)+jump()))
        self.assertTrue(bridge.finish_ready())
        bridge.hurt_packets[1].append((0x150,b'accepted combat'))
        self.assertFalse(bridge.finish_ready())

    def test_packed_guid_growth_keeps_combat_and_object_boundaries(self):
        mapping={0xF130002329000001:0xF130002329400001}
        body=packed_guid(next(iter(mapping)))+packed_guid(SELF)+b'payload'
        transformed=remap_combat(0x250,body,guid_map=mapping)
        reader=Reader(transformed,remap_enabled=False)
        self.assertEqual(reader.guid(),next(iter(mapping.values())))
        self.assertEqual(reader.guid(),0xFF0101)
        self.assertEqual(bytes(reader.take(7)),b'payload');reader.end()

if __name__=='__main__': unittest.main()

