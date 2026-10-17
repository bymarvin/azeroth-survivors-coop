"""Disposable four-peer native chest contention and guest-four coin pickup."""
import struct
import time

from group_online import GroupOnlineBridge
from native_probe import CHOOSE, SPAWN_LOOT, game_field
from sessions import HEARTBEAT, Pose


def loot_clear(center, chests):
    # Keep both the contested pickup and later waiting positions clear of map loot.
    return all(sum((a - b) ** 2 for a, b in zip(position, (center[0] + waiting, *center[1:]))) > 100
               for _, position, _, _ in chests.values() for waiting in (0, 20))


def clear_loot_center(pose, chests):
    for offset in range(30, 151, 10):
        center = [pose.x + offset, pose.y, pose.z]
        if loot_clear(center, chests):
            return center
    raise ValueError('No clear native economy test location near the host')


class NetworkEconomyVerification(GroupOnlineBridge):
    def __init__(self, output, number, channels):
        super().__init__(output, number, channels)
        self.step = 0
        self.center = None
        self.prepared = False
        self.snapshots = {}
        self.reservations = set()
        self.spawned_steps = set()
        self.baseline = None
        self.coin_seen = False
        self.settled = None
        # The native start loot appears with the first running frame. Choose
        # the fixture only from a host loot snapshot taken in phase 1.
        self.loot_fresh = False

    def decorate(self, peer, message):
        super().decorate(peer, message)
        if self.number == 1:
            message['economy_diagnostic'] = [self.step, self.center]
        if self.number in self.snapshots:
            message['economy_snapshot'] = self.snapshots[self.number]

    def receive_peer(self, peer, message):
        if self.number == 1 and (message.get('claim') or {}).get('status') == 'reserved':
            self.reservations.add(peer)
        super().receive_peer(peer, message)
        if self.number != 1 and 'economy_diagnostic' in message:
            self.step, self.center = message['economy_diagnostic']
        if 'economy_snapshot' in message:
            self.snapshots[peer] = message['economy_snapshot']

    def record(self, **event):
        if event.get('event') == 'shared_gold_pickup' and event.get('picker') == 4:
            self.coin_seen = True
        super().record(**event)

    def sync_chests(self, client, context):
        # Let all three native clients reserve before the host resolves the
        # contested object. Only the diagnostic delays this arbitration.
        if client.number == 1 and self.step == 1 and self.chest_claim and len(self.reservations) < 3:
            return False
        result = super().sync_chests(client, context)
        if client.number == 1 and self.native_states[1][0] == 1:
            self.loot_fresh = True
        return result

    def before_batch(self, client, context):
        game = client.server + 0x10
        phase = self.native_states[client.number][0]
        if phase == 2:
            count = struct.unpack('<Q', client.memory(game + game_field(0x618), 8))[0]
            if not 1 <= count <= 16:
                raise ValueError('Invalid native choices')
            client.call_before(context, CHOOSE, game, (client.number - 1) % count)
            return True
        if phase != 1:
            return super().before_batch(client, context)
        client.put(game + game_field(0x4A0), struct.pack('<f', 1000))
        client.put(game + game_field(0x4F8), struct.pack('<f', 1000))
        if self.number == 1 and self.center is None and self.ready == set(self.members) and self.loot_fresh:
            pose = self.router.players[0xFF0101].pose
            self.center = clear_loot_center(pose, self.chests)
            self.record(event='network_economy_center', center=self.center, loot=len(self.chests))
        if self.center is None:
            return super().before_batch(client, context)
        if not self.prepared:
            self.prepared = True
            for offset, value in ((0x4A8, 100), (0x6D0, 100), (0x6D4, 0), (0x894, 20)):
                client.put(game + game_field(offset), struct.pack('<I', value))
        if self.number != 1:
            x, y, z = self.center
            if self.step >= 2 and self.number != 4:
                x += 20
            pose = Pose(x, y, z, 0)
            client.put(game + game_field(0x488), struct.pack('<4f', x, y, z, 0))
            self.router.players[0xFF0100 + self.number].pose = pose
            self.latest_movement[self.number] = (HEARTBEAT, struct.pack('<II4fI', 0, 0, x, y, z, 0, 0))
        gold = struct.unpack('<I', client.memory(game + game_field(0x4A8), 4))[0]
        earned, opened = struct.unpack('<II', client.memory(game + game_field(0x6D0), 8))
        self.snapshots[self.number] = [gold, earned, opened, self.step, bool(self.chest_claim)]
        if self.number == 1 and len(self.snapshots) == 4:
            current = [self.snapshots[n] for n in self.members]
            if self.step == 0:
                self.step = 1
            if self.step == 1 and sum(s[2] for s in current) == 1 and not any(s[4] for s in current):
                assert self.reservations == {2, 3, 4}, self.reservations
                spending = [s[1] - s[0] for s in current]
                assert sorted(spending) == [0, 0, 0, 20], spending
                opener = next(n for n in self.members if self.snapshots[n][2] == 1)
                assert opener != 1 and spending[opener - 1] == 20
                self.record(event='network_chest_contention_verified', opener=opener, snapshots=current)
                self.baseline = [s[:3] for s in current]
                self.step = 2
            if self.step in (1, 2) and self.step not in self.spawned_steps:
                if self.step == 1 and not loot_clear(self.center, self.chests):
                    # Native loot landed on the fixture before the contested chest.
                    if any(s[2] for s in current) or any(s[4] for s in current):
                        raise AssertionError(f'Native loot reached the economy fixture: {current}')
                    self.center = clear_loot_center(self.router.players[0xFF0101].pose, self.chests)
                    self.record(event='network_economy_center', center=self.center, loot=len(self.chests))
                    return super().before_batch(client, context)
                if self.step == 1 or all(s[3] == 2 for s in current[1:]):
                    self.spawned_steps.add(self.step)
                    client.call_before(context, SPAWN_LOOT, game, 2 if self.step == 1 else 1,
                                       amount=1 if self.step == 1 else 40, position=self.center)
                    return True
            if self.step == 2 and self.coin_seen:
                deltas = [s[0] - old[0] for s, old in zip(current, self.baseline)]
                if min(deltas) >= 40 and len(set(deltas)) == 1 and not any(s[4] for s in current):
                    assert all(s[2] == old[2] and s[1] - old[1] == delta
                               for s, old, delta in zip(current, self.baseline, deltas))
                    if self.settled is None:
                        self.settled = time.monotonic()
                    elif time.monotonic() - self.settled > 2:
                        self.record(event='network_guest_four_gold_verified', amount=deltas[0], snapshots=current)
                        self.stop_requested = True
        return super().before_batch(client, context)
