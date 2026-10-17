"""Incoming damage must progress alongside mirrors without changing native calls."""
import io
import json
import os
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from native_guest_combat import NativeCombatBridge
from native_probe import game_field, HURT


class IncomingHitTests(unittest.TestCase):
    def bridge(self, number=3):
        with patch.dict(os.environ, COOP_PLAYERS='4'):
            bridge = NativeCombatBridge(io.StringIO())
        bridge.ready = set(bridge.members)
        bridge.native_states = {n: (1, 1, 0, 0) for n in bridge.members}
        memory = bytearray(0x1000)
        struct.pack_into('<f', memory, game_field(0x514), 1)
        struct.pack_into('<f', memory, game_field(0x4A0), 1000)
        struct.pack_into('<f', memory, game_field(0x85C), 99)
        memory[game_field(0x8BF)] = 1
        calls = []
        def call(context, rva, game, attacker, **kwargs):
            self.assertEqual(rva, HURT)
            calls.append((attacker, kwargs['damage'], kwargs['melee'],
                          struct.unpack_from('<f', memory, game_field(0x85C))[0]))
            health = struct.unpack_from('<f', memory, game_field(0x4A0))[0]
            struct.pack_into('<f', memory, game_field(0x4A0), health - kwargs['damage'])
            kwargs['after']()
        client = SimpleNamespace(number=number, server=-16,
            memory=lambda a, n: memory[a:a+n],
            put=lambda a, b: memory.__setitem__(slice(a, a+len(b)), b), call_before=call)
        return bridge, client, calls, memory

    def test_damage_and_busy_mirror_work_both_progress_for_every_guest(self):
        for number in (2, 3, 4):
            bridge, client, calls, _ = self.bridge(number)
            with patch.object(bridge, 'sync_mirrors', return_value=True) as mirrors, \
                    patch.object(bridge, 'sync_chests', return_value=False):
                for turn in range(260):
                    if turn % 2 == 0:
                        bridge.queue_incoming_hit(number, 'hits', (11, 1, turn / 10))
                    bridge.before_batch(client, bytearray(1232))
                    # Each turn models one native queue write (the hit chain ends there);
                    # within one write at most HITS_PER_BATCH hits are applied (0.0.12).
                    bridge.hit_batch_written(number)
            self.assertEqual(len(calls), 130)
            self.assertEqual(mirrors.call_count, 130)
            self.assertFalse(bridge.incoming_queue(number, 'hits'))
            self.assertEqual(bridge.hit_metrics[number, 'hits']['high_water'], 1)

    def test_mixed_hits_keep_order_flags_damage_and_restore_live_clock(self):
        bridge, client, calls, memory = self.bridge()
        bridge.queue_incoming_hit(3, 'hits', (11, 1, 1))
        bridge.queue_incoming_hit(3, 'areas', (22, 2), 2)
        bridge.queue_incoming_hit(3, 'hits', (33, 3, 3))
        for _ in range(3):
            self.assertTrue(bridge.apply_incoming_hit(client, bytearray(1232)))
            self.assertEqual(struct.unpack_from('<f', memory, game_field(0x85C))[0], 99)
        self.assertEqual(calls, [(11, 1, True, 1), (22, 2, False, 2), (33, 3, True, 3)])

    def test_pause_and_menu_retain_hits_death_and_victory_retire_obsolete_hits(self):
        for number in (2, 3, 4):
            bridge, client, calls, _ = self.bridge(number)
            for phase in (2, 3):
                bridge.native_states[number] = (phase, 1, 0, 0)
                if not bridge.incoming_queue(number, 'hits'):
                    bridge.queue_incoming_hit(number, 'hits', (11, 1, 1))
                self.assertFalse(bridge.apply_incoming_hit(client, None))
                self.assertEqual(len(bridge.incoming_queue(number, 'hits')), 1)
            bridge.native_states[number] = (1, 1, 0, 0)
            bridge.router.paused = True
            self.assertFalse(bridge.apply_incoming_hit(client, None))
            bridge.router.paused = False
            for phase in (4, 5):
                if not bridge.incoming_queue(number, 'hits'):
                    bridge.queue_incoming_hit(number, 'hits', (11, 1, 1))
                bridge.queue_incoming_hit(number, 'areas', (22, 2))
                bridge.native_states[number] = (phase, 1, 0, 0)
                with patch.object(bridge, 'sync_mirrors', return_value=False), \
                        patch.object(bridge, 'sync_chests', return_value=False):
                    bridge.before_batch(client, None)
                self.assertFalse(bridge.incoming_queue(number, 'hits'))
                self.assertFalse(bridge.incoming_queue(number, 'areas'))
            self.assertFalse(calls)
            self.assertEqual(bridge.hit_metrics[number, 'hits']['obsolete'], 2)

    def test_overflow_merges_same_attacker_without_losing_damage(self):
        # 0.0.12: an overloaded queue folds hits instead of dropping them.
        bridge, _, _, _ = self.bridge()
        for i in range(128):
            bridge.queue_incoming_hit(3, 'hits', (11, 1, i))
        bridge.queue_incoming_hit(3, 'hits', (11, 1, 128))
        queue = bridge.hit_queues[3]
        self.assertEqual(len(queue), 128)
        self.assertEqual(sum(hit[1] for hit in queue), 129)  # No damage lost.
        self.assertEqual(queue[0], (11, 2, 0))  # Oldest pair folded at the older hit's place and clock.
        self.assertEqual(queue[-1][2], 128)
        self.assertEqual(len(bridge.hit_metadata[(3, 'hits')]), 128)
        rows = [json.loads(row) for row in bridge.output.getvalue().splitlines()]
        merged = [r for r in rows if r['event'] == 'hit_queue_merged']
        self.assertEqual((merged[0]['player'], merged[0]['queue'], merged[0]['merged'], merged[0]['damage']),
                         (3, 'hits', 1, 1))
        self.assertFalse([r for r in rows if r['event'] == 'hit_queue_overflow'])
        self.assertEqual(bridge.hit_metrics[3, 'hits']['merged_damage'], 1)

    def test_overflow_preserves_guard_and_actionable_summary(self):
        bridge, _, _, _ = self.bridge()
        for i in range(128):
            bridge.queue_incoming_hit(3, 'hits', (1000 + i, 1, i))  # Nothing to merge: all attackers differ.
        # Last resort (decision 15.10.2026): keep the newest 128 instead of ending the session.
        bridge.queue_incoming_hit(3, 'hits', (2000, 1, 128))
        event = json.loads(bridge.output.getvalue().splitlines()[-1])
        self.assertEqual((event['player'], event['queue'], event['attempted_length'], event['dropped']),
                         (3, 'hits', 129, 1))
        self.assertEqual(len(bridge.hit_queues[3]), 128)
        self.assertEqual((bridge.hit_queues[3][0][2], bridge.hit_queues[3][-1][2]), (1, 128))
        self.assertEqual(len(bridge.hit_metadata[(3, 'hits')]), 128)
        summary = next(q for q in event['diagnostics']['incoming_hits'] if q['player'] == 3 and q['queue'] == 'hits')
        self.assertEqual(summary['high_water'], 128)
        self.assertEqual(summary['phase'], 1)

    def write(self, bridge, client, limit=200):
        """One native queue write: retry before_batch until it lets the write proceed."""
        for _ in range(limit):
            if not bridge.before_batch(client, bytearray(1232)):
                break
        bridge.hit_batch_written(client.number)

    def test_one_write_applies_up_to_the_chain_limit(self):
        from visibility_bridge import HITS_PER_BATCH
        bridge, client, calls, memory = self.bridge()
        struct.pack_into('<f', memory, game_field(0x4A0), 100000)
        with patch('visibility_bridge.HIT_CHAIN_SECONDS', 60), \
                patch.object(bridge, 'sync_mirrors', return_value=False), \
                patch.object(bridge, 'sync_chests', return_value=False):
            for i in range(30):
                bridge.queue_incoming_hit(3, 'hits', (11, 1, i))
            self.write(bridge, client)
            self.assertEqual(len(calls), HITS_PER_BATCH)
            self.write(bridge, client)
        self.assertEqual(len(calls), 30)
        stats = bridge.hit_batch_stats[3]
        self.assertEqual((stats[0], stats[1], stats[2]), (2, 30, HITS_PER_BATCH))

    def burst(self, interleaved):
        bridge, client, calls, memory = self.bridge()
        struct.pack_into('<f', memory, game_field(0x4A0), 10 ** 9)
        sent = []
        with patch('visibility_bridge.HIT_CHAIN_SECONDS', 60), \
                patch.object(bridge, 'sync_mirrors', return_value=False), \
                patch.object(bridge, 'sync_chests', return_value=False):
            for i in range(500):
                hit = (100 + i % 7, 10 + (i * 37) % 90, i / 10)
                sent.append(hit)
                bridge.queue_incoming_hit(3, 'hits', hit)
                if interleaved and i % 20 == 19:
                    self.write(bridge, client)
            for _ in range(100):
                self.write(bridge, client)
        rows = [json.loads(row) for row in bridge.output.getvalue().splitlines()]
        return bridge, calls, sent, rows

    def test_burst_of_500_hits_applies_all_damage_in_order(self):
        bridge, calls, sent, rows = self.burst(interleaved=True)
        self.assertEqual([(a, d) for a, d, _, _ in calls], [hit[:2] for hit in sent])  # Same order.
        self.assertEqual(sum(c[1] for c in calls), sum(h[1] for h in sent))
        self.assertFalse([r for r in rows if r['event'] in ('hit_queue_overflow', 'hit_queue_merged')])
        self.assertFalse(bridge.hit_queues[3])

    def test_burst_of_500_at_once_merges_but_never_drops(self):
        bridge, calls, sent, rows = self.burst(interleaved=False)
        self.assertEqual(sum(c[1] for c in calls), sum(h[1] for h in sent))  # All damage applied.
        self.assertLess(len(calls), 500)  # Folded hits were applied as fewer, larger hits.
        self.assertTrue([r for r in rows if r['event'] == 'hit_queue_merged'])
        self.assertFalse([r for r in rows if r['event'] == 'hit_queue_overflow'])
        self.assertEqual(bridge.hit_metrics[3, 'hits']['high_water'], 128)
        self.assertTrue(all(c[1] <= 100000 for c in calls))
        first_seen = []
        for attacker, _, _, _ in calls:
            if attacker not in first_seen:
                first_seen.append(attacker)
        self.assertEqual(first_seen, [100 + i for i in range(7)])  # Attackers keep their arrival order.

    def test_merging_respects_the_native_hit_maximum(self):
        from play_limits import MAX_HIT_DAMAGE as M
        bridge, _, _, _ = self.bridge()
        for i in range(128):
            bridge.queue_incoming_hit(3, 'hits', (11, .6 * M, i))
        bridge.queue_incoming_hit(3, 'hits', (11, .6 * M, 128))  # No pair fits under the maximum.
        rows = [json.loads(row) for row in bridge.output.getvalue().splitlines()]
        self.assertEqual([r['event'] for r in rows][-1], 'hit_queue_overflow')
        self.assertTrue(all(hit[1] <= M for hit in bridge.hit_queues[3]))
        bridge, _, _, _ = self.bridge()
        bridge.queue_incoming_hit(3, 'hits', (11, M - 10, 0))  # Too big to take more.
        for i in range(1, 128):
            bridge.queue_incoming_hit(3, 'hits', (11, 20, i))
        bridge.queue_incoming_hit(3, 'hits', (11, 20, 128))
        queue = bridge.hit_queues[3]
        self.assertEqual((queue[0], queue[1]), ((11, M - 10, 0), (11, 40, 1)))  # Newer pair folded instead.
        self.assertEqual(sum(hit[1] for hit in queue), M - 10 + 128 * 20)

    def test_chain_stops_cleanly_at_death_and_pause(self):
        bridge, client, calls, memory = self.bridge()
        original = client.call_before
        def lethal(context, rva, game, attacker, **kwargs):
            original(context, rva, game, attacker, **kwargs)
            if struct.unpack_from('<f', memory, game_field(0x4A0))[0] <= 0:
                bridge.native_states[3] = (4, 1, 0, 0)  # As read back by the next queue-write retry.
        client.call_before = lethal
        with patch('visibility_bridge.HIT_CHAIN_SECONDS', 60), \
                patch.object(bridge, 'sync_mirrors', return_value=False), \
                patch.object(bridge, 'sync_chests', return_value=False):
            for i in range(10):
                bridge.queue_incoming_hit(3, 'hits', (11, 300, i))
            self.write(bridge, client)
        self.assertEqual(len(calls), 4)  # 1000 health: the fourth hit is lethal, the chain ends.
        self.assertFalse(bridge.hit_queues[3])  # The dead life's remaining hits are obsolete.
        self.assertEqual(bridge.hit_metrics[3, 'hits']['obsolete'], 6)
        bridge, client, calls, memory = self.bridge()
        def pausing(context, rva, game, attacker, **kwargs):
            original_call(context, rva, game, attacker, **kwargs)
            bridge.router.paused = len(calls) == 3
        original_call = client.call_before
        client.call_before = pausing
        with patch('visibility_bridge.HIT_CHAIN_SECONDS', 60), \
                patch.object(bridge, 'sync_mirrors', return_value=False), \
                patch.object(bridge, 'sync_chests', return_value=False):
            for i in range(10):
                bridge.queue_incoming_hit(3, 'hits', (11, 1, i))
            self.write(bridge, client)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(bridge.hit_queues[3]), 7)  # Paused: kept for later, not dropped.

    def test_chain_and_merge_are_deterministic(self):
        def run():
            bridge, calls, sent, rows = self.burst(interleaved=False)
            stable = [{k: v for k, v in r.items() if k not in ('queued_seconds', 'diagnostics')} for r in rows
                      if r['event'] != 'hit_queue_merged']
            return calls, stable, list(bridge.hit_metrics[3, 'hits'].items())
        first, second = run(), run()
        self.assertEqual(first[0], second[0])
        self.assertEqual(first[1], second[1])
        self.assertEqual([kv for kv in first[2] if kv[0] != 'max_wait'], [kv for kv in second[2] if kv[0] != 'max_wait'])

    def test_completed_transition_deduplicates_and_rejects_midgame_new_hero(self):
        bridge, _, _, _ = self.bridge()
        bridge.completed_transition(3, 9)
        self.assertFalse(bridge.completed_players)
        bridge.native_states[3] = (5, 1, 0, 0)
        bridge.queue_incoming_hit(3, 'hits', (11, 1, 1))
        bridge.queue_incoming_hit(3, 'areas', (22, 2), 2)
        bridge.completed_transition(3, 9)
        bridge.completed_transition(3, 6)
        rows = [json.loads(row) for row in bridge.output.getvalue().splitlines()]
        self.assertEqual([row['action'] for row in rows if row['event'] == 'completed_run_transition'], ['new_hero'])
        self.assertFalse(bridge.hit_queues[3])
        self.assertFalse(bridge.areas_by_guest[3])
        retired = [row for row in rows if row['event'] == 'incoming_hits_obsolete']
        self.assertEqual([(row['queue'], row['reason']) for row in retired],
                         [('hits', 'run_transition'), ('areas', 'run_transition')])

    def test_remote_pending_entries_do_not_block_a_later_host_decision(self):
        bridge, _, _, _ = self.bridge()
        bridge.request_victory_action(8)
        bridge.request_victory_action(9)
        self.assertEqual(bridge.end_action['command'], 8)
        del bridge.end_pending[1]  # Only this native game is owned by the host process.
        bridge.request_victory_action(9)
        self.assertEqual(bridge.end_action, dict(sequence=2, command=9))

    def test_host_wire_preserves_mixed_order_and_uses_slot_three_queue(self):
        from group_online import GroupOnlineBridge
        class Wire:
            def __init__(self):
                self.sent = []
            def send(self, message):
                self.sent.append(message)
        with patch.dict(os.environ, COOP_PLAYERS='3'):
            wire = Wire()
            host = GroupOnlineBridge(io.StringIO(), 1, {3: wire})
            guest = GroupOnlineBridge(io.StringIO(), 3, {1: Wire()})
        host.other = 3
        host.queue_incoming_hit(3, 'hits', (11, 1, 1))
        host.queue_incoming_hit(3, 'areas', (22, 2), 2)
        host.queue_incoming_hit(3, 'hits', (33, 3, 3))
        saved = host._select_guest(3)
        host.send_state()
        host._restore_guest(3, saved)
        self.assertFalse(host.hit_queues[3])
        self.assertFalse(host.guest_hits)
        message = wire.sent[0]
        self.assertEqual(message['hit_order'], [['hits', 1], ['areas', 2], ['hits', 3]])
        guest.receive_peer(1, message)
        self.assertEqual(guest.hit_queues[3], [(11, 1, 1), (33, 3, 3)])
        self.assertEqual(guest.areas_by_guest[3], [(22, 2)])
        self.assertEqual([m[2] for m in guest.hit_metadata[3, 'hits']], [1, 3])

    def test_again_capture_waits_for_the_same_message_final_party_states(self):
        from group_online import GroupOnlineBridge
        class Wire:
            def __init__(self): self.sent = []
            def send(self, message): self.sent.append(message)
        with patch.dict(os.environ, COOP_PLAYERS='3'):
            wire = Wire()
            host = GroupOnlineBridge(io.StringIO(), 1, {3: wire})
            guest = GroupOnlineBridge(io.StringIO(), 3, {1: Wire()})
        host.other = 3
        host.native_states[1] = (4, 1, 0, 0)
        host.restart_requested = True
        host.send_state()
        message = dict(wire.sent[0], party={'2': dict(state=[4, 1, 0, 0], ready=False, loaded=False)})
        guest.templates[2] = b'existing template'
        guest.native_states = {1: (1, 1, 0, 0), 2: (1, 1, 0, 0), 3: (4, 1, 0, 0)}
        guest.receive_peer(1, message)
        rows = [json.loads(row) for row in guest.output.getvalue().splitlines()]
        self.assertEqual([r['action'] for r in rows if r['event'] == 'completed_run_transition'], ['again'])

    def test_host_captures_guest_initiated_again(self):
        from group_online import GroupOnlineBridge
        class Wire:
            def __init__(self): self.sent = []
            def send(self, message): self.sent.append(message)
        with patch.dict(os.environ, COOP_PLAYERS='3'):
            wire = Wire()
            host = GroupOnlineBridge(io.StringIO(), 1, {3: Wire()})
            guest = GroupOnlineBridge(io.StringIO(), 3, {1: wire})
        host.native_states = {n: (4, 1, 0, 0) for n in host.members}
        guest.native_states = dict(host.native_states)
        guest.restart_requested = True
        guest.send_state()
        host.receive_peer(3, wire.sent[0])
        rows = [json.loads(row) for row in host.output.getvalue().splitlines()]
        self.assertEqual([(r['player'], r['action']) for r in rows if r['event'] == 'completed_run_transition'], [(1, 'again')])
        outgoing = Wire()
        host.channel = outgoing
        host.other = 2
        host.send_state()
        self.assertTrue(outgoing.sent[0]['restart'], 'Host must forward guest Again to the remaining guest')

    def test_final_xp_menu_quiesces_without_consuming_talents_or_dropping_damage(self):
        bridge, client, _, _ = self.bridge()
        client.saved_context = None
        bridge.clients = {3: client}
        bridge.native_states[3] = (2, 5, 1, 1)
        bridge.pause_pending[3] = True
        self.assertTrue(bridge.finish_ready())
        self.assertNotIn(3, bridge.pause_pending)
        self.assertEqual(bridge.native_states[3], (2, 5, 1, 1))
        bridge.queue_incoming_hit(3, 'hits', (11, 1, 1))
        self.assertFalse(bridge.finish_ready())
        self.assertEqual(len(bridge.hit_queues[3]), 1)


if __name__ == '__main__':
    unittest.main()
