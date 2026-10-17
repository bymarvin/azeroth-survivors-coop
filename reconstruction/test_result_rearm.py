"""Map unlock and class XP after a fall in co-op (native run evaluation, offline with a fake client).

Native 7264: TICK runs the result function 0x542d270 once per new phase 4/5 (phase != Server+0xfbc), so also
when a co-op player falls. Every call credits class XP for the whole run so far (0x5414de0 on the account
table, victory bonus with Game+0x858); the map unlock behind it runs once per run (lock Server+0xfba). A revived
player won no map at the victory and got the XP up to the fall twice. Bridge.rearm_result opens the lock, takes
back the fall credit and clears the last evaluated phase: the real end credits the whole run once.
User: "its important that downed people still get the exp so they dont fall behind the other people".
"""
import io
import os
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from native_probe import AWARD_XP, RESUME, game_field
from sessions import Pose
from updated_layout import RESULT_EVALUATION
from visibility_bridge import Bridge

LAYOUT = RESULT_EVALUATION['7264']
SERVER, TABLE = 0x100000, 0x900000
CLASS, OTHER, BONUS = 3, 5, 200


class Memory:
    """Sparse process memory: the fake client reads and writes bytes like the real one."""

    def __init__(self):
        self.bytes = {}

    def read(self, address, size):
        return bytes(self.bytes.get(address + i, 0) for i in range(size))

    def put(self, address, data):
        for i, value in enumerate(data):
            self.bytes[address + i] = value


class NativeRun:
    """The native game of one player: class XP table, run class, victory flag, TICK's run evaluation."""

    def __init__(self, memory, entries=((CLASS, 1000), (OTHER, 50))):
        self.memory = memory
        self.accounts(entries)
        memory.put(SERVER + LAYOUT['class_id'], bytes([CLASS]))
        self.unlocks = 0

    def accounts(self, entries):
        base = SERVER + LAYOUT['account']
        self.memory.put(base + 0x68, struct.pack('<QQ', TABLE, len(entries)))
        for i, (cls, xp) in enumerate(entries):
            self.memory.put(TABLE + i * 32, struct.pack('<I', xp) + bytes([cls]))

    def xp(self):
        count = struct.unpack('<Q', self.memory.read(SERVER + LAYOUT['account'] + 0x70, 8))[0]
        return {self.memory.read(TABLE + i * 32 + 4, 1)[0]: struct.unpack('<I', self.memory.read(TABLE + i * 32, 4))[0]
                for i in range(count)}

    def byte(self, key):
        return self.memory.read(SERVER + LAYOUT[key], 1)[0]

    def tick(self, phase, run_xp, victory=False):
        """TICK: evaluate a new phase 4/5 once; credit the run (+ victory bonus), unlock once per run."""
        if victory:
            self.memory.put(SERVER + LAYOUT['victory'], struct.pack('<I', 1))
        if phase not in (4, 5) or phase == self.byte('last_phase'):
            return False
        self.memory.put(SERVER + LAYOUT['last_phase'], bytes([phase]))
        cls = self.byte('class_id')
        count = struct.unpack('<Q', self.memory.read(SERVER + LAYOUT['account'] + 0x70, 8))[0]
        for i in range(count):
            if self.memory.read(TABLE + i * 32 + 4, 1)[0] == cls:
                old = struct.unpack('<I', self.memory.read(TABLE + i * 32, 4))[0]
                self.memory.put(TABLE + i * 32, struct.pack('<I', old + run_xp + (BONUS if victory else 0)))
        if self.byte('lock') == 0:
            self.memory.put(SERVER + LAYOUT['lock'], b'\x01')
            self.unlocks += bool(victory)
        return True


class ResultRearmTests(unittest.TestCase):
    def setUp(self):
        self.layout = patch('visibility_bridge.result_evaluation', return_value=LAYOUT)
        self.layout.start()
        self.addCleanup(self.layout.stop)

    def player(self, number=2):
        memory = Memory()
        events = io.StringIO()
        with patch.dict(os.environ, COOP_PLAYERS='2'):
            from native_guest_combat import NativeCombatBridge
            bridge = NativeCombatBridge(events, shared_world=True)
        calls = []
        client = SimpleNamespace(number=number, server=SERVER, memory=memory.read, put=memory.put,
                                 call_before=lambda *args, **kwargs: calls.append((args, kwargs)))
        return bridge, client, NativeRun(memory), events, calls

    def fall_and_revive(self, bridge, client, run, run_xp):
        self.assertTrue(run.tick(4, run_xp))                    # The fall: native evaluation without victory.
        bridge.rearm_result(client, 'revival')

    def won_without_falling(self, run_values):
        bridge, client, run, _, _ = self.player()
        bridge.remember_result_xp(client)
        self.assertTrue(run.tick(5, run_values[-1], victory=True))
        return run.xp(), run.unlocks

    def test_one_and_three_falls_then_victory_equal_a_victory_without_falls(self):
        for falls in ((40,), (40, 70, 95)):
            with self.subTest(falls=len(falls)):
                bridge, client, run, events, _ = self.player()
                bridge.remember_result_xp(client)               # Run start.
                for run_xp in falls:
                    self.fall_and_revive(bridge, client, run, run_xp)
                    self.assertEqual(run.xp(), {CLASS: 1000, OTHER: 50})  # Back to the start value.
                    self.assertEqual((run.byte('lock'), run.byte('last_phase')), (0, 0))
                self.assertTrue(run.tick(5, 120, victory=True))
                self.assertEqual((run.xp(), run.unlocks), self.won_without_falling(falls + (120,)))
                self.assertEqual(run.xp()[CLASS], 1000 + 120 + BONUS)  # Full run values and the victory bonus.

    def test_revival_through_sync_revival_rearms_before_resume(self):
        bridge, client, run, _, calls = self.player()
        bridge.remember_result_xp(client)
        run.tick(4, 40)
        bridge.router.add_player(0xFF0101, '1', Pose(0, 0, 0, 0))
        bridge.router.add_player(0xFF0102, '2', Pose(1, 0, 0, 0))
        bridge.native_states = {1: (1, 5, 0, 0), 2: (4, 5, 0, 0)}
        bridge.revive_progress[2] = (3.0, bridge.host_clock)
        bridge.revive_status[2] = 'in_range'
        run.memory.put(SERVER + 0x10 + game_field(0x4F8), struct.pack('<f', 200.0))
        self.assertTrue(bridge.sync_revival(client, None))
        self.assertEqual(calls[-1][0][1], RESUME)
        self.assertEqual((run.byte('lock'), run.byte('last_phase'), run.xp()[CLASS]), (0, 0, 1000))

    def test_downed_at_the_victory_gets_the_full_credit_with_bonus(self):
        bridge, client, run, _, _ = self.player()
        bridge.remember_result_xp(client)
        run.tick(4, 25)                                         # Still down when the host wins.
        bridge.shared_victory(client)
        self.assertEqual(run.memory.read(SERVER + 0x10 + game_field(0x8BF), 1), b'\x01')
        self.assertTrue(run.tick(5, 120, victory=True))
        self.assertEqual((run.xp(), run.unlocks), self.won_without_falling((120,)))

    def test_team_defeat_after_falls_credits_once(self):
        bridge, client, run, _, _ = self.player()
        bridge.remember_result_xp(client)
        self.fall_and_revive(bridge, client, run, 40)
        self.assertTrue(run.tick(4, 80))                        # Final fall, nobody left to revive.
        self.assertEqual(run.xp()[CLASS], 1080)
        self.assertEqual(run.unlocks, 0)

    def test_run_left_after_a_revival_keeps_the_fall_credit_once(self):
        bridge, client, run, events, _ = self.player()
        bridge.remember_result_xp(client)
        self.fall_and_revive(bridge, client, run, 40)
        self.assertEqual(run.xp()[CLASS], 1000)
        bridge.draining = True
        bridge.keep_open_result(client)
        bridge.keep_open_result(client)                         # Every drained batch: still only once.
        self.assertEqual(run.xp(), {CLASS: 1040, OTHER: 50})
        self.assertIn('result_open_credit_kept', events.getvalue())

    def test_victory_after_revival_needs_no_open_credit(self):
        bridge, client, run, _, _ = self.player()
        bridge.remember_result_xp(client)
        self.fall_and_revive(bridge, client, run, 40)
        run.tick(5, 120, victory=True)
        bridge.keep_open_result(client)                         # Drain after the victory: nothing added.
        self.assertEqual(run.xp()[CLASS], 1000 + 120 + BONUS)

    def test_victory_continue_keeps_the_won_xp(self):
        bridge, client, run, _, _ = self.player()
        bridge.remember_result_xp(client)
        run.tick(5, 90, victory=True)
        run.memory.put(SERVER + LAYOUT['victory'], bytes(4))   # "Keep fighting": playing on.
        bridge.remember_result_xp(client)                       # 5 -> 1 takes a new snapshot.
        self.fall_and_revive(bridge, client, run, 100)
        self.assertEqual(run.xp()[CLASS], 1000 + 90 + BONUS)

    def test_nothing_written_unless_only_the_fall_evaluation_changed_the_account(self):
        cases = {
            'account_changed_otherwise': lambda run: run.accounts(((CLASS, 1040), (OTHER, 60))),
            'not_a_fall_evaluation': lambda run: run.memory.put(SERVER + LAYOUT['last_phase'], b'\x05'),
            'no_snapshot': None,
        }
        for reason, change in cases.items():
            with self.subTest(reason=reason):
                bridge, client, run, events, _ = self.player()
                if change is not None:
                    bridge.remember_result_xp(client)
                run.tick(4, 40)
                if change is not None:
                    change(run)
                before = run.xp()
                bridge.rearm_result(client, 'revival')
                bridge.rearm_result(client, 'revival')
                self.assertEqual(run.xp(), before)
                self.assertEqual(run.byte('lock'), 0)           # The map unlock is reopened in any case.
                self.assertNotEqual(run.byte('last_phase'), 0)  # A later fall is not evaluated again.
                self.assertEqual(events.getvalue().count('"result_xp_kept"'), 1)
                self.assertIn(reason, events.getvalue())

    def test_only_the_current_class_entry_is_written(self):
        bridge, client, run, _, _ = self.player()
        bridge.remember_result_xp(client)
        run.accounts(((CLASS, 1000), (OTHER, 50), (7, 0)))
        run.memory.put(SERVER + LAYOUT['class_id'], b'\x07')    # First run of class 7: entry created by the fall.
        run.tick(4, 30)
        self.assertEqual(run.xp()[7], 30)
        bridge.rearm_result(client, 'revival')
        self.assertEqual(run.xp(), {CLASS: 1000, OTHER: 50, 7: 0})

    def test_unsupported_build_writes_nothing(self):
        bridge, client, run, events, _ = self.player()
        self.layout.stop()
        with patch('visibility_bridge.result_evaluation', return_value=None):
            run.tick(4, 40)
            before = dict(run.memory.bytes)
            bridge.remember_result_xp(client)
            bridge.rearm_result(client, 'revival')
            self.assertEqual(run.memory.bytes, before)
        self.layout.start()
        self.assertIn('unsupported_build', events.getvalue())

    def test_run_xp_reaches_a_downed_guest(self):
        bridge, client, run, events, calls = self.player(number=2)
        bridge.xp_pending = 75                                  # Host kills while the guest is down.
        self.assertTrue(bridge.mirror_xp(client, None, 4))
        self.assertEqual(calls[-1][0][1:], (AWARD_XP, SERVER + 0x10, 75))
        self.assertEqual(bridge.xp_pending, 0)
        self.assertFalse(bridge.mirror_xp(client, None, 5))     # Nothing left; a finished run gets none.

    def test_offsets_per_build(self):
        self.assertEqual({k: v and (v['lock'], v['last_phase'], v['account'], v['class_id'], v['victory'])
                          for k, v in RESULT_EVALUATION.items()},
                         {'0843': (0xDFA, 0xDFC, 0x940, 0x35C, 0x820), '47e4': (0xFA2, 0xFA4, 0x9A8, 0x294, 0x868),
                          '0931': (0xFBA, 0xFBC, 0x9A8, 0x294, 0x868), '7264': (0xFBA, 0xFBC, 0x9A8, 0x294, 0x868),
                          'reviewed': None})


if __name__ == '__main__':
    unittest.main()
