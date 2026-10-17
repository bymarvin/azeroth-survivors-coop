"""Debugger exit events must retire dead memory without stopping other guests."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_probe


class NativeShutdownTests(unittest.TestCase):
    def test_native_child_disables_debug_heap_without_disabling_debugger(self):
        process = SimpleNamespace(pid=123, poll=lambda: 0)
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'_NO_DEBUG_HEAP': '0'}), \
                patch.object(native_probe, '_candidate_home', None), \
                patch.object(native_probe, 'EXECUTABLE', SimpleNamespace(read_bytes=lambda: b'')), \
                patch.object(native_probe, 'ACTIVE_HASH', hashlib.sha256(b'').hexdigest()), \
                patch.object(native_probe.subprocess, 'Popen', return_value=process) as launch:
            client = native_probe.Native(1, profile_folder=directory)
            try:
                self.assertEqual(launch.call_args.kwargs['env']['_NO_DEBUG_HEAP'], '1')
                self.assertEqual(os.environ['_NO_DEBUG_HEAP'], '0')
                self.assertTrue(launch.call_args.kwargs['creationflags'] & 2)  # DEBUG_ONLY_THIS_PROCESS
            finally:
                client.stop()

    def test_diagnostic_executable_uses_verified_profile_without_replacing_active_report(self):
        root = Path(__file__).resolve().parents[1]
        from build_hooks import UPDATED_HASH
        baseline = root / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        active = root / 'analysis/active-hooks.json'
        before = active.read_bytes()
        result = subprocess.run(
            [sys.executable, '-c', 'import native_probe as n; print(n.ACTIVE_HASH); print(n.EXECUTABLE)'],
            cwd=root / 'reconstruction', capture_output=True, text=True, check=True,
            env={**os.environ, 'COOP_BUILD': 'updated', 'COOP_EXECUTABLE': str(baseline)})
        self.assertEqual(result.stdout.splitlines(), [UPDATED_HASH, str(baseline)])
        self.assertEqual(active.read_bytes(), before)
        report = json.loads((root / 'analysis/diagnostic-hooks/active-hooks.json').read_text())
        self.assertEqual(report['sha256'], UPDATED_HASH)
        self.assertTrue(report['automatic_activation_allowed'])

    def test_diagnostic_report_directory_still_rejects_unverified_build(self):
        from build_hooks import resolve_reviewed_profile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'reconstruction').mkdir()
            (root / 'reconstruction/reviewed-hooks.json').write_text('{}')
            blocked = dict(automatic_activation_allowed=False, sha256='unknown')
            with patch('build_hooks.ROOT', root), patch('build_hooks.compatibility_report', return_value=blocked), patch('build_hooks.probe_identity', return_value={}):
                with self.assertRaises(ValueError):
                    resolve_reviewed_profile('unknown.exe', developer_discovery=True, report_directory=root / 'diagnostic')
            self.assertEqual(json.loads((root / 'diagnostic/updated-hook-discovery.json').read_text()), blocked)
            self.assertFalse((root / 'diagnostic/active-hooks.json').exists())
            self.assertFalse((root / 'analysis/active-hooks.json').exists())

    def test_diagnostic_run_skips_unrelated_root_audit(self):
        root = Path(__file__).resolve().parents[1]
        with patch.object(native_probe, '_diagnostic_executable', 'selected.exe'), \
                patch.object(native_probe.subprocess, 'run') as audit:
            native_probe.run(0, 0, SimpleNamespace())
        audit.assert_not_called()

    def test_report_retries_transient_windows_sharing_failure(self):
        from build_hooks import write_report
        with tempfile.TemporaryDirectory() as directory, patch('build_hooks.time.sleep') as sleep:
            destination = Path(directory) / 'report.json'
            original_replace = Path.replace
            calls = []
            def replace(source, target):
                calls.append(target)
                if len(calls) < 3:
                    raise PermissionError('Windows sharing violation')
                return original_replace(source, target)
            with patch.object(Path, 'replace', replace):
                write_report(destination, {'verified': True})
            self.assertEqual(json.loads(destination.read_text()), {'verified': True})
            self.assertEqual(len(calls), 3)
            self.assertEqual(sleep.call_count, 2)

    def test_report_retry_is_bounded_and_preserves_original_failure(self):
        from build_hooks import write_report
        first = PermissionError('original Windows sharing violation')
        with tempfile.TemporaryDirectory() as directory, patch('build_hooks.time.sleep') as sleep:
            destination = Path(directory) / 'report.json'
            with patch.object(Path, 'replace', side_effect=[first] + [PermissionError('later')] * 5) as replace:
                with self.assertRaises(PermissionError) as raised:
                    write_report(destination, {})
            self.assertIs(raised.exception, first)
            self.assertEqual(replace.call_count, 6)
            self.assertEqual(sleep.call_count, 5)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def run_exits(self, order, stop_on_host=False, failure=None, guard=False):
        instances, notified, continued, cleanup = {}, [], [], []
        callback = SimpleNamespace(clients={}, stop_requested=False, record=lambda **event: None)
        def native_exited(client, code):
            self.assertNotIn(client.number, callback.clients)
            self.assertTrue(client.exited)
            self.assertIn(client.number, continued)  # EXIT_PROCESS continued first.
            notified.append((client.number, code))
            if stop_on_host and client.number == 1:
                callback.stop_requested = True
        callback.native_exited = native_exited
        def finish_ready():
            self.assertTrue(all(not getattr(c, 'exited', False) for c in callback.clients.values()))
            return True
        callback.finish_ready = finish_ready
        class Client:
            def __init__(self, number, **kwargs):
                self.number = number
                self.base = 0
                self.dispatch_guard_traps = {0x123456: 'cast_tag'} if guard else {}
                self.code = None
                self.process = SimpleNamespace(pid=number, poll=lambda: self.code, wait=lambda timeout: self.code)
                instances[number] = self
                callback.clients[number] = self
            def stop(self):
                cleanup.append(self.number)
                self.code = 0
        events = iter(order)
        def wait(event, timeout):
            number, code = next(events)
            if len(notified) < len(continued):
                raise AssertionError('Departure was not reported before another event')
            struct.pack_into('<III', event, 0, 1 if guard else 5, number, number)
            struct.pack_into('<I', event, 16, code)
            if guard:
                struct.pack_into('<Q', event, 32, 0x123456)
            return True
        def cont(pid, tid, status):
            continued.append(pid)
            instances[pid].code = 0
            return True
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(native_probe, 'ROOT', Path(folder)), \
                patch.object(native_probe, 'EXECUTABLE', SimpleNamespace(read_bytes=lambda: b'')), \
                patch.object(native_probe, 'ACTIVE_HASH', hashlib.sha256(b'').hexdigest()), \
                patch.object(native_probe, 'BUILD', 'legacy'), \
                patch.object(native_probe, 'Native', Client), \
                patch.object(native_probe, 'wait', wait), patch.object(native_probe, 'cont', cont):
            if failure is None:
                native_probe.run(360, 2, callback)
            else:
                with self.assertRaisesRegex(RuntimeError, failure):
                    native_probe.run(360, 2, callback)
        self.assertEqual(cleanup, [1, 2])
        return notified

    def test_undrained_shutdown_records_counters_and_fails_after_cleanup(self):
        from itertools import count
        events, stopped = [], []
        class Client:
            def __init__(self, number, **kwargs):
                self.number = number
                self.process = SimpleNamespace(pid=number, poll=lambda: 0, wait=lambda timeout: 0)
            def stop(self): stopped.append(self.number)
        callback = SimpleNamespace(finish_ready=lambda: False, record=lambda **event: events.append(event),
                                   counts={'world_captured': 3, 'world_delivered': 2},
                                   native_states={1: (3, 1, 0, 0)}, pause_pending={})
        clock = count(0, 10)
        with patch.object(native_probe, 'Native', Client), \
                patch.object(native_probe, 'EXECUTABLE', SimpleNamespace(read_bytes=lambda: b'')), \
                patch.object(native_probe, 'ACTIVE_HASH', hashlib.sha256(b'').hexdigest()), \
                patch.object(native_probe, 'BUILD', 'legacy'), \
                patch.object(native_probe.time, 'monotonic', side_effect=lambda: next(clock)):
            with self.assertRaisesRegex(TimeoutError, 'did not drain'):
                native_probe.run(0, 1, callback)
        self.assertEqual(stopped, [1])
        final = next(e for e in events if e['event'] == 'shutdown_drain_finished')
        self.assertFalse(final['ready'])
        self.assertEqual(final['counters'], callback.counts)
        self.assertGreater(final['elapsed'], 0)

    def test_clean_guest_exit_continues_host(self):
        self.assertEqual(self.run_exits([(2, 0), (1, 0)]), [(2, 0), (1, 0)])

    def test_host_exit_notifies_before_survivor_shutdown(self):
        self.assertEqual(self.run_exits([(1, 0)], stop_on_host=True), [(1, 0)])

    def test_crash_is_reported_after_retiring_dead_memory_and_cleaning_up(self):
        self.assertEqual(self.run_exits([(2, 42)], failure='Client 2 exited: 42'), [(2, 42)])

    def test_dispatch_guard_trap_reports_contract_and_cleans_up(self):
        self.assertEqual(self.run_exits([(2, 0xC000001D)], guard=True,
            failure='native cast_tag compatibility guard failed'), [])


if __name__ == '__main__':
    unittest.main()
