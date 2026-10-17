"""Automatic bootstrap tests cannot promote incomplete compatibility."""
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import build_hooks


class AutomaticObservationTests(unittest.TestCase):
    def test_disposable_test_cached_by_all_inputs_but_never_activates(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'reconstruction').mkdir()
            (root / 'relay').mkdir()
            for name in ('routing.py', 'client.py', 'server.py'):
                (root / 'relay' / name).write_text('# fixture')
            (root / 'reconstruction/reference-metadata.json').write_text('{}')
            analysis = root / 'analysis'
            analysis.mkdir()
            source = root / 'reconstruction/native_probe.py'
            source.write_text('# observer')
            binary = root / 'game.exe'
            binary.write_bytes(b'game')
            active = analysis / 'active-hooks.json'
            active.write_text('previous verified profile')
            def run(command, **kwargs):
                self.assertEqual(kwargs['env']['COOP_EXECUTABLE'], str(binary))
                log = Path(command[command.index('--observation-report') + 1])
                rows = [dict(event='observation_start', sha256=hashlib.sha256(binary.read_bytes()).hexdigest()),
                        dict(event='observation_hud_owner', server_matches=True, fields_match=True),
                        dict(event='observation_batch_layout', server_matches=True, connection_matches=True,
                             packet_arguments_match=True, ui_bounds_valid=True),
                        dict(event='observation_summary', batch_hits=1,
                             hits={name: 1 for name in ('TICK','SERIALIZE','WRITE','HUD_DELIVER')})]
                log.write_text('\n'.join(json.dumps(row) for row in rows))
                return SimpleNamespace(returncode=0)
            with patch.object(build_hooks, 'ROOT', root), patch.object(build_hooks.subprocess, 'run', side_effect=run) as execute:
                for _ in range(2):
                    result = build_hooks.test_observation_candidate(binary, analysis)
                    self.assertEqual(result['status'], 'passed')
                    self.assertFalse(result['automatic_activation_allowed'])
                    self.assertFalse(result['gameplay_verified'])
                self.assertEqual(execute.call_count, 1)
                # A bootstrap cache cannot satisfy the additional native calls,
                # even if a child incorrectly exits successfully without them.
                calls = build_hooks.test_observation_candidate(binary, analysis, candidate_calls=True)
                self.assertEqual(calls['status'], 'failed')
                self.assertEqual(execute.call_count, 2)
                source.write_text('# changed observer')
                build_hooks.test_observation_candidate(binary, analysis)
                self.assertEqual(execute.call_count, 3)
                binary.write_bytes(b'changed game')
                build_hooks.test_observation_candidate(binary, analysis)
                self.assertEqual(execute.call_count, 4)
            self.assertEqual(active.read_text(), 'previous verified profile')

    def test_missing_events_fail_even_when_child_returns_success(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'reconstruction').mkdir()
            (root / 'relay').mkdir()
            for name in ('routing.py', 'client.py', 'server.py'):
                (root / 'relay' / name).write_text('# fixture')
            (root / 'reconstruction/reference-metadata.json').write_text('{}')
            (root / 'analysis').mkdir()
            binary = root / 'game.exe'
            binary.write_bytes(b'game')
            with patch.object(build_hooks, 'ROOT', root), patch.object(build_hooks.subprocess, 'run',
                    return_value=SimpleNamespace(returncode=0, stderr='RuntimeError: Native title disagrees with current choice')):
                result = build_hooks.test_observation_candidate(binary, root / 'analysis')
                self.assertEqual(result['status'], 'failed')
                self.assertFalse(result['automatic_activation_allowed'])
                self.assertEqual(result['reason'], 'RuntimeError: Native title disagrees with current choice')


if __name__ == '__main__':
    unittest.main()
