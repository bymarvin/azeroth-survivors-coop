"""Room-only breakpoint dependencies must be captured before candidate activation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


class NativeInventoryTests(unittest.TestCase):
    def test_offline_inventory_runs_under_parent_resolver_lock(self):
        import msvcrt
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ, COOP_CANDIDATE_PROFILE='must-not-load.json',
                           COOP_CANDIDATE_HOME='must-not-use')
        environment['PYTHONPATH'] = os.pathsep.join(str(root / p) for p in ('.tools/python', 'analysis', 'reconstruction'))
        with (root / 'analysis/compatibility-resolver.lock').open('a+b') as lock:
            if lock.seek(0, 2) == 0:
                lock.write(b'0')
                lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            try:
                result = subprocess.run([sys.executable, '-c',
                    'import json; from inventory_native_contracts import runtime_inputs; r=runtime_inputs(); '
                    'import native_probe,build_hooks; '
                    'assert native_probe.resolve_reviewed_profile is build_hooks.resolve_reviewed_profile; '
                    'print(json.dumps({k:len(r[k]) for k in ("addresses","fields","patches")}))'],
                    cwd=root, env=environment, capture_output=True, text=True, check=True, timeout=30)
            finally:
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        self.assertEqual(json.loads(result.stdout), dict(addresses=95, fields=70, patches=39))

    def test_room_map_hook_is_a_required_patch_precondition(self):
        root = Path(__file__).resolve().parents[1]
        environment = {k: v for k, v in os.environ.items() if not k.startswith('COOP_CANDIDATE_')}
        environment['PYTHONPATH'] = os.pathsep.join(str(root / p) for p in ('.tools/python', 'analysis', 'reconstruction'))
        result = subprocess.run([sys.executable, '-c',
            'import json; from inventory_native_contracts import runtime_inputs; print(json.dumps(runtime_inputs()))'],
            cwd=root, env=environment, capture_output=True, text=True, check=True, timeout=30)
        inventory = json.loads(result.stdout)
        manifest = json.loads((root / 'reconstruction/reviewed-hooks.json').read_text())
        address = manifest['hooks']['MAP_SELECT']['reference_rva']
        self.assertIn([address, '55'], inventory['patches'])


if __name__ == '__main__':
    unittest.main()
