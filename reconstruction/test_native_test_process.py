import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from native_test_process import run_verifier


@unittest.skipUnless(os.name == 'nt', 'Windows native acceptance runner')
class VerifierProcessTests(unittest.TestCase):
    def test_assertions_enabled_and_timeout_removes_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            script = home / 'verify.py'
            (home / 'sibling.py').write_text("value='assertions enabled'")
            script.write_text("import sibling; assert __debug__; print(sibling.value)")
            with (home / 'result.txt').open('w') as output:
                result = run_verifier([str(script)], cwd=home.parent, env=dict(os.environ, PYTHONOPTIMIZE='2'),
                                      stdout=output, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertIn('assertions enabled', (home / 'result.txt').read_text())
            script.write_text("import subprocess,sys,time,pathlib\n"
                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
                "pathlib.Path('child.pid').write_text(str(child.pid))\ntime.sleep(60)\n")
            orphan = home / 'orphan.py'
            orphan.write_text("import subprocess,sys\n"
                "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n")
            with (home / 'result.txt').open('w') as output:
                result = run_verifier([str(orphan)], cwd=home, env=os.environ, stdout=output, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('live descendants', (home / 'result.txt').read_text())
            with (home / 'result.txt').open('w') as output, self.assertRaises(subprocess.TimeoutExpired):
                run_verifier([str(script)], cwd=home, env=os.environ, stdout=output, timeout=1)
            pid = int((home / 'child.pid').read_text())
            kernel = C.WinDLL('kernel32', use_last_error=True)
            kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
            kernel.OpenProcess.restype = W.HANDLE
            kernel.GetExitCodeProcess.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
            kernel.CloseHandle.argtypes = [W.HANDLE]
            handle = kernel.OpenProcess(0x1000, False, pid)
            if handle:
                try:
                    code = W.DWORD()
                    self.assertTrue(kernel.GetExitCodeProcess(handle, C.byref(code)))
                    self.assertNotEqual(code.value, 259, 'Descendant still active after timeout')
                finally:
                    kernel.CloseHandle(handle)


if __name__ == '__main__':
    unittest.main()
