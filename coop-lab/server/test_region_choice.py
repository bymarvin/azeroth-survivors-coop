"""Region choice at co-op start (coop_launcher.py), boot-log format.

Unit checks of the question (EU/US, remembered, Enter, timeout, invalid keys, arguments,
COOP_REGION, explicit URL, no console) and a real "cmd /c Start-Coop.cmd" run in a
temporary folder whose room browser is a stub that only records the directory URL.

  python test_region_choice.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import coop_launcher as launcher  # noqa: E402

EU, US = launcher.REGIONS['eu'][1], launcher.REGIONS['us'][1]


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def keys(*sequence):
    """read_key stub: None means 'no key in this poll'."""
    items = list(sequence)
    return lambda: items.pop(0) if items else None


class ChoiceTests(unittest.TestCase):
    def choose(self, default, *pressed, seconds=5):
        clock, lines = Clock(), []
        result = launcher.choose_region(default, keys(*pressed), measured=dict(eu=31, us=None), seconds=seconds,
                                        now=clock.now, sleep=clock.sleep, write=lines.append)
        return result, clock.t, lines

    def test_keys_select_eu_or_us(self):
        self.assertEqual(self.choose('eu', '2')[0], ('us', 'key'))
        self.assertEqual(self.choose('us', '1')[0], ('eu', 'key'))
        self.assertEqual(self.choose('eu', 'U')[0], ('us', 'key'))

    def test_enter_and_timeout_keep_the_last_choice(self):
        self.assertEqual(self.choose('us', '\r')[0], ('us', 'enter'))
        (region, how), waited, lines = self.choose('us')
        self.assertEqual((region, how), ('us', 'timeout'))
        self.assertAlmostEqual(waited, 5, delta=.1)
        self.assertIn('<- last choice', next(l for l in lines if '[2]' in l))
        self.assertIn('31 ms', next(l for l in lines if '[1]' in l))
        self.assertIn('not reachable', next(l for l in lines if '[2]' in l))

    def test_invalid_keys_warn_and_keep_waiting(self):
        (region, how), _, lines = self.choose('eu', 'x', None, '7', '2')
        self.assertEqual((region, how), ('us', 'key'))
        self.assertEqual(sum('[ WARN ]' in l for l in lines), 2)
        (region, how), waited, _ = self.choose('eu', 'x')  # Invalid, then nothing: still times out.
        self.assertEqual((region, how, round(waited)), ('eu', 'timeout', 5))


class ResolveTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix='region-test-'))
        self.addCleanup(shutil.rmtree, self.folder, True)

    def resolve(self, argument=None, option=None, interactive=False, environment=None, *pressed):
        asked = []
        def measure():
            asked.append(True)
            return {}
        clock = Clock()
        result = launcher.resolve_directory(argument, option, self.folder, interactive=interactive,
                                            read_key=keys(*pressed), measure=measure, environment=environment or {},
                                            write=lambda line: None, now=clock.now, sleep=clock.sleep)
        return result, bool(asked)

    def test_default_is_eu_and_choices_are_remembered(self):
        self.assertEqual(self.resolve(), ((EU, 'eu', 'remembered'), False))  # No console: no waiting.
        self.assertEqual(self.resolve(None, None, True, None, '2'), ((US, 'us', 'key'), True))
        self.assertEqual((self.folder / launcher.REGION_FILE).read_text().strip(), 'us')
        self.assertEqual(self.resolve(), ((US, 'us', 'remembered'), False))
        self.assertEqual(self.resolve(None, None, True, None, '\r')[0], (US, 'us', 'enter'))

    def test_arguments_and_environment_override_without_asking(self):
        self.assertEqual(self.resolve('us', None, True), ((US, 'us', 'argument'), False))
        self.assertEqual(self.resolve('EU', None, True), ((EU, 'eu', 'argument'), False))
        self.assertEqual(self.resolve(None, 'us', True), ((US, 'us', 'argument'), False))
        self.assertEqual(self.resolve(None, None, True, dict(COOP_REGION='eu')), ((EU, 'eu', 'argument'), False))
        self.assertEqual((self.folder / launcher.REGION_FILE).read_text().strip(), 'eu')

    def test_explicit_url_is_used_as_is_and_not_remembered(self):
        (self.folder / launcher.REGION_FILE).write_text('us\n')
        self.assertEqual(self.resolve('http://127.0.0.1:47770', None, True), (('http://127.0.0.1:47770', None, 'url'), False))
        self.assertEqual((self.folder / launcher.REGION_FILE).read_text().strip(), 'us')

    def test_damaged_or_unwritable_memory_falls_back_to_eu(self):
        (self.folder / launcher.REGION_FILE).write_text('mars\n')
        self.assertEqual(self.resolve()[0], (EU, 'eu', 'remembered'))

    def test_latency_of_an_unreachable_directory_is_none(self):
        self.assertIsNone(launcher.latency_ms('https://127.0.0.1:1', timeout=.3))


class StartCoopTests(unittest.TestCase):
    """Real Start-Coop.cmd -> coop_launcher.py chain (no console input, stub room browser)."""
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix='start-coop-region-'))
        self.addCleanup(shutil.rmtree, self.folder, True)
        shutil.copyfile(ROOT / 'Start-Coop.cmd', self.folder / 'Start-Coop.cmd')
        shutil.copyfile(ROOT / 'coop_launcher.py', self.folder / 'coop_launcher.py')
        (self.folder / 'COOP-VERSION.txt').write_text('test')
        (self.folder / 'reconstruction').mkdir()
        (self.folder / 'reconstruction/room_client.py').write_text(
            'import sys, pathlib\n'
            'args = sys.argv[1:]\n'
            "pathlib.Path(__file__).with_name('started.txt').write_text(args[args.index('--directory') + 1])\n")
        runtime = Path(os.environ.get('COOP_TEST_RUNTIME', ROOT / '.coop-runtime'))
        if not runtime.is_dir():
            runtime = Path(sys.executable).parent
        subprocess.run(['cmd', '/c', 'mklink', '/J', str(self.folder / '.coop-runtime'), str(runtime)],
                       check=True, capture_output=True)
        # Cleanups run last-in first-out: drop only the link before the folder is deleted.
        self.addCleanup(os.rmdir, self.folder / '.coop-runtime')

    def start(self, *arguments):
        (self.folder / 'reconstruction/started.txt').unlink(missing_ok=True)
        env = dict(os.environ, COOP_AUTO_UPDATE='0')
        env.pop('COOP_REGION', None)
        command = 'cmd /c ""' + str(self.folder / 'Start-Coop.cmd') + '"' + ''.join(' ' + a for a in arguments) + '"'
        done = subprocess.run(command, cwd=self.folder, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=60)
        started = (self.folder / 'reconstruction/started.txt')
        return done, started.read_text() if started.exists() else None

    def test_start_coop_passes_region_arguments_and_remembers(self):
        done, url = self.start()
        self.assertEqual(url, EU, done.stdout[-600:])
        self.assertIn('[  OK  ] Region EU', done.stdout)
        done, url = self.start('us')
        self.assertEqual(url, US, done.stdout[-600:])
        done, url = self.start()
        self.assertEqual(url, US)  # Remembered, no console: no question, no waiting.
        done, url = self.start('--region', 'eu')
        self.assertEqual(url, EU)
        done, url = self.start('http://127.0.0.1:47770')
        self.assertEqual(url, 'http://127.0.0.1:47770')
        self.assertEqual((self.folder / launcher.REGION_FILE).read_text().strip(), 'eu')


class BootLogResult(unittest.TextTestResult):
    def startTest(self, test):
        self._started = time.monotonic()
        self.stream.write(f'[ .... ] {test.id().split(".", 1)[1]}\n')
        self.stream.flush()
        super().startTest(test)

    def addSuccess(self, test):
        super().addSuccess(test)
        self.stream.write(f'[  OK  ] {test.id().split(".", 1)[1]} ({time.monotonic() - self._started:.2f} s)\n')

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.stream.write(f'[FAILED] {test.id().split(".", 1)[1]}: {err[1]}\n')

    def addError(self, test, err):
        super().addError(test, err)
        self.stream.write(f'[FAILED] {test.id().split(".", 1)[1]}: CRASH {err[0].__name__}: {err[1]}\n')


if __name__ == '__main__':
    runner = unittest.TextTestRunner(stream=sys.stdout, verbosity=0, resultclass=BootLogResult)
    result = runner.run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    print(f'[ INFO ] summary: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun} passed',
          flush=True)
    sys.exit(0 if result.wasSuccessful() else 1)
