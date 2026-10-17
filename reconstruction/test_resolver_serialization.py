"""Real spawned processes exercise the resolver lock without launching games."""
import hashlib
import json
import multiprocessing as mp
from pathlib import Path
import tempfile
import unittest


def resolver_worker(root, entered, release, waiting, results, fail=False):
    import build_hooks
    root = Path(root)
    build_hooks.ROOT = root
    def resolve(binary, **kwargs):
        profile = root / 'analysis/active-hooks.json'
        if profile.exists():
            results.put(('reuse', json.loads(profile.read_text())['sha256']))
            return json.loads(profile.read_text())
        with (root / 'writers.txt').open('a') as log:
            log.write('writer\n')
        entered.set()
        if not release.wait(15):
            raise TimeoutError('Test did not release writer')
        if fail:
            raise ValueError('deliberate discovery failure')
        value = dict(sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest())
        build_hooks.write_report(profile, value)
        return value
    build_hooks._resolve_reviewed_profile = resolve
    try:
        value = build_hooks.resolve_reviewed_profile(root / 'game.exe', developer_discovery=True,
            progress=lambda stage, detail: waiting.set() if stage == 'waiting' else None)
        results.put(('passed', value['sha256']))
    except Exception as error:
        results.put(('failed', str(error)))


class ResolverSerializationTests(unittest.TestCase):
    def run_workers(self, *, fail=False, changed=None):
        context = mp.get_context('spawn')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'analysis').mkdir()
            (root / 'reconstruction').mkdir()
            (root / 'relay').mkdir()
            for name in ('routing.py', 'client.py', 'server.py'):
                (root / 'relay' / name).write_text('# fixture')
            (root / 'reconstruction/reference-metadata.json').write_text('{}')
            (root / 'game.exe').write_bytes(b'reviewed fixture')
            (root / 'reconstruction/source.py').write_text('version = 1\n')
            entered, release, waiting = context.Event(), context.Event(), context.Event()
            results = context.Queue()
            args = (str(root), entered, release, waiting, results)
            first = context.Process(target=resolver_worker, args=(*args, fail))
            second = context.Process(target=resolver_worker, args=(*args, False))
            workers = [first, second]
            try:
                first.start()
                self.assertTrue(entered.wait(10))
                second.start()
                self.assertTrue(waiting.wait(10))
                if changed:
                    (root / changed).write_bytes(b'changed while waiting')
                release.set()
                for worker in workers:
                    worker.join(15)
                    self.assertEqual(worker.exitcode, 0)
                rows = [results.get(timeout=2) for _ in range(2 if fail or changed else 3)]
                self.assertEqual((root / 'writers.txt').read_text().splitlines(), ['writer'])
                if changed:
                    self.assertEqual(sum(row[0] == 'failed' for row in rows), 2)
                    self.assertTrue(any('while waiting' in row[1] for row in rows))
                elif fail:
                    self.assertEqual(sum(row[0] == 'failed' for row in rows), 2)
                    self.assertTrue(any('concurrent compatibility check failed' in row[1] for row in rows))
                    retry = context.Process(target=resolver_worker, args=args)
                    workers.append(retry)
                    retry.start()
                    retry.join(15)
                    self.assertEqual(retry.exitcode, 0)
                    self.assertEqual(results.get(timeout=2)[0], 'passed')
                    self.assertEqual(len((root / 'writers.txt').read_text().splitlines()), 2)
                else:
                    self.assertEqual(sum(row[0] == 'passed' for row in rows), 2)
                    self.assertEqual(sum(row[0] == 'reuse' for row in rows), 1)
            finally:
                release.set()
                for worker in workers:
                    if worker.pid and worker.is_alive():
                        worker.terminate()
                        worker.join(5)
                results.close()

    def test_single_writer_and_waiter_revalidates_published_profile(self):
        self.run_workers()

    def test_failure_shared_only_with_waiter_and_lock_released_for_retry(self):
        self.run_workers(fail=True)

    def test_changed_executable_while_waiting_is_rejected(self):
        self.run_workers(changed='game.exe')

    def test_changed_resolver_source_while_waiting_is_rejected(self):
        self.run_workers(changed='reconstruction/source.py')


if __name__ == '__main__':
    unittest.main()
