"""Run every reconstruction/test_*.py module in its own process (boot-log format, parallel, watchdog per module).

  run_tests.py [--root <mod folder>] [--timeout 300]
A crash or hang of one module never hides the others. Summary at the end; exit code 1 on any failure.
"""
import argparse
import ctypes
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ctypes import wintypes
from pathlib import Path


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def threads():
    k = ctypes.windll.kernel32
    k.GetCurrentProcess.restype = wintypes.HANDLE
    k.GetProcessAffinityMask.argtypes = (wintypes.HANDLE, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t))
    a, b = ctypes.c_size_t(), ctypes.c_size_t()
    return max(1, min(16, bin(a.value).count('1'))) if k.GetProcessAffinityMask(k.GetCurrentProcess(), ctypes.byref(a), ctypes.byref(b)) else 4


CANDIDATE = None


def run(root, module, timeout):
    t = time.time()
    env = dict(os.environ, PYTHONIOENCODING='utf-8', PYTHONDONTWRITEBYTECODE='1')
    if CANDIDATE:
        # Isolated candidate path (as static_check.py): the unbound release is loaded without active-hooks.json.
        env.update(COOP_CANDIDATE_PROFILE=str(CANDIDATE), COOP_CANDIDATE_HOME=str(CANDIDATE.parent), COOP_BUILD='updated')
    try:
        p = subprocess.run([str(root / '.coop-runtime/python.exe'), '-m', 'unittest', module], cwd=root / 'reconstruction',
                           capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout, env=env)
    except subprocess.TimeoutExpired as e:
        return module, 'KILL', time.time() - t, f'Hänger nach {timeout} s', (e.stderr or '')[-1500:] if isinstance(e.stderr, str) else ''
    tail = (p.stderr or '').strip().splitlines()
    summary = next((l for l in reversed(tail) if l.startswith(('OK', 'FAILED'))), '')
    ran = next((l for l in reversed(tail) if l.startswith('Ran ')), '')
    if p.returncode == 0:
        return module, 'OK', time.time() - t, f'{ran}; {summary}', ''
    kind = 'FAILED' if summary.startswith('FAILED') else 'FAILED'
    detail = summary or f'CRASH Exit {p.returncode}'
    return module, kind, time.time() - t, f'{ran}; {detail}', '\n'.join(tail[-40:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument('--timeout', type=int, default=300)
    ap.add_argument('--candidate', type=Path, help='candidate.json written by static_check.py')
    args = ap.parse_args()
    global CANDIDATE
    CANDIDATE = args.candidate
    modules = sorted(p.stem for p in (args.root / 'reconstruction').glob('test_*.py'))
    workers = threads()
    log(' INFO ', f'{len(modules)} Testmodule in {args.root}, {workers} Threads, Watchdog {args.timeout} s je Modul')
    t0, results = time.time(), []
    with ThreadPoolExecutor(workers) as pool:
        futures = {pool.submit(run, args.root, m, args.timeout): m for m in modules}
        for m in modules:
            log(' .... ', m)
        for n, f in enumerate(as_completed(futures), 1):
            module, kind, seconds, info, detail = f.result()
            results.append((module, kind, info, detail))
            tag = {'OK': '  OK  ', 'KILL': ' KILL '}.get(kind, 'FAILED')
            log(tag, f'{module} ({seconds:.1f} s, {info})')
            for line in detail.splitlines()[-12:] if kind != 'OK' else ():
                log(' INFO ', f'  {line}')
            if n % 8 == 0:
                log(f'{100 * n // len(modules):3d} %', f'{n}/{len(modules)} Module fertig')
    ok = sum(1 for r in results if r[1] == 'OK')
    log(' INFO ', f'Zusammenfassung: {ok}/{len(results)} Module bestanden ({time.time() - t0:.1f} s, {len(results) / max(time.time() - t0, .01):.2f} Module/s); '
                  f'nicht bestanden: {", ".join(sorted(r[0] for r in results if r[1] != "OK")) or "keine"}')
    return 0 if ok == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
