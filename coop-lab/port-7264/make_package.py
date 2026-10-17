"""Build the shippable co-op zip for game 0.95.0 (7264d50b) including AzerothSurvivors.exe and Data (boot-log format).

  make_package.py [--out "D:/Azeroth Survivors Together Releases"] [--name "Azeroth Survivors Together 0.95.0"]

1. stage: copy runtime, tools, reconstruction, analysis code + bound active-hooks.json, relay, launchers, exe, Data
   (no saves, compatibility tests, logs, launcher profiles, coop-lab dev tools, __pycache__)
2. package-manifest.json: sha256 of every staged file (parallel)
3. check from the staged copy with its own Python: source identity equals the bound acceptance and the normal
   (non-isolated) launch path resolves 'verified_adapter'; files the check creates are removed again
4. zip with 7-Zip (multithreaded; MPQ archives are stored, everything else deflated)
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEVEN_ZIP = Path(r'C:\Program Files\7-Zip\7z.exe')
GAME_SHA = '7264d50b82a1ecc2b5f0fcf2f29669c2acaa8bb87c058e17898a47a12984ff30'


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def threads():
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetProcessAffinityMask.argtypes = (wintypes.HANDLE, ctypes.POINTER(ctypes.c_size_t),
                                                    ctypes.POINTER(ctypes.c_size_t))
        process, system = ctypes.c_size_t(), ctypes.c_size_t()
        if not kernel32.GetProcessAffinityMask(kernel32.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(system)):
            return 4
        return max(1, min(16, bin(process.value).count('1')))
    except Exception:
        return 4


def package_files():
    def tree(folder, keep=lambda p: True):
        return [p for p in (ROOT / folder).rglob('*')
                if p.is_file() and '__pycache__' not in p.parts and keep(p)]
    files = tree('.coop-runtime') + tree('.tools') + tree('reconstruction') + tree('Data')
    files += tree('relay', lambda p: p.suffix == '.py')
    files += tree('analysis', lambda p: p.parent == ROOT / 'analysis' and (
        p.suffix == '.py' or p.name in ('active-hooks.json', 'native-contract-baseline.json', 'UPDATE-COMPATIBILITY.md')))
    files += [ROOT / n for n in ('AzerothSurvivors.exe', 'Start-Coop.cmd', 'coop_launcher.py',  # no Start-Solo-Test.cmd (user decision)
                                 'coop_autoupdate.py', 'COOP-VERSION.txt',
                                 # From 0.0.13 every package ships the updater (Start-Coop uses it directly).
                                 'Azeroth-Survivors-Together-Updater.exe')]
    return sorted(files)


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path, default=Path(r'D:\Azeroth Survivors Together Releases'))
    ap.add_argument('--name', default='Azeroth Survivors Together 0.95.0')
    args = ap.parse_args()
    workers = threads()
    log(' INFO ', f'{workers} Threads (aus der aktuellen Affinität)')

    t = time.time()
    log(' .... ', 'Vorbedingungen')
    if sha256(ROOT / 'AzerothSurvivors.exe') != GAME_SHA:
        log('FAILED', 'Vorbedingungen: AzerothSurvivors.exe ist nicht 7264d50b (0.95.0)')
        return 1
    if not (ROOT / 'Azeroth-Survivors-Together-Updater.exe').is_file():
        log('FAILED', 'Vorbedingungen: Azeroth-Survivors-Together-Updater.exe (Updater 3, coop-updater.exe) fehlt im Build-Ordner')
        return 1
    if not SEVEN_ZIP.is_file():
        log('FAILED', f'Vorbedingungen: {SEVEN_ZIP} fehlt')
        return 1
    log('  OK  ', f'Vorbedingungen ({time.time() - t:.1f} s)')

    t = time.time()
    stage = args.out / 'stage' / args.name
    log(' .... ', f'Staging nach {stage}')
    if stage.exists():
        shutil.rmtree(stage)
    files = package_files()
    total = sum(p.stat().st_size for p in files)
    def copy(path):
        target = stage / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    with ThreadPoolExecutor(workers) as pool:
        list(pool.map(copy, files))
    log('  OK  ', f'Staging ({time.time() - t:.1f} s, {len(files)} Dateien, {total / 2**30:.2f} GiB)')

    t = time.time()
    log(' .... ', 'package-manifest.json erzeugen')
    staged = sorted(p for p in stage.rglob('*') if p.is_file())
    with ThreadPoolExecutor(workers) as pool:
        digests = list(pool.map(sha256, staged))
    manifest = {p.relative_to(stage).as_posix(): d for p, d in zip(staged, digests)}
    # The same bytes the updater writes after an update (indent 1, sorted, text mode).
    (stage / 'package-manifest.json').write_text(json.dumps(manifest, indent=1, sort_keys=True), encoding='utf-8')
    log('  OK  ', f'package-manifest.json erzeugen ({time.time() - t:.1f} s, {len(manifest)} Einträge, '
                  f'{total / 2**20 / max(time.time() - t, 0.01):.0f} MiB/s)')

    t = time.time()
    log(' .... ', 'Startpfad im Staging prüfen (eigene Python-Laufzeit, nicht isoliert)')
    before = {p for p in stage.rglob('*')}
    check = ("import sys, json, pathlib; root = pathlib.Path.cwd(); "
             "sys.path[:0] = [str(root / '.tools/python'), str(root / 'reconstruction')]; import build_hooks; "
             "exe = root / 'AzerothSurvivors.exe'; "
             "bound = json.loads((root / 'analysis/active-hooks.json').read_text())['adapter_profile']; "
             "same = bound['identity'] == build_hooks.probe_identity(exe) == bound['native_acceptance']['identity']; "
             "report = build_hooks.resolve_reviewed_profile(exe); "
             "print(json.dumps(dict(identity_equal=same, status=report.get('status'), "
             "automatic=report.get('automatic_activation_allowed'))))")
    env = {k: v for k, v in os.environ.items() if not k.startswith('COOP_')}
    result = subprocess.run([str(stage / '.coop-runtime/python.exe'), '-B', '-c', check], cwd=stage, env=env,
                            capture_output=True, text=True, timeout=300)
    for extra in sorted({p for p in stage.rglob('*')} - before, key=lambda p: len(p.parts), reverse=True):
        shutil.rmtree(extra) if extra.is_dir() else extra.unlink()
    try:
        verdict = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        verdict = None
    if not verdict or not verdict['identity_equal'] or verdict['status'] != 'verified_adapter' or not verdict['automatic']:
        log('FAILED', f'Startpfad im Staging: {verdict} {result.stderr.strip()[-600:]}')
        return 1
    log('  OK  ', f'Startpfad im Staging prüfen ({time.time() - t:.1f} s, {verdict})')

    t = time.time()
    archive = args.out / (args.name.replace(' ', '-') + '.zip')
    log(' .... ', f'Zip packen nach {archive}')
    if archive.exists():
        archive.unlink()
    # Deflate everything except the already compressed MPQ archives (stored, -mx0 pass appends them).
    base = [str(SEVEN_ZIP), 'a', '-tzip', f'-mmt={workers}', '-bb0', '-bd', str(archive)]
    for flags, pattern in ((['-mx=5', '-xr!*.MPQ'], args.name), (['-mx=0'], f'{args.name}/Data/*.MPQ')):
        run = subprocess.run(base + flags + [pattern], cwd=stage.parent, capture_output=True, text=True)
        if run.returncode != 0:
            log('FAILED', f'Zip packen: 7z {run.returncode} {run.stderr.strip()[-400:]}')
            return 1
    log('  OK  ', f'Zip packen ({time.time() - t:.1f} s, {archive.stat().st_size / 2**30:.2f} GiB)')

    t = time.time()
    log(' .... ', 'Zip testen (7z t)')
    run = subprocess.run([str(SEVEN_ZIP), 't', f'-mmt={workers}', str(archive)], capture_output=True, text=True)
    if run.returncode != 0 or 'Everything is Ok' not in run.stdout:
        log('FAILED', f'Zip testen: {run.stdout.strip()[-400:]}')
        return 1
    log('  OK  ', f'Zip testen ({time.time() - t:.1f} s, sha256 {sha256(archive)})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
