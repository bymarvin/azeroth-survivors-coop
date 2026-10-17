"""Build one co-op update zip that brings every earlier release to the current package (boot-log format).

  make_update.py [--target <staged release folder>] [--source <label>=<staged folder or release zip>] ...
                 [--out "D:/Azeroth Survivors Together Releases"]

The update holds only files whose content differs from the target in at least
one known source release, plus coop-update/update.py, the target manifest and
the source manifests (to name the recognised version). Extracted into a game
folder, Update-Coop.cmd installs it with that folder's own Python.
"""
import argparse
import os
import hashlib
import json
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RELEASES = Path(r'D:\Azeroth Survivors Together Releases')
SEVEN_ZIP = Path(r'C:\Program Files\7-Zip\7z.exe')
DEFAULT_SOURCES = (
    ('Azeroth Survivors Together 0.92.0', RELEASES / 'stage/Azeroth Survivors Together 0.92.0'),
    ('Azeroth Survivors Together 0.93.1', RELEASES / 'stage/Azeroth Survivors Together 0.93.1'),
    ('Azeroth Survivors Together 0.95.0 (co-op 0.0.10)', Path(r'D:\Azeroth-Survivors-Together-0.95.0.zip')),
)
# Installs that cannot be updated with a small file (all game data differs):
# co-op 0.0.7 to 0.0.10 for game 0.84 (their manifests list no exe).
TOO_OLD = {'co-op 0.0.7-0.0.10 for game 0.84': 'dc165e348d0a15062f58d83530619b0f57479028a28507f449c8bcffea0fb306'}


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def manifest(source):
    if source.suffix == '.zip':
        with zipfile.ZipFile(source) as archive:
            name = next(n for n in archive.namelist() if n.endswith('/package-manifest.json') and n.count('/') == 1)
            return json.loads(archive.read(name))
    return json.loads((source / 'package-manifest.json').read_text(encoding='utf-8'))


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', type=Path, default=RELEASES / 'stage/Azeroth Survivors Together 0.95.0')
    ap.add_argument('--source', action='append', help='label=path (staged folder or release zip)')
    ap.add_argument('--out', type=Path, default=RELEASES)
    ap.add_argument('--name', default='Azeroth-Survivors-Together-0.95.0-update')
    ap.add_argument('--no-exe', action='store_true', help='only the zip (tests)')
    args = ap.parse_args()
    sources = ([tuple(s.split('=', 1)) for s in args.source] if args.source else
               [(label, str(path)) for label, path in DEFAULT_SOURCES])

    t = time.time()
    log(' .... ', 'Manifeste laden')
    target = manifest(args.target)
    version = (args.target / 'COOP-VERSION.txt').read_text(encoding='utf-8').strip()
    known = {label: manifest(Path(path)) for label, path in sources}
    log('  OK  ', f'Manifeste laden ({time.time() - t:.1f} s, Ziel {version}, {len(target)} Dateien, '
                  f'Quellen {", ".join(label for label, _ in sources)})')

    t = time.time()
    log(' .... ', 'Inhalt bestimmen')
    payload = sorted(p for p in target if any(m.get(p) != target[p] for m in known.values()))
    sys.path.insert(0, str(ROOT / 'coop-lab/updater'))
    from update import user_area  # The updater's own rule: player data is never shipped or written.
    for p in [p for p in payload if user_area(p)]:
        log(' WARN ', f'Inhalt bestimmen: Nutzerbereich, nicht im Update: {p}')
    payload = [p for p in payload if not user_area(p)]
    runtime = [p for p in payload if p.startswith('.coop-runtime/')]
    if runtime:
        log('FAILED', f'Inhalt bestimmen: Update würde die laufende Python-Laufzeit ändern ({runtime[0]}); '
                      'dafür ist das volle Paket nötig')
        return 1
    for label, m in known.items():
        if 'AzerothSurvivors.exe' not in m:
            log('FAILED', f'Inhalt bestimmen: {label} hat keinen exe-Hash im Manifest')
            return 1
        changed = [p for p in target if m.get(p) != target[p]]
        log(' INFO ', f'{label}: {len(changed)} Dateien, {sum((args.target / p).stat().st_size for p in changed) / 2**20:.1f} MiB')
    size = sum((args.target / p).stat().st_size for p in payload)
    log('  OK  ', f'Inhalt bestimmen ({time.time() - t:.1f} s, {len(payload)} Dateien, {size / 2**20:.1f} MiB unkomprimiert)')

    t = time.time()
    stage = args.out / 'stage' / args.name
    log(' .... ', f'Staging nach {stage}')
    if stage.exists():
        shutil.rmtree(stage)
    tool = stage / 'coop-update'
    (tool / 'files').mkdir(parents=True)
    updater = ROOT / 'coop-lab/updater'
    shutil.copy2(updater / 'Update-Coop.cmd', stage / 'Update-Coop.cmd')
    shutil.copy2(updater / 'README-UPDATE.txt', stage / 'README-UPDATE.txt')
    shutil.copy2(updater / 'update.py', tool / 'update.py')
    (tool / 'VERSION').write_text(version + '\n', encoding='utf-8')
    (tool / 'target-manifest.json').write_text(json.dumps(target, indent=1, sort_keys=True), encoding='utf-8')
    (tool / 'sources.json').write_text(json.dumps(dict(releases=known, too_old=TOO_OLD), indent=1, sort_keys=True),
                                       encoding='utf-8')
    for p in payload:
        (tool / 'files' / p).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.target / p, tool / 'files' / p)
        if sha256(tool / 'files' / p) != target[p]:
            log('FAILED', f'Staging: {p} weicht vom Zielmanifest ab')
            return 1
    log('  OK  ', f'Staging ({time.time() - t:.1f} s, {len(payload)} Dateien + Updater)')

    t = time.time()
    archive = args.out / (args.name + '.zip')
    log(' .... ', f'Zip packen nach {archive}')
    if archive.exists():
        archive.unlink()
    base = [str(SEVEN_ZIP), 'a', '-tzip', '-mmt=on', '-bb0', '-bd', str(archive)]
    # Deflate everything except the already compressed MPQ archives, which are stored.
    passes = [(['-mx=7', '-xr!*.MPQ'], '*')]
    if any(p.endswith('.MPQ') for p in payload):
        passes.append((['-mx=0'], 'coop-update/files/Data/*.MPQ'))
    for flags, pattern in passes:
        result = subprocess.run(base + flags + [pattern], cwd=stage, capture_output=True, text=True)
        if result.returncode != 0:
            log('FAILED', f'Zip packen: {result.stderr.strip()[-300:]}')
            return 1
    log('  OK  ', f'Zip packen ({time.time() - t:.1f} s, {archive.stat().st_size / 2**20:.1f} MiB)')

    t = time.time()
    log(' .... ', 'Zip testen')
    result = subprocess.run([str(SEVEN_ZIP), 't', str(archive)], capture_output=True, text=True)
    with zipfile.ZipFile(archive) as z:
        names = set(z.namelist())
    expected = {'Update-Coop.cmd', 'README-UPDATE.txt', 'coop-update/update.py', 'coop-update/VERSION',
                'coop-update/target-manifest.json', 'coop-update/sources.json', *(f'coop-update/files/{p}' for p in payload)}
    if result.returncode != 0 or not expected <= names:
        log('FAILED', f'Zip testen: 7z {result.returncode}, fehlend {sorted(expected - names)[:3]}')
        return 1
    digest = sha256(archive)
    log('  OK  ', f'Zip testen ({time.time() - t:.1f} s, {len(names)} Einträge, sha256 {digest})')
    if args.no_exe:
        (args.out / (args.name + '.sha256.txt')).write_text(f'{digest}  {archive.name}' + chr(10), encoding='utf-8')
        return 0
    t = time.time()
    exe = args.out / (args.name + '.exe')
    log(' .... ', f'Update-exe bauen nach {exe}')
    project = updater / 'exe'
    built = subprocess.run(['cargo', 'build', '--release', '--quiet'], cwd=project, capture_output=True, text=True,
                           env=dict(os.environ, COOP_UPDATE_ZIP=str(archive.resolve()),
                                    CARGO_TARGET_DIR=str(args.out / 'stage' / (args.name + '-cargo'))))
    if built.returncode != 0:
        log('FAILED', f'Update-exe bauen: {built.stderr.strip()[-400:]}')
        return 1
    shutil.copy2(args.out / 'stage' / (args.name + '-cargo') / 'release/coop-update.exe', exe)
    with open(exe, 'rb') as stream:
        if stream.read().find(open(archive, 'rb').read(1 << 16)) < 0:
            log('FAILED', 'Update-exe bauen: Zip nicht eingebettet')
            return 1
    exe_digest = sha256(exe)
    log('  OK  ', f'Update-exe bauen ({time.time() - t:.1f} s, {exe.stat().st_size / 2**20:.1f} MiB, sha256 {exe_digest})')

    (args.out / (args.name + '.sha256.txt')).write_text(
        f'{exe_digest}  {exe.name}' + chr(10) + f'{digest}  {archive.name}' + chr(10), encoding='utf-8')
    readme = (updater / 'DISCORD-UPDATE.txt').read_text(encoding='utf-8')
    (args.out / (args.name + '-DISCORD.txt')).write_text(
        readme.replace('{SHA256}', digest).replace('{EXE_SHA256}', exe_digest)
        .replace('{SIZE}', f'{exe.stat().st_size / 2**20:.0f} MB'), encoding='utf-8')
    log(' INFO ', f'SHA-256 und Discord-Text neben dem Zip: {args.name}.sha256.txt, {args.name}-DISCORD.txt')
    return 0


if __name__ == '__main__':
    sys.exit(main())
