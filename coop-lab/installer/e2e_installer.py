"""End-to-end test of the web installer against local servers (boot-log format).

  e2e_installer.py --staging <package staging, e.g. build-0.0.13> --work <new folder>
                   [--real-release <github-0.0.13>] [--production-installer <azsurvivors-installer.exe>]

Everything is signed with a throwaway test key (never the release key): a test
build of the installer and of updater exe 4 trust it. Two packages A and B
(B = A with another version and launcher) with full game file assets for fresh
installs (patch.MPQ raw), two signed game file sources (the first one missing).
Cases: the folder choice without --dir (next to the exe / the exe's own folder),
a fresh install next to the exe in a Downloads-like folder (runtime half
downloaded before: it continues; shortcuts into a test folder), the installer
copied into that game folder with release B (update mode through the installed
updater exe, no new shortcuts), no write access (Program Files), too little
space, a damaged runtime archive (nothing installed), a foreign signature, and
the production installer accepting the real release key (--real-release).
Shortcuts only go to <work>/shortcuts: nothing touches the real desktop or Start menu.
"""
import argparse
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from functools import partial
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(ROOT / 'coop-lab/updater'), str(ROOT / 'reconstruction')]
import sign_release  # noqa: E402

PYTHON = Path(sys.executable)
EXE = 'Azeroth-Survivors-Together-Updater.exe'
RESULTS = []


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


INSTALLER = 'Azeroth-Survivors-Together-Installer.exe'


def tree(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*')
            if p.is_file() and not p.relative_to(root).as_posix().startswith(('coop-update', 'coop-update-'))
            and '__pycache__' not in p.parts and not p.name.endswith('.exe.old') and p.name != INSTALLER}


def shortcut_target(link):
    run = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
                          f"(New-Object -ComObject WScript.Shell).CreateShortcut('{link}').TargetPath"],
                         capture_output=True, text=True)
    return run.stdout.strip()


def copy(source, target):
    for path in source.rglob('*'):
        out = target / path.relative_to(source)
        if path.is_dir():
            out.mkdir(parents=True, exist_ok=True)
        elif path.stat().st_size > 8 << 20:
            out.parent.mkdir(parents=True, exist_ok=True)
            os.link(path, out)
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, out)


def manifest(stage):
    files = sorted(p for p in stage.rglob('*') if p.is_file() and p.name != 'package-manifest.json')
    data = {p.relative_to(stage).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    (stage / 'package-manifest.json').write_text(json.dumps(data, indent=1, sort_keys=True), encoding='utf-8')


class Files(http.server.SimpleHTTPRequestHandler):
    """Static files with HTTP Range (curl -C - and the updater continue there)."""
    root, tamper = None, {}

    def __init__(self, *a, **k):
        super().__init__(*a, directory=str(type(self).root), **k)

    def log_message(self, *a):
        pass

    def send_head(self):
        name = self.path.lstrip('/')
        if name in type(self).tamper:
            body = type(self).tamper[name]
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            return __import__('io').BytesIO(body)
        path = Path(self.translate_path(self.path))
        header = self.headers.get('Range')
        if not header or not path.is_file():
            return super().send_head()
        start = int(header.split('=')[1].split('-')[0])
        size = path.stat().st_size
        if start >= size:
            self.send_response(416)
            self.send_header('Content-Range', f'bytes */{size}')
            self.end_headers()
            return None
        stream = open(path, 'rb')
        stream.seek(start)
        self.send_response(206)
        self.send_header('Content-Range', f'bytes {start}-{size - 1}/{size}')
        self.send_header('Content-Length', str(size - start))
        self.end_headers()
        return stream


def serve(root):
    handler = type('Root', (Files,), {'root': root, 'tamper': {}})
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, handler, f'http://127.0.0.1:{server.server_port}/'


def case(name, fn):
    log(' .... ', name)
    started = time.time()
    try:
        info = fn()
        log('  OK  ', f'{name} ({time.time() - started:.1f} s, {info})')
        RESULTS.append(True)
    except Exception as error:
        log('FAILED', f'{name}: {type(error).__name__}: {error}')
        RESULTS.append(False)


def cargo(crate, target, env, *extra):
    built = subprocess.run(['cargo', 'build', '--release', '--quiet', *extra], cwd=crate, capture_output=True, text=True,
                           env=dict(os.environ, CARGO_TARGET_DIR=str(target), **env))
    if built.returncode:
        raise SystemExit(built.stderr[-800:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--staging', type=Path, required=True)
    ap.add_argument('--work', type=Path, required=True)
    ap.add_argument('--real-release', type=Path)
    ap.add_argument('--production-installer', type=Path)
    args = ap.parse_args()
    work = args.work
    if work.exists():
        raise SystemExit(f'{work} exists; use a new folder')
    work.mkdir(parents=True)
    t0 = time.time()

    log(' .... ', 'Testschlüssel, Test-Installer, Test-Updater 4')
    started = time.time()
    sign_release.create(work / 'key', sign_release.CURRENT)
    pub = sign_release.public(sign_release.load(work / 'key'))
    cargo(HERE, work / 'cargo-installer', dict(COOP_INSTALLER_TEST_KEY=pub))
    cargo(ROOT / 'coop-lab/updater/exe', work / 'cargo-updater', dict(COOP_UPDATER_VERSION='4', COOP_UPDATER_TEST_KEY=pub),
          '--bin', 'coop-updater')
    installer = work / 'cargo-installer/release/azsurvivors-installer.exe'
    updater = work / 'cargo-updater/release/coop-updater.exe'
    log('  OK  ', f'Testschlüssel, Test-Installer, Test-Updater 4 ({time.time() - started:.1f} s, '
                  f'Installer {installer.stat().st_size // 1024} KiB)')

    log(' .... ', 'Pakete A und B, Spieldatei-Vollassets')
    started = time.time()
    stage_a, stage_b = work / 'stage-a', work / 'stage-b'
    copy(args.staging, stage_a)
    shutil.copy2(updater, stage_a / EXE)
    (stage_a / 'COOP-VERSION.txt').write_text('0.0.20-community+game-7264d50b', encoding='utf-8')
    manifest(stage_a)
    copy(stage_a, stage_b)
    (stage_b / 'COOP-VERSION.txt').write_text('0.0.21-community+game-7264d50b', encoding='utf-8')
    with open(stage_b / 'coop_launcher.py', 'a', encoding='utf-8') as stream:
        stream.write('\n# release B (installer test)\n')
    manifest(stage_b)
    gamefiles = work / 'gamefiles'
    run = subprocess.run([str(PYTHON), '-I', str(ROOT / 'coop-lab/updater/make_game_patches.py'), '--target', str(stage_a),
                          '--out', str(gamefiles), '--full-for-all', '--full-max-mb', '2047'],
                         capture_output=True, text=True, encoding='utf-8', errors='replace')
    if run.returncode:
        raise SystemExit(run.stdout[-800:])
    assets = json.loads((gamefiles / 'gamefiles.json').read_text())
    raw = sorted(p for p, v in assets.items() if (v.get('full') or {}).get('encoding') == 'raw')
    log('  OK  ', f'Pakete A und B ({time.time() - started:.1f} s, Vollassets für {len(assets)} Spieldateien, raw: {raw})')

    release_server, release, release_url = serve(work / 'release-a')
    missing_server, _, missing_url = serve(work / 'nothing')
    game_server, _, game_url = serve(gamefiles)
    (work / 'nothing').mkdir()

    log(' .... ', 'Release-Ordner A und B (Testschlüssel, zwei Spieldatei-Quellen)')
    started = time.time()
    for name, stage, sequence in (('release-a', stage_a, 1000), ('release-b', stage_b, 2000)):
        run = subprocess.run([str(PYTHON), str(ROOT / 'coop-lab/port-7264/make_release.py'), '--target', str(stage),
                              '--updater-exe', str(updater), '--updater-version', '4', '--min-updater', '4',
                              '--gamefiles', str(gamefiles), '--gamefiles-url', missing_url, '--gamefiles-url', game_url,
                              '--allow-local-http', '--full-package-url', 'https://github.com/bymarvin/azeroth-survivors-together#full-package',
                              '--sequence', str(sequence), '--key-dir', str(work / 'key'), '--out', str(work / name)],
                             capture_output=True, text=True, encoding='utf-8', errors='replace')
        if run.returncode:
            raise SystemExit(run.stdout[-800:])
    log('  OK  ', f'Release-Ordner ({time.time() - started:.1f} s)')
    latest = json.loads((work / 'release-a/latest.json').read_text())
    runtime_asset = latest['archives']['runtime']['asset']

    def install(exe, folder, *extra, url=None):
        dir_args = ['--dir', str(folder)] if folder else []
        return subprocess.run([str(exe), *dir_args, '--no-shortcuts', '--no-pause', '--no-open',
                               '--release-url', url or release_url, '--allow-local-http', *extra],
                              capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=1800)

    def placed(folder):
        """The test installer copied into a folder, started there without --dir (like a double-click)."""
        folder.mkdir(parents=True, exist_ok=True)
        shutil.copy2(installer, folder / INSTALLER)
        return folder / INSTALLER

    def chosen(run):
        line = next((l for l in run.stdout.splitlines() if '] Folder ' in l), '')
        return line.split('] Folder ', 1)[1].rsplit(' (', 1)[0] if line else None

    def choice():
        downloads, named, alone = work / 'Downloads x', work / 'Azeroth Survivors Together', work / 'empty one'
        downloads.mkdir()
        (downloads / 'other download.zip').write_bytes(b'x')
        want = {downloads: downloads / 'Azeroth Survivors Together', named: named, alone: alone}
        for folder, target in want.items():
            exe = placed(folder)
            run = install(exe, None, '--needed-space', str(10 ** 18))  # Stops right after the folder choice.
            if chosen(run) != str(target) or 'Nothing was installed' not in run.stdout or tree(target):
                raise AssertionError(f'{folder.name}: chose {chosen(run)!r}, wanted {target}: {run.stdout[-500:]}')
            (folder / INSTALLER).unlink()
        shutil.rmtree(downloads / 'Azeroth Survivors Together')
        return 'Downloads-like folder -> subfolder "Azeroth Survivors Together"; folder of that name / empty folder -> itself'
    case('Folder choice without questions', choice)

    def same(folder, stage):
        got, want = tree(folder), tree(stage)
        differ = sorted(p for p in want if got.get(p) != want[p])
        extra = sorted(p for p in got if p not in want)
        if differ or extra:
            raise AssertionError(f'differs from {stage.name}: {differ[:5]} extra {extra[:5]}')

    downloads = work / 'Downloads x'
    folder = downloads / 'Azeroth Survivors Together'
    links = work / 'shortcuts'

    def started_here(exe):
        return subprocess.run([str(exe), '--no-pause', '--no-open', '--shortcut-folder', str(links),
                               '--release-url', release_url, '--allow-local-http'],
                              capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=1800)

    def fresh():
        release.root = work / 'release-a'
        partial_dir = folder / 'coop-update' / 'install'
        partial_dir.mkdir(parents=True)
        data = (work / 'release-a' / runtime_asset).read_bytes()
        (partial_dir / runtime_asset).write_bytes(data[:len(data) // 2])  # An interrupted earlier attempt.
        for sub in ('Desktop', 'Programs'):
            (links / sub).mkdir(parents=True, exist_ok=True)
        started = time.time()
        run = started_here(placed(downloads))
        if run.returncode:
            raise AssertionError(run.stdout[-1200:])
        same(folder, stage_a)
        if 'SHA-256 matches the release' not in run.stdout or 'Done - start Start-Coop.cmd' not in run.stdout:
            raise AssertionError(run.stdout[-600:])
        loose = sorted(p.name for p in downloads.iterdir())
        if loose != sorted([INSTALLER, 'Azeroth Survivors Together', 'other download.zip']):
            raise AssertionError(f'loose files next to the installer: {loose}')
        for sub in ('Desktop', 'Programs'):
            target = shortcut_target(links / sub / 'Azeroth Survivors Together.lnk')
            if target.lower() != str(folder / 'Start-Coop.cmd').lower():
                raise AssertionError(f'{sub} shortcut points to {target!r}')
        return (f'next to the exe in "Azeroth Survivors Together", byte-equal to package A ({len(tree(folder))} files, '
                f'{sum(f.stat().st_size for f in folder.rglob("*") if f.is_file()) / 2**30:.2f} GiB) in {time.time() - started:.0f} s; '
                'runtime continued from 50 %, first game file source 404 -> second; desktop + Start menu shortcut -> Start-Coop.cmd')
    case('Fresh install next to the installer', fresh)

    def update_mode():
        release.root = work / 'release-b'
        for link in links.rglob('*.lnk'):
            link.unlink()
        run = started_here(placed(folder))  # The installer inside the game folder.
        if run.returncode or 'existing installation: update' not in run.stdout or chosen(run) != str(folder):
            raise AssertionError(run.stdout[-1200:])
        same(folder, stage_b)
        if list(links.rglob('*.lnk')):
            raise AssertionError('an update created shortcuts')
        return 'installer inside the game folder: that folder, update by its own updater exe, byte-equal to B, no shortcuts'
    case('Installer in the game folder: update mode', update_mode)

    def no_write_access():
        target = Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'Azeroth Survivors Together E2E'
        if target.exists():
            raise AssertionError(f'{target} exists already')
        run = install(installer, target)
        if run.returncode == 0 or 'No write access' not in run.stdout or target.exists():
            raise AssertionError(run.stdout[-800:])
        return 'Program Files without admin: clear message, nothing created, no admin prompt'
    case('No write access', no_write_access)

    def no_space():
        target = work / 'no space'
        run = install(installer, target, '--needed-space', str(10 ** 18))
        if run.returncode == 0 or 'GiB needed. Nothing was installed' not in run.stdout or tree(target):
            raise AssertionError(run.stdout[-800:])
        return 'too little space: message, nothing installed'
    case('Too little space', no_space)

    def damaged():
        release.root = work / 'release-a'
        data = bytearray((work / 'release-a' / runtime_asset).read_bytes())
        data[len(data) // 2] ^= 1
        release.tamper = {runtime_asset: bytes(data)}
        target = work / 'damaged'
        try:
            run = install(installer, target)
        finally:
            release.tamper = {}
        if run.returncode == 0 or 'does not match its signed size/SHA-256' not in run.stdout or tree(target):
            raise AssertionError(run.stdout[-800:])
        return 'refused, nothing installed'
    case('Damaged runtime archive', damaged)

    if args.production_installer:
        def foreign():
            release.root = work / 'release-a'
            target = work / 'foreign'
            run = install(args.production_installer, target)
            if run.returncode == 0 or 'not signed by a trusted key' not in run.stdout or tree(target):
                raise AssertionError(run.stdout[-800:])
            return 'production installer refuses the test-signed release, nothing installed'
        case('Foreign signature', foreign)

    if args.production_installer and args.real_release:
        def real_key():
            release.root = args.real_release
            target = work / 'real-key'
            run = install(args.production_installer, target)
            if 'Read signed release description' not in run.stdout or 'signed by KT0uZ26Iiq4B' not in run.stdout:
                raise AssertionError(run.stdout[-800:])
            return 'production installer accepts the real release key (stopped later as expected: ' + \
                   (run.stdout.strip().splitlines()[-1][:120] if run.stdout.strip() else '') + ')'
        case('Production installer and the real release key', real_key)

    for server in (release_server, missing_server, game_server):
        server.shutdown()
    log(' INFO ', f'Zusammenfassung: {sum(RESULTS)}/{len(RESULTS)} bestanden ({time.time() - t0:.0f} s)')
    return 0 if all(RESULTS) else 1


if __name__ == '__main__':
    sys.exit(main())
