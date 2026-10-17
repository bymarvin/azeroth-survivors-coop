"""The installer and updater under Wine (WSL Ubuntu, wine 10), boot-log format; no game is started.

  wine_installer_test.py --e2e <work folder of a passed e2e_installer.py run> [--live <production installer>]

Linux players run the co-op through Wine/Proton, where curl.exe and tar.exe do not exist. Uses the test key,
test installer/updater and packages A/B of the e2e run. The test servers run inside WSL (Wine cannot reach the
Windows 127.0.0.1): release A/B on 48860, a game file source that is gone on 48861, the game file assets on 48862.
Cases: fresh install under Wine (byte-equal to package A, first source 404 -> second), the installer again with
release B (update mode through the installed updater exe under Wine), and with --live the production installer
against the real release into a throwaway Linux folder.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DISTRO, USER = 'Ubuntu', 'azdev'
PREFIX = '/home/azdev/.wine-azinstall'
RELEASE_PORT, GONE_PORT, GAME_PORT = 48860, 48861, 48862
RESULTS = []


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def linux(path):
    """D:\\a b -> /mnt/d/a b"""
    path = str(Path(path).resolve())
    return '/mnt/' + path[0].lower() + path[2:].replace('\\', '/')


def wsl(*command, timeout=600, stdin=None):
    return subprocess.run(['wsl', '-d', DISTRO, '-u', USER, '--exec', *command], capture_output=True, text=True,
                          encoding='utf-8', errors='replace', timeout=timeout, input=stdin)


def wine(*command, timeout=3600):
    # Without winedbg a crash ends the process (and fails the case) instead of waiting for a dialog under Xvfb.
    return wsl('env', f'WINEPREFIX={PREFIX}', 'WINEDEBUG=-all', 'WINEARCH=win64', 'WINEDLLOVERRIDES=winedbg.exe=d',
               'xvfb-run', '-a', 'wine', *command, timeout=timeout)


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


def tree_check(folder, stage):
    """Compare a Linux folder with a package folder inside WSL (sha256 of every file, user areas excluded)."""
    script = r'''
import hashlib, sys
from pathlib import Path
def tree(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*')
            if p.is_file() and not p.relative_to(root).as_posix().startswith('coop-update')
            and '__pycache__' not in p.parts and not p.name.endswith('.exe.old')}
got, want = tree(sys.argv[1]), tree(sys.argv[2])
differ = sorted(p for p in want if got.get(p) != want[p])
extra = sorted(p for p in got if p not in want)
print(len(want), differ[:5], extra[:5])
'''
    run = wsl('python3', '-c', script, folder, linux(stage), timeout=900)
    count, *rest = run.stdout.strip().split(' ', 1)
    if run.returncode or rest != ['[] []']:
        raise AssertionError(f'differs from {Path(stage).name}: {run.stdout.strip()[-400:]} {run.stderr[-300:]}')
    return int(count)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--e2e', type=Path, required=True)
    ap.add_argument('--live', type=Path, help='production installer: also install the real release under Wine')
    args = ap.parse_args()
    work, t0 = args.e2e, time.time()
    installer = work / 'cargo-installer/release/azsurvivors-installer.exe'
    updater = work / 'cargo-updater/release/coop-updater.exe'
    python = Path(sys.executable)

    log(' .... ', 'Wine-Präfix und Test-Releases (feste Ports für die Server in WSL)')
    started = time.time()
    version = wsl('wine', '--version', timeout=60).stdout.strip()
    wine('wineboot', '-i', timeout=600)
    for name, stage, sequence in (('wine-release-a', 'stage-a', 3000), ('wine-release-b', 'stage-b', 4000)):
        out = work / name
        if not (out / 'latest.json').is_file():
            run = subprocess.run([str(python), str(ROOT / 'coop-lab/port-7264/make_release.py'), '--target', str(work / stage),
                                  '--updater-exe', str(updater), '--updater-version', '4', '--min-updater', '4',
                                  '--gamefiles', str(work / 'gamefiles'),
                                  '--gamefiles-url', f'http://127.0.0.1:{GONE_PORT}/',
                                  '--gamefiles-url', f'http://127.0.0.1:{GAME_PORT}/', '--allow-local-http',
                                  '--full-package-url', 'https://github.com/bymarvin/azeroth-survivors-together#full-package',
                                  '--sequence', str(sequence), '--key-dir', str(work / 'key'), '--out', str(out)],
                                 capture_output=True, text=True, encoding='utf-8', errors='replace')
            if run.returncode:
                raise SystemExit(run.stdout[-800:])
    log('  OK  ', f'Wine-Präfix und Test-Releases ({time.time() - started:.1f} s, {version})')

    base = f'/home/azdev/azinst-{int(time.time())}'
    folder = f'{base}/Downloads x/Azeroth Survivors Together'
    windows_folder = 'Z:' + folder.replace('/', '\\')

    def servers(release):
        server = subprocess.Popen(['wsl', '-d', DISTRO, '-u', USER, '--exec', 'python3', linux(HERE / 'wine_server.py'),
                                   f'{RELEASE_PORT}={linux(work / release)}', f'{GONE_PORT}=-',
                                   f'{GAME_PORT}={linux(work / "gamefiles")}'],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        if server.stdout.readline().strip() != 'ready':
            raise RuntimeError('test servers did not start in WSL')
        return server

    def install(exe, *extra, folder_arg=windows_folder, url=f'http://127.0.0.1:{RELEASE_PORT}/'):
        options = ['--dir', folder_arg, '--no-shortcuts', '--no-pause', '--no-open', *extra]
        if url:
            options += ['--release-url', url, '--allow-local-http']
        return wine(linux(exe), *options)

    def fresh():
        server = servers('wine-release-a')
        try:
            run = install(installer)
        finally:
            server.stdin.close()
            server.wait(10)
        if run.returncode or 'Done - start Start-Coop.cmd' not in run.stdout:
            raise AssertionError((run.stdout + run.stderr)[-1500:])
        files = tree_check(folder, work / 'stage-a')
        if 'curl' in run.stdout or 'tar.exe' in run.stdout:
            raise AssertionError('an external tool was used')
        return f'byte-equal to package A ({files} files) under {version}; WinHTTP + ZIP reader, Python updater'
    case('Fresh install under Wine', fresh)

    def update_mode():
        server = servers('wine-release-b')
        try:
            run = install(installer)
        finally:
            server.stdin.close()
            server.wait(10)
        if run.returncode or 'existing installation: update' not in run.stdout:
            raise AssertionError((run.stdout + run.stderr)[-1500:])
        files = tree_check(folder, work / 'stage-b')
        return f'existing installation updated by its own updater exe under Wine, byte-equal to package B ({files} files)'
    case('Installer again under Wine: update mode', update_mode)

    if args.live:
        def live():
            target = 'Z:' + f'{base}/live/Azeroth Survivors Together'.replace('/', '\\')
            run = install(args.live, folder_arg=target, url=None)
            text = run.stdout + run.stderr
            if run.returncode or 'Installed co-op version:' not in text:
                raise AssertionError(text[-1500:])
            installed = next(line for line in text.splitlines() if 'Installed co-op version:' in line)
            return f'real release from GitHub and the server under Wine: {installed.split("version:")[1].split(".", 3)[:3]}'
        case('Production installer against the live release under Wine', live)

    log(' INFO ', f'Testordner in WSL (nicht gelöscht): {base}')
    log(' INFO ', f'Zusammenfassung: {sum(RESULTS)}/{len(RESULTS)} bestanden ({time.time() - t0:.0f} s)')
    return 0 if all(RESULTS) else 1


if __name__ == '__main__':
    sys.exit(main())
