"""publish_release.py with the REAL sftp client against a local sftp-server (boot-log format; no network, no server).

Windows' OpenSSH sftp.exe talks to Git's sftp-server.exe directly (sftp -D), so every batch line goes through
the same parser as on the server: Windows paths with spaces, put/reput/rename, a broken-off upload that has to
continue, a rerun that uploads nothing, latest.json replaced, cleanup after three releases. gh is simulated.
"""
import ctypes
import json
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish_release as pub  # noqa: E402

SERVER_EXE = Path(r'C:\Program Files\Git\usr\lib\ssh\sftp-server.exe')
RESULTS = []


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def test(name, fn):
    log(' .... ', name)
    t = time.time()
    try:
        info = fn()
        log('  OK  ', f'{name} ({time.time() - t:.2f} s{", " + info if info else ""})')
        RESULTS.append(True)
    except Exception as error:
        log('FAILED', f'{name}: {type(error).__name__}: {error}')
        for line in traceback.format_exc().splitlines()[-4:]:
            log(' INFO ', line)
        RESULTS.append(False)


def short(path):
    """8.3 path: sftp -D splits its command at spaces."""
    buffer = ctypes.create_unicode_buffer(1024)
    ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, 1024)
    return buffer.value


class LocalSftp(pub.Runner):
    """Real sftp batches (local sftp-server), simulated gh."""

    def __init__(self, client):
        # Git's msys sftp starts the server by its msys path; Windows' sftp.exe needs a path without spaces.
        server = '/usr/lib/ssh/sftp-server' if 'Git' in client else short(SERVER_EXE)
        super().__init__(dry=False, connect=['-D', server], client=client)
        self.gh_log, self.tags = [], set()
        self.batches = []

    def sftp(self, lines, read_only=False):
        self.batches.append(list(lines))
        return super().sftp(lines, read_only)

    def gh(self, *args, read_only=False, check=True):
        if args[:2] == ('auth', 'status'):
            return 'ok'
        if args[:2] == ('release', 'view'):
            return '{"tagName": "x"}' if args[2] in self.tags else ('{"assets": []}' if 'gamefiles' in args[4] else None)
        if args[:2] == ('release', 'create'):
            self.tags.add(args[2])
        self.gh_log.append(args)
        return ''


def release(root, version, game_bytes):
    out, game = root / f'rel {version}', root / f'game files {version}'
    out.mkdir()
    game.mkdir()
    for name, data in (('latest.json', json.dumps({'version': f'{version}-community+game-abc'}).encode()),
                       ('latest.json.sig', b's' * 64), (f'mod-{version}.zip', b'm' * 3000),
                       ('Azeroth-Survivors-Together-Updater.exe', b'u' * 5000)):
        (out / name).write_bytes(data)
    (game / 'Data-patch.MPQ-abc.xz').write_bytes(game_bytes)
    (game / 'exe-a.azp').write_bytes(b'p' * 777)
    return out, game


def main():
    if not SERVER_EXE.is_file() or not pub.SFTP_CLIENTS:
        log('FAILED', f'needs an sftp client {pub.SFTP_CLIENTS} and {SERVER_EXE}')
        return 1
    for client in pub.SFTP_CLIENTS:
        run_client(client)
    log(' INFO ', f'Zusammenfassung: {sum(RESULTS)}/{len(RESULTS)} bestanden')
    return 0 if all(RESULTS) else 1


def run_client(client):
    which = 'Git' if 'Git' in client else 'Windows'
    root = Path(tempfile.mkdtemp(prefix='publish sftp '))  # A space in every path.
    remote = root / 'server root' / 'files'
    remote.mkdir(parents=True)
    pub.FILES = f'/{remote.drive[0].lower()}{remote.as_posix()[2:]}'  # How Git's sftp-server names C:\... (/c/...).
    pub.INDEX = pub.FILES + '/published.json'
    log(' INFO ', f'sftp {client} -> {SERVER_EXE}, server folder {remote}')
    big = bytes(range(256)) * (8 << 12)  # 8 MiB

    def game_url(tag):
        return [f'https://{pub.SERVER_HOST}/game-{tag}/',
                f'https://github.com/bymarvin/azeroth-survivors-gamefiles/releases/download/game-{tag}/']

    def first():
        out, game = release(root, '0.0.14', big)
        target = remote / 'game-t1'
        target.mkdir()
        (target / 'Data-patch.MPQ-abc.xz.part').write_bytes(big[:3 << 20])  # Broken off at 3 MiB.
        runner = LocalSftp(client)
        assert pub.publish(out, json.loads((out / 'latest.json').read_text()), game_url('t1'), game, runner=runner) == 0
        for name in ('Data-patch.MPQ-abc.xz', 'exe-a.azp'):
            assert (target / name).read_bytes() == (game / name).read_bytes(), name
        assert not list(target.glob('*.part')), list(target.glob('*.part'))
        for p in out.iterdir():
            assert (remote / 'releases' / 'v0.0.14' / p.name).read_bytes() == p.read_bytes(), p.name
        assert (remote / 'latest.json').read_bytes() == (out / 'latest.json').read_bytes()
        lines = [line for batch in runner.batches for line in batch]
        assert any(line.startswith('reput ') and 'Data-patch' in line for line in lines), 'no resume'
        assert any(line.startswith('put ') and 'exe-a.azp' in line for line in lines), 'no fresh put'
        assert not any('\\' in line for line in lines), 'backslash in a batch line'
        return 'Windows paths with spaces, broken-off .part continued with reput, new files with put, byte-equal'
    test(f'{which} sftp: upload', first)

    def rerun():
        out, game = root / 'rel 0.0.14', root / 'game files 0.0.14'
        runner = LocalSftp(client)
        assert pub.publish(out, json.loads((out / 'latest.json').read_text()), game_url('t1'), game, runner=runner) == 0
        puts = [line for batch in runner.batches for line in batch
                if line.startswith(('put ', 'reput ')) and 'game-t1' in line]
        assert not puts, puts
        return 'second run: game files already there, nothing uploaded again'
    test(f'{which} sftp: rerun', rerun)

    def newer_and_cleanup():
        for version, tag in (('0.0.15', 't2'), ('0.0.16', 't3')):
            out, game = release(root, version, big[::-1])
            assert pub.publish(out, json.loads((out / 'latest.json').read_text()), game_url(tag), game,
                               runner=LocalSftp(client)) == 0
        assert json.loads((remote / 'latest.json').read_text())['version'].startswith('0.0.16')
        assert sorted(p.name for p in remote.iterdir() if p.name.startswith('game-')) == ['game-t2', 'game-t3']
        assert sorted(p.name for p in (remote / 'releases').iterdir()) == ['v0.0.15', 'v0.0.16']
        index = json.loads((remote / 'published.json').read_text())
        assert index == {'game': ['game-t2', 'game-t3'], 'releases': ['v0.0.15', 'v0.0.16']}, index
        return 'latest.json replaced by rename, oldest game folder and release removed, 2 kept'
    test(f'{which} sftp: newer releases and cleanup', newer_and_cleanup)

    def full_zip():
        import hashlib
        import zipfile
        for version, tag, size in (('0.0.17', 't4', 3 << 20), ('0.0.18', 't5', 1 << 20)):
            out, game = release(root, version, big)
            package = root / f'package {version}.zip'
            with zipfile.ZipFile(package, 'w') as z:
                z.writestr('Start-Coop.cmd', version * (size // len(version)))
            assert pub.publish(out, json.loads((out / 'latest.json').read_text()), game_url(tag), game,
                               runner=LocalSftp(client), full_zip=package) == 0
            served = remote / 'full' / pub.FULL_NAME
            assert served.read_bytes() == package.read_bytes(), version  # The newest replaced the previous one.
            expected = hashlib.sha256(package.read_bytes()).hexdigest() + '  ' + pub.FULL_NAME + chr(10)
            assert (remote / 'full' / (pub.FULL_NAME + '.sha256')).read_text() == expected
        assert sorted(p.name for p in (remote / 'full').iterdir()) == [pub.FULL_NAME, pub.FULL_NAME + '.sha256']
        return 'full zip under the fixed name, a newer one replaces it (rename), .sha256 next to it, no .part left'
    test(f'{which} sftp: full package zip', full_zip)

    shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
