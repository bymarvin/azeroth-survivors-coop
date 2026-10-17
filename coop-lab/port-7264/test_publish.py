"""Tests for publish_release.py with a simulated server and GitHub (no network; boot-log format)."""
import sys
import tempfile
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish_release as pub  # noqa: E402

RESULTS = []
GITHUB = 'https://github.com/bymarvin/azeroth-survivors-gamefiles/releases/download/game-7264d50b/'
SERVER = 'https://azsurvivors.duckdns.org/game-7264d50b/'


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


def ls(entries):
    """sftp ls -l output: {name: size} files, {name: None} directories."""
    return '\n'.join(f'{"d" if size is None else "-"}rwxr-xr-x    ? 997 986 {size or 4096} Oct 17 05:00 /files/x/{name}'
                     for name, size in entries.items())


class Fake(pub.Runner):
    """Answers read-only queries from a simulated state, records every changing command in order."""

    def __init__(self, server, free, gh_logged_in=True, game_releases=None, main_tags=()):
        super().__init__(dry=False)
        self.server, self.free, self.logged_in = server, free, gh_logged_in
        self.game_releases, self.main_tags, self.log = game_releases or {}, set(main_tags), []
        self.index = None

    def read_file(self, remote):
        return self.index
    def sftp(self, lines, read_only=False):
        if read_only:
            line = lines[0]
            if line.startswith('df '):
                return f'        Size         Used        Avail       (root)    %Capacity\n 10000000 3000000 {self.free // 1024} 0 30%'
            path = line.split()[-1].strip('"')
            return ls(self.server.get(path, {}))
        self.log.append(('sftp', lines))
        return ''

    def gh(self, *args, read_only=False, check=True):
        if args[:2] == ('auth', 'status'):
            return 'ok' if self.logged_in else None
        if args[:2] == ('release', 'view'):
            tag, repo = args[2], args[4]
            if repo == pub.MAIN_REPO:
                return '{"tagName": "%s"}' % tag if tag in self.main_tags else None
            assets = self.game_releases.get((repo, tag))
            return None if assets is None else '{"assets": [%s]}' % ', '.join(
                '{"name": "%s", "size": %d}' % item for item in assets.items())
        self.log.append(('gh', list(args)))
        return ''


def folders():
    root = Path(tempfile.mkdtemp())
    out, game = root / 'release', root / 'gamefiles'
    out.mkdir()
    game.mkdir()
    for name, size in (('latest.json', 900), ('latest.json.sig', 64), ('manifest-0.0.14.json', 2000),
                       ('mod-0.0.14.zip', 3000), ('runtime-0.0.14.zip', 4000), ('Azeroth-Survivors-Together-Updater.exe', 5000),
                       ('UPLOAD.txt', 10)):
        (out / name).write_bytes(b'x' * size)
    for name, size in (('exe-a.azp', 600), ('Data-patch.MPQ-abc.raw', 50000)):
        (game / name).write_bytes(b'y' * size)
    return out, game


LATEST = {'version': '0.0.14-community+game-7264d50b'}


def main():
    def normal():
        out, game = folders()
        server = {'/files': {'game-1': None, 'game-2': None, 'game-7264d50b': None, 'releases': None,
                             'latest.json': 10},
                  '/files/game-7264d50b': {'exe-a.azp': 600},  # Already there: skipped.
                  '/files/game-1': {'old.raw': 1 << 30}, '/files/game-2': {'older.raw': 10},
                  '/files/releases': {'v0.0.12': None, 'v0.0.13': None}}
        fake = Fake(server, free=1 << 30, game_releases={('bymarvin/azeroth-survivors-gamefiles', 'game-7264d50b'): {}})
        fake.index = '{"game": ["game-1", "game-2"], "releases": ["v0.0.12", "v0.0.13"]}'
        assert pub.publish(out, LATEST, [GITHUB, SERVER], game, runner=fake) == 0
        flat = [(kind, ' '.join(cmd)) for kind, cmd in fake.log]
        uploads = [c for k, c in flat if k == 'sftp' and 'put "' in c]
        assert 'Data-patch.MPQ-abc.raw' in uploads[0] and 'exe-a.azp' not in uploads[0], uploads[0]
        create = next(i for i, (k, c) in enumerate(flat) if c.startswith('release create v0.0.14'))
        game_up = next(i for i, (k, c) in enumerate(flat) if 'put "' in c and 'game-7264d50b' in c)
        gh_game = next(i for i, (k, c) in enumerate(flat) if 'upload game-7264d50b' in c)
        assert game_up < create and gh_game < create, flat  # Game files are everywhere before the release exists.
        assert '--draft' in flat[create][1] and 'UPLOAD.txt' not in flat[create][1]
        assert flat[create + 1][1].startswith('release edit v0.0.14') and '--latest' in flat[create + 1][1]
        mirror = [c for k, c in flat if k == 'sftp' and '/files/releases/v0.0.14' in c][0]
        assert mirror.index('latest.json.sig.part') > mirror.index('runtime-0.0.14.zip'), mirror
        root_latest = [c for k, c in flat if k == 'sftp' and '"/files/latest.json.part"' in c][0]
        assert root_latest.index('latest.json.sig') < root_latest.index('"/files/latest.json.part"'), root_latest
        cleanup = flat[-1][1]
        assert 'rmdir "/files/game-1"' in cleanup and 'v0.0.12' in cleanup and 'game-2' not in cleanup \
            and 'v0.0.13' not in cleanup and 'game-7264d50b' not in cleanup, cleanup
        index = [c for k, c in flat if 'published.json' in c][0]
        assert 'put "' in index and chr(92) not in index, index  # Local paths with / (sftp eats backslashes).
        return 'skips existing assets, game files before the draft release, latest.json last, keeps 2 versions by publish order'
    test('Publish order, skip, cleanup', normal)

    def existing_tag():
        out, game = folders()
        fake = Fake({'/files': {'game-7264d50b': None}, '/files/game-7264d50b': {}}, free=1 << 30,
                    game_releases={('bymarvin/azeroth-survivors-gamefiles', 'game-7264d50b'): {'exe-a.azp': 600,
                                                                                               'Data-patch.MPQ-abc.raw': 50000}},
                    main_tags={'v0.0.14'})
        assert pub.publish(out, LATEST, [GITHUB, SERVER], game, runner=fake) == 0
        flat = [' '.join(cmd) for kind, cmd in fake.log if kind == 'gh']
        assert not any('upload game-7264d50b' in c for c in flat), flat  # Nothing missing on GitHub.
        uploads = [c for c in flat if c.startswith('release upload v0.0.14')]
        assert 'latest.json' not in uploads[0] and uploads[1].endswith('latest.json'), uploads
        return 'existing tag: files replaced, latest.json in the last upload; complete game release left alone'
    test('Existing release tag', existing_tag)

    def refused():
        out, game = folders()
        fake = Fake({'/files': {}}, free=1 << 30, gh_logged_in=False)
        assert pub.publish(out, LATEST, [GITHUB, SERVER], game, runner=fake) == 1 and not fake.log
        fake = Fake({'/files': {}}, free=10_000)  # Less than the upload plus margin.
        assert pub.publish(out, LATEST, [GITHUB, SERVER], game, runner=fake) == 1 and not fake.log
        return 'gh not logged in / too little space on the server: nothing uploaded'
    test('Preflight refuses before uploading', refused)

    def parsing():
        assert pub.release_tag('0.0.14-community+game-7264d50b') == 'v0.0.14'
        server, github = pub.sources([GITHUB, SERVER])
        assert server == ['/files/game-7264d50b'] and github == [('bymarvin/azeroth-survivors-gamefiles', 'game-7264d50b')]
        try:
            pub.sources(['https://example.com/x/'])
        except RuntimeError:
            pass
        else:
            raise AssertionError('unknown source accepted')
        listing = pub.parse_listing('-rw-r--r--    ? 997      986     1340199244 Oct 17 05:00 /files/game-x/Data-patch.MPQ-1.raw\n'
                                    'drwxr-xr-x    ? 997      986           4096 Oct 17 05:00 /files/releases')
        assert listing == {'Data-patch.MPQ-1.raw': (1340199244, False), 'releases': (4096, True)}, listing
        assert pub.parse_df('        Size         Used        Avail       (root)    %Capacity\n'
                            '    10146860      2726880      6898228      7419980          27%') == 6898228 * 1024
        return 'tag, sources, sftp ls -l and df output'
    test('Parsing', parsing)

    log(' INFO ', f'Zusammenfassung: {sum(RESULTS)}/{len(RESULTS)} bestanden')
    return 0 if all(RESULTS) else 1


if __name__ == '__main__':
    sys.exit(main())
