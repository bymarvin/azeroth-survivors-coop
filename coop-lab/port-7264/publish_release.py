"""Publish a signed release folder (make_release.py --publish; boot-log format).

Order (players never see a half-uploaded release):
1. preflight: gh is logged in, the server answers over SFTP, the upload fits
   (free space after the planned cleanup); otherwise nothing is uploaded;
2. game file assets to every signed source: our server (azdeploy, SFTP chroot,
   /files/game-<hash>/, resumable, .part then rename) and the GitHub game file
   repository (release <tag>); only missing ones (names carry the SHA-256);
3. the release on GitHub (main repository): a new tag is created as a draft
   with every file and then published as "Latest" in one step; an existing tag
   gets its files replaced, latest.json and its signature last;
4. a mirror of the release folder on the server (/files/releases/<tag>/,
   latest.json and .sig last);
5. cleanup on the server: only the newest KEEP game versions and releases stay.
   The order comes from /files/published.json (written by every publish); a
   directory that is not listed there is never removed.
--publish-dry-run prints every command instead of running it. Standalone, for a folder that is
already signed (uploads exactly what the dry run showed):
  publish_release.py <release folder> --gamefiles <dir> --gamefiles-url URL ... [--publish]
"""
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path

SERVER_HOST = 'azsurvivors.duckdns.org'
SERVER_USER = 'azdeploy'
SERVER_KEY = Path.home() / '.ssh' / 'azsurvivors_upload'
FILES = '/files'
MAIN_REPO = 'bymarvin/azeroth-survivors-together'
KEEP = 2
MARGIN = 256 << 20
INDEX = FILES + '/published.json'
LATEST = ('latest.json.sig', 'latest.json')  # Uploaded last, signature before the description.


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


# A fixed sftp, not whichever comes first on PATH. Git's comes first: Windows' own OpenSSH ignores a key file
# whose ACL it finds too open (the upload key has an OWNER RIGHTS entry). Both get the same batch lines.
SFTP_CLIENTS = [str(p) for p in (Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'Git' / 'usr' / 'bin' / 'sftp.exe',
                                 Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'OpenSSH' / 'sftp.exe')
                if p.is_file()]
SFTP = SFTP_CLIENTS[0] if SFTP_CLIENTS else 'sftp'


def local_arg(path):
    """A local path for an sftp batch line: sftp reads a backslash inside quotes as an escape, so use /."""
    text = Path(path).resolve().as_posix()
    if '"' in text:
        raise RuntimeError(f'path with a quote cannot go into an sftp batch: {text}')
    return f'"{text}"'


class Runner:
    """Runs (or, dry, prints) sftp batches and gh commands."""

    def __init__(self, dry, host=SERVER_HOST, user=SERVER_USER, key=SERVER_KEY, connect=None, client=None):
        self.dry, self.host, self.user, self.key, self.client = dry, host, user, key, client or SFTP
        # Tests: connect=['-D', '<sftp-server>'] talks to a local sftp-server instead of the server.
        self.connect = connect or ['-i', str(key), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=20', f'{user}@{host}']
        self.commands = []

    def sftp(self, lines, read_only=False):
        if self.dry and not read_only:
            self.commands.append(('sftp', list(lines)))
            for line in lines:
                log(' CMD  ', f'sftp> {line}')
            return ''
        with tempfile.NamedTemporaryFile('w', suffix='.sftp', delete=False, encoding='utf-8') as batch:
            batch.write('\n'.join(lines) + '\n')
        try:
            run = subprocess.run([self.client, '-b', batch.name, *self.connect],
                                 capture_output=True, text=True, encoding='utf-8', errors='replace',
                                 stdin=subprocess.DEVNULL, timeout=6 * 3600)
        finally:
            os.unlink(batch.name)
        if run.returncode:
            raise RuntimeError(f'sftp failed: {(run.stderr or run.stdout).strip()[-400:]}')
        return run.stdout

    def read_file(self, remote):
        """Text of a small remote file, or None if it is missing."""
        with tempfile.TemporaryDirectory() as folder:
            local = Path(folder) / 'file'
            try:
                Runner.sftp(self, [f'get "{remote}" {local_arg(local)}'], read_only=True)
            except RuntimeError:
                return None
            return local.read_text(encoding='utf-8') if local.exists() else None

    def gh(self, *args, read_only=False, check=True):
        if self.dry and not read_only:
            self.commands.append(('gh', list(args)))
            log(' CMD  ', 'gh ' + ' '.join(f'"{a}"' if ' ' in a else a for a in args))
            return ''
        run = subprocess.run(['gh', *args], capture_output=True, text=True, encoding='utf-8', errors='replace',
                             stdin=subprocess.DEVNULL, timeout=6 * 3600)
        if check and run.returncode:
            raise RuntimeError(f'gh {args[0]} {args[1] if len(args) > 1 else ""} failed: '
                               f'{(run.stderr or run.stdout).strip()[-400:]}')
        return run.stdout if not run.returncode else None


def parse_listing(text):
    """{name: (size, is_dir)} from `sftp ls -l` output."""
    entries = {}
    for line in text.splitlines():
        parts = line.split(None, 8)
        if len(parts) == 9 and parts[0][:1] in '-d' and parts[4].isdigit():
            entries[parts[8].rstrip('/').rsplit('/', 1)[-1]] = (int(parts[4]), parts[0][0] == 'd')
    return entries


def parse_df(text):
    """Available bytes from `sftp df` (sizes in KiB): Size Used Avail (Root) %Capacity."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and all(p.isdigit() for p in parts[:3]):
            return int(parts[2]) * 1024
    raise RuntimeError(f'cannot read the free space from: {text.strip()[-200:]}')


def sources(urls):
    """Server directories and GitHub (repo, tag) pairs among the signed game file sources."""
    server, github = [], []
    for url in urls:
        parts = urllib.parse.urlsplit(url)
        if parts.hostname == SERVER_HOST:
            server.append(FILES + parts.path.rstrip('/'))
        else:
            match = re.fullmatch(r'/([^/]+)/([^/]+)/releases/download/([^/]+)/', parts.path)
            if parts.hostname != 'github.com' or not match:
                raise RuntimeError(f'unknown game file source {url}: only {SERVER_HOST} and GitHub releases')
            github.append((f'{match.group(1)}/{match.group(2)}', match.group(3)))
    return server, github


def release_tag(version):
    match = re.match(r'(\d+\.\d+\.\d+)', version)
    if not match:
        raise RuntimeError(f'no release tag for version {version}')
    return 'v' + match.group(1)


def publish(out, latest, urls, gamefiles, dry=False, runner=None):
    """Upload everything. Returns 0, or 1 before anything was uploaded if a check fails."""
    try:
        return _publish(out, latest, urls, gamefiles, dry, runner)
    except RuntimeError as error:  # sftp/gh failed: what is up stays, a rerun skips it and continues.
        log('FAILED', f'Veröffentlichen: {error}; nochmal starten setzt fort (latest.json kommt immer zuletzt)')
        return 1


def _publish(out, latest, urls, gamefiles, dry, runner):
    runner = runner or Runner(dry)
    t0 = time.time()
    tag = release_tag(latest['version'])
    release_files = sorted(p for p in out.iterdir() if p.is_file() and p.name != 'UPLOAD.txt' and p.name not in LATEST)
    release_files += [out / name for name in LATEST]
    game_assets = sorted(p for p in (gamefiles.iterdir() if gamefiles else ()) if p.suffix in ('.azp', '.xz', '.raw'))
    server_game, github_game = sources(urls) if game_assets else ([], [])

    started = time.time()
    log(' .... ', 'Veröffentlichen: Vorprüfung')
    if runner.gh('auth', 'status', read_only=True, check=False) is None:
        log('FAILED', 'Veröffentlichen: gh ist nicht angemeldet (gh auth login); nichts hochgeladen')
        return 1
    listing = parse_listing(runner.sftp([f'ls -l "{FILES}"'], read_only=True))
    releases = parse_listing(runner.sftp([f'ls -l "{FILES}/releases"'], read_only=True)) if 'releases' in listing else {}
    free = parse_df(runner.sftp([f'df "{FILES}"'], read_only=True))
    existing = {}
    for directory in server_game:
        name = directory.rsplit('/', 1)[-1]
        existing[directory] = parse_listing(runner.sftp([f'ls -l "{directory}"'], read_only=True)) if name in listing else {}
    upload = [(directory, p) for directory in server_game for p in game_assets
              if existing[directory].get(p.name, (None,))[0] != p.stat().st_size]
    needed = sum(p.stat().st_size for _, p in upload) + sum(p.stat().st_size for p in release_files)
    try:
        index = json.loads(runner.read_file(INDEX) or '{}')
    except ValueError:
        index = {}
    game_order = [n for n in index.get('game', []) if n in listing]
    release_order = [n for n in index.get('releases', []) if n in releases]
    current = [d.rsplit('/', 1)[-1] for d in server_game]
    game_order = [n for n in game_order if n not in current] + current  # Oldest first, this release last.
    release_order = [n for n in release_order if n != tag] + [tag]
    old_game = game_order[:max(0, len(game_order) - KEEP)]
    old_releases = release_order[:max(0, len(release_order) - KEEP)]
    freed = 0
    for name in old_game:
        freed += sum(s for s, _ in parse_listing(runner.sftp([f'ls -l "{FILES}/{name}"'], read_only=True)).values())
    if free + freed < needed + MARGIN:
        log('FAILED', f'Veröffentlichen: zu wenig Platz auf dem Server ({free / 2**30:.2f} GiB frei, nach dem Aufräumen '
                      f'{(free + freed) / 2**30:.2f} GiB, gebraucht {(needed + MARGIN) / 2**30:.2f} GiB); nichts hochgeladen')
        return 1
    log('  OK  ', f'Veröffentlichen: Vorprüfung ({time.time() - started:.1f} s, Server {free / 2**30:.2f} GiB frei, '
                  f'{len(upload)} Spieldatei-Assets fehlen dort ({sum(p.stat().st_size for _, p in upload) / 2**20:.0f} MiB), '
                  f'aufräumen danach: {old_game + [f"releases/{r}" for r in old_releases] or "nichts"})')

    def put_all(directory, paths):
        # reput resumes, but refuses a .part that does not exist yet: fresh files go up with put.
        partial = parse_listing(runner.sftp([f'-ls -l "{directory}"'], read_only=True))
        lines = [f'-mkdir "{directory}"']
        for p in paths:
            part = f'"{directory}/{p.name}.part"'
            have = partial.get(p.name + '.part', (None,))[0]
            if have != p.stat().st_size:
                lines.append(f'{"reput" if have and have < p.stat().st_size else "put"} {local_arg(p)} {part}')
            lines.append(f'rename {part} "{directory}/{p.name}"')
        runner.sftp(lines)

    for directory in server_game:
        started = time.time()
        paths = [p for d, p in upload if d == directory]
        log(' .... ', f'Spieldateien -> {SERVER_HOST}{directory[len(FILES):]}/')
        if paths:
            put_all(directory, paths)
        log('  OK  ', f'Spieldateien -> {SERVER_HOST}{directory[len(FILES):]}/ ({time.time() - started:.1f} s, '
                      f'{len(paths)} hochgeladen, {len(game_assets) - len(paths)} schon da)')
    for repo, game_tag in github_game:
        started = time.time()
        log(' .... ', f'Spieldateien -> GitHub {repo} {game_tag}')
        view = runner.gh('release', 'view', game_tag, '-R', repo, '--json', 'assets', read_only=True, check=False)
        if view is None:
            runner.gh('release', 'create', game_tag, '-R', repo, '--title', f'Game files {game_tag}', '--notes',
                      'Game file patches and full assets for the Azeroth Survivors Together updater (signed by the release).')
            have = {}
        else:
            have = {a['name']: a['size'] for a in json.loads(view)['assets']}
        missing = [p for p in game_assets if have.get(p.name) != p.stat().st_size]
        if missing:
            runner.gh('release', 'upload', game_tag, '-R', repo, '--clobber', *map(str, missing))
        log('  OK  ', f'Spieldateien -> GitHub {repo} {game_tag} ({time.time() - started:.1f} s, '
                      f'{len(missing)} hochgeladen, {len(game_assets) - len(missing)} schon da)')

    started = time.time()
    log(' .... ', f'Release {tag} -> GitHub {MAIN_REPO}')
    if runner.gh('release', 'view', tag, '-R', MAIN_REPO, '--json', 'tagName', read_only=True, check=False) is None:
        runner.gh('release', 'create', tag, '-R', MAIN_REPO, '--draft', '--title', f'Azeroth Survivors Together {tag}',
                  '--notes', f'Co-op {latest["version"]}. Update: Start-Coop.cmd does it automatically, or run '
                             'Azeroth-Survivors-Together-Updater.exe in your game folder.', *map(str, release_files))
        runner.gh('release', 'edit', tag, '-R', MAIN_REPO, '--draft=false', '--latest')
        how = 'neu, als Entwurf hochgeladen und dann als Latest veröffentlicht'
    else:
        runner.gh('release', 'upload', tag, '-R', MAIN_REPO, '--clobber', *map(str, release_files[:-2]))
        runner.gh('release', 'upload', tag, '-R', MAIN_REPO, '--clobber', *map(str, release_files[-2:]))
        runner.gh('release', 'edit', tag, '-R', MAIN_REPO, '--latest')
        how = 'vorhanden, Dateien ersetzt (latest.json zuletzt)'
    log('  OK  ', f'Release {tag} -> GitHub {MAIN_REPO} ({time.time() - started:.1f} s, {how})')

    started = time.time()
    log(' .... ', f'Release-Spiegel -> {SERVER_HOST}/releases/{tag}/')
    put_all(f'{FILES}/releases', [])
    put_all(f'{FILES}/releases/{tag}', release_files)
    put_all(FILES, [out / name for name in LATEST])
    log('  OK  ', f'Release-Spiegel ({time.time() - started:.1f} s, latest.json zuletzt)')

    started = time.time()
    log(' .... ', 'Server aufräumen')
    with tempfile.TemporaryDirectory() as folder:
        index_file = Path(folder) / 'published.json'
        index_file.write_text(json.dumps(dict(game=[n for n in game_order if n not in old_game],
                                              releases=[n for n in release_order if n not in old_releases]), indent=1),
                              encoding='utf-8')
        put_all(FILES, [index_file])
    lines = []
    for directory in [f'{FILES}/{n}' for n in old_game] + [f'{FILES}/releases/{n}' for n in old_releases]:
        # File by file from the listing: sftp does not expand a * inside quotes.
        entries = parse_listing(runner.sftp([f'ls -l "{directory}"'], read_only=True))
        lines += [f'rm "{directory}/{name}"' for name, (_, is_dir) in sorted(entries.items()) if not is_dir]
        lines.append(f'rmdir "{directory}"')
    if lines:
        runner.sftp(lines)
    log('  OK  ', f'Server aufräumen ({time.time() - started:.1f} s, entfernt: {old_game + old_releases or "nichts"})')
    log(' INFO ', f'Veröffentlicht: {tag} ({time.time() - t0:.0f} s)' + (' [Probelauf, nichts ausgeführt]' if dry else ''))
    return 0


def main():
    """Publish a release folder that make_release.py already signed (the same bytes as its dry run)."""
    import argparse
    ap = argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument('release', type=Path, help='folder of make_release.py (latest.json, latest.json.sig, ...)')
    ap.add_argument('--gamefiles', type=Path, help='folder of make_game_patches.py')
    ap.add_argument('--gamefiles-url', action='append', default=[], help='as given to make_release.py, same order')
    ap.add_argument('--publish', action='store_true', help='really upload (without it: dry run, only prints)')
    args = ap.parse_args()
    latest = json.loads((args.release / 'latest.json').read_text(encoding='utf-8'))
    manifest = json.loads((args.release / latest['manifest']['asset']).read_text(encoding='utf-8'))
    signed = (manifest.get('gamefiles') or {}).get('urls') or [(manifest.get('gamefiles') or {}).get('url')]
    if args.gamefiles and signed != args.gamefiles_url:
        log('FAILED', f'--gamefiles-url {args.gamefiles_url} weicht von der signierten Liste {signed} ab')
        return 1
    return publish(args.release, latest, args.gamefiles_url, args.gamefiles, dry=not args.publish)


if __name__ == '__main__':
    raise SystemExit(main())
