"""Build the upload folder of one self-updater release (boot-log format).

  make_release.py --target <staged package folder> [--game-sources game-sources.json]
                  --updater-exe <built updater exe> [--updater-version N] [--min-updater N]
                  [--sequence N] [--announce-key KEY] [--retire-key KEY] [--key-dir DIR] [--out DIR]
                  [--full-package-url URL] [--no-check-urls] [--installer-exe EXE] [--publish | --publish-dry-run]

Output (upload everything except UPLOAD.txt as assets of ONE GitHub release):
  latest.json, latest.json.sig     signed release description (fixed names)
  manifest-<version>.json          every file with SHA-256, size and source
  mod-<version>.zip                mod files (reconstruction, analysis, relay, launcher)
  runtime-<version>.zip            .coop-runtime and .tools (normally never downloaded)
  Azeroth-Survivors-Together-Updater.exe
  Azeroth-Survivors-Together-Installer.exe   (with --installer-exe; must embed the signing key)
Game files (AzerothSurvivors.exe, Data/*) are never put on GitHub: their HTTPS
address comes from game-sources.json ({"<path>": "https://..."}) and their
SHA-256 from the staged package; UPLOAD.txt lists what must be reachable there.
A game file without an address (no direct host) gets the release page on
GitHub as its source (UNHOSTED). Folders that already have the file (same game
version) never download it. For a folder of another game version that address
answers with a web page at once, so the updater stops before downloading or
installing anything and shows the signed --full-package-url (works with the
bound self_update.py, no client change).
Every game file address is probed (first KiB via HTTP Range): it must deliver the
file itself with the signed size, not a web page. Hosts with a download page or
captcha in between (storage.to, uploadex and similar) cannot work; players then
get the signed --full-package-url instead and nothing is installed halfway.
"""
import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'reconstruction'), str(ROOT / 'coop-lab/updater')]
import self_update  # noqa: E402
import sign_release  # noqa: E402


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def kind(path):
    if path == self_update.EXE or path.startswith('Data/'):
        return 'game'
    if path.startswith(('.coop-runtime/', '.tools/')):
        return 'runtime'
    return 'mod'


UNHOSTED = self_update.RELEASE_URL.split('/releases/')[0] + '/releases'  # Always a page, never the file.
INSTALLER_ASSET = 'Azeroth-Survivors-Together-Installer.exe'


def asset(path):
    return dict(asset=path.name, sha256=sha256(path), size=path.stat().st_size)


def probe(net, url, size):
    """None if the address delivers the file directly (size matches), else the reason."""
    try:
        request = urllib.request.Request(url, headers={'Range': 'bytes=0-1023'})
        with net.open(request) as response:
            kind = (response.headers.get('Content-Type') or '').lower()
            head = response.read(1024)
            total = response.headers.get('Content-Range', '').rpartition('/')[2]
            length = int(total) if total.isdigit() else int(response.headers.get('Content-Length') or -1)
    except urllib.error.HTTPError as error:
        return f'answers {error.code}'
    except (self_update.Refused, OSError, ValueError) as error:
        return str(error)
    if kind.startswith(('text/html', 'application/xhtml')) or head.lstrip()[:15].lower().startswith(
            (b'<!doctype html', b'<html')):
        return 'answers with a web page (download page or captcha), not the file'
    if response.status == 206 and length != size:
        return f'delivers {length} bytes, the file has {size}'
    if response.status == 200 and length not in (-1, size):
        return f'delivers {length} bytes, the file has {size}'
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', type=Path, required=True)
    ap.add_argument('--game-sources', type=Path, help='{path: HTTPS address} of game files; without: full package only')
    ap.add_argument('--updater-exe', type=Path, required=True)
    ap.add_argument('--updater-version', type=int, default=self_update.UPDATER_VERSION)
    ap.add_argument('--min-updater', type=int, default=1)
    ap.add_argument('--sequence', type=int, help='default: seconds since 1970 (monotonic between releases)')
    ap.add_argument('--announce-key', action='append', default=[])
    ap.add_argument('--retire-key', action='append', default=[])
    ap.add_argument('--key-dir', type=Path, default=sign_release.KEY_DIR)
    ap.add_argument('--out', type=Path)
    ap.add_argument('--full-package-url', default='https://azsurvivors.duckdns.org/full/Azeroth-Survivors-Together.zip',
                    help='HTTPS page or file of the full package (shown when game files cannot be downloaded directly); '
                         'default: the newest full zip on the server (publish_release --full-zip)')
    ap.add_argument('--full-zip', type=Path, help='with --publish: the full package zip for that address')
    ap.add_argument('--no-check-urls', action='store_true', help='do not probe the game file addresses')
    ap.add_argument('--allow-local-http', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--unhosted-source', default=UNHOSTED, help=argparse.SUPPRESS)  # Tests: a local page.
    ap.add_argument('--installer-exe', type=Path, help=f'built web installer, shipped as {INSTALLER_ASSET}')
    ap.add_argument('--publish', action='store_true',
                    help='after signing: game files to every source, the release to GitHub, a mirror to the server')
    ap.add_argument('--publish-dry-run', action='store_true', help='print the publish commands instead of running them')
    ap.add_argument('--gamefiles', type=Path, help='folder of coop-lab/updater/make_game_patches.py (gamefiles.json)')
    ap.add_argument('--gamefiles-url', action='append', default=[],
                    help='HTTPS base address of those assets, ending in /, e.g. '
                         'https://github.com/bymarvin/azeroth-survivors-gamefiles/releases/download/<tag>/; '
                         'several in the order the updater tries them (updater 4)')
    args = ap.parse_args()

    t = time.time()
    log(' .... ', 'Paket lesen')
    target = json.loads((args.target / 'package-manifest.json').read_text(encoding='utf-8'))
    version = (args.target / 'COOP-VERSION.txt').read_text(encoding='utf-8').strip()
    sources = json.loads(args.game_sources.read_text(encoding='utf-8')) if args.game_sources else {}
    # Asset names: GitHub renames other characters (e.g. '+'), the signed names must stay exact.
    tag = re.sub(r'[^0-9A-Za-z._-]', '-', version)
    out = args.out or Path(r'D:\Azeroth Survivors Together Releases') / f'github-{tag}'
    out.mkdir(parents=True, exist_ok=True)
    bad = [p for p in target if not self_update.safe_path(p) or self_update.user_area(p)]
    if bad:
        log('FAILED', f'Paket lesen: unzulässiger Pfad {bad[0]}')
        return 1
    wrong = [p for p in target if sha256(args.target / p) != target[p]]
    if wrong:
        log('FAILED', f'Paket lesen: {wrong[0]} passt nicht zum Paketmanifest')
        return 1
    shipped = target.get(self_update.UPDATER_ASSET)
    if shipped and (shipped != sha256(args.updater_exe) or args.min_updater < 3):
        # The package ships the updater: the release asset must be the same exe, and only updater 3+
        # can replace its own running exe as part of an update.
        log('FAILED', 'Paket lesen: die Updater-exe im Paket muss gleich --updater-exe sein und --min-updater >= 3')
        return 1
    log('  OK  ', f'Paket lesen ({time.time() - t:.1f} s, co-op {version}, {len(target)} Dateien'
                  + (', mit Updater-exe' if shipped else '') + ')')

    t = time.time()
    log(' .... ', 'Quellen der Spieldateien prüfen')
    net = self_update.Net('https://example.invalid/', allow_local_http=args.allow_local_http)
    hosted = sorted(p for p in target if kind(p) == 'game' and p in sources)
    offline = sorted(p for p in target if kind(p) == 'game' and p not in sources)
    if offline:
        if not args.full_package_url:
            log('FAILED', f'Quellen: {len(offline)} Spieldateien ohne Adresse (z. B. {offline[0]}) brauchen '
                          '--full-package-url')
            return 1
        log(' WARN ', f'{len(offline)} Spieldateien ohne Adresse (z. B. {offline[0]}): nur im Vollpaket; Ordner einer '
                      'anderen Spielversion bekommen den Vollpaket-Link')
    game = hosted
    try:
        for p in game:
            net.check_scheme(sources[p])
            net.allow(sources[p])
        if args.full_package_url and not args.full_package_url.startswith('https://'):
            raise self_update.Refused(f'Refusing a non-HTTPS address: {args.full_package_url}')
    except self_update.Refused as error:
        log('FAILED', f'Quellen: {error}')
        return 1
    if not args.no_check_urls and game:
        with ThreadPoolExecutor(min(self_update.threads(), len(game))) as pool:
            problems = list(pool.map(lambda p: probe(net, sources[p], (args.target / p).stat().st_size), game))
        bad = [(p, why) for p, why in zip(game, problems) if why]
        for p, why in bad:
            log(' WARN ', f'{p}: {sources[p].split("?")[0]} {why}')
        if bad:
            log('FAILED', f'Quellen: {len(bad)} Adressen liefern die Datei nicht direkt. Direkte HTTPS-Links nötig '
                          '(ohne Zwischenseite/Captcha), sonst bekommen Spieler nur den Hinweis aufs Vollpaket')
            return 1
    if not args.full_package_url:
        log(' WARN ', 'Kein --full-package-url: bei neuen Spieldateien ohne Direktlink sehen Spieler nur '
                      '"Vollpaket von der Release-Seite laden"')
    log('  OK  ', f'Quellen der Spieldateien prüfen ({time.time() - t:.1f} s, {len(game)} Spieldateien extern'
                  + (', Adressen nicht geprüft' if args.no_check_urls else ', alle liefern direkt') + ')')

    t = time.time()
    log(' .... ', 'Archive bauen')
    archives = {}
    for name in ('mod', 'runtime'):
        paths = sorted(p for p in target if kind(p) == name)
        path = out / f'{name}-{tag}.zip'
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for p in paths:
                info = zipfile.ZipInfo(p, date_time=(2020, 1, 1, 0, 0, 0))  # Reproducible archives.
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, (args.target / p).read_bytes())
        archives[name] = asset(path)
        log(' INFO ', f'{path.name}: {len(paths)} Dateien, {path.stat().st_size / 2**20:.1f} MiB')
    log('  OK  ', f'Archive bauen ({time.time() - t:.1f} s)')

    t = time.time()
    log(' .... ', 'Manifest und latest.json schreiben')
    files = {}
    patches = {}
    if args.gamefiles:
        # Updater 2: game files as binary patches / full assets from the game file release.
        patches = json.loads((args.gamefiles / 'gamefiles.json').read_text(encoding='utf-8'))
        urls = args.gamefiles_url
        good = urls and all(u.endswith('/') and (u.startswith('https://') or args.allow_local_http and
                                                  u.startswith('http://127.0.0.1:')) for u in urls)
        raw = any((v.get('full') or {}).get('encoding') == 'raw' for v in patches.values())
        need = 4 if len(urls) > 1 or raw else 2
        if args.min_updater < need or not good:
            log('FAILED', f'Spielpatches brauchen --min-updater {need} und --gamefiles-url https://.../ (mit /)'
                          + (' (mehrere Quellen oder Raw-Assets: Updater 4)' if need == 4 else ''))
            return 1
        stale = [p for p in patches if p not in target or patches[p]['sha256'] != target[p]]
        if stale:
            log('FAILED', f'Spielpatches passen nicht zum Paket: {stale[0]}')
            return 1
    for p in sorted(target):
        entry = dict(sha256=target[p], size=(args.target / p).stat().st_size)
        if kind(p) != 'game':
            entry['source'] = dict(archive=kind(p))
        elif p in patches:
            entry['source'] = dict(patches=[{k: e[k] for k in ('from_sha256', 'asset', 'sha256', 'size')}
                                            for e in patches[p]['patches']])
            if patches[p].get('full'):
                entry['source']['full'] = {k: patches[p]['full'][k] for k in ('asset', 'sha256', 'size', 'encoding')
                                           if k in patches[p]['full']}
        else:
            # Full package only: a page, never this file (stops at once, see UNHOSTED).
            entry['source'] = dict(url=sources.get(p, args.unhosted_source))
        files[p] = entry
    manifest = out / f'manifest-{tag}.json'
    body = dict(version=version, files=files)
    if patches:
        # Updater 2/3 read one "url"; updater 4 tries "urls" in this signed order.
        body['gamefiles'] = dict(urls=args.gamefiles_url) if args.min_updater >= 4 else dict(url=args.gamefiles_url[0])
    manifest.write_text(json.dumps(body, indent=1, sort_keys=True), encoding='utf-8')
    updater = out / self_update.UPDATER_ASSET
    updater.write_bytes(args.updater_exe.read_bytes())
    latest = dict(format=1, product=self_update.PRODUCT, version=version,
                  sequence=args.sequence or int(time.time()),
                  signed_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                  min_updater=args.min_updater,
                  updater=dict(asset(updater), version=args.updater_version),
                  manifest=asset(manifest), archives=archives,
                  keys=dict(add=args.announce_key, retire=args.retire_key))
    if args.full_package_url:
        latest['full_package'] = dict(url=args.full_package_url)
    data = json.dumps(latest, indent=1, sort_keys=True).encode('utf-8')
    self_update.validate_latest(latest)
    (out / 'latest.json').write_bytes(data)
    log('  OK  ', f'Manifest und latest.json schreiben ({time.time() - t:.1f} s, sequence {latest["sequence"]})')

    t = time.time()
    log(' .... ', 'Signieren')
    signature = sign_release.sign_bytes(data, args.key_dir)
    (out / 'latest.json.sig').write_bytes(signature)
    key = sign_release.public(sign_release.load(args.key_dir))
    if self_update.verify(data, signature, [key]) != key:
        log('FAILED', 'Signieren: Signatur lässt sich nicht prüfen')
        return 1
    if key not in self_update.TRUSTED_KEYS:
        log(' WARN ', 'Signierschlüssel steht nicht in self_update.TRUSTED_KEYS (nur ein angekündigter Schlüssel '
                      'oder ein Test): bestehende Updater nehmen dieses Release nur nach einer Ankündigung an')
    log('  OK  ', f'Signieren ({time.time() - t:.1f} s, Schlüssel {key[:12]}...)')
    if args.installer_exe:
        # The installer trusts the keys of the self_update.py it embeds: this release's key must be among them.
        installer = args.installer_exe.read_bytes()
        if installer[:2] != b'MZ' or key.encode('ascii') not in installer:
            log('FAILED', f'Installer: {args.installer_exe} ist keine exe oder vertraut dem Signierschlüssel nicht')
            return 1
        (out / INSTALLER_ASSET).write_bytes(installer)
        log('  OK  ', f'Installer ({len(installer)} B, sha256 {sha256(out / INSTALLER_ASSET)[:16]}..., kennt den Schlüssel)')

    lines = [f'Release co-op {version} (sequence {latest["sequence"]})', '',
             'Upload as assets of ONE GitHub release (mark it "Latest"):']
    lines += [f'  {name}' for name in ('latest.json', 'latest.json.sig', manifest.name,
                                        f'mod-{tag}.zip', f'runtime-{tag}.zip', updater.name)
              + ((INSTALLER_ASSET,) if args.installer_exe else ())]
    lines += ['', 'Game files - must be downloadable at exactly these HTTPS addresses (never on GitHub):']
    lines += [f'  {p}  {files[p]["size"]} bytes  sha256 {files[p]["sha256"]}' + chr(10) + f'      {sources[p]}'
              for p in game] or ['  (none)']
    if patches:
        assets = sorted({e['asset'] for v in patches.values() for e in v['patches'] + ([v['full']] if v.get('full') else [])})
        lines += ['', f'Game file assets: upload to every game file source {", ".join(args.gamefiles_url)}',
                  f'  (from {args.gamefiles}):'] + [f'  {a}' for a in assets]
        lines += ['', 'Folders whose game files have neither a patch nor a full asset are sent to',
                  f'  {args.full_package_url or "MISSING --full-package-url (players see: from the release page)"}']
    else:
        lines += ['', f'Game files only in the full package ({len(offline)}): folders of another game version are sent to',
                  f'  {args.full_package_url or "MISSING --full-package-url (players see: from the release page)"}']
    (out / 'UPLOAD.txt').write_text(chr(10).join(lines) + chr(10), encoding='utf-8')
    log(' INFO ', f'Upload-Ordner {out} (siehe UPLOAD.txt)')
    if args.publish or args.publish_dry_run:
        sys.path.insert(0, str(Path(__file__).resolve().parent))  # python -I leaves the script folder out.
        import publish_release
        return publish_release.publish(out, latest, args.gamefiles_url, args.gamefiles, dry=not args.publish,
                                       full_zip=args.full_zip)
    return 0


if __name__ == '__main__':
    sys.exit(main())
