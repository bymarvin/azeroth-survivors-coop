"""Azeroth Survivors Together co-op updater 2: game file patches (boot-log format).

Embedded only in Azeroth-Survivors-Together-Updater.exe (version 2) next to
reconstruction/self_update.py, which stays unchanged in the game folder (it is
pinned by the binding and keeps the launcher check). This module extends it:

- A game file in the signed manifest may have the source
    {"patches": [{"from_sha256", "asset", "sha256", "size"}...], "full": {"asset", "sha256", "size"}}
  with assets in the release named by the manifest's "gamefiles": {"url": "https://.../download/<tag>/"}.
- The updater picks the patch for the local file's SHA-256, else the full
  asset (xz), else it asks for the full package. The local SHA is checked
  before patching and the result against the target SHA; then the usual
  backup / install / verify / rollback of self_update runs.
- Releases that use patches set min_updater 2, so updater 1 fetches this one first.
- Version 3: the package ships this updater exe (from 0.0.13). If the running
  exe is one of the changed files, it is not replaced while it runs: after a
  successful install the new one waits as <exe>.new and the run ends with 3;
  the exe swaps itself and runs once more (nothing left to do). Releases that
  ship the exe set min_updater 3.
"""
import os
import re
import shutil
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # -I leaves the script folder out.
import self_update as su  # noqa: E402
import game_patch  # noqa: E402

UPDATER_VERSION = 3
su.UPDATER_VERSION = UPDATER_VERSION
RUNNING = {}  # 'exe': the running updater exe, 'pending': its new version staged during this run
_validate_files, _fetch_files = su.validate_files, su.fetch_files
GAMEFILES = {}  # The signed base address of the game file assets of this run.


def valid_asset(entry):
    return (isinstance(entry, dict) and isinstance(entry.get('asset'), str) and su.safe_path(entry['asset'])
            and '/' not in entry['asset'] and type(entry.get('size')) is int and entry['size'] >= 0
            and isinstance(entry.get('sha256'), str) and re.fullmatch(r'[0-9a-f]{64}', entry['sha256']))


def validate_files(manifest, net):
    files = _validate_files(manifest, net)
    patched = [p for p, e in files.items() if 'patches' in e['source'] or 'full' in e['source']]
    if not patched:
        return files
    base = (manifest.get('gamefiles') or {}).get('url') if isinstance(manifest.get('gamefiles'), dict) else None
    if not isinstance(base, str) or not base.endswith('/'):
        raise su.Refused('manifest has game file patches but no game file address. Nothing was changed.')
    base = GAMEFILES.get('override') or base  # Diagnostics/tests, like --release-url: assets stay SHA-pinned.
    net.check_scheme(base)
    net.allow(base)
    GAMEFILES['url'] = base
    for p in patched:
        source = files[p]['source']
        patches, full = source.get('patches', []), source.get('full')
        if (not isinstance(patches, list) or len(patches) > 64 or not all(
                valid_asset(e) and isinstance(e.get('from_sha256'), str) and re.fullmatch(r'[0-9a-f]{64}', e['from_sha256'])
                for e in patches) or full is not None and not valid_asset(full)):
            raise su.Refused(f'manifest has an invalid game file source for {p}. Nothing was changed.')
    return files


def need_full_package(latest, reason):
    full = ((latest or {}).get('full_package') or {}).get('url')
    return su.NeedFullPackage(f'This update needs new game files that cannot be updated automatically ({reason}). '
                              'Nothing was changed. Download the full package'
                              + (f' here: {full}' if full else ' from the release page'))


def choose(path, local, entry):
    """(kind, asset entry) for turning the local file into the target, or None."""
    source = entry['source']
    for patch in source.get('patches', []):
        if local is not None and patch['from_sha256'] == local:
            return 'patch', patch
    if source.get('full'):
        return 'full', source['full']
    return None


def fetch_files(net, latest, files, needed, work):
    root = work.parent.parent  # <game>/coop-update/release-<version>
    patched = [p for p in needed if 'patches' in files[p]['source'] or 'full' in files[p]['source']]
    plans = {}
    for p in patched:
        local = su.sha256(root / p) if (root / p).is_file() else None
        chosen = choose(p, local, files[p])
        if chosen is None:
            raise need_full_package(latest, f'no patch from your {p}')
        plans[p] = (local, *chosen)
    total = sum(entry['size'] for _, _, entry in plans.values()) + sum(files[p]['size'] for p in plans)
    free = shutil.disk_usage(work.parent).free
    if free < total * 2 + 64 * 2**20:
        raise su.Refused(f'Not enough free disk space for the game file update: {free / 2**20:.0f} MiB free, '
                         f'{(total * 2 + 64 * 2**20) / 2**20:.0f} MiB needed. Nothing was changed.')
    staged = {}
    for p, (local, kind, entry) in sorted(plans.items()):
        started = su.step(f'Download {kind} for {p}')
        asset = work / 'gamefiles' / entry['asset']
        try:
            # external: a missing or taken-down game file release (404/410/a page) means the full package.
            how = net.download(GAMEFILES['url'] + urllib.parse.quote(entry['asset']), asset, entry['size'],
                               entry['sha256'], external=True)
        except su.NotDirect as error:
            raise need_full_package(latest, str(error)) from error
        su.done(f'Download {kind} for {p}', started, f'{entry["size"] / 2**20:.2f} MiB {how} '
                                                    f'(file {files[p]["size"] / 2**20:.1f} MiB)')
        started = su.step(f'Build {p}')
        target = work / 'files' / p
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + '.building')
        try:
            if kind == 'patch':
                if su.sha256(root / p) != local:  # Unchanged since the comparison.
                    raise su.Refused(f'{p} changed during the update. Nothing was changed.')
                digest = game_patch.apply(root / p, asset, temporary)
            else:
                digest = game_patch.unpack_full(asset, temporary, files[p]['size'])
        except ValueError as error:
            temporary.unlink(missing_ok=True)
            asset.unlink(missing_ok=True)  # Damaged: the next run downloads it again.
            raise su.Refused(f'{entry["asset"]} could not be applied ({error}). Run the updater again; '
                             'if it persists, report it. Nothing was changed.') from error
        if digest != files[p]['sha256'] or os.path.getsize(temporary) != files[p]['size']:
            temporary.unlink(missing_ok=True)
            asset.unlink(missing_ok=True)
            raise su.Refused(f'{p} built from {entry["asset"]} does not match its signed SHA-256. Run the updater '
                             'again; if it persists, report it. Nothing was changed.')
        os.replace(temporary, target)
        su.done(f'Build {p}', started, f'{kind}, SHA-256 matches the release')
        staged[p] = target
    rest = [p for p in needed if p not in plans]
    staged.update(_fetch_files(net, latest, files, rest, work) if rest else {})
    running = RUNNING.get('exe')
    if su.UPDATER_ASSET in staged and running is not None and running == (root / su.UPDATER_ASSET).resolve():
        # A running exe cannot be replaced (install would refuse it as locked): it follows after the install.
        pending = work.parent / (su.UPDATER_ASSET + '.pending')
        shutil.copyfile(staged.pop(su.UPDATER_ASSET), pending)
        RUNNING['pending'] = pending
        su.log(' INFO ', f'{su.UPDATER_ASSET} is running: its new version is put in place after this update')
    return staged


su.validate_files, su.fetch_files = validate_files, fetch_files


def main(argv=None, builtin=su.TRUSTED_KEYS):
    import argparse
    ap = argparse.ArgumentParser(add_help=False, allow_abbrev=False)  # --game is not --gamefiles-url.
    ap.add_argument('--gamefiles-url')  # Hidden: another address for the signed game file assets.
    extra, rest = ap.parse_known_args(sys.argv[1:] if argv is None else argv)
    GAMEFILES.clear()
    # Also from the environment: it survives the exe's self-update and older updaters ignore it.
    override = extra.gamefiles_url or os.environ.get('COOP_GAMEFILES_URL')
    if override:
        GAMEFILES['override'] = override
    RUNNING.clear()
    exe = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    exe.add_argument('--updater-exe')
    running = exe.parse_known_args(rest)[0].updater_exe
    if running:
        RUNNING['exe'] = Path(running).resolve()
    try:
        code = su.main(rest, builtin)
        if RUNNING.get('pending') is not None and code == 0:
            os.replace(RUNNING.pop('pending'), RUNNING['exe'].with_name(RUNNING['exe'].name + '.new'))
            su.log(' INFO ', 'Restarting with the new updater to finish (it replaces itself now)')
            return su.SELF_UPDATE_READY
        return code
    finally:
        leftover = RUNNING.pop('pending', None)
        if leftover is not None:
            leftover.unlink(missing_ok=True)  # Install failed: the running exe stays as it is.


if __name__ == '__main__':
    try:
        sys.exit(main())
    except su.Offline as error:
        su.log('FAILED', f'{error}. Check your internet connection and try again. Nothing was changed.')
        sys.exit(4)
    except su.Refused as error:
        su.log('FAILED', str(error))
        sys.exit(2)
    except Exception as error:
        su.log('FAILED', f'{type(error).__name__}: {error}')
        sys.exit(1)
