"""Automatic co-op update before the launcher starts (Start-Coop.cmd, boot-log format).

Start-Coop.cmd runs this with the co-op Python before the launcher. It only
decides; the update itself runs in Azeroth-Survivors-Together-Updater.exe after
this Python has ended, so the runtime and every file are free:

  exit 0   start the launcher (no update, offline, skipped, switched off, error)
  exit 10  run the updater exe, then the launcher

Uses the bound reconstruction/self_update.py (signed release description,
SHA-256 of the updater asset). At most about 3 s when nothing is new or the
network is slow. Switch off with COOP_AUTO_UPDATE=0 or the file
coop-update/no-auto-update. Lines also go to coop-update/update.log.
"""
import argparse
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'reconstruction'))  # -I leaves the script folder out.
import self_update as su  # noqa: E402

INSTALL = 10
OFF_FILE = 'coop-update/no-auto-update'


def switched_off(root):
    return os.environ.get('COOP_AUTO_UPDATE', '1').strip() == '0' or (root / OFF_FILE).exists()


def enter_pressed():
    """True if the player pressed Enter (console only)."""
    try:
        import msvcrt
    except ImportError:
        return False
    while msvcrt.kbhit():
        if msvcrt.getwch() in '\r\n':
            return True
    return False


def wait_or_skip(seconds):
    """Count down; True if the player skipped with Enter."""
    end = time.monotonic() + seconds
    shown = None
    while (left := end - time.monotonic()) > 0:
        if enter_pressed():
            return True
        if shown != int(left) + 1:
            shown = int(left) + 1
            print(f'[ INFO ] Update starts in {shown} s (Enter = skip)', flush=True)
        time.sleep(.05)
    return enter_pressed()


def read_release(root, args, builtin):
    """(latest, status) or None within the time limit; never raises."""
    result = {}

    def ask():
        try:
            net = su.Net(args.release_url, timeout=args.timeout, allow_local_http=args.allow_local_http)
            latest, _, _ = su.read_latest(net, root, builtin)
            result['value'] = latest, su.compare(root, latest), net
        except su.Offline as error:
            result['error'] = f'offline ({error})'
        except Exception as error:  # Refused, damaged files: start as usual.
            result['error'] = f'{type(error).__name__}: {error}'
    worker = threading.Thread(target=ask, daemon=True)
    worker.start()
    worker.join(args.timeout)
    if worker.is_alive():
        return None, f'no answer within {args.timeout:.0f} s'
    return result.get('value'), result.get('error')


def ensure_updater(net, latest, root):
    """The updater exe ships with the package (from 0.0.13); only a missing one is downloaded (signed asset).

    An older exe in the folder updates itself (min_updater / its own new version after the install).
    """
    entry, exe = latest['updater'], root / su.UPDATER_ASSET
    if exe.is_file():
        return 'present'
    temporary = exe.with_name(exe.name + '.download')
    net.download(net.url(entry['asset']), temporary, entry['size'], entry['sha256'])
    os.replace(temporary, exe)
    return 'downloaded'


def main(argv=None, builtin=su.TRUSTED_KEYS):
    ap = argparse.ArgumentParser(description='Automatic co-op update check (Start-Coop.cmd)')
    ap.add_argument('--release-url', default=su.RELEASE_URL)
    ap.add_argument('--timeout', type=float, default=3.0)
    ap.add_argument('--countdown', type=float, default=5.0)
    ap.add_argument('--allow-local-http', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--extra-trusted-key', action='append', default=[], help=argparse.SUPPRESS)
    ap.add_argument('--game', type=Path, default=ROOT, help=argparse.SUPPRESS)
    args, _ = ap.parse_known_args(argv)  # Start-Coop passes the same diagnostic options to the updater exe.
    builtin = (*builtin, *args.extra_trusted_key)
    root = args.game
    try:
        (root / 'coop-update').mkdir(exist_ok=True)
        su.LOG = (root / 'coop-update' / 'update.log').open('a', encoding='utf-8')
    except OSError:
        su.LOG = None
    if switched_off(root):
        su.log(' INFO ', f'Automatic update is switched off (COOP_AUTO_UPDATE=0 or {OFF_FILE})')
        return 0
    started = su.step('Look for a co-op update')
    found, problem = read_release(root, args, builtin)
    if found is None:
        su.done('Look for a co-op update', started, f'{problem}; starting as usual')
        return 0
    latest, status, net = found
    installed = su.installed_version(root)
    if status != 'newer':
        su.done('Look for a co-op update', started, f'co-op {installed} is current')
        return 0
    su.done('Look for a co-op update', started, f'co-op {latest["version"]} is available')
    su.log(' INFO ', f'Update {installed} -> {latest["version"]} will be installed... (Enter = skip)')
    if wait_or_skip(args.countdown):
        su.log(' INFO ', 'Update skipped; starting the installed version')
        return 0
    started = su.step('Prepare the updater')
    try:
        how = ensure_updater(net, latest, root)
    except Exception as error:
        su.log('FAILED', f'Prepare the updater: {error}. Starting the installed version.')
        return 0
    su.done('Prepare the updater', started, f'{su.UPDATER_ASSET} {how}')
    return INSTALL


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:  # Never block the launcher.
        print(f'[FAILED] Automatic update: {type(error).__name__}: {error}. Starting the installed version.', flush=True)
        sys.exit(0)
