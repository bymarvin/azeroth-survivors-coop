"""Start the room browser using the public directory by default."""
from base64 import b64decode
import argparse
import os
from pathlib import Path
import subprocess
import socket
import sys
import threading


def check_for_update(root, wait=3.0):
    """Ask GitHub for a newer signed release; offline or slow: start as usual, say nothing."""
    if os.environ.get('COOP_UPDATE_CHECKED') == '1':
        return  # Start-Coop.cmd already asked (coop_autoupdate.py) a moment ago.
    def ask():
        try:
            sys.path.insert(0, str(root / 'reconstruction'))
            import self_update
            status, latest = self_update.check(root, timeout=wait)
        except Exception:
            return
        if status == 'newer':
            updater = root / self_update.UPDATER_ASSET
            how = (f'close the game and run {updater.name} in this folder' if updater.is_file() else
                   'download Azeroth-Survivors-Together-Updater.exe from '
                   'https://github.com/bymarvin/azeroth-survivors-together/releases/latest, '
                   'put it into this folder and run it')
            print(f'[ INFO ] Update available: co-op {latest}. To install it, {how}.', flush=True)
    worker = threading.Thread(target=ask, daemon=True)
    worker.start()
    worker.join(wait)


if __name__ == '__main__':
    # Obfuscation only: the destination remains discoverable at runtime.
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', nargs='?', default=b64decode('aHR0cHM6Ly9kYXNoMjgxMi5kZQ==').decode('ascii'))
    parser.add_argument('--profile', type=Path, help='Independent launcher settings/log folder')
    parser.add_argument('--isolated-profile', action='store_true', help='Use a disposable native save for another local client')
    args = parser.parse_args()
    directory = args.directory
    # Use a fresh UI port so another install's old launcher cannot receive this session.
    # If the port is taken during handoff, room_client fails binding before opening a browser.
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        ui_port = reservation.getsockname()[1]
    try:
        version = Path(__file__).with_name('COOP-VERSION.txt').read_text(encoding='utf-8').strip() or 'unknown'
    except (OSError, UnicodeError):
        version = 'unknown'
    print('Co-op framework version: ' + version, flush=True)
    print('Co-op game folder: ' + str(Path(__file__).resolve().parent), flush=True)
    check_for_update(Path(__file__).resolve().parent)
    raise SystemExit(subprocess.call([
        sys.executable, str(Path(__file__).parent / 'reconstruction' / 'room_client.py'),
        '--directory', directory, '--port', str(ui_port), '--open-browser',
        *(['--isolated-profile'] if args.isolated_profile else []),
        *(['--profile', str(args.profile.resolve())] if args.profile else []),
    ]))
