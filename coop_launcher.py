"""Start the room browser with the EU, US or OCE room directory (asked at start, remembered)."""
import argparse
import os
from pathlib import Path
import subprocess
import socket
import sys
import threading
import time
from urllib.parse import urlsplit

# Order = menu numbers [1], [2], [3]; the first letter of each key also selects it.
# All three directories run on our own servers (EU since 0.0.19).
REGIONS = {
    'eu': ('EU', 'https://lobby.azsurvivors-eu.duckdns.org'),
    'us': ('US', 'https://lobby.azsurvivors.duckdns.org'),
    'oce': ('OCE', 'https://lobby.azsurvivors-oce.duckdns.org'),
}
REGION_FILE = 'coop-region.txt'  # Last choice; not part of any release, so updates keep it.
CHOICE_SECONDS = 5


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


def region_of(value):
    """'eu'/'us'/'oce' (any case) for a region name, None otherwise."""
    value = (value or '').strip().lower()
    return value if value in REGIONS else None


def remembered_region(root):
    try:
        return region_of((root / REGION_FILE).read_text(encoding='utf-8')) or 'eu'
    except (OSError, UnicodeError):
        return 'eu'


def remember_region(root, region):
    try:
        (root / REGION_FILE).write_text(region + '\n', encoding='utf-8')
    except OSError:
        pass  # A read-only folder only means the question shows the default next time.


def latency_ms(url, timeout=1.5):
    """TCP connect time to the directory's HTTPS port in ms, None if it does not answer."""
    parts = urlsplit(url)
    started = time.perf_counter()
    try:
        with socket.create_connection((parts.hostname, parts.port or 443), timeout):
            return round((time.perf_counter() - started) * 1000)
    except (OSError, ValueError):
        return None


def latencies(timeout=1.5):
    """All regions measured in parallel (at most `timeout` seconds in total)."""
    results = {}
    def measure(key):
        results[key] = latency_ms(REGIONS[key][1], timeout)
    workers = [threading.Thread(target=measure, args=(key,), daemon=True) for key in REGIONS]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout + .5)
    return results


def console_key():
    """A key pressed in this console window, or None (never blocks)."""
    import msvcrt
    return msvcrt.getwch() if msvcrt.kbhit() else None


def choose_region(default, read_key, *, measured=None, seconds=CHOICE_SECONDS, now=time.monotonic,
                  sleep=time.sleep, write=print):
    """Ask for a region; Enter or no key within `seconds` keeps `default`. Returns (region, how)."""
    measured = measured or {}
    order = list(REGIONS)
    shortcuts = {str(number): key for number, key in enumerate(order, 1)}
    shortcuts.update({key[0]: key for key in order})
    def label(key):
        name, url = REGIONS[key]
        ms = measured.get(key)
        speed = f'{ms} ms' if ms is not None else ('not reachable' if key in measured else '')
        return f'  [{order.index(key) + 1}] {name:<3}  {urlsplit(url).hostname:<34} {speed}'
    numbers = ', '.join(str(n) for n in range(1, len(order))) + f' or {len(order)}'
    write('Co-op region (room list and relay):')
    for key in REGIONS:
        write(label(key) + ('   <- last choice' if key == default else ''))
    write(f'Press {numbers}, Enter = {REGIONS[default][0]} (starts automatically in {seconds} s).')
    deadline = now() + seconds
    while True:
        key = read_key()
        if key is None:
            if now() >= deadline:
                return default, 'timeout'
            sleep(.05)
            continue
        key = key.lower()
        if key in ('\r', '\n'):
            return default, 'enter'
        if key in shortcuts:
            return shortcuts[key], 'key'
        write('[ WARN ] Press ' + ', '.join(f'{n} ({REGIONS[k][0]})' for n, k in enumerate(order, 1)) + ' or Enter.')


def resolve_directory(argument, region_option, root, *, interactive, read_key=console_key, measure=latencies,
                      environment=os.environ, write=print, **choice):
    """Directory URL to use, plus how it was chosen.

    Order: an explicit URL (tests, private directories) > a region argument or --region >
    COOP_REGION > the question at start (remembered choice preselected; without a console
    the remembered choice is used at once).
    """
    if argument and region_of(argument) is None:
        return argument, None, 'url'
    region = region_of(argument) or region_of(region_option) or region_of(environment.get('COOP_REGION'))
    how = 'argument' if region else None
    if region is None:
        default = remembered_region(root)
        if interactive:
            region, how = choose_region(default, read_key, measured=measure(), write=write, **choice)
        else:
            region, how = default, 'remembered'
    remember_region(root, region)
    return REGIONS[region][1], region, how


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', nargs='?', help='eu, us, oce or a room directory URL (skips the region question)')
    parser.add_argument('--region', choices=sorted(REGIONS), help='Use this region without asking')
    parser.add_argument('--profile', type=Path, help='Independent launcher settings/log folder')
    parser.add_argument('--isolated-profile', action='store_true', help='Use a disposable native save for another local client')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
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
    print('Co-op game folder: ' + str(root), flush=True)
    check_for_update(root)
    interactive = sys.stdin is not None and sys.stdin.isatty() and os.name == 'nt'
    directory, region, how = resolve_directory(args.directory, args.region, root, interactive=interactive)
    if region:
        print(f'[  OK  ] Region {REGIONS[region][0]} ({urlsplit(directory).hostname}, {how}). '
              f'Change it next time with 1/2/3 at start, or start with "Start-Coop.cmd eu|us|oce".', flush=True)
    raise SystemExit(subprocess.call([
        sys.executable, str(Path(__file__).parent / 'reconstruction' / 'room_client.py'),
        '--directory', directory, '--port', str(ui_port), '--open-browser',
        *(['--isolated-profile'] if args.isolated_profile else []),
        *(['--profile', str(args.profile.resolve())] if args.profile else []),
    ]))
