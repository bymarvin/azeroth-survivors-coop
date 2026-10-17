"""Live check of the deployed US lobby and relay without a game start (boot-log format).

Uses the real client code (relay.routing.Routes, coop_transport) against
https://lobby.azsurvivors.duckdns.org and its relay on TCP 47771:
  1. GET /rooms over HTTPS (system CA store)
  2. a PRIVATE test room: host creates, guest joins, host publishes an unreachable
     direct address, so the guest must use the relay
  3. game channel through the live relay with TLS pinning, messages both ways, latency
  4. the relay refuses an invalid membership
  5. both leave; the room is gone from the directory afterwards

  python live_check_us_lobby.py [--directory https://lobby.azsurvivors.duckdns.org]
"""
import argparse
import asyncio
import json
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'reconstruction'))
RESULTS = []


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def check(name, condition, detail=''):
    RESULTS.append(bool(condition))
    log('  OK  ' if condition else 'FAILED', f'{name}{" (" + str(detail) + ")" if detail != "" else ""}')
    return condition


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--directory', default='https://lobby.azsurvivors.duckdns.org')
    args = ap.parse_args()
    host_name = urlsplit(args.directory).hostname
    started = time.monotonic()

    def call(path, data=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request(args.directory + path, None if data is None else json.dumps(data).encode(),
                                         headers)
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read())

    t = time.monotonic()
    rooms = call('/rooms')
    check('GET /rooms over HTTPS', isinstance(rooms.get('rooms'), list), f'{len(rooms["rooms"])} rooms, '
          f'{(time.monotonic() - t) * 1000:.0f} ms')

    from coop_transport import create_pairing
    from relay import routing
    from relay.client import connect as relay_connect
    build = 'cd' * 32  # Test value; the directory only compares host and guest builds.
    pairing = Path(tempfile.mkdtemp(prefix='us-live-')) / 'p'
    invite = create_pairing(pairing)
    host = call('/create', dict(name='US relay live check', player='LiveCheckHost', private=True, build=build,
                                region='na', version='0.95.0'))
    room = host['room']['id']
    routes = []
    try:
        guest = call('/join', dict(room=room, player='LiveCheckGuest', build=build, invite=host['room']['invite']))
        host_view = call('/connection', dict(room=room, address='192.0.2.1', port=47799,
                                             fingerprint=invite['fingerprint']), host['token'])
        guest_view = call('/poll', dict(room=room), guest['token'])
        check('private test room created, joined, connection published',
              guest_view['slot'] == 2 and guest_view['connection']['fingerprint'] == invite['fingerprint'])
        check('private room not in the public list', all(r['id'] != room for r in call('/rooms')['rooms']))

        bad = asyncio.run(_attempt(relay_connect, host_name, dict(room=room, token='x' * 40), 1))
        check('relay refuses an invalid membership', bad != 'paired', bad)

        events = []
        host_routes = routing.Routes(host_view, host['token'], pairing, build, server=host_name,
                                     log=lambda **e: events.append(('host', e)))
        guest_routes = routing.Routes(guest_view, guest['token'], None, build, server=host_name,
                                      log=lambda **e: events.append(('guest', e)))
        routes += [host_routes, guest_routes]
        t = time.monotonic()
        while time.monotonic() - t < 60 and not (host_routes.channels.get(2) and guest_routes.channels.get(1)):
            time.sleep(.05)
        check('guest reached the host through the live relay (TLS-pinned game channel)',
              guest_routes.labels.get(2) == 'Relay' and host_routes.channels.get(2) is not None,
              f'{time.monotonic() - t:.1f} s, {[(s, e["event"], e.get("reason")) for s, e in events]}')
        sender, receiver = host_routes.channels[2], guest_routes.channels[1]
        rtts = []
        for n in range(20):
            t = time.monotonic()
            sender.send(dict(kind='live_check', n=n))
            while True:
                messages = [m for m in receiver.drain() if m.get('kind') == 'live_check']
                if messages:
                    break
                time.sleep(.001)
            receiver.send(dict(kind='live_check_back', n=n))
            while not [m for m in sender.drain() if m.get('kind') == 'live_check_back']:
                time.sleep(.001)
            rtts.append((time.monotonic() - t) * 1000)
        rtts.sort()
        check('20 round trips host -> relay -> guest -> relay -> host', len(rtts) == 20,
              f'median {rtts[10]:.0f} ms, max {rtts[-1]:.0f} ms')
    finally:
        for item in routes:
            item.close()
        for token in (locals().get('guest', {}).get('token'), host['token']):
            if token:
                try:
                    view = call('/poll', dict(room=room), token)
                    call('/action', dict(room=room, action='leave', revision=view['revision']), token)
                except Exception:
                    pass
        try:
            call('/poll', dict(room=room), host['token'])
            gone = False
        except urllib.error.HTTPError as error:
            gone = error.code == 400
        check('test room removed after leaving', gone)
    log(' INFO ', f'summary: {sum(RESULTS)}/{len(RESULTS)} checks passed in {time.monotonic() - started:.1f} s')
    return 0 if all(RESULTS) else 1


async def _attempt(relay_connect, host, membership, peer):
    try:
        stream = await relay_connect(host, 47771, membership, peer)
        stream[1].close()
        return 'paired'
    except Exception as error:
        return type(error).__name__


if __name__ == '__main__':
    import urllib.error  # noqa: F401  (used in main)
    sys.exit(main())
