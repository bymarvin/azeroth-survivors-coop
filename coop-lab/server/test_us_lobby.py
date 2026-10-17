"""Local end-to-end check of the US lobby + relay setup (boot-log format, no game start).

Starts the unchanged reconstruction/lobby_server.py and relay/server.py as separate
processes (the relay with a throwaway certificate for "localhost" that only this test
trusts), then drives the real client code (relay.routing.Routes, coop_transport):

  1. room directory: create, join, publish the connection, poll, GET /rooms
  2. guest direct attempt to an unreachable address falls back to the relay
  3. game channel through the relay with TLS pinning; a wrong fingerprint is refused
  4. the relay refuses invalid credentials and non-members
  5. throughput through the relay and the relay's CPU time per MB

  python test_us_lobby.py [--seconds 8]
"""
import argparse
import ctypes
import datetime
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'reconstruction'))
RESULTS = []


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def check(name, condition, detail=''):
    RESULTS.append((name, bool(condition)))
    log('  OK  ' if condition else 'FAILED', f'{name}{" (" + str(detail) + ")" if detail != "" else ""}')
    return condition


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def make_certificate(folder):
    """Throwaway CA + server certificate for localhost (trusted only via SSL_CERT_FILE here)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'US lobby test CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (folder / 'ca.pem').write_bytes(ca.public_bytes(pem))
    (folder / 'fullchain.pem').write_bytes(cert.public_bytes(pem) + ca.public_bytes(pem))
    (folder / 'key.pem').write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))


def cpu_seconds(process):
    """User+kernel CPU time of a child process (Windows GetProcessTimes)."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    times = [wintypes.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(wintypes.HANDLE(int(process._handle)), *[ctypes.byref(t) for t in times]):
        return float('nan')
    value = lambda t: (t.dwHighDateTime << 32 | t.dwLowDateTime) / 1e7
    return value(times[2]) + value(times[3])


class Directory:
    def __init__(self, url):
        self.url = url

    def call(self, path, data=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request(self.url + path, None if data is None else json.dumps(data).encode(), headers)
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read())


def room_with_relay(directory, build, address, fingerprint_from=None):
    """Host creates and publishes, guest joins; returns host/guest views, tokens, pairing folder."""
    from coop_transport import create_pairing
    pairing = Path(tempfile.mkdtemp(prefix='us-lobby-pairing-'))
    invite = create_pairing(pairing / 'p')
    fingerprint = invite['fingerprint']
    if fingerprint_from is not None:
        fingerprint = create_pairing(Path(tempfile.mkdtemp(prefix='us-lobby-other-')) / 'p')['fingerprint']
    host = directory.call('/create', dict(name='US test', player='Host', private=False, build=build, region='na',
                                          version='0.95.0'))
    room_id = host['room']['id']
    guest = directory.call('/join', dict(room=room_id, player='Guest', build=build))
    host_view = directory.call('/connection', dict(room=room_id, address=address, port=free_port(),
                                                   fingerprint=fingerprint), host['token'])
    guest_view = directory.call('/poll', dict(room=room_id), guest['token'])
    return host_view, host['token'], guest_view, guest['token'], pairing / 'p'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--seconds', type=float, default=8)
    args = ap.parse_args()
    started = time.monotonic()
    work = Path(tempfile.mkdtemp(prefix='us-lobby-test-'))
    log(' .... ', f'test certificate and services in {work}')
    make_certificate(work)
    os.environ['SSL_CERT_FILE'] = str(work / 'ca.pem')  # Trust the test CA (relay client uses the default context).
    lobby_port, relay_port = free_port(), free_port()
    python = sys.executable
    env = dict(os.environ, PYTHONUNBUFFERED='1')
    lobby = subprocess.Popen([python, '-E', '-s', str(ROOT / 'reconstruction/lobby_server.py'), '--bind', '127.0.0.1',
                              '--port', str(lobby_port), '--collected-logs', str(work / 'collected-logs')],
                             cwd=ROOT / 'reconstruction', env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    relay = subprocess.Popen([python, '-E', '-s', str(ROOT / 'relay/server.py'), '--bind', '127.0.0.1',
                              '--port', str(relay_port), '--directory', f'http://127.0.0.1:{lobby_port}',
                              '--cert', str(work / 'fullchain.pem'), '--key', str(work / 'key.pem')],
                             cwd=ROOT / 'relay', env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    routes = []
    try:
        directory = Directory(f'http://127.0.0.1:{lobby_port}')
        for _ in range(100):
            try:
                rooms = directory.call('/rooms')
                break
            except OSError:
                time.sleep(.1)
        check('lobby GET /rooms', rooms == dict(rooms=[]), rooms)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', relay_port), 1):
                    break
            except OSError:
                time.sleep(.1)
        log('  OK  ', f'services up ({time.monotonic() - started:.1f} s, lobby :{lobby_port}, relay :{relay_port})')

        from relay import routing
        from relay.client import connect as relay_connect
        build = 'ab' * 32
        events = []
        host_view, host_token, guest_view, guest_token, pairing = room_with_relay(directory, build, '192.0.2.1')
        listing = directory.call('/rooms')['rooms']
        check('room listed without connection data', len(listing) == 1 and 'connection' not in listing[0]
              and 'invite' not in listing[0], listing[0].keys())
        host = routing.Routes(host_view, host_token, pairing, build, server='localhost', port=relay_port,
                              log=lambda **e: events.append(('host', e)))
        guest = routing.Routes(guest_view, guest_token, None, build, server='localhost', port=relay_port,
                               log=lambda **e: events.append(('guest', e)))
        routes += [host, guest]
        t = time.monotonic()
        while time.monotonic() - t < 30 and not (host.channels.get(2) and guest.channels.get(1)):
            time.sleep(.05)
        linked = time.monotonic() - t
        check('guest direct attempt failed, relay link established',
              guest.labels.get(2) == 'Relay' and host.labels.get(2) == 'Relay',
              f'{linked:.1f} s, events {[(s, e["event"], e.get("reason")) for s, e in events]}')
        sender, receiver = host.channels[2], guest.channels[1]
        check('game channel TLS-pinned to the host certificate', sender is not None and receiver is not None)

        import base64
        import random

        def load(seconds, rate, size, reverse_size):
            """Host->guest messages at `rate`/s (0 = as fast as the link takes them), plus guest->host."""
            rng = random.Random(7)
            blob = base64.b64encode(rng.randbytes(size)).decode()  # Hardly compressible, like hex/base64 state.
            back = base64.b64encode(rng.randbytes(reverse_size)).decode()
            counts = dict(sent=0, received=0, back=0, back_received=0)
            wire_before = sender.wire_bytes + receiver.wire_bytes
            done = threading.Event()

            def drain(channel, key):
                while not done.is_set():
                    for message in channel.drain():
                        if message.get('kind') == 'load':
                            counts[key] += 1
                    time.sleep(.002)
            readers = [threading.Thread(target=drain, args=(receiver, 'received'), daemon=True),
                       threading.Thread(target=drain, args=(sender, 'back_received'), daemon=True)]
            for reader in readers:
                reader.start()
            cpu_before, wall = cpu_seconds(relay), time.monotonic()
            stop, tick = wall + seconds, wall
            while time.monotonic() < stop:
                if rate:
                    tick += 1 / rate
                    time.sleep(max(0, tick - time.monotonic()))
                    sender.send(dict(kind='load', n=counts['sent'], blob=blob))
                    counts['sent'] += 1
                    if reverse_size:
                        receiver.send(dict(kind='load', n=counts['back'], blob=back))
                        counts['back'] += 1
                elif sender.outgoing.qsize() < 32:
                    sender.send(dict(kind='load', n=counts['sent'], blob=blob))
                    counts['sent'] += 1
                else:
                    time.sleep(.001)
            deadline = time.monotonic() + 60
            while (counts['received'] < counts['sent'] or counts['back_received'] < counts['back']) \
                    and time.monotonic() < deadline:
                time.sleep(.01)
            elapsed = time.monotonic() - wall
            cpu = cpu_seconds(relay) - cpu_before
            done.set()
            wire = sender.wire_bytes + receiver.wire_bytes - wire_before
            return counts, elapsed, cpu, wire

        # The relay closes a tunnel above 8 MiB/s per direction (BYTES_PER_SECOND); stay below it.
        counts, elapsed, cpu, wire = load(args.seconds, 600, 4500, 0)
        mb = wire / 1e6
        check('all messages arrived through the relay (3.7 MB/s, below the relay cap)', counts['received'] == counts['sent'],
              f"{counts['received']}/{counts['sent']}")
        log(' INFO ', f'bulk: {mb / elapsed:.2f} MB/s ({mb * 8 / elapsed:.1f} Mbit/s) through one tunnel, '
                      f'relay CPU {cpu:.2f} s for {mb:.1f} MB = {cpu / mb * 1000:.1f} ms/MB')
        RESULTS.append(('metric_max_mb_per_s', mb / elapsed))
        # Game-like: 25 states/s at ~1 KB on the wire host->guest (0.21 Mbit/s measured in 0.0.12 per
        # guest) and 25 small messages back; one tunnel = one guest, a 4-player game has three.
        counts, elapsed, cpu, wire = load(20, 25, 750, 200)
        check('game-like load arrived completely in both directions',
              counts['received'] == counts['sent'] and counts['back_received'] == counts['back'],
              f"{counts['received']}/{counts['sent']} and {counts['back_received']}/{counts['back']}")
        per_guest_mbit = wire * 8 / elapsed / 1e6
        log(' INFO ', f'game-like tunnel: {per_guest_mbit:.3f} Mbit/s both ways, relay CPU {cpu / elapsed * 100:.2f} % '
                      f'of one core ({cpu:.2f} s in {elapsed:.0f} s)')
        RESULTS.append(('metric_guest_mbit', per_guest_mbit))
        RESULTS.append(('metric_guest_cpu_share', cpu / elapsed))

        # A wrong fingerprint in the published connection must never yield a channel.
        bad_host_view, bad_host_token, bad_guest_view, bad_guest_token, bad_pairing = room_with_relay(
            directory, build, '192.0.2.1', fingerprint_from='other')
        bad_events = []
        bad_host = routing.Routes(bad_host_view, bad_host_token, bad_pairing, build, server='localhost',
                                  port=relay_port)
        bad_guest = routing.Routes(bad_guest_view, bad_guest_token, None, build, server='localhost', port=relay_port,
                                   log=lambda **e: bad_events.append(e))
        routes += [bad_host, bad_guest]
        time.sleep(12)
        check('wrong host fingerprint refused (no channel)', not bad_guest.channels.get(1),
              f'guest error {bad_guest.error!r}')

        # Relay handshake with test data: invalid credentials and non-members get no tunnel.
        import asyncio
        async def attempt(membership, peer):
            try:
                stream = await relay_connect('localhost', relay_port, membership, peer)
                stream[1].close()
                return 'paired'
            except Exception as error:
                return type(error).__name__
        bad = asyncio.run(attempt(dict(room='0' * 24, token='x' * 32), 1))
        check('relay refuses an unknown room/token', bad != 'paired', bad)
        wrong_peer = asyncio.run(attempt(dict(room=guest_view['id'], token=guest_token), 3))
        check('relay refuses a guest-to-guest link', wrong_peer != 'paired', wrong_peer)
    finally:
        for item in routes:
            item.close()
        for process in (relay, lobby):
            process.terminate()
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()
        relay_log = relay.stdout.read().decode(errors='replace')
        lobby_log = lobby.stdout.read().decode(errors='replace')
        check('service output contains no tokens or invitations',
              all(token not in relay_log + lobby_log for token in (locals().get('host_token', '-'), locals().get('guest_token', '-'))),
              f'relay said {relay_log.strip()!r}')
    passed = sum(1 for name, ok in RESULTS if not name.startswith('metric_') and ok)
    total = sum(1 for name, _ in RESULTS if not name.startswith('metric_'))
    log(' INFO ', f'summary: {passed}/{total} checks passed in {time.monotonic() - started:.1f} s')
    return 0 if passed == total else 1


if __name__ == '__main__':
    sys.exit(main())
