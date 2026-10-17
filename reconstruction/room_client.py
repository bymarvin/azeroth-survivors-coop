"""Local room-browser controller and native game launcher. No third-party services."""
import argparse
import hashlib
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import ssl
import sys
import threading
from collections import deque
import time
import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from launcher_profile import LauncherProfile, game_version

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def failure_description(error, directory):
    """Share actionable diagnostics without exposing request URLs, bodies or tokens."""
    target = urlsplit(directory)
    endpoint = f'{target.scheme}://{target.netloc.rsplit("@", 1)[-1]}'
    cause = error.reason if isinstance(error, URLError) and not isinstance(error, HTTPError) else error
    if isinstance(cause, ssl.SSLCertVerificationError):
        code = getattr(cause, 'verify_code', None)
        detail = {10: 'The TLS certificate has expired.', 9: 'The TLS certificate is not yet valid.',
                  18: 'The TLS certificate is self-signed.', 19: 'The TLS certificate chain is self-signed.',
                  20: 'The TLS certificate issuer is not trusted.',
                  62: 'The TLS certificate does not match the server name.'}.get(code, 'TLS certificate verification failed.')
        detail += (f' [SSLCertVerificationError; verify code {code}]. '
                   'Check Windows date, time and time zone. If correct, report this to the server administrator; '
                   'a VPN, proxy or antivirus HTTPS filter can also present a different certificate. '
                   f'PC time (UTC): {datetime.now(timezone.utc).isoformat(timespec="seconds")}.')
    elif isinstance(error, HTTPError):
        try:
            status = HTTPStatus(error.code).phrase
        except ValueError:
            status = 'Unknown status'
        detail = f'HTTP {error.code} {status}. '
        detail += ('The directory service is unavailable; retry shortly.' if error.code >= 500 else
                   'The directory rejected the request; refresh the lobby and check your room details.')
    elif isinstance(cause, (TimeoutError, socket.timeout)):
        detail = 'The directory request timed out. Check your connection, VPN/proxy and firewall, then retry.'
    elif isinstance(cause, socket.gaierror):
        detail = 'DNS lookup failed. Check your Internet connection and DNS settings.'
    elif isinstance(cause, ConnectionRefusedError):
        detail = 'Connection refused. The service may be offline or blocked by a firewall.'
    elif isinstance(cause, ssl.SSLError):
        detail = f'TLS handshake failed [{getattr(cause, "reason", None) or "SSLError"}]. Check your VPN/proxy or HTTPS filtering and contact the administrator.'
    elif isinstance(error, json.JSONDecodeError):
        detail = 'The directory returned invalid JSON. A proxy, captive portal or server error may be returning another page.'
    elif isinstance(error, OSError) and not isinstance(error, URLError):
        code = getattr(error, 'winerror', None) or error.errno
        if code in (98, 10048):
            detail = 'The local host port is already in use. Close the other host session or choose another port in Connection settings.'
        elif isinstance(error, PermissionError):
            detail = 'Access denied. Check game-folder write permissions and security software blocking the local host connection.'
        else:
            detail = 'Local system operation failed. Check the game folder and local connection settings.'
        return f'{detail} [{type(error).__name__}; code {code}]'
    elif isinstance(error, URLError):
        detail = f'Network request failed [{type(cause).__name__}; code {getattr(cause, "winerror", None) or getattr(cause, "errno", None)}]. Check your connection, VPN/proxy and firewall.'
    elif isinstance(error, ValueError):
        return str(error)
    else:
        return f'Unexpected launcher error [{type(error).__name__}]. Report this message to the co-op maintainer.'
    return f'Directory {endpoint}: {detail}'


# Published when the host has no reachable port. Every directory version accepts
# it and earlier clients sent it too; guests then use the relay.
NO_DIRECT_OFFER = '127.0.0.1'
# "Next run": seconds the host waits for confirmations before closing the game, and for the
# confirmed guests to rejoin before it starts without the missing ones.
NEXT_RUN_CONFIRM = 10
# The link to the host closed after this player's run had ended (host left, or the line/relay dropped).
AFTER_RUN_STATUS = 'Run finished; the connection to the host closed. Your progress is saved.'
NEXT_RUN_WAIT = 120


def next_run_closing(bridge, next_room, now):
    """Host game thread: close the game for the next run once every guest confirmed, or after NEXT_RUN_CONFIRM s.

    Guests that never confirm (left, hung, or a 0.0.15 launcher that ignores the invitation) are not waited for.
    """
    if not next_room or not bridge.next_run_offer or next_room['expected'] is not None:
        return False
    guests = {n for n in bridge.members if n != 1} - bridge.departed
    if not bridge.next_run_acks >= guests and now - next_room['offered'] <= NEXT_RUN_CONFIRM:
        return False
    next_room['expected'] = sorted(bridge.next_run_acks & guests)
    bridge.record(event='next_run_closing', confirmed=next_room['expected'], missing=sorted(guests - bridge.next_run_acks))
    return True


class RoomClient:
    def __init__(self, directory, *, diagnostic_autostart=False, isolated_profile=False, profile_folder=None):
        parsed = urlsplit(directory)
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost')):
            raise ValueError('Remote room directories require HTTPS')
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Invalid directory URL')
        self.directory = directory.rstrip('/')
        self.diagnostic_autostart = diagnostic_autostart
        self.isolated_profile = isolated_profile or diagnostic_autostart
        self.profile = LauncherProfile(profile_folder or ROOT / 'coop-lab' /
            ('launcher-' + secrets.token_hex(8) if self.isolated_profile else 'launcher'))
        self.membership = self.room = self.pairing = None
        self.next_room = None    # host: the following room (membership, confirmed guests, waiting since)
        self.next_invite = None  # guest: the host's invitation, joined once the current game has closed
        self.status, self.error = 'Choose a room or host your own.', None
        self.events, self.commands = queue.Queue(32), queue.Queue(32)
        self.bridge = None
        self.launched = False
        self.room_detached = False
        self.worker = None
        self.routes = None
        self.mapper = None  # Host port mapping (UPnP/PCP/NAT-PMP) of the open room.
        self.cancel = threading.Event()
        self.stopped = threading.Event()
        self.lock = threading.RLock()
        self.build = hashlib.sha256(Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe')).read_bytes()).hexdigest()
        self.version = game_version(Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe')), self.build)

    def request(self, path, data=None, authenticated=False, token=None):
        headers = {'Content-Type': 'application/json'}
        if authenticated or token:
            headers['Authorization'] = 'Bearer ' + (token or self.membership['token'])
        request = urllib.request.Request(self.directory + path,
            None if data is None else json.dumps(data).encode(), headers)
        with urllib.request.urlopen(request, timeout=20) as response:
            if int(response.headers.get('Content-Length', '0')) > 1048576:
                raise ValueError('Directory response exceeds bound')
            data = response.read(1048577)
            if len(data) > 1048576:
                raise ValueError('Directory response exceeds bound')
            return json.loads(data)

    def network_event(self, **event):
        """Connection diagnostics (port mapping, route); never invitations, tickets or tokens."""
        event['time'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
        self.last_network_event = event
        if (event.get('event') == 'guest_route' and event.get('route') == 'Relay'
                and (self.room or {}).get('connection', {}).get('address') not in (None, NO_DIRECT_OFFER)):
            # A direct offer existed but the guest could not reach it: most often
            # Windows Firewall blocking inbound TCP for the launcher. No rule is
            # created automatically; the player decides.
            port = self.room['connection'].get('port')
            hint = (f'Player {event.get("slot")} could not reach you directly and uses the relay. '
                    f'If Windows Firewall asked about co-op, allow it, or allow inbound TCP port {port}.')
            self.firewall_hint = hint
            self.write_network_event(dict(event='firewall_hint', level='WARN', slot=event.get('slot'),
                                          port=port, time=event['time']))
        self.write_network_event(event)

    def write_network_event(self, event):
        try:
            folder = self.profile.folder / 'logs'
            folder.mkdir(parents=True, exist_ok=True)
            with (folder / f'network-{datetime.now(timezone.utc):%Y%m%d}.jsonl').open('a', encoding='utf-8') as log:
                log.write(json.dumps(event) + '\n')
        except OSError:
            pass  # Diagnostics never block hosting.

    def direct_endpoint(self, address, port):
        """Address guests may try directly, or None: guests then use the relay."""
        address = (address or '').strip()
        if urlsplit(self.directory).hostname in ('127.0.0.1', 'localhost'):
            return address if address and address.lower() != 'auto' else '127.0.0.1'  # Local test directory.
        if address and address.lower() != 'auto':
            # Typed in by the player (forwarded port, or a LAN address for players at
            # home): published unchanged as in earlier versions, no router mapping.
            from port_mapping import public_address
            self.network_event(event='direct_offer', source='manual', port=port,
                               scope='public' if public_address(address) else 'other')
            return address
        if os.environ.get('COOP_UPNP') == '0':
            self.network_event(event='upnp_failed', reason='disabled')
            return None
        from port_mapping import PortMapper
        self.status = 'Opening the game port on your router (UPnP)…'
        mapper = PortMapper(port, self.network_event)
        mapped = mapper.open()
        if not mapped:
            return None
        self.mapper = mapper
        import atexit
        atexit.register(mapper.close)  # Normal exit; a crash is covered by the lease.
        return mapped[0]

    def release_mapping(self):
        mapper, self.mapper = self.mapper, None
        if mapper:
            mapper.close()

    def create(self, name, player, private, address, port, region=None):
        from coop_transport import create_pairing
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError('Choose a game port between 1024 and 65535 in Connection settings.')
        with self.lock:
            if self.membership or self.worker and self.worker.is_alive() or getattr(self, 'hosting', False):
                raise ValueError('Leave the current room first')
            self.reset_session()
            self.hosting = True  # Blocks a second create/join while the router is asked.
        try:
            # Router discovery and mapping take seconds: never under the lock, so the
            # room browser keeps answering (and shows the status) meanwhile.
            direct = self.direct_endpoint(address, port)
            with self.lock:
                if self.stopped.is_set() or self.membership or self.worker and self.worker.is_alive():
                    self.release_mapping()  # Browser closed or a room appeared meanwhile.
                    raise ValueError('Room creation was cancelled.')
                self.publish_room(name, player, private, port, region, direct, create_pairing)
        finally:
            self.hosting = False

    def publish_room(self, name, player, private, port, region, direct, create_pairing):
        """Create the listing and publish the endpoint; runs under the lock."""
        pairing = ROOT / '.coop-rooms' / secrets.token_hex(12)
        invite = create_pairing(pairing)
        try:
            self.membership = self.request('/create', dict(name=name, player=player, private=private, build=self.build, region=region, version=self.version))
        except Exception:
            self.release_mapping()
            raise
        self.room = self.membership['room']
        self.pairing = pairing
        try:
            # Same request as every earlier client: the unchanged directory accepts it.
            self.room = self.request('/connection', dict(room=self.room['id'],
                address=direct or NO_DIRECT_OFFER, port=port, fingerprint=invite['fingerprint']), True)
            self.start_routes()
        except Exception:
            self.leave_membership(self.room['id'], 'Could not open the host connection.')
            raise
        self.status = ('Waiting for players. Guests can connect directly.' if direct else
                       'Waiting for players. Guests connect through the relay.')
        self.profile.save(player=player, region=region, name=name)

    def join(self, player, room_id=None, code=None, region=None):
        with self.lock:
            if self.membership or self.worker and self.worker.is_alive() or getattr(self, 'hosting', False):
                raise ValueError('Leave the current room first')
            self.reset_session()
            invite = None
            if code:
                room_id, invite = code.strip().split(':', 1)
            self.membership = self.request('/join', dict(room=room_id, player=player, build=self.build, invite=invite))
            self.room = self.membership['room']
            self.start_routes()
            self.status = 'Joined. Checking the connection to the host…'
            self.profile.save(player=player, region=region)

    def start_routes(self):
        from relay.routing import Routes
        if self.room.get('connection'):
            self.routes = Routes(dict(self.room), self.membership['token'], self.pairing, self.build,
                                 server=urlsplit(self.directory).hostname, log=self.network_event)

    def reset_session(self):
        self.build = hashlib.sha256(Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe')).read_bytes()).hexdigest()
        self.version = game_version(Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe')), self.build)
        self.cancel.clear()
        self.launched = self.room_detached = False
        self.error = None
        self.commands, self.events = queue.Queue(32), queue.Queue(32)

    def action(self, action):
        with self.lock:
            if not self.room:
                raise ValueError('Join a room first')
            if action == 'leave':
                self.cancel.set()
                self.next_invite = None  # A guest who leaves between runs stays out of the next one.
                self.drop_next_room()
                self.leave_membership(self.room['id'], 'Left the room.')
                return
            if action == 'next_run':
                self.next_run()
                return
            if action == 'start':
                current = hashlib.sha256(Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe')).read_bytes()).hexdigest()
                if current != self.build or self.room.get('build', self.build) != current:
                    raise ValueError('Game build changed or differs from the host. Leave and rejoin with the matching executable.')
            if (self.room_detached and action == 'keep_fighting') or action == 'new_hero':
                # The decision travels over the game channel (host_action), which is what guests apply.
                # New hero is never told to the directory: its "menu" phase makes the relay close every
                # tunnel within 15 s (relay/server.py monitor), cutting relay guests off after the run
                # and before Next run. The listing stays in "victory", which the relay keeps open.
                if not self.bridge:
                    raise ValueError('The game has already ended.')
                self.queue_game_command(8 if action == 'keep_fighting' else 9)
                return
            fresh = self.request('/poll', dict(room=self.room['id']), True)
            result = self.request('/action', dict(room=fresh['id'], action=action, revision=fresh['revision'], build=self.build), True)
            if action in ('keep_fighting', 'new_hero') and self.bridge:
                self.queue_game_command(8 if action == 'keep_fighting' else 9)
            self.room = result
            if self.routes:
                self.routes.update(dict(self.room))

    def next_run(self):
        """Host: open the following room and invite the party over the running game's channels.

        The directory is unchanged: a new private room (same name and region) with the same host
        connection and pairing, so guests can verify it is this host's room. The game closes once every
        guest confirmed (at most NEXT_RUN_CONFIRM s); the launcher then switches to the new room.
        """
        bridge = self.bridge
        if self.room['slot'] != 1:
            raise ValueError('Only the host starts the next run.')
        if self.next_room:
            raise ValueError('The next run is already being prepared.')
        if bridge is None or not hasattr(bridge, 'offer_next_run') or not bridge.run_over():
            raise ValueError('Finish the current run first (victory, defeat or give up).')
        connection = self.room.get('connection') or {}
        host = next(p['name'] for p in self.room['players'] if p['slot'] == 1)
        membership = self.request('/create', dict(name=self.room['name'], player=host, private=True, build=self.build,
                                                  region=self.room.get('region'), version=self.version))
        try:
            membership['room'] = self.request('/connection', dict(room=membership['room']['id'],
                address=connection['address'], port=connection['port'], fingerprint=connection['fingerprint']),
                token=membership['token'])
        except Exception:
            self.drop_next_room(membership)
            raise
        self.next_room = dict(membership=membership, offered=time.monotonic(), expected=None, since=None, polled=0)
        bridge.offer_next_run(membership['room']['id'], membership['room']['invite'])
        self.status = 'Next run: inviting the party…'

    def drop_next_room(self, membership=None):
        """Close a prepared next room (host leaves or the old game failed); best effort."""
        membership = membership or (self.next_room or {}).get('membership')
        self.next_room = None
        if membership:
            try:
                self.request('/action', dict(room=membership['room']['id'], action='leave',
                                             revision=membership['room']['revision']), token=membership['token'])
            except Exception:
                pass  # It expires without polls anyway.

    def switch_to_next_room(self, next_room):
        """Host, after the old game closed: the prepared room becomes the current one."""
        with self.lock:
            self.reset_session()
            self.membership = next_room['membership']
            self.room = self.membership['room']
            self.start_routes()
            next_room['since'] = time.monotonic()
            self.next_room = next_room
            count = len(next_room['expected'])
            self.status = (f'Next run: waiting for {count} player{"s" if count != 1 else ""} to rejoin…' if count else
                           'Next run: nobody confirmed. Start alone or wait for players to join with the invite.')

    def invited(self, offer, room):
        """Guest game thread: the host's invitation (pinned channel, peer 1); joined after this game closes."""
        if self.cancel.is_set():
            return  # Leaving: never rejoin.
        me = next(p['name'] for p in room['players'] if p['slot'] == room['slot'])
        self.next_invite = dict(offer, player=me, region=room.get('region'), fingerprint=room['connection']['fingerprint'])
        self.status = 'The host started the next run. You rejoin automatically when this game closes (or Leave).'

    def join_next_run(self):
        """Guest, once the previous game has closed: join the host's next room, only if it is this host's."""
        offer, self.next_invite = self.next_invite, None
        try:
            self.join(offer['player'], code=f'{offer["room"]}:{offer["invite"]}', region=offer['region'])
        except Exception as error:
            self.status = 'Could not join the next run. Choose a room or host your own.'
            self.error = 'Next run: ' + failure_description(error, self.directory)
            return
        if (self.room.get('connection') or {}).get('fingerprint') != offer['fingerprint']:
            self.leave_membership(self.room['id'], 'Not joined: the next-run room does not belong to your host.')
            self.error = 'The invitation did not lead to your host\'s room; nothing was joined.'
            return
        self.status = 'Rejoined the party for the next run. Waiting for the host to start.'

    def next_run_due(self):
        """Host heartbeat: keep the prepared room alive; start once the confirmed guests are back."""
        next_room, now = self.next_room, time.monotonic()
        if next_room['since'] is None:
            if now - next_room['polled'] >= 10:  # The directory retires members silent for 60 s.
                next_room['polled'] = now
                membership = next_room['membership']
                membership['room'] = self.request('/poll', dict(room=membership['room']['id']), token=membership['token'])
            return
        if self.room['id'] != next_room['membership']['room']['id'] or self.room['phase'] != 'lobby':
            self.next_room = None
            return
        expected = next_room['expected']
        names = {p['slot']: p['name'] for p in self.room['players']}
        if not expected or len(names) - 1 < len(expected) and now - next_room['since'] < NEXT_RUN_WAIT:
            return
        self.next_room = None
        if len(names) == 1:
            self.status = 'Nobody rejoined in time. Start alone, or share the invite and start when the party is back.'
            return
        self.room = self.request('/action', dict(room=self.room['id'], action='start', revision=self.room['revision'],
                                                 build=self.build), True)
        missing = len(expected) - (len(names) - 1)
        self.status = ('Next run started.' if missing <= 0 else
                       f'Next run started without {missing} player{"s" if missing != 1 else ""} who did not rejoin in time.')

    def queue_game_command(self, command):
        try:
            self.commands.put_nowait(command)
        except queue.Full:
            raise ValueError('The game is busy; try the choice again in a moment.') from None

    def game_event(self, event):
        """Called on the game thread: never block or raise for directory bookkeeping."""
        if self.room_detached:
            return  # No listing left to update; the game channel carries the decision.
        try:
            self.events.put_nowait(event)
        except queue.Full:
            self.dropped_events = getattr(self, 'dropped_events', 0) + 1

    def chat(self, text):
        with self.lock:
            if not self.room:
                raise ValueError('Join a room first')
            self.room = self.request('/chat', dict(room=self.room['id'], text=text), True)

    def leave_membership(self, room_id, status, keep_mapping=False):
        """Retire this session only; never clear a subsequently joined room."""
        with self.lock:
            if not self.membership or not self.room or self.room['id'] != room_id:
                return
            try:
                self.request('/action', dict(room=room_id, action='leave', revision=self.room['revision']), True)
            except HTTPError as error:
                if error.code != 400:  # Already-closed rooms need no further cleanup.
                    message = 'The directory could not confirm leaving; membership will expire automatically.'
                    self.error = f'{self.error}\n{message}' if self.error else message
            except Exception:
                message = 'The directory could not confirm leaving; membership will expire automatically.'
                self.error = f'{self.error}\n{message}' if self.error else message
            finally:
                try:
                    if self.routes:
                        self.routes.close()
                finally:
                    self.routes = None
                    self.membership = self.room = None
                    self.status = status
                    if not keep_mapping:  # The next room keeps the host's port and router mapping.
                        self.release_mapping()

    def poll_room(self):
        """Only a rejected membership poll means the room has disappeared."""
        try:
            self.room = self.request('/poll', dict(room=self.room['id']), True)
        except HTTPError as error:
            if error.code != 400:
                raise
            if self.bridge is not None:
                # The directory only matches players. A running game owns its
                # authenticated channels and ends through them, not the listing.
                self.room_detached = True
                self.status = ('The room listing expired; the game continues over the existing connection. '
                               'Victory choices still work in the game window.')
                return False
            guest = self.room['slot'] != 1
            self.cancel.set()
            if self.routes:
                self.routes.close()
                self.routes = None
            self.release_mapping()
            self.membership = self.room = None
            self.status = 'The host ended the room.' if guest else 'The room has closed.'
            return False
        if not self.routes:
            self.start_routes()
        if self.routes:
            self.routes.update(dict(self.room))
        return True

    def heartbeat(self):
        while not self.stopped.wait(.5):
            try:
                with self.lock:
                    if (getattr(self, 'next_invite', None) and not self.membership
                            and not (self.worker and self.worker.is_alive())):
                        self.join_next_run()
                    if getattr(self, 'next_room', None):
                        self.next_run_due()
                    if not self.membership or getattr(self, 'room_detached', False):
                        continue
                    if not self.poll_room():
                        continue
                    while not self.events.empty():
                        event = self.events.get_nowait()
                        if self.room['slot'] != 1:
                            continue
                        if event == 9:
                            continue  # New hero stays off the directory (see action): the relay keeps the tunnels.
                        desired = 'victory' if event == 'victory' else 'keep_fighting'
                        required = 'playing' if event == 'victory' else 'victory'
                        if self.room['phase'] == required:
                            try:
                                self.room = self.request('/action', dict(room=self.room['id'], action=desired,
                                    revision=self.room['revision']), True)
                            except HTTPError as error:
                                if error.code != 400:
                                    raise
                                # Another guest may have left since the poll.
                                # Retry the native decision after refreshing.
                                self.events.put_nowait(event)
                                break
                    if self.room['phase'] == 'playing' and not self.launched:
                        self.launched = True
                        self.worker = threading.Thread(target=self.play, args=(dict(self.room),), daemon=True)
                        self.worker.start()
            except Exception as error:
                self.error = 'Room connection failed: ' + failure_description(error, self.directory)

    def check_compatibility(self):
        from build_hooks import resolve_reviewed_profile
        binary = Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe'))
        current = hashlib.sha256(binary.read_bytes()).hexdigest()
        if current != self.build:
            raise ValueError('The game changed after joining this room. Leave and join a room using the updated game.')
        candidate = os.environ.get('COOP_CANDIDATE_PROFILE')
        if candidate:
            if not self.isolated_profile:
                raise ValueError('Candidate compatibility profiles are restricted to isolated acceptance tests')
            home = Path(os.environ.get('COOP_CANDIDATE_HOME', '')).resolve()
            parent = (ROOT / 'coop-lab/compatibility-tests').resolve()
            if parent not in home.parents or not home.is_dir():
                raise ValueError('Candidate acceptance requires a disposable compatibility-test directory')
            from build_hooks import load_isolated_adapter_profile
            profile = load_isolated_adapter_profile(binary, candidate)
            if hashlib.sha256(binary.read_bytes()).hexdigest() != current or profile.get('sha256') != current:
                raise ValueError('The game changed during isolated compatibility checking')
            self.status = 'Isolated compatibility check ready. Connecting the test party…'
            return profile
        def progress(stage, detail):
            self.status = {
                'checking': 'Checking game compatibility…',
                'discovering': 'Update detected → checking compatibility…',
                'ready': 'Compatibility ready. Connecting the party…',
                'failure': 'Compatibility check stopped. See the details below.',
            }.get(stage, detail)
        profile = resolve_reviewed_profile(binary, allow_runtime_relocation=True, progress=progress,
            report_directory=ROOT / 'analysis/diagnostic-hooks' if os.environ.get('COOP_EXECUTABLE') else None)
        after = hashlib.sha256(binary.read_bytes()).hexdigest()
        if after != current or profile.get('sha256') != current or after != self.build:
            raise ValueError('The game changed during compatibility checking. Leave and join a room using the updated game.')
        return profile

    def play(self, room):
        channels = {}
        save = None
        crash_log = None
        after_run = None  # A link lost after the finished run: reported, never shown as an error.
        gameplay_log = None
        bridge = None
        diagnostic_events = deque(maxlen=96)
        completed_room = {k: room.get(k) for k in ('id', 'run', 'slot', 'build', 'version')}
        completed_room['build'] = completed_room['build'] or self.build
        completed_room['version'] = completed_room['version'] or self.version
        try:
            framework = (ROOT / 'COOP-VERSION.txt').read_text(encoding='utf-8').strip()
        except OSError:
            framework = 'unknown'
        upload_permit = room.get('crash_upload_permit')
        private_values = [room.get('invite'), room.get('ticket'), upload_permit,
                          (self.membership or {}).get('token'),
                          *room.get('tickets', {}).values()]
        try:
            if room.get('build', self.build) != self.build:
                raise ValueError('Host and local executable SHA-256 hashes differ; session start refused')
            profile = self.check_compatibility()
            from group_online import GroupOnlineBridge
            from native_guest_combat import NativeCombatBridge
            from party_menu import PartyMenu
            from native_probe import ACTIVE_HASH, run
            if ACTIVE_HASH != profile['sha256']:
                raise ValueError('The game changed while this launcher was open. Restart the launcher to load its verified adapter.')
            binary = Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe'))
            if (hashlib.sha256(binary.read_bytes()).hexdigest() != profile['sha256'] or
                    profile['sha256'] != self.build):
                raise ValueError('The game changed before party connection. Leave and join a room using the updated game.')
            number, count = room['slot'], len(room['players'])
            os.environ['COOP_PLAYERS'] = str(count)
            connection = room['connection']
            if not connection:
                raise ValueError('The host has not published its connection')
            self.status = 'Rechecking the final party connections…'
            with self.lock:
                if not self.poll_room() or self.room['players'] != room['players'] or self.room['slot'] != number:
                    raise ValueError('Party changed before launch. Form a new room to try again.')
                routes = self.routes
            if count > 1:
                if routes is None:
                    raise ValueError('Party connection is unavailable')
                channels = routes.prepare(room, self.cancel)
            with self.lock:
                if self.cancel.is_set() or self.stopped.is_set():
                    return
                if not self.poll_room() or self.room['players'] != room['players']:
                    raise ValueError('Party changed before launch. Form a new room to try again.')
                for channel in channels.values():
                    channel.check()
            owner = self
            parent = GroupOnlineBridge if channels else NativeCombatBridge
            class Game(PartyMenu, parent):
                def record(self, **event):
                    name = event.get('event')
                    if name in ('native_state', 'revival_progress', 'network_health', 'transport_failure',
                                'hit_queue_overflow', 'incoming_hits_obsolete', 'completed_run_transition',
                                'guest_departed', 'host_departed'):
                        row = json.dumps(event)
                        if len(row) <= 8192:
                            diagnostic_events.append(row)
                    if name == 'completed_run_transition' and event['player'] == number:
                        try:
                            from crash_reports import upload_completed
                            upload_completed(owner.directory, upload_permit, completed_room,
                                event['action'], event['duration_seconds'], framework,
                                '\n'.join(diagnostic_events), event['diagnostics'],
                                owner.profile.folder / 'logs', private_values)
                        except Exception as error:
                            print(f'Completion diagnostics could not be saved ({type(error).__name__}); gameplay continues.',
                                  file=sys.stderr, flush=True)
                    if event.get('event') == 'host_departed':
                        owner.status = (AFTER_RUN_STATUS if event.get('after_run') else 'The host ended the game.')
                    if event.get('event') == 'guest_departed':
                        owner.status = f'Player {event.get("player")} left. The remaining party can keep playing.'
                    if event.get('event') == 'party_restart_requires_lobby':
                        owner.status = ('Press Next run in the room browser to play the next map with this party.'
                                        if number == 1 else 'Waiting for the host to start the next run (or Leave).')
                    if event.get('event') == 'party_waiting_for_map':
                        owner.status = 'Choose your class and gear. Enter the game after the host confirms the map.'
                    if (event.get('event') == 'native_state' and event.get('player') == number
                            and not owner.cancel.is_set() and not owner.room_detached
                            and not owner.status.startswith(('The host ended', AFTER_RUN_STATUS))):
                        owner.status = 'Playing.' if event.get('phase') == 1 else 'Game connected.'
                    if event.get('event') == 'native_state' and event.get('player') == 1 and event.get('phase') == 5:
                        owner.game_event('victory')
                    if event.get('event') == 'host_victory_action':
                        owner.game_event(event['command'])
                    super().record(**event)

                def next_run_offered(self, offer):
                    owner.invited(offer, room)

                def poll_network(self):
                    if owner.cancel.is_set() or owner.stopped.is_set():
                        self.stop_requested = True
                        return
                    if number == 1 and next_run_closing(self, owner.next_room, time.monotonic()):
                        self.stop_requested = True  # Normal drain and save; the launcher switches rooms.
                    if owner.room_detached and not getattr(self, 'room_listing_logged', False):
                        self.room_listing_logged = True  # Logged on the game thread only.
                        self.record(event='room_listing_lost', room=room['id'])
                    while not owner.commands.empty():
                        command = owner.commands.get_nowait()
                        if command == 'stop':
                            self.stop_requested = True
                        elif number == 1 and self.native_states.get(1, (0,))[0] == 5:
                            self.request_victory_action(command)
                    if channels:
                        previous_map = self.host_map
                        super().poll_network()
                        if number != 1 and previous_map is None and self.host_map is not None:
                            owner.status = 'Host map confirmed. Finish your class and gear, then enter the game.'

            # Acceptance of several runs in a row (next run) keeps each run's log: log_suffix per run.
            with (ROOT / f'analysis/room-player-{number}{getattr(self, "log_suffix", "")}.jsonl').open('w') as output:
                gameplay_log = Path(output.name)
                bridge = Game(output, number, channels) if channels else Game(output)
                if self.diagnostic_autostart:
                    bridge.autostart = True
                    bridge.host_map = 'elwynn'
                self.bridge = bridge
                self.status = 'Loading the game in a window…'
                if not self.isolated_profile:
                    from personal_save import PersonalSave
                    save = PersonalSave(ROOT / 'coop-lab/personal')
                    bridge.profile_folder = save.folder
                # Event serialization and file writes leave the debugger thread:
                # every hook halts the game until it returns.
                getattr(bridge, 'start_log_writer', lambda: None)()
                try:
                    try:
                        run(86400, 1, bridge, player_numbers=[number])
                        failure = getattr(bridge, 'connection_failure', None)
                        if failure is not None and getattr(bridge, 'connection_after_run', False):
                            after_run = failure
                        elif failure is not None:
                            raise ConnectionError('Co-op host connection lost; local cleanup completed') from failure
                    except TimeoutError as error:
                        # The game has already closed and shutdown_drain_finished holds
                        # the leftover work; ending a played session is not a crash.
                        if not str(error).startswith('Co-op shutdown did not drain'):
                            raise
                        bridge.record(event='shutdown_drain_abandoned', error=str(error))
                    bridge.record(event='summary', **bridge.counts)
                    for peer, channel in list(channels.items()):
                        if not channel.closed:
                            try:
                                channel.finish()
                            except ConnectionError:
                                if not (channel.closed or channel.peer_goodbye.is_set()
                                        or peer in getattr(bridge, 'departed', ())
                                        or getattr(bridge, 'peer_finished', False)):
                                    raise
                finally:
                    getattr(bridge, 'stop_log_writer', lambda: None)()  # Before the log file closes.
        except Exception as error:
            log = self.profile.log_exception(error, room.get('slot', 1))
            crash_log = log
            if not self.cancel.is_set():
                cause = error.__cause__
                self.error = f'Game session failed: {error}' + (f' ({cause})' if cause else '')
                if log:
                    self.error += f' Full traceback: {log}'
        finally:
            if save:
                try:
                    # Native run has closed its processes, including on disconnect.
                    # Preserve any completed native save on every exit path.
                    save.commit()
                except Exception as error:
                    log = self.profile.log_exception(error, room.get('slot', 1), 'saving progress')
                    message = f'Progress could not be copied to single-player: {error}' + (f' Full traceback: {log}' if log else '')
                    self.error = f'{self.error}\n{message}' if self.error else message
                finally:
                    try:
                        save.close()
                    except Exception as error:
                        self.profile.log_exception(error, room.get('slot', 1), 'save cleanup')
            for channel in list(channels.values()):
                if not channel.closed:
                    try:
                        channel.close()
                    except Exception as error:
                        self.profile.log_exception(error, room.get('slot', 1), 'connection cleanup')
            self.bridge = None
            if after_run is not None and not crash_log:
                try:
                    raise ConnectionError('Co-op connection lost after the finished run; progress saved') from after_run
                except ConnectionError as error:
                    crash_log = self.profile.log_exception(error, room.get('slot', 1), 'after the run', quiet=True)
            if crash_log:
                from crash_reports import upload_report
                diagnostics = bridge.diagnostic_summary() if bridge is not None else None
                if after_run is not None:
                    diagnostics = dict(diagnostics or {}, after_run=True)  # Marked: the run had already ended.
                try:
                    report_status = upload_report(self.directory, upload_permit, crash_log,
                        gameplay_log, framework, private_values, diagnostics=diagnostics)
                except Exception as error:
                    report_status = f'Crash report upload failed ({type(error).__name__}); local logs retained.'
                if after_run is None:  # After the run: reported quietly, no error look for the player.
                    print(report_status, file=sys.stderr, flush=True)
                if self.error:
                    self.error += ' ' + report_status
            next_room = self.next_room if room.get('slot') == 1 else None
            if next_room and (next_room['expected'] is None or crash_log or self.stopped.is_set()):
                self.drop_next_room()  # The old game did not close for the next run.
                next_room = None
            status = (self.status if self.status.startswith(('The host ended', AFTER_RUN_STATUS)) or self.next_invite else
                      'The game session ended. Join or create a room to play again.')
            try:
                self.leave_membership(room['id'], status, keep_mapping=bool(next_room))
            except Exception as error:
                self.profile.log_exception(error, room.get('slot', 1), 'room cleanup')
            if next_room:
                try:
                    self.switch_to_next_room(next_room)
                except Exception as error:
                    self.profile.log_exception(error, 1, 'next run')
                    self.error = 'Next run could not open the new room: ' + failure_description(error, self.directory)
                    self.drop_next_room(next_room['membership'])
                    self.release_mapping()

    def state(self):
        with self.lock:
            room = None if self.room is None else {k: v for k, v in self.room.items()
                if k not in ('ticket', 'tickets', 'connection', 'crash_upload_permit')}
            if room and 'invite' in room:
                room['invite'] = room['id'] + ':' + room['invite']
            entry = None
            bridge = self.bridge
            if (room and room['slot'] != 1 and room['phase'] == 'playing'
                    and not self.error and not self.cancel.is_set()):
                if bridge:
                    if room['slot'] not in bridge.ready and room['slot'] not in bridge.menu_players:
                        entry = dict(ready=bridge.host_map is not None, map=bridge.host_map)
                elif not self.launched or self.worker and self.worker.is_alive():
                    entry = dict(ready=False, map=None, starting=True)
            routes, latency = {}, {}
            if self.routes:
                with self.routes.lock:
                    routes = dict(self.routes.labels)
                    if room:
                        latency = {(peer if room['slot'] == 1 else room['slot']): channel.latency_ms()
                                   for peer, channel in self.routes.channels.items()}
            status = self.status + (' ' + self.profile.warning if self.profile.warning else '')
            if getattr(self, 'firewall_hint', None) and room and room.get('slot') == 1:
                status += ' ' + self.firewall_hint
            next_run = dict(available=bool(room and room['slot'] == 1 and bridge is not None and not self.next_room
                                           and hasattr(bridge, 'offer_next_run') and bridge.run_over()),
                            preparing=bool(self.next_room), invited=bool(self.next_invite),
                            run_over=bool(bridge is not None and hasattr(bridge, 'run_finished_here') and bridge.run_finished_here()))
            return dict(room=room, status=status, error=self.error, guest_entry=entry, routes=routes, latency=latency,
                        connection_error=self.routes.error if self.routes else None, next_run=next_run)

    def shutdown(self):
        self.stopped.set()
        self.cancel.set()
        if self.worker and self.worker.is_alive():
            self.worker.join(15)
        with self.lock:
            if self.room:
                self.leave_membership(self.room['id'], 'Room browser closed.')
            self.release_mapping()


class UI(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass

    def reply(self, status, body, content='application/json'):
        body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', content + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.headers.get('Host') != f'127.0.0.1:{self.server.server_port}':
            self.reply(403, dict(error='Invalid local host'))
            return
        try:
            if self.path == '/':
                page = (ROOT / 'reconstruction/lobby.html').read_text(encoding='utf-8').replace('__CLIENT_SECRET__', self.server.secret)
                defaults = json.dumps(self.server.client.profile.preferences, ensure_ascii=True).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
                page = page.replace('__LAUNCHER_DEFAULTS__', defaults)
                self.reply(200, page.encode(), 'text/html')
            elif self.path == '/state':
                self.reply(200, self.server.client.state())
            elif self.path == '/rooms':
                client = self.server.client
                self.reply(200, dict(client.request('/rooms'), local_build=client.build, local_version=client.version))
            else:
                self.reply(404, dict(error='Not found'))
        except Exception as error:
            self.reply(503, dict(error=failure_description(error, self.server.client.directory)))

    def do_POST(self):
        if self.headers.get('X-Coop-Client') != self.server.secret or self.headers.get_content_type() != 'application/json':
            self.reply(403, dict(error='Invalid local request'))
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 1 <= size <= 8192:
                raise ValueError('Request is too large')
            data = json.loads(self.rfile.read(size))
            client = self.server.client
            if self.path == '/create':
                client.create(data['name'], data['player'], data['private'], data['address'], data['port'], data.get('region'))
            elif self.path == '/join':
                client.join(data['player'], data.get('room'), data.get('code'), data.get('region'))
            elif self.path == '/chat':
                client.chat(data['text'])
            elif self.path == '/action':
                client.action(data['action'])
            else:
                raise ValueError('Unknown action')
            self.reply(200, client.state())
        except Exception as error:
            self.reply(400, dict(error=failure_description(error, self.server.client.directory)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', default='http://127.0.0.1:47770')
    parser.add_argument('--port', type=int, default=47772)
    parser.add_argument('--local-directory', action='store_true')
    parser.add_argument('--open-browser', action='store_true')
    parser.add_argument('--profile', type=Path, help='Independent launcher settings/log folder; use a different folder per local client')
    parser.add_argument('--isolated-profile', action='store_true',
                        help='Use disposable characters for multiple local test clients')
    args = parser.parse_args()
    directory = None
    if args.local_directory:
        from lobby_server import server
        directory = server(('127.0.0.1', 47770))
        threading.Thread(target=directory.serve_forever, daemon=True).start()
    client = RoomClient(args.directory, isolated_profile=args.isolated_profile, profile_folder=args.profile)
    threading.Thread(target=client.heartbeat, daemon=True).start()
    with ThreadingHTTPServer(('127.0.0.1', args.port), UI) as app:
        app.client, app.secret = client, secrets.token_hex(32)
        print(f'Room browser: http://127.0.0.1:{args.port}', flush=True)
        if args.open_browser:
            import webbrowser
            webbrowser.open(f'http://127.0.0.1:{args.port}')
        try:
            app.serve_forever()
        finally:
            client.shutdown()
            if directory:
                directory.shutdown()
                directory.server_close()


if __name__ == '__main__':
    main()
