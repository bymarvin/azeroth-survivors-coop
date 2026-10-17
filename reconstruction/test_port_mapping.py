"""Offline checks for host port mapping against an in-process fake IGD and NAT-PMP/PCP gateway.

Everything runs on loopback: the "gateway" is 127.0.0.1, SSDP goes to a local
UDP responder, SOAP to a local HTTP server, NAT-PMP/PCP to a local UDP server.
No packet leaves the machine and no real router is touched.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import re
import socket
import struct
import threading
import time
import unittest
from types import SimpleNamespace

import port_mapping
from port_mapping import PortMapper, MappingError, safe_xml, public_address

GATEWAY = LOCAL = '127.0.0.1'
SERVICE = 'urn:schemas-upnp-org:service:WANIPConnection:1'


class FakeIgd:
    """SSDP responder plus HTTP description/SOAP control on loopback."""
    def __init__(self, external='81.169.145.7', responder=GATEWAY, description=None, errors=None, existing=None,
                 delay=0.0):
        self.external, self.errors, self.mappings, self.calls = external, dict(errors or {}), dict(existing or {}), []
        self.delay = delay  # A slow router: seconds before the SSDP answer.
        self.http = ThreadingHTTPServer((GATEWAY, 0), self.handler())
        self.http.daemon_threads = True
        self.description = description or (
            '<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceList><device>'
            '<serviceList><service><serviceType>' + SERVICE + '</serviceType>'
            '<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></deviceList></device></root>')
        self.ssdp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ssdp.bind((responder, 0))
        self.ssdp.settimeout(.1)
        self.running = True
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        threading.Thread(target=self.answer, daemon=True).start()

    @property
    def ssdp_port(self):
        return self.ssdp.getsockname()[1]

    def answer(self):
        while self.running:
            try:
                data, sender = self.ssdp.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            if data.startswith(b'M-SEARCH'):
                time.sleep(self.delay)
                reply = ('HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n'
                         f'LOCATION: http://{GATEWAY}:{self.http.server_port}/desc.xml\r\n\r\n')
                try:
                    self.ssdp.sendto(reply.encode(), sender)
                except OSError:
                    pass  # Closed while a delayed answer was pending.

    def handler(self):
        igd = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def send(self, status, body):
                data = body.encode()
                self.send_response(status)
                self.send_header('Content-Type', 'text/xml')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self.send(200, igd.description)

            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length'])).decode()
                action = self.headers['SOAPAction'].strip('"').split('#')[1]
                args = dict(re.findall(r'<(New\w+)>([^<]*)</\1>', body))
                igd.calls.append((action, args))
                if action in igd.errors:
                    code = igd.errors[action]
                    if isinstance(code, list):
                        code = code.pop(0) if code else None
                    if code:
                        return self.send(500, '<?xml version="1.0"?><s:Envelope xmlns:s="x"><s:Body><s:Fault><detail>'
                                         f'<UPnPError><errorCode>{code}</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>')
                values = {}
                if action == 'GetExternalIPAddress':
                    values = dict(NewExternalIPAddress=igd.external)
                elif action == 'GetSpecificPortMappingEntry':
                    entry = igd.mappings.get(int(args['NewExternalPort']))
                    if entry is None:
                        return self.send(500, '<?xml version="1.0"?><e><errorCode>714</errorCode></e>')
                    values = entry
                elif action == 'GetGenericPortMappingEntry':
                    rows = list(igd.mappings.items())
                    index = int(args['NewPortMappingIndex'])
                    if index >= len(rows):
                        return self.send(500, '<?xml version="1.0"?><e><errorCode>713</errorCode></e>')
                    port, entry = rows[index]
                    values = dict(NewExternalPort=port, NewProtocol='TCP', **entry)
                elif action == 'AddPortMapping':
                    igd.mappings[int(args['NewExternalPort'])] = dict(
                        NewInternalClient=args['NewInternalClient'], NewInternalPort=args['NewInternalPort'],
                        NewLeaseDuration=args['NewLeaseDuration'],
                        NewPortMappingDescription=args['NewPortMappingDescription'])
                elif action == 'DeletePortMapping':
                    igd.mappings.pop(int(args['NewExternalPort']), None)
                inner = ''.join(f'<{k}>{v}</{k}>' for k, v in values.items())
                self.send(200, '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
                          f'<s:Body><u:{action}Response xmlns:u="{SERVICE}">{inner}</u:{action}Response></s:Body></s:Envelope>')
        return Handler

    def close(self):
        self.running = False
        self.http.shutdown()
        self.http.server_close()
        self.ssdp.close()


class FakePmp:
    """NAT-PMP (version 0) and optionally PCP (version 2) on one UDP port."""
    def __init__(self, external='93.184.216.34', pcp=False, result=0, assign=None):
        self.external, self.pcp, self.result, self.assign = external, pcp, result, assign
        self.mappings, self.requests = {}, []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((GATEWAY, 0))
        self.sock.settimeout(.1)
        self.running = True
        threading.Thread(target=self.serve, daemon=True).start()

    @property
    def port(self):
        return self.sock.getsockname()[1]

    def serve(self):
        while self.running:
            try:
                data, sender = self.sock.recvfrom(1100)
            except (socket.timeout, OSError):
                continue
            self.requests.append(data)
            if data[0] == 2:
                if not self.pcp:
                    self.sock.sendto(struct.pack('!BBH', 0, data[1] | 0x80, 1) + b'\x00' * 8, sender)
                    continue
                lifetime = struct.unpack('!I', data[4:8])[0]
                nonce, internal = data[24:36], struct.unpack('!H', data[40:42])[0]
                external = self.assign or internal
                if lifetime:
                    self.mappings[internal] = lifetime
                else:
                    self.mappings.pop(internal, None)
                reply = (struct.pack('!BBBBII', 2, 0x81, 0, self.result, lifetime, 1) + b'\x00' * 12 + nonce +
                         struct.pack('!B3xHH', 6, internal, external) + b'\x00' * 10 + b'\xff\xff' +
                         socket.inet_aton(self.external))
                self.sock.sendto(reply, sender)
            elif data[:2] == b'\x00\x00':
                self.sock.sendto(struct.pack('!BBHI', 0, 0x80, 0, 1) + socket.inet_aton(self.external), sender)
            elif data[:2] == b'\x00\x02':
                _, _, _, internal, _, lifetime = struct.unpack('!BBHHHI', data[:12])
                if lifetime:
                    self.mappings[internal] = lifetime
                else:
                    self.mappings.pop(internal, None)
                self.sock.sendto(struct.pack('!BBHIHHI', 0, 0x82, self.result, 1, internal,
                                             self.assign or internal, lifetime), sender)

    def close(self):
        self.running = False
        self.sock.close()


def closed_udp_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind((GATEWAY, 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class PortMappingTests(unittest.TestCase):
    def mapper(self, igd=None, pmp=None, **options):
        events = []
        mapper = PortMapper(47771, lambda **e: events.append(e), route=lambda: (GATEWAY, LOCAL),
                            timeout=.6, ssdp=(GATEWAY, igd.ssdp_port if igd else closed_udp_port()),
                            pmp_port=pmp.port if pmp else closed_udp_port(), **options)
        return mapper, events

    def test_upnp_maps_publishes_and_cleans_up(self):
        igd = FakeIgd()
        try:
            mapper, events = self.mapper(igd)
            self.assertEqual(mapper.open(), ('81.169.145.7', 47771))
            self.assertEqual(igd.mappings[47771]['NewInternalClient'], LOCAL)
            self.assertEqual(igd.mappings[47771]['NewLeaseDuration'], '3600')
            self.assertEqual(events[-1]['event'], 'upnp_mapped')
            mapper.close()
            self.assertNotIn(47771, igd.mappings)
            self.assertEqual(events[-1]['event'], 'upnp_released')
            mapper.close()  # Idempotent.
        finally:
            igd.close()

    def test_cgnat_or_private_external_address_gets_no_direct_offer(self):
        for external, kind in (('100.64.12.1', 'cgnat'), ('192.168.0.2', 'private'), ('10.1.2.3', 'private')):
            igd = FakeIgd(external=external)
            try:
                mapper, events = self.mapper(igd)
                self.assertIsNone(mapper.open())
                self.assertEqual((events[-1]['event'], events[-1]['reason'], events[-1]['external']),
                                 ('upnp_failed', 'not_public', kind))
                self.assertNotIn(47771, igd.mappings)  # The pointless mapping was removed again.
            finally:
                igd.close()

    def test_router_without_upnp_or_pmp(self):
        mapper, events = self.mapper()
        started = time.monotonic()
        self.assertIsNone(mapper.open())
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual(events[-1]['event'], 'upnp_failed')
        self.assertEqual(set(events[-1]['attempts']), {'upnp', 'pcp', 'nat-pmp'})
        self.assertEqual(events[-1]['attempts']['upnp'], 'no_upnp')

    def test_other_devices_rule_is_never_touched(self):
        foreign = {47771: dict(NewInternalClient='192.168.1.50', NewInternalPort='47771', NewLeaseDuration='0')}
        igd = FakeIgd(existing=foreign)
        try:
            mapper, events = self.mapper(igd)
            self.assertIsNone(mapper.open())
            self.assertEqual(events[-1]['attempts']['upnp'], 'conflict')
            self.assertEqual(igd.mappings, foreign)
            self.assertFalse([c for c in igd.calls if c[0] in ('AddPortMapping', 'DeletePortMapping')])
        finally:
            igd.close()

    def test_own_stale_rule_is_refreshed_and_718_is_a_conflict(self):
        own = {47771: dict(NewInternalClient=LOCAL, NewInternalPort='47771', NewLeaseDuration='100')}
        igd = FakeIgd(existing=own)
        try:
            mapper, _ = self.mapper(igd)
            self.assertIsNotNone(mapper.open())  # Left over by an earlier crash of this PC.
            mapper.close()
        finally:
            igd.close()
        igd = FakeIgd(errors=dict(AddPortMapping='718'))
        try:
            mapper, events = self.mapper(igd)
            self.assertIsNone(mapper.open())
            self.assertEqual(events[-1]['attempts']['upnp'], 'conflict')
        finally:
            igd.close()

    def test_permanent_lease_only_router(self):
        igd = FakeIgd(errors=dict(AddPortMapping=['725']))
        try:
            mapper, events = self.mapper(igd)
            self.assertIsNotNone(mapper.open())
            self.assertEqual(igd.mappings[47771]['NewLeaseDuration'], '0')
            self.assertIn('upnp_permanent_lease', [e['event'] for e in events])
            self.assertIsNone(mapper.renewer)  # Nothing to renew.
            mapper.close()
            self.assertNotIn(47771, igd.mappings)
        finally:
            igd.close()

    def test_crashed_permanent_rules_of_this_pc_are_cleaned_up(self):
        mine = dict(NewInternalClient=LOCAL, NewPortMappingDescription=port_mapping.DESCRIPTION)
        existing = {
            47790: dict(mine, NewInternalPort='47790', NewLeaseDuration='0'),        # Our crash leftover.
            47791: dict(mine, NewInternalPort='47791', NewLeaseDuration='0'),        # Another leftover.
            47792: dict(mine, NewInternalPort='47792', NewLeaseDuration='1800'),     # Leased: expires itself.
            47793: dict(NewInternalClient=LOCAL, NewInternalPort='47793', NewLeaseDuration='0',
                        NewPortMappingDescription='Some other program'),             # Not ours.
            47794: dict(mine, NewInternalClient='192.168.1.77', NewInternalPort='47794',
                        NewLeaseDuration='0'),                                       # Another PC.
            47771: dict(mine, NewInternalPort='47771', NewLeaseDuration='0'),        # Same port: taken over.
        }
        igd = FakeIgd(existing=existing, errors=dict(AddPortMapping=['725']))
        try:
            mapper, events = self.mapper(igd)
            self.assertIsNotNone(mapper.open())
            self.assertEqual(sorted(igd.mappings), [47771, 47792, 47793, 47794])
            removed = [e for e in events if e['event'] == 'upnp_stale_removed']
            self.assertEqual((removed[0]['ports'], removed[0]['level']), ([47790, 47791], 'WARN'))
            warned = [e for e in events if e['event'] == 'upnp_permanent_lease']
            self.assertEqual(warned[0]['level'], 'WARN')
            mapper.close()
            self.assertEqual(sorted(igd.mappings), [47792, 47793, 47794])  # Ours gone on close.
        finally:
            igd.close()

    def test_lease_is_renewed_while_open(self):
        igd = FakeIgd()
        try:
            mapper, events = self.mapper(igd, lease=1, min_renew=.2)
            self.assertIsNotNone(mapper.open())
            deadline = time.monotonic() + 3
            while mapper.renewals < 2 and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertGreaterEqual(mapper.renewals, 2)
            mapper.close()
            count = mapper.renewals
            time.sleep(.6)
            self.assertEqual(mapper.renewals, count)  # Renewal stops with the room.
        finally:
            igd.close()

    def test_responses_from_other_hosts_are_ignored(self):
        igd = FakeIgd(responder='127.0.0.2')  # Answers, but not from the default gateway.
        try:
            mapper, events = self.mapper(igd)
            self.assertIsNone(mapper.open())
            self.assertEqual(events[-1]['attempts']['upnp'], 'no_upnp')
            self.assertFalse(igd.calls)
        finally:
            igd.close()

    def test_xml_declarations_and_oversized_answers_are_refused(self):
        bomb = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><root>&b;</root>')
        igd = FakeIgd(description=bomb)
        try:
            mapper, events = self.mapper(igd)
            self.assertIsNone(mapper.open())
            self.assertEqual(events[-1]['attempts']['upnp'], 'xml_declarations_refused')
        finally:
            igd.close()
        with self.assertRaises(MappingError):
            safe_xml(b'<a>' + b'x' * port_mapping.MAX_BODY + b'</a>')

    def test_foreign_control_url_is_refused(self):
        description = ('<root><device><serviceList><service><serviceType>' + SERVICE + '</serviceType>'
                       '<controlURL>http://192.0.2.80/ctl</controlURL></service></serviceList></device></root>')
        igd = FakeIgd(description=description)
        try:
            mapper, events = self.mapper(igd)
            self.assertIsNone(mapper.open())
            self.assertEqual(events[-1]['attempts']['upnp'], 'foreign_gateway_url')
        finally:
            igd.close()

    def test_nat_pmp_fallback_maps_and_releases(self):
        pmp = FakePmp()
        try:
            mapper, events = self.mapper(pmp=pmp)
            self.assertEqual(mapper.open(), ('93.184.216.34', 47771))
            self.assertEqual((events[-1]['event'], events[-1]['method']), ('upnp_mapped', 'nat-pmp'))
            self.assertEqual(pmp.mappings, {47771: 3600})
            mapper.close()
            self.assertEqual(pmp.mappings, {})
        finally:
            pmp.close()

    def test_pcp_fallback_and_changed_port_is_refused(self):
        pmp = FakePmp(pcp=True)
        try:
            mapper, events = self.mapper(pmp=pmp)
            self.assertEqual(mapper.open(), ('93.184.216.34', 47771))
            self.assertEqual(events[-1]['method'], 'pcp')
            mapper.close()
            self.assertEqual(pmp.mappings, {})
        finally:
            pmp.close()
        pmp = FakePmp(pcp=True, assign=50000)
        try:
            mapper, events = self.mapper(pmp=pmp)
            self.assertIsNone(mapper.open())
            self.assertEqual(events[-1]['attempts']['pcp'], 'port_changed')
            self.assertEqual(pmp.mappings, {})  # The moved mapping was deleted again.
        finally:
            pmp.close()

    def test_route_failure_and_port_bounds(self):
        events = []
        def no_route():
            raise MappingError('no_gateway')
        self.assertIsNone(PortMapper(47771, lambda **e: events.append(e), route=no_route).open())
        self.assertEqual(events[-1], dict(event='upnp_failed', reason='no_gateway', method='route'))
        for port in (80, 70000, '47771'):
            with self.assertRaises(ValueError):
                PortMapper(port)


class AddressTests(unittest.TestCase):
    def test_public_address_helper(self):
        self.assertTrue(public_address('8.8.8.8'))
        self.assertTrue(public_address('2001:4860:4860::8888'))
        for text in ('100.127.255.254', '::ffff:10.0.0.1', '192.168.1.2', '127.0.0.1', '203.0.113.7',
                     'example.com', None, '', 7):
            self.assertFalse(public_address(text), text)


class HostOfferTests(unittest.TestCase):
    def owner(self, directory):
        import room_client
        events = []
        owner = SimpleNamespace(directory=directory, mapper=None, status='',
                                network_event=lambda **e: events.append(e))
        return room_client.RoomClient.direct_endpoint.__get__(owner), owner, events

    def test_local_directory_keeps_loopback_and_never_maps(self):
        direct, owner, events = self.owner('http://127.0.0.1:47770')
        self.assertEqual(direct('auto', 47771), '127.0.0.1')
        self.assertEqual(direct('127.0.0.1', 47771), '127.0.0.1')
        self.assertEqual(events, [])

    def test_remote_directory_manual_disabled_and_mapped(self):
        import os
        from unittest.mock import patch
        direct, owner, events = self.owner('https://dash2812.de')
        self.assertEqual(direct('81.169.145.7', 47771), '81.169.145.7')
        self.assertEqual(events[-1]['scope'], 'public')
        # A typed-in LAN address is published unchanged, as in earlier versions.
        self.assertEqual(direct('192.168.1.2', 47771), '192.168.1.2')
        self.assertEqual(events[-1]['scope'], 'other')
        with patch.dict(os.environ, COOP_UPNP='0'):
            self.assertIsNone(direct('auto', 47771))
        self.assertEqual(events[-1], dict(event='upnp_failed', reason='disabled'))
        igd = FakeIgd()
        try:
            def fake_mapper(port, log):
                return PortMapper(port, log, route=lambda: (GATEWAY, LOCAL), timeout=.6,
                                  ssdp=(GATEWAY, igd.ssdp_port), pmp_port=closed_udp_port())
            with patch.dict(os.environ, COOP_UPNP='1'), patch('port_mapping.PortMapper', fake_mapper):
                self.assertEqual(direct('auto', 47771), '81.169.145.7')
            self.assertIsNotNone(owner.mapper)
            owner.mapper.close()
            self.assertNotIn(47771, igd.mappings)
        finally:
            igd.close()


class UnchangedDirectoryTests(unittest.TestCase):
    """0.0.12 hosts against the unchanged directory code (lobby.py of 0.0.7 / Fix 7264)."""
    def host(self, direct):
        import threading
        import room_client
        from lobby import Rooms
        rooms, sent, state = Rooms(), [], {}
        def request(path, data=None, authenticated=False):
            sent.append((path, dict(data or {})))
            if path == '/create':
                state.update(rooms.create(data['name'], data['player'], data['private'], data['build'],
                                          data.get('region'), data.get('version')))
                return state
            if path == '/connection':  # Exactly what lobby_server passes on.
                return rooms.connection(data['room'], state['token'], data['address'], data['port'], data['fingerprint'])
            raise AssertionError(path)
        owner = SimpleNamespace(membership=None, worker=None, lock=threading.RLock(), request=request,
                                build='b' * 64, version='0.95.0', pairing=None, stopped=threading.Event(),
                                reset_session=lambda: None, direct_endpoint=lambda address, port: direct,
                                release_mapping=lambda: None, start_routes=lambda: None,
                                leave_membership=lambda *a: None, status='',
                                profile=SimpleNamespace(save=lambda **k: None))
        owner.publish_room = room_client.RoomClient.publish_room.__get__(owner)
        room_client.RoomClient.create(owner, 'Room', 'Host', False, 'auto', 47771)
        return owner, [data for path, data in sent if path == '/connection']

    def test_mapped_public_address_is_accepted(self):
        owner, published = self.host('81.169.145.7')
        self.assertEqual(owner.room['connection']['address'], '81.169.145.7')
        self.assertIn('directly', owner.status)
        self.assertEqual(set(published[0]), {'room', 'address', 'port', 'fingerprint'})

    def test_no_offer_sends_the_former_placeholder_never_null(self):
        owner, published = self.host(None)
        self.assertEqual([p['address'] for p in published], ['127.0.0.1'])
        self.assertEqual(owner.room['connection']['address'], '127.0.0.1')
        self.assertIn('relay', owner.status)
        self.assertEqual(set(published[0]), {'room', 'address', 'port', 'fingerprint'})  # No new fields.


class HostingWithoutLockTests(unittest.TestCase):
    """The room browser stays responsive while a slow router is asked."""
    def client(self, igd):
        import os
        import tempfile
        from unittest.mock import patch
        import room_client
        client = room_client.RoomClient('https://dash2812.de', profile_folder=tempfile.mkdtemp())
        state = {}
        def request(path, data=None, authenticated=False):
            if path == '/create':
                state.update(token='secret', room=dict(id='r1', slot=1, revision=1))
                return state
            if path == '/connection':
                return dict(id='r1', slot=1, revision=2, phase='lobby', players=[],
                            connection=dict(address=data['address'], port=data['port']))
            raise AssertionError(path)
        client.request, client.start_routes = request, lambda: None
        def fake_mapper(port, log):
            return PortMapper(port, log, route=lambda: (GATEWAY, LOCAL), timeout=3,
                              ssdp=(GATEWAY, igd.ssdp_port), pmp_port=closed_udp_port())
        patches = [patch.dict(os.environ, COOP_UPNP='1'), patch('port_mapping.PortMapper', fake_mapper)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        return client

    def test_state_answers_and_shows_progress_during_a_slow_mapping(self):
        igd = FakeIgd(delay=1.5)
        self.addCleanup(igd.close)
        client = self.client(igd)
        errors = []
        def host():
            try:
                client.create('Room', 'Host', False, 'auto', 47771)
            except Exception as error:
                errors.append(error)
        worker = threading.Thread(target=host)
        worker.start()
        time.sleep(.3)
        started = time.monotonic()
        state = client.state()
        self.assertLess(time.monotonic() - started, .5)  # Not blocked by the router.
        self.assertIn('Opening the game port on your router', state['status'])
        with self.assertRaises(ValueError):
            client.join('Guest', 'other-room')  # No second session while hosting starts.
        worker.join(10)
        self.assertEqual(errors, [])
        self.assertEqual(client.room['connection']['address'], '81.169.145.7')
        self.assertIn('directly', client.state()['status'])
        client.release_mapping()
        self.assertNotIn(47771, igd.mappings)

    def test_closing_the_browser_during_mapping_releases_it(self):
        igd = FakeIgd(delay=1.0)
        self.addCleanup(igd.close)
        client = self.client(igd)
        errors = []
        def host():
            try:
                client.create('Room', 'Host', False, 'auto', 47771)
            except Exception as error:
                errors.append(error)
        worker = threading.Thread(target=host)
        worker.start()
        time.sleep(.3)
        client.shutdown()  # Browser closed while the router is still being asked.
        worker.join(10)
        self.assertEqual([str(e) for e in errors], ['Room creation was cancelled.'])
        self.assertIsNone(client.room)
        self.assertIsNone(client.mapper)
        self.assertNotIn(47771, igd.mappings)


class GuestRouteTests(unittest.TestCase):
    """Guest: direct first (bounded), relay on failure or without a direct offer."""
    def run_guest(self, address, direct, server='dash2812.de'):
        import concurrent.futures
        import queue
        import sys
        from pathlib import Path
        from unittest.mock import patch
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # This checkout's relay/.
        from relay import routing
        calls, events = [], []

        class Channel:
            closed, error = False, None
            def __init__(self):
                self.incoming = queue.Queue()
            def send(self, message):
                if message.get('kind') == 'route':
                    self.route = message['route']
                    self.incoming.put(dict(kind='route', run=1, slot=2))
            def check(self):
                pass
            def close(self):
                self.closed = True

        def connect(host, port, invite, build, slot, timeout=10):
            calls.append((host, port, timeout))
            if host != '127.0.0.1' and not direct:
                raise TimeoutError('Co-op connection timed out')
            return Channel()

        class Helper:
            def __init__(self, *args):
                self.ready = concurrent.futures.Future()
                self.ready.set_result(50123)
            def close(self):
                pass
        room = dict(id='r', slot=2, run=1, ticket='t', tickets={},
                    connection=dict(address=address, port=47771, fingerprint='f' * 64))
        with patch.object(routing, 'connect', connect), patch.object(routing, 'Helper', Helper):
            routes = routing.Routes(room, 'token', None, 'build', server=server, log=lambda **e: events.append(e))
            try:
                deadline = time.monotonic() + 5
                while 1 not in routes.channels and time.monotonic() < deadline:
                    time.sleep(.02)
                label = routes.labels.get(2)
                channel = routes.channels.get(1)
            finally:
                routes.close()
        return calls, events, label, channel

    def test_direct_connection_is_used_when_reachable(self):
        # Also the same-router case: the public address via the router's hairpin NAT.
        calls, events, label, channel = self.run_guest('81.169.145.7', direct=True)
        self.assertEqual((label, channel.route), ('Direct', 'Direct'))
        self.assertEqual(calls, [('81.169.145.7', 47771, 3)])
        self.assertEqual(events[0]['event'], 'direct_connected')

    def test_direct_timeout_falls_back_to_relay(self):
        # Also a router without hairpin NAT for a guest at the host's home.
        calls, events, label, channel = self.run_guest('81.169.145.7', direct=False)
        self.assertEqual((label, channel.route), ('Relay', 'Relay'))
        self.assertEqual(calls, [('81.169.145.7', 47771, 3), ('127.0.0.1', 50123, 10)])
        self.assertEqual([(e['event'], e.get('reason')) for e in events],
                         [('direct_failed', 'TimeoutError'), ('relay_connected', None)])

    def test_placeholder_on_a_remote_directory_goes_straight_to_relay(self):
        for address in ('127.0.0.1', None):
            calls, events, label, channel = self.run_guest(address, direct=True)
            self.assertEqual(label, 'Relay')
            self.assertEqual(calls, [('127.0.0.1', 50123, 10)])  # Only the local relay link.
            self.assertEqual(events[0], dict(event='direct_failed', slot=2, route='relay', reason='no_direct_offer'))
            self.assertFalse(any(v in ('t', 'token') for e in events for v in e.values()))

    def test_local_test_directory_keeps_the_loopback_direct_route(self):
        calls, events, label, channel = self.run_guest('127.0.0.1', direct=True, server='127.0.0.1')
        self.assertEqual(label, 'Direct')
        self.assertEqual(calls, [('127.0.0.1', 47771, 3)])


class FirewallHintTests(unittest.TestCase):
    def hint(self, address):
        import tempfile
        from pathlib import Path
        import room_client
        folder = tempfile.mkdtemp()
        owner = SimpleNamespace(profile=SimpleNamespace(folder=Path(folder)),
                                room=dict(slot=1, connection=dict(address=address, port=47771)))
        owner.write_network_event = room_client.RoomClient.write_network_event.__get__(owner)
        event = room_client.RoomClient.network_event.__get__(owner)
        event(event='guest_route', slot=3, route='Direct')
        event(event='guest_route', slot=2, route='Relay')
        log = ''.join(p.read_text() for p in Path(folder, 'logs').glob('network-*.jsonl'))
        return getattr(owner, 'firewall_hint', None), log

    def test_hint_when_a_guest_needs_the_relay_despite_an_offer(self):
        hint, log = self.hint('81.169.145.7')
        self.assertIn('inbound TCP port 47771', hint)
        self.assertIn('"event": "firewall_hint"', log)
        self.assertIn('"level": "WARN"', log)

    def test_no_hint_when_the_relay_was_the_only_way(self):
        for address in ('127.0.0.1', None):
            hint, log = self.hint(address)
            self.assertIsNone(hint)
            self.assertNotIn('firewall_hint', log)


if __name__ == '__main__':
    unittest.main()
