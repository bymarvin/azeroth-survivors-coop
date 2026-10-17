"""Real loopback TLS, authentication, framing and bounded damage acknowledgements."""
import io
import json
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, PropertyMock

from coop_transport import create_pairing, accept, connect, encode, receive
from online_bridge import OnlineBridge


class TransportTests(unittest.TestCase):
    def test_receive_backpressure_has_distinct_timeout_diagnostics(self):
        with tempfile.TemporaryDirectory() as folder, socket.create_server(('127.0.0.1', 0)) as listener:
            invite = create_pairing(folder)
            result = []
            thread = threading.Thread(target=lambda: result.append(accept(listener, folder, invite, 'test')))
            thread.start()
            guest = connect('127.0.0.1', listener.getsockname()[1], invite, 'test')
            thread.join(5)
            host = result[0]
            try:
                for i in range(64):
                    host.send(dict(index=i))
                deadline = time.monotonic() + 14
                while guest.error is None and time.monotonic() < deadline:
                    time.sleep(.05)
                self.assertIsInstance(guest.error, TimeoutError)
                self.assertIn('local incoming queue full', str(guest.error))
                report = guest.diagnostics()
                self.assertEqual(report['incoming_messages'], 16)
                self.assertGreaterEqual(report['receive_full_seconds'], 9)
            finally:
                guest.close()
                host.close()

    def test_diagnostic_snapshot_preserves_cause_and_queue_pressure_without_payload(self):
        from coop_transport import Channel
        with patch('coop_transport.threading.Thread.start'):
            channel = Channel(None)
        channel.send(dict(token='private-token'))
        channel.incoming.put_nowait(dict(ticket='private-ticket'))
        channel.error = TimeoutError('Co-op local receive backlog prevented reads for the timeout window')
        channel.last_received -= 12
        channel.receive_full_since = time.monotonic() - 11
        with patch.object(Channel, 'receive_full_since', create=True, new_callable=PropertyMock,
                          side_effect=[channel.receive_full_since, None]) as full_since:
            report = channel.diagnostics()
            full_since.assert_called_once()
        self.assertEqual(report['incoming_messages'], 1)
        self.assertEqual(report['outgoing_messages'], 1)
        self.assertGreaterEqual(report['last_receive_seconds'], 12)
        self.assertGreaterEqual(report['receive_full_seconds'], 11)
        self.assertEqual(report['errors'][0]['type'], 'TimeoutError')
        self.assertNotIn('private-', json.dumps(report))

    def test_outgoing_burst_is_fifo_nonblocking_and_bounded(self):
        from coop_transport import Channel, MAX_MESSAGE
        with patch('coop_transport.threading.Thread.start'):
            channel = Channel(None)
        for index in range(256):
            channel.send(dict(index=index))
        with self.assertRaisesRegex(TimeoutError, '256 messages'):
            channel.send(dict(index=256))
        bodies = [channel.outgoing.get_nowait() for _ in range(256)]
        self.assertEqual([json.loads(body)['index'] for body in bodies], list(range(256)))
        self.assertEqual(channel.queued_bytes, sum(map(len, bodies)))
        import coop_transport
        self.assertGreaterEqual(MAX_MESSAGE, 32 << 20)  # 0.0.12: a full snapshot of 10x the old enemy bound fits.
        with patch('coop_transport.threading.Thread.start'):
            channel = Channel(None)
        # The backlog rule with the old 1 MiB messages and 16 MiB backlog (keeps the test small).
        with patch.object(coop_transport, 'MAX_MESSAGE', 1 << 20), patch.object(coop_transport, 'MAX_BACKLOG', 16 << 20):
            message = dict(data='x' * ((1 << 20) - 128))
            for _ in range(16):
                channel.send(message)
            queued = channel.queued_bytes
            with self.assertRaisesRegex(TimeoutError, '16 MiB'):
                channel.send(message)
        self.assertEqual(channel.outgoing.qsize(), 16)
        self.assertEqual(channel.queued_bytes, queued)

    def test_tls_pairing_and_state_exchange(self):
        with tempfile.TemporaryDirectory() as folder, socket.create_server(('127.0.0.1', 0)) as listener:
            invite = create_pairing(folder)
            result = []
            thread = threading.Thread(target=lambda: result.append(accept(listener, folder, invite, 'test-build')))
            thread.start()
            guest = connect('127.0.0.1', listener.getsockname()[1], invite, 'test-build')
            thread.join(5)
            self.assertEqual(len(result), 1)
            host = result[0]
            try:
                a, b = OnlineBridge(io.StringIO(), 1, host), OnlineBridge(io.StringIO(), 2, guest)
                a.xp_pending, a.gold_pending = 25, 12
                a.send_state()
                deadline = time.monotonic() + 3
                while guest.incoming.empty() and time.monotonic() < deadline:
                    time.sleep(.01)
                for message in guest.drain():
                    b.receive_state(message)
                self.assertEqual((b.xp_pending, b.gold_pending), (25, 12))
                self.assertEqual((a.xp_pending, a.gold_pending), (0, 0))
                b.damage_pending[123] = 14
                b.send_state()
                deadline = time.monotonic() + 3
                while host.incoming.empty() and time.monotonic() < deadline:
                    time.sleep(.01)
                for message in host.drain():
                    a.receive_state(message)
                self.assertEqual(a.damage_pending, {123: 14})
                a.damage_done[123] = 14
                a.send_state()
                deadline = time.monotonic() + 3
                while guest.incoming.empty() and time.monotonic() < deadline:
                    time.sleep(.01)
                for message in guest.drain():
                    b.receive_state(message)
                self.assertEqual(b.damage_pending, {})
                payload = 'x' * 400000
                for i in range(8):
                    host.send(dict(kind='burst', index=i, data=payload))
                    guest.send(dict(kind='burst', index=i, data=payload))
                received = [[], []]
                deadline = time.monotonic() + 5
                while min(map(len, received)) < 8 and time.monotonic() < deadline:
                    for j, channel in enumerate((host, guest)):
                        received[j].extend(channel.drain())
                    time.sleep(.01)
                for messages in received:
                    self.assertEqual([m['index'] for m in messages], list(range(8)))
                    self.assertTrue(all(m['data'] == payload for m in messages))
                for i in range(64):
                    host.send(dict(kind='loading', index=i))
                deadline = time.monotonic() + 3
                while not guest.incoming.full() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(guest.incoming.full())
                # A loading native client must apply backpressure, not disconnect.
                messages = []
                while len(messages) < 64 and time.monotonic() < deadline:
                    messages.extend(guest.drain())
                    time.sleep(.01)
                self.assertEqual([m['index'] for m in messages], list(range(64)))
                deadline = time.monotonic() + 3
                while host.queued_bytes and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertEqual(host.queued_bytes, 0)
                host.finish()
                self.assertTrue(guest.peer_goodbye.wait(3))
                host.close()
                guest.finish()  # A late local shutdown must not write to the closed peer.
            finally:
                guest.close()
                host.close()

    def test_bad_token_and_pin_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            invite = create_pairing(folder)
            for key in ('token', 'fingerprint'):
                with socket.create_server(('127.0.0.1', 0)) as listener:
                    errors = []
                    def serve():
                        try:
                            accept(listener, folder, invite, 'test-build')
                        except Exception as error:
                            errors.append(type(error))
                    thread = threading.Thread(target=serve)
                    thread.start()
                    with self.assertRaises((ValueError, ConnectionError)):
                        connect('127.0.0.1', listener.getsockname()[1], dict(invite, **{key: '0' * 64}), 'test-build')
                    thread.join(5)
                    self.assertTrue(errors)

    def test_frame_limits_and_nonfinite_values(self):
        with self.assertRaises(ValueError):
            encode({'damage': float('nan')})
        a, b = socket.socketpair()
        with a, b:
            a.sendall(b'\x7f\xff\xff\xff')
            with self.assertRaises(ValueError):
                receive(b)


if __name__ == '__main__':
    unittest.main()
