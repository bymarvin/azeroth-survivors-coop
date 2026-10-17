"""Bidirectional RTT over real TLS without consuming application messages."""
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from coop_transport import Channel, MAX_MESSAGE, accept, connect, create_pairing, encode, receive
from coop_transport import frame_payload, read_exact


def receive_frame(sock):
    """A gameplay frame as Channel writes it (protocol 2 may compress it)."""
    import struct
    size = struct.unpack('!I', read_exact(sock, 4))[0]
    return frame_payload(read_exact(sock, size))


class LatencyTests(unittest.TestCase):
    def test_old_peer_and_invalid_probe_replies_preserve_payloads(self):
        # Socket pair isolates envelope compatibility from the real TLS check below.
        class Socket:
            def __init__(self, sock): self.sock = sock
            def __getattr__(self, key): return getattr(self.sock, key)
            def pending(self): return 0
        left, right = socket.socketpair()
        channel = Channel(Socket(left))
        right.settimeout(3)
        try:
            channel.send(dict(kind='prepare'))
            envelope = receive_frame(right)
            self.assertEqual(envelope['payload'], dict(kind='prepare'))
            probe = envelope['ping']
            for seq, pong in enumerate((None, True, -1, probe + 1)):
                # Older peers omit metadata; malformed/mismatched replies do not create samples.
                right.sendall(encode(dict(seq=seq, payload=dict(kind='start'), pong=pong)))
            deadline = time.monotonic() + 2
            while channel.incoming.qsize() < 4 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(channel.drain(), [dict(kind='start')] * 4)
            self.assertIsNone(channel.latency_ms())
            right.sendall(encode(dict(seq=4, payload=None, pong=probe)))
            deadline = time.monotonic() + 2
            while channel.latency_ms() is None and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertIsNotNone(channel.latency_ms())
            sample = channel.latency_sample
            right.sendall(encode(dict(seq=5, payload=dict(kind='check'), pong=probe)))
            deadline = time.monotonic() + 2
            while channel.incoming.empty() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(channel.drain(), [dict(kind='check')])
            self.assertEqual(channel.latency_sample, sample)
            channel.send(dict(data='x' * (MAX_MESSAGE - 100)))
            large = receive_frame(right)
            while large['payload'] is None:
                large = receive_frame(right)
            self.assertEqual(len(large['payload']['data']), MAX_MESSAGE - 100)
        finally:
            channel.close(); right.close()

    def test_both_peers_probe_without_polling_application_queues(self):
        with tempfile.TemporaryDirectory() as folder, socket.create_server(('127.0.0.1', 0)) as listener:
            invite = create_pairing(folder)
            accepted = []
            worker = threading.Thread(target=lambda: accepted.append(accept(listener, folder, invite, 'test')))
            worker.start()
            guest = connect('127.0.0.1', listener.getsockname()[1], invite, 'test')
            worker.join(5)
            host = accepted[0]
            try:
                deadline = time.monotonic() + 5
                while (host.latency_ms() is None or guest.latency_ms() is None) and time.monotonic() < deadline:
                    time.sleep(.02)
                for channel in (host, guest):
                    self.assertIsNotNone(channel.latency_ms())
                    self.assertLess(channel.latency_ms(), 1000)
                    self.assertEqual(channel.drain(), [])
                    channel.send(dict(kind='prepare', run=1))
                deadline = time.monotonic() + 3
                while (host.incoming.empty() or guest.incoming.empty()) and time.monotonic() < deadline:
                    time.sleep(.02)
                for channel in (host, guest):
                    self.assertEqual(channel.drain(), [dict(kind='prepare', run=1)])
                host.finish()
                self.assertTrue(guest.peer_goodbye.wait(3))
            finally:
                host.close(); guest.close()

    def test_stale_closed_and_failed_samples_are_unavailable(self):
        with patch('coop_transport.threading.Thread.start'):
            channel = Channel(None)
        self.assertIsNone(channel.latency_ms())
        channel.latency_sample = (.042, time.monotonic())
        self.assertEqual(channel.latency_ms(), 42)
        channel.latency_sample = (.042, time.monotonic() - 11)
        self.assertIsNone(channel.latency_ms())
        channel.latency_sample = (.042, time.monotonic())
        channel.error = TimeoutError()
        self.assertIsNone(channel.latency_ms())
        channel.error = None
        channel.closed = True
        self.assertIsNone(channel.latency_ms())


if __name__ == '__main__':
    unittest.main()
