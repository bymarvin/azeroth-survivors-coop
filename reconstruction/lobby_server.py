"""Bounded room directory API; loopback by default, TLS required for remote use."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
from urllib.parse import urlsplit

from lobby import Rooms
from crash_reports import CrashReports, MAX_REPORT


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass  # Never log invitations or membership credentials.

    def reply(self, status, value):
        body = json.dumps(value, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.rooms.expire()
        if self.path == '/rooms':
            self.reply(200, dict(rooms=self.server.rooms.listing()))
        else:
            self.reply(404, dict(error='Unknown endpoint'))

    def do_POST(self):
        try:
            origin = self.headers.get('Origin')
            if origin and urlsplit(origin).netloc != self.headers.get('Host'):
                raise ValueError('Cross-origin requests are unavailable')
            if self.headers.get_content_type() != 'application/json' or self.headers.get('Transfer-Encoding'):
                raise ValueError('Use a bounded JSON request')
            length = int(self.headers.get('Content-Length', '0'))
            crash = self.path in ('/crash-report', '/completed-report')
            metadata = self.server.reports.authorize(self.headers.get('Authorization', '')) if crash else None
            if not 1 <= length <= (MAX_REPORT if crash else 8192):
                raise ValueError('Request exceeds size limit')
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError('Incomplete request')
            request = json.loads(body)
            if not isinstance(request, dict):
                raise ValueError('Expected a JSON object')
            rooms = self.server.rooms
            rooms.expire()
            if crash:
                result = self.server.reports.collect(metadata, request, completed=self.path == '/completed-report')
            elif self.path == '/create':
                result = rooms.create(request['name'], request['player'], request['private'], request['build'], request.get('region'), request.get('version'))
            elif self.path == '/join':
                result = rooms.join(request['room'], request['player'], request['build'], request.get('invite'))
            elif self.path in ('/poll', '/action', '/connection', '/chat'):
                auth = self.headers.get('Authorization', '')
                if not auth.startswith('Bearer '):
                    raise ValueError('Membership is required')
                if self.path == '/chat':
                    result = rooms.chat(request['room'], auth[7:], request['text'])
                elif self.path == '/connection':
                    result = rooms.connection(request['room'], auth[7:], request['address'], request['port'], request['fingerprint'])
                elif self.path == '/poll':
                    result = rooms.poll(request['room'], auth[7:])
                else:
                    result = rooms.action(request['room'], auth[7:], request['action'], request['revision'], request.get('build'))
            else:
                self.reply(404, dict(error='Unknown endpoint'))
                return
            if self.path in ('/create', '/join', '/poll'):
                room = result['room'] if 'room' in result else result
                room['crash_upload_permit'] = self.server.reports.permit(room)
            self.reply(200, result)
        except (ValueError, KeyError, TypeError, TimeoutError):
            self.reply(400, dict(error='Request rejected; check room state, membership and game build'))
        except OSError:
            self.reply(503, dict(error='Report storage unavailable; keep the local report'))


def server(address, *, collected_logs='collected-logs'):
    result = ThreadingHTTPServer(address, Handler)
    result.daemon_threads = True
    result.rooms = Rooms()
    result.reports = CrashReports(collected_logs)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=47770)
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--collected-logs', default='collected-logs')
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key) or (args.bind not in ('127.0.0.1', 'localhost') and not args.cert):
        parser.error('Remote room directories require --cert and --key')
    with server((args.bind, args.port), collected_logs=args.collected_logs) as app:
        if args.cert:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(args.cert, args.key)
            app.socket = context.wrap_socket(app.socket, server_side=True)
        print('Room directory started', flush=True)
        app.serve_forever()


if __name__ == '__main__':
    main()
