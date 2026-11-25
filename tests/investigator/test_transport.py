"""C2: redirects are refused, so a 3xx can never steer a request off loopback."""
import http.server
import json
import socket
import threading
import unittest
from unittest import mock

from opentrace_investigator import transport
from opentrace_investigator.transport import HttpTransport


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.server.hits.append(self.path)
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if self.server.location:
            self.send_response(self.server.code)
            self.send_header("Location", self.server.location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({"Format": "text", "Subformat": "english", "Content": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(testcase, location=None, code=307):
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    server.hits, server.location, server.code = [], location, code
    threading.Thread(target=server.serve_forever, daemon=True).start()
    testcase.addCleanup(server.server_close)
    testcase.addCleanup(server.shutdown)
    return server


class RedirectRefusalTest(unittest.TestCase):
    def test_non_loopback_redirect_destination_is_never_contacted(self):
        server = _serve(self, location="http://203.0.113.7:8080/nlip")  # TEST-NET-3, non-loopback
        contacted = []
        real = socket.create_connection

        def recording(address, *args, **kwargs):
            contacted.append(address[0])
            if address[0] != "127.0.0.1":
                raise AssertionError("non-loopback connection attempted: %s" % (address,))
            return real(address, *args, **kwargs)

        with mock.patch.object(socket, "create_connection", recording):
            for code in (301, 302, 303, 307, 308):
                server.code = code
                resp = HttpTransport("http://127.0.0.1:%d" % server.server_port).post({"Format": "text",
                                                                                     "Subformat": "english",
                                                                                     "Content": "hi"})
                self.assertEqual(resp.status, code)
        self.assertEqual(set(contacted), {"127.0.0.1"})
        self.assertEqual(len(server.hits), 5)

    def test_loopback_redirect_is_not_followed_either(self):
        canary = _serve(self)
        server = _serve(self, location="http://127.0.0.1:%d/nlip" % canary.server_port)
        resp = HttpTransport("http://127.0.0.1:%d" % server.server_port).post_raw(b"{}")
        self.assertEqual(resp.status, 307)
        self.assertEqual(canary.hits, [])

    def test_opener_has_refusing_redirect_handler(self):
        t = HttpTransport("http://127.0.0.1:9")
        handlers = [type(h) for h in t._opener.handlers]
        self.assertIn(transport._RefuseRedirects, handlers)
        self.assertEqual([h for h in handlers if issubclass(h, transport.urllib.request.HTTPRedirectHandler)],
                         [transport._RefuseRedirects])


if __name__ == "__main__":
    unittest.main()
