"""ECMA-431 HTTP binding client (POST /nlip, application/json) using urllib.

Refuses non-loopback endpoints; urllib proxies are disabled so a loopback request
never leaves the host even when proxy variables are set. Redirects are refused (never
followed), so a 3xx response cannot steer a request to another host; the 3xx status is
returned to the caller like any other non-200 response.

I2-REQ-01 (I1-IR-05): every exchange has ONE monotonic whole-exchange limit that bounds
connecting, sending, the status line and headers, and the body together. Per-operation
socket timeouts alone do not bound a slow-drip peer, so a watchdog also force-closes the
connection when the limit is reached. Every path (success, HTTP error, reset, timeout,
oversize body) closes the connection and stops the watchdog.
"""
import http.client
import ipaddress
import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

NLIP_PATH = "/nlip"

TRANSPORT_GRACE_S = 2.0       # slack after the task deadline for B's own failed result
TRANSPORT_MIN_S = 1.0
TRANSPORT_MAX_S = 930.0       # MAX_TASK_DEADLINE_S (900) + 30
CONTROL_TIMEOUT_S = 5.0       # capability/control exchanges carry no task deadline
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class SpecialistUnavailable(Exception):
    """Connection refused, reset or otherwise unreachable (not a deadline expiry)."""


class SpecialistTimeout(Exception):
    """The whole-exchange limit was reached before a complete response arrived."""


class ResponseTooLarge(Exception):
    """The response body exceeded MAX_RESPONSE_BYTES; it is never parsed."""


def task_timeout(deadline, now):
    """Whole-exchange limit for a task: (deadline - now) + grace, clamped (I2-REQ-01 item 1)."""
    remaining = (deadline - now).total_seconds()
    return max(TRANSPORT_MIN_S, min(TRANSPORT_MAX_S, remaining + TRANSPORT_GRACE_S))


def _loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: returning None makes urllib surface the 3xx as HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Response:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def json(self):
        return json.loads(self.body.decode("utf-8"))


class ExchangeDeadline:
    """One monotonic limit shared by every phase of an exchange."""

    def __init__(self, limit_s, clock=time.monotonic):
        self._clock = clock
        self.limit_s = limit_s
        self._end = clock() + limit_s
        self.expired = False

    def remaining(self):
        return self._end - self._clock()

    def check(self):
        if self.remaining() <= 0:
            self.expired = True
            raise SpecialistTimeout("exchange limit of %.2fs reached" % self.limit_s)


class _Exchange:
    """Per-call state: the deadline, the tracked sockets and the watchdog."""

    def __init__(self, deadline):
        self.deadline = deadline
        self.sockets = []
        self._lock = threading.Lock()
        self._timer = None
        self.closed = False

    def arm(self):
        self._timer = threading.Timer(max(self.deadline.remaining(), 0.0), self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self):
        self.deadline.expired = True
        self.close_sockets()

    def track(self, sock):
        with self._lock:
            if self.closed:
                _kill(sock)
                raise SpecialistTimeout("exchange closed")
            self.sockets.append(sock)

    def close_sockets(self):
        with self._lock:
            self.closed = True
            socks, self.sockets = self.sockets, []
        for sock in socks:
            _kill(sock)

    def finish(self):
        if self._timer is not None:
            self._timer.cancel()
            self._timer.join(timeout=1.0)
        self.close_sockets()


def _kill(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def default_connector(address, timeout):
    # Looked up at call time so tests (and the redirect test) can intercept it.
    return socket.create_connection(address, timeout=timeout)


class _BoundedConnection(http.client.HTTPConnection):
    """HTTPConnection whose connect step honours the exchange deadline.

    The connector runs in a helper thread that is joined with the remaining time, so a
    connector that ignores its timeout cannot hold the exchange past its limit. The helper
    closes any socket it eventually obtains after being abandoned.
    """

    def __init__(self, *args, exchange=None, connector=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._exchange = exchange
        self._connector = connector or default_connector

    def connect(self):
        ex = self._exchange
        ex.deadline.check()
        box = {}
        abandoned = threading.Event()

        def work():
            try:
                sock = self._connector((self.host, self.port), max(ex.deadline.remaining(), 0.05))
            except BaseException as err:  # noqa: BLE001 - reported to the caller
                box["err"] = err
                return
            if abandoned.is_set():
                _kill(sock)
                return
            box["sock"] = sock

        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        thread.join(max(ex.deadline.remaining(), 0.0))
        if thread.is_alive():
            abandoned.set()
            ex.deadline.expired = True
            raise SpecialistTimeout("connect did not finish within the exchange limit")
        if "err" in box:
            raise box["err"]
        sock = box["sock"]
        ex.track(sock)
        self.sock = sock
        self.sock.settimeout(max(ex.deadline.remaining(), 0.05))


class _TrackedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, transport):
        super().__init__()
        self._transport = transport

    def http_open(self, req):
        ex = self._transport._current

        def factory(host, **kwargs):
            return _BoundedConnection(host, exchange=ex, connector=self._transport.connector, **kwargs)

        return self.do_open(factory, req)


class HttpTransport:
    def __init__(self, base_url, timeout=5.0, connector=None):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != "http" or not _loopback(parsed.hostname or ""):
            raise ValueError("I1 transport is loopback-only (PD-03)")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.connector = connector
        self._current = None
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RefuseRedirects(),
                                                   _TrackedHTTPHandler(self))

    def post_raw(self, body, content_type="application/json", timeout=None):
        limit = self.timeout if timeout is None else timeout
        exchange = _Exchange(ExchangeDeadline(limit))
        self._current = exchange
        req = urllib.request.Request(self.base_url + NLIP_PATH, data=body, method="POST",
                                     headers={"Content-Type": content_type})
        exchange.arm()
        try:
            try:
                with self._opener.open(req, timeout=limit) as resp:
                    return Response(resp.status, dict(resp.headers), self._read(resp, exchange))
            except urllib.error.HTTPError as err:
                try:
                    return Response(err.code, dict(err.headers), self._read(err, exchange))
                finally:
                    err.close()
        except (SpecialistTimeout, ResponseTooLarge):
            raise
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError,
                http.client.HTTPException, ValueError) as err:
            if exchange.deadline.expired or exchange.deadline.remaining() <= 0:
                raise SpecialistTimeout(type(err).__name__)
            raise SpecialistUnavailable(type(err).__name__)
        finally:
            exchange.finish()
            self._current = None

    @staticmethod
    def _read(resp, exchange):
        data = resp.read(MAX_RESPONSE_BYTES + 1)
        exchange.deadline.check()
        if len(data) > MAX_RESPONSE_BYTES:
            raise ResponseTooLarge("response exceeded %d bytes" % MAX_RESPONSE_BYTES)
        return data

    def post(self, message, timeout=None):
        return self.post_raw(json.dumps(message).encode("utf-8"), timeout=timeout)
