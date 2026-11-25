"""UIP-01A network guard: a Python-level safety net for running TRUSTED OpenTrace code against recorded fixtures.

Not a security boundary and never a reason to run untrusted code (contract UIP-01A section 4f). It makes an accidental
network attempt fail loudly and leaves a record:

* allowed: numeric ``127.0.0.1`` / ``::1`` connections to ports the tool itself registered, and ``AF_UNIX`` paths under one directory;
* every other ``connect``, ``connect_ex``, ``sendto``, ``create_connection`` or name resolution raises ``NetGuardViolation`` and is
  appended to the violation log (the run must then fail).

A violation can never vanish because the log failed (correction 01, finding UIP-01A-IR-03): the log is opened when the guard is
installed (a log that cannot be opened makes installation fail loudly); a denial whose log write fails is kept in memory and reported by
``collect_violations``; in a spawned child, where the parent cannot see memory, a failed log write or a failed guard installation ends
the process at once (exit status ``EXIT_LOG_FAILURE`` / ``EXIT_INSTALL_FAILURE``) so the parent's phase fails. ``collect_violations``
treats a missing or corrupt log as an error, never as an empty log. The guard remains a safety net for trusted code, not a security boundary.

``socketpair`` and binding a listening socket are not connections and are not affected.

Spawned children (the adapter runs the engine in a ``spawn`` process) do not inherit Python patches, so ``prepare_child_environment``
writes a copy of this module plus a ``sitecustomize.py`` into a temp directory and prepends it to ``PYTHONPATH``; the child installs the
same guard (with no allowed ports) at interpreter start and appends to the same log.
"""
import json
import os
import socket
import sys

LOG_ENV = "UIP_NETGUARD_LOG"
PORTS_ENV = "UIP_NETGUARD_PORTS"
UNIX_ENV = "UIP_NETGUARD_UNIX"
_LOOPBACK = {"127.0.0.1", "::1"}
EXIT_LOG_FAILURE = 86      # a spawned child could not record a denied connection
EXIT_INSTALL_FAILURE = 87  # a spawned child could not install the guard


class NetGuardViolation(OSError):
    """Raised for any network operation the guard does not allow."""


class NetGuardInstallError(RuntimeError):
    """The guard could not be installed (for example its log cannot be opened). Fatal: no run may continue unguarded."""


class NetGuardLogError(RuntimeError):
    """The violation log is missing, unreadable or corrupt, so the absence of violations cannot be established."""


class _State:
    installed = False
    ports = set()
    unix_root = None
    log_path = None
    log_fd = None
    log_failed = False
    is_child = False
    originals = {}
    violations = []
    unlogged = []


STATE = _State()


def _record(kind, target):
    entry = {"kind": kind, "target": str(target), "pid": os.getpid()}
    STATE.violations.append(entry)
    if STATE.log_path:
        written = False
        try:
            payload = (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8")
            written = STATE.log_fd is not None and os.write(STATE.log_fd, payload) == len(payload)
        except (OSError, ValueError, TypeError):
            written = False
        if not written:
            STATE.log_failed = True
            STATE.unlogged.append(entry)
            if STATE.is_child:  # the parent cannot read this process's memory: end here so the parent's phase fails
                try:
                    sys.stderr.write("netguard: could not record a denied %s to %s; child terminated\n" % (kind, target))
                except Exception:
                    pass
                os._exit(EXIT_LOG_FAILURE)
    raise NetGuardViolation("netguard: %s to %s is not allowed" % (kind, target))


def _allowed_address(family, address):
    if family == socket.AF_UNIX:
        if STATE.unix_root is None or not isinstance(address, (str, bytes, os.PathLike)):
            return False
        path = os.path.abspath(os.fsdecode(address))
        root = os.path.abspath(STATE.unix_root)
        return path == root or path.startswith(root + os.sep)
    if family in (socket.AF_INET, socket.AF_INET6):
        if not isinstance(address, tuple) or len(address) < 2:
            return False
        host, port = address[0], address[1]
        return host in _LOOPBACK and port in STATE.ports
    return False


def _guard_connect(kind, original):
    def wrapper(self, address, *rest):
        if not _allowed_address(self.family, address):
            _record(kind, address)
        return original(self, address, *rest)
    return wrapper


def _guard_sendto(original):
    def wrapper(self, data, *args):
        address = args[-1] if args else None
        if not _allowed_address(self.family, address):
            _record("sendto", address)
        return original(self, data, *args)
    return wrapper


def _guard_resolution(kind, original):
    def wrapper(host, *args, **kwargs):
        if host is not None and host != "" and host not in _LOOPBACK:
            _record(kind, host)
        return original(host, *args, **kwargs)
    return wrapper


def _guard_create_connection(original):
    def wrapper(address, *args, **kwargs):
        host, port = address[0], address[1]
        if host not in _LOOPBACK or port not in STATE.ports:
            _record("create_connection", address)
        return original(address, *args, **kwargs)
    return wrapper


def install(allowed_ports=(), unix_root=None, log_path=None):
    """Install the guard in this process. Idempotent: a second call only updates the allowed set.
    Raises ``NetGuardInstallError`` (and installs nothing) when the log cannot be opened."""
    fd = None
    if log_path:
        try:
            fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        except OSError as exc:
            raise NetGuardInstallError("netguard: cannot open the violation log %s: %s" % (log_path, type(exc).__name__)) from exc
    if STATE.log_fd is not None and STATE.log_fd != fd:
        try:
            os.close(STATE.log_fd)
        except OSError:
            pass
    STATE.log_fd = fd
    STATE.ports = set(allowed_ports)
    STATE.unix_root = unix_root
    STATE.log_path = log_path
    if STATE.installed:
        return STATE
    o = STATE.originals
    o["connect"], o["connect_ex"], o["sendto"] = socket.socket.connect, socket.socket.connect_ex, socket.socket.sendto
    o["create_connection"], o["getaddrinfo"] = socket.create_connection, socket.getaddrinfo
    o["gethostbyname"], o["gethostbyname_ex"], o["gethostbyaddr"] = socket.gethostbyname, socket.gethostbyname_ex, socket.gethostbyaddr
    socket.socket.connect = _guard_connect("connect", o["connect"])
    socket.socket.connect_ex = _guard_connect("connect_ex", o["connect_ex"])
    socket.socket.sendto = _guard_sendto(o["sendto"])
    socket.create_connection = _guard_create_connection(o["create_connection"])
    socket.getaddrinfo = _guard_resolution("getaddrinfo", o["getaddrinfo"])
    socket.gethostbyname = _guard_resolution("gethostbyname", o["gethostbyname"])
    socket.gethostbyname_ex = _guard_resolution("gethostbyname_ex", o["gethostbyname_ex"])
    socket.gethostbyaddr = _guard_resolution("gethostbyaddr", o["gethostbyaddr"])
    STATE.installed = True
    return STATE


def allow_port(port):
    """Register the single loopback port the tool itself opened."""
    STATE.ports.add(int(port))


def uninstall():
    """Restore the original socket functions (tests only)."""
    if not STATE.installed:
        if STATE.log_fd is not None:  # an install that failed part-way, or a log opened by a later call
            try:
                os.close(STATE.log_fd)
            except OSError:
                pass
            STATE.log_fd = None
        return
    o = STATE.originals
    socket.socket.connect, socket.socket.connect_ex, socket.socket.sendto = o["connect"], o["connect_ex"], o["sendto"]
    socket.create_connection, socket.getaddrinfo = o["create_connection"], o["getaddrinfo"]
    socket.gethostbyname, socket.gethostbyname_ex, socket.gethostbyaddr = o["gethostbyname"], o["gethostbyname_ex"], o["gethostbyaddr"]
    STATE.installed = False
    STATE.ports = set()
    STATE.violations = []
    STATE.unlogged = []
    STATE.log_failed = False
    STATE.is_child = False
    STATE.log_path = None
    if STATE.log_fd is not None:
        try:
            os.close(STATE.log_fd)
        except OSError:
            pass
        STATE.log_fd = None


def collect_violations(path):
    """Every violation this run must fail on: the entries in the log (this process and any spawned child) plus every violation this
    process itself recorded in memory that the log does not account for (a failed write, or a log emptied or truncated afterwards).
    A known violation is never dropped because of what the log later contains; an ordinary logged event is counted once (each in-memory
    entry cancels one equal log entry). A missing, unreadable or corrupt log raises ``NetGuardLogError`` (never an empty result)."""
    entries = []
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    if not isinstance(entry, dict) or "kind" not in entry:
                        raise ValueError("line %d is not a violation record" % number)
                    entries.append(entry)
        except (OSError, ValueError) as exc:
            raise NetGuardLogError("netguard: violation log %s cannot be read (%s); a clean run cannot be established" % (path, type(exc).__name__)) from exc
    unaccounted = list(entries)
    for known in STATE.violations:
        if known in unaccounted:
            unaccounted.remove(known)  # already in the log: counted once
        else:
            entries.append(known)      # not in the log (unwritten, truncated or removed): still fatal
    return entries


def read_log(path):
    """Lenient diagnostic read of ``path`` (empty list when absent). Phases use ``collect_violations`` instead."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def install_from_environment():
    """Child side: install from the environment prepared by ``prepare_child_environment`` (no ports unless listed)."""
    log_path = os.environ.get(LOG_ENV)
    if not log_path:
        return None
    ports = [int(p) for p in os.environ.get(PORTS_ENV, "").split(",") if p]
    state = install(allowed_ports=ports, unix_root=os.environ.get(UNIX_ENV) or None, log_path=log_path)
    state.is_child = True
    return state


_SITECUSTOMIZE = (
    "# written by tools/uip/netguard.py for a spawned child; installs the same network guard at interpreter start\n"
    "# Python continues after an exception in sitecustomize, so a failure here ends the process instead (never an unguarded child)\n"
    "try:\n"
    "    import uip_netguard\n"
    "    uip_netguard.install_from_environment()\n"
    "except BaseException as exc:\n"
    "    import os, sys\n"
    "    try:\n"
    "        sys.stderr.write('uip netguard failed to install: %r\\n' % (exc,))\n"
    "    except Exception:\n"
    "        pass\n"
    "    os._exit(87)\n"
)


def prepare_child_environment(directory, log_path, unix_root=None):
    """Prepare ``directory`` (the tool's temp dir) so spawned Python children install the guard; update ``os.environ`` in place."""
    os.makedirs(directory, exist_ok=True)
    with open(os.path.abspath(__file__), "rb") as src, open(os.path.join(directory, "uip_netguard.py"), "wb") as dst:
        dst.write(src.read())
    with open(os.path.join(directory, "sitecustomize.py"), "w", encoding="utf-8") as handle:
        handle.write(_SITECUSTOMIZE)
    existing = os.environ.get("PYTHONPATH", "")
    os.environ["PYTHONPATH"] = directory + (os.pathsep + existing if existing else "")
    os.environ[LOG_ENV] = log_path
    os.environ[PORTS_ENV] = ""
    os.environ[UNIX_ENV] = unix_root or ""


def child_probe():
    """Run inside a spawned child: attempt a connection the guard must deny. Returns True when it was blocked."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect(("203.0.113.1", 9))  # TEST-NET-3; never routable
        finally:
            sock.close()
    except OSError as exc:  # the child guard is a second copy of this module: match by name, not by class identity
        return type(exc).__name__ == "NetGuardViolation"
    return False
