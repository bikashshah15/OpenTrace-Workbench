"""UIP-01A: the network guard in the parent process and inside a spawned child (positive control)."""
import multiprocessing
import os
import socket
import tempfile
import unittest

from tests.uip import support  # noqa: F401  (puts tools/uip on sys.path)
import netguard


class ParentGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="uip-ng-")
        self.log = os.path.join(self.tmp, "violations.log")
        netguard.install(allowed_ports=(), unix_root=self.tmp, log_path=self.log)

    def tearDown(self):
        netguard.uninstall()

    def test_a_denied_connection_raises_and_is_recorded(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        with self.assertRaises(netguard.NetGuardViolation):
            sock.connect(("203.0.113.1", 9))
        sock.close()
        self.assertEqual([v["kind"] for v in netguard.read_log(self.log)], ["connect"])

    def test_connect_ex_create_connection_sendto_and_name_resolution_are_denied(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with self.assertRaises(netguard.NetGuardViolation):
            sock.connect_ex(("203.0.113.1", 9))
        with self.assertRaises(netguard.NetGuardViolation):
            sock.sendto(b"x", ("203.0.113.1", 9))
        sock.close()
        with self.assertRaises(netguard.NetGuardViolation):
            socket.create_connection(("203.0.113.1", 9), timeout=1)
        for call in (lambda: socket.getaddrinfo("example.invalid", 80), lambda: socket.gethostbyname("example.invalid"),
                     lambda: socket.gethostbyname_ex("example.invalid"), lambda: socket.gethostbyaddr("203.0.113.1")):
            with self.assertRaises(netguard.NetGuardViolation):
                call()
        self.assertEqual(len(netguard.read_log(self.log)), 7)

    def test_loopback_to_the_single_registered_port_is_permitted_and_another_port_is_not(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        other = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        other.bind(("127.0.0.1", 0))
        other.listen(1)
        other_port = other.getsockname()[1]
        netguard.allow_port(port)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2)
        client.connect(("127.0.0.1", port))  # permitted
        client.close()
        denied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self.assertRaises(netguard.NetGuardViolation):
            denied.connect(("127.0.0.1", other_port))
        denied.close()
        server.close()
        other.close()
        self.assertEqual(len(netguard.read_log(self.log)), 1)

    def test_numeric_loopback_resolution_is_allowed_but_a_loopback_name_is_not(self):
        socket.getaddrinfo("127.0.0.1", 80)  # numeric loopback: no violation
        with self.assertRaises(netguard.NetGuardViolation):
            socket.getaddrinfo("localhost", 80)

    def test_unix_sockets_only_under_the_tool_directory(self):
        inside = os.path.join(self.tmp, "u.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(inside)
        server.listen(1)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(inside)  # permitted
        client.close()
        server.close()
        outside = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        with self.assertRaises(netguard.NetGuardViolation):
            outside.connect("/var/run/syslog")
        outside.close()

    def test_socketpair_and_binding_are_not_connections(self):
        a, b = socket.socketpair()
        a.sendall(b"ok")
        self.assertEqual(b.recv(2), b"ok")
        a.close()
        b.close()
        self.assertEqual(netguard.read_log(self.log), [])


class SpawnedChildGuard(unittest.TestCase):
    """The adapter runs the engine in a ``spawn`` child, which inherits no Python patches: the prepared sitecustomize must install the guard."""

    def test_a_denied_connection_inside_a_spawned_child_is_blocked_and_recorded(self):
        tmp = tempfile.mkdtemp(prefix="uip-ng-child-")
        log = os.path.join(tmp, "violations.log")
        saved = {k: os.environ.get(k) for k in ("PYTHONPATH", netguard.LOG_ENV, netguard.PORTS_ENV, netguard.UNIX_ENV)}
        try:
            netguard.prepare_child_environment(os.path.join(tmp, "guard"), log, unix_root=tmp)
            ctx = multiprocessing.get_context("spawn")
            parent, child = ctx.Pipe(duplex=False)
            proc = ctx.Process(target=_probe_and_report, args=(child,))
            proc.start()
            child.close()
            self.assertTrue(parent.poll(60), "child did not answer")
            blocked = parent.recv()
            proc.join(30)
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertTrue(blocked, "the child's denied connection was not blocked")
        recorded = netguard.read_log(log)
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0]["kind"], "connect")
        self.assertNotEqual(recorded[0]["pid"], os.getpid())


def _probe_and_report(conn):
    conn.send(netguard.child_probe())
    conn.close()


if __name__ == "__main__":
    unittest.main()
