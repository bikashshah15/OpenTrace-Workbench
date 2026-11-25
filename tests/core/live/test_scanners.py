import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

from opentrace_core.live import isolation, scanners
from opentrace_core.live.source import SourceRecord
from tests.core.live import support

SHA = "c" * 40


class Cfg(scanners.ScannerConfig):
    def __init__(self, **kw):
        super().__init__(pins={"syft": "9.9.9", "cdxgen": "9.9.9"}, scan_seconds=kw.pop("seconds", 20), **kw)


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-scan-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        os.makedirs(os.path.join(self.dir, "ws", "src"))
        self.ws = os.path.join(self.dir, "ws")
        self.src = SourceRecord("https://github.com/o/r", SHA, "d" * 40, True, 3, 30, "e" * 64)
        self.iso = support.PassThrough()

    def spec(self, kind, tool_path, version="9.9.9"):
        base = scanners.SYFT if kind == "sbom" else scanners.CDXGEN
        spec = dict(base)
        spec["resolve"] = lambda config, p=tool_path, v=version: (
            ([p, "scan", "dir:.", "-o", "cyclonedx-json={out}"] if kind == "sbom" else [p, "-o", "{out}"]), [p], [self.dir], v) if p else None
        return spec

    def run_one(self, kind, tool, *, version="9.9.9", cancel=None, seconds=20, iso=None):
        return scanners.run_scanner(self.spec(kind, tool, version), Cfg(seconds=seconds), iso or self.iso, self.src, self.ws,
                                    cancel=cancel or threading.Event())

    def test_success_records_version_scope_outcome_and_original_digest(self):
        doc = support.cyclonedx([support.library("a"), support.library("b")], spec="1.7")
        run = self.run_one("sbom", support.fake_tool(self.dir, "syft", output=doc))
        self.assertEqual((run.outcome, run.reason, run.exit_code), ("acquired", None, 0))
        self.assertEqual((run.version, run.pinned_version, run.spec_version), ("9.9.9", "9.9.9", "1.7"))
        self.assertEqual(run.data, doc)
        import hashlib
        self.assertEqual(run.sha256, hashlib.sha256(doc).hexdigest())
        self.assertEqual((run.record_count, run.record_count_unit), (2, "components"))
        self.assertEqual(run.scope["revision"], SHA)
        self.assertEqual(run.scope["file_count"], 3)
        self.assertEqual(run.isolation, "test-passthrough")
        self.assertTrue(run.duration_ms >= 0)
        self.assertEqual(os.listdir(self.ws), ["src"], "per-run scratch directories are removed")

    def test_successful_empty_cbom_is_a_completed_scan_not_a_failure(self):
        doc = support.cyclonedx([support.library("only-a-library")], spec="1.6")
        run = self.run_one("cbom", support.fake_tool(self.dir, "cdxgen", output=doc))
        self.assertEqual(run.outcome, "acquired")
        self.assertEqual((run.record_count, run.record_count_unit), (0, "crypto_assets"))
        self.assertEqual(run.record_counts["components"], 1)
        self.assertIn("not a failed scan", run.meaning)
        self.assertIsNotNone(run.data)
        self.assertIsNone(run.reason)

    def test_cbom_with_assets_counts_only_cryptographic_assets(self):
        run = self.run_one("cbom", support.fake_tool(self.dir, "cdxgen", output=support.cyclonedx([support.library("x"), support.crypto_asset(), support.crypto_asset("AES")])))
        self.assertEqual((run.outcome, run.record_count), ("acquired", 2))
        self.assertEqual(run.meaning, "")

    def test_nonzero_exit_fails_even_when_a_document_was_written(self):
        doc = support.cyclonedx([support.library("a")], spec="1.6")
        run = self.run_one("cbom", support.fake_tool(self.dir, "cdxgen", output=doc, exit_code=3, stdout="boom: dependency extractor failed"))
        self.assertEqual((run.outcome, run.reason, run.exit_code), ("failed", "nonzero_exit", 3))
        self.assertIsNone(run.data)
        self.assertIsNone(run.sha256)
        self.assertIsNotNone(run.rejected_sha256, "the rejected bytes are digested, never offered")
        self.assertIn("boom: dependency extractor failed", run.warnings)
        self.assertNotIn("data", run.as_dict())

    def test_failure_modes_are_distinct_from_empty(self):
        cases = [("no_output", dict(output=None)),
                 ("output_not_json", dict(output=b"not json")),
                 ("output_not_cyclonedx", dict(output=b'{"bomFormat":"SPDX"}')),
                 ("output_components_invalid", dict(output=json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [1]}).encode())),
                 ("unsupported_spec_version", dict(output=support.cyclonedx([], spec="1.7")))]
        for reason, kw in cases:
            with self.subTest(reason):
                run = self.run_one("cbom", support.fake_tool(self.dir, "cdxgen", **kw))
                self.assertEqual((run.outcome, run.reason), ("failed", reason))
                self.assertIsNone(run.data)

    def test_unavailable_is_not_failed(self):
        self.assertEqual(self.run_one("sbom", None).reason, "tool_not_found")
        self.assertEqual(self.run_one("sbom", None).outcome, "unavailable")
        wrong = self.run_one("sbom", support.fake_tool(self.dir, "syft", output=support.cyclonedx()), version="1.0.0")
        self.assertEqual((wrong.outcome, wrong.reason, wrong.exit_code), ("unavailable", "version_mismatch", None))
        self.assertIn("pinned version 9.9.9", wrong.warnings[0])
        blocked = self.run_one("sbom", support.fake_tool(self.dir, "syft2", output=support.cyclonedx()), iso=support.PassThrough(False))
        self.assertEqual((blocked.outcome, blocked.reason), ("unavailable", "isolation_unavailable"))
        self.assertEqual(isolation.NoIsolation().available()[0], False)

    def test_timeout_kills_the_scanner_and_is_a_failure(self):
        started = time.monotonic()
        run = self.run_one("sbom", support.fake_tool(self.dir, "syft", output=support.cyclonedx(), sleep=30), seconds=1)
        self.assertEqual((run.outcome, run.reason), ("failed", "timeout"))
        self.assertLess(time.monotonic() - started, 10)
        self.assertIsNone(run.data)

    def test_cancellation_stops_the_scanner(self):
        cancel = threading.Event()
        threading.Timer(0.5, cancel.set).start()
        run = self.run_one("sbom", support.fake_tool(self.dir, "syft", output=support.cyclonedx(), sleep=30), cancel=cancel)
        self.assertEqual((run.outcome, run.reason), ("cancelled", "cancelled"))

    def test_processes_are_registered_with_the_session(self):
        seen = []
        scanners.run_scanner(self.spec("sbom", support.fake_tool(self.dir, "syft", output=support.cyclonedx())), Cfg(), self.iso,
                             self.src, self.ws, cancel=threading.Event(), register=seen.append)
        self.assertEqual(len(seen), 1)
        self.assertIsNotNone(seen[0].process.poll())

    def test_the_command_runs_with_a_scrubbed_environment_and_named_paths_only(self):
        run = self.run_one("sbom", support.fake_tool(self.dir, "syft", output=support.cyclonedx()))
        argv, kw = self.iso.wrapped[0]
        self.assertEqual(kw["exec_paths"], [argv[0]])
        self.assertTrue(all(p.startswith(self.ws) for p in kw["write_paths"]))
        env = scanners._scrubbed_env("/h", "/t")
        self.assertEqual(env["PATH"], "/var/empty")
        self.assertFalse(set(env) & {"AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "SSH_AUTH_SOCK"})


class VersionProbeTest(unittest.TestCase):
    def test_cdxgen_version_comes_from_the_installed_package_not_the_repository(self):
        d = tempfile.mkdtemp(prefix="ot-cdx-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        pkg = os.path.join(d, "node_modules", "@cyclonedx", "cdxgen")
        os.makedirs(pkg)
        with open(os.path.join(pkg, "package.json"), "w") as handle:
            json.dump({"name": "@cyclonedx/cdxgen", "version": "12.9.0"}, handle)
        self.assertEqual(scanners._version_cdxgen(d), "12.9.0")
        with open(os.path.join(pkg, "package.json"), "w") as handle:
            json.dump({"name": "not-cdxgen", "version": "12.9.0"}, handle)
        self.assertIsNone(scanners._version_cdxgen(d))


@unittest.skipUnless(sys.platform == "darwin", "Seatbelt provider is macOS only")
class SeatbeltTest(unittest.TestCase):
    def setUp(self):
        self.iso = isolation.SeatbeltIsolation()
        self.dir = os.path.realpath(tempfile.mkdtemp(prefix="ot-sb-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.out = os.path.join(self.dir, "out")
        os.mkdir(self.out)

    def run_in(self, argv, exec_paths, read_paths=()):
        wrapped = self.iso.wrap(argv, read_paths=list(read_paths), write_paths=[self.out], exec_paths=exec_paths)
        import subprocess
        return subprocess.run(wrapped, capture_output=True, timeout=30)

    def test_self_test_proves_enforcement(self):
        self.assertEqual(self.iso.available(), (True, ""))

    def test_write_is_allowed_only_in_the_named_directory(self):
        self.assertEqual(self.run_in(["/usr/bin/touch", os.path.join(self.out, "ok")], ["/usr/bin/touch"]).returncode, 0)
        outside = os.path.join(self.dir, "outside")
        self.assertNotEqual(self.run_in(["/usr/bin/touch", outside], ["/usr/bin/touch"]).returncode, 0)
        self.assertFalse(os.path.exists(outside))

    def test_only_the_named_binary_may_be_executed(self):
        self.assertNotEqual(self.run_in(["/bin/sh", "-c", "/usr/bin/id"], ["/bin/sh"]).returncode, 0)

    def test_network_is_denied(self):
        import socket
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        port = str(listener.getsockname()[1])
        import subprocess
        self.assertEqual(subprocess.run(["/usr/bin/nc", "-z", "127.0.0.1", port], capture_output=True, timeout=20).returncode, 0, "control: reachable without the sandbox")
        self.assertNotEqual(self.run_in(["/usr/bin/nc", "-z", "127.0.0.1", port], ["/usr/bin/nc"]).returncode, 0)

    def test_the_users_home_directory_is_not_readable(self):
        home = os.path.expanduser("~")
        secret = os.path.join(home, ".opentrace-isolation-probe-%d" % os.getpid())
        with open(secret, "w") as handle:
            handle.write("secret")
        self.addCleanup(os.unlink, secret)
        self.assertNotEqual(self.run_in(["/bin/cat", secret], ["/bin/cat"]).returncode, 0)
        self.assertEqual(self.run_in(["/bin/cat", secret], ["/bin/cat"], read_paths=[secret]).returncode, 0, "named paths remain readable")
        self.assertNotEqual(self.run_in(["/bin/ls", home], ["/bin/ls"]).returncode, 0, "the home directory cannot be listed")
        # Node resolves a script path by lstat-ing every ancestor; metadata stays readable (regression: cdxgen under ~/.tools failed).
        self.assertEqual(self.run_in(["/usr/bin/stat", home], ["/usr/bin/stat"]).returncode, 0)


class NoProviderTest(unittest.TestCase):
    def test_no_isolation_never_passes_through(self):
        with self.assertRaises(isolation.IsolationUnavailable):
            isolation.NoIsolation().wrap(["/bin/true"], read_paths=[], write_paths=[], exec_paths=[])
