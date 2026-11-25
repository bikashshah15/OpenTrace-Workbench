"""UIP-01A: baseline helpers, the 120 s phase supervisor (with an injected shorter limit, harness only), refusal rules."""
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from tests.uip import support
import baseline
import compare


class Hashing(unittest.TestCase):
    def test_git_blob_ids_match_git(self):
        self.assertEqual(baseline.git_blob_sha1(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")
        self.assertEqual(baseline.git_blob_sha1(b"hello\n"), "ce013625030ba8dba906f756967f9e9ca394464a")

    def test_canonical_json_is_sorted_compact_utf8(self):
        self.assertEqual(baseline.canonical({"b": [1, {"z": 0, "a": "é"}], "a": None}), '{"a":null,"b":[1,{"a":"é","z":0}]}')

    def test_list_files_is_sorted_and_ignores_cache_noise(self):
        with tempfile.TemporaryDirectory() as root:
            for rel in ("d/b.py", "d/a.py", "d/__pycache__/x.pyc", "d/n/c.json", "d/.DS_Store", "d/m.pyc"):
                path = os.path.join(root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                support.write(path, b"x", "wb")
            self.assertEqual(baseline.list_files(root, "d"), ["d/a.py", "d/b.py", "d/n/c.json"])

    def test_the_protected_sets_name_real_files_at_start(self):
        for rel in baseline.CLASS_P_FILES + baseline.CLASS_N_FILES + baseline.TOOL_FILES[:2]:
            self.assertTrue(os.path.isfile(os.path.join(support.ROOT, rel)), rel)
        self.assertEqual(baseline.PHASE_TIMEOUT_SECONDS, 120)

    def test_the_phase_limit_has_no_flag_or_environment_override(self):
        help_text = subprocess.run([sys.executable, os.path.join(support.TOOLS, "baseline.py"), "generate", "--help"], capture_output=True, text=True).stdout
        self.assertNotIn("timeout", help_text.lower())
        self.assertNotIn("limit", help_text.lower())
        source = support.read(os.path.join(support.TOOLS, "baseline.py"), "r")
        self.assertNotIn("os.environ.get(\"UIP_PHASE", source)
        self.assertIn("PHASE_TIMEOUT_SECONDS = 120", source)


class Supervisor(unittest.TestCase):
    def test_a_fast_phase_passes_and_reports_its_name_and_limit(self):
        res = baseline.run_supervised([sys.executable, "-c", "print('ok')"], name="fast")
        self.assertEqual((res["phase"], res["returncode"], res["timed_out"], res["group_gone"], res["limit_seconds"]), ("fast", 0, False, True, 120))
        self.assertIn("ok", res["output"])

    def test_a_slow_phase_that_spawns_a_child_is_killed_with_its_whole_group_and_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "child.pid")
            code = ("import os,subprocess,sys,time\n"
                    "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(600)'])\n"
                    "open(%r,'w').write(str(c.pid))\n"
                    "time.sleep(600)\n") % pidfile
            started = time.monotonic()
            res = baseline.run_supervised([sys.executable, "-c", code], name="slow-with-child", timeout=2)  # injected shorter limit: harness only
            self.assertLess(time.monotonic() - started, 30)
            self.assertTrue(res["timed_out"])
            self.assertTrue(res["group_gone"])
            self.assertEqual(res["phase"], "slow-with-child")
            child = int(support.read(pidfile, "r"))
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)

    def test_report_phase_turns_a_timeout_into_a_failure_naming_the_phase(self):
        res = {"phase": "slow", "elapsed_seconds": 2.0, "limit_seconds": 2, "returncode": -9, "timed_out": True, "group_gone": True, "output": ""}
        import io
        err = io.StringIO()
        old = sys.stderr
        sys.stderr = err
        try:
            code = baseline.report_phase(res)
        finally:
            sys.stderr = old
        self.assertEqual(code, 124)
        self.assertIn("slow", err.getvalue())

    def test_a_failing_phase_is_a_failure(self):
        res = baseline.run_supervised([sys.executable, "-c", "import sys;sys.exit(3)"], name="bad")
        self.assertEqual(baseline.report_phase(res), 3)


class Refusal(unittest.TestCase):
    def test_the_generator_will_not_overwrite_an_existing_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "m.json")
            support.write(target, "{}")
            before = support.read(target)
            proc = subprocess.run([sys.executable, os.path.join(support.TOOLS, "baseline.py"), "generate", "--start-sha", support.START_SHA, "--out", target],
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("refusing to overwrite", proc.stderr)
            self.assertEqual(support.read(target), before)

    def test_compare_has_no_update_accept_or_force_mode(self):
        for flag in ("--update", "--accept", "--force", "--bless"):
            proc = subprocess.run([sys.executable, os.path.join(support.TOOLS, "compare.py"), "--manifest", "x.json", flag], capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 2, flag)
            self.assertIn("unrecognized arguments", proc.stderr)
        text = support.read(os.path.join(support.TOOLS, "compare.py"), "r")
        for word in ("--update", "--accept", "--force"):
            self.assertNotIn('add_argument("%s"' % word, text)

    def test_compare_fails_when_the_manifest_is_missing_or_unreadable(self):
        proc = subprocess.run([sys.executable, os.path.join(support.TOOLS, "compare.py"), "--manifest", "/nonexistent/manifest.json"], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 2)
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.json")
            support.write(bad, "{not json")
            proc = subprocess.run([sys.executable, os.path.join(support.TOOLS, "compare.py"), "--manifest", bad], capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("FAILURE", proc.stdout)


class DiffLines(unittest.TestCase):
    def test_diff_names_path_expected_and_actual_and_reports_reordering(self):
        self.assertEqual(list(compare.diff({"a": {"b": 1}}, {"a": {"b": 2}})), ["DIFF $.a.b: expected 1 actual 2"])
        self.assertEqual(list(compare.diff({"x": [1, 2, 3]}, {"x": [3, 2, 1]})), ["DIFF $.x: reordered (same 3 elements, different order)"])
        self.assertIn("missing from the current output", list(compare.diff({"k": 1}, {}))[0])
        self.assertIn("not in the baseline", list(compare.diff({}, {"k": 1}))[0])
        self.assertEqual(list(compare.diff({"x": [1]}, {"x": [1, 2]}))[0], "DIFF $.x: length expected 1 actual 2")
        self.assertEqual(list(compare.diff({"a": 1}, {"a": True}))[0].split(":")[0], "DIFF $.a")  # a bool is not the int 1

    def test_a_guard_violation_during_collection_is_a_failure_not_a_pass(self):
        import socket
        import netguard
        original = baseline.collect

        def collect_that_connects(root, tmp):
            try:
                socket.create_connection(("203.0.113.1", 9), timeout=1)
            except OSError:
                pass
            return original.__globals__["collect_static"](root)

        with tempfile.TemporaryDirectory() as tmp:
            manifest = os.path.join(tmp, "m.json")
            support.write(manifest, json.dumps({"schema": baseline.SCHEMA}))
            args = type("A", (), {"manifest": manifest, "tmp": tmp})()
            baseline.collect = collect_that_connects
            try:
                self.assertEqual(compare.worker(args), compare.EXIT_FAILURE)
            finally:
                baseline.collect = original
                netguard.uninstall()


if __name__ == "__main__":
    unittest.main()
