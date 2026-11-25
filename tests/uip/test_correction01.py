"""UIP-01A correction 01 regression tests (findings UIP-01A-IR-01, IR-02, IR-03). Deterministic; temp directories only.

IR-01  the comparator enforces its exclusion policy itself; a submitted manifest cannot redefine the oracle.
IR-02  process-group cleanup distinguishes "gone" from "could not tell".
IR-03  a recorded network violation can never disappear because its log could not be written.
"""
import copy
import errno
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests.uip import support
import baseline
import compare
import netguard

V1 = os.path.join(support.ROOT, "evidence", "uip", "baseline", "opentrace-uip-baseline-v1.json")
V2 = os.path.join(support.ROOT, "evidence", "uip", "baseline", "opentrace-uip-baseline-v2.json")


def load_v1():
    return json.loads(support.read(V1, "r"))


# -- IR-01 ------------------------------------------------------------------------------------------------------------------------------
class ExclusionPolicy(unittest.TestCase):
    PROTECTED = ("class_p", "class_n", "semantic", "golden_exports", "produced_legacy_exports", "served", "tools", "limits", "reference",
                 "schema", "start_sha", "excluded_from_comparison")

    def test_the_legitimate_v1_manifest_is_valid(self):
        self.assertEqual(compare.validate_manifest(load_v1()), [])

    def test_the_trusted_policy_permits_only_environment_and_commands(self):
        self.assertEqual(set(compare.PERMITTED_EXCLUSIONS), {"environment", "commands"})

    def test_a_submitted_exclusion_of_any_protected_section_is_rejected(self):
        for section in self.PROTECTED + ("made_up",):
            with self.subTest(section=section):
                m = load_v1()
                m["excluded_from_comparison"][section] = "unauthorized exclusion"
                problems = compare.validate_manifest(m)
                self.assertTrue(problems, "exclusion of %s was accepted" % section)
                self.assertTrue(any(section in p for p in problems), problems)

    def test_exclusion_values_must_be_reasons_and_the_container_a_mapping(self):
        for bad in (["environment"], "environment", None, {"environment": 1}, {"environment": ""}):
            with self.subTest(bad=bad):
                m = load_v1()
                m["excluded_from_comparison"] = bad
                self.assertTrue(compare.validate_manifest(m))

    def test_compare_manifest_ignores_the_submitted_exclusions_for_protected_sections(self):
        """The direct-function probe from the review: a protected-file change and a changed verdict, hidden by exclusions."""
        manifest = load_v1()
        manifest["excluded_from_comparison"].update({"class_p": "x", "semantic": "x"})
        current = copy.deepcopy(load_v1())
        link = "src/core/opentrace_core/bombridge/links.py"
        current["class_p"]["files"][link]["sha256"] = "0" * 64
        current["semantic"]["discovery"]["candidates"][0]["finding"]["state"] = "supported"
        lines = compare.compare_manifest(manifest, current)
        self.assertTrue(any("class_p.files." + link in l for l in lines), lines)
        self.assertTrue(any("semantic.discovery.candidates[0].finding.state" in l for l in lines), lines)

    def test_only_environment_and_commands_are_informational(self):
        manifest, current = load_v1(), load_v1()
        current["environment"]["python"] = "0.0.0"
        current["commands"] = {"generator": "other"}
        self.assertEqual(compare.compare_manifest(manifest, current), [])
        current["start_sha"] = "0" * 40  # a later checkout is legitimate; the tool policy (not the manifest) says so
        self.assertEqual(compare.compare_manifest(manifest, current), [])
        current["tools"]["tools/uip/compare.py"] = "0" * 64
        self.assertTrue(compare.compare_manifest(manifest, current))

    def test_ordered_candidate_lists_are_still_compared_in_order(self):
        manifest, current = load_v1(), load_v1()
        current["semantic"]["discovery"]["candidates"].reverse()
        lines = compare.compare_manifest(manifest, current)
        self.assertTrue(any("semantic.discovery.candidates" in l and "reordered" in l for l in lines), lines)

    def test_malformed_manifests_are_reported_not_crashed_on(self):
        cases = {"list": [], "string": "x", "null": None, "number": 3}
        for name, value in cases.items():
            with self.subTest(name=name):
                self.assertTrue(compare.validate_manifest(value))
        for section in ("class_p", "class_n", "semantic", "tools", "served", "golden_exports", "produced_legacy_exports", "limits", "reference",
                        "start_sha", "schema", "excluded_from_comparison"):
            with self.subTest(missing=section):
                m = load_v1()
                del m[section]
                self.assertTrue(any(section in p for p in compare.validate_manifest(m)))
        for section, wrong in (("class_p", []), ("class_n", "x"), ("semantic", None), ("tools", 3), ("served", []), ("golden_exports", []),
                               ("produced_legacy_exports", {}), ("limits", []), ("reference", "x"), ("start_sha", 3)):
            with self.subTest(wrong_type=section):
                m = load_v1()
                m[section] = wrong
                self.assertTrue(any(section in p for p in compare.validate_manifest(m)))
        m = load_v1()
        m["semantic"]["discovery"]["candidates"] = {}
        self.assertTrue(compare.validate_manifest(m))
        m = load_v1()
        m["class_p"]["files"] = []
        self.assertTrue(compare.validate_manifest(m))

    def test_unsupported_schema_and_unknown_sections_are_rejected(self):
        m = load_v1()
        m["schema"] = "opentrace.uip.baseline/2"
        self.assertTrue(any("schema" in p for p in compare.validate_manifest(m)))
        m = load_v1()
        m["extra_section"] = {}
        self.assertTrue(any("extra_section" in p for p in compare.validate_manifest(m)))

    def run_cli(self, manifest_text):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "m.json")
            support.write(path, manifest_text)
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            return subprocess.run([sys.executable, os.path.join(support.TOOLS, "compare.py"), "--manifest", path],
                                  capture_output=True, text=True, timeout=120, env=env, cwd=support.ROOT)

    def test_cli_rejects_malformed_manifests_clearly_with_the_failure_exit_status(self):
        good = load_v1()
        bad_exclusion = copy.deepcopy(good)
        bad_exclusion["excluded_from_comparison"]["class_p"] = "unauthorized exclusion"
        missing = copy.deepcopy(good)
        del missing["semantic"]
        for name, text in (("not an object", "[]"), ("exclusion of class_p", json.dumps(bad_exclusion)), ("missing semantic", json.dumps(missing))):
            with self.subTest(name=name):
                proc = self.run_cli(text)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertIn("FAILURE: manifest", proc.stdout)
                self.assertNotIn("Traceback", proc.stdout + proc.stderr)
                self.assertNotIn("0 difference(s)", proc.stdout)


# -- IR-02 ------------------------------------------------------------------------------------------------------------------------------
HEADER = "  PID  PPID  PGID STAT COMMAND\n"


def ps_result(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(["ps"], returncode, stdout, stderr)


class ProcessInspection(unittest.TestCase):
    """``killpg`` is injected to answer EPERM (the macOS zombie-only condition); ``ps`` outcomes are injected. ``wait=0``: one pass only."""

    def gone(self, ps=None, killpg=PermissionError, wait=0):
        side = killpg if killpg is not None else None
        with mock.patch.object(baseline.os, "killpg", side_effect=side), mock.patch.object(baseline.subprocess, "run", **ps):
            return baseline._group_gone(123, wait=wait)

    def test_valid_zombie_only_inspection_is_gone(self):
        self.assertTrue(self.gone({"return_value": ps_result(HEADER + "  123     1   123 Z+   (python)\n  124   123   123 Z    <defunct>\n")}))

    def test_a_valid_listing_with_no_members_is_gone(self):
        self.assertTrue(self.gone({"return_value": ps_result(HEADER + "  900     1   900 S    other\n")}))

    def test_live_members_are_not_gone(self):
        self.assertFalse(self.gone({"return_value": ps_result(HEADER + "  123     1   123 S    python\n  124   123   123 Z    <defunct>\n")}))

    def test_a_live_member_of_another_group_does_not_count(self):
        self.assertTrue(self.gone({"return_value": ps_result(HEADER + "  900     1   900 S    other\n  123     1   123 Z    x\n")}))

    def test_failed_ps_is_unknown_not_success(self):
        for returncode in (1, 2, 127):
            with self.subTest(returncode=returncode):
                self.assertFalse(self.gone({"return_value": ps_result("", returncode, "ps: permission denied")}))
                self.assertFalse(self.gone({"return_value": ps_result(HEADER, returncode, "ps: error")}))

    def test_empty_output_with_status_zero_is_unknown(self):
        self.assertFalse(self.gone({"return_value": ps_result("", 0)}))

    def test_unavailable_or_timed_out_ps_is_unknown(self):
        for exc in (FileNotFoundError("ps"), PermissionError("ps"), OSError(errno.EMFILE, "x"), subprocess.TimeoutExpired("ps", 10),
                    UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")):
            with self.subTest(exc=type(exc).__name__):
                self.assertFalse(self.gone({"side_effect": exc}))

    def test_malformed_matching_rows_are_unknown(self):
        for row in ("  123     1   123\n", "  123     1   123 \n", "  123     1   123 ?? x\n", "  abc   def   123 Z x\n", "  123     1   123 9 x\n"):
            with self.subTest(row=row):
                self.assertFalse(self.gone({"return_value": ps_result(HEADER + row)}))

    def test_a_listing_without_the_expected_header_is_unknown(self):
        self.assertFalse(self.gone({"return_value": ps_result("  123     1   123 Z    x\n")}))
        self.assertFalse(self.gone({"return_value": ps_result("garbage\n  123 1 123 Z x\n")}))

    def test_permission_error_itself_is_never_taken_as_zombie_only(self):
        self.assertFalse(self.gone({"side_effect": OSError("ps cannot run")}))

    def test_a_missing_group_is_gone_without_asking_ps(self):
        with mock.patch.object(baseline.os, "killpg", side_effect=ProcessLookupError), mock.patch.object(baseline.subprocess, "run", side_effect=AssertionError("ps must not be needed")):
            self.assertTrue(baseline._group_gone(123, wait=0))

    def test_a_group_that_still_answers_is_not_gone(self):
        with mock.patch.object(baseline.os, "killpg", return_value=None), mock.patch.object(baseline.subprocess, "run", side_effect=AssertionError("not consulted")):
            self.assertFalse(baseline._group_gone(123, wait=0))

    def test_other_oserrors_from_killpg_are_unknown(self):
        self.assertFalse(self.gone({"return_value": ps_result(HEADER)}, killpg=OSError(errno.EIO, "io")))

    def test_live_members_helper_answers_none_when_it_cannot_tell(self):
        with mock.patch.object(baseline.subprocess, "run", return_value=ps_result("", 1, "denied")):
            self.assertIsNone(baseline._live_members(123))
        with mock.patch.object(baseline.subprocess, "run", return_value=ps_result(HEADER + "  123 1 123 Z x\n")):
            self.assertEqual(baseline._live_members(123), [])
        with mock.patch.object(baseline.subprocess, "run", return_value=ps_result(HEADER + "  123 1 123 S x\n")):
            self.assertEqual(len(baseline._live_members(123)), 1)

    def test_an_uncertain_inspection_after_a_real_phase_is_reported_as_not_gone(self):
        with mock.patch.object(baseline, "_group_gone", return_value=False), mock.patch.object(baseline.subprocess, "run", return_value=ps_result("", 1, "denied")):
            res = baseline.run_supervised([sys.executable, "-c", "print(1)"], name="uncertain")
        self.assertFalse(res["group_gone"])
        self.assertNotEqual(baseline.report_phase(res), 0)


# -- IR-03 ------------------------------------------------------------------------------------------------------------------------------
class EnvironmentRestoring(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        self.addCleanup(self._restore)
        self.addCleanup(netguard.uninstall)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)


class GuardLogFailure(EnvironmentRestoring):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp(prefix="uip-ir03-")
        self.log = os.path.join(self.tmp, "netguard.log")

    def denied_and_caught(self):
        sock = netguard.socket.socket(netguard.socket.AF_INET, netguard.socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect(("203.0.113.1", 9))
        except OSError:
            pass  # trusted collection code that swallows the exception
        finally:
            sock.close()

    def test_a_log_that_cannot_be_opened_makes_guard_installation_fail_loudly(self):
        real_open = os.open

        def refuse(path, *a, **kw):
            if str(path).endswith("netguard.log"):
                raise PermissionError(errno.EACCES, "denied", path)
            return real_open(path, *a, **kw)

        with mock.patch.object(netguard.os, "open", side_effect=refuse):
            with self.assertRaises(netguard.NetGuardInstallError):
                netguard.install(allowed_ports=(), unix_root=self.tmp, log_path=self.log)
        self.assertFalse(netguard.STATE.installed)

    def test_a_log_path_in_a_missing_directory_makes_installation_fail(self):
        with self.assertRaises(netguard.NetGuardInstallError):
            netguard.install(allowed_ports=(), unix_root=self.tmp, log_path=os.path.join(self.tmp, "no", "such", "netguard.log"))

    def test_a_denial_whose_log_write_fails_is_still_reported(self):
        netguard.install(allowed_ports=(), unix_root=self.tmp, log_path=self.log)
        with mock.patch.object(netguard.os, "write", side_effect=OSError(errno.EIO, "disk")):
            self.denied_and_caught()
        found = netguard.collect_violations(self.log)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "connect")
        self.assertTrue(netguard.STATE.log_failed)

    def test_a_missing_log_is_an_error_not_an_empty_log(self):
        netguard.install(allowed_ports=(), unix_root=self.tmp, log_path=self.log)
        os.remove(self.log)
        with self.assertRaises(netguard.NetGuardLogError):
            netguard.collect_violations(self.log)

    def test_a_clean_run_reports_nothing_and_a_logged_denial_is_counted_once(self):
        netguard.install(allowed_ports=(), unix_root=self.tmp, log_path=self.log)
        self.assertEqual(netguard.collect_violations(self.log), [])
        self.denied_and_caught()
        self.assertEqual(len(netguard.collect_violations(self.log)), 1)

    def test_a_corrupt_log_is_an_error(self):
        netguard.install(allowed_ports=(), unix_root=self.tmp, log_path=self.log)
        support.write(self.log, "{not json\n", "a")
        with self.assertRaises(netguard.NetGuardLogError):
            netguard.collect_violations(self.log)


class WorkerFailurePaths(EnvironmentRestoring):
    """The comparator and generator phases must fail when collection catches the denial, whichever way the log fails."""

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp(prefix="uip-ir03-w-")
        self.original = baseline.collect
        self.addCleanup(setattr, baseline, "collect", self.original)

    def catching_collect(self, fail_write=False):
        import contextlib

        def collect(root, tmp):
            ctx = mock.patch.object(netguard.os, "write", side_effect=OSError(errno.EIO, "disk")) if fail_write else contextlib.nullcontext()
            with ctx:
                try:
                    netguard.socket.create_connection(("203.0.113.1", 9), timeout=1)
                except OSError:
                    pass
            return self.original.__globals__["collect_static"](root)
        return collect

    def compare_args(self):
        manifest = os.path.join(self.tmp, "m.json")
        support.write(manifest, json.dumps(load_v1()))
        return type("A", (), {"manifest": manifest, "tmp": self.tmp})()

    def generate_args(self):
        return type("A", (), {"tmp": self.tmp, "start_sha": support.START_SHA, "sandbox": "", "result": os.path.join(self.tmp, "result.json")})()

    def test_comparator_fails_when_the_caught_denial_could_not_be_logged(self):
        baseline.collect = self.catching_collect(fail_write=True)
        self.assertEqual(compare.worker(self.compare_args()), compare.EXIT_FAILURE)

    def test_comparator_fails_when_the_log_cannot_even_be_opened(self):
        real_open = os.open

        def refuse(path, *a, **kw):
            if str(path).endswith("netguard.log"):
                raise PermissionError(errno.EACCES, "denied", path)
            return real_open(path, *a, **kw)

        baseline.collect = self.catching_collect()
        with mock.patch.object(netguard.os, "open", side_effect=refuse):
            self.assertEqual(compare.worker(self.compare_args()), compare.EXIT_FAILURE)

    def test_comparator_fails_when_the_log_is_deleted_during_collection(self):
        def collect(root, tmp):
            os.remove(os.path.join(tmp, "netguard.log"))
            return self.original.__globals__["collect_static"](root)
        baseline.collect = collect
        self.assertEqual(compare.worker(self.compare_args()), compare.EXIT_FAILURE)

    def test_generator_fails_and_writes_no_manifest_when_the_caught_denial_could_not_be_logged(self):
        baseline.collect = self.catching_collect(fail_write=True)
        args = self.generate_args()
        self.assertNotEqual(baseline.worker_generate(args), 0)
        self.assertFalse(os.path.exists(args.result))

    def test_generator_fails_when_the_log_cannot_be_opened(self):
        real_open = os.open

        def refuse(path, *a, **kw):
            if str(path).endswith("netguard.log"):
                raise PermissionError(errno.EACCES, "denied", path)
            return real_open(path, *a, **kw)

        baseline.collect = self.catching_collect()
        args = self.generate_args()
        with mock.patch.object(netguard.os, "open", side_effect=refuse):
            self.assertNotEqual(baseline.worker_generate(args), 0)
        self.assertFalse(os.path.exists(args.result))


def _caught_denial_with_failing_log(conn):
    """Child: the log write fails, the trusted code swallows the denial, and would otherwise report success."""
    import errno as _errno

    def broken_write(*a, **kw):
        raise OSError(_errno.EIO, "disk")
    netguard.os.write = broken_write
    blocked = netguard.child_probe()
    conn.send(blocked)
    conn.close()


def _touch_when_run(path):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("ran")


class SpawnedChildLogFailure(EnvironmentRestoring):
    def spawn(self, target, args):
        ctx = multiprocessing.get_context("spawn")
        proc = ctx.Process(target=target, args=args)
        proc.start()
        proc.join(60)
        if proc.is_alive():
            proc.kill()
            proc.join()
            self.fail("child did not finish")
        return proc

    def test_a_caught_denial_with_a_failing_log_cannot_end_in_a_clean_child(self):
        tmp = tempfile.mkdtemp(prefix="uip-ir03-c-")
        log = os.path.join(tmp, "violations.log")
        netguard.prepare_child_environment(os.path.join(tmp, "guard"), log, unix_root=tmp)
        ctx = multiprocessing.get_context("spawn")
        parent, child = ctx.Pipe(duplex=False)
        proc = ctx.Process(target=_caught_denial_with_failing_log, args=(child,))
        proc.start()
        child.close()
        proc.join(60)
        self.assertFalse(proc.is_alive())
        self.assertNotEqual(proc.exitcode, 0, "the child finished cleanly although its violation could not be recorded")
        with self.assertRaises(EOFError, msg="the child went on to report a normal result"):
            parent.recv()  # only end-of-file: the child died before it could answer

    def test_a_child_whose_guard_cannot_install_dies_before_running_any_code(self):
        tmp = tempfile.mkdtemp(prefix="uip-ir03-i-")
        marker = os.path.join(tmp, "ran")
        netguard.prepare_child_environment(os.path.join(tmp, "guard"), os.path.join(tmp, "no", "such", "dir", "violations.log"), unix_root=tmp)
        proc = self.spawn(_touch_when_run, (marker,))
        self.assertNotEqual(proc.exitcode, 0)
        self.assertFalse(os.path.exists(marker), "the child ran trusted code without a guard")

    def test_a_missing_guard_module_is_fatal_in_the_child(self):
        tmp = tempfile.mkdtemp(prefix="uip-ir03-m-")
        marker = os.path.join(tmp, "ran")
        log = os.path.join(tmp, "violations.log")
        guard_dir = os.path.join(tmp, "guard")
        netguard.prepare_child_environment(guard_dir, log, unix_root=tmp)
        os.remove(os.path.join(guard_dir, "uip_netguard.py"))
        proc = self.spawn(_touch_when_run, (marker,))
        self.assertNotEqual(proc.exitcode, 0)
        self.assertFalse(os.path.exists(marker))

    def test_a_denial_in_a_child_is_still_recorded_and_fails_the_parent_check(self):
        tmp = tempfile.mkdtemp(prefix="uip-ir03-p-")
        log = os.path.join(tmp, "violations.log")
        netguard.install(allowed_ports=(), unix_root=tmp, log_path=log)
        netguard.prepare_child_environment(os.path.join(tmp, "guard"), log, unix_root=tmp)
        ctx = multiprocessing.get_context("spawn")
        parent, child = ctx.Pipe(duplex=False)
        proc = ctx.Process(target=_probe_and_report, args=(child,))
        proc.start()
        child.close()
        self.assertTrue(parent.poll(60))
        self.assertTrue(parent.recv())
        proc.join(30)
        self.assertEqual(len(netguard.collect_violations(log)), 1)


def _probe_and_report(conn):
    conn.send(netguard.child_probe())
    conn.close()


if __name__ == "__main__":
    unittest.main()


# -- IR-03 remainder (correction 02): a known violation stays fatal whatever the log later contains -----------------------------------
class KnownViolationSurvivesLogClearing(EnvironmentRestoring):
    """Correction 02 (UIP-01A-IR-03 remainder): a denial that was logged and caught, then had the log emptied, must still fail."""

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp(prefix="uip-ir03c-")
        self.log = os.path.join(self.tmp, "netguard.log")
        self.original = baseline.collect
        self.addCleanup(setattr, baseline, "collect", self.original)
        self.matching = json.loads(support.read(V2, "r"))  # collection data that matches the v2 manifest exactly

    def denied_and_caught(self):
        try:
            netguard.socket.create_connection(("203.0.113.1", 9), timeout=1)
        except OSError:
            pass

    def emptying_collect(self):
        def collect(root, tmp):
            self.denied_and_caught()
            with open(os.path.join(tmp, "netguard.log"), "w"):  # truncate: the log is empty, the data unchanged
                pass
            return copy.deepcopy(self.matching)
        return collect

    def test_direct_collection_keeps_known_events_after_the_log_is_cleared(self):
        netguard.install(allowed_ports=(), unix_root=self.tmp, log_path=self.log)
        self.denied_and_caught()
        with open(self.log, "w"):
            pass
        found = netguard.collect_violations(self.log)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "create_connection")

    def test_normal_logged_events_are_not_double_counted(self):
        netguard.install(allowed_ports=(), unix_root=self.tmp, log_path=self.log)
        self.denied_and_caught()
        self.denied_and_caught()
        self.assertEqual(len(netguard.collect_violations(self.log)), 2)

    def test_a_partly_cleared_log_counts_each_event_once(self):
        netguard.install(allowed_ports=(), unix_root=self.tmp, log_path=self.log)
        self.denied_and_caught()
        with open(self.log, "rb") as handle:
            first = handle.read()
        self.denied_and_caught()
        with open(self.log, "wb") as handle:  # only the first event survives
            handle.write(first)
        self.assertEqual(len(netguard.collect_violations(self.log)), 2)

    def test_a_clean_empty_log_still_passes(self):
        netguard.install(allowed_ports=(), unix_root=self.tmp, log_path=self.log)
        self.assertEqual(os.path.getsize(self.log), 0)
        self.assertEqual(netguard.collect_violations(self.log), [])

    def test_a_logged_child_entry_is_kept_alongside_parent_memory(self):
        netguard.install(allowed_ports=(), unix_root=self.tmp, log_path=self.log)
        self.denied_and_caught()
        child = {"kind": "connect", "target": "('203.0.113.2', 9)", "pid": os.getpid() + 1}
        support.write(self.log, json.dumps(child) + "\n", "a")
        self.assertEqual(len(netguard.collect_violations(self.log)), 2)

    def test_comparator_fails_when_a_caught_denial_is_followed_by_an_emptied_log(self):
        baseline.collect = self.emptying_collect()
        manifest = os.path.join(self.tmp, "m.json")
        support.write(manifest, json.dumps(self.matching))
        args = type("A", (), {"manifest": manifest, "tmp": self.tmp})()
        self.assertEqual(compare.worker(args), compare.EXIT_FAILURE)

    def test_the_matching_data_alone_passes_so_the_failure_above_is_the_violation(self):
        baseline.collect = lambda root, tmp: copy.deepcopy(self.matching)
        manifest = os.path.join(self.tmp, "m.json")
        support.write(manifest, json.dumps(self.matching))
        args = type("A", (), {"manifest": manifest, "tmp": self.tmp})()
        self.assertEqual(compare.worker(args), compare.EXIT_PASS)

    def test_generator_fails_and_writes_no_manifest_when_the_log_is_emptied_after_a_caught_denial(self):
        baseline.collect = self.emptying_collect()
        args = type("A", (), {"tmp": self.tmp, "start_sha": support.START_SHA, "sandbox": "", "result": os.path.join(self.tmp, "result.json")})()
        self.assertNotEqual(baseline.worker_generate(args), 0)
        self.assertFalse(os.path.exists(args.result))
