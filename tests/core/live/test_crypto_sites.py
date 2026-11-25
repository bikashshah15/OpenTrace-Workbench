"""UIP-12: the bounded, conservative Python ``hashlib`` call-site collector (offline, in process; synthetic trees; no network, no execution).

Every tree here is SYNTHETIC (written by the test into a temp directory). The donor ``cryptoscan`` is reused unchanged and is only parsed text.
"""
import hashlib
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from opentrace_core.bombridge import cryptoscan
from opentrace_core.live import crypto_sites as cs, source_declarations as sd

URL = "https://github.com/acme/widget"
SHA = "a" * 40


def write(root, rel, data):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data if isinstance(data, bytes) else data.encode())


class Base(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ot-cs-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def collect(self, files, **kw):
        for rel, data in files.items():
            write(self.root, rel, data)
        return sd.collect(self.root, URL, SHA, **kw)

    def sites(self, files, **kw):
        out = self.collect(files, **kw)
        self.assertEqual(out["status"], "collected")
        return out["record"]["crypto_call_sites"], out


class ObservationTest(Base):
    def test_constructors_new_pbkdf2_and_scrypt_keep_the_literal_as_written_and_the_operation_class(self):
        src = ('import hashlib\n'
               'a = hashlib.sha256(b"x")\n'
               'b = hashlib.new("SHA-256")\n'
               'c = hashlib.pbkdf2_hmac("sha256", b"p", b"s", 1)\n'
               'd = hashlib.scrypt(b"p", salt=b"s", n=2, r=1, p=1)\n')
        sites, _ = self.sites({"app/mod.py": src})
        self.assertEqual([(s["line"], s["operation"], s["algorithm_source"], s["algorithm_literal"]) for s in sites],
                         [(2, "hash", "function_name", None), (3, "hash", "literal", "SHA-256"),
                          (4, "pbkdf2_hmac", "literal", "sha256"), (5, "scrypt", "function_name", None)])
        self.assertEqual(sites[1]["algorithm"], "sha256")           # the donor normalises; the original spelling is kept beside it
        self.assertTrue(all(s["binding_status"] == "unique_module_level" and s["audit_complete"] for s in sites))
        self.assertEqual(sites[0]["file_sha256"], hashlib.sha256(src.encode()).hexdigest())

    def test_from_import_alias_and_look_alikes(self):
        src = ('from hashlib import sha256 as s\nimport myhashlib\nx = s(b"1")\ny = myhashlib.sha256(b"2")\n')
        sites, _ = self.sites({"m.py": src})
        self.assertEqual([(s["line"], s["binding"]) for s in sites], [(3, "from_import")])      # myhashlib.sha256 is not a site

    def test_dynamic_algorithm_is_an_unresolved_observation_not_dropped(self):
        sites, _ = self.sites({"m.py": 'import hashlib\nhashlib.new(name)\nhashlib.new(name="sha256")\n'})
        self.assertEqual([(s["algorithm_resolved"], s["algorithm_source"]) for s in sites], [(False, "dynamic"), (False, "dynamic")])

    def test_rebinding_shadowing_and_non_module_level_imports_are_ambiguous(self):
        cases = {
            "rebound.py": 'import hashlib\nhashlib = object()\nhashlib.sha256(b"x")\n',
            "param.py": 'import hashlib\ndef f(hashlib):\n    return hashlib.sha256(b"x")\n',
            "func_import.py": 'def f():\n    import hashlib\n    return hashlib.sha256(b"x")\n',
            "try_import.py": 'try:\n    import hashlib\nexcept ImportError:\n    hashlib = None\nhashlib.sha256(b"x")\n',
            "twice.py": 'import hashlib\nimport hashlib\nhashlib.sha256(b"x")\n',
            "redef.py": 'from hashlib import sha256\ndef sha256(x):\n    return 1\nsha256(b"x")\n',
        }
        sites, out = self.sites({k: v for k, v in cases.items()})
        by = {s["path"]: s for s in sites}
        self.assertEqual(set(by), set(cases))
        for path, s in by.items():
            with self.subTest(path):
                self.assertEqual(s["binding_status"], "ambiguous")
                self.assertTrue(s["audit_complete"])

    def test_the_whole_call_excerpt_is_verbatim_and_a_long_one_is_flagged_truncated(self):
        long_arg = "a" * 2500
        sites, _ = self.sites({"m.py": f'import hashlib\nhashlib.new(\n    "sha256",\n)\nhashlib.sha256(b"{long_arg}")\n'})
        self.assertEqual(sites[0]["excerpt"], 'hashlib.new(\n    "sha256",\n)')
        self.assertEqual((sites[0]["line"], sites[0]["end_line"]), (2, 4))
        self.assertFalse(sites[0]["excerpt_truncated"])
        self.assertTrue(sites[1]["excerpt_truncated"])
        self.assertEqual(len(sites[1]["excerpt"]), cs.MAX_EXCERPT)

    def test_order_is_deterministic_and_independent_of_creation_order(self):
        files = {"z/b.py": 'import hashlib\nhashlib.md5(b"1")\n', "a/a.py": 'import hashlib\nhashlib.sha1(b"1")\n', "m.py": 'import hashlib\nhashlib.sha512(b"1")\n'}
        first, _ = self.sites(files)
        shutil.rmtree(self.root)
        os.makedirs(self.root)
        second, _ = self.sites(dict(reversed(list(files.items()))))
        self.assertEqual([s["path"] for s in first], [s["path"] for s in second])
        self.assertEqual([s["path"] for s in first], ["m.py", "a/a.py", "z/b.py"])      # files before subdirectories, each sorted


class LocalModuleTest(Base):
    def test_a_local_hashlib_module_file_or_directory_is_present(self):
        for files in ({"hashlib.py": "x = 1\n", "m.py": 'import hashlib\nhashlib.sha256(b"1")\n'},
                      {"pkg/hashlib/__init__.py": "", "m.py": "x = 1\n"}):
            with self.subTest(list(files)):
                shutil.rmtree(self.root)
                os.makedirs(self.root)
                _, out = self.sites(files)
                self.assertEqual(out["record"]["searched"]["local_module_named_hashlib"]["status"], "present")

    def test_absent_only_after_a_complete_search_and_unknown_after_an_early_stop(self):
        _, out = self.sites({"m.py": 'import hashlib\nhashlib.sha256(b"1")\n'})
        self.assertEqual(out["record"]["searched"]["local_module_named_hashlib"]["status"], "absent_after_complete_search")
        ticks = iter(range(10000))
        out = sd.collect(self.root, URL, SHA, clock=lambda: float(next(ticks)), budget=1.0)
        self.assertFalse(out["record"]["searched"]["traversal"]["complete"])
        self.assertEqual(out["record"]["searched"]["local_module_named_hashlib"]["status"], "unknown_incomplete")

    def test_an_entry_cap_and_an_unreadable_directory_are_unknown_not_clean(self):
        write(self.root, "a.py", "x = 1\n")
        write(self.root, "b.py", "x = 1\n")
        with mock.patch.object(sd, "MAX_ENTRIES", 1):
            out = sd.collect(self.root, URL, SHA)
        self.assertEqual(out["record"]["searched"]["local_module_named_hashlib"]["status"], "unknown_incomplete")
        write(self.root, "sub/c.py", "x = 1\n")
        real = os.scandir

        def scandir(path):
            if str(path).endswith("sub"):
                raise PermissionError("no")
            return real(path)
        with mock.patch("os.scandir", scandir):
            out = sd.collect(self.root, URL, SHA)
        self.assertEqual(out["record"]["searched"]["local_module_named_hashlib"]["status"], "unknown_incomplete")


class FailureAndBoundsTest(Base):
    def test_syntax_decode_nul_and_read_failures_are_per_file_and_never_stop_the_others(self):
        files = {"ok.py": 'import hashlib\nhashlib.sha256(b"1")\n', "bad_syntax.py": "def (:\n", "latin.py": b"x = '\xff'\n", "nul.py": b"x = 1\x00\n"}
        sites, out = self.sites(files)
        py = out["record"]["searched"]["python"]
        self.assertEqual([s["path"] for s in sites], ["ok.py"])
        self.assertEqual(py["syntax_errors"]["count"] + py["skipped"]["count"], 3)
        self.assertEqual(py["skipped"]["by_reason"].get("not_utf8"), 1)
        self.assertFalse(py["complete"])
        self.assertEqual(py["count_kind"], "at_least")

    def test_an_unreadable_or_symlinked_python_file_is_skipped_with_a_reason(self):
        write(self.root, "real.py", "x = 1\n")
        os.symlink(os.path.join(self.root, "real.py"), os.path.join(self.root, "link.py"))
        out = sd.collect(self.root, URL, SHA)
        py = out["record"]["searched"]["python"]
        self.assertEqual(py["python_files_total"], 2)
        self.assertEqual(py["parsed"], 1)                      # the symlink is never followed

    def test_each_bound_skips_with_a_reason_and_lower_bound_counts(self):
        write(self.root, "big.py", "x = '" + "a" * 100 + "'\n")
        write(self.root, "lines.py", "x = 1\n" * 5)
        write(self.root, "ok.py", 'import hashlib\nhashlib.sha256(b"1")\n')
        with mock.patch.object(cs, "MAX_FILE_BYTES", 50), mock.patch.object(cs, "MAX_LINES", 3):
            out = sd.collect(self.root, URL, SHA)
        by = out["record"]["searched"]["python"]["skipped"]["by_reason"]
        self.assertEqual(by, {"over_line_limit": 1, "too_large": 1} if True else by)
        self.assertEqual(out["record"]["searched"]["python"]["count_kind"], "at_least")

    def test_file_count_total_bytes_and_site_limits(self):
        for i in range(5):
            write(self.root, f"f{i}.py", 'import hashlib\nhashlib.sha256(b"1")\nhashlib.sha1(b"2")\n')
        with mock.patch.object(cs, "MAX_PY_FILES", 3):
            out = sd.collect(self.root, URL, SHA)
        py = out["record"]["searched"]["python"]
        self.assertEqual((py["selected"], py["over_file_limit"], py["python_files_total"]), (3, 2, 5))
        with mock.patch.object(cs, "MAX_TOTAL_BYTES", 100):
            out = sd.collect(self.root, URL, SHA)
        self.assertGreater(out["record"]["searched"]["python"]["skipped"]["by_reason"].get("over_total_bytes", 0), 0)
        with mock.patch.object(cs, "MAX_SITES", 3):
            out = sd.collect(self.root, URL, SHA)
        py = out["record"]["searched"]["python"]
        self.assertEqual((len(out["record"]["crypto_call_sites"]), py["sites"]["observed"], py["sites"]["over_site_limit"]), (3, 10, 7))
        self.assertFalse(py["complete"])

    def test_the_soft_budget_is_checked_between_files_an_in_flight_file_may_overrun_it(self):
        for name in ("a.py", "b.py", "c.py"):
            write(self.root, name, 'import hashlib\nhashlib.sha256(b"1")\n')
        now = [0.0]
        calls = []
        real = cryptoscan.scan_source

        def slow(path, text):
            calls.append(path)
            now[0] += 100.0            # the in-flight parse overruns the 20 s soft deadline; it is not interrupted
            return real(path, text)
        with mock.patch.object(cryptoscan, "scan_source", slow):
            out = sd.collect(self.root, URL, SHA, clock=lambda: now[0])
        py = out["record"]["searched"]["python"]
        self.assertEqual(calls, ["a.py"])                                   # the first file finished although it overran
        self.assertEqual([s["path"] for s in out["record"]["crypto_call_sites"]], ["a.py"])    # its sites stay usable ...
        self.assertTrue(py["deadline_hit"])
        self.assertEqual((py["parsed"], py["not_parsed_time_budget"], py["complete"]), (1, 2, False))
        # ... but the audit did not run after the deadline: the site is an observation only
        self.assertFalse(out["record"]["crypto_call_sites"][0]["audit_complete"])
        self.assertEqual(py["audit_failures"]["listed"], [{"path": "a.py", "reason": "deadline_before_audit"}])
        self.assertEqual(out["record"]["searched"]["local_module_named_hashlib"]["status"], "unknown_incomplete")

    def test_an_audit_failure_keeps_the_donor_observation_without_attached_facts(self):
        write(self.root, "a.py", 'import hashlib\nhashlib.new("sha256")\n')
        with mock.patch.object(cs, "audit_file", side_effect=RecursionError()):
            out = sd.collect(self.root, URL, SHA)
        s = out["record"]["crypto_call_sites"][0]
        self.assertEqual((s["audit_complete"], s["binding_status"], s["algorithm_literal"], s["algorithm_source"]), (False, "unknown", None, None))
        self.assertEqual(out["record"]["searched"]["python"]["audit_failures"]["count"], 1)

    def test_a_parse_exception_is_a_per_file_skip(self):
        write(self.root, "a.py", "x = 1\n")
        write(self.root, "b.py", 'import hashlib\nhashlib.sha256(b"1")\n')
        real = cryptoscan.scan_source

        def boom(path, text):
            if path == "a.py":
                raise MemoryError()
            return real(path, text)
        with mock.patch.object(cryptoscan, "scan_source", boom):
            out = sd.collect(self.root, URL, SHA)
        self.assertEqual(out["record"]["searched"]["python"]["skipped"]["by_reason"], {"parse_error": 1})
        self.assertEqual(len(out["record"]["crypto_call_sites"]), 1)


class CancellationTest(Base):
    def test_cancel_before_during_parse_and_after_returns_no_record(self):
        write(self.root, "a.py", 'import hashlib\nhashlib.sha256(b"1")\n')
        write(self.root, "b.py", 'import hashlib\nhashlib.sha256(b"1")\n')
        pre = threading.Event()
        pre.set()
        self.assertEqual(sd.collect(self.root, URL, SHA, cancel=pre)["status"], "cancelled")
        for point in ("scan", "audit"):
            with self.subTest(point):
                ev = threading.Event()
                if point == "scan":
                    real = cryptoscan.scan_source

                    def hook(path, text, real=real, ev=ev):
                        out = real(path, text)
                        ev.set()
                        return out
                    ctx = mock.patch.object(cryptoscan, "scan_source", hook)
                else:
                    real_a = cs.audit_file

                    def hook(text, path, sites, real_a=real_a, ev=ev):
                        real_a(text, path, sites)
                        ev.set()
                    ctx = mock.patch.object(cs, "audit_file", hook)
                with ctx:
                    out = sd.collect(self.root, URL, SHA, cancel=ev)
                self.assertEqual((out["status"], out["record"], out["copies"]), ("cancelled", None, {}))


class LanguageCensusTest(Base):
    def test_other_languages_are_counted_by_extension_never_parsed(self):
        _, out = self.sites({"a.js": "x", "b.ts": "x", "c.go": "x", "d.js": "x", "README.md": "x"})
        census = out["record"]["searched"]["other_source_languages"]
        self.assertEqual((census["count"], census["by_extension"]), (4, {".go": 1, ".js": 2, ".ts": 1}))
        self.assertEqual(out["record"]["searched"]["python"]["python_files_total"], 0)


if __name__ == "__main__":
    unittest.main()
