"""UIP-10: the bounded, deterministic, cancellable requirement-file collector (no network, no execution, in process)."""
import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from opentrace_core.live import source_declarations as sd

URL = "https://github.com/acme/widget"
SHA = "a" * 40


def write(root, rel, data=b"requests==2.31.0\n"):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data if isinstance(data, bytes) else data.encode())
    return path


class Base(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ot-decl-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def run_collect(self, **kw):
        return sd.collect(self.root, URL, SHA, **kw)


class SelectionTest(Base):
    def test_requirement_files_are_selected_by_name_in_deterministic_order_with_exact_bytes(self):
        write(self.root, "requirements.txt", "flask==2.0\n")
        write(self.root, "docker/main/requirements-wheels.txt", "numpy>=1\nscipy\n")
        write(self.root, "requirements/dev.txt", "pytest==7\n")
        write(self.root, "docs/notes.txt", "not a requirements file\n")
        write(self.root, "a/requirements.txt", "six\n")
        out = self.run_collect()
        paths = [r["path"] for r in out["record"]["requirement_files"]]
        self.assertEqual(paths, ["requirements.txt", "a/requirements.txt", "docker/main/requirements-wheels.txt", "requirements/dev.txt"])
        self.assertEqual(out["copies"]["docker/main/requirements-wheels.txt"], b"numpy>=1\nscipy\n")
        rec = {r["path"]: r for r in out["record"]["requirement_files"]}
        self.assertEqual(rec["docker/main/requirements-wheels.txt"]["named_requirements"], 2)
        self.assertEqual(rec["requirements.txt"]["sha256"], hashlib.sha256(b"flask==2.0\n").hexdigest())
        self.assertTrue(out["summary"]["traversal"]["complete"])
        self.assertEqual(out["summary"]["traversal"]["count_kind"], "exact")
        # identical tree -> identical record digest (no timestamps)
        self.assertEqual(self.run_collect()["record_sha256"], out["record_sha256"])

    def test_the_record_digest_is_over_its_canonical_json_and_the_bundle_carries_byte_exact_copies(self):
        write(self.root, "requirements.txt", "flask==2.0\n")
        out = self.run_collect()
        self.assertEqual(hashlib.sha256(sd.canonical_bytes(out["record"])).hexdigest(), out["record_sha256"])
        bundle = json.loads(sd.bundle_bytes(out))
        self.assertEqual(bundle["record_sha256"], out["record_sha256"])
        self.assertEqual(set(bundle["copies"]), {"requirements.txt"})

    def test_markers_and_directives_are_preserved_as_text_and_not_followed(self):
        write(self.root, "requirements.txt", "-r other.txt\nfoo==1; python_version<'3.9'\n")
        write(self.root, "other.txt", "hidden==1\n")
        out = self.run_collect()
        self.assertEqual([r["path"] for r in out["record"]["requirement_files"]], ["requirements.txt"])
        self.assertNotIn("other.txt", out["copies"])

    def test_nested_same_named_files_are_all_collected(self):
        write(self.root, "requirements.txt", "a\n")
        write(self.root, "docs/requirements.txt", "b\n")
        out = self.run_collect()
        self.assertEqual([r["path"] for r in out["record"]["requirement_files"]], ["requirements.txt", "docs/requirements.txt"])


class UnsupportedAndEmptyTest(Base):
    def test_other_ecosystems_and_unread_python_formats_are_listed_by_name_and_never_parsed(self):
        write(self.root, "package.json", "{}")
        write(self.root, "web/package-lock.json", "{}")
        write(self.root, "go.mod", "module x\n")
        write(self.root, "pyproject.toml", "[project]\n")
        out = self.run_collect()
        un = out["summary"]["unsupported"]
        self.assertEqual(un["count"], 4)
        self.assertEqual(sorted(f["ecosystem"] for f in un["listed"]), ["go", "npm", "npm", "python"])
        self.assertEqual(out["record"]["requirement_files"], [])
        self.assertEqual(out["copies"], {})

    def test_an_empty_tree_is_a_complete_collection_of_nothing(self):
        out = self.run_collect()
        self.assertEqual(out["status"], "collected")
        self.assertEqual(out["summary"]["matched"], 0)
        self.assertTrue(out["summary"]["traversal"]["complete"])


class BoundsTest(Base):
    def test_a_file_over_the_byte_limit_is_not_collected_and_not_partially_read(self):
        write(self.root, "requirements.txt", b"x" * (sd.MAX_FILE_BYTES + 1))
        write(self.root, "requirements-ok.txt", "ok\n")
        out = self.run_collect()
        self.assertEqual([r["path"] for r in out["record"]["requirement_files"]], ["requirements-ok.txt"])
        self.assertEqual(out["summary"]["skipped"]["by_reason"], {"too_large": 1})
        self.assertEqual(out["summary"]["skipped"]["listed"], [{"path": "requirements.txt", "reason": "too_large"}])

    def test_the_line_limit_utf8_rule_and_symlinks(self):
        write(self.root, "requirements-many.txt", "a\n" * (sd.MAX_LINES + 1))
        write(self.root, "requirements-bad.txt", b"\xff\xfe\n")
        write(self.root, "real.txt", "x\n")
        os.symlink("real.txt", os.path.join(self.root, "requirements-link.txt"))
        out = self.run_collect()
        self.assertEqual(out["summary"]["skipped"]["by_reason"], {"not_regular": 1, "not_utf8": 1, "over_line_limit": 1})
        self.assertEqual(out["record"]["requirement_files"], [])

    def test_exactly_at_the_line_limit_is_collected(self):
        write(self.root, "requirements.txt", "a\n" * sd.MAX_LINES)
        self.assertEqual(len(self.run_collect()["record"]["requirement_files"]), 1)

    def test_the_file_count_limit_skips_the_rest_in_traversal_order_and_says_so(self):
        for i in range(sd.MAX_FILES_COLLECTED + 3):
            write(self.root, "requirements-%03d.txt" % i, "p%d\n" % i)
        out = self.run_collect()
        self.assertEqual(len(out["record"]["requirement_files"]), sd.MAX_FILES_COLLECTED)
        self.assertEqual(out["summary"]["skipped"]["by_reason"], {"over_file_limit": 3})
        self.assertEqual(out["record"]["requirement_files"][0]["path"], "requirements-000.txt")
        self.assertEqual(out["summary"]["skipped"]["listed"][0]["path"], "requirements-%03d.txt" % sd.MAX_FILES_COLLECTED)
        self.assertEqual(out["summary"]["matched"], sd.MAX_FILES_COLLECTED + 3)

    def test_the_total_byte_limit(self):
        with mock.patch.object(sd, "MAX_TOTAL_BYTES", 30):
            write(self.root, "requirements-a.txt", "a" * 20 + "\n")
            write(self.root, "requirements-b.txt", "b" * 20 + "\n")
            out = self.run_collect()
        self.assertEqual([r["path"] for r in out["record"]["requirement_files"]], ["requirements-a.txt"])
        self.assertEqual(out["summary"]["skipped"]["by_reason"], {"over_total_bytes": 1})

    def test_the_skipped_listing_is_bounded_but_its_count_is_not(self):
        with mock.patch.object(sd, "MAX_FILES_COLLECTED", 0):
            for i in range(sd.MAX_SKIPPED_LISTED + 5):
                write(self.root, "requirements-%03d.txt" % i, "p\n")
            out = self.run_collect()
        skipped = out["summary"]["skipped"]
        self.assertEqual(skipped["count"], sd.MAX_SKIPPED_LISTED + 5)
        self.assertEqual(len(skipped["listed"]), sd.MAX_SKIPPED_LISTED)

    def test_unsafe_names_are_skipped_not_collected(self):
        write(self.root, "requirements-\x07.txt", "a\n")
        out = self.run_collect()
        self.assertEqual(out["summary"]["skipped"]["by_reason"], {"unsafe_path": 1})


class EarlyStopTest(Base):
    def populate(self):
        write(self.root, "requirements.txt", "a\n")
        for i in range(5):
            write(self.root, "pkg/f%d.py" % i, "x = 1\n")

    def test_the_entry_cap_stops_traversal_and_every_count_becomes_a_lower_bound(self):
        self.populate()
        with mock.patch.object(sd, "MAX_ENTRIES", 3):
            out = self.run_collect()
        trav = out["summary"]["traversal"]
        self.assertFalse(trav["complete"])
        self.assertEqual(trav["stop_reason"], "entry_cap")
        self.assertEqual(trav["count_kind"], "at_least")
        self.assertEqual(out["record"]["searched"]["requirement_files_matched"]["count_kind"], "at_least")
        self.assertEqual(out["summary"]["unsupported"]["count_kind"], "at_least")
        self.assertIn("lower bound", " ".join(out["record"]["limitations"]))

    def test_the_time_budget_uses_the_injected_clock(self):
        self.populate()
        ticks = iter(range(0, 1000))
        out = self.run_collect(clock=lambda: float(next(ticks)), budget=5.0)
        self.assertEqual(out["summary"]["traversal"]["stop_reason"], "time_budget")
        self.assertFalse(out["summary"]["traversal"]["complete"])

    def test_a_stopped_run_still_returns_what_it_fully_collected_before_the_stop(self):
        write(self.root, "a-requirements.txt", "one\n")       # sorts before the subdirectory
        write(self.root, "zdir/%s" % ("x" * 3), "x\n")
        with mock.patch.object(sd, "MAX_ENTRIES", 1):
            out = self.run_collect()
        self.assertEqual([r["path"] for r in out["record"]["requirement_files"]], ["a-requirements.txt"])
        self.assertFalse(out["summary"]["traversal"]["complete"])


class CancellationTest(Base):
    def test_cancel_set_before_the_walk_returns_no_record(self):
        write(self.root, "requirements.txt", "a\n")
        cancel = threading.Event()
        cancel.set()
        out = self.run_collect(cancel=cancel)
        self.assertEqual((out["status"], out["record"], out["copies"]), ("cancelled", None, {}))

    def test_cancel_during_traversal_is_noticed_between_entries(self):
        for i in range(10):
            write(self.root, "d%02d/requirements.txt" % i, "a\n")
        cancel = threading.Event()
        calls = {"n": 0}
        real = os.scandir

        def scandir(path):
            calls["n"] += 1
            if calls["n"] == 3:
                cancel.set()
            return real(path)
        with mock.patch.object(sd.os, "scandir", scandir):
            out = self.run_collect(cancel=cancel)
        self.assertEqual(out["status"], "cancelled")
        self.assertLess(calls["n"], 11)          # stopped before every directory was visited

    def test_cancel_during_a_bounded_read_is_noticed_between_chunks(self):
        write(self.root, "requirements.txt", b"a\n" * 100)
        cancel = threading.Event()
        real_read = os.read
        seen = {"n": 0}

        def read(fd, n):
            seen["n"] += 1
            cancel.set()
            return real_read(fd, 7)                 # tiny chunks: the file needs many reads
        with mock.patch.object(sd.os, "read", read):
            out = self.run_collect(cancel=cancel)
        self.assertEqual(out["status"], "cancelled")
        self.assertEqual(seen["n"], 1)

    def test_a_collector_never_calls_anything_that_executes_or_reaches_the_network(self):
        write(self.root, "requirements.txt", "a\n")
        with mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess")), \
                mock.patch("socket.socket", side_effect=AssertionError("socket")):
            self.assertEqual(self.run_collect()["status"], "collected")


if __name__ == "__main__":
    unittest.main()
