import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from opentrace_core.live import policy, source
from tests.core.live import support

SHA = "a" * 40


class PolicyTest(unittest.TestCase):
    def test_shipped_allowlist_is_one_full_sha_entry(self):
        entries = policy.load_allowlist()
        self.assertEqual(list(entries), ["modelcontextprotocol/inspector"])
        self.assertRegex(entries["modelcontextprotocol/inspector"]["commit_sha"], r"^[0-9a-f]{40}$")

    def test_exact_repository_and_commit_only(self):
        entries = {"o/r": {"repo": "o/r", "commit_sha": SHA}}
        self.assertEqual(policy.check_allowed(entries, "O", "R", SHA)["commit_sha"], SHA)
        with self.assertRaises(policy.PolicyError) as other:
            policy.check_allowed(entries, "o", "other", SHA)
        self.assertEqual(other.exception.code, "not_allowlisted")
        with self.assertRaises(policy.PolicyError) as moved:
            policy.check_allowed(entries, "o", "r", "b" * 40)
        self.assertEqual(moved.exception.code, "commit_not_allowlisted")

    def test_entries_must_carry_full_lowercase_sha(self):
        for bad in ("abc1234", "A" * 40, "a" * 39, ""):
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
                json.dump({"schema": "opentrace.live_allowlist/1", "entries": [{"repo": "o/r", "commit_sha": bad}]}, handle)
            self.addCleanup(os.unlink, handle.name)
            with self.assertRaises(policy.PolicyError):
                policy.load_allowlist(handle.name)


class SourceTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-src-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.files = {"package-lock.json": b'{"lockfileVersion":3}\n', "src/a.js": b"a\nb\n", "run.sh": b"#!/bin/sh\necho hi\n"}
        self.origin, self.sha, self.tree = support.make_repo(self.dir, self.files, symlink="/etc/passwd",
                                                              attributes="*.js text eol=crlf\n")
        self.ws = os.path.join(self.dir, "ws")
        os.mkdir(self.ws)

    def acquire(self, *sha, **kw):
        return source.acquire(self.origin, sha[0] if sha else self.sha, self.ws, allow_protocol="file",
                              canonical_url="https://github.com/o/r", **kw)

    def test_exact_commit_is_fetched_and_every_blob_verified(self):
        rec = self.acquire()
        self.assertTrue(rec.verified)
        self.assertEqual((rec.commit_sha, rec.tree_sha), (self.sha, self.tree))
        self.assertEqual(rec.repository_url, "https://github.com/o/r")
        self.assertEqual(rec.file_count, 4)  # three files + .gitattributes
        by_path = {i["path"]: i["sha256"] for i in rec.inputs}
        for name, data in self.files.items():
            self.assertEqual(by_path[name], hashlib.sha256(data).hexdigest())
            with open(os.path.join(self.ws, "src", *name.split("/")), "rb") as handle:
                self.assertEqual(handle.read(), data, "bytes must equal the committed blob (no eol/filter conversion)")

    def test_nothing_is_executable_and_symlinks_are_not_materialised(self):
        rec = self.acquire()
        self.assertEqual([s["path"] for s in rec.skipped], ["link"])
        self.assertFalse(os.path.lexists(os.path.join(self.ws, "src", "link")))
        for base, _d, files in os.walk(os.path.join(self.ws, "src")):
            for name in files:
                self.assertFalse(os.access(os.path.join(base, name), os.X_OK), name)

    def test_short_or_uppercase_sha_is_refused_before_any_git_call(self):
        for bad in (self.sha[:12], self.sha.upper() + "0", "", None):
            with self.assertRaises(source.SourceError) as err:
                self.acquire(bad)
            self.assertEqual(err.exception.code, "sha_not_full")
            shutil.rmtree(self.ws), os.mkdir(self.ws)

    def test_an_unknown_commit_is_not_acquired(self):
        with self.assertRaises(source.SourceError) as err:
            self.acquire("b" * 40)
        self.assertEqual(err.exception.code, "fetch_failed")

    def test_bytes_that_do_not_match_the_tree_object_id_are_rejected(self):
        with mock.patch.object(source, "git_object_id", return_value="0" * 40):
            with self.assertRaises(source.SourceError) as err:
                self.acquire()
        self.assertEqual(err.exception.code, "blob_mismatch")

    def test_cancellation_stops_the_fetch(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(source.SourceError) as err:
            self.acquire(cancel=cancel)
        self.assertEqual(err.exception.code, "cancelled")

    def test_unsafe_paths_are_never_materialised(self):
        for bad in ("", "/etc/x", "../x", "a/../b", "a//b", ".git/config", "a/.GIT/x", "a\\b", "a/./b"):
            self.assertFalse(source._safe_path(bad), bad)
        self.assertTrue(source._safe_path("web/package-lock.json"))

    def test_git_object_id_matches_git(self):
        self.assertEqual(source.git_object_id(b"hello\n"), "ce013625030ba8dba906f756967f9e9ca394464a")  # `printf 'hello\n' | git hash-object --stdin`
