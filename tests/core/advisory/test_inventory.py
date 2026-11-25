import hashlib
import os
import shutil
import tempfile
import threading
import unittest

from opentrace_core.advisory import inventory
from opentrace_core.live.source import SourceRecord
from tests.core.advisory import support

SHA = "a" * 40
TREE = "b" * 40


def make_tree(root, files):
    src = os.path.join(root, "src")
    inputs = []
    for path, data in sorted(files.items()):
        full = os.path.join(src, *path.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(data)
        inputs.append({"path": path, "sha256": hashlib.sha256(data).hexdigest()})
    record = SourceRecord("https://github.com/acme/widget", SHA, TREE, True, len(files), sum(map(len, files.values())),
                          "c" * 64, (), tuple(inputs), "git")
    return record, src


class InventoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = support.specialist_binary()

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-inv-test-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.groups = []

    def run_inventory(self, files, cancel=None):
        if not self.binary:
            self.skipTest("no Go toolchain: Evidence Specialist B cannot be built")
        record, src = make_tree(self.dir, files)
        return inventory.inventory(record, src, self.binary, repo_name="acme/widget", register=self.groups.append,
                                   cancel=cancel or threading.Event(), scratch=self.dir)

    def test_i3_parser_reads_the_lockfile_and_keeps_unqueryable_rows(self):
        res = self.run_inventory({"package-lock.json": support.lock_bytes(), "README.md": b"hi\n"})
        self.assertEqual(res.status, "complete")
        by = {r["name_original"]: r for r in res.rows}
        self.assertEqual((by["minimatch"]["version_state"], by["minimatch"]["version_original"]), ("exact", "3.1.2"))
        self.assertEqual(by["minimatch"]["ecosystem"], "npm")
        self.assertEqual(by["minimatch"]["path"], "package-lock.json")
        self.assertEqual(by["gitdep"]["version_state"], "non_registry")        # visible, never queried
        self.assertEqual({m["path"]: m["state"] for m in res.manifests}, {"package-lock.json": "parsed"})
        self.assertTrue(res.policy_digest.startswith("sha256:"))

    def test_specialist_group_is_confirmed_gone_on_return(self):
        self.run_inventory({"package-lock.json": support.lock_bytes()})
        self.assertEqual(len(self.groups), 1)
        self.assertTrue(self.groups[0].gone)

    def test_a_lockfile_the_parser_cannot_read_is_reported_not_dropped(self):
        res = self.run_inventory({"package-lock.json": b"{ not json"})
        self.assertEqual(res.status, "partial")
        self.assertEqual(res.rows, ())
        self.assertNotEqual(res.manifests[0]["state"], "parsed")

    def test_no_manifest_is_a_complete_empty_inventory(self):
        res = self.run_inventory({"src/index.js": b"console.log(1)\n"})
        self.assertEqual((res.status, res.rows), ("complete", ()))
        self.assertEqual(self.groups, [])                                       # B is not even started

    def test_files_in_excluded_directories_are_not_parsed(self):
        res = self.run_inventory({"package-lock.json": support.lock_bytes(), "node_modules/x/package-lock.json": support.lock_bytes()})
        paths = {r["path"] for r in res.rows}
        self.assertEqual(paths, {"package-lock.json"})
        self.assertIn(("node_modules/x/package-lock.json", "excluded"), [(m["path"], m["state"]) for m in res.manifests])

    def test_a_manifest_changed_since_export_is_refused(self):
        record, src = make_tree(self.dir, {"package-lock.json": support.lock_bytes()})
        with open(os.path.join(src, "package-lock.json"), "ab") as handle:
            handle.write(b" ")
        with self.assertRaises(inventory.InventoryError) as ctx:
            inventory.inventory(record, src, self.binary or "/bin/true", repo_name="acme/widget", register=self.groups.append,
                                cancel=threading.Event(), scratch=self.dir)
        self.assertEqual(ctx.exception.code, "tree_changed")
        self.assertEqual(self.groups, [])

    def test_cancel_stops_before_parsing_and_still_cleans_up(self):
        cancel = threading.Event()
        cancel.set()
        if not self.binary:
            self.skipTest("no Go toolchain")
        with self.assertRaises(inventory.InventoryError) as ctx:
            self.run_inventory({"package-lock.json": support.lock_bytes()}, cancel=cancel)
        self.assertEqual(ctx.exception.code, "cancelled")
        self.assertTrue(all(g.gone for g in self.groups))

    def test_missing_binary_is_not_discovered_or_built_implicitly(self):
        self.assertIsNone(inventory.specialist_binary({}))
        self.assertIsNone(inventory.specialist_binary({inventory.SPECIALIST_ENV: "/nonexistent/b"}))


if __name__ == "__main__":
    unittest.main()
