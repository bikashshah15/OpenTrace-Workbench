"""Manifest policy, path validation and listing parsing (I3-REQ-03 items 2-3, I3-REQ-04)."""
import json
import unittest

from opentrace_core.cohort import policy as pol


def row(path, mode="100644", typ="blob", size=10, sha="a" * 40):
    return {"mode": mode, "type": typ, "sha": sha, "size": size, "path": path}


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.policy = pol.load_policy()

    def test_policy_digest_is_stable_and_file_is_canonical_json(self):
        self.assertTrue(pol.policy_digest().startswith("sha256:"))
        self.assertEqual(self.policy["policy_id"], "manifest_policy/1")

    def test_c5_hostile_paths_are_rejected_not_selected(self):
        bad = ["../go.mod", "a/../go.mod", "/abs/go.mod", "a//go.mod", "a/./go.mod", "a\n/go.mod", "a\\b/go.mod", "x" * 600 + "/go.mod",
               "a\x00/go.mod", "a/\x1b/go.mod"]
        out = pol.select_manifests([row(p) for p in bad], self.policy)
        self.assertEqual(out["selected"], [])
        self.assertEqual(len(out["rejected"]), len(bad))
        self.assertTrue(all(r["reason"] for r in out["rejected"]))

    def test_c6_excluded_segments_are_recorded_not_dropped(self):
        paths = ["node_modules/x/package.json", "vendor/y/go.mod", "pkg/testdata/z/go.mod", "ok/go.mod"]
        out = pol.select_manifests([row(p) for p in paths], self.policy)
        self.assertEqual([r["path"] for r in out["selected"]], ["ok/go.mod"])
        self.assertEqual(sorted(r["path"] for r in out["excluded"]), sorted(paths[:3]))

    def test_c3_symlink_and_submodule_matches_are_never_selected(self):
        out = pol.select_manifests([row("a/go.mod", mode="120000"), row("b/package-lock.json", mode="160000", typ="commit"),
                                    row("c/go.mod")], self.policy)
        self.assertEqual([r["path"] for r in out["selected"]], ["c/go.mod"])
        self.assertEqual(sorted(r["reason"] for r in out["nonblob"]), ["mode_120000", "mode_160000"])

    def test_kinds_and_requirements_pattern(self):
        names = ["go.mod", "go.sum", "package.json", "package-lock.json", "pnpm-lock.yaml", "uv.lock", "pyproject.toml",
                 "examples/requirements-dev.txt", "yarn.lock", "README.md"]
        out = pol.select_manifests([row(n) for n in names], self.policy)
        kinds = {r["path"]: r["kind"] for r in out["selected"]}
        self.assertEqual(kinds["examples/requirements-dev.txt"], "requirements_txt")
        self.assertEqual(kinds["uv.lock"], "uv_lock")
        self.assertNotIn("README.md", kinds)
        self.assertEqual(len(kinds), 9)

    def test_selection_is_sorted_bytewise_and_input_order_independent(self):
        rows = [row("b/go.mod"), row("a/go.mod"), row("B/go.mod")]
        a = pol.select_manifests(rows, self.policy)["selected"]
        b = pol.select_manifests(list(reversed(rows)), self.policy)["selected"]
        self.assertEqual(a, b)
        self.assertEqual([r["path"] for r in a], ["B/go.mod", "a/go.mod", "b/go.mod"])

    def test_parse_ls_tree_round_trip_and_malformed(self):
        raw = b"100644 blob " + b"a" * 40 + b"      12\tgo.mod\x00160000 commit " + b"b" * 40 + b"       -\tsub\x00"
        rows = pol.parse_ls_tree(raw)
        self.assertEqual([r["path"] for r in rows], ["go.mod", "sub"])
        self.assertIsNone(rows[1]["size"])
        with self.assertRaises(ValueError):
            pol.parse_ls_tree(b"100644 blob abc\tgo.mod\x00")
        with self.assertRaises(ValueError):
            pol.parse_ls_tree(b"no tab here\x00")


if __name__ == "__main__":
    unittest.main()
