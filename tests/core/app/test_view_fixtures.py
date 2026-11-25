"""UIP-01B: the fixture corpus (evidence/uip/fixtures): validity, the invalid matrix, manifests, determinism, leakage and provenance."""
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest

from opentrace_core.app import view_contracts as vc
from tests.core.app.test_view_contracts import FIXTURES, REPO, jload, jsonschema_validators, load_builder, valid_fixture_payloads

SYNTHETIC = ["bom-large-synthetic", "cbom-empty-and-partial-synthetic", "contexts-600-synthetic", "deps-82-synthetic", "deps-paths-synthetic",
             "malicious-text-synthetic", "no-ai-synthetic", "nonpython-synthetic", "scan-status-matrix-synthetic"]
RECORDED = "fri" + "gate-recorded"
# This bundle is sanitized in the public export; v3 keeps the protected donor hash.
SANITIZED_EXPORT_SOURCE_HASHES = {
    "tests/core/bombridge/fixtures/bundles/frigate-v0.18.2-cpu-pilot.json": "2ff13bd1caa2aa856ac0670b9f7b5b935f5aa548ac8e34f6299a9526faaef86e",
}
# Frigate tokens assembled from pieces so this file does not itself carry them as one literal.
TOKENS = ["fri" + "gate", "blake" + "blackshear", "web" + "-new", "tflite" + "_runtime", "yolo" + "v6n", "hai" + "lo", "cpu" + "_model", "ai_edge" + "_litert"]


def read_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def tree_digest(root):
    out = {}
    for base, _, names in os.walk(root):
        for n in names:
            p = os.path.join(base, n)
            with open(p, "rb") as h:
                out[os.path.relpath(p, root)] = hashlib.sha256(h.read()).hexdigest()
    return out


class ValidFixtures(unittest.TestCase):
    def test_every_valid_fixture_passes_both_layers(self):
        validators, _, _ = jsonschema_validators()
        count = 0
        for fx, fname, name, payload in valid_fixture_payloads():
            vc.validate_payload(name, payload)
            errors = sorted(validators[name].iter_errors(payload), key=lambda e: list(e.path))
            self.assertEqual(errors, [], "%s/%s: JSON Schema rejects a valid fixture" % (fx, fname))
            vc.structural_check(name, payload)
            count += 1
        self.assertGreaterEqual(count, 79)

    def test_fixture_directories_are_exactly_the_agreed_set(self):
        dirs = sorted(d for d in os.listdir(FIXTURES) if os.path.isdir(os.path.join(FIXTURES, d)))
        self.assertEqual(dirs, sorted(SYNTHETIC + [RECORDED, "legacy-view-snapshots", "invalid"]))
        self.assertTrue(os.path.isfile(os.path.join(FIXTURES, "README.md")))

    def test_scan_matrix_sequence_is_ordered(self):
        files = sorted(f for f in os.listdir(os.path.join(FIXTURES, "scan-status-matrix-synthetic")) if f.startswith("scan-0") and int(f[5:7]) <= 4)
        vc.validate_sequence([jload(os.path.join(FIXTURES, "scan-status-matrix-synthetic", f)) for f in files])

    def test_no_fixture_claims_live_mode_or_a_session_id_other_than_the_fixed_one(self):
        for fx, fname, name, payload in valid_fixture_payloads():
            text = json.dumps(payload)
            self.assertNotIn('"mode": "live"', text.replace('":"', '": "'), "%s/%s" % (fx, fname))
            b = payload.get("binding")
            if b is not None:
                self.assertEqual(b["mode"], "captured", "%s/%s" % (fx, fname))
                self.assertEqual(b["generation"], 1)
            for sid in __import__("re").findall(r'"session_id": "([0-9a-f]{32})"', json.dumps(payload, indent=1)):
                self.assertEqual(sid, "0" * 31 + "1")


class InvalidCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.B = load_builder()
        cls.dir = os.path.join(FIXTURES, "invalid")
        cls.expected = jload(os.path.join(cls.dir, "EXPECTED.json"))

    def test_expected_covers_exactly_the_files(self):
        files = sorted(f for f in os.listdir(self.dir) if f not in ("EXPECTED.json", "MANIFEST.json"))
        self.assertEqual(files, sorted(self.expected))
        self.assertGreaterEqual(len(files), 60)

    def test_every_case_is_rejected_with_its_exact_typed_error(self):
        for fname, exp in sorted(self.expected.items()):
            env = jload(os.path.join(self.dir, fname))
            got = self.B.run_case(env)
            self.assertEqual(got, (exp["code"], exp["detail_code"]), fname)

    def test_structural_cases_are_rejected_by_json_schema_too_and_semantic_cases_are_not_expected_to_be(self):
        validators, _, _ = jsonschema_validators()
        checked = {"structural": 0, "semantic": 0}
        for fname, exp in sorted(self.expected.items()):
            env = jload(os.path.join(self.dir, fname))
            if env.get("route") or env.get("sequence") is not None or env.get("payload") is None:
                continue
            name, payload = env["schema_name"], env["payload"]
            js_errors = list(validators[name].iter_errors(payload))
            try:
                vc.structural_check(name, payload)
                std_ok = True
            except vc.ContractError:
                std_ok = False
            self.assertEqual(std_ok, not js_errors, "%s: the two structural engines disagree" % fname)
            if exp["layer"] == "structural":
                self.assertTrue(js_errors, fname)
                self.assertFalse(std_ok, fname)
            else:
                self.assertTrue(std_ok, "%s is semantic but fails structure" % fname)
            checked[exp["layer"]] += 1
        self.assertGreater(checked["structural"], 10)
        self.assertGreater(checked["semantic"], 30)

    def test_required_rejection_cases_exist(self):
        names = {f[:-5] for f in self.expected}
        required = ["dependency-152-nodes", "dependency-241-edges", "candidates-26-items", "full-view-151-nodes", "excerpt-601-chars", "query-81-chars",
                    "scan-percent-field", "sbom-completed-without-output", "failed-stage-with-output", "handoff-ready-on-failed-job", "seq-regression",
                    "stale-generation", "binding-mismatch", "unlocated-group-with-files", "distinct-greater-than-membership", "root-total-mismatch",
                    "fallback-category-python", "shortcut-edge-from-focus", "wrong-depth", "missing-edge-endpoint", "duplicate-node-id", "filter-totals-not-summing",
                    "no-match-counted-as-gap", "not-run-not-counted-as-gap", "not-run-without-explanation", "31-matches", "empty-state-with-assets",
                    "failed-state-with-assets", "absence-established-true", "supplemental-not-experimental", "supplemental-without-file-hash",
                    "original-without-pointer", "advisory-without-evidence", "implementation-link-not-resolved", "attribute-recorded-without-value",
                    "attribute-unavailable-with-value", "model-filename-marked-resolved", "context-inspector-security-concern", "source-checked-without-evidence",
                    "bom-entity-carries-verdict", "evidence-only-with-assertion", "excluded-evidence-on-supporting-edge", "resolution-inconsistent",
                    "relationship-with-items", "not-compared-without-detail", "two-assertions-in-focused-graph", "duplicate-canonical-ref", "control-character",
                    "request-unknown-parameter", "request-duplicate-parameter", "request-page-size-override", "request-unsupported-version",
                    "resolved-without-identity", "unresolved-with-binding"]
        self.assertEqual([n for n in required if n not in names], [])

    def test_semantic_corpus_is_not_masked_by_an_earlier_rule(self):
        # every semantic case must fail on the rule it names, not on an unrelated structural error
        for fname, exp in sorted(self.expected.items()):
            if exp["layer"] == "semantic" and exp["code"] in ("projection_failed",):
                self.assertTrue(exp["detail_code"].startswith("invariant:"), fname)


class Manifests(unittest.TestCase):
    def test_every_manifest_digest_matches_its_files(self):
        for d in sorted(os.listdir(FIXTURES)):
            path = os.path.join(FIXTURES, d)
            if not os.path.isdir(path):
                continue
            m = jload(os.path.join(path, "MANIFEST.json"))
            self.assertEqual(m["schema"], "opentrace.uip.fixture_manifest/1")
            self.assertEqual(m["name"], d)
            self.assertIn(m["provenance"], ("recorded", "derived", "synthetic"))
            on_disk = sorted(f for f in os.listdir(path) if f != "MANIFEST.json" and f != "EXPECTED.json")
            self.assertEqual(on_disk, sorted(e["path"] for e in m["files"]), d)
            for e in m["files"]:
                with open(os.path.join(path, e["path"]), "rb") as h:
                    data = h.read()
                self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), (e["bytes"], e["sha256"]), "%s/%s" % (d, e["path"]))
            with open(os.path.join(REPO, m["builder"]["path"]), "rb") as h:
                self.assertEqual(hashlib.sha256(h.read()).hexdigest(), m["builder"]["sha256"], "builder changed after %s was generated" % d)

    def test_provenance_labels_are_accurate(self):
        prov = {d: jload(os.path.join(FIXTURES, d, "MANIFEST.json"))["provenance"] for d in os.listdir(FIXTURES) if os.path.isdir(os.path.join(FIXTURES, d))}
        self.assertEqual(prov[RECORDED], "derived")
        self.assertEqual(prov["legacy-view-snapshots"], "derived")
        for d in SYNTHETIC + ["invalid"]:
            self.assertEqual(prov[d], "synthetic", d)
            self.assertEqual(jload(os.path.join(FIXTURES, d, "MANIFEST.json"))["sources"], [])

    def test_derived_sources_are_the_protected_recorded_inputs(self):
        v3 = jload(os.path.join(REPO, "evidence", "uip", "baseline", "opentrace-uip-baseline-v3.json"))["class_p"]["files"]
        for d in (RECORDED, "legacy-view-snapshots"):
            m = jload(os.path.join(FIXTURES, d, "MANIFEST.json"))
            self.assertGreaterEqual(len(m["sources"]), 6)
            for s in m["sources"]:
                self.assertIn(s["path"], v3, s["path"])
                if s["path"] in SANITIZED_EXPORT_SOURCE_HASHES:
                    self.assertEqual(s["sha256"], SANITIZED_EXPORT_SOURCE_HASHES[s["path"]], s["path"])
                    self.assertNotEqual(s["sha256"], v3[s["path"]]["sha256"], s["path"])
                else:
                    self.assertEqual(s["sha256"], v3[s["path"]]["sha256"], s["path"])

    def test_frigate_names_only_where_allowed(self):
        allowed = {RECORDED, "legacy-view-snapshots"}
        roots = [(d, os.path.join(FIXTURES, d)) for d in sorted(os.listdir(FIXTURES)) if os.path.isdir(os.path.join(FIXTURES, d))]
        for d, path in roots:
            has = False
            for f in os.listdir(path):
                text = read_text(os.path.join(path, f)).lower().replace("contains_frigate_names", "")  # the manifest key itself is contract-named
                has = has or any(t in text for t in TOKENS)
                if d not in allowed:
                    self.assertFalse([t for t in TOKENS if t in text], "%s/%s" % (d, f))
            self.assertEqual(jload(os.path.join(path, "MANIFEST.json"))["contains_frigate_names"], d in allowed, d)
            if d in allowed:
                self.assertTrue(has, d)
        for p in [os.path.join(REPO, "contracts", "workbench"), os.path.join(REPO, "src", "core", "opentrace_core", "app", "view_contracts.py"),
                  os.path.join(REPO, "tools", "uip_fixtures"), os.path.join(FIXTURES, "README.md")]:
            files = [p] if os.path.isfile(p) else [os.path.join(b, n) for b, _, ns in os.walk(p) for n in ns if n.endswith((".json", ".py", ".md"))]
            for f in files:
                text = read_text(f).lower()
                self.assertFalse([t for t in TOKENS if t in text], f)


class FrigateRecordedObservations(unittest.TestCase):
    """The recorded case is observed, not asserted: compare with the v3 record and the report's stated expectations."""

    def test_candidate_numbers_equal_the_v3_record(self):
        p = jload(os.path.join(FIXTURES, RECORDED, "bom-candidates-offset-00.json"))
        v3 = jload(os.path.join(REPO, "evidence", "uip", "baseline", "opentrace-uip-baseline-v3.json"))["semantic"]["observed_vs_report"]
        c = p["counts"]
        self.assertEqual(c["candidates_total"], v3["candidates"]["observed"])
        self.assertEqual(c["state_counts"]["contradicted"], v3["contradicted"]["observed"])
        self.assertEqual(c["state_counts"]["unverifiable"], v3["unverifiable"]["observed"])
        self.assertEqual(c["state_counts"]["unknown_coverage"], v3["coverage_tasks"]["observed"])
        self.assertEqual(c["candidates_total"], 79)
        self.assertEqual(c["candidates_total"], 69 + 10)
        self.assertEqual(c["filter_group_counts"], {"represented": 0, "not_represented": 69, "unknown": 10})
        self.assertEqual(len(p["items"]), 25)
        self.assertLess(c["assertions_unique"], c["candidates_total"] + 1)

    def test_crypto_and_ai_are_original_artifact_only_and_truthful(self):
        cr = jload(os.path.join(FIXTURES, RECORDED, "crypto-assets.json"))
        self.assertEqual((cr["availability"]["state"], cr["page"]["assets_total"], len(cr["services"])), ("completed_empty", 0, 13))
        self.assertFalse(cr["absence_established"])
        ai = jload(os.path.join(FIXTURES, RECORDED, "ai-assets.json"))
        self.assertEqual(len(ai["assets"]), 1)
        for a in ai["assets"] + cr["services"]:
            self.assertEqual(a["provenance"]["origin"], "original_artifact")
        self.assertTrue(all(pr["provenance"]["origin"] == "original_artifact" and not pr["provenance"]["experimental"] for pr in cr["producers"] + ai["producers"]))
        self.assertTrue(all(v["state"] == "unavailable" for v in ai["assets"][0]["attributes"].values()))

    def test_contexts_match_the_existing_view_totals_and_group_semantics(self):
        c = jload(os.path.join(FIXTURES, RECORDED, "contexts.json"))
        self.assertEqual((c["root"]["distinct_total"], c["root"]["membership_total"], c["root"]["unlocated_total"]), (1989, 1976, 13))
        self.assertEqual([g["category"] for g in c["groups"]], ["documentation", "web", "python_requirements", "github_actions", None])
        self.assertEqual(c["root"]["name"], c["binding"]["repository"]["owner"] + "/" + c["binding"]["repository"]["name"])

    def test_dependency_page_states_lookup_was_not_performed_rather_than_clean(self):
        p = jload(os.path.join(FIXTURES, RECORDED, "dependency-page.json"))
        self.assertEqual(p["page"]["matches_shown"], 30)
        self.assertNotEqual(p["focus"]["node_id"], "web" + "-new")
        self.assertIsNotNone(p["lookup"]["explanation"])
        self.assertTrue(all(n["advisory_lookup"] in ("match", "not_run") for n in p["nodes"]))

    def test_first_candidate_graph_has_no_inferred_edges(self):
        g = jload(os.path.join(FIXTURES, RECORDED, "bom-graph-focused-first.json"))
        self.assertEqual(g["graph_state"], "assertion_graph")
        self.assertEqual(sum(1 for n in g["nodes"] if n["kind"] == "assertion"), 1)
        for e in g["edges"]:
            self.assertEqual(e["from"], next(n["node_id"] for n in g["nodes"] if n["kind"] == "assertion"))


class BuilderDeterminism(unittest.TestCase):
    def run_builder(self, out):
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join([os.path.join(REPO, "src", "core"), os.path.join(REPO, "src", "agents", "investigator"), env.get("PYTHONPATH", "")])
        r = subprocess.run([sys.executable, os.path.join(REPO, "tools", "uip_fixtures", "build.py"), "--out", out], env=env, capture_output=True, text=True, timeout=600, cwd=REPO)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_two_runs_are_byte_identical_and_equal_the_committed_fixtures(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            self.run_builder(os.path.join(a, "f"))
            self.run_builder(os.path.join(b, "f"))
            ta, tb = tree_digest(os.path.join(a, "f")), tree_digest(os.path.join(b, "f"))
            self.assertEqual(ta, tb)
            committed = tree_digest(FIXTURES)
            committed.pop("README.md", None)
            self.assertEqual(ta, committed, "committed fixtures are stale: rerun tools/uip_fixtures/build.py")

    def test_guard_refuses_external_connections_but_allows_loopback_and_socketpair(self):
        B = load_builder()
        with B.no_external_network():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with self.assertRaises(OSError) as ctx:
                    s.connect(("93.184.216.34", 80))
                self.assertIn("refused", str(ctx.exception))
                with self.assertRaises(OSError):
                    socket.getaddrinfo("example.invalid", 80)
            finally:
                s.close()
            a, b = socket.socketpair()
            a.sendall(b"x")
            self.assertEqual(b.recv(1), b"x")
            a.close()
            b.close()
        self.assertTrue(callable(socket.socket.connect))


if __name__ == "__main__":
    unittest.main()
