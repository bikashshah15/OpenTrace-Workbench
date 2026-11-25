"""UIP-13: the model generator and its gates, at generator level (offline; no network, no execution).

Synthetic bundles for the gate matrix; the captured Frigate and Viseron source-declaration records and scan scopes (read from the repository fixtures) for the
captured cases. The unchanged rule ``model_identity.declared_in_aibom/1`` is the verdict. The Viseron raw AI-BOM bytes are not in this repository, so the
zero-model document used with the captured Viseron scope is SYNTHETIC (same shape: CycloneDX 1.6, no model); this is stated, not hidden.
"""
import copy
import hashlib
import json
import os
import unittest

from opentrace_core.bombridge import assess as bb_assess, discovery as bb_discovery, discovery_models as dm, rules
from opentrace_core.bombridge.discovery import GeneratorError

from tools.uip13 import fixture_oracle as oracle

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
LIVE = os.path.join(os.path.dirname(HERE), "live", "fixtures")
M1 = "https://models.example.org/a/det.onnx"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def load(*parts):
    with open(os.path.join(*parts), "rb") as f:
        return f.read()


def aibom(models=()):
    comps = [{"type": "machine-learning-model", "bom-ref": ref, "name": name, "externalReferences": [{"type": "distribution", "url": u} for u in urls]} for ref, name, urls in models]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": {"tools": [{"name": "cisco-aibom", "version": "1.10.1"}]}, "components": comps}


REV = "c" * 40


def bundle(scope, repo="https://github.com/acme/w", rev=REV):
    return {"capture": {"scope_id": "scope:t", "origin": "captured", "repository": {"url": repo, "revision": rev, "revision_selection": {"tree_sha": "b" * 40}},
                        "inventories": [{"inventory_id": "inv:cisco-aibom", "kind": "aibom", "origin": "captured", "generator": "cisco-aibom 1.10.1", "scan_scope": scope,
                                         "source_file": "cisco-aibom.cdx.json"}], "configuration": "t", "unknown": [], "unavailable": []},
            "entities": [], "evidence": [], "assertions": [], "input_checks": [], "origin": "captured", "notice": "t"}


def manifest(doc_sha, rev=REV, inputs=None, repo="https://github.com/acme/w"):
    return {"schema": "bombridge.acquisition/1", "repository": repo, "revision": rev, "inputs": inputs or [{"path": "m.py", "sha256": "d" * 64}], "tree_differs_from_revision": False,
            "generator": {"name": "cisco-aibom", "version": "1.10.1", "invocation": "x"}, "output_sha256": doc_sha, "limitations": []}


def ref(path, locator, line=1, fsha="d" * 64, kind="python", method="python-ast-string-constant", ordinal=0, excerpt=None):
    return {"occurrence_id": dm._h16(path, line, ordinal, locator), "ordinal": ordinal, "path": path, "file_sha256": fsha, "line": line, "end_line": line, "source_kind": kind,
            "method": method, "locator": locator, "excerpt": excerpt or f'M = "{locator}"', "excerpt_truncated": False}


def run(refs, *, doc=None, state="usable", scope=None, man=None, digests="auto", budget=500, rev=REV, extra_options=None, model_inputs=None):
    doc = aibom() if doc is None else doc
    raw = json.dumps(doc, sort_keys=True).encode()
    scope = {"paths": ["."], "listing_sha256": "e" * 64, "revision": rev, "tree_sha": "b" * 40, "file_count": 1} if scope is None else scope
    b = bundle(scope, rev=rev)
    ai = {"state": state, "inventory_id": "inv:cisco-aibom", "sha256": sha(raw), "doc": doc, "manifest": man or manifest(sha(raw), rev), "scan_scope": scope, "source_file": "cisco-aibom.cdx.json", "inventories": 1}
    listing = {r["path"]: r["file_sha256"] for r in refs} if digests == "auto" else digests
    gen = dm.ModelGenerator(dict({"aibom": ai, "source_digests": listing, "max_candidates": 500, "total_cap": 2000}, **(extra_options or {})))
    sd = {"repository": b["capture"]["repository"]["url"], "revision": rev, "requirement_files": [], "model_references": refs}
    report = {}
    out = bb_discovery.discover(b, raw_inventories={"inv:cisco-aibom": {"doc": doc, "sha256": sha(raw)}}, source_declarations=sd, requirement_texts={}, requirements=False,
                                extra_generators=(gen,), generator_report=report)
    return out, report, gen


def findings(out):
    ents = {e["entity_id"]: e for e in out["entities"]}
    res = {}
    for a in out["assertions"]:
        if a["family"] != "model_identity":
            continue
        f = rules.assess(a, ents, out["evidence"], {i["inventory_id"]: i for i in out["capture"]["inventories"]})
        res[a["assertion_id"]] = f
    return res


def cands(out):
    return [c for c in out["discovery"]["candidates"] if c["group"].startswith("models:")]


class GateMatrixTest(unittest.TestCase):
    def test_supported_only_for_an_exact_unique_locator_in_a_usable_bound_scope(self):
        out, rep, gen = run([ref("m.py", M1)], doc=aibom([("r", "d", [M1])]))
        [f] = findings(out).values()
        self.assertEqual((f["state"], f["rule_id"]), ("supported", "model_identity.declared_in_aibom/1"))
        self.assertEqual(rep["models"]["status"], "ok")
        self.assertEqual(gen.info["compared"], 1)

    def test_file_digest_gates(self):
        out, rep, gen = run([ref("m.py", M1)], doc=aibom([("r", "d", [M1])]), digests={})
        [c] = cands(out)
        self.assertEqual((c["assertion_id"], c["detail"]["reason_code"]), (None, "source_digest_unverified"))
        out, rep, gen = run([ref("m.py", M1)], doc=aibom([("r", "d", [M1])]), digests={"m.py": "0" * 64})
        self.assertEqual(cands(out)[0]["detail"]["reason_code"], "source_digest_mismatch")
        out, rep, gen = run([ref("m.py", M1)], doc=aibom([("r", "d", [M1])]), digests=None)
        self.assertEqual(cands(out)[0]["detail"]["reason_code"], "source_digest_unverified")

    def test_document_level_states_decided_by_the_orchestrator(self):
        for state, reason in (("not_run", "aibom_not_run"), ("failed", "aibom_requested_but_unavailable"), ("malformed", "aibom_document_malformed"),
                              ("digest_mismatch", "aibom_output_digest_mismatch")):
            with self.subTest(state):
                out, rep, gen = run([ref("m.py", M1)], state=state)
                [c] = cands(out)
                self.assertEqual((c["assertion_id"], c["detail"]["reason_code"]), (None, reason))
                self.assertFalse([e for e in out["evidence"] if e["observation"].get("kind") == "aibom_document"])

    def test_unsupported_spec_is_unusable_and_no_document_node_is_created(self):
        doc = aibom()
        doc["specVersion"] = "1.4"
        out, rep, gen = run([ref("m.py", M1)], doc=doc)
        self.assertEqual(cands(out)[0]["detail"]["reason_code"], "aibom_document_unusable")
        self.assertFalse([e for e in out["evidence"] if e["observation"].get("kind") == "aibom_document"])

    def test_binding_and_scope_gates(self):
        base = {"paths": ["."], "listing_sha256": "e" * 64, "revision": REV, "tree_sha": "b" * 40, "file_count": 1}
        cases = {
            "scope_missing": dict(base, listing_sha256="xyz"), "scope_revision_mismatch": dict(base, revision="9" * 40),
            "scope_digest_mismatch": dict(base, file_count=5), "scope_ambiguous": dict(base, paths=[".", "/abs"]),
        }
        for reason, scope in cases.items():
            with self.subTest(reason):
                out, rep, gen = run([ref("m.py", M1)], doc=aibom([("r", "d", [M1])]), scope=scope)
                self.assertEqual(cands(out)[0]["detail"]["reason_code"], reason)
                self.assertIsNone(cands(out)[0]["assertion_id"])

    def test_binding_not_recorded_when_the_manifest_does_not_bind_the_revision(self):
        out, rep, gen = run([ref("m.py", M1)], doc=aibom([("r", "d", [M1])]), man=manifest("f" * 64))      # output digest of another file: no recorded binding
        self.assertEqual(cands(out)[0]["detail"]["reason_code"], "binding_not_recorded")
        self.assertTrue([e for e in out["evidence"] if e["observation"].get("kind") == "aibom_document"], "the document evidence explains the reason")

    def test_scope_paths_prefix_at_a_boundary_only(self):
        scope = {"paths": ["pkg"], "listing_sha256": "e" * 64, "revision": REV, "tree_sha": "b" * 40, "file_count": 1}
        out, rep, gen = run([ref("pkg/m.py", M1), ref("pkgx/m.py", "https://h.example/n.onnx")], doc=aibom(), scope=scope)
        by = {c["title"].split(":")[0]: c["detail"]["reason_code"] for c in cands(out)}
        self.assertEqual(sorted(by.values(), key=str), [None, "outside_aibom_scan_scope"])

    def test_a_group_with_both_in_and_out_of_scope_occurrences_is_compared_on_the_in_scope_ones_only(self):
        scope = {"paths": ["pkg"], "listing_sha256": "e" * 64, "revision": REV, "tree_sha": "b" * 40, "file_count": 1}
        out, rep, gen = run([ref("out/a.py", M1), ref("pkg/b.py", M1)], doc=aibom([("r", "d", [M1])]), scope=scope)
        [c] = cands(out)
        self.assertEqual((c["detail"]["occurrences_in_scope"], c["detail"]["occurrences_not_compared"]), (1, 1))
        [f] = findings(out).values()
        self.assertEqual(f["state"], "supported")
        used = {u["evidence_id"] for u in f["used_evidence"]}
        outside = [e["evidence_id"] for e in out["evidence"] if (e["observation"].get("resolution") or {}).get("gate") == "outside_aibom_scan_scope"]
        self.assertEqual(len(outside), 1)
        self.assertFalse(used & set(outside), "outside-scope text is never used by the rule")
        self.assertEqual(gen.info["scope_blocked"], 1)

    def test_the_rule_still_never_contradicts(self):
        out, rep, gen = run([ref("m.py", M1)], doc=aibom([("r", "x", ["https://other.example/x.onnx"])]))
        self.assertNotIn(list(findings(out).values())[0]["state"], ("contradicted", "supported"))

    def test_a_string_literal_is_attached_only_when_the_rule_pattern_would_miss_the_token(self):
        wrapped = ref("a.sh", M1, kind="shell", method="line-url-token", excerpt=f"fetch ({M1})")      # the rule's own pattern would take ')' into the token
        plain = ref("b.py", "https://h.example/n.onnx")
        out, rep, gen = run([wrapped, plain], doc=aibom([("r", "d", [M1])]))
        obs = {e["observation"]["artifact"]["locator"]: e["observation"] for e in out["evidence"] if e["observation"].get("kind") == "source_excerpt"}
        self.assertNotIn("string_literals", obs["b.py"])
        self.assertEqual(obs["a.sh"]["string_literals"], [M1])
        f = [x for x in findings(out).values() if x["state"] == "supported"]
        self.assertEqual(len(f), 1)


class IdsBoundsAndIsolationTest(unittest.TestCase):
    def test_all_generated_ids_are_hashes_without_repository_or_producer_text(self):
        evil = "/Users/me/../secret path"
        out, rep, gen = run([ref("my secret/dir/m.py", M1)], doc=aibom([("ok-ref", "x", [M1])]))
        text = json.dumps({k: [x[{"entities": "entity_id", "evidence": "evidence_id", "assertions": "assertion_id"}[k]] for x in out[k]] for k in ("entities", "evidence", "assertions")})
        self.assertNotIn("secret", text)
        self.assertNotIn("my secret", json.dumps([c["candidate_id"] for c in cands(out)]))

    def test_unrepresentable_or_duplicate_aibom_ids_omit_entities_but_keep_the_verdict(self):
        models = [("same", "a", [M1]), ("same", "b", ["https://x/y.onnx"])]
        out, rep, gen = run([ref("m.py", M1)], doc=aibom(models))
        self.assertEqual(rep["models"]["status"], "ok")
        self.assertEqual(gen.info["aibom_model_entities_omitted"], 2)
        [f] = findings(out).values()
        self.assertEqual(f["state"], "supported")
        bad = [("<script>", "a", [M1])]
        out, rep, gen = run([ref("m.py", M1)], doc=aibom(bad))
        self.assertEqual(gen.info["aibom_model_entities_omitted"], 1)

    def test_budget_truncation_is_a_deterministic_prefix_and_never_a_drop(self):
        refs = [ref("m.py", f"https://h.example/m{i:03d}.onnx", line=i + 1) for i in range(10)]
        out1, rep, gen = run(refs, budget=4, extra_options={"max_candidates": 4})
        out2, _, _ = run(list(reversed(refs)), extra_options={"max_candidates": 4})
        self.assertEqual((gen.info["groups_total"], gen.info["groups_shown"], gen.info["groups_truncated"]), (10, 4, 6))
        self.assertEqual(sorted(c["candidate_id"] for c in cands(out1)), sorted(c["candidate_id"] for c in cands(out2)))
        self.assertEqual(rep["models"]["status"], "ok")

    def test_the_budget_follows_the_remaining_aggregate_capacity(self):
        g = dm.ModelGenerator({"max_candidates": 500, "total_cap": 2000})
        self.assertEqual((g.budget_for(0), g.budget_for(1800), g.budget_for(1700), g.budget_for(2000), g.budget_for(5000)), (500, 200, 300, 0, 0))

    def test_zero_budget_yields_no_candidates_but_the_family_is_reported(self):
        out, rep, gen = run([ref("m.py", M1)], extra_options={"max_candidates": 0})
        self.assertEqual((cands(out), gen.info["groups_truncated"]), ([], 1))

    def test_candidate_id_collisions_are_avoided_deterministically(self):
        refs = [ref("m.py", f"https://h.example/m{i:04d}.onnx", line=i + 1) for i in range(300)]
        out, rep, gen = run(refs)
        ids = [c["candidate_id"] for c in cands(out)]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(rep["models"]["status"], "ok")

    def test_a_conflicting_record_under_one_id_discards_only_this_family(self):
        out, rep, gen = run([ref("m.py", M1)])
        b = bundle({"paths": ["."], "listing_sha256": "e" * 64, "revision": REV})
        clash = {"entity_id": "scope:t::inv:bombridge-discovery::model:" + dm.hashlib.sha256(M1.encode()).hexdigest()[:16], "kind": "model", "name": "other"}
        b["entities"].append(clash)
        doc = aibom()
        raw = json.dumps(doc, sort_keys=True).encode()
        gen2 = dm.ModelGenerator({"aibom": {"state": "usable", "inventory_id": "inv:cisco-aibom", "sha256": sha(raw), "doc": doc, "manifest": manifest(sha(raw)),
                                            "scan_scope": b["capture"]["inventories"][0]["scan_scope"], "inventories": 1}, "source_digests": {"m.py": "d" * 64}})
        report = {}
        sd = {"repository": b["capture"]["repository"]["url"], "revision": REV, "requirement_files": [], "model_references": [ref("m.py", M1)]}
        res = bb_discovery.discover(b, raw_inventories={}, source_declarations=sd, requirement_texts={}, requirements=False, extra_generators=(gen2,), generator_report=report)
        self.assertEqual((report["models"]["status"], report["models"]["code"]), ("failed", "id_collision"))
        self.assertEqual([c for c in res["discovery"]["candidates"] if c["group"].startswith("models:")], [])

    def test_session_exceptions_propagate_out_of_the_family_boundary(self):
        from unittest import mock

        class Stop(Exception):
            pass
        gen = dm.ModelGenerator({"aibom": {"state": "not_run"}})
        b = bundle({"paths": ["."]})
        sd = {"repository": b["capture"]["repository"]["url"], "revision": REV, "requirement_files": [], "model_references": [ref("m.py", M1)]}
        with mock.patch.object(dm.ModelGenerator, "__call__", side_effect=Stop()):
            with self.assertRaises(Stop):
                bb_discovery.discover(b, raw_inventories={}, source_declarations=sd, requirement_texts={}, requirements=False, extra_generators=(gen,), generator_report={}, propagate=(Stop,))

    def test_the_discovery_note_names_the_model_family_when_it_ran(self):
        out, rep, gen = run([ref("m.py", M1)])
        note = out["discovery"]["notes"][-1]
        self.assertIn("model references", note)
        self.assertNotIn("models, dependency edges", note)
        self.assertIn("model_references_vs_aibom", out["discovery"]["ported_scope"])


class CapturedFixturesTest(unittest.TestCase):
    """Captured inputs, expectations derived by the separately written oracle ``tools/uip13/fixture_oracle.py``."""

    def _captured(self, decl_path, bundle_path, scope_inputs=None):
        decl = json.loads(load(decl_path))
        cap = json.loads(load(bundle_path))
        inv = next(i for i in cap["capture"]["inventories"] if i["kind"] == "aibom")
        refs = []
        ordinals = {}
        for r in decl["model_references"]:
            key = (r["path"], r["lines"][0], r["lines"][1])
            o = ordinals.get(key, 0)
            ordinals[key] = o + 1
            kind = "python" if r["path"].endswith(".py") else "shell" if r["path"].endswith(".sh") else "dockerfile"
            rec = {"occurrence_id": dm._h16(*key, o, r["locator"]), "ordinal": o, "path": r["path"], "file_sha256": r["file_sha256"], "line": r["lines"][0], "end_line": r["lines"][1],
                   "source_kind": kind, "method": r["method"], "locator": r["locator"], "excerpt": r["excerpt"], "excerpt_truncated": False}
            if r["method"].endswith("joined-string-literals") and r.get("string_literal"):
                rec["string_literal"] = r["locator"]
            refs.append(rec)
        return decl, cap, inv, refs

    def _run(self, decl, cap, inv, refs, doc):
        raw = json.dumps(doc, sort_keys=True).encode()
        rev = cap["capture"]["repository"]["revision"]
        b = copy.deepcopy(cap)
        for k in ("entities", "evidence", "assertions"):
            b[k] = []
        b["capture"]["inventories"] = [dict(inv, source_sha256=sha(raw))]
        sc = inv["scan_scope"]
        inputs = [{"path": p, "sha256": "d" * 64} for p in sc["paths"]] if len(sc["paths"]) == sc["file_count"] else [{"path": f"f{i}", "sha256": "d" * 64} for i in range(sc["file_count"])]
        man = manifest(sha(raw), rev, inputs, b["capture"]["repository"]["url"])
        ai = {"state": "usable", "inventory_id": inv["inventory_id"], "sha256": sha(raw), "doc": doc, "manifest": man, "scan_scope": sc, "inventories": 1, "source_file": "cisco-aibom.cdx.json"}
        listing = {r["path"]: r["file_sha256"] for r in refs}      # fixture limitation: the whole-tree listing is derived from the captured records
        gen = dm.ModelGenerator({"aibom": ai, "source_digests": listing})
        sd = {"repository": b["capture"]["repository"]["url"], "revision": rev, "requirement_files": [], "model_references": refs}
        report = {}
        out = bb_discovery.discover(b, raw_inventories={}, source_declarations=sd, requirement_texts={}, requirements=False, extra_generators=(gen,), generator_report=report)
        return out, report, gen

    def test_frigate_captured_mixed_scope_and_basename_only_candidates(self):
        decl_path = os.path.join(FIX, "inputs", "frigate", "source-declarations.json")
        decl, cap, inv, refs = self._captured(decl_path, os.path.join(FIX, "bundles", "frigate-v0.18.2-cpu-pilot.json"), None)
        doc = json.loads(load(FIX, "inputs", "frigate", "raw", "cisco-aibom.cdx.json"))
        # the captured document names a local path in its bom-ref; the generator must shorten no producer text into ids
        scope_inputs = json.loads(load(FIX, "inputs", "frigate", "aibom-scope.json"))["files"]
        out, rep, gen = self._run(decl, cap, inv, refs, doc)
        want = oracle.expectations(decl, inv["scan_scope"]["paths"])
        self.assertEqual((want["occurrences"], want["groups"], len(want["compared"]), len(want["outside"])), (6, 5, 4, 1))
        by = {}
        for c in cands(out):
            by[c["detail"]["reason_code"]] = by.get(c["detail"]["reason_code"], 0) + 1
        self.assertEqual(by, {None: 4, "outside_aibom_scan_scope": 1})
        self.assertEqual(gen.info["compared"], len(want["compared"]))
        self.assertEqual(sum(1 for c in cands(out) if c["detail"]["reason_code"] == "outside_aibom_scan_scope"), len(want["outside"]))
        verdicts = {}
        for f in findings(out).values():
            verdicts[tuple(f["reason_codes"])] = verdicts.get(tuple(f["reason_codes"]), 0) + 1
        self.assertEqual(verdicts, {("no_matching_model_record",): 2, ("candidates_without_locator_match",): 2})
        self.assertNotIn("supported", [f["state"] for f in findings(out).values()])

    def test_viseron_captured_scope_with_a_synthetic_zero_model_document(self):
        decl_path = os.path.join(LIVE, "viseron", "donor-source-declarations.json")
        decl, cap, inv, refs = self._captured(decl_path, os.path.join(FIX, "bundles", "viseron-v3.7.0-hailo-detector.json"))
        out, rep, gen = self._run(decl, cap, inv, refs, aibom())
        want = oracle.expectations(decl, inv["scan_scope"]["paths"])
        self.assertEqual((want["occurrences"], want["groups"], len(want["compared"]), len(want["outside"])), (10, 9, 1, 8))
        self.assertEqual(gen.info["compared"], 1)
        self.assertEqual(sum(1 for c in cands(out) if c["detail"]["reason_code"] == "outside_aibom_scan_scope"), 8)
        [f] = findings(out).values()
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["no_matching_model_record"]))
        [cmp_c] = [c for c in cands(out) if c["assertion_id"]]
        self.assertEqual(cmp_c["detail"]["occurrences_in_scope"], 2)       # the same default URL repeated in const.py (donor: lines 8-9 and 12-13)


class CorrectionsR2Test(unittest.TestCase):
    def test_r2_09_scope_paths_are_normalised_for_matching(self):
        for forms in (["./pkg"], ["pkg/"], ["pkg"], ["./pkg/"]):
            with self.subTest(forms):
                scope = {"paths": forms, "listing_sha256": "e" * 64, "revision": REV, "tree_sha": "b" * 40, "file_count": 1}
                out, rep, gen = run([ref("pkg/m.py", M1)], doc=aibom([("r", "d", [M1])]), scope=scope)
                self.assertEqual(findings(out) and list(findings(out).values())[0]["state"], "supported")

    def test_r2_08_outside_scope_and_gate_failed_counts_are_separate(self):
        scope = {"paths": ["pkg"], "listing_sha256": "e" * 64, "revision": REV, "tree_sha": "b" * 40, "file_count": 1}
        refs = [ref("pkg/a.py", M1), ref("out/b.py", M1), ref("pkg/c.py", M1, fsha="1" * 64)]
        out, rep, gen = run(refs, doc=aibom([("r", "d", [M1])]), scope=scope, digests={"pkg/a.py": "d" * 64, "out/b.py": "d" * 64, "pkg/c.py": "2" * 64})
        [c] = cands(out)
        d = c["detail"]
        self.assertEqual((d["occurrences_in_scope"], d["occurrences_outside_scope"], d["occurrences_gate_failed"], d["occurrences_not_compared"]), (1, 1, 1, 2))


if __name__ == "__main__":
    unittest.main()
