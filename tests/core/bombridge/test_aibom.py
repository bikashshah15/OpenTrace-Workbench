"""AI-BOM intake and the declared_in_aibom rule. All inputs are SYNTHETIC / illustrative."""
import copy
import hashlib
import json
import pathlib
import unittest

from opentrace_core.bombridge.adapters import AibomError, aibom_document_observation
from opentrace_core.bombridge.acquisition import manifest_errors, resolve_binding
from opentrace_core.bombridge.aibom_bundle import aibom_records
from opentrace_core.bombridge.pipeline import canonical, run, run_doc

ROOT = pathlib.Path(__file__).resolve().parent / "fixtures"
RAW = ROOT / "fixtures/illustrative/synthetic-mlbom.cdx.json"
DEMO = ROOT / "bundles/aibom-link-demo.bundle.json"
EXPORT = ROOT / "exports/illustrative/aibom-link-demo.result.json"
FRIGATE = ROOT / "bundles/frigate-v0.18.2-cpu-pilot.json"
REV = "0123456789abcdef0123456789abcdef01234567"
S, INV = "scope:t", "inv:aibom"
URL = "https://models.example.invalid/unique.tflite"


def doc():
    return copy.deepcopy(json.loads(RAW.read_text()))


def sha(d):
    return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()


def manifest_for(d, revision=REV, differs=False, out_sha=None, repo="https://example.invalid/x"):
    return {"schema": "bombridge.acquisition/1", "repository": repo, "revision": revision,
            "inputs": [{"path": "docker/Dockerfile", "sha256": "a" * 64}], "tree_differs_from_revision": differs,
            "generator": {"name": "g", "version": "1", "invocation": "SYNTHETIC"}, "output_sha256": out_sha or sha(d), "limitations": ["SYNTHETIC"]}


def finding(d, locator=URL, source_files=("docker/Dockerfile",), revision=REV, excerpt=None, source=True, inventory_sha=None, manifest="auto"):
    """One synthetic link case: AI-BOM doc `d` vs a source reference stating `locator`."""
    man = manifest_for(d) if manifest == "auto" else manifest
    ents, ev, inv = aibom_records(d, sha(d), scope_id=S, inventory_id=INV, origin="illustrative", evidence_id="e-ai", source_file="x.json",
                                  manifest=man, repository_url="https://example.invalid/x")
    R = f"{S}::src::r"
    entities = ents + [{"entity_id": R, "kind": "model", "name": "r", "version": None, "source": {"inventory_id": "src", "source_ref": "r"},
                        "identity_matches": [], "artifact": {"class": "external_acquisition", "locators": [locator]}, "origin": "illustrative"}]
    evidence = [ev]
    if source:
        evidence.append({"evidence_id": "e-src", "scope_id": S, "method": "m", "tool": "t", "source_locator": "s", "scope": {"revision": REV}, "observes": [R],
                         "observation": {"kind": "source_excerpt", "artifact": {"locator": source_files[0]}, "lines": [1, 1],
                                         "excerpt": excerpt or f"RUN wget {locator}", "file_sha256": "0" * 64},
                         "limitations": [], "underlying_source": "src:file", "origin": "illustrative"})
    bundle = {"schema": "bombridge.bundle/2", "origin": "illustrative", "notice": "ILLUSTRATIVE",
              "capture": {"scope_id": S, "repository": {"url": "https://example.invalid/x", "revision": REV}, "build": None, "configuration": None, "model": None,
                          "execution": None, "unknown": ["build", "configuration", "model", "execution"], "unavailable": [], "inventories": [inv], "origin": "illustrative"},
              "entities": entities,
              "assertions": [{"assertion_id": "a", "family": "model_identity", "subject": R, "predicate": "declared_in_aibom",
                              "object": {"inventory_id": INV, "inventory_sha256": inventory_sha or sha(d)}, "declared_in": {"inventory_id": "src", "source_ref": "s"},
                              "scope_id": S, "scope": {"revision": revision}, "origin": "illustrative"}],
              "evidence": evidence}
    return run_doc(bundle)["findings"][0]


class Extraction(unittest.TestCase):
    def setUp(self):
        self.raw = doc()
        self.obs = aibom_document_observation(self.raw, "f" * 64)

    def test_document_producer_subject_and_models(self):
        o = self.obs
        self.assertEqual((o["status"], o["document"]["spec_version"], o["document"]["serial_number"]), ("ok", "1.6", "urn:uuid:00000000-0000-4000-8000-000000000001"))
        self.assertEqual(o["producer"], [{"name": "synthetic-aibom-generator", "version": "0.0", "vendor": "illustrative"}])
        self.assertEqual((o["subject"]["name"], o["subject"]["declared_revision"]["value"]), ("synthetic-subject", REV))
        self.assertEqual([m["bom_ref"] for m in o["models"]], ["model-unique", "model-samename", "model-dup-a", "model-dup-b"])
        self.assertEqual(o["counts"], {"components_total": 5, "models": 4, "by_type": {"library": 1, "machine-learning-model": 4}})
        self.assertEqual(o["coverage"], {"stated": False, "compositions": []})
        self.assertIn("the document states no coverage (no compositions)", o["limitations"])

    def test_original_references_and_hashes_are_preserved(self):
        m = self.obs["models"][0]
        self.assertEqual((m["raw_pointer"], m["bom_ref"], m["name"], m["version"]), ("/components/0", "model-unique", "unique-detector", "1"))
        self.assertEqual(m["external_references"], [{"type": "distribution", "url": URL}])
        self.assertEqual(m["locations"], [{"file": "docker/Dockerfile", "line": 10}])
        self.assertEqual(m["hashes"][0]["alg"], "SHA-256")  # original spelling kept
        self.assertEqual(m["hashes"][0]["normalized_algorithm"], "sha256")
        self.assertEqual(m["hashes"][0]["content"], self.raw["components"][0]["hashes"][0]["content"])
        self.assertNotIn("modelCard", json.dumps(self.obs))  # unknown fields stay only in the raw file
        self.assertEqual(hashlib.sha256(RAW.read_bytes()).hexdigest(), json.loads(DEMO.read_text())["capture"]["inventories"][0]["source_sha256"])

    def test_missing_pieces_become_explicit_limitations(self):
        d = doc()
        del d["metadata"]
        o = aibom_document_observation(d, "f" * 64)
        self.assertIsNone(o["subject"])
        self.assertTrue(any("no metadata.component" in x for x in o["limitations"]))
        self.assertTrue(any("declares no source revision" in x for x in o["limitations"]))
        self.assertTrue(any("model declares no hash" in x for x in o["limitations"]))  # model-samename
        d = doc()
        d["metadata"]["component"]["version"] = "1.2.3"  # a version is not a revision
        self.assertIsNone(aibom_document_observation(d, "f" * 64)["subject"]["declared_revision"])

    def test_unsupported_spec_version_extracts_nothing(self):
        d = doc()
        d["specVersion"] = "1.4"
        o = aibom_document_observation(d, "f" * 64)
        self.assertEqual((o["status"], o["models"]), ("unsupported", []))
        self.assertIn("1.4", o["limitations"][0])

    def test_malformed_input_fails_clearly(self):
        cases = []
        d = doc(); d["bomFormat"] = "SPDX"; cases.append((d, "bomFormat"))
        d = doc(); d["components"] = {"a": 1}; cases.append((d, "components must be a list"))
        d = doc(); del d["components"][0]["name"]; cases.append((d, "needs string 'type' and 'name'"))
        d = doc(); d["components"][0]["hashes"][0]["content"] = "xyz"; cases.append((d, "not hexadecimal"))
        d = doc(); d["components"][0]["hashes"][0]["content"] = "ab"; cases.append((d, "64 hexadecimal"))
        d = doc(); d["components"][0]["externalReferences"] = [{"type": "x"}]; cases.append((d, "string 'url'"))
        d = doc(); d["components"][0]["evidence"]["occurrences"] = [{"line": 3}]; cases.append((d, "string 'location'"))
        cases.append(([], "JSON object"))
        for bad, msg in cases:
            with self.assertRaises(AibomError) as cm:
                aibom_document_observation(bad, "f" * 64)
            self.assertIn(msg, str(cm.exception))


class Linking(unittest.TestCase):
    def test_unique_locator_match_supports_at_declaration_level_only(self):
        f = finding(doc())
        self.assertEqual((f["state"], f["category"], f["reason_codes"]), ("supported", "declaration_agreement", ["locator_equal_unique"]))
        self.assertEqual(f["layers"], {"declared_in_aibom": True, "referenced_by_source": True, "artifact_acquired_and_hashed": False, "observed_loading": False})
        self.assertIn("not artifact identity", f["bounded_meaning"])
        self.assertIn("digest verification", f["bounded_meaning"])

    def test_shared_source_is_not_presented_as_independent(self):
        f = finding(doc())
        self.assertEqual(f["shared_source_files"], ["docker/Dockerfile"])
        self.assertIn("not independent verification", f["provenance_note"])
        g = finding(doc(), source_files=("some/other/file",))
        self.assertEqual(g["shared_source_files"], [])
        self.assertIn("does not prove they are independent", g["provenance_note"])
        self.assertNotIn("independent_sources", json.dumps(f))

    def test_missing_model_digest_does_not_block_the_declaration(self):
        d = doc()
        d["components"][0]["hashes"] = []
        f = finding(d)
        self.assertEqual(f["state"], "supported")
        self.assertIn("declares no hash", f["digest_verification"])
        self.assertEqual(finding(doc())["digest_verification"], "not performed: no artifact was acquired or hashed")

    def test_same_basename_different_location_is_a_candidate_not_a_match(self):
        f = finding(doc(), locator="https://origin.example.invalid/models/samename.tflite")
        self.assertEqual((f["state"], f["reason_codes"], f["matched_model"]), ("unverifiable", ["candidates_without_locator_match"], None))
        self.assertEqual([(c["bom_ref"], c["match"], c["locators_differ"]) for c in f["candidates"]], [("model-samename", "basename_only", True)])

    def test_name_alone_never_links(self):
        d = doc()
        d["components"][0]["externalReferences"] = []  # named like the file, but states no locator
        d["components"][0]["name"] = "unique.tflite"
        f = finding(d, locator="https://elsewhere.example.invalid/unique.tflite")
        self.assertEqual((f["state"], f["matched_model"]), ("unverifiable", None))
        self.assertEqual(f["candidates"][0]["match"], "basename_only")

    def test_ambiguous_identity_is_kept_as_candidates(self):
        f = finding(doc(), locator="https://models.example.invalid/dup.tflite")
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["ambiguous_model_identity"]))
        self.assertEqual([c["bom_ref"] for c in f["candidates"]], ["model-dup-a", "model-dup-b"])
        self.assertIsNone(f["matched_model"])

    def test_missing_record_is_unverifiable_never_contradicted(self):
        f = finding(doc(), locator="https://models.example.invalid/absent.tflite")
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["no_matching_model_record"]))
        d = doc()
        d["compositions"] = [{"aggregate": "complete", "assemblies": ["model-unique"]}]  # a stated coverage is recorded, not trusted as a contract
        g = finding(d, locator="https://models.example.invalid/absent.tflite")
        self.assertEqual(g["state"], "unverifiable")

    def test_hash_shaped_version_without_acquisition_binding_is_only_a_declaration(self):
        f = finding(doc(), manifest=None)  # the document declares a 40-hex version; no manifest
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["no_compatible_aibom_document"]))
        self.assertEqual(f["excluded_evidence"][0]["reason_code"], "scope_missing")
        self.assertIn("a declared revision alone does not scope", f["excluded_evidence"][0]["detail"])
        obs = aibom_document_observation(doc(), "f" * 64)
        self.assertEqual(obs["subject"]["declared_revision"]["value"], REV)  # still preserved as a declaration
        b = resolve_binding(obs, None, "f" * 64)
        self.assertEqual((b["level"], b["revision"], b["declared"]), ("declared", None, REV))

    def test_recorded_binding_scopes_a_bom_that_omits_a_revision(self):
        d = doc()
        d["metadata"]["component"]["version"] = "1.0"  # BOM declares no revision
        f = finding(d)
        self.assertEqual(f["state"], "supported")
        b = resolve_binding(aibom_document_observation(d, sha(d)), manifest_for(d), sha(d), "https://example.invalid/x")
        self.assertEqual((b["level"], b["revision"], b["declared"], b["corroborated"]), ("recorded", REV, None, None))
        self.assertIn("not independently corroborated", b["notes"][0])

    def test_mismatched_output_digest_gives_no_binding(self):
        d = doc()
        f = finding(d, manifest=manifest_for(d, out_sha="9" * 64))
        self.assertEqual((f["state"], f["excluded_evidence"][0]["reason_code"]), ("unverifiable", "scope_missing"))
        self.assertIn("differs from the supplied BOM digest", f["excluded_evidence"][0]["detail"])

    def test_conflicting_declared_and_recorded_revisions_are_preserved(self):
        d = doc()  # declares REV
        other = "f" * 40
        f = finding(d, manifest=manifest_for(d, revision=other))
        self.assertEqual(f["state"], "unverifiable")
        self.assertIn("conflicts with recorded revision", f["excluded_evidence"][0]["detail"])
        b = resolve_binding(aibom_document_observation(d, sha(d)), manifest_for(d, revision=other), sha(d))
        self.assertEqual((b["level"], b["declared"], b["recorded"], b["revision"]), ("conflict", REV, other, None))

    def test_tree_differing_from_revision_is_a_conflict_and_incomplete_manifest_is_unusable(self):
        d = doc()
        b = resolve_binding(aibom_document_observation(d, sha(d)), manifest_for(d, differs=True), sha(d))
        self.assertEqual((b["level"], b["revision"]), ("conflict", None))
        bad = manifest_for(d)
        del bad["generator"]["invocation"]
        self.assertTrue(manifest_errors(bad))
        self.assertEqual(resolve_binding(aibom_document_observation(d, sha(d)), bad, sha(d))["revision"], None)
        self.assertIn("exact 40-hex", "; ".join(manifest_errors({**manifest_for(d), "revision": "main"})))

    def test_assertion_naming_another_document_digest_excludes_the_document(self):
        f = finding(doc(), inventory_sha="1" * 64)
        self.assertEqual((f["state"], f["excluded_evidence"][0]["reason_code"]), ("unverifiable", "inventory_binding_mismatch"))

    def test_source_reference_must_state_the_locator_as_a_whole_url(self):
        f = finding(doc(), excerpt=f"RUN wget {URL}.bak")  # longer URL: not the same token
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["source_reference_not_observed"]))
        self.assertEqual(finding(doc(), source=False)["reason_codes"], ["source_reference_not_observed"])

    def test_unsupported_document_is_inconclusive(self):
        d = doc()
        d["specVersion"] = "1.5"
        f = finding(d)
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["aibom_format_unsupported"]))


class DemoAndPilot(unittest.TestCase):
    def setUp(self):
        self.r = run(DEMO)

    def test_demo_cases(self):
        self.assertEqual({f["assertion_id"]: f["state"] for f in self.r["findings"]},
                         {"r1-declared-in-aibom": "supported", "r2-declared-in-aibom": "unverifiable", "r3-declared-in-aibom": "unverifiable", "r4-declared-in-aibom": "unverifiable"})

    def test_graph_connections_and_candidates(self):
        edges = {(e["from"].split("::")[-1], e["to"].split("::")[-1], e["type"]) for e in self.r["graph"]["edges"]}
        self.assertIn(("r1", "model-unique", "declared_as"), edges)
        self.assertIn(("r2", "model-samename", "candidate_match"), edges)
        self.assertIn(("r3", "model-dup-a", "candidate_match"), edges)
        self.assertIn(("r3", "model-dup-b", "candidate_match"), edges)
        self.assertFalse([e for e in edges if e[0] in ("r2", "r3") and e[2] == "declared_as"])
        self.assertFalse([e for e in edges if e[2] == "runtime" or "load" in e[2]])  # no model-to-runtime edge

    def test_illustrative_stays_out_of_real_results(self):
        self.assertEqual(self.r["summary"]["real"], {})
        self.assertIn("illustrative assertion vs illustrative evidence", self.r["summary"]["illustrative"])
        self.assertIn("ILLUSTRATIVE", self.r["notice"])
        real = run(FRIGATE)
        self.assertFalse([n for n in real["graph"]["nodes"] if n["type"] == "evidence" and n["observation"].get("kind") == "aibom_document" and n["origin"] != "captured"])
        self.assertNotIn("synthetic", json.dumps(real["graph"]["nodes"]))
        self.assertEqual(real["summary"]["illustrative"], {})


    def test_real_frigate_graph_ingests_the_actual_scan_without_overclaiming(self):
        real = run(FRIGATE)
        checks = {c["input"]: c for c in real["input_checks"]}
        self.assertEqual(checks["08-ai-bom"]["status"], "present_inspected")
        self.assertIn("one machine-learning-model", checks["08-ai-bom"]["detail"])
        self.assertNotIn("sk-", json.dumps(real))
        self.assertEqual(checks["15-existing-aibom-input"]["status"], "not_found_in_inspected_scope")
        self.assertTrue(checks["15-existing-aibom-input"]["searched"])
        docs = [n["observation"] for n in real["graph"]["nodes"] if n["type"] == "evidence" and n["observation"]["kind"] == "aibom_document"]
        self.assertEqual([(d["counts"]["models"], d["binding"]["level"]) for d in docs], [(1, "recorded")])
        self.assertEqual([m["name"] for m in docs[0]["models"]], ["yolov6n.hef"])
        p7 = next(f for f in real["findings"] if f["assertion_id"] == "p7-model-declared-in-aibom")
        self.assertEqual((p7["state"], p7["reason_codes"], p7["matched_model"]), ("unverifiable", ["no_matching_model_record"], None))
        p5 = next(f for f in real["findings"] if f["assertion_id"].startswith("p5"))
        self.assertEqual((p5["state"], p5["category"], p5["coverage_contract"]["established"]), ("contradicted", "inventory_coverage_gap", False))
        self.assertIn("does not show that other components of the inventory describe the revision", p5["bounded_meaning"])
        for aid in ("p1-model-acquired-from", "p2-detector-default-model", "p3-detector-uses-tflite-runtime"):
            self.assertEqual(next(f for f in real["findings"] if f["assertion_id"] == aid)["reason_codes"], ["rule_not_implemented"])


if __name__ == "__main__":
    unittest.main()
