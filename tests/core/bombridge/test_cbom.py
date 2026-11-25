"""Crypto inventory extractor, CBOM intake, the CBOM link rule, and the prepared AI-BOM scope. Synthetic unless stated."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import unittest

from opentrace_core.bombridge import cryptoscan
from opentrace_core.bombridge.adapters import AibomError, cbom_document_observation
from opentrace_core.bombridge.cbom_bundle import cbom_records
from opentrace_core.bombridge.pipeline import canonical, run, run_doc
from opentrace_core.bombridge.acquisition import manifest_errors

ROOT = pathlib.Path(__file__).resolve().parent / "fixtures"
PILOT = ROOT / "bundles/frigate-v0.18.2-cpu-pilot.json"
RAW = ROOT / "inputs/frigate/raw/cdxgen-cbom.cdx.json"
HISTORICAL = ROOT / "inputs/frigate/raw/bombridge-crypto-inventory.cdx.json"
REV = "0123456789abcdef0123456789abcdef01234567"
S, INV = "scope:c", "inv:cbom"
FILE = "pkg/model.py"


def sites(text):
    s, o, e = cryptoscan.scan_source("x.py", text)
    return s, o, e


class Extractor(unittest.TestCase):
    def test_finds_module_attribute_alias_and_from_import_calls(self):
        s, _, _ = sites("import hashlib as h\nfrom hashlib import sha256 as sx, new\n\nclass A:\n    def f(self):\n        h.md5(b'')\n        sx()\n        new('SHA-1')\n")
        self.assertEqual([(x["algorithm"], x["line"], x["context"]) for x in s], [("md5", 6, "A.f"), ("sha256", 7, "A.f"), ("sha1", 8, "A.f")])

    def test_pbkdf2_and_scrypt_and_usedforsecurity(self):
        s, _, _ = sites("import hashlib\nhashlib.pbkdf2_hmac('sha256', b'', b'', 1)\nhashlib.scrypt(b'')\nhashlib.md5(usedforsecurity=False)\n")
        self.assertEqual([x["algorithm"] for x in s], ["sha256", "scrypt", "md5"])
        self.assertIs(s[2]["usedforsecurity"], False)

    def test_dynamic_algorithm_is_unresolved_not_guessed(self):
        s, _, _ = sites("import hashlib\nname = 'md5'\nhashlib.new(name)\n")
        self.assertEqual((s[0]["algorithm"], s[0]["algorithm_resolved"]), (None, False))

    def test_only_hashlib_is_inventoried_other_crypto_imports_are_noted_not_inventoried(self):
        s, o, _ = sites("import ssl, secrets\nfrom cryptography.hazmat.primitives import serialization\nimport mylib\nmylib.md5(b'')\nssl.create_default_context()\n")
        self.assertEqual(s, [])
        self.assertEqual(sorted(x["module"] for x in o), ["cryptography.hazmat.primitives", "secrets", "ssl"])

    def test_unrelated_names_do_not_match(self):
        s, _, _ = sites("import hashlib\nclass K:\n    def md5(self): pass\nK().md5()\nmd5 = 3\n")
        self.assertEqual(s, [])

    def test_syntax_errors_are_reported_not_skipped_silently(self):
        c = cryptoscan.build_cbom({"a.py": "def (:", "b.py": "import hashlib\nhashlib.md5()\n"}, "r", REV, "0" * 64)
        props = {p["name"]: p["value"] for p in c["metadata"]["properties"]}
        self.assertEqual(json.loads(props["bombridge:parse-errors"])[0]["file"], "a.py")
        self.assertEqual(props["bombridge:files-parsed"], "1")

    def test_output_is_labeled_incomplete_and_deterministic(self):
        files = {"b.py": "import hashlib\nhashlib.sha256()\n", "a.py": "import hashlib\nhashlib.md5()\n"}
        c1, c2 = cryptoscan.build_cbom(files, "r", REV, "0" * 64), cryptoscan.build_cbom(dict(reversed(list(files.items()))), "r", REV, "0" * 64)
        self.assertEqual(json.dumps(c1, sort_keys=True), json.dumps(c2, sort_keys=True))
        self.assertEqual(c1["metadata"]["tools"]["components"][0]["name"], "BOMBridge experimental source-derived crypto inventory")
        self.assertEqual(c1["compositions"][0]["aggregate"], "incomplete")
        self.assertEqual([c["name"] for c in c1["components"]], ["md5", "sha256"])
        self.assertEqual(c1["components"][0]["cryptoProperties"]["oid"], "2.16.840.1.113549.2.5")



def cdoc(occ_line=10, file=FILE, alg="md5", extra=None, spec="1.6"):
    d = {"bomFormat": "CycloneDX", "specVersion": spec, "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000009", "version": 1,
         "metadata": {"tools": {"components": [{"type": "application", "name": cryptoscan.LABEL, "version": "0", "author": "x"}]},
                      "component": {"type": "application", "bom-ref": "s", "name": "subject", "version": REV},
                      "properties": [{"name": "bombridge:label", "value": cryptoscan.LABEL}, {"name": "other", "value": "dropped"}]},
         "components": [{"type": "cryptographic-asset", "bom-ref": f"crypto/algorithm/{alg}", "name": alg,
                         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
                         "evidence": {"occurrences": [{"location": file, "line": occ_line, "offset": 4, "additionalContext": "hashlib.md5 in f"}] + (extra or [])}}],
         "compositions": [{"aggregate": "incomplete", "assemblies": [f"crypto/algorithm/{alg}"]}]}
    return d


def sha(d):
    return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()


def manifest(d, third_party=False):
    return {"schema": "bombridge.acquisition/1", "repository": "https://example.invalid/x", "revision": REV, "inputs": [{"path": FILE, "sha256": "a" * 64}],
            "tree_differs_from_revision": False, "generator": {"name": "g", "version": "1", "invocation": "SYNTHETIC", "third_party": third_party},
            "output_sha256": sha(d), "limitations": ["SYNTHETIC"]}


def finding(d, lines=(9, 11), alg="md5", file=FILE, man="auto", excerpt=None, inv_sha=None, source=True, producer=None):
    man = manifest(d) if man == "auto" else man
    ents, ev, inv = cbom_records(d, sha(d), scope_id=S, inventory_id=INV, origin="illustrative", evidence_id="e-cbom", source_file="x.json", manifest=man, repository_url="https://example.invalid/x")
    subj = f"{S}::src::loc"
    entities = ents + [{"entity_id": subj, "kind": "code_location", "name": "f", "version": None, "source": {"inventory_id": "src", "source_ref": "loc"}, "identity_matches": [], "origin": "illustrative"}]
    evidence = [ev]
    if source:
        evidence.append({"evidence_id": "e-src", "scope_id": S, "method": "m", "tool": "t", "source_locator": file, "scope": {"revision": REV}, "observes": [subj],
                         "observation": {"kind": "source_excerpt", "artifact": {"locator": file}, "lines": list(lines), "excerpt": excerpt or f"h = hashlib.{alg}()", "file_sha256": "0" * 64},
                         "limitations": [], "underlying_source": "src:file", "origin": "illustrative"})
    bundle = {"schema": "bombridge.bundle/2", "origin": "illustrative", "notice": "ILLUSTRATIVE",
              "capture": {"scope_id": S, "repository": {"url": "https://example.invalid/x", "revision": REV}, "build": None, "configuration": None, "model": None, "execution": None,
                          "unknown": ["build", "configuration", "model", "execution"], "unavailable": [], "inventories": [inv], "origin": "illustrative"},
              "entities": entities,
              "assertions": [{"assertion_id": "a", "family": "crypto_attribution", "subject": subj, "predicate": "operation_declared_in_cbom",
                              "object": {"inventory_id": INV, "inventory_sha256": inv_sha or sha(d), "algorithm": alg, "file": file, **({"producer": producer} if producer else {})}, "declared_in": {"inventory_id": "src", "source_ref": "s"},
                              "scope_id": S, "scope": {"revision": REV}, "origin": "illustrative"}], "evidence": evidence}
    return run_doc(bundle)["findings"][0]


class CbomIntake(unittest.TestCase):
    def test_extraction_and_preservation(self):
        o = cbom_document_observation(cdoc(), "f" * 64)
        a = o["assets"][0]
        self.assertEqual((o["status"], a["bom_ref"], a["name"], a["algorithm"], a["primitive"], a["raw_pointer"]), ("ok", "crypto/algorithm/md5", "md5", "md5", "hash", "/components/0"))
        self.assertEqual(a["occurrences"], [{"file": FILE, "line": 10, "offset": 4, "context": "hashlib.md5 in f"}])
        self.assertEqual(o["extractor_notes"], {"bombridge:label": cryptoscan.LABEL})  # only bombridge:* properties are read
        self.assertIn("the document itself states that its coverage is incomplete or unknown", o["limitations"])
        self.assertEqual(o["subject"]["declared_revision"]["value"], REV)

    def test_unsupported_and_malformed(self):
        self.assertEqual(cbom_document_observation(cdoc(spec="1.4"), "f" * 64)["assets"], [])
        d = cdoc(); d["bomFormat"] = "x"
        with self.assertRaises(AibomError):
            cbom_document_observation(d, "f" * 64)
        d = cdoc(); d["components"][0]["evidence"]["occurrences"] = [{"line": 1}]
        with self.assertRaises(AibomError):
            cbom_document_observation(d, "f" * 64)


class CbomRule(unittest.TestCase):
    def test_unique_call_site_in_range_supports_at_declaration_level_with_explicit_limits(self):
        f = finding(cdoc())
        self.assertEqual((f["state"], f["category"], f["reason_codes"]), ("supported", "declaration_agreement", ["call_site_in_range_unique"]))
        self.assertEqual(f["layers"], {"library_mentioned": False, "algorithm_record": True, "matching_call_site": True, "referenced_by_source": True, "integrity_verification": False, "runtime_execution": False})
        self.assertIn("integrity verification of any artifact", f["not_established"])
        self.assertIn("that the algorithm is a vulnerability here", f["not_established"])
        self.assertIn("protection of the model by any TLS or other crypto component", f["not_established"])

    def test_shared_source_and_own_generator_are_not_independent_confirmation(self):
        f = finding(cdoc())
        self.assertEqual(f["shared_source_files"], [FILE])
        self.assertIn("not independent verification", f["provenance_note"])
        self.assertIn("own experimental extractor", f["provenance_note"])
        g = finding(cdoc(), man={**manifest(cdoc()), "generator": {"name": "g", "version": "1", "invocation": "x", "third_party": True}})
        self.assertNotIn("own experimental extractor", g["provenance_note"])

    def test_call_site_outside_the_observed_range_is_only_a_candidate(self):
        f = finding(cdoc(occ_line=50))
        self.assertEqual((f["state"], f["reason_codes"], f["matched_asset"]), ("unverifiable", ["call_sites_elsewhere_in_file"], None))
        self.assertEqual(f["candidates"][0]["match"], "same_file_other_line")

    def test_other_call_site_does_not_hide_the_matching_one(self):
        f = finding(cdoc(extra=[{"location": FILE, "line": 50, "additionalContext": "other"}]))
        self.assertEqual(f["state"], "supported")
        self.assertEqual(sorted(c["match"] for c in f["candidates"]), ["location_in_range", "same_file_other_line"])

    def test_two_call_sites_in_range_are_ambiguous(self):
        f = finding(cdoc(extra=[{"location": FILE, "line": 11, "additionalContext": "second"}]))
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["multiple_call_sites_in_range"]))

    def test_different_algorithm_or_file_never_contradicts(self):
        f = finding(cdoc(alg="sha256"))
        self.assertEqual((f["state"], f["reason_codes"], f["layers"]["algorithm_record"]), ("unverifiable", ["no_algorithm_record"], False))
        f = finding(cdoc(file="other.py"))  # an md5 record exists, but its only location is another file
        self.assertEqual((f["state"], f["reason_codes"], f["layers"]["algorithm_record"], f["layers"]["matching_call_site"]), ("unverifiable", ["algorithm_record_without_matching_location"], True, False))

    def test_algorithm_record_without_location_cannot_support_a_call_site_claim(self):
        d = cdoc()
        d["components"][0]["evidence"] = {"occurrences": []}  # algorithm-only evidence: the algorithm is recorded, no source location
        f = finding(d)
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["algorithm_record_without_matching_location"]))
        self.assertEqual((f["layers"]["algorithm_record"], f["layers"]["matching_call_site"], f["matched_asset"]), (True, False, None))
        self.assertIn("cannot support a call-site claim", f["rationale"])
        d["components"][0]["evidence"] = {}
        self.assertEqual(finding(d)["state"], "unverifiable")

    def test_library_mention_is_neither_an_algorithm_record_nor_a_call_site(self):
        d = cdoc(); d["components"] = [{"type": "library", "name": "cryptography", "version": "1", "purl": "pkg:pypi/cryptography@1"}]
        f = finding(d)
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["library_mention_only"]))
        self.assertEqual((f["layers"]["library_mentioned"], f["layers"]["algorithm_record"], f["layers"]["matching_call_site"]), (True, False, False))

    def test_zero_asset_document_is_a_successful_unverifiable_result_never_a_contradiction(self):
        d = cdoc(); d["components"] = []; d["services"] = [{"name": "svc", "endpoints": ["/x"]}]
        o = cbom_document_observation(d, "f" * 64)
        self.assertEqual((o["status"], o["counts"]["assets"], o["counts"]["services"]), ("ok", 0, 1))
        f = finding(d)
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["no_algorithm_record"]))
        self.assertIn("0 cryptographic asset(s) and 1 service record(s)", f["rationale"])

    def test_assertion_bound_to_one_producer_version_excludes_other_producers(self):
        d = cdoc()
        d["metadata"]["tools"] = {"components": [{"type": "application", "name": "cdxgen", "version": "12.9.0"}]}
        self.assertEqual(finding(d, producer={"name": "cdxgen", "version": "12.9.0"})["state"], "supported")
        for other in ({"name": "cdxgen", "version": "12.8.0"}, {"name": cryptoscan.LABEL, "version": "0"}):
            f = finding(d, producer=other)
            self.assertEqual(f["state"], "unverifiable")
            self.assertEqual([x["reason_code"] for x in f["excluded_evidence"]], ["producer_binding_mismatch"])

    def test_unbound_document_cannot_support(self):
        f = finding(cdoc(), man=None)
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["no_compatible_cbom_document"]))
        self.assertIn("a declared revision alone does not scope", f["excluded_evidence"][0]["detail"])

    def test_manifest_for_another_output_or_other_inventory_is_excluded(self):
        d = cdoc()
        self.assertEqual(finding(d, man=manifest(d) | {"output_sha256": "9" * 64})["state"], "unverifiable")
        self.assertEqual(finding(d, inv_sha="1" * 64)["excluded_evidence"][0]["reason_code"], "inventory_binding_mismatch")

    def test_source_excerpt_must_show_the_algorithm_at_the_file(self):
        self.assertEqual(finding(cdoc(), excerpt="x = compute()")["reason_codes"], ["source_location_not_observed"])
        self.assertEqual(finding(cdoc(), source=False)["reason_codes"], ["source_location_not_observed"])


class RealPilot(unittest.TestCase):
    def setUp(self):
        self.r = run(PILOT)

    def test_p8_cdxgen_has_no_md5_record_so_the_call_site_claim_is_unverifiable(self):
        p8 = next(f for f in self.r["findings"] if f["assertion_id"] == "p8-md5-call-represented-in-cdxgen-cbom")
        self.assertEqual((p8["state"], p8["reason_codes"], p8["matched_asset"], p8["rule_id"]), ("unverifiable", ["no_algorithm_record"], None, "crypto_attribution.operation_declared_in_cbom/2"))
        self.assertEqual(p8["layers"], {"library_mentioned": False, "algorithm_record": False, "matching_call_site": False, "referenced_by_source": True,
                                        "integrity_verification": False, "runtime_execution": False})
        self.assertEqual(sorted(u["evidence_id"] for u in p8["used_evidence"]), ["ev10-md5-model-hash", "ev20-cdxgen-cbom"])  # source observation kept as comparison evidence
        a = next(n for n in self.r["graph"]["nodes"] if n["id"] == "assertion:p8-md5-call-represented-in-cdxgen-cbom")
        self.assertEqual(a["object"]["producer"], {"name": "cdxgen", "version": "12.9.0"})
        p4 = next(f for f in self.r["findings"] if f["assertion_id"] == "p4-model-hashed-with-md5")
        self.assertEqual(p4["reason_codes"], ["rule_not_implemented"])  # a call site would not establish what is hashed
        p5 = next(f for f in self.r["findings"] if f["assertion_id"].startswith("p5"))
        self.assertEqual((p5["state"], p5["category"]), ("contradicted", "inventory_coverage_gap"))  # original finding preserved

    def test_active_graph_has_exactly_three_inventory_producers_and_nothing_from_the_historical_extractor(self):
        gens = {i["inventory_id"]: i["generator"] for i in self.r["capture"]["inventories"] if i["kind"] in ("sbom", "cbom", "aibom")}
        self.assertEqual(gens, {"inv:syft-source-dir": "syft 1.51.1", "inv:cdxgen-cbom": "cdxgen 12.9.0", "inv:cisco-aibom": "cisco-aibom 1.10.0"})
        text = json.dumps(self.r)
        for gone in ("bombridge-crypto", "p6-md5-call-declared-in-cbom", "cryptoscan", "crypto/algorithm/md5", "own experimental extractor", "hashlib call sites in frigate"):
            self.assertNotIn(gone, text)
        self.assertEqual([k for k in self.r["summary"]["real"]], ["curated assertion vs captured evidence", "curated assertion vs no used evidence"])
        self.assertTrue(HISTORICAL.exists())  # kept as historical research data, outside the active graph

    def test_cdxgen_document_is_a_successful_scan_with_zero_crypto_assets(self):
        inv = next(i for i in self.r["capture"]["inventories"] if i["inventory_id"] == "inv:cdxgen-cbom")
        self.assertTrue(inv["third_party_generator"])
        self.assertEqual(inv["source_sha256"], hashlib.sha256(RAW.read_bytes()).hexdigest())
        doc = next(n for n in self.r["graph"]["nodes"] if n["id"] == "evidence:ev20-cdxgen-cbom")["observation"]
        self.assertEqual((doc["status"], doc["document"]["spec_version"], doc["counts"]["components_total"], doc["counts"]["assets"], doc["counts"]["services"]), ("ok", "1.6", 0, 0, 13))
        self.assertEqual((doc["binding"]["level"], doc["acquisition_outcome"]["status"], doc["acquisition_outcome"]["exit_code"]), ("recorded", "completed", 0))
        self.assertEqual(doc["producer"][0]["version"], "12.9.0")
        self.assertIn("successful document with zero crypto assets", " ".join(doc["limitations"]))
        self.assertNotIn("md5", RAW.read_text().lower())  # the raw capture itself says nothing about md5

    def test_historical_extractor_capture_is_preserved_unchanged(self):
        self.assertEqual(hashlib.sha256(HISTORICAL.read_bytes()).hexdigest(), "edfa6416934747756024139b6f8b7fe905cea502a20e798e2f4b597e59ee06a9")

    def test_ai_bom_is_the_real_scan_output_bound_by_manifest(self):
        docs = [n["observation"] for n in self.r["graph"]["nodes"] if n["type"] == "evidence" and n["observation"]["kind"] == "aibom_document"]
        self.assertEqual(len(docs), 1)
        raw = ROOT / "inputs/frigate/raw/cisco-aibom.cdx.json"
        self.assertEqual(docs[0]["document"]["raw_sha256"], hashlib.sha256(raw.read_bytes()).hexdigest())
        self.assertEqual(next(c for c in self.r["input_checks"] if c["input"] == "08-ai-bom")["status"], "present_inspected")

    def test_deterministic_export(self):
        self.assertEqual(canonical(run(PILOT)), canonical(run(PILOT)))
        self.assertEqual(canonical(run(PILOT)), (ROOT / "exports/frigate/frigate-v0.18.2-cpu-pilot.result.json").read_text())

    def test_historical_crypto_manifest_still_matches_its_preserved_capture(self):
        m = json.loads((ROOT / "inputs/frigate/crypto-acquisition.json").read_text())
        self.assertEqual(manifest_errors(m), [])
        self.assertIs(m["generator"]["third_party"], False)
        self.assertEqual(m["output_sha256"], hashlib.sha256(HISTORICAL.read_bytes()).hexdigest())

    def test_cdxgen_manifest_is_valid_and_records_the_actual_command_and_outcome(self):
        m = json.loads((ROOT / "inputs/frigate/cdxgen-acquisition.json").read_text())
        self.assertEqual(manifest_errors(m), [])
        self.assertIs(m["generator"]["third_party"], True)
        self.assertEqual((m["generator"]["name"], m["generator"]["version"]), ("cdxgen", "12.9.0"))
        self.assertIn("--no-install-deps", m["generator"]["invocation"])
        self.assertIn("deny network", m["generator"]["invocation"])
        self.assertEqual(m["output_sha256"], hashlib.sha256(RAW.read_bytes()).hexdigest())
        self.assertEqual((m["revision"], m["tree_differs_from_revision"]), ("cfa08c56b23d23280c3d0a218e5a43182c97445b", False))
        paths = {i["path"] for i in m["inputs"]}
        self.assertTrue({"frigate/detectors/detector_config.py", "frigate/api/auth.py"} <= paths)
        self.assertEqual((m["outcome"]["status"], m["outcome"]["cryptographic_assets"], m["outcome"]["warnings_in_log"]), ("completed", 0, []))
        self.assertIn("Python source-level algorithm inventory is not documented", m["documented_coverage"]["statement"])


class PreparedAibomScope(unittest.TestCase):
    def setUp(self):
        self.s = json.loads((ROOT / "inputs/frigate/aibom-scope.json").read_text())

    def test_scope_record_is_consistent_and_bounded(self):
        self.assertEqual(self.s["revision"], "cfa08c56b23d23280c3d0a218e5a43182c97445b")
        self.assertEqual(self.s["file_count"], len(self.s["files"]))
        self.assertTrue(all(f["path"].split("/")[0] + "/" + f["path"].split("/")[1] in ("frigate/detectors", "frigate/config", "docker/main") for f in self.s["files"]))
        self.assertFalse([f for f in self.s["files"] if pathlib.PurePosixPath(f["path"]).name.startswith(".")])
        entries = json.dumps([{"path": f["path"], "sha256": f["sha256"], "bytes": f["bytes"]} for f in self.s["files"]], sort_keys=True, separators=(",", ":"))
        self.assertEqual(hashlib.sha256(entries.encode()).hexdigest(), self.s["listing_sha256"])
        self.assertEqual(self.s["transformations"], "none")



if __name__ == "__main__":
    unittest.main()
