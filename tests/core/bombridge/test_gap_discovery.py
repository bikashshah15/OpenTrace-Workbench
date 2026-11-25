"""I8: the ported BOMBridge gap discovery over the recorded Frigate inputs (engine level; no server, no network).

The expected values are the donor's own committed discovery export (Peiran Shi's overlay) reduced to the requirement path that
I8 ports (``fixtures/exports/frigate/*.discovery.requirements.oracle.json``). They were produced by the donor, not by OpenTrace.
"""
import copy
import hashlib
import json
import pathlib
import unittest

from opentrace_core.bombridge import adapters, discovery, pipeline

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
FRIGATE = json.loads((FIXTURES / "bundles/frigate-v0.18.2-cpu-pilot.json").read_text())
SBOM_ID = "inv:syft-source-dir"
SBOM_BYTES = (FIXTURES / "inputs/frigate/raw/syft-source-dir.cdx.json").read_bytes()
DECL_PATH = FIXTURES / "inputs/frigate/source-declarations.json"
DECL_BYTES = DECL_PATH.read_bytes()
DECL_SHA = "aada73d87aebbba9f0f65a61d09549b921f5bf8b7c3fbe0e5b510168bc24185c"
ORACLE = json.loads((FIXTURES / "exports/frigate/frigate-v0.18.2-cpu-pilot.discovery.requirements.oracle.json").read_text())
TFLITE_ID = "cand:missing_component:88eb4e77"


def read_copy(path):
    return (FIXTURES / "inputs/frigate/raw/source" / path).read_bytes()


def inputs(bundle=FRIGATE, declarations=DECL_BYTES, sha=DECL_SHA, copies=read_copy, sbom=SBOM_BYTES):
    sd, texts = discovery.read_declarations(bundle, declarations, expected_sha256=sha, read_copy=copies)
    inv = next(i for i in bundle["capture"]["inventories"] if i["inventory_id"] == SBOM_ID)
    return dict(raw_inventories={SBOM_ID: {"doc": json.loads(sbom), "sha256": inv["source_sha256"]}}, source_declarations=sd, requirement_texts=texts)


def run(bundle=FRIGATE, **kw):
    found = discovery.discover(bundle, **inputs(bundle, **kw))
    return found, pipeline.run_doc(found)


class RecordedCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle, cls.result = run()
        cls.cands = {c["candidate_id"]: c for c in cls.result["discovery"]["candidates"]}

    def test_inputs_are_the_pinned_captures(self):
        self.assertEqual(hashlib.sha256(DECL_BYTES).hexdigest(), DECL_SHA)
        inv = next(i for i in FRIGATE["capture"]["inventories"] if i["inventory_id"] == SBOM_ID)
        self.assertEqual(hashlib.sha256(SBOM_BYTES).hexdigest(), inv["source_sha256"])

    def test_candidates_and_verdicts_equal_the_donor_export(self):
        got = sorted(({"candidate_id": c["candidate_id"], "category": c["category"], "group": c["group"], "assertion_id": c["assertion_id"],
                       "state": (c["finding"] or {}).get("state"), "rule_id": (c["finding"] or {}).get("rule_id"),
                       "reason_codes": (c["finding"] or {}).get("reason_codes"), "evidence_location": c["evidence_location"]}
                      for c in self.result["discovery"]["candidates"]), key=lambda x: x["candidate_id"])
        self.assertEqual(got, ORACLE["candidates"])
        self.assertEqual((len(got), sum(x["state"] == "contradicted" for x in got), sum(x["category"] == "unknown_coverage" for x in got)), (79, 69, 10))

    def test_tflite_runtime_is_a_contradicted_inventory_coverage_gap(self):
        c = self.cands[TFLITE_ID]
        self.assertEqual((c["category"], c["evidence_location"], c["selected_inventory"]), ("missing_component", "docker/main/requirements-wheels.txt:75,76", SBOM_ID))
        self.assertIn("tflite_runtime (direct_url)", c["title"])
        f = c["finding"]
        self.assertEqual((f["state"], f["rule_id"], f["category"], f["reason_codes"]),
                         ("contradicted", "inventory_coverage.requirement_represented/1", "inventory_coverage_gap", ["not_represented_in_fully_parsed_inventory"]))
        self.assertEqual(sorted(c["evidence_ids"]), ["ev09-syft-lookup-tflite-runtime", "ev14-requirements-declaration-tflite-runtime"])

    def test_the_engine_generates_the_gap_without_the_curated_records(self):
        """Remove the curated tflite_runtime assertion, entity and evidence: discovery must regenerate the candidate itself, with its own
        declaration and lookup records, and the unchanged rule reaches the same verdict on them."""
        b = copy.deepcopy(FRIGATE)
        drop_ev = {"ev09-syft-lookup-tflite-runtime", "ev14-requirements-declaration-tflite-runtime"}
        b["assertions"] = [a for a in b["assertions"] if a["assertion_id"] != "p5-requirement-represented-in-inventory"]
        b["evidence"] = [e for e in b["evidence"] if e["evidence_id"] not in drop_ev]
        for e in b["entities"]:
            if e.get("requirement", {}).get("normalized_name") == "tflite-runtime":
                e["requirement"] = None
        for e in b["evidence"]:
            e["observes"] = [o for o in e.get("observes", []) if "tflite" not in o]
        b["entities"] = [e for e in b["entities"] if "req-tflite-runtime" not in e["entity_id"]]
        for a in b["assertions"]:
            a.pop("title", None)
        found, res = run(b)
        c = next(x for x in res["discovery"]["candidates"] if "tflite_runtime" in x["title"])
        self.assertTrue(c["assertion_id"].startswith("dreq-tflite-runtime-"))
        self.assertTrue(all(e.startswith(("dev-decl-", "dev-look-")) for e in c["evidence_ids"]), c["evidence_ids"])
        self.assertEqual(c["candidate_id"], TFLITE_ID)
        self.assertEqual((c["finding"]["state"], c["finding"]["rule_id"]), ("contradicted", "inventory_coverage.requirement_represented/1"))
        decl = next(e for e in found["evidence"] if e["evidence_id"] == next(i for i in c["evidence_ids"] if i.startswith("dev-decl-")))
        self.assertEqual(decl["observation"]["declarations"][0]["line"], 75)
        self.assertEqual(decl["observation"]["declarations"][0]["form"], "direct_url")

    def test_rule_ids_are_only_the_existing_inventory_rule_for_discovered_assertions(self):
        ids = {f["rule_id"] for f in self.result["findings"] if f["assertion_id"] in set(self.result["discovery"]["verification_assertions"])}
        self.assertEqual(ids, {"inventory_coverage.requirement_represented/1"})
        self.assertEqual([r["rule_id"] for r in self.result["rules"]], [
            "model_identity.digest/2", "inventory_coverage.requirement_represented/1", "crypto_attribution.operation_declared_in_cbom/2", "model_identity.declared_in_aibom/1"])

    def test_curated_findings_are_unchanged_by_discovery(self):
        legacy = pipeline.run_doc(FRIGATE)
        for f in legacy["findings"]:
            same = next(x for x in self.result["findings"] if x["assertion_id"] == f["assertion_id"])
            self.assertEqual({k: v for k, v in same.items() if k != "evaluation"}, {k: v for k, v in f.items() if k != "evaluation"}, f["assertion_id"])
        self.assertNotIn("discovery", legacy)  # a bundle without the section keeps its output byte-for-byte

    def test_deterministic_and_input_bundle_unmodified(self):
        before = json.dumps(FRIGATE, sort_keys=True)
        again = run()[1]
        self.assertEqual(pipeline.canonical(again), pipeline.canonical(self.result))
        self.assertEqual(json.dumps(FRIGATE, sort_keys=True), before)


class MissingOrMismatchedInputs(unittest.TestCase):
    """A missing or mismatched capture input is a labeled coverage state or a typed refusal; it is never a contradiction."""

    def test_declarations_with_the_wrong_digest_are_refused(self):
        with self.assertRaises(discovery.InputError) as cm:
            inputs(sha="0" * 64)
        self.assertEqual(cm.exception.code, "declarations_digest_mismatch")
        with self.assertRaises(discovery.InputError) as cm:
            inputs(declarations=DECL_BYTES + b" ")
        self.assertEqual(cm.exception.code, "declarations_digest_mismatch")

    def test_declarations_for_another_revision_or_repository_are_refused(self):
        for key, value in (("revision", "0" * 40), ("repository", "https://github.com/example/other")):
            sd = json.loads(DECL_BYTES)
            sd[key] = value
            data = json.dumps(sd).encode()
            with self.assertRaises(discovery.InputError) as cm:
                inputs(declarations=data, sha=hashlib.sha256(data).hexdigest())
            self.assertEqual(cm.exception.code, "declarations_scope_mismatch", key)

    def test_malformed_or_unsupported_declarations_are_refused(self):
        for data in (b"not json", json.dumps({"schema": "other/1", "requirement_files": []}).encode(), json.dumps({"schema": discovery.DECLARATIONS_SCHEMA, "requirement_files": "x"}).encode()):
            with self.assertRaises(discovery.InputError) as cm:
                inputs(declarations=data, sha=hashlib.sha256(data).hexdigest())
            self.assertEqual(cm.exception.code, "declarations_invalid")

    def test_discover_itself_refuses_a_foreign_revision(self):
        kw = inputs()
        kw["source_declarations"] = dict(kw["source_declarations"], revision="1" * 40)
        with self.assertRaises(discovery.InputError):
            discovery.discover(FRIGATE, **kw)

    def test_a_changed_or_missing_requirement_copy_is_unknown_coverage_for_that_file_only(self):
        target = "docker/main/requirements-wheels.txt"

        def changed(path):
            data = read_copy(path)
            return data + b"\n# edited\n" if path == target else data

        def missing(path):
            if path == target:
                raise OSError("gone")
            return read_copy(path)
        base = run()[1]["discovery"]["candidates"]
        compared = lambda cs: [c for c in cs if c["group"].endswith(target) and not c["group"] == "requirements:" + target]
        elsewhere = lambda cs: sorted(c["candidate_id"] for c in cs if target not in c["group"])
        self.assertTrue(compared(base))
        for label, copies in (("changed", changed), ("missing", missing)):
            res = run(copies=copies)[1]["discovery"]["candidates"]
            copy_cands = [c for c in res if c["group"] == "requirements:" + target and c["title"].endswith("differs from its recorded digest")]
            self.assertEqual(len(copy_cands), 1, label)
            self.assertEqual((copy_cands[0]["category"], copy_cands[0]["finding"]), ("unknown_coverage", None), label)
            self.assertEqual(compared(res), [], label)                   # nothing of that file is compared, so nothing is contradicted
            self.assertEqual(elsewhere(res), elsewhere(base), label)     # every other file is unaffected

    def test_an_sbom_that_does_not_list_the_file_with_the_same_digest_is_unknown_not_contradicted(self):
        sbom = json.loads(SBOM_BYTES)
        for c in sbom["components"]:                                     # the SBOM records a different SHA-256 for the file
            if c.get("type") == "file" and c.get("name", "").endswith("/docker/main/requirements-wheels.txt"):
                for h in c.get("hashes", []):
                    h["content"] = "f" * 64
        res = run(sbom=json.dumps(sbom).encode())[1]["discovery"]["candidates"]
        group = "requirements:%s:docker/main/requirements-wheels.txt" % SBOM_ID
        seen = [c for c in res if c["group"] == group]
        self.assertTrue(seen)
        for c in seen:
            self.assertEqual(c["category"], "unknown_coverage", c["title"])
            self.assertIn("different SHA-256", c["trigger"])
        discovered = [c for c in seen if c["assertion_id"].startswith("dreq-")]
        self.assertTrue(discovered)
        for c in discovered:   # the unchanged rule agrees: it cannot bind the inventory to the file, so it is unverifiable, never contradicted
            self.assertEqual((c["finding"]["state"], c["finding"]["reason_codes"]), ("unverifiable", ["no_usable_observation"]), c["title"])
        # (The donor reuses the curated tflite_runtime assertion for its candidate; its verdict rests on its own curated evidence, bound to the
        # original SBOM. The Workbench never reaches this case with different SBOM bytes: the artifact digest check refuses them first.)

    def test_coverage_is_labeled_unknown_when_markers_cannot_be_evaluated(self):
        cands = run()[1]["discovery"]["candidates"]
        markers = [c for c in cands if "carry environment markers" in c["title"]]
        self.assertTrue(markers)
        for c in markers:
            self.assertEqual((c["category"], c["assertion_id"], c["finding"]), ("unknown_coverage", None, None))
            self.assertIn("no target environment was recorded", c["title"])


class DonorParsing(unittest.TestCase):
    def test_overlay_line_rules_ported_into_the_adapter(self):
        p = adapters.parse_requirement_line
        self.assertEqual(p("numpy # pinned later")["form"], "unpinned")
        self.assertIsNone(p("# only a comment"))
        self.assertIsNone(p("   "))
        self.assertEqual(p("-r other.txt")["directive"], {"option": "-r", "kind": "requirement_file", "argument": "other.txt"})
        self.assertEqual(p("--index-url https://x.invalid/simple")["directive"]["kind"], "option")
        self.assertEqual(p("pkg @ https://x.invalid/pkg-1.0-py3-none-any.whl#egg=pkg")["form"], "direct_url")  # '#egg' is not a comment
        self.assertEqual(p("tflite_runtime @ https://example.invalid/t-2.17.1-cp311-cp311-linux_x86_64.whl; platform_machine == 'x86_64'")["marker"], "platform_machine == 'x86_64'")

    def test_nested_components_are_traversed_by_the_lookup(self):
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"type": "application", "name": "outer", "components": [{"type": "library", "name": "Deep_Pkg", "version": "1", "purl": "pkg:pypi/deep-pkg@1"}]}]}
        look = adapters.inventory_lookup_observation(doc, "0" * 64, "deep-pkg", "requirements.txt")
        self.assertEqual(len(look["matches"]), 1)

    def test_the_port_adds_no_third_party_import(self):
        import ast
        import opentrace_core.bombridge.discovery as mod
        roots = set()
        for n in ast.walk(ast.parse(pathlib.Path(mod.__file__).read_text())):
            if isinstance(n, ast.Import):
                roots |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom) and not n.level:
                roots.add((n.module or "").split(".")[0])
        self.assertLessEqual(roots, {"copy", "hashlib", "json", "re"})


if __name__ == "__main__":
    unittest.main()
