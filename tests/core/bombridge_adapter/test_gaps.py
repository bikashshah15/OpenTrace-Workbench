"""I8: adapter validation of the ``discovery`` payload (bundle side and result side). Pure; no server, no worker."""
import copy
import json
import pathlib
import unittest

from opentrace_core.bombridge import discovery, pipeline
from opentrace_core.bombridge_adapter import validation as v

FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "bombridge" / "fixtures"
FRIGATE = json.loads((FIXTURES / "bundles/frigate-v0.18.2-cpu-pilot.json").read_text())
SBOM_ID = "inv:syft-source-dir"
DECL = (FIXTURES / "inputs/frigate/source-declarations.json").read_bytes()
DECL_SHA = "aada73d87aebbba9f0f65a61d09549b921f5bf8b7c3fbe0e5b510168bc24185c"


def build():
    sd, texts = discovery.read_declarations(FRIGATE, DECL, expected_sha256=DECL_SHA,
                                            read_copy=lambda p: (FIXTURES / "inputs/frigate/raw/source" / p).read_bytes())
    inv = next(i for i in FRIGATE["capture"]["inventories"] if i["inventory_id"] == SBOM_ID)
    raw = json.loads((FIXTURES / "inputs/frigate/raw/syft-source-dir.cdx.json").read_bytes())
    found = discovery.discover(FRIGATE, raw_inventories={SBOM_ID: {"doc": raw, "sha256": inv["source_sha256"]}}, source_declarations=sd, requirement_texts=texts)
    return found, pipeline.run_doc(found)


FOUND, RESULT = build()
codes = lambda errs: sorted((e.code, e.detail) for e in errs)


class BundleSide(unittest.TestCase):
    def test_a_bundle_without_discovery_has_nothing_to_validate(self):
        self.assertEqual(v.validate_discovery(FRIGATE), [])

    def test_the_real_payload_validates(self):
        self.assertEqual(v.validate_discovery(FOUND), [])

    def test_every_reference_must_resolve_inside_the_bundle(self):
        for field, value, detail in (("assertion_id", "nope", "unknown_assertion"), ("entity_id", "nope", "unknown_entity"),
                                     ("selected_inventory", "inv:nope", "unknown_inventory"), ("evidence_ids", ["ev-nope"], "unknown_evidence")):
            b = copy.deepcopy(FOUND)
            b["discovery"]["candidates"][0][field] = value
            self.assertIn(("dangling_reference", detail), codes(v.validate_discovery(b)), field)
        b = copy.deepcopy(FOUND)
        b["discovery"]["verification_assertions"].append("nope")
        self.assertIn(("dangling_reference", "unknown_assertion"), codes(v.validate_discovery(b)))

    def test_schema_category_duplicates_judgments_and_size_are_checked(self):
        b = copy.deepcopy(FOUND); b["discovery"]["schema"] = "other/1"
        self.assertEqual(codes(v.validate_discovery(b)), [("unsupported_schema", "unsupported_discovery_schema")])
        b = copy.deepcopy(FOUND); b["discovery"]["candidates"][0]["category"] = "made_up"
        self.assertIn(("invalid_bundle", "unknown_category"), codes(v.validate_discovery(b)))
        b = copy.deepcopy(FOUND); b["discovery"]["candidates"][1]["candidate_id"] = b["discovery"]["candidates"][0]["candidate_id"]
        self.assertIn(("invalid_bundle", "duplicate_id"), codes(v.validate_discovery(b)))
        b = copy.deepcopy(FOUND); b["discovery"]["candidates"][0]["finding"] = {"state": "supported"}
        self.assertIn(("invalid_bundle", "derived_judgment_supplied"), codes(v.validate_discovery(b)))
        b = copy.deepcopy(FOUND); b["discovery"]["candidates"] = b["discovery"]["candidates"] * 30
        self.assertEqual(codes(v.validate_discovery(b)), [("size_limit", "candidates_over_limit")])
        b = copy.deepcopy(FOUND); b["discovery"]["candidates"] = {"a": 1}
        self.assertEqual(codes(v.validate_discovery(b)), [("invalid_bundle", "candidates_and_verification_must_be_arrays")])

    def test_the_donor_validator_accepts_the_discovered_bundle(self):
        from opentrace_core.bombridge.contract import validate_bundle
        self.assertEqual(validate_bundle(FOUND), [])


class MalformedCandidateFields(unittest.TestCase):
    """I8-IR-01: a list or object where a string id belongs is a typed error, never an exception (unhashable set lookups)."""

    def test_unhashable_or_wrongly_typed_fields_are_typed_errors(self):
        for field, detail in (("category", ("invalid_bundle", "unknown_category")), ("assertion_id", ("invalid_bundle", "reference_must_be_string_or_null")),
                              ("entity_id", ("invalid_bundle", "reference_must_be_string_or_null")), ("selected_inventory", ("invalid_bundle", "reference_must_be_string_or_null"))):
            for bad in (["x"], {"a": 1}, 7, True):
                b = copy.deepcopy(FOUND)
                b["discovery"]["candidates"][0][field] = bad
                try:
                    got = codes(v.validate_discovery(b))
                except TypeError as exc:
                    self.fail("%s=%r raised %r" % (field, bad, exc))
                self.assertIn(detail, got, (field, bad))

    def test_null_optional_references_stay_valid(self):
        b = copy.deepcopy(FOUND)
        for c in b["discovery"]["candidates"]:
            if c["category"] == "unknown_coverage":
                c["assertion_id"] = c["entity_id"] = c["selected_inventory"] = None
        self.assertEqual(v.validate_discovery(b), [])
        self.assertTrue(any(c["assertion_id"] is None for c in b["discovery"]["candidates"]))

    def test_the_full_prevalidation_reports_instead_of_crashing(self):
        b = copy.deepcopy(FOUND)
        b["discovery"]["candidates"][0]["assertion_id"] = ["p5"]
        errs = v.validate_discovery(b)
        self.assertTrue(errs and all(hasattr(e, "code") for e in errs))


class ResultCandidates(unittest.TestCase):
    check = staticmethod(lambda result, bundle=FOUND: codes(v._validate_result_discovery(result, bundle, result["findings"])))

    def test_non_object_entries_anywhere_are_rejected(self):
        for where in ("trailing", "leading", "middle"):
            for junk in (None, 5, "x", [1]):
                r = copy.deepcopy(RESULT)
                cands = r["discovery"]["candidates"]
                if where == "trailing":
                    cands.append(junk)
                elif where == "leading":
                    cands.insert(0, junk)
                else:
                    cands[len(cands) // 2] = junk
                self.assertTrue(self.check(r), (where, junk))
                self.assertTrue(any(c == "invalid_result" for c, _ in self.check(r)), (where, junk))

    def test_the_count_and_order_must_equal_the_submitted_candidates(self):
        r = copy.deepcopy(RESULT); r["discovery"]["candidates"].append(copy.deepcopy(r["discovery"]["candidates"][0]))
        self.assertIn(("invalid_result", "candidate_set_changed"), self.check(r))
        r = copy.deepcopy(RESULT); r["discovery"]["candidates"].reverse()
        self.assertIn(("invalid_result", "candidate_set_changed"), self.check(r))
        r = copy.deepcopy(RESULT); r["discovery"]["candidates"] = r["discovery"]["candidates"][:-1]
        self.assertIn(("invalid_result", "candidate_set_changed"), self.check(r))

    def test_every_candidate_is_validated_not_only_those_that_are_objects(self):
        r = copy.deepcopy(RESULT); r["discovery"]["candidates"][-1] = None
        self.assertIn(("invalid_result", "candidate_not_object"), self.check(r))

    def test_schema_inputs_and_other_metadata_must_be_preserved(self):
        for key, value in (("schema", "bombridge.discovery/2"), ("inputs", []), ("generator", "other"), ("ported_scope", ["everything"]),
                           ("notes", ["edited"]), ("counts", {"by_category": {}}), ("verification_assertions", [])):
            r = copy.deepcopy(RESULT); r["discovery"][key] = value
            self.assertIn(("invalid_result", "discovery_metadata_changed"), self.check(r), key)
        r = copy.deepcopy(RESULT); r["discovery"]["inputs"][0]["sha256"] = "0" * 64
        self.assertIn(("invalid_result", "discovery_metadata_changed"), self.check(r))
        r = copy.deepcopy(RESULT); r["discovery"]["extra"] = 1
        self.assertIn(("invalid_result", "discovery_metadata_changed"), self.check(r))
        r = copy.deepcopy(RESULT); del r["discovery"]["inputs"]
        self.assertIn(("invalid_result", "discovery_metadata_changed"), self.check(r))

    def test_an_unhashable_rule_or_state_in_a_verdict_is_a_typed_error(self):
        i = next(n for n, c in enumerate(RESULT["discovery"]["candidates"]) if c["finding"])
        for field in ("rule_id", "state"):
            r = copy.deepcopy(RESULT); r["discovery"]["candidates"][i]["finding"][field] = ["x"]
            self.assertIn(("invalid_result", "unknown_rule_or_state"), self.check(r), field)

    def test_the_engines_derived_fields_are_allowed(self):
        self.assertEqual(self.check(RESULT), [])
        self.assertTrue({"verification", "gap_states"} <= set(RESULT["discovery"]))


class ResultSide(unittest.TestCase):
    check = staticmethod(lambda result, bundle=FOUND: codes(v._validate_result_discovery(result, bundle, result["findings"])))

    def test_the_real_result_validates_and_only_known_rules_appear(self):
        self.assertEqual(self.check(RESULT), [])
        rules = {c["finding"]["rule_id"] for c in RESULT["discovery"]["candidates"] if c["finding"]}
        self.assertTrue(rules <= v._RULES, rules)

    def test_a_result_discovery_for_a_bundle_without_one_is_refused(self):
        self.assertEqual(self.check(RESULT, FRIGATE), [("invalid_result", "discovery_not_in_bundle")])
        legacy = pipeline.run_doc(FRIGATE)
        self.assertEqual(self.check(legacy, FRIGATE), [])

    def test_a_missing_or_altered_section_is_refused(self):
        r = copy.deepcopy(RESULT); del r["discovery"]
        self.assertEqual(self.check(r), [("invalid_result", "discovery_section_missing_or_malformed")])
        r = copy.deepcopy(RESULT); r["discovery"]["candidates"].pop()
        self.assertEqual(self.check(r), [("invalid_result", "candidate_set_changed")])
        r = copy.deepcopy(RESULT); r["discovery"]["candidates"][0]["title"] = "edited"
        self.assertIn(("invalid_result", "candidate_changed"), self.check(r))

    def test_a_verdict_that_is_not_the_assertions_finding_is_refused(self):
        i = next(n for n, c in enumerate(RESULT["discovery"]["candidates"]) if c["finding"] and c["finding"]["state"] == "contradicted")
        r = copy.deepcopy(RESULT); r["discovery"]["candidates"][i]["finding"]["state"] = "supported"
        self.assertIn(("invalid_result", "finding_differs_from_assertion_finding"), self.check(r))
        r = copy.deepcopy(RESULT); r["discovery"]["candidates"][i]["finding"]["rule_id"] = "made_up.rule/9"
        self.assertIn(("invalid_result", "unknown_rule_or_state"), self.check(r))
        r = copy.deepcopy(RESULT); r["discovery"]["candidates"][i]["finding"]["state"] = "maybe"
        self.assertIn(("invalid_result", "unknown_rule_or_state"), self.check(r))
        j = next(n for n, c in enumerate(RESULT["discovery"]["candidates"]) if c["finding"] is None)
        r = copy.deepcopy(RESULT); r["discovery"]["candidates"][j]["finding"] = {"state": "contradicted", "rule_id": "inventory_coverage.requirement_represented/1"}
        self.assertIn(("invalid_result", "finding_without_assertion"), self.check(r))


if __name__ == "__main__":
    unittest.main()


class BomWorkbenchProjection(unittest.TestCase):
    """UIP-08: real bound I8 result, frozen BOM schemas, no collector or network."""

    @classmethod
    def setUpClass(cls):
        import hashlib
        from opentrace_core.bombridge_adapter import BoundAssessment
        from .test_adapter import fixture
        from opentrace_core.bombridge_adapter.validation import json_bytes
        cls._bundle, cls.context, cls.artifacts, cls.reader = fixture()
        native = {"analysis_digest": cls.context.identity["analysis_digest"],
                  "session_id": cls.context.expected_session["session_id"],
                  "generation": cls.context.expected_session["generation"],
                  "configuration": cls.context.expected_configuration,
                  "bundle_sha256": RESULT["bundle_sha256"]}
        seal = hashlib.sha256(json_bytes({"binding": native, "result": RESULT, "source_bundle": FOUND})).hexdigest()
        cls.bound = BoundAssessment("opentrace.bombridge_assessment/1", native, RESULT, seal, FOUND)
        path = pathlib.Path(__file__).resolve().parents[3] / "evidence/uip/fixtures/frigate-recorded/bom-candidates-offset-00.json"
        cls.binding = json.loads(path.read_text())["binding"]
        cls.binding["analysis_digest"] = native["analysis_digest"]
        cls.binding["assessment"]["bundle_sha256"] = native["bundle_sha256"]
        cls.binding["assessment"]["validation_digest"] = seal

    def payload(self, producer, **kwargs):
        return producer(self.bound, context=self.context, workbench_binding=self.binding,
                        artifacts=self.artifacts, read_artifact=self.__class__.reader, **kwargs)

    def test_queue_preserves_candidate_ids_and_distinct_counts(self):
        from opentrace_core.bombridge_adapter.gaps import project_bom_candidates
        from opentrace_core.app.view_contracts import validate_payload
        first = self.payload(project_bom_candidates)
        validate_payload("bom_candidates", first, request={"generation": 1, "offset": 0}, expected_binding=self.binding)
        self.assertEqual(first["counts"]["candidates_total"], len(RESULT["discovery"]["candidates"]))
        self.assertEqual(first["items"][0]["item_id"], RESULT["discovery"]["candidates"][0]["candidate_id"])
        self.assertEqual(first["counts"]["relationships_total"], len(RESULT["graph"]["edges"]))
        self.assertEqual(first["capabilities"][1]["state"], "not_run")
        second = self.payload(project_bom_candidates, offset=25)
        self.assertFalse({x["item_id"] for x in first["items"]} & {x["item_id"] for x in second["items"]})

    def test_focused_graphs_use_exact_recorded_membership_and_roles(self):
        from opentrace_core.bombridge_adapter.gaps import project_bom_graph
        from opentrace_core.app.view_contracts import validate_payload
        a, b = RESULT["discovery"]["candidates"][:2]
        ga = self.payload(project_bom_graph, candidate_id=a["candidate_id"])
        gb = self.payload(project_bom_graph, candidate_id=b["candidate_id"])
        validate_payload("bom_graph", ga, request={"generation": 1, "scope_kind": "focused_candidate", "candidate_id": a["candidate_id"]}, expected_binding=self.binding)
        self.assertNotEqual({n["node_id"] for n in ga["nodes"]}, {n["node_id"] for n in gb["nodes"]})
        source_nodes = {n["id"] for n in RESULT["graph"]["nodes"]}
        source_edges = {(e["from"], e["to"], e["type"]) for e in RESULT["graph"]["edges"]}
        self.assertTrue(all(n["node_id"] in source_nodes for n in ga["nodes"]))
        self.assertTrue(all((e["from"], e["to"], e["type"]) in source_edges for e in ga["edges"]))
        self.assertTrue(all(e["role"] != "used" for e in ga["edges"] if any(n["node_id"] in (e["from"], e["to"]) and n["evidence_role"] == "excluded" for n in ga["nodes"])))

    def test_related_inventory_chooser_uses_exact_identity(self):
        from opentrace_core.bombridge_adapter.gaps import project_bom_related_checks
        from opentrace_core.app.view_contracts import validate_payload
        p = self.payload(project_bom_related_checks, subject_id="inv:syft-source-dir")
        validate_payload("bom_related_checks", p, request={"generation": 1, "subject_kind": "record", "subject_id": "inv:syft-source-dir"}, expected_binding=self.binding)
        self.assertEqual(p["resolution"], "multiple")
        self.assertTrue(p["page"]["has_more"])
        self.assertTrue(all(any(c["candidate_id"] == x["item_id"] and c["selected_inventory"] == "inv:syft-source-dir" for c in RESULT["discovery"]["candidates"]) for x in p["items"]))

    def test_full_graph_accepts_exact_recorded_scan_root_id(self):
        from opentrace_core.bombridge_adapter.gaps import project_bom_graph, project_bom_related_checks
        from opentrace_core.app.view_contracts import validate_payload, validate_request
        p = self.payload(project_bom_graph, scope_kind="full_view", offset=200)
        validate_payload("bom_graph", p, request={"generation": 1, "scope_kind": "full_view", "offset": 200}, expected_binding=self.binding)
        recorded = next(n["node_id"] for n in p["nodes"] if "<scan-root>" in n["node_id"])
        self.assertIn(recorded, {n["id"] for n in RESULT["graph"]["nodes"]})
        self.assertTrue(all(e["from"] in {n["node_id"] for n in p["nodes"]} and e["to"] in {n["node_id"] for n in p["nodes"]} for e in p["edges"]))
        self.assertIn(recorded, {r["node_id"] for r in p["records"]})
        req = validate_request("bom_related_checks", {"generation": 1, "subject_kind": "record", "subject_id": recorded})
        related = self.payload(project_bom_related_checks, subject_id=req["subject_id"])
        validate_payload("bom_related_checks", related, request=req, expected_binding=self.binding)
        self.assertEqual(related["subject"]["id"], recorded)
        self.assertEqual(related["subject"]["canonical_ref"]["record_id"], recorded)

    def test_bom_id_exception_rejects_other_markup_controls_and_overlength(self):
        from opentrace_core.app.view_contracts import ContractError, validate_request
        good = next(n["id"] for n in RESULT["graph"]["nodes"] if "<scan-root>" in n["id"])
        for bad in (good.replace("<scan-root>", "<other>"), good + "<scan-root>",
                    good.replace("<scan-root>", "<script>"), good.replace("_<scan-root>/", "<scan-root>/"),
                    good.replace("_<scan-root>/", "_<scan-root>"), good + "\n", good + "\x01", "x" * 161):
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                validate_request("bom_related_checks", {"generation": 1, "subject_kind": "record", "subject_id": bad})

    def test_wrong_binding_is_unavailable_not_empty_success(self):
        from opentrace_core.bombridge_adapter.gaps import project_bom_candidates
        from opentrace_core.bombridge_adapter import AdapterError
        wrong = copy.deepcopy(self.binding)
        wrong["assessment"]["validation_digest"] = "0" * 64
        with self.assertRaises(AdapterError):
            project_bom_candidates(self.bound, context=self.context, workbench_binding=wrong,
                                   artifacts=self.artifacts, read_artifact=self.__class__.reader)
