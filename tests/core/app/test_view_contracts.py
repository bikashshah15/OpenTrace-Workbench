"""UIP-01B: schemas, limits and validators of the Workbench view contracts (opentrace.workbench.*/1).

Structural rules are checked against both the stdlib validator and JSON Schema; semantic rules (counts, graphs, bindings,
state transitions) only against the semantic validator. No route, handler or UI is involved.
"""
import copy
import glob
import importlib.util
import json
import os
import re
import unittest

from opentrace_core.app import view_contracts as vc

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SCHEMA_DIR = os.path.join(REPO, "contracts", "workbench", "v1", "schemas")
FIXTURES = os.path.join(REPO, "evidence", "uip", "fixtures")

# The frozen contract section 4.2 values, mirrored here (the contract table is prose; this is the reviewer-visible copy).
FROZEN = {"response_max_bytes": 1048576, "stages": 9, "context_groups": 12, "files_per_group_page_max": 40, "files_per_group_page_default": 20,
          "dependency_match_page": 30, "dependency_connectors_per_page": 120, "dependency_edges_per_page": 240, "dependency_path_depth": 12,
          "search_results": 10, "component_list_page": 40, "asset_page": 30, "asset_source_groups": 24, "review_items_per_page": 50,
          "links_per_page": 90, "services_per_page": 30, "bom_queue_page": 25, "bom_focused_nodes": 80, "bom_focused_edges": 160,
          "bom_full_view_primary": 100, "bom_full_view_neighbors": 50, "bom_full_view_nodes": 150, "bom_full_view_edges": 300,
          "bom_related_page": 20, "offset_max": 1000000, "warnings_per_payload": 10, "reason_codes": 8, "limitations": 6,
          "evidence_refs_per_row": 20, "source_locations_per_record": 20, "occurrences_per_asset": 20, "raw_locations_per_file": 5}
FROZEN_BYTES = {"scan_status": 32768, "inspector": 65536, "bom_related_checks": 65536, "bom_candidates": 131072, "contexts": 524288,
                "dependency_page": 524288, "crypto_assets": 524288, "ai_assets": 524288, "bom_graph": 524288, "error": 4096}
FROZEN_STRINGS = {"id": 160, "path": 512, "name": 256, "label": 120, "message": 400, "excerpt": 600, "rationale": 900, "url": 2048, "query": 80}


def jload(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def load_builder():
    spec = importlib.util.spec_from_file_location("uip_fixture_builder", os.path.join(REPO, "tools", "uip_fixtures", "build.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def jsonschema_validators():
    import jsonschema
    from referencing import Registry, Resource
    schemas = {}
    for path in glob.glob(os.path.join(SCHEMA_DIR, "*.schema.json")):
        with open(path, encoding="utf-8") as h:
            doc = json.load(h)
        schemas[os.path.basename(path)[:-len(".schema.json")]] = doc
    registry = Registry().with_resources([(d["$id"], Resource.from_contents(d)) for d in schemas.values()])
    return {n: jsonschema.Draft202012Validator(d, registry=registry) for n, d in schemas.items() if n not in ("common", "requests")}, schemas, registry


def valid_fixture_payloads():
    out = []
    for fx in sorted(os.listdir(FIXTURES)):
        d = os.path.join(FIXTURES, fx)
        if not os.path.isdir(d) or fx in ("invalid", "legacy-view-snapshots"):
            continue
        manifest = jload(os.path.join(d, "MANIFEST.json"))
        for entry in manifest["files"]:
            out.append((fx, entry["path"], entry["schema"].split(".")[-1].split("/")[0], jload(os.path.join(d, entry["path"]))))
    return out


class SchemaAndLimits(unittest.TestCase):
    def test_twelve_schema_files_with_stable_ids(self):
        names = sorted(os.path.basename(p)[:-len(".schema.json")] for p in glob.glob(os.path.join(SCHEMA_DIR, "*.schema.json")))
        self.assertEqual(names, sorted(["common", "error", "requests", "scan_status", "contexts", "dependency_page", "crypto_assets", "ai_assets",
                                        "inspector", "bom_candidates", "bom_graph", "bom_related_checks"]))
        _, schemas, _ = jsonschema_validators()
        import jsonschema
        for name, doc in schemas.items():
            jsonschema.Draft202012Validator.check_schema(doc)
            self.assertEqual(doc["$id"], "https://opentrace.local/contracts/workbench/v1/schemas/%s.schema.json" % name)
            self.assertNotIn('"format"', json.dumps(doc), name)
            if name not in ("common", "requests"):
                self.assertIs(doc["additionalProperties"], False, name)
                self.assertEqual(doc["properties"]["schema"]["const"], "opentrace.workbench.%s/1" % name)

    def test_every_object_schema_is_closed(self):
        def walk(node, where):
            if isinstance(node, dict):
                if node.get("type") == "object" and "properties" in node:
                    self.assertIs(node.get("additionalProperties"), False, where)
                for k, v in node.items():
                    walk(v, where + "/" + k)
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, "%s/%d" % (where, i))
        for path in glob.glob(os.path.join(SCHEMA_DIR, "*.schema.json")):
            walk(jload(path), os.path.basename(path))

    def test_limits_equal_the_frozen_values_and_the_validator(self):
        on_disk = jload(os.path.join(REPO, "contracts", "workbench", "v1", "limits.json"))
        self.assertEqual(vc.LIMITS, on_disk)
        for k, v in FROZEN.items():
            self.assertEqual(on_disk[k], v, k)
        self.assertEqual(on_disk["payload_max_bytes"], FROZEN_BYTES)
        self.assertEqual(on_disk["string_chars"], FROZEN_STRINGS)
        self.assertEqual(on_disk["bom_full_view_nodes"], on_disk["bom_full_view_primary"] + on_disk["bom_full_view_neighbors"])

    def test_schema_bounds_agree_with_limits(self):
        s = lambda n: jload(os.path.join(SCHEMA_DIR, n + ".schema.json"))
        L = vc.LIMITS
        dp = s("dependency_page")["properties"]
        self.assertEqual(dp["nodes"]["maxItems"], 1 + L["dependency_match_page"] + L["dependency_connectors_per_page"])
        self.assertEqual(dp["edges"]["maxItems"], L["dependency_edges_per_page"])
        self.assertEqual(dp["page"]["properties"]["size"]["const"], 30)
        self.assertEqual(s("bom_candidates")["properties"]["items"]["maxItems"], 25)
        self.assertEqual(s("bom_graph")["properties"]["nodes"]["maxItems"], 150)
        self.assertEqual(s("bom_graph")["properties"]["edges"]["maxItems"], 300)
        self.assertEqual(s("scan_status")["properties"]["stages"]["minItems"], 9)
        self.assertEqual(s("contexts")["properties"]["groups"]["maxItems"], 12)
        self.assertEqual(s("crypto_assets")["properties"]["assets"]["maxItems"], 30)
        self.assertEqual(s("bom_related_checks")["properties"]["items"]["maxItems"], 20)
        self.assertEqual(len(s("common")["$defs"]["excerpt"]["pattern"]) > 0, True)
        self.assertEqual(s("common")["$defs"]["excerpt"]["maxLength"], 600)
        self.assertEqual(s("common")["$defs"]["query"]["maxLength"], 80)
        self.assertEqual(s("common")["$defs"]["path"]["maxLength"], 512)


class OpaqueIds(unittest.TestCase):
    def test_ids_are_stable_per_analysis_and_differ_across_analyses(self):
        a = "sha256:" + "a" * 64
        b = "sha256:" + "b" * 64
        x = vc.opaque_id("ctx", a, "file", "src/app.py")
        self.assertEqual(x, vc.opaque_id("ctx", a, "file", "src/app.py"))
        self.assertNotEqual(x, vc.opaque_id("ctx", b, "file", "src/app.py"))
        self.assertNotEqual(x, vc.opaque_id("ctx", a, "file", "src/app2.py"))
        self.assertRegex(x, r"^ctx:[0-9a-f]{24}$")
        self.assertEqual(vc.opaque_id("ctx", a, "file", "x"), vc.opaque_id("ctx", a, "file", "x"))


class Requests(unittest.TestCase):
    CTX = "ctx:" + "0" * 24

    def test_normalization_and_defaults(self):
        out = vc.validate_request("dependency_page", {"generation": "3", "context_id": self.CTX, "query": "  react "})
        self.assertEqual(out, {"generation": 3, "context_id": self.CTX, "query": "react", "filter": "all", "offset": 0})
        out = vc.validate_request("contexts", {"generation": 1})
        self.assertEqual((out["files_offset"], out["files_limit"]), (0, 20))
        self.assertEqual(vc.validate_request("bom_candidates", {"generation": 1, "size": "25"})["size"], 25)

    def test_each_route_accepts_its_minimum_and_rejects_the_rest(self):
        minimal = {"scan_status": {"generation": 1, "job_id": "job:" + "1" * 24}, "contexts": {"generation": 1},
                   "dependency_page": {"generation": 1, "context_id": self.CTX}, "crypto_assets": {"generation": 1}, "ai_assets": {"generation": 1},
                   "inspector": {"generation": 1, "tab": "bom", "selection_kind": "edge", "selection_id": "edge:abc"},
                   "bom_candidates": {"generation": 1}, "bom_graph": {"generation": 1, "scope_kind": "full_view"},
                   "bom_related_checks": {"generation": 1, "subject_kind": "record", "subject_id": "inv:sbom-source"}}
        self.assertEqual(sorted(minimal), sorted(vc.ROUTE_KEYS))
        for route, params in minimal.items():
            vc.validate_request(route, params)
            with self.assertRaises(vc.ContractError) as ctx:
                vc.validate_request(route, dict(params, unexpected="1"))
            self.assertEqual((ctx.exception.code, ctx.exception.detail_code), ("invalid_request", "unknown_parameter"), route)
            missing = {k: v for k, v in params.items() if k != "generation"}
            with self.assertRaises(vc.ContractError) as ctx:
                vc.validate_request(route, missing)
            self.assertEqual(ctx.exception.detail_code, "missing_field", route)

    def test_boundaries_are_inclusive(self):
        vc.validate_request("contexts", {"generation": 1, "files_limit": "40", "files_offset": "1000000"})
        with self.assertRaises(vc.ContractError):
            vc.validate_request("contexts", {"generation": 1, "files_limit": "41"})
        vc.validate_request("bom_candidates", {"generation": 1, "query": "q" * 80})
        with self.assertRaises(vc.ContractError):
            vc.validate_request("bom_candidates", {"generation": 1, "query": "q" * 81})

    def test_typed_failures(self):
        for params, code, detail in [({"generation": "0"}, "invalid_request", "bound_exceeded"), ({"generation": True}, "invalid_request", "type_error"),
                                     ({"generation": "-1"}, "invalid_request", "type_error"), ({"generation": "1", "schema_version": "2"}, "unsupported_version", "schema_version"),
                                     ({"generation": "1", "filter": "x"}, "invalid_request", "enum_violation")]:
            with self.assertRaises(vc.ContractError) as ctx:
                vc.validate_request("crypto_assets", params)
            self.assertEqual((ctx.exception.code, ctx.exception.detail_code), (code, detail), params)
        with self.assertRaises(ValueError):
            vc.validate_request("nope", {})

    def test_error_body_keeps_the_legacy_envelope(self):
        try:
            vc.validate_request("crypto_assets", {"generation": 1, "zzz": 1})
        except vc.ContractError as exc:
            body = exc.body(generation=1)
            self.assertEqual((body["error"], exc.status), ("invalid_request", 400))
            self.assertIn("message", body)
            vc.validate_payload("error", body)
        with self.assertRaises(vc.ContractError):
            vc.validate_payload("error", {"error": "invented_code", "message": "x"})
        self.assertEqual(sorted(vc.STATUS), sorted(["invalid_request", "stale_generation", "no_analysis", "not_found", "projection_failed",
                                                     "unsupported_version", "binding_mismatch", "response_too_large", "job_not_found"]))


class SizeCeilings(unittest.TestCase):
    def test_ceiling_is_independent_of_field_limits_and_exact(self):
        for name, cap in FROZEN_BYTES.items():
            vc.check_size(name, cap)
            with self.assertRaises(vc.ContractError) as ctx:
                vc.check_size(name, cap + 1)
            self.assertEqual(ctx.exception.code, "response_too_large", name)
        with self.assertRaises(vc.ContractError):
            vc.check_size("contexts", 1048577)

    def test_a_valid_boundary_payload_is_rejected_by_a_lowered_ceiling_alone(self):
        B = load_builder()
        p = jload(os.path.join(FIXTURES, "deps-82-synthetic", "page-offset-00.json"))
        vc.validate_payload("dependency_page", p)
        size = len(vc.canonical_bytes(p))
        lowered = copy.deepcopy(vc.LIMITS)
        lowered["payload_max_bytes"]["dependency_page"] = size - 1
        with self.assertRaises(vc.ContractError) as ctx:
            vc.validate_payload("dependency_page", p, limits=lowered)
        self.assertEqual((ctx.exception.code, ctx.exception.detail_code), ("response_too_large", "bound_exceeded"))
        lowered["payload_max_bytes"]["dependency_page"] = size
        vc.validate_payload("dependency_page", p, limits=lowered)


class BoundaryFixtures(unittest.TestCase):
    """Valid payloads that sit exactly on a bound, where the shape can reach it."""

    def load(self, fx, name):
        return jload(os.path.join(FIXTURES, fx, name))

    def test_30_matches_25_rows_150_nodes_600_char_excerpt(self):
        p = self.load("deps-82-synthetic", "page-offset-00.json")
        self.assertEqual(sum(1 for n in p["nodes"] if n["role"] == "match"), 30)
        self.assertEqual(len(self.load("bom-large-synthetic", "candidates-offset-00.json")["items"]), 25)
        g = self.load("bom-large-synthetic", "graph-full-view-offset-000.json")
        self.assertEqual((len(g["nodes"]), g["counts"]["primary_shown"], g["counts"]["neighbors_shown"]), (150, 100, 50))
        ex = self.load("malicious-text-synthetic", "crypto-hostile.json")["assets"][0]["occurrences"][0]["source_location"]["excerpt"]
        self.assertEqual(len(ex), 600)
        c = self.load("contexts-600-synthetic", "contexts-group-python-offset-20.json")
        self.assertEqual(len(c["groups"][0]["files"]), 40)

    def test_connector_budget_boundary_is_visible(self):
        p = self.load("deps-paths-synthetic", "paths-connectors-omitted.json")
        self.assertLessEqual(p["limits"]["connectors_shown"], 120)
        self.assertTrue(p["limits"]["connectors_truncated"])
        omitted = [n for n in p["nodes"] if n["path_state"] == "connectors_omitted"]
        self.assertTrue(omitted)
        for n in omitted:  # a match whose connectors did not fit stays listed with no drawn edge
            self.assertEqual(n["role"], "match")
            self.assertFalse([e for e in p["edges"] if n["node_id"] in (e["from"], e["to"])])

    def test_dependency_paging_30_30_22_excludes_connectors(self):
        pages = [self.load("deps-82-synthetic", "page-offset-%02d.json" % o) for o in (0, 30, 60)]
        self.assertEqual([p["page"]["matches_shown"] for p in pages], [30, 30, 22])
        self.assertEqual({p["page"]["matches_total"] for p in pages}, {82})
        self.assertEqual([(p["page"]["range_first"], p["page"]["range_last"]) for p in pages], [(1, 30), (31, 60), (61, 82)])
        seen = [n["node_id"] for p in pages for n in p["nodes"] if n["role"] == "match"]
        self.assertEqual(len(seen), len(set(seen)))
        trans = self.load("deps-paths-synthetic", "paths-transitive.json")
        self.assertTrue(any(n["role"] == "connector" for n in trans["nodes"]))
        self.assertEqual(trans["page"]["matches_shown"], sum(1 for n in trans["nodes"] if n["role"] == "match"))


class SemanticValidation(unittest.TestCase):
    """Unit-level semantic checks beyond the fixture corpus."""

    def setUp(self):
        self.d = jload(os.path.join(FIXTURES, "deps-paths-synthetic", "paths-all.json"))

    def test_cycle_and_diamond_terminate_and_keep_actual_edges(self):
        vc.validate_payload("dependency_page", self.d)
        cyc = jload(os.path.join(FIXTURES, "deps-paths-synthetic", "paths-cycle-fallback.json"))
        vc.validate_payload("dependency_page", cyc)
        self.assertEqual(cyc["focus"]["basis"], "cycle_fallback")
        ids = {n["node_id"]: n for n in self.d["nodes"]}
        names = {n["name"]: n for n in self.d["nodes"]}
        incoming = [e for e in self.d["edges"] if e["to"] == names["node-d"]["node_id"]]
        self.assertEqual(len(incoming), 2, "a component with two incoming paths keeps both recorded edges")
        self.assertEqual(names["node-d"]["depth"], 2)
        self.assertTrue(all(e["from"] in ids and e["to"] in ids for e in self.d["edges"]))

    def test_lookup_states_are_distinct_and_no_match_is_covered(self):
        by = {n["name"]: n for n in self.d["nodes"]}
        self.assertEqual(by["node-b"]["advisory_lookup"], "no_match")
        self.assertEqual(by["node-b"]["gap_causes"], [])
        self.assertFalse(by["node-b"]["flags"]["evidence_gap"])
        for name, state in [("node-c", "unavailable"), ("node-d", "unsupported"), ("node-e", "missing_version"), ("node-g", "not_run")]:
            self.assertEqual(by[name]["advisory_lookup"], state)
            self.assertTrue(by[name]["flags"]["evidence_gap"], name)
        off = jload(os.path.join(FIXTURES, "deps-paths-synthetic", "paths-lookup-off.json"))
        self.assertEqual(off["lookup"]["mode"], "off")
        self.assertIn("not performed", off["lookup"]["explanation"])
        self.assertTrue(all(n["flags"]["evidence_gap"] for n in off["nodes"] if n["role"] != "focus"))

    def test_scan_status_transitions(self):
        seq = [jload(p) for p in sorted(glob.glob(os.path.join(FIXTURES, "scan-status-matrix-synthetic", "scan-0[0-4]-*.json")))]
        vc.validate_sequence(seq)
        self.assertEqual([p["job"]["state"] for p in seq], ["queued", "running", "running", "running", "completed"])
        self.assertEqual([p["binding_state"] for p in seq], ["unresolved", "unresolved", "resolved", "resolved", "resolved"])
        self.assertIsNone(seq[0]["binding"])
        self.assertIsNone(seq[0]["identity"])
        failed = jload(os.path.join(FIXTURES, "scan-status-matrix-synthetic", "scan-07-failed-resolution.json"))
        self.assertIsNone(failed["binding"])
        self.assertEqual(failed["job"]["state"], "failed")
        self.assertFalse(failed["handoff"]["ready"])
        self.assertEqual({s["state"] for s in failed["stages"][1:]}, {"not_run"})
        states = set()
        for path in glob.glob(os.path.join(FIXTURES, "scan-status-matrix-synthetic", "*.json")):
            if path.endswith("MANIFEST.json"):
                continue
            for s in jload(path)["stages"]:
                states.add(s["state"])
        self.assertEqual(states, set(["queued", "running", "completed", "completed_empty", "partial", "not_run", "unsupported", "failed", "cancelled"]))

    def test_no_fabricated_percentage_exists_in_the_schema(self):
        raw = json.dumps(jload(os.path.join(SCHEMA_DIR, "scan_status.schema.json")))
        for word in ("percent", "eta", "progress"):
            self.assertNotIn('"%s"' % word, raw)

    def test_family_and_counts_are_separate(self):
        p = jload(os.path.join(FIXTURES, "bom-large-synthetic", "candidates-offset-00.json"))
        self.assertEqual(p["counts"]["candidates_total"], 60)
        self.assertEqual(p["counts"]["assertions_unique"], 49 + 0)  # 40 contradicted share one assertion pair; 10 supported; tasks have none
        self.assertLess(p["counts"]["assertions_unique"], p["counts"]["candidates_total"])
        shared = [i for i in jload(os.path.join(FIXTURES, "bom-large-synthetic", "candidates-offset-00.json"))["items"] if i["assertion_id"] == "assert-shared"]
        self.assertEqual(len(shared), 2)
        self.assertNotEqual(shared[0]["item_id"], shared[1]["item_id"])
        names = [i["display"]["name"] for i in p["items"]]
        self.assertEqual(names.count("same-name"), 2)

    def test_context_counts_never_label_a_sum_as_unique(self):
        c = jload(os.path.join(FIXTURES, "contexts-600-synthetic", "contexts-page-0.json"))
        located_sum = sum(g["distinct_total"] for g in c["groups"] if g["kind"] == "located")
        self.assertGreater(located_sum, c["root"]["located_distinct_total"], "shared components appear in several groups")
        self.assertEqual(c["root"]["distinct_total"], c["root"]["located_distinct_total"] + c["root"]["unlocated_total"])
        self.assertTrue(all(g["category"] != "python_requirements" or g["label"] == "Python requirements" for g in c["groups"]))
        other = next(g for g in c["groups"] if g["category"] == "other_locations")
        self.assertEqual(other["basis"], "fallback")


def fx(*parts):
    return jload(os.path.join(FIXTURES, *parts))


def expect_error(test, name, payload, code, detail_prefix, **kw):
    with test.assertRaises(vc.ContractError) as ctx:
        vc.validate_payload(name, payload, **kw)
    test.assertEqual(ctx.exception.code, code, ctx.exception)
    test.assertTrue(ctx.exception.detail_code.startswith(detail_prefix), ctx.exception)


class CorrectionIR01Binding(unittest.TestCase):
    """UIP-01B-IR-01: nested references, assessment fields, repository and job ownership are all bound."""

    def setUp(self):
        self.cand = fx("bom-large-synthetic", "candidates-offset-00.json")
        self.exp = copy.deepcopy(self.cand["binding"])
        self.req = {"generation": 1}

    def test_the_untouched_payload_passes_with_the_full_expected_binding(self):
        vc.validate_payload("bom_candidates", self.cand, request=self.req, expected_binding=self.exp)

    def test_candidate_reference_fields_are_bound(self):
        for key, value in [("analysis_digest", "sha256:" + "9" * 64), ("generation", 2), ("session_id", "f" * 32),
                           ("configuration", "config:other"), ("bundle_sha256", "9" * 64)]:
            p = copy.deepcopy(self.cand)
            p["items"][0]["canonical_ref"]["binding"][key] = value
            expect_error(self, "bom_candidates", p, "binding_mismatch", "invariant:canonical_ref", request=self.req, expected_binding=self.exp)

    def test_graph_and_inspector_references_are_bound(self):
        g = fx("bom-large-synthetic", "graph-focused-assertion.json")
        i = fx("bom-large-synthetic", "inspector-candidate.json")
        for name, p, setter in [("bom_graph", g, lambda q: q["nodes"][0]["canonical_ref"]["binding"].__setitem__("analysis_digest", "sha256:" + "8" * 64)),
                                ("inspector", i, lambda q: q["selection"]["canonical_ref"]["binding"].__setitem__("generation", 3)),
                                ("inspector", i, lambda q: q["selection"]["canonical_ref"]["binding"].__setitem__("bundle_sha256", "7" * 64))]:
            vc.validate_payload(name, p, request=self.req, expected_binding=p["binding"])
            q = copy.deepcopy(p)
            setter(q)
            expect_error(self, name, q, "binding_mismatch", "invariant:canonical_ref", request=self.req, expected_binding=p["binding"])

    def test_references_in_one_payload_share_one_session(self):
        p = copy.deepcopy(self.cand)
        p["items"][1]["canonical_ref"]["binding"]["session_id"] = "e" * 32
        expect_error(self, "bom_candidates", p, "binding_mismatch", "invariant:canonical_ref_session", request=self.req)

    def test_assessment_fields_in_the_expected_binding_are_enforced(self):
        for key, value in [("configuration", "config:changed"), ("validation_digest", "9" * 64), ("bundle_sha256", "8" * 64)]:
            p = copy.deepcopy(self.cand)
            p["binding"]["assessment"][key] = value
            expect_error(self, "bom_candidates", p, "binding_mismatch", "invariant:assessment", request=self.req, expected_binding=self.exp)

    def test_repository_object_in_the_expected_binding_is_enforced(self):
        p = copy.deepcopy(self.cand)
        p["binding"]["repository"]["owner"] = "someone-else"
        expect_error(self, "bom_candidates", p, "binding_mismatch", "invariant:repository", request=self.req, expected_binding=self.exp)

    def test_a_partial_expected_binding_is_a_recursive_subset(self):
        vc.validate_payload("bom_candidates", self.cand, request=self.req, expected_binding={"assessment": {"bundle_sha256": self.exp["assessment"]["bundle_sha256"]}})
        expect_error(self, "bom_candidates", self.cand, "binding_mismatch", "invariant:assessment", request=self.req,
                     expected_binding={"assessment": {"bundle_sha256": "0" * 64}})

    def test_scan_job_ownership_is_checked_before_pinning(self):
        pre = fx("scan-status-matrix-synthetic", "scan-01-resolving.json")
        vc.validate_payload("scan_status", pre, request={"generation": 1, "job_id": pre["job"]["job_id"]})
        expect_error(self, "scan_status", pre, "job_not_found", "invariant:job_id", request={"generation": 1, "job_id": "job:" + "0" * 24})
        self.assertIsNone(pre["binding"])
        vc.validate_payload("scan_status", pre, request={"generation": 1}, expected_binding={"analysis_digest": "sha256:" + "1" * 64})


class CorrectionIR02Links(unittest.TestCase):
    """UIP-01B-IR-02: every link is inert or exactly the pinned revision destination."""

    BAD = ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "https://user:password@github.com/evil/repo/blob/wrong/file",
           "https://example.org/unrelated"]

    def test_occurrence_links_reject_active_and_unrelated_destinations(self):
        base = fx("cbom-empty-and-partial-synthetic", "crypto-partial.json")
        vc.validate_payload("crypto_assets", base)
        for href in self.BAD:
            p = copy.deepcopy(base)
            next(a for a in p["assets"] if a["occurrences"])["occurrences"][0]["source_location"]["link"]["href"] = href
            expect_error(self, "crypto_assets", p, "projection_failed", "invariant:link", )

    def test_context_revision_links_reject_the_same_set_and_wrong_commits(self):
        base = fx("contexts-600-synthetic", "contexts-page-0.json")
        for href in self.BAD + [base["groups"][0]["files"][0]["revision_link"]["href"].replace(base["binding"]["commit_sha"], "0" * 40)]:
            p = copy.deepcopy(base)
            p["groups"][0]["files"][0]["revision_link"]["href"] = href
            expect_error(self, "contexts", p, "projection_failed", "invariant:link")

    def test_a_link_for_another_path_is_rejected(self):
        base = fx("contexts-600-synthetic", "contexts-page-0.json")
        p = copy.deepcopy(base)
        f = p["groups"][0]["files"]
        f[0]["revision_link"]["href"] = f[1]["revision_link"]["href"]
        expect_error(self, "contexts", p, "projection_failed", "invariant:link")

    def test_encoded_path_destinations_and_inert_hostile_text_are_accepted(self):
        c = fx("malicious-text-synthetic", "contexts-hostile.json")
        vc.validate_payload("contexts", c)
        hrefs = [f["revision_link"]["href"] for g in c["groups"] for f in g["files"]]
        self.assertTrue(any(h and "%" in h for h in hrefs), "an encoded path destination is exercised")
        self.assertTrue(any(h is None for h in hrefs), "hostile text stays inert with a null href")
        vc.validate_payload("crypto_assets", fx("malicious-text-synthetic", "crypto-hostile.json"))

    def test_text_can_never_become_the_destination(self):
        base = fx("contexts-600-synthetic", "contexts-page-0.json")
        p = copy.deepcopy(base)
        p["groups"][0]["files"][0]["revision_link"] = {"href": None, "text": "javascript:alert(1)"}
        vc.validate_payload("contexts", p)


class CorrectionIR03Paging(unittest.TestCase):
    """UIP-01B-IR-03: counts.truncated is shown < total everywhere; effective offsets are validated."""

    def test_every_committed_fixture_follows_the_frozen_counts_rule(self):
        seen = 0
        for fxn, fname, name, p in valid_fixture_payloads():
            if isinstance(p.get("counts"), dict) and set(p["counts"]) == {"total", "shown", "truncated"}:
                self.assertEqual(p["counts"]["truncated"], p["counts"]["shown"] < p["counts"]["total"], "%s/%s" % (fxn, fname))
                seen += 1
        self.assertGreater(seen, 40)

    def test_last_dependency_page_is_truncated_by_the_frozen_definition_and_has_no_next_page(self):
        last = fx("deps-82-synthetic", "page-offset-60.json")
        self.assertEqual((last["counts"]["total"], last["counts"]["shown"], last["counts"]["truncated"]), (82, 22, True))
        self.assertFalse(last["page"]["has_more"])
        first = fx("deps-82-synthetic", "page-offset-00.json")
        self.assertTrue(first["page"]["has_more"])

    def test_has_more_is_not_accepted_as_the_truncation_flag(self):
        p = fx("deps-82-synthetic", "page-offset-60.json")
        p["counts"]["truncated"] = False
        expect_error(self, "dependency_page", p, "projection_failed", "invariant:counts_truncated")

    def test_out_of_range_offsets_are_rejected_on_every_paged_payload(self):
        c = fx("bom-large-synthetic", "candidates-offset-00.json")
        c["page"]["offset"] = 1000000
        expect_error(self, "bom_candidates", c, "projection_failed", "invariant:page_offset")
        r = fx("bom-large-synthetic", "related-shared-offset-00.json")
        r["page"]["offset"] = 1000000
        expect_error(self, "bom_related_checks", r, "projection_failed", "invariant:page_offset")
        d = fx("deps-82-synthetic", "page-offset-00.json")
        d["page"]["offset"] = 90
        expect_error(self, "dependency_page", d, "projection_failed", "invariant:page_offset")
        a = fx("cbom-empty-and-partial-synthetic", "crypto-partial.json")
        a["page"]["offset"] = 30
        expect_error(self, "crypto_assets", a, "projection_failed", "invariant:page_offset")

    def test_empty_lists_only_accept_offset_zero(self):
        n = fx("nonpython-synthetic", "bom-not-compared.json")
        n["page"]["offset"] = 25
        expect_error(self, "bom_candidates", n, "projection_failed", "invariant:page_offset")
        e = fx("cbom-empty-and-partial-synthetic", "crypto-completed-empty.json")
        e["page"]["offset"] = 30
        expect_error(self, "crypto_assets", e, "projection_failed", "invariant:page_offset")
        rel = fx("bom-large-synthetic", "related-none.json")
        rel["page"]["offset"] = 20
        expect_error(self, "bom_related_checks", rel, "projection_failed", "invariant:page_offset")

    def test_last_pages_validate(self):
        for fxn, fname in [("bom-large-synthetic", "candidates-offset-50.json"), ("bom-large-synthetic", "related-shared-offset-40.json"),
                           ("deps-82-synthetic", "page-offset-60.json")]:
            p = fx(fxn, fname)
            name = "bom_candidates" if "candidates" in fname else "bom_related_checks" if "related" in fname else "dependency_page"
            vc.validate_payload(name, p)
            if "truncated" in p["counts"]:
                self.assertTrue(p["counts"]["truncated"], fname)
            self.assertFalse(p["page"]["has_more"], fname)
            self.assertGreater(p["page"]["offset"], 0, fname)


class CorrectionIR04Dependency(unittest.TestCase):
    """UIP-01B-IR-04: omission invariants and node-level coverage for the focus."""

    def test_connectors_omitted_requires_no_edge_and_truthful_flags(self):
        p = fx("deps-paths-synthetic", "paths-all.json")
        n = next(x for x in p["nodes"] if x["role"] == "match" and x["depth"] == 2)
        n["path_state"] = "connectors_omitted"
        expect_error(self, "dependency_page", p, "projection_failed", "invariant:omitted_path")
        p2 = fx("deps-paths-synthetic", "paths-all.json")
        n2 = next(x for x in p2["nodes"] if x["role"] == "match" and x["depth"] == 2)
        n2["path_state"] = "connectors_omitted"
        p2["edges"] = [e for e in p2["edges"] if n2["node_id"] not in (e["from"], e["to"])]
        expect_error(self, "dependency_page", p2, "projection_failed", "invariant:truncation_flags")

    def test_truncation_flags_cannot_be_set_without_an_omission(self):
        p = fx("deps-paths-synthetic", "paths-all.json")
        p["limits"]["connectors_truncated"] = True
        expect_error(self, "dependency_page", p, "projection_failed", "invariant:truncation_flags")

    def test_the_omitted_fixture_still_validates_and_depth_limit_nodes_draw_no_edge(self):
        p = fx("deps-paths-synthetic", "paths-connectors-omitted.json")
        vc.validate_payload("dependency_page", p)
        d = fx("deps-paths-synthetic", "paths-depth-limit.json")
        vc.validate_payload("dependency_page", d)
        for n in d["nodes"]:
            if n["path_state"] == "depth_limit":
                self.assertFalse([e for e in d["edges"] if n["node_id"] in (e["from"], e["to"])])

    def test_the_focus_carries_truthful_node_level_coverage_when_lookup_is_off(self):
        off = fx("deps-paths-synthetic", "paths-lookup-off.json")
        focus = next(n for n in off["nodes"] if n["role"] == "focus")
        self.assertEqual((focus["advisory_lookup"], focus["gap_causes"], focus["flags"]["evidence_gap"]), ("not_run", ["lookup_not_run"], True))
        # the focus stays outside the descendant totals and the match count
        self.assertEqual(off["filter_totals"]["all"], off["filter_totals"]["direct"] + off["filter_totals"]["transitive"])
        self.assertEqual(sum(1 for n in off["nodes"] if n["role"] == "match"), off["page"]["matches_shown"])

    def test_a_focus_that_hides_its_coverage_is_rejected(self):
        off = fx("deps-paths-synthetic", "paths-lookup-off.json")
        focus = next(n for n in off["nodes"] if n["role"] == "focus")
        focus["gap_causes"], focus["flags"]["evidence_gap"] = [], False
        expect_error(self, "dependency_page", off, "projection_failed", "invariant:gap_causes")

    def test_focus_without_a_source_location_is_a_gap_but_not_a_match(self):
        p = fx("deps-82-synthetic", "page-offset-00.json")
        focus = next(n for n in p["nodes"] if n["role"] == "focus")
        focus["has_source_location"] = False
        expect_error(self, "dependency_page", p, "projection_failed", "invariant:gap_causes")
        focus["gap_causes"], focus["flags"]["evidence_gap"] = ["missing_source_location"], True
        vc.validate_payload("dependency_page", p)
        self.assertEqual(p["filter_totals"]["evidence_gaps"], fx("deps-82-synthetic", "page-offset-00.json")["filter_totals"]["evidence_gaps"])


class CorrectionT7FromTheContract(unittest.TestCase):
    """Frozen T7: limits.json equals the section 4.2 values parsed from the contract's own table."""

    def test_limits_equal_the_values_in_the_contract_markdown(self):
        with open(os.path.join(REPO, ".context", "contracts", "UIP-01B.md"), encoding="utf-8") as h:
            text = h.read()
        sect = text[text.index("### 4.2 Bounds"):text.index("### 4.3")]
        L = vc.LIMITS

        def row(key):
            m = re.search(r"^\| `%s`[^|]*\|([^|]*)\|" % key, sect, re.M)
            self.assertIsNotNone(m, key)
            return m.group(1)
        num = lambda s: int(s.replace(",", ""))
        self.assertEqual(num(re.search(r"[0-9][0-9,]+", row("response_max_bytes")).group()), L["response_max_bytes"])
        self.assertEqual(int(re.search(r"\d+", row("dependency_match_page")).group()), L["dependency_match_page"])
        self.assertEqual(int(re.search(r"\d+", row("dependency_connectors_per_page")).group()), L["dependency_connectors_per_page"])
        self.assertEqual(int(re.search(r"\d+", row("dependency_edges_per_page")).group()), L["dependency_edges_per_page"])
        self.assertEqual(int(re.search(r"\d+", row("dependency_path_depth")).group()), L["dependency_path_depth"])
        self.assertEqual(int(re.search(r"\d+", row("context_groups")).group()), L["context_groups"])
        self.assertEqual(int(re.search(r"\d+", row("bom_queue_page")).group()), L["bom_queue_page"])
        self.assertEqual(int(re.search(r"\d+", row("bom_related_page")).group()), L["bom_related_page"])
        self.assertEqual(num(re.search(r"[0-9][0-9,]+", row("offset_max")).group()), L["offset_max"])
        d, m = re.search(r"default (\d+), max (\d+)", row("files_per_group_page")).groups()
        self.assertEqual((int(d), int(m)), (L["files_per_group_page_default"], L["files_per_group_page_max"]))
        n, e = re.findall(r"\d+", row("bom_focused_graph"))[:2]
        self.assertEqual((int(n), int(e)), (L["bom_focused_nodes"], L["bom_focused_edges"]))
        p, nb, tot, edges = [int(x) for x in re.findall(r"\d+", row("bom_full_view_page"))[:4]]
        self.assertEqual((p, nb, tot, edges), (L["bom_full_view_primary"], L["bom_full_view_neighbors"], L["bom_full_view_nodes"], L["bom_full_view_edges"]))
        caps = {}
        for seg in re.search(r"per-payload byte caps[^|]*\|([^|]*)\|", sect).group(1).split(" · "):
            kib = re.search(r"(\d+) KiB", seg)
            for key in re.split(r",\s*", re.sub(r"\s*\d+ KiB.*$", "", seg.strip())):
                caps[key.strip()] = int(kib.group(1)) * 1024
        self.assertEqual(caps, L["payload_max_bytes"])


if __name__ == "__main__":
    unittest.main()
