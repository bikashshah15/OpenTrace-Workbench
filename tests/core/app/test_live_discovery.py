"""UIP-10: live requirement -> SBOM connections, in process (no listening server, no scanner, no network, no provider).

The recorded Viseron v3.7.0 inputs are a CAPTURED fixture (donor-captured Syft SBOM and requirement files, see
``tests/core/live/fixtures/viseron/PROVENANCE.md``); the comparison with the donor oracle is a differential check, not a live validation.
"""
import copy
import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from opentrace_core.app import live_discovery, server as server_mod
from opentrace_core.app.views import Views, ViewError
from opentrace_core.bombridge_adapter import AdapterContext, ArtifactRecord
from opentrace_core.intake.identity import build_identity
from opentrace_core.intake.url import parse_repository_url
from opentrace_core.live import bundle as live_bundle, scanners as sc, source_declarations as sd
from opentrace_core.live.source import SourceRecord
from opentrace_core.live.view_source import LiveSource
from opentrace_core.session import SessionError, SessionService

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
FIX = os.path.join(ROOT, "tests", "core", "live", "fixtures", "viseron")
URL = "https://github.com/roflcoopter/viseron"
SHA = "699c65bc3eaec09eb3ade8b82ef1adec106298fe"
SBOM_SHA = "3a39cbc92c5826f2c4f668c86c45eddef547e6ab76e1c4cd1106c58c043f1888"
DONOR_SBOM_SHA = "c1480dcb032048a402ead3dc0e889f3e8a47b982e32f4345cb5bc066db7bb750"
LABEL = "scan-profile:opentrace.scan.default/1;target-environment:not-recorded"


def fixture_bytes(*parts):
    with open(os.path.join(FIX, *parts), "rb") as handle:
        return handle.read()


def make_identity(sid, generation, url=URL, sha=SHA):
    parsed = parse_repository_url(url)
    resolution = SimpleNamespace(owner=parsed.owner, name=parsed.name, canonical_url=url, requested={"kind": "tag", "text": "v3.7.0", "origin": "url_tree"},
                                 commit_sha=sha, resolved_at="2026-11-15T12:00:00Z", basis="test", manual_corroboration=False, default_branch="main")
    scan = {"profile_id": "opentrace.scan.default/1", "inventories": ["cbom", "sbom"], "scope": "repository_root"}
    return build_identity(parsed, None, resolution, scan, {"session_id": sid, "generation": generation})


def sbom_run(data, sha=SHA):
    run = sc.ScanRun(scanner="syft", kind="sbom", tool="Syft", pinned_version="1.51.1", version="1.51.1", isolation="test", scope={"revision": sha})
    run.outcome, run.data, run.size, run.sha256 = "acquired", data, len(data), hashlib.sha256(data).hexdigest()
    run.record_count, run.record_count_unit, run.spec_version, run.exit_code = len(json.loads(data)["components"]), "components", "1.6", 0
    run.record_counts = {"components": run.record_count}
    return run


class Harness(unittest.TestCase):
    """A real SessionService and the real live bundle builder; the scanners and the checkout are replaced by recorded bytes."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-livedisc-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.service = SessionService(os.path.join(self.dir, "s"))
        handle = self.service.create_session()
        self.sid, self.token = handle.session_id, handle.token

    def begin(self, url=URL, sha=SHA, sbom=None):
        self.ticket = self.service.begin_analysis(self.sid, self.token, None)
        self.identity = make_identity(self.sid, self.ticket.generation, url, sha)
        self.session = {"session_id": self.sid, "generation": self.ticket.generation}
        data = sbom if sbom is not None else fixture_bytes("syft-sbom.cdx.json")
        source = SourceRecord(url, sha, "b" * 40, True, 1, 1, "c" * 64)
        self.parts, self.records, self.names, self.raw = live_bundle.build(self.identity, source, [sbom_run(data, sha)], self.sid, self.ticket.generation)
        for aid, name in self.names.items():
            self.service.commit_artifact(self.ticket, name, self.raw[aid], "application/json", "original")
        analysis = SimpleNamespace(identity=self.identity, ticket=self.ticket, records=self.records, names=self.names, mode="live", gaps=None, collection=None,
                                   assessment=None, configuration=live_bundle.configuration_label(self.identity))
        analysis.read = lambda aid: self.service.read_artifact(self.sid, self.token, analysis.names[aid]).data
        analysis.context = AdapterContext(self.identity, self.session, analysis.configuration,
                                          lambda: dict(self.session) if not self.ticket.cancel_event.is_set() else None)
        self.analysis = analysis
        return analysis

    def tree(self, files):
        root = os.path.join(self.dir, "tree")
        shutil.rmtree(root, ignore_errors=True)
        os.makedirs(root)
        for rel, data in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(data)
        return root

    def viseron_tree(self, extra=None):
        files = {n: fixture_bytes("source", n) for n in sorted(os.listdir(os.path.join(FIX, "source")))}
        files.update(extra or {})
        return self.tree(files)

    def collect(self, root, **kw):
        return sd.collect(root, URL, SHA, cancel=self.ticket.cancel_event, **kw)

    def run_discovery(self, sink):
        return live_discovery.run(self.analysis, self.ticket, self.service, bundle_parts=self.parts, records=self.records, sink=sink)

    def artifacts(self):
        return {r.name for r in self.service.list_artifacts(self.sid, self.token)}

    def views(self):
        a = self.analysis
        a.views = Views(LiveSource(), a)
        a.state = "complete"
        return a.views


class ConfigurationLabelTest(Harness):
    def test_one_deterministic_label_reaches_capture_context_and_both_assessments(self):
        a = self.begin()
        self.assertEqual(live_bundle.configuration_label(self.identity), LABEL)
        self.assertEqual(self.parts["capture"]["configuration"], LABEL)
        self.assertEqual(a.context.expected_configuration, LABEL)
        self.assertIn("configuration", self.parts["capture"]["unknown"])        # target environment uncertainty is preserved
        self.assertEqual(live_bundle.configuration_label(self.identity), live_bundle.configuration_label(self.identity))
        gaps, coll = self.run_discovery(self.collect(self.viseron_tree()))
        a.assessment = None
        binding = server_mod.build_binding(a) if hasattr(server_mod, "build_binding") else None
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(gaps["assessment"].binding["configuration"], LABEL)

    def test_the_label_is_in_the_analysis_payload_for_live_and_absent_for_nothing_else(self):
        a = self.begin()
        a.summary = {}
        payload = server_mod._analysis_payload(a)
        self.assertEqual(payload["identity"]["configuration"], LABEL)


class ViseronDifferentialTest(Harness):
    """CAPTURED Viseron v3.7.0 inputs against the donor oracle (overlay full-donor run). Not an independent live validation."""

    def test_the_donor_inputs_are_what_the_provenance_records(self):
        current_sha = hashlib.sha256(fixture_bytes("syft-sbom.cdx.json")).hexdigest()
        self.assertEqual(current_sha, SBOM_SHA)  # sanitized export bytes, recorded in the export provenance note
        self.assertNotEqual(current_sha, DONOR_SBOM_SHA)  # original donor capture hash, retained in this test for provenance
        donor = json.loads(fixture_bytes("donor-source-declarations.json"))
        self.assertEqual((donor["repository"], donor["revision"]), (URL, SHA))
        listed = {}
        for comp in json.loads(fixture_bytes("syft-sbom.cdx.json"))["components"]:
            if comp.get("type") == "file":
                listed[comp["name"].rsplit("/", 1)[-1]] = [h["content"] for h in comp["hashes"] if h["alg"] == "SHA-256"]
        for rf in donor["requirement_files"]:
            self.assertEqual(hashlib.sha256(fixture_bytes("source", rf["path"])).hexdigest(), rf["sha256"], rf["path"])
            self.assertEqual(listed[rf["path"]], [rf["sha256"]], rf["path"])          # the SBOM lists the file with the recorded digest

    def test_every_requirement_candidate_matches_the_donor_oracle_declaration_by_declaration(self):
        self.begin()
        out = self.collect(self.viseron_tree())
        donor = json.loads(fixture_bytes("donor-source-declarations.json"))
        mine = {r["path"]: r for r in out["record"]["requirement_files"]}
        for rf in donor["requirement_files"]:        # same files, bytes, digests, line and name counts as the donor collector
            for key in ("sha256", "bytes", "declaration_lines", "named_requirements"):
                self.assertEqual(mine[rf["path"]][key], rf[key], (rf["path"], key))
        gaps, coll = self.run_discovery(out)
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(coll["software"], {"state": "completed", "reason_code": None})
        result = gaps["assessment"].result
        got = sorted(({"category": c["category"], "group": c["group"], "title": c["title"], "evidence_location": c["evidence_location"],
                       "selected_inventory": c["selected_inventory"]} for c in result["discovery"]["candidates"] if c["group"].startswith("requirements:")),
                     key=lambda c: (c["category"], c["group"], c["title"]))
        oracle = json.loads(fixture_bytes("donor-requirement-oracle.json"))
        self.assertEqual(got, oracle["candidates"])                         # 8 missing_component + 1 unknown_coverage (markers), row for row
        counts = result["discovery"]["counts"]["requirements"]
        self.assertEqual({k: counts[k] for k in ("files", "named_requirements", "represented", "missing")},
                         {k: oracle["requirements_counts"][k] for k in ("files", "named_requirements", "represented", "missing")})
        self.assertEqual(self.artifacts() & {"source-declarations.json"}, {"source-declarations.json"})

    def test_markers_are_never_evaluated_they_become_unknown_coverage(self):
        self.begin()
        gaps, _ = self.run_discovery(self.collect(self.viseron_tree()))
        marker = [c for c in gaps["assessment"].result["discovery"]["candidates"] if "environment markers" in c["title"]]
        self.assertEqual(len(marker), 1)
        self.assertEqual(marker[0]["category"], "unknown_coverage")


class CapabilityStatesTest(Harness):
    def states(self, files, **kw):
        self.begin()
        sink = self.collect(self.tree(files), **kw)
        gaps, coll = self.run_discovery(sink)
        return gaps, coll

    def test_complete_collection_and_comparison_is_completed(self):
        gaps, coll = self.states({n: fixture_bytes("source", n) for n in os.listdir(os.path.join(FIX, "source"))})
        self.assertEqual(coll["software"], {"state": "completed", "reason_code": None})

    def test_unsupported_ecosystem_only_is_unsupported_not_an_empty_list(self):
        gaps, coll = self.states({"package.json": b"{}", "package-lock.json": b"{}", "index.js": b"1\n"})
        self.assertEqual((gaps["status"], gaps["code"]), ("not_compared", "unsupported_ecosystem"))
        self.assertEqual(coll["software"], {"state": "unsupported", "reason_code": "unsupported_ecosystem"})
        self.assertEqual(coll["cryptography"], {"state": "unsupported", "reason_code": "unsupported_ecosystem"})

    def test_no_declaration_files_is_completed_empty_which_is_not_unsupported(self):
        gaps, coll = self.states({"main.py": b"print(1)\n"})
        # the frozen contract allows completed_empty only beside a performed comparison, so the comparison runs and has zero candidates
        self.assertEqual((gaps["status"], coll["code"], coll["software"]), ("compared", "no_requirement_files", {"state": "completed_empty", "reason_code": "no_applicable_assets"}))
        self.assertEqual(gaps["assessment"].result["discovery"]["candidates"], [])

    def test_requirement_files_with_no_names_are_completed_empty(self):
        gaps, coll = self.states({"requirements.txt": b"# nothing\n"})
        self.assertEqual((gaps["status"], coll["code"], coll["software"]["state"]), ("compared", "no_named_requirements", "completed_empty"))
        self.assertEqual(gaps["assessment"].result["discovery"]["candidates"], [])

    def test_unevaluated_directives_that_yield_candidates_are_not_completed_empty(self):
        # UIP-10-IR-01 correction: ``-r other.txt`` is not followed and produces an unknown-coverage candidate, so the comparison is not empty.
        # (Before the correction this case was asserted to be completed_empty with named_requirements == 0.)
        gaps, coll = self.states({"requirements.txt": b"# nothing\n-r other.txt\n"})
        cands = gaps["assessment"].result["discovery"]["candidates"]
        self.assertTrue(cands)
        self.assertEqual({c["category"] for c in cands}, {"unknown_coverage"})
        self.assertEqual((gaps["status"], coll["code"], coll["software"]["state"]), ("compared", "completed", "completed"))

    def test_mixed_ecosystems_compare_python_and_report_partial_coverage(self):
        files = {n: fixture_bytes("source", n) for n in os.listdir(os.path.join(FIX, "source"))}
        files.update({"frontend/package-lock.json": b"{}", "pyproject.toml": b"[project]\n"})
        gaps, coll = self.states(files)
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(coll["software"], {"state": "partial", "reason_code": "partial_coverage"})
        self.assertEqual(coll["collection"]["unsupported"]["count"], 2)

    def test_skipped_matching_file_is_partial_and_never_counted_as_compared(self):
        files = {"requirements.txt": b"flask==2.0\n", "requirements-bad.txt": b"\xff\n"}
        gaps, coll = self.states(files)
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(coll["software"]["state"], "partial")
        self.assertEqual(coll["collection"]["skipped"]["by_reason"], {"not_utf8": 1})

    def test_every_matching_file_skipped_is_failed_not_partial(self):
        gaps, coll = self.states({"requirements.txt": b"\xff\n"})
        # UIP-12: a repository with no recognized source file has a complete empty crypto result, which needs a performed (crypto-only) comparison,
        # so gaps is "compared" with zero candidates; the software state is unchanged
        self.assertEqual((gaps["status"], coll["code"], coll["software"]), ("compared", "no_usable_requirement_files", {"state": "failed", "reason_code": "output_invalid"}))
        self.assertEqual(coll["cryptography"], {"state": "completed_empty", "reason_code": "no_applicable_assets"})

    def test_interrupted_traversal_with_nothing_collected_is_failed_with_timeout(self):
        ticks = iter(range(1000))
        gaps, coll = self.states({"x.py": b"1\n", "requirements.txt": b"a\n"}, clock=lambda: float(next(ticks)), budget=2.0)
        self.assertEqual((gaps["code"], coll["software"]), ("collector_timeout", {"state": "failed", "reason_code": "timeout"}))
        self.assertFalse(coll["collection"]["traversal"]["complete"])
        self.assertEqual(coll["collection"]["traversal"]["count_kind"], "at_least")

    def test_interrupted_traversal_after_some_files_is_partial_with_lower_bound_counts(self):
        self.begin()
        root = self.tree({"requirements.txt": b"flask==2.0\n", "zdir/requirements.txt": b"six\n", "zdir/more.py": b"1\n"})
        with mock.patch.object(sd, "MAX_ENTRIES", 2):
            sink = self.collect(root)
        gaps, coll = self.run_discovery(sink)
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(coll["software"], {"state": "partial", "reason_code": "partial_coverage"})
        self.assertEqual(coll["collection"]["traversal"]["count_kind"], "at_least")

    def test_not_attempted_and_collector_failure_are_distinct_from_everything_else(self):
        self.begin()
        gaps, coll = self.run_discovery({})
        self.assertEqual((gaps["code"], coll["software"]), ("collection_not_run", {"state": "not_run", "reason_code": "not_configured"}))
        gaps, coll = self.run_discovery({"status": "failed", "code": "collector_error"})
        self.assertEqual((gaps["code"], coll["software"]), ("collector_failed", {"state": "failed", "reason_code": "upstream_failed"}))

    def test_an_unexpected_fault_is_typed_and_leaves_the_inventory_views(self):
        self.begin()
        with mock.patch.object(live_discovery, "_run", side_effect=RuntimeError("boom /private/path")):
            gaps, coll = self.run_discovery({"status": "collected"})
        self.assertEqual((gaps["status"], gaps["code"], gaps["detail"]), ("not_compared", "collector_failed", "RuntimeError"))
        self.assertNotIn("/private/path", json.dumps(coll))

    def test_candidate_over_limit_is_a_typed_failure_not_a_crash(self):
        self.begin()
        sink = self.collect(self.viseron_tree())
        with mock.patch("opentrace_core.bombridge_adapter.validation.MAX_DISCOVERY_CANDIDATES", 3):
            gaps, coll = self.run_discovery(sink)
        self.assertEqual((gaps["status"], gaps["code"]), ("not_compared", "discovery_candidates_over_limit"))
        self.assertEqual(coll["software"]["state"], "failed")
        self.assertEqual(self.analysis.read("art:inv:syft-source-dir")[:1], b"{")        # the inventory view is untouched


class MetadataSelectionAndBindingTest(Harness):
    def test_the_sbom_is_selected_by_metadata_so_any_inventory_id_works(self):
        self.begin()
        parts = copy.deepcopy(self.parts)
        inv = next(i for i in parts["capture"]["inventories"] if i["kind"] == "sbom")
        self.assertEqual(inv["inventory_id"], "inv:syft-source-dir")           # the id is incidental: selection never names it
        src = ""
        for rel in ("app/live_discovery.py", "live/source_declarations.py"):
            with open(os.path.join(ROOT, "src/core/opentrace_core", rel), encoding="utf-8") as handle:
                src += handle.read()
        for forbidden in ("DemoSource", "inv:syft-source-dir", "frigate", "Frigate", "demo."):
            self.assertNotIn(forbidden, src)

    def test_a_tampered_sbom_is_not_compared(self):
        self.begin()
        sink = self.collect(self.viseron_tree())
        bad = copy.deepcopy(self.parts)
        next(i for i in bad["capture"]["inventories"] if i["kind"] == "sbom")["source_sha256"] = "0" * 64
        gaps, coll = live_discovery.run(self.analysis, self.ticket, self.service, bundle_parts=bad, records=self.records, sink=sink)
        self.assertEqual((gaps["code"], coll["software"]["state"]), ("inventory_digest_mismatch", "failed"))

    def test_a_missing_or_altered_copy_makes_only_that_file_unknown_coverage(self):
        self.begin()
        sink = self.collect(self.viseron_tree())
        sink["copies"]["requirements_ci.txt"] = b"altered\n"
        gaps, coll = self.run_discovery(sink)
        self.assertEqual(gaps["status"], "compared")
        titles = [c["title"] for c in gaps["assessment"].result["discovery"]["candidates"]]
        self.assertTrue(any("requirements_ci.txt" in t and "missing or differs" in t for t in titles))
        self.assertFalse(any("requirements_ci.txt" in t and "has no record" in t for t in titles))

    def test_a_record_for_another_revision_is_refused(self):
        self.begin()
        sink = self.collect(self.viseron_tree())
        sink["record"] = dict(sink["record"], revision="f" * 40)
        sink["record_sha256"] = hashlib.sha256(sd.canonical_bytes(sink["record"])).hexdigest()
        gaps, _ = self.run_discovery(sink)
        self.assertEqual(gaps["code"], "declarations_scope_mismatch")

    def test_a_record_that_does_not_match_its_digest_is_refused(self):
        self.begin()
        sink = self.collect(self.viseron_tree())
        sink["record_sha256"] = "0" * 64
        gaps, _ = self.run_discovery(sink)
        self.assertEqual(gaps["code"], "declarations_digest_mismatch")

    def test_no_frigate_data_appears_for_another_repository(self):
        self.begin()
        gaps, coll = self.run_discovery(self.collect(self.viseron_tree()))
        a = self.analysis
        a.gaps, a.collection = gaps, coll
        v = self.views()
        outputs = [v.gaps(0, None, None, ""), v.gaps_summary(), v.bom_candidates()]
        text = json.dumps(outputs).lower()
        self.assertNotIn("frigate", text)
        self.assertNotIn("tflite_runtime", text)
        self.assertIn("viseron", json.dumps(v.bom_candidates()["binding"]).lower())


class WorkspaceRoutesTest(Harness):
    """The existing BOM v1 projections over a live analysis (in process, through ``Views``)."""

    def setUp(self):
        super().setUp()
        self.begin()
        gaps, coll = self.run_discovery(self.collect(self.viseron_tree()))
        self.analysis.gaps, self.analysis.collection = gaps, coll
        self.v = self.views()

    def test_candidates_use_the_real_collection_state_not_candidate_counts(self):
        page = self.v.bom_candidates()
        self.assertEqual(page["mode"], "discovery_compared")
        caps = {c["family"]: c for c in page["capabilities"]}
        self.assertEqual(caps["software"], {"family": "software", "state": "completed", "reason_code": None})
        # UIP-12: cryptography is now computed (this fixture tree holds requirement files only, so no recognized source file exists: a complete empty result)
        self.assertEqual((caps["cryptography"]["state"], caps["cryptography"]["reason_code"]), ("completed_empty", "no_applicable_assets"))
        # UIP-13 (planned compatibility exception, contract section 6 row 7): a tree with no model-source file in any recognized form is
        # `unsupported/unsupported_ecosystem` (`no_recognized_source`) for models; `other` stays not run
        self.assertEqual((caps["ai_model"]["state"], caps["ai_model"]["reason_code"]), ("unsupported", "unsupported_ecosystem"))
        self.assertEqual((caps["other"]["state"], caps["other"]["reason_code"]), ("not_run", "not_configured"))
        self.assertEqual(page["counts"]["candidates_total"], 9)
        self.assertEqual(page["counts"]["family_counts"]["software"], 9)
        self.assertEqual(page["binding"]["assessment"]["configuration"], LABEL)

    def test_the_candidate_graph_and_related_checks_resolve_for_a_live_candidate(self):
        page = self.v.bom_candidates()
        item = next(i for i in page["items"] if i["category"] == "missing_component")
        graph = self.v.bom_graph(scope_kind="focused_candidate", candidate_id=item["item_id"])
        self.assertTrue(graph["nodes"])
        related = self.v.bom_related_checks(subject_kind="record", subject_id=graph["nodes"][0]["node_id"])
        self.assertIn("items", related)

    def test_the_gaps_view_carries_the_truthful_collection_facts(self):
        page = self.v.gaps(0, None, None, "")
        coll = page["collection"]
        self.assertEqual(coll["collection"]["collected"], 6)
        self.assertTrue(coll["collection"]["traversal"]["complete"])
        self.assertEqual(coll["record_sha256"], self.analysis.collection["record_sha256"])

    def test_the_frozen_view_contracts_accept_the_live_candidates_graph_and_related_payloads(self):
        from opentrace_core.app import view_contracts
        page = self.v.bom_candidates()
        view_contracts.validate_payload("bom_candidates", page)
        item = next(i for i in page["items"] if i["category"] == "missing_component")
        graph = self.v.bom_graph(scope_kind="focused_candidate", candidate_id=item["item_id"])
        view_contracts.validate_payload("bom_graph", graph)
        view_contracts.validate_payload("bom_related_checks", self.v.bom_related_checks(subject_kind="record", subject_id=graph["nodes"][0]["node_id"]))


class NotComparedRoutesTest(Harness):
    def test_every_live_capability_state_passes_the_frozen_bom_candidates_contract(self):
        from opentrace_core.app import view_contracts
        cases = {
            "unsupported": {"package.json": b"{}", "index.js": b"1\n"},
            "completed_empty": {"main.py": b"1\n"},
            "failed": {"requirements.txt": b"\xff\n", "index.js": b"1\n"},
            "partial": {"requirements.txt": b"flask==2.0\n", "frontend/package-lock.json": b"{}"},
            "completed": {"requirements.txt": b"flask==2.0\n"},
        }
        for expected, files in cases.items():
            with self.subTest(expected):
                self.begin()
                try:
                    gaps, coll = self.run_discovery(self.collect(self.tree(files)))
                    self.analysis.gaps, self.analysis.collection = gaps, coll
                    page = self.views().bom_candidates()
                    view_contracts.validate_payload("bom_candidates", page)
                    self.assertEqual({c["family"]: c for c in page["capabilities"]}["software"]["state"], expected)
                    self.assertEqual(page["mode"], "not_compared" if expected in ("unsupported", "failed") else "discovery_compared")
                finally:
                    self.service.finish(self.ticket, "complete")
        
    def test_unsupported_ecosystem_shows_unsupported_and_empty_list_is_not_green(self):
        self.begin()
        gaps, coll = self.run_discovery(self.collect(self.tree({"package.json": b"{}", "index.js": b"1\n"})))
        a = self.analysis
        a.gaps, a.collection = gaps, coll
        page = self.views().bom_candidates()
        self.assertEqual(page["mode"], "not_compared")
        self.assertEqual(page["status_detail"]["code"], "unsupported_ecosystem")
        caps = {c["family"]: c for c in page["capabilities"]}
        self.assertEqual((caps["software"]["state"], caps["software"]["reason_code"]), ("unsupported", "unsupported_ecosystem"))
        self.assertEqual(page["items"], [])
        self.assertEqual(self.views().gaps_summary()["collection"]["software"]["state"], "unsupported")

    def test_recorded_case_capabilities_are_unchanged_without_a_collection(self):
        self.begin()
        a = self.analysis
        a.gaps, a.collection = None, None
        with self.assertRaises(ViewError):
            self.views().gaps(0, None, None, "")
        page = self.views().bom_candidates()
        self.assertEqual({c["state"] for c in page["capabilities"]}, {"not_run"})
        self.assertEqual({c["reason_code"] for c in page["capabilities"]}, {"not_configured"})


class LifecycleTest(Harness):
    def test_cancel_before_collection_is_used_raises_and_publishes_nothing(self):
        self.begin()
        sink = self.collect(self.viseron_tree())
        self.ticket.cancel_event.set()
        with self.assertRaises(SessionError):
            self.run_discovery(sink)
        self.assertNotIn("source-declarations.json", self.artifacts())
        self.assertIsNone(self.analysis.gaps)

    def test_a_cancelled_collection_result_never_becomes_a_comparison(self):
        self.begin()
        self.ticket.cancel_event.set()
        sink = self.collect(self.viseron_tree())
        self.assertEqual(sink["status"], "cancelled")
        with self.assertRaises(SessionError):
            self.run_discovery(sink)
        self.assertNotIn("source-declarations.json", self.artifacts())

    def test_cancel_during_assessment_raises_and_the_assessment_is_discarded(self):
        self.begin()
        sink = self.collect(self.viseron_tree())

        def cancelling(*a, **kw):
            self.ticket.cancel_event.set()
            return SimpleNamespace(status="cancelled", errors=[], assessment=None)
        with mock.patch.object(live_discovery, "assess", cancelling):
            with self.assertRaises(SessionError):
                self.run_discovery(sink)

    def test_a_superseded_generation_cannot_publish_the_derived_artifact(self):
        self.begin()
        sink = self.collect(self.viseron_tree())
        old_ticket = self.ticket
        self.service.finish(old_ticket, "complete")
        self.service.begin_analysis(self.sid, self.token, None)          # a new generation supersedes the old ticket
        with self.assertRaises(SessionError):
            live_discovery.run(self.analysis, old_ticket, self.service, bundle_parts=self.parts, records=self.records, sink=sink)
        self.assertNotIn("source-declarations.json", self.artifacts())

    def test_end_session_during_the_run_leaves_nothing_behind(self):
        self.begin()
        sink = self.collect(self.viseron_tree())
        self.service.end_session(self.sid, self.token)
        with self.assertRaises(SessionError):
            self.run_discovery(sink)


if __name__ == "__main__":
    unittest.main()
