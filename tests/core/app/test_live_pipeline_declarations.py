"""UIP-10: the live pipeline wiring, in process (no listening server, no scanner, no network, no provider).

``AppState`` is built without a socket; ``scan_all`` is either exercised with a recorded source and fake scan runs, or replaced.
"""
import inspect
import json
import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from opentrace_core.app import server as server_mod
from opentrace_core.app.server import AppState
from opentrace_core.live import runner as live_runner, source as source_mod, source_declarations as sd
from opentrace_core.live.source import SourceRecord

from tests.core.app.test_live_discovery import LABEL, SHA, URL, fixture_bytes, make_identity, sbom_run


class FakeLive:
    advisories = None
    isolation = SimpleNamespace(description="test isolation")


class PipelineBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-livepipe-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.app = AppState(os.path.join(self.dir, "s"), live=FakeLive())
        self.addCleanup(self.app.close)
        handle = self.app.service.create_session()
        self.sid, self.token = handle.session_id, handle.token
        self.ticket = self.app.service.begin_analysis(self.sid, self.token, None)
        self.identity = make_identity(self.sid, self.ticket.generation)
        self.producer = server_mod._AnalysisProducer(self.ticket)
        self.sbom = fixture_bytes("syft-sbom.cdx.json")

    def tree(self, files):
        root = os.path.join(self.dir, "tree")
        shutil.rmtree(root, ignore_errors=True)
        for rel, data in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(data)
        return root

    def viseron_files(self):
        return {n: fixture_bytes("source", n) for n in sorted(os.listdir(os.path.join(os.path.dirname(__file__), "..", "live", "fixtures", "viseron", "source")))}

    def fake_scan_all(self, files, cancel_after_collect=False):
        source = SourceRecord(URL, SHA, "b" * 40, True, 1, 1, "c" * 64)
        root = self.tree(files)
        run = sbom_run(self.sbom)

        def scan_all(config, service, ticket, identity, on_stage=None, declarations_sink=None):
            if declarations_sink is not None:
                declarations_sink.update(sd.collect(root, URL, SHA, cancel=ticket.cancel_event))
            if cancel_after_collect:
                ticket.cancel_event.set()
            return source, [run], None, []
        return scan_all

    def run_pipeline(self, scan_all):
        with mock.patch.object(live_runner, "scan_all", scan_all):
            return server_mod._run_live_pipeline(self.app, self.sid, self.token, self.ticket, self.producer, None, None, identity=self.identity)


class LivePipelineTest(PipelineBase):
    def test_a_submitted_python_repository_gets_real_comparisons_through_the_existing_workbench(self):
        payload = self.run_pipeline(self.fake_scan_all(self.viseron_files()))
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["identity"]["configuration"], LABEL)
        self.assertEqual(payload["summary"]["gaps"]["status"], "compared")
        self.assertEqual(payload["summary"]["gaps"]["collection"]["software"]["state"], "completed")
        analysis = self.app.analyses[self.sid]
        self.assertEqual(analysis.gaps["status"], "compared")
        page = analysis.views.bom_candidates()
        self.assertEqual(page["mode"], "discovery_compared")
        self.assertEqual(page["counts"]["candidates_total"], 9)
        self.assertEqual(page["binding"]["repository"]["name"], "viseron")
        names = {r.name for r in self.app.service.list_artifacts(self.sid, self.token)}
        self.assertIn("source-declarations.json", names)
        self.assertIn("bombridge-result.json", names)
        self.assertNotIn("frigate", json.dumps([payload, page]).lower())

    def test_the_legacy_assessment_is_assessed_with_the_same_label(self):
        self.run_pipeline(self.fake_scan_all(self.viseron_files()))
        analysis = self.app.analyses[self.sid]
        self.assertEqual(analysis.assessment.binding["configuration"], LABEL)
        self.assertEqual(analysis.gaps["assessment"].binding["configuration"], LABEL)

    def test_an_npm_only_repository_completes_with_unsupported_and_keeps_every_inventory_view(self):
        payload = self.run_pipeline(self.fake_scan_all({"package.json": b"{}", "package-lock.json": b"{}", "index.js": b"1\n"}))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["summary"]["gaps"]["status"], "not_compared")
        self.assertEqual(payload["summary"]["gaps"]["collection"]["software"], {"state": "unsupported", "reason_code": "unsupported_ecosystem"})
        self.assertTrue(payload["summary"]["cards"])        # the inventory views are intact
        self.assertEqual(self.app.analyses[self.sid].views.bom_candidates()["mode"], "not_compared")

    def test_a_collector_failure_never_discards_the_inventory_views(self):
        def scan_all(config, service, ticket, identity, on_stage=None, declarations_sink=None):
            declarations_sink.update({"status": "failed", "code": "collector_error"})
            return SourceRecord(URL, SHA, "b" * 40, True, 1, 1, "c" * 64), [sbom_run(self.sbom)], None, []
        payload = self.run_pipeline(scan_all)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["summary"]["gaps"]["collection"]["software"], {"state": "failed", "reason_code": "upstream_failed"})

    def test_cancel_after_collection_publishes_no_analysis_and_no_late_result(self):
        payload = self.run_pipeline(self.fake_scan_all(self.viseron_files(), cancel_after_collect=True))
        self.assertEqual(payload, {"ok": False, "code": "cancelled"})
        self.assertNotIn(self.sid, self.app.analyses)

    def test_cancel_during_the_discovery_assessment_publishes_nothing(self):
        from opentrace_core.app import live_discovery

        def cancelling(*a, **kw):
            self.ticket.cancel_event.set()
            return SimpleNamespace(status="cancelled", errors=[], assessment=None)
        with mock.patch.object(live_discovery, "assess", cancelling):
            payload = self.run_pipeline(self.fake_scan_all(self.viseron_files()))
        self.assertEqual(payload, {"ok": False, "code": "cancelled"})
        self.assertNotIn(self.sid, self.app.analyses)

    def test_end_session_after_the_run_removes_the_session_artifacts(self):
        self.run_pipeline(self.fake_scan_all(self.viseron_files()))
        self.app.service.end_session(self.sid, self.token)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "s", self.sid)))

    def test_the_recorded_demo_path_is_not_touched(self):
        src = inspect.getsource(server_mod.Handler._discover_gaps)
        self.assertIn('inv_id = "inv:syft-source-dir"', src)
        self.assertIsNone(server_mod._Analysis(self.ticket, self.identity, [], {}).collection)


class ScanAllSinkTest(unittest.TestCase):
    """``scan_all`` keeps its defaults and return arity; the sink is the only addition."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-scanall-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        from opentrace_core.session import SessionService
        self.service = SessionService(os.path.join(self.dir, "s"))
        handle = self.service.create_session()
        self.ticket = self.service.begin_analysis(handle.session_id, handle.token, None)
        self.identity = make_identity(handle.session_id, self.ticket.generation)
        self.cfg = SimpleNamespace(worker=None, aibom=None, advisories=None, source_check_targets=None, scanners=None, isolation=None,
                                   allow_protocol="file", remote_for=lambda o, n: "x")
        self.workspace_seen = []

    def acquire(self, files):
        def acquire(remote, sha, workspace, **kw):
            self.workspace_seen.append(workspace)
            for rel, data in files.items():
                path = os.path.join(workspace, "src", *rel.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as handle:
                    handle.write(data)
            return SourceRecord(URL, SHA, "b" * 40, True, 1, 1, "c" * 64)
        return acquire

    def scan(self, files, **kw):
        runs = {"syft": sbom_run(fixture_bytes("syft-sbom.cdx.json"))}
        with mock.patch.object(source_mod, "acquire", self.acquire(files)), \
                mock.patch.object(live_runner, "run_scanner", lambda spec, *a, **k: runs["syft"]):
            return live_runner.scan_all(self.cfg, self.service, self.ticket, self.identity, **kw)

    def test_the_signature_and_return_arity_are_backward_compatible(self):
        params = inspect.signature(live_runner.scan_all).parameters
        self.assertIsNone(params["on_stage"].default)
        self.assertIsNone(params["declarations_sink"].default)
        self.assertEqual(len(self.scan({"requirements.txt": b"a\n"})), 4)

    def test_without_a_sink_the_collector_does_not_run(self):
        with mock.patch.object(sd, "collect", side_effect=AssertionError("collector ran")):
            self.assertEqual(len(self.scan({"requirements.txt": b"a\n"})), 4)

    def test_the_sink_is_filled_before_the_workspace_is_removed(self):
        sink = {}
        self.scan({"requirements.txt": b"flask==2.0\n", "web/package.json": b"{}"}, declarations_sink=sink)
        self.assertEqual(sink["status"], "collected")
        self.assertEqual([r["path"] for r in sink["record"]["requirement_files"]], ["requirements.txt"])
        self.assertEqual(sink["summary"]["unsupported"]["count"], 1)
        self.assertFalse(os.path.exists(self.workspace_seen[0]))                       # cleanup still verified absent

    def test_a_collector_fault_is_a_typed_sink_state_and_the_scan_still_returns(self):
        sink = {"stale": True}
        with mock.patch.object(sd, "collect", side_effect=RuntimeError("boom")):
            out = self.scan({"requirements.txt": b"a\n"}, declarations_sink=sink)
        self.assertEqual(sink, {"status": "failed", "code": "collector_error"})
        self.assertEqual(len(out), 4)

    def test_cancel_before_collection_leaves_a_cancelled_sink_and_still_cleans_up(self):
        self.ticket.cancel_event.set()
        sink = {}
        self.scan({"requirements.txt": b"a\n"}, declarations_sink=sink)
        self.assertEqual(sink["status"], "cancelled")
        self.assertFalse(os.path.exists(self.workspace_seen[0]))


if __name__ == "__main__":
    unittest.main()
