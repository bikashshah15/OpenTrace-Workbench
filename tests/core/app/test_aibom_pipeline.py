"""UIP-07C pipeline: the optional AI phase through the real one-click scan job (stage table P7, frozen validators, original bytes, AI tab with A1),
flag-off identity, provenance option A, cancellation, End session, cleanup-unverified. The AI worker/gateway are replaced at the ONE boundary
(``aibom_worker_client.run``); everything downstream is the real code. No network, no provider, no real key."""
import copy
import hashlib
import json
import threading
import time
import types
import unittest

from opentrace_core.app import scan_jobs, view_contracts as vc
from opentrace_core.live import aibom_cisco as ac, aibom_worker_client as wc, runner as live_runner, scanners as sc
from tests.core.app.test_scan_jobs import ScanBase, wait_for
from tests.core.live import aibom_support as S
from tests.core.live.test_live_app import URL

AI = "/api/workbench/v1/ai-assets"
MODEL = S.comp("llama-7b", "machine-learning-model", "app/main.py", 9, "model", ref="llama-7b_app/main.py_9")
LIBS = [S.comp("openai"), S.comp("langchain", line=2)]
PAIRS = LIBS + [MODEL]
FILES_AIBOM = {"package-lock.json": b'{"name":"w","lockfileVersion":3,"packages":{}}\n', "src/index.js": b"console.log(1)\n", "requirements.txt": b"openai\nlangchain\n",
               ".aibom.yaml": b"components: []\n", "app/main.py": b"model = 'llama-7b'\n"}


class FakeAibomClient:
    """Stands in for ``AibomClient`` only where LiveConfig asks questions; the run itself is patched at ``aibom_worker_client.run``."""

    def public(self, requested):
        return {"requested": bool(requested), "available": True, "reason": None, "provider": "openai", "host": "api.openai.com", "model": "gpt-6-luna",
                "sends": "repository file names and code excerpts chosen by the classifier"}


def ai_run(source, *, data=None, completeness="verified", counts=None, outcome="acquired", reason=None, warnings=(), unit_count=None):
    run = wc.new_run(source)
    run.version = "1.10.1"
    run.outcome, run.reason, run.warnings = outcome, reason, list(warnings)
    if outcome == "acquired":
        data = data if data is not None else S.cdx_bytes(PAIRS)
        n = len(json.loads(data)["components"])
        run.data, run.size, run.sha256, run.spec_version = data, len(data), hashlib.sha256(data).hexdigest(), "1.6"
        run.record_count, run.record_count_unit, run.record_counts = n, "components", dict({"components": n}, **(counts or {}))
        run.completeness = completeness
        run.exit_code = 0
    elif outcome == "failed" and data is not None:
        run.rejected_sha256 = hashlib.sha256(data).hexdigest()
    return run


class AiBase(ScanBase):
    FILES = FILES_AIBOM

    def ai_server(self, runs_factory, *, available=(True, None), **kw):
        srv = self.server(**kw)
        live = srv.app.live
        live.aibom = FakeAibomClient()
        live.aibom_available = lambda: available
        self.calls = []
        original = wc.run

        def run(config, service, ticket, source, workspace):
            self.calls.append(source.commit_sha)
            self.last_workspace = workspace
            return runs_factory(source, service, ticket)
        wc.run = run
        self.addCleanup(setattr, wc, "run", original)
        self.addCleanup(setattr, wc, "unavailable_run", wc.unavailable_run)
        return srv

    def scan(self, srv):
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        return c, out

    def ai_tab(self, c, out):
        resp, body = c.json("GET", AI + "?generation=%d" % out["status"]["generation"])
        self.assertEqual(resp.status, 200, body)
        return body

    def assertValid(self, out):
        status = out["status"]
        vc.validate_payload("scan_status", status, request={"generation": status["generation"], "job_id": status["job"]["job_id"]})


class FlagOffTest(AiBase):
    def test_flag_off_has_no_ai_surface_anywhere(self):
        srv = self.server()
        _, cfg = self.client(srv).json("GET", "/api/config")
        self.assertNotIn("ai_bom", cfg["live"])
        c, out = self.scan(srv)
        self.assertValid(out)
        st = self.stages(out)
        self.assertEqual((st["aibom"]["state"], st["aibom"]["reason_code"], st["aibom"]["outputs"], st["aibom"]["warnings"]), ("not_run", "not_configured", [], []))
        self.assertEqual(out["status"]["job"]["state"], "completed")
        names = [a["name"] for a in c.json("GET", "/api/artifacts")[1]["artifacts"]]
        self.assertEqual(names, ["syft-sbom.cdx.json", "cdxgen-cbom.cdx.json", "bombridge-result.json"])
        for run in out["result"]["summary"]["live"]["scan"]:
            self.assertNotIn("completeness", run)
            self.assertNotEqual(run["kind"], "aibom")
        self.assertEqual({card["kind"] for card in out["result"]["summary"]["cards"]}, {"sbom", "cbom"})
        tab = self.ai_tab(c, out)
        self.assertEqual(tab["availability"], {"state": "not_run", "reason_code": "not_configured", "message": "No AI inventory was generated for this analysis."})
        self.assertEqual(tab["page"]["assets_total"], 0)
        self.assertNotIn("aibom", json.dumps(out["result"]["summary"]["live"]["scan"]))

    def test_the_input_check_stays_not_applicable_and_the_notice_is_unchanged(self):
        from opentrace_core.live import bundle
        srv = self.server()
        c, out = self.scan(srv)
        analysis = srv.app.analyses[next(iter(srv.app.analyses))]
        self.assertTrue(analysis.mode == "live")
        runs = [sc.ScanRun(scanner="syft", kind="sbom", tool="Syft", pinned_version="9.9.9")]
        # build() with no aibom run: the live-aibom check is the unchanged not_applicable one and the notice has no AI sentence
        source = types.SimpleNamespace(commit_sha="a" * 40, tree_sha="b" * 40, file_count=1, listing_sha256="c" * 64, skipped=[], repository_url="u", inputs=[])
        identity = {"repository": {"owner": "o", "name": "n", "canonical_url": "https://github.com/o/n"}, "analysis_digest": "d" * 64,
                    "requested": {"kind": "default", "text": ""}, "resolved": {"basis": "x"}}
        parts, _recs, _names, _raw = bundle.build(identity, source, runs, "sid", 1)
        checks = {x["input"]: x for x in parts["input_checks"]}
        self.assertEqual(checks["live-aibom"]["status"], "not_applicable")
        self.assertEqual(checks["live-aibom"]["detail"], "No AI-BOM was requested for this live analysis.")
        self.assertNotIn("AI-BOM was generated", parts["notice"])

    def test_the_scan_run_dict_is_unchanged_for_sbom_and_cbom(self):
        run = sc.ScanRun(scanner="syft", kind="sbom", tool="Syft", pinned_version="1")
        self.assertNotIn("completeness", run.as_dict())          # unset: the serialised form is exactly what it was at START_SHA
        self.assertEqual(sorted(run.as_dict()), sorted(k for k in run.__dict__ if k not in ("data", "completeness")))
        run.completeness = "verified"
        self.assertEqual(run.as_dict()["completeness"], "verified")

    def test_only_exactly_cisco_requests_the_phase(self):
        for value in (None, "", "1", "true", "CISCO", "cisco ", "yes"):
            env = {"OPENTRACE_LIVE_SCAN": "1"}
            if value is not None:
                env["OPENTRACE_LIVE_AIBOM"] = value
            self.assertIsNone(live_runner.LiveConfig.from_env(env).aibom, value)
        cfg = live_runner.LiveConfig.from_env({"OPENTRACE_LIVE_SCAN": "1", "OPENTRACE_LIVE_AIBOM": "cisco"})
        self.assertIsInstance(cfg.aibom, wc.AibomClient)
        self.assertEqual(cfg.aibom_available(), (False, "isolation_unavailable"), "no bounded policy / worker verified here")

    def test_public_carries_ai_bom_only_when_requested_and_never_a_key_or_price(self):
        srv = self.server()
        self.assertNotIn("ai_bom", srv.app.live.public())
        srv = self.ai_server(lambda *a: None, available=(False, "isolation_unavailable"))
        pub = srv.app.live.public()["ai_bom"]
        self.assertEqual(pub, {"requested": True, "available": False, "reason": "isolation_unavailable", "provider": "openai", "host": "api.openai.com", "model": "gpt-6-luna",
                               "sends": "repository file names and code excerpts chosen by the classifier"})
        text = json.dumps(srv.app.live.public())
        for needle in ("ceiling", "nusd", "price", "reserv", "token"):
            self.assertNotIn(needle, text.lower(), needle)


class StageTableTest(AiBase):
    def serve(self, **kw):
        return self.ai_server(lambda source, service, ticket: ai_run(source, **kw))

    def test_row5_verified_with_components_completes_and_the_tab_lists_the_model(self):
        srv = self.serve()
        c, out = self.scan(srv)
        self.assertValid(out)
        st = self.stages(out)["aibom"]
        self.assertEqual((st["state"], st["reason_code"], st["warnings"]), ("completed", None, []))
        self.assertEqual(st["outputs"], [{"kind": "aibom", "artifact_id": "art:inv:cisco-aibom", "sha256": hashlib.sha256(S.cdx_bytes(PAIRS)).hexdigest(), "size": len(S.cdx_bytes(PAIRS))}])
        self.assertEqual(out["status"]["job"]["state"], "completed")
        self.assertEqual(self.calls, [self.sha])
        tab = self.ai_tab(c, out)
        self.assertEqual(tab["availability"]["state"], "completed")
        self.assertEqual([a["display_name"] for a in tab["assets"]], ["llama-7b"])
        self.assertEqual([a["kind"] for a in tab["assets"]], ["inventory_model"])
        self.assertEqual(tab["producers"][0]["provenance"]["producer_id"], "cisco-aibom")
        self.assertEqual(tab["assets"][0]["occurrences"], [], "Cisco output carries no source occurrence: no link is invented (FD-C8)")
        self.assertIs(tab["absence_established"], False)
        resp, data = c.req("GET", "/api/artifacts/cisco-aibom.cdx.json?disposition=attachment")
        self.assertEqual(data, S.cdx_bytes(PAIRS), "download is the producer's original bytes")
        self.assertEqual(resp.getheader("X-Artifact-Sha256"), hashlib.sha256(data).hexdigest())

    def test_row6_verified_zero_components_is_completed_empty_in_both_places(self):
        srv = self.serve(data=S.cdx_bytes([]))
        c, out = self.scan(srv)
        self.assertValid(out)
        st = self.stages(out)["aibom"]
        self.assertEqual((st["state"], st["reason_code"]), ("completed_empty", "no_applicable_assets"))
        self.assertTrue(st["outputs"])
        self.assertEqual(self.ai_tab(c, out)["availability"]["state"], "completed_empty")

    def test_units_components_only_artifact_is_stage_completed_but_tab_completed_empty(self):
        srv = self.serve(data=S.cdx_bytes(LIBS))
        c, out = self.scan(srv)
        self.assertValid(out)
        self.assertEqual(self.stages(out)["aibom"]["state"], "completed", "the stage counts CycloneDX components (2)")
        self.assertEqual(self.stages(out)["aibom"]["outputs"][0]["size"], len(S.cdx_bytes(LIBS)))
        tab = self.ai_tab(c, out)
        self.assertEqual((tab["availability"]["state"], tab["page"]["assets_total"]), ("completed_empty", 0), "the tab counts model rows (0)")
        self.assertIn("does not show that no AI is used", tab["availability"]["message"])

    def test_row7_every_non_verified_completeness_is_partial_in_both_places_including_zero_assets(self):
        cases = [("degraded", {"agentic_degraded_count": 2}), ("skipped", {"agentic_skipped": 1}), ("unverified", {"completeness_unverified": 1})]
        for completeness, counts in cases:
            for data in (S.cdx_bytes(PAIRS), S.cdx_bytes([])):
                srv = self.serve(data=data, completeness=completeness, counts=counts)
                c, out = self.scan(srv)
                self.assertValid(out)
                st = self.stages(out)["aibom"]
                self.assertEqual((st["state"], st["reason_code"], st["warnings"]), ("partial", "partial_coverage", [scan_jobs.WARNING_AI_INCOMPLETE]), completeness)
                self.assertTrue(st["outputs"])
                self.assertEqual(out["status"]["job"]["state"], "partial")
                tab = self.ai_tab(c, out)
                self.assertEqual(tab["availability"]["state"], "partial", (completeness, len(data)))
                self.assertIn("classifier", tab["producers"][0]["scope"])
                self.assertNotEqual(tab["availability"]["state"], "completed_empty", "never an empty success")
                self.assertTrue(out["status"]["handoff"]["ready"])

    def test_a1_leaves_other_inventories_and_the_demo_shape_unchanged(self):
        from opentrace_core.app import ai_assets
        self.assertEqual(ai_assets._classifier_state({}), (False, None))
        self.assertEqual(ai_assets._classifier_state({"components": 3, "unrelated": 1}), (False, None))
        self.assertEqual(ai_assets._classifier_state({"agentic_degraded_count": 0, "agentic_skipped": 0, "completeness_unverified": 0}), (False, None))
        self.assertEqual(ai_assets._classifier_state({"agentic_degraded_count": 4}), (True, "classifier degraded (4)"))
        self.assertEqual(ai_assets._classifier_state({"agentic_skipped": 1}), (True, "classifier skipped"))
        self.assertEqual(ai_assets._classifier_state({"completeness_unverified": 1}), (True, "classifier completeness unverified"))
        self.assertEqual(ai_assets._classifier_state({"agentic_degraded_count": 1, "agentic_skipped": 1}), (True, "classifier counts inconsistent"))
        for bad in (True, -1, 1.5, "1", None):
            self.assertEqual(ai_assets._classifier_state({"agentic_degraded_count": bad}), (True, "classifier completeness unverified"), bad)

    def test_row2_unavailable_continues_the_job_and_keeps_sbom_and_cbom(self):
        srv = self.ai_server(lambda source, service, ticket: wc.unavailable_run(source, "isolation_unavailable"))
        c, out = self.scan(srv)
        self.assertValid(out)
        st = self.stages(out)
        self.assertEqual((st["aibom"]["state"], st["aibom"]["reason_code"], st["aibom"]["warnings"], st["aibom"]["outputs"]),
                         ("partial", "partial_coverage", [scan_jobs.WARNING_AI_UNAVAILABLE], []))
        self.assertEqual((st["sbom"]["state"], st["cbom"]["state"], out["status"]["job"]["state"]), ("completed", "completed", "partial"))
        self.assertTrue(out["status"]["handoff"]["ready"], "partial derives from the existing job-state rule; hand-off stays ready")
        self.assertIsNotNone(out["result"])
        names = [a["name"] for a in c.json("GET", "/api/artifacts")[1]["artifacts"]]
        self.assertEqual(names, ["syft-sbom.cdx.json", "cdxgen-cbom.cdx.json", "bombridge-result.json"])
        tab = self.ai_tab(c, out)
        self.assertEqual((tab["availability"]["state"], tab["availability"]["reason_code"]), ("failed", "scanner_unavailable"))

    def test_a4_validator_semantics_for_aibom_partial_outputs(self):
        """Amendment A4: aibom ``partial`` may carry outputs or not; completed/completed_empty AI still require them; sbom/cbom and every other
        rule are unchanged."""
        srv = self.serve()
        c, out = self.scan(srv)
        base = out["status"]
        req = {"generation": base["generation"], "job_id": base["job"]["job_id"]}

        def doc(stage_id, state, reason, outputs, job_state):
            s = copy.deepcopy(base)
            st = next(x for x in s["stages"] if x["stage_id"] == stage_id)
            st.update(state=state, reason_code=reason, outputs=outputs)
            s["job"]["state"] = job_state
            return s

        def ok(s):
            vc.validate_payload("scan_status", s, request=req)

        def bad(s, rule="invariant:stage_outputs"):
            with self.assertRaises(vc.ContractError) as ctx:
                vc.validate_payload("scan_status", s, request=req)
            self.assertEqual(ctx.exception.detail_code, rule)
        outs = copy.deepcopy(next(x for x in base["stages"] if x["stage_id"] == "aibom")["outputs"])
        sbom_outs = copy.deepcopy(next(x for x in base["stages"] if x["stage_id"] == "sbom")["outputs"])
        ok(doc("aibom", "partial", "partial_coverage", outs, "partial"))                # with committed outputs (row 7)
        ok(doc("aibom", "partial", "partial_coverage", [], "partial"))                  # without (rows 2, 8-11)
        bad(doc("aibom", "completed", None, [], "completed"))                           # completed AI still needs outputs
        bad(doc("aibom", "completed_empty", "no_applicable_assets", [], "completed"))
        bad(doc("aibom", "running", None, outs, "running"))                             # outputs only for committed states
        bad(doc("aibom", "not_run", "not_configured", outs, "completed"))
        for sid in ("sbom", "cbom"):                                                    # SBOM/CBOM constraints unchanged
            bad(doc(sid, "partial", "partial_coverage", [], "partial"))
            bad(doc(sid, "completed", None, [], "completed"))
            bad(doc(sid, "failed", "scanner_failed", sbom_outs, "failed"))
        bad(doc("advisory_lookup", "completed", None, sbom_outs, "completed"))
        bad(doc("aibom", "partial", "scanner_failed", [], "partial"), "invariant:stage_reason")   # reason rules still enforced
        s = doc("aibom", "partial", "partial_coverage", [], "partial")
        s["job"]["state"] = "completed"
        bad(s, "invariant:job_state")                                                   # job-state derivation still enforced
        s = doc("aibom", "partial", "partial_coverage", [], "partial")
        s["handoff"]["ready"] = False
        bad(s, "invariant:handoff_ready")                                               # hand-off rule still enforced

    def test_rows8_to_11_failed_runs_are_typed_and_never_an_inventory(self):
        secret = S.fragments("AK", "IA", "IOSFODNN7", "EXAMPLE")
        cases = {"output_invalid": ("failed", "output_invalid", S.cdx_bytes(PAIRS)), "timeout": ("failed", "timeout", None), "policy_refused": ("failed", "policy_refused", None),
                 "scanner_failed": ("failed", "scanner_failed", None)}
        for tab_reason, (outcome, reason, rejected) in cases.items():
            srv = self.ai_server(lambda source, service, ticket, o=outcome, r=reason, d=rejected: ai_run(source, outcome=o, reason=r, data=d, warnings=["the artifact was refused (x)"]))
            c, out = self.scan(srv)
            self.assertValid(out)
            st = self.stages(out)["aibom"]
            self.assertEqual((st["state"], st["reason_code"], st["warnings"], st["outputs"]), ("partial", "partial_coverage", [scan_jobs.WARNING_AI_NOT_COMPLETED], []), reason)
            self.assertEqual((out["status"]["job"]["state"], out["status"]["handoff"]["ready"]), ("partial", True), reason)
            self.assertIsNotNone(out["result"], reason)
            self.assertEqual(self.stages(out)["sbom"]["state"], "completed")
            names = [a["name"] for a in c.json("GET", "/api/artifacts")[1]["artifacts"]]
            self.assertNotIn("cisco-aibom.cdx.json", names, "a refused or failed artifact is never offered")
            tab = self.ai_tab(c, out)
            self.assertEqual((tab["availability"]["state"], tab["availability"]["reason_code"]), ("failed", tab_reason), reason)
            self.assertEqual(tab["assets"], [])
            self.assertNotIn(secret, json.dumps(out) + json.dumps(tab))

    def test_row3_an_sbom_failure_means_the_ai_phase_never_runs(self):
        srv = self.ai_server(lambda source, service, ticket: ai_run(source), sbom_exit=3, sbom=None)
        c, out = self.scan(srv)
        self.assertValid(out)
        st = self.stages(out)
        self.assertEqual((st["sbom"]["state"], st["aibom"]["state"], st["aibom"]["reason_code"]), ("failed", "not_run", "upstream_failed"))
        self.assertEqual(self.calls, [], "no AI request is made when the SBOM failed first")

    def test_the_phase_runs_after_the_scanners_and_never_before_a_cancel_is_honoured(self):
        order = []
        srv = self.ai_server(lambda source, service, ticket: (order.append("ai"), ai_run(source))[1])
        original = live_runner.run_scanner
        live_runner.run_scanner = lambda spec, *a, **k: (order.append(spec["kind"]), original(spec, *a, **k))[1]
        self.addCleanup(setattr, live_runner, "run_scanner", original)
        self.scan(srv)
        self.assertEqual(order, ["sbom", "cbom", "ai"])


class LifecycleTest(AiBase):
    def test_row12_cancel_during_the_ai_phase_cancels_the_stage_and_registers_nothing(self):
        entered, release = threading.Event(), threading.Event()

        def factory(source, service, ticket):
            entered.set()
            release.wait(20)
            return ai_run(source, outcome="cancelled", reason="cancelled")
        srv = self.ai_server(factory)
        c = self.session(srv)
        _, env = self.start(c)
        self.assertTrue(entered.wait(15))
        box = {}
        thread = threading.Thread(target=lambda: box.update(zip(("resp", "body"), c.json("POST", "/api/analysis/cancel", {}))))
        thread.start()
        job = self.job_of(srv)
        wait_for(lambda: job.ticket.cancel_event.is_set(), message="cancel request")
        release.set()
        thread.join(20)
        out = self.poll(c, env)
        self.assertValid(out)
        st = self.stages(out)
        self.assertEqual((out["status"]["job"]["state"], st["aibom"]["state"], st["aibom"]["reason_code"]), ("cancelled", "cancelled", "cancelled_by_user"))
        self.assertIsNone(out["result"])
        self.assertEqual(srv.app.analyses, {})
        wait_for(lambda: self.gate_free(srv))
        self.assertEqual(out["status"]["cleanup"]["state"], "verified")

    def test_row13_end_session_during_the_ai_phase_discards_everything(self):
        entered, release = threading.Event(), threading.Event()

        def factory(source, service, ticket):
            entered.set()
            release.wait(20)
            return ai_run(source)             # a perfectly good artifact arrives AFTER the session ended
        srv = self.ai_server(factory)
        c = self.session(srv)
        _, env = self.start(c)
        self.assertTrue(entered.wait(15))
        box = {}
        thread = threading.Thread(target=lambda: box.update(state=c.json("POST", "/api/session/end", {})[1].get("state")))
        thread.start()
        job = self.job_of(srv)
        wait_for(lambda: job.ticket.cancel_event.is_set(), message="End session request")
        release.set()
        thread.join(20)
        wait_for(lambda: job.terminal, message="terminal job")
        self.assertEqual(job.state(), "cancelled")
        self.assertIsNone(job.result)
        self.assertEqual(srv.app.analyses, {})
        self.assertEqual(box["state"], "deleted_verified")
        wait_for(lambda: self.gate_free(srv))

    def test_row14_an_unverifiable_ai_cleanup_fails_the_job_and_quarantines_the_gate(self):
        srv = self.ai_server(lambda source, service, ticket: ai_run(source, outcome="failed", reason="cleanup_unverified", warnings=["x"]))
        c = self.session(srv)
        _, env = self.start(c)
        out = self.poll(c, env)
        self.assertValid(out)
        st = self.stages(out)
        self.assertEqual((st["aibom"]["state"], st["aibom"]["reason_code"]), ("failed", "cleanup_unverified"))
        self.assertEqual(out["status"]["job"]["state"], "failed")
        self.assertIsNone(out["result"])
        self.assertFalse(out["status"]["handoff"]["ready"])
        job = self.job_of(srv)
        self.assertTrue(job.cleanup_unverified)
        self.assertEqual(out["status"]["cleanup"]["state"], "unverified")
        self.assertEqual(srv.app.analyses, {})
        self.assertEqual(c.json("GET", "/api/artifacts")[1]["artifacts"], [], "nothing was committed or offered: not the SBOM, not the CBOM, not an AI artifact")


class ProvenanceTest(AiBase):
    def test_option_a_the_ai_manifest_and_scope_carry_the_unchanged_original_tree_identity(self):
        srv = self.ai_server(lambda source, service, ticket: ai_run(source))
        c, out = self.scan(srv)
        self.assertValid(out)
        analysis = srv.app.analyses[next(iter(srv.app.analyses))]
        rec = {r.kind: r for r in analysis.records}
        self.assertEqual(set(rec), {"sbom", "cbom", "aibom"})
        for kind in ("sbom", "cbom", "aibom"):
            m = rec[kind].acquisition_manifest
            self.assertEqual((m["tree_differs_from_revision"], m["revision"]), (False, self.sha), kind)
            self.assertEqual(m["inputs"], rec["sbom"].acquisition_manifest["inputs"], "the AI input is the same full exported tree: identical input identity")
            self.assertEqual(m["repository"], rec["sbom"].acquisition_manifest["repository"])
            for banned in ("exclude", "excluded", "filter", "view"):
                self.assertFalse([k for k in m if banned in k.lower()], (kind, banned))
        ai = rec["aibom"].acquisition_manifest
        self.assertEqual((ai["generator"]["name"], ai["generator"]["version"]), ("cisco-aibom", "1.10.1"))
        self.assertEqual(ai["output_sha256"], rec["aibom"].sha256)
        scan = {r["kind"]: r for r in analysis.scan}
        self.assertEqual(scan["aibom"]["scope"]["tree_sha"], scan["sbom"]["scope"]["tree_sha"])
        self.assertEqual(scan["aibom"]["scope"]["listing_sha256"], scan["sbom"]["scope"]["listing_sha256"])
        card = next(c_ for c_ in out["result"]["summary"]["cards"] if c_["kind"] == "aibom")
        self.assertEqual((card["state"], card["binding_label"], card["binding_conflicts"]), ("acquired", "recorded", []))

    def test_the_full_tree_is_what_the_ai_worker_is_handed_including_a_repository_aibom_file(self):
        seen = {}

        def factory(source, service, ticket):
            import os
            seen["listing"] = sorted(os.listdir(os.path.join(self.last_workspace, "src")))
            return ai_run(source)
        srv = self.ai_server(factory)
        self.scan(srv)
        self.assertIn(".aibom.yaml", seen["listing"], "no .aibom.* exclusion exists anywhere (FD-C14 option A)")
        self.assertIn("app", seen["listing"])

    def test_sbom_and_cbom_manifests_are_identical_with_and_without_the_ai_phase(self):
        off = self.server()
        self.scan(off)
        a_off = off.app.analyses[next(iter(off.app.analyses))]
        srv = self.ai_server(lambda source, service, ticket: ai_run(source))
        self.scan(srv)
        a_on = srv.app.analyses[next(iter(srv.app.analyses))]
        for kind in ("sbom", "cbom"):
            r_off = next(r for r in a_off.records if r.kind == kind)
            r_on = next(r for r in a_on.records if r.kind == kind)
            self.assertEqual(r_off.acquisition_manifest, r_on.acquisition_manifest, kind)
            self.assertEqual((r_off.sha256, r_off.record_counts, r_off.state), (r_on.sha256, r_on.record_counts, r_on.state))

    def test_limitations_and_the_input_check_state_the_truth(self):
        srv = self.ai_server(lambda source, service, ticket: ai_run(source, completeness="degraded", counts={"agentic_degraded_count": 2}))
        c, out = self.scan(srv)
        analysis = srv.app.analyses[next(iter(srv.app.analyses))]
        ai = next(r for r in analysis.records if r.kind == "aibom")
        text = " | ".join(ai.limitations).lower()
        for needle in ("separate worker container", "does not claim independent verification", "file names and code excerpts", "gpt-6-luna", "no exclusion",
                       "repository-declared", "steering", "classifier completeness: degraded", "agentic_degraded_count=2", "producer-reported", "no occurrence link"):
            self.assertIn(needle, text, needle)
        self.assertNotIn("no network access", text, "the SBOM/CBOM isolation sentence must not be claimed for the AI step")
        sbom = next(r for r in analysis.records if r.kind == "sbom")
        self.assertIn("network access denied", " | ".join(sbom.limitations), "the SBOM/CBOM sentence stays true and unchanged")


if __name__ == "__main__":
    unittest.main()
