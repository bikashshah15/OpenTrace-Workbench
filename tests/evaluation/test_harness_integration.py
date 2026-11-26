"""Integration smoke tests of the E1/E4/E5 harness code against the REAL orchestration, using only the SYNTHETIC fallback composite
(external inputs deliberately absent, so nothing from DeepBits, BF-CBOM or the Frigate capture is used).

They check that the harness runs end to end (patch boundaries, canonicalisation, E1 derivations, E5 recorder/timers). They assert
harness properties only (completion, internal consistency), never evaluation numbers, and they write nothing outside temp dirs.
"""
import copy
import os
import shutil
import tempfile
import unittest

from tools.evaluation import common as C
from tools.evaluation import e1_case_study as E1
from tools.evaluation import e4_integration as E4
from tools.evaluation import e5_efficiency as E5

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def synthetic_cfg(d):
    cfg = C.load_config()
    cfg["benchmarks"] = {"deepbits": os.path.join(d, "absent"), "bf_cbom": os.path.join(d, "absent"), "ai_references": None}
    cfg["captures"] = []
    cfg["e4"]["reference_bundles"] = ["composite-a"]
    return cfg


class E4HarnessTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ot-eval-int-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.cfg = synthetic_cfg(self.dir)

    def test_fault_matrix_runs_on_the_synthetic_fallback(self):
        ctx = C.RunContext(self.cfg, output_root=os.path.join(self.dir, "out"), run_id="s", opentrace_root=ROOT)
        st = E4.run(ctx)
        self.assertIn(st["status"], ("completed", "partial"))
        pre = C.read_json(os.path.join(ctx.out, "e4", "reference_preconditions.json"))
        self.assertTrue(all(p["provenance"]["software"].startswith("controlled") for p in pre), "synthetic fallback is labelled controlled")
        rows = C.read_csv(os.path.join(ctx.out, "e4", "fault_injection_results.csv"))
        self.assertEqual({r["condition"] for r in rows}, set(E4.CONDITIONS) - {"R0"})

    def test_e1_derivations_and_e5_timers_on_a_synthetic_live_result(self):
        ref = E4.build_reference("composite-a", self.cfg, ROOT)
        h = E4.LiveHarness()
        self.addCleanup(h.close)
        rec = E5.Recorder()
        ps = rec.patches()
        for p in ps:
            p.start()
        try:
            out = h.go(ref)
        finally:
            for p in reversed(ps):
                p.stop()
        self.assertEqual(out["gaps"]["status"], "compared")
        self.assertTrue(rec.discover and rec.assemble_out and rec.assess)
        # E5 timers on the recorded inputs (one repetition, no warm-up)
        from opentrace_core.bombridge.pipeline import run_doc
        from opentrace_core.bombridge_adapter import runner
        rows = E5._time(run_doc, 1, 0, 0.005, lambda: copy.deepcopy(rec.assemble_out[-1]))
        self.assertEqual(rows[0]["status"], "ok", rows[0]["error"])
        a, k = rec.assess[-1]

        def worker(b):
            res = runner.assess(a[0] if a else k["context"], b, artifacts=k.get("artifacts", ()), read_artifact=k.get("read_artifact"))
            if res.status != "complete":
                raise RuntimeError(res.status)
        rows = E5._time(worker, 1, 0, 0.005, lambda: copy.deepcopy(rec.assemble_out[-1]))
        self.assertEqual(rows[0]["status"], "ok", rows[0]["error"])
        d_args, d_kw = rec.discover[-1]
        kw = copy.deepcopy({kk: vv for kk, vv in d_kw.items() if kk != "propagate"})
        kw["generator_report"] = {}
        from opentrace_core.bombridge import discovery as D
        D.discover(*copy.deepcopy(d_args), **kw)
        # E1 derivations on a raw record shaped like collect_capture's output
        bound = out["gaps"]["assessment"]
        names = {"sbom": "syft-sbom.cdx.json", "cbom": "cdxgen-cbom.cdx.json", "aibom": "cisco-aibom.cdx.json"}
        raw_docs = {}
        import json
        for k_, n in names.items():
            data = json.dumps(ref[k_], sort_keys=True).encode()
            raw_docs[n] = {"sha256": C.sha256_bytes(data), "doc": ref[k_]}
        raw = {"capture_id": "synthetic", "provenance_tier": "controlled", "repository": ref["repository"], "revision": ref["revision"],
               "bound": {"result": bound.result, "source_bundle": bound.source_bundle}, "bom_candidates": {"items": [], "pages": [], "errors": []},
               "raw_docs": raw_docs, "manifest": {"files": {}}, "scan_record_runs": [], "collection": out["collection"],
               "source": {"file_count": len(ref["listing"]), "inputs": {r["path"]: r["sha256"] for r in ref["listing"]}},
               "declarations_record": {"crypto_call_sites": [], "model_references": [], "requirement_files": []},
               "declaration_copies_text": {"requirements.txt": ref["files"]["requirements.txt"].decode()},
               "declaration_copies_sha256": {"requirements.txt": C.sha256_bytes(ref["files"]["requirements.txt"])}, "inspectors": {}, "base_result_findings": 0}
        rows = E1.build_findings(raw)
        self.assertTrue(rows)
        E1.repository_statistics(raw)
        E1.findings_by_domain(rows, raw["collection"])
        tr = E1.traceability(rows, raw, None)
        self.assertEqual(len(tr), len(rows))
        sample, strata = E1.audit_sample(rows, 5, C.RunContext.rng(type("X", (), {"seed": 1})(), "t"), "synthetic")
        audit = E1.audit_rows(sample, raw, {t["row_id"]: t for t in tr}, {})
        self.assertTrue(any(r["record_kind"] == "verification_assertion" for r in rows), "represented claims without a candidate are kept")
        self.assertTrue(all(r["audit_status"] == "not_reviewed" for r in audit))
        self.assertIn("synthetic", E1.case_examples_md(raw, sample, {}))


if __name__ == "__main__":
    unittest.main()
