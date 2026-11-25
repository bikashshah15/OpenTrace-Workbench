"""UIP-07C P8 path rules on the live pipeline: the container scan root ``/scan/repo`` (and worker-internal paths) must not appear on any DERIVED surface
(scan status, result payload, AI tab, legacy AI view, artifact listing); the accepted artifact itself is served UNCHANGED (original-byte provenance),
which is the one place the producer's own absolute paths remain."""
import json
import types
import unittest

from tests.core.app.test_aibom_pipeline import AiBase, ai_run
from tests.core.live import aibom_support as S

ROOT = "/scan/repo"
PAIRS = [S.comp("openai", file=ROOT + "/requirements.txt", line=1),                                                         # deterministic form: absolute resolved path
         S.comp("langchain", file=ROOT + "/requirements.txt", line=2),
         S.comp("llama-7b", "machine-learning-model", ROOT + "/app/main.py", 9, "model", ref="llama-7b_/scan/repo/app/main.py_9"),
         S.comp("agent-added-model", "machine-learning-model", "app/main.py", 12, "model", ref="agent-added-model_app/main.py_12"),   # relative, in the tree
         S.comp("ghost-model", "machine-learning-model", "no/such/file.py", 3, "model", ref="ghost-model_no/such/file.py_3"),          # relative, not in the tree
         S.comp("escape-model", "machine-learning-model", "../../etc/passwd", 1, "model", ref="escape-model_../../etc/passwd_1")]    # escape attempt


class PrivacyTest(AiBase):
    def test_no_container_path_reaches_a_derived_surface_and_no_occurrence_is_invented(self):
        data = S.cdx_bytes(PAIRS)
        srv = self.ai_server(lambda source, service, ticket: ai_run(source, data=data))
        c, out = self.scan(srv)
        self.assertValid(out)
        tab = self.ai_tab(c, out)
        surfaces = {"scan_status": out["status"], "result": out["result"], "ai_tab": tab, "artifact_list": c.json("GET", "/api/artifacts")[1]}
        for name, doc in surfaces.items():
            text = json.dumps(doc)
            for needle in (ROOT, "/scan/", "/spool", "/work/", "/opt/venv", "/ctl", "gateway:8788"):
                self.assertNotIn(needle, text, (name, needle))
        self.assertEqual([a["display_name"] for a in tab["assets"]], sorted(a["display_name"] for a in tab["assets"]), "stable order")
        names = {a["display_name"] for a in tab["assets"]}
        self.assertEqual(names, {"llama-7b", "agent-added-model", "ghost-model", "escape-model"}, "model rows only; libraries are not AI assets")
        for asset in tab["assets"]:
            self.assertEqual(asset["occurrences"], [], "Cisco output has no relative evidence occurrences: none is invented from a producer-reported path")
            self.assertEqual(asset["occurrences_total"], 0)
            self.assertEqual(asset["identity_state"], "unresolved")
        self.assertEqual(tab["links"], [])
        resp, body = c.req("GET", "/api/artifacts/cisco-aibom.cdx.json?disposition=attachment")
        self.assertEqual(body, data, "the artifact is served unchanged, including the producer's own absolute paths")
        self.assertIn(ROOT.encode(), body)

    def test_a5_the_legacy_ai_view_presents_the_scan_root_for_cisco_artifacts_only(self):
        """Amendment A5: the ACTUAL /api/view/ai response (list and selected record) shows ``<scan-root>``; ids, pointers, digests and the downloadable
        artifact bytes are untouched; flag-off live scans and the Demo are byte-for-byte unchanged."""
        data = S.cdx_bytes(PAIRS)
        srv = self.ai_server(lambda source, service, ticket: ai_run(source, data=data))
        c, out = self.scan(srv)
        legacy = c.json("GET", "/api/view/ai")[1]
        text = json.dumps(legacy)
        for needle in (ROOT, "/spool", "/work/", "/scan/"):
            self.assertNotIn(needle, text, needle)
        model = next(m for m in legacy["models"] if m["record"]["name"] == "llama-7b")
        self.assertEqual(model["record"]["bom-ref"], "llama-7b_<scan-root>/app/main.py_9")
        self.assertIn({"name": "cisco-aibom:file", "value": "<scan-root>/app/main.py"}, model["record"]["properties"])
        self.assertEqual(model["id"], "art:inv:cisco-aibom/components/2", "ids and pointers are not rewritten")
        selected = c.json("GET", "/api/view/ai?selected=" + model["id"])[1]
        self.assertNotIn(ROOT, json.dumps(selected), "the selected-record presentation is normalised too")
        self.assertEqual(selected["selected_id"], model["id"])
        resp, body = c.req("GET", "/api/artifacts/cisco-aibom.cdx.json?disposition=attachment")
        self.assertEqual(body, data)
        self.assertIn(ROOT.encode(), body)
        self.assertEqual(resp.getheader("X-Artifact-Sha256"), __import__("hashlib").sha256(data).hexdigest())

    def test_a5_leaves_demo_flag_off_and_non_cisco_responses_unchanged(self):
        from opentrace_core.app import legacy_ai_presentation as lp
        probe = {"models": [{"id": "x", "record": {"bom-ref": "a_/scan/repo/b"}}], "supporting_records": [], "inspector": None}
        for analysis in (types.SimpleNamespace(mode="captured", records=[]), types.SimpleNamespace(mode="live", records=[]),
                         types.SimpleNamespace(mode="live", records=[types.SimpleNamespace(kind="aibom", state="acquired", acquisition_manifest={"generator": {"name": "other-tool"}})]),
                         types.SimpleNamespace(mode="live", records=[types.SimpleNamespace(kind="aibom", state="acquired", acquisition_manifest=None)]),
                         types.SimpleNamespace(mode="live", records=[types.SimpleNamespace(kind="aibom", state="failed", acquisition_manifest={"generator": {"name": "cisco-aibom"}})])):
            self.assertIs(lp.present(probe, analysis), probe)
        cisco = types.SimpleNamespace(mode="live", records=[types.SimpleNamespace(kind="aibom", state="acquired", acquisition_manifest={"generator": {"name": "cisco-aibom"}})])
        shown = lp.present(probe, cisco)
        self.assertEqual(shown["models"][0]["record"]["bom-ref"], "a_<scan-root>/b")
        self.assertEqual(probe["models"][0]["record"]["bom-ref"], "a_/scan/repo/b", "the source dict is not mutated")
        srv = self.server()
        c, out = self.scan(srv)
        before = c.json("GET", "/api/view/ai")[1]
        self.assertNotIn("<scan-root>", json.dumps(before))

    def test_a_derived_id_never_embeds_a_path_or_the_bom_ref(self):
        ac = S.cisco_module()
        ids = {ac.derived_id("a" * 64, p[0]["bom-ref"]) for p in PAIRS}
        self.assertEqual(len(ids), len(PAIRS))
        for i in ids:
            self.assertRegex(i, r"^[0-9a-f]{24}$")


if __name__ == "__main__":
    unittest.main()
