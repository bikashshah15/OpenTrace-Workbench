"""Stage 4 increment A (contract S4-AI-SOURCE v1.0.0): the AI tab's projection of source observations.

Inputs come from the real collector run on SYNTHETIC temp trees (and hand-made bad records). Expected ids use the local re-implementation of the
documented derivation from test_ai_assets.py, not the producer's helper.
"""
import copy
import json
import os
import shutil
import tempfile
import unittest

from opentrace_core.app import ai_assets as aa
from opentrace_core.live import ai_source, source_declarations as sd
from tests.core.app.test_ai_assets import ART, binding, build, doc, inputs, inv, ml, oid

URL = "https://github.com/acme/widget"
SHA = "c" * 40
FALLBACK = "import os\n\ntry:\n    from tflite_runtime.interpreter import Interpreter\nexcept ModuleNotFoundError:\n    from ai_edge_litert.interpreter import Interpreter\n"


def collect(files):
    root = tempfile.mkdtemp(prefix="ot-aisrc-")
    try:
        for rel, data in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as h:
                h.write(data)
        return ai_source.present(sd.collect(root, URL, SHA))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def with_source(src, aibom=None):
    return {"aibom": aibom, "source": src, "mode": "live"}


class Projection(unittest.TestCase):
    def test_runtimes_fallback_link_and_alternative_binding(self):
        src = collect({"det/cpu.py": FALLBACK, "other/svc.py": 'U = "http://127.0.0.1:11434/api/generate"\n'})
        b = binding()
        p, _ = build(with_source(src), b)
        by_name = {a["display_name"]: a for a in p["assets"]}
        self.assertEqual(set(by_name), {"tflite_runtime", "ai_edge_litert", "http://127.0.0.1:11434/api/generate"})
        pre, fb, svc = by_name["tflite_runtime"], by_name["ai_edge_litert"], by_name["http://127.0.0.1:11434/api/generate"]
        self.assertEqual((pre["kind"], fb["kind"], svc["kind"]), ("runtime", "runtime", "ai_service"))
        self.assertEqual(pre["asset_id"], oid("ast", b["analysis_digest"], "asset", "src-rt|tflite_runtime"))
        for a in (pre, fb, svc):
            self.assertEqual(a["provenance"]["origin"], "supplemental_observation")
            self.assertTrue(a["provenance"]["experimental"])
            self.assertEqual(a["identity_state"], "unresolved")
            self.assertTrue(all(v["state"] == "unavailable" for v in a["attributes"].values()))
            self.assertIsNone(a["display_group"])
        # location, hash and line are bound to the right occurrence
        o_pre, o_fb = pre["occurrences"][0], fb["occurrences"][0]
        self.assertEqual((o_pre["source_location"]["path"], o_pre["source_location"]["line_start"]), ("det/cpu.py", 4))
        self.assertEqual((o_fb["source_location"]["path"], o_fb["source_location"]["line_start"]), ("det/cpu.py", 6))
        self.assertEqual(len(o_pre["source_location"]["file_sha256"]), 64)
        # the fallback occurrence points at the preferred occurrence, with its condition; the preferred one has neither
        self.assertEqual(o_fb["alternative_of"], o_pre["occurrence_id"])
        self.assertIsNone(o_pre["alternative_of"])
        self.assertEqual(o_fb["condition"]["basis"], "source_text")
        self.assertIn("ImportError", o_fb["condition"]["text"])
        self.assertEqual(o_pre["condition"], {"text": None, "basis": "none"})
        self.assertEqual(p["links"], [{"relation": "conditionally_selects", "from": pre["asset_id"], "to": fb["asset_id"], "basis": "recorded",
                                       "evidence_ref": None, "condition": o_fb["condition"]["text"]}])
        self.assertEqual(p["filter_totals"], {"all": 3, "models": 0, "runtimes": 2, "ai_services": 1, "findings": 0})
        self.assertEqual([x["provenance"]["producer_id"] for x in p["producers"]], [aa.SOURCE_ID])
        self.assertEqual(p["producers"][0]["outcome"], "completed")
        self.assertEqual(p["availability"]["state"], "completed")
        self.assertEqual(p["counts"]["total"], 3)

    def test_filtered_or_capped_preferred_occurrence_never_breaks_the_payload(self):
        src = collect({"det/cpu.py": FALLBACK})
        p, _ = build(with_source(src), query="ai_edge")             # preferred asset filtered out: alternative_of must be dropped, not dangling
        self.assertEqual([a["display_name"] for a in p["assets"]], ["ai_edge_litert"])
        self.assertIsNone(p["assets"][0]["occurrences"][0]["alternative_of"])
        self.assertIn("ImportError", p["assets"][0]["occurrences"][0]["condition"]["text"])
        files = {"p/f%02d.py" % i: "import tflite_runtime\n" for i in range(40)}
        files["z/fb.py"] = FALLBACK
        p, _ = build(with_source(collect(files)))                   # preferred occurrence beyond the per-asset occurrence cap
        self.assertTrue(p["assets"])

    def test_opposite_relations_in_two_files_draw_no_link(self):
        a = "try:\n    import onnxruntime\nexcept ImportError:\n    import openvino\n"
        b = "try:\n    import openvino\nexcept ImportError:\n    import onnxruntime\n"
        p, _ = build(with_source(collect({"a.py": a, "b.py": b})))
        self.assertEqual(p["links"], [])
        self.assertEqual(len(p["assets"]), 2)

    def test_same_pair_in_two_files_one_generic_link(self):
        p, _ = build(with_source(collect({"a.py": FALLBACK, "b.py": FALLBACK})))
        self.assertEqual(len(p["links"]), 1)
        self.assertIn("declared in 2 places", p["links"][0]["condition"])

    def test_filters_and_link_only_when_both_ends_in_page(self):
        src = collect({"a.py": FALLBACK})
        p, _ = build(with_source(src), filter="runtimes")
        self.assertEqual(len(p["assets"]), 2)
        self.assertEqual(len(p["links"]), 1)
        p2, _ = build(with_source(src), filter="models")
        self.assertEqual((p2["assets"], p2["links"]), ([], []))
        p3, _ = build(with_source(src), filter="ai_services")
        self.assertEqual((p3["assets"], p3["links"]), ([], []))

    def test_wrong_binding_rejected_by_contract(self):
        src = collect({"a.py": FALLBACK})
        b = binding()
        p, _ = build(with_source(src), b)
        p["links"][0]["to"] = "ast:" + "0" * 24                   # an endpoint that is not an asset of this payload
        with self.assertRaises(Exception):
            from tests.core.app.test_ai_assets import accept
            accept(p, b)

    def test_separate_from_inventory_models(self):
        d = doc([ml("yolo.onnx", [("m/a.yaml", 3)], url="https://x.invalid/yolo.onnx")])
        src = collect({"a.py": "import onnxruntime\n"})
        p, _ = build(with_source(src, inv(d)))
        kinds = sorted(a["kind"] for a in p["assets"])
        self.assertEqual(kinds, ["model_reference", "runtime"])
        self.assertEqual({x["provenance"]["producer_id"] for x in p["producers"]}, {"cisco-aibom", aa.SOURCE_ID})
        model = next(a for a in p["assets"] if a["kind"] == "model_reference")
        self.assertEqual(model["provenance"]["origin"], "original_artifact")
        self.assertFalse(model["provenance"]["experimental"])
        self.assertEqual(p["filter_totals"]["models"], 1)
        self.assertEqual(p["filter_totals"]["runtimes"], 1)

    def test_absent_source_leaves_payload_byte_identical(self):
        d = doc([ml("yolo.onnx", [("m/a.yaml", 3)])])
        a, _ = build(inputs(inv(d)))
        b, _ = build({"aibom": inv(d), "source": None, "mode": "captured"})
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertEqual(a["links"], [])

    def test_complete_scan_with_nothing_found_changes_nothing(self):
        src = collect({"a.py": "x = 1\n"})
        self.assertEqual(src["runtimes"] + src["services"] + src["relations"], [])
        p, _ = build(with_source(src))
        self.assertEqual((p["availability"]["state"], p["producers"], p["assets"]), ("not_run", [], []))
        self.assertEqual(p["availability"]["message"], "No AI inventory was generated for this analysis.")

    def test_incomplete_scan_is_partial_even_without_assets(self):
        src = collect({"bad.py": "def (:\n", "ok.py": "x = 1\n"})
        p, _ = build(with_source(src))
        self.assertEqual(p["producers"][0]["outcome"], "partial")
        self.assertEqual(p["availability"]["state"], "partial")
        self.assertEqual(p["assets"], [])

    def test_collector_failure_is_failed_not_empty(self):
        p, _ = build(with_source({"state": "failed", "code": "collector_error"}))
        self.assertEqual((p["availability"]["state"], p["assets"]), ("failed", []))
        self.assertEqual(p["producers"][0]["outcome"], "failed")

    def test_unbindable_relation_is_dropped_and_counted_not_invented(self):
        src = collect({"a.py": FALLBACK})
        bad = copy.deepcopy(src)
        bad["relations"][0]["fallback"]["line"] = 99            # no runtime observation at that line
        p, _ = build(with_source(bad))
        self.assertEqual(p["links"], [])
        self.assertEqual(p["producers"][0]["outcome"], "partial")
        self.assertTrue(all(o["alternative_of"] is None for a in p["assets"] for o in a["occurrences"]))

    def test_hostile_records_are_dropped(self):
        src = collect({"a.py": "import onnxruntime\n"})
        bad = copy.deepcopy(src)
        bad["runtimes"].append(dict(bad["runtimes"][0], path="/etc/passwd"))
        bad["runtimes"].append(dict(bad["runtimes"][0], path="../x.py"))
        bad["runtimes"].append(dict(bad["runtimes"][0], file_sha256="zz"))
        bad["services"] = [{"path": "a.py", "line": 1, "end_line": 1, "endpoint": "https://h.test/Users/x/v1/completions", "file_sha256": "a" * 64}]
        p, _ = build(with_source(bad))
        text = json.dumps(p)
        self.assertNotIn("/etc/passwd", text)
        self.assertEqual([a["display_name"] for a in p["assets"]].count("onnxruntime"), 1)
        self.assertEqual(p["producers"][0]["outcome"], "partial")

    def test_multiple_occurrences_one_asset_and_group_ids(self):
        src = collect({"a/x.py": "import onnxruntime\n", "b/y.py": "import onnxruntime\n"})
        p, _ = build(with_source(src))
        self.assertEqual(len(p["assets"]), 1)
        self.assertEqual(p["assets"][0]["occurrences_total"], 2)
        self.assertEqual(len(p["assets"][0]["source_group_ids"]), 2)

    def test_no_local_paths_or_frigate_names(self):
        src = collect({"a.py": FALLBACK})
        p, _ = build(with_source(src))
        text = json.dumps(p).lower()
        for needle in ("/users/", "/private/", "frigate", "web-new", "hailo8l"):
            self.assertNotIn(needle, text)


if __name__ == "__main__":
    unittest.main()
