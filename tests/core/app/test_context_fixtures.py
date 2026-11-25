"""UIP-04 fixtures (evidence/uip/visual/uip-04/fixtures/uip04-*): valid under the frozen validator, reproducible, honest about provenance."""
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest

from opentrace_core.app import view_contracts as vc

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
FIX = os.path.join(ROOT, "evidence", "uip", "visual", "uip-04", "fixtures")
EXPECTED = ["uip04-eleven-groups", "uip04-hostile-text", "uip04-large-map", "uip04-multi-ecosystem", "uip04-one-group", "uip04-overlap",
            "uip04-synthetic-12-group-layout-capacity", "uip04-unlocated-only", "uip04-unlocated-with-files", "uip04-unrepresentable-path", "uip04-zero-location"]
TOKENS = ("frigate", "blakeblackshear", "web-new", "tflite_runtime", "yolov6n", "hailo", "cpu_model", "ai_edge_litert")


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def builder():
    spec = importlib.util.spec_from_file_location("uip04_build", os.path.join(ROOT, "tools", "uip04", "build_fixtures.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Fixtures(unittest.TestCase):
    def test_directory_set(self):
        self.assertEqual(sorted(d for d in os.listdir(FIX)), EXPECTED)

    def test_every_contexts_payload_passes_both_validator_layers(self):
        n = 0
        for d in EXPECTED:
            for e in load(os.path.join(FIX, d, "MANIFEST.json"))["files"]:
                if e["schema"] == "opentrace.workbench.contexts/1":
                    vc.validate_payload("contexts", load(os.path.join(FIX, d, e["path"])), request={"generation": 1})
                    n += 1
                elif e["schema"] == "opentrace.workbench.error/1":
                    vc.validate_payload("error", load(os.path.join(FIX, d, e["path"])))
                    n += 1
        self.assertGreaterEqual(n, 20)

    def test_manifest_digests_match_and_no_recorded_repository_names(self):
        for d in EXPECTED:
            m = load(os.path.join(FIX, d, "MANIFEST.json"))
            self.assertEqual(m["provenance"], "synthetic")
            for e in m["files"]:
                with open(os.path.join(FIX, d, e["path"]), "rb") as handle:
                    data = handle.read()
                self.assertEqual(hashlib.sha256(data).hexdigest(), e["sha256"], d + "/" + e["path"])
                text = data.decode("utf-8").lower()
                self.assertEqual([t for t in TOKENS if t in text], [], d + "/" + e["path"])

    def test_builder_is_reproducible_and_equals_the_committed_files(self):
        b = builder()
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            b.build_all(one)
            b.build_all(two)
            for d in EXPECTED:
                for name in sorted(os.listdir(os.path.join(FIX, d))):
                    with open(os.path.join(FIX, d, name), "rb") as h:
                        committed = h.read()
                    for out in (one, two):
                        with open(os.path.join(out, d, name), "rb") as h:
                            self.assertEqual(h.read(), committed, "%s/%s is stale: rerun tools/uip04/build_fixtures.py" % (d, name))

    def test_fixture_properties_the_contract_requires(self):
        eleven = load(os.path.join(FIX, "uip04-eleven-groups", "contexts-page-0.json"))
        self.assertEqual(len(eleven["groups"]), 11)
        self.assertEqual([g["category"] for g in eleven["groups"]][:10], list(__import__("opentrace_core.app.context_groups", fromlist=["x"]).CATEGORY_ORDER))
        big = load(os.path.join(FIX, "uip04-large-map", "contexts-page-0.json"))
        self.assertLessEqual(len(big["groups"]), 11)
        self.assertGreaterEqual(sum(g["files_counts"]["total"] for g in big["groups"]), 600)
        self.assertGreater(max(g["files_counts"]["total"] for g in big["groups"]), 100)
        self.assertTrue(all(len(g["files"]) <= 20 for g in big["groups"]))
        overlap = load(os.path.join(FIX, "uip04-overlap", "contexts-page-0.json"))
        self.assertTrue(any(g["distinct_total"] < g["membership_total"] for g in overlap["groups"]))
        self.assertLess(overlap["root"]["distinct_total"], sum(g["distinct_total"] for g in overlap["groups"]))
        only = load(os.path.join(FIX, "uip04-unlocated-only", "contexts-page-0.json"))
        self.assertEqual([(g["kind"], g["files"]) for g in only["groups"]], [("unlocated", [])])
        self.assertEqual(load(os.path.join(FIX, "uip04-zero-location", "contexts-page-0.json"))["groups"], [])
        self.assertEqual(len(load(os.path.join(FIX, "uip04-one-group", "contexts-page-0.json"))["groups"]), 1)
        err = load(os.path.join(FIX, "uip04-unrepresentable-path", "error-projection-failed.json"))
        self.assertEqual((err["error"], err["detail_code"]), ("projection_failed", "unrepresentable_path"))
        twelve = load(os.path.join(FIX, "uip04-synthetic-12-group-layout-capacity", "contexts-page-0.json"))
        self.assertEqual(len(twelve["groups"]), 12)
        notes = load(os.path.join(FIX, "uip04-synthetic-12-group-layout-capacity", "MANIFEST.json"))["notes"]
        self.assertIn("SYNTHETIC", notes)
        self.assertIn("not a classifier output", notes)


if __name__ == "__main__":
    unittest.main()
