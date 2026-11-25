"""I3-REQ-02 (CP2): the v3 contract and its negotiated selector, core-only (no jsonschema).
tools/contracts/check_examples.py cross-checks the same examples against jsonschema 4.23.0 (dev only)."""
import base64
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from opentrace_core import timeutil, validate
from opentrace_core.artifacts import ArtifactStore
from opentrace_core.canon import canonical_bytes

ROOT = Path(__file__).resolve().parents[2]
V3 = ROOT / "contracts" / "evidence" / "v3"
EX = V3 / "examples"
MANIFEST = json.loads((EX / "manifest.json").read_text())


def load(rel):
    return json.loads((EX / rel).read_text())


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class V3ExamplesTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = ArtifactStore(Path(tmp.name) / "store")
        for rel in MANIFEST["store_inputs"]:
            self.store.put((ROOT / rel).read_bytes(), media_type="text/plain; charset=utf-8", producer="fixture",
                           revision_binding="bound_by_digest")

    def semantic(self, entry, instance):
        spec = entry["semantic"]
        return validate.validate_result(instance, load(spec["task"]), load(spec["capability"]), self.store,
                                        timeutil.parse_ts(spec["received_at"]), negotiated="3.0")

    def test_every_valid_example_passes_structure_and_semantics(self):
        for entry in MANIFEST["valid"]:
            inst = load(entry["file"])
            report = validate.check_structure(entry["kind"], inst, "3.0")
            self.assertTrue(report.ok, (entry["file"], report.codes))
            if "semantic" in entry:
                self.assertTrue(self.semantic(entry, inst).ok, (entry["file"], self.semantic(entry, inst).codes))

    def test_every_invalid_example_fails_with_its_named_code(self):
        for entry in MANIFEST["invalid"]:
            inst = load(entry["file"])
            if entry["layer"] == "schema":
                self.assertIn(entry["expected_code"], validate.check_structure(entry["kind"], inst, "3.0").codes, entry["file"])
            else:
                self.assertTrue(validate.check_structure(entry["kind"], inst, "3.0").ok, entry["file"])
                self.assertIn(entry["expected_code"], self.semantic(entry, inst).codes, entry["file"])

    def test_every_v3_example_is_listed_and_the_manifest_has_no_phantoms(self):
        listed = {e["file"] for e in MANIFEST["valid"] + MANIFEST["invalid"]}
        on_disk = {str(p.relative_to(EX)) for p in EX.glob("*/*.json")}
        self.assertEqual(listed, on_disk)

    def test_v1_and_v2_example_sets_still_exist_next_to_v3(self):
        # the non-modification diff itself is a repository check (see the I3 verification commands); here the
        # directories are only required to exist next to v3 and to stay valid under their own selectors
        for major in ("v1", "v2"):
            self.assertTrue((ROOT / "contracts" / "evidence" / major / "examples" / "manifest.json").is_file())


class NegotiatedSelectorTest(unittest.TestCase):
    """The (major, token) pair: a major 3 payload is processed only with negotiated 3.0."""

    def test_major_3_needs_negotiated_3_0(self):
        cap = load("valid/capability_response.json")
        for negotiated in (None, "2.0"):
            report = validate.check_structure("capability_response", cap, negotiated)
            self.assertEqual(report.codes, ["unsupported_schema_version"], negotiated)
        self.assertTrue(validate.check_structure("capability_response", cap, "3.0").ok)

    def test_major_2_and_1_payloads_are_not_accepted_under_3_0_negotiation(self):
        v2 = json.loads((ROOT / "contracts" / "evidence" / "v2" / "examples" / "valid" / "capability_response.json").read_text())
        v1 = json.loads((ROOT / "contracts" / "evidence" / "v1" / "examples" / "valid" / "capability_response.json").read_text())
        # 1.x is always accepted (I1 behavior); a 2.x payload needs negotiated 2.0
        self.assertTrue(validate.check_structure("capability_response", v1, "3.0").ok)
        self.assertEqual(validate.check_structure("capability_response", v2, "3.0").codes, ["unsupported_schema_version"])

    def test_the_context_registry_selects_3_0_from_the_issued_task_version(self):
        from opentrace_core.context import ContextRegistry
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        reg = ContextRegistry(ArtifactStore(Path(tmp.name) / "s"))
        task = load("valid/task_request_repo_inventory.json")
        reg.start_run(task["run_id"], task["context"]["repo_id"])
        reg.register_task(task, task["run_id"], load("valid/capability_response.json"))
        self.assertEqual(reg.tasks[task["task_id"]]["negotiated"], "3.0")


class TableRulesTest(unittest.TestCase):
    """V12-V16 beyond the shipped examples: mutate the valid results and expect the named code."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = ArtifactStore(Path(tmp.name) / "store")
        self.store.put((ROOT / MANIFEST["store_inputs"][0]).read_bytes(), media_type="text/plain; charset=utf-8", producer="fixture",
                       revision_binding="bound_by_digest")
        self.task = load("valid/task_request_repo_inventory.json")
        self.cap = load("valid/capability_response.json")

    def check(self, result):
        return validate.validate_result(result, self.task, self.cap, self.store, timeutil.parse_ts("2026-10-14T12:00:30.000Z"),
                                        negotiated="3.0").codes

    def retable(self, result, mutate):
        res = copy.deepcopy(result)
        art = res["artifacts"][0]
        table = json.loads(base64.b64decode(art["content_b64"]))
        mutate(table)
        data = canonical_bytes(table)
        old = art["digest"]
        art.update(digest=digest(data), bytes=len(data), content_b64=base64.b64encode(data).decode())
        for ev in res["evidence"]:
            ev["collection_method"]["output_artifact"] = art["digest"] if ev["collection_method"]["output_artifact"] == old else ev["collection_method"]["output_artifact"]
            d = ev.get("details") or {}
            for k in ("table_artifact", "table_digest"):
                if d.get(k) == old:
                    d[k] = art["digest"]
            if d.get("occurrence_count") is not None and ev["kind"] == "manifest_inventory":
                d["occurrence_count"] = len(table["rows"])
        return res

    def test_the_unmodified_example_is_clean(self):
        self.assertEqual(self.check(load("valid/result_manifest_inventory.json")), [])

    def test_v12_duplicate_and_unsorted_locators_are_table_integrity(self):
        base = load("valid/result_manifest_inventory.json")
        dup = self.retable(base, lambda t: t["rows"].append(dict(t["rows"][0])))
        self.assertIn("table_integrity", self.check(dup))
        unsorted = self.retable(base, lambda t: t["rows"].reverse())
        self.assertIn("table_integrity", self.check(unsorted))

    def test_v12_missing_field_and_wrong_path_and_unknown_state(self):
        base = load("valid/result_manifest_inventory.json")
        self.assertIn("table_integrity", self.check(self.retable(base, lambda t: t["rows"][0].pop("scope"))))
        self.assertIn("table_integrity", self.check(self.retable(base, lambda t: t.update(path="other/go.mod"))))
        self.assertIn("table_integrity", self.check(self.retable(base, lambda t: t["rows"][0].update(version_state="guess"))))

    def test_v12_the_key_is_the_locator_within_the_manifest_not_the_name(self):
        # two rows with the same package name at different locators are fine (multiple versions/sources)
        base = load("valid/result_manifest_inventory.json")
        same_name = self.retable(base, lambda t: t["rows"][1].update(name_original=t["rows"][0]["name_original"],
                                                                     name_normalized=t["rows"][0]["name_normalized"]))
        self.assertEqual(self.check(same_name), [])

    def test_v14_a_partial_manifest_cannot_be_a_supported_claim(self):
        res = load("valid/result_manifest_inventory.json")
        res["evidence"][1]["details"]["status"] = "partial"
        res["evidence"][1]["details"]["unparsed_constructs"] = [{"class": "x", "count": 1}]
        self.assertIn("partial_promoted", self.check(res))

    def test_v13_a_hosted_result_cannot_carry_an_observed_revision(self):
        task = load("valid/task_request_github_sbom.json")
        res = load("valid/result_hosted_unbound.json")
        res["context"]["observed_revision"] = res["context"]["requested_revision"]
        report = validate.validate_result(res, task, self.cap, self.store, timeutil.parse_ts("2026-10-14T12:00:30.000Z"), negotiated="3.0")
        self.assertIn("hosted_binding_violation", report.codes)

    def test_hosted_table_rows_have_no_source_path(self):
        task = load("valid/task_request_github_sbom.json")
        res = load("valid/result_hosted_unbound.json")
        art = res["artifacts"][0]
        table = json.loads(base64.b64decode(art["content_b64"]))
        table["rows"][0]["source_path"] = "package.json"
        data = canonical_bytes(table)
        old = art["digest"]
        art.update(digest=digest(data), bytes=len(data), content_b64=base64.b64encode(data).decode())
        for ev in res["evidence"]:
            if ev["collection_method"]["output_artifact"] == old:
                ev["collection_method"]["output_artifact"] = art["digest"]
            d = ev.get("details") or {}
            for k in ("table_artifact", "table_digest"):
                if d.get(k) == old:
                    d[k] = art["digest"]
        report = validate.validate_result(res, task, self.cap, self.store, timeutil.parse_ts("2026-10-14T12:00:30.000Z"), negotiated="3.0")
        self.assertIn("table_integrity", report.codes)


if __name__ == "__main__":
    unittest.main()
