"""I2-REQ-02/03 (CP2): fixture pins, patches, the v2 contract and its negotiated selector.

Core-only: no jsonschema. tools/contracts/check_examples.py cross-checks the same examples
against jsonschema 4.23.0 (dev only)."""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from opentrace_core import timeutil, validate
from opentrace_core.artifacts import ArtifactStore

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "evidence" / "fixtures" / "i2" / "go-acceptlang"
V2 = ROOT / "contracts" / "evidence" / "v2"
sha = lambda b: hashlib.sha256(b).hexdigest()

PINS = {  # contract section 2.2 and 2.4 (frozen)
    "go.mod": "c27f4195df35d814878a8c65c26db265f5011a091b7a9b746ed726504c147d16",
    "go.sum": "4c4a13f3b543e8a2a0bc254b16fcba71e6948f41808d3162f1a438a40c9346da",
    "negotiate.go": "e215fcd065370ac3fcd46ba869eaa4fdca183de450693a0505b19c56ad149c5c",
    "negotiate_test.go": "9db42012e27e122cd5e066d6fdd04bb6f97870511392cadb72604b014dbb5096",
    "cmd/negotiate/main.go": "9ecc19da482d13c52d02820fc2ae3a9e5b3db006aebd652feaf23e1945db0d47",
}
PATCHES = {
    "cand-min-fix": "0c64473a4e3bbaf7e79eba952c7984d35134cc228cb4277cccbfa152ddd0e8cb",
    "cand-latest-incompatible": "bcdf24007bf5a3c2aa0a414379c18b3a0817ad9debc7cdc30ce51abc136ab31e",
    "cand-regress": "6d163dcf598c3230d7ca4bc9e3ad8da341a42be74f380097e6aaf3af11be6f6a",
    "cand-oracle-tamper": "c140ceda43ac251630f8c020d19ab352d159f5fa12740b77a9bdb25344172be1",
}
MANIFEST_DIGEST = "ca850ae111d4809095c15dd8da9dba65a665235a8f5bbbdbcb31f784f2705b4c"


class FixturePinsTest(unittest.TestCase):
    def test_every_source_file_matches_its_pinned_digest(self):
        for rel, digest in PINS.items():
            self.assertEqual(sha((FIX / rel).read_bytes()), digest, rel)

    def test_source_manifest_reproduces_the_pinned_bytes_and_digest(self):
        files = [{"path": rel, "sha256": PINS[rel], "bytes": (FIX / rel).stat().st_size} for rel in sorted(PINS)]
        canonical = (json.dumps({"schema": "opentrace.source_manifest/1", "files": files}, sort_keys=True,
                                separators=(",", ":")) + "\n").encode()
        self.assertEqual((FIX / "source_manifest.json").read_bytes(), canonical)
        self.assertEqual(sha(canonical), MANIFEST_DIGEST)

    def test_readme_labels_the_fixture_synthetic_and_is_not_a_manifest_member(self):
        self.assertIn("SYNTHETIC", (FIX / "README.md").read_text())
        self.assertNotIn("README.md", json.loads((FIX / "source_manifest.json").read_text())["files"].__repr__())

    def test_patch_digests_and_manifest_labels(self):
        manifest = json.loads((FIX / "patches" / "MANIFEST.json").read_text())
        self.assertEqual(manifest["base_manifest_digest"], "sha256:" + MANIFEST_DIGEST)
        by_name = {p["name"]: p for p in manifest["patches"]}
        self.assertEqual(set(by_name), set(PATCHES))
        for name, digest in PATCHES.items():
            self.assertEqual(sha((FIX / "patches" / (name + ".patch")).read_bytes()), digest, name)
            self.assertEqual(by_name[name]["candidate_id"], "sha256:" + digest)
        self.assertEqual(by_name["cand-regress"]["label"], "SYNTHETIC")
        self.assertEqual(by_name["cand-oracle-tamper"]["label"], "SYNTHETIC")

    @unittest.skipUnless(shutil.which("git"), "git not available")
    def test_patches_apply_to_the_baseline_and_touch_only_their_listed_files(self):
        manifest = {p["name"]: p for p in json.loads((FIX / "patches" / "MANIFEST.json").read_text())["patches"]}
        for name in PATCHES:
            with tempfile.TemporaryDirectory() as tmp:
                for rel in PINS:
                    dest = Path(tmp) / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy(FIX / rel, dest)
                patch = FIX / "patches" / (name + ".patch")
                env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
                subprocess.run(["git", "apply", "--check", "-p1", str(patch)], cwd=tmp, check=True, env=env)
                subprocess.run(["git", "apply", "-p1", str(patch)], cwd=tmp, check=True, env=env)
                changed = sorted(rel for rel in PINS if sha((Path(tmp) / rel).read_bytes()) != PINS[rel])
                self.assertEqual(changed, manifest[name]["files"], name)

    def test_required_checks_spec_is_frozen(self):
        spec = json.loads((FIX / "required_checks.json").read_text())
        self.assertEqual([c["check_id"] for c in spec["checks"]], ["modverify", "build", "vet", "test", "modlist"])
        self.assertEqual([c["required"] for c in spec["checks"]], [True, True, True, True, False])
        self.assertEqual(spec["checks"][3]["argv"], ["go", "test", "-count=1", "-json", "-timeout", "60s", "./..."])
        self.assertEqual(spec["oracle_files"], ["negotiate_test.go"])
        raw = (FIX / "required_checks.json").read_bytes()
        self.assertEqual(raw, (json.dumps(spec, sort_keys=True, separators=(",", ":")) + "\n").encode())


class V2SelectorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.manifest = json.loads((V2 / "examples" / "manifest.json").read_text())
        self.store = ArtifactStore(Path(self.tmp.name) / "store")
        for rel in self.manifest["store_inputs"]:
            self.store.put((ROOT / rel).read_bytes(), media_type="text/plain", producer="fixture",
                           revision_binding="bound_by_digest")

    def load(self, rel):
        return json.loads((V2 / "examples" / rel).read_text())

    def test_major_2_is_unsupported_by_default_and_accepted_when_negotiated(self):
        payload = self.load("valid/capability_request.json")
        self.assertEqual(validate.check_structure("capability_request", payload).codes, ["unsupported_schema_version"])
        self.assertTrue(validate.check_structure("capability_request", payload, negotiated="2.0").ok)
        self.assertEqual(validate.check_structure("capability_request", payload, negotiated="1.0").codes,
                         ["unsupported_schema_version"])

    def test_major_1_still_validates_with_or_without_negotiation(self):
        v1 = json.loads((ROOT / "contracts/evidence/v1/examples/valid/capability_request.json").read_text())
        self.assertTrue(validate.check_structure("capability_request", v1).ok)
        self.assertTrue(validate.check_structure("capability_request", v1, negotiated="2.0").ok)

    def test_major_3_is_never_accepted(self):
        payload = self.load("valid/capability_request.json")
        payload["schema_version"] = "3.0"
        self.assertEqual(validate.check_structure("capability_request", payload, negotiated="2.0").codes,
                         ["unsupported_schema_version"])

    def test_every_v2_example_behaves_as_listed(self):
        def semantic(entry, instance):
            spec = entry["semantic"]
            return validate.validate_result(instance, self.load(spec["task"]), self.load(spec["capability"]),
                                            self.store, timeutil.parse_ts(spec["received_at"]), negotiated="2.0")
        for entry in self.manifest["valid"]:
            instance = self.load(entry["file"])
            self.assertTrue(validate.check_structure(entry["kind"], instance, "2.0").ok, entry["file"])
            if "semantic" in entry:
                self.assertTrue(semantic(entry, instance).ok, "%s: %s" % (entry["file"], semantic(entry, instance).codes))
        for entry in self.manifest["invalid"]:
            instance = self.load(entry["file"])
            if entry["layer"] == "schema":
                self.assertIn(entry["expected_code"], validate.check_structure(entry["kind"], instance, "2.0").codes,
                              entry["file"])
            else:
                self.assertIn(entry["expected_code"], semantic(entry, instance).codes, entry["file"])

    def test_a_2_0_result_is_not_accepted_without_negotiation(self):
        entry = next(e for e in self.manifest["valid"] if e["file"] == "valid/result_osv_positive.json")
        spec = entry["semantic"]
        report = validate.validate_result(self.load(entry["file"]), self.load(spec["task"]), self.load(spec["capability"]),
                                          self.store, timeutil.parse_ts(spec["received_at"]))
        self.assertEqual(report.codes, ["unsupported_schema_version"])


if __name__ == "__main__":
    unittest.main()
