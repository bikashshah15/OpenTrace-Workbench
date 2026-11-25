"""UIP-02: the shared inspector shell renders every FULL UIP-01B inspector fixture, and those fixtures are valid against the frozen
contract (checked here with the Python validator). The shell's *local* presentation model is deliberately NOT a UIP-01B payload: it
carries no binding, digest, canonical reference or schema field (asserted in tests/ui/unit/uip02_ui.test.mjs), so it is never run through
this validator and never described as validated."""
import glob
import json
import os
import shutil
import subprocess
import unittest

from opentrace_core.app import view_contracts as vc

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIX = os.path.join(REPO, "evidence", "uip", "fixtures")


def fixture_paths():
    return sorted(p for p in glob.glob(os.path.join(FIX, "*", "inspector-*.json")) if os.sep + "invalid" + os.sep not in p)


@unittest.skipUnless(shutil.which("node"), "node is required for the UI cross-check")
class InspectorShellCrossCheck(unittest.TestCase):
    def test_valid_fixtures_validate_and_render(self):
        paths = fixture_paths()
        self.assertGreaterEqual(len(paths), 6)
        for p in paths:
            with open(p, encoding="utf-8") as handle:
                vc.validate_payload("inspector", json.load(handle))   # raises ContractError when the frozen contract is violated
        proc = subprocess.run(["node", os.path.join(REPO, "tests", "ui", "uip02_render_fixtures.mjs"), *paths], capture_output=True, text=True, timeout=60, cwd=REPO)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for item in json.loads(proc.stdout):
            self.assertEqual(item["questions"], item["expected"], item["path"])
            self.assertEqual(item["origin"], "bound_inspector")
            self.assertTrue(item["inert"], item["path"])

    def test_invalid_inspector_fixtures_are_rejected_by_the_contract(self):
        bad = sorted(glob.glob(os.path.join(FIX, "invalid", "inspector-*.json")))
        self.assertTrue(bad)
        for p in bad:
            with open(p, encoding="utf-8") as handle:
                doc = json.load(handle)
            payload = doc.get("payload", doc)
            if not isinstance(payload, dict) or payload.get("schema") != "opentrace.workbench.inspector/1":
                continue
            with self.assertRaises(vc.ContractError, msg=p):
                vc.validate_payload("inspector", payload, request=doc.get("request"), expected_binding=doc.get("expected_binding"))


if __name__ == "__main__":
    unittest.main()
