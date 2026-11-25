"""UIP-01B: the existing Workbench view responses are unchanged (contract test T6). Runs the existing handlers in process on the
recorded demo inputs (loopback and the engine's spawn IPC only) and compares them with the committed snapshots."""
import os
import re
import unittest

from tests.core.app.test_view_contracts import FIXTURES, jload, load_builder

SNAP = os.path.join(FIXTURES, "legacy-view-snapshots")


class LegacySnapshots(unittest.TestCase):
    def test_existing_routes_return_exactly_the_recorded_snapshots(self):
        B = load_builder()
        manifest = jload(os.path.join(SNAP, "MANIFEST.json"))
        names = sorted(e["path"] for e in manifest["files"])
        self.assertEqual(names, sorted(["contexts.json", "dependencies-per-side-6.json", "dependencies-per-side-1.json", "crypto.json", "ai.json", "bom.json",
                                        "gaps-offset-0.json", "gap-first.json", "dependencies-network.json"]))
        with B.no_external_network():
            with B.recorded_demo() as (client, analysis, body):
                first = jload(os.path.join(SNAP, "gaps-offset-0.json"))["items"][0]["candidate_id"]
                live = B.legacy_snapshots(client, analysis, first)
        for name, payload in live.items():
            self.assertEqual(payload, jload(os.path.join(SNAP, name + ".json")), name)

    def test_snapshots_carry_the_fixed_session_value_only(self):
        for f in os.listdir(SNAP):
            if f == "MANIFEST.json":
                continue
            with open(os.path.join(SNAP, f), encoding="utf-8") as handle:
                text = handle.read()
            for sid in re.findall(r'"session_id": "([0-9a-f]{32})"', text):
                self.assertEqual(sid, "0" * 31 + "1", f)
        self.assertIn("session_id (random per run) replaced by a fixed value", jload(os.path.join(SNAP, "MANIFEST.json"))["normalized"])

    def test_existing_page_size_and_default_focus_behaviour_are_snapshotted_as_is(self):
        # recorded, not endorsed: the old routes keep per_side 1/6 and their own focus rule until later increments replace them
        six, one = jload(os.path.join(SNAP, "dependencies-per-side-6.json")), jload(os.path.join(SNAP, "dependencies-per-side-1.json"))
        self.assertEqual((six["per_side"], one["per_side"]), (6, 1))
        self.assertEqual(jload(os.path.join(SNAP, "gaps-offset-0.json"))["totals"]["candidates"], 79)


if __name__ == "__main__":
    unittest.main()
