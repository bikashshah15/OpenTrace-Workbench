"""UIP-10 correction round: independent review findings UIP-10-IR-01 (incomplete coverage must not be completed_empty) and UIP-10-IR-02
(directory read failures must not become a complete traversal). Each case runs the real collector, the real discovery/assessment pipeline and
the real BOM candidates projection in process (no listening server, scanner, network, provider or browser). They assert the CORRECT behaviour and
fail on the reviewed source (660dbd0)."""
import os
import unittest
from unittest import mock

from opentrace_core.app import live_discovery, view_contracts
from opentrace_core.live import source_declarations as sd

from tests.core.app.test_live_discovery import Harness


def _sw(page):
    return next(c for c in page["capabilities"] if c["family"] == "software")


class ReviewCorrections(Harness):
    def setUp(self):
        super().setUp()
        self.begin()

    def end_to_end(self, root, **kw):
        out = self.collect(root, **kw)
        gaps, coll = self.run_discovery(out)
        self.analysis.gaps, self.analysis.collection = gaps, coll
        page = self.views().bom_candidates()
        view_contracts.validate_payload("bom_candidates", page)          # frozen schema compliance for every case
        return out, gaps, coll, page

    def assert_partial_with_zero_candidates(self, root, **kw):
        out, gaps, coll, page = self.end_to_end(root, **kw)
        self.assertEqual(gaps["status"], "compared")
        self.assertEqual(coll["software"], {"state": "partial", "reason_code": "partial_coverage"}, coll["code"])
        self.assertEqual(page["mode"], "discovery_compared")
        self.assertEqual(page["counts"]["candidates_total"], 0)
        self.assertEqual(_sw(page), {"family": "software", "state": "partial", "reason_code": "partial_coverage"})
        return out, coll

    # -- IR-01 -----------------------------------------------------------------
    def test_ir01_empty_requirements_plus_unreadable_encoding_is_partial_not_completed_empty(self):
        root = self.tree({"requirements.txt": b"", "requirements-z.txt": b"\xff\xfe\x00bad"})
        out, coll = self.assert_partial_with_zero_candidates(root)
        self.assertEqual((out["summary"]["collected"], out["summary"]["skipped"]["count"], out["summary"]["named_requirements"]), (1, 1, 0))

    def test_ir01_empty_requirements_plus_unsupported_declaration_is_partial(self):
        root = self.tree({"requirements.txt": b"", "package.json": b"{}"})
        out, coll = self.assert_partial_with_zero_candidates(root)
        self.assertEqual(out["summary"]["unsupported"]["count"], 1)

    def test_ir01_empty_requirements_plus_early_stop_is_partial(self):
        root = self.tree({"requirements.txt": b"", "sub/requirements.txt": b"flask==2.0\n"})
        with mock.patch.object(sd, "MAX_ENTRIES", 1):
            out, coll = self.assert_partial_with_zero_candidates(root)
        self.assertEqual(out["summary"]["traversal"]["count_kind"], "at_least")

    def _complete_empty(self, files, code):
        out, gaps, coll, page = self.end_to_end(self.tree(files))
        self.assertEqual((gaps["status"], coll["code"], page["mode"], page["counts"]["candidates_total"]), ("compared", code, "discovery_compared", 0))
        self.assertEqual(_sw(page), {"family": "software", "state": "completed_empty", "reason_code": "no_applicable_assets"})

    def test_ir01_complete_requirement_file_without_names_stays_completed_empty_with_zero_candidates(self):
        self._complete_empty({"requirements.txt": b"# nothing\n"}, "no_named_requirements")

    def test_ir01_complete_tree_without_requirement_files_stays_completed_empty_with_zero_candidates(self):
        self._complete_empty({"main.py": b"1\n"}, "no_requirement_files")

    def test_ir01_directive_only_files_that_yield_candidates_are_not_reported_completed_empty(self):
        out, gaps, coll, page = self.end_to_end(self.tree({"requirements.txt": b"-r other.txt\n"}))
        if page["counts"]["candidates_total"]:
            self.assertNotEqual(coll["software"]["state"], "completed_empty")
        else:
            self.assertEqual(coll["software"]["state"], "completed_empty")

    def test_ir01_populated_partial_result_keeps_candidates_and_partial_state(self):
        root = self.tree({"requirements.txt": b"definitely-not-in-the-sbom==1.0\n", "package.json": b"{}"})
        out, gaps, coll, page = self.end_to_end(root)
        self.assertGreater(page["counts"]["candidates_total"], 0)
        self.assertEqual(_sw(page)["state"], "partial")

    # -- IR-02 -----------------------------------------------------------------
    def _scandir_failing_on(self, suffix):
        real = os.scandir

        def fake(path="."):
            if str(path).endswith(suffix):
                raise PermissionError(13, "denied for /secret/place")
            return real(path)
        return mock.patch("os.scandir", fake)

    def test_ir02_unreadable_root_is_failed_never_a_complete_empty_traversal(self):
        root = self.tree({"requirements.txt": b"flask==2.0\n"})
        with mock.patch("os.scandir", side_effect=PermissionError(13, "denied for /secret/place")):
            out = self.collect(root)
        trav = out["summary"]["traversal"]
        self.assertFalse(trav["complete"])
        self.assertEqual((trav["stop_reason"], trav["count_kind"]), ("directory_unreadable", "at_least"))
        self.assertEqual(out["summary"]["unreadable"]["listed"], [{"path": "."}])
        self.assertEqual(live_discovery.classify(out["summary"]), ("failed", "upstream_failed", "collector_unreadable"))
        with mock.patch("os.scandir", side_effect=PermissionError(13, "denied for /secret/place")):
            gaps, coll = self.run_discovery(self.collect(root))
        self.assertEqual((gaps["status"], coll["software"]), ("not_compared", {"state": "failed", "reason_code": "upstream_failed"}))
        blob = repr((gaps, coll, out["record"]))
        self.assertNotIn("secret", blob)
        self.assertNotIn(self.dir, blob)

    def test_ir02_unreadable_subdirectory_next_to_a_usable_file_is_partial(self):
        root = self.tree({"requirements.txt": b"definitely-not-in-the-sbom==1.0\n", "locked/requirements.txt": b"hidden==1\n"})
        with self._scandir_failing_on("locked"):
            out, gaps, coll, page = self.end_to_end(root)
        s = out["summary"]
        self.assertEqual(s["collected"], 1)
        self.assertFalse(s["traversal"]["complete"])
        self.assertEqual(s["unreadable"], {"count": 1, "count_kind": "at_least", "listed": [{"path": "locked"}], "listed_limit": sd.MAX_UNREADABLE_LISTED})
        self.assertEqual(coll["software"], {"state": "partial", "reason_code": "partial_coverage"})
        self.assertEqual(_sw(page)["state"], "partial")
        self.assertNotIn("denied", repr(out["record"]))

    def test_ir02_unreadable_subdirectory_with_only_an_empty_file_is_partial_with_zero_candidates(self):
        root = self.tree({"requirements.txt": b"", "locked/x.txt": b"x"})
        with self._scandir_failing_on("locked"):
            self.assert_partial_with_zero_candidates(root)

    def test_ir02_listed_unreadable_directories_are_bounded(self):
        root = self.tree({"requirements.txt": b"flask\n", **{"d%03d/f.txt" % i: b"x" for i in range(sd.MAX_UNREADABLE_LISTED + 5)}})
        real = os.scandir

        def fake(path="."):
            if os.path.basename(str(path)).startswith("d0"):
                raise OSError("boom")
            return real(path)
        with mock.patch("os.scandir", fake):
            out = self.collect(root)
        u = out["summary"]["unreadable"]
        self.assertEqual(len(u["listed"]), sd.MAX_UNREADABLE_LISTED)
        self.assertGreater(u["count"], sd.MAX_UNREADABLE_LISTED)

    def test_ir02_cancellation_still_returns_no_record(self):
        root = self.tree({"requirements.txt": b"flask\n"})
        self.ticket.cancel_event.set()
        out = self.collect(root)
        self.assertEqual((out["status"], out["record"]), ("cancelled", None))


if __name__ == "__main__":
    unittest.main()
