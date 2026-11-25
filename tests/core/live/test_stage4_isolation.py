"""Stage 4 collector failure isolation (S4R/C): a fault in one new phase must not discard requirement files, hashlib sites or the other collector.

Synthetic trees only; faults are injected by patching the phase entry points. Nothing is imported, executed, downloaded or called."""
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from opentrace_core.live import ai_source, crypto_source, source_declarations as sd

URL, SHA = "https://github.com/acme/widget", "c" * 40
FILES = {
    "requirements.txt": "flask==2.0\n",
    "app/a.py": "import hashlib\nimport onnxruntime\nimport jwt\nhashlib.sha256(b'x')\njwt.encode({}, 'k', algorithm='HS256')\n",
}


def boom(*a, **k):
    raise RuntimeError("injected")


class Isolation(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ot-iso-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        for rel, data in FILES.items():
            path = os.path.join(self.root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "w").write(data)

    def run_sd(self, **kw):
        return sd.collect(self.root, URL, SHA, **kw)

    def test_baseline_has_everything(self):
        out = self.run_sd()
        rec = out["record"]
        self.assertEqual(len(rec["requirement_files"]), 1)
        self.assertTrue(rec["crypto_call_sites"])
        self.assertTrue(rec["ai_source"]["runtimes"])
        self.assertTrue(rec["crypto_source"]["jwt"])
        self.assertNotIn("failed", rec["ai_source"]["summary"])

    def test_ai_phase_fault_keeps_everything_else(self):
        with mock.patch.object(ai_source, "run_phase", boom):
            out = self.run_sd()
        self.assertEqual(out["status"], "collected")
        rec = out["record"]
        self.assertEqual(len(rec["requirement_files"]), 1)          # UIP-10 comparison input intact
        self.assertTrue(rec["crypto_call_sites"])                   # hashlib sites intact
        self.assertTrue(rec["crypto_source"]["jwt"])                # the other new collector intact
        self.assertTrue(rec["crypto_source"]["summary"]["complete"])
        self.assertEqual(rec["ai_source"]["runtimes"], [])
        self.assertTrue(rec["ai_source"]["summary"]["failed"])
        self.assertFalse(rec["ai_source"]["summary"]["complete"])
        self.assertEqual(rec["ai_source"]["summary"]["count_kind"], "at_least")
        self.assertEqual(ai_source.present(out), {"state": "failed", "code": "collector_error"})
        self.assertEqual(crypto_source.present(out)["state"], "collected")

    def test_crypto_phase_fault_keeps_everything_else(self):
        with mock.patch.object(crypto_source, "run_phase", boom):
            out = self.run_sd()
        rec = out["record"]
        self.assertEqual(len(rec["requirement_files"]), 1)
        self.assertTrue(rec["crypto_call_sites"])
        self.assertTrue(rec["ai_source"]["runtimes"])
        self.assertTrue(rec["ai_source"]["summary"]["complete"])
        self.assertEqual(rec["crypto_source"]["jwt"], [])
        self.assertTrue(rec["crypto_source"]["summary"]["failed"])
        pres = crypto_source.present(out)
        self.assertEqual(pres["state"], "collected")                # the hashlib sites survive
        self.assertTrue(pres["hashlib"])
        self.assertFalse(pres["summary"]["complete"])                # ...and the source producer reads partial, never complete

    def test_both_phases_fault(self):
        with mock.patch.object(ai_source, "run_phase", boom), mock.patch.object(crypto_source, "run_phase", boom):
            out = self.run_sd()
        self.assertEqual(out["status"], "collected")
        self.assertEqual(len(out["record"]["requirement_files"]), 1)
        self.assertTrue(out["record"]["crypto_call_sites"])

    def test_cancellation_is_not_swallowed(self):
        ev = threading.Event()
        ev.set()
        self.assertEqual(self.run_sd(cancel=ev)["status"], "cancelled")
        ev2 = threading.Event()

        def cancelling(*a, **k):
            ev2.set()
            return None
        with mock.patch.object(ai_source, "run_phase", cancelling):
            self.assertEqual(self.run_sd(cancel=ev2)["status"], "cancelled")

    def test_soft_budget_of_each_phase_is_bounded_and_fits_the_stage(self):
        self.assertLessEqual(ai_source.BUDGET_SECONDS + crypto_source.BUDGET_SECONDS, 20.0)
        ticks = iter(range(0, 10_000, 100))                           # a clock that jumps past any budget
        out = sd.collect(self.root, URL, SHA, clock=lambda: next(ticks))
        for key in ("ai_source", "crypto_source"):
            self.assertTrue(out["record"][key]["summary"]["deadline_hit"] or out["record"]["searched"]["traversal"]["stop_reason"])
            self.assertFalse(out["record"][key]["summary"]["complete"])


if __name__ == "__main__":
    unittest.main()
