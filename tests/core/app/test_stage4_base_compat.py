"""Stage 4 absent-input compatibility against the PINNED base 436844b (S4R-11 / pre-launch B).

tests/core/app/fixtures/s4_base_436844b_golden.json was produced by running ``s4_golden_cases.py`` against commit 436844bcc502f36b12dace00eb21fb0aa5d4cc49
BEFORE any Stage 4 change. These tests compare the candidate's production output to that file (never to the candidate's own output).

INTENTIONAL DIFFERENCES (every one is asserted, none is tolerated silently):
  D1  declarations record: additive keys ``ai_source`` and ``crypto_source``; the ``limitations`` string gains one passage describing them.
  D2  declarations ``record_sha256`` therefore changes for EVERY live scan, with or without AI/crypto evidence (the digest hashes the whole record).
  D3  collection summary gains ``ai_source`` and ``crypto_source``.
  D4  a live scan always passes the collection result: a complete scan that observed nothing leaves both tabs identical to the base (test_stage4_review_fixes.CollectedEmptyLive);
      an INCOMPLETE scan that observed nothing adds an experimental 'partial' source producer and makes availability 'partial' (by design, never 'completed').
  D5  every live scan with hashlib calls now lists hashlib algorithm assets in the Crypto tab (experimental source observations); a local module named hashlib makes the producer partial.
Everything else in the declarations record, and every AI/Crypto page payload for inputs without source evidence, is identical to the base."""
import hashlib
import json
import os
import unittest

from tests.core.app import s4_golden_cases
from opentrace_core.live import source_declarations as sd

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = json.load(open(os.path.join(HERE, "fixtures", "s4_base_436844b_golden.json")))
BASE_SHA = "436844bcc502f36b12dace00eb21fb0aa5d4cc49"
PASSAGE_START, PASSAGE_END = "ai_source holds statically observed", "crypto_call_sites are statically observed"


class AbsentInputCompat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.now = s4_golden_cases.cases()

    def test_golden_is_from_the_base_and_has_no_stage4_keys(self):
        self.assertNotIn("ai_source", GOLDEN["declarations.record"])
        self.assertNotIn("crypto_source", GOLDEN["declarations.record"])
        self.assertNotIn("ai_source", GOLDEN["declarations.summary_keys"])

    def test_every_page_payload_without_source_evidence_is_identical(self):
        names = [k for k in GOLDEN if k.startswith(("ai.", "crypto."))]
        self.assertGreaterEqual(len(names), 12)
        for name in names:
            with self.subTest(name):
                self.assertEqual(json.dumps(self.now[name], sort_keys=True), json.dumps(GOLDEN[name], sort_keys=True))

    def test_declarations_record_differs_only_by_the_documented_additions(self):
        rec = json.loads(json.dumps(self.now["declarations.record"]))
        self.assertEqual(set(rec) - set(GOLDEN["declarations.record"]), {"ai_source", "crypto_source"})                       # D1
        rec.pop("ai_source")
        rec.pop("crypto_source")
        hit = [n for n, t in enumerate(rec["limitations"]) if PASSAGE_START in t]
        self.assertEqual(len(hit), 1)
        lim = rec["limitations"][hit[0]]
        i, j = lim.index(PASSAGE_START), lim.index(PASSAGE_END)
        self.assertGreater(j, i)
        rec["limitations"][hit[0]] = lim[:i] + lim[j:]
        self.assertEqual(json.dumps(rec, sort_keys=True), json.dumps(GOLDEN["declarations.record"], sort_keys=True))

    def test_digest_changes_for_every_scan_for_the_documented_reason_and_is_deterministic(self):
        self.assertNotEqual(self.now["declarations.digest"], GOLDEN["declarations.digest"])                                      # D2
        self.assertEqual(self.now["declarations.digest"], hashlib.sha256(sd.canonical_bytes(self.now["declarations.record"])).hexdigest())
        again = s4_golden_cases.cases()
        self.assertEqual(again["declarations.digest"], self.now["declarations.digest"])                                          # deterministic identity
        self.assertEqual(sd.SCHEMA, GOLDEN["declarations.record"]["schema"])                                                     # schema/version unchanged

    def test_consumer_binding_accepts_the_extended_record(self):
        from opentrace_core.bombridge import discovery as bbd
        rec = self.now["declarations.record"]
        raw = sd.canonical_bytes(rec)
        bundle = {"capture": {"repository": {"revision": rec["revision"], "url": rec["repository"]}}}
        got, texts = bbd.read_declarations(bundle, raw, expected_sha256=hashlib.sha256(raw).hexdigest(), read_copy=lambda p: (_ for _ in ()).throw(KeyError(p)))
        self.assertEqual(got["requirement_files"], GOLDEN["declarations.record"]["requirement_files"])   # the UIP-10 comparison input is unchanged
        self.assertEqual(texts, {})
        with self.assertRaises(bbd.InputError):                                                          # a wrong pin is still refused
            bbd.read_declarations(bundle, raw, expected_sha256=GOLDEN["declarations.digest"], read_copy=lambda p: b"")

    def test_summary_and_copies(self):
        self.assertEqual(set(self.now["declarations.summary_keys"]) - set(GOLDEN["declarations.summary_keys"]), {"ai_source", "crypto_source"})   # D3
        self.assertEqual(set(GOLDEN["declarations.summary_keys"]) - set(self.now["declarations.summary_keys"]), set())
        self.assertEqual(self.now["declarations.copies"], GOLDEN["declarations.copies"])


if __name__ == "__main__":
    unittest.main()
