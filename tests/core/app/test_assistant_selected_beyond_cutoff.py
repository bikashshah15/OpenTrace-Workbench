"""Stage 4 assistant completion: a valid, user-selected record that lies beyond its own source's normal retention cutoff must still be retained
and citable, without fabricating anything for an unknown selection. Synthetic rows only; no provider, no network."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/core"))

from opentrace_core.app.assistant.resolver import resolve_turn_evidence  # noqa: E402
from tests.core.app.test_assistant_resolver import BINDING, packet  # noqa: E402
from opentrace_core.app.assistant.resolver import _binding_digest  # noqa: E402

DIGEST = _binding_digest(BINDING)
BIG = "x" * 1900                    # makes the byte budget bite long before 60 rows are retained


def rows(prefix, n=60):
    return [("%s-%02d" % (prefix, i), "declaration", "Record %02d" % i, BIG, "%s:%s-%02d" % (prefix, prefix, i)) for i in range(n)]


def subject(kind, rid, label="selected"):
    return {"kind": kind, "id": rid, "label": label, "binding_digest": DIGEST}


def detail(context, source):
    return [e for e in context.evidence if e.source == source and e.kind != "source_state"]


class SelectedBeyondCutoff(unittest.TestCase):
    def resolve(self, subj, **sources):
        return resolve_turn_evidence(binding=BINDING, context_id="ctx-cutoff", subject=subj,
                                     projections={s: packet("completed", source=s, rows=r) for s, r in sources.items()})

    def test_baseline_without_selection_cuts_at_the_normal_cutoff(self):
        ctx = self.resolve(None, dependencies=rows("dep"))
        kept = detail(ctx, "dependencies")
        self.assertLess(len(kept), 24)
        self.assertTrue(ctx.sources["dependencies"]["truncated"])
        self.assertFalse(any("dep-55" in e.locator for e in kept), "dep-55 is beyond the normal cutoff")
        self.assertTrue(kept[0].locator.endswith("dep-00"))

    def test_selected_record_beyond_cutoff_is_retained_first_and_truncation_stays_visible(self):
        ctx = self.resolve(subject("dependency", "dep-55"), dependencies=rows("dep"))
        kept = detail(ctx, "dependencies")
        self.assertTrue(kept[0].locator.endswith("dep-55"), [e.locator for e in kept][:3])
        self.assertEqual(sum(1 for e in kept if e.locator.endswith("dep-55")), 1, "retained exactly once")
        self.assertTrue(ctx.sources["dependencies"]["truncated"])
        self.assertTrue(any("truncated" in x for x in ctx.limitations))
        self.assertEqual(ctx.subject["id"], "dep-55")
        self.assertLessEqual(len(ctx.evidence), 24)
        self.assertLessEqual(sum(len(e.excerpt.encode("utf-8")) for e in ctx.evidence), 32_768)
        # the citation identity of the retained record is a real, turn-local evidence id; nothing was invented
        ids = [e.evidence_id for e in ctx.evidence]
        self.assertEqual(len(ids), len(set(ids)))

    def test_selection_matched_by_locator_suffix_when_record_id_differs(self):
        r = [(("rec-%02d" % i), "declaration", "R%02d" % i, BIG, "dependencies:dep-%02d" % i) for i in range(60)]
        ctx = self.resolve(subject("dependency", "dep-58"), dependencies=r)
        self.assertTrue(detail(ctx, "dependencies")[0].locator.endswith(":dep-58"))

    def test_selected_record_in_a_later_source_is_not_starved_by_an_alphabetically_earlier_source(self):
        ctx = self.resolve(subject("crypto", "cry-57"), dependencies=rows("dep"), crypto=rows("cry"))
        kept = detail(ctx, "crypto")
        self.assertTrue(kept and kept[0].locator.endswith("cry-57"))
        self.assertTrue(ctx.sources["crypto"]["truncated"])

    def test_unknown_selected_id_fabricates_nothing_and_changes_no_order(self):
        base = self.resolve(None, dependencies=rows("dep"))
        ctx = self.resolve(subject("dependency", "dep-99"), dependencies=rows("dep"))
        self.assertEqual([e.locator for e in detail(ctx, "dependencies")], [e.locator for e in detail(base, "dependencies")])
        self.assertFalse(any("dep-99" in e.locator or "dep-99" in e.label for e in ctx.evidence))

    def test_selected_record_of_a_failed_source_stays_excluded(self):
        bad = packet("failed", source="dependencies", reason="scanner_failed")
        ctx = resolve_turn_evidence(binding=BINDING, context_id="ctx-failed", subject=subject("dependency", "dep-55"), projections={"dependencies": bad})
        self.assertEqual(detail(ctx, "dependencies"), [])
        self.assertEqual(ctx.sources["dependencies"]["state"], "failed")


if __name__ == "__main__":
    unittest.main()
