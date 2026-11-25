import unittest

from opentrace_core.intake.state import (
    ARTIFACT_OUTCOMES, GenerationGuard, InvalidTransition, State, transition,
)


class StateTest(unittest.TestCase):
    def ready(self, manual_sha=None, preview="p", fingerprint="f", resolved_at=1000):
        state = State(status="resolving", manual_sha=manual_sha, inputs_fingerprint=fingerprint)
        return transition(state, "resolved_ok", preview=preview, resolved_at=resolved_at,
                          inputs_fingerprint=fingerprint)

    def test_invalid_edit_drops_preview_and_advanced_off_removes_manual_revision(self):
        ready = self.ready(manual_sha="abcdef1")
        invalid = transition(ready, "edit_invalid", inputs_fingerprint="bad")
        self.assertEqual(invalid.status, "invalid")
        self.assertIsNone(invalid.preview)
        state = transition(ready, "advanced_off")
        self.assertEqual(state.status, "stale")
        self.assertIsNone(state.manual_sha)
        self.assertIsNone(state.preview)
        with self.assertRaises(InvalidTransition):
            transition(state, "start", now=1001)

    def test_C5_advanced_off_during_resolution_rejects_late_results(self):
        resolving = State(status="resolving", manual_sha="abcdef1", preview="pending")
        stale = transition(resolving, "advanced_off")
        self.assertEqual(stale.status, "stale")
        self.assertIsNone(stale.preview)
        self.assertIsNone(stale.manual_sha)
        with self.assertRaises(InvalidTransition):
            transition(stale, "resolved_ok", preview="late", resolved_at=1000)
        with self.assertRaises(InvalidTransition):
            transition(stale, "resolved_error", status="unavailable")

    def test_resolution_freshness_and_input_change(self):
        ready = self.ready()
        self.assertEqual(transition(ready, "clock_tick", now=1600).status, "ready")
        stale = transition(ready, "clock_tick", now=1601)
        self.assertEqual(stale.status, "stale")
        self.assertIsNone(stale.preview)
        changed = transition(ready, "clock_tick", now=1001, inputs_fingerprint="changed")
        self.assertEqual(changed.status, "stale")
        with self.assertRaises(InvalidTransition):
            transition(ready, "start", now=1001, inputs_fingerprint="changed")

    def test_C6_start_requires_now_and_accepts_exactly_600_seconds(self):
        ready = self.ready(resolved_at=1000)
        with self.assertRaises(InvalidTransition):
            transition(ready, "start")
        with self.assertRaises(InvalidTransition):
            transition(ready, "start", now=1601)
        with self.assertRaises(InvalidTransition):
            transition(ready, "start", now=10 ** 1000)
        self.assertEqual(transition(ready, "start", now=1600).status, "acquiring")

    def test_no_acquisition_progress_before_start_and_artifact_outcomes_are_distinct(self):
        ready = self.ready()
        with self.assertRaises(InvalidTransition):
            transition(ready, "acquisition_partial", artifacts={})
        acquiring = transition(ready, "start", now=1001)
        self.assertEqual(acquiring.status, "acquiring")
        partial = transition(acquiring, "acquisition_partial", artifacts={"sbom": "partial"})
        self.assertEqual(partial.status, "partial")
        self.assertEqual(len(set(ARTIFACT_OUTCOMES)), 3)
        self.assertEqual(set(ARTIFACT_OUTCOMES), {"missing", "failed", "zero_record_success"})

    def test_other_resolution_and_lifecycle_transitions(self):
        resolving = transition(State(), "submit", inputs_fingerprint="f")
        self.assertEqual(resolving.status, "resolving")
        unavailable = transition(resolving, "resolved_error", status="unavailable")
        self.assertEqual(unavailable.status, "unavailable")
        self.assertEqual(transition(unavailable, "submit").status, "resolving")
        ready = self.ready()
        self.assertEqual(transition(ready, "cancel").status, "cancelled")
        self.assertEqual(transition(ready, "reset"), State())
        with self.assertRaises(InvalidTransition):
            transition(State(status="acquiring"), "edit_invalid")

    def test_generation_guard_discards_older_overlapping_result(self):
        guard = GenerationGuard()
        first = guard.begin()
        second = guard.begin()
        state = State(status="resolving")
        self.assertTrue(guard.accept(second))
        state = transition(state, "resolved_ok", preview="new", resolved_at=1001)
        if guard.accept(first):
            state = transition(state, "resolved_ok", preview="old", resolved_at=1000)
        self.assertEqual(state.preview, "new")
        guard.end()
        self.assertFalse(guard.accept(second))


if __name__ == "__main__":
    unittest.main()
