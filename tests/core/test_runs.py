import unittest

from opentrace_core import runs


class RunStateMachineTest(unittest.TestCase):
    def test_happy_path(self):
        run = runs.Run("r", "repo")
        run.transition(runs.RUNNING)
        run.transition(runs.SUCCEEDED)
        self.assertTrue(run.final)
        self.assertEqual([h[0] for h in run.history], ["queued", "running", "succeeded"])

    def test_final_states_are_immutable(self):
        for final in (runs.PARTIAL, runs.SUCCEEDED, runs.FAILED, runs.CANCELED):
            run = runs.Run("r", "repo")
            run.transition(runs.RUNNING)
            run.transition(final)
            for target in (runs.QUEUED, runs.RUNNING, runs.PARTIAL, runs.SUCCEEDED, runs.FAILED, runs.CANCELED):
                with self.assertRaises(runs.InvalidTransition):
                    run.transition(target)
            self.assertEqual(run.state, final)

    def test_partial_never_becomes_succeeded(self):
        run = runs.Run("r", "repo")
        run.transition(runs.RUNNING)
        run.transition(runs.PARTIAL, "missing_evidence")
        with self.assertRaises(runs.InvalidTransition):
            run.transition(runs.SUCCEEDED)

    def test_queued_cannot_skip_to_success(self):
        run = runs.Run("r", "repo")
        with self.assertRaises(runs.InvalidTransition):
            run.transition(runs.SUCCEEDED)
        run.transition(runs.CANCELED, "superseded")
        self.assertEqual(run.reason, "superseded")


if __name__ == "__main__":
    unittest.main()
