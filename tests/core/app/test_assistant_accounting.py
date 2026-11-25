import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/core"))

from opentrace_core.app.assistant.accounting import (  # noqa: E402
    BudgetError,
    SpendLedger,
    worst_case_micro_usd,
)


class SpendLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "assistant-ledger.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def reserve(self, ledger, key, *, input_tokens=16000, output_tokens=2048,
                in_rate=100000, out_rate=500000):
        return ledger.reserve(key, "gpt-6-luna", input_tokens=input_tokens, output_tokens=output_tokens,
                              input_micro_usd_per_million=in_rate,
                              output_micro_usd_per_million=out_rate)

    def test_model_price_upper_bound_includes_full_output_and_rounds_up(self):
        self.assertEqual(worst_case_micro_usd(16000, 2048, 100000, 500000), 2624)
        self.assertEqual(worst_case_micro_usd(1, 1, 1, 1), 2)
        with self.assertRaises(ValueError):
            worst_case_micro_usd(1, -1, 1, 1)

    def test_reserve_then_dispatch_then_settle_releases_unused_amount(self):
        ledger = SpendLedger(self.path)
        reservation = self.reserve(ledger, "r1")
        self.assertEqual(reservation.reserve_micro_usd, 2624)
        self.assertEqual(ledger.snapshot().reserved_micro_usd, 2624)
        ledger.mark_dispatched("r1")
        overrun = ledger.settle("r1", 1100)
        self.assertFalse(overrun)
        snapshot = ledger.snapshot()
        self.assertEqual((snapshot.spend_micro_usd, snapshot.reserved_micro_usd), (1100, 0))
        self.assertEqual(snapshot.dispatches, 1)

    def test_restart_keeps_inflight_reservation_conservative_without_prompt_data(self):
        first = SpendLedger(self.path)
        self.reserve(first, "r1")
        first.mark_dispatched("r1")
        second = SpendLedger(self.path)
        snap = second.snapshot()
        self.assertEqual(snap.reserved_micro_usd, 2624)
        self.assertEqual(snap.dispatches, 1)
        row = second.reservation("r1")
        self.assertEqual(row["state"], "dispatched")
        with open(self.path, "rb") as f:
            raw = f.read()
        self.assertNotIn(b"What was observed", raw)
        self.assertNotIn(b"evidence", raw)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_initialization_never_changes_process_umask_and_rejects_symlink(self):
        before = os.umask(0)
        os.umask(before)
        SpendLedger(self.path)
        after = os.umask(0)
        os.umask(after)
        self.assertEqual(after, before)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        link = os.path.join(self.tmp.name, "linked-ledger.sqlite3")
        os.symlink(self.path, link)
        with self.assertRaises(OSError):
            SpendLedger(link)
        public_dir = os.path.join(self.tmp.name, "public-dir")
        os.mkdir(public_dir, 0o755)
        os.chmod(public_dir, 0o755)
        public_ledger = os.path.join(public_dir, "ledger.sqlite3")
        with self.assertRaisesRegex(ValueError, "owner-owned and private"):
            SpendLedger(public_ledger)

    def test_uncertain_usage_remains_reserved_and_counts_dispatch(self):
        ledger = SpendLedger(self.path)
        self.reserve(ledger, "r1")
        ledger.mark_dispatched("r1")
        ledger.mark_uncertain("r1")
        snap = ledger.snapshot()
        self.assertEqual(snap.reserved_micro_usd, 2624)
        self.assertEqual(snap.dispatches, 1)
        with self.assertRaises(BudgetError):
            ledger.settle("r1", 0)

    def test_pre_dispatch_failure_releases_reservation_without_consuming_dispatch(self):
        ledger = SpendLedger(self.path, dispatch_limit=1)
        self.reserve(ledger, "r1")
        ledger.release_before_dispatch("r1")
        self.assertEqual(ledger.snapshot().dispatches, 0)
        self.reserve(ledger, "r2")
        ledger.mark_dispatched("r2")
        self.assertEqual(ledger.snapshot().dispatches, 1)
        with self.assertRaises(BudgetError):
            self.reserve(ledger, "r3")

    def test_hard_budget_dispatch_and_per_call_ceiling(self):
        ledger = SpendLedger(self.path, total_limit_micro_usd=500, dispatch_limit=40,
                             per_dispatch_limit_micro_usd=200)
        self.reserve(ledger, "r1", input_tokens=10, output_tokens=10, in_rate=1_000_000, out_rate=1_000_000)
        ledger.mark_dispatched("r1")
        ledger.settle("r1", 250)
        self.reserve(ledger, "r2", input_tokens=10, output_tokens=10, in_rate=1_000_000, out_rate=1_000_000)
        ledger.mark_dispatched("r2")
        ledger.settle("r2", 250)
        with self.assertRaises(BudgetError):
            self.reserve(ledger, "r3", input_tokens=10, output_tokens=10,
                         in_rate=1_000_000, out_rate=1_000_000)
        with self.assertRaises(BudgetError):
            self.reserve(ledger, "too-large", input_tokens=100, output_tokens=100,
                         in_rate=1_000_000, out_rate=1_000_000)

    def test_global_reservation_is_atomic_across_ledger_instances(self):
        ledgers = [SpendLedger(self.path, total_limit_micro_usd=1000, dispatch_limit=40,
                               per_dispatch_limit_micro_usd=200) for _ in range(8)]
        barrier = threading.Barrier(len(ledgers))
        successes, failures = [], []
        def reserve_one(i, ledger):
            barrier.wait()
            try:
                self.reserve(ledger, "r" + str(i), input_tokens=10, output_tokens=10,
                             in_rate=10_000_000, out_rate=10_000_000)
                successes.append(i)
            except BudgetError as exc:
                failures.append(exc.code)
        threads = [threading.Thread(target=reserve_one, args=(i, ledger)) for i, ledger in enumerate(ledgers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual((len(successes), len(failures)), (5, 3))
        self.assertEqual(SpendLedger(self.path).snapshot().reserved_micro_usd, 1000)

    def test_dollar_and_per_request_ceilings_are_fixed_and_the_dispatch_allowance_is_bounded(self):
        ledger = SpendLedger(self.path, total_limit_micro_usd=99_000_000,
                             dispatch_limit=900, per_dispatch_limit_micro_usd=9_000_000)
        self.assertEqual(ledger.total_limit, 5_000_000, "the dollar budget cannot be raised by configuration")
        self.assertEqual(ledger.per_dispatch_limit, 200_000)
        self.assertEqual(ledger.dispatch_limit, 900, "an operator allowance sized for interactive use is honoured")
        self.assertEqual(SpendLedger(self.path).dispatch_limit, 400, "the default allowance")
        self.assertEqual(SpendLedger(self.path, dispatch_limit=10 ** 9).dispatch_limit, 10_000, "and it has a sanity ceiling")
        small = SpendLedger(self.path, dispatch_limit=3)
        for index in range(3):
            self.reserve(small, "r" + str(index), input_tokens=0, output_tokens=1, in_rate=0, out_rate=1)
        self.assertEqual(small.snapshot().remaining_dispatches, 0)
        with self.assertRaises(BudgetError) as caught:
            self.reserve(small, "r3", input_tokens=0, output_tokens=1, in_rate=0, out_rate=1)
        self.assertEqual(caught.exception.code, "dispatch_limit")
        with self.assertRaises(BudgetError):
            self.reserve(ledger, "over-tokens", input_tokens=16001, output_tokens=1,
                         in_rate=1, out_rate=1)

    def test_overrun_is_retained_as_actual_cost_and_never_silently_hidden(self):
        ledger = SpendLedger(self.path, total_limit_micro_usd=1000)
        self.reserve(ledger, "r1", input_tokens=10, output_tokens=10,
                     in_rate=1_000_000, out_rate=1_000_000)
        ledger.mark_dispatched("r1")
        self.assertTrue(ledger.settle("r1", 251))
        self.assertEqual(ledger.snapshot().spend_micro_usd, 251)
        self.assertEqual(ledger.reservation("r1")["state"], "settled_overrun")


if __name__ == "__main__":
    unittest.main()
