"""I2-REQ-09: the exact 14-task schedule, unadvertised operations and the legacy peer (U10a)."""
import unittest

from opentrace_core.context import ContextRegistry
from opentrace_investigator import i2
from opentrace_investigator.investigator import Investigator
from opentrace_investigator.transport import SpecialistUnavailable

from tests.helpers import fixture_store, valid

D = "sha256:" + "d" * 64
INPUTS = i2.I2Inputs("repo-1", D, "sha256:" + "c" * 64, D, D, D, D, D,
                     {v: D for v in ("baseline", "cand-min-fix", "cand-latest-incompatible", "cand-regress", "cand-oracle-tamper")},
                     {n: "sha256:" + str(i) * 64 for i, n in enumerate(("cand-min-fix", "cand-latest-incompatible", "cand-regress", "cand-oracle-tamper"), 1)})


class Recorder:
    def __init__(self):
        self.sent = []

    def post(self, message, timeout=None):
        self.sent.append(message)
        raise SpecialistUnavailable("stub")


def investigator(case, version, operations):
    store, _ = fixture_store(case)
    rec = Recorder()
    a = Investigator(rec, ContextRegistry(store), enable_v2=True)
    cap = valid("capability_response")
    cap["operations"] = operations
    a.capability, a.version = cap, version
    return a, rec


class ScheduleTest(unittest.TestCase):
    def test_schedule_is_exactly_fourteen_in_contract_order(self):
        self.assertEqual(len(i2.SCHEDULE), 14)
        self.assertEqual(i2.SCHEDULE[:4], [("go_mod_inventory", "baseline"), ("osv_advisory_match", "baseline"),
                                           ("govulncheck_source", "baseline"), ("change_validate", "baseline")])
        self.assertEqual(i2.SCHEDULE[4:7], [(op, "cand-min-fix") for op in ("change_validate", "osv_advisory_match", "govulncheck_source")])
        self.assertEqual(i2.SCHEDULE[-1], ("change_validate", "cand-oracle-tamper"))
        self.assertEqual(sum(1 for op, v in i2.SCHEDULE if op == "change_validate" and v == "baseline"), 1)

    def test_u10a_unadvertised_operations_are_unknown_and_nothing_else_is_sent(self):
        a, rec = investigator(self, "1.0", ["go_mod_inventory"])
        atts = i2.run_investigation(a, INPUTS)
        self.assertEqual(len(atts), 14)
        self.assertEqual(len(rec.sent), 1)                      # only the 1.0 inventory task
        self.assertEqual(rec.sent[0]["Content"]["schema_version"], "1.0")
        unsent = [x for x in atts if x["task"].get("unsent")]
        self.assertEqual(len(unsent), 13)
        self.assertEqual({x["rejection"] for x in unsent}, {"unsupported_operation"})

    def test_v2_peer_receives_each_advertised_operation_with_the_capture_set(self):
        ops = ["go_mod_inventory", "osv_advisory_match", "govulncheck_source", "change_validate"]
        a, rec = investigator(self, "2.0", ops)
        i2.run_investigation(a, INPUTS)
        self.assertEqual(len(rec.sent), 14)
        for msg in rec.sent:
            self.assertEqual(msg["Content"]["capture_set_id"], INPUTS.capture_set_id)
            self.assertEqual(msg["Content"]["schema_version"], "2.0")


if __name__ == "__main__":
    unittest.main()
