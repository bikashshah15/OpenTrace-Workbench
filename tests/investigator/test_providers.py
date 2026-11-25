import unittest

from opentrace_investigator.providers import MAX_NEXT_STEP, OfflineScriptedPolicy, OpenAIProvider, ProviderDisabled
from opentrace_investigator.transport import HttpTransport


class ProviderTest(unittest.TestCase):
    def test_openai_provider_constructs_but_is_disabled(self):
        provider = OpenAIProvider(model="unset")
        for call in (lambda: provider.plan_requirements(["inventory"]), lambda: provider.choose_operations({}),
                     lambda: provider.next_step([], 0)):
            with self.assertRaises(ProviderDisabled):
                call()

    def test_offline_policy_requests_only_negotiated_operations(self):
        policy = OfflineScriptedPolicy()
        self.assertEqual(policy.choose_operations({"operations": ["go_mod_inventory"]}), ["go_mod_inventory"])
        self.assertEqual(policy.choose_operations({"operations": []}), [])
        reqs = policy.plan_requirements(["inventory", "call_path"])
        self.assertEqual([r["dimension"] for r in reqs], ["inventory", "call_path"])

    def test_next_step_is_bounded_and_names_call_path_worker(self):
        policy = OfflineScriptedPolicy()
        text = policy.next_step([{"dimension": "call_path"}], 3)
        self.assertIn("call-path worker", text)
        self.assertIn("I2", text)
        many = [{"dimension": d} for d in ("call_path", "code_presence", "crypto_discovery", "configuration")]
        self.assertLessEqual(len(policy.next_step(many, 0)), MAX_NEXT_STEP)

    def test_failure_guidance_uses_the_recorded_cause(self):
        """I1-IR-04: no 'declares inventory' advice when the cause is not a missing capability."""
        policy = OfflineScriptedPolicy()
        cases = {"unsupported_schema_version": "schema", "stale_run": "superseded", "context_mismatch": "context",
                 "correlation_mismatch": "token", "integrity_failure_quarantined": "Integrity",
                 "artifact_integrity_failure": "Integrity", "worker_failed": "worker", "deadline_exceeded": "deadline",
                 "specialist_unavailable": "unreachable", "http_302": "HTTP 302"}
        for reason, needle in cases.items():
            text = policy.next_step([{"requirement_id": "req-1-inventory", "dimension": "inventory",
                                      "reason": reason}], 0, failure=reason)
            self.assertIn(needle, text, reason)
            self.assertNotIn("declares inventory", text, reason)
            self.assertLessEqual(len(text), MAX_NEXT_STEP)
        # availability failure before any task exists (no unknowns recorded)
        self.assertIn("unreachable", policy.next_step([], 0, failure="specialist_unavailable"))

    def test_capability_gaps_keep_dimension_guidance(self):
        policy = OfflineScriptedPolicy()
        text = policy.next_step([{"dimension": "call_path", "reason": "unsupported_dimension"}], 3)
        self.assertIn("call-path worker", text)
        text = policy.next_step([{"dimension": "inventory", "reason": "requirement_not_covered"}], 0,
                                failure="requirement_not_covered")
        self.assertIn("no supported inventory claim", text)
        self.assertNotIn("declares inventory", text)

    def test_transport_is_loopback_only(self):
        for url in ("http://example.com:80", "https://127.0.0.1:1", "http://10.0.0.1:80", "http://localhost:80"):
            with self.assertRaises(ValueError):
                HttpTransport(url)
        HttpTransport("http://127.0.0.1:9")
        HttpTransport("http://[::1]:9")


if __name__ == "__main__":
    unittest.main()
