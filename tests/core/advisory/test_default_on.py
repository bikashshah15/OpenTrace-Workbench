"""LIVE-ADVISORIES-DEFAULT-01: live OSV lookup is on by default with live scanning, opts out with OPENTRACE_LIVE_ADVISORIES=0,
is absent when live scanning is off, and is never triggered by the captured Demo. No network: transports are recorded doubles."""
import unittest

from opentrace_core.advisory.config import AdvisoryConfig
from opentrace_core.live.runner import LiveConfig
from tests.core.advisory import support
from tests.core.advisory.test_live_advisory_app import AdvisoryAppBase

LIVE = {"OPENTRACE_LIVE_SCAN": "1"}


class DefaultOnConfigTest(unittest.TestCase):
    def test_unset_empty_and_one_enable_the_lookup(self):
        for env in ({}, {"OPENTRACE_LIVE_ADVISORIES": ""}, {"OPENTRACE_LIVE_ADVISORIES": "1"}):
            self.assertIsNotNone(AdvisoryConfig.from_env(env), env)

    def test_explicit_zero_opts_out(self):
        self.assertIsNone(AdvisoryConfig.from_env({"OPENTRACE_LIVE_ADVISORIES": "0"}))

    def test_an_unrecognised_value_fails_closed_to_off(self):
        for value in ("false", "off", "yes", "true", "2"):
            self.assertIsNone(AdvisoryConfig.from_env({"OPENTRACE_LIVE_ADVISORIES": value}), value)

    def test_live_scanning_enabled_defaults_advisories_on(self):
        live = LiveConfig.from_env(dict(LIVE))
        self.assertIsNotNone(live.advisories)
        self.assertTrue(live.public()["advisories"]["enabled"])

    def test_live_scanning_enabled_with_opt_out_has_no_advisories(self):
        live = LiveConfig.from_env(dict(LIVE, OPENTRACE_LIVE_ADVISORIES="0"))
        self.assertIsNone(live.advisories)
        self.assertEqual(live.public()["advisories"], {"enabled": False})

    def test_live_scanning_disabled_means_no_live_config_at_all(self):
        for env in ({}, {"OPENTRACE_LIVE_ADVISORIES": "1"}, {"OPENTRACE_LIVE_SCAN": "0"}):
            self.assertIsNone(LiveConfig.from_env(env), env)

    def test_surrounding_whitespace_is_ignored(self):
        self.assertIsNone(AdvisoryConfig.from_env({"OPENTRACE_LIVE_ADVISORIES": " 0 "}))
        self.assertIsNotNone(AdvisoryConfig.from_env({"OPENTRACE_LIVE_ADVISORIES": " 1 "}))

    def test_the_specialist_is_found_from_the_environment_and_absence_is_reported(self):
        cfg = AdvisoryConfig.from_env({"OPENTRACE_SPECIALIST_BIN": "/nonexistent/evidence-specialist"})
        self.assertFalse(cfg.public()["specialist_available"])

    def test_the_disclosure_text_names_what_is_sent_and_where_and_what_is_not(self):
        pub = AdvisoryConfig().public()
        self.assertEqual(pub["host"], "api.osv.dev")
        for word in ("ecosystem", "name", "exact version"):
            self.assertIn(word, pub["sends"])
        self.assertIn("no source files or credentials", pub["sends"])


class EnvDerivedServiceTest(AdvisoryAppBase):
    """The server is built from the environment-derived LiveConfig (not an injected one): demo and config stay offline, the scan path is wired."""

    def _server(self, env, osv):
        live = LiveConfig.from_env(env)
        live.advisories.transport = osv
        live.advisories.specialist_bin = self.binary
        base = self.advisory_server(osv)
        base.app.live.advisories = live.advisories if live.advisories else None
        return base

    def test_default_env_wires_the_lookup_and_demo_stays_offline(self):
        osv = support.RecordedOsv()
        srv = self._server(dict(LIVE), osv)
        c = self.client(srv)
        c.json("POST", "/api/analysis/demo", {})
        self.assertEqual(osv.calls, [])
        _, cfg = c.json("GET", "/api/config")
        self.assertTrue(cfg["live"]["advisories"]["enabled"])
        c2, body = self.run_live(srv)
        self.assertGreater(len(osv.calls), 0, "a live scan under the default configuration does look up OSV")
        self.assertEqual(body["summary"]["advisory_lookup"]["lookup"], "complete")

    def test_opt_out_env_makes_a_live_scan_send_nothing(self):
        osv = support.RecordedOsv()
        base = self.advisory_server(osv)
        live = LiveConfig.from_env(dict(LIVE, OPENTRACE_LIVE_ADVISORIES="0"))
        base.app.live.advisories = live.advisories
        c, body = self.run_live(base)
        self.assertEqual(osv.calls, [])
        self.assertEqual(body["summary"]["live"]["advisory"], "not_run")


class DefaultOnServiceTest(AdvisoryAppBase):
    def test_demo_makes_no_osv_request_even_with_lookup_configured(self):
        osv = support.RecordedOsv()
        srv = self.advisory_server(osv)
        c = self.client(srv)
        resp, body = c.json("POST", "/api/analysis/demo", {})
        self.assertEqual(resp.status, 200, body)
        c.json("GET", "/api/config")
        self.assertEqual(osv.calls, [], "browsing the captured demo must not touch OSV")
        self.assertIsNone(body["summary"].get("advisory_lookup"))

    def test_config_makes_no_osv_request(self):
        osv = support.RecordedOsv()
        c = self.client(self.advisory_server(osv))
        c.json("GET", "/api/config")
        self.assertEqual(osv.calls, [])

    def test_a_missing_specialist_is_unavailable_not_no_vulnerabilities(self):
        osv = support.RecordedOsv()
        c, body = self.run_live(self.advisory_server(osv, binary=False))
        s = body["summary"]["advisory_lookup"]
        self.assertEqual(s["lookup"], "unavailable")
        self.assertEqual(s["states"]["no_match"], 0)
        self.assertEqual(osv.calls, [])


if __name__ == "__main__":
    unittest.main()
