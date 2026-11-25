import threading
import unittest

from opentrace_core.advisory import osv
from opentrace_core.advisory.osv import Response
from tests.core.advisory import support


def occ(name, version, state="exact", eco="npm", path="package-lock.json"):
    return {"ecosystem": eco, "name_original": name, "name_normalized": name, "version_original": version, "version_state": state,
            "locator": "/packages/node_modules/" + name, "path": path, "repo": "acme/widget"}


OCCS = [occ("minimatch", "3.1.2"), occ("ms", "2.1.3"), occ("brace-expansion", "1.1.11")]
NO_SLEEP = lambda s: None  # noqa: E731


class OsvLookupTest(unittest.TestCase):
    def run_lookup(self, transport, occs=OCCS, **kw):
        return osv.run(occs, transport, sleep=NO_SLEEP, **kw)

    def test_complete_lookup_distinguishes_advisories_from_none(self):
        t = support.RecordedOsv()
        lk = self.run_lookup(t)
        self.assertEqual(lk.status, "complete")
        self.assertEqual(lk.answers["npm|minimatch|3.1.2"]["ids"], ["GHSA-23c5-xmqv-rm74"])
        self.assertEqual(lk.answers["npm|ms|2.1.3"], dict(lk.answers["npm|ms|2.1.3"], state="answered", ids=[]))
        self.assertEqual(set(lk.records), {"GHSA-23c5-xmqv-rm74"})
        self.assertEqual(lk.records["GHSA-23c5-xmqv-rm74"]["digest"][:7], "sha256:")

    def test_only_exact_versions_are_queried_and_only_name_and_version_are_sent(self):
        t = support.RecordedOsv()
        lk = self.run_lookup(t, OCCS + [occ("gitdep", "1.0.0", state="non_registry"), occ("rangey", "^1.0.0", state="range")])
        self.assertEqual(sorted((q["package"]["name"], q["version"]) for q in t.queries),
                         [("brace-expansion", "1.1.11"), ("minimatch", "3.1.2"), ("ms", "2.1.3")])
        for q in t.queries:
            self.assertEqual(set(q), {"package", "version"})
            self.assertEqual(set(q["package"]), {"name", "ecosystem"})
        self.assertEqual({u["reason"] for u in lk.unresolved}, {"non_registry", "range"})
        self.assertTrue(all(c[1] in ("/v1/querybatch", "/v1/vulns/GHSA-23c5-xmqv-rm74") for c in t.calls))

    def test_unreachable_service_is_unavailable_never_no_advisories(self):
        lk = self.run_lookup(support.RecordedOsv("down"))
        self.assertEqual(lk.status, "unavailable")
        self.assertEqual(lk.reason, "network_error")
        self.assertTrue(all(a["state"] == "failed" and a["ids"] == [] for a in lk.answers.values()))
        self.assertEqual(lk.counts()["answered"], 0)

    def test_server_errors_are_retried_then_reported(self):
        t = support.RecordedOsv("http503")
        waits = []
        lk = osv.run(OCCS, t, sleep=waits.append)
        self.assertEqual(lk.status, "unavailable")
        self.assertEqual(lk.reason, "http_503")
        self.assertEqual(len([c for c in t.calls if c[1] == "/v1/querybatch"]), 3)
        self.assertIn(1, waits)
        self.assertIn(3, waits)

    def test_unparseable_answer_is_a_failure(self):
        lk = self.run_lookup(support.RecordedOsv("garbage"))
        self.assertEqual(lk.status, "unavailable")
        self.assertEqual({a["reason"] for a in lk.answers.values()}, {"unparseable_response"})

    def test_partial_lookup_keeps_answered_and_failed_queries_apart(self):
        many = [occ("pkg%03d" % i, "1.0.0") for i in range(130)] + [occ("minimatch", "3.1.2")]
        lk = self.run_lookup(support.RecordedOsv("second_batch_down"), many)
        self.assertEqual(lk.status, "partial")
        c = lk.counts()
        self.assertEqual(c["planned_queries"], 131)
        self.assertGreater(c["answered"], 0)
        self.assertGreater(c["failed"], 0)
        self.assertEqual(c["answered"] + c["failed"], 131)

    def test_failed_record_fetch_is_recorded_and_makes_the_lookup_partial(self):
        lk = self.run_lookup(support.RecordedOsv("records_down"))
        self.assertEqual(lk.status, "partial")
        self.assertIn("GHSA-23c5-xmqv-rm74", lk.record_failures)
        self.assertEqual(lk.answers["npm|minimatch|3.1.2"]["ids"], ["GHSA-23c5-xmqv-rm74"])   # the match itself stands

    def test_rejected_query_index_is_isolated(self):
        calls = []

        def transport(method, path, body=None):
            import json
            calls.append(path)
            qs = json.loads(body)["queries"]
            if len(qs) == 3:
                return Response(400, b'{"code":3,"message":"error in query at index 1: invalid version"}')
            return Response(200, json.dumps({"results": [{} for _ in qs]}).encode())
        lk = self.run_lookup(transport)
        states = {k: (a["state"], a["reason"]) for k, a in lk.answers.items()}
        self.assertEqual(sum(1 for s in states.values() if s == ("failed", "query_rejected")), 1)
        self.assertEqual(sum(1 for s in states.values() if s[0] == "answered"), 2)

    def test_pagination_collects_every_page_and_failed_page_is_a_failure(self):
        pages = {"npm|minimatch|3.1.2": [["GHSA-a"], ["GHSA-b"]]}
        lk = self.run_lookup(support.RecordedOsv(pages=pages, records={}))
        self.assertEqual(lk.answers["npm|minimatch|3.1.2"]["ids"], ["GHSA-a", "GHSA-b"])
        endless = {"npm|minimatch|3.1.2": [["GHSA-%d" % i] for i in range(40)]}
        lk = self.run_lookup(support.RecordedOsv(pages=endless, records={}))
        self.assertTrue(lk.answers["npm|minimatch|3.1.2"]["truncated"])
        self.assertEqual(len(lk.answers["npm|minimatch|3.1.2"]["ids"]), osv.LIMITS["page_cap"])

    def test_malformed_first_page_results_are_unavailable_never_empty(self):
        key = "npm|minimatch|3.1.2"
        cases = {
            "vulns null": {"vulns": None},
            "vulns object": {"vulns": {"id": "GHSA-x"}},
            "vulns string": {"vulns": "GHSA-x"},
            "entry without id": {"vulns": [{"modified": "2026-01-01T00:00:00Z"}]},
            "entry id not a string": {"vulns": [{"id": 7}]},
            "entry not an object": {"vulns": ["GHSA-x"]},
            "entry id with invalid characters": {"vulns": [{"id": "../x"}]},
            "result not an object": ["GHSA-x"],
            "token not a string": {"vulns": [{"id": "GHSA-a"}], "next_page_token": 5},
            "empty token": {"vulns": [{"id": "GHSA-a"}], "next_page_token": ""},
        }
        for name, bad in cases.items():
            with self.subTest(name):
                lk = self.run_lookup(self.answering(key, bad, others_ok=True), [occ("minimatch", "3.1.2"), occ("ms", "2.1.3")])
                self.assertEqual((lk.answers[key]["state"], lk.answers[key]["reason"], lk.answers[key]["ids"]), ("failed", "malformed_result", []))
                self.assertEqual(lk.answers["npm|ms|2.1.3"]["state"], "answered")      # a bad neighbour does not spoil a valid result
                self.assertEqual(lk.status, "partial")

    def test_valid_empty_results_stay_no_advisory_returned(self):
        key = "npm|minimatch|3.1.2"
        for name, good in {"empty object": {}, "vulns empty list": {"vulns": []}, "vulns absent, token null": {"next_page_token": None}}.items():
            with self.subTest(name):
                lk = self.run_lookup(self.answering(key, good), [occ("minimatch", "3.1.2")])
                self.assertEqual((lk.answers[key]["state"], lk.answers[key]["ids"], lk.status), ("answered", [], "complete"))

    def test_malformed_continuation_pages_are_unavailable_not_a_short_answer(self):
        key = "npm|minimatch|3.1.2"
        first = {"vulns": [{"id": "GHSA-a"}], "next_page_token": "t1"}
        cases = {
            "vulns null": {"vulns": None},
            "vulns object": {"vulns": {"id": "GHSA-b"}},
            "entry missing id": {"vulns": [{"modified": "x"}]},
            "result not an object": 3,
            "two results": None,
        }
        for name, page in cases.items():
            with self.subTest(name):
                def transport(method, path, body=None, page=page):
                    import json
                    q = json.loads(body)["queries"]
                    if q[0].get("page_token"):
                        res = [{"vulns": []}, {"vulns": []}] if page is None else [page]
                        return Response(200, json.dumps({"results": res}).encode())
                    return Response(200, json.dumps({"results": [first]}).encode())
                lk = self.run_lookup(transport, [occ("minimatch", "3.1.2")])
                a = lk.answers[key]
                self.assertEqual((a["state"], a["ids"]), ("failed", []))
                self.assertTrue(a["reason"].startswith("page_failed"), a["reason"])
                self.assertEqual(lk.status, "unavailable")

    def test_valid_continuation_with_empty_last_page_completes(self):
        key = "npm|minimatch|3.1.2"
        lk = self.run_lookup(support.RecordedOsv(pages={key: [["GHSA-a"], []]}, records={}), [occ("minimatch", "3.1.2")])
        self.assertEqual((lk.answers[key]["state"], lk.answers[key]["ids"]), ("answered", ["GHSA-a"]))

    def answering(self, key, result, others_ok=False):
        """A transport that answers query ``key`` with the raw ``result`` and every other query with an empty result."""
        import json

        def transport(method, path, body=None):
            if path != "/v1/querybatch":
                return Response(404, b"")
            qs = json.loads(body)["queries"]
            out = []
            for q in qs:
                k = "%s|%s|%s" % (q["package"]["ecosystem"], q["package"]["name"], q["version"])
                out.append(result if k == key else {})
            return Response(200, json.dumps({"results": out}).encode())
        return transport

    def test_page_limit_with_no_advisory_seen_is_unavailable_not_an_answer(self):
        key = "npm|minimatch|3.1.2"
        t = support.RecordedOsv(pages={key: [[] for _ in range(40)]}, records={})
        lk = self.run_lookup(t, [occ("minimatch", "3.1.2"), occ("ms", "2.1.3")])
        a = lk.answers[key]
        self.assertEqual((a["state"], a["reason"], a["ids"]), ("failed", "page_limit_reached", []))
        self.assertEqual(lk.answers["npm|ms|2.1.3"]["state"], "answered")
        self.assertEqual(lk.status, "partial")
        self.assertEqual(len([c for c in t.calls if c[1] == "/v1/querybatch"]), 1 + osv.LIMITS["page_cap"] - 1)

    def test_page_limit_after_advisories_were_seen_keeps_the_match_and_marks_it_incomplete(self):
        key = "npm|minimatch|3.1.2"
        pages = {key: [["GHSA-a"]] + [[] for _ in range(40)]}
        lk = self.run_lookup(support.RecordedOsv(pages=pages, records={}), [occ("minimatch", "3.1.2")])
        a = lk.answers[key]
        self.assertEqual((a["state"], a["ids"], a["truncated"]), ("answered", ["GHSA-a"], True))
        self.assertEqual(lk.status, "partial")
        self.assertEqual(lk.counts()["incomplete_answers"], 1)

    def test_a_token_that_ends_exactly_at_the_limit_is_complete(self):
        key = "npm|minimatch|3.1.2"
        pages = {key: [["GHSA-a"]] + [[] for _ in range(osv.LIMITS["page_cap"] - 1)]}      # exactly page_cap pages; the last carries no token
        lk = self.run_lookup(support.RecordedOsv(pages=pages, records={}), [occ("minimatch", "3.1.2")])
        self.assertEqual((lk.answers[key]["state"], lk.answers[key]["truncated"], lk.answers[key]["ids"]), ("answered", False, ["GHSA-a"]))

    def test_cancel_stops_before_any_request(self):
        cancel = threading.Event()
        cancel.set()
        t = support.RecordedOsv()
        lk = self.run_lookup(t, cancel=cancel)
        self.assertEqual(t.calls, [])
        self.assertEqual(lk.status, "unavailable")
        self.assertEqual({a["reason"] for a in lk.answers.values()}, {"cancelled"})

    def test_nothing_exact_means_nothing_queried(self):
        t = support.RecordedOsv()
        lk = self.run_lookup(t, [occ("x", "^1", state="range")])
        self.assertEqual((lk.status, t.calls), ("complete", []))

    def test_real_transport_refuses_paths_outside_the_osv_api(self):
        with self.assertRaises(OSError):
            osv.OsvTransport()("GET", "/etc/passwd")

    def test_log_document_has_digests_but_no_bodies(self):
        lk = self.run_lookup(support.RecordedOsv())
        doc = osv.log_document(lk).decode()
        self.assertIn("opentrace.advisory_lookup/1", doc)
        self.assertIn(lk.exchanges[0]["response_sha256"], doc)
        self.assertNotIn("basicConstraints", doc)
        self.assertNotIn("Technical Details", doc)


if __name__ == "__main__":
    unittest.main()
