"""Selection adoption and strict answer validation through the NORMAL Assistant route (POST /api/assistant/ask on the recorded Frigate analysis).

The provider is a mock broker injected into the running app: no network, no model, no spend. It sees exactly what the real broker would be sent."""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))

from opentrace_core.app import make_server, replay as demo_replay  # noqa: E402
from opentrace_core.app.assistant.accounting import MAX_INPUT_TOKENS  # noqa: E402
from opentrace_core.app.assistant.providers import GenerationResult, ProviderConfig, Usage, create_adapter  # noqa: E402
from tests.core.app.test_demo_replay import FIXTURE, HAVE  # noqa: E402
from tests.core.app.test_server import Client  # noqa: E402


def sent(request):
    """The current-turn payload (last message) of a request the Workbench built."""
    return json.loads(request.messages[-1].content)


class MockBroker:
    """Answers from a script of callables(request, payload) -> answer dict; records every request. Never contacts anything."""

    def __init__(self, script):
        self.script, self.requests = list(script), []

    def generate(self, request):
        self.requests.append(request)
        answer = self.script.pop(0)(request, sent(request))
        return GenerationResult("complete", json.dumps(answer), Usage(input_tokens=1, output_tokens=1), "gpt-6-luna", "completed", "openai", "protocol_and_local_semantic")


def base(payload):
    return {"context_id": payload["context_id"], "turn_id": payload["turn_id"]}


def detail_ids(payload):
    return [e["evidence_id"] for e in payload["evidence"] if e["kind"] != "source_state"]


def state_ids(payload):
    return [e["evidence_id"] for e in payload["evidence"] if e["kind"] == "source_state"]


def good(_request, payload):
    """A supported answer: a finding that cites the first detail record (the selected item), plus a stated limitation that cites a coverage record."""
    return dict(base(payload), answer_status="partial", claims=[{"kind": "finding", "text": "The selected record is a declared package with no inventory record.", "evidence_ids": detail_ids(payload)[:1]}],
                limitations=[{"text": "Not every source was checked.", "evidence_ids": state_ids(payload)[:1]}], next_steps=[])


def coverage_only_finding(_request, payload):
    """A provider reply that labels coverage-only evidence as a finding."""
    return dict(base(payload), answer_status="partial", claims=[{"kind": "finding", "text": "The package is vulnerable.", "evidence_ids": state_ids(payload)[:1]}],
                limitations=[{"text": "Coverage is incomplete.", "evidence_ids": state_ids(payload)[:1]}], next_steps=[])


@unittest.skipUnless(HAVE, "replay fixture not present")
class RouteBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="ot-assist-route-")
        cls.server = make_server(os.path.join(cls.dir, "s"), reap_seconds=3600, live=None, replay=demo_replay.ReplayCapture(FIXTURE))
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.app.close()
        cls.server.server_close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def open(self, script):
        self.c = Client(self.server)
        self.c.start()
        body = self.c.json("POST", "/api/analysis/demo", {})[1]
        self.generation = body["generation"]
        queue = self.c.json("GET", "/api/workbench/v1/bom-candidates?generation=%d&offset=0" % self.generation)[1]
        self.item = next(i for i in queue["items"] if i["display"]["name"].startswith("types-peewee"))
        self.broker = MockBroker(script)
        self.server.app.assistant_broker = self.broker
        return self.item

    def ask(self, question, *, adopt=False, subject=None):
        return self.c.json("POST", "/api/assistant/ask", {"question": question, "generation": self.generation, "adopt_subject": adopt, "subject": subject})

    def selected(self):
        return {"kind": "bom", "id": self.item["item_id"]}

    def bound(self, request):
        return create_adapter(ProviderConfig("openai", "gpt-6-luna", "dummy", None)).input_token_upper_bound(request)


@unittest.skipUnless(HAVE, "replay fixture not present")
class SelectionRouteTest(RouteBase):
    def test_adopting_the_selected_gap_binds_the_turn_and_a_follow_up_keeps_it(self):
        self.open([good, good])
        resp, first = self.ask("Why is types-peewee a gap?", adopt=True, subject=self.selected())
        self.assertEqual(resp.status, 200, first)
        self.assertEqual((first["subject"]["kind"], first["subject"]["id"]), ("bom", self.item["item_id"]))
        self.assertIn("types-peewee", first["subject"]["label"])
        request = self.broker.requests[0]
        payload = sent(request)
        self.assertEqual(payload["subject"]["id"], self.item["item_id"])
        selected = next(e for e in payload["evidence"] if e["kind"] != "source_state")
        self.assertIn(self.item["item_id"], selected["excerpt"], "the selected item's own record is the first detail sent")
        self.assertLessEqual(self.bound(request), MAX_INPUT_TOKENS, "the adopted Frigate context now fits the broker's input budget")
        omitted = [n for n in payload["limitations"] if "left out of this request" in n]
        self.assertEqual(len(omitted), 1, "what was trimmed is disclosed to the model ...")
        self.assertIn(omitted[0], first["limitations"], "... and to the user")
        self.assertTrue(all(i in {c["evidence_id"] for c in first["citations"]} for i in state_ids(payload)))
        resp, second = self.ask("And is it used at runtime?")                     # an ordinary follow-up: no new selection
        self.assertEqual(resp.status, 200, second)
        self.assertEqual(second["context_id"], first["context_id"])
        self.assertEqual(second["subject"]["id"], self.item["item_id"])
        follow = self.broker.requests[1]
        self.assertEqual(sent(follow)["subject"]["id"], self.item["item_id"], "the follow-up is still bound to the selected finding")
        self.assertEqual(follow.messages[0].content, "Why is types-peewee a gap?", "bounded history is carried")
        self.assertLessEqual(self.bound(follow), MAX_INPUT_TOKENS)

    PLAIN_SBOM = "types-peewee is listed in docker/main/requirements-dev.txt (line 4), but this Syft 1.51.1 scan found no matching entry in the SBOM."

    def first_detail(self, index):
        return next(e["evidence_id"] for e in sent(self.broker.requests[index])["evidence"] if e["kind"] != "source_state")

    def test_a_busy_broker_and_an_exhausted_allowance_get_different_plain_messages(self):
        from opentrace_core.app.assistant.providers import ProviderError
        self.open([good])
        self.server.app.assistant_broker = type("Raising", (), {"generate": lambda self, request: (_ for _ in ()).throw(ProviderError(self.code))})()
        results = {}
        for code in ("broker_busy", "broker_allowance_exhausted"):
            self.server.app.assistant_broker.code = code
            resp, body = self.ask("What cryptography does this repository declare?")
            self.assertEqual(resp.status, 502, body)
            results[code] = body
            self.assertEqual(body["error"], code)
        self.assertIn("Try again in a moment", results["broker_busy"]["message"])
        self.assertNotIn("Try again", results["broker_allowance_exhausted"]["message"].replace("Trying again will not help", ""))
        self.assertIn("allowance has been used up", results["broker_allowance_exhausted"]["message"])
        self.assertNotEqual(results["broker_busy"]["message"], results["broker_allowance_exhausted"]["message"])

    def test_a_first_reply_that_fails_validation_gets_the_comparison_in_plain_words(self):
        self.open([coverage_only_finding])
        resp, body = self.ask("Why is types-peewee a gap?", adopt=True, subject=self.selected())
        self.assertEqual(resp.status, 200, body)
        self.assertTrue(body["fallback"])
        claim = body["answer"]["claims"][0]
        self.assertEqual(claim["text"], self.PLAIN_SBOM)
        for raw in ("wildcard_pin", "inv:syft", "contradicted", "SBOM comparison result"):
            self.assertNotIn(raw, claim["text"])
        self.assertEqual(claim["evidence_ids"], [self.first_detail(0)], "an evidence link to the selected record")
        self.assertIn("could not be checked", body["answer"]["limitations"][0]["text"])

    def test_explain_this_after_other_turns_is_a_first_turn_on_its_subject_and_gets_the_plain_explanation(self):
        self.open([good, coverage_only_finding])
        self.assertEqual(self.ask("What cryptography does this repository declare?")[0].status, 200)       # an earlier turn on the whole analysis
        resp, body = self.ask("Explain this item to someone who is not a specialist.", adopt=True, subject=self.selected())
        self.assertEqual(resp.status, 200, body)
        self.assertTrue(body["fallback"])
        self.assertEqual(body["answer"]["claims"][0]["text"], self.PLAIN_SBOM, "switching subject starts a new context, so this is not a follow-up")

    def test_a_follow_up_that_falls_back_answers_only_what_the_record_covers_or_says_it_cannot(self):
        self.open([good, coverage_only_finding, coverage_only_finding, good])
        self.assertEqual(self.ask("Why is types-peewee a gap?", adopt=True, subject=self.selected())[0].status, 200)
        resp, body = self.ask("Is it vulnerable?")                                  # the SBOM comparison record says nothing about advisories
        self.assertEqual(resp.status, 200, body)
        self.assertTrue(body["fallback"])
        self.assertEqual(body["answer"]["answer_status"], "unknown")
        claim = body["answer"]["claims"][0]
        self.assertEqual(claim["kind"], "unknown")
        self.assertIn("does not cover that question", claim["text"])
        self.assertNotIn("listed in", claim["text"], "the first explanation is not repeated")
        self.assertLess(len(claim["text"]), 160)
        self.assertEqual(claim["evidence_ids"], [self.first_detail(1)], "the evidence link is kept")
        self.assertEqual(body["subject"]["id"], self.item["item_id"])
        resp, body = self.ask("Why might it be missing from the SBOM?")             # the record does answer this one, in plain words
        self.assertEqual(resp.status, 200, body)
        self.assertEqual(body["answer"]["claims"][0]["text"], self.PLAIN_SBOM)
        self.assertEqual(body["answer"]["claims"][0]["evidence_ids"], [self.first_detail(2)])
        resp, third = self.ask("Is it declared in a lockfile?")                    # the conversation continues on the same subject
        self.assertEqual(resp.status, 200, third)
        self.assertEqual(third["subject"]["id"], self.item["item_id"])

    def test_with_no_item_a_coverage_only_finding_is_still_withheld_in_plain_language(self):
        self.open([coverage_only_finding])
        resp, body = self.ask("Summarise the cryptography coverage")
        self.assertEqual((resp.status, body["error"]), (400, "finding_state_unsupported"))
        self.assertIn("withheld", body["message"])
        self.assertIn("Explain this", body["message"])
        self.assertNotIn("finding state unsupported", body["message"])

    def test_an_answer_may_only_cite_evidence_that_was_actually_sent(self):
        omitted_cite = []

        def cite_omitted(request, payload):
            unsent = [i for i in omitted_cite if i not in {e["evidence_id"] for e in payload["evidence"]}]
            self.assertTrue(unsent, "this Frigate context omits detail records to fit, so some permitted ids were not sent")
            return dict(base(payload), answer_status="partial", claims=[{"kind": "finding", "text": "Invented support.", "evidence_ids": unsent[:1]}],
                        limitations=[{"text": "Partial.", "evidence_ids": state_ids(payload)[:1]}], next_steps=[])
        self.open([good, cite_omitted])
        resp, first = self.ask("Why is types-peewee a gap?", adopt=True, subject=self.selected())
        omitted_cite.extend(c["evidence_id"] for c in first["citations"])
        resp, body = self.ask("Anything else?")
        self.assertEqual(resp.status, 200)
        self.assertTrue(body["fallback"], "the invented citation was rejected by the validator; only the verified record is shown")
        self.assertNotEqual(body["answer"]["claims"][0]["text"], "Invented support.")

    def test_a_selection_that_cannot_be_used_is_explained_and_changes_nothing(self):
        self.open([good, good])
        self.assertEqual(self.ask("Why is types-peewee a gap?", adopt=True, subject=self.selected())[0].status, 200)
        for subject, code in (({"kind": "bom", "id": "cand:not-a-record"}, "subject_not_in_resolved_evidence"), ({"kind": "candidate_gap", "id": "x"}, "subject_invalid")):
            resp, body = self.ask("Use this instead", adopt=True, subject=subject)
            self.assertEqual((resp.status, body["error"]), (400, code))
            self.assertIn("Explain this", body["message"])
            self.assertNotEqual(body["message"], code.replace("_", " "))
        resp, after = self.ask("Still on the original subject?")
        self.assertEqual(resp.status, 200, after)
        self.assertEqual(after["subject"]["id"], self.item["item_id"], "a refused adoption never retargets the thread")

    def test_without_adoption_the_first_turn_is_about_the_whole_repository(self):
        """The observed live behaviour: a selection that is not checked is not used."""
        self.open([good])
        resp, body = self.ask("Why is types-peewee a gap?")
        self.assertEqual(resp.status, 200, body)
        self.assertEqual(body["subject"]["kind"], "analysis")
        self.assertIn("blakeblackshear/frigate", body["subject"]["label"])
        resp, body = self.ask("x?", subject={"kind": "bom", "id": self.item["item_id"]})
        self.assertEqual((resp.status, body["error"]), (400, "subject_requires_explicit_adoption"))
        self.assertIn("Explain this", body["message"])


class AssetSentenceTest(unittest.TestCase):
    def item(self, label, excerpt):
        from opentrace_core.app.assistant.resolver import ResolvedEvidence
        return ResolvedEvidence("ev-x", "model_observations", "ai_inventory_model", "completed", label, excerpt, "model_observations:x")

    def test_a_record_with_too_little_detail_says_so_briefly(self):
        from opentrace_core.app.assistant.service import _sentence_for
        self.assertEqual(_sentence_for(self.item("Recorded asset", "{}")), "OpenTrace recorded this item, but its record has too little detail to explain it further.")

    def test_a_truncated_record_still_yields_its_leading_summary(self):
        from opentrace_core.app.assistant.service import _sentence_for
        cut = '{"_summary":{"experimental":true,"kind":"runtime","line":3,"name":"x_rt","path":"a/b.py","places":2},"asset_id":"ast:1","attributes":{"long":"' + "z" * 50
        self.assertIn("x_rt is an AI runtime that the scan recorded, found in a/b.py at line 3.", _sentence_for(self.item("x_rt", cut)))


@unittest.skipUnless(HAVE, "replay fixture not present")
class ExplainThisRouteTest(RouteBase):
    """The four reported Frigate cases (3bca9b8676846d175f6b9f53f5818cbb9d36ec3e), on the normal route."""
    PACKAGES = (("js-yaml", "4.3.0"), ("qs", "6.14.1"), ("@faker-js/faker", "5.5.3"))

    def package_ids(self):
        from opentrace_core.app import dependency_pages as DP
        analysis = next(iter(self.server.app.analyses.values()))
        found = {}
        for row in DP._chooser_rows(analysis):
            graph, _ = DP._graph_for(analysis, row["path"])
            for nid, info in graph.nodes.items():
                if (info["name"], info["version"]) in self.PACKAGES:
                    found.setdefault((info["name"], info["version"]), nid)
        return found

    def test_case_1_with_no_item_a_vague_question_asks_which_item_and_makes_no_model_call(self):
        self.open([good, good])
        for question in ("What does this finding mean?", "Why might it be missing from the SBOM?", "tell me about it"):
            resp, body = self.ask(question)
            self.assertEqual(resp.status, 200, body)
            self.assertIn("Which item do you mean?", body["clarify"])
            self.assertIn("Explain this", body["clarify"])
            self.assertNotIn("answer", body)
        self.assertEqual(self.broker.requests, [], "no provider request was built or sent")
        resp, body = self.ask("What cryptography does this repository declare?")      # a whole-analysis question still reaches the assistant
        self.assertEqual(resp.status, 200)
        self.assertEqual(len(self.broker.requests), 1)

    def test_the_fallback_for_an_ai_runtime_uses_the_selected_records_own_name_and_location(self):
        """Reported: Explain this on tflite_runtime fell back to "OpenTrace recorded Recorded asset in its model observations evidence."."""
        from opentrace_core.app import ai_assets
        self.open([coverage_only_finding])
        analysis = next(iter(self.server.app.analyses.values()))
        asset = next(a for a in ai_assets.respond(analysis, {"generation": self.generation, "schema_version": 1})["assets"] if a["display_name"] == "tflite_runtime")
        resp, body = self.ask("Explain this", adopt=True, subject={"kind": "model", "id": asset["asset_id"]})
        self.assertEqual(resp.status, 200, body)
        self.assertTrue(body["fallback"])
        claim = body["answer"]["claims"][0]
        loc = asset["occurrences"][0]["source_location"]
        self.assertNotIn("Recorded asset", claim["text"])
        self.assertIn("tflite_runtime is an AI runtime that the scan recorded, found in %s" % loc["path"], claim["text"])
        self.assertIn("not that it is installed or used", claim["text"])
        selected = next(e for e in sent(self.broker.requests[0])["evidence"] if e["kind"] != "source_state")
        self.assertEqual(claim["evidence_ids"], [selected["evidence_id"]], "the evidence link is the selected record")
        self.assertIn('"name":"tflite_runtime"', selected["excerpt"])
        self.assertEqual(body["subject"]["label"], "tflite_runtime")

    def test_cases_2_to_4_every_clicked_package_resolves_and_its_own_record_is_sent_first(self):
        self.open([good] * 3)
        ids = self.package_ids()
        self.assertEqual(set(ids), set(self.PACKAGES), "all three packages are in the recorded Frigate inventory")
        for index, (key, nid) in enumerate(ids.items()):
            resp, body = self.ask("tell me about it", adopt=True, subject={"kind": "dependency", "id": nid})
            self.assertEqual(resp.status, 200, (key, body))
            self.assertEqual(body["subject"]["kind"], "dependency")
            self.assertIn(key[0], body["subject"]["label"])
            payload = sent(self.broker.requests[index])
            selected = next(e for e in payload["evidence"] if e["kind"] != "source_state")
            record = json.loads(selected["excerpt"])
            self.assertEqual((record["name"], record["version"], record["node_id"]), (key[0], key[1], nid), "the clicked row's own record comes before any broader context")
            self.assertLessEqual(self.bound(self.broker.requests[index]), MAX_INPUT_TOKENS)

    def test_a_failed_citation_check_on_a_clicked_package_gives_a_short_factual_answer_with_an_evidence_link(self):
        self.open([coverage_only_finding] * 3)
        for key, nid in self.package_ids().items():
            resp, body = self.ask("tell me more about it", adopt=True, subject={"kind": "dependency", "id": nid})
            self.assertEqual(resp.status, 200, (key, body))
            self.assertTrue(body["fallback"])
            text = body["answer"]["claims"][0]["text"]
            self.assertTrue(text.startswith("%s %s is a package from the npm ecosystem," % key), text)
            self.assertLessEqual(text.count(". "), 3)
            link = body["answer"]["claims"][0]["evidence_ids"][0]
            self.assertIn(link, {c["evidence_id"] for c in body["citations"]})
            self.server.app.assistant.clear(next(iter(self.server.app.analyses)))        # start the next package on a fresh thread

    def test_a_follow_up_stays_on_the_displayed_subject_until_explain_this_switches_it(self):
        self.open([good, good, good, good])
        ids = self.package_ids()
        qs, js = ids[("qs", "6.14.1")], ids[("js-yaml", "4.3.0")]
        self.assertEqual(self.ask("Explain this", adopt=True, subject={"kind": "dependency", "id": qs})[0].status, 200)
        resp, follow = self.ask("Why does it matter?")                              # the Workbench selection may have changed meanwhile; the request carries none
        self.assertEqual(follow["subject"]["id"], qs)
        resp, switched = self.ask("Explain this", adopt=True, subject={"kind": "dependency", "id": js})
        self.assertEqual(switched["subject"]["id"], js)
        resp, after = self.ask("And why does that matter?")
        self.assertEqual(after.get("subject", {}).get("id"), js, after)


if __name__ == "__main__":
    unittest.main()
