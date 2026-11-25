"""Session-only history, adoption and stale-response lifecycle checks."""

import os
import json
import sys
import threading
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from email.message import Message as HttpHeaders

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../src/core"))

from opentrace_core.app.assistant.resolver import _binding_digest, resolve_turn_evidence  # noqa: E402
from opentrace_core.app.assistant.service import (  # noqa: E402
    ConversationError,
    ConversationManager,
    MAX_HISTORY_PAIRS,
    make_generation_request,
    validate_generated_answer,
)


BINDING = {
    "session_id": "1" * 32,
    "analysis_digest": "a" * 64,
    "repository": {"host": "github.com", "owner": "fixture", "name": "repo",
                   "canonical_url": "https://github.com/fixture/repo"},
    "commit_sha": "b" * 40,
    "requested_ref": {"kind": "commit", "text": "b" * 40},
    "generation": 1,
    "mode": "captured",
    "assessment": None,
}


def context(context_id, generation=1):
    binding = dict(BINDING, generation=generation)
    return resolve_turn_evidence(binding=binding, context_id=context_id, projections={})


class AssistantConversationTests(unittest.TestCase):
    def test_analysis_transition_cannot_land_between_authorization_and_turn_finalization(self):
        from opentrace_core.app.server import AppState
        entered = threading.Event(); release = threading.Event(); order = []

        class FakeService:
            generation = 1
            def current_generation(self, _sid, _token):
                entered.set(); release.wait(2)
                return self.generation
            def begin_analysis(self, _sid, _token, _digest, *, expected_generation=None):
                self.generation += 1
                return SimpleNamespace(session_id=BINDING["session_id"], generation=self.generation)

        state = object.__new__(AppState)
        state.assistant_lifecycle_lock = threading.RLock(); state.assistant = ConversationManager()
        state.service = FakeService(); state.lock = threading.Lock()
        analysis = SimpleNamespace(state="complete", ticket=SimpleNamespace(
            session_id=BINDING["session_id"], generation=1))
        state.analyses = {BINDING["session_id"]: analysis}
        ctx = context("ctx-lifecycle")
        ticket = state.assistant.begin(session_id=BINDING["session_id"], generation=1,
                                       binding_digest=ctx.binding_digest, question="Question", context=ctx)
        finished = []
        finish_thread = threading.Thread(target=lambda: finished.append(state.finish_assistant_turn(
            BINDING["session_id"], "token", analysis, ticket, {"answer_status": "unknown", "claims": []})))
        finish_thread.start(); self.assertTrue(entered.wait(1))
        transition_thread = threading.Thread(target=lambda: (state.begin_assistant_analysis(BINDING["session_id"], "token"), order.append("transition")))
        transition_thread.start()
        self.assertFalse(order, "generation retirement waits while finish owns the lifecycle boundary")
        release.set(); finish_thread.join(2); transition_thread.join(2)
        self.assertFalse(finish_thread.is_alive()); self.assertFalse(transition_thread.is_alive())
        self.assertEqual(len(finished), 1)
        self.assertEqual(order, ["transition"])
        self.assertIsNone(state.assistant.current_context(BINDING["session_id"],
                                                         binding_digest=ctx.binding_digest, generation=1))

    def test_followup_keeps_original_context_and_explicit_adoption_changes_it(self):
        manager = ConversationManager()
        original = context("ctx-original")
        first = manager.begin(session_id=BINDING["session_id"], generation=1,
                              binding_digest=original.binding_digest, question="What is recorded?",
                              context=original)
        manager.finish(first, {"answer_status": "unknown", "claims": []}, still_authorized=lambda: True)
        other = context("ctx-selected")
        followup = manager.begin(session_id=BINDING["session_id"], generation=1,
                                 binding_digest=original.binding_digest, question="Explain that.", context=other)
        self.assertEqual(followup.context.context_id, "ctx-original")
        manager.fail(followup)
        adopted = manager.begin(session_id=BINDING["session_id"], generation=1,
                                binding_digest=original.binding_digest, question="Ask about this object.",
                                context=other, adopt_context=True)
        self.assertEqual(adopted.context.context_id, "ctx-selected")
        manager.fail(adopted)

    def test_stale_or_cancelled_provider_response_never_enters_history(self):
        manager = ConversationManager()
        ctx = context("ctx-stale")
        ticket = manager.begin(session_id=BINDING["session_id"], generation=1,
                              binding_digest=ctx.binding_digest, question="Question", context=ctx)
        self.assertTrue(manager.cancel(BINDING["session_id"]))
        self.assertTrue(ticket.cancel_event.is_set())
        with self.assertRaises(ConversationError):
            manager.finish(ticket, {"answer_status": "unknown", "claims": []}, still_authorized=lambda: True)
        manager.fail(ticket)


    def test_history_is_bounded_and_reset_on_analysis_binding_change(self):
        manager = ConversationManager()
        ctx = context("ctx-history")
        for index in range(MAX_HISTORY_PAIRS + 2):
            ticket = manager.begin(session_id=BINDING["session_id"], generation=1,
                                   binding_digest=ctx.binding_digest, question=f"Q {index}", context=ctx)
            manager.finish(ticket, {"answer_status": "unknown", "claims": []}, still_authorized=lambda: True)
        final = manager.begin(session_id=BINDING["session_id"], generation=1,
                              binding_digest=ctx.binding_digest, question="Current follow-up")
        self.assertEqual(len(manager.completed_history(final)), MAX_HISTORY_PAIRS)
        manager.fail(final)
        next_ctx = context("ctx-new-analysis", generation=2)
        fresh = manager.begin(session_id=BINDING["session_id"], generation=2,
                              binding_digest=next_ctx.binding_digest, question="New repository analysis",
                              context=next_ctx)
        self.assertEqual(manager.completed_history(fresh), ())
        manager.fail(fresh)

    def test_a_session_has_no_fixed_submission_cutoff_and_session_clear_retires_history_and_signals_pending(self):
        manager = ConversationManager()
        ctx = context("ctx-limit")
        for index in range(60):                                   # well past the former fixed cutoff of 20
            ticket = manager.begin(session_id=BINDING["session_id"], generation=1,
                                   binding_digest=ctx.binding_digest, question=f"Q {index}", context=ctx)
            manager.fail(ticket)
        still = manager.begin(session_id=BINDING["session_id"], generation=1, binding_digest=ctx.binding_digest, question="Question 61", context=ctx)
        manager.fail(still)
        # A lifecycle clear signals a pending provider wait and removes its context.
        second = ConversationManager()
        active = second.begin(session_id=BINDING["session_id"], generation=1,
                              binding_digest=ctx.binding_digest, question="Pending", context=ctx)
        second.clear(BINDING["session_id"])
        self.assertTrue(active.cancel_event.is_set())
        self.assertIsNone(second.current_context(BINDING["session_id"],
                                                 binding_digest=ctx.binding_digest, generation=1))

    def test_clear_keeps_global_and_session_slots_until_provider_call_finalizes(self):
        manager = ConversationManager()
        first_ctx, second_ctx = context("ctx-first"), context("ctx-second")
        first = manager.begin(session_id="1" * 32, generation=1, binding_digest=first_ctx.binding_digest,
                              question="first", context=first_ctx)
        second = manager.begin(session_id="2" * 32, generation=1, binding_digest=second_ctx.binding_digest,
                               question="second", context=second_ctx)
        manager.clear("1" * 32)
        self.assertTrue(first.cancel_event.is_set())
        with self.assertRaises(ConversationError):
            manager.begin(session_id="1" * 32, generation=1, binding_digest=first_ctx.binding_digest,
                          question="same session after clear", context=first_ctx)
        with self.assertRaises(ConversationError):
            manager.begin(session_id="3" * 32, generation=1, binding_digest=first_ctx.binding_digest,
                          question="global third", context=first_ctx)
        manager.fail(first)  # Actual request finalization releases the tombstoned slot.
        replacement = manager.begin(session_id="1" * 32, generation=1,
                                   binding_digest=first_ctx.binding_digest, question="after finalization",
                                   context=first_ctx)
        manager.fail(replacement)
        manager.fail(second)

    def test_question_utf8_limit_is_enforced_before_submission(self):
        manager = ConversationManager()
        ctx = context("ctx-bytes")
        with self.assertRaises(ConversationError):
            manager.begin(session_id=BINDING["session_id"], generation=1,
                          binding_digest=ctx.binding_digest, question="é" * 2_001, context=ctx)

    def test_generation_prompt_contains_only_frozen_context_and_explicit_source_states(self):
        manager = ConversationManager()
        ctx = context("ctx-prompt")
        ticket = manager.begin(session_id=BINDING["session_id"], generation=1,
                              binding_digest=ctx.binding_digest, question="Are model references present?", context=ctx)
        request = make_generation_request(ticket, manager.completed_history(ticket))
        self.assertEqual(request.messages[-1].role, "user")
        self.assertIn('"context_id":"ctx-prompt"', request.messages[-1].content)
        current = json.loads(request.messages[-1].content)
        self.assertEqual(current["source_states"]["model_observations"]["state"], "not_compared")
        self.assertEqual(current["source_states"]["model_observations"]["reason_code"], "projection_not_resolved")
        self.assertEqual(request.max_output_tokens, 2048)
        manager.fail(ticket)

    def test_answer_validation_requires_detail_evidence_for_findings_and_state_evidence_for_unknowns(self):
        from opentrace_core.app.assistant.resolver import _binding_digest, resolve_turn_evidence, SOURCE_CONTRACTS
        binding_digest = _binding_digest(BINDING)
        row = {"record_id": "package:1", "kind": "dependency_observation", "label": "fixture package",
               "excerpt": "fixture-lib 1.2", "locator": "dependency:ctx:1", "binding_digest": binding_digest}
        ctx = resolve_turn_evidence(binding=BINDING, context_id="ctx-answer",
                                    projections={"dependencies": {"state": "completed",
                                        "contract_id": SOURCE_CONTRACTS["dependencies"],
                                        "binding_digest": binding_digest, "entries": [row]}})
        manager = ConversationManager()
        ticket = manager.begin(session_id=BINDING["session_id"], generation=1,
                               binding_digest=ctx.binding_digest, question="What package is recorded?", context=ctx)
        state_id = next(item.evidence_id for item in ctx.evidence if item.kind == "source_state" and item.source == "advisories")
        with self.assertRaises(ConversationError):
            validate_generated_answer(json.dumps({
                "answer_status": "answered", "context_id": ctx.context_id, "turn_id": ticket.turn_id,
                "claims": [{"kind": "finding", "text": "No advisories were found.", "evidence_ids": [state_id]}],
                "limitations": [], "next_steps": []}), ticket)
        detail_id = next(item.evidence_id for item in ctx.evidence if item.kind == "dependency_observation")
        with self.assertRaises(ConversationError):
            validate_generated_answer(json.dumps({
                "answer_status": "answered", "context_id": ctx.context_id, "turn_id": ticket.turn_id,
                "claims": [{"kind": "finding", "text": "fixture-lib 1.2 is recorded.", "evidence_ids": [detail_id]}],
                "limitations": [], "next_steps": []}), ticket)
        accepted = validate_generated_answer(json.dumps({
            "answer_status": "partial", "context_id": ctx.context_id, "turn_id": ticket.turn_id,
            "claims": [{"kind": "finding", "text": "fixture-lib 1.2 is recorded.", "evidence_ids": [detail_id]}],
            "limitations": [], "next_steps": []}), ticket)
        self.assertEqual(accepted["answer_status"], "partial")
        manager.fail(ticket)

class AssistantRouteTests(unittest.TestCase):
    """Exercise assistant route handlers with a real session service and fake transport."""

    def setUp(self):
        from opentrace_core.app.server import Handler
        from opentrace_core.session import SessionService
        self.temp = tempfile.TemporaryDirectory(prefix="ot-assistant-route-")
        self.service = SessionService(self.temp.name)
        self.handle = self.service.create_session()
        self.analysis_ticket = self.service.begin_analysis(self.handle.session_id, self.handle.token, None)
        self.analysis = SimpleNamespace(
            state="complete", ticket=self.analysis_ticket,
            identity={"repository": {"canonical_url": "https://github.com/fixture/repo"},
                      "resolved": {"commit_sha": "b" * 40}})
        self.ctx = resolve_turn_evidence(
            binding=BINDING, context_id="ctx-route", projections={},
            subject={"kind": "analysis", "id": None, "label": "fixture/repo", "binding_digest": _binding_digest(BINDING)})
        self.manager = ConversationManager()
        self.app = SimpleNamespace(
            service=self.service, assistant=self.manager, assistant_lifecycle_lock=threading.RLock(),
            analyses={self.handle.session_id: self.analysis}, lock=threading.Lock())
        self.app._assistant_context_current = lambda sid, token, analysis: (
            self.service.current_generation(sid, token) == analysis.ticket.generation
            and self.app.analyses.get(sid) is analysis)
        self.app.finish_assistant_turn = lambda sid, token, analysis, ticket, answer: self.manager.finish(
            ticket, answer, still_authorized=lambda: self.app._assistant_context_current(sid, token, analysis))

        class Broker:
            calls = 0
            def generate(inner, request):
                inner.calls += 1
                prompt = json.loads(request.messages[-1].content)
                answer = {"answer_status": "unknown", "context_id": prompt["context_id"],
                          "turn_id": prompt["turn_id"], "claims": [], "limitations": [], "next_steps": []}
                return SimpleNamespace(status="complete", content=json.dumps(answer),
                                       profile="openai", model="gpt-6-luna",
                                       validation_level="deterministic_fixture")
        self.broker = Broker()
        self.app.assistant_broker = self.broker
        self.handler = object.__new__(Handler)
        self.handler.server = SimpleNamespace(app=self.app, server_address=("127.0.0.1", 8765))
        self.handler.headers = HttpHeaders()
        self.handler.headers["Cookie"] = f"ot_session={self.handle.session_id}.{self.handle.token}"
        self.handler._json = lambda status, payload, headers=None: (status, payload)
        self.handler._error = lambda status, code, message=None: (status, {"error": code, "message": message or code})
        self.handler._note_job_cancel = lambda *_args: None
        self.app.sweep_quarantine = lambda: None
        self.handler._assistant_resolve_context = lambda _analysis, _subject: (self.ctx, self.ctx.sources)
        self.handler._analysis = lambda: Handler._analysis(self.handler)
        self.binding_patch = patch("opentrace_core.app.workbench_binding.build_binding", return_value=BINDING)
        self.binding_patch.start()

    def tearDown(self):
        self.binding_patch.stop()
        try:
            from opentrace_core.session import SessionError
            try:
                self.service.end_session(self.handle.session_id, self.handle.token)
            except SessionError:
                pass
        finally:
            self.temp.cleanup()

    def request_body(self, **overrides):
        body = {"question": "What does this repository evidence show?", "generation": 1,
                "adopt_subject": False, "subject": None}
        body.update(overrides)
        return body

    def test_ask_authorizes_strict_request_and_returns_bound_inert_response(self):
        status, response = self.handler._assistant_ask(self.request_body())
        self.assertEqual(status, 200)
        self.assertEqual(response["subject"]["kind"], "analysis")
        self.assertEqual(response["provider"], {"profile": "openai", "model": "gpt-6-luna",
                                                  "validation_level": "deterministic_fixture"})
        self.assertEqual(set(response), {"context_id", "turn_id", "answer", "citations", "subject",
                                         "source_states", "limitations", "provider", "fallback"})
        self.assertEqual(response["answer"]["answer_status"], "unknown")
        self.assertGreater(len(response["citations"]), 0)
        self.assertEqual(self.broker.calls, 1)

    def test_ask_rejects_client_provider_evidence_and_wrong_generation_fields(self):
        for body in (self.request_body(provider="openai"),
                     self.request_body(evidence=[{"excerpt": "client supplied"}]),
                     self.request_body(generation=2)):
            with self.subTest(body=body):
                status, payload = self.handler._assistant_ask(body)
                self.assertIn(status, (400, 409))
                self.assertNotEqual(status, 200)
        self.assertEqual(self.broker.calls, 0)

    def test_ask_uses_existing_session_authorization_before_provider_call(self):
        self.handler.headers.replace_header("Cookie", f"ot_session={self.handle.session_id}.wrong-token")
        with self.assertRaises(Exception) as caught:
            self.handler._assistant_ask(self.request_body())
        self.assertEqual(getattr(caught.exception, "code", None), "access_denied")
        self.assertEqual(self.broker.calls, 0)

    def test_cancel_and_citation_routes_reauthorize_and_resolve_only_retained_ids(self):
        from opentrace_core.app.server import Handler
        pending = self.manager.begin(session_id=self.handle.session_id, generation=1,
                                     binding_digest=self.ctx.binding_digest, question="pending", context=self.ctx)
        status, payload = Handler._post(self.handler, "/api/assistant/cancel", {})
        self.assertEqual((status, payload["cancel_requested"]), (200, True))
        self.assertTrue(pending.cancel_event.is_set())
        self.manager.fail(pending)

        status, response = self.handler._assistant_ask(self.request_body())
        self.assertEqual(status, 200)
        citation = response["citations"][0]
        status, opened = Handler._get_api(self.handler, "/api/assistant/citation", {
            "context_id": [response["context_id"]], "evidence_id": [citation["evidence_id"]]})
        self.assertEqual(status, 200)
        self.assertEqual(opened["evidence_id"], citation["evidence_id"])
        self.assertIn("excerpt", opened)
        status, denied = Handler._get_api(self.handler, "/api/assistant/citation", {
            "context_id": [response["context_id"]], "evidence_id": ["forged"]})
        self.assertEqual(status, 404)

    def test_analysis_cancel_and_end_session_retire_server_history_and_pending_turns(self):
        from opentrace_core.app.server import Handler
        pending = self.manager.begin(session_id=self.handle.session_id, generation=1,
                                     binding_digest=self.ctx.binding_digest, question="pending", context=self.ctx)
        status, payload = Handler._post(self.handler, "/api/analysis/cancel", {})
        self.assertEqual(status, 200)
        self.assertTrue(pending.cancel_event.is_set())
        self.assertIsNone(self.manager.current_context(self.handle.session_id,
                                                       binding_digest=self.ctx.binding_digest, generation=1))
        self.manager.fail(pending)

        # A new analyzed generation may establish a fresh context, which End
        # session must retire along with any pending provider request.
        self.analysis_ticket = self.service.begin_analysis(self.handle.session_id, self.handle.token, None)
        self.analysis = SimpleNamespace(state="complete", ticket=self.analysis_ticket,
                                        identity={"repository": {"canonical_url": "https://github.com/fixture/repo"},
                                                  "resolved": {"commit_sha": "b" * 40}})
        self.app.analyses[self.handle.session_id] = self.analysis
        fresh = context("ctx-end", generation=self.analysis_ticket.generation)
        end_ticket = self.manager.begin(session_id=self.handle.session_id,
                                        generation=self.analysis_ticket.generation,
                                        binding_digest=fresh.binding_digest, question="pending at end", context=fresh)
        status, payload = Handler._post(self.handler, "/api/session/end", {})
        self.assertEqual((status, payload["state"]), (200, "deleted_verified"))
        self.assertTrue(end_ticket.cancel_event.is_set())
        self.assertIsNone(self.manager.current_context(self.handle.session_id,
                                                       binding_digest=fresh.binding_digest,
                                                       generation=self.analysis_ticket.generation))
        self.manager.fail(end_ticket)


class CapturedDemoAssistantPathTests(unittest.TestCase):
    """Actual captured analysis and production ask handlers, without a listening socket."""

    def test_completed_demo_whole_analysis_question_reaches_deterministic_broker(self):
        from opentrace_core.app.server import AppState, Handler

        class Broker:
            calls = 0

            def generate(self, request):
                self.calls += 1
                prompt = json.loads(request.messages[-1].content)
                evidence = next((item for item in prompt["evidence"]
                                 if item.get("kind") == "source_state"), None)
                answer = {
                    "answer_status": "unknown",
                    "context_id": prompt["context_id"],
                    "turn_id": prompt["turn_id"],
                    "claims": ([{"kind": "unknown", "text": "Fixture-only answer.",
                                 "evidence_ids": [evidence["evidence_id"]]}] if evidence else []),
                    "limitations": [],
                    "next_steps": [],
                }
                return SimpleNamespace(status="complete", content=json.dumps(answer), profile="fixture",
                                       model="offline", validation_level="deterministic_fixture")

        with tempfile.TemporaryDirectory(prefix="ot-assistant-captured-demo-") as root:
            app = AppState(root, reap_seconds=3600, live=None)
            handler = object.__new__(Handler)
            handler.server = SimpleNamespace(app=app, server_address=("127.0.0.1", 0))
            handler.headers = HttpHeaders()
            handler._json = lambda status, payload, headers=None: (status, payload, headers or {})
            handler._error = lambda status, code, message=None: (status, {"error": code}, {})
            broker = Broker()
            app.assistant_broker = broker
            trace = []
            session_id = token = None
            try:
                # The same session-cookie -> demo setup sequence used by the UI, directly
                # through production handlers. No HTTP server is bound or started.
                session_status, _, session_headers = handler._post("/api/session", {})
                self.assertEqual(session_status, 201)
                handler.headers["Cookie"] = session_headers["Set-Cookie"].split(";", 1)[0]
                session_id, token = handler.headers["Cookie"].split("=", 1)[1].split(".", 1)
                demo_status, demo, _ = handler._post("/api/analysis/demo", {})
                analysis = app.analyses.get(session_id)
                self.assertEqual(demo_status, 200)
                self.assertTrue(demo.get("ok"), "captured DemoSource setup must complete before the ask")
                self.assertIsNotNone(analysis, "completed analysis must be published")
                self.assertEqual(analysis.state, "complete")
                from opentrace_core.app.workbench_binding import build_binding
                from opentrace_core.app.assistant.resolver import _ANALYSIS_DIGEST, _SESSION_ID, _SHA40
                active_binding = dict(build_binding(analysis), session_id=analysis.ticket.session_id)
                self.assertRegex(active_binding["session_id"], _SESSION_ID)
                self.assertRegex(active_binding["analysis_digest"], _ANALYSIS_DIGEST)
                self.assertRegex(active_binding["commit_sha"], _SHA40)
                self.assertTrue(all(isinstance(active_binding["repository"].get(key), str)
                                    and active_binding["repository"].get(key)
                                    for key in ("host", "owner", "name", "canonical_url")))

                original = handler._assistant_resolve_context

                def capture_resolver_error(active_analysis, subject):
                    try:
                        return original(active_analysis, subject)
                    except Exception as exc:
                        import traceback

                        for frame in traceback.extract_tb(exc.__traceback__):
                            filename = os.path.abspath(frame.filename)
                            repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
                            location = (os.path.relpath(filename, repo) if filename.startswith(repo + os.sep)
                                        else "<external>")
                            trace.append((type(exc).__name__, location, frame.name, frame.lineno))
                        raise

                handler._assistant_resolve_context = capture_resolver_error
                status, response, _ = handler._assistant_ask({
                    "question": "What does this whole analysis establish about the captured repository evidence?",
                    "generation": demo["generation"], "adopt_subject": False, "subject": None,
                })
                if status != 200:
                    locations = "; ".join(f"{kind} {path}:{function}:{line}"
                                           for kind, path, function, line in trace)
                    self.fail(f"ask returned {status} {response.get('error')}; broker_calls={broker.calls}; {locations}")
                self.assertEqual(response["answer"]["answer_status"], "unknown")
                self.assertEqual(broker.calls, 1)
            finally:
                try:
                    if session_id and token:
                        app.service.end_session(session_id, token)
                except Exception:
                    pass
                app.close()

    def test_captured_demo_offered_yolov6_model_is_resolvable_for_adoption(self):
        from opentrace_core.app.server import AppState, Handler
        from opentrace_core.app.ai_assets import respond as ai_assets_respond
        from opentrace_core.app.assistant.resolver import resolve_active_analysis
        from opentrace_core.app.workbench_binding import build_binding

        class Broker:
            calls = 0

            def generate(self, request):
                self.calls += 1
                prompt = json.loads(request.messages[-1].content)
                evidence = next((item for item in prompt["evidence"]
                                 if item.get("kind") == "ai_inventory_model"), None)
                if evidence is None:
                    evidence = next(item for item in prompt["evidence"]
                                    if item.get("kind") == "source_state")
                answer = {
                    "answer_status": "unknown", "context_id": prompt["context_id"],
                    "turn_id": prompt["turn_id"],
                    "claims": [{"kind": "unknown", "text": "Fixture-only answer.",
                                "evidence_ids": [evidence["evidence_id"]]}],
                    "limitations": [], "next_steps": [],
                }
                return SimpleNamespace(status="complete", content=json.dumps(answer),
                                       profile="fixture", model="offline",
                                       validation_level="deterministic_fixture")

        with tempfile.TemporaryDirectory(prefix="ot-assistant-model-adoption-") as root:
            app = AppState(root, reap_seconds=3600, live=None)
            handler = object.__new__(Handler)
            handler.server = SimpleNamespace(app=app, server_address=("127.0.0.1", 0))
            handler.headers = HttpHeaders()
            handler._json = lambda status, payload, headers=None: (status, payload, headers or {})
            handler._error = lambda status, code, message=None: (status, {"error": code}, {})
            broker = Broker()
            app.assistant_broker = broker
            session_id = token = None
            try:
                session_status, _, session_headers = handler._post("/api/session", {})
                self.assertEqual(session_status, 201)
                handler.headers["Cookie"] = session_headers["Set-Cookie"].split(";", 1)[0]
                session_id, token = handler.headers["Cookie"].split("=", 1)[1].split(".", 1)
                demo_status, demo, _ = handler._post("/api/analysis/demo", {})
                analysis = app.analyses.get(session_id)
                self.assertEqual(demo_status, 200)
                self.assertTrue(demo.get("ok"))
                self.assertEqual(analysis.state, "complete")

                offered = ai_assets_respond(analysis, {
                    "generation": demo["generation"], "schema_version": 1,
                })
                selected = next(asset for asset in offered["assets"]
                                if asset["display_name"] == "yolov6n.hef")
                selected_id = selected["asset_id"]
                binding = dict(build_binding(analysis), session_id=session_id)
                diagnostic_context = resolve_active_analysis(
                    analysis, context_id="offline-adoption-inspection",
                    subject={"kind": "model", "id": selected_id, "label": "pending",
                             "binding_digest": _binding_digest(binding)},
                )
                selected_in_resolved = any(
                    item.source == "model_observations"
                    and item.locator == "model_observations:" + selected_id
                    for item in diagnostic_context.evidence
                )
                source_state = diagnostic_context.sources["model_observations"]
                original_context = handler._assistant_ask({
                    "question": "Summarize the whole analysis.",
                    "generation": demo["generation"], "adopt_subject": False, "subject": None,
                })
                self.assertEqual(original_context[0], 200)
                original_context_id = original_context[1]["context_id"]
                status, response, _ = handler._assistant_ask({
                    "question": "What does this selected inventory model establish?",
                    "generation": demo["generation"], "adopt_subject": True,
                    "subject": {"kind": "model", "id": selected_id},
                })
                self.assertEqual((status, response.get("error"), broker.calls),
                                 (200, None, 2),
                                 "the AI-assets/1 page offered the selected asset; resolver diagnostic: "
                                 f"selected_in_page={any(a['asset_id'] == selected_id for a in offered['assets'])}, "
                                 f"selected_in_resolved={selected_in_resolved}, "
                                 f"model_state={source_state['state']}, "
                                 f"model_entry_count={source_state['entry_count']}, "
                                 f"model_truncated={source_state['truncated']}, "
                                 f"resolved_entries={len(diagnostic_context.evidence)}")
                self.assertTrue(selected_in_resolved)
                self.assertGreater(source_state["entry_count"], 0)
                self.assertEqual(response["subject"]["id"], selected_id)
                cited = {item["evidence_id"] for item in response["citations"]}
                self.assertTrue(set(response["answer"]["claims"][0]["evidence_ids"]) <= cited)
                self.assertEqual(response["answer"]["answer_status"], "unknown")

                # Explicit adoption changes the current context, while citations
                # from the original whole-analysis turn remain bound to its context.
                changed = response
                self.assertNotEqual(changed["context_id"], original_context_id)
                changed_ids = {item["evidence_id"] for item in changed["citations"]}
                original_only = next(item["evidence_id"] for item in original_context[1]["citations"]
                                     if item["evidence_id"] not in changed_ids)
                citation_status, citation, _ = handler._get_api(
                    "/api/assistant/citation", {"context_id": [original_context_id],
                                                 "evidence_id": [original_only]})
                self.assertEqual(citation_status, 200)
                self.assertEqual(citation["evidence_id"], original_only)
                wrong_context = handler._get_api(
                    "/api/assistant/citation", {"context_id": [changed["context_id"]],
                                                 "evidence_id": [original_only]})
                self.assertEqual((wrong_context[0], wrong_context[1].get("error")),
                                 (404, "citation_not_found"))
            finally:
                try:
                    if session_id and token:
                        app.service.end_session(session_id, token)
                except Exception:
                    pass
                app.close()

    def test_captured_demo_rejects_unoffered_model_subject_before_broker(self):
        from opentrace_core.app.server import AppState, Handler

        class Broker:
            calls = 0

            def generate(self, _request):
                self.calls += 1
                raise AssertionError("invalid adoption must not reach the broker")

        with tempfile.TemporaryDirectory(prefix="ot-assistant-invalid-adoption-") as root:
            app = AppState(root, reap_seconds=3600, live=None)
            handler = object.__new__(Handler)
            handler.server = SimpleNamespace(app=app, server_address=("127.0.0.1", 0))
            handler.headers = HttpHeaders()
            handler._json = lambda status, payload, headers=None: (status, payload, headers or {})
            handler._error = lambda status, code, message=None: (status, {"error": code}, {})
            broker = Broker()
            app.assistant_broker = broker
            session_id = token = None
            try:
                session_status, _, headers = handler._post("/api/session", {})
                self.assertEqual(session_status, 201)
                handler.headers["Cookie"] = headers["Set-Cookie"].split(";", 1)[0]
                session_id, token = handler.headers["Cookie"].split("=", 1)[1].split(".", 1)
                demo_status, demo, _ = handler._post("/api/analysis/demo", {})
                self.assertEqual(demo_status, 200)
                self.assertTrue(demo.get("ok"))
                status, response, _ = handler._assistant_ask({
                    "question": "Describe this object.", "generation": demo["generation"],
                    "adopt_subject": True, "subject": {"kind": "model", "id": "forged-model-id"},
                })
                self.assertEqual((status, response.get("error"), broker.calls),
                                 (400, "subject_not_in_resolved_evidence", 0))
            finally:
                try:
                    if session_id and token:
                        app.service.end_session(session_id, token)
                except Exception:
                    pass
                app.close()

    def test_failed_captured_demo_adoption_does_not_retarget_next_followup(self):
        from opentrace_core.app.server import AppState, Handler
        from opentrace_core.app.ai_assets import respond as ai_assets_respond

        class Broker:
            calls = 0
            fail_next = False
            context_ids = []

            def generate(self, request):
                self.calls += 1
                prompt = json.loads(request.messages[-1].content)
                self.context_ids.append(prompt["context_id"])
                if self.fail_next:
                    self.fail_next = False
                    raise RuntimeError("deterministic provider failure")
                evidence = next(item for item in prompt["evidence"]
                                if item.get("kind") == "source_state")
                answer = {
                    "answer_status": "unknown", "context_id": prompt["context_id"],
                    "turn_id": prompt["turn_id"],
                    "claims": [{"kind": "unknown", "text": "Fixture-only answer.",
                                "evidence_ids": [evidence["evidence_id"]]}],
                    "limitations": [], "next_steps": [],
                }
                return SimpleNamespace(status="complete", content=json.dumps(answer),
                                       profile="fixture", model="offline",
                                       validation_level="deterministic_fixture")

        with tempfile.TemporaryDirectory(prefix="ot-assistant-failed-adoption-") as root:
            app = AppState(root, reap_seconds=3600, live=None)
            handler = object.__new__(Handler)
            handler.server = SimpleNamespace(app=app, server_address=("127.0.0.1", 0))
            handler.headers = HttpHeaders()
            handler._json = lambda status, payload, headers=None: (status, payload, headers or {})
            handler._error = lambda status, code, message=None: (status, {"error": code}, {})
            broker = Broker()
            app.assistant_broker = broker
            session_id = token = None
            try:
                session_status, _, headers = handler._post("/api/session", {})
                self.assertEqual(session_status, 201)
                handler.headers["Cookie"] = headers["Set-Cookie"].split(";", 1)[0]
                session_id, token = handler.headers["Cookie"].split("=", 1)[1].split(".", 1)
                demo_status, demo, _ = handler._post("/api/analysis/demo", {})
                self.assertEqual(demo_status, 200)
                self.assertTrue(demo.get("ok"))

                original = handler._assistant_ask({
                    "question": "Summarize the whole analysis.",
                    "generation": demo["generation"], "adopt_subject": False, "subject": None,
                })
                self.assertEqual(original[0], 200)
                original_context_id = original[1]["context_id"]
                offered = ai_assets_respond(app.analyses.get(session_id), {
                    "generation": demo["generation"], "schema_version": 1,
                })
                selected_id = next(item["asset_id"] for item in offered["assets"]
                                   if item["display_name"] == "yolov6n.hef")
                broker.fail_next = True
                failed = handler._assistant_ask({
                    "question": "Adopt this model, but the provider fails.",
                    "generation": demo["generation"], "adopt_subject": True,
                    "subject": {"kind": "model", "id": selected_id},
                })
                self.assertEqual((failed[0], failed[1].get("error"), broker.calls),
                                 (500, "assistant_request_failed", 2))

                followup = handler._assistant_ask({
                    "question": "Continue the previous whole-analysis question.",
                    "generation": demo["generation"], "adopt_subject": False, "subject": None,
                })
                self.assertEqual(followup[0], 200)
                self.assertEqual(followup[1]["context_id"], original_context_id)
                self.assertEqual(broker.context_ids[2], original_context_id)
            finally:
                try:
                    if session_id and token:
                        app.service.end_session(session_id, token)
                except Exception:
                    pass
                app.close()


if __name__ == "__main__":
    unittest.main()
