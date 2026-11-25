"""Loopback-only HTTP service for the I4E Workbench (stdlib only, no network egress)."""
import contextlib
import hashlib
import hmac
import json
import mimetypes
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

from opentrace_core.advisory import join as advisory_join, osv as advisory_osv
from opentrace_core.bombridge import discovery as bb_discovery
from opentrace_core.bombridge import pipeline
from opentrace_core.bombridge_adapter import AdapterContext, AdapterError, assemble, assess
from opentrace_core.intake.identity import build_identity
from opentrace_core.intake.resolve import resolve
from opentrace_core.intake.url import IntakeError, parse_manual_sha, parse_repository_url
from opentrace_core.live import policy as live_policy
from opentrace_core.live import runner as live_runner
from opentrace_core.live import source as live_source
from opentrace_core.live import ai_source as live_ai_source
from opentrace_core.live import crypto_source as live_crypto_source
from opentrace_core.live import source_checks as live_source_checks
from opentrace_core.live.bundle import artifact_id, build as build_live_bundle, configuration_label
from . import live_discovery
from opentrace_core.live.view_source import LiveSource
from opentrace_core.session.producers import ProcessProducer  # noqa: F401  (re-exported for tests)
from opentrace_core.session import SessionError, SessionService

from . import replay as demo_replay
from . import scan_jobs
from .demo import DEFAULT_URL, SCAN, DemoSource, utc_now
from .views import ViewError, Views
from .assistant.resolver import resolve_active_analysis
from .assistant.service import (CLARIFY_TEXT, FALLBACK_CODES, ConversationError, ConversationManager, fallback_answer, make_generation_request, needs_item,
                               validate_generated_answer)
from .assistant.providers import AssistantBrokerClient, ProviderError

BIND_HOST = "127.0.0.1"
CONTAINER_BIND_VAR = "OPENTRACE_CONTAINER_BIND"   # "1" lets the service listen on 0.0.0.0 INSIDE its container (I6)
COOKIE = "ot_session"
UI_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "ui"))
CSP = ("default-src 'self'; worker-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
MAX_BODY = 16 * 1024
DENIED = {"error": "access_denied", "message": "access denied"}
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


ASSISTANT_PLAIN_ERRORS = {
    "input_too_large": "This question is too large for the assistant to read together with the evidence. Shorten it and ask again.",
    "broker_input_limit": "This question is too large for the assistant to read together with the evidence. Shorten it and ask again.",
    "question_too_large": "The question is too long. Shorten it to 4,000 characters or fewer and ask again.",
    "broker_busy_or_budget": "The assistant is busy or has reached a limit. Wait a moment and try again.",
    "broker_busy": "The assistant is busy with another request right now. Try again in a moment.",
    "broker_allowance_exhausted": "The local assistant usage allowance has been used up, so it cannot answer more questions. Trying again will not help until the allowance is raised or reset.",
    "assistant_busy": "The assistant is busy with another request. Wait a moment and try again.",
    "broker_unavailable": "The assistant service could not complete the request. Try again in a moment.",
    # Answers the strict validator withholds (the validator itself is unchanged).
    "finding_state_unsupported": "The assistant's answer was withheld: it presented evidence coverage, or evidence that could not be confirmed, as a finding. "
                                 "Ask about a specific item instead: select it in the Workbench and choose “Explain this”.",
    "answer_status_inconsistent": "The assistant's answer was withheld because its stated confidence did not match the evidence behind it. Select an item and choose “Explain this”, or ask again.",
    "answer_validation_failed": "The assistant's answer was withheld because it did not cite the supplied evidence correctly. Ask again, or select an item and choose “Explain this”.",
    "invalid_provider_output": "The assistant's answer was withheld because it was not in the expected form. Ask again.",
    # Subject selection ("Use current selection for this question") that cannot be used.
    "subject_not_in_resolved_evidence": "OpenTrace could not find that item in the evidence the assistant can read, so it cannot be explained. Select another item and choose “Explain this”, or ask about the whole analysis.",
    "subject_invalid": "That kind of item cannot be explained yet. Select a package, finding or record in the Workbench and choose “Explain this”.",
    "subject_required": "Select the item you want explained in the Workbench, then choose “Explain this”.",
    "subject_requires_explicit_adoption": "Choose “Explain this” on the item to switch what the assistant is talking about.",
}


class _Analysis:
    """Server-side state for one analysis; lives only in memory and dies with the session."""

    def __init__(self, ticket, identity, records, names):
        self.ticket = ticket
        self.identity = identity
        self.records = records
        self.names = names
        self.assessment = None
        self.collection = None    # UIP-10: live collection/capability state (``live_discovery``); ``None`` for the recorded case
        self.gaps = None          # I8: {"status": "compared", "assessment": BoundAssessment} or {"status": "not_compared", "code", "detail"}; demo only
        self.context = None
        self.crypto_source = None  # Stage 4 B (``live.crypto_source.present``)
        self.ai_source = None     # Stage 4 A: source observations for the AI tab (``live.ai_source.present``); ``None`` when none were collected
        self.views = None
        self.read = None
        self.summary = None
        self.state = "running"
        self.mode = "captured"
        self.configuration = None
        self.scan = None


class _AnalysisProducer:
    """Session producer for the in-process analysis: stop() cancels, is_alive() reports the run."""

    def __init__(self, ticket):
        self.ticket = ticket
        self.running = True

    def stop(self):
        self.ticket.cancel_event.set()

    def is_alive(self):
        return self.running


_FROM_ENV = object()


def _recording(transport, parsed):
    """Wrap an intake transport so the repository record GitHub returns is kept for the admission policy (no extra request)."""
    path = "/repos/{}/{}".format(parsed.owner, parsed.name)
    box = {}

    def wrapped(request_path):
        response = transport(request_path)
        if request_path == path and getattr(response, "status", None) == 200:
            box["repo"] = getattr(response, "body", None)
        return response
    return wrapped, box


class AppState:
    def __init__(self, session_root, *, demo=None, reap_seconds=30.0, service=None, live=_FROM_ENV, replay=_FROM_ENV):
        self.demo = demo or DemoSource()
        # The CLI selects the bundled replay. In-process callers can supply a capture or use the legacy demo.
        self.replay = demo_replay.from_env() if replay is _FROM_ENV else replay
        # Live scanning is opt-in: OPENTRACE_LIVE_SCAN=1 (or an injected LiveConfig). None means disabled.
        self.live = live_runner.LiveConfig.from_env() if live is _FROM_ENV else live
        self.service = service or SessionService(session_root)
        self.assistant = ConversationManager()
        self.assistant_lifecycle_lock = threading.RLock()
        try:
            self.assistant_broker = AssistantBrokerClient.from_env()
        except (ProviderError, ValueError):
            self.assistant_broker = None
        self.analyses = {}          # session id -> _Analysis
        self.lock = threading.Lock()
        self.live_gate = threading.Lock()   # one live scan at a time
        self.scan_jobs = {}         # session id -> ScanJob (UIP-03: the running reservation, then the retained terminal record)
        self.quarantine = {}        # session id -> ScanJob whose cleanup is unconfirmed: the gate stays held until the session is verified gone
        self.scan_clock = scan_jobs.Clock()
        self.scan_thread_factory = threading.Thread   # tests substitute a failing factory to exercise rollback
        self.scan_park_seconds = 30.0   # how long an UNCLAIMED parked job thread waits before expiring (tests inject a tiny value)
        self.cleanup_wait = 5.0     # seconds a finished job waits for transient leftovers (a cancel's trash removal) before calling cleanup unverified
        self.service.startup_sweep()
        self._stop = threading.Event()
        self._reaper = threading.Thread(target=self._reap, args=(reap_seconds,), daemon=True)
        self._reaper.start()

    def _reap(self, interval):
        while not self._stop.wait(interval):
            try:
                with self.assistant_lifecycle_lock:
                    self.service.tick()
                    with self.lock:
                        live = set(self.service._sessions)
                        for sid in [s for s in self.analyses if s not in live]:
                            self.analyses.pop(sid, None)
                            self.assistant.clear(sid)
                        for sid in [s for s, j in self.scan_jobs.items() if s not in live and j.terminal]:
                            self.scan_jobs.pop(sid, None)
                self.sweep_quarantine()
            except Exception:
                pass

    def _assistant_context_current(self, sid, token, analysis):
        try:
            generation = self.service.current_generation(sid, token)
            with self.lock:
                current = self.analyses.get(sid)
            return (current is analysis and analysis is not None and analysis.state == "complete"
                    and generation == analysis.ticket.generation and analysis.ticket.session_id == sid)
        except Exception:
            return False

    def begin_assistant_analysis(self, sid, token, *, expected_generation=None):
        """Advance generation and retire its assistant context as one transition."""
        with self.assistant_lifecycle_lock:
            ticket = self.service.begin_analysis(sid, token, None, expected_generation=expected_generation)
            self.assistant.clear(sid)
            return ticket

    def finish_assistant_turn(self, sid, token, analysis, ticket, answer):
        """Reauthorize and append while analysis/session replacement is excluded."""
        with self.assistant_lifecycle_lock:
            return self.assistant.finish(
                ticket, answer,
                still_authorized=lambda: self._assistant_context_current(sid, token, analysis))

    # -- UIP-03 gate ownership ---------------------------------------------
    def release_gate(self, job):
        """Release the service gate for ``job`` exactly once (idempotent)."""
        with self.lock:
            if not job.gate_held:
                return False
            job.gate_held = False
            self.quarantine.pop(job.sid, None)
        self.live_gate.release()
        return True

    def sweep_quarantine(self):
        """A quarantined job's gate is released only once its session is verified deleted (absent from the registry)."""
        with self.lock:
            gone = [j for sid, j in self.quarantine.items() if sid not in self.service._sessions and j.terminal]
        for job in gone:
            job.quarantined = False
            self.release_gate(job)

    def close(self):
        self._stop.set()
        with self.lock:
            jobs = [j for j in self.scan_jobs.values() if not j.terminal or j.gate_held]
        for job in jobs:     # shutdown: stop every unfinished job through its producer (the ticket's cancel event)
            job.cancel_reason = job.cancel_reason or "session_ended"
            job_ticket = getattr(job, "ticket", None)
            if job_ticket is not None:
                job_ticket.cancel_event.set()
        me = threading.current_thread()
        for job in jobs:
            thread = job.thread
            if thread is not None and thread is not me and thread.is_alive():
                thread.join(10)


def _note(observer, event, **detail):
    """Tell an optional observer about a pipeline boundary. Never raises and never changes a result (UIP-03)."""
    if observer is None:
        return
    try:
        observer(event, detail)
    except Exception:
        pass


def _analysis_payload(analysis):
    ident = analysis.identity
    return {"ok": True, "generation": analysis.ticket.generation,
            "identity": {"repository": ident["repository"]["canonical_url"], "owner": ident["repository"]["owner"],
                         "name": ident["repository"]["name"], "commit": ident["resolved"]["commit_sha"],
                         "requested": ident["requested"], "basis": ident["resolved"]["basis"],
                         "configuration": analysis.configuration, "analysis_digest": ident["analysis_digest"],
                         "mode": analysis.mode},
            "summary": analysis.summary}


def _run_live_pipeline(app, sid, token, ticket, producer, parsed, res, *, identity=None, manual_sha=None, observer=None, register=True, replay=None):
    """The live analysis after admission, shared by the legacy ``/api/analysis/live`` route and the UIP-03 scan job.

    Returns the JSON-able dict the legacy route sends (``{"ok": False, ...}`` or the analysis payload). ``observer`` (job only)
    hears about boundaries; ``identity`` (job only) is the already-pinned identity, otherwise it is built here; ``register=False``
    when the caller registered the producer already. With the defaults this is the legacy behavior, byte for byte.
    """
    live = replay.live if replay is not None else app.live    # replay: the recorded scan's stand-in; no scanner, OSV or provider is reached
    try:
        if register:
            app.service.register_producer(ticket, producer)
        session = {"session_id": sid, "generation": ticket.generation}
        scan_cfg = live_runner.SCAN
        if identity is None:
            identity = build_identity(parsed, manual_sha, res, scan_cfg, session)
        try:
            declarations = {}
            if replay is not None:
                source, runs, inventory, collected = replay.scan_all(identity, declarations)
            else:
                source, runs, inventory, collected = live_runner.scan_all(live, app.service, ticket, identity, on_stage=observer,
                                                                          declarations_sink=declarations)
        except live_source.SourceError as exc:
            app.service.finish(ticket, "failed")
            _note(observer, "source_failed", code=exc.code)
            return {"ok": False, "code": exc.code, "stage": "source",
                    "message": "the pinned commit could not be acquired and verified: " + exc.code}
        if ticket.cancel_event.is_set():
            raise SessionError("stale_generation", "cancelled")
        _note(observer, "projection_started")
        bundle_parts, records, names, raw = build_live_bundle(identity, source, runs, sid, ticket.generation, advisory=live.advisories is not None, source_checks=collected)
        scan_runs = [r.as_dict() for r in runs]
        if any(r.reason == "cleanup_unverified" for r in runs):
            app.service.finish(ticket, "failed")
            return {"ok": False, "code": "cleanup_unverified", "stage": "scan", "scan": scan_runs,
                    "message": "a scanner's process group could not be confirmed gone, so no result is shown"}
        if not any(r.outcome == "acquired" and r.kind == "sbom" for r in runs):
            app.service.finish(ticket, "failed")
            return {"ok": False, "code": "sbom_unavailable", "stage": "scan", "scan": scan_runs,
                    "message": "the SBOM scan did not produce an inventory, so no dependency view can be shown"}
        analysis = _Analysis(ticket, identity, records, {r.artifact_id: names[r.artifact_id] for r in records if r.artifact_id in names})
        analysis.mode, analysis.scan = "live", scan_runs
        analysis.configuration = configuration_label(identity)   # UIP-10 D2: scan profile, not an observed environment
        analysis.read = lambda aid: app.service.read_artifact(sid, token, analysis.names[aid]).data
        analysis.context = AdapterContext(identity, session, analysis.configuration,
                                          lambda: dict(session) if not ticket.cancel_event.is_set() else None)
        assembled = assemble(analysis.context, capture=bundle_parts["capture"], entities=bundle_parts["entities"],
                             observations=bundle_parts["observations"], assertions=bundle_parts["assertions"],
                             input_checks=bundle_parts["input_checks"], origin=bundle_parts["origin"],
                             notice=bundle_parts["notice"], artifacts=records, read_artifact=lambda aid: raw[aid])
        for aid, name in analysis.names.items():
            app.service.commit_artifact(ticket, name, raw[aid], "application/json", "original")
        _note(observer, "artifacts_committed", runs=runs, records=records, names=analysis.names, raw=raw)
        outcome = assess(analysis.context, assembled, artifacts=records, read_artifact=analysis.read, cancel=ticket.cancel_event)
        if outcome.status != "complete":
            app.service.finish(ticket, "failed")
            return {"ok": False, "code": outcome.status, "scan": scan_runs,
                    "errors": [e.as_dict() for e in outcome.errors]}
        analysis.assessment = outcome.assessment
        app.service.commit_artifact(ticket, "bombridge-result.json", pipeline.canonical(outcome.assessment.result).encode("utf-8"),
                                    "application/json", "derived")
        # UIP-10: requirement -> SBOM comparison for this repository (collected before cleanup; unchanged discovery and assessment).
        analysis.gaps, analysis.collection = live_discovery.run(analysis, ticket, app.service, bundle_parts=bundle_parts, records=records, sink=declarations)
        lookup = report = None
        if live.advisories is not None:
            _note(observer, "advisory_lookup_started")
            if replay is not None:
                lookup, report = replay.advisory()
            else:
                lookup, report = Handler._advisory_lookup(live.advisories, inventory, raw[records_sbom_id(records)], ticket)
            if ticket.cancel_event.is_set():
                raise SessionError("stale_generation", "cancelled")
            if lookup is not None:
                app.service.commit_artifact(ticket, "advisory-lookup.json", replay.advisory_log_bytes() if replay is not None else advisory_osv.log_document(lookup),
                                            "application/json", "derived")
            _note(observer, "advisory_lookup_done", report=report, lookup=lookup)
        analysis.views = Views(LiveSource(report, lookup), analysis)
        analysis.summary = analysis.views.summary()
        analysis.summary["gaps"] = analysis.views.gaps_summary()
        analysis.summary["advisory_lookup"] = None if report is None else dict(
            report["summary"], inventory_detail=inventory.as_dict() if inventory else None, not_established=report["not_established"])
        kind_run = {r["kind"]: r for r in scan_runs}
        for card in analysis.summary["cards"]:
            card["artifact_name"] = analysis.names.get(card["artifact_id"])
            card["scan"] = kind_run.get(card["kind"])
        analysis.summary["live"] = {"source": source.as_dict(), "scan": scan_runs, "isolation": live.isolation.description,
                                    "advisory": "not_run" if report is None else report["summary"]["lookup"],
                                    "checks": "assessed" if bundle_parts["assertions"] else "none_assessed"}
        if replay is not None:
            analysis.summary["live"]["replay"] = replay.replay_note
        analysis.crypto_source = live_crypto_source.present(declarations)   # Stage 4 B: JWT/TLS/hashlib source observations for the Crypto tab (session-only)
        analysis.ai_source = live_ai_source.present(declarations)    # Stage 4 A: session-only source observations for the AI tab (not part of the summary payload)
        analysis.summary["source_checks"] = live_source_checks.present(
            collected, source.repository_url, source.commit_sha, outcome.assessment.result, next((r for r in runs if r.kind == "cbom"), None))
        with app.lock:
            app.analyses[sid] = analysis
        app.service.finish(ticket, "complete")
        analysis.state = "complete"
    except SessionError as exc:
        producer.running = False
        return {"ok": False, "code": "cancelled" if exc.code == "stale_generation" else exc.code}
    except Exception as exc:  # AdapterError etc.: typed, metadata only, never repository content
        producer.running = False
        with contextlib.suppress(SessionError):
            app.service.finish(ticket, "failed")
        return {"ok": False, "code": getattr(exc, "code", "analysis_failed"), "message": type(exc).__name__}
    finally:
        producer.running = False
    return _analysis_payload(analysis)


class _JobObserver:
    """Maps pipeline boundaries to the frozen stage states of one job. Reads only; every method tolerates being skipped."""

    def __init__(self, job):
        self.job = job

    def __call__(self, event, d):
        j = self.job
        if event == "acquire_started":
            j.stage("acquire_source", "running")
        elif event == "acquire_done":
            j.stage("acquire_source", "completed")
        elif event == "scan_phase_started":
            j.scanners_started(d["kinds"], d["shared"])
        elif event == "scan_phase_done":
            runs = d["runs"] if d.get("shared", True) else d["runs"][-1:]
            for run in runs:
                self._settle_unaccepted(run)
        elif event == "aibom_started":
            j.stage("aibom", "running")
        elif event == "aibom_done":
            self._settle_aibom(d["run"])
        elif event == "inventory_started":
            j.stage("advisory_lookup", "running")
        elif event == "source_checks_started":
            j.stage("source_checks", "running")
        elif event == "source_checks_done":
            seen = d.get("collected") or []
            observed = [c for c in seen if c.get("status") == "observed"]
            if not seen:
                j.stage("source_checks", "not_run", "not_configured")
            elif observed and len(observed) == len(seen):
                j.stage("source_checks", "completed")
            else:
                j.stage("source_checks", "partial", "partial_coverage", warnings=[scan_jobs.WARNING_SOURCE_PARTIAL])
        elif event == "projection_started":
            j.stage("evidence_projection", "running")
        elif event == "artifacts_committed":
            self._publish_scanners(d["runs"])
        elif event == "advisory_lookup_done":
            report = d.get("report") or {}
            state = ((report.get("summary") or {}).get("lookup"))
            if state == "complete":
                j.stage("advisory_lookup", "completed")
            elif state == "partial":
                j.stage("advisory_lookup", "partial", "partial_coverage", warnings=[scan_jobs.WARNING_ADVISORY_PARTIAL])
            else:
                j.stage("advisory_lookup", "partial", "partial_coverage", warnings=[scan_jobs.WARNING_ADVISORY_UNAVAILABLE])

    def _settle_unaccepted(self, run):
        j = self.job
        if run.outcome == "acquired":
            return    # accepted output stays ``running`` until it is committed as an artifact (``artifacts_committed``)
        if run.reason == "cleanup_unverified":
            j.cleanup_unverified = True
        cancelled = run.outcome == "cancelled" or (j.ticket is not None and j.ticket.cancel_event.is_set() and run.reason != "cleanup_unverified")
        if cancelled:       # a scanner killed by a cancel or End session is cancelled, not failed
            j.stage(run.kind, "cancelled", "session_ended" if j.cancel_reason == "session_ended" else "cancelled_by_user")
        else:
            j.stage(run.kind, "failed", scan_jobs.run_reason(run.reason))

    # UIP-07C P7 rows 2 and 8-11 (amendment A4 lets ``aibom`` be ``partial`` with or without committed outputs): a run that produced no artifact is
    # ``partial/partial_coverage`` with a fixed warning; the job state derives to ``partial``, hand-off stays ready, SBOM/CBOM stay accessible, and the
    # AI tab / run record carry the precise reason.
    AI_NO_ARTIFACT = ("partial", "partial_coverage")

    def _settle_aibom(self, run):
        j = self.job
        if run.outcome == "acquired":
            return    # an accepted artifact stays ``running`` until it is committed (``artifacts_committed``)
        if run.reason == "cleanup_unverified":
            j.cleanup_unverified = True
            j.stage("aibom", "failed", "cleanup_unverified")          # row 14: the job fails and the gate is quarantined, as for scanners
        elif run.outcome == "cancelled" or (j.ticket is not None and j.ticket.cancel_event.is_set()):
            j.stage("aibom", "cancelled", "session_ended" if j.cancel_reason == "session_ended" else "cancelled_by_user")
        else:
            warning = scan_jobs.WARNING_AI_UNAVAILABLE if run.outcome == "unavailable" else scan_jobs.WARNING_AI_NOT_COMPLETED
            j.stage("aibom", self.AI_NO_ARTIFACT[0], self.AI_NO_ARTIFACT[1], warnings=[warning])

    def _publish_aibom(self, run):
        j = self.job
        out = [{"kind": "aibom", "artifact_id": artifact_id("aibom"), "sha256": run.sha256, "size": run.size}]
        if run.completeness != "verified":      # degraded / skipped / unverified (row 7): the typed counts reach the AI tab through A1
            j.stage("aibom", "partial", "partial_coverage", outputs=out, warnings=[scan_jobs.WARNING_AI_INCOMPLETE])
        elif run.record_count == 0:
            j.stage("aibom", "completed_empty", "no_applicable_assets", outputs=out)
        else:
            j.stage("aibom", "completed", outputs=out)

    def _publish_scanners(self, runs):
        j = self.job
        for run in runs:
            if run.outcome != "acquired":
                continue
            if run.kind == "aibom":
                self._publish_aibom(run)
                continue
            out = [{"kind": run.kind, "artifact_id": artifact_id(run.kind), "sha256": run.sha256, "size": run.size}]
            note = [scan_jobs.WARNING_SCANNER_NOTES] if run.warnings else []
            if run.record_count == 0:
                j.stage(run.kind, "completed_empty", "no_applicable_assets", outputs=out, warnings=note)
            else:
                j.stage(run.kind, "completed", outputs=out, warnings=note)


def _fail_resolution(job, reason, code):
    job.stage("resolve_revision", "failed", reason, warnings=[scan_jobs.failure_note(code)])
    job.fail_remaining()


def _scan_job_main(app, job, ticket, producer, parsed, manual_sha):
    """The job thread: resolve once, pin, run the shared pipeline, settle the stage table, release the gate, publish the terminal state.

    Never holds ``app.lock`` or a session lock across a wait; never joins a thread.
    """
    live, sid = app.live, job.sid
    outcome = None          # the pipeline's dict
    try:
        job.start()
        try:
            transport, record = _recording(live.transport, parsed)
            res = resolve(parsed, manual_sha, transport, now=utc_now)          # the ONLY resolution of this job
            live.check(res.owner, res.name, res.commit_sha, record.get("repo"))
        except IntakeError as exc:
            _fail_resolution(job, scan_jobs.intake_reason(exc.code), exc.code)
            return
        except live_policy.PolicyError as exc:
            _fail_resolution(job, "policy_refused", exc.code)
            return
        ok, _why = live.isolation.available()
        if not ok:
            _fail_resolution(job, "scanner_unavailable", "isolation_unavailable")
            return
        if ticket.cancel_event.is_set():
            job.cancel_all()
            return
        identity = build_identity(parsed, manual_sha, res, live_runner.SCAN, {"session_id": sid, "generation": ticket.generation})
        job.pin(identity)
        outcome = _run_live_pipeline(app, sid, job.token, ticket, producer, parsed, res, identity=identity, manual_sha=manual_sha,
                                     observer=_JobObserver(job), register=False)
    except Exception:
        if job.identity is None:     # nothing was pinned yet: the resolution step itself is the one that failed
            job.stage("resolve_revision", "failed", "scanner_unavailable", warnings=[scan_jobs.GENERIC_FAILURE_NOTE])
        else:
            job.stage("evidence_projection", "failed", "output_invalid", warnings=[scan_jobs.GENERIC_FAILURE_NOTE])
        job.fail_remaining()
    finally:
        producer.running = False
        _settle(app, job, ticket, outcome)


class _Launch:
    """The ownership hand-over between the request handler and a job thread that was started *before* the session was touched (UIP-03-IR-04).

    One small state machine under one lock, so neither side can act on a guess about the other:
    ``parked`` -> ``claimed`` (the handler took ownership: the worker must now wait for ``release`` however long the reservation takes)
    ``parked`` -> ``expired`` (the worker gave up while nobody had claimed it: the handler's later ``claim`` fails and it refuses the start
    before any session state is touched). ``args`` stays ``None`` when a claimed reservation was rolled back; the worker then exits.
    """

    def __init__(self):
        self.go = threading.Event()
        self.args = None
        self._lock = threading.Lock()
        self._state = "parked"

    def claim(self):
        with self._lock:
            if self._state != "parked":
                return False
            self._state = "claimed"
            return True

    def expire(self):
        with self._lock:
            if self._state != "parked":
                return False
            self._state = "expired"
            return True


def _scan_job_entry(app, launch):
    # While unclaimed the worker may expire (nothing exists to orphan). Once claimed it waits for the handler's release, which the
    # handler's try/finally always performs, so a reservation that is later published always has its worker.
    while not launch.go.wait(app.scan_park_seconds):
        if launch.expire():
            return
    args = launch.args
    if args is None:
        return
    _scan_job_main(app, *args)


def _await_cleanup(app, job, ticket):
    """True ONLY when cleanup is positively verified: no workspace, no cancellation leftovers, no live producer, no ending session.

    Transient leftovers (a cancel's trash removal, a producer that is still stopping) are given a bounded time to clear. Any doubt,
    including an error while checking, is *unverified*: this function never defaults to verified.
    """
    deadline = time.monotonic() + app.cleanup_wait
    while True:
        try:
            if job.cleanup_unverified:
                return False
            session = app.service._sessions.get(job.sid)
            if session is not None and getattr(session, "state", "active") in ("ending", "cleanup_failed"):
                return False
            facts = app.service.cleanup_facts(ticket)
            if not (facts["workspace_present"] or facts["trash_present"] or facts["producers_alive"]):
                return True
        except Exception:
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def _finish_session_analysis(app, ticket):
    """Mark this job's session analysis failed unless the pipeline already finished it. A cancelled, ended or replaced ticket is
    refused by the service (``stale_generation``) and is left exactly as it is: it is never revived."""
    with contextlib.suppress(Exception):
        app.service.finish(ticket, "failed")


def _settle(app, job, ticket, outcome):
    """Final accounting. Order: stage table, cleanup verification, gate decision, terminal publication.

    The gate is released only when cleanup was positively verified. Any other path (including an error in this function) quarantines it:
    the gate then stays held until the session is verified deleted.
    """
    st = {"verified": False, "handoff": False, "analysis": None}
    try:
        _settle_stages(app, job, ticket, outcome, st)
    except Exception:
        st["handoff"] = False
        with contextlib.suppress(Exception):
            if job.state() not in ("failed", "cancelled"):
                job.stage("evidence_projection", "failed", "output_invalid", warnings=[scan_jobs.GENERIC_FAILURE_NOTE])
            job.fail_remaining()
    finally:
        cleanup = "verified" if st["verified"] else "unverified"
        try:
            if st["verified"]:
                app.release_gate(job)               # the pipeline returned and cleanup is KNOWN: only now may another job start
            else:
                with app.lock:
                    job.quarantined = True
                    app.quarantine[job.sid] = job   # the gate stays held until the session is verified deleted
            if st["handoff"] and not job.terminal:
                job.registered(st["analysis"], _analysis_payload(st["analysis"]), cleanup)
            else:
                job.finish(cleanup)
        finally:
            if not job.terminal:
                job.finish("unverified")           # never leave a job that polls forever; the gate decision above already stands


def _settle_stages(app, job, ticket, outcome, st):
    sid = job.sid
    ok = outcome is not None and outcome.get("ok") is True
    analysis = None
    if ok:
        with app.lock:
            analysis = app.analyses.get(sid)
        if analysis is None or analysis.ticket is not ticket or ticket.cancel_event.is_set():
            ok = False      # ended or cancelled after the pipeline registered: nothing is published
            job.cancel_reason = job.cancel_reason or "session_ended"
            job.cancel_all()
    elif outcome is not None:
        code = outcome.get("code")
        if code in ("cancelled", "access_denied", "stale_generation"):
            if code != "cancelled":
                job.cancel_reason = job.cancel_reason or "session_ended"
            job.cancel_all()
        elif outcome.get("stage") == "source":
            if code == "cleanup_unverified":
                job.cleanup_unverified = True       # an unconfirmed source process group is never "cleaned up"
            job.stage("acquire_source", "failed", scan_jobs.source_reason(code), warnings=[scan_jobs.failure_note(code)])
        elif code == "cleanup_unverified":
            job.cleanup_unverified = True
        elif code == "sbom_unavailable":
            job.stage("sbom", "failed", "scanner_failed")
        else:
            job.stage("evidence_projection", "failed", "output_invalid", warnings=[scan_jobs.GENERIC_FAILURE_NOTE])
    if not ok:
        _finish_session_analysis(app, ticket)      # an early exit (no pipeline) left the session analysis running (UIP-03-IR-03)
    verified = _await_cleanup(app, job, ticket)
    if not verified:
        job.cleanup_unverified = True
        if ok:
            ok = False
            with app.lock:
                if app.analyses.get(sid) is analysis:
                    app.analyses.pop(sid, None)      # no result is readable while cleanup is uncertain
        if job.state() not in ("failed", "cancelled"):
            job.stage("evidence_projection", "failed", "cleanup_unverified")
    elif ok:
        job.stage("evidence_projection", "completed")
    # A scanner that failed leaves the frozen job state ``failed`` (no hand-off), whatever the legacy pipeline went on to do.
    handoff = ok and verified and not any(job.stages[k]["state"] in ("failed", "cancelled") for k in scan_jobs.STAGE_ORDER)
    job.fail_remaining(keep=("workbench_ready",) if handoff else ())
    if ticket.cancel_event.is_set() and job.state() not in ("cancelled", "failed"):
        handoff = False
        job.cancel_all()
    st.update(verified=verified, handoff=handoff, analysis=analysis)


class Handler(BaseHTTPRequestHandler):
    server_version = "OpenTraceLoopback/1"
    protocol_version = "HTTP/1.1"

    # -- plumbing -----------------------------------------------------------
    def log_message(self, fmt, *args):  # metadata only, never content
        pass

    @property
    def app(self):
        return self.server.app

    def _origin(self):
        return "http://{}:{}".format(BIND_HOST, self.server.server_address[1])

    def _host_ok(self):
        port = self.server.server_address[1]
        return self.headers.get("Host") in ("127.0.0.1:{}".format(port), "localhost:{}".format(port))

    def _send(self, status, body=b"", content_type="application/json", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, payload, headers=None):
        self._send(status, json.dumps(payload, separators=(",", ":")).encode("utf-8"), headers=headers)

    def _error(self, status, code, message=None):
        self._json(status, {"error": code, "message": message or code.replace("_", " ")})

    def _denied(self, headers=None):
        self._json(403, DENIED, headers=headers)

    # -- credential ---------------------------------------------------------
    def _credential(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE:
                sid, _, token = value.partition(".")
                return sid, token
        return None, None

    def _cookie(self, sid, token):
        return "{}={}.{}; HttpOnly; SameSite=Strict; Path=/api".format(COOKIE, sid, token)

    def _expired_cookie(self):
        return "{}=; HttpOnly; SameSite=Strict; Path=/api; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT".format(COOKIE)

    def _analysis(self):
        """Authorize through the I4D token; returns (sid, token, analysis) or raises SessionError."""
        sid, token = self._credential()
        # Any authorized call validates the token (and refreshes idle time) in the session service.
        self.app.service.list_artifacts(sid, token)
        with self.app.lock:
            analysis = self.app.analyses.get(sid)
        return sid, token, analysis

    # -- dispatch -----------------------------------------------------------
    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._error(405, "method_not_allowed")

    do_DELETE = do_PATCH = do_PUT

    def _dispatch(self, method):
        try:
            if not self._host_ok():
                return self._error(421, "bad_host", "unexpected Host header")
            parts = urlsplit(self.path)
            path, query = parts.path, parse_qs(parts.query, keep_blank_values=True)
            if method == "POST":
                origin = self.headers.get("Origin")
                if origin is not None and origin != self._origin():
                    return self._error(403, "bad_origin")
                if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
                    return self._error(415, "unsupported_media_type")
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY or length < 0:
                    return self._error(413, "body_too_large")
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else {}
                except (UnicodeDecodeError, ValueError):
                    return self._error(400, "invalid_json")
                if not isinstance(body, dict):
                    return self._error(400, "invalid_json")
                return self._post(path, body)
            if path.startswith("/api/"):
                return self._get_api(path, query)
            return self._static(path)
        except SessionError as exc:
            if exc.code == "access_denied":
                return self._denied()
            status = {"analysis_active": 409, "stale_generation": 409, "no_active_analysis": 409,
                      "artifact_not_found": 404, "invalid_name": 400}.get(exc.code, 500)
            return self._error(status, exc.code, exc.message)
        except ViewError as exc:
            return self._error(400 if exc.code == "invalid_request" else 404 if exc.code == "not_found" else 500,
                               exc.code, exc.message)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            return self._error(500, "internal_error")

    # -- POST ---------------------------------------------------------------
    def _post(self, path, body):
        if path == "/api/session":
            old_sid, old_token = self._credential()
            with self.app.assistant_lifecycle_lock:
                if old_sid:  # a new session replaces whatever this browser still holds
                    self._note_job_cancel(old_sid, "session_ended")
                    try:
                        self.app.service.end_session(old_sid, old_token)
                        self.app.assistant.clear(old_sid)
                    except SessionError:
                        pass
                    with self.app.lock:
                        self.app.analyses.pop(old_sid, None)
                    self.app.sweep_quarantine()
                handle = self.app.service.create_session()
            return self._json(201, {"status": "active", "generation": handle.generation},
                              headers={"Set-Cookie": self._cookie(handle.session_id, handle.token)})
        if path == "/api/intake/preview":
            return self._preview(body)
        if path == "/api/analysis/demo":
            return self._demo(body)
        if path == "/api/analysis/live":
            return self._live(body)
        if path == "/api/scan":
            return self._scan_start(body)
        if path == "/api/analysis/cancel":
            sid, token = self._credential()
            with self.app.assistant_lifecycle_lock:
                self.app.service.list_artifacts(sid, token)  # authorize before clearing session-owned assistant state
                self.app.assistant.clear(sid)
                self._note_job_cancel(sid, "user")
                state = self.app.service.cancel_analysis(sid, token)
                with self.app.lock:
                    self.app.analyses.pop(sid, None)
            return self._json(200, {"state": state})
        if path == "/api/session/end":
            sid, token = self._credential()
            with self.app.assistant_lifecycle_lock:
                self._note_job_cancel(sid, "session_ended")
                state = self.app.service.end_session(sid, token)
                self.app.assistant.clear(sid)
                with self.app.lock:
                    self.app.analyses.pop(sid, None)
                self.app.sweep_quarantine()
            return self._json(200 if state == "deleted_verified" else 500, {"state": state},
                              headers={"Set-Cookie": self._expired_cookie()})
        if path == "/api/assistant/ask":
            return self._assistant_ask(body)
        if path == "/api/assistant/cancel":
            sid, _, _ = self._analysis()
            with self.app.assistant_lifecycle_lock:
                return self._json(200, {"cancel_requested": self.app.assistant.cancel(sid)})
        return self._error(404, "not_found")

    def _assistant_ask(self, body):
        allowed = {"question", "generation", "adopt_subject", "subject"}
        if set(body) != allowed or type(body.get("generation")) is not int or type(body.get("adopt_subject")) is not bool:
            return self._error(400, "invalid_request")
        question = body.get("question")
        if not isinstance(question, str) or not question.strip():
            return self._error(400, "question_required")
        try:
            question_size = len(question.encode("utf-8"))
        except UnicodeEncodeError:
            return self._error(400, "invalid_question")
        if question_size > 4_000:
            return self._error(413, "question_too_large")
        sid, token, analysis = self._analysis()
        if (analysis is None or analysis.state != "complete"
                or body["generation"] != analysis.ticket.generation):
            return self._error(409, "stale_generation" if analysis else "no_analysis")
        if not self.app._assistant_context_current(sid, token, analysis):
            return self._error(409, "stale_generation")
        manager = self.app.assistant
        from .assistant.resolver import _binding_digest
        from .workbench_binding import build_binding
        current_binding = dict(build_binding(analysis), session_id=sid)
        binding_digest = _binding_digest(current_binding)
        existing = manager.current_context(sid, binding_digest=binding_digest,
                                           generation=analysis.ticket.generation)
        # Conversation binding digest includes session identity; resolve a context
        # only for an initial whole-analysis turn or an explicit subject adoption.
        candidate = None
        state = None
        try:
            if body["adopt_subject"]:
                candidate, state = self._assistant_resolve_context(analysis, body.get("subject"))
            elif body.get("subject") is not None:
                return self._error(400, "subject_requires_explicit_adoption", ASSISTANT_PLAIN_ERRORS["subject_requires_explicit_adoption"])
            elif existing is None:
                candidate, state = self._assistant_resolve_context(analysis, {"kind": "analysis", "id": None})
            with self.app.assistant_lifecycle_lock:
                if not self.app._assistant_context_current(sid, token, analysis):
                    return self._error(409, "stale_generation")
                # Re-read after acquiring the transition lock. A thread cleared
                # or adopted while resolution ran must not be silently reused.
                existing = manager.current_context(sid, binding_digest=binding_digest,
                                                   generation=analysis.ticket.generation)
                if candidate is None and existing is None:
                    return self._error(409, "stale_generation")
                ticket = manager.begin(session_id=sid, generation=analysis.ticket.generation,
                                       binding_digest=(candidate.binding_digest if candidate else existing.binding_digest),
                                       question=question, context=candidate,
                                       adopt_context=body["adopt_subject"] or existing is None)
            history = manager.completed_history(ticket)
            if needs_item(question, ticket.context.subject, bool(history)):
                # No item is attached and the question points at "this/it": ask which item, without a model call (no provider request, no spend).
                manager.fail(ticket)
                return self._json(200, {"clarify": CLARIFY_TEXT, "context_id": None, "subject": None})
            request = make_generation_request(ticket, history)
            if self.app.assistant_broker is None:
                manager.fail(ticket)
                return self._error(503, "assistant_provider_unavailable", "the assistant provider is not configured")
            result = self.app.assistant_broker.generate(request)
            if result.status != "complete" or result.content is None:
                manager.fail(ticket)
                return self._error(502, "assistant_" + result.status, "the assistant provider did not return a complete answer")
            fallback_used = False
            try:
                answer = validate_generated_answer(result.content, ticket)
            except ConversationError as exc:
                answer = fallback_answer(ticket, follow_up=bool(history) and not ticket.context_was_new) if exc.code in FALLBACK_CODES else None
                if answer is None:
                    raise
                fallback_used = True
            with self.app.assistant_lifecycle_lock:
                turn = self.app.finish_assistant_turn(sid, token, analysis, ticket, answer)
                citations = [{"evidence_id": item.evidence_id, "source": item.source, "kind": item.kind,
                              "label": item.label, "state": item.state}
                             for item in ticket.context.evidence]
                return self._json(200, {"context_id": turn.context_id, "turn_id": turn.turn_id,
                                        "answer": answer, "citations": citations,
                                        "subject": ({key: ticket.context.subject[key] for key in ("kind", "id", "label")}
                                                    if ticket.context.subject else None),
                                        "source_states": {key: dict(value) for key, value in ticket.context.sources.items()},
                                        "limitations": list(ticket.context.limitations) + list(ticket.request_state.get("notes", [])),
                                        "provider": ({"profile": "opentrace", "model": "recorded-fields", "validation_level": "deterministic_fallback"} if fallback_used else
                                                     {"profile": result.profile or "unknown", "model": result.model,
                                                      "validation_level": result.validation_level or "unknown"}),
                                        "fallback": fallback_used})
        except ConversationError as exc:
            if "ticket" in locals():
                manager.fail(ticket)
            status = 429 if exc.code in {"answer_in_flight", "assistant_busy"} else 409 if "stale" in exc.code or "cancel" in exc.code else 400
            return self._error(status, exc.code, ASSISTANT_PLAIN_ERRORS.get(exc.code))
        except (ProviderError, ValueError) as exc:
            if "ticket" in locals():
                manager.fail(ticket)
            code = exc.code if isinstance(exc, ProviderError) else "assistant_request_invalid"
            return self._error(502 if isinstance(exc, ProviderError) else 400, code, ASSISTANT_PLAIN_ERRORS.get(code))
        except Exception:
            if "ticket" in locals():
                manager.fail(ticket)
            return self._error(500, "assistant_request_failed")

    def _assistant_resolve_context(self, analysis, requested_subject):
        from .assistant.resolver import _binding_digest
        from .workbench_binding import build_binding
        if not isinstance(requested_subject, dict) or set(requested_subject) != {"kind", "id"}:
            raise ConversationError("subject_required")
        kind, subject_id = requested_subject["kind"], requested_subject["id"]
        if kind == "analysis":
            if subject_id is not None:
                raise ConversationError("subject_invalid")
            label = analysis.identity["repository"]["canonical_url"] + " @ " + analysis.identity["resolved"]["commit_sha"]
            subject = {"kind": kind, "id": None, "label": label}
        else:
            allowed = {"dependency": "dependencies", "advisory": "advisories", "crypto": "crypto",
                       "model": "model_observations", "bom": "bom", "relationship": "relationships",
                       "context": "repository"}
            source = allowed.get(kind)
            if source is None or not isinstance(subject_id, str) or not subject_id or len(subject_id.encode("utf-8")) > 256:
                raise ConversationError("subject_invalid")
            subject = {"kind": kind, "id": subject_id, "label": "pending"}
        binding = dict(build_binding(analysis), session_id=analysis.ticket.session_id)
        context_id = __import__("uuid").uuid4().hex
        binding_digest = _binding_digest(binding)
        if kind != "analysis":
            context = resolve_active_analysis(analysis, context_id=context_id,
                                              subject=dict(subject, binding_digest=binding_digest))
            matched = [item for item in context.evidence if item.source == source and
                       (item.locator.endswith(":" + subject_id) or item.locator.endswith("/" + subject_id)
                        or item.evidence_id == subject_id)]
            if not matched:
                raise ConversationError("subject_not_in_resolved_evidence")
            subject["label"] = matched[0].label
        else:
            subject["label"] = label
        context = resolve_active_analysis(analysis, context_id=context_id,
                                          subject=dict(subject, binding_digest=binding_digest))
        return context, context.sources

    def _preview(self, body):
        url = body.get("url")
        advanced = body.get("advanced") is True
        manual = body.get("manual_sha") if advanced else None  # hidden Advanced input never applies
        live = self.app.live if body.get("live") is True else None
        demo = self.app.demo
        try:
            parsed = parse_repository_url(url if isinstance(url, str) else "")
            sha = parse_manual_sha(manual)
            transport, record = (_recording(live.transport, parsed) if live else (demo.transport(), {}))
            res = resolve(parsed, sha, transport, now=utc_now)
        except IntakeError as exc:
            return self._json(200, {"ok": False, "code": exc.code, "field": exc.field, "message": exc.message})
        out = {
            "ok": True, "repository": res.canonical_url, "requested": res.requested, "commit": res.commit_sha,
            "basis": res.basis, "resolved_at": res.resolved_at, "default_branch": res.default_branch,
            "manual_corroboration": res.manual_corroboration, "captured": res.commit_sha == demo.revision,
            "source": "github_api" if live else "recorded_fixture",
            "scope": {"inventories": SCAN["inventories"], "scope": SCAN["scope"]}}
        if live:
            try:
                admitted = live.check(res.owner, res.name, res.commit_sha, record.get("repo"))
                out["live"] = {"allowed": True, "policy": admitted.get("policy", live_policy.POLICY_ALLOWLIST), "scope": {"inventories": live_runner.SCAN["inventories"], "scope": live_runner.SCAN["scope"]},
                               "scanners": dict(live.scanners.pins),
                               "advisories": live.advisories.public() if live.advisories else {"enabled": False}}
            except live_policy.PolicyError as exc:
                out["live"] = {"allowed": False, "code": exc.code, "message": exc.message}
        return self._json(200, out)

    def _demo_replay(self, parsed, res, rep_cap, sid, token):
        """Open the saved live scan through the unchanged pipeline, with recorded inputs (no scanner, OSV or provider call)."""
        app = self.app
        ticket = app.begin_assistant_analysis(sid, token)
        producer = _AnalysisProducer(ticket)
        return self._json(200, _run_live_pipeline(app, sid, token, ticket, producer, parsed, res, replay=rep_cap))

    def _demo(self, body):
        app, demo = self.app, self.app.demo
        sid, token = self._credential()
        rep_cap = app.replay
        url = body.get("url") if isinstance(body.get("url"), str) else (rep_cap.default_url if rep_cap is not None else DEFAULT_URL)
        try:
            parsed = parse_repository_url(url)
            tree = parsed.tree_segments
            if (rep_cap is not None and (parsed.owner, parsed.name) == (rep_cap.owner, rep_cap.name)
                    and tree and len(tree) == 1 and len(tree[0]) >= 7 and rep_cap.revision.startswith(tree[0].lower())):
                res = resolve(parsed, None, rep_cap.transport(), now=utc_now)
                return self._demo_replay(parsed, res, rep_cap, sid, token)
            res = resolve(parsed, None, demo.transport(), now=utc_now)
        except IntakeError as exc:
            return self._json(200, {"ok": False, "code": exc.code, "message": exc.message})
        if res.commit_sha != demo.revision:
            return self._error(400, "not_captured", "only the captured Frigate case can be opened offline")
        ticket = app.begin_assistant_analysis(sid, token)
        producer = _AnalysisProducer(ticket)
        try:
            app.service.register_producer(ticket, producer)
            session = {"session_id": sid, "generation": ticket.generation}
            identity = build_identity(parsed, None, res, SCAN, session)
            records = demo.artifact_records(identity["analysis_digest"], sid, ticket.generation)
            names = {r.artifact_id: demo.files[r.inventory_id] for r in records}
            analysis = _Analysis(ticket, identity, records, names)
            analysis.configuration = demo.configuration
            analysis.read = lambda aid: app.service.read_artifact(sid, token, names[aid]).data
            analysis.context = AdapterContext(
                identity, session, demo.configuration,
                lambda: dict(session) if not ticket.cancel_event.is_set() else None)
            reader = lambda aid: demo.raw[aid.removeprefix("art:")]
            bundle = demo.bundle
            assembled = assemble(analysis.context, capture=bundle["capture"], entities=bundle["entities"],
                                 observations=bundle["evidence"], assertions=bundle["assertions"],
                                 input_checks=bundle["input_checks"], origin=bundle["origin"],
                                 notice=bundle.get("notice"), artifacts=records, read_artifact=reader)
            for record in records:
                app.service.commit_artifact(ticket, names[record.artifact_id], demo.raw[record.inventory_id],
                                            "application/json", "original")
            outcome = assess(analysis.context, assembled, artifacts=records, read_artifact=analysis.read,
                             cancel=ticket.cancel_event)
            if outcome.status != "complete":
                app.service.finish(ticket, "failed")
                return self._json(200, {"ok": False, "code": outcome.status,
                                        "errors": [e.as_dict() for e in outcome.errors]})
            analysis.assessment = outcome.assessment
            app.service.commit_artifact(ticket, "bombridge-result.json",
                                        pipeline.canonical(outcome.assessment.result).encode("utf-8"),
                                        "application/json", "derived")
            analysis.gaps = self._discover_gaps(analysis, ticket, demo, records, bundle)
            if analysis.gaps["status"] == "cancelled":
                app.service.finish(ticket, "failed")
                return self._json(200, {"ok": False, "code": "cancelled"})
            analysis.views = Views(demo, analysis)
            analysis.summary = analysis.views.summary()
            analysis.summary["gaps"] = analysis.views.gaps_summary()
            for card in analysis.summary["cards"]:
                card["artifact_name"] = names.get(card["artifact_id"])
            with app.lock:
                app.analyses[sid] = analysis
            app.service.finish(ticket, "complete")
            analysis.state = "complete"
        except SessionError as exc:
            # Cancelled, ended or superseded while running: nothing is published.
            producer.running = False
            return self._json(200, {"ok": False, "code": "cancelled" if exc.code == "stale_generation" else exc.code})
        finally:
            producer.running = False
        return self._json(200, self._analysis_payload(analysis))

    def _discover_gaps(self, analysis, ticket, demo, records, bundle):
        """Candidate gaps for the recorded case (I8): discovery over captured inputs, assessed by the unchanged engine in the same
        isolated worker. Nothing is collected here. Any missing or mismatched input is a labeled ``not_compared`` state with its
        reason, never an empty or contradicting result. Runs before the analysis is published, so a cancel or End session that
        arrives meanwhile leaves no discovery output behind (``cancelled``)."""
        inv_id = "inv:syft-source-dir"

        def not_compared(code, detail):
            return {"status": "not_compared", "code": code, "detail": detail}
        try:
            inv = next(i for i in bundle["capture"]["inventories"] if i["inventory_id"] == inv_id)
            declarations, read_copy = demo.discovery_inputs()
            sd, texts = bb_discovery.read_declarations(bundle, declarations, expected_sha256=demo.declarations_sha256, read_copy=read_copy)
            raw = analysis.read("art:" + inv_id)  # the session's original bytes; the adapter already verified their digest
            if hashlib.sha256(raw).hexdigest() != inv.get("source_sha256"):
                raise bb_discovery.InputError("inventory_digest_mismatch", "the SBOM bytes do not match the captured inventory digest")
            found = bb_discovery.discover(bundle, raw_inventories={inv_id: {"doc": json.loads(raw.decode("utf-8")), "sha256": inv["source_sha256"]}},
                                          source_declarations=sd, requirement_texts=texts)
        except bb_discovery.InputError as exc:
            return not_compared(exc.code, exc.detail)
        except (OSError, KeyError, StopIteration, ValueError):
            return not_compared("inputs_unavailable", "a captured discovery input could not be read")
        if ticket.cancel_event.is_set():
            return {"status": "cancelled"}
        try:
            assembled = assemble(analysis.context, capture=found["capture"], entities=found["entities"], observations=found["evidence"],
                                 assertions=found["assertions"], input_checks=found["input_checks"], origin=found["origin"],
                                 notice=found.get("notice"), artifacts=records, read_artifact=analysis.read, discovery=found["discovery"])
        except AdapterError as exc:
            return not_compared("discovery_payload_invalid", exc.errors[0].code + ": " + exc.errors[0].detail)
        outcome = assess(analysis.context, assembled, artifacts=records, read_artifact=analysis.read, cancel=ticket.cancel_event)
        if outcome.status == "cancelled" or ticket.cancel_event.is_set():
            return {"status": "cancelled"}
        if outcome.status != "complete":
            return not_compared("discovery_assessment_" + outcome.status, outcome.errors[0].code + ": " + outcome.errors[0].detail if outcome.errors else outcome.status)
        return {"status": "compared", "assessment": outcome.assessment}

    # -- UIP-03: one-click scan job ----------------------------------------
    def _note_job_cancel(self, sid, reason):
        """Record why an unfinished job is being stopped (first reason wins); the stop itself is the existing producer path."""
        with self.app.lock:
            job = self.app.scan_jobs.get(sid)
        if job is not None and not job.terminal and job.cancel_reason is None:
            job.cancel_reason = reason

    def _scan_response(self, success_status, job):
        """Build, validate and send the ``scan_job_response/1`` envelope; a contract failure is a typed error, never a partial body.

        The contract modules read ``contracts/workbench/v1`` at import, so they are imported here (not at module import): the service
        itself and the protected-output tools that load this module from a minimal copy do not depend on that directory.
        """
        from . import scan_contract, view_contracts
        status = job.status_document()
        result = job.result if status["job"]["state"] in scan_jobs.READY_STATES and status["handoff"]["ready"] else None
        try:
            envelope = scan_contract.build(status, result, request={"generation": job.generation, "job_id": job.job_id})
        except view_contracts.ContractError as exc:
            return self._json(exc.status, exc.body())
        return self._json(success_status, envelope)

    def _scan_start(self, body):
        app = self.app
        sid, token = self._credential()
        current = app.service.current_generation(sid, token)                     # authenticates (403 on failure)
        generation = body.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int):
            return self._error(400, "invalid_request", "generation must be an integer")
        if generation != current:                                               # stale: rejected before any ownership changes
            return self._error(409, "stale_generation", "the session has moved on; start again")
        if app.live is None:
            return self._json(200, {"ok": False, "code": "live_disabled", "message": "live scanning is not enabled on this service"})
        url = body.get("url") if isinstance(body.get("url"), str) else ""
        advanced = body.get("advanced") is True
        try:
            parsed = parse_repository_url(url)
            manual = parse_manual_sha(body.get("manual_sha") if advanced else None)
        except IntakeError as exc:
            return self._json(200, {"ok": False, "code": exc.code, "field": exc.field, "message": exc.message})
        refusal = {"ok": False}
        job = ticket = producer = None
        launch = _Launch()
        with app.assistant_lifecycle_lock, app.lock:                            # atomic reservation and assistant context retirement
            held = app.scan_jobs.get(sid)
            if held is not None and (not held.terminal or held.quarantined):
                return self._json(200, dict(refusal, code="scan_in_progress", message="this session already has a scan in progress"))
            if not app.live_gate.acquire(blocking=False):
                return self._json(200, dict(refusal, code="scanner_busy", message="another scan is running or still being cleaned up; try again when it finishes"))
            try:
                # The job thread is started FIRST, parked until the reservation is complete. If it cannot start, no session state has
                # been touched yet: the generation, the analysis record and the earlier artifacts are exactly as they were (UIP-03-IR-04).
                thread = app.scan_thread_factory(target=_scan_job_entry, args=(app, launch), daemon=True)
                thread.start()
            except Exception:
                app.live_gate.release()
                return self._json(200, dict(refusal, code="scan_unavailable", message="the scan could not be started; nothing was changed"))
            if not launch.claim():
                # The parked worker already expired: no reservation exists yet, so refuse before touching any session state.
                app.live_gate.release()
                return self._json(200, dict(refusal, code="scan_unavailable", message="the scan could not be started; nothing was changed"))
            try:
                try:
                    # The generation precondition is checked under the session lock that advances the generation (UIP-03-IR-02).
                    ticket = app.begin_assistant_analysis(sid, token, expected_generation=generation)
                except SessionError as exc:
                    app.live_gate.release()
                    ticket = None
                    if exc.code == "analysis_active":
                        return self._json(200, dict(refusal, code="scan_in_progress", message="this session already has an analysis running"))
                    raise
                producer = _AnalysisProducer(ticket)
                app.service.register_producer(ticket, producer)
                job = scan_jobs.ScanJob(sid, ticket.generation, url=url, clock=app.scan_clock,
                                        advisory_configured=app.live.advisories is not None,
                                        aibom_configured=getattr(app.live, "aibom", None) is not None)
                job.token, job.ticket, job.gate_held = token, ticket, True
                job.thread = thread
                app.scan_jobs[sid] = job
                launch.args = (job, ticket, producer, parsed, manual)
            except Exception as exc:
                if ticket is not None:
                    # The session already advanced (a published generation is never reused or decremented): finish what was begun, as a unit.
                    producer and setattr(producer, "running", False)
                    with contextlib.suppress(Exception):
                        app.service.finish(ticket, "failed")
                    if job is not None and app.scan_jobs.get(sid) is job:
                        app.scan_jobs.pop(sid, None)
                    if job is not None:
                        job.gate_held = False
                    app.live_gate.release()
                if isinstance(exc, SessionError):
                    raise
                return self._json(200, dict(refusal, code="scan_unavailable", message="the scan could not be started; the session was already advancing, so start again"))
            finally:
                launch.go.set()                                                 # the parked thread runs the job, or exits (args is None)
        return self._scan_response(202, job)

    def _contexts_v1(self, query):
        """UIP-04: ``opentrace.workbench.contexts/1`` (grouped repository contexts). Typed errors only; legacy views are untouched.

        Imported here for the same reason as ``_scan_response``: the contract modules read ``contracts/workbench/v1`` at import.
        """
        from . import context_groups, view_contracts
        _, _, analysis = self._analysis()                                       # authenticates (403 on failure)
        try:
            if analysis is None or analysis.state != "complete":
                raise view_contracts.ContractError("no_analysis", "no_active_analysis", "", "no completed analysis in this session")
            try:
                payload = context_groups.respond(analysis, query)
            except view_contracts.ContractError as exc:
                if exc.code == "stale_generation":
                    return self._json(exc.status, exc.body(analysis.ticket.generation))
                raise
            return self._send(200, context_groups.encode_response(payload))
        except view_contracts.ContractError as exc:
            return self._json(exc.status, exc.body())

    def _dependency_route(self, query, handler):
        """UIP-05: ``dependency_page/1`` and ``dependency_contexts/1``. Typed errors only; legacy views are untouched."""
        from . import dependency_pages, view_contracts
        _, _, analysis = self._analysis()                                       # authenticates (403 on failure)
        try:
            if analysis is None or analysis.state != "complete":
                raise view_contracts.ContractError("no_analysis", "no_active_analysis", "", "no completed analysis in this session")
            try:
                payload = getattr(dependency_pages, handler)(analysis, query)
            except view_contracts.ContractError as exc:
                if exc.code == "stale_generation":
                    return self._json(exc.status, exc.body(analysis.ticket.generation))
                raise
            return self._send(200, dependency_pages.encode_response(payload))
        except view_contracts.ContractError as exc:
            return self._json(exc.status, exc.body())

    def _crypto_assets_v1(self, query):
        """UIP-06: ``opentrace.workbench.crypto_assets/1``. Typed errors only; the legacy crypto family view is untouched."""
        from . import crypto_assets, view_contracts
        _, _, analysis = self._analysis()                                       # authenticates (403 on failure)
        try:
            if analysis is None or analysis.state != "complete":
                raise view_contracts.ContractError("no_analysis", "no_active_analysis", "", "no completed analysis in this session")
            try:
                payload = crypto_assets.respond(analysis, query)
            except view_contracts.ContractError as exc:
                if exc.code == "stale_generation":
                    return self._json(exc.status, exc.body(analysis.ticket.generation))
                raise
            return self._send(200, crypto_assets.encode_response(payload))
        except view_contracts.ContractError as exc:
            return self._json(exc.status, exc.body())

    def _ai_assets_v1(self, query):
        """UIP-07: ``opentrace.workbench.ai_assets/1``. Typed errors only; the legacy AI family view is untouched."""
        from . import ai_assets, view_contracts
        _, _, analysis = self._analysis()                                       # authenticates (403 on failure)
        try:
            if analysis is None or analysis.state != "complete":
                raise view_contracts.ContractError("no_analysis", "no_active_analysis", "", "no completed analysis in this session")
            try:
                payload = ai_assets.respond(analysis, query)
            except view_contracts.ContractError as exc:
                if exc.code == "stale_generation":
                    return self._json(exc.status, exc.body(analysis.ticket.generation))
                raise
            return self._send(200, ai_assets.encode_response(payload))
        except view_contracts.ContractError as exc:
            return self._json(exc.status, exc.body())

    def _bom_v1(self, query, route_key):
        """UIP-08: read-only, validated BOM v1 projections of the bound assessment.

        The contract import stays local for minimal protected-output service copies.
        Legacy routes are untouched.
        """
        from . import view_contracts as vc
        from .workbench_binding import build_binding

        sid, token, analysis = self._analysis()  # uniform authentication first
        try:
            request = vc.validate_request(route_key, query)
            if analysis is None or analysis.state != "complete":
                raise vc.ContractError("no_analysis", "no_active_analysis", "", "no completed analysis in this session")
            generation = self.app.service.current_generation(sid, token)
            if request["generation"] != generation or analysis.ticket.generation != generation:
                raise vc.ContractError("stale_generation", "invariant:generation", "generation", "the session has moved on")
            params = {k: v for k, v in request.items() if k not in ("generation", "schema_version", "size")}
            try:
                payload = getattr(analysis.views, route_key)(**params)
            except ViewError as exc:
                code = exc.code if exc.code in ("invalid_request", "not_found", "binding_mismatch") else "projection_failed"
                raise vc.ContractError(code, exc.code, "", exc.message) from exc
            vc.validate_payload(route_key, payload, request=request, expected_binding=build_binding(analysis))
            if self.app.service.current_generation(sid, token) != generation:
                raise vc.ContractError("stale_generation", "invariant:generation", "generation", "the session has moved on")
            with self.app.lock:
                if self.app.analyses.get(sid) is not analysis:
                    raise vc.ContractError("stale_generation", "invariant:analysis", "", "the session has moved on")
            return self._send(200, vc.canonical_bytes(payload), "application/json; charset=utf-8")
        except vc.ContractError as exc:
            return self._json(exc.status, exc.body(analysis.ticket.generation if analysis and exc.code == "stale_generation" else None))

    def _scan_status(self, query):
        app = self.app
        sid, token = self._credential()
        current = app.service.current_generation(sid, token)                    # authenticate (403) like every authorized read
        job_id = (query.get("job") or [""])[0]
        raw_generation = (query.get("generation") or [""])[0]
        with app.lock:
            job = app.scan_jobs.get(sid)
            registered = app.analyses.get(sid)
        if not re.fullmatch(r"job:[0-9a-f]{24}", job_id) or job is None or job.job_id != job_id:
            return self._error(404, "job_not_found", "no such scan job")
        if not re.fullmatch(r"[0-9]{1,9}", raw_generation) or int(raw_generation) != job.generation:
            return self._error(409, "stale_generation", "the scan belongs to another generation")
        # A hand-off result is served only while it is still the session's current analysis. Once another analysis (a Demo, another
        # scan, a legacy route) owns the session the successful result is retired. Failed and cancelled statuses carry no result, so
        # they stay observable even though cancelling advanced the generation (UIP-03-IR-02).
        if job.state() in scan_jobs.READY_STATES and (job.analysis is None or registered is not job.analysis or current != job.generation):
            job.retire()
            return self._error(409, "stale_generation", "the session has moved on; this scan result is no longer current")
        return self._scan_response(200, job)

    def _live(self, body):
        app = self.app
        if app.live is None:
            return self._error(403, "live_disabled", "live scanning is not enabled on this service")
        # One live scan at a time per service: the scanner worker runs one job, and the GitHub intake is rate limited.
        if not app.live_gate.acquire(blocking=False):
            return self._json(200, {"ok": False, "code": "scanner_busy", "message": "another live scan is running; try again when it finishes"})
        try:
            return self._live_run(body)
        finally:
            app.live_gate.release()

    def _live_run(self, body):
        app = self.app
        sid, token = self._credential()
        live = app.live
        ok, reason = live.isolation.available()
        url = body.get("url") if isinstance(body.get("url"), str) else ""
        try:
            parsed = parse_repository_url(url)
            transport, record = _recording(live.transport, parsed)
            res = resolve(parsed, None, transport, now=utc_now)
            live.check(res.owner, res.name, res.commit_sha, record.get("repo"))
        except IntakeError as exc:
            return self._json(200, {"ok": False, "code": exc.code, "message": exc.message})
        except live_policy.PolicyError as exc:
            return self._json(200, {"ok": False, "code": exc.code, "message": exc.message})
        if not ok:
            return self._json(200, {"ok": False, "code": "isolation_unavailable",
                                    "message": "no isolation boundary is available, so nothing was scanned: " + reason})
        ticket = app.begin_assistant_analysis(sid, token)
        producer = _AnalysisProducer(ticket)
        return self._json(200, _run_live_pipeline(app, sid, token, ticket, producer, parsed, res))

    @staticmethod
    def _advisory_lookup(cfg, inventory, sbom_bytes, ticket):
        """OSV lookup of the lockfile inventory, joined to the SBOM. Returns ``(Lookup | None, report)``."""
        error = None
        if inventory is None or inventory.status == "unavailable":
            error = (inventory.reason if inventory is not None else "") or "inventory_unavailable"
            lookup = None
        else:
            kw = {"sleep": cfg.sleep} if cfg.sleep else {}
            lookup = advisory_osv.run(inventory.rows, cfg.transport, cancel=ticket.cancel_event, **kw)
        return lookup, advisory_join.build(json.loads(sbom_bytes.decode("utf-8")), inventory, lookup, lookup_error=error)

    def _analysis_payload(self, analysis):
        return _analysis_payload(analysis)

    # -- GET API ------------------------------------------------------------
    def _get_api(self, path, query):
        q = lambda name, default=None: (query.get(name) or [default])[0]
        if path == "/api/assistant/citation":
            sid, token, analysis = self._analysis()
            if analysis is None or analysis.state != "complete":
                return self._error(409, "no_analysis")
            with self.app.assistant_lifecycle_lock:
                if not self.app._assistant_context_current(sid, token, analysis):
                    return self._error(409, "stale_generation")
                try:
                    item = self.app.assistant.citation(sid, q("context_id", ""), q("evidence_id", ""))
                except ConversationError as exc:
                    return self._error(404, exc.code)
                return self._json(200, {"evidence_id": item.evidence_id, "source": item.source,
                                        "kind": item.kind, "state": item.state, "label": item.label,
                                        "excerpt": item.excerpt})
        if path == "/api/config":
            return self._json(200, {"live": self.app.live.public() if self.app.live else {"enabled": False}})
        if path == "/api/scan/status":
            return self._scan_status(query)
        if path == "/api/workbench/v1/contexts":
            return self._contexts_v1(query)
        if path == "/api/workbench/v1/dependencies":
            return self._dependency_route(query, "respond")
        if path == "/api/workbench/v1/dependency-contexts":
            return self._dependency_route(query, "respond_contexts")
        if path == "/api/workbench/v1/crypto-assets":
            return self._crypto_assets_v1(query)
        if path == "/api/workbench/v1/ai-assets":
            return self._ai_assets_v1(query)
        if path == "/api/workbench/v1/bom-candidates":
            return self._bom_v1(query, "bom_candidates")
        if path == "/api/workbench/v1/bom-graph":
            return self._bom_v1(query, "bom_graph")
        if path == "/api/workbench/v1/bom-related-checks":
            return self._bom_v1(query, "bom_related_checks")
        if path == "/api/artifacts":
            sid, token = self._credential()
            records = self.app.service.list_artifacts(sid, token)
            with self.app.lock:
                analysis = self.app.analyses.get(sid)
            return self._json(200, {"generation": analysis.ticket.generation if analysis else None,
                                    "artifacts": [{"name": r.name, "kind": r.kind, "media_type": r.media_type,
                                                   "size": r.size, "sha256": r.sha256} for r in records]})
        if path.startswith("/api/artifacts/"):
            from urllib.parse import unquote
            name = unquote(path[len("/api/artifacts/"):])
            sid, token = self._credential()
            if not _NAME.fullmatch(name):
                self.app.service.list_artifacts(sid, token)
                return self._error(404, "artifact_not_found")
            art = self.app.service.read_artifact(sid, token, name)
            disp = "attachment" if q("disposition", "inline") == "attachment" else "inline"
            return self._send(200, art.data, art.record.media_type, {
                "X-Artifact-Sha256": art.record.sha256, "X-Artifact-Kind": art.record.kind,
                "Content-Disposition": '{}; filename="{}"'.format(disp, art.record.name)})
        if path in ("/api/view/advisory-lookup", "/api/view/advisory-evidence"):
            _, _, analysis = self._analysis()
            if analysis is None or analysis.state != "complete":
                return self._error(409, "no_analysis")
            gen = q("generation")
            if gen is not None and gen != str(analysis.ticket.generation):
                return self._error(409, "stale_generation")
            try:
                if path.endswith("lookup"):
                    return self._json(200, analysis.views.advisory_lookup(q("state"), q("q", ""), int(q("page", "0"))))
                return self._json(200, analysis.views.advisory_evidence(q("id", "")))
            except ValueError:
                return self._error(400, "invalid_request")
            except ViewError as exc:
                return self._error(404 if exc.code == "not_found" else 400, exc.code, exc.message)
        if path in ("/api/view/gaps", "/api/view/gap"):
            _, _, analysis = self._analysis()
            if analysis is None or analysis.state != "complete":
                return self._error(409, "no_analysis")
            gen = q("generation")
            if gen is not None and gen != str(analysis.ticket.generation):
                return self._error(409, "stale_generation")
            try:
                if path.endswith("gaps"):
                    data = analysis.views.gaps(int(q("offset", "0")), q("category"), q("state"), (q("q") or "").strip()[:80])
                else:
                    data = analysis.views.gap(q("id", ""))
            except ValueError:
                return self._error(400, "invalid_request")
            data["generation"] = analysis.ticket.generation
            return self._json(200, data)
        if path.startswith("/api/view/advisory/"):
            _, _, analysis = self._analysis()
            if analysis is None:
                return self._error(409, "no_analysis")
            from urllib.parse import unquote
            return self._json(200, analysis.views.advisory(unquote(path[len("/api/view/advisory/"):])))
        if path == "/api/view/dependencies/network":
            _, _, analysis = self._analysis()
            if analysis is None or analysis.state != "complete":
                return self._error(409, "no_analysis")
            gen = q("generation")
            if gen is not None and gen != str(analysis.ticket.generation):
                return self._error(409, "stale_generation")
            data = analysis.views.network(q("context") or None)
            data["generation"] = analysis.ticket.generation
            return self._json(200, data)
        if path.startswith("/api/view/"):
            tab = path[len("/api/view/"):]
            _, _, analysis = self._analysis()
            if analysis is None or analysis.state != "complete":
                return self._error(409, "no_analysis")
            gen = q("generation")
            if gen is not None and gen != str(analysis.ticket.generation):
                return self._error(409, "stale_generation")
            views = analysis.views
            if tab == "contexts":
                data = views.contexts(q("selected"))
            elif tab == "dependencies":
                try:
                    per = int(q("per_side", "6"))
                    in_off, out_off, adv_page = int(q("in_offset", "0")), int(q("out_offset", "0")), int(q("adv_page", "0"))
                    list_off = int(q("list_offset", "0"))
                except ValueError:
                    raise ViewError("invalid_request", "numeric parameter expected")
                if per not in (1, 6) or in_off < 0 or out_off < 0 or list_off < 0:
                    raise ViewError("invalid_request", "bad paging")
                data = views.dependencies(q("context") or None, q("selected") or None, per, in_off, out_off,
                                          (q("q") or "").strip()[:80], (q("adv_q") or "").strip()[:80], adv_page,
                                          q("inspect") or None, q("list") == "1", (q("list_q") or "").strip()[:80], list_off)
            elif tab in ("crypto", "ai", "bom"):
                data = views.family(tab, q("selected") or None)
                if tab == "ai":
                    from . import legacy_ai_presentation        # UIP-07C A5: presentation only; unchanged for the Demo and non-Cisco inventories
                    data = legacy_ai_presentation.present(data, analysis)
            else:
                return self._error(404, "not_found")
            data["generation"] = analysis.ticket.generation
            return self._json(200, data)
        return self._error(404, "not_found")

    # -- static -------------------------------------------------------------
    def _static(self, path):
        if path in ("/", "/index.html"):
            rel = "index.html"
        elif path.startswith("/static/"):
            rel = path[len("/static/"):]
        else:
            return self._error(404, "not_found")
        full = os.path.realpath(os.path.join(UI_ROOT, rel))
        if not full.startswith(UI_ROOT + os.sep) or not os.path.isfile(full):
            return self._error(404, "not_found")
        with open(full, "rb") as handle:
            data = handle.read()
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if full.endswith(".js") or full.endswith(".mjs"):
            ctype = "text/javascript; charset=utf-8"
        elif ctype.startswith("text/") or ctype in ("application/json",):
            ctype += "; charset=utf-8"
        self._send(200, data, ctype)


class LoopbackServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, app):
        host, port = address
        # Outside a container the service binds to 127.0.0.1 only. Inside the Compose container it must listen on the
        # container interface; Compose publishes that port on the host's 127.0.0.1 only, and the Host-header check below
        # still accepts only 127.0.0.1:<port> / localhost:<port>.
        if host != BIND_HOST and not (host == "0.0.0.0" and os.environ.get(CONTAINER_BIND_VAR) == "1"):
            raise ValueError("the service binds to 127.0.0.1 only")
        self.app = app
        super().__init__((host, port), Handler)


def make_server(session_root, *, port=0, host=BIND_HOST, **kw):
    app = AppState(session_root, **kw)
    return LoopbackServer((host, port), app)


def records_sbom_id(records):
    return next(r.artifact_id for r in records if r.kind == "sbom")
