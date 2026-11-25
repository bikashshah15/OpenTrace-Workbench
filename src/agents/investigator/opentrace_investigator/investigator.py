"""Investigator A: capability exchange, task dispatch over HTTP, result handling.

Every result passes through the deterministic core before it can support a
conclusion. Partial results keep their unknowns; failures record no evidence.
"""
import copy
import datetime as _dt
import itertools
import json

from opentrace_core import (CONTRACT_VERSION, CONTRACT_VERSION_V2, CONTRACT_VERSION_V3, NEGOTIATED_V2, NEGOTIATED_V3, runs,
                            timeutil, validate)

from . import IMPLEMENTATION, SERVICE_ID, nlip
from .providers import OfflineScriptedPolicy
from . import transport as _transport
from .transport import ResponseTooLarge, SpecialistTimeout, SpecialistUnavailable

PEER = "evidence-specialist-b"
DEFAULT_DEADLINE_S = 30          # PD-08
MAX_WORKER_JOBS = 1              # PD-08
MAX_PRODUCED_BYTES = 256 * 1024  # PD-08
MAX_PRODUCED_BYTES_V2 = 1024 * 1024  # I2 contract section 5


class ProtocolError(Exception):
    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code, self.detail = code, detail


class Pending:
    """A dispatched task and its HTTP response, not yet delivered to core."""

    def __init__(self, run_id, task, request_msg, response, message, payload, error=None):
        self.run_id, self.task, self.request_msg = run_id, task, request_msg
        self.response, self.message, self.payload, self.error = response, message, payload, error
        self.recorded = False
        self.injected = False


class Outcome:
    def __init__(self, run_id, run_state, reason, conclusion, attachment=None, http_status=None,
                 payload_kind=None, rejection_code=None, result_status=None, payload=None):
        self.run_id, self.run_state, self.reason = run_id, run_state, reason
        self.payload = payload
        self.conclusion, self.attachment, self.http_status = conclusion, attachment, http_status
        self.payload_kind, self.rejection_code, self.result_status = payload_kind, rejection_code, result_status

    def as_dict(self):
        return {"run_id": self.run_id, "run_state": self.run_state, "reason": self.reason,
                "http_status": self.http_status, "payload_kind": self.payload_kind,
                "rejection_code": self.rejection_code, "result_status": self.result_status,
                "attachment": self.attachment.as_dict() if self.attachment else None,
                "conclusion": self.conclusion}


class Investigator:
    def __init__(self, transport, registry, trace=None, policy=None, clock=timeutil.now, id_prefix="a",
                 enable_v2=False, enable_v3=False):
        self.transport = transport
        self.registry = registry
        self.trace = trace
        self.policy = policy or OfflineScriptedPolicy()
        self.clock = clock
        self.capability = None
        # Major 2.0 is opt-in (I2). With the default the Investigator behaves exactly as in I1: it
        # sends only 1.0 messages and never a contract token.
        self.enable_v2 = enable_v2
        # Major 3.0 is opt-in as well (I3): only the I3 schedule enables it. When the peer does not list 3.0, or its
        # 3.0 reply is not valid, no 3.0 task is ever issued and the reason is kept in ``v3_unavailable``.
        self.enable_v3 = enable_v3
        self.v3_unavailable = None
        self.capability_exchanges = 0
        self.version = CONTRACT_VERSION
        self.capability_v1 = None
        self._ids = itertools.count(1)
        self._prefix = id_prefix

    def _next_id(self, kind):
        return "%s-%s-%03d" % (self._prefix, kind, next(self._ids))

    def _record(self, direction, msg, status, event, case, injected=False, headers=None, raw_body=None):
        if self.trace is None:
            return
        sender, receiver = (SERVICE_ID, PEER) if direction == "request" else (PEER, SERVICE_ID)
        if direction == "delivery":
            sender, receiver = ("test-harness" if injected else PEER), "opentrace-core"
        elif direction == "local":
            sender, receiver = SERVICE_ID, "opentrace-core"
        path = "/nlip" if direction in ("request", "response") else None
        self.trace.record(direction, sender, receiver, path, status, msg, event, headers=headers,
                          injected=injected, case=case, raw_body=raw_body)

    # -- capability exchange --------------------------------------------------
    def negotiate(self, case=None):
        self.capability_exchanges += 1
        request_id = self._next_id("cap")
        payload = {"kind": "capability_request", "schema_version": CONTRACT_VERSION, "request_id": request_id,
                   "requester": {"service_id": SERVICE_ID, "implementation": IMPLEMENTATION},
                   "contract_versions": [CONTRACT_VERSION]}
        msg = nlip.build(payload, token=request_id, summary="Capability request from investigator-a.", control=True)
        self._record("request", msg, None, {"kind": "capability_request", "request_id": request_id}, case,
                     headers={"Content-Type": "application/json"})
        response = self.transport.post(msg, timeout=_transport.CONTROL_TIMEOUT_S)
        reply = nlip.parse(response.json())
        cap = nlip.structured_payload(reply)
        report = validate.check_structure("capability_response", cap)
        ok = response.status == 200 and nlip.is_control(reply) and report.ok and \
            nlip.correlation_token(reply) == request_id and cap.get("request_id") == request_id
        self._record("response", reply, response.status,
                     {"kind": "capability_response", "accepted": ok, "issues": report.codes}, case,
                     headers=response.headers)
        if not ok:
            raise ProtocolError("capability_invalid", ",".join(report.codes) or "bad capability reply")
        if CONTRACT_VERSION not in cap["contract_versions"]:
            raise ProtocolError("unsupported_schema_version", "no common contract version")
        self.capability = self.capability_v1 = cap
        self.version = CONTRACT_VERSION
        if self.enable_v3 and CONTRACT_VERSION_V3 in cap["contract_versions"]:
            self._negotiate_v3(case)
        elif self.enable_v3:
            self.v3_unavailable = "peer does not list contract 3.0"
        if self.version == CONTRACT_VERSION and self.enable_v2 and CONTRACT_VERSION_V2 in cap["contract_versions"]:
            self._negotiate_v2(case)
        return self.capability

    def _negotiate_v2(self, case=None):
        """Step (3)-(4) of the exchange matrix: a 2.0 request with the contract token."""
        self.capability_exchanges += 1
        request_id = self._next_id("cap")
        payload = {"kind": "capability_request", "schema_version": CONTRACT_VERSION_V2, "request_id": request_id,
                   "requester": {"service_id": SERVICE_ID, "implementation": IMPLEMENTATION},
                   "contract_versions": [CONTRACT_VERSION_V2]}
        msg = nlip.build(payload, token=request_id, summary="Capability request (2.0) from investigator-a.",
                         control=True, contract_token=CONTRACT_VERSION_V2)
        self._record("request", msg, None, {"kind": "capability_request", "request_id": request_id,
                                            "schema_version": CONTRACT_VERSION_V2}, case,
                     headers={"Content-Type": "application/json"})
        response = self.transport.post(msg, timeout=_transport.CONTROL_TIMEOUT_S)
        reply = nlip.parse(response.json())
        cap = nlip.structured_payload(reply)
        report = validate.check_structure("capability_response", cap, NEGOTIATED_V2)
        ok = (response.status == 200 and nlip.is_control(reply) and report.ok
              and nlip.correlation_token(reply) == request_id and cap.get("request_id") == request_id
              and nlip.contract_tokens(reply) == [CONTRACT_VERSION_V2]
              and cap.get("schema_version") == CONTRACT_VERSION_V2 and cap.get("capability_version") == "2.0")
        self._record("response", reply, response.status,
                     {"kind": "capability_response", "accepted": ok, "issues": report.codes,
                      "schema_version": CONTRACT_VERSION_V2}, case, headers=response.headers)
        if not ok:
            raise ProtocolError("capability_invalid", ",".join(report.codes) or "bad 2.0 capability reply")
        self.capability = cap
        self.version = CONTRACT_VERSION_V2

    def _negotiate_v3(self, case=None):
        """A 3.0 request with the contract token. Anything but a valid 3.0 reply (including a 1.0
        ``unsupported_schema_version`` rejection from an older peer) means no 3.0: no 3.0 task is issued."""
        self.capability_exchanges += 1
        request_id = self._next_id("cap")
        payload = {"kind": "capability_request", "schema_version": CONTRACT_VERSION_V3, "request_id": request_id,
                   "requester": {"service_id": SERVICE_ID, "implementation": IMPLEMENTATION},
                   "contract_versions": [CONTRACT_VERSION_V3]}
        msg = nlip.build(payload, token=request_id, summary="Capability request (3.0) from investigator-a.",
                         control=True, contract_token=CONTRACT_VERSION_V3)
        self._record("request", msg, None, {"kind": "capability_request", "request_id": request_id,
                                            "schema_version": CONTRACT_VERSION_V3}, case,
                     headers={"Content-Type": "application/json"})
        response = self.transport.post(msg, timeout=_transport.CONTROL_TIMEOUT_S)
        reply = nlip.parse(response.json())
        cap = nlip.structured_payload(reply)
        report = validate.check_structure("capability_response", cap, NEGOTIATED_V3)
        ok = (response.status == 200 and nlip.is_control(reply) and report.ok
              and nlip.correlation_token(reply) == request_id and cap.get("request_id") == request_id
              and nlip.contract_tokens(reply) == [CONTRACT_VERSION_V3]
              and cap.get("schema_version") == CONTRACT_VERSION_V3 and cap.get("capability_version") == "3.0")
        self._record("response", reply, response.status,
                     {"kind": "capability_response", "accepted": ok, "issues": report.codes,
                      "schema_version": CONTRACT_VERSION_V3}, case, headers=response.headers)
        if not ok:
            code = cap.get("code") if isinstance(cap, dict) and cap.get("kind") == "rejection" else None
            self.v3_unavailable = "invalid 3.0 capability reply (%s)" % (code or ",".join(report.codes) or "not accepted")
            return
        self.capability = cap
        self.version = CONTRACT_VERSION_V3

    # -- tasks ------------------------------------------------------------------
    def start_run(self, repo_id, run_id=None):
        return self.registry.start_run(run_id or self._next_id("run"), repo_id)

    def build_task(self, run_id, context, dimensions, inputs, overrides=None, operation=None,
                   capture_set_id=None, deadline_s=None):
        now = self.clock()
        v2 = self.version in (CONTRACT_VERSION_V2, CONTRACT_VERSION_V3)
        task = {
            "kind": "task_request",
            "schema_version": self.version,
            "task_id": self._next_id("task"),
            "run_id": run_id,
            "capability_version": self.capability["capability_version"],
            "issued_at": timeutil.format_ts(now),
            "deadline": timeutil.format_ts(now + _dt.timedelta(seconds=deadline_s or DEFAULT_DEADLINE_S)),
            "context": copy.deepcopy(context),
            "requirements": self.policy.plan_requirements(dimensions),
            "operations": [operation] if operation else self.policy.choose_operations(self.capability),
            "inputs": copy.deepcopy(inputs),
            "budget": {"max_worker_jobs": MAX_WORKER_JOBS,
                       "max_produced_artifact_bytes": MAX_PRODUCED_BYTES_V2 if v2 else MAX_PRODUCED_BYTES},
        }
        if capture_set_id is not None:
            task["capture_set_id"] = capture_set_id
        task.update(overrides or {})
        return task

    def dispatch(self, run_id, task, case=None, injected=False):
        run = self.registry.runs[run_id]
        if run.state == runs.QUEUED:
            run.transition(runs.RUNNING)
        self.registry.register_task(task, run_id, self.capability)
        msg = nlip.build(task, token=run_id, summary="Task %s for run %s." % (task["task_id"], run_id),
                         contract_token=self._contract_token_for(task))
        limit = None
        try:
            deadline = timeutil.parse_ts(task["deadline"])
        except (KeyError, ValueError):
            deadline = None
        if deadline is not None:
            now = self.clock()
            if deadline <= now and not injected:
                # Ordinary dispatch of an already-expired task opens no socket (I2-REQ-01 item 2).
                # The explicitly labeled synthetic injection path (unchanged I1 R6a) still sends it,
                # so B's own HTTP-200 deadline rejection stays exercised.
                pending = Pending(run_id, task, msg, None, None, None,
                                  error=("deadline_exceeded", "task deadline had passed before dispatch"))
                pending.injected = injected
                return pending
            limit = _transport.task_timeout(deadline, now)
        self._record("request", msg, None, {"kind": "task_request", "task_id": task["task_id"], "run_id": run_id,
                                            "requirements": [r["dimension"] for r in task["requirements"]]},
                     case, injected=injected, headers={"Content-Type": "application/json"})
        try:
            response = self.transport.post(msg, timeout=limit)
        except SpecialistTimeout as err:
            pending = Pending(run_id, task, msg, None, None, None, error=("specialist_timeout", str(err)))
        except ResponseTooLarge as err:
            pending = Pending(run_id, task, msg, None, None, None, error=("response_too_large", str(err)))
        except SpecialistUnavailable as err:
            pending = Pending(run_id, task, msg, None, None, None, error=("specialist_unavailable", str(err)))
        else:
            try:
                reply = nlip.parse(response.json())
                payload = nlip.structured_payload(reply)
            except (ValueError, nlip.NlipError) as err:
                pending = Pending(run_id, task, msg, response, None, None, error=("invalid_response", str(err)))
            else:
                pending = Pending(run_id, task, msg, response, reply, payload)
        pending.injected = injected
        return pending

    def _contract_token_for(self, task):
        """The token follows the NEGOTIATED contract, never a payload that merely says 2.x or 3.x."""
        version = str(task.get("schema_version", ""))
        if self.version == CONTRACT_VERSION_V2 and version.startswith("2."):
            return CONTRACT_VERSION_V2
        if self.version == CONTRACT_VERSION_V3 and version.startswith("3."):
            return CONTRACT_VERSION_V3
        return None

    def record_response(self, pending, case=None, injected=False):
        """Record the HTTP response leg now; delivery to core happens later via receive()."""
        if pending.response is not None and not pending.recorded:
            payload = pending.payload if isinstance(pending.payload, dict) else {}
            self._record("response", pending.message, pending.response.status,
                         {"kind": payload.get("kind"), "task_id": payload.get("task_id"), "delivery": "deferred"},
                         case, injected=injected or pending.injected, headers=pending.response.headers)
            pending.recorded = True

    def exchange_raw(self, body, case=None, injected=True):
        """POST arbitrary bytes to /nlip (test inputs); records both legs. Returns (status, reply or None)."""
        try:
            request_msg = nlip.parse(json.loads(body.decode("utf-8")))
        except (ValueError, nlip.NlipError, UnicodeDecodeError):
            request_msg = None
        self._record("request", request_msg, None, None, case, injected=injected,
                     headers={"Content-Type": "application/json"},
                     raw_body=None if request_msg is not None else body.decode("utf-8", "replace"))
        response = self.transport.post_raw(body)
        try:
            reply = nlip.parse(response.json())
        except (ValueError, nlip.NlipError):
            reply = None
        self._record("response", reply, response.status, None, case, injected=injected, headers=response.headers)
        return response.status, reply

    def receive(self, pending, message=None, case=None, injected=False):
        """Deliver a response (or an injected substitute) for ``pending`` through core."""
        run_id, task = pending.run_id, pending.task
        status = pending.response.status if pending.response is not None else None
        msg = message if message is not None else pending.message
        payload = nlip.structured_payload(msg) if message is not None else pending.payload
        delivery = message is not None or pending.recorded

        def finish(outcome, event):
            event = dict(event, conclusion=outcome.conclusion)
            if delivery:
                self._record("delivery", msg, None, event, case, injected=injected)
            elif pending.response is not None:
                self._record("response", msg, status, event, case, injected=injected or pending.injected,
                             headers=pending.response.headers)
            else:
                self._record("local", None, None, event, case, injected=injected or pending.injected)
            pending.recorded = True
            return outcome

        if pending.error is not None and message is None:
            code, detail = pending.error
            self.registry.fail(run_id, code)
            return finish(self._failed(run_id, task, code, status), {"kind": "failure", "code": code})

        kind = payload.get("kind") if isinstance(payload, dict) else None
        if status != 200 and message is None:
            code = "http_%s" % status
            self.registry.fail(run_id, code)
            return finish(self._failed(run_id, task, code, status), {"kind": "failure", "code": code})
        reply_major = str(payload.get("schema_version", "")) if isinstance(payload, dict) else ""
        if kind in ("rejection", "result") and ((reply_major.startswith("2.") and nlip.contract_tokens(msg) != [CONTRACT_VERSION_V2])
                                                or (reply_major.startswith("3.") and nlip.contract_tokens(msg) != [CONTRACT_VERSION_V3])):
            # A major 2 or 3 reply without the echoed contract token is not processed (I2-REQ-02, I3-REQ-02).
            if not injected:
                self.registry.fail(run_id, "invalid_response")
            return finish(self._failed(run_id, task, "invalid_response", status, payload_kind=kind),
                          {"kind": "failure", "code": "invalid_response", "detail": "contract token missing"})
        token = nlip.correlation_token(msg) if kind in ("rejection", "result") else None
        if kind in ("rejection", "result") and token != run_id:
            # A's own check, before acting on any domain payload (rejection or result):
            # the conversation token must be echoed unchanged.
            self.registry.record_rejection("correlation_mismatch", payload, "token not echoed unchanged", injected)
            if not injected:
                self.registry.fail(run_id, "correlation_mismatch")
            run = self.registry.runs[run_id]
            outcome = Outcome(run_id, run.state, "correlation_mismatch",
                              self._conclusion(run_id, task, run, None, payload, failure="correlation_mismatch"),
                              http_status=status, payload_kind=kind, rejection_code="correlation_mismatch",
                              result_status=payload.get("status"), payload=payload)
            return finish(outcome, {"kind": "attach_rejected", "codes": ["correlation_mismatch"],
                                    "task_id": payload.get("task_id")})
        if kind == "rejection" and self.registry.runs[run_id].final:
            # Late rejection for a run that is already final (superseded or finished):
            # retain it, keep the final state and reason, attach nothing (I1-IR-02).
            code = payload.get("code", "rejected")
            self.registry.record_rejection("stale_run", payload, "late rejection %s for final run" % code, injected)
            run = self.registry.runs[run_id]
            outcome = Outcome(run_id, run.state, "stale_run", self._conclusion(run_id, task, run, None, payload,
                                                                               failure="stale_run"),
                              http_status=status, payload_kind=kind, rejection_code="stale_run", payload=payload)
            return finish(outcome, {"kind": "late_delivery_retained", "codes": ["stale_run"],
                                    "producer_code": code, "task_id": payload.get("task_id"),
                                    "run_state": run.state})
        if kind == "rejection":
            code = payload.get("code", "rejected")
            self.registry.fail(run_id, code)
            return finish(self._failed(run_id, task, code, status, payload_kind=kind, rejection_code=code),
                          {"kind": "rejection", "code": code, "task_id": payload.get("task_id")})
        if kind != "result":
            if not injected:
                self.registry.fail(run_id, "invalid_response")
            return finish(self._failed(run_id, task, "invalid_response", status, payload_kind=kind),
                          {"kind": "failure", "code": "invalid_response"})

        att = self.registry.attach(payload, token, received_at=self.clock(), injected=injected)
        if not att.accepted and not injected:
            self.registry.fail(run_id, att.codes[0])
        run = self.registry.runs[run_id]
        outcome = Outcome(run_id, run.state, run.reason if att.accepted or not injected else att.codes[0],
                          self._conclusion(run_id, task, run, att, payload), attachment=att, http_status=status,
                          payload_kind=kind, rejection_code=None if att.accepted else att.codes[0],
                          result_status=payload.get("status"), payload=payload)
        event = {"kind": "result_attached" if att.accepted else "attach_rejected", "codes": att.codes,
                 "task_id": payload.get("task_id"), "result_status": payload.get("status"),
                 "run_state": run.state, "quarantined": att.quarantined,
                 "claims": att.claims, "missing_evidence": payload.get("missing_evidence"),
                 # core's derived record, kept apart from the producer payload (I1-IR-01)
                 "coverage": att.coverage, "derived_state": att.derived_state,
                 "producer_status": att.producer_status}
        return finish(outcome, event)

    def _ensure_capability(self, run, case):
        """Negotiate once. Returns a failed Outcome, or None when a capability is in hand."""
        if self.capability is not None:
            return None
        try:
            self.negotiate(case)
        except (SpecialistUnavailable, SpecialistTimeout, ResponseTooLarge) as err:
            code = "specialist_unavailable"
            if isinstance(err, SpecialistTimeout):
                code = "specialist_timeout"
            elif isinstance(err, ResponseTooLarge):
                code = "response_too_large"
            self.registry.fail(run.run_id, code)
            outcome = self._failed(run.run_id, None, code, None)
            self._record("local", None, None, {"kind": "failure", "code": code,
                                                  "detail": str(err), "conclusion": outcome.conclusion}, case)
            return outcome
        except (ProtocolError, ValueError, nlip.NlipError) as err:
            code = getattr(err, "code", "capability_invalid")
            self.registry.fail(run.run_id, code)
            return self._failed(run.run_id, None, code, None)
        return None

    def investigate(self, context, dimensions, inputs, run_id=None, case=None, overrides=None, injected=False):
        run = self.start_run(context["repo_id"], run_id)
        failed = self._ensure_capability(run, case)
        if failed is not None:
            return failed
        task = self.build_task(run.run_id, context, dimensions, inputs, overrides)
        pending = self.dispatch(run.run_id, task, case=case, injected=injected)
        return self.receive(pending, case=case)

    def run_task(self, context, dimension, inputs, operation, capture_set_id=None, deadline_s=None, case=None,
                 overrides=None, injected=False):
        """One I2 task exchange in its own run (each task finishes before the next starts).

        Returns (outcome, task). ``task`` is None only when negotiation itself failed.
        """
        run = self.start_run(context["repo_id"])
        failed = self._ensure_capability(run, case)
        if failed is not None:
            return failed, None
        task = self.build_task(run.run_id, context, [dimension], inputs, overrides, operation=operation,
                               capture_set_id=capture_set_id if self.version in (CONTRACT_VERSION_V2, CONTRACT_VERSION_V3) else None,
                               deadline_s=deadline_s)
        pending = self.dispatch(run.run_id, task, case=case, injected=injected)
        return self.receive(pending, case=case), task

    # -- conclusions --------------------------------------------------------------
    def _failed(self, run_id, task, code, status, payload_kind=None, rejection_code=None):
        run = self.registry.runs[run_id]
        return Outcome(run_id, run.state, code, self._conclusion(run_id, task, run, None, None, failure=code),
                       http_status=status, payload_kind=payload_kind, rejection_code=rejection_code)

    def _conclusion(self, run_id, task, run, att, payload, failure=None):
        """investigation_conclusion domain event. Unknowns are never upgraded."""
        supported, unsupported, unknowns = [], [], []
        requirements = task["requirements"] if task else []
        if att is not None and att.accepted:
            for claim in att.claims:
                (supported if claim["status"] == "supported" else unsupported).append(claim["claim_id"])
            # Unknowns come from core's coverage, not from the producer's status: every
            # unsatisfied requirement stays explicitly unknown (I1-IR-01).
            for cov in att.coverage:
                if not cov["satisfied"]:
                    unknowns.append({"requirement_id": cov["requirement_id"], "dimension": cov["dimension"],
                                     "reason": cov["reason"]})
            task_ids = {r["requirement_id"] for r in requirements}
            for missing in payload.get("missing_evidence", []):
                if missing["requirement_id"] not in task_ids:  # never drop a producer-reported gap
                    unknowns.append({"requirement_id": missing["requirement_id"], "dimension": missing["dimension"],
                                     "reason": missing["reason"]})
        else:
            reason = failure or (att.codes[0] if att is not None and att.codes else run.reason) or "no_result"
            for req in requirements:
                unknowns.append({"requirement_id": req["requirement_id"], "dimension": req["dimension"],
                                 "reason": reason})
        recorded_failure = failure if failure else (run.reason if run.state == runs.FAILED else None)
        return {"kind": "investigation_conclusion", "run_id": run_id,
                "task_id": task["task_id"] if task else None, "run_state": run.state,
                "failure": recorded_failure,
                "supported_claims": sorted(supported), "unsupported_claims": sorted(unsupported),
                "unknowns": unknowns,
                "next_step": self.policy.next_step(unknowns, len(supported), failure=recorded_failure)}
