"""Pure intake state transitions and stale-response generation protection."""

from dataclasses import dataclass, replace
from enum import Enum
import math


class InvalidTransition(ValueError):
    pass


class ArtifactOutcome(str, Enum):
    MISSING = "missing"
    FAILED = "failed"
    ZERO_RECORD_SUCCESS = "zero_record_success"


ARTIFACT_OUTCOMES = tuple(outcome.value for outcome in ArtifactOutcome)


def _numeric_timestamp(value):
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    return isinstance(value, int) or math.isfinite(value)


@dataclass(frozen=True)
class State:
    status: str = "untouched"
    manual_sha: str | None = None
    preview: object | None = None
    inputs_fingerprint: str | None = None
    resolved_at: float | None = None
    payload: object | None = None


_STATES = {"untouched", "invalid", "resolving", "unavailable", "resolution_unavailable", "ready", "stale", "acquiring", "partial", "complete", "failed", "cancelled"}


def transition(state, event, **data):
    if not isinstance(state, State) or state.status not in _STATES:
        raise InvalidTransition("unknown intake state")
    if event == "reset":
        return State()
    if event == "edit_invalid" and state.status not in ("acquiring", "partial", "complete", "failed", "cancelled"):
        return replace(state, status="invalid", preview=None, inputs_fingerprint=data.get("inputs_fingerprint"), payload=None)
    if event == "edit_valid" and state.status not in ("acquiring", "partial", "complete", "failed", "cancelled"):
        status = "stale" if state.preview is not None else "untouched"
        return replace(state, status=status, preview=None, inputs_fingerprint=data.get("inputs_fingerprint"), payload=None)
    if event == "advanced_off":
        if state.status in ("acquiring", "partial", "complete", "failed", "cancelled"):
            raise InvalidTransition("cannot change Advanced during acquisition")
        invalidate_resolution = state.status == "resolving" and state.manual_sha is not None
        return replace(state, manual_sha=None,
                       status="stale" if invalidate_resolution or (state.status == "ready" and state.manual_sha is not None) else state.status,
                       preview=None if invalidate_resolution or (state.status == "ready" and state.manual_sha is not None) else state.preview)
    if event == "submit" and state.status in ("untouched", "invalid", "unavailable", "resolution_unavailable", "stale"):
        return replace(state, status="resolving", preview=None, inputs_fingerprint=data.get("inputs_fingerprint", state.inputs_fingerprint), payload=None)
    if event == "resolved_ok" and state.status == "resolving":
        return replace(state, status="ready", preview=data.get("preview"), payload=data.get("payload"),
                       inputs_fingerprint=data.get("inputs_fingerprint", state.inputs_fingerprint),
                       resolved_at=data.get("resolved_at"))
    if event == "resolved_error" and state.status == "resolving":
        status = data.get("status", "resolution_unavailable")
        if status not in ("unavailable", "resolution_unavailable"):
            raise InvalidTransition("invalid resolution error state")
        return replace(state, status=status, preview=None, payload=data.get("payload"))
    if event == "clock_tick" and state.status == "ready":
        now = data.get("now")
        changed = data.get("inputs_fingerprint", state.inputs_fingerprint) != state.inputs_fingerprint
        expired = state.resolved_at is None or now is None or now - state.resolved_at > 600
        if changed or expired:
            return replace(state, status="stale", preview=None)
        return state
    if event == "start" and state.status == "ready":
        now = data.get("now")
        if (not _numeric_timestamp(now) or not _numeric_timestamp(state.resolved_at)
                or now - state.resolved_at > 600):
            raise InvalidTransition("preview is stale")
        if data.get("inputs_fingerprint", state.inputs_fingerprint) != state.inputs_fingerprint:
            raise InvalidTransition("inputs changed since resolution")
        return replace(state, status="acquiring")
    if event == "acquisition_partial" and state.status == "acquiring":
        return replace(state, status="partial", payload=data.get("artifacts", {}))
    if event == "acquisition_complete" and state.status == "acquiring":
        return replace(state, status="complete", payload=data.get("artifacts", {}))
    if event == "acquisition_failed" and state.status == "acquiring":
        return replace(state, status="failed", payload=data.get("artifacts", {}))
    if event == "cancel" and state.status in ("acquiring", "ready", "resolving"):
        return replace(state, status="cancelled", preview=None)
    raise InvalidTransition("event {!r} is not allowed from {}".format(event, state.status))


class GenerationGuard:
    def __init__(self):
        self._generation = 0
        self._ended = False

    def begin(self):
        self._generation += 1
        self._ended = False
        return self._generation

    def accept(self, generation):
        return not self._ended and generation == self._generation

    def end(self):
        self._generation += 1
        self._ended = True
