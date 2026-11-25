"""Run state machine: queued -> running -> partial | succeeded | failed | canceled.

Final states are immutable; nothing turns partial into succeeded.
"""
from . import timeutil

QUEUED, RUNNING = "queued", "running"
PARTIAL, SUCCEEDED, FAILED, CANCELED = "partial", "succeeded", "failed", "canceled"
FINAL = frozenset({PARTIAL, SUCCEEDED, FAILED, CANCELED})
_ALLOWED = {
    QUEUED: {RUNNING, FAILED, CANCELED},
    RUNNING: {PARTIAL, SUCCEEDED, FAILED, CANCELED},
}


class InvalidTransition(Exception):
    pass


class Run:
    def __init__(self, run_id, repo_id):
        self.run_id = run_id
        self.repo_id = repo_id
        self.state = QUEUED
        self.reason = None
        self.history = [(QUEUED, None, timeutil.format_ts(timeutil.now()))]

    @property
    def final(self):
        return self.state in FINAL

    def transition(self, state, reason=None):
        if state not in _ALLOWED.get(self.state, set()):
            raise InvalidTransition("%s: %s -> %s not allowed" % (self.run_id, self.state, state))
        self.state = state
        self.reason = reason
        self.history.append((state, reason, timeutil.format_ts(timeutil.now())))

    def as_dict(self):
        return {"run_id": self.run_id, "repo_id": self.repo_id, "state": self.state, "reason": self.reason,
                "history": [{"state": s, "reason": r, "at": t} for s, r, t in self.history]}
