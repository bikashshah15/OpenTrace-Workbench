"""Session service: tokens, generations, artifacts, expiry and verified cleanup (I4D).

Everything a session owns lives under ``root/<session_id>``. No caller-supplied
string is ever joined into a path. Access control and freshness are enforced
under one lock per session; teardown flips the state (revoking access and
advancing the generation) before it touches any producer or file.
"""

import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import stat
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from opentrace_core.intake.state import GenerationGuard

IDLE_SECONDS = 2 * 60 * 60
ABSOLUTE_SECONDS = 8 * 60 * 60
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_ARTIFACTS = 64
MAX_SESSION_BYTES = 256 * 1024 * 1024

_SESSION_ID = re.compile(r"^[0-9a-f]{32}$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_KINDS = ("original", "derived")
_LOG_KEYS = ("event", "session", "state", "generation", "reason", "code", "count", "duration_ms")
_DENIED = "access denied"


class SessionError(Exception):
    def __init__(self, code, message=None):
        super().__init__(message or code)
        self.code = code
        self.message = message or code


@dataclass(frozen=True)
class SessionHandle:
    session_id: str
    token: str
    generation: int


class AnalysisTicket:
    """Held by producers; carries no credential, only identity and cancellation."""

    def __init__(self, session_id, generation):
        self.session_id = session_id
        self.generation = generation
        self.cancel_event = threading.Event()


@dataclass(frozen=True)
class ArtifactRecord:
    name: str
    kind: str
    media_type: str
    size: int
    sha256: str
    analysis_digest: object
    generation: int


@dataclass(frozen=True)
class Artifact:
    data: bytes
    record: ArtifactRecord


class _Analysis:
    def __init__(self, ticket, digest):
        self.ticket = ticket
        self.digest = digest
        self.state = "running"
        self.artifacts = OrderedDict()  # name -> (ArtifactRecord, filename)
        self.bytes = 0


class _Session:
    def __init__(self, sid, token_hash, path, now):
        self.sid = sid
        self.token_hash = token_hash
        self.path = path
        self.lock = threading.RLock()
        self.guard = GenerationGuard()
        self.generation = 0
        self.state = "active"
        self.analysis = None
        self.created = now
        self.last_access = now
        self.cleaning = False
        self.counter = 0
        # Registered producers stay owned by the session until verified stopped,
        # across finish, cancellation (even failed or in flight) and later analyses.
        self.producers = []


def _remove_path(path):
    if os.path.islink(path):
        os.unlink(path)
    elif os.path.lexists(path):
        shutil.rmtree(path)


def _token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _default_sink(event):
    logging.getLogger("opentrace.session").info(json.dumps(event, sort_keys=True))


class SessionService:
    def __init__(self, root, *, clock=time.monotonic, remover=_remove_path, sink=_default_sink,
                 idle_seconds=IDLE_SECONDS, absolute_seconds=ABSOLUTE_SECONDS,
                 producer_wait_seconds=2.0):
        self._clock = clock
        self._remove = remover
        self._sink = sink
        self._idle = idle_seconds
        self._absolute = absolute_seconds
        self._producer_wait = producer_wait_seconds
        self._registry_lock = threading.Lock()
        self._sessions = {}
        self._root = self._prepare_root(os.fspath(root))

    # -- root ---------------------------------------------------------------
    @staticmethod
    def _prepare_root(root):
        if not os.path.lexists(root):
            os.makedirs(root, mode=0o700)
            os.chmod(root, 0o700)
        info = os.lstat(root)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise SessionError("unsafe_root", "session root must be a private directory")
        return os.path.realpath(root)

    # -- logging ------------------------------------------------------------
    def _emit(self, session=None, **fields):
        event = {key: value for key, value in fields.items() if key in _LOG_KEYS}
        if session is not None:
            event["session"] = hashlib.sha256(session.encode("ascii")).hexdigest()[:12]
        try:
            self._sink(event)
        except Exception:  # logging must never break teardown
            pass

    # -- lifecycle ----------------------------------------------------------
    def create_session(self):
        sid = secrets.token_hex(16)
        token = secrets.token_urlsafe(32)
        path = os.path.join(self._root, sid)
        os.mkdir(path, 0o700)
        os.chmod(path, 0o700)
        os.mkdir(os.path.join(path, "a"), 0o700)
        session = _Session(sid, _token_digest(token), path, self._clock())
        with self._registry_lock:
            self._sessions[sid] = session
        self._emit(sid, event="session_created", state="active", generation=0)
        return SessionHandle(sid, token, 0)

    def _expired_reason(self, session, now):
        if now - session.created > self._absolute:
            return "absolute_expired"
        if now - session.last_access > self._idle:
            return "idle_expired"
        return None

    @contextlib.contextmanager
    def _locked(self, sid, token):
        with self._registry_lock:
            session = self._sessions.get(sid) if isinstance(sid, str) else None
        digest = _token_digest(token if isinstance(token, str) else "")
        if session is None:
            hmac.compare_digest(digest, digest)
            raise SessionError("access_denied", _DENIED)
        reason = self._expired_reason(session, self._clock())
        if reason is not None and session.state == "active":
            self._end(session, reason)
            raise SessionError("access_denied", _DENIED)
        with session.lock:
            stored = session.token_hash
            if (session.state != "active" or stored is None
                    or not hmac.compare_digest(stored, digest)):
                raise SessionError("access_denied", _DENIED)
            session.last_access = self._clock()
            yield session

    def begin_analysis(self, sid, token, analysis_digest=None, *, expected_generation=None):
        """Begin the session's next analysis.

        ``expected_generation`` (UIP-03) is a precondition checked under the SAME session lock that advances the generation: when
        given and it differs from the session's current generation, nothing is changed and ``stale_generation`` is raised. ``None``
        (every legacy caller) keeps the previous behavior exactly.
        """
        with self._locked(sid, token) as session:
            if expected_generation is not None and expected_generation != session.generation:
                raise SessionError("stale_generation", "the session has moved on")
            if session.analysis is not None and session.analysis.state == "running":
                raise SessionError("analysis_active", "an analysis is already running")
            self._reset_artifacts(session)
            session.generation = session.guard.begin()
            ticket = AnalysisTicket(sid, session.generation)
            session.analysis = _Analysis(ticket, analysis_digest)
        self._emit(sid, event="analysis_started", state="running", generation=ticket.generation)
        return ticket

    def current_generation(self, sid, token):
        """Read-only: the session's current generation (UIP-03 request precondition). Authenticates like any other call."""
        with self._locked(sid, token) as session:
            return session.generation

    def cleanup_facts(self, ticket):
        """Read-only (UIP-03): what is positively known about the leftovers of ``ticket``'s analysis.

        Returns ``{"session_present", "workspace_present", "trash_present", "producers_alive"}``. A session that is no longer
        registered was verified deleted (the registry entry is removed only after verified deletion), so nothing is left. Nothing
        here changes state or deletes anything; callers treat any exception or non-clean answer as *unverified*.
        """
        with self._registry_lock:
            session = self._sessions.get(getattr(ticket, "session_id", None))
        if session is None:
            return {"session_present": False, "workspace_present": False, "trash_present": False, "producers_alive": 0}
        with session.lock:
            workspace = os.path.join(session.path, "a", "w{}".format(ticket.generation))
            trash = any(entry.startswith("t") for entry in os.listdir(session.path)) if os.path.isdir(session.path) else False
            alive = sum(1 for producer in session.producers if self._alive(producer))
            return {"session_present": True, "workspace_present": os.path.lexists(workspace), "trash_present": trash, "producers_alive": alive}

    def _reset_artifacts(self, session):
        directory = os.path.join(session.path, "a")
        if os.path.isdir(directory) and not os.listdir(directory):
            return
        try:
            self._remove(directory)
            os.mkdir(directory, 0o700)
        except Exception:
            raise SessionError("cleanup_failed", "previous analysis data could not be removed")
        if os.path.lexists(directory) and os.listdir(directory):
            raise SessionError("cleanup_failed", "previous analysis data could not be removed")

    def register_producer(self, ticket, producer):
        try:
            with self._ticket_session(ticket) as session:
                session.producers.append(producer)
        except SessionError:
            with contextlib.suppress(Exception):
                producer.stop()
            raise

    @contextlib.contextmanager
    def _ticket_session(self, ticket):
        with self._registry_lock:
            session = self._sessions.get(getattr(ticket, "session_id", None))
        if session is None:
            raise SessionError("stale_generation", "analysis is no longer current")
        with session.lock:
            analysis = session.analysis
            if (session.state != "active" or analysis is None or analysis.ticket is not ticket
                    or analysis.state != "running" or not session.guard.accept(ticket.generation)):
                raise SessionError("stale_generation", "analysis is no longer current")
            yield session

    def workspace(self, ticket):
        """A fresh private scratch directory for the current analysis (I5).

        One directory per analysis generation (``w<generation>``): a cancelled worker that resumes late
        can only ever touch its own, already-removed path, never a replacement analysis's workspace.
        It lives inside the artifact directory, so cancellation, a new analysis, End session, expiry
        and the startup sweep all remove it with the session's own verified cleanup. The caller never
        supplies a path component.
        """
        with self._ticket_session(ticket) as session:
            path = os.path.join(session.path, "a", "w{}".format(ticket.generation))
            os.mkdir(path, 0o700)
            return path

    def finish(self, ticket, outcome):
        if outcome not in ("complete", "failed"):
            raise SessionError("stale_generation", "invalid outcome")
        with self._ticket_session(ticket) as session:
            session.analysis.state = outcome
            session.producers = [p for p in session.producers if self._alive(p)]
        self._emit(ticket.session_id, event="analysis_finished", state=outcome,
                   generation=ticket.generation)

    def cancel_analysis(self, sid, token):
        with self._locked(sid, token) as session:
            analysis = session.analysis
            if analysis is None or analysis.state != "running":
                raise SessionError("no_active_analysis", "no analysis is running")
            analysis.state = "cancelled"
            analysis.ticket.cancel_event.set()
            session.guard.end()
            session.generation += 1
            producers = list(session.producers)
            analysis.artifacts = OrderedDict()
            analysis.bytes = 0
            session.counter += 1
            trash = os.path.join(session.path, "t{}".format(session.counter))
            os.rename(os.path.join(session.path, "a"), trash)
            os.mkdir(os.path.join(session.path, "a"), 0o700)
            generation = session.generation
        self._emit(sid, event="analysis_cancelled", state="cancelled", generation=generation)
        self._stop_producers(producers)
        alive = self._prune_producers(session)
        try:
            self._remove(trash)
        except Exception:
            pass
        if os.path.lexists(trash):
            raise SessionError("cleanup_failed", "analysis data could not be removed")
        if alive:
            raise SessionError("producer_still_alive", "a producer did not stop")
        return "cancelled"

    # -- artifacts ----------------------------------------------------------
    def commit_artifact(self, ticket, name, data, media_type, kind):
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise SessionError("invalid_name", "artifact name is not allowed")
        if kind not in _KINDS or not isinstance(data, (bytes, bytearray)):
            raise SessionError("invalid_name", "artifact kind or data is not allowed")
        data = bytes(data)
        with self._ticket_session(ticket) as session:
            analysis = session.analysis
            if name in analysis.artifacts:
                raise SessionError("duplicate_artifact", "artifact name already committed")
            if (len(data) > MAX_ARTIFACT_BYTES or len(analysis.artifacts) >= MAX_ARTIFACTS
                    or analysis.bytes + len(data) > MAX_SESSION_BYTES):
                raise SessionError("size_limit", "artifact limits exceeded")
            session.counter += 1
            filename = "{:04d}.bin".format(session.counter)
            directory = os.path.join(session.path, "a")
            temp = os.path.join(directory, ".tmp{}".format(session.counter))
            final = os.path.join(directory, filename)
            try:
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                os.rename(temp, final)
            except OSError:
                with contextlib.suppress(OSError):
                    os.unlink(temp)
                raise SessionError("storage_error", "artifact could not be stored")
            record = ArtifactRecord(name, kind, str(media_type), len(data),
                                    hashlib.sha256(data).hexdigest(), analysis.digest,
                                    ticket.generation)
            analysis.artifacts[name] = (record, filename)
            analysis.bytes += len(data)
            return record

    def list_artifacts(self, sid, token):
        with self._locked(sid, token) as session:
            analysis = session.analysis
            if analysis is None:
                return []
            return [record for record, _ in analysis.artifacts.values()]

    def read_artifact(self, sid, token, name):
        with self._locked(sid, token) as session:
            analysis = session.analysis
            entry = analysis.artifacts.get(name) if analysis and isinstance(name, str) else None
            if entry is None:
                raise SessionError("artifact_not_found", "artifact not found")
            record, filename = entry
            try:
                with open(os.path.join(session.path, "a", filename), "rb") as handle:
                    data = handle.read()
            except OSError:
                raise SessionError("artifact_integrity_error", "artifact is unreadable")
            if len(data) != record.size or hashlib.sha256(data).hexdigest() != record.sha256:
                raise SessionError("artifact_integrity_error", "artifact does not match its digest")
            return Artifact(data, record)

    # -- end, expiry, sweep -------------------------------------------------
    def end_session(self, sid, token):
        with self._locked(sid, token) as session:
            pass
        return self._end(session, "user")

    def retry_cleanup(self, sid):
        with self._registry_lock:
            session = self._sessions.get(sid)
        if session is None or session.state != "cleanup_failed":
            raise SessionError("access_denied", _DENIED)
        return self._end(session, "retry")

    @staticmethod
    def _alive(producer):
        try:
            return bool(producer.is_alive())
        except Exception:
            return True

    def _prune_producers(self, session):
        """Drop only producers verified not alive; return those still owned."""
        with session.lock:
            session.producers = [p for p in session.producers if self._alive(p)]
            return list(session.producers)

    def _stop_producers(self, producers):
        for producer in producers:
            try:
                producer.stop()
            except Exception:
                pass
        deadline = time.monotonic() + self._producer_wait  # real time, not the injected clock
        while any(self._alive(p) for p in producers) and time.monotonic() < deadline:
            time.sleep(0.005)

    def _end(self, session, reason):
        started = self._clock()
        with session.lock:
            if session.cleaning:
                return session.state
            if session.state == "deleted_verified":
                return session.state
            session.cleaning = True
            first = session.state == "active"
            session.state = "ending"
            session.token_hash = None  # 1. revoke access
            if first:
                session.guard.end()  # 2. advance generation
                session.generation += 1
            if session.analysis is not None:
                session.analysis.ticket.cancel_event.set()
            producers = list(session.producers)
        self._emit(session.sid, event="session_ending", state="ending", reason=reason,
                   generation=session.generation)
        try:
            self._stop_producers(producers)  # 3. producers and assessment
            alive = self._prune_producers(session)
            try:
                self._remove(session.path)  # 4. data
            except Exception:
                pass
            removed = not os.path.lexists(session.path)  # 5. verify
            verified = removed and not alive
            with session.lock:
                if verified:
                    session.state = "deleted_verified"
                    session.analysis = None
                else:
                    session.state = "cleanup_failed"
        finally:
            with session.lock:
                session.cleaning = False
        duration = int((self._clock() - started) * 1000)
        if session.state == "deleted_verified":
            with self._registry_lock:
                self._sessions.pop(session.sid, None)
            self._emit(session.sid, event="session_deleted_verified", state=session.state,
                       reason=reason, duration_ms=duration)
        else:
            self._emit(session.sid, event="session_cleanup_failed", state=session.state,
                       reason=reason, code="cleanup_failed", duration_ms=duration)
        return session.state

    def tick(self):
        with self._registry_lock:
            sessions = list(self._sessions.values())
        counts = {"expired": 0, "retried": 0, "deleted": 0, "failed": 0}
        now = self._clock()
        for session in sessions:
            if session.state == "active":
                reason = self._expired_reason(session, now)
                if reason is None:
                    continue
                counts["expired"] += 1
            elif session.state == "cleanup_failed":
                reason = "retry"
                counts["retried"] += 1
            else:
                continue
            result = self._end(session, reason)
            counts["deleted" if result == "deleted_verified" else "failed"] += 1
        return counts

    def startup_sweep(self):
        with self._registry_lock:
            live = set(self._sessions)
        removed = failed = skipped = 0
        for entry in os.scandir(self._root):
            if not _SESSION_ID.fullmatch(entry.name) or entry.name in live:
                skipped += 1
                continue
            try:
                self._remove(entry.path)
            except Exception:
                pass
            if os.path.lexists(entry.path):
                failed += 1
            else:
                removed += 1
        self._emit(event="startup_sweep", count=removed)
        return {"removed": removed, "failed": failed, "skipped": skipped}
