"""Spawn-isolated, bounded execution of the unchanged BOMBridge engine."""
import hashlib
import json
import multiprocessing
import queue
import threading
import time

from opentrace_core.bombridge import pipeline
from .types import AdapterResult, BoundAssessment, TypedError
from .validation import check_context, json_bytes, validate_result

DEFAULT_BUNDLE_LIMIT = 16 * 1024 * 1024
DEFAULT_RESULT_LIMIT = 32 * 1024 * 1024
DEFAULT_DEADLINE = 30.0


def _engine_worker(payload):
    return pipeline.run_doc(payload)


def _worker_entry(conn, payload_bytes, target, writer=None):
    try:
        if writer is not None:
            writer(conn)
            return
        payload = json.loads(payload_bytes.decode("utf-8"))
        value = target(payload)
        result = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        conn.send_bytes(result)
    except BaseException as exc:
        try:
            conn.send_bytes(json.dumps({"__adapter_worker_error__": type(exc).__name__,
                                       "detail": str(exc)[:500]}, sort_keys=True).encode("utf-8"))
        except (OSError, ValueError):
            pass
    finally:
        conn.close()


def _receive_frame(conn, result_limit, outcome, ready, done):
    """Blocking framed read isolated from the deadline/cancellation supervisor."""
    ready.set()
    try:
        outcome.put((True, conn.recv_bytes(maxlength=result_limit + 1)))
    except BaseException as exc:
        outcome.put((False, exc))
    finally:
        done.set()


def _cancelled(cancel):
    if cancel is None:
        return False
    if isinstance(cancel, bool):
        return cancel
    return bool(cancel() if callable(cancel) else cancel.is_set())


def assess(context, bundle, *, artifacts=(), read_artifact=lambda _id: b"", cancel=None,
           deadline=DEFAULT_DEADLINE, bundle_limit=DEFAULT_BUNDLE_LIMIT,
           result_limit=DEFAULT_RESULT_LIMIT, _worker_target=None, _worker_writer=None):
    """Validate and assess in a spawn child. Expected input/runtime failures are typed."""
    errors = check_context(context)
    if errors:
        return AdapterResult("failed", errors=errors)
    try:
        payload = json_bytes(bundle)
    except (TypeError, ValueError, OverflowError):
        return AdapterResult("failed", errors=[TypedError("invalid_bundle", "$", "invalid_json")])
    if len(payload) > bundle_limit:
        return AdapterResult("failed", errors=[TypedError("size_limit", "$", "bundle_over_limit")])
    from .validation import normalize_artifact, prevalidate_bundle, validate_artifacts
    errors = prevalidate_bundle(bundle, context)
    if errors:
        return AdapterResult("failed", errors=errors)
    art_errors, _, _ = validate_artifacts(context, bundle, artifacts, read_artifact)
    incomplete = any(normalize_artifact(a).get("state") != "acquired" for a in artifacts if isinstance(normalize_artifact(a), dict)) or any(
        e.detail == "missing_artifact" or e.detail.startswith(("artifact_unavailable:","artifact_not_acquired:")) for e in art_errors)
    errors.extend(art_errors)
    if errors:
        return AdapterResult("partial" if incomplete else "failed", errors=errors)
    if _cancelled(cancel):
        return AdapterResult("cancelled", errors=[TypedError("cancelled", "worker", "cancelled_before_spawn")])
    if check_context(context):
        return AdapterResult("cancelled", errors=[TypedError("session_mismatch", "current_session", "stale_before_spawn")])
    mp = multiprocessing.get_context("spawn")
    recv_conn, send_conn = mp.Pipe(duplex=False)
    process = mp.Process(target=_worker_entry, args=(send_conn, payload, _worker_target or _engine_worker, _worker_writer))
    result = None
    err = None
    started = time.monotonic()
    outcome = queue.Queue(maxsize=1)
    ready = threading.Event()
    reader_done = threading.Event()
    receiver = None
    try:
        process.start()
        send_conn.close()
        receiver = threading.Thread(target=_receive_frame,
            args=(recv_conn, result_limit, outcome, ready, reader_done), daemon=True)
        receiver.start()
        if not ready.wait(timeout=max(0.0, min(deadline, 1.0))):
            err = TypedError("invalid_result", "worker", "receiver_not_ready")
        while True:
            if err is not None:
                break
            if _cancelled(cancel):
                err = TypedError("cancelled", "worker", "cancelled_during_run"); break
            if check_context(context):
                err = TypedError("session_mismatch", "current_session", "stale_during_run"); break
            remaining = deadline - (time.monotonic() - started)
            if remaining <= 0:
                err = TypedError("timeout", "worker", "deadline_exceeded"); break
            try:
                ok, message = outcome.get(timeout=min(0.025, remaining))
            except queue.Empty:
                ok = None
            if ok is not None:
                if not ok:
                    detail = "result_over_limit_or_truncated" if isinstance(message, OSError) else "worker_failed:truncated_or_closed_frame"
                    err = TypedError("size_limit" if detail.startswith("result_over") else "invalid_result", "result", detail)
                    break
                if len(message) > result_limit:
                    err = TypedError("size_limit", "result", "result_over_limit"); break
                try:
                    result = json.loads(message.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    err = TypedError("invalid_result", "result", "invalid_json"); break
                if isinstance(result, dict) and "__adapter_worker_error__" in result:
                    err = TypedError("invalid_result", "worker", "worker_failed:" + result["__adapter_worker_error__"]); result = None
                break
            if not process.is_alive() and reader_done.is_set():
                err = TypedError("invalid_result", "worker", "worker_failed:no_response"); break
        if err is not None:
            if process.is_alive():
                process.terminate()
            process.join(timeout=1)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill(); process.join(timeout=1)
            return AdapterResult("cancelled" if err.code in ("cancelled", "session_mismatch") else "failed", errors=[err])
        process.join(timeout=1)
        if process.is_alive():
            process.terminate(); process.join(timeout=1)
        if process.exitcode not in (0, None):
            return AdapterResult("failed", errors=[TypedError("invalid_result", "worker", "worker_failed:exit_{}".format(process.exitcode))])
        errors = validate_result(result, context=context, bundle=bundle, artifacts=artifacts, read_artifact=read_artifact)
        if errors:
            return AdapterResult("failed", errors=errors)
        if _cancelled(cancel) or check_context(context):
            return AdapterResult("cancelled", errors=[TypedError("session_mismatch" if check_context(context) else "cancelled", "release", "stale_or_cancelled_after_validation")])
        b = {"analysis_digest": context.identity["analysis_digest"],
             "session_id": context.expected_session["session_id"],
             "generation": context.expected_session["generation"],
             "configuration": context.expected_configuration,
             "bundle_sha256": result["bundle_sha256"]}
        owned_bundle = json.loads(payload.decode("utf-8"))
        seal = hashlib.sha256(json_bytes({"binding": b, "result": result, "source_bundle": owned_bundle})).hexdigest()
        return AdapterResult("complete", BoundAssessment("opentrace.bombridge_assessment/1", b, result, seal, owned_bundle))
    finally:
        try:
            send_conn.close()
        except OSError:
            pass
        try:
            recv_conn.close()
        except OSError:
            pass
        if receiver is not None:
            receiver.join(timeout=1)
        if process.pid is not None and process.is_alive():
            process.terminate(); process.join(timeout=1)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill(); process.join(timeout=1)
        try:
            process.close()
        except (ValueError, AttributeError):
            pass
