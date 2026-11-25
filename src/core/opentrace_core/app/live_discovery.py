"""Live requirement -> SBOM discovery for a submitted repository (UIP-10 Stage 1). OpenTrace-authored.

This is the live generalisation of ``server._discover_gaps`` (which stays untouched for the recorded case). The comparison logic is the
unchanged BOMBridge discovery (``bombridge.discovery``) and the unchanged assessment worker; this module only

* selects the SBOM from the capture's recorded inventories by metadata (kind, acquisition outcome, recorded digest) and re-hashes its bytes,
* digest-binds the collected requirement files (``live.source_declarations``) to that capture's repository and revision,
* maps what was *collected* and what was *compared* onto the existing frozen capability vocabulary, and
* never publishes anything for a cancelled or superseded generation.

Collection availability and comparison verdicts are separate: a verdict ("represented", "no match") lives in the candidates; the
capability ``state`` here only says whether the family could be collected and compared.

UIP-12 Stage 2 adds the cryptography family (Python ``hashlib`` call sites vs the selected CBOM) as a second generator of the *same* discovery bundle:
one ``discover`` call, one ``assemble``, one ``assess``, one bound assessment. Families fail independently at input selection and at generation
(child ``_Out``); a failure of the shared assembly/assessment is reported as shared, with at most one fallback that drops crypto (never on
cancellation). See contract ``UIP-12`` sections 6.2 and 6.3.
"""
import hashlib
import json

from opentrace_core.bombridge import discovery as bb_discovery, discovery_crypto, discovery_models
from opentrace_core.bombridge.adapters import AibomError, aibom_document_observation
from opentrace_core.bombridge_adapter import AdapterError, assemble, assess
from opentrace_core.live import source_declarations as decl
from opentrace_core.session import SessionError

SCHEMA = "opentrace.live_collection/1"
ARTIFACT = "source-declarations.json"

MESSAGES = {
    "completed": "Requirement files were collected and compared with the SBOM.",
    "partial_coverage": "Requirement files were compared with the SBOM, but coverage is partial: some matching files were skipped, traversal stopped early "
                        "or a directory could not be read, or declaration files of other formats or ecosystems were found and not compared.",
    "no_requirement_files": "No Python requirement file was found in the exported source, so nothing was compared. This is not a finding that nothing is missing.",
    "no_named_requirements": "Requirement files were found but declare no named requirement, so nothing was compared.",
    "unsupported_ecosystem": "Only declaration files of formats or ecosystems this build does not read were found, so nothing was compared.",
    "no_usable_requirement_files": "Requirement files were found but none could be read within the limits, so nothing was compared.",
    "collector_timeout": "Collecting requirement files exceeded its time budget before any file was read, so nothing was compared.",
    "collector_unreadable": "The exported source could not be read (a directory listing failed) before any requirement file was collected, so nothing was compared.",
    "collector_entry_cap": "The exported source has more entries than the collector may visit before any file was read, so nothing was compared.",
    "collector_failed": "Collecting requirement files failed, so nothing was compared.",
    "collection_not_run": "Requirement files were not collected for this analysis, so nothing was compared.",
    "inventory_unavailable": "No usable SBOM is recorded for this analysis, so nothing was compared.",
    "inventory_digest_mismatch": "The SBOM does not match its recorded digest, so nothing was compared.",
    "declarations_digest_mismatch": "The collected requirement files do not match their digest, so nothing was compared.",
    "declarations_invalid": "The collected requirement record could not be read, so nothing was compared.",
    "declarations_scope_mismatch": "The collected requirement record describes another repository or revision, so nothing was compared.",
    "inputs_unavailable": "A collected input could not be read, so nothing was compared.",
    "discovery_candidates_over_limit": "The comparison produced more candidates than the service may assess, so nothing was compared.",
    "discovery_payload_invalid": "The comparison could not be assembled, so nothing was compared.",
    "discovery_assessment": "The comparison could not complete, so nothing was compared.",
    "software_generator_failed": "The software comparison could not be generated, so nothing was compared for software.",
}

CRYPTO_MESSAGES = {
    "completed": "Python hashlib call sites were observed and compared with the selected CBOM; each site has its own verdict.",
    "partial_coverage": "Python source coverage is partial (traversal or parsing stopped early, files were skipped, other source languages exist, or some sites cannot be compared "
                        "for lack of usable CBOM scope); observed sites are shown and nothing is concluded about the rest.",
    "completed_empty_python": "No supported hashlib call site was observed in the Python files that were parsed. This is not evidence that no cryptography is used.",
    "completed_empty_no_source": "No source file in a recognized language was found, so nothing was compared. This is not evidence that no cryptography is used.",
    "unsupported_languages": "Only source files in languages this build does not read were found, so nothing was compared.",
    "cbom_not_run": "Python hashlib call sites were observed, but no CBOM was produced for this analysis, so nothing was compared.",
    "cbom_failed": "Python hashlib call sites were observed, but the CBOM producer did not deliver a document, so nothing was compared.",
    "cbom_unsupported_document": "Python hashlib call sites were observed, but the CBOM document cannot be read by this build, so nothing was compared.",
    "incomplete_no_files": "Python source inspection stopped before any file was parsed, so nothing was compared.",
    "collector_failed": "Collecting Python call sites failed, so nothing was compared.",
    "inventory_digest_mismatch": "The CBOM does not match its recorded digest, so nothing was compared.",
    "over_candidate_limit": "The observed Python call sites exceed what the service may compare next to the software comparison, so none were compared; software results are unchanged.",
    "generator_failed": "The cryptography comparison could not be generated, so nothing was compared; software results are unchanged.",
    "shared_assembly_failure": "The combined comparison could not be assembled; it was repeated without cryptography, so nothing was compared for cryptography.",
    "shared_failure": "The combined comparison could not complete, so nothing was compared.",
    "not_attempted": "Python call sites were not collected for this analysis, so nothing was compared.",
}


MODEL_MESSAGES = {
    "completed": "Model references were observed in source and compared with the selected AI-BOM; each reference has its own verdict (declaration level only).",
    "partial_coverage": "Model-reference coverage is partial (collection stopped early or skipped files, dynamic expressions could not be resolved, other source languages exist, "
                        "candidates were truncated, or some references cannot be compared for lack of usable AI-BOM binding or scope); observed references are shown and nothing is "
                        "concluded about the rest.",
    "completed_empty_no_references": "No static model-file URL was observed in the supported source files that were read. This is not evidence that no model is used.",
    "no_recognized_source": "No source file in a form this build reads (Python, Dockerfile, shell) or another recognized language was found, so nothing was observed. This is not evidence that no model is used.",
    "only_unsupported_source": "Only source files in languages this build does not read were found, so nothing was observed. This is not evidence that no model is used.",
    "aibom_not_run": "Model references were observed, but no AI-BOM was produced for this analysis, so nothing was compared.",
    "aibom_requested_but_unavailable": "Model references were observed, but the AI-BOM producer did not deliver a document, so nothing was compared.",
    "aibom_document_unusable": "Model references were observed, but the AI-BOM document is of a form this build cannot read, so nothing was compared.",
    "aibom_document_malformed": "Model references were observed, but the AI-BOM document could not be read, so nothing was compared.",
    "aibom_output_digest_mismatch": "Model references were observed, but the AI-BOM does not match its recorded digest, so nothing was compared.",
    "incomplete_no_files": "Model-reference collection stopped before any file was read, so nothing was observed.",
    "collector_failed": "Collecting model references failed, so nothing was compared.",
    "generator_failed": "The model comparison could not be generated, so nothing was compared for models; other results are unchanged.",
    "id_collision": "The model comparison produced conflicting records, so nothing was compared for models; other results are unchanged.",
    "shared_assembly_failure": "The combined comparison could not be assembled; it was repeated without models, so nothing was compared for models.",
    "shared_failure": "The combined comparison could not complete, so nothing was compared.",
    "not_attempted": "Model references were not collected for this analysis, so nothing was compared.",
}
_MODELS_NOT_RUN = {"state": "not_run", "reason_code": "not_configured", "code": "not_attempted", "message": MODEL_MESSAGES["not_attempted"], "coverage": None,
                   "producer": None, "correspondence": None, "observed_references": 0, "observed_groups": 0}

# the binding-error set of contract UIP-13 section 7: never retried (a corrupt or unreadable source binding is not a shared payload problem)
BINDING_CODES = ("session_mismatch", "artifact_digest_mismatch", "revision_mismatch", "configuration_mismatch")


def _cancelled(ticket):
    if ticket.cancel_event.is_set():
        raise SessionError("stale_generation", "cancelled")


def _software(state, reason):
    return {"state": state, "reason_code": reason}


_CRYPTO_NOT_RUN = {"state": "not_run", "reason_code": "not_configured", "code": "not_attempted", "message": CRYPTO_MESSAGES["not_attempted"], "coverage": None,
                   "comparison": "not_run", "observed_sites": 0, "assessed_sites": 0, "observation_only": {}}


def not_attempted():
    return _collection("not_run", "not_configured", "collection_not_run", None, None)


def _collection(state, reason, code, summary, record_sha, crypto=None, models=None):
    crypto = crypto or _CRYPTO_NOT_RUN
    models = models or _MODELS_NOT_RUN
    return {"schema": SCHEMA, "software": _software(state, reason), "code": code, "message": MESSAGES[code],
            "collection": None if summary is None else {k: summary[k] for k in ("traversal", "collected", "matched", "skipped", "unsupported", "unreadable", "named_requirements") if k in summary},
            "record_sha256": record_sha,
            "cryptography": {"state": crypto["state"], "reason_code": crypto["reason_code"]}, "crypto": crypto,
            "ai_model": {"state": models["state"], "reason_code": models["reason_code"]}, "models": models}


def _is_full(summary):
    return bool(summary["traversal"]["complete"] and summary["skipped"]["count"] == 0 and summary["unsupported"]["count"] == 0
                and (summary.get("unreadable") or {}).get("count", 0) == 0)


def classify(summary):
    """(state, reason_code, code) for a finished collection that has not been compared yet, or None when it must be compared."""
    trav, collected = summary["traversal"], summary["collected"]
    unsupported, skipped = summary["unsupported"]["count"], summary["skipped"]["count"]
    if collected == 0:
        if not trav["complete"]:
            if trav["stop_reason"] == "time_budget":
                return "failed", "timeout", "collector_timeout"
            if trav["stop_reason"] == "directory_unreadable":
                return "failed", "upstream_failed", "collector_unreadable"
            return "failed", "upstream_failed", "collector_entry_cap"
        if skipped:
            return "failed", "output_invalid", "no_usable_requirement_files"
        if unsupported:
            return "unsupported", "unsupported_ecosystem", "unsupported_ecosystem"
        return "completed_empty", "no_applicable_assets", "no_requirement_files"
    if summary["named_requirements"] == 0 and _is_full(summary):
        # Only a genuinely complete collection may be ``completed_empty`` (UIP-10-IR-01). Incomplete coverage (skipped files, unsupported
        # declaration formats, an early stop, an unread directory) falls through and is compared as ``partial`` with whatever candidates exist.
        return "completed_empty", "no_applicable_assets", "no_named_requirements"
    return None


# ----------------------------------------------------------------------------------------------------- cryptography family
def crypto_state(summary, *, sites, comparison, scope_blocked, failure=None):
    """The frozen capability ``(state, reason_code, code)`` of the cryptography family: the ordered conditions of contract UIP-12 6.3
    (first match wins). Availability outranks coverage; coverage outranks per-site verdicts, which never change the state by themselves.

    ``comparison`` is one of ``performed``, ``not_run``, ``failed``, ``unsupported_document``; ``scope_blocked`` counts sites that cannot be compared
    for lack of usable CBOM scope or because they lie outside it; ``failure`` is ``(state, reason, code)`` for a hard failure (row 2)."""
    if failure:
        return failure
    py = summary["python"]
    trav = summary["traversal"]
    parsed, py_total, other = py["parsed"], py["python_files_total"], summary["other_languages"]["count"]
    if not trav["complete"] and parsed == 0:
        return ("failed", "timeout" if trav["stop_reason"] == "time_budget" else "upstream_failed", "incomplete_no_files")
    if sites >= 1 and comparison != "performed":
        if comparison == "not_run":
            return "not_run", "not_configured", "cbom_not_run"
        if comparison == "failed":
            return "failed", "scanner_failed", "cbom_failed"
        return "failed", "output_invalid", "cbom_unsupported_document"
    if py_total == 0 and other > 0 and trav["complete"] and sites == 0:
        return "unsupported", "unsupported_ecosystem", "unsupported_languages"
    mixed = parsed >= 1 and other > 0
    if not py["complete"] or mixed or scope_blocked > 0:
        return "partial", "partial_coverage", "partial_coverage"
    if sites == 0 and (parsed >= 1 or (py_total == 0 and other == 0)):
        return ("completed_empty", "no_applicable_assets", "completed_empty_python" if parsed >= 1 else "completed_empty_no_source")
    return "completed", None, "completed"


def _crypto_detail(summary, state, reason, code, *, sites, assessed, observation_only, comparison, extra=None):
    py = summary["python"]
    detail = {"state": state, "reason_code": reason, "code": code, "message": CRYPTO_MESSAGES[code],
              "coverage": {"complete": bool(py["complete"]), "count_kind": py.get("count_kind"), "python_files_total": py["python_files_total"], "parsed": py["parsed"],
                           "skipped": py["skipped"], "syntax_errors": py["syntax_errors"], "audit_failures": py["audit_failures"],
                           "sites": py["sites"], "not_parsed_time_budget": py["not_parsed_time_budget"], "over_file_limit": py["over_file_limit"],
                           "other_source_languages": summary["other_languages"], "local_module_named_hashlib": summary["local_module"],
                           "python_version": py["python_version"], "soft_budget_note": py["timing"]},
              "comparison": comparison, "observed_sites": sites, "assessed_sites": assessed, "observation_only": dict(observation_only)}
    detail.update(extra or {})
    return detail


def _select_cbom(analysis, capture, records, observations):
    """Metadata-only CBOM selection (no inventory-ID literal). Returns ``(options_cbom, hard_failure_or_None, doc_status)``."""
    inv = next((i for i in capture["inventories"] if i.get("kind") == "cbom"), None)
    if inv is None:
        return {"state": "not_run"}, None, None
    if (inv.get("acquisition") or {}).get("outcome") != "acquired" or not inv.get("source_sha256"):
        return {"state": "failed", "inventory_id": inv["inventory_id"]}, None, None
    artifact = next((r.artifact_id for r in records if r.inventory_id == inv["inventory_id"] and r.kind == "cbom"), None)
    if artifact is None:
        return {"state": "failed", "inventory_id": inv["inventory_id"]}, None, None
    try:
        raw = analysis.read(artifact)
    except SessionError:
        raise
    except (OSError, KeyError, ValueError):
        return {"state": "failed", "inventory_id": inv["inventory_id"]}, None, None
    if hashlib.sha256(raw).hexdigest() != inv["source_sha256"]:
        return {"state": "failed", "inventory_id": inv["inventory_id"]}, ("failed", "output_invalid", "inventory_digest_mismatch"), None
    prod = None
    status = "ok"
    for e in (observations or ()):
        o = e.get("observation") or {}
        if o.get("kind") == "cbom_document" and (o.get("document") or {}).get("raw_sha256") == inv["source_sha256"]:
            status = o.get("status", "ok")
            for t in o.get("producer") or []:
                if t.get("name") and t.get("version"):
                    prod = {"name": t["name"], "version": t["version"]}
                    break
    return {"state": "usable", "inventory_id": inv["inventory_id"], "sha256": inv["source_sha256"], "scan_scope": inv.get("scan_scope"), "producer": prod}, None, status


# ----------------------------------------------------------------------------------------------------- model family (UIP-13)
def _select_aibom(analysis, capture, records):
    """Metadata-only AI-BOM selection and the document-level gates D1-D5 and D6 (contract UIP-13 5.4 / 6). The producer mapping is the one of
    ``app.ai_assets.collect`` (M1-M6). Returns ``(options_aibom, producer)``; ``producer = {kind, state, reason_code, code, ...}`` where ``kind`` is
    ``not_run`` / ``failed`` / ``malformed`` / ``digest_mismatch`` / ``unusable`` / ``usable``."""
    from .scan_jobs import run_reason
    invs = [i for i in capture["inventories"] if i.get("kind") == "aibom"]
    rec = next((r for r in records if getattr(r, "kind", None) == "aibom"), None)
    if not invs and rec is None:
        return {"state": "not_run"}, {"kind": "not_run", "state": "not_run", "reason_code": "not_configured", "code": "aibom_not_run"}
    inv = invs[0] if invs else {}
    iid = inv.get("inventory_id")
    acq = inv.get("acquisition") or {}
    reason = acq.get("reason")
    state = getattr(rec, "state", None)

    def failed(code="aibom_requested_but_unavailable", why="scanner_failed", kind="failed"):
        return ({"state": "failed", "inventory_id": iid}, {"kind": kind, "state": "failed", "reason_code": why, "code": code})

    if state == "cancelled":
        return failed(why="scanner_failed")
    if state == "failed" or (state == "not_acquired" and reason not in (None, "not_run", "disabled")):
        return failed(why=run_reason(reason) if reason else "scanner_failed")
    if state == "not_acquired" or rec is None:
        why = "disabled" if reason == "disabled" else "not_configured"
        return {"state": "not_run", "inventory_id": iid}, {"kind": "not_run", "state": "not_run", "reason_code": why, "code": "aibom_not_run"}
    if state != "acquired" or not inv.get("source_sha256"):
        return failed()
    try:
        raw = analysis.read(rec.artifact_id)
    except SessionError:
        raise
    except (OSError, KeyError, ValueError):
        return failed()
    if hashlib.sha256(raw).hexdigest() != inv["source_sha256"]:
        return ({"state": "digest_mismatch", "inventory_id": iid}, {"kind": "digest_mismatch", "state": "failed", "reason_code": "output_invalid", "code": "aibom_output_digest_mismatch"})
    try:
        doc = json.loads(raw.decode("utf-8"))
        obs = aibom_document_observation(doc, inv["source_sha256"])
    except (UnicodeDecodeError, ValueError, AibomError, RecursionError):
        return ({"state": "malformed", "inventory_id": iid}, {"kind": "malformed", "state": "failed", "reason_code": "output_invalid", "code": "aibom_document_malformed"})
    producer = [{"name": t.get("name"), "version": t.get("version")} for t in (obs.get("producer") or [])[:3] if isinstance(t, dict)]
    base = {"inventory_id": iid, "sha256": inv["source_sha256"], "doc": doc, "manifest": getattr(rec, "acquisition_manifest", None),
            "scan_scope": inv.get("scan_scope"), "producer": producer, "source_file": inv.get("source_file"), "inventories": len(invs),
            "completeness": inv.get("completeness")}
    if obs.get("status") != "ok":
        return (dict(base, state="usable"), {"kind": "unusable", "state": "unsupported", "reason_code": "unsupported_ecosystem", "code": "aibom_document_unusable"})
    return dict(base, state="usable"), {"kind": "usable", "state": "usable", "reason_code": None, "code": None}


def model_state(summary, *, refs, producer, info, failure=None):
    """The frozen capability ``(state, reason_code, code)`` of the model family: the ordered rows of contract UIP-13 section 6 (first match wins).
    Availability outranks coverage; coverage outranks per-reference verdicts, which never change the state by themselves."""
    if failure:
        return failure
    m, trav = summary["models"], summary["traversal"]
    processed = m["processed"]
    if (not trav["complete"] or m["deadline_hit"]) and processed == 0:
        return ("failed", "timeout" if (m["deadline_hit"] or trav.get("stop_reason") == "time_budget") else "upstream_failed", "incomplete_no_files")
    if refs >= 1 and producer["kind"] != "usable":
        return producer["state"], producer["reason_code"], producer["code"]
    census, skipped = m["census"], m["skipped"]["count"]
    if census["matched_model_source_entries"] == 0 and trav["complete"] and skipped == 0:
        return ("unsupported", "unsupported_ecosystem", "no_recognized_source" if m["census"]["other_languages"] == 0 else "only_unsupported_source")
    mixed = processed >= 1 and m["census"]["other_languages"] > 0
    truncated = int(info.get("groups_truncated", 0)) > 0
    scope_blocked = int(info.get("scope_blocked", 0)) > 0
    if not m["complete"] or m["dynamic"]["count"] > 0 or mixed or truncated or scope_blocked:
        return "partial", "partial_coverage", "partial_coverage"
    if refs == 0 and processed >= 1:
        return "completed_empty", "no_applicable_assets", "completed_empty_no_references"
    return "completed", None, "completed"


def _models_detail(summary, state, reason, code, *, refs, groups, producer, info, extra=None):
    m = summary["models"]
    cov = {"complete": bool(m["complete"]), "count_kind": m.get("count_kind"), "selected": m["selected"], "processed": m["processed"], "skipped": m["skipped"],
           "dynamic": m["dynamic"], "references": m["references"], "census": m["census"], "diagnostics": m["diagnostics"],
           "diagnostics_total": m["diagnostics_total"], "not_processed_time_budget": m["not_processed_time_budget"], "deadline_hit": m["deadline_hit"],
           "traversal_complete": bool(summary["traversal"]["complete"]), "soft_budget_note": m["timing"]}
    prod = {k: producer.get(k) for k in ("kind", "state", "reason_code", "code")}
    prod.update({k: producer.get(k) for k in ("version", "completeness", "output_sha256", "inventory_id") if producer.get(k) is not None})
    corr = {"performed": bool(info.get("compared") or info.get("references")) and producer["kind"] == "usable", "compared_groups": int(info.get("compared", 0)),
            "groups_total": int(info.get("groups_total", groups)), "groups_shown": int(info.get("groups_shown", 0)),
            "groups_truncated": int(info.get("groups_truncated", 0)), "not_compared": dict(info.get("reasons") or {}),
            "document_reason": info.get("document_reason"), "aibom_model_entities_omitted": int(info.get("aibom_model_entities_omitted", 0))}
    detail = {"state": state, "reason_code": reason, "code": code, "message": MODEL_MESSAGES[code], "coverage": cov, "producer": prod, "correspondence": corr,
              "observed_references": refs, "observed_groups": groups}
    detail.update(extra or {})
    return detail


def _source_digests(records):
    for r in records:
        m = getattr(r, "acquisition_manifest", None)
        if isinstance(m, dict) and m.get("inputs"):
            return {i["path"]: i["sha256"] for i in m["inputs"] if isinstance(i, dict) and "path" in i and "sha256" in i}
    return None


def _failed(code, detail, summary, sha, reason="output_invalid", crypto=None, models=None):
    key = code if code in MESSAGES else ("discovery_assessment" if code.startswith("discovery_assessment_") else "discovery_payload_invalid")
    coll = _collection("failed", reason, key, summary, sha, crypto, models)
    return {"status": "not_compared", "code": code, "detail": detail}, coll


def _retryable(code, detail):
    """Contract UIP-13 7: a binding error (corrupt/unreadable source binding, stale session) is never a shared payload problem and is never retried."""
    return not (code in BINDING_CODES or (code == "dangling_reference" and detail == "artifact_unavailable"))


def _attempt(analysis, ticket, donor_bundle, sd, texts, raw_inventories, records, *, requirements, generators, report):
    """One generate -> assemble -> assess pass over one bundle. Returns ``("ok", found, outcome)`` or ``("fail", code, detail, retryable)``.
    Cancellation raises ``SessionError`` (never converted into a failure, never retried). When a model generator took part the failure detail is the
    fixed typed code only (never ``err.detail``, which can embed record ids)."""
    found = bb_discovery.discover(donor_bundle, raw_inventories=raw_inventories, source_declarations=sd, requirement_texts=texts,
                                  requirements=requirements, extra_generators=generators, generator_report=report, propagate=(SessionError,))
    _cancelled(ticket)
    models_in = any(getattr(g, "name", "") == "models" for g in generators)
    sw = report.get("software")
    if sw and sw["status"] != "ok" and not any((report.get(n) or {}).get("status") == "ok" for n in ("crypto", "models")):
        # the software generator failed (its output was discarded whole) and nothing else was generated: there is no comparison to publish
        return "fail", "software_generator_failed", (sw["code"] if models_in else sw["code"] + ": " + str(sw["detail"])), False
    try:
        assembled = assemble(analysis.context, capture=found["capture"], entities=found["entities"], observations=found["evidence"],
                             assertions=found["assertions"], input_checks=found["input_checks"], origin=found["origin"],
                             notice=found.get("notice"), artifacts=records, read_artifact=analysis.read, discovery=found["discovery"])
    except AdapterError as exc:
        err = exc.errors[0]
        text = err.code if models_in else err.code + ": " + err.detail
        if err.detail == "candidates_over_limit":
            return "fail", "discovery_candidates_over_limit", text, _retryable(err.code, err.detail)
        return "fail", "discovery_payload_invalid", text, _retryable(err.code, err.detail)
    outcome = assess(analysis.context, assembled, artifacts=records, read_artifact=analysis.read, cancel=ticket.cancel_event)
    _cancelled(ticket)
    if outcome.status == "cancelled":
        raise SessionError("stale_generation", "cancelled")
    if outcome.status != "complete":
        e0 = outcome.errors[0] if outcome.errors else None
        detail = (e0.code if models_in else e0.code + ": " + e0.detail) if e0 else outcome.status
        return "fail", "discovery_assessment_" + outcome.status, detail, _retryable(e0.code, e0.detail) if e0 else True
    return "ok", found, outcome


def _run(analysis, ticket, service, *, bundle_parts, records, sink):
    """Return ``(gaps, collection)``; raises ``SessionError`` when the generation is cancelled or superseded.

    ``gaps`` is ``{"status": "compared", "assessment": ...}`` or ``{"status": "not_compared", "code", "detail"}`` (what
    ``analysis.gaps`` holds); ``collection`` is the capability/collection state for the views. Collection problems never raise.
    """
    _cancelled(ticket)
    status = (sink or {}).get("status")
    if status == "cancelled":
        raise SessionError("stale_generation", "cancelled")
    if status != "collected":
        code = "collector_failed" if status == "failed" else "collection_not_run"
        if status == "failed":
            crypto = dict(_CRYPTO_NOT_RUN, state="failed", reason_code="upstream_failed", code="collector_failed", message=CRYPTO_MESSAGES["collector_failed"], comparison="failed")
            models = dict(_MODELS_NOT_RUN, state="failed", reason_code="upstream_failed", code="collector_failed", message=MODEL_MESSAGES["collector_failed"])
            coll = _collection("failed", "upstream_failed", code, None, None, crypto, models)
        else:
            coll = not_attempted()
        return {"status": "not_compared", "code": code, "detail": (sink or {}).get("code") or "no collection result"}, coll
    summary, record, copies, record_sha = sink["summary"], sink["record"], sink["copies"], sink["record_sha256"]

    # The derived artifact is committed only while this generation is current (commit_artifact itself rejects a stale ticket).
    service.commit_artifact(ticket, ARTIFACT, decl.bundle_bytes(sink), "application/json", "derived")
    _cancelled(ticket)

    capture = bundle_parts["capture"]
    donor_bundle = {"capture": capture, "entities": bundle_parts["entities"], "evidence": bundle_parts["observations"],
                    "assertions": bundle_parts["assertions"], "input_checks": bundle_parts["input_checks"], "origin": bundle_parts["origin"],
                    "notice": bundle_parts["notice"]}
    sites = list(record.get("crypto_call_sites") or [])
    sites_n = len(sites)
    refs_n = len(record.get("model_references") or [])
    groups_n = len({r["locator"] for r in (record.get("model_references") or [])})

    # ---- shared input: the collected record (a failure here is genuinely shared) ---------------------------------------------------------
    sd = texts = shared = None
    try:
        sd, texts = bb_discovery.read_declarations(donor_bundle, decl.canonical_bytes(record), expected_sha256=record_sha, read_copy=lambda path: copies[path])
    except bb_discovery.InputError as exc:
        shared = (exc.code, exc.detail, "output_invalid")
    except SessionError:
        raise
    except (OSError, KeyError, ValueError):
        shared = ("inputs_unavailable", "a collected input could not be read", "output_invalid")

    # ---- software family inputs ---------------------------------------------------------------------------------------------------------
    verdict = classify(summary)
    sw_hard = verdict is not None and verdict[0] != "completed_empty"
    sw_run, sw_fail, raw_inventories = False, None, {}
    if sw_hard:
        sw_fail = ("hard", verdict)
    elif shared:
        sw_fail = ("fail",) + shared
    else:
        sbom = next((i for i in capture["inventories"] if i.get("kind") == "sbom" and i.get("source_sha256")
                     and (i.get("acquisition") or {}).get("outcome") == "acquired"), None)
        artifact = next((r.artifact_id for r in records if sbom and r.inventory_id == sbom["inventory_id"] and r.kind == "sbom"), None)
        if sbom is None or artifact is None:
            sw_fail = ("fail", "inventory_unavailable", "no acquired SBOM inventory", "upstream_failed")
        else:
            try:
                raw = analysis.read(artifact)
                if hashlib.sha256(raw).hexdigest() != sbom["source_sha256"]:
                    raise bb_discovery.InputError("inventory_digest_mismatch", "the SBOM bytes do not match the recorded inventory digest")
                raw_inventories = {sbom["inventory_id"]: {"doc": json.loads(raw.decode("utf-8")), "sha256": sbom["source_sha256"]}}
                sw_run = True
            except bb_discovery.InputError as exc:
                sw_fail = ("fail", exc.code, exc.detail, "output_invalid")
            except SessionError:
                raise
            except (OSError, KeyError, StopIteration, ValueError):
                sw_fail = ("fail", "inputs_unavailable", "a collected input could not be read", "output_invalid")

    # ---- cryptography family inputs -----------------------------------------------------------------------------------------------------
    cbom, cbom_failure, doc_status = _select_cbom(analysis, capture, records, bundle_parts["observations"])
    unsupported_doc = cbom["state"] == "usable" and doc_status != "ok"
    comparison = "performed" if cbom["state"] == "usable" and not unsupported_doc else ("unsupported_document" if unsupported_doc else cbom["state"])
    crypto_failure = cbom_failure or (("failed", "output_invalid", "shared_failure") if shared else None)
    cr_gen = crypto_failure is None and sites_n > 0       # every observed site stays visible, even when no CBOM exists to compare with
    zero_state = crypto_state(summary, sites=0, comparison="performed", scope_blocked=0, failure=crypto_failure)[0] if sites_n == 0 else None
    options = {"cbom": cbom, "source_digests": _source_digests(records), "local_module": summary["local_module"]["status"], "max_candidates": 500, "total_cap": 2000}
    crypto_gen = discovery_crypto.CryptoGenerator(options) if cr_gen else None

    # ---- model family inputs (UIP-13): the generator runs iff at least one reference exists ---------------------------------------------
    aibom_opts, producer = ({"state": "not_run"}, {"kind": "not_run", "state": "not_run", "reason_code": "not_configured", "code": "aibom_not_run"})
    if refs_n >= 1 and not shared:
        aibom_opts, producer = _select_aibom(analysis, capture, records)
        producer["version"] = ", ".join(f"{t['name']} {t['version']}" for t in (aibom_opts.get("producer") or []) if t.get("name")) or None
        producer["completeness"] = aibom_opts.get("completeness")
        producer["output_sha256"] = aibom_opts.get("sha256")
        producer["inventory_id"] = aibom_opts.get("inventory_id")
    model_gen = discovery_models.ModelGenerator({"aibom": aibom_opts, "source_digests": _source_digests(records), "max_candidates": 500, "total_cap": 2000}) \
        if (refs_n >= 1 and not shared) else None
    m_zero_state = model_state(summary, refs=0, producer=producer, info={})[0] if refs_n == 0 else None
    generators = tuple(g for g in (crypto_gen, model_gen) if g is not None)

    # a comparison is performed whenever something can be compared or a frozen state needs one (completed_empty / partial ride on discovery_compared)
    need = (sw_run or bool(generators) or zero_state in ("partial", "completed_empty") or m_zero_state in ("partial", "completed_empty")) and not shared
    report = {}
    gaps = found = outcome = None
    fail = None
    dropped = set()
    if need:
        res = _attempt(analysis, ticket, donor_bundle, sd, texts, raw_inventories, records, requirements=sw_run, generators=generators, report=report)
        report1 = dict(report)      # a family that failed locally in attempt 1 must not be forgotten when a later attempt omits it (R2-01)
        if res[0] == "fail" and res[3]:
            # contract UIP-13 7: E1 = families that actually generated in attempt 1; attempt 2 = E1 without models; attempt 3 = software only
            eff = set()
            if sw_run and not (report.get("software") and report["software"]["status"] != "ok"):
                eff.add("software")
            eff |= {g.name for g in generators if (report.get(g.name) or {}).get("status") == "ok"}
            first_fail, first_report, prev, plan = res, report, set(eff), []
            for fams in (eff - {"models"}, eff - {"models", "crypto"}):
                if fams and fams != prev:
                    plan.append(fams)
                    prev = fams
            final = set(eff)
            for fams in plan:
                _cancelled(ticket)      # cancellation never retries; checked again before anything is published
                report = {}
                res = _attempt(analysis, ticket, donor_bundle, sd, texts, raw_inventories, records, requirements=("software" in fams),
                               generators=tuple(g for g in generators if g.name in fams), report=report)
                if res[0] == "ok":
                    final = fams
                    break
                if not res[3]:
                    break
            if res[0] == "fail":
                res, report = first_fail, first_report      # genuinely shared: report the original typed cause for every family
            else:
                dropped = eff - final
                for name, entry in report1.items():
                    if name not in report and entry["status"] in ("failed", "dropped"):
                        report[name] = entry
        if res[0] == "ok":
            found, outcome = res[1], res[2]
        else:
            fail = res

    def cr_detail(state, reason, code, *, assessed=0, obs=None, extra=None):
        return _crypto_detail(summary, state, reason, code, sites=sites_n, assessed=assessed, observation_only=obs or {}, comparison=comparison, extra=extra)

    def mo_detail(state, reason, code, *, info=None, extra=None):
        return _models_detail(summary, state, reason, code, refs=refs_n, groups=groups_n, producer=producer, info=info or {}, extra=extra)

    sw_gen = report.get("software")
    if sw_run and sw_gen and sw_gen["status"] != "ok":      # the software generator failed inside an otherwise good attempt; crypto's output is the bound assessment
        sw_run = False
        sw_fail = ("fail", "software_generator_failed", sw_gen["code"] + ": " + str(sw_gen["detail"]), "output_invalid")

    # ---- compose the family states -------------------------------------------------------------------------------------------------------
    if shared:
        # the collected record itself is unusable: nothing could be compared for any family
        code, detail, reason = shared
        st, rs, cd = "failed", "output_invalid", "shared_failure"
        crypto = cr_detail(st, rs, cd) if cbom_failure is None else cr_detail(*cbom_failure)
        models = mo_detail("failed", "output_invalid", "shared_failure")
        if sw_fail and sw_fail[0] == "hard":
            state, reason2, code2 = sw_fail[1]
            return {"status": "not_compared", "code": code2, "detail": MESSAGES[code2]}, _collection(state, reason2, code2, summary, record_sha, crypto, models)
        return _failed(code, detail, summary, record_sha, reason, crypto, models)
    if fail is not None:
        code, detail = fail[1], fail[2]
        crypto = cr_detail("failed", "output_invalid", "shared_failure", extra={"typed_cause": code})
        # D5 (AI-BOM bytes differ from the recorded digest) is also a corrupt source binding for the shared assembly: it fails closed, is never retried and
        # is named as such for models
        models = mo_detail("failed", "output_invalid", "aibom_output_digest_mismatch" if refs_n >= 1 and producer["kind"] == "digest_mismatch" else "shared_failure",
                           extra={"typed_cause": code})
        own = report.get("crypto")
        if code == "software_generator_failed" and own and own["status"] in ("failed", "dropped"):    # both generators failed on their own: keep crypto's own typed cause
            crypto = cr_detail("failed", "output_invalid", own["code"] if own["status"] == "dropped" else "generator_failed", extra={"typed_cause": own["code"]})
        own_m = report.get("models")
        if code == "software_generator_failed" and own_m and own_m["status"] in ("failed", "dropped"):
            models = mo_detail("failed", "output_invalid", "id_collision" if own_m["code"] == "id_collision" else "generator_failed", extra={"typed_cause": own_m["code"]})
        if sw_fail and sw_fail[0] == "hard":     # the software family had already ended on its own: keep its own typed state
            s_state, s_reason, s_code = sw_fail[1]
            return {"status": "not_compared", "code": s_code, "detail": MESSAGES[s_code]}, _collection(s_state, s_reason, s_code, summary, record_sha, crypto, models)
        if sw_fail:
            return _failed(sw_fail[1], sw_fail[2], summary, record_sha, sw_fail[3], crypto, models)
        return _failed(code, detail, summary, record_sha, "output_invalid", crypto, models)

    gen_report = report.get("crypto")
    info = dict(getattr(crypto_gen, "info", {}) or {}) if crypto_gen else {}
    failure = crypto_failure
    if "crypto" in dropped:
        failure = ("failed", "output_invalid", "shared_assembly_failure")
    elif gen_report and gen_report["status"] == "dropped":
        failure = ("failed", "output_invalid", gen_report["code"])
    elif gen_report and gen_report["status"] == "failed":
        failure = ("failed", "output_invalid", "generator_failed")
    if gen_report and gen_report["status"] == "ok":
        info = gen_report["info"]
    scope_blocked = int(info.get("scope_blocked", 0)) if not failure else 0
    state, reason, code = crypto_state(summary, sites=sites_n, comparison=comparison, scope_blocked=scope_blocked, failure=failure)
    obs = info.get("observation_only", {}) if (gen_report and gen_report["status"] == "ok") else {}
    extra = {}
    if gen_report and gen_report["status"] in ("dropped", "failed"):
        extra = {"typed_cause": gen_report["code"], "dropped_candidates": sites_n if gen_report["status"] == "dropped" else 0, "budget": gen_report["info"].get("budget")}
    crypto = cr_detail(state, reason, code, assessed=int(info.get("assessed", 0)) if (gen_report and gen_report["status"] == "ok") else 0, obs=obs, extra=extra)

    # ---- model state ----------------------------------------------------------------------------------------------------------------------
    m_report = report.get("models")
    m_failure, m_info, m_extra = None, {}, {}
    if "models" in dropped:
        m_failure = ("failed", "output_invalid", "shared_assembly_failure")
    elif m_report and m_report["status"] in ("dropped", "failed"):
        m_failure = ("failed", "output_invalid", "id_collision" if m_report["code"] == "id_collision" else "generator_failed")
        m_extra = {"typed_cause": m_report["code"]}
    elif m_report and m_report["status"] == "ok":
        m_info = m_report["info"]
    elif model_gen is not None and not need:
        m_failure = ("failed", "output_invalid", "generator_failed")
    m_state, m_reason, m_code = model_state(summary, refs=refs_n, producer=producer, info=m_info, failure=m_failure)
    models = mo_detail(m_state, m_reason, m_code, info=m_info, extra=m_extra)

    # ---- software state -------------------------------------------------------------------------------------------------------------------
    if not sw_run:
        if sw_fail and sw_fail[0] == "hard":
            s_state, s_reason, s_code = sw_fail[1]
            sw_coll = _collection(s_state, s_reason, s_code, summary, record_sha, crypto, models)
            gaps = {"status": "not_compared", "code": s_code, "detail": MESSAGES[s_code]}
        else:
            s_code, s_detail, s_reason = sw_fail[1], sw_fail[2], sw_fail[3]
            gaps, sw_coll = _failed(s_code, s_detail, summary, record_sha, s_reason, crypto, models)
        if outcome is not None:     # a crypto-only / model-only comparison exists: it is the one bound assessment
            gaps = {"status": "compared", "assessment": outcome.assessment}
        return gaps, sw_coll
    sw_cands = [c for c in found["discovery"]["candidates"] if str(c.get("group") or "").startswith("requirements:")]
    if verdict is not None and not sw_cands:
        s_state, s_reason, s_code = verdict
        return {"status": "compared", "assessment": outcome.assessment}, _collection(s_state, s_reason, s_code, summary, record_sha, crypto, models)
    full = _is_full(summary)
    coll = _collection("completed" if full else "partial", None if full else "partial_coverage", "completed" if full else "partial_coverage", summary, record_sha, crypto, models)
    return {"status": "compared", "assessment": outcome.assessment}, coll


def run(analysis, ticket, service, *, bundle_parts, records, sink):
    """``_run`` with a fault guard: anything unexpected is a typed ``failed`` state for the comparison only (never repository content),
    so the analysis keeps its valid inventory views. A cancelled or superseded generation still raises ``SessionError``."""
    try:
        return _run(analysis, ticket, service, bundle_parts=bundle_parts, records=records, sink=sink)
    except SessionError:
        raise
    except Exception as exc:
        crypto = dict(_CRYPTO_NOT_RUN, state="failed", reason_code="upstream_failed", code="collector_failed", message=CRYPTO_MESSAGES["collector_failed"], comparison="failed")
        models = dict(_MODELS_NOT_RUN, state="failed", reason_code="upstream_failed", code="collector_failed", message=MODEL_MESSAGES["collector_failed"])
        coll = _collection("failed", "upstream_failed", "collector_failed", None, None, crypto, models)
        return {"status": "not_compared", "code": "collector_failed", "detail": type(exc).__name__}, coll
