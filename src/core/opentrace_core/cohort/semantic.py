"""The semantic comparison projection ``opentrace.i3.semantic/1`` (I3-REQ-11 item 3; I2-FU-02).

Two digest classes never mix. INTEGRITY digests are raw: the exact bytes of every blob, capture and artifact, the
canonical bytes of each result including context, ids, ``issued_at``, ``deadline``, ``received_at``, ``observed_at``
and every other field, and the replay-manifest pin. This module defines only the SEMANTIC projection, used solely
to decide whether two reruns agree on meaning. It is a POSITIVE list defined by purpose and schema path (see
tools/i3/SEMANTIC_PROJECTION.md): each object type lists the fields that carry meaning; run, task and evidence ids
are replaced by ordinal labels consistently inside the document, so references still resolve. Only the declared
envelope paths are dropped. Nothing is ever removed by key NAME inside embedded third-party content (``details``
and everything below it are carried verbatim). The semantic digest is stored beside the integrity digests under its
own name and is never a pin or an integrity check.
"""
from ..canon import canonical_bytes, canonical_digest

SCHEMA = "opentrace.i3.semantic/1"

# Declared envelope paths: present in raw results and tasks, absent from the projection.
ENVELOPE_PATHS = ("/task_id", "/run_id", "/issued_at", "/deadline", "/completed_at", "/received_at", "/evidence/*/evidence_id", "/claims/*/evidence_ids/*",
                  "/evidence/*/observed_at", "/claims/*/claim_id", "/artifacts/*/captured_at", "/artifacts/*/content_b64",
                  "/artifacts/*/source_ref", "/artifacts/*/producer", "/duration_ms", "/max_rss_kb", "/captured_at",
                  "/evidence/*/observation", "/claims/*/explanation", "/claims/*/proposition", "/missing_evidence/*/detail",
                  "/errors/*/message")

CONTEXT_FIELDS = ("repo_id", "requested_revision", "observed_revision", "baseline_id", "candidate_id", "language", "build_scope")


def _context(ctx):
    return {k: ctx.get(k) for k in CONTEXT_FIELDS}


def project_result(result):
    """Projection of one result. Evidence and claim ids become ordinal labels e<N> and c<N>."""
    ev_label = {e["evidence_id"]: "e%d" % (i + 1) for i, e in enumerate(result["evidence"])}
    evidence = []
    for e in result["evidence"]:
        evidence.append({
            "label": ev_label[e["evidence_id"]], "kind": e["kind"], "dimension": e["dimension"], "locator": e["locator"],
            "subject": e["subject"], "scope": e["scope"], "limitations": e["limitations"],
            "artifact_ref": {"digest": e["artifact_ref"]["digest"], "media_type": e["artifact_ref"]["media_type"]},
            "collection_method": {"tool": e["collection_method"]["tool"], "tool_version": e["collection_method"]["tool_version"],
                                  "output_artifact": e["collection_method"]["output_artifact"]},
            "details": e.get("details")})
    claims = []
    for i, c in enumerate(result["claims"]):
        claims.append({"label": "c%d" % (i + 1), "type": c["type"], "status": c["status"], "dimension": c["dimension"],
                       "vuln_id": c.get("vuln_id"), "query_key": c.get("query_key"), "check_id": c.get("check_id"),
                       "evidence": [ev_label.get(i2, "unresolved:" + i2) for i2 in c["evidence_ids"]]})
    return {
        "schema": SCHEMA, "kind": "result", "schema_version": result["schema_version"], "status": result["status"],
        "context": _context(result["context"]), "capture_set_id": result.get("capture_set_id"),
        "producer": {"service_id": result["producer"]["service_id"], "capability_version": result["producer"]["capability_version"],
                     "operations_used": sorted(result["producer"]["operations_used"]),
                     "dimensions_used": sorted(result["producer"]["dimensions_used"])},
        "evidence": evidence, "claims": claims,
        "missing_evidence": [{"requirement_id": m["requirement_id"], "dimension": m["dimension"], "reason": m["reason"],
                              "query_key": m.get("query_key")} for m in result["missing_evidence"]],
        "artifacts": [{"digest": a["digest"], "media_type": a["media_type"], "bytes": a["bytes"], "role": a["role"]}
                      for a in result["artifacts"]],
        "warnings": list(result["warnings"]), "errors": [{"code": e["code"], "retryable": e["retryable"]} for e in result["errors"]]}


def project_task(task):
    return {"schema": SCHEMA, "kind": "task", "schema_version": task["schema_version"], "operations": sorted(task["operations"]),
            "context": _context(task["context"]), "capture_set_id": task.get("capture_set_id"),
            "requirements": [{"requirement_id": r["requirement_id"], "dimension": r["dimension"]} for r in task["requirements"]],
            "inputs": [{"digest": i["digest"], "media_type": i["media_type"], "role": i.get("role")} for i in task["inputs"]],
            "budget": task["budget"]}


def project_attachment(att):
    """Projection of one schedule entry (task, result or rejection, decision)."""
    task = att["task"]
    return {"operation": att["operation"], "task": project_task(task) if not task.get("unsent") else {"unsent": True},
            "result": project_result(att["result"]) if att.get("result") else None, "rejection": att.get("rejection"),
            "attached": bool(att.get("attached")), "run_state": att.get("run_state")}


def semantic_digests(attachments):
    """[(ordinal, operation, semantic digest)] in schedule order."""
    return [{"ordinal": i + 1, "operation": a["operation"], "semantic_digest": canonical_digest(project_attachment(a))}
            for i, a in enumerate(attachments)]


def run_semantic_digest(attachments, derived_bytes):
    """The run-level semantic digest: every task projection plus the byte digests of the derived files."""
    from ..canon import digest_of_bytes
    doc = {"schema": SCHEMA, "tasks": semantic_digests(attachments),
           "derived": {name: digest_of_bytes(data) for name, data in sorted(derived_bytes.items())}}
    return canonical_digest(doc), doc
