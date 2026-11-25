"""Deterministic conclusion projection (I2-REQ-08 item 4).

``derive_conclusion(attachments, labels=None)`` takes the recorded attachments of ONE investigation
and returns a JSON-able dict that is sorted, carries no clock reading of its own and includes
digests. Replay re-derives it from recorded data and compares digests; the Investigator's
``next_step`` is added outside this function and is reported as recorded.

An attachment is a dict: ``task``, ``result`` (or None), ``rejection`` (or None), ``origin``
(``fresh`` / ``reused``), ``reused_from`` (or None), ``received_at``, ``control`` (bool).
Control attachments never contribute evidence. The baseline ``change_validate`` is attached once;
each candidate comparison reads it with origin ``reused`` and the original run, task, observed and
receipt times, never new ones.
"""
from . import change as ch
from .canon import canonical_digest

SCHEMA = "opentrace.conclusion/1"


def _op(att):
    return att["task"]["operations"][0]


def _variant(att, labels):
    cid = att["task"]["context"].get("candidate_id")
    return "baseline" if cid is None else (labels or {}).get(cid, cid)


def _observed_at(result):
    stamps = sorted(e["observed_at"] for e in (result or {}).get("evidence", []))
    return stamps[0] if stamps else None


def _group(att, labels):
    result = att.get("result")
    return {"task_id": att["task"]["task_id"], "run_id": att["task"]["run_id"], "operation": _op(att),
            "variant": _variant(att, labels), "origin": att.get("origin", "fresh"),
            "status": result.get("status") if result else None,
            "rejection": att.get("rejection"),
            "result_digest": canonical_digest(result) if result else None,
            "evidence_ids": sorted(e["evidence_id"] for e in result["evidence"]) if result else []}


def _claims(att, labels):
    result = att.get("result") or {}
    out = []
    for c in result.get("claims", []):
        out.append({"variant": _variant(att, labels), "operation": _op(att), "type": c["type"], "status": c["status"],
                    "vuln_id": c.get("vuln_id"), "check_id": c.get("check_id"), "claim_id": c["claim_id"]})
    return out


def _unknowns(att, labels):
    result = att.get("result") or {}
    out = [{"variant": _variant(att, labels), "operation": _op(att), "requirement_id": m["requirement_id"],
            "reason": m["reason"]} for m in result.get("missing_evidence", [])]
    out += [{"variant": _variant(att, labels), "operation": _op(att), "vuln_id": c.get("vuln_id"),
             "reason": c["type"]} for c in result.get("claims", []) if c["status"] == "unknown"]
    if att.get("rejection"):
        out.append({"variant": _variant(att, labels), "operation": _op(att), "requirement_id": None,
                    "reason": att["rejection"]})
    return out


def _side(att, by_variant, labels, op):
    for a in by_variant.get(_variant(att, labels), []):
        if _op(a) == op:
            return a
    return None


def derive_conclusion(attachments, labels=None):
    inv = [a for a in attachments if not a.get("control")]
    controls = [a for a in attachments if a.get("control")]
    by_variant = {}
    for a in inv:
        by_variant.setdefault(_variant(a, labels), []).append(a)

    def op_of(variant, op):
        for a in by_variant.get(variant, []):
            if _op(a) == op:
                return a
        return None

    base_change = op_of("baseline", "change_validate")
    base_osv, base_vuln = op_of("baseline", "osv_advisory_match"), op_of("baseline", "govulncheck_source")
    families = []
    if base_osv and base_osv.get("result"):
        for e in base_osv["result"]["evidence"]:
            if e["kind"] == "advisory_match":
                d = e["details"]
                families.append({"vuln_id": d["vuln_id"], "withdrawn": bool(d.get("withdrawn")),
                                 "aliases": sorted(d.get("aliases") or []), "module": e["subject"].get("module"),
                                 "version": e["subject"].get("version")})
    families.sort(key=lambda f: (f["vuln_id"], f["module"] or ""))

    call_use = {}
    view = ch.call_use_view(base_vuln["result"]) if base_vuln else None
    if view and view["complete"]:
        for vid in view["paths"]:
            call_use[vid] = "static_call_path_found"
        for vid in view["not_established"]:
            call_use.setdefault(vid, "call_path_not_established")

    comparisons = {}
    run_ids = {a["task"]["run_id"] for a in inv}
    if base_change is not None:
        baseline = {"task": base_change["task"], "result": base_change.get("result"), "rejection": base_change.get("rejection"),
                    "osv": base_osv.get("result") if base_osv else None, "vuln": base_vuln.get("result") if base_vuln else None,
                    "origin": "reused", "received_at": base_change.get("received_at"), "run_final": base_change.get("run_final", True),
                    "reused_from": {"run_id": base_change["task"]["run_id"], "task_id": base_change["task"]["task_id"],
                                    "observed_at": _observed_at(base_change.get("result")),
                                    "received_at": base_change.get("received_at")}}
        for variant in sorted(v for v in by_variant if v != "baseline"):
            cand = op_of(variant, "change_validate")
            if cand is None:
                continue
            osv, vuln = op_of(variant, "osv_advisory_match"), op_of(variant, "govulncheck_source")
            side = {"task": cand["task"], "result": cand.get("result"), "rejection": cand.get("rejection"),
                    "osv": osv.get("result") if osv else None, "vuln": vuln.get("result") if vuln else None,
                    "origin": "fresh", "received_at": cand.get("received_at")}
            comparisons[variant] = ch.evaluate_change(baseline, side, run_ids)

    conclusion = {
        "schema": SCHEMA,
        "groups": sorted((_group(a, labels) for a in inv), key=lambda g: g["task_id"]),
        "supported_claims": sorted((c for a in inv for c in _claims(a, labels) if c["status"] == "supported"),
                                   key=lambda c: (c["variant"], c["claim_id"])),
        "unknowns": sorted((u for a in inv for u in _unknowns(a, labels)),
                           key=lambda u: (u["variant"], u["operation"], str(u.get("requirement_id")), str(u.get("vuln_id")), u["reason"])),
        "advisory_families": families,
        "call_use": dict(sorted(call_use.items())),
        "change_comparisons": comparisons,
        "controls": sorted(({"task_id": a["task"]["task_id"], "operation": _op(a), "rejection": a.get("rejection"),
                             "status": (a.get("result") or {}).get("status")} for a in controls), key=lambda c: c["task_id"]),
        "task_counts": {"investigation": len(inv), "control": len(controls)},
    }
    ch.assert_no_forbidden_wording(conclusion)
    return conclusion


def conclusion_digest(conclusion):
    return canonical_digest(conclusion)
