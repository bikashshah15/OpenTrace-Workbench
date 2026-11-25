"""Cryptography tab payload (UIP-06): ``opentrace.workbench.crypto_assets/1``.

Pure and read-only. It projects what the analysis already recorded: the original CBOM's cryptographic-asset components, its endpoint
services, and (labelled experimental) the existing I5C source observations. It adds no collector, no rule and no verdict, never runs a
scanner or reads repository files, never knows a repository by name, and never treats prototype data as evidence.

Frozen behaviour implemented here (contract UIP-06 v1.0.0 4.5-4.6):

* **Exact provenance.** Evidence paths, JSON pointers and ids are copied exactly as recorded and are never clipped, ellipsized or given
  replacement characters. Only display labels are clipped, separately. A path that cannot be represented exactly in the frozen schema
  (empty, longer than 512 characters, or containing a C0 control character) is a typed ``projection_failed`` /
  ``path_not_representable`` for the whole response; nothing is repaired.
* **Bounds.** Source groups are analysis-global and never exceed 24 (one per file, else deterministic directory coarsening, else one
  "Other locations" group). At most 20 occurrences are shown per asset with the exact ``occurrences_total``; ``group_id`` only
  *prioritizes* a group's occurrences and never guarantees that every occurrence is reachable. Services are capped at 30 with counts.
  Assets are paged by aligned offsets. No links are emitted. Review items are bounded by a typed refusal guard, never truncated.
* **Availability.** Per-producer outcomes and an exhaustive first-match precedence (``decide_availability``); valid original assets
  stay visible whatever a supplemental producer did; filtering to zero never changes availability.
"""
import hashlib
import json
import re
import threading
import weakref
from urllib.parse import quote

from . import view_contracts as vc
from ..live import crypto_source as live_crypto_source
from .workbench_binding import build_binding

LIM = vc.LIMITS
PAGE = LIM["asset_page"]                      # 30
GROUP_CAP = LIM["asset_source_groups"]        # 24
OCC_CAP = LIM["occurrences_per_asset"]        # 20
REVIEW_CAP = LIM["review_items_per_page"]     # 50
LINK_CAP = LIM["links_per_page"]              # 90
SERVICE_CAP = LIM["services_per_page"]        # 30
RESPONSE_MAX_BYTES = 524288
PATH_MAX = LIM["string_chars"]["path"]        # 512
FILTERS = ("all", "findings", "algorithms", "protocols", "certificates")
ORIGINAL_ID_FALLBACK = "cbom"
SUPPLEMENTAL_ID = "opentrace-source-check"
SOURCE_ID = "opentrace-source-crypto"
SOURCE_SCOPE = "Experimental static source observation (hashlib, jwt and TLS-configuration call sites of supported forms); absence is not established."
SUPPLEMENTAL_SCOPE = "One reviewed call site on one pinned commit (experimental source observation); absence is not established."
ROOT_LABEL = "(repository root)"
OTHER_LABEL = "Other locations"
OUTCOMES = ("completed", "partial", "failed", "not_run", "unsupported")
FAILED_REASONS = vc.REASONS_BY_STATE["failed"]
NOT_RUN_REASONS = vc.REASONS_BY_STATE["not_run"]
_ENGINE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+#~=,-]{0,159}$")
_PRODUCER_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_KINDS = {"algorithm": "algorithm", "protocol": "protocol", "certificate": "certificate"}
_ATTRS = ("algorithm_name", "primitive", "parameter", "protocol_name", "protocol_version", "certificate_subject")
_NOT_RECORDED = "not recorded in the artifact"


# ----------------------------------------------------------------------------------------------------------------------- text
def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _controls(text):
    return "".join("�" if ord(ch) < 0x20 else ch for ch in text)


def _clean(text, limit):
    """Display normalization for labels and names: control characters become U+FFFD, long text ends with an ellipsis.

    Never used for evidence paths, pointers or ids (see ``_exact_path``)."""
    if text is None:
        return None
    text = _controls(str(text))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _plain(text, limit):
    """Control characters become U+FFFD, then a plain cut at ``limit`` (the derived frozen Demo fixture cuts endpoint text this way)."""
    return _controls(str(text))[:limit]


def _fail(detail, message, path=""):
    raise vc.ContractError("projection_failed", detail, path, message)


def _exact_path(value, where):
    """An evidence path is kept byte for byte or the response is refused; it is never repaired."""
    ok = isinstance(value, str) and 1 <= len(value) <= PATH_MAX and not any(ord(ch) < 0x20 for ch in value)
    if not ok:
        _fail("path_not_representable", "a recorded evidence path cannot be represented exactly in the frozen schema (%s)" % where, where)
    return value


# --------------------------------------------------------------------------------------------------------------- availability
def decide_availability(outcomes, assets_total):
    """Exhaustive first-match precedence of contract 4.6. ``outcomes``: list of (producer_id, outcome, reason) in listing order.

    Returns ``(state, reason_code, degrading_ids)``. Every combination of outcomes and asset presence maps to exactly one result."""
    kinds = [o for _, o, _ in outcomes]
    degrading = [pid for pid, o, _ in outcomes if o in ("failed", "partial")]
    has = kinds.count
    if assets_total > 0:
        return ("partial", "partial_coverage", degrading) if degrading else ("completed", None, [])          # rows 1-2
    if has("partial"):
        return "partial", "partial_coverage", degrading                                                       # row 3
    if has("failed") and has("completed"):
        return "partial", "partial_coverage", degrading                                                       # row 4
    if has("failed"):                                                                                         # row 5
        reason = next(r for _, o, r in outcomes if o == "failed")
        return "failed", reason, degrading
    if has("completed"):
        return "completed_empty", "no_applicable_assets", []                                                  # row 6
    if has("unsupported"):
        return "unsupported", "unsupported_ecosystem", []                                                     # row 7
    if has("not_run"):                                                                                        # row 8
        reason = next(r for _, o, r in outcomes if o == "not_run")
        return "not_run", reason, []
    return "not_run", "not_configured", []                                                                    # row 9


def _message(state, mode, degrading, reason, src_obs=False):
    cap = "captured " if mode == "captured" else ""
    if src_obs and state == "completed":
        return "Cryptographic assets from the original CBOM (when present) and experimental source observations; neither establishes runtime use or deployed configuration."
    if state == "completed":
        return "Cryptographic assets recorded in the original CBOM."
    if state == "partial":
        who = ", ".join(degrading) if degrading else "a producer"
        return "Collection was incomplete (%s). The assets shown are those that were recorded; this is not a complete inventory." % who
    if state == "completed_empty":
        return "The %sCBOM lists no cryptographic assets. This does not show that no cryptography is used." % cap
    if state == "failed":
        return "The cryptographic-asset collection failed (%s); no assets can be shown." % reason
    if state == "unsupported":
        return "No supported CBOM inventory exists for this repository; nothing was collected."
    return "Cryptographic-asset collection was not run for this analysis."


# ------------------------------------------------------------------------------------------------------------------- inputs
def _producer_parts(text):
    """``"cdxgen 12.9.0"`` -> (``cdxgen``, ``cdxgen 12.9.0``). The id never contains anything outside the frozen pattern."""
    words = str(text or "").strip().split()
    head = re.sub(r"[^a-z0-9._-]", "-", words[0].lower()) if words else ""
    head = head.lstrip("-._")[:64]
    return (head if _PRODUCER_ID.match(head or "!") else ORIGINAL_ID_FALLBACK), (_clean(text, 64) if text else None)


def _doc_producer(doc):
    try:
        tool = doc["metadata"]["tools"]["components"][0]
        return ("%s %s" % (tool["name"], tool["version"])).strip()
    except (KeyError, IndexError, TypeError):
        return None


def collect(analysis):
    """Read the recorded facts of one analysis into plain data. The only place that touches the analysis object."""
    records = [r for r in getattr(analysis, "records", ()) if getattr(r, "kind", None) == "cbom"]
    runs = [r for r in (analysis.scan or []) if isinstance(r, dict) and r.get("kind") == "cbom"]
    cbom = None
    summary = analysis.summary or {}
    card = next((c for c in summary.get("cards", []) if c.get("kind") == "cbom"), None)
    if records:
        rec = records[0]
        counts = dict(getattr(rec, "record_counts", None) or {})
        outcome, reason, doc = "completed", None, None
        try:
            doc = json.loads(analysis.read(rec.artifact_id))
            if not isinstance(doc, dict):
                raise ValueError("not an object")
        except Exception:                                           # an unreadable or non-JSON artifact is an invalid output
            outcome, reason, doc = "failed", "output_invalid", None
        if outcome == "completed" and (counts.get("files_excluded") or counts.get("unparsed_total")):
            outcome = "partial"
        producer = (card or {}).get("producer") or (_doc_producer(doc) if doc else None)
        cbom = {"artifact_id": rec.artifact_id, "outcome": outcome, "reason": reason, "doc": doc, "producer": producer,
                "sha256": getattr(rec, "sha256", None)}
    elif runs:
        run = runs[0]
        if run.get("outcome") == "acquired":
            cbom = {"artifact_id": None, "outcome": "failed", "reason": "output_invalid", "doc": None, "producer": None, "sha256": None}
        elif run.get("outcome") == "cancelled":
            _fail("unmapped_reason", "a cancelled CBOM run has no frozen availability reason")
        else:
            from .scan_jobs import run_reason
            cbom = {"artifact_id": None, "outcome": "failed", "reason": run_reason(run.get("reason")), "doc": None,
                    "producer": "%s %s" % (run.get("tool") or "", run.get("version") or "") if run.get("tool") else None, "sha256": None}
    source = None
    if "source_checks" in summary and summary["source_checks"] is not None:
        source = {"targets": list(summary["source_checks"]), "outcome": None, "reason": None}
    obs = getattr(analysis, "crypto_source", None)
    return {"cbom": cbom, "source": source, "src_obs": obs if isinstance(obs, dict) else None, "mode": analysis.mode}


# ------------------------------------------------------------------------------------------------------------ original assets
def _prop(component, name):
    for p in component.get("properties") or []:
        if isinstance(p, dict) and p.get("name") == name and isinstance(p.get("value"), str) and p["value"]:
            return p["value"]
    return None


def _scalar(value):
    return value if isinstance(value, str) and value.strip() else None


def _attr(value, basis):
    if value is None:
        return {"state": "unavailable", "value": None, "basis": _NOT_RECORDED}
    return {"state": "recorded", "value": _clean(value, 256), "basis": basis}


def _original_attributes(component, kind):
    cp = component.get("cryptoProperties") if isinstance(component.get("cryptoProperties"), dict) else {}
    algo = cp.get("algorithmProperties") if isinstance(cp.get("algorithmProperties"), dict) else {}
    proto = cp.get("protocolProperties") if isinstance(cp.get("protocolProperties"), dict) else {}
    cert = cp.get("certificateProperties") if isinstance(cp.get("certificateProperties"), dict) else {}
    out = {k: _attr(None, None) for k in _ATTRS}
    name = _scalar(component.get("name"))
    if kind == "algorithm" and name:
        out["algorithm_name"] = _attr(name, "component name")
    prim = _scalar(algo.get("primitive"))
    if prim:
        out["primitive"] = _attr(prim, "cryptoProperties.algorithmProperties.primitive")
    else:
        alt = _prop(component, "cdx:crypto:primitive")
        if alt:
            out["primitive"] = _attr(alt, "property cdx:crypto:primitive")
    param = _scalar(algo.get("parameterSetIdentifier"))
    if param:
        out["parameter"] = _attr(param, "cryptoProperties.algorithmProperties.parameterSetIdentifier")
    pname = _scalar(proto.get("type"))
    if pname:
        out["protocol_name"] = _attr(pname, "cryptoProperties.protocolProperties.type")
    pver = _scalar(proto.get("version"))
    if pver:
        out["protocol_version"] = _attr(pver, "cryptoProperties.protocolProperties.version")
    subj = _scalar(cert.get("subjectName"))
    if subj:
        out["certificate_subject"] = _attr(subj, "cryptoProperties.certificateProperties.subjectName")
    return out


def _pinned_link(binding, path):
    """The pinned-revision destination the frozen validator requires (no fragment; the renderer may add a line anchor). Inert when too long."""
    repo = binding["repository"]
    if any(seg in (".", "..") for seg in path.split("/")):      # a URL parser reinterprets dot segments (can leave the repository/commit): inert link, path kept exact
        return {"href": None, "text": path}
    href = "https://github.com/%s/%s/blob/%s/%s" % (repo["owner"], repo["name"], binding["commit_sha"], quote(path, safe="/"))
    return {"href": href if len(href) <= 2048 and repo["host"] == "github.com" else None, "text": path}


def _original_assets(binding, cbom, producer_id):
    """Asset records of the original CBOM with *all* their occurrences (bounding happens at page time)."""
    digest = binding["analysis_digest"]
    doc = cbom["doc"]
    out = []
    for index, comp in enumerate(doc.get("components") or []):
        if not isinstance(comp, dict):
            continue
        if comp.get("type") not in ("cryptographic-asset", "cryptographic-asset-function") and comp.get("cryptoProperties") is None:
            continue
        cp = comp.get("cryptoProperties") if isinstance(comp.get("cryptoProperties"), dict) else {}
        kind = _KINDS.get(cp.get("assetType"), "other_crypto")
        pointer = "/components/%d" % index
        key = "%s%s" % (cbom["artifact_id"], pointer)
        name = _scalar(comp.get("name")) or _scalar(comp.get("bom-ref")) or "(unnamed)"
        occs = []
        raw = ((comp.get("evidence") or {}).get("occurrences")) if isinstance(comp.get("evidence"), dict) else None
        for oi, o in enumerate(raw if isinstance(raw, list) else []):
            if not isinstance(o, dict) or not isinstance(o.get("location"), str):
                continue
            path = _exact_path(o["location"], "%s/evidence/occurrences/%d/location" % (pointer, oi))
            line = o.get("line") if isinstance(o.get("line"), int) and not isinstance(o.get("line"), bool) and o["line"] >= 1 else None
            sym = _scalar(o.get("symbol"))
            occs.append({"path": path, "line": line, "index": oi, "operation": _clean(sym, 200) if sym else None, "file_sha256": None,
                         "excerpt": None, "key": key})
        out.append({"origin": "original", "key": key, "kind": kind, "name": _clean(name, 256), "producer_id": producer_id,
                    "provenance_pointer": pointer, "artifact_id": cbom["artifact_id"], "attributes": _original_attributes(comp, kind),
                    "occurrences": occs, "reviews": []})
    return out


# --------------------------------------------------------------------------------------------------------- supplemental assets
def _ids(items, limit):
    out = []
    for item in items or []:
        value = item.get("evidence_id") if isinstance(item, dict) else item
        if isinstance(value, str) and _ENGINE_ID.match(value) and value not in out:
            out.append(value)
    return out[:limit]


def _review_for(conclusion, evidence_id):
    """Review item fields from an existing rule conclusion (FD-4). ``supported`` (the CBOM agrees) and no conclusion emit nothing."""
    if not conclusion or conclusion.get("state") in (None, "supported"):
        return None
    rule = str(conclusion.get("rule_id") or "")
    rule_id, _, version = rule.partition("/")
    codes = ", ".join(str(c) for c in (conclusion.get("reason_codes") or [])) or "none recorded"
    return {"rule_id": _clean(rule_id or "unrecorded", 120), "rule_version": _clean(version or "unrecorded", 32), "tone": "review",
            "condition": _clean("Rule state %s; reason codes %s" % (conclusion["state"], codes), 200),
            "evidence_ids": _ids([evidence_id] + list(conclusion.get("used_evidence") or []), 20),
            "rationale": _clean(conclusion.get("rationale") or "", 900) or "", "bounded_meaning": _clean(conclusion.get("bounded_meaning") or "", 400) or "",
            "next_action": _clean(conclusion.get("next_action") or "", 400) or ""}


def _supplemental_assets(source):
    """One experimental asset per observed, fully bound I5C target. Targets without path, file hash or line yield nothing."""
    assets, skipped = [], 0
    for t in source["targets"]:
        if t.get("status") != "observed":
            skipped += 1
            continue
        obs = t.get("source_observation") or {}
        path, sha, line = obs.get("path"), obs.get("file_sha256"), obs.get("line")
        if not (isinstance(path, str) and isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha) and isinstance(line, int) and line >= 1):
            skipped += 1
            continue
        path = _exact_path(path, "source observation path")
        res = obs.get("resolution") or {}
        algo = _scalar(res.get("literal_algorithm")) or "unrecorded algorithm"
        key = "source-check|%s|%d|%s" % (path, line, algo)
        conclusions = t.get("conclusions") if "conclusions" in t else [t.get("conclusion")]
        reviews = [r for r in (_review_for(c, obs.get("evidence_id")) for c in conclusions or []) if r]
        excerpt = obs.get("excerpt")
        attrs = {k: _attr(None, None) for k in _ATTRS}
        attrs["algorithm_name"] = _attr(algo, "string literal at the call site")
        assets.append({"origin": "supplemental", "key": key, "kind": "algorithm", "name": _clean(algo, 256), "producer_id": SUPPLEMENTAL_ID,
                       "provenance_pointer": None, "artifact_id": None, "attributes": attrs, "reviews": reviews,
                       "occurrences": [{"path": path, "line": line, "index": 0, "operation": _clean(res.get("call"), 200) if res.get("call") else None,
                                        "file_sha256": sha, "excerpt": excerpt if isinstance(excerpt, str) else None, "key": key}]})
    return assets, skipped


# ------------------------------------------------------------------------------------------------------------------- grouping
def build_groups(paths):
    """Analysis-global source groups (contract 4.5). Returns ``(groups, group_of)``; groups are dicts in deterministic order.

    ``group_of(path)`` -> the group key of an occurrence path. The number of groups never exceeds 24."""
    paths = list(paths)
    distinct = sorted(set(paths))

    def dir_segments(p):
        return p.split("/")[:-1]

    def spec(kind, text, label, path):
        return {"kind": kind, "text": text, "label": label, "path": path}

    if len(distinct) <= GROUP_CAP:
        groups = [spec("file", p, _clean(p, LIM["string_chars"]["label"]), p) for p in distinct]
        return groups, (lambda p: ("file", p))

    depth_of = {p: len(dir_segments(p)) for p in distinct}

    def prefix(p, d):
        segs = dir_segments(p)
        return "/".join(segs[:min(d, len(segs))])

    for d in range(max(1, max(depth_of.values())), 0, -1):
        prefixes = {prefix(p, d) for p in distinct}
        if len(prefixes) <= GROUP_CAP:
            groups = [spec("dir", pre, ROOT_LABEL if pre == "" else _clean(pre + "/", LIM["string_chars"]["label"]), pre or None) for pre in sorted(prefixes)]
            return groups, (lambda p, d=d: ("dir", prefix(p, d)))
    # even depth 1 exceeds the cap: the 23 largest top-level prefixes keep their group, the rest share "Other locations"
    top = {}
    for p in paths:                                   # occurrence counts (a path with several occurrences weighs more)
        top[prefix(p, 1)] = top.get(prefix(p, 1), 0) + 1
    keep = sorted(top, key=lambda k: (-top[k], k))[:GROUP_CAP - 1]
    groups = [spec("dir", pre, ROOT_LABEL if pre == "" else _clean(pre + "/", LIM["string_chars"]["label"]), pre or None) for pre in sorted(keep)]
    groups.append(spec("other", "", OTHER_LABEL, None))
    kept = set(keep)
    return groups, (lambda p: ("dir", prefix(p, 1)) if prefix(p, 1) in kept else ("other", ""))


# --------------------------------------------------------------------------------------------------------------------- model
class Model:
    """The analysis-global projection (everything except the request's filter, query, group and offset)."""

    def __init__(self, binding, assets, groups, group_ids, services, services_total, producers, availability, mode):
        self.binding, self.assets, self.groups, self.group_ids = binding, assets, groups, group_ids
        self.services, self.services_total = services, services_total
        self.producers, self.availability, self.mode = producers, availability, mode


def _coverage(considered=0, parsed=0, unparsed=0):
    return {"files_considered": considered, "files_parsed": parsed, "files_excluded": 0, "excluded_paths": [], "unparsed_total": unparsed,
            "unknown_dynamic_values_total": 0}


def _final_excerpt(o):
    """Defensive second pass (FR-05): whatever reaches a shown occurrence is re-tokenized; uncertain text is omitted."""
    ex = o.get("excerpt")
    if not isinstance(ex, str):
        return None
    keep = [x for x in [o.get("algorithm")] + list(o.get("algorithms") or []) if isinstance(x, str)]
    return live_crypto_source._redact(ex, keep)


def _safe_hashlib_excerpt(o):
    """The recorded excerpt starts at the line start (possibly inside a string opened on an earlier line) and may be truncated. The safe excerpt starts
    at the call's own column (a parsed position), ends at the call's closing bracket and is tokenized; anything uncertain is omitted (``None``)."""
    text, col = o.get("excerpt"), o.get("col")
    if not isinstance(text, str) or not isinstance(col, int) or isinstance(col, bool) or col < 0:
        return None
    first, sep, rest = text.partition("\n")
    raw = first.encode("utf-8", "surrogatepass")
    if col > len(raw):
        return None
    try:
        tail = raw[col:].decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not re.match(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*\s*\(", tail):      # the text at (line, col) must be the call's own dotted name
        return None
    return live_crypto_source._redact(tail + sep + rest, [o["algorithm"]] if isinstance(o.get("algorithm"), str) else [], stop_at_call=True)


def _prov(pid, version, origin, artifact_id, pointer, experimental):
    return {"producer_id": pid, "producer_version": version, "origin": origin, "artifact_id": artifact_id, "json_pointer": pointer, "experimental": experimental}


def _rel_ok(value):
    """A repository-relative path: never absolute, drive/UNC/scheme-qualified, backslashed or dot-segmented (such a record is dropped, never rewritten)."""
    return bool(value.strip()) and not (value.startswith("/") or re.match(r"^[A-Za-z]:", value) or "\\" in value or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value)
                                         or any(seg in (".", "..") for seg in value.split("/")))


_TLS_REVIEW = {("tls_insecure_set", "True"), ("check_hostname", "False"), ("verify_mode", "CERT_NONE")}
_TLS_NAME = {"mqtt_tls_set": "MQTT TLS configuration", "mqtt_tls_insecure_set": "MQTT TLS configuration"}
_HASHLIB_OP = {"pbkdf2_hmac": "hashlib.pbkdf2_hmac call", "scrypt": "hashlib.scrypt call", "hash": "hashlib hash call"}


def _review_condition(setting, val, path, line):
    """One review per place: the condition always ends with ``:line`` and carries a short digest of the full path, so a long path never makes two places collide after the 200-character cut."""
    head = "Source sets %s to %s at " % (setting, val)
    plain = "%s%s:%d" % (head, path, line)
    if len(plain) <= 200:
        return _clean(plain, 200)
    tail = ":%d [%s]" % (line, _sha("path|" + path)[:8])
    room = 200 - len(head) - len(tail)
    shown = path if len(path) <= room else "…" + path[-(max(room, 2) - 1):]
    return _clean(head + shown + tail, 200)


def _src_obs_assets(obs):
    """Stage 4 B: assets from hashlib / jwt / TLS source observations. Returns ``(assets, dropped)``. Every asset is experimental; none is a CBOM record."""
    by_key, order, dropped = {}, [], 0

    def valid(o):
        return (isinstance(o.get("path"), str) and 1 <= len(o["path"]) <= PATH_MAX and not any(ord(ch) < 0x20 for ch in o["path"]) and _rel_ok(o["path"]) and isinstance(o.get("file_sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", o["file_sha256"])
                and isinstance(o.get("line"), int) and not isinstance(o.get("line"), bool) and o["line"] >= 1)

    def add(key, kind, name, attrs, operation, o, review=None):
        a = by_key.get(key)
        if a is None:
            base = {k: _attr(None, None) for k in _ATTRS}
            base.update(attrs)
            a = by_key[key] = {"origin": "supplemental", "key": key, "kind": kind, "name": _clean(name, 256), "producer_id": SOURCE_ID, "provenance_pointer": None,
                               "artifact_id": None, "attributes": base, "reviews": [], "occurrences": []}
            order.append(a)
        a["occurrences"].append({"path": _exact_path(o["path"], "source observation path"), "line": o["line"], "index": len(a["occurrences"]),
                                 "operation": _clean(operation, 200), "file_sha256": o["file_sha256"], "excerpt": _final_excerpt(o), "key": key})
        if review is not None and review["condition"] not in {r["condition"] for r in a["reviews"]}:
            a["reviews"].append(review)

    for o in obs.get("hashlib") or []:
        if not valid(o):
            dropped += 1
            continue
        if isinstance(o.get("excerpt"), str):          # a hashlib call may carry a literal password/salt: shown excerpts never carry string literals (the algorithm literal is kept)
            o = dict(o, excerpt=_safe_hashlib_excerpt(o))
        alg = _scalar(o.get("algorithm")) if o.get("algorithm_resolved") else None
        op = _HASHLIB_OP.get(o.get("operation"), "hashlib call")
        if o.get("binding_status") != "unique_module_level":
            add("src-hl|binding", "other_crypto", "hashlib call (binding not established)", {}, op, o)      # shadowed/rebound/non-module-level name: not claimed
        elif alg:
            add("src-hl|" + alg, "algorithm", alg, {"algorithm_name": _attr(alg, "algorithm named at a hashlib call site")}, op, o)
        else:
            add("src-hl|unresolved", "other_crypto", "hashlib call (algorithm not resolved)", {}, op, o)
    for o in obs.get("jwt") or []:
        if not valid(o) or o.get("call") not in ("jwt.encode", "jwt.decode"):
            dropped += 1
            continue
        algs, src = o.get("algorithms"), o.get("algorithm_source")
        if src == "literal" and isinstance(algs, list) and algs and all(isinstance(x, str) and x for x in algs):
            for alg in sorted(set(algs)):
                add("src-jwt|" + alg, "algorithm", alg, {"algorithm_name": _attr(alg, "string literal at a jwt call")}, "%s call" % o["call"], o)
        elif src in ("not_stated", "dynamic", "empty"):
            add("src-jwt|" + src, "other_crypto", "JWT call (algorithm %s)" % {"not_stated": "not stated", "dynamic": "dynamic", "empty": "list empty"}[src], {}, "%s call" % o["call"], o)
        else:
            dropped += 1
    for o in obs.get("tls") or []:
        if not valid(o) or not isinstance(o.get("form"), str) or not isinstance(o.get("setting"), str):
            dropped += 1
            continue
        name = _TLS_NAME.get(o["form"], "TLS context configuration (ssl module)")
        val = o.get("value") if isinstance(o.get("value"), str) else None
        attrs = {"protocol_name": _attr("TLS", "name of the called API or assigned attribute")}
        # a version/protocol constant is shown on its own occurrence (operation text), never as an asset-level attribute: one asset aggregates several places
        op = "%s(%s)" % (o["setting"], val if val else "") if o["form"] in ("mqtt_tls_set", "mqtt_tls_insecure_set", "ssl_default_context", "ssl_context") else \
             "%s = %s" % (o["setting"], val if val else "")
        review = None
        if (o["setting"], val) in _TLS_REVIEW:
            review = {"rule_id": "source-observation.tls_verification_relaxed", "rule_version": "1", "tone": "review",
                      "condition": _review_condition(o["setting"], val, o["path"], o["line"]), "evidence_ids": [],
                      "rationale": "This source line relaxes certificate or hostname verification for a TLS connection.",
                      "bounded_meaning": "Conditional review item, not a confirmed vulnerability: whether this code runs, and whether it reaches a deployed configuration, is not established.",
                      "next_action": "Check whether this setting is configurable or test-only before relying on it."}
        add("src-tls|" + name, "protocol", name, attrs, op, o, review)
    return order, dropped


def build_model(inputs, binding):
    digest = binding["analysis_digest"]
    mode = inputs.get("mode") or binding["mode"]
    cbom, source = inputs.get("cbom"), inputs.get("source")
    assets, producers, outcomes, services, services_total = [], [], [], [], 0
    orig_id = None
    if cbom is not None:
        orig_id, version = _producer_parts(cbom.get("producer"))
        outcome, reason = cbom["outcome"], cbom.get("reason")
        if outcome not in OUTCOMES:
            _fail("unmapped_outcome", "an unrecognised producer outcome is not guessed")
        if outcome == "failed" and reason not in FAILED_REASONS:
            _fail("unmapped_reason", "a failed producer needs a recorded reason in the frozen vocabulary")
        if outcome == "not_run" and reason not in NOT_RUN_REASONS:
            reason = "not_configured" if reason is None else _fail("unmapped_reason", "a not-run producer needs a frozen reason")
        doc = cbom.get("doc")
        if doc is not None and outcome in ("completed", "partial"):
            assets += _original_assets(binding, cbom, orig_id)
            svcs = []
            for si, rec in enumerate(doc.get("services") or []):
                if not isinstance(rec, dict):
                    continue
                sid = "%s/services/%d" % (cbom["artifact_id"], si)
                name = _plain(rec.get("name") or sid, 256) or sid
                svcs.append({"service_id": sid[:160], "name": name, "endpoint_text": _plain(rec.get("endpoints") or rec.get("endpoint") or "", 512),
                             "provenance": _prov(orig_id, None, "original_artifact", cbom["artifact_id"], "/services", False)})
            svcs.sort(key=lambda s: (s["name"], s["service_id"]))
            services_total, services = len(svcs), svcs[:SERVICE_CAP]
        if mode == "captured":
            scope = "cdxgen over the whole repository (captured); per-file coverage counts are not recorded in the captured artifact; zeros mean unrecorded"
        else:
            scope = "cdxgen over the acquired source tree at the pinned commit; per-file coverage counts are not recorded in the artifact; zeros mean unrecorded"
        producers.append({"provenance": _prov(orig_id, version, "original_artifact", cbom.get("artifact_id"), "/components", False),
                          "scope": scope[:200], "outcome": outcome, "coverage": _coverage()})
        outcomes.append((orig_id, outcome, reason))
    if source is not None:
        targets = source["targets"]
        sup, skipped = _supplemental_assets(source) if source.get("outcome") is None else ([], 0)
        outcome, reason = source.get("outcome"), source.get("reason")
        if outcome is None:
            observed = sum(1 for t in targets if t.get("status") == "observed")
            outcome = "not_run" if not targets else ("completed" if skipped == 0 else "partial")
            reason = "not_configured" if outcome == "not_run" else None
            parsed = len(sup)
        else:
            parsed = 0
        if outcome == "failed" and reason not in FAILED_REASONS:
            _fail("unmapped_reason", "a failed producer needs a recorded reason in the frozen vocabulary")
        if outcome == "not_run" and reason not in NOT_RUN_REASONS:
            reason = "not_configured"
        assets += sup
        producers.append({"provenance": _prov(SUPPLEMENTAL_ID, None, "supplemental_observation", None, None, True), "scope": SUPPLEMENTAL_SCOPE,
                          "outcome": outcome, "coverage": _coverage(len(targets), parsed if outcome != "not_run" else 0, skipped)})
        outcomes.append((SUPPLEMENTAL_ID, outcome, reason))
    obs, src_flag = inputs.get("src_obs"), False
    if obs is not None:
        if obs.get("state") != "collected":
            src_flag = True
            producers.append({"provenance": _prov(SOURCE_ID, None, "supplemental_observation", None, None, True), "scope": SOURCE_SCOPE, "outcome": "failed",
                              "coverage": _coverage()})
            outcomes.append((SOURCE_ID, "failed", "scanner_failed"))
        else:
            sup_assets, dropped = _src_obs_assets(obs)
            summ = obs.get("summary") or {}
            ok = bool(summ.get("complete")) and bool(obs.get("hashlib_complete")) and not dropped
            if not (ok and not sup_assets):          # a complete scan that observed nothing lists no producer (prior state unchanged; no absence claimed)
                src_flag = True
                considered = summ.get("selected") if isinstance(summ.get("selected"), int) else 0
                parsed = summ.get("parsed") if isinstance(summ.get("parsed"), int) else 0
                outcome = "completed" if ok else "partial"
                producers.append({"provenance": _prov(SOURCE_ID, None, "supplemental_observation", None, None, True), "scope": SOURCE_SCOPE, "outcome": outcome,
                                  "coverage": _coverage(considered, parsed, max(0, considered - parsed) + dropped)})
                outcomes.append((SOURCE_ID, outcome, None))
                assets += sup_assets
    # groups are analysis-global: every occurrence path of every asset
    groups, group_of = build_groups([o["path"] for a in assets for o in a["occurrences"]])
    gid = {}
    for g in groups:
        g["group_id"] = vc.opaque_id("grp", digest, "source", "%s|%s" % (g["kind"], g["text"]))
        gid[(g["kind"], g["text"])] = g["group_id"]
    order = {g["group_id"]: i for i, g in enumerate(groups)}
    for a in assets:
        a["asset_id"] = vc.opaque_id("ast", digest, "asset", a["key"])
        a["occurrences"].sort(key=lambda o: (o["path"], o["line"] or 0, o["index"]))
        for o in a["occurrences"]:
            o["group_id"] = gid[group_of(o["path"])]
            o["occurrence_id"] = vc.opaque_id("occ", digest, "occurrence", "%s|%d|%s|%s" % (a["key"], o["index"], o["path"], o["line"]))
        a["group_ids"] = sorted({o["group_id"] for o in a["occurrences"]}, key=lambda g: order[g])
        a["order"] = (order[a["group_ids"][0]] if a["group_ids"] else len(groups), a["name"].casefold(), a["asset_id"])
        for r in a["reviews"]:
            r["review_id"] = "rev:" + _sha("review|%s|%s" % (a["asset_id"], r["rule_id"] + ("|" + r["condition"] if r["rule_id"].startswith("source-observation.") else "")))[:24]
    assets.sort(key=lambda a: a["order"])
    per_group = {}
    for a in assets:
        for g in a["group_ids"]:
            per_group[g] = per_group.get(g, 0) + 1
    for g in groups:
        g["assets_total"] = per_group.get(g["group_id"], 0)
    state, reason, degrading = decide_availability(outcomes, len(assets))
    if state == "failed" and reason not in FAILED_REASONS:
        _fail("unmapped_reason", "a failed availability needs a frozen reason")
    availability = {"state": state, "reason_code": reason, "message": _message(state, mode, degrading, reason, src_flag)[:400]}
    return Model(binding, assets, groups, order, services, services_total, producers, availability, mode)


# -------------------------------------------------------------------------------------------------------------------- payload
def _asset_payload(model, a, prioritize):
    occs = a["occurrences"]
    if prioritize:
        occs = [o for o in occs if o["group_id"] == prioritize] + [o for o in occs if o["group_id"] != prioritize]
    shown = []
    for o in occs[:OCC_CAP]:
        excerpt = o["excerpt"]
        state = "unavailable"
        if excerpt is not None:
            state = "recorded"
            if len(excerpt) > LIM["string_chars"]["excerpt"]:
                excerpt, state = excerpt[: LIM["string_chars"]["excerpt"] - 1] + "…", "clipped"
            excerpt = "".join("\ufffd" if ord(ch) < 0x20 and ch not in "\t\n" else ch for ch in excerpt)
        line = o["line"]
        shown.append({"occurrence_id": o["occurrence_id"],
                      "source_location": {"path": o["path"], "file_sha256": o["file_sha256"], "line_start": line, "line_end": line, "excerpt": excerpt,
                                          "excerpt_state": state, "link": _pinned_link(model.binding, o["path"])},
                      "operation": o["operation"], "condition": {"text": None, "basis": "none"}, "alternative_of": None, "producer_id": a["producer_id"]})
    experimental = a["origin"] == "supplemental"
    return {"asset_id": a["asset_id"], "kind": a["kind"], "display_name": a["name"],
            "provenance": _prov(a["producer_id"], None, "supplemental_observation" if experimental else "original_artifact", a["artifact_id"],
                                a["provenance_pointer"], experimental),
            "attributes": a["attributes"], "source_group_ids": list(a["group_ids"]), "occurrences": shown, "occurrences_total": len(occs)}


def _matches(a, query):
    q = query.casefold()
    return q in a["name"].casefold() or any(q in o["path"].casefold() for o in a["occurrences"])


def page_payload(model, request):
    """The request-specific slice. Pure; raises typed ``ContractError`` for invalid offsets and unknown groups."""
    flt, query, group_id, offset = request.get("filter", "all"), request.get("query", ""), request.get("group_id"), request.get("offset", 0)
    if group_id is not None and group_id not in model.group_ids:
        raise vc.ContractError("not_found", "unknown_group", "group_id", "no such source group in this analysis")
    kinds = {"algorithms": "algorithm", "protocols": "protocol", "certificates": "certificate"}
    findings = lambda a: bool(a["reviews"])                                                   # noqa: E731
    totals = {"all": len(model.assets), "findings": sum(1 for a in model.assets if findings(a)),
              "algorithms": sum(1 for a in model.assets if a["kind"] == "algorithm"),
              "protocols": sum(1 for a in model.assets if a["kind"] == "protocol"),
              "certificates": sum(1 for a in model.assets if a["kind"] == "certificate")}
    chosen = [a for a in model.assets if (flt == "all" or (flt == "findings" and findings(a)) or (flt in kinds and a["kind"] == kinds[flt]))]
    if query:
        chosen = [a for a in chosen if _matches(a, query)]
    if group_id is not None:
        chosen = [a for a in chosen if group_id in a["group_ids"]]
    total = len(chosen)
    if offset % PAGE != 0 or (offset != 0 if total == 0 else offset >= total):
        raise vc.ContractError("invalid_request", "offset", "offset", "the offset is not an aligned page start inside the filtered total")
    window = chosen[offset:offset + PAGE]
    assets = [_asset_payload(model, a, group_id) for a in window]
    reviews = []
    for a in window:
        for r in a["reviews"]:
            reviews.append({"review_id": r["review_id"], "asset_id": a["asset_id"], "rule_id": r["rule_id"], "rule_version": r["rule_version"],
                            "tone": r["tone"], "condition": r["condition"], "evidence_ids": r["evidence_ids"], "rationale": r["rationale"],
                            "bounded_meaning": r["bounded_meaning"], "next_action": r["next_action"]})
    if len(reviews) > REVIEW_CAP:
        _fail("review_items_exceed_bound", "this page would need %d review items; the frozen schema allows %d" % (len(reviews), REVIEW_CAP))
    used = {g for a in window for g in a["group_ids"]}
    groups = [{"group_id": g["group_id"], "label": g["label"], "path": g["path"], "assets_total": g["assets_total"]} for g in model.groups if g["group_id"] in used]
    shown = len(assets)
    sv = model.services
    return {"schema": "opentrace.workbench.crypto_assets/1", "binding": model.binding, "tab": "crypto", "availability": model.availability,
            "absence_established": False, "producers": model.producers, "filter": flt, "filter_totals": totals, "source_groups": groups,
            "assets": assets, "links": [], "review_items": reviews,
            "page": {"offset": offset, "size": PAGE, "assets_total": total, "assets_shown": shown, "has_more": offset + shown < total},
            "counts": {"total": total, "shown": shown, "truncated": shown < total},
            "services": sv, "services_counts": {"total": model.services_total, "shown": len(sv), "truncated": len(sv) < model.services_total}}


def build_payload(inputs, binding, request):
    model = build_model(inputs, binding)
    payload = page_payload(model, request)
    if len(payload["links"]) > LINK_CAP:
        _fail("links_exceed_bound", "links exceed the frozen bound")
    return payload


# ----------------------------------------------------------------------------------------------------------------------- route
_LOCK = threading.Lock()
_CACHE = weakref.WeakKeyDictionary()        # analysis -> (analysis_digest, Model)


def _model_for(analysis, binding):
    with _LOCK:
        hit = _CACHE.get(analysis)
    if hit is not None and hit[0] == binding["analysis_digest"]:
        return hit[1]
    model = build_model(collect(analysis), binding)
    with _LOCK:
        _CACHE[analysis] = (binding["analysis_digest"], model)
    return model


def respond(analysis, params):
    """Validate the request, build and validate ``crypto_assets/1``. Raises ``view_contracts.ContractError`` (typed)."""
    request = vc.validate_request("crypto_assets", params)
    binding = build_binding(analysis)
    if request["generation"] != binding["generation"]:
        raise vc.ContractError("stale_generation", "invariant:generation", "generation", "the session has moved on")
    model = _model_for(analysis, binding)
    payload = page_payload(model, request)
    expected = {k: binding[k] for k in ("analysis_digest", "commit_sha", "repository", "requested_ref", "mode", "assessment")}
    vc.validate_payload("crypto_assets", payload, request={"generation": request["generation"]}, expected_binding=expected)
    return payload


def encode_response(payload):
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(body) > RESPONSE_MAX_BYTES:
        raise vc.ContractError("response_too_large", "bound_exceeded", "", "%d bytes exceeds the %d byte ceiling" % (len(body), RESPONSE_MAX_BYTES))
    return body
