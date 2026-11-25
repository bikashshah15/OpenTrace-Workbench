"""AI models tab payload (UIP-07): ``opentrace.workbench.ai_assets/1``.

Pure and read-only. It projects what the analysis already recorded: the ``machine-learning-model`` components of the one AI-BOM
artifact (kind ``aibom``). It adds no collector, no rule and no verdict, never reads repository files, never knows a repository or an
inventory vendor by name, and never treats prototype data as evidence.

Frozen behaviour implemented here (contract UIP-07 v1.0.0 4.2-4.6):

* **Classification** is ordered and exhaustive (``_parse_components``): a valid distribution URL gives ``model_reference`` (the URL wins);
  everything else is ``inventory_model``. ``model_artifact``, ``runtime`` and ``ai_service`` are never emitted from production inputs and
  identity is never ``resolved``: an inventory's path or hash does not prove committed model bytes.
* **Locations** come only from relative ``evidence.occurrences`` entries. Local/absolute paths (for example in ``properties`` or
  ``bom-ref``) are never evidence and never appear in a payload. A non-relative location is dropped and counted; a relative-looking path
  that cannot be represented exactly in the frozen schema is a typed ``projection_failed`` / ``path_not_representable``. Nothing is invented.
* **Source observations (Stage 4, contract S4-AI-SOURCE)** are an additional, separately labelled producer (``opentrace-source-ai``, origin
  ``supplemental_observation``, experimental): ``runtime`` and ``ai_service`` assets and ``conditionally_selects`` links projected from the
  ``ai_source`` observations of the live source-declarations record. They are imports/literals in source text, never installed or active runtimes,
  never merged into inventory-reported models, and are absent (payload unchanged) when no such record exists (captured Demo, flag-off scans).
* **Availability** is mapped from existing records (``collect``) and decided by the exhaustive precedence shared with UIP-06
  (``crypto_assets.decide_availability``, imported, not edited).
"""
import json
import re
import threading
import weakref

from . import view_contracts as vc
from .crypto_assets import (OTHER_LABEL, ROOT_LABEL, _clean, _controls, _coverage, _fail, _pinned_link, _prov, build_groups,  # noqa: F401
                            decide_availability, encode_response)
from .workbench_binding import build_binding

LIM = vc.LIMITS
PAGE = LIM["asset_page"]
OCC_CAP = LIM["occurrences_per_asset"]
REVIEW_CAP = LIM["review_items_per_page"]
LINK_CAP = LIM["links_per_page"]
PATH_MAX = LIM["string_chars"]["path"]
FILTERS = ("all", "models", "runtimes", "ai_services", "findings")
MODEL_KINDS = ("model_artifact", "model_reference", "inventory_model")
FALLBACK_ID = "ai-inventory"
SOURCE_ID = "opentrace-source-ai"
SOURCE_SCOPE = "Experimental static source observation (runtime imports, inference-API endpoint literals, import fallbacks); absence is not established."
_OP_RUNTIME = "runtime import in source (not an installed or active runtime)"
_OP_SERVICE = "inference-API endpoint literal in source (not a reachable service)"
FAILED_REASONS = vc.REASONS_BY_STATE["failed"]
NOT_RUN_REASONS = vc.REASONS_BY_STATE["not_run"]
_PRODUCER_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_ATTRS = ("provider", "model_version", "license", "dataset_provenance", "artifact_digest", "active_configuration")
_NOT_RECORDED = "not recorded by this producer"
_DIGEST_BASIS = "hash recorded by the inventory; not a verified model digest"
_DISPLAY_RULE = "same basename shown together; identities stay separate"
_URL_PREFIX = "declared model URL: "
_URL_TOO_LONG = "declared model URL (too long to show exactly; see the AI-BOM download)"
_LOCATION_PHRASE = "inventory-reported location"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DRIVE = re.compile(r"^[A-Za-z]:")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_LOCAL_PATH = re.compile(r"""(?:^|[\s"'=,;()\[\]<>{}:|])(?:/[^\s/]|~/|\\\\|[A-Za-z]:[\\/]|file:)""", re.IGNORECASE)   # a URI scheme is case-insensitive: FILE:///, File:///


def _has_local_path(text):
    """True when an artifact-derived label contains a local path (privacy invariant N1) at a token start or right after a delimiter
    (whitespace, quote, ``= , ; ( ) [ ] < > { } | :``): absolute POSIX (``/x``), home (``~/``), drive (``C:\\``/``C:/``), UNC (``\\\\``) or ``file:``.
    So ``label:/Users/x`` is caught while ``org/model:v1``, ``https://example.com/m``, relative labels and a lone ``/`` are not."""
    return bool(_LOCAL_PATH.search(str(text or "")))


# ------------------------------------------------------------------------------------------------------------------- inputs
def _producer_parts(text):
    """``"cisco-aibom 1.10.0"`` -> (``cisco-aibom``, ``cisco-aibom 1.10.0``). The id never leaves the frozen pattern."""
    if _has_local_path(text):                    # N1: never emitted, never rewritten into another identity; the version is simply not recorded
        return FALLBACK_ID, None
    words = str(text or "").strip().split()
    head = re.sub(r"[^a-z0-9._-]", "-", words[0].lower()).lstrip("-._")[:64] if words else ""
    return (head if _PRODUCER_ID.match(head or "!") else FALLBACK_ID), (_clean(text, 64) if text else None)


def _doc_producer(doc):
    """A CycloneDX ``metadata.tools`` entry, list shape or ``components`` shape (last resort; the inventory card comes first)."""
    try:
        tools = doc["metadata"]["tools"]
        tool = (tools["components"] if isinstance(tools, dict) else tools)[0]
        return ("%s %s" % (tool["name"], tool.get("version") or "")).strip()
    except (KeyError, IndexError, TypeError):
        return None


def collect(analysis):
    """The AI-BOM facts (``_collect_aibom``) plus the Stage 4 source observations, if any (``analysis.ai_source``)."""
    out = _collect_aibom(analysis)
    src = getattr(analysis, "ai_source", None)
    out["source"] = src if isinstance(src, dict) else None
    return out


def _collect_aibom(analysis):
    """Read the recorded facts of one analysis into plain data (contract 4.6 M1-M6). The only place that touches the analysis object.

    Returns ``{"aibom": None | {...}, "mode": ...}``. ``None`` means no producer is listed (M1): no ``aibom`` record and no run, which is
    also how the bundle's ``live-aibom`` ``not_applicable`` check is represented. Free-text limitations and warnings are never parsed."""
    from .scan_jobs import run_reason
    records = [r for r in getattr(analysis, "records", ()) if getattr(r, "kind", None) == "aibom"]
    runs = [r for r in (analysis.scan or []) if isinstance(r, dict) and r.get("kind") == "aibom"]
    summary = analysis.summary or {}
    card = next((c for c in summary.get("cards", []) if c.get("kind") == "aibom"), None)
    if len(records) > 1:
        _fail("multiple_inventories", "more than one AI inventory is recorded; none is guessed")
    run = runs[0] if runs else None
    run_producer = "%s %s" % (run.get("tool") or "", run.get("version") or "") if run and run.get("tool") else None
    run_failing = run is not None and run.get("reason") not in (None, "not_run", "disabled")

    def out(artifact_id, outcome, reason, doc=None, doc_producer=None, record_counts=None):
        # the inventory card's producer (the generator) first, then the run's tool and version, then the document's own tool entry
        return {"artifact_id": artifact_id, "outcome": outcome, "reason": reason, "doc": doc, "record_counts": record_counts or {},
                "producer": (card or {}).get("producer") or run_producer or doc_producer}

    if not records and not runs:
        return {"aibom": None, "mode": analysis.mode}                                                    # M1
    if records:
        rec = records[0]
        state = getattr(rec, "state", None)
        if state == "cancelled":
            _fail("unmapped_reason", "a cancelled AI inventory has no frozen availability reason")      # M2
        if state == "failed" or (state == "not_acquired" and run_failing):
            return {"aibom": out(None, "failed", run_reason(run.get("reason")) if run else "scanner_failed"), "mode": analysis.mode}   # M3
        if state == "not_acquired":
            reason = "disabled" if run and run.get("reason") == "disabled" else "not_configured"
            return {"aibom": out(None, "not_run", reason), "mode": analysis.mode}                         # M4
        if state != "acquired":
            _fail("unmapped_reason", "an unrecognised AI inventory state is not guessed")                 # M5 (never matches acquired)
        counts = dict(getattr(rec, "record_counts", None) or {})
        try:                                                                                              # M6 (malformed)
            doc = json.loads(analysis.read(rec.artifact_id))
            if not isinstance(doc, dict) or ("components" in doc and not isinstance(doc["components"], list)):
                raise ValueError("not a CycloneDX object with a component list")
        except Exception:
            return {"aibom": out(rec.artifact_id, "failed", "output_invalid", None, None, counts), "mode": analysis.mode}
        return {"aibom": out(rec.artifact_id, "completed", None, doc, _doc_producer(doc), counts), "mode": analysis.mode}   # M7/M8 in build_model
    outcome = run.get("outcome")                                                                          # a run without a record
    if outcome == "cancelled":
        _fail("unmapped_reason", "a cancelled AI inventory has no frozen availability reason")
    if outcome == "failed" or outcome == "acquired" or run_failing:
        return {"aibom": out(None, "failed", "output_invalid" if outcome == "acquired" else run_reason(run.get("reason"))), "mode": analysis.mode}
    return {"aibom": out(None, "not_run", "disabled" if run.get("reason") == "disabled" else "not_configured"), "mode": analysis.mode}


# ------------------------------------------------------------------------------------------------------------ classification
def _relative_path(value):
    """True when ``value`` looks like a repository-relative location (contract 4.3 C3b). Anything else is not repository evidence."""
    if not value.strip() or value.startswith("/") or _DRIVE.match(value) or "\\" in value or _SCHEME.match(value):
        return False
    return not any(seg in (".", "..") for seg in value.split("/"))


def _exact_location(value, where):
    ok = 1 <= len(value) <= PATH_MAX and not any(ord(ch) < 0x20 for ch in value)
    if not ok:
        _fail("path_not_representable", "a recorded evidence path cannot be represented exactly in the frozen schema (%s)" % where, where)
    return value


def _valid_url(value):
    return (isinstance(value, str) and value != "" and not any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in value)
            and value.lower().startswith(("http://", "https://")) and len(value) > len("https://"))


def _parse_components(doc, artifact_id):
    """Ordered, exhaustive classification (contract 4.3). Returns ``(assets, unparsed)``; assets hold *all* occurrences (paging later)."""
    assets, unparsed, ordinal = [], 0, 0
    for raw_index, comp in enumerate(doc.get("components") or []):
        if not isinstance(comp, dict):                                   # C0: a non-object entry is counted, never an asset
            unparsed += 1
            continue
        if comp.get("type") != "machine-learning-model":                 # C0: other components are ignored
            continue
        k, ordinal = ordinal, ordinal + 1
        name = comp.get("name")
        if not isinstance(name, str) or not name.strip() or _has_local_path(name):   # C1 (+ N1: a local-path name is never emitted)
            unparsed += 1
            continue
        pointer = "/components/%d" % raw_index
        occs = []
        evidence = comp.get("evidence")
        raw_occ = evidence.get("occurrences") if isinstance(evidence, dict) else None
        for oi, o in enumerate(raw_occ if isinstance(raw_occ, list) else []):                        # C3
            if not isinstance(o, dict) or not isinstance(o.get("location"), str) or not _relative_path(o["location"]):
                unparsed += 1
                continue
            path = _exact_location(o["location"], "%s/evidence/occurrences/%d/location" % (pointer, oi))
            line = o.get("line") if isinstance(o.get("line"), int) and not isinstance(o.get("line"), bool) and o["line"] >= 1 else None
            occs.append({"path": path, "line": line, "index": oi, "operation": _LOCATION_PHRASE})
        urls, bad_urls = [], 0                                           # C4/C5
        for ref in comp.get("externalReferences") if isinstance(comp.get("externalReferences"), list) else []:
            if isinstance(ref, dict) and ref.get("type") == "distribution":
                if _valid_url(ref.get("url")):
                    urls.append(ref["url"])
                else:
                    bad_urls += 1
        unparsed += bad_urls + max(0, len(urls) - 1)
        kind = "model_reference" if urls else "inventory_model"
        if urls and occs:
            text = _URL_PREFIX + urls[0]
            occs[0]["operation"] = text if len(text) <= 200 else _URL_TOO_LONG
        digest = None                                                    # C6
        for h in comp.get("hashes") if isinstance(comp.get("hashes"), list) else []:
            if isinstance(h, dict) and str(h.get("alg", "")).upper() == "SHA-256" and isinstance(h.get("content"), str) and _HEX64.match(h["content"]):
                digest = h["content"]
                break
        attrs = {a: {"state": "unavailable", "value": None, "basis": _NOT_RECORDED} for a in _ATTRS}
        if digest:
            attrs["artifact_digest"] = {"state": "recorded", "value": digest, "basis": _DIGEST_BASIS}
        assets.append({"key": "ai-%d" % k, "kind": kind, "name": _clean(name, 256), "raw_name": name, "pointer": pointer,
                       "artifact_id": artifact_id, "attributes": attrs, "occurrences": occs})
    return assets, unparsed


_CLASSIFIER_KEYS = (("agentic_degraded_count", "classifier degraded"), ("agentic_skipped", "classifier skipped"),
                    ("completeness_unverified", "classifier completeness unverified"))


def _classifier_state(counts):
    """UIP-07C A1: read the three typed completeness counts the live bundle writes from the P6 mapping table.

    Returns ``(incomplete, note)``. No key present (the Demo, PR #28 records, flag-off live scans) -> ``(False, None)``: output unchanged. A present
    key that is not a non-negative ``int`` (``bool`` rejected) is read as *unverified*; more than one non-zero family is inconsistent. In every such
    case the inventory is ``partial``; nothing here invents a coverage number."""
    present = {k: counts[k] for k, _ in _CLASSIFIER_KEYS if k in counts}
    if not present:
        return False, None
    if any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in present.values()):
        return True, "classifier completeness unverified"
    nonzero = [(k, label) for k, label in _CLASSIFIER_KEYS if present.get(k)]
    if len(nonzero) > 1:
        return True, "classifier counts inconsistent"
    if nonzero:
        k, label = nonzero[0]
        return True, label + (" (%d)" % present[k] if k == "agentic_degraded_count" else "")
    return False, None


def _composition_incomplete(doc):
    comps = doc.get("compositions")
    return any(isinstance(c, dict) and isinstance(c.get("aggregate"), str) and c["aggregate"].startswith("incomplete")
               for c in (comps if isinstance(comps, list) else []))


# --------------------------------------------------------------------------------------------------------------------- model
class Model:
    """The analysis-global projection (everything except the request's filter, query, group and offset)."""

    def __init__(self, binding, assets, groups, group_ids, producers, availability, mode, links=()):
        self.binding, self.assets, self.groups, self.group_ids = binding, assets, groups, group_ids
        self.producers, self.availability, self.mode = producers, availability, mode
        self.links = list(links)


def _message(state, mode, degrading, reason, source=False):
    cap = "captured " if mode == "captured" else ""
    if source and state in ("completed", "partial", "completed_empty") and not degrading:
        if state == "completed_empty":
            return "No AI assets were recorded by the inventory or by the experimental source scan. This does not show that no AI is used."
        return ("Inventory-reported models and experimental source observations (runtime imports, endpoint literals); "
                "identity, provider and runtime use are not established.")
    if state == "completed":
        return "Inventory-reported models only; identity, provider and runtime use are not established."
    if state == "partial":
        who = ", ".join(degrading) if degrading else "the AI inventory"
        return "Collection was incomplete (%s). The models shown are those that were recorded; this is not a complete inventory." % who
    if state == "completed_empty":
        return "The %sAI inventory lists no AI assets. This does not show that no AI is used." % cap
    if state == "failed":
        return "The AI inventory collection failed (%s); no assets can be shown." % reason
    if state == "unsupported":
        return "No supported AI inventory exists for this repository; nothing was collected."
    return "No AI inventory was generated for this analysis."


def _source_assets(src):
    """Stage 4 A: runtime and service assets (one per module / endpoint, every observation an occurrence) and the preferred/fallback relations.

    Returns ``(assets, relations, summary_facts)``. A relation whose preferred or fallback import is not among the recorded runtime observations
    (for example dropped by a collection cap) is not emitted; it is counted."""
    by_key, order = {}, []

    def add(key, kind, name, occ):
        a = by_key.get(key)
        if a is None:
            attrs = {k: {"state": "unavailable", "value": None, "basis": _NOT_RECORDED} for k in _ATTRS}
            a = by_key[key] = {"origin": "supplemental", "key": key, "kind": kind, "name": _clean(name, 256), "raw_name": name, "pointer": None,
                               "artifact_id": None, "attributes": attrs, "occurrences": [], "display_group": None}
            order.append(a)
        occ["index"] = len(a["occurrences"])
        a["occurrences"].append(occ)

    def valid(o):
        return (isinstance(o.get("path"), str) and 1 <= len(o["path"]) <= PATH_MAX and not any(ord(ch) < 0x20 for ch in o["path"]) and _relative_path(o["path"]) and isinstance(o.get("file_sha256"), str) and _HEX64.match(o["file_sha256"])
                and isinstance(o.get("line"), int) and not isinstance(o.get("line"), bool) and o["line"] >= 1)
    dropped = 0
    for o in src.get("runtimes") or []:
        if not valid(o) or not isinstance(o.get("module"), str) or _has_local_path(o["module"]):
            dropped += 1
            continue
        add("src-rt|" + o["module"], "runtime", o["module"],
            {"path": _exact_location(o["path"], "source runtime path"), "line": o["line"], "end_line": o.get("end_line") or o["line"], "operation": _OP_RUNTIME,
             "file_sha256": o["file_sha256"], "excerpt": o.get("excerpt"), "ref": ("rt", o["path"], o["line"], o["module"]), "condition": None, "alt": None})
    for o in src.get("services") or []:
        if not valid(o) or not isinstance(o.get("endpoint"), str) or not _valid_url(o["endpoint"]) or _has_local_path(o["endpoint"]):
            dropped += 1
            continue
        add("src-svc|" + o["endpoint"], "ai_service", o["endpoint"],
            {"path": _exact_location(o["path"], "source service path"), "line": o["line"], "end_line": o.get("end_line") or o["line"], "operation": _OP_SERVICE,
             "file_sha256": o["file_sha256"], "excerpt": o.get("excerpt"), "ref": ("svc", o["path"], o["line"], o["endpoint"]), "condition": None, "alt": None})
    relations, unbound = [], 0
    for r in src.get("relations") or []:
        pre, fb = r.get("preferred") or {}, r.get("fallback") or {}
        cond = r.get("condition")
        if not (isinstance(r.get("path"), str) and isinstance(cond, str) and cond and len(cond) <= 200 and not any(ord(ch) < 0x20 for ch in cond)
                and isinstance(pre.get("module"), str) and isinstance(fb.get("module"), str)):
            unbound += 1
            continue
        pocc = next((x for a in order for x in a["occurrences"] if x["ref"] == ("rt", r["path"], pre.get("line"), pre["module"])), None)
        focc = next((x for a in order for x in a["occurrences"] if x["ref"] == ("rt", r["path"], fb.get("line"), fb["module"])), None)
        if pocc is None or focc is None:
            unbound += 1
            continue
        focc["condition"], focc["alt"] = cond, pocc["ref"]
        relations.append({"preferred": "src-rt|" + pre["module"], "fallback": "src-rt|" + fb["module"], "condition": cond})
    return order, relations, {"dropped": dropped, "unbound_relations": unbound}


def build_model(inputs, binding):
    digest = binding["analysis_digest"]
    mode = inputs.get("mode") or binding["mode"]
    inv = inputs.get("aibom")
    assets, producers, outcomes = [], [], []
    if inv is not None:
        doc = inv.get("doc")
        outcome, reason = inv["outcome"], inv.get("reason")
        if outcome not in ("completed", "partial", "failed", "not_run", "unsupported"):
            _fail("unmapped_outcome", "an unrecognised producer outcome is not guessed")
        if outcome == "failed" and reason not in FAILED_REASONS:
            _fail("unmapped_reason", "a failed producer needs a recorded reason in the frozen vocabulary")
        if outcome == "not_run" and reason not in NOT_RUN_REASONS:
            _fail("unmapped_reason", "a not-run producer needs a frozen reason")
        counts = inv.get("record_counts") or {}
        rec_excluded = counts.get("files_excluded") if isinstance(counts.get("files_excluded"), int) else 0
        rec_unparsed = counts.get("unparsed_total") if isinstance(counts.get("unparsed_total"), int) else 0
        unparsed, declared_incomplete = 0, False
        ai_incomplete, ai_note = _classifier_state(counts)                                                  # A1
        pid, version = _producer_parts(inv.get("producer") or (_doc_producer(doc) if doc else None))
        if doc is not None and outcome in ("completed", "partial"):
            assets, unparsed = _parse_components(doc, inv["artifact_id"])
            declared_incomplete = _composition_incomplete(doc)
            if outcome == "completed" and (rec_excluded or rec_unparsed or unparsed or declared_incomplete or ai_incomplete):   # M7 (+A1)
                outcome, reason = "partial", None
        scope = ("AI inventory (captured)" if mode == "captured" else "AI inventory") + \
                "; per-file coverage counts are not recorded in the captured artifact; zeros mean unrecorded"
        if declared_incomplete:
            scope += "; the inventory declares itself incomplete"
        if ai_note:
            scope += "; " + ai_note
        cov = _coverage(0, 0, rec_unparsed + unparsed)
        cov["files_excluded"] = rec_excluded
        producers.append({"provenance": _prov(pid, version, "original_artifact", inv.get("artifact_id"), "/components", False),
                          "scope": scope[:200], "outcome": outcome, "coverage": cov})
        outcomes.append((pid, outcome, reason))
    else:
        pid = None
    src, src_links, src_ids = inputs.get("source"), [], False
    if src is not None:
        src_ids = True
        if src.get("state") != "collected":
            producers.append({"provenance": _prov(SOURCE_ID, None, "supplemental_observation", None, None, True), "scope": SOURCE_SCOPE, "outcome": "failed",
                              "coverage": _coverage()})
            outcomes.append((SOURCE_ID, "failed", "scanner_failed"))
        else:
            sassets, srels, facts = _source_assets(src)
            summ = src.get("summary") or {}
            ok = bool(summ.get("complete")) and not facts["dropped"] and not facts["unbound_relations"]
            outcome = "completed" if ok else "partial"
            if ok and not sassets:      # a complete scan that observed nothing lists no producer: the tab's prior (accepted) state is unchanged, and no absence is claimed
                src_ids = False
                sassets = srels = None
            parsed = summ.get("parsed") if isinstance(summ.get("parsed"), int) else 0
            considered = summ.get("selected") if isinstance(summ.get("selected"), int) else 0
            if sassets is not None:
                producers.append({"provenance": _prov(SOURCE_ID, None, "supplemental_observation", None, None, True), "scope": SOURCE_SCOPE, "outcome": outcome,
                                  "coverage": _coverage(considered, parsed, max(0, considered - parsed) + facts["dropped"] + facts["unbound_relations"])})
                outcomes.append((SOURCE_ID, outcome, None))
                for a in sassets:
                    a["producer_id"] = SOURCE_ID
                assets += sassets
                src_links = srels
    groups, group_of = build_groups([o["path"] for a in assets for o in a["occurrences"]])
    gid = {}
    for g in groups:
        g["group_id"] = vc.opaque_id("grp", digest, "source", "%s|%s" % (g["kind"], g["text"]))
        gid[(g["kind"], g["text"])] = g["group_id"]
    order = {g["group_id"]: i for i, g in enumerate(groups)}
    names = {}
    for a in assets:
        if a.get("origin") != "supplemental":
            names[a["name"]] = names.get(a["name"], 0) + 1
    for a in assets:
        a["asset_id"] = vc.opaque_id("ast", digest, "asset", a["key"])
        if a.get("origin") != "supplemental":
            a["producer_id"] = pid
        a["occurrences"].sort(key=lambda o: (o["path"], o["line"] or 0, o["index"]))
        for o in a["occurrences"]:
            o["group_id"] = gid[group_of(o["path"])]
            o["occurrence_id"] = vc.opaque_id("occ", digest, "occurrence", "%s|%d|%s|%s" % (a["key"], o["index"], o["path"], o["line"]))
        a["group_ids"] = sorted({o["group_id"] for o in a["occurrences"]}, key=lambda g: order[g])
        a["order"] = (order[a["group_ids"][0]] if a["group_ids"] else len(groups), a["name"].casefold(), a["asset_id"])
        if a.get("origin") != "supplemental":
            a["display_group"] = ({"group_id": vc.opaque_id("grp", digest, "display", a["name"]), "rule": _DISPLAY_RULE} if names[a["name"]] > 1 else None)
    occ_of = {o["ref"]: o["occurrence_id"] for a in assets for o in a["occurrences"] if o.get("ref")}
    for a in assets:
        for o in a["occurrences"]:
            if o.get("alt") is not None:
                o["alt"] = occ_of[o["alt"]]
    by_key = {a["key"]: a["asset_id"] for a in assets}
    links, pairs = [], {}
    for r in src_links:
        pairs.setdefault((r["preferred"], r["fallback"]), []).append(r["condition"])
    for (pre, fb), conds in pairs.items():
        if (fb, pre) in pairs or pre not in by_key or fb not in by_key:
            continue                                   # opposite declarations in different places contradict each other: no asset-level link is drawn
        cond = conds[0] if len(conds) == 1 else ("declared in %d places: the fallback import runs if the try block raises ImportError" % len(conds))
        links.append({"relation": "conditionally_selects", "from": by_key[pre], "to": by_key[fb], "basis": "recorded", "evidence_ref": None, "condition": cond[:200]})
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
    availability = {"state": state, "reason_code": reason, "message": _message(state, mode, degrading, reason, src_ids)[:400]}
    return Model(binding, assets, groups, order, producers, availability, mode, links[:LINK_CAP])


# -------------------------------------------------------------------------------------------------------------------- payload
def _asset_payload(model, a, prioritize):
    occs = a["occurrences"]
    if prioritize:
        occs = [o for o in occs if o["group_id"] == prioritize] + [o for o in occs if o["group_id"] != prioritize]
    shown = []
    for o in occs[:OCC_CAP]:
        excerpt, state = o.get("excerpt"), "unavailable"
        if isinstance(excerpt, str) and excerpt:
            limit = LIM["string_chars"]["excerpt"]
            excerpt, state = ("".join("\ufffd" if ord(ch) < 0x20 and ch not in "\t\n" else ch for ch in excerpt), "recorded")
            if len(excerpt) > limit:
                excerpt, state = excerpt[:limit - 1] + "…", "clipped"
        else:
            excerpt = None
        cond = o.get("condition")
        shown.append({"occurrence_id": o["occurrence_id"],
                      "source_location": {"path": o["path"], "file_sha256": o.get("file_sha256"), "line_start": o["line"], "line_end": o.get("end_line") or o["line"],
                                          "excerpt": excerpt, "excerpt_state": state, "link": _pinned_link(model.binding, o["path"])},
                      "operation": o["operation"], "condition": ({"text": cond, "basis": "source_text"} if cond else {"text": None, "basis": "none"}),
                      "alternative_of": o.get("alt"), "producer_id": a["producer_id"]})
    experimental = a.get("origin") == "supplemental"
    return {"asset_id": a["asset_id"], "kind": a["kind"], "display_name": a["name"],
            "provenance": _prov(a["producer_id"], None, "supplemental_observation" if experimental else "original_artifact", a["artifact_id"], a["pointer"], experimental),
            "attributes": a["attributes"], "source_group_ids": list(a["group_ids"]), "occurrences": shown, "occurrences_total": len(occs),
            "identity_state": "unresolved", "display_group": a["display_group"]}


def _matches(a, query):
    q = query.casefold()
    return q in a["name"].casefold() or any(q in o["path"].casefold() for o in a["occurrences"])


def _page_links(model, shown_assets):
    """Links whose both ends are assets of this page (the validator requires every endpoint to be in the payload)."""
    ids = {a["asset_id"] for a in shown_assets}
    return [dict(l) for l in model.links if l["from"] in ids and l["to"] in ids]


def page_payload(model, request):
    """The request-specific slice. Pure; raises typed ``ContractError`` for invalid offsets and unknown groups."""
    flt, query, group_id, offset = request.get("filter", "all"), request.get("query", ""), request.get("group_id"), request.get("offset", 0)
    if group_id is not None and group_id not in model.group_ids:
        raise vc.ContractError("not_found", "unknown_group", "group_id", "no such source group in this analysis")
    totals = {"all": len(model.assets), "models": sum(1 for a in model.assets if a["kind"] in MODEL_KINDS),
              "runtimes": sum(1 for a in model.assets if a["kind"] == "runtime"),
              "ai_services": sum(1 for a in model.assets if a["kind"] == "ai_service"), "findings": 0}
    kinds = {"models": MODEL_KINDS, "runtimes": ("runtime",), "ai_services": ("ai_service",)}
    chosen = [a for a in model.assets if flt == "all" or (flt in kinds and a["kind"] in kinds[flt])]      # findings: none exist (FD-4)
    if query:
        chosen = [a for a in chosen if _matches(a, query)]
    if group_id is not None:
        chosen = [a for a in chosen if group_id in a["group_ids"]]
    total = len(chosen)
    if offset % PAGE != 0 or (offset != 0 if total == 0 else offset >= total):
        raise vc.ContractError("invalid_request", "offset", "offset", "the offset is not an aligned page start inside the filtered total")
    window = chosen[offset:offset + PAGE]
    assets = [_asset_payload(model, a, group_id) for a in window]
    emitted = {o["occurrence_id"] for a in assets for o in a["occurrences"]}
    for a in assets:
        for o in a["occurrences"]:
            if o["alternative_of"] is not None and o["alternative_of"] not in emitted:
                o["alternative_of"] = None          # the preferred occurrence is on another page, filtered out or beyond the per-asset cap
    used = {g for a in window for g in a["group_ids"]}
    groups = [{"group_id": g["group_id"], "label": g["label"], "path": g["path"], "assets_total": g["assets_total"]} for g in model.groups if g["group_id"] in used]
    shown = len(assets)
    return {"schema": "opentrace.workbench.ai_assets/1", "binding": model.binding, "tab": "ai", "availability": model.availability,
            "absence_established": False, "producers": model.producers, "filter": flt, "filter_totals": totals, "source_groups": groups,
            "assets": assets, "links": _page_links(model, assets), "review_items": [],
            "page": {"offset": offset, "size": PAGE, "assets_total": total, "assets_shown": shown, "has_more": offset + shown < total},
            "counts": {"total": total, "shown": shown, "truncated": shown < total}}


def build_payload(inputs, binding, request):
    model = build_model(inputs, binding)
    payload = page_payload(model, request)
    if len(payload["links"]) > LINK_CAP:
        _fail("links_exceed_bound", "links exceed the frozen bound")
    if len(payload["review_items"]) > REVIEW_CAP:
        _fail("review_items_exceed_bound", "review items exceed the frozen bound")
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
    """Validate the request, build and validate ``ai_assets/1``. Raises ``view_contracts.ContractError`` (typed)."""
    request = vc.validate_request("ai_assets", params)
    binding = build_binding(analysis)
    if request["generation"] != binding["generation"]:
        raise vc.ContractError("stale_generation", "invariant:generation", "generation", "the session has moved on")
    model = _model_for(analysis, binding)
    payload = page_payload(model, request)
    expected = {k: binding[k] for k in ("analysis_digest", "commit_sha", "repository", "requested_ref", "mode", "assessment")}
    vc.validate_payload("ai_assets", payload, request={"generation": request["generation"]}, expected_binding=expected)
    return payload
