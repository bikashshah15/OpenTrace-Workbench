"""UIP-01B: validators for the versioned Workbench view contracts (``opentrace.workbench.*/1``).

Two layers, as in ``contracts/analysis/v1``:

* **structural** - a small stdlib interpreter of the JSON Schema subset the schema files use (type, const, enum, required,
  properties, additionalProperties, items, min/max length/items/value, pattern, anyOf, ``$ref`` into ``common.schema.json``).
  JSON Schema itself is the same rule set; tests cross-check the two engines on structural cases.
* **semantic** - every cross-record, graph, arithmetic, state-transition and external-binding invariant of contract
  ``UIP-01B.md`` section 4. JSON Schema is not asked to express these.

No I/O except loading the schema files once, no engine imports, no network. Nothing here is wired to a route.
"""
import hashlib
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
CONTRACT_DIR = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "contracts", "workbench", "v1"))

with open(os.path.join(CONTRACT_DIR, "limits.json"), encoding="utf-8") as _handle:
    LIMITS = json.load(_handle)

PAYLOADS = ("scan_status", "contexts", "dependency_page", "crypto_assets", "ai_assets", "inspector",
            "bom_candidates", "bom_graph", "bom_related_checks", "error")
SCHEMA_IDS = {n: "opentrace.workbench.%s/1" % n for n in PAYLOADS}
ROUTE_KEYS = ("scan_status", "contexts", "dependency_page", "crypto_assets", "ai_assets", "inspector",
              "bom_candidates", "bom_graph", "bom_related_checks")

STATUS = {"invalid_request": 400, "stale_generation": 409, "no_analysis": 409, "not_found": 404, "projection_failed": 500,
          "unsupported_version": 400, "binding_mismatch": 409, "response_too_large": 500, "job_not_found": 404}

STAGE_ORDER = ("resolve_revision", "acquire_source", "sbom", "cbom", "aibom", "advisory_lookup", "source_checks",
               "evidence_projection", "workbench_ready")
REASONS_BY_STATE = {
    "not_run": {"disabled", "not_configured", "upstream_failed"},
    "unsupported": {"unsupported_ecosystem"},
    "failed": {"invalid_revision", "policy_refused", "rate_limited", "scanner_unavailable", "scanner_failed", "timeout",
              "output_invalid", "cleanup_unverified"},
    "partial": {"partial_coverage"},
    "completed_empty": {"no_applicable_assets"},
    "cancelled": {"cancelled_by_user", "session_ended"},
}
CATEGORY_TOKEN = {"documentation": "blue", "web": "green", "node_packages": "green", "python_requirements": "amber",
                  "go_modules": "amber", "rust_crates": "amber", "java_build": "amber", "github_actions": "purple",
                  "container_files": "purple", "other_locations": "neutral"}
TAB_KINDS = {"contexts": {"repository", "group", "file"}, "dependencies": {"package"},
             "crypto": {"asset", "group", "occurrence", "review_item"}, "ai": {"asset", "group", "occurrence", "review_item"},
             "bom": {"candidate", "assertion", "entity", "evidence", "edge"}}
FILTER_GROUP = {"contradicted": "not_represented", "supported": "represented", "conflicting_evidence": "unknown",
                "unverifiable": "unknown", "unknown_coverage": "unknown", "no_rule": "unknown"}
INVENTORY_FAMILY = {"sbom": "software", "cbom": "cryptography", "aibom": "ai_model"}
CONTEXT_KINDS = {"repository", "group", "file"}


class ContractError(Exception):
    """A typed contract failure: ``code`` is one of STATUS, ``detail_code`` names the rule, ``path`` locates it."""

    def __init__(self, code, detail_code, path="", message=None):
        super().__init__("%s [%s] %s %s" % (code, detail_code, path, message or ""))
        self.code, self.detail_code, self.path, self.message = code, detail_code, path, message or detail_code

    @property
    def status(self):
        return STATUS[self.code]

    def body(self, generation=None):
        out = {"schema": SCHEMA_IDS["error"], "error": self.code, "message": str(self.message)[:LIMITS["string_chars"]["message"]],
               "detail_code": self.detail_code[:120]}
        if self.path:
            out["field"] = self.path[:120]
        if generation is not None:
            out["generation"] = generation
        return out


def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def opaque_id(prefix, analysis_digest, kind, key):
    """Contract 4.1: first 24 hex of sha256(canonical_json({analysis_digest, kind, key})); stable across generations."""
    digest = hashlib.sha256(canonical_bytes({"analysis_digest": analysis_digest, "kind": kind, "key": key})).hexdigest()
    return "%s:%s" % (prefix, digest[:24])


# ---------------------------------------------------------------- structural layer
_SCHEMAS = {}


def _schema(name):
    if name not in _SCHEMAS:
        with open(os.path.join(CONTRACT_DIR, "schemas", name + ".schema.json"), encoding="utf-8") as handle:
            _SCHEMAS[name] = json.load(handle)
    return _SCHEMAS[name]


def _resolve(ref):
    file_part, _, pointer = ref.partition("#")
    node = _schema(file_part.replace(".schema.json", ""))
    for part in [p for p in pointer.split("/") if p]:
        node = node[part]
    return node


def _is_type(value, kind):
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "null":
        return value is None
    if kind == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, float) and value.is_integer())
    return False


def _fail(code, detail, path, message=None):
    raise ContractError(code, detail, path, message)


def _structural(schema, value, path, code):
    if "$ref" in schema:
        return _structural(_resolve(schema["$ref"]), value, path, code)
    if "anyOf" in schema:
        last = None
        for alt in schema["anyOf"]:
            try:
                return _structural(alt, value, path, code)
            except ContractError as exc:
                if alt.get("type") != "null":
                    last = exc
        raise last or ContractError(code, "type_error", path)
    if "const" in schema and (value != schema["const"] or type(value) is not type(schema["const"])):
        _fail(code, "enum_violation", path, "must equal %r" % (schema["const"],))
    if "enum" in schema and not any(value == e and type(value) is type(e) for e in schema["enum"]):
        _fail(code, "enum_violation", path, "not an allowed value")
    kind = schema.get("type")
    if kind is not None and not _is_type(value, kind):
        _fail(code, "type_error", path, "expected %s" % kind)
    if kind == "integer":
        if "minimum" in schema and value < schema["minimum"] or "maximum" in schema and value > schema["maximum"]:
            _fail(code, "bound_exceeded", path, "integer out of range")
    elif kind == "string":
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1 << 60):
            _fail(code, "bound_exceeded", path, "string length")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            _fail(code, "pattern_violation", path, "string does not match the required form")
    elif kind == "array":
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 1 << 60):
            _fail(code, "bound_exceeded", path, "array length")
        for i, item in enumerate(value):
            _structural(schema["items"], item, "%s/%d" % (path, i), code)
    elif kind == "object":
        props = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                _fail(code, "missing_field", "%s/%s" % (path, name))
        for name in value:
            if name not in props:
                if schema.get("additionalProperties") is False:
                    _fail(code, "unknown_field", "%s/%s" % (path, name))
                continue
            _structural(props[name], value[name], "%s/%s" % (path, name), code)


# ---------------------------------------------------------------- helpers for the semantic layer
def _sem(detail, path="", message=None):
    raise ContractError("projection_failed", "invariant:" + detail, path, message)


def _need(cond, detail, path="", message=None):
    if not cond:
        _sem(detail, path, message)


def _counts(cb, shown_len, path):
    """Contract 4.1: counts.truncated == (shown < total) everywhere, paged or not; has_more is a separate next-page flag."""
    _need(cb["shown"] == shown_len, "counts_shown", path)
    _need(cb["shown"] <= cb["total"], "counts_total", path)
    _need(cb["truncated"] is (cb["shown"] < cb["total"]), "counts_truncated", path)


def _page_offset(offset, size, total, path):
    """The effective, aligned offset: 0 for an empty list, otherwise inside the filtered total."""
    _need(offset % size == 0 and (offset == 0 if total == 0 else offset < total), "page_offset", path,
          "offset %d is not an effective aligned page start for a total of %d" % (offset, total))


def _unique(items, key, detail, path):
    seen = set()
    for item in items:
        v = item[key]
        _need(v not in seen, detail, path, "duplicate %r" % (v,))
        seen.add(v)
    return seen


# ---------------------------------------------------------------- semantic: scan_status
def _derive_job_state(stages):
    states = [s["state"] for s in stages]
    if "failed" in states:
        return "failed"
    if "cancelled" in states:
        return "cancelled"
    if all(s == "queued" for s in states):
        return "queued"
    if "queued" in states or "running" in states:
        return "running"
    if any(s in ("partial", "unsupported") for s in states):
        return "partial"
    return "completed"


def _semantic_scan_status(p):
    stages = p["stages"]
    _need([s["stage_id"] for s in stages] == list(STAGE_ORDER), "stage_order", "/stages")
    for i, s in enumerate(stages):
        path = "/stages/%d" % i
        st, reason = s["state"], s["reason_code"]
        has_out = bool(s["outputs"])
        should_out = s["stage_id"] in ("sbom", "cbom", "aibom") and st in ("completed", "completed_empty", "partial")
        if s["stage_id"] == "aibom" and st == "partial":
            should_out = has_out          # UIP-07C A4: a partial AI stage may or may not carry committed outputs; every other stage/state is unchanged
        _need(has_out == should_out, "stage_outputs", path, "outputs exist only for committed sbom/cbom/aibom output")
        if st in REASONS_BY_STATE:
            _need(reason in REASONS_BY_STATE[st], "stage_reason", path, "reason_code not allowed for state %s" % st)
        else:
            _need(reason is None, "stage_reason", path, "reason_code forbidden for state %s" % st)
        if st == "queued":
            _need(s["started_at"] is None and s["finished_at"] is None, "stage_times", path)
        elif st == "running":
            _need(s["started_at"] is not None and s["finished_at"] is None, "stage_times", path)
        elif st in ("completed", "completed_empty", "partial", "failed"):
            _need(s["started_at"] is not None and s["finished_at"] is not None, "stage_times", path)
        if s["finished_at"] is not None and s["started_at"] is not None:
            _need(s["started_at"] <= s["finished_at"], "stage_times", path)
    job = p["job"]
    derived = _derive_job_state(stages)
    _need(job["state"] == derived, "job_state", "/job/state", "state %s but stages derive %s" % (job["state"], derived))
    if derived == "completed":
        for s in stages:
            _need(s["state"] in ("completed", "completed_empty") or (s["state"] == "not_run" and s["reason_code"] in ("disabled", "not_configured")),
                  "job_state", "/job/state")
    _need(job["created_at"] <= job["updated_at"], "job_times", "/job")
    h = p["handoff"]
    _need(h["ready"] == (job["state"] in ("completed", "partial")), "handoff_ready", "/handoff/ready")
    _need((h["blocked_reason"] is None) == h["ready"], "handoff_reason", "/handoff/blocked_reason")
    if job["state"] == "cancelled":
        _need(p["cleanup"]["state"] != "not_needed", "cleanup_state", "/cleanup/state")
    b = p["binding"]
    resolved = p["binding_state"] == "resolved"
    _need(p["pinned"] == resolved == (p["identity"] is not None) == (b is not None), "pinning", "/binding_state",
          "pinned, binding_state, identity and binding must agree")
    if resolved:
        _need(b["generation"] == p["generation"] and b["mode"] == p["mode"], "binding_generation", "/binding")
        ident = p["identity"]
        _need(ident["resolved"]["commit_sha"] == b["commit_sha"], "identity_commit", "/identity/resolved/commit_sha")
        _need(ident["analysis_digest"] == b["analysis_digest"], "identity_digest", "/identity/analysis_digest")
        _need(ident["session"]["generation"] == p["generation"], "identity_generation", "/identity/session/generation")
        _need(stages[0]["state"] in ("completed", "partial", "completed_empty"), "resolved_requires_resolution", "/stages/0")
        _need(b["assessment"] is None or stages[7]["state"] in ("completed", "partial"), "assessment_before_projection", "/binding/assessment")
    else:
        _need(stages[0]["state"] != "completed", "resolution_incomplete", "/stages/0",
              "a completed resolve_revision stage requires a pinned binding")


def validate_sequence(payloads):
    """Across the scan_status payloads of one job: seq strictly increases, updated_at and generation never regress."""
    last = None
    for i, p in enumerate(payloads):
        if last is not None:
            _need(p["job"]["job_id"] == last["job"]["job_id"], "sequence_job", "/%d" % i)
            _need(p["job"]["seq"] > last["job"]["seq"], "sequence_seq", "/%d" % i)
            _need(p["job"]["updated_at"] >= last["job"]["updated_at"], "sequence_time", "/%d" % i)
            _need(p["generation"] == last["generation"], "sequence_generation", "/%d" % i)
        last = p


# ---------------------------------------------------------------- semantic: contexts
def _semantic_contexts(p):
    b, root = p["binding"], p["root"]
    repo = b["repository"]
    _need(root["name"] == "%s/%s" % (repo["owner"], repo["name"]), "root_identity", "/root/name")
    _need(root["canonical_url"] == repo["canonical_url"] and root["commit_sha"] == b["commit_sha"], "root_identity", "/root")
    groups = p["groups"]
    _counts(p["counts"], len(groups), "/counts")
    gids = _unique(groups, "group_id", "duplicate_id", "/groups")
    fids, located_membership, located_distinct_sum = set(), 0, 0
    unlocated_seen = 0
    for gi, g in enumerate(groups):
        path = "/groups/%d" % gi
        _need(g["distinct_total"] <= g["membership_total"], "distinct_le_membership", path)
        if g["kind"] == "unlocated":
            unlocated_seen += 1
            _need(g["files"] == [] and g["category"] is None and g["token"] == "neutral", "unlocated_group", path)
            _need(g["distinct_total"] == root["unlocated_total"], "unlocated_total", path)
            _need(g["files_counts"]["total"] == 0, "unlocated_group", path)
        else:
            _need(g["category"] is not None and CATEGORY_TOKEN[g["category"]] == g["token"], "category_token", path)
            _need(g["basis"] != "fallback" or g["category"] == "other_locations", "fallback_category", path)
            located_membership += g["membership_total"]
            located_distinct_sum += g["distinct_total"]
        _counts(g["files_counts"], len(g["files"]), path + "/files_counts")
        _need(g["files_offset"] == 0 if g["files_counts"]["total"] == 0 else g["files_offset"] < g["files_counts"]["total"], "page_offset", path + "/files_offset")
        for fi, f in enumerate(g["files"]):
            fp = "%s/files/%d" % (path, fi)
            _need(f["file_id"] not in fids, "duplicate_id", fp)
            fids.add(f["file_id"])
            _need(f["distinct_total"] <= f["membership_total"], "distinct_le_membership", fp)
            _need(len(f["raw_locations"]) <= f["raw_locations_total"], "raw_locations_total", fp)
        if not g["files_counts"]["truncated"] and g["kind"] == "located":
            _need(sum(f["membership_total"] for f in g["files"]) == g["membership_total"], "group_membership_sum", path)
    _need(unlocated_seen <= 1, "unlocated_group", "/groups")
    _need(root["distinct_total"] == root["located_distinct_total"] + root["unlocated_total"], "root_distinct_total", "/root")
    if not p["counts"]["truncated"]:  # a page restricted to some groups cannot be summed
        _need(root["membership_total"] == located_membership, "root_membership_total", "/root")
        _need(located_distinct_sum >= root["located_distinct_total"], "located_distinct_overlap", "/root")
    if p["selected_id"] is not None:
        _need(p["selected_id"] in gids or p["selected_id"] in fids, "selected_id", "/selected_id")


# ---------------------------------------------------------------- semantic: dependency_page
def _bfs(focus, edges):
    adj = {}
    for e in edges:
        adj.setdefault(e["from"], []).append(e["to"])
    dist, frontier = {focus: 0}, [focus]
    while frontier:
        nxt = []
        for n in frontier:
            for m in adj.get(n, ()):
                if m not in dist:          # visited set: cycles terminate
                    dist[m] = dist[n] + 1
                    nxt.append(m)
        frontier = nxt
    return dist


def _semantic_dependency_page(p):
    nodes, edges, page = p["nodes"], p["edges"], p["page"]
    ids = _unique(nodes, "node_id", "duplicate_id", "/nodes")
    _unique(edges, "edge_id", "duplicate_id", "/edges")
    for i, e in enumerate(edges):
        _need(e["from"] in ids and e["to"] in ids, "edge_endpoint", "/edges/%d" % i)
        _need(e["from"] != e["to"], "edge_self_loop", "/edges/%d" % i)
    foci = [n for n in nodes if n["role"] == "focus"]
    _need(len(foci) == 1 and foci[0]["node_id"] == p["focus"]["node_id"] and foci[0]["depth"] == 0, "focus_node", "/nodes")
    matches = [n for n in nodes if n["role"] == "match"]
    connectors = [n for n in nodes if n["role"] == "connector"]
    _need(len(matches) <= LIMITS["dependency_match_page"], "match_page", "/nodes")
    _need(len(connectors) <= LIMITS["dependency_connectors_per_page"] and len(edges) <= LIMITS["dependency_edges_per_page"], "connector_bounds", "/nodes")
    _need(p["limits"]["connectors_shown"] == len(connectors), "connectors_shown", "/limits")
    dist = _bfs(foci[0]["node_id"], edges)
    omitted = [n for n in nodes if n["path_state"] in ("connectors_omitted", "depth_limit")]
    for n in omitted:
        _need(not any(n["node_id"] in (e["from"], e["to"]) for e in edges), "omitted_path", "/edges",
              "a match whose path was omitted is listed with no edge drawn for it")
    _need((p["limits"]["connectors_truncated"] or p["limits"]["edges_truncated"]) == any(n["path_state"] == "connectors_omitted" for n in nodes),
          "truncation_flags", "/limits", "truncation flags must be set exactly when a path was omitted")
    for i, n in enumerate(nodes):
        path = "/nodes/%d" % i
        if n["role"] == "focus":
            continue
        if n["path_state"] == "complete":
            _need(n["node_id"] in dist, "unreachable_node", path)
            _need(n["depth"] == dist[n["node_id"]], "depth_mismatch", path, "depth must equal the distance over the payload's own edges")
        elif n["path_state"] == "depth_limit":
            _need(n["depth"] == LIMITS["dependency_path_depth"] + 1, "depth_limit", path)
        else:
            _need(n["depth"] >= 2, "connectors_omitted_depth", path)
        _need(n["flags"]["direct"] == (n["depth"] == 1) and n["flags"]["transitive"] == (n["depth"] >= 2), "flags_depth", path)
    for i, e in enumerate(edges):
        if e["from"] == foci[0]["node_id"]:
            target = next(n for n in nodes if n["node_id"] == e["to"])
            _need(target["depth"] == 1, "direct_edge_to_deeper_node", "/edges/%d" % i)
    lookup = p["lookup"]
    gap_lookup = {"unavailable", "unsupported", "missing_version", "not_run"}
    for i, n in enumerate(nodes):
        path = "/nodes/%d" % i
        if lookup["mode"] == "off":
            _need(n["advisory_lookup"] == "not_run", "lookup_off", path, "lookup off means every node is not_run")
        # node-level coverage is truthful for every node including the focus; the focus stays outside matches and filter totals
        causes = set(n["gap_causes"])
        _need(len(causes) == len(n["gap_causes"]), "gap_causes", path)
        _need(("missing_source_location" in causes) == (not n["has_source_location"]), "gap_causes", path)
        _need(("lookup_not_run" in causes) == (n["advisory_lookup"] == "not_run"), "gap_causes", path)
        _need(("lookup_incomplete" in causes) == (n["advisory_lookup"] in gap_lookup - {"not_run"}), "gap_causes", path)
        _need(n["flags"]["evidence_gap"] == bool(causes), "evidence_gap_flag", path)
        _need((n["advisory_match_count"] >= 1) if n["advisory_lookup"] == "match" else n["advisory_match_count"] == 0, "advisory_match_count", path)
    any_not_run = any(n["advisory_lookup"] == "not_run" for n in nodes)
    _need((lookup["explanation"] is not None) == any_not_run, "lookup_explanation", "/lookup/explanation",
          "an explanation that lookup was not performed is required exactly when a node is not_run")
    flt = p["filter"]
    for i, n in enumerate(matches):
        ok = {"all": True, "direct": n["flags"]["direct"], "transitive": n["flags"]["transitive"],
              "advisory": n["advisory_lookup"] == "match", "evidence_gaps": n["flags"]["evidence_gap"]}[flt]
        _need(ok, "filter_predicate", "/nodes", "a shown match does not satisfy filter %s" % flt)
    ft = p["filter_totals"]
    _need(ft["all"] == ft["direct"] + ft["transitive"] and ft["advisory"] <= ft["all"] and ft["evidence_gaps"] <= ft["all"], "filter_totals", "/filter_totals")
    _need(page["matches_shown"] == len(matches), "matches_shown", "/page")
    _need(page["matches_total"] <= ft[flt] and (p["query"] != "" or page["matches_total"] == ft[flt]), "matches_total", "/page")
    _need(page["matches_shown"] <= page["matches_total"], "matches_shown", "/page")
    _page_offset(page["offset"], page["size"], page["matches_total"], "/page/offset")
    _need(page["has_more"] == (page["offset"] + page["matches_shown"] < page["matches_total"]), "has_more", "/page")
    if page["matches_shown"]:
        _need(page["range_first"] == page["offset"] + 1 and page["range_last"] == page["offset"] + page["matches_shown"], "page_range", "/page")
    else:
        _need(page["range_first"] == 0 and page["range_last"] == 0, "page_range", "/page")
    _counts(p["counts"], page["matches_shown"], "/counts")
    _need(p["counts"]["total"] == page["matches_total"], "counts_total", "/counts")
    _need(p["focus"]["candidates_total"] >= 1, "focus_candidates", "/focus")
    lc = lookup["counts_by_state"]
    _need(all(v >= 0 for v in lc.values()), "lookup_counts", "/lookup")


# ---------------------------------------------------------------- semantic: asset inventories
def _semantic_assets(p):
    tab = p["tab"]
    av = p["availability"]
    st, reason = av["state"], av["reason_code"]
    if st == "completed":
        _need(reason is None, "availability_reason", "/availability")
    else:
        _need(reason in REASONS_BY_STATE.get(st, set()), "availability_reason", "/availability")
    producers = p["producers"]
    pids = {}
    for i, pr in enumerate(producers):
        pid = pr["provenance"]["producer_id"]
        _need(pid not in pids, "duplicate_id", "/producers/%d" % i)
        pids[pid] = pr
        prov = pr["provenance"]
        if prov["origin"] == "supplemental_observation":
            _need(prov["experimental"] is True, "supplemental_experimental", "/producers/%d" % i)
    page = p["page"]
    total = page["assets_total"]
    if st in ("failed", "not_run", "unsupported", "completed_empty"):
        _need(total == 0, "availability_assets", "/availability", "state %s requires zero assets" % st)
    if st == "completed_empty":
        _need(any(pr["outcome"] == "completed" for pr in producers), "empty_requires_completed_producer", "/producers")
    if st in ("completed", "partial"):
        _need(len(producers) >= 1, "producers_required", "/producers")
    _need(page["assets_shown"] == len(p["assets"]) and page["assets_shown"] <= total, "page_counts", "/page")
    _page_offset(page["offset"], page["size"], total, "/page/offset")
    _need(page["has_more"] == (page["offset"] + page["assets_shown"] < total), "has_more", "/page")
    _counts(p["counts"], len(p["assets"]), "/counts")
    _need(p["counts"]["total"] == total, "counts_total", "/counts")
    ft = p["filter_totals"]
    _need(ft["all"] >= total if p["filter"] == "all" else True, "filter_totals", "/filter_totals")
    group_ids = _unique(p["source_groups"], "group_id", "duplicate_id", "/source_groups")
    asset_ids = _unique(p["assets"], "asset_id", "duplicate_id", "/assets")
    occ_ids = set()
    for ai, a in enumerate(p["assets"]):
        path = "/assets/%d" % ai
        prov = a["provenance"]
        _need(prov["producer_id"] in pids, "asset_producer", path, "asset provenance names no listed producer")
        _need(prov["origin"] == pids[prov["producer_id"]]["provenance"]["origin"], "asset_origin", path)
        if prov["origin"] == "original_artifact":
            _need(prov["artifact_id"] is not None and prov["json_pointer"] is not None, "original_pointer", path)
        if prov["origin"] == "supplemental_observation":
            _need(prov["experimental"] is True and len(a["occurrences"]) >= 1, "supplemental_source", path)
        for gid in a["source_group_ids"]:
            _need(gid in group_ids, "source_group_ref", path)
        _need(a["occurrences_total"] >= len(a["occurrences"]), "occurrences_total", path)
        for oi, o in enumerate(a["occurrences"]):
            op = "%s/occurrences/%d" % (path, oi)
            _need(o["occurrence_id"] not in occ_ids, "duplicate_id", op)
            occ_ids.add(o["occurrence_id"])
            loc = o["source_location"]
            if prov["origin"] == "supplemental_observation":
                _need(loc["file_sha256"] is not None and loc["line_start"] is not None and loc["line_end"] is not None, "supplemental_source", op,
                      "supplemental observations need file, hash and line range")
            if loc["line_start"] is not None and loc["line_end"] is not None:
                _need(loc["line_start"] <= loc["line_end"], "line_range", op)
        for k, attr in a["attributes"].items():
            _need((attr["state"] == "recorded") == (attr["value"] is not None), "attribute_value", "%s/attributes/%s" % (path, k),
                  "a value is present exactly when state is recorded")
        if tab == "ai" and a["identity_state"] == "resolved":
            ok = a["attributes"]["artifact_digest"]["state"] == "recorded" or (a["kind"] == "inventory_model" and prov["origin"] == "original_artifact")
            _need(ok, "model_identity", path, "a model name or filename is not a resolved identity without evidence")
    for ai, a in enumerate(p["assets"]):
        for o in a["occurrences"]:
            if o["alternative_of"] is not None:
                _need(o["alternative_of"] in occ_ids and o["alternative_of"] != o["occurrence_id"], "alternative_ref", "/assets/%d" % ai)
    known = asset_ids | group_ids | occ_ids
    if tab == "crypto":
        sids = _unique(p["services"], "service_id", "duplicate_id", "/services")
        known |= sids
        _counts(p["services_counts"], len(p["services"]), "/services_counts")
        for i, s in enumerate(p["services"]):
            _need(s["provenance"]["producer_id"] in pids, "asset_producer", "/services/%d" % i)
    for i, l in enumerate(p["links"]):
        path = "/links/%d" % i
        _need(l["from"] in known and l["to"] in known, "link_endpoint", path)
        if l["relation"] == "implemented_by":
            _need(l["basis"] == "resolved", "implementation_link", path, "a library implementation link needs a resolved basis")
        if l["relation"] == "conditionally_selects":
            _need(l["condition"] is not None, "conditional_link", path)
    for i, r in enumerate(p["review_items"]):
        path = "/review_items/%d" % i
        if r["tone"] == "advisory":
            _need(len(r["evidence_ids"]) >= 1, "advisory_evidence", path, "an advisory tone needs identifiable evidence")
        if r["asset_id"] is not None:
            _need(r["asset_id"] in asset_ids, "review_asset", path)
    _unique(p["review_items"], "review_id", "duplicate_id", "/review_items")


# ---------------------------------------------------------------- semantic: inspector
def _semantic_inspector(p):
    tab, sel = p["tab"], p["selection"]
    _need(sel["kind"] in TAB_KINDS[tab], "selection_kind", "/selection/kind", "kind %s is not valid for tab %s" % (sel["kind"], tab))
    bom = tab == "bom"
    _need(p["question_set"] == ("bom_comparison" if bom else "context_four"), "question_set", "/question_set")
    third = "comparison_established" if bom else "security_concern"
    ids = [a["question_id"] for a in p["answers"]]
    _need(ids == ["what_is_this", "why_here", third, "what_unknown"], "answers_order", "/answers")
    ans = {a["question_id"]: a for a in p["answers"]}
    if sel["kind"] in CONTEXT_KINDS:
        _need(p["badge"]["kind"] == "context", "context_badge", "/badge")
        _need(ans["security_concern"]["state"] == "not_applicable", "context_security", "/answers/2",
              "a repository context is not a security assessment")
    if bom and sel["kind"] in ("entity", "evidence", "edge"):
        _need(ans["comparison_established"]["state"] in ("not_applicable", "not_assessed"), "no_verdict_on_record", "/answers/2")
    for i, r in enumerate(p["evidence_rows"]):
        if r["status"] in ("source_checked", "advisory_match"):
            _need(r["evidence_ref"] is not None, "row_evidence", "/evidence_rows/%d" % i)
    _need(len(set(p["actions"])) == len(p["actions"]), "actions_unique", "/actions")
    _need(p["sources_coverage"]["available"] or p["sources_coverage"]["items"] == [], "sources_coverage", "/sources_coverage")


# ---------------------------------------------------------------- semantic: bom_candidates
def _semantic_bom_candidates(p):
    c, items, page, f = p["counts"], p["items"], p["page"], p["filters"]
    mode = p["mode"]
    _need(sum(c["state_counts"].values()) == c["candidates_total"], "state_counts", "/counts/state_counts")
    _need(sum(c["filter_group_counts"].values()) == c["candidates_total"], "filter_group_counts", "/counts/filter_group_counts")
    fam = sum(c["family_counts"].values())
    _need(fam == c["candidates_total"] if c["family_counts_disjoint"] else fam >= c["candidates_total"], "family_counts", "/counts/family_counts")
    _need(c["filtered_total"] <= c["candidates_total"], "filtered_total", "/counts")
    _need(c["assertions_unique"] <= c["candidates_total"] or mode == "legacy_checks", "assertions_unique", "/counts")
    if mode == "not_compared":
        _need(items == [] and p["status_detail"] is not None and c["candidates_total"] == 0 and c["filtered_total"] == 0, "not_compared_shape", "/mode",
              "a comparison that was not performed is never an empty success")
        _need(all(cap["state"] in ("not_run", "unsupported", "failed") for cap in p["capabilities"]) and p["capabilities"], "not_compared_capabilities", "/capabilities")
    else:
        _need(p["status_detail"] is None, "status_detail", "/status_detail")
    _need(len(items) <= LIMITS["bom_queue_page"], "page", "/page")
    _page_offset(page["offset"], page["size"], c["filtered_total"], "/page/offset")
    _need(page["has_more"] == (page["offset"] + len(items) < c["filtered_total"]), "has_more", "/page")
    _need(len(items) <= c["filtered_total"], "page", "/items")
    seen, refs = set(), set()
    assertions = set()
    for i, it in enumerate(items):
        path = "/items/%d" % i
        _need(it["item_id"] not in seen, "duplicate_id", path)
        seen.add(it["item_id"])
        ref = canonical_bytes(it["canonical_ref"])
        _need(ref not in refs, "duplicate_canonical_ref", path)
        refs.add(ref)
        if it["assertion_id"] is not None:
            assertions.add(it["assertion_id"])
        _need(it["filter_group"] == FILTER_GROUP[it["state"]], "filter_group", path)
        _need(it["item_kind"] == ("legacy_check" if mode == "legacy_checks" else "candidate"), "item_kind", path)
        if it["family_basis"] == "unclassified":
            _need(it["family"] == "other", "family_basis", path)
        if it["family_basis"] == "inventory_kind":
            _need(it["inventory"] is not None and INVENTORY_FAMILY[it["inventory"]["kind"]] == it["family"], "family_basis", path)
        for key, field in (("family", "family"), ("filter_group", "filter_group"), ("state", "state"), ("category", "category")):
            if f[key] is not None:
                _need(it[field] == f[key], "filter_predicate", path)
        if f["query"]:
            _need(f["query"].lower() in it["display"]["raw_title"].lower() or f["query"].lower() in it["display"]["name"].lower(), "filter_predicate", path)
    _need(len(assertions) <= c["assertions_unique"], "assertions_unique", "/counts")


# ---------------------------------------------------------------- semantic: bom_graph
def _semantic_bom_graph(p):
    nodes, edges, scope, c = p["nodes"], p["edges"], p["scope"], p["counts"]
    kind, gs = scope["kind"], p["graph_state"]
    ids = _unique(nodes, "node_id", "duplicate_id", "/nodes")
    _unique(edges, "edge_id", "duplicate_id", "/edges")
    byid = {n["node_id"]: n for n in nodes}
    for i, e in enumerate(edges):
        _need(e["from"] in ids and e["to"] in ids, "edge_endpoint", "/edges/%d" % i)
    _need([r["node_id"] for r in p["records"]] == [n["node_id"] for n in nodes], "records_alternative", "/records")
    _need((kind == "focused_candidate") == (scope["candidate_id"] is not None), "scope_candidate", "/scope")
    _need((kind == "full_view") == (p["page"] is not None), "scope_page", "/page")
    assertion_nodes = [n for n in nodes if n["kind"] == "assertion"]
    if kind == "group_summary":
        _need(nodes == [] and edges == [] and p["records"] == [], "group_summary_shape", "/nodes")
    elif gs == "assertion_graph":
        _need(p["message_code"] is None, "message_code", "/message_code")
        _need(len(assertion_nodes) == 1 if kind == "focused_candidate" else len(assertion_nodes) >= 1, "assertion_count", "/nodes",
              "an assertion graph holds the recorded assertion")
    elif gs == "evidence_only":
        _need(p["message_code"] == "more_evidence_needed" and assertion_nodes == [], "evidence_only_shape", "/nodes",
              "an evidence-only task never gains an assertion")
        _need(any(n["kind"] == "evidence" for n in nodes) and all(n["state"] is None for n in nodes), "evidence_only_shape", "/nodes",
              "no verdict may appear on an evidence-only graph")
    elif gs == "no_graph_collection_task":
        _need(nodes == [] and edges == [] and p["records"] == [] and p["message_code"] == "more_evidence_needed", "no_graph_shape", "/nodes")
    else:
        _need(nodes == [] and edges == [], "not_compared_shape", "/nodes")
    if kind == "focused_candidate":
        _need(len(nodes) <= LIMITS["bom_focused_nodes"] and len(edges) <= LIMITS["bom_focused_edges"], "focused_bounds", "/nodes")
        _need(all(n["role"] == "primary" for n in nodes), "focused_roles", "/nodes")
        for i, n in enumerate(nodes):
            if n["kind"] == "evidence":
                _need(n["evidence_role"] is not None, "evidence_role", "/nodes/%d" % i)
    else:
        primary = [n for n in nodes if n["role"] == "primary"]
        neigh = [n for n in nodes if n["role"] == "neighbor"]
        _need(len(primary) <= LIMITS["bom_full_view_primary"] and len(neigh) <= LIMITS["bom_full_view_neighbors"]
              and len(edges) <= LIMITS["bom_full_view_edges"], "full_view_bounds", "/nodes")
        prim_ids = {n["node_id"] for n in primary}
        for n in neigh:
            _need(any((e["from"] == n["node_id"] and e["to"] in prim_ids) or (e["to"] == n["node_id"] and e["from"] in prim_ids) for e in edges),
                  "neighbor_connected", "/nodes", "a neighbor exists only through a recorded edge to a primary node")
    for i, e in enumerate(edges):
        ev = [byid[x] for x in (e["from"], e["to"]) if byid[x]["kind"] == "evidence"]
        if e["role"] == "excluded":
            _need(ev and all(n["evidence_role"] == "excluded" for n in ev), "excluded_edge", "/edges/%d" % i)
        if e["role"] == "used":
            _need(all(n["evidence_role"] != "excluded" for n in ev), "excluded_as_support", "/edges/%d" % i, "excluded evidence never supports")
    for i, n in enumerate(nodes):
        if n["kind"] == "evidence" and n["evidence_role"] == "excluded":
            for e in edges:
                if n["node_id"] in (e["from"], e["to"]):
                    _need(e["role"] == "excluded", "excluded_as_support", "/nodes/%d" % i, "excluded evidence connects only through excluded edges")
    _need(c["nodes_shown"] == len(nodes) and c["edges_shown"] == len(edges), "graph_counts", "/counts")
    _need(c["primary_shown"] + c["neighbors_shown"] == c["nodes_shown"]
          and c["primary_shown"] == sum(1 for n in nodes if n["role"] == "primary"), "graph_counts", "/counts")
    _need(c["omitted_nodes"] == c["nodes_in_scope"] - c["nodes_shown"] if kind != "group_summary" else True, "graph_counts", "/counts")
    if kind != "group_summary":
        _need(c["nodes_in_scope"] >= c["nodes_shown"] and c["edges_in_scope"] >= c["edges_shown"]
              and c["omitted_edges"] == c["edges_in_scope"] - c["edges_shown"], "graph_counts", "/counts")
        _need(p["truncated"] == (c["omitted_nodes"] > 0 or c["omitted_edges"] > 0), "graph_truncated", "/truncated")


# ---------------------------------------------------------------- semantic: bom_related_checks
def _semantic_bom_related(p):
    subj, items, c, page = p["subject"], p["items"], p["counts"], p["page"]
    if subj["kind"] == "relationship":
        _need(p["resolution"] == "not_applicable" and items == [] and p["related_total"] == 0, "relationship_shape", "/resolution",
              "a relationship never guesses a candidate")
    else:
        want = "none" if p["related_total"] == 0 else "single" if p["related_total"] == 1 else "multiple"
        _need(p["resolution"] == want, "resolution", "/resolution")
        if want == "none":
            _need(p["record_detail"] is not None and items == [], "none_requires_detail", "/record_detail")
        if want == "single":
            _need(len(items) == 1, "single_item", "/items")
    _need(len(items) <= p["related_total"], "related_total", "/related_total")
    _counts(c, len(items), "/counts")
    _need(c["total"] == p["related_total"], "counts_total", "/counts")
    _page_offset(page["offset"], page["size"], p["related_total"], "/page/offset")
    _need(page["has_more"] == (page["offset"] + len(items) < p["related_total"]), "has_more", "/page")
    _unique(items, "item_id", "duplicate_id", "/items")


SEMANTIC = {"scan_status": _semantic_scan_status, "contexts": _semantic_contexts, "dependency_page": _semantic_dependency_page,
            "crypto_assets": _semantic_assets, "ai_assets": _semantic_assets, "inspector": _semantic_inspector,
            "bom_candidates": _semantic_bom_candidates, "bom_graph": _semantic_bom_graph, "bom_related_checks": _semantic_bom_related,
            "error": lambda p: None}


def _walk(node, key):
    """Yield every dict value stored under ``key`` anywhere in the payload."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key and isinstance(v, dict):
                yield v
            yield from _walk(v, key)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v, key)


def _subset(expected, actual):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and _subset(v, actual[k]) for k, v in expected.items())
    return expected == actual


EXPECTED_BINDING_KEYS = ("analysis_digest", "commit_sha", "repository", "requested_ref", "mode", "assessment", "session_id")


def _mismatch(detail, path, message):
    raise ContractError("binding_mismatch", "invariant:" + detail, path, message)


def check_binding(name, payload, expected=None):
    """Bind the payload, its sealed assessment fields and every nested canonical_ref.

    ``expected`` is a (possibly partial) section 4.3 binding, compared as a recursive subset: any of ``analysis_digest``,
    ``commit_sha``, ``repository`` (object), ``requested_ref``, ``mode``, ``assessment`` (object, e.g. configuration,
    validation_digest, bundle_sha256) and ``session_id`` (the session every canonical_ref must carry). ``generation`` is
    checked against the request, not here. Unknown keys are a programming error.
    """
    binding = payload["binding"]
    if expected is not None:
        unknown = set(expected) - set(EXPECTED_BINDING_KEYS) - {"generation"}
        if unknown:
            raise ValueError("unknown expected_binding keys: %s" % sorted(unknown))
    if expected is not None and binding is not None:
        for key in ("analysis_digest", "commit_sha", "repository", "requested_ref", "mode", "assessment"):
            if key in expected and not _subset(expected[key], binding[key]):
                _mismatch(key, "/binding/" + key, "payload is bound to a different %s" % key)
    sessions = set()
    if binding is not None:
        for ref in _walk(payload, "canonical_ref"):
            rb = ref["binding"]
            if rb["analysis_digest"] != binding["analysis_digest"]:
                _mismatch("canonical_ref_analysis_digest", "/canonical_ref", "a reference is sealed to another analysis")
            if rb["generation"] != binding["generation"]:
                _mismatch("canonical_ref_generation", "/canonical_ref", "a reference carries another generation")
            if binding["assessment"] is not None:
                if rb["configuration"] != binding["assessment"]["configuration"]:
                    _mismatch("canonical_ref_configuration", "/canonical_ref", "a reference carries another configuration")
                if rb["bundle_sha256"] != binding["assessment"]["bundle_sha256"]:
                    _mismatch("canonical_ref_bundle", "/canonical_ref", "a reference carries another bundle digest")
            sessions.add(rb["session_id"])
        if len(sessions) > 1:
            _mismatch("canonical_ref_session", "/canonical_ref", "references in one payload carry different sessions")
    if expected is not None and "session_id" in expected and sessions and sessions != {expected["session_id"]}:
        _mismatch("canonical_ref_session", "/canonical_ref", "references carry another session")


def _check_link(link, path, binding, ptr):
    from urllib.parse import quote, urlsplit
    href = link["href"]
    if href is None:
        return
    try:
        parts = urlsplit(href)
    except ValueError:
        _sem("link_destination", ptr, "unparseable link")
    if parts.scheme.lower() not in ("http", "https"):
        _sem("link_scheme", ptr, "only http(s) links may be active; repository text stays inert with a null href")
    if "@" in parts.netloc:
        _sem("link_credentials", ptr, "a link may not carry credentials")
    r = binding["repository"]
    expected = "https://github.com/%s/%s/blob/%s/%s" % (r["owner"], r["name"], binding["commit_sha"], quote(path, safe="/"))
    _need(href == expected, "link_destination", ptr, "a source link must be the pinned revision destination built from the binding and the percent-encoded path")


def check_links(payload):
    binding = payload.get("binding")
    if binding is None:
        return

    def walk(node, ptr):
        if isinstance(node, dict):
            for k in ("link", "revision_link"):
                if isinstance(node.get(k), dict) and "path" in node:
                    _check_link(node[k], node["path"], binding, ptr + "/" + k)
            for k, v in node.items():
                walk(v, "%s/%s" % (ptr, k))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, "%s/%d" % (ptr, i))
    walk(payload, "")


def structural_check(name, payload):
    """Structural layer only (the rules the JSON Schema file expresses)."""
    if name not in PAYLOADS:
        raise ValueError("unknown payload %r" % name)
    _structural(_schema(name), payload, "", "projection_failed")


def check_size(name, nbytes, limits=None):
    lim = limits or LIMITS
    cap = min(lim["payload_max_bytes"][name], lim["response_max_bytes"])
    if nbytes > cap:
        raise ContractError("response_too_large", "bound_exceeded", "", "%d bytes exceeds the %d byte ceiling for %s" % (nbytes, cap, name))


def validate_payload(name, payload, *, request=None, expected_binding=None, limits=None):
    """Structural, semantic, links, request/job/generation, binding, then the byte ceiling. Raises ContractError.

    ``request`` carries ``generation`` (and ``job_id`` for scan_status); ``expected_binding`` is the section 4.3 subset
    described at ``check_binding``.
    """
    structural_check(name, payload)
    SEMANTIC[name](payload)
    if name != "error":
        if request is not None:
            if name == "scan_status" and "job_id" in request and request["job_id"] != payload["job"]["job_id"]:
                raise ContractError("job_not_found", "invariant:job_id", "/job/job_id", "the job belongs to another request")
            generation = payload["generation"] if name == "scan_status" else payload["binding"]["generation"]
            if request.get("generation") != generation:
                raise ContractError("stale_generation", "invariant:generation", "/binding/generation", "payload generation differs from the request")
        check_binding(name, payload, expected_binding)
        check_links(payload)
    check_size(name, len(canonical_bytes(payload)), limits)


# ---------------------------------------------------------------- requests
_INT_RE = re.compile(r"^[0-9]{1,9}(?!\n)$")
_DEFAULTS = {"dependency_page": {"filter": "all", "offset": 0}, "crypto_assets": {"filter": "all", "offset": 0},
             "ai_assets": {"filter": "all", "offset": 0}, "bom_candidates": {"offset": 0}, "bom_graph": {"offset": 0},
             "bom_related_checks": {"offset": 0}, "contexts": {"files_offset": 0, "files_limit": LIMITS["files_per_group_page_default"]}}


def validate_request(route_key, params):
    """Normalize and validate request parameters (decimal strings or ints; lists are duplicates). Raises ContractError."""
    if route_key not in ROUTE_KEYS:
        raise ValueError("unknown route key %r" % route_key)
    schema = _schema("requests")["$defs"][route_key]
    out = {}
    for name, value in params.items():
        if isinstance(value, (list, tuple)):
            if len(value) != 1:
                _fail("invalid_request", "duplicate_parameter", name, "parameter repeated")
            value = value[0]
        prop = schema["properties"].get(name)
        if prop is None:
            _fail("invalid_request", "unknown_parameter", name, "unknown parameter")
        if prop.get("type") == "integer" or prop.get("const") is not None and isinstance(prop.get("const"), int):
            if isinstance(value, str):
                if not _INT_RE.match(value):
                    _fail("invalid_request", "type_error", name, "decimal integer expected")
                value = int(value)
            elif not isinstance(value, int) or isinstance(value, bool):
                _fail("invalid_request", "type_error", name)
        elif isinstance(value, str) and name == "query":
            value = value.strip()
        out[name] = value
    if "schema_version" in out and out["schema_version"] != 1:
        _fail("unsupported_version", "schema_version", "schema_version", "only schema_version 1 is served")
    for key, default in _DEFAULTS.get(route_key, {}).items():
        out.setdefault(key, default)
    _structural(schema, out, "", "invalid_request")
    return out
