"""Dependencies tab payloads (UIP-05): ``opentrace.workbench.dependency_page/1`` and the additive chooser ``dependency_contexts/1``.

Pure and read-only. The context graph comes from the existing adapter projection (``analysis.views._scope``: components that are
members of one source context and the recorded dependency edges whose both ends are members). Nothing here reads repository files,
infers a path from array order, invents a root or an edge, or knows a repository by name.

Algorithm (contract UIP-05 4.3). Adjacency is sorted by node id; a breadth-first search from the focus with a visited set records the
shortest distance and one parent per node (depth cap 12). For each page match the parent chain is drawn (connectors do not use the
30-match quota; at most 120 connectors and 240 edges). After the paths, every recorded edge between displayed nodes with a complete
path whose ``dist[to] == dist[from] + 1`` is added in sorted order while fewer than 240 edges are drawn. Nothing else is drawn.
``page_from_graph`` is the same computation as the frozen fixture builder (``tools/uip_fixtures/build.py::dep_page``, the oracle) on
the same graph shape; the only designed differences are the real ``source_pointers`` and the cause-specific truncation flags.
"""
import hashlib
import threading
import weakref

from . import context_groups, view_contracts as vc
from .workbench_binding import build_binding

LIM = vc.LIMITS
PAGE = LIM["dependency_match_page"]
CONNECTOR_CAP = LIM["dependency_connectors_per_page"]
EDGE_CAP = LIM["dependency_edges_per_page"]
DEPTH_CAP = LIM["dependency_path_depth"]
CHOOSER_MAX = 40
RESPONSE_MAX_BYTES = 524288
GAP_LOOKUP = {"unavailable", "unsupported", "missing_version", "not_run"}
LOOKUP_STATES = ("match", "no_match", "unavailable", "unsupported", "missing_version", "not_run")
DEPENDENCY_CATEGORIES = ("node_packages", "web", "python_requirements", "go_modules", "rust_crates", "java_build")

EXPL_DEFAULT = "Advisory lookup was not performed for these components; this is not a completed clean lookup and not a finding."
EXPL_RECORDED = ("The recorded advisory snapshot does not state per-component query coverage: components without a recorded match "
                 "are shown as not run, not as a completed clean lookup.")
EXPL_OFF = ("Advisory lookup is not enabled for this analysis, so no advisory source was contacted: components are shown as not run, "
            "not as a completed clean lookup.")


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def edge_id(a, c):
    """The derivation the frozen fixtures use (independent of the binding)."""
    return "edge:%s" % _sha("|".join((a, c)))[:24]       # == build.py eid("edge", a, c): the prefix is not part of the hashed text


def _clean(text, limit):
    """Display normalization required by the frozen schema (no control characters, bounded length). Identity is the node id."""
    if text is None:
        return None
    text = "".join("�" if ord(ch) < 0x20 else ch for ch in str(text))
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------------------------------------------- graph model
class Graph:
    """``nodes``: id -> {name, version, eco, loc, lookup, matches}; ``edges``: sorted unique (from, to); ``pointers``: (from, to) -> [str]."""

    def __init__(self, nodes, edges, pointers=None):
        self.nodes = nodes
        pairs = sorted({(a, c) for a, c in edges if a != c and a in nodes and c in nodes})
        self.edges = pairs
        self.pointers = pointers or {}


def choose_focus(graph):
    """Focus when none is requested: ``(node_id, basis, candidates_total)`` or None for an empty graph (contract 4.3)."""
    nodes = graph.nodes
    if not nodes:
        return None
    incoming, out = set(), {}
    for a, c in graph.edges:
        incoming.add(c)
        out.setdefault(a, set()).add(c)

    def key(n):
        info = nodes[n]
        return (-len(out.get(n, ())), (info["name"] or "").lower(), info["version"] or "", n)
    roots = sorted((n for n in nodes if n not in incoming), key=key)
    if roots:
        unique = len(roots) == 1 or len(out.get(roots[0], ())) > len(out.get(roots[1], ()))
        return roots[0], "graph_root" if unique else "disconnected_fallback", len(roots)
    return sorted(nodes, key=key)[0], "cycle_fallback", len(nodes)


def page_from_graph(binding, ctx_id, ctx_path, graph, focus, *, filt="all", offset=0, query="", lookup_mode="recorded",
                    explanation=None, basis="requested", candidates_total=1, connector_cap=CONNECTOR_CAP, edge_cap=EDGE_CAP,
                    depth_cap=DEPTH_CAP):
    nodes = graph.nodes
    adj = {}
    for a, c in graph.edges:
        adj.setdefault(a, []).append(c)
    dist, parent, frontier = {focus: 0}, {}, [focus]
    while frontier:
        nxt = []
        for n in frontier:
            if dist[n] > depth_cap:
                continue
            for m in adj.get(n, ()):
                if m not in dist:
                    dist[m] = dist[n] + 1
                    parent[m] = n
                    nxt.append(m)
        frontier = nxt
    reach = {n: d for n, d in dist.items() if n != focus}

    def causes(n):
        info, c = nodes[n], []
        if not info["loc"]:
            c.append("missing_source_location")
        if info["lookup"] == "not_run":
            c.append("lookup_not_run")
        if info["lookup"] in GAP_LOOKUP - {"not_run"}:
            c.append("lookup_incomplete")
        return c
    pred = {"all": lambda n: True, "direct": lambda n: reach[n] == 1, "transitive": lambda n: reach[n] >= 2,
            "advisory": lambda n: nodes[n]["lookup"] == "match", "evidence_gaps": lambda n: bool(causes(n))}
    totals = {k: sum(1 for n in reach if f(n)) for k, f in pred.items()}
    q = query.lower()
    sel = sorted((n for n in reach if pred[filt](n) and (not q or q in ((nodes[n]["name"] or "") + " " + (nodes[n]["version"] or "")).lower())),
                 key=lambda n: ((nodes[n]["name"] or "").lower(), nodes[n]["version"] or "", n))
    if sel:
        offset = min(offset - offset % PAGE, ((len(sel) - 1) // PAGE) * PAGE)
    else:
        offset = 0
    page_matches = sel[offset:offset + PAGE]
    shown_ids, edges, connectors, states = set(page_matches), {}, [], {}
    omitted_for = set()
    for m in page_matches:
        d = reach[m]
        if d > depth_cap:
            states[m] = "depth_limit"
            continue
        path, cur = [], m
        while cur != focus:
            path.append((parent[cur], cur))
            cur = parent[cur]
        new_conn = [e[0] for e in path if e[0] not in shown_ids and e[0] != focus]
        new_edges = [e for e in path if (e[0], e[1]) not in edges]
        too_many_connectors = len(connectors) + len(set(new_conn)) > connector_cap
        if too_many_connectors or len(edges) + len(new_edges) > edge_cap:
            states[m] = "connectors_omitted"
            omitted_for.add("connectors" if too_many_connectors else "edges")
            continue
        states[m] = "complete"
        for e in path:
            edges[(e[0], e[1])] = True
        for c in new_conn:
            if c not in shown_ids:
                shown_ids.add(c)
                connectors.append(c)
    for key in [k for k in edges if k[0] not in shown_ids | {focus} or k[1] not in shown_ids | {focus}]:
        del edges[key]
    complete = {m for m in page_matches if states[m] == "complete"} | set(connectors) | {focus}
    for a, c in graph.edges:
        if a in complete and c in complete and (a, c) not in edges and len(edges) < edge_cap and dist.get(c) == dist.get(a, -9) + 1:
            edges[(a, c)] = True

    def node_obj(n, role):
        info = nodes[n]
        d = 0 if n == focus else (reach[n] if reach[n] <= depth_cap else depth_cap + 1)
        cs = causes(n)
        return {"node_id": n, "name": info["name"] or "", "version": info["version"], "ecosystem": info["eco"], "role": role, "depth": d,
                "path_state": "complete" if n == focus else states.get(n, "complete"), "advisory_lookup": info["lookup"],
                "advisory_match_count": info["matches"] if info["lookup"] == "match" else 0, "has_source_location": info["loc"],
                "flags": {"direct": d == 1, "transitive": d >= 2, "evidence_gap": bool(cs)}, "gap_causes": cs}
    out_nodes = [node_obj(focus, "focus")] + [node_obj(n, "match") for n in page_matches]
    out_nodes += [node_obj(n, "connector") for n in connectors if n not in set(page_matches)]
    out_edges = [{"edge_id": edge_id(a, c), "from": a, "to": c, "kind": "declares_dependency",
                  "source_pointers": list(graph.pointers.get((a, c), ["/dependencies"]))[:3]} for (a, c) in sorted(edges)]
    shown = len(page_matches)
    lk = {k: 0 for k in LOOKUP_STATES}
    for n in reach:
        lk[nodes[n]["lookup"]] += 1
    any_nr = any(n["advisory_lookup"] == "not_run" for n in out_nodes)
    expl = (explanation or EXPL_DEFAULT) if any_nr else None
    conn_count = len([n for n in out_nodes if n["role"] == "connector"])
    return {"schema": "opentrace.workbench.dependency_page/1", "binding": binding, "context": {"context_id": ctx_id, "path": ctx_path},
            "focus": {"node_id": focus, "basis": basis, "candidates_total": candidates_total}, "filter": filt, "query": query,
            "lookup": {"mode": lookup_mode, "explanation": expl, "counts_by_state": lk}, "filter_totals": totals,
            "page": {"offset": offset, "size": PAGE, "matches_total": len(sel), "matches_shown": shown, "has_more": offset + shown < len(sel),
                     "range_first": offset + 1 if shown else 0, "range_last": offset + shown},
            "nodes": out_nodes, "edges": out_edges,
            "limits": {"connectors_shown": conn_count, "connectors_truncated": "connectors" in omitted_for,
                       "edges_truncated": "edges" in omitted_for},
            "counts": _count_block(len(sel), shown)}


def _count_block(total, shown):
    return {"total": total, "shown": shown, "truncated": shown < total}


# ------------------------------------------------------------------------------------------------- analysis -> graph and lookup
_LOCK = threading.Lock()
_CACHE = weakref.WeakKeyDictionary()          # analysis -> (digest, {path: (graph, lookup_mode)})
_CHOOSER = weakref.WeakKeyDictionary()        # analysis -> (digest, rows)


def _ref_state(source):
    """ref -> (state, matches, ecosystem) lookup for the analysis' advisory source, and the lookup mode."""
    rows_by_ref = getattr(source, "rows_by_ref", None) or {}
    report = getattr(source, "report", None)
    if getattr(source, "mode", None) == "live":
        if report is None:
            return "off", rows_by_ref, None, {}
        eco = {s["bom_ref"]: r["ecosystem"] for r in report["rows"] for s in r["sbom"] if s["bom_ref"]}
        return "live", rows_by_ref, getattr(source, "state_by_ref", {}), eco
    return "recorded", rows_by_ref, None, {}


def _lookup_for(mode, rows_by_ref, states, ref):
    rows = rows_by_ref.get(ref) or [] if ref else []
    if mode == "off":
        return "not_run", 0
    if mode == "recorded":
        return ("match", len(rows)) if rows else ("not_run", 0)
    found = (states or {}).get(ref) if ref else None
    if not found:
        return ("match", len(rows)) if rows else ("not_run", 0)
    st, reason = found["state"], found.get("reason") or ""
    if st == "match":
        return "match", max(1, len(rows))
    if st in ("no_match", "unavailable"):
        return st, 0
    if reason.startswith("version_"):
        return "missing_version", 0
    if reason == "not_in_lockfile_inventory":
        return "unsupported", 0
    return "not_run", 0


def _purl_types(analysis, artifact_id):
    """component index -> purl type (``npm``, ``pypi`` ...) from the analyzed SBOM; empty when the artifact has none. Cached per analysis."""
    import json
    digest = analysis.identity["analysis_digest"]
    with _LOCK:
        hit = _CACHE.get(analysis)
        if hit is not None and hit[0] == digest and ("purl", artifact_id) in hit[1]:
            return hit[1][("purl", artifact_id)]
    out = {}
    try:
        doc = json.loads(analysis.read(artifact_id).decode("utf-8"))
        for i, comp in enumerate(doc.get("components") or []):
            purl = comp.get("purl") if isinstance(comp, dict) else None
            if isinstance(purl, str) and purl.startswith("pkg:") and "/" in purl:
                out[i] = purl[4:].split("/", 1)[0].lower()
    except Exception:
        out = {}
    with _LOCK:
        hit = _CACHE.get(analysis)
        if hit is not None and hit[0] == digest:
            hit[1][("purl", artifact_id)] = out
    return out


def _build_graph(analysis, path):
    views = analysis.views
    _, tab = views._scope(path)
    mode, rows_by_ref, states, eco = _ref_state(views.demo)
    nodes, pointers = {}, {}
    for n in tab["nodes"]:
        ref = n.get("bom_ref")
        lookup, matches = _lookup_for(mode, rows_by_ref, states, ref)
        ptr = n.get("pointer") or ""
        idx = int(ptr.rsplit("/", 1)[-1]) if ptr.startswith("/components/") and ptr.rsplit("/", 1)[-1].isdigit() else None
        purl_eco = _purl_types(analysis, n["artifact_id"]).get(idx) if n.get("artifact_id") and idx is not None else None
        nodes[n["id"]] = {"name": _clean(n.get("name"), 256) or "", "version": _clean(n.get("version"), 128) or None,
                          "eco": _clean(purl_eco or eco.get(ref), 64) or None, "loc": bool(n.get("locations")), "lookup": lookup, "matches": matches}
    edges = []
    for e in tab["edges"]:
        edges.append((e["from"], e["to"]))
        ptrs = pointers.setdefault((e["from"], e["to"]), [])
        ptrs.extend(p for p in (e.get("source_pointers") or []) if isinstance(p, str) and 1 <= len(p) <= 512 and p not in ptrs)
    for key in pointers:
        pointers[key] = sorted(pointers[key])[:3] or ["/dependencies"]
    return Graph(nodes, edges, pointers), mode


def _graph_for(analysis, path):
    digest = analysis.identity["analysis_digest"]
    with _LOCK:
        hit = _CACHE.get(analysis)
        if hit is None or hit[0] != digest:
            hit = (digest, {})
            _CACHE[analysis] = hit
        cached = hit[1].get(path)
    if cached is not None:
        return cached
    try:
        built = _build_graph(analysis, path)
    except vc.ContractError:
        raise
    except Exception as exc:
        detail = getattr(exc, "code", None) or "projection_failed"
        raise vc.ContractError("projection_failed", str(detail)[:120] if isinstance(detail, str) else "projection_failed", "", "projection failed")
    with _LOCK:
        hit[1][path] = built
    return built


# ----------------------------------------------------------------------------------------------------------------- chooser model
def _chooser_rows(analysis):
    digest = analysis.identity["analysis_digest"]
    with _LOCK:
        hit = _CHOOSER.get(analysis)
        if hit is not None and hit[0] == digest:
            return hit[1]
    model = context_groups.model_for(analysis)
    rows = []
    for g in model.layout(digest):
        if g.kind != "located":
            continue
        for f in g.files:
            rows.append({"context_id": f["file_id"], "path": f["path"], "components_total": len(f["members"]), "category": g.category})
    rows.sort(key=lambda r: r["path"].encode("utf-8"))
    with _LOCK:
        _CHOOSER[analysis] = (digest, rows)
    return rows


def default_context(rows):
    """``(context_id, basis)`` over the complete set; independent of any paging, query or UI state."""
    eligible = [r for r in rows if r["category"] in DEPENDENCY_CATEGORIES]
    basis = "largest_dependency_file"
    if not eligible:
        eligible, basis = list(rows), "largest_file"
    if not eligible:
        return None, "none"
    best = sorted(eligible, key=lambda r: (-r["components_total"], r["path"].encode("utf-8")))[0]
    return best["context_id"], basis


_DEP_CONTEXT_PARAMS = {"generation", "offset", "limit", "query", "schema_version"}


def _chooser_request(params):
    out = {}
    for name, value in params.items():
        if isinstance(value, (list, tuple)):
            if len(value) != 1:
                raise vc.ContractError("invalid_request", "duplicate_parameter", name, "parameter repeated")
            value = value[0]
        if name not in _DEP_CONTEXT_PARAMS:
            raise vc.ContractError("invalid_request", "unknown_parameter", name, "unknown parameter")
        out[name] = value
    for name, lo, hi in (("generation", 1, 10 ** 9), ("offset", 0, LIM["offset_max"]), ("limit", 1, CHOOSER_MAX), ("schema_version", 1, 1)):
        if name in out:
            v = out[name]
            if isinstance(v, str):
                if not (v.isascii() and v.isdigit() and len(v) <= 9):
                    raise vc.ContractError("invalid_request", "type_error", name, "decimal integer expected")
                v = int(v)
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                raise vc.ContractError("invalid_request", "range_error", name, "out of range")
            out[name] = v
    if "generation" not in out:
        raise vc.ContractError("invalid_request", "missing_parameter", "generation", "generation is required")
    q = out.get("query", "")
    if not isinstance(q, str) or len(q.strip()) > LIM["string_chars"]["query"] or any(ord(ch) < 0x20 for ch in q):
        raise vc.ContractError("invalid_request", "invalid_query", "query", "query too long or contains control characters")
    out["query"] = q.strip()
    out.setdefault("offset", 0)
    out.setdefault("limit", CHOOSER_MAX)
    return out


def respond_contexts(analysis, params):
    request = _chooser_request(params)
    binding = build_binding(analysis)
    if request["generation"] != binding["generation"]:
        raise vc.ContractError("stale_generation", "invariant:generation", "generation", "the session has moved on")
    rows = _chooser_rows(analysis)
    default_id, default_basis = default_context(rows)
    q = request["query"].lower()
    matched = [r for r in rows if not q or q in r["path"].lower()]
    total = len(matched)
    offset = request["offset"]
    if offset and offset >= total:
        raise vc.ContractError("invalid_request", "offset_out_of_range", "offset", "the offset is past the last context")
    page = matched[offset:offset + request["limit"]]
    return {"schema": "opentrace.workbench.dependency_contexts/1", "binding": binding, "default_context_id": default_id,
            "default_basis": default_basis, "total": total, "offset": offset, "limit": request["limit"],
            "rows": [dict(r) for r in page], "counts": _count_block(total, len(page))}


def validate_contexts_payload(payload):
    """Local semantic validator of the chooser payload (not a frozen schema): bounds, uniqueness, count identities."""
    def need(cond, detail):
        if not cond:
            raise vc.ContractError("projection_failed", "invariant:" + detail, "", detail)
    rows = payload["rows"]
    need(len(rows) <= CHOOSER_MAX and len(rows) == payload["counts"]["shown"], "rows_shown")
    need(payload["counts"]["total"] == payload["total"] and payload["counts"]["truncated"] is (len(rows) < payload["total"]), "counts")
    need(len({r["context_id"] for r in rows}) == len(rows), "duplicate_context")
    for r in rows:
        need(vc._is_type(r["context_id"], "string") and r["context_id"].startswith("ctx:") and 1 <= len(r["path"]) <= 512
             and not any(ord(ch) < 0x20 for ch in r["path"]) and r["components_total"] >= 1, "row")
    need((payload["default_context_id"] is None) == (payload["default_basis"] == "none"), "default")
    need(payload["offset"] + len(rows) <= payload["total"] or payload["total"] == 0, "offset")


# ----------------------------------------------------------------------------------------------------------------------- route
def respond(analysis, params):
    """Validate the request, build and validate ``dependency_page/1``. Raises ``view_contracts.ContractError`` (typed)."""
    request = vc.validate_request("dependency_page", params)
    binding = build_binding(analysis)
    if request["generation"] != binding["generation"]:
        raise vc.ContractError("stale_generation", "invariant:generation", "generation", "the session has moved on")
    rows = _chooser_rows(analysis)
    by_id = {r["context_id"]: r for r in rows}
    ctx = by_id.get(request["context_id"])
    if ctx is None:
        raise vc.ContractError("invalid_request", "unknown_context", "context_id", "no such source context in this analysis")
    graph, mode = _graph_for(analysis, ctx["path"])
    focus_id = request.get("focus_id")
    if focus_id is not None:
        if focus_id not in graph.nodes:
            raise vc.ContractError("invalid_request", "unknown_focus", "focus_id", "the focus is not a package of this context")
        incoming = {c for _, c in graph.edges}
        basis, candidates = "requested", sum(1 for n in graph.nodes if n not in incoming) or len(graph.nodes)
        focus = focus_id
    else:
        chosen = choose_focus(graph)
        if chosen is None:
            raise vc.ContractError("not_found", "no_dependency_data", "context_id", "no package is recorded for this context")
        focus, basis, candidates = chosen
    explanation = {"recorded": EXPL_RECORDED, "off": EXPL_OFF}.get(mode)
    payload = page_from_graph(binding, ctx["context_id"], ctx["path"], graph, focus, filt=request["filter"], offset=request["offset"],
                              query=request.get("query", ""), lookup_mode=mode, explanation=explanation, basis=basis, candidates_total=candidates)
    expected = {k: binding[k] for k in ("analysis_digest", "commit_sha", "repository", "requested_ref", "mode", "assessment")}
    vc.validate_payload("dependency_page", payload, request={"generation": request["generation"]}, expected_binding=expected)
    return payload


def encode_response(payload):
    import json
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(body) > RESPONSE_MAX_BYTES:
        raise vc.ContractError("response_too_large", "bound_exceeded", "", "%d bytes exceeds the %d byte ceiling" % (len(body), RESPONSE_MAX_BYTES))
    return body
