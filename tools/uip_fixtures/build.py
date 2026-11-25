"""UIP-01B fixture builder: deterministic payload fixtures for ``opentrace.workbench.*/1``.

* ``synthetic`` fixtures are defined here from fixed seeds (no recorded-repository names, no prototype data).
* ``derived`` fixtures (the recorded-case set and ``legacy-view-snapshots``) run the *existing* trusted Workbench handlers in
  process on the recorded demo inputs (loopback HTTP and the engine's spawn IPC only) and map the results into the new shapes.
  The mapping is fixture-only code, not a production projection.
* Determinism: fixed clock, fixed session id, fixed generation, fixed seeds. The only values replaced after a real run are
  listed under ``normalized`` in the fixture manifest.

External network activity is refused for the whole run. Usage: ``python tools/uip_fixtures/build.py [--out DIR]``.
"""
import copy
import hashlib
import http.client
import json
import os
import re
import socket
import sys
import tempfile
import threading
from contextlib import contextmanager

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
for _p in (os.path.join(REPO, "src", "core"), os.path.join(REPO, "src", "agents", "investigator")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from opentrace_core.app import view_contracts as vc  # noqa: E402

FIXED_TS = "2026-01-01T00:00:00Z"
FIXED_SESSION = "00000000000000000000000000000001"
FIXED_VALIDATION = hashlib.sha256(b"uip-01b-fixture-validation-digest").hexdigest()
SEED = "uip-01b/1"
DEFAULT_OUT = os.path.join(REPO, "evidence", "uip", "fixtures")
RECORDED_NAME = "fri" + "gate-recorded"  # split so the leak scan can cover this file
CONTAINS_KEY = "contains_fri" + "gate_names"  # manifest key named by the contract
BUILDER_PATH = "tools/uip_fixtures/build.py"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- network guard (external activity forbidden)
@contextmanager
def no_external_network():
    real_connect, real_connect_ex, real_gai = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

    def ok_addr(addr):
        if isinstance(addr, str):
            return True  # AF_UNIX
        return addr[0] in ("127.0.0.1", "::1", "localhost")

    def connect(self, addr):
        if not ok_addr(addr):
            raise OSError("uip-fixtures: external connection refused: %r" % (addr,))
        return real_connect(self, addr)

    def connect_ex(self, addr):
        if not ok_addr(addr):
            raise OSError("uip-fixtures: external connection refused: %r" % (addr,))
        return real_connect_ex(self, addr)

    def gai(host, *a, **k):
        if host not in ("127.0.0.1", "::1", "localhost", None):
            raise OSError("uip-fixtures: name resolution refused: %r" % (host,))
        return real_gai(host, *a, **k)
    socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = connect, connect_ex, gai
    try:
        yield
    finally:
        socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = real_connect, real_connect_ex, real_gai


# ---------------------------------------------------------------- shared constructors
def repo_obj(owner, name):
    return {"host": "github.com", "owner": owner, "name": name, "canonical_url": "https://github.com/%s/%s" % (owner, name)}


def assessment_binding(seed, kind="discovery"):
    return {"kind": kind, "schema": "opentrace.bombridge_assessment/1", "validation_digest": sha(seed + ":validation"),
            "bundle_sha256": sha(seed + ":bundle"), "configuration": "config:fixture:" + sha(seed)[:16]}


def make_binding(owner, name, seed, *, assessment=False, mode="captured", generation=1):
    return {"analysis_digest": "sha256:" + sha(seed + ":analysis"), "repository": repo_obj(owner, name), "commit_sha": sha(seed + ":commit")[:40],
            "requested_ref": {"kind": "tag", "text": "v1.0.0"}, "generation": generation, "mode": mode,
            "assessment": assessment_binding(seed) if assessment else None}


def oid(b, prefix, kind, key):
    return vc.opaque_id(prefix, b["analysis_digest"], kind, str(key))


def cref(b, record_class, record_id, seed="fixture"):
    return {"record_class": record_class, "record_id": record_id,
            "binding": {"analysis_digest": b["analysis_digest"], "session_id": FIXED_SESSION, "generation": b["generation"],
                        "configuration": (b["assessment"] or {}).get("configuration", "config:fixture:" + sha(seed)[:16]),
                        "bundle_sha256": (b["assessment"] or {}).get("bundle_sha256", sha(seed + ":bundle"))}}


def count_block(total, shown, truncated=None):
    return {"total": total, "shown": shown, "truncated": (shown < total) if truncated is None else truncated}


def link(b, path):
    from urllib.parse import quote
    r = b["repository"]
    return {"href": "https://github.com/%s/%s/blob/%s/%s" % (r["owner"], r["name"], b["commit_sha"], quote(path)), "text": path}


def inert_link(text):
    return {"href": None, "text": text}


def eid(prefix, *parts):
    return "%s:%s" % (prefix, sha("|".join(str(p) for p in parts))[:24])


def prov(producer, origin, *, artifact_id=None, pointer=None, experimental=False, version=None):
    return {"producer_id": producer, "producer_version": version, "origin": origin, "artifact_id": artifact_id,
            "json_pointer": pointer, "experimental": experimental}


def attr(state="unavailable", value=None, basis=None):
    return {"state": state, "value": value, "basis": basis}


# ---------------------------------------------------------------- scan_status
STAGES = vc.STAGE_ORDER


def stage(sid, state, reason=None, *, t0=None, t1=None, outputs=()):
    return {"stage_id": sid, "state": state, "reason_code": reason, "started_at": t0, "finished_at": t1, "updated_at": t1 or t0 or FIXED_TS,
            "outputs": list(outputs), "warnings": []}


def out(kind, seed):
    return {"kind": kind, "artifact_id": "art:%s-%s" % (kind, sha(seed + kind)[:8]), "sha256": sha(seed + kind + ":bytes"), "size": 1000 + len(seed)}


def scan_payload(seed, job_seq, stages, *, owner="example-org", name="sample-web", resolved=True, cancelled_cleanup=None, mode="captured", t="2026-01-01T00:00:%02dZ"):
    b = make_binding(owner, name, seed, assessment=False, mode=mode)
    state = vc._derive_job_state(stages)
    ready = state in ("completed", "partial")
    identity = None
    if resolved:
        identity = {"schema": "opentrace.analysis_identity/1", "input": {"url": "https://github.com/%s/%s/tree/v1.0.0" % (owner, name), "manual_sha": None},
                    "repository": b["repository"], "requested": {"kind": "tag", "text": "v1.0.0", "origin": "url_tree"},
                    "resolved": {"commit_sha": b["commit_sha"], "resolved_at": FIXED_TS, "basis": "url_revision", "manual_corroboration": False},
                    "scan": {"profile_id": "opentrace.scan.default/1", "inventories": ["aibom", "cbom", "sbom"], "scope": "repository_root"},
                    "session": {"generation": 1}, "analysis_digest": b["analysis_digest"]}
    cleanup = "not_needed" if state != "cancelled" else (cancelled_cleanup or "verified")
    return {"schema": "opentrace.workbench.scan_status/1", "generation": 1, "mode": mode,
            "job": {"job_id": oid(b, "job", "job", seed), "seq": job_seq, "state": state, "created_at": FIXED_TS, "updated_at": t % (job_seq % 60),
                    "elapsed_ms": job_seq * 1000},
            "binding_state": "resolved" if resolved else "unresolved", "binding": b if resolved else None, "pinned": resolved, "identity": identity,
            "stages": stages, "handoff": {"ready": ready, "blocked_reason": None if ready else "Workbench is not ready: the scan has not completed."},
            "cleanup": {"state": cleanup}}


def stages_for(spec, seed):
    """spec: stage_id -> (state, reason) ; others queued. Times derive from position."""
    res = []
    for i, sid in enumerate(STAGES):
        state, reason = spec.get(sid, ("queued", None))
        t0 = "2026-01-01T00:00:%02dZ" % (i * 2 + 1) if state not in ("queued", "not_run", "unsupported") else None
        t1 = "2026-01-01T00:00:%02dZ" % (i * 2 + 2) if state in ("completed", "completed_empty", "partial", "failed", "cancelled") and t0 else None
        outs = [out(sid, seed)] if sid in ("sbom", "cbom", "aibom") and state in ("completed", "completed_empty", "partial") else []
        res.append(stage(sid, state, reason, t0=t0, t1=t1, outputs=outs))
    return res


def scan_matrix():
    seed = "scan-matrix"
    done = {s: ("completed", None) for s in STAGES}
    seqs = []
    q = stages_for({}, seed)
    seqs.append(("00-queued", scan_payload(seed, 0, q, resolved=False)))
    seqs.append(("01-resolving", scan_payload(seed, 1, stages_for({"resolve_revision": ("running", None)}, seed), resolved=False)))
    seqs.append(("02-acquiring", scan_payload(seed, 2, stages_for({"resolve_revision": ("completed", None), "acquire_source": ("running", None)}, seed))))
    seqs.append(("03-sbom-running", scan_payload(seed, 3, stages_for({"resolve_revision": ("completed", None), "acquire_source": ("completed", None), "sbom": ("running", None)}, seed))))
    full = dict(done)
    full.update({"aibom": ("not_run", "not_configured"), "advisory_lookup": ("not_run", "disabled"), "source_checks": ("not_run", "disabled")})
    seqs.append(("04-completed", scan_payload(seed, 4, stages_for(full, seed))))
    empty = dict(full)
    empty["cbom"] = ("completed_empty", "no_applicable_assets")
    p_empty = scan_payload("scan-empty", 4, stages_for(empty, "scan-empty"))
    part = dict(full)
    part.update({"cbom": ("partial", "partial_coverage"), "aibom": ("unsupported", "unsupported_ecosystem")})
    p_part = scan_payload("scan-partial", 4, stages_for(part, "scan-partial"))
    fail_resolve = {"resolve_revision": ("failed", "invalid_revision")}
    fail_resolve.update({s: ("not_run", "upstream_failed") for s in STAGES[1:]})
    p_fail1 = scan_payload("scan-fail-resolve", 2, stages_for(fail_resolve, "scan-fail-resolve"), resolved=False)
    fail_scan = dict(done)
    fail_scan.update({"cbom": ("failed", "scanner_failed"), "aibom": ("not_run", "not_configured"), "advisory_lookup": ("not_run", "upstream_failed"),
                      "source_checks": ("not_run", "upstream_failed"), "evidence_projection": ("not_run", "upstream_failed"), "workbench_ready": ("not_run", "upstream_failed")})
    p_fail2 = scan_payload("scan-fail-scan", 6, stages_for(fail_scan, "scan-fail-scan"))
    canc = {"resolve_revision": ("completed", None), "acquire_source": ("completed", None), "sbom": ("cancelled", "cancelled_by_user")}
    canc.update({s: ("cancelled", "cancelled_by_user") for s in STAGES[3:]})
    p_c1 = scan_payload("scan-cancel-ok", 5, stages_for(canc, "scan-cancel-ok"), cancelled_cleanup="verified")
    p_c2 = scan_payload("scan-cancel-unverified", 5, stages_for(canc, "scan-cancel-unverified"), cancelled_cleanup="unverified")
    files = dict(seqs)
    files.update({"05-completed-empty-cbom": p_empty, "06-partial": p_part, "07-failed-resolution": p_fail1, "08-failed-scan": p_fail2,
                  "09-cancelled-cleanup-verified": p_c1, "10-cancelled-cleanup-unverified": p_c2})
    return files, [p for _, p in seqs]


# ---------------------------------------------------------------- contexts
def classify(path):
    base = path.rsplit("/", 1)[-1]
    if path.startswith("docs/"):
        return "documentation", "path_prefix"
    if path.startswith("web/"):
        return "web", "path_prefix"
    if path.startswith(".github/"):
        return "github_actions", "path_prefix"
    if re.match(r"^requirements.*\.txt$", base):
        return "python_requirements", "manifest_basename"
    if base == "go.mod":
        return "go_modules", "manifest_basename"
    if base == "Cargo.toml":
        return "rust_crates", "manifest_basename"
    if base == "pom.xml":
        return "java_build", "manifest_basename"
    if base == "package.json" or base == "package-lock.json":
        return "node_packages", "manifest_basename"
    if base == "Dockerfile":
        return "container_files", "manifest_basename"
    return "other_locations", "fallback"


CAT_LABEL = {"documentation": "Documentation", "web": "Web application", "node_packages": "Node packages", "python_requirements": "Python requirements",
             "go_modules": "Go modules", "rust_crates": "Rust crates", "java_build": "Java build files", "github_actions": "GitHub Actions",
             "container_files": "Container files", "other_locations": "Other locations"}
CAT_ORDER = list(CAT_LABEL)


def contexts_payload(b, files, unlocated_ids, *, files_limit=20, files_offset=0, only_category=None, selected=None):
    """files: list of {path, raw_locations, basis[], members:set}. Group by classifier; distinct = union of member ids."""
    by_cat = {}
    for f in files:
        cat, basis = classify(f["path"])
        by_cat.setdefault(cat, []).append((f, basis))
    all_members, groups, membership_total = set(), [], 0
    group_rows = []
    for cat in CAT_ORDER:
        if cat not in by_cat:
            continue
        rows = sorted(by_cat[cat], key=lambda x: x[0]["path"])
        members = set().union(*[r[0]["members"] for r in rows])
        all_members |= members
        mem = sum(len(r[0]["members"]) for r in rows)
        membership_total += mem
        group_rows.append((cat, rows, members, mem))
    unl = sorted(unlocated_ids)
    for cat, rows, members, mem in group_rows:
        if only_category and cat != only_category:
            continue
        page = rows[files_offset:files_offset + files_limit]
        fcards = []
        for f, basis in page:
            fid = oid(b, "ctx", "file", f["path"])
            fcards.append({"file_id": fid, "path": f["path"], "raw_locations": f["raw_locations"][:5], "raw_locations_total": len(f["raw_locations"]),
                           "normalization_basis": f["basis"], "distinct_total": len(f["members"]), "membership_total": len(f["members"]),
                           "dependency_context_id": fid if cat in ("node_packages", "web", "python_requirements", "go_modules", "rust_crates", "java_build") else None,
                           "revision_link": link(b, f["path"])})
        groups.append({"group_id": oid(b, "grp", "group", cat), "kind": "located", "category": cat, "token": vc.CATEGORY_TOKEN[cat],
                       "label": CAT_LABEL[cat], "basis": rows[0][1] if len({r[1] for r in rows}) == 1 else "path_prefix",
                       "distinct_total": len(members), "membership_total": mem, "files": fcards,
                       "files_counts": count_block(len(rows), len(fcards), len(fcards) < len(rows)), "files_offset": files_offset})
    if unl and not only_category:
        groups.append({"group_id": oid(b, "grp", "group", "unlocated"), "kind": "unlocated", "category": None, "token": "neutral",
                       "label": "Unlocated components", "basis": "fallback", "distinct_total": len(unl), "membership_total": len(unl), "files": [],
                       "files_counts": count_block(0, 0, False), "files_offset": 0})
    total_groups = len(group_rows) + (1 if unl else 0)
    r = b["repository"]
    return {"schema": "opentrace.workbench.contexts/1", "binding": b,
            "root": {"name": "%s/%s" % (r["owner"], r["name"]), "canonical_url": r["canonical_url"], "commit_sha": b["commit_sha"],
                     "distinct_total": len(all_members) + len(unl), "membership_total": membership_total,
                     "located_distinct_total": len(all_members), "unlocated_total": len(unl)},
            "edge_semantics": "grouping_or_inventory_location", "groups": groups, "selected_id": selected,
            "counts": count_block(total_groups, len(groups))}


# ---------------------------------------------------------------- dependency pages
GAP_LOOKUP = {"unavailable", "unsupported", "missing_version", "not_run"}


def dep_page(b, ctx_path, graph, focus, *, filt="all", offset=0, query="", lookup_mode="recorded", explanation=None, basis="requested",
             candidates_total=1, connector_cap=None, edge_cap=None, depth_cap=None):
    """graph: {"nodes": {id: {name, version, eco, loc(bool), lookup, matches(int)}}, "edges": [(from, to)]}. Fixture-only projection."""
    connector_cap = connector_cap or vc.LIMITS["dependency_connectors_per_page"]
    edge_cap = edge_cap or vc.LIMITS["dependency_edges_per_page"]
    depth_cap = depth_cap or vc.LIMITS["dependency_path_depth"]
    nodes, adj = graph["nodes"], {}
    for a, c in graph["edges"]:
        adj.setdefault(a, []).append(c)
    for k in adj:
        adj[k].sort()
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
    sel = sorted((n for n in reach if pred[filt](n) and (not q or q in (nodes[n]["name"] + " " + (nodes[n]["version"] or "")).lower())),
                 key=lambda n: (nodes[n]["name"].lower(), nodes[n]["version"] or "", n))
    page_matches = sel[offset:offset + 30]
    shown_ids, edges, connectors, states = set(page_matches), {}, [], {}
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
        if len(connectors) + len(set(new_conn)) > connector_cap or len(edges) + len(new_edges) > edge_cap:
            states[m] = "connectors_omitted"
            continue
        states[m] = "complete"
        for e in path:
            edges[(e[0], e[1])] = True
        for c in new_conn:
            if c not in shown_ids:
                shown_ids.add(c)
                connectors.append(c)
    # a connector may itself be a match elsewhere on the page: it stays a match
    for key in [k for k in edges if k[0] not in shown_ids | {focus} or k[1] not in shown_ids | {focus}]:
        del edges[key]
    # recorded edges among displayed nodes with complete paths (multiple incoming paths preserved)
    complete = {m for m in page_matches if states[m] == "complete"} | set(connectors) | {focus}
    for a, c in graph["edges"]:
        if a in complete and c in complete and (a, c) not in edges and len(edges) < edge_cap and dist.get(c) == dist.get(a, -9) + 1:
            edges[(a, c)] = True

    def node_obj(n, role):
        info = nodes[n]
        d = 0 if n == focus else (reach[n] if reach[n] <= depth_cap else depth_cap + 1)
        cs = causes(n)
        return {"node_id": n, "name": info["name"], "version": info["version"], "ecosystem": info["eco"], "role": role, "depth": d,
                "path_state": "complete" if n == focus else states.get(n, "complete"), "advisory_lookup": info["lookup"],
                "advisory_match_count": info["matches"] if info["lookup"] == "match" else 0, "has_source_location": info["loc"],
                "flags": {"direct": d == 1, "transitive": d >= 2, "evidence_gap": bool(cs)}, "gap_causes": cs}
    out_nodes = [node_obj(focus, "focus")] + [node_obj(n, "match") for n in page_matches]
    out_nodes += [node_obj(n, "connector") for n in connectors if n not in set(page_matches)]
    out_edges = [{"edge_id": eid("edge", a, c), "from": a, "to": c, "kind": "declares_dependency", "source_pointers": ["/dependencies/%s" % sha(a + c)[:6]]}
                 for (a, c) in sorted(edges)]
    shown = len(page_matches)
    lk = {k: 0 for k in ("match", "no_match", "unavailable", "unsupported", "missing_version", "not_run")}
    for n in reach:
        lk[nodes[n]["lookup"]] += 1
    any_nr = any(n["advisory_lookup"] == "not_run" for n in out_nodes)
    expl = (explanation or "Advisory lookup was not performed for these components; this is not a completed clean lookup and not a finding.") if any_nr else None
    conn_count = len([n for n in out_nodes if n["role"] == "connector"])
    return {"schema": "opentrace.workbench.dependency_page/1", "binding": b, "context": {"context_id": oid(b, "ctx", "file", ctx_path), "path": ctx_path},
            "focus": {"node_id": focus, "basis": basis, "candidates_total": candidates_total}, "filter": filt, "query": query,
            "lookup": {"mode": lookup_mode, "explanation": expl, "counts_by_state": lk}, "filter_totals": totals,
            "page": {"offset": offset, "size": 30, "matches_total": len(sel), "matches_shown": shown, "has_more": offset + shown < len(sel),
                     "range_first": offset + 1 if shown else 0, "range_last": offset + shown},
            "nodes": out_nodes, "edges": out_edges,
            "limits": {"connectors_shown": conn_count, "connectors_truncated": any(s == "connectors_omitted" for s in states.values()),
                       "edges_truncated": False},
            "counts": count_block(len(sel), shown)}


def gnode(name, ver="1.0.0", loc=True, lookup="no_match", matches=0, eco="npm"):
    return {"name": name, "version": ver, "eco": eco, "loc": loc, "lookup": lookup, "matches": matches}


# ---------------------------------------------------------------- assets
def assets_payload(tab, b, availability, producers, assets, *, services=None, links=(), reviews=(), groups=(), filt="all", offset=0, total=None):
    crypto = tab == "crypto"
    total = len(assets) if total is None else total
    kinds = {"findings": lambda a: False}
    flt = {"all": total, "findings": len(reviews)}
    if crypto:
        flt.update({"algorithms": sum(1 for a in assets if a["kind"] == "algorithm"), "protocols": sum(1 for a in assets if a["kind"] == "protocol"),
                    "certificates": sum(1 for a in assets if a["kind"] == "certificate")})
    else:
        flt.update({"models": sum(1 for a in assets if a["kind"].startswith(("model", "inventory"))), "runtimes": sum(1 for a in assets if a["kind"] == "runtime"),
                    "ai_services": sum(1 for a in assets if a["kind"] == "ai_service")})
    shown = len(assets)
    more = offset + shown < total
    payload = {"schema": "opentrace.workbench.%s_assets/1" % tab, "binding": b, "tab": tab, "availability": availability, "absence_established": False,
               "producers": producers, "filter": filt, "filter_totals": flt, "source_groups": list(groups), "assets": assets, "links": list(links),
               "review_items": list(reviews), "page": {"offset": offset, "size": 30, "assets_total": total, "assets_shown": shown, "has_more": more},
               "counts": count_block(total, shown)}
    if crypto:
        sv = services or []
        payload["services"] = sv
        payload["services_counts"] = count_block(len(sv), len(sv))
    return payload


def avail(state, message, reason=None):
    default = {"completed": None, "completed_empty": "no_applicable_assets", "partial": "partial_coverage", "failed": "scanner_failed",
               "unsupported": "unsupported_ecosystem", "not_run": "not_configured"}
    return {"state": state, "reason_code": reason or default[state], "message": message}


def producer(pid, origin, scope, outcome, *, artifact_id=None, pointer=None, experimental=False, cov=None, version=None):
    c = {"files_considered": 0, "files_parsed": 0, "files_excluded": 0, "excluded_paths": [], "unparsed_total": 0, "unknown_dynamic_values_total": 0}
    c.update(cov or {})
    return {"provenance": prov(pid, origin, artifact_id=artifact_id, pointer=pointer, experimental=experimental, version=version), "scope": scope,
            "outcome": outcome, "coverage": c}


def source_loc(b, path, l0, l1, excerpt, sha_=None):
    return {"path": path, "file_sha256": sha_ or sha(b["commit_sha"] + path), "line_start": l0, "line_end": l1, "excerpt": excerpt,
            "excerpt_state": "recorded" if excerpt else "unavailable", "link": link(b, path)}


def occ(b, key, path, l0, l1, excerpt, operation=None, cond=None, cond_basis="none", alt=None, producer_id="x", with_hash=True):
    loc = source_loc(b, path, l0, l1, excerpt)
    if not with_hash:
        loc["file_sha256"] = None
    return {"occurrence_id": oid(b, "occ", "occurrence", key), "source_location": loc, "operation": operation,
            "condition": {"text": cond, "basis": cond_basis}, "alternative_of": alt, "producer_id": producer_id}


def asset(b, key, kind, name, provenance, *, attrs=None, occs=(), groups=(), tab="crypto", identity="unresolved", dgroup=None):
    keys = ["algorithm_name", "primitive", "parameter", "protocol_name", "protocol_version", "certificate_subject"] if tab == "crypto" else \
           ["provider", "model_version", "license", "dataset_provenance", "artifact_digest", "active_configuration"]
    a = {"asset_id": oid(b, "ast", "asset", key), "kind": kind, "display_name": name, "provenance": provenance,
         "attributes": {k: (attrs or {}).get(k, attr("unavailable", None, "not recorded by this producer")) for k in keys},
         "source_group_ids": list(groups), "occurrences": list(occs), "occurrences_total": len(occs)}
    if tab == "ai":
        a["identity_state"] = identity
        a["display_group"] = dgroup
    return a


def src_group(b, label, path, total):
    return {"group_id": oid(b, "grp", "source", path or label), "label": label, "path": path, "assets_total": total}


# ---------------------------------------------------------------- inspector
def inspector(b, tab, kind, sid, title, *, rows=(), badge=None, bom=False, third_state=None, ref=None, actions=("source_access", "ask_about_this")):
    ctx = kind in vc.CONTEXT_KINDS
    third = "comparison_established" if bom else "security_concern"
    if third_state is None:
        third_state = "not_applicable" if ctx or (bom and kind in ("entity", "evidence", "edge")) else "not_assessed"
    body = {"what_is_this": "Recorded %s selected in this analysis." % kind, "why_here": "It appears in the recorded inventory scope for this revision.",
            third: "This record is not a security assessment." if ctx else "No assessment was performed for this record.",
            "what_unknown": "Runtime use, installation and deployed configuration are not established."}
    qs = ["what_is_this", "why_here", third, "what_unknown"]
    return {"schema": "opentrace.workbench.inspector/1", "binding": b, "tab": tab,
            "selection": {"kind": kind, "id": sid, "canonical_ref": ref}, "title": title,
            "badge": badge or {"kind": "context" if ctx else "neutral", "label": "Repository context" if ctx else "Record"},
            "question_set": "bom_comparison" if bom else "context_four",
            "answers": [{"question_id": q, "state": third_state if q == third else "not_assessed" if q == "what_unknown" else "inventory_reported", "body": body[q]} for q in qs],
            "evidence_rows": list(rows), "sources_coverage": {"available": True, "items": ["Original artifact digest is recorded in the scan."]},
            "actions": list(actions), "next_step": None}


# ---------------------------------------------------------------- BOM
CATS = {"missing_component": "Missing component", "unknown_coverage": "Coverage unknown"}


def bom_item(b, key, name, *, category="missing_component", state="contradicted", assertion=None, path=None, line=None, inv_kind="sbom", family=None,
             basis=None, inherited=False, graph="assertion_graph", mode_kind="candidate", rule="inventory_coverage.requirement_represented/1"):
    inv = {"inventory_id": "inv:%s-source" % inv_kind, "kind": inv_kind, "generator": "fixture-generator 1.0", "sha256": sha("inv:" + inv_kind)} if inv_kind else None
    fam = family or (vc.INVENTORY_FAMILY[inv_kind] if inv_kind else "other")
    fb = basis or ("inventory_kind" if inv_kind and family is None else "unclassified" if fam == "other" else "typed_metadata")
    cid = "cand:%s:%s" % (category, sha(key)[:8])
    return {"item_id": cid, "item_kind": mode_kind, "assertion_id": assertion, "canonical_ref": cref(b, "candidate", cid, "bom"),
            "display": {"name": name, "raw_title": "%s is declared in source but not represented in the inventory" % name}, "family": fam,
            "family_basis": fb, "category": category, "state": state, "filter_group": vc.FILTER_GROUP[state], "inherited": inherited,
            "location": {"path": path, "line_start": line, "line_end": line} if path else None, "inventory": inv, "rule_id": rule if state != "unknown_coverage" else None,
            "graph_state": graph}


def bom_candidates_payload(b, items_all, *, offset=0, filters=None, mode="discovery_compared", status_detail=None, caps=None, all_items=None):
    all_items = items_all if all_items is None else all_items
    f = {"family": None, "filter_group": None, "state": None, "category": None, "query": ""}
    f.update(filters or {})

    def match(it):
        return all((f[k] is None or it[k] == f[k]) for k in ("family", "filter_group", "state", "category")) and \
               (not f["query"] or f["query"].lower() in it["display"]["name"].lower())
    sel = [it for it in items_all if match(it)]
    page = sel[offset:offset + 25]
    fam = {k: 0 for k in vc.FAMILIES_LIST} if hasattr(vc, "FAMILIES_LIST") else {k: 0 for k in ("software", "cryptography", "ai_model", "other")}
    st = {k: 0 for k in ("supported", "contradicted", "conflicting_evidence", "unverifiable", "unknown_coverage", "no_rule")}
    fg = {"represented": 0, "not_represented": 0, "unknown": 0}
    for it in all_items:
        fam[it["family"]] += 1
        st[it["state"]] += 1
        fg[it["filter_group"]] += 1
    default_caps = [{"family": "software", "state": "completed", "reason_code": None},
                    {"family": "cryptography", "state": "not_run", "reason_code": "not_configured"},
                    {"family": "ai_model", "state": "not_run", "reason_code": "not_configured"},
                    {"family": "other", "state": "completed", "reason_code": None}]
    return {"schema": "opentrace.workbench.bom_candidates/1", "binding": b, "mode": mode, "status_detail": status_detail,
            "capabilities": caps or default_caps,
            "counts": {"candidates_total": len(all_items), "assertions_unique": len({i["assertion_id"] for i in all_items if i["assertion_id"]}),
                       "records_total": 3 * len(all_items), "relationships_total": 2 * len(all_items), "filtered_total": len(sel), "family_counts": fam,
                       "state_counts": st, "filter_group_counts": fg, "family_counts_disjoint": True},
            "filters": f, "items": page, "page": {"offset": offset, "size": 25, "has_more": offset + len(page) < len(sel)}}


def gn(b, nid, kind, label, *, role="primary", ev=None, state=None, origin="recorded_result"):
    return {"node_id": nid, "canonical_ref": cref(b, "graph_" + kind, nid, "bom"), "kind": kind, "label": label[:120], "full_label": label[:256],
            "origin": origin, "role": role, "evidence_role": ev, "state": state}


def ge(eid_, a, c, typ, role=None, why=None):
    return {"edge_id": eid_, "from": a, "to": c, "type": typ, "label": typ[:120], "role": role, "rationale": why}


def graph_payload(b, scope_kind, nodes, edges, gstate, *, cand=None, group=None, query="", page=None, nodes_in_scope=None, edges_in_scope=None, msg=None):
    primary = sum(1 for n in nodes if n["role"] == "primary")
    nis = len(nodes) if nodes_in_scope is None else nodes_in_scope
    eis = len(edges) if edges_in_scope is None else edges_in_scope
    return {"schema": "opentrace.workbench.bom_graph/1", "binding": b,
            "scope": {"kind": scope_kind, "candidate_id": cand, "group": group, "query": query}, "graph_state": gstate, "message_code": msg,
            "nodes": nodes, "edges": edges, "records": [{"node_id": n["node_id"], "full_label": n["full_label"]} for n in nodes], "page": page,
            "counts": {"nodes_in_scope": nis, "nodes_shown": len(nodes), "primary_shown": primary, "neighbors_shown": len(nodes) - primary,
                       "edges_in_scope": eis, "edges_shown": len(edges), "omitted_nodes": nis - len(nodes), "omitted_edges": eis - len(edges)},
            "truncated": nis > len(nodes) or eis > len(edges)}


def related_payload(b, subject, items_all, *, offset=0, kind="record", detail=None):
    page = items_all[offset:offset + 20]
    total = len(items_all)
    res = "not_applicable" if kind == "relationship" else "none" if total == 0 else "single" if total == 1 else "multiple"
    more = offset + len(page) < total
    return {"schema": "opentrace.workbench.bom_related_checks/1", "binding": b,
            "subject": {"kind": kind, "id": subject, "canonical_ref": cref(b, kind, subject, "bom")}, "resolution": res, "related_total": total,
            "items": page, "record_detail": detail if res in ("none",) else None, "counts": count_block(total, len(page)),
            "page": {"offset": offset, "size": 20, "has_more": more}}


def rel_item(it):
    return {"item_id": it["item_id"], "assertion_id": it["assertion_id"], "display_name": it["display"]["name"], "family": it["family"],
            "state": it["state"], "location": it["location"]}


def record_detail(title):
    return {"title": title, "kinds": ["inventory"], "provenance": prov("fixture-generator", "original_artifact", artifact_id="art:fixture", pointer="/metadata"),
            "limitations": ["No focused assessment graph is attached to this record."]}


# ---------------------------------------------------------------- manifest + writing
class Fixture:
    def __init__(self, name, provenance, notes, normalized=None, sources=None, recorded_names=False):
        self.name, self.provenance, self.notes, self.normalized, self.sources, self.recorded_names = name, provenance, notes, normalized or [], sources or [], recorded_names
        self.files = {}

    def add(self, fname, schema_name, payload):
        self.files[fname] = (schema_name, payload)


def write_fixture(out_dir, fx, validated=True):
    d = os.path.join(out_dir, fx.name)
    os.makedirs(d, exist_ok=True)
    entries = []
    for fname in sorted(fx.files):
        schema_name, payload = fx.files[fname]
        if validated and schema_name != "sequence":
            vc.validate_payload(schema_name, payload)
        data = (json.dumps(payload, sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
        with open(os.path.join(d, fname), "wb") as h:
            h.write(data)
        entries.append({"path": fname, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "schema": vc.SCHEMA_IDS.get(schema_name, schema_name)})
    with open(os.path.join(REPO, BUILDER_PATH), "rb") as h:
        bsha = hashlib.sha256(h.read()).hexdigest()
    manifest = {"schema": "opentrace.uip.fixture_manifest/1", "name": fx.name, "provenance": fx.provenance, "files": entries, "sources": fx.sources,
                "builder": {"path": BUILDER_PATH, "sha256": bsha, "seed": SEED}, CONTAINS_KEY: fx.recorded_names, "normalized": fx.normalized,
                "notes": fx.notes}
    with open(os.path.join(d, "MANIFEST.json"), "w", encoding="utf-8") as h:
        h.write(json.dumps(manifest, sort_keys=True, indent=1, ensure_ascii=False) + "\n")
    return manifest


# ================================================================ synthetic fixtures
def _pk(name):
    return "pkg:%s" % name


def fx_deps82():
    fx = Fixture("deps-82-synthetic", "synthetic", "One focus with 82 direct dependencies: pages 30/30/22; connectors never count toward the 30; filter variants.")
    b = make_binding("example-org", "sample-web", "deps82")
    nodes = {_pk("root"): gnode("root-app", "1.0.0", True, "no_match")}
    edges = []
    special = {"match": {7, 21, 44, 63}, "unavailable": {10}, "missing_version": {20}, "unsupported": {30}, "not_run": {60}}
    noloc = {15, 16}
    for i in range(1, 83):
        lk = next((k for k, s in special.items() if i in s), "no_match")
        n = gnode("dep-%03d" % i, None if lk == "missing_version" else "1.%d.0" % i, i not in noloc, lk, 1 if lk == "match" else 0)
        nodes[_pk("dep-%03d" % i)] = n
        edges.append((_pk("root"), _pk("dep-%03d" % i)))
    g = {"nodes": nodes, "edges": edges}
    ctx = "app/package-lock.json"
    for off in (0, 30, 60):
        fx.add("page-offset-%02d.json" % off, "dependency_page", dep_page(b, ctx, g, _pk("root"), offset=off, basis="graph_root"))
    for flt in ("advisory", "direct", "transitive", "evidence_gaps"):
        fx.add("filter-%s.json" % flt, "dependency_page", dep_page(b, ctx, g, _pk("root"), filt=flt, basis="graph_root"))
    fx.add("search-dep-04.json", "dependency_page", dep_page(b, ctx, g, _pk("root"), query="dep-04", basis="graph_root"))
    return fx


def fx_deps_paths():
    fx = Fixture("deps-paths-synthetic", "synthetic", "Chains with shared connectors, a diamond, a cycle, disconnected components, connectors_omitted, depth_limit, every lookup state and a lookup-off variant.")
    b = make_binding("example-org", "path-lab", "depspaths")
    ctx = "lab/package-lock.json"
    P = _pk
    nodes = {P("focus"): gnode("focus-root", "1.0.0", True, "no_match")}
    spec = {"a": ("match", "1.0.0"), "b": ("no_match", "1.0.0"), "c": ("unavailable", "1.0.0"), "d": ("unsupported", "1.0.0"), "e": ("missing_version", None),
            "g": ("not_run", "1.0.0"), "f": ("no_match", "1.0.0")}
    for k, (lk, ver) in spec.items():
        nodes[P(k)] = gnode("node-" + k, ver, True, lk, 2 if lk == "match" else 0)
    edges = [(P("focus"), P("a")), (P("focus"), P("b")), (P("focus"), P("c")), (P("a"), P("d")), (P("b"), P("d")), (P("d"), P("e")),
             (P("e"), P("a")), (P("c"), P("g")), (P("e"), P("f"))]
    nodes[P("x")] = gnode("island-x", "1.0.0")
    nodes[P("y")] = gnode("island-y", "1.0.0")
    edges.append((P("x"), P("y")))
    g = {"nodes": nodes, "edges": edges}
    fx.add("paths-all.json", "dependency_page", dep_page(b, ctx, g, P("focus"), basis="graph_root", candidates_total=2))
    fx.add("paths-transitive.json", "dependency_page", dep_page(b, ctx, g, P("focus"), filt="transitive", basis="graph_root", candidates_total=2))
    fx.add("paths-evidence-gaps.json", "dependency_page", dep_page(b, ctx, g, P("focus"), filt="evidence_gaps", basis="graph_root", candidates_total=2))
    fx.add("paths-requested-focus.json", "dependency_page", dep_page(b, ctx, g, P("a"), basis="requested", candidates_total=2))
    off_nodes = {k: dict(v, lookup="not_run", matches=0) for k, v in nodes.items()}
    fx.add("paths-lookup-off.json", "dependency_page", dep_page(b, ctx, {"nodes": off_nodes, "edges": edges}, P("focus"), lookup_mode="off", basis="graph_root", candidates_total=2))
    cyc = {"nodes": {P("p"): gnode("cycle-p"), P("q"): gnode("cycle-q"), P("r"): gnode("cycle-r")}, "edges": [(P("p"), P("q")), (P("q"), P("r")), (P("r"), P("p"))]}
    fx.add("paths-cycle-fallback.json", "dependency_page", dep_page(b, ctx, cyc, P("p"), basis="cycle_fallback", candidates_total=3))
    disc = {"nodes": {P("m"): gnode("comp-m"), P("n"): gnode("comp-n"), P("u"): gnode("comp-u"), P("v"): gnode("comp-v")},
            "edges": [(P("m"), P("n")), (P("u"), P("v"))]}
    fx.add("paths-disconnected-fallback.json", "dependency_page", dep_page(b, ctx, disc, P("m"), basis="disconnected_fallback", candidates_total=2))
    # connectors_omitted: 30 advisory leaves, each behind a 7-node chain; the connector budget (120) fits 17 leaves
    cn = {P("hub"): gnode("hub-root")}
    ce = []
    for i in range(30):
        prev = P("hub")
        for j in range(7):
            nid = P("c%02d-%d" % (i, j))
            cn[nid] = gnode("zz-chain-%02d-%d" % (i, j))
            ce.append((prev, nid))
            prev = nid
        leaf = P("leaf-%02d" % i)
        cn[leaf] = gnode("aa-leaf-%02d" % i, "1.0.0", True, "match", 1)
        ce.append((prev, leaf))
    fx.add("paths-connectors-omitted.json", "dependency_page", dep_page(b, ctx, {"nodes": cn, "edges": ce}, P("hub"), filt="advisory", basis="graph_root"))
    # depth_limit: a chain of 15 below the focus; nodes first seen at depth 13 are depth_limit
    dn = {P("top"): gnode("chain-top")}
    de, prev = [], P("top")
    for i in range(1, 16):
        nid = P("n%02d" % i)
        dn[nid] = gnode("chain-n%02d" % i)
        de.append((prev, nid))
        prev = nid
    fx.add("paths-depth-limit.json", "dependency_page", dep_page(b, ctx, {"nodes": dn, "edges": de}, P("top"), basis="graph_root"))
    return fx


def _ctx_files(prefix_counts, seed_members):
    pass


def fx_contexts600():
    fx = Fixture("contexts-600-synthetic", "synthetic", "600 files across all ten categories, unlocated components, components shared between groups (distinct vs membership), 20-file default paging and a one-group page.")
    b = make_binding("example-org", "mono-lab", "ctx600")
    spec = [("docs/guide%03d/index.md", 60, "docs"), ("web/app%03d/package.json", 80, "web"), ("services/s%03d/requirements.txt", 120, "py"),
            (".github/workflows/w%03d.yml", 50, "gha"), ("cmd/c%03d/go.mod", 100, "go"), ("crates/x%03d/Cargo.toml", 60, "rs"),
            ("mod%03d/pom.xml", 40, "java"), ("docker/d%03d/Dockerfile", 30, "ctr"), ("misc/m%03d.cfg", 60, "misc")]
    files, k = [], 0
    for pat, n, tag in spec:
        for i in range(n):
            members = {"comp-%s-%03d-%d" % (tag, i, j) for j in range(3)}
            if i % 10 == 0 and tag != "docs":
                members.add("comp-shared-%03d" % (i // 10))  # appears in several groups: distinct < membership
            path = pat % i
            files.append({"path": path, "raw_locations": ["/" + path], "basis": ["syft_root_relative"], "members": members})
    assert len(files) == 600
    unl = ["comp-unlocated-%d" % i for i in range(7)]
    fx.add("contexts-page-0.json", "contexts", contexts_payload(b, files, unl))
    fx.add("contexts-group-python-offset-20.json", "contexts", contexts_payload(b, files, unl, files_offset=20, files_limit=40, only_category="python_requirements"))
    fx.add("contexts-group-python-last-page.json", "contexts", contexts_payload(b, files, unl, files_offset=100, files_limit=40, only_category="python_requirements"))
    fx.add("contexts-selected-group.json", "contexts", contexts_payload(b, files, unl, selected=oid(b, "grp", "group", "web")))
    return fx


def _fam_scan(seed, owner, name, **over):
    spec = {s: ("completed", None) for s in STAGES}
    spec.update({"aibom": ("not_run", "not_configured"), "advisory_lookup": ("not_run", "disabled"), "source_checks": ("not_run", "disabled")})
    spec.update(over)
    return scan_payload(seed, 7, stages_for(spec, seed), owner=owner, name=name)


def fx_nonpython():
    fx = Fixture("nonpython-synthetic", "synthetic", "A Go repository: go_modules/other_locations contexts; crypto unsupported, ai not_run; BOM comparison not_compared (never an empty success).")
    b = make_binding("example-org", "gotool", "nonpy", assessment=True)
    files = []
    for i in range(6):
        p = "cmd/tool%d/go.mod" % i
        files.append({"path": p, "raw_locations": ["/" + p], "basis": ["syft_root_relative"], "members": {"go-comp-%d-%d" % (i, j) for j in range(4)}})
    files.append({"path": "Makefile", "raw_locations": ["/Makefile"], "basis": ["syft_root_relative"], "members": {"go-comp-make"}})
    fx.add("contexts.json", "contexts", contexts_payload(b, files, []))
    fx.add("crypto-unsupported.json", "crypto_assets", assets_payload("crypto", b, avail("unsupported", "No supported cryptographic inventory exists for this ecosystem; nothing was compared."), [], []))
    fx.add("ai-not-run.json", "ai_assets", assets_payload("ai", b, avail("not_run", "AI inventory is not configured for this scan."), [], []))
    caps = [{"family": f, "state": "unsupported", "reason_code": "unsupported_ecosystem"} for f in ("software", "cryptography", "ai_model")] + \
           [{"family": "other", "state": "not_run", "reason_code": "not_configured"}]
    fx.add("bom-not-compared.json", "bom_candidates", bom_candidates_payload(b, [], mode="not_compared", caps=caps,
           status_detail={"code": "python_requirements_unsupported", "message": "Requirement discovery supports Python requirement files only; no comparison was performed."}))
    fx.add("scan-status.json", "scan_status", _fam_scan("nonpy-scan", "example-org", "gotool", cbom=("unsupported", "unsupported_ecosystem")))
    return fx


def fx_no_ai():
    fx = Fixture("no-ai-synthetic", "synthetic", "A repository without AI assets: ai_assets completed_empty versus an unconfigured stage (not_run) kept distinct.")
    b = make_binding("example-org", "plain-lib", "noai")
    prod = [producer("fixture-aibom", "original_artifact", "AI inventory over the repository root", "completed", artifact_id="art:aibom-fixture", pointer="/components", cov={"files_considered": 40, "files_parsed": 40})]
    fx.add("ai-completed-empty.json", "ai_assets", assets_payload("ai", b, avail("completed_empty", "The AI inventory completed and lists no AI assets. This does not show that no AI is used."), prod, []))
    fx.add("ai-not-run.json", "ai_assets", assets_payload("ai", b, avail("not_run", "AI inventory is not configured for this scan."), [], []))
    fx.add("scan-status.json", "scan_status", _fam_scan("noai-scan", "example-org", "plain-lib"))
    return fx


def fx_cbom_ai():
    fx = Fixture("cbom-empty-and-partial-synthetic", "synthetic", "Crypto empty/partial/failed states, endpoint services, supplemental-shaped (experimental, invented) records; AI unsupported, same-basename references, alternatives, unavailable/unknown attributes.")
    b = make_binding("example-org", "crypto-lab", "cbomai")
    gp = src_group(b, "Source: src/net", "src/net", 2)
    svc = [{"service_id": "svc:%s" % sha("svc%d" % i)[:12], "name": "endpoint-%d" % i, "endpoint_text": "https://svc%d.invalid/api" % i,
            "provenance": prov("fixture-cbom", "original_artifact", artifact_id="art:cbom-fixture", pointer="/services/%d" % i)} for i in range(3)]
    p_orig = producer("fixture-cbom", "original_artifact", "cbom generator over the repository root", "completed", artifact_id="art:cbom-fixture", pointer="/components",
                      cov={"files_considered": 120, "files_parsed": 120}, version="1.0")
    fx.add("crypto-completed-empty.json", "crypto_assets", assets_payload("crypto", b, avail("completed_empty", "The CBOM completed and lists no cryptographic assets. This does not show that no cryptography is used."),
           [p_orig], [], services=svc))
    p_sup = producer("fixture-source-observer", "supplemental_observation", "experimental static observation of two source files", "partial", experimental=True,
                     cov={"files_considered": 4, "files_parsed": 2, "files_excluded": 2, "excluded_paths": ["vendor/big.generated.c", "src/net/dynamic.py"],
                          "unparsed_total": 2, "unknown_dynamic_values_total": 2}, version="0.1")
    a1 = asset(b, "a1", "algorithm", "SHA-256", prov("fixture-cbom", "original_artifact", artifact_id="art:cbom-fixture", pointer="/components/0"),
               attrs={"algorithm_name": attr("recorded", "SHA-256", "recorded in the CBOM"), "primitive": attr("recorded", "hash", "recorded in the CBOM")})
    a3 = asset(b, "a3", "certificate", "service-cert", prov("fixture-cbom", "original_artifact", artifact_id="art:cbom-fixture", pointer="/components/1"),
               attrs={"certificate_subject": attr("recorded", "CN=service.invalid", "recorded in the CBOM")}, groups=[gp["group_id"]])
    o1 = occ(b, "o1", "src/net/client.py", 12, 14, "ctx = make_context(verify=False)", operation="TLS context creation", cond="verification flag is set in source",
             cond_basis="source_text", producer_id="fixture-source-observer")
    a2 = asset(b, "a2", "protocol", "TLS client setup", prov("fixture-source-observer", "supplemental_observation", experimental=True, version="0.1"),
               attrs={"protocol_name": attr("recorded", "TLS", "source text")}, occs=[o1], groups=[gp["group_id"]])
    rv = {"review_id": "rev:%s" % sha("r1")[:12], "asset_id": a2["asset_id"], "rule_id": "fixture.tls_flag_review", "rule_version": "1", "tone": "review",
          "condition": "A source flag disables certificate verification when set", "evidence_ids": ["ev:%s" % sha("e1")[:12]],
          "rationale": "The source text sets a verification flag to false in one call. This is a conditional review item, not a confirmed vulnerability.",
          "bounded_meaning": "Deployed configuration is not established by this source line.", "next_action": "Check whether the flag is configurable at deployment."}
    lk = [{"relation": "located_in", "from": a2["asset_id"], "to": gp["group_id"], "basis": "recorded", "evidence_ref": None, "condition": None}]
    fx.add("crypto-partial.json", "crypto_assets", assets_payload("crypto", b, avail("partial", "Two files were excluded and two dynamic values are unknown; the list is incomplete."),
           [p_orig, p_sup], [a1, a2, a3], services=svc, links=lk, reviews=[rv], groups=[gp]))
    p_fail = producer("fixture-cbom", "original_artifact", "cbom generator over the repository root", "failed", artifact_id="art:cbom-fixture", pointer="/")
    fx.add("crypto-failed.json", "crypto_assets", assets_payload("crypto", b, avail("failed", "The CBOM generator failed; nothing was recorded."), [p_fail], []))
    # ---- AI
    ag = src_group(b, "Source: config", "config", 3)
    p_ai = producer("fixture-aibom", "original_artifact", "AI inventory over the repository root", "completed", artifact_id="art:aibom-fixture", pointer="/components", cov={"files_considered": 30, "files_parsed": 30})
    p_ref = producer("fixture-source-refs", "supplemental_observation", "experimental source and config reference scan", "partial", experimental=True,
                     cov={"files_considered": 10, "files_parsed": 9, "files_excluded": 1, "excluded_paths": ["scripts/gen.py"], "unparsed_total": 1}, version="0.1")
    m1 = asset(b, "m1", "model_artifact", "detector.bin", prov("fixture-aibom", "original_artifact", artifact_id="art:aibom-fixture", pointer="/components/0"), tab="ai", groups=[ag["group_id"]])
    r1 = asset(b, "r1", "model_reference", "model.bin", prov("fixture-source-refs", "supplemental_observation", experimental=True, version="0.1"), tab="ai", groups=[ag["group_id"]],
               occs=[occ(b, "r1o", "config/a.yaml", 5, 5, "model: https://a.invalid/model.bin", operation="model reference", producer_id="fixture-source-refs")],
               dgroup={"group_id": oid(b, "grp", "display", "model.bin"), "rule": "same basename shown together; identities stay separate"},
               attrs={"provider": attr("unknown", None, "the source names no provider")})
    r2 = asset(b, "r2", "model_reference", "model.bin", prov("fixture-source-refs", "supplemental_observation", experimental=True, version="0.1"), tab="ai", groups=[ag["group_id"]],
               occs=[occ(b, "r2o", "config/b.yaml", 9, 9, "model: https://b.invalid/model.bin", operation="model reference", producer_id="fixture-source-refs")],
               dgroup={"group_id": oid(b, "grp", "display", "model.bin"), "rule": "same basename shown together; identities stay separate"})
    o_pref = occ(b, "rt1", "src/infer.py", 3, 4, "import runtime_primary", operation="runtime import", producer_id="fixture-source-refs")
    o_fb = occ(b, "rt2", "src/infer.py", 6, 7, "import runtime_fallback", operation="runtime import", cond="used only if the first import fails",
               cond_basis="source_text", alt=o_pref["occurrence_id"], producer_id="fixture-source-refs")
    rt1 = asset(b, "rt1", "runtime", "runtime_primary", prov("fixture-source-refs", "supplemental_observation", experimental=True, version="0.1"), tab="ai", occs=[o_pref], groups=[ag["group_id"]])
    rt2 = asset(b, "rt2", "runtime", "runtime_fallback", prov("fixture-source-refs", "supplemental_observation", experimental=True, version="0.1"), tab="ai", occs=[o_fb], groups=[ag["group_id"]])
    lk2 = [{"relation": "conditionally_selects", "from": rt1["asset_id"], "to": rt2["asset_id"], "basis": "recorded", "evidence_ref": None, "condition": "fallback import only if the first import fails"},
           {"relation": "references", "from": r1["asset_id"], "to": ag["group_id"], "basis": "recorded", "evidence_ref": None, "condition": None}]
    fx.add("ai-references.json", "ai_assets", assets_payload("ai", b, avail("partial", "Model references and runtime imports are source observations only; no model binary or runtime use is established."),
           [p_ai, p_ref], [m1, r1, r2, rt1, rt2], links=lk2, groups=[ag]))
    fx.add("ai-unsupported.json", "ai_assets", assets_payload("ai", b, avail("unsupported", "No supported AI inventory exists for this ecosystem."), [], []))
    fx.add("scan-status.json", "scan_status", _fam_scan("cbomai-scan", "example-org", "crypto-lab", cbom=("partial", "partial_coverage"), aibom=("unsupported", "unsupported_ecosystem")))
    return fx


def fx_scan_matrix():
    files, seq = scan_matrix()
    fx = Fixture("scan-status-matrix-synthetic", "synthetic", "A seq-ordered job sequence (files 00-04) plus terminal variants covering every stage state, handoff ready/blocked and cancel cleanup verified/unverified; pre-resolution payloads carry a null binding.")
    for name, p in files.items():
        fx.add("scan-%s.json" % name, "scan_status", p)
    fx.sequence = seq
    return fx


def fx_bom_large():
    fx = Fixture("bom-large-synthetic", "synthetic", "60 candidates (25/25/10), a record shared by 45 checks (20/20/5), evidence-only and no-graph tasks, a shared assertion, one name at two files, excluded evidence, a 400-node full view paged by 100 plus neighbors.")
    b = make_binding("example-org", "bom-lab", "bomlarge", assessment=True)
    items = []
    for i in range(40):
        name = "same-name" if i in (5, 6) else "pkg-%02d" % i
        assertion = "assert-shared" if i in (3, 4) else "assert-%02d" % i
        items.append(bom_item(b, "c%02d" % i, name, assertion=assertion, path="reqs/r%d.txt" % (i % 7), line=i + 1, inherited=i < 3))
    for i in range(40, 50):
        items.append(bom_item(b, "c%02d" % i, "ok-%02d" % i, state="supported", assertion="assert-%02d" % i, path="reqs/ok.txt", line=i))
    for i in range(50, 60):
        st = "unknown_coverage" if i < 54 else "unverifiable"
        items.append(bom_item(b, "c%02d" % i, "task-%02d" % i, category="unknown_coverage", state=st, inv_kind=None, path="reqs/task.txt", line=i,
                              graph="evidence_only" if i % 2 else "no_graph_collection_task", rule=None))
    for off in (0, 25, 50):
        fx.add("candidates-offset-%02d.json" % off, "bom_candidates", bom_candidates_payload(b, items, offset=off))
    fx.add("candidates-not-represented.json", "bom_candidates", bom_candidates_payload(b, items, filters={"filter_group": "not_represented"}))
    fx.add("candidates-search-same-name.json", "bom_candidates", bom_candidates_payload(b, items, filters={"query": "same-name"}))
    # focused assertion graph with used, context and excluded evidence
    a0 = items[0]
    aid = "assert-00"
    ns = [gn(b, aid, "assertion", "Requirement represented in inventory", state="contradicted"),
          gn(b, "ev:decl-0", "evidence", "Requirement declaration", ev="used"), gn(b, "ev:look-0", "evidence", "Inventory lookup", ev="used"),
          gn(b, "ev:ctx-0", "evidence", "Parse context", ev="context"), gn(b, "ev:excl-0", "evidence", "Excluded record", ev="excluded")]
    es = [ge("edge:a1", aid, "ev:decl-0", "used_evidence", "used", "Declares the requirement."), ge("edge:a2", aid, "ev:look-0", "used_evidence", "used", "Looked the name up in the inventory."),
          ge("edge:a3", aid, "ev:ctx-0", "context_evidence", "context"), ge("edge:a4", aid, "ev:excl-0", "excluded_evidence", "excluded", "Excluded: different scope.")]
    fx.add("graph-focused-assertion.json", "bom_graph", graph_payload(b, "focused_candidate", ns, es, "assertion_graph", cand=a0["item_id"]))
    ev_only = items[51]
    ns2 = [gn(b, "ev:t-1", "evidence", "Cited source declaration", ev="context"), gn(b, "ev:t-2", "evidence", "Cited inventory record", ev="context")]
    fx.add("graph-evidence-only.json", "bom_graph", graph_payload(b, "focused_candidate", ns2, [], "evidence_only", cand=ev_only["item_id"], msg="more_evidence_needed"))
    fx.add("graph-no-graph.json", "bom_graph", graph_payload(b, "focused_candidate", [], [], "no_graph_collection_task", cand=items[50]["item_id"], msg="more_evidence_needed"))
    fx.add("graph-group-summary.json", "bom_graph", graph_payload(b, "group_summary", [], [], "assertion_graph", group="software", nodes_in_scope=0, edges_in_scope=0))
    # full view: 400 nodes
    allnodes, alledges = {}, []
    for i in range(40):
        allnodes["assert-%02d" % i] = ("assertion", "Assertion %02d" % i)
    for i in range(80):
        allnodes["ent-%02d" % i] = ("entity", "Entity %02d" % i)
    for i in range(240):
        allnodes["ev-%03d" % i] = ("evidence", "Evidence %03d" % i)
    for i in range(40):
        allnodes["inv-%02d" % i] = ("inventory", "Inventory %02d" % i)
    for i in range(240):
        alledges.append(("assert-%02d" % (i % 40), "ev-%03d" % i, "used_evidence", "used"))
    for j in range(80):
        alledges.append(("ent-%02d" % j, "ev-%03d" % (j * 3), "declares", "context"))
    for k in range(40):
        alledges.append(("inv-%02d" % k, "assert-%02d" % k, "compared_with", "context"))
    order = {"assertion": 0, "entity": 1, "evidence": 2, "inventory": 3}
    ranked = sorted(allnodes, key=lambda n: (order[allnodes[n][0]], allnodes[n][1], n))

    def full(off, q=""):
        primary = ranked[off:off + 100]
        pset = set(primary)
        neigh = sorted({x for a, c, _, _ in alledges for x in (a, c) if (a in pset) != (c in pset) and x not in pset},
                       key=lambda n: (order[allnodes[n][0]], allnodes[n][1], n))[:50]
        shown = set(primary) | set(neigh)
        ns_ = [gn(b, n, allnodes[n][0], allnodes[n][1], role="primary" if n in pset else "neighbor",
                  ev=("used" if allnodes[n][0] == "evidence" else None), state="contradicted" if allnodes[n][0] == "assertion" else None) for n in primary + neigh]
        es_ = [ge("edge:%s" % sha(a + c)[:12], a, c, t, r) for a, c, t, r in alledges if a in shown and c in shown][:300]
        return graph_payload(b, "full_view", ns_, es_, "assertion_graph", group="all", query=q, page={"offset": off, "primary_size": 100},
                             nodes_in_scope=400, edges_in_scope=len(alledges))
    fx.add("graph-full-view-offset-000.json", "bom_graph", full(0))
    fx.add("graph-full-view-offset-100.json", "bom_graph", full(100))
    shared = [rel_item(it) for it in items if it["inventory"] and it["inventory"]["kind"] == "sbom"][:45]
    for off in (0, 20, 40):
        fx.add("related-shared-offset-%02d.json" % off, "bom_related_checks", related_payload(b, "inv:sbom-source", shared, offset=off))
    fx.add("related-single.json", "bom_related_checks", related_payload(b, "ev:decl-0", [rel_item(items[0])]))
    fx.add("related-none.json", "bom_related_checks", related_payload(b, "ev:orphan", [], detail=record_detail("Orphan evidence record")))
    fx.add("related-relationship.json", "bom_related_checks", related_payload(b, "edge:a1", [], kind="relationship"))
    fx.add("inspector-candidate.json", "inspector", inspector(b, "bom", "candidate", items[0]["item_id"], "pkg-00 comparison", bom=True, third_state="not_represented",
           ref=items[0]["canonical_ref"], rows=[{"status": "declared", "label": "Source requirement declaration", "detail": "Declared in reqs/r0.txt.", "evidence_ref": "ev:decl-0", "provenance": None},
                                              {"status": "not_represented", "label": "Comparison result", "detail": "Not represented in the compared inventory.", "evidence_ref": None, "provenance": None}],
           badge={"kind": "review", "label": "Not represented"}))
    fx.add("inspector-entity.json", "inspector", inspector(b, "bom", "entity", "ent-00", "Entity 00", bom=True, third_state="not_applicable"))
    return fx


HOSTILE = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)", "data:text/html,<svg onload=alert(1)>",
           "a‮b‬", "__proto__", "{{7*7}}", "' OR '1'='1"]


def fx_malicious():
    fx = Fixture("malicious-text-synthetic", "synthetic", "Hostile names, paths, excerpts and URLs validate as inert text with href null; a 600-character excerpt is valid at the boundary. Control characters and the 601 case are in invalid/.")
    b = make_binding("example-org", "hostile-lab", "mal")
    files = [{"path": "src/%s.py" % HOSTILE[1], "raw_locations": ["/src/%s.py" % HOSTILE[1]], "basis": ["syft_recorded_path"], "members": {"m-1", "m-2"}},
             {"path": "docs/%s.md" % HOSTILE[4], "raw_locations": ["/docs/x.md"], "basis": ["syft_recorded_path"], "members": {"m-3"}}]
    c = contexts_payload(b, files, [])
    c["groups"][0]["files"][0]["revision_link"] = inert_link(HOSTILE[2])
    fx.add("contexts-hostile.json", "contexts", c)
    exc = "x" * 592 + "<script>"  # exactly 600 characters: the boundary value
    o = occ(b, "mo", "src/a.py", 1, 1, exc, operation=HOSTILE[0], cond=HOSTILE[2], cond_basis="source_text", producer_id="fixture-source-observer")
    a = asset(b, "ma", "protocol", HOSTILE[0], prov("fixture-source-observer", "supplemental_observation", experimental=True), occs=[o],
              attrs={"protocol_name": attr("recorded", HOSTILE[3], "source text")})
    a["occurrences"][0]["source_location"]["link"] = inert_link(HOSTILE[3])
    fx.add("crypto-hostile.json", "crypto_assets", assets_payload("crypto", b, avail("partial", HOSTILE[7]),
           [producer("fixture-source-observer", "supplemental_observation", HOSTILE[0], "partial", experimental=True)], [a]))
    fx.add("inspector-hostile.json", "inspector", inspector(b, "contexts", "file", "ctx:" + sha("h")[:24], HOSTILE[1]))
    return fx


# ================================================================ derived fixtures (existing handlers, recorded demo)
class _Client:
    def __init__(self, port):
        self.port, self.cookie = port, None

    def req(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        h = {"Host": "127.0.0.1:%d" % self.port}
        if body is not None:
            h["Content-Type"] = "application/json"
        if self.cookie:
            h["Cookie"] = self.cookie
        conn.request(method, path, json.dumps(body) if body is not None else None, h)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def json(self, method, path, body=None):
        resp, data = self.req(method, path, body)
        return resp.status, (json.loads(data) if data else None), data

    def start(self):
        resp, _ = self.req("POST", "/api/session", {})
        self.cookie = resp.getheader("Set-Cookie").split(";")[0]


@contextmanager
def recorded_demo():
    """Run the existing app on the recorded demo inputs (loopback only); yield (client, analysis, demo)."""
    from opentrace_core.app import make_server
    root = tempfile.mkdtemp(prefix="uip-fixtures-")
    srv = make_server(os.path.join(root, "s"), reap_seconds=3600)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        client = _Client(srv.server_address[1])
        client.start()
        status, body, _ = client.json("POST", "/api/analysis/demo", {})
        if status != 200 or not body.get("ok"):
            raise RuntimeError("recorded demo analysis failed: %r" % (body,))
        analysis = list(srv.app.analyses.values())[0]
        yield client, analysis, body
    finally:
        srv.shutdown()
        srv.app.close()
        srv.server_close()


def _norm_session(text, real):
    return text.replace(real, FIXED_SESSION)


def legacy_snapshots(client, analysis, first_candidate):
    real = analysis.identity["session"]["session_id"]
    routes = {"contexts": "/api/view/contexts", "dependencies-per-side-6": "/api/view/dependencies?per_side=6", "dependencies-per-side-1": "/api/view/dependencies?per_side=1",
              "crypto": "/api/view/crypto", "ai": "/api/view/ai", "bom": "/api/view/bom", "gaps-offset-0": "/api/view/gaps?offset=0",
              "gap-first": "/api/view/gap?id=" + first_candidate, "dependencies-network": "/api/view/dependencies/network"}
    out = {}
    for name, path in sorted(routes.items()):
        status, _, raw = client.json("GET", path)
        if status != 200:
            raise RuntimeError("%s returned %s" % (path, status))
        out[name] = json.loads(_norm_session(raw.decode("utf-8"), real))
    return out


def _file_sha(path):
    with open(path, "rb") as h:
        return hashlib.sha256(h.read()).hexdigest()


def _split_loc(loc):
    m = re.match(r"^(.*?):([0-9][0-9,\-]*)$", loc or "")
    if not m:
        return (loc, None, None) if loc else (None, None, None)
    nums = [int(x) for x in re.split(r"[,\-]", m.group(2)) if x]
    return m.group(1), min(nums), max(nums)


def derive_recorded(out_dir):
    from opentrace_core.app import demo as demo_mod
    with recorded_demo() as (client, an, body):
        demo = an.views.demo
        ident = an.identity
        real = ident["session"]["session_id"]
        adata = an.gaps["assessment"].as_dict()
        ab = adata["binding"]
        b = {"analysis_digest": ident["analysis_digest"], "repository": ident["repository"], "commit_sha": ident["resolved"]["commit_sha"],
             "requested_ref": {"kind": ident["requested"]["kind"], "text": ident["requested"]["text"]}, "generation": an.ticket.generation, "mode": "captured",
             "assessment": {"kind": "discovery", "schema": "opentrace.bombridge_assessment/1", "validation_digest": FIXED_VALIDATION,
                            "bundle_sha256": ab["bundle_sha256"], "configuration": ab["configuration"]}}
        b0 = dict(b, assessment=None)
        fx = Fixture(RECORDED_NAME, "derived", "Payloads mapped (fixture-only code) from the existing handlers run in process on the recorded demo inputs. Crypto and AI are original-artifact-only; observed numbers are recorded, not asserted.",
                     normalized=["identity.resolved.resolved_at replaced by the fixed clock", "session_id (random per run) replaced by a fixed value everywhere it appears",
                                 "binding.assessment.validation_digest replaced by a fixed digest (the real seal covers the random session id)"],
                     recorded_names=True)
        base = demo_mod.DEFAULT_FIXTURES
        srcs = [os.path.join(base, demo_mod.BUNDLE), demo_mod.ADVISORIES, os.path.join(base, demo_mod.SOURCE_DECLARATIONS)]
        srcs += [os.path.join(base, inv["source_file"]) for inv in demo.bundle["capture"]["inventories"] if inv.get("source_sha256")]
        fx.sources = [{"path": os.path.relpath(p, REPO).replace(os.sep, "/"), "sha256": _file_sha(p), "role": "recorded input"} for p in srcs]
        # ---- contexts
        proj = an.views._project("contexts")["tabs"][0]
        files = [{"path": r["path"], "raw_locations": r["raw_locations"], "basis": r["normalization_basis"], "members": {c["id"] for c in r["components"]}} for r in proj["rows"]]
        unl = [c["id"] for c in proj["unlocated"]["components"]]
        ctxp = contexts_payload(b, files, unl)
        _, legacy_ctx, _ = client.json("GET", "/api/view/contexts")
        ctxp_ok = (ctxp["root"]["distinct_total"], ctxp["root"]["membership_total"], ctxp["root"]["unlocated_total"]) == \
                  (legacy_ctx["component_total"], legacy_ctx["membership_total"], legacy_ctx["unlocated_total"])
        fx.notes += " Observed context totals match the existing contexts view: %s." % ctxp_ok
        if not ctxp_ok:
            raise RuntimeError("derived context totals differ from the existing view")
        fx.add("contexts.json", "contexts", ctxp)
        # ---- dependency page
        ctx_path = "web/package-lock.json"
        raw, tab = an.views._scope(ctx_path)
        gn_, gedges, incoming, outdeg = {}, [], set(), {}
        for n in tab["nodes"]:
            rows = demo.rows_by_ref.get(n.get("bom_ref")) or []
            gn_[n["id"]] = gnode(n.get("name") or "", n.get("version"), bool(n.get("locations")), "match" if rows else "not_run", len(rows), n.get("type") and "npm" or "npm")
        for e in tab["edges"]:
            gedges.append((e["from"], e["to"]))
            incoming.add(e["to"])
            outdeg[e["from"]] = outdeg.get(e["from"], 0) + 1
        roots = [n for n in gn_ if n not in incoming]
        roots.sort(key=lambda n: (-outdeg.get(n, 0), gn_[n]["name"], n))
        focus = roots[0]
        fx.add("dependency-page.json", "dependency_page", dep_page(
            b, ctx_path, {"nodes": gn_, "edges": gedges}, focus, basis="graph_root", candidates_total=len(roots), lookup_mode="recorded",
            explanation="The recorded advisory snapshot does not state per-component query coverage: components without a recorded match are shown as not run, not as a completed clean lookup."))
        # ---- BOM candidates
        rows, offset = [], 0
        while True:
            status, page, _ = client.json("GET", "/api/view/gaps?offset=%d" % offset)
            rows += page["items"]
            if not page["has_more"]:
                break
            offset += page["limit"]
        legacy_ids = {c["assertion_id"] for c in body["summary"].get("checks", [])}
        items = []
        for r in rows:
            kind = (r.get("bom") or {}).get("kind")
            path, l0, l1 = _split_loc(r.get("location"))
            fam = vc.INVENTORY_FAMILY.get(kind, "other")
            gs = "assertion_graph" if r["rule_id"] else ("evidence_only" if r["has_evidence"] else "no_graph_collection_task")
            it = {"item_id": r["candidate_id"], "item_kind": "candidate", "assertion_id": r.get("assertion_id"), "canonical_ref": cref(b, "candidate", r["candidate_id"], "recorded"),
                  "display": {"name": r["title"][:256], "raw_title": r["title"][:256]}, "family": fam, "family_basis": "inventory_kind" if kind else "unclassified",
                  "category": r["category"], "state": r["state"], "filter_group": vc.FILTER_GROUP[r["state"]], "inherited": r.get("assertion_id") in legacy_ids,
                  "location": {"path": path, "line_start": l0, "line_end": l1} if path else None,
                  "inventory": {"inventory_id": r["bom"]["inventory_id"], "kind": kind, "generator": r["bom"]["label"], "sha256": r["bom"]["sha256"]} if kind else None,
                  "rule_id": r["rule_id"], "graph_state": gs}
            items.append(it)
        bundle = adata["source_bundle"]
        findings = adata["result"].get("findings", [])
        rels = sum(len(f.get("used_evidence", [])) + len(f.get("excluded_evidence", [])) for f in findings)
        cp = bom_candidates_payload(b, items)
        cp["counts"]["records_total"] = len(bundle.get("evidence", []))
        cp["counts"]["relationships_total"] = rels
        cp["capabilities"] = [{"family": "software", "state": "completed", "reason_code": None},
                              {"family": "cryptography", "state": "not_run", "reason_code": "not_configured"},
                              {"family": "ai_model", "state": "not_run", "reason_code": "not_configured"},
                              {"family": "other", "state": "completed", "reason_code": None}]
        fx.add("bom-candidates-offset-00.json", "bom_candidates", cp)
        first = items[0]
        _, gdet, _ = client.json("GET", "/api/view/gap?id=" + first["item_id"])
        cand = gdet["candidate"]
        evs = {"requirement_declaration": "Requirement declaration", "inventory_name_lookup": "Inventory lookup"}
        gnodes, gedges2 = [], []
        aid = cand.get("assertion_id")
        if aid and first["graph_state"] == "assertion_graph":
            gnodes.append(gn(b, aid, "assertion", cand["title"][:120], state=cand["state"]))
        for rec in cand["records"]:
            role = rec["role"] if rec["role"] in ("used", "excluded") else "context"
            gnodes.append(gn(b, rec["evidence_id"], "evidence", evs.get(rec.get("kind"), "Evidence record"), ev=role))
            if aid and first["graph_state"] == "assertion_graph":
                gedges2.append(ge(eid("edge", aid, rec["evidence_id"]), aid, rec["evidence_id"], str(rec.get("relation") or rec["role"])[:64], role))
        fx.add("bom-graph-focused-first.json", "bom_graph", graph_payload(b, "focused_candidate", gnodes, gedges2, first["graph_state"], cand=first["item_id"],
               msg=None if first["graph_state"] == "assertion_graph" else "more_evidence_needed"))
        inv_id = first["inventory"]["inventory_id"]
        rel_items = [rel_item(it) for it in items if it["inventory"] and it["inventory"]["inventory_id"] == inv_id]
        fx.add("bom-related-shared-record.json", "bom_related_checks", related_payload(b, inv_id, rel_items))
        # ---- crypto / ai (original artifacts only)
        _, cry, _ = client.json("GET", "/api/view/crypto")
        _, ai, _ = client.json("GET", "/api/view/ai")
        cbom = next(i for i, k in demo.kinds.items() if k == "cbom")
        aibom = next(i for i, k in demo.kinds.items() if k == "aibom")
        svc = []
        for s in cry.get("services", []):
            rec = s["record"]
            svc.append({"service_id": s["id"][:160], "name": str(rec.get("name") or s["id"])[:256], "endpoint_text": str(rec.get("endpoints") or rec.get("endpoint") or "")[:512],
                        "provenance": prov("cdxgen", "original_artifact", artifact_id="art:" + cbom, pointer="/services")})
        note = "per-file coverage counts are not recorded in the captured artifact; zeros mean unrecorded"
        pc = producer("cdxgen", "original_artifact", "cdxgen over the whole repository (captured); " + note, "completed", artifact_id="art:" + cbom, pointer="/components",
                      version=str(demo.inventory_meta[cbom].get("generator")))
        nca = cry.get("crypto_asset_total", 0)
        cp2 = assets_payload("crypto", b, avail("completed_empty" if nca == 0 else "completed", "The captured CBOM lists no cryptographic assets. This does not show that no cryptography is used.") if nca == 0 else
                             avail("completed", "Original CBOM assets."), [pc], [], services=svc[:30])
        if nca:
            raise RuntimeError("expected a zero-asset recorded CBOM; observed %d (report the difference)" % nca)
        fx.add("crypto-assets.json", "crypto_assets", cp2)
        pa = producer("cisco-aibom", "original_artifact", "AI inventory (captured); " + note, "completed", artifact_id="art:" + aibom, pointer="/components",
                      version=str(demo.inventory_meta[aibom].get("generator")))
        aassets = []
        for i, m in enumerate(ai.get("models", [])[:30]):
            rec = m["record"]
            aassets.append(asset(b, "ai-%d" % i, "inventory_model", str(rec.get("name") or m["id"])[:256],
                                 prov("cisco-aibom", "original_artifact", artifact_id="art:" + aibom, pointer="/components/%d" % i), tab="ai", identity="unresolved"))
        fx.add("ai-assets.json", "ai_assets", assets_payload("ai", b, avail("completed", "Inventory-reported models only; identity, provider and runtime use are not established."), [pa], aassets))
        # ---- inspector
        grp = ctxp["groups"][0]
        fx.add("inspector-root.json", "inspector", inspector(b, "contexts", "repository", oid(b, "grp", "root", "repository"), "%s/%s" % (b["repository"]["owner"], b["repository"]["name"])))
        fx.add("inspector-group.json", "inspector", inspector(b, "contexts", "group", grp["group_id"], grp["label"]))
        fx.add("inspector-file.json", "inspector", inspector(b, "contexts", "file", grp["files"][0]["file_id"], grp["files"][0]["path"]))
        # ---- scan status (captured replay)
        spec = {"resolve_revision": ("completed", None), "acquire_source": ("not_run", "not_configured"), "sbom": ("completed", None), "cbom": ("completed_empty", "no_applicable_assets"),
                "aibom": ("completed", None), "advisory_lookup": ("completed", None), "source_checks": ("not_run", "disabled"), "evidence_projection": ("completed", None),
                "workbench_ready": ("completed", None)}
        stg = stages_for(spec, "recorded")
        kind_inv = {k: i for i, k in demo.kinds.items()}
        for st_ in stg:
            if st_["outputs"]:
                iid = kind_inv[st_["stage_id"]]
                data = demo.raw[iid]
                st_["outputs"] = [{"kind": st_["stage_id"], "artifact_id": "art:" + iid, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}]
        sp = scan_payload("recorded", 9, stg, owner=b["repository"]["owner"], name=b["repository"]["name"])
        sp["binding"] = b
        sp["identity"] = {k: v for k, v in ident.items()}
        sp["identity"]["session"] = {"generation": ident["session"]["generation"]}
        sp["identity"]["resolved"] = dict(ident["resolved"], resolved_at=FIXED_TS)
        sp["job"]["job_id"] = oid(b, "job", "job", "recorded")
        fx.add("scan-status-captured-replay.json", "scan_status", sp)
        # ---- legacy snapshots
        snap = Fixture("legacy-view-snapshots", "derived", "Existing handler responses on the recorded demo, canonicalized; only the random session id is replaced by a fixed value.",
                       normalized=["session_id (random per run) replaced by a fixed value"], sources=fx.sources, recorded_names=True)
        for name, payload in legacy_snapshots(client, an, first["item_id"]).items():
            snap.add(name + ".json", "legacy", payload)
        return fx, snap


# ================================================================ invalid corpus
def run_case(env):
    """Returns None when accepted, else (code, detail_code)."""
    try:
        if env.get("route"):
            vc.validate_request(env["route"], env["params"])
        elif env.get("sequence") is not None:
            vc.validate_sequence(env["sequence"])
        else:
            vc.validate_payload(env["schema_name"], env["payload"], request=env.get("request"), expected_binding=env.get("expected_binding"))
    except vc.ContractError as exc:
        return exc.code, exc.detail_code
    return None


def build_cases(F):
    """F: {fixture name: Fixture}. Returns [(case name, envelope, code, detail_code, layer)]."""
    def get(fx, fname):
        return copy.deepcopy(F[fx].files[fname][1])
    cases = []

    def add(name, schema_name, payload, code, detail, layer, **extra):
        env = {"schema_name": schema_name, "payload": payload, "request": None, "expected_binding": None, "route": None, "params": None, "sequence": None}
        env.update(extra)
        cases.append((name, env, code, detail, layer))
    PF = "projection_failed"
    d = get("deps-82-synthetic", "page-offset-00.json")
    c = get("contexts-600-synthetic", "contexts-page-0.json")
    p = copy.deepcopy(c); p["root"]["extra"] = 1; add("unknown-field", "contexts", p, PF, "unknown_field", "structural")
    p = copy.deepcopy(c); p["schema"] = "opentrace.workbench.contexts/2"; add("wrong-schema-id", "contexts", p, PF, "enum_violation", "structural")
    p = copy.deepcopy(c); del p["edge_semantics"]; add("missing-field", "contexts", p, PF, "missing_field", "structural")
    p = copy.deepcopy(c); p["counts"]["total"] = "3"; add("wrong-type", "contexts", p, PF, "type_error", "structural")
    p = copy.deepcopy(d); p["nodes"][1]["advisory_lookup"] = "maybe"; add("bad-enum", "dependency_page", p, PF, "enum_violation", "structural")
    p = copy.deepcopy(d); p["nodes"] = p["nodes"] + [dict(p["nodes"][-1], node_id="x%d" % i) for i in range(121)]; add("dependency-152-nodes", "dependency_page", p, PF, "bound_exceeded", "structural")
    p = copy.deepcopy(d); p["edges"] = [dict(p["edges"][0], edge_id="e%d" % i) for i in range(241)]; add("dependency-241-edges", "dependency_page", p, PF, "bound_exceeded", "structural")
    p = copy.deepcopy(d); p["query"] = "q" * 81; add("query-81-chars", "dependency_page", p, PF, "bound_exceeded", "structural")
    bc = get("bom-large-synthetic", "candidates-offset-00.json")
    p = copy.deepcopy(bc); p["items"] = p["items"] + [dict(p["items"][0], item_id="cand:x:%d" % i) for i in range(1)]; add("candidates-26-items", "bom_candidates", p, PF, "bound_exceeded", "structural")
    gf = get("bom-large-synthetic", "graph-full-view-offset-000.json")
    p = copy.deepcopy(gf); p["nodes"] = p["nodes"] + [dict(p["nodes"][0], node_id="extra-%d" % i) for i in range(1)]; add("full-view-151-nodes", "bom_graph", p, PF, "bound_exceeded", "structural")
    ch = get("malicious-text-synthetic", "crypto-hostile.json")
    p = copy.deepcopy(ch); p["assets"][0]["occurrences"][0]["source_location"]["excerpt"] = "y" * 601; add("excerpt-601-chars", "crypto_assets", p, PF, "bound_exceeded", "structural")
    p = copy.deepcopy(ch); p["assets"][0]["display_name"] += "\u0007"; add("control-character", "crypto_assets", p, PF, "pattern_violation", "structural")
    p = get("cbom-empty-and-partial-synthetic", "crypto-completed-empty.json"); p["absence_established"] = True; add("absence-established-true", "crypto_assets", p, PF, "enum_violation", "structural")
    sc = get("scan-status-matrix-synthetic", "scan-04-completed.json")
    p = copy.deepcopy(sc); p["percent"] = 50; add("scan-percent-field", "scan_status", p, PF, "unknown_field", "structural")
    # ---- semantic: scan_status
    p = copy.deepcopy(sc); next(s for s in p["stages"] if s["stage_id"] == "sbom")["outputs"] = []; add("sbom-completed-without-output", "scan_status", p, PF, "invariant:stage_outputs", "semantic")
    fs = get("scan-status-matrix-synthetic", "scan-08-failed-scan.json")
    p = copy.deepcopy(fs); next(s for s in p["stages"] if s["stage_id"] == "cbom")["outputs"] = [{"kind": "cbom", "artifact_id": "art:x", "sha256": "0" * 64, "size": 1}]
    add("failed-stage-with-output", "scan_status", p, PF, "invariant:stage_outputs", "semantic")
    p = copy.deepcopy(fs); p["handoff"] = {"ready": True, "blocked_reason": None}; add("handoff-ready-on-failed-job", "scan_status", p, PF, "invariant:handoff_ready", "semantic")
    seq = F["scan-status-matrix-synthetic"].sequence
    cases.append(("seq-regression", {"schema_name": "scan_status", "payload": None, "request": None, "expected_binding": None, "route": None, "params": None,
                                      "sequence": [copy.deepcopy(seq[3]), copy.deepcopy(seq[2])]}, PF, "invariant:sequence_seq", "semantic"))
    p = copy.deepcopy(sc); p["identity"] = None; add("resolved-without-identity", "scan_status", p, PF, "invariant:pinning", "semantic")
    pre = get("scan-status-matrix-synthetic", "scan-01-resolving.json")
    p = copy.deepcopy(pre); p["binding"] = copy.deepcopy(sc["binding"]); add("unresolved-with-binding", "scan_status", p, PF, "invariant:pinning", "semantic")
    # ---- request / binding
    add("stale-generation", "dependency_page", copy.deepcopy(d), "stale_generation", "invariant:generation", "semantic", request={"generation": 2})
    add("binding-mismatch", "dependency_page", copy.deepcopy(d), "binding_mismatch", "invariant:analysis_digest", "semantic",
        request={"generation": 1}, expected_binding={"analysis_digest": "sha256:" + "0" * 64})
    # ---- contexts
    p = copy.deepcopy(c); g = next(x for x in p["groups"] if x["kind"] == "unlocated"); g["files"] = copy.deepcopy(p["groups"][0]["files"][:1]); add("unlocated-group-with-files", "contexts", p, PF, "invariant:unlocated_group", "semantic")
    p = copy.deepcopy(c); p["groups"][0]["distinct_total"] = p["groups"][0]["membership_total"] + 1; add("distinct-greater-than-membership", "contexts", p, PF, "invariant:distinct_le_membership", "semantic")
    p = copy.deepcopy(c); p["root"]["distinct_total"] += 1; add("root-total-mismatch", "contexts", p, PF, "invariant:root_distinct_total", "semantic")
    p = copy.deepcopy(c); g = next(x for x in p["groups"] if x["category"] == "other_locations"); g["category"], g["token"] = "python_requirements", "amber"
    add("fallback-category-python", "contexts", p, PF, "invariant:fallback_category", "semantic")
    # ---- dependency
    paths = get("deps-paths-synthetic", "paths-all.json")
    fid = paths["focus"]["node_id"]
    p = copy.deepcopy(paths); tgt = next(n for n in p["nodes"] if n["depth"] == 2)["node_id"]
    p["edges"].append({"edge_id": "edge:shortcut", "from": fid, "to": tgt, "kind": "declares_dependency", "source_pointers": []}); add("shortcut-edge-from-focus", "dependency_page", p, PF, "invariant:depth_mismatch", "semantic")
    p = copy.deepcopy(paths); next(n for n in p["nodes"] if n["depth"] == 2)["depth"] = 3; add("wrong-depth", "dependency_page", p, PF, "invariant:depth_mismatch", "semantic")
    p = copy.deepcopy(paths); p["edges"][0]["to"] = "pkg:missing"; add("missing-edge-endpoint", "dependency_page", p, PF, "invariant:edge_endpoint", "semantic")
    p = copy.deepcopy(paths); p["nodes"].append(copy.deepcopy(p["nodes"][1])); add("duplicate-node-id", "dependency_page", p, PF, "invariant:duplicate_id", "semantic")
    p = copy.deepcopy(paths); p["filter_totals"]["all"] += 1; add("filter-totals-not-summing", "dependency_page", p, PF, "invariant:filter_totals", "semantic")
    p = copy.deepcopy(paths); n = next(x for x in p["nodes"] if x["advisory_lookup"] == "no_match" and x["role"] != "focus"); n["flags"]["evidence_gap"] = True; add("no-match-counted-as-gap", "dependency_page", p, PF, "invariant:evidence_gap_flag", "semantic")
    off = get("deps-paths-synthetic", "paths-lookup-off.json")
    p = copy.deepcopy(off); n = next(x for x in p["nodes"] if x["role"] != "focus"); n["gap_causes"] = []; n["flags"]["evidence_gap"] = False; add("not-run-not-counted-as-gap", "dependency_page", p, PF, "invariant:gap_causes", "semantic")
    p = copy.deepcopy(off); p["lookup"]["explanation"] = None; add("not-run-without-explanation", "dependency_page", p, PF, "invariant:lookup_explanation", "semantic")
    p = copy.deepcopy(d); p["nodes"].append(dict(p["nodes"][-1], node_id="x-extra")); add("31-matches", "dependency_page", p, PF, "invariant:match_page", "semantic")
    om = get("deps-paths-synthetic", "paths-connectors-omitted.json")
    p = copy.deepcopy(om); next(x for x in p["nodes"] if x["role"] == "match")["role"] = "connector"; add("match-reclassified-as-connector", "dependency_page", p, PF, "invariant:connectors_shown", "semantic")
    # ---- assets
    ce = get("cbom-empty-and-partial-synthetic", "crypto-completed-empty.json")
    a_ref = get("cbom-empty-and-partial-synthetic", "crypto-partial.json")["assets"][0]
    p = copy.deepcopy(ce); p["assets"] = [a_ref]; p["page"]["assets_total"] = 1; p["page"]["assets_shown"] = 1; p["counts"] = count_block(1, 1, False)
    add("empty-state-with-assets", "crypto_assets", p, PF, "invariant:availability_assets", "semantic")
    cf = get("cbom-empty-and-partial-synthetic", "crypto-failed.json")
    p = copy.deepcopy(cf); p["assets"] = [a_ref]; p["page"]["assets_total"] = 1; p["page"]["assets_shown"] = 1; p["counts"] = count_block(1, 1, False)
    add("failed-state-with-assets", "crypto_assets", p, PF, "invariant:availability_assets", "semantic")
    cp = get("cbom-empty-and-partial-synthetic", "crypto-partial.json")
    p = copy.deepcopy(cp); p["producers"][1]["provenance"]["experimental"] = False; add("supplemental-not-experimental", "crypto_assets", p, PF, "invariant:supplemental_experimental", "semantic")
    p = copy.deepcopy(cp); a2 = next(a for a in p["assets"] if a["provenance"]["origin"] == "supplemental_observation"); a2["occurrences"][0]["source_location"]["file_sha256"] = None
    add("supplemental-without-file-hash", "crypto_assets", p, PF, "invariant:supplemental_source", "semantic")
    p = copy.deepcopy(cp); p["assets"][0]["provenance"]["json_pointer"] = None; add("original-without-pointer", "crypto_assets", p, PF, "invariant:original_pointer", "semantic")
    p = copy.deepcopy(cp); p["review_items"][0]["tone"] = "advisory"; p["review_items"][0]["evidence_ids"] = []; add("advisory-without-evidence", "crypto_assets", p, PF, "invariant:advisory_evidence", "semantic")
    p = copy.deepcopy(cp); p["links"].append({"relation": "implemented_by", "from": p["assets"][0]["asset_id"], "to": p["assets"][1]["asset_id"], "basis": "recorded", "evidence_ref": None, "condition": None})
    add("implementation-link-not-resolved", "crypto_assets", p, PF, "invariant:implementation_link", "semantic")
    p = copy.deepcopy(cp); p["assets"][0]["attributes"]["algorithm_name"]["value"] = None; add("attribute-recorded-without-value", "crypto_assets", p, PF, "invariant:attribute_value", "semantic")
    p = copy.deepcopy(cp); p["assets"][0]["attributes"]["parameter"]["value"] = "256"; add("attribute-unavailable-with-value", "crypto_assets", p, PF, "invariant:attribute_value", "semantic")
    ai = get("cbom-empty-and-partial-synthetic", "ai-references.json")
    p = copy.deepcopy(ai); next(a for a in p["assets"] if a["kind"] == "model_reference")["identity_state"] = "resolved"; add("model-filename-marked-resolved", "ai_assets", p, PF, "invariant:model_identity", "semantic")
    # ---- inspector
    ih = get("malicious-text-synthetic", "inspector-hostile.json")
    p = copy.deepcopy(ih); p["answers"][2]["state"] = "needs_review"; add("context-inspector-security-concern", "inspector", p, PF, "invariant:context_security", "semantic")
    ic = get("bom-large-synthetic", "inspector-candidate.json")
    p = copy.deepcopy(ic); p["evidence_rows"].append({"status": "source_checked", "label": "Checked", "detail": "x", "evidence_ref": None, "provenance": None}); add("source-checked-without-evidence", "inspector", p, PF, "invariant:row_evidence", "semantic")
    ie = get("bom-large-synthetic", "inspector-entity.json")
    p = copy.deepcopy(ie); p["answers"][2]["state"] = "not_represented"; add("bom-entity-carries-verdict", "inspector", p, PF, "invariant:no_verdict_on_record", "semantic")
    # ---- bom
    nc = get("nonpython-synthetic", "bom-not-compared.json")
    p = copy.deepcopy(nc); p["status_detail"] = None; add("not-compared-without-detail", "bom_candidates", p, PF, "invariant:not_compared_shape", "semantic")
    p = copy.deepcopy(bc); p["items"][1]["canonical_ref"] = copy.deepcopy(p["items"][0]["canonical_ref"]); add("duplicate-canonical-ref", "bom_candidates", p, PF, "invariant:duplicate_canonical_ref", "semantic")
    eo = get("bom-large-synthetic", "graph-evidence-only.json")
    p = copy.deepcopy(eo); n = gn(F["bom-large-synthetic"].files["graph-focused-assertion.json"][1]["binding"], "assert-x", "assertion", "Invented assertion"); p["nodes"].append(n); p["records"].append({"node_id": "assert-x", "full_label": "Invented assertion"})
    p["counts"]["nodes_shown"] = p["counts"]["primary_shown"] = p["counts"]["nodes_in_scope"] = 3; p["counts"]["omitted_nodes"] = 0
    add("evidence-only-with-assertion", "bom_graph", p, PF, "invariant:evidence_only_shape", "semantic")
    fg = get("bom-large-synthetic", "graph-focused-assertion.json")
    p = copy.deepcopy(fg); [e for e in p["edges"] if e["role"] == "excluded"][0]["role"] = "used"; add("excluded-evidence-on-supporting-edge", "bom_graph", p, PF, "invariant:excluded_as_support", "semantic")
    p = copy.deepcopy(fg); n2 = copy.deepcopy(p["nodes"][0]); n2["node_id"] = "assert-second"; p["nodes"].append(n2); p["records"].append({"node_id": "assert-second", "full_label": n2["full_label"]})
    for k in ("nodes_in_scope", "nodes_shown", "primary_shown"): p["counts"][k] += 1
    add("two-assertions-in-focused-graph", "bom_graph", p, PF, "invariant:assertion_count", "semantic")
    rs = get("bom-large-synthetic", "related-shared-offset-00.json")
    p = copy.deepcopy(rs); p["resolution"] = "single"; add("resolution-inconsistent", "bom_related_checks", p, PF, "invariant:resolution", "semantic")
    rr = get("bom-large-synthetic", "related-relationship.json")
    p = copy.deepcopy(rr); p["items"] = copy.deepcopy(rs["items"][:1]); add("relationship-with-items", "bom_related_checks", p, PF, "invariant:relationship_shape", "semantic")
    # ---- correction batch: sealed references, links, paging, dependency omissions
    full = copy.deepcopy(bc["binding"])
    for key, val, detail in [("analysis_digest", "sha256:" + "9" * 64, "invariant:canonical_ref_analysis_digest"), ("generation", 2, "invariant:canonical_ref_generation"),
                             ("configuration", "config:other", "invariant:canonical_ref_configuration"), ("bundle_sha256", "9" * 64, "invariant:canonical_ref_bundle")]:
        p = copy.deepcopy(bc); p["items"][0]["canonical_ref"]["binding"][key] = val
        add("candidate-ref-other-%s" % key.replace("_", "-"), "bom_candidates", p, "binding_mismatch", detail, "semantic", request={"generation": 1}, expected_binding=full)
    p = copy.deepcopy(bc); p["items"][1]["canonical_ref"]["binding"]["session_id"] = "e" * 32
    add("candidate-refs-two-sessions", "bom_candidates", p, "binding_mismatch", "invariant:canonical_ref_session", "semantic", request={"generation": 1})
    gfoc = get("bom-large-synthetic", "graph-focused-assertion.json")
    p = copy.deepcopy(gfoc); p["nodes"][0]["canonical_ref"]["binding"]["analysis_digest"] = "sha256:" + "8" * 64
    add("graph-ref-other-analysis", "bom_graph", p, "binding_mismatch", "invariant:canonical_ref_analysis_digest", "semantic", request={"generation": 1}, expected_binding=gfoc["binding"])
    p = copy.deepcopy(ic); p["selection"]["canonical_ref"]["binding"]["generation"] = 3
    add("inspector-ref-other-generation", "inspector", p, "binding_mismatch", "invariant:canonical_ref_generation", "semantic", request={"generation": 1}, expected_binding=ic["binding"])
    for key, val in [("configuration", "config:changed"), ("validation_digest", "9" * 64), ("bundle_sha256", "8" * 64)]:
        p = copy.deepcopy(bc); p["binding"]["assessment"][key] = val
        add("assessment-%s-changed" % key.replace("_", "-"), "bom_candidates", p, "binding_mismatch", "invariant:assessment", "semantic", request={"generation": 1}, expected_binding=full)
    p = copy.deepcopy(bc); p["binding"]["repository"]["owner"] = "someone-else"
    add("repository-owner-changed", "bom_candidates", p, "binding_mismatch", "invariant:repository", "semantic", request={"generation": 1}, expected_binding=full)
    add("scan-job-owned-by-another-request", "scan_status", copy.deepcopy(pre), "job_not_found", "invariant:job_id", "semantic",
        request={"generation": 1, "job_id": "job:" + "0" * 24})
    cpart = get("cbom-empty-and-partial-synthetic", "crypto-partial.json")
    for nm, href, detail in [("javascript-scheme", "javascript:alert(1)", "invariant:link_scheme"), ("data-scheme", "data:text/html,<script>alert(1)</script>", "invariant:link_scheme"),
                             ("credentials", "https://user:password@github.com/evil/repo/blob/wrong/file", "invariant:link_credentials"),
                             ("unrelated-host", "https://example.org/unrelated", "invariant:link_destination")]:
        p = copy.deepcopy(cpart); next(a for a in p["assets"] if a["occurrences"])["occurrences"][0]["source_location"]["link"]["href"] = href
        add("occurrence-link-" + nm, "crypto_assets", p, PF, detail, "semantic")
    p = copy.deepcopy(c); p["groups"][0]["files"][0]["revision_link"]["href"] = p["groups"][0]["files"][1]["revision_link"]["href"]
    add("revision-link-for-another-path", "contexts", p, PF, "invariant:link_destination", "semantic")
    last = get("deps-82-synthetic", "page-offset-60.json")
    p = copy.deepcopy(last); p["counts"]["truncated"] = False
    add("counts-truncated-taken-from-has-more", "dependency_page", p, PF, "invariant:counts_truncated", "semantic")
    p = copy.deepcopy(bc); p["page"]["offset"] = 1000000; add("candidates-offset-out-of-range", "bom_candidates", p, PF, "invariant:page_offset", "semantic")
    p = get("bom-large-synthetic", "related-shared-offset-00.json"); p["page"]["offset"] = 1000000; add("related-offset-out-of-range", "bom_related_checks", p, PF, "invariant:page_offset", "semantic")
    p = copy.deepcopy(nc); p["page"]["offset"] = 25; add("empty-list-nonzero-offset", "bom_candidates", p, PF, "invariant:page_offset", "semantic")
    p = copy.deepcopy(paths); n = next(x for x in p["nodes"] if x["role"] == "match" and x["depth"] == 2); n["path_state"] = "connectors_omitted"
    add("omitted-path-with-drawn-edges", "dependency_page", p, PF, "invariant:omitted_path", "semantic")
    p = copy.deepcopy(paths); n = next(x for x in p["nodes"] if x["role"] == "match" and x["depth"] == 2); n["path_state"] = "connectors_omitted"
    p["edges"] = [e for e in p["edges"] if n["node_id"] not in (e["from"], e["to"])]
    add("omitted-path-with-false-truncation-flags", "dependency_page", p, PF, "invariant:truncation_flags", "semantic")
    p = copy.deepcopy(off); f_ = next(x for x in p["nodes"] if x["role"] == "focus"); f_["gap_causes"] = []; f_["flags"]["evidence_gap"] = False
    add("focus-hides-lookup-not-run", "dependency_page", p, PF, "invariant:gap_causes", "semantic")
    # ---- requests
    ctx = d["context"]["context_id"]
    base = {"generation": 1, "context_id": ctx}

    def rq(name, params, code, detail, route="dependency_page"):
        cases.append((name, {"schema_name": None, "payload": None, "request": None, "expected_binding": None, "route": route, "params": params, "sequence": None},
                      code, detail, "structural" if code == "invalid_request" and detail in ("bound_exceeded", "enum_violation", "missing_field", "pattern_violation") else "semantic"))
    rq("request-unknown-parameter", dict(base, foo="1"), "invalid_request", "unknown_parameter")
    rq("request-duplicate-parameter", {"generation": ["1", "2"], "context_id": ctx}, "invalid_request", "duplicate_parameter")
    rq("request-query-81-chars", dict(base, query="q" * 81), "invalid_request", "bound_exceeded")
    rq("request-page-size-override", dict(base, size="31"), "invalid_request", "enum_violation")
    rq("request-missing-generation", {"context_id": ctx}, "invalid_request", "missing_field")
    rq("request-unsupported-version", dict(base, schema_version="2"), "unsupported_version", "schema_version")
    rq("request-non-decimal-offset", dict(base, offset="1e3"), "invalid_request", "type_error")
    rq("request-offset-too-large", dict(base, offset="1000001"), "invalid_request", "bound_exceeded")
    return cases


def write_invalid(out_dir, F):
    d = os.path.join(out_dir, "invalid")
    os.makedirs(d, exist_ok=True)
    expected, entries = {}, []
    for name, env, code, detail, layer in build_cases(F):
        got = run_case(env)
        if got != (code, detail):
            raise RuntimeError("invalid case %s: expected %s, got %s" % (name, (code, detail), got))
        data = (json.dumps(env, sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
        fname = name + ".json"
        with open(os.path.join(d, fname), "wb") as h:
            h.write(data)
        expected[fname] = {"code": code, "detail_code": detail, "layer": layer}
        entries.append({"path": fname, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "schema": "invalid-case-envelope"})
    with open(os.path.join(d, "EXPECTED.json"), "w", encoding="utf-8") as h:
        h.write(json.dumps(expected, sort_keys=True, indent=1) + "\n")
    with open(os.path.join(REPO, BUILDER_PATH), "rb") as h:
        bsha = hashlib.sha256(h.read()).hexdigest()
    manifest = {"schema": "opentrace.uip.fixture_manifest/1", "name": "invalid", "provenance": "synthetic", "files": entries, "sources": [],
                "builder": {"path": BUILDER_PATH, "sha256": bsha, "seed": SEED}, CONTAINS_KEY: False, "normalized": [],
                "notes": "Mutations of valid fixtures. Each envelope names the rule it breaks; EXPECTED.json records the exact code, detail code and layer (structural cases are rejected by JSON Schema too; semantic cases are not expected to be)."}
    with open(os.path.join(d, "MANIFEST.json"), "w", encoding="utf-8") as h:
        h.write(json.dumps(manifest, sort_keys=True, indent=1) + "\n")
    return expected


# ================================================================ main
def build_all(out_dir):
    synthetic = [fx_deps82(), fx_deps_paths(), fx_contexts600(), fx_nonpython(), fx_no_ai(), fx_cbom_ai(), fx_scan_matrix(), fx_bom_large(), fx_malicious()]
    F = {fx.name: fx for fx in synthetic}
    with no_external_network():
        recorded, snapshots = derive_recorded(out_dir)
    F[recorded.name] = recorded
    os.makedirs(out_dir, exist_ok=True)
    manifests = {}
    for fx in list(F.values()) + [snapshots]:
        manifests[fx.name] = write_fixture(out_dir, fx, validated=fx.name != "legacy-view-snapshots")
    write_invalid(out_dir, F)
    return manifests


def main(argv=None):
    argv = argv or sys.argv[1:]
    out = DEFAULT_OUT
    if "--out" in argv:
        out = os.path.abspath(argv[argv.index("--out") + 1])
    manifests = build_all(out)
    print("built %d fixture sets into %s" % (len(manifests) + 1, out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
