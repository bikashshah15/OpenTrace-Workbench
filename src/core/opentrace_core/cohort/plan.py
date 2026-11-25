"""Deterministic planning from verified captures (I3-REQ-04, I3-REQ-06, I3-REQ-10).

Everything here is a pure function of a verified capture set (and the occurrence tables derived from it).
No network, no clock. Bundles are canonical JSON; the planner never reads a file outside the capture sets.
"""
import json
import posixpath

from ..canon import canonical_bytes, canonical_digest, digest_of_bytes
from . import identity

MANIFEST_BUNDLE = "opentrace.i3.source_bundle/1"
OSV_BUNDLE = "opentrace.i3.osv_bundle/1"
HOSTED_BUNDLE = "opentrace.i3.hosted_bundle/1"
OSV_PLAN = "opentrace.i3.osv_plan/1"
BUILD_SCOPE = "static inventory; no build; no code execution"
BATCH_SIZE = 100
INVENTORY_KINDS = ("go_mod", "npm_lock", "pnpm_lock", "uv_lock")
LOCK_FOR_PACKAGE_JSON = ("npm_lock", "pnpm_lock")
LANGUAGE = {"go_mod": "go", "npm_lock": "typescript", "pnpm_lock": "typescript", "package_json": "typescript", "uv_lock": "python"}
MAX_INVENTORY_TASKS = 40


def _dir(path):
    d = posixpath.dirname(path)
    return d


def _ancestors(path):
    """Directories from the file's own directory up to the root ('')."""
    d = _dir(path)
    out = [d]
    while d:
        d = posixpath.dirname(d)
        out.append(d)
    return out


def _file_entry(row, blob):
    return {"path": row["path"], "kind": row["kind"], "git_blob": row["sha"], "sha256": blob[0][7:] if blob else "",
            "bytes": blob[1] if blob else (row["size"] or 0), "mode": row["mode"], "blob": blob[0] if blob else "", "hint": ""}


def source_tasks(sourceset):
    """The deterministic list of repo_inventory tasks, one per inventory manifest, in (repo, path) order.

    Each task is {repo, path, kind, language, bundle (dict), bundle_bytes, bundle_digest, blobs {digest: bytes},
    inputs, context, capture_set_id}. The first task of a repository also carries the repository scope and the
    manifest paths that have no inventory task (excluded, unsupported kinds, unreadable, hostile).
    """
    tasks, notes = [], []
    for repo in sorted(sourceset.repos):
        sr = sourceset.repos[repo]
        sel = sourceset.selection(repo)
        selected = sel["selected"]
        blob_of = lambda row: sr.blobs.get(row["path"])  # noqa: E731
        by_kind_dir = {}
        for row in selected:
            by_kind_dir.setdefault((row["kind"], _dir(row["path"])), []).append(row)

        def lock_above(path, kinds):
            return any((k, d) in by_kind_dir and blob_of(by_kind_dir[(k, d)][0]) for k in kinds for d in _ancestors(path))

        inventory, extras, companions = [], [], {}
        for row in selected:
            kind, blob = row["kind"], blob_of(row)
            entry = _file_entry(row, blob)
            if blob is None:
                entry["hint"] = "too_large"
                extras.append(entry)
            elif kind in INVENTORY_KINDS:
                inventory.append((row, entry))
            elif kind == "package_json":
                if lock_above(row["path"], LOCK_FOR_PACKAGE_JSON):
                    continue  # reported by the covering lock (or accounted as unaccounted by core)
                inventory.append((row, entry))
            elif kind == "pyproject":
                if lock_above(row["path"], ("uv_lock",)):
                    continue
                extras.append(entry)
            elif kind == "go_sum" and ("go_mod", _dir(row["path"])) in by_kind_dir and blob_of(by_kind_dir[("go_mod", _dir(row["path"]))][0]):
                companions[_dir(row["path"])] = entry
            else:
                extras.append(entry)
        for row in sel["excluded"]:
            extras.append(dict(_file_entry(row, None), hint="excluded_path_segment"))
        for row in sel["nonblob"]:
            extras.append(dict(_file_entry(row, None), hint=row["reason"]))
        for row in sel["rejected"]:
            extras.append(dict(_file_entry(row, None), hint="rejected_%s" % row["reason"]))
        extras.sort(key=lambda e: (e["path"].encode("utf-8", "surrogateescape"), e["hint"]))
        siblings = [{"path": r["path"], "kind": r["kind"], "git_blob": r["sha"]} for r in selected]
        if not inventory:
            notes.append({"repo": repo, "note": "no inventory manifest"})
            continue
        for n, (row, entry) in enumerate(inventory):
            comp = companions.get(_dir(row["path"])) if row["kind"] == "go_mod" else None
            bundle = {"schema": MANIFEST_BUNDLE, "kind": "source", "repo": repo, "commit": sr.commit, "tree": sr.event["tree"],
                      "source_capture_set_id": sourceset.captures.id, "listing_digest": sr.listing_digest,
                      "selected_manifest_count": len(selected), "excluded_by_policy_count": len(sel["excluded"]),
                      "emit_scope": n == 0, "manifest": entry, "companions": [comp] if comp else [],
                      "siblings": siblings, "extras": extras if n == 0 else []}
            blobs = {entry["blob"]: sourceset.blob(repo, row["path"])}
            if comp:
                blobs[comp["blob"]] = sourceset.blob(repo, comp["path"])
            raw = canonical_bytes(bundle)
            digest = digest_of_bytes(raw)
            blobs[digest] = raw
            tasks.append({
                "repo": repo, "path": row["path"], "kind": row["kind"], "language": LANGUAGE[row["kind"]],
                "bundle": bundle, "bundle_bytes": raw, "bundle_digest": digest, "blobs": blobs,
                "inputs": [{"digest": digest, "media_type": "application/json", "role": "bundle_manifest"}],
                "context": {"repo_id": "github.com/%s" % repo, "requested_revision": sr.commit, "observed_revision": sr.commit,
                            "baseline_id": "baseline", "candidate_id": None, "language": LANGUAGE[row["kind"]],
                            "build_scope": BUILD_SCOPE},
                "capture_set_id": sourceset.captures.id})
    if len(tasks) > MAX_INVENTORY_TASKS:
        raise ValueError("more than %d inventory tasks" % MAX_INVENTORY_TASKS)
    return tasks, notes


# ---- OSV planning ---------------------------------------------------------------------------------------

def occurrences_of(tables):
    """Flatten {(repo, path): table} into sorted occurrence dicts carrying their manifest and repo."""
    out = []
    for (repo, path) in sorted(tables):
        for row in tables[(repo, path)]["rows"]:
            out.append(dict(row, repo=repo, path=path))
    return out


def osv_plan(occurrences, go_form):
    """Planned queries (unique exact triples), batches of at most BATCH_SIZE, and the unresolved occurrences.

    Every occurrence is linked to exactly one triple or is unresolved with a reason, never both and never neither.
    """
    triples, unresolved, links = {}, [], []
    for occ in occurrences:
        state = occ["version_state"]
        if state != "exact":
            unresolved.append(dict(occ, reason=state))
            continue
        eco = occ["ecosystem"]
        try:
            name = identity.normalize_name(eco, occ["name_original"])
            sent = identity.version_queried(eco, occ["version_original"], go_form)
        except identity.IdentityError:
            unresolved.append(dict(occ, reason="version_unqueryable"))
            continue
        if name != occ["name_normalized"]:
            unresolved.append(dict(occ, reason="unresolved_identity"))
            continue
        key = identity.query_key(eco, name, sent)
        t = triples.setdefault(key, {"query_key": key, "ecosystem": eco, "name": name, "version_queried": sent,
                                     "version_original": occ["version_original"], "originals": set()})
        t["originals"].add(occ["version_original"])
        links.append({"query_key": key, "repo": occ["repo"], "path": occ["path"], "locator": occ["locator"]})
    queries = sorted(triples.values(), key=lambda t: (t["ecosystem"].encode(), t["name"].encode(), t["version_queried"].encode()))
    for t in queries:
        t["originals"] = sorted(t["originals"])
        t["version_original"] = t["originals"][0]
    batches = [queries[i:i + BATCH_SIZE] for i in range(0, len(queries), BATCH_SIZE)]
    digest = canonical_digest({"schema": OSV_PLAN, "query_key_form": "ecosystem|name|version", "go_version_form": go_form,
                               "queries": [[q["ecosystem"], q["name"], q["version_queried"]] for q in queries]})
    return {"queries": queries, "batches": batches, "planned_query_digest": digest, "go_version_form": go_form,
            "unresolved": unresolved, "links": links}


def _response_ids(raw):
    ids = []
    try:
        for res in json.loads(raw).get("results", []):
            ids.extend(v["id"] for v in res.get("vulns", []) if isinstance(v, dict) and "id" in v)
    except (ValueError, AttributeError, TypeError):
        pass
    return ids


def osv_batch_bundle(captures, batch, plan):
    """Bundle manifest for one planned batch: every captured round whose queries belong to the batch, in capture
    order, plus the record digests of every returned ID. The query keys of rounds come from the captured requests."""
    keys = {q["query_key"] for q in batch}
    rounds, ids = [], []
    for e in captures.entries:
        if e["kind"] != "osv_querybatch" or not e["request_digest"]:
            continue
        try:
            queries = json.loads(captures.blob(e["request_digest"]))["queries"]
        except (ValueError, KeyError, TypeError):
            continue
        qkeys = {identity.query_key_from_request(q) for q in queries}
        if not qkeys or not qkeys <= keys:
            continue
        item = {"request": e["request_digest"], "response": e["response_digest"] or "", "status": e["status"] or 0}
        if rounds and rounds[-1]["request"] == item["request"]:
            rounds[-1] = item  # a retried attempt of the same request replaces the failed one
        else:
            rounds.append(item)
        if item["response"] and item["status"] == 200:
            ids.extend(_response_ids(captures.blob(item["response"])))
    records = {}
    for e in captures.entries:
        if e["kind"] == "osv_vuln":
            vid = e["url"].rstrip("/").rsplit("/", 1)[-1]
            if vid in ids:
                records[vid] = {"digest": e["response_digest"] or "", "status": e["status"] or 0}
    bundle = {"schema": OSV_BUNDLE, "kind": "osv", "capture_set_id": captures.id,
              "planned_query_digest": plan["planned_query_digest"], "query_key_form": "ecosystem|name|version",
              "queries": [{"query_key": q["query_key"], "ecosystem": q["ecosystem"], "name": q["name"],
                           "version_queried": q["version_queried"], "version_original": q["version_original"]} for q in batch],
              "rounds": rounds, "records": records}
    return canonical_bytes(bundle)


def osv_capture_blobs(captures, bundle_raw):
    """Digest -> bytes of every blob a bundle references (rounds and records), verified by the capture set."""
    bundle = json.loads(bundle_raw)
    wanted = []
    for r in bundle["rounds"]:
        wanted += [r["request"], r["response"]]
    wanted += [rec["digest"] for rec in bundle["records"].values()]
    return {d: captures.blob(d) for d in dict.fromkeys(wanted) if d}


# ---- hosted bundle ---------------------------------------------------------------------------------------

def hosted_credential_class(captures):
    """The credential CLASS the acquisition recorded on its entries (never a token); one class per capture set."""
    classes = {e["headers"].get("x-opentrace-credential-class") for e in captures.entries if e["kind"].startswith("github_")}
    classes.discard(None)
    if len(classes) != 1 or next(iter(classes)) not in ("unauthenticated", "token_read_only", "app"):
        raise ValueError("a hosted capture set records exactly one valid credential class")
    return next(iter(classes))


def hosted_bundle(captures, repo, pin, credential_class=None):
    """Bundle of the captured GitHub exchange of one repository (entries in capture order)."""
    credential_class = credential_class or hosted_credential_class(captures)
    entries = []
    for e in captures.entries:
        # every github_* entry names its repository in the URL fragment (the fragment is record metadata only)
        if not e["kind"].startswith("github_") or not e["url"].endswith("#repo=%s" % repo):
            continue
        entries.append({"seq": len(entries) + 1, "kind": e["kind"], "method": e["method"], "url": e["url"], "status": e["status"],
                        "headers": e["headers"], "response": e["response_digest"] or "", "bytes": e["bytes"],
                        "redirect_hops": e["redirect_hops"]})
    return canonical_bytes({"schema": HOSTED_BUNDLE, "kind": "hosted", "capture_set_id": captures.id, "repo": repo,
                            "requested_pin": pin, "credential_class": credential_class, "entries": entries})


def hosted_capture_blobs(captures, bundle_raw):
    bundle = json.loads(bundle_raw)
    return {e["response"]: captures.blob(e["response"]) for e in bundle["entries"] if e["response"]}
