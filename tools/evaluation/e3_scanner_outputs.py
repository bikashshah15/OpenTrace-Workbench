"""E3-C: actual scanner output for the 11 frozen external anchors (7 DeepBits declarations, 4 BF-CBOM hash call sites).

Stages (each explicit; nothing is chained automatically):

``plan``      verify the frozen anchors against the local benchmarks and report prerequisites. Writes nothing.
``source``    fetch the commit named in each benchmark ZIP with OpenTrace's own verified acquisition (``live.source.acquire``:
              every blob re-hashed against the commit tree). Needs ``--allow-network`` (or ``--git-remote`` for a local clone).
``acquire``   scan that exported tree in the isolated OpenTrace scanner worker. Needs ``--allow-scans``. No unisolated fallback.
``evaluate``  offline: raw-inventory lookup, unchanged OpenTrace collector, live bundle builder and ``live_discovery.run`` on the
              same source and the same BOM bytes.

Without a verified commit and a recorded scan no revision or binding is invented: raw representation and collection are still
reported where possible, and the end-to-end assessment is ``unavailable`` with the reason.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import zipfile
from types import SimpleNamespace

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from tools.evaluation import baselines as B  # noqa: E402
from tools.evaluation import common as C  # noqa: E402
from tools.evaluation import e4_integration as E4  # noqa: E402
from tools.evaluation import scanner_reference as R  # noqa: E402

CAPTURE_SCHEMA = "opentrace.evaluation.e3c_capture/1"
DATASETS = {
    "deepbits": {"domain": "sbom", "kind": "sbom", "scanner": "syft", "repository": "https://github.com/DeepBitsTechnology/sbom-benchmark",
                 "zip": "sbom-benchmark-main.zip", "zip_sha256": "b2b32284552d629a839033bf6e88ba8914048019c6007a7875cb81b68ec69431", "anchors": 7},
    "bf_cbom": {"domain": "cbom", "kind": "cbom", "scanner": "cdxgen", "repository": "https://github.com/SEG-UNIBE/BF-CBOM",
                "zip": "BF-CBOM-main.zip", "zip_sha256": "64e5fd94d0a7d610bacbc3001cf45d362c379d8396d357f53f72f4a95916e70f", "anchors": 4},
}


# ================================================================================================== frozen reference
def anchor_path(a: dict) -> str:
    """The anchor's path relative to the repository root (the scanned root)."""
    return a.get("repo_path") or a["path"]


def reference_selection(frozen: str) -> dict:
    """The eleven frozen external anchors and the recorded exclusions. The selection is read, never changed."""
    path = os.path.join(frozen, "selection_manifest.json")
    m = C.read_json(path)
    anchors = [a for a in m["anchors"] if a["domain"] in ("sbom", "cbom")]
    counts = {d: sum(a["domain"] == d for a in anchors) for d in ("sbom", "cbom")}
    if counts != {"sbom": 7, "cbom": 4}:
        raise C.HarnessError(f"expected 7 SBOM and 4 CBOM anchors in the frozen selection, found {counts}")
    return {"selection_sha256": C.read_json(os.path.join(frozen, "FROZEN.json"))["selection_sha256"],
            "selection_manifest_sha256": C.sha256_file(path), "anchors": anchors,
            "excluded": [x for x in m["excluded"] if x["domain"] in ("sbom", "cbom")]}


def check_anchors(ref: dict, dataset: str, tree: str) -> list[dict]:
    """Each anchor's file digest and line text, checked against a source tree."""
    out = []
    for a in ref["anchors"]:
        if a["domain"] != DATASETS[dataset]["domain"]:
            continue
        p = os.path.join(tree, *anchor_path(a).split("/"))
        rec = {"anchor_id": a["anchor_id"], "path": anchor_path(a), "file_present": os.path.isfile(p) and not os.path.islink(p)}
        if rec["file_present"]:
            rec["file_sha256_matches"] = C.sha256_file(p) == a["file_sha256"]
            lines = C.read_bytes(p).decode("utf-8", "replace").splitlines()
            n = (a.get("line_range") or a.get("lines"))[0]
            rec["line_text_matches"] = 0 < n <= len(lines) and lines[n - 1].strip() == (a.get("text") or a.get("line_text")).strip()
        rec["verified"] = bool(rec.get("file_sha256_matches") and rec.get("line_text_matches"))
        out.append(rec)
    return out


def zip_identity(path: str) -> dict:
    """Archive digest, the commit id GitHub stores in the ZIP comment (a claim until verified) and per-file digests."""
    with zipfile.ZipFile(path) as z:
        comment = z.comment.decode("ascii", "replace").strip()
        files = {}
        for i in z.infolist():
            if not i.is_dir():
                files[i.filename.split("/", 1)[1]] = hashlib.sha256(z.read(i)).hexdigest()
    return {"archive_sha256": C.sha256_file(path), "commit_claimed_by_archive": comment if re.fullmatch(r"[0-9a-f]{40}", comment) else None,
            "files": files}


def compare_files(exported: dict, archive: dict) -> dict:
    return {"identical": exported == archive, "only_in_commit": sorted(set(exported) - set(archive)), "only_in_archive": sorted(set(archive) - set(exported)),
            "different": sorted(p for p in set(exported) & set(archive) if exported[p] != archive[p])}


def tree_matches(tree: str, inputs: list[dict]) -> list[str]:
    """Paths whose bytes on disk differ from the recorded export (missing, changed or additional files)."""
    want = {i["path"]: i["sha256"] for i in inputs}
    have = {r["path"]: r["sha256"] for r in C.tree_listing(tree, exclude_dirs=())}
    return sorted(p for p in set(want) | set(have) if want.get(p) != have.get(p))


# ================================================================================================== stage: source
def stage_source(captures: str, ref: dict, zips: str, dataset: str, remote: str | None, allow_network: bool) -> dict:
    from opentrace_core.live import source as S
    spec = DATASETS[dataset]
    zp = os.path.join(zips, spec["zip"])
    ident = zip_identity(zp)
    if ident["archive_sha256"] != spec["zip_sha256"]:
        raise C.HarnessError(f"{spec['zip']} is not the archive used by the completed evaluation")
    commit = ident["commit_claimed_by_archive"]
    if not commit:
        raise C.NotRunError(f"{spec['zip']} names no commit; the source cannot be bound to a revision")
    if not remote and not allow_network:
        raise C.NotRunError("fetching the commit needs --allow-network, or --git-remote with a local clone that contains it")
    base = os.path.join(captures, dataset)
    os.makedirs(base)                                   # never overwrite a capture
    workspace = os.path.join(base, "workspace")
    os.makedirs(workspace)
    try:
        record = S.acquire(remote or spec["repository"], commit, workspace, canonical_url=spec["repository"],
                           allow_protocol="file" if remote else "https")
    except S.SourceError as exc:
        C.write_json(os.path.join(base, "source_failure.json"), {"commit": commit, "code": exc.code, "detail": exc.detail, "at": C.utc_now()})
        raise C.NotRunError(f"commit {commit[:12]} was not verified: {exc.code}") from exc
    os.rename(os.path.join(workspace, "src"), os.path.join(base, "src"))
    shutil.rmtree(workspace, ignore_errors=True)
    exported = {i["path"]: i["sha256"] for i in record.inputs}
    doc = {"schema": CAPTURE_SCHEMA, "dataset": dataset, "acquired_at": C.utc_now(),
           "record": record.as_dict() | {"inputs": [dict(i) for i in record.inputs]},
           "fetched_from": "local clone supplied by the operator" if remote else spec["repository"],
           "archive": {"name": spec["zip"], "sha256": ident["archive_sha256"], "commit_in_comment": commit},
           "archive_comparison": compare_files(exported, ident["files"]), "anchor_checks": check_anchors(ref, dataset, os.path.join(base, "src"))}
    C.write_json(os.path.join(base, "source.json"), doc)
    return doc


# ================================================================================================== stage: acquire
def stage_acquire(captures: str, dataset: str, spool_in: str, spool_out: str, image_id: str | None, scan_seconds: int) -> dict:
    """Run the pinned Syft and cdxgen in the isolated worker over the verified export. Both outputs are kept; one is scored."""
    from opentrace_core.live import worker_client as W
    from opentrace_core.live.scanners import ScannerConfig
    from opentrace_core.live.source import SourceRecord
    base = os.path.join(captures, dataset)
    src_doc = _load(os.path.join(base, "source.json"))
    if src_doc is None:
        raise C.NotRunError(f"no verified source for {dataset}: run --stage source first")
    rec = src_doc["record"]
    changed = tree_matches(os.path.join(base, "src"), rec["inputs"])
    if changed:
        raise C.HarnessError(f"the exported source differs from its record: {changed[:5]}")
    if os.path.exists(os.path.join(base, "capture.json")):
        raise C.HarnessError(f"a capture already exists for {dataset}; use a new --captures directory (attempts are never overwritten)")
    source = SourceRecord(**{k: v for k, v in rec.items() if k not in ("skipped", "inputs")}, skipped=tuple(rec["skipped"]), inputs=tuple(rec["inputs"]))
    client = W.WorkerClient(spool_in, spool_out)
    status, why = client.status()
    if status is None:
        raise C.NotRunError(f"isolated scanner worker unavailable: {why}")          # no attempt, no capture, no unisolated fallback
    config = SimpleNamespace(worker=client, scanners=ScannerConfig(scan_seconds=scan_seconds))
    ticket = SimpleNamespace(cancel_event=threading.Event())
    service = SimpleNamespace(register_producer=lambda *_: None)
    started = C.utc_now()
    with tempfile.TemporaryDirectory(prefix="ot-e3c-scan-") as workspace:
        shutil.copytree(os.path.join(base, "src"), os.path.join(workspace, "src"))
        runs = W.scan(config, service, ticket, source, workspace)
    serialised, artifacts = [], {}
    for run in runs:
        d = run.as_dict()
        serialised.append(d)
        if run.outcome == "acquired":
            name = f"{run.scanner}.cdx.json"
            with open(os.path.join(base, name), "xb") as fh:
                fh.write(run.data)
            artifacts[run.kind] = {"file": name, "sha256": run.sha256}
    after = tree_matches(os.path.join(base, "src"), rec["inputs"])
    doc = {"schema": CAPTURE_SCHEMA, "dataset": dataset, "started_at": started, "finished_at": C.utc_now(),
           "source_record_sha256": C.sha256_file(os.path.join(base, "source.json")), "runs": serialised, "artifacts": artifacts,
           "source_unchanged_after_scan": not after,
           "worker": {**client.public(), "image_id_declared_by_operator": image_id}}
    C.write_json(os.path.join(base, "capture.json"), doc)
    return doc


# ================================================================================================== capture loading
def _load(path: str):
    return C.read_json(path) if os.path.isfile(path) else None


def load_capture(captures: str, dataset: str) -> dict:
    """Validate one capture. States are kept apart:

    ``capture_missing`` / ``capture_invalid`` / ``scanner_failed`` / ``scanner_unavailable`` / ``scanner_cancelled`` /
    ``acquired`` / ``acquired_empty`` (a successful scan whose inventory has no record of the scored kind).
    ``binding`` is ``verified`` only for a commit-verified export whose bytes and scan record agree.
    """
    spec = DATASETS[dataset]
    base = os.path.join(captures, dataset)
    out = {"dataset": dataset, "scanner": spec["scanner"], "state": "capture_missing", "reason": None, "binding": "unbound",
           "binding_reason": "no verified source record", "source": None, "runs": [], "artifacts": {}, "tree": None, "document": None}
    try:
        src = _load(os.path.join(base, "source.json"))
        cap = _load(os.path.join(base, "capture.json"))
        if src and os.path.isdir(os.path.join(base, "src")):
            changed = tree_matches(os.path.join(base, "src"), src["record"]["inputs"])
            if changed:
                out.update(state="capture_invalid", reason=f"exported source differs from its record: {changed[:5]}")
                return out
            out.update(source=src, tree=os.path.join(base, "src"))
            if src.get("schema") == CAPTURE_SCHEMA and src["record"].get("verified") is True \
                    and re.fullmatch(r"[0-9a-f]{40}", src["record"].get("commit_sha") or ""):
                out.update(binding="verified", binding_reason=None)
        if cap is None:
            out["reason"] = (src and "no scan record") or ((_load(os.path.join(base, "source_failure.json")) or {}).get("code")) or "no capture directory"
            return out
        if out["binding"] == "verified" and cap.get("source_record_sha256") != C.sha256_file(os.path.join(base, "source.json")):
            out.update(binding="unbound", binding_reason="the scan record names a different source record")
        if out["binding"] == "verified" and cap.get("source_unchanged_after_scan") is not True:
            out.update(binding="unbound", binding_reason="the source was not shown unchanged after the scan")
        if out["binding"] == "verified" and any((r.get("scope") or {}).get("listing_sha256") != src["record"]["listing_sha256"]
                                                or (r.get("scope") or {}).get("revision") != src["record"]["commit_sha"] for r in cap["runs"]):
            out.update(binding="unbound", binding_reason="a scan scope disagrees with the source record")
        out.update(runs=cap["runs"], capture=cap)
        for kind, art in cap["artifacts"].items():
            if os.path.basename(art["file"]) != art["file"]:
                raise ValueError("artifact path is not a plain file name")
            path = os.path.join(base, art["file"])
            data = C.read_bytes(path) if os.path.isfile(path) and not os.path.islink(path) else None
            run = next((r for r in cap["runs"] if r["kind"] == kind), None)
            if data is None or not run or run.get("outcome") != "acquired" or not (C.sha256_bytes(data) == art["sha256"] == run.get("sha256")):
                out.update(state="capture_invalid", reason=f"{kind} bytes are missing or differ from the scan record")
                return out
            out["artifacts"][kind] = data
        if any(r.get("outcome") == "acquired" and r["kind"] not in out["artifacts"] for r in cap["runs"]):
            out.update(state="capture_invalid", reason="an acquired run is recorded without its output bytes")
            return out
        run = next((r for r in cap["runs"] if r["kind"] == spec["kind"]), None)
        if run is None:
            out.update(state="capture_missing", reason=f"no {spec['scanner']} run recorded")
        elif run["outcome"] != "acquired":
            state = {"failed": "scanner_failed", "cancelled": "scanner_cancelled"}.get(run["outcome"], "scanner_unavailable")
            out.update(state=state, reason=run.get("reason"))
        else:
            out["document"] = R.parse_document(out["artifacts"][spec["kind"]])
            wanted = "library" if spec["kind"] == "sbom" else "cryptographic-asset"
            n = sum(c.get("type") == wanted for _, c in R.walk(out["document"].get("components")))
            out.update(state="acquired" if n else "acquired_empty", reason=None)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        out.update(state="capture_invalid", reason=f"{type(exc).__name__}: {exc}"[:300], document=None, binding="unbound", binding_reason="capture unreadable")
    return out


# ================================================================================================== OpenTrace (unchanged)
def collect(tree: str, repository: str, revision: str) -> dict:
    """OpenTrace's bounded static collector on a temporary copy of the tree."""
    from opentrace_core.live import source_declarations as sd
    with tempfile.TemporaryDirectory(prefix="ot-e3c-collect-") as tmp:
        dst = os.path.join(tmp, "tree")
        shutil.copytree(tree, dst, symlinks=True)
        return sd.collect(dst, repository, revision)


def run_pipeline(cap: dict, sink: dict) -> tuple[dict, dict]:
    """The live Workbench route after scanning: session, live bundle builder, ``live_discovery.run``. Inputs are the recorded
    source record, the recorded scan runs and the captured bytes; no resolution flag or file binding is set here."""
    from opentrace_core.app import live_discovery
    from opentrace_core.bombridge_adapter import AdapterContext
    from opentrace_core.intake.identity import build_identity
    from opentrace_core.intake.url import parse_repository_url
    from opentrace_core.live import bundle as live_bundle
    from opentrace_core.live.scanners import ScanRun
    from opentrace_core.live.source import SourceRecord
    rec = cap["source"]["record"]
    source = SourceRecord(**{k: v for k, v in rec.items() if k not in ("skipped", "inputs")}, skipped=tuple(rec["skipped"]), inputs=tuple(rec["inputs"]))
    runs = [ScanRun(**{**r, "data": cap["artifacts"].get(r["kind"])}) for r in cap["runs"]]
    h = E4.LiveHarness()
    try:
        ticket = h.service.begin_analysis(h.sid, h.token, None)
        session = {"session_id": h.sid, "generation": ticket.generation}
        parsed = parse_repository_url(source.repository_url)
        resolved = SimpleNamespace(owner=parsed.owner, name=parsed.name, canonical_url=source.repository_url,
                                   requested={"kind": "commit", "text": source.commit_sha, "origin": "url_tree"}, commit_sha=source.commit_sha,
                                   resolved_at=cap["source"]["acquired_at"], basis="E3-C: commit fetched by full SHA and verified blob by blob",
                                   manual_corroboration=False, default_branch="main")
        identity = build_identity(parsed, None, resolved, {"profile_id": "opentrace.scan.default/1", "inventories": ["cbom", "sbom"], "scope": "repository_root"}, session)
        parts, records, names, raw = live_bundle.build(identity, source, runs, h.sid, ticket.generation)
        for aid, name in names.items():
            h.service.commit_artifact(ticket, name, raw[aid], "application/json", "original")
        analysis = SimpleNamespace(identity=identity, ticket=ticket, records=records, names=names, mode="live", gaps=None, collection=None, assessment=None,
                                   configuration=live_bundle.configuration_label(identity))
        analysis.read = lambda aid: h.service.read_artifact(h.sid, h.token, analysis.names[aid]).data
        analysis.context = AdapterContext(identity, session, analysis.configuration, lambda: dict(session))
        return live_discovery.run(analysis, ticket, h.service, bundle_parts=parts, records=records, sink=sink)
    finally:
        h.close()


def observed(sink: dict, a: dict) -> dict:
    """Did the collector observe this source item? A miss is a miss, including a file outside the collector's selection."""
    from opentrace_core.bombridge import discovery as D
    if not sink or sink.get("status") != "collected":
        return {"observed": None, "reason": "collection_unavailable"}
    path = anchor_path(a)
    if a["domain"] == "sbom":
        data = (sink.get("copies") or {}).get(path)
        if data is None:
            return {"observed": False, "reason": "file_not_collected"}
        hit = [d for d in D.requirement_declarations(data.decode("utf-8", "replace"))
               if d.get("normalized_name") == a["normalized_name"] and d["line"] == a["line_range"][0]]
        return {"observed": bool(hit), "reason": None if hit else "declaration_not_parsed", "locator": f"{path}:{a['line_range'][0]}"}
    sites = [s for s in (sink.get("record") or {}).get("crypto_call_sites") or [] if s.get("path") == path and s.get("operation") == "hash"
             and s.get("line") in (a.get("item_lines") or [a["call_line"]]) and B.alias(s.get("algorithm")) == B.alias(a["constructor"])]
    return {"observed": bool(sites), "reason": None if sites else "site_not_observed", "locator": f"{path}:{a['call_line']}",
            "call": sites[0].get("call") if sites else None}


def assessment_rows(gaps: dict, collection: dict, a: dict) -> dict:
    """The claim generated for one anchor (if any) and its finding, read from the bound assessment."""
    path = anchor_path(a)
    records = E4.discovered_records(gaps)
    family = "software" if a["domain"] == "sbom" else "cryptography"
    fam_state = E4.family_states(collection).get(family)
    claims, observations = [], []
    for r in records:
        if r["family"] != family:
            continue
        if a["domain"] == "sbom":
            req = (r["entity"] or {}).get("requirement") or {}
            if r["assertion"] and req.get("file") == path and req.get("normalized_name") == a["normalized_name"]:
                claims.append(r)
        else:
            c = r["candidate"] or {}
            site = re.fullmatch(re.escape(path) + r":(\d+)", str(c.get("evidence_location") or ""))
            if site and int(site.group(1)) in (a.get("item_lines") or [a["call_line"]]):
                alg = (r["assertion"] or {}).get("object", {}).get("algorithm") if r["assertion"] else None
                if r["assertion"] and B.alias(alg) == B.alias(a["constructor"]):
                    claims.append(r)
                elif not r["assertion"]:
                    observations.append(r)
    base = {"family_state": fam_state, "claims": len(claims), "assertion_id": None, "state": None, "category": None, "reason_codes": [],
            "evidence": [], "rationale": None}
    if claims:
        r = claims[0]
        f = r["finding"]
        return base | {"assessment": f["state"], "assertion_id": f["assertion_id"], "state": f["state"], "category": f.get("category"),
                       "reason_codes": f.get("reason_codes"), "rationale": f.get("rationale"), "rule_id": f.get("rule_id"),
                       "evidence": f.get("used_evidence"), "excluded_evidence": f.get("excluded_evidence"), "finding": f}
    if observations:
        c = observations[0]["candidate"]
        return base | {"assessment": "not_assessed", "reason_codes": [(c.get("detail") or {}).get("reason_code")]}
    if not gaps or gaps.get("status") != "compared" or (fam_state and fam_state[0] in ("failed", "not_run")):
        return base | {"assessment": "unavailable", "reason_codes": [(fam_state or (None, (gaps or {}).get("code")))[1]]}
    return base | {"assessment": "not_discovered"}


# ================================================================================================== stage: evaluate
AUDIT_FIELDS = ("reviewer", "review_date", "source_confirmed", "raw_lookup_confirmed", "binding_confirmed", "verdict_justified", "notes")


def evaluate(ctx: C.RunContext, ref: dict, captures: str, benchmarks: dict) -> list[dict]:
    out = lambda *p: ctx.path("e3c", *p)
    rows, lookups, collection_rows, claims, runs, manifest = [], [], [], [], [], {}
    for dataset, spec in DATASETS.items():
        cap = load_capture(captures, dataset)
        anchors = [a for a in ref["anchors"] if a["domain"] == spec["domain"]]
        tree = cap["tree"] or benchmarks.get(dataset)
        tree_basis = "commit_verified_export" if cap["tree"] else "local_benchmark_copy_unbound"
        checks = {c["anchor_id"]: c for c in check_anchors(ref, dataset, tree)} if tree and os.path.isdir(tree) else {}
        revision = cap["source"]["record"]["commit_sha"] if cap["tree"] else "unbound"
        sink, collect_error = None, None
        if checks:
            try:
                sink = collect(tree, spec["repository"], revision)
            except Exception as exc:
                collect_error = f"{type(exc).__name__}: {exc}"[:300]
        usable = cap["state"] in ("acquired", "acquired_empty")
        gaps = collection = None
        why = None
        if cap["binding"] != "verified":
            why = "source_binding_unverified"
        elif cap["state"] == "capture_invalid":
            why = "capture_invalid"
        elif not cap["runs"]:
            why = "no_scan_record"
        elif sink is None:
            why = "collection_unavailable"
        else:
            try:                                          # a failed scanner run goes through the live route as a failed run
                gaps, collection = run_pipeline(cap, sink)
                C.write_json(out("raw", dataset, "opentrace_collection.json"), collection, root=ctx.opentrace_root)
            except Exception as exc:
                why = f"pipeline_error: {type(exc).__name__}: {exc}"[:300]
        manifest[dataset] = {"capture_state": cap["state"], "capture_reason": cap["reason"], "binding": cap["binding"], "binding_reason": cap["binding_reason"],
                             "collector_tree": tree_basis, "collector_error": collect_error, "pipeline_not_run_reason": why,
                             "source": {k: v for k, v in (cap["source"] or {}).items() if k != "record"}
                             | {"record": {k: v for k, v in (cap["source"] or {}).get("record", {}).items() if k != "inputs"}},
                             "worker": (cap.get("capture") or {}).get("worker")}
        runs += [{"dataset": dataset, "scored": r["kind"] == spec["kind"], **r} for r in cap["runs"]]
        for kind, data in cap["artifacts"].items():
            with open(out("raw", dataset, f"{kind}.cdx.json"), "wb") as fh:
                fh.write(data)
        for a in anchors:
            check = checks.get(a["anchor_id"], {"verified": False})
            if not usable:
                look = (R.sbom_lookup(None, a["name"], anchor_path(a)) if spec["domain"] == "sbom"
                        else R.cbom_lookup(None, a["constructor"], anchor_path(a), a["item_lines"]))
                look["reason"] = f"{cap['state']}: {cap['reason']}"
            elif not check["verified"]:
                look = {"status": "inventory_unavailable", "reason": "anchor not verified against the scanned source", "records": []}
            elif spec["domain"] == "sbom":
                look = R.sbom_lookup(cap["document"], a["name"], anchor_path(a))
            else:
                look = R.cbom_lookup(cap["document"], a["constructor"], anchor_path(a), a["item_lines"])
            seen = observed(sink, a) if check["verified"] else {"observed": None, "reason": "anchor_unverified_in_collected_tree"}
            if why:
                res = {"assessment": "unavailable", "claims": None, "reason_codes": [why], "state": None, "category": None, "assertion_id": None, "evidence": []}
            else:
                res = assessment_rows(gaps, collection, a)
            base = {"anchor_id": a["anchor_id"], "dataset": dataset, "domain": a["domain"], "path": anchor_path(a),
                    "line": (a.get("line_range") or a.get("lines"))[0], "expected": a.get("normalized_name") or a.get("constructor"),
                    "source_file_sha256": a["file_sha256"], "anchor_verified": check["verified"]}
            lookups.append(base | {"capture_state": cap["state"], **look})
            collection_rows.append(base | {"collector_tree": tree_basis, **seen})
            claims.append(base | res)
            rows.append(base | {"capture_state": cap["state"], "binding": cap["binding"], "raw_status": look["status"], "raw_reason": look["reason"],
                                "raw_algorithm_level": look.get("algorithm_level"), "raw_name_present": look.get("name_present"),
                                "collector_observed": seen["observed"], "collector_reason": seen.get("reason"),
                                "claim_generated": None if res["claims"] is None else res["claims"] > 0, "duplicate_claims": max(0, (res["claims"] or 0) - 1),
                                "assessment": res["assessment"], "category": res.get("category"), "reason_codes": res.get("reason_codes"),
                                "assertion_id": res.get("assertion_id"), "independent_review": "not_reviewed" if res.get("state") else "not_applicable"})
    C.write_json(out("reference_selection.json"), ref, root=ctx.opentrace_root)
    C.write_csv(out("excluded_reference_items.csv"), ref["excluded"])
    C.write_json(out("acquisition_manifest.json"), manifest, root=ctx.opentrace_root)
    C.write_jsonl(out("scanner_runs.jsonl"), runs, root=ctx.opentrace_root)
    C.write_csv(out("raw_inventory_lookup.csv"), lookups)
    C.write_csv(out("source_collection.csv"), collection_rows)
    C.write_jsonl(out("claim_assessments.jsonl"), claims, root=ctx.opentrace_root)
    C.write_csv(out("per_item_comparison.csv"), rows)
    C.write_csv(out("manual_audit.csv"), [{k: r[k] for k in ("anchor_id", "path", "line", "raw_status", "assessment", "reason_codes")}
                                          | {f: "" for f in AUDIT_FIELDS} for r in rows])
    summary = summarise(rows)
    C.write_csv(out("domain_summary.csv"), summary)
    with open(out("paper_table_e3c.md"), "w", encoding="utf-8") as fh:
        fh.write(paper_table(summary))
    with open(out("limitations.md"), "w", encoding="utf-8") as fh:
        fh.write(LIMITATIONS)
    return rows


VERDICTS = ("supported", "contradicted", "conflicting_evidence", "unverifiable", "not_assessed", "not_discovered", "unavailable")


def summarise(rows: list[dict]) -> list[dict]:
    """Per-domain counts over all frozen items. ``None`` (never 0) when the track did not produce comparable data."""
    out = []
    for dataset, spec in DATASETS.items():
        rs = [r for r in rows if r["dataset"] == dataset]
        raw_ok = bool(rs) and all(r["raw_status"] != "inventory_unavailable" for r in rs)
        col_ok = bool(rs) and all(r["collector_observed"] is not None for r in rs)
        run_ok = bool(rs) and all(r["claim_generated"] is not None for r in rs)
        count = lambda key, val: sum(r[key] == val for r in rs)
        assessed = [r for r in rs if r["assessment"] in ("supported", "contradicted", "conflicting_evidence", "unverifiable")]
        out.append({"dataset": dataset, "scanner": spec["scanner"], "N": len(rs), "capture_state": rs[0]["capture_state"] if rs else None,
                    "binding": rs[0]["binding"] if rs else None,
                    "raw_unique_match": count("raw_status", "unique_match") if raw_ok else None,
                    "raw_absent": count("raw_status", "absent") if raw_ok else None,
                    "raw_ambiguous": count("raw_status", "ambiguous") if raw_ok else None,
                    "raw_insufficient": count("raw_status", "insufficient_location_or_identity") if raw_ok else None,
                    "raw_parse_incomplete": count("raw_status", "parse_incomplete") if raw_ok else None,
                    "raw_algorithm_level_only": sum(bool(r["raw_algorithm_level"]) and r["raw_status"] != "unique_match" for r in rs) if raw_ok and spec["domain"] == "cbom" else None,
                    "collector_observed": count("collector_observed", True) if col_ok else None,
                    "claims_generated": count("claim_generated", True) if run_ok else None,
                    "additional_source_evidence": sum(r["collector_observed"] is True and r["raw_status"] != "unique_match" for r in rs) if raw_ok and col_ok else None,
                    **{f"verdict_{v}": count("assessment", v) for v in VERDICTS},
                    "assessed": len(assessed), "assessed_independently_reviewed": 0, "independently_justified": None})
    return out


def paper_table(summary: list[dict]) -> str:
    by = {s["dataset"]: s for s in summary}
    cell = lambda s, k: "N/A" if s[k] is None else f"{s[k]}/{s['N']}"
    rows = [("Eligible reference source items", lambda s: str(s["N"])),
            ("Capture state / source binding", lambda s: f"{s['capture_state']} / {s['binding']}"),
            ("Items represented by raw BOM (strict unique match)", lambda s: cell(s, "raw_unique_match")),
            ("Items observed by OpenTrace collector", lambda s: cell(s, "collector_observed")),
            ("Claims generated / eligible", lambda s: cell(s, "claims_generated")),
            ("Supported / contradicted / conflicting / unverifiable / not assessed / not discovered / unavailable",
             lambda s: " / ".join(str(s["verdict_" + v]) for v in VERDICTS)),
            ("Independently justified / assessed", lambda s: f"not reviewed / {s['assessed']}")]
    md = "| Measurement | DeepBits / Syft | BF-CBOM / cdxgen |\n|---|---|---|\n"
    return md + "".join(f"| {label} | {f(by['deepbits'])} | {f(by['bf_cbom'])} |\n" for label, f in rows)


LIMITATIONS = """# E3-C limitations

* Eleven frozen items (7 requirement declarations, 4 hashlib call sites) from two benchmarks; no recall, precision or completeness claim.
* The reference shows that a declaration or call exists in source, not that anything is installed, resolved, executed or secure.
* SBOM claim: normalized PyPI name representation. CBOM claim: a hash operation and its source occurrence.
* A missing record is a representation difference or unresolved correspondence, not a confirmed scanner defect.
* An empty CBOM is a valid observation, not evidence that the source contains no cryptography. A failed scan is not an empty inventory.
* No verdict has been independently reviewed until manual_audit.csv is completed by a person.
* BF-CBOM is GPL-3.0: the captured source export and excerpts stay local and are not redistributed.
"""


# ================================================================================================== CLI
def plan(ref: dict, benchmarks: dict, zips: str, captures: str | None, spool_in: str | None, spool_out: str | None) -> dict:
    out = {"selection_sha256": ref["selection_sha256"], "anchors": {d: sum(a["domain"] == d for a in ref["anchors"]) for d in ("sbom", "cbom")},
           "excluded": {d: sum(a["domain"] == d for a in ref["excluded"]) for d in ("sbom", "cbom")}, "datasets": {}}
    for dataset, spec in DATASETS.items():
        d = out["datasets"][dataset] = {"scanner": spec["scanner"]}
        zp = os.path.join(zips, spec["zip"])
        if os.path.isfile(zp):
            ident = zip_identity(zp)
            d["archive_sha256_matches"] = ident["archive_sha256"] == spec["zip_sha256"]
            d["commit_claimed_by_archive_unverified"] = ident["commit_claimed_by_archive"]
        else:
            d["archive"] = "missing"
        tree = benchmarks.get(dataset)
        if tree and os.path.isdir(tree):
            checks = check_anchors(ref, dataset, tree)
            d["anchors_verified_in_local_copy"] = f"{sum(c['verified'] for c in checks)}/{spec['anchors']}"
        else:
            d["anchors_verified_in_local_copy"] = "local benchmark missing"
        if captures:
            cap = load_capture(captures, dataset)
            d.update(capture_state=cap["state"], capture_reason=cap["reason"], binding=cap["binding"])
        else:
            d.update(capture_state="capture_missing", binding="unbound")
    if spool_in and spool_out:
        from opentrace_core.live import worker_client as W
        status, why = W.WorkerClient(spool_in, spool_out).status()
        out["worker"] = {"ready": status is not None, "reason": why or None, "tools": (status or {}).get("tools")}
    else:
        out["worker"] = {"ready": None, "reason": "no spool directories given; not checked"}
    return out


def main(argv=None) -> int:
    root = C.default_opentrace_root()
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--stage", required=True, choices=("plan", "source", "acquire", "evaluate"))
    ap.add_argument("--frozen", default=os.path.join(root, "evaluation_data", "frozen", "e2_selection"))
    ap.add_argument("--deepbits", default=os.path.join(root, "evaluation_data", "external", "deepbits"))
    ap.add_argument("--bf-cbom", default=os.path.join(root, "evaluation_data", "external", "bf_cbom"))
    ap.add_argument("--archives", default=os.path.join(root, "..", "..", "inputs", "Evaluation_Experiments"))
    ap.add_argument("--captures", help="capture directory (written by source/acquire, read by evaluate)")
    ap.add_argument("--dataset", choices=tuple(DATASETS), action="append")
    ap.add_argument("--git-remote", action="append", default=[], metavar="DATASET=PATH", help="local clone to fetch from instead of GitHub")
    ap.add_argument("--allow-network", action="store_true")
    ap.add_argument("--allow-scans", action="store_true")
    ap.add_argument("--spool-in")
    ap.add_argument("--spool-out")
    ap.add_argument("--worker-image-id")
    ap.add_argument("--scan-seconds", type=int, default=180)
    ap.add_argument("--output-root")
    ap.add_argument("--run-id")
    args = ap.parse_args(argv)
    C.bootstrap_paths(root)
    captures = os.path.abspath(args.captures) if args.captures else None
    benchmarks = {"deepbits": os.path.abspath(args.deepbits), "bf_cbom": os.path.abspath(args.bf_cbom)}
    zips = os.path.abspath(args.archives)
    datasets = args.dataset or list(DATASETS)
    try:
        ref = reference_selection(os.path.abspath(args.frozen))
        if args.stage == "plan":
            print(json.dumps(plan(ref, benchmarks, zips, captures, args.spool_in, args.spool_out), indent=2))
            return 0
        if not captures:
            ap.error("--captures is required")
        if args.stage in ("source", "acquire"):
            if args.stage == "acquire" and not (args.allow_scans and args.spool_in and args.spool_out):
                ap.error("acquire needs --allow-scans, --spool-in and --spool-out")
            remotes = dict(x.split("=", 1) for x in args.git_remote)
            code = 0
            for d in datasets:
                try:
                    if args.stage == "source":
                        doc = stage_source(captures, ref, zips, d, remotes.get(d), args.allow_network)
                        print(json.dumps({"dataset": d, "commit": doc["record"]["commit_sha"], "files": doc["record"]["file_count"],
                                          "identical_to_archive": doc["archive_comparison"]["identical"],
                                          "anchors_verified": sum(c["verified"] for c in doc["anchor_checks"])}))
                    else:
                        doc = stage_acquire(captures, d, os.path.abspath(args.spool_in), os.path.abspath(args.spool_out), args.worker_image_id, args.scan_seconds)
                        print(json.dumps({"dataset": d, "runs": [{k: r.get(k) for k in ("scanner", "outcome", "reason", "version", "record_count")} for r in doc["runs"]]}))
                except (C.NotRunError, C.HarnessError, OSError) as exc:     # one dataset's failure does not stop the other
                    print(f"{d}: not completed: {exc}", file=sys.stderr)
                    code = 1
            return code
        if not (args.output_root and args.run_id):
            ap.error("evaluate needs --output-root and --run-id")
        ctx = C.RunContext({}, output_root=os.path.abspath(args.output_root), run_id=args.run_id, opentrace_root=root)
        guard = {"frozen_selection": os.path.abspath(args.frozen), **benchmarks, "captures": captures}
        with C.immutability_guard(guard, ctx, "e3c_inputs"):
            rows = evaluate(ctx, ref, captures, benchmarks)
        complete = all(r["raw_status"] != "inventory_unavailable" and r["assessment"] != "unavailable" for r in rows)
        ctx.status("E3-C", "completed" if complete else "partial", None if complete else "see acquisition_manifest.json")
        print(json.dumps({"run": ctx.out, "summary": summarise(rows)}, indent=2))
        return 0 if complete else 1
    except (C.NotRunError, C.HarnessError, OSError, zipfile.BadZipFile) as exc:
        print(f"BLOCKED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
