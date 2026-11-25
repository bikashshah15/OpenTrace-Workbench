#!/usr/bin/env python3
"""Build the replay fixture for the saved Frigate 3bca9b86 live capture.

    python3 -I tools/demo_replay/build_frigate_3bca9b8_fixture.py CAPTURE_DIR [OUT_DIR [SOURCE_INPUTS_JSON]]

SOURCE_INPUTS_JSON is the output of reconstruct_source_inputs.py (verified against tree_sha and listing_sha256); without it the replay's
acquisition manifests fall back to the files the source-declarations record cites.

CAPTURE_DIR is the private capture directory (artifacts/, scan-status.json, addendum/). Nothing is read from the network.
The output directory defaults to src/core/opentrace_core/app/demo/frigate-3bca9b8 and receives:

* the six original artifacts, byte for byte (their SHA-256 is checked against the capture's own index AND the hashes the scan
  recorded in scan-status.json);
* ``scan-record.json``  - identity, source record, scanner runs and inventory summary, copied from the recorded scan status;
* ``advisory-report.json`` - the recorded advisory join report: every row, family and OSV record body, assembled from the
  session's advisory views plus the SBOM (the OSV log keeps digests only, so bodies come from that session's own projection);
* ``MANIFEST.json`` - hashes, provenance and the evidence map (which file backs which displayed evidence) and known limits.
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "src", "core"))
from opentrace_core.advisory import join as advisory_join  # noqa: E402

REVISION = "3bca9b8676846d175f6b9f53f5818cbb9d36ec3e"
JOB = "job:79086c0277b8dff8a5d09e65"
ORIGINALS = ("syft-sbom.cdx.json", "cdxgen-cbom.cdx.json", "cisco-aibom.cdx.json", "source-declarations.json",
             "advisory-lookup.json", "bombridge-result.json")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    with open(path, "rb") as handle:
        data = handle.read()
    return data, json.loads(data.decode("utf-8"))


def dump(path, doc):
    data = (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    with open(path, "wb") as handle:
        handle.write(data)
    return data


def main(argv):
    if not 2 <= len(argv) <= 4:
        raise SystemExit(__doc__)
    cap = os.path.abspath(argv[1])
    out = os.path.abspath(argv[2]) if len(argv) == 3 else os.path.join(REPO, "src", "core", "opentrace_core", "app", "demo", "frigate-3bca9b8")
    os.makedirs(out, exist_ok=True)

    status_bytes, status = load(os.path.join(cap, "scan-status.json"))
    st, result = status["status"], status["result"]
    assert st["job"]["job_id"] == JOB and st["binding"]["commit_sha"] == REVISION, "capture is not the expected job/revision"
    index = json.load(open(os.path.join(cap, "artifacts-index.json")))
    declared = {a["name"]: a["sha256"] for a in index["artifacts"]}
    recorded = {o["artifact_id"]: o["sha256"] for stage in st["stages"] for o in stage["outputs"]}
    recorded_by_name = {"syft-sbom.cdx.json": recorded["art:inv:syft-source-dir"], "cdxgen-cbom.cdx.json": recorded["art:inv:cdxgen-cbom"],
                        "cisco-aibom.cdx.json": recorded["art:inv:cisco-aibom"]}

    files = {}
    raw = {}
    for name in ORIGINALS:
        data, _ = load(os.path.join(cap, "artifacts", name))
        digest = sha(data)
        assert declared[name] == digest, "artifact index hash mismatch: " + name
        if name in recorded_by_name:
            assert recorded_by_name[name] == digest, "scan-status recorded hash mismatch: " + name
        with open(os.path.join(out, name), "wb") as handle:
            handle.write(data)
        raw[name] = data
        files[name] = {"sha256": digest, "size": len(data), "origin": "original capture bytes" if name != "bombridge-result.json" else "original capture bytes (oracle only; recomputed by replay and compared)"}

    sbom = json.loads(raw["syft-sbom.cdx.json"].decode("utf-8"))
    live = result["summary"]["live"]
    def cited_files(node, found):
        """(path, sha256) of every exported file the source-declarations record cites; each pair is the collector's own observation."""
        if isinstance(node, dict):
            digest = node.get("file_sha256") or (node.get("sha256") if "bytes" in node else None)
            if node.get("path") and isinstance(digest, str) and len(digest) == 64:
                assert found.setdefault(node["path"], digest) == digest, "conflicting digests for " + node["path"]
            for value in node.values():
                cited_files(value, found)
        elif isinstance(node, list):
            for value in node:
                cited_files(value, found)
        return found
    decl = json.loads(raw["source-declarations.json"].decode("utf-8"))
    cited = cited_files(decl["record"], {})
    full = None
    if len(argv) == 4:
        with open(argv[3], "rb") as handle:
            full_bytes = handle.read()
        full = json.loads(full_bytes.decode("utf-8"))
        src = live["source"]
        for key in ("commit_sha", "tree_sha", "listing_sha256", "file_count", "byte_count"):
            assert full[key] == src[key], "source inputs disagree with the capture: " + key
        assert len(full["inputs"]) == src["file_count"] and full["provenance"]["verified_against"]["listing_sha256"] == src["listing_sha256"]
        listed = {i["path"]: i["sha256"] for i in full["inputs"]}
        assert len(listed) == len(full["inputs"])
        for path, digest in cited.items():     # independent cross-check: every digest the collector recorded is the listed one
            assert listed.get(path) == digest, "cited file disagrees with the verified listing: " + path
        with open(os.path.join(out, "source-inputs.json"), "wb") as handle:
            handle.write(full_bytes)
        files["source-inputs.json"] = {"sha256": sha(full_bytes), "size": len(full_bytes),
                                       "origin": "reconstructed by reconstruct_source_inputs.py (one fetch of the full SHA) and verified against the capture's tree_sha, listing_sha256, file_count, byte_count and skipped entries"}
    scan_record = {"schema": "opentrace.demo_replay.scan_record/1", "job_id": JOB, "identity": result["identity"], "source": live["source"],
                   "runs": live["scan"], "isolation": live["isolation"], "advisory_state": live["advisory"], "checks": live["checks"],
                   "inventory_detail": result["summary"]["advisory_lookup"]["inventory_detail"], "source_checks": result["summary"].get("source_checks") or [],
                   "source_inputs": "full" if full else "cited_subset",
                   "source_inputs_cited": [{"path": p, "sha256": d} for p, d in sorted(cited.items())],
                   "stages": st["stages"], "analysis_digest": st["binding"]["analysis_digest"]}
    data = dump(os.path.join(out, "scan-record.json"), scan_record)
    files["scan-record.json"] = {"sha256": sha(data), "size": len(data), "origin": "scan-status.json result.summary.live + identity + stages (copied)"}

    # ---- recorded advisory report -------------------------------------------------------------------------------
    rows_doc = json.load(open(os.path.join(cap, "addendum", "advisory-lookup-all-rows.json")))
    evidence = json.load(open(os.path.join(cap, "addendum", "advisory-evidence-by-row.json")))
    famdoc = json.load(open(os.path.join(cap, "addendum", "advisory-families.json")))
    sbom_side = {r["id"]: r["sbom"] for r in advisory_join.build(sbom, None, None)["rows"]}
    row_families = {}
    for ev in evidence.values():
        for f in ev["families"]:
            row_families.setdefault(f["key"], f)
    records, families = {}, {}
    body_missing = []
    for key in sorted(row_families):
        fam = famdoc[key]
        if "raw" not in fam:   # lockfile-only group: the view source never exposed it, so no record bodies exist in the session projection
            body_missing.append(key)
            families[key] = {"key": key, "label": row_families[key]["label"], "severity": row_families[key]["severity"],
                             "summary": row_families[key]["summary"], "aliases": [row_families[key]["label"]], "ids": [],
                             "active": None, "withdrawn": row_families[key]["withdrawn"], "records_fetched": 0}
            continue
        recs = fam["raw"]
        for rec in recs:
            records[rec["id"]] = rec
        families[key] = {"key": key, "label": fam["label"], "severity": fam["severity"], "summary": fam["summary"], "aliases": fam["aliases"],
                         "ids": fam["ids"], "active": any(not r.get("withdrawn") for r in recs) if recs else None,
                         "withdrawn": row_families[key]["withdrawn"], "records_fetched": len(recs)}
    rows, notes = [], []
    for item in rows_doc["items"]:
        ev = evidence[item["id"]]
        sbom_rows = sbom_side.get(item["id"], [])
        if len(sbom_rows) != ev["sbom_records"]:
            notes.append("sbom list differs for " + item["id"])
        row = {"id": ev["id"], "ecosystem": ev["ecosystem"], "name": ev["name"], "version": ev["version"], "state": ev["state"], "reason": ev["reason"],
               "join": ev["join"], "query_key": ev["query_key"], "evidence": ev["evidence"], "sbom": sbom_rows, "inventory": ev["inventory"],
               "families": [families[f["key"]] for f in ev["families"]]}
        if ev["state"] == "match":
            row["withdrawn_only"] = bool(ev["withdrawn_only"])
        rows.append(row)
    truncated = [{"id": r["id"], "inventory_records_reported": evidence[r["id"]]["inventory_records"], "inventory_rows_kept": len(r["inventory"])}
                 for r in rows if evidence[r["id"]]["inventory_records"] != len(r["inventory"])]
    report = {"summary": rows_doc["summary"], "rows": rows, "families": families, "not_established": rows_doc["not_established"]}
    assert report["summary"]["rows"] == len(rows)
    for state, count in report["summary"]["states"].items():
        assert sum(1 for r in rows if r["state"] == state) == count, state
    assert not notes, notes
    assert len(body_missing) == report["summary"]["lockfile_only"]["advisory_groups"], body_missing
    advisory = {"schema": "opentrace.demo_replay.advisory_report/1", "queried_at": json.loads(raw["advisory-lookup.json"].decode("utf-8"))["source"]["queried_at"],
                "report": report, "records": records}
    data = dump(os.path.join(out, "advisory-report.json"), advisory)
    files["advisory-report.json"] = {"sha256": sha(data), "size": len(data),
                                     "origin": "assembled: rows/families/records from the capture session's advisory views (addendum/), SBOM lists re-derived from syft-sbom.cdx.json"}

    manifest = {
        "schema": "opentrace.demo_replay.manifest/1", "revision": REVISION, "repository": "https://github.com/blakeblackshear/frigate", "job_id": JOB,
        "analysis_digest": st["binding"]["analysis_digest"],
        "capture": {"status_sha256": sha(status_bytes), "note": "private capture directory is not part of this fixture; its scan-status.json hash is recorded here"},
        "files": files,
        "evidence_map": {
            "contexts / dependencies (Syft inventory)": "syft-sbom.cdx.json",
            "dependencies (OSV matches, coverage counts, reachability notice)": ["advisory-lookup.json (digest log, counts)", "advisory-report.json (rows, families, OSV record bodies)"],
            "cryptography (source-observed hashlib/TLS)": "source-declarations.json record.crypto_call_sites, record.crypto_source",
            "cryptography (CBOM, zero crypto assets)": "cdxgen-cbom.cdx.json",
            "ai models (Cisco AI-BOM, degraded coverage)": "cisco-aibom.cdx.json",
            "ai models (source-declared model URLs and runtimes)": "source-declarations.json record.model_references, record.ai_source",
            "bom connections / zero assessed checks": "bombridge-result.json (recomputed by replay; compared byte-for-byte)",
        },
        "limits": {
            "inventory_rows_capped_at_10": truncated,
            "advisory_report": "the OSV log stores digests only; record bodies and lockfile rows come from the capture session's own advisory views (inventory lists are capped at 10 per row by that view)",
            "worker_paths": "syft-sbom.cdx.json and cdxgen-cbom.cdx.json contain ephemeral worker paths of the form /spool/in/<job-token>/src/...; kept unmodified so the original hashes stay valid",
            "record_bodies": {"fetched_by_scan": report["summary"]["counts"]["records_fetched"], "present_in_fixture": len(records),
                              "families_without_bodies": body_missing,
                              "reason": "these families belong to lockfile-only rows, which the advisory view does not expose; only label/severity/summary/withdrawn survive"},
            "source_inputs": ("the full {}-file listing was reconstructed with the original export rules and verified against tree_sha and listing_sha256 (source-inputs.json)".format(live["source"]["file_count"]) if full else
                              "the original manifest listed all {} exported files; the capture keeps only listing_sha256 and the tree id, so the replay's acquisition manifests list just the files the source-declarations record cites ({} files, each a recorded observation)".format(live["source"]["file_count"], len(cited))),
            "not_replayed": "no scanner, OSV, GitHub or OpenAI call is made by the replay",
        },
    }
    mdata = dump(os.path.join(out, "MANIFEST.json"), manifest)
    print("fixture written to", out)
    for name, meta in sorted(files.items()):
        print("  {:<28} {:>9} bytes  {}".format(name, meta["size"], meta["sha256"][:16]))
    print("  MANIFEST.json                {:>9} bytes  {}".format(len(mdata), sha(mdata)[:16]))
    print("rows", len(rows), "families", len(families), "records", len(records), "capped rows", len(truncated))


if __name__ == "__main__":
    main(sys.argv)
