#!/usr/bin/env python3
"""Reconstruct the exported-file listing of the saved Frigate scan and verify it against the capture's recorded values.

    PYTHONPATH=src/core .venv/bin/python tools/demo_replay/reconstruct_source_inputs.py FIXTURE_DIR OUT_JSON

Makes ONE network request sequence: a bare ``git fetch --depth 1`` of the full commit SHA recorded in the fixture, by the unchanged
``opentrace_core.live.source.acquire`` (same git hardening, same export, same SHA-256 per file, same listing digest as the original scan).
It then compares the result with scan-record.json (tree_sha, listing_sha256, file_count, byte_count, skipped entries). Only when EVERY value
matches is OUT_JSON written; otherwise the discrepancy is printed, nothing is written and the exit status is 1. The workspace is deleted.
"""
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone

from opentrace_core.live import source as live_source


def main(argv):
    if len(argv) != 3:
        raise SystemExit(__doc__)
    fixture, out = os.path.abspath(argv[1]), os.path.abspath(argv[2])
    with open(os.path.join(fixture, "scan-record.json"), encoding="utf-8") as handle:
        record = json.load(handle)
    want = record["source"]
    url, sha = want["repository_url"], want["commit_sha"]
    work = tempfile.mkdtemp(prefix="ot-reconstruct-")
    os.chmod(work, 0o700)
    try:
        started = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        got = live_source.acquire(url, sha, work, canonical_url=url)
        mismatches = []
        for key in ("commit_sha", "tree_sha", "listing_sha256", "file_count", "byte_count", "verified"):
            if getattr(got, key) != want[key]:
                mismatches.append((key, want[key], getattr(got, key)))
        if list(got.skipped) != list(want["skipped"]):
            mismatches.append(("skipped", want["skipped"], list(got.skipped)))
        if len(got.inputs) != want["file_count"]:
            mismatches.append(("len(inputs)", want["file_count"], len(got.inputs)))
        if mismatches:
            for item in mismatches:
                print("MISMATCH %s: recorded=%r fetched=%r" % item)
            print("validation FAILED; nothing written")
            return 1
        doc = {"schema": "opentrace.demo_replay.source_inputs/1", "repository": url, "commit_sha": sha, "tree_sha": got.tree_sha,
               "listing_sha256": got.listing_sha256, "file_count": got.file_count, "byte_count": got.byte_count,
               "inputs": [{"path": i["path"], "sha256": i["sha256"]} for i in got.inputs],
               "provenance": {"method": "opentrace_core.live.source.acquire (unchanged): bare git fetch --depth 1 of the full SHA, every blob re-hashed "
                                         "to its git object id, SHA-256 per file, listing digest over sorted 'path<TAB>blob-sha1' lines",
                              "fetched_at": started, "git_version": got.git_version, "recorded_git_version": want.get("git_version"),
                              "verified_against": {"tree_sha": want["tree_sha"], "listing_sha256": want["listing_sha256"],
                                                   "file_count": want["file_count"], "byte_count": want["byte_count"],
                                                   "skipped": want["skipped"]}}}
        with open(out, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.chmod(out, 0o600)
        print("VERIFIED tree_sha=%s listing_sha256=%s files=%d bytes=%d skipped=%d" % (got.tree_sha, got.listing_sha256, got.file_count, got.byte_count, len(got.skipped)))
        return 0
    except live_source.SourceError as exc:
        print("acquisition failed: %s; nothing written" % exc)
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
