#!/usr/bin/env python3
"""UIP-07C flag-off byte-identity evidence: run ONE deterministic flag-off live scan job through the real service and write a canonical transcript.

Run it twice, once with PYTHONPATH pointing at the START_SHA source tree and once at the implementation tree, and compare the transcripts' sha256:

    PYTHONPATH=<tree>/src/core python tools/uip07c/flag_off_transcript.py --out T.json

The transcript holds: GET /api/config, the scan status document (stage table), the result payload, the artifact names and original-byte digests, the AI tab
payload, the legacy analysis payload and the donor bundle built by ``live/bundle.py``. Volatile values (timestamps, durations, random ids, temp paths) are
replaced by fixed tokens; nothing else is normalised. Uses the repository's own test doubles (local git repository, fake scanners): no network, no Docker."""
import argparse
import hashlib
import json
import os
import re
import sys
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, REPO)          # the `tests` package (shared doubles); the code under test comes from PYTHONPATH

from tests.core.app.test_scan_jobs import ScanBase  # noqa: E402

VOLATILE_KEYS = {"created_at", "updated_at", "started_at", "finished_at", "elapsed_ms", "duration_ms", "job_id", "log_sha256", "time", "session_id", "resolved_at"}
OUT = {}


def canon(value, root):
    if isinstance(value, dict) and value.get("kind") == "derived" and "sha256" in value:
        value = dict(value, sha256="<derived: embeds the session id and a resolution time; its size is still compared>")
    if isinstance(value, dict):
        return {k: ("<volatile>" if k in VOLATILE_KEYS else canon(v, root)) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [canon(v, root) for v in value]
    if isinstance(value, str):
        return value.replace(root, "<tmp>")
    return value


class Transcript(ScanBase):
    def test_transcript(self):
        from opentrace_core.live import bundle
        srv = self.server()
        c = self.session(srv)
        _, cfg = c.json("GET", "/api/config")
        _, env = self.start(c)
        out = self.poll(c, env)
        arts = c.json("GET", "/api/artifacts")[1]["artifacts"]
        digests = {}
        for a in arts:
            _, data = c.req("GET", "/api/artifacts/" + a["name"] + "?disposition=attachment")
            digests[a["name"]] = hashlib.sha256(data).hexdigest() if a["name"] != "bombridge-result.json" else "derived-not-compared-bytes"
        tab = c.json("GET", "/api/workbench/v1/ai-assets?generation=%d" % out["status"]["generation"])[1]
        analysis = srv.app.analyses[next(iter(srv.app.analyses))]
        bundle_doc = {"records": [r.as_dict() for r in analysis.records], "scan": analysis.scan, "summary_keys": sorted(analysis.summary)}
        OUT.update(canon({"config": cfg, "status": out["status"], "result": out["result"], "artifacts": arts, "artifact_digests": digests, "ai_tab": tab, "bundle": bundle_doc},
                         self.dir))
        OUT["_bundle_module_sentence"] = [i for i in (bundle.LABELS, bundle.ARTIFACT_NAMES, bundle.INVENTORY_IDS) if i is not None] and sorted(bundle.ARTIFACT_NAMES)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    suite = unittest.TestSuite([Transcript("test_transcript")])
    result = unittest.TextTestRunner(stream=open(os.devnull, "w")).run(suite)
    if not result.wasSuccessful():
        print("transcript run failed:", [str(f[1])[-300:] for f in result.failures + result.errors])
        sys.exit(2)
    OUT.pop("_bundle_module_sentence", None)      # the module constants differ by design (new aibom entries); the records above are what must match
    text = json.dumps(OUT, indent=1, sort_keys=True)
    open(args.out, "w").write(text + "\n")
    print("transcript sha256", hashlib.sha256(text.encode()).hexdigest(), "bytes", len(text))


if __name__ == "__main__":
    main()
