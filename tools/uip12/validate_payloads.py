#!/usr/bin/env python3
"""UIP-12 validation: validate saved v1 payloads against the frozen Workbench schemas (offline, read-only). Usage: validate_payloads.py <dir> <out.json>"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../src/core"))
from opentrace_core.app import view_contracts
d, out = sys.argv[1], sys.argv[2]; res = []
for f, kind in (("payload_bom_candidates.json", "bom_candidates"), ("payload_bom_graph.json", "bom_graph"), ("payload_bom_related.json", "bom_related_checks")):
    p = os.path.join(d, f)
    if not os.path.exists(p):
        res.append({"file": f, "ok": False, "detail": "missing"}); continue
    try:
        view_contracts.validate_payload(kind, json.load(open(p))); res.append({"file": f, "kind": kind, "ok": True})
    except Exception as exc:
        res.append({"file": f, "kind": kind, "ok": False, "detail": repr(exc)[:300]})
json.dump(res, open(out, "w"), indent=1); print(json.dumps(res)); sys.exit(0 if all(r["ok"] for r in res) else 1)
