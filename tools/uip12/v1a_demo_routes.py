#!/usr/bin/env python3
"""UIP-12 validation V1a (test harness, read-only HTTP): the captured Frigate demo in the built Workbench container returns exactly the recorded legacy
snapshots and a frozen-schema-valid v1 candidate page. Standard library only plus the repo's own frozen validator on the host.
Usage: OPENTRACE_PORT=8770 PYTHONPATH=src/core python3 tools/uip12/v1a_demo_routes.py --out result.json
"""
import argparse, http.client, json, os, re, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SNAP = os.path.join(ROOT, "evidence/uip/fixtures/legacy-view-snapshots")
FIXED = "00000000000000000000000000000001"
ROUTES = {"contexts": "/api/view/contexts", "dependencies-per-side-6": "/api/view/dependencies?per_side=6", "dependencies-per-side-1": "/api/view/dependencies?per_side=1",
          "crypto": "/api/view/crypto", "ai": "/api/view/ai", "bom": "/api/view/bom", "gaps-offset-0": "/api/view/gaps?offset=0", "dependencies-network": "/api/view/dependencies/network"}


class C:
    def __init__(self, port):
        self.port, self.cookie = port, None

    def req(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
        h = {"Host": "127.0.0.1:%d" % self.port}
        if body is not None:
            h["Content-Type"] = "application/json"
        if self.cookie:
            h["Cookie"] = self.cookie
        conn.request(method, path, json.dumps(body) if body is not None else None, h)
        r = conn.getresponse(); data = r.read(); sc = r.getheader("Set-Cookie"); conn.close()
        if sc:
            self.cookie = sc.split(";")[0]
        return r.status, data


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True); a = ap.parse_args()
    port = int(os.environ.get("OPENTRACE_PORT", "8770")); c = C(port); res = {"checks": [], "synthetic": False}
    t0 = time.time()

    def check(i, ok, d=""):
        res["checks"].append({"id": i, "ok": bool(ok), "detail": str(d)[:300]}); print(("PASS " if ok else "FAIL ") + i, d if not ok else "")
    st, _ = c.req("POST", "/api/session", {}); check("session_started", st in (200, 201), st)
    st, raw = c.req("POST", "/api/analysis/demo", {}); body = json.loads(raw); check("demo_analysis_ok", st == 200 and body.get("ok"), st)
    texts = {}
    for name, path in ROUTES.items():
        st, raw = c.req("GET", path); texts[name] = raw.decode(); check("GET " + path, st == 200, st)
    m = re.search(r'"session_id":\s*"([0-9a-f]{32})"', texts["gaps-offset-0"])
    real = m.group(1) if m else None; check("session_id_found", real)
    first = json.loads(texts["gaps-offset-0"].replace(real, FIXED))["items"][0]["candidate_id"]
    st, raw = c.req("GET", "/api/view/gap?id=" + first); texts["gap-first"] = raw.decode(); check("GET /api/view/gap?id=<first>", st == 200, st)
    for name, text in sorted(texts.items()):
        live = json.loads(text.replace(real, FIXED))
        want = json.load(open(os.path.join(SNAP, name + ".json")))
        check("equals_recorded_snapshot:" + name, live == want, "differs" if live != want else "")
    gaps = json.loads(texts["gaps-offset-0"]); check("recorded_path_has_no_collection_object", "collection" not in json.dumps(body.get("summary", {}).get("gaps", {})) and "crypto" not in (gaps.get("status") or ""), "")
    st, raw = c.req("GET", "/api/workbench/v1/bom-candidates?schema_version=1&generation=%s" % body["generation"])
    check("GET bom-candidates (demo)", st == 200, st)
    try:
        sys.path.insert(0, os.path.join(ROOT, "src/core"))
        from opentrace_core.app import view_contracts
        view_contracts.validate_payload("bom_candidates", json.loads(raw)); check("bom_candidates_valid_against_frozen_schema", True)
    except Exception as exc:
        check("bom_candidates_valid_against_frozen_schema", False, repr(exc))
    st, raw = c.req("POST", "/api/session/end", {}); ended = json.loads(raw) if raw else {}
    check("demo_session_ended", st == 200 and ended.get("state") == "deleted_verified", ended.get("state"))
    res["seconds"] = round(time.time() - t0, 1); json.dump(res, open(a.out, "w"), indent=1)
    return 0 if all(x["ok"] for x in res["checks"]) else 1


if __name__ == "__main__":
    sys.exit(main())
