#!/usr/bin/env python3
"""UIP-10 validation driver (test harness; stdlib only). Drives the isolated Compose stack over loopback HTTP and the ``docker`` CLI of the OWNED
project only. It never rebuilds expected outputs: the legacy comparison reads the committed snapshots and fails on any difference.

  demo   --port P --out DIR        captured-demo legacy routes vs evidence/uip/fixtures/legacy-view-snapshots; End session
  inspect --port P --out DIR       evidence for the already submitted scan; submits nothing
  end    --port P --out DIR        End session for the cookie saved by scan
  scan   --port P --out DIR        verify the pinned repository metadata, then submit EXACTLY ONE live scan (no retry), record evidence,
                                   read the live routes, validate them against the frozen contracts, End session
"""
import argparse
import hashlib
import http.client
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SNAP = os.path.join(ROOT, "evidence", "uip", "fixtures", "legacy-view-snapshots")
FIXED_SESSION = "00000000000000000000000000000001"
REPO_URL = "https://github.com/miguelgrinberg/microblog"
PIN = "a975ef64864354867c88e0ed3a17ba7d17dca752"
WB = "ot-uip10-val-workbench-1"
SCAN_CAP_SECONDS = 8 * 60


class Client:
    def __init__(self, port):
        self.port, self.cookie = port, None

    def req(self, method, path, body=None, timeout=60):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
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

    def json(self, method, path, body=None, timeout=60):
        resp, data = self.req(method, path, body, timeout)
        try:
            return resp.status, (json.loads(data) if data else None), data
        except ValueError:
            return resp.status, {"raw": data[:200].decode("utf-8", "replace")}, data

    def start(self):
        resp, _ = self.req("POST", "/api/session", {})
        self.cookie = resp.getheader("Set-Cookie").split(";")[0]


def sh(*argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=60)


def jload(path):
    with open(path, encoding="utf-8") as h:
        return json.load(h)


def save(out, name, obj):
    with open(os.path.join(out, name), "w", encoding="utf-8") as h:
        json.dump(obj, h, indent=1, sort_keys=True)
        h.write("\n")


def end_session(client):
    status, ended, _ = client.json("POST", "/api/session/end", {})
    after, _, _ = client.json("GET", "/api/artifacts")
    left = sorted(sh("docker", "exec", WB, "ls", "-A", "/var/opentrace/sessions").stdout.split())
    return {"http": status, "state": (ended or {}).get("state"), "artifacts_http_after_end": after, "session_dirs_left": left}


def image_has_uip10():
    """Hash the UIP-10 modules INSIDE the owned container and compare with the repository bytes (not an exec on a retained image)."""
    out = {}
    for rel in ("src/core/opentrace_core/app/live_discovery.py", "src/core/opentrace_core/live/source_declarations.py", "src/ui/components/gaps.js"):
        cont = sh("docker", "exec", WB, "python", "-I", "-c", "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())", "/opt/opentrace/" + rel).stdout.strip()
        with open(os.path.join(ROOT, rel), "rb") as h:
            out[rel] = {"container": cont, "repository": hashlib.sha256(h.read()).hexdigest()}
        out[rel]["equal"] = out[rel]["container"] == out[rel]["repository"]
    return out


def cmd_demo(args):
    c = Client(args.port)
    c.start()
    status, body, _ = c.json("POST", "/api/analysis/demo", {}, timeout=300)
    res = {"demo_http": status, "demo_ok": bool(body and body.get("ok")), "uip10_in_image": image_has_uip10(), "routes": {}}
    _, _, probe = c.json("GET", "/api/view/gaps?offset=0")
    sids = set(re.findall(r'"session_id": ?"([0-9a-f]{32})"', probe.decode("utf-8")))
    assert len(sids) == 1, sids
    real = sids.pop()
    res["session_id_is_dir_name"] = real
    first = jload(os.path.join(SNAP, "gaps-offset-0.json"))["items"][0]["candidate_id"]
    routes = {"contexts": "/api/view/contexts", "dependencies-per-side-6": "/api/view/dependencies?per_side=6", "dependencies-per-side-1": "/api/view/dependencies?per_side=1",
              "crypto": "/api/view/crypto", "ai": "/api/view/ai", "bom": "/api/view/bom", "gaps-offset-0": "/api/view/gaps?offset=0",
              "gap-first": "/api/view/gap?id=" + first, "dependencies-network": "/api/view/dependencies/network"}
    for name, path in sorted(routes.items()):
        st, _, raw = c.json("GET", path)
        got = json.loads(raw.decode("utf-8").replace(real, FIXED_SESSION)) if st == 200 else None
        want = jload(os.path.join(SNAP, name + ".json"))
        res["routes"][name] = {"path": path, "http": st, "equal_to_recorded_snapshot": got == want}
    # captured demo is not a live analysis: it must carry no collection object and the BOM candidates must keep today's inference
    st, cand, _ = c.json("GET", "/api/workbench/v1/bom-candidates?schema_version=1&generation=%d" % body["generation"])
    res["demo_bom_candidates"] = {"http": st, "mode": (cand or {}).get("mode"), "capabilities": (cand or {}).get("capabilities"),
                                  "has_collection": "collection" in json.dumps(cand or {})}
    res["end_session"] = end_session(c)
    res["own_session_dir_removed"] = real not in res["end_session"]["session_dirs_left"]
    res["all_equal"] = all(r["equal_to_recorded_snapshot"] for r in res["routes"].values())
    save(args.out, "v1_demo.json", res)
    print(json.dumps({"all_equal": res["all_equal"], "uip10_in_image": all(v["equal"] for v in res["uip10_in_image"].values()), "end": res["end_session"]["state"]}))
    return 0 if res["all_equal"] and res["demo_ok"] else 1


def github(path):
    r = sh("gh", "api", path)
    return json.loads(r.stdout) if r.returncode == 0 else None


def cmd_scan(args):
    meta = github("repos/miguelgrinberg/microblog")
    commit = github("repos/miguelgrinberg/microblog/commits/" + PIN)
    branch = github("repos/miguelgrinberg/microblog/branches/main")
    tree = github("repos/miguelgrinberg/microblog/git/trees/%s?recursive=1" % PIN)
    decl = sorted(t["path"] for t in (tree or {}).get("tree", []) if t["type"] == "blob" and re.search(r"requirements|package\.json|pyproject|setup\.py|setup\.cfg|Pipfile|poetry|go\.mod", t["path"]))
    pre = {"public": bool(meta) and not meta.get("private"), "license": ((meta or {}).get("license") or {}).get("spdx_id"), "archived": (meta or {}).get("archived"),
           "size_kb": (meta or {}).get("size"), "commit_sha": (commit or {}).get("sha"), "main_head": ((branch or {}).get("commit") or {}).get("sha"),
           "blob_count": len([t for t in (tree or {}).get("tree", []) if t["type"] == "blob"]), "declaration_files": decl}
    pre["ok"] = bool(pre["public"] and pre["commit_sha"] == PIN and pre["main_head"] == PIN and pre["license"] == "MIT" and not pre["archived"]
                     and pre["size_kb"] == 83 and pre["blob_count"] == 73 and decl == ["requirements.txt"])
    save(args.out, "v3_preflight.json", pre)
    if not pre["ok"]:
        print("PRECHECK DIFFERS - V3 NOT SUBMITTED:", json.dumps(pre))
        return 3
    c = Client(args.port)
    c.start()
    with open(os.path.join(args.out, "session.cookie"), "w") as h:     # scratch only (never committed): lets the browser reuse the open live session, then `end`
        h.write(c.cookie)
    save(args.out, "v3_attempt.json", {"submitted_at": time.strftime("%FT%TZ", time.gmtime()), "url": REPO_URL, "pin": PIN})   # written BEFORE the one submission
    t0 = time.monotonic()
    status, preview, _ = c.json("POST", "/api/intake/preview", {"url": REPO_URL + "/tree/" + PIN, "live": True}, timeout=120)
    save(args.out, "v3_preview.json", {"http": status, "body": preview})
    if status != 200 or not (preview or {}).get("ok") or (preview or {}).get("commit") != PIN:
        print("PREVIEW DID NOT RESOLVE THE PIN - NOT SUBMITTED")
        return 4
    status, body, raw = c.json("POST", "/api/analysis/live", {"url": REPO_URL + "/tree/" + PIN}, timeout=SCAN_CAP_SECONDS)
    elapsed = round(time.monotonic() - t0, 1)
    save(args.out, "v3_analysis_response.json", {"http": status, "seconds": elapsed, "body": body})
    return post(c, args, body, status, elapsed)


def post(c, args, body, status, elapsed):
    res = {"http": status, "seconds": elapsed, "ok": (body or {}).get("ok"), "code": (body or {}).get("code")}
    if (body or {}).get("ok"):
        res["resolved_commit"] = body["identity"]["commit"]
        res["source_commit_sha"] = body["summary"]["live"]["source"]["commit_sha"]
        res["resolved_equals_pin"] = res["resolved_commit"] == PIN and res["source_commit_sha"] == PIN
        ls, listing, _ = c.json("GET", "/api/artifacts")
        arts = []
        for a in (listing or {}).get("artifacts", []):
            st, resp_raw = c.req("GET", "/api/artifacts/%s?disposition=attachment" % a["name"], timeout=120)
            arts.append({"name": a["name"], "kind": a["kind"], "bytes": len(resp_raw), "listed_sha256": a["sha256"], "downloaded_sha256": hashlib.sha256(resp_raw).hexdigest()})
            if a["name"] in ("source-declarations.json", "sbom.cdx.json") or a["name"].endswith(".cdx.json"):
                with open(os.path.join(args.out, "v3_artifact_" + a["name"].replace("/", "_")), "wb") as h:
                    h.write(resp_raw)
        res["artifacts"] = arts
        routes, gen = {}, "schema_version=1&generation=%d" % body["generation"]
        for name, path in (("bom_candidates", "/api/workbench/v1/bom-candidates?" + gen),
                           ("bom_candidates_not_represented", "/api/workbench/v1/bom-candidates?filter_group=not_represented&" + gen),
                           ("bom_candidates_unknown", "/api/workbench/v1/bom-candidates?filter_group=unknown&" + gen),
                           ("bom_graph_full", "/api/workbench/v1/bom-graph?scope_kind=full_view&group=all&" + gen),
                           ("gaps_page", "/api/view/gaps?offset=0")):
            st, obj, rawr = c.json("GET", path, timeout=120)
            routes[name] = {"http": st}
            save(args.out, "v3_route_" + name + ".json", obj)
        res["routes"] = routes
        cands = jload(os.path.join(args.out, "v3_route_bom_candidates.json")) or {}
        first = (cands.get("items") or [None])[0]
        if first:
            st, graph, _ = c.json("GET", "/api/workbench/v1/bom-graph?scope_kind=focused_candidate&candidate_id=%s&%s" % (first["item_id"], gen), timeout=120)
            save(args.out, "v3_route_bom_graph_focused.json", graph)
            res["routes"]["bom_graph_focused"] = {"http": st}
            node = next((n["node_id"] for n in (graph or {}).get("nodes", []) if n.get("kind") == "entity"), None)
            if node:
                st, rel, _ = c.json("GET", "/api/workbench/v1/bom-related-checks?subject_kind=record&subject_id=%s&%s" % (node, gen), timeout=120)
                save(args.out, "v3_route_bom_related.json", rel)
                res["routes"]["bom_related_checks"] = {"http": st}
        save(args.out, "v3_analysis_summary_live.json", ((body or {}).get("summary") or {}).get("live"))
    save(args.out, "v3_result.json", res)
    print(json.dumps({k: res.get(k) for k in ("http", "seconds", "ok", "code", "resolved_equals_pin")}))
    return 0 if res.get("ok") else 1


def cmd_inspect(args):
    """Post-submission evidence for the ALREADY SUBMITTED scan (reads the saved response; submits nothing)."""
    c = Client(args.port)
    with open(os.path.join(args.out, "session.cookie")) as h:
        c.cookie = h.read().strip()
    saved = jload(os.path.join(args.out, "v3_analysis_response.json"))
    return post(c, args, saved["body"], saved["http"], saved["seconds"])


def cmd_extra(args):
    """More live-analysis route reads on the open session: legacy view routes, BOM related checks for a recorded entity and the first full-graph page."""
    c = Client(args.port)
    with open(os.path.join(args.out, "session.cookie")) as h:
        c.cookie = h.read().strip()
    saved = jload(os.path.join(args.out, "v3_analysis_response.json"))
    gen = "schema_version=1&generation=%d" % saved["body"]["generation"]
    res = {}
    for name, path in (("legacy_contexts", "/api/view/contexts"), ("legacy_dependencies", "/api/view/dependencies?per_side=6"), ("legacy_crypto", "/api/view/crypto"),
                       ("legacy_ai", "/api/view/ai"), ("legacy_bom", "/api/view/bom"), ("legacy_gaps", "/api/view/gaps?offset=0"),
                       ("wb_contexts", "/api/workbench/v1/contexts?" + gen), ("wb_crypto", "/api/workbench/v1/crypto-assets?" + gen),
                       ("wb_ai", "/api/workbench/v1/ai-assets?" + gen), ("wb_bom_family_software", "/api/workbench/v1/bom-candidates?family=software&" + gen),
                       ("wb_bom_graph_group_summary", "/api/workbench/v1/bom-graph?scope_kind=group_summary&group=all&" + gen)):
        st, obj, raw = c.json("GET", path, timeout=120)
        res[name] = {"http": st, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        if name in ("wb_crypto", "wb_ai", "wb_bom_family_software"):
            res[name]["capabilities"] = (obj or {}).get("capabilities")
    graph = jload(os.path.join(args.out, "v3_route_bom_graph_full.json"))
    node = next((n["node_id"] for n in graph.get("nodes", []) if n.get("kind") == "entity"), None)
    st, rel, raw = c.json("GET", "/api/workbench/v1/bom-related-checks?subject_kind=record&subject_id=%s&%s" % (node, gen), timeout=120)
    res["wb_related_checks"] = {"http": st, "subject": node, "resolution": (rel or {}).get("resolution"), "related_total": (rel or {}).get("related_total")}
    save(args.out, "v3_extra_routes.json", res)
    print(json.dumps({k: v["http"] for k, v in res.items()}))
    return 0


def cmd_end(args):
    c = Client(args.port)
    with open(os.path.join(args.out, "session.cookie")) as h:
        c.cookie = h.read().strip()
    res = end_session(c)
    save(args.out, "v3_end_session.json", res)
    print(json.dumps(res))
    return 0 if res["state"] == "deleted_verified" and not res["session_dirs_left"] else 1


def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=("demo", "scan", "inspect", "extra", "end"))
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args()
    os.makedirs(a.out, exist_ok=True)
    return {"demo": cmd_demo, "scan": cmd_scan, "inspect": cmd_inspect, "extra": cmd_extra, "end": cmd_end}[a.mode](a)


if __name__ == "__main__":
    sys.exit(main())
