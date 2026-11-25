#!/usr/bin/env python3
"""Compare the whole BOM connections projection of a replay session with the live session it replays.

    python3 -I tools/demo_replay/bom_parity.py CAPTURE_DIR REPLAY_URL [LIVE_URL LIVE_COOKIE_JAR]

With the live arguments it first reads the live session (read-only GETs) and saves each response under CAPTURE_DIR/addendum/bom/;
without them it compares against the files saved there earlier. Covered: every page and filter of /api/workbench/v1/bom-candidates and
/api/view/gaps, every candidate's /api/view/gap detail, and the bom-graph projections (full view, group summaries, each focused candidate).
Only the session id may differ. Exit status 1 on any other difference.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_replay import curl, diff  # noqa: E402

SESSION = re.compile(r"session_id$|/binding/assessment/validation_digest$")   # session-bound seal; see verify_replay.py


def get(base, jar, path):
    raw = curl(base, jar, path)
    try:
        return json.loads(raw)
    except ValueError:
        return {"unparseable": hashlib.sha256(raw).hexdigest()}


def plan(fetch, gen):
    """Every request of the BOM connections tab; ``fetch(name, path)`` records and returns the parsed response."""
    g = "generation=%d" % gen
    first = fetch("gaps-0", "/api/view/gaps?%s&offset=0" % g)
    total = first["filtered_total"]
    ids = [i["candidate_id"] for i in first["items"]]
    for off in range(25, total, 25):
        ids += [i["candidate_id"] for i in fetch("gaps-%d" % off, "/api/view/gaps?%s&offset=%d" % (g, off))["items"]]
    for st in ("unverifiable", "unknown_coverage", "contradicted"):
        fetch("gaps-state-" + st, "/api/view/gaps?%s&state=%s" % (g, st))
    for off in range(0, total, 25):
        fetch("cand-%d" % off, "/api/workbench/v1/bom-candidates?%s&offset=%d" % (g, off))
    for q in ("family=ai_model", "family=cryptography", "family=software", "filter_group=unknown", "filter_group=not_represented", "state=unverifiable",
              "state=unknown_coverage", "category=unknown_coverage", "query=yolov6n", "query=md5"):
        fetch("cand-" + q, "/api/workbench/v1/bom-candidates?%s&%s" % (g, q))
    for cid in ids:
        fetch("gap-" + cid, "/api/view/gap?%s&id=%s" % (g, urllib.parse.quote(cid, safe="")))
    fetch("graph-full", "/api/workbench/v1/bom-graph?%s&scope_kind=full_view&offset=0" % g)
    for grp in ("software", "cryptography", "ai_model", "all"):
        fetch("graph-group-" + grp, "/api/workbench/v1/bom-graph?%s&scope_kind=group_summary&group=%s" % (g, grp))
    for cid in ids:
        if "missing_component" not in cid:       # focused graphs for every crypto/model/coverage candidate; the 59 software ones share one rule
            fetch("graph-" + cid, "/api/workbench/v1/bom-graph?%s&scope_kind=focused_candidate&candidate_id=%s" % (g, urllib.parse.quote(cid, safe="")))
    return ids


def session_for(base, jar):
    curl(base, jar, "/api/session", body="{}")
    return json.loads(curl(base, jar, "/api/analysis/demo", body="{}"))["generation"]


def main(argv):
    if len(argv) not in (3, 5):
        raise SystemExit(__doc__)
    cap, replay_url = argv[1].rstrip("/"), argv[2]
    store = os.path.join(cap, "addendum", "bom")
    if len(argv) == 5:
        os.makedirs(store, mode=0o700, exist_ok=True)
        live_url, live_jar = argv[3], argv[4]
        gen = json.loads(curl(live_url, live_jar, "/api/artifacts"))["generation"]
        saved = {}

        def fetch_live(name, path):
            doc = get(live_url, live_jar, path)
            saved[name] = doc
            return doc
        plan(fetch_live, gen)
        for name, doc in saved.items():
            with open(os.path.join(store, name.replace(":", "_").replace("/", "_") + ".json"), "w") as handle:
                json.dump(doc, handle, sort_keys=True)
        print("saved %d live responses under %s" % (len(saved), store))
    jar = os.path.join(tempfile.mkdtemp(prefix="bom-parity-"), "jar")
    gen = session_for(replay_url, jar)
    fails, n, model_ok = 0, 0, 0

    def fetch_replay(name, path):
        nonlocal fails, n
        doc = get(replay_url, jar, path)
        with open(os.path.join(store, name.replace(":", "_").replace("/", "_") + ".json")) as handle:
            want = json.load(handle)
        d = [x for x in diff(doc, want) if not SESSION.search(x[1])]
        n += 1
        if d:
            fails += 1
            print("FAIL %-60s %d diff(s) %s" % (name[:60], len(d), d[:3]))
        return doc
    ids = plan(fetch_replay, gen)
    print("compared %d responses (%d candidates); %d differ" % (n, len(ids), fails))
    subprocess.run(["rm", "-rf", os.path.dirname(jar)])
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
