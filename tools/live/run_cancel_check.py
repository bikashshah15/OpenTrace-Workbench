#!/usr/bin/env python3
"""I5A live cancel check: cancel the real cdxgen mid-scan, then verify no scanner process remains and End session is verified.

Run from the repository root like run_demo.py (OPENTRACE_LIVE_SCAN=1, OPENTRACE_CDXGEN_DIR). The main guard matters: BOMBridge assessment uses multiprocessing spawn."""
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, "tools/live"); sys.path.insert(0, "src/core")
import run_demo as rd
from opentrace_core.live.runner import LiveConfig
from opentrace_core.live import policy
def main():
    entry = next(iter(policy.load_allowlist().values()))
    base = tempfile.mkdtemp(prefix="ot-cancel-")
    srv = rd.start(os.path.join(base, "s"), LiveConfig()); port = srv.server_address[1]
    c = rd.Client(port); c.json("POST", "/api/session", {})
    url = "https://github.com/%s/tree/%s" % (entry["repo"], entry["commit_sha"])
    res = {}
    t = threading.Thread(target=lambda: res.update(c.json("POST", "/api/analysis/live", {"url": url})[1])); t.start()
    # wait until cdxgen is running, then cancel
    deadline = time.time() + 60
    while time.time() < deadline and not rd.processes_named("cdxgen.js"): time.sleep(0.05)
    saw = len(rd.processes_named("cdxgen.js"))
    t0 = time.time(); st, out = c.json("POST", "/api/analysis/cancel", {}); t.join(30)
    left = len(rd.processes_named("cdxgen.js")) + len(rd.processes_named(base))
    st2, ended = c.json("POST", "/api/session/end", {})
    print(json.dumps({"cdxgen_processes_seen_before_cancel": saw, "cancel_state": out.get("state"), "analysis_result": [res.get("ok"), res.get("code")], "seconds_to_cancel": round(time.time()-t0,1), "leftover_processes": left, "end_state": ended.get("state"), "sessions_dir_empty": os.listdir(os.path.join(base, "s")) == []}))
    rd.stop(srv)

if __name__ == '__main__':
    main()
