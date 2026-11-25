#!/usr/bin/env python3
"""Compare a running replay Workbench with the private live capture it replays.

    python3 -I tools/demo_replay/verify_replay.py CAPTURE_DIR [BASE_URL]      (BASE_URL defaults to http://127.0.0.1:8799)

Starts its own session, opens the demo through the normal entry point (POST /api/analysis/demo with an empty body, as the Demo button does),
then checks: every served artifact is byte-identical to the captured one, and every projection captured from the live session
(summary, contexts, dependency-contexts, crypto-assets, ai-assets, bom-candidates, gaps, advisory lookup) is equal after ignoring the
fields that legitimately differ between sessions (session id, replay labelling). Exit status 1 on any unexpected difference.
"""
import json
import os
import subprocess
import sys
import tempfile

import re

IGNORED = {"/live/isolation", "/live/replay"}   # replay labelling, by design
# The only differences allowed between a replay session and the live capture are the session id and the per-session seal over the assessment
# (validation_digest differs between two replay sessions of identical data while bundle_sha256 and every count stay equal; checked in bom_parity.py).
EXPECTED = [("session", re.compile(r"/binding/(assessment/)?(session_id|validation_digest)$|/canonical_ref/binding/session_id$"))]


def classify(found):
    expected, unexpected = {}, []
    for item in found:
        for name, rx in EXPECTED:
            if rx.search(item[1]):
                expected[name] = expected.get(name, 0) + 1
                break
        else:
            unexpected.append(item)
    return expected, unexpected


def curl(base, jar, path, body=None, save=None):
    cmd = ["curl", "-s", "-c", jar, "-b", jar, base + path]
    if body is not None:
        cmd[1:1] = ["-H", "Content-Type: application/json", "-d", body]
    out = subprocess.run(cmd, capture_output=True, check=True).stdout
    return out


def diff(a, b, path="", out=None):
    out = [] if out is None else out
    if path in IGNORED:
        return out
    if type(a) is not type(b):
        out.append(("TYPE", path))
    elif isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if path + "/" + k in IGNORED:
                continue
            if k not in a:
                out.append(("only_in_capture", path + "/" + k))
            elif k not in b:
                out.append(("only_in_replay", path + "/" + k))
            else:
                diff(a[k], b[k], path + "/" + k, out)
    elif isinstance(a, list):
        if len(a) != len(b):
            out.append(("LEN", path, len(a), len(b)))
        else:
            for i, (x, y) in enumerate(zip(a, b)):
                diff(x, y, "%s[%d]" % (path, i), out)
    elif a != b:
        out.append(("DIFF", path, str(a)[:60], str(b)[:60]))
    return out


def main(argv):
    if not 2 <= len(argv) <= 3:
        raise SystemExit(__doc__)
    cap = argv[1].rstrip("/")
    base = argv[2] if len(argv) == 3 else "http://127.0.0.1:8799"
    jar = os.path.join(tempfile.mkdtemp(prefix="replay-verify-"), "jar")   # never write into the private capture
    failures = 0
    curl(base, jar, "/api/session", body="{}")
    demo = json.loads(curl(base, jar, "/api/analysis/demo", body="{}"))
    assert demo.get("ok"), demo
    gen = demo["generation"]
    status = json.load(open(cap + "/scan-status.json"))
    print("commit", demo["identity"]["commit"], "digest", demo["identity"]["analysis_digest"][:23], "(capture:", status["status"]["binding"]["analysis_digest"][:23] + ")")
    if demo["identity"]["analysis_digest"] != status["status"]["binding"]["analysis_digest"]:
        failures += 1
        print("FAIL analysis digest differs")
    index = json.load(open(cap + "/artifacts-index.json"))["artifacts"]
    served = {a["name"] for a in json.loads(curl(base, jar, "/api/artifacts"))["artifacts"]}
    for a in index:
        if a["name"] not in served:
            failures += 1
            print("FAIL artifact not served:", a["name"])
            continue
        same = curl(base, jar, "/api/artifacts/" + a["name"]) == open(cap + "/artifacts/" + a["name"], "rb").read()
        print("%-4s artifact %-26s byte-identical to capture" % ("ok" if same else "FAIL", a["name"]))
        failures += not same
    checks = [("summary", demo["summary"], status["result"]["summary"])]
    for name in ("contexts", "dependency-contexts", "crypto-assets", "ai-assets", "bom-candidates"):
        checks.append((name, json.loads(curl(base, jar, "/api/workbench/v1/%s?generation=%d" % (name, gen))), json.load(open(cap + "/workbench-v1/%s.json" % name))))
    checks.append(("gaps", json.loads(curl(base, jar, "/api/view/gaps?generation=%d" % gen)), json.load(open(cap + "/views/gaps.json"))))
    checks.append(("advisory-lookup", json.loads(curl(base, jar, "/api/view/advisory-lookup?generation=%d" % gen)), json.load(open(cap + "/views/advisory-lookup.json"))))
    for name, replay, captured in checks:
        expected, d = classify(diff(replay, captured))
        print("%-4s projection %-20s unexpected=%d expected(documented)=%s %s" % ("ok" if not d else "FAIL", name, len(d), expected or "{}", d[:4] if d else ""))
        failures += bool(d)
    subprocess.run(["rm", "-rf", os.path.dirname(jar)])
    print("RESULT:", "all checks passed" if not failures else "%d check(s) failed" % failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
