"""UIP-12 validation (test harness): the real Workbench with live scanning on LOCAL SYNTHETIC fixtures for the active-inspector browser checks.

Every repository, CBOM and SBOM here is SYNTHETIC (written by this file); a "positive" correspondence is a synthetic CBOM that records a hash occurrence at the
call site, NOT a third-party live comparison. Local git repositories stand in for public repositories (recorded GitHub transport, pass-through isolation, no
network, no Docker, no real scanner). The fake Syft is the UIP-10 one; the fake cdxgen reads ``.ot-cbom.json`` from the scanned tree and writes a CycloneDX
1.6 CBOM from it (a producer failure is ``{"fail": true}``). The CBOM scan scope recorded by the real runner is the whole tree; for the cases that need another
scope, a wrapper around ``runner.run_scanner`` rewrites ``run.scope`` after the real call (marker ``scope`` in the spec): "outside" -> paths ["vendor"], "none" -> {}.
Usage: PYTHONPATH=<repo>:<repo>/src/core python3 tests/ui/browser/uip12_crypto_service.py --case matrix|states|interact
"""
import argparse
import importlib.util
import json
import os
import sys
import tempfile

from opentrace_core.app import make_server
from opentrace_core.live import runner as live_runner, scanners as sc, source_declarations as sd
from opentrace_core.live.runner import LiveConfig
from opentrace_core.live.scanners import ScannerConfig
from tests.core.live import support

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("uip10_coverage_service", os.path.join(HERE, "uip10_coverage_service.py"))
uip10 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uip10)

PY = b'import hashlib\n\ndef f(x):\n    return hashlib.sha256(x).hexdigest()\n'
REQ = {"requirements.txt": b"flask==2.0.0\n"}


def cbom(assets=(), scope="whole", fail=False):
    return (".ot-cbom.json", json.dumps({"assets": list(assets), "scope": scope, "fail": fail}).encode())


def repo(files, **kw):
    out = dict(REQ); out.update(files)
    k, v = cbom(**kw); out[k] = v
    return out


def occ(file, line, ctx="hashlib.sha256 in f", name="SHA-256"):
    return {"name": name, "file": file, "line": line, "ctx": ctx}


CASES = {
    "matrix": [
        ("positive", repo({"app/m.py": PY}, assets=[occ("app/m.py", 4)])),                                             # SYNTHETIC positive
        ("renamed", repo({"app/m.py": b'from hashlib import sha256 as s\nx = s(b"x")\n'}, assets=[occ("app/m.py", 2, "hashlib.sha256 in <module>")])),
        ("zeroasset", repo({"app/m.py": PY})),                                                                           # successful CBOM, no cryptographic asset
        ("obsonly", repo({"app/m.py": b'import hashlib\nhashlib.pbkdf2_hmac("sha256", b"p", b"s", 1)\nhashlib.new(name)\n'})),
        ("outside", repo({"app/m.py": PY}, assets=[occ("app/m.py", 4)], scope="outside")),
        ("noscope", repo({"app/m.py": PY}, assets=[occ("app/m.py", 4)], scope="none")),
        ("cbomfail", repo({"app/m.py": PY}, fail=True)),
    ],
    "states": [
        ("partial", repo({"app/m.py": PY, "a.js": b"x\n", "package.json": b"{}\n"})),
        ("empty", dict(REQ, **{"main.py": b"print(1)\n"})),
        ("nosource", {"README.md": b"# readme\n"}),
        ("nodeonly", {"package.json": b"{}\n", "a.js": b"x\n"}),
        ("failrepo", dict(REQ, **{".ot-fail": b"1\n", "app/m.py": PY})),
    ],
    "interact": [
        ("multi", repo({"app/a.py": b'import hashlib\nx = hashlib.sha256(b"a")\n', "app/b.py": b'import hashlib\ny = hashlib.md5(b"b")\n',
                        "app/c.py": b'import hashlib\nz = hashlib.pbkdf2_hmac("sha256", b"p", b"s", 1)\n'}, assets=[occ("app/a.py", 2, "hashlib.sha256 in <module>")])),
    ],
}

FAKE_CDXGEN = '''#!{python}
import json, os, sys
if len(sys.argv) > 1 and sys.argv[1] == "version":
    print("Version: 9.9.9"); sys.exit(0)
out = None
for i, a in enumerate(sys.argv):
    if a == "-o" and i + 1 < len(sys.argv):
        out = sys.argv[i + 1]
spec = {{"assets": [], "scope": "whole", "fail": False}}
if os.path.isfile(".ot-cbom.json"):
    spec = json.load(open(".ot-cbom.json"))
if spec.get("fail"):
    sys.exit(3)
comps = [{{"type": "cryptographic-asset", "name": a["name"], "bom-ref": "crypto/algorithm/" + a["name"],
          "cryptoProperties": {{"assetType": "algorithm", "algorithmProperties": {{"primitive": "hash"}}}},
          "evidence": {{"occurrences": [{{"location": a["file"], "line": a["line"], "offset": 4, "additionalContext": a["ctx"]}}]}}}} for a in spec["assets"]]
doc = {{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000012",
       "metadata": {{"timestamp": "2026-01-01T00:00:00Z", "tools": {{"components": [{{"type": "application", "name": "cdxgen", "version": "9.9.9"}}]}},
                    "properties": [{{"name": "ot:fixture-scope", "value": spec.get("scope", "whole")}}]}},
       "components": comps, "dependencies": []}}
open(out, "w").write(json.dumps(doc, sort_keys=True))
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    args = parser.parse_args()
    root = tempfile.mkdtemp(prefix="ot-uip12-fix-")
    tools = os.path.join(root, "tools")
    os.mkdir(tools)
    allow, origins, shas = {}, {}, {}
    for name, files in CASES[args.case]:
        origin, sha, _ = support.make_repo(os.path.join(root, name), files)
        allow["acme/" + name] = {"repo": "acme/" + name, "commit_sha": sha}
        origins[("acme", name)], shas[name] = origin, sha
    syft = os.path.join(tools, "syft")
    with open(syft, "w") as handle:
        handle.write(uip10.FAKE_SYFT.format(python=sys.executable))
    os.chmod(syft, 0o755)
    cdx = os.path.join(tools, "cdxgen")
    with open(cdx, "w") as handle:
        handle.write(FAKE_CDXGEN.format(python=sys.executable))
    os.chmod(cdx, 0o755)
    cfg = ScannerConfig(syft_path=syft, node_path=cdx, cdxgen_dir=tools, pins={"syft": "9.9.9", "cdxgen": "9.9.9"})
    sc._resolve_cdxgen = lambda config: ([cdx, "-o", "{out}"], [cdx], [tools], "9.9.9")
    sc.CDXGEN["resolve"] = sc._resolve_cdxgen
    real = live_runner.run_scanner

    def wrapped(spec, config, isolation, source, workspace, **kw):
        run = real(spec, config, isolation, source, workspace, **kw)
        if run.kind == "cbom" and run.outcome == "acquired":
            marks = {p.get("name"): p.get("value") for p in (json.loads(run.data).get("metadata", {}).get("properties") or [])}
            mode = marks.get("ot:fixture-scope")
            if mode == "outside":
                run.scope = dict(run.scope, paths=["vendor"])
            elif mode == "none":
                run.scope = {}
        return run
    live_runner.run_scanner = wrapped
    transports = [(n, support.recorded_transport("acme", n, shas[n])) for n in shas]

    def transport(path):
        for _, t in transports:
            try:
                return t(path)
            except OSError:
                continue
        raise OSError("no recorded response")
    live = LiveConfig(allowlist=allow, scanners=cfg, isolation=support.PassThrough(), transport=transport,
                      remote_for=lambda o, n: origins[(o, n)], allow_protocol="file")
    if args.case == "states":
        sd.os = uip10._MarkerOsProxy(os)
    srv = make_server(os.path.join(root, "s"), reap_seconds=3600, live=live)
    print("OpenTrace UIP-12 SYNTHETIC fixture service http://127.0.0.1:%d/" % srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.app.close()


if __name__ == "__main__":
    sys.exit(main())
