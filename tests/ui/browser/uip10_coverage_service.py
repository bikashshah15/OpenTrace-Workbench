"""UIP-10 validation (test harness): the real Workbench with live scanning on LOCAL fixtures for the coverage-state browser checks.

Local git repositories stand in for public repositories, a fake Syft derives its SBOM from the requirements.txt it finds in its working directory
(file component with the file's SHA-256 + one library component per declaration, except names starting ``absent-``), a fake cdxgen emits a small CBOM,
isolation is the test pass-through and GitHub is a recorded transport. No network, Docker or real scanner. ``--case failed`` injects a deterministic
permission failure at the collector's filesystem boundary (its private ``os.scandir``), not a permission on a checked-out directory.
Usage: PYTHONPATH=<repo>:<repo>/src/core python3 tests/ui/browser/uip10_coverage_service.py --case partial|empty|unsupported|failed [--marker X]
"""
import argparse
import os
import sys
import tempfile

from opentrace_core.app import make_server
from opentrace_core.live import scanners as sc, source_declarations as sd
from opentrace_core.live.runner import LiveConfig
from opentrace_core.live.scanners import ScannerConfig
from tests.core.live import support

CASES = {
    "partial": [("widget", {"requirements.txt": b"flask==2.0.0\nabsent-pkg==1.0.0\n", "package.json": b"{}\n"}),
                ("gadget", {"requirements.txt": b"flask==2.0.0\n", "package.json": b"{}\n"})],
    "empty": [("plain", {"main.py": b"print(1)\n"})],
    "unsupported": [("nodeonly", {"package.json": b"{}\n"})],
    "completed": [("okrepo", {"requirements.txt": b"flask==2.0.0\n"}), ("plain", {"main.py": b"print(1)\n"})],   # F1-F3 round: completed (all declarations present in the SBOM) and completed_empty in one service
    # F1/F3 follow-up round: several states per service. followupA = partial (populated, zero total) + compared; followupB = unsupported + failed + compared.
    "followupA": [("widget", {"requirements.txt": b"flask==2.0.0\nabsent-pkg==1.0.0\n", "package.json": b"{}\n"}),
                  ("gadget", {"requirements.txt": b"flask==2.0.0\n", "package.json": b"{}\n"}),
                  ("okrepo", {"requirements.txt": b"flask==2.0.0\n"})],
    "followupB": [("nodeonly", {"package.json": b"{}\n"}),
                  ("failrepo", {"requirements.txt": b"flask==2.0.0\n", ".ot-fail": b"1\n"}),   # the collector's directory listing of THIS tree is made to fail (marker file)
                  ("okrepo", {"requirements.txt": b"flask==2.0.0\n"})],
    "failed": [("widget", {"requirements.txt": b"flask==2.0.0\n"})],
}

FAKE_SYFT = '''#!{python}
import hashlib, json, os, re, sys
if len(sys.argv) > 1 and sys.argv[1] == "version":
    print("Version: 9.9.9"); sys.exit(0)
out = [a.split("=", 1)[1] for a in sys.argv if a.startswith("cyclonedx-json=")][0]
comps = []
if os.path.isfile("requirements.txt"):
    data = open("requirements.txt", "rb").read()
    comps.append({{"type": "file", "name": "/spool/in/fixture/src/requirements.txt", "bom-ref": "file-requirements",
                  "hashes": [{{"alg": "SHA-256", "content": hashlib.sha256(data).hexdigest()}}]}})
    for line in data.decode().splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==(\\S+)$", line.strip())
        if m and not m.group(1).startswith("absent-"):
            ref = "pkg:pypi/%s@%s" % (m.group(1).lower(), m.group(2))
            comps.append({{"type": "library", "name": m.group(1), "version": m.group(2), "bom-ref": ref, "purl": ref,
                          "properties": [{{"name": "syft:location:0:path", "value": "/requirements.txt"}}]}})
doc = {{"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
       "metadata": {{"timestamp": "2026-01-01T00:00:00Z", "tools": {{"components": [{{"type": "application", "name": "syft", "version": "9.9.9"}}]}}}},
       "components": comps, "dependencies": []}}
open(out, "w").write(json.dumps(doc, sort_keys=True))
'''


class _OsProxy:
    """Replaces ``os`` inside ``source_declarations`` only: its directory listing fails with PermissionError (deterministic, user-independent)."""
    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def scandir(self, *args, **kwargs):
        raise PermissionError(13, "injected permission failure")


class _MarkerOsProxy(_OsProxy):
    """Like _OsProxy, but only a tree that contains the marker file ``.ot-fail`` at its root fails (deterministic, per repository)."""
    def scandir(self, path=".", *args, **kwargs):
        if self._real.path.exists(self._real.path.join(os.fspath(path), ".ot-fail")):
            raise PermissionError(13, "injected permission failure")
        return self._real.scandir(path, *args, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    parser.add_argument("--marker", default="")
    args = parser.parse_args()
    root = tempfile.mkdtemp(prefix="ot-uip10-cov-")
    tools = os.path.join(root, "tools")
    os.mkdir(tools)
    allow, origins, shas = {}, {}, {}
    for name, files in CASES[args.case]:
        origin, sha, _ = support.make_repo(os.path.join(root, name), files)
        allow["acme/" + name] = {"repo": "acme/" + name, "commit_sha": sha}
        origins[("acme", name)], shas[name] = origin, sha
    syft = os.path.join(tools, "syft")
    with open(syft, "w") as handle:
        handle.write(FAKE_SYFT.format(python=sys.executable))
    os.chmod(syft, 0o755)
    cdx = support.fake_tool(tools, "cdxgen", output=support.cyclonedx([support.crypto_asset()], spec="1.6"))
    cfg = ScannerConfig(syft_path=syft, node_path=cdx, cdxgen_dir=tools, pins={"syft": "9.9.9", "cdxgen": "9.9.9"})
    sc._resolve_cdxgen = lambda config: ([cdx, "-o", "{out}"], [cdx], [tools], "9.9.9")
    sc.CDXGEN["resolve"] = sc._resolve_cdxgen
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
    if args.case == "failed":
        sd.os = _OsProxy(os)
    elif args.case == "followupB":
        sd.os = _MarkerOsProxy(os)
    srv = make_server(os.path.join(root, "s"), reap_seconds=3600, live=live)
    print("OpenTrace UIP-10 coverage service http://127.0.0.1:%d/" % srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.app.close()


if __name__ == "__main__":
    sys.exit(main())
