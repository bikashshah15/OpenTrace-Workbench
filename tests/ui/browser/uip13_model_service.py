"""UIP-13 validation (test harness): the real Workbench with live scanning on LOCAL SYNTHETIC fixtures for the active-inspector browser checks (desktop).

Every repository, SBOM and AI-BOM here is SYNTHETIC (written by this file); a "supported" correspondence is a synthetic AI-BOM that lists the source locator, NOT a
third-party live comparison and NOT a Cisco run. Local git repositories stand in for public repositories (recorded GitHub transport, pass-through isolation, no
network, no Docker, no real scanner, no provider). The fake Syft is the UIP-10 one. The AI phase is the real runner/bundle/orchestrator code path with only the
producer replaced: ``aibom_worker_client.run`` is wrapped to read ``.ot-aibom.json`` from the scanned tree and build the ScanRun the worker client would have
returned (scope, version pin, completeness and digest come from the real helper functions). ``--case norun`` runs with no AI-BOM configured.
Usage: PYTHONPATH=<repo>:<repo>/src/core python3 tests/ui/browser/uip13_model_service.py --case matrix|states|norun|interact
"""
import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile

from opentrace_core.app import make_server
from opentrace_core.live import aibom_cisco as ac, aibom_worker_client as awc, runner as live_runner, scanners as sc, source_declarations as sd
from opentrace_core.live.runner import LiveConfig
from opentrace_core.live.scanners import ScannerConfig
from tests.core.live import support

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("uip10_coverage_service", os.path.join(HERE, "uip10_coverage_service.py"))
uip10 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uip10)
_spec12 = importlib.util.spec_from_file_location("uip12_crypto_service", os.path.join(HERE, "uip12_crypto_service.py"))
uip12 = importlib.util.module_from_spec(_spec12)
_spec12.loader.exec_module(uip12)       # only for its fake cdxgen (writes a successful zero-asset CBOM when the tree has no .ot-cbom.json)

M1 = "https://models.example.org/a/det.onnx"
M2 = "https://models.example.org/b/other.tflite?download=1#v2"
M3 = "https://models.example.org/c/third.hef"
REQ = {"requirements.txt": b"flask==2.0.0\n"}
PY1 = ('MODEL = "%s"\n' % M1).encode()


def aibom(models=(), scope="whole", fail=False, spec="1.6"):
    return (".ot-aibom.json", json.dumps({"models": [list(m) for m in models], "scope": scope, "fail": fail, "spec": spec}).encode())


def repo(files, **kw):
    out = dict(REQ)
    out.update(files)
    k, v = aibom(**kw)
    out[k] = v
    return out


CASES = {
    "matrix": [
        ("pos", repo({"app/m.py": PY1, "docker/Dockerfile": ("RUN wget %s\n" % M2).encode()}, models=[("ref-1", "det", [M1])])),        # SYNTHETIC positive for M1
        ("zeromodel", repo({"app/m.py": PY1}, models=[])),
        ("ambig", repo({"app/m.py": PY1}, models=[("r1", "a", [M1]), ("r2", "b", [M1])])),
        ("basename", repo({"app/m.py": PY1}, models=[("r1", "det.onnx", ["https://elsewhere.example/x/det.onnx"])])),
        ("outside", repo({"app/m.py": PY1}, models=[("r1", "det", [M1])], scope="outside")),
        ("noscope", repo({"app/m.py": PY1}, models=[("r1", "det", [M1])], scope="none")),
        ("aibomfail", repo({"app/m.py": PY1}, fail=True)),
        ("hostile", repo({"app/m.py": PY1}, models=[("<script>alert(1)</script>", "<img src=x onerror=alert(2)>", [M1])])),
    ],
    "states": [
        ("dyn", repo({"app/m.py": b'u = f"https://h.example/{name}.onnx?rev={rev}"\n'}, models=[])),
        ("empty", repo({"app/m.py": b"print(1)\n"}, models=[])),
        ("nosource", {"README.md": b"# readme\n", ".ot-aibom.json": aibom()[1]}),
        ("mixed", repo({"app/m.py": PY1, "a.go": b"package x\n"}, models=[("r1", "det", [M1])])),
        ("bigtree", repo({"app/m%02d.py" % i: ('M = "https://models.example.org/m%02d.onnx"\n' % i).encode() for i in range(30)}, models=[])),
    ],
    "norun": [
        ("norun", repo({"app/m.py": PY1, "docker/Dockerfile": ("RUN wget %s\n" % M2).encode()}, models=[])),
        ("blankrepo", repo({"app/m.py": b"print(1)\n"}, models=[])),
    ],
    "interact": [
        ("multi", repo({"app/a.py": PY1, "app/b.py": ('B = "%s"\n' % M2).encode(), "app/c.py": ('C = "%s"\n' % M3).encode()},
                       models=[("r1", "det", [M1]), ("r3", "third.hef", ["https://elsewhere.example/q/third.hef"])])),
    ],
}


class FakeAibom:
    """Stands in for the AI worker client: always available; the producer itself is replaced in ``run`` below."""
    def availability(self):
        return True, None, None

    def public(self, _flag):
        return {"enabled": True, "provider": "SYNTHETIC fixture (no provider)"}


class Cfg(LiveConfig):
    def aibom_available(self):
        return (True, None) if self.aibom is not None else (False, "not_configured")


def fake_run(config, service, ticket, source, workspace):
    run = awc.new_run(source)
    run.version = ac.PINNED_VERSION
    run.isolation = "synthetic-fixture"
    spec = {"models": [], "scope": "whole", "fail": False, "spec": "1.6"}
    path = os.path.join(workspace, "src", ".ot-aibom.json")
    if os.path.isfile(path):
        spec = json.load(open(path))
    if spec.get("fail"):
        run.outcome, run.reason = "failed", "scanner_failed"
        return run
    comps = [{"type": "machine-learning-model", "bom-ref": ref, "name": name, "externalReferences": [{"type": "distribution", "url": u} for u in urls]}
             for ref, name, urls in spec["models"]]
    doc = {"bomFormat": "CycloneDX", "specVersion": spec.get("spec", "1.6"), "version": 1, "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000013",
           "metadata": {"timestamp": "2026-01-01T00:00:00Z", "tools": {"components": [{"type": "application", "name": "cisco-aibom", "version": ac.PINNED_VERSION}]}},
           "components": comps}
    data = json.dumps(doc, sort_keys=True).encode()
    run.outcome, run.data, run.size, run.sha256, run.exit_code = "acquired", data, len(data), hashlib.sha256(data).hexdigest(), 0
    run.spec_version = doc["specVersion"]
    run.record_count, run.record_count_unit, run.record_counts = sc.count_records(doc, "aibom")
    run.completeness = "verified"
    run.meaning = "a successful scan that reported no model" if run.record_count == 0 else ""
    mode = spec.get("scope")
    if mode == "outside":
        run.scope = dict(run.scope, paths=["vendor"])
    elif mode == "none":
        run.scope = {}
    return run


def build(case):
    """The ``LiveConfig`` and temp root of one case (shared by the service and the in-process dry run; nothing listens here)."""
    root = tempfile.mkdtemp(prefix="ot-uip13-fix-")
    tools = os.path.join(root, "tools")
    os.mkdir(tools)
    allow, origins, shas = {}, {}, {}
    for name, files in CASES[case]:
        origin, sha, _ = support.make_repo(os.path.join(root, name), files)
        allow["acme/" + name] = {"repo": "acme/" + name, "commit_sha": sha}
        origins[("acme", name)], shas[name] = origin, sha
    syft = os.path.join(tools, "syft")
    with open(syft, "w") as handle:
        handle.write(uip10.FAKE_SYFT.format(python=sys.executable))
    os.chmod(syft, 0o755)
    cdx = os.path.join(tools, "cdxgen")
    with open(cdx, "w") as handle:
        handle.write(uip12.FAKE_CDXGEN.format(python=sys.executable))
    os.chmod(cdx, 0o755)
    cfg = ScannerConfig(syft_path=syft, node_path=cdx, cdxgen_dir=tools, pins={"syft": "9.9.9", "cdxgen": "9.9.9"})
    sc._resolve_cdxgen = lambda config: ([cdx, "-o", "{out}"], [cdx], [tools], "9.9.9")
    sc.CDXGEN["resolve"] = sc._resolve_cdxgen
    awc.run = fake_run
    transports = [(n, support.recorded_transport("acme", n, shas[n])) for n in shas]

    def transport(path):
        for _, t in transports:
            try:
                return t(path)
            except OSError:
                continue
        raise OSError("no recorded response")
    live = Cfg(allowlist=allow, scanners=cfg, isolation=support.PassThrough(), transport=transport, remote_for=lambda o, n: origins[(o, n)], allow_protocol="file",
               aibom=None if case == "norun" else FakeAibom())
    return live, root, shas


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    args = parser.parse_args()
    live, root, _ = build(args.case)
    srv = make_server(os.path.join(root, "s"), reap_seconds=3600, live=live)
    print("OpenTrace UIP-13 SYNTHETIC fixture service http://127.0.0.1:%d/" % srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.app.close()


if __name__ == "__main__":
    sys.exit(main())
