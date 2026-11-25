"""Stage 4 closing-extension fixture service (test harness only): ONE synthetic service for the targeted preconditions. SYNTHETIC repositories, fake scanners, no network,
Docker, real scanner, provider or Cisco.

  i5c       a repository whose reviewed call-site target is INJECTED into the live configuration (``source_check_targets``, the documented test seam of live.runner), so the
            PRODUCTION source-check collector, assessment and projection run on it; the fake cdxgen reports the SHA-256 occurrence at the same file:line
  r203      the PRODUCTION shared-input failure path (R2-03: the collected declarations cannot be read, every family is unavailable); the failure is INJECTED by this service
            process (a monkeypatch of ``read_declarations`` for this one repository), the handlers and projections are production code
  pos       a supported model candidate with a delivered fake AI-BOM inventory (the AI banner: inventory generated in this scan)
  aibomfail the AI-BOM producer fails (the AI banner: requested but not delivered)
Usage: PYTHONPATH=<repo>:<repo>/src/core python3 tests/ui/browser/stage4_ext_service.py
"""
import hashlib
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


u13 = _load("uip13_model_service")
u12 = u13.uip12

I5C_FILE = "clients/mcpdo/src/connection/auth-helper.ts"
I5C_LINE = 76
I5C_CALL = '  const hash = createHash("sha256").update(key).digest("hex").slice(0, 16);'


def i5c_source():
    lines = ['import { createHash } from "node:crypto";', ""] + ["// filler %02d" % i for i in range(3, I5C_LINE)] + [I5C_CALL, "export { hash };", ""]
    assert lines[I5C_LINE - 1] == I5C_CALL
    return ("\n".join(lines)).encode()


def occ(file, line):
    return {"name": "SHA-256", "file": file, "line": line, "ctx": "createHash in f"}


pos = dict(u13.CASES["matrix"])["pos"]
aibomfail = dict(u13.CASES["matrix"])["aibomfail"]
u13.CASES["ext"] = [
    ("i5c", u12.repo({I5C_FILE: i5c_source()}, assets=[occ(I5C_FILE, I5C_LINE)])),
    ("r203", u13.repo({"app/m.py": u13.PY1}, models=[])),
    ("pos", pos),
    ("aibomfail", aibomfail),
]


def configure(live, shas):
    """Inject the I5C target and the R2-03 fault. Returns nothing; both are confined to this service process."""
    data = i5c_source()
    live.source_check_targets = {("acme/i5c", shas["i5c"]): ({"file": I5C_FILE, "line": I5C_LINE, "algorithm": "sha256", "file_sha256": hashlib.sha256(data).hexdigest(), "call_site": I5C_CALL},)}
    from opentrace_core.app import live_discovery
    orig = live_discovery.bb_discovery.read_declarations

    def faulty(bundle, declarations_bytes, **kw):
        if str(((bundle.get("capture") or {}).get("repository") or {}).get("url", "")).endswith("/r203"):
            raise live_discovery.bb_discovery.InputError("declarations_invalid", "fixture-injected shared input failure")
        return orig(bundle, declarations_bytes, **kw)
    live_discovery.bb_discovery.read_declarations = faulty


def main():
    from opentrace_core.app import make_server
    live, root, shas = u13.build("ext")
    configure(live, shas)
    srv = make_server(os.path.join(root, "s"), reap_seconds=3600, live=live)
    print("OpenTrace STAGE4 EXTENSION SYNTHETIC fixture service http://127.0.0.1:%d/" % srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.app.close()


if __name__ == "__main__":
    sys.exit(main())
