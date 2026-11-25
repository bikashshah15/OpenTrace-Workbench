"""Stage 4 diagnostic fixture service (test harness only): ONE synthetic service hosting `modelsupp` (graph geometry diagnostic, P8) and `cbomfail` (failed-CBOM scan status, UIP-D19 observation).

Reuses the already-reviewed synthetic repo definitions of uip13_model_service.py (modelsupp) and uip12_crypto_service.py (cbomfail); each repository is its own isolated scenario
(own synthetic files, own fake scanner configuration, deterministic content). No network, Docker, real scanner, provider or Cisco.
Usage: PYTHONPATH=<repo>:<repo>/src/core python3 tests/ui/browser/stage4_diag_service.py
"""
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
u13.CASES["diag"] = [
    ("modelsupp", dict(u13.CASES["matrix"])["pos"]),          # SYNTHETIC supported + inconclusive model candidates (same definition as the P8 service)
    ("cbomfail", dict(u12.CASES["matrix"])["cbomfail"]),     # SYNTHETIC repo whose CBOM generator fails (UIP-D19: no hand-off)
]


def main():
    from opentrace_core.app import make_server
    live, root, _ = u13.build("diag")
    srv = make_server(os.path.join(root, "s"), reap_seconds=3600, live=live)
    print("OpenTrace STAGE4 DIAGNOSTIC SYNTHETIC fixture service http://127.0.0.1:%d/" % srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.app.close()


if __name__ == "__main__":
    sys.exit(main())
