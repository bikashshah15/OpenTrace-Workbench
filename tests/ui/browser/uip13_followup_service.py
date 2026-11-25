"""UIP-13 follow-up (test harness only): ONE synthetic fixture service hosting a Stage 3 model case set and a Stage 2 crypto case, for the desktop graph/banner verification.

Every repository, SBOM, CBOM and AI-BOM is SYNTHETIC (built by uip13_model_service.py / uip12_crypto_service.py fixtures); no network, Docker, scanner, provider or Cisco.
Usage: PYTHONPATH=<repo>:<repo>/src/core python3 tests/ui/browser/uip13_followup_service.py
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
u13.CASES["followup"] = [
    ("modelsupp", dict(u13.CASES["matrix"])["pos"]),          # Stage 3: SYNTHETIC supported + inconclusive model candidates
    ("modeloutside", dict(u13.CASES["matrix"])["outside"]),  # Stage 3: SYNTHETIC reference outside the AI-BOM scan scope
    ("cryptosupp", dict(u12.CASES["matrix"])["positive"]),  # Stage 2: SYNTHETIC crypto call site declared in a CBOM
]


def main():
    from opentrace_core.app import make_server
    live, root, _ = u13.build("followup")
    srv = make_server(os.path.join(root, "s"), reap_seconds=3600, live=live)
    print("OpenTrace UIP-13 FOLLOW-UP SYNTHETIC fixture service http://127.0.0.1:%d/" % srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.app.close()


if __name__ == "__main__":
    sys.exit(main())
