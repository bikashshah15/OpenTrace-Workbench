"""Browser-test service for the live advisory lookup (RT-01 correction): the real Workbench with live scanning AND advisory lookup enabled
against LOCAL fixtures only. A local git repository stands in for the public repository, fake scanner scripts stand in for Syft and cdxgen,
Evidence Specialist B is the real Go parser built from this repository, and OSV is the RECORDED transport (tests/core/advisory/support.py).
Nothing here touches the network, Docker or a real scanner.

    --mode joined   the SBOM lists the lockfile packages (the normal joined case)
    --mode zero     the SBOM holds one unrelated component and none of the lockfile packages (RT-01: nothing joins; matches stay lockfile-only)

Usage: PYTHONPATH=<repo>:<repo>/src/core:<repo>/src/agents/investigator python3 tests/ui/browser/advisory_service.py --mode zero --port 8793
Scan URL in the browser: https://github.com/acme/widget/tree/v1
"""
import argparse
import json
import os
import sys
import tempfile

from opentrace_core.advisory.config import AdvisoryConfig
from opentrace_core.app import make_server
from opentrace_core.live import scanners as sc
from opentrace_core.live.runner import LiveConfig
from opentrace_core.live.scanners import ScannerConfig
from tests.core.advisory import support as adv
from tests.core.live import support
from tests.core.live.test_live_app import CBOM_EMPTY

FILES = {"package-lock.json": adv.lock_bytes(), "src/index.js": b"console.log(1)\n"}
UNRELATED = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
    {"type": "library", "name": "unrelated", "version": "1.0.0", "bom-ref": "u1", "purl": "pkg:npm/unrelated@1.0.0"}]}).encode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("joined", "zero"), default="joined")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    binary = adv.specialist_binary()
    if not binary:
        sys.exit("no Go toolchain: Evidence Specialist B cannot be built")
    root = tempfile.mkdtemp(prefix="ot-ui-adv-")
    origin, sha, _ = support.make_repo(root, FILES)
    tools = os.path.join(root, "tools")
    os.mkdir(tools)
    sbom = UNRELATED if args.mode == "zero" else adv.sbom_bytes()
    syft = support.fake_tool(tools, "syft", output=sbom)
    cdx = support.fake_tool(tools, "cdxgen", output=CBOM_EMPTY)
    cfg = ScannerConfig(syft_path=syft, node_path=cdx, cdxgen_dir=tools, pins={"syft": "9.9.9", "cdxgen": "9.9.9"})
    sc._resolve_cdxgen = lambda config: ([cdx, "-o", "{out}"], [cdx], [tools], "9.9.9")
    sc.CDXGEN["resolve"] = sc._resolve_cdxgen
    advisories = AdvisoryConfig(specialist_bin=binary, transport=adv.RecordedOsv(), sleep=lambda s: None)
    live = LiveConfig(allowlist={"acme/widget": {"repo": "acme/widget", "commit_sha": sha}}, scanners=cfg, isolation=support.PassThrough(),
                      transport=support.recorded_transport("acme", "widget", sha), remote_for=lambda o, n: origin, allow_protocol="file", advisories=advisories)
    srv = make_server(os.path.join(root, "s"), port=args.port, reap_seconds=3600, live=live)
    print("OpenTrace advisory test service (%s) http://127.0.0.1:%d/" % (args.mode, srv.server_address[1]), flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.app.close()


if __name__ == "__main__":
    sys.exit(main())
