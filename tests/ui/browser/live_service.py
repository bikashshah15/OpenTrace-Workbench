"""UIP-03 browser-test service: the real Workbench with live scanning enabled against LOCAL fixtures only.

A local git repository stands in for the public repository, fake scanner scripts stand in for Syft and cdxgen, the isolation provider is
the test pass-through and GitHub is a recorded transport. Nothing here touches the network, Docker or a real scanner.
Usage: PYTHONPATH=<repo>:<repo>/src/core python3 tests/ui/browser/live_service.py [--cbom-sleep N]  (prints the URL like the real service)
"""
import argparse
import os
import sys
import tempfile
import threading

from opentrace_core.app import make_server
from opentrace_core.live import scanners as sc
from opentrace_core.live.runner import LiveConfig
from opentrace_core.live.scanners import ScannerConfig
from tests.core.live import support

FILES = {"package-lock.json": b'{"name":"w","lockfileVersion":3,"packages":{}}\n', "src/index.js": b"console.log(1)\n"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cbom-sleep", type=int, default=0)
    parser.add_argument("--sbom-sleep", type=int, default=0)
    parser.add_argument("--policy", default="allowlist")
    args = parser.parse_args()
    root = tempfile.mkdtemp(prefix="ot-ui-live-")
    origin, sha, _ = support.make_repo(root, FILES)
    tools = os.path.join(root, "tools")
    os.mkdir(tools)
    sbom = support.cyclonedx([support.library("left-pad"), support.library("lodash", "4.17.21")], spec="1.7")
    cbom = support.cyclonedx([support.library("left-pad"), support.crypto_asset()], spec="1.6")
    syft = support.fake_tool(tools, "syft", output=sbom, sleep=args.sbom_sleep)
    cdx = support.fake_tool(tools, "cdxgen", output=cbom, sleep=args.cbom_sleep)
    cfg = ScannerConfig(syft_path=syft, node_path=cdx, cdxgen_dir=tools, pins={"syft": "9.9.9", "cdxgen": "9.9.9"})
    sc._resolve_cdxgen = lambda config: ([cdx, "-o", "{out}"], [cdx], [tools], "9.9.9")
    sc.CDXGEN["resolve"] = sc._resolve_cdxgen
    live = LiveConfig(allowlist={"acme/widget": {"repo": "acme/widget", "commit_sha": sha}}, scanners=cfg, isolation=support.PassThrough(),
                      transport=support.recorded_transport("acme", "widget", sha), remote_for=lambda o, n: origin, allow_protocol="file")
    srv = make_server(os.path.join(root, "s"), reap_seconds=3600, live=live)
    print("OpenTrace live test service http://127.0.0.1:%d/" % srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.app.close()


if __name__ == "__main__":
    sys.exit(main())
