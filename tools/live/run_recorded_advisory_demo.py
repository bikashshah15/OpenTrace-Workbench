#!/usr/bin/env python3
"""Serve the Workbench for a walkthrough of the I5B advisory lookup with RECORDED responses only (no network).

    PYTHONPATH=src/core:src/agents/investigator python3 tools/live/run_recorded_advisory_demo.py [--osv ok|down|second_batch_down|records_down]

The scanned "repository" is a local git fixture (``tests/core/advisory/fixtures``), the scanners are shell stand-ins
that emit the fixture SBOM, the lockfile inventory is produced by the real Evidence Specialist B, and OSV answers come
from the recorded fixtures (the advisory record is the verbatim OSV record from the 2026-11-04 snapshot). Nothing here
contacts GitHub or OSV. Open the printed URL, enter ``https://github.com/acme/widget/tree/v1`` and choose Scan live.
"""
import argparse
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "src" / "core"), str(ROOT / "src" / "agents" / "investigator")]

from tests.core.advisory import support                                   # noqa: E402
from tests.core.advisory.test_live_advisory_app import AdvisoryAppBase    # noqa: E402


class Demo(AdvisoryAppBase):
    def runTest(self):  # pragma: no cover - never run as a test
        pass


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--osv", default="ok", choices=["ok", "down", "http503", "second_batch_down", "records_down", "garbage"])
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    Demo.setUpClass()
    case = Demo()
    case.setUp()
    osv = support.RecordedOsv(args.osv)
    srv = case.advisory_server(osv)
    print("OpenTrace recorded advisory demo (OSV mode: {}): http://127.0.0.1:{}/".format(args.osv, srv.server_address[1]), flush=True)
    print("Scan URL: https://github.com/acme/widget/tree/v1", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        case.doCleanups()


if __name__ == "__main__":
    main(sys.argv[1:])
