"""Test doubles for I5B: a recorded OSV transport, fixture loaders and a cached Specialist B build."""
import json
import os
import shutil
import tempfile
import threading
from pathlib import Path

from opentrace_core.advisory import inventory
from opentrace_core.advisory.osv import Response

FIX = Path(__file__).resolve().parent / "fixtures"
_BIN = {}
_LOCK = threading.Lock()


def lock_bytes():
    return (FIX / "package-lock.json").read_bytes()


def sbom_bytes():
    return (FIX / "syft-sbom.cdx.json").read_bytes()


def sbom_doc():
    return json.loads(sbom_bytes())


def recorded():
    doc = json.loads((FIX / "osv" / "answers.json").read_text())
    return doc["answers"], {"GHSA-23c5-xmqv-rm74": (FIX / "osv" / "GHSA-23c5-xmqv-rm74.json").read_bytes()}


def specialist_binary():
    """Build Evidence Specialist B once per test process; None when no Go toolchain is available."""
    with _LOCK:
        if "bin" not in _BIN:
            if not shutil.which("go"):
                _BIN["bin"] = None
            else:
                out = tempfile.mkdtemp(prefix="ot-b-bin-")
                _BIN["bin"] = inventory.build_specialist(out)
    return _BIN["bin"]


class RecordedOsv:
    """OSV answered from the recorded fixtures. ``mode`` selects a failure to inject.

    ``calls`` lists (method, path); ``queries`` every query object received, so a test can assert exactly what was sent.
    """

    def __init__(self, mode="ok", answers=None, records=None, pages=None):
        a, r = recorded()
        self.answers = a if answers is None else answers
        self.records = r if records is None else records
        self.mode, self.pages = mode, pages or {}
        self.calls, self.queries = [], []
        self.batches = 0

    def __call__(self, method, path, body=None):
        self.calls.append((method, path))
        if self.mode == "down":
            raise OSError("connection refused")
        if self.mode == "http503":
            return Response(503, b"unavailable")
        if path == "/v1/querybatch":
            self.batches += 1
            if self.mode == "second_batch_down" and self.batches > 1:
                raise OSError("connection reset")
            qs = json.loads(body)["queries"]
            self.queries.extend(qs)
            results = []
            for q in qs:
                key = "%s|%s|%s" % (q["package"]["ecosystem"], q["package"]["name"], q["version"])
                if self.mode == "garbage":
                    return Response(200, b"<html>not json</html>")
                token = q.get("page_token")
                if key in self.pages:
                    pages = self.pages[key]
                    idx = int(token) if token else 0
                    ids = pages[idx]
                    res = {"vulns": [{"id": i} for i in ids]}
                    if idx + 1 < len(pages):
                        res["next_page_token"] = str(idx + 1)
                    results.append(res)
                    continue
                ids = self.answers.get(key, [])
                results.append({"vulns": [{"id": i, "modified": "2026-03-27T00:00:00Z"} for i in ids]} if ids else {})
            return Response(200, json.dumps({"results": results}).encode())
        if path.startswith("/v1/vulns/"):
            if self.mode == "records_down":
                raise OSError("connection reset")
            vid = path[len("/v1/vulns/"):]
            if vid in self.records:
                return Response(200, self.records[vid])
            return Response(404, b'{"code":5,"message":"Bug not found."}')
        return Response(404, b"")
