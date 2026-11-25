"""Immutable capture sets and bundle manifests (I2-REQ-04, section 3.4).

A capture set directory is named by the hex of its manifest digest:

  <hex>/capture_manifest.json   canonical bytes; the preimage of the set ID (contains no set ID)
  <hex>/CAPTURE_SET_ID          sidecar "sha256:<hex>\\n", excluded from every hash
  <hex>/blobs/<hex>             verbatim request/response bytes (write-once, read-only)

Core never touches the network. Real captures come from tools/i2/acquire.py (class A2); the
builder here is also used by tests with entries labelled synthetic.
"""
import json
import os
import re
from pathlib import Path

from .canon import canonical_bytes, digest_of_bytes
from .artifacts import hex_of

SCHEMA = "opentrace.capture_manifest/1"
ENTRY_FIELDS = ("capture_id", "kind", "method", "url", "status", "headers", "captured_at", "request_digest",
                "response_digest", "bytes", "network_phase", "provenance", "acquirer", "redirect_hops", "attempt")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class CaptureError(Exception):
    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code, self.detail = code, detail


class CaptureBuilder:
    """Collects entries and blobs, then writes a new, write-once capture set."""

    def __init__(self, acquirer, provenance="real"):
        self.acquirer, self.provenance = acquirer, provenance
        self.entries, self.blobs = [], {}

    def add(self, kind, method, url, status, headers, captured_at, request=None, response=None,
            redirect_hops=None, attempt=1, network_phase="controlled_acquisition"):
        if not _TS.match(captured_at):
            raise ValueError("captured_at must be YYYY-MM-DDTHH:MM:SSZ")
        entry = {"capture_id": "c%03d" % (len(self.entries) + 1), "kind": kind, "method": method, "url": url,
                 "status": status, "headers": {k.lower(): v for k, v in sorted((headers or {}).items())},
                 "captured_at": captured_at,
                 "request_digest": digest_of_bytes(request) if request is not None else None,
                 "response_digest": digest_of_bytes(response) if response is not None else None,
                 "bytes": len(response) if response is not None else len(request or b""),
                 "network_phase": network_phase, "provenance": self.provenance, "acquirer": self.acquirer,
                 "redirect_hops": list(redirect_hops or []), "attempt": attempt}
        for body in (request, response):
            if body is not None:
                self.blobs[digest_of_bytes(body)] = body
        self.entries.append(entry)
        return entry

    def manifest_bytes(self):
        return canonical_bytes({"schema": SCHEMA, "captures": self.entries})

    def write(self, out_root):
        data = self.manifest_bytes()
        set_id = digest_of_bytes(data)
        target = Path(out_root) / hex_of(set_id)
        if target.exists():
            raise CaptureError("capture_set_exists", "refusing to overwrite capture set %s" % set_id)
        (target / "blobs").mkdir(parents=True)
        for digest, body in self.blobs.items():
            path = target / "blobs" / hex_of(digest)
            path.write_bytes(body)
            os.chmod(path, 0o444)
        manifest = target / "capture_manifest.json"
        manifest.write_bytes(data)
        os.chmod(manifest, 0o444)
        sidecar = target / "CAPTURE_SET_ID"
        sidecar.write_text(set_id + "\n")
        os.chmod(sidecar, 0o444)
        return target


class CaptureSet:
    def __init__(self, directory):
        self.dir = Path(directory)
        try:
            self.manifest_raw = (self.dir / "capture_manifest.json").read_bytes()
            self.manifest = json.loads(self.manifest_raw)
        except (OSError, ValueError) as err:
            raise CaptureError("capture_missing", "capture_manifest.json: %s" % type(err).__name__)
        self.id = digest_of_bytes(self.manifest_raw)
        self.entries = self.manifest.get("captures", [])

    def verify(self):
        """Return a list of (code, detail); empty means the set is intact."""
        problems = []
        if self.manifest_raw != canonical_bytes(self.manifest):
            problems.append(("capture_set_id_mismatch", "manifest is not in canonical form"))
        if hex_of(self.id) != self.dir.name:
            problems.append(("capture_set_id_mismatch", "directory name is not the manifest digest"))
        sidecar = self.dir / "CAPTURE_SET_ID"
        if not sidecar.is_file() or sidecar.read_text().strip() != self.id:
            problems.append(("capture_set_id_mismatch", "CAPTURE_SET_ID sidecar differs from the manifest digest"))
        if self.manifest.get("schema") != SCHEMA:
            problems.append(("capture_integrity_failure", "unknown manifest schema"))
        seen = set()
        for i, e in enumerate(self.entries):
            if tuple(sorted(e)) != tuple(sorted(ENTRY_FIELDS)) or e.get("capture_id") != "c%03d" % (i + 1):
                problems.append(("capture_integrity_failure", "entry %d has unexpected fields or id" % (i + 1)))
                continue
            for field in ("request_digest", "response_digest"):
                digest = e[field]
                if digest is None or digest in seen:
                    continue
                seen.add(digest)
                path = self.dir / "blobs" / hex_of(digest)
                if not path.is_file():
                    problems.append(("capture_missing", "blob %s (%s)" % (digest, e["capture_id"])))
                elif digest_of_bytes(path.read_bytes()) != digest:
                    problems.append(("capture_integrity_failure", "blob %s differs from its digest" % digest))
            body = e["response_digest"] or e["request_digest"]
            if body and (self.dir / "blobs" / hex_of(body)).is_file() and \
                    len((self.dir / "blobs" / hex_of(body)).read_bytes()) != e["bytes"]:
                problems.append(("capture_integrity_failure", "%s byte count differs" % e["capture_id"]))
        return problems

    def blob(self, digest):
        path = self.dir / "blobs" / hex_of(digest)
        if not path.is_file():
            raise CaptureError("capture_missing", digest)
        data = path.read_bytes()
        if digest_of_bytes(data) != digest:
            raise CaptureError("capture_integrity_failure", digest)
        return data

    def real_only(self):
        return all(e["provenance"] == "real" for e in self.entries)

    # -- bundle manifests (inputs for the Specialist) ------------------------------------------
    def _osv_requests_use_bare_versions(self):
        """True when the captured OSV batch request names versions without the leading "v"."""
        for e in self.entries:
            if e["kind"] == "osv_querybatch" and e["request_digest"]:
                try:
                    queries = json.loads(self.blob(e["request_digest"]))["queries"]
                except (CaptureError, ValueError, KeyError):
                    return False
                versions = [q.get("version", "") for q in queries]
                return bool(versions) and not any(v.startswith("v") for v in versions)
        return False

    def osv_bundle(self, planned, skipped=()):
        """planned: [(module, version)] to evaluate; skipped: [(module, version_or_None, reason)]."""
        rounds, records = [], {}
        for e in self.entries:
            if e["kind"] == "osv_querybatch":
                item = {"request": e["request_digest"], "response": e["response_digest"], "status": e["status"] or 0}
                if rounds and rounds[-1]["request"] == item["request"]:
                    rounds[-1] = item            # a retried attempt of the same request replaces the failed one
                else:
                    rounds.append(item)
            elif e["kind"] == "osv_vuln":
                vid = e["url"].rstrip("/").rsplit("/", 1)[-1]
                records[vid] = {"digest": e["response_digest"], "status": e["status"] or 0}
        bare = self._osv_requests_use_bare_versions()
        # The key must equal what the captured request carries (the OSV form settled by the acquisition
        # probe); `version` keeps the module version as the fixture states it.
        def key(m, v):
            v = v or ""
            return "%s@%s" % (m, v.lstrip("v") if bare else v)
        queries = [{"query_key": key(m, v), "module": m, "version": v} for m, v in planned]
        queries += [{"query_key": key(m, v), "module": m, "version": v or "", "skip_reason": r}
                    for m, v, r in skipped]
        bundle = {"schema": "opentrace.bundle_manifest/1", "kind": "osv", "capture_set_id": self.id,
                  "queries": queries, "rounds": rounds, "records": records}
        return canonical_bytes(bundle)

    def vulndb_bundle(self):
        files = []
        for e in self.entries:
            if e["kind"] == "vulndb_file" and e["status"] == 200:
                path = e["url"].split("://", 1)[1].split("/", 1)[1]
                files.append({"path": path, "digest": e["response_digest"]})
        files.sort(key=lambda f: f["path"])
        return canonical_bytes({"schema": "opentrace.bundle_manifest/1", "kind": "vulndb", "capture_set_id": self.id,
                                "db_url": "https://vuln.go.dev", "files": files})

    def provenance_blob(self, kind):
        for e in self.entries:
            if e["kind"] == kind:
                return e["response_digest"]
        return None

    def ingest(self, store, extra=()):
        """Put every referenced blob into an ArtifactStore (verified, write-once). Returns the digests."""
        out = []
        for e in self.entries:
            for field in ("request_digest", "response_digest"):
                d = e[field]
                if d and d not in out:
                    store.put_checked(d, self.blob(d), media_type="application/octet-stream",
                                      producer="capture:%s" % self.id, revision_binding="unbound")
                    out.append(d)
        return out
