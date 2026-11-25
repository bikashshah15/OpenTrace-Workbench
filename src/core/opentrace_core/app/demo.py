"""Captured Frigate demo inputs, recorded intake transport and advisory snapshot (I4E).

Offline only: nothing here opens a socket. The recorded transport answers the I4A resolver from
the committed Frigate bundle; unknown repositories raise, which the resolver reports as
``resolution_unavailable``.
"""
import hashlib
import json
import os
from datetime import datetime, timezone

from opentrace_core.bombridge_adapter import ArtifactRecord
from opentrace_core.intake.resolve import Response

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
DEFAULT_FIXTURES = os.path.join(REPO_ROOT, "tests", "core", "bombridge", "fixtures")
ADVISORIES = os.path.join(HERE, "demo", "frigate_advisories.json")
BUNDLE = os.path.join("bundles", "frigate-v0.18.2-cpu-pilot.json")
DEFAULT_URL = "https://github.com/blakeblackshear/frigate/tree/v0.18.2"
SCAN = {"profile_id": "opentrace.scan.default/1", "inventories": ["aibom", "cbom", "sbom"],
        "scope": "repository_root"}
# Pinned digests of the three original Frigate artifacts (I4C oracle / committed fixtures).
PINNED_SBOM_SHA256 = "b7f24bb62503cfe11a8339a27493029f15da0312c94e9c1a01e76e18f285cee9"
# I8: the captured source-declaration record for the same revision (BOMBridge gap-discovery overlay, Peiran Shi) and its requirement-file copies.
SOURCE_DECLARATIONS = os.path.join("inputs", "frigate", "source-declarations.json")
SOURCE_COPIES = os.path.join("inputs", "frigate", "raw", "source")
PINNED_SOURCE_DECLARATIONS_SHA256 = "aada73d87aebbba9f0f65a61d09549b921f5bf8b7c3fbe0e5b510168bc24185c"


class DemoSource:
    """Loads the committed Frigate bundle, raw BOM bytes and the OSV advisory snapshot."""

    def __init__(self, fixtures=DEFAULT_FIXTURES, advisories=ADVISORIES):
        self.fixtures = fixtures
        with open(os.path.join(fixtures, BUNDLE), encoding="utf-8") as handle:
            self.bundle = json.load(handle)
        repo = self.bundle["capture"]["repository"]
        self.url = repo["url"]
        self.revision = repo["revision"]
        self.owner, self.name = self.url.rsplit("/", 2)[-2:]
        self.configuration = self.bundle["capture"]["configuration"]
        self.raw = {}      # inventory_id -> bytes
        self.files = {}    # inventory_id -> artifact name (session safe)
        self.kinds = {}
        self.inventory_meta = {}
        for inv in self.bundle["capture"]["inventories"]:
            if not inv.get("source_sha256"):
                continue
            with open(os.path.join(fixtures, inv["source_file"]), "rb") as handle:
                data = handle.read()
            iid = inv["inventory_id"]
            self.raw[iid] = data
            self.files[iid] = os.path.basename(inv["source_file"]).lower()
            self.kinds[iid] = inv["kind"]
            self.inventory_meta[iid] = {"generator": inv.get("generator"), "label": inv.get("label"),
                                        "format": inv.get("format")}
        self.declarations_sha256 = PINNED_SOURCE_DECLARATIONS_SHA256
        with open(advisories, encoding="utf-8") as handle:
            self.advisories = json.load(handle)
        self.families = {f["key"]: f for f in self.advisories["families"]}
        self.rows_by_ref = {}
        for row in self.advisories["rows"]:
            for ref in row["component_ids"]:
                self.rows_by_ref.setdefault(ref, []).append(row)

    def artifact_records(self, analysis_digest, session_id, generation):
        out = []
        for iid, data in sorted(self.raw.items()):
            doc = json.loads(data)
            kind = self.kinds[iid]
            if kind == "sbom":
                count, unit, counts = len(doc.get("components", [])), "components", {"components": len(doc.get("components", []))}
            elif kind == "cbom":
                count, unit, counts = 0, "crypto_assets", {"crypto_assets": 0, "services": len(doc.get("services", []))}
            else:
                count, unit, counts = len(doc.get("components", [])), "models", {"models": len(doc.get("components", []))}
            out.append(ArtifactRecord("art:" + iid, iid, kind, "acquired", hashlib.sha256(data).hexdigest(),
                                      count, unit, counts, analysis_digest, session_id, generation))
        return out

    def discovery_inputs(self):
        """(source-declaration bytes, reader for its requirement-file copies). Offline fixtures only; collection is not done here.

        The reader maps a repository-relative path from the (digest-pinned) record to a copy under the fixture root and refuses
        anything that is absolute, climbs out, or is not a regular file; the engine then checks each copy's SHA-256.
        """
        with open(os.path.join(self.fixtures, SOURCE_DECLARATIONS), "rb") as handle:
            declarations = handle.read()
        root = os.path.realpath(os.path.join(self.fixtures, SOURCE_COPIES))

        def read_copy(path):
            parts = path.split("/")
            if os.path.isabs(path) or "\\" in path or any(p in ("", ".", "..") for p in parts):
                raise KeyError(path)
            full = os.path.realpath(os.path.join(root, *parts))
            if not full.startswith(root + os.sep) or not os.path.isfile(full):
                raise KeyError(path)
            with open(full, "rb") as handle:
                return handle.read()
        return declarations, read_copy

    def transport(self):
        """Recorded GitHub REST responses for the captured repository only."""
        prefix = "/repos/{}/{}".format(self.owner, self.name)
        sha = self.revision

        def transport(path):
            if not path.lower().startswith(prefix.lower()):
                raise OSError("no recorded response")
            rest = path[len(prefix):]
            if rest == "":
                return Response(200, {"full_name": "{}/{}".format(self.owner, self.name), "default_branch": "dev"})
            if rest == "/git/ref/heads/dev":
                return Response(200, {"ref": "refs/heads/dev", "object": {"type": "commit", "sha": sha}})
            if rest == "/git/ref/tags/v0.18.2":
                return Response(200, {"ref": "refs/tags/v0.18.2", "object": {"type": "commit", "sha": sha}})
            if rest.startswith("/commits/"):
                value = rest[len("/commits/"):].lower()
                if len(value) >= 7 and sha.startswith(value):
                    return Response(200, {"sha": sha})
            return Response(404, None)
        return transport


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)
