"""Offline replay of a saved live scan. Set ``OPENTRACE_DEMO_REPLAY`` to select a capture.

The fixture is built by ``tools/demo_replay/build_frigate_3bca9b8_fixture.py`` from a private capture. This module opens no socket,
runs no scanner and calls no provider. It only reconstructs the inputs the live pipeline (``server._run_live_pipeline``) normally
obtains from a scan - the source record, the scanner runs with their original bytes, the source declarations and the advisory
report - so the unchanged assemble/assess/projection code produces the same Workbench views. Every file is checked against the
fixture manifest, and the scan's recorded hashes, before anything is served.
"""
import base64
import hashlib
import json
import os
from types import SimpleNamespace

from opentrace_core.intake.resolve import Response
from opentrace_core.live.scanners import ScanRun
from opentrace_core.live.source import SourceRecord

ENV = "OPENTRACE_DEMO_REPLAY"
BUNDLED_FIXTURE = os.path.join(os.path.dirname(__file__), "demo", "frigate-3bca9b8")
SCHEMA = "opentrace.demo_replay.manifest/1"
_FILES = ("syft-sbom.cdx.json", "cdxgen-cbom.cdx.json", "cisco-aibom.cdx.json", "source-declarations.json", "advisory-lookup.json",
          "bombridge-result.json", "scan-record.json", "advisory-report.json")


class ReplayError(Exception):
    pass


class _Inventory:
    """What the pipeline reads from the lockfile inventory: its status and its summary record."""

    def __init__(self, detail):
        self.status, self.reason, self._detail = detail["status"], detail.get("reason"), detail

    def as_dict(self):
        return dict(self._detail)


class ReplayCapture:
    """One verified, immutable recorded live scan."""

    def __init__(self, directory):
        self.directory = os.path.abspath(directory)
        try:
            with open(os.path.join(self.directory, "MANIFEST.json"), "rb") as handle:
                self.manifest = json.loads(handle.read().decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise ReplayError("replay manifest unreadable") from exc
        if self.manifest.get("schema") != SCHEMA:
            raise ReplayError("unsupported replay manifest")
        self.raw = {}
        for name in _FILES + (("source-inputs.json",) if "source-inputs.json" in self.manifest["files"] else ()):
            meta = self.manifest["files"].get(name)
            try:
                with open(os.path.join(self.directory, name), "rb") as handle:
                    data = handle.read()
            except (OSError, TypeError) as exc:
                raise ReplayError("replay file missing: " + name) from exc
            if meta is None or hashlib.sha256(data).hexdigest() != meta["sha256"] or len(data) != meta["size"]:
                raise ReplayError("replay file does not match its recorded hash: " + name)
            self.raw[name] = data
        self.revision = self.manifest["revision"]
        self.url = self.manifest["repository"]
        self.owner, self.name = self.url.rsplit("/", 2)[-2:]
        self.default_url = "{}/tree/{}".format(self.url, self.revision)
        self.job_id = self.manifest["job_id"]
        record = json.loads(self.raw["scan-record.json"].decode("utf-8"))
        advisory = json.loads(self.raw["advisory-report.json"].decode("utf-8"))
        if record["identity"]["commit"] != self.revision or record["source"]["commit_sha"] != self.revision:
            raise ReplayError("replay record is for another revision")
        self.record = record
        src = dict(record["source"])
        src["skipped"] = tuple(src.get("skipped", ()))
        # Full exported-file listing (verified against tree_sha/listing_sha256 when the fixture was built); else only the files the record cites.
        if record.get("source_inputs") == "full":
            full = json.loads(self.raw["source-inputs.json"].decode("utf-8"))
            if (full["commit_sha"], full["tree_sha"], full["listing_sha256"], full["file_count"]) != (
                    src["commit_sha"], src["tree_sha"], src["listing_sha256"], src["file_count"]) or len(full["inputs"]) != src["file_count"]:
                raise ReplayError("source inputs disagree with the scan record")
            src["inputs"] = tuple({"path": i["path"], "sha256": i["sha256"]} for i in full["inputs"])
        else:
            src["inputs"] = tuple({"path": i["path"], "sha256": i["sha256"]} for i in record["source_inputs_cited"])
        self.source = SourceRecord(**src)
        self.analysis_digest = record["analysis_digest"]
        self.runs = [self._run(r) for r in record["runs"]]
        self.inventory = _Inventory(record["inventory_detail"])
        self.report = advisory["report"]
        self.lookup = SimpleNamespace(queried_at=advisory["queried_at"],
                                      records={vid: {"record": rec} for vid, rec in advisory["records"].items()})
        self.declarations = self._sink(json.loads(self.raw["source-declarations.json"].decode("utf-8")))
        # An isolation description that says what happened here, then what the recorded scan was.
        self.isolation = SimpleNamespace(description=(
            "Recorded replay of a saved live scan (job {}); nothing was scanned or contacted by this session. The saved scan ran in: {}".format(
                self.job_id, record["isolation"])))
        self.live = SimpleNamespace(advisories=object(), isolation=self.isolation, aibom=object())
        limits = self.manifest["limits"]
        self.replay_note = {"job_id": self.job_id, "revision": self.revision, "manifest_sha256": hashlib.sha256(
            json.dumps(self.manifest["files"], sort_keys=True).encode("utf-8")).hexdigest(),
            "limits": [limits["source_inputs"], limits["advisory_report"]]
            + ([] if "source-inputs.json" in self.manifest["files"] else
               ["the model-reference comparison with the AI-BOM is not recomputed: it needs the full exported-file input list, so those references show as not compared"])}

    @staticmethod
    def _sink(doc):
        """Rebuild the collector's result (``status``/``record``/``copies``/``summary``) from the saved derived artifact.

        The artifact stores ``record`` + ``copies`` (base64) + ``record_sha256``; the ``summary`` is exactly the collector's own digest of the
        record's ``searched`` block (``live/source_declarations.collect``), so it is re-derived rather than invented.
        """
        record, searched = doc["record"], doc["record"]["searched"]
        copies = {path: base64.b64decode(item["base64"]) for path, item in doc["copies"].items()}
        for path, item in doc["copies"].items():
            if hashlib.sha256(copies[path]).hexdigest() != item["sha256"]:
                raise ReplayError("a requirement-file copy does not match its recorded hash")
        summary = {"traversal": searched["traversal"], "collected": len(record["requirement_files"]), "matched": searched["requirement_files_matched"]["count"],
                   "skipped": searched["requirement_files_skipped"], "unsupported": searched["unsupported_declaration_files"],
                   "unreadable": searched["directories_unreadable"], "python": searched["python"], "other_languages": searched["other_source_languages"],
                   "local_module": searched["local_module_named_hashlib"], "crypto_sites": len(record["crypto_call_sites"]), "models": searched["model_sources"],
                   "model_references": len(record["model_references"]), "ai_source": record["ai_source"]["summary"],
                   "crypto_source": record["crypto_source"]["summary"], "named_requirements": sum(r["named_requirements"] for r in record["requirement_files"]),
                   "record_sha256": doc["record_sha256"]}
        return {"status": "collected", "record": record, "record_sha256": doc["record_sha256"], "copies": copies, "summary": summary}

    def _run(self, rec):
        data = self.raw[{"sbom": "syft-sbom.cdx.json", "cbom": "cdxgen-cbom.cdx.json", "aibom": "cisco-aibom.cdx.json"}[rec["kind"]]]
        if hashlib.sha256(data).hexdigest() != rec["sha256"] or len(data) != rec["size"]:
            raise ReplayError("scan record disagrees with the artifact bytes: " + rec["kind"])
        fields = {k: v for k, v in rec.items() if k in ScanRun.__dataclass_fields__}
        run = ScanRun(**fields)
        run.data = data
        return run

    def scan_all(self, identity, declarations_sink):
        """The shape of ``live_runner.scan_all``: ``(source, runs, inventory, collected)``; fills the declarations sink."""
        if identity["resolved"]["commit_sha"] != self.revision:
            raise ReplayError("identity is for another revision")
        declarations_sink.clear()
        declarations_sink.update(self.declarations)    # a fresh shallow copy per session; the fixture itself is never handed out
        return self.source, list(self.runs), self.inventory, list(self.record.get("source_checks") or [])

    def advisory(self):
        return self.lookup, self.report

    def advisory_log_bytes(self):
        return self.raw["advisory-lookup.json"]

    def transport(self):
        """Recorded GitHub REST responses for the captured repository only (the I4A resolver)."""
        prefix = "/repos/{}/{}".format(self.owner, self.name)
        sha = self.revision

        def transport(path):
            if not path.lower().startswith(prefix.lower()):
                raise OSError("no recorded response")
            rest = path[len(prefix):]
            if rest == "":
                return Response(200, {"full_name": "{}/{}".format(self.owner, self.name), "default_branch": "dev"})
            if rest.startswith("/commits/"):
                value = rest[len("/commits/"):].lower()
                if len(value) >= 7 and sha.startswith(value):
                    return Response(200, {"sha": sha})
            return Response(404, None)
        return transport


def from_env(environ=None, *, default=None):
    path = (os.environ if environ is None else environ).get(ENV, default)
    return ReplayCapture(path) if path else None
