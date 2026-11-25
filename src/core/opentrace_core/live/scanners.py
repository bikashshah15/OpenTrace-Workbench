"""Pinned Syft (SBOM) and cdxgen (CBOM) runs over an exported source tree (I5).

Every run returns one ``ScanRun`` record: tool, exact version, scope, outcome and the SHA-256 of the
original output bytes. The outcomes are kept apart on purpose:

* ``acquired``    exit 0 and a valid CycloneDX document. ``record_count`` may be 0: a successful empty
                  CBOM is a completed scan that found no cryptographic asset, not a failure.
* ``failed``      the tool ran and did not produce an acceptable document (non-zero exit, invalid or
                  unsupported output, timeout, oversize output). Rejected bytes are never offered as an
                  artifact; only their digest is recorded.
* ``unavailable`` the scan could not be attempted (tool missing, version differs from the pin, no
                  isolation provider).
* ``cancelled``   the session ended or the analysis was cancelled first.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field

from . import policy
from .isolation import IsolationUnavailable
from . import source as source_mod
from opentrace_core.session.producers import ProcessGroup

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class ProbeUnverified(Exception):
    pass


@dataclass
class ScanRun:
    scanner: str
    kind: str                  # sbom | cbom
    tool: str
    pinned_version: str
    version: str | None = None
    outcome: str = "unavailable"
    reason: str | None = None
    exit_code: int | None = None
    command: str = ""
    isolation: str = ""
    spec_version: str | None = None
    data: bytes | None = None                  # accepted original bytes (acquired only)
    sha256: str | None = None                  # accepted artifact
    size: int | None = None
    rejected_sha256: str | None = None         # output of a failed run: digest only, never served
    record_count: int | None = None
    record_count_unit: str | None = None
    record_counts: dict = field(default_factory=dict)
    meaning: str = ""
    warnings: list = field(default_factory=list)
    log_sha256: str | None = None
    duration_ms: int = 0
    scope: dict = field(default_factory=dict)
    completeness: str | None = None            # AI-BOM only (UIP-07C P6): verified | degraded | skipped | unverified

    def as_dict(self):
        out = {k: v for k, v in self.__dict__.items() if k != "data"}
        out["record_counts"] = dict(self.record_counts)
        if out.get("completeness") is None:
            out.pop("completeness", None)      # not set for SBOM/CBOM runs: their serialised form is unchanged
        return out


def _clean(text, workspace):
    text = _ANSI.sub("", text).replace(workspace, "<workspace>")
    return text.replace(os.path.expanduser("~"), "<home>")


def _warnings(text, workspace, limit=12):
    lines = []
    for raw in _clean(text, workspace).splitlines():
        line = raw.strip()
        if line and line not in lines:
            lines.append(line[:300])
        if len(lines) >= limit:
            break
    return lines


def validate_cyclonedx(data, kind):
    """Return (doc, error_code). A CBOM must be CycloneDX 1.6, the only CBOM version BOMBridge reads."""
    try:
        doc = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, "output_not_json"
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX" or not isinstance(doc.get("specVersion"), str):
        return None, "output_not_cyclonedx"
    comps = doc.get("components", [])
    if not isinstance(comps, list) or not all(isinstance(c, dict) and isinstance(c.get("type"), str) and isinstance(c.get("name"), str) for c in comps):
        return None, "output_components_invalid"
    if kind in ("cbom", "aibom") and doc["specVersion"] != policy.CBOM_SPEC_VERSION:
        return None, "unsupported_spec_version"
    return doc, None


def count_records(doc, kind):
    comps = doc.get("components", [])
    by_type = {}
    for c in comps:
        by_type[c["type"]] = by_type.get(c["type"], 0) + 1
    services = doc.get("services", [])
    services = len(services) if isinstance(services, list) else 0
    if kind == "cbom":
        n = by_type.get("cryptographic-asset", 0)
        return n, "crypto_assets", {"crypto_assets": n, "components": len(comps), "services": services}
    if kind == "aibom":
        # The stage unit is CycloneDX ``components`` (may include non-model components); the AI tab counts projected model rows separately.
        return len(comps), "components", {"components": len(comps)}
    return len(comps), "components", {"components": len(comps)}


def _parse_syft_version(text):
    match = re.search(r"^Version:\s+(\S+)", text or "", re.M)
    return match.group(1).lstrip("v") if match else None


def _version_cdxgen(install_dir):
    try:
        with open(os.path.join(install_dir, "node_modules", "@cyclonedx", "cdxgen", "package.json"), encoding="utf-8") as handle:
            doc = json.load(handle)
        return doc.get("version") if doc.get("name") == "@cyclonedx/cdxgen" else None
    except (OSError, ValueError):
        return None


class ScannerConfig:
    """Where the pinned scanners are installed. Nothing is discovered from the scanned repository."""

    def __init__(self, *, syft_path=None, node_path=None, cdxgen_dir=None, pins=None, scan_seconds=policy.SCAN_SECONDS):
        self.syft_path = syft_path or shutil.which("syft")
        self.node_path = node_path or shutil.which("node")
        self.cdxgen_dir = cdxgen_dir or os.environ.get("OPENTRACE_CDXGEN_DIR")
        self.pins = dict(pins or policy.SCANNER_PINS)
        self.scan_seconds = scan_seconds
        self.cdxgen_seconds = scan_seconds


def _scrubbed_env(home, tmp):
    return {"PATH": "/var/empty", "HOME": home, "TMPDIR": tmp, "CDXGEN_TEMP_DIR": tmp, "NO_COLOR": "1", "LANG": "C",
            "SYFT_CHECK_FOR_APP_UPDATE": "false", "CDXGEN_THREAD_COUNT": "1"}


def _execute(argv, *, cwd, env, seconds, cancel, register, out_path):
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    group = ProcessGroup(process)
    if register:
        register(group)
    chunks, size = [], [0]

    def drain():
        try:
            while True:
                block = process.stdout.read(8192)
                if not block:
                    return
                if size[0] < policy.MAX_LOG_BYTES * 4:
                    chunks.append(block)
                    size[0] += len(block)
        finally:
            process.stdout.close()

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    deadline = time.monotonic() + seconds
    reason = None
    while process.poll() is None:
        if cancel.is_set():
            reason = "cancelled"
        elif time.monotonic() > deadline:
            reason = "timeout"
        else:
            try:
                if os.path.exists(out_path) and os.path.getsize(out_path) > policy.MAX_SCANNER_OUTPUT:
                    reason = "output_too_large"
            except OSError:
                pass
        if reason:
            group.signal(signal.SIGKILL)
            break
        time.sleep(0.05)
    verified = group.kill_and_confirm(source_mod.GROUP_CONFIRM_SECONDS)  # bounded; confirms the leader too
    source_mod._close_pipes([thread], [process.stdout], verified)
    if not verified:
        reason = "cleanup_unverified"  # outranks cancelled/timeout: the scanner's group is not known to be gone
    return reason, process.returncode, b"".join(chunks)


def evaluate_output(run, spec, kind, reason, code, data):
    """Decide a ScanRun's outcome from what a scanner left behind (shared by the local and worker paths).

    ``reason`` is a stop reason (timeout, output_too_large, ...) or None; ``code`` the exit code; ``data``
    the raw output bytes or None. Rejected bytes are never offered; only their digest is recorded.
    """
    if reason:
        run.outcome, run.reason = "failed", reason
    elif code != 0:
        run.outcome, run.reason = "failed", "nonzero_exit"
    elif data is None:
        run.outcome, run.reason = "failed", "no_output"
    else:
        doc, error = validate_cyclonedx(data, kind)
        if error:
            run.outcome, run.reason = "failed", error
        else:
            run.outcome, run.data, run.size = "acquired", data, len(data)
            run.sha256 = hashlib.sha256(data).hexdigest()
            run.spec_version = doc["specVersion"]
            run.record_count, run.record_count_unit, run.record_counts = count_records(doc, kind)
            run.meaning = spec["empty_meaning"] if run.record_count == 0 else ""
    if run.outcome == "failed" and data is not None:
        run.rejected_sha256 = hashlib.sha256(data).hexdigest()
    return run


def run_scanner(spec, config, isolation, source, workspace, *, cancel, register=None):
    """Run one scanner and return its ScanRun. Never raises for a scanner problem."""
    kind, name = spec["kind"], spec["scanner"]
    run = ScanRun(scanner=name, kind=kind, tool=spec["tool"], pinned_version=config.pins[name], isolation=isolation.name,
                  scope={"basis": "whole repository tree exported from the pinned commit (blobs only; symlinks and submodules not materialised)",
                         "file_count": source.file_count, "listing_sha256": source.listing_sha256, "paths": ["."],
                         "revision": source.commit_sha, "tree_sha": source.tree_sha})
    started = time.monotonic()
    src = os.path.join(workspace, "src")
    out_dir = os.path.join(workspace, "out-" + name)
    home = os.path.join(workspace, "home-" + name)
    tmp = os.path.join(workspace, "tmp-" + name)
    for path in (out_dir, home, tmp):
        os.makedirs(path, mode=0o700, exist_ok=True)
    out_path = os.path.join(out_dir, spec["output"])
    try:
        resolved = spec["resolve"](config)
        if resolved is None:
            run.reason = "tool_not_found"
            return run
        argv, exec_paths, read_paths, version = resolved
        if callable(version):
            # The version probe executes the scanner binary too: same boundary, same session tracking.
            def probe(probe_argv):
                wrapped_probe = isolation.wrap(probe_argv, read_paths=list(read_paths) + [src], write_paths=[out_dir, home, tmp], exec_paths=exec_paths)
                reason_p, code_p, log_p = _execute(wrapped_probe, cwd=src, env=_scrubbed_env(home, tmp), seconds=20, cancel=cancel,
                                                   register=register, out_path=os.path.join(out_dir, ".probe"))
                if reason_p == "cleanup_unverified":
                    raise ProbeUnverified()
                return log_p.decode("utf-8", "replace") if code_p == 0 and not reason_p else None
            try:
                version = version(probe)
            except IsolationUnavailable as exc:
                run.reason, run.warnings = "isolation_unavailable", [exc.reason]
                return run
            except ProbeUnverified:
                run.outcome, run.reason = "failed", "cleanup_unverified"
                run.warnings = ["the version probe's process group could not be confirmed gone"]
                return run
            if cancel.is_set():
                run.outcome, run.reason = "cancelled", "cancelled"
                return run
        run.version = version
        if version != config.pins[name]:
            run.reason = "version_mismatch"
            run.warnings = ["installed version {} differs from the pinned version {}".format(version or "unknown", config.pins[name])]
            return run
        run.command = spec["display"].format(version=version)
        argv = [a.replace("{out}", out_path) for a in argv]
        try:
            wrapped = isolation.wrap(argv, read_paths=list(read_paths) + [src], write_paths=[out_dir, home, tmp], exec_paths=exec_paths)
        except IsolationUnavailable as exc:
            run.reason = "isolation_unavailable"
            run.warnings = [exc.reason]
            return run
        reason, code, log = _execute(wrapped, cwd=src, env=_scrubbed_env(home, tmp), seconds=getattr(config, name + "_seconds", config.scan_seconds),
                                     cancel=cancel, register=register, out_path=out_path)
        run.exit_code = code
        run.log_sha256 = hashlib.sha256(log).hexdigest()
        run.warnings = _warnings(log.decode("utf-8", "replace"), workspace)
        if reason == "cleanup_unverified":
            run.outcome, run.reason = "failed", "cleanup_unverified"
            run.warnings = ["the scanner's process group could not be confirmed gone; its output was discarded"] + run.warnings
            return run
        if reason == "cancelled":
            run.outcome, run.reason = "cancelled", "cancelled"
            return run
        data = None
        if os.path.isfile(out_path) and not os.path.islink(out_path):
            if os.path.getsize(out_path) > policy.MAX_SCANNER_OUTPUT:
                run.outcome, run.reason = "failed", "output_too_large"
                return run
            with open(out_path, "rb") as handle:
                data = handle.read()
        evaluate_output(run, spec, kind, reason, code, data)
        return run
    finally:
        run.duration_ms = int((time.monotonic() - started) * 1000)
        for path in (out_dir, home, tmp):
            shutil.rmtree(path, ignore_errors=True)


def _resolve_syft(config):
    path = config.syft_path
    if not path or not os.access(path, os.X_OK):
        return None
    real = os.path.realpath(path)
    version = lambda probe: _parse_syft_version(probe([real, "version"]))
    argv = [real, "scan", "dir:.", "-o", "cyclonedx-json={out}", "-q"]
    return argv, [real], [os.path.dirname(real)], version


def _resolve_cdxgen(config):
    if not (config.cdxgen_dir and config.node_path and os.access(config.node_path, os.X_OK)):
        return None
    script = os.path.join(config.cdxgen_dir, "node_modules", "@cyclonedx", "cdxgen", "bin", "cdxgen.js")
    if not os.path.isfile(script):
        return None
    node = os.path.realpath(config.node_path)
    version = _version_cdxgen(config.cdxgen_dir)
    argv = [node, script, "-r", ".", "--no-install-deps", "--include-crypto", "--evidence",
            "--spec-version", policy.CBOM_SPEC_VERSION, "-o", "{out}"]
    return argv, [node], [os.path.realpath(config.cdxgen_dir), os.path.dirname(os.path.dirname(node))], version


SYFT = {"scanner": "syft", "kind": "sbom", "tool": "Syft", "output": "syft.cdx.json", "resolve": _resolve_syft,
        "display": "syft {version} scan dir:. -o cyclonedx-json -q",
        "empty_meaning": "a successful scan that reported no components; not a failed scan"}
CDXGEN = {"scanner": "cdxgen", "kind": "cbom", "tool": "cdxgen", "output": "cdxgen.cbom.cdx.json", "resolve": _resolve_cdxgen,
          "display": "cdxgen {version} -r . --no-install-deps --include-crypto --evidence --spec-version 1.6",
          "empty_meaning": "a successful scan that reported no cryptographic asset; not a failed scan, and not evidence that no cryptography is used"}
