"""Shared helpers for the OpenTrace evaluation package (E1-E5).

Everything here is standard library except the optional ``psutil`` (memory sampling) and ``PyYAML`` (config; already a pinned
OpenTrace dev dependency). Nothing in this module imports the OpenTrace verification engine: the engine is imported lazily by the
experiment modules that need it, after :func:`bootstrap_paths` has put the checkout on ``sys.path``.

Conventions used by every experiment
------------------------------------
* A run writes to ``<output_root>/<run_id>/`` and never overwrites an existing run directory (immutable per-run outputs).
* Every record carries a ``provenance_tier`` (``captured``, ``external_reference``, ``controlled``, ``live_new``); see PROVENANCE_TIERS.
* A rate is always reported as ``{"n": .., "N": .., "rate": ..}``; an empty denominator gives ``rate: None`` (never 0 or 100).
* Unavailable inputs or tools are recorded as ``not_run`` with a reason; harness defects raise :class:`HarnessError`.
"""
from __future__ import annotations

import csv
import datetime as _dt
import hashlib
import importlib.metadata as _md
import io
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterable

# ----------------------------------------------------------------------------------------------------------------- constants
PROVENANCE_TIERS = {
    "captured": "original, hash-verified recorded inventory/source evidence; a scanner record is not ground truth",
    "external_reference": "upstream published declarations/annotations or independently inspected public source",
    "controlled": "synthetic or mutated inventory, manifest or observation assembled for a known verification test",
    "live_new": "new acquisition with full pinned provenance and actual scanner results",
}
# Common assessment states used to compare methods (frozen before scoring; see e2_e3_verification.STATE_MAP).
COMMON_STATES = ("supported", "contradicted", "conflicting", "unverifiable", "refused", "error", "timeout", "not_run", "not_applicable")
DEFINITIVE_STATES = ("supported", "contradicted")
ABSTAIN_STATES = ("unverifiable", "refused")
FAILURE_STATES = ("error", "timeout", "not_run")

EVAL_SCHEMA_VERSION = "opentrace.evaluation/1"
OPENTRACE_MARKER = os.path.join("src", "core", "opentrace_core", "bombridge", "pipeline.py")


class HarnessError(RuntimeError):
    """An evaluation-harness defect or an invalid evaluation input (distinct from a measured method failure)."""


class NotRunError(RuntimeError):
    """A prerequisite (input, tool, dependency) is unavailable: the step is reported as ``not_run`` with this reason."""


# ----------------------------------------------------------------------------------------------------------------- paths
def default_opentrace_root() -> str:
    """``tools/evaluation/common.py`` -> the checkout root two levels above ``tools``."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def bootstrap_paths(opentrace_root: str) -> str:
    """Make ``opentrace_core``, the investigator agent and the repository root (``tests.*``, ``tools.*``) importable.

    Mirrors ``PYTHONPATH=src/core:src/agents/investigator`` from docs/REPRODUCIBILITY.md, plus the root for test helpers.
    Returns the absolute root. Raises HarnessError if the root does not look like an OpenTrace checkout.
    """
    root = os.path.abspath(opentrace_root)
    if not os.path.isfile(os.path.join(root, OPENTRACE_MARKER)):
        raise HarnessError(f"not an OpenTrace checkout (missing {OPENTRACE_MARKER}): {root}")
    for p in (os.path.join(root, "src", "agents", "investigator"), os.path.join(root, "src", "core"), root):
        if p not in sys.path:
            sys.path.insert(0, p)
    return root


def resolve_path(path: str | None, base: str) -> str | None:
    """Relative config paths are resolved against ``base`` (the OpenTrace root); ``None`` stays ``None``."""
    if path in (None, ""):
        return None
    path = os.path.expanduser(str(path))
    return os.path.abspath(path if os.path.isabs(path) else os.path.join(base, path))


def redact(text: Any, root: str | None) -> Any:
    """Replace absolute local prefixes in strings (recursively) so paper artifacts carry no private paths."""
    home = os.path.expanduser("~")
    if isinstance(text, str):
        if root:
            text = text.replace(os.path.abspath(root), "<opentrace-root>")
        return text.replace(home, "<home>") if home and home != "/" else text
    if isinstance(text, dict):
        return {k: redact(v, root) for k, v in text.items()}
    if isinstance(text, list):
        return [redact(v, root) for v in text]
    return text


# ----------------------------------------------------------------------------------------------------------------- hashing / canonical JSON
def read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def read_text(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON bytes (sorted keys, compact separators, UTF-8)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_sha256(obj: Any) -> str:
    return sha256_bytes(canonical_bytes(obj))


def document_bytes(doc: Any) -> bytes:
    """The serialisation used for every *controlled* BOM document written by this package (stable, human-readable)."""
    return (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def tree_listing(root: str, *, exclude_dirs: Iterable[str] = (".git", "__pycache__", "node_modules")) -> list[dict]:
    """Sorted ``[{path, sha256, size}]`` for every regular file below ``root`` (symlinks are recorded, never followed)."""
    out = []
    skip = set(exclude_dirs)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full):
                out.append({"path": rel, "sha256": None, "size": None, "symlink": True})
                continue
            out.append({"path": rel, "sha256": sha256_file(full), "size": os.path.getsize(full)})
    return out


def listing_sha256(listing: list[dict]) -> str:
    return canonical_sha256([[x["path"], x["sha256"]] for x in listing])


def content_revision_token(listing_digest: str) -> str:
    """A 40-hex *content-derived* revision token for inputs without Git history (e.g. a ZIP download).

    It is NOT a Git commit and is always reported with ``revision_kind: content_derived_not_git``; OpenTrace's acquisition
    manifests require a 40-hex revision string, so the token only serves as an equality key inside controlled bundles.
    """
    return hashlib.sha1(("opentrace-eval-content-token:" + listing_digest).encode()).hexdigest()


def git_revision(path: str) -> dict:
    """``{"git_sha": .., "available": bool, "reason": ..}`` when Git metadata exists.

    Linked worktrees store ``.git`` as a text file pointing at their worktree metadata, so checking only for a directory would
    incorrectly mark a clean worktree as an extracted archive.
    """
    if not os.path.exists(os.path.join(path, ".git")):
        return {"git_sha": None, "available": False, "reason": "no .git metadata (e.g. extracted archive); Git revision unavailable"}
    git = shutil.which("git")
    if not git:
        return {"git_sha": None, "available": False, "reason": "git executable not found"}
    try:
        sha = subprocess.run([git, "-C", path, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=20, check=True).stdout.strip()
        dirty = subprocess.run([git, "-C", path, "status", "--porcelain"], capture_output=True, text=True, timeout=60).stdout.strip() != ""
        return {"git_sha": sha, "available": True, "dirty_worktree": dirty, "reason": None}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"git_sha": None, "available": False, "reason": f"git rev-parse failed: {type(exc).__name__}"}


# ----------------------------------------------------------------------------------------------------------------- config
DEFAULT_CONFIG_NAME = os.path.join(os.path.dirname(__file__), "config.yaml")


def load_config(path: str | None = None, overrides: dict | None = None) -> dict:
    """Load YAML (PyYAML) or JSON config and apply dotted-key overrides (``{"e5.repetitions": 3}``)."""
    path = path or DEFAULT_CONFIG_NAME
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # PyYAML is pinned in requirements-dev.txt
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise HarnessError("PyYAML is required to read a YAML config (pip install -r requirements-dev.txt)") from exc
        cfg = yaml.safe_load(text) or {}
    else:
        cfg = json.loads(text)
    if not isinstance(cfg, dict):
        raise HarnessError(f"config {path} must be a mapping")
    for key, value in (overrides or {}).items():
        set_dotted(cfg, key, value)
    cfg["_config_path"] = os.path.abspath(path)
    cfg["_config_sha256"] = sha256_file(path)
    return cfg


def set_dotted(cfg: dict, key: str, value: Any) -> None:
    cur = cfg
    parts = key.split(".")
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = value


def get_dotted(cfg: dict, key: str, default: Any = None) -> Any:
    cur: Any = cfg
    for p in key.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


# ----------------------------------------------------------------------------------------------------------------- run context / output
def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id(prefix: str = "run") -> str:
    return f"{prefix}-{_dt.datetime.now(_dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"


class RunContext:
    """One evaluation run: an immutable output directory, the seed, the config, and a JSONL event log."""

    def __init__(self, cfg: dict, *, output_root: str, run_id: str | None = None, opentrace_root: str, allow_existing: bool = False):
        self.cfg = cfg
        self.opentrace_root = os.path.abspath(opentrace_root)
        self.run_id = run_id or new_run_id()
        self.out = os.path.join(os.path.abspath(output_root), self.run_id)
        if os.path.exists(self.out) and not allow_existing:
            raise HarnessError(f"run directory exists (outputs are immutable per run): {self.out}")
        os.makedirs(os.path.join(self.out, "logs"), exist_ok=True)
        self.seed = int(cfg.get("seed", 0))
        self._log = os.path.join(self.out, "logs", "events.jsonl")
        self.statuses: dict[str, dict] = {}

    def path(self, *parts: str) -> str:
        p = os.path.join(self.out, *parts)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def subdir(self, *parts: str) -> str:
        p = os.path.join(self.out, *parts)
        os.makedirs(p, exist_ok=True)
        return p

    def rng(self, purpose: str) -> random.Random:
        """A deterministic RNG per purpose (seed and purpose string are both recorded)."""
        return random.Random(f"{self.seed}:{purpose}")

    def log(self, event: str, **fields: Any) -> None:
        rec = {"t": utc_now(), "event": event, **fields}
        with open(self._log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(redact(rec, self.opentrace_root), sort_keys=True, default=str) + "\n")

    def status(self, experiment: str, status: str, reason: str | None = None, **extra: Any) -> dict:
        """Record the outcome of one experiment/step: completed | partial | not_run | harness_error."""
        assert status in ("completed", "partial", "not_run", "harness_error", "skipped_by_config"), status
        rec = {"experiment": experiment, "status": status, "reason": reason, "t": utc_now(), **extra}
        self.statuses[experiment] = rec
        write_json(self.path("run_status.json"), self.statuses)
        self.log("status", **rec)
        return rec


def write_json(path: str, obj: Any, *, root: str | None = None) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    data = redact(obj, root) if root else obj
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, sort_keys=True, indent=2, ensure_ascii=False, default=_json_default)
        fh.write("\n")
    return path


def read_json(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_jsonl(path: str, rows: Iterable[Any], *, root: str | None = None) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(redact(r, root) if root else r, sort_keys=True, ensure_ascii=False, default=_json_default) + "\n")
    return path


def read_jsonl(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def write_csv(path: str, rows: list[dict], fieldnames: list[str] | None = None) -> str:
    """Write rows; nested values are JSON-encoded; ``None`` becomes an empty cell. Header is written even for zero rows."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    if fieldnames is None:
        fieldnames = []
        for r in rows:
            for k in r:
                if k not in fieldnames:
                    fieldnames.append(k)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _cell(r.get(k)) for k in fieldnames})
    return path


def read_csv(path: str) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _cell(v: Any) -> Any:
    if v is None:
        return ""
    if isinstance(v, (dict, list, tuple)):
        return json.dumps(v, sort_keys=True, ensure_ascii=False, default=_json_default)
    return v


def _json_default(o: Any) -> Any:
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    if isinstance(o, bytes):
        return {"__bytes_sha256__": sha256_bytes(o), "size": len(o)}
    if hasattr(o, "as_dict"):
        return o.as_dict()
    return repr(o)


def markdown_table(rows: list[dict], columns: list[str], headers: list[str] | None = None) -> str:
    headers = headers or columns
    out = io.StringIO()
    out.write("| " + " | ".join(headers) + " |\n")
    out.write("|" + "|".join("---" for _ in headers) + "|\n")
    for r in rows:
        out.write("| " + " | ".join(str(_cell(r.get(c))).replace("|", "\\|") for c in columns) + " |\n")
    return out.getvalue()


# ----------------------------------------------------------------------------------------------------------------- metrics helpers
def rate(n: int, N: int) -> dict:
    """``{"n", "N", "rate"}``; ``rate`` is ``None`` for an empty denominator (never reported as 0% or 100%)."""
    return {"n": int(n), "N": int(N), "rate": (n / N) if N else None}


def fmt_rate(r: dict | None, digits: int = 3) -> str:
    if not r or r.get("N") in (None, 0) or r.get("rate") is None:
        return "N/A" if not r else f"{r.get('n', 0)}/{r.get('N', 0)} (N/A)"
    return f"{r['n']}/{r['N']} ({r['rate']:.{digits}f})"


def percentile(values: list[float], q: float) -> float | None:
    """Linear-interpolation percentile (Hyndman-Fan type 7, numpy's default); ``q`` in [0, 1]. ``None`` for no values."""
    if not values:
        return None
    xs = sorted(values)
    if len(xs) == 1:
        return float(xs[0])
    h = (len(xs) - 1) * q
    lo = int(h)
    hi = min(lo + 1, len(xs) - 1)
    return float(xs[lo] + (h - lo) * (xs[hi] - xs[lo]))


def summary_stats(values: list[float]) -> dict:
    """median / q1 / q3 / IQR (type-7 quantiles), min, max, n."""
    if not values:
        return {"n": 0, "median": None, "q1": None, "q3": None, "iqr": None, "min": None, "max": None, "quantile_method": "type7_linear"}
    q1, med, q3 = percentile(values, 0.25), percentile(values, 0.5), percentile(values, 0.75)
    return {"n": len(values), "median": med, "q1": q1, "q3": q3, "iqr": (q3 - q1), "min": min(values), "max": max(values),
            "quantile_method": "type7_linear"}


# ----------------------------------------------------------------------------------------------------------------- environment / provenance
def _pkg_version(name: str) -> str | None:
    try:
        return _md.version(name)
    except _md.PackageNotFoundError:
        return None


def memory_total_bytes() -> int | None:
    try:
        import psutil  # optional
        return int(psutil.virtual_memory().total)
    except ImportError:
        pass
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    if sys.platform == "darwin":
        try:
            return int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=5).stdout.strip())
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
    return None


def cpu_model() -> str | None:
    try:
        with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    if sys.platform == "darwin":
        try:
            return subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True, timeout=5).stdout.strip() or None
        except (OSError, subprocess.SubprocessError):
            return None
    return platform.processor() or None


def tool_version(executable: str | None, args: tuple = ("--version",), timeout: int = 30) -> dict:
    """Locate an external CLI and record ``--version`` output; never installs or downloads anything."""
    if not executable:
        return {"available": False, "path": None, "version_output": None, "reason": "not configured"}
    path = shutil.which(executable) or (executable if os.path.isfile(executable) and os.access(executable, os.X_OK) else None)
    if not path:
        return {"available": False, "path": None, "version_output": None, "reason": f"{executable!r} not found on PATH"}
    try:
        p = subprocess.run([path, *args], capture_output=True, text=True, timeout=timeout)
        return {"available": True, "path": path, "version_output": (p.stdout or p.stderr).strip()[:500], "exit_code": p.returncode, "reason": None}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "path": path, "version_output": None, "reason": f"{type(exc).__name__} while running --version"}


def environment_info(cfg: dict | None = None) -> dict:
    """Python / OS / CPU / RAM / key dependency versions / external tools (no network)."""
    cfg = cfg or {}
    tools = (cfg.get("external_tools") or {})
    return {
        "captured_at": utc_now(),
        "python": {"version": sys.version, "implementation": platform.python_implementation(), "executable_basename": os.path.basename(sys.executable)},
        "os": {"system": platform.system(), "release": platform.release(), "version": platform.version(), "machine": platform.machine(),
               "platform": platform.platform()},
        "cpu": {"model": cpu_model(), "logical_cpus": os.cpu_count()},
        "memory_total_bytes": memory_total_bytes(),
        "packages": {n: _pkg_version(n) for n in ("jsonschema", "PyYAML", "networkx", "psutil", "packaging")},
        "external_tools": {name: tool_version(exe) for name, exe in sorted(tools.items())},
        "env": {k: os.environ.get(k) for k in ("PYTHONHASHSEED", "OPENTRACE_DEMO_REPLAY") if k in os.environ},
    }


@contextmanager
def immutability_guard(paths: dict[str, str], ctx: "RunContext | None" = None, label: str = "inputs"):
    """Hash every file below each path before and after the block; record and raise on any change.

    Used to show that the replay fixture, the external benchmarks and production code were not modified by a run.
    """
    before = {k: listing_sha256(tree_listing(p)) if os.path.isdir(p) else (sha256_file(p) if os.path.isfile(p) else None)
              for k, p in paths.items() if p}
    yield before
    after = {k: listing_sha256(tree_listing(p)) if os.path.isdir(p) else (sha256_file(p) if os.path.isfile(p) else None)
             for k, p in paths.items() if p}
    changed = sorted(k for k in before if before[k] != after.get(k))
    rec = {"label": label, "before": before, "after": after, "changed": changed, "unchanged": not changed}
    if ctx is not None:
        write_json(ctx.path("logs", f"immutability_{label}.json"), rec)
    if changed:
        raise HarnessError(f"inputs were modified during the run ({label}): {changed}")


class Timer:
    """``with Timer() as t: ...; t.ns`` using ``time.perf_counter_ns``."""

    def __enter__(self):
        self.start = time.perf_counter_ns()
        self.ns = None
        return self

    def __exit__(self, *exc):
        self.ns = time.perf_counter_ns() - self.start
        return False

    @property
    def seconds(self) -> float | None:
        return None if self.ns is None else self.ns / 1e9


def stable_sample(items: list, k: int, rng: random.Random, key=lambda x: x) -> list:
    """Seeded sample that does not depend on input order (items are sorted by ``key`` first)."""
    xs = sorted(items, key=key)
    if k >= len(xs):
        return xs
    return sorted(rng.sample(xs, k), key=key)
