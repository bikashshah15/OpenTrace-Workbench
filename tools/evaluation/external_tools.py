"""Bounded adapters for the E3-B external document tools (CycloneDX CLI ``validate``, ``sbom-tools diff``).

Extends ``baselines.py`` (which is left unchanged, so the completed E2/E3 code paths are untouched) for two measurement issues:

* its CycloneDX adapter reads every nonzero exit as "invalid"; here a rejection counts only with the tool's own rejection message;
* its ``sbom-tools diff`` call requests no output format; here ``-o json`` is required and the JSON is parsed strictly.

An operation the installed release does not document is ``unsupported_operation``; output that cannot be interpreted is
``unclassified`` / ``unparsed_output``. Neither is ever counted as a wrong answer or as a success.

Message and schema expectations come from the public sources at cyclonedx-cli v0.33.1 and sbom-tools v0.4.0. Nothing is installed.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time

from tools.evaluation import common as C

PARSER_VERSION = "opentrace.e3b.parsers/1"
CDX_VALID_MARK = "BOM validated successfully."
CDX_INVALID_MARK = "BOM is not valid."
TOOLS = {
    "cyclonedx-cli": {"default": "cyclonedx", "help": ("validate",), "required": ("--input-file", "--input-format", "--input-version", "--fail-on-errors")},
    "sbom-tools": {"default": "sbom-tools", "help": ("diff",), "required": ("--output",), "optional": ("--offline", "--no-config", "--quiet")},
}


def _env(home: str) -> dict:
    """Minimal environment: no user config or credentials; network enrichment is also disabled on the command line."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home, "TMPDIR": home, "LANG": "en_US.UTF-8", "NO_COLOR": "1",
           "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "SBOM_TOOLS_OFFLINE": "1"}
    if os.environ.get("DOTNET_ROOT"):
        env["DOTNET_ROOT"] = os.environ["DOTNET_ROOT"]
    return env


def run_command(argv: list[str], timeout: float) -> dict:
    """Run an argument array (never a shell) in an empty temporary directory. Returns raw bytes; never raises for a tool problem."""
    with tempfile.TemporaryDirectory(prefix="ot-e3b-") as home:
        started, t0 = C.utc_now(), time.perf_counter_ns()
        out = {"argv": list(argv), "started_at": started, "exit_code": None, "stdout": b"", "stderr": b"", "timeout": False, "os_error": None}
        try:
            p = subprocess.run(argv, capture_output=True, timeout=timeout, cwd=home, env=_env(home), stdin=subprocess.DEVNULL)
            out.update(exit_code=p.returncode, stdout=p.stdout or b"", stderr=p.stderr or b"")
        except subprocess.TimeoutExpired as exc:
            out.update(timeout=True, stdout=exc.stdout or b"", stderr=exc.stderr or b"")
        except OSError as exc:
            out["os_error"] = type(exc).__name__
        out["wall_ms"] = (time.perf_counter_ns() - t0) / 1e6
        return out


def probe(tool: str, executable: str | None, timeout: float = 60) -> dict:
    """``--version`` and ``--help`` only. ``usable`` means every required flag is documented by the installed release."""
    spec = TOOLS[tool]
    info = C.tool_version(executable or spec["default"])
    out = {"tool": tool, "configured": executable or spec["default"], **info, "usable": False, "supported_flags": [], "missing_flags": [], "help": {}}
    if not info["available"]:
        return out
    texts = {}
    for args in ((), spec["help"]):
        r = run_command([info["path"], *args, "--help"], timeout)
        texts[" ".join(args) or "(top)"] = (r["stdout"] + r["stderr"]).decode("utf-8", "replace")
    out["help"] = texts
    sub = spec["help"][0]
    if not re.search(rf"(?m)^\s*{sub}\b", texts["(top)"]):
        out["reason"] = f"installed release does not list a '{sub}' subcommand"
        return out
    flags = tuple(spec["required"]) + tuple(spec.get("optional", ()))
    both = texts["(top)"] + "\n" + texts[sub]
    out["supported_flags"] = [f for f in flags if f in both]
    out["missing_flags"] = [f for f in spec["required"] if f not in both]
    out["usable"] = not out["missing_flags"]
    if not out["usable"]:
        out["reason"] = "installed release does not document " + ", ".join(out["missing_flags"])
    return out


def unavailable_status(info: dict) -> str | None:
    if not info.get("available"):
        return "not_run"
    return None if info.get("usable") else "unsupported_operation"


def cyclonedx_argv(info: dict, path: str, input_version: str) -> list[str]:
    return [info["path"], "validate", "--input-file", path, "--input-format", "json", "--input-version", input_version, "--fail-on-errors"]


def classify_cyclonedx(r: dict) -> dict:
    """``valid``/``invalid`` only when exit code and the documented message agree."""
    if r.get("timeout"):
        return {"status": "timeout", "verdict": None, "diagnostic": "timed out"}
    if r.get("os_error"):
        return {"status": "execution_error", "verdict": None, "diagnostic": r["os_error"]}
    text = (r["stdout"] + b"\n" + r["stderr"]).decode("utf-8", "replace")
    ok, bad, code = CDX_VALID_MARK in text, CDX_INVALID_MARK in text, r["exit_code"]
    if code == 0 and ok and not bad:
        return {"status": "completed", "verdict": "valid", "diagnostic": None}
    if code == 1 and bad and not ok:
        return {"status": "completed", "verdict": "invalid", "diagnostic": None}
    if ok or bad:
        return {"status": "unclassified", "verdict": None, "diagnostic": f"exit code {code} disagrees with the printed message"}
    return {"status": "unclassified" if code else "unparsed_output", "verdict": None,
            "diagnostic": f"exit code {code} without a documented validation message; a rejection cannot be told apart from a tool error"}


def sbom_tools_argv(info: dict, old: str, new: str) -> list[str]:
    glob = [f for f in ("--offline", "--no-config", "--quiet") if f in info.get("supported_flags", [])]
    return [info["path"], *glob, "diff", old, new, "--output", "json"]


def classify_sbom_diff(r: dict) -> dict:
    """Parse ``reports.components.{added,removed,modified}``. Exit 0 is expected because no ``--fail-on-*`` flag is passed."""
    base = {"components": None}      # None, never empty lists, when the output cannot be used
    if r.get("timeout"):
        return {"status": "timeout", "diagnostic": "timed out", **base}
    if r.get("os_error"):
        return {"status": "execution_error", "diagnostic": r["os_error"], **base}
    if r["exit_code"] != 0:
        return {"status": "execution_error", "diagnostic": f"exit code {r['exit_code']}", **base}
    try:
        doc = json.loads(r["stdout"].decode("utf-8"))
        comps = doc["reports"]["components"]
        counts = doc["summary"]["components"]
        parsed = {}
        for key in ("added", "removed", "modified"):
            rows = comps[key]
            if not isinstance(rows, list) or not all(isinstance(x, dict) and isinstance(x.get("name"), str) for x in rows):
                raise ValueError(f"reports.components.{key} is not a list of named records")
            if counts[key] != len(rows):
                raise ValueError(f"summary.components.{key} disagrees with the listed records")
            parsed[key] = rows
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        return {"status": "unparsed_output", "diagnostic": f"{type(exc).__name__}: {exc}"[:300], **base}
    return {"status": "completed", "diagnostic": None, "components": parsed}


# --------------------------------------------------------------------------------------------- independent change oracle
def purl_type(component_or_id) -> str | None:
    text = component_or_id.get("purl") if isinstance(component_or_id, dict) else component_or_id
    m = re.search(r"pkg:([^/]+)/", text or "")
    return m.group(1).lower() if m else None


def library_changes(old: dict, new: dict) -> dict:
    """Added/removed library records between two documents, read directly from their bytes (no external or OpenTrace output)."""
    def index(doc):
        return {(purl_type(c), c.get("name"), c.get("version"), c.get("purl")) for c in _walk(doc.get("components")) if c.get("type") == "library"}
    a, b = index(old), index(new)
    rec = lambda k: {"ecosystem": k[0], "name": k[1], "version": k[2], "purl": k[3]}
    return {"removed": sorted((rec(k) for k in a - b), key=str), "added": sorted((rec(k) for k in b - a), key=str)}


def _walk(comps):
    for c in comps if isinstance(comps, list) else []:
        if isinstance(c, dict):
            yield c
            yield from _walk(c.get("components"))


def _record_ecosystem(x: dict) -> str | None:
    eco = x.get("ecosystem")
    return str(eco).lower() if eco else purl_type(str(x.get("id") or ""))


def surfaced(expected: dict, components: dict) -> dict:
    """Was the removed target record reported, and at what granularity?

    ``record_level``  listed as removed, same name and ecosystem;
    ``name_only``     listed as removed, same name, the output carries no ecosystem;
    ``component_level_modified``  only a modification of that name is reported (coarser than the known removal);
    ``not_surfaced``  neither.
    """
    name, eco = expected["name"].lower(), expected["ecosystem"]
    named = lambda key: [x for x in components[key] if x["name"].lower() == name]
    removed = named("removed")
    if any(_record_ecosystem(x) in (eco, {"pypi": "python"}.get(eco)) for x in removed):
        level = "record_level"
    elif any(_record_ecosystem(x) is None for x in removed):
        level = "name_only"
    elif named("modified"):
        level = "component_level_modified"
    else:
        level = "not_surfaced"
    matched = len(removed) + len(named("modified")) + len(named("added"))
    return {"granularity": level, "surfaced": level in ("record_level", "name_only", "component_level_modified"),
            "target_added_records": [{"name": x["name"], "ecosystem": _record_ecosystem(x)} for x in named("added")],
            "modified_fields": sorted({str(f.get("field")) for x in named("modified") for f in x.get("field_changes") or [] if isinstance(f, dict)}),
            "other_records_reported": sum(len(components[k]) for k in ("added", "removed", "modified")) - matched}
