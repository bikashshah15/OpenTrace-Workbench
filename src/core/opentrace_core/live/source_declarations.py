"""Bounded static collector of Python requirement files from the sealed exported tree (UIP-10 Stage 1).

OpenTrace-authored. It replaces the checkout collector of the BOMBridge gap-discovery overlay (``sources.collect``: ``git ls-files`` over a
checkout), which cannot run on a sealed tree without ``.git``. What is reused from the overlay is the *selection rule* (its requirement
globs) and the pip line parsing that the imported ``bombridge.adapters`` / ``bombridge.discovery`` already provide. Nothing here evaluates
markers, follows ``-r``/``-c`` directives, imports, installs, executes or touches the network.

Behaviour (contract ``UIP-10`` v1.0.0, section 4.1):

* deterministic traversal: iterative depth-first; in each directory the non-directory entries come first in sorted byte-wise name order,
  then each subdirectory in sorted order; symlinks are never followed;
* bounded: 64 requirement files, 1 MiB per file, 8 MiB in total, 20,000 lines per file, ``MAX_FILES`` non-directory entries visited,
  a 10 s budget; a matching file that cannot be fully read within the limits is *not collected* and is recorded with its reason;
* never silent: an early stop (time budget, entry cap) or a directory that could not be read is recorded and every count is then a lower
  bound (``count_kind: at_least``, ``traversal.complete: false``); unread directories are listed by relative path only (never the
  exception text or an absolute path);
* cancellable during traversal and between bounded read chunks; a cancelled run returns no record;
* byte-exact copies; the record carries each file's SHA-256 and its own digest is computed over its canonical JSON.
"""
import base64
import fnmatch
import hashlib
import json
import os
import stat
import time

from opentrace_core.bombridge import discovery as bb_discovery

from . import ai_source, crypto_sites, crypto_source, model_refs, policy

SCHEMA = "bombridge.source-declarations/1"
TOOL = "opentrace_core/live/source_declarations.py"
REQUIREMENT_GLOBS = ("*requirements*.txt", "requirements/*.txt")   # overlay ``sources.REQUIREMENT_GLOBS``, case-sensitive

MAX_FILES_COLLECTED = 64
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_LINES = 20000
MAX_ENTRIES = policy.MAX_FILES
BUDGET_SECONDS = 10.0
CHUNK = 64 * 1024
MAX_UNSUPPORTED_LISTED = 50
MAX_SKIPPED_LISTED = 100
MAX_UNREADABLE_LISTED = 50

# Other recognized source languages (UIP-12): counted by extension in the same walk, never parsed or compared.
OTHER_SOURCE_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".java", ".kt", ".rs", ".rb", ".php", ".c", ".h", ".cc", ".cpp", ".cs", ".swift", ".scala")
MAX_LOCAL_MODULES_LISTED = 20

# Declaration files this unit does not read: reported by name only, never parsed or compared.
UNSUPPORTED_DECLARATIONS = {
    "pyproject.toml": ("python", "pyproject"), "setup.py": ("python", "setup.py"), "setup.cfg": ("python", "setup.cfg"),
    "Pipfile": ("python", "Pipfile"), "Pipfile.lock": ("python", "Pipfile.lock"), "poetry.lock": ("python", "poetry.lock"),
    "uv.lock": ("python", "uv.lock"),
    "package.json": ("npm", "package.json"), "package-lock.json": ("npm", "package-lock.json"), "yarn.lock": ("npm", "yarn.lock"),
    "pnpm-lock.yaml": ("npm", "pnpm-lock.yaml"), "go.mod": ("go", "go.mod"), "Cargo.toml": ("cargo", "Cargo.toml"),
    "pom.xml": ("maven", "pom.xml"), "build.gradle": ("gradle", "build.gradle"), "Gemfile": ("ruby", "Gemfile"),
    "composer.json": ("php", "composer.json"),
}


class Stop(Exception):
    """Internal: traversal ended early (``reason``)."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _matches(rel):
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(name, g) or fnmatch.fnmatchcase(rel, g) for g in REQUIREMENT_GLOBS)


def _safe_name(name):
    return bool(name) and "\\" not in name and not any(ord(c) < 32 or ord(c) == 127 for c in name) and name not in (".", "..")


def _walk(root, tick):
    """Yield ``(rel, abs_path, kind)`` for every non-directory entry in deterministic order; ``kind`` is ``file``, ``symlink`` or ``other``,
    ``dir`` (UIP-12: directory names only, for the local-module search; not an entry), or ``unreadable_dir`` (``rel`` is ``""`` for the root) when a directory listing failed (UIP-10-IR-02: never silently skipped)."""
    stack = [("", root)]
    while stack:
        rel_dir, path = stack.pop()
        tick()
        try:
            with os.scandir(path) as it:
                entries = sorted(it, key=lambda e: os.fsencode(e.name))
        except OSError:
            yield rel_dir, path, "unreadable_dir"
            continue
        subdirs = []
        for entry in entries:
            tick()
            rel = entry.name if not rel_dir else rel_dir + "/" + entry.name
            try:
                if entry.is_symlink():
                    yield rel, entry.path, "symlink"
                elif entry.is_dir(follow_symlinks=False):
                    subdirs.append((rel, entry.path))
                    yield rel, entry.path, "dir"
                elif entry.is_file(follow_symlinks=False):
                    yield rel, entry.path, "file"
                else:
                    yield rel, entry.path, "other"
            except OSError:
                yield rel, entry.path, "other"
        # files of this directory were yielded above; the first sorted subdirectory is entered next (stack is LIFO)
        stack.extend(reversed(subdirs))


def _read_bounded(path, tick):
    """Read one regular file without following links, never past ``MAX_FILE_BYTES``. Returns bytes, or ``None`` when too large."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        chunks, total = [], 0
        while True:
            tick()
            block = os.read(fd, min(CHUNK, MAX_FILE_BYTES + 1 - total))
            if not block:
                return b"".join(chunks)
            chunks.append(block)
            total += len(block)
            if total > MAX_FILE_BYTES:
                return None
    finally:
        os.close(fd)


def _line_count(data):
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


def _isolated(run, kind, selected, cancel, clock, py_total, py_over, pre_skipped):
    """Run one Stage 4 phase so that an unexpected fault in it cannot discard the requirement-file comparison, the hashlib sites or the other
    collector's completed results. A fault yields an empty, explicitly failed result (``summary.failed``); cancellation is still ``None``."""
    try:
        return run(selected, cancel=cancel, clock=clock, py_total=py_total, py_over_limit=py_over, pre_skipped=pre_skipped)
    except Exception:
        summary = {"python_files_total": py_total, "selected": len(selected), "parsed": 0, "complete": False, "failed": True, "failure": "collector_error",
                   "deadline_hit": False, "over_file_limit": py_over, "skipped": {"count": 0, "by_reason": {}, "listed": [], "listed_limit": MAX_SKIPPED_LISTED},
                   "syntax_errors": {"count": 0}, "observed": {}, "recorded": {}, "over_limit": {}, "diagnostics": {}}
        if kind == "ai":
            return {"runtimes": [], "relations": [], "services": [], "summary": summary}
        return {"jwt": [], "tls": [], "summary": summary}


def collect(tree_dir, repository_url, commit_sha, *, cancel=None, clock=time.monotonic, budget=BUDGET_SECONDS):
    """Walk the exported tree and return ``{"status", "record", "copies", "summary"}``.

    ``status`` is ``collected`` or ``cancelled`` (no record, nothing to publish). ``summary`` is the truthful account of the run:
    ``traversal.complete`` is false after an early stop and every count is then marked ``at_least``.
    """
    started = clock()
    root = os.path.realpath(tree_dir)
    state = {"entries": 0, "stop": None}
    found, collected, skipped, copies, unsupported = 0, [], [], {}, []
    skipped_total = {}
    unsupported_count, total_bytes = 0, 0
    unreadable, unreadable_count = [], 0
    py_selected, py_total, py_over, py_nonregular = [], 0, 0, []
    other_langs = {}
    m_selected, m_pre, m_over, m_census = [], [], 0, {"python": 0, "dockerfile": 0, "shell": 0}
    local_modules, local_modules_count = [], 0

    def tick():
        if cancel is not None and cancel.is_set():
            raise Stop("cancelled")
        if clock() - started > budget:
            raise Stop("time_budget")

    def skip(rel, reason):
        skipped_total[reason] = skipped_total.get(reason, 0) + 1
        if len(skipped) < MAX_SKIPPED_LISTED:
            skipped.append({"path": rel, "reason": reason})

    try:
        tick()
        for rel, path, kind in _walk(root, tick):
            if kind == "unreadable_dir":
                unreadable_count += 1
                if len(unreadable) < MAX_UNREADABLE_LISTED:
                    unreadable.append({"path": rel or "."})
                continue
            if kind == "dir":
                if rel.rsplit("/", 1)[-1] == "hashlib":
                    local_modules_count += 1
                    if len(local_modules) < MAX_LOCAL_MODULES_LISTED:
                        local_modules.append({"path": rel, "kind": "directory"})
                continue
            state["entries"] += 1
            if state["entries"] > MAX_ENTRIES:
                state["entries"] = MAX_ENTRIES
                raise Stop("entry_cap")
            name = rel.rsplit("/", 1)[-1]
            is_req = _matches(rel)
            mkind = model_refs.source_kind(name)
            if mkind is not None:       # UIP-13: model-phase selection in this one walk (never a second traversal)
                m_census[mkind] += 1
                if kind != "file":
                    m_pre.append((rel, "not_regular"))
                elif not model_refs.safe_path(rel):
                    m_pre.append((rel, "unsafe_path"))
                elif len(m_selected) < model_refs.MAX_FILES:
                    m_selected.append((rel, path, mkind))
                else:
                    m_over += 1
            if kind in ("symlink", "other") and name.endswith(".py"):
                py_total += 1
                if len(py_nonregular) < MAX_SKIPPED_LISTED:
                    py_nonregular.append((rel, "not_regular"))
            if kind == "file":
                stem, dot, ext = name.rpartition(".")
                if dot and ext in ("py", "pyi") and stem == "hashlib":
                    local_modules_count += 1
                    if len(local_modules) < MAX_LOCAL_MODULES_LISTED:
                        local_modules.append({"path": rel, "kind": "file"})
                if name.endswith(".py"):
                    py_total += 1
                    if not all(_safe_name(part) for part in rel.split("/")):
                        pass
                    elif len(py_selected) < crypto_sites.MAX_PY_FILES:
                        py_selected.append((rel, path))
                    else:
                        py_over += 1
                else:
                    for e in OTHER_SOURCE_EXTENSIONS:
                        if name.endswith(e):
                            other_langs[e] = other_langs.get(e, 0) + 1
                            break
            if kind == "file" and name in UNSUPPORTED_DECLARATIONS and not is_req:
                unsupported_count += 1
                if len(unsupported) < MAX_UNSUPPORTED_LISTED:
                    eco, fmt = UNSUPPORTED_DECLARATIONS[name]
                    unsupported.append({"path": rel, "ecosystem": eco, "format": fmt})
                continue
            if not is_req:
                continue
            found += 1
            if not all(_safe_name(part) for part in rel.split("/")):
                skip(rel, "unsafe_path")
                continue
            if kind != "file":
                skip(rel, "not_regular")
                continue
            if len(collected) >= MAX_FILES_COLLECTED:
                skip(rel, "over_file_limit")
                continue
            try:
                size = os.lstat(path).st_size
                if size > MAX_FILE_BYTES:
                    skip(rel, "too_large")
                    continue
                if total_bytes + size > MAX_TOTAL_BYTES:
                    skip(rel, "over_total_bytes")
                    continue
                data = _read_bounded(path, tick)
            except Stop:
                raise
            except OSError:
                skip(rel, "not_regular")
                continue
            if data is None:
                skip(rel, "too_large")
                continue
            if total_bytes + len(data) > MAX_TOTAL_BYTES:
                skip(rel, "over_total_bytes")
                continue
            if _line_count(data) > MAX_LINES:
                skip(rel, "over_line_limit")
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                skip(rel, "not_utf8")
                continue
            decls = bb_discovery.requirement_declarations(text)
            total_bytes += len(data)
            copies[rel] = data
            collected.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "declaration_lines": len(decls),
                              "named_requirements": len({d["normalized_name"] for d in decls if d.get("normalized_name")})})
    except Stop as stop:
        state["stop"] = stop.reason
    if state["stop"] == "cancelled":
        return {"status": "cancelled", "record": None, "copies": {}, "summary": None}
    phase = crypto_sites.run_phase(py_selected, cancel=cancel, clock=clock, py_total=py_total, py_over_limit=py_over, pre_skipped=py_nonregular)
    if phase is None:
        return {"status": "cancelled", "record": None, "copies": {}, "summary": None}

    aphase = _isolated(ai_source.run_phase, "ai", py_selected, cancel, clock, py_total, py_over, py_nonregular)   # Stage 4 A
    if aphase is None:
        return {"status": "cancelled", "record": None, "copies": {}, "summary": None}

    cphase = _isolated(crypto_source.run_phase, "crypto", py_selected, cancel, clock, py_total, py_over, py_nonregular)   # Stage 4 B
    if cphase is None:
        return {"status": "cancelled", "record": None, "copies": {}, "summary": None}

    mphase = model_refs.run_phase(m_selected, cancel=cancel, clock=clock, over_file_limit=m_over, pre_skipped=m_pre)
    if mphase is None:
        return {"status": "cancelled", "record": None, "copies": {}, "summary": None}

    complete = state["stop"] is None and unreadable_count == 0
    stop_reason = state["stop"] or ("directory_unreadable" if unreadable_count else None)
    kind = "exact" if complete else "at_least"
    # a clean binding is never inferred from an incomplete search: an early stop (or the parse-phase soft deadline, contract UIP-12 section 4) makes it unknown
    local = ("present" if local_modules_count else "absent_after_complete_search" if complete and not phase["summary"]["deadline_hit"] else "unknown_incomplete")
    psum = dict(phase["summary"], traversal_complete=complete)
    psum["complete"] = bool(psum["complete"] and complete and not py_nonregular)
    psum["count_kind"] = "exact" if psum["complete"] else "at_least"       # exact only when every Python file was inspected and parsed
    other_total = sum(other_langs.values())
    asum = dict(aphase["summary"], traversal_complete=complete)
    asum["complete"] = bool(asum["complete"] and complete and not py_nonregular)
    asum["count_kind"] = "exact" if asum["complete"] else "at_least"
    csum = dict(cphase["summary"], traversal_complete=complete)
    csum["complete"] = bool(csum["complete"] and complete and not py_nonregular)
    csum["count_kind"] = "exact" if csum["complete"] else "at_least"
    msum = dict(mphase["summary"], traversal_complete=complete,
                census={"python": py_total, "dockerfile": m_census["dockerfile"], "shell": m_census["shell"], "other_languages": other_total,
                        "matched_model_source_entries": sum(m_census.values())})
    msum["complete"] = bool(msum["complete"] and complete)
    msum["count_kind"] = "exact" if msum["complete"] else "at_least"
    traversal = {"complete": complete, "stop_reason": stop_reason, "entries_visited": state["entries"], "count_kind": kind}
    searched = {
        "traversal": traversal,
        "order": "depth-first; per directory, files then subdirectories, each in byte-wise name order; symlinks not followed",
        "requirement_globs": list(REQUIREMENT_GLOBS),
        "limits": {"requirement_files": MAX_FILES_COLLECTED, "bytes_per_file": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES,
                   "lines_per_file": MAX_LINES, "entries": MAX_ENTRIES, "budget_seconds": budget},
        "requirement_files_matched": {"count": found, "count_kind": kind},
        "requirement_files_skipped": {"count": sum(skipped_total.values()), "count_kind": kind, "by_reason": dict(sorted(skipped_total.items())),
                                      "listed": skipped, "listed_limit": MAX_SKIPPED_LISTED},
        "unsupported_declaration_files": {"count": unsupported_count, "count_kind": kind, "listed": unsupported,
                                          "listed_limit": MAX_UNSUPPORTED_LISTED},
        "directories_unreadable": {"count": unreadable_count, "count_kind": kind, "listed": unreadable, "listed_limit": MAX_UNREADABLE_LISTED},
        "python": psum,
        "model_sources": msum,
        "other_source_languages": {"count": other_total, "count_kind": kind, "by_extension": dict(sorted(other_langs.items()))},
        "local_module_named_hashlib": {"status": local, "count": local_modules_count, "listed": local_modules, "listed_limit": MAX_LOCAL_MODULES_LISTED},
    }
    record = {
        "schema": SCHEMA, "repository": repository_url, "revision": commit_sha,
        "collected_by": {"tool": TOOL, "note": "reads files of the exported tree only; nothing imported, installed, downloaded or executed; "
                                               "requirement-file selection and line rules follow the BOMBridge gap-discovery overlay"},
        "requirement_files": collected,   # traversal order (deterministic)
        "crypto_call_sites": phase["sites"],   # UIP-12: Python hashlib call sites (observations; never CBOM records)
        "ai_source": {"runtimes": aphase["runtimes"], "relations": aphase["relations"], "services": aphase["services"], "summary": asum,
                      "collector": ai_source.COLLECTOR, "collector_version": ai_source.COLLECTOR_VERSION},   # Stage 4 A: observations only; never AI-BOM records
        "crypto_source": {"jwt": cphase["jwt"], "tls": cphase["tls"], "summary": csum,
                          "collector": crypto_source.COLLECTOR, "collector_version": crypto_source.COLLECTOR_VERSION},   # Stage 4 B: observations only; never CBOM records
        "model_references": mphase["references"],   # UIP-13: statically observed model-file references (observations; never AI-BOM records)
        "searched": searched,
        "limitations": ["source declarations state what the requirement files name; they do not show what is built, installed or loaded",
                        "requirement files are matched by name; a file installed under another name is not found",
                        "markers are preserved as text and never evaluated; -r/-c directives are reported, not followed",
                        "only Python requirement files are read; other declaration files are listed by name and never compared",
                        "model_references are statically observed HTTP(S) model-file URLs in Python string constants, Dockerfile lines and shell lines (UIP-13): not download, "
                        "load, execution or selection, possibly dead code, a docstring or a string that is not a setting; dynamic expressions are diagnostics only; "
                        "ai_source holds statically observed Python imports of a fixed table of inference-runtime modules, inference-API endpoint literals and try/except-ImportError import fallbacks "
                        "(Stage 4): not an installed package, version, active runtime, reachable service, model load or execution; dynamic forms emit nothing; "
                        "crypto_source holds statically observed Python jwt encode/decode calls and TLS-configuration calls/assignments of fixed forms (Stage 4): not execution, "
                        "not proof that the receiver is the named library, not deployed configuration, and an algorithm or flag name is never a vulnerability by itself; "
                        "crypto_call_sites are statically observed Python hashlib calls (UIP-12): not execution, not proof that the called module is the standard library, "
                        "and not a statement about cryptography the scan did not observe"
                        + ("" if complete else "; traversal was incomplete (stopped early or a directory could not be read), so every count here is a lower bound")],
    }
    digest = hashlib.sha256(canonical_bytes(record)).hexdigest()
    return {"status": "collected", "record": record, "record_sha256": digest, "copies": copies,
            "summary": {"traversal": traversal, "collected": len(collected), "matched": found, "skipped": searched["requirement_files_skipped"],
                        "unsupported": searched["unsupported_declaration_files"],
                        "unreadable": searched["directories_unreadable"], "python": psum, "other_languages": searched["other_source_languages"],
                        "local_module": searched["local_module_named_hashlib"], "crypto_sites": len(phase["sites"]), "models": msum, "model_references": len(mphase["references"]), "ai_source": asum, "crypto_source": csum, "named_requirements": sum(r["named_requirements"] for r in collected),
                        "record_sha256": digest}}


def bundle_bytes(result):
    """The single derived session artifact: ``{record, copies: {path: {sha256, base64}}}`` as canonical JSON."""
    copies = {p: {"sha256": hashlib.sha256(b).hexdigest(), "base64": base64.b64encode(b).decode("ascii")} for p, b in sorted(result["copies"].items())}
    return canonical_bytes({"record": result["record"], "record_sha256": result["record_sha256"], "copies": copies})
