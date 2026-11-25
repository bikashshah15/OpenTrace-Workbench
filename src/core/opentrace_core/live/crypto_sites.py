"""Bounded static collection of Python ``hashlib`` call sites from the sealed exported tree (UIP-12 Stage 2). OpenTrace-authored.

Reuses the BOMBridge ``cryptoscan`` extractor (imported byte-identically; Peiran/BOMBridge donor base ``7195f6eb``) by calling its public
``scan_source``; the overlay checkout collector (``sources.collect``: ``git ls-files``) cannot run on a tree without ``.git`` and is not used.
Nothing here imports, executes, installs or downloads anything; it only reads bytes and parses them with the standard ``ast`` module.

Contract ``UIP-12`` v1.0.0, section 4. Behaviour in short:

* the file selection, language census and local-module search happen in the Stage 1 walk (``live.source_declarations``); this module runs the
  *second phase* over the selected ``*.py`` files with its own soft clock;
* the clock is **soft**: it is read only between bounded operations. ``ast.parse``, the donor visitor and the audit below are synchronous and
  not interruptible, so one file can overrun the deadline; the byte and line limits bound input size, not CPU or memory;
* cancellation is checked before and after every such operation and between read chunks; a cancelled run returns ``None`` and records nothing;
* the donor normalises ``new``/``pbkdf2_hmac`` literals through ``canonical_alg`` at collection and its alias sets are file-wide, so, **only for
  files that produced sites**, a second small AST audit recovers the literal as written and checks the alias binding (conservatively).
"""
import ast
import hashlib
import os
import re
import stat
import sys
import time

from opentrace_core.bombridge import cryptoscan

MAX_PY_FILES = 2000
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_LINES = 20000
BUDGET_SECONDS = 20.0
MAX_SITES = 1000
MAX_EXCERPT = 2000
MAX_SKIPPED_LISTED = 100
MAX_SYNTAX_ERRORS_LISTED = 50
MAX_AUDIT_FAILURES_LISTED = 50
CHUNK = 64 * 1024

OPERATION = {"hashlib.pbkdf2_hmac": "pbkdf2_hmac", "hashlib.scrypt": "scrypt"}


class Cancelled(Exception):
    pass


def _read_bounded(path, cancel):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        chunks, total = [], 0
        while True:
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            block = os.read(fd, min(CHUNK, MAX_FILE_BYTES + 1 - total))
            if not block:
                return b"".join(chunks)
            chunks.append(block)
            total += len(block)
            if total > MAX_FILE_BYTES:
                return None
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------------------------- audit (second AST pass)
class _Bindings(ast.NodeVisitor):
    """Counts, flow-insensitively and for the whole file, every way an identifier can be bound, and records the module-level hashlib imports."""

    def __init__(self):
        self.count = {}
        self.module_level = {}   # identifier -> ("module"|"from", imported name)
        self.calls = {}          # (lineno, col_offset) -> ast.Call
        self._depth_module = True

    def _bind(self, name):
        self.count[name] = self.count.get(name, 0) + 1

    def visit_Module(self, node):
        for stmt in node.body:
            if isinstance(stmt, ast.Import):
                for a in stmt.names:
                    if a.name == "hashlib":
                        self.module_level[a.asname or "hashlib"] = ("module", "hashlib")
            elif isinstance(stmt, ast.ImportFrom) and stmt.module == "hashlib" and stmt.level == 0:
                for a in stmt.names:
                    if a.name != "*":
                        self.module_level[a.asname or a.name] = ("from", a.name)
        self.generic_visit(node)

    def visit_Import(self, node):
        for a in node.names:
            self._bind((a.asname or a.name).split(".")[0])

    def visit_ImportFrom(self, node):
        for a in node.names:
            self._bind(a.asname or a.name)

    def _def(self, node):
        self._bind(node.name)
        self.generic_visit(node)

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _def

    def visit_arg(self, node):
        self._bind(node.arg)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._bind(node.id)

    def visit_ExceptHandler(self, node):
        if node.name:
            self._bind(node.name)
        self.generic_visit(node)

    def visit_Global(self, node):
        for n in node.names:
            self._bind(n)

    visit_Nonlocal = visit_Global

    def visit_MatchAs(self, node):
        if node.name:
            self._bind(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node):
        if node.name:
            self._bind(node.name)

    def visit_MatchMapping(self, node):
        if node.rest:
            self._bind(node.rest)
        self.generic_visit(node)

    def visit_Call(self, node):
        self.calls[(node.lineno, node.col_offset)] = node
        self.generic_visit(node)


def audit_file(text, path, sites):
    """Attach literal / binding facts to the sites of one file (a second parse). Raises on any failure; the caller records it."""
    tree = ast.parse(text, filename=path)
    b = _Bindings()
    b.visit(tree)
    for s in sites:
        node = b.calls.get((s["line"], s["col"]))
        if node is None:
            raise ValueError("call node not found")
        fn, alias = node.func, None
        if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
            alias = fn.value.id
        elif isinstance(fn, ast.Name):
            alias = fn.id
        kind = s["call"]
        const = None
        if kind in ("hashlib.new", "hashlib.pbkdf2_hmac"):
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                const = first.value
            s["algorithm_source"] = "literal" if const is not None else "dynamic"
        else:
            s["algorithm_source"] = "function_name"
        s["algorithm_literal"] = const
        info = b.module_level.get(alias)
        # the name as imported (``from hashlib import sha256 as s`` -> "sha256"): a verified fact that lets the rule establish the operation of a renamed call
        s["imported_name"] = info[1] if info is not None and info[0] == "from" else None
        if info is None:
            binding, status = "non_module_level_import", "ambiguous"
        elif b.count.get(alias, 0) != 1:
            binding, status = "rebound_in_file", "ambiguous"
        else:
            binding, status = ("from_import" if info[0] == "from" else "module_level_import"), "unique_module_level"
        s["binding"], s["binding_status"] = binding, status
        s["audit_complete"] = True


# ---------------------------------------------------------------------------------------------- the phase
def _site_record(rel, fsha, s, src_lines):
    end = s["end_line"] or s["line"]
    excerpt = "\n".join(src_lines[s["line"] - 1:end])
    truncated = len(excerpt) > MAX_EXCERPT
    rec = {"path": rel, "file_sha256": fsha, "line": s["line"], "end_line": end, "col": s["col"], "call": s["call"],
           "operation": OPERATION.get(s["call"], "hash"), "algorithm": s["algorithm"], "algorithm_resolved": s["algorithm_resolved"],
           "context": s["context"], "source_line": s["source_line"][:400], "excerpt": excerpt[:MAX_EXCERPT], "excerpt_truncated": truncated,
           "algorithm_literal": None, "algorithm_source": None, "binding": None, "binding_status": "unknown", "audit_complete": False, "imported_name": None}
    if "usedforsecurity" in s:
        rec["usedforsecurity"] = s["usedforsecurity"]
    return rec


def run_phase(selected, *, cancel=None, clock=time.monotonic, budget=BUDGET_SECONDS, py_total=0, py_over_limit=0, pre_skipped=()):
    """Second phase over ``selected`` = ``[(rel, abs_path)]`` in traversal order. Returns ``None`` when cancelled, else ``{"sites", "summary"}``."""
    started = clock()
    skipped, skipped_total = [], {}
    for rel, reason in pre_skipped:        # selected by the walk but not a regular file (a symlink is never followed)
        skipped_total[reason] = skipped_total.get(reason, 0) + 1
        if len(skipped) < MAX_SKIPPED_LISTED:
            skipped.append({"path": rel, "reason": reason})
    syntax_errors, syntax_total = [], 0
    audit_failures, audit_total = [], 0
    sites, sites_total = [], 0
    parsed = not_parsed = 0
    total_bytes = 0
    deadline_hit = False

    def cancelled():
        return cancel is not None and cancel.is_set()

    def skip(rel, reason):
        skipped_total[reason] = skipped_total.get(reason, 0) + 1
        if len(skipped) < MAX_SKIPPED_LISTED:
            skipped.append({"path": rel, "reason": reason})

    try:
        for index, (rel, path) in enumerate(selected):
            if cancelled():
                raise Cancelled()
            if clock() - started > budget:
                deadline_hit = True
                not_parsed = len(selected) - index
                break
            try:
                size = os.lstat(path).st_size
                if size > MAX_FILE_BYTES:
                    skip(rel, "too_large")
                    continue
                if total_bytes + size > MAX_TOTAL_BYTES:
                    skip(rel, "over_total_bytes")
                    continue
                data = _read_bounded(path, cancel)
            except Cancelled:
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
            if data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0) > MAX_LINES:
                skip(rel, "over_line_limit")
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                skip(rel, "not_utf8")
                continue
            total_bytes += len(data)
            if cancelled():
                raise Cancelled()
            try:
                found, _observed, err = cryptoscan.scan_source(rel, text)
            except Exception:       # ValueError (NUL), RecursionError, MemoryError ...: a per-file skip, never a collection failure
                skip(rel, "parse_error")
                continue
            if cancelled():
                raise Cancelled()
            if err:
                syntax_total += 1
                if len(syntax_errors) < MAX_SYNTAX_ERRORS_LISTED:
                    syntax_errors.append({"path": rel, "error": err[:120]})
                continue
            parsed += 1
            if not found:
                continue
            fsha = hashlib.sha256(data).hexdigest()
            lines = re.split(r"\r\n|\r|\n", text)   # as ast counts lines (FR-01)
            recs = [_site_record(rel, fsha, s, lines) for s in found]
            if clock() - started > budget:
                audit_failed = "deadline_before_audit"
            else:
                try:
                    audit_file(text, rel, recs)
                    audit_failed = None
                except Exception:
                    audit_failed = "audit_error"
                    for r in recs:      # keep the donor observation, drop partially attached facts
                        r.update(algorithm_literal=None, algorithm_source=None, binding=None, binding_status="unknown", audit_complete=False, imported_name=None)
            if cancelled():
                raise Cancelled()
            if audit_failed:
                audit_total += 1
                if len(audit_failures) < MAX_AUDIT_FAILURES_LISTED:
                    audit_failures.append({"path": rel, "reason": audit_failed})
            for r in sorted(recs, key=lambda x: (x["line"], x["col"])):
                sites_total += 1
                if len(sites) < MAX_SITES:
                    sites.append(r)
    except Cancelled:
        return None
    complete = (not deadline_hit and not skipped_total and not syntax_total and not audit_total and sites_total <= MAX_SITES and py_over_limit == 0)
    summary = {"python_files_total": py_total, "selected": len(selected), "parsed": parsed, "not_parsed_time_budget": not_parsed,
               "over_file_limit": py_over_limit, "deadline_hit": deadline_hit,
               "skipped": {"count": sum(skipped_total.values()), "by_reason": dict(sorted(skipped_total.items())), "listed": skipped,
                           "listed_limit": MAX_SKIPPED_LISTED},
               "syntax_errors": {"count": syntax_total, "listed": syntax_errors, "listed_limit": MAX_SYNTAX_ERRORS_LISTED},
               "audit_failures": {"count": audit_total, "listed": audit_failures, "listed_limit": MAX_AUDIT_FAILURES_LISTED},
               "sites": {"observed": sites_total, "recorded": len(sites), "over_site_limit": max(0, sites_total - MAX_SITES)},
               "bytes_parsed": total_bytes, "complete": complete,
               "limits": {"python_files": MAX_PY_FILES, "bytes_per_file": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES, "lines_per_file": MAX_LINES,
                          "sites": MAX_SITES, "excerpt_chars": MAX_EXCERPT, "budget_seconds_soft": budget},
               "python_version": ".".join(str(x) for x in sys.version_info[:3]),
               "timing": "the budget is soft: checked between bounded operations only; an in-flight parse/visit/audit can overrun it"}
    return {"sites": sites, "summary": summary}
