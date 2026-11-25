"""Bounded static collection of AI runtime imports, AI service endpoints and import fallbacks from the sealed exported tree (Stage 4 increment A).

OpenTrace-authored. Contract ``S4-AI-SOURCE`` v1.0.0 (``.context/contracts/S4-AI-SOURCE.md``). The file selection happens in the one walk of
``live.source_declarations`` (the same ``*.py`` selection as ``crypto_sites``); this module runs one more phase over those files with its own soft clock.
It reads bytes and parses them with the standard ``ast`` module. Nothing is imported, executed, installed, downloaded or resolved.

What a record means: an *observation* that source text imports a known inference runtime module, names an inference-API endpoint literal, or
imports one runtime inside ``try`` and another in an ``except ImportError`` handler. It is not an installed package, version, active runtime,
reachable service, model load or execution. Dynamic forms (``importlib``, ``__import__``, f-strings, relative imports) emit nothing.

The clock is soft (read between operations); ``ast.parse`` can overrun it. A cancelled run returns ``None`` and records nothing.
"""
import ast
import hashlib
import os
import re
import stat
import sys
import time
from urllib.parse import urlsplit

MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_LINES = 20000
BUDGET_SECONDS = 10.0   # Stage 4: each new phase is at most 10 s soft (S4R-C: +20 s worst case over the pre-existing walk, hashlib and model phases)
MAX_RUNTIME_OBS = 1000
MAX_SERVICE_OBS = 500
MAX_RELATIONS = 200
MAX_EXCERPT = 600
MAX_SKIPPED_LISTED = 100
CHUNK = 64 * 1024

COLLECTOR = "opentrace_core/live/ai_source.py"
COLLECTOR_VERSION = "1"

# top-level module -> display name. A fixed table: nothing outside it is a runtime, whatever its name suggests.
RUNTIME_MODULES = {
    "tflite_runtime": "TensorFlow Lite runtime",
    "ai_edge_litert": "LiteRT (ai-edge-litert)",
    "hailo_platform": "Hailo runtime (HailoRT)",
    "onnxruntime": "ONNX Runtime",
    "openvino": "OpenVINO",
    "tensorrt": "TensorRT",
    "pycoral": "PyCoral (Coral Edge TPU)",
}
SERVICE_PATHS = ("/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/api/generate", "/api/chat")
_IMPORT_ERRORS = ("ImportError", "ModuleNotFoundError")
_TEMPLATE = re.compile(r"[${}%]")
_TRY_TYPES = tuple(t for t in (ast.Try, getattr(ast, "TryStar", None)) if t is not None)


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


def _runtime_of(stmt):
    """The table runtime a plain import statement names, as ``(module, form)``, or ``None``. Relative imports never match."""
    if isinstance(stmt, ast.Import):
        hits = [a.name.split(".")[0] for a in stmt.names if a.name.split(".")[0] in RUNTIME_MODULES]
        return (hits[0], "import") if len(hits) == 1 else None
    if isinstance(stmt, ast.ImportFrom) and stmt.level == 0 and stmt.module:
        top = stmt.module.split(".")[0]
        return (top, "from_import") if top in RUNTIME_MODULES else None
    return None


def _own_runtimes(stmts):
    return [(s, _runtime_of(s)) for s in stmts if _runtime_of(s) is not None]


def _catches_only_import_errors(handler):
    t = handler.type
    if isinstance(t, ast.Name):
        return t.id in _IMPORT_ERRORS
    if isinstance(t, ast.Tuple) and t.elts:
        return all(isinstance(e, ast.Name) and e.id in _IMPORT_ERRORS for e in t.elts)
    return False


def _excerpt(lines, first, last):
    text = "\n".join(lines[first - 1:last])
    return text[:MAX_EXCERPT]


def _service_endpoint(value):
    """``(endpoint, diagnostic)``: a sanitized ``scheme://host[:port]/path`` for a whole-string inference-API URL, else ``(None, code or None)``."""
    text = value.strip()
    if not text.lower().startswith(("http://", "https://")) or any(ch.isspace() for ch in text):
        return None, None
    try:
        parts = urlsplit(text)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None, None
    path = parts.path.rstrip("/")
    if not any(path.endswith(p) for p in SERVICE_PATHS):
        return None, None
    if _TEMPLATE.search(text):
        return None, "dynamic_expression"
    if parts.username is not None or parts.password is not None:
        return None, "credential_in_url"
    if not host:
        return None, "no_host"
    netloc = host.lower() if ":" not in host else "[%s]" % host
    if port:
        netloc += ":%d" % port
    return "%s://%s%s" % (parts.scheme.lower(), netloc, path), None


class _Visitor(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.runtimes, self.relations, self.services = [], [], []
        self.ambiguous = 0
        self.diagnostics = {}

    def _diag(self, code):
        self.diagnostics[code] = self.diagnostics.get(code, 0) + 1

    def _runtime(self, node):
        if isinstance(node, ast.Import):
            hits = sorted({a.name.split(".")[0] for a in node.names if a.name.split(".")[0] in RUNTIME_MODULES})
            form = "import"
        else:
            hit = _runtime_of(node)
            hits, form = ([hit[0]] if hit else []), "from_import"
        end = getattr(node, "end_lineno", None) or node.lineno
        if end == node.lineno and getattr(node, "end_col_offset", None) is not None:
            # only the statement's own columns, never the rest of the physical line
            ex = self.lines[node.lineno - 1].encode("utf-8")[node.col_offset:node.end_col_offset].decode("utf-8", "replace")[:MAX_EXCERPT]
        else:
            ex = _excerpt(self.lines, node.lineno, end)
        for module in hits:
            self.runtimes.append({"line": node.lineno, "end_line": end, "module": module, "form": form, "excerpt": ex})

    def visit_Import(self, node):
        self._runtime(node)

    def visit_ImportFrom(self, node):
        self._runtime(node)

    def visit_Expr(self, node):
        # a bare string statement (a docstring or a stray literal) is never an endpoint observation
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        # the literal pieces of an f-string are never emitted; the placeholders are still visited for nested forms
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                self.visit(part)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            endpoint, diag = _service_endpoint(node.value)
            if endpoint is not None:
                end = getattr(node, "end_lineno", None) or node.lineno
                self.services.append({"line": node.lineno, "end_line": end, "endpoint": endpoint, "excerpt": None})
            elif diag:
                self._diag(diag)

    def _try(self, node):
        body = _own_runtimes(node.body)
        eligible = [h for h in node.handlers if _catches_only_import_errors(h)]
        handlers = [(h, _own_runtimes(h.body)) for h in eligible]
        handlers = [(h, r) for h, r in handlers if r]
        if body or handlers:
            if len(body) == 1 and len(node.body) == 1 and len(handlers) == 1 and len(handlers[0][1]) == 1 and len(eligible) == len(node.handlers):
                (stmt_a, (mod_a, _)), (h, [(stmt_b, (mod_b, _))]) = body[0], handlers[0]
                if mod_a != mod_b:
                    end = getattr(stmt_b, "end_lineno", None) or stmt_b.lineno
                    self.relations.append({
                        "preferred": {"module": mod_a, "line": stmt_a.lineno}, "fallback": {"module": mod_b, "line": stmt_b.lineno},
                        "condition": "the fallback import runs if the try block (a single import of %s) raises ImportError" % mod_a,
                        "excerpt": _excerpt(self.lines, stmt_a.lineno, end), "first_line": stmt_a.lineno, "last_line": end})
                else:
                    self.ambiguous += 1
            elif body and handlers:
                self.ambiguous += 1
        self.generic_visit(node)

    visit_Try = _try
    visit_TryStar = _try


def scan_source(text, rel):
    """Parse one file. Returns ``(runtimes, relations, services, ambiguous, diagnostics, error)``; ``error`` is a short string or ``None``."""
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as exc:
        return [], [], [], 0, {}, "syntax_error: %s" % (exc.msg or "")[:100]
    v = _Visitor(text.split("\n"))
    v.visit(tree)
    return v.runtimes, v.relations, v.services, v.ambiguous, v.diagnostics, None


def run_phase(selected, *, cancel=None, clock=time.monotonic, budget=BUDGET_SECONDS, py_total=0, py_over_limit=0, pre_skipped=()):
    """Phase over ``selected`` = ``[(rel, abs_path)]``. Returns ``None`` when cancelled, else ``{"runtimes","relations","services","summary"}``."""
    started = clock()
    skipped, skipped_total = [], {}
    for rel, reason in pre_skipped:
        skipped_total[reason] = skipped_total.get(reason, 0) + 1
        if len(skipped) < MAX_SKIPPED_LISTED:
            skipped.append({"path": rel, "reason": reason})
    runtimes, relations, services = [], [], []
    totals = {"runtimes": 0, "relations": 0, "services": 0}
    diag_total, ambiguous_total, syntax_total, parsed, total_bytes = {}, 0, 0, 0, 0
    deadline_hit, not_parsed = False, 0

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
                deadline_hit, not_parsed = True, len(selected) - index
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
            try:
                rts, rels, svcs, amb, diag, err = scan_source(text, rel)
            except Exception:           # ValueError (NUL), RecursionError, MemoryError ...: a per-file skip, never a collection failure
                skip(rel, "parse_error")
                continue
            if cancelled():
                raise Cancelled()
            if err:
                syntax_total += 1
                continue
            parsed += 1
            ambiguous_total += amb
            for k, n in diag.items():
                diag_total[k] = diag_total.get(k, 0) + n
            if not (rts or rels or svcs):
                continue
            fsha = hashlib.sha256(data).hexdigest()
            for o in sorted(rts, key=lambda x: (x["line"], x["module"])):
                totals["runtimes"] += 1
                if len(runtimes) < MAX_RUNTIME_OBS:
                    runtimes.append(dict(o, path=rel, file_sha256=fsha, display=RUNTIME_MODULES[o["module"]]))
            for o in sorted(rels, key=lambda x: x["first_line"]):
                totals["relations"] += 1
                if len(relations) < MAX_RELATIONS:
                    relations.append(dict(o, path=rel, file_sha256=fsha))
            for o in sorted(svcs, key=lambda x: (x["line"], x["endpoint"])):
                totals["services"] += 1
                if len(services) < MAX_SERVICE_OBS:
                    services.append(dict(o, path=rel, file_sha256=fsha))
    except Cancelled:
        return None
    over = {k: max(0, totals[k] - cap) for k, cap in (("runtimes", MAX_RUNTIME_OBS), ("relations", MAX_RELATIONS), ("services", MAX_SERVICE_OBS))}
    complete = (not deadline_hit and not skipped_total and not syntax_total and not any(over.values()) and py_over_limit == 0)
    summary = {"python_files_total": py_total, "selected": len(selected), "parsed": parsed, "not_parsed_time_budget": not_parsed,
               "over_file_limit": py_over_limit, "deadline_hit": deadline_hit,
               "skipped": {"count": sum(skipped_total.values()), "by_reason": dict(sorted(skipped_total.items())), "listed": skipped,
                           "listed_limit": MAX_SKIPPED_LISTED},
               "syntax_errors": {"count": syntax_total},
               "observed": dict(totals), "recorded": {"runtimes": len(runtimes), "relations": len(relations), "services": len(services)},
               "over_limit": over, "ambiguous_relations": ambiguous_total, "diagnostics": dict(sorted(diag_total.items())),
               "bytes_parsed": total_bytes, "complete": complete,
               "limits": {"bytes_per_file": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES, "lines_per_file": MAX_LINES, "runtimes": MAX_RUNTIME_OBS,
                          "services": MAX_SERVICE_OBS, "relations": MAX_RELATIONS, "budget_seconds_soft": budget},
               "runtime_modules": sorted(RUNTIME_MODULES), "service_paths": list(SERVICE_PATHS),
               "python_version": ".".join(str(x) for x in sys.version_info[:3]),
               "timing": "the budget is soft: checked between bounded operations only; an in-flight parse can overrun it"}
    return {"runtimes": runtimes, "relations": relations, "services": services, "summary": summary}


def present(sink):
    """The session-only presentation input for the AI tab, from the collection sink of one scan (``source_declarations.collect`` result).

    ``None`` when no collection result exists (the producer did not run). ``{"state": "failed", "code"}`` when the collector faulted or produced no
    record. Else ``{"state": "collected", runtimes, relations, services, summary}``. The observations are copied; nothing is added or inferred."""
    if not isinstance(sink, dict) or not sink:
        return None
    record = sink.get("record")
    block = record.get("ai_source") if isinstance(record, dict) else None
    if sink.get("status") != "collected" or not isinstance(block, dict):
        return {"state": "failed", "code": str(sink.get("code") or sink.get("status") or "no_record")[:60]}
    if (block.get("summary") or {}).get("failed"):
        return {"state": "failed", "code": "collector_error"}      # this collector faulted; the rest of the record is intact
    return {"state": "collected", "runtimes": list(block["runtimes"]), "relations": list(block["relations"]), "services": list(block["services"]),
            "summary": dict(block["summary"]), "record_sha256": sink.get("record_sha256")}
