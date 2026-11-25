"""Bounded static collection of model-file references from the sealed exported tree (UIP-13 Stage 3). OpenTrace-authored.

Contract ``UIP-13`` v1.0.0, section 5. The selection of source files happens in the one walk of ``live.source_declarations``; this module runs the
*model phase* over the selected files (Python, Dockerfile, shell) with its own soft clock. It reads bytes, parses Python with the standard ``ast``
module and tokenizes text lines with ``re``. Nothing is imported, executed, downloaded or resolved.

Provenance: the extension list, the selection globs and the narrow reference / joined-literal logic follow the BOMBridge gap-discovery overlay
``src/bombridge/sources.py`` (Peiran Shi; sha256 7b139713...5ed7; no git history) and are *ported*, not copied. Deliberate differences: URL tokens keep
``{``/``}``/``$`` so template placeholders are recognised (the donor splits at ``{``); the literal pieces of an f-string are never emitted (the donor's
``ast.walk`` visits them as ordinary constants); trailing ``.,;:`` is stripped; every bound, cancellation point, path rule and diagnostic below is new.
BOMBridge licensing remains unresolved (BB-REL-01); nothing here claims otherwise.

Behaviour in short: a *reference* is one HTTP(S) URL token whose query/fragment-stripped path ends in a model-file extension, found in a Python string
constant, a Dockerfile line or a shell line. Its *locator* is the token verbatim (query and fragment kept); dynamic tokens and f-string pieces are
diagnostics, never locators. The clock is soft (checked between operations); ``ast.parse`` and an in-flight read can overrun it. A cancelled run
returns ``None`` and records nothing.
"""
import ast
import fnmatch
import hashlib
import json
import os
import re
import stat
import time

COLLECTOR = "opentrace_core/live/model_refs.py"
COLLECTOR_VERSION = "1"
EXTENSIONS = (".tflite", ".hef", ".onnx", ".pt", ".pth", ".pb", ".rknn", ".engine", ".h5", ".safetensors", ".gguf", ".mlmodel", ".caffemodel", ".ort")
ARCHIVE_EXTENSIONS = (".zip", ".tar.gz", ".tgz", ".tar")
DOCKERFILE_GLOBS = ("Dockerfile", "Dockerfile.*", "*.Dockerfile", "*.dockerfile")
SHELL_GLOBS = ("*.sh",)
MAX_FILES = 2000
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_LINES = 20000
BUDGET_SECONDS = 20.0
MAX_REFERENCES = 1000
MAX_DIAGNOSTICS = 100
MAX_LOCATOR = 2048
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_EXCERPT = 2000
MAX_PATH = 512
CHUNK = 64 * 1024
DIAGNOSTIC_CODES = ("too_large", "over_total_bytes", "over_line_limit", "not_utf8", "not_regular", "unsafe_path", "syntax_error", "parse_error",
                    "over_file_limit", "not_processed_time_budget", "dynamic_expression", "phase_error", "locator_too_long", "record_bytes")

_URL = re.compile(r"https?://[^\s'\"<>()\[\]`\\]+")
_TEMPLATE = re.compile(r"[${}]|%[sdr]|%\(")


class Cancelled(Exception):
    pass


def source_kind(name):
    """``python`` / ``dockerfile`` / ``shell`` for a basename the model phase reads, else ``None`` (case-sensitive, as the donor globs)."""
    if name.endswith(".py"):
        return "python"
    if any(fnmatch.fnmatchcase(name, g) for g in DOCKERFILE_GLOBS):
        return "dockerfile"
    if any(fnmatch.fnmatchcase(name, g) for g in SHELL_GLOBS):
        return "shell"
    return None


def safe_path(rel):
    """True for a relative POSIX path the queue projection can represent (<= 512 chars, no control characters, no backslash, no dot segments)."""
    if not rel or len(rel) > MAX_PATH:
        return False
    return all(part and part not in (".", "..") and "\\" not in part and not any(ord(c) < 32 or ord(c) == 127 for c in part) for part in rel.split("/"))


def _url_path(token):
    return token.split("#")[0].split("?")[0].rstrip("/").lower()


def shape(token):
    """``model`` / ``archive`` / ``None`` for a URL token (query and fragment removed; case-insensitive for recognition only)."""
    p = _url_path(token)
    if p.endswith(EXTENSIONS):
        return "model"
    if p.endswith(ARCHIVE_EXTENSIONS):
        return "archive"
    return None


def _h16(*parts):
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:16]


def _tokens(text):
    """URL tokens of one string/line: ``[(token, is_dynamic)]`` for model- or archive-shaped tokens only (trailing ``.,;:`` stripped)."""
    out = []
    for m in _URL.finditer(text):
        tok = m.group(0).rstrip(".,;:")
        kind = shape(tok)
        if kind is None:
            continue
        out.append((tok, kind, bool(_TEMPLATE.search(tok))))
    return out


def _window(text, locator):
    """``(excerpt, truncated)``: the text, or a window of MAX_EXCERPT characters containing the locator when the text is longer."""
    if len(text) <= MAX_EXCERPT:
        return text, False
    i = max(0, text.find(locator))
    start = max(0, min(i - max(0, (MAX_EXCERPT - len(locator)) // 2), len(text) - MAX_EXCERPT))
    return text[start:start + MAX_EXCERPT], True


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


def _python(text, lines, add, dynamic, long_locator):      # ``lines``: the text split exactly as ast counts lines (\r\n, \r, \n)
    """Scan the string constants of one parsed Python module. The literal pieces of an f-string / template string are never scanned as locators."""
    tree = ast.parse(text)
    dyn_types = tuple(t for t in (getattr(ast, "JoinedStr", None), getattr(ast, "TemplateStr", None)) if t is not None)
    stack = [tree]
    while stack:
        node = stack.pop()
        if dyn_types and isinstance(node, dyn_types):
            pieces = "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
            if any(shape(t) for t in (m.group(0).rstrip(".,;:") for m in _URL.finditer(pieces))) or (
                    "http" in pieces and pieces.lower().endswith(EXTENSIONS)):
                dynamic(node.lineno)
            for v in node.values:           # expressions inside the braces are ordinary code; the literal pieces are not scanned
                if not isinstance(v, ast.Constant) and hasattr(v, "value") and isinstance(v.value, ast.AST):
                    stack.append(v.value)
                    spec = getattr(v, "format_spec", None)      # ``{x:{expr}}``: the spec is code too; its own literal pieces are never locators
                    if isinstance(spec, ast.AST):
                        stack.append(spec)
            continue
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            a, b = node.lineno, node.end_lineno or node.lineno
            seen = {}
            for tok, kind, templ in _tokens(node.value):
                if templ:
                    dynamic(a)
                    continue
                if kind != "model":
                    continue
                if len(tok) > MAX_LOCATOR:
                    long_locator(a)
                    continue
                on = None
                for k in range(a, min(b, len(lines)) + 1):      # the n-th identical token of one constant is found after the previous one (R2-05)
                    i = lines[k - 1].find(tok, seen.get(k, 0))
                    if i >= 0:
                        seen[k] = i + len(tok)
                        on = k
                        break
                if on is not None:
                    add(tok, on, on, "python-ast-string-constant", lines[on - 1], None)
                else:
                    add(tok, a, b, "python-ast-joined-string-literals", "\n".join(lines[a - 1:b]), tok)
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_LINES = re.compile(r"\r\n|\r|\n")


def _clean_path(rel):
    """A diagnostic path: control characters replaced and at most MAX_PATH characters (the full path of an unsafe entry is never echoed)."""
    return _CTRL.sub("?", rel)[:MAX_PATH]


def _text(lines, add, dynamic, long_locator):
    for n, line in enumerate(lines, 1):
        for tok, kind, templ in _tokens(line):
            if templ:
                dynamic(n)
            elif kind == "model":
                if len(tok) > MAX_LOCATOR:
                    long_locator(n)
                else:
                    add(tok, n, n, "line-url-token", line, None)


def run_phase(selected, *, cancel=None, clock=time.monotonic, budget=BUDGET_SECONDS, over_file_limit=0, pre_skipped=()):
    """Model phase over ``selected`` = ``[(rel, abs_path, kind)]`` in traversal order. Returns ``None`` when cancelled, else
    ``{"references", "summary"}`` (references sorted bytewise; contract 5.3)."""
    started = clock()
    skipped_total, diag_total = {}, {}
    diagnostics = []
    refs, observed, over_limit, record_bytes, capped = [], 0, 0, 0, False
    processed = bytes_read = dynamic_total = 0
    deadline_hit = phase_error = False
    not_processed = 0

    def diag(code, rel, line=None):
        diag_total[code] = diag_total.get(code, 0) + 1
        if len(diagnostics) < MAX_DIAGNOSTICS:
            d = {"path": _clean_path(rel), "code": code}
            if line is not None:
                d["line"] = line
            diagnostics.append(d)

    def skip(rel, code):
        skipped_total[code] = skipped_total.get(code, 0) + 1
        diag(code, rel)

    def cancelled():
        return cancel is not None and cancel.is_set()

    for rel, reason in pre_skipped:
        skip(rel, reason)
    try:
        for index, (rel, path, kind) in enumerate(selected):
            if cancelled():
                raise Cancelled()
            if clock() - started > budget:
                deadline_hit = True
                not_processed = len(selected) - index
                diag("not_processed_time_budget", "*", None)
                break
            if not safe_path(rel):
                skip(rel, "unsafe_path")
                continue
            try:
                size = os.lstat(path).st_size
                if size > MAX_FILE_BYTES:
                    skip(rel, "too_large")
                    continue
                if bytes_read + size > MAX_TOTAL_BYTES:
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
            if bytes_read + len(data) > MAX_TOTAL_BYTES:
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
            bytes_read += len(data)
            if cancelled():
                raise Cancelled()
            fsha = hashlib.sha256(data).hexdigest()
            lines = _LINES.split(text) if kind == "python" else text.split("\n")
            found, counts = [], {"dyn": 0, "long": 0}
            ordinals = {}

            def add(tok, a, b, method, excerpt, literal, _found=found, _ord=ordinals, _fsha=fsha, _rel=rel, _kind=kind):
                ordinal = _ord.get((a, b), 0)
                _ord[(a, b)] = ordinal + 1
                ex, trunc = _window(excerpt, tok)
                rec = {"occurrence_id": _h16(_rel, _fsha, a, b, ordinal, method, tok), "ordinal": ordinal, "path": _rel, "file_sha256": _fsha, "line": a, "end_line": b,
                       "source_kind": _kind, "method": method, "locator": tok, "excerpt": ex, "excerpt_truncated": trunc}
                if literal is not None:
                    rec["string_literal"] = literal
                _found.append(rec)

            def dynamic(line, _c=counts, _rel=rel):
                _c["dyn"] += 1
                diag("dynamic_expression", _rel, line)

            def long_locator(line, _c=counts, _rel=rel):
                _c["long"] += 1
                diag("locator_too_long", _rel, line)

            try:
                if kind == "python":
                    _python(text, lines, add, dynamic, long_locator)
                else:
                    _text(lines, add, dynamic, long_locator)
            except SyntaxError:
                skip(rel, "syntax_error")
                continue
            except Exception:       # ValueError (NUL), RecursionError, MemoryError ...: a per-file skip, never a collection failure
                skip(rel, "parse_error")
                continue
            if cancelled():
                raise Cancelled()
            processed += 1
            dynamic_total += counts["dyn"]
            for rec in found:
                observed += 1
                size = len(json.dumps(rec, sort_keys=True, ensure_ascii=True))
                if capped or len(refs) >= MAX_REFERENCES or record_bytes + size > MAX_RECORD_BYTES:
                    over_limit += 1
                    if not capped and record_bytes + size > MAX_RECORD_BYTES and len(refs) < MAX_REFERENCES:
                        diag("record_bytes", rel)
                    capped = True       # the caps drop everything after the first point at which either is reached (contract 5.3)
                    continue
                record_bytes += size
                refs.append(rec)
    except Cancelled:
        return None
    except Exception:           # unexpected phase-level fault: coverage is incomplete, the collection itself is not failed
        phase_error = True
        diag("phase_error", "*", None)
    refs.sort(key=lambda r: (os.fsencode(r["path"]), r["line"], r["end_line"], r["ordinal"], r["method"], r["locator"]))
    long_total = diag_total.get("locator_too_long", 0)
    complete = bool(not deadline_hit and not skipped_total and not phase_error and not over_file_limit and not over_limit and not long_total)
    groups = len({r["locator"] for r in refs})
    summary = {
        "collector": COLLECTOR, "collector_version": COLLECTOR_VERSION, "extensions": list(EXTENSIONS),
        "globs": {"python": ["*.py"], "dockerfile": list(DOCKERFILE_GLOBS), "shell": list(SHELL_GLOBS)},
        "selected": len(selected), "processed": processed, "bytes_read": bytes_read, "over_file_limit": over_file_limit,
        "not_processed_time_budget": not_processed, "deadline_hit": deadline_hit, "phase_error": phase_error,
        "skipped": {"count": sum(skipped_total.values()), "by_reason": dict(sorted(skipped_total.items()))},
        "dynamic": {"count": dynamic_total},
        "references": {"observed": observed, "recorded": len(refs), "over_limit": over_limit, "groups": groups},
        "diagnostics": diagnostics, "diagnostics_listed_limit": MAX_DIAGNOSTICS,
        "diagnostics_total": {"count": sum(diag_total.values()), "by_code": dict(sorted(diag_total.items()))},
        "complete": complete,
        "limits": {"files": MAX_FILES, "bytes_per_file": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES, "lines_per_file": MAX_LINES,
                   "references": MAX_REFERENCES, "diagnostics": MAX_DIAGNOSTICS, "locator_chars": MAX_LOCATOR, "record_bytes": MAX_RECORD_BYTES,
                   "budget_seconds_soft": budget},
        "timing": "the budget is soft: checked between bounded operations only; an in-flight read or ast.parse can overrun it",
    }
    return {"references": refs, "summary": summary}
