"""Bounded static collection of Python JWT and TLS configuration call sites from the sealed exported tree (Stage 4 increment B).

OpenTrace-authored. Contract ``S4-CRYPTO-SOURCE`` v1.0.0 (``.context/contracts/S4-CRYPTO-SOURCE.md``). Runs as one more phase over the ``*.py`` files
already selected by the ``live.source_declarations`` walk, with its own soft clock. Standard ``ast`` only; nothing is imported, executed, resolved or
downloaded. The existing ``hashlib`` observations (``crypto_sites``) are not re-collected here.

An observation states what source text says at one place: a ``jwt`` encode/decode call and the algorithm literal(s) it names (or that none is stated
or that the value is dynamic), or one TLS-related call/assignment of a known form. It is not execution, not proof that the receiver is the named
library, not a statement about deployed configuration, and an algorithm or flag name is never a vulnerability by itself.

Supported forms (everything else emits nothing):

* JWT: ``<alias>.encode(..)`` / ``<alias>.decode(..)`` where ``alias`` is bound by ``import jwt`` / ``import jwt as alias`` at module level and not
  rebound in the file, or a bare ``encode`` / ``decode`` bound by ``from jwt import ...`` (same single-binding rule). ``algorithm="X"`` (encode) and
  ``algorithms=[...]`` (decode) are read only when they are string literals (a tuple/list of literals for decode).
* TLS (file must import ``paho...`` for the MQTT forms and ``ssl`` for the ssl forms): ``<x>.tls_set(..)``, ``<x>.tls_insecure_set(True|False)``,
  ``ssl.create_default_context(..)``, ``ssl.SSLContext(<ssl.PROTOCOL_*>)``, ``<x>.check_hostname = True|False``, ``<x>.verify_mode = ssl.CERT_*``,
  ``<x>.minimum_version = ssl.TLSVersion.*``.
"""
import ast
import hashlib
import io
import re
import os
import stat
import sys
import time
import tokenize

MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_LINES = 20000
BUDGET_SECONDS = 10.0   # Stage 4: each new phase is at most 10 s soft (S4R-C: +20 s worst case over the pre-existing walk, hashlib and model phases)
MAX_JWT = 500
MAX_TLS = 500
MAX_EXCERPT = 600
MAX_SKIPPED_LISTED = 100
CHUNK = 64 * 1024
COLLECTOR = "opentrace_core/live/crypto_source.py"
COLLECTOR_VERSION = "1"

_VERIFY_MODES = ("CERT_NONE", "CERT_OPTIONAL", "CERT_REQUIRED")


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


class _Bindings(ast.NodeVisitor):
    """Counts every way a name is bound in the file (flow-insensitive) and records module-level imports."""

    def __init__(self):
        self.count, self.jwt_alias, self.jwt_from, self.ssl_alias, self.paho = {}, {}, {}, {}, False

    def bind(self, n):
        self.count[n] = self.count.get(n, 0) + 1

    def visit_Module(self, node):
        for st in node.body:
            if isinstance(st, ast.Import):
                for a in st.names:
                    top = a.name.split(".")[0]
                    if a.name == "jwt":
                        self.jwt_alias[a.asname or "jwt"] = True
                    if a.name == "ssl":
                        self.ssl_alias[a.asname or "ssl"] = True
                    if top == "paho":
                        self.paho = True
            elif isinstance(st, ast.ImportFrom) and st.level == 0 and st.module:
                if st.module == "jwt":
                    for a in st.names:
                        if a.name in ("encode", "decode"):
                            self.jwt_from[a.asname or a.name] = a.name
                if st.module.split(".")[0] == "paho":
                    self.paho = True
        self.generic_visit(node)

    def visit_Import(self, node):
        for a in node.names:
            self.bind((a.asname or a.name).split(".")[0])

    def visit_ImportFrom(self, node):
        for a in node.names:
            self.bind(a.asname or a.name)

    def _def(self, node):
        self.bind(node.name)
        self.generic_visit(node)

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _def

    def visit_arg(self, node):
        self.bind(node.arg)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bind(node.id)

    def visit_ExceptHandler(self, node):
        if node.name:
            self.bind(node.name)
        self.generic_visit(node)

    def visit_Global(self, node):
        for n in node.names:
            self.bind(n)

    visit_Nonlocal = visit_Global


def _literal_str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _algorithms(node):
    """``(list, source)``: ``"literal"`` for a string constant or a non-empty list/tuple/set of only string constants, ``"empty"`` for an empty literal
    collection, else ``dynamic``."""
    one = _literal_str(node)
    if one is not None:
        return [one], "literal"
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)) and not node.elts:
        return None, "empty"
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)) and node.elts and all(_literal_str(e) is not None for e in node.elts):
        return [_literal_str(e) for e in node.elts], "literal"
    return None, "dynamic"


# Only a known algorithm name may survive redaction (FR-02): never a shape check, so a secret placed in an algorithm slot is not shown.
_ALLOWED_LABELS = frozenset(x.lower() for x in (
    "none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES256K", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA", "Ed25519", "Ed448",
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s",
    "shake_128", "shake_256", "ripemd160", "sm3", "sha-1", "sha-224", "sha-256", "sha-384", "sha-512"))


def _lines(text):
    """Physical lines exactly as ``ast`` counts them (``\n``, ``\r`` and ``\r\n``); ``split("\n")`` misaligned ``lineno`` for bare-CR files (FR-01)."""
    return re.split(r"\r\n|\r|\n", text)
_OPEN, _CLOSE = "([{", ")]}"


def _redact(text, keep=None, *, stop_at_call=False):
    """A safe excerpt of ``text``, or ``None`` when it cannot be made safe. ``text`` must START at a code position known from the parsed source
    (an AST node start), never at a line start that could lie inside a string.

    The text is tokenized (not pattern-matched): every string literal (plain, prefixed, escaped, triple-quoted, f-string, implicit concatenation)
    becomes ``"..."`` and every comment is dropped, except a plain unprefixed literal that is one of the known algorithm labels in ``keep``. Anything the tokenizer cannot complete (an unterminated or truncated literal, unbalanced brackets, a fragment that starts
    inside a quote) yields ``None``: uncertain content is omitted, never guessed. ``stop_at_call`` ends the excerpt at the bracket that closes
    the first opened bracket (the call's own closing parenthesis), so trailing text on the same line is never examined or shown."""
    keep = {k for k in (keep or ()) if isinstance(k, str) and k.lower() in _ALLOWED_LABELS}
    if not isinstance(text, str) or "\x00" in text:
        return None
    starts, pos = [], 0
    for ln in text.split("\n"):
        starts.append(pos)
        pos += len(ln) + 1

    def off(rc):
        return starts[rc[0] - 1] + rc[1]
    fstart, fend = getattr(tokenize, "FSTRING_START", None), getattr(tokenize, "FSTRING_END", None)
    spans, depth, fdepth, fbegin, end, opened = [], 0, 0, 0, len(text), False
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text + "\n").readline):
            tt = tok.type
            if fstart is not None and tt == fstart:
                if fdepth == 0:
                    fbegin = off(tok.start)
                fdepth += 1
            elif fend is not None and tt == fend:
                fdepth -= 1
                if fdepth < 0:
                    return None
                if fdepth == 0:
                    spans.append((fbegin, off(tok.end), "fstring"))
            elif fdepth:
                continue
            elif tt == tokenize.STRING:
                spans.append((off(tok.start), off(tok.end), tok.string))
            elif tt == tokenize.COMMENT:
                spans.append((off(tok.start), off(tok.end), None))
            elif tt == tokenize.ERRORTOKEN:
                return None
            elif tt == tokenize.OP and tok.string in _OPEN:
                depth += 1
                opened = True
            elif tt == tokenize.OP and tok.string in _CLOSE:
                depth -= 1
                if depth < 0:
                    return None
                if depth == 0 and opened and stop_at_call:
                    end = off(tok.end)
                    break
            elif tt == tokenize.ENDMARKER:
                break
    except (tokenize.TokenError, SyntaxError, IndentationError, ValueError):
        return None
    if depth != 0 and not (stop_at_call and end != len(text)):
        return None
    if stop_at_call and (not opened or end == len(text) and depth != 0):
        return None
    out, at = [], 0
    for b0, b1, lit in sorted(spans):
        if b0 >= end:
            break
        out.append(text[at:b0])
        if lit is None:
            pass
        elif lit != "fstring" and re.fullmatch(r"([\'\"])([^\\'\"\n]*)\1", lit) and lit[1:-1] in keep:
            out.append(lit)
        else:
            out.append('"\u2026"')
        at = b1
    out.append(text[at:end])
    return "".join(out)


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self, lines, b):
        self.lines, self.b = lines, b
        self.jwt, self.tls = [], []

    def _ex(self, node, keep=None):
        """The excerpt is the node's own source span (start column to end column, from the parsed tree), tokenized and redacted; ``None`` if uncertain."""
        end = getattr(node, "end_lineno", None) or node.lineno
        ecol = getattr(node, "end_col_offset", None)
        try:
            first = self.lines[node.lineno - 1].encode("utf-8")[node.col_offset:]
            if end == node.lineno:
                parts = [first[: ecol - node.col_offset].decode("utf-8")]
            else:
                mid = self.lines[node.lineno:end - 1]
                parts = [first.decode("utf-8")] + mid + [self.lines[end - 1].encode("utf-8")[:ecol].decode("utf-8")]
        except (IndexError, TypeError, UnicodeDecodeError):
            return end, None
        safe = _redact("\n".join(parts), keep)
        return end, (safe[:MAX_EXCERPT] if safe is not None else None)

    def _unique(self, name):
        return self.b.count.get(name, 0) == 1

    def _ssl(self, dotted):
        """``dotted`` rooted at a uniquely bound ``ssl`` alias -> the remainder, else ``None``."""
        if not dotted:
            return None
        head, _, rest = dotted.partition(".")
        return rest if head in self.b.ssl_alias and self._unique(head) and rest else None

    def visit_Call(self, node):
        fn = node.func
        call = None
        if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.attr in ("encode", "decode") \
                and fn.value.id in self.b.jwt_alias and self._unique(fn.value.id):
            call = fn.attr
        elif isinstance(fn, ast.Name) and fn.id in self.b.jwt_from and self._unique(fn.id):
            call = self.b.jwt_from[fn.id]
        if call:
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            name = "algorithm" if call == "encode" else "algorithms"
            starred = any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords)
            third = node.args[2] if len(node.args) >= 3 and not any(isinstance(a, ast.Starred) for a in node.args[:3]) else None
            if name in kw:
                algs, src = _algorithms(kw[name])
            elif third is not None:
                algs, src = _algorithms(third)            # PyJWT accepts the algorithm(s) as the third positional argument
            elif starred:
                algs, src = None, "dynamic"               # **kwargs / *args could supply it
            else:
                algs, src = None, "not_stated"
            end, excerpt = self._ex(node, keep=algs)
            self.jwt.append({"line": node.lineno, "end_line": end, "call": "jwt." + call, "algorithms": algs, "algorithm_source": src, "excerpt": excerpt})
        elif isinstance(fn, ast.Attribute):
            tls = None
            if fn.attr == "tls_set" and self.b.paho:
                tls = {"form": "mqtt_tls_set", "setting": "tls_set", "value": None}
            elif fn.attr == "tls_insecure_set" and self.b.paho:
                arg = node.args[0] if node.args else None
                val = arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, bool) else None
                tls = {"form": "mqtt_tls_insecure_set", "setting": "tls_insecure_set", "value": None if val is None else str(val)}
            else:
                rest = self._ssl(_dotted(fn))
                if rest == "create_default_context":
                    tls = {"form": "ssl_default_context", "setting": "create_default_context", "value": None}
                elif rest == "SSLContext":
                    proto = _dotted(node.args[0]) if node.args else None
                    tail = self._ssl(proto) if proto else None
                    tls = {"form": "ssl_context", "setting": "SSLContext", "value": tail if tail and tail.startswith("PROTOCOL_") else None}
            if tls:
                end, excerpt = self._ex(node)
                self.tls.append(dict(tls, line=node.lineno, end_line=end, excerpt=excerpt))
        self.generic_visit(node)

    def visit_Assign(self, node):
        self._assign(node, node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._assign(node, [node.target], node.value)
        self.generic_visit(node)

    def _assign(self, node, targets, value):
        for t in targets:
            if not isinstance(t, ast.Attribute) or t.attr not in ("check_hostname", "verify_mode", "minimum_version") \
                    or not any(self._unique(a) for a in self.b.ssl_alias):
                continue
            val = None
            if t.attr == "check_hostname" and isinstance(value, ast.Constant) and isinstance(value.value, bool):
                val = str(value.value)
            elif t.attr == "verify_mode":
                tail = self._ssl(_dotted(value))
                val = tail if tail in _VERIFY_MODES else None
            elif t.attr == "minimum_version":
                tail = self._ssl(_dotted(value))
                val = tail if tail and tail.startswith("TLSVersion.") else None
            if val is not None:
                end, excerpt = self._ex(node)
                self.tls.append({"form": "ssl_" + t.attr, "setting": t.attr, "value": val, "line": node.lineno, "end_line": end, "excerpt": excerpt})


def scan_source(text, rel):
    """``(jwt, tls, error)`` for one file."""
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as exc:
        return [], [], "syntax_error: %s" % (exc.msg or "")[:100]
    b = _Bindings()
    b.visit(tree)
    v = _Visitor(_lines(text), b)
    v.visit(tree)
    return v.jwt, v.tls, None


def run_phase(selected, *, cancel=None, clock=time.monotonic, budget=BUDGET_SECONDS, py_total=0, py_over_limit=0, pre_skipped=()):
    """Phase over ``selected`` = ``[(rel, abs_path)]``. ``None`` when cancelled, else ``{"jwt","tls","summary"}``."""
    started = clock()
    skipped, skipped_total = [], {}
    for rel, reason in pre_skipped:
        skipped_total[reason] = skipped_total.get(reason, 0) + 1
        if len(skipped) < MAX_SKIPPED_LISTED:
            skipped.append({"path": rel, "reason": reason})
    jwt, tls = [], []
    totals = {"jwt": 0, "tls": 0}
    syntax_total = parsed = total_bytes = not_parsed = 0
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
                j, t, err = scan_source(text, rel)
            except Exception:
                skip(rel, "parse_error")
                continue
            if cancelled():
                raise Cancelled()
            if err:
                syntax_total += 1
                continue
            parsed += 1
            if not (j or t):
                continue
            fsha = hashlib.sha256(data).hexdigest()
            for o in sorted(j, key=lambda x: (x["line"], x["call"])):
                totals["jwt"] += 1
                if len(jwt) < MAX_JWT:
                    jwt.append(dict(o, path=rel, file_sha256=fsha))
            for o in sorted(t, key=lambda x: (x["line"], x["setting"])):
                totals["tls"] += 1
                if len(tls) < MAX_TLS:
                    tls.append(dict(o, path=rel, file_sha256=fsha))
    except Cancelled:
        return None
    over = {"jwt": max(0, totals["jwt"] - MAX_JWT), "tls": max(0, totals["tls"] - MAX_TLS)}
    complete = (not deadline_hit and not skipped_total and not syntax_total and not any(over.values()) and py_over_limit == 0)
    summary = {"python_files_total": py_total, "selected": len(selected), "parsed": parsed, "not_parsed_time_budget": not_parsed,
               "over_file_limit": py_over_limit, "deadline_hit": deadline_hit,
               "skipped": {"count": sum(skipped_total.values()), "by_reason": dict(sorted(skipped_total.items())), "listed": skipped, "listed_limit": MAX_SKIPPED_LISTED},
               "syntax_errors": {"count": syntax_total}, "observed": dict(totals), "recorded": {"jwt": len(jwt), "tls": len(tls)}, "over_limit": over,
               "bytes_parsed": total_bytes, "complete": complete,
               "limits": {"bytes_per_file": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES, "lines_per_file": MAX_LINES, "jwt": MAX_JWT, "tls": MAX_TLS,
                          "budget_seconds_soft": budget},
               "python_version": ".".join(str(x) for x in sys.version_info[:3]),
               "timing": "the budget is soft: checked between bounded operations only; an in-flight parse can overrun it"}
    return {"jwt": jwt, "tls": tls, "summary": summary}


def present(sink):
    """Session-only presentation input for the Crypto tab: this module's observations plus the existing hashlib sites, from one collection sink.

    ``None`` when there is no collection result; ``{"state": "failed", "code"}`` when the collector faulted or recorded nothing; else
    ``{"state": "collected", "hashlib", "jwt", "tls", "summary", "hashlib_complete"}``. Copies only; nothing is inferred."""
    if not isinstance(sink, dict) or not sink:
        return None
    record = sink.get("record")
    block = record.get("crypto_source") if isinstance(record, dict) else None
    if sink.get("status") != "collected" or not isinstance(block, dict):
        return {"state": "failed", "code": str(sink.get("code") or sink.get("status") or "no_record")[:60]}
    sm = sink.get("summary") or {}
    py = sm.get("python") or {}
    local = (sm.get("local_module") or {}).get("status")
    return {"state": "collected", "hashlib": list(record.get("crypto_call_sites") or []), "jwt": list(block["jwt"]), "tls": list(block["tls"]),
            "summary": dict(block["summary"]), "hashlib_complete": bool(py.get("complete")) and local != "present"}
