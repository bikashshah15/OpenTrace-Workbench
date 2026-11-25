"""BOMBridge experimental source-derived crypto inventory.

A deliberately small, deterministic extractor: it finds Python `hashlib` call sites with the standard `ast` module and
writes them as a CycloneDX 1.6 CBOM-shaped document. It is NOT a third-party CBOM generator, has not been validated
against any standard, and covers one construct family only:

  covered:      calls to hashlib.<hash>(...), hashlib.new("<alg>"), hashlib.pbkdf2_hmac("<alg>", ...), hashlib.scrypt,
                including `import hashlib as h` and `from hashlib import md5 as x` aliases.
  not covered:  every other library (pyca/cryptography, ssl, hmac, secrets, ...), dynamic algorithm names, getattr calls,
                code in non-Python files, anything not parsed (syntax errors are reported). Imports of other crypto modules
                are listed as "observed, not inventoried" and are not operations.

A call site says an algorithm is *invoked in source at that location*. It does not say the code runs, what data is hashed,
that the result is used for integrity or security, or that the algorithm choice is a vulnerability.
"""

import ast
import hashlib
import json
import uuid

LABEL = "BOMBridge experimental source-derived crypto inventory"
VERSION = "0.1"
HASHES = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256", "sha3_224", "sha3_256", "sha3_384", "sha3_512",
          "blake2b", "blake2s", "shake_128", "shake_256"}
OIDS = {"md5": "2.16.840.1.113549.2.5", "sha1": "1.3.14.3.2.26", "sha224": "2.16.840.1.101.3.4.2.4", "sha256": "2.16.840.1.101.3.4.2.1",
        "sha384": "2.16.840.1.101.3.4.2.2", "sha512": "2.16.840.1.101.3.4.2.3"}
OTHER_CRYPTO_MODULES = {"cryptography", "ssl", "hmac", "secrets", "bcrypt", "passlib", "jwt", "Crypto", "OpenSSL"}


def _norm(name):
    return name.lower().replace("-", "").replace("_", "") if name else name


def canonical_alg(name):
    """'SHA-256' / 'sha256' / 'sha_256' -> 'sha256'; unknown names are returned lower-cased."""
    n = (name or "").lower().replace("-", "").replace("_", "")
    for h in sorted(HASHES, key=len, reverse=True):
        if _norm(h) == n:
            return h
    return (name or "").lower()


class _Visitor(ast.NodeVisitor):
    def __init__(self, path, lines):
        self.path, self.lines = path, lines
        self.module_aliases, self.func_aliases = set(), {}
        self.stack, self.sites, self.observed = [], [], []

    def visit_Import(self, node):
        for a in node.names:
            top = a.name.split(".")[0]
            if a.name == "hashlib":
                self.module_aliases.add(a.asname or "hashlib")
            elif top in OTHER_CRYPTO_MODULES:
                self.observed.append({"module": a.name, "line": node.lineno})

    def visit_ImportFrom(self, node):
        if node.module == "hashlib" and node.level == 0:
            for a in node.names:
                self.func_aliases[a.asname or a.name] = a.name
        elif node.module and node.level == 0 and node.module.split(".")[0] in OTHER_CRYPTO_MODULES:
            self.observed.append({"module": node.module, "line": node.lineno})

    def _scope(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scope

    def visit_Call(self, node):
        fn = None
        f = node.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in self.module_aliases:
            fn = f.attr
        elif isinstance(f, ast.Name) and f.id in self.func_aliases:
            fn = self.func_aliases[f.id]
        if fn:
            self._record(node, fn)
        self.generic_visit(node)

    def _record(self, node, fn):
        first = node.args[0] if node.args else None
        const = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else None
        if fn in HASHES:
            alg, how = fn, "hashlib." + fn
        elif fn in ("new", "pbkdf2_hmac"):
            alg, how = (canonical_alg(const) if const else None), "hashlib." + fn
        elif fn == "scrypt":
            alg, how = "scrypt", "hashlib.scrypt"
        else:
            return
        site = {"file": self.path, "line": node.lineno, "end_line": node.end_lineno, "col": node.col_offset, "call": how,
                "algorithm": alg, "algorithm_resolved": alg is not None,
                "context": ".".join(self.stack) or "<module>", "source_line": self.lines[node.lineno - 1].strip()}
        for kw in node.keywords:
            if kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant):
                site["usedforsecurity"] = kw.value.value
        self.sites.append(site)


def scan_source(path, text):
    """Return (sites, observed_imports, error) for one file."""
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as e:
        return [], [], f"{e.msg} (line {e.lineno})"
    v = _Visitor(path, text.splitlines())
    v.visit(tree)
    return v.sites, v.observed, None


def build_cbom(files, repository, revision, scope_sha256):
    """files: {relative_path: text}. Returns a CycloneDX 1.6 CBOM-shaped dict (deterministic: no timestamp)."""
    sites, observed, errors, n_parsed = [], [], [], 0
    for p in sorted(files):
        s, o, err = scan_source(p, files[p])
        if err:
            errors.append({"file": p, "error": err})
            continue
        n_parsed += 1
        sites += s
        observed += [{"file": p, **x} for x in o]
    by_alg = {}
    for s in sites:
        by_alg.setdefault(s["algorithm"] or "unresolved", []).append(s)
    comps = []
    for alg in sorted(by_alg):
        c = {"type": "cryptographic-asset", "bom-ref": f"crypto/algorithm/{alg}", "name": alg,
             "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash" if alg in HASHES or alg == "unresolved" else "other"}},
             "evidence": {"occurrences": [{"location": s["file"], "line": s["line"], "offset": s["col"],
                                           "additionalContext": f"{s['call']} in {s['context']}" + (f"; usedforsecurity={s['usedforsecurity']}" if "usedforsecurity" in s else "")}
                                          for s in sorted(by_alg[alg], key=lambda x: (x["file"], x["line"], x["col"]))]}}
        if alg in OIDS:
            c["cryptoProperties"]["oid"] = OIDS[alg]
        if alg == "unresolved":
            c["description"] = "hashlib call whose algorithm is not a string literal; not resolved by this extractor"
        comps.append(c)
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, scope_sha256)),
            "metadata": {"tools": {"components": [{"type": "application", "name": LABEL, "version": VERSION, "author": "BOMBridge (this repository)"}]},
                         "component": {"type": "application", "bom-ref": "subject", "name": repository, "version": revision},
                         "properties": [{"name": "bombridge:label", "value": LABEL},
                                        {"name": "bombridge:extraction-method", "value": "python-ast call-site detection of hashlib; not validated against any standard"},
                                        {"name": "bombridge:scope-listing-sha256", "value": scope_sha256},
                                        {"name": "bombridge:files-parsed", "value": str(n_parsed)},
                                        {"name": "bombridge:parse-errors", "value": json.dumps(errors, sort_keys=True)},
                                        {"name": "bombridge:observed-not-inventoried", "value": json.dumps(sorted(observed, key=lambda x: (x["file"], x["line"], x["module"])), sort_keys=True)}]},
            "components": comps,
            "compositions": [{"aggregate": "incomplete", "assemblies": [c["bom-ref"] for c in comps]}]}
