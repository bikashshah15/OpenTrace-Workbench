"""E3-C raw-inventory lookup: what does a captured CycloneDX document itself record about one frozen reference item?

Independent of OpenTrace: nothing here imports ``opentrace_core``, and no OpenTrace verdict, rule, collector or alias table is
used. The reference items are the frozen external anchors; a missing or unknown output never removes one from a denominator.

Statuses: ``unique_match``, ``absent``, ``ambiguous``, ``insufficient_location_or_identity``, ``parse_incomplete``,
``inventory_unavailable``. A representation difference is not, by itself, a scanner defect.
"""
from __future__ import annotations

import json
import re

# Finite equivalence sets for the four selected algorithms, fixed before any scan (lower-cased record names).
HASH_NAMES = {"md5": ("md5", "md-5"), "sha1": ("sha1", "sha-1"), "sha256": ("sha256", "sha-256", "sha2-256"),
              "sha3_256": ("sha3-256", "sha3_256", "sha3256", "sha-3-256")}
WORKER_SOURCE = re.compile(r"^/spool/in/[0-9a-f]{32}/src/")


def walk(components, pointer="/components"):
    for i, c in enumerate(components if isinstance(components, list) else []):
        if isinstance(c, dict):
            here = f"{pointer}/{i}"
            yield here, c
            yield from walk(c.get("components"), here + "/components")


def parse_document(data: bytes) -> dict:
    doc = json.loads(data.decode("utf-8"))
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX" or not isinstance(doc.get("components", []), list):
        raise ValueError("not a CycloneDX JSON document with a component list")
    return doc


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def rel_path(value: str) -> str:
    """A producer path relative to the scanned root: strips a leading ``/`` or ``./`` and the worker's job source prefix."""
    value = WORKER_SOURCE.sub("", str(value))
    return re.sub(r"^(\./|/)+", "", value)


def _properties(c):
    return [p for p in c.get("properties") or [] if isinstance(p, dict)]


def _ecosystem(c):
    purl = c.get("purl")
    if isinstance(purl, str) and purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0].lower()
    for p in _properties(c):
        if p.get("name") == "syft:package:type":
            return {"python": "pypi"}.get(p.get("value"), p.get("value"))
    return None


def _result(status, reason, records=(), **extra):
    return {"status": status, "reason": reason, "records": list(records), **extra}


def sbom_lookup(doc: dict | None, name: str, declared_file: str) -> dict:
    """Name-level PyPI representation (not version, installation or completeness).

    With several distinct identities of the name, the one attributed to the declaring file is taken if it is the only one so
    attributed; otherwise the item is ``ambiguous``.
    """
    if doc is None:
        return _result("inventory_unavailable", "no usable captured SBOM", name_present=None, file_attributed=None, declared_file_listed=None)
    comps = list(walk(doc.get("components")))
    listed = [c for _, c in comps if c.get("type") == "file" and rel_path(c.get("name", "")) == declared_file]
    libs = [(p, c) for p, c in comps if c.get("type") == "library"]
    unclassified = sum(1 for _, c in libs if not c.get("name") or _ecosystem(c) is None)
    want = pep503(name)
    hits = []
    for pointer, c in libs:
        if c.get("name") and _ecosystem(c) == "pypi" and pep503(c["name"]) == want:
            locs = sorted({rel_path(p.get("value")) for p in _properties(c) if re.fullmatch(r"syft:location:\d+:path", str(p.get("name")))})
            hits.append({"pointer": pointer, "bom_ref": c.get("bom-ref"), "name": c["name"], "version": c.get("version"), "purl": c.get("purl"), "locations": locs})
    other_eco = [p for p, c in libs if c.get("name") and pep503(c["name"]) == want and _ecosystem(c) not in ("pypi", None)]
    identity = lambda h: h["purl"] or (h["name"], h["version"])
    here = [h for h in hits if declared_file in h["locations"]]
    extra = {"name_present": bool(hits), "file_attributed": bool(here), "declared_file_listed": bool(listed),
             "other_ecosystem_records": other_eco, "library_components": len(libs), "unclassified_components": unclassified}
    if hits:
        if len({identity(h) for h in hits}) == 1:
            return _result("unique_match", "one pypi identity with this normalized name", hits, **extra)
        if len({identity(h) for h in here}) == 1:
            return _result("unique_match", "several identities; exactly one is attributed to the declaring file", hits, **extra)
        return _result("ambiguous", f"{len({identity(h) for h in hits})} distinct pypi identities share the name", hits, **extra)
    if unclassified:
        return _result("parse_incomplete", f"no match, and {unclassified} library record(s) have no usable name or ecosystem", **extra)
    return _result("absent", "no pypi library record with this normalized name", **extra)


def _occurrences(c):
    """``(path, line, convention)`` for every recorded occurrence; ``line`` is None when the record gives none."""
    out = []
    for o in (c.get("evidence") or {}).get("occurrences") or []:
        if not isinstance(o, dict) or not o.get("location"):
            continue
        path, line, how = str(o["location"]), o.get("line"), "line_field"
        if not isinstance(line, int):
            m = re.search(r"(?:#L?|:)(\d+)$", path)
            line, how = (int(m.group(1)), "line_in_location_suffix") if m else (None, "no_line")
            if m:
                path = path[:m.start()]
        out.append((rel_path(path), line, how))
    return out


def cbom_lookup(doc: dict | None, constructor: str, path: str, lines: list[int]) -> dict:
    """Strict occurrence-level representation: an ``algorithm`` record of this hash with an occurrence on an annotated line.

    The weaker ``algorithm_level`` flag (the algorithm is recorded anywhere) is reported separately and is not a match.
    """
    if doc is None:
        return _result("inventory_unavailable", "no usable captured CBOM", algorithm_level=None, records_at_location=None, crypto_assets=None)
    names = HASH_NAMES[constructor]
    assets = [(p, c) for p, c in walk(doc.get("components")) if c.get("type") == "cryptographic-asset"]
    strict, same, unlocated, at_site = [], [], [], []
    for pointer, c in assets:
        props = c.get("cryptoProperties") or {}
        occ = _occurrences(c)
        rec = {"pointer": pointer, "bom_ref": c.get("bom-ref"), "name": c.get("name"), "asset_type": props.get("assetType"),
               "primitive": (props.get("algorithmProperties") or {}).get("primitive"),
               "occurrences": [{"location": p, "line": n, "convention": h} for p, n, h in occ]}
        here = [o for o in occ if o[0] == path and o[1] in lines]
        if here:
            at_site.append(rec)
        if str(c.get("name", "")).lower() not in names:
            continue
        same.append(rec)
        if props.get("assetType") == "algorithm":
            strict += [rec for _ in here]
        if not occ or any(p == path and n is None for p, n, _ in occ):
            unlocated.append(rec)
    extra = {"algorithm_level": bool(same), "records_at_location": at_site, "crypto_assets": len(assets),
             "empty_inventory": not assets, "accepted_names": list(names)}
    if len(strict) == 1:
        return _result("unique_match", "one algorithm occurrence on the annotated line(s)", strict, **extra)
    if strict:
        return _result("ambiguous", f"{len(strict)} matching occurrences on the annotated line(s)", strict, **extra)
    if any(r["asset_type"] != "algorithm" for r in at_site if r in same):
        return _result("insufficient_location_or_identity", "a record of this name is on the line but is not an algorithm asset", same, **extra)
    if unlocated:
        return _result("insufficient_location_or_identity", "the algorithm is recorded without a usable file and line", unlocated, **extra)
    return _result("absent", "no occurrence of this algorithm on the annotated line(s)"
                   + ("; the inventory has no cryptographic asset" if not assets else ""), same, **extra)
