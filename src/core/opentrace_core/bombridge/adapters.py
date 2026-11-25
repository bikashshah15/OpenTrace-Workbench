"""Small input adapters for the requirement-to-inventory check. No universal parser.

They turn two raw inputs into *observations* (plain dicts for evidence records):
  - lines of a pip requirements file that name one package,
  - a lookup of one package identity in a CycloneDX inventory.
Judgments (represented / not represented) are made by rules_inventory, not here.
"""

import re

from .assess import digest_error

SUPPORTED_FORMS = ("exact_pin", "wildcard_pin", "range", "direct_url", "vcs", "unpinned")
_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]*"
_LINE = re.compile(rf"^(?P<name>{_NAME})\s*(?P<extras>\[[^\]]*\])?\s*(?P<rest>.*)$")
_WHEEL = re.compile(r"^(?P<dist>[^-]+)-(?P<version>[^-]+)(?:-(?P<build>\d[^-]*))?-(?P<py>[^-]+)-(?P<abi>[^-]+)-(?P<plat>[^-]+)\.whl$")
_INLINE_COMMENT = re.compile(r"(^|\s+)#.*$")  # pip: a comment starts at '#' preceded by whitespace (so '#egg=' in a URL is not one)
_DIRECTIVES = {"-r": "requirement_file", "--requirement": "requirement_file", "-c": "constraint_file", "--constraint": "constraint_file",
               "-e": "editable", "--editable": "editable"}


def normalize_name(name):
    """PEP 503 normalization: runs of -, _, . become '-', lower-cased (equal to packaging.utils.canonicalize_name)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def walk_components(comps, base="/components"):
    """Yield (component, raw_pointer) for a CycloneDX components list and every nested components list (depth first).

    I8: from the BOMBridge gap-discovery overlay (Peiran Shi), unchanged.
    """
    for i, c in enumerate(comps if isinstance(comps, list) else []):
        if not isinstance(c, dict):
            continue
        ptr = f"{base}/{i}"
        yield c, ptr
        if isinstance(c.get("components"), list):
            yield from walk_components(c["components"], ptr + "/components")


def wheel_identity(url):
    """Identity read from a wheel *file name* in a URL (PEP 427). Nothing is downloaded or inspected."""
    m = _WHEEL.match(url.split("#")[0].split("?")[0].rsplit("/", 1)[-1])
    if not m:
        return None
    return {"distribution": m["dist"], "version": m["version"], "python_tag": m["py"], "abi_tag": m["abi"],
            "platform_tag": m["plat"], "source": "file name in URL only"}


def parse_requirement_line(raw):
    """One requirement line -> dict, or None for blank/comment. Unsupported shapes get form='unsupported'.

    Follows pip's line handling where it is unambiguous: an inline comment (' #...') is dropped, a bare name is a requirement
    without a version constraint (form 'unpinned'). pip options and file directives (-r, -c, -e, --index-url, ...) are
    'unsupported' requirement lines; a directive is described under 'directive' so a caller can report it, but no referenced
    file is followed here. Markers are preserved verbatim as text and are not evaluated.

    I8 adaptation: the overlay's optional PEP 508 check through the ``packaging`` library (``_pep508_ok``) is NOT ported, so
    this module keeps its stdlib/networkx-only import boundary. The overlay itself falls back to this regex-only behaviour
    when ``packaging`` is absent; the 79 requirement candidates for the recorded Frigate case are identical with and without it.
    """
    s = _INLINE_COMMENT.sub("", raw).strip()
    if not s:
        return None
    if s.startswith("git+"):
        egg = re.search(r"#egg=([A-Za-z0-9._-]+)", s)
        return {"raw": raw, "form": "vcs" if egg else "unsupported", "name": egg.group(1) if egg else None, "url": s.split("#")[0], "marker": None}
    if s.startswith("-"):
        opt, _, arg = s.partition(" ") if " " in s else s.partition("=")
        return {"raw": raw, "form": "unsupported", "name": None, "marker": None,
                "directive": {"option": opt, "kind": _DIRECTIVES.get(opt, "option"), "argument": arg.strip().strip("'\"") or None}}
    spec, _, marker = s.partition(";")
    marker = marker.strip() or None
    m = _LINE.match(spec.strip())
    if not m:
        return {"raw": raw, "form": "unsupported", "name": None, "marker": marker}
    name, rest = m["name"], m["rest"].strip()
    d = {"raw": raw, "name": name, "marker": marker, "extras": m["extras"]}
    if rest.startswith("@"):
        url = rest[1:].strip()
        d.update(form="direct_url", url=url, wheel=wheel_identity(url))
    elif not rest:
        d.update(form="unpinned")
    elif re.fullmatch(r"==\s*[A-Za-z0-9_.!+-]+\.\*", rest):
        d.update(form="wildcard_pin", specifier=rest.replace(" ", ""))
    elif re.fullmatch(r"==\s*[A-Za-z0-9_.!+-]+", rest):
        d.update(form="exact_pin", specifier=rest.replace(" ", ""))
    elif re.fullmatch(r"(?:(?:~=|>=|<=|!=|<|>|===?)\s*[A-Za-z0-9_.!+*-]+\s*,?\s*)+", rest):
        d.update(form="range", specifier=rest.replace(" ", ""))
    else:
        d.update(form="unsupported", name=None)
    return d


def requirement_declaration_observation(text, rel_path, file_sha256, target_name):
    """Observation: what a requirements file declares for one package, plus a summary of the whole file."""
    target = normalize_name(target_name)
    forms, unsupported, found = {}, [], []
    for n, raw in enumerate(text.splitlines(), 1):
        p = parse_requirement_line(raw)
        if p is None:
            continue
        forms[p["form"]] = forms.get(p["form"], 0) + 1
        if p["form"] == "unsupported":
            unsupported.append(n)
        elif normalize_name(p["name"]) == target:
            found.append({"line": n, **{k: v for k, v in p.items() if k not in ("raw",) and v is not None},
                          "normalized_name": target, "original_text": raw.strip()})
    return {"kind": "requirement_declaration", "artifact": {"locator": rel_path}, "file_sha256": file_sha256,
            "file_sha256_algorithm": "sha256", "target": {"normalized_name": target}, "declarations": found,
            "file_summary": {"requirement_lines": sum(forms.values()), "forms": dict(sorted(forms.items())),
                             "unsupported_lines": unsupported},
            "markers_note": "markers are preserved as text; none was evaluated"}


def _prop(c, name):
    return next((p["value"] for p in c.get("properties", []) if p["name"] == name), None)


def _ecosystem(c):
    purl = c.get("purl")
    if purl and purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0]
    t = _prop(c, "syft:package:type")
    return {"python": "pypi"}.get(t, t)  # other Syft types are kept as-is (never equal to 'pypi')


def inventory_lookup_observation(cdx, raw_sha256, normalized_name, rel_path, ecosystem="pypi"):
    """Observation: exact (normalized name, ecosystem) lookup in a CycloneDX inventory.

    No substring matching. Also reports how completely the inventory could be parsed and whether
    it lists the requirements file it is being compared with (path suffix + recorded SHA-256).
    Nested components (components[].components[]) are traversed, so a library recorded only inside another
    component is found; `parse.complete` is never true for records that were not read.
    """
    comps = [c for c, _ in walk_components(cdx.get("components", []))]
    libs = [c for c in comps if c.get("type") == "library"]
    unclassified = [c for c in libs if not c.get("name") or _ecosystem(c) is None]
    matches = []
    for c in libs:
        if c.get("name") and _ecosystem(c) == ecosystem and normalize_name(c["name"]) == normalized_name:
            matches.append({"bom_ref": c.get("bom-ref"), "name": c["name"], "version": c.get("version"), "purl": c.get("purl"),
                            "locations": sorted(p["value"] for p in c.get("properties", []) if re.fullmatch(r"syft:location:\d+:path", p["name"]))})
    files = [c for c in comps if c.get("type") == "file" and c.get("name", "").endswith("/" + rel_path)]
    attributed = sorted(c["name"] for c in libs if _ecosystem(c) == ecosystem
                        and ("/" + rel_path) in [p["value"] for p in c.get("properties", []) if re.fullmatch(r"syft:location:\d+:path", p["name"])])
    tools = [t for t in cdx.get("metadata", {}).get("tools", {}).get("components", []) if isinstance(t, dict)]
    return {"kind": "inventory_name_lookup",
            "inventory": {"format": f"{cdx.get('bomFormat')} {cdx.get('specVersion')}", "raw_sha256": raw_sha256,
                          "generator": " ".join(f"{t.get('name')} {t.get('version')}" for t in tools) or None},
            "query": {"normalized_name": normalized_name, "ecosystem": ecosystem, "match": "exact normalized name; no substring matching"},
            "parse": {"components_total": len(comps), "library_components": len(libs), "unclassified_components": len(unclassified),
                      "complete": not unclassified},
            "scanned_file": {"path": rel_path, "file_components_matching_path_suffix": len(files),
                             "recorded_sha256": sorted(h["content"].lower() for f in files for h in f.get("hashes", []) if h.get("alg") == "SHA-256")},
            "components_attributed_to_selected_file": attributed,
            "matches": matches}


# --------------------------------------------------------------------------------------------
# AI-BOM intake: CycloneDX 1.6 only (the ML-BOM output documented for Cisco AI BOM, `-o cyclonedx`).
# Read: metadata.{timestamp,tools,component}, serialNumber, version, compositions[], components[]
# of type machine-learning-model with bom-ref, name, version, group, purl, hashes[], externalReferences[],
# evidence.occurrences[]. Everything else stays only in the raw file. Other spec versions are not read.
# --------------------------------------------------------------------------------------------
AIBOM_SPEC = "1.6"
_ALG = {"SHA-256": "sha256", "SHA-512": "sha512"}
_SHA40 = re.compile(r"[0-9a-f]{40}")


class AibomError(ValueError):
    """Malformed AI-BOM input (a validation error, not a finding)."""


def _list(d, key, where):
    v = d.get(key, [])
    if not isinstance(v, list):
        raise AibomError(f"{where}.{key} must be a list")
    return v


def _norm_hash(h, where, limits):
    if not (isinstance(h, dict) and isinstance(h.get("alg"), str) and isinstance(h.get("content"), str)):
        raise AibomError(f"{where}: hash needs string 'alg' and 'content'")
    if not re.fullmatch(r"[0-9a-fA-F]+", h["content"]):
        raise AibomError(f"{where}: hash content is not hexadecimal")
    alg = _ALG.get(h["alg"])
    if alg and digest_error(alg, h["content"]):
        raise AibomError(f"{where}: {digest_error(alg, h['content'])}")
    if not alg:
        limits.append(f"{where}: hash algorithm {h['alg']!r} is not normalized (supported: {sorted(_ALG)})")
    return {"alg": h["alg"], "content": h["content"], "normalized_algorithm": alg}


def aibom_document_observation(doc, raw_sha256):
    """Observation describing an AI-BOM document and its model declarations. Raises AibomError if malformed.

    A scope is never inferred here: `subject.declared_revision` is set only from a 40-hex
    metadata.component.version in the document itself.
    """
    if not isinstance(doc, dict):
        raise AibomError("AI-BOM must be a JSON object")
    if doc.get("bomFormat") != "CycloneDX":
        raise AibomError(f"bomFormat must be 'CycloneDX', got {doc.get('bomFormat')!r}")
    spec = doc.get("specVersion")
    if not isinstance(spec, str):
        raise AibomError("specVersion is missing or not a string")
    comps = _list(doc, "components", "document")
    md = doc.get("metadata", {})
    if not isinstance(md, dict):
        raise AibomError("metadata must be an object")
    limits = []
    obs = {"kind": "aibom_document",
           "document": {"format": "CycloneDX", "spec_version": spec, "serial_number": doc.get("serialNumber"),
                        "document_version": doc.get("version"), "timestamp": md.get("timestamp"), "raw_sha256": raw_sha256},
           "producer": None, "subject": None, "coverage": {"stated": False, "compositions": []}, "models": [],
           "counts": {"components_total": len(comps)}, "limitations": limits, "status": "ok"}
    if spec != AIBOM_SPEC:
        obs["status"] = "unsupported"
        limits.append(f"spec version {spec} is not read by this adapter (supported: {AIBOM_SPEC}); no model declaration was extracted")
        return obs
    for i, c in enumerate(comps):
        if not (isinstance(c, dict) and isinstance(c.get("type"), str) and isinstance(c.get("name"), str)):
            raise AibomError(f"components[{i}] needs string 'type' and 'name'")
    tools = md.get("tools")
    tl = tools.get("components", []) if isinstance(tools, dict) else tools if isinstance(tools, list) else []
    if tl and all(isinstance(t, dict) for t in tl):
        obs["producer"] = [{"name": t.get("name"), "version": t.get("version"), "vendor": t.get("author") or t.get("publisher") or t.get("vendor")} for t in tl]
    else:
        limits.append("no producer (metadata.tools) recorded")
    sub = md.get("component")
    if isinstance(sub, dict):
        ver = sub.get("version") if isinstance(sub.get("version"), str) else None
        obs["subject"] = {"bom_ref": sub.get("bom-ref"), "type": sub.get("type"), "name": sub.get("name"), "version": ver,
                          "declared_revision": {"value": ver, "basis": "metadata.component.version is a 40-hex string"} if ver and _SHA40.fullmatch(ver) else None}
    if not obs["subject"]:
        limits.append("no metadata.component: the document names no subject")
    if not (obs["subject"] or {}).get("declared_revision"):
        limits.append("the document declares no source revision; scope cannot be taken from the document")
    comp = _list(doc, "compositions", "document")
    obs["coverage"] = {"stated": bool(comp), "compositions": [
        {"aggregate": x.get("aggregate"), "assemblies": x.get("assemblies", []), "dependencies": x.get("dependencies", [])} for x in comp if isinstance(x, dict)]}
    if not comp:
        limits.append("the document states no coverage (no compositions)")
    types = {}
    for i, c in enumerate(comps):
        types[c["type"]] = types.get(c["type"], 0) + 1
        if c.get("components"):
            limits.append(f"components[{i}] has nested components, which are not read")
        if c["type"] != "machine-learning-model":
            continue
        where = f"components[{i}]"
        hashes = [_norm_hash(h, f"{where}.hashes[{k}]", limits) for k, h in enumerate(_list(c, "hashes", where))]
        refs = []
        for k, r in enumerate(_list(c, "externalReferences", where)):
            if not (isinstance(r, dict) and isinstance(r.get("url"), str)):
                raise AibomError(f"{where}.externalReferences[{k}] needs a string 'url'")
            refs.append({"type": r.get("type"), "url": r["url"]})
        ev = c.get("evidence", {}) if isinstance(c.get("evidence"), dict) else {}
        locs = []
        for k, o in enumerate(_list(ev, "occurrences", f"{where}.evidence")):
            if not (isinstance(o, dict) and isinstance(o.get("location"), str)):
                raise AibomError(f"{where}.evidence.occurrences[{k}] needs a string 'location'")
            locs.append({"file": o["location"], "line": o.get("line")})
        if not hashes:
            limits.append(f"{where}: model declares no hash (representable, but its digest cannot be verified)")
        props = {p["name"]: p.get("value") for p in c.get("properties", []) if isinstance(p, dict) and str(p.get("name", "")).startswith("cisco-aibom:")}
        obs["models"].append({"raw_pointer": f"/components/{i}", "bom_ref": c.get("bom-ref"), "name": c["name"], "version": c.get("version"),
                              "group": c.get("group"), "purl": c.get("purl"), "hashes": hashes, "external_references": refs, "locations": locs,
                              "generator_properties": props})
    obs["counts"].update(models=len(obs["models"]), by_type=dict(sorted(types.items())))
    if not obs["models"]:
        limits.append("the document declares no machine-learning-model component")
    return obs


# --------------------------------------------------------------------------------------------
# CBOM intake: CycloneDX 1.6 documents with components of type cryptographic-asset.
# Read: serialNumber, version, metadata.{tools,component,properties named bombridge:*}, compositions[], and per asset:
# bom-ref, name, description, cryptoProperties.{assetType, oid, algorithmProperties.primitive}, evidence.occurrences[].
# Everything else stays only in the raw file. Other spec versions are not read.
# --------------------------------------------------------------------------------------------
CRYPTO_LIBRARY_NAMES = frozenset({"cryptography", "pycryptodome", "pycryptodomex", "pynacl", "pyopenssl", "bcrypt", "passlib", "hashlib", "openssl", "libssl", "m2crypto",
                                  "argon2-cffi", "ecdsa", "rsa", "paramiko"})


def cbom_document_observation(doc, raw_sha256):
    """Observation describing a CBOM document and its cryptographic assets. Raises AibomError if malformed."""
    if not isinstance(doc, dict):
        raise AibomError("CBOM must be a JSON object")
    if doc.get("bomFormat") != "CycloneDX":
        raise AibomError(f"bomFormat must be 'CycloneDX', got {doc.get('bomFormat')!r}")
    spec = doc.get("specVersion")
    if not isinstance(spec, str):
        raise AibomError("specVersion is missing or not a string")
    comps = _list(doc, "components", "document")
    md = doc.get("metadata", {})
    if not isinstance(md, dict):
        raise AibomError("metadata must be an object")
    limits = []
    obs = {"kind": "cbom_document",
           "document": {"format": "CycloneDX", "spec_version": spec, "serial_number": doc.get("serialNumber"), "document_version": doc.get("version"),
                        "timestamp": md.get("timestamp"), "raw_sha256": raw_sha256},
           "producer": None, "subject": None, "coverage": {"stated": False, "compositions": []}, "assets": [],
           "extractor_notes": {}, "counts": {"components_total": len(comps)}, "limitations": limits, "status": "ok"}
    if spec != AIBOM_SPEC:
        obs["status"] = "unsupported"
        limits.append(f"spec version {spec} is not read by this adapter (supported: {AIBOM_SPEC}); no asset was extracted")
        return obs
    for i, c in enumerate(comps):
        if not (isinstance(c, dict) and isinstance(c.get("type"), str) and isinstance(c.get("name"), str)):
            raise AibomError(f"components[{i}] needs string 'type' and 'name'")
    tools = md.get("tools")
    tl = tools.get("components", []) if isinstance(tools, dict) else tools if isinstance(tools, list) else []
    if tl and all(isinstance(t, dict) for t in tl):
        obs["producer"] = [{"name": t.get("name"), "version": t.get("version"), "vendor": t.get("author") or t.get("publisher") or t.get("vendor")} for t in tl]
    else:
        limits.append("no producer (metadata.tools) recorded")
    sub = md.get("component")
    if isinstance(sub, dict):
        ver = sub.get("version") if isinstance(sub.get("version"), str) else None
        obs["subject"] = {"bom_ref": sub.get("bom-ref"), "type": sub.get("type"), "name": sub.get("name"), "version": ver,
                          "declared_revision": {"value": ver, "basis": "metadata.component.version is a 40-hex string"} if ver and _SHA40.fullmatch(ver) else None}
    else:
        limits.append("no metadata.component: the document names no subject")
    comp = _list(doc, "compositions", "document")
    obs["coverage"] = {"stated": bool(comp), "compositions": [{"aggregate": x.get("aggregate"), "assemblies": x.get("assemblies", [])} for x in comp if isinstance(x, dict)]}
    if not comp:
        limits.append("the document states no coverage (no compositions)")
    elif any(x.get("aggregate") in ("incomplete", "unknown", "not_specified") for x in comp if isinstance(x, dict)):
        limits.append("the document itself states that its coverage is incomplete or unknown")
    for pr in md.get("properties", []) if isinstance(md.get("properties"), list) else []:
        if isinstance(pr, dict) and str(pr.get("name", "")).startswith("bombridge:"):
            obs["extractor_notes"][pr["name"]] = pr.get("value")
    types = {}
    for i, c in enumerate(comps):
        types[c["type"]] = types.get(c["type"], 0) + 1
        if c["type"] != "cryptographic-asset":
            continue
        where = f"components[{i}]"
        cp = c.get("cryptoProperties", {}) if isinstance(c.get("cryptoProperties"), dict) else {}
        ev = c.get("evidence", {}) if isinstance(c.get("evidence"), dict) else {}
        occ = []
        for k, o in enumerate(_list(ev, "occurrences", f"{where}.evidence")):
            if not (isinstance(o, dict) and isinstance(o.get("location"), str)):
                raise AibomError(f"{where}.evidence.occurrences[{k}] needs a string 'location'")
            occ.append({"file": o["location"], "line": o.get("line"), "offset": o.get("offset"), "context": o.get("additionalContext")})
        ap = cp.get("algorithmProperties", {}) if isinstance(cp.get("algorithmProperties"), dict) else {}
        if not occ:
            limits.append(f"{where}: asset has no source occurrences")
        obs["assets"].append({"raw_pointer": f"/components/{i}", "bom_ref": c.get("bom-ref"), "name": c["name"], "asset_type": cp.get("assetType"),
                              "primitive": ap.get("primitive"), "oid": cp.get("oid"), "algorithm": c["name"].lower(), "occurrences": occ})
    # a library mention (a software component that is a crypto library) is not an algorithm record and not a call site; kept apart
    obs["library_mentions"] = [{"raw_pointer": f"/components/{i}", "name": c["name"], "purl": c.get("purl")} for i, c in enumerate(comps)
                               if c["type"] != "cryptographic-asset" and c["name"].lower().replace("_", "-") in CRYPTO_LIBRARY_NAMES]
    svc = doc.get("services", [])
    svc = svc if isinstance(svc, list) else []
    obs["services"] = {"count": len(svc), "names": sorted(str(x.get("name")) for x in svc if isinstance(x, dict))[:50],
                       "note": "service records describe endpoints found in source; they are not cryptographic assets"} if svc else {"count": 0, "names": [], "note": None}
    obs["counts"].update(assets=len(obs["assets"]), by_type=dict(sorted(types.items())), services=len(svc), library_mentions=len(obs["library_mentions"]))
    if not obs["assets"]:
        limits.append("the document declares no cryptographic-asset component (a successful document with zero crypto assets; not a failed scan)")
    return obs


# --------------------------------------------------------------------------------------------
# Dependency mapping observations (Python only): which top-level module does a source line import, and which top-level packages
# does a distribution's own setup declaration provide. Pure parsing with `ast`; nothing is imported or executed.
# --------------------------------------------------------------------------------------------
def python_import_observation(text, rel_path, file_sha256, line):
    """Observation: the import statement on one line of a Python file (first match at `line`), reduced to module names."""
    import ast
    tree = ast.parse(text)
    hits = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) and n.lineno <= line <= (n.end_lineno or n.lineno)]
    if len(hits) != 1:
        raise ValueError(f"{rel_path}:{line}: expected exactly one import statement, found {len(hits)}")
    n = hits[0]
    if isinstance(n, ast.ImportFrom):
        if n.level:
            raise ValueError(f"{rel_path}:{line}: relative import has no top-level distribution name")
        modules, names = [n.module], [a.name for a in n.names]
    else:
        modules, names = [a.name for a in n.names], []
    return {"kind": "python_import", "artifact": {"locator": rel_path}, "file_sha256": file_sha256, "file_sha256_algorithm": "sha256",
            "lines": [n.lineno, n.end_lineno or n.lineno], "statement": ast.get_source_segment(text, n), "modules": modules, "imported_names": names,
            "top_level": sorted({m.split(".")[0] for m in modules})}


def distribution_declaration_observation(setup_text, setup_sha256, rel_path, tree):
    """Observation: what a distribution's setup.py declares (name, version, packages) plus which top-level directories hold packages.

    `tree` is a recorded directory listing at the same tag ({'listing': {'/': [...], '/pkg': [...]}}). With `packages=find_packages()` the
    provided top-level packages are the directories of that listing that contain __init__.py. This is the distribution's SOURCE declaration,
    not installed-package metadata (top_level.txt / RECORD), which was not observed.
    """
    import ast
    mod = ast.parse(setup_text)
    calls = [n for n in ast.walk(mod) if isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", None)) == "setup"]
    if len(calls) != 1:
        raise ValueError("expected exactly one setup() call")
    kw = {k.arg: k for k in calls[0].keywords if k.arg}

    def const(key):
        v = kw.get(key)
        return (v.value.value, v.value.lineno) if v is not None and isinstance(v.value, ast.Constant) else (None, None)

    name, name_line = const("name")
    version, version_line = const("version")
    pk = kw.get("packages")
    find = pk is not None and isinstance(pk.value, ast.Call) and getattr(pk.value.func, "id", None) == "find_packages" and not pk.value.args and not pk.value.keywords
    listing = tree["listing"]
    top = sorted(d["name"] for d in listing["/"] if d["type"] == "dir" and any(x["name"] == "__init__.py" for x in listing.get("/" + d["name"], [])))
    return {"kind": "distribution_declaration", "artifact": {"locator": rel_path}, "file_sha256": setup_sha256, "file_sha256_algorithm": "sha256",
            "distribution": {"name": name, "name_line": name_line, "version": version, "version_line": version_line},
            "packages_expression": ("find_packages()" if find else None), "packages_line": pk.value.lineno if pk is not None else None,
            "provided_top_level": top if find else [],
            "tree": {"repository": tree["repository"], "ref": tree["ref"], "commit": tree["commit"], "base_path": tree["base_path"],
                     "directories": sorted(d["name"] for d in listing["/"] if d["type"] == "dir")}}
