"""Discovery of candidate requirement gaps in a captured SBOM, and the assertions that verify them (I8).

Ported from BOMBridge ``src/bombridge/discovery.py`` (gap-discovery overlay by Peiran Shi on donor base 7195f6e). The
discovery and assessment *logic* is the donor's: for each requirement file the source declares, every named requirement is
compared (PEP 503 normalized name, exact) with the selected SBOM inventory inside the scope the file's recorded SHA-256
binds; the candidate carries the assertion that verifies it, and that assertion is assessed by the existing rule
``inventory_coverage.requirement_represented/1`` exactly like a curated one. No network, no execution, no collection.

Adaptations for OpenTrace (each is a deliberate omission or a boundary change, not a change to the compared logic):

* Only the requirement -> SBOM path is ported. Not ported: model-locator and hashlib candidates, dependency/edge intake,
  external-evidence edges, BOM structure checks, missing-document candidates, the ``dependency_requirement.*`` rules (so the
  donor's version-satisfied and marker-applies verification assertions are not generated) and release/impact views.
* No filesystem, subprocess or ``packaging`` use: ``discover`` receives parsed documents and requirement-file text; the caller
  (the Workbench's recorded-fixture loader) reads and digest-checks the bytes. ``read_declarations`` below is the pure
  validation of the captured source-declaration record.
* Markers are never evaluated here (no recorded target environment exists in this slice), so a requirement file with
  markers yields the donor's ``unknown_coverage`` candidate "no target environment was recorded".
* The discovered bundle keeps the bundle's records byte-for-byte and appends; ``discovery`` is an extra top-level section.
"""

import copy
import hashlib
import json
import re

from . import adapters

SCHEMA = "bombridge.discovery/1"
GENERATOR = "bombridge.discovery/1"
DISC_INV = "inv:bombridge-discovery"
CATEGORIES = ("missing_component", "missing_connection", "missing_bom_document", "unknown_coverage", "invalid_reference")
TOOL = "opentrace_core/bombridge/discovery.py"
DECLARATIONS_SCHEMA = "bombridge.source-declarations/1"
PORTED_SCOPE = ("requirement_declarations_vs_sbom",)


def _h(*parts):
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:8]


def _slug(s, n=32):
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")[:n] or "x"


class InputError(ValueError):
    """A captured discovery input is missing, malformed, or does not match its recorded identity/digest."""

    def __init__(self, code, detail):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def requirement_declarations(text):
    """[{line, ...parsed}] for every non-blank, non-comment line (unsupported ones included, so nothing is silently dropped).

    Donor ``sources.requirement_declarations``; the donor's checkout collector in that module is not ported.
    """
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        p = adapters.parse_requirement_line(raw)
        if p is None:
            continue
        d = {"line": n, "original_text": raw.strip(), **{k: v for k, v in p.items() if k != "raw" and v is not None}}
        if p.get("name"):
            d["normalized_name"] = adapters.normalize_name(p["name"])
        out.append(d)
    return out


def read_declarations(bundle, declarations_bytes, *, expected_sha256, read_copy):
    """Validate the captured source-declaration record and read its requirement-file copies; pure (bytes in, data out).

    The record's own SHA-256 must equal the pinned digest, its repository and revision must equal the bundle's capture, and
    each requirement-file copy must hash to the SHA-256 the record states. A copy that is missing or differs is *not* an
    error here: discovery reports it as an ``unknown_coverage`` candidate for that file and compares nothing from it.
    Returns (source_declarations, {path: text}). Raises InputError for anything that makes the whole record unusable.
    """
    if hashlib.sha256(declarations_bytes).hexdigest() != expected_sha256:
        raise InputError("declarations_digest_mismatch", "the source-declaration record does not match its pinned SHA-256")
    try:
        sd = json.loads(declarations_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise InputError("declarations_invalid", "the source-declaration record is not valid JSON")
    if not isinstance(sd, dict) or sd.get("schema") != DECLARATIONS_SCHEMA or not isinstance(sd.get("requirement_files"), list):
        raise InputError("declarations_invalid", "the source-declaration record has an unsupported schema")
    cap = bundle["capture"]["repository"]
    if sd.get("revision") != cap["revision"] or sd.get("repository") != cap["url"]:
        raise InputError("declarations_scope_mismatch", "the source declarations describe another repository or revision than the captured scan")
    texts = {}
    for rf in sd["requirement_files"]:
        if not (isinstance(rf, dict) and isinstance(rf.get("path"), str) and isinstance(rf.get("sha256"), str)):
            raise InputError("declarations_invalid", "a requirement-file entry has no path or digest")
        try:
            data = read_copy(rf["path"])
        except (OSError, KeyError):
            continue
        if isinstance(data, bytes) and hashlib.sha256(data).hexdigest() == rf["sha256"]:
            try:
                texts[rf["path"]] = data.decode("utf-8")
            except UnicodeDecodeError:
                pass
    return sd, texts


class _Out:
    """Accumulates discovered records; ids are derived from content so a re-run over the same inputs gives the same ids."""

    def __init__(self, bundle, strict=False):
        """``strict`` (UIP-12 opted-in path only): one canonical ID, one content, checked at creation against this generator's own records *and* the base
        bundle's. Identical records deduplicate; different content under one ID raises ``GeneratorError("id_collision")``. The default (False) is the earlier
        behaviour: the first record under an ID wins silently."""
        self.b = bundle
        self.strict = strict
        self._seen = ({"entities": {e["entity_id"]: e for e in bundle["entities"]}, "evidence": {e["evidence_id"]: e for e in bundle["evidence"]},
                       "assertions": {a["assertion_id"]: a for a in bundle["assertions"]}, "candidates": {}} if strict else None)
        self.scope_id = bundle["capture"]["scope_id"]
        self.rev = bundle["capture"]["repository"]["revision"]
        self.entities, self.evidence, self.assertions, self.candidates = [], [], [], []
        self.ent_ids = {e["entity_id"] for e in bundle["entities"]}
        self.ev_ids = {e["evidence_id"] for e in bundle["evidence"]}
        self.as_ids = {a["assertion_id"] for a in bundle["assertions"]}
        self.verification = []
        self.counts = {}
        # discovered records carry the bundle's provenance class: synthetic inputs stay illustrative, real captures are captured
        self.origin = "illustrative" if bundle.get("origin") == "illustrative" else "captured"

    def eid(self, local):
        return f"{self.scope_id}::{DISC_INV}::{local}"

    def _admit(self, kind, record):
        """True if the record is new; False if an identical record already holds its ID; raises on different content (strict mode only)."""
        rid = record[_KEYS[kind]]
        old = self._seen[kind].get(rid)
        if old is None:
            self._seen[kind][rid] = record
            return True
        if not _same(old, record):
            raise GeneratorError("id_collision", f"{kind[:-1]} {rid} exists with different content")
        return False

    def entity(self, local, kind, name, version=None, **extra):
        e = {"entity_id": self.eid(local), "kind": kind, "name": name, "version": version, "source": {"inventory_id": DISC_INV, "source_ref": local},
             "identity_matches": [], "origin": self.origin, **extra}
        if (self._admit("entities", e) if self.strict else e["entity_id"] not in self.ent_ids):
            self.ent_ids.add(e["entity_id"])
            self.entities.append(e)
        return e["entity_id"]

    def ev(self, evidence_id, *, method, locator, scope, obs, limitations, underlying, observes, tool=TOOL):
        rec = {"evidence_id": evidence_id, "scope_id": self.scope_id, "method": method, "tool": tool, "source_locator": locator, "scope": scope,
               "observation": obs, "observes": sorted(set(observes)), "limitations": limitations, "underlying_source": underlying, "origin": self.origin}
        if (self._admit("evidence", rec) if self.strict else evidence_id not in self.ev_ids):
            self.ev_ids.add(evidence_id)
            self.evidence.append(rec)
        return evidence_id

    def assertion(self, aid, family, subject, predicate, obj, source_ref, scope, title, candidate=None, rule_version=None):
        rec = {"assertion_id": aid, "family": family, "subject": subject, "predicate": predicate, "object": obj,
               "declared_in": {"inventory_id": DISC_INV, "source_ref": source_ref}, "scope_id": self.scope_id, "scope": scope, "origin": self.origin,
               "title": title, "discovery": {"generator": GENERATOR, "candidate": candidate}}
        if rule_version is not None:
            rec["rule_version"] = rule_version
        if (self._admit("assertions", rec) if self.strict else aid not in self.as_ids):
            self.as_ids.add(aid)
            self.assertions.append(rec)
            if candidate is None:
                self.verification.append(aid)
        return aid

    def candidate(self, category, *, group, title, trigger, proposed_claim, next_action, inventory=None, location=None, identity_basis=None,
                  assertion=None, entity=None, evidence=(), scope=None, detail=None, key=None):
        assert category in CATEGORIES, category
        cid = f"cand:{category}:{_h(group, key or title)}"
        rec = {"candidate_id": cid, "category": category, "group": group, "title": title, "trigger": trigger, "proposed_claim": proposed_claim,
               "selected_inventory": inventory, "evidence_location": location, "identity_basis": identity_basis, "assertion_id": assertion,
               "entity_id": entity, "evidence_ids": sorted(set(evidence)), "scope": scope or {}, "detail": detail, "next_action": next_action}
        if not self.strict or self._admit("candidates", rec):
            self.candidates.append(rec)
        return cid

    def bump(self, *path):
        d = self.counts
        for p in path[:-1]:
            d = d.setdefault(p, {})
        d[path[-1]] = d.get(path[-1], 0) + 1


# ----------------------------------------------------------------------------------------------------------------------
def discover(bundle, *, raw_inventories, source_declarations, requirement_texts, requirements=True, extra_generators=(), generator_report=None, propagate=()):
    """Return a new bundle with discovered records and a `discovery` section. The input bundle is not modified.

    raw_inventories: {inventory_id: {"doc": parsed JSON, "sha256": hex}} for inventories whose raw bytes the caller has already
      checked against the inventory record's source_sha256.
    source_declarations: a validated bombridge.source-declarations/1 record of the same repository and revision (read_declarations).
    requirement_texts: {path: text} of the requirement files whose copies matched their recorded digests.

    UIP-12 (all optional; with the defaults the output is byte-identical to before): ``requirements=False`` skips the requirement -> SBOM
    generator; ``extra_generators`` are further generators (``discovery_crypto``), each run on a *child* ``_Out`` whose records are merged into
    this bundle only if it finishes (a fault, a candidate-budget overrun or an ID collision with different content discards that generator
    whole); ``generator_report`` is a caller-supplied dict that receives one typed entry per generator (never written into the bundle); with either of the
    two, the requirement generator too runs on a child ``_Out`` (key ``software``) and every child is ID-strict (identical records deduplicate, conflicting
    content under one ID fails the generator, base-bundle records included). ``propagate`` is a tuple of exception types (session retirement/cancellation)
    that are never treated as generator faults and escape every boundary.
    """
    if not isinstance(source_declarations, dict):
        raise InputError("declarations_invalid", "source declarations are required")
    b = copy.deepcopy(bundle)
    cap = b["capture"]
    if source_declarations.get("revision") != cap["repository"]["revision"] or source_declarations.get("repository") != cap["repository"]["url"]:
        raise InputError("declarations_scope_mismatch", "source declarations describe another repository or revision than the bundle's capture; nothing is compared")
    out = _Out(b)
    invs = {i["inventory_id"]: i for i in cap["inventories"]}
    inv_entity = {e["inventory_id"]: e["entity_id"] for e in b["entities"] if e.get("kind") == "inventory" and e.get("inventory_id")}
    for iid, inv in sorted(invs.items()):
        if inv.get("kind") in ("sbom", "aibom", "cbom") and iid not in inv_entity:
            inv_entity[iid] = out.entity("inventory-" + _slug(iid), "inventory", f"{inv.get('generator', iid)} document", inventory_id=iid)
    inputs = []
    for iid, inv in sorted(invs.items()):
        if inv.get("kind") in ("sbom", "aibom", "cbom"):
            inputs.append({"kind": "inventory", "inventory_id": iid, "source_file": inv.get("source_file"), "sha256": inv.get("source_sha256"),
                           "status": "loaded" if iid in raw_inventories else ("not_acquired" if inv.get("acquired") is False else "not_loaded")})
    inputs.append({"kind": "source_declarations", "repository": source_declarations["repository"], "revision": source_declarations["revision"],
                   "requirement_files": len(source_declarations["requirement_files"]), "requirement_files_loaded": len(requirement_texts)})
    opted = bool(extra_generators) or generator_report is not None      # UIP-12 Stage 2 path: every generator is transactional and ID-strict
    sw_done = False
    if requirements and not opted:
        _requirements(out, invs, inv_entity, raw_inventories, source_declarations, requirement_texts)    # recorded path: unchanged, a fault propagates
        sw_done = True
    elif requirements:
        child = _Out(b, strict=True)
        try:
            _requirements(child, invs, inv_entity, raw_inventories, source_declarations, requirement_texts)
            _merge(out, child)
            sw_done = True
        except Exception as exc:  # fault boundary of the software generator: only its output is discarded; crypto still runs
            _propagate(exc, propagate)
            if generator_report is not None:
                generator_report["software"] = _fault_entry(exc)
    scope = list(PORTED_SCOPE) if sw_done else []
    crypto_note = models_note = False
    for gen in extra_generators:
        child = _Out(b, strict=True)
        name = getattr(gen, "name", "generator")
        try:
            gen(child, invs=invs, inv_entity=inv_entity, raw=raw_inventories, srcdecl=source_declarations,
                budget=gen.budget_for(len(out.candidates)))
            _merge(out, child)
        except Exception as exc:  # fault boundary of one generator: nothing of it is kept, the others are untouched
            _propagate(exc, propagate)
            if generator_report is not None:
                generator_report[name] = _fault_entry(exc)
            continue
        scope += list(getattr(gen, "ported_scope", ()))
        if name == "models":      # UIP-13: the note names each family that ran
            models_note = bool(getattr(gen, "ported_scope", ()))
        else:
            crypto_note = crypto_note or bool(getattr(gen, "ported_scope", ()))
        if getattr(gen, "input_entry", None):
            inputs.append(gen.input_entry)
        if generator_report is not None:
            generator_report[name] = {"status": "ok", "code": None, "detail": None, "info": dict(getattr(gen, "info", {}) or {})}
    if sw_done and generator_report is not None:
        generator_report["software"] = {"status": "ok", "code": None, "detail": None, "info": {}}

    b["entities"] += out.entities
    b["evidence"] += out.evidence
    b["assertions"] += out.assertions
    if not any(i["inventory_id"] == DISC_INV for i in cap["inventories"]):
        cap["inventories"].append({"inventory_id": DISC_INV, "kind": "discovery", "generator": GENERATOR, "intended_coverage": [],
                                   "label": "not a BOM: candidate gaps and the assertions that verify them, generated from captured inputs; every candidate is assessed by a rule",
                                   "origin": out.origin})
    cats = {c: sum(1 for x in out.candidates if x["category"] == c) for c in CATEGORIES}
    b["discovery"] = {"schema": SCHEMA, "generator": GENERATOR, "ported_scope": scope, "inputs": inputs,
                      "candidates": sorted(out.candidates, key=lambda c: (CATEGORIES.index(c["category"]), c["group"], c["title"])),
                      "verification_assertions": sorted(out.verification), "counts": {"by_category": cats, **out.counts},
                      "notes": ["A candidate is a hypothesis generated by set comparison; its verdict is the finding of the assertion it names.",
                                "Unknown coverage is a collection or parsing task, not a defect. Missing evidence is never turned into a contradiction.",
                                ("Only requirement declarations compared with the selected SBOM are discovered in this build; models, cryptographic call sites, "
                                 "dependency edges and document structure are not.") if sw_done and not crypto_note and not models_note else
                                ("Requirement declarations compared with the selected SBOM" if sw_done else "No requirement declarations")
                                + (" and Python hashlib call sites compared with the selected CBOM" if crypto_note else "")
                                + (" and model references in Python, Dockerfile and shell source compared with the selected AI-BOM" if models_note else "")
                                + " are discovered in this build; " + ("" if models_note else "models, ") + "dependency edges and document structure are not."]}
    b["notice"] = (b.get("notice") or "") + " DISCOVERY: candidate gaps and verification assertions were generated mechanically from captured inputs (" + \
        ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in cats.items() if v) + "); curated records are unchanged."
    return b


def _propagate(exc, propagate):
    """Session retirement and cancellation are control flow, never an ordinary generator fault: the caller names their exception types and they are re-raised
    out of every fault boundary (this module imports nothing from the session layer)."""
    if propagate and isinstance(exc, tuple(propagate)):
        raise exc


def _fault_entry(exc):
    return {"status": "dropped" if getattr(exc, "dropped", False) else "failed", "code": getattr(exc, "code", "generator_error"),
            "detail": getattr(exc, "detail", type(exc).__name__), "info": dict(getattr(exc, "info", {}) or {})}


class GeneratorError(Exception):
    """A generator ended without a usable result (``dropped``: a deliberate refusal such as a candidate-budget overrun)."""

    def __init__(self, code, detail="", *, dropped=False, info=None):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.dropped, self.info = code, detail, dropped, info or {}


_KEYS = {"entities": "entity_id", "evidence": "evidence_id", "assertions": "assertion_id", "candidates": "candidate_id"}


def _same(a, b):
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def _merge(parent, child):
    """Merge a finished child generator into the parent. Identical records sharing an ID deduplicate; different content under one ID fails the
    generator (no silent overwrite, no assumption that equal IDs mean equal content). All checks run before anything is appended."""
    additions = {}
    for kind, key in _KEYS.items():
        have = {r[key]: r for r in getattr(parent, kind)}
        new = []
        for r in getattr(child, kind):
            old = have.get(r[key])
            if old is None:
                new.append(r)
                have[r[key]] = r
            elif not _same(old, r):
                raise GeneratorError("id_collision", f"{kind[:-1]} {r[key]} exists with different content")
        additions[kind] = new
    for kind, new in additions.items():
        getattr(parent, kind).extend(new)
        if kind == "entities":
            parent.ent_ids.update(r["entity_id"] for r in new)
        elif kind == "evidence":
            parent.ev_ids.update(r["evidence_id"] for r in new)
        elif kind == "assertions":
            parent.as_ids.update(r["assertion_id"] for r in new)
    parent.verification.extend(a for a in child.verification if a not in parent.verification)
    for k, v in child.counts.items():
        parent.counts[k] = v


def _existing(b):
    idx = {"decl": {}, "look": {}, "req_assert": {}, "req_entity": {}, "file_entity": {}}
    for e in b["evidence"]:
        o = e["observation"]
        if o.get("kind") == "requirement_declaration":
            idx["decl"][(o["artifact"]["locator"], o["target"]["normalized_name"])] = e["evidence_id"]
        elif o.get("kind") == "inventory_name_lookup":
            idx["look"][(o["inventory"]["raw_sha256"], o["query"]["normalized_name"], o["scanned_file"]["path"])] = e["evidence_id"]
    ents = {e["entity_id"]: e for e in b["entities"]}
    for e in b["entities"]:
        r = e.get("requirement")
        if r:
            idx["req_entity"][(r.get("file"), r.get("normalized_name"))] = e["entity_id"]
        if e.get("kind") == "source_file":
            idx["file_entity"].setdefault(e["name"], e["entity_id"])
    for a in b["assertions"]:
        o = a["object"] if isinstance(a["object"], dict) else {}
        if a["predicate"] == "represents_requirement":
            r = (ents.get(a["subject"], {})).get("requirement") or {}
            idx["req_assert"][(r.get("file"), r.get("normalized_name"), o.get("inventory_id"))] = a["assertion_id"]
    return idx


def _file_listing(doc, path):
    files = [c for c, _ in adapters.walk_components(doc.get("components", [])) if c.get("type") == "file" and c.get("name", "").endswith("/" + path)]
    return len(files), sorted(h["content"].lower() for f in files for h in f.get("hashes", []) if h.get("alg") == "SHA-256")


def _requirements(out, invs, inv_entity, raw, srcdecl, texts):
    idx = _existing(out.b)
    sboms = [i for i in sorted(invs) if invs[i].get("kind") == "sbom" and i in raw]
    rev = out.rev
    for rf in sorted(srcdecl["requirement_files"], key=lambda x: x["path"]):
        path = rf["path"]
        text = texts.get(path)
        if text is None or hashlib.sha256(text.encode("utf-8")).hexdigest() != rf["sha256"]:
            out.candidate("unknown_coverage", group=f"requirements:{path}", key="copy", title=f"{path}: the captured copy is missing or differs from its recorded digest",
                          trigger="requirement file copy not readable", proposed_claim="the declarations of this file are compared", location=path,
                          next_action="re-collect the source declarations at the pinned revision")
            continue
        out.bump("requirements", "files")
        decls = requirement_declarations(text)
        file_ent = idx["file_entity"].get(path) or out.entity(f"source-file:{path}", "source_file", path)
        named = {}
        for d in decls:
            if d.get("normalized_name"):
                named.setdefault(d["normalized_name"], []).append(d)
        unsupported = [d for d in decls if d["form"] == "unsupported" and not d.get("directive")]
        directives = [d for d in decls if (d.get("directive") or {}).get("kind") in ("requirement_file", "constraint_file", "editable")]
        options = [d for d in decls if (d.get("directive") or {}).get("kind") == "option"]
        for norm, ds in sorted(named.items()):
            out.bump("requirements", "named_requirements")
            name = ds[0]["name"]
            req_ent = idx["req_entity"].get((path, norm)) or out.entity(
                f"req:{path}:{norm}", "requirement", f"{name} (declared in {path})",
                requirement={"file": path, "name": name, "normalized_name": norm}, relations=[{"type": "declared_in", "target": file_ent}])
            decl_id = idx["decl"].get((path, norm)) or out.ev(
                f"dev-decl-{_h(path, norm)}-{_slug(norm, 24)}", method="requirements-line-parse", locator=path, scope={"revision": rev},
                obs=adapters.requirement_declaration_observation(text, path, rf["sha256"], name),
                limitations=["declaration only: a declared requirement is not an installed or used package", "markers are preserved as text; none was evaluated"],
                underlying=f"source-file:{path}@{rev[:12]}", observes=[req_ent, file_ent])
            lines = ",".join(str(d["line"]) for d in ds)
            forms = sorted({d["form"] for d in ds})
            for iid in sboms:
                doc, sha = raw[iid]["doc"], raw[iid]["sha256"]
                look = adapters.inventory_lookup_observation(doc, sha, norm, path)
                look_id = idx["look"].get((sha, norm, path)) or out.ev(
                    f"dev-look-{_slug(iid, 16)}-{_h(path, norm, sha)}-{_slug(norm, 20)}", method="cyclonedx-exact-name-lookup", locator=invs[iid].get("source_file"),
                    scope={"revision": rev}, obs=look,
                    limitations=["lookup result for one normalized package name (exact, no substring matching)", "a source-directory inventory is not an image or runtime SBOM",
                                 "binding of the inventory to the revision rests on the SHA-256 it records for this requirements file; the rule checks it"],
                    underlying=f"tool-output:{_slug(iid)}-{sha[:12]}", observes=[req_ent, inv_entity[iid]])
                curated = idx["req_assert"].get((path, norm, iid))
                aid = curated or out.assertion(
                    f"dreq-{_slug(norm, 20)}-{_h(iid, path, norm)}", "inventory_coverage", req_ent, "represents_requirement",
                    {"inventory_entity": inv_entity[iid], "inventory_id": iid, "inventory_sha256": sha},
                    f"{path}:{lines} (discovery: every named requirement of a requirements file the source declares)", {"revision": rev},
                    f"{name} · {path}:{lines}", candidate=None)
                n_files, hashes = _file_listing(doc, path)
                listed = n_files == 1 and rf["sha256"] in hashes
                if look["matches"]:
                    out.bump("requirements", "represented")
                    continue  # donor also generated a version_satisfied verification assertion here; that rule is not ported (I8)
                if listed and look["parse"]["complete"]:
                    cat, why = "missing_component", (f"{iid} lists {path} with the same SHA-256 and has no component named {norm} among "
                                                      f"{look['parse']['library_components']} library components")
                    out.bump("requirements", "missing")
                else:
                    cat = "unknown_coverage"
                    why = (f"{iid} does not list {path}, so its components cannot be bound to this file" if n_files == 0 else
                           f"{iid} records {n_files} files matching {path}" if n_files != 1 else
                           f"{iid} records a different SHA-256 for {path}" if not listed else "the inventory could not be fully classified")
                    out.bump("requirements", "unknown")
                out.candidate(cat, group=f"requirements:{iid}:{path}", key=norm, inventory=iid, location=f"{path}:{lines}", assertion=aid, entity=req_ent,
                              evidence=[decl_id, look_id], scope={"revision": rev},
                              title=f"{name} ({', '.join(forms)}) declared at {path}:{lines} has no record in {iid}", trigger=why,
                              identity_basis="PEP 503 normalized name within the pypi ecosystem (exact; no substring or resemblance)",
                              proposed_claim=f"requirement {name} is represented in {iid}",
                              next_action=("establish whether the generator is expected to represent the " + "/".join(forms) + " form (coverage contract), or add an inventory that does"
                                           if cat == "missing_component" else "obtain an inventory that records this file and its digest, then re-run discovery"))
        if unsupported:
            out.candidate("unknown_coverage", group=f"requirements:{path}", key="unsupported", location=f"{path}:" + ",".join(str(d["line"]) for d in unsupported),
                          title=f"{len(unsupported)} line(s) of {path} are not a supported requirement form", trigger="; ".join(d["original_text"][:80] for d in unsupported[:3]),
                          proposed_claim="every requirement line is compared", next_action="inspect the lines; they are neither compared nor counted as missing")
        if directives:
            out.candidate("unknown_coverage", group=f"requirements:{path}", key="directives", location=f"{path}:" + ",".join(str(d["line"]) for d in directives),
                          title=f"{len(directives)} pip file directive(s) in {path} are reported, not followed",
                          trigger="; ".join(f"{d['directive']['option']} {d['directive']['argument'] or ''}".strip() for d in directives[:3]),
                          proposed_claim="requirements included from other files are compared", next_action="compare the referenced file on its own (it is collected if it matches the requirement globs)")
        if options:
            out.bump("requirements", "option_lines")
        markers = [d for d in decls if d.get("marker")]
        if markers:  # the donor evaluates these only against a recorded target environment; this build records none
            out.candidate("unknown_coverage", group=f"requirements:{path}", key="markers", location=f"{path}:" + ",".join(str(d["line"]) for d in markers),
                          title=f"{len(markers)} declaration(s) in {path} carry environment markers; no target environment was recorded",
                          trigger="; ".join(f"{d['name']} ; {d['marker']}" for d in markers[:3]),
                          proposed_claim="which of these declarations apply to the selected build is known",
                          next_action="record the target environment (pip inspect 'environment' in the selected image), then re-run discovery to evaluate the markers")
