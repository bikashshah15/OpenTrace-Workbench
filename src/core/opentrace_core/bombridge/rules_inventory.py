"""Implemented rule: inventory_coverage.requirement_represented/1.

Bounded assertion: "this declared requirement is represented in this specific inventory".
It is NOT: the inventory is complete; the application uses the library; the library is
installed in a deployed image; the version, platform, build or artifact is the same.
Matching granularity: PEP 503 normalized package name within the pypi ecosystem.
"""

from .adapters import SUPPORTED_FORMS
from .assess import assertion_scope_gaps, assess_state, check_evidence_scope

RULE_ID = "inventory_coverage.requirement_represented/1"
REQUIRED_SCOPE = ("revision",)
GRANULARITY = {"identity": "PEP 503 normalized package name within the pypi ecosystem",
               "not_established": ["version", "platform or marker applicability", "build", "artifact equality",
                                   "inventory completeness", "that other components of the inventory describe this revision", "application use", "installation in a deployed image", "runtime loading"]}
BOUNDED_MEANING = ("Whether this parsed inventory contains a component with the declared package name, where the inventory's recorded digest of the "
                   "requirements file matches that file at the stated revision. The digest binds that one file to the revision; it does not show that other "
                   "components of the inventory describe the revision. Not a statement about completeness, use, installation or runtime.")


def applies(a):
    return a["family"] == "inventory_coverage" and a["predicate"] == "represents_requirement"


def _identities(matches):
    return {m["purl"] or (m["name"], m["version"]) for m in matches}


def assess(f, assertion, entities, evidence, inventories):
    """Fill finding f (already holding base fields) for a represents_requirement assertion."""
    ent = entities[assertion["subject"]]
    req = ent.get("requirement", {})
    obj = assertion["object"]
    f.update(rule_id=RULE_ID, required_scope=list(REQUIRED_SCOPE), bounded_meaning=BOUNDED_MEANING, match_granularity=GRANULARITY)
    f["applicability"] = {"applicable": True, "reason_code": "representation_assertion",
                          "reason": "assertion names a declared requirement and a specific inventory"}
    contract = (inventories.get(obj.get("inventory_id")) or {}).get("coverage_contract") or {"established": False}
    f["coverage_contract"] = contract
    exclude = lambda e, c, d: f["excluded_evidence"].append({"evidence_id": e["evidence_id"], "reason_code": c, "detail": d})
    # a declaration is a candidate only for the asserted package: same file AND same normalized target name. Declarations of other
    # packages in the same file are not about this requirement and are neither used nor listed as excluded.
    decls = [e for e in evidence if e["observation"].get("kind") == "requirement_declaration"
             and e["observation"]["artifact"]["locator"] == req.get("file")
             and (e["observation"].get("target") or {}).get("normalized_name") == req.get("normalized_name")]
    looks = [e for e in evidence if e["observation"].get("kind") == "inventory_name_lookup"
             and e["observation"]["query"]["normalized_name"] == req.get("normalized_name")
             and e["observation"]["query"].get("ecosystem", "pypi") == "pypi"
             and e["observation"]["scanned_file"]["path"] == req.get("file")]  # a lookup made for another requirements file is not about this declaration
    cands = sorted(decls + looks, key=lambda e: e["evidence_id"])
    byid = {e["evidence_id"]: e for e in cands}

    def seal():
        srcs = {}
        for u in f["used_evidence"]:
            srcs.setdefault(byid[u["evidence_id"]]["underlying_source"], []).append(u["evidence_id"])
        f["underlying_sources"] = sorted(srcs)  # known shared sources only; distinct ids do not prove independence
        f["shared_underlying_sources"] = {k: v for k, v in sorted(srcs.items()) if len(v) > 1}
        f["evidence_origins"] = sorted({byid[u["evidence_id"]]["origin"] for u in f["used_evidence"]})
        return f

    def done(code, why, action):
        f.update(state="unverifiable", reason_codes=[code], rationale="Unverifiable: " + why, next_action=action)
        return seal()

    gaps = assertion_scope_gaps(REQUIRED_SCOPE, assertion["scope"])
    if gaps:
        for e in cands:
            exclude(e, "assertion_scope_incomplete", "assertion lacks required scope: " + ", ".join(gaps))
        return done("assertion_scope_incomplete", "assertion lacks required scope " + ", ".join(gaps) + ".", "state the revision the inventory is claimed to describe")

    ok_d, ok_l = [], []
    for e in cands:
        if e["scope_id"] != assertion["scope_id"]:
            exclude(e, "capture_mismatch", f"evidence capture {e['scope_id']!r} vs assertion capture {assertion['scope_id']!r}")
            continue
        sok, code, detail = check_evidence_scope(REQUIRED_SCOPE, assertion["scope"], e["scope"])
        if not sok:
            exclude(e, code, detail)
            continue
        if e in looks and e["observation"]["inventory"]["raw_sha256"] != obj.get("inventory_sha256"):
            exclude(e, "inventory_binding_mismatch", "lookup was made on a different inventory file than the one the assertion names")
            continue
        (ok_d if e in decls else ok_l).append(e)

    used = lambda e, rel, code, why, role: f["used_evidence"].append(
        {"evidence_id": e["evidence_id"], "role": role, "relation": rel, "reason_code": code, "reason": why})
    # requirement identity must be adequate: a supported form, with a parsed name, at the compatible revision
    adequate = [e for e in ok_d if e["observation"]["declarations"]
                and all(d["form"] in SUPPORTED_FORMS for d in e["observation"]["declarations"])]
    for e in ok_d:
        if e in adequate:
            ds = e["observation"]["declarations"]
            used(e, "context", "requirement_declared", f"{len(ds)} declaration line(s): " + "; ".join(
                f"line {d['line']} {d['form']}" + (f" marker {d['marker']!r}" if d.get("marker") else "") for d in ds), "declaration")
        else:
            exclude(e, "requirement_identity_insufficient", "file has no supported declaration for this package name")
    if not adequate:
        for e in ok_l:
            exclude(e, "requirement_identity_insufficient", "no adequate requirement declaration to compare against")
        return done("requirement_identity_insufficient", "no adequate declaration of the requirement was observed at this revision.",
                    "inspect the requirements file and the parser's handling of the declaring line")
    if not ok_l:
        return done("no_inventory_observation", "no lookup of this inventory for this package was observed.", "run the identity lookup on the captured inventory")
    file_hashes = sorted({e["observation"]["file_sha256"] for e in adequate})
    if len(file_hashes) > 1:  # never choose one by list position: the declarations describe different bytes of the file
        for e in ok_l:
            exclude(e, "declaration_files_differ", f"declarations at this revision record {len(file_hashes)} different SHA-256 values for {req.get('file')}")
        return done("declaration_files_differ", f"the declarations of this requirement were read from {len(file_hashes)} different versions of {req.get('file')}.",
                    "re-read the requirements file once at the stated revision")

    decl_hash = file_hashes[0]
    for e in ok_l:
        o = e["observation"]
        sf, matches = o["scanned_file"], o["matches"]
        n_files, hashes = sf["file_components_matching_path_suffix"], sf["recorded_sha256"]
        if n_files == 1 and hashes and decl_hash not in hashes:
            exclude(e, "scan_file_differs", "the inventory records a different SHA-256 for the requirements file than the file at this revision")
            continue
        if n_files != 1 or not hashes:
            used(e, "inconclusive", "scan_binding_unsubstantiated",
                 "inventory lists the requirements file " + ("zero or several times" if n_files != 1 else "without a SHA-256") +
                 "; its binding to this revision is not substantiated", "inventory")
        elif len(_identities(matches)) > 1:
            used(e, "inconclusive", "ambiguous_identity", f"{len(_identities(matches))} distinct components share the normalized name", "inventory")
        elif matches:
            used(e, "supports", "represented_by_unambiguous_component", "one component identity with the same normalized name and ecosystem", "inventory")
        elif o["parse"]["complete"]:
            used(e, "contradicts", "not_represented_in_fully_parsed_inventory",
                 f"no component with this normalized name among {o['parse']['library_components']} library components (all classified); "
                 "the inventory lists the requirements file with the same SHA-256", "inventory")
        else:
            used(e, "inconclusive", "inventory_parse_incomplete", f"{o['parse']['unclassified_components']} component(s) could not be classified", "inventory")

    rels = [u["relation"] for u in f["used_evidence"] if u["role"] == "inventory"]
    f["state"] = assess_state(True, rels)
    seal()
    f["reason_codes"] = sorted({u["reason_code"] for u in f["used_evidence"] if u["role"] == "inventory"})
    kinds = {d["form"] for e in adequate for d in e["observation"]["declarations"]}
    if f["state"] == "supported":
        f["category"] = "requirement_represented"
        f["rationale"] = "Supported: the inventory contains one component with the declared normalized name (name-level only; version, platform and artifact not compared)."
        f["next_action"] = None
    elif f["state"] == "contradicted":
        contracted = contract.get("established") and kinds <= set(contract.get("declaration_forms", []))
        f["category"] = "completeness_defect" if contracted else "inventory_coverage_gap"
        f["rationale"] = ("Contradicted: the declared requirement has no component of that name in the fully parsed inventory, which lists the same requirements file. "
                          + ("An explicit coverage contract says this inventory is expected to include this declaration form: completeness defect."
                             if contracted else "No coverage contract is established that this inventory should include this declaration form, so this is an inventory discrepancy (coverage gap), not a completeness defect or vulnerability."))
        f["next_action"] = ("report to the inventory's owner" if contracted else
                            "establish whether this generator is expected to represent this declaration form (documentation or owner statement), or add an inventory that does")
    elif f["state"] == "conflicting_evidence":
        f["category"] = None
        f["rationale"] = "Conflicting lookups of the same inventory."
        f["next_action"] = "inspect both lookups"
    else:
        f["category"] = None
        f["reason_codes"] = f["reason_codes"] or ["no_usable_observation"]
        f["rationale"] = "Unverifiable: " + "; ".join(u["reason"] for u in f["used_evidence"] if u["role"] == "inventory") + "."
        f["next_action"] = "resolve the named binding, identity or parsing gap, then re-run"
    return f
