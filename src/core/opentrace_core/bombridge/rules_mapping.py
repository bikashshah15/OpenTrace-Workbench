"""Implemented rule: dependency_mapping.import_resolves_to_component/1.

Bounded assertion: "this source import statement can be mapped, by evidence other than name resemblance, to this component of this SBOM".
An import name is a module name, not a package name; the two may differ. The mapping needs three observations, each at the same capture:
  1. python_import                the import statement (file, lines) and its top-level module
  2. distribution_declaration     a distribution's own source declaration that it provides that top-level package (setup name, version, packages)
  3. inventory_name_lookup        the SBOM component with that distribution's normalized name (exact) and the same version
Supported only when all three agree. Name resemblance between the module and a component is never used: the lookup is by the distribution's
declared name. It never establishes: that the distribution declared in the SBOM's source file is the one installed or run, that the
component's declaring file is a runtime dependency list, or that the import executes. The declaring file of the component is reported as a limit.
"""

from .adapters import normalize_name
from .assess import assertion_scope_gaps, assess_state, check_evidence_scope

RULE_ID = "dependency_mapping.import_resolves_to_component/1"
REQUIRED_SCOPE = ("revision",)
BOUNDED_MEANING = ("The top-level module imported at the stated source line is provided by a distribution whose own source declaration names it, and that "
                   "distribution's name and version equal exactly one component of the stated SBOM. Source-reconstructed mapping, not installed-package metadata. "
                   "Not a statement that the component is installed or run, that its declaring file is a runtime dependency list, or that the import executes.")
NOT_ESTABLISHED = ["installation of the component in any image", "that the SBOM's declaring file is a runtime dependency list", "that the import executes",
                   "installed-package metadata (top_level.txt, RECORD)", "that a model loaded by this library is described by any AI-BOM"]


def applies(a):
    return a["family"] == "dependency_mapping" and a["predicate"] == "import_resolves_to_component"


def assess(f, assertion, entities, evidence, inventories):
    obj = assertion["object"]
    f.update(rule_id=RULE_ID, required_scope=list(REQUIRED_SCOPE), bounded_meaning=BOUNDED_MEANING, not_established=NOT_ESTABLISHED,
             layers={"import_observed": False, "distribution_declares_module": False, "sbom_component_name_and_version_equal": False})
    f["provenance_note"] = "The mapping is reconstructed from source declarations (the importing file and the distribution's own setup); no installed-package metadata was observed."
    f["applicability"] = {"applicable": True, "reason_code": "import_mapping_assertion", "reason": "assertion maps a source import to a component of a named SBOM"}
    exclude = lambda e, c, d: f["excluded_evidence"].append({"evidence_id": e["evidence_id"], "reason_code": c, "detail": d})
    top = obj["top_level"]
    cands = sorted((e for e in evidence if e["observation"].get("kind") in ("python_import", "distribution_declaration", "inventory_name_lookup")), key=lambda e: e["evidence_id"])
    byid = {e["evidence_id"]: e for e in cands}

    def seal(state, code, why, action):
        f["state"] = state
        f["reason_codes"] = [code] if code else f["reason_codes"]
        f["rationale"], f["next_action"] = why, action
        srcs = {}
        for u in f["used_evidence"]:
            srcs.setdefault(byid[u["evidence_id"]]["underlying_source"], []).append(u["evidence_id"])
        f["underlying_sources"] = sorted(srcs)
        f["shared_underlying_sources"] = {k: v for k, v in sorted(srcs.items()) if len(v) > 1}
        f["evidence_origins"] = sorted({byid[u["evidence_id"]]["origin"] for u in f["used_evidence"]})
        return f

    gaps = assertion_scope_gaps(REQUIRED_SCOPE, assertion["scope"])
    if gaps:
        for e in cands:
            exclude(e, "assertion_scope_incomplete", "assertion lacks required scope: " + ", ".join(gaps))
        return seal("unverifiable", "assertion_scope_incomplete", "Unverifiable: assertion lacks required scope " + ", ".join(gaps) + ".", "state the revision")
    ok = []
    for e in cands:
        o = e["observation"]
        if e["scope_id"] != assertion["scope_id"]:
            exclude(e, "capture_mismatch", "evidence belongs to another capture")
            continue
        sok, code, detail = check_evidence_scope(REQUIRED_SCOPE, assertion["scope"], e["scope"])
        if not sok:
            exclude(e, code, detail)
            continue
        if o["kind"] == "inventory_name_lookup" and o["inventory"]["raw_sha256"] != obj.get("inventory_sha256"):
            exclude(e, "inventory_binding_mismatch", "lookup was made on a different inventory file than the one the assertion names")
            continue
        if o["kind"] == "python_import" and (o["artifact"]["locator"] != obj["import_file"] or top not in o["top_level"]):
            exclude(e, "import_not_at_named_location", f"not the import of {top} in {obj['import_file']}")
            continue
        ok.append(e)
    imp = [e for e in ok if e["observation"]["kind"] == "python_import"]
    dist = [e for e in ok if e["observation"]["kind"] == "distribution_declaration"]
    f["layers"]["import_observed"] = bool(imp)
    for e in imp:
        f["used_evidence"].append({"evidence_id": e["evidence_id"], "role": "import", "relation": "context", "reason_code": "import_statement_observed",
                                   "reason": f"{e['observation']['artifact']['locator']} lines {e['observation']['lines']} import module {top}"})
    if not imp:
        return seal("unverifiable", "import_not_observed", f"Unverifiable: no observation of the import of {top} at {obj['import_file']}.", "collect the import statement")
    providers = [e for e in dist if top in e["observation"]["provided_top_level"] and e["observation"]["distribution"]["name"]]
    for e in dist:
        if e not in providers:
            exclude(e, "distribution_does_not_declare_module", f"its source declaration does not provide top-level package {top}")
    if not providers:
        # the import name alone is not a package name; an exact lookup of the module name is recorded only as the reason the mapping fails
        direct = [e for e in ok if e["observation"]["kind"] == "inventory_name_lookup" and e["observation"]["query"]["normalized_name"] == normalize_name(top)]
        for e in direct:
            f["used_evidence"].append({"evidence_id": e["evidence_id"], "role": "import_name_lookup", "relation": "inconclusive", "reason_code": "import_name_is_not_a_package_name",
                                       "reason": f"exact lookup of the import name {top!r} found {len(e['observation']['matches'])} component(s); a module name is not evidence of a package"})
        return seal("unverifiable", "no_distribution_declares_module",
                    f"Unverifiable: no distribution declaration was observed that provides the module {top}. A resemblance between the module name and a package name is not used.",
                    "observe the declaring distribution's source or installed metadata")
    p = providers[0]
    d = p["observation"]["distribution"]
    f["layers"]["distribution_declares_module"] = True
    f["used_evidence"].append({"evidence_id": p["evidence_id"], "role": "distribution", "relation": "context", "reason_code": "distribution_declares_module",
                               "reason": f"setup name={d['name']!r} (line {d['name_line']}), version={d['version']!r} (line {d['version_line']}), packages={p['observation']['packages_expression']} "
                                         f"(line {p['observation']['packages_line']}); the listing at the tag has {top}/__init__.py"})
    want = normalize_name(d["name"])
    looks = [e for e in ok if e["observation"]["kind"] == "inventory_name_lookup" and e["observation"]["query"]["normalized_name"] == want]
    if not looks:
        return seal("unverifiable", "no_inventory_lookup", f"Unverifiable: the distribution {d['name']} was not looked up in the SBOM.", "run the exact-name lookup on the SBOM")
    relations = []
    for e in looks:
        o = e["observation"]
        ms = o["matches"]
        if not o["parse"]["complete"]:
            rel, code, why = "inconclusive", "inventory_parse_incomplete", "the inventory could not be fully classified"
        elif not ms:
            rel, code, why = "contradicts", "distribution_not_in_inventory", f"no component named {d['name']} among {o['parse']['library_components']} library components"
        elif len({m["purl"] or (m["name"], m["version"]) for m in ms}) > 1:
            rel, code, why = "inconclusive", "ambiguous_component", "several distinct components share the normalized name"
        elif ms[0]["version"] != d["version"]:
            rel, code, why = "inconclusive", "version_differs", f"component {ms[0]['name']} {ms[0]['version']} vs distribution version {d['version']}"
        else:
            m = ms[0]
            rel, code, why = "supports", "component_equals_declared_distribution", (f"component {m['name']} {m['version']} ({m['purl']}) equals the distribution's declared name and version; "
                                                                                      f"the SBOM attributes it to {', '.join(m['locations'])}")
            f["matched_component"] = m
            f["layers"]["sbom_component_name_and_version_equal"] = True
        f["used_evidence"].append({"evidence_id": e["evidence_id"], "role": "inventory", "relation": rel, "reason_code": code, "reason": why})
        relations.append(rel)
    state = assess_state(True, relations)
    codes = sorted({u["reason_code"] for u in f["used_evidence"] if u["role"] == "inventory"})
    if state == "supported":
        f["category"] = "source_reconstructed_mapping"
        m = f["matched_component"]
        sf = ", ".join(m["locations"])
        f["provenance_note"] = (f"The component is attributed by the SBOM to {sf} only. Whether that file lists what the runtime installs is a separate question and is not decided here.")
        return seal(state, None, f"Supported (source-reconstructed): module {top} is provided by distribution {d['name']} {d['version']} by that distribution's own setup declaration, and the SBOM has "
                                 f"exactly that component. {f['provenance_note']}", None) | {"reason_codes": codes}
    return seal(state, None, "Unverifiable: " + "; ".join(u["reason"] for u in f["used_evidence"] if u["role"] == "inventory") + ".", "resolve the named gap, then re-run") | {"reason_codes": codes}
