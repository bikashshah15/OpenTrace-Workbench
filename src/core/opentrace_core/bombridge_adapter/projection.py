"""Deterministic, inert Workbench data projections over a bound assessment."""
import copy
import hashlib
import json
from urllib.parse import unquote

from opentrace_core.bombridge.acquisition import resolve_binding
from .types import AdapterContext, AdapterError, BoundAssessment, ProjectionRequest, TypedError, ViewModels
from .validation import check_context, validate_artifacts, json_bytes

TAB_ORDER = (("contexts", "Repository contexts"), ("dependencies", "Dependencies"),
             ("cryptography", "Cryptography"), ("ai_models", "AI models"),
             ("bom_connections", "BOM connections"))
_POINTER = lambda i: "/components/{}".format(i)


def _artifact_json(a, read_artifact):
    raw = read_artifact(a["artifact_id"])
    if hashlib.sha256(raw).hexdigest() != a.get("sha256"):
        raise AdapterError([TypedError("artifact_digest_mismatch", a["artifact_id"], "artifact_bytes_digest_mismatch")])
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AdapterError([TypedError("invalid_result", a["artifact_id"], "invalid_json")])
    if not isinstance(doc, dict):
        raise AdapterError([TypedError("invalid_result", a["artifact_id"], "artifact_document_not_object")])
    for key in ("components", "services", "dependencies"):
        if key in doc and not isinstance(doc[key], list):
            raise AdapterError([TypedError("invalid_result", a["artifact_id"] + "/" + key, "artifact_reference_array_invalid")])
    return doc


def _canon(record_class, record_id, binding):
    return {"record_class": record_class, "record_id": record_id, "binding": copy.deepcopy(binding)}


def _page(items, offset, count):
    page = items[offset:offset + count]
    return {"items": page, "total": len(items), "shown": len(page), "offset": offset,
            "has_more": offset + len(page) < len(items)}


def _locations(component):
    out = []
    props = component.get("properties", [])
    if isinstance(props, list):
        for prop in props:
            if isinstance(prop, dict) and isinstance(prop.get("name"), str) and prop["name"].startswith("syft:location:") and prop["name"].endswith(":path") and isinstance(prop.get("value"), str):
                raw = prop["value"]
                out.append((raw, raw[1:] if raw.startswith("/") else raw, "syft_root_relative" if raw.startswith("/") else "syft_recorded_path"))
    for occ in component.get("occurrences", []) if isinstance(component.get("occurrences", []), list) else []:
        if isinstance(occ, dict):
            raw = occ.get("location") or occ.get("path")
            if isinstance(raw, str):
                out.append((raw, raw, "cyclonedx_occurrence"))
    unique = {}
    for row in out:
        unique[(row[0], row[1])] = row
    return sorted(unique.values())


def _component_rows(a, doc, binding):
    rows = []
    comps = doc.get("components", [])
    if not isinstance(comps, list):
        raise AdapterError([TypedError("invalid_result", a["artifact_id"] + "/components", "components_not_array")])
    for i, comp in enumerate(comps):
        if not isinstance(comp, dict):
            raise AdapterError([TypedError("invalid_result", a["artifact_id"] + _POINTER(i), "component_not_object")])
        rows.append({"id": a["artifact_id"] + _POINTER(i), "name": comp.get("name"), "version": comp.get("version"),
                     "type": comp.get("type"), "bom_ref": comp.get("bom-ref"),
                     "canonical_ref": _canon("artifact_component", a["artifact_id"] + _POINTER(i), binding),
                     "locations": _locations(comp), "pointer": _POINTER(i), "artifact_id": a["artifact_id"]})
    metadata = doc.get("metadata", {})
    root = metadata.get("component") if isinstance(metadata, dict) else None
    root_row = None
    if isinstance(root, dict):
        root_row = {"id": a["artifact_id"] + "/metadata/component", "name": root.get("name"),
                    "version": root.get("version"), "type": root.get("type"), "bom_ref": root.get("bom-ref"),
                    "canonical_ref": _canon("artifact_metadata_component", a["artifact_id"] + "/metadata/component", binding),
                    "locations": [], "pointer": "/metadata/component", "artifact_id": a["artifact_id"]}
    return rows, root_row


def _tab(tab_id, title, rows=None, nodes=None, edges=None, selected=None, **extra):
    return {"id": tab_id, "title": title, "rows": rows or [], "nodes": nodes or [], "edges": edges or [],
            "total": len(rows if rows is not None else nodes or []),
            "shown": len(rows if rows is not None else nodes or []), "page": None,
            "selected_id": selected, **extra}


def verify_bound(assessment, context, artifacts, read_artifact):
    """Recheck session, binding, seal, capture identity and raw artifact digests; returns (bound, binding, result, by_id, by_inventory).

    Shared by every projection (the Workbench tabs and the I8 candidate-gap view). Raises AdapterError with typed codes.
    """
    if isinstance(assessment, BoundAssessment):
        bound = assessment.as_dict()
    else:
        raise AdapterError([TypedError("invalid_result", "assessment", "assessment_not_bound")])
    errors = check_context(context)
    if bound.get("schema") != "opentrace.bombridge_assessment/1":
        errors.append(TypedError("unsupported_schema", "assessment.schema", "unsupported_assessment_schema"))
    expected = {"analysis_digest": context.identity.get("analysis_digest"), "session_id": context.expected_session.get("session_id"),
                "generation": context.expected_session.get("generation"), "configuration": context.expected_configuration}
    binding = bound.get("binding", {})
    for key, value in expected.items():
        if binding.get(key) != value:
            errors.append(TypedError("session_mismatch" if key in ("session_id", "generation") else "configuration_mismatch", "binding." + key, "assessment_binding_mismatch"))
    result = bound.get("result")
    if not isinstance(result, dict):
        errors.append(TypedError("invalid_result", "assessment.result", "result_not_object"))
    elif result.get("schema") != "bombridge.result/2" or binding.get("bundle_sha256") != result.get("bundle_sha256"):
        errors.append(TypedError("invalid_result", "assessment.result", "assessment_result_binding_mismatch"))
    try:
        seal = hashlib.sha256(json_bytes({"binding": binding, "result": result, "source_bundle": bound.get("source_bundle")})).hexdigest()
    except (TypeError, ValueError, OverflowError):
        seal = None
    if not bound.get("validation_digest") or bound.get("validation_digest") != seal:
        errors.append(TypedError("invalid_result", "assessment", "assessment_content_changed_or_unsealed"))
    capture = result.get("capture") if isinstance(result, dict) else None
    repository = capture.get("repository") if isinstance(capture, dict) else None
    resolved = context.identity.get("resolved", {}) if isinstance(context.identity, dict) else {}
    expected_repo = context.identity.get("repository", {}).get("canonical_url") if isinstance(context.identity.get("repository"), dict) else None
    if not isinstance(repository, dict) or repository.get("url") != expected_repo or repository.get("revision") != resolved.get("commit_sha") or capture.get("configuration") != context.expected_configuration:
        errors.append(TypedError("revision_mismatch", "assessment.result.capture", "assessment_capture_binding_mismatch"))
    if errors:
        raise AdapterError(errors)
    art_errors, by_id, by_inventory = validate_artifacts(context, {"capture": result.get("capture", {})}, artifacts, read_artifact)
    if art_errors:
        raise AdapterError(art_errors)
    return bound, binding, result, by_id, by_inventory


def project(assessment, *, context, artifacts=(), read_artifact=lambda _id: b"", request=None):
    request = request or ProjectionRequest("contexts")
    if isinstance(request, dict):
        try:
            request = ProjectionRequest(**request)
        except TypeError:
            raise AdapterError([TypedError("invalid_result", "request", "invalid_projection_request")])
    if not isinstance(request, ProjectionRequest):
        raise AdapterError([TypedError("invalid_result", "request", "invalid_projection_request")])
    if request.tab not in {x[0] for x in TAB_ORDER} or request.per_side not in (1, 6) or type(request.per_side) is not int or any(type(x) is not int or x < 0 for x in (request.incoming_offset, request.outgoing_offset)) or (request.selected_id is not None and not isinstance(request.selected_id, str)) or (request.context_path is not None and not isinstance(request.context_path, str)):
        raise AdapterError([TypedError("invalid_result", "request", "invalid_projection_request")])
    bound, binding, result, by_id, by_inventory = verify_bound(assessment, context, artifacts, read_artifact)
    binding = copy.deepcopy(binding)
    parsed = {}
    for aid, art in sorted(by_id.items()):
        if art.get("state") == "acquired":
            parsed[aid] = _artifact_json(art, read_artifact)

    sbom = next((by_inventory.get(inv.get("inventory_id")) for inv in result["capture"].get("inventories", []) if isinstance(inv, dict) and inv.get("kind") == "sbom" and by_inventory.get(inv.get("inventory_id"))), None)
    components, root = _component_rows(sbom, parsed[sbom["artifact_id"]], binding) if sbom and sbom["artifact_id"] in parsed else ([], None)
    component_by_ref = {}
    duplicate_refs = set()
    if root and isinstance(root.get("bom_ref"), str):
        component_by_ref[root["bom_ref"]] = root
    for row in components:
        ref = row.get("bom_ref")
        if isinstance(ref, str):
            if ref in component_by_ref: duplicate_refs.add(ref)
            component_by_ref[ref] = row
    if duplicate_refs:
        raise AdapterError([TypedError("invalid_result", "components", "ambiguous_duplicate_bom_ref:" + sorted(duplicate_refs)[0])])

    contexts = {}
    unlocated = []
    for comp in components:
        if not comp["locations"]:
            unlocated.append(comp)
        for raw, path, basis in comp["locations"]:
            contexts.setdefault(path, {})[comp["id"]] = {"component": comp, "raw_location": raw, "normalization_basis": basis}
    context_rows = []
    for path, members in sorted(contexts.items()):
        context_rows.append({"id": "context:" + path, "path": path, "raw_locations": sorted({m["raw_location"] for m in members.values()}),
                             "normalization_basis": sorted({m["normalization_basis"] for m in members.values()}),
                             "components": [m["component"] for _, m in sorted(members.items())], "total": len(members)})
    requested_path = request.context_path
    if requested_path is not None and requested_path not in contexts:
        raise AdapterError([TypedError("invalid_result", "request.context_path", "invalid_projection_request:unknown_context")])
    repo_id="repository:"+str(context.identity.get("repository",{}).get("canonical_url"))
    context_nodes=[{"id":repo_id,"type":"repository","canonical_ref":_canon("repository",context.identity.get("repository",{}).get("canonical_url"),binding)}]
    context_edges=[]
    for row in context_rows:
        context_nodes.append({"id":row["id"],"type":"path_group","path":row["path"],"raw_locations":row["raw_locations"],"normalization_basis":row["normalization_basis"],"total":row["total"],"canonical_ref":_canon("repository_context",row["path"],binding)})
        context_edges.append({"from":repo_id,"to":row["id"],"key":"path:"+row["path"],"type":"location_grouping"})
        for component_id in sorted(contexts[row["path"]]):
            comp=contexts[row["path"]][component_id]["component"]
            if not any(n["id"]==comp["id"] for n in context_nodes): context_nodes.append({"id":comp["id"],"type":"component","name":comp.get("name"),"bom_ref":comp.get("bom_ref"),"canonical_ref":copy.deepcopy(comp["canonical_ref"])})
            context_edges.append({"from":row["id"],"to":comp["id"],"key":"member:"+comp["pointer"],"type":"location_membership","raw_location":contexts[row["path"]][component_id]["raw_location"],"normalization_basis":contexts[row["path"]][component_id]["normalization_basis"]})
    unlocated_node="context:unlocated"
    if unlocated:
        context_nodes.append({"id":unlocated_node,"type":"unlocated_group","total":len(unlocated),"canonical_ref":_canon("repository_context","unlocated",binding)})
        context_edges.append({"from":repo_id,"to":unlocated_node,"key":"unlocated","type":"location_grouping"})
        for comp in unlocated:
            if not any(n["id"]==comp["id"] for n in context_nodes): context_nodes.append({"id":comp["id"],"type":"component","name":comp.get("name"),"bom_ref":comp.get("bom_ref"),"canonical_ref":copy.deepcopy(comp["canonical_ref"])})
            context_edges.append({"from":unlocated_node,"to":comp["id"],"key":"unlocated:"+comp["pointer"],"type":"location_membership"})
    context_tab = _tab("contexts", "Repository contexts", rows=context_rows, nodes=context_nodes,edges=context_edges,selected="context:" + requested_path if requested_path else None,
                       unlocated={"total": len(unlocated), "components": unlocated}, component_total=len(components), membership_total=sum(x["total"] for x in context_rows))

    # Dependency edges are only explicit CycloneDX references. Identical repeated rows collapse.
    dependencies = []
    dep_doc = parsed.get(sbom["artifact_id"], {}) if sbom else {}
    edge_sources = {}
    unresolved_map = {}
    deps = dep_doc.get("dependencies", [])
    if isinstance(deps, list):
        for i, row in enumerate(deps):
            if not isinstance(row, dict) or not isinstance(row.get("ref"), str) or not isinstance(row.get("dependsOn", []), list):
                raise AdapterError([TypedError("invalid_result", "dependencies[{}]".format(i), "invalid_dependency_row")])
            for j, ref in enumerate(row.get("dependsOn", [])):
                if not isinstance(ref, str):
                    raise AdapterError([TypedError("invalid_result", "dependencies[{}].dependsOn[{}]".format(i,j), "dependency_ref_not_string")])
                key = (row["ref"], ref)
                edge_sources.setdefault(key, []).append("/dependencies/{}/dependsOn/{}".format(i,j))
                if row["ref"] not in component_by_ref or ref not in component_by_ref:
                    unresolved_map.setdefault(key, []).append("/dependencies/{}/dependsOn/{}".format(i,j))
    unresolved=[{"from_ref":src,"to_ref":dst,"source_pointers":sorted(pointers)} for (src,dst),pointers in sorted(unresolved_map.items())]
    dep_edges=[]
    for (src,dst), pointers in sorted(edge_sources.items()):
        if src not in component_by_ref or dst not in component_by_ref:
            continue
        dep_edges.append({"from": component_by_ref[src]["id"], "to": component_by_ref[dst]["id"], "from_ref": src, "to_ref": dst,
                          "source_pointers": sorted(pointers), "type": "depends_on", "canonical_ref": _canon("artifact_dependency", pointers[0], binding)})
    selected = request.selected_id
    if selected is not None and not any(c["id"] == selected for c in components):
        known = any(selected == "context:" + p for p in contexts)
        if not known:
            # Non-dependency tabs may use domain record IDs; unknown selections are rejected below.
            pass
    dep_selected = selected if selected and any(c["id"] == selected for c in components) else None
    incoming_all = sorted([e for e in dep_edges if e["to"] == dep_selected], key=lambda e:(e["from_ref"],e["source_pointers"][0])) if dep_selected else []
    outgoing_all = sorted([e for e in dep_edges if e["from"] == dep_selected], key=lambda e:(e["to_ref"],e["source_pointers"][0])) if dep_selected else []
    eligible_in = incoming_all; eligible_out = outgoing_all
    if requested_path:
        member_ids = set(contexts[requested_path])
        if dep_selected and dep_selected not in member_ids:
            raise AdapterError([TypedError("invalid_result", "request.selected_id", "invalid_projection_request:selection_outside_context")])
        eligible_in = [e for e in incoming_all if e["from"] in member_ids]
        eligible_out = [e for e in outgoing_all if e["to"] in member_ids]
    if request.tab == "dependencies" and selected is not None and dep_selected is None:
        raise AdapterError([TypedError("invalid_result", "request.selected_id", "invalid_projection_request:unknown_selection")])
    if dep_selected:
        edges_for_page = _page(eligible_in, request.incoming_offset, request.per_side)
        out_page = _page(eligible_out, request.outgoing_offset, request.per_side)
        deps_rows = {dep_selected: next(c for c in components if c["id"] == dep_selected)}
        for e in edges_for_page["items"] + out_page["items"]:
            other = e["from"] if e["to"] == dep_selected else e["to"]
            deps_rows[other] = next(c for c in components if c["id"] == other)
        dependency_tab = _tab("dependencies", "Dependencies", nodes=list(deps_rows.values()), edges=edges_for_page["items"] + out_page["items"], selected=dep_selected,
                              incoming={**edges_for_page, "before_context_filter": len(incoming_all), "eligible_total": len(eligible_in)},
                              outgoing={**out_page, "before_context_filter": len(outgoing_all), "eligible_total": len(eligible_out)}, unresolved=unresolved)
    else:
        filtered_components=components
        filtered_edges=dep_edges
        if requested_path:
            member_ids=set(contexts[requested_path])
            filtered_components=[c for c in components if c["id"] in member_ids]
            filtered_edges=[e for e in dep_edges if e["from"] in member_ids and e["to"] in member_ids]
        dependency_tab = _tab("dependencies", "Dependencies", nodes=filtered_components, edges=filtered_edges, selected=None,
                              incoming={"items":[],"total":0,"shown":0,"offset":0,"has_more":False}, outgoing={"items":[],"total":0,"shown":0,"offset":0,"has_more":False}, unresolved=unresolved)

    checks = copy.deepcopy(result.get("findings", []))
    input_assertions = {a.get("assertion_id"): a for a in result.get("_input_assertions", []) if isinstance(a,dict)}
    graph = result.get("graph", {})
    graph_nodes = graph.get("nodes", []) if isinstance(graph,dict) else []
    node_map = {n["id"]: n for n in graph_nodes if isinstance(n,dict) and isinstance(n.get("id"),str)}
    evidence_map = {"evidence:"+e.get("evidence_id"): e for e in result.get("_input_evidence",[]) if isinstance(e,dict) and isinstance(e.get("evidence_id"),str)}
    assertion_domain = {}
    for node in graph_nodes:
        if isinstance(node,dict) and node.get("type")=="assertion": assertion_domain[node.get("id","").split(":",1)[-1]]=node
    for f in checks:
        if isinstance(f,dict):
            f["canonical_ref"] = _canon("assertion", f.get("assertion_id"), binding)
            node = assertion_domain.get(f.get("assertion_id"), {})
            f.setdefault("bounded_meaning", node.get("rationale"))
            rule = next((r for r in result.get("rules",[]) if isinstance(r,dict) and r.get("rule_id")==f.get("rule_id")),{})
            f.setdefault("not_established", copy.deepcopy(rule.get("not_established", [])))
    active_tab = request.tab
    known_assertions={f.get("assertion_id") for f in checks if isinstance(f,dict)}
    raw_selectable = set()
    for aid, doc in parsed.items():
        raw_selectable.update(aid + _POINTER(i) for i, x in enumerate(doc.get("components", [])) if isinstance(x, dict))
        raw_selectable.update(aid + "/services/{}".format(i) for i, x in enumerate(doc.get("services", [])) if isinstance(x, dict))
    selected_known = request.selected_id is None or request.selected_id in node_map or request.selected_id in known_assertions or request.selected_id in {c["id"] for c in components} or request.selected_id in {"context:"+p for p in contexts} or request.selected_id in raw_selectable
    if request.selected_id is not None and not selected_known:
        raise AdapterError([TypedError("invalid_result", "request.selected_id", "invalid_projection_request:unknown_selection")])
    # Rule-family tab subsets remain plain records, tied to canonical assertions.
    crypto_checks = [f for f in checks if isinstance(f,dict) and (assertion_domain.get(f.get("assertion_id"),{}).get("family")=="crypto_attribution" or str(f.get("rule_id","")).startswith("crypto_"))]
    ai_checks = [f for f in checks if isinstance(f,dict) and (assertion_domain.get(f.get("assertion_id"),{}).get("family")=="model_identity" or str(f.get("rule_id","")).startswith("model_"))]
    crypto_raw=[]; crypto_services=[]; ai_models=[]
    for art in by_id.values():
        if art.get("state")!="acquired": continue
        doc=parsed.get(art["artifact_id"],{})
        if art.get("kind")=="cbom":
            crypto_raw=[{"id":art["artifact_id"]+_POINTER(i),"record":copy.deepcopy(x),"pointer":_POINTER(i),"artifact_id":art["artifact_id"],"canonical_ref":_canon("artifact_component",art["artifact_id"]+_POINTER(i),binding)} for i,x in enumerate(doc.get("components",[])) if isinstance(x,dict) and (x.get("type") in ("cryptographic-asset", "cryptographic-asset-function") or x.get("cryptoProperties") is not None)]
            crypto_services=[{"id":art["artifact_id"]+"/services/{}".format(i),"record":copy.deepcopy(x),"pointer":"/services/{}".format(i),"artifact_id":art["artifact_id"],"canonical_ref":_canon("artifact_service",art["artifact_id"]+"/services/{}".format(i),binding)} for i,x in enumerate(doc.get("services",[])) if isinstance(x,dict)]
        elif art.get("kind")=="aibom":
            ai_models=[{"id":art["artifact_id"]+_POINTER(i),"record":copy.deepcopy(x),"pointer":_POINTER(i),"artifact_id":art["artifact_id"],"canonical_ref":_canon("artifact_model",art["artifact_id"]+_POINTER(i),binding)} for i,x in enumerate(doc.get("components",[])) if isinstance(x,dict) and x.get("type") == "machine-learning-model"]
    def check_tab(tab_id,title,items):
        valid={x.get("assertion_id") for x in items if isinstance(x,dict)}
        sel=request.selected_id if request.selected_id in valid else None
        return _tab(tab_id,title,rows=items,selected=sel,selection_prompt="Select a check" if request.selected_id and sel is None else None)
    crypto_tab=check_tab("cryptography","Cryptography",crypto_raw)
    crypto_tab["checks"]=crypto_checks
    crypto_tab["services"]=crypto_services
    crypto_tab["crypto_asset_total"]=len(crypto_raw)
    ai_tab=check_tab("ai_models","AI models",ai_models)
    ai_tab["checks"]=ai_checks
    def family_graph(items):
        assertion_ids={"assertion:"+x["assertion_id"] for x in items if isinstance(x,dict) and isinstance(x.get("assertion_id"),str)}
        evidence_ids={"evidence:"+e.get("evidence_id") for x in items if isinstance(x,dict) for field in ("used_evidence","excluded_evidence") for e in x.get(field,[]) if isinstance(e,dict) and isinstance(e.get("evidence_id"),str)}
        keep=set(assertion_ids)|evidence_ids
        edges=[]
        for edge in graph.get("edges",[]):
            if not isinstance(edge,dict): continue
            if edge.get("from") in assertion_ids or edge.get("to") in assertion_ids or (edge.get("from") in node_map and edge.get("to") in assertion_ids):
                edges.append(copy.deepcopy(edge)); keep.update((edge.get("from"),edge.get("to")))
        return [copy.deepcopy(n) for n in graph_nodes if isinstance(n,dict) and n.get("id") in keep], edges
    crypto_tab["nodes"],crypto_tab["edges"]=family_graph(crypto_checks)
    ai_tab["nodes"],ai_tab["edges"]=family_graph(ai_checks)
    for family_tab in (crypto_tab, ai_tab):
        for node in family_tab["nodes"]:
            node["canonical_ref"] = _canon(node.get("type", "domain_record"), node.get("id"), binding)
    crypto_tab["total"]=len(crypto_tab["nodes"]); crypto_tab["shown"]=len(crypto_tab["nodes"])
    ai_tab["total"]=len(ai_tab["nodes"]); ai_tab["shown"]=len(ai_tab["nodes"])
    crypto_tab["selected_id"]=request.selected_id if request.selected_id in {f.get("assertion_id") for f in crypto_checks} or any(x["id"]==request.selected_id for x in crypto_raw+crypto_services) else None
    ai_tab["selected_id"]=request.selected_id if request.selected_id in {f.get("assertion_id") for f in ai_checks} or any(x["id"]==request.selected_id for x in ai_models) else None
    if crypto_tab["selected_id"] is not None: crypto_tab.pop("selection_prompt",None)
    if ai_tab["selected_id"] is not None: ai_tab.pop("selection_prompt",None)
    if request.selected_id is not None and crypto_tab["selected_id"] is None and request.tab=="cryptography":
        crypto_tab["selection_prompt"]="Select a check in this tab"
    if request.selected_id is not None and ai_tab["selected_id"] is None and request.tab=="ai_models":
        ai_tab["selection_prompt"]="Select a check in this tab"
    domain_graph={"nodes":copy.deepcopy(graph.get("nodes",[])),"edges":copy.deepcopy(graph.get("edges",[]))}
    for node in domain_graph["nodes"]:
        if isinstance(node,dict):
            node["canonical_ref"]=_canon(node.get("type","domain_record"),node.get("id"),binding)
    links=copy.deepcopy(result.get("inventory_links",[]))
    bom_tab=_tab("bom_connections","BOM connections",nodes=domain_graph["nodes"],edges=domain_graph["edges"],selected=request.selected_id if request.selected_id in node_map else None,
                 inventory_links=links,scope_links=[x for x in links if isinstance(x,dict) and x.get("kind")=="shared_scan_paths"],
                 record_links=[x for x in links if isinstance(x,dict) and x.get("kind")!="shared_scan_paths"])
    tabs=[context_tab,dependency_tab,crypto_tab,ai_tab,bom_tab]
    artifact_cards=[]
    source_bundle=bound.get("source_bundle") if isinstance(bound.get("source_bundle"),dict) else {}
    source_evidence=source_bundle.get("evidence",[]) if isinstance(source_bundle.get("evidence",[]),list) else []
    capture_repository=(result.get("capture",{}).get("repository",{})
                        if isinstance(result.get("capture"),dict) else {})
    repository_url=capture_repository.get("url") if isinstance(capture_repository,dict) else None
    for aid,art in sorted(by_id.items()):
        inv=next((x for x in result.get("capture",{}).get("inventories",[]) if isinstance(x,dict) and x.get("inventory_id")==art.get("inventory_id")),{})
        related_observations=[copy.deepcopy(e) for e in source_evidence if isinstance(e,dict)
                              and isinstance(e.get("observation"),dict)
                              and isinstance(e["observation"].get("document"),dict)
                              and e["observation"]["document"].get("raw_sha256")==art.get("sha256")]
        raw_binding=copy.deepcopy(inv.get("scan_binding")) if isinstance(inv.get("scan_binding"),dict) else None
        source_observation=(related_observations[0].get("observation",{}) if related_observations else {})
        resolved_binding=(resolve_binding(source_observation, art.get("acquisition_manifest"), art.get("sha256"), repository_url)
                          if art.get("kind") in ("aibom", "cbom") else None)
        if resolved_binding is not None:
            binding_label=resolved_binding.get("level")
            binding_conflicts=copy.deepcopy(resolved_binding.get("conflicts", []))
            binding_notes=copy.deepcopy(resolved_binding.get("notes", []))
            corroborated=resolved_binding.get("corroborated")
            if binding_conflicts or binding_label == "conflict":
                provenance_status="conflict"
            elif binding_label == "recorded":
                provenance_status="recorded_unverified"
            elif binding_label == "declared":
                provenance_status="declared"
            else:
                provenance_status="unknown"
        else:
            binding_label=None
            binding_conflicts=copy.deepcopy(inv.get("binding_conflicts", []))
            binding_notes=copy.deepcopy(inv.get("binding_notes", []))
            corroborated=None
            provenance_status="unknown" if raw_binding is None and not art.get("acquisition_manifest") else "recorded_unverified"
        artifact_cards.append({"artifact_id":aid,"inventory_id":art.get("inventory_id"),"kind":art.get("kind"),"state":art.get("state"),
                               "record_count":art.get("record_count"),"record_count_unit":art.get("record_count_unit"),
                               "record_counts":copy.deepcopy(art.get("record_counts")),"sha256":art.get("sha256"),
                               "producer":inv.get("generator"),"scope":copy.deepcopy(inv.get("scan_scope")),
                               "binding_basis":inv.get("scan_binding",{}).get("basis") if isinstance(inv.get("scan_binding"),dict) else None,
                               "raw_binding":raw_binding,"observed_binding":copy.deepcopy(source_observation.get("binding")),
                               "binding_label":binding_label,"resolved_binding":copy.deepcopy(resolved_binding),
                               "binding_conflicts":binding_conflicts,"binding_notes":binding_notes,
                               "corroborated":corroborated,
                               "acquisition_manifest":copy.deepcopy(art.get("acquisition_manifest")),
                               "binding_observations":related_observations,
                               "provenance_status":provenance_status,
                               "canonical_ref":_canon("artifact",aid,binding)})
    checks_tab = next(x for x in tabs if x["id"]==active_tab)
    shown_ids={r.get("assertion_id") for r in checks_tab.get("checks",[]) if isinstance(r,dict)}
    if active_tab in ("cryptography", "ai_models") and request.selected_id is not None:
        shown_ids &= {request.selected_id.removeprefix("assertion:")}
    used=set(); excluded=set()
    for f in checks:
        if f.get("assertion_id") not in shown_ids: continue
        used.update(x.get("evidence_id") for x in f.get("used_evidence",[]) if isinstance(x,dict))
        excluded.update(x.get("evidence_id") for x in f.get("excluded_evidence",[]) if isinstance(x,dict))
    # Evidence nodes retain the source identity and label; union is derived from visible checks.
    supporting=[]
    for node in graph_nodes:
        if isinstance(node,dict) and node.get("type")=="evidence":
            eid=node.get("id","").removeprefix("evidence:")
            if eid in used or eid in excluded:
                supporting.append({"evidence_id":eid,"label":"used" if eid in used else "excluded","record":copy.deepcopy(node),"canonical_ref":_canon("evidence",eid,binding)})
    inspector = []
    if request.selected_id is not None:
        if request.tab == "contexts":
            inspector = [copy.deepcopy(next(x for x in context_rows if x["id"]==request.selected_id))] if request.selected_id.startswith("context:") and any(x["id"]==request.selected_id for x in context_rows) else []
        elif request.tab == "dependencies" and dep_selected:
            comp=next(c for c in components if c["id"]==dep_selected)
            source=parsed.get(comp["artifact_id"],{})
            pointer=comp["pointer"]
            raw_record=source.get("metadata",{}).get("component") if pointer=="/metadata/component" else (source.get("components",[])[int(pointer.split("/")[-1])] if pointer.startswith("/components/") else None)
            inspector=[{"record":copy.deepcopy(raw_record),"pointer":pointer,"artifact_id":comp["artifact_id"],"canonical_ref":copy.deepcopy(comp["canonical_ref"])}]
        elif request.tab in ("cryptography","ai_models"):
            allowed=crypto_checks if request.tab=="cryptography" else ai_checks
            wanted=request.selected_id.removeprefix("assertion:")
            check=next((f for f in allowed if f.get("assertion_id")==wanted),None)
            if check is not None:
                node=assertion_domain.get(wanted,{})
                subject_id=next((e.get("to") for e in graph.get("edges",[]) if isinstance(e,dict) and e.get("from")=="assertion:"+wanted and e.get("key")=="subject"),None)
                subject=node_map.get(subject_id)
                connected=[e for e in graph.get("edges",[]) if isinstance(e,dict) and (e.get("from")=="assertion:"+wanted or e.get("to")=="assertion:"+wanted or (subject_id and e.get("from")==subject_id))]
                inspector=[{"check":copy.deepcopy(check),"assertion_node":copy.deepcopy(node),"subject_node":copy.deepcopy(subject),"candidates":copy.deepcopy([e for e in connected if e.get("type") in ("candidate_match","declared_as")]),"connecting_edges":copy.deepcopy(connected),"used_evidence":copy.deepcopy(check.get("used_evidence",[])),"excluded_evidence":copy.deepcopy(check.get("excluded_evidence",[]))}]
            else:
                raw_rows=crypto_raw+crypto_services if request.tab=="cryptography" else ai_models
                raw_row=next((x for x in raw_rows if x["id"]==request.selected_id),None)
                if raw_row:
                    doc=parsed[raw_row["artifact_id"]]
                    pointer=raw_row["pointer"]
                    raw_record=doc.get("services",[])[int(pointer.split("/")[-1])] if pointer.startswith("/services/") else doc.get("components",[])[int(pointer.split("/")[-1])]
                    inspector=[{"record":copy.deepcopy(raw_record),"pointer":pointer,"artifact_id":raw_row["artifact_id"],"canonical_ref":copy.deepcopy(raw_row["canonical_ref"])}]
                else:
                    checks_tab=crypto_tab if request.tab=="cryptography" else ai_tab
                    checks_tab["selection_prompt"]="Select a check in this tab"
        elif request.tab=="bom_connections" and request.selected_id in node_map:
            inspector=[copy.deepcopy(node_map[request.selected_id])]
    limitations=copy.deepcopy(result.get("limitations",[])) if isinstance(result.get("limitations",[]),list) else []
    capture=result.get("capture",{})
    limitations.append({"type":"capture_coverage","origin":capture.get("origin"),"unknown":copy.deepcopy(capture.get("unknown",[])),"unavailable":copy.deepcopy(capture.get("unavailable",[]))})
    limitations.extend({"type":"artifact_limitations","artifact_id":a.get("artifact_id"),"items":copy.deepcopy(a.get("limitations",[]))} for a in by_id.values() if a.get("limitations"))
    if check_context(context):
        raise AdapterError([TypedError("session_mismatch", "current_session", "stale_after_projection")])
    return ViewModels(binding,tabs,artifact_cards,checks,supporting,inspector,limitations).as_dict()
