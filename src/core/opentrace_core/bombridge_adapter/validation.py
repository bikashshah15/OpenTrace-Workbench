"""Structural, identity, artifact and result binding checks for I4C."""
import hashlib
import json
import re

from opentrace_core.intake.identity import validate_identity
from opentrace_core.bombridge.contract import JUDGMENT_KEYS, validate_bundle
from .types import AdapterError, TypedError

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_STATES = {"not_requested", "not_acquired", "acquiring", "acquired", "failed", "unsupported", "cancelled"}
_KINDS = {"sbom", "cbom", "aibom"}
_DISCOVERY_SCHEMA = "bombridge.discovery/1"
_DISCOVERY_CATEGORIES = {"missing_component", "missing_connection", "missing_bom_document", "unknown_coverage", "invalid_reference"}
MAX_DISCOVERY_CANDIDATES = 2000
_DISCOVERY_DERIVED = ("candidates", "verification", "gap_states")  # added by the engine (pipeline.attach_findings); every other key must equal the bundle's
_STATES = ("supported", "contradicted", "conflicting_evidence", "unverifiable")
_RULES = {"model_identity.digest/2", "inventory_coverage.requirement_represented/1",
          "model_identity.declared_in_aibom/1", "dependency_mapping.import_resolves_to_component/1",
          "crypto_attribution.operation_declared_in_cbom/2", "crypto_attribution.operation_declared_in_cbom/3",
          "crypto_attribution.operation_declared_in_cbom/4"}


def _error(code, path, detail):
    return TypedError(code, path, detail)


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def check_context(context, *, require_current=True):
    errors = []
    identity = context.identity
    if not isinstance(identity, dict):
        return [_error("revision_mismatch", "identity", "invalid_identity: identity_not_object")]
    if not isinstance(context.expected_session, dict) or not callable(context.current_session):
        return [_error("session_mismatch", "context", "invalid_expected_session_or_callback")]
    if context.expected_configuration is not None and not isinstance(context.expected_configuration, str):
        errors.append(_error("configuration_mismatch", "context.expected_configuration", "expected_string_or_null"))
    for message in validate_identity(identity):
        errors.append(_error("revision_mismatch", "identity", "invalid_identity: " + message))
    pair = identity.get("session", {}) if isinstance(identity, dict) else {}
    if pair != context.expected_session:
        errors.append(_error("session_mismatch", "identity.session", "expected_session_mismatch"))
    if require_current:
        try:
            current = context.current_session()
        except Exception as exc:
            errors.append(_error("session_mismatch", "current_session", "current_session_unavailable:" + type(exc).__name__))
            current = None
        if current != context.expected_session:
            errors.append(_error("session_mismatch", "current_session", "stale_session"))
    return errors


def normalize_artifact(a):
    if hasattr(a, "as_dict"):
        return a.as_dict()
    return a


def validate_artifacts(context, bundle, artifacts, read_artifact):
    errors = []
    by_inventory = {}
    by_id = {}
    for index, raw in enumerate(artifacts):
        a = normalize_artifact(raw)
        path = "artifacts[{}]".format(index)
        if not isinstance(a, dict):
            errors.append(_error("invalid_bundle", path, "artifact_not_object")); continue
        aid, iid, kind, state = (a.get(k) for k in ("artifact_id", "inventory_id", "kind", "state"))
        if not isinstance(aid, str) or not aid or not isinstance(iid, str) or not iid:
            errors.append(_error("invalid_bundle", path, "artifact_identity_required")); continue
        if aid in by_id or iid in by_inventory:
            errors.append(_error("invalid_bundle", path, "duplicate_id"))
        by_id[aid] = a; by_inventory[iid] = a
        if not isinstance(kind,str) or kind not in _KINDS or not isinstance(state,str) or state not in _ARTIFACT_STATES:
            errors.append(_error("invalid_bundle", path, "invalid_kind_or_state"))
        count = a.get("record_count")
        if count is not None and (type(count) is not int or count < 0):
            errors.append(_error("invalid_bundle", path + ".record_count", "nonnegative_integer_or_null_required"))
        if not isinstance(a.get("record_count_unit"), str) or not a["record_count_unit"]:
            errors.append(_error("invalid_bundle", path + ".record_count_unit", "count_unit_required"))
        if a.get("record_counts") is not None and not isinstance(a.get("record_counts"),dict):
            errors.append(_error("invalid_bundle", path + ".record_counts", "record_counts_must_be_object"))
        if a.get("acquisition_manifest") is not None and not isinstance(a.get("acquisition_manifest"),dict):
            errors.append(_error("invalid_bundle", path + ".acquisition_manifest", "manifest_must_be_object"))
        if not isinstance(a.get("limitations",[]),list):
            errors.append(_error("invalid_bundle", path + ".limitations", "limitations_must_be_array"))
        if state == "acquired":
            if not isinstance(a.get("sha256"), str) or not _HEX64.fullmatch(a["sha256"]):
                errors.append(_error("invalid_bundle", path + ".sha256", "acquired_digest_required"))
            if a.get("analysis_digest") != context.identity.get("analysis_digest") or a.get("session_id") != context.expected_session.get("session_id") or type(a.get("generation")) is not int or a.get("generation") != context.expected_session.get("generation"):
                errors.append(_error("session_mismatch", path, "artifact_context_mismatch"))
            try:
                raw_bytes = read_artifact(aid)
                if not isinstance(raw_bytes, bytes):
                    raise TypeError("reader_must_return_bytes")
                digest = hashlib.sha256(raw_bytes).hexdigest()
                if digest != a.get("sha256"):
                    errors.append(_error("artifact_digest_mismatch", path, "artifact_bytes_digest_mismatch"))
            except Exception as exc:
                errors.append(_error("dangling_reference", path, "artifact_unavailable:" + type(exc).__name__))
        elif a.get("sha256") is not None:
            errors.append(_error("invalid_bundle", path + ".sha256", "non_acquired_artifact_has_digest"))

    capture = bundle.get("capture") if isinstance(bundle, dict) else None
    inventories = capture.get("inventories", []) if isinstance(capture, dict) else []
    for i, inv in enumerate(inventories):
        if not isinstance(inv, dict):
            continue
        source_digest = inv.get("source_sha256")
        if source_digest is None:
            continue
        aid = by_inventory.get(inv.get("inventory_id"))
        path = "capture.inventories[{}]".format(i)
        if not aid:
            errors.append(_error("dangling_reference", path, "missing_artifact")); continue
        if aid.get("state") != "acquired":
            errors.append(_error("dangling_reference", path, "artifact_not_acquired:" + str(aid.get("state")))); continue
        if aid.get("kind") != inv.get("kind") or aid.get("sha256") != source_digest:
            errors.append(_error("artifact_digest_mismatch", path, "inventory_artifact_binding_mismatch"))
    return errors, by_id, by_inventory


def validate_discovery(bundle):
    """Typed checks for the optional ``discovery`` section: every reference must resolve inside the bundle. Never raises."""
    d = bundle.get("discovery")
    if d is None:
        return []
    errors = []
    if not isinstance(d, dict) or d.get("schema") != _DISCOVERY_SCHEMA:
        return [_error("unsupported_schema", "discovery.schema", "unsupported_discovery_schema")]
    cands, ver = d.get("candidates"), d.get("verification_assertions")
    if not isinstance(cands, list) or not isinstance(ver, list):
        return [_error("invalid_bundle", "discovery", "candidates_and_verification_must_be_arrays")]
    if len(cands) > MAX_DISCOVERY_CANDIDATES:
        return [_error("size_limit", "discovery.candidates", "candidates_over_limit")]
    assertion_ids = {a.get("assertion_id") for a in bundle.get("assertions", []) if isinstance(a, dict)}
    evidence_ids = {e.get("evidence_id") for e in bundle.get("evidence", []) if isinstance(e, dict)}
    entity_ids = {e.get("entity_id") for e in bundle.get("entities", []) if isinstance(e, dict)}
    inventory_ids = {i.get("inventory_id") for i in bundle.get("capture", {}).get("inventories", []) if isinstance(i, dict)}
    seen = set()
    for i, c in enumerate(cands):
        path = "discovery.candidates[{}]".format(i)
        if not isinstance(c, dict) or not isinstance(c.get("candidate_id"), str) or not c["candidate_id"]:
            errors.append(_error("invalid_bundle", path, "candidate_id_required")); continue
        if c["candidate_id"] in seen:
            errors.append(_error("invalid_bundle", path, "duplicate_id"))
        seen.add(c["candidate_id"])
        if not isinstance(c.get("category"), str) or c["category"] not in _DISCOVERY_CATEGORIES:
            errors.append(_error("invalid_bundle", path + ".category", "unknown_category"))
        if not isinstance(c.get("title"), str) or not isinstance(c.get("group"), str):
            errors.append(_error("invalid_bundle", path, "title_and_group_must_be_strings"))
        if any(k in c for k in ("finding", "state")):
            errors.append(_error("invalid_bundle", path, "derived_judgment_supplied"))
        # field types are checked before any set lookup: a list or object is unhashable and must be a typed error, not an exception
        for field, known, detail in (("assertion_id", assertion_ids, "unknown_assertion"), ("entity_id", entity_ids, "unknown_entity"),
                                     ("selected_inventory", inventory_ids, "unknown_inventory")):
            value = c.get(field)
            if value is None:
                continue
            if not isinstance(value, str):
                errors.append(_error("invalid_bundle", path + "." + field, "reference_must_be_string_or_null"))
            elif value not in known:
                errors.append(_error("dangling_reference", path + "." + field, detail))
        refs = c.get("evidence_ids")
        if not isinstance(refs, list) or any(not isinstance(x, str) or x not in evidence_ids for x in refs):
            errors.append(_error("dangling_reference", path + ".evidence_ids", "unknown_evidence"))
    if any(not isinstance(x, str) or x not in assertion_ids for x in ver):
        errors.append(_error("dangling_reference", "discovery.verification_assertions", "unknown_assertion"))
    return errors


def prevalidate_bundle(bundle, context):
    errors = []
    if not isinstance(bundle, dict):
        return [_error("invalid_bundle", "$", "bundle_not_object")]
    try:
        json_bytes(bundle)
    except (TypeError, ValueError, OverflowError):
        errors.append(_error("invalid_bundle", "$", "invalid_json"))
        return errors
    if bundle.get("schema") != "bombridge.bundle/2":
        errors.append(_error("unsupported_schema", "schema", "unsupported_bundle_schema"))
    for name in ("entities", "assertions", "evidence", "input_checks"):
        if not isinstance(bundle.get(name), list):
            errors.append(_error("invalid_bundle", name, "expected_array"))
    cap = bundle.get("capture")
    if not isinstance(cap, dict):
        errors.append(_error("invalid_bundle", "capture", "expected_object")); return errors
    if not isinstance(cap.get("repository"), dict) or not isinstance(cap.get("inventories"), list):
        errors.append(_error("invalid_bundle", "capture", "invalid_capture_containers"))
    if not isinstance(cap.get("unknown"), list) or not isinstance(cap.get("unavailable"), list):
        errors.append(_error("invalid_bundle", "capture", "unknown_unavailable_must_be_arrays"))
    if cap.get("origin") not in ("captured", "curated", "illustrative") or bundle.get("origin") not in ("captured", "curated", "illustrative", "mixed"):
        errors.append(_error("invalid_bundle", "origin", "invalid_origin"))
    if cap.get("configuration") != context.expected_configuration:
        errors.append(_error("configuration_mismatch", "capture.configuration", "configuration_mismatch"))
    if any(not isinstance(bundle.get(name), list) for name in ("entities", "assertions", "evidence", "input_checks")):
        return errors
    if not isinstance(cap.get("repository"), dict) or not isinstance(cap.get("inventories"), list) or not isinstance(cap.get("unknown"), list) or not isinstance(cap.get("unavailable"), list):
        return errors
    if any(not isinstance(x,str) for x in cap["unknown"]+cap["unavailable"]):
        errors.append(_error("invalid_bundle", "capture", "unknown_unavailable_ids_must_be_strings"))
    repo = context.identity.get("repository", {})
    resolved = context.identity.get("resolved", {})
    if cap.get("repository", {}).get("url") != repo.get("canonical_url") or cap.get("repository", {}).get("revision") != resolved.get("commit_sha"):
        errors.append(_error("revision_mismatch", "capture.repository", "repository_mismatch"))
    seen_inventories=set()
    for i, inv in enumerate(cap.get("inventories", [])):
        if not isinstance(inv,dict):
            errors.append(_error("invalid_bundle", "capture.inventories[{}]".format(i), "inventory_not_object")); continue
        if not isinstance(inv.get("inventory_id"),str) or not isinstance(inv.get("kind"),str):
            errors.append(_error("invalid_bundle", "capture.inventories[{}]".format(i), "inventory_identity_required"))
        elif inv["inventory_id"] in seen_inventories:
            errors.append(_error("invalid_bundle", "capture.inventories[{}]".format(i), "duplicate_id"))
        else:
            seen_inventories.add(inv["inventory_id"])
        if inv.get("scan_scope") is not None and not isinstance(inv.get("scan_scope"),dict):
            errors.append(_error("invalid_bundle", "capture.inventories[{}].scan_scope".format(i), "scan_scope_not_object"))
        if isinstance(inv.get("scan_scope"), dict):
            rev = inv["scan_scope"].get("revision")
            if rev is not None and rev != resolved.get("commit_sha"):
                errors.append(_error("revision_mismatch", "capture.inventories[{}].scan_scope.revision".format(i), "inventory_revision_mismatch"))
    for name, idkey in (("entities", "entity_id"), ("assertions", "assertion_id"), ("evidence", "evidence_id")):
        seen = set()
        for i, rec in enumerate(bundle.get(name, [])):
            if not isinstance(rec, dict):
                errors.append(_error("invalid_bundle", "{}[{}]".format(name, i), "record_not_object")); continue
            ident = rec.get(idkey)
            if not isinstance(ident, str) or not ident:
                errors.append(_error("invalid_bundle", "{}[{}].{}".format(name, i, idkey), "record_id_required"))
            elif ident in seen:
                errors.append(_error("invalid_bundle", name, "duplicate_id:" + ident))
            if isinstance(ident,str):
                seen.add(ident)
    # Donor validation is safe only after nested records are dictionaries/lists.
    for kind in ("entities", "assertions", "evidence", "input_checks"):
        if any(not isinstance(x, dict) for x in bundle.get(kind, [])):
            return errors
    for rec in bundle.get("entities", []) + bundle.get("assertions", []) + bundle.get("evidence", []):
        if ("scope" in rec or "assertion_id" in rec or "evidence_id" in rec) and not isinstance(rec.get("scope"), dict):
            errors.append(_error("invalid_bundle", "scope", "scope_not_object"))
        for key in ("scope", "observation", "identity_matches"):
            if key in rec and not isinstance(rec[key], (dict, list)):
                errors.append(_error("invalid_bundle", key, "invalid_nested_type"))
        if "observation" in rec and not isinstance(rec["observation"], dict):
            errors.append(_error("invalid_bundle", "observation", "expected_object"))
        for key in ("relations", "identity_matches"):
            if key in rec and (not isinstance(rec[key], list) or any(not isinstance(x, dict) for x in rec[key])):
                errors.append(_error("invalid_bundle", key, "expected_array_of_objects"))
        if "observes" in rec and (not isinstance(rec["observes"], list) or any(not isinstance(x, str) for x in rec["observes"])):
            errors.append(_error("invalid_bundle", "observes", "expected_array_of_ids"))
        if isinstance(rec.get("observation"), dict) and "observation" in rec:
            observation = rec["observation"]
            if "artifact" in observation and not isinstance(observation["artifact"], dict):
                errors.append(_error("invalid_bundle", "observation.artifact", "expected_object"))
    if any(e.code == "invalid_bundle" for e in errors):
        return errors
    for i, ent in enumerate(bundle.get("entities", [])):
        if "artifact" in ent and not isinstance(ent.get("artifact"),dict):
            errors.append(_error("invalid_bundle", "entities[{}].artifact".format(i), "artifact_not_object"))
        if "source" in ent and not isinstance(ent.get("source"),dict):
            errors.append(_error("invalid_bundle", "entities[{}].source".format(i), "source_not_object"))
        for j, rel in enumerate(ent.get("relations", [])):
            if not isinstance(rel.get("target"),str):
                errors.append(_error("invalid_bundle", "entities[{}].relations[{}].target".format(i,j), "reference_id_must_be_string"))
        for j, match in enumerate(ent.get("identity_matches", [])):
            if not isinstance(match.get("other"),str):
                errors.append(_error("invalid_bundle", "entities[{}].identity_matches[{}].other".format(i,j), "reference_id_must_be_string"))
    entity_ids={e.get("entity_id") for e in bundle.get("entities",[]) if isinstance(e,dict) and isinstance(e.get("entity_id"),str)}
    for i, ent in enumerate(bundle.get("entities", [])):
        for j, rel in enumerate(ent.get("relations", [])):
            if isinstance(rel.get("target"),str) and rel["target"] not in entity_ids:
                errors.append(_error("dangling_reference", "entities[{}].relations[{}].target".format(i,j), "unknown_entity"))
        for j, match in enumerate(ent.get("identity_matches", [])):
            if isinstance(match.get("other"),str) and match["other"] not in entity_ids:
                errors.append(_error("dangling_reference", "entities[{}].identity_matches[{}].other".format(i,j), "unknown_entity"))
    for i, assertion in enumerate(bundle.get("assertions", [])):
        if not isinstance(assertion.get("subject"),str) or not isinstance(assertion.get("scope_id"),str):
            errors.append(_error("invalid_bundle", "assertions[{}]".format(i), "assertion_references_must_be_strings"))
    for i, evidence in enumerate(bundle.get("evidence", [])):
        if not isinstance(evidence.get("scope_id"),str):
            errors.append(_error("invalid_bundle", "evidence[{}].scope_id".format(i), "scope_id_must_be_string"))
    for i, check in enumerate(bundle.get("input_checks", [])):
        if not isinstance(check.get("input"),str):
            errors.append(_error("invalid_bundle", "input_checks[{}].input".format(i), "input_id_must_be_string"))
    if any(e.code == "invalid_bundle" for e in errors):
        # The donor validator intentionally assumes structurally typed records.
        return errors
    for key in JUDGMENT_KEYS:
        if key in bundle:
            errors.append(_error("invalid_bundle", key, "derived_judgment_supplied"))
    for msg in validate_bundle(bundle):
        errors.append(_error("invalid_bundle", "bundle", msg))
    errors.extend(validate_discovery(bundle))
    return errors


def _validate_result_discovery(result, bundle, findings):
    """The result's discovery section must be the bundle's, plus verdicts that are exactly the findings of the assertions named."""
    expected = bundle.get("discovery")
    got = result.get("discovery")
    if expected is None:
        return [_error("invalid_result", "discovery", "discovery_not_in_bundle")] if got is not None else []
    if not isinstance(got, dict) or not isinstance(got.get("candidates"), list):
        return [_error("invalid_result", "discovery", "discovery_section_missing_or_malformed")]
    errors = []
    by = {f.get("assertion_id"): f for f in findings if isinstance(f, dict)}
    # the returned section keeps every submitted field (schema, inputs, counts, notes, ...); only the engine's derived fields are added
    keep = lambda d: {k: v for k, v in d.items() if k not in _DISCOVERY_DERIVED}
    if keep(got) != keep(expected):
        errors.append(_error("invalid_result", "discovery", "discovery_metadata_changed"))
    submitted, returned = expected.get("candidates", []), got["candidates"]
    bad = [i for i, c in enumerate(returned) if not isinstance(c, dict)]
    errors.extend(_error("invalid_result", "discovery.candidates[{}]".format(i), "candidate_not_object") for i in bad)
    if bad:
        return errors
    if len(submitted) != len(returned) or [c.get("candidate_id") for c in submitted] != [c.get("candidate_id") for c in returned]:
        errors.append(_error("invalid_result", "discovery.candidates", "candidate_set_changed"))
        return errors
    for i, (src, c) in enumerate(zip(submitted, returned)):
        path = "discovery.candidates[{}]".format(i)
        if {k: v for k, v in c.items() if k != "finding"} != src:
            errors.append(_error("invalid_result", path, "candidate_changed"))
        f, fnd = c.get("finding"), by.get(src.get("assertion_id"))
        if fnd is None:
            if f is not None:
                errors.append(_error("invalid_result", path + ".finding", "finding_without_assertion"))
            continue
        if not isinstance(f, dict) or not isinstance(f.get("rule_id"), str) or f["rule_id"] not in _RULES or f.get("state") not in _STATES:
            errors.append(_error("invalid_result", path + ".finding", "unknown_rule_or_state")); continue
        if f.get("state") != fnd.get("state") or f.get("rule_id") != fnd.get("rule_id"):
            errors.append(_error("invalid_result", path + ".finding", "finding_differs_from_assertion_finding"))
    return errors


def validate_result(result, *, context, bundle, artifacts=(), read_artifact=lambda _id: b""):
    errors = check_context(context)
    bundle_errors = prevalidate_bundle(bundle, context)
    errors.extend(bundle_errors)
    if bundle_errors:
        return sorted(errors, key=lambda e: (e.path, e.code, e.detail))
    art_errors, _, by_inventory = validate_artifacts(context, bundle, artifacts, read_artifact)
    errors.extend(art_errors)
    if not isinstance(result, dict):
        errors.append(_error("invalid_result", "$", "result_not_object")); return sorted(errors, key=lambda e:(e.path,e.code,e.detail))
    try:
        raw = json_bytes(result)
        if len(raw) > 32 * 1024 * 1024:
            errors.append(_error("size_limit", "$", "result_over_32_mib"))
    except (TypeError, ValueError, OverflowError):
        errors.append(_error("invalid_result", "$", "invalid_json")); return sorted(errors, key=lambda e:(e.path,e.code,e.detail))
    if result.get("schema") != "bombridge.result/2":
        errors.append(_error("unsupported_schema", "schema", "unsupported_result_schema"))
    try:
        expected_hash = hashlib.sha256(json_bytes(bundle)).hexdigest()
    except (TypeError, ValueError, OverflowError):
        errors.append(_error("invalid_bundle", "$", "invalid_json")); return sorted(errors, key=lambda e:(e.path,e.code,e.detail))
    if result.get("bundle_sha256") != expected_hash:
        errors.append(_error("invalid_result", "bundle_sha256", "bundle_digest_mismatch"))
    if result.get("capture") != bundle.get("capture"):
        errors.append(_error("invalid_result", "capture", "capture_changed"))
    if result.get("notice") != bundle.get("notice"):
        errors.append(_error("invalid_result", "notice", "notice_changed"))
    expected_checks = sorted(bundle.get("input_checks", []), key=lambda c: c.get("input", "") if isinstance(c, dict) else "")
    if result.get("input_checks") != expected_checks:
        errors.append(_error("invalid_result", "input_checks", "input_checks_changed"))
    rules = result.get("rules")
    findings = result.get("findings")
    if not isinstance(findings, list):
        errors.append(_error("invalid_result", "findings", "expected_array")); findings = []
    if not isinstance(rules, list) or any(not isinstance(r, dict) or not isinstance(r.get("rule_id"), str) or r.get("rule_id") not in _RULES for r in rules):
        errors.append(_error("invalid_result", "rules", "unknown_or_malformed_rule"))
    else:
        expected_base = ["model_identity.digest/2", "inventory_coverage.requirement_represented/1",
                         "crypto_attribution.operation_declared_in_cbom/2", "model_identity.declared_in_aibom/1"]
        ids = [r["rule_id"] for r in rules]
        used = {f.get("rule_id") for f in findings if isinstance(f, dict)}
        extras = [r for r in ("dependency_mapping.import_resolves_to_component/1", "crypto_attribution.operation_declared_in_cbom/3",
                              "crypto_attribution.operation_declared_in_cbom/4") if r in used]
        if ids != expected_base + extras:
            errors.append(_error("invalid_result", "rules", "rule_order_or_mapping_presence_mismatch"))
    assertions = bundle.get("assertions", [])
    if any(not isinstance(a, dict) or not isinstance(a.get("assertion_id"), str) for a in assertions):
        errors.append(_error("invalid_bundle", "assertions", "invalid_assertion_ids"))
        assertions = [a for a in assertions if isinstance(a, dict) and isinstance(a.get("assertion_id"), str)]
    input_ids = [a.get("assertion_id") for a in assertions if isinstance(a, dict)]
    finding_ids = [f.get("assertion_id") for f in findings if isinstance(f, dict)]
    if sorted(input_ids) != sorted(finding_ids) or len(finding_ids) != len(set(finding_ids)):
        errors.append(_error("invalid_result", "findings", "assertion_coverage_mismatch"))
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            errors.append(_error("invalid_result", "findings[{}]".format(i), "finding_not_object")); continue
        if f.get("rule_id") is not None and (not isinstance(f.get("rule_id"), str) or f.get("rule_id") not in _RULES):
            errors.append(_error("invalid_result", "findings[{}].rule_id".format(i), "unknown_rule"))
        if f.get("state") not in {"supported", "contradicted", "conflicting_evidence", "unverifiable"}:
            errors.append(_error("invalid_result", "findings[{}].state".format(i), "unknown_state"))
        if not isinstance(f.get("applicability"), dict) or f["applicability"].get("applicable") not in (True, False, None):
            errors.append(_error("invalid_result", "findings[{}].applicability".format(i), "invalid_applicability"))
        if not isinstance(f.get("assertion_id"), str) or f.get("assertion_id") not in input_ids:
            errors.append(_error("dangling_reference", "findings[{}].assertion_id".format(i), "unknown_assertion"))
        input_evidence_ids = {e.get("evidence_id") for e in bundle.get("evidence", []) if isinstance(e, dict)}
        for field in ("used_evidence", "excluded_evidence"):
            refs = f.get(field)
            if not isinstance(refs, list):
                errors.append(_error("invalid_result", "findings[{}].{}".format(i, field), "expected_array")); continue
            if any(not isinstance(ref, dict) or ref.get("evidence_id") not in input_evidence_ids for ref in refs):
                errors.append(_error("dangling_reference", "findings[{}].{}".format(i, field), "unknown_evidence"))
    graph = result.get("graph")
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        errors.append(_error("invalid_result", "graph", "invalid_graph")); graph={"nodes":[],"edges":[]}
    node_ids=[]
    for n in graph["nodes"]:
        if not isinstance(n,dict) or not isinstance(n.get("id"),str):
            errors.append(_error("invalid_result", "graph.nodes", "invalid_node")); continue
        node_ids.append(n["id"])
    if len(node_ids)!=len(set(node_ids)):
        errors.append(_error("invalid_result", "graph.nodes", "duplicate_id"))
    edge_ids=[]
    for e in graph["edges"]:
        if not isinstance(e,dict) or not all(isinstance(e.get(k),str) for k in ("from","to","key")):
            errors.append(_error("invalid_result", "graph.edges", "invalid_edge")); continue
        edge_ids.append((e["from"],e["to"],e["key"]))
        if e["from"] not in node_ids or e["to"] not in node_ids:
            errors.append(_error("dangling_reference", "graph.edges", "dangling_endpoint"))
    if len(edge_ids)!=len(set(edge_ids)):
        errors.append(_error("invalid_result", "graph.edges", "duplicate_edge"))
    valid_refs={"entity:"+str(e.get("entity_id")) for e in bundle.get("entities",[]) if isinstance(e,dict)} | {"assertion:"+str(a.get("assertion_id")) for a in assertions if isinstance(a,dict)} | {"evidence:"+str(e.get("evidence_id")) for e in bundle.get("evidence",[]) if isinstance(e,dict)}
    if set(node_ids)-valid_refs:
        errors.append(_error("dangling_reference", "graph.nodes", "unknown_domain_record"))
    if set(node_ids) != valid_refs:
        errors.append(_error("invalid_result", "graph.nodes", "domain_node_coverage_mismatch"))
    capture = bundle.get("capture", {})
    inventory_ids = {i.get("inventory_id") for i in capture.get("inventories", []) if isinstance(i, dict)} if isinstance(capture, dict) else set()
    evidence_ids = {e.get("evidence_id") for e in bundle.get("evidence", []) if isinstance(e, dict)}
    links = result.get("inventory_links", [])
    if not isinstance(links, list):
        errors.append(_error("invalid_result", "inventory_links", "expected_array")); links = []
    for i, link in enumerate(links):
        if not isinstance(link, dict) or not isinstance(link.get("between"), list) or any(not isinstance(x,str) or x not in inventory_ids for x in link.get("between", [])):
            errors.append(_error("dangling_reference", "inventory_links[{}].between".format(i), "unknown_inventory")); continue
        if link.get("kind") == "shared_scan_paths" and link.get("connects_records") is not False:
            errors.append(_error("invalid_result", "inventory_links[{}]".format(i), "scope_link_must_not_connect_records"))
        link_evidence=link.get("evidence",[])
        if not isinstance(link_evidence,list) or any(not isinstance(e,str) or e not in evidence_ids for e in link_evidence):
            errors.append(_error("dangling_reference", "inventory_links[{}].evidence".format(i), "unknown_evidence"))
    errors.extend(_validate_result_discovery(result, bundle, findings))
    for edge in graph["edges"]:
        if isinstance(edge,dict) and edge.get("type") not in {"subject","object","assesses","excluded_from","observes","candidate_match","declared_as","identity_match","dependency","relationship"}:
            # Donor relationship labels are data; only reference resolution is enforced here.
            pass
    return sorted(errors, key=lambda e:(e.path,e.code,e.detail))
