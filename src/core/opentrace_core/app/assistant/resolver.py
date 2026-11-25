"""Bounded server-side evidence normalization for a single frozen assistant turn.

The caller supplies projections created from an authorized active analysis, never
browser-provided evidence. This module deliberately treats a missing or failed
projection as uncertainty rather than as an empty successful result.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping


MAX_ENTRIES = 24
MAX_ENTRY_BYTES = 2_048
MAX_TOTAL_EXCERPT_BYTES = 32_768
VALID_STATES = {"completed", "completed_empty", "not_run", "unavailable", "failed",
                "partial", "unsupported", "not_compared"}
COMPARISON_FAMILIES = {"bom", "model_correspondence", "candidate_gaps", "model_observations"}
ALLOWED_SOURCES = {"repository", "dependencies", "advisories", "crypto", "model_observations",
                   "model_correspondence", "candidate_gaps", "bom", "relationships"}
SOURCE_CONTRACTS = {
    "repository": "opentrace.workbench.contexts/1",
    "dependencies": "opentrace.workbench.dependency_page/1",
    "advisories": "opentrace.workbench.dependency_page/1",
    "crypto": "opentrace.workbench.crypto_assets/1",
    "model_observations": "opentrace.workbench.ai_assets/1",
    "model_correspondence": "opentrace.workbench.bom_candidates/1",
    "candidate_gaps": "opentrace.bombridge_assessment/1",
    "bom": "opentrace.workbench.bom_candidates/1",
    "relationships": "opentrace.workbench.bom_graph/1",
}
EMPTY_PROOFS = {
    "repository": None,
    "dependencies": "validated_assessment_zero_components",
    "advisories": "advisory_lookup_completed_zero_results",
    "crypto": "validated_assessment_zero_crypto_assets",
    "model_observations": "stage3_model_collection_completed_empty",
    "model_correspondence": "stage3_model_comparison_completed_empty",
    "candidate_gaps": "stage3_gap_comparison_completed_empty",
    "bom": "validated_bom_projection_zero_candidates",
    "relationships": "validated_bom_graph_zero_relationships",
}
_SESSION_ID = re.compile(r"^[0-9a-f]{32}$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA64 = re.compile(r"^[0-9a-f]{64}$")
_ANALYSIS_DIGEST = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")


class EvidenceResolutionError(ValueError):
    """The server-owned evidence packet could not be safely bound or normalized."""


@dataclass(frozen=True)
class ResolvedEvidence:
    evidence_id: str
    source: str
    kind: str
    state: str
    label: str
    excerpt: str
    locator: str


@dataclass(frozen=True)
class ResolvedContext:
    context_id: str
    binding_digest: str
    subject: Mapping[str, Any] | None
    sources: Mapping[str, Mapping[str, Any]]
    evidence: tuple[ResolvedEvidence, ...]
    limitations: tuple[str, ...]

    @property
    def permitted_evidence_ids(self) -> frozenset[str]:
        return frozenset(item.evidence_id for item in self.evidence)

    def citation(self, evidence_id: str) -> ResolvedEvidence:
        for item in self.evidence:
            if item.evidence_id == evidence_id:
                return item
        raise EvidenceResolutionError("citation is outside frozen context")


def resolve_turn_evidence(*, binding: Mapping[str, Any], context_id: str,
                          projections: Mapping[str, Mapping[str, Any]],
                          subject: Mapping[str, Any] | None = None) -> ResolvedContext:
    """Normalize trusted Workbench projection packets for one immutable turn.

    Each trusted projection packet has `{state, contract_id, binding_digest,
    entries, reason_code, completion_proof}`. Its exact source contract ID must
    match `SOURCE_CONTRACTS`. The server adapter must validate the actual Workbench
    projection/assessment before constructing this packet. `completed_empty` is
    accepted only with the source-specific proof token in `EMPTY_PROOFS`; a generic
    empty page or a bare caller-supplied state cannot establish it.
    `entries` contains `{record_id, kind, label, excerpt, locator, binding_digest}`.
    Locators are opaque server-owned keys; callers re-resolve them when a citation
    is opened. A Stage 3 `not_compared` or failed comparison suppresses all
    comparison-derived BOM/model-correspondence entries regardless of empty pages.
    Independently observed model-reference entries may be passed under the
    separate `model_observations` source when the comparison is healthy. A
    failed whole Stage 3 comparison suppresses that family as unknown/unavailable
    too; current Stage 3 does not expose model-reference identities on this path.
    """
    if not isinstance(binding, Mapping) or not isinstance(context_id, str) or not context_id:
        raise EvidenceResolutionError("active analysis binding required")
    repo = binding.get("repository")
    if (not isinstance(binding.get("session_id"), str) or not _SESSION_ID.fullmatch(binding["session_id"])
            or not isinstance(binding.get("generation"), int) or isinstance(binding.get("generation"), bool)
            or binding["generation"] < 1
            or not isinstance(binding.get("analysis_digest"), str)
            or not _ANALYSIS_DIGEST.fullmatch(binding["analysis_digest"])
            or not isinstance(binding.get("commit_sha"), str) or not _SHA40.fullmatch(binding["commit_sha"])
            or not isinstance(repo, Mapping)
            or not all(isinstance(repo.get(key), str) and repo.get(key) for key in
                       ("host", "owner", "name", "canonical_url"))):
        raise EvidenceResolutionError("session-bound active analysis identity required")
    binding_digest = _binding_digest(binding)
    if len(context_id.encode("utf-8")) > 96:
        raise EvidenceResolutionError("context identifier too long")
    frozen_subject = _normalize_subject(subject, binding_digest) if subject is not None else None

    normalized: dict[str, dict[str, Any]] = {}
    entries: list[ResolvedEvidence] = []
    limitations: list[str] = []
    # The user's explicitly adopted subject must get first opportunity within
    # the shared bounded evidence list. Source-local sorting alone is not
    # sufficient: alphabetically earlier sources can consume the entire detail
    # budget before the selected source is visited.
    subject_source = ({"context": "repository", "dependency": "dependencies",
                       "advisory": "advisories", "crypto": "crypto",
                       "model": "model_observations", "bom": "bom",
                       "relationship": "relationships"}.get(frozen_subject.get("kind"))
                      if frozen_subject else None)
    source_order = sorted(projections)
    if subject_source in source_order:
        source_order.remove(subject_source)
        source_order.insert(0, subject_source)
    for source in source_order:
        packet = projections[source]
        if not isinstance(source, str) or source not in ALLOWED_SOURCES or not isinstance(packet, Mapping):
            raise EvidenceResolutionError("invalid projection packet")
        state = packet.get("state")
        if state not in VALID_STATES:
            raise EvidenceResolutionError("invalid projection state")
        if packet.get("contract_id") != SOURCE_CONTRACTS[source]:
            raise EvidenceResolutionError("projection contract mismatch")
        packet_binding = packet.get("binding_digest")
        if packet_binding != binding_digest:
            state = "failed"
            reason_code = "binding_mismatch"
            source_entries = []
            limitations.append(source + ": source binding changed; evidence excluded")
        else:
            reason_code = _safe_reason(packet.get("reason_code"))
            source_entries = packet.get("entries", [])
            if not isinstance(source_entries, list):
                state, reason_code, source_entries = "failed", "projection_invalid", []
            if state in {"not_run", "unavailable", "failed", "unsupported", "not_compared"} and source_entries:
                # Non-success states may expose independent observations only through
                # their own source packet; never treat a candidate page as complete.
                state, reason_code, source_entries = "failed", "state_entries_conflict", []
            elif state == "completed_empty" and source_entries:
                state, reason_code, source_entries = "failed", "empty_state_with_entries", []
            elif state == "completed_empty" and (EMPTY_PROOFS[source] is None
                                                   or packet.get("completion_proof") != EMPTY_PROOFS[source]):
                state, reason_code = "failed", "empty_success_unproven"
            elif state == "completed" and not source_entries:
                # An empty page is not proof of a completed negative lookup.
                state, reason_code = "failed", "empty_success_unproven"
        normalized[source] = {"state": state, "reason_code": reason_code,
                              "entry_count": 0, "truncated": False}
        if state not in {"completed", "completed_empty", "partial"}:
            limitations.append(_state_limitation(source, state, reason_code))
            continue

        # Stable server-side order makes truncation reproducible. IDs are scoped to
        # this context and never contain source paths or provider-controlled text.
        wanted_id = frozen_subject.get("id") if frozen_subject else None
        def prioritized(row):
            locator = row.get("locator") if isinstance(row, Mapping) else None
            record_id = row.get("record_id") if isinstance(row, Mapping) else None
            selected = bool(wanted_id and (record_id == wanted_id or
                                           (isinstance(locator, str) and locator.endswith(":" + wanted_id))))
            return (0 if selected else 1, _entry_sort_key(row))
        ordered = sorted(source_entries, key=prioritized)
        accepted = 0
        for row in ordered:
            if len(entries) >= MAX_ENTRIES:
                normalized[source]["truncated"] = True
                break
            item = _normalize_entry(source, row, binding_digest, state)
            excerpt_bytes = len(item.excerpt.encode("utf-8"))
            used = sum(len(existing.excerpt.encode("utf-8")) for existing in entries)
            if excerpt_bytes > MAX_ENTRY_BYTES:
                item = ResolvedEvidence(item.evidence_id, item.source, item.kind, item.state,
                                        item.label, _truncate_utf8(item.excerpt, MAX_ENTRY_BYTES), item.locator)
                excerpt_bytes = len(item.excerpt.encode("utf-8"))
                normalized[source]["truncated"] = True
            if used + excerpt_bytes > MAX_TOTAL_EXCERPT_BYTES:
                normalized[source]["truncated"] = True
                break
            if any(existing.evidence_id == item.evidence_id for existing in entries):
                raise EvidenceResolutionError("duplicate evidence identity")
            entries.append(item)
            accepted += 1
        normalized[source]["entry_count"] = accepted
        if normalized[source]["truncated"]:
            limitations.append(source + ": evidence was deterministically truncated")
        if state == "partial":
            limitations.append(_state_limitation(source, state, reason_code))

    for source in ALLOWED_SOURCES - normalized.keys():
        normalized[source] = {"state": "unavailable", "reason_code": "projection_not_resolved",
                              "entry_count": 0, "truncated": False}
        limitations.append(_state_limitation(source, "unavailable", "projection_not_resolved"))

    gaps = normalized.get("candidate_gaps")
    if gaps is None:
        gaps = {"state": "unavailable", "reason_code": "comparison_state_missing",
                "entry_count": 0, "truncated": False}
        normalized["candidate_gaps"] = gaps
        limitations.append(_state_limitation("candidate_gaps", gaps["state"], gaps["reason_code"]))
    if gaps["state"] in {"failed", "unavailable", "not_run", "unsupported", "not_compared"}:
        for source in COMPARISON_FAMILIES - {"candidate_gaps"}:
            if source in normalized:
                # A comparison-dependent positive result is invalid unless the
                # candidate-gap projection proves the same comparison completed.
                normalized[source] = {"state": "not_compared", "reason_code": gaps["reason_code"] or "comparison_failed",
                                      "entry_count": 0, "truncated": False}
                entries = [item for item in entries if item.source != source]
                limitations.append(_state_limitation(source, "not_compared", gaps["reason_code"] or "comparison_failed"))

    # Reserve one citation for each source-state record so claims about missing,
    # partial or failed evidence can cite the server's actual state. Detailed
    # evidence is deterministically capped to make room within the same 24-entry
    # total. These records describe coverage only; they are not findings.
    state_entries = []
    for source in sorted(normalized):
        state = normalized[source]
        state_value = {"state": state["state"], "reason_code": state["reason_code"],
                       "entry_count": state["entry_count"], "truncated": state["truncated"]}
        state_entries.append(_normalize_entry(source, {
            "record_id": "__assistant_source_state__:" + source,
            "kind": "source_state", "label": source.replace("_", " ") + " evidence coverage",
            "excerpt": json.dumps(state_value, sort_keys=True, separators=(",", ":")), "locator": "source_state:" + source,
            "binding_digest": binding_digest}, binding_digest, state["state"]))
    detail_limit = max(0, MAX_ENTRIES - len(state_entries))
    if len(entries) > detail_limit:
        omitted = entries[detail_limit:]
        entries = entries[:detail_limit]
        for source in {item.source for item in omitted}:
            normalized[source]["truncated"] = True
            limitations.append(source + ": evidence was deterministically truncated")
        # State citations include the final truncation flags and detail counts.
        state_entries = []
        for source in sorted(normalized):
            state = normalized[source]
            retained_count = len([e for e in entries if e.source == source])
            normalized[source]["entry_count"] = retained_count
            state_value = {"state": state["state"], "reason_code": state["reason_code"],
                           "entry_count": retained_count,
                           "truncated": state["truncated"]}
            state_entries.append(_normalize_entry(source, {
                "record_id": "__assistant_source_state__:" + source,
                "kind": "source_state", "label": source.replace("_", " ") + " evidence coverage",
                "excerpt": json.dumps(state_value, sort_keys=True, separators=(",", ":")), "locator": "source_state:" + source,
                "binding_digest": binding_digest}, binding_digest, state["state"]))

    frozen_sources = MappingProxyType({key: MappingProxyType(dict(value)) for key, value in normalized.items()})
    return ResolvedContext(context_id=context_id, binding_digest=binding_digest,
                           subject=MappingProxyType(dict(frozen_subject)) if frozen_subject is not None else None,
                           sources=frozen_sources, evidence=tuple(state_entries + entries),
                           limitations=tuple(dict.fromkeys(limitations)))


def resolve_active_analysis(analysis: Any, *, context_id: str,
                            subject: Mapping[str, Any] | None = None) -> ResolvedContext:
    """Build bounded evidence from validated server-side Workbench projectors.

    This function accepts only the active in-memory analysis object selected by
    the authenticated Workbench handler. It does not accept request summaries or
    caller-provided projection packets. Existing response builders validate each
    projection against its frozen Workbench contract before data is normalized.
    Session/generation liveness must still be checked by the HTTP handler after
    the provider round trip.
    """
    from opentrace_core.app import ai_assets, context_groups, crypto_assets, dependency_pages, view_contracts
    from opentrace_core.app.workbench_binding import build_binding

    ticket = getattr(analysis, "ticket", None)
    views = getattr(analysis, "views", None)
    if (ticket is None or not getattr(ticket, "session_id", None)
            or not isinstance(getattr(ticket, "generation", None), int)
            or getattr(analysis, "state", None) != "complete" or views is None):
        raise EvidenceResolutionError("active completed analysis required")
    workbench_binding = build_binding(analysis)
    binding = dict(workbench_binding, session_id=ticket.session_id)
    generation = ticket.generation
    binding_digest = _binding_digest(binding)

    def row(source: str, record_id: str, kind: str, label: str,
            value: Any, locator: str) -> dict[str, Any]:
        if not isinstance(value, str):
            value = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        return {"record_id": record_id, "kind": kind, "label": label, "excerpt": value,
                "locator": locator, "binding_digest": binding_digest}

    packets: dict[str, dict[str, Any]] = {}
    identity = {key: binding[key] for key in ("repository", "commit_sha", "requested_ref", "mode", "generation")}
    repo_rows = [row("repository", "analysis-identity", "analysis_identity",
                     "Admitted repository and resolved revision", identity, "analysis_binding")]
    repository_state, repository_reason = "completed", None
    contexts = None
    try:
        contexts = context_groups.respond(analysis, {"generation": generation, "files_limit": 1})
        view_contracts.validate_payload("contexts", contexts, request={"generation": generation},
                                        expected_binding=workbench_binding)
        _assert_payload_binding(contexts, workbench_binding)
        root = contexts["root"]
        repo_rows.append(row("repository", "repository-inventory-summary", "repository_inventory_summary",
                             "Recorded repository inventory scope",
                             {key: root[key] for key in ("distinct_total", "located_distinct_total", "unlocated_total")},
                             "repository_inventory_summary"))
        requested_subject = subject if isinstance(subject, Mapping) else None
        if requested_subject and requested_subject.get("kind") == "context":
            requested_id = requested_subject.get("id")
            model = context_groups.model_for(analysis)
            for group in model.layout(workbench_binding["analysis_digest"]):
                if group.group_id == requested_id:
                    repo_rows.append(row("repository", group.group_id, "repository_context_group", group.label,
                                         {"kind": group.kind, "category": group.category,
                                          "distinct_total": group.distinct, "membership_total": group.membership},
                                         "context_group:" + group.group_id))
                    break
                selected_file = next((item for item in group.files if item["file_id"] == requested_id), None)
                if selected_file:
                    path_label = _truncate_utf8(selected_file["path"], 256)
                    repo_rows.append(row("repository", selected_file["file_id"], "repository_context_file",
                                         path_label, {"path": selected_file["path"],
                                         "distinct_total": len(selected_file["members"]),
                                         "normalization_basis": sorted(set(selected_file["basis"]))},
                                         "context_file:" + selected_file["file_id"]))
                    break
    except view_contracts.ContractError as exc:
        _, repository_reason = _projection_error_state(exc)
        repository_state = "partial"
    packets["repository"] = _trusted_packet("repository", repository_state, binding_digest,
                                            repo_rows if repository_state == "completed" else repo_rows[:1],
                                            repository_reason)

    # Dependency context selection and package pages are produced by the same
    # validated projectors used by the existing Workbench routes.
    dependency_rows: list[dict[str, Any]] = []
    advisory_rows: list[dict[str, Any]] = []
    dependency_state, dependency_reason = "not_run", "no_dependency_projection"
    advisory_state, advisory_reason = "not_run", "lookup_not_run"
    try:
        chooser = dependency_pages.respond_contexts(analysis, {"generation": generation})
        dependency_pages.validate_contexts_payload(chooser)
        _assert_payload_binding(chooser, workbench_binding)
        pages = []
        # A clicked package must be resolved from the authorized Workbench data BEFORE any broader context: the default page of a context shows only a
        # bounded slice of its packages, so a package outside that slice (qs, @faker-js/faker, js-yaml in docs/package-lock.json) used to be "unavailable".
        # Look the package up in each context's own graph and read the page focused on it; its records then go first.
        focused = []
        asked = subject if isinstance(subject, Mapping) else None
        want = asked.get("id") if asked and asked.get("kind") == "dependency" else None
        if isinstance(want, str) and want:
            for crow in dependency_pages._chooser_rows(analysis):
                graph, _mode = dependency_pages._graph_for(analysis, crow["path"])
                if want in graph.nodes:
                    focused.append(dependency_pages.respond(analysis, {"generation": generation, "context_id": crow["context_id"],
                                                                       "schema_version": 1, "focus_id": want}))
                    break
        for page in focused:
            _assert_payload_binding(page, workbench_binding)
            pages.append(page)
            for node in page["nodes"]:
                rid = page["context"]["context_id"] + ":" + node["node_id"]
                label = "{} {}".format(node.get("name") or "Package", node.get("version") or "").strip()
                dependency_rows.append(row("dependencies", rid, "dependency_observation", label, node,
                                           "dependency:" + rid))
                lookup = node.get("advisory_lookup")
                advisory_rows.append(row("advisories", rid, "advisory_lookup_state", label,
                                         {"state": lookup, "match_count": node.get("advisory_match_count"),
                                          "has_source_location": node.get("has_source_location")},
                                         "dependency:" + rid))
        seen_rids = {r["record_id"] for r in dependency_rows}
        for context in chooser["rows"]:
            page = dependency_pages.respond(analysis, {"generation": generation, "context_id": context["context_id"],
                                                       "schema_version": 1})
            _assert_payload_binding(page, workbench_binding)
            pages.append(page)
            for node in page["nodes"]:
                rid = context["context_id"] + ":" + node["node_id"]
                if rid in seen_rids:
                    continue
                label = "{} {}".format(node.get("name") or "Package", node.get("version") or "").strip()
                dependency_rows.append(row("dependencies", rid, "dependency_observation", label, node,
                                           "dependency:" + context["context_id"] + ":" + node["node_id"]))
                lookup = node.get("advisory_lookup")
                advisory_rows.append(row("advisories", rid, "advisory_lookup_state", label,
                                         {"state": lookup, "match_count": node.get("advisory_match_count"),
                                          "has_source_location": node.get("has_source_location")},
                                         "dependency:" + context["context_id"] + ":" + node["node_id"]))
        if dependency_rows:
            dependency_state, dependency_reason = "completed", None
        elif contexts and contexts["root"]["distinct_total"] == 0:
            dependency_state, dependency_reason = "completed_empty", None
        else:
            dependency_state, dependency_reason = "not_run", "no_dependency_contexts"
        if chooser["counts"]["truncated"] or any(page["page"]["has_more"] for page in pages):
            dependency_state, dependency_reason = "partial", "projection_page_truncated"
        modes = {page["lookup"]["mode"] for page in pages}
        if not pages or modes == {"off"}:
            advisory_state, advisory_reason, advisory_rows = "not_run", "lookup_not_run", []
        elif any(item.get("advisory_lookup") in {"not_run", "unavailable", "missing_version", "unsupported"}
                 for page in pages for item in page["nodes"]):
            advisory_state, advisory_reason = "partial", "lookup_incomplete"
        else:
            advisory_state, advisory_reason = "completed", None
    except view_contracts.ContractError as exc:
        dependency_state, dependency_reason = _projection_error_state(exc)
        advisory_state, advisory_reason = dependency_state, dependency_reason
        dependency_rows, advisory_rows = [], []
    packets["dependencies"] = _trusted_packet("dependencies", dependency_state, binding_digest,
                                              dependency_rows, dependency_reason,
                                              EMPTY_PROOFS["dependencies"] if dependency_state == "completed_empty" else None)
    packets["advisories"] = _trusted_packet("advisories", advisory_state, binding_digest,
                                            advisory_rows, advisory_reason)

    # Family payloads carry explicit availability states; a zero-row page is
    # completed-empty only when that validated source state says so.
    for source, module in (("crypto", crypto_assets), ("model_observations", ai_assets)):
        try:
            payload = module.respond(analysis, {"generation": generation, "schema_version": 1})
            _assert_payload_binding(payload, workbench_binding)
            state = payload["availability"]["state"]
            reason = payload["availability"].get("reason_code")
            items = payload["assets"]
            rows = [row(source, item.get("asset_id") or item.get("asset_id", str(i)),
                        "crypto_asset" if source == "crypto" else "ai_inventory_model",
                        item.get("display_name") or item.get("label") or item.get("name") or "Recorded asset",
                        _with_summary(item), source + ":" + str(item.get("asset_id") or i))
                    for i, item in enumerate(items)]
            if payload["counts"]["truncated"]:
                state, reason = "partial", "projection_page_truncated"
            proof = EMPTY_PROOFS[source] if state == "completed_empty" else None
            packets[source] = _trusted_packet(source, state, binding_digest, rows, reason, proof)
        except view_contracts.ContractError as exc:
            state, reason = _projection_error_state(exc)
            packets[source] = _trusted_packet(source, state, binding_digest, [], reason)

    gaps = getattr(analysis, "gaps", None)
    if not isinstance(gaps, dict):
        packets["candidate_gaps"] = _trusted_packet("candidate_gaps", "unavailable", binding_digest, [],
                                                    "comparison_state_missing")
        packets["bom"] = _trusted_packet("bom", "unavailable", binding_digest, [], "comparison_state_missing")
        packets["model_correspondence"] = _trusted_packet("model_correspondence", "unavailable", binding_digest, [],
                                                          "comparison_state_missing")
    elif gaps.get("status") != "compared":
        reason = _safe_reason(gaps.get("code")) or "comparison_not_compared"
        packets["candidate_gaps"] = _trusted_packet("candidate_gaps", "not_compared", binding_digest, [], reason)
        packets["bom"] = _trusted_packet("bom", "not_compared", binding_digest, [], reason)
        packets["model_correspondence"] = _trusted_packet("model_correspondence", "not_compared", binding_digest, [], reason)
        packets["relationships"] = _trusted_packet("relationships", "not_compared", binding_digest, [], reason)
    else:
        try:
            gap_payload = views.gaps(0, None, None, "")
            _validate_gaps_projection(gap_payload, analysis, workbench_binding)
            gap_rows = [row("candidate_gaps", item["candidate_id"], "candidate_gap",
                             item.get("title") or item.get("category") or "Candidate gap", item,
                             "candidate_gap:" + item["candidate_id"]) for item in gap_payload.get("items", [])]
            gap_state = "completed_empty" if not gap_rows and not gap_payload.get("has_more") else "completed"
            if gap_payload.get("has_more"):
                gap_state = "partial"
            gap_proof = EMPTY_PROOFS["candidate_gaps"] if gap_state == "completed_empty" else None
            packets["candidate_gaps"] = _trusted_packet("candidate_gaps", gap_state, binding_digest,
                                                        gap_rows, None, gap_proof)
            bom_payload = views.bom_candidates()
            view_contracts.validate_payload("bom_candidates", bom_payload,
                                            request={"generation": generation},
                                            expected_binding=workbench_binding)
            bom_items = bom_payload["items"]
            bom_state = "completed_empty" if not bom_items and not bom_payload["page"]["has_more"] else "completed"
            if bom_payload["page"]["has_more"]:
                bom_state = "partial"
            bom_proof = EMPTY_PROOFS["bom"] if bom_state == "completed_empty" else None
            packets["bom"] = _trusted_packet("bom", bom_state, binding_digest,
                                              [row("bom", item["item_id"], "bom_candidate",
                                                   item.get("display", {}).get("name") or "BOM candidate", item,
                                                   "bom:" + item["item_id"]) for item in bom_items], None, bom_proof)
            model_items = [item for item in bom_items if item.get("family") == "ai_model"]
            model_capability = next((item for item in bom_payload["capabilities"] if item.get("family") == "ai_model"), None)
            if model_capability is None:
                model_state, model_reason = "unavailable", "model_capability_missing"
            else:
                model_state = model_capability.get("state")
                model_reason = model_capability.get("reason_code")
                if model_state not in VALID_STATES:
                    model_state, model_reason = "failed", "model_capability_invalid"
                elif bom_payload["page"]["has_more"] and model_state in {"completed", "completed_empty"}:
                    model_state, model_reason = "partial", "projection_page_truncated"
                elif model_state == "completed_empty" and model_items:
                    model_state, model_reason = "failed", "model_capability_entries_conflict"
                elif model_state == "completed" and not model_items:
                    model_state, model_reason = "failed", "model_capability_entries_conflict"
            model_proof = EMPTY_PROOFS["model_correspondence"] if model_state == "completed_empty" else None
            packets["model_correspondence"] = _trusted_packet("model_correspondence", model_state, binding_digest,
                                                              [row("model_correspondence", item["item_id"],
                                                                   "model_bom_candidate",
                                                                   item.get("display", {}).get("name") or "Model correspondence",
                                                                   item, "bom:" + item["item_id"])
                                                               for item in model_items] if model_state in {"completed", "partial"} else [],
                                                              model_reason, model_proof)
            # Relationships come from the existing validated full-view graph
            # projector. Its empty no-task state is explicitly not-run; an
            # empty validated assertion/evidence graph is completed-empty.
            try:
                graph_payload = views.bom_graph(scope_kind="full_view", offset=0)
                view_contracts.validate_payload(
                    "bom_graph", graph_payload,
                    request={"generation": generation, "scope_kind": "full_view", "offset": 0},
                    expected_binding=workbench_binding)
                graph_state = graph_payload["graph_state"]
                if graph_state == "no_graph_collection_task":
                    packets["relationships"] = _trusted_packet(
                        "relationships", "not_run", binding_digest, [], "graph_collection_not_run")
                elif graph_state == "not_compared":
                    packets["relationships"] = _trusted_packet(
                        "relationships", "not_compared", binding_digest, [], "graph_not_compared")
                else:
                    graph_rows = [row(
                        "relationships", edge["edge_id"], "bom_relationship",
                        edge.get("label") or edge.get("kind") or "Recorded BOM relationship", edge,
                        "bom_graph:" + edge["edge_id"])
                        for edge in graph_payload["edges"]]
                    relation_state = "completed" if graph_rows else "completed_empty"
                    relation_reason = None
                    proof = EMPTY_PROOFS["relationships"] if not graph_rows else None
                    if graph_payload["page"] and graph_payload["page"]["has_more"]:
                        relation_state, relation_reason, proof = "partial", "projection_page_truncated", None
                    packets["relationships"] = _trusted_packet(
                        "relationships", relation_state, binding_digest, graph_rows, relation_reason, proof)
            except Exception as exc:
                _, relation_reason = _projection_error_state(exc)
                packets["relationships"] = _trusted_packet(
                    "relationships", "failed", binding_digest, [], relation_reason)
        except Exception as exc:
            _, reason = _projection_error_state(exc)
            packets["candidate_gaps"] = _trusted_packet("candidate_gaps", "failed", binding_digest, [],
                                                        reason)
            packets["bom"] = _trusted_packet("bom", "failed", binding_digest, [], reason)
            packets["model_correspondence"] = _trusted_packet("model_correspondence", "failed", binding_digest,
                                                              [], reason)
            packets["relationships"] = _trusted_packet("relationships", "not_compared", binding_digest, [], reason)

    return resolve_turn_evidence(binding=binding, context_id=context_id, projections=packets, subject=subject)


def _trusted_packet(source: str, state: str, binding_digest: str, rows: list[dict[str, Any]],
                    reason_code: str | None = None, completion_proof: str | None = None) -> dict[str, Any]:
    return {"state": state, "contract_id": SOURCE_CONTRACTS[source], "binding_digest": binding_digest,
            "entries": rows, "reason_code": reason_code, "completion_proof": completion_proof}


def _assert_payload_binding(payload: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    if payload.get("binding") != expected:
        raise EvidenceResolutionError("projected evidence binding mismatch")


def _validate_gaps_projection(payload: Any, analysis: Any, expected: Mapping[str, Any]) -> None:
    """Validate the non-Workbench candidate-gap projector before using its rows."""
    if not isinstance(payload, Mapping) or payload.get("status") != "compared":
        raise EvidenceResolutionError("candidate-gap projection is not compared")
    assessment = getattr(analysis, "gaps", {}).get("assessment")
    source_binding = getattr(assessment, "binding", None)
    projected_binding = payload.get("binding")
    workbench_assessment = expected.get("assessment")
    if (getattr(assessment, "schema", None) != "opentrace.bombridge_assessment/1"
            or not isinstance(source_binding, Mapping) or projected_binding != source_binding
            or not isinstance(workbench_assessment, Mapping)
            or source_binding.get("analysis_digest") != expected.get("analysis_digest")
            or source_binding.get("session_id") != getattr(analysis.ticket, "session_id", None)
            or source_binding.get("generation") != expected.get("generation")
            or source_binding.get("bundle_sha256") != workbench_assessment.get("bundle_sha256")
            or getattr(assessment, "validation_digest", None) != workbench_assessment.get("validation_digest")):
        raise EvidenceResolutionError("candidate-gap projection binding mismatch")
    items = payload.get("items")
    totals = payload.get("totals")
    filtered_total, offset, limit, has_more = (payload.get(key) for key in ("filtered_total", "offset", "limit", "has_more"))
    if (not isinstance(items, list) or len(items) > 25 or not isinstance(totals, Mapping)
            or type(filtered_total) is not int or filtered_total < 0 or type(offset) is not int or offset != 0
            or type(limit) is not int or limit != 25 or type(has_more) is not bool
            or type(totals.get("candidates")) is not int or totals["candidates"] < 0
            or totals["candidates"] != filtered_total
            or len(items) != min(limit, filtered_total)
            or has_more != (offset + len(items) < filtered_total)):
        raise EvidenceResolutionError("candidate-gap projection shape invalid")
    ids = []
    for item in items:
        if not isinstance(item, Mapping) or not isinstance(item.get("candidate_id"), str) or not item["candidate_id"]:
            raise EvidenceResolutionError("candidate-gap projection row invalid")
        ids.append(item["candidate_id"])
    if len(ids) != len(set(ids)):
        raise EvidenceResolutionError("candidate-gap projection has duplicate rows")


def _projection_error_state(exc: Exception) -> tuple[str, str]:
    code = getattr(exc, "code", "projection_failed")
    if code == "no_analysis":
        return "unavailable", "no_active_analysis"
    if code == "not_found":
        return "not_run", "source_projection_not_available"
    if code == "stale_generation" or code == "binding_mismatch":
        return "failed", "binding_mismatch"
    return "failed", "projection_failed"


def _with_summary(item: Mapping[str, Any]) -> Any:
    """Asset records are serialized with sorted keys, so a long `attributes` object could push the identifying fields past the per-entry byte cap. A small `_summary` (which sorts
    first) repeats ONLY fields already in the record: its name, kind, whether it is an experimental source observation, how many places record it, and the first location."""
    if not isinstance(item, Mapping):
        return item
    occs = item.get("occurrences") if isinstance(item.get("occurrences"), list) else []
    first = occs[0] if occs and isinstance(occs[0], Mapping) else {}
    loc = first.get("source_location") if isinstance(first.get("source_location"), Mapping) else {}
    prov = item.get("provenance") if isinstance(item.get("provenance"), Mapping) else {}
    summary = {"name": item.get("display_name"), "kind": item.get("kind"), "experimental": bool(prov.get("experimental")),
               "places": item.get("occurrences_total") if isinstance(item.get("occurrences_total"), int) else len(occs),
               "path": loc.get("path"), "line": loc.get("line_start"), "operation": first.get("operation")}
    return {**item, "_summary": {k: v for k, v in summary.items() if v is not None}}


def _normalize_entry(source: str, row: Any, binding_digest: str, source_state: str) -> ResolvedEvidence:
    if not isinstance(row, Mapping) or row.get("binding_digest") != binding_digest:
        raise EvidenceResolutionError("evidence row binding mismatch")
    record_id = row.get("record_id")
    kind, label, excerpt, locator = (row.get(key) for key in ("kind", "label", "excerpt", "locator"))
    if not all(isinstance(value, str) and value for value in (record_id, kind, label, excerpt, locator)):
        raise EvidenceResolutionError("evidence row invalid")
    if any(len(value.encode("utf-8")) > maximum for value, maximum in
           ((record_id, 256), (kind, 64), (label, 256), (locator, 512))):
        raise EvidenceResolutionError("evidence metadata exceeds limit")
    _inert_text(excerpt)
    evidence_id = "ev-" + hashlib.sha256((binding_digest + "\0" + source + "\0" + record_id).encode()).hexdigest()[:32]
    return ResolvedEvidence(evidence_id, source, kind, source_state, label, excerpt, locator)


def _binding_digest(binding: Mapping[str, Any]) -> str:
    try:
        raw = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise EvidenceResolutionError("invalid active analysis binding") from exc
    if len(raw) > 16_384:
        raise EvidenceResolutionError("active analysis binding exceeds limit")
    return hashlib.sha256(raw).hexdigest()


def _normalize_subject(subject: Mapping[str, Any], binding_digest: str) -> Mapping[str, Any]:
    if not isinstance(subject, Mapping) or set(subject) != {"kind", "id", "label", "binding_digest"}:
        raise EvidenceResolutionError("subject must be server-resolved")
    if subject.get("binding_digest") != binding_digest:
        raise EvidenceResolutionError("subject binding mismatch")
    kind, subject_id, label = subject.get("kind"), subject.get("id"), subject.get("label")
    if kind == "analysis":
        if subject_id is not None:
            raise EvidenceResolutionError("analysis subject identifier invalid")
    elif kind in {"context", "dependency", "advisory", "crypto", "model", "bom", "relationship"}:
        if not isinstance(subject_id, str) or not subject_id or len(subject_id.encode("utf-8")) > 256:
            raise EvidenceResolutionError("subject identifier invalid")
    else:
        raise EvidenceResolutionError("unsupported subject kind")
    if not isinstance(label, str) or not label or len(label.encode("utf-8")) > 256:
        raise EvidenceResolutionError("subject label invalid")
    _inert_text(label)
    return {"kind": kind, "id": subject_id, "label": label, "binding_digest": binding_digest}


def _entry_sort_key(row: Any) -> tuple[str, str]:
    if not isinstance(row, Mapping) or not isinstance(row.get("record_id"), str):
        raise EvidenceResolutionError("evidence row invalid")
    return row["record_id"], str(row.get("kind", ""))


def _safe_reason(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 96 or not value.replace("_", "").isalnum():
        return "source_reported_failure"
    return value


def _state_limitation(source: str, state: str, reason: str | None) -> str:
    suffix = " (" + reason + ")" if reason else ""
    return source + ": evidence state is " + state + suffix


def _inert_text(value: str) -> None:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EvidenceResolutionError("invalid evidence text") from exc
    if not encoded or any(ord(char) < 0x20 and char not in "\n\t" for char in value):
        raise EvidenceResolutionError("invalid evidence text")


def _truncate_utf8(value: str, byte_limit: int) -> str:
    encoded = value.encode("utf-8")[:byte_limit]
    while encoded:
        try:
            return encoded.decode("utf-8")
        except UnicodeDecodeError:
            encoded = encoded[:-1]
    return ""
