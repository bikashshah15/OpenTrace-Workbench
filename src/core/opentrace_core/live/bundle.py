"""Assemble the donor bundle, artifact records and acquisition manifests for one live analysis (I5).

Only what a collector actually produced is asserted: the scan outcomes themselves, the source
identity, and (when a CBOM was acquired) the generator's own document observation. There are no
assertions in this slice, so the Workbench reports zero inventory checks rather than borrowing the
captured Frigate checks. A failed or unavailable scan is recorded as such; it never becomes an
empty inventory, and a successful empty CBOM is recorded as a completed scan with zero assets.
"""
import json

from opentrace_core.bombridge.acquisition import MANIFEST_SCHEMA
from opentrace_core.bombridge.adapters import cbom_document_observation
from opentrace_core.bombridge_adapter import ArtifactRecord

from . import source_checks as source_checks_mod

INVENTORY_IDS = {"sbom": "inv:syft-source-dir", "cbom": "inv:cdxgen-cbom", "aibom": "inv:cisco-aibom"}
ARTIFACT_NAMES = {"sbom": "syft-sbom.cdx.json", "cbom": "cdxgen-cbom.cdx.json", "aibom": "cisco-aibom.cdx.json"}
FORMATS = {"sbom": "CycloneDX {} JSON", "cbom": "CycloneDX {} (CBOM)", "aibom": "CycloneDX {} (AI-BOM)"}
LABELS = {
    "sbom": "source-directory inventory (package manifests and lockfiles in the exported tree); not a deployed-image or runtime SBOM",
    "cbom": "CBOM · cdxgen: third-party generator, source-only run over the whole exported tree; coverage is the generator's own "
            "(Java keystores and certificates, JavaScript/TypeScript source algorithms, crypto-library components); an empty result is not evidence that no cryptography is used",
    "aibom": "AI-BOM · Cisco AI-BOM: third-party, language-model-assisted generator run over the whole exported tree in a separate worker; the classifier "
             "chose what to add or prune, so repository-declared and repository-text steering is possible; coverage and completeness are the "
             "generator's own; an empty result is not evidence that no AI is used",
}
NOT_ESTABLISHED = {"sbom": "that the scanner reported every component the repository contains",
                   "cbom": "that the scanner reported every component the repository contains",
                   "aibom": "that the producer reported every AI asset the repository contains, or that its classifier completed for every candidate"}


def artifact_id(kind):
    return "art:" + INVENTORY_IDS[kind]


def _ai_limitations(run, source):
    from . import aibom_cisco as ac
    items = ["the AI inventory step ran in a separate worker container configured so that its only network route is a restricted gateway to the provider; "
             "this record does not claim independent verification of that isolation ({})".format(run.isolation),
             "repository file names and code excerpts chosen by the classifier were sent to OpenAI (model {}) through that gateway; OpenTrace keeps no "
             "request or response bodies (ephemeral processing, not 'no scanned data')".format(ac.MODEL),
             "the repository was read as data: nothing was built, installed or executed; the full exported tree was read with no exclusion, so "
             "repository-declared (.aibom.*, inline annotations) and repository-text steering of the classifier is possible",
             "scope: the whole exported tree at the pinned commit ({} files; {} symlink/submodule entries not materialised)".format(source.file_count, len(source.skipped)),
             "classifier completeness: {}".format(run.completeness or "not applicable")
             + ("" if run.completeness in (None, "verified") else " (" + ", ".join("{}={}".format(k, v) for k, v in sorted(run.record_counts.items()) if k != "components") + ")"),
             "paths and line numbers are producer-reported; none is verified as a source occurrence and no occurrence link is offered"]
    items.extend(run.warnings[:6])
    return tuple(items)


def _limitations(run, source):
    if run.kind == "aibom":
        return _ai_limitations(run, source)
    items = ["scan ran with network access denied, write access limited to scratch directories and no process execution other than the scanner itself ({})".format(run.isolation),
             "the repository was read as data: nothing was built, installed or executed",
             "scope: the whole exported tree at the pinned commit ({} files; {} symlink/submodule entries not materialised)".format(source.file_count, len(source.skipped))]
    if run.kind == "cbom":
        items.append("cdxgen's reachability/usage analysis (atom) did not run in this boundary; the result is manifest, lockfile and source-pattern based")
    items.extend(run.warnings[:6])
    return tuple(items)


def manifest(run, source):
    """A ``bombridge.acquisition/1`` record for an acquired output; ``None`` otherwise."""
    if run.outcome != "acquired":
        return None
    return {"schema": MANIFEST_SCHEMA, "repository": source.repository_url, "revision": source.commit_sha,
            "inputs": [dict(i) for i in source.inputs], "tree_differs_from_revision": False,
            "generator": {"name": run.tool, "version": run.version, "invocation": run.command},
            "output_sha256": run.sha256, "limitations": list(_limitations(run, source))}


def _inventory(run, source):
    inv = {"inventory_id": INVENTORY_IDS[run.kind], "kind": run.kind, "origin": "captured", "label": LABELS[run.kind],
           "generator": "{} {}".format(run.tool, run.version or run.pinned_version), "command": run.command,
           "scan_scope": dict(run.scope), "acquisition": {
               "outcome": run.outcome, "reason": run.reason, "exit_code": run.exit_code, "isolation": run.isolation,
               "version": run.version, "pinned_version": run.pinned_version, "duration_ms": run.duration_ms}}
    if run.outcome == "acquired":
        inv.update({"format": FORMATS[run.kind].format(run.spec_version), "source_file": ARTIFACT_NAMES[run.kind],
                    "source_sha256": run.sha256, "record_counts": dict(run.record_counts),
                    "scan_binding": {"basis": "scan run by OpenTrace over the tree exported from the pinned commit; every exported blob was "
                                              "re-hashed against the commit's tree before scanning",
                                     "not_established": NOT_ESTABLISHED[run.kind]}})
        if run.kind == "aibom":
            inv["completeness"] = run.completeness
    return inv


def _input_check(run):
    if run.outcome == "acquired":
        detail = "{} {} produced a valid CycloneDX {} document ({} {}).".format(run.tool, run.version, run.spec_version, run.record_count, run.record_count_unit)
        if run.record_count == 0:
            detail += " " + run.meaning + "."
        return {"input": "live-" + run.kind, "status": "present_inspected", "detail": detail, "evidence": []}
    detail = "{} was not acquired ({}{}); no inventory exists for this input and none is substituted.".format(
        run.tool, run.outcome, ": " + run.reason if run.reason else "")
    return {"input": "live-" + run.kind, "status": "referenced_not_acquired", "detail": detail, "evidence": []}


def configuration_label(identity):
    """UIP-10 D2: one deterministic label for every live analysis. It names the scan profile; it is NOT an observed runtime environment."""
    return "scan-profile:{};target-environment:not-recorded".format(identity["scan"]["profile_id"])


def build(identity, source, runs, session_id, generation, advisory=False, source_checks=()):
    """Return everything the adapter needs: bundle parts, ArtifactRecords, names and raw bytes."""
    repo = identity["repository"]
    scope_id = "scope:live-{}-{}-{}".format(repo["owner"], repo["name"], source.commit_sha[:12]).lower()
    capture = {"scope_id": scope_id, "origin": "captured",
               "repository": {"url": repo["canonical_url"], "revision": source.commit_sha,
                              "revision_selection": {"method": "OpenTrace intake: server-side resolution, then fetch by full SHA and verified against the commit's tree",
                                                     "requested": identity["requested"], "basis": identity["resolved"]["basis"],
                                                     "tree_sha": source.tree_sha}},
               "build": None, "configuration": configuration_label(identity), "model": None, "execution": None,
               "unknown": ["build", "configuration", "model", "execution"], "unavailable": [],
               "inventories": [_inventory(r, source) for r in runs]}
    records, names, raw, evidence, checks = [], {}, {}, [], []
    for run in runs:
        aid, iid = artifact_id(run.kind), INVENTORY_IDS[run.kind]
        acquired = run.outcome == "acquired"
        state = "acquired" if acquired else ("cancelled" if run.outcome == "cancelled" else "failed" if run.outcome == "failed" else "not_acquired")
        records.append(ArtifactRecord(
            aid, iid, run.kind, state, run.sha256 if acquired else None, run.record_count if acquired else None,
            run.record_count_unit if acquired else ("crypto_assets" if run.kind == "cbom" else "components"),
            dict(run.record_counts) if acquired else None, identity["analysis_digest"], session_id, generation,
            manifest(run, source), _limitations(run, source)))
        checks.append(_input_check(run))
        if acquired:
            names[aid] = ARTIFACT_NAMES[run.kind]
            raw[aid] = run.data
        if acquired and run.kind == "cbom":
            doc = json.loads(run.data.decode("utf-8"))
            obs = cbom_document_observation(doc, run.sha256)
            obs["acquisition_generator"] = {"name": run.tool, "version": run.version, "third_party": True, "invocation": run.command}
            obs["acquisition_outcome"] = {"status": "completed", "exit_code": run.exit_code, "cyclonedx_spec_version": run.spec_version,
                                          "cryptographic_assets": run.record_count, "components": run.record_counts.get("components"),
                                          "services": run.record_counts.get("services"), "meaning": run.meaning or "a successful scan"}
            obs["acquisition_scope"] = {"file_count": source.file_count, "included_paths": ["."], "listing_sha256": source.listing_sha256,
                                        "method": "tree exported from the pinned commit"}
            evidence.append({"evidence_id": "ev-live-cdxgen-cbom", "scope_id": scope_id, "method": "cyclonedx-1.6-cbom-intake",
                             "observes": [], "origin": "captured", "scope": {"revision": source.commit_sha},
                             "source_locator": ARTIFACT_NAMES["cbom"], "tool": "opentrace_core/bombridge/adapters.py",
                             "underlying_source": "tool-output:cbom-" + run.sha256[:12], "observation": obs,
                             "limitations": list(_limitations(run, source))
                             + ["what the document says, not whether it is right"]})
    checks.insert(0, {"input": "live-source-revision", "status": "present_inspected", "evidence": [],
                      "detail": "Commit {} fetched by full SHA; its tree {} was read blob by blob and every blob re-hashed to the object id in the tree.".format(source.commit_sha[:12], source.tree_sha[:12])})
    cbom_run = next((r for r in runs if r.kind == "cbom"), None)
    entities, src_evidence, assertions = source_checks_mod.bundle_parts(list(source_checks), scope_id, source.commit_sha, cbom_run)
    evidence.extend(src_evidence)
    if source_checks:
        observed = [c for c in source_checks if c["status"] == "observed"]
        skipped = [c for c in source_checks if c["status"] != "observed"]
        if observed:
            checks.append({"input": "live-source-crypto-call", "status": "present_inspected", "evidence": [],
                           "detail": "{} target call site(s) read statically from the exported tree: {}.".format(
                               len(observed), "; ".join("{}:{}".format(c["file"], c["line"]) for c in observed))})
        if skipped:
            checks.append({"input": "live-source-crypto-call-skipped", "status": "not_found_in_inspected_scope", "evidence": [],
                           "searched": "the declared target line(s) of the exported tree at the pinned commit, read statically",
                           "detail": "Skipped, no observation recorded: " + "; ".join("{}:{} ({})".format(c["target"]["file"], c["target"]["line"], c["reason"]) for c in skipped) + "."})
    if not any(r.kind == "aibom" for r in runs):
        checks.append({"input": "live-aibom", "status": "not_applicable", "evidence": [],
                       "reason": "no AI-BOM phase ran for this live analysis (the phase is optional and was not requested or not configured)",
                       "detail": "No AI-BOM was requested for this live analysis."})
    bundle = {"capture": capture, "entities": entities, "observations": evidence, "assertions": assertions, "input_checks": checks,
              "origin": "captured", "notice": "LIVE SCAN. Inventories were generated by Syft and cdxgen from one pinned public commit; there are no curated "
                                              "declarations. " + ("One source-backed CBOM check was assessed by BOMBridge rule /3 over a statically read call site. " if assertions else "There are no assessed inventory checks in this analysis. ") + (
                                                  "Advisory matching is a separate lookup of the lockfile inventory against OSV, joined to the SBOM; "
                                                  "it is not a BOMBridge check." if advisory else "There is no live advisory matching.") + (
                                                  " The AI-BOM was generated by Cisco AI-BOM, a language-model-assisted producer; it is recorded as that "
                                                  "generator's own inventory and is not a BOMBridge check." if any(r.kind == "aibom" for r in runs) else "")}
    return bundle, records, names, raw
