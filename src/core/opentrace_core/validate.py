"""Structural and semantic validation of domain payloads (I1-REQ-05).

Semantic rules applied to a result against the task it answers:
  (a) context_mismatch            result context != task context
  (b) artifact_missing / artifact_integrity_failure / produced_artifact_integrity_failure
  (c) unknown_evidence_reference  claim cites an evidence ID that is not in the result
  (d) dimension_promotion         claim dimension differs from a cited evidence dimension
  (e) deadline_exceeded           received after the task deadline
  (f) capability_scope_exceeded   operations/dimensions outside the negotiated capability
Rule (b) issues are integrity issues: the caller quarantines instead of hiding them.
"""
import base64
import binascii

from . import NEGOTIATED_V2, NEGOTIATED_V3, SUPPORTED_MAJOR, timeutil
from .artifacts import IntegrityError, digest_of
from .schema import structural_errors

CONTEXT_FIELDS = ("repo_id", "requested_revision", "baseline_id", "candidate_id")
INTEGRITY_CODES = frozenset({"artifact_missing", "artifact_integrity_failure",
                             "produced_artifact_integrity_failure"})


class Issue:
    __slots__ = ("code", "detail", "claim_id", "digest")

    def __init__(self, code, detail, claim_id=None, digest=None):
        self.code, self.detail, self.claim_id, self.digest = code, detail, claim_id, digest

    def as_dict(self):
        out = {"code": self.code, "detail": self.detail}
        if self.claim_id is not None:
            out["claim_id"] = self.claim_id
        if self.digest is not None:
            out["digest"] = self.digest
        return out

    def __repr__(self):
        return "Issue(%r, %r)" % (self.code, self.detail)


class Report:
    def __init__(self, issues=None):
        self.issues = list(issues or [])

    @property
    def codes(self):
        return [i.code for i in self.issues]

    @property
    def integrity_issues(self):
        return [i for i in self.issues if i.code in INTEGRITY_CODES]

    @property
    def blocking_issues(self):
        return [i for i in self.issues if i.code not in INTEGRITY_CODES]

    @property
    def ok(self):
        return not self.issues


def schema_major(payload):
    version = payload.get("schema_version") if isinstance(payload, dict) else None
    if not isinstance(version, str):
        return None
    head = version.split(".", 1)[0]
    return int(head) if head.isdigit() else None


def check_structure(kind, payload, negotiated=None):
    """Version rule first (distinct code), then schema-equivalent structure.

    Major 1 is always accepted. Major 2 is accepted only when the caller passes
    ``negotiated="2.0"`` and major 3 only with ``negotiated="3.0"`` (set by the transport layer when the
    matching contract token is present); with the default the behavior is exactly the I1 behavior.
    """
    if not isinstance(payload, dict):
        return Report([Issue("schema_invalid", "payload is not an object")])
    if payload.get("kind") != kind:
        return Report([Issue("schema_invalid", "expected kind %s" % kind)])
    major = schema_major(payload)
    allowed = {SUPPORTED_MAJOR} | ({2} if negotiated == NEGOTIATED_V2 else set()) | ({3} if negotiated == NEGOTIATED_V3 else set())
    if major is not None and major not in allowed:
        return Report([Issue("unsupported_schema_version",
                             "schema_version %s is not major %d" % (payload.get("schema_version"), SUPPORTED_MAJOR))])
    errors = structural_errors(kind, payload, major=major if major is not None else SUPPORTED_MAJOR)
    return Report([Issue("schema_invalid", e) for e in errors])


def _decode_b64(text):
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None


def validate_result(result, task, capability, store, received_at, negotiated=None):
    """Return a Report for a result payload answering ``task`` under ``capability``.

    ``capability`` is the negotiated capability_response payload; ``store`` an
    ArtifactStore; ``received_at`` an aware datetime.
    """
    report = check_structure("result", result, negotiated)
    if not report.ok:
        return report
    issues = []

    # (a) context agreement
    for field in CONTEXT_FIELDS:
        if result["context"].get(field) != task["context"].get(field):
            issues.append(Issue("context_mismatch", "context.%s differs from the task" % field))

    # (b) artifact integrity
    produced = {}
    for art in result["artifacts"]:
        data = _decode_b64(art["content_b64"])
        actual = digest_of(data) if data is not None else None
        if data is None or actual != art["digest"] or len(data) != art["bytes"]:
            issues.append(Issue("produced_artifact_integrity_failure",
                                "content_b64 does not match digest/bytes", digest=art["digest"]))
        else:
            produced[art["digest"]] = data
        # An already-stored copy under the same digest must itself still verify; a
        # corrupted existing copy is an integrity failure, never overwritten (write-once).
        if store.exists(art["digest"]):
            try:
                store.get(art["digest"])
            except IntegrityError:
                issues.append(Issue("artifact_integrity_failure", "stored copy of produced artifact does not match digest",
                                    digest=art["digest"]))
    known_produced = {a["digest"] for a in result["artifacts"]}
    refs = []
    for ev in result["evidence"]:
        refs.append(ev["artifact_ref"]["digest"])
        refs.append(ev["collection_method"]["output_artifact"])
    for digest in sorted(set(refs)):
        if digest in known_produced:
            continue
        if not store.exists(digest):
            issues.append(Issue("artifact_missing", "referenced artifact not in store", digest=digest))
            continue
        try:
            store.get(digest)
        except IntegrityError:
            issues.append(Issue("artifact_integrity_failure", "stored bytes do not match digest", digest=digest))

    # (c) claims cite existing evidence, (d) no dimension promotion
    evidence = {ev["evidence_id"]: ev for ev in result["evidence"]}
    for claim in result["claims"]:
        for eid in claim["evidence_ids"]:
            if eid not in evidence:
                issues.append(Issue("unknown_evidence_reference", "cites missing evidence %s" % eid,
                                    claim_id=claim["claim_id"]))
            elif evidence[eid]["dimension"] != claim["dimension"]:
                issues.append(Issue("dimension_promotion",
                                    "%s claim cites %s evidence %s" % (claim["dimension"], evidence[eid]["dimension"], eid),
                                    claim_id=claim["claim_id"]))

    # (e) deadline
    if received_at > timeutil.parse_ts(task["deadline"]):
        issues.append(Issue("deadline_exceeded", "result received after the task deadline"))

    # (f) capability scope
    ops = set(capability.get("operations", []))
    dims = set(capability.get("dimensions", []))
    producer = result["producer"]
    if producer["service_id"] != capability.get("service_id"):
        issues.append(Issue("capability_scope_exceeded", "producer is not the negotiated service"))
    for op in producer["operations_used"]:
        if op not in ops or op not in task["operations"]:
            issues.append(Issue("capability_scope_exceeded", "operation %s not negotiated" % op))
    # Claim dimensions are bound to evidence dimensions by rule (d), so (f) checks evidence.
    used_dims = set(producer["dimensions_used"]) | {e["dimension"] for e in result["evidence"]}
    for dim in sorted(used_dims - dims):
        issues.append(Issue("capability_scope_exceeded", "dimension %s not negotiated" % dim))
    if schema_major(result) == 2:
        from . import validate_v2
        issues.extend(validate_v2.semantic_issues(result, task))
    elif schema_major(result) == 3:
        from . import validate_v2, validate_v3
        issues.extend(validate_v2.semantic_issues(result, task))
        issues.extend(validate_v3.semantic_issues(result, task, store, produced))
    return Report(issues)


def dependent_claims(result, bad_digests):
    """Claim IDs that rest on any evidence derived from a quarantined artifact."""
    tainted = {ev["evidence_id"] for ev in result.get("evidence", [])
               if ev["artifact_ref"]["digest"] in bad_digests
               or ev["collection_method"]["output_artifact"] in bad_digests}
    return [c["claim_id"] for c in result.get("claims", []) if tainted.intersection(c["evidence_ids"])]
