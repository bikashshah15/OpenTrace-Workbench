"""Assessment semantics shared by rules (docs/ARCHITECTURE.md, "State semantics").

Pure functions. A rule states which scope fields it requires; a required field that is
missing is never a wildcard. There is no generic "optional field" matching: if a field
matters to a result, the rule requires it.
"""

SCOPE_FIELDS = ("revision", "build", "configuration", "model", "execution")
STATES = ("supported", "contradicted", "conflicting_evidence", "unverifiable")
RELATIONS = ("supports", "contradicts", "inconclusive")
DIGEST_LENGTHS = {"sha256": 64, "sha512": 128}


def digest_error(algorithm, value):
    """None if (algorithm, value) is a supported, well-formed digest, else a message."""
    if algorithm not in DIGEST_LENGTHS:
        return f"unsupported digest algorithm {algorithm!r} (supported: {sorted(DIGEST_LENGTHS)})"
    n = DIGEST_LENGTHS[algorithm]
    if not isinstance(value, str) or len(value) != n or any(c not in "0123456789abcdefABCDEF" for c in value):
        return f"{algorithm} digest must be {n} hexadecimal characters"
    return None


def assertion_scope_gaps(required, assertion_scope):
    """Required fields the assertion does not specify. Non-empty => unverifiable."""
    return [f for f in required if assertion_scope.get(f) is None]


def check_evidence_scope(required, assertion_scope, evidence_scope):
    """Return (ok, reason_code, detail) for candidate evidence.

    Call only when assertion_scope_gaps() is empty. Missing and mismatched required fields
    have different reason codes; neither is ever support or contradiction.
    """
    for f in required:
        got = evidence_scope.get(f)
        if got is None:
            return False, "scope_missing", f"{f}: not recorded on evidence"
        if got != assertion_scope[f]:
            return False, "scope_mismatch", f"{f}: assertion {assertion_scope[f]!r} vs evidence {got!r}"
    return True, None, None


def assess_state(applicable, relations):
    """Map relations from *used* (scope-compatible, artifact-matched) evidence to a state.

    applicable is True, False or None (unknown). Only False yields no state. Unknown
    applicability is handled by the caller (rule not implemented => unverifiable).
    No relations, or only inconclusive ones, is unverifiable and never contradicted.
    """
    if applicable is False:
        return None
    sup, con = "supports" in relations, "contradicts" in relations
    if sup and con:
        return "conflicting_evidence"
    if con:
        return "contradicted"
    if sup:
        return "supported"
    return "unverifiable"
