"""Severity band of an OSV record (I3-REQ-09).

Order of evidence: (1) the recorded database_specific.severity label, (2) a CVSS v3.1 vector's base score computed
by the FIRST CVSS v3.1 formula, (3) anything else is unknown. If the label and the vector both give a band and they
differ, the higher band is used and ``conflict`` is set (conservative attention rule). An absent score is never 0.
Bands here are facts about a record; their *ranking placement* is the ranking policy's choice.
"""
import math
import re

KNOWN_ORDER = ("critical", "high", "medium", "low", "none")
LABELS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VEC = re.compile(r"^CVSS:3\.1/(.+)$")


def roundup(value):
    """CVSS v3.1 Roundup: smallest one-decimal value >= input, robust to binary floating point."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss31_base(vector):
    """Base score of a ``CVSS:3.1/...`` vector, or None when it is not a complete valid v3.1 base vector."""
    m = _VEC.match(vector or "")
    if not m:
        return None
    parts = {}
    for item in m.group(1).split("/"):
        key, sep, val = item.partition(":")
        if not sep or key in parts:
            return None
        parts[key] = val
    base = {k: parts.get(k) for k in _METRICS}
    if any(v is None for v in base.values()):
        return None
    try:
        scope_changed = {"U": False, "C": True}[base["S"]]
        pr = (_PR_C if scope_changed else _PR_U)[base["PR"]]
        iss = 1 - (1 - _CIA[base["C"]]) * (1 - _CIA[base["I"]]) * (1 - _CIA[base["A"]])
        exploit = 8.22 * _AV[base["AV"]] * _AC[base["AC"]] * pr * _UI[base["UI"]]
    except KeyError:
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploit) if scope_changed else impact + exploit
    return roundup(min(total, 10))


def band_of_score(score):
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def severity_of_record(record):
    """{"band", "source", "score", "label", "label_band", "vector_band", "conflict"} for one raw OSV record."""
    ds = record.get("database_specific") if isinstance(record.get("database_specific"), dict) else {}
    label = ds.get("severity") if isinstance(ds.get("severity"), str) else None
    label_band = LABELS.get(label.upper()) if label else None
    vector, score, vector_band = None, None, None
    unsupported = False
    for entry in record.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == "CVSS_V3" and isinstance(entry.get("score"), str) and entry["score"].startswith("CVSS:3.1/"):
            computed = cvss31_base(entry["score"])
            if computed is None:
                unsupported = True
            elif score is None or computed > score:
                vector, score, vector_band = entry["score"], computed, band_of_score(computed)
        else:
            unsupported = True
    conflict = bool(label_band and vector_band and label_band != vector_band)
    known = [b for b in (label_band, vector_band) if b]
    if known:
        band = min(known, key=KNOWN_ORDER.index)
        source = "label_and_vector" if label_band and vector_band else ("label" if label_band else "vector")
    else:
        band = "unknown"
        if label is not None:
            source = "unrecognized_label"
        elif unsupported:
            source = "unsupported_vector"
        else:
            source = "absent"
    return {"band": band, "source": source, "score": score, "label": label, "label_band": label_band,
            "vector_band": vector_band, "vector": vector, "conflict": conflict}


def family_band(member_severities):
    """Highest KNOWN band among active members; ``unknown`` only when no active member is known.

    ``member_severities`` are severity_of_record results of ACTIVE (not withdrawn) members. Returns
    (band or None for no active member, has_unknown_member).
    """
    if not member_severities:
        return None, False
    known = [s["band"] for s in member_severities if s["band"] != "unknown"]
    unknown_present = any(s["band"] == "unknown" for s in member_severities)
    if known:
        return min(known, key=KNOWN_ORDER.index), unknown_present
    return "unknown", unknown_present
