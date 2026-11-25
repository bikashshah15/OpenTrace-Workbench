"""UIP-07C A5: presentation-only normalisation of the fixed container scan root in the LEGACY AI view, for newly generated Cisco artifacts only.

The legacy ``/api/view/ai`` response copies each producer component record from the artifact bytes (``bombridge_adapter/projection.py``, protected and
unchanged). For a live Cisco artifact those records carry the constant container root ``/scan/repo`` (in ``bom-ref`` and ``cisco-aibom:file``). Here, at the
response boundary, string VALUES inside the copied records are shown with the existing ``<scan-root>`` form. Nothing else changes: the artifact bytes and
download, digests, ids, pointers, canonical references and identity are untouched (they are not rewritten, and keys/ids are skipped); a ``bom-ref`` is an opaque
string and is neither parsed nor used to infer a path or a link. Responses for the Demo, flag-off live scans and non-Cisco inventories are returned unchanged."""
import copy

ROOT = "/scan/repo"
SCAN_ROOT = "<scan-root>"
_KEEP = frozenset({"id", "pointer", "canonical_ref", "artifact_id", "sha256", "raw_pointer", "evidence_id", "selected_id", "entity_id", "assertion_id"})
_SECTIONS = ("models", "supporting_records", "inspector")


def is_cisco_live(analysis):
    if getattr(analysis, "mode", None) != "live":
        return False
    for rec in getattr(analysis, "records", ()):
        gen = ((getattr(rec, "acquisition_manifest", None) or {}).get("generator") or {})
        if getattr(rec, "kind", None) == "aibom" and getattr(rec, "state", None) == "acquired" and gen.get("name") == "cisco-aibom":
            return True
    return False


def _norm(value, skip=False):
    if isinstance(value, str):
        return value if skip else value.replace(ROOT + "/", SCAN_ROOT + "/").replace(ROOT, SCAN_ROOT)
    if isinstance(value, dict):
        return {k: _norm(v, k in _KEEP) for k, v in value.items()}
    if isinstance(value, list):
        return [_norm(v, skip) for v in value]
    return value


def present(data, analysis):
    """Return ``data`` unchanged unless this is the AI tab of a live analysis holding an acquired Cisco AI-BOM."""
    if not is_cisco_live(analysis):
        return data
    out = copy.copy(data)
    for key in _SECTIONS:
        if key in out and out[key] is not None:
            out[key] = _norm(out[key])
    return out
