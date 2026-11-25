"""Manifest selection (I3-REQ-04) and path validation (I3-REQ-03 item 3).

The policy is the data file contracts/cohort/v1/manifest_policy.json; its digest is recorded wherever the
selection is used. Excluded matches are reported (never dropped); hostile paths are rejected, never used.
"""
import json
import os
import re
from pathlib import Path

from ..canon import canonical_digest

POLICY_PATH = Path(__file__).resolve().parents[4] / "contracts" / "cohort" / "v1" / "manifest_policy.json"


def load_policy(path=POLICY_PATH):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def policy_digest(policy=None):
    return canonical_digest(policy or load_policy())


def path_problem(path, max_bytes=512):
    """Return a reason string when ``path`` must never be used, else None."""
    if not isinstance(path, str) or not path:
        return "empty_path"
    try:
        raw = path.encode("utf-8")
    except UnicodeEncodeError:
        return "not_utf8"
    if len(raw) > max_bytes:
        return "too_long"
    if "\x00" in path:
        return "nul_byte"
    if path.startswith("/"):
        return "absolute_path"
    parts = path.split("/")
    if any(p in ("..", ".", "") for p in parts):
        return "dot_segment"
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in path):
        return "control_character"
    if "\\" in path:
        return "backslash"
    return None


def parse_ls_tree(raw):
    """Parse ``git ls-tree -r -l -z`` bytes into rows (mode, type, sha, size, path). Malformed records raise ValueError."""
    rows = []
    for rec in raw.split(b"\x00"):
        if not rec:
            continue
        meta, sep, path = rec.partition(b"\t")
        if not sep:
            raise ValueError("ls-tree record without a tab")
        parts = meta.split()
        if len(parts) != 4:
            raise ValueError("ls-tree record with %d fields" % len(parts))
        mode, typ, sha, size = (p.decode("ascii") for p in parts)
        rows.append({"mode": mode, "type": typ, "sha": sha, "size": None if size == "-" else int(size),
                     "path": path.decode("utf-8", "surrogateescape")})
    return rows


def classify(path, policy):
    """Manifest kind for the basename, or None."""
    base = os.path.basename(path)
    kind = policy["basenames"].get(base)
    if kind:
        return kind
    for pat in policy.get("basename_patterns", []):
        if re.match(pat["regex"], base):
            return pat["kind"]
    return None


def select_manifests(rows, policy=None):
    """Apply the policy to listing rows.

    Returns {"selected": [...], "excluded": [...], "rejected": [...], "nonblob": [...]} where every entry keeps
    path, kind and the listing fields. ``rejected`` are hostile paths (never read); ``nonblob`` are matches whose
    mode is not a regular blob (symlink 120000, submodule 160000): recorded, never read.
    """
    policy = policy or load_policy()
    limits = policy["limits"]
    excluded_segments = set(policy["excluded_path_segments"])
    out = {"selected": [], "excluded": [], "rejected": [], "nonblob": []}
    for row in rows:
        kind = classify(row["path"], policy)
        if kind is None:
            continue
        item = dict(row, kind=kind)
        problem = path_problem(row["path"], limits["max_path_bytes"])
        if problem:
            out["rejected"].append(dict(item, reason=problem))
            continue
        if row["type"] != "blob" or row["mode"] not in ("100644", "100755"):
            out["nonblob"].append(dict(item, reason="mode_%s" % row["mode"]))
            continue
        if excluded_segments & set(row["path"].split("/")[:-1]):
            out["excluded"].append(dict(item, reason="excluded_path_segment"))
            continue
        out["selected"].append(item)
    for key in out:
        out[key].sort(key=lambda r: r["path"].encode("utf-8", "surrogateescape"))
    return out
