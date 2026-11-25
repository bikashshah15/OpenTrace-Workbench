"""Hosted-versus-pinned reconciliation (I3-REQ-07, I3-REQ-08 item 5).

A comparison of identities and versions by (ecosystem, name_normalized, version_original). It is never a binding:
``binding_state`` is the constant ``unbound``, also when every hosted row agrees. Partial agreement is a list of
agreeing occurrences, not a property of the hosted document.
"""

SCHEMA = "opentrace.i3.reconciliation/1"
SETS = ("agree", "hosted_only", "pinned_only", "version_differs", "hosted_unmatchable", "pinned_unmatchable")


def _b(value):
    return value.encode("utf-8", "surrogatepass")


def reconcile_repo(repo, occurrences, hosted_table):
    """occurrences: pinned occurrence dicts of one repository; hosted_table: the hosted table dict (rows) or None."""
    out = {"repo": repo, "binding_state": "unbound", "lists": {k: [] for k in SETS}}
    if hosted_table is None:
        out["counts"] = {k: 0 for k in SETS}
        out["compared"] = False
        return out
    out["compared"] = True
    pinned = {}
    pinned_unmatchable = []
    for occ in occurrences:
        if occ["version_state"] != "exact":
            pinned_unmatchable.append(occ)
            continue
        pinned.setdefault((occ["ecosystem"], occ["name_normalized"]), []).append(occ)
    hosted = {}
    for row in hosted_table["rows"]:
        if row["ecosystem"] not in ("Go", "npm", "PyPI") or row["version_state"] != "exact":
            out["lists"]["hosted_unmatchable"].append({"spdx_id": row["spdx_id"], "ecosystem": row["ecosystem"],
                                                        "name_normalized": row["name_normalized"], "version_original": row["version_original"],
                                                        "reason": row["version_state"]})
            continue
        hosted.setdefault((row["ecosystem"], row["name_normalized"]), []).append(row)
    for ident in sorted(set(pinned) | set(hosted), key=lambda k: (_b(k[0]), _b(k[1]))):
        p, h = pinned.get(ident, []), hosted.get(ident, [])
        if p and not h:
            for occ in p:
                out["lists"]["pinned_only"].append({"ecosystem": ident[0], "name_normalized": ident[1], "version_original": occ["version_original"],
                                                    "path": occ["path"], "locator": occ["locator"]})
        elif h and not p:
            for row in h:
                out["lists"]["hosted_only"].append({"ecosystem": ident[0], "name_normalized": ident[1], "version_original": row["version_original"],
                                                    "spdx_id": row["spdx_id"]})
        else:
            hosted_versions = {r["version_original"] for r in h}
            pinned_versions = {o["version_original"] for o in p}
            common = hosted_versions & pinned_versions
            if common:
                for v in sorted(common, key=_b):
                    out["lists"]["agree"].append({"ecosystem": ident[0], "name_normalized": ident[1], "version_original": v,
                                                  "pinned": [{"path": o["path"], "locator": o["locator"]} for o in p if o["version_original"] == v],
                                                  "hosted": [r["spdx_id"] for r in h if r["version_original"] == v]})
            rest_p, rest_h = sorted(pinned_versions - common, key=_b), sorted(hosted_versions - common, key=_b)
            if rest_p or rest_h:
                out["lists"]["version_differs"].append({"ecosystem": ident[0], "name_normalized": ident[1],
                                                        "pinned_versions": rest_p, "hosted_versions": rest_h})
    for occ in pinned_unmatchable:
        out["lists"]["pinned_unmatchable"].append({"ecosystem": occ["ecosystem"], "name_normalized": occ["name_normalized"],
                                                   "version_original": occ["version_original"], "reason": occ["version_state"],
                                                   "path": occ["path"], "locator": occ["locator"]})
    out["counts"] = {k: len(v) for k, v in out["lists"].items()}
    return out


def reconcile(tables, hosted):
    """tables {(repo, path): table}; hosted {repo: {"scope", "table"}} -> sorted list of per-repo reconciliations."""
    by_repo = {}
    for (repo, path), table in sorted(tables.items()):
        for row in table["rows"]:
            by_repo.setdefault(repo, []).append(dict(row, repo=repo, path=path))
    out = []
    for repo in sorted(set(by_repo) | set(hosted)):
        h = hosted.get(repo)
        out.append(reconcile_repo(repo, by_repo.get(repo, []), h["table"] if h else None))
    return out
