"""Two deterministic rankers over one frozen findings projection, and the unresolved queue (I3-REQ-09).

The policy is a committed data file; its digest is written into every output. Both rankers consume the identical
projection (``input_digest``). Nothing here states that one ranker is better than another: this is a ranking
implementation only, with no labels and no metrics. Ranks are positions in a transparent sort, not severity claims.
"""
import json
from pathlib import Path

from ..canon import canonical_digest

POLICY_PATH = Path(__file__).resolve().parents[4] / "contracts" / "cohort" / "v1" / "ranking_policy.json"
RANKER_SEVERITY = "severity_first/1"
RANKER_EVIDENCE = "evidence_aware/1"
SCHEMA = "opentrace.i3.ranking/1"


class RankingError(ValueError):
    pass


def load_policy(path=POLICY_PATH):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def policy_digest(policy=None):
    return canonical_digest(policy or load_policy())


def _bytes(value):
    return value.encode("utf-8", "surrogatepass")


def _tie(group):
    return (_bytes(group["ecosystem"]), _bytes(group["name_normalized"]), _bytes(group["family_id"]))


def _sort_key(ranker, policy, group):
    band_rank = {b: i for i, b in enumerate(policy["severity_bands_in_ranking_order"])}
    tiers = policy["evidence_tiers_descending"]
    band = group["band"]
    if band not in band_rank:
        raise RankingError("unknown severity band %r" % (band,))
    if ranker == RANKER_SEVERITY:
        return (band_rank[band],) + _tie(group)
    if ranker == RANKER_EVIDENCE:
        tier = group.get("tier", "E1")
        if tier not in tiers:
            raise RankingError("unknown evidence tier %r" % (tier,))
        return (tiers.index(tier), band_rank[band], -int(group["repos_supported"]), 0 if group["has_direct"] else 1,
                0 if group["has_runtime_scope"] else 1) + _tie(group)
    raise RankingError("unknown ranker %r" % (ranker,))


def _explain(ranker, group):
    parts = ["band %s" % group["band"]]
    if group.get("has_unknown_member"):
        parts.append("has an unrecorded-severity member")
    if group.get("severity_conflict"):
        parts.append("label and vector differ (higher band used)")
    if ranker == RANKER_EVIDENCE:
        parts = ["tier %s" % group.get("tier", "E1")] + parts + [
            "%d repositories with a supported match" % group["repos_supported"],
            "direct occurrence" if group["has_direct"] else "no direct occurrence",
            "runtime scope" if group["has_runtime_scope"] else "no runtime-scoped occurrence"]
    return "; ".join(parts)


def rank(ranker, projection, policy=None):
    """Ranked entries of one ranker. Every group appears exactly once; input order never matters."""
    policy = policy or load_policy()
    keys = [g["group_key"] for g in projection]
    if len(set(keys)) != len(keys):
        raise RankingError("duplicate group key in the projection")
    ordered = sorted(projection, key=lambda g: _sort_key(ranker, policy, g))
    return [{"rank": i + 1, "group_key": g["group_key"], "family_id": g["family_id"], "ecosystem": g["ecosystem"],
             "name_normalized": g["name_normalized"], "band": g["band"], "tier": g.get("tier", "E1"),
             "repos_supported": g["repos_supported"], "has_direct": g["has_direct"], "has_runtime_scope": g["has_runtime_scope"],
             "has_unknown_member": bool(g.get("has_unknown_member")), "explanation": _explain(ranker, g)}
            for i, g in enumerate(ordered)]


def unresolved_queue(unresolved, policy=None):
    """Items grouped by (ecosystem, name_normalized, reason); never merged into the ranked list, never dropped."""
    grouped = {}
    for u in unresolved:
        g = grouped.setdefault((u["ecosystem"], u["name_normalized"], u["reason"]),
                               {"ecosystem": u["ecosystem"], "name_normalized": u["name_normalized"], "reason": u["reason"],
                                "repos": set(), "occurrences": 0, "has_direct": False, "items": []})
        g["repos"].add(u["repo"])
        g["occurrences"] += 1
        g["has_direct"] = g["has_direct"] or u.get("direct") is True
        g["items"].append({"repo": u["repo"], "path": u["path"], "locator": u["locator"], "version_original": u["version_original"]})
    out = []
    for g in grouped.values():
        g["items"].sort(key=lambda i: (_bytes(i["repo"]), _bytes(i["path"]), _bytes(i["locator"])))
        out.append({"ecosystem": g["ecosystem"], "name_normalized": g["name_normalized"], "reason": g["reason"],
                    "distinct_repos": len(g["repos"]), "occurrences": g["occurrences"], "has_direct": g["has_direct"], "items": g["items"]})
    out.sort(key=lambda g: (-g["distinct_repos"], -g["occurrences"], 0 if g["has_direct"] else 1, _bytes(g["ecosystem"]),
                            _bytes(g["name_normalized"]), _bytes(g["reason"])))
    for i, g in enumerate(out):
        g["position"] = i + 1
    return out


def ranking_document(ranker, projection, unresolved, policy=None):
    policy = policy or load_policy()
    return {"schema": SCHEMA, "ranker": ranker, "policy_id": policy["policy_id"], "policy_digest": policy_digest(policy),
            "input_digest": canonical_digest(projection), "ranked": rank(ranker, projection, policy),
            "unresolved": unresolved_queue(unresolved, policy),
            "statement": "A transparent ordering of advisory families over inventory matches. It is not a claim about "
                         "reachability or impact, and no comparison between rankers is made."}
