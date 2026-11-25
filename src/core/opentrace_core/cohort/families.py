"""Advisory families over fetched OSV records (I3-REQ-08 item 1).

Union-find over ``id`` and ``aliases[]`` of every fetched record. ``related[]`` and ``upstream[]`` never union.
A family keeps every member's raw record digest; it is active when any fetched member is not withdrawn and
withdrawn only when every fetched member is. ``family_id`` is the lexicographically smallest member ID, so it is
stable for a given set of records.
"""
from . import severity as sev


class _UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _affected(record):
    out = []
    for a in record.get("affected") or []:
        pkg = a.get("package") or {}
        out.append({"ecosystem": pkg.get("ecosystem"), "package": pkg.get("name"),
                    "ranges": [{"type": r.get("type"), "events": r.get("events", [])} for r in a.get("ranges") or []]})
    return out


def build_families(records):
    """records: {vuln_id: {"record": raw dict, "digest": sha256:...}} -> {family_id: family dict}, sorted deterministically."""
    uf = _UnionFind()
    for vid, item in records.items():
        uf.find(vid)
        for alias in item["record"].get("aliases") or []:
            if isinstance(alias, str) and alias:
                uf.union(vid, alias)
    groups = {}
    for node in list(uf.parent):
        groups.setdefault(uf.find(node), []).append(node)
    families = {}
    for members in groups.values():
        members.sort()
        family_id = members[0]
        member_rows, active_sev = [], []
        for mid in members:
            item = records.get(mid)
            if item is None:
                member_rows.append({"id": mid, "fetched": False, "record_digest": None, "withdrawn": None, "severity": None,
                                    "affected": [], "related": []})
                continue
            rec = item["record"]
            withdrawn = bool(rec.get("withdrawn"))
            s = sev.severity_of_record(rec)
            member_rows.append({"id": mid, "fetched": True, "record_digest": item["digest"], "withdrawn": withdrawn,
                                "severity": s, "affected": _affected(rec),
                                "related": sorted(set(list(rec.get("related") or []) + list(rec.get("upstream") or [])))})
            if not withdrawn:
                active_sev.append(s)
        fetched = [m for m in member_rows if m["fetched"]]
        band, has_unknown = sev.family_band(active_sev)
        families[family_id] = {"family_id": family_id, "members": member_rows,
                               "active": any(not m["withdrawn"] for m in fetched),
                               "withdrawn": bool(fetched) and all(m["withdrawn"] for m in fetched),
                               "band": band, "has_unknown_member": has_unknown,
                               "severity_conflict": any(s["conflict"] for s in active_sev)}
    return {k: families[k] for k in sorted(families)}


def family_of(families):
    """{member id: family_id}."""
    return {m["id"]: fid for fid, fam in families.items() for m in fam["members"]}
