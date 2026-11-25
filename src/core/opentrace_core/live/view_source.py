"""Stand-in for the captured demo source in the Workbench views of a live analysis (I5).

A live analysis never uses the captured Frigate advisory snapshot. Without live advisory lookup
(the default) every advisory lookup is empty and the summary says so. With it (I5B) the advisories
come from this analysis's own OSV lookup, joined to its own SBOM.
"""
from opentrace_core.advisory import join


class LiveSource:
    configuration = None
    mode = "live"

    def __init__(self, report=None, lookup=None):
        self.report = report
        self.rows_by_id = {r["id"]: r for r in report["rows"]} if report else {}
        view = join.to_view_source(report) if report else {"families": [], "rows": []}
        records = {vid: item["record"] for vid, item in lookup.records.items()} if lookup is not None else {}
        self.advisories = {"families": view["families"], "rows": view["rows"], "records": records,
                           "captured_at": lookup.queried_at if lookup is not None else None, "live": True}
        self.families = {f["key"]: f for f in view["families"]}
        self.state_by_ref = {s["bom_ref"]: {"state": r["state"], "reason": r["reason"], "join": r["join"]}
                             for r in (report["rows"] if report else []) for s in r["sbom"] if s["bom_ref"]}
        self.rows_by_ref = {}
        for row in view["rows"]:
            for ref in row["component_ids"]:
                self.rows_by_ref.setdefault(ref, []).append(row)
