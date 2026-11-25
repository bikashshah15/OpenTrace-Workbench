"""UIP-04 deterministic fixture builder (verification tool; no application code, no network).

Writes ``evidence/uip/visual/uip-04/fixtures/uip04-*`` (NOT under evidence/uip/fixtures: the frozen UIP-01B fixture tests enumerate that
directory, so adding directories there would break assertions this increment may not edit): payloads produced by the PRODUCTION code path (``app/context_groups.respond`` over a stub
analysis and a hand-built adapter-shaped projection), each validated by the frozen UIP-01B validator, with a MANIFEST of digests.
All repositories are synthetic (no recorded-repository names). The 12-group payload is a clearly labelled hand-built layout-capacity
case, NOT a classifier output (a production repository yields at most 11 groups).

    PYTHONPATH=src/core python tools/uip04/build_fixtures.py [--out evidence/uip/visual/uip-04/fixtures]
"""
import hashlib
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "src", "core"))
from opentrace_core.app import context_groups as cg  # noqa: E402
from opentrace_core.app import view_contracts as vc  # noqa: E402
from opentrace_core.app.workbench_binding import build_binding  # noqa: E402

BUILDER = "tools/uip04/build_fixtures.py"
SEED = "uip-04/1"


class _Ticket:
    def __init__(self, generation):
        self.generation = generation


class _Views:
    def __init__(self, tab):
        self.tab = tab

    def _project(self, name, **kw):
        return {"tabs": [self.tab]}


class StubAnalysis:
    def __init__(self, tab, seed, owner="example-org", name="sample-web", generation=1):
        digest = "sha256:" + hashlib.sha256((SEED + ":" + seed).encode()).hexdigest()
        self.identity = {"analysis_digest": digest, "repository": {"host": "github.com", "owner": owner, "name": name, "canonical_url": "https://github.com/%s/%s" % (owner, name)},
                         "requested": {"kind": "tag", "text": "v1.0.0", "origin": "url_tree"},
                         "resolved": {"commit_sha": hashlib.sha256((SEED + ":" + seed + ":commit").encode()).hexdigest()[:40]}}
        self.ticket = _Ticket(generation)
        self.mode = "captured"
        self.assessment = None
        self.gaps = None
        self.views = _Views(tab)
        self.state = "complete"


def tab_of(files, unlocated=(), component_total=None, raw=None):
    rows = [{"path": p, "raw_locations": (raw or {}).get(p, ["/" + p]), "normalization_basis": ["syft_root_relative"], "components": [{"id": c} for c in ids]}
            for p, ids in sorted(files.items())]
    located = {c for ids in files.values() for c in ids}
    return {"rows": rows, "unlocated": {"components": [{"id": c} for c in unlocated]},
            "component_total": component_total if component_total is not None else len(located) + len(unlocated)}


def request(analysis, **params):
    return cg.respond(analysis, {k: [str(v)] for k, v in params.items()})


def analysis_stub(a):
    """The minimal /api/analysis payload the page needs to open a Workbench on a fixture (harness use only)."""
    ident = a.identity
    return {"ok": True, "generation": a.ticket.generation, "identity": {"repository": ident["repository"]["canonical_url"], "owner": ident["repository"]["owner"], "name": ident["repository"]["name"],
            "commit": ident["resolved"]["commit_sha"], "requested": ident["requested"], "basis": "url_revision", "configuration": "config:fixture", "analysis_digest": ident["analysis_digest"], "mode": "captured"},
            "summary": {"components": 0, "edges": 0, "unresolved_edges": 0, "advisory_groups": 0, "advisory_rows": 0, "inventory_checks": 0, "checks": [], "cards": []}}


def files_for(prefix_counts, members_per_file=3, seed="f"):
    files, n = {}, 0
    for pattern, count in prefix_counts:
        for i in range(count):
            path = pattern % i if "%" in pattern else (pattern if i == 0 else "%d/%s" % (i, pattern))
            files[path] = ["%s%d" % (seed, n + k) for k in range(members_per_file)]
            n += members_per_file
    return files


class Fixture:
    def __init__(self, name, notes):
        self.name, self.notes, self.files, self.schemas = name, notes, {}, {}

    def add(self, fname, payload, schema="opentrace.workbench.contexts/1"):
        self.files[fname], self.schemas[fname] = payload, schema


def write(out, fx):
    d = os.path.join(out, fx.name)
    os.makedirs(d, exist_ok=True)
    entries = []
    for fname in sorted(fx.files):
        data = (json.dumps(fx.files[fname], sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
        with open(os.path.join(d, fname), "wb") as handle:
            handle.write(data)
        entries.append({"path": fname, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "schema": fx.schemas[fname]})
    with open(os.path.join(REPO, BUILDER), "rb") as handle:
        bsha = hashlib.sha256(handle.read()).hexdigest()
    manifest = {"schema": "opentrace.uip.fixture_manifest/1", "name": fx.name, "provenance": "synthetic", "files": entries,
                "builder": {"path": BUILDER, "sha256": bsha, "seed": SEED}, "contains_frigate_names": False, "notes": fx.notes}
    with open(os.path.join(d, "MANIFEST.json"), "w", encoding="utf-8") as handle:
        handle.write(json.dumps(manifest, sort_keys=True, indent=1, ensure_ascii=False) + "\n")


def standard(fx, a, **page0):
    """page 0 (limit 20 default) plus the analysis stub every browser harness needs."""
    p = request(a, generation=1, **page0)
    fx.add("contexts-page-0.json", p)
    fx.add("analysis.json", analysis_stub(a), "opentrace.uip.analysis_stub/1")
    return p


def build_all(out):
    fixtures = []

    # ---- non-Frigate multi-ecosystem (with unlocated components)
    files = files_for([("web/app/p%d/package.json", 2), ("docs/guide%d.md", 1), ("svc/go%d/go.mod", 2), ("svc/Dockerfile.%d", 1), (".github/workflows/w%d.yml", 3), ("tools/x%d.sh", 2)], seed="m")
    a = StubAnalysis(tab_of(files, unlocated=["um0", "um1", "um2"]), "multi")
    fx = Fixture("uip04-multi-ecosystem", "A multi-ecosystem synthetic repository with located and unlocated components.")
    standard(fx, a)
    fixtures.append(fx)

    # ---- unlocated only, and unlocated together with files
    a = StubAnalysis(tab_of({}, unlocated=["u%d" % i for i in range(7)]), "unlocated-only")
    fx = Fixture("uip04-unlocated-only", "Every component lacks a recorded location: one header-only Unlocated group, no files.")
    standard(fx, a)
    fixtures.append(fx)
    a = StubAnalysis(tab_of(files_for([("web/a%d/package.json", 2), ("go.mod", 1)], seed="w"), unlocated=["uw0", "uw1"]), "unlocated-with-files")
    fx = Fixture("uip04-unlocated-with-files", "Located files plus an Unlocated group in the next grid slot.")
    standard(fx, a)
    fixtures.append(fx)

    # ---- overlap: components in more than one group and more than one file
    files = {"web/a/package.json": ["s", "t", "w1"], "web/b/package.json": ["s", "w2"], "docs/package-lock.json": ["s", "t", "d1"], ".github/workflows/ci.yml": ["t", "a1"]}
    a = StubAnalysis(tab_of(files), "overlap")
    fx = Fixture("uip04-overlap", "Components shared between files and groups: group distinct < group membership; the root counts each component once.")
    standard(fx, a)
    fixtures.append(fx)

    # ---- large map (>= 600 files, one group > 100, at most 11 groups)
    files = files_for([("web/pkg%03d/package.json", 213), ("docs/d%03d.md", 120), ("svc/svc%03d/go.mod", 140), ("deps/r%03d/requirements.txt", 90), (".github/workflows/w%03d.yml", 40), ("misc/o%03d/main.c", 50)], members_per_file=2, seed="L")
    assert len(files) >= 600
    a = StubAnalysis(tab_of(files, unlocated=["ul%d" % i for i in range(11)]), "large")
    fx = Fixture("uip04-large-map", "More than 600 files; the largest group has 213. Pages of 20 (Graph) and 40 (List); response_too_large retry ladder fixtures.")
    p0 = standard(fx, a)
    big = next(g for g in p0["groups"] if g["files_counts"]["total"] == 213)
    for off, lim in ((20, 20), (40, 20), (60, 20), (80, 20), (20, 10), (100, 40), (140, 40), (180, 40)):   # Graph pages of 20 up to the 100-card cap, a retry step (10), List pages of 40
        fx.add("contexts-group-web-offset-%d-limit-%d.json" % (off, lim), request(a, generation=1, group_id=big["group_id"], files_offset=off, files_limit=lim))
    fx.add("contexts-page-0-limit-5.json", request(a, generation=1, files_limit=5))
    fx.add("contexts-page-0-limit-1.json", request(a, generation=1, files_limit=1))
    fx.add("error-response-too-large.json", {"schema": "opentrace.workbench.error/1", "error": "response_too_large", "message": "payload exceeds the ceiling", "detail_code": "bound_exceeded"}, "opentrace.workbench.error/1")
    fixtures.append(fx)

    # ---- hostile text (inert) -- paths are data, never markup
    hostile = ['web/"><img src=x onerror=alert(1)>.json', "docs/<script>alert(1)</script>.md", "javascript:alert(1)", "web/a b/%2e%2e/c#frag?q=1", ".github/workflows/‮<b>x</b>.yml"]
    a = StubAnalysis(tab_of({p: ["h%d" % i] for i, p in enumerate(hostile)}), "hostile", owner="o-w-n-e-r", name="<b>repo</b>".replace("<", "x").replace(">", "x"))
    fx = Fixture("uip04-hostile-text", "Markup-like, URL-scheme-like and bidi text in paths: rendered as text, links stay inert unless an exact pinned https://github.com/ URL.")
    standard(fx, a)
    fixtures.append(fx)

    # ---- unrepresentable path: the typed failure the route returns (nothing dropped)
    tab = tab_of({"web/ok.json": ["a"]})
    tab["rows"].append({"path": "web/ctl\x01.json", "raw_locations": ["/web/ctl\x01.json"], "normalization_basis": ["syft_recorded_path"], "components": [{"id": "z"}]})
    tab["component_total"] = 2
    a = StubAnalysis(tab, "unrepresentable")
    try:
        request(a, generation=1)
    except vc.ContractError as exc:
        body = exc.body()
    else:
        raise SystemExit("expected unrepresentable_path")
    fx = Fixture("uip04-unrepresentable-path", "A recorded path the frozen schema cannot carry: projection_failed / unrepresentable_path (the Contexts tab shows an explicit unavailable state).")
    fx.add("error-projection-failed.json", body, "opentrace.workbench.error/1")
    fx.add("analysis.json", analysis_stub(a), "opentrace.uip.analysis_stub/1")
    fixtures.append(fx)

    # ---- one group, zero locations
    a = StubAnalysis(tab_of({"go.mod": ["a", "b"], "svc/go.sum": ["a", "c"]}), "one-group")
    fx = Fixture("uip04-one-group", "A single Go modules group.")
    standard(fx, a)
    fixtures.append(fx)
    a = StubAnalysis(tab_of({}, component_total=0), "zero")
    fx = Fixture("uip04-zero-location", "No located and no unlocated components: an empty valid map.")
    standard(fx, a)
    fixtures.append(fx)

    # ---- eleven groups (all ten categories plus Unlocated) produced by the classifier
    cats = {"docs/a%d.md": 2, "web/a%d.js": 2, "app/package-%d/package.json": 2, "req/requirements-%d.txt": 3, "mod/go%d/go.mod": 2, "crate/c%d/Cargo.toml": 1, "jvm/j%d/pom.xml": 2,
            ".github/workflows/w%d.yml": 3, "ctr/Dockerfile.%d": 2, "other/o%d.rs": 2}
    files = files_for([(k, v) for k, v in cats.items()], seed="e")
    a = StubAnalysis(tab_of(files, unlocated=["ue0", "ue1"]), "eleven")
    fx = Fixture("uip04-eleven-groups", "All ten categories plus Unlocated, produced by the production classifier (the maximum a real repository can yield).")
    p = standard(fx, a)
    assert len(p["groups"]) == 11
    fixtures.append(fx)

    # ---- synthetic 12-group layout-capacity payload (hand-built, NOT a classifier output)
    twelve = json.loads(json.dumps(p))
    extra = json.loads(json.dumps(next(g for g in twelve["groups"] if g["category"] == "other_locations")))
    extra["group_id"] = vc.opaque_id("grp", twelve["binding"]["analysis_digest"], "group", "synthetic-capacity")
    extra["label"] = "Synthetic capacity group"
    for i, f in enumerate(extra["files"]):
        f["path"] = "synthetic/capacity/s%d.rs" % i
        f["file_id"] = vc.opaque_id("ctx", twelve["binding"]["analysis_digest"], "file", f["path"])
        f["dependency_context_id"] = f["file_id"]
        f["raw_locations"] = ["/" + f["path"]]
        f["revision_link"] = {"href": "https://github.com/example-org/sample-web/blob/%s/%s" % (twelve["binding"]["commit_sha"], f["path"]), "text": f["path"]}
    twelve["groups"].insert(-1, extra)
    twelve["counts"] = {"total": 12, "shown": 12, "truncated": False}
    twelve["root"]["membership_total"] += extra["membership_total"]
    twelve["root"]["located_distinct_total"] += extra["distinct_total"]
    twelve["root"]["distinct_total"] += extra["distinct_total"]
    vc.validate_payload("contexts", twelve, request={"generation": 1})
    fx = Fixture("uip04-synthetic-12-group-layout-capacity", "SYNTHETIC layout-capacity test only: a hand-built 12-group payload (the schema maximum). It is not a classifier output and not a repository fixture.")
    fx.add("contexts-page-0.json", twelve)
    fx.add("analysis.json", analysis_stub(a), "opentrace.uip.analysis_stub/1")
    fixtures.append(fx)

    for fx in fixtures:
        for fname, payload in fx.files.items():
            if fx.schemas[fname] == "opentrace.workbench.contexts/1":
                vc.validate_payload("contexts", payload, request={"generation": 1})
        write(out, fx)
    return [fx.name for fx in fixtures]


if __name__ == "__main__":
    out = os.path.join(REPO, "evidence", "uip", "visual", "uip-04", "fixtures")
    if "--out" in sys.argv:
        out = os.path.abspath(sys.argv[sys.argv.index("--out") + 1])
    print("\n".join(build_all(out)))
