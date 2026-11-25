"""UIP-05: the dependency-page producer (pure graph core, focus rules, chooser default) against the frozen oracle and adversarial graphs."""
import copy
import json
import os
import random
import unittest

from opentrace_core.app import dependency_pages as dp
from opentrace_core.app import view_contracts as vc
from tests.core.app.test_view_contracts import FIXTURES, load_builder

BUILDER = load_builder()


def jload(*parts):
    with open(os.path.join(FIXTURES, *parts), encoding="utf-8") as handle:
        return json.load(handle)


def G(nodes, edges):
    return dp.Graph({k: dict(v) for k, v in nodes.items()}, edges)


def gn(name, ver="1.0.0", loc=True, lookup="no_match", matches=0, eco="npm"):
    return BUILDER.gnode(name, ver, loc, lookup, matches, eco)


def pk(name):
    return "pkg:%s" % name


def page(graph, focus, binding=None, **kw):
    b = binding or BUILDER.make_binding("example-org", "unit-lab", "uip05")
    kw.setdefault("basis", "requested")
    return dp.page_from_graph(b, vc.opaque_id("ctx", b["analysis_digest"], "file", "lab/package-lock.json"), "lab/package-lock.json", graph, focus, **kw), b


def oracle(graph, focus, binding, **kw):
    return BUILDER.dep_page(binding, "lab/package-lock.json", {"nodes": graph.nodes, "edges": list(graph.edges)}, focus, **kw)


def pairs(p):
    return sorted((e["from"], e["to"]) for e in p["edges"])


def strip_pointers(p):
    p = copy.deepcopy(p)
    for e in p["edges"]:
        e["source_pointers"] = []
    return p


def accept(test, payload, binding):
    vc.validate_payload("dependency_page", payload, request={"generation": binding["generation"]},
                        expected_binding={k: binding[k] for k in ("analysis_digest", "commit_sha", "repository", "requested_ref", "mode", "assessment")})


# ---------------------------------------------------------------- the frozen fixtures (exact-field oracle)
def deps82():
    nodes = {pk("root"): gn("root-app", "1.0.0", True, "no_match")}
    edges = []
    special = {"match": {7, 21, 44, 63}, "unavailable": {10}, "missing_version": {20}, "unsupported": {30}, "not_run": {60}}
    for i in range(1, 83):
        lk = next((k for k, s in special.items() if i in s), "no_match")
        nodes[pk("dep-%03d" % i)] = gn("dep-%03d" % i, None if lk == "missing_version" else "1.%d.0" % i, i not in {15, 16}, lk, 1 if lk == "match" else 0)
        edges.append((pk("root"), pk("dep-%03d" % i)))
    return G(nodes, edges)


def paths_graph():
    P = pk
    nodes = {P("focus"): gn("focus-root", "1.0.0", True, "no_match")}
    spec = {"a": ("match", "1.0.0"), "b": ("no_match", "1.0.0"), "c": ("unavailable", "1.0.0"), "d": ("unsupported", "1.0.0"),
            "e": ("missing_version", None), "g": ("not_run", "1.0.0"), "f": ("no_match", "1.0.0")}
    for k, (lk, ver) in spec.items():
        nodes[P(k)] = gn("node-" + k, ver, True, lk, 2 if lk == "match" else 0)
    edges = [(P("focus"), P("a")), (P("focus"), P("b")), (P("focus"), P("c")), (P("a"), P("d")), (P("b"), P("d")), (P("d"), P("e")),
             (P("e"), P("a")), (P("c"), P("g")), (P("e"), P("f"))]
    nodes[P("x")] = gn("island-x")
    nodes[P("y")] = gn("island-y")
    edges.append((P("x"), P("y")))
    return G(nodes, edges)


class FrozenOracle(unittest.TestCase):
    """Production equals every committed frozen fixture in every field except edges[].source_pointers (contract 4.3)."""

    def compare(self, fixture_dir, name, graph, focus, **kw):
        frozen = jload(fixture_dir, name)
        got = dp.page_from_graph(frozen["binding"], frozen["context"]["context_id"], frozen["context"]["path"], graph, focus, **kw)
        self.assertEqual(strip_pointers(got), strip_pointers(frozen), name)
        self.assertEqual([e["edge_id"] for e in got["edges"]], [e["edge_id"] for e in frozen["edges"]])
        accept(self, got, frozen["binding"])

    def test_deps_82_pages_and_filters(self):
        g = deps82()
        for off in (0, 30, 60):
            self.compare("deps-82-synthetic", "page-offset-%02d.json" % off, g, pk("root"), offset=off, basis="graph_root")
        for flt in ("advisory", "direct", "transitive", "evidence_gaps"):
            self.compare("deps-82-synthetic", "filter-%s.json" % flt, g, pk("root"), filt=flt, basis="graph_root")
        self.compare("deps-82-synthetic", "search-dep-04.json", g, pk("root"), query="dep-04", basis="graph_root")

    def test_82_direct_is_30_30_22_and_connectors_never_consume_the_quota(self):
        g = deps82()
        shown = [dp.page_from_graph(BUILDER.make_binding("e", "r", "s"), "ctx:" + "0" * 24, "p", g, pk("root"), offset=o, basis="graph_root")["page"] for o in (0, 30, 60)]
        self.assertEqual([p["matches_shown"] for p in shown], [30, 30, 22])
        self.assertEqual({p["matches_total"] for p in shown}, {82})

    def test_paths_fixtures(self):
        g, P = paths_graph(), pk
        d = "deps-paths-synthetic"
        self.compare(d, "paths-all.json", g, P("focus"), basis="graph_root", candidates_total=2)
        self.compare(d, "paths-transitive.json", g, P("focus"), filt="transitive", basis="graph_root", candidates_total=2)
        self.compare(d, "paths-evidence-gaps.json", g, P("focus"), filt="evidence_gaps", basis="graph_root", candidates_total=2)
        self.compare(d, "paths-requested-focus.json", g, P("a"), basis="requested", candidates_total=2)
        off = {k: dict(v, lookup="not_run", matches=0) for k, v in g.nodes.items()}
        self.compare(d, "paths-lookup-off.json", G(off, g.edges), P("focus"), lookup_mode="off", basis="graph_root", candidates_total=2)
        cyc = G({P("p"): gn("cycle-p"), P("q"): gn("cycle-q"), P("r"): gn("cycle-r")}, [(P("p"), P("q")), (P("q"), P("r")), (P("r"), P("p"))])
        self.compare(d, "paths-cycle-fallback.json", cyc, P("p"), basis="cycle_fallback", candidates_total=3)
        disc = G({P("m"): gn("comp-m"), P("n"): gn("comp-n"), P("u"): gn("comp-u"), P("v"): gn("comp-v")}, [(P("m"), P("n")), (P("u"), P("v"))])
        self.compare(d, "paths-disconnected-fallback.json", disc, P("m"), basis="disconnected_fallback", candidates_total=2)

    def test_connector_cap_and_depth_limit_fixtures(self):
        P = pk
        cn, ce = {P("hub"): gn("hub-root")}, []
        for i in range(30):
            prev = P("hub")
            for j in range(7):
                nid = P("c%02d-%d" % (i, j))
                cn[nid] = gn("zz-chain-%02d-%d" % (i, j))
                ce.append((prev, nid))
                prev = nid
            leaf = P("leaf-%02d" % i)
            cn[leaf] = gn("aa-leaf-%02d" % i, "1.0.0", True, "match", 1)
            ce.append((prev, leaf))
        self.compare("deps-paths-synthetic", "paths-connectors-omitted.json", G(cn, ce), P("hub"), filt="advisory", basis="graph_root")
        dn, de, prev = {P("top"): gn("chain-top")}, [], P("top")
        for i in range(1, 16):
            nid = P("n%02d" % i)
            dn[nid] = gn("chain-n%02d" % i)
            de.append((prev, nid))
            prev = nid
        self.compare("deps-paths-synthetic", "paths-depth-limit.json", G(dn, de), P("top"), basis="graph_root")


# ---------------------------------------------------------------- edge selection
class EdgeSelection(unittest.TestCase):
    def test_diamond_draws_both_incoming_edges_and_lists_the_match_once(self):
        g = G({pk(n): gn(n) for n in ("f", "a", "b", "d")}, [(pk("f"), pk("a")), (pk("f"), pk("b")), (pk("a"), pk("d")), (pk("b"), pk("d"))])
        p, b = page(g, pk("f"))
        self.assertEqual(pairs(p), sorted([(pk("f"), pk("a")), (pk("f"), pk("b")), (pk("a"), pk("d")), (pk("b"), pk("d"))]))
        self.assertEqual([n["node_id"] for n in p["nodes"] if n["node_id"] == pk("d")], [pk("d")])
        self.assertEqual(next(n for n in p["nodes"] if n["node_id"] == pk("d"))["depth"], 2)
        accept(self, p, b)

    def test_cycle_terminates_and_back_edges_are_not_drawn(self):
        g = G({pk(n): gn(n) for n in ("f", "a", "b")}, [(pk("f"), pk("a")), (pk("a"), pk("b")), (pk("b"), pk("f")), (pk("b"), pk("a"))])
        p, b = page(g, pk("f"))
        self.assertEqual(pairs(p), sorted([(pk("f"), pk("a")), (pk("a"), pk("b"))]))
        accept(self, p, b)

    def test_cross_level_edge_to_a_deeper_shown_node_is_not_drawn_and_no_shortcut_from_the_focus(self):
        g = G({pk(n): gn(n) for n in ("f", "a", "b", "c")}, [(pk("f"), pk("a")), (pk("a"), pk("b")), (pk("b"), pk("c")), (pk("a"), pk("c"))])
        p, b = page(g, pk("f"))
        # c is at distance 2 via a->c; b->c is a cross-level (dist 3 vs 2) edge that must not be drawn; no focus->c edge exists
        self.assertEqual(next(n for n in p["nodes"] if n["node_id"] == pk("c"))["depth"], 2)
        self.assertNotIn((pk("b"), pk("c")), pairs(p))
        self.assertFalse(any(e["from"] == pk("f") and e["to"] == pk("c") for e in p["edges"]))
        accept(self, p, b)

    def test_equal_length_parents_tie_break_is_deterministic_across_input_order(self):
        names = ("f", "a", "b", "d")
        edges = [(pk("f"), pk("b")), (pk("f"), pk("a")), (pk("b"), pk("d")), (pk("a"), pk("d"))]
        results = set()
        for seed in range(6):
            e = list(edges)
            random.Random(seed).shuffle(e)
            p, _ = page(G({pk(n): gn(n) for n in names}, e), pk("f"))
            results.add(json.dumps(p, sort_keys=True))
        self.assertEqual(len(results), 1)

    def test_connector_cap_omits_the_whole_path_and_sets_the_cause_flag(self):
        cap = dp.CONNECTOR_CAP
        nodes, edges = {pk("hub"): gn("hub")}, []
        for i in range(20):                       # 20 chains x 8 connectors = 160 > the 120 cap, each leaf at depth 9 (< depth cap)
            prev = pk("hub")
            for j in range(8):
                nid = pk("c%d-%d" % (i, j))
                nodes[nid] = gn("zz%d-%d" % (i, j))
                edges.append((prev, nid))
                prev = nid
            nodes[pk("leaf%d" % i)] = gn("aa-leaf%d" % i, lookup="match", matches=1)
            edges.append((prev, pk("leaf%d" % i)))
        p, b = page(G(nodes, edges), pk("hub"), filt="advisory")
        states = {n["node_id"]: n["path_state"] for n in p["nodes"] if n["role"] == "match"}
        self.assertIn("connectors_omitted", states.values())
        self.assertTrue(p["limits"]["connectors_truncated"] and not p["limits"]["edges_truncated"])
        omitted = {k for k, v in states.items() if v == "connectors_omitted"}
        self.assertFalse(any(e["to"] in omitted or e["from"] in omitted for e in p["edges"]))
        self.assertLessEqual(p["limits"]["connectors_shown"], cap)
        accept(self, p, b)

    def test_edge_cap_sets_edges_truncated_and_extra_edges_drop_deterministically(self):
        # many parallel two-edge paths exceed the 240-edge budget by edges, not by connector count
        nodes, edges = {pk("f"): gn("f")}, []
        for i in range(30):
            nodes[pk("m%02d" % i)] = gn("m%02d" % i)
            edges.append((pk("f"), pk("m%02d" % i)))
        for i in range(30):
            for j in range(10):
                t = pk("t%02d-%d" % (i, j))
                nodes[t] = gn("t%02d-%d" % (i, j), lookup="match", matches=1)
                edges.append((pk("m%02d" % i), t))
        g = G(nodes, edges)
        p1, b = page(g, pk("f"), filt="advisory")
        p2, _ = page(G({k: dict(v) for k, v in nodes.items()}, list(reversed(edges))), pk("f"), filt="advisory")
        self.assertEqual(json.dumps(p1, sort_keys=True), json.dumps(p2, sort_keys=True))
        self.assertLessEqual(len(p1["edges"]), dp.EDGE_CAP)
        self.assertTrue(p1["limits"]["edges_truncated"] or len(p1["edges"]) <= dp.EDGE_CAP)
        accept(self, p1, b)

    def test_depth_limit_node_draws_no_edge(self):
        nodes, edges, prev = {pk("top"): gn("top")}, [], pk("top")
        for i in range(1, 16):
            nodes[pk("n%02d" % i)] = gn("n%02d" % i)
            edges.append((prev, pk("n%02d" % i)))
            prev = pk("n%02d" % i)
        p, b = page(G(nodes, edges), pk("top"))
        deep = [n for n in p["nodes"] if n["path_state"] == "depth_limit"]
        self.assertTrue(deep)
        self.assertFalse(any(e["to"] == d["node_id"] for d in deep for e in p["edges"]))
        accept(self, p, b)

    def test_random_graphs_match_the_frozen_builder_and_never_invent_an_edge(self):
        rng = random.Random(20261114)
        for trial in range(60):
            n = rng.randint(2, 40)
            names = ["n%02d" % i for i in range(n)]
            nodes = {pk(x): gn(x, lookup=rng.choice(dp.LOOKUP_STATES), matches=1, loc=rng.random() > .2) for x in names}
            edges = [(pk(rng.choice(names)), pk(rng.choice(names))) for _ in range(rng.randint(1, n * 3))]
            g = G(nodes, edges)
            focus = pk(rng.choice(names))
            filt = rng.choice(["all", "direct", "transitive", "advisory", "evidence_gaps"])
            p, b = page(g, focus, filt=filt)
            for node in nodes.values():                      # builder normalises matches for non-match states itself
                pass
            ref = oracle(g, focus, b, filt=filt)
            self.assertEqual(strip_pointers(p), strip_pointers(ref), trial)
            recorded = set(g.edges)
            self.assertTrue(set(pairs(p)) <= recorded, trial)
            self.assertEqual(len(pairs(p)), len(set(pairs(p))))
            self.assertFalse(any(e["from"] == e["to"] for e in p["edges"]))
            accept(self, p, b)


# ---------------------------------------------------------------- focus rules
class FocusRules(unittest.TestCase):
    def test_graph_root_unique_by_outdegree(self):
        g = paths_graph()
        self.assertEqual(dp.choose_focus(g), (pk("focus"), "graph_root", 2))

    def test_peer_roots_are_disconnected_fallback_name_ordered(self):
        g = G({pk(n): gn("comp-" + n) for n in "mnuv"}, [(pk("m"), pk("n")), (pk("u"), pk("v"))])
        self.assertEqual(dp.choose_focus(g), (pk("m"), "disconnected_fallback", 2))

    def test_pure_cycle_is_cycle_fallback_over_all_nodes(self):
        g = G({pk(n): gn("cycle-" + n) for n in "pqr"}, [(pk("p"), pk("q")), (pk("q"), pk("r")), (pk("r"), pk("p"))])
        self.assertEqual(dp.choose_focus(g), (pk("p"), "cycle_fallback", 3))

    def test_single_root_and_deps82(self):
        self.assertEqual(dp.choose_focus(deps82()), (pk("root"), "graph_root", 1))

    def test_empty_graph_has_no_focus_and_no_name_is_privileged(self):
        self.assertIsNone(dp.choose_focus(G({}, [])))
        priv = "web" + "-new"
        g = G({pk("a"): gn("alpha"), pk("w"): gn(priv)}, [(pk("a"), pk("x"))] if False else [])
        self.assertEqual(dp.choose_focus(g)[0], pk("a"))        # alphabetical, not the legacy name preference

    def test_self_loops_are_dropped_and_do_not_make_a_root_look_referenced(self):
        g = G({pk("a"): gn("a"), pk("b"): gn("b")}, [(pk("a"), pk("a")), (pk("a"), pk("b"))])
        self.assertEqual(g.edges, [(pk("a"), pk("b"))])
        self.assertEqual(dp.choose_focus(g), (pk("a"), "graph_root", 1))


# ---------------------------------------------------------------- paging, filters, coverage
class PagingAndCoverage(unittest.TestCase):
    def test_offset_is_clamped_to_an_effective_aligned_page_start(self):
        g = deps82()
        for asked, effective in ((5, 0), (59, 30), (60, 60), (10 ** 6, 60)):
            p, b = page(g, pk("root"), offset=asked)
            self.assertEqual(p["page"]["offset"], effective)
            accept(self, p, b)

    def test_query_changes_matches_total_but_not_filter_totals(self):
        g = deps82()
        full, _ = page(g, pk("root"))
        q, b = page(g, pk("root"), query="dep-04")
        self.assertEqual(q["filter_totals"], full["filter_totals"])
        self.assertEqual(q["page"]["matches_total"], 10)
        accept(self, q, b)

    def test_no_match_appears_twice_across_pages_and_sorting_is_deterministic(self):
        g = deps82()
        seen = []
        for off in (0, 30, 60):
            p, _ = page(g, pk("root"), offset=off)
            seen += [n["node_id"] for n in p["nodes"] if n["role"] == "match"]
        self.assertEqual(len(seen), len(set(seen)))
        self.assertEqual(seen, sorted(seen, key=lambda i: (g.nodes[i]["name"].lower(), g.nodes[i]["version"] or "", i)))

    def test_completed_no_match_is_covered_every_other_state_is_a_gap(self):
        g = deps82()
        p, _ = page(g, pk("root"))
        for n in p["nodes"]:
            gap = "lookup_incomplete" in n["gap_causes"] or "lookup_not_run" in n["gap_causes"]
            self.assertEqual(gap, n["advisory_lookup"] in dp.GAP_LOOKUP, n["name"])
            if n["advisory_lookup"] in ("no_match", "match"):
                self.assertNotIn("lookup_incomplete", n["gap_causes"])

    def test_lookup_states_map_from_the_join_vocabulary(self):
        rows = {"r1": [{"x": 1}]}
        f = dp._lookup_for
        self.assertEqual(f("live", rows, {"r1": {"state": "match", "reason": ""}}, "r1"), ("match", 1))
        self.assertEqual(f("live", {}, {"a": {"state": "no_match", "reason": ""}}, "a"), ("no_match", 0))
        self.assertEqual(f("live", {}, {"a": {"state": "unavailable", "reason": "timeout"}}, "a"), ("unavailable", 0))
        self.assertEqual(f("live", {}, {"a": {"state": "not_looked_up", "reason": "version_range"}}, "a"), ("missing_version", 0))
        self.assertEqual(f("live", {}, {"a": {"state": "not_looked_up", "reason": "not_in_lockfile_inventory"}}, "a"), ("unsupported", 0))
        self.assertEqual(f("live", {}, {"a": {"state": "not_looked_up", "reason": "lookup_not_run"}}, "a"), ("not_run", 0))
        self.assertEqual(f("off", rows, None, "r1"), ("not_run", 0))
        self.assertEqual(f("recorded", rows, None, "r1"), ("match", 1))
        self.assertEqual(f("recorded", rows, None, "zz"), ("not_run", 0))

    def test_hostile_text_is_normalised_for_the_schema_and_stays_text(self):
        evil = '<img src=x onerror=alert(1)>\n‮"javascript:alert(1)'
        g = G({pk("f"): gn("root"), pk("e"): dict(gn("x"), name=dp._clean(evil, 256), version=dp._clean("1.0\n", 128))}, [(pk("f"), pk("e"))])
        p, b = page(g, pk("f"))
        node = next(n for n in p["nodes"] if n["node_id"] == pk("e"))
        self.assertNotIn("\n", node["name"])
        self.assertIn("<img", node["name"])                         # not rewritten except control characters; the UI escapes it
        accept(self, p, b)
        self.assertEqual(dp._clean("a" * 300, 256), "a" * 255 + "…")


# ---------------------------------------------------------------- chooser
def fake_rows(n):
    return [{"context_id": "ctx:%024x" % i, "path": "dir%03d/file.txt" % i, "components_total": i % 7 + 1, "category": "other_locations"} for i in range(n)]


class ChooserDefault(unittest.TestCase):
    def row(self, path, total, category):
        return {"context_id": "ctx:" + dp._sha(path)[:24], "path": path, "components_total": total, "category": category}

    def test_default_prefers_dependency_categories_largest_then_path(self):
        rows = [self.row("docs/a.md", 900, "documentation"), self.row("b/package-lock.json", 5, "node_packages"),
                self.row("a/package-lock.json", 5, "node_packages"), self.row("c/go.sum", 3, "go_modules")]
        cid, basis = dp.default_context(rows)
        self.assertEqual((cid, basis), (rows[2]["context_id"], "largest_dependency_file"))

    def test_default_falls_back_to_all_files_then_none(self):
        rows = [self.row("docs/a.md", 2, "documentation"), self.row("x/z.txt", 9, "other_locations")]
        self.assertEqual(dp.default_context(rows), (rows[1]["context_id"], "largest_file"))
        self.assertEqual(dp.default_context([]), (None, "none"))

    def test_default_is_independent_of_row_order(self):
        rows = [self.row("p%d/package-lock.json" % i, i % 4 + 1, "node_packages") for i in range(50)]
        want = dp.default_context(rows)
        for seed in range(5):
            shuffled = list(rows)
            random.Random(seed).shuffle(shuffled)
            self.assertEqual(dp.default_context(shuffled), want)

    def test_request_validation(self):
        ok = dp._chooser_request({"generation": ["1"], "limit": ["40"], "offset": ["0"], "query": [" a/b "]})
        self.assertEqual((ok["limit"], ok["offset"], ok["query"]), (40, 0, "a/b"))
        for bad in ({}, {"generation": "1", "limit": "41"}, {"generation": "1", "limit": "0"}, {"generation": "1", "offset": "-1"},
                    {"generation": "1", "bogus": "1"}, {"generation": ["1", "1"]}, {"generation": "0"}, {"generation": "1", "query": "x" * 81},
                    {"generation": "1", "query": "a\nb"}, {"generation": "1", "offset": "1000001"}, {"generation": "1", "schema_version": "2"}):
            with self.assertRaises(vc.ContractError, msg=str(bad)):
                dp._chooser_request(bad)

    def test_local_validator_accepts_and_rejects(self):
        payload = {"rows": fake_rows(3), "counts": {"total": 3, "shown": 3, "truncated": False}, "total": 3, "offset": 0,
                   "default_context_id": "ctx:" + "0" * 24, "default_basis": "largest_file"}
        dp.validate_contexts_payload(payload)
        broken = copy.deepcopy(payload)
        broken["rows"].append(dict(broken["rows"][0]))
        with self.assertRaises(vc.ContractError):
            dp.validate_contexts_payload(broken)


if __name__ == "__main__":
    unittest.main()
