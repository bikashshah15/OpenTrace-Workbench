"""UIP-04: classifier, grouping, counts, identity, paging and payload bounds of ``app/context_groups.py`` (no server, no network).

Every payload built here is also checked with the frozen UIP-01B validator; none of the synthetic repositories carries a
recorded-repository name.
"""
import hashlib
import os
import unittest

from opentrace_core.app import context_groups as cg
from opentrace_core.app import view_contracts as vc
from opentrace_core.app.workbench_binding import build_binding

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))


class Ticket:
    def __init__(self, generation):
        self.generation = generation


class FakeViews:
    def __init__(self, tab):
        self.tab = tab
        self.calls = 0

    def _project(self, name, **kw):
        self.calls += 1
        return {"tabs": [self.tab]}


class FakeAnalysis:
    """The minimum an analysis exposes to the contexts route: identity, ticket, mode, views, no sealed assessment."""

    def __init__(self, tab, *, digest="sha256:" + "ab" * 32, generation=1, owner="example-org", name="sample-web"):
        self.identity = {"analysis_digest": digest, "repository": {"host": "github.com", "owner": owner, "name": name,
                                                                    "canonical_url": "https://github.com/%s/%s" % (owner, name)},
                         "requested": {"kind": "tag", "text": "v1.0.0", "origin": "url_tree"},
                         "resolved": {"commit_sha": "0123456789abcdef0123456789abcdef01234567"}}
        self.ticket = Ticket(generation)
        self.mode = "captured"
        self.assessment = None
        self.gaps = None
        self.views = FakeViews(tab)
        self.state = "complete"


def tab_of(files, unlocated=(), *, component_total=None):
    """files: {path: [component ids]} -> an adapter ``contexts`` tab (only the fields the model reads)."""
    rows = [{"path": p, "raw_locations": ["/" + p], "normalization_basis": ["syft_root_relative"],
             "components": [{"id": c} for c in ids]} for p, ids in sorted(files.items())]
    located = {c for ids in files.values() for c in ids}
    return {"rows": rows, "unlocated": {"components": [{"id": c} for c in unlocated]},
            "component_total": component_total if component_total is not None else len(located) + len(unlocated)}


def respond(analysis, **params):
    return cg.respond(analysis, {k: [str(v)] for k, v in params.items()})


def code_of(analysis, **params):
    try:
        respond(analysis, **params)
    except vc.ContractError as exc:
        return exc.code, exc.detail_code
    raise AssertionError("expected a ContractError for %r" % (params,))


class Classifier(unittest.TestCase):
    def test_every_rule_and_its_basis(self):
        cases = [("docs/x.md", "documentation", "path_prefix"), ("web/src/a.js", "web", "path_prefix"),
                 (".github/workflows/ci.yml", "github_actions", "path_prefix"),
                 ("requirements.txt", "python_requirements", "manifest_basename"), ("a/requirements-dev.txt", "python_requirements", "manifest_basename"),
                 ("pyproject.toml", "python_requirements", "manifest_basename"), ("Pipfile", "python_requirements", "manifest_basename"),
                 ("Pipfile.lock", "python_requirements", "manifest_basename"), ("x/poetry.lock", "python_requirements", "manifest_basename"),
                 ("setup.py", "python_requirements", "manifest_basename"), ("setup.cfg", "python_requirements", "manifest_basename"),
                 ("go.mod", "go_modules", "manifest_basename"), ("svc/go.sum", "go_modules", "manifest_basename"),
                 ("Cargo.toml", "rust_crates", "manifest_basename"), ("Cargo.lock", "rust_crates", "manifest_basename"),
                 ("pom.xml", "java_build", "manifest_basename"), ("build.gradle", "java_build", "manifest_basename"),
                 ("build.gradle.kts", "java_build", "manifest_basename"), ("gradle.lockfile", "java_build", "manifest_basename"),
                 ("package.json", "node_packages", "manifest_basename"), ("a/package-lock.json", "node_packages", "manifest_basename"),
                 ("yarn.lock", "node_packages", "manifest_basename"), ("pnpm-lock.yaml", "node_packages", "manifest_basename"),
                 ("Dockerfile", "container_files", "manifest_basename"), ("a/Dockerfile.dev", "container_files", "manifest_basename"),
                 ("docker-compose.yml", "container_files", "manifest_basename"), ("docker-compose.yaml", "container_files", "manifest_basename"),
                 ("compose.yaml", "container_files", "manifest_basename"), ("compose.yml", "container_files", "manifest_basename"),
                 ("src/main.rs", "other_locations", "fallback")]
        for path, category, basis in cases:
            self.assertEqual(cg.classify(path), (category, basis), path)

    def test_prefix_precedes_basename(self):
        self.assertEqual(cg.classify("web/package.json")[0], "web")
        self.assertEqual(cg.classify("docs/requirements.txt")[0], "documentation")
        self.assertEqual(cg.classify("docs/package-lock.json")[0], "documentation")
        self.assertEqual(cg.classify(".github/Dockerfile")[0], "github_actions")

    def test_unusual_prefix_forms_classify_by_basename_only(self):
        self.assertEqual(cg.classify("./web/package.json"), ("node_packages", "manifest_basename"))
        self.assertEqual(cg.classify("../docs/requirements.txt"), ("python_requirements", "manifest_basename"))
        self.assertEqual(cg.classify("a//docs/x.md"), ("other_locations", "fallback"))
        self.assertEqual(cg.classify("web//package.json"), ("node_packages", "manifest_basename"))
        self.assertEqual(cg.classify("./docs/readme.md"), ("other_locations", "fallback"))

    def test_unknown_is_other_never_python_and_matching_is_case_sensitive(self):
        for p in ("README.md", "requirements.txt.bak", "Requirements.txt", "dockerfile", "Docs/a.md", "WEB/a.js", "pyproject.toml.orig", "xDockerfile"):
            self.assertEqual(cg.classify(p), ("other_locations", "fallback"), p)

    def test_every_category_is_mapped_to_an_existing_token(self):
        for category in cg.CATEGORY_ORDER:
            self.assertIn(category, vc.CATEGORY_TOKEN)
            self.assertIn(category, cg.LABELS)


class Counts(unittest.TestCase):
    def test_union_versus_membership_overlap_and_root_identity(self):
        files = {"web/a/package-lock.json": ["c1", "c2", "c3"], "web/b/package.json": ["c2", "c4"], "docs/package-lock.json": ["c1", "c9"]}
        a = FakeAnalysis(tab_of(files, unlocated=["u1", "u2"]))
        p = respond(a, generation=1)
        web = next(g for g in p["groups"] if g["category"] == "web")
        self.assertEqual((web["distinct_total"], web["membership_total"]), (4, 5))           # union {c1,c2,c3,c4}; 3 + 2 memberships
        self.assertEqual([f["membership_total"] for f in web["files"]], [3, 2])
        doc = next(g for g in p["groups"] if g["category"] == "documentation")
        self.assertEqual((doc["distinct_total"], doc["membership_total"]), (2, 2))
        root = p["root"]
        self.assertEqual((root["located_distinct_total"], root["unlocated_total"], root["distinct_total"]), (5, 2, 7))   # c1..c4,c9 + 2
        self.assertEqual(root["membership_total"], 7)                                           # 5 + 2 located memberships, a sum
        self.assertEqual(root["distinct_total"], a.views.tab["component_total"])
        unl = p["groups"][-1]
        self.assertEqual((unl["kind"], unl["category"], unl["token"], unl["files"], unl["distinct_total"], unl["membership_total"]),
                         ("unlocated", None, "neutral", [], 2, 2))
        self.assertEqual(unl["label"], "Unlocated components")

    def test_unlocated_group_only_when_present_and_never_invents_files(self):
        p = respond(FakeAnalysis(tab_of({"go.mod": ["a"]})), generation=1)
        self.assertEqual([g["kind"] for g in p["groups"]], ["located"])
        only = respond(FakeAnalysis(tab_of({}, unlocated=["x", "y", "z"])), generation=1)
        self.assertEqual([(g["kind"], g["files"], g["distinct_total"]) for g in only["groups"]], [("unlocated", [], 3)])
        self.assertEqual((only["root"]["located_distinct_total"], only["root"]["distinct_total"], only["root"]["membership_total"]), (0, 3, 0))

    def test_zero_location_repository_is_an_empty_valid_map(self):
        p = respond(FakeAnalysis(tab_of({}, component_total=0)), generation=1)
        self.assertEqual((p["groups"], p["counts"], p["root"]["distinct_total"]), ([], {"total": 0, "shown": 0, "truncated": False}, 0))

    def test_inconsistent_projection_totals_fail_loudly(self):
        self.assertEqual(code_of(FakeAnalysis(tab_of({"go.mod": ["a"]}, component_total=9)), generation=1)[0], "projection_failed")

    def test_component_with_two_locations_counts_once_at_root_and_in_each_group(self):
        a = FakeAnalysis(tab_of({"web/p.json": ["s"], "docs/p.json": ["s"]}))
        p = respond(a, generation=1)
        self.assertEqual(p["root"]["located_distinct_total"], 1)
        self.assertEqual(sorted((g["category"], g["distinct_total"]) for g in p["groups"]), [("documentation", 1), ("web", 1)])
        self.assertEqual(p["root"]["membership_total"], 2)


class Identity(unittest.TestCase):
    def test_ids_are_stable_across_generations_and_change_with_the_digest(self):
        tab = tab_of({"web/a.json": ["a"], "go.mod": ["b"]}, unlocated=["u"])
        one = respond(FakeAnalysis(tab, generation=1), generation=1)
        two = respond(FakeAnalysis(tab, generation=7), generation=7)
        other = respond(FakeAnalysis(tab, digest="sha256:" + "cd" * 32), generation=1)

        def ids(p):
            return [g["group_id"] for g in p["groups"]] + [f["file_id"] for g in p["groups"] for f in g["files"]]
        self.assertEqual(ids(one), ids(two))
        self.assertTrue(set(ids(one)).isdisjoint(ids(other)))
        self.assertEqual(len(set(ids(one))), len(ids(one)))
        self.assertTrue(all(i.startswith(("grp:", "ctx:")) for i in ids(one)))

    def test_file_and_group_derivations_follow_the_frozen_opaque_id(self):
        a = FakeAnalysis(tab_of({"web/a.json": ["a"]}))
        p = respond(a, generation=1)
        d = a.identity["analysis_digest"]
        self.assertEqual(p["groups"][0]["group_id"], vc.opaque_id("grp", d, "group", "web"))
        self.assertEqual(p["groups"][0]["files"][0]["file_id"], vc.opaque_id("ctx", d, "file", "web/a.json"))

    def test_every_located_file_carries_a_dependency_context_id_equal_to_its_file_id(self):
        p = respond(FakeAnalysis(tab_of({"docs/x.md": ["a"], ".github/w.yml": ["b"], "src/o.rs": ["c"], "go.mod": ["d"]})), generation=1)
        for g in p["groups"]:
            for f in g["files"]:
                self.assertEqual(f["dependency_context_id"], f["file_id"])

    def test_root_identity_comes_from_the_binding_not_from_constants(self):
        p = respond(FakeAnalysis(tab_of({"go.mod": ["a"]}), owner="acme", name="widgets"), generation=1)
        self.assertEqual((p["root"]["name"], p["root"]["canonical_url"]), ("acme/widgets", "https://github.com/acme/widgets"))
        self.assertEqual(p["groups"][0]["files"][0]["revision_link"]["href"],
                         "https://github.com/acme/widgets/blob/0123456789abcdef0123456789abcdef01234567/go.mod")


class Ordering(unittest.TestCase):
    def test_all_ten_categories_plus_unlocated_is_eleven_groups_in_enum_order(self):
        files = {"docs/a.md": ["1"], "web/a.js": ["2"], "package.json": ["3"], "requirements.txt": ["4"], "go.mod": ["5"], "Cargo.toml": ["6"],
                 "pom.xml": ["7"], ".github/w.yml": ["8"], "Dockerfile": ["9"], "src/x.c": ["10"]}
        p = respond(FakeAnalysis(tab_of(files, unlocated=["u"])), generation=1)
        self.assertEqual(len(p["groups"]), 11)
        self.assertEqual([g["category"] for g in p["groups"]], list(cg.CATEGORY_ORDER) + [None])
        self.assertEqual([g["label"] for g in p["groups"]][:3], ["Documentation", "Web application", "Node packages"])

    def test_files_sort_by_code_point_and_only_present_categories_appear(self):
        p = respond(FakeAnalysis(tab_of({"web/b.json": ["1"], "web/B.json": ["2"], "web/a.json": ["3"], "web/é.json": ["4"]})), generation=1)
        self.assertEqual([f["path"] for f in p["groups"][0]["files"]], ["web/B.json", "web/a.json", "web/b.json", "web/é.json"])
        self.assertEqual(len(p["groups"]), 1)


def big_analysis(n_python=130):
    files = {"web/p%03d/package.json" % i: ["w%d" % i] for i in range(200)}
    files.update({"svc/requirements-%03d.txt" % i: ["p%d" % i, "shared"] for i in range(n_python)})
    files.update({"docs/d%03d.md" % i: ["d%d" % i] for i in range(120)})
    files.update({"pkg%03d/go.mod" % i: ["g%d" % i] for i in range(150)})
    return FakeAnalysis(tab_of(files, unlocated=["u1", "u2"]))


class Paging(unittest.TestCase):
    def setUp(self):
        self.a = big_analysis()
        self.p0 = respond(self.a, generation=1)
        self.py = next(g for g in self.p0["groups"] if g["category"] == "python_requirements")

    def group(self, **kw):
        return respond(self.a, generation=1, group_id=self.py["group_id"], **kw)

    def test_initial_page_is_twenty_per_group_with_honest_hidden_totals(self):
        self.assertEqual(self.py["files_counts"], {"total": 130, "shown": 20, "truncated": True})
        self.assertEqual(self.py["files_offset"], 0)
        self.assertEqual(self.p0["counts"], {"total": 5, "shown": 5, "truncated": False})
        self.assertEqual(sum(f["membership_total"] for f in self.py["files"]), 40)             # 20 files x (own + shared)
        self.assertEqual(self.py["membership_total"], 260)
        self.assertEqual(self.py["distinct_total"], 131)                                      # 130 own + one shared

    def test_files_limit_without_group_bounds_every_group(self):
        p = respond(self.a, generation=1, files_limit=5)
        self.assertTrue(all(len(g["files"]) <= 5 for g in p["groups"]))
        self.assertEqual(max(len(g["files"]) for g in p["groups"]), 5)
        self.assertEqual(p["groups"][-1]["kind"], "unlocated")

    def test_group_request_returns_only_that_group_with_global_root_totals(self):
        p = self.group(files_offset=20, files_limit=40)
        self.assertEqual(len(p["groups"]), 1)
        self.assertEqual(p["counts"], {"total": 5, "shown": 1, "truncated": True})
        self.assertEqual(p["groups"][0]["files_counts"], {"total": 130, "shown": 40, "truncated": True})
        self.assertEqual(p["groups"][0]["files_offset"], 20)
        self.assertEqual(p["groups"][0]["files"][0]["path"], self.py["files"][0]["path"][:-len("000.txt")] + "020.txt")
        self.assertEqual(p["root"], self.p0["root"])

    def test_offset_boundaries_for_a_nonempty_group(self):
        total = 130
        self.assertEqual(self.group(files_offset=0)["groups"][0]["files_offset"], 0)
        self.assertEqual(len(self.group(files_offset=total - 1)["groups"][0]["files"]), 1)
        for bad in (total, total + 1, 999999):
            self.assertEqual(code_of(self.a, generation=1, group_id=self.py["group_id"], files_offset=bad), ("invalid_request", "files_offset_out_of_range"))
        self.assertEqual(code_of(self.a, generation=1, group_id=self.py["group_id"], files_offset=1000001)[0], "invalid_request")

    def test_offset_need_not_be_aligned_to_the_limit(self):
        p = self.group(files_offset=7, files_limit=20)
        self.assertEqual((p["groups"][0]["files_offset"], len(p["groups"][0]["files"])), (7, 20))

    def test_unlocated_group_accepts_only_offset_zero(self):
        unl = self.p0["groups"][-1]
        self.assertEqual(respond(self.a, generation=1, group_id=unl["group_id"], files_offset=0)["groups"][0]["files"], [])
        self.assertEqual(code_of(self.a, generation=1, group_id=unl["group_id"], files_offset=1), ("invalid_request", "files_offset_out_of_range"))

    def test_limit_bounds_and_forms_that_are_refused(self):
        for ok in (1, 20, 40):
            self.assertLessEqual(len(self.group(files_limit=ok)["groups"][0]["files"]), ok)
        for bad in (0, 41):
            self.assertEqual(code_of(self.a, generation=1, files_limit=bad)[0], "invalid_request")
        self.assertEqual(code_of(self.a, generation=1, files_offset=0), ("invalid_request", "files_offset_requires_group"))
        self.assertEqual(code_of(self.a, generation=1, files_offset=20), ("invalid_request", "files_offset_requires_group"))
        self.assertEqual(code_of(self.a, generation=1, group_id="grp:" + "0" * 24), ("invalid_request", "unknown_group"))

    def test_unknown_and_duplicate_parameters_and_versions(self):
        self.assertEqual(code_of(self.a, generation=1, nope=1), ("invalid_request", "unknown_parameter"))
        with self.assertRaises(vc.ContractError) as dup:
            cg.respond(self.a, {"generation": ["1"], "files_limit": ["5", "6"]})
        self.assertEqual(dup.exception.detail_code, "duplicate_parameter")
        self.assertEqual(code_of(self.a, generation=1, schema_version=2)[0], "unsupported_version")
        self.assertEqual(code_of(self.a, generation="x")[0], "invalid_request")
        with self.assertRaises(vc.ContractError):
            cg.respond(self.a, {})                                                          # generation is required

    def test_stale_generation_and_selected_echo(self):
        self.assertEqual(code_of(self.a, generation=2)[0], "stale_generation")
        one = respond(self.a, generation=1, selected=self.py["group_id"])
        self.assertEqual(one["selected_id"], self.py["group_id"])
        fid = self.py["files"][3]["file_id"]
        self.assertEqual(respond(self.a, generation=1, selected=fid)["selected_id"], fid)
        self.assertIsNone(respond(self.a, generation=1, selected="grp:" + "1" * 24)["selected_id"])      # well-formed, not returned -> null
        late = self.group(files_offset=100, selected=self.p0["groups"][0]["group_id"])                  # a group not in this page -> null
        self.assertIsNone(late["selected_id"])

    def test_a_group_page_validates_with_the_frozen_validator_and_counts_are_honest(self):
        for offset in (0, 40, 120):
            p = self.group(files_offset=offset, files_limit=40)
            vc.validate_payload("contexts", p, request={"generation": 1})
            fc = p["groups"][0]["files_counts"]
            self.assertEqual(fc["shown"], len(p["groups"][0]["files"]))
            self.assertEqual(fc["truncated"], fc["shown"] < fc["total"])

    def test_model_is_built_once_per_analysis(self):
        respond(self.a, generation=1)
        respond(self.a, generation=1, group_id=self.py["group_id"], files_offset=20)
        self.assertEqual(self.a.views.calls, 1)


class Bounds(unittest.TestCase):
    def test_large_map_stays_within_the_payload_ceiling(self):
        files = {}
        for cat_prefix in ("docs/", "web/", ".github/", "pk/requirements-", "pk/go-"):
            for i in range(130):
                files["%s%04d%s" % (cat_prefix, i, ".txt" if "requirements" in cat_prefix else ".md")] = ["c%s%d" % (cat_prefix[:2], i)]
        a = FakeAnalysis(tab_of(files))
        self.assertGreaterEqual(len(files), 600 - 100)
        body = cg.encode_response(respond(a, generation=1, files_limit=40))
        self.assertLess(len(body), cg.RESPONSE_MAX_BYTES)

    def test_a_payload_over_the_ceiling_is_response_too_large_never_truncated(self):
        pad = "k" * 420
        bases = {"documentation": "docs/%s/a%03d.md", "web": "web/%s/a%03d.js", "node_packages": "%s/n%03d/package.json",
                 "python_requirements": "%s/n%03d/requirements.txt", "go_modules": "%s/n%03d/go.mod", "rust_crates": "%s/n%03d/Cargo.toml",
                 "java_build": "%s/n%03d/pom.xml", "github_actions": ".github/%s/a%03d.yml", "container_files": "%s/n%03d/Dockerfile",
                 "other_locations": "%s/n%03d/x.rs"}
        files = {}
        for cat, pattern in bases.items():
            for i in range(40):
                path = pattern % (pad, i)
                self.assertEqual(cg.classify(path)[0], cat)
                files[path] = ["c-%s-%d" % (cat, i)]
        a = FakeAnalysis(tab_of(files))
        self.assertEqual(code_of(a, generation=1, files_limit=40), ("response_too_large", "bound_exceeded"))
        small = respond(a, generation=1, files_limit=1)                                            # the contract's last retry step fits
        self.assertTrue(all(len(g["files"]) <= 1 for g in small["groups"]))
        self.assertLess(len(cg.encode_response(small)), cg.RESPONSE_MAX_BYTES)

    def test_hostile_text_stays_data_and_links_use_the_percent_encoded_pinned_path(self):
        hostile = ["web/<img src=x onerror=alert(1)>.json", "docs/\"><script>alert(1)</script>.md", "javascript:alert(1)", "web/a b/%2e%2e/c#frag?q=1"]
        a = FakeAnalysis(tab_of({p: ["h%d" % i] for i, p in enumerate(hostile)}))
        p = respond(a, generation=1)
        paths = [f["path"] for g in p["groups"] for f in g["files"]]
        self.assertEqual(sorted(paths), sorted(hostile))                                           # not rewritten or sanitized
        for g in p["groups"]:
            for f in g["files"]:
                href = f["revision_link"]["href"]
                self.assertTrue(href.startswith("https://github.com/example-org/sample-web/blob/0123456789abcdef"))
                self.assertNotIn("<", href)
                self.assertNotIn(" ", href)
        self.assertEqual([f["revision_link"]["text"] for g in p["groups"] for f in g["files"]], paths)

    def test_a_path_that_would_leave_the_pinned_prefix_gets_an_inert_link_and_stays_recorded_unchanged(self):
        """UIP-04-IR-01: dot segments are reinterpreted by URL parsers; the link is withheld, the evidence is not rewritten."""
        from urllib.parse import urlsplit
        prefix = "https://github.com/example-org/sample-web/blob/0123456789abcdef0123456789abcdef01234567/"
        dotted = ["../../../../attacker/other/blob/main/README.md", "web/../../x.json", "web/./x.json", "web/..", "docs/x/.", "./docs/x.md", "../docs/x.md"]
        ok = ["web/a b/%2e%2e/c#frag?q=1.json", ".github/workflows/ci.yml", "docs/..hidden.md", "docs/a...b.md", "web/v1.2/x.json", "web/é\\x.json", "docs//x.md"]
        a = FakeAnalysis(tab_of({p: ["c%d" % i] for i, p in enumerate(dotted + ok)}))
        p = respond(a, generation=1, files_limit=40)
        files = {f["path"]: f for g in p["groups"] for f in g["files"]}
        self.assertEqual(sorted(files), sorted(dotted + ok))                                      # recorded paths unchanged, none dropped
        for path in dotted:
            self.assertIsNone(files[path]["revision_link"]["href"], path)
            self.assertEqual(files[path]["revision_link"]["text"], path)
        for path in ok:
            href = files[path]["revision_link"]["href"]
            self.assertIsNotNone(href, path)
            u = urlsplit(href)
            self.assertEqual((u.scheme, u.netloc, u.query, u.fragment), ("https", "github.com", "", ""), path)
            self.assertTrue(href.startswith(prefix), path)
            self.assertNotIn("/./", u.path); self.assertNotIn("/../", u.path); self.assertFalse(u.path.endswith(("/.", "/..")))

    def test_unrepresentable_paths_are_a_typed_failure_nothing_dropped(self):
        for bad in ("", "a" * 513, "web/ctl\x01char.json", "web/new\nline.json"):
            tab = tab_of({"go.mod": ["a"], "web/ok.json": ["b"]})
            tab["rows"].append({"path": bad or "x", "raw_locations": ["/" + bad if bad else ""], "normalization_basis": ["syft_recorded_path"], "components": [{"id": "z"}]})
            tab["component_total"] = 3
            self.assertEqual(code_of(FakeAnalysis(tab), generation=1), ("projection_failed", "unrepresentable_path"), repr(bad)[:20])
        tab = tab_of({"web/ok.json": ["b"]})
        tab["rows"][0]["raw_locations"] = ["/web/ok.json", "/web/\x07bell.json"]
        self.assertEqual(code_of(FakeAnalysis(tab), generation=1), ("projection_failed", "unrepresentable_path"))

    def test_raw_locations_are_capped_at_five_with_an_honest_total(self):
        tab = tab_of({"web/p.json": ["a"]})
        tab["rows"][0]["raw_locations"] = ["/web/p%d.json" % i for i in range(8)]
        f = respond(FakeAnalysis(tab), generation=1)["groups"][0]["files"][0]
        self.assertEqual((len(f["raw_locations"]), f["raw_locations_total"]), (5, 8))

    def test_one_group_repository(self):
        p = respond(FakeAnalysis(tab_of({"go.mod": ["a"], "svc/go.sum": ["a", "b"]})), generation=1)
        self.assertEqual((len(p["groups"]), p["counts"]), (1, {"total": 1, "shown": 1, "truncated": False}))
        one = respond(FakeAnalysis(tab_of({"go.mod": ["a"]})), generation=1, group_id=p["groups"][0]["group_id"])
        self.assertEqual(one["counts"], {"total": 1, "shown": 1, "truncated": False})


class Binding(unittest.TestCase):
    def test_binding_has_the_frozen_shape_and_no_invented_assessment(self):
        a = FakeAnalysis(tab_of({"go.mod": ["a"]}))
        b = build_binding(a)
        self.assertEqual(set(b), {"analysis_digest", "repository", "commit_sha", "requested_ref", "generation", "mode", "assessment"})
        self.assertIsNone(b["assessment"])
        self.assertEqual(b["requested_ref"], {"kind": "tag", "text": "v1.0.0"})

    def test_discovery_assessment_wins_then_legacy(self):
        class Sealed:
            schema = "opentrace.bombridge_assessment/1"

            def __init__(self, seed):
                self.validation_digest = hashlib.sha256(seed.encode()).hexdigest()
                self.binding = {"bundle_sha256": hashlib.sha256((seed + "b").encode()).hexdigest(), "configuration": "config:" + seed}
        a = FakeAnalysis(tab_of({"go.mod": ["a"]}))
        a.assessment = Sealed("legacy")
        self.assertEqual(build_binding(a)["assessment"]["kind"], "legacy")
        a.gaps = {"status": "compared", "assessment": Sealed("disc")}
        self.assertEqual(build_binding(a)["assessment"]["kind"], "discovery")
        a.gaps = {"status": "not_compared"}
        self.assertEqual(build_binding(a)["assessment"]["kind"], "legacy")
        a.assessment.validation_digest = None
        self.assertIsNone(build_binding(a)["assessment"])


class NoHardCodedRepository(unittest.TestCase):
    """Contract section 7: the production identity/grouping modules know no repository by name and have no Python fallback."""

    def test_modules_contain_no_literal_repository_name_or_python_fallback(self):
        for rel in ("src/core/opentrace_core/app/context_groups.py", "src/core/opentrace_core/app/workbench_binding.py"):
            with open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
                text = handle.read().lower()
            for token in ("frigate", "blakeblackshear", "groupfor", "python / detector"):
                self.assertNotIn(token, text, "%s contains %r" % (rel, token))
        self.assertEqual(cg.classify("src/unknown.bin")[0], "other_locations")


class ProtectedSurfaces(unittest.TestCase):
    """Blob SHA-1s of surfaces that no later task may change without an authorized, recorded pin refresh (contract section 3, C3 of UIP-04).

    Originally recorded at START_SHA 9cd07bc. Three pins were refreshed on 2026-11-15 after verifying the authorized diffs (record
    `.context/logs/UIP-08_PIN_REFRESH_2026-11-15.md`); the other four remain the UIP-04 values. Historical -> current:
      app/views.py          c26b1336... -> 6e014d60...  UIP-08 (additive read-only BOM projection methods; no line removed)
      app/view_contracts.py 6210a035... -> b96e91e4...  UIP-07C Cisco amendment A4 (aibom partial-stage outputs optional)
      live/runner.py        61c1da90... -> 7044e1b2...  UIP-07C Cisco A2 (AI-BOM phase config, disclosure block, aibom events)
      app/views.py          7024c7df... -> fd1a686f...  UIP-13 (live_capabilities reads the computed ai_model state; the single authorized pin refresh, record .context/logs/UIP-13_IMPLEMENTATION_2026-11-16.md)
      app/views.py          fd1a686f... -> 2799ff2c...  Stage 4 (the `web-new` preference removed, `str(n["id"])` tie-break; record .context/logs/STAGE4_PIN_REFRESH_2026-11-17.md; owner-authorized 2026-11-17)
    Expected values are literals on purpose: no dynamic recomputation."""
    PINNED = {"src/core/opentrace_core/app/views.py": "2799ff2cc4283c5870e9e67a6f53bda25e587e4a",
              "src/core/opentrace_core/bombridge_adapter/projection.py": "8eaee3fc02636fb403522ef60a94331123705be7",
              "src/core/opentrace_core/app/view_contracts.py": "b96e91e45381679158d8ba49d87a4dd3162d032d",
              "src/core/opentrace_core/session/service.py": "e7fc8640518d0649b05c098433d05404c444f30b",
              "src/core/opentrace_core/live/runner.py": "604dbcbad0e6f52f9b9d9f4153fcda38db1921ec",
              "contracts/workbench/v1/limits.json": "264a49146c08ed20d740dd78c87a415276426658",
              "contracts/workbench/v1/schemas/contexts.schema.json": "585c5f3731b32552363a1809b68e6bde53302382"}

    def test_protected_files_are_byte_identical_to_the_start_sha(self):
        for rel, want in self.PINNED.items():
            with open(os.path.join(ROOT, rel), "rb") as handle:
                data = handle.read()
            self.assertEqual(hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest(), want, rel)


if __name__ == "__main__":
    unittest.main()
