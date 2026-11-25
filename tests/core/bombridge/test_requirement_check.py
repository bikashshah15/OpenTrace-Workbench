"""Controlled cases for inventory_coverage.requirement_represented/1.

Everything here is SYNTHETIC (origin 'illustrative'): invented package names, invented inventories.
Nothing is derived from the Frigate capture.
"""
import hashlib
import unittest

from opentrace_core.bombridge.adapters import (inventory_lookup_observation, normalize_name, parse_requirement_line,
                                requirement_declaration_observation, wheel_identity)
from opentrace_core.bombridge.pipeline import run_doc

REQ_PATH = "synthetic/requirements.txt"
I = "illustrative"
S = "scope:synthetic"
REV = "synthetic-rev-1"


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def lib(name, version="1.0", loc="/" + REQ_PATH, purl=True):
    c = {"bom-ref": f"ref-{name}-{version}", "type": "library", "name": name, "version": version,
         "properties": [{"name": "syft:package:type", "value": "python"}, {"name": "syft:location:0:path", "value": loc}]}
    if purl:
        c["purl"] = f"pkg:pypi/{name.lower()}@{version}"
    return c


def inventory(libs, req_text, listed=True, file_hash=None):
    comps = list(libs)
    if listed:
        comps.append({"bom-ref": "f1", "type": "file", "name": "/synthetic/root/" + REQ_PATH,
                      "hashes": [{"alg": "SHA-256", "content": file_hash or sha(req_text)}]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.7", "metadata": {"tools": {"components": [{"name": "synthetic-gen", "version": "0"}]}},
            "components": comps}


def case(*args, **kw):
    """Build and run a synthetic bundle with one representation assertion; return its finding."""
    return run_doc(make_doc(*args, **kw))["findings"][0]


def make_doc(req_text, libs, target="foo_bar", listed=True, file_hash=None, mutate=None, contract=None, inv_sha_in_assertion=None):
    cdx = inventory(libs, req_text, listed, file_hash)
    raw = "synthetic-inventory-" + str(len(libs))
    raw_sha = sha(raw)
    E = lambda k: f"{S}::inv:cur::{k}"
    ent = lambda k, kind, extra=None: {"entity_id": E(k), "kind": kind, "name": k, "version": None, "source": {"inventory_id": "inv:cur", "source_ref": k},
                                       "identity_matches": [], "origin": I, **(extra or {})}
    norm = normalize_name(target)
    inv_rec = {"inventory_id": "inv:synth", "kind": "sbom", "generator": "synthetic", "source_file": "n/a", "intended_coverage": ["synthetic"], "origin": I}
    if contract:
        inv_rec["coverage_contract"] = contract
    d = {"schema": "bombridge.bundle/2", "origin": I, "notice": "SYNTHETIC ILLUSTRATIVE test data",
         "capture": {"scope_id": S, "repository": {"url": "https://example.invalid/synthetic", "revision": REV}, "build": None, "configuration": None,
                     "model": None, "execution": None, "unknown": ["build", "configuration", "model", "execution"], "unavailable": [],
                     "inventories": [inv_rec], "origin": I},
         "entities": [ent("reqfile", "source_file"),
                      ent("req", "requirement", {"requirement": {"file": REQ_PATH, "name": target, "normalized_name": norm}}),
                      ent("inv", "inventory", {"inventory_id": "inv:synth"})],
         "assertions": [{"assertion_id": "r1", "family": "inventory_coverage", "subject": E("req"), "predicate": "represents_requirement",
                         "object": {"inventory_entity": E("inv"), "inventory_id": "inv:synth", "inventory_sha256": inv_sha_in_assertion or raw_sha},
                         "declared_in": {"inventory_id": "inv:cur", "source_ref": "synthetic"}, "scope_id": S, "scope": {"revision": REV}, "origin": I}],
         "evidence": [
             {"evidence_id": "d1", "scope_id": S, "method": "m", "tool": "t", "source_locator": REQ_PATH, "scope": {"revision": REV},
              "observation": requirement_declaration_observation(req_text, REQ_PATH, sha(req_text), target),
              "limitations": ["synthetic"], "underlying_source": "src:synthetic-req", "origin": I},
             {"evidence_id": "l1", "scope_id": S, "method": "m", "tool": "t", "source_locator": "inv", "scope": {"revision": REV},
              "observation": inventory_lookup_observation(cdx, raw_sha, norm, REQ_PATH),
              "limitations": ["synthetic"], "underlying_source": "tool:synthetic-inv", "origin": I}]}
    if mutate:
        mutate(d)
    return d


REQ = "foo_bar @ https://example.invalid/foo_bar-2.0-py3-none-any.whl ; sys_platform == 'linux'\nother==1.0\n"


class Adapters(unittest.TestCase):
    def test_normalization_is_pep503(self):
        for n in ("Foo_Bar", "foo.bar", "FOO--bar", "foo-bar"):
            self.assertEqual(normalize_name(n), "foo-bar")
        self.assertNotEqual(normalize_name("foobar"), "foo-bar")

    def test_line_forms_and_markers_preserved(self):
        p = parse_requirement_line("tflite_runtime @ https://x/y/tflite_runtime-2.17.1-cp311-cp311-linux_x86_64.whl; platform_machine == 'x86_64'")
        self.assertEqual((p["form"], p["marker"], p["name"]), ("direct_url", "platform_machine == 'x86_64'", "tflite_runtime"))
        self.assertEqual((p["wheel"]["version"], p["wheel"]["platform_tag"]), ("2.17.1", "linux_x86_64"))
        self.assertEqual(parse_requirement_line("a == 1.2.*")["form"], "wildcard_pin")
        self.assertEqual(parse_requirement_line("a == 1.2")["form"], "exact_pin")
        self.assertEqual(parse_requirement_line("a>=1,<2")["form"], "range")
        self.assertEqual(parse_requirement_line("fastapi[standard] == 0.1.*")["extras"], "[standard]")
        self.assertEqual(parse_requirement_line("git+https://h/r#egg=py3nvml")["name"], "py3nvml")
        self.assertEqual(parse_requirement_line("-r other.txt")["form"], "unsupported")
        self.assertEqual(parse_requirement_line("a >>> 2")["form"], "unsupported")
        self.assertIsNone(parse_requirement_line("  # comment"))
        self.assertIsNone(wheel_identity("https://x/not-a-wheel.tar.gz"))


class Representation(unittest.TestCase):
    def test_normalized_name_match_supports_but_not_version(self):
        f = case(REQ, [lib("foo-bar", "9.9")])  # declared wheel is 2.0; inventory says 9.9
        self.assertEqual((f["state"], f["category"]), ("supported", "requirement_represented"))
        self.assertIn("version", f["match_granularity"]["not_established"])
        self.assertEqual(f["evaluation"], "illustrative assertion vs illustrative evidence")

    def test_genuine_non_match_in_fully_parsed_inventory_is_contradicted_gap(self):
        f = case(REQ, [lib("something-else"), lib("other")])
        self.assertEqual((f["state"], f["category"], f["coverage_contract"]["established"]), ("contradicted", "inventory_coverage_gap", False))
        self.assertIn("not a completeness defect", f["rationale"])
        self.assertIn("establish whether this generator", f["next_action"])

    def test_completeness_defect_only_with_explicit_contract_covering_the_form(self):
        c = {"established": True, "declaration_forms": ["direct_url"], "source": "synthetic owner statement"}
        self.assertEqual(case(REQ, [lib("other")], contract=c)["category"], "completeness_defect")
        c2 = {"established": True, "declaration_forms": ["exact_pin"]}
        self.assertEqual(case(REQ, [lib("other")], contract=c2)["category"], "inventory_coverage_gap")
        self.assertEqual(case(REQ, [lib("other")], contract={"established": False, "declaration_forms": ["direct_url"]})["category"], "inventory_coverage_gap")

    def test_similar_looking_names_do_not_match(self):
        libs = [lib(n) for n in ("foo-baz", "foobar", "foo-bar-extra", "xfoo-bar", "foo")]
        f = case(REQ, libs)
        self.assertEqual(f["state"], "contradicted")

    def test_other_ecosystem_with_same_name_does_not_match(self):
        npm = {"bom-ref": "n1", "type": "library", "name": "foo-bar", "version": "1", "purl": "pkg:npm/foo-bar@1"}
        self.assertEqual(case(REQ, [npm])["state"], "contradicted")

    def test_ambiguous_identity_is_unverifiable(self):
        f = case(REQ, [lib("foo-bar", "1.0"), lib("Foo_Bar", "2.0", loc="/other/req.txt")])
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["ambiguous_identity"]))
        same = case(REQ, [lib("foo-bar", "1.0"), lib("foo-bar", "1.0", loc="/other/req.txt")])  # one identity listed twice
        self.assertEqual(same["state"], "supported")

    def test_incomplete_inventory_parse_never_gives_a_definite_non_match(self):
        odd = {"bom-ref": "u1", "type": "library", "name": "mystery"}  # no purl, no ecosystem
        f = case(REQ, [lib("other"), odd])
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["inventory_parse_incomplete"]))

    def test_unsupported_requirement_line_is_unverifiable(self):
        f = case("foo_bar >>> 2\n", [lib("other")])
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["requirement_identity_insufficient"]))
        self.assertEqual(case("-r other.txt\n", [lib("other")])["state"], "unverifiable")

    def test_requirement_not_declared_in_file_is_unverifiable(self):
        self.assertEqual(case("other==1.0\n", [lib("other")])["reason_codes"], ["requirement_identity_insufficient"])

    def test_markers_are_preserved_not_evaluated(self):
        f = case(REQ, [lib("other")])
        self.assertIn("sys_platform == 'linux'", f["used_evidence"][0]["reason"])


class Binding(unittest.TestCase):
    def test_scan_file_hash_differs_excludes_the_lookup(self):
        f = case(REQ, [lib("foo-bar")], file_hash=sha("a different file"))
        self.assertEqual(f["state"], "unverifiable")
        self.assertEqual([x["reason_code"] for x in f["excluded_evidence"]], ["scan_file_differs"])

    def test_inventory_not_listing_the_file_cannot_support_or_contradict(self):
        for libs in ([lib("foo-bar")], [lib("other")]):
            f = case(REQ, libs, listed=False)
            self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["scan_binding_unsubstantiated"]))

    def test_lookup_of_a_different_inventory_is_excluded(self):
        f = case(REQ, [lib("foo-bar")], inv_sha_in_assertion="0" * 64)
        self.assertEqual(f["state"], "unverifiable")
        self.assertEqual(f["excluded_evidence"][0]["reason_code"], "inventory_binding_mismatch")

    def test_evidence_from_another_revision_is_excluded_not_contradicting(self):
        def mutate(d):
            d["evidence"][1]["scope"]["revision"] = "another-rev"
        f = case(REQ, [lib("other")], mutate=mutate)
        self.assertEqual((f["state"], f["excluded_evidence"][0]["reason_code"]), ("unverifiable", "scope_mismatch"))

    def test_assertion_without_revision_is_unverifiable(self):
        def mutate(d):
            d["assertions"][0]["scope"] = {}
        f = case(REQ, [lib("other")], mutate=mutate)
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["assertion_scope_incomplete"]))

    def test_summary_separates_resolved_from_unresolved(self):
        d_res = run_doc(make_doc(REQ, [lib("other")]))
        b = d_res["summary"]["illustrative"]["illustrative assertion vs illustrative evidence"]
        self.assertEqual((b["resolved"], b["unresolved"], b["states"]["contradicted"]), (1, 0, 1))


if __name__ == "__main__":
    unittest.main()
