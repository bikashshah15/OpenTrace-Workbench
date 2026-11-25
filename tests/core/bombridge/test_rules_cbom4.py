"""UIP-12: rule crypto_attribution.operation_declared_in_cbom/4 (synthetic bundles; offline). /2 and /3 are checked unchanged.

SYNTHETIC: every document, source excerpt and manifest below is written by the test. Nothing here is a captured or live result.
"""
import hashlib
import json
import pathlib
import unittest

from opentrace_core.bombridge import cryptoscan, rules, rules_cbom, rules_cbom3, rules_cbom4
from opentrace_core.bombridge.cbom_bundle import cbom_records
from opentrace_core.bombridge.pipeline import run_doc

REV = "0123456789abcdef0123456789abcdef01234567"
S, INV = "scope:c", "inv:cbom"
FILE = "pkg/model.py"
SRC = pathlib.Path(__file__).resolve().parents[3] / "src/core/opentrace_core/bombridge"
GOOD = {k: True for k in rules_cbom4.REQUIRED_CHECKS}


def cdoc(assets, *, spec="1.6", producer=("cdxgen", "12.9.0"), libs=()):
    comps = []
    for a in assets:
        name = a["name"]
        comps.append({"type": "cryptographic-asset", "bom-ref": a.get("ref", f"crypto/algorithm/{name}"), "name": name,
                      "cryptoProperties": {"assetType": a.get("asset_type", "algorithm"), "algorithmProperties": {"primitive": a.get("primitive", "hash")}},
                      "evidence": {"occurrences": [{"location": o.get("file", FILE), "line": o["line"], "offset": 4, "additionalContext": o.get("ctx", "hashlib.sha256 in f")}
                                                   for o in a.get("occ", [])]}})
    comps += [{"type": "library", "name": n, "purl": f"pkg:pypi/{n}"} for n in libs]
    return {"bomFormat": "CycloneDX", "specVersion": spec, "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000010", "version": 1,
            "metadata": {"tools": {"components": [{"type": "application", "name": producer[0], "version": producer[1]}]},
                         "component": {"type": "application", "bom-ref": "s", "name": "subject", "version": REV}},
            "components": comps, "compositions": [{"aggregate": "incomplete", "assemblies": []}]}


def sha(d):
    return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()


def manifest(d):
    return {"schema": "bombridge.acquisition/1", "repository": "https://example.invalid/x", "revision": REV, "inputs": [{"path": FILE, "sha256": "a" * 64}],
            "tree_differs_from_revision": False, "generator": {"name": "cdxgen", "version": "12.9.0", "invocation": "SYNTHETIC", "third_party": True},
            "output_sha256": sha(d), "limitations": ["SYNTHETIC"]}


def resolution(call="python:hashlib.sha256", checks="good", **kw):
    r = {"call": call, "algorithm_source": "function_name", "algorithm_literal": None, "binding": "module_level_import", "binding_status": "unique_module_level",
         "collector": "test", "checks": dict(GOOD) if checks == "good" else checks}
    r.update(kw)
    return r


def finding(d, *, alg="sha256", excerpt="h = hashlib.sha256(b'x')", lines=(9, 11), res="default", file=FILE, inv_sha=None, producer="default", doc_rev=REV, scope_rev=REV, version=4):
    ents, ev, inv = cbom_records(d, sha(d), scope_id=S, inventory_id=INV, origin="illustrative", evidence_id="e-cbom", source_file="x.json", manifest=manifest(d),
                                 repository_url="https://example.invalid/x")
    subj = f"{S}::src::loc"
    entities = ents + [{"entity_id": subj, "kind": "code_location", "name": "f", "version": None, "source": {"inventory_id": "src", "source_ref": "loc"}, "identity_matches": [], "origin": "illustrative"}]
    obs = {"kind": "source_excerpt", "artifact": {"locator": file}, "lines": list(lines), "excerpt": excerpt, "file_sha256": "0" * 64}
    r = resolution() if res == "default" else res
    if r is not None:
        obs["resolution"] = r
    evidence = [ev, {"evidence_id": "e-src", "scope_id": S, "method": "m", "tool": "t", "source_locator": file, "scope": {"revision": scope_rev}, "observes": [subj],
                     "observation": obs, "limitations": [], "underlying_source": "src:file", "origin": "illustrative"}]
    prod = {"name": "cdxgen", "version": "12.9.0"} if producer == "default" else producer
    bundle = {"schema": "bombridge.bundle/2", "origin": "illustrative", "notice": "ILLUSTRATIVE",
              "capture": {"scope_id": S, "repository": {"url": "https://example.invalid/x", "revision": REV}, "build": None, "configuration": None, "model": None, "execution": None,
                          "unknown": ["build", "configuration", "model", "execution"], "unavailable": [], "inventories": [inv], "origin": "illustrative"},
              "entities": entities,
              "assertions": [{"assertion_id": "a", "family": "crypto_attribution", "subject": subj, "predicate": "operation_declared_in_cbom", "rule_version": version,
                              "object": {"inventory_id": INV, "inventory_sha256": inv_sha or sha(d), "algorithm": alg, "file": file, "operation": "hash",
                                         **({"producer": prod} if prod else {})},
                              "declared_in": {"inventory_id": "src", "source_ref": "s"}, "scope_id": S, "scope": {"revision": REV}, "origin": "illustrative"}], "evidence": evidence}
    return run_doc(bundle)["findings"][0]


ASSET = {"name": "sha256", "occ": [{"line": 10}]}


class AliasPolicyTest(unittest.TestCase):
    # the expected table is written independently of the module's literal: per-row patterns of contract section 5.2
    @staticmethod
    def expected():
        t = {"md5": {"md5"}, "sha1": {"sha1", "sha-1", "sha_1"}, "blake2b": {"blake2b"}, "blake2s": {"blake2s"}}
        for n in (224, 256, 384, 512):
            t[f"sha{n}"] = {f"sha{n}", f"sha-{n}", f"sha_{n}"}
            t[f"sha3_{n}"] = {f"sha3_{n}", f"sha3-{n}", f"sha3{n}", f"sha-3-{n}", f"sha_3_{n}"}
        for n in (224, 256):
            t[f"sha512_{n}"] = {f"sha512_{n}", f"sha512-{n}", f"sha512{n}"}
        for n in (128, 256):
            t[f"shake_{n}"] = {f"shake_{n}", f"shake-{n}", f"shake{n}"}
        return t

    def test_the_mapping_in_the_code_equals_the_contract_table_row_for_row(self):
        self.assertEqual({k: set(v) for k, v in rules_cbom4.ALIASES.items()}, self.expected())
        self.assertEqual(set(rules_cbom4.ALIASES), set(cryptoscan.HASHES))

    def test_every_listed_spelling_in_every_case_maps_to_its_canonical_name(self):
        for canon, spellings in self.expected().items():
            for sp in spellings:
                for variant in (sp, sp.upper(), sp.title()):
                    self.assertEqual(rules_cbom4.canonical(variant), canon, variant)

    def test_unlisted_excluded_and_unknown_names_never_alias_even_when_canonical_alg_would(self):
        for name in ("s-h-a256", "sha--256", "sha-512/256", "sha2-256", "hmac-sha256", "hmac-sha-256", "pbkdf2-hmac-sha256", "pbkdf2_hmac_sha256", "rsa-sha256",
                     "ecdsa-with-sha256", "sha256withrsa", "2.16.840.1.101.3.4.2.1", "ripemd160", "scrypt", "sha_3256", "sha-3_256"):
            with self.subTest(name):
                self.assertIsNone(rules_cbom4.canonical(name))
        self.assertEqual(cryptoscan.canonical_alg("s-h-a256"), "sha256")          # the donor function is broader: it is not the policy
        self.assertNotEqual(rules_cbom4.canonical("s-h-a256"), cryptoscan.canonical_alg("s-h-a256"))

    def test_the_mapping_is_a_subset_of_canonical_alg_equivalences_never_the_reverse(self):
        for canon, spellings in rules_cbom4.ALIASES.items():
            for sp in spellings:
                self.assertEqual(cryptoscan.canonical_alg(sp), canon)

    def test_the_imported_donor_and_the_earlier_rules_are_byte_identical(self):
        self.assertEqual(hashlib.sha256((SRC / "cryptoscan.py").read_bytes()).hexdigest(), "79d92b3f21725fd6accb8542ad50722ec2661c3064c717580c111c5cc79ced6f")
        self.assertEqual(hashlib.sha256((SRC / "rules_cbom.py").read_bytes()).hexdigest(), "7c4518ad3d8dfa81eade2afa58d880649122863c9a0997910cd2c4c793a60de0")
        self.assertEqual(hashlib.sha256((SRC / "rules_cbom3.py").read_bytes()).hexdigest(), "9c72e22b3e3b5352ac79ead34d1e7e5bc0052ecaa209bbaf6e089b12e5ea7db3")


class DispatchTest(unittest.TestCase):
    def test_a_version_4_assertion_reaches_rule_4_not_the_version_agnostic_rule_2(self):
        f = finding(cdoc([ASSET]))
        self.assertEqual(f["rule_id"], rules_cbom4.RULE_ID)
        self.assertTrue(rules_cbom.applies({"family": "crypto_attribution", "predicate": "operation_declared_in_cbom", "rule_version": 4}))   # /2 would also match
        self.assertFalse(rules_cbom3.applies({"family": "crypto_attribution", "predicate": "operation_declared_in_cbom", "rule_version": 4}))

    def test_rules_2_and_3_keep_their_dispatch(self):
        self.assertEqual(finding(cdoc([ASSET]), version=3)["rule_id"], rules_cbom3.RULE_ID)
        f = finding(cdoc([{"name": "md5", "occ": [{"line": 10, "ctx": "hashlib.md5 in f"}]}]), alg="md5", excerpt="h = hashlib.md5()", version=None)
        self.assertEqual(f["rule_id"], rules_cbom.RULE_ID)


class MatchingTest(unittest.TestCase):
    def test_exact_spelling_with_every_check_true_is_supported(self):
        f = finding(cdoc([ASSET]))
        self.assertEqual((f["state"], f["reason_codes"]), ("supported", ["call_site_in_range_unique"]))
        self.assertEqual(f["algorithm_alias"]["applied"], False)

    def test_an_approved_alias_is_supported_and_both_raw_values_are_reported(self):
        f = finding(cdoc([{"name": "SHA-256", "occ": [{"line": 10}]}]), alg="sha256")
        self.assertEqual(f["state"], "supported")
        a = f["algorithm_alias"]
        self.assertEqual((a["applied"], a["source_value"], a["cbom_value"], a["canonical"]), (True, "sha256", "SHA-256", "sha256"))

    def test_an_alias_without_every_check_is_blocked(self):
        d = cdoc([{"name": "SHA-256", "occ": [{"line": 10}]}])
        bad = dict(GOOD, tree_search_complete_no_local_module=False)
        f = finding(d, res=resolution(checks=bad))
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["alias_requires_resolved_call"]))

    def test_an_unlisted_spelling_is_exact_only(self):
        f = finding(cdoc([{"name": "s-h-a256", "occ": [{"line": 10}]}]))
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["no_algorithm_record"]))

    def test_hmac_and_pbkdf2_names_are_not_the_same_operation(self):
        for name in ("HMAC-SHA-256", "PBKDF2-HMAC-SHA256", "hmac-sha256"):
            with self.subTest(name):
                f = finding(cdoc([{"name": name, "occ": [{"line": 10}]}]))
                self.assertEqual(f["state"], "unverifiable")

    def test_wrong_primitive_or_asset_type_is_excluded_even_with_the_right_name_and_place(self):
        for kw in ({"primitive": "kdf"}, {"primitive": "mac"}, {"asset_type": "related-crypto-material"}):
            with self.subTest(kw):
                f = finding(cdoc([dict(ASSET, **kw)]))
                self.assertEqual((f["state"], f["excluded_assets"][0]["reason_code"]), ("unverifiable", "primitive_mismatch"))

    def test_an_occurrence_recorded_for_another_hashlib_function_is_excluded(self):
        f = finding(cdoc([{"name": "sha256", "occ": [{"line": 10, "ctx": "hashlib.pbkdf2_hmac in hash_password"}]}]))
        self.assertEqual(f["state"], "unverifiable")
        self.assertEqual(f["excluded_assets"][0]["reason_code"], "operation_context_mismatch")

    def test_multiple_occurrences_in_range_elsewhere_wrong_file_and_no_location(self):
        self.assertEqual(finding(cdoc([{"name": "sha256", "occ": [{"line": 10}, {"line": 11}]}]))["reason_codes"], ["multiple_call_sites_in_range"])
        self.assertEqual(finding(cdoc([{"name": "sha256", "occ": [{"line": 50}]}]))["reason_codes"], ["call_sites_elsewhere_in_file"])
        self.assertEqual(finding(cdoc([{"name": "sha256", "occ": [{"line": 10, "file": "other.py"}]}]))["reason_codes"], ["algorithm_record_without_matching_location"])
        self.assertEqual(finding(cdoc([{"name": "sha256", "occ": []}]))["reason_codes"], ["algorithm_record_without_matching_location"])

    def test_zero_asset_library_mention_and_unsupported_document(self):
        self.assertEqual(finding(cdoc([]))["reason_codes"], ["no_algorithm_record"])
        self.assertEqual(finding(cdoc([], libs=("cryptography",)))["reason_codes"], ["library_mention_only"])
        f = finding(cdoc([ASSET], spec="1.4"), producer=None)      # an unreadable document names no producer, so the live orchestrator binds none
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["cbom_format_unsupported"]))

    def test_wrong_inventory_digest_producer_or_revision_scope_excludes_the_document(self):
        d = cdoc([ASSET])
        for kw, code in (({"inv_sha": "f" * 64}, "inventory_binding_mismatch"), ({"producer": {"name": "other", "version": "1"}}, "producer_binding_mismatch")):
            with self.subTest(code):
                f = finding(d, **kw)
                self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["no_compatible_cbom_document"]))
                self.assertIn(code, [e["reason_code"] for e in f["excluded_evidence"]])
        f = finding(d, scope_rev="f" * 40)
        self.assertEqual(f["state"], "unverifiable")

    def test_the_source_must_show_the_algorithm_in_the_named_file(self):
        self.assertEqual(finding(cdoc([ASSET]), excerpt="h = hashlib.md5()")["reason_codes"], ["source_location_not_observed"])
        self.assertEqual(finding(cdoc([ASSET]), excerpt="sha256_helper(x)")["reason_codes"], ["source_location_not_observed"])   # whole token only


class StrictChecksTest(unittest.TestCase):
    def test_every_required_check_must_be_the_boolean_true(self):
        d = cdoc([ASSET])
        for key in rules_cbom4.REQUIRED_CHECKS:
            for bad in ("missing", None, False, "true", 1, "yes", [True], {"v": True}, 0):
                with self.subTest(key=key, bad=bad):
                    checks = dict(GOOD)
                    if bad == "missing":
                        del checks[key]
                    else:
                        checks[key] = bad
                    f = finding(d, res=resolution(checks=checks))
                    self.assertNotEqual(f["state"], "supported")
                    self.assertEqual(f["reason_codes"], ["source_resolution_ambiguous"])

    def test_checks_that_are_not_an_object_or_a_resolution_that_is_absent_or_foreign_never_support(self):
        d = cdoc([ASSET])
        for res in (resolution(checks=None), resolution(checks=["x"]), resolution(checks="true"), None, {"call": "node:crypto.createHash", "checks": dict(GOOD)}):
            with self.subTest(res=res):
                self.assertNotEqual(finding(d, res=res)["state"], "supported")

    def test_an_apparent_match_cannot_override_a_failed_gate_and_unknown_extra_values_do_not_help(self):
        d = cdoc([ASSET])
        extra = dict(GOOD, extra_ok=True)
        self.assertEqual(finding(d, res=resolution(checks=extra))["state"], "supported")          # an extra true key is ignored, not required
        missing_one = {k: v for k, v in GOOD.items() if k != "audit_complete"}
        self.assertEqual(finding(d, res=resolution(checks=dict(missing_one, bogus=True)))["state"], "unverifiable")


if __name__ == "__main__":
    unittest.main()
