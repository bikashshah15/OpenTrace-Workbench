"""UIP-06: the crypto-assets producer on production-shaped inputs against independently authored expectations.

The frozen fixtures are schema/renderer fixtures; this module never compares production output with a payload the producer wrote.
Expected values are written by hand here (ids use a local re-implementation of the documented derivation, not the producer's helper).
"""
import copy
import hashlib
import itertools
import json
import os
import random
import unittest

from opentrace_core.app import crypto_assets as ca
from opentrace_core.app import view_contracts as vc
from tests.core.app.test_view_contracts import load_builder

BUILDER = load_builder()
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
I5C = os.path.join(ROOT, "tests", "core", "live", "fixtures", "i5c")
ART = "art:inv:cdxgen-cbom"
PRODUCER = "cdxgen 12.9.0"


# ------------------------------------------------------------------------------------------------ independent helpers
def oid(prefix, digest, kind, key):
    """The documented derivation (contract 4.1), re-implemented here: first 24 hex of sha256(canonical_json({analysis_digest, kind, key}))."""
    body = json.dumps({"analysis_digest": digest, "kind": kind, "key": key}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "%s:%s" % (prefix, hashlib.sha256(body.encode("utf-8")).hexdigest()[:24])


def binding(seed="uip06"):
    return BUILDER.make_binding("example-org", "unit-lab", seed)


def accept(payload, b):
    vc.validate_payload("crypto_assets", payload, request={"generation": b["generation"]},
                        expected_binding={k: b[k] for k in ("analysis_digest", "commit_sha", "repository", "requested_ref", "mode", "assessment")})


def build(inputs, b=None, **request):
    b = b or binding()
    payload = ca.build_payload(inputs, b, dict({"generation": b["generation"], "filter": "all", "offset": 0}, **request))
    accept(payload, b)
    return payload, b


def comp(name, occurrences, asset_type="algorithm", **extra):
    c = {"type": "cryptographic-asset", "name": name, "cryptoProperties": {"assetType": asset_type},
         "evidence": {"occurrences": [{"location": p, "line": l, "symbol": "node:crypto.createHash"} for p, l in occurrences]}}
    c.update(extra)
    return c


def cbom_doc(components, services=()):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"tools": {"components": [{"name": "cdxgen", "version": "12.9.0"}]}},
            "components": components, "services": list(services)}


def original(doc, outcome="completed", reason=None):
    return {"artifact_id": ART, "outcome": outcome, "reason": reason, "doc": doc, "producer": PRODUCER, "sha256": None}


def inputs(cbom=None, source=None, mode="captured"):
    return {"cbom": cbom, "source": source, "mode": mode}


def observed(path="src/a.ts", line=76, sha="a" * 64, algo="sha256", conclusion=None, conclusions=None):
    t = {"status": "observed", "assertion_id": "live-src-crypto-x",
         "source_observation": {"evidence_id": "ev-live-src-x", "path": path, "line": line, "file_sha256": sha, "excerpt": "  createHash(\"%s\")" % algo,
                                "resolution": {"literal_algorithm": algo, "call": "node:crypto.createHash"}},
         "conclusion": conclusion or {"state": "supported", "rule_id": "crypto_attribution.operation_declared_in_cbom/3", "reason_codes": ["match"],
                                      "rationale": "r", "bounded_meaning": "m", "next_action": None, "used_evidence": []}}
    if conclusions is not None:
        t["conclusions"] = conclusions
    return t


UNSUPPORTED = {"state": "inconclusive", "rule_id": "crypto_attribution.operation_declared_in_cbom/3", "reason_codes": ["no_cbom_occurrence", "x"],
               "rationale": "The CBOM does not state this call site.", "bounded_meaning": "Declaration level only.", "next_action": "Inspect the CBOM.",
               "used_evidence": [{"evidence_id": "ev-cbom-1"}]}


def real_cbom():
    with open(os.path.join(I5C, "cdxgen-cbom.cdx.json"), "rb") as handle:
        return json.loads(handle.read())


def many_files(n, per_dir=None, prefix="d"):
    """n assets, each with one occurrence in its own file (optionally spread over directories)."""
    comps = []
    for i in range(n):
        d = "%s%02d/" % (prefix, i // per_dir) if per_dir else ""
        comps.append(comp("alg-%04d" % i, [("%ssrc/f%04d.py" % (d, i), 1)]))
    return cbom_doc(comps)


# ----------------------------------------------------------------------------------------------------------- PE-2 / PE-3 / PE-4
class RealRecordedInputs(unittest.TestCase):
    def test_pe2_real_recorded_nonpython_cbom_equals_the_hand_written_expectation(self):
        b = binding()
        p, _ = build(inputs(original(real_cbom())), b)
        d = b["analysis_digest"]
        paths = [("clients/mcpdo/src/connection/auth-helper.ts", 76), ("clients/mcpdo/src/daemon/paths.ts", 108),
                 ("test-servers/src/skills.ts", 99), ("test-servers/src/test-server-oauth.ts", 982)]
        key = ART + "/components/934"
        groups = [{"group_id": oid("grp", d, "source", "file|" + path), "label": path, "path": path, "assets_total": 1} for path, _ in paths]
        occs = []
        for i, (path, line) in enumerate(paths):
            href = "https://github.com/%s/%s/blob/%s/%s" % (b["repository"]["owner"], b["repository"]["name"], b["commit_sha"], path)
            occs.append({"occurrence_id": oid("occ", d, "occurrence", "%s|%d|%s|%d" % (key, i, path, line)),
                         "source_location": {"path": path, "file_sha256": None, "line_start": line, "line_end": line, "excerpt": None,
                                             "excerpt_state": "unavailable", "link": {"href": href, "text": path}},
                         "operation": "node:crypto.createHash", "condition": {"text": None, "basis": "none"}, "alternative_of": None, "producer_id": "cdxgen"})
        na = {"state": "unavailable", "value": None, "basis": "not recorded in the artifact"}
        asset = {"asset_id": oid("ast", d, "asset", key), "kind": "algorithm", "display_name": "sha-256",
                 "provenance": {"producer_id": "cdxgen", "producer_version": "cdxgen 12.9.0", "origin": "original_artifact" if False else "original_artifact",
                                "artifact_id": ART, "json_pointer": "/components/934", "experimental": False},
                 "attributes": {"algorithm_name": {"state": "recorded", "value": "sha-256", "basis": "component name"},
                                "primitive": {"state": "recorded", "value": "hash", "basis": "property cdx:crypto:primitive"},
                                "parameter": na, "protocol_name": na, "protocol_version": na, "certificate_subject": na},
                 "source_group_ids": [g["group_id"] for g in groups], "occurrences": occs, "occurrences_total": 4}
        asset["provenance"]["producer_version"] = None
        asset["provenance"] = {"producer_id": "cdxgen", "producer_version": None, "origin": "original_artifact", "artifact_id": ART,
                               "json_pointer": "/components/934", "experimental": False}
        self.assertEqual(p["assets"], [asset])
        self.assertEqual(p["source_groups"], groups)
        self.assertEqual(p["links"], [])
        self.assertEqual(p["review_items"], [])
        self.assertEqual(p["services"], [])
        self.assertEqual(p["services_counts"], {"total": 0, "shown": 0, "truncated": False})
        self.assertEqual(p["availability"]["state"], "completed")
        self.assertIsNone(p["availability"]["reason_code"])
        self.assertEqual([x["provenance"]["producer_id"] for x in p["producers"]], ["cdxgen"])
        self.assertEqual(p["producers"][0]["outcome"], "completed")
        self.assertEqual(p["filter_totals"], {"all": 1, "findings": 0, "algorithms": 1, "protocols": 0, "certificates": 0})
        self.assertEqual(p["page"], {"offset": 0, "size": 30, "assets_total": 1, "assets_shown": 1, "has_more": False})
        self.assertIs(p["absence_established"], False)

    def test_pe3_supported_observation_adds_a_separate_experimental_asset_in_the_same_group(self):
        doc = real_cbom()
        sha = json.load(open(os.path.join(I5C, "CAPTURE.json")))["files"]["auth-helper.ts"]
        line = open(os.path.join(I5C, "auth-helper.ts"), encoding="utf-8").read().split("\n")[75]
        src = {"targets": [observed(path="clients/mcpdo/src/connection/auth-helper.ts", line=76, sha=sha)]}
        src["targets"][0]["source_observation"]["excerpt"] = line
        p, b = build(inputs(original(doc), src, mode="live"))
        self.assertEqual(p["availability"]["state"], "completed")
        self.assertEqual([x["outcome"] for x in p["producers"]], ["completed", "completed"])
        self.assertEqual([x["provenance"]["experimental"] for x in p["producers"]], [False, True])
        self.assertEqual(len(p["assets"]), 2)
        sup = next(a for a in p["assets"] if a["provenance"]["origin"] == "supplemental_observation")
        orig = next(a for a in p["assets"] if a["provenance"]["origin"] == "original_artifact")
        self.assertNotEqual(sup["asset_id"], orig["asset_id"])
        o = sup["occurrences"][0]["source_location"]
        self.assertEqual((o["file_sha256"], o["line_start"], o["line_end"], o["excerpt"], o["excerpt_state"]), (sha, 76, 76, line, "recorded"))
        self.assertTrue(sup["provenance"]["experimental"])
        shared = set(sup["source_group_ids"]) & set(orig["source_group_ids"])
        self.assertEqual(len(shared), 1)                      # both producers report the file: two labelled cards in one group
        self.assertEqual(p["review_items"], [])
        self.assertEqual(p["filter_totals"]["all"], 2)

    def test_pe4_a_conclusion_that_is_not_supported_yields_exactly_one_review_item(self):
        src = {"targets": [observed(conclusion=UNSUPPORTED)]}
        p, _ = build(inputs(original(cbom_doc([])), src, mode="live"))
        self.assertEqual(len(p["review_items"]), 1)
        r = p["review_items"][0]
        self.assertEqual((r["rule_id"], r["rule_version"], r["tone"]), ("crypto_attribution.operation_declared_in_cbom", "3", "review"))
        self.assertEqual(r["evidence_ids"], ["ev-live-src-x", "ev-cbom-1"])
        self.assertEqual(r["condition"], "Rule state inconclusive; reason codes no_cbom_occurrence, x")
        self.assertEqual(r["asset_id"], p["assets"][0]["asset_id"])
        self.assertEqual(p["filter_totals"]["findings"], 1)
        p2, _ = build(inputs(original(cbom_doc([])), src, mode="live"), filter="findings")
        self.assertEqual(p2["page"]["assets_total"], 1)

    def test_an_observation_without_path_hash_or_line_yields_no_asset(self):
        for field, value in (("file_sha256", None), ("line", None), ("path", None), ("file_sha256", "short")):
            t = observed()
            t["source_observation"][field] = value
            p, _ = build(inputs(original(cbom_doc([])), {"targets": [t]}, mode="live"))
            self.assertEqual(p["assets"], [], field)
            self.assertEqual(p["producers"][1]["outcome"], "partial", field)        # the skipped target is counted, not hidden

    def test_the_prototype_names_cannot_appear(self):
        p, _ = build(inputs(original(real_cbom())))
        text = json.dumps(p).lower()
        for name in ("pbkdf2", "hs256", "mqtt", "frigate", "ot5-data"):
            self.assertNotIn(name, text)


# --------------------------------------------------------------------------------------------------------- availability (PE-5, PE-6)
OUTS = ("completed", "partial", "failed", "not_run", "unsupported")


def oracle(orig, supp, assets):
    """Independently written from the contract 4.6 table (rows 1-9); first match decides."""
    outs = [o for o in (orig, supp) if o]
    if assets > 0:
        return "partial" if any(o in ("failed", "partial") for o in outs) else "completed"
    if "partial" in outs:
        return "partial"
    if "failed" in outs and "completed" in outs:
        return "partial"
    if "failed" in outs:
        return "failed"
    if "completed" in outs:
        return "completed_empty"
    if "unsupported" in outs:
        return "unsupported"
    return "not_run"


def make(orig, orig_assets, supp, supp_assets):
    cb = None
    if orig:
        doc = cbom_doc([comp("a%d" % i, [("src/o%d.py" % i, 3)]) for i in range(orig_assets)], [{"name": "svc-b"}, {"name": "svc-a", "endpoints": ["/x"]}])
        reason = {"failed": "scanner_failed", "not_run": "not_configured"}.get(orig)
        cb = original(doc if orig in ("completed", "partial") else None, orig, reason)
    sc = None
    if supp:
        if supp in ("failed", "not_run", "unsupported"):
            sc = {"targets": [], "outcome": supp, "reason": {"failed": "scanner_failed", "not_run": "not_configured"}.get(supp)}
        elif supp == "completed":
            sc = {"targets": [observed(path="src/s%d.ts" % i, line=i + 1) for i in range(supp_assets)], "outcome": None}
        else:
            sc = {"targets": [observed(path="src/s%d.ts" % i, line=i + 1) for i in range(supp_assets)] + [{"status": "skipped", "file": "x", "line": 1, "reason": "r"}], "outcome": None}
    return inputs(cb, sc, mode="live")


class Availability(unittest.TestCase):
    def test_exhaustive_precedence_every_combination_matches_the_independent_decision_function(self):
        checked = 0
        for orig, supp in itertools.product((None,) + OUTS, (None,) + OUTS):
            for oa, sa in itertools.product((0, 2), (0, 1)):
                if orig not in ("completed", "partial") and oa:
                    continue
                if supp not in ("completed", "partial") and sa:
                    continue
                if supp == "completed" and not sa:
                    continue                                    # an observed target always yields an asset; "completed, zero assets" cannot occur
                if orig is None and oa:
                    continue
                inp = make(orig, oa, supp, sa)
                p, b = build(inp)
                total = oa + sa
                want = oracle(orig, "partial" if (supp == "partial") else supp, total)
                self.assertEqual(p["availability"]["state"], want, (orig, oa, supp, sa))
                self.assertEqual(p["page"]["assets_total"], total)
                self.assertIs(p["absence_established"], False)
                if want in ("failed", "not_run", "unsupported", "completed_empty"):
                    self.assertEqual(total, 0)
                checked += 1
        self.assertGreater(checked, 50)

    def test_partial_producer_with_zero_assets_and_no_completed_producer_is_partial_never_empty_or_failed(self):
        for supp in (None, "failed", "not_run", "unsupported"):
            p, _ = build(make("partial", 0, supp, 0))
            self.assertEqual((p["availability"]["state"], p["availability"]["reason_code"]), ("partial", "partial_coverage"), supp)
        p, _ = build(make("failed", 0, "partial", 0))                           # original failed + supplemental partial (skipped target only)
        self.assertEqual(p["availability"]["state"], "partial")
        self.assertEqual([x["outcome"] for x in p["producers"]], ["failed", "partial"])

    def test_mixed_outcomes_and_valid_original_assets_stay_visible(self):
        for supp in (None, "partial", "failed", "not_run", "unsupported", "completed"):
            p, _ = build(make("completed", 2, supp, 1 if supp in ("partial", "completed") else 0))
            names = {a["display_name"] for a in p["assets"] if a["provenance"]["origin"] == "original_artifact"}
            self.assertEqual(names, {"a0", "a1"}, supp)
            self.assertEqual(p["availability"]["state"], "partial" if supp in ("partial", "failed") else "completed", supp)
        p, _ = build(make("partial", 2, "failed", 0))
        self.assertEqual({a["display_name"] for a in p["assets"]}, {"a0", "a1"})
        self.assertEqual(p["availability"]["state"], "partial")

    def test_pe5_named_cases(self):
        cases = [("completed", 0, "completed", 1, "completed"), ("completed", 2, "partial", 1, "partial"), ("completed", 0, "failed", 0, "partial"), ("failed", 0, "completed", 1, "partial"),
                 ("completed", 0, "not_run", 0, "completed_empty"), ("unsupported", 0, None, 0, "unsupported"), ("failed", 0, None, 0, "failed"),
                 ("not_run", 0, None, 0, "not_run"), (None, 0, None, 0, "not_run")]
        for orig, oa, supp, sa, want in cases:
            p, _ = build(make(orig, oa, supp, sa))
            self.assertEqual(p["availability"]["state"], want, (orig, supp))
        p, _ = build(make("failed", 0, None, 0))
        self.assertEqual((p["services"], p["availability"]["reason_code"]), ([], "scanner_failed"))
        p, _ = build(make(None, 0, None, 0))
        self.assertEqual(p["availability"]["reason_code"], "not_configured")
        p, _ = build(make("completed", 0, None, 0))                           # zero-asset success keeps its services
        self.assertEqual(p["availability"]["state"], "completed_empty")
        self.assertEqual([s["name"] for s in p["services"]], ["svc-a", "svc-b"])
        self.assertEqual(p["services_counts"], {"total": 2, "shown": 2, "truncated": False})

    def test_pe6_filter_to_zero_never_changes_availability_and_distinctions_hold(self):
        p, _ = build(inputs(original(real_cbom())), filter="certificates")
        self.assertEqual((p["availability"]["state"], p["page"]["assets_total"], p["filter_totals"]["all"]), ("completed", 0, 1))
        for kw in ({"query": "nothing-matches"}, {"filter": "protocols"}):
            q, _ = build(inputs(original(real_cbom())), **kw)
            self.assertEqual(q["availability"]["state"], "completed")
        empty, _ = build(make("completed", 0, None, 0))
        failed, _ = build(make("failed", 0, None, 0))
        partial, _ = build(make("completed", 0, "failed", 0))
        states = [x["availability"] for x in (empty, failed, partial)]
        self.assertEqual(len({(s["state"], s["reason_code"], s["message"]) for s in states}), 3)
        self.assertNotIn("no cryptography", empty["availability"]["message"].replace("does not show that no cryptography", ""))
        svc_only, _ = build(make("completed", 0, None, 0))
        self.assertEqual(svc_only["page"]["assets_total"], 0)
        self.assertEqual(svc_only["filter_totals"]["all"], 0)

    def test_an_unmapped_failure_reason_is_a_typed_refusal_never_guessed(self):
        with self.assertRaises(vc.ContractError) as cm:
            ca.build_payload(inputs(original(None, "failed", "mystery")), binding(), {"generation": 1, "filter": "all", "offset": 0})
        self.assertEqual((cm.exception.code, cm.exception.detail_code), ("projection_failed", "unmapped_reason"))


# -------------------------------------------------------------------------------------------------------------- bounds (PE-7)
class Bounds(unittest.TestCase):
    def groups(self, doc):
        p, b = build(inputs(original(doc)), filter="all")
        return p

    def global_groups(self, doc):
        model = ca.build_model(inputs(original(doc)), binding())
        return model

    def test_group_counts_23_24_25_files(self):
        for n, want in ((23, 23), (24, 24)):
            m = self.global_groups(many_files(n))
            self.assertEqual((len(m.groups), {g["kind"] for g in m.groups}), (want, {"file"}))
        m = self.global_groups(many_files(25))
        self.assertLessEqual(len(m.groups), 24)
        self.assertEqual({g["kind"] for g in m.groups}, {"dir"})                       # 25 files in one directory -> one directory group
        self.assertEqual([g["label"] for g in m.groups], ["src/"])
        self.assertEqual(m.groups[0]["assets_total"], 25)

    def test_depth_reduction_picks_the_largest_depth_within_the_cap(self):
        comps = [comp("a%d" % i, [("t%02d/u%02d/f.py" % (i // 2, i), 1)]) for i in range(48)]        # 48 files, 24 depth-1 prefixes, 48 depth-2
        m = self.global_groups(cbom_doc(comps))
        self.assertEqual({g["kind"] for g in m.groups}, {"dir"})
        self.assertEqual(sorted(g["label"] for g in m.groups), sorted("t%02d/" % i for i in range(24)))
        comps = [comp("a%d" % i, [("t%02d/u%d/f.py" % (i // 4, i % 4), 1)]) for i in range(80)]      # depth 2 -> 80 prefixes; depth 1 -> 20
        m = self.global_groups(cbom_doc(comps))
        self.assertEqual(sorted(g["label"] for g in m.groups), sorted("t%02d/" % i for i in range(20)))

    def test_more_than_24_top_level_directories_use_one_other_group(self):
        comps = [comp("a%d" % i, [("top%02d/f.py" % i, 1)] * (1 + (i % 3))) for i in range(30)]
        m = self.global_groups(cbom_doc(comps))
        self.assertEqual(len(m.groups), 24)
        self.assertEqual(sum(1 for g in m.groups if g["kind"] == "other"), 1)
        other = next(g for g in m.groups if g["kind"] == "other")
        self.assertEqual((other["label"], other["path"]), ("Other locations", None))
        named = sorted(g["label"] for g in m.groups if g["kind"] == "dir")
        self.assertEqual(len(named), 23)
        # the 23 kept are the largest by occurrence count (3, then 2, ...), ties broken by prefix ascending
        counts = {"top%02d/" % i: 1 + (i % 3) for i in range(30)}
        want = sorted(sorted(counts, key=lambda k: (-counts[k], k))[:23])
        self.assertEqual(named, want)
        self.assertEqual(sum(g["assets_total"] for g in m.groups), 30)

    def test_root_level_files_use_the_repository_root_group(self):
        comps = [comp("a%d" % i, [("f%02d.py" % i, 1)]) for i in range(30)]
        m = self.global_groups(cbom_doc(comps))
        self.assertEqual([(g["label"], g["path"]) for g in m.groups], [("(repository root)", None)])

    def test_assets_paging_0_1_30_31_60_61(self):
        for n in (0, 1, 30, 31, 60, 61):
            doc = many_files(n)
            p, b = build(inputs(original(doc)))
            self.assertEqual(p["page"]["assets_total"], n)
            self.assertEqual(p["page"]["assets_shown"], min(n, 30))
            seen = []
            off = 0
            while True:
                q, _ = build(inputs(original(doc)), offset=off)
                seen += [a["asset_id"] for a in q["assets"]]
                self.assertLessEqual(len(q["assets"]), 30)
                self.assertEqual(q["counts"]["truncated"], q["page"]["assets_shown"] < q["page"]["assets_total"])
                if not q["page"]["has_more"]:
                    break
                off += 30
            self.assertEqual(len(seen), n)
            self.assertEqual(len(set(seen)), n)                                         # no duplicates across pages

    def test_misaligned_and_out_of_range_offsets_are_refused_not_clamped(self):
        doc = many_files(61)
        for off in (1, 29, 31, 61, 90, 120):
            with self.assertRaises(vc.ContractError) as cm:
                build(inputs(original(doc)), offset=off)
            self.assertEqual((cm.exception.code, cm.exception.detail_code), ("invalid_request", "offset"))
        with self.assertRaises(vc.ContractError):
            build(inputs(original(cbom_doc([]))), offset=30)                            # empty total: offset 0 only
        build(inputs(original(cbom_doc([]))), offset=0)

    def test_occurrences_19_20_21_and_more_than_20_in_one_group(self):
        for n, shown in ((19, 19), (20, 20), (21, 20)):
            doc = cbom_doc([comp("sha-256", [("src/f%02d.py" % i, i + 1) for i in range(n)])])
            p, _ = build(inputs(original(doc)))
            a = p["assets"][0]
            self.assertEqual((len(a["occurrences"]), a["occurrences_total"]), (shown, n))
            self.assertEqual(len(a["source_group_ids"]), n if n <= 24 else 24)
        # 45 occurrences in ONE file group: exactly 20 are listed, the total is exact, and nothing claims the rest are reachable
        doc = cbom_doc([comp("sha-256", [("src/one.py", i + 1) for i in range(45)])])
        p, b = build(inputs(original(doc)))
        a = p["assets"][0]
        self.assertEqual((len(a["occurrences"]), a["occurrences_total"], len(a["source_group_ids"])), (20, 45, 1))
        q, _ = build(inputs(original(doc)), group_id=a["source_group_ids"][0])
        self.assertEqual((len(q["assets"][0]["occurrences"]), q["assets"][0]["occurrences_total"]), (20, 45))
        self.assertEqual([o["source_location"]["line_start"] for o in q["assets"][0]["occurrences"]], list(range(1, 21)))
        shown_lines = {o["source_location"]["line_start"] for o in q["assets"][0]["occurrences"]}
        self.assertFalse(set(range(21, 46)) & shown_lines)                              # lines 21..45 are not reachable through the payload
        self.assertEqual(len(doc["components"][0]["evidence"]["occurrences"]), 45)       # the original artifact still holds all of them

    def test_group_id_prioritizes_that_groups_occurrences_without_a_reachability_claim(self):
        doc = cbom_doc([comp("alg", [("a/%02d.py" % i, 1) for i in range(15)] + [("z/last.py", 9)])])
        m = ca.build_model(inputs(original(doc)), binding())
        z = next(g["group_id"] for g in m.groups if g["path"] == "z/last.py")
        base, _ = build(inputs(original(doc)))
        first, _ = build(inputs(original(doc)), group_id=z)
        self.assertEqual(first["assets"][0]["occurrences"][0]["source_location"]["path"], "z/last.py")
        self.assertEqual(len(first["assets"][0]["occurrences"]), 16)
        self.assertEqual(first["assets"][0]["occurrences_total"], 16)
        self.assertEqual(len(base["assets"][0]["occurrences"]), 16)

    def test_services_29_30_31(self):
        for n in (29, 30, 31):
            doc = cbom_doc([], [{"name": "svc-%03d" % i} for i in range(n)])
            p, _ = build(inputs(original(doc)))
            self.assertEqual(p["services_counts"], {"total": n, "shown": min(n, 30), "truncated": n > 30})
            self.assertEqual(len(p["services"]), min(n, 30))
            self.assertEqual(p["page"]["assets_total"], 0)                              # services are never assets

    def test_links_are_always_empty(self):
        p, _ = build(inputs(original(real_cbom())))
        self.assertEqual(p["links"], [])

    def test_review_items_49_50_51_by_injected_rule_results(self):
        def page_with(per_asset):
            targets = [observed(path="src/s%d.ts" % i, line=1, conclusions=[dict(UNSUPPORTED, rule_id="rule.number_%d/1" % k) for k in range(per_asset[i])])
                       for i in range(len(per_asset))]
            return build(inputs(original(cbom_doc([])), {"targets": targets}, mode="live"))[0]
        self.assertEqual(len(page_with([2] * 24 + [1])["review_items"]), 49)
        self.assertEqual(len(page_with([2] * 25)["review_items"]), 50)
        with self.assertRaises(vc.ContractError) as cm:
            page_with([2] * 25 + [1])
        self.assertEqual((cm.exception.code, cm.exception.detail_code), ("projection_failed", "review_items_exceed_bound"))

    def test_a_hashing_name_alone_never_creates_a_review(self):
        doc = cbom_doc([comp("MD5", [("src/a.py", 1)]), comp("SHA-1", [("src/b.py", 2)])])
        p, _ = build(inputs(original(doc)))
        self.assertEqual((p["review_items"], p["filter_totals"]["findings"]), ([], 0))

    def test_maximal_text_stays_within_the_frozen_limits_and_the_response_cap(self):
        names = ["N" * 600 + str(i) for i in range(30)]
        doc = cbom_doc([comp(names[i], [("d%02d/" % i + "p" * 480 + ".py", 1)]) for i in range(30)], [{"name": "S" * 400, "endpoints": ["e" * 900]}] * 30)
        p, _ = build(inputs(original(doc)))
        self.assertEqual(len(ca.encode_response(p)) < ca.RESPONSE_MAX_BYTES, True)
        self.assertTrue(all(len(a["display_name"]) <= 256 for a in p["assets"]))
        self.assertTrue(all(len(s["name"]) <= 256 and len(s["endpoint_text"]) <= 512 for s in p["services"]))
        with self.assertRaises(vc.ContractError) as cm:
            ca.encode_response({"x": "y" * (ca.RESPONSE_MAX_BYTES + 1)})
        self.assertEqual(cm.exception.code, "response_too_large")

    def test_no_dangling_references_and_stable_order_over_random_cboms(self):
        rng = random.Random(6)
        for case in range(12):
            comps = []
            for i in range(rng.randint(0, 70)):
                occs = [("%s/%s/f%02d.py" % (rng.choice("abcdefghij"), rng.choice("pqrstuvw"), rng.randint(0, 40)), rng.randint(1, 50)) for _ in range(rng.randint(0, 25))]
                comps.append(comp("alg-%d" % rng.randint(0, 40), occs, rng.choice(["algorithm", "protocol", "certificate", "related-crypto-material"])))
            doc = cbom_doc(comps)
            b = binding()
            for flt in ca.FILTERS:
                off = 0
                while True:
                    p = ca.build_payload(inputs(original(doc)), b, {"generation": 1, "filter": flt, "offset": off})
                    accept(p, b)
                    gids = {g["group_id"] for g in p["source_groups"]}
                    self.assertLessEqual(len(gids), 24)
                    for a in p["assets"]:
                        self.assertTrue(set(a["source_group_ids"]) <= gids)
                    if not p["page"]["has_more"]:
                        break
                    off += 30
            shuffled = copy.deepcopy(doc)
            for c in shuffled["components"]:
                rng.shuffle(c["evidence"]["occurrences"])
            a1 = ca.build_payload(inputs(original(doc)), b, {"generation": 1, "filter": "all", "offset": 0})
            a2 = ca.build_payload(inputs(original(doc)), b, {"generation": 1, "filter": "all", "offset": 0})
            self.assertEqual(json.dumps(a1, sort_keys=True), json.dumps(a2, sort_keys=True))
            self.assertEqual([a["display_name"] for a in a1["assets"]], sorted([a["display_name"] for a in a1["assets"]], key=lambda n: n.casefold()) if len({a["source_group_ids"][0] if a["source_group_ids"] else "" for a in a1["assets"]}) == 1 else [a["display_name"] for a in a1["assets"]])

    def test_the_global_group_list_does_not_depend_on_the_filter_or_page(self):
        doc = many_files(40, per_dir=2)
        b = binding()
        base = ca.build_model(inputs(original(doc)), b)
        self.assertLessEqual(len(base.groups), 24)
        p = ca.build_payload(inputs(original(doc)), b, {"generation": 1, "filter": "protocols", "offset": 0})
        self.assertEqual(p["source_groups"], [])


# ------------------------------------------------------------------------------------------------------- exact provenance paths
class ExactPaths(unittest.TestCase):
    def refused(self, path):
        doc = cbom_doc([comp("alg", [(path, 1)])])
        with self.assertRaises(vc.ContractError) as cm:
            build(inputs(original(doc)))
        self.assertEqual((cm.exception.code, cm.exception.detail_code), ("projection_failed", "path_not_representable"))

    def test_control_characters_in_a_path_are_refused_never_replaced(self):
        for bad in ("src/a\x00b.py", "src/a\tb.py", "src/a\nb.py", "src/a\x1bb.py", "src/\x1f.py"):
            self.refused(bad)

    def test_an_empty_or_over_limit_path_is_refused(self):
        self.refused("")
        self.refused("p" * 513)
        self.refused("d/" + "p" * 511)

    def test_an_exact_limit_path_is_preserved_byte_for_byte(self):
        path = "src/" + "p" * 505 + ".py"                                    # 512 characters
        self.assertEqual(len(path), 512)
        p, _ = build(inputs(original(cbom_doc([comp("alg", [(path, 5)])]))))
        self.assertEqual(p["assets"][0]["occurrences"][0]["source_location"]["path"], path)
        self.assertEqual(p["source_groups"][0]["path"], path)
        self.assertNotIn("…", p["assets"][0]["occurrences"][0]["source_location"]["path"])

    def test_a_long_label_is_clipped_while_the_evidence_path_is_unchanged(self):
        path = "src/" + "q" * 300 + ".py"
        p, _ = build(inputs(original(cbom_doc([comp("alg", [(path, 5)])]))))
        g = p["source_groups"][0]
        self.assertEqual(len(g["label"]), 120)
        self.assertTrue(g["label"].endswith("…"))
        self.assertEqual(g["path"], path)
        self.assertEqual(p["assets"][0]["occurrences"][0]["source_location"]["path"], path)
        self.assertEqual(p["assets"][0]["occurrences"][0]["source_location"]["link"]["text"], path)

    def test_unusual_but_valid_path_characters_are_kept_exactly(self):
        path = "src/ünï/ＣＪＫ ‮rtl .py#x%y"
        p, _ = build(inputs(original(cbom_doc([comp("alg", [(path, 5)])]))))
        self.assertEqual(p["assets"][0]["occurrences"][0]["source_location"]["path"], path)

    def test_the_same_rule_holds_for_a_supplemental_observation_path(self):
        t = observed(path="src/a\x00.ts")
        with self.assertRaises(vc.ContractError) as cm:
            build(inputs(original(cbom_doc([])), {"targets": [t]}, mode="live"))
        self.assertEqual(cm.exception.detail_code, "path_not_representable")

    def test_display_text_is_normalized_separately(self):
        doc = cbom_doc([comp("bad\x00name" + "x" * 300, [("src/a.py", 1)])], [{"name": "svc\x01", "endpoints": "e\x02"}])
        p, _ = build(inputs(original(doc)))
        self.assertEqual(len(p["assets"][0]["display_name"]), 256)
        self.assertIn("�", p["assets"][0]["display_name"])
        self.assertEqual((p["services"][0]["name"], p["services"][0]["endpoint_text"]), ("svc�", "e�"))


class PinnedLinks(unittest.TestCase):
    """IR-01: a literal dot segment is reinterpreted by URL parsers, so such a path gets an inert link; the recorded path itself stays exact."""
    def link(self, path):
        p, b = build(inputs(original(cbom_doc([comp("alg", [(path, 5)])]))))
        return p["assets"][0]["occurrences"][0]["source_location"], b

    def test_dot_segments_give_a_null_link_and_keep_the_exact_path(self):
        for path in ("../../../../other-owner/other-repo/blob/" + "b" * 40 + "/other.ts", "./a.py", "a/./b.py", "a/../b.py", "..", "."):
            loc, _ = self.link(path)
            self.assertEqual((loc["path"], loc["link"]), (path, {"href": None, "text": path}), path)

    def test_valid_and_dot_like_names_keep_the_pinned_link(self):
        for path in ("src/.hidden/a...b.py", "src/..dots/x.py", "src/sp ace.py", "src/q'(1)!*.py", "src/a#b?c%d.py"):
            loc, b = self.link(path)
            self.assertTrue(loc["link"]["href"].startswith("https://github.com/%s/%s/blob/%s/" % (b["repository"]["owner"], b["repository"]["name"], b["commit_sha"])), path)
            self.assertEqual(loc["path"], path)


class HostileText(unittest.TestCase):
    def test_hostile_names_and_excerpts_stay_inert_text(self):
        evil = "<img src=x onerror=alert(1)>‮'\"&"
        t = observed(algo="sha256")
        t["source_observation"]["excerpt"] = evil + "\x01\x1b" + "z" * 700
        doc = cbom_doc([comp(evil, [("src/a.py", 1)])], [{"name": evil, "endpoints": [evil]}])
        p, _ = build(inputs(original(doc), {"targets": [t]}, mode="live"))
        text = p["assets"][0]["display_name"]
        self.assertIn("<img", text)                                              # data, never markup: escaping is the renderer's duty
        sup = next(a for a in p["assets"] if a["provenance"]["origin"] == "supplemental_observation")
        loc = sup["occurrences"][0]["source_location"]
        self.assertEqual(loc["excerpt_state"], "clipped")
        self.assertLessEqual(len(loc["excerpt"]), 600)
        self.assertNotIn("\x01", loc["excerpt"])


if __name__ == "__main__":
    unittest.main()
