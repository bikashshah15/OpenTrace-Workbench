"""I5C: one source-backed CBOM check on the pinned MCP Inspector commit, tested against recorded real artifacts.

Recorded inputs (tests/core/live/fixtures/i5c/CAPTURE.json): the real cdxgen CBOM and Syft SBOM produced for commit 074b8108... and the real
source file at that commit. Nothing here calls GitHub, a scanner or OSV. Variants (missing CBOM, occurrence moved) are built from the
recorded bytes in memory and say so.
"""
import copy
import hashlib
import json
import os
import pathlib
import shutil
import tempfile
import threading
import unittest

from opentrace_core.app import make_server
from opentrace_core.bombridge import pipeline
from opentrace_core.bombridge.adapters import cbom_document_observation
from opentrace_core.live import scanners as sc
from opentrace_core.live import source_checks
from opentrace_core.live.runner import LiveConfig
from opentrace_core.live.scanners import ScannerConfig
from tests.core.live import support
from tests.core.live.test_live_app import LiveAppBase

FIX = pathlib.Path(__file__).resolve().parent / "fixtures" / "i5c"
CAPTURE = json.loads((FIX / "CAPTURE.json").read_text())
CBOM_BYTES = (FIX / "cdxgen-cbom.cdx.json").read_bytes()
SBOM_BYTES = (FIX / "syft-sbom.cdx.json").read_bytes()
SOURCE = (FIX / "auth-helper.ts").read_bytes()
PATH = "clients/mcpdo/src/connection/auth-helper.ts"
PINNED = ("modelcontextprotocol/inspector", CAPTURE["commit_sha"])
CALL_SITE = '  const hash = createHash("sha256").update(key).digest("hex").slice(0, 16);'
TARGET = {"file": PATH, "line": 76, "algorithm": "sha256", "file_sha256": CAPTURE["source_file"]["sha256"], "call_site": CALL_SITE}
SCOPE = "scope:i5c-test"


class RecordedInputs(unittest.TestCase):
    def test_the_recorded_files_are_the_ones_the_capture_record_names(self):
        for name, digest in CAPTURE["files"].items():
            self.assertEqual(hashlib.sha256((FIX / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(CAPTURE["analysis_generation"], 1)
        self.assertTrue(CAPTURE["analysis_ok"])
        self.assertEqual(CAPTURE["commit_sha"], "074b8108f340590268f2900741403755e923a11c")
        self.assertEqual(source_checks.targets_for(*PINNED), [TARGET])
        self.assertEqual(source_checks.targets_for("acme/widget", PINNED[1]), [])


def tree_with(text_or_bytes, rel=PATH):
    root = tempfile.mkdtemp(prefix="ot-i5c-tree-")
    target = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(target))
    with open(target, "wb") as handle:
        handle.write(text_or_bytes if isinstance(text_or_bytes, bytes) else text_or_bytes.encode())
    return root


class Collector(unittest.TestCase):
    def observe(self, content, target=TARGET):
        root = tree_with(content)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return source_checks.observe(root, target)

    def test_the_real_call_resolves_to_node_createhash_with_the_literal_sha256(self):
        got = self.observe(SOURCE)
        self.assertEqual(got["status"], "observed")
        self.assertEqual((got["file"], got["line"]), (PATH, 76))
        self.assertEqual(got["excerpt"], '  const hash = createHash("sha256").update(key).digest("hex").slice(0, 16);')
        self.assertEqual(got["file_sha256"], CAPTURE["source_file"]["sha256"])
        r = got["resolution"]
        self.assertEqual((r["call"], r["module"], r["literal_algorithm"], r["import_line"], r["import_text"]),
                         ("node:crypto.createHash", "node:crypto", "sha256", 2, 'import { createHash } from "node:crypto";'))

    def skipped(self, content, reason, target=TARGET, bind=True):
        """``bind``: bind the target to this content (as a reviewed target would be), so the structural checks are what is exercised."""
        if bind:
            raw = content if isinstance(content, bytes) else content.encode()
            lines = raw.decode("utf-8", "replace").split("\n")
            text = lines[target["line"] - 1] if 1 <= target["line"] <= len(lines) else "x"
            target = dict(target, file_sha256=hashlib.sha256(raw).hexdigest(), call_site=text)
        got = self.observe(content, target)
        self.assertEqual((got["status"], got["reason"]), ("skipped", reason), got)

    def with_line(self, line_text, header='import { createHash } from "node:crypto";\n'):
        return header + "\n" * 2 + line_text + "\n"

    T = {"file": PATH, "line": 4, "algorithm": "sha256"}

    def test_ambiguous_or_unsupported_calls_are_skipped(self):
        self.skipped(self.with_line('const a = createHash("sha256"), b = createHash("sha256");'), "several_calls_on_line", self.T)
        self.skipped(self.with_line("const a = createHash(algo);"), "argument_is_not_a_string_literal", self.T)
        self.skipped(self.with_line('const a = createHash("sha512");'), "literal_differs_from_target", self.T)
        self.skipped(self.with_line('const a = hasher.createHash("sha256");'), "no_call", self.T)
        self.skipped(self.with_line('// const a = createHash("sha256");'), "target_line_is_a_comment", self.T)
        self.skipped(self.with_line("const a = 1;"), "no_call", self.T)

    def test_a_createhash_that_is_not_the_node_import_is_skipped(self):
        call = 'const a = createHash("sha256");'
        self.skipped(self.with_line(call, header='import { createHash } from "./my-crypto.js";\n'), "createHash_not_imported_exactly_once_from_node_crypto", self.T)
        self.skipped(self.with_line(call, header=""), "createHash_not_imported_exactly_once_from_node_crypto", dict(self.T, line=3))
        self.skipped(self.with_line(call, header='import { createHash as h } from "node:crypto";\n'), "createHash_not_imported_exactly_once_from_node_crypto", self.T)
        self.skipped(self.with_line(call, header='import { createHash } from "node:crypto";\nimport { createHash as c2 } from "./x.js";\n'),
                     "createHash_not_imported_exactly_once_from_node_crypto", dict(self.T, line=5))
        self.skipped(self.with_line(call + "\nfunction createHash() {}", header='import { createHash } from "node:crypto";\n'),
                     "createHash_declared_elsewhere_in_file", self.T)

    def mutated_real(self, line75, line77=None):
        lines = SOURCE.decode().split("\n")
        self.assertEqual(lines[75].strip(), CALL_SITE.strip())     # the reviewed call-site line itself is untouched
        lines[74] = line75
        if line77 is not None:
            lines[76] = line77
        return "\n".join(lines)

    def test_the_reviewed_target_is_bound_to_the_exact_source_file_and_call_site(self):
        self.skipped(self.mutated_real("export function pendingAuthMarkerPath(createHash: (a: string) => unknown, key: string): string {"),
                     "file_sha256_differs_from_reviewed", bind=False)      # shadowed parameter: the old reading accepted this
        self.skipped(self.mutated_real("const note = `", "`;"), "file_sha256_differs_from_reviewed", bind=False)   # the call site inside a template literal
        self.skipped(self.mutated_real("/*", "*/"), "file_sha256_differs_from_reviewed", bind=False)                # the call site inside a block comment
        self.skipped(SOURCE + b"\n", "file_sha256_differs_from_reviewed", bind=False)                               # any other byte change
        self.skipped(SOURCE, "call_site_differs_from_reviewed", dict(TARGET, call_site=CALL_SITE.replace("sha256", "sha512")), bind=False)
        self.skipped(SOURCE, "target_not_bound_to_reviewed_source", {k: v for k, v in TARGET.items() if k not in ("file_sha256", "call_site")}, bind=False)
        self.skipped(SOURCE, "target_not_bound_to_reviewed_source", {k: v for k, v in TARGET.items() if k != "call_site"}, bind=False)

    def test_without_the_binding_the_syntactic_reading_alone_is_not_enough(self):
        """Documents why the binding exists: bound to its own content, a shadowed parameter still reads as a resolved call."""
        content = self.mutated_real("export function pendingAuthMarkerPath(createHash: (a: string) => unknown, key: string): string {")
        self.assertEqual(self.observe(content, dict(TARGET, file_sha256=hashlib.sha256(content.encode()).hexdigest()))["status"], "observed")

    def test_a_missing_file_or_line_is_skipped_and_nothing_is_invented(self):
        root = tree_with(SOURCE, rel="other/file.ts")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.assertEqual(source_checks.observe(root, TARGET)["reason"], "file_not_in_exported_tree")
        self.skipped(SOURCE, "line_out_of_range", dict(TARGET, line=9999))
        self.skipped(b"\xff\xfe\x00", "file_not_utf8")


def cbom_observation(doc_bytes=CBOM_BYTES, mutate=None):
    doc = json.loads(doc_bytes)
    if mutate:
        mutate(doc)
    raw = json.dumps(doc, sort_keys=True).encode() if mutate else doc_bytes
    obs = cbom_document_observation(doc, hashlib.sha256(raw).hexdigest())
    obs["acquisition_generator"] = {"name": "cdxgen", "version": "12.9.0", "third_party": True}
    return obs, hashlib.sha256(raw).hexdigest()


class CbomRun:  # the few fields of a ScanRun that the bundle parts read
    tool, version, outcome = "cdxgen", "12.9.0", "acquired"

    def __init__(self, sha):
        self.sha256 = sha


def bundle(include_cbom=True, mutate=None, strip_resolution=False, assertion_rule_version=3):
    observed = source_checks.observe(tree_with(SOURCE), TARGET)
    obs, sha = cbom_observation(mutate=mutate)
    ents, evs, asserts = source_checks.bundle_parts([observed], SCOPE, CAPTURE["commit_sha"], CbomRun(sha) if include_cbom else None)
    if strip_resolution:
        del evs[0]["observation"]["resolution"]
    if assertion_rule_version is None:
        del asserts[0]["rule_version"]
    if include_cbom:
        evs.append({"evidence_id": "ev-cbom", "scope_id": SCOPE, "method": "cyclonedx-1.6-cbom-intake", "observes": [], "origin": "captured", "scope": {"revision": CAPTURE["commit_sha"]},
                    "source_locator": "cdxgen-cbom.cdx.json", "tool": "t", "underlying_source": "tool-output:cbom", "observation": obs, "limitations": ["what the document says"]})
    capture = {"scope_id": SCOPE, "origin": "captured", "repository": {"url": CAPTURE["repository"], "revision": CAPTURE["commit_sha"]}, "build": None, "configuration": None,
               "model": None, "execution": None, "unknown": ["build", "configuration", "model", "execution"], "unavailable": [], "inventories": []}
    return {"schema": "bombridge.bundle/2", "origin": "captured", "notice": "n", "capture": capture, "entities": ents, "evidence": evs, "assertions": asserts, "input_checks": []}


def finding(doc):
    result = pipeline.run_doc(doc)
    return result, next(f for f in result["findings"] if f["assertion_id"].startswith("live-src-crypto"))


def move_every_sha256_occurrence(doc, to_line=None, to_file=None):
    for comp in doc["components"]:
        if comp.get("name") == "sha-256":
            for oc in comp["evidence"]["occurrences"]:
                if oc["location"] == PATH:
                    if to_line:
                        oc["line"] = to_line
                    if to_file:
                        oc["location"] = to_file


class RuleV3(unittest.TestCase):
    def test_the_real_recorded_cbom_supports_the_source_call_and_keeps_both_raw_values(self):
        result, f = finding(bundle())
        self.assertEqual((f["rule_id"], f["state"], f["category"]), ("crypto_attribution.operation_declared_in_cbom/3", "supported", "declaration_agreement"))
        self.assertEqual(f["reason_codes"], ["call_site_in_range_unique"])
        self.assertEqual(f["algorithm_alias"], {"pair": ["sha-256", "sha256"], "applied": True, "assertion_value": "sha256", "source_value": "sha256", "cbom_value": "sha-256"})
        self.assertEqual([c["line"] for c in f["candidates"]], [76])
        self.assertEqual((f["candidates"][0]["name"], f["candidates"][0]["match"], f["candidates"][0]["locators"]), ("sha-256", "location_in_range", [PATH + ":76"]))
        self.assertTrue(f["layers"]["matching_call_site"] and f["layers"]["algorithm_record"])
        self.assertFalse(f["layers"]["runtime_execution"] or f["layers"]["integrity_verification"])
        self.assertIn("crypto_attribution.operation_declared_in_cbom/3", [r["rule_id"] for r in result["rules"]])
        # the evidence the rule saw is the raw records, unmodified
        ev = {e["evidence_id"]: e for e in bundle()["evidence"]}
        self.assertIn('createHash("sha256")', ev["ev-live-src-" + source_checks._slug(PATH, 76)]["observation"]["excerpt"])

    def test_missing_cbom_evidence_leaves_the_check_unassessed(self):
        _, f = finding(bundle(include_cbom=False))
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["no_compatible_cbom_document"]))
        self.assertIsNone(f["matched_asset"])
        self.assertTrue(f["layers"]["referenced_by_source"])

    def test_a_sha256_asset_recorded_only_at_a_different_file_is_not_a_match(self):
        _, f = finding(bundle(mutate=lambda d: move_every_sha256_occurrence(d, to_file="test-servers/src/elsewhere.ts")))
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["algorithm_record_without_matching_location"]))
        self.assertIsNone(f["matched_asset"])
        self.assertTrue(f["layers"]["algorithm_record"] and not f["layers"]["matching_call_site"])

    def test_a_sha256_asset_recorded_at_another_line_of_the_same_file_is_not_a_match(self):
        _, f = finding(bundle(mutate=lambda d: move_every_sha256_occurrence(d, to_line=80)))
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["call_sites_elsewhere_in_file"]))
        self.assertEqual([(c["match"], c["line"]) for c in f["candidates"]], [("same_file_other_line", 80)])
        self.assertIsNone(f["matched_asset"])

    def test_the_alias_is_not_applied_without_a_resolved_call(self):
        _, f = finding(bundle(strip_resolution=True))
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["alias_requires_resolved_call"]))
        self.assertIsNone(f["matched_asset"])
        self.assertFalse(f["algorithm_alias"]["applied"])

    def test_no_other_spelling_is_normalized(self):
        def md5_asset_only(doc):
            for comp in doc["components"]:
                if comp.get("name") == "sha-256":
                    comp["name"] = "sha-2-56"
        _, f = finding(bundle(mutate=md5_asset_only))
        self.assertEqual(f["state"], "unverifiable")
        self.assertIsNone(f["matched_asset"])
        self.assertFalse(f["algorithm_alias"]["applied"])

    def test_rule_v2_still_cannot_assess_this_pair_and_keeps_its_own_id(self):
        result, f = finding(bundle(assertion_rule_version=None))
        self.assertEqual(f["rule_id"], "crypto_attribution.operation_declared_in_cbom/2")
        self.assertEqual((f["state"], f["reason_codes"]), ("unverifiable", ["no_algorithm_record"]))
        self.assertNotIn("algorithm_alias", f)
        self.assertNotIn("crypto_attribution.operation_declared_in_cbom/3", [r["rule_id"] for r in result["rules"]])

    def test_rule_v2_with_the_cbom_spelling_cannot_match_the_source_excerpt(self):
        doc = bundle(assertion_rule_version=None)
        doc["assertions"][0]["object"]["algorithm"] = "sha-256"
        _, f = finding(doc)
        self.assertEqual((f["rule_id"], f["state"], f["reason_codes"]), ("crypto_attribution.operation_declared_in_cbom/2", "unverifiable", ["source_location_not_observed"]))


def present(doc_mutate=None, include_cbom=True):
    doc = bundle(include_cbom=include_cbom, mutate=doc_mutate)
    result = pipeline.run_doc(doc)
    sha = next((e["observation"]["document"]["raw_sha256"] for e in doc["evidence"] if e["observation"]["kind"] == "cbom_document"), None)

    class Run(CbomRun):
        reason, spec_version = None, "1.6"
        outcome = "acquired" if include_cbom else "failed"
    observed = source_checks.observe(tree_with(SOURCE), TARGET)
    return source_checks.present([observed], CAPTURE["repository"], CAPTURE["commit_sha"], result, Run(sha) if include_cbom else None)[0]


def duplicate_in_range(doc, as_new_asset):
    for comp in doc["components"]:
        if comp.get("name") == "sha-256":
            occ = next(o for o in comp["evidence"]["occurrences"] if o["location"] == PATH and o["line"] == 76)
            if as_new_asset:
                twin = copy.deepcopy(comp)
                twin["bom-ref"] = comp["bom-ref"] + "#twin"
                doc["components"].append(twin)
            else:
                comp["evidence"]["occurrences"].append(dict(occ))
            return


class Presenter(unittest.TestCase):
    def test_a_unique_supported_match_is_named_and_nothing_else_is_a_candidate(self):
        got = present()
        self.assertEqual(got["conclusion"]["state"], "supported")
        self.assertEqual((got["cbom_record"]["matching_occurrence"]["file"], got["cbom_record"]["matching_occurrence"]["line"]), (PATH, 76))
        self.assertEqual(got["cbom_record"]["candidates"], [])

    def test_two_occurrences_in_range_are_candidates_and_none_is_matched(self):
        for as_new_asset in (False, True):
            got = present(lambda d: duplicate_in_range(d, as_new_asset))
            self.assertEqual((got["conclusion"]["state"], got["conclusion"]["reason_codes"]), ("unverifiable", ["multiple_call_sites_in_range"]), as_new_asset)
            self.assertIsNone(got["cbom_record"]["matching_occurrence"], as_new_asset)
            self.assertEqual([(c["match"], c["line"]) for c in got["cbom_record"]["candidates"]], [("location_in_range", 76)] * 2, as_new_asset)

    def test_an_unsupported_result_never_names_a_match(self):
        got = present(lambda d: move_every_sha256_occurrence(d, to_line=80))
        self.assertIsNone(got["cbom_record"]["matching_occurrence"])
        self.assertEqual([c["line"] for c in got["cbom_record"]["candidates"]], [80])
        self.assertIsNone(present(include_cbom=False)["cbom_record"]["matching_occurrence"])


_ORIGINAL = sc._resolve_cdxgen


class Workbench(LiveAppBase):
    """The recorded artifacts served through the real loopback service; scanners are fake scripts that emit the recorded bytes."""
    FILES = {PATH: SOURCE, "package-lock.json": b'{"name":"w","lockfileVersion":3,"packages":{}}\n'}

    def serve(self, cbom=CBOM_BYTES, cbom_exit=0):
        syft = support.fake_tool(self.tools, "syft", output=SBOM_BYTES, version="1.51.1")
        cdx = support.fake_tool(self.tools, "cdxgen", output=cbom, exit_code=cbom_exit, version="12.9.0")
        cfg = ScannerConfig(syft_path=syft, node_path=cdx, cdxgen_dir=self.tools, pins={"syft": "1.51.1", "cdxgen": "12.9.0"})
        sc._resolve_cdxgen = lambda config: ([cdx, "-o", "{out}"], [cdx], [self.tools], "12.9.0")
        sc.CDXGEN["resolve"] = sc._resolve_cdxgen
        self.addCleanup(lambda: (setattr(sc, "_resolve_cdxgen", _ORIGINAL), sc.CDXGEN.__setitem__("resolve", _ORIGINAL)))
        live = LiveConfig(allowlist={"acme/widget": {"repo": "acme/widget", "commit_sha": self.sha}}, scanners=cfg, isolation=support.PassThrough(),
                          transport=support.recorded_transport("acme", "widget", self.sha), remote_for=lambda o, n: self.origin, allow_protocol="file",
                          source_check_targets={("acme/widget", self.sha): (TARGET,)})
        srv = make_server(os.path.join(self.dir, "sessions"), reap_seconds=3600, live=live)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), srv.app.close(), srv.server_close()))
        return srv

    def test_the_matching_case_shows_three_separate_blocks(self):
        c, body = self.run_live(self.serve())
        self.assertTrue(body["ok"], body)
        sm = body["summary"]
        self.assertEqual((sm["inventory_checks"], sm["live"]["checks"], len(sm["source_checks"])), (1, "assessed", 1))
        sc_ = sm["source_checks"][0]
        src, cbom, concl = sc_["source_observation"], sc_["cbom_record"], sc_["conclusion"]
        self.assertEqual((src["path"], src["line"], src["commit"]), (PATH, 76, self.sha))
        self.assertEqual(src["excerpt"], '  const hash = createHash("sha256").update(key).digest("hex").slice(0, 16);')
        self.assertEqual(src["file_sha256"], CAPTURE["source_file"]["sha256"])
        self.assertEqual(src["resolution"]["call"], "node:crypto.createHash")
        self.assertEqual((cbom["document"]["sha256"], cbom["document"]["acquired"]), (hashlib.sha256(CBOM_BYTES).hexdigest(), True))
        self.assertEqual((cbom["matching_occurrence"]["name"], cbom["matching_occurrence"]["file"], cbom["matching_occurrence"]["line"]), ("sha-256", PATH, 76))
        self.assertEqual((concl["state"], concl["rule_id"]), ("supported", "crypto_attribution.operation_declared_in_cbom/3"))
        self.assertEqual(concl["algorithm_alias"]["cbom_value"], "sha-256")
        self.assertNotIn("state", src)            # the observation carries no conclusion
        self.assertNotIn("rationale", src)
        self.assertNotIn("source_observation", concl)
        self.assertEqual([x["assertion_id"] for x in sm["checks"]], [sc_["assertion_id"]])
        _, crypto = c.json("GET", "/api/view/crypto?generation=%d" % body["generation"])
        self.assertEqual([x["state"] for x in crypto["checks"]], ["supported"])
        resp, data = c.req("GET", "/api/artifacts/cdxgen-cbom.cdx.json?disposition=attachment")
        self.assertEqual(data, CBOM_BYTES)

    def test_a_failed_cbom_scan_leaves_the_check_unassessed(self):
        _, body = self.run_live(self.serve(cbom=b"", cbom_exit=3))
        self.assertTrue(body["ok"], body)
        sc_ = body["summary"]["source_checks"][0]
        self.assertEqual(sc_["status"], "observed")
        self.assertFalse(sc_["cbom_record"]["document"]["acquired"])
        self.assertEqual((sc_["conclusion"]["state"], sc_["conclusion"]["reason_codes"]), ("unverifiable", ["no_compatible_cbom_document"]))
        self.assertIsNone(sc_["cbom_record"]["matching_occurrence"])

    def test_a_sha256_asset_at_another_location_is_not_matched(self):
        moved = json.loads(CBOM_BYTES)
        move_every_sha256_occurrence(moved, to_line=80)
        _, body = self.run_live(self.serve(cbom=json.dumps(moved).encode()))
        self.assertTrue(body["ok"], body)
        sc_ = body["summary"]["source_checks"][0]
        self.assertEqual(sc_["conclusion"]["state"], "unverifiable")
        self.assertIsNone(sc_["cbom_record"]["matching_occurrence"])
        self.assertEqual([o["line"] for o in sc_["cbom_record"]["candidates"]], [80])

    def test_a_commit_without_a_declared_target_has_no_source_check(self):
        srv = self.serve()
        srv.app.live.source_check_targets = {}
        _, body = self.run_live(srv)
        self.assertEqual((body["summary"]["inventory_checks"], body["summary"]["source_checks"], body["summary"]["live"]["checks"]), (0, [], "none_assessed"))

    def test_an_ambiguous_target_is_skipped_and_shown_as_skipped(self):
        srv = self.serve()
        srv.app.live.source_check_targets = {("acme/widget", self.sha): (dict(TARGET, line=77),)}
        _, body = self.run_live(srv)
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["summary"]["inventory_checks"], 0)
        self.assertEqual(body["summary"]["source_checks"], [{"status": "skipped", "file": PATH, "line": 77, "reason": "call_site_differs_from_reviewed"}])


if __name__ == "__main__":
    unittest.main()
