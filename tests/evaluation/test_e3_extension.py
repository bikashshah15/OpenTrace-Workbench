"""E3-B / E3-C extension tests. Every input here is synthetic and every external tool or scanner is mocked.

No benchmark file, frozen case or prior result is opened; no tool, scanner, container or network is used.
"""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from tools.evaluation import common as C
from tools.evaluation import e3_external_comparison as EB
from tools.evaluation import e3_scanner_outputs as EC
from tools.evaluation import external_tools as X
from tools.evaluation import scanner_reference as R

C.bootstrap_paths(C.default_opentrace_root())


def reply(code=0, out=b"", err=b"", timeout=False, os_error=None):
    return {"argv": ["x"], "started_at": "t", "wall_ms": 1.0, "exit_code": code, "stdout": out, "stderr": err, "timeout": timeout, "os_error": os_error}


def diff_json(added=(), removed=(), modified=()):
    comps = {"added": list(added), "removed": list(removed), "modified": list(modified)}
    return json.dumps({"summary": {"components": {k: len(v) for k, v in comps.items()}}, "reports": {"components": comps}}).encode()


class CycloneDxParsing(unittest.TestCase):
    def test_accept_and_reject(self):
        self.assertEqual(X.classify_cyclonedx(reply(0, b"BOM validated successfully.\n"))["verdict"], "valid")
        self.assertEqual(X.classify_cyclonedx(reply(1, b"BOM is not valid.\n"))["verdict"], "invalid")

    def test_tool_problems_are_not_rejections(self):
        for r, status in ((reply(3, err=b"usage"), "unclassified"), (reply(134, err=b"Unhandled exception"), "unclassified"),
                          (reply(0, b""), "unparsed_output"), (reply(0, b"BOM is not valid."), "unclassified"),
                          (reply(None, timeout=True), "timeout"), (reply(None, os_error="OSError"), "execution_error")):
            got = X.classify_cyclonedx(r)
            self.assertEqual((got["status"], got["verdict"]), (status, None))


class SbomToolsParsing(unittest.TestCase):
    TARGET = {"name": "alpha", "ecosystem": "pypi"}

    def found(self, **kw):
        return X.surfaced(self.TARGET, X.classify_sbom_diff(reply(0, diff_json(**kw)))["components"])

    def test_granularity(self):
        self.assertEqual(self.found(removed=[{"name": "alpha", "ecosystem": "PyPI"}])["granularity"], "record_level")
        self.assertEqual(self.found(removed=[{"name": "alpha", "ecosystem": None, "id": "pkg:pypi/alpha@1"}])["granularity"], "record_level")
        self.assertEqual(self.found(removed=[{"name": "alpha", "ecosystem": None}])["granularity"], "name_only")
        coarse = self.found(modified=[{"name": "alpha", "field_changes": [{"field": "purl"}]}])
        self.assertEqual((coarse["granularity"], coarse["modified_fields"]), ("component_level_modified", ["purl"]))
        wrong = self.found(removed=[{"name": "alpha", "ecosystem": "npm"}], added=[{"name": "beta"}])
        self.assertEqual((wrong["surfaced"], wrong["other_records_reported"]), (False, 1))

    def test_unusable_output(self):
        for out in (b"not json", b"{}", json.dumps({"reports": {"components": {}}}).encode(),
                    diff_json().replace(b'"added": 0', b'"added": 2')):
            self.assertEqual(X.classify_sbom_diff(reply(0, out))["status"], "unparsed_output")
        self.assertEqual(X.classify_sbom_diff(reply(3, diff_json()))["status"], "execution_error")
        self.assertEqual(X.classify_sbom_diff(reply(None, timeout=True))["status"], "timeout")

    def test_probe_missing_and_unsupported(self):
        info = X.probe("sbom-tools", "/nonexistent/sbom-tools")
        self.assertEqual(X.unavailable_status(info), "not_run")
        avail = {"available": True, "path": "/x/sbom-tools", "version_output": "sbom-tools 0.0", "reason": None}
        with mock.patch.object(C, "tool_version", return_value=avail), mock.patch.object(X, "run_command", return_value=reply(0, b"Commands:\n  quality  x\n")):
            self.assertEqual(X.unavailable_status(X.probe("sbom-tools", "sbom-tools")), "unsupported_operation")
        with mock.patch.object(C, "tool_version", return_value=avail), \
                mock.patch.object(X, "run_command", return_value=reply(0, b"Commands:\n  diff  x\n -o, --output <FMT>\n --offline\n")):
            ok = X.probe("sbom-tools", "sbom-tools")
        self.assertIsNone(X.unavailable_status(ok))
        self.assertEqual(X.sbom_tools_argv(ok, "a", "b"), ["/x/sbom-tools", "--offline", "diff", "a", "b", "--output", "json"])


class E3BExecution(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.prior = os.path.join(self.d, "prior")
        os.makedirs(self.prior)

    def doc(self, name, body):
        with open(os.path.join(self.prior, name), "wb") as fh:
            fh.write(body)
        return {"path": name, "sha256": hashlib.sha256(body).hexdigest()}

    def plan(self):
        v = lambda i, kind: {"op_id": f"val-{i}", "tool": "cyclonedx-cli", "case_id": f"c{i}", "operation": "validate", "input_kind": kind,
                             "oracle": "valid" if kind == "valid_document" else "invalid", "input_version": "v1_6", "input": self.doc(f"{i}.json", b"{}")}
        d = {"op_id": "diff-1", "tool": "sbom-tools", "case_id": "d1", "operation": "diff", "variant": "MR2", "old": self.doc("a.json", b"1"),
             "new": self.doc("b.json", b"2"), "expected_removed": {"name": "alpha", "ecosystem": "pypi"}, "expected_added": []}
        return {"operations": [v(1, "valid_document"), v(2, "valid_document"), v(3, "malformed_control"), d]}

    def tools(self, sbom_available=True):
        ok = {"available": True, "usable": True, "path": "/x/t", "version_output": "t 1", "supported_flags": []}
        return {"cyclonedx-cli": ok, "sbom-tools": ok if sbom_available else {"available": False, "reason": "not found"}}

    def test_denominators_failures_and_missing_tool(self):
        ctx = C.RunContext({}, output_root=os.path.join(self.d, "out"), run_id="r1", opentrace_root=C.default_opentrace_root())
        replies = [reply(0, b"BOM validated successfully."), reply(134, err=b"boom"), reply(1, b"BOM is not valid.")]
        with mock.patch.object(X, "run_command", side_effect=replies):
            runs = EB.execute(ctx, self.plan(), self.tools(sbom_available=False), self.prior, 5)
        t = EB.tabulate(self.plan(), runs)
        s = {r["task"]: r for r in t["summary"]}
        self.assertEqual((s["valid_documents_accepted"]["planned"], s["valid_documents_accepted"]["interpretable"],
                          s["valid_documents_accepted"]["success"], s["valid_documents_accepted"]["strict_of_attempted"]), (2, 1, 1, "1/2 (0.500)"))
        self.assertEqual(s["malformed_controls_rejected"]["success"], 1)
        missing = s["known_removed_record_surfaced"]
        self.assertEqual((missing["attempted"], missing["success"], missing["not_run"], missing["of_interpretable"]), (0, None, 1, "N/A"))
        self.assertEqual(EB._cell(missing), "not run")
        self.assertEqual(set(t["diff_granularity"].values()), {None})      # unexecuted metrics are never zero
        self.assertEqual(len(runs), 4)
        with self.assertRaises(C.HarnessError):      # no silent overwrite
            C.RunContext({}, output_root=os.path.join(self.d, "out"), run_id="r1", opentrace_root=C.default_opentrace_root())

    def test_input_digest_mismatch_refused(self):
        entry = self.doc("z.json", b"abc")
        with self.assertRaises(C.HarnessError):
            EB._input(os.path.join(self.prior, "z.json"), "0" * 64, self.prior)
        self.assertEqual(EB._input(os.path.join(self.prior, "z.json"), entry["sha256"], self.prior), entry)

    def test_change_oracle_reads_bytes(self):
        lib = lambda eco: {"type": "library", "name": "alpha", "version": "1", "purl": f"pkg:{eco}/alpha@1"}
        got = X.library_changes({"components": [{"type": "application", "name": "x", "components": [lib("pypi")]}]}, {"components": [lib("npm")]})
        self.assertEqual(([r["ecosystem"] for r in got["removed"]], [r["ecosystem"] for r in got["added"]]), (["pypi"], ["npm"]))


def pylib(name, version="1", path="/req/requirements.txt", eco="pypi"):
    return {"type": "library", "name": name, "version": version, "purl": f"pkg:{eco}/{name}@{version}",
            "properties": [{"name": "syft:location:0:path", "value": path}]}


def asset(name, location="app/h.py", line=4, asset_type="algorithm"):
    occ = {"location": location} | ({"line": line} if line else {})
    return {"type": "cryptographic-asset", "name": name, "bom-ref": name, "cryptoProperties": {"assetType": asset_type, "algorithmProperties": {"primitive": "hash"}},
            "evidence": {"occurrences": [occ]}}


class RawLookup(unittest.TestCase):
    def sbom(self, *comps):
        return R.sbom_lookup({"components": list(comps)}, "Alpha_Pkg", "req/requirements.txt")["status"]

    def test_sbom(self):
        self.assertEqual(self.sbom({"type": "application", "name": "n", "components": [pylib("alpha-pkg")]}), "unique_match")
        self.assertEqual(self.sbom(pylib("alpha-pkg"), pylib("alpha-pkg")), "unique_match")
        self.assertEqual(self.sbom(pylib("alpha-pkg", "1"), pylib("alpha-pkg", "2", "/other.txt")), "unique_match")
        self.assertEqual(self.sbom(pylib("alpha-pkg", "1", "/x"), pylib("alpha-pkg", "2", "/y")), "ambiguous")
        self.assertEqual(self.sbom(pylib("alpha-pkg", eco="npm")), "absent")
        self.assertEqual(self.sbom({"type": "library", "name": "mystery"}), "parse_incomplete")
        self.assertEqual(R.sbom_lookup(None, "a", "f")["status"], "inventory_unavailable")

    def cbom(self, *comps):
        return R.cbom_lookup({"components": list(comps)}, "sha256", "app/h.py", [4])

    def test_cbom(self):
        self.assertEqual(self.cbom(asset("SHA-256"))["status"], "unique_match")
        self.assertEqual(self.cbom(asset("SHA256".lower(), "app/h.py:4", None))["status"], "unique_match")
        self.assertEqual(self.cbom(asset("sha-256", "/spool/in/" + "a" * 32 + "/src/app/h.py"))["status"], "unique_match")
        self.assertEqual(self.cbom(asset("sha-256"), asset("sha-256"))["status"], "ambiguous")
        self.assertEqual(self.cbom(asset("sha-256", line=None))["status"], "insufficient_location_or_identity")
        self.assertEqual(self.cbom(asset("sha-256", asset_type="related-crypto-material"))["status"], "insufficient_location_or_identity")
        elsewhere = self.cbom(asset("sha-256", line=9))
        self.assertEqual((elsewhere["status"], elsewhere["algorithm_level"]), ("absent", True))
        empty = self.cbom()
        self.assertEqual((empty["status"], empty["empty_inventory"]), ("absent", True))
        self.assertEqual(R.cbom_lookup(None, "md5", "f", [1])["status"], "inventory_unavailable")

    def test_reference_module_is_independent(self):
        text = C.read_text(R.__file__)
        self.assertNotIn("import opentrace", text)
        self.assertNotIn("from opentrace", text)


@unittest.skipUnless(shutil.which("git"), "git required")
class E3CEndToEnd(unittest.TestCase):
    """Synthetic repositories (local git), synthetic scanner outputs, the real collector, bundle builder and assessment route."""

    REQ = b"alpha-pkg==1.0\nbeta-pkg\n"
    PY = b"import hashlib\n\n\ndef a(x):\n    return hashlib.sha256(x).hexdigest()\n\n\ndef b(x):\n    return hashlib.md5(x).hexdigest()\n"

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.caps = os.path.join(self.d, "captures")
        files = {"deepbits": {"req/requirements.txt": self.REQ, "req/otherreq.txt": b"gamma-pkg\n"}, "bf_cbom": {"proj/app/h.py": self.PY}}
        sha = lambda b: hashlib.sha256(b).hexdigest()
        sb = lambda n, f, line, data: {"anchor_id": f"sbom:{f}:{n}", "domain": "sbom", "path": f, "line_range": [line, line], "name": n, "normalized_name": n,
                                       "file_sha256": sha(data), "text": data.decode().splitlines()[line - 1]}
        cb = lambda alg, line: {"anchor_id": f"cbom:{alg}", "domain": "cbom", "path": "app/h.py", "repo_path": "proj/app/h.py", "constructor": alg,
                                "call_line": line, "item_lines": [line], "lines": [line, line], "file_sha256": sha(self.PY),
                                "line_text": self.PY.decode().splitlines()[line - 1]}
        self.ref = {"selection_sha256": "x", "excluded": [], "anchors": [
            sb("alpha-pkg", "req/requirements.txt", 1, self.REQ), sb("beta-pkg", "req/requirements.txt", 2, self.REQ),
            sb("gamma-pkg", "req/otherreq.txt", 1, b"gamma-pkg\n"), cb("sha256", 5), cb("md5", 9)]}
        self.remotes, self.zips = {}, os.path.join(self.d, "zips")
        os.makedirs(self.zips)
        self.specs = {k: dict(v) for k, v in EC.DATASETS.items()}
        for name, tree in files.items():
            repo = os.path.join(self.d, name)
            for rel, data in tree.items():
                os.makedirs(os.path.dirname(os.path.join(repo, rel)), exist_ok=True)
                with open(os.path.join(repo, rel), "wb") as fh:
                    fh.write(data)
            git = lambda *a: subprocess.run(["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *a],
                                            check=True, capture_output=True, text=True).stdout.strip()
            git("init", "-q")
            git("add", "-A")
            git("commit", "-qm", "synthetic")
            zp = os.path.join(self.zips, self.specs[name]["zip"])
            git("archive", "--format=zip", "--prefix=x/", "-o", zp, "HEAD")
            self.specs[name]["zip_sha256"] = C.sha256_file(zp)
            self.remotes[name] = repo
        p = mock.patch.object(EC, "DATASETS", self.specs)
        p.start()
        self.addCleanup(p.stop)

    def source(self):
        for name in self.specs:
            doc = EC.stage_source(self.caps, self.ref, self.zips, name, self.remotes[name], False)
            self.assertTrue(doc["record"]["verified"] and doc["archive_comparison"]["identical"])
            self.assertTrue(all(c["verified"] for c in doc["anchor_checks"]))

    def acquire(self, outputs):
        """Mock only the worker transport; ``outputs[dataset]`` is ``{scanner: document or None (failed)}``."""
        from opentrace_core.live import scanners as S, worker_client as W

        def fake_scan(config, service, ticket, source, workspace):
            name = "deepbits" if "DeepBits" in source.repository_url else "bf_cbom"
            runs = []
            for spec in (S.SYFT, S.CDXGEN):
                run = S.ScanRun(scanner=spec["scanner"], kind=spec["kind"], tool=spec["tool"], pinned_version="p", version="p", isolation="synthetic",
                                scope={"revision": source.commit_sha, "listing_sha256": source.listing_sha256, "paths": ["."],
                                       "file_count": source.file_count, "tree_sha": source.tree_sha}, command="synthetic")
                doc = outputs[name].get(spec["scanner"])
                S.evaluate_output(run, spec, spec["kind"], None, 0 if doc else 1, json.dumps(doc).encode() if doc else None)
                runs.append(run)
            return runs
        with mock.patch.object(W.WorkerClient, "status", return_value=({"tools": {}}, "")), mock.patch.object(W, "scan", fake_scan):
            for name in outputs:
                EC.stage_acquire(self.caps, name, os.path.join(self.d, "in"), os.path.join(self.d, "out"), None, 5)

    def sbom(self):
        return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            pylib("alpha-pkg", path="/req/requirements.txt"),
            {"type": "file", "name": "/req/requirements.txt", "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(self.REQ).hexdigest()}]}]}

    def cbom(self, *comps):
        return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": list(comps), "metadata": {"tools": {"components": [{"name": "synthetic", "version": "1"}]}}}

    def evaluate(self, run_id):
        ctx = C.RunContext({}, output_root=os.path.join(self.d, "results"), run_id=run_id, opentrace_root=C.default_opentrace_root())
        benches = {n: self.remotes[n] for n in self.specs}
        rows = EC.evaluate(ctx, self.ref, self.caps, benches)
        return {r["anchor_id"]: r for r in rows}, {s["dataset"]: s for s in EC.summarise(rows)}

    def test_tracks_stay_separate(self):
        self.source()
        self.acquire({"deepbits": {"syft": self.sbom()}, "bf_cbom": {"cdxgen": self.cbom(asset("sha-256", "proj/app/h.py", 5))}})
        rows, s = self.evaluate("ok")
        a, b, g = (rows[f"sbom:req/{f}"] for f in ("requirements.txt:alpha-pkg", "requirements.txt:beta-pkg", "otherreq.txt:gamma-pkg"))
        self.assertEqual((a["raw_status"], a["collector_observed"], a["assessment"]), ("unique_match", True, "supported"))
        self.assertEqual((b["raw_status"], b["collector_observed"], b["assessment"]), ("absent", True, "contradicted"))
        self.assertEqual((g["collector_observed"], g["collector_reason"], g["claim_generated"], g["assessment"]), (False, "file_not_collected", False, "not_discovered"))
        sha, md5 = rows["cbom:sha256"], rows["cbom:md5"]
        self.assertEqual((sha["raw_status"], sha["assessment"]), ("unique_match", "supported"))
        self.assertEqual((md5["raw_status"], md5["collector_observed"], md5["assessment"]), ("absent", True, "unverifiable"))
        self.assertEqual((s["deepbits"]["N"], s["deepbits"]["raw_unique_match"], s["deepbits"]["collector_observed"], s["deepbits"]["claims_generated"]), (3, 1, 2, 2))
        for d in s.values():
            self.assertEqual(sum(d["verdict_" + v] for v in EC.VERDICTS), d["N"])

    def test_failed_empty_missing_and_tampered(self):
        self.source()
        rows, s = self.evaluate("nocapture")
        self.assertEqual({r["capture_state"] for r in rows.values()}, {"capture_missing"})
        self.assertEqual((s["bf_cbom"]["raw_unique_match"], s["bf_cbom"]["claims_generated"], s["bf_cbom"]["collector_observed"]), (None, None, 2))
        self.acquire({"deepbits": {}, "bf_cbom": {"cdxgen": self.cbom()}})
        rows, s = self.evaluate("failed-and-empty")
        self.assertEqual((s["deepbits"]["capture_state"], s["deepbits"]["raw_absent"], s["deepbits"]["verdict_unavailable"]), ("scanner_failed", None, 3))
        self.assertEqual((s["bf_cbom"]["capture_state"], s["bf_cbom"]["raw_absent"], s["bf_cbom"]["verdict_unverifiable"]), ("acquired_empty", 2, 2))
        with open(os.path.join(self.caps, "bf_cbom", "cdxgen.cdx.json"), "ab") as fh:
            fh.write(b" ")
        rows, s = self.evaluate("tampered")
        self.assertEqual((s["bf_cbom"]["capture_state"], s["bf_cbom"]["raw_absent"], s["bf_cbom"]["verdict_unavailable"]), ("capture_invalid", None, 2))

    def test_unbound_source_gets_no_assessment(self):
        rows, s = self.evaluate("unbound")
        self.assertEqual((s["deepbits"]["binding"], s["deepbits"]["collector_observed"], s["deepbits"]["verdict_unavailable"]), ("unbound", 2, 3))

    def test_gates(self):
        with self.assertRaises(C.NotRunError):
            EC.stage_source(self.caps, self.ref, self.zips, "deepbits", None, False)
        self.source()
        with self.assertRaises(FileExistsError):
            EC.stage_source(self.caps, self.ref, self.zips, "deepbits", self.remotes["deepbits"], False)
        with self.assertRaises(C.NotRunError):     # no heartbeat: nothing is scanned and no capture is written
            EC.stage_acquire(self.caps, "deepbits", os.path.join(self.d, "in"), os.path.join(self.d, "out"), None, 5)
        self.assertFalse(os.path.exists(os.path.join(self.caps, "deepbits", "capture.json")))


if __name__ == "__main__":
    unittest.main()
