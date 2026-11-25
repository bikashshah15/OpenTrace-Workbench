"""UIP-01A: generation determinism and tamper tests. Everything runs on temp copies of the tools and sources; the real checkout is never modified."""
import json
import os
import shutil
import tempfile
import unittest

from tests.uip import support

ROOT = support.ROOT


class OnScratchCopy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="uip-scratch-")
        cls.pristine = support.scratch_repo(os.path.join(cls.base, "pristine"))
        cls.manifest = os.path.join(cls.base, "m1.json")
        cls.manifest2 = os.path.join(cls.base, "m2.json")
        for path in (cls.manifest, cls.manifest2):
            proc = support.run_tool(cls.pristine, "baseline.py", "generate", "--start-sha", support.START_SHA, "--out", path)
            assert proc.returncode == 0, proc.stdout + proc.stderr

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def copy_repo(self, name):
        dest = os.path.join(self.base, name)
        shutil.copytree(self.pristine, dest)
        return dest

    def compare(self, repo, manifest=None):
        return support.run_tool(repo, "compare.py", "--manifest", manifest or self.manifest)

    def lines(self, proc):
        return [l for l in proc.stdout.splitlines() if l.startswith("DIFF")]


class Determinism(OnScratchCopy):
    def test_two_generator_runs_are_byte_identical(self):
        self.assertEqual(support.read(self.manifest), support.read(self.manifest2))

    def test_the_manifest_records_what_the_contract_requires(self):
        m = json.loads(support.read(self.manifest, "r"))
        self.assertEqual((m["schema"], m["start_sha"], m["limits"]), ("opentrace.uip.baseline/1", support.START_SHA, {"phase_timeout_seconds": 120}))
        self.assertEqual(set(m["tools"]), {"tools/uip/netguard.py", "tools/uip/baseline.py", "tools/uip/compare.py"})
        self.assertTrue({"python", "node", "fixed_environment"} <= set(m["environment"]))
        self.assertIn("generator", m["commands"])
        self.assertEqual(set(m["excluded_from_comparison"]), {"environment", "commands"})
        self.assertEqual(m["class_p"]["directories"].keys(), {"src/core/opentrace_core/bombridge", "src/workers/scanner", "tests/core/bombridge/fixtures", "tests/uip"})
        self.assertEqual(len(m["golden_exports"]), 5)
        self.assertTrue(all(r["equals_golden"] for r in m["produced_legacy_exports"]))
        self.assertTrue(m["served"]["pins"]["sbom_equals_pin"] and m["served"]["pins"]["declarations_equal_pin"])
        self.assertIn("socketpair", m["served"]["route"])
        self.assertTrue(m["semantic"]["discovery"]["equals_donor_requirements_oracle"])
        self.assertEqual(set(m["semantic"]["observed_vs_report"]), {"candidates", "missing_component", "unknown_coverage", "contradicted", "unverifiable", "coverage_tasks"})

    def test_the_comparator_passes_against_the_unchanged_copy_and_writes_nothing(self):
        before = sorted(os.path.relpath(os.path.join(d, f), self.pristine) for d, _, fs in os.walk(self.pristine) for f in fs if "__pycache__" not in d)
        manifest_before = support.read(self.manifest)
        proc = self.compare(self.pristine)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("0 difference(s)", proc.stdout)
        after = sorted(os.path.relpath(os.path.join(d, f), self.pristine) for d, _, fs in os.walk(self.pristine) for f in fs if "__pycache__" not in d)
        self.assertEqual(before, after)
        self.assertEqual(support.read(self.manifest), manifest_before)


class Tamper(OnScratchCopy):
    def test_modifying_a_protected_file_fails_and_names_it(self):
        repo = self.copy_repo("t-modify")
        path = os.path.join(repo, "src/core/opentrace_core/bombridge/links.py")
        support.write(path, "\n# tamper\n", "a")
        proc = self.compare(repo)
        self.assertEqual(proc.returncode, 1, proc.stdout[-1500:] + proc.stderr[-800:])
        self.assertTrue(any("class_p.files.src/core/opentrace_core/bombridge/links.py" in l for l in self.lines(proc)), proc.stdout)

    def test_changing_one_legacy_export_byte_fails(self):
        repo = self.copy_repo("t-legacy")
        path = os.path.join(repo, "tests/core/bombridge/fixtures/exports/frigate/frigate-v0.18.2-cpu-pilot.result.json")
        data = bytearray(support.read(path))
        data[-2] ^= 0x01
        support.write(path, bytes(data), "wb")
        proc = self.compare(repo)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        out = "\n".join(self.lines(proc))
        self.assertIn("golden_exports", out)
        self.assertIn("equals_golden", out)

    def test_deleting_a_protected_file_fails(self):
        repo = self.copy_repo("t-delete")
        os.remove(os.path.join(repo, "src/core/opentrace_core/bombridge/PROVENANCE.md"))
        proc = self.compare(repo)
        self.assertEqual(proc.returncode, 1, proc.stdout[-1500:] + proc.stderr[-800:])
        self.assertTrue(any("PROVENANCE.md" in l and "missing" in l for l in self.lines(proc)), proc.stdout)

    def test_an_unlisted_file_under_a_protected_directory_fails(self):
        repo = self.copy_repo("t-extra")
        support.write(os.path.join(repo, "src/core/opentrace_core/bombridge/not_in_baseline.py"), "# extra\n")
        proc = self.compare(repo)
        self.assertEqual(proc.returncode, 1, proc.stdout[-1500:] + proc.stderr[-800:])
        out = "\n".join(self.lines(proc))
        self.assertIn("not_in_baseline.py", out)
        self.assertIn("directories", out)

    def test_reordered_candidates_fail_with_a_reordering_line(self):
        manifest = os.path.join(self.base, "m-reordered.json")
        m = json.loads(support.read(self.manifest, "r"))
        m["semantic"]["discovery"]["candidates"].reverse()
        support.write(manifest, json.dumps(m, sort_keys=True, indent=1))
        proc = self.compare(self.pristine, manifest)
        self.assertEqual(proc.returncode, 1, proc.stdout[-1500:] + proc.stderr[-800:])
        self.assertTrue(any("semantic.discovery.candidates" in l and "reordered" in l for l in self.lines(proc)), proc.stdout)

    def test_a_changed_tool_invalidates_the_manifest(self):
        repo = self.copy_repo("t-tool")
        support.write(os.path.join(repo, "tools/uip/netguard.py"), "\n# changed\n", "a")
        proc = self.compare(repo)
        self.assertEqual(proc.returncode, 1, proc.stdout[-1500:] + proc.stderr[-800:])
        self.assertTrue(any("tools.tools/uip/netguard.py" in l for l in self.lines(proc)), proc.stdout)

    def test_a_changed_semantic_output_fails(self):
        manifest = os.path.join(self.base, "m-semantic.json")
        m = json.loads(support.read(self.manifest, "r"))
        m["semantic"]["discovery"]["candidates"][0]["finding"]["state"] = "supported"
        support.write(manifest, json.dumps(m, sort_keys=True, indent=1))
        proc = self.compare(self.pristine, manifest)
        self.assertEqual(proc.returncode, 1, proc.stdout[-1500:] + proc.stderr[-800:])
        self.assertTrue(any("candidates[0].finding.state" in l for l in self.lines(proc)), proc.stdout)


class ExclusionTamper(OnScratchCopy):
    """UIP-01A-IR-01 at the CLI: a manifest copy that excludes a protected section must not hide a protected change."""

    def exclusion_manifest(self, name, **exclusions):
        m = json.loads(support.read(self.manifest, "r"))
        m["excluded_from_comparison"].update(exclusions)
        path = os.path.join(self.base, name)
        support.write(path, json.dumps(m, sort_keys=True, indent=1))
        return path

    def test_an_excluded_class_p_does_not_hide_a_changed_protected_file(self):
        repo = self.copy_repo("t-excl-links")
        support.write(os.path.join(repo, "src/core/opentrace_core/bombridge/links.py"), "\n# harmless comment\n", "a")
        proc = self.compare(repo, self.exclusion_manifest("m-excl-class-p.json", class_p="unauthorized exclusion"))
        self.assertNotEqual(proc.returncode, 0, "a protected change passed: " + proc.stdout[-800:])
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("class_p", proc.stdout)
        self.assertNotIn("0 difference(s)", proc.stdout)

    def test_excluding_semantic_or_legacy_or_tools_is_refused_even_on_an_unchanged_tree(self):
        for section in ("semantic", "golden_exports", "produced_legacy_exports", "tools", "served"):
            with self.subTest(section=section):
                proc = self.compare(self.pristine, self.exclusion_manifest("m-excl-%s.json" % section, **{section: "unauthorized exclusion"}))
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertIn(section, proc.stdout)

    def test_the_two_informational_exclusions_still_pass_on_an_unchanged_tree(self):
        proc = self.compare(self.pristine, self.exclusion_manifest("m-excl-ok.json", environment="informational"))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
