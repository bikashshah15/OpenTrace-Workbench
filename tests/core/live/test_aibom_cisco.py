"""UIP-07C shared producer module: argument vector, environment, per-artifact gate (P8 steps 1-6), N-cases, completeness mapping (P6), path rules.

Expected outcomes are authored from the frozen contract, not copied from what the code returns."""
import json
import sys
import types
import unittest

from opentrace_core.live import policy
from tests.core.live import aibom_support as S

ac = S.cisco_module()
LISTING = {"requirements.txt", "app/main.py", "src/a.py", "pkg/__init__.py"}


class ConstantsTest(unittest.TestCase):
    def test_policy_and_module_constants_agree(self):
        self.assertEqual((ac.PINNED_VERSION, ac.PHASE_SECONDS, ac.MAX_ARTIFACT_BYTES, ac.MAX_COMPONENTS),
                         (policy.AIBOM_PIN, policy.AIBOM_PHASE_SECONDS, policy.MAX_AIBOM_OUTPUT, policy.MAX_AIBOM_COMPONENTS))
        self.assertEqual((ac.PINNED_VERSION, ac.MODEL, ac.SCAN_ROOT, ac.SPEC_VERSION), ("1.10.1", "gpt-6-luna", "/scan/repo", "1.6"))
        self.assertEqual((policy.AIBOM_ENABLE_VAR, policy.AIBOM_ENABLE_VALUE), ("OPENTRACE_LIVE_AIBOM", "cisco"))

    def test_the_module_is_standard_library_only(self):
        import ast
        import os
        tree = ast.parse(open(os.path.join(S.LIVE, "aibom_cisco.py")).read())
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                mods.add((node.module or "").split(".")[0])
        stdlib = set(sys.stdlib_module_names)
        # cyclonedx is imported lazily inside validate_schema only (worker image); every top-level import is the standard library
        top_level = {n.names[0].name.split(".")[0] for n in tree.body if isinstance(n, ast.Import)} | {(n.module or "").split(".")[0] for n in tree.body if isinstance(n, ast.ImportFrom)}
        self.assertTrue(top_level <= stdlib, top_level - stdlib)
        self.assertIn("cyclonedx", mods)


class ArgvEnvTest(unittest.TestCase):
    EXPECTED = ["/venv/cisco-aibom", "analyze", "/scan/repo", "-o", "{fmt}", "-O", "/out/f", "--llm-provider", "openai", "--llm-api-base", "http://gateway:8788/v1",
                "--llm-model", "gpt-6-luna", "--custom-catalog", "/opt/aibom/empty-catalog.json", "--cache-dir", "/work/j/cache", "--no-galileo", "--no-code-snippets",
                "--no-progress", "--validate", "--llm-init-kwargs", '{"use_responses_api": false, "reasoning_effort": "none"}', "--agentic-timeout", "90",
                "--agentic-max-retry-seconds", "240", "--agentic-concurrency", "1", "--agentic-batch-size", "5", "--agentic-max-consecutive-failures", "3"]

    def vector(self, fmt):
        return ac.build_argv("/venv/cisco-aibom", fmt=fmt, out_path="/out/f", cache_dir="/work/j/cache", catalog_path="/opt/aibom/empty-catalog.json")

    def test_the_exact_vector_for_both_passes(self):
        for fmt in ("cyclonedx", "json"):
            self.assertEqual(self.vector(fmt), [a.replace("{fmt}", fmt) for a in self.EXPECTED])
        with self.assertRaises(ValueError):
            self.vector("sarif")

    def test_forbidden_flags_and_repository_values_are_absent(self):
        argv = self.vector("cyclonedx")
        for flag in ("--agentic-review-secrets", "--llm-reasoning", "--llm-api-key", "--post-url", "--galileo", "--ai-defense-api-key", "--platform-token",
                     "--include-code-snippets", "--github-org", "--repos-file", "--images-file"):
            self.assertNotIn(flag, argv, flag)
        self.assertEqual(json.loads(argv[argv.index("--llm-init-kwargs") + 1]), {"use_responses_api": False, "reasoning_effort": "none"})
        self.assertEqual(argv[argv.index("--llm-api-base") + 1], "http://gateway:8788/v1")
        self.assertNotIn("api.openai.com", " ".join(argv))
        # a repository-controlled directory name cannot reach the vector: only constants and OpenTrace-owned paths are inputs
        self.assertEqual(sorted(a for a in argv if a.startswith("/")), sorted(["/venv/cisco-aibom", "/scan/repo", "/out/f", "/opt/aibom/empty-catalog.json", "/work/j/cache"]))

    def test_environment_is_an_allowlist_and_inherits_nothing(self):
        env = ac.scrub_env({"OPENAI_API_KEY": "x", "AWS_SECRET_ACCESS_KEY": "y", "HOME": "/root"}, scratch_home="/work/j/home", scratch_tmp="/work/j/tmp",
                           token="tok" * 12, kb_path="/opt/aibom/kb.duckdb", kb_sha256="0" * 64, env_file="/opt/aibom/empty.env", venv_bin="/opt/venv/bin")
        self.assertTrue(set(env) <= set(ac.ENV_ALLOWLIST))
        self.assertEqual(env["HOME"], "/work/j/home")
        self.assertEqual(env["AIBOM_LLM_API_KEY"], "tok" * 12)
        self.assertEqual(env["AIBOM_ENV_FILE"], "/opt/aibom/empty.env")
        for name in env:
            self.assertFalse(name.startswith(("OPENAI", "AWS", "ANTHROPIC", "GITHUB", "AI_DEFENSE", "GALILEO")), name)
        self.assertNotIn("OPENAI_API_KEY", env)

    def test_the_display_command_names_the_pin_and_model_only(self):
        text = ac.display_command()
        self.assertIn("1.10.1", text)
        self.assertIn("gpt-6-luna", text)
        self.assertNotIn("http", text)


class GateTest(unittest.TestCase):
    def good(self, **kw):
        return S.cdx_bytes([S.comp("openai"), S.comp("langchain", line=2), S.comp("a-model", "machine-learning-model", "app/main.py", 9, "model")], **kw)

    def test_a_conforming_artifact_is_accepted(self):
        doc, error, cats = ac.check_artifact(self.good())
        self.assertEqual((error, cats), (None, {}))
        self.assertEqual(len(doc["components"]), 3)
        object_form = json.loads(self.good())
        object_form["metadata"]["tools"] = {"components": [{"type": "application", "name": "cisco-aibom", "version": "1.10.1"}]}
        self.assertIsNone(ac.check_artifact(json.dumps(object_form).encode())[1])

    def test_structural_refusals(self):
        cases = {
            "not json": (b"{", "output_not_json"), "array": (b"[]", "output_not_json"), "bad utf8": (b"\xff", "output_not_json"),
            "nan": (b'{"bomFormat":"CycloneDX","x":NaN}', "output_not_json"),
            "other format": (json.dumps({"bomFormat": "SPDX", "specVersion": "1.6"}).encode(), "unsupported_spec_version"),
            "spec 1.5": (S.cdx_bytes(spec="1.5"), "unsupported_spec_version"), "spec 1.7": (S.cdx_bytes(spec="1.7"), "unsupported_spec_version"),
            "version": (S.cdx_bytes(version="1.10.0"), "producer_mismatch"), "no tools": (S.cdx_bytes(tools=[]), "producer_mismatch"),
            "two tools": (S.cdx_bytes(tools=[{"name": "cisco-aibom", "version": "1.10.1"}, {"name": "other", "version": "1"}]), "producer_mismatch"),
            "other tool": (S.cdx_bytes(tools=[{"name": "syft", "version": "1.10.1"}]), "producer_mismatch"),
            "no metadata": (json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}).encode(), "producer_mismatch"),
            "component type": (S.cdx_bytes(extra={"components": [{"type": 5, "name": "x"}]}), "output_components_invalid"),
            "component name": (S.cdx_bytes(extra={"components": [{"type": "library"}]}), "output_components_invalid"),
            "components not list": (S.cdx_bytes(extra={"components": {}}), "output_components_invalid"),
            "too many": (S.cdx_bytes(extra={"components": [{"type": "library", "name": "n%d" % i} for i in range(2001)]}), "output_components_invalid"),
        }
        for name, (data, reason) in cases.items():
            doc, error, cats = ac.check_artifact(data)
            self.assertEqual((doc, error), (None, reason), name)
        self.assertEqual(ac.check_artifact(b"x" * (ac.MAX_ARTIFACT_BYTES + 1))[1], "output_too_large")
        self.assertEqual(ac.check_artifact("not bytes")[1], "output_too_large")
        self.assertEqual(len(json.loads(S.cdx_bytes(extra={"components": [{"type": "library", "name": "n%d" % i} for i in range(2000)]}))["components"]), 2000)
        self.assertIsNone(ac.check_artifact(S.cdx_bytes(extra={"components": [{"type": "library", "name": "n%d" % i} for i in range(2000)]}))[1])

    def forms(self):
        return {
            "url_userinfo": "https://user:" + "pw" + "@host.example/x", "pem_private_key": "-----BEGIN " + "RSA PRIVATE KEY-----",
            "aws_access_key_id": S.fragments("AK", "IA", "IOSFODNN7", "EXAMPLE"), "github_token": S.fragments("gh", "p_", "a" * 36),
            "openai_style_key": S.fragments("s", "k-", "proj-", "A" * 30), "slack_token": S.fragments("xo", "xb-", "1234567890-abc"),
            "stripe_key": S.fragments("s", "k_", "live_", "a" * 20), "google_api_key": S.fragments("AI", "za", "A" * 35),
        }

    def test_every_recognised_secret_form_is_refused_wherever_it_hides(self):
        for category, text in self.forms().items():
            for where in ("description", "storage_uri", "config_source", "dataset_source", "name", "property_value", "bom_ref", "metadata", "key"):
                pairs = [S.comp("openai")]
                doc = S.cdx_doc(pairs)
                c = doc["components"][0]
                if where == "description":
                    c["description"] = "uses " + text
                elif where in ("storage_uri", "config_source", "dataset_source"):
                    c["properties"].append({"name": "cisco-aibom:" + where, "value": text})
                elif where == "name":
                    c["name"] = text
                elif where == "property_value":
                    c["properties"].append({"name": "x", "value": text})
                elif where == "bom_ref":
                    c["bom-ref"] = text
                elif where == "metadata":
                    doc["metadata"]["note"] = text
                else:
                    c[text] = 1
                result = ac.check_artifact(json.dumps(doc).encode())
                self.assertEqual(result[1], "sensitive_content", (category, where))
                self.assertIn(category, result[2], (category, where))
                self.assertNotIn(text, json.dumps(result[2]), "the category counts never echo the matched value")
                self.assertTrue(set(result[2]) <= set(ac.GATE_CATEGORIES))

    def test_secret_components_and_vulnerabilities_are_refused(self):
        secret = S.comp("hardcoded-key", "application", kind="secret")
        self.assertEqual(ac.check_artifact(S.cdx_bytes([S.comp("a"), secret]))[2], {"secret_component": 1})
        for vulns in ([{"id": "aibom-secret-1"}], [{}], [1]):
            result = ac.check_artifact(S.cdx_bytes(extra={"vulnerabilities": vulns}))
            self.assertEqual((result[1], result[2]), ("sensitive_content", {"vulnerabilities_present": 1}))
        self.assertIsNone(ac.check_artifact(S.cdx_bytes(extra={"vulnerabilities": []}))[1], "an empty list is not a finding")

    def test_ordinary_text_is_not_a_false_positive(self):
        harmless = ["git@github.com:org/repo.git", "https://github.com/org/repo", "https://github.com/org/repo@v1", "user@example.com", "sk-short", "the AKIA prefix",
                    "ghp_tooshort", "postgres://localhost/db", "AIza", "a model called luna-6", "-----BEGIN CERTIFICATE-----"]
        doc = S.cdx_doc([S.comp("openai")])
        doc["components"][0]["description"] = " | ".join(harmless)
        self.assertEqual(ac.check_artifact(json.dumps(doc).encode())[1], None)

    def test_deeply_nested_strings_are_still_scanned_and_bounded(self):
        doc = S.cdx_doc([S.comp("openai")])
        nested = cur = []
        for _ in range(30):
            nxt = []
            cur.append(nxt)
            cur = nxt
        cur.append(self.forms()["github_token"])
        doc["metadata"]["note"] = nested
        self.assertEqual(ac.check_artifact(json.dumps(doc).encode())[1], "sensitive_content")


class SchemaValidationTest(unittest.TestCase):
    """P8 step 7. The real validator runs in the worker image (TEST-1 container tests); here its three outcomes are driven through a stand-in."""

    def install(self, behaviour):
        schema, validation, jsonmod = (types.ModuleType(n) for n in ("cyclonedx.schema", "cyclonedx.validation", "cyclonedx.validation.json"))
        schema.SchemaVersion = types.SimpleNamespace(V1_6="1.6")

        class Validator:
            def __init__(self, version):
                self.version = version

            def validate_str(self, text, all_errors=False):
                self.__class__.seen = (self.version, all_errors)
                if behaviour == "raise":
                    raise RuntimeError("missing extra")
                return None if behaviour == "valid" else object()
        jsonmod.JsonValidator = Validator
        mods = {"cyclonedx": types.ModuleType("cyclonedx"), "cyclonedx.schema": schema, "cyclonedx.validation": validation, "cyclonedx.validation.json": jsonmod}
        saved = {k: sys.modules.get(k) for k in mods}
        sys.modules.update(mods)
        self.addCleanup(lambda: [sys.modules.pop(k, None) if v is None else sys.modules.__setitem__(k, v) for k, v in saved.items()])
        return Validator

    def test_valid_invalid_and_unavailable(self):
        v = self.install("valid")
        self.assertIsNone(ac.validate_schema(b"{}"))
        self.assertEqual(v.seen, ("1.6", True))                       # the 1.6 schema, with all_errors
        self.install("invalid")
        self.assertEqual(ac.validate_schema(b"{}"), "schema_invalid")        # N1/N2: any returned error refuses
        self.install("raise")
        self.assertEqual(ac.validate_schema(b"{}"), "schema_validator_unavailable")   # N3: the F0 signature is a refusal, never a skip
        self.assertEqual(ac.validate_schema(b"\xff"), "schema_validator_unavailable")

    def test_without_the_library_the_answer_is_unavailable(self):
        for k in [k for k in sys.modules if k == "cyclonedx" or k.startswith("cyclonedx.")]:
            self.addCleanup(sys.modules.__setitem__, k, sys.modules[k])
            del sys.modules[k]
        sys.modules["cyclonedx"] = None            # import raises ImportError
        self.addCleanup(sys.modules.pop, "cyclonedx", None)
        self.assertEqual(ac.validate_schema(b"{}"), "schema_validator_unavailable")


class CompletenessTest(unittest.TestCase):
    def f(self, status="success", count=0, reasons=None):
        return {"agentic_status": status, "agentic_degraded_count": count, "agentic_degradation_reasons": {} if reasons is None else reasons, "status": "completed"}

    def test_the_exhaustive_mapping_rows(self):
        m = ac.map_completeness
        self.assertEqual(m(self.f("success", 0, {}), True), ("verified", {}))
        self.assertEqual(m(self.f("success", 2, {"provider_outage": 2}), True), ("unverified", {"completeness_unverified": 1}))
        self.assertEqual(m(self.f("success", 0, {"rate_limited": 1}), True), ("unverified", {"completeness_unverified": 1}))
        self.assertEqual(m(self.f("degraded", 2, {"missing_agentic_verdict": 2}), True), ("degraded", {"agentic_degraded_count": 2}))
        self.assertEqual(m(self.f("degraded", 3, {"provider_outage": 1, "rate_limited": 2}), True), ("degraded", {"agentic_degraded_count": 3}))
        self.assertEqual(m(self.f("degraded", 0, {}), True), ("unverified", {"completeness_unverified": 1}))
        self.assertEqual(m(self.f("degraded", 2, {"provider_outage": 1}), True), ("unverified", {"completeness_unverified": 1}))     # sum != count
        self.assertEqual(m(self.f("skipped", 0, {}), True), ("skipped", {"agentic_skipped": 1}))
        self.assertEqual(m(self.f("skipped", 7, {"batch_timeout": 7}), True), ("skipped", {"agentic_skipped": 1}))

    def test_invalid_inputs_and_binding_failures_are_unverified_and_invent_no_count(self):
        unverified = ("unverified", {"completeness_unverified": 1})
        bad = [self.f("weird"), self.f(None), self.f("success", True), self.f("success", 1.0), self.f("success", -1), self.f("degraded", 1_000_001, {"provider_outage": 1_000_001}),
               self.f("degraded", 1, {"made_up_reason": 1}), self.f("degraded", 1, {"provider_outage": 0}), self.f("degraded", 1, {"provider_outage": True}),
               self.f("degraded", 1, {"provider_outage": 1.0}), self.f("degraded", 1, []), self.f("degraded", 1, None), {"agentic_status": "success"}, {}, None, "x",
               self.f("degraded", True, {"provider_outage": 1}), self.f("skipped", True, {})]      # a boolean count would equal 1: it must not be read as an integer
        for fields in bad:
            if isinstance(fields, dict) and fields.get("agentic_degradation_reasons") is None and "agentic_degradation_reasons" in fields:
                pass
            self.assertEqual(ac.map_completeness(fields, True), unverified, fields)
        for status in ("success", "degraded", "skipped"):
            self.assertEqual(ac.map_completeness(self.f(status, 1 if status == "degraded" else 0, {"provider_outage": 1} if status == "degraded" else {}), False), unverified)
        self.assertEqual(ac.map_completeness(None, False), unverified)

    def test_only_one_typed_count_family_may_be_non_zero(self):
        self.assertTrue(ac.counts_consistent({}))
        self.assertTrue(ac.counts_consistent({"agentic_degraded_count": 3}))
        self.assertFalse(ac.counts_consistent({"agentic_degraded_count": 3, "agentic_skipped": 1}))
        self.assertFalse(ac.counts_consistent({"agentic_skipped": 1, "completeness_unverified": 1}))
        self.assertFalse(ac.counts_consistent({"agentic_degraded_count": True}))
        self.assertFalse(ac.counts_consistent({"agentic_degraded_count": -1}))

    def test_the_replay_status_fields_are_read_from_the_observed_shape(self):
        doc = S.replay_doc([S.comp("openai")], status="degraded", count=2, reasons={"missing_agentic_verdict": 2})
        self.assertEqual(ac.extract_replay(doc), {"agentic_status": "degraded", "agentic_degraded_count": 2, "agentic_degradation_reasons": {"missing_agentic_verdict": 2}, "status": "completed"})
        for bad in (None, [], {}, {"aibom_analysis": []}, {"aibom_analysis": {}}, {"aibom_analysis": {"metadata": 3}}):
            self.assertIsNone(ac.extract_replay(bad))

    def test_the_reason_vocabulary_covers_the_observed_and_pinned_hints(self):
        for observed in ("missing_agentic_verdict", "provider_outage"):
            self.assertIn(observed, ac.REASON_VOCABULARY)
        self.assertEqual(len(ac.REASON_VOCABULARY), 13)


class ComparisonTest(unittest.TestCase):
    def setUp(self):
        self.pairs = [S.comp("openai"), S.comp("langchain", line=2), S.comp("m", "machine-learning-model", "app/main.py", 9, "model", ref="m_app/main.py_9")]

    def eq(self, cdx_pairs=None, replay_pairs=None):
        return ac.components_equal(S.cdx_doc(cdx_pairs if cdx_pairs is not None else self.pairs), S.replay_doc(replay_pairs if replay_pairs is not None else self.pairs))

    def test_equal_sets_match_and_the_root_is_stripped(self):
        self.assertTrue(self.eq())
        rel = [S.comp("openai", file="requirements.txt")]
        self.assertTrue(ac.components_equal(S.cdx_doc(rel), S.replay_doc([S.comp("openai", file=S.ROOT_PATH + "/requirements.txt", ref=rel[0][0]["bom-ref"])])))

    def test_every_kind_of_difference_is_a_mismatch(self):
        c = lambda **k: S.comp("openai", **k)  # noqa: E731
        self.assertFalse(self.eq(replay_pairs=self.pairs[:2]))                                # missing component
        self.assertFalse(self.eq(replay_pairs=self.pairs + [S.comp("extra")]))                # extra component
        self.assertFalse(self.eq([c()], [S.comp("openai", kind="model", ctype="machine-learning-model", ref=c()[0]["bom-ref"])]))        # type differs
        self.assertFalse(self.eq([c()], [S.comp("other", ref=c()[0]["bom-ref"])]))            # name differs
        self.assertFalse(self.eq([c()], [S.comp("openai", file=S.ROOT_PATH + "/other.txt", ref=c()[0]["bom-ref"])]))   # path differs
        self.assertFalse(self.eq([c()], [S.comp("openai", line=99, ref=c()[0]["bom-ref"])]))  # line differs where both carry one
        self.assertFalse(self.eq([c()], [S.comp("openai", ref="different-ref")]))             # bom-ref / instance_id corroboration
        self.assertFalse(self.eq([c(), c()], [c()]))                                          # a multiset, not a set

    def test_a_line_present_on_only_one_side_is_not_compared(self):
        cdx = S.comp("openai")
        no_line = dict(cdx[0], properties=[p for p in cdx[0]["properties"] if p["name"] != "cisco-aibom:line"])
        self.assertTrue(ac.components_equal(S.cdx_doc([(no_line, cdx[1])]), S.replay_doc([cdx])))

    def test_unmappable_replay_types_fail_closed(self):
        c = S.comp("x")
        r = dict(c[1], component_type="brand_new_kind")
        self.assertFalse(ac.components_equal(S.cdx_doc([c]), S.replay_doc([(c[0], r)])))
        self.assertFalse(ac.components_equal(S.cdx_doc([c]), {"aibom_analysis": {"sources": []}}))
        self.assertFalse(ac.components_equal(S.cdx_doc([c]), {}))

    def test_the_type_mapping_matches_the_pinned_reporter(self):
        expected = {"machine-learning-model": "model llm_endpoint model_endpoint embedding model_artifact", "library": "tool dependency", "data": "dataset vector_store",
                    "file": "skill", "application": ("agent mcp_server mcp_client training_run experiment_tracker model_registry data_versioning ml_pipeline "
                                                     "agent_proxy mcp_gateway retriever knowledge_base feature_store memory prompt hyperparameter guardrail observability secret other")}
        seen = set()
        for cdx, names in expected.items():
            for n in names.split():
                self.assertEqual(ac.cdx_type_for(n), cdx, n)
                seen.add(n)
        self.assertEqual(len(seen), 30, "every member of the pinned 30-value enum is mapped")
        self.assertIsNone(ac.cdx_type_for("not_in_the_enum"))
        self.assertIsNone(ac.cdx_type_for(None))


class PathRuleTest(unittest.TestCase):
    def test_a_path_is_verified_only_against_the_exported_listing(self):
        verified = ["/scan/repo/requirements.txt", "requirements.txt", "app/main.py", "./app/main.py", "app//main.py", "/scan/repo/app/../app/main.py", "src/./a.py"]
        for p in verified:
            self.assertEqual(ac.classify_path(p, LISTING), "verified", p)
        unverified = ["not/in/tree.py", "/scan/repo/missing.txt", "../etc/passwd", "/etc/passwd", "/scan/repo/../x", "/scan/other/requirements.txt", "..", ".", "",
                      "app\\main.py", "app/main.py\x00", "/", "/scan/repo", None, 5, "/scan/repo/app/../../etc/passwd"]
        for p in unverified:
            self.assertEqual(ac.classify_path(p, LISTING), "unverified", repr(p))

    def test_derived_ids_come_from_the_digest_and_an_opaque_ref(self):
        a = ac.derived_id("a" * 64, "name_/scan/repo/requirements.txt_1")
        self.assertEqual(a, ac.derived_id("a" * 64, "name_/scan/repo/requirements.txt_1"))
        self.assertNotEqual(a, ac.derived_id("b" * 64, "name_/scan/repo/requirements.txt_1"))
        self.assertNotEqual(a, ac.derived_id("a" * 64, "name_/other/root/requirements.txt_1"))
        self.assertEqual(len(a), 24)
        self.assertNotIn("scan", a)


if __name__ == "__main__":
    unittest.main()
