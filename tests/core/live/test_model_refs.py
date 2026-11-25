"""UIP-13: the bounded static model-reference collector (offline, in process; synthetic trees; no network, no execution).

Every tree here is SYNTHETIC (written by the test into a temp directory). Nothing is imported, executed or downloaded.
"""
import json
import os
import shutil
import tempfile
import threading
import unittest

from opentrace_core.live import model_refs as mr, source_declarations as sd

URL = "https://github.com/acme/widget"
SHA = "a" * 40


class Tree(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ot-modelrefs-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def w(self, rel, data):
        path = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())

    def collect(self, **kw):
        out = sd.collect(self.root, URL, SHA, **kw)
        return out

    def refs(self, **kw):
        out = self.collect(**kw)
        return out["record"]["model_references"], out["record"]["searched"]["model_sources"]


class ReferenceFormsTest(Tree):
    def test_python_string_constants_dockerfile_and_shell_lines(self):
        self.w("a.py", 'M = "https://h.example/a.onnx"\n')
        self.w("docker/Dockerfile", "RUN wget https://h.example/b.tflite\n")
        self.w("run.sh", "curl -o m https://h.example/c.gguf\n")
        refs, summary = self.refs()
        self.assertEqual([(r["path"], r["source_kind"], r["locator"]) for r in refs],
                         [("a.py", "python", "https://h.example/a.onnx"), ("docker/Dockerfile", "dockerfile", "https://h.example/b.tflite"), ("run.sh", "shell", "https://h.example/c.gguf")])
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["references"], {"observed": 3, "recorded": 3, "over_limit": 0, "groups": 3})

    def test_every_listed_extension_is_recognized_and_archives_are_not(self):
        body = "".join(f'x{i} = "https://h.example/m{e}"\n' for i, e in enumerate(mr.EXTENSIONS)) + 'z = "https://h.example/m.zip"\nt = "https://h.example/m.tar.gz"\n'
        self.w("a.py", body)
        refs, _ = self.refs()
        self.assertEqual(sorted(r["locator"].rsplit("/", 1)[-1] for r in refs), sorted("m" + e for e in mr.EXTENSIONS))

    def test_query_and_fragment_stay_in_the_locator_and_only_the_path_is_matched(self):
        self.w("a.py", 'a = "https://h.example/m.onnx?download=1#part"\nb = "https://h.example/m.onnx?download=2#part"\nc = "https://h.example/m.txt?x=.onnx"\n')
        refs, _ = self.refs()
        self.assertEqual([r["locator"] for r in refs], ["https://h.example/m.onnx?download=1#part", "https://h.example/m.onnx?download=2#part"])

    def test_extension_recognition_is_case_insensitive_but_the_locator_is_never_case_folded(self):
        self.w("a.sh", "wget https://H.example/M.ONNX\n")
        refs, _ = self.refs()
        self.assertEqual(refs[0]["locator"], "https://H.example/M.ONNX")

    def test_adjacent_literals_are_joined_by_the_language_and_recorded_as_such(self):
        self.w("a.py", 'M = ("https://h.example/a/"\n     "b.tflite")\n')
        refs, _ = self.refs()
        [r] = refs
        self.assertEqual((r["method"], r["line"], r["end_line"], r["string_literal"]), ("python-ast-joined-string-literals", 1, 2, "https://h.example/a/b.tflite"))
        self.assertIn("b.tflite", r["excerpt"])

    def test_repeated_identical_tokens_are_separate_occurrences_with_an_ordinal(self):
        self.w("a.sh", "wget https://h.example/m.pt https://h.example/m.pt\n")
        self.w("b.sh", "wget https://h.example/m.pt\n")
        refs, summary = self.refs()
        self.assertEqual([(r["path"], r["ordinal"]) for r in refs], [("a.sh", 0), ("a.sh", 1), ("b.sh", 0)])
        self.assertEqual(len({r["occurrence_id"] for r in refs}), 3)
        self.assertEqual((summary["references"]["observed"], summary["references"]["groups"]), (3, 1))

    def test_fstring_pieces_and_template_tokens_are_diagnostics_never_locators(self):
        self.w("a.py", 'a = f"https://h.example/{name}.onnx?rev={rev}#x"\nb = f"https://h.example/m.onnx?rev={rev}"\nc = "https://h.example/{}.onnx".format(1)\n'
                       'd = "https://h.example/%s.onnx" % n\ne = f"{base}/plain.txt"\n')
        self.w("Dockerfile", "RUN curl https://h.example/${MODEL}.onnx?rev=$REV#x https://h.example/m.onnx?rev=$REV\n")
        refs, summary = self.refs()
        self.assertEqual(refs, [])
        self.assertEqual(summary["dynamic"]["count"], 6)
        self.assertEqual({d["code"] for d in summary["diagnostics"]}, {"dynamic_expression"})
        self.assertTrue(summary["complete"])       # diagnostics are separate from file coverage (the capability rule treats dynamic ones as incompleteness)

    def test_a_string_inside_an_fstring_expression_is_ordinary_code(self):
        self.w("a.py", 'a = f"{\'https://h.example/m.onnx\'}"\n')
        refs, _ = self.refs()
        self.assertEqual([r["locator"] for r in refs], ["https://h.example/m.onnx"])

    def test_trailing_punctuation_is_stripped_from_the_token(self):
        self.w("a.sh", 'wget "https://h.example/m.onnx"; echo https://h.example/n.onnx.\n')
        refs, _ = self.refs()
        self.assertEqual([r["locator"] for r in refs], ["https://h.example/m.onnx", "https://h.example/n.onnx"])

    def test_other_schemes_and_path_only_references_are_not_collected(self):
        self.w("a.py", 's3 = "s3://b/m.onnx"\np = "models/m.onnx"\nf = "file:///m.onnx"\n')
        refs, _ = self.refs()
        self.assertEqual(refs, [])

    def test_comments_are_not_scanned_but_docstrings_are(self):
        self.w("a.py", '# https://h.example/c.onnx\n"""https://h.example/d.onnx"""\n')
        refs, _ = self.refs()
        self.assertEqual([r["locator"] for r in refs], ["https://h.example/d.onnx"])

    def test_nothing_is_executed_or_imported(self):
        marker = os.path.join(self.root, "executed")
        self.w("evil.py", f'open({marker!r}, "w").write("x")\nM = "https://h.example/m.onnx"\n')
        self.w("run.sh", f"touch {marker}\nwget https://h.example/n.onnx\n")
        refs, _ = self.refs()
        self.assertEqual(len(refs), 2)
        self.assertFalse(os.path.exists(marker))

    def test_no_git_directory_is_needed_and_output_is_deterministic(self):
        for name in ("b.py", "a.py", "sub/z.sh", "sub/a.sh"):
            self.w(name, 'M = "https://h.example/m.onnx"\n' if name.endswith(".py") else "wget https://h.example/m.onnx\n")
        one = json.dumps(self.refs()[0], sort_keys=True)
        two = json.dumps(self.refs()[0], sort_keys=True)
        self.assertEqual(one, two)
        self.assertEqual([r["path"] for r in json.loads(one)], ["a.py", "b.py", "sub/a.sh", "sub/z.sh"])

    def test_the_record_digest_covers_the_references(self):
        self.w("a.py", 'M = "https://h.example/m.onnx"\n')
        first = self.collect()["record_sha256"]
        self.w("a.py", 'M = "https://h.example/n.onnx"\n')
        self.assertNotEqual(first, self.collect()["record_sha256"])


class CoverageAndBoundsTest(Tree):
    def test_syntax_error_and_non_utf8_make_collection_incomplete_with_bounded_path_and_code_only(self):
        self.w("bad.py", "def (:\n")
        self.w("enc.sh", b"\xff\xfe wget https://h.example/m.onnx\n")
        self.w("ok.py", 'M = "https://h.example/m.onnx"\n')
        refs, s = self.refs()
        self.assertEqual(len(refs), 1)
        self.assertFalse(s["complete"])
        self.assertEqual(s["skipped"]["by_reason"], {"not_utf8": 1, "syntax_error": 1})
        self.assertEqual({tuple(sorted(d)) for d in s["diagnostics"]}, {("code", "path")})
        self.assertNotIn(self.root, json.dumps(s))
        self.assertEqual((s["selected"], s["processed"]), (3, 1))

    def test_symlink_and_unsafe_path_are_recorded_not_followed(self):
        self.w("real.sh", "wget https://h.example/m.onnx\n")
        os.symlink("real.sh", os.path.join(self.root, "link.sh"))
        refs, s = self.refs()
        self.assertEqual([r["path"] for r in refs], ["real.sh"])
        self.assertEqual(s["skipped"]["by_reason"], {"not_regular": 1})

    def test_over_long_paths_are_unsafe(self):
        self.assertFalse(mr.safe_path("a/" * 300 + "x.py"))
        self.assertFalse(mr.safe_path("a/../b.py"))
        self.assertFalse(mr.safe_path("a\\b.py"))
        self.assertTrue(mr.safe_path("pkg/m.py"))

    def test_per_file_bounds_skip_with_a_reason(self):
        self.w("big.sh", b"#" * (mr.MAX_FILE_BYTES + 1))
        self.w("lines.sh", b"x\n" * (mr.MAX_LINES + 1))
        refs, s = self.refs()
        self.assertEqual(s["skipped"]["by_reason"], {"over_line_limit": 1, "too_large": 1})
        self.assertFalse(s["complete"])

    def test_total_byte_budget(self):
        old = mr.MAX_TOTAL_BYTES
        mr.MAX_TOTAL_BYTES = 100
        self.addCleanup(setattr, mr, "MAX_TOTAL_BYTES", old)
        for i in range(4):
            self.w(f"f{i}.sh", "wget https://h.example/m.onnx\n" + "#" * 40)
        _, s = self.refs()
        self.assertGreaterEqual(s["skipped"]["by_reason"].get("over_total_bytes", 0), 1)

    def test_selected_file_cap_counts_the_overflow_and_is_incomplete(self):
        old = mr.MAX_FILES
        mr.MAX_FILES = 2
        self.addCleanup(setattr, mr, "MAX_FILES", old)
        for i in range(4):
            self.w(f"f{i}.sh", "wget https://h.example/m.onnx\n")
        refs, s = self.refs()
        self.assertEqual((s["selected"], s["over_file_limit"], len(refs)), (2, 2, 2))
        self.assertFalse(s["complete"])

    def test_reference_cap_keeps_the_first_in_traversal_order_and_counts_the_rest(self):
        old = mr.MAX_REFERENCES
        mr.MAX_REFERENCES = 3
        self.addCleanup(setattr, mr, "MAX_REFERENCES", old)
        self.w("a.sh", "".join(f"wget https://h.example/m{i}.onnx\n" for i in range(5)))
        refs, s = self.refs()
        self.assertEqual((len(refs), s["references"]["observed"], s["references"]["over_limit"]), (3, 5, 2))
        self.assertEqual([r["locator"][-7:] for r in refs], ["m0.onnx", "m1.onnx", "m2.onnx"])
        self.assertFalse(s["complete"])

    def test_diagnostic_listing_is_bounded_but_totals_are_exact(self):
        for i in range(mr.MAX_DIAGNOSTICS + 20):
            self.w(f"d{i:03d}.py", "def (:\n")
        _, s = self.refs()
        self.assertEqual((len(s["diagnostics"]), s["diagnostics_total"]["count"]), (mr.MAX_DIAGNOSTICS, mr.MAX_DIAGNOSTICS + 20))

    def test_a_locator_over_the_bound_is_a_diagnostic_never_truncated_or_emitted(self):
        self.w("a.sh", "wget https://h.example/" + "x" * 2100 + ".onnx\n")
        refs, s = self.refs()
        self.assertEqual(refs, [])
        self.assertEqual(s["diagnostics_total"]["by_code"], {"locator_too_long": 1})
        self.assertFalse(s["complete"])

    def test_record_byte_cap(self):
        old = mr.MAX_RECORD_BYTES
        mr.MAX_RECORD_BYTES = 700
        self.addCleanup(setattr, mr, "MAX_RECORD_BYTES", old)
        self.w("a.sh", "".join(f"wget https://h.example/m{i}.onnx\n" for i in range(6)))
        refs, s = self.refs()
        self.assertLess(len(refs), 6)
        self.assertEqual(s["references"]["over_limit"], 6 - len(refs))

    def test_a_long_line_gets_a_window_that_contains_the_locator(self):
        self.w("a.sh", "#" * 3000 + " wget https://h.example/m.onnx " + "#" * 3000 + "\n")
        [r], _ = self.refs()
        self.assertTrue(r["excerpt_truncated"])
        self.assertLessEqual(len(r["excerpt"]), mr.MAX_EXCERPT)
        self.assertIn(r["locator"], r["excerpt"])

    def test_soft_deadline_marks_the_rest_not_processed_and_incomplete(self):
        for i in range(3):
            self.w(f"f{i}.sh", "wget https://h.example/m.onnx\n")
        ticks = iter(range(0, 1000))
        out = mr.run_phase([(f"f{i}.sh", os.path.join(self.root, f"f{i}.sh"), "shell") for i in range(3)], clock=lambda: next(ticks) * 7.0, budget=20.0)
        s = out["summary"]
        self.assertTrue(s["deadline_hit"])
        self.assertGreater(s["not_processed_time_budget"], 0)
        self.assertFalse(s["complete"])

    def test_cancellation_returns_no_record(self):
        self.w("a.sh", "wget https://h.example/m.onnx\n")
        ev = threading.Event()
        ev.set()
        out = sd.collect(self.root, URL, SHA, cancel=ev)
        self.assertEqual((out["status"], out["record"]), ("cancelled", None))

    def test_cancellation_between_files_in_the_model_phase(self):
        self.w("a.sh", "wget https://h.example/m.onnx\n")
        ev = threading.Event()
        calls = {"n": 0}
        real = mr._read_bounded
        def reader(path, cancel):
            calls["n"] += 1
            ev.set()
            return real(path, cancel)
        mr._read_bounded = reader
        self.addCleanup(setattr, mr, "_read_bounded", real)
        self.assertIsNone(mr.run_phase([("a.sh", os.path.join(self.root, "a.sh"), "shell"), ("b.sh", os.path.join(self.root, "a.sh"), "shell")], cancel=ev))

    def test_an_unexpected_phase_error_is_incomplete_not_a_collection_failure(self):
        self.w("a.sh", "wget https://h.example/m.onnx\n")
        real = mr._text
        def boom(*a, **k):
            raise MemoryError()
        mr._text = boom
        self.addCleanup(setattr, mr, "_text", real)
        refs, s = self.refs()
        self.assertEqual(refs, [])
        self.assertEqual(s["skipped"]["by_reason"], {"parse_error": 1})
        self.assertFalse(s["complete"])

    def test_the_shared_walk_is_not_repeated_and_census_counts_each_kind(self):
        self.w("a.py", "x = 1\n")
        self.w("Dockerfile", "FROM x\n")
        self.w("k.dockerfile", "FROM x\n")
        self.w("run.sh", "x\n")
        self.w("a.go", "x\n")
        out = self.collect()
        m = out["record"]["searched"]["model_sources"]
        self.assertEqual(m["census"], {"python": 1, "dockerfile": 2, "shell": 1, "other_languages": 1, "matched_model_source_entries": 4})
        self.assertEqual(out["record"]["searched"]["traversal"]["entries_visited"], 5)

    def test_stage_two_fields_and_limits_are_unchanged(self):
        self.w("requirements.txt", "flask==2.0\n")
        out = self.collect()
        rec = out["record"]
        self.assertEqual(rec["schema"], "bombridge.source-declarations/1")
        self.assertEqual(rec["searched"]["limits"]["requirement_files"], 64)
        self.assertEqual(rec["searched"]["python"]["limits"]["python_files"], 2000)
        self.assertEqual(len(rec["requirement_files"]), 1)


class CorrectionsR2Test(Tree):
    def test_r2_04_the_record_byte_cap_is_a_traversal_order_prefix(self):
        old = mr.MAX_RECORD_BYTES
        mr.MAX_RECORD_BYTES = 5000
        self.addCleanup(setattr, mr, "MAX_RECORD_BYTES", old)
        self.w("a.sh", "wget https://h.example/big.onnx " + "\u00e9" * 600 + "\n")
        self.w("b.sh", "wget https://h.example/s1.onnx\n" + "".join(f"# \u00e9\u00e9\u00e9\n" for _ in range(1)))
        self.w("c.sh", "wget https://h.example/" + "x" * 1800 + ".onnx " + "\u00e9" * 500 + "\n")
        self.w("d.sh", "wget https://h.example/tiny.onnx\n")
        refs, s = self.refs()
        names = [r["path"] for r in refs]
        self.assertEqual(names, sorted(names))
        self.assertEqual(s["references"]["recorded"] + s["references"]["over_limit"], s["references"]["observed"])
        if s["references"]["over_limit"]:
            admitted = {r["path"] for r in refs}
            dropped_first = next(p for p in ("a.sh", "b.sh", "c.sh", "d.sh") if p not in admitted)
            self.assertTrue(all(p < dropped_first for p in admitted), "nothing after the first dropped record may be admitted")

    def test_r2_05_a_repeated_token_in_one_multiline_constant_gets_its_own_line(self):
        self.w("a.py", 'D = """\nhttps://h.example/m.onnx\nx\nhttps://h.example/m.onnx\n"""\n')
        refs, _ = self.refs()
        self.assertEqual([(r["line"], r["excerpt"]) for r in refs], [(2, "https://h.example/m.onnx"), (4, "https://h.example/m.onnx")])

    def test_r2_06_cr_only_line_endings_do_not_lose_the_file(self):
        self.w("a.py", b'A = 1\rM = "https://h.example/m.onnx"\r')
        refs, s = self.refs()
        self.assertEqual([(r["line"], r["locator"]) for r in refs], [(2, "https://h.example/m.onnx")])
        self.assertTrue(s["complete"])

    def test_r2_07_diagnostic_paths_are_cleaned_and_bounded(self):
        self.assertEqual(mr._clean_path("a\x01<b>\n" + "x" * 700), ("a?<b>?" + "x" * 700)[:512])
        self.w("a\x01b.sh", "wget https://h.example/m.onnx\n") if False else None
        out = mr.run_phase([("a/" * 300 + "x.sh", os.path.join(self.root, "none"), "shell"), ("p\x01<b>.sh", os.path.join(self.root, "none"), "shell")])
        for d in out["summary"]["diagnostics"]:
            self.assertLessEqual(len(d["path"]), 512)
            self.assertNotRegex(d["path"], r"[\x00-\x1f]")
        self.assertEqual(out["summary"]["skipped"]["by_reason"], {"unsafe_path": 2})

    def test_nested_fstring_format_spec_expressions_are_code_not_locators(self):
        self.w("a.py", 'a = f"{x:{\'https://h.example/a.onnx\'}}"\nb = f"{x:.2f}https://h.example/{y}.onnx"\n')
        refs, s = self.refs()
        self.assertEqual([r["locator"] for r in refs], ["https://h.example/a.onnx"])
        self.assertEqual(s["dynamic"]["count"], 1)


if __name__ == "__main__":
    unittest.main()
