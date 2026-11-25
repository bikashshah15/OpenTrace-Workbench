"""Stage 4 increment A (contract S4-AI-SOURCE v1.0.0): the bounded static AI runtime / service / fallback collector.

Every tree is SYNTHETIC (written by the test into a temp directory). Nothing is imported, executed, downloaded or called.
"""
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from opentrace_core.live import ai_source, source_declarations as sd

URL = "https://github.com/acme/widget"
SHA = "b" * 40


def write(root, rel, data):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data if isinstance(data, bytes) else data.encode())


class Base(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ot-ai-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def ai(self, files, **kw):
        for rel, data in files.items():
            write(self.root, rel, data)
        out = sd.collect(self.root, URL, SHA, **kw)
        self.assertEqual(out["status"], "collected")
        return out["record"]["ai_source"], out


TRY_FALLBACK = """try:
    from tflite_runtime.interpreter import Interpreter
except ModuleNotFoundError:
    from ai_edge_litert.interpreter import Interpreter
"""


class Runtimes(Base):
    def test_import_forms_positive(self):
        a, _ = self.ai({"src/a.py": "import onnxruntime\nimport hailo_platform as hp\nfrom openvino.runtime import Core\nimport os\n"})
        self.assertEqual([(r["module"], r["form"], r["line"]) for r in a["runtimes"]],
                         [("onnxruntime", "import", 1), ("hailo_platform", "import", 2), ("openvino", "from_import", 3)])
        self.assertEqual(a["runtimes"][0]["path"], "src/a.py")
        self.assertEqual(len(a["runtimes"][0]["file_sha256"]), 64)
        self.assertEqual(a["runtimes"][1]["display"], "Hailo runtime (HailoRT)")
        self.assertEqual(a["relations"], [])

    def test_multi_import_statement_emits_each(self):
        a, _ = self.ai({"a.py": "import onnxruntime, tensorrt, json\n"})
        self.assertEqual(sorted(r["module"] for r in a["runtimes"]), ["onnxruntime", "tensorrt"])

    def test_unsupported_forms_emit_nothing(self):
        src = ("import importlib\nm = importlib.import_module('onnxruntime')\n__import__('tflite_runtime')\n"
               "from . import onnxruntime\nfrom .tflite_runtime import x\nimport torch\nimport tensorflow.lite\nname = 'onnxruntime'\n")
        a, _ = self.ai({"a.py": src})
        self.assertEqual(a["runtimes"], [])
        self.assertEqual(a["relations"], [])

    def test_lookalike_modules_do_not_match(self):
        a, _ = self.ai({"a.py": "import onnxruntime_extensions\nimport my_tflite_runtime\nfrom tensorrt_lean import x\n"})
        self.assertEqual(a["runtimes"], [])

    def test_import_is_not_execution_wording(self):
        _, out = self.ai({"a.py": "import onnxruntime\n"})
        self.assertTrue(any("not an installed package" in x for x in out["record"]["limitations"]))


class Fallback(Base):
    def test_preferred_fallback_positive_binds_correct_lines(self):
        a, _ = self.ai({"frigate/cpu.py": "import os\n\n" + TRY_FALLBACK})
        self.assertEqual(len(a["relations"]), 1)
        r = a["relations"][0]
        self.assertEqual((r["preferred"]["module"], r["preferred"]["line"]), ("tflite_runtime", 4))
        self.assertEqual((r["fallback"]["module"], r["fallback"]["line"]), ("ai_edge_litert", 6))
        self.assertIn("ImportError", r["condition"])
        self.assertLessEqual(len(r["condition"]), 200)
        self.assertEqual({x["module"] for x in a["runtimes"]}, {"tflite_runtime", "ai_edge_litert"})

    def test_tuple_handler_and_import_error(self):
        a, _ = self.ai({"a.py": "try:\n    import onnxruntime\nexcept (ImportError, ModuleNotFoundError):\n    import openvino\n"})
        self.assertEqual(len(a["relations"]), 1)

    def test_negative_forms_keep_imports_but_no_relation(self):
        cases = {
            "bare": "try:\n    import onnxruntime\nexcept:\n    import openvino\n",
            "exception": "try:\n    import onnxruntime\nexcept Exception:\n    import openvino\n",
            "same": "try:\n    import onnxruntime\nexcept ImportError:\n    import onnxruntime as o2\n",
            "two_in_body": "try:\n    import onnxruntime\n    import tensorrt\nexcept ImportError:\n    import openvino\n",
            "mixed_handlers": "try:\n    import onnxruntime\nexcept ImportError:\n    import openvino\nexcept ValueError:\n    pass\n",
            "non_runtime_fallback": "try:\n    import onnxruntime\nexcept ImportError:\n    onnxruntime = None\n",
            "nested_in_if": "try:\n    import onnxruntime\nexcept ImportError:\n    if True:\n        import openvino\n",
        }
        for name, src in cases.items():
            with self.subTest(name):
                a, out = self.ai({"a_%s.py" % name: src})
                self.assertEqual([r for r in a["relations"]], [], name)
                self.assertGreaterEqual(len(a["runtimes"]), 1, name)
            shutil.rmtree(self.root)
            os.makedirs(self.root)

    def test_ambiguous_is_counted(self):
        a, _ = self.ai({"a.py": "try:\n    import onnxruntime\nexcept ImportError:\n    import onnxruntime\n"})
        self.assertEqual(a["summary"]["ambiguous_relations"], 1)


class Services(Base):
    def test_endpoint_positive_sanitized(self):
        a, _ = self.ai({"llm.py": 'URL = "http://LocalHost:11434/api/generate?x=1#f"\nB = "https://api.example.test/v1/chat/completions"\nX = "https://e.test/api"\n'})
        self.assertEqual([s["endpoint"] for s in a["services"]], ["http://localhost:11434/api/generate", "https://api.example.test/v1/chat/completions"])

    def test_negative_and_diagnostics(self):
        src = ('A = f"https://h.test/v1/embeddings/{x}"\nB = "https://u:p@h.test/v1/embeddings"\nC = "https://h.test/{model}/v1/completions"\n'
               'D = "see https://h.test/v1/completions for docs"\nE = "https://h.test/other"\n"""https://h.test/api/chat"""\n'
               'F = "http:///v1/completions"\ndef f():\n    "http://h.test/v1/chat/completions"\n')
        a, _ = self.ai({"a.py": src})
        diag = a["summary"]["diagnostics"]
        self.assertEqual(diag.get("credential_in_url"), 1)
        self.assertEqual(diag.get("dynamic_expression"), 1)
        self.assertEqual(a["services"], [], "bare string statements (docstrings) emit nothing")
        self.assertNotIn("u:p", repr(a))

    def test_no_secret_or_credential_in_record(self):
        a, out = self.ai({"a.py": 'K = "https://user:secret@h.test/v1/chat/completions"\n'})
        self.assertNotIn("secret", repr(out["record"]))


class Review(Base):
    def test_try_body_with_other_statements_is_not_a_relation(self):
        a, _ = self.ai({"a.py": "try:\n    import onnxruntime\n    import mylocal\nexcept ImportError:\n    import openvino\n"})
        self.assertEqual(a["relations"], [])
        self.assertEqual(len(a["runtimes"]), 2)

    def test_import_excerpt_is_only_the_statement(self):
        a, _ = self.ai({"a.py": "import onnxruntime; KEY = 'sk-secret'\n"})
        self.assertEqual(a["runtimes"][0]["excerpt"], "import onnxruntime")
        self.assertNotIn("sk-secret", repr(a))


class Bounds(Base):
    def test_cancel_returns_no_record(self):
        write(self.root, "a.py", "import onnxruntime\n")
        ev = threading.Event()
        ev.set()
        out = sd.collect(self.root, URL, SHA, cancel=ev)
        self.assertEqual(out["status"], "cancelled")
        self.assertIsNone(ai_source.run_phase([("a.py", os.path.join(self.root, "a.py"))], cancel=ev))

    def test_deterministic(self):
        files = {"b/x.py": TRY_FALLBACK, "a/y.py": "import onnxruntime\n"}
        a1, o1 = self.ai(files)
        a2 = sd.collect(self.root, URL, SHA)["record"]["ai_source"]
        self.assertEqual(a1, a2)
        self.assertEqual([r["path"] for r in a1["runtimes"]], ["a/y.py", "b/x.py", "b/x.py"])

    def test_syntax_error_and_non_utf8_are_incomplete_not_empty(self):
        a, _ = self.ai({"bad.py": "def (:\n", "ok.py": "import onnxruntime\n", "bin.py": b"\xff\xfe"})
        s = a["summary"]
        self.assertFalse(s["complete"])
        self.assertEqual(s["count_kind"], "at_least")
        self.assertEqual(s["syntax_errors"]["count"], 1)
        self.assertEqual(len(a["runtimes"]), 1)

    def test_complete_when_clean(self):
        a, _ = self.ai({"ok.py": "x = 1\n"})
        self.assertTrue(a["summary"]["complete"])
        self.assertEqual(a["summary"]["count_kind"], "exact")
        self.assertEqual(a["runtimes"] + a["relations"] + a["services"], [])

    def test_caps_make_it_incomplete(self):
        with mock.patch.object(ai_source, "MAX_RUNTIME_OBS", 2):
            a, _ = self.ai({"a.py": "import onnxruntime\nimport openvino\nimport tensorrt\n"})
        self.assertEqual(len(a["runtimes"]), 2)
        self.assertEqual(a["summary"]["over_limit"]["runtimes"], 1)
        self.assertFalse(a["summary"]["complete"])

    def test_no_absolute_paths(self):
        a, _ = self.ai({"p/a.py": "import onnxruntime\n"})
        self.assertNotIn(self.root, repr(a))


if __name__ == "__main__":
    unittest.main()
