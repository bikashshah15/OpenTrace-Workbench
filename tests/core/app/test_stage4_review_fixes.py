"""Stage 4 re-review fixes S4RR-01/02/03/07/09/10 (synthetic trees; nothing executed, imported or fetched)."""
import json
import os
import shutil
import tempfile
import unittest

from opentrace_core.app import ai_assets as aa, crypto_assets as ca
from opentrace_core.live import ai_source, crypto_source, source_declarations as sd
from tests.core.app import test_ai_assets as ta, test_crypto_assets as tc
from tests.core.app.test_stage4_base_compat import GOLDEN

URL, SHA = "https://github.com/acme/widget", "e" * 40


def collect(files):
    root = tempfile.mkdtemp(prefix="ot-s4rr-")
    try:
        for rel, data in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as h:
                h.write(data)
        return sd.collect(root, URL, SHA)
    finally:
        shutil.rmtree(root, ignore_errors=True)


LONG = "/".join(["d" * 60] * 9)          # 539 characters


class LongPath(unittest.TestCase):
    def test_one_overlong_path_is_dropped_not_fatal_and_other_assets_survive(self):
        out = collect({LONG + "/a.py": "import onnxruntime\nimport jwt\njwt.encode(p, k, algorithm='HS256')\n", "ok/b.py": "import tflite_runtime\nimport jwt\njwt.encode(p, k, algorithm='RS256')\n"})
        b = ta.binding()
        p = aa.build_payload({"aibom": ta.inv(ta.doc([ta.ml("m.onnx", [("m/a.yaml", 3)])])), "source": ai_source.present(out), "mode": "live"}, b, {"generation": b["generation"], "filter": "all", "offset": 0})
        names = [a["display_name"] for a in p["assets"]]
        self.assertIn("tflite_runtime", names); self.assertNotIn("onnxruntime", names); self.assertIn("m.onnx", names)
        self.assertEqual([x["outcome"] for x in p["producers"] if x["provenance"]["producer_id"] == aa.SOURCE_ID], ["partial"])
        cb = tc.binding()
        cd = tc.cbom_doc([tc.comp("SHA-256", [("a.js", 3)])])
        q = ca.build_payload({"cbom": tc.original(cd), "source": None, "src_obs": crypto_source.present(out), "mode": "live"}, cb, {"generation": cb["generation"], "filter": "all", "offset": 0})
        cn = [a["display_name"] for a in q["assets"]]
        self.assertIn("RS256", cn); self.assertNotIn("HS256", cn); self.assertIn("SHA-256", cn)
        self.assertEqual([x["outcome"] for x in q["producers"] if x["provenance"]["producer_id"] == ca.SOURCE_ID], ["partial"])


class Redaction(unittest.TestCase):
    def jwt(self, src):
        return collect({"a.py": src})["record"]["crypto_source"]["jwt"]

    def test_unterminated_by_truncation_is_not_leaked(self):
        pad = "x = 1  # " + "p" * 560 + "\n"
        src = "import jwt\n" + "t = jwt.encode(payload,\n    " + "z" * 0 + "'" + "TOPSECRETKEYVALUE" * 3 + "', algorithm='HS256')\n"
        for o in self.jwt(src):
            self.assertNotIn("TOPSECRET", o["excerpt"])
        src2 = "import jwt\nt = jwt.encode({" + ", ".join('"k%d": 1' % i for i in range(75)) + '}, "TOPSECRETKEY", algorithm="HS256")\n'
        for o in self.jwt(src2):
            self.assertNotIn("TOPSECRET", o["excerpt"])
            self.assertLessEqual(len(o["excerpt"]), crypto_source.MAX_EXCERPT)

    def test_triple_quoted_multiline_literal_is_redacted(self):
        o = self.jwt('import jwt\nt = jwt.encode(p, """\nsuper-secret-key\n""", algorithm="HS256")\n')[0]
        self.assertNotIn("super-secret-key", o["excerpt"])
        self.assertEqual(o["algorithms"], ["HS256"])

    def test_hashlib_excerpt_literals_are_redacted_at_projection(self):
        out = collect({"a.py": 'import hashlib\nk = hashlib.pbkdf2_hmac("sha256", b"hunter2-password", b"salt", 1000)\n'})
        cb = tc.binding()
        q = ca.build_payload({"cbom": None, "source": None, "src_obs": crypto_source.present(out), "mode": "live"}, cb, {"generation": cb["generation"], "filter": "all", "offset": 0})
        self.assertNotIn("hunter2", json.dumps(q))
        self.assertIn("sha256", [a["display_name"] for a in q["assets"]])


class Reviews(unittest.TestCase):
    def test_long_path_places_do_not_collide(self):
        path = "/".join(["p" * 60] * 3) + "/x.py"
        src = "import ssl\nx = ssl.create_default_context()\nx.check_hostname = False\ny = ssl.create_default_context()\ny.check_hostname = False\nz = ssl.create_default_context()\nz.check_hostname = False\n"
        out = collect({path: src})
        cb = tc.binding()
        q = ca.build_payload({"cbom": None, "source": None, "src_obs": crypto_source.present(out), "mode": "live"}, cb, {"generation": cb["generation"], "filter": "all", "offset": 0})
        self.assertEqual(len(q["review_items"]), 3)
        self.assertEqual(len({r["review_id"] for r in q["review_items"]}), 3)
        self.assertTrue(all(r["condition"].count(":") >= 1 and len(r["condition"]) <= 200 for r in q["review_items"]))
        deep = "/".join(["q" * 70] * 6) + "/y.py"                         # path far longer than the condition budget
        out = collect({deep: src})
        q = ca.build_payload({"cbom": None, "source": None, "src_obs": crypto_source.present(out), "mode": "live"}, cb, {"generation": cb["generation"], "filter": "all", "offset": 0})
        self.assertEqual(len(q["review_items"]), 3)


class Starred(unittest.TestCase):
    def test_third_positional_after_starred_is_dynamic(self):
        o = collect({"a.py": 'import jwt\njwt.decode(*a, k, ["HS256"])\n'})["record"]["crypto_source"]["jwt"]
        self.assertEqual([x["algorithm_source"] for x in o], ["dynamic"])


class CollectedEmptyLive(unittest.TestCase):
    """S4RR-09: a real live scan always passes ``present(sink)``. Complete-and-empty equals the pinned base payload; incomplete-and-empty differs by design."""
    D = ta.doc([ta.ml("yolo.onnx", [("m/a.yaml", 3)]), ta.ml("big.gguf", [("m/b.yaml", None)], url="https://example.org/big.gguf")])

    def ai(self, src):
        return ta.build({"aibom": ta.inv(self.D), "source": src, "mode": "live"})[0]

    def test_complete_empty_scan_equals_base_golden(self):
        src = ai_source.present(collect({"a.py": "x = 1\n"}))
        self.assertEqual(json.dumps(self.ai(src), sort_keys=True), json.dumps(GOLDEN["ai.models.live"], sort_keys=True))
        cd = tc.cbom_doc([tc.comp("SHA-256", [("a.js", 3), ("b.js", 9)]), tc.comp("AES-128-GCM", [("c.js", 4)])])
        cs = crypto_source.present(collect({"a.py": "x = 1\n"}))
        got = tc.build({"cbom": tc.original(cd), "source": None, "src_obs": cs, "mode": "live"})[0]
        self.assertEqual(json.dumps(got, sort_keys=True), json.dumps(GOLDEN["crypto.cbom.live"], sort_keys=True))

    def test_incomplete_empty_scan_adds_a_partial_producer_by_design(self):
        src = ai_source.present(collect({"bad.py": "def (:\n", "ok.py": "x = 1\n"}))
        p = self.ai(src)
        self.assertEqual(p["availability"]["state"], "partial")
        self.assertEqual([x["outcome"] for x in p["producers"] if x["provenance"]["producer_id"] == aa.SOURCE_ID], ["partial"])
        self.assertEqual(p["assets"], GOLDEN["ai.models.live"]["assets"])           # the inventory assets themselves are unchanged


if __name__ == "__main__":
    unittest.main()
