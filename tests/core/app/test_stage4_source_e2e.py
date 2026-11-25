"""Stage 4: AI / Crypto source observations end to end through the REAL loopback service (fake scanners, synthetic repository, no network).

This is the proof that the wiring runner -> source_declarations -> analysis.ai_source / analysis.crypto_source -> the two Workbench routes works;
the projection unit tests build their inputs by hand. SYNTHETIC repository files only.
"""
import json
import unittest

from tests.core.live.test_source_check import PATH, SOURCE, Workbench

AI = "/api/workbench/v1/ai-assets"
CRYPTO = "/api/workbench/v1/crypto-assets"
FILES = {
    PATH: SOURCE,
    "package-lock.json": b'{"name":"w","lockfileVersion":3,"packages":{}}\n',
    "det/cpu.py": (b"try:\n    from tflite_runtime.interpreter import Interpreter\nexcept ModuleNotFoundError:\n"
                   b"    from ai_edge_litert.interpreter import Interpreter\n"),
    "svc/llm.py": b'ENDPOINT = "http://127.0.0.1:11434/api/generate"\n',
    "auth/t.py": b'import jwt\nt = jwt.encode(p, k, algorithm="HS256")\n',
    "net/m.py": b'import paho.mqtt.client as mqtt\nc.tls_set(ca)\nc.tls_insecure_set(True)\n',
    "lib/h.py": b'import hashlib\nd = hashlib.md5(b"x").hexdigest()\n',
    # unsupported / dynamic forms: must emit nothing
    "bad/dyn.py": (b"import importlib\nm = importlib.import_module('onnxruntime')\nU = f'https://h.test/v1/chat/completions/{x}'\n"
                   b"try:\n    import openvino\nexcept Exception:\n    import tensorrt\n"),
}


class SourceE2E(Workbench):
    FILES = FILES

    def get(self, c, body, route, q=""):
        resp, p = c.json("GET", route + "?generation=%d%s" % (body["generation"], q))
        self.assertEqual(resp.status, 200, p)
        return p

    def test_ai_tab_shows_source_runtimes_service_and_fallback(self):
        c, body = self.run_live(self.serve())
        self.assertTrue(body["ok"], body)
        p = self.get(c, body, AI)
        by = {a["display_name"]: a for a in p["assets"]}
        self.assertEqual(set(by), {"tflite_runtime", "ai_edge_litert", "http://127.0.0.1:11434/api/generate", "openvino", "tensorrt"})
        self.assertEqual([x["provenance"]["producer_id"] for x in p["producers"]], ["opentrace-source-ai"])
        self.assertEqual(p["producers"][0]["outcome"], "completed")
        # the try/except-Exception form is ambiguous: its imports are observed, no relation is drawn for it; the ImportError form is
        self.assertEqual(len(p["links"]), 1)
        l = p["links"][0]
        self.assertEqual((l["from"], l["to"], l["relation"]), (by["tflite_runtime"]["asset_id"], by["ai_edge_litert"]["asset_id"], "conditionally_selects"))
        fb = by["ai_edge_litert"]["occurrences"][0]
        self.assertEqual(fb["alternative_of"], by["tflite_runtime"]["occurrences"][0]["occurrence_id"])
        self.assertEqual((fb["source_location"]["path"], fb["source_location"]["line_start"]), ("det/cpu.py", 4))
        self.assertTrue(all(a["provenance"]["experimental"] for a in p["assets"]))
        self.assertNotIn("onnxruntime", json.dumps(p), "importlib / dynamic forms emit nothing")
        self.assertEqual(p["filter_totals"]["runtimes"], 4)
        self.assertEqual(p["filter_totals"]["ai_services"], 1)

    def test_crypto_tab_shows_jwt_tls_hashlib_beside_but_apart_from_the_cbom(self):
        c, body = self.run_live(self.serve())
        self.assertTrue(body["ok"], body)
        p = self.get(c, body, CRYPTO)
        names = {a["display_name"]: a for a in p["assets"]}
        for expected in ("HS256", "MQTT TLS configuration", "md5"):
            self.assertIn(expected, names)
        src = [a for a in p["assets"] if a["provenance"]["producer_id"] == "opentrace-source-crypto"]
        self.assertTrue(src and all(a["provenance"]["origin"] == "supplemental_observation" and a["provenance"]["experimental"] for a in src))
        self.assertEqual([r["rule_id"] for r in p["review_items"]], ["source-observation.tls_verification_relaxed"])
        self.assertTrue(all(r["tone"] == "review" for r in p["review_items"]))
        self.assertNotIn("/", "".join(a["display_name"] for a in src).replace("(", "").replace(")", ""), "no path text in display names")
        self.assertEqual(self.get(c, body, CRYPTO, "&filter=findings")["page"]["assets_total"], 1)

    def test_session_end_removes_the_observations(self):
        c, body = self.run_live(self.serve())
        self.assertTrue(body["ok"], body)
        c.json("POST", "/api/session/end", {})
        resp, _ = c.json("GET", AI + "?generation=%d" % body["generation"])
        self.assertIn(resp.status, (403, 409))


for _n in [n for n in dir(Workbench) if n.startswith("test_")]:
    setattr(SourceE2E, _n, None)


if __name__ == "__main__":
    unittest.main()
