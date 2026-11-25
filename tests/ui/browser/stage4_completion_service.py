"""Stage 4 completion fixture service (test harness only): ONE synthetic service hosting the repositories of the closing campaign.

Repositories (each its own isolated scenario; SYNTHETIC files, fake scanners, no network, Docker, real scanner, provider or Cisco):
  aicrypto  supported AI + Crypto source forms (runtime fallback, endpoint literal, JWT, TLS, hashlib) and a supported model candidate
  unsupp    only UNSUPPORTED/dynamic forms (importlib, f-string endpoint, bare except, rebound jwt): the tabs must show no source observation
  partial   a file that cannot be parsed plus one supported runtime import (incomplete collection)
  modelsupp the existing synthetic supported + inconclusive model candidates (graph geometry, BOM)
  cbomfail  a repository whose CBOM generator fails (UIP-D19: no hand-off; copy correction)
  bounds    520 service literals and 520 JWT calls in one file (collector caps 500/500, asset page 30)
  aifault / cryptofault  the fixture service makes ONE new collector phase raise (monkeypatch in this service process only)
Usage: PYTHONPATH=<repo>:<repo>/src/core python3 tests/ui/browser/stage4_completion_service.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


u13 = _load("uip13_model_service")
u12 = u13.uip12

AICRYPTO = {
    "det/cpu.py": (b"try:\n    from tflite_runtime.interpreter import Interpreter\nexcept ModuleNotFoundError:\n"
                   b"    from ai_edge_litert.interpreter import Interpreter\nimport hailo_platform\n"),
    "svc/llm.py": b'ENDPOINT = "http://127.0.0.1:11434/api/generate"\n',
    "auth/t.py": b'import jwt\nt = jwt.encode(p, k, algorithm="HS256")\nc = jwt.decode(t, k, algorithms=["HS256", "RS256"])\n',
    "net/m.py": b'import paho.mqtt.client as mqtt\nc.tls_set(ca)\nc.tls_insecure_set(True)\n',
    "net/ctx.py": b'import ssl\nx = ssl.create_default_context()\nx.minimum_version = ssl.TLSVersion.TLSv1_2\n',
    "lib/h.py": b'import hashlib\nd = hashlib.md5(b"x").hexdigest()\nk = hashlib.pbkdf2_hmac("sha256", pw, salt, 1000)\n',
    "app/m.py": u13.PY1,
}
UNSUPP = {
    "bad/dyn.py": (b"import importlib\nm = importlib.import_module('onnxruntime')\nU = f'https://h.test/v1/chat/completions/{x}'\n"
                   b"try:\n    import openvino\nexcept:\n    import tensorrt\nimport jwt\njwt = other()\njwt.encode(p, k, algorithm='HS256')\n").replace(b"import openvino", b"x = 1  # no runtime import").replace(b"import tensorrt", b"y = 2"),
}
PARTIAL = {"bad/syntax.py": b"def (:\n", "ok/rt.py": b"import onnxruntime\n"}

# bounds: one file whose observations exceed the collectors' recorded caps (500 service literals, 500 JWT calls) and the 30-asset page
BOUNDS = {"big/many.py": ("".join('S%d = "http://10.0.%d.%d:8080/v1/chat/completions"\n' % (i, i // 200, i % 200) for i in range(520))
                          + "import jwt\n" + "".join("jwt.encode(p, k, algorithm='HS256')\n" for _ in range(520))).encode()}
# collector faults injected by THIS fixture service only (a monkeypatch in the service process; not product behaviour): the marker file makes ONE phase raise
AIFAULT = {"FAULT_AI.py": b"import onnxruntime\n", "ok/h.py": b"import hashlib\nhashlib.sha256(b'x')\nimport jwt\njwt.encode(p, k, algorithm='HS256')\n"}
CRYPTOFAULT = {"FAULT_CRYPTO.py": b"import jwt\n", "ok/rt.py": b"import onnxruntime\n", "ok/h.py": b"import hashlib\nhashlib.sha256(b'x')\n"}


def inject_faults():
    from opentrace_core.live import ai_source, crypto_source
    for mod, marker in ((ai_source, "FAULT_AI.py"), (crypto_source, "FAULT_CRYPTO.py")):
        orig = mod.run_phase

        def faulty(selected, *a, _orig=orig, _marker=marker, **k):
            if any(rel == _marker for rel, _ in selected):
                raise RuntimeError("fixture-injected collector fault")
            return _orig(selected, *a, **k)
        mod.run_phase = faulty


u13.CASES["final"] = [
    ("aicrypto", u13.repo(AICRYPTO, models=[("ref-1", "det", [u13.M1])])),
    ("unsupp", u13.repo(UNSUPP, models=[])),
    ("partial", u13.repo(PARTIAL, models=[])),
    ("modelsupp", dict(u13.CASES["matrix"])["pos"]),
    ("cbomfail", dict(u12.CASES["matrix"])["cbomfail"]),
    ("bounds", u13.repo(BOUNDS, models=[])),
    ("aifault", u13.repo(AIFAULT, models=[])),
    ("cryptofault", u13.repo(CRYPTOFAULT, models=[])),
]


def main():
    from opentrace_core.app import make_server
    inject_faults()
    live, root, _ = u13.build("final")
    srv = make_server(os.path.join(root, "s"), reap_seconds=3600, live=live)
    print("OpenTrace STAGE4 COMPLETION SYNTHETIC fixture service http://127.0.0.1:%d/" % srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.app.close()


if __name__ == "__main__":
    sys.exit(main())
