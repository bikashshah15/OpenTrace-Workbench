"""Stage 4 compatibility cases: representative inputs WITHOUT any Stage 4 source evidence.

``cases()`` runs against whichever opentrace_core is importable. The committed golden file was produced by running this module against the
pinned base commit 436844bcc502f36b12dace00eb21fb0aa5d4cc49 (before any Stage 4 change); the candidate's tests compare to that file, never to
the candidate's own output. Usage to regenerate from the base tree: ``cd <base worktree> && python <this file>`` (stdout is the JSON)."""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.getcwd())

from opentrace_core.live import source_declarations as sd                              # noqa: E402
from tests.core.app import test_ai_assets as ta, test_crypto_assets as tc               # noqa: E402

TREE = {
    "requirements.txt": "flask==2.0\nrequests>=2\n",
    "app/main.py": "import hashlib\nhashlib.sha256(b'x').hexdigest()\nMODEL = 'https://example.org/m/yolo.onnx'\n",
    "app/plain.py": "x = 1\n",
    "run.sh": "echo hi\n",
}


def _tree(root):
    for rel, data in TREE.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as h:
            h.write(data)


def cases():
    out = {}
    d = ta.doc([ta.ml("yolo.onnx", [("m/a.yaml", 3)]), ta.ml("big.gguf", [("m/b.yaml", None)], url="https://example.org/big.gguf")])
    out["ai.models.captured"] = ta.build(ta.inputs(ta.inv(d)))[0]
    out["ai.models.live"] = ta.build(ta.inputs(ta.inv(d), "live"))[0]
    out["ai.models.filter_models"] = ta.build(ta.inputs(ta.inv(d)), filter="models")[0]
    out["ai.models.query"] = ta.build(ta.inputs(ta.inv(d)), query="yolo")[0]
    out["ai.none"] = ta.build({"aibom": None, "mode": "captured"})[0]
    out["ai.failed"] = ta.build(ta.inputs(ta.inv(None, outcome="failed", reason="scanner_failed")))[0]
    out["ai.partial"] = ta.build(ta.inputs(ta.inv(d, outcome="partial")))[0]
    cd = tc.cbom_doc([tc.comp("SHA-256", [("a.js", 3), ("b.js", 9)]), tc.comp("AES-128-GCM", [("c.js", 4)])])
    out["crypto.cbom.captured"] = tc.build(tc.inputs(tc.original(cd)))[0]
    out["crypto.cbom.live"] = tc.build(tc.inputs(tc.original(cd), None, "live"))[0]
    out["crypto.cbom.filter_algorithms"] = tc.build(tc.inputs(tc.original(cd)), filter="algorithms")[0]
    out["crypto.none"] = tc.build(tc.inputs(None))[0]
    out["crypto.failed"] = tc.build(tc.inputs(tc.original(None, outcome="failed", reason="scanner_failed")))[0]
    root = tempfile.mkdtemp(prefix="ot-s4g-")
    try:
        _tree(root)
        r = sd.collect(root, "https://github.com/acme/widget", "d" * 40)
        out["declarations.record"] = r["record"]
        out["declarations.digest"] = r["record_sha256"]
        out["declarations.summary_keys"] = sorted(r["summary"])
        out["declarations.copies"] = sorted(r["copies"])
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return out


if __name__ == "__main__":
    print(json.dumps(cases(), sort_keys=True, indent=1))
