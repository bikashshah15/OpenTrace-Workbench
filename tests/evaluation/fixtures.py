"""SYNTHETIC smoke fixtures for the evaluation-package tests.

Everything here is invented by the test (package names, files, URLs, annotations). It imitates only the *formats* of the DeepBits
benchmark (``python/req`` + pip-freeze ground truth), BF-CBOM (``ground_truth.yaml`` micro project) and a recorded capture's
``source-declarations.json``. It is never evaluation data and no number derived from it is reported anywhere.
"""
import hashlib
import json
import os

REQ = """# synthetic requirements file (format sample only)
-r other.txt
-c cons.txt
-f https://example.invalid/wheels.html

alpha-pkg
beta_pkg == 1.2.*
gamma-pkg [extra] >= 2.0, == 2.*
delta-pkg @ https://example.invalid/delta-pkg-3.0.zip
./local/epsilon_pkg-1.0-py3-none-any.whl
https://example.invalid/zeta_pkg-1.0-py3-none-any.whl
eta-pkg #inline comment
"""
OTHER = "theta-pkg"
CONS = "alpha-pkg==1.0\n"
CONT = "iota-pkg \\\n==\\\n1.0\n"
GROUNDTRUTH = "\n".join(["alpha-pkg==1.0", "beta-pkg==1.2.3", "gamma-pkg==2.1", "delta-pkg @ https://example.invalid/delta-pkg-3.0.zip#sha256=00",
                         "epsilon-pkg @ file:///local/epsilon_pkg-1.0-py3-none-any.whl", "eta-pkg==4.0", "theta-pkg==5.0", "kappa-dep==0.1"]) + "\n"

PY = """import hashlib
import hmac
import os


def step01():
    digest_a = hashlib.sha256(b"data").hexdigest()


def step02():
    digest_b = hashlib.md5(b"data").hexdigest()


def step03():
    tag = hmac.new(b"k", b"data", hashlib.sha256).hexdigest()


def step04():
    key = hashlib.pbkdf2_hmac("sha256", b"pw", os.urandom(16), 1000)


def step05():
    # md5 and sha1 are mentioned in this comment only
    name = "sha256_label"
    print(name)


def step06():
    digest_c = hashlib.sha3_256(b"data").hexdigest()
"""
GT_YAML = """version: synthetic-1
assets:
- {id: sha-256, group: SHA-2}
- {id: md5, group: MD5}
- {id: hmac-sha256, group: HMAC}
- {id: pbkdf2-hmac-sha256, group: PBKDF}
- {id: sha3-256, group: SHA-3}
projects:
  micro-python:
    path: experiments/corpus/micro/python
    language: python
    file: app/demo.py
    lines:
      sha-256: [7]
      md5: [11]
      hmac-sha256: [15]
      pbkdf2-hmac-sha256: [19]
      sha3-256: [29]
    calls: {sha-256: 7, md5: 11, hmac-sha256: 15, pbkdf2-hmac-sha256: 19, sha3-256: 29}
    expected:
      sha-256: {unit: SHA-256, family: SHA-2}
      md5: {unit: MD5, family: MD5}
      hmac-sha256: {unit: HMAC, family: HMAC}
      pbkdf2-hmac-sha256: {unit: PBKDF2, family: PBKDF2}
      sha3-256: {unit: SHA3-256, family: SHA-3}
    accepted:
      1: [SHA-2, MD5, SHA-3]
    decoys:
      comment:
        lines: [23]
        what: a comment naming algorithms
      identifier:
        lines: [24, 25]
        what: a variable named after an algorithm
"""
REV = "a" * 40
URLS = ["https://models.example.org/smoke/v1/detector.onnx", "https://models.example.org/smoke/v1/classifier.tflite", "http://x/placeholder.onnx"]


def _w(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data if isinstance(data, bytes) else data.encode())


def build(root):
    """Create the three synthetic inputs under ``root``; return a config-override dict pointing at them."""
    db = os.path.join(root, "deepbits")
    _w(os.path.join(db, "README.md"), "# synthetic sbom benchmark sample\n")
    _w(os.path.join(db, "LICENSE"), "MIT License\n\nsynthetic\n")
    for name, text in (("requirements.txt", REQ), ("other.txt", OTHER), ("cons.txt", CONS), ("cont.txt", CONT), ("groundtruth", GROUNDTRUTH)):
        _w(os.path.join(db, "python", "req", name), text)
    bf = os.path.join(root, "bfcbom")
    _w(os.path.join(bf, "LICENSE"), "                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n")
    _w(os.path.join(bf, "VERSION"), "synthetic\n")
    _w(os.path.join(bf, "experiments", "corpus", "micro", "ground_truth.yaml"), GT_YAML)
    _w(os.path.join(bf, "experiments", "corpus", "micro", "python", "app", "demo.py"), PY)
    _w(os.path.join(bf, "experiments", "corpus", "micro", "python", "requirements.txt"), "cryptography>=42\n")
    cap = os.path.join(root, "capture")
    files = {"models.py": "".join(f'MODEL_{i} = "{u}"\n' for i, u in enumerate(URLS)).encode(), "README.md": b"synthetic\n"}
    for p, b in files.items():
        _w(os.path.join(cap, "tree", p), b)
    sha = {p: hashlib.sha256(b).hexdigest() for p, b in files.items()}
    refs = [{"path": "models.py", "line": i + 1, "end_line": i + 1, "locator": u, "excerpt": f'MODEL_{i} = "{u}"', "file_sha256": sha["models.py"],
             "method": "python-ast-string-constant", "occurrence_id": hashlib.sha256(u.encode()).hexdigest()[:16], "ordinal": 0, "source_kind": "python",
             "excerpt_truncated": False} for i, u in enumerate(URLS)]
    record = {"schema": "bombridge.source-declarations/1", "repository": "https://github.com/opentrace-eval/synthetic-capture", "revision": REV,
              "requirement_files": [], "crypto_call_sites": [], "model_references": refs}
    _w(os.path.join(cap, "source-declarations.json"), json.dumps({"record": record, "record_sha256": "0" * 64, "copies": {}}))
    listing = [{"path": p, "sha256": sha[p]} for p in sorted(files)]
    _w(os.path.join(cap, "source-inputs.json"), json.dumps({"inputs": listing, "tree_sha": "b" * 40, "listing_sha256": "c" * 64, "file_count": len(listing)}))
    return {"benchmarks": {"deepbits": db, "bf_cbom": bf, "ai_references": os.path.join(root, "ai_refs")},
            "captures": [{"id": "synthetic-capture", "path": cap, "provenance_tier": "controlled"}],
            "e2": {"selection_dir": os.path.join(root, "frozen"), "domains": ["sbom", "cbom", "aibom"], "tracks": ["fixed_claim", "collector", "discovery"],
                   "transformations": ["MR1", "MR2", "MR3", "MR4", "MR5", "MR6", "MR7"], "negative_controls": ["NC-ecosystem", "NC-primitive", "NC-query"],
                   "mr1_repetitions": 1, "method_timeout_seconds": 60,
                   "deepbits": {"python_req_dir": "python/req", "anchor_files": ["requirements.txt", "other.txt"], "groundtruth": "groundtruth",
                                "include_unlabeled_files": False, "excluded_manifests": []},
                   "bf_cbom": {"ground_truth": "experiments/corpus/micro/ground_truth.yaml", "project": "micro-python", "hash_groups": ["SHA-1", "SHA-2", "SHA-3", "MD5"]},
                   "aibom": {"captured_sources": ["synthetic-capture"], "exclude_placeholder_hosts": True, "model_extensions": [".onnx", ".tflite"]}}}


def config(root, base_cfg):
    """Merge the synthetic paths into a copy of the package's default config."""
    import copy
    cfg = copy.deepcopy(base_cfg)
    ov = build(root)
    cfg["benchmarks"] = ov["benchmarks"]
    cfg["captures"] = ov["captures"]
    cfg["e2"] = ov["e2"]
    cfg["external_tools"] = {"cyclonedx": "cyclonedx-not-installed-in-tests", "sbom_tools": "sbom-tools-not-installed-in-tests"}
    if os.environ.get("OPENTRACE_EVAL_SCHEMA_DIR"):
        cfg.setdefault("e3", {})["cyclonedx_schema_dir"] = os.environ["OPENTRACE_EVAL_SCHEMA_DIR"]
    return cfg
