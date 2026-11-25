"""UIP-06 renderer fixtures: SYNTHETIC crypto_assets/1 payloads for the Cryptography tab renderer tests and captures.

Every name, path and rule result here is invented for layout/state coverage (labelled ``synthetic`` in the paths). They are produced by the
production producer from in-memory inputs so they are schema-valid, but they are NOT evidence, never prototype data, and never a producer
oracle (the producer's oracle is tests/core/app/test_crypto_assets.py). Run: PYTHONPATH=src/core python tools/uip06/make_renderer_fixtures.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "src", "core"))
sys.path.insert(0, REPO)
from opentrace_core.app import crypto_assets as ca  # noqa: E402
from tests.core.app.test_view_contracts import load_builder  # noqa: E402

OUT = os.path.join(REPO, "evidence", "uip", "visual", "uip-06", "fixtures", "renderer")
BUILDER = load_builder()
BINDING = BUILDER.make_binding("example-org", "synthetic-lab", "uip06-renderer")


def comp(name, occs, kind="algorithm"):
    return {"type": "cryptographic-asset", "name": name, "cryptoProperties": {"assetType": kind},
            "evidence": {"occurrences": [{"location": p, "line": l, "symbol": "synthetic.call"} for p, l in occs]}}


def doc(components, services=()):
    return {"metadata": {"tools": {"components": [{"name": "synthetic-cbom-tool", "version": "0.0"}]}}, "components": components, "services": list(services)}


def orig(d, outcome="completed", reason=None):
    return {"artifact_id": "art:inv:synthetic-cbom", "outcome": outcome, "reason": reason, "doc": d, "producer": "synthetic-cbom-tool 0.0", "sha256": None}


def inputs(cb=None, src=None, mode="captured"):
    return {"cbom": cb, "source": src, "mode": mode}


def obs(path, line, algo="sha256", state="inconclusive"):
    return {"status": "observed", "source_observation": {"evidence_id": "ev-synthetic-%d" % line, "path": path, "line": line, "file_sha256": "b" * 64,
            "excerpt": "  synthetic_hash(\"%s\")  # invented line" % algo, "resolution": {"literal_algorithm": algo, "call": "synthetic.call"}},
            "conclusion": {"state": state, "rule_id": "synthetic_rule.example/1", "reason_codes": ["synthetic"], "rationale": "Synthetic rationale for layout tests.",
                           "bounded_meaning": "Synthetic bounded meaning.", "next_action": "Synthetic next action.", "used_evidence": []}}


def page(name, inp, **req):
    payload = ca.build_payload(inp, BINDING, dict({"generation": 1, "filter": "all", "offset": 0}, **req))
    with open(os.path.join(OUT, name + ".json"), "w", encoding="utf-8") as h:
        json.dump(payload, h, indent=1, ensure_ascii=False, sort_keys=True)
        h.write("\n")


def grid(groups, per):
    comps = []
    for g in range(groups):
        for i in range(per):
            comps.append(comp("synthetic-alg-%d-%d" % (g, i), [("synthetic/g%02d/file.py" % g, 10 + i)], ["algorithm", "protocol", "certificate"][(g + i) % 3]))
    return doc(comps)


def main():
    os.makedirs(OUT, exist_ok=True)
    page("multi3", inputs(orig(doc([comp("synthetic-alg-%d-%d" % (g, i), [("synthetic/g%d/file.py" % g, 10 + i)], ["algorithm", "protocol", "certificate"][(g + i) % 3]) for g in range(3) for i in range(3) if (g, i) != (2, 2)],
                                [{"name": "synthetic-service", "endpoints": ["/a"]}])), {"targets": [obs("synthetic/g2/file.py", 12)]}))
    page("tall5", inputs(orig(grid(1, 5))))
    page("wrap7", inputs(orig(doc([comp("synthetic-w%d" % g, [("synthetic/w%02d/file.py" % g, 1)]) for g in range(7)]))))
    page("dense24", inputs(orig(doc([comp("synthetic-d%02d" % i, [("top%02d/sub/file%02d.py" % (i % 30, i), 1)]) for i in range(30)]))))
    page("occ45", inputs(orig(doc([comp("synthetic-many", [("synthetic/one/file.py", i + 1) for i in range(45)])]))))
    page("partial_empty", inputs(orig(doc([]), "partial"), None))
    page("failed", inputs(orig(None, "failed", "scanner_failed")))
    page("unsupported", inputs(orig(None, "unsupported")))
    page("not_run", inputs(None, {"targets": [], "outcome": None}, mode="live"))
    page("hostile", inputs(orig(doc([comp("<img src=x onerror=alert(1)>‮ rtl & \"q\"", [("synthetic/<b>x</b>/‮file.py", 3)]),
                                      comp("N" * 400, [("synthetic/" + "d" * 200 + "/file.py", 2)])], [{"name": "<script>alert(1)</script>", "endpoints": "javascript:alert(1)"}]))))
    page("certificates_zero", inputs(orig(doc([comp("synthetic-hash-%d" % i, [("synthetic/h%d/file.py" % i, 4)]) for i in range(3)]))), filter="certificates")
    page("findings", inputs(orig(grid(2, 2)), {"targets": [obs("synthetic/g1/file.py", 11)]}), filter="findings")


if __name__ == "__main__":
    main()
