"""UIP-07 renderer fixtures: SYNTHETIC ai_assets/1 payloads for the AI models tab renderer tests and captures.

Every name, path, condition and rule result here is invented for layout/state coverage (labelled ``synthetic``). Inventory-only pages come from
the production producer on in-memory inputs; pages that need what no production producer emits yet (runtimes, AI services, preferred/fallback
alternatives, conditional links, review items) are built with the frozen fixture builder (``tools/uip_fixtures/build.py``). None of it is
evidence, none is prototype data, and none is a producer oracle (the oracle is tests/core/app/test_ai_assets.py). Every payload is checked with
the frozen validator. Run: PYTHONPATH=src/core python tools/uip07/make_renderer_fixtures.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "src", "core"))
sys.path.insert(0, REPO)
from opentrace_core.app import ai_assets as aa  # noqa: E402
from opentrace_core.app import view_contracts as vc  # noqa: E402
from tests.core.app.test_view_contracts import load_builder  # noqa: E402

OUT = os.path.join(REPO, "evidence", "uip", "visual", "uip-07", "fixtures", "renderer")
B = load_builder()
BINDING = B.make_binding("example-org", "synthetic-lab", "uip07-renderer")
EXPECTED = {k: BINDING[k] for k in ("analysis_digest", "commit_sha", "repository", "requested_ref", "mode", "assessment")}
PID = "synthetic-ai-inventory"


def write(name, payload):
    vc.validate_payload("ai_assets", payload, request={"generation": BINDING["generation"]}, expected_binding=EXPECTED)
    with open(os.path.join(OUT, name + ".json"), "w", encoding="utf-8") as h:
        json.dump(payload, h, indent=1, ensure_ascii=False, sort_keys=True)
        h.write("\n")


# ---- inventory-only pages: the production producer on in-memory inputs
def ml(name, locs=(), url=None):
    c = {"type": "machine-learning-model", "name": name}
    if locs:
        c["evidence"] = {"occurrences": [{"location": p, "line": l} for p, l in locs]}
    if url:
        c["externalReferences"] = [{"type": "distribution", "url": url}]
    return c


def inv(components, outcome="completed", reason=None, counts=None):
    d = None if outcome in ("failed", "not_run", "unsupported") else {"bomFormat": "CycloneDX", "components": components}
    return {"aibom": {"artifact_id": "art:inv:synthetic-aibom", "outcome": outcome, "reason": reason, "doc": d, "producer": "synthetic-aibom 0.0", "record_counts": counts or {}}, "mode": "captured"}


def produced(name, inp, **req):
    write(name, aa.build_payload(inp, BINDING, dict({"generation": 1, "filter": "all", "offset": 0}, **req)))


# ---- hand-built pages (no production producer emits these yet)
NA = B.attr("unavailable", None, "not recorded by this producer")


def pv(experimental=True):
    return B.prov(PID, "supplemental_observation" if experimental else "original_artifact", artifact_id=None if experimental else "art:inv:synthetic-aibom",
                  pointer=None if experimental else "/components", experimental=experimental)


def occ(key, path, l0, l1, op, cond=None, alt=None):
    return B.occ(BINDING, key, path, l0, l1, "synthetic excerpt line", operation=op, cond=cond, cond_basis="source_text" if cond else "none", alt=alt, producer_id=PID)


def grp(path, label=None, total=0):
    return B.src_group(BINDING, label or path, path, total)


def built(assets, groups, links=(), reviews=(), filt="all", producer_outcome="completed"):
    prod = B.producer(PID, "supplemental_observation", "synthetic experimental source observation", producer_outcome, experimental=True)
    return B.assets_payload("ai", BINDING, B.avail("completed", "Synthetic renderer fixture: invented assets for layout and state coverage."), [prod], assets, links=links, reviews=reviews, groups=groups, filt=filt)


def reference_composition():
    """Two source groups: a detector with a model reference and a runtime, a second with a model reference and a preferred/fallback runtime pair."""
    g1, g2 = grp("synthetic/detector_a.py", "Synthetic detector A", 2), grp("synthetic/detector_b.py", "Synthetic detector B", 3)
    a_model = B.asset(BINDING, "m1", "model_reference", "synthetic_model_a.bin", pv(), occs=[occ("m1", "synthetic/detector_a.py", 10, 10, "declared model path")], groups=[g1["group_id"]], tab="ai")
    a_run = B.asset(BINDING, "r1", "runtime", "synthetic_runtime_a", pv(), occs=[occ("r1", "synthetic/detector_a.py", 3, 3, "runtime import")], groups=[g1["group_id"]], tab="ai")
    b_model = B.asset(BINDING, "m2", "model_reference", "synthetic_model_b.bin", pv(), occs=[occ("m2", "synthetic/detector_b.py", 20, 20, "declared model path")], groups=[g2["group_id"]], tab="ai")
    pref = occ("r2", "synthetic/detector_b.py", 5, 5, "runtime import", cond="preferred import in a try block")
    b_pref = B.asset(BINDING, "r2", "runtime", "synthetic_runtime_b1_preferred", pv(), occs=[pref], groups=[g2["group_id"]], tab="ai")
    fb = occ("r3", "synthetic/detector_b.py", 8, 8, "runtime import", cond="used only if the first import fails", alt=pref["occurrence_id"])
    b_fb = B.asset(BINDING, "r3", "runtime", "synthetic_runtime_b2_fallback", pv(), occs=[fb], groups=[g2["group_id"]], tab="ai")
    link = {"relation": "conditionally_selects", "from": b_pref["asset_id"], "to": b_fb["asset_id"], "basis": "recorded", "evidence_ref": None, "condition": "fallback import only if the first import fails"}
    return [a_model, a_run, b_model, b_pref, b_fb], [g1, g2], [link]


def main():
    os.makedirs(OUT, exist_ok=True)
    assets, groups, links = reference_composition()
    write("ref_composition", built(assets, groups, links))
    write("ref_models_only", built([a for a in assets if a["kind"] == "model_reference"], groups, [], filt="models"))
    svc = B.asset(BINDING, "s1", "ai_service", "synthetic-hosted-endpoint", pv(), occs=[occ("s1", "synthetic/detector_a.py", 30, 30, "service URL reference")], groups=[groups[0]["group_id"]], tab="ai")
    write("with_service", built(assets + [svc], groups, links))
    rev = {"review_id": "rev:" + "0" * 24, "asset_id": assets[0]["asset_id"], "rule_id": "synthetic_rule.example", "rule_version": "1", "tone": "review", "condition": "Synthetic review condition",
           "evidence_ids": ["ev-synthetic-1"], "rationale": "Synthetic rationale for state coverage.", "bounded_meaning": "Synthetic bounded meaning.", "next_action": "Synthetic next action."}
    write("findings", built(assets, groups, links, reviews=[rev], filt="all"))
    # a 3 x 3 grid for the ordinary geometry check
    gs = [grp("synthetic/g%d/file.py" % g, "Synthetic group %d" % g, 3) for g in range(3)]
    grid = [B.asset(BINDING, "g%d-%d" % (g, i), "model_reference" if i < 2 else "runtime", "synthetic-%d-%d" % (g, i), pv(),
                    occs=[occ("g%d-%d" % (g, i), "synthetic/g%d/file.py" % g, i + 1, i + 1, "declared")], groups=[gs[g]["group_id"]], tab="ai") for g in range(3) for i in range(3)]
    write("multi3", built(grid, gs))
    # produced inventory pages
    produced("demo_like", inv([ml("synthetic_model.hef")]))
    produced("display_group", inv([ml("model.bin", [("cfg/a.yaml", 5)], "https://a.invalid/model.bin"), ml("model.bin", [("cfg/b.yaml", 9)], "https://b.invalid/model.bin"), ml("other.bin")]))
    produced("unlocated_and_located", inv([ml("synthetic_a.onnx", [("synthetic/models/a.py", 4)]), ml("synthetic_b.onnx"), ml("synthetic_c.onnx", [("synthetic/models/a.py", 9)])]))
    produced("tall5", inv([ml("synthetic-t%d.onnx" % i, [("synthetic/one/file.py", i + 1)]) for i in range(5)]))
    produced("wrap7", inv([ml("synthetic-w%d.onnx" % g, [("synthetic/w%02d/file.py" % g, 1)]) for g in range(7)]))
    produced("paged45", inv([ml("synthetic-p%03d.onnx" % i, [("synthetic/p%02d/f.py" % (i % 5), i + 1)]) for i in range(45)]), offset=30)
    produced("occ45", inv([ml("synthetic-many.onnx", [("synthetic/one/file.py", i + 1) for i in range(45)])]))
    produced("completed_empty", inv([]))
    produced("partial_empty", inv([], counts={"unparsed_total": 2}))
    produced("partial_models", inv([ml("synthetic_a.onnx", [("synthetic/a.py", 1)])], counts={"unparsed_total": 1}))
    produced("failed", inv(None, "failed", "output_invalid"))
    produced("unsupported", inv(None, "unsupported"))
    produced("not_run", {"aibom": None, "mode": "live"})
    produced("filter_to_zero", inv([ml("synthetic_a.onnx")]), query="zzz")
    produced("services_empty", inv([ml("synthetic_a.onnx")]), filter="ai_services")
    produced("findings_empty", inv([ml("synthetic_a.onnx")]), filter="findings")
    produced("hostile", inv([ml("<img src=x onerror=alert(1)>‮ rtl & \"q\"", [("synthetic/<b>x</b>/‮file.py", 3)]), ml("N" * 400, [("synthetic/" + "d" * 200 + "/file.py", 2)])]))


if __name__ == "__main__":
    main()
