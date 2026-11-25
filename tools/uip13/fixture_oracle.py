"""UIP-13 independent expectation oracle for the captured Frigate / Viseron fixtures (offline, stdlib only).

It does not import ``opentrace_core``. From the captured donor source-declaration record and the captured scan scope it derives what the contract says
must happen to each exact-locator group: which groups have an occurrence inside the AI-BOM scan scope (compared) and which lie wholly outside. It is
written separately from the collector and the generator so that a disagreement is a finding, not a tautology. The donor tokenizer differs from the
OpenTrace collector (contract section 5.1), so these expectations are about the *captured records*, not about the collector's own counts.
"""
import json
import sys


def inside(path, paths):
    return any(p in (".", "") or path == p or path.startswith(p.rstrip("/") + "/") for p in paths)


def expectations(declarations, scope_paths):
    groups = {}
    for r in declarations["model_references"]:
        groups.setdefault(r["locator"], []).append(r)
    out = {"occurrences": len(declarations["model_references"]), "groups": len(groups), "compared": [], "outside": []}
    for loc, occs in sorted(groups.items()):
        (out["compared"] if any(inside(o["path"], scope_paths) for o in occs) else out["outside"]).append(loc)
    return out


if __name__ == "__main__":
    d = json.load(open(sys.argv[1]))
    print(json.dumps(expectations(d, json.loads(sys.argv[2])), indent=1))
