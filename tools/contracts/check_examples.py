#!/usr/bin/env python3
"""Check contracts/evidence/v1, v2 and v3 examples: valid examples pass, invalid examples fail.

Every example is checked against its JSON Schema with jsonschema==4.23.0 (dev/test
only; requirements-dev.txt) and with the core's stdlib structural checker, which must
agree. Semantic examples are also run through the core validator (I1-REQ-05) and must
fail with their named code. Offline: schema $refs resolve from the local registry only.
"""
import importlib.metadata
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "core"))

try:
    import jsonschema
    from referencing import Registry, Resource
    from referencing.exceptions import NoSuchResource
except ImportError:
    print("BLOCKER: jsonschema==4.23.0 is not installed (pip install -r requirements-dev.txt)")
    sys.exit(2)

from opentrace_core import timeutil, validate  # noqa: E402
from opentrace_core.artifacts import ArtifactStore  # noqa: E402
from opentrace_core.schema import BASE, BASE_V2, BASE_V3, SchemaSet  # noqa: E402

MAJORS = {1: ROOT / "contracts" / "evidence" / "v1", 2: ROOT / "contracts" / "evidence" / "v2",
          3: ROOT / "contracts" / "evidence" / "v3"}
BASES = {1: BASE, 2: BASE_V2, 3: BASE_V3}


def no_retrieve(uri):
    raise NoSuchResource(ref=uri)  # never fetch remote schemas


def load_major(major):
    contract = MAJORS[major]
    base = BASES[major]
    schemas = {}
    for path in sorted((contract / "schemas").glob("*.schema.json")):
        doc = json.loads(path.read_text())
        jsonschema.Draft202012Validator.check_schema(doc)
        schemas[doc["$id"]] = doc
    registry = Registry(retrieve=no_retrieve).with_resources(
        (sid, Resource.from_contents(doc)) for sid, doc in schemas.items())
    core_schemas = SchemaSet(contract / "schemas", base)

    def schema_errors(kind, instance):
        validator = jsonschema.Draft202012Validator(schemas[base + kind + ".schema.json"], registry=registry,
                                                    format_checker=None)
        return sorted(e.message for e in validator.iter_errors(instance))
    return contract, core_schemas, schema_errors


def check_major(major):
    contract, core_schemas, schema_errors = load_major(major)
    EXAMPLES = contract / "examples"
    negotiated = {1: None, 2: "2.0", 3: "3.0"}[major]
    version = importlib.metadata.version("jsonschema")

    manifest = json.loads((EXAMPLES / "manifest.json").read_text())
    listed = {e["file"] for e in manifest["valid"] + manifest["invalid"]}
    on_disk = {str(p.relative_to(EXAMPLES)) for p in EXAMPLES.glob("*/*.json")}
    failures = []
    if listed != on_disk:
        failures.append("manifest/file mismatch: unlisted=%s missing=%s" % (sorted(on_disk - listed), sorted(listed - on_disk)))

    with tempfile.TemporaryDirectory() as tmp:
        store = ArtifactStore(Path(tmp) / "store")
        for rel in manifest["store_inputs"]:
            store.put((ROOT / rel).read_bytes(), media_type="text/plain; charset=utf-8", producer="fixture",
                      revision_binding="bound_by_digest")

        def semantic(entry, instance):
            spec = entry["semantic"]
            task = json.loads((EXAMPLES / spec["task"]).read_text())
            cap = json.loads((EXAMPLES / spec["capability"]).read_text())
            return validate.validate_result(instance, task, cap, store, timeutil.parse_ts(spec["received_at"]),
                                            negotiated=negotiated)

        for valid, entries in ((True, manifest["valid"]), (False, manifest["invalid"])):
            for entry in entries:
                instance = json.loads((EXAMPLES / entry["file"]).read_text())
                js = schema_errors(entry["kind"], instance)
                core = core_schemas.errors(entry["kind"], instance)
                agree = bool(js) == bool(core)
                problems = [] if agree else ["jsonschema and core structural checker disagree (js=%d core=%d)" % (len(js), len(core))]
                if valid:
                    if js:
                        problems.append("schema errors: %s" % js[:3])
                    if "semantic" in entry:
                        report = semantic(entry, instance)
                        if not report.ok:
                            problems.append("semantic issues: %s" % report.codes)
                elif entry["layer"] == "schema":
                    if not js:
                        problems.append("expected a schema failure")
                    code = validate.check_structure(entry["kind"], instance, negotiated).codes
                    if entry["expected_code"] not in code:
                        problems.append("core check_structure gave %s, expected %s" % (code, entry["expected_code"]))
                else:
                    if js:
                        problems.append("semantic example must pass the schema: %s" % js[:3])
                    report = semantic(entry, instance)
                    if entry["expected_code"] not in report.codes:
                        problems.append("semantic codes %s lack %s" % (report.codes, entry["expected_code"]))
                verdict = "PASS" if not problems else "FAIL"
                expect = "valid" if valid else "invalid/%s:%s" % (entry["layer"], entry["expected_code"])
                print("%s %-55s %s" % (verdict, entry["file"], expect))
                for p in problems:
                    print("     - " + p)
                if problems:
                    failures.append(entry["file"])
    print("major %d: jsonschema %s; %d examples; %d failures" % (major, version, len(listed), len(failures)))
    return len(failures), listed


def cross_major():
    """Every example of one major must fail the other major's schemas (the version pattern differs)."""
    problems = []
    loaded = {m: load_major(m) for m in MAJORS}
    for src, other in [(a, b) for a in MAJORS for b in MAJORS if a != b]:
        contract = MAJORS[src]
        for path in sorted((contract / "examples" / "valid").glob("*.json")):
            instance = json.loads(path.read_text())
            if not loaded[other][2](instance["kind"], instance):
                problems.append("v%d example %s validates under v%d schemas" % (src, path.name, other))
    for p in problems:
        print("FAIL cross-major: " + p)
    print("cross-major: %d problems" % len(problems))
    return len(problems)


def main():
    version = importlib.metadata.version("jsonschema")
    if version != "4.23.0":
        print("BLOCKER: expected jsonschema 4.23.0, found %s" % version)
        return 2
    total, count = 0, 0
    for major in sorted(MAJORS):
        failed, listed = check_major(major)
        total += failed
        count += len(listed)
    total += cross_major()
    print("jsonschema %s; %d examples across majors; %d failures" % (version, count, total))
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
