"""UIP-01A comparator (contract UIP-01A v1.0.0, 4h): re-collect the protected-output data and diff it against a baseline manifest.

Fail closed. Exit status: 0 = no differences; 1 = differences (one line each: ``DIFF <path>: expected ... actual ...``);
2 = failure (crash, unreadable manifest, network-guard violation) ; 124 = the 120 s phase limit was exceeded (a failure).
There is no update, accept or force mode, and this tool never writes a manifest or any repository file (its worker uses a temp directory only).
Changing a baseline needs an owner decision recorded as a numbered UIP-Dnn item and a NEW manifest version.

Usage: python tools/uip/compare.py --manifest PATH
"""
import argparse
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import baseline  # noqa: E402
import netguard  # noqa: E402

EXIT_PASS, EXIT_DIFF, EXIT_FAILURE = 0, 1, 2
_SHORT = 140


def _short(value):
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return text if len(text) <= _SHORT else text[:_SHORT] + "...(%d chars)" % len(text)


def diff(expected, actual, path="$"):
    """Yield one line per difference. Lists are compared in order; a pure reordering is reported as one line."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(set(expected) | set(actual)):
            sub = "%s.%s" % (path, key)
            if key not in actual:
                yield "DIFF %s: missing from the current output; expected %s" % (sub, _short(expected[key]))
            elif key not in expected:
                yield "DIFF %s: not in the baseline; actual %s" % (sub, _short(actual[key]))
            else:
                yield from diff(expected[key], actual[key], sub)
        return
    if isinstance(expected, list) and isinstance(actual, list):
        if expected != actual and sorted(json.dumps(x, sort_keys=True) for x in expected) == sorted(json.dumps(x, sort_keys=True) for x in actual):
            yield "DIFF %s: reordered (same %d elements, different order)" % (path, len(expected))
            return
        if len(expected) != len(actual):
            yield "DIFF %s: length expected %d actual %d" % (path, len(expected), len(actual))
        for index in range(min(len(expected), len(actual))):
            yield from diff(expected[index], actual[index], "%s[%d]" % (path, index))
        return
    if expected != actual or type(expected) is not type(actual):
        yield "DIFF %s: expected %s actual %s" % (path, _short(expected), _short(actual))


# Trusted exclusion policy (UIP-01A 4d; correction 01, finding UIP-01A-IR-01). It lives in tool code, which the manifest records by hash.
# A submitted manifest can neither widen nor narrow it. Only these two sections are informational (they describe the machine and the
# invocation, not protected output); ``start_sha`` is not compared because a later checkout legitimately has a different commit, and
# ``schema`` is checked for equality by ``validate_manifest`` instead. Nothing else is ever excluded.
PERMITTED_EXCLUSIONS = ("environment", "commands")
_NOT_COMPARED = frozenset(PERMITTED_EXCLUSIONS) | {"excluded_from_comparison", "start_sha", "schema"}

# Required manifest structure for schema opentrace.uip.baseline/1: section -> (type, required keys of that section and their types).
_OBJ, _LIST, _STR = dict, list, str
_STRUCTURE = {
    "schema": (_STR, {}),
    "start_sha": (_STR, {}),
    "environment": (_OBJ, {}),
    "commands": (_OBJ, {}),
    "excluded_from_comparison": (_OBJ, {}),
    "limits": (_OBJ, {}),
    "reference": (_OBJ, {"path": _STR, "sha256": _STR}),
    "tools": (_OBJ, {}),
    "class_p": (_OBJ, {"directories": _OBJ, "files": _OBJ}),
    "class_n": (_OBJ, {"files": _OBJ}),
    "golden_exports": (_OBJ, {}),
    "produced_legacy_exports": (_LIST, {}),
    "served": (_OBJ, {"route": _STR, "artifacts": _LIST, "pins": _OBJ}),
    "semantic": (_OBJ, {"discovery": _OBJ, "observed_vs_report": _OBJ, "rule_outputs": _OBJ, "validator_matrix": _LIST}),
}


def _type_name(kind):
    return {dict: "an object", list: "a list", str: "a string"}[kind]


def validate_manifest(manifest):
    """Problems (empty list when valid) with a submitted manifest's structure and exclusion declaration, before any comparison."""
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object, not %s" % type(manifest).__name__]
    problems = []
    for key in sorted(set(manifest) - set(_STRUCTURE)):
        problems.append("unsupported section %r" % key)
    for key, (kind, inner) in _STRUCTURE.items():
        if key not in manifest:
            problems.append("required section %r is missing" % key)
            continue
        value = manifest[key]
        if not isinstance(value, kind):
            problems.append("section %r must be %s" % (key, _type_name(kind)))
            continue
        for sub, sub_kind in inner.items():
            if sub not in value:
                problems.append("required field %r.%s is missing" % (key, sub))
            elif not isinstance(value[sub], sub_kind):
                problems.append("field %r.%s must be %s" % (key, sub, _type_name(sub_kind)))
    if manifest.get("schema") != baseline.SCHEMA and isinstance(manifest.get("schema"), str):
        problems.append("unsupported schema %r (this comparator reads %r)" % (manifest["schema"], baseline.SCHEMA))
    disc = manifest.get("semantic", {}).get("discovery") if isinstance(manifest.get("semantic"), dict) else None
    if isinstance(disc, dict) and not isinstance(disc.get("candidates"), list):
        problems.append("field 'semantic.discovery.candidates' must be a list")
    excl = manifest.get("excluded_from_comparison")
    if isinstance(excl, dict):
        for name, reason in sorted(excl.items()):
            if name not in PERMITTED_EXCLUSIONS:
                problems.append("excluded_from_comparison.%s: this section is protected and cannot be excluded (permitted: %s)" % (name, ", ".join(PERMITTED_EXCLUSIONS)))
            elif not isinstance(reason, str) or not reason.strip():
                problems.append("excluded_from_comparison.%s: a non-empty reason string is required" % name)
    return problems


def compare_manifest(manifest, current):
    """Diff lines between a manifest and the current collection. The exclusion policy is the trusted one above; anything the manifest
    declares about exclusions is ignored here (``validate_manifest`` rejects it before this runs)."""
    expected = {k: v for k, v in manifest.items() if k not in _NOT_COMPARED}
    actual = {k: v for k, v in current.items() if k not in _NOT_COMPARED}
    return list(diff(expected, actual))


def worker(args):
    try:
        with open(args.manifest, "rb") as handle:
            manifest = json.loads(handle.read().decode("utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        print("FAILURE: manifest unreadable: %s" % type(exc).__name__)
        return EXIT_FAILURE
    problems = validate_manifest(manifest)
    if problems:
        print("FAILURE: manifest invalid: %d problem(s)" % len(problems))
        for line in problems:
            print("  - " + line)
        return EXIT_FAILURE
    try:
        log = os.path.join(args.tmp, "netguard.log")
        netguard.install(allowed_ports=(), unix_root=args.tmp, log_path=log)
        netguard.prepare_child_environment(os.path.join(args.tmp, "guard"), log, unix_root=args.tmp)
        current = baseline.collect(baseline.REPO_ROOT, args.tmp)
        violations = netguard.collect_violations(log)  # raises when the log is missing or unreadable: that is a failure, not an empty log
    except BaseException as exc:  # a crash is a failure, never a pass
        print("FAILURE: collection crashed: %s: %s" % (type(exc).__name__, str(exc)[:300]))
        return EXIT_FAILURE
    if violations:
        print("FAILURE: network guard violations: %s" % json.dumps(violations))
        return EXIT_FAILURE
    differences = compare_manifest(manifest, current)
    for line in differences:
        print(line)
    print("compare: %d difference(s) against %s" % (len(differences), os.path.basename(args.manifest)))
    return EXIT_DIFF if differences else EXIT_PASS


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest")
    sub = ap.add_subparsers(dest="cmd")
    w = sub.add_parser("_worker")
    w.add_argument("mode")
    w.add_argument("--result")
    w.add_argument("--tmp", required=True)
    w.add_argument("--manifest", dest="manifest")
    args = ap.parse_args(argv)  # unknown flags (for example --update, --accept, --force) are rejected: there is no such mode
    if args.cmd == "_worker":
        return worker(args)
    if not args.manifest:
        ap.error("--manifest is required")
    manifest_path = os.path.abspath(args.manifest)
    if not os.path.isfile(manifest_path):
        sys.stderr.write("FAILURE: manifest not found: %s\n" % manifest_path)
        return EXIT_FAILURE
    res, _ = baseline.supervise_worker(os.path.abspath(__file__), "compare", ["--manifest", manifest_path], name="compare")
    code = baseline.report_phase(res)
    if code == 124:
        return 124
    return res["returncode"] if res["returncode"] in (EXIT_PASS, EXIT_DIFF) and res["group_gone"] else EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
