"""UIP-03 (IR-06): validate every status/envelope the visual stub will serve with the REAL contract validators.

Reads a JSON file ``{name: {"status": {...}, "result": {...}|null}}`` and runs each through ``scan_contract.build`` (which runs the frozen
UIP-01B ``scan_status/1`` validator unchanged: structure, semantics, 32,768-byte ceiling; then the transport rules: a result exists exactly for a
completed/partial hand-off, agrees with the status binding, and fits the 1 MiB ceiling). Prints a JSON report and exits 1 on any violation.
Usage: PYTHONPATH=src/core python3 -I tools/uip/validate_scan_envelopes.py FILE
"""
import json
import sys

from opentrace_core.app import scan_contract, view_contracts as vc


def main(path):
    with open(path, encoding="utf-8") as handle:
        docs = json.load(handle)
    report, failed = [], 0
    for name in sorted(docs):
        entry = docs[name]
        status, result = entry["status"], entry.get("result")
        try:
            env = scan_contract.build(status, result, request={"generation": status["generation"], "job_id": status["job"]["job_id"]})
            report.append({"name": name, "ok": True, "job_state": status["job"]["state"], "has_result": env["result"] is not None})
        except vc.ContractError as exc:
            failed += 1
            report.append({"name": name, "ok": False, "code": exc.code, "detail": exc.body()})
    print(json.dumps({"schema": "opentrace.uip.visual.fixture_validation/1", "checked": len(report), "failed": failed, "results": report}, indent=1))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
