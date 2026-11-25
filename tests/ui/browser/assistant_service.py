"""Captured DemoSource with an in-process deterministic assistant broker.

This fixture is for browser interaction only. It does not invoke a provider,
scanner, source transport, or paid service.
"""
import json
import os
import sys
import time
from pathlib import Path

from opentrace_core.app import make_server


class FixtureBroker:
    def __init__(self):
        self.count = 0
        self.count_path = os.environ.get("OT_ASSISTANT_BROKER_COUNT_FILE")

    def generate(self, request):
        current = json.loads(request.messages[-1].content)
        self.count += 1
        if self.count_path:
            Path(self.count_path).write_text(str(self.count), encoding="ascii")
        if current.get("question") == "Deterministic cancellation probe":
            time.sleep(1.5)
        evidence = current.get("evidence") or []
        item = next((row for row in evidence if row.get("kind") == "source_state"), None)
        claims = []
        next_steps = []
        if item:
            claims.append({"kind": "unknown", "text": "This deterministic browser fixture does not infer a repository finding.",
                           "evidence_ids": [item["evidence_id"]]})
            next_steps.append({"action": "open_evidence", "evidence_id": item["evidence_id"],
                               "label": "Inspect captured coverage"})
        answer = {"answer_status": "unknown", "context_id": current["context_id"],
                  "turn_id": current["turn_id"], "claims": claims, "limitations": [],
                  "next_steps": next_steps}
        return type("FixtureResult", (), {"status": "complete", "content": json.dumps(answer),
                    "profile": "deterministic-fixture", "model": "offline-browser-fixture",
                    "validation_level": "fixture-only"})()


def main():
    root = os.environ.get("OT_ASSISTANT_FIXTURE_STATE", "/tmp/ot-assistant-browser-state")
    server = make_server(root, reap_seconds=3600)
    server.app.assistant_broker = FixtureBroker()
    print("assistant browser fixture: http://127.0.0.1:%s/" % server.server_address[1], flush=True)
    try:
        server.serve_forever()
    finally:
        server.app.close()


if __name__ == "__main__":
    sys.exit(main())
