"""UIP-07C TEST-1: runs the REAL gateway module (the same file the image runs) with the fake provider injected as its upstream transport.
The production program has no test mode and no upstream override, so a test cannot weaken it; the harness only supplies a transport object.
Run inside the gateway image: python -I /opt/test/gateway_harness.py   (the synthetic key below is not a credential)."""
import os
import sys

sys.path.insert(0, "/opt/gateway")
sys.path.insert(0, "/opt/test")
import fake_provider  # noqa: E402
import gateway as gw  # noqa: E402

for sub in ("jobs", "revoke", "attest", "ack"):
    os.makedirs(os.path.join("/ctl", sub), exist_ok=True)
g = gw.Gateway(ctl_dir="/ctl", ledger_path="/ledger/ledger.jsonl", pricing_path="/run/opentrace/pricing.json", transport=fake_provider.FakeUpstream("/upstream"),
               key="TEST-NOT-A-REAL-KEY", hosts=("gateway:8788",))
sys.stderr.write("test gateway ready={} ledger_ok={}\n".format(g.status()["ready"], g.ledger is not None))
sys.stderr.flush()
gw.serve(g, "0.0.0.0", 8788)
