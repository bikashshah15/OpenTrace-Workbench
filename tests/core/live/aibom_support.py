"""Test doubles and loaders for the UIP-07C AI-BOM work (gateway, AI worker, Workbench client). No network, no provider, no real key.

The gateway and the AI worker are standalone programs (they run in their own images), so they are loaded by path rather than imported from a package.
Every secret-looking value in this module is a synthetic placeholder built for the test; nothing here is, or resembles, a real credential beyond its shape.
"""
import calendar
import hashlib
import importlib.util
import json
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
LIVE = os.path.join(ROOT, "src", "core", "opentrace_core", "live")
GATEWAY_PATH = os.path.join(ROOT, "src", "workers", "gateway", "gateway.py")
WORKER_DIR = os.path.join(ROOT, "src", "workers", "aibom")

NOW = 1_800_000_000          # fixed test epoch (2027-01-15)


def _load(name, path, extra_path=None):
    if extra_path and extra_path not in sys.path:
        sys.path.insert(0, extra_path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def gateway_module():
    return sys.modules.get("ot_gateway") or _load("ot_gateway", GATEWAY_PATH)


def cisco_module():
    """The shared stdlib-only module exactly as the worker image imports it (top-level name ``aibom_cisco``)."""
    return sys.modules.get("aibom_cisco") or _load("aibom_cisco", os.path.join(LIVE, "aibom_cisco.py"))


def worker_module():
    cisco_module()
    return sys.modules.get("ot_aibom_worker") or _load("ot_aibom_worker", os.path.join(WORKER_DIR, "worker.py"), extra_path=LIVE)


class Clock:
    def __init__(self, now=NOW):
        self.now = now
        self.lock = threading.Lock()

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def iso(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def pricing_record(gw, now=NOW, **override):
    rec = dict(gw.PRICING_CONSTANTS)
    rec.update({"sources": ["https://example.invalid/a", "https://example.invalid/b", "https://example.invalid/c"],
                "verified_on": iso(now - 3600), "valid_until": iso(now + 7 * 86400)})
    rec.update(override)
    return rec


def write_json(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)


def token_pair():
    # fixed, obviously synthetic bearer tokens (>= 32 chars of the allowed alphabet)
    return "tokA" + "a" * 40, "tokB" + "b" * 40


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def job_doc(gw, job_id, tokens, *, now=NOW, generation=1, ceiling=1_000_000_000, max_requests=32, ttl=720, model=None, b_requests=0):
    token_a, token_b = tokens
    return {"schema": "opentrace.gateway_job/1", "job_id": job_id, "token_sha256": sha(token_a), "session_generation": generation,
            "model": model or gw.MODEL, "issued_at": now, "expires_at": now + ttl,
            "passes": {"A": {"token_sha256": sha(token_a), "max_requests": max_requests, "max_in_bytes_per_request": 1024 * 1024,
                             "max_out_tokens": 16384, "ceiling_nusd": ceiling},
                       "B": {"token_sha256": sha(token_b), "max_requests": b_requests, "max_in_bytes_per_request": 1024 * 1024,
                             "max_out_tokens": 0, "ceiling_nusd": 0}}}


def chat_response(prompt=10, completion=5, **extra):
    usage = {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion}
    usage.update(extra)
    return {"id": "chatcmpl-test", "object": "chat.completion", "created": 0, "model": "gpt-6-luna",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}], "usage": usage}


class FakeTransport:
    """Records what the gateway would send upstream; never touches the network. ``reply`` is a callable or a fixed (status, dict) pair."""

    def __init__(self, reply=None, block=None):
        self.calls = []
        self.reply = reply or (200, chat_response())
        self.block = block          # optional threading.Event: the send waits for it (or for cancellation)
        self.entered = threading.Event()
        self.cancelled = False
        self.lock = threading.Lock()

    def send(self, body, cancel):
        with self.lock:
            self.calls.append(json.loads(body.decode("utf-8")))
        self.entered.set()
        if self.block is not None:
            # wait until released or cancelled
            while not self.block.wait(0.02):
                if cancel.event.is_set():
                    self.cancelled = True
                    raise OSError("closed by gateway")
        reply = self.reply(len(self.calls)) if callable(self.reply) else self.reply
        status, doc = reply
        data = doc if isinstance(doc, (bytes, bytearray)) else json.dumps(doc).encode("utf-8")
        return status, bytes(data)


def chat_request(gw, **override):
    body = {"model": gw.MODEL, "messages": [{"role": "system", "content": "SYSTEM-SENTINEL-TEXT"}, {"role": "user", "content": "USER-SENTINEL-TEXT"}],
            "temperature": 0, "n": 1}
    body.update(override)
    return body


# -- AI-BOM document builders (independently authored; shapes follow the F0b observations, expected outcomes are stated in the tests) ----------------
ROOT_PATH = "/scan/repo"


def comp(name, ctype="library", file=ROOT_PATH + "/requirements.txt", line=1, kind="dependency", ref=None, props=None):
    """One artifact component and its pass-B JSON twin, as a pair ``(cdx_component, replay_component)``."""
    ref = ref or "%s_%s_%s" % (name, file, line)
    properties = [{"name": "cisco-aibom:file", "value": file}, {"name": "cisco-aibom:line", "value": str(line)}, {"name": "cisco-aibom:type", "value": kind}]
    properties.extend(props or [])
    cdx = {"bom-ref": ref, "description": "%s — %s" % (name, kind), "name": name, "properties": properties, "type": ctype}
    replay = {"component_type": kind, "name": name, "file_path": file, "line_number": line, "instance_id": ref}
    return cdx, replay


def cdx_doc(pairs=(), *, version="1.10.1", spec="1.6", tools=None, extra=None):
    pairs = json.loads(json.dumps([list(p) for p in pairs]))      # deep copy: a test that edits the document must never edit the shared fixture
    doc = {"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json", "bomFormat": "CycloneDX", "specVersion": spec, "version": 1,
           "serialNumber": "urn:uuid:11111111-2222-4333-8444-555555555555", "components": [p[0] for p in pairs],
           "dependencies": [{"ref": p[0]["bom-ref"]} for p in pairs],
           "metadata": {"timestamp": "2027-01-15T00:00:00+00:00", "tools": tools if tools is not None else [{"name": "cisco-aibom", "vendor": "Cisco", "version": version}]}}
    doc.update(extra or {})
    return doc


def cdx_bytes(pairs=(), **kw):
    return json.dumps(cdx_doc(pairs, **kw), sort_keys=True).encode("utf-8")


def replay_doc(pairs=(), *, status="success", count=0, reasons=None, overall="completed"):
    groups = {}
    for _c, r in pairs:
        groups.setdefault("model" if r["component_type"] == "model" else "dependency", []).append(r)
    return {"aibom_analysis": {"errors": [], "metadata": {"agentic_degradation_reasons": reasons if reasons is not None else {}, "agentic_degraded_count": count,
                                                          "agentic_status": status, "analyzer_version": "1.10.1", "output_format": "json", "status": overall},
                               "sources": {"repo": {"components": groups, "source_name": "repo", "source_path": ROOT_PATH}},
                               "summary": {"total_components": len(pairs)}}}


def replay_bytes(pairs=(), **kw):
    return json.dumps(replay_doc(pairs, **kw), sort_keys=True).encode("utf-8")


def fragments(*parts):
    """Secret-shaped strings are assembled from fragments so no credential-looking literal sits in the repository."""
    return "".join(parts)
