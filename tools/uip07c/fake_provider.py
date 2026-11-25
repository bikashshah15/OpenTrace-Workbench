"""UIP-07C TEST-1 fake provider: a scripted OpenAI-shaped chat-completions responder used as the UPSTREAM TRANSPORT of the real gateway code.

Standard library only. It is not a model and makes no claim to resemble one. It records request STRUCTURE and digests only (never message text,
never a response). Modes come from ``<dir>/mode.json`` and are re-read per request: success | degraded | sleep | error500 | badusage | roundtrip.
Nothing here touches a network: the gateway under test calls ``send()`` directly, so no socket is opened for the 'provider'."""
import hashlib
import json
import os
import re
import threading
import time

MODEL = "gpt-6-luna"
IID = re.compile(r"""instance_id["']?\s*[:=]\s*["']([^"']+)["']""")


def _text(messages):
    out = []
    for m in messages if isinstance(messages, list) else []:
        c = m.get("content") if isinstance(m, dict) else None
        if isinstance(c, str):
            out.append(c)
        elif isinstance(c, list):
            out.extend(p.get("text", "") for p in c if isinstance(p, dict))
    return "\n".join(out)


class FakeUpstream:
    def __init__(self, directory):
        self.dir = directory
        self.lock = threading.Lock()
        self.n = 0

    def mode(self):
        try:
            with open(os.path.join(self.dir, "mode.json")) as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return {"mode": "degraded"}

    def record(self, rec):
        with open(os.path.join(self.dir, "requests.jsonl"), "a") as handle:
            handle.write(json.dumps(rec, sort_keys=True) + "\n")

    def send(self, body, cancel):
        req = json.loads(body.decode("utf-8"))
        with self.lock:
            self.n += 1
            n = self.n
        mode = self.mode()
        messages = req.get("messages") or []
        tools = req.get("tools") or []
        ids = sorted(set(IID.findall(_text(messages))))
        tc = req.get("tool_choice")
        rf = req.get("response_format")
        rec = {"idx": n, "model": req.get("model"), "top_level_fields": sorted(req), "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
               "message_roles": [m.get("role") for m in messages if isinstance(m, dict)], "tool_count": len(tools),
               "tool_names": [((t.get("function") or {}).get("name")) for t in tools if isinstance(t, dict)][:40],
               "tool_choice": tc if isinstance(tc, str) else ("function:%s" % (tc.get("function") or {}).get("name") if isinstance(tc, dict) else None),
               "response_format_type": rf.get("type") if isinstance(rf, dict) else None, "max_completion_tokens": req.get("max_completion_tokens"),
               "max_tokens_present": "max_tokens" in req, "reasoning_effort": req.get("reasoning_effort"), "n": req.get("n"), "stream": req.get("stream"),
               "candidate_ids_seen": len(ids), "mode": mode.get("mode")}
        self.record(rec)
        end = time.monotonic() + float(mode.get("sleep", 0))
        while time.monotonic() < end:
            if cancel.event.wait(0.05):
                raise OSError("closed by gateway")
        if mode.get("mode") == "error500":
            return 500, json.dumps({"error": {"message": "scripted failure", "type": "server_error"}}).encode()
        payload = {}
        if mode.get("mode") == "success":
            payload = {"enriched_components": [{"instance_id": i, "updates": {}, "decision_annotation": {"decision": "confirmed", "justification": "scripted",
                                                                                                         "evidence_kinds": [], "evidence_locations": []}} for i in ids],
                       "new_components": [{"name": "scripted-model", "component_type": "model", "file_path": "app/main.py", "line_number": 3, "framework": "scripted",
                                           "model_name": "scripted/model", "metadata": {},
                                           "decision_annotation": {"decision": "added", "justification": "scripted", "evidence_kinds": [], "evidence_locations": []}}]}
        elif mode.get("mode") == "degraded":
            payload = {"new_components": [{"name": "scripted-model", "component_type": "model", "file_path": "app/main.py", "line_number": 3, "framework": "scripted",
                                           "model_name": "scripted/model", "metadata": {}}]}
        roles = [m.get("role") for m in messages if isinstance(m, dict)]
        if mode.get("mode") == "roundtrip" and tools and "tool" not in roles:
            # First call of a round trip: answer with ONE tool call (the producer executes it and sends a follow-up carrying assistant tool_calls + a tool message).
            usage = {"prompt_tokens": 1000, "completion_tokens": 50, "total_tokens": 1050}
            return 200, json.dumps({"id": "chatcmpl-scripted-%d" % n, "object": "chat.completion", "created": 0, "model": MODEL, "choices": [{"index": 0, "finish_reason": "tool_calls",
                    "message": {"role": "assistant", "content": None, "tool_calls": [{"id": "call_rt_%d" % n, "type": "function",
                                                                                      "function": {"name": "ls", "arguments": json.dumps({"path": "/"})}}]}}], "usage": usage}).encode()
        if mode.get("mode") == "roundtrip":
            mode = dict(mode, mode="degraded")
        forced = None
        tools_named = [(t.get("function") or {}).get("name") for t in tools]
        if isinstance(tc, dict):
            forced = (tc.get("function") or {}).get("name")
        elif tc in ("required", "any") and tools_named:
            forced = "AgentResponse" if "AgentResponse" in tools_named else tools_named[0]
        msg = {"role": "assistant", "content": None}
        if forced:
            msg["tool_calls"] = [{"id": "call_%d" % n, "type": "function", "function": {"name": forced, "arguments": json.dumps(payload if forced == "AgentResponse" else {})}}]
            finish = "tool_calls"
        elif isinstance(rf, dict) and rf.get("type") in ("json_schema", "json_object"):
            msg["content"], finish = json.dumps(payload), "stop"
        else:
            msg["content"], finish = "scripted: analysis complete.", "stop"
        usage = mode.get("usage") or {"prompt_tokens": 1000, "completion_tokens": 100}
        usage = {"prompt_tokens": usage["prompt_tokens"], "completion_tokens": usage["completion_tokens"], "total_tokens": usage["prompt_tokens"] + usage["completion_tokens"]}
        if mode.get("mode") == "badusage":
            usage["total_tokens"] += 1
        return 200, json.dumps({"id": "chatcmpl-scripted-%d" % n, "object": "chat.completion", "created": 0, "model": MODEL,
                                "choices": [{"index": 0, "message": msg, "finish_reason": finish}], "usage": usage}).encode()
