"""Sanitized wire trace (I1-REQ-07): one JSONL line per HTTP exchange leg.

Sanitization: every ``content_b64`` value becomes {"elided", "bytes", "digest"};
configured absolute path prefixes (store, output dir, HOME, temp) are replaced by
placeholders; credential-like header values are redacted; no environment is read
into the trace.
"""
import base64
import binascii
import copy
import json
import re

from . import timeutil
from .artifacts import digest_of

_SECRET_HEADER = re.compile(r"(authorization|cookie|token)", re.IGNORECASE)
_ABS_PATH = re.compile(r"(?<![A-Za-z0-9_.:/>-])/(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]*")


def _elide(value):
    data = None
    if isinstance(value, str):
        try:
            data = base64.b64decode(value.encode("ascii"), validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError):
            data = None
    return {"elided": True, "bytes": len(data) if data is not None else None,
            "digest": digest_of(data) if data is not None else None}


class Sanitizer:
    def __init__(self, path_prefixes=None):
        # Longest first so nested prefixes map to the most specific placeholder.
        items = sorted((path_prefixes or {}).items(), key=lambda kv: -len(kv[0]))
        self.prefixes = [(str(k).rstrip("/"), v) for k, v in items if k and str(k) not in ("/", "")]

    def text(self, value):
        for prefix, placeholder in self.prefixes:
            value = value.replace(prefix, placeholder)
        # Any remaining absolute path is reduced to its basename.
        return _ABS_PATH.sub(lambda m: "<abs-path>/" + m.group(0).rstrip("/").rsplit("/", 1)[-1], value)

    def value(self, obj):
        if isinstance(obj, dict):
            out = {}
            for key, val in obj.items():
                out[key] = _elide(val) if key == "content_b64" else self.value(val)
            return out
        if isinstance(obj, list):
            return [self.value(v) for v in obj]
        if isinstance(obj, str):
            return self.text(obj)
        return obj

    def headers(self, headers):
        out = {}
        for key, val in (headers or {}).items():
            out[key] = "<redacted>" if _SECRET_HEADER.search(key) else self.text(str(val))
        return out


class TraceWriter:
    def __init__(self, path, sanitizer=None):
        self.path = path
        self.sanitizer = sanitizer or Sanitizer()
        self.seq = 0
        open(self.path, "w", encoding="utf-8").close()

    def record(self, direction, sender, receiver, http_path, http_status, nlip, domain_event,
               headers=None, injected=False, case=None, raw_body=None):
        self.seq += 1
        entry = {
            "seq": self.seq,
            "ts": timeutil.format_ts(timeutil.now()),
            "case": case,
            "direction": direction,
            "from": sender,
            "to": receiver,
            "path": http_path,
            "http_status": http_status,
            "headers": self.sanitizer.headers(headers),
            "injected": bool(injected),
            "nlip": self.sanitizer.value(copy.deepcopy(nlip)),
            "domain_event": self.sanitizer.value(copy.deepcopy(domain_event)),
        }
        if raw_body is not None:
            entry["raw_body"] = self.sanitizer.text(raw_body[:512])
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry
