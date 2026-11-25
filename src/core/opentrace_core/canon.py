"""Canonical JSON bytes and digests for immutable manifests (I2-REQ-04, section 3.4).

Keys sorted, separators "," and ":", ensure_ascii=False, no floats, exactly one trailing LF.
The same rule is used for the source manifest, capture manifest, run and replay manifests.
"""
import hashlib
import json


def canonical_bytes(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def digest_of_bytes(data):
    return "sha256:" + sha256_hex(data)


def canonical_digest(obj):
    return digest_of_bytes(canonical_bytes(obj))
