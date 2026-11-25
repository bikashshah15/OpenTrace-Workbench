"""Content-addressed, write-once artifact store (PD-06).

Layout under the store root (store-relative paths only are ever reported):
  sha256/<hex>       artifact bytes, read-only after write
  meta/<hex>.json    metadata sidecar
  quarantine.jsonl   integrity failures (never hidden, never stored as content)
"""
import hashlib
import json
import os
import re
from pathlib import Path

from . import timeutil

_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
REVISION_BINDING = ("bound_by_digest", "unbound", "unknown")


class ArtifactConflict(Exception):
    """Different bytes were offered for an existing digest."""


class IntegrityError(Exception):
    def __init__(self, digest, actual):
        super().__init__("artifact bytes do not match %s" % digest)
        self.digest = digest
        self.actual = actual


def digest_of(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hex_of(digest):
    match = _DIGEST.match(digest) if isinstance(digest, str) else None
    if not match:
        raise ValueError("not a sha256 digest: %r" % (digest,))
    return match.group(1)


class ArtifactStore:
    def __init__(self, root):
        self.root = Path(root)
        (self.root / "sha256").mkdir(parents=True, exist_ok=True)
        (self.root / "meta").mkdir(parents=True, exist_ok=True)

    def relpath(self, digest):
        return "sha256/" + hex_of(digest)

    def _path(self, digest):
        return self.root / "sha256" / hex_of(digest)

    def put(self, data, media_type, producer, source_ref=None, revision_binding="unknown",
            captured_at=None):
        """Store bytes under their digest. Same bytes again is a no-op; different bytes raise."""
        if revision_binding not in REVISION_BINDING:
            raise ValueError("invalid revision_binding")
        digest = digest_of(data)
        path = self._path(digest)
        if path.exists():
            if path.read_bytes() != data:
                raise ArtifactConflict(digest)
            return digest
        tmp = path.with_name(path.name + ".tmp-%d" % os.getpid())
        tmp.write_bytes(data)
        os.chmod(tmp, 0o444)
        os.replace(tmp, path)
        meta = {
            "digest": digest,
            "bytes": len(data),
            "media_type": media_type,
            "producer": producer,
            "source_ref": source_ref,
            "captured_at": captured_at or timeutil.format_ts(timeutil.now()),
            "revision_binding": revision_binding,
            "path": self.relpath(digest),
        }
        meta_path = self.root / "meta" / (hex_of(digest) + ".json")
        meta_path.write_text(json.dumps(meta, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.chmod(meta_path, 0o444)
        return digest

    def put_checked(self, digest, data, **meta):
        """Store bytes only if they hash to the claimed digest."""
        actual = digest_of(data)
        if actual != digest:
            raise IntegrityError(digest, actual)
        return self.put(data, **meta)

    def exists(self, digest):
        try:
            return self._path(digest).is_file()
        except ValueError:
            return False

    def get(self, digest):
        """Return verified bytes; raise IntegrityError when the file was altered."""
        data = self._path(digest).read_bytes()
        actual = digest_of(data)
        if actual != digest:
            raise IntegrityError(digest, actual)
        return data

    def actual_digest(self, digest):
        """Digest of the bytes currently stored under ``digest`` (None if absent)."""
        try:
            return digest_of(self._path(digest).read_bytes())
        except (OSError, ValueError):
            return None

    def meta(self, digest):
        path = self.root / "meta" / (hex_of(digest) + ".json")
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def quarantine(self, digest, actual, reason, origin):
        record = {"digest": digest, "actual_digest": actual, "reason": reason, "origin": origin,
                  "recorded_at": timeutil.format_ts(timeutil.now())}
        with open(self.root / "quarantine.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def quarantined(self):
        path = self.root / "quarantine.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
