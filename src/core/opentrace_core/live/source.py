"""Acquire one repository at one full commit SHA and verify it against the commit's own objects.

Bare ``git fetch`` of the exact SHA, then an export that never uses a checkout, a hook or a
filter: every blob is read with ``git cat-file --batch``, its Git object id is recomputed from
the bytes received, and the file is written with ``O_EXCL|O_NOFOLLOW``. Symlinks and submodules
are listed but never materialised. Nothing in the repository is built, installed or executed.
"""
import hashlib
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field

from opentrace_core.session.producers import ProcessGroup

from . import policy

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
GIT_CONFIG = ("core.hooksPath=/dev/null", "core.fsmonitor=false", "core.symlinks=false",
              "core.autocrlf=false", "core.attributesFile=/dev/null", "protocol.allow=never",
              "http.followRedirects=false", "transfer.fsckObjects=true", "fetch.fsckObjects=true",
              "gc.auto=0", "fetch.recurseSubmodules=false", "credential.helper=")


class SourceError(Exception):
    def __init__(self, code, detail=""):
        super().__init__("{}: {}".format(code, detail) if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SourceRecord:
    repository_url: str
    commit_sha: str
    tree_sha: str
    verified: bool
    file_count: int
    byte_count: int
    listing_sha256: str
    skipped: tuple = field(default_factory=tuple)   # ({"path", "reason"}, ...) never materialised
    inputs: tuple = field(default_factory=tuple)     # ({"path", "sha256"}, ...) every exported file
    git_version: str = ""

    def as_dict(self):
        return {"repository_url": self.repository_url, "commit_sha": self.commit_sha, "tree_sha": self.tree_sha,
                "verified": self.verified, "file_count": self.file_count, "byte_count": self.byte_count,
                "listing_sha256": self.listing_sha256, "skipped": list(self.skipped), "git_version": self.git_version}


def _git_bin():
    found = shutil.which("git")
    if not found:
        raise SourceError("git_unavailable", "git was not found on PATH")
    return found


def _env(home):
    return {"PATH": "/usr/bin:/bin", "HOME": home, "LANG": "C", "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ASKPASS": "/usr/bin/false",
            "GIT_ATTR_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_LFS_SKIP_SMUDGE": "1"}


def _args(allow_protocol):
    out = []
    for item in GIT_CONFIG:
        out += ["-c", item]
        if item == "protocol.allow=never":
            out += ["-c", "protocol.{}.allow=always".format(allow_protocol)]
    return out


def _tree_bytes(path):
    total = 0
    for base, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(base, name)).st_size
            except OSError:
                pass
    return total


GROUP_CONFIRM_SECONDS = 5.0


def _close_pipes(threads, streams, verified):
    """Join the drain threads briefly and close the pipes only when that cannot block.

    A reader thread still inside ``read()`` (a live, unkillable leader keeps the pipe open) holds the
    buffer lock, so closing from here would block; leave the daemon thread and let the failure return.
    """
    for t in threads:
        t.join(2 if verified else 0.2)
    # The drain threads close their own pipes when the reads end; nothing is closed from here.


def _run(cmd, env, *, cwd, cancel, seconds, watch=None, limit=None, register=None, input_bytes=None):
    process = subprocess.Popen(cmd, cwd=cwd, env=env,
                               stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    group = ProcessGroup(process)
    if register:
        register(group)
    outputs = {}

    def drain(name, stream):
        try:
            outputs[name] = stream.read()
        finally:
            stream.close()  # closed by the only thread that reads it, so an unverified group never blocks the caller

    threads = [threading.Thread(target=drain, args=(n, s), daemon=True)
               for n, s in (("out", process.stdout), ("err", process.stderr))]
    for t in threads:
        t.start()
    if input_bytes is not None:
        def feed():
            try:
                process.stdin.write(input_bytes)
                process.stdin.close()
            except OSError:
                pass
        threading.Thread(target=feed, daemon=True).start()
    deadline = time.monotonic() + seconds
    reason = None
    while process.poll() is None:
        if cancel is not None and cancel.is_set():
            reason = "cancelled"
        elif time.monotonic() > deadline:
            reason = "timeout"
        elif watch and limit and _tree_bytes(watch) > limit:
            reason = "size_limit"
        if reason:
            group.signal(signal.SIGKILL)
            break
        time.sleep(0.05)
    # No unbounded wait: the leader and everything it left in the group must be CONFIRMED gone within
    # GROUP_CONFIRM_SECONDS (a live leader whose signaling is denied makes this False, not a hang).
    verified = group.kill_and_confirm(GROUP_CONFIRM_SECONDS)
    _close_pipes(threads, (process.stdout, process.stderr), verified)
    if not verified:
        raise SourceError("cleanup_unverified", "the process group could not be confirmed gone")
    if reason:
        raise SourceError(reason)
    return process.returncode, outputs.get("out", b""), outputs.get("err", b"")


def git_object_id(data):
    return hashlib.sha1(b"blob %d\x00" % len(data) + data, usedforsecurity=False).hexdigest()


def _safe_path(path):
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        return False
    return all(p not in ("", ".", "..") and p.lower() != ".git" for p in path.split("/"))


def _parse_tree(raw):
    entries = []
    for chunk in raw.split(b"\x00"):
        if not chunk:
            continue
        meta, _, path = chunk.partition(b"\t")
        fields = meta.decode("ascii").split()
        if len(fields) != 4:
            raise SourceError("tree_unparseable")
        mode, kind, sha, size = fields
        entries.append((mode, kind, sha, size, path.decode("utf-8", "surrogateescape")))
    return entries


def acquire(remote_url, commit_sha, workspace, *, cancel=None, register=None, allow_protocol="https",
            canonical_url=None, seconds=policy.FETCH_SECONDS):
    """Fetch ``commit_sha`` from ``remote_url`` and export it to ``workspace/src``.

    ``canonical_url`` is what the identity records (the https GitHub URL); ``remote_url`` differs
    only in tests that use a local repository with ``allow_protocol="file"``.
    """
    if not (isinstance(commit_sha, str) and _SHA40.fullmatch(commit_sha)):
        raise SourceError("sha_not_full", "a full 40-character lowercase commit SHA is required")
    git = _git_bin()
    home = os.path.join(workspace, "home")
    bare = os.path.join(workspace, "bare")
    src = os.path.join(workspace, "src")
    for path in (home, src):
        os.makedirs(path, mode=0o700, exist_ok=False)
    base = [git] + _args(allow_protocol)
    kw = dict(env=_env(home), cwd=workspace, cancel=cancel or threading.Event(), register=register)
    code, out, _ = _run([git, "--version"], seconds=10, **kw)
    git_version = out.decode("ascii", "replace").strip() if code == 0 else ""
    code, _, err = _run(base + ["init", "--bare", "-q", bare], seconds=20, **kw)
    if code:
        raise SourceError("git_init_failed", err.decode("utf-8", "replace")[:200])
    gd = base + ["--git-dir", bare]
    code, _, err = _run(gd + ["fetch", "-q", "--depth", "1", "--no-tags", "--no-recurse-submodules", remote_url, commit_sha],
                        seconds=seconds, watch=bare, limit=policy.MAX_FETCH_BYTES, **kw)
    if code:
        raise SourceError("fetch_failed", err.decode("utf-8", "replace")[:300])
    code, out, _ = _run(gd + ["rev-parse", "--verify", "FETCH_HEAD^{commit}"], seconds=20, **kw)
    fetched = out.decode("ascii", "replace").strip()
    if code or fetched != commit_sha:
        raise SourceError("commit_mismatch", "fetched commit {} is not the requested commit".format(fetched[:12] or "?"))
    code, out, _ = _run(gd + ["cat-file", "-t", commit_sha], seconds=20, **kw)
    if code or out.strip() != b"commit":
        raise SourceError("commit_mismatch", "object is not a commit")
    code, out, _ = _run(gd + ["rev-parse", "--verify", commit_sha + "^{tree}"], seconds=20, **kw)
    tree_sha = out.decode("ascii", "replace").strip()
    if code or not _SHA40.fullmatch(tree_sha):
        raise SourceError("tree_unreadable")
    code, raw, _ = _run(gd + ["ls-tree", "-r", "-l", "-z", "--full-tree", tree_sha], seconds=60, **kw)
    if code:
        raise SourceError("tree_unreadable")
    entries = _parse_tree(raw)
    if len(entries) > policy.MAX_FILES:
        raise SourceError("size_limit", "more than {} entries".format(policy.MAX_FILES))
    files, skipped, total = [], [], 0
    for mode, kind, sha, size, path in entries:
        if not _safe_path(path):
            raise SourceError("unsafe_path", "the tree contains a path that cannot be materialised safely")
        if kind == "blob" and mode in ("100644", "100755"):
            files.append((sha, int(size), path))
            total += int(size)
        elif kind == "blob" and mode == "120000":
            skipped.append({"path": path, "reason": "symlink_not_materialised"})
        elif kind == "commit":
            skipped.append({"path": path, "reason": "submodule_not_fetched"})
        else:
            raise SourceError("unsupported_entry", "tree entry type is not supported")
    if total > policy.MAX_TREE_BYTES:
        raise SourceError("size_limit", "tree larger than {} bytes".format(policy.MAX_TREE_BYTES))
    requests = "".join(sha + "\n" for sha, _s, _p in files).encode("ascii")
    code, stream, err = _run(gd + ["cat-file", "--batch"], seconds=seconds, input_bytes=requests, **kw)
    if code:
        raise SourceError("blob_read_failed", err.decode("utf-8", "replace")[:200])
    inputs, listing, cursor = [], [], 0
    for sha, size, path in files:
        newline = stream.find(b"\n", cursor)
        header = stream[cursor:newline].decode("ascii", "replace").split() if newline >= 0 else []
        if len(header) != 3 or header[0] != sha or header[1] != "blob" or int(header[2]) != size:
            raise SourceError("blob_read_failed", "unexpected object header")
        data = stream[newline + 1:newline + 1 + size]
        cursor = newline + 1 + size + 1
        if len(data) != size or git_object_id(data) != sha:
            raise SourceError("blob_mismatch", "bytes for one file do not hash to the object id in the commit's tree")
        target = os.path.join(src, *path.split("/"))
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            raise SourceError("path_collision", "two tree paths map to one file on this filesystem")
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        inputs.append({"path": path, "sha256": hashlib.sha256(data).hexdigest()})
        listing.append("{}\t{}".format(path, sha))
    if cursor != len(stream):
        raise SourceError("blob_read_failed", "unexpected trailing object data")
    listing_sha = hashlib.sha256("\n".join(sorted(listing)).encode("utf-8", "surrogateescape")).hexdigest()
    shutil.rmtree(bare, ignore_errors=True)
    return SourceRecord(canonical_url or remote_url, commit_sha, tree_sha, True, len(files), total, listing_sha,
                        tuple(skipped), tuple(sorted(inputs, key=lambda i: i["path"])), git_version)
