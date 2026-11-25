"""Package inventory for a live analysis, produced by the I3 parsers (I5B, EDQ-13 option 1).

The exported tree of the pinned commit is read once, before the session workspace is removed. Manifest
selection is the I3 policy (``cohort.policy``), the task bundles are the I3 bundles (``cohort.plan``) and
the parsing is done by Evidence Specialist B's ``repo_inventory`` operation through the existing
Investigator, so a live analysis and the I3 cohort replay interpret a lockfile the same way. B is started
as a loopback-only child in its own process group, registered with the session, and confirmed gone before
this function returns; an unconfirmed group raises ``InventoryError("cleanup_unverified")``.

Nothing here executes repository code. Every manifest is hashed again and compared with the digest
recorded when the tree was exported; a file that changed since export is not parsed.
"""
import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from opentrace_core.canon import canonical_digest
from opentrace_core.cohort import plan, policy as manifest_policy, tables
from opentrace_core.session.producers import ProcessGroup

SPECIALIST_ENV = "OPENTRACE_SPECIALIST_BIN"
GO_ENV = {"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOFLAGS": "", "GOENV": "off"}
START_SECONDS = 20
MAX_MANIFEST_BYTES = 8 * 1024 * 1024


class InventoryError(Exception):
    def __init__(self, code, detail=""):
        super().__init__("{}: {}".format(code, detail) if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class InventoryResult:
    """``status``: ``complete`` (every selected manifest parsed), ``partial`` (some did not) or ``unavailable``."""
    status: str
    rows: tuple = field(default_factory=tuple)       # I3 occurrence rows, each carrying repo/path of its manifest
    manifests: tuple = field(default_factory=tuple)   # one record per manifest the policy selected or excluded
    notes: tuple = field(default_factory=tuple)
    reason: str = ""
    policy_digest: str = ""
    parser_version: str = ""

    def as_dict(self):
        return {"status": self.status, "reason": self.reason or None, "occurrences": len(self.rows),
                "manifests": list(self.manifests), "notes": list(self.notes), "policy_digest": self.policy_digest or None,
                "parser": self.parser_version or None}


def unavailable(reason):
    return InventoryResult("unavailable", reason=reason)


def specialist_binary(environ=None):
    path = (os.environ if environ is None else environ).get(SPECIALIST_ENV)
    return path if path and os.access(path, os.X_OK) else None


def build_specialist(out_dir, source_dir=None):
    """Operator/test helper: ``go build`` Evidence Specialist B from this repository, offline."""
    src = Path(source_dir) if source_dir else Path(__file__).resolve().parents[3] / "agents" / "evidence_specialist"
    binary = Path(out_dir) / "evidence-specialist"
    subprocess.run(["go", "build", "-trimpath", "-o", str(binary), "."], check=True, cwd=str(src),
                   env=dict(os.environ, **GO_ENV), capture_output=True)
    return str(binary)


# ---- the exported tree as an I3 source set ---------------------------------------------------------------

class _Repo:
    def __init__(self, name, commit, tree, listing_digest, rows, blobs):
        self.repo, self.commit = name, commit
        self.event = {"tree": tree}
        self.listing_digest = listing_digest
        self.rows = rows
        self.blobs = blobs        # path -> ("sha256:<hex>", size)


class _Captures:
    def __init__(self, ident):
        self.id = ident


class TreeSourceSet:
    """Duck-typed stand-in for ``cohort.sources.SourceSet`` over the exported tree (``plan.source_tasks`` reads only this)."""

    def __init__(self, repo_name, source, src_dir, policy):
        self.policy = policy
        self._data = {}
        digests = {i["path"]: i["sha256"] for i in source.inputs}
        rows, blobs = [], {}
        for path in sorted(digests):
            if manifest_policy.classify(path, policy) is None:
                continue
            full = os.path.join(src_dir, *path.split("/"))
            try:
                if os.path.islink(full) or os.path.getsize(full) > MAX_MANIFEST_BYTES:
                    continue
                with open(full, "rb") as handle:
                    data = handle.read()
            except OSError:
                continue
            if hashlib.sha256(data).hexdigest() != digests[path]:
                raise InventoryError("tree_changed", "an exported manifest no longer matches its export digest")
            rows.append({"mode": "100644", "type": "blob", "path": path, "size": len(data),
                         "sha": hashlib.sha1(b"blob %d\x00" % len(data) + data, usedforsecurity=False).hexdigest()})  # nosec: git object id
            blobs[path] = ("sha256:" + digests[path], len(data))
            self._data[path] = data
        self.repos = {repo_name: _Repo(repo_name, source.commit_sha, source.tree_sha, "sha256:" + source.listing_sha256, rows, blobs)}
        self.captures = _Captures(canonical_digest({"schema": "opentrace.live_tree/1", "commit": source.commit_sha,
                                                    "listing_sha256": source.listing_sha256}))

    def selection(self, repo):
        return manifest_policy.select_manifests(self.repos[repo].rows, self.policy)

    def blob(self, repo, path):
        return self._data[path]


# ---- running B ------------------------------------------------------------------------------------------

def _path_with_go():
    """B's start-up check needs ``go`` on PATH (its I2 govulncheck lane); repo_inventory itself never runs it."""
    go = shutil.which("go")
    if go is None:
        raise InventoryError("go_toolchain_missing", "Evidence Specialist B needs the Go toolchain on PATH to start")
    return os.pathsep.join(["/usr/bin", "/bin", os.path.dirname(go)])


def _start(binary, store_dir, home, register):
    path = _path_with_go()
    port_file = os.path.join(home, "b.port")
    log = open(os.path.join(home, "b.log"), "wb")
    try:
        process = subprocess.Popen([binary, "--addr", "127.0.0.1:0", "--store", store_dir, "--port-file", port_file],
                                   cwd=home, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                   env={"PATH": path, "HOME": home, "TMPDIR": home, "LANG": "C", **GO_ENV})
    finally:
        log.close()
    group = ProcessGroup(process)
    register(group)
    deadline = time.monotonic() + START_SECONDS
    while time.monotonic() < deadline:
        try:
            text = Path(port_file).read_text().strip()
        except OSError:
            text = ""
        if text:
            return group, int(text)
        if process.poll() is not None:
            raise InventoryError("specialist_exited", "the Evidence Specialist exited during start-up")
        time.sleep(0.05)
    raise InventoryError("specialist_start_timeout", "the Evidence Specialist did not report a port")


def inventory(source, src_dir, binary, *, repo_name, register, cancel, scratch=None):
    """Parse the manifests of the exported tree with the I3 parsers. Never raises for parse problems; raises
    ``InventoryError`` for infrastructure problems (and ``cleanup_unverified`` if B cannot be confirmed gone)."""
    try:
        from opentrace_core.artifacts import ArtifactStore
        from opentrace_core.context import ContextRegistry
        from opentrace_investigator import i3
        from opentrace_investigator.investigator import Investigator
        from opentrace_investigator.transport import HttpTransport
    except ImportError as exc:
        raise InventoryError("investigator_unavailable", type(exc).__name__)
    policy = manifest_policy.load_policy()
    sourceset = TreeSourceSet(repo_name, source, src_dir, policy)
    task_plans, notes = plan.source_tasks(sourceset)
    pdigest = manifest_policy.policy_digest(policy)
    manifests = [{"path": r["path"], "kind": r["kind"], "state": "selected"} for r in sourceset.selection(repo_name)["selected"]]
    manifests += [{"path": r["path"], "kind": r["kind"], "state": "excluded", "reason": r["reason"]}
                  for r in sourceset.selection(repo_name)["excluded"]]
    if not task_plans:
        return InventoryResult("complete", (), tuple(manifests), tuple(n["note"] for n in notes), "", pdigest, "")
    home = tempfile.mkdtemp(prefix="ot-inv-", dir=scratch)
    group = None
    try:
        store_dir = os.path.join(home, "store")
        store = ArtifactStore(Path(store_dir))
        group, port = _start(binary, store_dir, home, register)
        investigator = Investigator(HttpTransport("http://127.0.0.1:%d" % port), ContextRegistry(store), None, enable_v3=True, id_prefix="live")
        attachments = []
        for n, tp in enumerate(task_plans, 1):
            if cancel.is_set():
                raise InventoryError("cancelled")
            spec = {"operation": "repo_inventory", "context": tp["context"], "inputs": tp["inputs"],
                    "capture_set_id": tp["capture_set_id"], "blobs": tp["blobs"], "ordinal": n}
            attachments.append(i3.run_one(investigator, store, spec, extra={"repo": tp["repo"], "manifest_path": tp["path"], "kind": tp["kind"]}))
        accepted = i3.accepted_results(attachments, "repo_inventory")
        occ = tables.occurrence_tables(accepted, store) if accepted else {}
    except InventoryError:
        raise
    except Exception as exc:  # typed metadata only; never repository content
        raise InventoryError("inventory_failed", type(exc).__name__)
    finally:
        if group is not None and not group.terminate(2.0):
            raise InventoryError("cleanup_unverified", "the Evidence Specialist process group could not be confirmed gone")
        shutil.rmtree(home, ignore_errors=True)
    rows = tuple(plan.occurrences_of(occ))
    by_path = {m["path"]: m for m in manifests}
    parsed = {path for (_repo, path) in occ}
    failed = 0
    for att in attachments:
        path = att.get("manifest_path")
        rec = by_path.get(path)
        if rec is None:
            continue
        if path in parsed:
            table = occ[(repo_name, path)]
            rec.update({"state": "parsed" if table["status"] == "parsed" else table["status"], "rows": len(table["rows"]),
                        "unparsed_constructs": list(table["unparsed_constructs"])})
            if table["status"] != "parsed":
                failed += 1
        else:
            rec.update({"state": "not_parsed", "reason": att.get("rejection") or att.get("reason") or "rejected"})
            failed += 1
    return InventoryResult("partial" if failed else "complete", rows, tuple(manifests), tuple(n["note"] for n in notes), "", pdigest, "i3/1")
