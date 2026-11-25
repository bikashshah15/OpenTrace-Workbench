"""Live acquisition orchestration: config, gate, and one scan of one allowlisted commit (I5)."""
import os
import shutil

from opentrace_core.session.producers import GroupProducer

from . import github, policy, source as source_mod, source_checks, source_declarations
from .isolation import default_isolation
from .scanners import CDXGEN, SYFT, ScannerConfig, run_scanner

ENABLE_VAR = "OPENTRACE_LIVE_SCAN"
BACKEND_VAR = "OPENTRACE_SCAN_BACKEND"   # "worker" = the isolated Linux scanner worker (I6); unset = local macOS Seatbelt (I5)
POLICY_VAR = "OPENTRACE_LIVE_POLICY"     # "bounded" = public GitHub repositories within limits, only while the worker verifies
SCAN = {"profile_id": "opentrace.scan.default/1", "inventories": ["cbom", "sbom"], "scope": "repository_root"}


class LiveConfig:
    """Everything live scanning depends on, injected so tests never touch the network or a real scanner."""

    def __init__(self, *, allowlist=None, scanners=None, isolation=None, transport=None,
                 remote_for=None, allow_protocol="https", advisories=None, source_check_targets=None,
                 worker=None, policy_mode=policy.POLICY_ALLOWLIST, aibom=None):
        self.allowlist = policy.load_allowlist() if allowlist is None else allowlist
        self.scanners = scanners or ScannerConfig()
        self.worker = worker                # WorkerClient or None; when set, scanners run only inside the worker container
        self.policy_mode = policy_mode      # requested mode; effective_policy() is what applies
        self.isolation = isolation or (worker.isolation if worker is not None else default_isolation())
        self.transport = transport or github.transport
        self.remote_for = remote_for or (lambda owner, name: "https://github.com/{}/{}".format(owner, name))
        self.allow_protocol = allow_protocol
        self.advisories = advisories      # AdvisoryConfig or None (live advisory lookup is opt-in, I5B)
        self.source_check_targets = source_check_targets  # None = the built-in pinned targets (I5C); tests may inject their own
        self.aibom = aibom                  # AibomClient or None: the optional Cisco AI-BOM phase (UIP-07C); None = not requested

    @classmethod
    def from_env(cls, environ=None):
        environ = os.environ if environ is None else environ
        if environ.get(ENABLE_VAR) != "1":
            return None
        from opentrace_core.advisory.config import AdvisoryConfig
        worker = None
        if environ.get(BACKEND_VAR) == "worker":
            from .worker_client import WorkerClient
            worker = WorkerClient.from_env(environ)
        mode = policy.POLICY_BOUNDED if environ.get(POLICY_VAR) == policy.POLICY_BOUNDED else policy.POLICY_ALLOWLIST
        aibom = None
        if environ.get(policy.AIBOM_ENABLE_VAR) == policy.AIBOM_ENABLE_VALUE:     # exactly ``cisco``; ``1`` or anything else is not a request
            from .aibom_worker_client import AibomClient
            aibom = AibomClient.from_env(environ)
        return cls(advisories=AdvisoryConfig.from_env(environ), worker=worker, policy_mode=mode, aibom=aibom)

    def effective_policy(self):
        """Bounded public-repository scanning applies only while the Linux worker boundary verifies right now.

        Anything else (local Seatbelt, a worker whose checks fail, no worker) keeps the pilot allowlist.
        """
        if self.policy_mode == policy.POLICY_BOUNDED and self.worker is not None:
            ok, _ = self.isolation.available()
            if ok:
                return policy.POLICY_BOUNDED
        return policy.POLICY_ALLOWLIST

    def check(self, owner, name, commit_sha, repo):
        """Admit this resolved repository and commit under the effective policy, or raise PolicyError."""
        if self.effective_policy() == policy.POLICY_BOUNDED:
            return policy.check_bounded(owner, name, commit_sha, repo)
        return policy.check_allowed(self.allowlist, owner, name, commit_sha)

    def aibom_available(self):
        """``(True, None)`` or ``(False, reason)``: the AI phase may run only while the gateway and AI worker verify AND the bounded public
        policy applies (which itself needs the scanner worker verified right now)."""
        if self.aibom is None:
            return False, "not_configured"
        if self.effective_policy() != policy.POLICY_BOUNDED:
            return False, "isolation_unavailable"
        ok, reason, _why = self.aibom.availability()
        return (True, None) if ok else (False, reason)

    def public(self):
        ok, reason = self.isolation.available()
        effective = self.effective_policy()
        doc = self._public(ok, reason, effective)
        if self.aibom is not None:
            # Pre-scan disclosure (UIP-07C A2): added only when the AI phase is requested, so the flag-off document is unchanged. No key, no prices.
            available, why = self.aibom_available()
            doc["ai_bom"] = dict(self.aibom.public(True), available=available, reason=why)
        return doc

    def _public(self, ok, reason, effective):
        return {"enabled": True, "policy": {"requested": self.policy_mode, "effective": effective,
                                            "bounded": policy.bounded_summary() if effective == policy.POLICY_BOUNDED else None,
                                            "pilot_restriction": effective != policy.POLICY_BOUNDED},
                "worker": self.worker.public() if self.worker is not None else None,
                "allowlist": [{"repo": e["repo"], "commit_sha": e["commit_sha"]} for e in self.allowlist.values()],
                "scanners": dict(self.scanners.pins), "isolation": {"name": self.isolation.name, "available": ok,
                                                                    "reason": reason or None, "description": self.isolation.description},
                "advisories": self.advisories.public() if self.advisories else {"enabled": False}}


def scan(config, service, ticket, identity):
    """Fetch, verify and scan the identity's commit. Returns ``(SourceRecord, [ScanRun, ...])``."""
    source, runs, _ = scan_with_inventory(config, service, ticket, identity)
    return source, runs


def scan_with_inventory(config, service, ticket, identity):
    """As ``scan_all`` without the source observations (kept for existing callers)."""
    return scan_all(config, service, ticket, identity)[:3]


def _emit(on_stage, event, **detail):
    """Report a pipeline boundary to an optional observer (UIP-03). Never raises, never changes a result, never skips cleanup."""
    if on_stage is None:
        return
    try:
        on_stage(event, detail)
    except Exception:
        pass


def scan_all(config, service, ticket, identity, on_stage=None, declarations_sink=None):
    """As ``scan`` plus the package inventory (I5B) when live advisory lookup is enabled, else ``None``, plus the I5C source
    observations as a fourth element (empty unless the commit has a declared target).

    The inventory is produced from the exported tree before it is removed. An infrastructure failure
    becomes an ``unavailable`` inventory (with a reason); only an unverifiable cleanup raises.

    The exported tree is removed before returning, whatever happens, and verified absent; the
    session's own cleanup removes anything left (cancellation, End session, expiry, startup sweep).

    ``declarations_sink`` (UIP-10) is an optional dict the caller supplies; when given, the bounded requirement-file collector runs over the
    exported tree before it is removed and its result (or a typed failure) is written into it. The return value and every default are unchanged.

    ``on_stage`` (UIP-03) is an optional observer ``on_stage(event, detail)`` told about the actual boundaries below; its failures are
    swallowed. With ``None`` the behavior is byte-identical to before.
    """
    repo, sha = identity["repository"], identity["resolved"]["commit_sha"]
    workspace = service.workspace(ticket)

    def register(group):
        service.register_producer(ticket, GroupProducer(group))

    try:
        _emit(on_stage, "acquire_started")
        source = source_mod.acquire(config.remote_for(repo["owner"], repo["name"]), sha, workspace, cancel=ticket.cancel_event,
                                    register=register, allow_protocol=config.allow_protocol, canonical_url=repo["canonical_url"])
        if source.commit_sha != sha:
            raise source_mod.SourceError("commit_mismatch", "acquired commit differs from the resolved commit")
        _emit(on_stage, "acquire_done")
        runs = []
        if config.worker is not None:
            from . import worker_client
            # One worker job runs both scanners: the observable boundary is the single shared phase (no per-scanner telemetry exists).
            _emit(on_stage, "scan_phase_started", shared=True, kinds=[s["kind"] for s in (SYFT, CDXGEN)])
            runs = worker_client.scan(config, service, ticket, source, workspace)
            _emit(on_stage, "scan_phase_done", runs=runs, shared=True)
        else:
            for spec in (SYFT, CDXGEN):
                _emit(on_stage, "scan_phase_started", shared=False, kinds=[spec["kind"]])
                runs.append(run_scanner(spec, config.scanners, config.isolation, source, workspace, cancel=ticket.cancel_event, register=register))
                _emit(on_stage, "scan_phase_done", runs=list(runs), shared=False)
                if ticket.cancel_event.is_set() or runs[-1].reason == "cleanup_unverified":
                    break
        if (config.aibom is not None and not ticket.cancel_event.is_set() and not any(r.reason == "cleanup_unverified" for r in runs)
                and any(r.kind == "sbom" and r.outcome == "acquired" for r in runs)):
            # Optional AI-BOM phase (UIP-07C): after the scanners, only when requested, only after a usable SBOM, and only while the AI worker,
            # gateway and bounded policy verify right now. Never changes the SBOM/CBOM runs; an unavailable phase is a typed run, not an error.
            from . import aibom_worker_client
            _emit(on_stage, "aibom_started")
            available, why = config.aibom_available()
            if available:
                ai_run = aibom_worker_client.run(config, service, ticket, source, workspace)
            else:
                ai_run = aibom_worker_client.unavailable_run(source, why)
            runs.append(ai_run)
            _emit(on_stage, "aibom_done", run=ai_run)
        inv = None
        if config.advisories is not None and not ticket.cancel_event.is_set() and not any(r.reason == "cleanup_unverified" for r in runs):
            _emit(on_stage, "inventory_started")
            inv = _inventory(config.advisories, source, workspace, ticket, register, repo)
            _emit(on_stage, "inventory_done", inventory=inv)
        _emit(on_stage, "source_checks_started")
        collected = source_checks.collect(os.path.join(workspace, "src"), "{}/{}".format(repo["owner"], repo["name"]), sha, config.source_check_targets)
        _emit(on_stage, "source_checks_done", collected=collected)
        if declarations_sink is not None:
            declarations_sink.clear()
            try:
                declarations_sink.update(source_declarations.collect(os.path.join(workspace, "src"), repo["canonical_url"], sha, cancel=ticket.cancel_event))
            except Exception:  # a collector fault is a typed state for the comparison only; the scan result is unaffected
                declarations_sink.update({"status": "failed", "code": "collector_error"})
        return source, runs, inv, collected
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def _inventory(advisories, source, workspace, ticket, register, repo):
    from opentrace_core.advisory import inventory
    if not advisories.specialist_bin:
        return inventory.unavailable("specialist_unavailable")
    try:
        return inventory.inventory(source, os.path.join(workspace, "src"), advisories.specialist_bin,
                                   repo_name="{}/{}".format(repo["owner"], repo["name"]), register=register,
                                   cancel=ticket.cancel_event, scratch=workspace)
    except inventory.InventoryError as exc:
        if exc.code == "cleanup_unverified":
            raise
        return inventory.unavailable(exc.code)
