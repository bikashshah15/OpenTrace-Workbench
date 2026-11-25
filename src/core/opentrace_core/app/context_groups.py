"""Generic repository contexts map payloads (UIP-04): ``opentrace.workbench.contexts/1``.

Pure and read-only. Input is the adapter's ``contexts`` projection (normalized paths, recorded raw locations, member component
ids, unlocated components); output is the grouped repository -> group -> file payload the frozen UIP-01B schema describes.
Nothing here reads repository files, invents a location, or knows a repository by name: grouping is the ordered classifier of
contract UIP-04 section 4.3 over the normalized path, counts are distinct (union) versus membership (sum), identities are the
frozen ``opaque_id`` derivation, and paging is bounded.
"""
import json
import re
import threading
import weakref
from urllib.parse import quote

from . import view_contracts as vc
from .workbench_binding import build_binding

CATEGORY_ORDER = ("documentation", "web", "node_packages", "python_requirements", "go_modules", "rust_crates", "java_build",
                  "github_actions", "container_files", "other_locations")
LABELS = {"documentation": "Documentation", "web": "Web application", "node_packages": "Node packages",
          "python_requirements": "Python requirements", "go_modules": "Go modules", "rust_crates": "Rust crates",
          "java_build": "Java build files", "github_actions": "GitHub Actions", "container_files": "Container files",
          "other_locations": "Other locations"}
UNLOCATED_LABEL = "Unlocated components"
RESPONSE_MAX_BYTES = 524288

_PREFIXES = (("docs/", "documentation"), ("web/", "web"), (".github/", "github_actions"))
_REQUIREMENTS = re.compile(r"^requirements.*\.txt\Z")
_BASENAMES = (
    (frozenset({"pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "setup.py", "setup.cfg"}), "python_requirements"),
    (frozenset({"go.mod", "go.sum"}), "go_modules"),
    (frozenset({"Cargo.toml", "Cargo.lock"}), "rust_crates"),
    (frozenset({"pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"}), "java_build"),
    (frozenset({"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}), "node_packages"),
    (frozenset({"Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yaml", "compose.yml"}), "container_files"),
)


def classify(path):
    """Ordered, case-sensitive classifier (contract 4.3). Returns ``(category, basis)``; unknown -> ``other_locations``/``fallback``.

    A path starting with ``./`` or ``../`` or containing ``//`` is classified by basename only (no prefix match).
    """
    if not (path.startswith("./") or path.startswith("../") or "//" in path):
        for prefix, category in _PREFIXES:
            if path.startswith(prefix):
                return category, "path_prefix"
    base = path.rsplit("/", 1)[-1]
    if _REQUIREMENTS.match(base):
        return "python_requirements", "manifest_basename"
    for names, category in _BASENAMES:
        if base in names or (category == "container_files" and base.startswith("Dockerfile.")):
            return category, "manifest_basename"
    return "other_locations", "fallback"


def _representable(text):
    return isinstance(text, str) and 1 <= len(text) <= 512 and not any(ord(ch) < 0x20 for ch in text)


class _Group:
    __slots__ = ("kind", "category", "label", "basis", "distinct", "membership", "files", "group_id")


class ContextsModel:
    """Grouped view of one analysis' recorded locations; built once per analysis and digest."""

    def __init__(self, files, unlocated_ids, component_total):
        self.files = []
        for f in files:
            raw = sorted(set(f["raw_locations"]))
            if not _representable(f["path"]) or not all(_representable(r) for r in raw):
                raise vc.ContractError("projection_failed", "unrepresentable_path", "/groups",
                                       "a recorded location cannot be carried by the contract; nothing was dropped or rewritten")
            self.files.append({"path": f["path"], "raw": raw, "basis": sorted(set(f["basis"])), "members": frozenset(f["members"])})
        self.files.sort(key=lambda f: f["path"])
        self.unlocated = frozenset(unlocated_ids)
        self.component_total = component_total
        located = set()
        for f in self.files:
            located |= f["members"]
        if len(located) + len(self.unlocated) != component_total:
            raise vc.ContractError("projection_failed", "component_total_mismatch", "/root", "located and unlocated components do not add up")
        self.located_distinct = len(located)
        self._layouts = {}

    @classmethod
    def from_projection(cls, tab):
        files = [{"path": r["path"], "raw_locations": r["raw_locations"], "basis": r["normalization_basis"],
                  "members": [c["id"] for c in r["components"]]} for r in tab["rows"]]
        return cls(files, [c["id"] for c in tab["unlocated"]["components"]], tab["component_total"])

    def layout(self, digest):
        """The ordered groups (only non-empty categories, then Unlocated) with stable opaque ids for ``digest``."""
        if digest in self._layouts:
            return self._layouts[digest]
        by_category = {}
        for f in self.files:
            category, basis = classify(f["path"])
            by_category.setdefault(category, []).append((f, basis))
        groups = []
        for category in CATEGORY_ORDER:
            rows = by_category.get(category)
            if not rows:
                continue
            g = _Group()
            g.kind, g.category, g.label = "located", category, LABELS[category]
            g.basis = rows[0][1]                                   # a category has one basis (rules 1-3 prefix, 4-9 basename, 10 fallback)
            members = set()
            for f, _ in rows:
                members |= f["members"]
            g.distinct, g.membership = len(members), sum(len(f["members"]) for f, _ in rows)
            g.files = []
            for f, _ in rows:
                card = dict(f)
                card["file_id"] = vc.opaque_id("ctx", digest, "file", f["path"])
                g.files.append(card)
            g.group_id = vc.opaque_id("grp", digest, "group", category)
            groups.append(g)
        if self.unlocated:
            g = _Group()
            g.kind, g.category, g.label, g.basis = "unlocated", None, UNLOCATED_LABEL, "fallback"
            g.distinct = g.membership = len(self.unlocated)
            g.files = []
            g.group_id = vc.opaque_id("grp", digest, "group", "unlocated")
            groups.append(g)
        self._layouts[digest] = groups
        return groups


def _link(binding, path):
    """The pinned-revision link, or ``href: None`` when the recorded path cannot yield a faithful one.

    The recorded path is never rewritten. A ``.`` or ``..`` segment is reinterpreted by every URL parser (it can leave the
    repository and commit, or silently point at a different file), so such a path gets an inert link (frozen schema: ``href`` is nullable).
    """
    if any(seg in (".", "..") for seg in path.split("/")):
        return {"href": None, "text": path}
    r = binding["repository"]
    href = "https://github.com/%s/%s/blob/%s/%s" % (r["owner"], r["name"], binding["commit_sha"], quote(path, safe="/"))
    return {"href": href if len(href) <= 2048 else None, "text": path}


def _file_card(f, binding):
    return {"file_id": f["file_id"], "path": f["path"], "raw_locations": f["raw"][:5], "raw_locations_total": len(f["raw"]),
            "normalization_basis": f["basis"], "distinct_total": len(f["members"]), "membership_total": len(f["members"]),
            "dependency_context_id": f["file_id"], "revision_link": _link(binding, f["path"])}


def _count_block(total, shown):
    return {"total": total, "shown": shown, "truncated": shown < total}


def build_payload(model, binding, *, group_id=None, files_offset=0, files_limit=20, selected=None):
    """Assemble ``contexts/1``. ``group_id`` None: every group, first page of each. Otherwise only that group, paged."""
    groups = model.layout(binding["analysis_digest"])
    repo = binding["repository"]
    chosen = groups
    if group_id is not None:
        chosen = [g for g in groups if g.group_id == group_id]
        if not chosen:
            raise vc.ContractError("invalid_request", "unknown_group", "group_id", "no such group in this analysis")
    out, ids = [], set()
    for g in chosen:
        total = len(g.files)
        offset = files_offset if group_id is not None else 0
        if group_id is not None and (offset >= total if total else offset != 0):
            raise vc.ContractError("invalid_request", "files_offset_out_of_range", "files_offset", "the offset is past the last file of this group")
        page = g.files[offset:offset + files_limit]
        cards = [_file_card(f, binding) for f in page]
        ids.add(g.group_id)
        ids.update(c["file_id"] for c in cards)
        out.append({"group_id": g.group_id, "kind": g.kind, "category": g.category,
                    "token": "neutral" if g.kind == "unlocated" else vc.CATEGORY_TOKEN[g.category], "label": g.label, "basis": g.basis,
                    "distinct_total": g.distinct, "membership_total": g.membership, "files": cards,
                    "files_counts": _count_block(total, len(cards)), "files_offset": offset})
    unlocated_total = len(model.unlocated)
    return {"schema": "opentrace.workbench.contexts/1", "binding": binding,
            "root": {"name": "%s/%s" % (repo["owner"], repo["name"]), "canonical_url": repo["canonical_url"],
                     "commit_sha": binding["commit_sha"], "distinct_total": model.located_distinct + unlocated_total,
                     "membership_total": sum(g.membership for g in groups if g.kind == "located"),
                     "located_distinct_total": model.located_distinct, "unlocated_total": unlocated_total},
            "edge_semantics": "grouping_or_inventory_location", "groups": out,
            "selected_id": selected if selected in ids else None, "counts": _count_block(len(groups), len(out))}


# One model per analysis object and digest (a session's analysis is replaced, never mutated, so the cache cannot go stale).
_CACHE = weakref.WeakKeyDictionary()
_LOCK = threading.Lock()


def model_for(analysis):
    digest = analysis.identity["analysis_digest"]
    with _LOCK:
        hit = _CACHE.get(analysis)
        if hit is not None and hit[0] == digest:
            return hit[1]
    try:
        raw = analysis.views._project("contexts")             # the same existing projection call views.context_list uses
    except vc.ContractError:
        raise
    except Exception as exc:
        detail = getattr(exc, "code", None) or "projection_failed"
        raise vc.ContractError("projection_failed", str(detail)[:120] if isinstance(detail, str) else "projection_failed", "", "projection failed")
    model = ContextsModel.from_projection(raw["tabs"][0])
    with _LOCK:
        _CACHE[analysis] = (digest, model)
    return model


def respond(analysis, params):
    """Validate the request, build and validate the payload. ``params`` maps name -> value or list of values (parse_qs).

    Raises ``view_contracts.ContractError`` (typed) for every refusal.
    """
    request = vc.validate_request("contexts", params)
    if "files_offset" in params and "group_id" not in params:
        raise vc.ContractError("invalid_request", "files_offset_requires_group", "files_offset", "files_offset needs group_id")
    binding = build_binding(analysis)
    if request["generation"] != binding["generation"]:
        raise vc.ContractError("stale_generation", "invariant:generation", "generation", "the session has moved on")
    model = model_for(analysis)
    payload = build_payload(model, binding, group_id=request.get("group_id"), files_offset=request["files_offset"],
                            files_limit=request["files_limit"], selected=request.get("selected"))
    expected = {k: binding[k] for k in ("analysis_digest", "commit_sha", "repository", "requested_ref", "mode", "assessment")}
    vc.validate_payload("contexts", payload, request={"generation": request["generation"]}, expected_binding=expected)
    return payload


def encode_response(payload):
    """UTF-8 JSON bytes of the validated payload, bounded to the contract's response ceiling (never truncated)."""
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(body) > RESPONSE_MAX_BYTES:
        raise vc.ContractError("response_too_large", "bound_exceeded", "", "%d bytes exceeds the %d byte ceiling" % (len(body), RESPONSE_MAX_BYTES))
    return body
