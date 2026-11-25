"""Allowlist, pinned scanner versions and limits for live acquisition (I5)."""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ALLOWLIST_PATH = os.path.join(HERE, "allowlist.json")

SCANNER_PINS = {"syft": "1.51.1", "cdxgen": "12.9.0"}
# BOMBridge reads CycloneDX 1.6 CBOMs only (adapters.AIBOM_SPEC); Syft's SBOM is read as emitted.
CBOM_SPEC_VERSION = "1.6"
SCAN_PROFILE = "opentrace.scan.live/1"

# UIP-07C Cisco AI-BOM phase (additive; the limits above are unchanged). The producer module repeats these as stdlib-only constants because it
# also runs inside the AI worker image; a test keeps the two in step.
AIBOM_PIN = "1.10.1"
AIBOM_ENABLE_VAR = "OPENTRACE_LIVE_AIBOM"
AIBOM_ENABLE_VALUE = "cisco"
AIBOM_PHASE_SECONDS = 600
MAX_AIBOM_OUTPUT = 8 * 1024 * 1024
MAX_AIBOM_COMPONENTS = 2000

MAX_FETCH_BYTES = 128 * 1024 * 1024
MAX_FILES = 20000
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_SCANNER_OUTPUT = 48 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024
FETCH_SECONDS = 120
SCAN_SECONDS = 180

# Bounded public-repository policy (I6). The hard per-scan bounds above and in source.py still apply; this adds a
# pre-check on what GitHub reports about the repository so an oversized repository is refused before any fetch.
MAX_REPO_API_KB = 1024 * 1024        # GitHub's reported repository size (whole history), 1 GiB
POLICY_ALLOWLIST = "allowlist"
POLICY_BOUNDED = "bounded"
BOUNDED_SUMMARY = ("public github.com repository, full 40-hex commit resolved by this service, GitHub-reported size at most 1 GiB, "
                   "at most {files} files and {tree} MiB of exported blobs, {fetch} MiB fetched, {fetch_s}s fetch and {scan_s}s per scanner")

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$")


class PolicyError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def load_allowlist(path=ALLOWLIST_PATH):
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    if doc.get("schema") != "opentrace.live_allowlist/1":
        raise PolicyError("allowlist_invalid", "unsupported allowlist schema")
    entries = {}
    for entry in doc.get("entries", []):
        repo, sha = entry.get("repo"), entry.get("commit_sha")
        if not (isinstance(repo, str) and _REPO.fullmatch(repo) and isinstance(sha, str) and _SHA40.fullmatch(sha)):
            raise PolicyError("allowlist_invalid", "every entry needs owner/name and a full lowercase 40-hex commit")
        entries[repo.lower()] = {"repo": repo, "commit_sha": sha}
    return entries


def check_allowed(entries, owner, name, commit_sha):
    """Return the entry when this exact repository and commit are allowlisted, else raise."""
    entry = entries.get("{}/{}".format(owner, name).lower())
    if entry is None:
        raise PolicyError("not_allowlisted", "this repository is not on the live-scan allowlist")
    if entry["commit_sha"] != commit_sha:
        raise PolicyError("commit_not_allowlisted",
                          "this repository is allowlisted only at its pinned commit {}".format(entry["commit_sha"]))
    return entry


def bounded_summary():
    return BOUNDED_SUMMARY.format(files=MAX_FILES, tree=MAX_TREE_BYTES // (1024 * 1024), fetch=MAX_FETCH_BYTES // (1024 * 1024),
                                  fetch_s=FETCH_SECONDS, scan_s=SCAN_SECONDS)


def check_bounded(owner, name, commit_sha, repo):
    """Admit a public GitHub repository at a resolved full commit, or raise. ``repo`` is GitHub's own repository record.

    There is no per-repository entry: the only inputs are the shape of the request (already parsed and resolved by the
    intake modules) and what GitHub reports about the repository.
    """
    if not (isinstance(owner, str) and isinstance(name, str) and _REPO.fullmatch("{}/{}".format(owner, name))):
        raise PolicyError("repository_not_supported", "the repository name is not supported")
    if not (isinstance(commit_sha, str) and _SHA40.fullmatch(commit_sha)):
        raise PolicyError("commit_not_resolved", "the revision did not resolve to a full commit SHA")
    if not isinstance(repo, dict):
        raise PolicyError("repository_unverified", "GitHub's repository record was not available, so the repository was not admitted")
    if repo.get("private") is not False or repo.get("visibility", "public") != "public":
        raise PolicyError("repository_not_public", "only public repositories can be scanned")
    if repo.get("disabled") is True:
        raise PolicyError("repository_disabled", "GitHub reports this repository as disabled")
    size = repo.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise PolicyError("repository_unverified", "GitHub did not report a repository size, so the repository was not admitted")
    if size > MAX_REPO_API_KB:
        raise PolicyError("repository_too_large", "GitHub reports {} MiB, above the {} MiB limit".format(size // 1024, MAX_REPO_API_KB // 1024))
    return {"repo": "{}/{}".format(owner, name), "commit_sha": commit_sha, "policy": POLICY_BOUNDED, "github_size_kb": size}
