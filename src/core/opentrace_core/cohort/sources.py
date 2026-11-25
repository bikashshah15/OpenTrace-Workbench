"""Typed view of a source capture set (kinds repo_fetch_event, repo_listing, source_blob, license_blob).

Core never touches the network. The view is built only from a verified CaptureSet and the approved pins.
"""
import json

from ..captures import CaptureError
from . import policy as pol

SOURCE_KINDS = ("repo_fetch_event", "repo_listing", "source_blob", "license_blob")


class SourceError(Exception):
    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code, self.detail = code, detail


def _repo_of(url):
    # https://github.com/<owner>/<name>(.git|/tree/..|/blob/<sha>/<path>)
    rest = url.split("://", 1)[1].split("/", 3)
    return "%s/%s" % (rest[1], rest[2].replace(".git", "")) if len(rest) >= 3 else None


class SourceRepo:
    def __init__(self, repo, commit):
        self.repo, self.commit = repo, commit
        self.event = None
        self.listing_digest = None
        self.rows = []
        self.blobs = {}        # path -> (digest, bytes length)
        self.license = None    # (path, digest)

    def to_dict(self):
        return {"repo": self.repo, "commit": self.commit, "tree": self.event["tree"], "listing_digest": self.listing_digest}


class SourceSet:
    def __init__(self, captures, pins, policy=None):
        self.captures, self.pins = captures, pins
        self.policy = policy or pol.load_policy()
        self.repos = {}
        by_repo = {p["repo"]: p for p in pins["repos"]}
        for e in captures.entries:
            if e["kind"] not in SOURCE_KINDS:
                raise SourceError("unexpected_kind", "%s is not a source capture kind" % e["kind"])
            if e["provenance"] != "real":
                raise SourceError("not_real", "entry %s is not real" % e["capture_id"])
            repo = _repo_of(e["url"])
            if repo not in by_repo:
                raise SourceError("unknown_repo", "%s is not in the approved pins" % repo)
            pin = by_repo[repo]
            sr = self.repos.setdefault(repo, SourceRepo(repo, pin["commit"]))
            if e["kind"] == "repo_fetch_event":
                sr.event = json.loads(captures.blob(e["response_digest"]))
            elif e["kind"] == "repo_listing":
                if pin["commit"] not in e["url"]:
                    raise SourceError("commit_mismatch", "%s listing is not for the pinned commit" % repo)
                sr.listing_digest = e["response_digest"]
                sr.rows = pol.parse_ls_tree(captures.blob(e["response_digest"]))
            else:
                path = e["url"].split("/blob/%s/" % pin["commit"], 1)
                if len(path) != 2:
                    raise SourceError("commit_mismatch", "%s blob entry is not for the pinned commit" % repo)
                if e["kind"] == "license_blob":
                    sr.license = (path[1], e["response_digest"])
                else:
                    sr.blobs[path[1]] = (e["response_digest"], e["bytes"])
        for repo, pin in by_repo.items():
            sr = self.repos.get(repo)
            if sr is None or sr.event is None or not sr.rows:
                raise SourceError("incomplete", "%s is missing from the source capture set" % repo)
            if sr.event["commit"] != pin["commit"] or sr.event["tree"] != pin["tree"]:
                raise SourceError("pin_mismatch", "%s: recorded commit/tree differ from the approved pin" % repo)

    def selection(self, repo):
        return pol.select_manifests(self.repos[repo].rows, self.policy)

    def blob(self, repo, path):
        digest, _ = self.repos[repo].blobs[path]
        return self.captures.blob(digest)
