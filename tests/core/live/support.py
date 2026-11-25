"""Test doubles for live scanning: a local git repository, fake scanner scripts, pass-through isolation."""
import json
import os
import shutil
import stat
import subprocess
import tempfile

from opentrace_core.intake.resolve import Response

GIT_ENV = {"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
           "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}


def git(cwd, *args):
    out = subprocess.run(["git", *args], cwd=cwd, env=GIT_ENV, capture_output=True, check=True)
    return out.stdout.decode().strip()


def make_repo(root, files, *, symlink=None, attributes=None):
    """Create a local repository and return (path, commit_sha, tree_sha)."""
    path = os.path.join(root, "origin")
    os.makedirs(path)
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "uploadpack.allowAnySHA1InWant", "true")
    for name, data in files.items():
        target = os.path.join(path, *name.split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(data)
    if attributes:
        with open(os.path.join(path, ".gitattributes"), "w") as handle:
            handle.write(attributes)
    if symlink:
        os.symlink(symlink, os.path.join(path, "link"))
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "fixture")
    return path, git(path, "rev-parse", "HEAD"), git(path, "rev-parse", "HEAD^{tree}")


def cyclonedx(components=(), spec="1.6", extra=None):
    doc = {"bomFormat": "CycloneDX", "specVersion": spec, "version": 1, "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
           "metadata": {"timestamp": "2026-01-01T00:00:00Z", "tools": {"components": [{"type": "application", "name": "fake", "version": "1"}]}},
           "components": list(components), "dependencies": []}
    doc.update(extra or {})
    return json.dumps(doc, sort_keys=True).encode()


def library(name, version="1.0.0"):
    ref = "pkg:npm/{}@{}".format(name, version)
    return {"type": "library", "name": name, "version": version, "bom-ref": ref, "purl": ref,
            "properties": [{"name": "syft:location:0:path", "value": "package-lock.json"}]}


def crypto_asset(name="SHA-256"):
    return {"type": "cryptographic-asset", "name": name, "bom-ref": "crypto/" + name,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
            "evidence": {"occurrences": [{"location": "src/a.js", "line": 1}]}}


def fake_tool(directory, name, *, output=None, exit_code=0, sleep=0, version="9.9.9", stdout="", output_path_arg=None):
    """A shell script that behaves like a scanner: ``version`` prints the version, otherwise it
    writes ``output`` to the path after ``-o`` (or ``cyclonedx-json=``)."""
    script = os.path.join(directory, name)
    payload = os.path.join(directory, name + ".payload")
    if output is not None:
        with open(payload, "wb") as handle:
            handle.write(output)
    body = """#!/bin/sh
if [ "$1" = "version" ]; then /bin/echo "Version: {version}"; exit 0; fi
out=""
for a in "$@"; do
  case "$a" in
    cyclonedx-json=*) out="${{a#cyclonedx-json=}}";;
    *) if [ "$prev" = "-o" ]; then out="$a"; fi;;
  esac
  prev="$a"
done
/bin/echo "{stdout}"
if [ {sleep} -gt 0 ]; then /bin/sleep {sleep}; fi
if [ -n "$out" ] && [ -f "{payload}" ]; then /bin/cp "{payload}" "$out"; fi
exit {exit_code}
""".format(version=version, stdout=stdout, sleep=sleep, payload=payload, exit_code=exit_code)
    with open(script, "w") as handle:
        handle.write(body)
    os.chmod(script, os.stat(script).st_mode | stat.S_IXUSR)
    return script


class PassThrough:
    """Test-only isolation: runs the command unchanged. Production never has such a provider."""
    name = "test-passthrough"
    description = "test double"

    def __init__(self, available=True):
        self._available = available
        self.wrapped = []

    def available(self):
        return (True, "") if self._available else (False, "test: unavailable")

    def wrap(self, argv, **kw):
        from opentrace_core.live.isolation import IsolationUnavailable
        if not self._available:
            raise IsolationUnavailable("test: unavailable")
        self.wrapped.append((list(argv), kw))
        return list(argv)


def recorded_transport(owner, name, sha, default_branch="main"):
    """Recorded GitHub REST answers for one repository whose branch ``main`` and tag ``v1`` are ``sha``."""
    prefix = "/repos/{}/{}".format(owner, name)

    def transport(path):
        if not path.lower().startswith(prefix.lower()):
            raise OSError("no recorded response")
        rest = path[len(prefix):]
        if rest == "":
            return Response(200, {"full_name": "{}/{}".format(owner, name), "default_branch": default_branch})
        if rest in ("/git/ref/heads/" + default_branch, "/git/ref/tags/v1"):
            return Response(200, {"ref": "refs/" + rest[len("/git/ref/"):], "object": {"type": "commit", "sha": sha}})
        if rest.startswith("/commits/") and sha.startswith(rest[len("/commits/"):].lower()):
            return Response(200, {"sha": sha})
        return Response(404, None)
    return transport
