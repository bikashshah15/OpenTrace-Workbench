#!/usr/bin/env python3
"""UIP-07C BUILD-1 helper: assemble the offline build contexts and build the two images with networking disabled.

    build_aibom_images.py context --prep DIR --out DIR      assemble contexts from the retained PREP-1 inputs (wheelhouse, KB); verifies every hash
    build_aibom_images.py build   --out DIR --ledger FILE   docker build --network none --pull=false, labelled, with an invocation ledger line

PREP-1 downloads (wheels, KB, licence text) are NOT in git. ``context`` refuses to proceed unless the wheelhouse is exactly the hash-locked set
(115 wheels, no extras, no missing) and the KB matches its pinned digest. ``build`` never pulls and never touches the network: the base image
is digest-pinned in the Dockerfiles and must already be local (PREP-1). Standard library only; no package is imported or executed here.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
LIVE = os.path.join(REPO, "src", "core", "opentrace_core", "live")
LOCK = os.path.join(REPO, "tools", "live", "cisco-aibom", "requirements.lock")
KB_NAME = "aibom_catalog-1.10.1.duckdb"
KB_SHA256 = "b1165384a646094aa6a4762d676f285c1c68b6d7f9367c90a129b529904a3268"
KB_SIZE = 76296192
BASE_DIGEST = "sha256:aed314f1f0c7e988b7aee5d889414ec977430bad37770966c52aff5366a13a06"
LABEL = "opentrace.uip07c"
IMAGES = {"aibom-worker": "opentrace-aibom-worker:uip07c", "gateway": "opentrace-gateway:uip07c"}
MAX_IMAGE_BYTES = 3 * 1024 ** 3
MAX_BUILDS, MAX_SECONDS = 9, 30 * 60      # 6 originally; 8 by owner authorization (2026-11-15) to recreate the worker image and build the corrected gateway image; 9 by a further authorization for ONE gateway-only rebuild


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def lock_hashes():
    out = []
    for line in open(LOCK, encoding="ascii"):
        match = re.match(r"^(\S+)==(\S+) --hash=sha256:([0-9a-f]{64})$", line.strip())
        if match:
            out.append((match.group(1), match.group(2), match.group(3)))
    return out


def cmd_context(args):
    wheelhouse = os.path.join(args.prep, "wheelhouse")
    files = sorted(os.listdir(wheelhouse))
    by_hash = {sha256(os.path.join(wheelhouse, f)): f for f in files}
    entries = lock_hashes()
    problems = []
    if len(entries) != 115 or len(files) != 115:
        problems.append("expected 115 locked entries and 115 wheels, found %d and %d" % (len(entries), len(files)))
    missing = [name for name, version, digest in entries if digest not in by_hash]
    extra = [f for h, f in by_hash.items() if h not in {d for _n, _v, d in entries}]
    if missing:
        problems.append("locked but absent or different: " + ", ".join(missing))
    if extra:
        problems.append("present but not in the lock: " + ", ".join(sorted(extra)))
    if any(not f.endswith(".whl") for f in files):
        problems.append("the wheelhouse holds a file that is not a wheel")
    kb = os.path.join(args.prep, "kb", KB_NAME)
    if not os.path.isfile(kb) or os.path.getsize(kb) != KB_SIZE or sha256(kb) != KB_SHA256:
        problems.append("the knowledge base is missing or differs from its pin")
    if problems:
        print("\n".join("STOP " + p for p in problems))
        return 1
    worker, gateway = os.path.join(args.out, "aibom-worker"), os.path.join(args.out, "gateway")
    for target in (worker, gateway):
        shutil.rmtree(target, ignore_errors=True)
        os.makedirs(target)
    shutil.copytree(wheelhouse, os.path.join(worker, "wheelhouse"))
    shutil.copy(LOCK, os.path.join(worker, "requirements.lock"))
    cisco = os.path.join(REPO, "tools", "live", "cisco-aibom")
    for name in ("verify_install.py", "KB.sha256", "empty-catalog.json", "empty.env"):
        shutil.copy(os.path.join(cisco, name), worker)
    shutil.copytree(os.path.join(cisco, "licences"), os.path.join(worker, "licences"))
    shutil.copy(kb, worker)
    shutil.copy(os.path.join(LIVE, "aibom_cisco.py"), worker)
    for name in ("worker.py", "validate_artifact.py"):
        shutil.copy(os.path.join(REPO, "src", "workers", "aibom", name), worker)
    shutil.copy(os.path.join(REPO, "deploy", "docker", "Dockerfile.aibom-worker"), worker)
    shutil.copy(os.path.join(REPO, "src", "workers", "gateway", "gateway.py"), gateway)
    shutil.copy(os.path.join(REPO, "deploy", "docker", "Dockerfile.gateway"), gateway)
    manifest = {}
    for base in (worker, gateway):
        for root, _dirs, names in os.walk(base):
            for name in names:
                path = os.path.join(root, name)
                if not path.startswith(os.path.join(worker, "wheelhouse")) and name != "aibom_catalog-1.10.1.duckdb":
                    manifest[os.path.relpath(path, args.out)] = sha256(path)
    with open(os.path.join(args.out, "context_manifest.json"), "w") as handle:
        json.dump({"wheels_verified": len(files), "kb_sha256": KB_SHA256, "base_digest": BASE_DIGEST, "files": manifest}, handle, indent=1, sort_keys=True)
    print("contexts ready: %d wheels hash-verified against the lock; KB verified; label %s" % (len(files), LABEL))
    return 0


def ledger(path, record):
    n = sum(1 for _ in open(path)) if os.path.exists(path) else 0
    record["seq"] = n + 1
    with open(path, "a") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def cmd_build(args):
    started_all = time.monotonic()
    done = sum(1 for line in open(args.ledger) if '"BUILD-1"' in line) if os.path.exists(args.ledger) else 0
    for service, tag in IMAGES.items():
        if args.only and service != args.only:
            continue
        if done >= MAX_BUILDS or time.monotonic() - started_all > MAX_SECONDS:
            print("STOP build cap reached")
            return 1
        context = os.path.join(args.out, service)
        dockerfile = "Dockerfile.aibom-worker" if service == "aibom-worker" else "Dockerfile.gateway"
        argv = ["docker", "build", "--network", "none", "--pull=false", "--label", "%s=BUILD-1" % LABEL, "-t", tag, "-f", os.path.join(context, dockerfile), context]
        t0 = datetime.datetime.now(datetime.timezone.utc)
        process = subprocess.run(argv)
        t1 = datetime.datetime.now(datetime.timezone.utc)
        done += 1
        ledger(args.ledger, {"activity": "BUILD-1", "tool": "docker", "argv_sha256": hashlib.sha256("\0".join(argv).encode()).hexdigest(), "hosts": "none (--network none, --pull=false)",
                             "service": service, "start": t0.strftime("%Y-%m-%dT%H:%M:%SZ"), "end": t1.strftime("%Y-%m-%dT%H:%M:%SZ"), "exit": process.returncode})
        if process.returncode != 0:
            print("STOP build of %s failed (exit %d)" % (service, process.returncode))
            return 1
        size = int(subprocess.check_output(["docker", "image", "inspect", tag, "--format", "{{.Size}}"]).decode().strip())
        print("%s built: %d bytes (cap %d)" % (tag, size, MAX_IMAGE_BYTES))
        if size > MAX_IMAGE_BYTES:
            print("STOP image over the 3 GiB cap")
            return 1
    return 0


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("context")
    c.add_argument("--prep", required=True)
    c.add_argument("--out", required=True)
    b = sub.add_parser("build")
    b.add_argument("--out", required=True)
    b.add_argument("--ledger", required=True)
    b.add_argument("--only", choices=sorted(IMAGES), help="build just this service (the other image is left untouched)")
    args = parser.parse_args()
    sys.exit(cmd_context(args) if args.cmd == "context" else cmd_build(args))


if __name__ == "__main__":
    main()
