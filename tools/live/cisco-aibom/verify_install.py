#!/usr/bin/env python3
"""BUILD-1 check, run inside the image build with networking disabled: the installed distribution set must equal the hash-locked 115-wheel
set exactly, and the ``json-validation`` extra of cyclonedx-python-lib must be present. A mismatch fails the BUILD, not a later run.
Standard library only; reads installed metadata, imports no package. Usage: verify_install.py /requirements.lock"""
import importlib.metadata as md
import re
import sys


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


lock = {}
for line in open(sys.argv[1], encoding="ascii"):
    match = re.match(r"^([A-Za-z0-9_.-]+)(\[[^\]]*\])?==(\S+) --hash=sha256:[0-9a-f]{64}$", line.strip())
    if match:
        lock[norm(match.group(1))] = match.group(3)
installed = {norm(d.metadata["Name"]): d.version for d in md.distributions() if norm(d.metadata["Name"]) != "pip"}
problems = []
if len(lock) != 115:
    problems.append("lock has %d entries, expected 115" % len(lock))
for name in sorted(set(lock) | set(installed)):
    if lock.get(name) != installed.get(name):
        problems.append("%s: lock %s installed %s" % (name, lock.get(name), installed.get(name)))
extra_needed = []
for req in md.requires("cyclonedx-python-lib") or []:
    if re.search(r"""extra\s*==\s*['"]json-validation['"]""", req):
        extra_needed.append(norm(re.split(r"[\s;<>=!~\[(]", req.strip())[0]))
if not extra_needed:
    problems.append("cyclonedx-python-lib declares no json-validation extra requirements")
for name in extra_needed:
    if name not in installed:
        problems.append("json-validation extra requirement missing: " + name)
print("installed=%d locked=%d json_validation_extra=%s" % (len(installed), len(lock), ",".join(sorted(extra_needed))))
if problems:
    print("\n".join("PROBLEM " + p for p in problems))
    sys.exit(1)
print("OK installed set equals the hash-locked set")
