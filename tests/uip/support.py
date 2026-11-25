"""Shared helpers for the UIP-01A tool tests (scratch copies and manifests live in temp directories only)."""
import os
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TOOLS = os.path.join(ROOT, "tools", "uip")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

START_SHA = "f80358bf7af4c1614dcea5f4a5d6acae567006db"
_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")


def scratch_repo(destination):
    """A minimal temp copy of what the tools read (tools, src, tests, the reference HTML). Never the real checkout."""
    for rel in ("tools/uip", "src", "tests"):
        shutil.copytree(os.path.join(ROOT, rel), os.path.join(destination, rel), ignore=_IGNORE)
    ref = ".context/references/prototypes/OpenTrace-UI-Update-9-Combined.html"
    os.makedirs(os.path.dirname(os.path.join(destination, ref)))
    shutil.copy2(os.path.join(ROOT, ref), os.path.join(destination, ref))
    return destination


def run_tool(repo, script, *args, timeout=300):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return subprocess.run([sys.executable, os.path.join(repo, "tools", "uip", script), *args], capture_output=True, text=True, timeout=timeout, env=env)


def read(path, mode="rb"):
    with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as handle:
        return handle.read()


def write(path, data, mode="w"):
    with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as handle:
        handle.write(data)
