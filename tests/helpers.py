"""Shared test fixtures: contract examples and a temporary store holding the I1 fixture."""
import copy
import json
import tempfile
from pathlib import Path

from opentrace_core import timeutil
from opentrace_core.artifacts import ArtifactStore

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "contracts" / "evidence" / "v1" / "examples"
FIXTURE = ROOT / "evidence" / "fixtures" / "i1" / "gomod-basic" / "go.mod"
FIXTURE_DIGEST = "sha256:38eb8de4d5c72ffbe83edeaedf13770a696b51dec0e7c74a44edeaa7e290b92b"
RECEIVED = timeutil.parse_ts("2026-10-13T12:00:01.500Z")


def example(rel):
    return copy.deepcopy(json.loads((EXAMPLES / rel).read_text()))


def valid(name):
    return example("valid/%s.json" % name)


def fixture_store(testcase):
    tmp = tempfile.TemporaryDirectory()
    testcase.addCleanup(tmp.cleanup)
    store = ArtifactStore(Path(tmp.name) / "store")
    store.put(FIXTURE.read_bytes(), media_type="text/plain; charset=utf-8", producer="fixture",
              revision_binding="bound_by_digest")
    return store, Path(tmp.name)
