#!/usr/bin/env python3
"""P8 step 7 helper: validate one file against the CycloneDX 1.6 schema in a short-lived child process of the venv interpreter.
Prints exactly one token (ok | schema_invalid | schema_validator_unavailable) and nothing else; the artifact text is never echoed."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aibom_cisco  # noqa: E402

try:
    with open(sys.argv[1], "rb") as handle:
        data = handle.read(aibom_cisco.MAX_ARTIFACT_BYTES + 1)
    token = aibom_cisco.validate_schema(data) if len(data) <= aibom_cisco.MAX_ARTIFACT_BYTES else "schema_invalid"
except Exception:
    token = "schema_validator_unavailable"
print("ok" if token is None else token)
