# Expected occurrence rows for the 16 real inventory manifests (I3-REQ-04 acceptance oracle)

Byte-for-byte copies of a private planning record (not in this export) (digests verified against `index.json` when copied;
a test re-verifies them). Generated at planning with independent maintained parsers (json, tomllib, PyYAML 6.0.3 `safe_load`,
a go.mod line scan); regenerable with the dev-only `tools/i3/expected_rows.py`. The runtime parsers must reproduce every row
tuple exactly. Never edit these files to make a parser pass.
