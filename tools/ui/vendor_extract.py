#!/usr/bin/env python3
"""Extract vendored UI assets and the advisory snapshot from the pinned prototype (I4E).

Reads the immutable prototype, verifies its sha256, and writes byte-for-byte copies of the
embedded blocks plus a digest manifest. The prototype file is never modified.

    python3 tools/ui/vendor_extract.py [--check]
"""
import hashlib
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROTOTYPE = os.path.join(ROOT, ".context", "references", "prototypes", "opentrace-workbench-2026-11-04.html")
PROTOTYPE_SHA256 = "493e48833ccc6c091c5567f3f45ad8df00978f4bd4b1168d94dcdf1caec2ff07"
VENDOR = os.path.join(ROOT, "src", "ui", "vendor")
DEMO = os.path.join(ROOT, "src", "core", "opentrace_core", "app", "demo")

# (script id, output path). The ELK API bundle is the id-less 1.6 MB UMD script after Cytoscape.
BLOCKS = [("flow-cytoscape-vendor", os.path.join(VENDOR, "cytoscape.min.js")),
          ("flow-elk-worker", os.path.join(VENDOR, "elk-worker.js")),
          ("flow-vendor-notices", os.path.join(VENDOR, "NOTICES.json"))]


def blocks(text):
    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", text, re.S):
        ident = re.search(r'\bid="([^"]+)"', m.group(1))
        yield (ident.group(1) if ident else None), m.group(2)


def style_blocks(text):
    for m in re.finditer(r"<style\b[^>]*>(.*?)</style>", text, re.S):
        yield m.group(1)


def extract():
    with open(PROTOTYPE, "rb") as handle:
        raw = handle.read()
    if hashlib.sha256(raw).hexdigest() != PROTOTYPE_SHA256:
        raise SystemExit("prototype digest mismatch; refusing to extract")
    text = raw.decode("utf-8")
    found = {}
    elk_api = None
    for ident, body in blocks(text):
        if ident:
            found[ident] = body
        elif body.startswith('(function(f){if(typeof exports==="object"') and len(body) > 1_000_000:
            elk_api = body
    out = {}
    for ident, path in BLOCKS:
        out[path] = found[ident].encode("utf-8")
    out[os.path.join(VENDOR, "elk.bundled.js")] = elk_api.encode("utf-8")
    data = json.loads(found["ot2-frigate-data"])
    advisories = {
        "source": "extracted from the pinned prototype block ot2-frigate-data; OSV snapshot, not a live query",
        "repository": data["repository"], "revision": data["revision"], "captured_at": data["captured_at"],
        "sbom_sha256": data["sbom_sha256"], "osv_source": data["osv"]["source"],
        "queries": data["osv"]["queries"], "completed": data["osv"]["completed"],
        "failures": data["osv"]["failures"], "queried_component_count": data["queried_component_count"],
        "families": data["advisory_families"], "rows": data["advisory_rows"],
        "records": data["osv"]["records"],
    }
    css = "/* Extracted verbatim from the pinned prototype by tools/ui/vendor_extract.py; do not edit. */\n"
    css += "\n".join(style_blocks(text))
    out[os.path.join(ROOT, "src", "ui", "styles", "prototype.css")] = css.encode("utf-8")
    out[os.path.join(DEMO, "frigate_advisories.json")] = (
        json.dumps(advisories, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return out


def main(argv):
    out = extract()
    manifest = {"prototype": os.path.relpath(PROTOTYPE, ROOT), "prototype_sha256": PROTOTYPE_SHA256, "files": {}}
    for path, data in sorted(out.items()):
        manifest["files"][os.path.relpath(path, ROOT)] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    rendered = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    manifest_path = os.path.join(VENDOR, "MANIFEST.json")
    if "--check" in argv:
        for path, data in out.items():
            if not os.path.exists(path) or open(path, "rb").read() != data:
                raise SystemExit("stale or missing: " + os.path.relpath(path, ROOT))
        if not os.path.exists(manifest_path) or open(manifest_path, "rb").read() != rendered:
            raise SystemExit("manifest stale")
        print("vendor assets match the pinned prototype")
        return
    os.makedirs(VENDOR, exist_ok=True)
    os.makedirs(DEMO, exist_ok=True)
    for path, data in out.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
    with open(manifest_path, "wb") as handle:
        handle.write(rendered)
    print(rendered.decode())


if __name__ == "__main__":
    main(sys.argv[1:])
