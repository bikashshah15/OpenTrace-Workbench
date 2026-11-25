#!/bin/sh
# Install the pinned cdxgen (CBOM scanner) for OpenTrace live scans (I5).
# Usage: tools/live/install_cdxgen.sh <target-dir>      (then export OPENTRACE_CDXGEN_DIR=<target-dir>)
# Lifecycle scripts are disabled and the exact tree is fixed by package-lock.json (integrity-checked).
# This installs a SCANNER; it never installs or runs anything from a scanned repository.
set -eu
target="${1:?target directory required}"
here="$(cd "$(dirname "$0")" && pwd)/cdxgen"
mkdir -p "$target"
cp "$here/package.json" "$here/package-lock.json" "$target/"
cd "$target"
npm ci --ignore-scripts --no-audit --no-fund
node -e 'const v=require("./node_modules/@cyclonedx/cdxgen/package.json").version; if(v!=="12.9.0"){console.error("unexpected cdxgen "+v);process.exit(1)}; console.log("cdxgen "+v+" installed in "+process.cwd())'
