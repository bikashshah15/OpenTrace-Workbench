# Third-party notices for the AI-BOM worker image (UIP-07C)

Scope (owner decisions D3/D5, 2026-11-14, FD-C17): this image is built and used locally by an operator. It is **not published** and its wheels
are **not redistributed**. Every dependency is installed **unmodified** from the hash-locked wheel (`requirements.lock`), so each package's own
licence, copyright and NOTICE files stay in its `*.dist-info` directory inside `/opt/venv`. Nothing here is legal clearance and nothing grants
a distribution right.

* `cisco-aibom` 1.10.1 — Apache-2.0 (Cisco). Pinned by tag commit `93ea541da490cc81394efa536fec9ab4de5c3e1e`; the knowledge base
  `aibom_catalog-1.10.1.duckdb` (sha256 `b1165384a646094aa6a4762d676f285c1c68b6d7f9367c90a129b529904a3268`) is a release asset of the same tag.
* MPL-2.0 components (`certifi`, `pathspec`, `orjson` (MPL-2.0 AND (Apache-2.0 OR MIT)), `fqdn`) are used unmodified.
* `packageurl-python` 0.17.6 — MIT; condition C1: the upstream MIT text is in `packageurl-python/LICENSE.mit` (source and digest in `SOURCE.txt`).
* **R1 (owner scope decision D5, not legal clearance):** the hash-locked `numpy` 2.5.4 aarch64 wheel
  (`numpy-2.5.4-cp313-cp313-manylinux_2_27_aarch64.manylinux_2_28_aarch64.whl`) bundles `libgfortran` (GPL-3.0-or-later WITH GCC-exception-3.1)
  and a `libquadmath` notice (LGPL-2.1-or-later). Local, unmodified, non-distributed use of that exact wheel only; the licence, exception,
  copyright and NOTICE texts remain in the wheel's dist-info and bundled-notice files. No general GPL/LGPL exception, no substitution or
  upgrade of this wheel, no image or wheel distribution.

The full licence evidence is in a private planning record (not in this export) and its JSON inventory.
