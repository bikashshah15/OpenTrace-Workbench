"""Compatibility entrypoint for the adapter's pure deterministic display data.

Lineage: the projection code adapts CycloneDX components, metadata.component,
properties, occurrences and dependencies directly from the frozen I4C contract
and its raw Frigate oracle. It does not import donor preview_model.py helpers:
those helpers read _ROOT, normalize paths against a developer checkout, and
contain fixed Frigate/cdxgen labels. No donor display helper is reused here.
"""
from opentrace_core.bombridge_adapter.projection import project

__all__ = ["project"]
