"""The shared ``binding`` object of the Workbench view contracts (UIP-01B ``common.schema.json#/$defs/binding``).

``build_binding(analysis)`` derives it from the active analysis' sealed identity (``analysis_identity/1``) and the existing
sealed assessment. No new digest algorithm exists here: every value is read from the analysis. The repository name and URL
therefore come from the analysis; no repository name is written in this module.

Assessment selection (reused by later routes): the discovery assessment (I8) when the analysis compared one, else the
legacy assessment, else ``None``. A sealed assessment without a validation digest is not bound (``None``), never invented.
"""

_HEX64 = frozenset("0123456789abcdef")


def _assessment_block(analysis):
    gaps = getattr(analysis, "gaps", None)
    if isinstance(gaps, dict) and gaps.get("status") == "compared" and gaps.get("assessment") is not None:
        sealed, kind = gaps["assessment"], "discovery"
    elif getattr(analysis, "assessment", None) is not None:
        sealed, kind = analysis.assessment, "legacy"
    else:
        return None
    digest = getattr(sealed, "validation_digest", None)
    binding = getattr(sealed, "binding", None) or {}
    bundle, configuration = binding.get("bundle_sha256"), binding.get("configuration")
    if not (isinstance(digest, str) and len(digest) == 64 and set(digest) <= _HEX64 and isinstance(bundle, str)
            and isinstance(configuration, str) and configuration):
        return None
    return {"kind": kind, "schema": sealed.schema, "validation_digest": digest, "bundle_sha256": bundle,
            "configuration": configuration}


def build_binding(analysis):
    ident = analysis.identity
    repo = ident["repository"]
    requested = ident["requested"]
    return {"analysis_digest": ident["analysis_digest"],
            "repository": {"host": repo["host"], "owner": repo["owner"], "name": repo["name"], "canonical_url": repo["canonical_url"]},
            "commit_sha": ident["resolved"]["commit_sha"],
            "requested_ref": {"kind": requested["kind"], "text": requested["text"]},
            "generation": analysis.ticket.generation,
            "mode": analysis.mode,
            "assessment": _assessment_block(analysis)}
