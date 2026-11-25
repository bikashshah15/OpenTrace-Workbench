"""First-party binding and view-data adapter around the unchanged BOMBridge engine."""
from .bundle import assemble
from .gaps import project_gap, project_gaps
from .projection import project
from .runner import assess
from .types import (AdapterContext, AdapterError, AdapterResult, ArtifactRecord,
                    BoundAssessment, ProjectionRequest, TypedError, ViewModels)
from .validation import validate_result

__all__ = ["AdapterContext", "AdapterError", "AdapterResult", "ArtifactRecord", "BoundAssessment",
           "ProjectionRequest", "TypedError", "ViewModels", "assemble", "assess", "project", "project_gap", "project_gaps", "validate_result"]
