"""Public records for the first-party BOMBridge adapter boundary."""
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass(frozen=True)
class TypedError:
    code: str
    path: str
    detail: str

    def as_dict(self):
        return {"code": self.code, "path": self.path, "detail": self.detail}


class AdapterError(ValueError):
    def __init__(self, errors):
        self.errors = sorted(errors, key=lambda e: (e.path, e.code, e.detail))
        super().__init__("; ".join("{} {}: {}".format(e.code, e.path, e.detail) for e in self.errors))


@dataclass(frozen=True)
class AdapterContext:
    identity: dict
    expected_session: dict
    expected_configuration: Optional[str]
    current_session: Callable[[], Optional[dict]]


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_id: str
    inventory_id: str
    kind: str
    state: str
    sha256: Optional[str] = None
    record_count: Optional[int] = None
    record_count_unit: Optional[str] = None
    record_counts: Optional[dict] = None
    analysis_digest: Optional[str] = None
    session_id: Optional[str] = None
    generation: Optional[int] = None
    acquisition_manifest: Optional[dict] = None
    limitations: tuple = field(default_factory=tuple)

    def as_dict(self):
        out = {"artifact_id": self.artifact_id, "inventory_id": self.inventory_id,
               "kind": self.kind, "state": self.state, "sha256": self.sha256,
               "record_count": self.record_count, "record_count_unit": self.record_count_unit,
               "record_counts": self.record_counts, "analysis_digest": self.analysis_digest,
               "session_id": self.session_id, "generation": self.generation,
               "acquisition_manifest": self.acquisition_manifest,
               "limitations": list(self.limitations)}
        return out


@dataclass
class AdapterResult:
    status: str
    assessment: Optional[dict] = None
    errors: list = field(default_factory=list)


@dataclass(frozen=True)
class BoundAssessment:
    schema: str
    binding: dict
    result: dict
    validation_digest: Optional[str] = None
    source_bundle: Optional[dict] = None

    def as_dict(self):
        return {"schema": self.schema, "binding": dict(self.binding), "result": self.result,
                "validation_digest": self.validation_digest,
                "source_bundle": self.source_bundle}


@dataclass(frozen=True)
class ProjectionRequest:
    tab: str
    selected_id: Optional[str] = None
    context_path: Optional[str] = None
    per_side: int = 6
    incoming_offset: int = 0
    outgoing_offset: int = 0


@dataclass
class ViewModels:
    binding: dict
    tabs: list
    inventory_cards: list
    checks: list
    supporting_records: list
    inspectors: list
    limitations: list

    def as_dict(self):
        return {"binding": self.binding, "tabs": self.tabs, "inventory_cards": self.inventory_cards,
                "checks": self.checks, "supporting_records": self.supporting_records,
                "inspectors": self.inspectors, "limitations": self.limitations}
