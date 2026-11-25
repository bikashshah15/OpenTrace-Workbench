"""Pure assembly of caller-supplied normalized records into a donor bundle."""
import copy
from .types import AdapterError, TypedError
from .validation import check_context, prevalidate_bundle, validate_artifacts


def assemble(context, *, capture, entities, observations, assertions, input_checks,
             origin, notice, artifacts, read_artifact, discovery=None):
    errors = check_context(context)
    if not isinstance(capture, dict):
        errors.append(TypedError("invalid_bundle", "capture", "expected_object"))
    if not all(isinstance(v, list) for v in (entities, observations, assertions, input_checks)):
        errors.append(TypedError("invalid_bundle", "$", "record_inputs_must_be_arrays"))
    if errors:
        raise AdapterError(errors)
    evidence = copy.deepcopy(observations)
    bundle = {"schema": "bombridge.bundle/2", "capture": copy.deepcopy(capture),
              "entities": copy.deepcopy(entities), "assertions": copy.deepcopy(assertions),
              "evidence": evidence, "input_checks": copy.deepcopy(input_checks),
              "origin": origin}
    if notice is not None:
        bundle["notice"] = copy.deepcopy(notice)
    if discovery is not None:  # I8: candidate gaps the donor discovery generated from captured inputs (validated by prevalidate_bundle)
        bundle["discovery"] = copy.deepcopy(discovery)
    errors = prevalidate_bundle(bundle, context)
    if errors:
        raise AdapterError(errors)
    artifact_errors, _, _ = validate_artifacts(context, bundle, artifacts, read_artifact)
    errors.extend(artifact_errors)
    if errors:
        raise AdapterError(errors)
    return bundle
