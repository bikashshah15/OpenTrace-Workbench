# E1 example evidence trails - frigate-recorded

Repository `https://github.com/blakeblackshear/frigate` at `3bca9b8676846d175f6b9f53f5818cbb9d36ec3e` (provenance: captured). One seeded example per available family, taken from the audit sample. These are trails to inspect, not verified conclusions.

## software

- Record: `cand:missing_component:0ff56a96` (candidate) - scipy (wildcard_pin) declared at docker/main/requirements-wheels.txt:43 has no record in inv:syft-source-dir
- Location: `docker/main/requirements-wheels.txt:43`
- State: **contradicted** (rule `inventory_coverage.requirement_represented/1`)
- Reason codes: not_represented_in_fully_parsed_inventory
- Rationale (tool): Contradicted: the declared requirement has no component of that name in the fully parsed inventory, which lists the same requirements file. No coverage contract is established that this inventory should include this declaration form, so this is an inventory discrepancy (coverage gap), not a completeness defect or vulnerability.
- Bounded meaning (tool): Whether this parsed inventory contains a component with the declared package name, where the inventory's recorded digest of the requirements file matches that file at the stated revision. The digest binds that one file to the revision; it does not show that other components of the inventory describe the revision. Not a statement about completeness, use, installation or runtime.
  - record `dev-decl-132e1a3e-scipy` (requirement_declaration, role declaration, relation context, reason requirement_declared): `docker/main/requirements-wheels.txt` lines None
  - record `dev-look-inv-syft-source--62746ca2-scipy` (inventory_name_lookup, role inventory, relation contradicts, reason not_represented_in_fully_parsed_inventory)
- Next action (tool): establish whether the generator is expected to represent the wildcard_pin form (coverage contract), or add an inventory that does

## cryptography

- Record: `cand:unknown_coverage:0dfaa078` (candidate) - sha256 call at frigate/api/auth.py:433: observed, not compared (operation_class_not_assessed)
- Location: `frigate/api/auth.py:433`
- State: **unknown_coverage**
- Reason codes: operation_class_not_assessed
  - record `dev-call4-2bf0abe7-sha256` (source_excerpt, role cited, relation None, reason None): `frigate/api/auth.py` lines [433, 435]
    ```
        pw_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
        )
    ```
- Next action (tool): see the reason; nothing is concluded about this call

## ai_model

- Record: `cand:unknown_coverage:19ed7365` (candidate) - mobilenetv2-7.onnx: referenced at testing-scripts/object_dataset.py:105 (2 occurrences), compared with inv:cisco-aibom
- Location: `testing-scripts/object_dataset.py:105`
- State: **unverifiable** (rule `model_identity.declared_in_aibom/1`)
- Reason codes: no_matching_model_record
- Rationale (tool): Unverifiable: no model record shares the locator or a name; absence is not a contradiction (no coverage contract).
- Bounded meaning (tool): An AI-BOM document whose recorded acquisition binding (not merely its declared revision) equals the stated revision lists a model with the same acquisition locator that the source reference states. Declaration-level agreement only: not artifact identity, digest verification, independent verification, or evidence that the model is loaded.
  - record `dev-model-7cc12b4e3ba8334d` (source_excerpt, role source_reference, relation context, reason locator_stated_in_source): `testing-scripts/object_dataset.py` lines [105, 105]
    ```
          https://github.com/onnx/models/raw/main/validated/vision/classification/mobilenet/model/mobilenetv2-7.onnx
    ```
  - record `dev-model-de0f60599542b6aa` (source_excerpt, role source_reference, relation context, reason locator_stated_in_source): `testing-scripts/object_dataset.py` lines [921, 925]
    ```
                "Path to ONNX MobileNetV2 file for model-independent embeddings "
                "(required by --confuses). Download once with: curl -L -o "
                "/config/model_cache/mobilenetv2-7.onnx https://github.com/onnx/"
                "models/raw/main/validated/vision/classification/mobilenet/model/"
                "mobilenetv2-7.onnx"
    ```
  - record `ev-live-aibom-719ba25fe34d` (aibom_document, role aibom_document, relation inconclusive, reason no_matching_model_record)
- Next action (tool): an absent declaration is not a defect: no coverage contract says the AI-BOM producer reports every model reference in source
