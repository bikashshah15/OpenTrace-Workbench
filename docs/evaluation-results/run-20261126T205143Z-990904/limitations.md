# Limitations (generated with the run; edit only to add, never to remove)

- E1 is descriptive. Recorded counts are what the tools and collectors reported, not ground truth; the AI-BOM capture is degraded. A manual
  audit sample is a check of selected findings, not an estimate of project-wide precision or recall.
- E2/E3 evaluate bounded, source-level declaration/correspondence claims on externally anchored but CONTROLLED BOM documents. They do not
  measure deployed-component completeness, vulnerability, runtime behaviour, model loading, version correctness or functional
  software-model-crypto dependencies. Derived cases of one anchor are correlated; no significance claim is made.
- B1/B2 are in-house baselines written for this evaluation; document validators (CycloneDX CLI, JSON schema) perform a different task and are
  reported separately.
- The CBOM resolution records of Track B are controlled (their facts are established by an AST parse of the source, not by OpenTrace's collector);
  Track A/C use the real collector and generators instead.
- E4 composite references are assembled for the experiment from external anchors; they are not real IoT products. Retention measures relative
  stability under isolated faults, not the correctness of the reference findings.
- E5 latencies are local, absolute measurements; memory is a sampled RSS estimate. Replay consistency demonstrates deterministic reconstruction
  from saved evidence only.
