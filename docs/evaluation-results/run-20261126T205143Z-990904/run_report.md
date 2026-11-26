# Evaluation run report

Run directory: `run-20261126T205143Z-990904`

## What ran

- **preflight**: not requested / not run
- **E1**: completed
- **E2**: completed
- **E3**: completed
- **E3-B**: completed
- **E3-C**: completed
- **E4**: completed
- **E5**: completed

## Environment

- Python: 3.14.7
- OS: macOS-26.6.2-arm64-arm-64bit-Mach-O
- CPU: Apple M4 (10 logical)
- RAM: 24.0 GiB

## Output files

- `e1/`: all_findings.jsonl, audit_strata.csv, case_examples.md, documented_reference_check.csv, e1_status.json, evidence_traceability.csv, evidence_traceability_checks.jsonl, findings_by_domain.csv, manual_audit.csv, repository_statistics.csv
- `e2_e3/`: FROZEN.json, baseline_comparison.csv, baseline_definitions.md, benchmark_cases.jsonl, collector_metrics.csv, discovery_coverage.csv, discovery_coverage_summary.csv, document_validation.csv, domain_metrics.csv, domain_metrics.json, excluded_cases.csv, expected_properties.jsonl, external_tool_runs.jsonl, individual_results.csv, original_vs_derived.csv, paired_results.csv, property_satisfaction.csv, scoring_policy.json, selection_manifest.json
- `e3b/`: capability_comparison.csv, document_validation.csv, external_tool_runs.jsonl, limitations.md, paper_table_e3b.md, plan.json, semantic_diff_results.csv, task_summary.csv, tool_versions.json
- `e3c/`: acquisition_manifest.json, claim_assessments.jsonl, domain_summary.csv, excluded_reference_items.csv, limitations.md, manual_audit.csv, paper_table_e3c.md, per_item_comparison.csv, raw_inventory_lookup.csv, reference_selection.json, scanner_runs.jsonl, source_collection.csv
- `e4/`: capability_states.jsonl, fault_injection_results.csv, integration_summary.md, investigation_capabilities.csv, reference_preconditions.json, task_results.jsonl, unaffected_retention.csv, unexpected_findings.csv
- `e5/`: environment.json, graph_sizes.csv, measurement_protocol.json, memory_summary.csv, process_rusage.json, replay_consistency.csv, replay_consistency_summary.json, replay_mismatch_details_frigate-recorded.jsonl, replay_reference_frigate-recorded.json, runtime_runs.csv, runtime_summary.csv, scanner_context.csv
- `paper_tables/`: table1_e1.csv, table1_e1.md, table2_e2_e3.csv, table2_e2_e3.md, table3_e4_e5.csv, table3_e4_e5.md

Every number in `paper_tables/` is read from these files; nothing is typed in by hand.
