"""I3 cohort derivations (pure, deterministic, standard library only; Python 3.10+).

policy      manifest selection and path validation (shared by the acquisition tool and the planner)
identity    ecosystem/name/version normalization and OSV query keys
severity    severity band of an OSV record (label, CVSS v3.1 base score)
families    alias families over fetched OSV records
tables      typed occurrence/hosted table readers (V12) and digest-checked loading
findings    shared findings, unresolved items, coverage denominators
reconcile   hosted-versus-pinned reconciliation (never a binding)
ranking     the two deterministic rankers over one frozen projection
"""
