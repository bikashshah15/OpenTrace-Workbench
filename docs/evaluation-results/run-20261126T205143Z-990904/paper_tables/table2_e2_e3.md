## Table 2 - E2/E3 controlled verification (Track B, fixed claims, identical inputs)

| Method | PSR n/N | CRR n/N | UCR n/N | Correct uncertainty n/N | Errors | Original anchors resolved n/N | Derived decidable resolved n/N |
|---|---|---|---|---|---|---|---|
| Name matching | 30/125 (0.240) | 46/46 (1.000) | 95/95 (1.000) | 0/95 (0.000) | 0 | 16/16 (1.000) | 30/30 (1.000) |
| Strong identity matching | 73/125 (0.584) | 46/46 (1.000) | 52/95 (0.547) | 43/95 (0.453) | 0 | 16/16 (1.000) | 30/30 (1.000) |
| OpenTrace | 125/125 (1.000) | 46/46 (1.000) | 0/95 (0.000) | 95/95 (1.000) | 0 | 16/16 (1.000) | 30/30 (1.000) |

Distinct anchors: 16 (original cases 16, derived 125). Derived cases of one anchor are related tests, not independent samples. Baselines are in-house controlled implementations. BOM documents are controlled; source anchors are external_reference/captured. CRR in the table pools originals and decidable derived cases. AI anchors taken from a recorded capture were found by OpenTrace's own collector.

**Document-level validation (separate task).** Schema-valid controlled documents: 141/141; structural negative controls rejected by the schema: 9/9; CycloneDX CLI runs completed: 150/150.
