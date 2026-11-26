## Table 3 - E4/E5 systems results

| Metric | Result |
|---|---|
| Capability illustration, Q4-Q6 outcomes for OpenTrace (not an accuracy score; other configurations lack these queries by design) | answered_correctly=4, correctly_unresolved=2 |
| References valid (findings in every family); construction facts agreeing | composite-a: valid=True, facts 11/11; composite-b: valid=True, facts 9/9 |
| Unaffected finding retention, all isolated failures pooled (n/N) | 104/104 |
| Retention by condition | R1@composite-a: 6/6, R2@composite-a: 7/7, R3@composite-a: 9/9, R4-software@composite-a: 6/6, R4-crypto@composite-a: 7/7, R4-models@composite-a: 9/9, R5-once@composite-a: 9/9, R5-twice@composite-a: 5/5, R1@composite-b: 6/6, R2@composite-b: 5/5, R3@composite-b: 7/7, R4-software@composite-b: 6/6, R4-crypto@composite-b: 5/5, R4-models@composite-b: 7/7, R5-once@composite-b: 7/7, R5-twice@composite-b: 3/3 |
| Changed or lost unaffected findings / unexpected new records in unaffected families | 0 / 0 |
| Fail-closed and lifecycle safety expectations met | 4/4 |
| Correct failure-state classification | 16/16 |
| Verification latency, engine run_doc (median, IQR, n) | 10.7 ms, IQR 0.3 ms, n=5, failed=0 |
| Verification latency, integrated worker (median, IQR, n) | 251.6 ms, IQR 35.2 ms, n=5, failed=0 |
| Offline replay latency (median, IQR, n) | 912.9 ms, IQR 49.6 ms, n=5, failed=0 |
| Peak memory (process tree RSS, sampled) | 279.7 MiB (psutil sampling every 5.0 ms; MiB = 2^20 bytes) |
| Canonical replay equality (successful repeats equal to reference / successful repeats) | frigate-recorded: 5/5 equal, 0 mismatched (successful 5/5 attempted) |

Retention compares unaffected-family findings with a controlled reference; it does not establish their correctness. Latencies are absolute local measurements (no overhead ratio against historical scanner times). Replay consistency is not scanner or LLM determinism.
