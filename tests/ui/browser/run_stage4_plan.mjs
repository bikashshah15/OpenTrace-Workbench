// Stage 4 launch/coverage plan as DATA (test harness only). Imported by the driver and checked offline by run_stage4_selftest.mjs:
// every DA row must be covered by a phase or explicitly declared unexercised with a reason; launches must fit the ceilings.
// Nothing here launches anything.
export const DA_ROWS = Array.from({ length: 21 }, (_, i) => 'DA-' + String(i + 1).padStart(2, '0'));

// One headed hermetic Chrome (C1) for the whole run; browser CONTEXTS isolate cases. C2 is reserved for the single harness-correction rerun.
export const LAUNCHES = [
  { id: 'C1', kind: 'chrome', phases: ['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7', 'P8'], note: 'shared headed Chrome; isolation by browser context per case' },
  { id: 'S1', kind: 'service', cmd: 'python -m opentrace_core.app (offline Demo, OPENTRACE_LIVE_*=0)', phases: ['P1', 'P2'] },
  { id: 'S2', kind: 'service', cmd: 'tests/ui/browser/live_service.py', phases: ['P3'] },
  { id: 'S3', kind: 'service', cmd: 'tests/ui/browser/live_service.py --cbom-sleep 25', phases: ['P4'] },
  { id: 'S4', kind: 'service', cmd: 'tests/ui/browser/uip12_crypto_service.py --case matrix', phases: ['P5'] },
  { id: 'S5', kind: 'service', cmd: 'tests/ui/browser/uip13_model_service.py --case matrix', phases: ['P6'] },
  { id: 'S6', kind: 'service', cmd: 'tests/ui/browser/uip12_crypto_service.py --case states', phases: ['P7'] },
  { id: 'S7', kind: 'service', cmd: 'tests/ui/browser/uip13_followup_service.py', phases: ['P8'] },
  { id: 'S8', kind: 'service', cmd: 'RESERVED: the single harness-correction rerun (counts inside the totals; no other use)', phases: [], reserved: true },
  { id: 'C2', kind: 'chrome', cmd: 'RESERVED: paired with S8 for the rerun only', phases: [], reserved: true },
];

// Evidence modes per phase: real-server = real backend projections in this run; fixture-substituted = frontend responses from contract JSON (NOT backend evidence).
export const PHASES = {
  P1: { service: 'S1', mode: 'real-server', title: 'Offline Demo on the real server', rows: ['DA-01', 'DA-04', 'DA-05', 'DA-06', 'DA-07', 'DA-08', 'DA-09', 'DA-10', 'DA-11', 'DA-13', 'DA-14', 'DA-15', 'DA-16', 'DA-17', 'DA-19'] },
  P2: { service: 'S1', mode: 'fixture-substituted', title: 'Contract fixtures through the real frontend (Fetch fulfilment; not backend evidence)', rows: ['DA-05', 'DA-06', 'DA-07', 'DA-08', 'DA-17', 'DA-21'] },
  P3: { service: 'S2', mode: 'real-server', title: 'One-click Scan on local fixture repos with fake scanners (1366 only)', rows: ['DA-01', 'DA-02', 'DA-03', 'DA-16'] },
  P4: { service: 'S3', mode: 'real-server', title: 'Slow CBOM: running panel, Cancel, End session during a scan', rows: ['DA-02', 'DA-16'] },
  P5: { service: 'S4', mode: 'real-server', title: 'Typed crypto correspondence matrix (synthetic repos, real projections)', rows: ['DA-07', 'DA-10', 'DA-12', 'DA-17'] },
  P6: { service: 'S5', mode: 'real-server', title: 'Typed model correspondence matrix (synthetic repos, real projections)', rows: ['DA-08', 'DA-10', 'DA-12', 'DA-17'] },
  P7: { service: 'S6', mode: 'real-server', title: 'Typed crypto states: partial / empty / no source / unsupported / failed', rows: ['DA-07', 'DA-10', 'DA-12'] },
  P8: { service: 'S7', mode: 'real-server', title: 'BOM inline graph: real clicks, camera, repaint, window resize (retained PR #76 failures re-measured)', rows: ['DA-10', 'DA-11', 'DA-19'] },
};

// Declared limits, written before any runtime. A row listed here is NOT claimed by any phase for the stated criteria.
export const UNEXERCISED = [
  { row: 'DA-18', reason: 'Assistant interface is Codex\'s (PR #75, unaccepted). Contingent on its final interface; accepted Codex evidence is reused only with matching source identity. No provider call; if no deterministic non-egressing fake exists the row stays "not yet exercised". No extra service/Chrome is reserved for it.' },
  { row: 'DA-02', reason: 'scan-status matrix states (queued/resolving/acquiring/sbom-running, partial, unsupported) beyond what P3/P4 reach are not exercised in a browser: run_scan_poll_checks / scan_states.mjs are not in any launch.' },
  { row: 'DA-12', reason: 'conflicting_evidence, no_rule and the R2-03 whole-comparison-unavailable state are not launched: uip13 `states`/`norun` and uip12 `interact` cases would each need another service (ceiling 8 reached).' },
  { row: 'DA-08', reason: 'uip13 `states`/`norun` (AI typed states on real projections) are not launched; AI typed states are observed only through contract fixtures (frontend-substituted) in P2 and the uip13 matrix in P6.' },
  { row: 'DA-15', reason: 'keyboard coverage is bounded to tab arrows, Enter/Space/Escape on observed controls, focus visibility, named zoom controls and live regions; no exhaustive screen-reader test.' },
  { row: 'DA-20', reason: 'offline regression and baseline comparison are P0 (no launch) and are not part of this driver.' },
  { row: 'DA-09', reason: 'queue paging (25/50) is exercised only through the Full graph pager; the queue pager selector is not confirmed in this driver.' },
  { row: 'DA-13', reason: 'source-backed check (I5C) and artifact-hash download equality are not driven; only evidence-detail presence and hash text are observed.' },
];

export const COUNTS = () => ({
  service: LAUNCHES.filter((l) => l.kind === 'service').length,
  chrome: LAUNCHES.filter((l) => l.kind === 'chrome').length,
  reservedRerun: LAUNCHES.filter((l) => l.reserved).length,
});
