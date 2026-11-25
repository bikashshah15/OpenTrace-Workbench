// UIP-03: pure model for the one-click Scan. No DOM, no fetch. The transport is `opentrace.scan_job_response/1`
// ({schema, status, result}); `status` is the frozen `opentrace.workbench.scan_status/1`. Nothing here invents progress:
// every state shown is a state the server reported, and there is no percentage anywhere.
import { disclosureVariant } from '../components/disclosure.js';

export const SCAN_SCHEMA = 'opentrace.scan_job_response/1';
export const STATUS_SCHEMA = 'opentrace.workbench.scan_status/1';
// Must equal the server's fixed note (scan_jobs.WARNING_SHARED_PHASE): the explicit marker of the shared worker phase.
export const SHARED_PHASE_NOTE = 'SBOM and CBOM are produced in one isolated worker phase; per-scanner progress is not available.';
export const TERMINAL_JOB = ['completed', 'partial', 'failed', 'cancelled'];

export const STAGE_LABEL = {
  resolve_revision: 'Resolve and pin the revision', acquire_source: 'Download and verify the commit', sbom: 'SBOM · Syft', cbom: 'CBOM · cdxgen',
  aibom: 'AI inventory', advisory_lookup: 'Advisory lookup', source_checks: 'Source-backed checks', evidence_projection: 'Prepare evidence', workbench_ready: 'Open the Workbench',
};
export const STATE_LABEL = {
  queued: 'Waiting', running: 'Running', completed: 'Done', completed_empty: 'Done · no applicable assets', partial: 'Partial', not_run: 'Not run',
  unsupported: 'Not supported', failed: 'Failed', cancelled: 'Cancelled',
};
export const STATE_MARK = { queued: '○', running: '◐', completed: '✓', completed_empty: '✓', partial: '!', not_run: '–', unsupported: '–', failed: '✕', cancelled: '–' };

// Frozen reason vocabulary -> what happened and a usable next step (fixed text; never tool output).
export const REASON = {
  disabled: ['This step is not enabled on this service.', ''],
  not_configured: ['This step is not configured.', ''],
  upstream_failed: ['An earlier step did not complete.', ''],
  unsupported_ecosystem: ['This repository uses an ecosystem this step does not support.', 'The other inventories are unaffected.'],
  invalid_revision: ['The requested revision could not be used.', 'Check the branch, tag or commit and scan again.'],
  policy_refused: ['This repository or commit is not admitted for live scanning.', 'Try a repository on the pilot list, or explore the sample findings.'],
  rate_limited: ['The revision lookup hit its request limit.', 'Try a simpler repository link, or wait and scan again.'],
  scanner_unavailable: ['The service could not run this step.', 'Try again later, or explore the sample findings.'],
  scanner_failed: ['A scanner did not produce a usable result.', 'Scan again. If it keeps failing, End session and try a different revision.'],
  timeout: ['This step took longer than its limit.', 'Scan again, or try a smaller repository.'],
  output_invalid: ['The result did not pass validation, so it is not shown.', 'Scan again. No result was published.'],
  cleanup_unverified: ['Cleanup could not be confirmed, so no result is shown.', 'End session; the service keeps scanning blocked until cleanup is verified.'],
  partial_coverage: ['The result covers only part of what was requested.', ''],
  no_applicable_assets: ['The scan completed and found no applicable assets.', ''],
  cancelled_by_user: ['You cancelled this scan.', 'Scan again when ready.'],
  session_ended: ['The session ended during the scan.', 'Start a new scan.'],
};
export const REFUSAL = {
  live_disabled: 'Live scanning is not enabled on this service.',
  scan_in_progress: 'A scan is already in progress in this session.',
  scanner_busy: 'Another scan is running or still being cleaned up. Try again when it finishes.',
  scan_unavailable: 'The scan could not be started. Nothing was changed; try again.',
  stale_generation: 'This page is out of date. Start the scan again.',
};

export const freshScan = () => ({ job: null, generation: null, epoch: null, lastSeq: -1, status: null, result: null, error: null, errorKind: null });

// A job is finished only when its state is terminal AND cleanup is known: the frozen derivation makes the state `failed`/`cancelled` the moment one
// stage does, while the pipeline may still be stopping (cleanup.state === 'pending'). Polling and the Cancel control follow this rule.
export function isTerminal(status) { return !!status && TERMINAL_JOB.includes(status.job.state) && status.cleanup.state !== 'pending'; }

// Is the response a well-formed envelope? (structure only; the server validates the frozen schema)
export function wellFormed(env) {
  return !!env && env.schema === SCAN_SCHEMA && env.status && env.status.schema === STATUS_SCHEMA && Array.isArray(env.status.stages)
    && env.status.stages.length === 9 && 'result' in env;
}

// Monotonic acceptance: only the same job, the same generation, never an older seq. Returns the new scan state or the old one.
export function applyEnvelope(scan, env, epoch) {
  if (scan.epoch !== epoch || !wellFormed(env)) return scan;
  const st = env.status;
  if (scan.job && st.job.job_id !== scan.job) return scan;
  if (scan.generation !== null && scan.job && st.generation !== scan.generation) return scan;
  if (st.job.seq < scan.lastSeq) return scan;          // an older poll never overwrites newer status
  return { ...scan, job: st.job.job_id, generation: st.generation, lastSeq: st.job.seq, status: st, result: env.result || scan.result, error: null, errorKind: null };
}

// Status updates stopped while the job was still reported as unfinished: what is shown is the LAST status received, not a fresh claim, and the
// service may still be working. (`errorKind`: 'transient' = a retry may help; 'lost' = the service no longer knows this job for this page.)
export function isStale(scan) { return !!scan && !!scan.error && !!scan.status && !isTerminal(scan.status); }
export const POLL_RETRY_DELAYS = [2000, 4000, 8000];   // bounded automatic retries of a failed status read before the user is told

// Scan may start only when the raw configuration says live scanning is available and nothing else is happening.
export function scanGate(s) {
  const cfg = s.config || { state: 'unknown', live: null };
  if (cfg.state === 'unknown') return { enabled: false, reason: 'Loading the service configuration…', variant: null };
  if (cfg.state === 'failed') return { enabled: false, reason: 'Scan is unavailable: the service configuration could not be loaded.', variant: null };
  const variant = disclosureVariant(cfg.live);
  if (variant !== 'A' && variant !== 'B') return { enabled: false, reason: variant === 'C' ? 'Scanning is unavailable on this service right now.' : 'Live scanning is not enabled on this service.', variant };
  if (s.busy) return { enabled: false, reason: s.busy === 'ending' ? 'Ending the session…' : 'A scan is in progress.', variant };
  if (s.scan && s.scan.status && !isTerminal(s.scan.status)) return { enabled: false, reason: 'A scan is in progress.', variant };
  return { enabled: true, reason: '', variant };
}

// The rows the normal panel shows. Unconfigured optional stages are omitted (never implied to have run); a failing or partial one is shown.
// While the worker backend runs both scanners in one job the two slots carry the shared-phase note: they collapse into ONE row.
export function visibleStages(status) {
  if (!status) return [];
  const by = Object.fromEntries(status.stages.map((x) => [x.stage_id, x]));
  const shared = by.sbom.state === 'running' && by.cbom.state === 'running'
    && by.sbom.warnings.includes(SHARED_PHASE_NOTE) && by.cbom.warnings.includes(SHARED_PHASE_NOTE);
  const rows = [];
  for (const st of status.stages) {
    const hiddenOptional = st.state === 'not_run' && (st.reason_code === 'disabled' || st.reason_code === 'not_configured');
    if (hiddenOptional) continue;
    if (shared && st.stage_id === 'cbom') continue;
    if (shared && st.stage_id === 'sbom') {
      rows.push({ id: 'scanners', label: 'Scanners · SBOM and CBOM', state: 'running', reason: null, note: SHARED_PHASE_NOTE, outputs: [] });
      continue;
    }
    const notes = st.warnings.filter((w) => w !== SHARED_PHASE_NOTE);
    if (st.stage_id === 'aibom' && st.state === 'running') notes.push('Cisco AI-BOM can take several minutes. You can minimize this window while the scan continues.');
    rows.push({ id: st.stage_id, label: STAGE_LABEL[st.stage_id], state: st.state, reason: st.reason_code, note: notes.join(' '), outputs: st.outputs });
  }
  return rows;
}

export function elapsedText(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

// One headline for the panel from the job state; the specific reason and next step come from the failing/cancelled stage.
export function outcome(status) {
  if (!status) return null;
  const state = status.job.state;
  if (TERMINAL_JOB.includes(state) && status.cleanup.state === 'pending') return { kind: 'working', text: 'Stopping and confirming cleanup…' };
  if (state === 'queued') return { kind: 'working', text: 'Waiting to start…' };
  if (state === 'running') return { kind: 'working', text: 'Scanning… The total amount of work is not known in advance.' };
  if (state === 'completed') return { kind: 'ok', text: 'Scan complete. Opening the Workbench…' };
  if (state === 'partial') return { kind: 'ok', text: 'Scan complete with partial results. Opening the Workbench…' };
  const stage = status.stages.find((x) => x.state === 'failed' || x.state === 'cancelled');
  const [what, next] = stage && REASON[stage.reason_code] ? REASON[stage.reason_code] : ['The scan did not complete.', 'Scan again.'];
  const note = stage ? stage.warnings.filter((w) => w !== SHARED_PHASE_NOTE).join(' ') : '';
  // A failed job names the failed stage and the blocked hand-off in fixed words (Stage 4: UIP-D19 stays as decided — any failed stage fails the job and the
  // Workbench is not opened). Stages that completed, including later ones, never mean the overall scan succeeded. `what` is a fixed reason text, never tool output.
  const failedStage = state === 'failed' && stage && stage.state === 'failed' ? STAGE_LABEL[stage.stage_id] : null;
  const named = failedStage ? `${failedStage} failed, so the Workbench was not opened.` : '';
  const caveat = failedStage ? 'Steps that finished do not mean the scan succeeded.' : '';
  return { kind: state === 'cancelled' ? 'cancelled' : 'failed', text: [state === 'cancelled' ? 'Scan cancelled.' : 'Scan did not complete.', named, what, note, caveat].filter(Boolean).join(' '), next };
}
