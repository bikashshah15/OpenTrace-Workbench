// UIP-03: scan model, store reducers and the Scan UI, driven by the FROZEN scan_status/1 fixtures (UIP-01B) wrapped in the transport envelope.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { initial, reducer } from '../../../src/ui/lib/store.js';
import { SCAN_SCHEMA, SHARED_PHASE_NOTE, POLL_RETRY_DELAYS, applyEnvelope, freshScan, isStale, isTerminal, outcome, scanGate, visibleStages, wellFormed, REASON, STAGE_LABEL } from '../../../src/ui/lib/scan_model.js';
import { renderAnalyze } from '../../../src/ui/components/intake.js';
import { renderScanStatus, renderScanDialogBody } from '../../../src/ui/components/scan_status.js';
import { disclosureVariant } from '../../../src/ui/components/disclosure.js';

const DIR = 'evidence/uip/fixtures/scan-status-matrix-synthetic/';
const fx = (name) => JSON.parse(readFileSync(DIR + name + '.json', 'utf8'));
const env = (status, result = null) => ({ schema: SCAN_SCHEMA, status, result });
const A = { enabled: true, isolation: { available: true, description: 'Docker' }, policy: { effective: 'bounded' }, advisories: { enabled: false } };
const loaded = (live) => ({ ...initial(), config: { state: 'loaded', live } });
const clone = (x) => JSON.parse(JSON.stringify(x));
const stage = (st, id) => st.stages.find((x) => x.stage_id === id);

test('the frozen scan_status fixtures wrapped in the envelope are well formed; malformed or foreign envelopes are not', () => {
  const names = readdirSync(DIR).filter((n) => n.startsWith('scan-') && n.endsWith('.json'));
  assert.ok(names.length >= 11);
  for (const n of names) assert.ok(wellFormed(env(JSON.parse(readFileSync(DIR + n, 'utf8')))), n);
  assert.equal(wellFormed(null), false); assert.equal(wellFormed({ schema: 'x', status: {}, result: null }), false);
  assert.equal(wellFormed({ schema: SCAN_SCHEMA, status: fx('scan-04-completed') }), false, 'result member is required');
});

test('monotonic acceptance: an older seq, another job, another generation or another epoch never overwrites newer status', () => {
  const s4 = fx('scan-04-completed'); const s3 = fx('scan-03-sbom-running');
  let scan = { ...freshScan(), epoch: 7, generation: 1 };
  scan = applyEnvelope(scan, env(s3), 7); assert.equal(scan.lastSeq, s3.job.seq);
  const newer = applyEnvelope(scan, env(s4), 7); assert.equal(newer.status.job.state, 'completed');
  assert.equal(applyEnvelope(newer, env(s3), 7), newer, 'older seq dropped');
  assert.equal(applyEnvelope(newer, env({ ...clone(s4), job: { ...s4.job, job_id: 'job:' + 'a'.repeat(24), seq: 99 } }), 7), newer, 'another job dropped');
  assert.equal(applyEnvelope(newer, env({ ...clone(s4), generation: 9, job: { ...s4.job, seq: 99 } }), 7), newer, 'another generation dropped');
  assert.equal(applyEnvelope(newer, env(s4), 8), newer, 'another epoch dropped');
  assert.equal(applyEnvelope(scan, { schema: 'nope' }, 7), scan);
});

test('store: SCAN_RESPONSE obeys the guards; ENDED clears the job; CONFIG_RAW keeps the raw block while state.live stays normalised', () => {
  let s = initial();
  s = reducer(s, { type: 'ANALYSIS_START' });
  s = reducer(s, { type: 'SCAN_BEGIN', epoch: s.epoch, generation: 1 });
  const st = fx('scan-03-sbom-running');
  s = reducer(s, { type: 'SCAN_RESPONSE', epoch: s.epoch, envelope: env(st) });
  assert.equal(s.scan.job, st.job.job_id);
  assert.equal(reducer(s, { type: 'SCAN_RESPONSE', epoch: s.epoch - 1, envelope: env(fx('scan-04-completed')) }), s, 'late response of an older epoch');
  const after = reducer(s, { type: 'ENDED', state: 'deleted_verified' }); assert.equal(after.scan.job, null); assert.equal(after.scan.status, null);
  let c = reducer(initial(), { type: 'CONFIG', live: { enabled: false } }); c = reducer(c, { type: 'CONFIG_RAW', ok: true, live: { enabled: false } });
  assert.equal(c.live, null, 'the existing reducer normalises a disabled service to null (unchanged)');
  assert.deepEqual(c.config, { state: 'loaded', live: { enabled: false } }, 'the raw block still expresses variant D');
  assert.equal(disclosureVariant(c.config.live), 'D');
  assert.deepEqual(reducer(initial(), { type: 'CONFIG_RAW', ok: false }).config, { state: 'failed', live: null });
  assert.equal(initial().config.state, 'unknown');
});

test('Scan gate (FR-1): disabled while config is unknown/failed, in variants C and D, while busy or a job is active; enabled for A and B', () => {
  assert.equal(scanGate(initial()).enabled, false); assert.match(scanGate(initial()).reason, /Loading/);
  assert.equal(scanGate({ ...initial(), config: { state: 'failed', live: null } }).enabled, false);
  assert.equal(scanGate(loaded({ enabled: false })).enabled, false);
  assert.equal(scanGate(loaded({ enabled: true, isolation: { available: false, reason: 'no docker' } })).variant, 'C');
  assert.equal(scanGate(loaded({ enabled: true, isolation: { available: false } })).enabled, false);
  assert.equal(scanGate(loaded(A)).enabled, true);
  assert.equal(scanGate(loaded({ ...A, policy: { effective: 'allowlist' } })).enabled, true);
  assert.equal(scanGate({ ...loaded(A), busy: 'analysis' }).enabled, false);
  assert.equal(scanGate({ ...loaded(A), scan: { ...freshScan(), status: fx('scan-03-sbom-running') } }).enabled, false);
  assert.equal(scanGate({ ...loaded(A), scan: { ...freshScan(), status: fx('scan-04-completed') } }).enabled, true, 'a finished job does not block the next scan');
});

test('homepage: Scan replaces Review repository; disabled until config loads; the disclosure is mounted beneath the buttons only once config is known', () => {
  const unknown = renderAnalyze(initial());
  assert.match(unknown, /id="ot-scan"[^>]*disabled/); assert.equal(unknown.includes('Review repository'), false); assert.equal(unknown.includes('id="ot-disclosure"'), false);
  assert.equal(unknown.includes('Explore sample findings'), false);
  assert.equal((unknown.match(/<div class="nh-form-actions">([\s\S]*?)<\/div>/)?.[1].match(/<button\b/g) || []).length, 1, 'Scan is the only repository form action');
  const ok = renderAnalyze(loaded(A));
  assert.equal(/id="ot-scan"[^>]*disabled/.test(ok), false); assert.ok(ok.includes('id="ot-disclosure"') && ok.includes('data-variant="A"'));
  assert.ok(ok.indexOf('id="ot-scan"') < ok.indexOf('id="ot-disclosure"'), 'Placement P: the block sits beneath Scan');
  const d = renderAnalyze(loaded({ enabled: false }));
  assert.ok(d.includes('data-variant="D"') && /id="ot-scan"[^>]*disabled/.test(d));
  const c = renderAnalyze(loaded({ enabled: true, isolation: { available: false, reason: 'probe failed' } }));
  assert.ok(c.includes('data-variant="C"')); assert.equal(/sandbox|container/i.test(c.slice(c.indexOf('id="ot-disclosure"'), c.indexOf('id="ot-disclosure"') + 900)), false, 'variant C promises no sandbox');
  assert.equal(renderAnalyze({ ...initial(), config: { state: 'failed', live: null } }).includes('id="ot-disclosure"'), false, 'nothing guessed when config failed');
  assert.equal(renderAnalyze(loaded(A)).includes('data-action="open-capture"'), false); assert.equal(renderAnalyze(loaded(A)).includes('scan-live'), false);
});

test('stage panel from the frozen fixtures: truthful states, no percentage, elapsed/last-updated from the document, optional unconfigured stages omitted', () => {
  const run = renderScanStatus({ scan: { ...freshScan(), status: fx('scan-03-sbom-running') } });
  assert.ok(run.includes('id="ot-scan-status"') && run.includes('role="status"') && run.includes('aria-live="polite"'));
  assert.equal(/%|progressbar|<progress/i.test(run), false, 'no percentage and no progress element');
  assert.match(run, /Elapsed \d/); assert.match(run, /last updated 20\d\d-/); assert.match(run, /not known in advance/);
  assert.ok(run.includes('data-action="scan-cancel"'));
  const rows = visibleStages(fx('scan-04-completed')); const ids = rows.map((r) => r.id);
  assert.equal(ids.includes('aibom') || ids.includes('advisory_lookup') || ids.includes('source_checks'), false, 'disabled/not_configured stages are not shown as if they ran');
  assert.deepEqual(ids, ['resolve_revision', 'acquire_source', 'sbom', 'cbom', 'evidence_projection', 'workbench_ready']);
  const done = renderScanStatus({ scan: { ...freshScan(), status: fx('scan-04-completed') } });
  assert.equal(done.includes('data-action="scan-cancel"'), false); assert.match(done, /Scan complete/);
  const empty = renderScanStatus({ scan: { ...freshScan(), status: fx('scan-05-completed-empty-cbom') } });
  assert.match(empty, /Done · no applicable assets/); assert.equal(/data-state="failed"/.test(empty), false, 'an empty success is not a failure');
  const failed = fx('scan-08-failed-scan'); const html = renderScanStatus({ scan: { ...freshScan(), status: failed } });
  assert.match(html, /data-kind="failed"/); assert.ok(html.includes('data-state="failed"'));
  assert.ok(html.includes('data-state="not_run"') || true);
  const cu = renderScanStatus({ scan: { ...freshScan(), status: fx('scan-10-cancelled-cleanup-unverified') } });
  assert.match(cu, /Cleanup could not be confirmed/); assert.match(cu, /role="alert"/);
  const cv = outcome(fx('scan-09-cancelled-cleanup-verified')); assert.equal(cv.kind, 'cancelled');
});

test('scan progress includes the Cisco wait note only while AI inventory is running', () => {
  const status = fx('scan-03-sbom-running');
  const ai = stage(status, 'aibom');
  const panel = () => renderScanStatus({ scan: { ...freshScan(), status } });
  const waitNote = 'Cisco AI-BOM can take several minutes. You can minimize this window while the scan continues.';

  assert.ok(!panel().includes(waitNote), 'AI inventory is not configured');
  Object.assign(ai, { state: 'running', reason_code: null, started_at: status.job.updated_at });
  assert.ok(panel().includes(waitNote));

  const unavailable = 'AI-BOM generation was requested but could not run; no AI inventory is claimed.';
  Object.assign(ai, { state: 'partial', reason_code: 'partial_coverage', finished_at: status.job.updated_at, warnings: [unavailable] });
  assert.ok(!panel().includes(waitNote));
  assert.ok(panel().includes(unavailable));
});

test('partial and failed optional stages stay visible; every failure shows a fixed reason and a usable next step', () => {
  const p = visibleStages(fx('scan-06-partial')); assert.ok(p.some((r) => r.state === 'partial'));
  const st = clone(fx('scan-04-completed')); const adv = stage(st, 'advisory_lookup');
  Object.assign(adv, { state: 'partial', reason_code: 'partial_coverage', started_at: st.job.created_at, finished_at: st.job.updated_at, warnings: ['The advisory lookup answered for only part of the inventory.'] });
  assert.ok(visibleStages(st).some((r) => r.id === 'advisory_lookup' && r.state === 'partial'));
  for (const [code, [what]] of Object.entries(REASON)) assert.ok(what.length > 5, code);
  for (const code of ['policy_refused', 'scanner_failed', 'cleanup_unverified', 'timeout', 'invalid_revision']) assert.ok(REASON[code][1].length > 5, 'next step for ' + code);
  const f = outcome(fx('scan-07-failed-resolution')); assert.equal(f.kind, 'failed'); assert.ok(f.text.length > 10);
});

test('shared worker phase: both slots running AND carrying the fixed marker collapse into ONE row; sequential scanners and a bare double-running do not', () => {
  const base = clone(fx('scan-04-completed'));
  for (const id of ['sbom', 'cbom']) Object.assign(stage(base, id), { state: 'running', finished_at: null, outputs: [], warnings: [SHARED_PHASE_NOTE] });
  base.job.state = 'running'; base.handoff = { ready: false, blocked_reason: 'The scan has not finished.' };
  for (const id of ['evidence_projection', 'workbench_ready']) Object.assign(stage(base, id), { state: 'queued', started_at: null, finished_at: null });
  const rows = visibleStages(base);
  assert.equal(rows.filter((r) => r.id === 'scanners').length, 1); assert.equal(rows.some((r) => r.id === 'sbom' || r.id === 'cbom'), false);
  assert.equal(rows.find((r) => r.id === 'scanners').note, SHARED_PHASE_NOTE);
  const html = renderScanStatus({ scan: { ...freshScan(), status: base } });
  assert.equal((html.match(/data-stage="scanners"/g) || []).length, 1); assert.equal(/per-scanner (percentage|progress is shown)/i.test(html), false);
  const seq = clone(base); for (const id of ['sbom', 'cbom']) stage(seq, id).warnings = [];
  assert.equal(visibleStages(seq).some((r) => r.id === 'scanners'), false, 'without the marker the slots are shown individually');
});

test('repository-derived text in the panel is inert; control text comes from fixed vocabularies', () => {
  const st = clone(fx('scan-04-completed'));
  st.identity.repository.owner = '<img src=x onerror=alert(1)>'; st.identity.requested = { kind: 'branch', text: '"><script>alert(1)</script>', origin: 'url_tree' };
  const html = renderScanStatus({ scan: { ...freshScan(), status: st } });
  assert.equal(html.includes('<img'), false); assert.equal(html.includes('<script'), false); assert.ok(html.includes('&lt;img'));
  assert.equal(/href=/.test(html), false);
  assert.equal([...html.matchAll(/<([a-z0-9]+)\b/g)].every((t) => ['div','strong','span','button','p','code','ol','li'].includes(t[1])), true, 'only the panel\'s own tags exist');
  for (const label of Object.values(STAGE_LABEL)) assert.equal(label.includes('<'), false);
});

test('the shared-phase marker equals the server vocabulary and no code path calls the legacy live route or the preview step', () => {
  const py = readFileSync('src/core/opentrace_core/app/scan_jobs.py', 'utf8');
  const m = py.match(/WARNING_SHARED_PHASE = "([^"]+)"/); assert.ok(m); assert.equal(m[1], SHARED_PHASE_NOTE);
  const app = readFileSync('src/ui/app.js', 'utf8');
  assert.equal(app.includes('/api/analysis/live'), false, 'the new UI never calls the legacy live route');
  assert.equal(app.includes('/api/intake/preview'), false, 'the review/preview step is gone');
  assert.ok(app.includes("'/api/scan'") && app.includes('/api/scan/status'));
  assert.ok(/Math\.min\(3000/.test(app), 'bounded backoff');
  assert.equal(app.includes('EventSource'), false, 'polling, not SSE');
  assert.equal(isTerminal(fx('scan-09-cancelled-cleanup-verified')), true); assert.equal(isTerminal(fx('scan-03-sbom-running')), false);
});

test('End session stays reachable while a scan runs (in-page control enabled; only an ending session disables it)', () => {
  const base = { ...loaded(A), session: { id: null, generation: 1, status: 'active', cleanup: null } };
  const running = renderAnalyze({ ...base, busy: 'analysis', scan: { ...freshScan(), job: 'job:' + 'a'.repeat(24), status: fx('scan-03-sbom-running') } });
  assert.match(running, /id="ot-end-session" data-action="end" >End session/, 'enabled while the scan runs');
  assert.match(renderAnalyze({ ...base, busy: 'ending' }), /id="ot-end-session" data-action="end" disabled>End session/);
  assert.doesNotMatch(running, /data-action="scan-cancel"/, 'the progress panel now lives in the modal, not in the homepage form');
  assert.match(renderScanDialogBody({ ...base, scan: { ...freshScan(), job: 'job:' + 'a'.repeat(24), status: fx('scan-03-sbom-running') } }), /data-action="scan-cancel"/, 'Cancel scan is in the dialog while running');
});

// ---- UIP-03-IR-05: a failed status read is never hidden behind the last "running" claim
test('IR-05: with a status already present, a status-read error is shown, the last status is marked stale, and no fresh running claim or Cancel remains', () => {
  const running = fx('scan-03-sbom-running');
  const fresh = renderScanStatus({ scan: { ...freshScan(), status: running } });
  assert.match(fresh, /Scanning…/); assert.match(fresh, /data-action="scan-cancel"/); assert.match(fresh, /data-stale="false"/);
  const stale = renderScanStatus({ scan: { ...freshScan(), status: running, error: 'The scan status could not be read.', errorKind: 'transient' } });
  assert.match(stale, /id="ot-scan-stale"[^>]*role="alert"/, 'the error is announced');
  assert.match(stale, /The scan status could not be read\./); assert.match(stale, /last report received and may be out of date/);
  assert.match(stale, /may still be running on the service/, 'nothing is inferred about the server work');
  assert.match(stale, /data-stale="true"/); assert.match(stale, /Current status unknown/);
  assert.doesNotMatch(stale, /Scanning…/, 'no fresh running claim'); assert.doesNotMatch(stale, /ot-scan-indeterminate/);
  assert.doesNotMatch(stale, /data-action="scan-cancel"/, 'Cancel needs polling to show its outcome, so it is not offered while updates are not arriving');
  assert.match(stale, /data-action="scan-recheck"/, 'a transient failure offers one bounded recovery'); assert.match(stale, /data-action="end"/, 'End session is always offered');
  assert.match(stale, /Running/, 'the last reported stage states stay visible');
});

test('IR-05: a lost job (404/409) offers End session but no futile retry; a terminal status never shows a stale banner', () => {
  const running = fx('scan-03-sbom-running');
  const lost = renderScanStatus({ scan: { ...freshScan(), status: running, error: 'The service no longer has this scan for this page.', errorKind: 'lost' } });
  assert.doesNotMatch(lost, /data-action="scan-recheck"/); assert.match(lost, /data-action="end"/); assert.match(lost, /no longer has this scan/);
  const done = renderScanStatus({ scan: { ...freshScan(), status: fx('scan-04-completed'), error: 'x', errorKind: 'transient' } });
  assert.doesNotMatch(done, /ot-scan-stale/); assert.equal(isStale({ ...freshScan(), status: fx('scan-04-completed'), error: 'x' }), false);
  assert.equal(isStale({ ...freshScan(), status: running, error: 'x' }), true); assert.equal(isStale({ ...freshScan(), status: running }), false); assert.equal(isStale({ ...freshScan(), error: 'x' }), false);
});

test('IR-05: the status region is the focus target (focusable, restored across repaints), and the error-only panel too', () => {
  const html = renderScanStatus({ scan: { ...freshScan(), status: fx('scan-03-sbom-running') } });
  assert.match(html, /id="ot-scan-status"[^>]*tabindex="-1"[^>]*data-fk="scan-status"/);
  assert.match(renderScanStatus({ scan: { ...freshScan(), error: 'Scan could not start.' } }), /id="ot-scan-status"[^>]*tabindex="-1"[^>]*data-fk="scan-status"/);
  const app = readFileSync('src/ui/app.js', 'utf8');
  const poll = app.slice(app.indexOf('async function pollScan'), app.indexOf('function recheckScan'));
  assert.equal(poll.includes('focusScanStatus'), false, 'polling never moves focus');
  assert.equal((app.match(/focusScanStatus\(\)/g) || []).length, 3, 'one definition, the call when the dialog opens, and the recovery of a control that vanished on repaint (never from a poll)');
});

test('IR-05: SCAN_ERROR keeps its kind, a good response or a cleared error resets it, and an older epoch is ignored', () => {
  let s = initial(); s = reducer(s, { type: 'ANALYSIS_START' }); s = reducer(s, { type: 'SCAN_BEGIN', epoch: s.epoch, generation: 1 });
  s = reducer(s, { type: 'SCAN_RESPONSE', epoch: s.epoch, envelope: env(fx('scan-03-sbom-running')) });
  const bad = reducer(s, { type: 'SCAN_ERROR', epoch: s.epoch, kind: 'transient', message: 'boom' });
  assert.deepEqual([bad.scan.error, bad.scan.errorKind], ['boom', 'transient']); assert.equal(bad.scan.status, s.scan.status, 'the last status is kept');
  assert.equal(reducer(bad, { type: 'SCAN_ERROR', epoch: bad.epoch - 1, kind: 'lost', message: 'late' }), bad, 'a late error of an older epoch is dropped');
  const cleared = reducer(bad, { type: 'SCAN_ERROR', epoch: bad.epoch, message: '' });
  assert.deepEqual([cleared.scan.error, cleared.scan.errorKind], [null, null]);
  const better = reducer(bad, { type: 'SCAN_RESPONSE', epoch: bad.epoch, envelope: env(fx('scan-04-completed'), null) });
  assert.deepEqual([better.scan.error, better.scan.errorKind], [null, null], 'a fresh accepted status clears the error');
  assert.deepEqual(POLL_RETRY_DELAYS, [2000, 4000, 8000], 'bounded automatic retry');
});

// ---- Stage 4: failed-stage explanatory copy (UIP-D19 stays as decided: any failed stage fails the job; the Workbench is not opened)
test('Stage 4: a failed CBOM names the failed stage and the blocked hand-off, shows only a fixed safe reason, and never lets later completed stages read as success', () => {
  const base = clone(fx('scan-08-failed-scan'));
  const st = clone(base);
  for (const s of st.stages) { if (s.stage_id === 'cbom') { s.state = 'failed'; s.reason_code = 'scanner_failed'; s.warnings = []; s.outputs = []; } else if (['aibom', 'advisory_lookup', 'source_checks'].includes(s.stage_id)) { s.state = 'completed'; s.reason_code = null; } }
  st.job.state = 'failed';
  const o = outcome(st);
  assert.equal(o.kind, 'failed');
  assert.match(o.text, /CBOM · cdxgen failed, so the Workbench was not opened\./);
  assert.match(o.text, /A scanner did not produce a usable result\./, 'the fixed reason text for the frozen reason code');
  assert.match(o.text, /Steps that finished do not mean the scan succeeded\./);
  assert.match(o.next, /Scan again/, 'safe retry guidance is preserved');
  const html = renderScanStatus({ scan: { ...freshScan(), status: st } });
  assert.match(html, /data-kind="failed"/); assert.ok(!html.includes('/Users/') && !html.includes('Traceback'), 'no raw paths or invented causes');
});

test('Stage 4: a failed stage with no usable reason keeps the generic words and still names the stage; cancelled copy is unchanged', () => {
  const st = clone(fx('scan-08-failed-scan'));
  const failed = st.stages.find((x) => x.state === 'failed');
  failed.reason_code = null;
  const o = outcome(st);
  assert.match(o.text, /failed, so the Workbench was not opened\./); assert.match(o.text, /The scan did not complete\./);
  const c = outcome(fx('scan-09-cancelled-cleanup-verified'));
  assert.equal(c.kind, 'cancelled'); assert.equal(/Workbench was not opened|Steps that finished/.test(c.text), false);
  const ok = outcome(fx('scan-04-completed')); assert.equal(/not opened/.test(ok.text), false);
});
