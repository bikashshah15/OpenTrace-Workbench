// Scan-progress modal: state, compact control, dialog markup and wiring, driven by the frozen scan_status fixtures (no DOM, no network).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initial, reducer } from '../../../src/ui/lib/store.js';
import { SCAN_SCHEMA, freshScan } from '../../../src/ui/lib/scan_model.js';
import { renderAnalyze } from '../../../src/ui/components/intake.js';
import { renderScanDialogBody, scanChipModel, renderScanChip, scanDialogModel, focusRestoreNeeded } from '../../../src/ui/components/scan_status.js';

const DIR = 'evidence/uip/fixtures/scan-status-matrix-synthetic/';
const fx = (n) => JSON.parse(readFileSync(DIR + n + '.json', 'utf8'));
const env = (status) => ({ schema: SCAN_SCHEMA, status, result: null });
const clone = (x) => JSON.parse(JSON.stringify(x));
const A = { enabled: true, isolation: { available: true, description: 'Docker' }, policy: { effective: 'bounded' }, advisories: { enabled: false } };
const app = readFileSync('src/ui/app.js', 'utf8');
const html = readFileSync('src/ui/index.html', 'utf8');

function begun() {   // a scan submission: ANALYSIS_START, then the dialog opens at once
  let s = { ...initial(), config: { state: 'loaded', live: A } };
  s = reducer(s, { type: 'ANALYSIS_START' });
  s = reducer(s, { type: 'SCAN_UI_BEGIN', epoch: s.epoch });
  return s;
}
const RUN_ID = fx('scan-03-sbom-running').job.job_id;
// A later report of the SAME job and generation (fixtures carry their own ids), so the monotonic guards accept it.
const later = (name, seq = 500, patch = (x) => x) => { const f = clone(fx(name)); f.job.job_id = RUN_ID; f.generation = 1; f.job.seq = seq; return env(patch(f)); };
function running() {
  let s = begun();
  s = reducer(s, { type: 'SCAN_BEGIN', epoch: s.epoch, generation: 1 });
  return reducer(s, { type: 'SCAN_RESPONSE', epoch: s.epoch, envelope: env(fx('scan-03-sbom-running')) });
}

test('open on submit, minimize, reopen: the job, status and generation are untouched', () => {
  const s0 = begun(); assert.deepEqual(s0.scanUi, { active: true, open: true });
  const s1 = running(); const job = s1.scan.job;
  const min = reducer(s1, { type: 'SCAN_UI_CLOSE', epoch: s1.epoch });
  assert.deepEqual(min.scanUi, { active: true, open: false }); assert.equal(min.scan, s1.scan, 'minimizing never touches the scan state');
  const back = reducer(min, { type: 'SCAN_UI_OPEN', epoch: min.epoch });
  assert.equal(back.scanUi.open, true); assert.equal(back.scan.job, job);
  assert.equal(back.busy, s1.busy, 'no restart');
});

test('missing URL: no dialog state is created (the error stays beside the input)', () => {
  const s = reducer({ ...initial() }, { type: 'INTAKE_STATE', patch: { state: 'invalid', error: 'Enter a GitHub repository URL', errorField: 'url' } });
  assert.deepEqual(s.scanUi, { active: false, open: false });
  const start = app.slice(app.indexOf('async function startScan'), app.indexOf('function focusScanStatus'));
  assert.ok(start.indexOf("if (!url)") < start.indexOf('SCAN_UI_BEGIN'), 'the empty-URL return comes before the dialog opens');
});

test('one scan submission only: a single /api/scan call site; the form handler is gated and the control actions only dispatch presentation', () => {
  assert.equal((app.match(/'\/api\/scan'/g) || []).length, 1);
  assert.match(app, /if \(scanGate\(store\.get\(\)\)\.enabled\) startScan\(\)/);
  const mid = app.slice(app.indexOf("case 'scan-minimize'"), app.indexOf("case 'end'"));
  assert.match(mid, /scan-minimize': dispatch\(\{ type: 'SCAN_UI_CLOSE'/); assert.match(mid, /scan-reopen': dispatch\(\{ type: 'SCAN_UI_OPEN'/);
  assert.doesNotMatch(mid.slice(0, mid.indexOf("case 'scan-reopen'") + 120), /pollScan|startScan|api\(|cancelScan/, 'minimize/reopen never poll, start, cancel or call the API');
  // while the dialog is hidden the gate still blocks a second submit (the job is unfinished, or busy)
  assert.equal(scanGateBlocked(reducer(running(), { type: 'SCAN_UI_CLOSE', epoch: running().epoch })), true);
});
import { scanGate } from '../../../src/ui/lib/scan_model.js';
const scanGateBlocked = (s) => !scanGate(s).enabled;

test('polling continues while minimized: responses change only scan state; the dialog state and polling guards are unchanged', () => {
  let s = running(); s = reducer(s, { type: 'SCAN_UI_CLOSE', epoch: s.epoch });
  const done = reducer(s, { type: 'SCAN_RESPONSE', epoch: s.epoch, envelope: later('scan-04-completed') });
  assert.equal(done.scan.status.job.state, 'completed'); assert.deepEqual(done.scanUi, { active: true, open: false });
  const poll = app.slice(app.indexOf('async function pollScan'), app.indexOf('function recheckScan'));
  assert.equal(/scanUi|SCAN_UI|isOpen|\.open/.test(poll), false, 'pollScan does not depend on dialog visibility');
  assert.match(poll, /sleepMs\(delay\)/); assert.match(poll, /POLL_RETRY_DELAYS/);
});

test('cancel: the existing flow is the only cancel path, and the dialog keeps showing the reported cleanup outcome', () => {
  assert.equal((app.match(/\/api\/analysis\/cancel/g) || []).length, 1);
  const body = renderScanDialogBody(running()); assert.match(body, /data-action="scan-cancel"/);
  let s = running(); s = reducer(s, { type: 'SCAN_RESPONSE', epoch: s.epoch, envelope: later('scan-09-cancelled-cleanup-verified', 900, (f) => { f.cleanup.state = 'pending'; return f; }) });
  assert.match(renderScanDialogBody(s), /Stopping and confirming cleanup/);
  const min = reducer(s, { type: 'SCAN_UI_CLOSE', epoch: s.epoch }); assert.match(scanChipModel(min).text, /Stopping scan/);
  const final = reducer(s, { type: 'SCAN_RESPONSE', epoch: s.epoch, envelope: later('scan-09-cancelled-cleanup-verified', 1000) });
  assert.match(renderScanDialogBody(final), /Scan cancelled/); assert.doesNotMatch(renderScanDialogBody(final), /data-action="scan-cancel"/);
});

test('success and usable partial results close the dialog and hand off; a failed scan keeps it', () => {
  const ok = reducer(running(), { type: 'ANALYSIS_READY', epoch: running().epoch, analysis: { ok: true, generation: 1, identity: { mode: 'live' } } });
  assert.deepEqual(ok.scanUi, { active: false, open: false }); assert.equal(ok.destination, 'workbench');
  const fin = app.slice(app.indexOf('async function finishScan'), app.indexOf('async function cancelScan'));
  assert.match(fin, /handoff\.ready && sc\.result && sc\.result\.ok/, 'the existing hand-off rule is unchanged');
  let f = running(); f = reducer(f, { type: 'SCAN_RESPONSE', epoch: f.epoch, envelope: later('scan-08-failed-scan') }); f = reducer(f, { type: 'ANALYSIS_FAILED', epoch: f.epoch, message: '' });
  assert.equal(f.scanUi.open, true, 'a failed scan stays visible'); assert.match(renderScanDialogBody(f), /data-kind="failed"/);
  assert.equal(scanDialogModel(f).primary, 'Close');
  const closed = reducer(f, { type: 'SCAN_UI_CLOSE', epoch: f.epoch });
  assert.equal(closed.intake.url, f.intake.url, 'the URL is retained'); assert.match(scanChipModel(closed).action, /View last status/);
});

test('refusal and failure-to-start appear in the dialog; with no status the panel shows the error and Close is offered', () => {
  let s = begun(); assert.match(renderScanDialogBody(s), /Starting analysis…/); assert.equal(scanDialogModel(s).primary, 'Minimize');
  s = reducer(s, { type: 'SCAN_BEGIN', epoch: s.epoch, generation: 1 });
  s = reducer(s, { type: 'SCAN_ERROR', epoch: s.epoch, message: 'This repository or commit is not admitted for live scanning.' });
  s = reducer(s, { type: 'ANALYSIS_FAILED', epoch: s.epoch, message: '' });
  assert.match(renderScanDialogBody(s), /not admitted for live scanning/); assert.equal(scanDialogModel(s).primary, 'Close');
  assert.equal(scanChipModel(reducer(s, { type: 'SCAN_UI_CLOSE', epoch: s.epoch })).text, 'Scan could not start');
});

test('stale status recovery: last report kept, no running claim, no activity animation, Check again and End session stay; the chip says status stopped', () => {
  let s = running(); s = reducer(s, { type: 'SCAN_ERROR', epoch: s.epoch, kind: 'transient', message: 'The scan status could not be read.' });
  const body = renderScanDialogBody(s);
  assert.match(body, /Status updates stopped/); assert.match(body, /data-action="scan-recheck"/); assert.match(body, /data-action="end"/);
  assert.doesNotMatch(body, /ot-scan-indeterminate/); assert.doesNotMatch(body, /Scanning…/); assert.match(body, /may still be running on the service/);
  assert.equal(scanDialogModel(s).primary, 'Hide', 'stale: "Close" could suggest the scan ended');
  const min = reducer(s, { type: 'SCAN_UI_CLOSE', epoch: s.epoch }); assert.equal(scanChipModel(min).kind, 'unknown'); assert.doesNotMatch(scanChipModel(min).text, /running/i);
  const lostBody = renderScanDialogBody(reducer(running(), { type: 'SCAN_ERROR', epoch: running().epoch, kind: 'lost', message: 'The service no longer has this scan for this page.' }));
  assert.doesNotMatch(lostBody, /scan-recheck/);
});

test('the compact control tracks the real outcome and exists only while the dialog is hidden', () => {
  assert.equal(scanChipModel(running()), null, 'dialog open: no control');
  assert.equal(scanChipModel({ ...initial() }), null, 'no scan: no control');
  const hide = (s) => reducer(s, { type: 'SCAN_UI_CLOSE', epoch: s.epoch });
  const m = scanChipModel(hide(running())); assert.equal(m.text + ' · ' + m.action, 'Analysis running · View progress');
  assert.match(renderScanChip(hide(running())), /Analysis running · View progress/);
  const cases = [['scan-04-completed', /Scan finished/], ['scan-08-failed-scan', /did not complete/], ['scan-09-cancelled-cleanup-verified', /cancelled/]];
  for (const [n, re] of cases) { let s = running(); s = reducer(s, { type: 'SCAN_RESPONSE', epoch: s.epoch, envelope: later(n) }); assert.match(scanChipModel(hide(s)).text, re, n); assert.doesNotMatch(scanChipModel(hide(s)).text, /running/i, n); }
  assert.match(renderScanChip(hide(begun())), /Starting analysis… · View progress/);
});

test('End session clears and closes the dialog; late responses and late open/close actions cannot reopen it or restore retired data', () => {
  const s = running(); const e = s.epoch;
  const ending = reducer(s, { type: 'END_STARTED' }); assert.deepEqual(ending.scanUi, { active: false, open: false });
  const ended = reducer(ending, { type: 'ENDED', state: 'deleted_verified' });
  assert.deepEqual(ended.scanUi, { active: false, open: false }); assert.equal(ended.scan.status, null); assert.equal(ended.intake.url, '');
  assert.equal(reducer(ended, { type: 'SCAN_UI_OPEN', epoch: e }), ended, 'a late reopen is ignored');
  assert.equal(reducer(ended, { type: 'SCAN_UI_BEGIN', epoch: e }), ended, 'a late begin from the retired epoch is ignored');
  assert.equal(reducer(ended, { type: 'SCAN_RESPONSE', epoch: e, envelope: env(fx('scan-04-completed')) }), ended, 'a late status is dropped');
  assert.equal(reducer(ended, { type: 'ANALYSIS_READY', epoch: e, analysis: { ok: true, generation: 1 } }), ended, 'a late hand-off is dropped');
  const hidden = reducer(s, { type: 'SCAN_UI_CLOSE', epoch: e }); const ended2 = reducer(reducer(hidden, { type: 'END_STARTED' }), { type: 'ENDED', state: 'gone' });
  assert.equal(reducer(ended2, { type: 'SCAN_UI_OPEN', epoch: e }).scanUi.open, false);
  assert.match(app, /case 'end': endSession\(\)/);
  assert.match(html, /id="ot-scan-dialog-end"[^>]*data-action="end"/, 'End session is reachable inside the modal');
});

test('the sample path never shares the scan dialog: ANALYSIS_START resets it, and no sample evidence is substituted', () => {
  const s = reducer(running(), { type: 'ANALYSIS_START' }); assert.deepEqual(s.scanUi, { active: false, open: false });
  const open = app.slice(app.indexOf('async function openAnalysis'), app.indexOf('// ----', app.indexOf('async function openAnalysis')));
  assert.doesNotMatch(open, /SCAN_UI/);
});

test('markup: dedicated native dialog outside any form, labelled heading, every non-submit control type="button", old inline panel gone', () => {
  const d = html.slice(html.indexOf('<dialog id="ot-scan-dialog"'), html.indexOf('</dialog>', html.indexOf('<dialog id="ot-scan-dialog"')));
  assert.match(d, /aria-labelledby="ot-scan-dialog-title"/); assert.match(d, /<h2 id="ot-scan-dialog-title">/);
  assert.equal(/<form/.test(d), false);
  for (const b of d.match(/<button[^>]*>/g)) assert.match(b, /type="button"/);
  assert.equal(html.match(/id="ot-scan-dialog"/g).length, 1); assert.notEqual(html.indexOf('id="ot-dialog"'), -1, 'the evidence/info dialog is separate');
  const base = { ...initial(), config: { state: 'loaded', live: A }, session: { id: null, generation: 1, status: 'active', cleanup: null } };
  const home = renderAnalyze({ ...reducer(base, { type: 'SCAN_UI_BEGIN', epoch: base.epoch }), busy: 'analysis', scan: { ...freshScan(), job: 'job:' + 'a'.repeat(24), status: fx('scan-03-sbom-running') } });
  assert.doesNotMatch(home, /id="ot-scan-status"/, 'the progress panel is not inline on the homepage');
  const form = home.slice(home.indexOf('<form'), home.indexOf('</form>')); assert.doesNotMatch(form, /ot-scan-chip/);
  const hid = renderAnalyze({ ...base, scanUi: { active: true, open: false }, scan: { ...freshScan(), job: 'job:' + 'a'.repeat(24), status: fx('scan-03-sbom-running') } });
  assert.match(hid, /id="ot-scan-chip"[^>]*type|type="button"[^>]*id="ot-scan-chip"/); assert.ok(hid.indexOf('ot-scan-chip') > hid.indexOf('</form>'), 'the control sits outside the scan form');
  for (const b of renderScanDialogBody(running()).match(/<button[^>]*>/g)) assert.match(b, /type="button"/);
});

test('focus and keyboard wiring: open focuses once, close restores to the control or Scan, Escape only hides, polling never moves focus, reduced motion + bounded scroll in CSS', () => {
  const r = app.slice(app.indexOf('function renderScanDialog'), app.indexOf('// After the dialog hides'));
  assert.match(r, /if \(!d\.open\) \{ d\.showModal\(\); focusScanStatus\(\); \}/, 'focus moves in once, when the dialog opens');
  const close = app.slice(app.indexOf("$('ot-scan-dialog').addEventListener('close'"), app.indexOf('// ------------------------------------------------------------------ effects'));
  assert.match(close, /SCAN_UI_CLOSE[\s\S]*scanReturnFocus/); assert.doesNotMatch(close, /cancelScan|\/api\//, 'closing does not cancel');
  assert.match(app, /function scanReturnFocus\(\)[\s\S]*ot-scan-chip[\s\S]*'ot-scan'[\s\S]*'ot-url'/);
  assert.match(app, /!\$\('ot-scan-dialog'\)\.open\)/, 'Escape does not also close the assistant behind the modal');
  const css = readFileSync('src/ui/styles/app.css', 'utf8');
  assert.match(css, /\.ot-scan-dialog\{[^}]*max-height:calc\(100dvh/); assert.match(css, /\.ot-scan-dialog-body\{[^}]*overflow:auto/);
  assert.match(css, /prefers-reduced-motion:reduce\)\{\.ot-scan-indeterminate\{animation:none/);
  assert.doesNotMatch(css.slice(css.indexOf('Scan-progress modal')), /#[0-9a-fA-F]{3,6}\b/, 'theme tokens only');
});

test('repository-derived text is escaped in the dialog', () => {
  const st = clone(fx('scan-03-sbom-running')); st.identity.repository.owner = '<img src=x onerror=alert(1)>'; st.identity.requested.text = '"><script>x</script>';
  const body = renderScanDialogBody({ scan: { ...freshScan(), status: st } });
  assert.equal(/<img|<script/.test(body), false); assert.match(body, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test('SMR-01..05: state closes the dialog on Escape, focus is restored synchronously to an enabled target, vanished controls keep focus inside, and a hidden homepage holds no stale control', () => {
  const cancel = app.slice(app.indexOf("addEventListener('cancel'"), app.indexOf('// Backstop'));
  assert.match(cancel, /ev\.preventDefault\(\)[\s\S]*SCAN_UI_CLOSE[\s\S]*scanReturnFocus\(\)/, 'Escape is closed by state, then focus is restored');
  assert.doesNotMatch(cancel, /cancelScan|\/api\//, 'Escape never cancels the scan');
  assert.match(app, /case 'scan-minimize': dispatch\(\{ type: 'SCAN_UI_CLOSE', epoch: epoch\(\) \}\); scanReturnFocus\(\)/);
  assert.match(app, /\.find\(\(x\) => x && !x\.disabled\)/, 'the first present AND enabled fallback target');
  assert.match(app, /hadFocus && !d\.contains\(document\.activeElement\)\) focusScanStatus\(\)/);
  assert.match(app, /\$\('ot-analyze'\)\.innerHTML = ''/);
  assert.equal((app.match(/focusScanStatus\(\)/g) || []).length, 3, 'definition + open + vanished-control recovery; never from polling');
  assert.equal(app.slice(app.indexOf('async function pollScan'), app.indexOf('function recheckScan')).includes('focusScanStatus'), false);
});

test('SMR-08: the error-only (refusal / failed start) panel keeps the focusable status region key so a repaint restores focus', () => {
  assert.match(renderScanDialogBody({ ...initial(), scan: { ...freshScan(), error: 'The service could not start the scan.' } }), /id="ot-scan-status"[^>]*tabindex="-1"[^>]*data-fk="scan-status"/);
});

test('SMR-09: every changed UI module parses as an ES module (the wiring tests read app.js as text, so a syntax error would otherwise pass them)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ot-parse-'));
  try {
    for (const f of ['src/ui/app.js', 'src/ui/lib/store.js', 'src/ui/components/scan_status.js', 'src/ui/components/intake.js']) {
      const copy = join(dir, f.replaceAll('/', '_') + '.mjs'); writeFileSync(copy, readFileSync(f, 'utf8'));
      execFileSync(process.execPath, ['--check', copy], { stdio: 'pipe' });   // throws on a SyntaxError
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
  const render = app.slice(app.indexOf('function render()'), app.indexOf('store.subscribe(render)'));
  assert.equal((render.match(/\belse if \(s\.destination === 'workbench'\)/g) || []).length, 1);
  assert.match(render, /if \(s\.destination !== 'analyze'\) \{ \$\('ot-analyze'\)\._html = ''/, 'a hidden homepage holds no stale scan control');
});

test('SMR-10/11: the close backstop only refocuses when it changed state; the focus fallback ends at the main region', () => {
  const close = app.slice(app.indexOf("$('ot-scan-dialog').addEventListener('close'"), app.indexOf('// ------------------------------------------------------------------ effects'));
  assert.ok(close.includes('!store.get().scanUi.open') && close.indexOf('!store.get().scanUi.open') < close.indexOf('scanReturnFocus'));
  assert.match(app, /\$\('ot-url'\), \$\('ot-main'\)\]\.find/);
});

test('SMR-13: every state-driven close (hand-off, End session, 403) restores focus synchronously, not only Escape/Minimize', () => {
  assert.match(app, /else if \(d\.open\) \{ d\.close\(\); scanReturnFocus\(\); \}/);
  assert.match(app, /function scanReturnFocus\(\)[\s\S]*: \$\('ot-main'\)/, 'on the Workbench the main region takes focus after a hand-off');
});

test('SMR-13 (corrected): a REMOVED minimized control / homepage element restores focus; a surviving or re-keyed control and ordinary polling never do', () => {
  const gone = { connected: false, activeIsBody: true };
  // minimized hand-off: the focused control is removed and the page left the homepage
  assert.equal(focusRestoreNeeded({ owner: 'chip', destination: 'workbench', ...gone }), true);
  // End session / 403 retirement from the minimized control: removed, still on the homepage
  assert.equal(focusRestoreNeeded({ owner: 'chip', destination: 'analyze', ...gone }), true);
  // another homepage element removed because the page left the homepage
  assert.equal(focusRestoreNeeded({ owner: 'analyze', destination: 'workbench', ...gone }), true);
  // NOT moved: ordinary polling repaint of the homepage replaced an unrelated focused element
  assert.equal(focusRestoreNeeded({ owner: 'analyze', destination: 'analyze', ...gone }), false, 'polling never steals focus from an unrelated element');
  // NOT moved: the control survived, or paint() re-focused its keyed replacement, or nothing scan-related held focus
  assert.equal(focusRestoreNeeded({ owner: 'chip', destination: 'analyze', connected: true, activeIsBody: false }), false);
  assert.equal(focusRestoreNeeded({ owner: 'chip', destination: 'analyze', connected: false, activeIsBody: false }), false, 'focus already landed somewhere');
  assert.equal(focusRestoreNeeded({ owner: null, destination: 'workbench', ...gone }), false);
  // wiring: captured before the repaint, evaluated after the dialog is rendered, and polling code has no focus calls
  const render = app.slice(app.indexOf('function render()'), app.indexOf('store.subscribe(render)'));
  assert.ok(render.indexOf('const focused = document.activeElement') < render.indexOf('paint($(\'ot-analyze\')') && render.indexOf('renderScanDialog(s)') < render.indexOf('focusRestoreNeeded({'));
  assert.match(render, /focusRestoreNeeded\(\{ owner: focusOwner, connected: !!focused && focused\.isConnected/);
  assert.equal(/focus\(/.test(app.slice(app.indexOf('async function pollScan'), app.indexOf('function recheckScan'))), false);
  // the chip is keyed, so an ordinary status-text repaint re-focuses the new node instead of dropping focus
  assert.match(renderScanChip({ ...reducer(running(), { type: 'SCAN_UI_CLOSE', epoch: running().epoch }) }), /id="ot-scan-chip"[^>]*data-fk="scan-chip"/);
});

test('SMR-13 (corrected): End session restores focus only when focus fell to <body>', () => {
  const end = app.slice(app.indexOf('async function endSession'), app.indexOf('// ------------------------------------------------------------------ preview'));
  assert.match(end, /dispatchEnded\(state\);[\s\S]*a === document\.body \|\| !a\.isConnected \|\| a\.closest\?\.\('\[hidden\]'\)\) scanReturnFocus\(\)/, 'SMR-15: a focused element that is gone OR merely hidden (the header End session button) counts as lost');
});
