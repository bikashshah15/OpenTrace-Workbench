// UIP-03: the Scan progress panel (renders the frozen scan_status/1 through lib/scan_model.js). Repository-derived text
// (URL, owner/name, requested revision, commit) is escaped; everything else is fixed text from the model.
import { esc } from '../lib/util.js';
import { STATE_LABEL, STATE_MARK, elapsedText, isStale, isTerminal, outcome, visibleStages, REFUSAL } from '../lib/scan_model.js';

export function renderScanStatus(s) {
  const scan = s.scan;
  if (!scan || (!scan.status && !scan.error)) return '';
  const st = scan.status;
  if (!st) return `<div class="ot-scan" id="ot-scan-status" role="status" aria-live="polite" tabindex="-1" data-fk="scan-status"><p class="ot-scan-outcome" data-kind="failed">${esc(scan.error)}</p></div>`;
  const out = outcome(st);
  const terminal = isTerminal(st);
  const ident = st.identity;
  const pin = ident
    ? `<p class="ot-scan-pin ot-help">Repository <strong>${esc(ident.repository.owner)}/${esc(ident.repository.name)}</strong> · ${esc(ident.requested.kind === 'default_branch' ? 'default branch' : ident.requested.kind)} <code>${esc(ident.requested.text)}</code> · pinned commit <code>${esc(ident.resolved.commit_sha)}</code></p>`
    : '<p class="ot-scan-pin ot-help">Resolving the revision…</p>';
  const rows = visibleStages(st).map((r) => `<li class="ot-scan-stage" data-stage="${esc(r.id)}" data-state="${esc(r.state)}"><span class="ot-scan-mark" aria-hidden="true">${STATE_MARK[r.state] || '•'}</span><span class="ot-scan-label">${esc(r.label)}</span><span class="ot-scan-state">${esc(STATE_LABEL[r.state] || r.state)}</span>${r.note ? `<span class="ot-scan-note ot-help">${esc(r.note)}</span>` : ''}</li>`).join('');
  const stale = isStale(scan);
  const busy = !terminal && !stale ? '<span class="ot-scan-indeterminate" aria-hidden="true"></span>' : '';
  const time = `<span class="ot-scan-time ot-help">${stale ? 'Last reported: elapsed' : 'Elapsed'} ${esc(elapsedText(st.job.elapsed_ms))} · last updated ${esc(st.job.updated_at)}</span>`;
  // While updates are not arriving the visible outcome of a Cancel could not be shown, so Cancel is not offered; End session is.
  const cancel = !terminal && !stale ? '<button type="button" class="text-action" id="ot-scan-cancel" data-fk="scan-cancel" data-action="scan-cancel">Cancel scan</button>' : '';
  const staleNote = stale
    ? `<div class="ot-note ot-session-error" id="ot-scan-stale" role="alert"><p><strong>Status updates stopped.</strong> ${esc(scan.error)} The stages below are the last report received and may be out of date. The scan may still be running on the service.</p><p class="ot-scan-recovery">${scan.errorKind === 'transient' ? '<button type="button" class="button" id="ot-scan-recheck" data-fk="scan-recheck" data-action="scan-recheck">Check again</button> ' : ''}<button type="button" class="button" id="ot-scan-end" data-fk="scan-end" data-action="end">End session</button></p></div>`
    : '';
  const cleanup = st.cleanup.state === 'unverified' ? '<p class="ot-note ot-session-error" role="alert">Cleanup could not be confirmed. Access to scanning stays blocked until the session is ended and removal is verified.</p>' : '';
  const headline = stale ? '<p class="ot-scan-outcome" data-kind="unknown">Current status unknown.</p>' : `<p class="ot-scan-outcome" data-kind="${esc(out.kind)}">${esc(out.text)}${out.next ? ` <span class="ot-scan-next">${esc(out.next)}</span>` : ''}</p>`;
  return `<div class="ot-scan" id="ot-scan-status" role="status" aria-live="polite" tabindex="-1" data-fk="scan-status" data-job-state="${esc(st.job.state)}" data-stale="${stale ? 'true' : 'false'}">
    <div class="ot-scan-head"><strong>Scan progress</strong>${busy}${time}${cancel}</div>
    ${pin}
    ${staleNote}
    <ol class="ot-scan-stages">${rows}</ol>
    ${headline}
    ${cleanup}</div>`;
}

export const refusalText = (res) => REFUSAL[res.code] || res.message || 'The scan could not be started.';

// ---- Scan-progress modal. The dialog body reuses renderScanStatus unchanged; before the first status or error exists it says only that the
// analysis is starting. Nothing here adds percentages, estimates or any claim the reported status does not make.
export const hasScanReport = (s) => !!(s.scan && (s.scan.status || s.scan.error));

export function renderScanDialogBody(s) {
  if (hasScanReport(s)) return renderScanStatus(s);
  return '<div class="ot-scan" id="ot-scan-status" role="status" aria-live="polite" tabindex="-1" data-fk="scan-status" data-job-state="starting"><div class="ot-scan-head"><strong>Scan progress</strong><span class="ot-scan-indeterminate" aria-hidden="true"></span></div><p class="ot-scan-outcome" data-kind="working">Starting analysis…</p></div>';
}

// The dialog's own controls: the primary action hides the dialog (Minimize while the scan is unfinished, Close once there is nothing running).
export function scanDialogModel(s) {
  const st = s.scan && s.scan.status;
  const running = !hasScanReport(s) || (!!st && !isTerminal(st) && !isStale(s.scan));
  // 'Hide' while status is stale: Close could suggest the scan ended, but it may still be running on the service.
  return { running, primary: running ? 'Minimize' : isStale(s.scan) ? 'Hide' : 'Close', endDisabled: s.busy === 'ending' };
}

// The compact homepage control shown while the dialog is hidden. Its words come from the same outcome the dialog shows, so a minimized scan can
// never keep saying "running" after it finished, failed, was cancelled, or stopped reporting.
export function scanChipModel(s) {
  if (!s.scanUi || !s.scanUi.active || s.scanUi.open) return null;
  const st = s.scan.status;
  if (!hasScanReport(s)) return { kind: 'working', text: 'Starting analysis…', action: 'View progress' };
  if (!st) return { kind: 'failed', text: 'Scan could not start', action: 'View status' };
  if (isStale(s.scan)) return { kind: 'unknown', text: 'Status updates stopped', action: 'View last status' };
  const out = outcome(st);
  if (out.kind === 'working') return { kind: 'working', text: st.job.state === 'queued' ? 'Analysis queued' : (['failed', 'cancelled'].includes(st.job.state) ? 'Stopping scan' : 'Analysis running'), action: 'View progress' };
  if (out.kind === 'ok') return { kind: 'ok', text: 'Scan finished', action: 'View status' };
  return { kind: out.kind, text: out.kind === 'cancelled' ? 'Scan cancelled' : 'Scan did not complete', action: 'View last status' };
}

export function renderScanChip(s) {
  const m = scanChipModel(s); if (!m) return '';
  const mark = { working: '◐', ok: '✓', failed: '✕', cancelled: '–', unknown: '!' }[m.kind] || '•';
  return `<p class="ot-scan-chip" data-kind="${esc(m.kind)}" role="status" aria-live="polite"><span class="ot-scan-chip-mark" aria-hidden="true">${mark}</span><button type="button" class="text-action" id="ot-scan-chip" data-fk="scan-chip" data-action="scan-reopen">${esc(m.text)} · ${esc(m.action)}</button></p>`;
}

// Focus rule for a repaint that REMOVES the focused scan control (hand-off, End session, 403 retirement). `owner` is what held focus before the repaint:
// 'chip' = the compact control, 'analyze' = another homepage element, null = anything else. Focus is moved only when that element is gone and nothing took its
// place (focus fell to <body>); a surviving control, a re-focused keyed control (paint() restores data-fk) and ordinary polling repaints are never touched.
// A non-chip homepage element only counts when the page left the homepage (otherwise an unrelated repaint could pull focus away from the person).
export function focusRestoreNeeded({ owner, connected, activeIsBody, destination }) {
  if (!owner || connected || !activeIsBody) return false;
  return owner === 'chip' || destination !== 'analyze';
}
