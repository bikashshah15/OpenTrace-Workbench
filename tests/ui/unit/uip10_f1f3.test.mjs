// UIP-10 F1-F3 (validation findings): renderer/store regressions, no browser. They fail on the reviewed source (32e4824) and pass after the correction.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as S from '../../../src/ui/lib/store.js';
import { bomDetailsHtml, renderBomWorkspace } from '../../../src/ui/components/gaps.js';

const { createStore, initial, bomKey } = S;
const identity = { analysis_digest: 'a'.repeat(64), owner: 'review', name: 'fixture', commit: 'b'.repeat(40) };
const mk = () => createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity }, workbench: { ...initial().workbench, tab: 'bom' } });
const patch = (s, p) => s.dispatch({ type: 'BOM_PATCH', patch: p });
const caps = (sw, reason = null) => [{ family: 'software', state: sw, reason_code: reason }, ...['cryptography', 'ai_model', 'other'].map((family) => ({ family, state: 'not_run', reason_code: 'not_configured' }))];
const cand = { item_id: 'cand:1', assertion_id: null, display: { name: 'flask', raw_title: 'flask' }, state: 'unknown_coverage', category: 'requirement', graph_state: 'no_graph', location: null, inventory: null, rule_id: null };
const compared = (sw, reason, items = [], total = items.length, filtered = items.length) => ({ binding: { analysis_digest: identity.analysis_digest }, mode: 'discovery_compared', counts: { candidates_total: total, filtered_total: filtered, records_total: 0 }, items, page: { offset: 0, size: 25, has_more: false }, capabilities: caps(sw, reason) });
const notCompared = (sw, reason, message) => ({ binding: { analysis_digest: identity.analysis_digest }, mode: 'not_compared', status_detail: { code: 'x', message }, counts: { candidates_total: 0, filtered_total: 0, records_total: 0 }, items: [], page: { offset: 0, size: 25, has_more: false }, capabilities: caps(sw, reason) });
const text = (html) => html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
const withQueue = (queue, view = 'software', extra = {}) => { const s = mk(); patch(s, { view, queue, ...extra }); return s; };
const fail = (s, kind, status, error = 'boom') => {
  const b = s.get().bom8, stamp = { kind, epoch: 3, generation: 7, seq: b.seq[kind] + 1, key: bomKey(b, kind) };
  s.dispatch({ type: 'BOM_REQUEST', ...stamp }); s.dispatch({ type: 'BOM_FAILED', ...stamp, status, error });
};

// ---------- F1 ----------
for (const [label, sw, reason, msg] of [['unsupported', 'unsupported', 'unsupported_ecosystem', 'Only declaration files of other formats were found, so nothing was compared.'], ['failed', 'failed', 'upstream_failed', 'The exported source could not be read, so nothing was compared.']]) {
  test(`F1 (${label}): a refused graph request on a not-compared analysis keeps the real reason, not "endpoint unavailable"`, () => {
    const s = withQueue(notCompared(sw, reason, msg), 'full');
    fail(s, 'graph', 404, 'The versioned BOM endpoint is unavailable in this build.');
    const html = text(renderBomWorkspace(s.get()));
    assert.doesNotMatch(html, /endpoint is unavailable/);
    assert.match(html, /Not compared\./);
    assert.ok(html.includes(msg), 'the actual reason is shown');
  });
}
test('F1: genuine errors stay visible (404 with a compared analysis, a non-404 failure, a network failure, and a failed queue request)', () => {
  const a = withQueue(compared('completed', null, [cand]), 'full'); fail(a, 'graph', 404, 'The versioned BOM endpoint is unavailable in this build.');
  assert.match(text(renderBomWorkspace(a.get())), /endpoint is unavailable/);
  const b = withQueue(notCompared('failed', 'upstream_failed', 'm'), 'full'); fail(b, 'graph', 500, 'Server error');
  assert.match(text(renderBomWorkspace(b.get())), /Server error/);
  const c = withQueue(notCompared('failed', 'upstream_failed', 'm'), 'full'); fail(c, 'graph', undefined, 'Failed to fetch');
  assert.match(text(renderBomWorkspace(c.get())), /Failed to fetch/);
  const d = withQueue(notCompared('failed', 'upstream_failed', 'm'), 'software'); fail(d, 'queue', 404, 'The versioned BOM endpoint is unavailable in this build.');
  assert.match(text(renderBomWorkspace(d.get())), /endpoint is unavailable/);
});
test('F1: an ended session still shows the ended-session message', () => {
  const s = withQueue(notCompared('failed', 'upstream_failed', 'm'), 'full'); fail(s, 'graph', 409, 'stale');
  assert.match(text(renderBomWorkspace(s.get())), /belongs to an ended session/);
});
test('F1: transitions - a genuine error is cleared by the next request/response, and a new analysis starts clean', () => {
  const s = withQueue(compared('completed', null, [cand]), 'full'); fail(s, 'graph', 500, 'Server error');
  assert.match(text(renderBomWorkspace(s.get())), /Server error/);
  const b = s.get().bom8, stamp = { kind: 'queue', epoch: 3, generation: 7, seq: b.seq.queue + 1, key: bomKey(b, 'queue') };
  s.dispatch({ type: 'BOM_REQUEST', ...stamp }); s.dispatch({ type: 'BOM_LOADED', ...stamp, data: compared('completed', null, [cand]) });
  assert.doesNotMatch(text(renderBomWorkspace(s.get())), /Server error/);
  assert.equal('errorKind' in s.get().bom8, false);
  const t = withQueue(compared('completed', null, [cand]), 'full'); fail(t, 'graph', 500, 'Server error');
  t.dispatch({ type: 'ANALYSIS_START' });
  assert.equal(t.get().bom8.error, null);
});
test('F1: a not-compared queue followed by a compared one does not keep the old reason or an error', () => {
  const s = withQueue(notCompared('failed', 'upstream_failed', 'OLD REASON'), 'full'); fail(s, 'graph', 404);
  patch(s, { queue: compared('completed', null, [cand]) });
  assert.doesNotMatch(text(renderBomWorkspace(s.get())), /OLD REASON|endpoint is unavailable/);
});

// ---------- F2 ----------
test('F2: partial with zero candidates never claims a completed or complete comparison', () => {
  const s = withQueue(compared('partial', 'partial_coverage', [], 0, 0), 'software');
  const html = text(renderBomWorkspace(s.get()));
  assert.match(html, /coverage was partial/);
  assert.doesNotMatch(html, /comparison completed/i);
  assert.match(bomDetailsHtml(s.get()), /data-coverage="partial"/); assert.doesNotMatch(renderBomWorkspace(s.get()), /data-coverage="partial"/);
});
test('F2: the partial notice does not depend on filter, search, total or view', () => {
  for (const view of ['software', 'gaps', 'full']) for (const total of [0, 1]) {
    const s = withQueue(compared('partial', 'partial_coverage', [], total, 0), view, { filter: 'represented', q: 'zzz' });
    assert.match(bomDetailsHtml(s.get()), /data-coverage="partial"/, `${view}/${total}`);
  }
});
test('F2: completed, completed_empty and an unlabelled legacy payload each get accurate, different wording', () => {
  const done = text(renderBomWorkspace(withQueue(compared('completed', null, [], 0, 0)).get()));
  assert.match(done, /produced no candidates/); assert.match(done, /no count of them is shown/); assert.doesNotMatch(done, /all (declarations|requirements)[^.]*represented|every declaration was/i);
  const empty = text(renderBomWorkspace(withQueue(compared('completed_empty', 'no_applicable_assets', [], 0, 0)).get()));
  assert.match(empty, /No requirement declarations were found/); assert.doesNotMatch(empty, /coverage was partial/);
  const legacy = text(renderBomWorkspace(withQueue({ ...compared('completed', null, [], 0, 0), capabilities: [] }).get()));
  assert.match(legacy, /completed with no candidates/);
});
test('F2: a filtered-empty list is distinct from an assessment with zero total candidates', () => {
  const filtered = text(renderBomWorkspace(withQueue(compared('completed', null, [], 1, 0), 'software', { filter: 'represented' }).get()));
  assert.match(filtered, /No candidates match this filter/); assert.doesNotMatch(filtered, /This assessment has no candidates/);
  const zero = text(renderBomWorkspace(withQueue(compared('completed', null, [], 0, 0)).get()));
  assert.match(zero, /This assessment has no candidates/); assert.doesNotMatch(zero, /match this filter/);
});
test('F2: unsupported and failed keep their own not-compared wording and no coverage notice', () => {
  for (const [sw, r] of [['unsupported', 'unsupported_ecosystem'], ['failed', 'upstream_failed']]) {
    const html = renderBomWorkspace(withQueue(notCompared(sw, r, 'REASON TEXT'), 'gaps').get());
    assert.match(text(html), /Not compared\. REASON TEXT/); assert.match(text(html), /Nothing was compared, so there are no candidates to list/); assert.doesNotMatch(html, /data-coverage/);
  }
});
// ---------- F3 ----------
test('F3: at 700 px and below the BOM launcher rides in the fixed details dock, and the open drawer keeps it above the drawer', () => {
  const css = readFileSync(new URL('../../../src/ui/styles/app.css', import.meta.url), 'utf8');
  const m = css.match(/@media\(max-width:700px\)\{body:has\(\.ot-bom8\) \.assistant-launch\{([^}]*)\}body:has\(\.ot-bom8-inspector\.open\) \.assistant-launch\{([^}]*)\}/);
  assert.ok(m, 'rule present');
  assert.match(m[1], /bottom:6px/); assert.match(m[1], /left:50%/); assert.match(m[1], /z-index:31/); assert.doesNotMatch(m[1], /bottom:62px/);
  assert.match(m[2], /bottom:calc\(45vh \+ 14px\)/);
});
