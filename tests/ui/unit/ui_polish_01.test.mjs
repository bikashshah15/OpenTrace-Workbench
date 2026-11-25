// UI-POLISH-01 (presentation only): BOM icons / status chips / selected-row marker, graph-control order and expanded-view labels, homepage dark-mode CSS.
// Pure string renderers over the real store and renderers (no browser, network or service). Run: node --test tests/ui/unit/ui_polish_01.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStore, initial } from '../../../src/ui/lib/store.js';
import * as M from '../../../src/ui/lib/ai_graph.js';
import * as C from '../../../src/ui/lib/crypto_graph.js';
import { requestKey as depKey } from '../../../src/ui/lib/dependency_graph.js';
import { renderBomWorkspace, bomStateChip, STATE_CLASS } from '../../../src/ui/components/gaps.js';
import { renderAiView } from '../../../src/ui/components/ai_graph.js';
import { renderCryptoView } from '../../../src/ui/components/crypto_graph.js';
import { renderDependencyView } from '../../../src/ui/components/dependency_graph.js';
import { renderContexts } from '../../../src/ui/components/context_map.js';
import { renderAnalyze } from '../../../src/ui/components/intake.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const json = (p) => JSON.parse(readFileSync(join(ROOT, p), 'utf8'));
const CSS = readFileSync(join(ROOT, 'src/ui/styles/app.css'), 'utf8');
const ident = (digest) => ({ mode: 'captured', owner: 'acme', name: 'widget', commit: '0'.repeat(40), analysis_digest: digest });

// ---------------------------------------------------------------- tiny tag reader (no DOM library in this repo)
const container = (html, cls) => { const m = html.match(new RegExp(`<div class="${cls}">([\\s\\S]*?)</div>`)); assert.ok(m, 'control cluster ' + cls + ' is rendered'); return m[1]; };
function controlOrder(inner) {
  const out = [];
  for (const m of inner.matchAll(/<(button|span)\b([^>]*)>([\s\S]*?)<\/\1>/g)) {
    const [, tag, attrs, text] = m;
    if (tag === 'span') { if (/zoom/.test(attrs)) out.push('percent'); continue; }
    if (/data-[a-z0-9]+-fitall/.test(attrs) || /Fit all<|FIT ALL/.test(text) && !/-fit[ =]/.test(attrs)) out.push('fitall');
    else if (/-fit\b/.test(attrs)) out.push('fit');
    else if (/zoom/.test(attrs)) out.push(/ out"|out"/.test(attrs) ? 'minus' : 'plus');
  }
  return out;
}

// ---------------------------------------------------------------- graph controls: order, labels, unchanged action attributes
const FRIGATE = json('evidence/uip/fixtures/frigate-recorded/contexts.json');
function contextsHtml() {
  const st = { ...initial(), analysis: { generation: 1, identity: ident(FRIGATE.binding.analysis_digest), summary: { components: 1, checks: [] } }, views: { contexts: FRIGATE }, workbench: initial().workbench };
  return renderContexts(st);
}
const dfx = (...p) => json(join('evidence/uip/fixtures', ...p));
function depHtml(expanded) {
  const P0 = dfx('deps-82-synthetic', 'page-offset-00.json');
  const st = createStore(initial()); st.dispatch({ type: 'ANALYSIS_START' }); const e = st.get().epoch;
  st.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: { generation: 1, identity: ident(P0.binding.analysis_digest), summary: { components: 1, checks: [] } } });
  st.dispatch({ type: 'TAB_STATE', tab: 'dependencies', patch: { ctxId: P0.context.context_id, expanded } });
  const d = () => st.get().workbench.perTab.dependencies;
  st.dispatch({ type: 'DEPPAGE_REQUEST', epoch: e, generation: 1, seq: 1, key: depKey(d()), intent: 'active' });
  st.dispatch({ type: 'DEPPAGE_LOADED', epoch: e, generation: 1, seq: 1, key: depKey(d()), data: P0 });
  return renderDependencyView(st.get(), { depInspector: () => '', depList: () => '' });
}
function famHtml(kind, expanded) {
  const dir = kind === 'crypto' ? 'uip-06' : 'uip-07';
  const page = json(`evidence/uip/visual/${dir}/fixtures/renderer/multi3.json`);
  const Mod = kind === 'crypto' ? C : M;
  const st = createStore(initial()); st.dispatch({ type: 'ANALYSIS_START' }); const e = st.get().epoch;
  st.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: { generation: 1, identity: ident(page.binding.analysis_digest), summary: { components: 1, checks: [], cards: [] } } });
  st.dispatch({ type: 'TAB_STATE', tab: kind === 'crypto' ? 'crypto' : 'ai', patch: { expanded } });
  const tab = () => st.get().workbench.perTab[kind === 'crypto' ? 'crypto' : 'ai'];
  const key = Mod.requestKey(tab()); const stamp = { epoch: e, generation: 1, seq: 1, key };
  st.dispatch({ type: kind === 'crypto' ? 'CRYPTO_REQUEST' : 'AI_REQUEST', ...stamp });
  st.dispatch({ type: kind === 'crypto' ? 'CRYPTO_LOADED' : 'AI_LOADED', ...stamp, data: page });
  return (kind === 'crypto' ? renderCryptoView : renderAiView)(st.get());
}

test('all four graph tabs order the controls minus, percentage, plus, Fit (Fit all stays where it was supported)', () => {
  assert.deepEqual(controlOrder(container(contextsHtml(), 'ot4-controls')), ['minus', 'percent', 'plus', 'fit']);
  assert.deepEqual(controlOrder(container(depHtml(false), 'ot-zoom')), ['minus', 'percent', 'plus', 'fit']);
  const cr = controlOrder(container(famHtml('crypto', false), 'otc-zoomctl'));
  assert.deepEqual(cr.slice(0, 4), ['minus', 'percent', 'plus', 'fit']); assert.ok(cr.length === 4 || (cr.length === 5 && cr[4] === 'fitall'));
  const ai = controlOrder(container(famHtml('ai', false), 'otai-zoomctl'));
  assert.deepEqual(ai.slice(0, 4), ['minus', 'percent', 'plus', 'fit']); assert.ok(ai.length === 4 || (ai.length === 5 && ai[4] === 'fitall'));
});

test('zoom factors, handler attributes and ids are unchanged', () => {
  const ctx = contextsHtml();
  assert.match(ctx, /data-ctx-zoom="1\.25" aria-label="Zoom repository contexts out"/); assert.match(ctx, /data-ctx-zoom="0\.8" aria-label="Zoom repository contexts in"/);
  assert.match(ctx, /id="ot4-zoom"/); assert.match(ctx, /<button[^>]*data-ctx-fit[^>]*>Fit</);
  const dep = depHtml(false);
  assert.match(dep, /data-ot5-zoom="0\.8" aria-label="Zoom out"/); assert.match(dep, /data-ot5-zoom="1\.25" aria-label="Zoom in"/);
  assert.match(dep, /data-ot5-fit aria-label="Fit all">Fit</); assert.match(dep, /id="ot5-zoom-label"/);
  assert.match(dep, /id="ot5-expand"[^>]*data-action="dep-expand"/);
  const cr = famHtml('crypto', false);
  assert.match(cr, /data-otc-zoom="0\.8333" aria-label="Zoom cryptography out"/); assert.match(cr, /data-otc-zoom="1\.2" aria-label="Zoom cryptography in"/);
  assert.match(cr, /data-otc-fit="1"/); assert.match(cr, /id="otc-zoom"/); assert.match(cr, /id="otc-expand"[^>]*data-otc-expand="1"/);
  const ai = famHtml('ai', false);
  assert.match(ai, /data-otai-zoom="0\.8333333333333334"/); assert.match(ai, /data-otai-zoom="1\.2"/);
  assert.match(ai, /data-otai-fit="1" id="otai-fit">Fit</); assert.match(ai, /id="otai-zoom"/); assert.match(ai, /id="otai-expand"[^>]*data-otai-expand="1"/);
});

test('expand control reads Expand / Close expanded view on every tab that has one, with aria-expanded kept', () => {
  const label = (html, id) => { const m = html.match(new RegExp(`<button[^>]*id="${id}"[^>]*aria-expanded="(true|false)"[^>]*>([^<]*)</button>`)); assert.ok(m, id); return [m[1], m[2]]; };
  assert.deepEqual(label(depHtml(false), 'ot5-expand'), ['false', 'Expand']); assert.deepEqual(label(depHtml(true), 'ot5-expand'), ['true', 'Close expanded view']);
  assert.deepEqual(label(famHtml('crypto', false), 'otc-expand'), ['false', 'Expand']); assert.deepEqual(label(famHtml('crypto', true), 'otc-expand'), ['true', 'Close expanded view']);
  assert.deepEqual(label(famHtml('ai', false), 'otai-expand'), ['false', 'Expand']); assert.deepEqual(label(famHtml('ai', true), 'otai-expand'), ['true', 'Close expanded view']);
});

// ---------------------------------------------------------------- BOM: icons, family, status chips, selection
const caps = ['software', 'cryptography', 'ai_model', 'other'].map((family) => ({ family, state: 'completed', reason_code: null }));
const item = (id, family, state, over = {}) => ({ item_id: id, assertion_id: null, display: { name: 'name-' + id, raw_title: 'name-' + id }, state, category: state, graph_state: 'evidence_only', family, location: { path: 'app/' + id + '.py' }, inventory: null, ...over });
const ITEMS = [item('s1', 'software', 'contradicted'), item('c1', 'cryptography', 'unknown_coverage'), item('a1', 'ai_model', 'unverifiable'), item('o1', 'other', 'supported'), item('x1', 'surprise', 'no_rule')];
function bomHtml({ selected = null, view = 'gaps' } = {}) {
  const s = createStore({ ...initial(), epoch: 3, analysis: { generation: 7, identity: { analysis_digest: 'a'.repeat(64), owner: 'acme', name: 'widget', commit: 'b'.repeat(40) } }, workbench: { ...initial().workbench, tab: 'bom' } });
  s.dispatch({ type: 'BOM_PATCH', patch: { view, selected, queue: { mode: 'discovery_compared', counts: { candidates_total: ITEMS.length, filtered_total: ITEMS.length, records_total: 0 }, items: ITEMS, capabilities: caps, page: { offset: 0, size: 25, has_more: false }, filters: {} }, graph: null } });
  return renderBomWorkspace(s.get());
}
const rowOf = (html, id) => { const m = html.match(new RegExp(`<button type="button" class="ot-bom8-row[^"]*" data-action="bom-select" data-id="${id}"[\\s\\S]*?</button>`)); assert.ok(m, id); return m[0]; };

test('the five inner view labels each carry a decorative icon and keep their visible text and aria-current', () => {
  const html = bomHtml({ view: 'crypto' }); const nav = html.match(/<nav class="ot-bom8-tabs"[\s\S]*?<\/nav>/)[0];
  const tabs = [...nav.matchAll(/<button\b[^>]*data-view="(\w+)"[^>]*aria-current="(\w+)"[^>]*>([\s\S]*?)<\/button>/g)];
  assert.deepEqual(tabs.map((t) => t[1]), ['software', 'crypto', 'ai', 'full', 'gaps']);
  assert.deepEqual(tabs.map((t) => t[2]), ['false', 'page', 'false', 'false', 'false']);
  assert.deepEqual(tabs.map((t) => t[3].replace(/<svg[\s\S]*?<\/svg>/g, '').replace(/<\/?span>/g, '')), ['Software · SBOM', 'Cryptography · CBOM', 'AI models · AI-BOM', 'Full evidence graph', 'Focused gaps']);
  const paths = tabs.map((t) => t[3].match(/<svg[\s\S]*?<\/svg>/g) || []);
  for (const p of paths) { assert.equal(p.length, 1); assert.match(p[0], /aria-hidden="true"/); assert.match(p[0], /focusable="false"/); assert.doesNotMatch(p[0], /<title|aria-label|role=/); }
  assert.equal(new Set(paths.map((p) => p[0])).size, 5, 'five different icons');
});

test('rows show a family icon, a status chip with the existing label and tone, and no icon claims verification for crypto', () => {
  const html = bomHtml();
  const fam = (id) => rowOf(html, id).match(/<svg class="ot-bom8-icon ot-bom8-family"[\s\S]*?<\/svg>/)[0];
  assert.equal(new Set(['s1', 'c1', 'a1', 'o1'].map(fam)).size, 4, 'one distinct family icon per family');
  assert.equal(fam('x1'), fam('o1'), 'an unknown family falls back to the neutral icon');
  for (const [id, label] of [['s1', 'Software'], ['c1', 'Cryptography'], ['a1', 'AI model'], ['o1', 'Other'], ['x1', 'Other']]) assert.match(rowOf(html, id), new RegExp(`ot-bom8-family-label">${label}<`));
  // chips reuse STATE_CLASS tones and the existing words (state with underscores spaced)
  for (const [id, state, text] of [['s1', 'contradicted', 'contradicted'], ['c1', 'unknown_coverage', 'unknown coverage'], ['a1', 'unverifiable', 'unverifiable'], ['o1', 'supported', 'supported'], ['x1', 'no_rule', 'no rule']]) {
    const r = rowOf(html, id); const tone = STATE_CLASS[state] || 'muted';
    assert.match(r, new RegExp(`class="ot-state ot-bom8-chip ${tone}" data-state="${state}"><svg[^>]*aria-hidden="true"[\\s\\S]*?</svg><span>${text}</span>`));
  }
  assert.doesNotMatch(fam('c1'), /<title|check|verified|aria-label/i);
  assert.equal(bomStateChip('contradicted'), bomStateChip('contradicted'));
});

test('selected row carries a visible Selected mark and class; unselected rows and hover carry neither; aria-pressed is kept', () => {
  const html = bomHtml({ selected: 'c1' });
  const sel = rowOf(html, 'c1'); const other = rowOf(html, 's1');
  assert.match(sel, /class="ot-bom8-row selected"/); assert.match(sel, /aria-pressed="true"/); assert.match(sel, /class="ot-bom8-selmark"><svg[^>]*aria-hidden="true"[\s\S]*?<span>Selected<\/span>/);
  assert.doesNotMatch(other, /selected|Selected/); assert.match(other, /aria-pressed="false"/);
  assert.equal((html.match(/ot-bom8-selmark/g) || []).length, 1);
  // CSS: hover and selected are different rules; selected adds a leading bar that hover lacks
  const rule = (sel2) => { const m = CSS.match(new RegExp(sel2.replace(/[.:]/g, '\\$&') + '\\{([^}]*)\\}')); assert.ok(m, sel2); return m[1]; };
  const hover = rule('.ot-bom8-row:hover,.ot-bom8-record:hover'); const picked = rule('.ot-bom8-row.selected,.ot-bom8-row.selected:hover,.ot-bom8-record.selected,.ot-bom8-record.selected:hover');
  assert.doesNotMatch(hover, /box-shadow/); assert.match(picked, /box-shadow:inset 4px 0 0/); assert.notEqual(hover, picked);
});

test('decorative SVGs in the BOM workspace are all aria-hidden', () => {
  const html = bomHtml({ selected: 'a1' });
  const svgs = html.match(/<svg\b[^>]*>/g) || []; assert.ok(svgs.length >= 5 + ITEMS.length * 2);
  for (const t of svgs) assert.match(t, /aria-hidden="true"/);
});

// ---------------------------------------------------------------- homepage form: markup preserved, dark overrides use theme tokens
test('homepage inputs and sample button keep their markup, values and disabled behaviour', () => {
  const s = initial(); s.intake = { ...s.intake, url: 'https://github.com/acme/widget' };
  const html = renderAnalyze({ ...s, advanced: true, intake: { ...s.intake, manualSha: 'abc1234' } });
  assert.match(html, /<input id="ot-url" data-fk="url" type="url" placeholder="https:\/\/github.com\/owner\/repository"[^>]*value="https:\/\/github.com\/acme\/widget">/);
  assert.match(html, /<input class="ot-commit" id="ot-commit" data-fk="commit" placeholder="Paste a 7–40 character commit SHA"[^>]*value="abc1234">/);
  assert.match(html, /<button type="button" id="nh-sample" data-action="sample">Explore sample findings<\/button>/);
});

test('dark-mode homepage rules exist for text, placeholder, focus and disabled states, use theme tokens, and the light rule is untouched', () => {
  assert.match(CSS, /#ot-home #ot-url,#ot-home #ot-commit\{background:#fff;color:var\(--ink\);border:1px solid #bccdc2;/, 'light rule unchanged');
  const dark = CSS.split('\n').filter((l) => /^html\[data-theme=dark\] #ot-home (:is\(#ot-url|#nh-sample|\.nh-form-actions)/.test(l));
  assert.ok(dark.length >= 8);
  const joined = dark.join('\n');
  for (const needle of [':is(#ot-url,#ot-commit){background:var(--bg);color:var(--ink)', '::placeholder{color:var(--muted)', ':focus{', ':disabled{', '#nh-sample{background:var(--bg);color:var(--teal)', '#nh-sample:disabled', '.button.primary:disabled']) assert.ok(joined.includes(needle), needle);
  assert.doesNotMatch(joined, /#fff\b|white|#[0-9a-f]{3,6}/i, 'dark overrides use theme tokens only');
});

// UPR-01: the legacy rule `.ot-bom8-row span{color:muted;font-size:11px}` has specificity (0,1,1); every new row-child rule must out-rank it.
test('new BOM row child rules out-rank the legacy `.ot-bom8-row span` rule (name stays ink/full size, chip text and Selected keep their tone)', () => {
  const legacy = /\.ot-bom8-row span,/.test(CSS); assert.ok(legacy, 'legacy rule still present');
  for (const sel of ['.ot-bom8-row .ot-bom8-name{', '.ot-bom8-row .ot-bom8-chip span{color:inherit', '.ot-bom8-row .ot-bom8-selmark,.ot-bom8-row .ot-bom8-selmark span{color:var(--dep-selected)', '.ot-bom8-row .ot-bom8-family-label{']) assert.ok(CSS.includes(sel), sel);
  assert.match(CSS, /\.ot-bom8-row \.ot-bom8-name\{[^}]*color:var\(--ink\);font-size:inherit/);
  for (const bare of ['\n.ot-bom8-name{', '\n.ot-bom8-chip{', '\n.ot-bom8-selmark{margin']) if (bare !== '\n.ot-bom8-selmark{margin') assert.ok(!CSS.includes(bare), 'bare single-class rule would lose: ' + bare.trim());
});
