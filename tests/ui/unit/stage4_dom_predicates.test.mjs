// Stage 4 closing campaign: OFFLINE check that the DOM predicates frozen for the browser run (FINAL_CAMPAIGN_FROZEN_EXPECTATIONS_v2.md, E1-E4, E10, E11) are
// expressible against what the REAL renderers emit for REAL server payloads (captured from the real server on the SYNTHETIC completion-service repos).
// This is string-level evidence about markup and copy; it is NOT a browser observation and does not establish layout, paint or interaction.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStore, initial } from '../../../src/ui/lib/store.js';
import * as MA from '../../../src/ui/lib/ai_graph.js';
import * as MC from '../../../src/ui/lib/crypto_graph.js';
import { renderAiView } from '../../../src/ui/components/ai_graph.js';
import { renderCryptoView } from '../../../src/ui/components/crypto_graph.js';

const DIR = join(dirname(fileURLToPath(import.meta.url)), 'fixtures/stage4_real');
const page = (n) => JSON.parse(readFileSync(join(DIR, n + '.json'), 'utf8'));
const analysis = (digest) => ({ generation: 1, identity: { mode: 'live', owner: 'acme', name: 'x', commit: '0'.repeat(40), analysis_digest: digest }, summary: { components: 1, checks: [], cards: [] } });
function opened(p) { const st = createStore(initial()); st.dispatch({ type: 'ANALYSIS_START' }); const e = st.get().epoch; st.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: analysis(p.binding.analysis_digest) }); return { st, e }; }
function loadAi(p, extra = {}) { const { st, e } = opened(p); st.dispatch({ type: 'TAB_STATE', tab: 'ai', patch: extra }); const key = MA.requestKey(st.get().workbench.perTab.ai); st.dispatch({ type: 'AI_REQUEST', epoch: e, generation: 1, seq: 1, key }); st.dispatch({ type: 'AI_LOADED', epoch: e, generation: 1, seq: 1, key, data: p }); return st; }
function loadCr(p, extra = {}) { const { st, e } = opened(p); st.dispatch({ type: 'TAB_STATE', tab: 'crypto', patch: extra }); const key = MC.requestKey(st.get().workbench.perTab.crypto); st.dispatch({ type: 'CRYPTO_REQUEST', epoch: e, generation: 1, seq: 1, key }); st.dispatch({ type: 'CRYPTO_LOADED', epoch: e, generation: 1, seq: 1, key, data: p }); return st; }
const text = (html) => html.replace(/<[^>]+>/g, ' ').replace(/&[a-z#0-9]+;/g, ' ').replace(/\s+/g, ' ');
const n = (html, re) => (html.match(re) || []).length;

test('E1: aicrypto AI renders pills 3/1/1, five asset cards in the graph, one alternative connector, experimental labels', () => {
  const h = renderAiView(loadAi(page('aicrypto_ai')).get());
  const t = text(h);
  assert.match(t, /Runtimes\s*3/); assert.match(t, /AI services\s*1/); assert.match(t, /Models\s*1/);
  assert.equal(n(h, /<g role="button"[^>]*data-otai-select="asset/g), 5);
  assert.equal(n(h, /class="otai-alt"/g), 1);
  assert.match(h, /id="otai-detail"/); assert.match(h, /class="ot-inspector otai-aside"/);
});

test('E1: the runtimes filter payload renders exactly 3 asset cards (selector used by the driver)', () => {
  const p = page('aicrypto_ai'); const q = JSON.parse(JSON.stringify(p)); q.assets = q.assets.filter((a) => a.kind === 'runtime'); q.counts = { total: 3, shown: 3, truncated: false };
  const h = renderAiView(loadAi(q, { filter: 'runtimes' }).get());
  assert.equal(n(h, /<g role="button"[^>]*data-otai-select="asset/g), 3);
});

test('E3: unsupp renders no asset card and the empty text is the honest absence wording; no experimental asset label', () => {
  const h = renderAiView(loadAi(page('unsupp_ai')).get()); const t = text(h);
  assert.equal(n(h, /data-otai-select="asset/g), 0); assert.match(h, /id="otai-empty"/);
  assert.doesNotMatch(t, /onnxruntime|openvino|tensorrt|chat\/completions/);
  const c = text(renderCryptoView(loadCr(page('unsupp_crypto')).get()));
  assert.doesNotMatch(c, /HS256|onnxruntime/);
});

test('E4: partial AI states the collection was incomplete and lists only onnxruntime', () => {
  const t = text(renderAiView(loadAi(page('partial_ai')).get()));
  assert.match(t, /incomplete/i); assert.match(t, /onnxruntime/); assert.doesNotMatch(t, /tflite_runtime/);
});

test('E10: bounds AI renders 30 cards, states 500 and a next-page control the driver can click', () => {
  const h = renderAiView(loadAi(page('bounds_ai')).get()); const t = text(h);
  assert.match(t, /500/); assert.match(t, /1–30 of 500/);
  assert.match(h, /<button type="button" data-otai-page="1"[^>]*aria-label="Next 30 assets" >/);
  assert.match(t, /incomplete/i);
  const c = text(renderCryptoView(loadCr(page('bounds_crypto')).get())); assert.match(c, /incomplete/i);
});

test('E11: aifault AI says incomplete with a failed producer; cryptofault Crypto says incomplete and keeps sha256', () => {
  const a = text(renderAiView(loadAi(page('aifault_ai')).get())); assert.match(a, /incomplete/i); assert.match(a, /failed/i);
  const c = text(renderCryptoView(loadCr(page('cryptofault_crypto')).get())); assert.match(c, /incomplete/i); assert.match(c, /sha256/);
});

test('E2: aicrypto Crypto renders a Findings count of 1 and the six frozen asset names; HS256 card is clickable (role=button, data-otc-select=asset)', () => {
  const h = renderCryptoView(loadCr(page('aicrypto_crypto')).get()); const t = text(h);
  assert.match(t, /Findings\s*1/);
  for (const nm of ['HS256', 'RS256', 'md5', 'sha256', 'MQTT TLS configuration']) assert.ok(t.includes(nm), nm);
  assert.equal(n(h, /<g role="button"[^>]*data-otc-select="asset/g), 6);
});

test('E1/E2: the selection inspector copy for an experimental runtime and for HS256 (what the driver reads from the aside)', () => {
  const p = page('aicrypto_ai'); const rt = p.assets.find((a) => a.display_name === 'tflite_runtime');
  const key = MA.assetKey(rt); const h = renderAiView(loadAi(p, { selected: key }).get()); const t = text(h);
  assert.match(t, /Experimental source observation/i); assert.match(t, /does not show that the runtime is installed or active/i); assert.doesNotMatch(t, /vulnerab/i);
  const pc = page('aicrypto_crypto'); const hs = pc.assets.find((a) => a.display_name === 'HS256');
  const tc = text(renderCryptoView(loadCr(pc, { selected: MC.assetKey(hs) }).get()));
  assert.match(tc, /Experimental source observation/i); assert.doesNotMatch(tc, /vulnerab/i);
});

test('API-level frozen predicates evaluated on the real payloads (E1 per-key totals, E4, E10, E11 producers) — the exact comparisons the driver makes', () => {
  const ai = page('aicrypto_ai');
  assert.ok([['all', 5], ['models', 1], ['runtimes', 3], ['ai_services', 1], ['findings', 0]].every(([k, v]) => ai.filter_totals[k] === v));
  const prod = (b) => b.producers.map((p) => [p.provenance.producer_id, p.outcome]);
  assert.deepEqual(prod(ai).map((x) => x[0]).sort(), ['cisco-aibom', 'opentrace-source-ai']);
  const pre = ai.assets.find((a) => a.display_name === 'tflite_runtime'), fb = ai.assets.find((a) => a.display_name === 'ai_edge_litert');
  assert.equal(ai.links.length, 1); assert.equal(ai.links[0].from, pre.asset_id); assert.equal(ai.links[0].to, fb.asset_id);
  assert.equal(fb.occurrences[0].alternative_of, pre.occurrences[0].occurrence_id);
  const b = page('bounds_ai'); assert.equal(b.filter_totals.all, 500); assert.equal(b.counts.shown, 30); assert.equal(b.counts.truncated, true); assert.deepEqual(prod(b).find((x) => x[0] === 'opentrace-source-ai'), ['opentrace-source-ai', 'partial']);
  assert.deepEqual(prod(page('aifault_ai')).find((x) => x[0] === 'opentrace-source-ai'), ['opentrace-source-ai', 'failed']);
  const fc = page('aifault_crypto'); assert.equal(fc.availability.state, 'completed'); assert.ok(['HS256', 'sha256'].every((n) => fc.assets.some((a) => a.display_name === n)));
  const gc = page('cryptofault_crypto'); assert.deepEqual(prod(gc).find((x) => x[0] === 'opentrace-source-crypto'), ['opentrace-source-crypto', 'partial']); assert.ok(gc.assets.some((a) => a.display_name === 'sha256') && !gc.assets.some((a) => a.display_name === 'HS256'));
  const cr = page('aicrypto_crypto'); assert.equal(cr.review_items.length, 1); assert.equal(cr.review_items[0].rule_id, 'source-observation.tls_verification_relaxed'); assert.equal(cr.assets.find((a) => a.asset_id === cr.review_items[0].asset_id).kind, 'protocol');
});
