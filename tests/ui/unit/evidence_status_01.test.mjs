// UI-EVIDENCE-STATUS-01: rendered-output and model tests for the compact evidence-status strip.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { evidenceStatus, inventoryStatus, STATE_CODES } from '../../../src/ui/lib/evidence_status.js';
import { renderEvidenceStrip, resetEvidenceDetails } from '../../../src/ui/components/evidence_strip.js';

const prod = (origin, outcome, extra = {}) => ({ provenance: { origin, producer_id: origin === 'original_artifact' ? 'cdxgen' : 'src-scan', producer_version: origin === 'original_artifact' ? 'cdxgen 12.9.0' : null, experimental: origin !== 'original_artifact', ...extra.prov }, scope: extra.scope || 'whole repository', outcome, coverage: extra.coverage || { files_considered: 0, files_parsed: 0, files_excluded: 0, excluded_paths: [], unparsed_total: 0, unknown_dynamic_values_total: 0 } });
const asset = (origin) => ({ asset_id: 'a1', provenance: { origin } });
const page = ({ producers = [], availability = { state: 'completed', reason_code: null, message: 'm' }, assets = [], all = assets.length, mode = 'live' } = {}) => ({ producers, availability, assets, filter_totals: { all }, binding: { mode } });
const card = (kind, o = {}) => ({ kind, state: 'acquired', record_count: 5, ...o });
const base = (o = {}) => ({
  analysis: { identity: { mode: o.mode || 'live' }, summary: { cards: o.cards ?? [card('sbom'), card('cbom'), card('aibom')] } },
  views: { ...(o.cryptoPage ? { cryptoPage: o.cryptoPage } : {}), ...(o.aiPage ? { aiPage: o.aiPage } : {}) },
  workbench: { perTab: { crypto: { pg: { status: o.cryptoStatus || 'idle' }, stale: !!o.cryptoStale }, ai: { pg: { status: o.aiStatus || 'idle' }, stale: false } } },
  advanced: !!o.advanced, busy: null,
});
const text = (s, kind, tab) => inventoryStatus(s, kind, tab).text;

test('valid inventory', () => {
  const s = base({ cryptoPage: page({ producers: [prod('original_artifact', 'completed')], assets: [asset('original_artifact')] }) });
  assert.equal(text(s, 'cbom', 'crypto'), 'CBOM available');
  assert.equal(inventoryStatus(s, 'cbom', 'crypto').tone, 'doc');
});
test('successful empty inventory states its scope', () => {
  const s = base({ cryptoPage: page({ producers: [prod('original_artifact', 'completed')], availability: { state: 'completed_empty', reason_code: 'no_applicable_assets', message: 'm' } }) });
  assert.equal(text(s, 'cbom', 'crypto'), 'CBOM available · No assets recorded within its scope');
});
test('partial inventory', () => {
  const s = base({ aiPage: page({ producers: [prod('original_artifact', 'partial')], assets: [asset('original_artifact')] }) });
  assert.equal(text(s, 'aibom', 'ai'), 'Partial AI-BOM · Coverage incomplete'); assert.equal(inventoryStatus(s, 'aibom', 'ai').tone, 'warn');
});
test('missing inventory: with and without displayed source observations', () => {
  const withSrc = base({ cryptoPage: page({ producers: [prod('supplemental_observation', 'completed')], assets: [asset('supplemental_observation')] }) });
  assert.equal(text(withSrc, 'cbom', 'crypto'), 'No CBOM available · Source observations only');
  const html = renderEvidenceStrip(withSrc, 'crypto'); assert.match(html, /Source observations displayed/);
  const without = base({ cryptoPage: page({ producers: [], availability: { state: 'not_run', reason_code: 'not_configured', message: 'm' } }) });
  assert.equal(text(without, 'cbom', 'crypto'), 'No CBOM available');
  const h2 = renderEvidenceStrip(without, 'crypto'); assert.doesNotMatch(h2, /Source observations only/); assert.match(h2, /No source observations displayed/);
  // a collected source scan that observed nothing is never "Source observations only"
  const empty = base({ cryptoPage: page({ producers: [prod('supplemental_observation', 'completed')], assets: [], all: 0, availability: { state: 'completed_empty', reason_code: 'no_applicable_assets', message: 'm' } }) });
  assert.equal(text(empty, 'cbom', 'crypto'), 'No CBOM available');
});
test('not run, unsupported, generation failure and invalid document are distinct', () => {
  const mk = (outcome, av, cardScan) => base({ aiPage: page({ producers: [prod('original_artifact', outcome)], availability: av }), cards: [card('sbom'), cardScan ? card('aibom', { scan: cardScan }) : card('aibom')] });
  assert.equal(text(mk('not_run', { state: 'not_run', reason_code: 'disabled', message: 'm' }), 'aibom', 'ai'), 'AI-BOM step not run');
  assert.equal(inventoryStatus(mk('not_run', { state: 'not_run', reason_code: 'disabled', message: 'm' }), 'aibom', 'ai').tone, 'neutral');
  assert.equal(text(mk('unsupported', { state: 'unsupported', reason_code: 'unsupported_ecosystem', message: 'm' }), 'aibom', 'ai'), 'AI-BOM unavailable · Input unsupported');
  assert.equal(text(mk('failed', { state: 'failed', reason_code: 'scanner_failed', message: 'm' }, { outcome: 'failed', reason: 'scanner_failed' }), 'aibom', 'ai'), 'AI-BOM generation failed');
  assert.equal(text(mk('failed', { state: 'failed', reason_code: 'output_invalid', message: 'm' }, { outcome: 'acquired' }), 'aibom', 'ai'), 'AI-BOM could not be read');
  assert.equal(text(mk('failed', { state: 'failed', reason_code: 'output_invalid', message: 'm' }), 'aibom', 'ai'), 'AI-BOM could not be read');
  // a failure whose cause is not recorded is never called a generation failure
  assert.equal(text(mk('failed', { state: 'partial', reason_code: 'partial_coverage', message: 'm' }), 'aibom', 'ai'), 'AI-BOM not usable · Cause not recorded');
});
test('loading and request error never claim absence', () => {
  assert.equal(text(base(), 'cbom', 'crypto'), 'Loading CBOM status…');
  assert.equal(text(base({ cryptoStatus: 'error' }), 'cbom', 'crypto'), 'CBOM status unavailable');
  assert.equal(text(base({ cryptoStale: true }), 'cbom', 'crypto'), 'CBOM status unavailable');
  for (const t of ['Loading CBOM status…', 'CBOM status unavailable']) assert.doesNotMatch(t, /No CBOM|not run|failed/);
  assert.equal(text(base({ aiStatus: 'loading' }), 'aibom', 'ai'), 'Loading AI-BOM status…');
});
test('Advanced views that never request the page do not claim loading', () => {
  assert.equal(text(base({ advanced: true }), 'cbom', 'crypto'), 'CBOM recorded · Not validated in this view');
});
test('captured versus live provenance', () => {
  const cap = base({ mode: 'captured', cards: [card('sbom', { producer: 'syft 1.51.1' })] });
  const live = base({ cards: [card('sbom', { scan: { outcome: 'acquired', tool: 'syft', version: '1.51.1' } })] });
  const d = (s) => Object.fromEntries(inventoryStatus(s, 'sbom', 'dependencies').details);
  assert.match(d(cap).Origin, /Captured evidence \(not a live scan\)/); assert.match(d(live).Origin, /Live scan/);
  assert.equal(d(cap).Producer, 'syft 1.51.1'); assert.equal(d(live).Producer, 'syft 1.51.1');
});
test('SBOM states come from the card or run, never from counts', () => {
  const s = (c) => base({ cards: c });
  assert.equal(text(s([card('sbom', { record_count: 0 })]), 'sbom', 'dependencies'), 'SBOM available · No assets recorded within its scope');
  assert.equal(text(s([card('sbom', { scan: { outcome: 'failed', reason: 'timeout' } })]), 'sbom', 'dependencies'), 'SBOM generation failed');
  assert.equal(text(s([card('sbom', { scan: { outcome: 'unavailable' } })]), 'sbom', 'dependencies'), 'SBOM step not run');
  assert.equal(text(s([]), 'sbom', 'dependencies'), 'SBOM status unavailable');
  const withCounts = base({ cards: [] }); withCounts.analysis.summary.components = 1989;
  assert.equal(text(withCounts, 'sbom', 'dependencies'), 'SBOM status unavailable');
});
test('mixed BOM availability: per-BOM indicators and no global comparison claim', () => {
  const s = base({ cards: [card('sbom'), card('cbom', { scan: { outcome: 'failed', reason: 'scanner_failed' } }), card('aibom', { scan: { outcome: 'unavailable' } })] });
  const m = evidenceStatus(s, 'bom'); assert.deepEqual(m.items.map((i) => i.name), ['SBOM', 'CBOM', 'AI-BOM']);
  assert.deepEqual(m.items.map((i) => i.text), ['SBOM available', 'CBOM generation failed', 'AI-BOM step not run']);
  const html = renderEvidenceStrip(s, 'bom');
  assert.match(html, /Inventory availability does not establish comparison completion or success\./);
  assert.doesNotMatch(html, /workspace|unavailable for this repository|Comparison (completed|succeeded)/i);
  assert.equal((html.match(/class="otev-item"/g) || []).length, 3);
});
test('per-tab scope lines', () => {
  const s = base();
  assert.match(renderEvidenceStrip(s, 'contexts'), /source locations recorded in the SBOM, not a complete repository file tree/);
  assert.match(renderEvidenceStrip(s, 'dependencies'), /Advisory-query coverage is reported separately\./);
  assert.equal(renderEvidenceStrip(s, 'nope'), '');
});
test('filter changes do not alter inventory availability', () => {
  const p = (filtered) => page({ producers: [prod('original_artifact', 'completed')], assets: filtered ? [] : [asset('original_artifact')], all: 7 });
  const a = base({ cryptoPage: p(false) }); const b = base({ cryptoPage: p(true) }); b.views.cryptoPage.page = { assets_total: 0 };
  assert.equal(text(a, 'cbom', 'crypto'), text(b, 'cbom', 'crypto')); assert.equal(text(b, 'cbom', 'crypto'), 'CBOM available');
});
test('another analysis status is not retained: the model reads only the current state', () => {
  const failed = base({ cryptoPage: page({ producers: [prod('original_artifact', 'failed')], availability: { state: 'failed', reason_code: 'scanner_failed', message: 'm' } }) });
  const next = base();   // a new analysis: views cleared
  assert.equal(text(failed, 'cbom', 'crypto'), 'CBOM generation failed');
  assert.equal(text(next, 'cbom', 'crypto'), 'Loading CBOM status…');
  assert.equal(renderEvidenceStrip({ ...next, busy: 'ending' }, 'crypto'), '');
  assert.equal(evidenceStatus({ ...next, analysis: null }, 'crypto'), null);
});
test('hostile producer, reason and scope strings stay inert text', () => {
  const evil = '<img src=x onerror=alert(1)>"\'&';
  const s = base({ cryptoPage: page({ producers: [{ ...prod('original_artifact', 'completed', { scope: evil, prov: { producer_version: evil } }) }] }), cards: [card('sbom', { producer: evil, scope: evil }), card('cbom', { scan: { outcome: 'failed', reason: evil, tool: evil } })] });
  for (const tab of ['crypto', 'bom', 'contexts']) { const html = renderEvidenceStrip(s, tab); assert.doesNotMatch(html, /<img/); assert.match(html, /&lt;img/); }
});
test('Details retains producer, origin, reason and scope; the disclosure is collapsed by default', () => {
  resetEvidenceDetails();
  const s = base({ aiPage: page({ producers: [prod('original_artifact', 'not_run')], availability: { state: 'not_run', reason_code: 'not_configured', message: 'm' } }) });
  const html = renderEvidenceStrip(s, 'ai');
  assert.doesNotMatch(html, /<details class="otev-details" open/);
  assert.match(html, /<dt>Producer<\/dt>/); assert.match(html, /<dt>Origin<\/dt>/); assert.match(html, /<dt>Reason<\/dt><dd>not configured/); assert.match(html, /<dt>Scope<\/dt>/);
  assert.match(html, /No AI inventory is available for this live scan|AI inventory/);   // the approved live AI-banner meaning lives in Details
});
test('live crypto note moved into Details; every state has an icon, a text and a tone', () => {
  assert.match(renderEvidenceStrip(base(), 'crypto'), /A scan that completes with zero cryptographic assets is a finished result/);
  for (const code of STATE_CODES) assert.ok(code);
  const html = renderEvidenceStrip(base(), 'bom'); assert.match(html, /<svg class="otev-icon"[^>]*aria-hidden="true"/);
});
test('the strip is mounted under the tabs, tab names unchanged, no new fetch', () => {
  const wb = readFileSync(new URL('../../../src/ui/components/workbench.js', import.meta.url), 'utf8');
  assert.ok(wb.indexOf('role="tablist"') < wb.indexOf('renderEvidenceStrip(s, tab') && wb.indexOf('renderEvidenceStrip(s, tab') < wb.indexOf('ot-layer-note'));
  for (const f of ['lib/evidence_status.js', 'components/evidence_strip.js']) assert.doesNotMatch(readFileSync(new URL('../../../src/ui/' + f, import.meta.url), 'utf8'), /\bfetch\(|api\(|dispatch\(|setTimeout|setInterval/);
});
test('CSS: scoped, wraps, no hex, no green/red semantics', () => {
  const css = readFileSync(new URL('../../../src/ui/styles/app.css', import.meta.url), 'utf8'); const i = css.indexOf('UI-EVIDENCE-STATUS-01'); const block = css.slice(i);
  assert.ok(i > 0); assert.doesNotMatch(block, /#[0-9a-fA-F]{3,8}\b/); assert.doesNotMatch(block, /--red|--teal|--dep-path|--dep-match/); assert.match(block, /flex-wrap:wrap/); assert.match(block, /overflow-wrap:anywhere/);
});
test('BOM tab: no ambiguous per-BOM source chips', () => {
  const s = base({ cryptoPage: page({ producers: [prod('original_artifact', 'completed'), prod('supplemental_observation', 'completed')], assets: [asset('supplemental_observation')] }) });
  assert.equal(evidenceStatus(s, 'bom').sources.length, 0); assert.equal(evidenceStatus(s, 'crypto').sources.length, 1);
  assert.equal((renderEvidenceStrip(s, 'bom').match(/data-role="source"/g) || []).length, 0);
});
test('two supplemental producers (one not run, one collected): source observations are displayed; the legacy capture label agrees', async () => {
  const { captureLabel } = await import('../../../src/ui/lib/crypto_graph.js');
  const pg = page({ producers: [prod('original_artifact', 'completed'), prod('supplemental_observation', 'not_run'), prod('supplemental_observation', 'completed')], assets: [asset('supplemental_observation')] });
  assert.equal(evidenceStatus(base({ cryptoPage: pg }), 'crypto').sources[0].code, 'displayed');
  assert.match(captureLabel(pg), /Experimental source observations/); assert.doesNotMatch(captureLabel(pg), /not collected/);
  const none = page({ producers: [prod('original_artifact', 'completed'), prod('supplemental_observation', 'not_run')] });
  assert.match(captureLabel(none), /Source observations not collected/);
});
test('ESR-01: a live AI/crypto tab prints no captured-mode layer note; captured and other tabs keep theirs', () => {
  const wb = readFileSync(new URL('../../../src/ui/components/workbench.js', import.meta.url), 'utf8');
  assert.ok(wb.includes("isLive(s) && (tab === 'ai' || tab === 'crypto') ? '' : `<p class=\"ot-help ot-layer-note\">"));
});
test('ESR-04: a reason belonging to another producer is not shown; ESR-06: absent card is unknown', () => {
  const s = base({ aiPage: page({ producers: [prod('original_artifact', 'not_run'), prod('supplemental_observation', 'unsupported')], availability: { state: 'unsupported', reason_code: 'unsupported_ecosystem', message: 'm' } }) });
  const i = inventoryStatus(s, 'aibom', 'ai'); assert.equal(i.text, 'AI-BOM step not run'); assert.ok(!i.details.some(([k]) => k === 'Reason'));
  assert.equal(text(base({ mode: 'captured', cards: [card('sbom')] }), 'cbom', 'bom'), 'CBOM status unavailable');
});
test('source observations collected but none on the current page: never "displayed" / "Source observations only"; inventory status unchanged', () => {
  const sup = prod('supplemental_observation', 'completed');
  for (const producers of [[sup], [prod('original_artifact', 'completed'), sup]]) {
    const s = base({ cryptoPage: page({ producers, assets: [], all: 6 }) });   // filter/offset returns nothing, whole set has 6
    const m = evidenceStatus(s, 'crypto'); assert.equal(m.sources[0].code, 'collected_not_on_page'); assert.equal(m.sources[0].text, 'Source observations collected · None on this page');
    assert.doesNotMatch(renderEvidenceStrip(s, 'crypto'), /Source observations only|Source observations displayed/);
  }
  const noInv = base({ cryptoPage: page({ producers: [prod('supplemental_observation', 'completed')], assets: [], all: 6 }) });
  assert.equal(text(noInv, 'cbom', 'crypto'), 'No CBOM available');
  const withInv = base({ cryptoPage: page({ producers: [prod('original_artifact', 'completed'), prod('supplemental_observation', 'completed')], assets: [], all: 6 }) });
  assert.equal(text(withInv, 'cbom', 'crypto'), 'CBOM available');
  const shown = base({ cryptoPage: page({ producers: [prod('supplemental_observation', 'completed')], assets: [asset('supplemental_observation')], all: 6 }) });
  assert.equal(text(shown, 'cbom', 'crypto'), 'No CBOM available · Source observations only');
});
