// Evidence tab: compact inventory cards (Details collapsed), supporting-evidence rows, Preview eye icon, empty sections hidden.
// Same renderer for the captured Frigate demo and live results. Pure string render; no browser, network or service.
import test from 'node:test';
import assert from 'node:assert/strict';
import { initial, freshWorkbench } from '../../../src/ui/lib/store.js';
import { renderEvidence } from '../../../src/ui/components/evidence.js';

const sha = 'a'.repeat(64);
const scan = (kind, over = {}) => ({ outcome: 'acquired', tool: kind === 'cbom' ? 'cdxgen' : 'syft', version: '1.2.3', pinned_version: '1.2.3', isolation: 'sandbox', record_count: 3, record_count_unit: 'components', meaning: 'm',
  scope: { basis: 'whole repository', file_count: 10, listing_sha256: sha }, sha256: sha, size: 100, warnings: ['WARN-ONE'], ...over });
const card = (kind, live, over) => ({ kind, artifact_name: `${kind}.json`, ...(live ? { scan: scan(kind, over) } : {}) });
const art = (name, kind = 'original') => ({ name, kind, size: 100, sha256: sha });
const mk = (live, { cards, arts, records = [], checks = [], summary = {} } = {}) => ({ ...initial(), destination: 'evidence', workbench: freshWorkbench(false),
  analysis: { generation: 1, identity: { mode: live ? 'live' : 'captured', owner: 'acme', name: 'widget', commit: 'abcdef0123456789abcdef0123456789abcdef01', analysis_digest: 'sha256:' + sha },
    summary: { components: 1, edges: 0, advisory_groups: 44, inventory_checks: 0, checks, source_checks: [], cards: cards || [card('aibom', live), card('sbom', live), card('cbom', live)], ...summary } },
  evidence: { artifacts: arts || [], records, preview: null } });
const derived = ['bombridge-result.json', 'source-declarations.json', 'advisory-lookup.json'].map((n) => art(n, 'derived'));
const inv = ['sbom', 'cbom', 'aibom'].map((k) => art(`${k}.json`));

for (const live of [false, true]) {
  const mode = live ? 'live' : 'demo';
  test(`${mode}: inventory cards in SBOM, CBOM, AI-BOM order with Preview (eye), Download and a collapsed Details`, () => {
    const html = renderEvidence(mk(live, { arts: [...inv, ...derived], summary: live ? { advisory_lookup: { lookup: 'complete', states: {} } } : {} }));
    const titles = [...html.matchAll(/<h3>([^<]+)<\/h3>/g)].map((m) => m[1]).slice(0, 3);
    assert.deepEqual(titles, ['Software inventory (SBOM)', 'Cryptography inventory (CBOM)', 'AI model inventory (AI-BOM)']);
    const cards = [...html.matchAll(/<article class="ot-small-card" data-inventory="[\s\S]*?<\/article>/g)].map((m) => m[0]);
    assert.equal(cards.length, 3);
    for (const c of cards) {
      assert.match(c, /<button type="button" class="button small" data-action="preview" data-name="[a-z]+\.json" ><svg class="ot-eye"[^>]*aria-hidden="true"[\s\S]*?<\/svg>Preview<\/button>/);
      assert.match(c, /Download/); assert.match(c, /<details class="ot-more"><summary>Details<\/summary>/); assert.doesNotMatch(c, /<details[^>]* open/);
      const outside = c.replace(/<details[\s\S]*?<\/details>/, '');
      assert.doesNotMatch(outside, /sha256|isolation|Scanner|Isolation|Scope/i, 'technical facts live only inside Details');
      assert.match(c, /<details[\s\S]*sha256[\s\S]*<\/details>/);
    }
    if (live) { assert.match(cards[0], /Scanner<\/dt><dd>syft 1\.2\.3/); assert.match(cards[0], /Scanner messages \(1\)[\s\S]*WARN-ONE/); assert.match(cards[0], /3 components reported/); }
  });
}
test('live: a failed inventory shows its failure visibly, no Preview or Download, and Details keeps the technical facts', () => {
  const html = renderEvidence(mk(true, { cards: [card('sbom', true), card('cbom', true, { outcome: 'failed', reason: 'timeout', sha256: null })], arts: [art('sbom.json')] }));
  const c = html.match(/data-inventory="cbom"[\s\S]*?<\/article>/)[0];
  assert.match(c, /role="alert"><strong>Failed\.<\/strong> timeout/); assert.doesNotMatch(c, /data-action="preview"|Download/); assert.match(c, /<summary>Details<\/summary>[\s\S]*Isolation/);
});
test('supporting evidence rows: friendly labels, original filenames and downloads kept, no BOMBridge in the visible tab', () => {
  for (const live of [false, true]) {
    const html = renderEvidence(mk(live, { arts: [...inv, ...derived], summary: { advisory_lookup: { lookup: 'complete', states: { match: 5 } }, gaps: { status: 'compared', totals: { candidates: 3 } } } }));
    const rows = [...html.matchAll(/<div class="group-record ot-support-row" data-artifact="([^"]+)">([\s\S]*?)<\/div>(?=<div class="group-record ot-support-row"|<\/div>)/g)];
    assert.equal(rows.length, 3, 'three compact rows and no separate advisory row');
    const label = { 'bombridge-result.json': 'Inventory assessment record', 'source-declarations.json': 'Source evidence', 'advisory-lookup.json': 'Advisory lookup record' };
    for (const [, name, body] of rows) {
      assert.match(body, new RegExp(`<strong>${label[name]}</strong>`)); assert.match(body, new RegExp(`download="${name}"`)); assert.match(body, new RegExp(`data-action="preview" data-name="${name}"`)); assert.match(body, /class="ot-eye"/);
    }
    assert.match(html, /<h2>Supporting evidence<\/h2>/); assert.doesNotMatch(html, /BOMBridge|Derived output|BOM comparison results/);
    assert.match(html, /Recorded inventory information and any checks included in the assessment\./);
    assert.match(html, /Repository observations, including dependency declarations, cryptography calls, and AI model references when collected\./);
    assert.match(html, /View comparisons in BOM connections/);
  }
});
test('one short advisory status; the old long card is gone and the full breakdown is in a collapsed Details', () => {
  for (const live of [false, true]) {
    const html = renderEvidence(mk(live, { arts: [...inv, ...derived], summary: live ? { advisory_lookup: { lookup: 'complete', states: { match: 5, no_match: 2 }, lockfile_only: { match: 2 } } } : {} }));
    assert.equal((html.match(/data-advisory-status="1"/g) || []).length, 1);
    assert.doesNotMatch(html, /ot-adv-capture|<h3>Package advisory/);
    assert.match(html, live ? /Lookup complete \u00b7 44 advisory groups matched[\s\S]*data-action="open-tab" data-tab="dependencies"/ : /Captured advisory snapshot \u00b7 44 advisory groups matched/);
    const d = html.match(/<details class="ot-more" id="ot-evidence-lookup">[\s\S]*?<\/details>/)[0]; assert.doesNotMatch(d, / open/);
    assert.match(d, live ? /5 advisory match, 2 no advisory returned[\s\S]*2 of the matches are on lockfile-only/ : /1775 unique version queries/);
    assert.equal(html.replace(d, '').includes('no advisory returned'), false);
  }
});
test('advisory status stays visible without a downloadable lookup record (unavailable, skipped, not enabled), with no Preview/Download', () => {
  const only = (L, live = true) => renderEvidence(mk(live, { arts: inv, summary: L === undefined ? {} : { advisory_lookup: L } }));
  for (const [L, re] of [[{ lookup: 'unavailable' }, /Lookup unavailable/], [{ lookup: 'not_run' }, /Lookup not run/], [undefined, /Advisory matching not run/]]) {
    const html = only(L); const row = html.match(/data-artifact="advisory-status">[\s\S]*?<\/details><\/span><\/div>/)[0];
    assert.match(row, re); assert.doesNotMatch(row, /advisory groups matched/); assert.doesNotMatch(row, /data-action="preview"|download=/);
  }
  assert.match(only(undefined), /not enabled for this service/);
});
test('the BOM link appears only when the active analysis has comparison results; no link for a not-compared analysis', () => {
  const sum = (g) => ({ advisory_lookup: { lookup: 'complete', states: {} }, ...(g ? { gaps: g } : {}) });
  assert.match(renderEvidence(mk(true, { arts: [...inv, ...derived], summary: sum({ status: 'compared', totals: { candidates: 0 } }) })), /View comparisons in BOM connections/);
  for (const g of [undefined, { status: 'not_compared', code: 'collection_not_run' }]) assert.doesNotMatch(renderEvidence(mk(true, { arts: [...inv, ...derived], summary: sum(g) })), /View comparisons in BOM connections/);
});
test('empty Inventory checks and Records sections are hidden; present ones still render', () => {
  for (const live of [false, true]) {
    const empty = renderEvidence(mk(live, { arts: inv })); assert.doesNotMatch(empty, /Inventory checks|Records behind the findings|ot-findings/);
    const full = renderEvidence(mk(live, { arts: inv, checks: [{ assertion_id: 'p5-requirement-represented-in-inventory', rule_id: 'r', state: 'contradicted' }], records: [{ evidence_id: 'ev1', label: 'used', record: { method: 'm' } }] }));
    assert.match(full, /Inventory checks/); assert.match(full, /Records behind the findings/); assert.match(full, /data-action="record" data-id="ev1"/);
  }
});
