// I5C: the source-backed check keeps the source observation, the CBOM record and the rule conclusion in three separate blocks.
// Run: node --test tests/ui/unit/        (Node >= 22)
import test from 'node:test';
import assert from 'node:assert/strict';
import { renderSourceChecks, sourceObservation, cbomRecord, ruleConclusion } from '../../../src/ui/components/sourcecheck.js';

const PATH = 'clients/mcpdo/src/connection/auth-helper.ts';
const COMMIT = '074b8108f340590268f2900741403755e923a11c';
const observation = { evidence_id: 'ev', repository: 'https://github.com/modelcontextprotocol/inspector', commit: COMMIT, path: PATH, line: 76,
  excerpt: '  const hash = createHash("sha256").update(key).digest("hex").slice(0, 16);', file_sha256: '9fae566d7fdf1161b02e1bec8ff0f2b19a1dd4ff9eb4e50c236f7e0e35adc450',
  resolution: { call: 'node:crypto.createHash', module: 'node:crypto', literal_algorithm: 'sha256', import_line: 2, import_text: 'import { createHash } from "node:crypto";', method: 'static reading' } };
const document = { acquired: true, artifact: 'cdxgen-cbom.cdx.json', spec_version: '1.6', sha256: 'a'.repeat(64), producer: { name: 'cdxgen', version: '12.9.0' } };
const matching = { name: 'sha-256', bom_ref: 'crypto/algorithm/sha-256@2.16.840.1.101.3.4.2.1', file: PATH, line: 76, context: 'hash', match: 'location_in_range' };
const conclusion = { state: 'supported', rule_id: 'crypto_attribution.operation_declared_in_cbom/3', reason_codes: ['call_site_in_range_unique'], rationale: 'Supported (declaration level): agree.',
  not_established: ['that the code runs'], next_action: null, algorithm_alias: { applied: true, source_value: 'sha256', cbom_value: 'sha-256' } };
const check = (over = {}) => ({ status: 'observed', assertion_id: 'live-src-crypto-x', source_observation: observation,
  cbom_record: { document, matching_occurrence: matching, candidates: [] }, conclusion, ...over });

test('renders nothing without a source check', () => {
  assert.equal(renderSourceChecks({}), '');
  assert.equal(renderSourceChecks({ source_checks: [] }), '');
});

test('the three blocks are separate and each carries only its own facts', () => {
  const html = renderSourceChecks({ source_checks: [check()] });
  const blocks = html.split('<section ').slice(1);
  assert.equal(blocks.length, 3);
  const [src, cbom, rule] = blocks;
  assert.match(src, /Source observation/); assert.match(cbom, /CBOM record/); assert.match(rule, /Rule conclusion/);
  assert.match(src, /auth-helper\.ts/); assert.match(src, /createHash\(&quot;sha256&quot;\)/); assert.match(src, new RegExp(COMMIT));
  assert.match(src, /9fae566d/);
  assert.doesNotMatch(src, /declaration agrees|operation_declared_in_cbom|<code>sha-256<\/code>/i);   // no conclusion, no CBOM value in the observation
  assert.match(cbom, /sha-256/); assert.match(cbom, new RegExp(PATH + ':76'));
  assert.doesNotMatch(cbom, /createHash|declaration agrees|operation_declared_in_cbom/i);
  assert.match(rule, /operation_declared_in_cbom\/3/); assert.match(rule, /declaration agrees/i);
  assert.doesNotMatch(rule, /9fae566d|createHash\(&quot;/);
});

test('the alias is shown with both raw values', () => {
  const rule = ruleConclusion(conclusion, 'live-src-crypto-x');
  assert.match(rule, /source <code>sha256<\/code> · CBOM <code>sha-256<\/code>/);
});

test('no CBOM acquired: the record block says nothing to compare and the conclusion stays unconfirmed', () => {
  const html = renderSourceChecks({ source_checks: [check({ cbom_record: { document: { acquired: false, outcome: 'failed', reason: 'nonzero_exit' }, matching_occurrence: null, candidates: [] },
    conclusion: { ...conclusion, state: 'unverifiable', reason_codes: ['no_compatible_cbom_document'], rationale: 'Unverifiable: none.', algorithm_alias: { applied: false } } })] });
  assert.match(html, /No CBOM document was acquired/); assert.match(html, /could not confirm/i); assert.doesNotMatch(html, /declaration agrees/i);
});

test('an asset at another line is listed as an other occurrence, not a match', () => {
  const html = cbomRecord({ document, matching_occurrence: null, candidates: [{ ...matching, line: 80, match: 'same_file_other_line' }] });
  assert.match(html, /no occurrence is matched to the observed file and line/i); assert.match(html, new RegExp(PATH + ':80'));
});

test('two occurrences in range are shown as candidates and none is singled out', () => {
  const html = cbomRecord({ document, matching_occurrence: null, candidates: [{ ...matching, match: 'location_in_range' }, { ...matching, bom_ref: 'second', match: 'location_in_range' }] });
  assert.match(html, /2 occurrences lie in the observed range, so none is singled out/); assert.match(html, /Candidate occurrences/);
  assert.doesNotMatch(html, /Asset \(as recorded\)/);
});

test('a skipped target is shown as skipped and nothing is assessed', () => {
  const html = renderSourceChecks({ source_checks: [{ status: 'skipped', file: PATH, line: 77, reason: 'several_calls_on_line' }] });
  assert.match(html, /Skipped/); assert.match(html, /nothing was assessed/); assert.doesNotMatch(html, /Rule conclusion/);
});

test('repository text is escaped', () => {
  const html = sourceObservation({ ...observation, excerpt: '<img src=x onerror=alert(1)>' });
  assert.doesNotMatch(html, /<img/); assert.match(html, /&lt;img/);
});
