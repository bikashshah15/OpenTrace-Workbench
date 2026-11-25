// Artifact preview: formatted-JSON display and full-artifact snippet search (pure helpers in src/ui/lib/preview.js).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { indentJson, formatArtifact, searchArtifact, DISPLAY_LIMIT, MAX_HITS } from '../../../src/ui/lib/preview.js';

const doc = { bomFormat: 'CycloneDX', components: [{ name: 'a', hashes: [{ alg: 'SHA-256', content: 'x' }] }], metadata: { tools: [{ name: 'syft' }] } };

test('one-line and already-indented JSON both display with the same two-space layout', () => {
  const a = formatArtifact(JSON.stringify(doc)); const b = formatArtifact(JSON.stringify(doc, null, 4));
  assert.equal(a.json, true); assert.equal(a.shown, b.shown); assert.equal(a.shown, JSON.stringify(doc, null, 2));
  assert.match(a.shown, /\n {2}"components": \[\n {4}\{/); assert.equal(a.truncated, false);
});
test('regression: a large integer, a duplicate key and string escapes survive formatting token for token', () => {
  const src = '{"id":12345678901234567890123,"f":1.0e+2,"a":1,"a":2,"s":"q\\"\\u00e9\\n  { , : }","e":{},"l":[],"n":[null,true,-0.50]}';
  const r = formatArtifact(src);
  assert.equal(r.json, true);
  assert.match(r.shown, /"id": 12345678901234567890123,/, 'the large integer keeps every digit');
  assert.match(r.shown, /"f": 1\.0e\+2,/); assert.match(r.shown, /-0\.50/);
  assert.equal((r.shown.match(/"a": /g) || []).length, 2, 'both duplicate keys remain, in order'); assert.ok(r.shown.indexOf('"a": 1') < r.shown.indexOf('"a": 2'));
  assert.ok(r.shown.includes('"s": "q\\"\\u00e9\\n  { , : }"'), 'string content and escapes are byte-identical');
  assert.match(r.shown, /"e": \{\},/); assert.match(r.shown, /"l": \[\],/);
  // Only whitespace outside strings differs: removing every whitespace outside strings from both sides gives the same text.
  const strip = (s) => s.replace(/"(?:[^"\\]|\\.)*"|\s+/g, (m) => (m[0] === '"' ? m : ''));
  assert.equal(strip(r.shown), strip(src));
  assert.notEqual(JSON.stringify(JSON.parse(src), null, 2), r.shown, 'JSON.stringify would have changed the number and dropped a key');
});
test('indentJson uses two spaces at every depth and is stable when applied twice', () => {
  const s = indentJson('{"a":[{"b":[1,2]}],"c":"x"}');
  assert.equal(s, '{\n  "a": [\n    {\n      "b": [\n        1,\n        2\n      ]\n    }\n  ],\n  "c": "x"\n}');
  assert.equal(indentJson(s), s);
});
test('the whole document is formatted BEFORE the display limit', () => {
  const big = JSON.stringify({ rows: Array.from({ length: 30000 }, (_, i) => ({ i })) });
  const r = formatArtifact(big);
  assert.equal(r.truncated, true); assert.equal(r.shown.length, DISPLAY_LIMIT); assert.ok(r.total > big.length, 'total is the formatted length');
  assert.match(r.shown.slice(0, 40), /^\{\n {2}"rows": \[\n {4}\{/, 'the shown text is formatted, not a slice of the one-line original');
  assert.equal(formatArtifact('{"a":1}').truncated, false);
});
test('invalid JSON falls back to the plain text unchanged', () => {
  const r = formatArtifact('not json {'); assert.deepEqual([r.json, r.shown, r.truncated], [false, 'not json {', false]);
  assert.equal(formatArtifact('').json, false);
});
test('search covers the whole artifact, beyond the display limit and in one-line files, with short snippets', () => {
  const oneLine = `{"pad":"${'x'.repeat(DISPLAY_LIMIT + 5000)}","needle":"Found-Me","tail":"${'y'.repeat(500)}"}`;
  const r = searchArtifact(oneLine, 'found-me');
  assert.equal(r.hits.length, 1); assert.equal(r.hits[0].match, 'Found-Me'); assert.match(r.hits[0].where, /^character \d+$/);
  assert.ok(r.hits[0].before.length < 100 && r.hits[0].after.length < 100, 'a snippet, not the whole line');
  assert.ok(oneLine.indexOf('Found-Me') > DISPLAY_LIMIT, 'the match is beyond the display limit');
});
test('multi-line files report line numbers; several matches on one line are separate hits; empty query and no match are empty', () => {
  const text = 'alpha\nbeta gamma beta\ndelta';
  assert.deepEqual(searchArtifact(text, 'BETA').hits.map((h) => h.where), ['line 2', 'line 2']);
  assert.deepEqual(searchArtifact(text, ''), { hits: [], more: false }); assert.equal(searchArtifact(text, 'zzz').hits.length, 0);
  assert.equal(searchArtifact('a.b*c', '.b*').hits.length, 1, 'regex characters are literal');
});
test('search is capped and says when more matches exist', () => {
  const r = searchArtifact('ab '.repeat(200), 'ab'); assert.equal(r.hits.length, MAX_HITS); assert.equal(r.more, true);
});
test('dialog wiring: labels, default Overview, limited-preview text, Download original, SHA-256 check, escaped snippets', () => {
  const app = readFileSync('src/ui/app.js', 'utf8');
  assert.match(app, /\[\['readable', 'Overview'\], \['raw', 'Formatted JSON'\], \['search', 'Search'\]\]/);
  assert.match(app, /const view = \{ mode: 'readable'/);
  assert.match(app, /Preview limited\. Download the original for the full file\./); assert.match(app, />Download original ↓</);
  assert.match(app, /esc\(h\.before\)\}<mark>\$\{esc\(h\.match\)\}<\/mark>\$\{esc\(h\.after\)\}/);
  assert.match(app, /const digest = await sha256\(buf\)/); assert.match(app, /digest === header/);
  assert.doesNotMatch(app, />Readable<|>Raw<|under Raw|use Raw/); assert.match(app, /Download original to get the exact file\./);
});
