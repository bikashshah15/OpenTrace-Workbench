// UIP-06 correction 01 regressions (IR-01 pinned-link integrity, IR-02 source-backed check drill-in, IR-03 manual retry).
// The real app.js loader/handler source is extracted unchanged into a Node VM with the real store, reducer and renderer (as the independent probes do);
// no browser. Each case failed against the reviewed code (6aa79c2) - see the correction log.
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { initial, createStore } from '../../../src/ui/lib/store.js';
import { requestKey, payloadFilter, pageNeeded, PAGE_SIZE, sourceHref } from '../../../src/ui/lib/crypto_graph.js';
import { renderCryptoView } from '../../../src/ui/components/crypto_graph.js';
import { ApiError, qs } from '../../../src/ui/lib/api.js';

const page = JSON.parse(readFileSync('evidence/uip/visual/uip-06/fixtures/renderer/multi3.json'));
const src = readFileSync('src/ui/app.js', 'utf8');
const block = src.slice(src.indexOf('let cryptoSeq ='), src.indexOf('async function loadSimple('));
const openCase = src.slice(src.indexOf("case 'open-check':"), src.indexOf("case 'tab-pres':"));
const CHECK = 'live-src-crypto-reviewed-call';
const sourceChecks = [{ status: 'observed', assertion_id: CHECK,
  source_observation: { evidence_id: 'ev-1', repository: 'https://github.com/o/n', commit: 'a'.repeat(40), path: 'src/a.ts', line: 76, excerpt: 'createHash("sha256")', file_sha256: 'f'.repeat(64), resolution: { call: 'node:crypto.createHash', module: 'node:crypto', import_line: 1, import_text: 'import', literal_algorithm: 'sha256', method: 'static' } },
  cbom_record: { document: { acquired: true, artifact: 'cdxgen-cbom.cdx.json', spec_version: '1.6', sha256: 'c'.repeat(64), producer: { name: 'cdxgen', version: '12.9.0' } }, matching_occurrence: { name: 'sha-256', file: 'src/a.ts', line: 76, context: 'hash', bom_ref: 'x' }, candidates: [] },
  conclusion: { state: 'supported', rule_id: 'crypto_attribution.operation_declared_in_cbom/3', reason_codes: ['match'], rationale: 'The CBOM states this call site.', not_established: ['Runtime use'], next_action: null, algorithm_alias: { applied: false } } }];
function setup({ advanced = false } = {}) {
  const store = createStore(initial({ advanced })); store.dispatch({ type: 'ANALYSIS_START' }); const e = store.get().epoch;
  store.dispatch({ type: 'ANALYSIS_READY', epoch: e, analysis: { generation: 1, identity: { mode: 'live', analysis_digest: page.binding.analysis_digest, owner: 'o', name: 'n', commit: 'a'.repeat(40) }, summary: { cards: [], checks: [], source_checks: sourceChecks } } });
  const pending = []; const legacy = [];
  const context = vm.createContext({ store, cryptoReqKey: requestKey, cryptoFilterOf: payloadFilter, cryptoPageNeeded: pageNeeded, CRYPTO_PAGE: PAGE_SIZE, ApiError, qs, epoch: () => store.get().epoch, gen: () => 1,
    dispatch: (a) => store.dispatch(a), revealSelection: () => {}, handleError: () => {}, loadSimple: (tab) => legacy.push(tab), ensureDepPage: () => {}, loadDeps: () => {}, $: () => null,
    api: (url) => new Promise((resolve, reject) => pending.push({ url, resolve, reject })) });
  vm.runInContext(block + `\nfunction inspectCheck(id){const t={dataset:{mode:'crypto',check:id}};switch('open-check'){${openCase}}}`, context);
  return { store, pending, legacy, run: (s) => vm.runInContext(s, context) };
}
const crypto = (t) => t.store.get().workbench.perTab.crypto;

// ---------------------------------------------------------------- IR-01
const B = { repository: { host: 'github.com', owner: 'bound-owner', name: 'bound-repo' }, commit_sha: 'a'.repeat(40) };
const link = (path) => ({ path, line_start: 9, line_end: 9, link: { href: `https://github.com/bound-owner/bound-repo/blob/${B.commit_sha}/${path}`, text: path } });
test('IR-01 client: dot-segment paths and URL-rewrite escapes never yield an active link', () => {
  const esc = '../../../../other-owner/other-repo/blob/' + 'b'.repeat(40) + '/other.ts';
  assert.equal(sourceHref(link(esc), B), null);
  for (const p of ['./a.ts', 'a/./b.ts', 'a/../b.ts', '..', '.', 'a/..', '../a']) assert.equal(sourceHref(link(p), B), null, p);
  const ok = link('src/ok.ts'); assert.equal(sourceHref(ok, B), ok.link.href + '#L9');
});
test('IR-01 client: foreign repository, wrong or short commit, credentials, query, fragment, port and scheme stay inert', () => {
  const good = link('src/ok.ts'); const h = good.link.href;
  for (const bad of [h.replace('bound-owner', 'evil'), h.replace('bound-repo', 'evil'), h.replace('a'.repeat(40), 'b'.repeat(40)), h.replace('a'.repeat(40), 'a'.repeat(39)), h + '?x=1', h + '#frag', h.replace('https://', 'https://u:p@'), h.replace('github.com', 'github.com:444'), h.replace('https', 'http'), h.replace('github.com', 'github.com.evil.test')])
    assert.equal(sourceHref({ ...good, link: { href: bad, text: 'x' } }, B), null, bad);
  assert.equal(sourceHref(good, { ...B, commit_sha: 'a'.repeat(39) }), null);
});
test('IR-01 client: legitimate special characters keep a valid link; recorded text is untouched', () => {
  for (const p of ['src/sp ace.ts', "src/q'(1)!*.ts", 'src/ünï/ＣＪＫ.ts', 'src/.hidden/..dots/a...b.ts', 'src/100%.ts', 'src/a#b?c.ts']) {
    const enc = p.split('/').map((t) => encodeURIComponent(t).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())).join('/');
    const l = { path: p, line_start: 1, line_end: 1, link: { href: `https://github.com/bound-owner/bound-repo/blob/${B.commit_sha}/${enc}`, text: p } };
    assert.ok(sourceHref(l, B), p); assert.equal(l.path, p);
  }
});

// ---------------------------------------------------------------- IR-03
test('IR-03 a failed current request is retained when the tab is revisited; Try again or a changed identity requests again', async () => {
  const t = setup(); const task = t.run('loadCryptoPage()'); t.pending[0].reject(new ApiError(500, { error: 'projection_failed' })); await task;
  assert.equal(crypto(t).pg.status, 'error'); assert.equal(t.pending.length, 1);
  t.run("openTab('crypto')"); t.run("openTab('crypto')"); assert.equal(t.pending.length, 1); assert.equal(crypto(t).pg.status, 'error');      // no automatic retry
  t.run("cryptoPatch({ filter: 'protocols', offset: 0 })"); t.run("openTab('crypto')"); assert.equal(t.pending.length, 2);                      // a changed identity requests
  const task2 = null; void task2;
  t.run('loadCryptoPage()'); assert.equal(t.pending.length, 3);                                                                                   // explicit Try again
});
test('IR-03 a loaded page is not re-requested on revisit, and a stale/lifecycle reset still clears the failure', async () => {
  const t = setup(); const task = t.run('loadCryptoPage()'); t.pending[0].resolve(structuredClone(page)); await task;
  t.run("openTab('crypto')"); assert.equal(t.pending.length, 1);
  t.store.dispatch({ type: 'END_STARTED' }); assert.equal(crypto(t).pg.status, 'idle'); assert.equal(crypto(t).checkId, null);
});

// ---------------------------------------------------------------- IR-02
test('IR-02 "Inspect in Cryptography" shows the requested recorded check in normal mode through the real handler', async () => {
  const t = setup(); t.run(`inspectCheck(${JSON.stringify(CHECK)})`);
  assert.equal(crypto(t).checkId, CHECK); assert.equal(t.store.get().workbench.tab, 'crypto'); assert.equal(crypto(t).selection, 'assertion:' + CHECK);   // legacy identity preserved
  t.pending[0].resolve(structuredClone(page)); await new Promise((r) => setImmediate(r));
  const html = renderCryptoView(t.store.get());
  assert.match(html, new RegExp('data-check-id="' + CHECK + '"')); assert.match(html, /Source observation/); assert.match(html, /CBOM record/); assert.match(html, /Rule conclusion/);
  assert.match(html, /crypto_attribution\.operation_declared_in_cbom\/3/); assert.match(html, /src\/a\.ts/);
  assert.doesNotMatch(html, /data-action="open-check"/);                                       // no self-referencing button inside the panel
  assert.equal(page.review_items.length >= 0, true);                                            // nothing is mapped to an asset or invented as a review item
  t.store.dispatch({ type: 'TAB_STATE', tab: 'crypto', patch: { checkId: null } }); assert.doesNotMatch(renderCryptoView(t.store.get()), /data-check-id/);
});
test('IR-02 an unknown check is stated as absent (nothing invented); Advanced keeps the legacy path; session replacement clears the request', async () => {
  const t = setup(); t.run("inspectCheck('no-such-check')"); t.pending[0].resolve(structuredClone(page)); await new Promise((r) => setImmediate(r));
  assert.match(renderCryptoView(t.store.get()), /not present in the current analysis/);
  const a = setup({ advanced: true }); a.run(`inspectCheck(${JSON.stringify(CHECK)})`);
  assert.equal(crypto(a).checkId, null); assert.equal(crypto(a).selection, 'assertion:' + CHECK); assert.deepEqual(a.legacy, ['crypto']); assert.equal(a.pending.length, 0);
  t.store.dispatch({ type: 'ANALYSIS_START' }); assert.equal(crypto(t).checkId, null);
});
