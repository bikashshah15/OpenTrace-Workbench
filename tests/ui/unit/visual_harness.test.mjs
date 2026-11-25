// UIP-02 §7.10: the visual harness's pure parts — metric, threshold rule, loopback guard, PNG round trip, capture records.
import test from 'node:test';
import assert from 'node:assert/strict';
import { diffStats, thresholdFor, summarize, isLoopbackUrl, encodePng, decodePng, sideBySide, captureRecord, RECORD_FIELDS, sha256, SETTINGS, CaptureError, checkExpectation, walkStates, assertMatrix, reviewableCoverage, APP_STATE_IDS, REFERENCE_STATE_IDS, VIEWPORTS, THEMES } from '../../../tools/uip/visual/lib.mjs';

const img = (w, h, fill = [10, 20, 30, 255]) => { const data = Buffer.alloc(w * h * 4); for (let i = 0; i < w * h; i++) data.set(fill, i * 4); return { width: w, height: h, data }; };

test('difference metric: identical is 0, one differing pixel, any channel, size mismatch is 1.0', () => {
  const a = img(10, 10); const b = img(10, 10);
  assert.deepEqual([diffStats(a, b).ratio, diffStats(a, b).pixels], [0, 0]);
  b.data[4 * 7 + 3] = 254;                       // alpha channel of one pixel
  assert.deepEqual([diffStats(a, b).ratio, diffStats(a, b).pixels, diffStats(a, b).total], [0.01, 1, 100]);
  const c = img(10, 10); c.data[0] = 11; c.data[4] = 11; assert.equal(diffStats(a, c).pixels, 2);
  const m = diffStats(a, img(10, 11)); assert.deepEqual([m.ratio, m.sizeMismatch], [1, true]);
});

test('threshold rule: 2 x max rounded up to 1e-6; zero variance gives 0; only the measurement is an input', () => {
  assert.equal(thresholdFor(0), 0);
  assert.equal(thresholdFor(0.0001), 0.0002);
  assert.equal(thresholdFor(0.0000011), 0.000003);   // 2.2e-6 rounds UP to 3e-6
  assert.equal(thresholdFor(1), 2);
  assert.equal(thresholdFor.length, 1, 'no slack/regression parameter');
  assert.deepEqual(summarize([]), { comparisons: 0, max: 0, mean: 0, threshold: 0 });
  const s = summarize([0, 0.00001, 0.00003]); assert.equal(s.max, 0.00003); assert.equal(s.threshold, 0.00006); assert.equal(s.comparisons, 3);
  assert.equal(summarize([0, 0, 0]).threshold, 0);
});

test('loopback guard: only loopback HTTP/WS and non-network schemes are allowed', () => {
  for (const u of ['http://127.0.0.1:8123/api/config', 'http://localhost:1/x', 'ws://127.0.0.1:9222/devtools', 'data:text/html,x', 'about:blank', 'blob:http://127.0.0.1/abc']) assert.equal(isLoopbackUrl(u), true, u);
  for (const u of ['https://github.com/a/b', 'http://example.com/', 'http://127.0.0.1.evil.com/', 'http://10.0.0.1/', 'https://api.osv.dev/v1', 'ftp://127.0.0.1/', 'not a url', '']) assert.equal(isLoopbackUrl(u), false, u);
});

test('PNG encode/decode round trip and side-by-side composition', () => {
  const a = img(7, 5, [1, 2, 3, 255]); a.data.set([200, 100, 50, 255], 4 * 9);
  const back = decodePng(encodePng(a)); assert.equal(back.width, 7); assert.equal(back.height, 5); assert.ok(back.data.equals(a.data));
  const sbs = sideBySide(a, img(4, 9)); assert.deepEqual([sbs.width, sbs.height], [7 + 12 + 4, 9]);
  assert.equal(sha256(Buffer.from('x')).length, 64);
});

test('capture record requires every field and a well-formed digest', () => {
  const ok = Object.fromEntries(RECORD_FIELDS.map((k) => [k, k === 'png_sha256' ? 'a'.repeat(64) : 'v']));
  assert.deepEqual(Object.keys(captureRecord(ok)), RECORD_FIELDS);
  for (const k of RECORD_FIELDS) { const bad = { ...ok }; delete bad[k]; assert.throws(() => captureRecord(bad), /missing/, k); }
  assert.throws(() => captureRecord({ ...ok, png_sha256: 'zz' }), /png_sha256/);
  for (const k of ['reference_hash', 'tested_commit', 'fixture', 'viewport', 'theme', 'tab', 'selection', 'browser', 'device_scale_factor', 'fonts', 'readiness']) assert.ok(RECORD_FIELDS.includes(k), k);
  assert.equal(SETTINGS.repeats, 10); assert.equal(SETTINGS.deviceScaleFactor, 1);
});

// ------------------------------------------------------------------ UIP-02-IR-04: fail-closed state walking (mock page, no browser)
const mockPage = () => { const p = { closed: 0, close: async () => { p.closed++; } }; return p; };
const harness = (observed) => { const log = { sunk: [], captured: [] }; return { log, hooks: { observe: async () => observed, capture: async (pg, st) => { log.captured.push(st.id); return Buffer.from(st.id); }, sink: async (r) => { log.sunk.push(r.state); } } }; };
const STATES = [
  { id: 'home', run: async () => {}, expect: { page: 'analyze' } },
  { id: 'workbench-contexts', run: async () => {}, expect: { page: 'workbench', layer: 'contexts' } },
];

test('a failed interaction throws, is never captured or recorded as that state, and the page is closed', async () => {
  const pg = mockPage(); const h = harness({ page: 'analyze', layer: 'contexts', theme: 'light' });
  const states = [{ id: 'home', run: async () => {}, expect: { page: 'analyze' } }, { id: 'inspector-contexts', run: async () => { throw new Error('click failed'); }, expect: {} }];
  await assert.rejects(walkStates(states, pg, h.hooks, { theme: 'light' }), (e) => e instanceof CaptureError && /state inspector-contexts: the interaction failed: click failed/.test(e.message));
  assert.deepEqual(h.log.sunk, ['home']); assert.deepEqual(h.log.captured, ['home']); assert.equal(pg.closed, 1);
});

test('a missing selection / control (the step finds nothing) fails; the old silent "found: false" cannot be recorded', async () => {
  const pg = mockPage(); const h = harness({ page: 'workbench', layer: 'contexts' });
  const states = [{ id: 'inspector-contexts', run: async () => { throw new CaptureError('control [data-context-root] was not found'); }, expect: {} }];
  await assert.rejects(walkStates(states, pg, h.hooks), /was not found/); assert.deepEqual(h.log.sunk, []); assert.equal(pg.closed, 1);
});

test('the wrong destination, tab, selection or a missing observation fails before any capture', async () => {
  for (const [observed, re] of [[{ page: 'analyze', layer: 'contexts' }, /page: expected "workbench", observed "analyze"/], [{ page: 'workbench', layer: 'crypto' }, /layer: expected "contexts", observed "crypto"/], [{ page: 'workbench' }, /layer: expected "contexts", observed undefined/], [null, /no page state was observed/]]) {
    const pg = mockPage(); const h = harness(observed);
    await assert.rejects(walkStates([STATES[1]], pg, h.hooks), re); assert.deepEqual(h.log.captured, []); assert.deepEqual(h.log.sunk, []); assert.equal(pg.closed, 1);
  }
});

test('the requested theme is a postcondition for every state', async () => {
  const pg = mockPage(); const h = harness({ page: 'analyze', theme: 'light' });
  await assert.rejects(walkStates([STATES[0]], pg, h.hooks, { theme: 'dark' }), /theme: expected "dark", observed "light"/); assert.deepEqual(h.log.sunk, []);
  const ok = harness({ page: 'analyze', theme: 'dark' }); assert.deepEqual(await walkStates([STATES[0]], mockPage(), ok.hooks, { theme: 'dark' }), ['home']);
});

test('expectations accept exact values, patterns and predicates and reject everything else', () => {
  checkExpectation('s', { a: 'x', b: /^ctx:/, c: (v) => v > 1 }, { a: 'x', b: 'ctx:1', c: 2 });
  for (const bad of [{ a: 'y', b: 'ctx:1', c: 2 }, { a: 'x', b: 'zzz', c: 2 }, { a: 'x', b: 'ctx:1', c: 1 }, { a: 'x', b: 'ctx:1' }]) assert.throws(() => checkExpectation('s', { a: 'x', b: /^ctx:/, c: (v) => v > 1 }, bad), CaptureError);
});

test('state expectations can depend on the viewport (expectFor) and the page still closes on success', async () => {
  const st = { id: 'inspector-contexts', run: async () => {}, expectFor: (c) => ({ record_id: c.vp.mobile ? /^ctx:/ : 'root' }) };
  const pg = mockPage(); const h = harness({ record_id: 'ctx:a' });
  assert.deepEqual(await walkStates([st], pg, h.hooks, { vp: { mobile: true } }), ['inspector-contexts']); assert.equal(pg.closed, 1);
  await assert.rejects(walkStates([st], mockPage(), harness({ record_id: 'ctx:a' }).hooks, { vp: { mobile: false } }), /record_id: expected "root"/);
});

test('a failing page.close() does not mask the capture error', async () => {
  const pg = { close: async () => { throw new Error('close failed'); } };
  await assert.rejects(walkStates([{ id: 'home', run: async () => { throw new Error('boom'); } }], pg, harness({}).hooks), /boom/);
});

test('an incomplete required matrix is an error naming what is missing; duplicates are errors', () => {
  const recs = []; for (const vp of ['1366', '390']) for (const th of ['light', 'dark']) { for (const s of APP_STATE_IDS) recs.push({ path: `app_${vp}_${th}_${s}.png` }); for (const s of REFERENCE_STATE_IDS) recs.push({ path: `reference_${vp}_${th}_${s}.png` }); }
  assert.equal(assertMatrix(recs, { app: APP_STATE_IDS, reference: REFERENCE_STATE_IDS }, ['1366', '390'], ['light', 'dark']), recs.length);
  assert.throws(() => assertMatrix(recs.slice(1), { app: APP_STATE_IDS, reference: REFERENCE_STATE_IDS }, ['1366', '390'], ['light', 'dark']), /incomplete: missing 1 \(app_1366_light_home\.png\)/);
  assert.throws(() => assertMatrix(recs, { app: APP_STATE_IDS, reference: REFERENCE_STATE_IDS }, ['1920'], ['light']), /missing 9/);
  assert.throws(() => assertMatrix([...recs, recs[0]], { app: APP_STATE_IDS, reference: REFERENCE_STATE_IDS }, ['1366'], ['light']), /duplicated app_1366_light_home\.png/);
});

test('committed-evidence coverage names every missing reviewable image (the six wide inspector captures)', () => {
  const vps = VIEWPORTS.map((v) => v.id); const all = reviewableCoverage(vps, THEMES, () => false);
  assert.equal(all.length, 3 * 2 * (3 + 3)); assert.ok(all.includes('app/app_1920_dark_inspector-ai.png') && all.includes('side-by-side/sbs_390_light_home.png'));
  const have = new Set(all.filter((p) => !/^app\/app_1920_/.test(p))); const present = (p) => have.has(p);
  const missing = reviewableCoverage(vps, THEMES, (p) => present(p));
  assert.deepEqual(missing.sort(), ['dark', 'light'].flatMap((th) => ['inspector-ai', 'inspector-crypto', 'inspector-dependencies'].map((s) => `app/app_1920_${th}_${s}.png`)).sort());
  assert.deepEqual(reviewableCoverage(vps, THEMES, () => true), []);
});
