// OFFLINE self-tests of the Stage 4 harness (node --test tests/ui/browser/run_stage4_selftest.mjs). No Chrome, no app/fixture service, no network, no provider.
// The supervisor tests spawn tiny local `node -e` helper processes (not services) to prove SIGTERM-only cleanup, descendant handling, survivor reporting and
// directory preservation. These tests establish the accounting/deadline/cleanup/routing LOGIC; they do NOT establish that the browser phases run correctly.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CEILINGS, createLedger, createDeadline, createSupervisor, createRecorder, descendantsOf, sleep } from './run_stage4_lib.mjs';
import { loadFixture, route, analysisEnvelope, handleRequest, FIXTURE_ROOT } from './run_stage4_fixtures.mjs';
import { UIP12_MATRIX, UIP13_MATRIX } from './run_stage4_cases.mjs';
import { DA_ROWS, LAUNCHES, PHASES, UNEXERCISED, COUNTS } from './run_stage4_plan.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const tmp = () => mkdtempSync(join(tmpdir(), 'ot-s4-selftest-'));
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };

// ---------------------------------------------------------------- ledger
test('ledger: cumulative, fail-closed at the ceilings, never resets', () => {
  const file = join(tmp(), 'allowance.json'); let t = 1000; const l = createLedger({ file, now: () => t });
  for (let i = 0; i < 8; i++) l.spend('service', 's' + i);
  assert.throws(() => l.spend('service', 'ninth'), /services? launches exhausted|service launches exhausted/);
  assert.equal(createLedger({ file, now: () => t }).snapshot().service, 8, 'a new ledger object over the same file sees the same count');
  for (let i = 0; i < 7; i++) l.spend('chrome', 'c' + i);
  l.spend('chrome', 'eighth chrome');
  assert.equal(l.snapshot().chrome, 8); assert.equal(l.snapshot().rerun, 0, 'rerun is only counted by markRerun');
  assert.throws(() => l.spend('chrome', 'ninth'), /chrome launches exhausted/);
});
test('ledger: the single rerun allowance cannot be spent twice; unknown kind refused; corrupt file fails closed', () => {
  const dir = tmp(); const file = join(dir, 'a.json'); const l = createLedger({ file });
  l.markRerun('first'); assert.throws(() => l.markRerun('second'), /rerun is already used/);
  assert.throws(() => l.spend('minutes', 'x'), /unknown allowance kind/);
  writeFileSync(file, '{not json'); assert.throws(() => createLedger({ file }).spend('service', 'x'));
  writeFileSync(file, JSON.stringify({ service: -1, chrome: 0, rerun: 0, events: [] })); assert.throws(() => createLedger({ file }).snapshot(), /ledger corrupt/);
});
test('ledger: planned caps reserve the last slots; they open only after markRerun and only for rerun spends; ceilings stay absolute', () => {
  const file = join(tmp(), 'p.json'); const l = createLedger({ file, planned: { service: 7, chrome: 1 } });
  for (let i = 0; i < 7; i++) l.spend('service', 's' + i); l.spend('chrome', 'c1');
  assert.throws(() => l.spend('service', 'eighth normal'), /reserved for the single harness-correction rerun/);
  assert.throws(() => l.spend('chrome', 'second chrome normal'), /reserved/);
  assert.throws(() => l.spend('service', 'rerun without marker', { rerun: true }), /reserved/, 'the reserved slot does not open without markRerun');
  l.markRerun('test'); l.spend('service', 'rerun service', { rerun: true }); l.spend('chrome', 'rerun chrome', { rerun: true });
  assert.deepEqual([l.snapshot().service, l.snapshot().chrome, l.snapshot().rerun], [8, 2, 1]);
  assert.throws(() => l.spend('service', 'ninth', { rerun: true }), /service launches exhausted/);
  assert.throws(() => l.markRerun('again'), /already used/);
});
test('ledger: the 90-minute clock starts at the first launch and refuses later launches; endAt is derived from it', () => {
  const file = join(tmp(), 'c.json'); let t = 5_000_000; const l = createLedger({ file, now: () => t });
  assert.equal(l.endAt(), null); l.spend('service', 'first'); assert.equal(l.endAt(), 5_000_000 + 90 * 60000);
  t += 89 * 60000; l.spend('service', 'within'); t += 2 * 60000; assert.throws(() => l.spend('service', 'late'), /90-minute clock exceeded/);
  assert.ok(l.remainingMs() < 0);
});

// ---------------------------------------------------------------- deadline watchdog
test('deadline: the watchdog schedules for the REMAINING time, fires onExpire once, and guard() throws afterwards', async () => {
  let t = 0, cb = null, ms = null, fired = 0; const d = createDeadline({ endAtMs: 600000, now: () => t, setTimer: (f, m) => { cb = f; ms = m; return 1; }, clearTimer: () => {}, onExpire: async () => { fired++; } }).start();
  assert.equal(ms, 600000); assert.doesNotThrow(() => d.guard());
  t = 600001; assert.throws(() => d.guard(), /DEADLINE/); await cb(); await cb(); assert.equal(fired, 1, 'onExpire runs once');
  const late = createDeadline({ endAtMs: 10, now: () => 50, setTimer: (f, m) => { ms = m; return 1; }, onExpire() {} }).start(); assert.equal(ms, 0, 'already-expired deadline fires immediately');
});

// ---------------------------------------------------------------- supervisor (real tiny node helpers; SIGTERM-only)
const NODE = process.execPath;
const sup = () => createSupervisor({ scanEveryMs: 200 });
test('supervisor: readiness resolves, descendants are tracked, stopAll SIGTERMs owner and descendants, dirs are then removed', async () => {
  const s = sup(); const dir = tmp(); writeFileSync(join(dir, 'state'), 'x');
  const code = `const {spawn}=require('child_process'); const g=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'}); console.log('READY http://127.0.0.1:1/ gc='+g.pid); setInterval(()=>{},1000)`;
  const r = await s.spawnOwned({ label: 'svc', cmd: NODE, args: ['-e', code], ready: /READY .* gc=(\d+)/, timeoutMs: 8000, dirs: [dir] });
  const gc = +r.match[1]; assert.ok(alive(r.proc.pid) && alive(gc));
  await sleep(450); const rep = await s.stopAll({ graceMs: 5000 }); s.stopTicker();
  assert.equal(rep[0].survivors.length, 0); assert.ok(!alive(r.proc.pid) && !alive(gc), 'owner and descendant exited');
  assert.equal(rep[0].descendantsSeen >= 1, true);
  const rm = s.removeDirs(rep); assert.equal(rm[0].removed, true); assert.equal(existsSync(dir), false);
});
test('supervisor: spawn error (ENOENT) rejects with bounded diagnostics and is reported as never started', async () => {
  const s = sup(); await assert.rejects(s.spawnOwned({ label: 'ghost', cmd: '/nonexistent/ot-stage4-binary', ready: /x/, timeoutMs: 2000, dirs: [] }), /ghost: spawn error/);
  const rep = await s.stopAll({ graceMs: 200 }); s.stopTicker(); assert.equal(rep[0].started, false); assert.match(rep[0].spawnError, /ENOENT/); assert.deepEqual(rep[0].survivors, []);
});
test('supervisor: early exit before readiness rejects with the child\'s diagnostics (bounded)', async () => {
  const s = createSupervisor({ scanEveryMs: 0, diagBytes: 100 });
  await assert.rejects(s.spawnOwned({ label: 'early', cmd: NODE, args: ['-e', "console.error('boom '.repeat(100)); process.exit(3)"], ready: /READY/, timeoutMs: 5000 }), (e) => /early: exited before ready \(code 3/.test(e.message) && e.message.length < 700);
  const rep = await s.stopAll({ graceMs: 200 }); assert.equal(rep[0].exit.code, 3); assert.ok(rep[0].diag.length <= 100 + 5 || rep[0].diag.length <= 300);
});
test('supervisor: readiness timeout rejects, the child stays registered, and stopAll then stops it (no leak, no SIGKILL needed)', async () => {
  const s = sup(); await assert.rejects(s.spawnOwned({ label: 'slow', cmd: NODE, args: ['-e', 'setInterval(()=>{},1000)'], ready: /NEVER/, timeoutMs: 400 }), /slow: not ready after 400 ms/);
  const pid = s.entries[0].proc.pid; assert.ok(alive(pid), 'still running after the failed start (the supervisor never kills by itself)');
  const rep = await s.stopAll({ graceMs: 5000 }); s.stopTicker(); assert.deepEqual(rep[0].survivors, []); assert.ok(!alive(pid));
});
test('supervisor: a process that ignores SIGTERM is REPORTED as a survivor, its directory is PRESERVED, and it is never SIGKILLed', async () => {
  const s = sup(); const dir = tmp(); writeFileSync(join(dir, 'live-state'), 'must survive while the owner lives');
  const r = await s.spawnOwned({ label: 'stubborn', cmd: NODE, args: ['-e', "process.on('SIGTERM',()=>{}); console.log('READY'); setTimeout(()=>process.exit(0),3500)"], ready: /READY/, timeoutMs: 5000, dirs: [dir] });
  const rep = await s.stopAll({ graceMs: 600 }); s.stopTicker();
  assert.deepEqual(rep[0].survivors, [r.proc.pid]); assert.ok(alive(r.proc.pid), 'not killed by the harness');
  const rm = s.removeDirs(rep); assert.equal(rm[0].removed, false); assert.match(rm[0].reason, /survivors/); assert.ok(existsSync(join(dir, 'live-state')), 'state of a live process is untouched');
  await new Promise((res) => r.proc.on('exit', res));                                   // it exits on its own
  const rep2 = await createSupervisor({ scanEveryMs: 0 }).stopAll({ graceMs: 50 }); assert.deepEqual(rep2, []);
  assert.equal(s.removeDirs([{ ...rep[0], survivors: [] }])[0].removed, true, 'once the owner has exited the directory may be removed');
});
test('supervisor: stopAll does not signal a recycled PID (command line differs from the one recorded) and does not repeat entries', async () => {
  const sent = []; let listing = [{ pid: 100, ppid: 1, command: 'svc' }, { pid: 200, ppid: 100, command: 'helper --x' }];
  const { EventEmitter } = await import('node:events'); const fake = () => Object.assign(new EventEmitter(), { pid: 100, exitCode: null, signalCode: null, stdout: new EventEmitter(), stderr: new EventEmitter() });
  const proc = fake(); const s = createSupervisor({ spawn: () => proc, ps: () => listing, kill: (pid, sig) => { sent.push([pid, sig]); listing = listing.filter((p) => p.pid !== pid); }, scanEveryMs: 0 });
  const p = s.spawnOwned({ label: 'svc', cmd: 'x', ready: /READY/, timeoutMs: 1000 }); proc.stdout.emit('data', 'READY'); await p;     // descendants 200 recorded as 'helper --x'
  listing = [{ pid: 100, ppid: 1, command: 'svc' }, { pid: 200, ppid: 1, command: 'someone-elses-process' }];                          // 200 was recycled by an unrelated process
  const rep = await s.stopAll({ graceMs: 50, pollMs: 10 });
  assert.deepEqual(sent.map((x) => x[0]), [100], 'only the owner is signalled'); assert.ok(sent.every((x) => x[1] === 'SIGTERM'));
  assert.equal(rep.length, 1); assert.deepEqual((await s.stopAll({ graceMs: 20, pollMs: 10 })), [], 'a second stopAll reports nothing again (no duplicates)');
});
test('supervisor: descendantsOf walks the process tree from a ps listing', () => {
  const list = [{ pid: 1, ppid: 0 }, { pid: 10, ppid: 1 }, { pid: 11, ppid: 10 }, { pid: 12, ppid: 11 }, { pid: 20, ppid: 1 }];
  assert.deepEqual([...descendantsOf(list, 10)].sort((a, b) => a - b), [11, 12]);
});
test('no code path SIGKILLs (comments excluded) in the new harness files', () => {
  for (const f of ['run_stage4_lib.mjs', 'run_stage4_fixtures.mjs', 'run_stage4_desktop.mjs', 'run_stage4_plan.mjs']) {
    const code = readFileSync(join(HERE, f), 'utf8').split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
    assert.ok(!/SIGKILL/.test(code.replace(/\/\/.*$/gm, '')), f + ' mentions SIGKILL in code');
  }
});

// ---------------------------------------------------------------- recorder
test('recorder: every observation needs an evidence mode; a row is never "matched"; a failure makes it "not matched"', () => {
  const r = createRecorder(['DA-01', 'DA-02', 'DA-03']);
  assert.throws(() => r.obs('DA-01', 'x', true, '', {}), /lacks an evidence mode/); assert.throws(() => r.obs('DA-99', 'x', true, '', { mode: 'ui-only' }), /unknown row/);
  r.obs('DA-01', 'a', true, '', { mode: 'real-server' }); r.obs('DA-02', 'b', false, '', { mode: 'fixture-substituted' }); const rows = r.finalize();
  assert.match(rows['DA-01'].status, /^not yet exercised \(partial/); assert.match(rows['DA-02'].status, /^not matched/); assert.equal(rows['DA-03'].status, 'not yet exercised');
  assert.ok(!Object.values(rows).some((x) => /^matched/.test(x.status)));
});

// ---------------------------------------------------------------- fixtures: identity, routing, isolation
const NAMES = ['contexts-600-synthetic', 'deps-82-synthetic', 'deps-paths-synthetic', 'bom-large-synthetic', 'malicious-text-synthetic', 'no-ai-synthetic', 'nonpython-synthetic', 'cbom-empty-and-partial-synthetic', 'scan-status-matrix-synthetic', 'frigate-recorded'];
test('fixtures: every named fixture loads and every file matches its MANIFEST sha256 (truthful identity)', () => { for (const n of NAMES) { const f = loadFixture(n); assert.ok(Object.keys(f.files).length > 0, n); assert.match(f.builderSha256, /^[0-9a-f]{64}$/); } });
test('fixtures: a modified fixture file is refused', () => {
  const root = tmp(); cpSync(join(FIXTURE_ROOT, 'deps-82-synthetic'), join(root, 'deps-82-synthetic'), { recursive: true });
  const p = join(root, 'deps-82-synthetic', 'page-offset-00.json'); writeFileSync(p, readFileSync(p, 'utf8').replace('"all"', '"alL"'));
  assert.throws(() => loadFixture('deps-82-synthetic', root), /sha256 .* != manifest/);
});
const U = (path, q = {}) => 'http://127.0.0.1:1' + path + '?' + new URLSearchParams(q).toString();
test('routing: deps-82 serves 30/30/22 for filter=all, an identified 82-match dataset; direct/offset 30 is UNROUTED (no such fixture), never guessed', () => {
  const fx = loadFixture('deps-82-synthetic'); const D = '/api/workbench/v1/dependencies';
  const shown = [0, 30, 60].map((o) => { const r = route(fx, U(D, { generation: 1, filter: 'all', offset: o, size: 30 })); assert.equal(r.kind, 'fixture'); assert.equal(r.body.page.matches_total, 82); return r.body.page.matches_shown; });
  assert.deepEqual(shown, [30, 30, 22]);
  assert.equal(route(fx, U(D, { generation: 1, filter: 'direct', offset: 30 })).kind, 'unrouted');
  assert.equal(route(fx, U(D, { generation: 1, filter: 'direct', offset: 0 })).file, 'filter-direct.json');
  assert.equal(route(fx, U(D, { generation: 1, filter: 'all', query: 'dep-04' })).file, 'search-dep-04.json');
  assert.equal(route(fx, U(D, { generation: 1, filter: 'transitive' })).body.page.matches_total, 0);
});
test('routing: the dependency chooser is ADAPTER-SYNTHESIZED from dependency_page.context and labelled as such', () => {
  const fx = loadFixture('deps-82-synthetic'); const r = route(fx, U('/api/workbench/v1/dependency-contexts', { generation: 1, limit: 20 }));
  assert.equal(r.kind, 'adapter'); assert.equal(r.body.default_context_id, fx.files['page-offset-00.json'].context.context_id); assert.equal(r.body.rows.length, 1); assert.match(r.adapterNote, /built from dependency_page\.context/);
});
test('routing: contexts-600 full page and group pages come from the payload group_id/offset; an unknown group is unrouted', () => {
  const fx = loadFixture('contexts-600-synthetic'); const C = '/api/workbench/v1/contexts';
  assert.equal(route(fx, U(C, { generation: 1, files_limit: 20 })).file, 'contexts-page-0.json');
  const g = fx.files['contexts-group-python-offset-20.json'].groups[0]; assert.equal(route(fx, U(C, { generation: 1, group_id: g.group_id, files_offset: 20, files_limit: 20 })).file, 'contexts-group-python-offset-20.json');
  assert.equal(route(fx, U(C, { generation: 1, group_id: 'grp:nope', files_offset: 0 })).kind, 'unrouted');
});
test('routing: bom-large queue pages 0/25/50, Full graph windows 0/100, group summary; unknown candidate graph is unrouted; legacy view routes are not fixture-backed', () => {
  const fx = loadFixture('bom-large-synthetic'); const Q = '/api/workbench/v1/bom-candidates', G = '/api/workbench/v1/bom-graph';
  assert.deepEqual([0, 25, 50].map((o) => route(fx, U(Q, { generation: 1, offset: o, size: 25 })).file), ['candidates-offset-00.json', 'candidates-offset-25.json', 'candidates-offset-50.json']);
  assert.deepEqual([0, 100].map((o) => route(fx, U(G, { generation: 1, scope_kind: 'full_view', group: 'all', offset: o })).file), ['graph-full-view-offset-000.json', 'graph-full-view-offset-100.json']);
  assert.equal(route(fx, U(G, { generation: 1, scope_kind: 'group_summary', group: 'software' })).file, 'graph-group-summary.json');
  assert.equal(route(fx, U(G, { generation: 1, scope_kind: 'focused_candidate', candidate_id: 'cand:nope' })).kind, 'unrouted');
  assert.equal(route(fx, U('/api/view/gap', { id: 'x' })).kind, 'unrouted'); assert.equal(route(fx, 'http://127.0.0.1:1/static/app.js'), null);
});
test('routing: typed-state fixtures are selected explicitly by the case; without a selection several candidates are unrouted', () => {
  const none = loadFixture('cbom-empty-and-partial-synthetic'); assert.equal(route(none, U('/api/workbench/v1/crypto-assets', { generation: 1 })).kind, 'unrouted');
  const sel = loadFixture('cbom-empty-and-partial-synthetic', undefined, { '/api/workbench/v1/crypto-assets': 'crypto-failed.json' }); assert.equal(route(sel, U('/api/workbench/v1/crypto-assets', { generation: 1 })).body.availability.state, 'failed');
  const single = loadFixture('no-ai-synthetic'); assert.equal(route(single, U('/api/workbench/v1/ai-assets', {})).kind, 'unrouted', 'two ai payloads in no-ai-synthetic: still must be chosen');
});
test('envelope: identity is the fixture\'s own binding (digest, commit, repository, ref, generation); responses bind to the same digest', () => {
  for (const n of ['contexts-600-synthetic', 'deps-82-synthetic', 'bom-large-synthetic']) {
    const fx = loadFixture(n); const env = analysisEnvelope(fx); const b = Object.values(fx.files).find((x) => x.binding).binding;
    assert.equal(env.identity.analysis_digest, b.analysis_digest); assert.equal(env.identity.commit, b.commit_sha); assert.equal(env.generation, b.generation); assert.equal(env.identity.repository, b.repository.canonical_url);
    for (const body of Object.values(fx.files)) if (body.binding) assert.equal(body.binding.analysis_digest, env.identity.analysis_digest, n + ' mixes bindings');
  }
});
test('routing with the query strings the app emits (generation, context_id, focus_id, size, family, scope_kind) reaches the same fixtures', () => {
  const dep = loadFixture('deps-82-synthetic'); const ctx = dep.files['page-offset-00.json'].context.context_id;
  const r = route(dep, U('/api/workbench/v1/dependencies', { generation: 1, context_id: ctx, filter: 'all', query: '', offset: 30, size: 30 })); assert.equal(r.file, 'page-offset-30.json');
  assert.equal(route(dep, U('/api/workbench/v1/dependencies', { generation: 1, context_id: 'ctx:other', filter: 'all', offset: 0, size: 30 })).kind, 'unrouted', 'a different context is not served');
  const bom = loadFixture('bom-large-synthetic'); assert.equal(route(bom, U('/api/workbench/v1/bom-candidates', { generation: 1, family: 'software', query: '', offset: 25, size: 25 })).file, 'candidates-offset-25.json');
  assert.equal(route(bom, U('/api/workbench/v1/bom-graph', { generation: 1, scope_kind: 'full_view', group: 'all', query: '', offset: 0 })).file, 'graph-full-view-offset-000.json');
});
test('every phase emits the DA rows the plan claims for it (static scan of the driver)', () => {
  const src = readFileSync(join(HERE, 'run_stage4_desktop.mjs'), 'utf8'); const fn = (name) => { const i = src.indexOf('async function ' + name + '('); const j = src.indexOf('\n// ====', i); return src.slice(i, j > i ? j : undefined); };
  // direct O('DA-nn', ...) calls plus loop tables of the form ['DA-nn', '<tab>', ...] whose rows are passed to O(row, ...)
  const rowsIn = (code) => new Set([...code.matchAll(/\b(?:O|rec\.obs)\('(DA-\d\d)'|\['(DA-\d\d)', '[a-z-]+'|'(DA-\d\d)'\]/g)].map((m) => m[1] || m[2] || m[3]));
  const emitted = { P1: rowsIn(fn('P1')), P2: rowsIn(fn('P2')), P3: rowsIn(fn('P3')), P4: rowsIn(fn('P4')), P7: rowsIn(fn('P7')), P8: rowsIn(fn('P8')) };
  const tm = rowsIn(fn('typedMatrix')); assert.ok(/row = family === 'crypto' \? 'DA-07' : 'DA-08'/.test(src)); tm.add('DA-07'); tm.add('DA-08'); emitted.P5 = new Set([...tm].filter((r) => r !== 'DA-08')); emitted.P6 = new Set([...tm].filter((r) => r !== 'DA-07'));
  for (const [p, def] of Object.entries(PHASES)) for (const r of def.rows) assert.ok(emitted[p].has(r), `${p} claims ${r} but emits only ${[...emitted[p]].join(',')}`);
});
test('handleRequest: non-loopback is failed; passthrough continues; fixture serves envelope/fixtures; case isolation (served sets and bindings are per fixture)', () => {
  const a = loadFixture('contexts-600-synthetic'), b = loadFixture('deps-82-synthetic'); const ea = analysisEnvelope(a), eb = analysisEnvelope(b);
  assert.equal(handleRequest({ url: 'https://example.com/x', fixture: a, envelope: ea }).action, 'fail');
  assert.deepEqual(handleRequest({ url: 'http://127.0.0.1:9/api/workbench/v1/contexts?generation=1', fixture: null }), { action: 'continue', served: 'real-server' });
  assert.equal(handleRequest({ url: 'http://127.0.0.1:9/api/analysis/demo', fixture: a, envelope: ea }).body.identity.analysis_digest, ea.identity.analysis_digest);
  const r = handleRequest({ url: 'http://127.0.0.1:9/api/workbench/v1/contexts?generation=1&files_limit=20', fixture: a, envelope: ea }); assert.equal(r.action, 'fulfill'); assert.match(r.served, /^fixture:contexts-page-0\.json/);
  assert.equal(b.served.size, 0, 'serving case A did not touch case B'); assert.notEqual(ea.identity.analysis_digest, eb.identity.analysis_digest);
  assert.equal(handleRequest({ url: 'http://127.0.0.1:9/static/app.js', fixture: a, envelope: ea }).action, 'continue');
  assert.equal(handleRequest({ url: 'http://127.0.0.1:9/api/workbench/v1/crypto-assets?generation=1', fixture: a, envelope: ea }).status, 404, 'an unmodelled route is a typed 404, not Demo data');
});

// ---------------------------------------------------------------- copied expectation data does not drift from the originals
test('cases: expectation tables run without ReferenceError and equal the original harness text (drift check)', () => {
  for (const w of Object.values(UIP12_MATRIX)) w.ex(''); for (const w of Object.values(UIP13_MATRIX)) for (const f of Object.values(w.ex)) f('');
  const body = (file, marker) => { const L = readFileSync(join(HERE, file), 'utf8').split('\n'); let i = L.findIndex((l) => l.includes(marker)); i = L.findIndex((l, k) => k >= i && l.includes('const want = {')); let j = i; while (L[j].trim() !== '};') j++; return L.slice(i + 1, j).join('\n'); };
  const mine = readFileSync(join(HERE, 'run_stage4_cases.mjs'), 'utf8');
  assert.ok(mine.includes(body('run_uip12_inspector.mjs', 'async function pairMatrix'))); assert.ok(mine.includes(body('run_uip13_inspector.mjs', 'async function caseMatrix')));
});

// ---------------------------------------------------------------- plan
test('plan: every DA row is covered by a phase or declared unexercised; launches fit the ceilings; the rerun is reserved inside the totals', () => {
  const covered = new Set(Object.values(PHASES).flatMap((p) => p.rows)); const declared = new Set(UNEXERCISED.map((u) => u.row));
  for (const r of DA_ROWS) assert.ok(covered.has(r) || declared.has(r), r + ' is neither covered nor declared'); assert.ok(declared.has('DA-18') && declared.has('DA-20'));
  for (const p of Object.values(PHASES)) for (const r of p.rows) assert.ok(DA_ROWS.includes(r), r);
  const c = COUNTS(); assert.ok(c.service <= CEILINGS.service && c.chrome <= CEILINGS.chrome); assert.equal(c.service, 8, 'seven phase services + one reserved'); assert.equal(c.chrome, 2, 'C1 + one reserved'); assert.equal(c.reservedRerun, 2);
  const ids = new Set(LAUNCHES.map((l) => l.id)); for (const p of Object.values(PHASES)) assert.ok(ids.has(p.service), p.service);
  for (const l of LAUNCHES.filter((x) => !x.reserved)) for (const ph of l.phases) assert.ok(PHASES[ph], ph);
  assert.equal(LAUNCHES.filter((l) => l.reserved && l.kind === 'service').length, 1, 'exactly one reserved service launch');
});
test('driver: --plan and --selftest exit 0 without launching anything', () => {
  for (const a of ['--plan', '--selftest']) execFileSync(process.execPath, [join(HERE, 'run_stage4_desktop.mjs'), a], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
});
test('driver: usage without "run" exits non-zero and neither creates nor changes the ledger (no accidental launch)', () => {
  const led = resolve(HERE, '../../../evidence/uip/validation/stage4-desktop/allowance.json');   // S4C-07: the committed evidence now contains a ledger, so assert "unchanged", not "absent"
  const before = existsSync(led) ? readFileSync(led, 'utf8') : null;
  assert.throws(() => execFileSync(process.execPath, [join(HERE, 'run_stage4_desktop.mjs')], { stdio: 'pipe' }));
  assert.equal(existsSync(led) ? readFileSync(led, 'utf8') : null, before, 'the driver must not have created or changed the ledger');
});

test('diagnostic mode (D-17): D1 only with --diagnostic, no --rerun; normal phases refuse --diagnostic; nothing launched or created', () => {
  const led = resolve(HERE, '../../../evidence/uip/validation/stage4-desktop/allowance_diagnostic.json');
  const before = existsSync(led) ? readFileSync(led, 'utf8') : null;
  for (const args of [['run', 'x', 'D1'], ['run', 'x', 'P1', '--diagnostic'], ['run', 'x', 'D1', '--diagnostic', '--rerun']]) {
    let code = 0; try { execFileSync(process.execPath, [join(HERE, 'run_stage4_desktop.mjs'), ...args], { stdio: 'pipe' }); } catch (e) { code = e.status; }
    assert.equal(code, 2, args.join(' '));
  }
  assert.equal(existsSync(led) ? readFileSync(led, 'utf8') : null, before, 'refused invocations must not create or change the diagnostic ledger');
});
test('diagnostic ledger is separate and capped at 1 service / 1 Chrome / 25 min and leaves the historical ledger untouched', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ot-s4-diag-'));
  const hist = join(dir, 'allowance.json'); writeFileSync(hist, JSON.stringify({ service: 8, chrome: 2, rerun: 1, clock_start: 1, events: [] }));
  const histBefore = readFileSync(hist, 'utf8');
  let t = 1000; const l = createLedger({ file: join(dir, 'allowance_diagnostic.json'), ceilings: Object.freeze({ service: 1, chrome: 1, minutes: 25, rerun: 0 }), now: () => t });
  l.spend('service', 'S9'); l.spend('chrome', 'C3');
  assert.throws(() => l.spend('service', 'again'), /CEILING/); assert.throws(() => l.spend('chrome', 'again'), /CEILING/); assert.throws(() => l.markRerun('x'), /CEILING/);
  assert.equal(l.endAt(), 1000 + 25 * 60000); t += 26 * 60000; assert.throws(() => l.spend('service', 'late'), /CEILING/);
  assert.equal(readFileSync(hist, 'utf8'), histBefore, 'historical ledger must be byte-unchanged');
});
test('static: P8 and D1 use the BOM Fit control (bom-fit), never the tab-graph gfit; D1 expectations header is present; diag service compiles', () => {
  const src = readFileSync(join(HERE, 'run_stage4_desktop.mjs'), 'utf8');
  assert.ok(!/\[data-action=gfit\]/.test(src.replace(/\/\/ bom-fit[^\n]*/g, '')) || !/querySelector\('\[data-action=gfit\]'\)/.test(src), 'no query for gfit');
  assert.ok((src.match(/\.ot-bom8-main \[data-action=bom-fit\]/g) || []).length >= 3);
  for (const k of ['E1 ', 'E2 ', 'E3 ', 'E4 ', 'E5 ', 'E6 ', 'C1 ', 'C7 ', 'FROZEN BEFORE LAUNCH']) assert.ok(src.includes(k), k);
  execFileSync('python3', ['-m', 'py_compile', join(HERE, 'stage4_diag_service.py')], { stdio: 'pipe' });
});

test('static: diagnostic wiring in the driver uses the separate ledger file and the D-17 ceilings; an existing output directory is refused (S4D-03/-11)', () => {
  const src = readFileSync(join(HERE, 'run_stage4_desktop.mjs'), 'utf8');
  assert.ok(src.includes("allowance_diagnostic.json") && src.includes('service: 1, chrome: 1, minutes: 25, rerun: 0'));
  assert.ok(/DIAG \? createLedger\(\{ file: DIAG_LEDGER_FILE/.test(src));
  assert.ok(src.includes('already holds evidence'));
});

test('confirmation mode (S4-FIX-01): D2 only with --confirmation; mutually exclusive with --diagnostic; own ledger 1/1/10 min; D2 expectations header frozen; reference prototype never opened', () => {
  const led = resolve(HERE, '../../../evidence/uip/validation/stage4-desktop/allowance_confirmation.json');
  const before = existsSync(led) ? readFileSync(led, 'utf8') : null;
  for (const args of [['run', 'x', 'D2'], ['run', 'x', 'P1', '--confirmation'], ['run', 'x', 'D2', '--confirmation', '--rerun'], ['run', 'x', 'D2', '--confirmation', '--diagnostic'], ['run', 'x', 'D1', '--confirmation']]) {
    let code = 0; try { execFileSync(process.execPath, [join(HERE, 'run_stage4_desktop.mjs'), ...args], { stdio: 'pipe' }); } catch (e) { code = e.status; }
    assert.equal(code, 2, args.join(' '));
  }
  assert.equal(existsSync(led) ? readFileSync(led, 'utf8') : null, before, 'refused invocations must not create or change the confirmation ledger');
  const src = readFileSync(join(HERE, 'run_stage4_desktop.mjs'), 'utf8');
  assert.ok(src.includes('allowance_confirmation.json') && src.includes('service: 1, chrome: 1, minutes: 10, rerun: 0') && /CONF \? createLedger\(\{ file: CONF_LEDGER_FILE/.test(src));
  for (const k of ['F0 ', 'F1 ', 'F2 ', 'F3 ', 'F4 ', 'F5 ', 'EXPECTATIONS FROZEN BEFORE LAUNCH']) assert.ok(src.includes(k), k);
  assert.ok(!/Update-9|opentrace-workbench|prototypes\//.test(src.slice(src.indexOf('D2: S4-FIX-01 confirmation')).replace(/\/\/[^\n]*/g, '')), 'D2 code never opens the prototype');
});

test('confirmation guard (S4F-B04): refuses to spend the launch on a product tree without the S4-FIX-01 fix; creates nothing', () => {
  const hasFix = readFileSync(resolve(HERE, '../../../src/ui/lib/graph_lifecycle.js'), 'utf8').includes('export function fitHost');
  if (hasFix) return;                                            // on a fixed tree this invocation would be a real launch: never run it from a test
  const led = resolve(HERE, '../../../evidence/uip/validation/stage4-desktop/allowance_confirmation.json'); const before = existsSync(led) ? readFileSync(led, 'utf8') : null;
  let code = 0, err = ''; try { execFileSync(process.execPath, [join(HERE, 'run_stage4_desktop.mjs'), 'run', 'guard-test', 'D2', '--confirmation'], { stdio: 'pipe' }); } catch (e) { code = e.status; err = String(e.stderr); }
  assert.equal(code, 2); assert.match(err, /fitHost/); assert.equal(existsSync(led) ? readFileSync(led, 'utf8') : null, before);
  assert.equal(existsSync(resolve(HERE, '../../../evidence/uip/validation/stage4-desktop/guard-test')), false);
});

test('static (S4G-01): in the never-run D1/D2 phases no code follows a trailing `//` comment on the same line (a comment must not swallow statements)', () => {
  const src = readFileSync(join(HERE, 'run_stage4_desktop.mjs'), 'utf8'); const body = src.slice(src.indexOf('async function D1'), src.indexOf('// ================================================================= orchestration'));
  const bad = body.split('\n').map((l, i) => [i, l.replace(/'[^'\n]*'|"[^"\n]*"|`[^`\n]*`/g, '')]).filter(([, l]) => /\/\/[^\n]*(;\s*(const|let|await|for|if|try)\b|\bconst \w+ = await\b)/.test(l) && !/^\s*\/\//.test(l));
  assert.deepEqual(bad.map(([i]) => i), [], 'code after // on lines ' + bad.map(([i]) => i).join(','));
});

test('closure mode (D3): own ledger 1/1/10 min; D3 only with --closure; modes mutually exclusive; frozen header; captures-first order; never opens the prototype', () => {
  const led = resolve(HERE, '../../../evidence/uip/validation/stage4-desktop/allowance_closure.json'); const before = existsSync(led) ? readFileSync(led, 'utf8') : null;
  for (const args of [['run', 'x', 'D3'], ['run', 'x', 'P1', '--closure'], ['run', 'x', 'D3', '--closure', '--rerun'], ['run', 'x', 'D3', '--closure', '--confirmation'], ['run', 'x', 'D2', '--closure'], ['run', 'x', 'D3', '--diagnostic']]) {
    let code = 0; try { execFileSync(process.execPath, [join(HERE, 'run_stage4_desktop.mjs'), ...args], { stdio: 'pipe' }); } catch (e) { code = e.status; }
    assert.equal(code, 2, args.join(' ')); }
  assert.equal(existsSync(led) ? readFileSync(led, 'utf8') : null, before);
  const src = readFileSync(join(HERE, 'run_stage4_desktop.mjs'), 'utf8'); const d3 = src.slice(src.indexOf('async function D3'), src.indexOf('// ================================================================= orchestration'));
  assert.ok(src.includes('allowance_closure.json') && /CLOS \? createLedger\(\{ file: CLOS_LEDGER_FILE, ceilings: Object\.freeze\(\{ service: 1, chrome: 1, minutes: 10, rerun: 0 \}\)/.test(src));
  for (const k of ['FROZEN BEFORE LAUNCH', 'CAPTURE LIST', 'T1 ', 'T8 ', 'R1 ', 'ORDER  Part 1 CAPTURES first']) assert.ok(src.includes(k), k);
  assert.ok(d3.indexOf('Part 1: captures') < d3.indexOf('Part 2: teardown') && d3.indexOf('Part 2: teardown') < d3.indexOf('Part 3: reachability'), 'captures first');
  assert.ok(!/clearTimeout\s*=/.test(d3), 'clearTimeout is not wrapped (the native one must be exercised)');
  assert.ok(!/Update-9|opentrace-workbench|prototypes\//.test(d3.replace(/\/\/[^\n]*/g, '').replace(/'[^'\n]*prototype[^'\n]*'/g, '')), 'D3 code never opens the prototype');
});
test('closure guard: refuses a product tree without the unbound-timer correction; creates nothing', () => {
  const lc = readFileSync(resolve(HERE, '../../../src/ui/lib/graph_lifecycle.js'), 'utf8'); if (lc.includes('export function fitHost') && lc.includes('host._clearTimer = (id) => clearTimer(id)')) return;   // on a corrected tree this would be a real launch
  const led = resolve(HERE, '../../../evidence/uip/validation/stage4-desktop/allowance_closure.json'); const before = existsSync(led) ? readFileSync(led, 'utf8') : null; let code = 0, err = '';
  try { execFileSync(process.execPath, [join(HERE, 'run_stage4_desktop.mjs'), 'run', 'guard-closure', 'D3', '--closure'], { stdio: 'pipe' }); } catch (e) { code = e.status; err = String(e.stderr); }
  assert.equal(code, 2); assert.match(err, /unbound-timer/); assert.equal(existsSync(led) ? readFileSync(led, 'utf8') : null, before);
});

// ---------------------------------------------------------------- closing campaign (--final, launch A / C)
const finalLedgerFile = resolve(HERE, '../../../evidence/uip/validation/stage4-desktop/allowance_final.json');
test('final mode: F1 only with --final and alone; P7/P8/D1-D3 refused with --final; exclusive with the other modes; each refusal exits 2 and creates/changes nothing', () => {
  const before = existsSync(finalLedgerFile) ? readFileSync(finalLedgerFile, 'utf8') : null;
  for (const args of [['run', 'x', 'F1'], ['run', 'x', 'F1,P1', '--final'], ['run', 'x', 'P7', '--final'], ['run', 'x', 'P8', '--final'], ['run', 'x', 'D3', '--final'], ['run', 'x', 'F1', '--final', '--closure'], ['run', 'x', 'F1', '--final', '--diagnostic'], ['run', 'x', 'F1', '--final', '--confirmation']]) {
    let code = 0; try { execFileSync(process.execPath, [join(HERE, 'run_stage4_desktop.mjs'), ...args], { stdio: 'pipe' }); } catch (e) { code = e.status; }
    assert.equal(code, 2, args.join(' ')); }
  assert.equal(existsSync(finalLedgerFile) ? readFileSync(finalLedgerFile, 'utf8') : null, before);
});
test('final ledger: 8 services / 4 Chrome / 90 min / 1 rerun; the planned 7/3 are normal, the last slot of each opens only after the single rerun; never resets', () => {
  const file = join(tmp(), 'allowance_final.json'); let t = 5000; const l = createLedger({ file, ceilings: Object.freeze({ service: 8, chrome: 4, minutes: 90, rerun: 1 }), planned: { service: 7, chrome: 3 }, now: () => t });
  for (let i = 0; i < 7; i++) l.spend('service', 's' + i); for (let i = 0; i < 3; i++) l.spend('chrome', 'c' + i);
  assert.throws(() => l.spend('service', 'x'), /reserved for the single harness-correction rerun/); assert.throws(() => l.spend('chrome', 'x'), /reserved/);
  l.markRerun('r'); l.spend('service', 'rerun', { rerun: true }); l.spend('chrome', 'rerun', { rerun: true });
  assert.throws(() => l.spend('service', 'ninth', { rerun: true }), /exhausted/); assert.throws(() => l.markRerun('again'), /already used/);
  assert.equal(createLedger({ file, ceilings: Object.freeze({ service: 8, chrome: 4, minutes: 90, rerun: 1 }), planned: { service: 7, chrome: 3 }, now: () => t }).snapshot().service, 8);
  t += 91 * 60000; assert.throws(() => createLedger({ file, ceilings: Object.freeze({ service: 8, chrome: 4, minutes: 90, rerun: 1 }), now: () => t }).spend('chrome', 'late'), /ceiling|exhausted|clock/i);
});
test('static: the driver wires the final ledger with the owner-set ceilings and planned 7/3; F1 requires a clean tree; wrapper and driver agree on the same ledger file and ceilings', () => {
  const src = readFileSync(join(HERE, 'run_stage4_desktop.mjs'), 'utf8'); const w = readFileSync(join(HERE, 'run_stage4_final_assistant.mjs'), 'utf8');
  assert.ok(src.includes('allowance_final.json') && w.includes('allowance_final.json'));
  assert.ok(/FINAL \? createLedger\(\{ file: FINAL_LEDGER_FILE, ceilings: Object\.freeze\(\{ service: 8, chrome: 4, minutes: 90, rerun: 1 \}\), planned: \{ service: 7, chrome: 3 \} \}\)/.test(src));
  assert.ok(/service: 8, chrome: 4, minutes: 90, rerun: 1/.test(w) && /service: 7, chrome: 3/.test(w));
  assert.ok(/\(FINAL \|\| EXT \|\| EXT2\) && meta\.srcDirty/.test(src));
});
test('static: F1/E9 contain every frozen scenario id, only existing DA rows, no SIGKILL, no prototype opening; and no code follows a trailing // comment on a line (S4G-01)', () => {
  const src = readFileSync(join(HERE, 'run_stage4_desktop.mjs'), 'utf8'); const a = src.indexOf('// ================================================================= F1: closing campaign'); const b = src.indexOf('// ================================================================= orchestration');
  const blk = src.slice(a, b); assert.ok(a > 0 && b > a);
  for (const id of ['E0', 'E1', 'E2', 'E3', 'E4', 'E5', 'E6', 'E7', 'E8', 'E9', 'E10', 'E11']) assert.ok(blk.includes(id + ' '), id);
  for (const m of blk.matchAll(/\bO\('(DA-\d\d)'/g)) assert.ok(DA_ROWS.includes(m[1]), m[1]);
  assert.ok(!/SIGKILL|kill -9/.test(blk));
  assert.ok(!/Update-9|opentrace-workbench|prototypes\//.test(blk.replace(/\/\/[^\n]*/g, '')));
  const bad = blk.split('\n').map((l, k) => [k, l.replace(/'[^'\n]*'|"[^"\n]*"|`[^`\n]*`/g, '')]).filter(([, l]) => /\/\/[^\n]*(;\s*(const|let|await|for|if|try)\b|\bconst \w+ = await\b)/.test(l) && !/^\s*\/\//.test(l));
  assert.deepEqual(bad.map(([k]) => k), [], 'code after // on lines ' + bad.map(([k]) => k).join(','));
  assert.ok(blk.indexOf('await D3(base)') > blk.indexOf('E5 cbomfail') && blk.indexOf('await E9(base)') > blk.indexOf('await D3(base)'), 'captures and non-destructive scenarios first; D3 then E9');
});
test('frozen v2 expectations: retained v1, the key numbers and ids the driver predicates use are written in the document, and the DA-18 driver copy matches the recorded sha256', () => {
  const doc = readFileSync(resolve(HERE, '../../../.context/stage4-prep/FINAL_CAMPAIGN_FROZEN_EXPECTATIONS_v2.md'), 'utf8'); const v1 = resolve(HERE, '../../../.context/stage4-prep/FINAL_CAMPAIGN_FROZEN_EXPECTATIONS.md');
  assert.ok(existsSync(v1), 'v1 retained'); const src = readFileSync(join(HERE, 'run_stage4_desktop.mjs'), 'utf8');
  for (const k of ['{all 5, models 1, runtimes 3, ai_services 1, findings 0}', 'source-observation.tls_verification_relaxed', '500', 'page `shown` 30', 'aifault', 'cryptofault', 'E9', 'R1', 'launch C', 'Broker', 'allowance_final.json', '7 services / 3 Chrome']) assert.ok(doc.includes(k), k);
  for (const k of ['source-observation.tls_verification_relaxed', 'bai.filter_totals.all === 500', 'bai.counts.shown === 30', 'opentrace-source-ai', 'opentrace-source-crypto']) assert.ok(src.includes(k), k);
  const sha = execFileSync('shasum', ['-a', '256', join(HERE, 'lab_assistant_driver_v3.mjs')], { encoding: 'utf8' }).split(' ')[0]; assert.equal(sha, 'c074f527559ffaf239d83b14080ad586ef469b709769e7dc0edc52c5121e6ab8'); assert.ok(doc.includes(sha));
});
test('assistant wrapper: --dry spends nothing and launches nothing; env is scrubbed and carries only the three caps (1 service, 1 Chrome, minutes); the driver refuses zero caps', async () => {
  const before = existsSync(finalLedgerFile) ? readFileSync(finalLedgerFile, 'utf8') : null;
  const out = execFileSync(process.execPath, [join(HERE, 'run_stage4_final_assistant.mjs'), '--dry'], { encoding: 'utf8' }); assert.match(out, /wouldSpend/);
  assert.equal(existsSync(finalLedgerFile) ? readFileSync(finalLedgerFile, 'utf8') : null, before);
  const { driverEnv } = await import('./run_stage4_final_assistant.mjs'); const env = driverEnv({ repo: '/r', sha: 'a'.repeat(40), out: '/o', py: '/p', minutes: 55, base: { PATH: '/bin', HOME: '/h', OPENAI_API_KEY: 'x', ANTHROPIC_API_KEY: 'y', GITHUB_TOKEN: 'z' } });
  assert.deepEqual(Object.keys(env).sort(), ['HOME', 'OT_ALLOW_CHROME', 'OT_ALLOW_MINUTES', 'OT_ALLOW_SERVICE', 'OT_EVIDENCE', 'OT_SRC', 'OT_SRC_SHA', 'PATH', 'PYTHON_BIN']);
  assert.equal(env.OT_ALLOW_SERVICE, '1'); assert.equal(env.OT_ALLOW_CHROME, '1'); assert.equal(env.OT_ALLOW_MINUTES, '55');
  let code = 0; try { execFileSync(process.execPath, [join(HERE, 'lab_assistant_driver_v3.mjs'), 'run', 'zero'], { stdio: 'pipe', env: { PATH: process.env.PATH, OT_EVIDENCE: tmp() } }); } catch (e) { code = e.status; } assert.notEqual(code, 0);
});
test('completion service: the final case exposes every scenario repository and the fault injection patches only the two new phase entry points', () => {
  const src = readFileSync(join(HERE, 'stage4_completion_service.py'), 'utf8');
  for (const r of ['aicrypto', 'unsupp', 'partial', 'modelsupp', 'cbomfail', 'bounds', 'aifault', 'cryptofault']) assert.ok(src.includes(`("${r}",`), r);
  assert.ok(/for mod, marker in \(\(ai_source, "FAULT_AI.py"\), \(crypto_source, "FAULT_CRYPTO.py"\)\)/.test(src)); assert.ok(/inject_faults\(\)\n    live, root, _ = u13\.build\("final"\)/.test(src));
  execFileSync('python3', ['-c', `import ast,sys;ast.parse(open(${JSON.stringify(join(HERE, 'stage4_completion_service.py'))}).read())`]);
});

// ---------------------------------------------------------------- closing extension (--ext)
const extLedgerFile = resolve(HERE, '../../../evidence/uip/validation/stage4-desktop/allowance_extension.json');
test('ext mode: X/X6 only with --ext; --ext runs only X,P7,X6; exclusive with the other modes; refusals exit 2 and touch nothing', () => {
  const before = existsSync(extLedgerFile) ? readFileSync(extLedgerFile, 'utf8') : null;
  for (const args of [['run', 'x', 'X'], ['run', 'x', 'X6'], ['run', 'x', 'F1', '--ext'], ['run', 'x', 'P1', '--ext'], ['run', 'x', 'D3', '--ext'], ['run', 'x', 'X', '--ext', '--final'], ['run', 'x', 'X', '--ext', '--closure'], ['run', 'x', 'X', '--ext']]) {
    let code = 0; try { execFileSync(process.execPath, [join(HERE, 'run_stage4_desktop.mjs'), ...args], { stdio: 'pipe' }); } catch (e) { code = e.status; }
    assert.equal(code, 2, args.join(' ')); }                      // the last case refuses for the missing --expect-sha
  assert.equal(existsSync(extLedgerFile) ? readFileSync(extLedgerFile, 'utf8') : null, before);
});
test('ext ledger: 4 services / 2 Chrome / 45 min / 1 rerun; planned 3/1; the last slot of each opens only after the single rerun', () => {
  const file = join(tmp(), 'allowance_extension.json'); const cfg = { ceilings: Object.freeze({ service: 4, chrome: 2, minutes: 45, rerun: 1 }), planned: { service: 3, chrome: 1 }, file, now: () => 7000 };
  const l = createLedger(cfg); for (let i = 0; i < 3; i++) l.spend('service', 's' + i); l.spend('chrome', 'c');
  assert.throws(() => l.spend('service', 'x'), /reserved/); assert.throws(() => l.spend('chrome', 'x'), /reserved/);
  l.markRerun('r'); l.spend('service', 'r', { rerun: true }); l.spend('chrome', 'r', { rerun: true }); assert.throws(() => l.spend('service', 'x', { rerun: true }), /exhausted/);
});
test('static: ext driver wiring (ledger file, ceilings, clean tree + expect-sha) and the X/X6 blocks (ids, DA rows, no code after a trailing // comment, no SIGKILL, no prototype)', () => {
  const src = readFileSync(join(HERE, 'run_stage4_desktop.mjs'), 'utf8');
  assert.ok(/EXT \? createLedger\(\{ file: EXT_LEDGER_FILE, ceilings: Object\.freeze\(\{ service: 4, chrome: 2, minutes: 45, rerun: 1 \}\), planned: \{ service: 3, chrome: 1 \} \}\)/.test(src) && src.includes('allowance_extension.json'));
  assert.ok(/\(FINAL \|\| EXT \|\| EXT2\) && meta\.srcDirty/.test(src) && /\(FINAL \|\| EXT \|\| EXT2\) && !\(EXPSHA/.test(src));
  const a = src.indexOf('// ================================================================= X: closing extension'); const b = src.indexOf('// ================================================================= orchestration'); const blk = src.slice(a, b); assert.ok(a > 0 && b > a);
  for (const id of ['X1a', 'X1b', 'X1c', 'X1d', 'X2', 'X3', 'X4', 'X5', 'X6']) assert.ok(blk.includes(id), id);
  for (const m of blk.matchAll(/\bO\('(DA-\d\d)'/g)) assert.ok(DA_ROWS.includes(m[1]), m[1]);
  assert.ok(!/SIGKILL|kill -9/.test(blk)); assert.ok(!/Update-9|opentrace-workbench|prototypes\//.test(blk.replace(/\/\/[^\n]*/g, '')));
  const bad = blk.split('\n').map((l, k) => [k, l.replace(/'[^'\n]*'|"[^"\n]*"|`[^`\n]*`/g, '')]).filter(([, l]) => /\/\/[^\n]*(;\s*(const|let|await|for|if|try)\b|\bconst \w+ = await\b)/.test(l) && !/^\s*\/\//.test(l)); assert.deepEqual(bad.map(([k]) => k), []);
  const doc = readFileSync(resolve(HERE, '../../../.context/stage4-prep/EXTENSION_FROZEN_EXPECTATIONS.md'), 'utf8'); for (const k of ['+(439,137)', '4 services', 'norun', 'conflicting_evidence', 'X1b']) assert.ok(doc.includes(k), k);
});
test('ext --steps: unknown or wrong-case names and use without --ext are refused with exit 2 before anything is spent', () => {
  const before = existsSync(extLedgerFile) ? readFileSync(extLedgerFile, 'utf8') : null;
  for (const args of [['run', 'x', 'X', '--ext', '--steps=X1D', '--expect-sha=0'.padEnd(20, '0')], ['run', 'x', 'X', '--ext', '--steps=X1', '--expect-sha=0'.padEnd(20, '0')], ['run', 'x', 'P7', '--steps=X3']]) {
    let code = 0; try { execFileSync(process.execPath, [join(HERE, 'run_stage4_desktop.mjs'), ...args], { stdio: 'pipe' }); } catch (e) { code = e.status; } assert.equal(code, 2, args.join(' ')); }
  assert.equal(existsSync(extLedgerFile) ? readFileSync(extLedgerFile, 'utf8') : null, before);
});

// ---------------------------------------------------------------- closing extension 2 (--ext2)
const ext2LedgerFile = resolve(HERE, '../../../evidence/uip/validation/stage4-desktop/allowance_extension2.json');
test('ext2 mode: Y/YE/YN/YI only with --ext2; --ext2 runs only those; exclusive with the other modes; --steps validated; refusals exit 2 and touch nothing', () => {
  const before = existsSync(ext2LedgerFile) ? readFileSync(ext2LedgerFile, 'utf8') : null; const sha = '--expect-sha=' + '0'.repeat(20);
  for (const args of [['run', 'x', 'Y'], ['run', 'x', 'YE'], ['run', 'x', 'X', '--ext2', sha], ['run', 'x', 'P1', '--ext2', sha], ['run', 'x', 'Y', '--ext2', '--ext', sha], ['run', 'x', 'Y', '--ext2', '--steps=Y9', sha], ['run', 'x', 'Y', '--ext2', '--steps=y1', sha], ['run', 'x', 'Y,YE,YN', '--ext2', '--rerun', sha], ['run', 'x', 'Y', '--ext2'], ['run', 'x', 'Y', '--steps=Y1']]) {
    let code = 0; try { execFileSync(process.execPath, [join(HERE, 'run_stage4_desktop.mjs'), ...args], { stdio: 'pipe' }); } catch (e) { code = e.status; } assert.equal(code, 2, args.join(' ')); }
  assert.equal(existsSync(ext2LedgerFile) ? readFileSync(ext2LedgerFile, 'utf8') : null, before);
});
test('ext2 ledger: 6 services / 2 Chrome / 45 min / 1 rerun; planned 4/1; the remaining slots open only after the single rerun', () => {
  const file = join(tmp(), 'allowance_extension2.json'); const cfg = { ceilings: Object.freeze({ service: 6, chrome: 2, minutes: 45, rerun: 1 }), planned: { service: 4, chrome: 1 }, file, now: () => 9000 };
  const l = createLedger(cfg); for (let i = 0; i < 4; i++) l.spend('service', 's' + i); l.spend('chrome', 'c');
  assert.throws(() => l.spend('service', 'x'), /reserved/); assert.throws(() => l.spend('chrome', 'x'), /reserved/);
  l.markRerun('r'); l.spend('service', 'r1', { rerun: true }); l.spend('service', 'r2', { rerun: true }); l.spend('chrome', 'r', { rerun: true }); assert.throws(() => l.spend('service', 'x', { rerun: true }), /exhausted/);
});
test('static: ext2 wiring and the Y/YE/YN/YI blocks (ids, DA rows, frontend-only label, no code after a trailing // comment, no SIGKILL, no prototype) and the frozen document', () => {
  const src = readFileSync(join(HERE, 'run_stage4_desktop.mjs'), 'utf8');
  assert.ok(/EXT2 \? createLedger\(\{ file: EXT2_LEDGER_FILE, ceilings: Object\.freeze\(\{ service: 6, chrome: 2, minutes: 45, rerun: 1 \}\), planned: \{ service: 4, chrome: 1 \} \}\)/.test(src) && src.includes('allowance_extension2.json'));
  const a = src.indexOf('// ================================================================= Y: closing extension 2'); const b = src.indexOf('// ================================================================= orchestration'); const blk = src.slice(a, b); assert.ok(a > 0 && b > a);
  for (const id of ['Y1', 'Y2', 'Y3', 'Y4', 'Y-I5C', 'Y-R2-03', 'Y-banner', 'YN', 'YI T1', 'YI T2', 'YI T3']) assert.ok(blk.includes(id), id);
  for (const m of blk.matchAll(/\bO\('(DA-\d\d)'/g)) assert.ok(DA_ROWS.includes(m[1]), m[1]);
  assert.ok(blk.includes("ctxOf('adapter-synthesized'") && blk.includes('frontend rendering only'), 'Y4 is labelled frontend-only');
  assert.ok(!/SIGKILL|kill -9/.test(blk)); assert.ok(!/Update-9|opentrace-workbench|prototypes\//.test(blk.replace(/\/\/[^\n]*/g, '')));
  const bad = blk.split('\n').map((l, k) => [k, l.replace(/'[^'\n]*'|"[^"\n]*"|`[^`\n]*`/g, '')]).filter(([, l]) => /\/\/[^\n]*(;\s*(const|let|await|for|if|try)\b|\bconst \w+ = await\b)/.test(l) && !/^\s*\/\//.test(l)); assert.deepEqual(bad.map(([k]) => k), []);
  const doc = readFileSync(resolve(HERE, '../../../.context/stage4-prep/EXTENSION2_FROZEN_EXPECTATIONS.md'), 'utf8'); for (const k of ['6 services', 'FRONTEND-ONLY', 'Y3', 'per-digest', 'offset 200', 'R2-03', 'hands off']) assert.ok(doc.includes(k), k);
});
