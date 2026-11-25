// Stage 4 harness library (test harness only; no product behaviour). Pure/injectable so the accounting, deadline, supervision and cleanup paths
// can be exercised offline by run_stage4_selftest.mjs without starting any app service, Chrome, network or provider.
// Policy: SIGTERM only (never SIGKILL); a survivor is REPORTED and its state directory PRESERVED; nothing here ever resets or extends an allowance.
import { spawn as realSpawn, execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export const CEILINGS = Object.freeze({ service: 8, chrome: 8, minutes: 90, rerun: 1 });
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------------ allowance ledger (cumulative, fixed path, fail-closed)
// `planned` = launches a normal run may spend (default: the ceilings). The slots between `planned` and the ceilings are RESERVED for the single harness-correction
// rerun: they open only after markRerun() (cap 1) and a spend with {rerun:true}. Ceilings stay absolute.
export function createLedger({ file, ceilings = CEILINGS, planned = null, now = Date.now }) {
  const plan = planned || { service: ceilings.service, chrome: ceilings.chrome };
  const load = () => {
    if (!existsSync(file)) return { service: 0, chrome: 0, rerun: 0, clock_start: null, events: [] };
    const j = JSON.parse(readFileSync(file, 'utf8'));                       // corrupt JSON throws: fail closed, never silently restart at zero
    for (const k of ['service', 'chrome', 'rerun']) if (!Number.isInteger(j[k]) || j[k] < 0) throw new Error('ledger corrupt: ' + k);
    return j;
  };
  const save = (j) => { mkdirSync(dirname(file), { recursive: true }); const t = file + '.tmp'; writeFileSync(t, JSON.stringify(j, null, 1)); renameSync(t, file); };
  const l = {
    snapshot: () => load(),
    endAt: () => { const j = load(); return j.clock_start ? j.clock_start + ceilings.minutes * 60000 : null; },
    remainingMs: () => { const e = l.endAt(); return e === null ? ceilings.minutes * 60000 : e - now(); },
    markRerun(note) { const j = load(); if (j.rerun >= ceilings.rerun) throw new Error('CEILING: the single harness-correction rerun is already used'); j.rerun++; j.events.push({ t: new Date(now()).toISOString(), kind: 'rerun-start', note: String(note).slice(0, 200), rerun: true }); save(j); return j; },
    // kind: 'service' | 'chrome'. rerun=true lets this launch use a reserved slot; only valid after markRerun(). It STILL counts inside the totals.
    spend(kind, note, { rerun = false } = {}) {
      if (!(kind in ceilings) || kind === 'minutes' || kind === 'rerun') throw new Error('unknown allowance kind ' + kind);
      const j = load();
      if (j.clock_start && now() - j.clock_start > ceilings.minutes * 60000) throw new Error(`CEILING: ${ceilings.minutes}-minute clock exceeded`);
      if (j[kind] >= ceilings[kind]) throw new Error(`CEILING: ${kind} launches exhausted (${j[kind]}/${ceilings[kind]})`);
      if (j[kind] >= plan[kind] && !(rerun && j.rerun >= 1)) throw new Error(`CEILING: the remaining ${kind} slot(s) are reserved for the single harness-correction rerun (planned ${plan[kind]}); start it with --rerun`);
      if (!j.clock_start) j.clock_start = now();
      j[kind]++;
      j.events.push({ t: new Date(now()).toISOString(), kind, note: String(note).slice(0, 200), rerun });
      save(j); return j;
    },
  };
  return l;
}

// ------------------------------------------------------------------ deadline watchdog
// Watches the REMAINING 90-minute budget for the whole run (not only at the next launch). On expiry it runs onExpire once (preserve results, stop owned processes).
export function createDeadline({ endAtMs, now = Date.now, setTimer = setTimeout, clearTimer = clearTimeout, onExpire }) {
  let timer = null, fired = false;
  const d = {
    get expired() { return fired || now() >= endAtMs; },
    guard() { if (d.expired) throw new Error('DEADLINE'); },
    start() { const ms = Math.max(0, endAtMs - now()); timer = setTimer(async () => { if (fired) return; fired = true; try { await onExpire?.(); } catch (e) { d.error = e; } }, ms); return d; },
    stop() { if (timer) clearTimer(timer); timer = null; },
  };
  return d;
}

// ------------------------------------------------------------------ process listing
export function psList() {
  const out = execFileSync('/bin/ps', ['-axo', 'pid=,ppid=,command='], { encoding: 'utf8', maxBuffer: 1 << 26 });
  return out.split('\n').map((l) => l.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/)).filter(Boolean).map((m) => ({ pid: +m[1], ppid: +m[2], command: m[3] }));
}
export const descendantsOf = (list, rootPid) => { const kids = new Map(); for (const p of list) (kids.get(p.ppid) || kids.set(p.ppid, []).get(p.ppid)).push(p.pid); const out = new Set(); const q = [rootPid]; while (q.length) for (const c of kids.get(q.pop()) || []) if (!out.has(c)) { out.add(c); q.push(c); } return out; };

// ------------------------------------------------------------------ supervisor
export function createSupervisor({ spawn = realSpawn, ps = psList, kill = (pid, sig) => process.kill(pid, sig), diagBytes = 2048, scanEveryMs = 1500, setTimer = setTimeout } = {}) {
  const entries = []; let ticker = null;
  const aliveSet = () => new Set(ps().map((p) => p.pid));
  function scanOnce() {
    let list; try { list = ps(); } catch { return; }
    for (const e of entries) {
      const cmd = new Map(list.map((p) => [p.pid, p.command]));
      if (e.proc.pid) for (const d of descendantsOf(list, e.proc.pid)) if (!e.seen.has(d)) e.seen.set(d, cmd.get(d));
      for (const p of list) if (e.tokens.some((t) => t && p.command.includes(t)) && !e.seen.has(p.pid)) e.seen.set(p.pid, p.command);        // e.g. Chrome helpers carry --user-data-dir=<owned dir>
      e.seen.delete(process.pid);
    }
  }
  const sup = {
    entries, scanOnce,
    // Starts and REGISTERS the child before awaiting readiness, so a failed start is still stopped and reported.
    // Rejects (with bounded diagnostics) on spawn error, early exit, or readiness timeout; it never kills on its own: stopAll() does.
    spawnOwned({ label, cmd, args = [], opts = {}, ready, timeoutMs = 30000, dirs = [], tokens = [] }) {
      const e = { label, proc: null, dirs, tokens, seen: new Map(), diag: '', spawnError: null, exit: null, ready: false, stopped: false };   // seen: pid -> command at first sight
      const append = (d) => { e.diag = (e.diag + d).slice(-diagBytes); };
      let proc; try { proc = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], ...opts }); } catch (err) { e.proc = { pid: undefined, exitCode: null, signalCode: null }; e.spawnError = String(err.message).slice(0, 300); entries.push(e); return Promise.reject(new Error(`${label}: spawn threw: ${e.spawnError}`)); }
      e.proc = proc; entries.push(e);
      proc.stdout?.on('data', append); proc.stderr?.on('data', append);
      if (!ticker && scanEveryMs) { ticker = setInterval(scanOnce, scanEveryMs); ticker.unref?.(); }
      return new Promise((resolve, reject) => {
        let done = false; const fail = (why) => { if (done) return; done = true; clearTimeout(t); reject(new Error(`${label}: ${why}; diagnostics: ${e.diag.slice(-600).replace(/\s+/g, ' ')}`)); };
        const t = setTimer(() => fail(`not ready after ${timeoutMs} ms`), timeoutMs);
        proc.on('error', (err) => { e.spawnError = String(err.message).slice(0, 300); fail('spawn error: ' + e.spawnError); });
        proc.on('exit', (code, sig) => { e.exit = { code, sig }; fail(`exited before ready (code ${code}, signal ${sig})`); });
        const check = () => { if (done) return; const m = e.diag.match(ready); if (m) { done = true; clearTimeout(t); e.ready = true; scanOnce(); resolve({ entry: e, proc, match: m }); } };
        proc.stdout?.on('data', check); proc.stderr?.on('data', check);
      });
    },
    // SIGTERM each owned process and every owned descendant seen so far; wait up to graceMs; report survivors. Never SIGKILL.
    // `only` limits the action to one entry (used to release a phase's service as soon as the phase ends).
    async stopAll({ graceMs = 8000, pollMs = 100, only = null } = {}) {
      scanOnce();
      const set = only ? entries.filter((e) => e === only) : entries.filter((e) => !e.stopped);
      const targets = new Map();                              // pid -> label
      let now0; try { now0 = new Map(ps().map((p) => [p.pid, p.command])); } catch { now0 = new Map(); }
      for (const e of set) {
        if (e.proc.pid && e.proc.exitCode === null && e.proc.signalCode === null) targets.set(e.proc.pid, e.label);
        // PID-reuse guard: a historically seen descendant is signalled only if its CURRENT command line is still the one recorded at first sight.
        for (const [p, c] of e.seen) if (now0.has(p) && c !== undefined && now0.get(p) === c) targets.set(p, e.label + ' (descendant)');
      }
      for (const [pid] of targets) { try { kill(pid, 'SIGTERM'); } catch { /* already gone */ } }
      const t0 = Date.now(); let alive;
      do { await sleep(pollMs); alive = aliveSet(); } while (Date.now() - t0 < graceMs && [...targets.keys()].some((p) => alive.has(p)));
      scanOnce(); const alive1 = aliveSet();
      for (const e of set) e.stopped = true;
      return set.map((e) => {
        const pids = [e.proc.pid, ...e.seen.keys()].filter((p) => p);
        const survivors = pids.filter((p) => alive1.has(p));
        return { label: e.label, pid: e.proc.pid ?? null, started: !!e.proc.pid, ready: e.ready, spawnError: e.spawnError, exit: e.exit, descendantsSeen: e.seen.size, survivors, dirs: e.dirs, diag: e.diag.slice(-300) };
      });
    },
    // Deletes an entry's directories ONLY if it and all its owned descendants have exited. Otherwise the directories are preserved and reported.
    removeDirs(report) {
      const out = [];
      for (const r of report) for (const d of r.dirs) {
        if (r.survivors.length) { out.push({ dir: d, removed: false, reason: `owner ${r.label} has survivors ${r.survivors.join(',')}` }); continue; }
        try { rmSync(d, { recursive: true, force: true }); out.push({ dir: d, removed: true }); } catch (err) { out.push({ dir: d, removed: false, reason: String(err.message).slice(0, 120) }); }
      }
      return out;
    },
    stopTicker() { if (ticker) clearInterval(ticker); ticker = null; },
    // Releases child stdio and the event-loop reference so a SIGTERM-ignoring survivor cannot keep the driver process alive after the results are written.
    detach() { for (const e of entries) { try { e.proc.stdout?.destroy(); e.proc.stderr?.destroy(); e.proc.unref?.(); } catch { /* ignore */ } } },
  };
  return sup;
}

// ------------------------------------------------------------------ row recorder
// Evidence modes (never mixed up in a claim): 'real-server' = produced by the real backend projection in this run; 'fixture-substituted' = a frontend response
// served from a contract JSON file (proves rendering, NOT that the backend generated or validated it); 'adapter-synthesized' = built by the harness from a fixture field.
export const MODES = ['real-server', 'fixture-substituted', 'adapter-synthesized', 'ui-only'];
export function createRecorder(rowIds) {
  const rows = Object.fromEntries(rowIds.map((id) => [id, { obs: [], status: 'not yet exercised' }]));
  const hygiene = [];
  return {
    rows, hygiene,
    obs(row, id, ok, detail, ctx) {
      if (!rows[row]) throw new Error('unknown row ' + row);
      if (!MODES.includes(ctx?.mode)) throw new Error(`observation ${row}/${id} lacks an evidence mode`);
      rows[row].obs.push({ id, ok: !!ok, detail: String(detail ?? '').slice(0, 400), ...ctx });
    },
    note(id, ok, detail) { hygiene.push({ id, ok: !!ok, detail: String(detail ?? '').slice(0, 400) }); },
    finalize() { for (const r of Object.values(rows)) if (r.obs.length) r.status = r.obs.some((o) => !o.ok) ? 'not matched (observed failure)' : 'not yet exercised (partial: recorded observations passed; the evaluator compares them with the full pass criteria)'; return rows; },
  };
}
