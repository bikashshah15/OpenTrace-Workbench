// Stage 4 closing campaign, launch C (DA-18): runs the frozen, previously reviewed deterministic assistant driver (lab_assistant_driver_v3.mjs, sha256 recorded in the
// frozen expectations) on THIS candidate tree, accounted in the SAME allowance ledger as the rest of the campaign (allowance_final.json): one service + one headed Chrome.
// The driver itself is byte-identical to the PR #79 evidence-branch copy; its EXPECT table is not touched. In-process deterministic broker; no provider, no network.
//   node run_stage4_final_assistant.mjs --dry                 print the plan; spend nothing, launch nothing
//   node run_stage4_final_assistant.mjs run <label> [--rerun]  spend 1 service + 1 Chrome from the final ledger, then run the driver
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createLedger } from './run_stage4_lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
export const LEDGER_FILE = join(REPO, 'evidence/uip/validation/stage4-desktop/allowance_final.json');
export const CEILINGS = Object.freeze({ service: 8, chrome: 4, minutes: 90, rerun: 1 });
export const PLANNED = Object.freeze({ service: 7, chrome: 3 });
export const DRIVER = join(HERE, 'lab_assistant_driver_v3.mjs');
export const MIN_MINUTES_NEEDED = 20;                 // the driver's readiness minimum (READINESS_V3: 1 service, 1 Chrome, 20 minutes)
export const driverEnv = ({ repo, sha, out, py, minutes, base = process.env }) => {
  const keep = ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'USER', 'LOGNAME', '__CF_USER_TEXT_ENCODING'];
  const env = {}; for (const k of keep) if (base[k]) env[k] = base[k];
  return { ...env, OT_SRC: repo, OT_SRC_SHA: sha, OT_EVIDENCE: out, PYTHON_BIN: py, OT_ALLOW_SERVICE: '1', OT_ALLOW_CHROME: '1', OT_ALLOW_MINUTES: String(minutes) };
};
const mode = process.argv[2];
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const sha = execFileSync('git', ['-C', REPO, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const dirty = execFileSync('git', ['-C', REPO, 'status', '--porcelain', '--', 'src', 'tests', 'tools'], { encoding: 'utf8' }).trim() !== '';
  const py = process.env.PYTHON_BIN || process.env.PYTHON || 'python3';
  if (mode === '--dry') {
    const l = createLedger({ file: LEDGER_FILE, ceilings: CEILINGS, planned: PLANNED });
    console.log(JSON.stringify({ repo: REPO, sha, dirty, driver: DRIVER, ledger: { ...l.snapshot(), events: undefined }, remainingMinutes: Math.floor(l.remainingMs() / 60000), wouldSpend: { service: 1, chrome: 1 } }, null, 1)); process.exit(0);
  }
  if (mode !== 'run' || !process.argv[3]) { console.error('usage: --dry | run <label> [--rerun]'); process.exit(2); }
  if (dirty) { console.error('refused: the tested tree must be clean (src/tests/tools); nothing launched'); process.exit(2); }
  const label = process.argv[3].replace(/[^\w.-]/g, '_'); const out = resolve(REPO, 'evidence/uip/validation/stage4-desktop', label);
  if (existsSync(out) && readdirSync(out).length) { console.error('refused: output directory already holds evidence'); process.exit(2); }
  const exp = (process.argv.find((a) => a.startsWith('--expect-sha=')) || '').slice(13);
  if (!(exp.length >= 12 && sha.startsWith(exp))) { console.error(`refused: --expect-sha=<reviewed candidate sha> must equal HEAD (${sha}); nothing spent`); process.exit(2); }
  if (!py.startsWith('/') || !existsSync(py)) { console.error('refused: PYTHON_BIN must be an absolute path to the project venv python (the driver preflight needs networkx); nothing spent'); process.exit(2); }
  const ledger = createLedger({ file: LEDGER_FILE, ceilings: CEILINGS, planned: PLANNED });
  const minutes = Math.floor(ledger.remainingMs() / 60000);
  if (minutes < MIN_MINUTES_NEEDED) { console.error(`refused: ${minutes} minutes remain; the driver needs at least ${MIN_MINUTES_NEEDED}; nothing spent`); process.exit(2); }
  mkdirSync(out, { recursive: true });
  const pre = spawnSync(process.execPath, [DRIVER, '--preflight'], { cwd: REPO, env: driverEnv({ repo: REPO, sha, out, py, minutes }), encoding: 'utf8' });   // the driver's own gate, BEFORE anything is spent
  if (pre.status !== 0) { console.error('refused: the driver preflight failed; nothing spent\n' + String(pre.stdout).slice(-1500)); process.exit(2); }
  const rerun = process.argv.includes('--rerun'); if (rerun) ledger.markRerun('harness-correction rerun of the DA-18 assistant driver');
  ledger.spend('service', 'DA-18 assistant fixture service (v3 driver)', { rerun }); ledger.spend('chrome', 'DA-18 assistant headed Chrome (v3 driver)', { rerun });
  console.log('allowance after spend:', JSON.stringify({ ...ledger.snapshot(), events: undefined }));
  const child = spawn(process.execPath, [DRIVER, 'run', label], { cwd: REPO, env: driverEnv({ repo: REPO, sha, out, py, minutes }), stdio: 'inherit' });
  child.on('exit', (code, sig) => { writeFileSync(join(out, 'wrapper_result.json'), JSON.stringify({ sha, label, exit: code, signal: sig, allowance: ledger.snapshot(), finished: new Date().toISOString() }, null, 1)); process.exit(code ?? 1); });
}
