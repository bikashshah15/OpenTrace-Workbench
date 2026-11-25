// UIP-03 acceptance review sheets: reference (left) | application (right) from EXISTING valid captures (no regeneration), cropped/downscaled for review.
//   node tools/uip/visual/accept_sbs.mjs --out evidence/uip/acceptance/uip-03/sheets
// Reference captures: evidence/uip/visual/uip-02/reference (reference hash d5bc14fa…3a148, unchanged). Application captures: evidence/uip/visual/uip-03/app.
// A montage of application-only Scan states is also produced (the reference defines none of them). Review aids, not parity oracles.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodePng, encodePng, sideBySide } from './lib.mjs';
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const args = process.argv.slice(2); const OUT = resolve(args[args.indexOf('--out') + 1] || join(REPO, 'evidence/uip/acceptance/uip-03/sheets'));
mkdirSync(OUT, { recursive: true });
const REF = join(REPO, 'evidence/uip/visual/uip-02/reference'), APP = join(REPO, 'evidence/uip/visual/uip-03/app');
const load = (p) => { if (!existsSync(p)) throw new Error('missing ' + p); return decodePng(readFileSync(p)); };
const crop = (img, h) => { const H = Math.min(h, img.height); return { width: img.width, height: H, data: img.data.subarray(0, img.width * H * 4) }; };
const scale = (img, k) => { if (k === 1) return img; const w = Math.floor(img.width / k), h = Math.floor(img.height / k), d = Buffer.alloc(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) { for (let c = 0; c < 4; c++) { let s = 0; for (let j = 0; j < k; j++) for (let i = 0; i < k; i++) s += img.data[((y * k + j) * img.width + (x * k + i)) * 4 + c]; d[(y * w + x) * 4 + c] = Math.round(s / (k * k)); } } return { width: w, height: h, data: d }; };
const sheets = [];
const pair = (name, refFile, appFile, h, k) => { const r = scale(crop(load(join(REF, refFile)), h), k), a = scale(crop(load(join(APP, appFile)), h), k);
  writeFileSync(join(OUT, name + '.png'), encodePng(sideBySide(r, a))); sheets.push({ sheet: name + '.png', left: 'reference/' + refFile, right: 'app/' + appFile, crop_px: h, downscale: k }); };
pair('sbs_home_A_1366_light', 'reference_1366_light_home.png', 'home-variant-A_1366_light.png', 1300, 2);
pair('sbs_home_A_1366_dark', 'reference_1366_dark_home.png', 'home-variant-A_1366_dark.png', 1300, 2);
pair('sbs_home_D_1366_light', 'reference_1366_light_home.png', 'home-variant-D_1366_light.png', 1300, 2);
pair('sbs_home_A_1920_light', 'reference_1920_light_home.png', 'home-variant-A_1920_light.png', 1300, 2);
pair('sbs_home_A_390_light', 'reference_390_light_home.png', 'home-variant-A_390_light.png', 1700, 1);
pair('sbs_home_A_390_dark', 'reference_390_dark_home.png', 'home-variant-A_390_dark.png', 1700, 1);
pair('sbs_handoff_1366_light', 'reference_1366_light_workbench-contexts.png', 'handoff-workbench-completed_1366_light.png', 1300, 2);
pair('sbs_handoff_390_dark', 'reference_390_dark_workbench-contexts.png', 'handoff-workbench-completed_390_dark.png', 1700, 1);
// application-only Scan states montage (1366 light, cropped to the intake region)
const states = ['scan-starting', 'scan-sbom-running', 'scan-shared-worker-phase', 'scan-failed-cbom', 'scan-cancelled', 'scan-completed-transient-panel'];
let row = null; const imgs = states.map((s) => scale(crop(load(join(APP, `${s}_1366_light.png`)), 1000), 2));
for (let i = 0; i < imgs.length; i += 2) { const pr = sideBySide(imgs[i], imgs[i + 1]); row = row ? (() => { const h = row.height + pr.height; const d = Buffer.alloc(Math.max(row.width, pr.width) * h * 4, 255); const W = Math.max(row.width, pr.width); for (let y = 0; y < row.height; y++) row.data.copy(d, y * W * 4, y * row.width * 4, (y + 1) * row.width * 4); for (let y = 0; y < pr.height; y++) pr.data.copy(d, (row.height + y) * W * 4, y * pr.width * 4, (y + 1) * pr.width * 4); return { width: W, height: h, data: d }; })() : pr; }
writeFileSync(join(OUT, 'montage_scan_states_app_only_1366_light.png'), encodePng(row));
sheets.push({ sheet: 'montage_scan_states_app_only_1366_light.png', states, note: 'application-only; no reference exists for Scan states', crop_px: 1000, downscale: 2 });
writeFileSync(join(OUT, 'index.json'), JSON.stringify({ schema: 'opentrace.uip.acceptance_sheets/1', reference_hash: 'd5bc14fabff29dc42a53dab1f91ae88a6165d70aee808f17e76d066901b3a148', sheets }, null, 1) + '\n');
console.log('wrote', sheets.length, 'sheets to', OUT);
