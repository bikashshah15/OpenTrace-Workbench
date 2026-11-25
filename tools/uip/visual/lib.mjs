// UIP-02 visual harness: pure helpers (no browser, no network). Unit-tested by tests/ui/unit/visual_harness.test.mjs.
//
// Difference metric (frozen by contract §6): for two same-size 8-bit RGBA captures, `ratio` = (number of pixels where ANY of the four
// channels differs by more than 0) / (width * height), in [0, 1]; `pixels` is the numerator. A size mismatch is ratio 1.0.
// Threshold = 2 x the maximum observed repeat ratio rounded UP to the next 1e-6; zero measured variance gives threshold 0. It is never
// raised to accommodate an implementation regression: the only input is the repeat measurement.
import { createHash } from 'node:crypto';
import { inflateSync, deflateSync } from 'node:zlib';

export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

export const VIEWPORTS = [{ id: '1366', width: 1366, height: 900 }, { id: '1920', width: 1920, height: 1080 }, { id: '390', width: 390, height: 844, mobile: true }];
export const THEMES = ['light', 'dark'];
export const MAX_PAGE_HEIGHT = 4000;
export const SETTINGS = { deviceScaleFactor: 1, reducedMotion: true, locale: 'en-US', timezone: 'UTC', maxPageHeight: MAX_PAGE_HEIGHT, repeats: 10, readiness: 'document.fonts.ready + 2 quiet animation frames + two consecutive byte-identical screenshots 200 ms apart (polled up to 5 s; failure otherwise)', motion: 'prefers-reduced-motion: reduce emulated (no style is injected: the app CSP is style-src self)', network: 'loopback HTTP only; every other request blocked and recorded' };

// Loopback HTTP and non-network schemes are permitted; every other request is blocked and recorded.
export function isLoopbackUrl(u) {
  let url; try { url = new URL(u); } catch { return false; }
  if (['data:', 'blob:', 'about:', 'file:'].includes(url.protocol)) return true;
  return ['http:', 'ws:'].includes(url.protocol) && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
}

// ---------------------------------------------------------------- PNG (8-bit, non-interlaced; what Chrome emits)
export function decodePng(buf) {
  if (buf.length < 8 || buf.readUInt32BE(0) !== 0x89504e47) throw new Error('not a PNG');
  let off = 8; let w = 0; let h = 0; let depth = 0; let ctype = 0; const idat = [];
  while (off < buf.length) {
    const len = buf.readUInt32BE(off); const type = buf.toString('ascii', off + 4, off + 8); const body = buf.subarray(off + 8, off + 8 + len);
    if (type === 'IHDR') { w = body.readUInt32BE(0); h = body.readUInt32BE(4); depth = body[8]; ctype = body[9]; if (body[12] !== 0) throw new Error('interlaced PNG unsupported'); }
    else if (type === 'IDAT') idat.push(body); else if (type === 'IEND') break;
    off += 12 + len;
  }
  if (depth !== 8 || (ctype !== 6 && ctype !== 2)) throw new Error(`unsupported PNG format depth=${depth} type=${ctype}`);
  const bpp = ctype === 6 ? 4 : 3; const stride = w * bpp; const raw = inflateSync(Buffer.concat(idat)); const out = Buffer.alloc(w * h * 4);
  let prev = Buffer.alloc(stride); let cur = Buffer.alloc(stride);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)]; raw.copy(cur, 0, y * (stride + 1) + 1, y * (stride + 1) + 1 + stride);
    for (let i = 0; i < stride; i++) {
      const a = i >= bpp ? cur[i - bpp] : 0; const b = prev[i]; const c = i >= bpp ? prev[i - bpp] : 0;
      let v = cur[i];
      if (f === 1) v += a; else if (f === 2) v += b; else if (f === 3) v += (a + b) >> 1;
      else if (f === 4) { const p = a + b - c; const pa = Math.abs(p - a); const pb = Math.abs(p - b); const pc = Math.abs(p - c); v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      else if (f !== 0) throw new Error('bad PNG filter ' + f);
      cur[i] = v & 255;
    }
    for (let x = 0; x < w; x++) { const o = (y * w + x) * 4; out[o] = cur[x * bpp]; out[o + 1] = cur[x * bpp + 1]; out[o + 2] = cur[x * bpp + 2]; out[o + 3] = bpp === 4 ? cur[x * bpp + 3] : 255; }
    [prev, cur] = [cur, prev];
  }
  return { width: w, height: h, data: out };
}

const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = (b) => { let c = 0xffffffff; for (const x of b) c = CRC[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
export function encodePng({ width, height, data }) {
  const chunk = (type, body) => { const o = Buffer.alloc(12 + body.length); o.writeUInt32BE(body.length, 0); o.write(type, 4, 'ascii'); body.copy(o, 8); o.writeUInt32BE(crc32(o.subarray(4, 8 + body.length)), 8 + body.length); return o; };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4); ihdr[8] = 8; ihdr[9] = 6;
  const raw = Buffer.alloc(height * (width * 4 + 1));
  for (let y = 0; y < height; y++) data.copy(raw, y * (width * 4 + 1) + 1, y * width * 4, (y + 1) * width * 4);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw, { level: 6 })), chunk('IEND', Buffer.alloc(0))]);
}

// ---------------------------------------------------------------- metric, thresholds, statistics
export function diffStats(a, b) {
  if (a.width !== b.width || a.height !== b.height) return { ratio: 1, pixels: Math.max(a.width * a.height, b.width * b.height), total: Math.max(a.width * a.height, b.width * b.height), sizeMismatch: true };
  const total = a.width * a.height; let pixels = 0;
  for (let i = 0; i < total * 4; i += 4) if (a.data[i] !== b.data[i] || a.data[i + 1] !== b.data[i + 1] || a.data[i + 2] !== b.data[i + 2] || a.data[i + 3] !== b.data[i + 3]) pixels++;
  return { ratio: total ? pixels / total : 0, pixels, total, sizeMismatch: false };
}
export const thresholdFor = (maxRatio) => (maxRatio > 0 ? Math.ceil(2 * maxRatio * 1e6) / 1e6 : 0);
export function summarize(ratios) {
  if (!ratios.length) return { comparisons: 0, max: 0, mean: 0, threshold: 0 };
  const max = Math.max(...ratios); return { comparisons: ratios.length, max, mean: ratios.reduce((x, y) => x + y, 0) / ratios.length, threshold: thresholdFor(max) };
}

// Side-by-side composition: two images on one canvas separated by a 12 px strip (review aid only).
export function sideBySide(left, right) {
  const gap = 12; const h = Math.max(left.height, right.height); const w = left.width + gap + right.width; const data = Buffer.alloc(w * h * 4, 255);
  const blit = (img, x0) => { for (let y = 0; y < img.height; y++) img.data.copy(data, (y * w + x0) * 4, y * img.width * 4, (y + 1) * img.width * 4); };
  blit(left, 0); blit(right, left.width + gap);
  for (let y = 0; y < h; y++) for (let x = left.width; x < left.width + gap; x++) { const o = (y * w + x) * 4; data[o] = 120; data[o + 1] = 120; data[o + 2] = 120; }
  return { width: w, height: h, data };
}

// ---------------------------------------------------------------- capture record (one per image)
export const RECORD_FIELDS = ['reference_hash', 'tested_commit', 'fixture', 'viewport', 'theme', 'tab', 'selection', 'state', 'browser', 'device_scale_factor', 'zoom', 'fonts', 'readiness', 'png_sha256', 'png_bytes', 'width', 'height', 'path'];
export function captureRecord(o) {
  const rec = {}; for (const k of RECORD_FIELDS) { if (!(k in o)) throw new Error('capture record is missing ' + k); rec[k] = o[k]; }
  if (!/^[0-9a-f]{64}$/.test(rec.png_sha256)) throw new Error('bad png_sha256');
  return rec;
}

// ---------------------------------------------------------------- fail-closed state walking (UIP-02-IR-04)
// A capture is labelled with a state only after (1) the step ran without error and (2) the OBSERVED page state matches that state's
// expectation. A failed interaction, a missing control, a wrong destination/tab/selection or a wrong theme throws a CaptureError
// BEFORE anything is captured or recorded for that state. The page is always closed. No browser is needed to test this module:
// `page` and every hook are injected.
export class CaptureError extends Error { constructor(message, detail = {}) { super(message); this.name = 'CaptureError'; this.detail = detail; } }
export const APP_STATE_IDS = ['home', 'workbench-contexts', 'inspector-contexts', 'inspector-dependencies', 'inspector-crypto', 'inspector-ai'];
export const REFERENCE_STATE_IDS = ['home', 'workbench-contexts', 'inspector-contexts'];

// expect: { key: value | RegExp | (observed value) => boolean }. A key missing from `observed` is a failure, never a pass.
export function checkExpectation(stateId, expect, observed) {
  if (!observed || typeof observed !== 'object') throw new CaptureError(`state ${stateId}: no page state was observed`);
  const bad = [];
  for (const [k, want] of Object.entries(expect || {})) {
    const got = observed[k];
    const ok = got === undefined || got === null ? false : want instanceof RegExp ? want.test(String(got)) : typeof want === 'function' ? !!want(got) : got === want;
    if (!ok) bad.push(`${k}: expected ${want instanceof RegExp ? want : typeof want === 'function' ? 'a matching value' : JSON.stringify(want)}, observed ${JSON.stringify(got)}`);
  }
  if (bad.length) throw new CaptureError(`state ${stateId}: the page is not in the expected state (${bad.join('; ')})`, { stateId, observed });
}

// states: [{ id, run(page), expect | expectFor(ctx) }]; hooks: { observe(page, st), settle(page, st), capture(page, st), sink(record) }.
export async function walkStates(states, page, hooks, ctx = {}) {
  const done = [];
  try {
    for (const st of states) {
      try { await st.run(page, ctx); } catch (e) { throw e instanceof CaptureError ? e : new CaptureError(`state ${st.id}: the interaction failed: ${e && e.message ? e.message : e}`, { stateId: st.id }); }
      if (hooks.settle) await hooks.settle(page, st);
      const observed = await hooks.observe(page, st);
      checkExpectation(st.id, { ...(typeof st.expectFor === 'function' ? st.expectFor(ctx) : st.expect), ...(ctx.theme ? { theme: ctx.theme } : {}) }, observed);
      const png = await hooks.capture(page, st);
      await hooks.sink({ state: st.id, observed, png });
      done.push(st.id);
    }
    return done;
  } finally {
    try { await page.close(); } catch { /* closing a broken page must not mask the real error */ }
  }
}

// Every (viewport, theme, state) of every required kind must be present exactly once; anything else is an error.
export function assertMatrix(records, required, viewports, themes) {
  const have = new Map(); for (const r of records) have.set(r.path, (have.get(r.path) || 0) + 1);
  const missing = []; const dup = [];
  for (const [prefix, states] of Object.entries(required)) for (const vp of viewports) for (const th of themes) for (const st of states) {
    const p = `${prefix}_${vp}_${th}_${st}.png`; const n = have.get(p) || 0;
    if (n === 0) missing.push(p); else if (n > 1) dup.push(p);
  }
  if (missing.length || dup.length) throw new CaptureError(`the capture matrix is incomplete${missing.length ? `: missing ${missing.length} (${missing.slice(0, 4).join(', ')}${missing.length > 4 ? ', …' : ''})` : ''}${dup.length ? `; duplicated ${dup.join(', ')}` : ''}`, { missing, dup });
  return records.length;
}

// Contract §6 reviewable coverage of a COMMITTED evidence set: per viewport and theme, an application image for each inspector state
// and a side-by-side for each state that has a reference counterpart. `exists(relativePath)` is injected.
export function reviewableCoverage(viewports, themes, exists) {
  const missing = [];
  for (const vp of viewports) for (const th of themes) {
    for (const st of APP_STATE_IDS.filter((s) => s.startsWith('inspector-') && !REFERENCE_STATE_IDS.includes(s))) if (!exists(`app/app_${vp}_${th}_${st}.png`)) missing.push(`app/app_${vp}_${th}_${st}.png`);
    for (const st of REFERENCE_STATE_IDS) if (!exists(`side-by-side/sbs_${vp}_${th}_${st}.png`)) missing.push(`side-by-side/sbs_${vp}_${th}_${st}.png`);
  }
  return missing;
}
