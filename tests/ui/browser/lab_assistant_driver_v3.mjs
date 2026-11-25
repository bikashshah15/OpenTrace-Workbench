// Lab Assistant deterministic browser-validation driver v3 (affected-check follow-up after the adoption correction; PR #75 is NOT modified).
// NOT LAUNCHED. Caps default to ZERO: it refuses to launch until an owner-approved allowance is supplied via
//   OT_ALLOW_SERVICE, OT_ALLOW_CHROME, OT_ALLOW_MINUTES (explicit numbers) and a fresh ledger-v3.json.
// Usage: OT_SRC=<pinned checkout> OT_EVIDENCE=<dir> PYTHON_BIN=<venv python> node lab_assistant_driver_v3.mjs <run LABEL | --preflight | --plan | --selftest>
// Runs the UNMODIFIED tests/ui/browser/assistant_service.py (in-process deterministic broker; no provider/network).
// Every real click is preceded by an elementFromPoint hit test; an occluded target is recorded and NOT bypassed with a programmatic click.
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import vm from 'node:vm';

const SRC = resolve(process.env.OT_SRC || '.');
const EVID = resolve(process.env.OT_EVIDENCE || '.');
const MODE = process.argv[2];
const LABEL = process.argv[3] || '';
const CAP = { service: Number(process.env.OT_ALLOW_SERVICE || 0), chrome: Number(process.env.OT_ALLOW_CHROME || 0), minutes: Number(process.env.OT_ALLOW_MINUTES || 0) };
const LEDGER = join(EVID, 'ledger-v3.json');
const HOME = process.env.HOME || '';
const TMP = (process.env.TMPDIR || '/tmp').replace(/\/$/, '');
const PY = process.env.PYTHON_BIN || '';

// ---------------- pure helpers (selftested) ----------------
export function cleanEnv(base, extra = {}) {
  const keep = ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'USER', 'LOGNAME', '__CF_USER_TEXT_ENCODING'];
  const out = {}; for (const k of keep) if (base[k]) out[k] = base[k];
  return { ...out, ...extra };
}
export const serviceExtra = (src, state, countFile) => ({ PYTHONPATH: `${src}/src/core:${src}/src/agents/investigator:${src}`, PYTHONDONTWRITEBYTECODE: '1',
  OT_ASSISTANT_FIXTURE_STATE: state, OT_ASSISTANT_BROKER_COUNT_FILE: countFile, OPENTRACE_LIVE_SCAN: '0', OPENTRACE_LIVE_ADVISORIES: '0', OPENTRACE_LIVE_AIBOM: '0' });
export function sanitize(text, repl = []) {
  let t = String(text || ''); for (const [from, to] of repl) if (from) t = t.split(from).join(to);
  return t.replace(/ot_session=[^\s;"]+/g, 'ot_session=<redacted>').replace(/(sk-|ghp_|xox[a-z]-)[A-Za-z0-9_-]{8,}/g, '<redacted>').replace(/\/Users\/[^/\s]+/g, '/Users/<user>').slice(-3000);
}
export function ledgerGate(l, kind, cap, now = Date.now()) {
  if (!(cap.service > 0 && cap.chrome > 0 && cap.minutes > 0)) return 'no owner-approved allowance supplied (OT_ALLOW_SERVICE/CHROME/MINUTES)';
  if (l.firstLaunchAt && now - l.firstLaunchAt > cap.minutes * 60000) return 'time allowance exhausted';
  if (kind === 'service' && l.service >= cap.service) return 'service launch allowance exhausted';
  if (kind === 'chrome' && l.chrome >= cap.chrome) return 'chrome launch allowance exhausted';
  return null;
}
export function descendants(rows, roots) {
  const kids = new Map(); for (const r of rows) (kids.get(r.ppid) || kids.set(r.ppid, []).get(r.ppid)).push(r.pid);
  const seen = new Set(roots); const q = [...roots]; while (q.length) for (const k of kids.get(q.shift()) || []) if (!seen.has(k)) { seen.add(k); q.push(k); }
  return [...seen];
}
export const hitVerdict = (h) => !!(h && h.found && h.insideViewport && h.ok);
export function settled(series, n = 5) {            // last n samples identical in zoom/pan and not animating
  if (series.length < n) return false; const t = series.slice(-n);
  return t.every((s) => s && !s.anim && s.z === t[0].z && s.px === t[0].px && s.py === t[0].py);
}
export function cookieSummary(a, b) {               // outcomes only; raw values never leave this function
  const pa = !!a, pb = !!b; return { presentA: pa, presentB: pb, httpOnlyA: !!a?.httpOnly, httpOnlyB: !!b?.httpOnly, distinct: pa && pb && a.value !== b.value };
}
export const camEqual = (a, b) => !!a && !!b && a.z === b.z && a.px === b.px && a.py === b.py;
export const sameSet = (a, b) => JSON.stringify([...(a || [])].sort()) === JSON.stringify([...(b || [])].sort());

// ---------------- frozen expectations (declared BEFORE any run; never edited after results) ----------------
// kind: 'dispatch' = the request reaches the deterministic broker (+1 broker invocation);
//       'pre-reject' = the server rejects before dispatch (0 broker invocations), with the exact status/code below;
//       'client-blocked' = the UI refuses to send (0 requests, 0 broker invocations), per assistantCanSubmit.
export const EXPECT = Object.freeze({
  Q1:   { kind: 'dispatch', note: 'whole-analysis question' },
  FU:   { kind: 'dispatch', note: 'follow-up with a different page selection; no adoption' },
  AD1:  { kind: 'dispatch', note: 'first explicit model adoption; must succeed' },
  REJ:  { kind: 'pre-reject', status: 400, code: 'subject_not_in_resolved_evidence', note: 'adoption request whose subject id is rewritten by the harness (Fetch request stage) to an id not in resolved evidence' },
  BLK1: { kind: 'client-blocked', note: 'plain follow-up after the rejected adoption: UI must refuse (adoptionUncertain) and send nothing' },
  AD2:  { kind: 'dispatch', note: 'recovery: re-checked explicit adoption after the rejection; must succeed' },
  LOST: { kind: 'dispatch', responseLost: true, note: 'adoption whose response is discarded by the harness (Fetch response stage); the server completes it, the UI never receives it' },
  BLK2: { kind: 'client-blocked', note: 'plain follow-up after the lost response: UI must refuse and send nothing' },
  AD3:  { kind: 'dispatch', note: 'retry: re-checked explicit adoption after the lost response; must succeed' },
  CAN:  { kind: 'dispatch', cancelled: true, note: 'cancellation probe (broker holds 1.5 s); retired by Cancel' },
  RPT:  { kind: 'dispatch', note: 'question asked after returning to the graph (repaint check)' },
  B1:   { kind: 'dispatch', context: 'B', note: 'question from the isolated browser context (only if its session precondition is met)' },
  END:  { kind: 'dispatch', lateStatus: 409, lateCode: 'stale_or_cancelled', note: 'End-session probe: pending at End, late reply must be retired' },
});
export const expectedBroker = (E = EXPECT, withB = true) => Object.entries(E).filter(([k, e]) => e.kind === 'dispatch' && (withB || e.context !== 'B')).length;
export const expectedRequests = (E = EXPECT, withB = true) => Object.entries(E).filter(([k, e]) => (e.kind === 'dispatch' || e.kind === 'pre-reject') && (withB || e.context !== 'B')).length;
export function rewriteAdoptBody(text, forgedId) {      // controlled harness mutation for REJ only; never records the body
  const j = JSON.parse(text); if (j.adopt_subject !== true || !j.subject || typeof j.subject !== 'object') throw new Error('not an adoption request');
  return JSON.stringify({ ...j, subject: { ...j.subject, id: forgedId } });
}
export function classifyPan(t) {         // deterministic reading of one pan trial; labels the evidence, never asserts a cause
  const e = t.events || []; const down = e.filter((x) => x.t === 'pointerdown');
  if (!e.length) return 'input-not-delivered';
  if (!down.length) return 'no-pointerdown-seen';
  if (down.some((x) => !x.trusted)) return 'untrusted-event';
  if (t.pathBlockers && t.pathBlockers.length) return 'path-crosses-element-outside-host';
  if (!down[0].inHost) return 'pointerdown-target-outside-host';
  if (t.moved) return 'panned';
  if (t.cy && (t.cy.tapstart || t.cy.grab) && !t.cy.viewport) return 'cy-received-press-but-no-viewport-change';
  if (t.cy && !t.cy.tapstart && !t.cy.grab) return 'host-received-pointer-but-cy-saw-no-tap';
  return 'unclassified';
}
export function classifyIso(p) {        // explicit precondition ladder for the isolated browser context; a failed precondition is NOT evidence about session leakage
  if (!p.initialized) return 'not-initialized'; if (!p.configOk) return 'config-not-loaded'; if (!p.foreground) return 'not-foreground';
  if (!p.delivered) return 'input-not-delivered'; if (!p.sessionRequested) return 'delivered-but-no-session-request'; if (!p.sessionOk) return 'session-request-failed'; if (!p.analysisReady) return 'analysis-not-ready';
  return 'met';
}
export const PRE_STATUS = (cls) => (cls === 'met' ? 'pass' : 'precondition-unmet');

// ---------------- in-page expressions (each is parse-checked in the selftest) ----------------
const q = JSON.stringify;
export const HIT = (sel) => `(()=>{const e=document.querySelector(${q(sel)});if(!e)return {found:false};e.scrollIntoView({block:'center',inline:'center',behavior:'instant'});const r=e.getBoundingClientRect();const x=r.x+r.width/2,y=r.y+r.height/2;const h=document.elementFromPoint(x,y);const d=(n)=>n?(n.tagName.toLowerCase()+(n.id?'#'+n.id:'')+(n.classList&&n.classList.length?'.'+[...n.classList].slice(0,2).join('.'):'')).slice(0,70):null;return {found:true,x,y,w:r.width,h:r.height,target:d(e),hit:d(h),ok:!!h&&(e===h||e.contains(h)),insideViewport:x>=0&&y>=0&&x<=innerWidth&&y<=innerHeight}})()`;
export const CAM = `(()=>{const h=document.querySelector('[data-bom-cy="inline"]'),c=h&&h._cy;return c?{z:c.zoom(),px:c.pan().x,py:c.pan().y,anim:c.animated(),n:c.nodes().length,e:c.edges().length,rd:!!c.renderer().destroyed,dest:c.destroyed(),sel:c.$(':selected').map(x=>x.id())}:null})()`;
export const STORE_SEL = `(()=>{const b=window.__otStore.get().bom8||{};return {view:b.view??null,selected:b.selected??null,selectedRecord:b.selectedRecord??null,popup:b.popup??null,req:b.req?!!(b.req.related||b.req.graph||b.req.detail||b.req.queue):false}})()`;
export const PAN_POINTS = `(()=>{const h=document.querySelector('[data-bom-cy="inline"]'),c=h&&h._cy;if(!c)return null;h.scrollIntoView({block:'center',inline:'center',behavior:'instant'});const r=h.getBoundingClientRect();const bbs=c.nodes().map(n=>n.renderedBoundingBox({includeLabels:true}));let best=null;for(let x=20;x<r.width-60;x+=20)for(let y=20;y<r.height-40;y+=20){const gx=r.x+x,gy=r.y+y,ex=gx+40,ey=gy+25;const a=document.elementFromPoint(gx,gy),b=document.elementFromPoint(ex,ey);if(!a||!b||!h.contains(a)||!h.contains(b))continue;const d=Math.min(...bbs.map(bb=>Math.max(bb.x1-x,x-bb.x2,bb.y1-y,y-bb.y2)));if(!best||d>best.d)best={d,x:gx,y:gy,ex,ey}}return best&&best.d>=6?best:{none:true,host:{x:r.x,y:r.y,w:r.width,h:r.height}}})()`;
export const ASSIST_STATE = `(()=>{const a=window.__otStore.get().assistant;const el=document.querySelector('#ot-assistant');return {turns:a.turns.length,domTurns:document.querySelectorAll('.ot-assistant-turn').length,pending:!!a.pending,error:!!a.error,subject:a.subject?.kind||null,min:!!el?.classList.contains('min'),hidden:!!el?.hidden}})()`;
export const ADOPT_STATE = `(()=>{const i=document.querySelector('.ot-assistant-adopt input');const l=i?.closest('label');return {present:!!i,disabled:!!i?.disabled,checked:!!i?.checked,labelHasName:/\\(.+\\)/.test(l?.textContent||''),label:(l?.textContent||'').trim().slice(0,120)}})()`;
export const CITES = `(()=>{const t=window.__otStore.get().assistant.turns[0].response;const ids=new Set([...(t.answer.claims||[]).flatMap(c=>c.evidence_ids),...(t.answer.limitations||[]).flatMap(c=>c.evidence_ids),...(t.answer.next_steps||[]).map(s=>s.evidence_id)]);const known=new Set((t.citations||[]).map(c=>c.evidence_id));const els=[...document.querySelectorAll('.ot-assistant-turn')[0].querySelectorAll('.ot-assistant-citation')];return {ctx:t.context_id,n:els.length,allCtx:els.every(e=>e.dataset.context===t.context_id),allCited:els.every(e=>ids.has(e.dataset.evidence)),allKnown:els.every(e=>known.has(e.dataset.evidence)),extraNotInClaims:els.filter(e=>!ids.has(e.dataset.evidence)).length}})()`;
const DESC = `const d=(n)=>n?(n.tagName.toLowerCase()+(n.id?'#'+n.id:'')+(n.classList&&n.classList.length?'.'+[...n.classList].slice(0,2).join('.'):'')).slice(0,70):null;`;
// C06A: citations inside the answer body (claims, answer limitations, next steps) must equal, as a multiset of context|evidence pairs, what the VALIDATED STRUCTURED ANSWER cites.
export const CITE_ANSWER = (i) => `(()=>{const S=window.__otStore.get().assistant.turns;const k=${i}<0?S.length+${i}:${i};const t=S[k].response;const el=document.querySelectorAll('.ot-assistant-turn')[k];const pair=(c,e)=>c+'|'+e;
const exp=[...(t.answer.claims||[]).flatMap(c=>c.evidence_ids),...(t.answer.limitations||[]).flatMap(c=>c.evidence_ids),...(t.answer.next_steps||[]).map(s=>s.evidence_id)].map(id=>pair(t.context_id,id)).sort();
const act=[...el.querySelectorAll(':scope > .ot-assistant-claim .ot-assistant-citation, :scope > p.ot-assistant-limit .ot-assistant-citation, :scope > .ot-assistant-next .ot-assistant-citation')].map(e=>pair(e.dataset.context,e.dataset.evidence)).sort();
const known=new Set((t.citations||[]).map(c=>c.evidence_id));
return {ctx:t.context_id,expected:exp,actual:act,equal:JSON.stringify(exp)===JSON.stringify(act),n:act.length,allKnown:act.every(a=>known.has(a.split('|')[1])),allCtx:act.every(a=>a.split('|')[0]===t.context_id)}})()`;
// C06B: server coverage / limitation links (inside .ot-assistant-coverage and the Evidence limitations list) must be exactly the source-state evidence of the source named next to them.
export const CITE_COVERAGE = (i) => `(()=>{${DESC}const S=window.__otStore.get().assistant.turns;const k=${i}<0?S.length+${i}:${i};const t=S[k].response;const el=document.querySelectorAll('.ot-assistant-turn')[k];const items=t.citations||[];
const stateOf=(src)=>items.find(c=>c.source===src&&c.kind==='source_state')||null;const srcs=Object.keys(t.source_states||{});
const expCov=srcs.filter(s=>stateOf(s)).map(s=>s+'|'+stateOf(s).evidence_id).sort();
const expLim=(t.limitations||[]).map(x=>{const s=srcs.find(key=>x.startsWith(key+':'));return s&&stateOf(s)?s+'|'+stateOf(s).evidence_id:null}).filter(Boolean).sort();
const covLi=[...el.querySelectorAll('.ot-assistant-coverage li')];const actCov=covLi.map(li=>{const b=li.querySelector('strong');const a=li.querySelector('.ot-assistant-citation');return a?(b.textContent.replace(/:$/,'').replaceAll(' ','_')+'|'+a.dataset.evidence):null}).filter(Boolean).sort();
const limLi=[...el.querySelectorAll('section.ot-assistant-limit li')];const actLim=limLi.map(li=>{const a=li.querySelector('.ot-assistant-citation');const s=srcs.find(key=>li.textContent.startsWith(key+':'));return a&&s?s+'|'+a.dataset.evidence:null}).filter(Boolean).sort();
const all=[...el.querySelectorAll('.ot-assistant-coverage .ot-assistant-citation, section.ot-assistant-limit li .ot-assistant-citation')];
const coverageInAnswerBody=[...el.querySelectorAll(':scope > .ot-assistant-claim .ot-assistant-citation, :scope > p.ot-assistant-limit .ot-assistant-citation, :scope > .ot-assistant-next .ot-assistant-citation')].filter(a=>a.textContent.trim()==='Open coverage evidence').length;
return {ctx:t.context_id,sources:srcs.length,expCov,actCov,covEqual:JSON.stringify(expCov)===JSON.stringify(actCov),expLim,actLim,limEqual:JSON.stringify(expLim)===JSON.stringify(actLim),links:all.length,allCtx:all.every(a=>a.dataset.context===t.context_id),allLabelCoverage:all.every(a=>a.textContent.trim()==='Open coverage evidence'),allSourceState:all.every(a=>{const it=items.find(c=>c.evidence_id===a.dataset.evidence);return !!it&&it.kind==='source_state'}),unique:[...new Set(all.map(a=>a.dataset.evidence))],covIds:[...new Set(actCov.map(x=>x.split('|')[1]))],limIds:[...new Set(actLim.map(x=>x.split('|')[1]))],coverageInAnswerBody}})()`;
export const ASSIST_FULL = `(()=>{const a=window.__otStore.get().assistant;return {turns:a.turns.length,domTurns:document.querySelectorAll('.ot-assistant-turn').length,pending:!!a.pending,error:a.error?String(a.error).slice(0,220):null,adoptNext:!!a.adoptNext,adoptionUncertain:!!a.adoptionUncertain,subject:a.subject?.kind||null,subjectLabel:a.subject?.label||null}})()`;
export const LAST_TURN = `(()=>{const S=window.__otStore.get().assistant.turns;const t=S[S.length-1];if(!t)return null;const r=t.response;const items=r.citations||[];return {ctx:r.context_id,subjectKind:r.subject?.kind||null,subjectId:r.subject?.id??null,subjectLabel:r.subject?.label||null,status:r.answer?.answer_status||null,modelSourceCitations:items.filter(c=>c.source==='model_observations').length,subjectEvidencePresent:!!r.subject&&items.some(c=>c.label===r.subject.label),citationCount:items.length}})()`;
export const DIALOG_READ = `(()=>{const d=document.querySelector('#ot-dialog[open]');if(!d)return null;return {text:d.textContent.replace(/\\s+/g,' ').trim().slice(0,400),excerptChars:(d.querySelector('pre.source-excerpt')?.textContent||'').trim().length,strong:(d.querySelector('strong')?.textContent||'').trim()}})()`;
export const PAN_INSTALL = `(()=>{${DESC}const h=document.querySelector('[data-bom-cy="inline"]');const c=h&&h._cy;if(!c)return false;window.__ltPan={ev:[],cy:{tapstart:0,tapend:0,grab:0,free:0,pan:0,viewport:0}};
if(!window.__ltPanL){window.__ltPanL=(e)=>{const P=window.__ltPan;if(!P||P.ev.length>400)return;P.ev.push({t:e.type,trusted:e.isTrusted,x:Math.round(e.clientX),y:Math.round(e.clientY),tgt:d(e.target),inHost:!!document.querySelector('[data-bom-cy="inline"]')?.contains(e.target),btn:e.buttons})};for(const t of ['pointerdown','pointermove','pointerup','mousedown','mouseup'])document.addEventListener(t,window.__ltPanL,true)}
const f=window.__ltPanCyF=window.__ltPanCyF||{};if(window.__ltPanCyC&&window.__ltPanCyC!==c){for(const k of Object.keys(f))try{window.__ltPanCyC.off(k,f[k])}catch(e){}}
for(const k of Object.keys(window.__ltPan.cy)){if(f[k])try{c.off(k,f[k])}catch(e){}f[k]=()=>{if(window.__ltPan)window.__ltPan.cy[k]++};c.on(k,f[k])}window.__ltPanCyC=c;return true})()`;
export const PAN_READ = `(()=>{const P=window.__ltPan;const h=document.querySelector('[data-bom-cy="inline"]');const c=h&&h._cy;const b=window.__otStore.get().bom8||{};return {events:P?P.ev.slice(0,60):null,eventCount:P?P.ev.length:0,cy:P?P.cy:null,focus:document.hasFocus(),vis:document.visibilityState,flags:c?{panning:c.panningEnabled(),userPanning:c.userPanningEnabled(),ungrabify:c.autoungrabify(),selected:c.$(':selected').length}:null,store:{view:b.view??null,selectedRecord:b.selectedRecord??null,popup:!!b.popup,drawer:b.drawer??null}}})()`;
export const PAN_PATH = (x, y, ex, ey) => `(()=>{${DESC}const h=document.querySelector('[data-bom-cy="inline"]');const out=[];let bad=[];for(let i=0;i<=8;i++){const px=${x}+(${ex}-${x})*i/8,py=${y}+(${ey}-${y})*i/8;const e=document.elementFromPoint(px,py);const inH=!!e&&h.contains(e);out.push(d(e));if(!inH)bad.push({i,hit:d(e)})}const h2=h.getBoundingClientRect();return {record:{found:true,ok:bad.length===0,insideViewport:${x}>=0&&${y}>=0&&${ex}<=innerWidth&&${ey}<=innerHeight,target:d(h),hit:out[0]},start:out[0],end:out[8],path:[...new Set(out)],blockers:bad}})()`;
export const PAN_POINTS_AT = (skip) => `(()=>{const h=document.querySelector('[data-bom-cy="inline"]'),c=h&&h._cy;if(!c)return null;h.scrollIntoView({block:'center',inline:'center',behavior:'instant'});const r=h.getBoundingClientRect();const bbs=c.nodes().map(n=>n.renderedBoundingBox({includeLabels:true}));let best=null;const skip=${JSON.stringify(skip || null)};for(let x=20;x<r.width-60;x+=20)for(let y=20;y<r.height-40;y+=20){const gx=r.x+x,gy=r.y+y,ex=gx+40,ey=gy+25;if(skip&&Math.hypot(gx-skip.x,gy-skip.y)<150)continue;let ok=true;for(let i=0;i<=8;i++){const e=document.elementFromPoint(gx+(ex-gx)*i/8,gy+(ey-gy)*i/8);if(!e||!h.contains(e)){ok=false;break}}if(!ok)continue;const d=Math.min(...bbs.map(bb=>Math.max(bb.x1-x,x-bb.x2,bb.y1-y,y-bb.y2)));if(!best||d>best.d)best={d,x:gx,y:gy,ex,ey}}return best&&best.d>=6?best:{none:true,host:{x:r.x,y:r.y,w:r.width,h:r.height}}})()`;
export const ISO_INSTALL = `(()=>{window.__ltClick={n:0,trusted:0,types:[]};const b=document.querySelector('#ot-demo');if(!b)return false;for(const t of ['pointerdown','mousedown','mouseup','click'])document.addEventListener(t,(e)=>{if(e.target&&(e.target===b||b.contains(e.target))){window.__ltClick.n++;if(e.isTrusted)window.__ltClick.trusted++;if(window.__ltClick.types.length<8)window.__ltClick.types.push(e.type)}},true);return true})()`;
export const ISO_READY = `(()=>({ready:document.readyState,store:!!window.__otStore,demo:!!document.querySelector('#ot-demo'),demoEnabled:!!document.querySelector('#ot-demo')&&!document.querySelector('#ot-demo').disabled,focus:document.hasFocus(),vis:document.visibilityState,click:window.__ltClick||null}))()`;

const INPAGE = { HIT: HIT('#x'), CAM, STORE_SEL, PAN_POINTS, ASSIST_STATE, ADOPT_STATE, CITES, CITE_ANSWER: CITE_ANSWER(-1), CITE_COVERAGE: CITE_COVERAGE(-1), ASSIST_FULL, LAST_TURN, DIALOG_READ, PAN_INSTALL, PAN_READ, PAN_PATH: PAN_PATH(1, 2, 3, 4), PAN_POINTS_AT: PAN_POINTS_AT({ x: 1, y: 2 }), ISO_INSTALL, ISO_READY };

if (MODE === '--selftest') {
  const bad = [];
  const env = cleanEnv({ PATH: '/bin', HOME: '/h', TMPDIR: '/t', OPENAI_API_KEY: 'x', GITHUB_TOKEN: 'q', CLAUDE_CODE_MESSAGING_TOKEN: 'z' });
  if (Object.keys(env).join() !== 'PATH,HOME,TMPDIR') bad.push('cleanEnv');
  const se = { ...env, ...serviceExtra('/s', '/st', '/c') }; if (se.OPENTRACE_LIVE_SCAN !== '0' || se.OPENTRACE_LIVE_ADVISORIES !== '0' || /KEY|TOKEN/.test(Object.keys(se).join())) bad.push('serviceExtra');
  const cap = { service: 1, chrome: 1, minutes: 20 };
  if (ledgerGate({ service: 0, chrome: 0 }, 'service', { service: 0, chrome: 0, minutes: 0 }) === null) bad.push('zero caps must refuse');
  if (ledgerGate({ service: 1, chrome: 0 }, 'service', cap) === null || ledgerGate({ service: 1, chrome: 1 }, 'chrome', cap) === null || ledgerGate({ service: 0, chrome: 0 }, 'service', cap) !== null) bad.push('caps');
  if (ledgerGate({ service: 0, chrome: 0, firstLaunchAt: 1 }, 'chrome', cap, 1 + 21 * 60000) === null) bad.push('time');
  if (descendants([{ pid: 2, ppid: 1 }, { pid: 3, ppid: 2 }, { pid: 5, ppid: 9 }], [2]).sort().join() !== '2,3') bad.push('descendants');
  if (hitVerdict({ found: true, insideViewport: true, ok: false }) || !hitVerdict({ found: true, insideViewport: true, ok: true }) || hitVerdict({ found: false })) bad.push('hitVerdict');
  const s = (z, px, py, anim = false) => ({ z, px, py, anim });
  if (settled([s(1, 0, 0), s(1, 0, 0)]) || !settled([1, 2, 3, 4, 5].map(() => s(1, 2, 3))) || settled([1, 2, 3, 4, 5].map((i) => s(1, i, 3)))) bad.push('settled');
  const cs = cookieSummary({ value: 'AAA', httpOnly: true }, { value: 'BBB', httpOnly: true });
  if (!cs.distinct || JSON.stringify(cs).includes('AAA') || cookieSummary({ value: 'A' }, { value: 'A' }).distinct || cookieSummary(null, { value: 'A' }).distinct) bad.push('cookieSummary');
  if (!camEqual(s(1, 2, 3), s(1, 2, 3)) || camEqual(s(1, 2, 3), s(1, 2, 4)) || !sameSet(['a', 'b'], ['b', 'a']) || sameSet(['a'], [])) bad.push('cam/set');
  for (const [k, v] of Object.entries(INPAGE)) { try { new vm.Script(v); } catch (e) { bad.push(`in-page ${k} does not parse: ${e.message}`); } }
  // ---- pure-helper checks for the frozen expectations and controlled mechanisms
  if (expectedBroker() !== 10 || expectedBroker(EXPECT, false) !== 9 || expectedRequests() !== 11 || expectedRequests(EXPECT, false) !== 10) bad.push('EXPECT totals');
  if (!Object.isFrozen(EXPECT)) bad.push('EXPECT must be frozen');
  try { const r = JSON.parse(rewriteAdoptBody('{"question":"q","generation":1,"adopt_subject":true,"subject":{"kind":"model","id":"real"}}', 'forged')); if (r.subject.id !== 'forged' || r.subject.kind !== 'model' || r.adopt_subject !== true || r.question !== 'q') bad.push('rewriteAdoptBody'); } catch { bad.push('rewriteAdoptBody threw'); }
  try { rewriteAdoptBody('{"adopt_subject":false,"subject":null}', 'x'); bad.push('rewriteAdoptBody must refuse non-adoption'); } catch { /* expected */ }
  const ev = (t, trusted = true, inHost = true) => ({ t, trusted, inHost });
  if (classifyPan({ events: [] }) !== 'input-not-delivered' || classifyPan({ events: [ev('pointerdown')], moved: true }) !== 'panned' || classifyPan({ events: [ev('pointerdown', true, false)] }) !== 'pointerdown-target-outside-host'
    || classifyPan({ events: [ev('pointerdown')], cy: { tapstart: 1, grab: 0, viewport: 0 } }) !== 'cy-received-press-but-no-viewport-change' || classifyPan({ events: [ev('pointerdown')], cy: { tapstart: 0, grab: 0, viewport: 0 } }) !== 'host-received-pointer-but-cy-saw-no-tap'
    || classifyPan({ events: [ev('pointerdown')], pathBlockers: [{ i: 3 }] }) !== 'path-crosses-element-outside-host' || classifyPan({ events: [ev('pointerdown', false)] }) !== 'untrusted-event') bad.push('classifyPan');
  const ok = { initialized: true, configOk: true, foreground: true, delivered: true, sessionRequested: true, sessionOk: true, analysisReady: true };
  if (classifyIso(ok) !== 'met' || classifyIso({ ...ok, foreground: false }) !== 'not-foreground' || classifyIso({ ...ok, delivered: false }) !== 'input-not-delivered' || classifyIso({ ...ok, sessionRequested: false }) !== 'delivered-but-no-session-request' || classifyIso({ ...ok, initialized: false }) !== 'not-initialized') bad.push('classifyIso');
  if (PRE_STATUS('met') !== 'pass' || PRE_STATUS('not-foreground') !== 'precondition-unmet') bad.push('PRE_STATUS');
  { const me = readFileSync(new URL(import.meta.url), 'utf8'); const swallowed = me.split('\n').map((l, i) => [i + 1, l]).filter(([, l]) => /(?<![:'"`])\/\/[^\n'"`]*;\s*(const|let|await)\b/.test(l)).map(([n]) => n); if (swallowed.length) bad.push('code after a // comment on lines ' + swallowed.join(',')); const writers = me.split('\n').filter((l) => /hitLog\.push\(/.test(l)); if (writers.length !== 1 || !/const recordHit/.test(writers[0])) bad.push('hitLog must have exactly one writer (recordHit): ' + writers.length);
    if (/hit:\s*'inside host'/.test(me) || /found:\s*true,\s*ok:\s*true,\s*insideViewport:\s*true/.test(me.replace(/^.*selftest.*$/gm, ''))) bad.push('synthetic hit-test literal present'); }
  // ---- source-backed checks (only when OT_SRC points at the pinned checkout): real renderer + real reducer drive the in-page citation expressions through a minimal DOM
  if (process.env.OT_SRC && existsSync(join(SRC, 'src/ui/components/assistant.js'))) {
    const { renderAssistant } = await import(pathToFileURL(join(SRC, 'src/ui/components/assistant.js')).href);
    const st = await import(pathToFileURL(join(SRC, 'src/ui/lib/store.js')).href);
    const unesc = (t) => t.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
    const VOID = new Set(['input', 'br', 'img', 'meta', 'hr']);
    const parse = (html) => { const root = { tag: '#root', cls: [], attrs: {}, kids: [], parent: null, text: '' }; let cur = root; const re = /<(\/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>|([^<]+)/g; let m;
      while ((m = re.exec(html))) { if (m[4] !== undefined) { cur.kids.push({ tag: '#text', text: unesc(m[4]), parent: cur }); continue; }
        if (m[1]) { let n = cur; while (n && n.tag !== m[2].toLowerCase()) n = n.parent; if (n && n.parent) cur = n.parent; continue; }
        const attrs = {}; for (const a of m[3].matchAll(/([\w-]+)(?:="([^"]*)")?/g)) attrs[a[1]] = a[2] === undefined ? '' : unesc(a[2]); const node = { tag: m[2].toLowerCase(), attrs, cls: (attrs.class || '').split(/\s+/).filter(Boolean), kids: [], parent: cur }; cur.kids.push(node); if (!VOID.has(node.tag) && !/\/\s*$/.test(m[3])) cur = node; }
      return root; };
    const textOf = (n) => (n.tag === '#text' ? n.text : (n.kids || []).map(textOf).join(''));
    const mkEl = (n) => { if (!n || n._el) return n && n._el; const el = { _n: n, tagName: n.tag.toUpperCase(), classList: n.cls, dataset: Object.fromEntries(Object.entries(n.attrs).filter(([k]) => k.startsWith('data-')).map(([k, v]) => [k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase()), v])), get textContent() { return textOf(n); }, open: 'open' in n.attrs };
      el.querySelectorAll = (sel) => qsa(n, sel).map(mkEl); el.querySelector = (sel) => mkEl(qsa(n, sel)[0]) || null; n._el = el; return el; };
    const matchCompound = (n, c) => { if (n.tag === '#text') return false; const mm = c.match(/^([a-z0-9]+)?((?:\.[\w-]+)*)((?:\[[\w-]+\])*)$/); if (!mm) throw new Error('selector unsupported in selftest: ' + c); if (mm[1] && n.tag !== mm[1]) return false;
      for (const k of (mm[2] || '').split('.').filter(Boolean)) if (!n.cls.includes(k)) return false; for (const a of (mm[3] || '').match(/\[([\w-]+)\]/g) || []) if (!(a.slice(1, -1) in n.attrs)) return false; return true; };
    const descendants = (n) => n.kids.flatMap((k) => (k.tag === '#text' ? [] : [k, ...descendants(k)]));
    const qsa = (scope, selector) => { const out = new Set(); for (const part of selector.split(',').map((x) => x.trim())) { const toks = part.replace(/>/g, ' > ').split(/\s+/).filter(Boolean); let set = [scope]; let childNext = false; let first = true;
        for (const tk of toks) { if (tk === '>') { childNext = true; continue; } if (tk === ':scope') { set = [scope]; first = false; continue; } const next = []; for (const base of set) { const pool = (childNext ? base.kids : descendants(base)).filter((x) => x.tag !== '#text'); for (const x of pool) if (matchCompound(x, tk)) next.push(x); } set = [...new Set(next)]; childNext = false; first = false; }
        for (const x of set) out.add(x); } return [...out]; };
    const sample = (mut = (r) => r) => ({ question: 'q', response: mut({ context_id: 'CTX1', turn_id: 't', answer: { answer_status: 'unknown', claims: [{ kind: 'unknown', text: 'claim', evidence_ids: ['e1', 'e2'] }], limitations: [{ text: 'lim', evidence_ids: ['e2'] }], next_steps: [{ action: 'open_evidence', evidence_id: 'e1', label: 'next' }] },
      citations: [{ evidence_id: 'e1', source: 'bom', kind: 'source_state', label: 'BOM coverage', state: 'completed' }, { evidence_id: 'e2', source: 'dependencies', kind: 'dep', label: 'Dep', state: 'completed' }, { evidence_id: 'e3', source: 'crypto', kind: 'source_state', label: 'Crypto coverage', state: 'partial' }, { evidence_id: 'e4', source: 'dependencies', kind: 'source_state', label: 'Dep coverage', state: 'completed' }],
      source_states: { bom: { state: 'completed', entry_count: 3 }, crypto: { state: 'partial', entry_count: 1, truncated: true }, dependencies: { state: 'completed', entry_count: 2 } }, limitations: ['crypto: only partial coverage'], subject: null, provider: { profile: 'p', model: 'm', validation_level: 'v' } }) });
    const run = (turn, expr) => { const s0 = { ...st.initial(), analysis: { generation: 1 }, assistant: { ...st.initial().assistant, turns: [turn] } }; const root = parse(renderAssistant(s0, null)); const arts = qsa(root, '.ot-assistant-turn').map(mkEl);
      const ctx = { window: { __otStore: { get: () => s0 } }, document: { querySelectorAll: (sel) => (sel === '.ot-assistant-turn' ? arts : []) } }; return vm.runInNewContext(expr, ctx); };
    const a = run(sample(), CITE_ANSWER(0)); if (!a.equal || a.n !== 4 || !a.allCtx || !a.allKnown) bad.push('CITE_ANSWER against the real renderer: ' + JSON.stringify(a));
    const c = run(sample(), CITE_COVERAGE(0)); if (!c.covEqual || !c.limEqual || c.links !== 4 || !c.allCtx || !c.allLabelCoverage || !c.allSourceState || c.sources !== 3 || c.expCov.length !== 3 || c.expLim.length !== 1) bad.push('CITE_COVERAGE against the real renderer: ' + JSON.stringify(c));
    // mutation controls: the expressions must DETECT a wrong rendering
    const t2 = sample(); t2.response.answer = { ...t2.response.answer, claims: [{ kind: 'unknown', text: 'claim', evidence_ids: ['e1'] }] };   // renderer shows e1 only, but expected set is computed from the SAME answer -> still equal (by construction)
    const t3 = sample(); const r3 = run(t3, CITE_ANSWER(0).replace("t.answer.claims||[]", "[{evidence_ids:['e9']}]")); if (r3.equal) bad.push('CITE_ANSWER must detect a differing expected set');
    const r4 = run(sample(), CITE_COVERAGE(0).replace("stateOf(s).evidence_id:null}).filter(Boolean).sort()", "'x|e999':null}).filter(Boolean).sort()")); if (r4.limEqual) bad.push('CITE_COVERAGE must detect a differing limitation link');
    // reducer expectations the frozen plan depends on (read from the real store, not assumed)
    const base = { ...st.initial(), analysis: { generation: 1 }, epoch: 1 }; const adopting = { ...base, assistant: { ...base.assistant, pending: true, adoptNext: true, requestId: 'r' } };
    const failedAdopt = st.reducer(adopting, { type: 'ASSISTANT_FAILED', epoch: 1, requestId: 'r', message: 'm', adoptionAttempted: true });
    if (failedAdopt.assistant.adoptNext !== false || failedAdopt.assistant.adoptionUncertain !== true || st.assistantCanSubmit(failedAdopt.assistant) !== false) bad.push('reducer: failed adoption must clear adoptNext, set adoptionUncertain and block plain submit');
    if (st.assistantCanSubmit({ ...failedAdopt.assistant, adoptNext: true }) !== true) bad.push('assistantCanSubmit must allow an explicit re-adoption');
    const plain = st.reducer({ ...base, assistant: { ...base.assistant, pending: true, requestId: 'r' } }, { type: 'ASSISTANT_FAILED', epoch: 1, requestId: 'r', message: 'm', adoptionAttempted: false }); if (plain.assistant.adoptionUncertain !== false) bad.push('reducer: a failed non-adoption must not set adoptionUncertain');
    const okRes = st.reducer({ ...failedAdopt, assistant: { ...failedAdopt.assistant, pending: true, requestId: 'r2' } }, { type: 'ASSISTANT_RESULT', epoch: 1, generation: 1, requestId: 'r2', question: 'q', response: { subject: null, answer: {} } }); if (okRes.assistant.adoptionUncertain !== false) bad.push('reducer: a received answer must clear adoptionUncertain');
  }
  console.log(bad.length ? 'SELFTEST FAIL ' + bad.join('; ') : 'SELFTEST OK');
  process.exit(bad.length ? 1 : 0);
}
const readLedger = () => existsSync(LEDGER) ? JSON.parse(readFileSync(LEDGER, 'utf8')) : { service: 0, chrome: 0, firstLaunchAt: null, attempts: [] };
const writeLedger = (l) => writeFileSync(LEDGER, JSON.stringify(l, null, 2));
const CHROME_BIN = process.env.CHROME_BIN || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

function preflight() {                         // spends NOTHING and launches nothing; imports only
  const out = { checks: [], ok: true }; const add = (id, ok, d) => { out.checks.push({ id, ok: !!ok, d }); if (!ok) out.ok = false; };
  add('OT_SRC has cdp.mjs and assistant_service.py', existsSync(join(SRC, 'tests/ui/browser/cdp.mjs')) && existsSync(join(SRC, 'tests/ui/browser/assistant_service.py')));
  try { const head = execFileSync('git', ['-C', SRC, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(); const dirty = execFileSync('git', ['-C', SRC, 'status', '--porcelain'], { encoding: 'utf8' }).trim();
    add('source pinned and clean', head === process.env.OT_SRC_SHA && !dirty, { head, expected: process.env.OT_SRC_SHA || null, dirty: !!dirty }); } catch (e) { add('source pinned and clean', false, String(e.message).slice(0, 120)); }
  add('PYTHON_BIN set and executable', !!PY && existsSync(PY), { python: PY ? PY.replace(HOME, '~') : null });
  if (PY && existsSync(PY)) { try { const r = execFileSync(PY, ['-c', 'import sys,networkx;from opentrace_core.app import make_server;assert sys.prefix!=sys.base_prefix,"not a venv";print(sys.version.split()[0],networkx.__version__,"venv")'], { cwd: SRC, encoding: 'utf8', env: cleanEnv(process.env, serviceExtra(SRC, join(TMP, 'unused'), join(TMP, 'unused'))) }).trim(); add('venv imports networkx and opentrace_core.app', true, r); }
    catch (e) { add('venv imports networkx and opentrace_core.app', false, sanitize(e.stderr || e.message, [[SRC, '<src>']]).slice(-300)); } }
  add('Chrome binary present', existsSync(CHROME_BIN));
  add('node >= 22 (global WebSocket)', Number(process.versions.node.split('.')[0]) >= 22, process.versions.node);
  add('ledger-v3 fresh or consistent', true, readLedger());
  add('owner allowance supplied (else launch refuses)', CAP.service > 0 && CAP.chrome > 0 && CAP.minutes > 0, CAP);
  return out;
}
if (MODE === '--preflight') { mkdirSync(EVID, { recursive: true }); const p = preflight(); console.log(JSON.stringify(p, null, 2)); process.exit(p.ok ? 0 : 1); }
if (MODE === '--plan') { console.log(JSON.stringify({ src: SRC, cap: CAP, ledger: readLedger() }, null, 2)); process.exit(0); }
if (MODE !== 'run' || !LABEL) { console.error('usage: run <LABEL> | --preflight | --plan | --selftest'); process.exit(2); }
mkdirSync(EVID, { recursive: true });
{ const pf = preflight(); if (!pf.ok) { console.error('PREFLIGHT FAILED (nothing spent):', JSON.stringify(pf.checks.filter((c) => !c.ok))); process.exit(4); } }

const { CHROME, connect, newPage } = await import(pathToFileURL(join(SRC, 'tests/ui/browser/cdp.mjs')).href);
const OUT = join(EVID, `v3-${LABEL}`); mkdirSync(OUT, { recursive: true });
const results = []; const owned = []; const hitLog = [];
// the ONLY writer of hitLog: entries are always real elementFromPoint readouts
const recordHit = (tag, label, sel, h) => hitLog.push({ tag, label, sel, found: h.found, ok: h.ok, insideViewport: h.insideViewport, target: h.target, hit: h.hit });
const notes = { readinessFailures: [], chromeExit: null, chromeStderr: '', serviceExit: null, serviceTail: '' };
const rec = (id, status, details, origin) => { results.push({ id, status, origin, details }); console.log(`${status.toUpperCase()} ${id}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
class Occluded extends Error { constructor(label, h) { super(`target occluded: ${label}`); this.hit = h; } }
let deadlineHit = false; let finishing = false; let deadlineTimer; let armed = false;
const deadlineP = new Promise((_, rej) => { globalThis.__arm = (ms) => { deadlineTimer = setTimeout(() => { deadlineHit = true; rej(new Error('allowance deadline reached')); }, ms); }; }); deadlineP.catch(() => {});
function spend(kind) {
  if (finishing || deadlineHit) throw new Error('no launch after deadline/cleanup began');
  const l = readLedger(); const why = ledgerGate(l, kind, CAP); if (why) throw new Error('ledger refused: ' + why);
  if (!l.firstLaunchAt) l.firstLaunchAt = Date.now(); l[kind]++; if (kind === 'service') l.attempts.push({ label: LABEL, at: new Date().toISOString() }); writeLedger(l);
  if (!armed) { armed = true; globalThis.__arm(Math.max(1000, l.firstLaunchAt + CAP.minutes * 60000 - Date.now() - 60000)); }
}
let service; let chrome; let page; let serviceLog = ''; let serviceUrl; const blocked = []; const cleanup = { dirs: [], survivors: [], signalled: [] };
const stateRoot = join(OUT, 'service-state'); const countFile = join(OUT, 'broker-count.txt');
const brokerCount = () => { try { return Number(readFileSync(countFile, 'utf8')); } catch { return 0; } };
const waitBroker = async (n, ms = 8000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (brokerCount() >= n) return true; await sleep(50); } return false; };
const shot = async (name, send = null) => { try { const r = await (send || page.send)('Page.captureScreenshot', { format: 'png' }); writeFileSync(join(OUT, name + '.png'), Buffer.from(r.data, 'base64')); } catch (e) { notes.readinessFailures.push('screenshot ' + name + ': ' + e.message); } };

async function startService() {
  spend('service');
  service = spawn(PY, [join(SRC, 'tests/ui/browser/assistant_service.py')], { cwd: SRC, env: cleanEnv(process.env, serviceExtra(SRC, stateRoot, countFile)), stdio: ['ignore', 'pipe', 'pipe'] });
  owned.push(service.pid);
  service.on('error', (e) => { notes.serviceExit = { code: null, sig: String(e.code || e.name) }; });
  service.stdout.on('data', (c) => { serviceLog = (serviceLog + c).slice(-4000); }); service.stderr.on('data', (c) => { serviceLog = (serviceLog + c).slice(-4000); });
  service.on('exit', (code, sig) => { notes.serviceExit = { code, sig }; });
  serviceUrl = await new Promise((res, rej) => { const t0 = Date.now(); const poll = () => { const m = serviceLog.match(/http:\/\/127\.0\.0\.1:\d+\//); if (m) return res(m[0]);
    if (notes.serviceExit) return rej(new Error('service exited early')); if (Date.now() - t0 > 25000) return rej(new Error('service readiness timeout')); setTimeout(poll, 50); }; poll(); })
    .catch((e) => { notes.readinessFailures.push('service: ' + e.message); throw e; });
}
async function startChrome() {
  spend('chrome');
  const profile = mkdtempSync(join(TMP, 'ot-lab-assistant-chrome-')); cleanup.dirs.push(profile);
  const args = [`--user-data-dir=${profile}`, `--crash-dumps-dir=${join(profile, 'Crashpad')}`, '--disable-breakpad', '--disable-crash-reporter', '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', '--window-size=1366,900', '--window-position=40,40', 'about:blank'];
  const proc = spawn(CHROME, args, { env: cleanEnv(process.env), stdio: ['ignore', 'ignore', 'pipe'] }); owned.push(proc.pid);
  let err = ''; proc.stderr.on('data', (c) => { err = (err + c).slice(-4000); notes.chromeStderr = sanitize(err, [[profile, '<fresh-profile>'], [HOME, '~']]); });
  proc.on('exit', (code, sig) => { notes.chromeExit = { code, sig }; });
  const wsUrl = await new Promise((res, rej) => { const t = setTimeout(() => rej(new Error('Chrome DevTools readiness timeout')), 25000);
    proc.once('error', (e) => { clearTimeout(t); rej(e); }); proc.once('exit', (c, s) => { clearTimeout(t); rej(new Error(`Chrome exited before ready (${c ?? s})`)); });
    proc.stderr.on('data', (c) => { const m = c.toString().match(/DevTools listening on (ws:\/\/\S+)/); if (m) { clearTimeout(t); res(m[1]); } }); })
    .catch((e) => { notes.readinessFailures.push('chrome: ' + e.message); throw e; });
  chrome = { browser: await connect(wsUrl), proc, profile, flags: args.map((a) => a.replace(profile, '<fresh-profile>')) };
}
async function terminateOwned() {              // SIGTERM only; roots are only still-running children this process spawned
  let rows = []; try { rows = execFileSync('ps', ['-axo', 'pid=,ppid='], { encoding: 'utf8' }).trim().split('\n').map((l) => { const [a, b] = l.trim().split(/\s+/).map(Number); return { pid: a, ppid: b }; }); } catch {}
  const alive = (p) => { try { process.kill(p, 0); return true; } catch (e) { return e.code !== 'ESRCH'; } };
  const roots = [service, chrome?.proc].filter((p) => p && Number.isInteger(p.pid) && p.exitCode === null && p.signalCode === null).map((p) => p.pid);
  const all = descendants(rows, roots).filter(alive);
  for (const p of all) { try { process.kill(p, 'SIGTERM'); cleanup.signalled.push(p); } catch {} }
  const t0 = Date.now(); while (Date.now() - t0 < 10000 && all.some(alive)) await sleep(200);
  cleanup.survivors = all.filter(alive); cleanup.limit = 'helpers reparented after a Chrome crash are not discovered';
  if (!cleanup.survivors.length) { for (const d of [...cleanup.dirs, stateRoot]) { try { rmSync(d, { recursive: true, force: true }); } catch {} } cleanup.dirsRemoved = true; } else cleanup.dirsRemoved = false;
}
const loop = /^(http:\/\/(127\.0\.0\.1|localhost):\d+\/|about:|data:|blob:)/;
// Loopback-only request interception. `hooks` (page A only) are the two CONTROLLED harness mechanisms, each armed explicitly by the driver and consumed once:
//   rewriteNextAsk  - request stage: replaces the adoption subject id of the next /api/assistant/ask with a forged id (server must reject before dispatch);
//   loseNextAskResponse - response stage: the server completes the request, the page never receives the response (fail, else a fulfilled 502 as fallback).
// Neither involves a provider; both only touch loopback traffic. Bodies are never recorded.
const hooks = { rewriteNextAsk: null, loseNextAskResponse: false, log: [] }; const expRowsRef = {}; const evidenceRef = {};
function intercept(send, sessionId, useHooks = false) {
  chrome.browser.on((m) => { if (m.sessionId !== sessionId || m.method !== 'Fetch.requestPaused') return; const p = m.params; const url = p.request.url; const id = p.requestId;
    if (!loop.test(url)) { blocked.push(url); send('Fetch.failRequest', { requestId: id, errorReason: 'BlockedByClient' }).catch(() => {}); return; }
    let path = ''; try { path = new URL(url).pathname; } catch {}
    const isAsk = useHooks && path === '/api/assistant/ask' && p.request.method === 'POST'; const responseStage = p.responseStatusCode !== undefined || p.responseErrorReason !== undefined;
    if (isAsk && !responseStage) { try { const j = JSON.parse(p.request.postData || '{}'); hooks.log.push({ kind: 'ask-observed', adopt: j.adopt_subject === true, subjectKind: j.subject?.kind ?? null, subjectId: j.subject?.id ?? null }); } catch { hooks.log.push({ kind: 'ask-observed', adopt: false, unreadable: true }); } }
    if (isAsk && !responseStage && hooks.rewriteNextAsk) { const forged = hooks.rewriteNextAsk; hooks.rewriteNextAsk = null;
      try { const nb = rewriteAdoptBody(p.request.postData || '', forged); hooks.log.push({ kind: 'rewrite-adopt-subject', path, applied: true }); send('Fetch.continueRequest', { requestId: id, postData: Buffer.from(nb).toString('base64') }).catch(() => {}); }
      catch (e) { hooks.log.push({ kind: 'rewrite-adopt-subject', path, applied: false, error: String(e.message).slice(0, 80) }); send('Fetch.continueRequest', { requestId: id }).catch(() => {}); }
      return; }
    if (isAsk && responseStage && hooks.loseNextAskResponse) { hooks.loseNextAskResponse = false;
      send('Fetch.failRequest', { requestId: id, errorReason: 'ConnectionReset' }).then(() => hooks.log.push({ kind: 'lose-response', path, mechanism: 'failRequest(ConnectionReset)', serverStatus: p.responseStatusCode ?? null }))
        .catch(() => send('Fetch.fulfillRequest', { requestId: id, responseCode: 502, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: Buffer.from('{"error":"harness_lost_response"}').toString('base64') })
          .then(() => hooks.log.push({ kind: 'lose-response', path, mechanism: 'fulfill(502) fallback', serverStatus: p.responseStatusCode ?? null })).catch(() => hooks.log.push({ kind: 'lose-response', path, mechanism: 'FAILED', serverStatus: null })));
      return; }
    const cont = responseStage ? send('Fetch.continueResponse', { requestId: id }).catch(() => send('Fetch.continueRequest', { requestId: id })) : send('Fetch.continueRequest', { requestId: id });
    cont.catch((e) => { if (hooks.log.length < 60) hooks.log.push({ kind: 'continue-failed', path, stage: responseStage ? 'response' : 'request', error: String(e.message).slice(0, 80) }); }); });
}
// generic page operations over any CDP session (main page and isolated context share these)
function ops(send, tag) {
  const ev = async (expr) => { const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error('eval: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text)); return r.result.value; };
  const waitFor = async (expr, ms = 15000, label = expr) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { try { if (await ev(`!!(${expr})`)) return true; } catch { /* context may be navigating; retry until timeout */ } await sleep(50); } throw new Error('timeout waiting for: ' + label); };
  const mouse = (type, x, y, extra = {}) => send('Input.dispatchMouseEvent', { type, x, y, ...extra });
  const hit = (sel) => ev(HIT(sel));
  const hclick = async (sel, label = sel) => {
    const h = await hit(sel); recordHit(tag, label, sel, h);
    if (!h.found) throw new Error(`target missing: ${label}`); if (!hitVerdict(h)) throw new Occluded(label, h);
    await mouse('mouseMoved', h.x, h.y); await mouse('mousePressed', h.x, h.y, { button: 'left', clickCount: 1 }); await mouse('mouseReleased', h.x, h.y, { button: 'left', clickCount: 1 }); return h;
  };
  const type = async (sel, text) => { await hclick(sel, 'composer'); await ev(`document.querySelector(${q(sel)}).select&&document.querySelector(${q(sel)}).select()`); await send('Input.insertText', { text }); };
  const key = async (k) => { const vk = { Escape: 27, Enter: 13 }[k] || 0; const b = { key: k, code: k, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk }; await send('Input.dispatchKeyEvent', { type: 'keyDown', ...b }); await send('Input.dispatchKeyEvent', { type: 'keyUp', ...b }); };
  return { ev, waitFor, hit, hclick, type, key, mouse, send };
}
async function settleCam(A, ms = 6000) { const series = []; const t0 = Date.now(); while (Date.now() - t0 < ms) { series.push(await A.ev(CAM)); if (settled(series)) return { ok: true, cam: series[series.length - 1], samples: series.length }; await sleep(150); } return { ok: false, cam: series[series.length - 1], samples: series.length }; }
async function dragPanel(A, toX, toY, label) {   // real pointer drag of the assistant title (a supported control); hit-test recorded
  const hd = await A.hit('#ot-assistant-handle strong'); recordHit('drag', label + ' (drag handle)', '#ot-assistant-handle strong', hd);
  if (!hitVerdict(hd)) throw new Occluded(label + ' drag handle', hd);
  await A.mouse('mouseMoved', hd.x, hd.y); await A.mouse('mousePressed', hd.x, hd.y, { button: 'left', clickCount: 1 });
  for (let i = 1; i <= 8; i++) await A.mouse('mouseMoved', hd.x + (toX - hd.x) * i / 8, hd.y + (toY - hd.y) * i / 8, { button: 'left', buttons: 1 });
  await A.mouse('mouseReleased', toX, toY, { button: 'left', clickCount: 1 }); await sleep(250);
}
// Bring a target into an unoccluded state ONLY through supported controls (minimize, then move). Never a programmatic click.
async function reach(A, sel, label) {
  try { return await reachInner(A, sel, label); } catch (e) { return { ok: false, steps: [{ step: 'error', error: safe(e) }], usabilityFinding: `${label}: ${safe(e)}` }; }
}
async function reachInner(A, sel, label) {
  const steps = []; let h = await A.hit(sel); recordHit('reach', label + ' (initial probe)', sel, h);
  steps.push({ step: 'initial', ok: hitVerdict(h), hit: h.hit || null }); if (hitVerdict(h)) return { ok: true, steps };
  const el = await A.ev(ASSIST_STATE);
  if (!el.min) { await A.hclick('[data-action="a-min"]', 'assistant Minimize'); await A.waitFor(`document.querySelector('#ot-assistant').classList.contains('min')`, 5000, 'panel minimized').catch(() => {}); await sleep(250);
    h = await A.hit(sel); recordHit('reach', label + ' (after minimize)', sel, h);
    steps.push({ step: 'minimize', ok: hitVerdict(h), hit: h.hit || null }); if (hitVerdict(h)) return { ok: true, steps }; }
  try { await dragPanel(A, 60, 820, label); h = await A.hit(sel); recordHit('reach', label + ' (after move)', sel, h);
    steps.push({ step: 'move', ok: hitVerdict(h), hit: h.hit || null }); if (hitVerdict(h)) return { ok: true, steps }; }
  catch (e) { steps.push({ step: 'move', ok: false, note: 'drag handle not reachable', error: safe(e) }); }
  return { ok: false, steps, usabilityFinding: `${label} remains covered (${h.hit}) after the supported Minimize and move controls` };
}
// Make the composer usable: reopen a closed panel, expand a minimized one, and move it back on screen through the supported drag if it is off-screen.
async function ensureComposer(A) {
  let st = await A.ev(ASSIST_STATE); if (st.hidden) await A.hclick('#ot-assistant-launch', 'assistant launcher');
  st = await A.ev(ASSIST_STATE); if (st.min) await A.hclick('[data-action="a-min"]', 'assistant Expand');
  await A.waitFor(`document.querySelector('#ot-assistant-question')`, 5000, 'composer');
  let h = await A.hit('#ot-assistant-question'); if (hitVerdict(h)) return;
  const w = await A.ev('innerWidth'); await dragPanel(A, Math.max(200, w - 460), 120, 'restore composer'); h = await A.hit('#ot-assistant-question');
  if (!hitVerdict(h)) throw new Occluded('composer after restore', h);
}
const apiLog = []; const askDiag = []; const reqLog = [];
function watchApi(sessionId, tag, send) {      // status and error CODE only; no bodies, cookies or headers are recorded
  const ids = new Map();
  chrome.browser.on(async (m) => { if (m.sessionId !== sessionId) return;
    if (m.method === 'Network.requestWillBeSent') { let rp; try { rp = new URL(m.params.request.url).pathname; } catch { return; } if (rp.startsWith('/api/') && reqLog.length < 400) reqLog.push({ tag, path: rp, method: m.params.request.method }); return; }
    if (m.method === 'Network.responseReceived') { let path; try { path = new URL(m.params.response.url).pathname; } catch { return; } if (!path.startsWith('/api/') || apiLog.length > 300) return; ids.set(m.params.requestId, apiLog.push({ tag, path, status: m.params.response.status }) - 1); }
    else if (m.method === 'Network.loadingFinished' && ids.has(m.params.requestId)) { const e = apiLog[ids.get(m.params.requestId)]; if (e.status >= 400) { try { const b = await send('Network.getResponseBody', { requestId: m.params.requestId }); const j = JSON.parse(b.body); e.code = String(j.code || j.error || '').slice(0, 60); } catch { e.code = '(unreadable)'; } } } });
}
const panelEvidence = {}; const evidence = { counts: {} };
const safe = (e) => sanitize(`${e.name}: ${e.message}`, [[HOME, '~'], [SRC, '<src>']]).slice(0, 400);
const step = async (id, origin, fn) => { try { const r = await fn(); rec(id, r.ok ? 'pass' : (r.unmet ? 'precondition-unmet' : (r.info ? 'info' : 'fail')), r.details, origin); return r; } catch (e) { rec(id, e instanceof Occluded ? 'blocked-occluded' : 'error', { error: safe(e), hit: e.hit ? { target: e.hit.target, hit: e.hit.hit } : undefined }, origin); return null; } };

async function body() {
  await startService(); await startChrome();
  page = await newPage(chrome.browser, { width: 1366, height: 900, mobile: false });
  await page.send('Emulation.clearDeviceMetricsOverride'); await page.send('Page.bringToFront'); await page.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] }); intercept(page.send, page.sessionId, true);
  const A = ops(page.send, 'A'); watchApi(page.sessionId, 'A', page.send);
  const S = { submitted: 0, firstContext: '', dlg1: '', adopted: null, B: null, bTurns0: null, bTurnsAfterAsk: null };
  const section = async (name, fn) => { try { await fn(); } catch (e) { rec(`SECTION ${name} aborted`, e instanceof Occluded ? 'blocked-occluded' : 'error', { error: safe(e), hit: e.hit ? { target: e.hit.target, hit: e.hit.hit } : undefined }, 'harness'); await shot(`err_${name}`).catch(() => {}); } };
  // One ask = type + real click on Ask. `id` keys the frozen EXPECT table; the observed request/broker deltas are compared to it after the outcome settles.
  const expRows = expRowsRef; evidenceRef.bAsked = false;
  const _unused = 0; const countReq = (tag) => reqLog.filter((e) => e.tag === tag && e.path === '/api/assistant/ask' && e.method === 'POST').length;
  const ask = async (X, text, tag = 'A') => { await ensureComposer(X); const before = (await X.ev(ASSIST_STATE)).turns; await X.type('#ot-assistant-question', text); await X.hclick('#ot-assistant-form button[type="submit"]', 'Ask'); S.submitted++; evidence.submitted = S.submitted;
    const started = await X.waitFor(`window.__otStore.get().assistant.pending || document.querySelectorAll('.ot-assistant-turn').length > ${before} || window.__otStore.get().assistant.error`, 4000).then(() => true).catch(() => false);
    if (!started) askDiag.push({ tag, text: text.slice(0, 40), ...(await X.ev(`({uiError:window.__otStore.get().assistant.error||null,adoptNext:!!window.__otStore.get().assistant.adoptNext,draftLen:(window.__otStore.get().assistant.draft||'').length,pending:!!window.__otStore.get().assistant.pending})`)) });
    return before; };
  const turnsWait = (X, n, label) => X.waitFor(`document.querySelectorAll('.ot-assistant-turn').length === ${n} && !window.__otStore.get().assistant.pending`, 30000, label);
  // askStep: runs `ask`, waits for the outcome class declared in EXPECT[id], then records expected-vs-observed request/broker deltas as an EXP-<id> row.
  const askStep = async (X, id, text, tag = 'A') => { const E = EXPECT[id]; const b0 = brokerCount(), r0 = countReq(tag); const before = await ask(X, text, tag);
    let outcome = null;
    if (E.kind === 'dispatch' && !E.responseLost && !E.cancelled && !E.lateStatus) { await turnsWait(X, before + 1, `${id} answer`).catch(() => {}); outcome = 'answered'; }
    else if (E.responseLost) { await X.waitFor(`!window.__otStore.get().assistant.pending && window.__otStore.get().assistant.error`, 15000, `${id} failure shown`).catch(() => {}); outcome = 'failure-shown'; await sleep(600); }
    else if (E.kind === 'pre-reject') { await X.waitFor(`!window.__otStore.get().assistant.pending && window.__otStore.get().assistant.error`, 10000, `${id} rejection shown`).catch(() => {}); outcome = 'rejection-shown'; await sleep(600); }
    else if (E.kind === 'client-blocked') { await sleep(1200); outcome = 'client-blocked'; }
    else outcome = 'caller-managed';                // CAN / END: the caller observes pending/cancel/end itself
    if (E.cancelled || E.lateStatus) await waitBroker(b0 + 1); else if (E.kind === 'dispatch') await waitBroker(b0 + 1, 3000); else await sleep(300);
    const row = { id, expected: { kind: E.kind, brokerDelta: E.kind === 'dispatch' ? 1 : 0, requestDelta: (E.kind === 'dispatch' || E.kind === 'pre-reject') ? 1 : 0, ...(E.status ? { status: E.status, code: E.code } : {}) },
      observed: { brokerDelta: brokerCount() - b0, requestDelta: countReq(tag) - r0, outcome } };
    row.match = row.observed.brokerDelta === row.expected.brokerDelta && row.observed.requestDelta === row.expected.requestDelta; expRows[id] = row;
    rec(`EXP-${id} frozen request/broker expectation (${E.note})`, row.match ? 'pass' : 'fail', row, 'frozen-expectation'); return { before, row }; };

  // ---- setup (fatal if it fails: nothing later can be evaluated)
  await page.goto(serviceUrl); await A.waitFor(`document.querySelector('#ot-demo')`, 15000, 'demo control');
  evidence.env = await A.ev(`({ua:navigator.userAgent,vis:document.visibilityState,focus:document.hasFocus(),iw:innerWidth,ih:innerHeight,sw:screen.width,sh:screen.height,dpr:devicePixelRatio,theme:window.__otStore?.get().theme})`);
  await A.hclick('#ot-demo', 'demo'); await A.waitFor(`window.__otStore?.get().analysis && !window.__otStore.get().busy`, 30000, 'analysis ready');
  evidence.fixture = await A.ev(`({generation:window.__otStore.get().analysis.generation,keys:Object.keys(window.__otStore.get().analysis).slice(0,8)})`);
  rec('C01 captured demo analysis is available', 'pass', evidence.fixture, 'codex');
  await A.hclick('#ot-tab-bom', 'BOM tab'); await A.waitFor(`document.querySelector('[data-bom-cy="inline"]')?._cy && !document.querySelector('[data-bom-cy="inline"]')._cy.destroyed()`, 20000, 'BOM graph');
  const s0 = await settleCam(A);
  await step('C02 BOM tab graph is populated and renderer is live', 'codex', async () => ({ ok: s0.cam.n > 0 && s0.cam.rd === false, details: { nodes: s0.cam.n, edges: s0.cam.e, rendererLive: s0.cam.rd === false, settled: s0.ok, camera: { z: s0.cam.z, px: s0.cam.px, py: s0.cam.py } } }));
  await shot('01_bom_graph');

  const sha = (t) => createHash('sha256').update(String(t || '')).digest('hex').slice(0, 16);
  const openCov = async (ctx) => { const sel = `.ot-assistant-turn:has(.ot-assistant-citation[data-context=${q(ctx)}]) .ot-assistant-coverage`; const isOpen = await A.ev(`!!document.querySelector(${q(sel)})?.open`);
    if (!isOpen) await A.hclick(sel + ' summary', 'coverage summary'); await A.waitFor(`document.querySelector(${q(sel)})?.open`, 3000, 'coverage open'); };
  const openLink = async (selector, label) => { await A.hclick(selector, label); await A.waitFor(`document.querySelector('#ot-dialog[open]')`, 10000, 'dialog'); const dlg = await A.ev(DIALOG_READ);
    const ex = await A.ev(`document.querySelector('#ot-dialog pre.source-excerpt')?.textContent?.trim()||''`); await A.key('Escape'); await A.waitFor(`!document.querySelector('#ot-dialog[open]')`, 5000).catch(() => {}); return { dlg, ex }; };
  const citeItem = (turn, id) => A.ev(`(()=>{const c=(window.__otStore.get().assistant.turns[${turn}].response.citations||[]).find(x=>x.evidence_id===${q(id)});return c?{source:c.source,state:c.state,label:c.label,kind:c.kind}:null})()`);
  S.excerpt = {};

  await section('answer', async () => {
    await A.hclick('#ot-assistant-launch', 'assistant launcher');
    await askStep(A, 'Q1', 'What does this captured repository analysis establish?');
    const whole = await A.ev(`(()=>{const t=window.__otStore.get().assistant.turns[0];return {status:t?.response?.answer?.answer_status,subject:t?.response?.subject?.kind,claimCount:t?.response?.answer?.claims?.length||0,visible:!!document.querySelector('.ot-assistant-turn .ot-assistant-claim p')?.textContent?.trim()}})()`);
    await step('C03 whole-analysis question returns a validated unknown answer bound to the analysis subject', 'codex', async () => ({ ok: whole.status === 'unknown' && whole.subject === 'analysis' && whole.claimCount > 0, details: whole }));
    await step('C04 validated answer is visibly rendered in the DOM', 'added', async () => ({ ok: whole.visible, details: { visible: whole.visible } }));
    await shot('02_whole_analysis_answer');
    const cites = await A.ev(CITES); S.firstContext = cites.ctx;
    await step('C05 claim and next investigation render turn-bound evidence citations', 'codex', async () => ({ ok: cites.n >= 2, details: { citationCount: cites.n } }));
    // C06 (run 1, failed as written) and C06-prime (run 2, relaxed post hoc) are historical and are NOT re-run. They are superseded by two separately predeclared checks:
    const ca = await A.ev(CITE_ANSWER(0));
    await step('C06A answer-body citations (claims, answer limitations, next steps) equal, as a multiset of context|evidence pairs, what the validated structured answer cites', 'predeclared', async () => ({ ok: ca.equal && ca.n >= 2 && ca.allKnown && ca.allCtx, details: ca }));
    await openCov(S.firstContext); const cv = await A.ev(CITE_COVERAGE(0));
    await step('C06B server coverage/limitation links are exactly the source-state evidence of the source shown beside them, in the turn context, labelled as coverage, and each opens that evidence', 'predeclared', async () => {
      const opened = []; let allOpen = cv.unique.length > 0;
      const groups = [['coverage', cv.covIds, (id) => `.ot-assistant-coverage .ot-assistant-citation[data-context=${q(S.firstContext)}][data-evidence=${q(id)}]`], ['limitation', cv.limIds, (id) => `section.ot-assistant-limit li .ot-assistant-citation[data-context=${q(S.firstContext)}][data-evidence=${q(id)}]`]];
      for (const [grp, ids, sel] of groups) for (const id of ids) { const it = await citeItem(0, id); const r = await openLink(sel(id), `${grp} link ${id.slice(0, 18)}`);
        const expectStrong = it ? `${it.source.replaceAll('_', ' ')} · ${it.state.replaceAll('_', ' ')}` : null; const good = !!it && it.kind === 'source_state' && r.dlg?.strong === expectStrong && r.ex.length > 0 && (r.dlg?.text || '').includes((it.label || '').slice(0, 40));
        if (!good) allOpen = false; if (grp === 'coverage') S.excerpt[id] = r.ex; opened.push({ group: grp, id, sourceKind: it?.kind, strongMatches: r.dlg?.strong === expectStrong, excerptChars: r.ex.length, excerptSha: sha(r.ex), good }); }
      return { ok: cv.covEqual && cv.limEqual && cv.expCov.length >= 1 && cv.coverageInAnswerBody === 0 && cv.allCtx && cv.allLabelCoverage && cv.allSourceState && allOpen, details: { coverageInAnswerBody: cv.coverageInAnswerBody, sources: cv.sources, expCov: cv.expCov, actCov: cv.actCov, covEqual: cv.covEqual, expLim: cv.expLim, actLim: cv.actLim, limEqual: cv.limEqual, links: cv.links, allCtx: cv.allCtx, allLabelCoverage: cv.allLabelCoverage, allSourceState: cv.allSourceState, opened } }; });
    await step('C06N supplementary (direct API, not a browser observation): a wrong context id does not resolve a turn citation', 'supplementary', async () => { const id = cv.unique[0] || ca.actual[0]?.split('|')[1];
      const st = await A.ev(`fetch('/api/assistant/citation?context_id=not-a-context&evidence_id='+encodeURIComponent(${q(id || '')}),{credentials:'same-origin'}).then(r=>r.status)`); return { ok: st === 404, details: { status: st, note: 'supplementary only; C06B/C07 are the browser observations' } }; });
    await step('C07 citation opens resolvable authorized evidence in the application dialog', 'codex', async () => { S.dlg1Id = await A.ev(`document.querySelector('.ot-assistant-turn .ot-assistant-claim .ot-assistant-citation')?.dataset.evidence||''`);
      const r = await openLink('.ot-assistant-turn .ot-assistant-claim .ot-assistant-citation', 'first claim citation'); S.dlg1 = r.ex; await shot('03_citation_dialog'); return { ok: !!S.dlg1, details: { excerptChars: S.dlg1.length, evidenceId: S.dlg1Id } }; });
  });

  await section('adoption', async () => {
    await A.hclick('#ot-tab-ai', 'AI tab'); await A.waitFor(`document.querySelector('#otai-svg g[data-otai-select][data-otai-kind]')`, 15000, 'AI asset cards');
    // choose the first asset card whose centre is actually the hit element (not covered by the panel or clipped)
    const card = await A.ev(`(()=>{for(const g of document.querySelectorAll('#otai-svg g[data-otai-select][data-otai-kind]')){g.scrollIntoView({block:'center',inline:'center',behavior:'instant'});const r=g.getBoundingClientRect();const h=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);if(h&&g.contains(h))return {key:g.dataset.otaiSelect,kind:g.dataset.otaiKind,label:(g.getAttribute('aria-label')||'').slice(0,80)};}return null})()`);
    if (!card) throw new Occluded('no unoccluded AI asset card', { target: 'g[data-otai-kind]', hit: 'none' });
    await A.hclick(`#otai-svg g[data-otai-select=${q(card.key)}]`, 'AI asset card'); await A.waitFor(`window.__otStore.get().workbench.perTab.ai.sel`, 5000, 'asset selected');
    const subjBefore = (await A.ev(ASSIST_STATE)).subject; const av = await A.ev(ADOPT_STATE);
    await step('C10 adoption is available for the selected AI asset (precondition; enabled checkbox naming the selection)', 'added', async () => ({ ok: av.present && !av.disabled && av.labelHasName, details: { card: { kind: card.kind, label: card.label }, ...av } }));
    await askStep(A, 'FU', 'Continue using the original conversation subject.');
    const f = await A.ev(`(()=>{const T=document.querySelectorAll('.ot-assistant-turn');const s=window.__otStore.get().assistant;return {ctx:T[T.length-1]?.querySelector('.ot-assistant-citation')?.dataset.context||'',subject:s.turns[s.turns.length-1]?.response?.subject?.kind}})()`);
    await step('C08 follow-up retains original whole-analysis context after page selection changes', 'codex', async () => ({ ok: !!S.firstContext && f.ctx === S.firstContext, details: { sameContext: f.ctx === S.firstContext } }));
    await step('C09 selection change did not silently retarget (follow-up subject still analysis)', 'added', async () => ({ ok: f.subject === 'analysis', details: { followupSubject: f.subject, subjectBefore: subjBefore } }));
    await shot('04_followup_frozen_subject');
    const adoptOn = async () => { await ensureComposer(A); await A.hclick('.ot-assistant-adopt input', 'adopt checkbox'); const st = await A.ev(ADOPT_STATE); if (!st.checked) throw new Error('adoption checkbox did not become checked'); };
    const observedSubjects = () => hooks.log.filter((e) => e.kind === 'ask-observed' && e.adopt);
    const adoptedOk = async (rowId, extra = {}) => { const st = await A.ev(ASSIST_FULL); const lt = await A.ev(LAST_TURN); const chk = (await A.ev(ADOPT_STATE)).checked; const obs = observedSubjects().slice(-1)[0] || null;
      const ok = !!lt && lt.subjectKind === 'model' && !!obs && lt.subjectId === obs.subjectId && lt.ctx !== S.firstContext && !chk && !st.adoptNext && !st.adoptionUncertain && !st.error && lt.modelSourceCitations > 0 && lt.subjectEvidencePresent;
      return { ok, details: { rowId, subjectKind: lt?.subjectKind, subjectIdEqualsRequested: !!obs && lt?.subjectId === obs.subjectId, contextChanged: lt?.ctx !== S.firstContext, checkboxCleared: !chk, adoptNext: st.adoptNext, adoptionUncertain: st.adoptionUncertain, uiError: st.error, modelSourceCitations: lt?.modelSourceCitations, subjectEvidenceInBoundedList: lt?.subjectEvidencePresent, citationCount: lt?.citationCount, ctx: lt?.ctx, ...extra } }; };

    await step('C11 explicit adoption (AD1) creates a new model-subject context whose bounded evidence contains the adopted subject, and clears one-turn adoption', 'codex', async () => {
      const a2 = await A.ev(ADOPT_STATE); if (!a2.present || a2.disabled) return { ok: false, details: { unavailable: a2 } };
      await adoptOn(); await askStep(A, 'AD1', 'Use the explicitly adopted model selection.'); const r = await adoptedOk('AD1'); S.ad1 = r.details.ctx; return r; });
    await shot('05_adopted_model_subject');
    await step('C12 after adoption, prior-turn citations still resolve their own frozen evidence (answer citation, coverage link), and the adopted turn\'s citation resolves', 'added', async () => {
      if (!S.ad1) return { ok: false, details: { notReached: 'AD1 did not produce an adopted context' } };
      const r1 = await openLink(`.ot-assistant-citation[data-context=${q(S.firstContext)}][data-evidence=${q(S.dlg1Id)}]`, 'turn-1 answer citation after adoption');
      await openCov(S.firstContext); const covId = Object.keys(S.excerpt)[0]; const r2 = covId ? await openLink(`.ot-assistant-coverage .ot-assistant-citation[data-context=${q(S.firstContext)}][data-evidence=${q(covId)}]`, 'turn-1 coverage link after adoption') : null;
      const r3 = await openLink(`.ot-assistant-turn .ot-assistant-claim .ot-assistant-citation[data-context=${q(S.ad1)}]`, 'adopted-turn citation');
      return { ok: !!r1.ex && r1.ex === S.dlg1 && !!r2 && r2.ex === S.excerpt[covId] && !!r3.ex, details: { answerCitationSameExcerpt: r1.ex === S.dlg1, coverageCitationSameExcerpt: !!r2 && r2.ex === S.excerpt[covId], coverageEvidenceId: covId || null, adoptedTurnCitationResolved: !!r3.ex } }; });
    await step('C12N supplementary (direct API): an evidence id that exists only in the original context does not resolve under the adopted context', 'supplementary', async () => {
      const r = await A.ev(`(async()=>{const T=window.__otStore.get().assistant.turns;const a=T[0].response,b=T[T.length-1].response;const bid=new Set((b.citations||[]).map(c=>c.evidence_id));const only=(a.citations||[]).find(c=>!bid.has(c.evidence_id));if(!only)return {noOnlyId:true};const s=await fetch('/api/assistant/citation?context_id='+encodeURIComponent(b.context_id)+'&evidence_id='+encodeURIComponent(only.evidence_id),{credentials:'same-origin'}).then(x=>x.status);return {status:s}})()`);
      return r.noOnlyId ? { info: true, ok: false, details: { unexercised: 'no original-only evidence id' } } : { ok: r.status === 404, details: r }; });

    // ---- rejection recovery (pre-dispatch rejection by the server; the rejected id is a harness mutation of the real adoption request, loopback only)
    const t0 = (await A.ev(ASSIST_FULL)).turns;
    await step('C29 a server-rejected adoption (400 subject_not_in_resolved_evidence, no dispatch) shows a recoverable error, clears the checkbox and appends no turn', 'predeclared', async () => {
      await adoptOn(); hooks.rewriteNextAsk = 'forged-model-id-v3'; const { row } = await askStep(A, 'REJ', 'Adoption request mutated by the harness to a subject outside resolved evidence.');
      const st = await A.ev(ASSIST_FULL); const rej = apiLog.filter((e) => e.tag === 'A' && e.path === '/api/assistant/ask').slice(-1)[0]; const chk = (await A.ev(ADOPT_STATE)).checked;
      return { ok: row.match && rej?.status === 400 && rej?.code === 'subject_not_in_resolved_evidence' && hooks.log.some((e) => e.kind === 'rewrite-adopt-subject' && e.applied) && !st.pending && !!st.error && !st.adoptNext && !chk && st.turns === t0, details: { rejection: { status: rej?.status, code: rej?.code }, rewriteApplied: hooks.log.some((e) => e.kind === 'rewrite-adopt-subject' && e.applied), ui: st, checkboxChecked: chk, turnsBefore: t0, brokerDelta: row.observed.brokerDelta, requestDelta: row.observed.requestDelta } }; });
    await step('C30 after the rejected adoption a plain follow-up is refused by the UI (nothing sent) until adoption is explicitly re-checked (adoptionUncertain)', 'predeclared', async () => {
      const { row } = await askStep(A, 'BLK1', 'Plain follow-up after the rejected adoption.'); const st = await A.ev(ASSIST_FULL);
      return { ok: row.match && st.adoptionUncertain && /response was not received/i.test(st.error || '') && st.turns === t0 && !st.pending, details: { ui: st, brokerDelta: row.observed.brokerDelta, requestDelta: row.observed.requestDelta, turnsBefore: t0 } }; });
    await step('C31 recovery: explicitly re-checking adoption after the rejection succeeds with the real selection and clears the uncertainty', 'predeclared', async () => { await adoptOn(); await askStep(A, 'AD2', 'Recovered explicit adoption after the rejection.'); const r = await adoptedOk('AD2'); S.ad2 = r.details.ctx; return { ...r, ok: r.ok && S.ad2 !== S.ad1 }; });

    // ---- uncertain outcome: the server completes the adoption but the response is lost (controlled harness mechanism, loopback only)
    const t1 = (await A.ev(ASSIST_FULL)).turns;
    await step('C32 lost adoption response: server dispatched and completed, UI has no turn, reports the uncertain outcome and clears the checkbox', 'predeclared', async () => {
      await adoptOn(); await page.send('Fetch.enable', { patterns: [{ urlPattern: '*' }, { urlPattern: '*/api/assistant/ask', requestStage: 'Response' }] });   // response-stage pause armed ONLY for this step
      let row; hooks.loseNextAskResponse = true; try { ({ row } = await askStep(A, 'LOST', 'Adoption whose response is discarded by the harness.')); } finally { hooks.loseNextAskResponse = false; await page.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] }).catch(() => {}); }
      const st = await A.ev(ASSIST_FULL); const mech = hooks.log.filter((e) => e.kind === 'lose-response').slice(-1)[0] || null; const chk = (await A.ev(ADOPT_STATE)).checked;
      if (!mech || mech.mechanism === 'FAILED' || st.turns !== t1) return { unmet: true, ok: false, details: { precondition: 'the controlled lost-response mechanism was not effective; this is not a product observation', mechanism: mech, ui: st, turnsBefore: t1, brokerDelta: row.observed.brokerDelta } };
      return { ok: row.match && st.turns === t1 && !st.pending && !st.adoptNext && !chk && st.adoptionUncertain && /may have changed/i.test(st.error || ''), details: { mechanism: mech, ui: st, checkboxChecked: chk, brokerDelta: row.observed.brokerDelta, requestDelta: row.observed.requestDelta } }; });
    await step('C33 after the lost response a plain follow-up is refused by the UI (nothing sent)', 'predeclared', async () => { const { row } = await askStep(A, 'BLK2', 'Plain follow-up after the lost response.'); const st = await A.ev(ASSIST_FULL);
      return { ok: row.match && st.adoptionUncertain && /response was not received/i.test(st.error || '') && st.turns === t1 && !st.pending, details: { ui: st, brokerDelta: row.observed.brokerDelta, requestDelta: row.observed.requestDelta } }; });
    await step('C34 retry: re-checking adoption after the lost response succeeds, appends the turn and clears the uncertainty', 'predeclared', async () => { await adoptOn(); await askStep(A, 'AD3', 'Retry of the explicit adoption after the lost response.'); const r = await adoptedOk('AD3'); const subj = observedSubjects();
      return { ...r, ok: r.ok && (await A.ev(ASSIST_FULL)).turns === t1 + 1, details: { ...r.details, observedAdoptionRequests: subj.length, sameSubjectAcrossAdoptions: new Set(subj.map((e) => e.subjectId)).size === 1 } }; });
    await shot('05b_after_retry');
  });

  await section('cancellation', async () => {
    await ensureComposer(A); const tb = (await A.ev(ASSIST_STATE)).turns; const b0 = brokerCount();
    await askStep(A, 'CAN', 'Deterministic cancellation probe'); const reached = expRows.CAN?.observed.brokerDelta === 1;
    await A.waitFor(`document.querySelector('[data-action="a-cancel"]')`, 5000, 'cancel control'); await A.hclick('[data-action="a-cancel"]', 'Cancel');
    await A.waitFor(`!window.__otStore.get().assistant.pending`, 10000, 'cancel retired'); await sleep(2500);
    const ac = await A.ev(ASSIST_STATE);
    await step('C13 cancellation retires the late fixture response without appending a turn', 'codex', async () => ({ ok: ac.turns === tb && ac.error && reached, details: { ...ac, turnsBefore: tb, brokerReached: reached } }));
    await step('C14 no stale reply appears after the broker hold elapsed (store and DOM)', 'added', async () => ({ ok: ac.turns === tb && ac.domTurns === tb && !ac.pending, details: ac }));
    await shot('06_after_cancel');
  });

  await section('isolation', async () => {   // explicit precondition ladder first; only a MET precondition lets the HttpOnly comparison and B's own conversation count as evidence
    const { browserContextId } = await chrome.browser.send('Target.createBrowserContext', { disposeOnDetach: true });
    const { targetId } = await chrome.browser.send('Target.createTarget', { url: 'about:blank', browserContextId });
    const { sessionId } = await chrome.browser.send('Target.attachToTarget', { targetId, flatten: true });
    const isoSend = (m, p = {}) => chrome.browser.send(m, p, sessionId); const B = ops(isoSend, 'B'); S.isoSend = isoSend; S.isoTarget = targetId;
    await isoSend('Page.enable'); await isoSend('Runtime.enable'); await isoSend('Network.enable'); await isoSend('Fetch.enable', { patterns: [{ urlPattern: '*' }] }); intercept(isoSend, sessionId, false); watchApi(sessionId, 'B', isoSend);
    const P = { initialized: false, configOk: false, foreground: false, delivered: false, sessionRequested: false, sessionOk: false, analysisReady: false }; const D = {};
    const until = async (fn, ms) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await fn()) return true; await sleep(100); } return false; };
    await isoSend('Page.navigate', { url: serviceUrl });
    P.initialized = await B.waitFor(`document.readyState==='complete' && window.__otStore && document.querySelector('#ot-demo') && !document.querySelector('#ot-demo').disabled`, 20000).then(() => true).catch(() => false);
    P.configOk = await until(async () => apiLog.some((e) => e.tag === 'B' && e.path === '/api/config' && e.status === 200), 10000);
    try { await chrome.browser.send('Target.activateTarget', { targetId }); await isoSend('Page.bringToFront'); } catch (e) { D.activateError = e.name; }
    try { await isoSend('Emulation.setFocusEmulationEnabled', { enabled: true }); D.focusEmulation = true; } catch (e) { D.focusEmulation = false; }
    P.foreground = await until(async () => { const r = await B.ev(ISO_READY).catch(() => null); D.ready = r; return !!r && r.vis === 'visible' && r.focus === true; }, 4000);
    await B.ev(ISO_INSTALL).catch(() => false);
    try { await B.hclick('#ot-demo', 'B demo'); D.clicked = true; } catch (e) { D.clicked = false; D.clickError = safe(e); }     // ONE real hit-tested click; no retry, no programmatic fallback
    P.delivered = await until(async () => { const r = await B.ev(ISO_READY).catch(() => null); D.afterClick = r; return !!r?.click && r.click.trusted >= 1; }, 3000);
    P.sessionRequested = await until(async () => reqLog.some((e) => e.tag === 'B' && e.path === '/api/session' && e.method === 'POST'), 5000);
    P.sessionOk = await until(async () => apiLog.some((e) => e.tag === 'B' && e.path === '/api/session' && e.status === 201), 10000);
    P.analysisReady = P.sessionOk && await B.waitFor(`window.__otStore?.get().analysis && !window.__otStore.get().busy`, 30000).then(() => true).catch(() => false);
    const cls = classifyIso(P); evidence.isoPrecondition = { P, cls, D, bRequests: reqLog.filter((e) => e.tag === 'B').map((e) => `${e.method} ${e.path}`), bApi: apiLog.filter((e) => e.tag === 'B').map((e) => `${e.path} ${e.status}`) };
    await step('C15P isolated-context precondition: initialized page and config, foreground activation, real input delivered, successful session request and analysis', 'predeclared', async () => ({ ok: cls === 'met', unmet: cls !== 'met', details: { classification: cls, ...P, ...D, note: 'a failed precondition is not evidence about session leakage' } }));
    await shot('07_isolated_context', isoSend); await chrome.browser.send('Target.activateTarget', { targetId: page.targetId }).catch(() => {}); await A.send('Page.bringToFront');
    if (cls !== 'met') { rec('C15 isolated browser context has a distinct HttpOnly session credential and no inherited conversation', 'precondition-unmet', { classification: cls, note: 'not evaluated; not evidence about leakage' }, 'codex'); return; }
    S.B = B; evidence.bWindow = await B.ev(`({iw:innerWidth,ih:innerHeight})`);
    const cookie = {}; const cu = `${serviceUrl}api/session`; const named = (arr) => (arr || []).find((c) => c.name === 'ot_session');
    for (const [mech, fa, fb] of [['Network.getCookies', () => page.send('Network.getCookies', { urls: [cu] }).then((r) => r.cookies), () => isoSend('Network.getCookies', { urls: [cu] }).then((r) => r.cookies)],
      ['Storage.getCookies', () => chrome.browser.send('Storage.getCookies', {}).then((r) => r.cookies), () => chrome.browser.send('Storage.getCookies', { browserContextId }).then((r) => r.cookies)]]) {
      try { cookie[mech] = cookieSummary(named(await fa()), named(await fb())); } catch (e) { cookie[mech] = { error: e.name }; } }
    S.bTurns0 = (await B.ev(ASSIST_STATE)).turns;
    await step('C15 isolated browser context has a distinct HttpOnly session credential and no inherited conversation', 'codex', async () => { const m = cookie['Network.getCookies'] || {}, m2 = cookie['Storage.getCookies'] || {};
      const dist = !!(m.distinct || m2.distinct); const http = !!((m.distinct && m.httpOnlyA && m.httpOnlyB) || (m2.distinct && m2.httpOnlyA && m2.httpOnlyB)); const eq = !!((m.presentA && m.presentB && m.distinct === false) || (m2.presentA && m2.presentB && m2.distinct === false));
      return { ok: dist && http && !eq && S.bTurns0 === 0, details: { cookie, distinct: dist, httpOnly: http, anyEqual: eq, inheritedTurns: S.bTurns0, bWindow: evidence.bWindow, note: 'comparison outcomes only; no raw credential recorded' } }; });
  });

  await section('repaint', async () => {
    await A.hclick('#ot-tab-bom', 'BOM tab'); await A.waitFor(`document.querySelector('[data-bom-cy="inline"]')?._cy && !document.querySelector('[data-bom-cy="inline"]')._cy.destroyed()`, 15000, 'BOM graph restored');
    await settleCam(A, 4000);
    const recSel = { attempted: false, rowFound: await A.ev(`!!document.querySelector('[data-action="bom-record"]')`) };
    if (recSel.rowFound) { recSel.attempted = true; try { await A.hclick('[data-action="bom-record"]', 'record row');
      recSel.relatedSettled = await A.waitFor(`!window.__otStore.get().bom8.req.related`, 8000).then(() => true).catch(() => false);
      if ((await A.ev(STORE_SEL)).popup) { await A.hclick('[data-action="bom-close"]', 'close related-checks popup'); recSel.popupClosedByClick = true; await A.waitFor(`!window.__otStore.get().bom8.popup`, 4000).catch(() => {}); } } catch (e) { recSel.error = safe(e); } }
    const s1 = await settleCam(A); const storeBefore = await A.ev(STORE_SEL); await A.ev(`(window.__ltRef=document.querySelector('[data-bom-cy="inline"]')._cy,true)`);
    await askStep(A, 'RPT', 'Answer after returning to the graph view.');
    const s2 = await settleCam(A, 3000); const sameInst = await A.ev(`document.querySelector('[data-bom-cy="inline"]')?._cy===window.__ltRef`); const storeAfter = await A.ev(STORE_SEL);
    evidence.camera = { before: s1.cam && { z: s1.cam.z, px: s1.cam.px, py: s1.cam.py }, after: s2.cam && { z: s2.cam.z, px: s2.cam.px, py: s2.cam.py }, settledBefore: s1.ok, settledAfter: s2.ok };
    await step('C16 assistant answer repaint preserves the graph instance, renderer and numeric camera', 'codex', async () => ({ ok: sameInst && s2.cam?.rd === false && s2.cam?.n === s1.cam?.n && s2.cam?.e === s1.cam?.e && camEqual(s1.cam, s2.cam) && s1.ok, details: { sameInstance: sameInst, rendererLive: s2.cam?.rd === false, nodes: s2.cam?.n, edges: s2.cam?.e, camera: evidence.camera } }));
    await step('C17 selected graph record (store and cytoscape) survives the assistant repaint', 'replacement', async () => {
      const id = storeBefore.selectedRecord;
      if (!recSel.rowFound) return { info: true, ok: false, details: { unexercised: 'no [data-action=bom-record] row available; no record selected', recSel } };
      const meaningful = recSel.attempted && !recSel.error && id != null && (s1.cam?.sel || []).includes(id);
      const kept = storeAfter.selectedRecord === id && (s2.cam?.sel || []).includes(id) && sameSet(s1.cam?.sel, s2.cam?.sel) && storeAfter.selected === storeBefore.selected;
      return { ok: meaningful && kept, details: { meaningfulPrecondition: meaningful, selectedRecordBefore: !!id, cySelectedBefore: s1.cam?.sel?.length ?? null, cySelectedAfter: s2.cam?.sel?.length ?? null, cyContainsRecordBefore: (s1.cam?.sel || []).includes(id), cyContainsRecordAfter: (s2.cam?.sel || []).includes(id), storeRecordUnchanged: storeAfter.selectedRecord === id, candidateUnchanged: storeAfter.selected === storeBefore.selected, recSel,
        gap: 'only store-backed selection is covered; cytoscape selection not backed by the store is cleared by syncGraph on every render, and a canvas tap is not exercised' } }; });
    await shot('08_after_answer_repaint');
  });

  await section('header-and-pan', async () => {
    const themeReach = await reach(A, '#ot-theme', 'theme toggle'); panelEvidence.theme = themeReach.steps; if (themeReach.usabilityFinding) panelEvidence.usabilityFinding = themeReach.usabilityFinding;
    rec('C28 header controls reachable through supported assistant minimize/move controls', themeReach.ok ? 'pass' : 'finding', { steps: themeReach.steps, usabilityFinding: themeReach.usabilityFinding || null }, 'added');
    await shot('09_panel_state_for_header'); const themeBefore = await A.ev(`window.__otStore.get().theme`);
    await step('C18 theme repaint keeps the active graph attached and rendered', 'codex', async () => { await A.hclick('#ot-theme', 'theme toggle'); await sleep(300);
      const th = await A.ev(`({theme:window.__otStore.get().theme,host:!!document.querySelector('[data-bom-cy="inline"]')?._cy,renderer:!!document.querySelector('[data-bom-cy="inline"]')?._cy?.renderer().destroyed,same:document.querySelector('[data-bom-cy="inline"]')?._cy===window.__ltRef})`);
      return { ok: th.theme !== themeBefore && th.theme === 'dark' && th.host && th.renderer === false, details: { themeBefore, themeAfter: th.theme, graphAttached: th.host, rendererLive: th.renderer === false, sameInstance: th.same } }; });
    await shot('10_dark_theme');
    for (const [n, tab] of [['C19', 'ai'], ['C20', 'crypto'], ['C21', 'bom']]) await step(`${n} tab navigation ${tab} remains usable after assistant and theme repaints`, 'codex', async () => { await A.hclick(`#ot-tab-${tab}`, `${tab} tab`); await sleep(300);
      const st = await A.ev(`(()=>{const h=document.querySelector('#ot-tabpanel [data-cy="${tab}"]')||document.querySelector('#ot-tabpanel [data-bom-cy="inline"]');return {selected:document.querySelector('#ot-tab-${tab}')?.getAttribute('aria-selected'),cy:!!h?._cy,alive:!!h?._cy&&!h._cy.destroyed(),renderer:!!h?._cy?.renderer().destroyed}})()`);
      return { ok: st.selected === 'true' && (!st.cy || st.alive), details: { selected: st.selected === 'true', graphAlive: !st.cy || st.alive, rendererLive: st.renderer === false } }; });
    await settleCam(A, 3000);
    const gReach = await reach(A, '[data-bom-cy="inline"]', 'BOM graph host'); panelEvidence.graphHost = gReach.steps;   // supported controls first
    // ---- pan matrix: real drags; every trial records elementFromPoint along the whole path, trusted pointer events seen by the page, cytoscape events, focus, camera before/after(+500 ms) and the 1:1 expectation.
    const activateA = async () => { try { await chrome.browser.send('Target.activateTarget', { targetId: page.targetId }); await page.send('Page.bringToFront'); } catch {} await A.waitFor('document.hasFocus()', 2000).catch(() => {}); };
    const trials = [];
    const panTrial = async (name, skip) => {
      await activateA(); await settleCam(A, 2500); const pts = await A.ev(PAN_POINTS_AT(skip)); const t = { name, state: null };
      if (!pts || pts.none) { t.noPoints = true; t.host = pts?.host; trials.push(t); return t; }
      await A.ev(PAN_INSTALL); const path = await A.ev(PAN_PATH(pts.x, pts.y, pts.ex, pts.ey)); const pre = await A.ev(PAN_READ); const p0 = await A.ev(CAM);
      recordHit('A', `pan ${name} start`, '[data-bom-cy=inline]', path.record);
      await A.mouse('mouseMoved', pts.x, pts.y); await A.mouse('mousePressed', pts.x, pts.y, { button: 'left', clickCount: 1 });
      for (let i = 1; i <= 5; i++) await A.mouse('mouseMoved', pts.x + (pts.ex - pts.x) * i / 5, pts.y + (pts.ey - pts.y) * i / 5, { button: 'left', buttons: 1 });
      await A.mouse('mouseReleased', pts.ex, pts.ey, { button: 'left', clickCount: 1 }); await sleep(300); const p1 = await A.ev(CAM); const post = await A.ev(PAN_READ); await sleep(500); const p2 = await A.ev(CAM);
      const dx = pts.ex - pts.x, dy = pts.ey - pts.y; const mx = p1.px - p0.px, my = p1.py - p0.py;
      Object.assign(t, { points: { start: { x: Math.round(pts.x), y: Math.round(pts.y) }, end: { x: Math.round(pts.ex), y: Math.round(pts.ey) }, clearancePx: Math.round(pts.d) }, path: path.path, pathBlockers: path.blockers, state: pre.store, focusBefore: pre.focus, vis: pre.vis, cyFlags: pre.flags,
        before: { px: p0.px, py: p0.py, z: p0.z }, after: { px: p1.px, py: p1.py, z: p1.z }, after500ms: { px: p2.px, py: p2.py, z: p2.z }, expected: { dx, dy }, moved: Math.abs(mx - dx) <= 1 && Math.abs(my - dy) <= 1, driftAfter500ms: Math.abs(p2.px - p1.px) + Math.abs(p2.py - p1.py),
        events: post.events, eventCount: post.eventCount, cy: post.cy, selectedAfter: p1.sel?.length ?? null });
      t.classification = classifyPan(t); trials.push(t); return t; };
    const ctxSel = await A.ev(STORE_SEL);
    // trial set 1: the state left by the repaint section (a record selected, details open), same configuration as the run-2 failure
    const T1 = await panTrial('selected-primary'); const T2 = await panTrial('selected-alt', T1.points && { x: T1.points.start.x, y: T1.points.start.y });
    // trial set 2: selection cleared through a supported control (BOM group button), graph settled
    // the group control exists only in the Full evidence graph view (gaps.js renders bom-group only for view 'full'): switch through the supported view control and record the view per trial
    let viewOk = false; try { await A.hclick('[data-action="bom-view"][data-view="full"]', 'BOM view: Full evidence graph'); await A.waitFor(`window.__otStore.get().bom8.view==='full' && document.querySelector('[data-bom-cy="inline"]')?._cy && !document.querySelector('[data-bom-cy="inline"]')._cy.destroyed()`, 15000); await settleCam(A, 4000); viewOk = true; } catch (e) { panelEvidence.viewSwitchError = safe(e); }
    let clearedOk = false; if (viewOk) try { await A.hclick('[data-action="bom-group"]', 'BOM group (clears record selection)'); await A.waitFor(`!window.__otStore.get().bom8.selectedRecord`, 5000); await A.waitFor(`document.querySelector('[data-bom-cy="inline"]')?._cy && !document.querySelector('[data-bom-cy="inline"]')._cy.destroyed()`, 10000); await settleCam(A, 4000); clearedOk = true; } catch (e) { panelEvidence.clearSelectionError = safe(e); }
    const T3 = clearedOk ? await panTrial('cleared-primary') : null; const T4 = clearedOk && T3?.points ? await panTrial('cleared-alt', { x: T3.points.start.x, y: T3.points.start.y }) : null;
    // trial set 3: reselect a record through the supported row control, then drag again (repeatability of set 1)
    let reselOk = false; if (ctxSel.selectedRecord || clearedOk) { try { await A.hclick('[data-action="bom-record"]', 'record row (reselect)'); await A.waitFor(`!window.__otStore.get().bom8.req.related`, 8000).catch(() => {}); if ((await A.ev(STORE_SEL)).popup) { await A.hclick('[data-action="bom-close"]', 'close related-checks popup'); await A.waitFor(`!window.__otStore.get().bom8.popup`, 4000).catch(() => {}); } await settleCam(A, 4000); reselOk = true; } catch (e) { panelEvidence.reselectError = safe(e); } }
    const T5 = reselOk ? await panTrial('reselected-primary') : null;
    evidence.panMatrix = trials.map((t) => ({ name: t.name, classification: t.classification || (t.noPoints ? 'no-clear-points' : null), moved: t.moved ?? null, state: t.state, focusBefore: t.focusBefore ?? null }));
    panelEvidence.panTrials = trials;
    await step('C22 graph pan drag works after assistant-triggered repaints, in the same configuration as the run-2 failure (record selected, details open): pan equals the 1:1 drag delta', 'codex', async () => { if (!T1 || T1.state?.selectedRecord == null) return { unmet: true, ok: false, details: { precondition: 'no record was selected at the start of the first trial, so this is not the run-2 configuration', trial: T1 } };
      return { ok: !T1.noPoints && T1.moved === true && T1.classification === 'panned', details: { trial: T1, note: 'strict: the same predicate that failed in run 2, now with real hit tests and pointer events' } }; });
    await step('C22M pan matrix: every drag in every predeclared state (selected x2, cleared x2, reselected) equals its 1:1 delta; each trial carries its classification', 'predeclared', async () => {
      const all = [T1, T2, T3, T4, T5]; const missing = all.map((t, i) => (t ? null : ['T3', 'T4', 'T5'][i - 2] || 'T' + (i + 1))).filter(Boolean);
      const bad = all.filter((t) => t && (t.noPoints || t.moved !== true)).map((t) => ({ name: t.name, classification: t.classification || 'no-clear-points' }));
      return { ok: !missing.length && !bad.length, unmet: !!missing.length && !bad.length, details: { viewSwitched: viewOk, clearedStateReached: clearedOk, reselectedStateReached: reselOk, classifications: trials.map((t) => ({ name: t.name, view: t.state?.view ?? null, classification: t.classification || 'no-clear-points', moved: t.moved, selectedRecord: t.state?.selectedRecord != null, popup: t.state?.popup, drawer: t.state?.drawer })), notRun: missing, notPanned: bad, note: 'a state that could not be reached is precondition-unmet unless a trial that did run failed to pan; classification labels the evidence only, not a cause' } }; });
    await shot('11_after_pan');
  });

  await section('pending-lifecycle', async () => {   // A has a pending request ended by End session while B (separate browser context) has its own request in flight/answered
    const gen0 = await A.ev(`window.__otStore.get().analysis.generation`); const b1 = brokerCount();
    if (S.B) { try { await chrome.browser.send('Target.activateTarget', { targetId: S.isoTarget }); await S.isoSend('Page.bringToFront'); await S.B.hclick('#ot-assistant-launch', 'B assistant launcher'); await askStep(S.B, 'B1', 'Isolated context question.', 'B'); S.bAsked = true; evidenceRef.bAsked = true; S.bTurnsAfterAsk = (await S.B.ev(ASSIST_STATE)).turns; } catch (e) { S.bError = safe(e); } await chrome.browser.send('Target.activateTarget', { targetId: page.targetId }).catch(() => {}); await A.send('Page.bringToFront'); }
    const b1b = brokerCount();   // B's work is finished BEFORE A's probe, so nothing slow sits between A's submit and End session
    await askStep(A, 'END', 'Deterministic cancellation probe'); const reached2 = expRows.END?.observed.brokerDelta === 1; await A.waitFor(`window.__otStore.get().assistant.pending`, 5000, 'pending');
    const endReach = await reach(A, '#ot-top-end', 'End session'); panelEvidence.endSession = endReach.steps; if (endReach.usabilityFinding) panelEvidence.usabilityFindingEnd = endReach.usabilityFinding;
    let ended = null;
    await step('C23 session end while a request is pending leaves no stale reply, turns or pending request', 'added', async () => {
      if (!endReach.ok) return { ok: false, details: { blocked: endReach.usabilityFinding, brokerReached: reached2 } };
      const pendingAtEnd = S.pendingAtEnd = await A.ev(`!!window.__otStore.get().assistant.pending`); await A.hclick('#ot-top-end', 'End session'); await A.waitFor(`document.getElementById('ot-ended-note')`, 30000, 'ended note'); await sleep(2500);
      ended = await A.ev(`(()=>{const a=window.__otStore.get().assistant;return {analysis:!!window.__otStore.get().analysis,turns:a.turns.length,pending:!!a.pending,domTurns:document.querySelectorAll('.ot-assistant-turn').length}})()`);
      if (!pendingAtEnd) return { unmet: true, ok: false, details: { precondition: 'the request was no longer pending when End session was clicked (timing); not a product observation', ...ended, brokerReached: reached2 } };
      return { ok: pendingAtEnd && !ended.analysis && ended.turns === 0 && !ended.pending && ended.domTurns === 0, details: { ...ended, pendingAtEnd, brokerReached: reached2, note: 'client-side lifecycle only; server-side cancellation of the ended session is not independently observed' } }; });
    await step('C23L the End-session probe\'s late reply was refused by the server (409 stale_or_cancelled)', 'predeclared', async () => { const last = apiLog.filter((e) => e.tag === 'A' && e.path === '/api/assistant/ask').slice(-1)[0] || null; if (!ended || S.pendingAtEnd === false) return { unmet: true, ok: false, details: { precondition: !ended ? 'End session step not completed' : 'the probe was not pending at End (timing), so a late reply is not expected', pendingAtEnd: S.pendingAtEnd ?? null } }; return { ok: last?.status === EXPECT.END.lateStatus && last?.code === EXPECT.END.lateCode, details: { status: last?.status ?? null, code: last?.code ?? null, expected: { status: EXPECT.END.lateStatus, code: EXPECT.END.lateCode } } }; });
    await shot('12_after_session_end');
    await step('C24 the other browser context keeps its own session, answer and conversation after this session ends', 'added', async () => {
      if (!S.B) return { unmet: true, ok: false, details: { precondition: 'isolated context session precondition (C15P) not met; not evidence about session separation' } };
      const bAfter = await S.B.ev(`({analysis:!!window.__otStore.get().analysis,turns:window.__otStore.get().assistant.turns.length,pending:!!window.__otStore.get().assistant.pending,domTurns:document.querySelectorAll('.ot-assistant-turn').length,text:[...document.querySelectorAll('.ot-assistant-turn')].map(t=>t.textContent.includes('Deterministic cancellation probe')).some(Boolean)})`);
      return { ok: bAfter.analysis && S.bTurnsAfterAsk === 1 && bAfter.turns === 1 && bAfter.domTurns === 1 && !bAfter.pending && !bAfter.text, details: { ...bAfter, bTurnsAfterAsk: S.bTurnsAfterAsk, bError: S.bError || null, note: 'B asked its own question before A ended; A\'s probe text must not appear in B' } }; });
    await step('C25 a new session/generation starts with an empty conversation', 'added', async () => { if (!ended) return { ok: false, details: { notReached: true } };
      await A.waitFor(`document.querySelector('#ot-demo')`, 15000, 'demo after end'); await A.hclick('#ot-demo', 'demo'); await A.waitFor(`window.__otStore?.get().analysis && !window.__otStore.get().busy`, 30000, 'new analysis'); await sleep(500);
      const fr = await A.ev(`({gen:window.__otStore.get().analysis.generation,turns:window.__otStore.get().assistant.turns.length,pending:!!window.__otStore.get().assistant.pending})`); return { ok: fr.turns === 0 && !fr.pending, details: { oldGeneration: gen0, newGeneration: fr.gen, ...fr } }; });
  });
  evidence.submitted = S.submitted;
}
let fatal = null;
try { await Promise.race([body(), deadlineP]); } catch (e) { fatal = e; rec('harness completed', 'error', { error: safe(e) }, 'harness'); console.error('FATAL', e.message); }
finally {
  finishing = true; clearTimeout(deadlineTimer);
  const total = brokerCount();
  const withB = reqLog.some((e) => e.tag === 'B' && e.path === '/api/assistant/ask'); const wantBroker = expectedBroker(EXPECT, withB), wantReq = expectedRequests(EXPECT, withB);
  const askReqs = reqLog.filter((e) => e.path === '/api/assistant/ask' && e.method === 'POST').length; const unrunSteps = Object.keys(EXPECT).filter((k) => !(k in expRowsRef) && !(k === 'B1' && !withB));
  rec('C26 broker invocations equal the frozen expectation (dispatching steps only; pre-dispatch rejections and UI-blocked asks excluded as declared), and every step matched its own frozen delta', (total === wantBroker && askReqs === wantReq && !unrunSteps.length && Object.values(expRowsRef).every((r) => r.match)) ? 'pass' : (fatal ? 'info' : 'fail'),
    { brokerInvocations: total, expectedBroker: wantBroker, sentAssistantAskRequests: askReqs, expectedRequests: wantReq, isolatedQuestionIncluded: withB, stepsNotReached: unrunSteps, perStep: expRowsRef, note: 'expectation derived from the frozen EXPECT table, not from the number of questions typed' }, 'frozen-expectation');
  rec('C27 browser issued no non-loopback request', blocked.length === 0 ? 'pass' : 'fail', { blockedRequestCount: blocked.length }, 'codex');
  try { if (page) await shot('99_final_state'); } catch {}
  try { notes.pageExceptions = page?.log.exceptions.slice(0, 20); notes.failedRequests = page?.log.failed.length; } catch {}
  try { notes.serviceSockets = service?.pid ? execFileSync('lsof', ['-nP', '-a', '-p', String(service.pid), '-i'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).split('\n').slice(0, 12) : null; } catch { notes.serviceSockets = 'lsof: none/err'; }
  try { chrome?.browser.close(); } catch {}
  await terminateOwned(); notes.chromeExit = notes.chromeExit || (chrome?.proc ? { code: chrome.proc.exitCode, sig: chrome.proc.signalCode } : null); notes.serviceTail = sanitize(serviceLog, [[HOME, '~'], [SRC, '<src>']]);
  const tally = {}; for (const r of results) tally[r.status] = (tally[r.status] || 0) + 1;
  writeFileSync(join(OUT, 'results.json'), JSON.stringify({ label: LABEL, testedSource: process.env.OT_SRC_SHA || null, finishedAt: new Date().toISOString(), ledger: readLedger(), cap: CAP, deadlineHit, chromeFlags: chrome?.flags, ownedPids: owned, cleanup,
    blockedExternalRequests: blocked.length, brokerInvocations: total, apiLog, requestLog: reqLog, askDiag, controlledHarnessMechanisms: hooks.log, evidence, panel: panelEvidence, hitTests: hitLog, notes, results, tally }, null, 2));
  console.log(JSON.stringify(tally), `survivors=${cleanup.survivors.length}`);
  process.exitCode = results.some((r) => r.status === 'fail' || r.status === 'error' || r.status === 'blocked-occluded') ? 1 : 0;   // precondition-unmet / info / finding do not set the exit code; the tally reports them
}
