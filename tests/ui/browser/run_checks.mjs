// Real-browser checks of the actual loopback app at 1366 px and 390 px (I4E §4).
// Usage: PYTHON=<python with requirements-dev> node tests/ui/browser/run_checks.mjs [outDir]
// Needs Google Chrome (CHROME_BIN overrides) and Node >= 22. No network beyond 127.0.0.1.
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, newPage } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const OUT = resolve(process.argv[2] || join(REPO, '.context/logs/I4E_BROWSER_CHECKS_2026-11-05'));
mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PINNED_SBOM = '8ee39ed7f937158ecc782d5839608079f1750dc9855212c54035b596e03513e7';

// ---------------------------------------------------------------- service
const root = mkdtempSync(join(tmpdir(), 'ot-sessions-'));
const svc = spawn(process.env.PYTHON || 'python3', ['-m', 'opentrace_core.app', '--port', '0', '--session-root', join(root, 's')], {
  cwd: REPO, env: { ...process.env, OPENTRACE_DEMO_REPLAY: '', PYTHONPATH: join(REPO, 'src/core') }, stdio: ['ignore', 'pipe', 'pipe'] });
const base = await new Promise((resolveUrl, reject) => {
  let buf = ''; const t = setTimeout(() => reject(new Error('service did not start: ' + buf)), 30000);
  svc.stdout.on('data', (d) => { buf += d; const m = buf.match(/http:\/\/127\.0\.0\.1:(\d+)\//); if (m) { clearTimeout(t); resolveUrl(m[0]); } });
  svc.stderr.on('data', (d) => { buf += d; });
});
const ORIGIN = new URL(base).origin;

// ---------------------------------------------------------------- harness
const results = []; let currentVp = '';
const check = (id, ok, detail = '') => { results.push({ vp: currentVp, id, ok: !!ok, detail: String(detail) }); console.log(`${ok ? 'PASS' : 'FAIL'} [${currentVp}] ${id}${detail ? ' — ' + String(detail).slice(0, 160) : ''}`); };
const storageReport = [];
const { browser, close } = await launch();

const txt = (pg, sel) => pg.eval(`(document.querySelector(${JSON.stringify(sel)})?.innerText||'')`);
const count = (pg, sel) => pg.eval(`document.querySelectorAll(${JSON.stringify(sel)}).length`);
const exists = (pg, sel) => pg.eval(`!!document.querySelector(${JSON.stringify(sel)})`);
const state = (pg) => pg.eval('JSON.parse(JSON.stringify(window.__otStore.get()))');
async function storage(pg) {
  return pg.eval(`(async()=>({local:Object.keys(localStorage).sort(),session:Object.keys(sessionStorage),idb:(indexedDB.databases?await indexedDB.databases():[]).map(d=>d.name),caches:(self.caches?await caches.keys():[]),cookieVisible:document.cookie}))()`);
}
const apiCalls = (pg) => pg.log.requests.filter((r) => r.url.startsWith(ORIGIN + '/api/') && r.type !== 'Other');
async function settle(pg, expr, ms = 15000) { await pg.waitFor(expr, ms, expr); await sleep(150); }

async function run(width, height, label) {
  currentVp = label; const narrow = width <= 700;
  const shots = (n) => `${OUT}/${label}_${n}.png`;
  // Graph evidence must show the graph: scroll the frame into view before capturing.
  const shotFrame = async (path) => { await pg.eval(`document.getElementById('ot-graph-frame')?.scrollIntoView({block:'start',behavior:'instant'})`); await sleep(200); await pg.screenshot(path); };
  const pg = await newPage(browser, { width, height, mobile: narrow });
  await pg.goto(base); await sleep(400);

  // --- storage before
  const before = await storage(pg); storageReport.push({ vp: label, phase: 'initial load', ...before });
  check('STORAGE-00 initial: no session/idb/cache storage', before.session.length === 0 && before.idb.length === 0 && before.caches.length === 0 && before.local.every((k) => k.startsWith('oecl.ui.')), JSON.stringify(before));
  await pg.screenshot(shots('01_analyze'));
  const home = await txt(pg, '#ot-analyze');
  check('UIP-02 homepage shows the combined-reference sections, the form and the sample action', /Know what's inside\./i.test(home) && /Verify what you trust\./i.test(home) && /Three inventories\. One evidence trail\./i.test(home) && /A camera app's AI model/i.test(home) && (await exists(pg, '#ot-form #ot-url')) && (await exists(pg, '#nh-sample')) && !/Live analysis unavailable/.test(home));
  check('UIP-02 QA homepage is not narrowed by the legacy 820px intake column (hero heading keeps two lines when wide)', await pg.eval(`(()=>{const w=document.querySelector('.ot-home-page'),h=document.querySelector('#hero-title');if(!w||!h)return false;const lh=parseFloat(getComputedStyle(h).lineHeight);const lines=Math.round(h.getBoundingClientRect().height/lh);return getComputedStyle(w).maxWidth==='none'&&(innerWidth<1100||lines<=2)})()`));
  check('UIP-02 original header and Workspace rail are intact on the homepage', (await exists(pg, '.topbar #ot-about')) && (await exists(pg, '.topbar #ot-demo')) && (await exists(pg, '.topbar #ot-top-end')) && (await exists(pg, 'nav.ot-rail [data-nav=workbench]')) && (await exists(pg, 'nav.ot-rail [data-nav=evidence]')));
  check('UIP-02 session status and an End session control stay on the homepage (disabled with no session)', /No active session/.test(await txt(pg, '#ot-session-status')) && (await pg.eval(`document.getElementById('ot-end-session').disabled`)));

  // --- REQ-01 intake (UIP-03: legacy assertions replaced with recorded reasons)
  // The review/preview step was replaced by the one-click Scan. This browser suite runs against the OFFLINE service (live scanning not
  // enabled), where Scan is disabled with the approved variant D disclosure and the labelled sample path is the way in. The invalid-URL
  // messages, the resolved-commit preview, the manual-commit preview and the open-captured-case button belonged to the retired preview
  // step; the one-click flow (refusals, pinning, Advanced manual commit, cancel, End session) is covered against a live-enabled local
  // service by tests/ui/browser/run_scan_checks.mjs and by tests/core/app/test_scan_jobs.py.
  await pg.waitFor(`document.getElementById('ot-disclosure')`, 15000);
  check('UIP-03 offline service: Scan is disabled with the approved variant D disclosure; no review/preview step exists', (await pg.eval(`document.getElementById('ot-scan').disabled`)) && /Live scanning is not enabled/.test(await txt(pg, '#ot-disclosure')) && !(await exists(pg, '#ot-preview,[data-action=open-capture],[data-action=scan-live]')) && !/Review repository/.test(await txt(pg, '#ot-form')), (await txt(pg, '#ot-disclosure')).slice(0, 90));
  check('UIP-03 the labelled sample path stays available next to the disabled Scan control', await exists(pg, '#nh-sample'));
  check('REQ-01 no progress element before acquisition', !(await exists(pg, '[role=progressbar],progress,.spinner,[aria-busy=true]')));
  check('REQ-01 Advanced is off: manual commit field absent', !(await exists(pg, '#ot-commit')));
  const reqsBeforeAdv = apiCalls(pg).length;
  await pg.click('label.advanced-control'); await settle(pg, `document.getElementById('ot-commit')`);
  check('REQ-01 Advanced on shows the manual commit field', await exists(pg, '#ot-commit'));
  await pg.type('#ot-commit', 'cfa08c5');
  await pg.click('label.advanced-control'); await sleep(300);
  const st = await state(pg);
  check('DEV-01 Advanced off removes the manual SHA and its field', st.intake.manualSha === '' && !(await exists(pg, '#ot-commit')));
  check('REQ-04 toggling Advanced on the intake page makes no request', apiCalls(pg).length === reqsBeforeAdv);

  // --- open the captured case through the labelled sample action (the same Demo action as the header control)
  await pg.click('#nh-sample'); await settle(pg, `document.querySelector('#ot-tabpanel [data-ctx]')`, 30000);
  await sleep(400);
  const cookieNames = await pg.eval('document.cookie');
  check('SESSION HttpOnly cookie is not readable from script', cookieNames === '', JSON.stringify(cookieNames));
  await pg.screenshot(shots('03_workbench_dependencies'), { fullPage: false });
  await pg.screenshot(shots('03b_workbench_full'), { fullPage: true });

  // --- PAR-01 / REQ-02
  const tabs = await pg.eval(`[...document.querySelectorAll('[role=tab]')].map(b=>b.innerText.trim())`);
  check('PAR-01 five tabs in UI-F01 order', JSON.stringify(tabs) === JSON.stringify(['Repository contexts', 'Dependencies', 'Cryptography', 'AI models', 'BOM connections']), tabs.join(' > '));
  // UIP-02 (legacy assertions updated with reasons): Demo opens on Repository contexts; the clutter, hero and standalone checks are gone
  // from the Workbench opening; the four pills come from the active analysis; the inventory-check cards now live in Evidence.
  check('UIP-02 Demo/Scan opens on Repository contexts (not Dependencies)', (await state(pg)).workbench.tab === 'contexts' && (await pg.eval(`document.getElementById('ot-tab-contexts').getAttribute('aria-selected')`)) === 'true' && (await exists(pg, '#ot4-stage,#ot4-list')));   // UIP-04: the contexts map replaced the legacy grid (reason recorded in the implementation log)
  check('UIP-02 a Dependencies preload did not select that tab', !(await exists(pg, '#ot-context')) && !(await exists(pg, '#ot5-context')) && (await pg.eval(`document.getElementById('ot-tab-dependencies').getAttribute('aria-selected')`)) === 'false');
  const clutter = await pg.eval(`['ot-demo-guide','ot-step-copy','ot-findings'].filter(i=>document.getElementById(i)).concat([...document.querySelectorAll('#ot-workbench .ot-identity,#ot-workbench .heading h1,#ot-workbench > .ot-note,#ot-workbench [data-action=export],#ot-workbench [data-action=step]')].map(e=>e.className||e.tagName))`);
  check('UIP-02 walkthrough, pinned banner, hero, hero export, source-only note and Inventory-checks cards are absent', clutter.length === 0, JSON.stringify(clutter));
  const sum = await txt(pg, '#ot2-enrichment');
  check('UIP-02 four pills show the Frigate fixture values (1,989 / 5,483 / 218 / 3) computed from the analysis', (await count(pg, '#ot2-enrichment li')) === 4 && /1,989/.test(sum) && /5,483/.test(sum) && /218/.test(sum) && /\b3\b/.test(sum) && /captured advisory evidence/.test(sum), sum.replace(/\n+/g, ' '));
  check('UIP-02 QA layer bar uses the reference treatment (paper fill, full hairline border, 14/16 padding)', await pg.eval(`(()=>{const t=document.querySelector('.ot-tabs');if(!t)return false;const p=document.createElement('i');p.style.background='var(--paper)';document.body.appendChild(p);const paper=getComputedStyle(p).backgroundColor;p.remove();const c=getComputedStyle(t);return c.backgroundColor===paper&&c.borderTopWidth==='1px'&&c.borderBottomWidth==='1px'&&(innerWidth<=700||c.paddingTop==='14px'&&c.paddingLeft==='16px')})()`));
  check('UIP-02 QA inspector sits flush with the frame edge at wide widths (no 16px inset)', await pg.eval(`(()=>{const l=document.querySelector('.ot-layout');return !!l&&(innerWidth<=700||getComputedStyle(l).paddingLeft==='0px'&&getComputedStyle(l).paddingRight==='0px')})()`));
  const insp0 = await txt(pg, '.ot-inspector');
  // UIP-04 (FR-7): the repository inspector is shown on open (previously a prompt or a record was accepted).
  check('UIP-02/UIP-04 contexts opens with the repository root selected and its inspector shown', /REPOSITORY/i.test(insp0) && /What is this\?/i.test(insp0) && (await state(pg)).workbench.perTab.contexts.selection === 'root', insp0.slice(0, 80).replace(/\n/g, ' '));
  await pg.click(narrow ? '[data-ctx]' : '[data-ctx=root]'); await sleep(300);
  const rootInsp = await txt(pg, '.ot-inspector');
  check('UIP-02 the context inspector asks the four fixed questions and does not claim "no security concern"', ['What is this?', 'Why is it here?', 'Is there a security concern?', 'What remains unknown?', 'Evidence for this record'].every((q) => rootInsp.toLowerCase().includes(q.toLowerCase())) && !/No security concern/i.test(rootInsp) && /not a security assessment/i.test(rootInsp));
  check('UIP-02 Sources & coverage is collapsed by default', !(await pg.eval(`document.querySelector('.ot-insp-sources').open`)));
  await pg.screenshot(shots('03a_contexts_default'), { fullPage: false });
  await pg.click('#ot-tab-dependencies'); await settle(pg, `document.querySelector('[data-dep-node]')&&document.querySelector('.ot-inspector h2')`, 30000); await sleep(300);
  check('PAR-01 context control visible only in Dependencies', await exists(pg, '#ot5-context'));   // UIP-05: the normal view's chooser replaced the legacy select (Advanced keeps #ot-context)

  // --- PAR-02 / PAR-03 (UIP-05: the normal view is the 30-match focus graph; the old six-per-side neighborhood checks are replaced, reasons in the UIP-05 log)
  const per = narrow ? 1 : 6;          // still the Advanced/legacy neighborhood size used by later checks
  const pickCtx = (path) => pg.eval(`(()=>{const s=document.getElementById('ot5-context');const o=s&&[...s.options].find(o=>o.dataset.path===${JSON.stringify(path)});if(!o)return false;s.value=o.value;s.dispatchEvent(new Event('change',{bubbles:true}));return true})()`);
  const focusTitle = () => pg.eval(`document.querySelector('#ot5-svg [data-role=focus] title')?.textContent||''`);
  const nodes = await count(pg, '#ot5-svg [data-dep-node]');
  check('PAR-02 the default page shows the focus and 30 matching packages (UIP-05; was at most 6 per side)', nodes === 31, `nodes=${nodes}`);
  const range = await txt(pg, '#ot5-page-count');
  check('PAR-02 the compact pager shows the match range and total', /^1–30 of 82$/.test(range), range);
  const focusName = await focusTitle();
  check('PAR-02 default focus is the recorded graph root with 82 dependencies', /^web-new /.test(focusName), focusName);
  await pg.click('[data-action=dep-page][data-dir="1"]'); await settle(pg, `/^31–60 of 82$/.test(document.getElementById('ot5-page-count')?.innerText)`);
  check('PAR-02 paging advances the window', true);
  await shotFrame(shots('04_dependencies_page2'));
  // inspect vs explore
  const firstNeighbor = await pg.eval(`[...document.querySelectorAll('#ot5-svg [data-dep-node]')].find(n=>n.dataset.role!=='focus')?.dataset.depNode`);
  await pg.click(`[data-dep-node="${firstNeighbor}"]`); await sleep(700);
  let s2 = await state(pg);
  check('PAR-03 clicking a neighbor inspects it without recentering', s2.workbench.perTab.dependencies.selection === firstNeighbor && s2.workbench.perTab.dependencies.focus !== firstNeighbor && s2.workbench.perTab.dependencies.history.length === 0);
  await pg.eval(`(()=>{const n=document.querySelector('#ot5-svg [data-dep-node="${firstNeighbor}"]');n.dispatchEvent(new MouseEvent('dblclick',{bubbles:true}))})()`);
  await settle(pg, `window.__otStore.get().workbench.perTab.dependencies.focus===${JSON.stringify(firstNeighbor)} && window.__otStore.get().views.depPage?.focus.node_id===${JSON.stringify(firstNeighbor)}`);
  s2 = await state(pg);
  check('PAR-03 double-click recenters on the package (Direct filter, first page)', s2.workbench.perTab.dependencies.focus === firstNeighbor && s2.workbench.perTab.dependencies.filter === 'direct' && s2.workbench.perTab.dependencies.gOffset === 0);
  await pickCtx('web/package-lock.json'); await settle(pg, `/^web-new /.test(document.querySelector('#ot5-svg [data-role=focus] title')?.textContent||'')`);
  check('PAR-03 choosing the context again returns to the generic default focus', (await state(pg)).workbench.perTab.dependencies.filter === 'direct' && /^web-new /.test(await focusTitle()));
  // search narrows the matches (it never accumulates an ancestor graph: the page is bounded by the contract)
  await pg.type('#ot5-search', 'axios'); await settle(pg, `window.__otStore.get().views.depPage?.query==='axios'`);
  const qp = (await state(pg)).views.depPage;
  check('PAR-02 search lists bounded matches (query sent to the payload)', qp.page.matches_total >= 1 && qp.page.matches_total <= 30 && qp.nodes.filter((n) => n.role === 'match').every((n) => /axios/i.test(n.name)), `matches=${qp.page.matches_total}`);
  await pg.eval(`(()=>{const i=document.getElementById('ot5-search');i.value='';i.dispatchEvent(new Event('input',{bubbles:true}))})()`); await settle(pg, `window.__otStore.get().views.depPage?.query===''`);
  check('PAR-02 display stays bounded after searches (focus + 30 matches + labeled connectors)', (await count(pg, '#ot5-svg [data-dep-node]')) <= 1 + 30 + 120);
  await pg.click('[data-ot5-zoom="1.25"]'); const z1 = await txt(pg, '#ot5-zoom-label'); await pg.click('[data-ot5-fit]'); const z2 = await txt(pg, '#ot5-zoom-label');
  check('PAR-03 zoom and Fit all work', z1 === '125%' && z2 === '100%', `${z1} → ${z2}`);
  await pg.click('[data-action=dep-pres][data-p=list]'); await settle(pg, `document.querySelector('.ot-list .component-item')`);
  check('PAR-03 Component list alternative is available', await exists(pg, '.ot-list .component-item'));
  await pg.click('[data-action=dep-pres][data-p=graph]'); await sleep(300);
  check('PAR-03 Graph view restored', await exists(pg, '#ot5-svg'));
  const overflow = await pg.eval(`document.documentElement.scrollWidth > document.documentElement.clientWidth + 1`);
  check('UI-F04 no horizontal page overflow', !overflow);
  const fullName = await pg.eval(`[...document.querySelectorAll('[data-dep-node]')].every(n=>n.getAttribute('aria-label')&&n.querySelector('title'))`);
  check('UI-F04 full package names stay accessible (aria-label + title)', fullName);

  // --- context filter (dependencies only) + Advanced presentation-only (REQ-04 / PAR-04)
  await pickCtx('docker/tensorrt/requirements-amd64.txt');
  await settle(pg, `window.__otStore.get().views.depPage?.context.path==='docker/tensorrt/requirements-amd64.txt'`); await sleep(500);
  const scoped = await pg.eval(`document.getElementById('ot5-context').selectedOptions[0].dataset.path + ' | ' + (window.__otStore.get().views.depPage?.context.path || '')`);   // UIP-05: the foot no longer repeats the source path
  check('Context filter scopes Dependencies', /^docker\/tensorrt\/requirements-amd64\.txt \| docker\/tensorrt\/requirements-amd64\.txt$/.test(scoped), scoped.slice(0, 120));
  await pickCtx('web/package-lock.json');
  // UIP-05: the legacy view/network for the context load after the page (they feed the inspector, advisories and Advanced), so wait for them too
  await settle(pg, `/^web-new /.test(document.querySelector('#ot5-svg [data-role=focus] title')?.textContent||'') && window.__otStore.get().views.dependencies?.context_path==='web/package-lock.json' && window.__otStore.get().network?.context_path==='web/package-lock.json'`, 30000);
  // --- GAP-1: Advanced dense dependency exploration (UI-F05 / PAR-04), presentation only
  const cyN = () => pg.eval(`document.querySelector('[data-cy-dense]')?._cy?.nodes().length ?? -1`);
  const cyE = () => pg.eval(`document.querySelector('[data-cy-dense]')?._cy?.edges().length ?? -1`);
  const allReq = () => pg.log.requests.length;
  const newReq = (from) => pg.log.requests.slice(from).map((r) => r.url.replace(ORIGIN, '')).join(' ');
  const artifactShas = () => pg.eval(`fetch('/api/artifacts').then(r=>r.json()).then(j=>j.artifacts.map(a=>a.name+':'+a.sha256).sort())`);
  const findingsBefore = JSON.stringify((await state(pg)).analysis.summary.checks);
  const advBefore = await txt(pg, '.ot-advisories');
  const summaryBefore = JSON.stringify((await state(pg)).analysis.summary);
  const shasBefore = await artifactShas();
  const focusBefore = (await state(pg)).workbench.perTab.dependencies.focus;
  let r0 = allReq();
  await pg.click('label.advanced-control'); await settle(pg, `document.querySelector('[data-cy-dense]')?._cy?.nodes().length>0`, 20000);
  check('PAR-04 turning Advanced ON issues no request of any kind (API, static or worker)', allReq() === r0, `new=${allReq() - r0}: ${newReq(r0)}`);
  const startN = await cyN();
  check('UI-F05 Advanced opens the dense explorer on a bounded start set (focus + ≤6 branches)', startN >= 2 && startN <= 7 && !(await exists(pg, '#ot-dep-svg')), `nodes=${startN}`);
  const ctl = await txt(pg, '#ot-dense-controls');
  check('UI-F05 controls restored: layout, Show, Expand, introduction paths, Back, Fit, Reset', /Dependency flow/.test(ctl) && /Network/.test(ctl) && /Explore branches/.test(ctl) && /Full context/.test(ctl) && /Expand dependencies · \d+ more/.test(ctl) && /Show introduction paths/.test(ctl) && /Back/.test(ctl) && (await exists(pg, '[data-action=dense-fit]')) && (await exists(pg, '[data-action=dense-reset]')) && (await exists(pg, '[data-action=dense-fitsel]')), ctl.replace(/\n/g, ' | '));
  check('UI-F04 no horizontal page overflow in the Advanced dense view', !(await pg.eval(`document.documentElement.scrollWidth > document.documentElement.clientWidth + 1`)));
  await shotFrame(shots('05_advanced_dense_explore'));
  await pg.click('[data-action=dense-expand]'); await settle(pg, `document.querySelector('[data-cy-dense]')._cy.nodes().length>${startN}`, 20000);
  const n1 = await cyN();
  check('UI-F05 Expand dependencies adds one bounded batch (≤8) of branches', n1 > startN && n1 - startN <= 8, `${startN} → ${n1}`);
  const picked = await pg.eval(`(()=>{const f=window.__otStore.get().workbench.perTab.dependencies.focus;const n=document.querySelector('[data-cy-dense]')._cy.nodes().filter(x=>x.id()!==f)[0];n.emit('tap');return n.id()})()`);
  await settle(pg, `window.__otStore.get().views.dependencies?.inspected?.component.id===${JSON.stringify(picked)}`);
  const sd = await state(pg);
  check('UI-F05 selecting a dense node inspects it without moving the focus', sd.workbench.perTab.dependencies.selection === picked && sd.workbench.perTab.dependencies.focus === focusBefore);
  check('PAR-04 Advanced inspector adds exact IDs and technical detail', /Technical detail/.test(await txt(pg, '.ot-inspector')) && /bom-ref/.test(await txt(pg, '.ot-inspector')) && /p5-requirement/.test(JSON.stringify((await state(pg)).analysis.summary.checks)));
  await pg.click('[data-action=dense-paths]'); await settle(pg, `/introduction-path nodes|No recorded path/.test(document.getElementById('ot-dense-status').innerText)`, 20000);
  check('UI-F05 Show introduction paths adds the declared path from a graph root', /introduction-path nodes|No recorded path to a graph root/.test(await txt(pg, '#ot-dense-status')), (await txt(pg, '#ot-dense-status')).slice(0, 140));
  const n2 = await cyN();
  await pg.click('[data-action=dense-layout][data-v=network]'); await settle(pg, `document.querySelector('[data-cy-dense]')._cy.nodes()[0].style('shape')==='ellipse'`, 25000);
  check('UI-F05 Network layout re-arranges the same nodes', (await cyN()) === n2);
  await pg.eval(`(()=>{const s=document.getElementById('ot-dense-view');s.value='full';s.dispatchEvent(new Event('change',{bubbles:true}))})()`);
  const scope = (await state(pg)).views.dependencies.scope;
  await settle(pg, `document.querySelector('[data-cy-dense]')._cy.nodes().length===${scope.components}`, 40000);
  check('UI-F05 Full context loads every record and captured edge of the selected context', (await cyN()) === scope.components && (await cyE()) === scope.edges && /Full context · .* of .* component records/.test(await txt(pg, '#ot-dense-status')), `nodes=${await cyN()}/${scope.components} edges=${await cyE()}/${scope.edges}`);
  await shotFrame(shots('05b_advanced_full_network'));
  await pg.click('[data-action=dense-fit]'); await pg.click('[data-action=dense-fitsel]'); await pg.click('[data-action=dense-reset]'); await pg.click('[data-action=dense-arrange]'); await sleep(1500);
  check('UI-F05 Fit all, Fit selection, Reset and Arrange operate on the dense graph', (await cyN()) === scope.components && (await pg.eval(`isFinite(document.querySelector('[data-cy-dense]')._cy.zoom())`)));
  await pg.click('[data-action=dense-back]'); await settle(pg, `document.querySelector('[data-cy-dense]')._cy.nodes().length<${scope.components}`, 25000);
  check('UI-F05 Back restores the previous dense state', (await cyN()) < scope.components);
  // a context larger than the Full-context limit disables that option and says why
  await pg.eval(`(()=>{const s=document.getElementById('ot-context');s.value='docs/package-lock.json';s.dispatchEvent(new Event('change',{bubbles:true}))})()`);
  await settle(pg, `document.querySelector('.ot-dense-limit')`, 25000);
  check('UI-F05 Full context is bounded: a 1,513-record context disables it and explains the limit', (await pg.eval(`document.querySelector('#ot-dense-view option[value=full]').disabled`)) && /limited to 600/.test(await txt(pg, '.ot-dense-limit')));
  await pg.eval(`(()=>{const s=document.getElementById('ot-context');s.value='web/package-lock.json';s.dispatchEvent(new Event('change',{bubbles:true}))})()`);
  await settle(pg, `document.querySelector('[data-cy-dense]')?._cy?.nodes().length>0 && window.__otStore.get().views.dependencies?.focus?.name==='web-new'`, 25000);
  // re-enter a dense state, then switch Advanced OFF
  await pg.click('[data-action=dense-expand]'); await sleep(1500);
  const focusDense = (await state(pg)).workbench.perTab.dependencies.focus;
  const selDense = (await state(pg)).workbench.perTab.dependencies.selection;
  r0 = allReq();
  await pg.click('label.advanced-control'); await settle(pg, `document.getElementById('ot5-svg')`);
  check('PAR-04 turning Advanced OFF issues no request of any kind (API, static or worker)', allReq() === r0, `new=${allReq() - r0}: ${newReq(r0)}`);
  const offState = await state(pg);
  const offDep = offState.workbench.perTab.dependencies;
  check('PAR-04 Advanced off returns the bounded readable graph (UIP-05: focus + at most 30 matches)', offState.advanced === false && (await count(pg, '#ot5-svg [data-dep-node]')) <= 31 && !(await exists(pg, '[data-cy-dense]')) && offDep.dense.visible === null);
  check('PAR-04 Advanced off keeps a valid focus (the one before the dense exploration)', offDep.focus === focusDense && focusDense === focusBefore && (await pg.eval(`document.querySelector('#ot5-svg [data-role=focus] title')?.textContent.startsWith('web-new')`)));
  check('PAR-04 the inspected package from the dense view stays inspectable', offDep.selection === selDense && (await txt(pg, '.ot-inspector h2')).length > 0);
  check('PAR-04 findings, advisory results and inventory provenance are unchanged by Advanced', JSON.stringify((await state(pg)).analysis.summary.checks) === findingsBefore && (await txt(pg, '.ot-advisories')) === advBefore && JSON.stringify((await state(pg)).analysis.summary) === summaryBefore && JSON.stringify(await artifactShas()) === JSON.stringify(shasBefore));
  await shotFrame(shots('05c_advanced_off_bounded'));

  // --- GAP-2: Component list — search and inspect a package outside the neighborhood without recentering
  const nb = (await state(pg)).views.dependencies;
  const nbIds = new Set([nb.focus.id, ...nb.incoming.items.map((x) => x.id), ...nb.outgoing.items.map((x) => x.id)]);
  await pg.click('[data-action=dep-pres][data-p=list]'); await settle(pg, `document.querySelector('#ot-component-list .component-item')`);
  const cl0 = (await state(pg)).views.dependencies.component_list;
  check('GAP-2 Component list is a searchable, paginated list scoped to the selected context', cl0.total === nb.scope.components && cl0.items.length <= 40 && (await exists(pg, '#ot5-search')) && (await exists(pg, '[data-action=list-page]')) && new RegExp(String(cl0.total).replace(/(\d)(?=(\d{3})+$)/, '$1,') + ' component records').test(await txt(pg, '#ot-list-count')), `total=${cl0.total} scope=${nb.scope.components}`);
  await pg.type('#ot5-search', 'axios'); await settle(pg, `window.__otStore.get().views.dependencies.component_list?.query==='axios'`);
  const clAx = (await state(pg)).views.dependencies.component_list; const ax = clAx.items[0];
  check('GAP-2 search finds a package outside the current neighborhood', clAx.total === 1 && ax.name === 'axios' && !nbIds.has(ax.id) && /1 component record matching/.test(await txt(pg, '#ot-list-count')), `${ax?.name} in neighborhood=${nbIds.has(ax?.id)}`);
  const histBefore = (await state(pg)).workbench.perTab.dependencies.history.length;
  await pg.click(`[data-dep-node="${ax.id}"]`); await settle(pg, `window.__otStore.get().views.dependencies?.inspected?.component.id===${JSON.stringify(ax.id)}`);
  const ls = (await state(pg)).workbench.perTab.dependencies;
  check('GAP-2 inspecting a listed package does not recenter the graph (focus and history unchanged)', ls.selection === ax.id && ls.focus === focusBefore && ls.history.length === histBefore && /axios/.test(await txt(pg, '.ot-inspector h2')) && /advisory match/i.test(await txt(pg, '.ot-inspector')));
  check('GAP-2 Explore remains a separate, explicit action', (await pg.eval(`!document.querySelector('[data-action=dep-explore]').disabled`)) && /Explore selected package/.test(await txt(pg, '.ot-list-head')));
  await pg.eval(`(()=>{const e=document.getElementById('ot5-search');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}))})()`); await settle(pg, `window.__otStore.get().views.dependencies.component_list?.query===''`);
  const p1 = (await state(pg)).views.dependencies.component_list.items[0].id;
  await pg.click('[data-action=list-page][data-dir="1"]'); await settle(pg, `window.__otStore.get().views.dependencies.component_list?.offset===40`);
  const p2 = (await state(pg)).views.dependencies.component_list;
  check('GAP-2 pagination advances and goes back', p2.items[0].id !== p1 && p2.items.length <= 40);
  await pg.click('[data-action=list-page][data-dir="-1"]'); await settle(pg, `window.__otStore.get().views.dependencies.component_list?.offset===0`);
  await pickCtx('docker/main/requirements-wheels.txt');
  await settle(pg, `window.__otStore.get().views.dependencies?.scope?.components===3 && window.__otStore.get().views.dependencies.component_list?.total===3`);
  check('GAP-2 the list is scoped to the selected context (3 records for requirements-wheels.txt)', (await count(pg, '#ot-component-list .component-item')) === 3);
  check('UI-F04 no horizontal page overflow in the Component list', !(await pg.eval(`document.documentElement.scrollWidth > document.documentElement.clientWidth + 1`)));
  await shotFrame(shots('05d_component_list'));
  await pickCtx('web/package-lock.json');
  await settle(pg, `window.__otStore.get().views.dependencies?.scope?.components===421`);
  await pg.click('[data-action=dep-pres][data-p=graph]'); await settle(pg, `document.getElementById('ot5-svg')`);

  // --- RACE-01: Dependencies context-switch race (independent review of PR #23): responses delivered out of order
  const CTX_B = 'docker/main/requirements-wheels.txt'; const CTX_C = 'docs/package-lock.json'; const CTX_A = 'web/package-lock.json';
  await pg.eval(`(()=>{ if (window.__origFetch) return; window.__origFetch = window.fetch.bind(window); window.__held = []; window.__hold = true;
    window.fetch = (u, i) => { const url = decodeURIComponent(String(u)); if (window.__hold && url.includes('/api/view/dependencies')) return new Promise((res, rej) => { window.__held.push({ url, go: () => window.__origFetch(u, i).then(res, rej) }); }); return window.__origFetch(u, i); }; })()`);
  const heldCount = () => pg.eval('window.__held.length');
  const release = async (kind, context) => { const ok = await pg.eval(`(()=>{const i=window.__held.findIndex(h=>${kind === 'network' ? "h.url.includes('/network')" : "!h.url.includes('/network')"}&&h.url.includes('context=${context}'));if(i<0)return false;window.__held.splice(i,1)[0].go();return true})()`); if (!ok) throw new Error(`no held ${kind} request for ${context}`); };
  const waitHeld = (kind, context) => settle(pg, `window.__held.some(h=>${kind === 'network' ? "h.url.includes('/network')" : "!h.url.includes('/network')"}&&h.url.includes('context=${context}'))`, 20000);
  const pickContext = (c) => pg.eval(`(()=>{const s=document.getElementById('ot-context');s.value=${JSON.stringify(c)};s.dispatchEvent(new Event('change',{bubbles:true}))})()`);
  await pg.click('label.advanced-control'); await settle(pg, `document.getElementById('ot-context')`, 20000);   // UIP-05: the legacy context select (and its race) lives on the Advanced surface
  const reqBefore = pg.log.requests.length;
  // Scenario 1 (network): switch A→C, C's view arrives so C's network request starts and stays in flight;
  // switch to B, B's network arrives first, then C's delayed network arrives.
  await pickContext(CTX_C); await waitHeld('view', CTX_C); await release('view', CTX_C);
  await waitHeld('network', CTX_C);                       // C's network request is now in flight
  await pickContext(CTX_B); await waitHeld('view', CTX_B); await release('view', CTX_B);
  await waitHeld('network', CTX_B);
  await release('network', CTX_B); await settle(pg, `window.__otStore.get().network?.context_path===${JSON.stringify(CTX_B)}`);
  await release('network', CTX_C); await sleep(600);       // the stale response is delivered now
  let rs = await state(pg);
  check('RACE-01 network: B arrived, then the delayed C response — B stays active', rs.network?.context_path === CTX_B && rs.views.dependencies.context_path === CTX_B && (await heldCount()) === 0, `network=${rs.network?.context_path}`);
  // Scenario 2 (view): switch to C then B, deliver B's view first, then C's delayed view.
  await pickContext(CTX_C); await waitHeld('view', CTX_C);
  await pickContext(CTX_B); await waitHeld('view', CTX_B);
  await release('view', CTX_B); await settle(pg, `window.__otStore.get().views.dependencies?.context_path===${JSON.stringify(CTX_B)} && window.__otStore.get().workbench.perTab.dependencies.focus`);
  const netReqs = pg.log.requests.length;
  await release('view', CTX_C); await sleep(600);          // the stale view response is delivered now
  rs = await state(pg); const rdv = rs.views.dependencies; const rdd = rs.workbench.perTab.dependencies;
  check('RACE-01 view: B arrived, then the delayed C response — the latest view stays active', rdv.context_path === CTX_B && rdd.context === CTX_B && rdv.focus.id === rdd.focus && rdv.focus.locations.every((l) => l === CTX_B), `view=${rdv.context_path} focus=${rdd.focus}`);
  check('RACE-01 the stale response changes nothing else: no focus rewrite and no network request for C', !pg.log.requests.slice(netReqs).some((r) => /network/.test(decodeURIComponent(r.url)) && /docs\/package-lock/.test(decodeURIComponent(r.url))) && (await heldCount()) === 0 && rs.network.context_path === CTX_B);
  // Advanced keeps its graph for the current context after the race.
  await settle(pg, `document.querySelector('[data-cy-dense]')?._cy?.nodes().length>0 && /of 3 component records/.test(document.getElementById('ot-dense-status')?.innerText||'')`, 20000);
  check('RACE-01 Advanced still shows the graph of the current context after the race', (await cyN()) >= 1 && /of 3 component records/.test(await txt(pg, '#ot-dense-status')) && !/Loading the dependency network/.test(await txt(pg, '#ot-tabpanel')), (await txt(pg, '#ot-dense-status')).slice(0, 90));
  // Restore the real fetch and the default context, then leave Advanced (the normal view returns to its own context).
  await pg.eval(`(()=>{ window.__hold = false; for (const h of window.__held.splice(0)) h.go(); window.fetch = window.__origFetch; delete window.__origFetch; })()`);
  await pickContext(CTX_A); await settle(pg, `window.__otStore.get().views.dependencies?.scope?.components===421 && window.__otStore.get().network?.context_path===${JSON.stringify(CTX_A)}`, 25000);
  await pg.click('label.advanced-control'); await settle(pg, `!document.querySelector('[data-cy-dense]') && document.getElementById('ot5-svg')`);
  check('RACE-01 console stays clean through the out-of-order delivery', pg.log.exceptions.length === 0 && !pg.log.console.some((c) => ['error', 'warning'].includes(c.type)), JSON.stringify(pg.log.console.slice(0, 2)));

  // --- tabs: PAR-05 / UI-F08
  const tabCalls = [];
  for (const t of ['crypto', 'ai', 'bom', 'contexts']) {
    const c0 = pg.log.requests.length;
    await pg.click(`#ot-tab-${t}`); await sleep(1400);
    const panel = await txt(pg, '.ot-inspector'); const hasCtx = await exists(pg, '#ot-context'); const hasAdv = await exists(pg, '.ot-advisories');
    const newReq = pg.log.requests.slice(c0).map((r) => r.url.replace(ORIGIN, ''));
    tabCalls.push(...newReq);
    check(`PAR-05 ${t}: no package advisory/parent/dependency counts or context filter from Dependencies`, !/Depends on|Used by|advisory match/i.test(panel) && !hasCtx && !hasAdv, panel.slice(0, 70).replace(/\n/g, ' '));
    await shotFrame(shots(`06_tab_${t}`));
  }
  check('PAR-01 context filter is not applied to other domains (no context= on their requests)', !tabCalls.some((u) => /context=/.test(u) && !/view\/dependencies/.test(u)), tabCalls.join(' '));
  // crypto: bounded check subgraph content
  // UIP-06 (test change recorded in the commit message): the normal Cryptography tab is now the crypto_assets/1 view; the Demo's CBOM lists no
  // assets, so it shows the honest empty state with 13 endpoint services. The legacy rule-check subgraph assertions moved to the unchanged
  // legacy route, which Advanced still renders.
  await pg.click('#ot-tab-crypto'); await pg.waitFor(`document.querySelector('#otc-empty')`, 15000, 'crypto empty state');
  const cryptoPanel = await txt(pg, '#ot-tabpanel');
  check('REQ-06 crypto (UIP-06) shows the honest empty Demo: no assets, 13 endpoint services, never "no cryptography"', /lists no cryptographic assets/.test(cryptoPanel) && /13 endpoint services/.test(cryptoPanel) && !/no cryptography/i.test(cryptoPanel.replaceAll('does not show that no cryptography is used', '')), cryptoPanel.slice(0, 90).replace(/\n/g, ' '));
  const legacyCrypto = await pg.eval(`fetch('/api/view/crypto?generation=1', { credentials: 'same-origin' }).then((r) => r.json())`);
  const nodesCount = legacyCrypto.nodes.length;
  check('REQ-06 the legacy crypto view is unchanged: bounded check subgraph (7 records), CBOM shows 0 assets', nodesCount === 7 && legacyCrypto.crypto_asset_total === 0 && legacyCrypto.services.length === 13, `nodes=${nodesCount}`);
  await pg.click('#ot-tab-bom'); await sleep(1200);
  const bomSt = await state(pg);
  check('REQ-06 BOM: shared_scan_paths are scope relations, not record edges', bomSt.views.bom.scope_links.length >= 1 && bomSt.views.bom.scope_links.every((l) => l.kind === 'shared_scan_paths') && !bomSt.views.bom.edges.some((e) => e.type === 'shared_scan_paths'));
  check('REQ-06 BOM foot states scope vs record relations', /Scope relations/.test(await txt(pg, '.ot-foot')) && /do not connect records/.test(await txt(pg, '.ot-foot')));
  // contexts: REQ-05
  await pg.click('#ot-tab-contexts'); await sleep(900);
  const ctxCount = await count(pg, '[data-ctx-kind=file]');   // UIP-04: file cards/rows carry data-ctx-kind=file and the new ctx: ids
  check('REQ-05 repository contexts list 13 files', ctxCount === 13, `files=${ctxCount}`);
  check('REQ-05 unlocated group and overlap counts are shown', /without a (recorded source )?location|no (captured|recorded) source-file location/.test(await txt(pg, '.ot-explorer')));
  const defaultPres = (await state(pg)).workbench.perTab.contexts.presentation;
  check(`UI-F09 contexts default is ${narrow ? 'List' : 'Graph'} at ${label}`, defaultPres === (narrow ? 'list' : 'graph'), defaultPres);
  await shotFrame(shots('07_contexts'));
  const ampId = await pg.eval(`[...document.querySelectorAll('[data-ctx-kind=file]')].find(e=>/docker\\/tensorrt\\/requirements-amd64\\.txt/.test(e.getAttribute('aria-label')||e.innerText||e.textContent))?.dataset.ctx`);
  await pg.click(`[data-ctx="${ampId}"]`); await sleep(400);
  check('REQ-05 selecting a file shows only context content (no package advisory boilerplate)', !/advisory match|Depends on|Used by/i.test(await txt(pg, '.ot-inspector')) && /13 captured|13/.test(await txt(pg, '.ot-inspector')));
  const callsB = pg.log.requests.length;
  await pg.click('[data-action=drill]'); await sleep(1500);
  const dd = await state(pg);
  check('PAR-06 file drill-down enters Dependencies with that file as context', dd.workbench.tab === 'dependencies' && dd.workbench.perTab.dependencies.context === 'docker/tensorrt/requirements-amd64.txt' && (await pg.eval(`document.getElementById('ot5-context').selectedOptions[0].dataset.path`)) === 'docker/tensorrt/requirements-amd64.txt');
  await pg.click('#ot-tab-crypto'); await sleep(800);
  check('PAR-06 ordinary tab switching does not carry the file filter to other domains', !(await exists(pg, '#ot-context')) && !pg.log.requests.slice(callsB).some((r) => /view\/(crypto|ai|bom)\?.*context=/.test(r.url)));
  await pg.click('#ot-tab-dependencies'); await sleep(800);
  check('PAR-06 returning to Dependencies keeps the drilled-in context', (await pg.eval(`document.getElementById('ot5-context').selectedOptions[0].dataset.path`)) === 'docker/tensorrt/requirements-amd64.txt');
  await pickCtx('web/package-lock.json'); await sleep(900);   // UIP-05: the normal view's chooser

  // --- check cards (relocated to Evidence by UIP-02) route to the matching tab
  await pg.click('[data-nav=evidence]'); await sleep(500);
  check('REQ-08 three inventory-check cards, separate from the advisory list (now in Evidence)', (await count(pg, '#ot-findings .ot-finding')) === 3 && !(await exists(pg, '#ot-workbench .ot-advisories')));
  check('REQ-08 no "safe" state is claimed for absence', !(/\bsafe\b/i.test(await txt(pg, '#ot-findings'))));
  await pg.click('[data-check="p8-md5-call-represented-in-cdxgen-cbom"]'); await sleep(1200);
  check('REQ-06 "Inspect evidence" opens the matching check in its tab', (await state(pg)).workbench.tab === 'crypto' && /Sources & coverage/i.test(await txt(pg, '.ot-inspector')));
  await pg.click('[data-nav=evidence]'); await sleep(500);
  await pg.click('[data-check="p7-model-declared-in-aibom"]'); await sleep(1200);
  check('REQ-06 AI model check selected in AI models', (await state(pg)).workbench.tab === 'ai' && /yolov6n|model/i.test(await txt(pg, '.ot-explorer')));
  await shotFrame(shots('08_ai_check'));

  // --- advisory dialog
  await pg.click('#ot-tab-dependencies'); await sleep(900);
  await pg.click('[data-action=read-advisory]'); await settle(pg, `document.getElementById('ot-dialog').open && document.getElementById('ot-dialog-content').innerText.length>20`);
  check('REQ-08 advisory dialog states a match is not exploitability', /not application reachability, exploitability/.test(await txt(pg, '#ot-dialog-content')));
  await pg.key('Escape'); await sleep(300);
  check('REQ-12 Escape closes the advisory dialog and returns focus to its opener', !(await pg.eval(`document.getElementById('ot-dialog').open`)) && (await pg.eval(`document.activeElement?.dataset?.action`)) === 'read-advisory');

  // --- REQ-12 info buttons + keyboard
  await pg.eval(`document.querySelector('#ot-workbench .ot-info').focus()`); await pg.key('Enter'); await sleep(300);
  const infoOpen = await pg.eval(`document.getElementById('ot-dialog').open`);
  await pg.key('Escape'); await sleep(300);
  check('REQ-12 info button opens with Enter, Escape closes and focus returns', infoOpen && (await pg.eval(`document.activeElement?.classList.contains('ot-info')`)));
  await pg.eval(`document.getElementById('ot-tab-dependencies').focus()`); await pg.key('ArrowRight'); await sleep(900);
  check('REQ-12 arrow keys move between tabs', (await state(pg)).workbench.tab === 'crypto');
  await pg.click('#ot-tab-dependencies'); await sleep(600);
  await pg.eval(`document.querySelector('[data-dep-node]:not([data-role=focus])').focus()`); await pg.key('Enter'); await sleep(700);
  check('REQ-12 package nodes are keyboard operable', (await state(pg)).workbench.perTab.dependencies.selection !== (await state(pg)).workbench.perTab.dependencies.focus);

  // --- REQ-11 assistant: no network
  const callsA = pg.log.requests.length;
  await pg.click('#ot-assistant-launch'); await sleep(300);
  check('REQ-11 assistant is labeled as an offline evidence guide', /OFFLINE EVIDENCE GUIDE/i.test(await txt(pg, '#ot-assistant')) && /does not call a model or the network/.test(await txt(pg, '#ot-assistant')));
  await pg.click('[data-action=a-ask][data-q=limits]'); await sleep(300);
  check('REQ-11 frozen answer carries citations', /Citations:/.test(await txt(pg, '#ot-assistant')));
  await pg.click('[data-action=a-pin]'); await pg.click('[data-action=a-min]'); await sleep(200);
  const ast = (await state(pg)).assistant;
  check('REQ-11 pin and minimize state', ast.pinned && ast.minimized);
  await pg.click('[data-action=a-min]'); await pg.click('[data-action=a-pin]');
  check('REQ-11 assistant makes no network request', pg.log.requests.length === callsA, `new=${pg.log.requests.length - callsA}`);
  await pg.screenshot(shots('09_assistant'));
  await pg.click('[data-action=a-close]'); await sleep(200);

  // --- Evidence page: REQ-07
  await pg.click('[data-nav=evidence]'); await sleep(900);
  check('REQ-07 three inventory cards plus labeled supporting-evidence rows', (await count(pg, '.ot-arts .ot-small-card')) === 3 && (await count(pg, '.ot-support-row')) >= 1 && /Derived by OpenTrace/i.test(await txt(pg, '.ot-support')));
  await pg.screenshot(shots('10_evidence'));
  const dl = await pg.eval(`(async()=>{const out={};const list=await (await fetch('/api/artifacts')).json();for(const a of list.artifacts){const r=await fetch('/api/artifacts/'+a.name+'?disposition=attachment');const b=await r.arrayBuffer();const h=[...new Uint8Array(await crypto.subtle.digest('SHA-256',b))].map(x=>x.toString(16).padStart(2,'0')).join('');out[a.name]={h,rec:a.sha256,hdr:r.headers.get('X-Artifact-Sha256'),size:b.byteLength,recsize:a.size,kind:a.kind,disp:r.headers.get('Content-Disposition')}}return out})()`);
  const sums = Object.values(dl).every((x) => x.h === x.rec && x.hdr === x.rec && x.size === x.recsize);
  check('REQ-07 downloaded bytes hash equals the I4D record and X-Artifact-Sha256', sums, JSON.stringify(Object.fromEntries(Object.entries(dl).map(([k, v]) => [k, v.h.slice(0, 12)]))));
  check('REQ-07 SBOM digest equals the pinned Frigate digest', dl['syft-source-dir.cdx.json']?.h === PINNED_SBOM);
  check('REQ-07 attachment disposition on download', /attachment/.test(dl['syft-source-dir.cdx.json']?.disp || ''));
  await pg.click('[data-action=preview][data-name="cdxgen-cbom.cdx.json"]'); await settle(pg, `document.getElementById('ot-dialog-content').innerText.toLowerCase().includes('sha256')`);
  const pvText = await txt(pg, '#ot-dialog-content');
  check('REQ-07 preview recomputes sha256 and shows it matches the session record', /matches the session record ✓/i.test(pvText) && /original artifact/i.test(pvText), pvText.slice(0, 120).replace(/\n/g, ' '));
  await pg.click('[data-pv=raw]'); await sleep(200);
  const rawOk = (await txt(pg, '#ot-raw')).includes('"bomFormat"');
  await pg.click('[data-pv=search]'); await sleep(150); await pg.type('#ot-prev-q', 'services'); await sleep(300);
  check('REQ-07 preview offers overview, formatted JSON and search views of the artifact', rawOk && /matches? in the whole artifact/.test(await txt(pg, '#ot-pv-count')) && (await count(pg, '.ot-hit')) > 0);
  await pg.screenshot(shots('11_preview'));
  await pg.click('#ot-dialog-close'); await sleep(300);
  check('REQ-12 preview dialog closes and returns focus to its opener', !(await pg.eval(`document.getElementById('ot-dialog').open`)) && (await pg.eval(`document.activeElement?.dataset?.action`)) === 'preview');
  await pg.click('[data-action=preview][data-name="bombridge-result.json"]'); await settle(pg, `document.getElementById('ot-dialog-content').innerText.toLowerCase().includes('sha256')`);
  check('REQ-07 derived output is labeled derived in preview', /derived output/i.test(await txt(pg, '#ot-dialog-content')));
  await pg.click('#ot-dialog-close'); await sleep(300);
  const recIds = await pg.eval(`[...document.querySelectorAll('.ot-records .group-record strong')].map(s=>s.innerText).sort()`);
  const bom = (await state(pg)).views.bom;
  const used = [...new Set(bom.checks.filter((c) => c.rule_id).flatMap((c) => [...c.used_evidence, ...c.excluded_evidence].map((e) => e.evidence_id)))].sort();
  check('REQ-08 supporting records equal the records used by the displayed checks', JSON.stringify(recIds) === JSON.stringify(used) && recIds.length > 0, `${recIds.length} records`);
  await pg.click('[data-action=record]'); await settle(pg, `document.getElementById('ot-dialog').open`); await pg.key('Escape'); await sleep(200);

  // --- Second tab, then End session: REQ-09 / REQ-10
  const pg2 = await newPage(browser, { width, height, mobile: narrow }); await pg2.goto(base);
  const second = await pg2.eval(`fetch('/api/artifacts').then(r=>r.status)`);
  check('REQ-09 a second tab shares the cookie before End session (200)', second === 200);
  // late-response test: delay view responses, then End
  await pg.click('[data-nav=workbench]'); await sleep(400);
  await pg.eval(`(()=>{const o=window.fetch.bind(window);window.fetch=(u,i)=>(String(u).includes('/api/view/dependencies')||String(u).includes('/api/workbench/v1/dependenc'))?o(u,i).then(r=>new Promise(res=>setTimeout(()=>res(r),1500))):o(u,i)})()`);
  await pg.eval(`document.querySelector('[data-action=dep-page][data-dir="1"]')?.click()`); await sleep(100);
  const epochBefore = (await state(pg)).epoch;
  await pg.click('#ot-top-end').catch(async () => pg.eval(`document.getElementById('ot-end-session')?.click()`));
  if (narrow) { await pg.eval(`document.querySelector('[data-nav=analyze]').click()`); await sleep(200); await pg.eval(`document.getElementById('ot-end-session').click()`); }
  await settle(pg, `window.__otStore.get().ended`, 20000);
  await sleep(2200); // the delayed, previously valid response arrives now
  const post = await state(pg);
  check('REQ-10 a late response is discarded after End session', post.analysis === null && Object.keys(post.views).length === 0 && post.session.status === 'none' && post.destination === 'analyze' && !(await exists(pg, '[data-dep-node]')));
  check('REQ-09 End session: UI cleared, Workbench and Evidence disabled', (await pg.eval(`document.querySelector('[data-nav=workbench]').disabled && document.querySelector('[data-nav=evidence]').disabled`)) && /Session ended/.test(await txt(pg, '#ot-ended-note')) && post.ended === 'deleted_verified', post.ended);
  check('REQ-09 server reports deleted_verified and the note says removal was verified', /removal was verified/.test(await txt(pg, '#ot-ended-note')));
  const denied = await pg2.eval(`Promise.all(['/api/artifacts','/api/view/contexts','/api/view/dependencies','/api/artifacts/syft-source-dir.cdx.json'].map(p=>fetch(p).then(async r=>[r.status,await r.text()])))`);
  check('REQ-09 a second tab using the old cookie is denied uniformly', denied.every(([s, b]) => s === 403 && /access denied/.test(b)) && new Set(denied.map((d) => d[1])).size === 1, JSON.stringify(denied.map((d) => d[0])));
  check('REQ-10 epoch advanced on End session', post.epoch > epochBefore);
  const after = await storage(pg); storageReport.push({ vp: label, phase: 'after End session', ...after });
  check('REQ-10 storage after End session: only oecl.ui.* keys, no session/idb/cache', after.session.length === 0 && after.idb.length === 0 && after.caches.length === 0 && after.local.every((k) => k.startsWith('oecl.ui.')), JSON.stringify(after));
  await pg.screenshot(shots('12_after_end'));
  // storage during the active session
  await pg2.close();

  // second analysis in the same page + mid-session storage snapshot
  await pg.click('#ot-demo'); await settle(pg, `document.querySelector('#ot-tabpanel [data-ctx]')`, 30000);
  check('UIP-02 a new Demo after End session opens on Repository contexts', (await state(pg)).workbench.tab === 'contexts');
  const mid = await storage(pg); storageReport.push({ vp: label, phase: 'active session (workbench open)', ...mid });
  check('REQ-10 storage while active: only oecl.ui.* keys', mid.session.length === 0 && mid.idb.length === 0 && mid.caches.length === 0 && mid.local.every((k) => k.startsWith('oecl.ui.')), JSON.stringify(mid));
  const s3 = await state(pg);
  check('REQ-10 a new analysis starts from a fresh generation and clean per-tab selections', s3.analysis.generation === 1 && s3.workbench.perTab.crypto.selection === null && s3.workbench.perTab.dependencies.history.length === 0);

  // --- request log / console / exceptions
  const reqs = pg.log.requests;
  const offOrigin = reqs.filter((r) => !r.url.startsWith(ORIGIN) && !r.url.startsWith('data:') && !r.url.startsWith('blob:') && r.url !== 'about:blank');
  check('NET every request is same-origin loopback (no CDN/provider/network)', offOrigin.length === 0, offOrigin.map((r) => r.url).join(' '));
  const consoleBad = pg.log.console.filter((c) => ['error', 'warning'].includes(c.type));
  check('CONSOLE clean (no errors or warnings)', consoleBad.length === 0, JSON.stringify(consoleBad.slice(0, 3)));
  check('CONSOLE no uncaught exceptions', pg.log.exceptions.length === 0, pg.log.exceptions.join(' '));
  const failed = pg.log.failed.filter((f) => !f.canceled);
  check('NET no failed requests', failed.length === 0, JSON.stringify(failed.slice(0, 3)));
  const unauth = pg.log.responses.filter((r) => r.url.startsWith(ORIGIN) && r.status >= 400);
  check('NET no unexpected 4xx/5xx responses during the happy path', unauth.length === 0, unauth.map((r) => r.status + ' ' + r.url.replace(ORIGIN, '')).join(' '));
  const paths = [...new Set(reqs.filter((r) => r.url.startsWith(ORIGIN)).map((r) => new URL(r.url).pathname.replace(/\/components\/.*/, '').replace(/^\/api\/artifacts\/.+/, '/api/artifacts/{name}').replace(/^\/api\/view\/advisory\/.+/, '/api/view/advisory/{key}')))].sort();
  storageReport.push({ vp: label, phase: 'request paths', paths, total: reqs.filter((r) => r.url.startsWith(ORIGIN)).length });
  const csp = pg.log.responses.find((r) => r.url === base);
  storageReport.push({ vp: label, phase: 'index headers', csp: csp?.headers['content-security-policy'] || csp?.headers['Content-Security-Policy'], cache: csp?.headers['cache-control'] });
  await pg.close();
}

let exit = 0;
try {
  await run(1366, 900, '1366');
  await run(390, 844, '390');
} catch (e) { console.error('HARNESS ERROR', e); results.push({ vp: currentVp, id: 'HARNESS', ok: false, detail: String(e.stack || e) }); exit = 1; }
finally { await close(); svc.kill('SIGTERM'); await sleep(300); rmSync(root, { recursive: true, force: true }); }

const failed = results.filter((r) => !r.ok);
const chromeVersion = 'see report header';
const lines = [`# I4E browser checks`, '', `Generated by \`tests/ui/browser/run_checks.mjs\`. Service: \`python -m opentrace_core.app\` on a loopback ephemeral port (${ORIGIN}). Browser: Google Chrome headless via DevTools Protocol (\`tests/ui/browser/cdp.mjs\`).`, '', `**${results.length - failed.length} passed, ${failed.length} failed** across ${results.length} checks (1366 px and 390 px).`, '', '| Viewport | Check | Result | Detail |', '|---|---|---|---|', ...results.map((r) => `| ${r.vp} | ${r.id} | ${r.ok ? 'PASS' : '**FAIL**'} | ${r.detail.replace(/\|/g, '\\|').replace(/\n/g, ' ').slice(0, 220)} |`), '', '## Request and storage evidence', '', '```json', JSON.stringify(storageReport, null, 2), '```'];
writeFileSync(`${OUT}/REPORT.md`, lines.join('\n') + '\n');
writeFileSync(`${OUT}/results.json`, JSON.stringify({ results, storageReport }, null, 2));
console.log(`\n${results.length - failed.length}/${results.length} passed; report: ${OUT}/REPORT.md`);
process.exit(failed.length || exit ? 1 : 0);
