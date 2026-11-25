// Desktop integration smoke for browser question -> authorized API -> fixture broker -> validated citation.
// Captured DemoSource only; fixture broker performs no provider/network work.
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { dirname, resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { CHROME, connect, newPage } from './cdp.mjs';

const out = resolve(process.env.OT_ASSISTANT_OUT || '/tmp/ot-assistant-browser-results');
mkdirSync(out, { recursive: true });
const results = [];
const check = (id, ok, details = null) => { results.push({ id, ok: !!ok, details }); console.log(`${ok ? 'PASS' : 'FAIL'} ${id}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pids = process.env.OT_PIDS_FILE;
const recordPid = (pid) => pids && Number.isInteger(pid) && appendFileSync(pids, `${pid}\n`);
const here = dirname(fileURLToPath(import.meta.url));
const python = process.env.PYTHON_BIN || 'python3';
const serviceRoot = join(out, `service-state-${Date.now()}`);
const brokerCountFile = join(out, `broker-count-${Date.now()}.txt`);
let service; let chrome; let page; let serviceLog = ''; let serviceSpawnError = null;
let serviceUrl = null; let blocked = []; const cleanupErrors = [];
const waitForChildClose = (child, timeoutMs = 3000) => new Promise((resolveClose) => {
  if (child.exitCode !== null || child.signalCode !== null || !Number.isInteger(child.pid)) return resolveClose(true);
  let done = false;
  const finish = (closed) => { if (done) return; done = true; clearTimeout(timer); resolveClose(closed); };
  const timer = setTimeout(() => finish(false), timeoutMs);
  child.once('close', () => finish(true));
  child.once('error', () => { if (!Number.isInteger(child.pid)) finish(true); });
});
function safeDiagnostic(error) {
  const exceptionClass = typeof error?.name === 'string' && /^[A-Za-z][A-Za-z0-9]*$/.test(error.name) ? error.name : 'Error';
  const repoRoot = resolve(here, '../../..');
  const sourceLocations = String(error?.stack || '').split('\n').map((line) => {
    const match = line.match(/^\s*at (?:(.*?) \()?((?:file:\/\/)?[^()\s]+\.(?:mjs|js|py)):(\d+):(\d+)\)?$/);
    if (!match) return null;
    const absolute = resolve(match[2].replace(/^file:\/\//, ''));
    if (!absolute.startsWith(`${repoRoot}/`)) return null;
    const fn = (match[1] || 'anonymous').replace(/[^A-Za-z0-9_.$<> -]/g, '').slice(0, 80);
    return { source: absolute.slice(repoRoot.length + 1), function: fn || 'anonymous', line: Number(match[3]) };
  }).filter(Boolean);
  return { exceptionClass, sourceLocations };
}
function processAlive(pid) {
  if (!Number.isInteger(pid)) return false;
  try { process.kill(pid, 0); return true; } catch (error) { return error.code !== 'ESRCH'; }
}
async function stopOwnedChild(child, firstSignal = 'SIGTERM') {
  if (!child) return true;
  if (child.exitCode !== null || child.signalCode !== null || !Number.isInteger(child.pid)) return true;
  try { child.kill(firstSignal); } catch {}
  let closed = await waitForChildClose(child, 3000);
  if (!closed) {
    try { process.kill(child.pid, 'SIGKILL'); } catch {}
    closed = await waitForChildClose(child, 3000);
  }
  return closed || !processAlive(child.pid);
}
async function launchAssistantChrome() {
  const profile = mkdtempSync(join(tmpdir(), 'ot-assistant-chrome-'));
  const args = [`--user-data-dir=${profile}`, `--crash-dumps-dir=${join(profile, 'Crashpad')}`,
    '--disable-breakpad', '--disable-crash-reporter', '--no-first-run', '--no-default-browser-check',
    '--remote-debugging-port=0', '--window-size=1366,900', '--window-position=40,40', 'about:blank'];
  const proc = spawn(CHROME, args, { env: { PATH: process.env.PATH || '' }, stdio: ['ignore', 'ignore', 'pipe'] });
  recordPid(proc.pid);
  let stderr = '';
  proc.stderr.on('data', (chunk) => { stderr = (stderr + chunk.toString()).slice(-4000); });
  try {
    const wsUrl = await new Promise((resolveWs, rejectWs) => {
      let settled = false;
      const finish = (fn, value) => { if (settled) return; settled = true; clearTimeout(timer); fn(value); };
      const timer = setTimeout(() => finish(rejectWs, new Error('Chrome startup timed out')), 20000);
      proc.once('error', (error) => finish(rejectWs, error));
      proc.once('exit', (code, signal) => finish(rejectWs, new Error(`Chrome exited (${code ?? signal})`)));
      proc.stderr.on('data', (chunk) => {
        const match = chunk.toString().match(/DevTools listening on (ws:\/\/\S+)/);
        if (match) finish(resolveWs, match[1]);
      });
    });
    const browser = await connect(wsUrl);
    return { browser, proc, profile, flags: args.map((arg) => arg.replace(profile, '<fresh-profile-dir>')),
      async close() {
        try { browser.close(); } catch {}
        const closed = await stopOwnedChild(proc, 'SIGKILL');
        if (!closed) throw new Error(`Chrome process ${proc.pid} did not exit; profile retained at ${profile}`);
        rmSync(profile, { recursive: true, force: true });
      } };
  } catch (error) {
    const closed = await stopOwnedChild(proc, 'SIGKILL');
    if (!closed) throw new Error(`${error.message}; Chrome pid ${proc.pid} did not exit; profile retained at ${profile}; stderr: ${stderr || '(empty)'}`);
    rmSync(profile, { recursive: true, force: true });
    throw new Error(`${error.message}; Chrome stderr: ${stderr || '(empty)'}`);
  }
}
try {
  service = spawn(python, [join(here, 'assistant_service.py')], {
    env: { PATH: process.env.PATH || '', PYTHONPATH: `${resolve(here, '../../..')}/src/core:${resolve(here, '../../..')}/src/agents/investigator:${resolve(here, '../../..')}`,
      OT_ASSISTANT_FIXTURE_STATE: serviceRoot, OT_ASSISTANT_BROKER_COUNT_FILE: brokerCountFile }, stdio: ['ignore', 'pipe', 'pipe'] });
  recordPid(service.pid);
  service.on('error', (error) => { serviceSpawnError = error; });
  service.stdout.on('data', (chunk) => { serviceLog += chunk.toString(); });
  service.stderr.on('data', (chunk) => { serviceLog += chunk.toString(); });
  serviceUrl = await new Promise((resolveUrl, reject) => {
    const timer = setTimeout(() => reject(new Error(`fixture service startup timeout: ${serviceLog.slice(-500)}`)), 20000);
    const poll = () => { const match = serviceLog.match(/http:\/\/127\.0\.0\.1:\d+\//); if (match) { clearTimeout(timer); resolveUrl(match[0]); }
      else if (serviceSpawnError) { clearTimeout(timer); reject(new Error(`fixture service spawn failed: ${serviceSpawnError.message}`)); }
      else if (service.exitCode !== null || service.signalCode !== null) { clearTimeout(timer); reject(new Error(`fixture service exited ${service.exitCode || service.signalCode}: ${serviceLog.slice(-500)}`)); }
      else setTimeout(poll, 50); }; poll();
  });
  chrome = await launchAssistantChrome();
  page = await newPage(chrome.browser, { width: 1366, height: 900, mobile: false });
  await page.send('Emulation.clearDeviceMetricsOverride');
  await page.send('Page.bringToFront');
  await page.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  chrome.browser.on((message) => {
    if (message.sessionId !== page.sessionId || message.method !== 'Fetch.requestPaused') return;
    const request = message.params; const url = request.request.url;
    if (/^(http:\/\/(127\.0\.0\.1|localhost):\d+\/|about:|data:|blob:)/.test(url)) {
      page.send('Fetch.continueRequest', { requestId: request.requestId }).catch(() => {});
    } else {
      blocked.push(url);
      page.send('Fetch.failRequest', { requestId: request.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
    }
  });
  await page.goto(serviceUrl);
  await page.waitFor(`document.querySelector('#ot-demo')`, 15000, 'captured demo control');
  await page.click('#ot-demo');
  await page.waitFor(`window.__otStore?.get().analysis && !window.__otStore.get().busy`, 30000, 'captured analysis ready');
  check('captured demo analysis is available', !!(await page.eval('window.__otStore.get().analysis')));

  await page.click('#ot-tab-bom');
  await page.waitFor(`document.querySelector('#ot-tabpanel [data-bom-cy="inline"]')`, 20000, 'BOM graph host');
  await page.waitFor(`(()=>{const h=document.querySelector('[data-bom-cy="inline"]');return h?._cy && !h._cy.destroyed()})()`, 20000, 'BOM graph renderer');
  const before = await page.eval(`(()=>{const h=document.querySelector('[data-bom-cy="inline"]'),c=h._cy;window.__assistantGraphRef=c;return {nodes:c.nodes().length,edges:c.edges().length,zoom:c.zoom(),pan:c.pan(),selected:c.$(':selected').map(n=>n.id()),renderer:!!c.renderer().destroyed}})()`);
  check('BOM tab graph is populated and renderer is live', before.nodes > 0 && before.renderer === false, { nodes: before.nodes, edges: before.edges, rendererLive: before.renderer === false });

  await page.click('#ot-assistant-launch');
  await page.waitFor(`document.querySelector('#ot-assistant-question')`, 10000, 'assistant composer');
  await page.type('#ot-assistant-question', 'What does this captured repository analysis establish?');
  await page.click('#ot-assistant-form button[type="submit"]');
  await page.waitFor(`document.querySelector('.ot-assistant-turn .ot-assistant-claim') && !window.__otStore.get().assistant.pending`, 30000, 'fixture answer');
  const wholeAnswer = await page.eval(`(()=>{const t=window.__otStore.get().assistant.turns[0];return {status:t?.response?.answer?.answer_status,subject:t?.response?.subject?.kind,claimCount:t?.response?.answer?.claims?.length||0}})()`);
  check('whole-analysis question returns a validated unknown answer bound to the analysis subject', wholeAnswer.status === 'unknown' && wholeAnswer.subject === 'analysis' && wholeAnswer.claimCount > 0, wholeAnswer);
  const citeCount = await page.eval(`document.querySelectorAll('.ot-assistant-turn .ot-assistant-citation').length`);
  check('claim and next investigation render turn-bound evidence citations', citeCount >= 2, { citationCount: citeCount });
  const firstContext = await page.eval(`document.querySelector('.ot-assistant-turn .ot-assistant-citation')?.dataset.context || ''`);
  await page.click('.ot-assistant-turn .ot-assistant-citation');
  await page.waitFor(`document.querySelector('#ot-dialog[open]')`, 10000, 'authorized citation dialog');
  const citationResolved = await page.eval(`!!document.querySelector('#ot-dialog pre.source-excerpt')?.textContent?.trim()`);
  check('citation opens resolvable authorized evidence in the application dialog', citationResolved, null);
  await page.key('Escape');

  // Selection changes do not retarget the frozen thread until explicit adoption.
  await page.click('#ot-tab-ai');
  await page.waitFor(`document.querySelector('[data-otai-select]')`, 15000, 'captured model selection');
  await page.click('[data-otai-select]');
  await page.waitFor(`window.__otStore.get().workbench.perTab.ai.sel`, 5000, 'model selected');
  await page.click('#ot-assistant-question');
  await page.type('#ot-assistant-question', 'Continue using the original conversation subject.');
  await page.click('#ot-assistant-form button[type="submit"]');
  await page.waitFor(`document.querySelectorAll('.ot-assistant-turn').length === 2 && !window.__otStore.get().assistant.pending`, 30000, 'frozen-subject follow-up');
  const followupContext = await page.eval(`document.querySelectorAll('.ot-assistant-turn')[1]?.querySelector('.ot-assistant-citation')?.dataset.context || ''`);
  check('follow-up retains original whole-analysis context after page selection changes', !!firstContext && followupContext === firstContext, null);

  await page.click('.ot-assistant-adopt input');
  await page.click('#ot-assistant-question');
  await page.type('#ot-assistant-question', 'Use the explicitly adopted model selection.');
  await page.click('#ot-assistant-form button[type="submit"]');
  await page.waitFor(`document.querySelectorAll('.ot-assistant-turn').length === 3 && !window.__otStore.get().assistant.pending`, 30000, 'adopted-subject answer');
  const adopted = await page.eval(`({context:document.querySelectorAll('.ot-assistant-turn')[2]?.querySelector('.ot-assistant-citation')?.dataset.context || '', subject:window.__otStore.get().assistant.subject?.kind, checked:!!document.querySelector('.ot-assistant-adopt input')?.checked})`);
  check('explicit adoption creates a new model-subject context and clears one-turn adoption', adopted.subject === 'model' && adopted.context !== firstContext && !adopted.checked, { adoptedSubject: adopted.subject, contextChanged: adopted.context !== firstContext, adoptionCleared: !adopted.checked });

  await page.click('#ot-assistant-question');
  await page.type('#ot-assistant-question', 'Deterministic cancellation probe');
  await page.click('#ot-assistant-form button[type="submit"]');
  await page.waitFor(`document.querySelector('[data-action="a-cancel"]')`, 5000, 'cancellation control');
  await page.click('[data-action="a-cancel"]');
  await page.waitFor(`!window.__otStore.get().assistant.pending`, 10000, 'cancelled response retired');
  const afterCancel = await page.eval(`({turns:window.__otStore.get().assistant.turns.length, error:!!window.__otStore.get().assistant.error})`);
  check('cancellation retires the late fixture response without appending a turn', afterCancel.turns === 3 && afterCancel.error, afterCancel);

  // A fresh browser context gets a distinct cookie/session and empty conversation history.
  const { browserContextId } = await chrome.browser.send('Target.createBrowserContext', { disposeOnDetach: true });
  const { targetId } = await chrome.browser.send('Target.createTarget', { url: 'about:blank', browserContextId });
  const { sessionId } = await chrome.browser.send('Target.attachToTarget', { targetId, flatten: true });
  const isolatedSend = (method, params = {}) => chrome.browser.send(method, params, sessionId);
  await isolatedSend('Page.enable'); await isolatedSend('Runtime.enable'); await isolatedSend('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  chrome.browser.on((message) => {
    if (message.sessionId !== sessionId || message.method !== 'Fetch.requestPaused') return;
    const request = message.params; const url = request.request.url;
    if (/^(http:\/\/(127\.0\.0\.1|localhost):\d+\/|about:|data:|blob:)/.test(url)) isolatedSend('Fetch.continueRequest', { requestId: request.requestId }).catch(() => {});
    else { blocked.push(url); isolatedSend('Fetch.failRequest', { requestId: request.requestId, errorReason: 'BlockedByClient' }).catch(() => {}); }
  });
  await isolatedSend('Page.navigate', { url: serviceUrl });
  const isolatedLoadDeadline = Date.now() + 10000;
  while (Date.now() < isolatedLoadDeadline) {
    const loaded = await isolatedSend('Runtime.evaluate', { expression: `!!document.querySelector('#ot-demo')`, returnByValue: true });
    if (loaded.result.value) break;
    await sleep(100);
  }
  await isolatedSend('Runtime.evaluate', { expression: `document.querySelector('#ot-demo')?.click()` });
  const isolatedReady = async () => {
    const result = await isolatedSend('Runtime.evaluate', { expression: `!!(window.__otStore?.get().session?.generation && window.__otStore.get().analysis && !window.__otStore.get().busy)`, returnByValue: true });
    return !!result.result.value;
  };
  const isolatedDeadline = Date.now() + 30000;
  while (!(await isolatedReady()) && Date.now() < isolatedDeadline) await sleep(100);
  const isolatedResult = await isolatedSend('Runtime.evaluate', { expression: `({turns:window.__otStore.get().assistant.turns.length})`, returnByValue: true });
  const isolatedState = isolatedResult.result.value;
  const cookieUrl = `${serviceUrl}api/session`;
  const originalCookies = await page.send('Network.getCookies', { urls: [cookieUrl] });
  const isolatedCookies = await isolatedSend('Network.getCookies', { urls: [cookieUrl] });
  const originalSessionCookie = originalCookies.cookies.find((cookie) => cookie.name === 'ot_session');
  const isolatedSessionCookie = isolatedCookies.cookies.find((cookie) => cookie.name === 'ot_session');
  const distinctSession = !!originalSessionCookie && !!isolatedSessionCookie && originalSessionCookie.value !== isolatedSessionCookie.value;
  check('isolated browser context has a distinct session cookie and no inherited conversation', distinctSession && isolatedState.turns === 0, { distinctSession, inheritedTurns: isolatedState.turns });
  await chrome.browser.send('Target.disposeBrowserContext', { browserContextId });

  await page.click('#ot-tab-bom');
  await page.waitFor(`document.querySelector('[data-bom-cy="inline"]')?._cy && !document.querySelector('[data-bom-cy="inline"]')._cy.destroyed()`, 15000, 'BOM graph restored');
  const repaintBaseline = await page.eval(`(()=>{const c=document.querySelector('[data-bom-cy="inline"]')._cy;window.__assistantGraphRef=c;return {nodes:c.nodes().length,edges:c.edges().length,zoom:c.zoom(),pan:c.pan()}})()`);
  await page.click('#ot-assistant-question');
  await page.type('#ot-assistant-question', 'Answer after returning to the graph view.');
  await page.click('#ot-assistant-form button[type="submit"]');
  await page.waitFor(`document.querySelectorAll('.ot-assistant-turn').length === 4 && !window.__otStore.get().assistant.pending`, 30000, 'answer after returning to graph');
  const afterAnswer = await page.eval(`(()=>{const h=document.querySelector('[data-bom-cy="inline"]'),c=h?._cy;return c?{same:c===window.__assistantGraphRef,renderer:!!c.renderer().destroyed,zoom:c.zoom(),pan:c.pan(),nodes:c.nodes().length,edges:c.edges().length}:null})()`);
  check('assistant answer repaint preserves the existing BOM graph instance and camera', !!afterAnswer && afterAnswer.same && afterAnswer.renderer === false && afterAnswer.nodes === repaintBaseline.nodes && afterAnswer.edges === repaintBaseline.edges && afterAnswer.zoom === repaintBaseline.zoom && JSON.stringify(afterAnswer.pan) === JSON.stringify(repaintBaseline.pan), { sameInstance: !!afterAnswer?.same, rendererLive: afterAnswer?.renderer === false, nodeCount: afterAnswer?.nodes, edgeCount: afterAnswer?.edges, cameraPreserved: !!afterAnswer && afterAnswer.zoom === repaintBaseline.zoom && JSON.stringify(afterAnswer.pan) === JSON.stringify(repaintBaseline.pan) });

  await page.click('#ot-theme');
  await sleep(250);
  const theme = await page.eval(`({theme:window.__otStore.get().theme,host:!!document.querySelector('[data-bom-cy="inline"]')?._cy,renderer:!!document.querySelector('[data-bom-cy="inline"]')?._cy?.renderer().destroyed})`);
  check('theme repaint keeps the active graph attached and rendered', theme.theme === 'dark' && theme.host && theme.renderer === false, { darkTheme: theme.theme === 'dark', graphAttached: theme.host, rendererLive: theme.renderer === false });

  for (const tab of ['ai', 'crypto', 'bom']) {
    await page.click(`#ot-tab-${tab}`);
    await sleep(300);
    const state = await page.eval(`(()=>{const h=document.querySelector('#ot-tabpanel [data-cy="${tab}"]')||document.querySelector('#ot-tabpanel [data-bom-cy="inline"]');return {selected:document.querySelector('#ot-tab-${tab}')?.getAttribute('aria-selected'),host:!!h,cy:!!h?._cy,alive:!!h?._cy&&!h._cy.destroyed(),renderer:!!h?._cy?.renderer().destroyed}})()`);
    check(`tab navigation ${tab} remains usable after assistant and theme repaints`, state.selected === 'true' && (!state.cy || state.alive), { selected: state.selected === 'true', graphAlive: !state.cy || state.alive, rendererLive: state.renderer === false });
  }

  await page.click('#ot-tab-bom'); await sleep(250);
  const hostRect = await page.eval(`(()=>{const h=document.querySelector('[data-bom-cy="inline"]'),r=h.getBoundingClientRect();return {x:r.x,y:r.y,w:r.width,h:r.height}})()`);
  const pan0 = await page.eval(`document.querySelector('[data-bom-cy="inline"]')._cy.pan()`);
  await page.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: hostRect.x + hostRect.w * 0.72, y: hostRect.y + hostRect.h * 0.72 });
  await page.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: hostRect.x + hostRect.w * 0.72, y: hostRect.y + hostRect.h * 0.72, button: 'left', clickCount: 1 });
  await page.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: hostRect.x + hostRect.w * 0.78, y: hostRect.y + hostRect.h * 0.76, button: 'left', buttons: 1 });
  await page.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: hostRect.x + hostRect.w * 0.78, y: hostRect.y + hostRect.h * 0.76, button: 'left', clickCount: 1 });
  await sleep(250);
  const pan1 = await page.eval(`document.querySelector('[data-bom-cy="inline"]')._cy.pan()`);
  check('graph pan drag works after assistant-triggered repaints', Math.abs(pan1.x - pan0.x) + Math.abs(pan1.y - pan0.y) > 0.1, { panChanged: Math.abs(pan1.x - pan0.x) + Math.abs(pan1.y - pan0.y) > 0.1 });
  check('browser issued no non-loopback request', blocked.length === 0, { blockedRequestCount: blocked.length });
} catch (error) {
  const diagnostic = safeDiagnostic(error);
  results.push({ id: 'harness completed', ok: false, ...diagnostic });
  console.error(JSON.stringify(diagnostic));
} finally {
  try {
    if (page) await page.close().catch((error) => cleanupErrors.push(`page: ${error?.name || 'Error'}`));
    if (chrome) {
      try { await chrome.close(); } catch (error) { cleanupErrors.push(`chrome: ${error?.name || 'Error'}`); }
    }
  } finally {
    let serviceClosed = !service || !!serviceSpawnError;
    if (service && !serviceSpawnError) serviceClosed = await stopOwnedChild(service, 'SIGTERM');
    if (!serviceClosed) cleanupErrors.push('fixture service did not exit; state retained');
    else {
      try { rmSync(serviceRoot, { recursive: true, force: true }); } catch (error) { cleanupErrors.push(`fixture state: ${error?.name || 'Error'}`); }
    }
    const brokerInvocations = (() => { try { return Number(readFileSync(brokerCountFile, 'utf8')); } catch { return 0; } })();
    writeFileSync(`${out}/assistant-browser-results.json`, JSON.stringify({ source: 'captured DemoSource', paidDispatches: 0,
      flags: chrome?.flags || [], results, cleanupErrors, browserExceptionCount: page?.log.exceptions.length || 0,
      browserFailedRequestCount: page?.log.failed.length || 0, blockedExternalRequestCount: blocked.length,
      brokerInvocations, broker: 'deterministic in-process fixture' }, null, 2));
  }
}
const failed = results.filter((item) => !item.ok);
console.log(`${results.length - failed.length}/${results.length} checks passed`);
process.exitCode = failed.length ? 1 : 0;
