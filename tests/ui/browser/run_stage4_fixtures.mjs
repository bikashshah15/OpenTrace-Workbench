// Stage 4 fixture adapter (test harness only). Serves the Workbench view-contract JSON in evidence/uip/fixtures/ to the REAL frontend by fulfilling
// the browser's requests from the Node side (CDP Fetch), so routing is pure and testable offline.
//
// WHAT THIS IS AND IS NOT: these fixtures are builder-defined payloads (tools/uip_fixtures/build.py; "synthetic" ones are not production projections).
// A check that uses this adapter proves that the REAL app.js/reducers/renderers handle a contract-valid payload. It does NOT show that the backend generated
// or validated the data and must never be cited as backend evidence. Every observation made through it is recorded with mode 'fixture-substituted'
// (or 'adapter-synthesized' for the two bodies below that the adapter builds itself).
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
export const FIXTURE_ROOT = join(REPO, 'evidence/uip/fixtures');
const ENVELOPE_DONOR = join(REPO, 'evidence/uip/visual/uip-04/fixtures/uip04-one-group/analysis.json');

// Loads a fixture directory and verifies every file against its MANIFEST sha256 (truthful identity: a modified fixture is refused).
export function loadFixture(name, root = FIXTURE_ROOT, select = {}) {
  const dir = join(root, name);
  const manifest = JSON.parse(readFileSync(join(dir, 'MANIFEST.json'), 'utf8'));
  const files = {};
  for (const f of manifest.files) {
    const bytes = readFileSync(join(dir, f.path));
    const sha = createHash('sha256').update(bytes).digest('hex');
    if (sha !== f.sha256) throw new Error(`fixture ${name}/${f.path}: sha256 ${sha} != manifest ${f.sha256}`);
    files[f.path] = JSON.parse(bytes.toString('utf8'));
  }
  return { name, dir, manifest, files, select, builderSha256: manifest.builder?.sha256 || null, served: new Set() };
}

const bindingOf = (fx) => { for (const b of Object.values(fx.files)) if (b.binding) return b.binding; return null; };

// The analysis envelope the app reads from /api/analysis/demo. Identity fields are the FIXTURE's own binding (digest, commit, repository, ref, generation);
// the `summary` block is borrowed from the uip04-one-group envelope because the view fixtures carry none (it is not part of any fixture).
export function analysisEnvelope(fx, donorPath = ENVELOPE_DONOR) {
  const b = bindingOf(fx); if (!b) throw new Error('fixture has no binding: ' + fx.name);
  const donor = JSON.parse(readFileSync(donorPath, 'utf8'));
  return { generation: b.generation, ok: true, summary: donor.summary,
    identity: { analysis_digest: b.analysis_digest, basis: 'url_revision', commit: b.commit_sha, configuration: b.assessment?.configuration || 'config:fixture', mode: b.mode,
      name: b.repository.name, owner: b.repository.owner, repository: b.repository.canonical_url, requested: { kind: b.requested_ref.kind, origin: 'url_tree', text: b.requested_ref.text } } };
}

const err = (code, detail) => ({ schema: 'opentrace.workbench.error/1', error: code, message: 'Stage 4 fixture adapter: ' + detail, detail_code: 'stage4_unrouted' });
const num = (v, d) => (v === undefined || v === null || v === '' ? d : Number(v));
const bySchema = (fx, schema) => Object.entries(fx.files).filter(([, b]) => b.schema === schema);

// Route one request. Returns {kind: 'fixture'|'adapter'|'unrouted', status, body, file?}. Query matching is explicit; anything not matched is 'unrouted' (never guessed).
export function route(fx, rawUrl) {
  const u = new URL(rawUrl, 'http://x'); const p = u.pathname; const q = (k) => u.searchParams.get(k);
  const hit = (file) => { fx.served.add(file); return { kind: 'fixture', status: 200, body: fx.files[file], file }; };
  const miss = (why) => ({ kind: 'unrouted', status: 404, body: err('invalid_request', why + ' ' + p + u.search) });
  if (p === '/api/workbench/v1/contexts') {
    const group = q('group_id'), off = num(q('files_offset'), 0), lim = num(q('files_limit'), 20);
    for (const [f, b] of bySchema(fx, 'opentrace.workbench.contexts/1')) {
      if (!group && b.groups.length > 1 && b.selected_id === null) return hit(f);
      if (group && b.groups.length === 1 && b.groups[0].group_id === group && b.groups[0].files_offset === off) return hit(f);
    }
    return miss('no contexts fixture for group=' + group + ' offset=' + off + ' limit=' + lim);
  }
  if (p === '/api/workbench/v1/dependencies') {
    const filter = q('filter') || 'all', query = q('query') || '', off = num(q('offset'), 0), ctx = q('context_id');
    for (const [f, b] of bySchema(fx, 'opentrace.workbench.dependency_page/1'))
      if (b.filter === filter && b.query === query && b.page.offset === off && (!ctx || b.context.context_id === ctx)) return hit(f);
    return miss(`no dependency page fixture for filter=${filter} query=${query} offset=${off}`);
  }
  if (p === '/api/workbench/v1/dependency-contexts') {
    // ADAPTER-SYNTHESIZED: the fixtures carry no chooser payload. One row is built from the dependency_page `context` field; nothing else is invented.
    const pg = bySchema(fx, 'opentrace.workbench.dependency_page/1')[0]; if (!pg) return miss('no dependency fixture');
    const c = pg[1].context; const row = { context_id: c.context_id, path: c.path, components_total: pg[1].filter_totals?.all ?? 0, category: 'dependency_manifest' };
    return { kind: 'adapter', status: 200, adapterNote: 'chooser built from dependency_page.context', body: { schema: 'opentrace.workbench.dependency_contexts/1', binding: pg[1].binding, default_context_id: c.context_id,
      default_basis: 'largest_dependency_file', total: 1, offset: 0, limit: num(q('limit'), 20), rows: [row], counts: { total: 1, shown: 1, truncated: false } } };
  }
  if (p === '/api/workbench/v1/bom-candidates') {
    // Routing ignores `family`: the fixtures carry filters.family = null; the app's software view requests family=software. Recorded as a limit, not hidden.
    const off = num(q('offset'), 0), query = q('query') || '', fg = q('filter_group') || null;
    for (const [f, b] of bySchema(fx, 'opentrace.workbench.bom_candidates/1'))
      if (b.page.offset === off && (b.filters.query || '') === query && (b.filters.filter_group || null) === fg && b.filters.state === null) return hit(f);
    return miss(`no bom-candidates fixture for offset=${off} query=${query} filter_group=${fg}`);
  }
  if (p === '/api/workbench/v1/bom-graph') {
    const kind = q('scope_kind'), cand = q('candidate_id'), group = q('group'), off = num(q('offset'), 0);
    for (const [f, b] of bySchema(fx, 'opentrace.workbench.bom_graph/1')) {
      const s = b.scope; if (s.kind !== kind) continue;
      if (kind === 'focused_candidate' && s.candidate_id === cand) return hit(f);
      if (kind === 'full_view' && s.group === (group || 'all') && (b.page?.offset ?? 0) === off) return hit(f);
      if (kind === 'group_summary' && s.group === group) return hit(f);
    }
    return miss(`no bom-graph fixture for ${kind} ${cand || group} offset=${off}`);
  }
  if (p === '/api/workbench/v1/crypto-assets' || p === '/api/workbench/v1/ai-assets') {
    // Several fixtures hold ONE payload per state (completed_empty / partial / failed / not_run ...) and the app sends no state parameter, so the CASE chooses
    // the file explicitly (fx.select[path]); with no selection a single candidate is served, several are an unrouted request (never guessed).
    if (fx.select?.[p]) return hit(fx.select[p]);
    const all = bySchema(fx, p.endsWith('crypto-assets') ? 'opentrace.workbench.crypto_assets/1' : 'opentrace.workbench.ai_assets/1');
    if (all.length === 1) return hit(all[0][0]);
    return miss(`${all.length} candidate fixtures; the case must select one`);
  }
  if (p.startsWith('/api/view/')) return miss('legacy view route not fixture-backed');
  return null;                                 // not an API route owned by the adapter
}

// Pure request handler used by the page's Fetch interception. mode: 'passthrough' (real server for everything on loopback) or a loaded fixture.
//  - any non-loopback URL: fail (recorded);  - /api/analysis/demo with a fixture: the fixture's envelope;  - routed API paths: fixture / adapter / typed 404;
//  - everything else on loopback: continue to the real service (static assets, config).
export function handleRequest({ url, fixture, envelope }) {
  const loop = /^(http:\/\/(127\.0\.0\.1|localhost)[:/])|^(data:|blob:|about:)/.test(url);
  if (!loop) return { action: 'fail', reason: 'non-loopback' };
  if (!fixture) return { action: 'continue', served: 'real-server' };
  const path = new URL(url).pathname;
  if (path === '/api/analysis/demo') return { action: 'fulfill', status: 200, body: envelope, served: 'adapter-synthesized:analysis-envelope' };
  const r = route(fixture, url);
  if (!r) return { action: 'continue', served: 'real-server' };
  return { action: 'fulfill', status: r.status, body: r.body, served: r.kind + (r.file ? ':' + r.file : '') + (r.adapterNote ? ':' + r.adapterNote : '') };
}

// Installs the handler on a page. `state.fixture` may be swapped between cases (isolation: one fixture per page/context; the log is per page).
export async function installRouting(pg, browser, state) {
  state.log = state.log || { served: [], blocked: [] };
  await pg.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  browser.on((m) => {
    if (m.sessionId !== pg.sessionId || m.method !== 'Fetch.requestPaused') return;
    const rid = m.params.requestId, url = m.params.request.url; const a = handleRequest({ url, fixture: state.fixture, envelope: state.envelope });
    if (a.action === 'fail') { state.log.blocked.push(url); pg.send('Fetch.failRequest', { requestId: rid, errorReason: 'BlockedByClient' }).catch(() => {}); return; }
    if (a.action === 'continue') { pg.send('Fetch.continueRequest', { requestId: rid }).catch(() => {}); return; }
    state.log.served.push({ url: url.replace(/^http:\/\/[^/]+/, ''), served: a.served, status: a.status });
    pg.send('Fetch.fulfillRequest', { requestId: rid, responseCode: a.status, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }, { name: 'Cache-Control', value: 'no-store' }], body: Buffer.from(JSON.stringify(a.body)).toString('base64') }).catch(() => {});
  });
}
