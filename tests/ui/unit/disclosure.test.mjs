// UIP-D08 disclosure copy selected only from the raw /api/config live block.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { disclosureVariant, disclosureParagraphs, renderDisclosure, DISCLOSURE_HEADING } from '../../../src/ui/components/disclosure.js';

const live = (o = {}) => ({ enabled: true, isolation: { available: true, reason: null, description: 'a gVisor sandbox' }, policy: { effective: 'bounded' }, advisories: { enabled: false }, ...o });
const REPO = 'Repository scan. OpenTrace pins your GitHub link to one commit. The SBOM and cryptography scanners read its files in a container with no network access.';
const ADV = 'Advisory lookup. When enabled, OpenTrace sends OSV only the ecosystem, name, and exact version of eligible lockfile dependencies.';
const CLEANUP = 'Session cleanup. OpenTrace keeps files and results locally for the session. End session attempts to delete them and reports whether cleanup succeeded.';
const NOSCORE = 'Results describe inventories and source evidence for that commit. They are not a security score.';
const DEFAULT_AI_MODE = 'In default mode, Scan can show supported AI model references found in source code, but skips live AI-BOM generation and comparison against a newly generated AI inventory. The captured Frigate AI-BOM remains available through Demo ↗.';
const adv = { enabled: true, host: 'api.osv.dev', sends: 'the ecosystem, package name and version of each lockfile entry' };

test('variants are chosen only from the live block; nothing before config loads', () => {
  for (const x of [undefined, null, 'x', 0]) { assert.equal(disclosureVariant(x), null); assert.equal(renderDisclosure(x), ''); }
  assert.equal(disclosureVariant(live()), 'A');
  assert.equal(disclosureVariant(live({ policy: { effective: 'allowlist' } })), 'B');
  assert.equal(disclosureVariant(live({ isolation: { available: false, reason: 'no worker' } })), 'C');
  assert.equal(disclosureVariant({ enabled: false }), 'D');
  assert.equal(disclosureVariant(live({ policy: {} })), null, 'an unknown policy is not guessed');
});

test('approved text, variant A', () => {
  assert.deepEqual(disclosureParagraphs(live()), [REPO, 'No advisory lookup is made.', CLEANUP, NOSCORE, DEFAULT_AI_MODE]);
  assert.deepEqual(disclosureParagraphs(live({ advisories: adv })), [REPO, ADV, CLEANUP, NOSCORE, DEFAULT_AI_MODE], 'order: repository scan, advisory lookup, session cleanup');
});

test('advisory parser unavailable: no query claim, the unavailability is stated', () => {
  const p = disclosureParagraphs(live({ advisories: { ...adv, specialist_available: false } }));
  assert.equal(p.some((x) => /sent to api\.osv\.dev/.test(x)), false);
  const a = p.filter((x) => /^Advisory lookup is enabled/.test(x));
  assert.equal(a.length, 1);
  assert.match(a[0], /package parser is not available/);
  assert.match(a[0], /no advisory lookup will be made/);
  assert.match(a[0], /lookup was unavailable/);
  assert.equal(p.includes(ADV), false);
});

test('approved text, variant B', () => {
  const p = disclosureParagraphs(live({ policy: { effective: 'allowlist' } }));
  assert.equal(p[0], 'Live scanning is limited to a short list of pre-approved repositories right now. If your link is not on it, nothing is downloaded and the reason is shown.');
  assert.equal(p[1], 'Approved repositories are read as data inside a sandbox (a gVisor sandbox); the repository’s code is not installed, built or run.');
  assert.deepEqual(p.slice(2), ['No advisory lookup is made.', CLEANUP, NOSCORE, DEFAULT_AI_MODE]);
  assert.equal(p.length, 6);
  assert.deepEqual(disclosureParagraphs(live({ policy: { effective: 'allowlist' }, advisories: adv })).slice(2), [ADV, CLEANUP, NOSCORE, DEFAULT_AI_MODE]);
});

test('approved text, variant C never mentions a sandbox or container; no advisory line (nothing is scanned, so nothing is sent)', () => {
  const c = live({ isolation: { available: false, reason: 'no isolation provider configured' } });
  const p = disclosureParagraphs(c);
  assert.deepEqual(p, ['Scanning is unavailable: OpenTrace could not verify an isolation boundary (no isolation provider configured). Nothing will be downloaded or scanned.', 'Demo ↗ opens the captured Frigate replay; it is not your repository.', DEFAULT_AI_MODE]);
  assert.equal(/sandbox|container/i.test(p.join(' ')), false);
  assert.equal(disclosureParagraphs({ ...c, advisories: adv }).length, 3);
});

test('approved text, variant D', () => {
  assert.deepEqual(disclosureParagraphs({ enabled: false }), ['Live scanning is not enabled on this service, so no repository is downloaded. Demo ↗ opens the captured Frigate replay; it is not your repository.', DEFAULT_AI_MODE]);
});

test('rendering: heading verbatim, text escaped, no deletion promise (mounted by UIP-03 in the intake only)', () => {
  assert.equal(DISCLOSURE_HEADING, 'What happens when you press Scan');
  const h = renderDisclosure(live({ isolation: { available: true, description: '<b>x</b>' }, policy: { effective: 'allowlist' } }));
  assert.ok(h.includes('What happens when you press Scan') && h.includes('data-variant="B"') && h.includes('&lt;b&gt;x&lt;/b&gt;'));
  assert.equal(/always deleted|is deleted when|will be deleted/i.test(h), false);
  // UIP-03 mounts it in the intake (Placement P). Legacy assertion changed with a recorded reason: UIP-02 asserted it was NOT mounted until the one-click Scan exists.
  assert.equal(readFileSync('src/ui/components/intake.js', 'utf8').includes('renderDisclosure'), true);
  for (const f of ['src/ui/app.js', 'src/ui/components/workbench.js']) assert.equal(readFileSync(f, 'utf8').includes('renderDisclosure'), false, `${f} must not mount the disclosure`);
});

// UIP-07C A2: the AI paragraph and the qualified isolation sentence appear only when the AI step is requested; flag off is byte-identical.
const aiBom = (o = {}) => ({ requested: true, available: true, reason: null, provider: 'openai', host: 'api.openai.com', model: 'gpt-6-luna', sends: 'repository file names and code excerpts chosen by the classifier', ...o });
test('UIP-07C A2: AI paragraph and qualified isolation sentence only when ai_bom.requested', () => {
  const base = disclosureParagraphs(live());
  assert.equal(base.length, 5, 'no ai_bom block: unchanged');
  assert.deepEqual(disclosureParagraphs(live({ ai_bom: aiBom({ requested: false }) })), base, 'not requested: unchanged');
  const p = disclosureParagraphs(live({ ai_bom: aiBom() }));
  assert.equal(p.length, 6);
  assert.equal(p[0], REPO);
  const ai = 'AI inventory. When available and enabled, Cisco AI-BOM sends selected file names and code excerpts to the configured LLM provider through a restricted gateway. Repository text and configuration can influence what it selects. OpenTrace explains if this step is skipped.';
  assert.equal(p[1], ai);
  for (const re of [/configured LLM provider/, /restricted gateway/, /file names and code excerpts/]) assert.match(p[1], re);
  assert.deepEqual(p.slice(2), base.slice(1), 'order: repository scan, AI inventory, advisory lookup, session cleanup');
  assert.equal(disclosureParagraphs(live({ ai_bom: aiBom(), advisories: adv })).indexOf(ADV), 2);
  assert.equal(disclosureParagraphs(live({ ai_bom: aiBom({ available: false, reason: 'isolation_unavailable' }) }))[1], ai + ' It is unavailable right now.');
  assert.equal(disclosureParagraphs(live({ isolation: { available: false, reason: 'x' }, ai_bom: aiBom() })).some((x) => x.startsWith('AI inventory.')), false, 'variant C never shows provider disclosure');
  assert.equal(disclosureParagraphs({ enabled: false, ai_bom: aiBom() }).some((x) => x.startsWith('AI inventory.')), false, 'variant D never shows provider disclosure');
  const h = renderDisclosure(live({ ai_bom: aiBom({ model: '<b>m</b>', host: 'h.example' }) }));
  assert.ok(!h.includes('<b>m</b>') && !h.includes('h.example') && !h.includes('gpt-6'), 'the fixed wording does not interpolate provider config');
});
