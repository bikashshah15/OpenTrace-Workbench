// About dialog (wide, diagram + five steps) and the BOMBridge-free user-facing copy. Pure string checks; no browser.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { ABOUT, ABOUT_DIAGRAM, INFO, STEP_COPY, LAYER_NOTE } from '../../../src/ui/lib/copy.js';

test('About: diagram above the copy, alt text, full-size link, and the five approved steps', () => {
  assert.ok(ABOUT.indexOf('<figure') < ABOUT.indexOf('OpenTrace connects software'));
  assert.match(ABOUT, /<img src="\/static\/assets\/opentrace-architecture\.webp" width="2400" height="1373" alt="Architecture diagram\./);
  assert.match(ABOUT, /<a href="\/static\/assets\/opentrace-architecture\.webp" target="_blank" rel="noopener">Open full-size diagram<\/a>/);
  const steps = [...ABOUT.matchAll(/<li><strong>([^<]+)<\/strong>/g)].map((m) => m[1]);
  assert.deepEqual(steps, ['Pin the repository revision.', 'Generate inventories and collect source evidence.', 'Compare source evidence with the inventories.', 'Look up dependency advisories.', 'Review the evidence.']);
  assert.match(ABOUT, /Choose Scan to analyze a repository when live scanning is available, or Demo to explore a recorded Frigate scan\./);
  assert.match(ABOUT, /Which code or models actually ran remains unverified\./);
  assert.doesNotMatch(ABOUT, /BOMBridge|remain planned/);
  assert.equal(statSync(join('src/ui', ABOUT_DIAGRAM.replace('/static/', ''))).isFile(), true);
});
test('About opens in the wide dialog (same layout as the artifact preview)', () => {
  assert.match(readFileSync('src/ui/app.js', 'utf8'), /modal\('How OpenTrace works', ABOUT, true\)/);
});
test('no BOMBridge name or "Backend integration remains planned" in user-facing UI source', () => {
  const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? (e.name === 'vendor' ? [] : walk(join(d, e.name))) : [join(d, e.name)]));
  for (const f of walk('src/ui').filter((p) => /\.(js|css|html)$/.test(p))) { const t = readFileSync(f, 'utf8'); assert.doesNotMatch(t, /BOMBridge/, f); assert.doesNotMatch(t, /Backend integration remains planned/, f); }
  assert.match(INFO.graphs, /source-to-inventory comparisons/); assert.match(LAYER_NOTE.bom, /^Inventory assessment evidence connections/);
  assert.ok(STEP_COPY.every((s) => !/BOMBridge/.test(s)));
});
test('Overview of each derived artifact uses its Evidence-tab label; filenames and the assessment facts are kept', () => {
  const app = readFileSync('src/ui/app.js', 'utf8');
  assert.match(app, /'bombridge-result\.json': 'Inventory assessment record', 'source-declarations\.json': 'Source evidence', 'advisory-lookup\.json': 'Advisory lookup record'/);
  assert.match(app, /DERIVED_LABEL\[name\] \|\| name/); assert.match(app, /Recorded inventory information and any checks included in the assessment\./);
  assert.match(app, /<dt>Findings<\/dt>/);
});
