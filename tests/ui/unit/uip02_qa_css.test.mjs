// UIP-02 visual QA: static guards for three scoped CSS corrections (no browser needed).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const css = readFileSync(new URL('../../../src/ui/styles/app.css', import.meta.url), 'utf8');

test('homepage wrapper is not limited by the legacy .ot-intake 820px column', () => {
  assert.match(css, /\.ot-intake\.ot-home-page\{max-width:none;margin:0\}/);
});
test('layer bar follows the reference: paper fill, full border, 14px 16px padding, not the --grid fill', () => {
  const m = css.match(/\n\.ot-tabs\{([^}]*)\}/);
  assert.ok(m, '.ot-tabs rule');
  assert.match(m[1], /background:var\(--paper\)/);
  assert.match(m[1], /border:1px solid var\(--line\)/);
  assert.match(m[1], /padding:14px 16px/);
  assert.doesNotMatch(m[1], /--grid/);
});
test('the layout grid has no side inset so the inspector meets the frame edge', () => {
  assert.match(css, /\.ot-layout\{[^}]*padding:0 0 16px/);
});
