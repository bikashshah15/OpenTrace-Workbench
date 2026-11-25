// Lab Assistant launcher: icon-only 56px circle with an accessible name, kept IDs/ARIA, CSS-only tooltip. Static markup/CSS checks.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync('src/ui/index.html', 'utf8'); const css = readFileSync('src/ui/styles/app.css', 'utf8');
const btn = html.match(/<button[^>]*id="ot-assistant-launch"[\s\S]*?<\/button>/)[0];

test('launcher markup: same id, aria-controls and aria-expanded; accessible name; decorative 24px inline SVG; no visible text', () => {
  assert.match(btn, /id="ot-assistant-launch"/); assert.match(btn, /aria-controls="ot-assistant"/); assert.match(btn, /aria-expanded="false"/); assert.match(btn, /aria-label="Ask Lab Assistant"/);
  assert.match(btn, /<svg[^>]*width="24" height="24" viewBox="0 0 24 24"[^>]*aria-hidden="true"/);
  assert.equal(btn.replace(/<svg[\s\S]*?<\/svg>/, '').replace(/<[^>]+>/g, '').trim(), '', 'no visible text');
  assert.doesNotMatch(btn, /<img|href=|src=/, 'inline, no new dependency');
});
test('launcher CSS: 56px circle, teal background with white icon, CSS-only tooltip on hover and keyboard focus, focus ring kept', () => {
  assert.match(css, /#ot-assistant-launch\{width:56px;height:56px;[^}]*border-radius:50%[^}]*background:#2d6e63;color:#fff/);
  assert.match(css, /#ot-assistant-launch::after\{content:"Ask Lab Assistant"/);
  assert.match(css, /#ot-assistant-launch:hover::after,#ot-assistant-launch:focus-visible::after\{opacity:1\}/);
  assert.doesNotMatch(css, /#ot-assistant-launch[^{]*\{[^}]*outline:\s*(none|0)/, 'the shared visible focus ring is not removed');
  assert.match(css, /body:has\(\.ot-bom8-inspector\.open\) \.assistant-launch\{bottom:calc\(45vh \+ 14px\)/, 'the mobile BOM-inspector adjustment is untouched');
});
test('handlers unchanged: toggle on click, focus returns to the launcher on close and Escape', () => {
  const app = readFileSync('src/ui/app.js', 'utf8');
  assert.match(app, /\$\('ot-assistant-launch'\)\.addEventListener\('click', \(\) => dispatch\(\{ type: 'ASSISTANT'/);
  assert.equal((app.match(/\$\('ot-assistant-launch'\)\.focus\(\)/g) || []).length, 2);
});
