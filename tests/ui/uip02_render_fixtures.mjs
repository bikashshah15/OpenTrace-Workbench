// Helper for tests/ui/test_uip02_inspector_crosscheck.py: renders each inspector payload given on the command line (JSON file paths)
// through the UIP-02 shell and prints one JSON summary per file.
import { readFileSync } from 'node:fs';
import { fromBoundInspector } from '../../src/ui/lib/inspector_model.js';
import { renderInspector } from '../../src/ui/components/inspector.js';

const out = process.argv.slice(2).map((p) => {
  const obj = JSON.parse(readFileSync(p, 'utf8'));
  const html = renderInspector(fromBoundInspector(obj));
  return { path: p, questions: [...html.matchAll(/data-question="([a-z_]+)"/g)].map((m) => m[1]), expected: obj.answers.map((a) => a.question_id), origin: /data-origin="([a-z_]+)"/.exec(html)[1],
    inert: !(html.match(/<[^>]+>/g) || []).some((t) => /^<(script|img|iframe|a)\b/i.test(t) || /\s(href|src|on\w+)=/i.test(t)) };
});
process.stdout.write(JSON.stringify(out));
