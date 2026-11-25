import test from 'node:test';
import assert from 'node:assert/strict';
import { assistantCanSubmit, initial, reducer } from '../../../src/ui/lib/store.js';
import { renderAssistant } from '../../../src/ui/components/assistant.js';

const analysis = { generation: 9, identity: { analysis_digest: 'a'.repeat(64) } };

test('analysis and session replacement clear assistant turns, subject, and pending response identity', () => {
  let s = { ...initial(), analysis, epoch: 3, assistant: { ...initial().assistant, turns: [{ question: 'old' }], draft: 'old', subject: { label: 'old repo' }, pending: true, requestId: 'r1' } };
  s = reducer(s, { type: 'ANALYSIS_START' });
  assert.deepEqual(s.assistant.turns, []); assert.equal(s.assistant.subject, null); assert.equal(s.assistant.requestId, null);
  s = { ...s, session: { ...s.session, id: 'old' }, assistant: { ...s.assistant, turns: [{ question: 'old' }] } };
  s = reducer(s, { type: 'SESSION', patch: { id: 'new' } });
  assert.deepEqual(s.assistant.turns, []);
});

test('late answer from a prior request or generation is ignored', () => {
  const s = { ...initial(), epoch: 4, analysis, assistant: { ...initial().assistant, pending: true, requestId: 'current' } };
  assert.equal(reducer(s, { type: 'ASSISTANT_RESULT', epoch: 3, generation: 9, requestId: 'current', response: {} }), s);
  assert.equal(reducer(s, { type: 'ASSISTANT_RESULT', epoch: 4, generation: 8, requestId: 'current', response: {} }), s);
  assert.equal(reducer(s, { type: 'ASSISTANT_RESULT', epoch: 4, generation: 9, requestId: 'old', response: {} }), s);
});

test('failed one-turn adoption is cleared and the UI tells the user to review and opt in again', () => {
  let s = { ...initial(), analysis, assistant: { ...initial().assistant, open: true, pending: true,
    adoptNext: true, requestId: 'adopt-1' } };
  s = reducer(s, { type: 'ASSISTANT_FAILED', epoch: s.epoch, requestId: 'adopt-1', adoptionAttempted: true,
    message: 'The request failed or its response was lost; the conversation subject may have changed. Review the current selection and explicitly check “Use current selection for this question” again before another question.' });
  assert.equal(s.assistant.adoptNext, false);
  assert.equal(s.assistant.adoptionUncertain, true);
  assert.equal(assistantCanSubmit(s.assistant), false);
  assert.equal(s.assistant.pending, false);
  const html = renderAssistant({ ...s, assistant: { ...s.assistant, draft: 'retry' } },
    { kind: 'model', id: 'next-model', label: 'A different current selection' });
  assert.match(html, /conversation subject may have changed/);
  assert.match(html, /class="ot-assistant-subject">About /); assert.doesNotMatch(html, /data-fk="aadopt"/);
  assert.doesNotMatch(html, /<input[^>]*data-fk="aadopt" checked/);
  const optedIn = reducer(s, { type: 'ASSISTANT', patch: { adoptNext: true } });
  assert.equal(assistantCanSubmit(optedIn.assistant), true);
  const resubmitted = reducer(optedIn, { type: 'ASSISTANT', patch: { pending: true, requestId: 'adopt-2' } });
  const reconciled = reducer(resubmitted, { type: 'ASSISTANT_RESULT', epoch: resubmitted.epoch, generation: analysis.generation,
    requestId: 'adopt-2', question: 'retry', response: { subject: { id: 'next-model' } } });
  assert.equal(reconciled.assistant.adoptionUncertain, false);
});

test('a lost response during a subject switch pauses free-form questions, keeps the draft, and only a successful Explain this resumes them', () => {
  const MSG = 'Choose Explain this again to confirm which item you’re asking about.';
  let s = { ...initial(), analysis, assistant: { ...initial().assistant, open: true, draft: 'my typed draft', pending: true, requestId: 'explain-1', pendingQuestion: 'Explain qs 6.14.1' } };
  s = reducer(s, { type: 'ASSISTANT_FAILED', epoch: s.epoch, requestId: 'explain-1', question: 'Explain qs 6.14.1', message: 'The assistant service is unavailable.', noRestore: true, adoptionAttempted: true });
  assert.equal(s.assistant.adoptionUncertain, true);
  assert.equal(assistantCanSubmit(s.assistant), false);
  assert.equal(s.assistant.draft, 'my typed draft');
  const html = renderAssistant(s, null);
  assert.equal(html.split(MSG).length - 1, 1, 'the recovery instruction appears exactly once');
  assert.equal(html.split('The assistant service is unavailable.').length - 1, 1);
  assert.match(html, /my typed draft/);
  assert.match(html, /<button type="submit" class="button small ot-assistant-ask"[^>]* disabled>/);
  const retry = reducer(s, { type: 'ASSISTANT_SUBMIT', requestId: 'explain-2', question: 'Explain qs 6.14.1', keepDraft: true });
  const other = reducer(retry, { type: 'ASSISTANT_FAILED', epoch: retry.epoch, requestId: 'explain-2', question: 'Explain qs 6.14.1', message: 'A different error.', noRestore: true, adoptionAttempted: false });
  const otherHtml = renderAssistant(other, null);
  assert.equal(other.assistant.adoptionUncertain, true);
  assert.equal(otherHtml.split(MSG).length - 1, 1);
  assert.equal(otherHtml.split('A different error.').length - 1, 1);
  assert.equal(retry.assistant.draft, 'my typed draft');
  const done = reducer(retry, { type: 'ASSISTANT_RESULT', epoch: retry.epoch, generation: analysis.generation, requestId: 'explain-2', question: 'Explain qs 6.14.1', response: { subject: { id: 'qs', label: 'qs 6.14.1' } } });
  assert.equal(done.assistant.adoptionUncertain, false);
  assert.equal(assistantCanSubmit(done.assistant), true);
  assert.equal(done.assistant.draft, 'my typed draft');
});

test('desktop panel renders free-form composer and claim citations as inert escaped text', () => {
  const s = { ...initial(), analysis, assistant: { ...initial().assistant, open: true, draft: 'hello', subject: { label: '<repo>' }, turns: [{ question: 'what?', subjectLabel: 'subject', response: {
    context_id: 'c1', answer: { answer_status: 'partial', claims: [{ kind: 'finding', text: '<script>alert(1)</script>', evidence_ids: ['ev1'] }], limitations: [], next_steps: [{ action: 'open_evidence', evidence_id: 'state1', label: 'Inspect coverage <details>' }] },
    citations: [{ evidence_id: 'ev1', label: 'record <one>' }, { evidence_id: 'state1', source: 'model_correspondence', kind: 'source_state', label: 'comparison coverage' }],
    source_states: { model_correspondence: { state: 'not_compared', entry_count: 0, truncated: false, reason_code: 'binding_conflict' } },
    limitations: ['model_correspondence: comparison was not performed'],
  } }] } };
  const html = renderAssistant(s, { kind: 'dependency', id: 'dep1', label: 'pkg' });
  assert.match(html, /id="ot-assistant-form"/);
  assert.match(html, /class="ot-assistant-subject">About /); assert.doesNotMatch(html, /Use current selection|data-fk="aadopt"/);
  assert.doesNotMatch(html, /<script>alert/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /data-action="a-citation"/);
  assert.match(html, /Lock position/);
  assert.match(html, /Model-to-BOM comparison: comparison was not performed/);   // plain-language limitation stays visible beside the answer
  assert.match(html, /Next: <button/);
  assert.match(html, /Inspect coverage &lt;details&gt;/);
});

const turnOf = (over) => ({ ...initial(), analysis, assistant: { ...initial().assistant, open: true, subject: { label: 'Whole repository analysis' }, turns: [{ question: 'Q?', subjectLabel: 'Whole repository analysis', response: {
  context_id: 'c1', provider: { profile: 'openai', model: 'gpt-6-luna', validation_level: 'strict' },
  citations: [{ evidence_id: 'ev1', label: 'crypto.py' }, { evidence_id: 'st-adv', source: 'advisories', kind: 'source_state', label: 'advisory coverage' }],
  source_states: { advisories: { state: 'not_run', entry_count: 0, truncated: false, reason_code: 'lookup_off' } },
  limitations: ['advisories: evidence state is not_run (lookup_off)'],
  answer: { answer_status: 'partial', claims: [{ kind: 'finding', text: 'AES-256-GCM is recorded.', evidence_ids: ['ev1'] }], limitations: [], next_steps: [] }, ...over } }] } });

test('minimal presentation: no internal labels outside Details; provider, states and reason codes are collapsed', () => {
  const html = renderAssistant(turnOf({}), null);
  const [main, details] = html.split('<details class="ot-assistant-details">');
  assert.ok(details, 'details exists');
  assert.doesNotMatch(main, />(finding|unknown|limitation)</); assert.doesNotMatch(main, /openai|gpt-6-luna|not_run|lookup_off|evidence records|strict/);
  assert.match(details, /openai \/ gpt-6-luna/); assert.match(details, /not_run/); assert.match(details, /lookup_off/); assert.match(details, /Open coverage evidence/);
  assert.doesNotMatch(main, /Partly answered/); assert.doesNotMatch(main, /Advisories was not run/);   // generic coverage is under Details, not beside a short answer
  assert.match(details, /Advisories was not run\./); assert.match(main, /class="ot-assistant-subject">About /); assert.doesNotMatch(main, /Follow-ups stay on this subject/);
  assert.match(main, /data-action="a-citation"[^>]*data-evidence="ev1"/);
});

test('an unknown answer states it cannot be determined; a plain answered answer adds no verdict or limits block', () => {
  const unk = renderAssistant(turnOf({ answer: { answer_status: 'unknown', claims: [], limitations: [], next_steps: [] } }), null);
  assert.match(unk, /Cannot be determined/);
  const ok = renderAssistant(turnOf({ limitations: [], answer: { answer_status: 'answered', claims: [{ kind: 'finding', text: 'Fact.', evidence_ids: ['ev1'] }], limitations: [], next_steps: [] } }), null);
  assert.doesNotMatch(ok, /ot-assistant-verdict|ot-assistant-limit/);
});

test('limitations are not listed twice only when the words are identical; citing a state record never hides a server limitation', () => {
  const main = (h) => h.split('<details')[0];
  const same = renderAssistant(turnOf({ limitations: ['advisories: evidence state is not_run'], answer: { answer_status: 'partial', claims: [{ kind: 'finding', text: 'Fact.', evidence_ids: ['ev1'] }],
    limitations: [{ text: 'Advisories was not run.', evidence_ids: ['st-adv'] }], next_steps: [] } }), null);
  assert.equal((main(same).match(/Advisories was not run/g) || []).length, 1);
  // REV-01: two distinct server limitations on one source; the model cites the state and mentions only one -> both stay visible.
  const two = renderAssistant(turnOf({ limitations: ['advisories: evidence was deterministically truncated', 'advisories: evidence state is partial (r)'], answer: { answer_status: 'partial',
    claims: [{ kind: 'unknown', text: 'Whether MD5 is used is unknown.', evidence_ids: ['st-adv'] }],
    limitations: [{ text: 'Advisory coverage is partial.', evidence_ids: ['st-adv'] }], next_steps: [] } }), null);
  assert.match(main(two), /Advisory coverage is partial\./); assert.doesNotMatch(main(two), /more limitations/); assert.doesNotMatch(main(two), /only part of the evidence fit/);
  const full = two.split('<details class="ot-assistant-details">')[1];   // nothing is hidden: every distinct limitation is under Details
  assert.match(full, /2 more limitations/);
  assert.match(full, /Advisories: only part of the evidence fit/); assert.match(full, /Advisories was only partly covered\./); assert.doesNotMatch(full, /Advisory coverage is partial\./, 'the one beside the answer is not repeated');
});

test('a background claim with the same words does not suppress a repository limitation; label quotes cannot break out of attributes', () => {
  const html = renderAssistant(turnOf({ limitations: ['advisories: evidence state is not_run'], citations: [{ evidence_id: 'ev1', label: 'x" onclick="alert(1)' }, { evidence_id: 'st-adv', source: 'advisories', kind: 'source_state', label: 's' }],
    answer: { answer_status: 'partial', claims: [{ kind: 'background', text: 'Advisories was not run.', evidence_ids: [] }, { kind: 'finding', text: 'F.', evidence_ids: ['ev1'] }], limitations: [], next_steps: [] } }), null);
  assert.match(html, /<li>Advisories was not run\./); assert.doesNotMatch(html, /" onclick="/); assert.match(html, /&quot; onclick=&quot;/);
  const err = renderAssistant({ ...turnOf({}), assistant: { ...turnOf({}).assistant, turns: [{ question: 'q', error: 'old' }] } }, null);
  assert.doesNotMatch(err, /role="status">old/);
});

test('a server limitation that the answer does not state remains visible, and background claims are labelled as a general explanation', () => {
  const html = renderAssistant(turnOf({ limitations: ['crypto: evidence was deterministically truncated'], answer: { answer_status: 'partial',
    claims: [{ kind: 'background', text: 'AES is a block cipher.', evidence_ids: [] }, { kind: 'finding', text: 'AES-256-GCM is recorded.', evidence_ids: ['ev1'] }], limitations: [], next_steps: [] } }), null);
  assert.match(html, /Cryptography: only part of the evidence fit/);
  assert.match(html, /General explanation, not from this repository:<\/em> AES is a block cipher\./);
});

test('model, evidence and label text is inert: no images, links, handlers or active markup are ever produced', () => {
  const bad = '<img src=x onerror=alert(1)> <a href="javascript:alert(1)">go</a> [md](javascript:alert(1)) ![i](https://evil.example/p.png) <svg onload=alert(1)> https://evil.example/';
  const html = renderAssistant(turnOf({ citations: [{ evidence_id: 'ev1', label: bad }, { evidence_id: 'st-adv', source: 'advisories', kind: 'source_state', label: bad }],
    limitations: ['advisories: ' + bad],
    answer: { answer_status: 'partial', claims: [{ kind: 'finding', text: bad, evidence_ids: ['ev1'] }, { kind: 'background', text: bad, evidence_ids: [] }],
      limitations: [{ text: bad, evidence_ids: ['st-adv'] }], next_steps: [{ action: 'open_evidence', evidence_id: 'st-adv', label: bad }] } }), { kind: 'dependency', id: 'd', label: bad });
  const without = html.replace(/<svg class="ot-assistant-icon"[^>]*>(?:<(?:rect|path)\b[^>]*\/>)+<\/svg>/g, '').replace(/<(button|input|label|textarea|form|header|div|section|article|details|summary|span|p|ul|li|strong|em|small|select|option|br)\b[^>]*>/g, '').replace(/<\/(button|label|textarea|form|header|div|section|article|details|summary|span|p|ul|li|strong|em|small|select|option)>/g, '');
  assert.doesNotMatch(without, /<[a-zA-Z]/, 'only the renderer own fixed tags exist');
  assert.doesNotMatch(html.replace(/<svg class="ot-assistant-icon"[^>]*>(?:<(?:rect|path)\b[^>]*\/>)+<\/svg>/g, ''), /<(img|a|svg|script|iframe|object|embed)\b/i);
  for (const tag of html.match(/<[^>]*>/g)) {   // escaped text cannot contain '>', so every match is a real tag
    assert.doesNotMatch(tag.replace(/"[^"]*"/g, '""'), /\s(on\w+|href|src|srcset|style)\s*=/i, tag.slice(0, 80));   // attribute names only; values are escaped text
    assert.ok(!/<[^>]*<\w/.test(tag), 'no nested tag start inside a tag');
  }
});

test('pending shows status and cancel; the Ask control is replaced; errors are announced', () => {
  const s = { ...turnOf({}), assistant: { ...turnOf({}).assistant, pending: true, error: 'It failed.' } };
  const html = renderAssistant(s, null);
  assert.match(html, /role="status"[^>]*>(<span[^>]*><i><\/i><i><\/i><i><\/i><\/span>)?<span>Thinking…/); assert.match(html, /data-action="a-cancel"/); assert.doesNotMatch(html, /type="submit"/); assert.match(html, /role="status">It failed\./);
});

test('assistant exposes validated current-graph relationships as explicit adoption choices', () => {
  const s = { ...initial(), analysis, assistant: { ...initial().assistant, open: true } };
  const html = renderAssistant(s, { kind: 'bom', id: 'candidate-1', label: 'candidate',
    relations: [{ edge_id: 'edge-1', label: 'candidate supports inventory' }] });
  assert.match(html, /ot-assistant-relationship/);
  assert.match(html, /edge-1/);
  assert.doesNotMatch(html, /Use current selection|data-fk="aadopt"/);
});

// ---- Stage 4 (V5): the launcher never sits over the end of the page content: its height plus a gap is reserved below the shell.
import { readFileSync as readCss } from 'node:fs';
test('S4-LAUNCHER: the shell reserves space for the fixed launcher so the footer and the end of the inspector clear it', () => {
  const css = readCss('src/ui/styles/app.css', 'utf8');
  const proto = readCss('src/ui/styles/prototype.css', 'utf8');
  const launch = /\.assistant-launch\{position:fixed;bottom:(\d+)px/.exec(proto);
  assert.ok(launch, 'the launcher is fixed at the bottom');
  const reserve = /\.ot-shell\{padding-bottom:(\d+)px\}/.exec(css);
  assert.ok(reserve, 'the reservation rule exists');
  assert.ok(Number(reserve[1]) >= Number(launch[1]) + 46 + 8, 'reserved height covers bottom offset + launcher height + gap');
  assert.match(css, /@media\(max-width:480px\)\{\.ot-shell\{padding-bottom:7\d?px\}\}/);
});

const withDraft = (draft, extra = {}) => ({ ...initial(), analysis, epoch: 2, assistant: { ...initial().assistant, open: true, draft, ...extra } });

test('submit moves the question into the transcript and clears the composer at once, with accessible pending feedback', () => {
  let s = reducer(withDraft('What is signed?'), { type: 'ASSISTANT_SUBMIT', requestId: 'r1', question: 'What is signed?' });
  assert.equal(s.assistant.draft, ''); assert.equal(s.assistant.pending, true); assert.equal(s.assistant.pendingQuestion, 'What is signed?');
  const html = renderAssistant(s, null);
  assert.match(html, /<article class="ot-assistant-turn ot-assistant-turn-pending" aria-busy="true"><p class="ot-assistant-q">What is signed\?<\/p>/);
  assert.match(html, /<p class="ot-assistant-thinking" role="status"><span class="ot-assistant-dots" aria-hidden="true">/);
  assert.match(html, /<textarea[^>]*>\s*<\/textarea>/); assert.match(html, /data-action="a-cancel"/); assert.doesNotMatch(html, /Waiting/);
  s = reducer(s, { type: 'ASSISTANT_RESULT', epoch: 2, generation: analysis.generation, requestId: 'r1', question: 'What is signed?', response: { context_id: 'c', answer: { answer_status: 'unknown', claims: [], limitations: [], next_steps: [] } } });
  assert.equal(s.assistant.pending, false); assert.equal(s.assistant.pendingQuestion, null); assert.equal(s.assistant.turns.length, 1); assert.equal(s.assistant.draft, '');
  assert.doesNotMatch(renderAssistant(s, null), /Thinking/);
});

test('a newer draft typed while pending survives the answer', () => {
  let s = reducer(withDraft('first'), { type: 'ASSISTANT_SUBMIT', requestId: 'r1', question: 'first' });
  s = reducer(s, { type: 'ASSISTANT', patch: { draft: 'second, typed while waiting' } });
  s = reducer(s, { type: 'ASSISTANT_RESULT', epoch: 2, generation: analysis.generation, requestId: 'r1', question: 'first', response: { context_id: 'c', answer: { answer_status: 'unknown', claims: [], limitations: [], next_steps: [] } } });
  assert.equal(s.assistant.draft, 'second, typed while waiting');
});

test('failure shows a clear error in the transcript and returns the question to an empty composer', () => {
  let s = reducer(withDraft('Why?'), { type: 'ASSISTANT_SUBMIT', requestId: 'r1', question: 'Why?' });
  s = reducer(s, { type: 'ASSISTANT_FAILED', epoch: 2, requestId: 'r1', question: 'Why?', message: 'Shorten it and ask again.' });
  assert.equal(s.assistant.draft, 'Why?'); assert.equal(s.assistant.failedQuestion, null); assert.equal(s.assistant.pending, false);
  const html = renderAssistant(s, null);
  assert.match(html, /<p class="ot-assistant-q">Why\?<\/p><p class="ot-assistant-error" role="alert">Shorten it and ask again\.<\/p>/);
  assert.doesNotMatch(html, /a-restore/);
});

test('failure never overwrites a newer draft; Restore appends the old question below it, once', () => {
  let s = reducer(withDraft('old question'), { type: 'ASSISTANT_SUBMIT', requestId: 'r1', question: 'old question' });
  s = reducer(s, { type: 'ASSISTANT', patch: { draft: 'newer draft' } });
  s = reducer(s, { type: 'ASSISTANT_FAILED', epoch: 2, requestId: 'r1', question: 'old question', message: 'It failed.' });
  assert.equal(s.assistant.draft, 'newer draft'); assert.equal(s.assistant.failedQuestion, 'old question');
  assert.match(renderAssistant(s, null), /data-action="a-restore"/);
  s = reducer(s, { type: 'ASSISTANT_RESTORE' });
  assert.equal(s.assistant.draft, 'newer draft\n\nold question'); assert.equal(s.assistant.failedQuestion, null);
  assert.equal(reducer(s, { type: 'ASSISTANT_RESTORE' }), s, 'nothing left to restore');
  assert.doesNotMatch(renderAssistant(s, null), /a-restore/);
});

test('stale responses neither clear a pending request nor restore a question', () => {
  const s = reducer(withDraft('q'), { type: 'ASSISTANT_SUBMIT', requestId: 'cur', question: 'q' });
  assert.equal(reducer(s, { type: 'ASSISTANT_FAILED', epoch: 2, requestId: 'old', question: 'x', message: 'm' }), s);
  assert.equal(reducer(s, { type: 'ASSISTANT_FAILED', epoch: 1, requestId: 'cur', question: 'x', message: 'm' }), s);
  const ended = reducer({ ...s, assistant: { ...s.assistant, pendingQuestion: 'q', failedQuestion: 'z' } }, { type: 'ANALYSIS_START' });
  assert.equal(ended.assistant.pendingQuestion, null); assert.equal(ended.assistant.failedQuestion, null);
});

test('the thinking animation has a reduced-motion rule and the dots are hidden from assistive technology', async () => {
  const { readFileSync } = await import('node:fs');
  const css = readFileSync(new URL('../../../src/ui/styles/app.css', import.meta.url), 'utf8');
  assert.match(css, /@media\(prefers-reduced-motion:reduce\)\{\.ot-assistant-dots i\{animation:none/);
  assert.match(css, /@keyframes ot-think/);
});

test('default view is compact: a limitation shows only when the answer raised one; the rest is under collapsed Details with coverage states kept distinct', () => {
  const states = { advisories: { state: 'failed', entry_count: 0, truncated: false, reason_code: 'x' }, crypto: { state: 'completed_empty', entry_count: 0, truncated: false, reason_code: null },
    dependencies: { state: 'partial', entry_count: 4, truncated: true, reason_code: 'p' } };
  const server = ['advisories: evidence state is failed (x)', 'crypto: evidence state is completed_empty', 'dependencies: evidence state is partial (p)'];
  const own = { answer_status: 'partial', claims: [{ kind: 'finding', text: 'Fact.', evidence_ids: ['ev1'] }], limitations: [{ text: 'Advisory results are missing for this package.', evidence_ids: ['st-adv'] }], next_steps: [] };
  const html = renderAssistant(turnOf({ source_states: states, limitations: server, answer: own }), null);
  const [main, details] = html.split('<details class="ot-assistant-details">');
  assert.equal((main.match(/<li>/g) || []).length - (main.match(/<option/g) || []).length, 1, 'exactly one limitation outside Details, the answer\'s own');
  assert.match(main, /Advisory results are missing for this package/); assert.doesNotMatch(main, /more limitations/); assert.doesNotMatch(main, /<details[^>]*open/);
  assert.match(details, /3 more limitations/); assert.match(details, /completed_empty/); assert.match(details, /Evidence coverage/);
  assert.match(details, /advisories:<\/strong> failed/); assert.match(details, /crypto:<\/strong> completed_empty/); assert.match(details, /dependencies:<\/strong> partial/);
  const quiet = renderAssistant(turnOf({ source_states: states, limitations: server }), null);        // the answer raised none: nothing beside the answer, nothing hidden
  const [qmain, qdetails] = quiet.split('<details class="ot-assistant-details">');
  assert.doesNotMatch(qmain, /ot-assistant-limit|Partly answered/); assert.match(qdetails, /All limitations/); assert.match(qdetails, /Advisories failed|failed/);
});

test('the subject is one short label; Explain this switches it and a clarification is a plain reply with no error styling', () => {
  const s = turnOf({});
  assert.match(renderAssistant({ ...s, assistant: { ...s.assistant, subject: { kind: 'dependency', label: 'qs 6.14.1' } } }, null), /<p class="ot-assistant-subject">About <strong>qs 6\.14\.1<\/strong><\/p>/);
  assert.match(renderAssistant({ ...s, assistant: { ...s.assistant, subject: { kind: 'analysis', label: 'x @ y' } } }, null), /<p class="ot-assistant-subject">About this analysis<\/p>/);
  let r = reducer({ ...s, epoch: 2, assistant: { ...s.assistant, pending: true, requestId: 'n1', pendingQuestion: 'What does this finding mean?' } }, { type: 'ASSISTANT_NOTE', epoch: 2, requestId: 'n1', question: 'What does this finding mean?', note: 'Which item do you mean?' });
  const html = renderAssistant(r, null);
  assert.match(html, /<p class="ot-assistant-q">What does this finding mean\?<\/p><p class="ot-assistant-reply">Which item do you mean\?<\/p>/);
  assert.equal(r.assistant.pending, false); assert.doesNotMatch(html, /ot-assistant-error/);
  assert.equal(reducer({ ...s, epoch: 2, assistant: { ...s.assistant, requestId: 'cur' } }, { type: 'ASSISTANT_NOTE', epoch: 2, requestId: 'old', question: 'q', note: 'n' }).assistant.turns.length, s.assistant.turns.length, 'stale note ignored');
});

test('Explain this keeps the typed draft, and a failed explanation never overwrites the composer', () => {
  let s = reducer({ ...initial(), analysis, epoch: 1, assistant: { ...initial().assistant, open: true, draft: 'my half-typed question' } }, { type: 'ASSISTANT_SUBMIT', requestId: 'e1', question: 'Explain qs 6.14.1', keepDraft: true });
  assert.equal(s.assistant.draft, 'my half-typed question'); assert.equal(s.assistant.pendingQuestion, 'Explain qs 6.14.1');
  s = reducer(s, { type: 'ASSISTANT_FAILED', epoch: 1, requestId: 'e1', question: 'Explain qs 6.14.1', message: 'It failed.', noRestore: true });
  assert.equal(s.assistant.draft, 'my half-typed question'); assert.equal(s.assistant.failedQuestion, null);
  assert.match(renderAssistant(s, null), /Explain qs 6\.14\.1<\/p><p class="ot-assistant-error" role="alert">It failed\./);
});

test('citations read "View evidence" and keep the record label as the tooltip', () => {
  const html = renderAssistant(turnOf({ answer: { answer_status: 'answered', claims: [{ kind: 'finding', text: 'Fact.', evidence_ids: ['ev1'] }, { kind: 'finding', text: 'Two.', evidence_ids: ['ev1', 'st-adv'] }], limitations: [], next_steps: [] } }), null);
  assert.match(html, />View evidence<\/button>/); assert.match(html, />View evidence 1<\/button>/); assert.match(html, /title="crypto\.py"/);
});

test('header and composer controls carry icons with accessible names and tooltips; Ask names its Enter shortcut', () => {
  const html = renderAssistant({ ...initial(), analysis, assistant: { ...initial().assistant, open: true } }, null);
  for (const [action, label] of [['a-position', 'Lock position'], ['a-min', 'Minimize']]) {
    const tag = html.match(new RegExp('<button[^>]*data-action="' + action + '"[^>]*>'))[0];
    assert.match(tag, new RegExp('aria-label="' + label + '"')); assert.match(tag, new RegExp('title="' + label + '"'));
    assert.match(html.split(tag)[1].split('</button>')[0], /^<svg[^>]*aria-hidden="true"/);
  }
  const locked = renderAssistant({ ...initial(), analysis, assistant: { ...initial().assistant, open: true, positionLocked: true, minimized: true } }, null);
  assert.match(locked, /aria-label="Unlock position"/); assert.match(locked, /aria-label="Expand"/);
  assert.match(html, /<button type="submit"[^>]*aria-label="Ask"[^>]*title="Ask \(Enter\)"[^>]*>Ask <svg/);
});

test('the panel body keeps its scroll position across re-renders (it is a keyed scroller), and Enter handling lives in the app with the composition guard', async () => {
  const html = renderAssistant({ ...initial(), analysis, assistant: { ...initial().assistant, open: true } }, null);
  assert.match(html, /<div class="body" data-scroll-key="assistant-body">/);
});

test('Try again appears only for a temporary busy state, never for an exhausted allowance or any other failure, and a retry replaces its failed turn', async () => {
  const fail = (code, retry) => {
    let s = { ...initial(), analysis, assistant: { ...initial().assistant, open: true, draft: 'keep me', pending: true, requestId: 'r1', pendingQuestion: 'Why?' } };
    return reducer(s, { type: 'ASSISTANT_FAILED', epoch: s.epoch, requestId: 'r1', question: 'Why?', message: 'msg ' + code, retry });
  };
  const retryOf = { ask: 'Why?', display: 'Why?', selection: null, retry: true };
  const busy = fail('broker_busy', retryOf);
  assert.match(renderAssistant(busy, null), /data-action="a-retry">Try again<\/button>/);
  assert.equal(busy.assistant.draft, 'keep me', 'the typed draft is untouched');
  assert.equal(busy.assistant.failedQuestion, null, 'the retry button replaces the restore prompt');
  for (const none of [fail('broker_allowance_exhausted', null), fail('answer_validation_failed', null), fail('broker_busy_or_budget', null)]) {   // the generic 429 code (also what an object or list in the broker's error field becomes)
    assert.doesNotMatch(renderAssistant(none, null), /Try again|a-retry/);
  }
  const again = reducer(busy, { type: 'ASSISTANT_SUBMIT', requestId: 'r2', question: 'Why?', keepDraft: true, dropFailed: true });
  assert.equal(again.assistant.turns.length, 0, 'the failed turn is replaced by the retry');
  assert.equal(again.assistant.retry, null);
  assert.equal(again.assistant.draft, 'keep me');
  const done = reducer(again, { type: 'ASSISTANT_RESULT', epoch: again.epoch, generation: analysis.generation, requestId: 'r2', question: 'Why?', response: { subject: { id: 'x' } } });
  assert.equal(done.assistant.retry, null);
  const { readFileSync } = await import('node:fs');
  const app = readFileSync(new URL('../../../src/ui/app.js', import.meta.url), 'utf8');
  assert.match(app, /err\.code === 'broker_busy' \|\| err\.code === 'assistant_busy'/, 'only the two temporary codes offer a retry');
  assert.doesNotMatch(app, /broker_busy_or_budget/, 'the generic 429 code never offers a retry');
  assert.doesNotMatch(app, /allowance_exhausted/, 'the UI never offers a retry for an exhausted allowance');
});
