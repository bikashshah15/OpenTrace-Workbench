// UIP-02 §4.2: adapters that feed the shared inspector shell. Two separate adapters, one presentation model.
//
//   fromBoundInspector(obj)  - a FULL UIP-01B `opentrace.workbench.inspector/1` object (validated elsewhere against the
//                              frozen contract). origin: 'bound_inspector'.
//   fromSelection(s, tab)    - maps the client data that exists TODAY (contexts rows, the inspected dependency, crypto/AI
//                              family nodes and checks) to a documented LOCAL presentation model. origin:
//                              'local_presentation_model'. It is NOT a validated UIP-01B payload and never claims to be:
//                              it carries no assessment digest, canonical reference, source-verification or binding field
//                              (none is manufactured). Genuine analysis identity (revision, generation, mode) is shown as
//                              plain text in Sources & coverage.
//
// Presentation model:
//   { origin, id, tab, type, title, subtitle, badge:{kind,label}, question_set,
//     answers:[{question_id,label,state,body,missing:[string]}],
//     evidence_rows:[{label,state,text}], sources:[string], actions:[{id,label,attrs}], next_step, technical:[[label,value]] }
// Every unknown / not-assessed answer names what evidence is missing.
import { reasonText } from '../components/lookup.js';
import { fmt } from './util.js';
import { findSelection } from './context_map.js';
import { ATTRIBUTE_LABELS } from './ai_graph.js';
import { bomSelectedItem } from './store.js';

export const QUESTION_LABEL = {
  what_is_this: 'What is this?', why_here: 'Why is it here?', security_concern: 'Is there a security concern?',
  comparison_established: 'What did the comparison establish?', what_unknown: 'What remains unknown?',
};
export const QUESTION_ORDER = {
  context_four: ['what_is_this', 'why_here', 'security_concern', 'what_unknown'],
  bom_comparison: ['what_is_this', 'why_here', 'comparison_established', 'what_unknown'],
};

// Seven visual symbols (report §5.7) mapped from the fourteen contract states. `tone` selects the palette variable.
export const STATE_META = {
  source_checked: { sym: 'checked', tone: 'checked', label: 'Source checked' },
  inventory_reported: { sym: 'reported', tone: 'reported', label: 'Inventory reported' },
  declared: { sym: 'reported', tone: 'reported', label: 'Declared' },
  captured: { sym: 'reported', tone: 'reported', label: 'Captured' },
  represented: { sym: 'reported', tone: 'reported', label: 'Represented' },
  unknown: { sym: 'unknown', tone: 'unknown', label: 'Unknown' },
  cannot_establish: { sym: 'unknown', tone: 'unknown', label: 'Cannot establish' },
  not_assessed: { sym: 'hollow', tone: 'neutral', label: 'Not assessed' },
  no_rule: { sym: 'hollow', tone: 'neutral', label: 'No rule' },
  not_applicable: { sym: 'dash', tone: 'neutral', label: 'Not applicable' },
  needs_review: { sym: 'warning', tone: 'review', label: 'Needs review' },
  not_represented: { sym: 'warning', tone: 'review', label: 'Not represented' },
  conflicting_evidence: { sym: 'warning', tone: 'review', label: 'Conflicting evidence' },
  advisory_match: { sym: 'alert', tone: 'advisory', label: 'Advisory match' },
};
export const stateMeta = (state) => STATE_META[state] || STATE_META.unknown;

const ACTION_LABEL = { source_access: 'Source access', advisory_access: 'Advisory access', ask_about_this: 'Explain this', download_artifact: 'Download artifact', open_graph: 'Open graph' };

// ------------------------------------------------------------------ bound (full UIP-01B object)
export function fromBoundInspector(o) {
  const b = o.badge || {};
  return {
    origin: 'bound_inspector', id: o.selection?.id ?? '', tab: o.tab, type: String(o.selection?.kind || '').replaceAll('_', ' '),
    title: o.title, subtitle: '', badge: { kind: b.kind || 'neutral', label: b.label || '' }, question_set: o.question_set,
    answers: (o.answers || []).map((a) => ({ question_id: a.question_id, label: QUESTION_LABEL[a.question_id] || a.question_id, state: a.state, body: a.body, missing: [] })),
    evidence_rows: (o.evidence_rows || []).map((r) => ({ label: r.label, state: r.status, text: r.detail || '' })),
    sources: o.sources_coverage?.available ? [...(o.sources_coverage.items || [])] : [],
    // Only 'ask_about_this' has a handler today; the others render disabled with a reason (no dead buttons).
    actions: (o.actions || []).map((id) => (id === 'ask_about_this' ? { id: 'ask', label: ACTION_LABEL[id], attrs: { 'data-action': 'ask' } } : { id, label: ACTION_LABEL[id] || id, disabled: 'Not connected in this view yet.' })),
    next_step: o.next_step || null, technical: [],
  };
}

// ------------------------------------------------------------------ local presentation model (existing data)
const ans = (question_id, state, body, missing = []) => ({ question_id, label: QUESTION_LABEL[question_id], state, body, missing });
const ASK = { id: 'ask', label: ACTION_LABEL.ask_about_this, attrs: { 'data-action': 'ask' } };
const EVIDENCE = { id: 'ctx-evidence', label: 'Inspect evidence ↗', attrs: { 'data-action': 'ctx-evidence' } };
const identityLine = (a) => {
  const id = a?.identity || {};
  const bits = [id.commit ? `Revision ${String(id.commit).slice(0, 12)}` : null, a?.generation != null ? `analysis generation ${a.generation}` : null, id.mode ? `${id.mode} analysis` : null].filter(Boolean);
  return bits.length ? bits.join(' · ') + '.' : '';
};
const ownerName = (a) => (a?.identity?.owner && a?.identity?.name ? `${a.identity.owner}/${a.identity.name}` : a?.identity?.name || 'This repository');
const plural = (n, w) => `${fmt(n)} ${w}${n === 1 ? '' : /(ch|sh|s|x)$/.test(w) ? 'es' : 's'}`;

// UIP-04: the contexts adapter reads the merged `opentrace.workbench.contexts/1` payload (views.contexts). Every number is a distinct
// component-record count unless it is labelled as file memberships; nothing is inferred beyond the recorded locations.
const BASIS_TEXT = { path_prefix: 'a leading path segment', manifest_basename: 'a package or build manifest file name', ecosystem: 'a package ecosystem', fallback: 'no more specific rule' };
const EVIDENCE_FACT = 'Installation, builds and execution were not observed. Source locations are the recorded inventory locations for this analysis; the groups are a display grouping, not an analysis of runtime behavior.';
const locatedGroups = (v) => v.groups.filter((g) => g.kind === 'located');
function contexts(s) {
  const v = s.views.contexts; if (!v) return null;
  const sel = s.workbench.perTab.contexts.selection; if (!sel) return null;
  const a = s.analysis; const idl = identityLine(a);
  const base = { origin: 'local_presentation_model', tab: 'contexts', subtitle: '', badge: { kind: 'context', label: 'Repository context' }, question_set: 'context_four', next_step: null, technical: [] };
  const sec = ans('security_concern', 'not_applicable', 'This record is not a security assessment. Package and asset findings are in their own views.');
  const unk = ans('what_unknown', 'not_assessed', 'Runtime use, installation and deployed configuration are not established.', ['runtime observation', 'a build or installation record']);
  const found = findSelection(v, sel); if (!found) return null;
  const { root } = v;
  if (found.kind === 'root') {
    const locations = locatedGroups(v).reduce((n, g) => n + (g.files_counts?.total ?? g.files.length), 0);
    return { ...base, id: 'root', type: 'Repository', title: root.name, answers: [
      ans('what_is_this', 'inventory_reported', `The pinned repository revision ${root.commit_sha.slice(0, 12)} that anchors every record in this analysis.`),
      ans('why_here', 'inventory_reported', `${plural(root.distinct_total, 'distinct component record')}: ${fmt(root.located_distinct_total)} with a recorded source location across ${plural(locations, 'source location')} and ${fmt(root.unlocated_total)} without one. This is a partial source inventory, not a map of every repository file.`),
      sec, unk],
    evidence_rows: [{ label: 'Distinct component records', state: 'inventory_reported', text: fmt(root.distinct_total) }, { label: 'With a recorded location', state: 'inventory_reported', text: fmt(root.located_distinct_total) },
      { label: 'Without a recorded location', state: root.unlocated_total ? 'unknown' : 'inventory_reported', text: fmt(root.unlocated_total) }, { label: 'File memberships', state: 'inventory_reported', text: fmt(root.membership_total) }, { label: 'Security assessment', state: 'not_assessed', text: '' }],
    sources: [idl, 'File memberships exceed distinct component records where a component is recorded in more than one file.', EVIDENCE_FACT].filter(Boolean), actions: [EVIDENCE, ASK] };
  }
  if (found.kind === 'unlocated') {
    const g = found.group;
    return { ...base, id: g.group_id, type: 'No location', title: g.label, answers: [
      ans('what_is_this', 'inventory_reported', `${plural(g.distinct_total, 'component record')} with no recorded source-file location.`),
      ans('why_here', 'unknown', 'They are in the inventory but carry no source location, so no context is claimed and none is invented.', ['a recorded source location']), sec, unk],
    evidence_rows: [{ label: 'Component records', state: 'inventory_reported', text: fmt(g.distinct_total) }, { label: 'Source location', state: 'unknown', text: '' }],
    sources: [idl, EVIDENCE_FACT].filter(Boolean), actions: [EVIDENCE, ASK] };
  }
  if (found.kind === 'group') {
    const g = found.group; const n = g.files_counts?.total ?? g.files.length;
    const memberships = g.membership_total > g.distinct_total ? ` ${fmt(g.membership_total)} file memberships in total (a component recorded in several files is counted in each).` : '';
    return { ...base, id: g.group_id, type: 'Context group', title: g.label, answers: [
      ans('what_is_this', 'inventory_reported', `A display grouping of source locations by ${BASIS_TEXT[g.basis] || 'path'}.`),
      ans('why_here', 'inventory_reported', `${plural(g.distinct_total, 'distinct component record')} refer${g.distinct_total === 1 ? 's' : ''} to ${plural(n, 'source location')} in this group.${memberships} File counts may overlap; this grouping does not establish installation, workflow execution or service topology.`),
      sec, unk],
    evidence_rows: [{ label: 'Distinct component records', state: 'inventory_reported', text: fmt(g.distinct_total) }, { label: 'Source locations', state: 'inventory_reported', text: fmt(n) },
      ...(g.membership_total > g.distinct_total ? [{ label: 'File memberships', state: 'inventory_reported', text: fmt(g.membership_total) }] : []), { label: 'Security assessment', state: 'not_assessed', text: '' }],
    sources: [idl, EVIDENCE_FACT].filter(Boolean), actions: [EVIDENCE, ASK] };
  }
  const { file, group } = found; const more = Math.max(0, file.raw_locations_total - file.raw_locations.length);
  return { ...base, id: file.file_id, type: 'Source file', title: file.path, answers: [
    ans('what_is_this', 'inventory_reported', `A source location recorded for ${plural(file.distinct_total, 'distinct component record')}.`),
    ans('why_here', 'inventory_reported', `Recorded location${file.raw_locations_total === 1 ? '' : 's'}: ${file.raw_locations.join(', ')}${more ? ` and ${more} more not shown` : ''}. Counts can overlap with other contexts; contexts are not additional repositories.`),
    sec, unk],
  evidence_rows: [{ label: 'Distinct component records', state: 'inventory_reported', text: fmt(file.distinct_total) }, ...(file.membership_total !== file.distinct_total ? [{ label: 'File memberships', state: 'inventory_reported', text: fmt(file.membership_total) }] : []),
    { label: 'Source location', state: 'inventory_reported', text: file.path }, { label: 'Group', state: 'inventory_reported', text: group.label }, { label: 'Security assessment', state: 'not_assessed', text: '' }],
  sources: [`Normalization: ${(file.normalization_basis || []).join(', ') || 'none recorded'}. Lines show grouping and membership only, not dependency or runtime relationships.`, idl, EVIDENCE_FACT].filter(Boolean),
  actions: [{ id: 'drill', label: 'Explore components →', attrs: { 'data-action': 'drill', 'data-path': file.path, 'data-dependency-context-id': file.dependency_context_id || '' } }, EVIDENCE, ASK] };
}

// The component-level advisory state. Returns { kind, badge, answer, row } from the SAME facts so the three can never disagree.
//   match | no_match | unavailable | not_looked_up | not_run | unknown_coverage
// Captured analyses carry no per-component coverage record unless the view supplies `advisory_lookup` explicitly; without it
// an empty match list is "unknown coverage", never a completed negative.
const NOT_CONFIRMED = 'An advisory match is not confirmed exploitability.';
const NO_ABSENCE = 'No match does not establish absence of vulnerabilities.';
export function advisoryState({ adv, live, lookup, k }) {
  const where = live ? 'this analysis’s OSV lookup' : 'the captured OSV query';
  const mk = (kind, badgeKind, badgeLabel, state, body, missing, row) => ({ kind, badge: { kind: badgeKind, label: badgeLabel }, answer: ans('security_concern', state, body, missing), row });
  if (adv.length) return mk('match', 'advisory', 'Advisory match', 'advisory_match', `${plural(adv.length, 'advisory match')} for the reported version in ${where}. ${NOT_CONFIRMED}`, ['reachability', 'exploitability in this application'], plural(adv.length, 'advisory match'));
  if (live && !lookup) return mk('not_run', 'neutral', 'Not assessed', 'not_assessed', 'Advisory matching was not run for this analysis.', ['an advisory lookup'], 'Advisory matching not run');
  const s = k && k.state;
  if (s === 'unavailable') return mk('unavailable', 'neutral', 'Lookup unavailable', 'unknown', `The lookup for this version did not complete (${reasonText(k.reason)}), so nothing is established either way.`, ['a completed advisory lookup for this version'], 'Lookup unavailable');
  if (s === 'not_looked_up') return mk('not_looked_up', 'neutral', 'Not looked up', 'not_assessed', 'This version was not looked up.', ['an advisory lookup result for this version'], 'Not looked up');
  if (s === 'no_match') return mk('no_match', 'neutral', live ? 'No match returned' : 'No match in captured query', live ? 'inventory_reported' : 'captured', `No advisory was returned by ${where} for the reported version. ${NO_ABSENCE}`, [], live ? 'No advisory returned' : 'No match in captured query');
  return mk('unknown_coverage', 'neutral', 'Coverage not recorded', 'unknown', live ? 'This version was not covered by the advisory lookup, or its result was not recorded.' : 'No advisory match is attached to this record, and the captured data does not record whether this version was queried. No negative result is claimed.', ['a per-version advisory lookup record'], 'Coverage not recorded');
}

function dependency(s) {
  const d = s.workbench.perTab.dependencies; const x = s.views.dependencies?.inspected; if (!x) return null;
  const a = s.analysis; const live = a?.identity?.mode === 'live'; const lookup = a?.summary?.advisory_lookup || null;
  const c = x.component; const adv = x.advisories || [];
  const eco = (c.bom_ref || '').startsWith('pkg:npm') ? 'NPM' : (c.bom_ref || '').startsWith('pkg:pypi') ? 'PYPI' : (c.type || '').toUpperCase();
  // ONE component-level advisory state drives the badge, the security answer and the evidence row (UIP-02-IR-01).
  // An empty match list alone never establishes that this component was queried.
  const adv_state = advisoryState({ adv, live, lookup, k: x.advisory_lookup });
  const sec = adv_state.answer;
  return { origin: 'local_presentation_model', id: c.id, tab: 'dependencies', type: 'Selected software component', title: c.name, subtitle: `${c.version || 'Version not reported'} · ${eco}`,
    badge: adv_state.badge, question_set: 'context_four', answers: [
      ans('what_is_this', 'inventory_reported', `A component record with reported version ${c.version || '(not reported)'}. It depends on ${x.depends_on} and is used by ${x.used_by} within the selected context.`),
      ans('why_here', 'inventory_reported', c.locations.length ? `Appears in ${c.locations[0]}${c.locations.length > 1 ? ` and ${c.locations.length - 1} other source location${c.locations.length === 2 ? '' : 's'}` : ''}. Arrows mean “declares a dependency on”.` : 'Recorded in the software inventory; no source location was captured.'),
      sec,
      ans('what_unknown', 'unknown', 'Installation, reachability and exploitability are not established; source records do not establish runtime use.', ['runtime or installation observation', 'reachability analysis'])],
    evidence_rows: [{ label: 'SBOM component', state: 'inventory_reported', text: c.version || '' }, { label: 'Source location', state: c.locations.length ? 'inventory_reported' : 'unknown', text: c.locations[0] || '' }, { label: 'Advisory query', state: sec.state, text: adv_state.row }],
    sources: [`Source: ${c.locations.join(', ') || 'no captured source location'}. Counts are within the selected context.`, identityLine(a)].filter(Boolean),
    actions: [ASK], next_step: null, technical: [['Record', c.id], ['bom-ref', c.bom_ref || '—'], ...(s.views.dependencies?.inspector && s.views.dependencies.inspector.pointer !== undefined ? [['Pointer', s.views.dependencies.inspector.pointer || '']] : [])] };
}

export const EXCERPT_PREVIEW = 380;
const CHECK_STATE = { supported: 'represented', contradicted: 'not_represented', unverifiable: 'cannot_establish', inconclusive: 'cannot_establish' };

function family(s, tab) {
  const v = s.views[tab]; if (!v) return null;
  const sel = s.workbench.perTab[tab].selection; const n = v.nodes.find((x) => x.id === sel); if (!n) return null;
  const a = s.analysis; const idl = identityLine(a);
  const plainId = n.id.replace(/^(assertion|evidence|entity):/, '');
  if (n.type === 'assertion') {
    const c = (v.checks || []).find((k) => 'assertion:' + k.assertion_id === n.id); if (!c) return null;
    const st = CHECK_STATE[c.state] || 'cannot_establish';
    const ev = (list) => (list || []).map((e) => `${e.evidence_id}${e.role ? ' (' + e.role + ')' : ''}`).join(', ') || 'none';
    const ne = c.not_established || [];
    return { origin: 'local_presentation_model', id: n.id, tab, type: 'Selected comparison', title: c.assertion_id, subtitle: c.rule_id ? `Rule ${c.rule_id}` : '', badge: { kind: st === 'represented' ? 'inventory' : 'review', label: String(c.state || '').replaceAll('_', ' ') },
      // UIP-02-IR-03: only the BOM tab substitutes the comparison question; crypto/AI keep the four approved questions and
      // explain the recorded comparison inside the security answer.
      question_set: tab === 'bom' ? 'bom_comparison' : 'context_four', answers: [
        ans('what_is_this', 'declared', c.bounded_meaning || 'A bounded comparison of a declaration against an inventory record.'),
        ans('why_here', 'inventory_reported', `Records used: ${ev(c.used_evidence)}.`),
        tab === 'bom' ? ans('comparison_established', st, c.rationale || 'No rationale was recorded.', st === 'cannot_establish' ? ne.slice(0, 2) : [])
          : ans('security_concern', st, `Recorded comparison: ${String(c.state || 'unknown').replaceAll('_', ' ')}. ${c.rationale || 'No rationale was recorded.'} This is a comparison of a declaration against recorded evidence, not a vulnerability finding or a security score; it does not show how the software behaves when run.`, st === 'cannot_establish' ? ne.slice(0, 2) : []),
        ans('what_unknown', ne.length ? 'unknown' : 'not_assessed', ne.length ? ne.join('; ') + '.' : 'No limitation was recorded for this check.', ne.length ? [] : ['a recorded coverage statement'])],
      evidence_rows: [...(c.used_evidence || []).map((e) => ({ label: e.evidence_id, state: 'captured', text: e.role || 'used' })), ...(c.excluded_evidence || []).map((e) => ({ label: e.evidence_id, state: 'not_applicable', text: 'excluded' }))].slice(0, 20),
      sources: [`Records used: ${ev(c.used_evidence)}`, `Records excluded: ${ev(c.excluded_evidence)}`, ...(c.next_action ? [`Next: ${c.next_action}`] : []), idl].filter(Boolean),
      actions: [ASK], next_step: c.next_action || null, technical: [['Assertion', c.assertion_id], ['Rule', c.rule_id || 'none'], ['Reason codes', (c.reason_codes || []).join(', ')]] };
  }
  if (n.type === 'evidence') {
    const loc = n.observation?.artifact?.locator; const exc = n.observation?.excerpt;
    const cps = exc ? [...exc] : []; const cut = cps.length > EXCERPT_PREVIEW;
    const locText = loc ? `${loc}${n.observation.lines ? ' lines ' + n.observation.lines.join('–') : ''}` : '';
    return { origin: 'local_presentation_model', id: n.id, tab, type: `${(n.origin || '').toUpperCase()} · ${n.method || ''}`.trim(), title: plainId, subtitle: '', badge: { kind: 'neutral', label: 'Record' }, question_set: 'context_four', answers: [
      ans('what_is_this', 'inventory_reported', 'A captured evidence record.'),
      ans('why_here', 'inventory_reported', loc ? `Source: ${loc}${n.observation.lines ? ' lines ' + n.observation.lines.join('–') : ''}.` : 'Used by a displayed check; no source locator was recorded.', loc ? [] : ['a source locator']),
      ans('security_concern', 'not_applicable', 'An evidence record carries no standalone security verdict.'),
      ans('what_unknown', (n.limitations || []).length ? 'unknown' : 'not_assessed', (n.limitations || []).join(' ') || 'No limitation was recorded for this record.', (n.limitations || []).length ? [] : ['a recorded limitation statement'])],
    evidence_rows: [
      loc ? { label: 'Source location', state: 'captured', text: locText } : { label: 'Source location', state: 'unknown', text: 'No source locator was recorded for this record.' },
      ...(exc ? [{ label: 'Excerpt', state: 'captured', text: cut ? cps.slice(0, EXCERPT_PREVIEW).join('') + '…' : exc, ...(cut ? { full: exc, omitted: cps.length - EXCERPT_PREVIEW } : {}) }] : [])],
    sources: [...(n.limitations || []), idl].filter(Boolean), actions: [ASK], next_step: null, technical: [['Record', n.id], ['Scope', n.scope?.revision || '']] };
  }
  if (n.type === 'entity') {
    return { origin: 'local_presentation_model', id: n.id, tab, type: `${(n.origin || '').toUpperCase()} · ${n.kind || ''}`.trim(), title: n.name || plainId, subtitle: n.version ? `Version ${n.version}` : '', badge: { kind: 'neutral', label: 'Record' }, question_set: 'context_four', answers: [
      ans('what_is_this', 'inventory_reported', `${n.version ? 'Version ' + n.version + '. ' : ''}A declared or observed record; it does not by itself establish identity with another record.`),
      ans('why_here', n.source ? 'inventory_reported' : 'unknown', n.source ? `Inventory ${n.source.inventory_id}${n.source.raw_pointer ? ' · ' + n.source.raw_pointer : ''}.` : 'No inventory source was recorded for this entity.', n.source ? [] : ['an inventory source reference']),
      ans('security_concern', 'not_applicable', 'An entity record carries no standalone security verdict.'),
      ans('what_unknown', 'not_assessed', 'Runtime use, deployment and execution are not established by this record.', ['runtime observation'])],
    evidence_rows: [], sources: [n.source ? `Inventory ${n.source.inventory_id}${n.source.raw_pointer ? ' · ' + n.source.raw_pointer : ''}` : '', idl].filter(Boolean), actions: [ASK], next_step: null, technical: [['Record', n.id]] };
  }
  return null;
}

// UIP-06 (FD-6): the Cryptography adapter reads one crypto_assets/1 page (views.cryptoPage). Local presentation model only; the frozen
// kinds asset / group / occurrence / review_item are the payload's own records. Nothing is invented: a name alone is never a finding.
const cryptoWhere = (a) => a.occurrences.map((o) => `${o.source_location.path}${o.source_location.line_start ? ':' + o.source_location.line_start : ''}`);
// Rule results move out of the answer body into a disclosure; the answer itself stays one conclusion-first sentence.
const reviewDetail = (reviews) => reviews.flatMap((r, i) => [`${r.rule_id} v${r.rule_version} · ${r.condition}`, i === 0 ? '' : r.bounded_meaning, r.rationale, r.next_action ? `Next: ${r.next_action}` : '', (r.evidence_ids || []).length ? `Evidence: ${r.evidence_ids.join(', ')}` : ''].filter(Boolean));
const reviewAnswer = (reviews) => ({ ...ans('security_concern', 'needs_review', `${reviews[0].bounded_meaning || reviews[0].condition}${reviews.length > 1 ? ` ${plural(reviews.length - 1, 'more review item')} ${reviews.length === 2 ? 'is' : 'are'} recorded.` : ''}`, []), detail: reviewDetail(reviews), detail_label: 'Rule result and rationale' });
const revisionSub = (b) => `Revision ${String(b.commit_sha).slice(0, 7)}`;
function cryptoModel(s, page, sel) {
  const a = s.analysis; const idl = identityLine(a); const b = page.binding;
  const base = { origin: 'local_presentation_model', tab: 'crypto', subtitle: revisionSub(b), question_set: 'context_four', next_step: null, technical: [] };
  const asset = page.assets.find((x) => 'asset:' + x.asset_id === sel);
  if (asset) {
    const reviews = page.review_items.filter((r) => r.asset_id === asset.asset_id); const where = cryptoWhere(asset); const exp = asset.provenance.experimental;
    const more = asset.occurrences_total > asset.occurrences.length ? ` (${asset.occurrences.length} of ${asset.occurrences_total} shown; the original CBOM lists all)` : '';
    const sec = reviews.length
      ? reviewAnswer(reviews)
      : ans('security_concern', 'not_assessed', 'No implemented rule produced a review for this asset. This is not a statement that it is safe or unsafe; an algorithm name alone is not a finding.', ['an implemented rule for this asset']);
    const unkBody = ['Runtime use is not observed.', exp ? 'Call sites elsewhere are not ruled out.' : '', asset.occurrences_total > asset.occurrences.length ? `Only ${asset.occurrences.length} of ${asset.occurrences_total} locations are listed here.` : '', where.length ? '' : 'No source location is recorded.'].filter(Boolean).join(' ');
    const unk = ans('what_unknown', 'unknown', unkBody, ['runtime observation', ...(where.length ? [] : ['a recorded source location'])]);
    return { ...base, id: asset.asset_id, type: 'Cryptographic asset', title: asset.display_name, badge: { kind: reviews.length ? 'review' : 'inventory', label: reviews.length ? 'Needs review' : (exp ? 'Experimental observation' : 'Recorded asset') }, answers: [
      ans('what_is_this', exp ? 'declared' : 'inventory_reported', `${exp ? 'An experimental source observation of' : 'A recorded'} ${asset.kind.replaceAll('_', ' ')} asset${exp ? ' (listed call sites only; absence elsewhere is not established)' : ' from the original CBOM'}.`),
      where.length ? ans('why_here', 'inventory_reported', `Recorded at ${plural(asset.occurrences_total, 'source location')}: ${where.slice(0, 5).join(', ')}${where.length > 5 ? ` and ${where.length - 5} more` : ''}${more}.`)
        : ans('why_here', 'unknown', 'The CBOM entry records no source file, so no location is claimed and none is guessed.', ['a recorded source location']),
      sec, unk],
    evidence_rows: [...reviews.flatMap((r) => (r.evidence_ids || []).map((id) => ({ label: 'Review evidence', state: 'captured', text: id }))), ...where.slice(0, 20).map((w) => ({ label: 'Source location', state: exp ? 'declared' : 'captured', text: w }))].slice(0, 40),
    sources: [`Producer: ${asset.provenance.producer_version || asset.provenance.producer_id}${exp ? ' (experimental)' : ''}.`, `Origin: ${exp ? 'experimental source observation' : 'original CBOM'}; kind: ${asset.kind.replaceAll('_', ' ')}.`, ...(exp ? ['Experimental source observation of the listed call sites; absence elsewhere is not established.'] : []), idl, `Static observation of recorded data at ${String(b.commit_sha).slice(0, 7)}. Runtime execution was not observed.`].filter(Boolean),
    actions: [ASK], next_step: reviews[0]?.next_action || null, technical: [['Asset', asset.asset_id], ['Producer', asset.provenance.producer_id], ['Pointer', asset.provenance.json_pointer || '—']] };
  }
  const group = page.source_groups.find((g) => 'group:' + g.group_id === sel);
  if (group) {
    return { ...base, id: group.group_id, type: 'Source group', title: group.label, badge: { kind: 'context', label: 'Source group' }, answers: [
      ans('what_is_this', 'inventory_reported', `A display grouping of recorded cryptographic-asset locations${group.path ? ' in ' + group.path : ''}.`),
      ans('why_here', 'inventory_reported', `${plural(group.assets_total, 'recorded asset')} name this location. The grouping does not establish dependency or runtime relationships.`),
      ans('security_concern', 'not_applicable', 'A source group is not a security assessment.'),
      ans('what_unknown', 'not_assessed', 'Whether the assets recorded here are used together, or used at all at run time, is not established.', ['runtime observation'])],
    evidence_rows: [{ label: 'Recorded assets', state: 'inventory_reported', text: fmt(group.assets_total) }, { label: 'Source location', state: group.path ? 'inventory_reported' : 'unknown', text: group.path || '' }],
    sources: [idl].filter(Boolean), actions: [ASK], technical: [['Group', group.group_id]] };
  }
  return { ...base, id: 'root', type: 'Repository', title: `${b.repository.owner}/${b.repository.name}`, badge: { kind: 'context', label: 'Repository' }, answers: [
    ans('what_is_this', 'inventory_reported', `The pinned revision ${b.commit_sha.slice(0, 12)} that anchors every recorded cryptographic asset.`),
    ans('why_here', 'inventory_reported', `${plural(page.filter_totals.all, 'recorded cryptographic asset')} and ${plural(page.services_counts.total, 'endpoint service')}. ${page.availability.message}`),
    ans('security_concern', 'not_applicable', 'The repository is not itself assessed here.'),
    ans('what_unknown', 'unknown', 'Cryptographic use that is not recorded in the CBOM or a source observation is not established, and runtime execution was not observed.', ['runtime observation'])],
  evidence_rows: [{ label: 'Recorded assets', state: 'inventory_reported', text: fmt(page.filter_totals.all) }, { label: 'Review items', state: page.filter_totals.findings ? 'needs_review' : 'not_assessed', text: fmt(page.filter_totals.findings) }, { label: 'Endpoint services', state: 'inventory_reported', text: fmt(page.services_counts.total) }],
  sources: [idl].filter(Boolean), actions: [ASK], technical: [] };
}
export function fromCrypto(s, page, sel) { return s.analysis && page ? cryptoModel(s, page, sel) : null; }

// UIP-07 (FD-6): the AI models adapter reads one ai_assets/1 page (views.aiPage). Local presentation model only; the frozen kinds asset / group /
// occurrence / review_item are the payload's own records. Nothing is invented: a model name or file name is never a verified identity, and a
// model security finding is "not assessed" unless a rule-backed review item exists.
const AI_WHAT = {
  inventory_model: 'A model reported by the AI-BOM inventory. A name or file name is not a verified model identity.',
  model_reference: 'A model reference declared in the repository. A declared location is not a fetched or verified model.',
  model_artifact: 'A model file recorded by a producer that read its bytes.',
  runtime: 'A runtime import or declaration seen by an experimental source observation. It does not show that the runtime is installed or active.',
  ai_service: 'An AI service reference seen by an experimental source observation. It does not show that the service is called.',
};
const AI_UNKNOWN = {
  inventory_model: 'Which model is actually loaded, and whether this inventory entry matches repository code, are not established.',
  model_reference: 'Whether the declared location was fetched, or the referenced model was loaded, is not established.',
  model_artifact: 'Whether this file is the model used at run time is not established.',
  runtime: 'Whether this runtime is installed or active is not established.',
  ai_service: 'Whether this service is called, and which model it serves, are not established.',
};
function aiModel(s, page, sel) {
  const a = s.analysis; const idl = identityLine(a); const b = page.binding;
  const base = { origin: 'local_presentation_model', tab: 'ai', subtitle: revisionSub(b), question_set: 'context_four', next_step: null, technical: [] };
  const asset = page.assets.find((x) => 'asset:' + x.asset_id === sel);
  if (asset) {
    const reviews = page.review_items.filter((r) => r.asset_id === asset.asset_id); const where = cryptoWhere(asset); const exp = asset.provenance.experimental;
    const more = asset.occurrences_total > asset.occurrences.length ? ` (${asset.occurrences.length} of ${asset.occurrences_total} shown; the AI-BOM lists all)` : '';
    const sec = reviews.length
      ? reviewAnswer(reviews)
      : ans('security_concern', 'not_assessed', 'Model and service security findings are not assessed in this view. This is not a statement that the model is safe or unsafe.', ['a rule-backed review for this asset']);
    const digest = asset.attributes.artifact_digest;
    const unrecorded = Object.entries(ATTRIBUTE_LABELS).filter(([k]) => !(asset.attributes[k] && asset.attributes[k].state === 'recorded')).map(([, label]) => label.toLowerCase());   // 'unknown' and 'not recorded' alike: no recorded value (Asset metadata shows which)
    const unresolved = asset.identity_state !== 'resolved';
    const unkBody = [AI_UNKNOWN[asset.kind] || 'Runtime use is not established.', unresolved ? 'A name, file name or URL is not a verified model identity.' : '', unrecorded.length ? `No recorded value for: ${unrecorded.join(', ')}.` : '', 'Runtime execution was not observed.'].filter(Boolean).join(' ');
    const unk = ans('what_unknown', 'unknown', unkBody, [...(unresolved ? ['a verified model identity'] : []), ...unrecorded.map((u) => `recorded ${u}`), 'runtime observation']);
    return { ...base, id: asset.asset_id, type: 'AI asset', title: asset.display_name, badge: { kind: reviews.length ? 'review' : 'inventory', label: reviews.length ? 'Needs review' : (exp ? 'Experimental observation' : 'Inventory-reported') }, answers: [
      ans('what_is_this', exp ? 'declared' : 'inventory_reported', AI_WHAT[asset.kind] || 'A recorded AI asset.'),
      where.length ? ans('why_here', 'inventory_reported', `Recorded at ${plural(asset.occurrences_total, 'repository location')}: ${where.slice(0, 5).join(', ')}${where.length > 5 ? ` and ${where.length - 5} more` : ''}${more}.`)
        : ans('why_here', 'unknown', 'The AI-BOM entry records no repository location, so no location is claimed and none is guessed.', ['a recorded repository location']),
      sec, unk],
    evidence_rows: [...reviews.flatMap((r) => (r.evidence_ids || []).map((id) => ({ label: 'Review evidence', state: 'captured', text: id }))),
      ...(digest && digest.state === 'recorded' ? [{ label: 'Recorded hash', state: 'inventory_reported', text: `${digest.value} (not a verified model digest)` }] : []),
      ...where.slice(0, 20).map((w) => ({ label: 'Repository location', state: exp ? 'declared' : 'inventory_reported', text: w }))].slice(0, 40),
    sources: [`Producer: ${asset.provenance.producer_version || asset.provenance.producer_id}${exp ? ' (experimental)' : ''}.`, `Origin: ${exp ? 'experimental source observation' : 'AI-BOM inventory'}; kind: ${asset.kind.replaceAll('_', ' ')}.`, ...(exp ? ['Experimental source observation; absence elsewhere is not established.'] : []), ...(asset.identity_state === 'resolved' ? ['Identity: resolved by recorded evidence.'] : []), ...(asset.display_group ? [`Listed together with other assets of the same name (${asset.display_group.rule}).`] : []), idl, `Static observation of recorded data at ${String(b.commit_sha).slice(0, 7)}. Runtime execution was not observed.`].filter(Boolean),
    actions: [ASK], next_step: reviews[0]?.next_action || null, technical: [['Asset', asset.asset_id], ['Producer', asset.provenance.producer_id], ['Pointer', asset.provenance.json_pointer || '—'], ['Identity', asset.identity_state]] };
  }
  const group = page.source_groups.find((g) => 'group:' + g.group_id === sel);
  if (group) {
    return { ...base, id: group.group_id, type: 'Source group', title: group.label, badge: { kind: 'context', label: 'Source group' }, answers: [
      ans('what_is_this', 'inventory_reported', `A display grouping of recorded AI-asset locations${group.path ? ' in ' + group.path : ''}.`),
      ans('why_here', 'inventory_reported', `${plural(group.assets_total, 'recorded asset')} name this location. The grouping does not establish dependency or runtime relationships.`),
      ans('security_concern', 'not_applicable', 'A source group is not a security assessment.'),
      ans('what_unknown', 'not_assessed', 'Whether the assets recorded here are used together, or used at all at run time, is not established.', ['runtime observation'])],
    evidence_rows: [{ label: 'Recorded assets', state: 'inventory_reported', text: fmt(group.assets_total) }, { label: 'Repository location', state: group.path ? 'inventory_reported' : 'unknown', text: group.path || '' }],
    sources: [idl].filter(Boolean), actions: [ASK], technical: [['Group', group.group_id]] };
  }
  return { ...base, id: 'root', type: 'Repository', title: `${b.repository.owner}/${b.repository.name}`, badge: { kind: 'context', label: 'Repository' }, answers: [
    ans('what_is_this', 'inventory_reported', `The pinned revision ${b.commit_sha.slice(0, 12)} that anchors every recorded AI asset.`),
    ans('why_here', 'inventory_reported', `${plural(page.filter_totals.all, 'recorded AI asset')}. ${page.availability.message}`),
    ans('security_concern', 'not_applicable', 'The repository is not itself assessed here.'),
    ans('what_unknown', 'unknown', 'Which model is loaded, its provider, version and license, and runtime use are not established by this summary. Runtime execution was not observed.', ['a verified model identity', 'runtime observation'])],
  evidence_rows: [{ label: 'Recorded assets', state: 'inventory_reported', text: fmt(page.filter_totals.all) }, { label: 'Review items', state: page.filter_totals.findings ? 'needs_review' : 'not_assessed', text: fmt(page.filter_totals.findings) }],
  sources: [idl].filter(Boolean), actions: [ASK], technical: [] };
}
export function fromAi(s, page, sel) { return s.analysis && page ? aiModel(s, page, sel) : null; }

// The model for the CURRENT selection of `tab`, or null (render the empty prompt). A selection that does not exist in the
// current analysis's views (e.g. left over from a previous analysis) yields null, never the old record.
export function fromSelection(s, tab) {
  if (!s.analysis) return null;
  if (tab === 'contexts') return contexts(s);
  if (tab === 'dependencies') return dependency(s);
  return family(s, tab);
}

// ------------------------------------------------------------------ ACTIVE BOM workspace (UIP-08 bound payloads)
// Three selection kinds, one shell: a candidate check, a recorded node, a recorded relationship. A node or arrow explains ITSELF; it never
// inherits the verdict of a check it is merely related to, and nothing here implies runtime data flow. The candidate's own evidence detail is used
// only when it was loaded for that exact candidate (`c.candidate_id === item.item_id`); until then only the listed item's own facts are stated.
const bomW = (v) => String(v || '').replaceAll('_', ' ');
const BOM_STATE = { supported: 'represented', contradicted: 'not_represented', unverifiable: 'cannot_establish', unknown_coverage: 'unknown', conflicting_evidence: 'conflicting_evidence', no_rule: 'no_rule' };
const BOM_BADGE = { represented: 'inventory', not_represented: 'review', cannot_establish: 'unknown', unknown: 'unknown', conflicting_evidence: 'review', no_rule: 'neutral' };
const BOM_FAMILY = { software: ['software', 'SBOM'], cryptography: ['cryptography', 'CBOM'], ai_model: ['AI model', 'AI-BOM'] };
const RECORD_LABEL = { requirement_declaration: 'Source requirement', inventory_name_lookup: 'Selected SBOM lookup', cbom_document: 'Selected CBOM', aibom_document: 'Selected AI-BOM' };
const recordLabel = (r) => RECORD_LABEL[r.kind] || (r.kind === 'source_excerpt' ? (r.reference_kind === 'model_reference' ? 'Model reference in source' : 'Source call site') : 'Evidence record');
const recordRow = (r) => {
  const lines = Array.isArray(r.source?.lines) ? ':' + r.source.lines.join('–') : '';
  const text = r.source?.file ? `${r.source.file}${lines}` : (r.document?.format ? `${r.document.format} ${r.document.spec_version || ''}`.trim() : bomW(r.role));
  return { label: recordLabel(r), state: r.kind === 'cbom_document' || r.kind === 'aibom_document' || r.kind === 'inventory_name_lookup' ? 'inventory_reported' : 'captured', text: `${text}${r.role ? ' · ' + bomW(r.role) : ''}` };
};
const locText = (l) => (l && l.path ? `${l.path}${l.line_start ? ':' + l.line_start + (l.line_end && l.line_end !== l.line_start ? '–' + l.line_end : '') : ''}` : '');

export function fromBom(s) {
  const b = s.bom8; if (!b) return null;
  const a = s.analysis; const idl = identityLine(a);
  if (b.selectedRecord) return bomRecordModel(b, idl);
  const item = bomSelectedItem(b); if (!item) return null;
  const c = b.detail?.candidate && b.detail.candidate.candidate_id === item.item_id ? b.detail.candidate : null;    // never another candidate's detail
  const st = BOM_STATE[item.state] || 'unknown'; const meta = stateMeta(st);
  const fam = BOM_FAMILY[item.family]; const where = locText(item.location);
  const ne = c ? (c.not_established || []) : [];
  const what = fam ? `A ${fam[0]} candidate check${where ? ' at ' + where : ''}, compared with the selected ${fam[1]}. It is a hypothesis, not a finding.` : `A candidate check${where ? ' at ' + where : ''} from the bound comparison. It is a hypothesis, not a finding.`;
  const why = c && c.trigger ? c.trigger : item.partial ? 'It was chosen from the related checks of a recorded item and is outside the current list.' : `The bound comparison recorded ${bomW(item.state)} for it${where ? ' at ' + where : ''}.`;
  const est = c ? (c.rationale || (c.state === 'unknown_coverage' ? 'Coverage is unknown: this was not compared against the BOM, and it is not a defect.' : 'No rationale was recorded.'))
    : item.partial ? `The bound comparison recorded ${bomW(item.state)}; its rule and inventory details load when the list includes this check.`
    : `${meta.label}${item.rule_id ? ` by rule ${item.rule_id}` : '; no rule verdict was recorded'}. ${b.detailError ? 'The rationale could not be loaded.' : 'The rationale is loading.'}`;
  const unknown = ne.length ? `${ne.join('; ')}.` : item.partial ? 'Its inventory and rule details are not loaded for this list.' : item.graph_state === 'assertion_graph' ? 'This inventory check does not establish installation or runtime use.' : 'More evidence is needed; no completeness conclusion is established.';
  const rows = [
    { label: 'Source location', state: where ? 'captured' : 'unknown', text: where || 'No location recorded' },
    { label: 'Inventory compared', state: item.inventory ? 'inventory_reported' : 'not_assessed', text: item.inventory ? `${item.inventory.generator} · ${item.inventory.inventory_id}` : (item.partial ? 'Not loaded for this list' : 'No bound inventory') },
    { label: 'Rule', state: item.rule_id ? 'captured' : 'not_assessed', text: item.rule_id || (item.partial ? 'Not loaded for this list' : 'No rule verdict') },
    ...(c ? (c.records || []).map(recordRow) : [])];
  return { origin: 'local_presentation_model', id: item.item_id, tab: 'bom', type: 'Candidate check', title: item.display.name, subtitle: bomW(item.category && !item.partial ? item.category : item.family), badge: { kind: BOM_BADGE[st], label: meta.label },
    question_set: 'bom_comparison', evidence_for: b.stale ? null : item.item_id,
    answers: [
      ans('what_is_this', 'declared', what),
      ans('why_here', 'inventory_reported', why),
      { ...ans('comparison_established', st, est, st === 'cannot_establish' || st === 'unknown' ? (ne.slice(0, 2).length ? ne.slice(0, 2) : ['a completed comparison for this check']) : []), ...(c && (c.reason_codes || []).length ? { detail: [`Reason codes: ${c.reason_codes.join(', ')}`], detail_label: 'How this was determined' } : {}) },
      ans('what_unknown', 'unknown', unknown, ne.length ? [] : ['installation or runtime observation'])],
    evidence_rows: rows,
    sources: [...ne.map((x) => `Not established: ${x}`), ...(c ? [`Identity basis: ${c.identity_basis || 'n/a'}`, ...(c.bounded_meaning ? [c.bounded_meaning] : [])] : []), `Canonical candidate ${item.item_id}`, ...(item.display.raw_title && item.display.raw_title !== item.display.name ? [`Full title: ${item.display.raw_title}`] : []), idl].filter(Boolean),
    actions: [{ id: 'ask', label: 'Explain this', attrs: { 'data-action': 'bom-ask' } }], next_step: c?.next_action || null,
    technical: [['Candidate', item.item_id], ['Assertion', (c && c.assertion_id) || item.assertion_id || 'none'], ['Rule', (c && c.rule_id) || item.rule_id || 'none'], ['Reason codes', c ? (c.reason_codes || []).join(', ') : '']] };
}
const nodeName = (b, id) => { const n = b.graph?.nodes?.find((x) => x.node_id === id); return n && n.full_label ? `${n.full_label} (${id})` : id; };
function bomRecordModel(b, idl) {
  const edge = b.graph?.edges?.find((e) => e.edge_id === b.selectedRecord);
  const node = b.graph?.nodes?.find((n) => n.node_id === b.selectedRecord);
  const subject = b.related?.subject?.id === b.selectedRecord ? b.related : null;
  const rel = !subject ? 'Looking up related checks…' : subject.resolution === 'multiple' ? `This exact record is used by ${fmt(subject.related_total)} checks. Each check states its own conclusion; none is stated here.` : subject.resolution === 'single' ? 'This exact record is used by one check. That check states its own conclusion; none is stated here.' : (subject.record_detail?.title || 'No related check is recorded for this exact record.');
  const third = ans('comparison_established', 'not_applicable', `A recorded ${edge ? 'relationship' : 'node'} is not itself a comparison. ${rel}`);
  const common = { origin: 'local_presentation_model', id: b.selectedRecord, tab: 'bom', subtitle: '', question_set: 'bom_comparison', actions: [], next_step: null, technical: [['Record', b.selectedRecord]] };
  if (edge) {
    return { ...common, type: 'Recorded relationship', title: edge.label || bomW(edge.type) || 'Recorded relationship', badge: { kind: 'inventory', label: 'Recorded relationship' }, answers: [
      ans('what_is_this', 'inventory_reported', `A recorded ${bomW(edge.type)} relationship from one recorded node to another. An arrow is a recorded association, not data flow or runtime use.`),
      edge.rationale ? ans('why_here', 'inventory_reported', edge.rationale) : ans('why_here', 'unknown', 'No rationale was recorded for this relationship.', ['a recorded rationale']),
      third,
      ans('what_unknown', 'not_assessed', 'Whether the two records interact at run time is not established by this relationship.', ['runtime observation'])],
    evidence_rows: [{ label: 'From', state: 'inventory_reported', text: nodeName(b, edge.from) }, { label: 'To', state: 'inventory_reported', text: nodeName(b, edge.to) }, { label: 'Type', state: 'inventory_reported', text: bomW(edge.type) }, { label: 'Role', state: edge.role ? 'inventory_reported' : 'unknown', text: bomW(edge.role) }],
    sources: ['Recorded in the bound evidence graph for this analysis. A relationship is not a verdict.', idl].filter(Boolean) };
  }
  if (node) {
    return { ...common, type: `Recorded ${bomW(node.kind || 'record')}`, title: node.full_label, badge: { kind: 'inventory', label: 'Recorded node' }, answers: [
      ans('what_is_this', 'inventory_reported', `A recorded ${bomW(node.kind || 'record')} in the bound evidence graph${node.evidence_role || node.role ? `, with role ${bomW(node.evidence_role || node.role)}` : ''}.`),
      ans('why_here', 'inventory_reported', b.graph?.scope?.kind === 'focused_candidate' ? 'It is recorded in the graph of the selected candidate check.' : 'It is recorded in the bound evidence graph.'),
      third,
      ans('what_unknown', 'not_assessed', 'Whether this record is used at run time is not established; the graph shows recorded evidence only.', ['runtime observation'])],
    evidence_rows: [{ label: 'Kind', state: 'inventory_reported', text: bomW(node.kind) }, { label: 'Role', state: (node.evidence_role || node.role) ? 'inventory_reported' : 'unknown', text: bomW(node.evidence_role || node.role) }, { label: 'Record id', state: 'inventory_reported', text: node.node_id }],
    sources: ['Recorded in the bound evidence graph for this analysis. A node is not a verdict.', idl].filter(Boolean) };
  }
  return { ...common, type: 'Recorded item', title: 'Selected record', badge: { kind: 'unknown', label: 'Not in the loaded graph' }, answers: [
    ans('what_is_this', 'unknown', 'This record is not in the graph that is currently loaded, so nothing is stated about it.', ['the graph that contains this record']),
    ans('why_here', 'unknown', 'No loaded record explains its presence.', ['a loaded graph']), ans('comparison_established', 'not_assessed', 'No comparison is stated for a record that is not loaded.'),
    ans('what_unknown', 'unknown', 'Everything about this record is unknown until its graph loads.', ['a loaded graph'])], evidence_rows: [], sources: [idl].filter(Boolean) };
}
