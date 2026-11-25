import { esc } from '../lib/util.js';
import { INFO } from '../lib/copy.js';
import { renderDisclosure } from './disclosure.js';
import { renderScanChip } from './scan_status.js';
import { scanGate } from '../lib/scan_model.js';

export const infoButton = (text, label) => `<button type="button" class="ot-info" data-info="${esc(text)}" aria-label="${esc(label)}">i</button>`;

// UIP-02 §3.2/§3.5: the combined-reference homepage. Markup is ported from the approved reference (no inline scripts);
// UIP-03 replaced the review step: one Scan action starts the pinned scan (no second confirmation), the D08 disclosure sits
// directly beneath the buttons (Placement P) and the real stage panel renders below them.
const HOME_SVG = `<svg aria-label="A camera app's AI model. The camera application points to the model named in the code and to the AI model inventory. OpenTrace looks for a matching entry, then shows the result and evidence." role="img" viewBox="0 0 490 300"><defs><marker id="ot-home-arr" markerHeight="7" markerWidth="7" orient="auto" refX="6" refY="3"><path d="M0 0 L6 3 L0 6" fill="none" stroke="#71847b"></path></marker></defs><g fill="none" marker-end="url(#ot-home-arr)" stroke="#71847b" stroke-width="1.8"><path d="M215 52L120 98"></path><path d="M275 52L370 98"></path><path d="M110 142L205 178"></path><path d="M380 142L285 178"></path><path d="M245 220V248"></path></g><g font-family="sans-serif" font-size="12" text-anchor="middle"><rect fill="#dbeaf6" height="42" rx="8" stroke="#93b6cf" width="200" x="145" y="10"></rect><text fill="#263d4e" x="245" y="35">Camera application</text><rect fill="#eee7fa" height="42" rx="8" stroke="#a99ac9" width="190" x="15" y="100"></rect><text fill="#42345d" x="110" y="125">Model named in the code</text><rect fill="#e2f1e8" height="42" rx="8" stroke="#98c6ab" width="190" x="285" y="100"></rect><text fill="#295b42" x="380" y="125">AI model inventory</text><rect fill="#f9e3da" height="42" rx="8" stroke="#d7b09a" width="230" x="130" y="178"></rect><text fill="#6f3f26" x="245" y="203">Look for a matching entry</text><rect fill="#fbefcf" height="42" rx="8" stroke="#e0c98a" width="230" x="130" y="250"></rect><text fill="#5e4a14" x="245" y="275">Show the result and evidence</text></g></svg>`;

export function sessionStatusText(s) {
  const active = s.session.status === 'active';
  return s.busy === 'analysis' ? 'Analyzing…' : s.busy === 'ending' ? 'Ending session…' : active ? 'Active session · temporary' : 'No active session';
}

// Honest status line: only what the loaded service configuration says; nothing is claimed before it loads.
export function liveStatusText(live) {
  return live && live.enabled ? 'Captured sample available · Live scanning is enabled on this service' : 'Captured sample available';
}

export function renderAnalyze(s) {
  const { intake: i, session: ss } = s;
  const active = ss.status === 'active';
  const status = sessionStatusText(s);
  const gate = scanGate(s);
  const disclosure = s.config && s.config.state === 'loaded' ? renderDisclosure(s.config.live) : '';
  const endedMsg = s.ended ? (s.ended === 'deleted_verified'
    ? 'Session ended. The temporary analysis data was deleted and removal was verified. The active analysis view, repository input and assistant conversation have been cleared.'
    : s.ended === 'cleanup_failed' ? 'Session closed, but cleanup could not be verified. Access is revoked; the service will retry removal.' : 'The session is no longer active on the service. The view, repository input and assistant conversation have been cleared.') : '';
  const undertext = s.live && s.live.enabled
    ? 'One repository per analysis. Repository roots and /tree/reference links are supported.'
    : 'One repository per analysis. Without live scanning this preview replays captured evidence; it does not fetch or scan your repository.';
  return `<div class="ot-intake ot-home-page"><div id="ot-home">
<section aria-labelledby="hero-title" class="nh-hero"><div><div class="nh-eyebrow">Evidence-backed IoT supply-chain verification</div><h1 id="hero-title">Know what's inside.<br><span>Verify what you trust.</span></h1><p class="nh-lead">OpenTrace connects software, cryptography, and AI components to the evidence behind them—helping developers and security reviewers find missing, inconsistent, or unsupported claims in one place.</p><div class="nh-bullets"><span class="nh-chip"><strong>01</strong> Unified component view</span><span class="nh-chip"><strong>02</strong> Cross-BOM relationships</span><span class="nh-chip"><strong>03</strong> Traceable findings</span></div></div>
<div class="nh-analysis-card" id="analyze"><div class="nh-card-overline">↗ &nbsp; Start an analysis</div><h2>Review a repository</h2><p>Enter a public GitHub repository URL and select Scan. Use Demo ↗ in the header to open the captured Frigate replay.</p>
  ${endedMsg ? `<p id="ot-ended-note" class="ot-note ot-ended ${s.ended === 'deleted_verified' || s.ended === 'gone' ? '' : 'ot-session-error'}" role="status">${esc(endedMsg)}</p>` : ''}
  ${s.notice ? `<p class="ot-note ot-session-error" role="alert">${esc(s.notice)}</p>` : ''}
  <form class="ot-card ot-context-form" id="ot-form" novalidate>
    <label class="ot-form-label" for="ot-url"><span>GitHub repository URL ${infoButton(INFO.url, 'About repository URLs')}</span><span class="nh-hint">Public repositories only</span></label>
    <div class="ot-url"><input id="ot-url" data-fk="url" type="url" placeholder="https://github.com/owner/repository" autocomplete="off" aria-describedby="ot-url-help ot-error" value="${esc(i.url)}"><div class="nh-form-actions"><button class="button primary" id="ot-scan" type="submit" ${gate.enabled ? '' : 'disabled aria-disabled="true"'} aria-describedby="ot-disclosure ot-scan-reason">Scan ↗</button></div></div>
    <p class="ot-help" id="ot-url-help">One repository per analysis. Repository roots and /tree/reference links are supported.</p>
    ${s.advanced ? `<div class="ot-advanced-field"><label for="ot-commit" class="ot-form-label">Commit SHA (optional)</label><input class="ot-commit" id="ot-commit" data-fk="commit" placeholder="Paste a 7–40 character commit SHA" autocomplete="off" value="${esc(i.manualSha)}"><p class="ot-help">Pins a repository-root URL. If a tree URL is also supplied, it must identify the same commit.</p></div>` : ''}
    <p id="ot-error" class="ot-error" role="alert">${esc(i.error)}</p>
    <p class="ot-help" id="ot-scan-reason" role="status">${gate.enabled ? '' : esc(gate.reason)}</p>
    ${disclosure}
  </form>
  ${renderScanChip(s)}
  <p class="nh-undertext">${esc(undertext)}</p>
  <div class="nh-mini-status ot-home-session"><span class="nh-dot"></span><span id="ot-session-status" role="status">${esc(status)}</span><span class="ot-home-sep" aria-hidden="true">·</span><span>${esc(liveStatusText(s.live))}</span>${infoButton(INFO.retention, 'About temporary session storage')}<button type="button" class="text-action" id="ot-end-session" data-action="end" ${active && s.busy !== 'ending' ? '' : 'disabled'}>End session</button></div>
</div></section>
<div class="nh-divider"></div>
<section aria-labelledby="about-title" id="about"><div class="nh-sectionhead"><div class="nh-eyebrow">What OpenTrace connects</div><h2 id="about-title">Three inventories. One evidence trail.</h2><p>A Bill of Materials (BOM) is a structured inventory. OpenTrace connects software, cryptographic, and AI records, then checks their declared relationships against available repository evidence.</p></div><div class="nh-grid3"><article class="nh-info"><div class="nh-iconbox nh-soft">SB</div><h3>SBOM</h3><strong>Software Bill of Materials</strong><p>Maps software packages, versions, libraries, and dependencies. Helps reveal missing components and potentially vulnerable versions.</p></article><article class="nh-info"><div class="nh-iconbox nh-crypto">CB</div><h3>CBOM</h3><strong>Cryptographic Bill of Materials</strong><p>Describes cryptographic algorithms, keys, certificates, and related assets. Helps examine which protections are declared and where they are used.</p></article><article class="nh-info"><div class="nh-iconbox nh-ai">AI</div><h3>AI-BOM</h3><strong>Artificial Intelligence Bill of Materials</strong><p>Describes AI models, runtimes, datasets, and available provenance metadata. Helps track model dependencies and unsupported claims.</p></article></div></section>
<section aria-labelledby="how-title" id="how" class="ot-home-how"><div class="nh-sectionhead"><div class="nh-eyebrow">From repository to evidence</div><h2 id="how-title">How an OpenTrace review works</h2><p>A focused workflow for developers, maintainers, security analysts, and supply-chain reviewers.</p></div><div class="nh-flow"><article class="nh-step"><div class="nh-num">01 / INPUT</div><h3>Choose a repository</h3><p>Enter a public GitHub URL. Use Advanced to enter a commit. When live scanning is enabled, Scan pins the revision and analyzes that commit.</p></article><article class="nh-step"><div class="nh-num">02 / EXTRACT</div><h3>Collect inventories and source evidence</h3><p>Gather available SBOM, CBOM, and AI-BOM records alongside observations from supported source files.</p></article><article class="nh-step"><div class="nh-num">03 / CONNECT</div><h3>Explore assets and compare evidence</h3><p>Explore dependencies, advisory matches, cryptography, and AI models. Open BOM connections to see which observations and BOM records were compared.</p></article><article class="nh-step"><div class="nh-num">04 / EXPLAIN</div><h3>Inspect evidence and download BOMs</h3><p>Select a result to see its source, the BOM checked, and any limits. Download the available inventories.</p></article></div></section>
<section aria-labelledby="results-title" class="nh-outcome"><div class="nh-diagram"><div class="nh-diagram-title">A camera app's AI model</div>${HOME_SVG}<div class="nh-legend">OpenTrace looks for the model named in the camera app's code in its AI inventory. The cards beside the graph explain the possible results.</div></div><div><div class="nh-eyebrow">BOM comparison outcomes</div><div class="nh-sectionhead ot-home-tight"><h2 id="results-title">See what the evidence supports.</h2><p>Review what was checked, the evidence behind the result, and where coverage was limited.</p></div><div class="nh-statuses"><div class="nh-status"><span class="nh-sym nh-verified">✓</span><div><h3>Represented</h3><p>The comparison found a corresponding record in the selected BOM within the checked scope.</p></div></div><div class="nh-status"><span class="nh-sym nh-inconsistent">!</span><div><h3>Not represented</h3><p>The comparison ran and found no corresponding record in the selected BOM within the checked scope.</p></div></div><div class="nh-status"><span class="nh-sym nh-unknown">?</span><div><h3>Coverage unknown</h3><p>The comparison could not confirm a result, or there wasn't enough comparable evidence to run it. Open the result for the reason.</p></div></div></div></div></section>
<aside class="nh-scope"><span aria-hidden="true" class="ot-home-info-icon">ⓘ</span><div><strong>What OpenTrace can—and cannot—establish</strong><p>Findings depend on the revision, available inventories, and inspected source paths. Declared dependencies are not runtime call paths. Crypto calls and model references do not establish deployed settings, model identity, or execution. Advisory matches and inventory discrepancies require context; they are not a repository security score.</p></div></aside>
</div></div>`;
}
