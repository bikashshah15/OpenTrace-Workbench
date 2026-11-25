// UIP-D08 (owner-approved copy rev. 3, Placement P): "What happens when you press Scan". Built and tested in UIP-02, NOT mounted
// until UIP-03 introduces the one-click Scan flow (contract §3.4, FR-3): its heading and first sentence describe pressing Scan.
// The variant comes only from the raw `/api/config` `live` block; until it has loaded (or if it failed) nothing is shown and no
// variant is guessed. NOTE for the mounting increment: the store's CONFIG reducer maps a disabled service to `live: null`, so
// pass the raw config block (variant D is `{enabled:false}`), not `state.live`.
import { esc } from '../lib/util.js';

export const DISCLOSURE_HEADING = 'What happens when you press Scan';
const NOT_SCORE = 'Results describe inventories and source evidence for that commit. They are not a security score.';
const RETENTION = 'Session cleanup. OpenTrace keeps files and results locally for the session. End session attempts to delete them and reports whether cleanup succeeded.';
const DEFAULT_AI_MODE = 'In default mode, Scan can show supported AI model references found in source code, but skips live AI-BOM generation and comparison against a newly generated AI inventory. The captured Frigate AI-BOM remains available through Demo ↗.';

export function disclosureVariant(live) {
  if (!live || typeof live !== 'object') return null;
  if (!live.enabled) return 'D';
  const available = !!(live.isolation && live.isolation.available);
  if (!available) return 'C';
  return live.policy && live.policy.effective === 'allowlist' ? 'B' : live.policy && live.policy.effective === 'bounded' ? 'A' : null;
}

function advisoryLine(live, variant) {
  const adv = live.advisories;
  if (adv && adv.enabled && adv.specialist_available === false) return 'Advisory lookup is enabled but its package parser is not available on this service, so no advisory lookup will be made; results will say the lookup was unavailable.';
  if (adv && adv.enabled) return 'Advisory lookup. When enabled, OpenTrace sends OSV only the ecosystem, name, and exact version of eligible lockfile dependencies.';
  return variant === 'A' || variant === 'B' ? 'No advisory lookup is made.' : null;
}

// UIP-07C A2 (copy approved with FD-C12): shown whenever the AI inventory step is requested (the `ai_bom` block is present only then).
function aiLine(live) {
  const ai = live.ai_bom;
  if (!ai || !ai.requested) return null;
  return `AI inventory. When available and enabled, Cisco AI-BOM sends selected file names and code excerpts to the configured LLM provider through a restricted gateway. Repository text and configuration can influence what it selects. OpenTrace explains if this step is skipped.${ai.available === false ? ' It is unavailable right now.' : ''}`;
}

const OPEN_A = 'Repository scan. OpenTrace pins your GitHub link to one commit. The SBOM and cryptography scanners read its files in a container with no network access.';

export function disclosureParagraphs(live) {
  const v = disclosureVariant(live); if (!v) return null;
  const adv = advisoryLine(live, v);
  const ai = (v === 'A' || v === 'B') ? aiLine(live) : null;
  const iso = live.isolation || {};
  const out = {
    A: [OPEN_A, ai, adv, RETENTION, NOT_SCORE],
    B: ['Live scanning is limited to a short list of pre-approved repositories right now. If your link is not on it, nothing is downloaded and the reason is shown.', `Approved repositories are read as data inside a sandbox (${iso.description}); the repository’s code is not installed, built or run.`, ai, adv, RETENTION, NOT_SCORE],
    C: [`Scanning is unavailable: OpenTrace could not verify an isolation boundary (${iso.reason}). Nothing will be downloaded or scanned.`, 'Demo ↗ opens the captured Frigate replay; it is not your repository.'],
    D: ['Live scanning is not enabled on this service, so no repository is downloaded. Demo ↗ opens the captured Frigate replay; it is not your repository.'],
  }[v];
  out.push(DEFAULT_AI_MODE);
  return out.filter(Boolean);
}

// Returns '' (nothing) until the config is known.
export function renderDisclosure(live) {
  const ps = disclosureParagraphs(live); if (!ps) return '';
  return `<div class="ot-disclosure nh-hint" id="ot-disclosure" data-variant="${esc(disclosureVariant(live))}"><strong>${esc(DISCLOSURE_HEADING)}</strong>${ps.map((p) => `<p>${esc(p)}</p>`).join('')}</div>`;
}
