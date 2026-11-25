// Static public-demo wording preserved from the finalized prototype (wording is part of the UI authority).
export const FINDING_COPY = {
  'p5-requirement-represented-in-inventory': { mode: 'bom', tag: 'Inventory discrepancy', title: 'A declared dependency is missing from the inventory', copy: 'tflite_runtime is declared in the requirements, but is not represented in the captured Syft SBOM.', limit: 'This does not establish a completeness defect or vulnerability.' },
  'p8-md5-call-represented-in-cdxgen-cbom': { mode: 'crypto', tag: 'Could not confirm', title: 'A source hash call has no inventory record', copy: 'An MD5 call appears in source, but the cdxgen CBOM reports no cryptographic assets.', limit: 'This scan does not establish Python algorithm coverage.' },
  'p7-model-declared-in-aibom': { mode: 'ai', tag: 'Could not confirm', title: 'The AI inventory does not match the selected model', copy: 'Cisco AI BOM reports yolov6n.hef; the selected CPU configuration refers to cpu_model.tflite.', limit: 'The scan covered three paths. Model identity and loading remain unverified.' },
};
export const FINDING_ORDER = ['p5-requirement-represented-in-inventory', 'p8-md5-call-represented-in-cdxgen-cbom', 'p7-model-declared-in-aibom'];
export const ARTIFACT_COPY = {
  sbom: ['Software inventory', 'SBOM · Syft 1.51.1', '1,989 components in the source-directory capture. A runtime installation inventory was not collected.'],
  cbom: ['Cryptography inventory', 'CBOM · cdxgen 12.9.0', 'Scan completed: 0 cryptographic assets and 13 endpoint services. Python algorithm coverage is not established.'],
  aibom: ['AI inventory', 'AI-BOM · Cisco AI BOM 1.10.0', 'One model reported: yolov6n.hef. The scan covered a bounded source copy of three paths.'],
};
export const STEP_COPY = [
  'Pinned Frigate v0.18.2 at cfa08c5. One researcher-created CPU configuration; three inventories with different scan scopes. Nothing was built or run.',
  'Review package advisory matches separately from the inventory discrepancy and two inconclusive inventory checks. No application exploitability has been established.',
  'Explore Dependencies and Repository contexts, then select BOM connections for captured inventory checks. Source observations and inventory declarations remain distinct.',
  'Inspect the SBOM, CBOM and AI-BOM artifacts and the captured records that support these checks.',
];
export const STEPS = ['1 · Repository & scope', '2 · Review findings', '3 · Trace connections', '4 · Inspect artifacts'];
export const LAYER_SUB = { contexts: 'Source files & inventory scope', dependencies: 'Declared dependencies · captured source', crypto: 'Cryptography · source & inventory evidence', ai: 'AI models · configuration & inventory evidence', bom: 'BOM connections · evidence relationships' };
export const LAYER_NOTE = {
  dependencies: 'Explore dependencies below the focused package. Filter advisory matches, direct dependencies, transitive paths or evidence gaps.',
  contexts: 'Separate files and package contexts within this one repository. Counts can overlap; contexts are not additional repositories.',
  crypto: 'Cryptographic assets recorded in the original CBOM, with clearly labelled experimental source observations where one was recorded. A CBOM that lists no assets does not show that no cryptography is used.',
  ai: 'Models recorded in the AI-BOM inventory, grouped by recorded source location where one exists. An inventory entry does not establish which model is loaded or used. A list that shows none does not show that no AI is used.',
  bom: 'Inventory assessment evidence connections: declarations, source observations and bounded assessments. These do not establish runtime execution.',
};
export const INFO = {
  url: 'Paste a public GitHub repository URL, or a tree URL pointing to a branch, tag or commit. A live service must resolve the reference to an exact commit before analysis.',
  findings: 'BOM checks compare source declarations and inventory records. They are separate from the package advisory matches above. Missing records can reflect scope or tool coverage.',
  graphs: 'These views reuse captured inventory assessment evidence. The Software, Cryptography and AI views show bounded source-to-inventory comparisons, not complete dependency or runtime graphs.',
  retention: 'This service keeps analysis artifacts only for the active session, in a private temporary directory. Ending the session revokes access, stops work, deletes the data and verifies removal. Nothing is stored in the browser except the Advanced and theme preferences.',
  context: 'The filter limits dependency components and their package advisory matches. It does not filter Cryptography, AI models or BOM connections.',
  advisories: 'Advisory matches are package-version records from a dated OSV query snapshot. They do not establish application use, reachability or exploitability.',
  evidence: 'These are the records used or excluded by the displayed inventory checks.',
};
export const ABOUT_DIAGRAM = '/static/assets/opentrace-architecture.webp';
export const ABOUT = `<figure class="ot-about-diagram"><a href="${ABOUT_DIAGRAM}" target="_blank" rel="noopener"><img src="${ABOUT_DIAGRAM}" width="2400" height="1373" alt="Architecture diagram. A pinned repository revision feeds four inputs: the SBOM, the CBOM, the AI-BOM and source code analysis. These flow into a step that compares inventories with source evidence, which feeds the Workbench. A separate path takes lockfile versions to OSV and then to the Dependencies tab. An optional dashed branch connects the Lab Assistant to the Workbench."></a><figcaption><a href="${ABOUT_DIAGRAM}" target="_blank" rel="noopener">Open full-size diagram</a></figcaption></figure>
<p>OpenTrace connects software, cryptography, and AI inventories to evidence from one exact revision of a public GitHub repository. Choose Scan to analyze a repository when live scanning is available, or Demo to explore a recorded Frigate scan.</p>
<ol><li><strong>Pin the repository revision.</strong> OpenTrace resolves the GitHub link to an exact commit and reads its files. The scan does not build or run the repository\u2019s code.</li>
<li><strong>Generate inventories and collect source evidence.</strong> Syft produces the software inventory (SBOM), and cdxgen produces the cryptography inventory (CBOM). Cisco AI-BOM produces the AI inventory when enabled. OpenTrace also looks for supported dependency declarations, cryptographic calls, and model references in source files.</li>
<li><strong>Compare source evidence with the inventories.</strong> OpenTrace checks whether selected source observations have corresponding inventory records. Results show what was represented, what had no matching record, and where the evidence was insufficient.</li>
<li><strong>Look up dependency advisories.</strong> When enabled, OpenTrace checks eligible lockfile package versions against OSV. The Dependencies tab shows package-version matches. Application reachability and exploitability remain undetermined.</li>
<li><strong>Review the evidence.</strong> Use the Workbench to explore relationships and trace results to source records. Open Evidence to review scan coverage and preview or download original artifacts.</li></ol>
<p>A missing inventory record can reflect scanner coverage. Source references describe what was found in the repository. Which code or models actually ran remains unverified.</p>`;

// Live-scan wording (I5). Nothing here describes captured Frigate evidence.
export const LIVE_STEP_COPY = [
  'One public repository at one exact commit, fetched by full SHA and verified against the commit\u2019s own tree. Syft and cdxgen read the files inside a no-network sandbox; nothing was built, installed or run.',
  'When advisory lookup is enabled, lockfile versions are looked up in OSV and joined to the SBOM; otherwise no advisory matching is run. The captured Frigate findings are never applied to live results.',
  'Explore Dependencies and Repository contexts from the generated SBOM. BOM connections show only what the two scans themselves recorded.',
  'Inspect and download the original Syft and cdxgen outputs. Each card shows the scanner version, scope, outcome and SHA-256.',
];
export const LIVE_LAYER_NOTE = {
  crypto: 'The CBOM comes from cdxgen run over the whole repository. A scan that completes with zero cryptographic assets is a finished result, not a failed scan, and it does not show that no cryptography is used.',
  bom: 'Evidence connections recorded by the live scan; these views do not establish runtime execution.',
};
// The live AI-layer banner states what THIS scan's AI inventory actually is. "Generated" is claimed only when the validated ai_assets/1 payload
// carries an AI-BOM producer whose outcome is completed/partial (an acquired but invalid or unreadable document is availability `failed`, so no usable
// inventory is implied). Source model references and runtimes never create an inventory claim. A captured (non-live) case keeps LAYER_NOTE.ai.
const AI_NONE = 'No AI inventory is available for this live scan: ';
const AI_SRC = ' Experimental source observations listed here, if any, are not an inventory';
export function liveAiNote(summary, aiPage) {
  const card = (summary?.cards || []).find((c) => c.kind === 'aibom');
  if (!card) return AI_NONE + 'the AI-BOM phase did not run.' + AI_SRC + ', and they do not show that no AI is used.';
  if ((card.scan || {}).outcome !== 'acquired') return AI_NONE + 'an AI-BOM was requested but it did not deliver a usable inventory.' + AI_SRC + '.';
  const prod = (aiPage?.producers || []).find((p) => p?.provenance?.origin === 'original_artifact');
  if (!prod) return aiPage ? AI_NONE + 'the AI-BOM was acquired but no validated inventory could be read from it.' + AI_SRC + '.' : 'The AI-BOM was acquired. Whether it holds a usable inventory is stated here once the validated AI inventory view is available.';
  if (prod.outcome === 'completed') return 'The AI inventory shown was generated in this live scan by Cisco AI-BOM, separately from Syft and cdxgen. An inventory entry does not establish which model is loaded or used; experimental source observations are labelled separately.';
  if (prod.outcome === 'partial') return 'The AI inventory shown is partial: it was generated in this live scan by Cisco AI-BOM, separately from Syft and cdxgen, and some of it could not be read. An inventory entry does not establish which model is loaded or used.';
  return AI_NONE + 'the AI-BOM was acquired but its document did not pass validation, so no inventory from it is shown.' + AI_SRC + '.';
}
export const LIVE_ARTIFACT_COPY = {
  sbom: ['Software inventory', 'SBOM \u00b7 Syft'],
  cbom: ['Cryptography inventory', 'CBOM \u00b7 cdxgen'],
};

// UIP-13: the live-scan banner states what the SCAN ran; an AI-BOM card means Cisco AI-BOM ran separately, so "no AI-BOM" would be false (it is still not an inventory check).
export function liveBarText(summary) {
  const aiRan = (summary?.cards || []).some((c) => c.kind === 'aibom');
  const replay = summary?.live?.replay;      // a replay of a saved scan says so; the pinned commit stays visible
  const head = replay && typeof replay.revision === 'string'
    ? 'Replay of a recorded scan of commit ' + replay.revision.slice(0, 12) + '. Syft and cdxgen ran in a no-network sandbox; '
    : 'Live scan of one resolved commit. Syft and cdxgen ran in a no-network sandbox; ';
  const L = summary?.advisory_lookup;       // the reported lookup status decides the wording; only a complete or partial lookup says versions were looked up
  const status = L ? L.lookup : null;
  const ran = L && status !== 'not_run' && status !== 'unavailable';
  const body = ran
    ? (status === 'partial' ? 'lockfile versions were only partly looked up in OSV.' : 'lockfile versions were then looked up in OSV.') + (aiRan ? '' : ' No AI-BOM.')
    : status === 'unavailable' ? 'the OSV advisory lookup was unavailable, so no versions were looked up.' + (aiRan ? '' : ' No AI-BOM.')
    : (aiRan ? 'no advisory matching was run (the AI-BOM was produced separately by Cisco AI-BOM and is compared with static model references in the BOM view).' : 'no advisory matching or AI-BOM was run.');
  return head + body + (summary?.inventory_checks ? ' One source-backed CBOM check was assessed.' : '');
}
