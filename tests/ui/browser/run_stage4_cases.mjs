// DATA copied verbatim from the existing validation harnesses (the originals are unmodified): the expected typed states and the expected inspector text per synthetic
// repository. UIP12_MATRIX <- tests/ui/browser/run_uip12_inspector.mjs `pairMatrix` (const want); UIP13_MATRIX <- run_uip13_inspector.mjs `caseMatrix` (const want).
// Copied at the Stage 4 packet head; if those files change, the self-test's drift check (run_stage4_selftest.mjs) fails.
const hasRecord = (t, kind) => t.includes(kind);
const has = (t, s) => t.includes(s);
export const UIP12_MATRIX = {
    positive: { n: 1, state: 'supported', cr: 'completed', ex: (t) => [['source call site shown (path:line, verbatim excerpt, digest)', hasRecord(t, 'Source call site') && /app\/m\.py:4/.test(t) && /hashlib\.sha256\(x\)\.hexdigest\(\)/.test(t) && /File SHA-256/.test(t)], ['CBOM record shown separately with census', hasRecord(t, 'Selected CBOM') && /1 cryptographic asset/.test(t)], ['conclusion supported with bounded meaning', /Conclusion:/.test(t) && /call_site_in_range_unique/.test(t) && /Declaration-level/.test(t)], ['alias decision shown, spelling applied', /Algorithm spelling/.test(t) && /finite alias mapping applied/.test(t)]] },
    renamed: { n: 1, state: 'supported', cr: 'completed', ex: (t) => [['verbatim renamed excerpt and imported name shown', /x = s\(b"x"\)/.test(t) && /imported name sha256/.test(t)], ['supported without synthetic text in the excerpt', /call_site_in_range_unique/.test(t)]] },
    zeroasset: { n: 1, state: 'unverifiable', cr: 'completed', ex: (t) => [['zero-asset CBOM census and no_algorithm_record', hasRecord(t, 'Selected CBOM') && /0 cryptographic assets/.test(t) && /no_algorithm_record/.test(t)], ['absence is not a contradiction', /Absence is not a contradiction/.test(t)]] },
    obsonly: { n: 2, state: null, cr: 'completed', ex: (t) => [['observation only: source record, no CBOM record fabricated', hasRecord(t, 'Source call site') && !hasRecord(t, 'Selected CBOM')], ['says it was not compared', /not compared|observed/i.test(t)]] },
    outside: { n: 1, state: null, cr: 'partial', ex: (t) => [['outside-scope: source shown, no CBOM record, reason visible', hasRecord(t, 'Source call site') && !hasRecord(t, 'Selected CBOM') && /outside/i.test(t)]] },
    noscope: { n: 1, state: null, cr: 'partial', ex: (t) => [['unrecorded scope: source shown, no CBOM record, reason visible', hasRecord(t, 'Source call site') && !hasRecord(t, 'Selected CBOM') && /scope/i.test(t)]] },
    cbomfail: { n: 1, state: null, cr: 'failed', ex: (t) => [['producer failed: source shown, no CBOM record fabricated', hasRecord(t, 'Source call site') && !hasRecord(t, 'Selected CBOM')]] },
};
export const UIP13_MATRIX = {
    pos: { n: 2, cap: 'completed', ex: { supported: (t) => [['shows source path:line, verbatim excerpt, exact locator and digest', /app\/m\.py:1/.test(t) && has(t, 'det.onnx') && has(t, 'Locator (exact') && /File SHA-256/.test(t)],
        ['shows the AI-BOM identity: producer, digest, recorded acquisition binding and scan scope', has(t, 'Selected AI-BOM') && /cisco-aibom/.test(t) && has(t, 'Acquisition binding: recorded') && has(t, 'AI-BOM scan scope (as recorded)')],
        ['conclusion is declaration level, with the intended-scope limit', /Declared in the AI-BOM \(declaration level\)/i.test(t) && /not that it examined every file or reference/.test(t) && /Declaration-level agreement only/.test(t)],
        ['download, load, execution and independent verification are explicitly NOT claimed', /not downloaded or executed/.test(t) && /not artifact identity, digest verification, independent verification, or evidence that the model is loaded/.test(t)]],
      unverifiable: (t) => [['inconclusive: no matching model record, with the reason', /no_matching_model_record|no matching model record/i.test(t) || /Could not/i.test(t)], ['query and fragment are part of the shown locator', has(t, '?download=1#v2')]] } },
    zeromodel: { n: 1, cap: 'completed', ex: { unverifiable: (t) => [['zero-model AI-BOM: record shown, 0 models declared, inconclusive (not an empty result)', has(t, 'Selected AI-BOM') && /0 models declared/.test(t)]] } },
    ambig: { n: 1, cap: 'completed', ex: { unverifiable: (t) => [['two exact locators: ambiguous, never supported', /ambiguous/i.test(t) && /2 AI-BOM models considered/.test(t)]] } },
    basename: { n: 1, cap: 'completed', ex: { unverifiable: (t) => [['basename-only is a candidate, not identity', /candidates_without_locator_match|basename|name or basename/i.test(t)]] } },
    outside: { n: 1, cap: 'partial', ex: { unknown_coverage: (t) => [['outside scope: source shown, reason visible, no verdict', has(t, 'Model reference in source') && /outside_aibom_scan_scope|outside the AI-BOM scope|outside aibom scan scope/i.test(t) && !/Declared in the AI-BOM \(declaration level\)/i.test(t)]] } },
    noscope: { n: 1, cap: 'partial', ex: { unknown_coverage: (t) => [['unrecorded scope: reason visible, no verdict', /scope_missing|does not record a usable scan scope|scope missing/i.test(t)]] } },
    aibomfail: { n: 1, cap: 'failed', ex: { unknown_coverage: (t) => [['producer failed: source shown, no AI-BOM record fabricated', has(t, 'Model reference in source') && !has(t, 'Selected AI-BOM') && !has(t, 'AI-BOM scan scope')]] } },
    hostile: { n: 1, cap: 'completed', ex: { supported: (t) => [['hostile AI-BOM text is shown as text', true]], unverifiable: (t) => [['hostile AI-BOM text is shown as text', true]] } },
};
