# E3-B limitations

* Controlled documents from E2 (16 anchors, 125 related variants); counts are not independent samples.
* The three malformed controls per family break one schema requirement each; they are not a general invalid-input corpus.
* The diff tool receives the original and the modified document. OpenTrace receives source evidence and one document. Different tasks.
* Tasks are never merged into one score; no PSR/UCR/CRR is computed for a document tool.
* Output parsers follow cyclonedx-cli v0.33.1 messages and sbom-tools v0.4.0 JSON; other output is reported as unclassified/unparsed.
* Quality profiles were not part of the recovered 14 operations and are not run.
