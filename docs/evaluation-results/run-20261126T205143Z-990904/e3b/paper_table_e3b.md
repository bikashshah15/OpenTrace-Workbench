| Task | CycloneDX CLI | sbom-tools | OpenTrace (existing results, not rerun) |
|---|---|---|---|
| Valid documents accepted / interpretable | 141/141 | not planned | separate task |
| Malformed controls rejected / interpretable | 9/9 | not planned | separate task |
| Known removed record surfaced in document pair / interpretable | not planned | 14/14 | separate task (receives one BOM, not the pair) |
| Source-grounded claim assessment | not evaluated (not applicable to this claim) | not evaluated (not applicable to this claim) | Existing E2/E3: 46/46 decidable resolved; 0/95 unsupported conclusions; 14/14 diff-pair variants `contradicted` from source + one BOM |

Diff granularity (interpretable runs): {"record_level": 14, "name_only": 0, "component_level_modified": 0, "not_surfaced": 0}. A diff tool receives both documents; surfacing a removal does not say it is wrong. A schema-valid document with a package removed is correctly accepted by a validator.
