# E3-C limitations

* Eleven frozen items (7 requirement declarations, 4 hashlib call sites) from two benchmarks; no recall, precision or completeness claim.
* The reference shows that a declaration or call exists in source, not that anything is installed, resolved, executed or secure.
* SBOM claim: normalized PyPI name representation. CBOM claim: a hash operation and its source occurrence.
* A missing record is a representation difference or unresolved correspondence, not a confirmed scanner defect.
* An empty CBOM is a valid observation, not evidence that the source contains no cryptography. A failed scan is not an empty inventory.
* No verdict has been independently reviewed until manual_audit.csv is completed by a person.
* BF-CBOM is GPL-3.0: the captured source export and excerpts stay local and are not redistributed.
