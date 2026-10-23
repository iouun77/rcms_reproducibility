# STIX 2.1 bundles used in Section V (Weaxor S1, Babuk S24)
Generated deterministically from records_24/*.json by scripts/build_stix_bundle.py using stix_mapping.csv.
Each bundle has 12 objects: malware 1, identity 1, indicator 1, file 1, artifact 1, note 1, attack-pattern 2, relationship 3, extension-definition 1.
Native fields (7) are placed in standard properties; all Extension-Required fields are serialized ONLY inside `extensions` keyed by the RCMS extension-definition.
NOTE: the comparison in Section V is the authors' semantic analysis of these bundles against the STIX 2.1 standard vocabulary; it is not the output of an independent third-party STIX consumer program.
