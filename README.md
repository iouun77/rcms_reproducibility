# RCMS v1.0 Reproducibility Package

## Reproduce (executable verification)
```
cd scripts
python3 validate_records.py   # E1: type/enum/required/gate; 2559 checked, 0 violations
python3 test_rules.py         # E2: 20/20 unit tests (per-condition prerequisites, boundaries, priority)
python3 evaluate_rules.py     # full chain method->prerequisites->assessment, 0 mismatch over 24 records
```
Expected outputs: `scripts/expected_results.json`. Judgment distribution: Full 4 / Partial 3 / Infeasible 17.

## Contents
- rcms_schema_v1.0.json : 108-field schema (types, allowed values, tier, gate, derives_from)
- records_24/ : 24 anonymized records (flat JSON, list fields as JSON arrays)
- derivation_rules.json : method/prerequisite/assessment rules (Weak-RNG <- weak_rng OR predictable_seed; Key-Reuse precedes Static-IV)
- stix_mapping.csv : per-field stix_object, stix_property, mbc_identifier, coverage, classification_rationale (Native 7 / Ext 38 / NR 63 under STIX 2.1 alone; Native 7 / Ext 41 / NR 60 under STIX 2.1+MBC)
- validation_results.csv : per-sample method/bruteforce/assessment (synced with records_24)
- scripts/ : validate_records.py, evaluate_rules.py, test_rules.py, expected_results.json
- experiments/, kappa_study/ : E1/E2/E5 results, annotation data

## Definitions
- Full = theoretical recoverability under stated prerequisites (NOT demonstrated decryption)
- Infeasible = no known recovery path within observed scope (NOT mathematical impossibility)
No malware binaries or decryption included.
