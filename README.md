# RCMS v1.0 — Reproducibility Package

Companion to: K. Kim, S. Lee, J. Cho, D. Lee, Y. Park, and H. Kim, "RCMS: Defining a Ransomware-Native Metadata Schema for Cryptographic Behavior," submitted to *IEEE Access*, 2026.

## Quick verification (reproduces every number in the paper)
```bash
cd scripts
python3 validate_records.py    # E1: 2,592 cells, 0 violations
python3 test_rules.py          # 23/23 boundary & counterexample tests
python3 evaluate_rules.py      # full chain recomputed from observations: 24/24 (R_rule = 1.00)
python3 compute_coverage.py    # Eqs. (13)-(17),(20): OC 72.0 / DC 77.8 / UR 20.8 / GIR 3.4 / C_analysis 98.6; layer fill 75.8/52.9/86.3/94.8
```
Judgment distribution: Full 4 / Partial 3 / Infeasible 16 / Undetermined 1. No malware binaries are included (SHA-256 only).


Repository: https://github.com/iouun77/rcms_reproducibility  
Zenodo DOI: _to be assigned at release v1.0.0_

## Reproduce (executable verification)
```
cd scripts
python3 compute_coverage.py   # Eqs.(13)-(17),(20): OC 72.0 / DC 77.8 / UR 20.8 / GIR 3.4 / C_analysis 98.6; layer fill rates 75.8/52.9/86.3/94.8
python3 validate_records.py   # E1: type/enum/required/gate; 2559 checked, 0 violations
python3 test_rules.py         # E2: 20/20 unit tests (per-condition prerequisites, boundaries, priority)
python3 evaluate_rules.py     # full chain method->prerequisites->assessment, 0 mismatch over 24 records
```
Expected outputs: `scripts/expected_results.json`. Judgment distribution: Full 4 / Partial 3 / Infeasible 16 / Undetermined 1.

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


## Semantics notes (v1.0, 2026-10-26)
- `crypto.known_plaintext.availability` records candidate presence only (candidate-present) and is not an input to `recovery.assessment.class`. For Key-Reuse/Static-IV, `required_conditions.candidate_verifiable = Confirmed` means a concrete verification oracle (plaintext–ciphertext pair or known fixed header) is identified; actual pair acquisition for a given victim is an operational condition outside the judgment.
- Thresholds T1 = 40, T2 = 56, T3 = 64 bits. `recovery.keyspace.exponent = 0` is a reserved value meaning 'no exhaustive-search target', not a 0-bit keyspace.
- Rules are evaluated in listed order (first match); method priority Hardcoded-Key > Key-Reuse > Weak-RNG > Memory-Key > Static-IV > None.
- `Full` = theoretical recoverability under the recorded prerequisites, not demonstrated decryption.

- Judgment rules follow Kleene three-valued logic (True ∨ U = True; False ∧ U = False; ¬U = U; otherwise U), with Not-Analyzed taking precedence over Undetermined. A method indicator that is Undetermined with no confirmed indicator yields method.class = Undetermined and assessment.class = Undetermined (S6).
- External consistency (A_ext) is reported only over X_ref = samples with an independently published *cryptographic* recovery result; decryptors based on leaked/seized keys (e.g., GandCrab, LockBit) are outside RCMS scope and are recorded in decryptor.public.present.
