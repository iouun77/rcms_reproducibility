#!/usr/bin/env python3
"""E2: Unit tests for recovery rules. Prerequisites are STRUCTURED
{condition: {status: Confirmed|Not-Confirmed|Undetermined, evidence: ...}},
so each cryptographic condition is tested independently via its status."""
import sys, json
sys.path.insert(0,".")
from evaluate_rules import derive_method, derive_bruteforce, prerequisites_met, derive_assessment, has_memory_evidence

def rec(**kw): return kw
def conds(d): return {"recovery.method.required_conditions": json.dumps(d)}

tests=[]
def T(name, got, exp): tests.append((name, got, exp))

# --- brute-force boundaries ---
T("keyspace=40 -> Immediate", derive_bruteforce(40), "Immediate")
T("keyspace=41 -> Conditional", derive_bruteforce(41), "Conditional")
T("keyspace=64 -> Conditional", derive_bruteforce(64), "Conditional")
T("keyspace=65 -> No", derive_bruteforce(65), "No")
T("keyspace=0 -> No (not a target)", derive_bruteforce(0), "No")
T("keyspace=Undetermined", derive_bruteforce("Undetermined"), "Undetermined")

# --- method derivation from OBSERVED fields (no circular use of method.class) ---
f1=rec(**{"weakness.static_iv.detected":"Yes","weakness.key_reuse.detected":"Yes"})
T("static_iv+key_reuse -> Key-Reuse (priority)", derive_method(f1), "Key-Reuse")
f2=rec(**{"weakness.weak_rng.detected":"No","weakness.predictable_seed.detected":"Yes"})
T("predictable_seed only -> Weak-RNG", derive_method(f2), "Weak-RNG")
f3=rec(**{"weakness.static_iv.detected":"Yes","weakness.key_reuse.detected":"No"})
T("static_iv only -> Static-IV", derive_method(f3), "Static-IV")
T("no weakness -> None", derive_method(rec()), "None")
# Memory-Key derived from OBSERVATION (required_artifacts), not method.class
f_mem=rec(**{"recovery.method.required_artifacts":'["process memory (RSA primes)"]'})
T("memory evidence -> Memory-Key (from observation)", derive_method(f_mem), "Memory-Key")
# CRUCIAL: fake method.class=Memory-Key WITHOUT memory evidence must NOT be accepted
f_fake=rec(**{"recovery.method.class":"Memory-Key"})
T("fake method.class=Memory-Key w/o evidence -> None (no circular ref)", derive_method(f_fake), "None")

# --- structured prerequisites (status-based, not substring) ---
T("Hardcoded Confirmed -> met", prerequisites_met({**conds({"file_encryption_key_verified":{"status":"Confirmed"}})}, "Hardcoded-Key"), True)
T("Hardcoded Undetermined -> unmet", prerequisites_met({**conds({"file_encryption_key_verified":{"status":"Undetermined"}})}, "Hardcoded-Key"), False)
T("Key-Reuse both Confirmed -> met", prerequisites_met({**conds({"keystream_reuse_confirmed":{"status":"Confirmed"},"candidate_verifiable":{"status":"Confirmed"}})}, "Key-Reuse"), True)
T("Key-Reuse one Undetermined -> unmet", prerequisites_met({**conds({"keystream_reuse_confirmed":{"status":"Confirmed"},"candidate_verifiable":{"status":"Undetermined"}})}, "Key-Reuse"), False)
T("Weak-RNG candidate Not-Confirmed -> unmet", prerequisites_met({**conds({"seed_observable":{"status":"Confirmed"},"candidate_verifiable":{"status":"Not-Confirmed"}})}, "Weak-RNG"), False)
T("empty conditions -> unmet", prerequisites_met(rec(), "Key-Reuse"), False)

# --- end-to-end assessment ---
f_full=rec(**{"weakness.hardcoded_key.detected":"Yes","recovery.keyspace.exponent":"0", **conds({"file_encryption_key_verified":{"status":"Confirmed"}})})
f_part=rec(**{"weakness.hardcoded_key.detected":"Yes","recovery.keyspace.exponent":"0", **conds({"file_encryption_key_verified":{"status":"Undetermined"}})})
T("assessment Full (prereq Confirmed)", derive_assessment(f_full), "Full")
T("assessment Partial (prereq Undetermined)", derive_assessment(f_part), "Partial")

# --- Kleene three-valued propagation ---
T("K3 OR: Yes with other Undetermined -> method selected", derive_method(rec(**{"weakness.key_reuse.detected":"Undetermined","weakness.weak_rng.detected":"Yes"})), "Weak-RNG")
T("K3 OR: all No except one Undetermined -> Undetermined (not None)", derive_method(rec(**{"weakness.hardcoded_key.detected":"No","weakness.key_reuse.detected":"No","weakness.weak_rng.detected":"No","weakness.predictable_seed.detected":"No","weakness.static_iv.detected":"Undetermined"})), "Undetermined")
T("K3: Undetermined method -> assessment Undetermined", derive_assessment(rec(**{"weakness.hardcoded_key.detected":"No","weakness.key_reuse.detected":"No","weakness.weak_rng.detected":"No","weakness.predictable_seed.detected":"No","weakness.static_iv.detected":"Undetermined","recovery.keyspace.exponent":"None"})), "Undetermined")


if __name__=="__main__":
    passed=0
    for name,got,exp in tests:
        ok=got==exp; passed+=ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {got} (expected {exp})")
    print(f"\n{passed}/{len(tests)} passed")
    assert passed==len(tests), "Some rule unit tests failed"
