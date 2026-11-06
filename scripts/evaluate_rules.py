#!/usr/bin/env python3
"""Evaluate the full recovery judgment chain (method -> prerequisites -> assessment)
from OBSERVED fields only (no judgment field is read as an input), and compare each
derived value with the recorded value for all 24 records.

Key design (addresses reviewer M1/M2):
- Memory-Key is derived from an OBSERVATION (required_artifacts mentioning memory
  residue), not from the recorded method.class, so there is no circular reference.
- Prerequisites are read from a STRUCTURED required_conditions object
  {condition: {status: Confirmed|Not-Confirmed|Undetermined, evidence: ...}},
  not from free-text substring matching.
"""
import json, glob, os

def get(f,k): return f.get(k)

def parse_conditions(f):
    """Return dict {condition: status}. Structured JSON expected; empty if absent."""
    raw = get(f,"recovery.method.required_conditions")
    if not raw or str(raw) in ("None","Undetermined","Not-Analyzed",""): return {}
    try:
        obj = json.loads(str(raw).replace("'",'"'))
        if isinstance(obj,dict):
            return {k:(v.get("status") if isinstance(v,dict) else v) for k,v in obj.items()}
    except Exception:
        return {}
    return {}

def has_memory_evidence(f):
    """Memory-Key derived from observation. Prefers forensic evidence in
    evidence.artifacts; falls back to required_artifacts mentioning memory residue.
    Does NOT read recovery.method.class (no circular reference)."""
    ev = str(get(f,"evidence.artifacts") or "").lower()
    arts = str(get(f,"recovery.method.required_artifacts") or "").lower()
    forensic = ("memory" in ev) or ("heap" in ev) or ("process memory" in ev) or ("residue" in ev)
    artifact = ("memory" in arts) or ("heap" in arts) or ("process memory" in arts)
    return forensic or artifact

def derive_method(f):
    """method.class from OBSERVED weakness/evidence fields, priority order.
    No judgment field is used as input."""
    if get(f,"weakness.hardcoded_key.detected")=="Yes": return "Hardcoded-Key"
    if get(f,"weakness.key_reuse.detected")=="Yes": return "Key-Reuse"
    if get(f,"weakness.weak_rng.detected")=="Yes" or get(f,"weakness.predictable_seed.detected")=="Yes": return "Weak-RNG"
    if has_memory_evidence(f): return "Memory-Key"           # derived from observation
    if get(f,"weakness.static_iv.detected")=="Yes": return "Static-IV"
    # Kleene three-valued OR: no indicator confirmed True, but at least one Undetermined -> Undetermined
    inds=[get(f,k) for k in ("weakness.hardcoded_key.detected","weakness.key_reuse.detected","weakness.weak_rng.detected","weakness.predictable_seed.detected","weakness.static_iv.detected")]
    if any(v=="Not-Analyzed" for v in inds): return "Not-Analyzed"
    if any(v=="Undetermined" for v in inds): return "Undetermined"
    return "None"

def prerequisites_met(f, method):
    """All required conditions for the method must have status == Confirmed."""
    conds = parse_conditions(f)
    required = {
        "Hardcoded-Key": ["file_encryption_key_verified"],
        "Key-Reuse":     ["keystream_reuse_confirmed","candidate_verifiable"],
        "Static-IV":     ["keystream_reuse_confirmed"],
        "Weak-RNG":      ["seed_observable","candidate_verifiable"],
        "Memory-Key":    ["no_reboot_heap_intact"],
    }.get(method, [])
    if not required: return False
    return all(conds.get(c)=="Confirmed" for c in required)

def derive_bruteforce(keyspace):
    s=str(keyspace)
    if s in ("Undetermined","Not-Analyzed","None") or keyspace is None: return "Undetermined"
    try: k=int(keyspace)
    except: return "Undetermined"
    if k==0: return "No"
    if k<=40: return "Immediate"
    if k<=64: return "Conditional"
    return "No"

def derive_assessment(f):
    method = derive_method(f)
    bf = derive_bruteforce(get(f,"recovery.keyspace.exponent"))
    if method in ("Undetermined","Not-Analyzed"): return method   # judgment withheld (K3 propagation)
    if method!="None":
        return "Full" if prerequisites_met(f, method) else "Partial"
    if bf=="Conditional": return "Keyspace-Reduced"
    return "Infeasible"

if __name__=="__main__":
    m_mis=a_mis=bf_mis=0
    for jf in sorted(glob.glob("../records_24/S*.json")):
        f=json.load(open(jf))["fields"]; sid=os.path.basename(jf).split("_")[0]
        dm=derive_method(f); rm=get(f,"recovery.method.class")
        if dm!=rm: print(f"{sid}: method derived={dm} recorded={rm}"); m_mis+=1
        dbf=derive_bruteforce(get(f,"recovery.keyspace.exponent")); rbf=get(f,"recovery.bruteforce.feasibility")
        if dbf!=rbf: print(f"{sid}: bruteforce derived={dbf} recorded={rbf}"); bf_mis+=1
        da=derive_assessment(f); ra=get(f,"recovery.assessment.class")
        if da!=ra: print(f"{sid}: assessment derived={da} recorded={ra}"); a_mis+=1
    print(f"\nmethod mismatches: {m_mis}")
    print(f"bruteforce mismatches: {bf_mis}")
    print(f"assessment mismatches: {a_mis}")
    assert m_mis==0 and a_mis==0 and bf_mis==0, "Rule chain inconsistent with records"
    print("PASS: full chain derived from OBSERVED fields matches records for all 24 samples (no judgment field used as input)")
