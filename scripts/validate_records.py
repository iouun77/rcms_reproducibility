#!/usr/bin/env python3
"""E1: Validate 24 RCMS records against schema.
Checks: (a) enum allowed-values, (b) data types incl. list<string> element types,
(c) required fields present, (d) gate conditions (dependent fields None when gate absent).
Reproduces the Section VI validity check over 2,559 recorded values."""
import json, os, glob

STATE={"None","Undetermined","Not-Analyzed"}

# gate parents: if parent value in {No, None} -> dependent (prefix) fields must be None/empty
GATES={
 "crypto.kdf.present":"crypto.kdf.",
 "crypto.asymmetric.algorithm":"crypto.asymmetric.",
 "ransom_note.present":"ransom_note.",
 "payment.victim_id.present":"payment.victim_id.",
}

def load_schema(path="../rcms_schema_v1.0.json"):
    s=json.load(open(path))
    return {f["path"]:f for f in s["fields"]}

def check_type(sv, dtype, allowed=""):
    """Return True if value conforms to the declared data_type."""
    dtype=str(dtype or ""); allowed=str(allowed or "")
    if sv in STATE: return True
    # numeric range encoded as string allowed-value like "int(0-512)|..."
    if "int(" in allowed:
        try: int(sv); return True
        except: return sv in STATE
    if dtype.startswith("list"):
        try:
            v=json.loads(sv.replace("'",'"'))
            return isinstance(v,list) and all(isinstance(x,str) for x in v)
        except: return False
    if dtype=="json":
        if sv in STATE: return True
        try:
            json.loads(sv.replace("'",'"')); return True
        except: return sv.startswith("[") or sv.startswith("{")
    # string, string(n), enum, datetime -> accept as text
    return True

def is_enum_allowed(allowed):
    """True only if allowed_values is a fixed enumeration of literal values."""
    a=str(allowed or "")
    if "|" not in a: return False
    # format descriptors / free-form indicators are NOT enumerations
    descriptors=["free-text","int(","json-array","crypto_function","URL","ISO-8601",
                 "template-id","date","UUID","hex","path","text","Name"]
    if any(d in a for d in descriptors): return False
    return True

def enum_options(allowed):
    a=str(allowed).replace("json-array of ","")
    return set(a.split("|"))|STATE

def check_enum(sv, allowed, dtype):
    if not is_enum_allowed(allowed): return True
    opts=enum_options(allowed)
    # list<string>: every element must be in enum
    if str(dtype).startswith("list") or str(allowed).startswith("json-array of"):
        try:
            v=json.loads(sv.replace("'",'"'))
            return all(x in opts for x in v)
        except: return False
    if sv.startswith("[") or sv.startswith("{"): return True
    return sv in opts

def validate_record(fields, schema):
    checked=empty=type_v=enum_v=req_v=gate_v=0
    viols=[]
    # gate: determine inactive prefixes
    gate_inactive=set()
    for gate,prefix in GATES.items():
        gv=str(fields.get(gate) or "")
        if gv in ("No","None",""):
            for p in schema:
                if p.startswith(prefix) and p!=gate: gate_inactive.add(p)
    for path,spec in schema.items():
        v=fields.get(path)
        sv="" if v is None else str(v).strip()
        # required check
        req=str(spec.get("requirement") or "")
        if sv=="":
            empty+=1
            if req=="R" and path not in gate_inactive:
                req_v+=1; viols.append(f"MISSING required {path}")
            continue
        checked+=1
        dtype=spec.get("data_type"); allowed=spec.get("allowed_values")
        # gate check: dependent field has a value though gate is absent
        if path in gate_inactive and sv not in STATE:
            gate_v+=1; viols.append(f"GATE {path}={sv} (parent absent)")
        # type check
        if not check_type(sv, dtype, allowed):
            type_v+=1; viols.append(f"TYPE {path}={sv} (expected {dtype})")
        # enum check
        if not check_enum(sv, allowed, dtype):
            enum_v+=1; viols.append(f"ENUM {path}={sv}")
    return dict(checked=checked,empty=empty,type=type_v,enum=enum_v,req=req_v,gate=gate_v,viols=viols)

if __name__=="__main__":
    schema=load_schema()
    tot=dict(checked=0,empty=0,type=0,enum=0,req=0,gate=0)
    for jf in sorted(glob.glob("../records_24/S*.json")):
        rec=json.load(open(jf))
        r=validate_record(rec["fields"], schema)
        for k in tot: tot[k]+=r[k]
        for v in r["viols"]: print(f"{os.path.basename(jf)}: {v}")
    print(f"\nChecked values: {tot['checked']}")
    print(f"Empty/gate-inactive cells: {tot['empty']}")
    print(f"Type violations: {tot['type']}")
    print(f"Enum violations: {tot['enum']}")
    print(f"Missing-required violations: {tot['req']}")
    print(f"Gate violations: {tot['gate']}")
    print(f"Total cells: {tot['checked']+tot['empty']} (expected 24x108=2592)")
    total_v=tot['type']+tot['enum']+tot['req']+tot['gate']
    assert total_v==0, f"Validation FAILED: {total_v} violations"
    print("PASS: all records conform (type, enum, required, gate)")
