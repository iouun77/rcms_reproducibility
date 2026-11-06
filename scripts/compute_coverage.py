#!/usr/bin/env python3
"""Compute the coverage measures of the paper exactly as defined:
  Eq.(13) OC  = |Obs| / |A|          Eq.(14) DC = (|Obs| + |None_a|) / |A|
  Eq.(15) UR  = (|U| + |NA|) / |A|   Eq.(16) GIR = (|F| - |A|) / |F|
  Eq.(17) C_analysis = (|F| - |F_NA|) / |F|
  Eq.(20) fill-rate(F_layer) = (|Confirmed| + |None|) / (|F_layer| - |Not-Analyzed|)   [gate-entailed None counted as None]
A = applicable fields = F minus fields deactivated by a gate (same four gate parents as validate_records.py).
Averages are reported over the 24 records.
"""
import json, glob, os, re, statistics
HERE=os.path.dirname(os.path.abspath(__file__)); ROOT=os.path.join(HERE,"..")
schema=json.load(open(os.path.join(ROOT,"rcms_schema_v1.0.json")))["fields"]
paths=[f["path"] for f in schema]; layer={f["path"]:f["layer"] for f in schema}
# gate relations: a field is gated by '<prefix>.present' / '<prefix>.included' when that gate is No/None
# gate parents (identical to validate_records.py)
GATES={"crypto.kdf.present":"crypto.kdf.","crypto.asymmetric.algorithm":"crypto.asymmetric.","ransom_note.present":"ransom_note.","payment.victim_id.present":"payment.victim_id."}
STATES=("None","Undetermined","Not-Analyzed")
def is_absent(v): return v in ("No","None",None,"")
def classify(rec):
    f=rec["fields"]; inactive=set()
    for g,pre in GATES.items():
        if is_absent(f.get(g)):
            for p in paths:
                if p!=g and p.startswith(pre): inactive.add(p)
    A=[p for p in paths if p not in inactive]
    obs=[p for p in A if f.get(p) not in STATES and f.get(p) not in (None,"")]
    none_a=[p for p in A if f.get(p)=="None"]           # analysis-confirmed absence (gate-entailed None are in `inactive`, not in A)
    und=[p for p in A if f.get(p)=="Undetermined"]; na=[p for p in A if f.get(p)=="Not-Analyzed"]
    F=len(paths); nA=len(A)
    oc=len(obs)/nA; dc=(len(obs)+len(none_a))/nA; ur=(len(und)+len(na))/nA; gir=(F-nA)/F
    ca=(F-sum(1 for p in paths if f.get(p)=="Not-Analyzed"))/F
    fr={}
    for L in ("L1","L2","L3","L4"):
        FL=[p for p in paths if layer[p]==L]; conf=[p for p in FL if f.get(p) not in STATES and f.get(p) not in (None,"")]
        nn=[p for p in FL if f.get(p)=="None"]; nan=[p for p in FL if f.get(p)=="Not-Analyzed"]
        fr[L]=(len(conf)+len(nn))/(len(FL)-len(nan))
    return dict(OC=oc,DC=dc,UR=ur,GIR=gir,C_analysis=ca,fill=fr)
rows=[classify(json.load(open(j))) for j in sorted(glob.glob(os.path.join(ROOT,"records_24","S*.json")))]
mean=lambda k: statistics.mean(r[k] for r in rows)*100
print(f"OC {mean('OC'):.1f}%  DC {mean('DC'):.1f}%  UR {mean('UR'):.1f}%  GIR {mean('GIR'):.1f}%  C_analysis {mean('C_analysis'):.1f}%  (N={len(rows)})")
for L in ("L1","L2","L3","L4"): print(f"  fill-rate {L}: {statistics.mean(r['fill'][L] for r in rows)*100:.1f}%")
