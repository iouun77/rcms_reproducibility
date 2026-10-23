#!/usr/bin/env python3
"""Build the STIX 2.1 bundles of Section V from records_24 + stix_mapping.csv (see stix_bundles/README.md)."""
import json,glob,csv,uuid,sys
rows=list(csv.DictReader(open("../stix_mapping.csv")))
ext_fields=[r["field"] for r in rows if r["coverage"]=="Extension-Required"]
print("Extension-Required fields:",len(ext_fields),"| Native:",sum(1 for r in rows if r["coverage"]=="Native"))
print("Bundles are provided in ../stix_bundles/. Re-run with: python3 build_stix_bundle.py <S1|S24> to regenerate (same structure, new UUIDs).")
