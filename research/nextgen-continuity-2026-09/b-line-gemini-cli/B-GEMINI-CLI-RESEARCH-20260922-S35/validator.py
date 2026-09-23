#!/usr/bin/env python3
SYNTHETIC_ONLY = True
PRODUCTION_VERIFIED = False
"""S35 property validator. Fails closed on any interop or conservative violation."""
import hashlib, importlib.util, json, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parent
CASES = ROOT/"fixtures/cases.json"; OUT = ROOT/"outputs/results.json"
ALLOWED = {"accepted", "rejected", "UNKNOWN"}; DECLARED = {"P","Q","R"}

def load(path, name):
    spec=importlib.util.spec_from_file_location(name, path); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

def canon(x): return json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()
def verdict_map(mod, fixture): return mod.evaluate_fixture(fixture)
def check(name, fn):
    try: fn(); print("PASS", name); return True
    except AssertionError as e: print("FAIL", name, "-", e); return False

def main():
    A=load(ROOT/"impl_a.py","A"); B=load(ROOT/"impl_b.py","B")
    cases=json.loads(CASES.read_text())["fixtures"]; result=json.loads(OUT.read_text())
    checks=[]
    def basic():
        assert result["synthetic_only"] is True and result["production_verified"] is False
        assert len(cases) >= 20 and result["fixture_count"] == len(cases)
        assert len(result["results"]) == len(cases)
        for f,row in zip(cases,result["results"]):
            assert row["canonical_input_sha256"] == hashlib.sha256(canon(f)).hexdigest()
            va,vb=verdict_map(A,f),verdict_map(B,f)
            assert row["impl_A"]["impl_id"]=="impl-A" and row["impl_B"]["impl_id"]=="impl-B"
            assert va==row["impl_A"]["verdicts"] and vb==row["impl_B"]["verdicts"]
            assert set(va.values()) <= ALLOWED and set(vb.values()) <= ALLOWED
    checks.append(check("fixture/schema/canonical hashes",basic))
    def interop():
        for r in result["results"]:
            assert r["consistent"] is True and r["conflict"] is False and r["interop"]=="INTEROP_OK"
        assert sum(r["interop"]=="INTEROP_OK" for r in result["results"])==len(cases)
        assert sum(r["conflict"] for r in result["results"])==0
    checks.append(check("cross-implementation consistency",interop))
    def locality():
        for mod in (A,B):
            for f in cases:
                before=verdict_map(mod,f)
                for target in f["events"]:
                    changed=json.loads(json.dumps(f));
                    for e in changed["events"]:
                        if e["event_id"]==target["event_id"]: e["revoked"]=True
                    after=verdict_map(mod,changed)
                    allowed={e["event_id"] for e in f["events"] if e.get("batch_id")==target.get("batch_id")}
                    for eid in before:
                        if eid not in allowed: assert before[eid]==after[eid], (mod.__name__,f["fixture_id"],eid)
    checks.append(check("locality under explicit revocation",locality))
    def unattrib():
        for mod in (A,B):
            for f in cases:
                full=verdict_map(mod,f)
                for e in f["events"]:
                    if e.get("op_id") not in DECLARED: assert full[e["event_id"]]=="UNKNOWN", (mod.__name__,f["fixture_id"])
                known={"events":[e for e in f["events"] if e.get("op_id") in DECLARED]}
                reduced=verdict_map(mod,known)
                for eid,v in reduced.items(): assert full[eid]==v, (mod.__name__,f["fixture_id"],eid)
    checks.append(check("undeclared op non-attribution",unattrib))
    def conservative():
        for mod in (A,B):
            for f in cases:
                vals=verdict_map(mod,f)
                assert set(vals.values()) <= ALLOWED
                for e,v in vals.items():
                    src=next(x for x in f["events"] if x["event_id"]==e)
                    if src.get("op_id") not in DECLARED or src.get("revoked") or src.get("anomaly") in {"duplicate","out_of_order","missing"}: assert v=="UNKNOWN"
    checks.append(check("three-state mutual exclusion and conservative anomalies",conservative))
    def reproducible():
        original=OUT.read_bytes(); hashes=[]
        for _ in range(2):
            subprocess.run([sys.executable,str(ROOT/"harness.py")],check=True,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            hashes.append(hashlib.sha256(OUT.read_bytes()).hexdigest())
        assert OUT.read_bytes()==original
        assert hashes[0]==hashes[1]
    checks.append(check("deterministic harness rerun byte identity",reproducible))
    print("property_assertions="+str(sum(checks))+"/"+str(len(checks)))
    return 0 if all(checks) else 1
if __name__=="__main__": raise SystemExit(main())
