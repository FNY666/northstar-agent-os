#!/usr/bin/env python3
import json, hashlib, hmac, sys
from pathlib import Path

KEY=b'S18-SYNTHETIC-LOCAL-KEY-v1'
ROOT=Path(__file__).resolve().parent

def canon(v): return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def sha(v): return hashlib.sha256(canon(v)).hexdigest()
def expected_hash(r): return hmac.new(KEY,canon({k:v for k,v in r.items() if k!='record_hash'}),hashlib.sha256).hexdigest()
def iso_in(ts,w): return w['start'] <= ts <= w['end']
def unique_records(rs):
    seen=set(); out=[]; duplicates=[]
    for r in rs:
        key=(r.get('seq'),r.get('record_hash'))
        if key in seen:
            duplicates.append(key); continue
        seen.add(key); out.append(r)
    return out,duplicates

def evaluate(c):
    rs,dups=unique_records(c['records'])
    rs=sorted(rs,key=lambda r:(r.get('seq',0),r.get('record_hash','')))
    blockers=[]; gaps=[]; rejects=[]
    # A record without self hash cannot establish either side of a contradiction.
    for r in rs:
        if not r.get('record_hash'):
            blockers.append(f"seq {r.get('seq')}: missing record_hash")
        elif expected_hash(r)!=r['record_hash']:
            blockers.append(f"seq {r.get('seq')}: record_hash verification failed")
    valid=[r for r in rs if r.get('record_hash') and expected_hash(r)==r['record_hash']]
    byseq={}
    for r in valid: byseq.setdefault(r.get('seq'),[]).append(r)
    for seq,items in sorted(byseq.items()):
        sig={(i.get('prev_hash'),i.get('payload')) for i in items}
        hashes={i.get('record_hash') for i in items}
        if len(hashes)>1:
            payloads={i.get('payload') for i in items}
            if len(payloads)>1: rejects.append(f"seq {seq}: verified fork with different payloads")
            else: blockers.append(f"seq {seq}: same-content fork requires external adjudication")
    seqs=sorted({r.get('seq') for r in valid if isinstance(r.get('seq'),int)})
    if seqs:
        if seqs[0] != 1: blockers.append(f"head truncated: first observed seq {seqs[0]}, anchor seq 1 unavailable")
        terminal=c.get('terminal_seq')
        if terminal is not None and seqs[-1] < terminal: blockers.append(f"tail truncated: observed through seq {seqs[-1]}, terminal seq {terminal} not reached")
        if seqs != list(range(seqs[0],seqs[-1]+1)):
            missing=[str(i) for i in range(seqs[0],seqs[-1]+1) if i not in seqs]
            gaps.append('missing sequence(s): '+','.join(missing))
        for i in range(1,len(seqs)):
            a,b=seqs[i-1],seqs[i]
            if b==a+1:
                prev=byseq[a][0]['record_hash']; got=byseq[b][0].get('prev_hash')
                if got!=prev:
                    rejects.append(f"seq {b}: prev_hash {got} contradicts verified predecessor seq {a} hash {prev}")
    for r in valid:
        w=c.get('observation_window')
        if w and not iso_in(r.get('timestamp',''),w): blockers.append(f"seq {r.get('seq')}: timestamp outside inclusive observation window")
    anchor=c.get('external_anchor')
    if anchor and anchor.get('status')=='unreachable': blockers.append('external anchor unreachable; source provenance is unverified')
    if gaps: blockers.extend(gaps)
    if rejects: status='REJECT'; reason='; '.join(rejects)
    elif blockers: status='UNKNOWN'; reason='; '.join(blockers)
    else: status='RECOVERED'; reason='all observed records form a verified contiguous chain within scope'
    prevs=[r.get('prev_hash') for r in rs]
    recs=[r.get('record_hash') for r in rs]
    return {'case_id':c['case_id'],'chain_id':c['chain_id'],'status':status,
      'prev_hash':prevs[0] if prevs else None,'record_hash':recs[0] if recs else None,
      'prev_hashes':prevs,'record_hashes':recs,'gap_location':gaps,
      'reason':reason,'blocking_conditions':blockers,'duplicate_records_ignored':len(dups),
      'canonical_input_sha256':sha(c),'synthetic_only':True,'production_verified':False}

def main():
    inp=ROOT/'fixtures/cases.json'; out=ROOT/'outputs/results.json'
    d=json.loads(inp.read_text()); results=[evaluate(c) for c in d['cases']]
    if any(r['status'] not in {'RECOVERED','UNKNOWN','REJECT'} for r in results): raise SystemExit('invalid state')
    if any(r['status']!=c['expected'] for r,c in zip(results,d['cases'])):
        for r,c in zip(results,d['cases']):
            if r['status']!=c['expected']: print('MISMATCH',c['case_id'],c['expected'],r['status'],r['reason'])
        raise SystemExit(2)
    out.write_text(json.dumps({'schema_version':'S18-results-v1','synthetic_only':True,'production_verified':False,'results':results},ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    print(f'PASS: {len(results)} cases; statuses={{RECOVERED:{sum(r["status"]=="RECOVERED" for r in results)}, UNKNOWN:{sum(r["status"]=="UNKNOWN" for r in results)}, REJECT:{sum(r["status"]=="REJECT" for r in results)}}}')
    print('OUTPUT',out)
if __name__=='__main__': main()
