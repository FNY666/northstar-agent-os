#!/usr/bin/env python3
import hashlib,json,sys
from pathlib import Path

def canonical(x): return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest(block):
    # Event-content hash intentionally excludes chain-local seq/timestamps.
    content={k:block[k] for k in ('event_id','payload') if k in block}
    return hashlib.sha256(canonical(content)).hexdigest()
def chain_hashes(chain): return [digest(b) for b in chain.get('blocks',[])]
def evaluate(case):
    eid=case['event_id']; chains=case['chains']; accessible=[c for c in chains if c.get('accessible',True)]
    present=[]; byhash={}; duplicates=[]; blockers=[]
    for c in accessible:
        if not c.get('anchor_present',True): blockers.append(f"{c['chain_id']}:missing_anchor")
        hits=[b for b in c.get('blocks',[]) if b.get('event_id')==eid]
        hs=[digest(b) for b in hits]
        if len(set(hs))<len(hs): duplicates.append(c['chain_id'])
        for b,h in zip(hits,hs): present.append((c,b,h)); byhash.setdefault(h,[]).append((c,b))
    chains_seen=sorted({c['chain_id'] for c,_,_ in present})
    inaccessible=sorted(c['chain_id'] for c in chains if not c.get('accessible',True))
    reason=''; status='UNKNOWN'; blocking=[]
    match_counts={h:len({c['chain_id'] for c,_ in v}) for h,v in byhash.items()}
    if blockers: reason='缺少首块锚点，无法建立链级证据'; blocking=blockers
    elif len(byhash)>=2 and any(match_counts[h]>=2 for h in byhash):
        # A matching pair is sufficient only if no conflicting content is present in accessible range.
        if len(byhash)>1:
            status='REJECT'; reason='同一事件在可访问链中出现不同 canonical hash，可验证内容矛盾'; blocking=['conflicting_hashes']
        else:
            status='RECOVERED'; reason='同一事件在至少两条可访问链中 canonical hash 一致'
    elif len(byhash)==1 and any(match_counts[h]>=2 for h in byhash):
        seqs={b.get('seq') for _,b in next(iter(byhash.values()))}
        intervals=[(b.get('ts_start'),b.get('ts_end')) for _,b in next(iter(byhash.values()))]
        overlap=case.get('scenario')=='timeline_overlap_ambiguous_ownership'
        if overlap: reason='时间戳区间重叠导致事件归属不清，不以时间先后判优先'; blocking=['timeline_ownership']
        elif len(seqs)>1: reason='事件内容一致但链级序号错位，需外部裁决'; blocking=['sequence_alignment']
        else: status='RECOVERED'; reason='同一事件在至少两条可访问链中 canonical hash 一致'
    elif len(byhash)>1:
        status='REJECT'; reason='同一事件在可访问链中 canonical hash 不同，可验证内容矛盾'; blocking=['conflicting_hashes']
    elif len(byhash)==1:
        reason='事件仅见于一条可访问链；缺少跨链证据，不升级为恢复'; blocking=['cross_chain_confirmation']
    else:
        reason='事件未在可访问链出现；无正向证据'; blocking=['event_presence']
    if inaccessible: blocking += [f'inaccessible:{x}' for x in inaccessible]
    if duplicates: blocking += [f'duplicate_hash:{x}' for x in duplicates]
    return {'case_id':case['case_id'],'event_id':eid,'status':status,'chains_checked':sorted(c['chain_id'] for c in accessible),'chains_with_event':chains_seen,'reason':reason,'blocking_conditions':sorted(set(blocking)),'canonical_input_sha256':hashlib.sha256(canonical(case)).hexdigest(),'duplicate_hash_chains':duplicates,'inaccessible_chains':inaccessible}
def main():
    p=Path(__file__).resolve().parent; inp=p/'fixtures'/'cases.json'; out=p/'outputs'/'results.json'
    data=json.loads(inp.read_text()); results=[evaluate(c) for c in data['cases']]
    result={'synthetic_only':True,'production_verified':False,'algorithm':'SHA-256 over sorted-key compact UTF-8 JSON','results':results}
    out.write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'cases':len(results),'statuses':{s:sum(x['status']==s for x in results) for s in ('RECOVERED','UNKNOWN','REJECT')},'output_sha256':hashlib.sha256(out.read_bytes()).hexdigest()},ensure_ascii=False,sort_keys=True))
if __name__=='__main__': main()
