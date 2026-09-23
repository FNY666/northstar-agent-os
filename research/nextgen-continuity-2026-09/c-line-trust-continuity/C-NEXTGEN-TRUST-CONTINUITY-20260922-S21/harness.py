#!/usr/bin/env python3
"""Offline deterministic S21 happens-before fixture harness."""
import argparse, hashlib, json
from pathlib import Path

def canon(o): return json.dumps(o,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def path_find(adj,x,y):
    q=[x]; prev={x:None}
    while q:
        u=q.pop(0)
        for v in sorted(adj.get(u,())):
            if v not in prev: prev[v]=u; q.append(v)
    if y not in prev:return None
    out=[]; z=y
    while z is not None: out.append(z); z=prev[z]
    return list(reversed(out))
def cycles(nodes,adj):
    color={n:0 for n in nodes}; cyc=[]
    def dfs(u):
        color[u]=1
        for v in sorted(adj.get(u,())):
            if color[v]==1: return True
            if color[v]==0 and dfs(v): return True
        color[u]=2; return False
    return any(color[n]==0 and dfs(n) for n in nodes)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--input',default='fixtures/cases.json'); ap.add_argument('--output',default='outputs/results.json'); a=ap.parse_args()
    d=json.loads(Path(a.input).read_text())
    results=[]
    for c in d['cases']:
        ns=[n['id'] for n in c['nodes']]; nset=set(ns); es=c['edges']; x=c['query']['x']; y=c['query']['y']
        malformed=any(e.get('from_record')!=e.get('from') or e.get('to_record')!=e.get('to') for e in es)
        missing_ref=any(e.get('from') not in nset or e.get('to') not in nset for e in es)
        valid=[e for e in es if e.get('from') in nset and e.get('to') in nset and e.get('from_record')==e.get('from') and e.get('to_record')==e.get('to')]
        adj={n:set() for n in ns}
        for e in valid: adj[e['from']].add(e['to'])
        path=None; reverse=None; reason=''; blocker=''
        if malformed:
            judgment='REJECT'; reason='edge endpoint record is inconsistent'; blocker='endpoint integrity failure'
        elif cycles(ns,adj):
            judgment='REJECT'; reason='causal cycle is a verifiable structural contradiction'; blocker='graph acyclicity violated'
        elif c.get('declarations',{}).get('invariant_graph_must_be_total_order'):
            bad=[]
            for i,u in enumerate(ns):
                for v in ns[i+1:]:
                    if not path_find(adj,u,v) and not path_find(adj,v,u): bad.append((u,v))
            if bad:
                judgment='REJECT'; reason='explicit total-order invariant is violated'; blocker='incomparable pair(s): '+','.join(u+'||'+v for u,v in bad)
            else: judgment=None
        else: judgment=None
        if judgment is None:
            if x not in nset or y not in nset or missing_ref:
                judgment='UNKNOWN'; reason='node or edge endpoint is missing from the recorded graph'; blocker='missing node/edge endpoint'
            elif x==y:
                judgment='UNKNOWN'; reason='strict happens-before is irreflexive'; blocker='same query node'
            else:
                path=path_find(adj,x,y); reverse=path_find(adj,y,x)
                if path:
                    direct=any(e['from']==x and e['to']==y for e in valid)
                    judgment='RECOVERED'; subclass='direct_edge' if direct else 'transitive_order'; reason=('direct edge establishes X ≺ Y' if direct else 'transitive closure establishes X ≺ Y'); blocker=''
                else:
                    judgment='UNKNOWN'; reason='no X-to-Y path; absence of reverse path is not evidence for an order'; blocker='incomparable/concurrent or missing causal edge'
        r={'case_id':c['case_id'],'nodes':ns,'edges':es,'query':{'x':x,'y':y},'judgment':judgment,'subclass':locals().get('subclass') if judgment=='RECOVERED' else None,'reason':reason,'blocking_condition':blocker,'inference_path':path if path else [],'reverse_path':reverse if reverse else [],'direct_edge_present':any(e.get('from')==x and e.get('to')==y for e in valid),'duplicate_edges_ignored':len(valid)-len(set((e['from'],e['to']) for e in valid)),'canonical_input_sha256':hashlib.sha256(canon({k:v for k,v in c.items() if k!='expected'})).hexdigest()}
        if r['judgment']=='RECOVERED': del subclass
        results.append(r)
    out={'schema_version':'S21-results-v1','synthetic_only':True,'production_verified':False,'fixture_count':len(results),'results':results}
    Path(a.output).parent.mkdir(parents=True,exist_ok=True); Path(a.output).write_text(json.dumps(out,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    counts={k:sum(r['judgment']==k for r in results) for k in ('RECOVERED','UNKNOWN','REJECT')}
    print(f"PASS: fixtures={len(results)} RECOVERED={counts['RECOVERED']} UNKNOWN={counts['UNKNOWN']} REJECT={counts['REJECT']}")
    print('PASS: results written',a.output)
if __name__=='__main__': main()
