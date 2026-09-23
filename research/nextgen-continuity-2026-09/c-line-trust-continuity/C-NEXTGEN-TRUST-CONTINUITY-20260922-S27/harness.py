#!/usr/bin/env python3
"""Synthetic-only trust-continuity evaluator; no network or production inputs."""
import hashlib, json, itertools
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = ROOT / 'fixtures' / 'cases.json'
OUT = ROOT / 'outputs' / 'results.json'
ALLOWED = {'RECOVERED', 'UNKNOWN', 'REJECT'}
EVIDENCE = {'platform_receipt', 'durable_log', 'external_effect'}


def _obs(case):
    return case.get('observations', [])


def evaluate(case):
    # All gates are fail-closed. No single observation can self-attest continuity.
    hard = case.get('hard_conflict', False)
    reasons = []
    q = case.get('quorum', {})
    threshold = int(q.get('threshold', 0))
    distinct = {o.get('observer_id') for o in _obs(case) if o.get('observer_id')}
    independent = len(distinct) == len(_obs(case)) and len(distinct) > 0
    quorum_ok = len(distinct) >= threshold and threshold > 0
    wm = case.get('watermark', {})
    samples = wm.get('samples', [])
    monotonic = True
    prev = None
    for s in samples:
        epoch, value = int(s.get('epoch', -1)), int(s.get('value', -1))
        if prev is not None:
            pe, pv = prev
            # A new epoch must not reduce the observed global floor.
            if value < pv or (epoch < pe):
                monotonic = False
        prev = (epoch, value)
    reached = bool(wm.get('revocation_reached', False))
    crash_closed = bool(case.get('crash_restart', {}).get('closed', False))
    evidence = case.get('evidence', [])
    kinds = {e.get('kind') for e in evidence if e.get('state') == 'confirmed'}
    evidence_complete = kinds == EVIDENCE and len(evidence) == 3
    evidence_consistent = evidence_complete and len({e.get('commit_digest') for e in evidence}) == 1
    # A crash-before/after repeated platform receipt is not independently closed.
    if 'duplicate_receipt' in case.get('crash_restart', {}).get('events', []):
        evidence_consistent = False
    retention = bool(case.get('retention', {}).get('within_boundary', False))
    query = bool(case.get('query', {}).get('complete', False))
    if hard:
        status = 'REJECT'
        reasons.append('explicit_hard_conflict')
    elif not quorum_ok:
        status = 'UNKNOWN'; reasons.append('quorum_missing_or_split')
    elif not independent:
        status = 'UNKNOWN'; reasons.append('observer_not_independent')
    elif not monotonic:
        status = 'UNKNOWN'; reasons.append('watermark_not_monotonic')
    elif not reached:
        status = 'UNKNOWN'; reasons.append('revocation_watermark_not_reached')
    elif not crash_closed:
        status = 'UNKNOWN'; reasons.append('crash_restart_unclosed')
    elif not evidence_complete:
        status = 'UNKNOWN'; reasons.append('evidence_class_missing')
    elif not evidence_consistent:
        status = 'UNKNOWN'; reasons.append('evidence_inconsistent')
    elif not retention:
        status = 'UNKNOWN'; reasons.append('retention_boundary_exceeded')
    elif not query:
        status = 'UNKNOWN'; reasons.append('query_gap')
    else:
        status = 'RECOVERED'; reasons.append('all_fail_closed_gates_satisfied')
    assert status in ALLOWED and len({status}) == 1
    return {'case_id': case['case_id'], 'status': status, 'reasons': reasons,
            'distinct_observers': sorted(distinct), 'quorum_observed': len(distinct),
            'quorum_threshold': threshold, 'checks': {
                'observer_independence': independent, 'quorum': quorum_ok,
                'watermark_monotonic': monotonic, 'revocation_reached': reached,
                'crash_restart_closed': crash_closed, 'evidence_complete': evidence_complete,
                'evidence_consistent': evidence_consistent, 'retention_within_boundary': retention,
                'query_complete': query}}


def base(case_id, **kw):
    obs = [{'observer_id':'o1','epoch':4,'watermark':12}, {'observer_id':'o2','epoch':4,'watermark':12}]
    ev = [{'kind':k,'state':'confirmed','commit_digest':'d-7'} for k in sorted(EVIDENCE)]
    x = {'case_id': case_id, 'classification': ['VERIFIED_CONTINUITY'],
         'quorum': {'threshold': 2, 'members': 3}, 'observations': obs,
         'watermark': {'samples':[{'epoch':4,'value':12}], 'revocation_reached':True},
         'crash_restart': {'events':['crash','restart','reconcile'], 'closed':True},
         'evidence':ev, 'retention':{'within_boundary':True,'age_days':2,'limit_days':7},
         'query':{'complete':True}, **kw}
    return x


def make_sweep():
    # 2^8 synthetic gate combinations; invariant: RECOVERED implies every gate.
    names = ['quorum','independence','monotonic','revocation','crash','evidence_complete','evidence_consistent','retention_query']
    violations=[]
    for bits in itertools.product((False, True), repeat=len(names)):
        d=dict(zip(names,bits)); c=base('sweep')
        if not d['quorum']: c['observations']=[{'observer_id':'o1'}]
        if not d['independence']: c['observations']=[{'observer_id':'o1'},{'observer_id':'o1'}]
        if not d['monotonic']: c['watermark']={'samples':[{'epoch':4,'value':12},{'epoch':5,'value':11}], 'revocation_reached':d['revocation']}
        else: c['watermark']['revocation_reached']=d['revocation']
        c['crash_restart']['closed']=d['crash']
        if not d['evidence_complete']: c['evidence']=c['evidence'][:2]
        if not d['evidence_consistent'] and c['evidence']: c['evidence'][-1]['commit_digest']='other'
        c['retention']['within_boundary']=d['retention_query']; c['query']['complete']=d['retention_query']
        r=evaluate(c)
        if r['status']=='RECOVERED' and not all(d.values()): violations.append(d)
    # Greedy minimizer: one flipped gate is the smallest non-recovery witness.
    minimal=[]
    for n in names:
        c=base('min');
        if n=='quorum': c['observations']=[{'observer_id':'o1'}]
        elif n=='independence': c['observations']=[{'observer_id':'o1'},{'observer_id':'o1'}]
        elif n=='monotonic': c['watermark']={'samples':[{'epoch':4,'value':12},{'epoch':5,'value':11}], 'revocation_reached':True}
        elif n=='revocation': c['watermark']['revocation_reached']=False
        elif n=='crash': c['crash_restart']['closed']=False
        elif n=='evidence_complete': c['evidence']=c['evidence'][:2]
        elif n=='evidence_consistent': c['evidence'][-1]['commit_digest']='other'
        else: c['retention']['within_boundary']=False; c['query']['complete']=False
        if evaluate(c)['status'] != 'RECOVERED': minimal.append(n)
    return {'combination_count':256, 'violations':len(violations), 'property_pass':not violations,
            'minimizer':{'single_gate_witnesses':minimal, 'minimal_witness_size':1}}


def main():
    cases=json.loads(CASES.read_text())
    results=[evaluate(c) for c in cases]
    sweep=make_sweep()
    payload={'schema_version':'s27-trust-continuity-results-1','synthetic_only':True,
             'production_verified':False,'case_count':len(results),'results':results,
             'property_sweep':sweep}
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'case_count':len(results),'status_counts':{s:sum(r['status']==s for r in results) for s in sorted(ALLOWED)},'property_sweep':sweep}, sort_keys=True))

if __name__=='__main__': main()
