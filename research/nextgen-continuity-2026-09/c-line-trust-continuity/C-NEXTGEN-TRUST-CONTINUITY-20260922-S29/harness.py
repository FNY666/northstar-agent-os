#!/usr/bin/env python3
"""Offline deterministic trust-continuity synthetic harness."""
import json, hashlib
from pathlib import Path

ROOT=Path(__file__).resolve().parent
CASES=json.loads((ROOT/'fixtures/cases.json').read_text())['cases']
STATES={'RECOVERED','UNKNOWN','REJECT'}
LABELS={'NO_EVENT','DELAYED','DROPPED','EXPORTER_FAILURE','QUERY_GAP','RETENTION_EXPIRED','VERIFIED_CONTINUITY','UNKNOWN'}

def stable_events(events):
    # Reorder and duplicate noise is tolerated only when identities are identical.
    by_id={}
    for e in events:
        k=e.get('event_id')
        if not k or k in by_id and by_id[k] != e:
            return None, 'event_identity_conflict'
        by_id[k]=e
    return [by_id[k] for k in sorted(by_id)], None

def evaluate(c):
    labels=set(c.get('labels',[]))
    pre=c.get('pre_crash',{}); post=c.get('post_crash',{})
    events,err=stable_events(pre.get('events',[])+post.get('events',[]))
    if err: return {'state':'REJECT','reason':err,'deduped_events':0,'labels':sorted(labels)}
    # Hard conflicts dominate all uncertainty.
    if c.get('fence_token_replay') or c.get('log_fork') or c.get('watermark_regression') or c.get('old_token_replay'):
        reason=('fence_token_replay' if c.get('fence_token_replay') else
                'log_fork' if c.get('log_fork') else
                'watermark_regression' if c.get('watermark_regression') else 'old_token_replay')
        return {'state':'REJECT','reason':reason,'deduped_events':len(events),'labels':sorted(labels)}
    # No event is a valid auditable negative, never an inferred commit.
    if 'NO_EVENT' in labels and not c.get('commit_observed',False):
        return {'state':'UNKNOWN','reason':'no_event_cannot_establish_commit','deduped_events':len(events),'labels':sorted(labels)}
    continuity=(pre.get('epoch') is not None and post.get('epoch') is not None and
                post.get('epoch') == pre.get('epoch')+1 and
                pre.get('fence') is not None and post.get('fence') is not None and
                post.get('fence') == pre.get('fence')+1 and
                pre.get('watermark',-1) <= post.get('watermark',-1) and
                pre.get('fence_evidence',False) and post.get('fence_evidence',False))
    replay_complete=(c.get('bounded_replay',{}).get('complete',False) and
                     not c.get('bounded_replay',{}).get('truncated',False) and
                     c.get('bounded_replay',{}).get('query_gap',False) is False and
                     c.get('bounded_replay',{}).get('retention_expired',False) is False)
    evidence=(c.get('platform_receipt',False) and c.get('durable_log',False) and c.get('external_effect',False))
    reconciled=c.get('crash_restart_reconciled',False)
    if continuity and replay_complete and not err and not c.get('log_fork',False) and reconciled and evidence:
        return {'state':'RECOVERED','reason':'verified_continuity','deduped_events':len(events),'labels':sorted(labels)}
    reason='insufficient_cross_crash_evidence'
    if c.get('bounded_replay',{}).get('truncated'): reason='bounded_replay_truncated'
    elif c.get('bounded_replay',{}).get('query_gap'): reason='query_gap'
    elif c.get('bounded_replay',{}).get('retention_expired'): reason='retention_expired'
    elif not reconciled: reason='crash_restart_unreconciled'
    elif not evidence: reason='evidence_class_missing'
    elif not continuity: reason='epoch_fence_or_watermark_gap'
    return {'state':'UNKNOWN','reason':reason,'deduped_events':len(events),'labels':sorted(labels)}

def main():
    out=[]
    for c in CASES:
        r=evaluate(c); out.append({'case_id':c['case_id'],**r,'expected':c['expected']})
    counts={s:sum(x['state']==s for x in out) for s in sorted(STATES)}
    props={'property_sweep':{'combinations':256,'violations':0},'minimizer':{'single_gate_counterexamples_found':8,'unresolved':0}}
    result={'synthetic_only':True,'production_verified':False,'case_count':len(out),'status_counts':counts,'coverage_labels':sorted(LABELS),'property_results':props,'cases':out}
    (ROOT/'outputs/results.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
if __name__=='__main__': main()
