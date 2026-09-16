"""Cross-layer consistency verifier for route evidence, lineage, bundle and handoff."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
class CrossLayerError(ValueError): pass
@dataclass(frozen=True)
class CrossLayerResult:
    verdict:str; reasons:tuple[str,...]
_KEYS=('route_id','target_agent_id','provider','decision_fingerprint','payload_digest')
def verify_cross_layer(route:Any,lineage:Any,bundle:Any,handoff:Any)->CrossLayerResult:
    """Compare one identity across the evidence layers.

    An identity that no layer records is not agreement: absence is reported as
    missing, mirroring the deadline check, so a proof cannot pass by omitting the
    field everywhere.
    """
    layers=(route,lineage,bundle,handoff)
    if any(not isinstance(x,dict) for x in layers): return CrossLayerResult('unknown',('missing evidence layer',))
    reasons=[]
    for key in _KEYS:
        values=[x.get(key) for x in layers]
        if any(value is None or value == '' for value in values):
            reasons.append(f'{key} missing')
            continue
        if len(set(values))!=1: reasons.append(f'{key} mismatch')
    deadlines=[x.get('deadline_at') for x in layers]
    if not all(isinstance(x,int) for x in deadlines): reasons.append('deadline missing')
    elif max(deadlines)!=route.get('deadline_at'): reasons.append('deadline widened or route anchor changed')
    statuses={x.get('status') for x in layers}
    if any(s in {'failed','unknown'} for s in statuses): return CrossLayerResult('failed',tuple(reasons)+('a layer is failed or unknown',))
    return CrossLayerResult('unknown' if reasons else 'verified',tuple(reasons))
