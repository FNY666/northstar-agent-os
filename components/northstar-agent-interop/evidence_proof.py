"""Composition verifier for Route Evidence proof layers."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from evidence_bundle import EvidenceError, verify_lineage_bundle, verify_proof
from evidence_chain import ChainError, verify_chain
from cross_layer_verifier import verify_cross_layer
from route_lineage import verify_lineage
class ProofError(ValueError): pass
@dataclass(frozen=True)
class ProofResult:
    verdict:str
    reasons:tuple[str,...]
def verify_route_evidence_proof(route_record:Any,lineage:Any,bundle:Any,checkpoint_chain:Any,event:Any,proof:Any,handoff:Any,*extra)->ProofResult:
    if any(x is None for x in (route_record,lineage,bundle,checkpoint_chain,event,proof,handoff)): return ProofResult('unknown',('missing evidence layer',))
    try:
        verify_chain(checkpoint_chain)
        verify_lineage_bundle(bundle,list(lineage.read()))
        verify_proof(bundle,event.to_dict() if hasattr(event,'to_dict') else event,proof)
    except (EvidenceError,ChainError,ValueError) as exc:
        return ProofResult('unknown',(str(exc),))
    lineage_result=verify_lineage(lineage,route_record=route_record,handoff=handoff)
    if lineage_result.verdict=='failed': return ProofResult('failed',lineage_result.reasons)
    if lineage_result.verdict!='verified': return ProofResult(lineage_result.verdict,lineage_result.reasons)
    return ProofResult('verified',())
