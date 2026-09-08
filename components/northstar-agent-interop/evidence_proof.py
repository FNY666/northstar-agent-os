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


@dataclass(frozen=True)
class ProofAttestation:
    schema_version: str
    verdict: str
    route_id: str
    proof_digest: str
    lineage_digest: str
    bundle_root: str
    checkpoint_root: str
    def to_dict(self): return self.__dict__.copy()

def _proof_digest(route_record, lineage, bundle, event, proof, handoff):
    import hashlib, json
    payload={'route':route_record,'lineage':[x.to_dict() for x in lineage.read()], 'bundle':bundle.to_dict(), 'event':event.to_dict() if hasattr(event,'to_dict') else event, 'proof':proof.__dict__, 'handoff':handoff}
    return 'sha256:'+hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':'),default=list).encode()).hexdigest()

def make_proof_attestation(route_record,lineage,bundle,checkpoint_chain,event,proof,handoff,*extra):
    result=verify_route_evidence_proof(route_record,lineage,bundle,checkpoint_chain,event,proof,handoff,*extra)
    if result.verdict!='verified': raise ProofError('cannot attest unverified evidence')
    import hashlib
    lineage_digest='sha256:'+hashlib.sha256(b''.join(x.canonical() for x in lineage.read())).hexdigest()
    checkpoint_root=list(checkpoint_chain.read())[-1].current_root
    return ProofAttestation('northstar.proof-attestation.v1','verified',route_record['route_id'],_proof_digest(route_record,lineage,bundle,event,proof,handoff),lineage_digest,bundle.root_digest,checkpoint_root)
