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
        checkpoints=list(checkpoint_chain.read())
        if not checkpoints or checkpoints[-1].current_root != bundle.root_digest:
            raise ProofError('checkpoint root does not match evidence bundle')
    except (EvidenceError,ChainError,ValueError) as exc:
        return ProofResult('unknown',(str(exc),))
    terminal = list(lineage.read())[-1]
    cross = verify_cross_layer(
        {
            'route_id': route_record.get('route_id'),
            'target_agent_id': route_record.get('selected_agent_id', route_record.get('target_agent_id')),
            'provider': route_record.get('selected_provider', route_record.get('provider')),
            'deadline_at': route_record.get('deadline_at'),
            'decision_fingerprint': route_record.get('decision_fingerprint'),
            'payload_digest': route_record.get('payload_digest'),
            'status': 'succeeded',
        },
        {
            'route_id': terminal.route_id,
            'target_agent_id': terminal.target_agent_id,
            'provider': terminal.provider,
            'deadline_at': terminal.deadline_at,
            'decision_fingerprint': terminal.decision_fingerprint,
            'payload_digest': terminal.payload_digest,
            'status': terminal.status,
        },
        {
            'route_id': getattr(bundle, 'route_id', terminal.route_id),
            'target_agent_id': terminal.target_agent_id,
            'provider': terminal.provider,
            'deadline_at': terminal.deadline_at,
            'decision_fingerprint': terminal.decision_fingerprint,
            'payload_digest': terminal.payload_digest,
            'status': terminal.status,
        },
        {
            'route_id': handoff.get('route_id'),
            'target_agent_id': handoff.get('target_agent_id'),
            'provider': handoff.get('provider'),
            'deadline_at': handoff.get('deadline_at'),
            'decision_fingerprint': handoff.get('decision_fingerprint'),
            'payload_digest': handoff.get('payload_digest'),
            'status': 'succeeded',
        },
    )
    if cross.verdict == 'failed': return ProofResult('failed', cross.reasons)
    if cross.verdict != 'verified': return ProofResult('unknown', cross.reasons)
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
