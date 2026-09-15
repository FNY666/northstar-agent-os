"""Final, non-authorizing composition of readiness decision and lease state."""
from __future__ import annotations
import hashlib,json,re
from dataclasses import dataclass
from typing import Any,Mapping
from evidence_readiness_lease import EvidenceReadinessLease,LeaseError,verify_readiness_lease
from evidence_readiness_lease_registry import EvidenceReadinessLeaseRegistry,LeaseRegistryError
from evidence_readiness_gate import EvidenceReadinessGate
from plan_evidence_decision import EvidencePlanManifest,PlanDecisionError,PlanEvidenceDecision
from evidence_state_projection import ClaimProjection,ProjectionError
from readiness_lease_witness import LeaseRegistryWitness,RegistryWitnessError,verify_registry_witness

SCHEMA='northstar.evidence-readiness-preflight.v1'
_DIGEST=re.compile(r'^sha256:[0-9a-f]{64}$')
_FIELDS=frozenset({'schema_version','lease_digest','registry_witness_digest','decision_digest','manifest_digest','gate_digest','state','lease_state','registry_state','decision_state','unverified','reasons','execution_authorized','preflight_digest'})
class PreflightError(ValueError): pass
@dataclass(frozen=True)
class EvidenceReadinessPreflight:
    schema_version:str; lease_digest:str; registry_witness_digest:str; decision_digest:str; manifest_digest:str; gate_digest:str; state:str; lease_state:str; registry_state:str; decision_state:str; unverified:tuple[str,...]; reasons:tuple[str,...]; execution_authorized:bool; preflight_digest:str
    def unsigned_dict(self): return {'schema_version':self.schema_version,'lease_digest':self.lease_digest,'registry_witness_digest':self.registry_witness_digest,'decision_digest':self.decision_digest,'manifest_digest':self.manifest_digest,'gate_digest':self.gate_digest,'state':self.state,'lease_state':self.lease_state,'registry_state':self.registry_state,'decision_state':self.decision_state,'unverified':list(self.unverified),'reasons':list(self.reasons),'execution_authorized':self.execution_authorized}
    def to_dict(self): return {**self.unsigned_dict(),'preflight_digest':self.preflight_digest}
    @property
    def computed_digest(self): return _hash(b'northstar.evidence-readiness-preflight.v1\0',self.unsigned_dict())
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_FIELDS or v['schema_version']!=SCHEMA: raise PreflightError('preflight fields invalid')
        for field in ('lease_digest','registry_witness_digest','decision_digest','manifest_digest','gate_digest','preflight_digest'): _digest(v[field],field)
        if v['state'] not in {'preflight-ready','preflight-unpinned','preflight-expired','preflight-revoked','preflight-stale','preflight-unknown','preflight-unverifiable'}: raise PreflightError('preflight state invalid')
        if not isinstance(v['execution_authorized'],bool) or v['execution_authorized']: raise PreflightError('preflight cannot authorize')
        result=cls(SCHEMA,v['lease_digest'],v['registry_witness_digest'],v['decision_digest'],v['manifest_digest'],v['gate_digest'],v['state'],v['lease_state'],v['registry_state'],v['decision_state'],tuple(v['unverified']),tuple(v['reasons']),False,v['preflight_digest'])
        if result.computed_digest!=result.preflight_digest: raise PreflightError('preflight digest mismatch')
        return result
@dataclass(frozen=True)
class PreflightVerdict:
    state:str; reasons:tuple[str,...]=(); unverified:tuple[str,...]=(); execution_authorized:bool=False; preflight_digest:str=''
def _canonical(v):
    try:return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    except (TypeError,ValueError) as e: raise PreflightError('preflight not canonical JSON') from e
def _hash(prefix,v): return 'sha256:'+hashlib.sha256(prefix+_canonical(v)).hexdigest()
def _digest(v,field):
    if not isinstance(v,str) or _DIGEST.fullmatch(v) is None: raise PreflightError(f'{field} invalid')
    return v
def _lease(v):
    if not isinstance(v,EvidenceReadinessLease): raise PreflightError('lease invalid')
    return v
def _witness(v):
    if not isinstance(v,LeaseRegistryWitness): raise PreflightError('registry witness invalid')
    return v
def _decision(v):
    if not isinstance(v,PlanEvidenceDecision): raise PreflightError('decision invalid')
    return v
def _manifest(v):
    if not isinstance(v,EvidencePlanManifest): raise PreflightError('manifest invalid')
    return v
def evaluate_preflight(*,lease,registry_witness,registry,decision,manifest,projections,now,expected_lease_digest,expected_registry_witness_digest,expected_decision_digest,expected_manifest_digest,expected_gate_digest)->EvidenceReadinessPreflight:
    lease=_lease(lease); witness=_witness(registry_witness); decision=_decision(decision); manifest=_manifest(manifest)
    if not isinstance(registry,EvidenceReadinessLeaseRegistry): raise PreflightError('registry invalid')
    try:
        lease_verdict=verify_readiness_lease(lease,decision,manifest,projections,now=now,expected_lease_digest=expected_lease_digest,expected_decision_digest=expected_decision_digest,expected_manifest_digest=expected_manifest_digest,expected_gate_digest=expected_gate_digest)
        registry_verdict=verify_registry_witness(witness,registry,now=now,expected_witness_digest=expected_registry_witness_digest)
    except (LeaseError,RegistryWitnessError) as e: raise PreflightError('preflight source verification failed') from e
    unresolved=list(lease_verdict.unverified)
    unresolved.extend(
        'registry_witness_digest_unpinned' if item == 'witness_digest_unpinned' else item
        for item in registry_verdict.unverified
    )
    reasons=list(lease_verdict.reasons)+list(registry_verdict.reasons)
    lease_current=lease_verdict.state in ('lease-valid','lease-valid-unpinned')
    unpinned=(lease_verdict.state=='lease-valid-unpinned'
        or registry_verdict.state=='current-unpinned'
        or expected_lease_digest is None
        or expected_registry_witness_digest is None
        or expected_decision_digest is None
        or expected_manifest_digest is None
        or expected_gate_digest is None)
    state='preflight-ready'
    if registry_verdict.state=='revoked': state='preflight-revoked'
    elif registry_verdict.state=='stale': state='preflight-stale'
    elif registry_verdict.state=='unverifiable': state='preflight-unverifiable'
    elif lease_verdict.state=='lease-expired' or registry_verdict.state=='expired': state='preflight-expired'
    elif registry_verdict.state=='unknown' or not lease_current: state='preflight-unknown'
    if unpinned:
        unresolved.append('preflight_pin_unpinned')
        if state=='preflight-ready': state='preflight-unpinned'
    draft=EvidenceReadinessPreflight(SCHEMA,lease.lease_digest,witness.witness_digest,decision.decision_digest,manifest.manifest_digest,decision.gate['gate_digest'],state,lease_verdict.state,registry_verdict.state,lease_verdict.claimed_decision_state,tuple(sorted(set(unresolved))),tuple(sorted(set(reasons))),False,'')
    return EvidenceReadinessPreflight(draft.schema_version,draft.lease_digest,draft.registry_witness_digest,draft.decision_digest,draft.manifest_digest,draft.gate_digest,draft.state,draft.lease_state,draft.registry_state,draft.decision_state,draft.unverified,draft.reasons,False,draft.computed_digest)
__all__=['SCHEMA','PreflightError','EvidenceReadinessPreflight','PreflightVerdict','evaluate_preflight']
