"""Replayable witness for a dispatch-admission snapshot."""
from __future__ import annotations
import hashlib,json,re
from dataclasses import dataclass
from typing import Any
from dispatch_admission import DispatchAdmission,DispatchAdmissionError
from evidence_readiness_preflight import EvidenceReadinessPreflight,PreflightError
from route_liveness import RouteLivenessVerdict

SCHEMA='northstar.dispatch-admission-witness.v1'
_DIGEST=re.compile(r'^sha256:[0-9a-f]{64}$')
_FIELDS=frozenset({'schema_version','admission_digest','preflight_digest','liveness_digest','plan_id','route_id','observed_at','witness_digest','execution_authorized'})
class AdmissionWitnessError(ValueError): pass

def _canonical(v):
    try:return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    except (TypeError,ValueError) as e: raise AdmissionWitnessError('witness is not canonical JSON') from e
def _hash(prefix,v): return 'sha256:'+hashlib.sha256(prefix+_canonical(v)).hexdigest()
def _digest(v,f):
    if not isinstance(v,str) or _DIGEST.fullmatch(v) is None: raise AdmissionWitnessError(f'{f} invalid')
    return v
def _label(v,f):
    if not isinstance(v,str) or not v or len(v)>128 or any(ord(c)<32 or ord(c)==127 for c in v): raise AdmissionWitnessError(f'{f} invalid')
    return v

def _source_digest(v):
    if isinstance(v,DispatchAdmission): return v.admission_digest
    if isinstance(v,EvidenceReadinessPreflight): return v.preflight_digest
    if isinstance(v,RouteLivenessVerdict):
        if v.execution_authorized is not False:
            raise AdmissionWitnessError('liveness cannot authorize execution')
        _label(v.route_id, 'liveness route_id')
        return v.computed_digest
    raise AdmissionWitnessError('source invalid')

@dataclass(frozen=True)
class DispatchAdmissionWitness:
    schema_version:str; admission_digest:str; preflight_digest:str; liveness_digest:str; plan_id:str; route_id:str; observed_at:int; witness_digest:str; execution_authorized:bool=False
    def unsigned_dict(self): return {'schema_version':self.schema_version,'admission_digest':self.admission_digest,'preflight_digest':self.preflight_digest,'liveness_digest':self.liveness_digest,'plan_id':self.plan_id,'route_id':self.route_id,'observed_at':self.observed_at,'execution_authorized':self.execution_authorized}
    def to_dict(self): return {**self.unsigned_dict(),'witness_digest':self.witness_digest}
    @property
    def computed_digest(self): return _hash(b'northstar.dispatch-admission-witness.v1\0',self.unsigned_dict())
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_FIELDS or v.get('schema_version')!=SCHEMA: raise AdmissionWitnessError('witness fields invalid')
        if v.get('execution_authorized') is not False: raise AdmissionWitnessError('witness cannot authorize')
        result=cls(SCHEMA,_digest(v['admission_digest'],'admission_digest'),_digest(v['preflight_digest'],'preflight_digest'),_digest(v['liveness_digest'],'liveness_digest'),_label(v['plan_id'],'plan_id'),_label(v['route_id'],'route_id'),v['observed_at'],_digest(v['witness_digest'],'witness_digest'),False)
        if not isinstance(v['observed_at'],int) or isinstance(v['observed_at'],bool): raise AdmissionWitnessError('observed_at invalid')
        if result.computed_digest!=result.witness_digest: raise AdmissionWitnessError('witness digest mismatch')
        return result

@dataclass(frozen=True)
class AdmissionWitnessVerdict:
    state:str; reasons:tuple[str,...]=(); unverified:tuple[str,...]=(); execution_authorized:bool=False

def make_admission_witness(admission,preflight,liveness,*,observed_at):
    if not isinstance(admission,DispatchAdmission) or not isinstance(preflight,EvidenceReadinessPreflight) or not isinstance(liveness,RouteLivenessVerdict): raise AdmissionWitnessError('source invalid')
    try:
        admission=DispatchAdmission.from_dict(admission.to_dict()); preflight=EvidenceReadinessPreflight.from_dict(preflight.to_dict())
    except (DispatchAdmissionError,PreflightError) as e: raise AdmissionWitnessError('source invalid') from e
    if not isinstance(observed_at,int) or isinstance(observed_at,bool): raise AdmissionWitnessError('observed_at invalid')
    if liveness.route_id != admission.route_id: raise AdmissionWitnessError('liveness route does not match admission')
    if preflight.preflight_digest != admission.preflight_digest: raise AdmissionWitnessError('preflight is not the one the admission was built from')
    if liveness.computed_digest != admission.liveness_digest: raise AdmissionWitnessError('liveness is not the one the admission was built from')
    if admission.evidence_state!=preflight.state or admission.route_state!=liveness.state: raise AdmissionWitnessError('admission/source state mismatch')
    draft=DispatchAdmissionWitness(SCHEMA,admission.admission_digest,preflight.preflight_digest,_source_digest(liveness),admission.plan_id,admission.route_id,observed_at,'')
    return DispatchAdmissionWitness(draft.schema_version,draft.admission_digest,draft.preflight_digest,draft.liveness_digest,draft.plan_id,draft.route_id,draft.observed_at,draft.computed_digest,False)

def verify_admission_witness(witness,admission,preflight,liveness,*,now,expected_witness_digest=None):
    if not isinstance(witness,DispatchAdmissionWitness): raise AdmissionWitnessError('witness invalid')
    witness=DispatchAdmissionWitness.from_dict(witness.to_dict())
    if not isinstance(now,int) or isinstance(now,bool): raise AdmissionWitnessError('now invalid')
    if expected_witness_digest is not None and _digest(expected_witness_digest,'expected_witness_digest')!=witness.witness_digest: raise AdmissionWitnessError('external witness digest mismatch')
    try:
        admission=DispatchAdmission.from_dict(admission.to_dict()); preflight=EvidenceReadinessPreflight.from_dict(preflight.to_dict())
    except (DispatchAdmissionError,PreflightError) as e: raise AdmissionWitnessError('source invalid') from e
    if admission.admission_digest!=witness.admission_digest or preflight.preflight_digest!=witness.preflight_digest or _source_digest(liveness)!=witness.liveness_digest:
        reasons=[]
        if admission.admission_digest!=witness.admission_digest: reasons.append('admission_changed')
        if preflight.preflight_digest!=witness.preflight_digest: reasons.append('preflight_changed')
        if _source_digest(liveness)!=witness.liveness_digest: reasons.append('liveness_changed')
        return AdmissionWitnessVerdict('stale',tuple(reasons),(),False)
    if admission.state=='unknown' or liveness.state=='unknown': return AdmissionWitnessVerdict('unknown',('source_unknown',),(),False)
    return AdmissionWitnessVerdict('current' if expected_witness_digest is not None else 'current-unpinned',(),() if expected_witness_digest is not None else ('witness_digest_unpinned',),False)

__all__=['SCHEMA','AdmissionWitnessError','DispatchAdmissionWitness','AdmissionWitnessVerdict','make_admission_witness','verify_admission_witness']
