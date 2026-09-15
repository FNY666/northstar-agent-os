"""Replayable plan evidence decisions that never authorize execution."""
from __future__ import annotations
import hashlib,json,re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from evidence_readiness_gate import EvidenceRequirement,EvidenceReadinessGate,GateError,evaluate_readiness,verify_readiness_gate
from evidence_state_projection import ClaimProjection,ProjectionError

MANIFEST_SCHEMA='northstar.evidence-plan-manifest.v1'
SCHEMA='northstar.plan-evidence-decision.v1'
_DIGEST=re.compile(r'^sha256:[0-9a-f]{64}$')
_ID=re.compile(r'^[A-Za-z0-9._:-]{1,128}$')
_STEP_FIELDS=frozenset({'step_id','claim_digest','rationale'})
_MANIFEST_FIELDS=frozenset({'schema_version','steps','manifest_digest'})
_DECISION_FIELDS=frozenset({'schema_version','manifest','manifest_digest','gate','state','blocked_claims','unknown_claims','execution_authorized','decision_digest'})

class PlanDecisionError(ValueError): pass

@dataclass(frozen=True)
class EvidencePlanStep:
    step_id:str; claim_digest:str; rationale:str
    def to_dict(self): return {'step_id':self.step_id,'claim_digest':self.claim_digest,'rationale':self.rationale}
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_STEP_FIELDS: raise PlanDecisionError('plan step fields invalid')
        _id(v['step_id'],'step_id');_digest(v['claim_digest'],'claim_digest')
        if not isinstance(v['rationale'],str) or not v['rationale'] or len(v['rationale'])>256: raise PlanDecisionError('step rationale invalid')
        return cls(v['step_id'],v['claim_digest'],v['rationale'])

@dataclass(frozen=True)
class EvidencePlanManifest:
    schema_version:str; steps:tuple[EvidencePlanStep,...]
    def __post_init__(self):
        if self.schema_version != MANIFEST_SCHEMA:
            raise PlanDecisionError('manifest schema invalid')
        if not isinstance(self.steps, tuple) or not self.steps:
            raise PlanDecisionError('manifest steps invalid')
        parsed = tuple(EvidencePlanStep.from_dict(step.to_dict()) for step in self.steps)
        if len({step.step_id for step in parsed}) != len(parsed):
            raise PlanDecisionError('manifest step ids duplicate')
        if len({step.claim_digest for step in parsed}) != len(parsed):
            raise PlanDecisionError('manifest claims duplicate')
        object.__setattr__(self, 'steps', tuple(sorted(parsed, key=lambda step: step.step_id)))
    @property
    def manifest_digest(self): return _hash(b'northstar.evidence-plan-manifest.v1\0',self.unsigned_dict())
    def unsigned_dict(self): return {'schema_version':self.schema_version,'steps':[x.to_dict() for x in self.steps]}
    def to_dict(self): return {**self.unsigned_dict(),'manifest_digest':self.manifest_digest}
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_MANIFEST_FIELDS or v['schema_version']!=MANIFEST_SCHEMA: raise PlanDecisionError('manifest fields invalid')
        if not isinstance(v['steps'],list) or not v['steps']: raise PlanDecisionError('manifest steps invalid')
        steps=tuple(EvidencePlanStep.from_dict(x) for x in v['steps'])
        if [x.step_id for x in steps]!=sorted(x.step_id for x in steps) or len({x.step_id for x in steps})!=len(steps): raise PlanDecisionError('manifest steps not canonical')
        if len({x.claim_digest for x in steps})!=len(steps): raise PlanDecisionError('manifest claims duplicate')
        result=cls(MANIFEST_SCHEMA,steps)
        if _digest(v['manifest_digest'],'manifest_digest')!=result.manifest_digest: raise PlanDecisionError('manifest digest mismatch')
        return result

@dataclass(frozen=True)
class PlanEvidenceDecision:
    schema_version:str; manifest:dict[str,Any]; manifest_digest:str; gate:dict[str,Any]; state:str; blocked_claims:tuple[str,...]; unknown_claims:tuple[str,...]; execution_authorized:bool; decision_digest:str
    def unsigned_dict(self): return {'schema_version':self.schema_version,'manifest':self.manifest,'manifest_digest':self.manifest_digest,'gate':self.gate,'state':self.state,'blocked_claims':list(self.blocked_claims),'unknown_claims':list(self.unknown_claims),'execution_authorized':self.execution_authorized}
    def to_dict(self): return {**self.unsigned_dict(),'decision_digest':self.decision_digest}
    @property
    def computed_digest(self): return _hash(b'northstar.plan-evidence-decision.v1\0',self.unsigned_dict())
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_DECISION_FIELDS or v['schema_version']!=SCHEMA: raise PlanDecisionError('decision fields invalid')
        manifest=EvidencePlanManifest.from_dict(v['manifest'])
        if _digest(v['manifest_digest'],'manifest_digest')!=manifest.manifest_digest: raise PlanDecisionError('decision manifest digest mismatch')
        try: gate=EvidenceReadinessGate.from_dict(v['gate'])
        except GateError as e: raise PlanDecisionError('decision gate invalid') from e
        if v['state'] not in {'ready','blocked','unknown'} or v['state']!=gate.state: raise PlanDecisionError('decision state mismatch')
        blocked=_digests(v['blocked_claims'],'blocked_claims');unknown=_digests(v['unknown_claims'],'unknown_claims')
        if blocked!=gate.blocked_claims or unknown!=gate.unknown_claims: raise PlanDecisionError('decision claim status mismatch')
        if not isinstance(v['execution_authorized'],bool) or v['execution_authorized']: raise PlanDecisionError('decision cannot authorize execution')
        digest=_digest(v['decision_digest'],'decision_digest')
        result=cls(SCHEMA,manifest.to_dict(),manifest.manifest_digest,gate.to_dict(),v['state'],blocked,unknown,False,digest)
        if result.computed_digest!=digest: raise PlanDecisionError('decision digest mismatch')
        return result

@dataclass(frozen=True)
class PlanDecisionVerdict:
    state:str; claimed_state:str; reasons:tuple[str,...]=(); unverified:tuple[str,...]=(); execution_authorized:bool=False; decision_digest:str=''

def _canonical(v):
    try:return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    except (TypeError,ValueError) as e: raise PlanDecisionError('value not canonical JSON') from e
def _hash(prefix,v): return 'sha256:'+hashlib.sha256(prefix+_canonical(v)).hexdigest()
def _digest(v,field):
    if not isinstance(v,str) or _DIGEST.fullmatch(v) is None: raise PlanDecisionError(f'{field} invalid')
    return v
def _id(v,field):
    if not isinstance(v,str) or _ID.fullmatch(v) is None: raise PlanDecisionError(f'{field} invalid')
    return v
def _digests(v,field):
    if not isinstance(v,list) or len(set(v))!=len(v) or v!=sorted(v): raise PlanDecisionError(f'{field} invalid')
    return tuple(_digest(x,field) for x in v)
def _manifest(manifest):
    try:return EvidencePlanManifest.from_dict(manifest.to_dict())
    except (AttributeError,PlanDecisionError) as e: raise PlanDecisionError('manifest invalid') from e
def _projections(projections):
    if not isinstance(projections,Mapping): raise PlanDecisionError('projections invalid')
    out={}
    for claim,item in projections.items():
        _digest(claim,'projection claim')
        try:p=ClaimProjection.from_dict(item.to_dict())
        except (AttributeError,ProjectionError) as e: raise PlanDecisionError('projection invalid') from e
        if p.claim_digest!=claim: raise PlanDecisionError('projection mapping mismatch')
        out[claim]=p
    return out
def _requirements(manifest): return [EvidenceRequirement(step.claim_digest,step.rationale) for step in manifest.steps]

def make_plan_evidence_decision(manifest:EvidencePlanManifest,projections:Mapping[str,ClaimProjection])->PlanEvidenceDecision:
    m=_manifest(manifest);p=_projections(projections)
    gate=evaluate_readiness('plan-evidence:'+m.manifest_digest[7:23],_requirements(m),p)
    unsigned=PlanEvidenceDecision(SCHEMA,m.to_dict(),m.manifest_digest,gate.to_dict(),gate.state,gate.blocked_claims,gate.unknown_claims,False,'')
    return PlanEvidenceDecision(unsigned.schema_version,unsigned.manifest,unsigned.manifest_digest,unsigned.gate,unsigned.state,unsigned.blocked_claims,unsigned.unknown_claims,False,unsigned.computed_digest)

def verify_plan_evidence_decision(decision:PlanEvidenceDecision,*,manifest:EvidencePlanManifest,projections:Mapping[str,ClaimProjection],expected_decision_digest:str|None=None,expected_manifest_digest:str|None=None,expected_gate_digest:str|None=None)->PlanDecisionVerdict:
    if not isinstance(decision,PlanEvidenceDecision): raise PlanDecisionError('decision invalid')
    parsed=PlanEvidenceDecision.from_dict(decision.to_dict());m=_manifest(manifest);p=_projections(projections)
    if parsed.manifest_digest!=m.manifest_digest or parsed.manifest!=m.to_dict(): raise PlanDecisionError('manifest mismatch')
    if expected_decision_digest is not None and _digest(expected_decision_digest,'expected_decision_digest')!=parsed.decision_digest: raise PlanDecisionError('external decision digest mismatch')
    if expected_manifest_digest is not None and _digest(expected_manifest_digest,'expected_manifest_digest')!=parsed.manifest_digest: raise PlanDecisionError('external manifest digest mismatch')
    replay=make_plan_evidence_decision(m,p)
    if replay.to_dict()!=parsed.to_dict(): raise PlanDecisionError('decision replay mismatch')
    try: gate_verdict=verify_readiness_gate(EvidenceReadinessGate.from_dict(parsed.gate),plan_id='plan-evidence:'+m.manifest_digest[7:23],requirements=_requirements(m),projections=p,expected_gate_digest=expected_gate_digest)
    except GateError as e: raise PlanDecisionError('gate verification failed') from e
    unresolved=list(gate_verdict.unverified)
    if expected_decision_digest is None: unresolved.append('decision_digest_unpinned')
    if expected_manifest_digest is None: unresolved.append('manifest_digest_unpinned')
    if expected_gate_digest is None: unresolved.append('gate_digest_unpinned')
    return PlanDecisionVerdict('decision-verified' if expected_decision_digest is not None and expected_manifest_digest is not None and expected_gate_digest is not None else 'decision-verified-unpinned',replay.state,(),tuple(sorted(set(unresolved))),False,parsed.decision_digest)

__all__=['MANIFEST_SCHEMA','SCHEMA','PlanDecisionError','EvidencePlanStep','EvidencePlanManifest','PlanEvidenceDecision','PlanDecisionVerdict','make_plan_evidence_decision','verify_plan_evidence_decision']
