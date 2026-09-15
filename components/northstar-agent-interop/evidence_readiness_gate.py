"""Evidence-precondition gates for agent plans, never action authorization."""
from __future__ import annotations
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from evidence_state_projection import ClaimProjection, ProjectionError

SCHEMA = "northstar.evidence-readiness-gate.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_REQ_FIELDS = frozenset({"claim_digest", "rationale"})
_GATE_FIELDS = frozenset({"schema_version", "plan_id", "requirements", "projections", "state", "blocked_claims", "unknown_claims", "reasons", "execution_authorized", "gate_digest"})

class GateError(ValueError): pass

@dataclass(frozen=True)
class EvidenceRequirement:
    claim_digest: str
    rationale: str
    def to_dict(self): return {"claim_digest":self.claim_digest,"rationale":self.rationale}
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_REQ_FIELDS: raise GateError("requirement fields invalid")
        _digest(v["claim_digest"],"claim_digest")
        if not isinstance(v["rationale"],str) or not v["rationale"] or len(v["rationale"])>256: raise GateError("requirement rationale invalid")
        return cls(v["claim_digest"],v["rationale"])

@dataclass(frozen=True)
class EvidenceReadinessGate:
    schema_version:str; plan_id:str; requirements:tuple[dict[str,Any],...]; projections:tuple[dict[str,Any],...]
    state:str; blocked_claims:tuple[str,...]; unknown_claims:tuple[str,...]; reasons:tuple[str,...]; execution_authorized:bool; gate_digest:str
    def unsigned_dict(self):
        return {"schema_version":self.schema_version,"plan_id":self.plan_id,"requirements":list(self.requirements),"projections":list(self.projections),"state":self.state,"blocked_claims":list(self.blocked_claims),"unknown_claims":list(self.unknown_claims),"reasons":list(self.reasons),"execution_authorized":self.execution_authorized}
    def to_dict(self): return {**self.unsigned_dict(),"gate_digest":self.gate_digest}
    @property
    def computed_digest(self): return _hash(b"northstar.evidence-readiness-gate.v1\0",self.unsigned_dict())
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_GATE_FIELDS or v["schema_version"]!=SCHEMA: raise GateError("gate fields invalid")
        _id(v["plan_id"],"plan_id")
        requirements=_requirements(v["requirements"])
        projections=_projections(v["projections"])
        state=v["state"]
        if state not in {"ready","blocked","unknown"}: raise GateError("gate state invalid")
        blocked=_digests(v["blocked_claims"],"blocked_claims"); unknown=_digests(v["unknown_claims"],"unknown_claims")
        reasons=_strings(v["reasons"],"reasons")
        if not isinstance(v["execution_authorized"],bool) or v["execution_authorized"]: raise GateError("gate cannot authorize execution")
        digest=_digest(v["gate_digest"],"gate_digest")
        result=cls(SCHEMA,v["plan_id"],requirements,projections,state,blocked,unknown,reasons,False,digest)
        if result.computed_digest!=digest: raise GateError("gate digest mismatch")
        return result

@dataclass(frozen=True)
class GateVerification:
    state:str; claimed_state:str; reasons:tuple[str,...]=(); unverified:tuple[str,...]=(); execution_authorized:bool=False; gate_digest:str=""

def _canonical(v):
    try:return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
    except (TypeError,ValueError) as e: raise GateError("value not canonical JSON") from e
def _hash(prefix,v): return "sha256:"+hashlib.sha256(prefix+_canonical(v)).hexdigest()
def _digest(v,field):
    if not isinstance(v,str) or _DIGEST.fullmatch(v) is None: raise GateError(f"{field} invalid")
    return v
def _id(v,field):
    if not isinstance(v,str) or _ID.fullmatch(v) is None: raise GateError(f"{field} invalid")
    return v
def _strings(v,field):
    if not isinstance(v,list) or len(set(v))!=len(v) or v!=sorted(v) or not all(isinstance(x,str) and x for x in v): raise GateError(f"{field} invalid")
    return tuple(v)
def _digests(v,field): return tuple(_digest(x,field) for x in _strings(v,field))
def _requirements(v):
    if not isinstance(v,list) or not v: raise GateError("requirements invalid")
    parsed=tuple(EvidenceRequirement.from_dict(x) for x in v)
    if len({x.claim_digest for x in parsed})!=len(parsed): raise GateError("duplicate requirements")
    if [x.claim_digest for x in parsed] != sorted(x.claim_digest for x in parsed): raise GateError("requirements not canonical")
    return tuple(x.to_dict() for x in parsed)
def _projections(v):
    if not isinstance(v,list): raise GateError("projections invalid")
    out=[]
    for raw in v:
        try:p=ClaimProjection.from_dict(raw)
        except ProjectionError as e: raise GateError("projection invalid") from e
        out.append(p)
    if [p.claim_digest for p in out] != sorted(p.claim_digest for p in out) or len({p.claim_digest for p in out})!=len(out): raise GateError("projections not canonical")
    return tuple(p.to_dict() for p in out)
def _parsed_requirements(requirements): return tuple(EvidenceRequirement.from_dict(x) for x in _requirements([x.to_dict() if isinstance(x,EvidenceRequirement) else x for x in requirements]))
def _parsed_projections(projections):
    if not isinstance(projections,Mapping): raise GateError("projections must be mapping")
    out={}
    for claim,value in projections.items():
        _digest(claim,"projection claim")
        try:p=ClaimProjection.from_dict(value.to_dict())
        except (AttributeError,ProjectionError) as e: raise GateError("projection invalid") from e
        if p.claim_digest!=claim: raise GateError("projection mapping mismatch")
        out[claim]=p
    return out

def evaluate_readiness(plan_id:str, requirements:Iterable[EvidenceRequirement], projections:Mapping[str,ClaimProjection])->EvidenceReadinessGate:
    _id(plan_id,"plan_id")
    reqs=_parsed_requirements(requirements); mapped=_parsed_projections(projections)
    blocked=[]; unknown=[]; reasons=[]; selected=[]
    for req in reqs:
        p=mapped.get(req.claim_digest)
        if p is None:
            unknown.append(req.claim_digest); reasons.append("missing_claim_projection"); continue
        selected.append(p)
        if p.state in {"conflicted","insufficient","unverifiable"}:
            blocked.append(req.claim_digest); reasons.append("blocked_claim:"+p.state)
        elif p.state=="unknown":
            unknown.append(req.claim_digest); reasons.append("unknown_claim")
    state="blocked" if blocked else ("unknown" if unknown else "ready")
    gate=EvidenceReadinessGate(SCHEMA,plan_id,tuple(r.to_dict() for r in reqs),tuple(p.to_dict() for p in sorted(selected,key=lambda x:x.claim_digest)),state,tuple(sorted(set(blocked))),tuple(sorted(set(unknown))),tuple(sorted(set(reasons))),False,"")
    return EvidenceReadinessGate(gate.schema_version,gate.plan_id,gate.requirements,gate.projections,gate.state,gate.blocked_claims,gate.unknown_claims,gate.reasons,False,gate.computed_digest)

def verify_readiness_gate(gate:EvidenceReadinessGate,*,plan_id:str,requirements:Iterable[EvidenceRequirement],projections:Mapping[str,ClaimProjection],expected_gate_digest:str|None=None)->GateVerification:
    try: parsed=EvidenceReadinessGate.from_dict(gate.to_dict())
    except (AttributeError,GateError) as e: raise GateError("gate invalid") from e
    if _id(plan_id,"plan_id")!=parsed.plan_id: raise GateError("plan id mismatch")
    replay=evaluate_readiness(plan_id,requirements,projections)
    for field in ("requirements","projections","state","blocked_claims","unknown_claims","reasons","execution_authorized"):
        if getattr(parsed,field)!=getattr(replay,field): raise GateError("gate replay mismatch: "+field)
    if expected_gate_digest is not None and _digest(expected_gate_digest,"expected_gate_digest")!=parsed.gate_digest: raise GateError("external gate digest mismatch")
    unresolved=[]
    for p in replay.projections:
        unresolved.extend(ClaimProjection.from_dict(p).unverified)
    if expected_gate_digest is None: unresolved.append("gate_digest_unpinned")
    return GateVerification("gate-verified" if expected_gate_digest is not None else "gate-verified-unpinned",replay.state,(),tuple(sorted(set(unresolved))),False,parsed.gate_digest)

__all__=["SCHEMA","GateError","EvidenceRequirement","EvidenceReadinessGate","GateVerification","evaluate_readiness","verify_readiness_gate"]
