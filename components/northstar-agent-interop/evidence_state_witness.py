"""Replayable bindings from evidence provenance to one claim projection."""
from __future__ import annotations
import hashlib,json,re
from dataclasses import dataclass
from typing import Any, Iterable
from admission_witness import AdmissionWitness,WitnessError
from evidence_conflict_ledger import ConflictObservation,ConflictLedgerError
from evidence_state_projection import ClaimProjection,ProjectionError,project_claim

SCHEMA='northstar.evidence-state-witness.v1'
_DIGEST=re.compile(r'^sha256:[0-9a-f]{64}$')
_FIELDS=frozenset({'schema_version','claim_digest','admission_witnesses','conflicts','projection','claimed_state','witness_digests','conflict_ids','state_digest'})

class StateWitnessError(ValueError): pass

@dataclass(frozen=True)
class EvidenceStateWitness:
    schema_version:str; claim_digest:str; admission_witnesses:tuple[dict[str,Any],...]; conflicts:tuple[dict[str,Any],...]; projection:dict[str,Any]; claimed_state:str; witness_digests:tuple[str,...]; conflict_ids:tuple[str,...]; state_digest:str
    def unsigned_dict(self):
        return {'schema_version':self.schema_version,'claim_digest':self.claim_digest,'admission_witnesses':list(self.admission_witnesses),'conflicts':list(self.conflicts),'projection':self.projection,'claimed_state':self.claimed_state,'witness_digests':list(self.witness_digests),'conflict_ids':list(self.conflict_ids)}
    def to_dict(self): return {**self.unsigned_dict(),'state_digest':self.state_digest}
    @property
    def computed_digest(self): return _hash(b'northstar.evidence-state-witness.v1\0',self.unsigned_dict())
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_FIELDS or v['schema_version']!=SCHEMA: raise StateWitnessError('state witness fields invalid')
        claim=_digest(v['claim_digest'],'claim_digest')
        witnesses=_witnesses(v['admission_witnesses']); conflicts=_conflicts(v['conflicts'])
        if not witnesses and not conflicts: raise StateWitnessError('state witness needs a source')
        if any(x.claim_digest!=claim for x in witnesses) or any(x.claim_digest!=claim for x in conflicts): raise StateWitnessError('state witness source claim mismatch')
        projection=_projection(v['projection'])
        if projection.claim_digest!=claim: raise StateWitnessError('state witness projection claim mismatch')
        if v['claimed_state']!=projection.state: raise StateWitnessError('state witness claimed state mismatch')
        wd=_digests(v['witness_digests'],'witness_digests'); cd=_digests(v['conflict_ids'],'conflict_ids')
        if wd!=tuple(sorted(x.witness_digest for x in witnesses)) or cd!=tuple(sorted(x.conflict_id for x in conflicts)): raise StateWitnessError('state witness provenance mismatch')
        digest=_digest(v['state_digest'],'state_digest')
        result=cls(SCHEMA,claim,tuple(x.to_dict() for x in witnesses),tuple(x.to_dict() for x in conflicts),projection.to_dict(),v['claimed_state'],wd,cd,digest)
        if result.computed_digest!=digest: raise StateWitnessError('state witness digest mismatch')
        return result

@dataclass(frozen=True)
class StateWitnessVerdict:
    state:str; claimed_state:str; reasons:tuple[str,...]=(); unverified:tuple[str,...]=(); state_digest:str=''

def _canonical(v):
    try:return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    except (TypeError,ValueError) as e: raise StateWitnessError('state witness not canonical JSON') from e
def _hash(prefix,v): return 'sha256:'+hashlib.sha256(prefix+_canonical(v)).hexdigest()
def _digest(v,field):
    if not isinstance(v,str) or _DIGEST.fullmatch(v) is None: raise StateWitnessError(f'{field} invalid')
    return v
def _digests(v,field):
    if not isinstance(v,list) or len(set(v))!=len(v) or v!=sorted(v): raise StateWitnessError(f'{field} invalid')
    return tuple(_digest(x,field) for x in v)
def _witnesses(v, *, canonical=True):
    if not isinstance(v,list): raise StateWitnessError('admission witnesses invalid')
    out=[]
    for raw in v:
        try: out.append(AdmissionWitness.from_dict(raw))
        except WitnessError as e: raise StateWitnessError('admission witness invalid') from e
    if canonical and ([x.witness_digest for x in out]!=sorted(x.witness_digest for x in out) or len({x.witness_digest for x in out})!=len(out)): raise StateWitnessError('admission witnesses not canonical')
    return tuple(out)
def _conflicts(v, *, canonical=True):
    if not isinstance(v,list): raise StateWitnessError('conflicts invalid')
    out=[]
    for raw in v:
        try: out.append(ConflictObservation.from_dict(raw))
        except ConflictLedgerError as e: raise StateWitnessError('conflict invalid') from e
    if canonical and ([x.conflict_id for x in out]!=sorted(x.conflict_id for x in out) or len({x.conflict_id for x in out})!=len(out)): raise StateWitnessError('conflicts not canonical')
    return tuple(out)
def _projection(v):
    try:return ClaimProjection.from_dict(v)
    except ProjectionError as e: raise StateWitnessError('projection invalid') from e

def make_state_witness(claim_digest:str, admission_witnesses:Iterable[AdmissionWitness], conflicts:Iterable[ConflictObservation]=())->EvidenceStateWitness:
    claim=_digest(claim_digest,'claim_digest')
    try:
        witness_wire=[x.to_dict() for x in admission_witnesses]
        conflict_wire=[x.to_dict() for x in conflicts]
    except AttributeError as exc:
        raise StateWitnessError('state witness source is invalid') from exc
    witnesses=tuple(sorted(_witnesses(witness_wire, canonical=False),key=lambda x:x.witness_digest))
    observations=tuple(sorted(_conflicts(conflict_wire, canonical=False),key=lambda x:x.conflict_id))
    if not witnesses and not observations: raise StateWitnessError('unknown state without source is not witnessable')
    if any(x.claim_digest!=claim for x in witnesses) or any(x.claim_digest!=claim for x in observations): raise StateWitnessError('state witness source claim mismatch')
    projection=project_claim(claim,witnesses,observations)
    unsigned=EvidenceStateWitness(SCHEMA,claim,tuple(x.to_dict() for x in witnesses),tuple(x.to_dict() for x in observations),projection.to_dict(),projection.state,projection.witness_digests,projection.conflict_ids,'')
    return EvidenceStateWitness(unsigned.schema_version,unsigned.claim_digest,unsigned.admission_witnesses,unsigned.conflicts,unsigned.projection,unsigned.claimed_state,unsigned.witness_digests,unsigned.conflict_ids,unsigned.computed_digest)

def verify_state_witness(witness:EvidenceStateWitness,*,expected_state_digest:str|None=None)->StateWitnessVerdict:
    if not isinstance(witness,EvidenceStateWitness): raise StateWitnessError('state witness invalid')
    parsed=EvidenceStateWitness.from_dict(witness.to_dict())
    witnesses=_witnesses(list(parsed.admission_witnesses)); conflicts=_conflicts(list(parsed.conflicts))
    replay=project_claim(parsed.claim_digest,witnesses,conflicts)
    if replay.to_dict()!=parsed.projection or replay.state!=parsed.claimed_state or replay.witness_digests!=parsed.witness_digests or replay.conflict_ids!=parsed.conflict_ids: raise StateWitnessError('state witness replay mismatch')
    if expected_state_digest is not None and _digest(expected_state_digest,'expected_state_digest')!=parsed.state_digest: raise StateWitnessError('external state digest mismatch')
    unresolved=list(replay.unverified)
    if expected_state_digest is None: unresolved.append('state_digest_unpinned')
    return StateWitnessVerdict('state-witness-verified' if expected_state_digest is not None else 'state-witness-verified-unpinned',replay.state,(),tuple(sorted(set(unresolved))),parsed.state_digest)

__all__=['SCHEMA','StateWitnessError','EvidenceStateWitness','StateWitnessVerdict','make_state_witness','verify_state_witness']
