"""Replayable observations of readiness-lease registry state."""
from __future__ import annotations
import hashlib,json,re
from dataclasses import dataclass
from typing import Any
from evidence_readiness_lease_registry import EvidenceReadinessLeaseRegistry,LeaseRegistryError

SCHEMA='northstar.readiness-lease-witness.v1'
_DIGEST=re.compile(r'^sha256:[0-9a-f]{64}$')
_FIELDS=frozenset({'schema_version','lease_digest','observed_state','record_sequence','registry_head_digest','observed_at','witness_digest'})

class RegistryWitnessError(ValueError): pass

@dataclass(frozen=True)
class LeaseRegistryWitness:
    schema_version:str; lease_digest:str; observed_state:str; record_sequence:int; registry_head_digest:str; observed_at:int; witness_digest:str
    def unsigned_dict(self): return {'schema_version':self.schema_version,'lease_digest':self.lease_digest,'observed_state':self.observed_state,'record_sequence':self.record_sequence,'registry_head_digest':self.registry_head_digest,'observed_at':self.observed_at}
    def to_dict(self): return {**self.unsigned_dict(),'witness_digest':self.witness_digest}
    @property
    def computed_digest(self): return _hash(b'northstar.readiness-lease-witness.v1\0',self.unsigned_dict())
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_FIELDS or v['schema_version']!=SCHEMA: raise RegistryWitnessError('lease witness fields invalid')
        lease=_digest(v['lease_digest'],'lease_digest'); head=_digest(v['registry_head_digest'],'registry_head_digest'); digest=_digest(v['witness_digest'],'witness_digest')
        if v['observed_state'] not in {'active','expired','revoked','unknown'}: raise RegistryWitnessError('observed state invalid')
        if not isinstance(v['record_sequence'],int) or isinstance(v['record_sequence'],bool) or v['record_sequence']<0: raise RegistryWitnessError('record sequence invalid')
        if not isinstance(v['observed_at'],int) or isinstance(v['observed_at'],bool): raise RegistryWitnessError('observed time invalid')
        result=cls(SCHEMA,lease,v['observed_state'],v['record_sequence'],head,v['observed_at'],digest)
        if result.computed_digest!=digest: raise RegistryWitnessError('witness digest mismatch')
        return result

@dataclass(frozen=True)
class RegistryWitnessVerdict:
    state:str; reasons:tuple[str,...]=(); unverified:tuple[str,...]=(); execution_authorized:bool=False; witness_digest:str=''

def _canonical(v):
    try:return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    except (TypeError,ValueError) as e: raise RegistryWitnessError('witness not canonical JSON') from e
def _hash(prefix,v): return 'sha256:'+hashlib.sha256(prefix+_canonical(v)).hexdigest()
def _digest(v,field):
    if not isinstance(v,str) or _DIGEST.fullmatch(v) is None: raise RegistryWitnessError(f'{field} invalid')
    return v

def make_registry_witness(registry:EvidenceReadinessLeaseRegistry,lease_digest:str,*,now:int)->LeaseRegistryWitness:
    if not isinstance(registry,EvidenceReadinessLeaseRegistry): raise RegistryWitnessError('registry invalid')
    _digest(lease_digest,'lease_digest')
    if not isinstance(now,int) or isinstance(now,bool): raise RegistryWitnessError('observed time invalid')
    verdict=registry.inspect(lease_digest,now=now)
    records=registry.records if verdict.state!='unverifiable' else []
    head=verdict.lease_digest if not records else records[-1].record_digest
    sequence=len(records)
    if verdict.state=='unverifiable': raise RegistryWitnessError('registry is unverifiable')
    unsigned=LeaseRegistryWitness(SCHEMA,lease_digest,verdict.state,sequence,head,now,'')
    return LeaseRegistryWitness(unsigned.schema_version,unsigned.lease_digest,unsigned.observed_state,unsigned.record_sequence,unsigned.registry_head_digest,unsigned.observed_at,unsigned.computed_digest)

def verify_registry_witness(witness:LeaseRegistryWitness,registry:EvidenceReadinessLeaseRegistry,*,now:int,expected_witness_digest:str|None=None)->RegistryWitnessVerdict:
    if not isinstance(witness,LeaseRegistryWitness): raise RegistryWitnessError('witness invalid')
    parsed=LeaseRegistryWitness.from_dict(witness.to_dict())
    if not isinstance(now,int) or isinstance(now,bool): raise RegistryWitnessError('observed time invalid')
    if expected_witness_digest is not None and _digest(expected_witness_digest,'expected_witness_digest')!=parsed.witness_digest: raise RegistryWitnessError('external witness digest mismatch')
    try: registry_verdict=registry.inspect(parsed.lease_digest,now=now); records=registry.records
    except LeaseRegistryError as e: return RegistryWitnessVerdict('unverifiable',(str(e),),(),False,parsed.witness_digest)
    current_head=records[-1].record_digest if records else parsed.lease_digest
    if registry_verdict.state=='unverifiable': return RegistryWitnessVerdict('unverifiable',registry_verdict.reasons,(),False,parsed.witness_digest)
    if registry_verdict.state=='revoked':
        state='revoked'; reasons=('lease_revoked',)
    elif registry_verdict.state=='expired':
        state='expired'; reasons=('lease_expired',)
    elif registry_verdict.state=='unknown':
        state='unknown'; reasons=('lease_unknown',)
    elif len(records)!=parsed.record_sequence or current_head!=parsed.registry_head_digest:
        return RegistryWitnessVerdict('stale',('registry_head_changed',),(),False,parsed.witness_digest)
    else:
        state='current'; reasons=()
    unresolved=[] if expected_witness_digest is not None else ['witness_digest_unpinned']
    if expected_witness_digest is None:
        state = state + '-unpinned' if state == 'current' else state
    return RegistryWitnessVerdict(state,reasons,tuple(unresolved),False,parsed.witness_digest)

__all__=['SCHEMA','RegistryWitnessError','LeaseRegistryWitness','RegistryWitnessVerdict','make_registry_witness','verify_registry_witness']
