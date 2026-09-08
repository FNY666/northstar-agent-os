"""Ordered checkpoint chain for Merkle evidence bundles."""
from __future__ import annotations
import hashlib,json,os,fcntl
from dataclasses import dataclass
from pathlib import Path
from typing import Any,Iterator
SCHEMA='northstar.evidence-chain.v1'; ZERO='sha256:'+'0'*64
class ChainError(ValueError): pass
def _digest(v):
    if not isinstance(v,str) or not v.startswith('sha256:') or len(v)!=71: raise ChainError('digest invalid')
    return v
def _canon(v): return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
@dataclass(frozen=True)
class EvidenceCheckpoint:
    schema_version:str; batch_sequence:int; previous_root:str; current_root:str; evidence_count:int; checkpoint_digest:str
    def _payload(self): return {'schema_version':self.schema_version,'batch_sequence':self.batch_sequence,'previous_root':self.previous_root,'current_root':self.current_root,'evidence_count':self.evidence_count}
    @property
    def computed_digest(self): return 'sha256:'+hashlib.sha256(_canon(self._payload())).hexdigest()
    def to_dict(self): return {**self._payload(),'checkpoint_digest':self.checkpoint_digest}
    @classmethod
    def from_dict(cls,v:Any):
        fields={'schema_version','batch_sequence','previous_root','current_root','evidence_count','checkpoint_digest'}
        if not isinstance(v,dict) or set(v)!=fields or v['schema_version']!=SCHEMA: raise ChainError('checkpoint fields invalid')
        if not isinstance(v['batch_sequence'],int) or v['batch_sequence']<1 or not isinstance(v['evidence_count'],int) or v['evidence_count']<1: raise ChainError('checkpoint numbers invalid')
        prev=_digest(v['previous_root']); cur=_digest(v['current_root']); digest=_digest(v['checkpoint_digest'])
        obj=cls(SCHEMA,v['batch_sequence'],prev,cur,v['evidence_count'],digest)
        if obj.computed_digest!=digest: raise ChainError('checkpoint digest mismatch')
        return obj
class EvidenceChain:
    def __init__(self,path:Path|str|None=None): self.path=Path(path) if path else None; self.records=[]
    def append(self,bundle):
        if not hasattr(bundle,'root_digest') or not isinstance(bundle.leaf_count,int) or bundle.leaf_count<1: raise ChainError('bundle invalid')
        seq=len(self.records)+1; prev=ZERO if seq==1 else self.records[-1].current_root
        cp0=EvidenceCheckpoint(SCHEMA,seq,prev,bundle.root_digest,bundle.leaf_count,'sha256:'+'0'*64); cp=EvidenceCheckpoint(SCHEMA,seq,prev,bundle.root_digest,bundle.leaf_count,cp0.computed_digest)
        if self.records and cp.previous_root!=self.records[-1].current_root: raise ChainError('previous root mismatch')
        self.records.append(cp)
        if self.path:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            with self.path.open('ab') as f:f.write(_canon(cp.to_dict())+b'\n');f.flush();os.fsync(f.fileno())
        return cp
    def append_fenced(self,bundle,lease,*,now:int,lease_path):
        from recovery_cursor import PersistentLeaseManager, RecoveryError
        try: PersistentLeaseManager(lease_path).validate(lease,now=now)
        except RecoveryError as exc: raise ChainError('lease invalid') from exc
        with Path(str(self.path)+'.lock').open('a+') as lock:
            fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
            try: return self.append(bundle)
            finally: fcntl.flock(lock.fileno(),fcntl.LOCK_UN)

    def read(self): return iter(self.records)

    @classmethod
    def from_records(cls,records):
        c=cls();
        for r in records:
            if not isinstance(r,EvidenceCheckpoint): raise ChainError('record invalid')
            c.records.append(r)
        return c
    @classmethod
    def from_path(cls,path):
        c=cls(path); path=Path(path)
        if not path.exists(): return c
        for raw in path.read_bytes().splitlines():
            try:c.records.append(EvidenceCheckpoint.from_dict(json.loads(raw)))
            except (ValueError,json.JSONDecodeError) as e: raise ChainError('chain corrupt') from e
        return c
def verify_chain(chain):
    previous=ZERO; sequence=1
    for record in chain.read():
        if record.batch_sequence!=sequence or record.previous_root!=previous: raise ChainError('chain continuity mismatch')
        if record.computed_digest!=record.checkpoint_digest: raise ChainError('checkpoint digest mismatch')
        previous=record.current_root;sequence+=1
