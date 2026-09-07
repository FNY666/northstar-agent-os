"""Owner-bound recovery cursor and local fencing primitives."""
from __future__ import annotations
from dataclasses import dataclass
import re
from typing import Any

_ID=re.compile(r'^[A-Za-z0-9._:-]{1,128}$')
_DIGEST=re.compile(r'^sha256:[0-9a-f]{64}$')
class RecoveryError(ValueError): pass

def _id(v,name):
    if not isinstance(v,str) or not _ID.fullmatch(v): raise RecoveryError(f'{name} invalid')
    return v

def _digest(v,name):
    if not isinstance(v,str) or not _DIGEST.fullmatch(v): raise RecoveryError(f'{name} invalid')
    return v

@dataclass(frozen=True)
class RecoveryCursor:
    sequence:int; event_digest:str; schema_version:str; journal_digest:str
    @classmethod
    def from_dict(cls,v:Any):
        if not isinstance(v,dict) or set(v)!={'sequence','event_digest','schema_version','journal_digest'}: raise RecoveryError('cursor fields invalid')
        if not isinstance(v['sequence'],int) or isinstance(v['sequence'],bool) or v['sequence']<0: raise RecoveryError('cursor sequence invalid')
        return cls(v['sequence'],_digest(v['event_digest'],'event_digest'),_id(v['schema_version'],'schema_version'),_digest(v['journal_digest'],'journal_digest'))
    def to_dict(self): return {'sequence':self.sequence,'event_digest':self.event_digest,'schema_version':self.schema_version,'journal_digest':self.journal_digest}

@dataclass(frozen=True)
class Lease:
    owner_id:str; fencing_token:int; expires_at:int
    def __post_init__(self):
        _id(self.owner_id,'owner_id')
        if not isinstance(self.fencing_token,int) or isinstance(self.fencing_token,bool) or self.fencing_token<1: raise RecoveryError('fencing token invalid')
        if not isinstance(self.expires_at,int) or isinstance(self.expires_at,bool): raise RecoveryError('expiry invalid')

class LeaseManager:
    def __init__(self): self._token=0; self._lease=None
    def acquire(self,owner_id:str,*,now:int,ttl:int)->Lease:
        _id(owner_id,'owner_id')
        if not isinstance(now,int) or not isinstance(ttl,int) or ttl<=0: raise RecoveryError('lease timing invalid')
        if self._lease is not None and self._lease.expires_at>now: raise RecoveryError('active lease exists')
        self._token+=1; self._lease=Lease(owner_id,self._token,now+ttl); return self._lease
    def heartbeat(self,lease:Lease,*,now:int,ttl:int)->Lease:
        self.validate(lease,now=now); renewed=Lease(lease.owner_id,lease.fencing_token,now+ttl); self._lease=renewed; return renewed
    def validate(self,lease:Lease,*,now:int)->None:
        if self._lease!=lease or lease.expires_at<=now: raise RecoveryError('lease is stale or expired')
