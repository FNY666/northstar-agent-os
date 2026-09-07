"""Owner-bound recovery cursor and persistent fencing leases."""
from __future__ import annotations
from dataclasses import dataclass
import fcntl, json, os, re
from typing import Any
_ID=re.compile(r'^[A-Za-z0-9._:-]{1,128}$'); _DIGEST=re.compile(r'^sha256:[0-9a-f]{64}$')
class RecoveryError(ValueError): pass
def _id(v,n):
    if not isinstance(v,str) or not _ID.fullmatch(v): raise RecoveryError(f'{n} invalid')
    return v
def _digest(v,n):
    if not isinstance(v,str) or not _DIGEST.fullmatch(v): raise RecoveryError(f'{n} invalid')
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
    def acquire(self,owner_id,*,now,ttl):
        _id(owner_id,'owner_id')
        if not isinstance(now,int) or not isinstance(ttl,int) or ttl<=0: raise RecoveryError('lease timing invalid')
        if self._lease is not None and self._lease.expires_at>now: raise RecoveryError('active lease exists')
        self._token+=1; self._lease=Lease(owner_id,self._token,now+ttl); return self._lease
    def heartbeat(self,lease,*,now,ttl): self.validate(lease,now=now); self._lease=Lease(lease.owner_id,lease.fencing_token,now+ttl); return self._lease
    def validate(self,lease,*,now):
        if self._lease!=lease or lease.expires_at<=now: raise RecoveryError('lease is stale or expired')
class PersistentLeaseManager:
    def __init__(self,path): self.path=os.fspath(path); self.lock_path=self.path+'.lock'
    def _read(self):
        try:
            with open(self.path,encoding='utf-8') as f: return Lease(**json.load(f))
        except FileNotFoundError: return None
    def read(self):
        lease=self._read()
        if lease is None: raise RecoveryError('no persisted lease')
        return lease
    def acquire(self,owner_id,*,now,ttl):
        _id(owner_id,'owner_id')
        if not isinstance(now,int) or not isinstance(ttl,int) or ttl<=0: raise RecoveryError('lease timing invalid')
        os.makedirs(os.path.dirname(self.path) or '.',exist_ok=True)
        with open(self.lock_path,'a+') as lock:
            fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
            current=self._read()
            if current is not None and current.expires_at>now: raise RecoveryError('active lease exists')
            token=1 if current is None else current.fencing_token+1; lease=Lease(owner_id,token,now+ttl)
            tmp=self.path+'.tmp'
            with open(tmp,'w',encoding='utf-8') as out:
                json.dump(lease.__dict__,out,separators=(',',':')); out.flush(); os.fsync(out.fileno())
            os.replace(tmp,self.path); fcntl.flock(lock.fileno(),fcntl.LOCK_UN); return lease
    def heartbeat(self, lease, *, now, ttl):
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
            raise RecoveryError('lease timing invalid')
        os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
        with open(self.lock_path, 'a+') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            current = self._read()
            if current != lease or lease.expires_at <= now:
                raise RecoveryError('lease is stale or expired')
            renewed = Lease(lease.owner_id, lease.fencing_token, now + ttl)
            tmp = self.path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as out:
                json.dump(renewed.__dict__, out, separators=(',', ':'))
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, self.path)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return renewed

    def validate(self,lease,*,now):
        if self.read()!=lease or lease.expires_at<=now: raise RecoveryError('lease is stale or expired')
