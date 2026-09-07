"""Crash-aware local transaction coordinator for lineage append/checkpoint."""
from __future__ import annotations
from dataclasses import dataclass
import fcntl, hashlib, json, os
from pathlib import Path
from typing import Any, Callable
from recovery_cursor import Lease, PersistentLeaseManager, RecoveryCursor, RecoveryError
from route_lineage import LineageGraph, RouteLineageEvent, LineageError, INTEGRITY_SCHEMA
class TransactionError(ValueError): pass
@dataclass(frozen=True)
class TransactionCheckpoint:
    sequence:int; event_digest:str; journal_digest:str; fencing_token:int; owner_id:str; state:str
    @classmethod
    def from_dict(cls,v:Any):
        fields={'sequence','event_digest','journal_digest','fencing_token','owner_id','state'}
        if not isinstance(v,dict) or set(v)!=fields: raise TransactionError('checkpoint fields invalid')
        if not isinstance(v['sequence'],int) or v['sequence']<0 or not isinstance(v['fencing_token'],int) or v['fencing_token']<1: raise TransactionError('checkpoint numbers invalid')
        if not isinstance(v['event_digest'],str) or not v['event_digest'].startswith('sha256:') or not isinstance(v['journal_digest'],str) or not v['journal_digest'].startswith('sha256:'): raise TransactionError('checkpoint digests invalid')
        if not isinstance(v['owner_id'],str) or not v['owner_id'] or v['state'] not in {'committed','unknown'}: raise TransactionError('checkpoint identity/state invalid')
        return cls(v['sequence'],v['event_digest'],v['journal_digest'],v['fencing_token'],v['owner_id'],v['state'])
    def to_dict(self): return self.__dict__.copy()
class TransactionalLineageStore:
    def __init__(self,lineage_path:Path|str,checkpoint_path:Path|str, fault:Callable[[str],None]|None=None):
        self.lineage=Path(lineage_path); self.checkpoint=Path(checkpoint_path); self.lock=self.lineage.with_name(self.lineage.name+'.txn.lock'); self.fault=fault
    def _journal_digest(self): return 'sha256:'+hashlib.sha256(self.lineage.read_bytes() if self.lineage.exists() else b'').hexdigest()
    def append(self,event:RouteLineageEvent,cursor:RecoveryCursor,lease:Lease,*,now:int)->RecoveryCursor:
        with self.lock.open('a+') as lock:
            fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
            manager=PersistentLeaseManager(self.checkpoint.parent / 'lease.json')
            try: manager.validate(lease,now=now)
            except RecoveryError as exc: raise TransactionError('lease invalid') from exc
            graph=LineageGraph.from_path(self.lineage); current=graph.cursor()
            if cursor!=current: raise TransactionError('cursor mismatch')
            if self.fault: self.fault('before_event_append')
            try: graph.append(event)
            except (ValueError,LineageError) as exc: raise TransactionError('event append failed') from exc
            next_cursor=graph.cursor(); cp=TransactionCheckpoint(next_cursor.sequence,next_cursor.event_digest,next_cursor.journal_digest,lease.fencing_token,lease.owner_id,'committed')
            if self.fault: self.fault('after_event_fsync')
            tmp=self.checkpoint.with_suffix('.tmp'); tmp.write_text(json.dumps(cp.to_dict(),separators=(',',':')),encoding='utf-8'); fd=os.open(tmp,os.O_RDONLY); os.fsync(fd); os.close(fd)
            if self.fault: self.fault('before_checkpoint_replace')
            os.replace(tmp,self.checkpoint)
            if self.fault: self.fault('after_checkpoint_replace')
            return next_cursor
    def recover(self):
        if not self.checkpoint.exists(): raise TransactionError('checkpoint missing')
        try: cp=TransactionCheckpoint.from_dict(json.loads(self.checkpoint.read_text()))
        except (json.JSONDecodeError,ValueError) as exc: raise TransactionError('checkpoint corrupt') from exc
        graph=LineageGraph.from_path(self.lineage); cursor=graph.cursor()
        if cp.state!='committed' or cp.sequence!=cursor.sequence or cp.event_digest!=cursor.event_digest or cp.journal_digest!=cursor.journal_digest: raise TransactionError('checkpoint mismatch')
        lease_path=self.checkpoint.parent / 'lease.json'
        try:
            lease=PersistentLeaseManager(lease_path).read()
        except RecoveryError as exc:
            raise TransactionError('persisted lease missing') from exc
        if lease.fencing_token != cp.fencing_token or lease.owner_id != cp.owner_id:
            raise TransactionError('checkpoint lease identity mismatch')
        return cursor,lease
