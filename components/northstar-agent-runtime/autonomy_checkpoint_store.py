"""Append-only, non-authorizing storage for autonomous continuation checkpoints."""
from __future__ import annotations
import fcntl,hashlib,json,os,tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any,Iterator
from autonomy_checkpoint import AutonomyCheckpoint,AutonomyCheckpointError

RECORD_SCHEMA="northstar.autonomy-checkpoint-record.v1"
HEAD_SCHEMA="northstar.autonomy-checkpoint-head.v1"
_RECORD_FIELDS=frozenset({"schema_version","sequence","checkpoint","prev_record_digest","record_digest"})
_HEAD_FIELDS=frozenset({"schema_version","sequence","head_record_digest"})
HISTORY_SCHEMA="northstar.continuation-history.v1"
HISTORY_STATES=frozenset({"continuous","objective_changed","unrecorded","unverifiable"})
_HISTORY_FIELDS=frozenset({"schema_version","state","session_id","entries","reasons","unverified","changed_at_sequence","head_digest","execution_authorized"})
_ENTRY_FIELDS=frozenset({"sequence","record_digest","checkpoint_digest","objective_digest","observed_at"})
class AutonomyCheckpointStoreError(ValueError):pass

def _canonical(value:Any)->bytes:
    try:return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
    except (TypeError,ValueError) as exc:raise AutonomyCheckpointStoreError("store value is not canonical JSON") from exc
def _digest(value:Any)->str:return "sha256:"+hashlib.sha256(_canonical(value)).hexdigest()
def _valid_digest(value:Any,field:str)->str:
    if not isinstance(value,str) or not value.startswith("sha256:") or len(value)!=71:raise AutonomyCheckpointStoreError(field+" invalid")
    try:int(value[7:],16)
    except ValueError:raise AutonomyCheckpointStoreError(field+" invalid") from None
    return value

def _session(value:Any)->str:
    if not isinstance(value,str) or not value or len(value)>128:raise AutonomyCheckpointStoreError("session_id invalid")
    return value

def _tokens(value:Any,field:str)->tuple[str,...]:
    if not isinstance(value,list) or any(not isinstance(token,str) for token in value):raise AutonomyCheckpointStoreError(field+" invalid")
    return tuple(value)

@dataclass(frozen=True)
class CheckpointRecord:
    schema_version:str;sequence:int;checkpoint:dict[str,Any];prev_record_digest:str|None;record_digest:str
    def unsigned_dict(self)->dict[str,Any]:return {"schema_version":self.schema_version,"sequence":self.sequence,"checkpoint":self.checkpoint,"prev_record_digest":self.prev_record_digest}
    def to_dict(self)->dict[str,Any]:return {**self.unsigned_dict(),"record_digest":self.record_digest}
    @property
    def computed_digest(self)->str:return _digest(self.unsigned_dict())
    @property
    def checkpoint_value(self)->AutonomyCheckpoint:return AutonomyCheckpoint.from_dict(self.checkpoint)
    @classmethod
    def from_dict(cls,value:Any)->"CheckpointRecord":
        if not isinstance(value,dict) or set(value)!=_RECORD_FIELDS or value.get("schema_version")!=RECORD_SCHEMA:raise AutonomyCheckpointStoreError("record fields invalid")
        sequence=value.get("sequence")
        if not isinstance(sequence,int) or isinstance(sequence,bool) or sequence<1:raise AutonomyCheckpointStoreError("record sequence invalid")
        try:checkpoint=AutonomyCheckpoint.from_dict(value["checkpoint"])
        except AutonomyCheckpointError as exc:raise AutonomyCheckpointStoreError("record checkpoint invalid") from exc
        prev=value.get("prev_record_digest")
        if (sequence==1 and prev is not None) or (sequence>1 and not isinstance(prev,str)):raise AutonomyCheckpointStoreError("record predecessor invalid")
        if prev is not None:_valid_digest(prev,"prev_record_digest")
        item=cls(RECORD_SCHEMA,sequence,checkpoint.to_dict(),prev,_valid_digest(value.get("record_digest"),"record_digest"))
        if item.computed_digest!=item.record_digest:raise AutonomyCheckpointStoreError("record digest mismatch")
        return item

@dataclass(frozen=True)
class CheckpointResolution:
    state:str;record:CheckpointRecord|None=None;reasons:tuple[str,...]=();unverified:tuple[str,...]=();execution_authorized:bool=False

@dataclass(frozen=True)
class ContinuationHistoryEntry:
    sequence:int
    record_digest:str
    checkpoint_digest:str
    objective_digest:str
    observed_at:int
    def to_dict(self)->dict[str,Any]:return {"sequence":self.sequence,"record_digest":self.record_digest,"checkpoint_digest":self.checkpoint_digest,"objective_digest":self.objective_digest,"observed_at":self.observed_at}
    @classmethod
    def from_dict(cls,value:Any)->"ContinuationHistoryEntry":
        if not isinstance(value,dict) or set(value)!=_ENTRY_FIELDS:raise AutonomyCheckpointStoreError("history entry fields invalid")
        sequence=value.get("sequence")
        if not isinstance(sequence,int) or isinstance(sequence,bool) or sequence<1:raise AutonomyCheckpointStoreError("history entry sequence invalid")
        observed_at=value.get("observed_at")
        if not isinstance(observed_at,int) or isinstance(observed_at,bool):raise AutonomyCheckpointStoreError("history entry observed_at invalid")
        return cls(sequence,_valid_digest(value.get("record_digest"),"record_digest"),_valid_digest(value.get("checkpoint_digest"),"checkpoint_digest"),_valid_digest(value.get("objective_digest"),"objective_digest"),observed_at)

@dataclass(frozen=True)
class ContinuationHistory:
    state:str
    session_id:str
    entries:tuple[ContinuationHistoryEntry,...]=()
    reasons:tuple[str,...]=()
    unverified:tuple[str,...]=()
    changed_at_sequence:int|None=None
    head_digest:str|None=None
    execution_authorized:bool=False
    def to_dict(self)->dict[str,Any]:return {"schema_version":HISTORY_SCHEMA,"state":self.state,"session_id":self.session_id,"entries":[entry.to_dict() for entry in self.entries],"reasons":list(self.reasons),"unverified":list(self.unverified),"changed_at_sequence":self.changed_at_sequence,"head_digest":self.head_digest,"execution_authorized":self.execution_authorized}
    @classmethod
    def from_dict(cls,value:Any)->"ContinuationHistory":
        if not isinstance(value,dict) or set(value)!=_HISTORY_FIELDS or value.get("schema_version")!=HISTORY_SCHEMA:raise AutonomyCheckpointStoreError("history fields invalid")
        if value.get("state") not in HISTORY_STATES:raise AutonomyCheckpointStoreError("history state invalid")
        if value.get("execution_authorized") is not False:raise AutonomyCheckpointStoreError("history cannot authorize execution")
        entries=value.get("entries")
        if not isinstance(entries,list):raise AutonomyCheckpointStoreError("history entries invalid")
        changed=value.get("changed_at_sequence")
        if changed is not None and (not isinstance(changed,int) or isinstance(changed,bool)):raise AutonomyCheckpointStoreError("history changed_at_sequence invalid")
        head=value.get("head_digest")
        return cls(value.get("state"),_session(value.get("session_id")),tuple(ContinuationHistoryEntry.from_dict(entry) for entry in entries),_tokens(value.get("reasons"),"reasons"),_tokens(value.get("unverified"),"unverified"),changed,None if head is None else _valid_digest(head,"head_digest"),False)

class AutonomyCheckpointStore:
    """One local append-only checkpoint history with a persisted head witness."""
    def __init__(self,path:str|Path):
        self.path=Path(path).absolute()
        self.head_path=self.path.with_name(self.path.name+".head.json")
        self.lock_path=self.path.with_name(self.path.name+".lock")
    def _locked(self)->Iterator[None]:
        self.path.parent.mkdir(parents=True,exist_ok=True)
        return _StoreLock(self.lock_path)
    def _records(self)->list[CheckpointRecord]:
        if not self.path.exists():
            if self.head_path.exists():raise AutonomyCheckpointStoreError("head witness exists without history")
            return []
        try:lines=self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:raise AutonomyCheckpointStoreError("history unreadable") from exc
        records=[]
        for number,line in enumerate(lines,1):
            if not line.strip():raise AutonomyCheckpointStoreError("history contains blank line")
            try:records.append(CheckpointRecord.from_dict(json.loads(line)))
            except (json.JSONDecodeError,AutonomyCheckpointStoreError) as exc:raise AutonomyCheckpointStoreError("history record invalid at line "+str(number)) from exc
        previous=None
        for expected,record in enumerate(records,1):
            if record.sequence!=expected or record.prev_record_digest!=previous:raise AutonomyCheckpointStoreError("history chain is not contiguous")
            previous=record.record_digest
        self._validate_head(records)
        return records
    def _validate_head(self,records:list[CheckpointRecord])->None:
        if not records:
            if self.head_path.exists():raise AutonomyCheckpointStoreError("head witness exists without history")
            return
        try:head=json.loads(self.head_path.read_text(encoding="utf-8"))
        except (OSError,json.JSONDecodeError) as exc:raise AutonomyCheckpointStoreError("head witness unreadable") from exc
        if not isinstance(head,dict) or set(head)!=_HEAD_FIELDS or head.get("schema_version")!=HEAD_SCHEMA:raise AutonomyCheckpointStoreError("head witness fields invalid")
        if head.get("sequence")!=records[-1].sequence or head.get("head_record_digest")!=records[-1].record_digest:raise AutonomyCheckpointStoreError("head witness does not match history")
    def _write_head(self,record:CheckpointRecord)->None:
        value={"schema_version":HEAD_SCHEMA,"sequence":record.sequence,"head_record_digest":record.record_digest}
        fd,tmp=tempfile.mkstemp(prefix=self.head_path.name+".",dir=str(self.path.parent))
        try:
            with os.fdopen(fd,"wb") as stream:
                stream.write(_canonical(value));stream.write(b"\n");stream.flush();os.fsync(stream.fileno())
            os.replace(tmp,self.head_path)
            directory=os.open(str(self.path.parent),os.O_RDONLY)
            try:os.fsync(directory)
            finally:os.close(directory)
        except OSError as exc:
            try:os.unlink(tmp)
            except OSError:pass
            raise AutonomyCheckpointStoreError("head witness could not be persisted") from exc
    def append(self,checkpoint:AutonomyCheckpoint)->CheckpointRecord:
        try:checkpoint=AutonomyCheckpoint.from_dict(checkpoint.to_dict())
        except (AttributeError,AutonomyCheckpointError) as exc:raise AutonomyCheckpointStoreError("checkpoint invalid") from exc
        with self._locked():
            records=self._records()
            if records and records[-1].checkpoint_value.checkpoint_digest==checkpoint.checkpoint_digest:return records[-1]
            record=CheckpointRecord(RECORD_SCHEMA,len(records)+1,checkpoint.to_dict(),records[-1].record_digest if records else None,"")
            record=CheckpointRecord(record.schema_version,record.sequence,record.checkpoint,record.prev_record_digest,record.computed_digest)
            try:
                with self.path.open("ab") as stream:
                    stream.write(_canonical(record.to_dict()));stream.write(b"\n");stream.flush();os.fsync(stream.fileno())
            except OSError as exc:raise AutonomyCheckpointStoreError("checkpoint record could not be appended") from exc
            self._write_head(record)
            return record
    def resolve(self,session_id:str,*,expected_record_digest:str|None=None)->CheckpointResolution:
        try:
            session=_session(session_id)
            if expected_record_digest is not None:_valid_digest(expected_record_digest,"expected_record_digest")
            with self._locked():records=self._records()
        except AutonomyCheckpointStoreError as exc:return CheckpointResolution("unverifiable",None,(str(exc),),(),False)
        matches=[record for record in records if record.checkpoint_value.session_id==session]
        if not matches:return CheckpointResolution("unrecorded",None,("checkpoint_unrecorded",),(),False)
        record=matches[-1]
        if expected_record_digest is not None and expected_record_digest!=record.record_digest:return CheckpointResolution("stale",record,("record_digest_changed",),(),False)
        if expected_record_digest is None:return CheckpointResolution("recorded-unpinned",record,(),("record_digest_unpinned",),False)
        return CheckpointResolution("recorded",record,(),(),False)
    def history(self,session_id:str,*,expected_head_digest:str|None=None)->ContinuationHistory:
        """Report objective continuity across a session's persisted checkpoints; read-only."""
        session=""
        try:
            session=_session(session_id)
            if expected_head_digest is not None:_valid_digest(expected_head_digest,"expected_head_digest")
            with self._locked():records=self._records()
        except AutonomyCheckpointStoreError as exc:return ContinuationHistory("unverifiable",session,(),(str(exc),),(),None,None,False)
        matches=[record for record in records if record.checkpoint_value.session_id==session]
        if not matches:return ContinuationHistory("unrecorded",session,(),("continuation_history_unrecorded",),(),None,None,False)
        entries=tuple(ContinuationHistoryEntry(record.sequence,record.record_digest,record.checkpoint_value.checkpoint_digest,record.checkpoint_value.goal_digest,record.checkpoint_value.observed_at) for record in matches)
        changed=None
        for previous,current in zip(entries,entries[1:]):
            if previous.objective_digest!=current.objective_digest:
                changed=current.sequence
                break
        reasons=("objective_changed",) if changed is not None else ()
        head=entries[-1].record_digest
        if expected_head_digest is None:unverified=("history_head_unpinned",)
        else:
            unverified=()
            if expected_head_digest!=head:reasons=reasons+("history_head_changed",)
        return ContinuationHistory("objective_changed" if changed is not None else "continuous",session,entries,reasons,unverified,changed,head,False)

class _StoreLock:
    def __init__(self,path:Path):self.path=path;self.handle=None
    def __enter__(self):
        self.handle=self.path.open("a+");fcntl.flock(self.handle,fcntl.LOCK_EX);return None
    def __exit__(self,*_):
        assert self.handle is not None;fcntl.flock(self.handle,fcntl.LOCK_UN);self.handle.close()

__all__=["AutonomyCheckpointStoreError","CheckpointRecord","CheckpointResolution","ContinuationHistoryEntry","ContinuationHistory","AutonomyCheckpointStore"]
