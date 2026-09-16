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

class _StoreLock:
    def __init__(self,path:Path):self.path=path;self.handle=None
    def __enter__(self):
        self.handle=self.path.open("a+");fcntl.flock(self.handle,fcntl.LOCK_EX);return None
    def __exit__(self,*_):
        assert self.handle is not None;fcntl.flock(self.handle,fcntl.LOCK_UN);self.handle.close()

__all__=["AutonomyCheckpointStoreError","CheckpointRecord","CheckpointResolution","AutonomyCheckpointStore"]
