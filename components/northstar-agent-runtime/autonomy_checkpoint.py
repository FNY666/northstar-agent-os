"""Host-owned, non-authorizing continuation checkpoints for AgentRuntime."""
from __future__ import annotations
import hashlib,json,re
from dataclasses import dataclass
from typing import Any

SCHEMA="northstar.autonomy-checkpoint.v1"
_DIGEST=re.compile(r"^sha256:[0-9a-f]{64}$")
_FIELDS=frozenset({"schema_version","goal_digest","session_id","runtime_digest","transcript_digest","budget_digest","observed_at","execution_authorized","checkpoint_digest"})
class AutonomyCheckpointError(ValueError): pass

def _canonical(value:Any)->bytes:
    try:return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
    except (TypeError,ValueError) as exc:raise AutonomyCheckpointError("checkpoint input is not canonical JSON") from exc
def _hash(domain:bytes,value:Any)->str:return "sha256:"+hashlib.sha256(domain+_canonical(value)).hexdigest()
def _host(value:Any,field:str)->Any:
    if value is None:raise AutonomyCheckpointError(f"{field} is required")
    _canonical(value);return value
def _digest(value:Any,field:str)->str:
    if not isinstance(value,str) or _DIGEST.fullmatch(value) is None:raise AutonomyCheckpointError(f"{field} invalid")
    return value

def _session(value:Any)->str:
    if not isinstance(value,str) or not value or len(value)>128:raise AutonomyCheckpointError("session_id invalid")
    return value

@dataclass(frozen=True)
class AutonomyCheckpoint:
    schema_version:str;goal_digest:str;session_id:str;runtime_digest:str;transcript_digest:str;budget_digest:str;observed_at:int;execution_authorized:bool;checkpoint_digest:str
    def unsigned_dict(self)->dict[str,Any]:return {"schema_version":self.schema_version,"goal_digest":self.goal_digest,"session_id":self.session_id,"runtime_digest":self.runtime_digest,"transcript_digest":self.transcript_digest,"budget_digest":self.budget_digest,"observed_at":self.observed_at,"execution_authorized":self.execution_authorized}
    def to_dict(self)->dict[str,Any]:return {**self.unsigned_dict(),"checkpoint_digest":self.checkpoint_digest}
    @property
    def computed_digest(self)->str:return _hash(b"northstar.autonomy-checkpoint.v1\0",self.unsigned_dict())
    @classmethod
    def from_dict(cls,value:Any)->"AutonomyCheckpoint":
        if not isinstance(value,dict) or set(value)!=_FIELDS or value.get("schema_version")!=SCHEMA:raise AutonomyCheckpointError("checkpoint fields invalid")
        if value.get("execution_authorized") is not False:raise AutonomyCheckpointError("checkpoint cannot authorize execution")
        if not isinstance(value.get("observed_at"),int) or isinstance(value.get("observed_at"),bool):raise AutonomyCheckpointError("observed_at invalid")
        item=cls(SCHEMA,_digest(value["goal_digest"],"goal_digest"),_session(value["session_id"]),_digest(value["runtime_digest"],"runtime_digest"),_digest(value["transcript_digest"],"transcript_digest"),_digest(value["budget_digest"],"budget_digest"),value["observed_at"],False,_digest(value["checkpoint_digest"],"checkpoint_digest"))
        if item.computed_digest!=item.checkpoint_digest:raise AutonomyCheckpointError("checkpoint digest mismatch")
        return item

@dataclass(frozen=True)
class ContinuationVerdict:
    state:str; reasons:tuple[str,...]=(); unverified:tuple[str,...]=(); execution_authorized:bool=False

def _observed_digest(value:Any,field:str,domain:bytes)->str:
    try:return _hash(domain,_host(value,field))
    except AutonomyCheckpointError:raise AutonomyCheckpointError(field+"_unreadable") from None

def verify_checkpoint(checkpoint:Any,*,goal:Any,session_id:str,runtime:Any,transcript:Any,budget:Any,now:int,expected_checkpoint_digest:str|None=None)->ContinuationVerdict:
    try:
        if not isinstance(checkpoint,AutonomyCheckpoint):raise AutonomyCheckpointError("checkpoint invalid")
        checkpoint=AutonomyCheckpoint.from_dict(checkpoint.to_dict())
    except (AttributeError,AutonomyCheckpointError):
        return ContinuationVerdict("unknown",("checkpoint_unreadable",),(),False)
    if not isinstance(now,int) or isinstance(now,bool):raise AutonomyCheckpointError("now invalid")
    if expected_checkpoint_digest is not None and _digest(expected_checkpoint_digest,"expected_checkpoint_digest")!=checkpoint.checkpoint_digest:raise AutonomyCheckpointError("external checkpoint digest mismatch")
    try:
        observed={
            "goal":_observed_digest(goal,"goal",b"northstar.autonomy-goal.v1\0"),
            "runtime":_observed_digest(runtime,"runtime",b"northstar.autonomy-runtime.v1\0"),
            "transcript":_observed_digest(transcript,"transcript",b"northstar.autonomy-transcript.v1\0"),
            "budget":_observed_digest(budget,"budget",b"northstar.autonomy-budget.v1\0"),
        }
        observed_session=_session(session_id)
    except AutonomyCheckpointError as error:
        return ContinuationVerdict("unknown",(str(error),),(),False)
    bindings={"goal":checkpoint.goal_digest,"runtime":checkpoint.runtime_digest,"transcript":checkpoint.transcript_digest,"budget":checkpoint.budget_digest}
    changed=[field+"_changed" for field,digest in bindings.items() if observed[field]!=digest]
    if observed_session!=checkpoint.session_id:changed.append("session_id_changed")
    if changed:return ContinuationVerdict("stale",tuple(changed),(),False)
    if expected_checkpoint_digest is None:return ContinuationVerdict("current-unpinned",(),("checkpoint_digest_unpinned",),False)
    return ContinuationVerdict("current",(),(),False)

def capture_checkpoint(*,goal:Any,session_id:str,runtime:Any,transcript:Any,budget:Any,observed_at:int)->AutonomyCheckpoint:
    if not isinstance(observed_at,int) or isinstance(observed_at,bool):raise AutonomyCheckpointError("observed_at invalid")
    draft=AutonomyCheckpoint(SCHEMA,_hash(b"northstar.autonomy-goal.v1\0",_host(goal,"goal")),_session(session_id),_hash(b"northstar.autonomy-runtime.v1\0",_host(runtime,"runtime")),_hash(b"northstar.autonomy-transcript.v1\0",_host(transcript,"transcript")),_hash(b"northstar.autonomy-budget.v1\0",_host(budget,"budget")),observed_at,False,"")
    return AutonomyCheckpoint(draft.schema_version,draft.goal_digest,draft.session_id,draft.runtime_digest,draft.transcript_digest,draft.budget_digest,draft.observed_at,False,draft.computed_digest)

__all__=["SCHEMA","AutonomyCheckpointError","AutonomyCheckpoint","ContinuationVerdict","capture_checkpoint","verify_checkpoint"]
