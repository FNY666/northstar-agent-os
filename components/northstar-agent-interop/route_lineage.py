"""Causal, append-only lifecycle evidence for route decisions and receipts."""
from __future__ import annotations
import hashlib, json, os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Literal
from route_replay import MigrationError, MigrationRegistry

SCHEMA = "northstar.route-lineage.v1"
INTEGRITY_SCHEMA = "northstar.route-lineage.v2"
ZERO_DIGEST = "0" * 64
STATUSES = ("planned", "dispatched", "succeeded", "failed", "replayed", "superseded")
OLD_FIELDS = {"schema_version","event_id","route_id","parent_event_id","receipt_id","status","target_agent_id","provider","capabilities","deadline_at","payload_digest","decision_fingerprint","retryable"}
V2_FIELDS = OLD_FIELDS | {"sequence","prev_event_digest"}
V2_FIELDS_WITH_DIGEST = V2_FIELDS | {"event_digest"}
IDS=lambda v:isinstance(v,str) and 1<=len(v)<=256 and all(c.isalnum() or c in '._:-' for c in v)
_DIGEST=lambda v:isinstance(v,str) and v.startswith('sha256:') and len(v)==71

class LineageError(ValueError): pass

@dataclass(frozen=True)
class RouteLineageEvent:
    schema_version:str; event_id:str; route_id:str; parent_event_id:str|None; receipt_id:str
    status:Literal["planned","dispatched","succeeded","failed","replayed","superseded"]
    target_agent_id:str; provider:str; capabilities:tuple[str,...]; deadline_at:int
    payload_digest:str; decision_fingerprint:str; retryable:bool
    sequence:int|None = None; prev_event_digest:str|None = None; supplied_event_digest:str|None = None

    @classmethod
    def from_dict(cls,v:Any):
        if not isinstance(v,dict): raise LineageError('lineage event must be an object')
        schema=v.get('schema_version')
        fields=set(v)
        if schema==SCHEMA:
            if fields != OLD_FIELDS: raise LineageError('unknown or missing lineage fields')
        elif schema==INTEGRITY_SCHEMA:
            if fields not in (V2_FIELDS,V2_FIELDS_WITH_DIGEST): raise LineageError('unknown or missing integrity fields')
        else: raise LineageError('invalid lineage schema')
        if v['status'] not in STATUSES: raise LineageError('invalid lineage status')
        for k in ('event_id','route_id','receipt_id','target_agent_id','provider'):
            if not IDS(v[k]): raise LineageError(f'invalid {k}')
        if v['parent_event_id'] is not None and not IDS(v['parent_event_id']): raise LineageError('invalid parent_event_id')
        if not isinstance(v['capabilities'],list) or len(set(v['capabilities']))!=len(v['capabilities']) or not all(isinstance(x,str) and ':' in x and '*' not in x for x in v['capabilities']): raise LineageError('invalid capabilities')
        if not isinstance(v['deadline_at'],int) or isinstance(v['deadline_at'],bool) or v['deadline_at']<0: raise LineageError('invalid deadline')
        if not _DIGEST(v['payload_digest']) or not _DIGEST(v['decision_fingerprint']): raise LineageError('invalid digest')
        if not isinstance(v['retryable'],bool): raise LineageError('invalid retryable')
        sequence = prev = supplied = None
        if schema==INTEGRITY_SCHEMA:
            sequence=v['sequence']; prev=v['prev_event_digest']; supplied=v.get('event_digest')
            if not isinstance(sequence,int) or isinstance(sequence,bool) or sequence<1: raise LineageError('invalid sequence')
            if not isinstance(prev,str) or len(prev)!=64 or any(c not in '0123456789abcdef' for c in prev): raise LineageError('invalid previous digest')
            if supplied is not None and (not isinstance(supplied,str) or not _DIGEST(supplied)): raise LineageError('invalid event digest')
        return cls(schema,v['event_id'],v['route_id'],v['parent_event_id'],v['receipt_id'],v['status'],v['target_agent_id'],v['provider'],tuple(sorted(v['capabilities'])),v['deadline_at'],v['payload_digest'],v['decision_fingerprint'],v['retryable'],sequence,prev,supplied)

    def _payload(self):
        return {'schema_version':self.schema_version,'event_id':self.event_id,'route_id':self.route_id,'parent_event_id':self.parent_event_id,'receipt_id':self.receipt_id,'status':self.status,'target_agent_id':self.target_agent_id,'provider':self.provider,'capabilities':list(self.capabilities),'deadline_at':self.deadline_at,'payload_digest':self.payload_digest,'decision_fingerprint':self.decision_fingerprint,'retryable':self.retryable, **({'sequence':self.sequence,'prev_event_digest':self.prev_event_digest} if self.schema_version==INTEGRITY_SCHEMA else {})}
    @property
    def event_digest(self):
        if self.schema_version!=INTEGRITY_SCHEMA: return None
        return "sha256:"+hashlib.sha256(json.dumps(self._payload(),ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    def to_dict(self):
        value=self._payload()
        if self.schema_version==INTEGRITY_SCHEMA: value['event_digest']=self.event_digest
        return value
    def canonical(self): return json.dumps(self.to_dict(),ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()

class LineageGraph:
    _migrations=MigrationRegistry()
    def __init__(self,path:Path|str|None=None): self.path=Path(path) if path else None; self.events:dict[str,RouteLineageEvent]={}
    @classmethod
    def migrations(cls): return cls._migrations
    def append(self,e:RouteLineageEvent):
        if e.event_id in self.events: raise LineageError('duplicate event_id')
        if e.schema_version==INTEGRITY_SCHEMA:
            expected=len(self.events)+1; expected_prev=ZERO_DIGEST if expected==1 else self.events[next(reversed(self.events))].event_digest.removeprefix('sha256:')
            if e.sequence!=expected or e.prev_event_digest!=expected_prev: raise LineageError('sequence or previous digest mismatch')
            if e.supplied_event_digest is not None and e.supplied_event_digest!=e.event_digest: raise LineageError('event digest mismatch')
        if e.parent_event_id:
            p=self.events.get(e.parent_event_id)
            if p is None or p.route_id!=e.route_id: raise LineageError('parent lineage mismatch')
            allowed={'planned':{'dispatched','superseded'},'dispatched':{'succeeded','failed'},'failed':{'replayed','planned'},'succeeded':{'replayed','superseded'},'replayed':set(),'superseded':set()}
            if e.status not in allowed.get(p.status,set()): raise LineageError('illegal lifecycle transition')
        self.events[e.event_id]=e
        if self.path:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            with self.path.open('ab') as f: f.write(e.canonical()+b'\n'); f.flush(); os.fsync(f.fileno())
        return e
    def read(self)->Iterator[RouteLineageEvent]: return iter(self.events.values())
    @classmethod
    def from_path(cls,path:Path|str):
        graph=cls(None); path=Path(path)
        if not path.exists():
            graph.path=path
            return graph
        with path.open('rb') as handle:
            for raw in handle:
                if not raw.endswith(b'\n'): continue
                try: graph.append(RouteLineageEvent.from_dict(json.loads(raw.decode('utf-8'))))
                except (UnicodeDecodeError,json.JSONDecodeError,ValueError) as exc: raise LineageError('lineage history is corrupt') from exc
        return graph

def derive_retry(parent:RouteLineageEvent,*,event_id:str,receipt_id:str,deadline_at:int,capabilities:list[str])->RouteLineageEvent:
    if parent.status!='failed' or not parent.retryable: raise LineageError('parent is not retryable')
    if deadline_at>parent.deadline_at or not set(capabilities).issubset(parent.capabilities): raise LineageError('retry widens deadline/capabilities')
    return RouteLineageEvent(parent.schema_version,event_id,parent.route_id,parent.event_id,receipt_id,'planned',parent.target_agent_id,parent.provider,tuple(sorted(capabilities)),deadline_at,parent.payload_digest,parent.decision_fingerprint,False)

def causal_chain(graph:LineageGraph,terminal_event_id:str)->tuple[RouteLineageEvent,...]:
    out=[]; seen=set(); current=terminal_event_id
    while current:
        if current in seen: raise LineageError('lineage cycle')
        seen.add(current); e=graph.events.get(current)
        if e is None: raise LineageError('missing lineage event')
        out.append(e); current=e.parent_event_id
    return tuple(reversed(out))

from dataclasses import dataclass as _dataclass

@_dataclass(frozen=True)
class VerificationResult:
    verdict: Literal["verified", "failed", "unknown"]
    reasons: tuple[str, ...]

def verify_lineage(graph: LineageGraph, *, route_record: dict[str, Any], handoff: dict[str, Any], max_events: int = 256) -> VerificationResult:
    events = list(graph.read())
    if not events or len(events) > max_events:
        return VerificationResult("unknown", ("lineage is missing or too large",))
    terminal = events[-1]
    reasons: list[str] = []
    if route_record.get("selected_agent_id") != handoff.get("target_agent_id"):
        reasons.append("handoff mismatches route identity")
    if route_record.get("selected_provider") != handoff.get("provider"):
        reasons.append("handoff mismatches route provider")
    if route_record.get("decision_fingerprint") != handoff.get("decision_fingerprint"):
        reasons.append("handoff mismatches decision fingerprint")
    if route_record.get("payload_digest") != handoff.get("payload_digest"):
        reasons.append("handoff mismatches payload digest")
    if not isinstance(handoff.get("deadline_at"), int) or handoff["deadline_at"] > route_record.get("deadline_at", -1):
        reasons.append("handoff deadline is wider than route")
    if terminal.status == "failed":
        return VerificationResult("failed", ("terminal receipt failed",))
    if terminal.status != "succeeded":
        return VerificationResult("unknown", ("lineage has no successful terminal receipt",))
    if terminal.target_agent_id != handoff.get("target_agent_id") or terminal.provider != handoff.get("provider"):
        reasons.append("terminal identity mismatch")
    if terminal.deadline_at > handoff.get("deadline_at", -1):
        reasons.append("terminal deadline is wider than handoff")
    if not set(terminal.capabilities).issubset(set(handoff.get("capabilities", []))):
        reasons.append("terminal capabilities exceed handoff")
    return VerificationResult("unknown" if reasons else "verified", tuple(reasons))


def from_migrated_path(cls, path: Path | str, *, target_schema: str = INTEGRITY_SCHEMA,
                       target_path: Path | str | None = None):
    """Read old lineage history through migration without overwriting source."""
    source = Path(path)
    destination = Path(target_path) if target_path is not None else None
    graph = cls(destination)
    if not source.exists():
        graph.path = destination
        return graph
    with source.open('rb') as handle:
        for raw in handle:
            if not raw.endswith(b'\n'):
                continue
            try:
                value = json.loads(raw.decode('utf-8'))
                if value.get('schema_version') != target_schema:
                    value, _ = cls.migrations().migrate(value, target_version=target_schema)
                graph.append(RouteLineageEvent.from_dict(value))
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise LineageError('lineage migration/recovery failed') from exc
    return graph

LineageGraph.from_migrated_path = classmethod(from_migrated_path)
