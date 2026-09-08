"""Strict, deterministic NDJSON audit projection for route evidence."""
from __future__ import annotations
import hashlib,json,os
from dataclasses import dataclass
from pathlib import Path
from typing import Any,Iterable
class AuditExportError(ValueError): pass
_ALLOWED={'schema_version','sequence','prev_event_digest','event_digest','event_id','route_id','receipt_id','status','target_agent_id','provider','capabilities','failure_class','policy_revision','decision_fingerprint','payload_digest','deadline_at','retryable','verdict','reason','attempt','parent_event_id'}
_FORBIDDEN={'prompt','raw_output','secret','token','password','api_key','context','opaque_context'}
def sanitize_event(value:Any)->dict[str,Any]:
    if not isinstance(value,dict): raise AuditExportError('event must be object')
    if set(value)&_FORBIDDEN or any(any(x in str(k).lower() for x in ('prompt','secret','token','password','context','output')) for k in value): raise AuditExportError('sensitive field in audit event')
    unknown=set(value)-_ALLOWED
    if unknown: raise AuditExportError('unknown audit fields')
    out={k:value[k] for k in sorted(value)}
    if not all(isinstance(k,str) for k in out): raise AuditExportError('invalid audit keys')
    return out
@dataclass(frozen=True)
class AuditManifest:
    schema_version:str; line_count:int; digest:str
    def to_dict(self): return {'schema_version':self.schema_version,'line_count':self.line_count,'digest':self.digest}
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!={'schema_version','line_count','digest'}: raise AuditExportError('manifest fields invalid')
        if v['schema_version']!='northstar.audit-export.v1' or not isinstance(v['line_count'],int) or not isinstance(v['digest'],str): raise AuditExportError('manifest invalid')
        return cls(v['schema_version'],v['line_count'],v['digest'])
def _line(value): return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n'
def export_ndjson(events:Iterable[Any],path:Path|str)->AuditManifest:
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True); lines=[_line(sanitize_event(e)) for e in events]; payload=''.join(lines).encode()
    with path.open('wb') as f: f.write(payload); f.flush(); os.fsync(f.fileno())
    os.chmod(path,0o600)
    return AuditManifest('northstar.audit-export.v1',len(lines),'sha256:'+hashlib.sha256(payload).hexdigest())
def verify_export(path:Path|str,manifest:AuditManifest)->None:
    path=Path(path); payload=path.read_bytes(); lines=payload.splitlines()
    if len(lines)!=manifest.line_count or 'sha256:'+hashlib.sha256(payload).hexdigest()!=manifest.digest: raise AuditExportError('audit manifest mismatch')
    for line in lines:
        try: sanitize_event(json.loads(line))
        except (json.JSONDecodeError,AuditExportError) as exc: raise AuditExportError('audit line invalid') from exc
