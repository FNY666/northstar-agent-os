"""Restricted Codex sidecar: strict request protocol plus optional stdio runner."""
from __future__ import annotations
import json, os, re, signal, subprocess, sys
from dataclasses import dataclass
from typing import Any

MAX_PROMPT_CHARS=100_000
MIN_TIMEOUT_MS=1_000
MAX_TIMEOUT_MS=300_000
FALLBACK_STATUSES={"transport_unavailable","timeout"}
CODEX_BIN=os.environ.get("CODEX_BIN","codex")
# CODEX_HOME is Codex's own config/auth directory. It is passed to the child
# verbatim: the sidecar never appends to it, so a host that sets it explicitly
# gets exactly the directory it asked for and no double-nested path.
CODEX_HOME=os.environ.get("CODEX_HOME","/var/lib/northstar-codex/codex-home")
# Deliberately not derived from CODEX_HOME: the workspace holds run inputs,
# while CODEX_HOME holds credentials, and they should not share a directory.
CODEX_WORKSPACE=os.environ.get("CODEX_WORKSPACE","/var/lib/northstar-codex/workspace")
SENSITIVE_PATTERNS=(
 re.compile(r"(?:sk|rk)-[A-Za-z0-9_-]{16,}",re.I),
 re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?",re.I),
 re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
 re.compile(r"(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*\S+",re.I),
 re.compile(r"authorization\s*:\s*bearer\s+\S+",re.I),)
@dataclass(frozen=True)
class Validation:
 ok: bool
 errors: tuple[str,...]=()

def _walk(value:Any):
 if isinstance(value,dict):
  for k,v in value.items(): yield str(k); yield from _walk(v)
 elif isinstance(value,(list,tuple)):
  for v in value: yield from _walk(v)
 elif value is not None: yield str(value)
def _text(value:Any)->str: return "\n".join(_walk(value))
def estimate_tokens(value:Any)->int:
 raw=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":")); return max(1,(len(raw)+3)//4)
def scan_sensitive(value:Any)->bool: return any(p.search(_text(value)) for p in SENSITIVE_PATTERNS)
def fallback_allowed(status:str)->bool:
 return status in FALLBACK_STATUSES

def classify_request(request:Any)->Validation:
 errors=[]
 if not isinstance(request,dict): return Validation(False,("request must be an object",))
 unknown=sorted(set(request)-{"request_id","prompt","timeout_ms"})
 if unknown: errors.append(f"unknown request fields: {', '.join(unknown)}")
 rid=request.get("request_id"); prompt=request.get("prompt"); timeout=request.get("timeout_ms")
 if not isinstance(rid,str) or not rid.strip(): errors.append("request_id must be a non-empty string")
 elif len(rid)>128: errors.append("request_id is too long")
 if not isinstance(prompt,str) or not prompt.strip(): errors.append("prompt must be a non-empty string")
 elif len(prompt)>MAX_PROMPT_CHARS: errors.append("prompt exceeds maximum size")
 if not isinstance(timeout,int) or isinstance(timeout,bool): errors.append("timeout_ms must be an integer")
 elif not MIN_TIMEOUT_MS<=timeout<=MAX_TIMEOUT_MS: errors.append("timeout_ms is outside the permitted range")
 return Validation(not errors,tuple(errors))
def parse_codex_event(line:str)->dict[str,str]|None:
 try: event=json.loads(line)
 except (TypeError,json.JSONDecodeError): return None
 item=event.get("item") if isinstance(event,dict) and event.get("type")=="item.completed" else None
 if not isinstance(item,dict) or item.get("type")!="agent_message" or not isinstance(item.get("text"),str): return None
 return {"type":"text","text":item["text"]}
def redact_error(value:str)->str:
 value=re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+",r"\1[REDACTED]",value)
 value=re.sub(r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|password)\s*[:=]\s*[^\s,;]+",r"\1=[REDACTED]",value)
 return re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?","[REDACTED_JWT]",value)
def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
 try:
  if proc.stdin: proc.stdin.close()
 except (OSError, ValueError): pass
 try:
  if proc.stdout: proc.stdout.close()
  if proc.stderr: proc.stderr.close()
 except (OSError, ValueError): pass
 try:
  os.killpg(proc.pid, signal.SIGTERM)
 except (ProcessLookupError, PermissionError, OSError):
  try: proc.kill()
  except (ProcessLookupError, OSError): pass
 try: proc.wait(timeout=2)
 except subprocess.TimeoutExpired:
  try: os.killpg(proc.pid, signal.SIGKILL)
  except (ProcessLookupError, PermissionError, OSError):
   try: proc.kill()
   except (ProcessLookupError, OSError): pass
  try: proc.wait(timeout=2)
  except subprocess.TimeoutExpired: pass

def run_one(request:object)->dict:
 checked=classify_request(request)
 if not checked.ok: return {"request_id":request.get("request_id") if isinstance(request,dict) else None,"status":"rejected","errors":list(checked.errors)}
 assert isinstance(request,dict)
 try:
  proc=subprocess.Popen([CODEX_BIN,"exec","--json","--ephemeral","--sandbox","read-only","--skip-git-repo-check","--cd",CODEX_WORKSPACE,"-"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=CODEX_WORKSPACE,env={"HOME":CODEX_HOME,"CODEX_HOME":CODEX_HOME,"PATH":os.environ.get("PATH","/usr/bin:/bin")},text=True,start_new_session=True)
  out,err=proc.communicate(request["prompt"],timeout=request["timeout_ms"]/1000)
 except subprocess.TimeoutExpired:
  _terminate_process_tree(proc); return {"request_id":request["request_id"],"status":"timeout"}
 except (OSError, ValueError) as error:
  return {"request_id":request["request_id"],"status":"internal_error","error":redact_error(str(error))}
 if proc.returncode!=0: return {"request_id":request["request_id"],"status":"codex_error","error":redact_error(err.strip() or f"exit {proc.returncode}")}
 text="".join(e["text"] for line in out.splitlines() if (e:=parse_codex_event(line)))
 if not text: return {"request_id":request["request_id"],"status":"protocol_error","error":"Codex completed without an agent message"}
 return {"request_id":request["request_id"],"status":"ok","text":text}
def main()->int:
 for line in sys.stdin:
  try: result=run_one(json.loads(line))
  except (json.JSONDecodeError,TypeError): result={"request_id":None,"status":"rejected","errors":["invalid JSON request"]}
  print(json.dumps(result,ensure_ascii=False),flush=True)
 return 0
if __name__=="__main__": raise SystemExit(main())
