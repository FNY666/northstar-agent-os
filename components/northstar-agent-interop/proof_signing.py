"""HMAC signing for sanitized proof attestations with explicit key IDs."""
from __future__ import annotations
import base64,hmac,hashlib,json,re
from dataclasses import dataclass
from typing import Any,Callable
from evidence_proof import ProofAttestation
class ProofSignatureError(ValueError): pass
_ID=re.compile(r'^[A-Za-z0-9._:-]{1,64}$')
_DIGEST_RE=re.compile(r'^sha256:[0-9a-f]{64}$')
def _canonical(v): return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def _validate_secret(secret):
    if not isinstance(secret,(bytes,bytearray)) or len(secret)<16: raise ProofSignatureError('signing secret is too short')
@dataclass(frozen=True)
class SignedProofAttestation:
    schema_version:str; key_id:str; signature:str; attestation:dict[str,Any]
    def to_dict(self): return {'schema_version':self.schema_version,'key_id':self.key_id,'signature':self.signature,'attestation':self.attestation}
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!={'schema_version','key_id','signature','attestation'} or v['schema_version']!='northstar.signed-proof-attestation.v1' or not isinstance(v['key_id'],str) or not _ID.fullmatch(v['key_id']) or not isinstance(v['signature'],str) or not isinstance(v['attestation'],dict): raise ProofSignatureError('signed attestation fields invalid')
        expected={'schema_version','verdict','route_id','proof_digest','lineage_digest','bundle_root','checkpoint_root'}
        if set(v['attestation']) != expected or v['attestation'].get('schema_version')!='northstar.proof-attestation.v1' or v['attestation'].get('verdict')!='verified': raise ProofSignatureError('inner attestation fields invalid')
        if not isinstance(v['attestation'].get('route_id'),str) or not v['attestation']['route_id'] or any(not isinstance(v['attestation'].get(k),str) or _DIGEST_RE.fullmatch(v['attestation'][k]) is None for k in ('proof_digest','lineage_digest','bundle_root','checkpoint_root')): raise ProofSignatureError('inner attestation digests invalid')
        return cls(v['schema_version'],v['key_id'],v['signature'],dict(v['attestation']))
def sign_attestation(attestation:ProofAttestation,*,key_id:str,secret:bytes)->SignedProofAttestation:
    if not isinstance(attestation,ProofAttestation) or attestation.verdict!='verified' or not _ID.fullmatch(key_id): raise ProofSignatureError('only valid verified attestation can be signed')
    _validate_secret(secret); value=attestation.to_dict(); signature=base64.urlsafe_b64encode(hmac.new(bytes(secret),_canonical(value),hashlib.sha256).digest()).decode().rstrip('=')
    return SignedProofAttestation('northstar.signed-proof-attestation.v1',key_id,signature,value)
def verify_signed_attestation(signed:SignedProofAttestation,*,key_resolver:Callable[[str],bytes|None],expected_key_id:str|None=None)->ProofAttestation:
    if not isinstance(signed,SignedProofAttestation) or (expected_key_id is not None and signed.key_id!=expected_key_id): raise ProofSignatureError('key identity mismatch')
    try:
        secret=key_resolver(signed.key_id)
    except Exception as exc:
        raise ProofSignatureError('signing key resolver failed') from exc
    if secret is None: raise ProofSignatureError('signing key unavailable')
    _validate_secret(secret); expected=base64.urlsafe_b64encode(hmac.new(bytes(secret),_canonical(signed.attestation),hashlib.sha256).digest()).decode().rstrip('=')
    if not hmac.compare_digest(expected,signed.signature): raise ProofSignatureError('proof signature mismatch')
    try: return ProofAttestation(signed.attestation['schema_version'],signed.attestation['verdict'],signed.attestation['route_id'],signed.attestation['proof_digest'],signed.attestation['lineage_digest'],signed.attestation['bundle_root'],signed.attestation['checkpoint_root'])
    except (KeyError,TypeError) as exc: raise ProofSignatureError('attestation payload invalid') from exc
