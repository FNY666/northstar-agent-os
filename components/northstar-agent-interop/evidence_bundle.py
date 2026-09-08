"""Ordered Merkle commitments for sanitized route evidence."""
from __future__ import annotations
import hashlib,json,os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
SCHEMA='northstar.evidence-bundle.v1'
class EvidenceError(ValueError): pass
def _canonical(v): return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def _hash(prefix,v): return hashlib.sha256(prefix+v).hexdigest()
def _leaf(event):
    if not isinstance(event,dict): raise EvidenceError('event must be object')
    forbidden=('prompt','secret','token','password','context','raw_output','output')
    if any(any(x in str(k).lower() for x in forbidden) for k in event): raise EvidenceError('sensitive evidence')
    return bytes.fromhex(_hash(b'leaf\0',_canonical(event)))
def _root(leaves):
    if not leaves: raise EvidenceError('empty bundle')
    layer=list(leaves)
    while len(layer)>1:
        if len(layer)%2: layer.append(layer[-1])
        layer=[hashlib.sha256(b'node\0'+layer[i]+layer[i+1]).digest() for i in range(0,len(layer),2)]
    return 'sha256:'+layer[0].hex()
@dataclass(frozen=True)
class MerkleProof:
    index:int; leaf_count:int; siblings:tuple[tuple[str,str],...]
@dataclass(frozen=True)
class EvidenceBundle:
    root_digest:str; leaf_count:int; schema_version:str; leaf_digests:tuple[str,...]
    def to_dict(self): return {'schema_version':self.schema_version,'root_digest':self.root_digest,'leaf_count':self.leaf_count,'leaf_digests':list(self.leaf_digests)}
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!={'schema_version','root_digest','leaf_count','leaf_digests'} or v['schema_version']!=SCHEMA: raise EvidenceError('bundle fields invalid')
        if not isinstance(v['root_digest'],str) or not v['root_digest'].startswith('sha256:') or len(v['root_digest'])!=71: raise EvidenceError('bundle root invalid')
        if not isinstance(v['leaf_count'],int) or v['leaf_count']<1 or not isinstance(v['leaf_digests'],list) or len(v['leaf_digests'])!=v['leaf_count'] or not all(isinstance(x,str) and x.startswith('sha256:') and len(x)==71 for x in v['leaf_digests']): raise EvidenceError('bundle count/digests invalid')
        if cls(v['root_digest'],v['leaf_count'],v['schema_version'],tuple(v['leaf_digests'])).root_digest != _root([bytes.fromhex(x[7:]) for x in v['leaf_digests']]): raise EvidenceError('bundle root mismatch')
        return cls(v['root_digest'],v['leaf_count'],v['schema_version'],tuple(v['leaf_digests']))
def build_bundle(events):
    events=list(events); leaves=tuple('sha256:'+_leaf(e).hex() for e in events); return EvidenceBundle(_root([bytes.fromhex(x[7:]) for x in leaves]),len(leaves),SCHEMA,leaves)
def make_proof(bundle,index):
    if not 0<=index<bundle.leaf_count: raise EvidenceError('proof index invalid')
    layer=[bytes.fromhex(x[7:]) for x in bundle.leaf_digests]; siblings=[]; i=index
    while len(layer)>1:
        if len(layer)%2: layer.append(layer[-1])
        pair=i^1; siblings.append(('right' if i%2==0 else 'left', 'sha256:'+layer[pair].hex())); layer=[hashlib.sha256(b'node\0'+layer[j]+layer[j+1]).digest() for j in range(0,len(layer),2)]; i//=2
    return MerkleProof(index,bundle.leaf_count,tuple(siblings))
def verify_proof(bundle,event,proof):
    if proof.leaf_count!=bundle.leaf_count or not 0<=proof.index<bundle.leaf_count: raise EvidenceError('proof metadata mismatch')
    expected_depth=0; size=bundle.leaf_count
    while size>1: expected_depth+=1; size=(size+1)//2
    if len(proof.siblings)!=expected_depth: raise EvidenceError('proof path length mismatch')
    current=_leaf(event); i=proof.index
    for direction,digest in proof.siblings:
        if direction not in {'left','right'} or not isinstance(digest,str) or not digest.startswith('sha256:') or len(digest)!=71: raise EvidenceError('proof sibling invalid')
        sibling=bytes.fromhex(digest[7:])
        current=hashlib.sha256(b'node\0'+(current+sibling if direction=='right' else sibling+current)).digest(); i//=2
    if 'sha256:'+current.hex()!=bundle.root_digest: raise EvidenceError('proof root mismatch')

def write_bundle(bundle:EvidenceBundle,path:Path|str)->None:
    if not isinstance(bundle,EvidenceBundle): raise EvidenceError('bundle type invalid')
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('wb') as f: f.write(_canonical(bundle.to_dict())); f.flush(); os.fsync(f.fileno())
    os.chmod(path,0o600)

def read_bundle(path:Path|str)->EvidenceBundle:
    try: return EvidenceBundle.from_dict(json.loads(Path(path).read_text(encoding='utf-8')))
    except (OSError,json.JSONDecodeError,EvidenceError) as exc: raise EvidenceError('bundle file invalid') from exc
