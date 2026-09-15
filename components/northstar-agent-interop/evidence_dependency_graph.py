"""Claim dependency graphs and replayable evidence-state derivations."""
from __future__ import annotations
import hashlib,json,re
from dataclasses import dataclass
from typing import Any,Iterable,Mapping
from evidence_state_projection import ClaimProjection,ProjectionError

SCHEMA='northstar.evidence-dependency-graph.v1'
WITNESS_SCHEMA='northstar.evidence-dependency-graph-witness.v1'
_DIGEST=re.compile(r'^sha256:[0-9a-f]{64}$')
_NODE_FIELDS=frozenset({'claim_digest','requires'})
_GRAPH_FIELDS=frozenset({'schema_version','nodes','graph_digest'})
_PROJ_FIELDS=frozenset({'schema_version','claim_digest','direct_state','state','requires','blocked_dependencies','unknown_dependencies','reasons','unverified','actionable'})
_WITNESS_FIELDS=frozenset({'schema_version','graph','graph_digest','direct_projections','projections','witness_digest'})
_DIRECT_STATES=frozenset({'supported','conflicted','insufficient','unverifiable','unknown'})

class DependencyGraphError(ValueError): pass

@dataclass(frozen=True)
class ClaimDependency:
    claim_digest:str; requires:tuple[str,...]
    def to_dict(self): return {'claim_digest':self.claim_digest,'requires':list(self.requires)}
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_NODE_FIELDS: raise DependencyGraphError('dependency node fields invalid')
        claim=_digest(v['claim_digest'],'claim_digest'); req=_digests(v['requires'],'requires')
        if claim in req: raise DependencyGraphError('self dependency invalid')
        return cls(claim,req)

@dataclass(frozen=True)
class EvidenceDependencyGraph:
    schema_version:str; nodes:tuple[ClaimDependency,...]
    def __post_init__(self):
        if self.schema_version!=SCHEMA: raise DependencyGraphError('graph schema invalid')
        if not isinstance(self.nodes,tuple) or not self.nodes: raise DependencyGraphError('graph nodes invalid')
        nodes=tuple(ClaimDependency.from_dict(x.to_dict()) for x in self.nodes)
        if len({x.claim_digest for x in nodes})!=len(nodes): raise DependencyGraphError('duplicate graph nodes')
        nodes=tuple(sorted(nodes,key=lambda x:x.claim_digest)); claims={x.claim_digest for x in nodes}
        if any(any(dep not in claims for dep in node.requires) for node in nodes): raise DependencyGraphError('undeclared dependency')
        if _has_cycle(nodes): raise DependencyGraphError('dependency cycle')
        object.__setattr__(self,'nodes',nodes)
    @property
    def graph_digest(self): return _hash(b'northstar.evidence-dependency-graph.v1\0',self.unsigned_dict())
    def unsigned_dict(self): return {'schema_version':self.schema_version,'nodes':[x.to_dict() for x in self.nodes]}
    def to_dict(self): return {**self.unsigned_dict(),'graph_digest':self.graph_digest}
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_GRAPH_FIELDS or v['schema_version']!=SCHEMA: raise DependencyGraphError('graph fields invalid')
        if not isinstance(v['nodes'],list) or not v['nodes']: raise DependencyGraphError('graph nodes invalid')
        nodes=tuple(ClaimDependency.from_dict(x) for x in v['nodes'])
        if [x.claim_digest for x in nodes]!=sorted(x.claim_digest for x in nodes): raise DependencyGraphError('graph nodes not canonical')
        result=cls(SCHEMA,nodes)
        if _digest(v['graph_digest'],'graph_digest')!=result.graph_digest: raise DependencyGraphError('graph digest mismatch')
        return result

@dataclass(frozen=True)
class DependencyProjection:
    schema_version:str; claim_digest:str; direct_state:str; state:str; requires:tuple[str,...]; blocked_dependencies:tuple[str,...]; unknown_dependencies:tuple[str,...]; reasons:tuple[str,...]; unverified:tuple[str,...]; actionable:bool
    def to_dict(self): return {'schema_version':self.schema_version,'claim_digest':self.claim_digest,'direct_state':self.direct_state,'state':self.state,'requires':list(self.requires),'blocked_dependencies':list(self.blocked_dependencies),'unknown_dependencies':list(self.unknown_dependencies),'reasons':list(self.reasons),'unverified':list(self.unverified),'actionable':self.actionable}
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_PROJ_FIELDS or v['schema_version']!=SCHEMA: raise DependencyGraphError('dependency projection fields invalid')
        claim=_digest(v['claim_digest'],'claim_digest')
        if v['direct_state'] not in _DIRECT_STATES or v['state'] not in _DIRECT_STATES|{'blocked'}: raise DependencyGraphError('dependency projection state invalid')
        requires=_digests(v['requires'],'requires'); blocked=_digests(v['blocked_dependencies'],'blocked_dependencies'); unknown=_digests(v['unknown_dependencies'],'unknown_dependencies')
        reasons=_strings(v['reasons'],'reasons'); unresolved=_strings(v['unverified'],'unverified')
        if not isinstance(v['actionable'],bool) or v['actionable']: raise DependencyGraphError('dependency projection cannot authorize')
        return cls(SCHEMA,claim,v['direct_state'],v['state'],requires,blocked,unknown,reasons,unresolved,False)

@dataclass(frozen=True)
class DependencyGraphWitness:
    schema_version:str; graph:dict[str,Any]; graph_digest:str; direct_projections:tuple[dict[str,Any],...]; projections:tuple[dict[str,Any],...]; witness_digest:str
    def unsigned_dict(self): return {'schema_version':self.schema_version,'graph':self.graph,'graph_digest':self.graph_digest,'direct_projections':list(self.direct_projections),'projections':list(self.projections)}
    def to_dict(self): return {**self.unsigned_dict(),'witness_digest':self.witness_digest}
    @property
    def computed_digest(self): return _hash(b'northstar.evidence-dependency-graph-witness.v1\0',self.unsigned_dict())
    @classmethod
    def from_dict(cls,v):
        if not isinstance(v,dict) or set(v)!=_WITNESS_FIELDS or v['schema_version']!=WITNESS_SCHEMA: raise DependencyGraphError('graph witness fields invalid')
        graph=EvidenceDependencyGraph.from_dict(v['graph'])
        if _digest(v['graph_digest'],'graph_digest')!=graph.graph_digest: raise DependencyGraphError('witness graph digest mismatch')
        direct=_source_projections(v['direct_projections']); derived=_derived_projections(v['projections'])
        if set(derived)!= {x.claim_digest for x in graph.nodes}: raise DependencyGraphError('witness projection coverage invalid')
        digest=_digest(v['witness_digest'],'witness_digest')
        result=cls(WITNESS_SCHEMA,graph.to_dict(),graph.graph_digest,tuple(x.to_dict() for x in direct.values()),tuple(x.to_dict() for x in derived.values()),digest)
        if result.computed_digest!=digest: raise DependencyGraphError('graph witness digest mismatch')
        return result

@dataclass(frozen=True)
class GraphWitnessVerdict:
    state:str; reasons:tuple[str,...]=(); unverified:tuple[str,...]=(); actionable:bool=False; witness_digest:str=''

def _canonical(v):
    try:return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    except (TypeError,ValueError) as e: raise DependencyGraphError('value not canonical JSON') from e
def _hash(prefix,v): return 'sha256:'+hashlib.sha256(prefix+_canonical(v)).hexdigest()
def _digest(v,field):
    if not isinstance(v,str) or _DIGEST.fullmatch(v) is None: raise DependencyGraphError(f'{field} invalid')
    return v
def _digests(v,field):
    if not isinstance(v,list) or len(set(v))!=len(v) or v!=sorted(v): raise DependencyGraphError(f'{field} invalid')
    return tuple(_digest(x,field) for x in v)
def _strings(v,field):
    if not isinstance(v,list) or len(set(v))!=len(v) or v!=sorted(v) or not all(isinstance(x,str) and x for x in v): raise DependencyGraphError(f'{field} invalid')
    return tuple(v)
def _has_cycle(nodes):
    edges={n.claim_digest:set(n.requires) for n in nodes}; visiting=set();done=set()
    def visit(n):
        if n in visiting:return True
        if n in done:return False
        visiting.add(n); result=any(visit(x) for x in edges[n]); visiting.remove(n);done.add(n);return result
    return any(visit(n) for n in edges)
def _graph(g):
    try:return EvidenceDependencyGraph.from_dict(g.to_dict())
    except (AttributeError,DependencyGraphError) as e: raise DependencyGraphError('graph invalid') from e
def _source_projections(values):
    if not isinstance(values,list): raise DependencyGraphError('direct projections invalid')
    out={}
    for raw in values:
        try:p=ClaimProjection.from_dict(raw)
        except ProjectionError as e: raise DependencyGraphError('direct projection invalid') from e
        if p.claim_digest in out: raise DependencyGraphError('duplicate direct projection')
        out[p.claim_digest]=p
    if list(out)!=sorted(out): raise DependencyGraphError('direct projections not canonical')
    return out
def _derived_projections(values):
    if not isinstance(values,list): raise DependencyGraphError('derived projections invalid')
    out={}
    for raw in values:
        p=DependencyProjection.from_dict(raw)
        if p.claim_digest in out: raise DependencyGraphError('duplicate derived projection')
        out[p.claim_digest]=p
    if list(out)!=sorted(out): raise DependencyGraphError('derived projections not canonical')
    return out
def _input_projections(values):
    if not isinstance(values,Mapping): raise DependencyGraphError('direct projections invalid')
    out={}
    for claim,value in values.items():
        _digest(claim,'direct claim')
        try:p=ClaimProjection.from_dict(value.to_dict())
        except (AttributeError,ProjectionError) as e: raise DependencyGraphError('direct projection invalid') from e
        if p.claim_digest!=claim: raise DependencyGraphError('direct projection mapping mismatch')
        out[claim]=p
    return out

def project_dependencies(graph:EvidenceDependencyGraph,direct_projections:Mapping[str,ClaimProjection])->dict[str,DependencyProjection]:
    g=_graph(graph); direct=_input_projections(direct_projections); result={}
    def derive(claim):
        if claim in result:return result[claim]
        node=next(x for x in g.nodes if x.claim_digest==claim); source=direct.get(claim)
        direct_state='unknown' if source is None else source.state
        dependencies=[derive(dep) for dep in node.requires]
        unresolved=[] if source is None else list(source.unverified)
        for dep in dependencies: unresolved.extend(dep.unverified)
        reasons=[]; blocked=[];unknown=[]
        if source is None:
            unknown.append(claim);reasons.append('missing_direct_projection');state='unknown'
        elif source.state in {'conflicted','insufficient','unverifiable'}:
            reasons.append('direct_state:'+source.state);state=source.state
        elif source.state=='unknown':
            unknown.append(claim);reasons.append('direct_state:unknown');state='unknown'
        else: state='supported'
        for dep in dependencies:
            if dep.state in {'blocked','conflicted','insufficient','unverifiable'}:
                blocked.append(dep.claim_digest);reasons.append('blocked_dependency:'+dep.state)
            elif dep.state=='unknown':
                unknown.append(dep.claim_digest);reasons.append('unknown_dependency');reasons.extend(dep.reasons)
        if blocked: state='blocked'
        elif unknown and state=='supported': state='unknown'
        projection=DependencyProjection(SCHEMA,claim,direct_state,state,node.requires,tuple(sorted(set(blocked))),tuple(sorted(set(unknown))),tuple(sorted(set(reasons))),tuple(sorted(set(unresolved))),False)
        result[claim]=projection;return projection
    for node in g.nodes:derive(node.claim_digest)
    return dict(sorted(result.items()))

def make_dependency_graph(nodes:Iterable[ClaimDependency])->EvidenceDependencyGraph:
    try: parsed=tuple(ClaimDependency.from_dict(x.to_dict()) for x in nodes)
    except (AttributeError,DependencyGraphError) as e: raise DependencyGraphError('dependency nodes invalid') from e
    return EvidenceDependencyGraph(SCHEMA,parsed)
def make_graph_witness(graph:EvidenceDependencyGraph,direct_projections:Mapping[str,ClaimProjection])->DependencyGraphWitness:
    g=_graph(graph); direct=_input_projections(direct_projections); derived=project_dependencies(g,direct)
    unsigned=DependencyGraphWitness(WITNESS_SCHEMA,g.to_dict(),g.graph_digest,tuple(p.to_dict() for _,p in sorted(direct.items())),tuple(p.to_dict() for _,p in sorted(derived.items())),'')
    return DependencyGraphWitness(unsigned.schema_version,unsigned.graph,unsigned.graph_digest,unsigned.direct_projections,unsigned.projections,unsigned.computed_digest)
def verify_graph_witness(witness:DependencyGraphWitness,graph:EvidenceDependencyGraph,direct_projections:Mapping[str,ClaimProjection],*,expected_digest:str|None=None)->GraphWitnessVerdict:
    if not isinstance(witness,DependencyGraphWitness): raise DependencyGraphError('graph witness invalid')
    parsed=DependencyGraphWitness.from_dict(witness.to_dict());g=_graph(graph);direct=_input_projections(direct_projections)
    if parsed.graph!=g.to_dict() or parsed.graph_digest!=g.graph_digest: raise DependencyGraphError('graph witness graph mismatch')
    if expected_digest is not None and _digest(expected_digest,'expected_digest')!=parsed.witness_digest: raise DependencyGraphError('external graph witness digest mismatch')
    derived=project_dependencies(g,direct)
    if tuple(p.to_dict() for _,p in sorted(direct.items()))!=parsed.direct_projections or tuple(p.to_dict() for _,p in sorted(derived.items()))!=parsed.projections: raise DependencyGraphError('graph witness replay mismatch')
    unresolved=[x for p in derived.values() for x in p.unverified]
    if expected_digest is None:unresolved.append('graph_witness_digest_unpinned')
    return GraphWitnessVerdict('graph-witness-verified' if expected_digest is not None else 'graph-witness-verified-unpinned',(),tuple(sorted(set(unresolved))),False,parsed.witness_digest)

__all__=['SCHEMA','WITNESS_SCHEMA','DependencyGraphError','ClaimDependency','EvidenceDependencyGraph','DependencyProjection','DependencyGraphWitness','GraphWitnessVerdict','make_dependency_graph','project_dependencies','make_graph_witness','verify_graph_witness']
