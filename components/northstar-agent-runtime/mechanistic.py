"""Causal circuit-tracing and ablation bookkeeping for mechanistic interpretability.

Research context (mechanistic interpretability): after a probe says a
concept is *correlated* with activations (see ``interpretability_probe``
for that layer), the causal question is asked with *circuits* and
*ablations* -- the IOI-circuit / induction-head / Othello-GPT line of
work. A circuit is a claimed computational subgraph (nodes such as
attention heads and MLP blocks, wired by edges) that a task routes
through; an ablation zeroes (or scrambles) a set of nodes and books the
host-observed change in task behavior.

This module provides a minimal, honest, deterministic *ledger* of those
declared decisions:

* ``circuit(circuit_id, spec, seq)`` -- declare one circuit:
  frozen ``CircuitRecord`` pinning the node/edge graph (acyclic,
  validated) for a named task.
* ``trace(circuit_id, seq)`` -- pure read view: frozen ``TraceReport``
  with the deterministic topological evaluation order of the circuit.
* ``ablate(circuit_id, ablation_id, node_ids, seq, effect_score=None,
  verdict="declared")`` -- book one declared ablation intervention:
  frozen ``AblationRecord``. The host-reported effect is data, never a
  causal claim.

House rules: frozen dataclasses, caller-supplied strictly increasing int
seqs, no wall-clock, RLock-guarded, fail-closed, stdlib-only,
``sha256:`` digest pins, ``audit.ndjson/1`` events. Failed mutations
consume their seq and book a ``mechanistic.rejected`` row; seq rewinds
raise bare without consuming.

Honest scope:

* This module books *declared* circuits, traces, and interventions. A
  digest pin proves ledger integrity -- it does not prove a circuit is
  faithful to any real model, and it does not prove an ablation effect
  is causal.
* ``effect_score`` / ``verdict`` are host-reported GIGO: a booked
  ``task-broken`` verdict means the host reported the task broke, never
  that these nodes compute the task.
* Trace order is a deterministic topological walk of the *declared*
  graph (Kahn's algorithm, node-id tie-break) -- a reading aid, not a
  proof of information flow.
* Simulated: nothing here executes a model, mutates activations, or
  observes real behavior. Pair the booked records with actual
  experimental harness data before drawing conclusions.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
MECHANISTIC_VERSION = "mechanistic.v1"

#: Schema pin carried by records and audit events.
MECHANISTIC_SCHEMA = "northstar.mechanistic.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_CIRCUIT_REGISTERED = "circuit-registered"
KIND_ABLATION_BOOKED = "ablation-booked"
KIND_REJECTED = "rejected"
_KINDS = (KIND_CIRCUIT_REGISTERED, KIND_ABLATION_BOOKED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"value", "score", "effect", "effect_score", "payload", "raw",
     "data", "spec", "nodes", "edges"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned node-kind vocabulary.
_NODE_KINDS = frozenset(
    {"attention-head", "mlp", "embedding", "logit", "probe", "custom"})

#: Pinned ablation verdict vocabulary.
_VERDICTS = frozenset(
    {"task-broken", "task-intact", "effect-unknown", "declared"})


class MechanisticError(Exception):
    """Base error for the mechanistic circuit ledger (programming errors)."""


class BadCircuitError(MechanisticError):
    """Malformed circuit id, task name, or spec."""


class DuplicateCircuitError(MechanisticError):
    """A circuit id was declared twice."""


class UnknownCircuitError(MechanisticError):
    """Reference to a circuit id that was never declared."""


class BadNodeError(MechanisticError):
    """Malformed node declaration."""


class BadEdgeError(MechanisticError):
    """Malformed edge, unknown endpoint, self-loop, duplicate, or cycle."""


class BadAblationError(MechanisticError):
    """Malformed ablation id, node set, score, or verdict."""


class DuplicateAblationError(MechanisticError):
    """An ablation id was booked twice."""


class UnknownAblationError(MechanisticError):
    """Reference to an ablation id that was never booked."""


class SeqOrderError(MechanisticError):
    """Seq was malformed or not strictly increasing."""


class AuditKindError(MechanisticError):
    """Unknown audit kind or banned detail key."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, what: str) -> str:
    """Validate an identifier: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadCircuitError(f"{what} must be str, "
                              f"got {type(value).__name__}")
    if not value:
        raise BadCircuitError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadCircuitError(f"{what} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadCircuitError(f"{what} must not contain whitespace")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": MECHANISTIC_SCHEMA,
        "parts": list(parts),
    })


def _node_key(node_id: str, layer: int, kind: str) -> Tuple[str, int, str]:
    return (node_id, layer, kind)


def _check_node(raw: object) -> Tuple[str, int, str]:
    """Validate one node declaration -> (node_id, layer, kind)."""
    if not isinstance(raw, Mapping):
        raise BadNodeError(
            f"node must be a mapping, got {type(raw).__name__}")
    try:
        node_id = raw["node_id"]
        layer = raw["layer"]
        kind = raw["kind"]
    except KeyError as e:
        raise BadNodeError(f"node missing required key: {e}")
    if isinstance(node_id, bool) or not isinstance(node_id, str) \
            or not node_id:
        raise BadNodeError("node_id must be a non-empty str")
    if len(node_id) > _MAX_ID_LEN:
        raise BadNodeError(f"node_id too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in node_id):
        raise BadNodeError("node_id must not contain whitespace")
    if isinstance(layer, bool) or not isinstance(layer, int):
        raise BadNodeError(
            f"layer must be int, got {type(layer).__name__}")
    if layer < 0:
        raise BadNodeError(f"layer must be >= 0, got {layer}")
    if kind not in _NODE_KINDS:
        raise BadNodeError(
            f"kind must be one of {sorted(_NODE_KINDS)}, got {kind!r}")
    return _node_key(node_id, layer, kind)


def _check_effect_score(value: object) -> Optional[float]:
    """Validate an optional host-reported effect score in [0, 1]."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise BadAblationError("effect_score must not be bool")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise BadAblationError(
            f"effect_score must be float, got {type(value).__name__}")
    if not math.isfinite(value):
        raise BadAblationError(f"effect_score must be finite, got {value!r}")
    if not 0.0 <= value <= 1.0:
        raise BadAblationError(
            f"effect_score must be in [0, 1], got {value!r}")
    return value


def _topo_order(nodes: List[Tuple[str, int, str]],
                edges: List[Tuple[str, str]]) -> Tuple[str, ...]:
    """Kahn's algorithm with node-id tie-break; raises on cycles."""
    node_ids = sorted(n[0] for n in nodes)
    indeg: Dict[str, int] = {nid: 0 for nid in node_ids}
    succ: Dict[str, List[str]] = {nid: [] for nid in node_ids}
    for src, dst in edges:
        succ[src].append(dst)
        indeg[dst] += 1
    ready = sorted(nid for nid in node_ids if indeg[nid] == 0)
    order: List[str] = []
    while ready:
        nid = ready.pop(0)
        order.append(nid)
        for nxt in sorted(succ[nid]):
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                ready.append(nxt)
        ready.sort()
    if len(order) != len(node_ids):
        raise BadEdgeError("circuit graph must be acyclic")
    return tuple(order)


def mechanistic_audit_event(kind: str, detail: Dict[str, object],
                           seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the mechanistic ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": MECHANISTIC_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class CircuitRecord:
    """Frozen record of one declared circuit."""
    circuit_id: str
    task: str
    node_count: int
    edge_count: int
    seq: int
    digest: str

    def verify(self, task: str, nodes: List[Tuple[str, int, str]],
               edges: List[Tuple[str, str]]) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "circuit", self.circuit_id, task,
            [list(n) for n in nodes], [list(e) for e in edges], self.seq)


@dataclass(frozen=True)
class TraceReport:
    """Frozen pure-read view: deterministic evaluation order of a circuit."""
    circuit_id: str
    order: Tuple[str, ...]
    seq: int
    digest: str

    def verify(self, circuit_id: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("trace", circuit_id, list(self.order),
                                   self.seq)


@dataclass(frozen=True)
class AblationRecord:
    """Frozen record of one declared ablation intervention."""
    ablation_id: str
    circuit_id: str
    node_count: int
    verdict: str
    seq: int
    digest: str

    def verify(self, circuit_id: str, node_ids: List[str]) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("ablation", self.ablation_id, circuit_id,
                                   sorted(node_ids), self.verdict, self.seq)


class Mechanistic:
    """Deterministic circuit-tracing / ablation bookkeeping ledger.

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:`` digest
    pins plus ``audit.ndjson/1`` rows. No wall-clock, no randomness.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._circuits: Dict[str, CircuitRecord] = {}
        self._circuit_nodes: Dict[str, List[Tuple[str, int, str]]] = {}
        self._circuit_edges: Dict[str, List[Tuple[str, str]]] = {}
        self._ablations: Dict[str, AblationRecord] = {}
        self._last_seq = 0
        self._audit: list = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq: object) -> int:
        """Validate seq; rewinds raise bare (no consumption)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing "
                f"(last={self._last_seq}, got={seq})")
        return seq

    def _burn(self, seq: int, error: Exception) -> None:
        """Consume the seq, book a rejected row, then raise."""
        self._last_seq = seq
        self._audit.append(mechanistic_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        self._audit.append(mechanistic_audit_event(audit_kind, detail, seq))

    # -- mutations ----------------------------------------------------------

    def circuit(self, circuit_id: object, spec: object,
                seq: object) -> CircuitRecord:
        """Declare one circuit (task + acyclic node/edge graph).

        ``spec`` is a mapping with ``task`` (a declared task label),
        ``nodes`` (list of ``{"node_id", "layer", "kind"}`` mappings) and
        ``edges`` (list of ``{"from", "to"}`` mappings). Duplicate circuit
        ids are refused; ids are never recycled.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                circuit_id = _check_id(circuit_id, "circuit_id")
                if circuit_id in self._circuits:
                    raise DuplicateCircuitError(
                        f"circuit already declared: {circuit_id!r}")
                if not isinstance(spec, Mapping):
                    raise BadCircuitError(
                        f"spec must be a mapping, "
                        f"got {type(spec).__name__}")
                task = spec.get("task")
                if isinstance(task, bool) or not isinstance(task, str) \
                        or not task:
                    raise BadCircuitError(
                        "spec['task'] must be a non-empty str")
                if len(task) > _MAX_ID_LEN:
                    raise BadCircuitError(
                        f"task too long (>{_MAX_ID_LEN} chars)")
                raw_nodes = spec.get("nodes")
                if not isinstance(raw_nodes, (list, tuple)) or not raw_nodes:
                    raise BadCircuitError(
                        "spec['nodes'] must be a non-empty list")
                nodes: List[Tuple[str, int, str]] = [
                    _check_node(n) for n in raw_nodes]
                node_ids = [n[0] for n in nodes]
                if len(set(node_ids)) != len(node_ids):
                    raise BadNodeError("node ids must be unique")
                raw_edges = spec.get("edges")
                if not isinstance(raw_edges, (list, tuple)):
                    raise BadCircuitError(
                        "spec['edges'] must be a list")
                edges: List[Tuple[str, str]] = []
                seen: set = set()
                known = set(node_ids)
                for raw in raw_edges:
                    if not isinstance(raw, Mapping):
                        raise BadEdgeError(
                            f"edge must be a mapping, "
                            f"got {type(raw).__name__}")
                    try:
                        src = raw["from"]
                        dst = raw["to"]
                    except KeyError as e:
                        raise BadEdgeError(
                            f"edge missing required key: {e}")
                    if not isinstance(src, str) or not isinstance(dst, str):
                        raise BadEdgeError(
                            "edge endpoints must be str")
                    if src not in known:
                        raise BadEdgeError(
                            f"edge from unknown node: {src!r}")
                    if dst not in known:
                        raise BadEdgeError(
                            f"edge to unknown node: {dst!r}")
                    if src == dst:
                        raise BadEdgeError(
                            f"self-loop refused on {src!r}")
                    if (src, dst) in seen:
                        raise BadEdgeError(
                            f"duplicate edge {src!r} -> {dst!r}")
                    seen.add((src, dst))
                    edges.append((src, dst))
                _topo_order(nodes, edges)  # raises BadEdgeError on cycles
            except MechanisticError as e:
                self._burn(seq, e)
            rec = CircuitRecord(
                circuit_id=circuit_id, task=task,
                node_count=len(nodes), edge_count=len(edges), seq=seq,
                digest=_pin("circuit", circuit_id, task,
                            [list(n) for n in nodes],
                            [list(e) for e in edges], seq))
            self._circuits[circuit_id] = rec
            self._circuit_nodes[circuit_id] = nodes
            self._circuit_edges[circuit_id] = edges
            self._last_seq = seq
            self._emit(KIND_CIRCUIT_REGISTERED,
                       {"circuit_id": circuit_id, "task": task,
                        "node_count": len(nodes),
                        "edge_count": len(edges),
                        "digest": rec.digest}, seq)
            return rec

    def ablate(self, circuit_id: object, ablation_id: object,
               node_ids: object, seq: object,
               effect_score: object = None,
               verdict: object = "declared") -> AblationRecord:
        """Book one declared ablation intervention on a circuit's nodes.

        ``node_ids`` must name declared nodes of ``circuit_id``.
        ``effect_score`` (optional, [0, 1]) and ``verdict`` (pinned
        vocabulary) are host-reported data -- booked, never a causal
        claim. Duplicate ablation ids are refused; ids never recycled.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                circuit_id = _check_id(circuit_id, "circuit_id")
                if circuit_id not in self._circuits:
                    raise UnknownCircuitError(
                        f"unknown circuit: {circuit_id!r}")
                if isinstance(ablation_id, bool) \
                        or not isinstance(ablation_id, str) \
                        or not ablation_id:
                    raise BadAblationError(
                        "ablation_id must be a non-empty str")
                if len(ablation_id) > _MAX_ID_LEN:
                    raise BadAblationError(
                        f"ablation_id too long (>{_MAX_ID_LEN} chars)")
                if any(ch.isspace() for ch in ablation_id):
                    raise BadAblationError(
                        "ablation_id must not contain whitespace")
                if ablation_id in self._ablations:
                    raise DuplicateAblationError(
                        f"ablation already booked: {ablation_id!r}")
                if not isinstance(node_ids, (list, tuple)) or not node_ids:
                    raise BadAblationError(
                        "node_ids must be a non-empty list")
                names: List[str] = []
                for nid in node_ids:
                    if isinstance(nid, bool) or not isinstance(nid, str):
                        raise BadAblationError(
                            "node ids must be str")
                    names.append(nid)
                if len(set(names)) != len(names):
                    raise BadAblationError("node ids must be unique")
                known = {n[0] for n in self._circuit_nodes[circuit_id]}
                for nid in names:
                    if nid not in known:
                        raise BadAblationError(
                            f"ablation node not in circuit: {nid!r}")
                score = _check_effect_score(effect_score)
                if verdict not in _VERDICTS:
                    raise BadAblationError(
                        f"verdict must be one of {sorted(_VERDICTS)}, "
                        f"got {verdict!r}")
            except MechanisticError as e:
                self._burn(seq, e)
            rec = AblationRecord(
                ablation_id=ablation_id, circuit_id=circuit_id,
                node_count=len(names), verdict=verdict, seq=seq,
                digest=_pin("ablation", ablation_id, circuit_id,
                            sorted(names), verdict, seq))
            self._ablations[ablation_id] = rec
            self._last_seq = seq
            self._emit(KIND_ABLATION_BOOKED,
                       {"ablation_id": ablation_id,
                        "circuit_id": circuit_id,
                        "node_count": len(names),
                        "verdict": verdict,
                        "has_effect_score": score is not None,
                        "digest": rec.digest}, seq)
            return rec

    # -- pure reads ----------------------------------------------------------

    def trace(self, circuit_id: object, seq: object) -> TraceReport:
        """Pure read view: deterministic evaluation order of a circuit.

        Validates the seq shape but consumes nothing and writes no audit
        row.
        """
        with self._lock:
            _check_seq(seq)
            if isinstance(circuit_id, bool) \
                    or not isinstance(circuit_id, str):
                raise UnknownCircuitError(
                    f"circuit_id must be str, "
                    f"got {type(circuit_id).__name__}")
            if circuit_id not in self._circuits:
                raise UnknownCircuitError(
                    f"unknown circuit: {circuit_id!r}")
            order = _topo_order(self._circuit_nodes[circuit_id],
                                self._circuit_edges[circuit_id])
            return TraceReport(
                circuit_id=circuit_id, order=order, seq=seq,
                digest=_pin("trace", circuit_id, list(order), seq))

    def circuit_record(self, circuit_id: object,
                       seq: object) -> CircuitRecord:
        """Pure read view of one declared circuit."""
        with self._lock:
            _check_seq(seq)
            if not isinstance(circuit_id, str) \
                    or circuit_id not in self._circuits:
                raise UnknownCircuitError(
                    f"unknown circuit: {circuit_id!r}")
            return self._circuits[circuit_id]

    def ablation_record(self, ablation_id: object,
                        seq: object) -> AblationRecord:
        """Pure read view of one booked ablation."""
        with self._lock:
            _check_seq(seq)
            if not isinstance(ablation_id, str) \
                    or ablation_id not in self._ablations:
                raise UnknownAblationError(
                    f"unknown ablation: {ablation_id!r}")
            return self._ablations[ablation_id]

    def circuit_ids(self, seq: object) -> Tuple[str, ...]:
        """Pure read view of declared circuit ids, sorted."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._circuits))

    def stats(self, seq: object) -> Dict[str, int]:
        """Pure read view: ledger counts."""
        with self._lock:
            _check_seq(seq)
            return {
                "circuits": len(self._circuits),
                "ablations": len(self._ablations),
                "audit_rows": len(self._audit),
                "last_seq": self._last_seq,
            }

    def audit_log(self, seq: object) -> Tuple[Dict[str, object], ...]:
        """Pure read view of the audit rows booked so far."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check smoke run."""
    m = Mechanistic()
    rec = m.circuit("ioi", {
        "task": "indirect-object-identification",
        "nodes": [
            {"node_id": "emb", "layer": 0, "kind": "embedding"},
            {"node_id": "h3.5", "layer": 3, "kind": "attention-head"},
            {"node_id": "mlp4", "layer": 4, "kind": "mlp"},
            {"node_id": "logits", "layer": 12, "kind": "logit"},
        ],
        "edges": [
            {"from": "emb", "to": "h3.5"},
            {"from": "h3.5", "to": "mlp4"},
            {"from": "mlp4", "to": "logits"},
        ],
    }, 1)
    assert rec.verify("indirect-object-identification",
                      [("emb", 0, "embedding"),
                       ("h3.5", 3, "attention-head"),
                       ("mlp4", 4, "mlp"),
                       ("logits", 12, "logit")],
                      [("emb", "h3.5"), ("h3.5", "mlp4"),
                       ("mlp4", "logits")])
    tr = m.trace("ioi", 2)
    assert tr.order == ("emb", "h3.5", "mlp4", "logits"), tr.order
    ab = m.ablate("ioi", "abl-1", ["h3.5"], 3,
                  effect_score=0.9, verdict="task-broken")
    assert ab.verify("ioi", ["h3.5"])
    assert m.stats(4)["circuits"] == 1
    print("mechanistic OK: circuit, trace, ablate, pins, audit")


if __name__ == "__main__":
    main()
