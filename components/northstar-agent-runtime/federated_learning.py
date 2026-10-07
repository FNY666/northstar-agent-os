"""Federated learning: FedAvg aggregation bookkeeping.

Research motivation: federated learning trains a shared model without
moving raw data to a central server. Clients train locally and ship only
parameter updates; the server averages them. McMahan et al. (2017)
introduced FedAvg, where the global update is the example-count-weighted
average of client updates -- clients with more examples count more.

Public API:

- ``GlobalModel`` -- frozen record: ``round`` (int >= 0), ``params``
  (tuple of finite numbers), ``digest`` (``sha256:`` pin over the
  canonical body).
- ``ClientUpdate`` -- frozen record: ``client_id`` (non-empty str),
  ``round`` (int >= 0), ``num_examples`` (int > 0, the FedAvg weight),
  ``params`` (tuple of finite numbers, same dimension as the global
  model), ``digest`` (``sha256:`` pin over the canonical body).
- ``FederatedLearning`` -- coordinator state machine: ``broadcast(params,
  seq)`` mints the next-round ``GlobalModel``; ``aggregate(updates,
  seq)`` runs weighted FedAvg over one round's updates; ``round(updates,
  seq)`` aggregates and immediately broadcasts the result as the next
  global model.
- ``AggregationResult`` -- frozen record: ``round``, ``clients`` (sorted
  tuple of contributing client ids), ``total_examples``, ``weights``
  (per-client ``num_examples / total_examples``), ``params`` (the
  weighted average), ``digest``.
- ``federated_learning_audit_event(kind, seq, ...)`` -- shapes
  ``audit.ndjson/1`` records (``model-broadcast`` / ``updates-aggregated``
  / ``round-completed`` / ``rejected``).

Honest scope:

- This is the *aggregation state machine*, not a training framework: no
  client training loop, no data, no network, no transport. The host
  moves updates; straggler handling, timeouts, and client selection are
  the host's job (pair with ``timeout_manager``).
- The weighted average is exact arithmetic on *host-reported* numbers:
  garbage in, garbage out. A client can lie about its params, its
  example count, or both, and FedAvg will faithfully average the lies.
- This is **not** Byzantine-robust aggregation: it has no outlier
  rejection, no clipping, no median-based defense. For malicious-update
  detection pair with ``federated_attack_detector`` (batch 5), which
  scores updates before they reach this aggregator.
- Digest pins bind *content*, never *correctness*. A ``digest`` proves
  an update has not been modified in transit to the aggregator; it says
  nothing about whether the numbers are honest, fresh, or useful.
- Integer params larger than 2^53 are rejected fail-closed (the JCS
  float-loss caveat documented in ``secure_aggregation``): digest pins
  must be collision-free, and model weights outside +-2^53 are
  meaningless.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

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
FEDERATED_LEARNING_VERSION = "federated-learning.v1"

#: Schema pin carried by records and audit events.
SCHEMA_PIN = "northstar.federated-learning.v1"

#: Integers beyond this magnitude are rejected: JCS float-loss caveat,
#: and no model weight needs them.
MAX_INT_MAGNITUDE = 2 ** 53

#: Fixed audit vocabulary.
_KIND_BROADCAST = "model-broadcast"
_KIND_AGGREGATED = "updates-aggregated"
_KIND_ROUND = "round-completed"
_KIND_REJECTED = "rejected"
_AUDIT_KINDS = (_KIND_BROADCAST, _KIND_AGGREGATED, _KIND_ROUND, _KIND_REJECTED)


class FederatedLearningError(Exception):
    """Base error for the federated learning layer (programming errors)."""


class AggregationError(FederatedLearningError):
    """Policy failure: the update set cannot be aggregated.

    Empty sets, duplicate clients, mixed rounds, and dimension
    mismatches all raise this instead of returning a guessed average.
    """


def _check_text(value: object, name: str) -> str:
    """Validate a non-empty text field."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must be non-empty")
    return value


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _check_round(value: object) -> int:
    """Validate a round counter: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"round must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"round must be >= 0, got {value}")
    return value


def _check_params(value: object, name: str = "params") -> Tuple[float, ...]:
    """Validate a parameter vector: non-empty list/tuple of finite numbers.

    Bools are rejected (``True == 1`` would alias weight 1 silently),
    NaN/inf are refused, and integers beyond 2^53 are rejected so the
    digest pin cannot collide via the JCS float-loss caveat.
    """
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise TypeError(f"{name} must be a list/tuple of numbers, "
                        f"got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must be non-empty")
    out: List[float] = []
    for i, elt in enumerate(value):
        if isinstance(elt, bool) or not isinstance(elt, (int, float)):
            raise TypeError(f"{name}[{i}] must be int/float, "
                            f"got {type(elt).__name__}")
        if not math.isfinite(elt):
            raise ValueError(f"{name}[{i}] must be finite, got {elt!r}")
        if isinstance(elt, int) and abs(elt) > MAX_INT_MAGNITUDE:
            raise ValueError(f"{name}[{i}] exceeds 2^53 (digest safety)")
        out.append(elt)
    return tuple(out)


def _pin(prefix: str, body: Dict[str, Any]) -> str:
    """Pin a canonical body with a domain-separated digest."""
    return "sha256:" + jcs_sha256_hex({"domain": prefix, **body})


@dataclass(frozen=True)
class GlobalModel:
    """One broadcast global model. ``digest`` pins round + params."""

    round: int
    params: Tuple[float, ...]
    digest: str

    def __init__(self, round: int, params: object) -> None:
        _check_round(round)
        params_t = _check_params(params)
        digest = _pin("global-model", {"round": round,
                                      "params": list(params_t)})
        object.__setattr__(self, "round", round)
        object.__setattr__(self, "params", params_t)
        object.__setattr__(self, "digest", digest)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "round": self.round,
            "params": list(self.params),
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ClientUpdate:
    """One client's local update for a round.

    ``num_examples`` is the FedAvg weight: clients that trained on more
    examples count more in the average.
    """

    client_id: str
    round: int
    num_examples: int
    params: Tuple[float, ...]
    digest: str

    def __init__(self, client_id: str, round: int, num_examples: object,
                 params: object) -> None:
        _check_text(client_id, "client_id")
        _check_round(round)
        if isinstance(num_examples, bool) or not isinstance(num_examples, int):
            raise TypeError("num_examples must be int, "
                            f"got {type(num_examples).__name__}")
        if num_examples <= 0:
            raise ValueError(f"num_examples must be > 0, got {num_examples}")
        params_t = _check_params(params)
        digest = _pin("client-update", {
            "client_id": client_id,
            "round": round,
            "num_examples": num_examples,
            "params": list(params_t),
        })
        object.__setattr__(self, "client_id", client_id)
        object.__setattr__(self, "round", round)
        object.__setattr__(self, "num_examples", num_examples)
        object.__setattr__(self, "params", params_t)
        object.__setattr__(self, "digest", digest)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "client_id": self.client_id,
            "round": self.round,
            "num_examples": self.num_examples,
            "params": list(self.params),
            "digest": self.digest,
        }


@dataclass(frozen=True)
class AggregationResult:
    """The FedAvg outcome: example-weighted mean of the update params."""

    round: int
    clients: Tuple[str, ...]
    total_examples: int
    weights: Tuple[float, ...]
    params: Tuple[float, ...]
    digest: str

    def __init__(self, round: int, clients: Sequence[str],
                 total_examples: int, weights: Sequence[float],
                 params: Sequence[float]) -> None:
        _check_round(round)
        clients_t = tuple(_check_text(c, "clients[]") for c in clients)
        if isinstance(total_examples, bool) or not isinstance(total_examples, int):
            raise TypeError("total_examples must be int")
        if total_examples <= 0:
            raise ValueError("total_examples must be > 0")
        weights_t = tuple(float(w) for w in weights)
        params_t = tuple(float(p) for p in params)
        if len(weights_t) != len(clients_t):
            raise ValueError("weights and clients must align")
        digest = _pin("aggregation-result", {
            "round": round,
            "clients": list(clients_t),
            "total_examples": total_examples,
            "weights": list(weights_t),
            "params": list(params_t),
        })
        object.__setattr__(self, "round", round)
        object.__setattr__(self, "clients", clients_t)
        object.__setattr__(self, "total_examples", total_examples)
        object.__setattr__(self, "weights", weights_t)
        object.__setattr__(self, "params", params_t)
        object.__setattr__(self, "digest", digest)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "round": self.round,
            "clients": list(self.clients),
            "total_examples": self.total_examples,
            "weights": list(self.weights),
            "params": list(self.params),
            "digest": self.digest,
        }


def _validate_update_set(updates: object) -> List[ClientUpdate]:
    """Fail-closed structural checks for one aggregation batch."""
    if isinstance(updates, (str, bytes)) or not isinstance(updates, (list, tuple)):
        raise TypeError("updates must be a list/tuple of ClientUpdate, "
                        f"got {type(updates).__name__}")
    if not updates:
        raise AggregationError("cannot aggregate an empty update set")
    items: List[ClientUpdate] = []
    for i, u in enumerate(updates):
        if not isinstance(u, ClientUpdate):
            raise TypeError(f"updates[{i}] must be ClientUpdate, "
                            f"got {type(u).__name__}")
        items.append(u)
    rounds = {u.round for u in items}
    if len(rounds) != 1:
        raise AggregationError(
            f"all updates must be from one round, got {sorted(rounds)}")
    ids = [u.client_id for u in items]
    if len(set(ids)) != len(ids):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise AggregationError(f"duplicate client ids: {dupes}")
    dims = {len(u.params) for u in items}
    if len(dims) != 1:
        raise AggregationError(
            f"all updates must share one param dimension, got {sorted(dims)}")
    return items


class FederatedLearning:
    """Coordinator-side FedAvg bookkeeping (McMahan et al. 2017).

    The host owns transport, client training, and round scheduling; this
    class owns the two operations that must be deterministic and auditable:
    broadcasting a pinned global model and averaging a round's updates
    with example-count weighting.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._next_round = 0
        self._global_model: GlobalModel | None = None

    def broadcast(self, params: object, seq: int) -> GlobalModel:
        """Mint the next-round global model and pin it.

        ``seq`` is a caller-supplied audit ordering number (no wall-clock).
        """
        _check_seq(seq)
        params_t = _check_params(params)
        with self._lock:
            model = GlobalModel(self._next_round, params_t)
            self._global_model = model
            self._next_round += 1
            return model

    def aggregate(self, updates: object, seq: int) -> AggregationResult:
        """Weighted average of one round's updates (FedAvg).

        ``weight_i = num_examples_i / total_examples``. Fail-closed on
        empty sets, duplicate clients, mixed rounds, and dimension
        mismatches -- a refused batch is never silently averaged.
        """
        _check_seq(seq)
        items = _validate_update_set(updates)
        total = sum(u.num_examples for u in items)
        dim = len(items[0].params)
        weights = [u.num_examples / total for u in items]
        avg = tuple(
            math.fsum(w * u.params[j] for w, u in zip(weights, items))
            for j in range(dim)
        )
        clients = tuple(sorted(u.client_id for u in items))
        # Align weights with the sorted client order.
        order = {u.client_id: i for i, u in enumerate(items)}
        sorted_weights = tuple(weights[order[c]] for c in clients)
        return AggregationResult(items[0].round, clients, total,
                                 sorted_weights, avg)

    def round(self, updates: object, seq: int) -> GlobalModel:
        """Run one full training round: aggregate, then broadcast.

        Returns the next-round ``GlobalModel`` whose params are the FedAvg
        of ``updates``.
        """
        result = self.aggregate(updates, seq)
        return self.broadcast(result.params, seq)

    def current_model(self) -> GlobalModel | None:
        """The most recently broadcast model, or None before any broadcast."""
        with self._lock:
            return self._global_model

    def next_round(self) -> int:
        """The round number the next broadcast will mint."""
        with self._lock:
            return self._next_round


def federated_learning_audit_event(
    kind: str,
    seq: int,
    global_model: GlobalModel | None = None,
    result: AggregationResult | None = None,
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for federated learning decisions."""
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown kind: {kind!r}")
    _check_seq(seq)
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "module": SCHEMA_PIN,
        "kind": kind,
        "audit_seq": seq,
    }
    if global_model is not None:
        if not isinstance(global_model, GlobalModel):
            raise TypeError("expected GlobalModel, "
                            f"got {type(global_model).__name__}")
        event["model_round"] = global_model.round
        event["model_digest"] = global_model.digest
    if result is not None:
        if not isinstance(result, AggregationResult):
            raise TypeError("expected AggregationResult, "
                            f"got {type(result).__name__}")
        event["agg_round"] = result.round
        event["agg_clients"] = list(result.clients)
        event["agg_digest"] = result.digest
    return event


def main() -> None:
    """Self-check: broadcast, FedAvg math, round advancement, refusals."""
    fl = FederatedLearning()
    assert fl.current_model() is None
    assert fl.next_round() == 0

    m0 = fl.broadcast([0.0, 0.0], 0)
    assert isinstance(m0, GlobalModel)
    assert m0.round == 0 and fl.next_round() == 1
    assert fl.current_model() is m0

    # FedAvg: client A [1, 2] with 1 example, client B [3, 4] with 3.
    a = ClientUpdate("a", 1, 1, [1.0, 2.0])
    b = ClientUpdate("b", 1, 3, [3.0, 4.0])
    r = fl.aggregate([a, b], 1)
    assert r.round == 1
    assert r.clients == ("a", "b")
    assert r.total_examples == 4
    assert r.weights == (0.25, 0.75), r.weights
    assert r.params == (2.5, 3.5), r.params

    # Single client: the average is its own params.
    solo = fl.aggregate([a], 2)
    assert solo.params == (1.0, 2.0)

    # round() advances: next broadcast is the aggregate, round 1.
    m1 = fl.round([a, b], 3)
    assert m1.round == 1 and m1.params == (2.5, 3.5)

    # Fail-closed batch refusals.
    for bad in ([], [a, a]):
        try:
            fl.aggregate(bad, 4)
        except AggregationError:
            pass
        else:
            raise AssertionError(f"must refuse: {bad!r}")
    c = ClientUpdate("c", 2, 1, [9.0, 9.0])
    d = ClientUpdate("d", 1, 1, [9.0])
    for bad in ([a, c], [a, d]):
        try:
            fl.aggregate(bad, 5)
        except AggregationError:
            pass
        else:
            raise AssertionError("must refuse mixed round / dimension")

    ev = federated_learning_audit_event("updates-aggregated", 6, result=r)
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["agg_digest"] == r.digest
    try:
        federated_learning_audit_event("bogus", 7)
    except ValueError:
        pass
    else:
        raise AssertionError("unknown kind must raise")

    print("federated-learning OK: broadcast, FedAvg math, round, refusals")


if __name__ == "__main__":
    main()
