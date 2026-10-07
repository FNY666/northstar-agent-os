"""Gossip protocol: deterministic probabilistic rumor dissemination.

Research motivation: a fleet of agent hosts needs *best-effort*
dissemination without a coordinator -- alert propagation ("host-3 tripped
its kill switch"), config drift notices, audit-head announcements. The
classic tool is gossip: each node forwards what it learns to a random
subset of peers (fanout), and rumors converge exponentially fast on a
connected graph. The failure mode it survives is *coordination failure*,
not Byzantine peers.

This module pins the mechanical, network-free halves:

- ``Rumor`` -- frozen record: ``rumor_id``, canonicalized ``payload``,
  ``origin`` node id, caller-supplied int ``seq``, and a ``sha256:``
  digest pin over the canonical body.
- ``GossipNode`` -- ``receive(rumor)`` accepts a rumor the first time it
  is seen (returns ``True``); duplicates return ``False``. ``spread`` is
  *deterministically* probabilistic: the peer subset is derived from
  ``sha256(version | node_id | peer_id | rumor_id | round_seq)``, so the
  same inputs always select the same peers (replayable, no global RNG).
- ``GossipNetwork`` -- an in-memory harness: a fixed peer set, a
  ``step(round_seq)`` that has every informed node spread and every
  selected peer receive, and a convergence probe. It simulates the
  *host's* view of one gossip round; real transport is the host's job.

Public API:

- ``Rumor`` -- frozen record with ``digest()`` and ``verify_digest()``.
- ``GossipNode(node_id, fanout, probability, peers)`` -- ``receive``,
  ``spread(rumor, round_seq)`` -> tuple of selected peer ids,
  ``seen_ids()``, ``infected_count()``.
- ``GossipNetwork(nodes)`` -- ``broadcast(origin_id, rumor,
  round_seq)``, ``step(round_seq)`` -> ``GossipRound`` (newly informed
  node ids, in deterministic order), ``infected()``, ``converged()``.
- ``gossip_audit_event(...)`` -- ``audit.ndjson/1``-shaped record
  (``gossip-received`` / ``gossip-spread`` / ``gossip-round``).

Honest scope:

- "Probabilistic" here means a hash draw against ``probability``: it
  models random peer selection deterministically, not a true random
  process. Two hosts with the same inputs make the same draws --
  that is a feature (replay), not a bug.
- ``receive`` records *that a rumor was seen*, not that its payload is
  true. Rumor content is untrusted; digest pins bind identity, not
  veracity. Byzantine peers can invent rumors -- filtering them is the
  application layer's job (e.g. signed rumor payloads).
- Convergence on a *partitioned* peer graph is impossible by
  construction: gossip never crosses a missing edge. ``converged()``
  answers "every reachable peer has seen the rumor" relative to the
  *configured* peer sets, never "the whole fleet knows".
- This is the dissemination *state machine*, not a transport. Timers,
  retries, backpressure, and crash recovery are the host's job.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Sequence

#: Module version pin.
GOSSIP_PROTOCOL_VERSION = "gossip-protocol.v1"

#: Schema pin carried by records and audit events.
GOSSIP_PROTOCOL_SCHEMA = "northstar.gossip-protocol.v1"

#: Audit event kinds.
EVENT_RECEIVED = "gossip-received"
EVENT_SPREAD = "gossip-spread"
EVENT_ROUND = "gossip-round"

#: Default fanout (peers contacted per spread).
DEFAULT_FANOUT = 3

#: Default forward probability per eligible peer.
DEFAULT_PROBABILITY = 1.0


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _check_str(value: object, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not allow_empty and not value:
        raise ValueError(f"{name} must be non-empty")
    return value


def _check_seq(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _canonicalize(value: object) -> str:
    """Stable canonical string for a JSON-like payload."""
    if value is None or isinstance(value, bool):
        return repr(value)
    if isinstance(value, (int, float)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise ValueError("payload must not contain NaN/inf")
        return repr(value)
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonicalize(v) for v in value) + "]"
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise ValueError("payload mapping keys must be str")
        items = sorted(value.items())
        return "{" + ",".join(repr(k) + ":" + _canonicalize(v) for k, v in items) + "}"
    raise TypeError(f"payload value of type {type(value).__name__} is not canonicalizable")


def _rumor_digest(rumor_id: str, payload: Mapping, origin: str, seq: int) -> str:
    body = "\x00".join(
        [GOSSIP_PROTOCOL_VERSION, rumor_id, _canonicalize(payload), origin, str(seq)]
    )
    return "sha256:" + _sha256_hex(body.encode("utf-8"))


def _draw(node_id: str, peer_id: str, rumor_id: str, round_seq: int) -> float:
    """Deterministic pseudo-random draw in [0, 1) for a (node, peer, rumor, round)."""
    material = "\x00".join(
        [GOSSIP_PROTOCOL_VERSION, node_id, peer_id, rumor_id, str(round_seq)]
    )
    digest = _sha256_hex(material.encode("utf-8"))
    return int(digest, 16) / 2**256


@dataclass(frozen=True)
class Rumor:
    """A frozen, digest-pinned rumor."""

    rumor_id: str
    payload: Mapping
    origin: str
    seq: int

    def __post_init__(self) -> None:
        _check_str(self.rumor_id, "rumor_id")
        _check_str(self.origin, "origin")
        _check_seq(self.seq, "seq")
        if not isinstance(self.payload, Mapping):
            raise TypeError(f"payload must be a mapping, got {type(self.payload).__name__}")
        _canonicalize(self.payload)  # validate canonicalizability eagerly

    def digest(self) -> str:
        """Digest pin binding (id, payload, origin, seq)."""
        return _rumor_digest(self.rumor_id, self.payload, self.origin, self.seq)

    def verify_digest(self, digest: str) -> bool:
        if not isinstance(digest, str):
            raise TypeError("digest must be a str")
        return hmac.compare_digest(self.digest(), digest)

    def as_dict(self) -> dict:
        return {
            "schema": GOSSIP_PROTOCOL_SCHEMA,
            "version": GOSSIP_PROTOCOL_VERSION,
            "rumor_id": self.rumor_id,
            "payload": dict(self.payload),
            "origin": self.origin,
            "seq": self.seq,
            "digest": self.digest(),
        }


class GossipError(Exception):
    """Configuration or usage error (fail-closed)."""


class GossipNode:
    """One gossip participant.

    ``fanout`` caps how many peers a single ``spread`` contacts;
    ``probability`` is the per-peer forward probability (hash draw).
    ``peers`` is the fixed set of peer node ids (self excluded
    automatically).
    """

    def __init__(
        self,
        node_id: str,
        peers: Iterable[str],
        *,
        fanout: int = DEFAULT_FANOUT,
        probability: float = DEFAULT_PROBABILITY,
    ) -> None:
        self.node_id = _check_str(node_id, "node_id")
        peer_list = list(peers)
        if not all(isinstance(p, str) and p for p in peer_list):
            raise TypeError("peers must be an iterable of non-empty str")
        if len(set(peer_list)) != len(peer_list):
            raise ValueError("peers must not contain duplicates")
        self.peers: tuple[str, ...] = tuple(sorted(set(peer_list) - {self.node_id}))
        if isinstance(fanout, bool) or not isinstance(fanout, int):
            raise TypeError(f"fanout must be an int, got {type(fanout).__name__}")
        if fanout < 1:
            raise ValueError("fanout must be >= 1")
        if isinstance(probability, bool) or not isinstance(probability, (int, float)):
            raise TypeError("probability must be a number")
        if not 0.0 <= float(probability) <= 1.0:
            raise ValueError("probability must be in [0, 1]")
        self.fanout = fanout
        self.probability = float(probability)
        self._seen: dict[str, Rumor] = {}

    def receive(self, rumor: Rumor) -> bool:
        """Accept a rumor; True on first sight, False on duplicate.

        Raises ``TypeError`` on non-Rumor input (fail-closed).
        """
        if not isinstance(rumor, Rumor):
            raise TypeError(f"rumor must be a Rumor, got {type(rumor).__name__}")
        if rumor.rumor_id in self._seen:
            return False
        self._seen[rumor.rumor_id] = rumor
        return True

    def spread(self, rumor: Rumor, round_seq: int) -> tuple[str, ...]:
        """Deterministically select peers to forward ``rumor`` to.

        Each peer gets a hash draw; peers with draw < ``probability``
        are eligible, then the ``fanout`` lowest draws are selected
        (draw ties broken by peer id). Pure and replayable: same
        inputs -> same peer tuple.
        """
        if not isinstance(rumor, Rumor):
            raise TypeError(f"rumor must be a Rumor, got {type(rumor).__name__}")
        _check_seq(round_seq, "round_seq")
        candidates: list[tuple[float, str]] = []
        for peer in self.peers:
            draw = _draw(self.node_id, peer, rumor.rumor_id, round_seq)
            if draw < self.probability:
                candidates.append((draw, peer))
        candidates.sort(key=lambda t: (t[0], t[1]))
        return tuple(peer for _, peer in candidates[: self.fanout])

    def has_seen(self, rumor_id: str) -> bool:
        _check_str(rumor_id, "rumor_id")
        return rumor_id in self._seen

    def seen_ids(self) -> tuple[str, ...]:
        """Rumor ids seen, in first-sight order."""
        return tuple(self._seen)

    def infected_count(self) -> int:
        return len(self._seen)


@dataclass(frozen=True)
class GossipRound:
    """Outcome of one network step."""

    round_seq: int
    newly_informed: tuple[str, ...]
    infected: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "schema": GOSSIP_PROTOCOL_SCHEMA,
            "version": GOSSIP_PROTOCOL_VERSION,
            "round_seq": self.round_seq,
            "newly_informed": list(self.newly_informed),
            "infected": list(self.infected),
        }


class GossipNetwork:
    """In-memory harness over a fixed set of ``GossipNode`` s.

    ``broadcast(origin_id, rumor, round_seq)`` seeds the rumor at the
    origin; ``step(round_seq)`` has every informed node spread to its
    selected peers and delivers. Deterministic throughout.
    """

    def __init__(self, nodes: Iterable[GossipNode]) -> None:
        node_list = list(nodes)
        if not node_list:
            raise ValueError("network must contain at least one node")
        if not all(isinstance(n, GossipNode) for n in node_list):
            raise TypeError("nodes must be GossipNode instances")
        ids = [n.node_id for n in node_list]
        if len(set(ids)) != len(ids):
            raise ValueError("node ids must be unique")
        self._nodes: dict[str, GossipNode] = {n.node_id: n for n in node_list}

    def node(self, node_id: str) -> GossipNode:
        try:
            return self._nodes[_check_str(node_id, "node_id")]
        except KeyError:
            raise KeyError(f"unknown node: {node_id}") from None

    def node_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._nodes))

    def broadcast(self, origin_id: str, rumor: Rumor, round_seq: int) -> None:
        """Seed ``rumor`` at the origin node (must name the origin)."""
        if not isinstance(rumor, Rumor):
            raise TypeError(f"rumor must be a Rumor, got {type(rumor).__name__}")
        _check_seq(round_seq, "round_seq")
        origin = self.node(origin_id)
        if rumor.origin != origin_id:
            raise GossipError("rumor.origin must match the broadcasting node")
        origin.receive(rumor)

    def step(self, round_seq: int) -> GossipRound:
        """One gossip round: informed nodes spread, selected peers receive."""
        _check_seq(round_seq, "round_seq")
        deliveries: dict[str, list[Rumor]] = {}
        for node_id in sorted(self._nodes):
            node = self._nodes[node_id]
            for rumor_id in node.seen_ids():
                rumor = node._seen[rumor_id]
                for peer_id in node.spread(rumor, round_seq):
                    deliveries.setdefault(peer_id, []).append(rumor)
        newly: list[str] = []
        for peer_id in sorted(deliveries):
            peer = self._nodes[peer_id]
            for rumor in deliveries[peer_id]:
                if peer.receive(rumor):
                    if peer_id not in newly:
                        newly.append(peer_id)
        return GossipRound(
            round_seq=round_seq,
            newly_informed=tuple(newly),
            infected=self.infected(),
        )

    def infected(self) -> tuple[str, ...]:
        """Node ids that have seen at least one rumor, sorted."""
        return tuple(sorted(n.node_id for n in self._nodes.values() if n.infected_count()))

    def infected_by(self, rumor_id: str) -> tuple[str, ...]:
        """Node ids that have seen ``rumor_id``, sorted."""
        _check_str(rumor_id, "rumor_id")
        return tuple(
            sorted(n.node_id for n in self._nodes.values() if n.has_seen(rumor_id))
        )

    def converged(self, rumor_id: str) -> bool:
        """True when every node has seen ``rumor_id``."""
        return len(self.infected_by(rumor_id)) == len(self._nodes)


def gossip_audit_event(
    kind: str,
    *,
    node_id: str,
    rumor_id: str,
    seq: int,
    detail: Optional[Mapping] = None,
) -> dict:
    """``audit.ndjson/1``-shaped record for a gossip event."""
    if kind not in (EVENT_RECEIVED, EVENT_SPREAD, EVENT_ROUND):
        raise ValueError(f"unknown gossip event kind: {kind}")
    _check_str(node_id, "node_id")
    _check_str(rumor_id, "rumor_id")
    _check_seq(seq, "seq")
    if detail is not None:
        if not isinstance(detail, Mapping):
            raise TypeError("detail must be a mapping")
        _canonicalize(detail)
    return {
        "audit": "audit.ndjson/1",
        "schema": GOSSIP_PROTOCOL_SCHEMA,
        "version": GOSSIP_PROTOCOL_VERSION,
        "kind": kind,
        "node_id": node_id,
        "rumor_id": rumor_id,
        "audit_seq": seq,
        "detail": dict(detail) if detail is not None else {},
    }


def main() -> None:
    nodes = [GossipNode(f"n{i}", [f"n{j}" for j in range(5) if j != i]) for i in range(5)]
    net = GossipNetwork(nodes)
    rumor = Rumor(rumor_id="r1", payload={"alert": "kill-switch"}, origin="n0", seq=1)
    net.broadcast("n0", rumor, 0)
    rounds = 0
    while not net.converged("r1") and rounds < 20:
        net.step(rounds)
        rounds += 1
    assert net.converged("r1"), "gossip did not converge on a 5-node clique"
    print(f"gossip-protocol OK: converged in {rounds} rounds, spread is deterministic")


if __name__ == "__main__":
    main()
