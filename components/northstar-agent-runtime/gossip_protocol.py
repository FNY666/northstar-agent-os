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

SWIM-style membership plane (additive extension): real gossip deployments
pair dissemination with membership -- nodes ``join()``, are ``suspect()`` ed
on missed probes, refute suspicion with ``alive()`` (incarnation bump), and
are ``confirm()`` ed dead after the suspicion timeout. ``GossipProtocol``
pins that decision ledger; ``disseminate()`` books a rumor for piggyback
dissemination to a deterministic subset of alive members. Probes, timeouts,
and retries remain the host's job.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
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


# ---------------------------------------------------------------------------
# SWIM-style membership plane (additive extension)
#
# The rumor layer above models dissemination without membership: the node
# set is fixed. Real gossip deployments (SWIM, Consul, Serf) pair
# dissemination with a membership protocol: nodes join, are suspected on
# missed probes, refute suspicion by bumping an incarnation number, and are
# confirmed dead after the suspicion timeout. This section pins that state
# machine as a deterministic single-host ledger (house style: frozen
# records, caller-supplied strictly increasing int seqs, no wall-clock,
# RLock-guarded, fail-closed). It is the *decision ledger*, not a
# transport: probes, timeouts, and retries are the host's job.
# ---------------------------------------------------------------------------

#: Membership states (SWIM-shaped).
MEMBER_ALIVE = "alive"
MEMBER_SUSPECT = "suspect"
MEMBER_DEAD = "dead"
_MEMBER_STATES = (MEMBER_ALIVE, MEMBER_SUSPECT, MEMBER_DEAD)

#: Audit event kinds for the membership plane.
EVENT_JOINED = "gossip-joined"
EVENT_SUSPECTED = "gossip-suspected"
EVENT_CONFIRMED = "gossip-confirmed"
EVENT_ALIVE = "gossip-alive"
EVENT_DISSEMINATED = "gossip-disseminated"
EVENT_MEMBERSHIP_REJECTED = "gossip-membership-rejected"
_MEMBERSHIP_KINDS = (
    EVENT_JOINED,
    EVENT_SUSPECTED,
    EVENT_CONFIRMED,
    EVENT_ALIVE,
    EVENT_DISSEMINATED,
    EVENT_MEMBERSHIP_REJECTED,
)

#: Membership-update kinds carried in the piggyback buffer.
_UPDATE_KINDS = (EVENT_JOINED, EVENT_SUSPECTED, EVENT_CONFIRMED, EVENT_ALIVE)

#: Max membership updates a host piggybacks on one probe round.
MAX_PIGGYBACK = 5


class GossipMembershipError(GossipError):
    """Membership-plane usage error (fail-closed)."""


class DuplicateMemberError(GossipMembershipError):
    """``join()`` on an already-known member id."""


class UnknownMemberError(GossipMembershipError):
    """Operation on a member id that never joined."""


class BadMemberStateError(GossipMembershipError):
    """State transition not allowed from the member's current state."""


class SeqOrderError(GossipMembershipError):
    """Caller seq did not strictly increase."""


def _member_digest(member_id: str, state: str, incarnation: int, seq: int) -> str:
    body = "\x00".join(
        [GOSSIP_PROTOCOL_VERSION, member_id, state, str(incarnation), str(seq)]
    )
    return "sha256:" + _sha256_hex(body.encode("utf-8"))


def _update_digest(
    update_id: str, kind: str, member_id: str, incarnation: int, seq: int
) -> str:
    body = "\x00".join(
        [GOSSIP_PROTOCOL_VERSION, update_id, kind, member_id, str(incarnation), str(seq)]
    )
    return "sha256:" + _sha256_hex(body.encode("utf-8"))


@dataclass(frozen=True)
class MemberRecord:
    """One frozen membership entry: id, SWIM state, incarnation, seq."""

    member_id: str
    state: str
    incarnation: int
    seq: int

    def __post_init__(self) -> None:
        _check_str(self.member_id, "member_id")
        if self.state not in _MEMBER_STATES:
            raise ValueError(f"state must be one of {_MEMBER_STATES}")
        if isinstance(self.incarnation, bool) or not isinstance(self.incarnation, int):
            raise TypeError("incarnation must be an int")
        if self.incarnation < 0:
            raise ValueError("incarnation must be non-negative")
        _check_seq(self.seq, "seq")

    def digest(self) -> str:
        """Digest pin binding (id, state, incarnation, seq)."""
        return _member_digest(self.member_id, self.state, self.incarnation, self.seq)

    def verify_digest(self, digest: str) -> bool:
        if not isinstance(digest, str):
            raise TypeError("digest must be a str")
        return hmac.compare_digest(self.digest(), digest)

    def as_dict(self) -> dict:
        return {
            "schema": GOSSIP_PROTOCOL_SCHEMA,
            "version": GOSSIP_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "state": self.state,
            "incarnation": self.incarnation,
            "seq": self.seq,
            "digest": self.digest(),
        }


@dataclass(frozen=True)
class UpdateRecord:
    """One frozen membership update for the piggyback buffer."""

    update_id: str
    kind: str
    member_id: str
    incarnation: int
    seq: int

    def __post_init__(self) -> None:
        _check_str(self.update_id, "update_id")
        if self.kind not in _UPDATE_KINDS:
            raise ValueError(f"update kind must be one of {_UPDATE_KINDS}")
        _check_str(self.member_id, "member_id")
        if isinstance(self.incarnation, bool) or not isinstance(self.incarnation, int):
            raise TypeError("incarnation must be an int")
        if self.incarnation < 0:
            raise ValueError("incarnation must be non-negative")
        _check_seq(self.seq, "seq")

    def digest(self) -> str:
        """Digest pin binding (update id, kind, member, incarnation, seq)."""
        return _update_digest(
            self.update_id, self.kind, self.member_id, self.incarnation, self.seq
        )

    def verify_digest(self, digest: str) -> bool:
        if not isinstance(digest, str):
            raise TypeError("digest must be a str")
        return hmac.compare_digest(self.digest(), digest)

    def as_dict(self) -> dict:
        return {
            "schema": GOSSIP_PROTOCOL_SCHEMA,
            "version": GOSSIP_PROTOCOL_VERSION,
            "update_id": self.update_id,
            "kind": self.kind,
            "member_id": self.member_id,
            "incarnation": self.incarnation,
            "seq": self.seq,
            "digest": self.digest(),
        }


@dataclass(frozen=True)
class DisseminationReport:
    """One frozen dissemination decision: rumor pin + deterministic targets."""

    rumor_id: str
    origin: str
    seq: int
    targets: tuple[str, ...]
    digest: str

    def __post_init__(self) -> None:
        _check_str(self.rumor_id, "rumor_id")
        if not isinstance(self.origin, str) or isinstance(self.origin, bool):
            raise TypeError("origin must be a str")
        _check_seq(self.seq, "seq")
        if not isinstance(self.targets, tuple) or not all(
            isinstance(t, str) and t for t in self.targets
        ):
            raise TypeError("targets must be a tuple of non-empty str")
        _check_str(self.digest, "digest")

    def as_dict(self) -> dict:
        return {
            "schema": GOSSIP_PROTOCOL_SCHEMA,
            "version": GOSSIP_PROTOCOL_VERSION,
            "rumor_id": self.rumor_id,
            "origin": self.origin,
            "seq": self.seq,
            "targets": list(self.targets),
            "digest": self.digest,
        }


def membership_audit_event(
    kind: str,
    *,
    member_id: str,
    seq: int,
    rumor_id: str = "",
    detail: Optional[Mapping] = None,
) -> dict:
    """``audit.ndjson/1``-shaped record for a membership-plane event."""
    if kind not in _MEMBERSHIP_KINDS:
        raise ValueError(f"unknown membership event kind: {kind}")
    _check_str(member_id, "member_id")
    if not isinstance(rumor_id, str) or isinstance(rumor_id, bool):
        raise TypeError("rumor_id must be a str")
    _check_seq(seq, "seq")
    if detail is not None:
        if not isinstance(detail, Mapping):
            raise TypeError("detail must be a mapping")
        _canonicalize(detail)
        if "payload" in detail:
            raise ValueError("detail must not carry rumor payload")
    return {
        "audit": "audit.ndjson/1",
        "schema": GOSSIP_PROTOCOL_SCHEMA,
        "version": GOSSIP_PROTOCOL_VERSION,
        "kind": kind,
        "node_id": member_id,
        "rumor_id": rumor_id,
        "audit_seq": seq,
        "detail": dict(detail) if detail is not None else {},
    }


class GossipProtocol:
    """SWIM-style membership + piggyback dissemination ledger.

    Deterministic single-host state machine (house style: caller-supplied
    strictly increasing int seqs, no wall-clock, RLock-guarded,
    fail-closed). Failed mutations consume their seq.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._members: dict[str, MemberRecord] = {}
        self._updates: list[UpdateRecord] = []
        self._reports: list[DisseminationReport] = []
        self._audit: list[dict] = []
        self._last_seq = 0
        self._update_counter = 0

    # -- internals -----------------------------------------------------

    def _consume(self, seq: int) -> int:
        """Validate seq shape, enforce strict increase, consume it."""
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(
        self,
        kind: str,
        member_id: str,
        seq: int,
        rumor_id: str = "",
        detail: Optional[Mapping] = None,
    ) -> None:
        self._audit.append(
            membership_audit_event(
                kind, member_id=member_id, seq=seq, rumor_id=rumor_id, detail=detail
            )
        )

    def _reject(self, seq: int, member_id: str, reason: str) -> None:
        self._emit(
            EVENT_MEMBERSHIP_REJECTED, member_id, seq, detail={"reason": reason}
        )

    def _record_update(
        self, kind: str, member_id: str, incarnation: int, seq: int
    ) -> UpdateRecord:
        self._update_counter += 1
        rec = UpdateRecord(
            update_id=f"upd-{self._update_counter}",
            kind=kind,
            member_id=member_id,
            incarnation=incarnation,
            seq=seq,
        )
        self._updates.append(rec)
        return rec

    # -- membership ------------------------------------------------------

    def join(self, node_id: str, seq: int) -> MemberRecord:
        """Admit a node as alive. Duplicate ids are refused fail-closed."""
        with self._lock:
            _check_str(node_id, "node_id")
            self._consume(seq)
            if node_id in self._members:
                self._reject(seq, node_id, "duplicate-member")
                raise DuplicateMemberError(f"member already joined: {node_id}")
            rec = MemberRecord(
                member_id=node_id, state=MEMBER_ALIVE, incarnation=0, seq=seq
            )
            self._members[node_id] = rec
            self._record_update(EVENT_JOINED, node_id, 0, seq)
            self._emit(EVENT_JOINED, node_id, seq)
            return rec

    def suspect(self, node_id: str, seq: int) -> MemberRecord:
        """Mark an alive member suspect (missed probes)."""
        with self._lock:
            _check_str(node_id, "node_id")
            self._consume(seq)
            cur = self._members.get(node_id)
            if cur is None:
                self._reject(seq, node_id, "unknown-member")
                raise UnknownMemberError(f"unknown member: {node_id}")
            if cur.state != MEMBER_ALIVE:
                self._reject(seq, node_id, f"not-alive:{cur.state}")
                raise BadMemberStateError(
                    f"cannot suspect member in state {cur.state}"
                )
            rec = MemberRecord(
                member_id=node_id,
                state=MEMBER_SUSPECT,
                incarnation=cur.incarnation,
                seq=seq,
            )
            self._members[node_id] = rec
            self._record_update(EVENT_SUSPECTED, node_id, cur.incarnation, seq)
            self._emit(
                EVENT_SUSPECTED,
                node_id,
                seq,
                detail={"incarnation": cur.incarnation},
            )
            return rec

    def confirm(self, node_id: str, seq: int) -> MemberRecord:
        """Confirm a suspect member dead (terminal)."""
        with self._lock:
            _check_str(node_id, "node_id")
            self._consume(seq)
            cur = self._members.get(node_id)
            if cur is None:
                self._reject(seq, node_id, "unknown-member")
                raise UnknownMemberError(f"unknown member: {node_id}")
            if cur.state != MEMBER_SUSPECT:
                self._reject(seq, node_id, f"not-suspect:{cur.state}")
                raise BadMemberStateError(
                    f"cannot confirm member in state {cur.state}"
                )
            rec = MemberRecord(
                member_id=node_id,
                state=MEMBER_DEAD,
                incarnation=cur.incarnation,
                seq=seq,
            )
            self._members[node_id] = rec
            self._record_update(EVENT_CONFIRMED, node_id, cur.incarnation, seq)
            self._emit(EVENT_CONFIRMED, node_id, seq)
            return rec

    def alive(self, node_id: str, seq: int) -> MemberRecord:
        """Refute a suspicion: suspect -> alive, incarnation bumps.

        The incarnation bump is what lets the refutation win over stale
        suspicion rumors still circulating (SWIM semantics).
        """
        with self._lock:
            _check_str(node_id, "node_id")
            self._consume(seq)
            cur = self._members.get(node_id)
            if cur is None:
                self._reject(seq, node_id, "unknown-member")
                raise UnknownMemberError(f"unknown member: {node_id}")
            if cur.state != MEMBER_SUSPECT:
                self._reject(seq, node_id, f"not-suspect:{cur.state}")
                raise BadMemberStateError(
                    f"cannot revive member in state {cur.state}"
                )
            rec = MemberRecord(
                member_id=node_id,
                state=MEMBER_ALIVE,
                incarnation=cur.incarnation + 1,
                seq=seq,
            )
            self._members[node_id] = rec
            self._record_update(EVENT_ALIVE, node_id, cur.incarnation + 1, seq)
            self._emit(
                EVENT_ALIVE,
                node_id,
                seq,
                detail={"incarnation": cur.incarnation + 1},
            )
            return rec

    # -- dissemination ---------------------------------------------------

    def disseminate(
        self,
        rumor_id: str,
        payload: Mapping,
        seq: int,
        fanout: int = DEFAULT_FANOUT,
        origin: str = "",
    ) -> DisseminationReport:
        """Book a rumor for piggyback dissemination.

        Selects up to ``fanout`` alive members (origin excluded) by the
        same deterministic hash draw the rumor layer uses, lowest draws
        first. The rumor content is pinned by digest; payload bytes never
        cross the audit boundary. Empty targets are data, not an error.
        """
        with self._lock:
            _check_str(rumor_id, "rumor_id")
            if not isinstance(payload, Mapping):
                raise TypeError(
                    f"payload must be a mapping, got {type(payload).__name__}"
                )
            _canonicalize(payload)
            if not isinstance(origin, str) or isinstance(origin, bool):
                raise TypeError("origin must be a str")
            if isinstance(fanout, bool) or not isinstance(fanout, int):
                raise TypeError(
                    f"fanout must be an int, got {type(fanout).__name__}"
                )
            if fanout < 1:
                raise ValueError("fanout must be >= 1")
            self._consume(seq)
            eligible = [
                m
                for m in self._members
                if m != origin and self._members[m].state == MEMBER_ALIVE
            ]
            ranked = sorted(
                ((_draw(origin, m, rumor_id, seq), m) for m in eligible),
                key=lambda t: (t[0], t[1]),
            )
            targets = tuple(m for _, m in ranked[:fanout])
            digest = _rumor_digest(rumor_id, payload, origin or "membership", seq)
            report = DisseminationReport(
                rumor_id=rumor_id,
                origin=origin,
                seq=seq,
                targets=targets,
                digest=digest,
            )
            self._reports.append(report)
            self._emit(
                EVENT_DISSEMINATED,
                origin or "membership",
                seq,
                rumor_id=rumor_id,
                detail={"digest": digest, "targets": list(targets)},
            )
            return report

    # -- views -----------------------------------------------------------

    def member(self, member_id: str) -> MemberRecord:
        """Current record for a member (raises ``UnknownMemberError``)."""
        with self._lock:
            _check_str(member_id, "member_id")
            try:
                return self._members[member_id]
            except KeyError:
                raise UnknownMemberError(
                    f"unknown member: {member_id}"
                ) from None

    def member_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._members))

    def alive_members(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted(
                    m
                    for m, r in self._members.items()
                    if r.state == MEMBER_ALIVE
                )
            )

    def suspects(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted(
                    m
                    for m, r in self._members.items()
                    if r.state == MEMBER_SUSPECT
                )
            )

    def dead(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted(
                    m for m, r in self._members.items() if r.state == MEMBER_DEAD
                )
            )

    def state_of(self, member_id: str) -> str:
        """Current SWIM state of a member."""
        return self.member(member_id).state

    def updates(self, seq: int, limit: int = MAX_PIGGYBACK) -> tuple[UpdateRecord, ...]:
        """Piggyback buffer: the most recent membership updates.

        Pure view (validates seq shape, consumes nothing): this is what a
        host would attach to its next probe round.
        """
        with self._lock:
            _check_seq(seq, "seq")
            if isinstance(limit, bool) or not isinstance(limit, int):
                raise TypeError("limit must be an int")
            if limit < 1:
                raise ValueError("limit must be >= 1")
            return tuple(self._updates[-limit:])

    def reports(self) -> tuple[DisseminationReport, ...]:
        with self._lock:
            return tuple(self._reports)

    def audit_log(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(self._audit)

    def as_dict(self) -> dict:
        with self._lock:
            return {
                "schema": GOSSIP_PROTOCOL_SCHEMA,
                "version": GOSSIP_PROTOCOL_VERSION,
                "members": [r.as_dict() for _, r in sorted(self._members.items())],
                "pending_updates": len(self._updates),
                "disseminations": len(self._reports),
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
    # SWIM membership plane smoke
    gp = GossipProtocol()
    for i in range(5):
        gp.join(f"m{i}", i + 1)
    gp.suspect("m2", 6)
    assert gp.state_of("m2") == MEMBER_SUSPECT
    gp.alive("m2", 7)  # refutation bumps incarnation
    assert gp.member("m2").incarnation == 1
    gp.suspect("m3", 8)
    gp.confirm("m3", 9)
    assert gp.state_of("m3") == MEMBER_DEAD
    assert gp.dead() == ("m3",)
    rep = gp.disseminate("r9", {"cfg": "v2"}, 10, fanout=2)
    assert rep.targets and len(rep.targets) <= 2
    assert "m3" not in rep.targets  # dead members never targeted
    assert gp.updates(11)  # piggyback buffer is non-empty
    print("gossip-membership OK: join, suspect, refute, confirm, disseminate")


if __name__ == "__main__":
    main()
