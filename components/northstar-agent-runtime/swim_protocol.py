"""SWIM protocol: gossip-based membership and failure detection.

Research motivation: SWIM (Scalable Weakly-consistent Infection-style
process group Membership, Das, Gupta, Motivala, 2002) gives a fleet of
hosts a shared view of who is alive without a central registry -- the
primitive a distributed kill switch, a leader elector, or a validator
fleet needs before it can trust "the fleet agrees". This module pins the
mechanical halves that do not require a network:

- failure detection: direct probe of a round-robin target; on no ack,
  ``k`` indirect probes through other members; ack through neither path
  marks the target SUSPECT.
- incarnation numbers: a suspected node refutes by bumping its
  incarnation and gossiping ALIVE; higher incarnation always overrides
  lower, so a live node can always clear a false suspicion.
- dissemination: infection-style gossip -- membership updates ride
  piggyback on probe/ack traffic, each update gossiped at most
  ``lambda * log2(n)`` times, at most ``piggyback_limit`` updates per
  message.

Public API:

- ``MemberStatus`` -- ALIVE / SUSPECT / FAILED (ordered by severity).
- ``SwimMember`` -- frozen record: ``node_id``, ``status``,
  ``incarnation``, ``status_seq`` (caller-supplied seq of last change).
- ``MembershipUpdate`` -- frozen gossip record: ``node_id``, ``status``,
  ``incarnation``, ``origin_seq``, ``gossip_count``.
- ``SwimNode`` -- stateful local view:
  ``add_member``, ``next_probe_target`` (deterministic round-robin),
  ``probe`` (direct), ``probe_indirect`` (k indirect), ``suspect``,
  ``refute_self``, ``confirm_failed`` (suspect-timeout gated),
  ``receive_gossip`` (incarnation-precedence merge),
  ``disseminate`` (bounded piggyback selection), plus
  ``alive_members`` / ``suspect_members`` / ``failed_members`` views and
  ``membership_digest``.
- ``swim_audit_event(...)`` -- ``audit.ndjson/1``-shaped record.

Honest scope:

- This is the membership *state machine*, not a network protocol. There
  is no socket, no timer, no actual probe packet here -- the host drives
  ``probe`` / ``probe_indirect`` with the acks its transport observed,
  and carries ``disseminate`` output to peers itself. A member marked
  ALIVE means "no probe reported otherwise", never "the host is healthy".
- Suspicion is local until gossiped: two nodes can disagree about a
  third (one suspects, one still alive) -- that is SWIM's weak
  consistency, and convergence is the gossip layer's job, not a
  guarantee of this module.
- ``confirm_failed`` is gated on a caller-supplied suspect timeout in
  seqs. Picking the timeout is the host's job (too short: flapping;
  too long: slow failure detection). This module enforces whatever the
  host configured, nothing more.
- Incarnation refutation assumes the suspected node is alive enough to
  gossip. A truly dead node never refutes, which is exactly why the
  suspect timeout exists.
- All time is caller-supplied int seqs (no wall-clock): probe rounds,
  timeouts, and gossip budgets are logical statements, immune to NTP
  jumps and replayable in tests.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence

#: Version pin for this module's record shape.
SWIM_PROTOCOL_VERSION = "swim-protocol.v1"

#: Schema pin carried by records and audit events.
SWIM_PROTOCOL_SCHEMA = "northstar.swim-protocol.v1"

#: Audit event kinds.
EVENT_MEMBER_ADDED = "member-added"
EVENT_PROBED = "probed"
EVENT_SUSPECTED = "suspected"
EVENT_REFUTED = "refuted"
EVENT_FAILED = "failed-confirmed"
EVENT_GOSSIP_RECEIVED = "gossip-received"
EVENT_GOSSIP_SENT = "gossip-sent"

_EVENT_KINDS = frozenset({
    EVENT_MEMBER_ADDED,
    EVENT_PROBED,
    EVENT_SUSPECTED,
    EVENT_REFUTED,
    EVENT_FAILED,
    EVENT_GOSSIP_RECEIVED,
    EVENT_GOSSIP_SENT,
})


class SwimError(Exception):
    """Raised on malformed input or illegal state transitions."""


class MemberStatus(str, Enum):
    """Membership status, ordered by severity."""

    ALIVE = "alive"
    SUSPECT = "suspect"
    FAILED = "failed"


# At equal incarnation, higher severity wins (SWIM merge rule).
_STATUS_SEVERITY = {
    MemberStatus.ALIVE: 0,
    MemberStatus.SUSPECT: 1,
    MemberStatus.FAILED: 2,
}


def _check_node_id(value: object, name: str = "node_id") -> str:
    """Validate a node id: non-empty string, whitespace-stripped."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    node_id = value.strip()
    if not node_id:
        raise ValueError(f"{name} must be non-empty")
    return node_id


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied seq: non-negative int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _check_incarnation(value: object, name: str = "incarnation") -> int:
    """Validate an incarnation number: non-negative int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _check_status(value: object, name: str = "status") -> MemberStatus:
    """Validate a MemberStatus (enum or case-insensitive string)."""
    if isinstance(value, MemberStatus):
        return value
    if isinstance(value, str):
        try:
            return MemberStatus(value.strip().lower())
        except ValueError:
            pass
    raise ValueError(f"{name} must be one of alive/suspect/failed, got {value!r}")


@dataclass(frozen=True)
class SwimMember:
    """One member as seen by the local node."""

    node_id: str
    status: MemberStatus
    incarnation: int
    status_seq: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", _check_node_id(self.node_id))
        object.__setattr__(self, "status", _check_status(self.status))
        object.__setattr__(self, "incarnation", _check_incarnation(self.incarnation))
        object.__setattr__(self, "status_seq", _check_seq(self.status_seq, "status_seq"))

    def as_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "status": self.status.value,
            "incarnation": self.incarnation,
            "status_seq": self.status_seq,
            "schema": SWIM_PROTOCOL_SCHEMA,
        }


@dataclass(frozen=True)
class MembershipUpdate:
    """One gossipable membership change."""

    node_id: str
    status: MemberStatus
    incarnation: int
    origin_seq: int
    gossip_count: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", _check_node_id(self.node_id))
        object.__setattr__(self, "status", _check_status(self.status))
        object.__setattr__(self, "incarnation", _check_incarnation(self.incarnation))
        object.__setattr__(self, "origin_seq", _check_seq(self.origin_seq, "origin_seq"))
        object.__setattr__(self, "gossip_count", _check_seq(self.gossip_count, "gossip_count"))

    def as_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "status": self.status.value,
            "incarnation": self.incarnation,
            "origin_seq": self.origin_seq,
            "gossip_count": self.gossip_count,
            "schema": SWIM_PROTOCOL_SCHEMA,
        }


@dataclass(frozen=True)
class ProbeOutcome:
    """Result of one (direct or indirect) probe round."""

    target: str
    ack: bool
    outcome: MemberStatus  # ALIVE on ack, SUSPECT on no-ack
    seq: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "target", _check_node_id(self.target))
        if isinstance(self.ack, bool) is False:
            raise TypeError(f"ack must be a bool, got {type(self.ack).__name__}")
        object.__setattr__(self, "outcome", _check_status(self.outcome))
        object.__setattr__(self, "seq", _check_seq(self.seq))

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "ack": self.ack,
            "outcome": self.outcome.value,
            "seq": self.seq,
            "schema": SWIM_PROTOCOL_SCHEMA,
        }


@dataclass(frozen=True)
class GossipReceipt:
    """What one receive_gossip call changed."""

    applied: tuple[str, ...]      # node ids whose local view changed
    ignored: tuple[str, ...]      # node ids whose updates lost precedence
    self_suspected: bool          # a peer suspects *this* node
    seq: int

    def __post_init__(self) -> None:
        if not isinstance(self.applied, tuple) or not isinstance(self.ignored, tuple):
            raise TypeError("applied/ignored must be tuples")
        for nid in self.applied + self.ignored:
            _check_node_id(nid)
        if isinstance(self.self_suspected, bool) is False:
            raise TypeError("self_suspected must be a bool")
        object.__setattr__(self, "seq", _check_seq(self.seq))

    def as_dict(self) -> dict:
        return {
            "applied": list(self.applied),
            "ignored": list(self.ignored),
            "self_suspected": self.self_suspected,
            "seq": self.seq,
            "schema": SWIM_PROTOCOL_SCHEMA,
        }


class SwimNode:
    """Local SWIM view for one node.

    Args:
        self_id: this node's id (always ALIVE, never probed).
        indirect_probe_k: indirect probers on direct-probe failure.
        suspect_timeout_seqs: seqs a SUSPECT must age before
            ``confirm_failed`` accepts the transition.
        gossip_lambda: gossip budget factor; each update is gossiped at
            most ``ceil(lambda * log2(n))`` times (min 1).
        piggyback_limit: max updates carried per ``disseminate`` call.
    """

    def __init__(
        self,
        self_id: str,
        indirect_probe_k: int = 3,
        suspect_timeout_seqs: int = 10,
        gossip_lambda: int = 3,
        piggyback_limit: int = 5,
    ) -> None:
        self._self_id = _check_node_id(self_id, "self_id")
        for name, value, minimum in (
            ("indirect_probe_k", indirect_probe_k, 1),
            ("suspect_timeout_seqs", suspect_timeout_seqs, 1),
            ("gossip_lambda", gossip_lambda, 1),
            ("piggyback_limit", piggyback_limit, 1),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an int, got {type(value).__name__}")
            if value < minimum:
                raise ValueError(f"{name} must be >= {minimum}")
        self._indirect_probe_k = indirect_probe_k
        self._suspect_timeout_seqs = suspect_timeout_seqs
        self._gossip_lambda = gossip_lambda
        self._piggyback_limit = piggyback_limit
        self._members: dict[str, SwimMember] = {}
        self._updates: dict[str, MembershipUpdate] = {}
        self._probe_cursor = 0

    # -- introspection -------------------------------------------------

    @property
    def self_id(self) -> str:
        return self._self_id

    def get(self, node_id: str) -> SwimMember | None:
        """Local view of one member, or None if unknown."""
        return self._members.get(_check_node_id(node_id))

    def member_ids(self) -> tuple[str, ...]:
        """All known member ids (excluding self), sorted."""
        return tuple(sorted(self._members))

    def alive_members(self) -> tuple[str, ...]:
        return tuple(sorted(
            nid for nid, m in self._members.items()
            if m.status is MemberStatus.ALIVE
        ))

    def suspect_members(self) -> tuple[str, ...]:
        return tuple(sorted(
            nid for nid, m in self._members.items()
            if m.status is MemberStatus.SUSPECT
        ))

    def failed_members(self) -> tuple[str, ...]:
        return tuple(sorted(
            nid for nid, m in self._members.items()
            if m.status is MemberStatus.FAILED
        ))

    def membership_digest(self) -> str:
        """Deterministic sha256 pin of the full local view."""
        parts = []
        for nid in sorted(self._members):
            m = self._members[nid]
            parts.append(f"{nid}:{m.status.value}:{m.incarnation}:{m.status_seq}")
        parts.append(f"self:{self._self_id}")
        return "sha256:" + hashlib.sha256(
            "\x00".join(parts).encode("utf-8")
        ).hexdigest()

    # -- membership changes --------------------------------------------

    def add_member(self, node_id: str, seq: int) -> SwimMember:
        """Join a member as ALIVE at incarnation 0."""
        nid = _check_node_id(node_id)
        seq = _check_seq(seq)
        if nid == self._self_id:
            raise SwimError("cannot add self as a member")
        if nid in self._members:
            raise SwimError(f"member already known: {nid}")
        member = SwimMember(nid, MemberStatus.ALIVE, 0, seq)
        self._members[nid] = member
        self._record_update(nid, MemberStatus.ALIVE, 0, seq)
        return member

    # -- failure detection ----------------------------------------------

    def next_probe_target(self) -> str | None:
        """Deterministic round-robin probe target (never self)."""
        ids = [nid for nid in sorted(self._members)
               if self._members[nid].status is not MemberStatus.FAILED]
        if not ids:
            return None
        target = ids[self._probe_cursor % len(ids)]
        self._probe_cursor += 1
        return target

    def probe(self, node_id: str, ack: bool, seq: int) -> ProbeOutcome:
        """Record one direct probe round.

        ack=True  -> member stays/confirmed ALIVE.
        ack=False -> member marked SUSPECT (incarnation unchanged).
        """
        nid = _check_node_id(node_id)
        if isinstance(ack, bool) is False:
            raise TypeError(f"ack must be a bool, got {type(ack).__name__}")
        seq = _check_seq(seq)
        member = self._members.get(nid)
        if member is None:
            raise SwimError(f"unknown member: {nid}")
        if member.status is MemberStatus.FAILED:
            raise SwimError(f"cannot probe failed member: {nid}")
        if ack:
            outcome = MemberStatus.ALIVE
            if member.status is not MemberStatus.ALIVE:
                self._set_status(nid, MemberStatus.ALIVE, member.incarnation, seq)
        else:
            outcome = MemberStatus.SUSPECT
            if member.status is MemberStatus.ALIVE:
                self._set_status(nid, MemberStatus.SUSPECT, member.incarnation, seq)
        return ProbeOutcome(nid, ack, outcome, seq)

    def probe_indirect(
        self, node_id: str, via: Sequence[str], ack: bool, seq: int
    ) -> ProbeOutcome:
        """Record one indirect probe round through ``via`` members.

        SWIM asks up to k other members to probe the target on our
        behalf; an ack through any of them clears the suspicion.
        """
        nid = _check_node_id(node_id)
        if isinstance(ack, bool) is False:
            raise TypeError(f"ack must be a bool, got {type(ack).__name__}")
        seq = _check_seq(seq)
        if not isinstance(via, Sequence) or isinstance(via, (str, bytes)):
            raise TypeError("via must be a sequence of node ids")
        via_ids = [_check_node_id(v, "via entry") for v in via]
        if len(via_ids) > self._indirect_probe_k:
            raise SwimError(
                f"too many indirect probers: {len(via_ids)} > {self._indirect_probe_k}"
            )
        for v in via_ids:
            if v == self._self_id or v == nid:
                raise SwimError(f"invalid indirect prober: {v}")
            if v not in self._members:
                raise SwimError(f"unknown indirect prober: {v}")
        # Same state transition as a direct probe.
        return self.probe(nid, ack, seq)

    def suspect(self, node_id: str, seq: int) -> SwimMember:
        """Mark a member SUSPECT directly (e.g. transport-level hint)."""
        nid = _check_node_id(node_id)
        seq = _check_seq(seq)
        member = self._members.get(nid)
        if member is None:
            raise SwimError(f"unknown member: {nid}")
        if member.status is MemberStatus.FAILED:
            raise SwimError(f"cannot suspect failed member: {nid}")
        if member.status is MemberStatus.ALIVE:
            self._set_status(nid, MemberStatus.SUSPECT, member.incarnation, seq)
        return self._members[nid]

    def confirm_failed(self, node_id: str, seq: int) -> SwimMember:
        """SUSPECT -> FAILED, only after the suspect timeout elapsed.

        Fail-closed: raises unless the member is SUSPECT *and*
        ``seq >= suspect_seq + suspect_timeout_seqs``.
        """
        nid = _check_node_id(node_id)
        seq = _check_seq(seq)
        member = self._members.get(nid)
        if member is None:
            raise SwimError(f"unknown member: {nid}")
        if member.status is not MemberStatus.SUSPECT:
            raise SwimError(
                f"can only confirm a suspect member, {nid} is {member.status.value}"
            )
        if seq < member.status_seq + self._suspect_timeout_seqs:
            raise SwimError(
                f"suspect timeout not elapsed for {nid}: "
                f"need seq >= {member.status_seq + self._suspect_timeout_seqs}"
            )
        self._set_status(nid, MemberStatus.FAILED, member.incarnation, seq)
        return self._members[nid]

    def refute_self(self, seq: int) -> MembershipUpdate:
        """Bump our own incarnation and gossip ALIVE (suspicion refuted).

        A node that learns it is suspected refutes by incrementing its
        incarnation: higher incarnation overrides every older view.
        """
        seq = _check_seq(seq)
        update = self._updates.get(self._self_id)
        incarnation = (update.incarnation if update else 0) + 1
        fresh = MembershipUpdate(self._self_id, MemberStatus.ALIVE, incarnation, seq, 0)
        self._updates[self._self_id] = fresh
        return fresh

    # -- gossip ----------------------------------------------------------

    def _max_gossip_rounds(self) -> int:
        n = max(1, len(self._members) + 1)  # members plus self
        return max(1, math.ceil(self._gossip_lambda * math.log2(n)))

    def disseminate(self, seq: int) -> tuple[MembershipUpdate, ...]:
        """Select up to ``piggyback_limit`` updates to piggyback.

        Only updates below the gossip budget are eligible; each selected
        update's ``gossip_count`` increments. Deterministic order
        (sorted by node id).
        """
        seq = _check_seq(seq)
        budget = self._max_gossip_rounds()
        eligible = sorted(
            (u for u in self._updates.values() if u.gossip_count < budget),
            key=lambda u: u.node_id,
        )[: self._piggyback_limit]
        out = []
        for u in eligible:
            bumped = MembershipUpdate(
                u.node_id, u.status, u.incarnation, u.origin_seq, u.gossip_count + 1
            )
            self._updates[u.node_id] = bumped
            out.append(bumped)
        return tuple(out)

    def receive_gossip(
        self, updates: Sequence[MembershipUpdate | Mapping], seq: int
    ) -> GossipReceipt:
        """Merge incoming gossip into the local view.

        Precedence (SWIM): higher incarnation wins; at equal
        incarnation, higher severity wins (FAILED > SUSPECT > ALIVE).
        A gossip about self with incarnation >= ours sets
        ``self_suspected`` so the host can call ``refute_self``.
        """
        seq = _check_seq(seq)
        if not isinstance(updates, Sequence) or isinstance(updates, (str, bytes)):
            raise TypeError("updates must be a sequence of MembershipUpdate")
        applied: list[str] = []
        ignored: list[str] = []
        self_suspected = False
        for raw in updates:
            update = self._coerce_update(raw)
            nid = update.node_id
            if nid == self._self_id:
                mine = self._updates.get(self._self_id)
                my_inc = mine.incarnation if mine else 0
                if (update.status is MemberStatus.SUSPECT
                        and update.incarnation >= my_inc):
                    self_suspected = True
                ignored.append(nid)
                continue
            member = self._members.get(nid)
            if member is None:
                # Unknown member joins at the gossiped state.
                self._members[nid] = SwimMember(
                    nid, update.status, update.incarnation, seq
                )
                self._record_update(nid, update.status, update.incarnation, seq)
                applied.append(nid)
                continue
            if update.incarnation > member.incarnation:
                self._set_status(nid, update.status, update.incarnation, seq)
                applied.append(nid)
            elif update.incarnation == member.incarnation and (
                _STATUS_SEVERITY[update.status] > _STATUS_SEVERITY[member.status]
            ):
                self._set_status(nid, update.status, update.incarnation, seq)
                applied.append(nid)
            else:
                ignored.append(nid)
        return GossipReceipt(tuple(applied), tuple(ignored), self_suspected, seq)

    # -- internals ---------------------------------------------------------

    def _set_status(
        self, node_id: str, status: MemberStatus, incarnation: int, seq: int
    ) -> None:
        self._members[node_id] = SwimMember(node_id, status, incarnation, seq)
        self._record_update(node_id, status, incarnation, seq)

    def _record_update(
        self, node_id: str, status: MemberStatus, incarnation: int, seq: int
    ) -> None:
        # Fresh news resets the gossip budget so it spreads again.
        self._updates[node_id] = MembershipUpdate(
            node_id, status, incarnation, seq, 0
        )

    @staticmethod
    def _coerce_update(raw: object) -> MembershipUpdate:
        if isinstance(raw, MembershipUpdate):
            return raw
        if isinstance(raw, Mapping):
            try:
                return MembershipUpdate(
                    node_id=raw["node_id"],
                    status=raw["status"],
                    incarnation=raw["incarnation"],
                    origin_seq=raw["origin_seq"],
                    gossip_count=raw.get("gossip_count", 0),
                )
            except KeyError as exc:
                raise SwimError(f"gossip update missing key: {exc}") from exc
        raise TypeError(
            f"gossip update must be MembershipUpdate or mapping, "
            f"got {type(raw).__name__}"
        )


def swim_audit_event(
    kind: str, node_id: str, seq: int, detail: str = ""
) -> dict:
    """Build an ``audit.ndjson/1``-shaped audit record for a SWIM event."""
    if kind not in _EVENT_KINDS:
        raise ValueError(f"unknown swim event kind: {kind!r}")
    nid = _check_node_id(node_id, "node_id")
    seq = _check_seq(seq, "seq")
    if not isinstance(detail, str):
        raise TypeError("detail must be a string")
    return {
        "event": "audit.ndjson/1",
        "kind": kind,
        "node_id": nid,
        "seq": seq,
        "detail": detail[:200],
        "schema": SWIM_PROTOCOL_SCHEMA,
    }


def main() -> None:
    """Self-check: probe -> suspect -> gossip -> refute -> fail."""
    node = SwimNode("n0", indirect_probe_k=2, suspect_timeout_seqs=3)
    node.add_member("n1", seq=1)
    node.add_member("n2", seq=1)

    # Direct probe failure suspects n1.
    out = node.probe("n1", ack=False, seq=2)
    assert out.outcome is MemberStatus.SUSPECT
    assert node.suspect_members() == ("n1",)

    # Gossip carries the suspicion (piggybacked).
    piggy = node.disseminate(seq=3)
    assert any(u.node_id == "n1" and u.status is MemberStatus.SUSPECT for u in piggy)

    # n1 refutes with a higher incarnation; the merge accepts it.
    refute = MembershipUpdate("n1", MemberStatus.ALIVE, 1, 4, 0)
    receipt = node.receive_gossip([refute], seq=5)
    assert receipt.applied == ("n1",)
    assert node.alive_members() == ("n1", "n2")

    # n2 goes suspect and the timeout elapses -> FAILED.
    node.probe("n2", ack=False, seq=6)
    try:
        node.confirm_failed("n2", seq=7)
        raise AssertionError("timeout gate should have refused")
    except SwimError:
        pass
    node.confirm_failed("n2", seq=9)
    assert node.failed_members() == ("n2",)

    print("swim-protocol OK: probe, gossip, refute, timeout-gated fail")


if __name__ == "__main__":
    main()
