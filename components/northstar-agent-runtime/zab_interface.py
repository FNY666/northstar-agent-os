"""ZooKeeper atomic broadcast (Zab) interface: proposal/ack/commit bookkeeping.

Research motivation: Zab (Junqueira, Reed, Serafini, DSN 2011) is the
crash-recovery atomic broadcast behind ZooKeeper -- the protocol a fleet
of agent coordinators would use to agree on one totally ordered stream of
state changes (a fleet config update, a global budget release, the
audit-head anchor) despite leader failures. This module pins the
mechanical bookkeeping of Zab's *broadcast phase* that does *not*
require a network:

- ``make_zxid(epoch, counter)`` -- mints a 64-bit ZooKeeper transaction
  id. The high 32 bits are the epoch (the leader's term), the low 32
  bits are the per-epoch counter. ZXIDs order by epoch first, then
  counter: ``compare_zxid`` / ``zxid_epoch`` / ``zxid_counter``.
- Leader: ``propose(value, seq)`` pins a value (by digest) under the
  next ZXID of the node's current epoch, ``receive_ack(ack)`` records
  follower acknowledgements, ``commit_ready(zxid)`` checks the quorum.
- Follower: ``receive_proposal(proposal)`` records a leader's proposal,
  ``ack(zxid, seq)`` mints a frozen ack for a *received* proposal only,
  ``commit(zxid, seq)`` marks a zxid committed when the leader's COMMIT
  arrives.

Zab safety invariants enforced locally:

- ZXID ordering: a follower never acks or commits a zxid that is not
  strictly greater than the last zxid it accepted (no gaps, no rewinds).
  ``propose`` on the leader never reuses a counter within an epoch.
- Epoch monotonicity: ``set_epoch`` refuses to move the epoch backwards;
  a new epoch resets the counter to zero (a new leader's first zxid is
  ``epoch:0``).
- Value binding: the proposal pins ``value_digest`` at propose time.
  Acks reference the zxid only, so an ack can never smuggle a different
  value in.
- Quorum: only acks from *distinct known* followers count; the quorum is
  ``floor(n/2) + 1`` of the known follower set unless the host sets an
  explicit one. One follower's ack counts once per zxid.

Honest scope:

- This is a single node's *interface bookkeeping*, not a distributed
  protocol. There is no leader election here (see ``leader_election``),
  no discovery/sync phases, no network round-trips, no partition
  detection. A "committed" record means "this node recorded a quorum of
  acks" (leader) or "this node was told to commit" (follower), never
  "the fleet agreed" -- the host's transport and the followers' honesty
  decide that.
- The node never sees raw values: ``propose`` pins ``sha256:`` over
  canonical JSON and keeps only the digest. It cannot become a second
  exfiltration channel.
- Canonical JSON note: values are serialized with ``json.dumps`` sorted
  keys and compact separators. Like every JSON canonicalizer (RFC 8785
  included), integers outside +/-2**53 are serialized as IEEE 754
  doubles and lose precision there -- values carrying such integers
  digest identically. Hosts needing exact large-integer pins must encode
  them as strings or fixed-width hex (the ``secure_aggregation`` module's
  ``_hexint`` shows the pattern).
- ``commit_ready`` returning ``False`` is a policy outcome ("quorum not
  yet reached"), never an error. Malformed inputs raise ``TypeError`` /
  ``ValueError`` / ``ZabError`` fail-closed.
- All seqs are caller-supplied ints (logical clock); no wall-clock is
  read anywhere in this module.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

#: Module version pin.
ZAB_INTERFACE_VERSION = "zab-interface.v1"

#: Schema pin carried by records and audit events.
ZAB_INTERFACE_SCHEMA = "northstar.zab-interface.v1"

#: Audit event kinds.
EVENT_PROPOSED = "zab-proposed"
EVENT_ACKED = "zab-acked"
EVENT_COMMITTED = "zab-committed"
EVENT_COMMIT_REFUSED = "zab-commit-refused"

_EVENT_KINDS = frozenset(
    {EVENT_PROPOSED, EVENT_ACKED, EVENT_COMMITTED, EVENT_COMMIT_REFUSED}
)

#: Zab roles.
ROLE_LEADER = "leader"
ROLE_FOLLOWER = "follower"
_ROLES = frozenset({ROLE_LEADER, ROLE_FOLLOWER})

#: ZXID layout: 64-bit total, high 32 bits epoch, low 32 bits counter.
_ZXID_BITS = 64
_EPOCH_BITS = 32
_COUNTER_BITS = 32
_EPOCH_MASK = (1 << _EPOCH_BITS) - 1
_COUNTER_MASK = (1 << _COUNTER_BITS) - 1
_MAX_ZXID = (1 << _ZXID_BITS) - 1


class ZabError(Exception):
    """Base error for Zab interface failures (fail-closed)."""


class EpochRegressionError(ZabError):
    """Raised when a node is asked to move its epoch backwards."""


class ZxidOrderError(ZabError):
    """Raised when a zxid violates the node's accepted ordering."""


def make_zxid(epoch: int, counter: int) -> int:
    """Mint a 64-bit zxid from epoch (high 32) and counter (low 32)."""
    epoch = _check_epoch(epoch)
    counter = _check_counter(counter)
    return (epoch << _COUNTER_BITS) | counter


def zxid_epoch(zxid: int) -> int:
    """Return the epoch (high 32 bits) of a zxid."""
    _check_zxid(zxid)
    return (zxid >> _COUNTER_BITS) & _EPOCH_MASK


def zxid_counter(zxid: int) -> int:
    """Return the counter (low 32 bits) of a zxid."""
    _check_zxid(zxid)
    return zxid & _COUNTER_MASK


def compare_zxid(a: int, b: int) -> int:
    """Order two zxids: -1 if a < b, 0 if equal, 1 if a > b.

    Ordering is by epoch first, then counter -- the plain integer
    comparison on the 64-bit value implements exactly this, but the
    explicit form documents the invariant.
    """
    ea, ca = zxid_epoch(a), zxid_counter(a)
    eb, cb = zxid_epoch(b), zxid_counter(b)
    if ea != eb:
        return -1 if ea < eb else 1
    if ca != cb:
        return -1 if ca < cb else 1
    return 0


def _check_epoch(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"epoch must be int, got {type(value).__name__}")
    if value < 0 or value > _EPOCH_MASK:
        raise ValueError(f"epoch out of range [0, 2**32-1]: {value}")
    return value


def _check_counter(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"counter must be int, got {type(value).__name__}")
    if value < 0 or value > _COUNTER_MASK:
        raise ValueError(f"counter out of range [0, 2**32-1]: {value}")
    return value


def _check_zxid(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"zxid must be int, got {type(value).__name__}")
    if value < 0 or value > _MAX_ZXID:
        raise ValueError(f"zxid out of range [0, 2**64-1]: {value}")
    return value


def _check_node_id(value: object, name: str = "node_id") -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{name} must be a non-empty str")
    return value


def _check_seq(value: object, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative: {value}")
    return value


def _check_role(value: object) -> str:
    if not isinstance(value, str) or value not in _ROLES:
        raise ValueError(f"role must be one of {sorted(_ROLES)}")
    return value


def _check_digest(value: object, name: str = "digest") -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise TypeError(f"{name} must be a sha256: digest pin")
    hexpart = value[len("sha256:"):]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise TypeError(f"{name} must be sha256: + 64 lowercase hex chars")
    return value


def _canonical(value: Any) -> bytes:
    """Canonical JSON encoding (sorted keys, compact separators)."""
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"value is not JSON-canonicalizable: {exc}") from exc
    return text.encode("utf-8")


def pin_value(value: Any) -> str:
    """Pin a value as a sha256: digest over canonical JSON."""
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class ZabProposal:
    """A leader's broadcast proposal: zxid + value digest pin."""

    zxid: int
    value_digest: str
    leader_id: str
    proposed_seq: int
    schema: str = ZAB_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        _check_zxid(self.zxid)
        _check_digest(self.value_digest)
        _check_node_id(self.leader_id, "leader_id")
        _check_seq(self.proposed_seq)
        if self.schema != ZAB_INTERFACE_SCHEMA:
            raise ValueError(f"bad schema pin: {self.schema}")

    def as_dict(self) -> dict:
        return {
            "zxid": self.zxid,
            "zxid_epoch": zxid_epoch(self.zxid),
            "zxid_counter": zxid_counter(self.zxid),
            "value_digest": self.value_digest,
            "leader_id": self.leader_id,
            "proposed_seq": self.proposed_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ZabAck:
    """A follower's acknowledgement of one zxid."""

    zxid: int
    follower_id: str
    ack_seq: int
    schema: str = ZAB_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        _check_zxid(self.zxid)
        _check_node_id(self.follower_id, "follower_id")
        _check_seq(self.ack_seq)
        if self.schema != ZAB_INTERFACE_SCHEMA:
            raise ValueError(f"bad schema pin: {self.schema}")

    def as_dict(self) -> dict:
        return {
            "zxid": self.zxid,
            "follower_id": self.follower_id,
            "ack_seq": self.ack_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ZabCommitRecord:
    """A committed zxid: the leader's quorum record or the follower's note."""

    zxid: int
    value_digest: str
    acceptors: tuple
    quorum: int
    committed_seq: int
    schema: str = ZAB_INTERFACE_SCHEMA

    def __post_init__(self) -> None:
        _check_zxid(self.zxid)
        _check_digest(self.value_digest)
        if not isinstance(self.acceptors, tuple) or not self.acceptors:
            raise TypeError("acceptors must be a non-empty tuple")
        for acc in self.acceptors:
            _check_node_id(acc, "acceptor")
        if len(set(self.acceptors)) != len(self.acceptors):
            raise ValueError("acceptors must be distinct")
        if isinstance(self.quorum, bool) or not isinstance(self.quorum, int):
            raise TypeError("quorum must be int")
        if self.quorum < 1 or self.quorum > len(self.acceptors):
            raise ValueError("quorum out of range")
        _check_seq(self.committed_seq)
        if self.schema != ZAB_INTERFACE_SCHEMA:
            raise ValueError(f"bad schema pin: {self.schema}")

    def as_dict(self) -> dict:
        return {
            "zxid": self.zxid,
            "zxid_epoch": zxid_epoch(self.zxid),
            "zxid_counter": zxid_counter(self.zxid),
            "value_digest": self.value_digest,
            "acceptors": list(self.acceptors),
            "quorum": self.quorum,
            "committed_seq": self.committed_seq,
            "schema": self.schema,
        }


def quorum_size(n_followers: int) -> int:
    """Standard majority quorum over the follower set."""
    if isinstance(n_followers, bool) or not isinstance(n_followers, int):
        raise TypeError("n_followers must be int")
    if n_followers < 1:
        raise ValueError("need at least one follower")
    return n_followers // 2 + 1


class ZabNode:
    """One Zab participant, leader or follower.

    The node keeps only mechanical bookkeeping: which zxids it proposed
    or received, which acks it recorded, and the highest zxid it has
    accepted/committed. Transport, leader election, and the sync phase
    are the host's job.
    """

    def __init__(
        self,
        node_id: str,
        role: str,
        epoch: int = 0,
        followers: Iterable[str] | None = None,
        quorum: int | None = None,
    ) -> None:
        self._node_id = _check_node_id(node_id)
        self._role = _check_role(role)
        self._epoch = _check_epoch(epoch)
        self._counter = 0
        self._followers: tuple = ()
        self._quorum = 1
        if self._role == ROLE_LEADER:
            flist = list(followers) if followers is not None else []
            for f in flist:
                _check_node_id(f, "follower")
            if len(set(flist)) != len(flist):
                raise ValueError("follower ids must be distinct")
            if self._node_id in flist:
                raise ValueError("leader cannot be its own follower")
            self._followers = tuple(sorted(flist))
            if quorum is None:
                self._quorum = quorum_size(len(flist)) if flist else 1
            else:
                if isinstance(quorum, bool) or not isinstance(quorum, int):
                    raise TypeError("quorum must be int")
                if quorum < 1 or (flist and quorum > len(flist)):
                    raise ValueError("quorum out of range")
                self._quorum = quorum
        # bookkeeping
        self._proposals: dict[int, ZabProposal] = {}
        self._received: dict[int, ZabProposal] = {}
        self._acks: dict[int, dict[str, ZabAck]] = {}
        self._committed: dict[int, ZabCommitRecord] = {}
        self._last_accepted: int | None = None

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def role(self) -> str:
        return self._role

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def quorum(self) -> int:
        return self._quorum

    @property
    def followers(self) -> tuple:
        return self._followers

    def set_epoch(self, epoch: int, seq: int) -> None:
        """Move to a new epoch (new leader term). Never backwards."""
        epoch = _check_epoch(epoch)
        _check_seq(seq)
        if epoch < self._epoch:
            raise EpochRegressionError(
                f"epoch regression: {self._epoch} -> {epoch}"
            )
        if epoch > self._epoch:
            self._epoch = epoch
            self._counter = 0

    # -- leader side ----------------------------------------------------

    def propose(self, value: Any, seq: int) -> ZabProposal:
        """Leader: broadcast the next zxid for a value (digest-pinned)."""
        if self._role != ROLE_LEADER:
            raise ZabError("only the leader can propose")
        _check_seq(seq)
        if self._counter >= _COUNTER_MASK:
            raise ZabError("zxid counter exhausted for this epoch")
        zxid = make_zxid(self._epoch, self._counter)
        self._counter += 1
        proposal = ZabProposal(
            zxid=zxid,
            value_digest=pin_value(value),
            leader_id=self._node_id,
            proposed_seq=seq,
        )
        self._proposals[zxid] = proposal
        self._acks.setdefault(zxid, {})
        return proposal

    def receive_ack(self, ack: ZabAck) -> None:
        """Leader: record a follower's ack for a known proposal."""
        if self._role != ROLE_LEADER:
            raise ZabError("only the leader records acks")
        if not isinstance(ack, ZabAck):
            raise TypeError("ack must be a ZabAck")
        if ack.follower_id not in self._followers:
            raise ZabError(f"unknown follower: {ack.follower_id}")
        if ack.zxid not in self._proposals:
            raise ZabError(f"ack for unknown zxid: {ack.zxid}")
        votes = self._acks[ack.zxid]
        if ack.follower_id in votes:
            raise ZabError(
                f"duplicate ack from {ack.follower_id} for zxid {ack.zxid}"
            )
        votes[ack.follower_id] = ack

    def commit_ready(self, zxid: int) -> bool:
        """Leader: True once a quorum of distinct followers acked the zxid."""
        if self._role != ROLE_LEADER:
            raise ZabError("only the leader checks commit readiness")
        _check_zxid(zxid)
        return len(self._acks.get(zxid, {})) >= self._quorum

    def commit(self, zxid: int, seq: int) -> ZabCommitRecord | None:
        """Mint/record a commit for a zxid.

        Leader: mints a commit record once the quorum is reached; returns
        ``None`` (policy outcome) while the quorum is short. Idempotent:
        re-committing returns the stored record.
        Follower: records the leader's COMMIT for a received zxid;
        idempotent as well.
        """
        if self._role == ROLE_LEADER:
            _check_zxid(zxid)
            _check_seq(seq)
            if zxid in self._committed:
                return self._committed[zxid]
            if not self.commit_ready(zxid):
                return None
            proposal = self._proposals[zxid]
            acceptors = tuple(sorted(self._acks[zxid].keys()))
            record = ZabCommitRecord(
                zxid=zxid,
                value_digest=proposal.value_digest,
                acceptors=acceptors,
                quorum=self._quorum,
                committed_seq=seq,
            )
            self._committed[zxid] = record
            self._last_accepted = (
                zxid
                if self._last_accepted is None
                or compare_zxid(zxid, self._last_accepted) > 0
                else self._last_accepted
            )
            return record
        # follower
        _check_zxid(zxid)
        _check_seq(seq)
        if zxid in self._committed:
            return self._committed[zxid]
        proposal = self._received.get(zxid)
        if proposal is None:
            raise ZxidOrderError(
                f"cannot commit zxid never received: {zxid}"
            )
        record = ZabCommitRecord(
            zxid=zxid,
            value_digest=proposal.value_digest,
            acceptors=(self._node_id,),
            quorum=1,
            committed_seq=seq,
        )
        self._committed[zxid] = record
        return record

    def commit_status(self, zxid: int) -> ZabCommitRecord | None:
        """Return the stored commit record for a zxid, if any."""
        _check_zxid(zxid)
        return self._committed.get(zxid)

    def ack_count(self, zxid: int) -> int:
        """Number of distinct follower acks recorded for a zxid."""
        _check_zxid(zxid)
        return len(self._acks.get(zxid, {}))

    # -- follower side --------------------------------------------------

    def receive_proposal(self, proposal: ZabProposal) -> None:
        """Follower: record a leader proposal; enforces zxid ordering."""
        if self._role != ROLE_FOLLOWER:
            raise ZabError("only a follower receives proposals")
        if not isinstance(proposal, ZabProposal):
            raise TypeError("proposal must be a ZabProposal")
        if proposal.zxid in self._received:
            raise ZxidOrderError(
                f"duplicate proposal zxid: {proposal.zxid}"
            )
        if self._last_accepted is not None and compare_zxid(
            proposal.zxid, self._last_accepted
        ) <= 0:
            raise ZxidOrderError(
                f"zxid {proposal.zxid} not greater than last accepted "
                f"{self._last_accepted}"
            )
        self._received[proposal.zxid] = proposal
        self._last_accepted = proposal.zxid

    def ack(self, zxid: int, seq: int) -> ZabAck:
        """Follower: ack a *received* proposal's zxid."""
        if self._role != ROLE_FOLLOWER:
            raise ZabError("only a follower acks")
        _check_zxid(zxid)
        _check_seq(seq)
        if zxid not in self._received:
            raise ZxidOrderError(
                f"cannot ack zxid never received: {zxid}"
            )
        return ZabAck(zxid=zxid, follower_id=self._node_id, ack_seq=seq)

    def last_accepted(self) -> int | None:
        """Highest zxid this node has accepted, or None."""
        return self._last_accepted


def zab_audit_event(kind: str, record: Any, seq: int) -> dict:
    """Shape an audit.ndjson/1-style event for a Zab action."""
    if kind not in _EVENT_KINDS:
        raise ValueError(f"unknown zab event kind: {kind}")
    _check_seq(seq, "audit_seq")
    if not hasattr(record, "as_dict"):
        raise TypeError("record must expose as_dict()")
    return {
        "kind": kind,
        "record": record.as_dict(),
        "audit_seq": seq,
        "schema": ZAB_INTERFACE_SCHEMA,
    }


def main() -> None:
    """Self-check: one leader, one follower, propose -> ack -> commit."""
    leader = ZabNode("n0", ROLE_LEADER, epoch=3, followers=["n1", "n2", "n3"])
    proposal = leader.propose({"config": "v2"}, seq=0)
    assert zxid_epoch(proposal.zxid) == 3
    assert zxid_counter(proposal.zxid) == 0
    follower = ZabNode("n1", ROLE_FOLLOWER)
    follower.receive_proposal(proposal)
    ack1 = follower.ack(proposal.zxid, seq=1)
    leader.receive_ack(ack1)
    assert not leader.commit_ready(proposal.zxid)
    f2 = ZabNode("n2", ROLE_FOLLOWER)
    f2.receive_proposal(proposal)
    leader.receive_ack(f2.ack(proposal.zxid, seq=2))
    assert leader.commit_ready(proposal.zxid)
    record = leader.commit(proposal.zxid, seq=3)
    assert record is not None and record.zxid == proposal.zxid
    # ordering guard
    try:
        follower.receive_proposal(proposal)
    except ZxidOrderError:
        pass
    else:
        raise AssertionError("duplicate proposal must raise")
    print("zab-interface OK: propose, ack, quorum commit, ordering enforced")


if __name__ == "__main__":
    main()
