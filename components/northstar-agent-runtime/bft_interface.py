"""Byzantine fault tolerance interface: PBFT pre-prepare/prepare/commit bookkeeping.

Research motivation: PBFT (Castro & Liskov 1999) is the canonical
practical Byzantine fault tolerant consensus protocol -- a fleet of
``3f+1`` replicas can agree on one value despite up to ``f`` Byzantine
(arbitrary/malicious) replicas. For agent fleets this is the machinery
behind fleet-level decisions that must survive compromised members: a
fleet kill decision, a global budget release, the audit-head anchor.

This module pins the *mechanical bookkeeping* of the PBFT normal-case
pipeline that does not require a network:

- ``request(client_id, operation, seq)`` -- a client pins a request
  (operation carried by digest only).
- ``pre_prepare_for(view, seq, request)`` -- the primary of ``view``
  mints a ``PrePrepare`` for one (view, seq) slot. One slot, one
  pre-prepare, ever (fail-closed).
- ``receive_pre_prepare(pp)`` -- a backup validates the pre-prepare
  (the claimed primary really is the primary of ``view``; the slot is
  free) and records it.
- ``receive_prepare(p)`` / ``receive_commit(c)`` -- the host feeds
  prepare/commit messages that arrived over the fleet's transport; each
  is validated (known replica, matching view/seq/digest, no duplicates).
- ``is_prepared(view, seq)`` -- true when this node holds the
  pre-prepare plus ``2f`` matching prepares from distinct known replicas
  (the PBFT "prepared" predicate: 2f+1 agreeing including the
  pre-prepare itself).
- ``is_committed(view, seq)`` -- true when prepared *and* ``2f+1``
  matching commits from distinct known replicas are recorded (the PBFT
  "committed-local" predicate).
- ``reply(request, result, seq)`` -- once committed, mints a frozen
  ``Reply`` for the client; returns ``None`` before commit (a reply is a
  policy outcome, never an error).

Byzantine-tolerance math pinned here:

- Replica count: ``n = 3f + 1`` for the configured ``f`` (constructor
  refuses a replica set smaller than that -- running PBFT with fewer
  replicas than the math needs is fail-closed, not best-effort).
- Quorum: ``2f + 1`` distinct known replicas. Any two quorums of a
  ``3f+1`` set intersect in at least ``f+1`` replicas, so at least one
  honest replica saw both -- the classic PBFT intersection argument,
  which is what this bookkeeping protects.

Honest scope:

- This is a single replica's *interface bookkeeping*, not a distributed
  protocol. There is no transport, no view-change protocol, no
  checkpointing, no client retransmission, no timer logic -- the host
  supplies all messages and the ``view`` number. A ``CommitRecord``
  means "this node recorded the PBFT predicates", never "the fleet
  agreed".
- It does not detect Byzantine replicas: a replica whose messages are
  internally consistent passes the bookkeeping. Catching liars is the
  consensus layer's job (quorum intersection), not this ledger's.
- The replica never sees raw operations or results: ``request`` and
  ``reply`` pin ``sha256:`` digests over canonical JSON and keep only
  the digest. It cannot become a second exfiltration channel.
- Canonical JSON note: values are serialized with ``json.dumps`` sorted
  keys and compact separators. Like every JSON canonicalizer (RFC 8785
  included), integers outside +/-2**53 are serialized as IEEE 754
  doubles and lose precision there -- digests over such values collide.
  Hosts needing exact large-integer pins must encode them as strings or
  fixed-width hex (the ``secure_aggregation`` module's ``_hexint`` shows
  the pattern).
- ``is_prepared`` / ``is_committed`` / ``reply`` returning ``None`` /
  ``False`` are policy outcomes ("predicates not yet satisfied"), never
  errors. Malformed inputs raise ``TypeError`` / ``ValueError`` /
  ``BFTError`` fail-closed.
- All seqs are caller-supplied ints (logical clock); no wall-clock is
  read anywhere in this module.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

#: Module version pin.
BFT_INTERFACE_VERSION = "bft-interface.v1"

#: Schema pin carried by records and audit events.
BFT_INTERFACE_SCHEMA = "northstar.bft-interface.v1"

#: Audit event kinds.
EVENT_REQUEST = "bft-request"
EVENT_PRE_PREPARE = "bft-pre-prepare"
EVENT_PREPARED = "bft-prepared"
EVENT_COMMITTED = "bft-committed"
EVENT_REPLY = "bft-reply"
EVENT_REFUSED = "bft-refused"

_EVENT_KINDS = frozenset(
    {
        EVENT_REQUEST,
        EVENT_PRE_PREPARE,
        EVENT_PREPARED,
        EVENT_COMMITTED,
        EVENT_REPLY,
        EVENT_REFUSED,
    }
)

#: Digest prefix for pinned values.
_DIGEST_PREFIX = "sha256:"


class BFTError(Exception):
    """Base error for BFT bookkeeping (fail-closed)."""


class ReplicaSetError(BFTError):
    """Raised when the replica set does not satisfy 3f+1 for the given f."""


class SlotConflictError(BFTError):
    """Raised when a (view, seq) slot is assigned twice."""


class MessageValidationError(BFTError):
    """Raised for a well-typed but inconsistent protocol message."""


def bft_quorum(f: int) -> int:
    """Return the PBFT quorum ``2f + 1``. Fail-closed on malformed input."""
    if isinstance(f, bool) or not isinstance(f, int):
        raise TypeError(f"f must be an int, got {type(f).__name__}")
    if f < 0:
        raise ValueError("f must be >= 0")
    return 2 * f + 1


def bft_replica_count(f: int) -> int:
    """Return the PBFT replica count ``3f + 1``. Fail-closed on malformed input."""
    if isinstance(f, bool) or not isinstance(f, int):
        raise TypeError(f"f must be an int, got {type(f).__name__}")
    if f < 0:
        raise ValueError("f must be >= 0")
    return 3 * f + 1


def _check_node_id(value: object, name: str = "node_id") -> str:
    """Validate a node id: non-empty string, whitespace-stripped."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    node_id = value.strip()
    if not node_id:
        raise ValueError(f"{name} must be non-empty")
    return node_id


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied logical seq: non-negative int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0")
    return value


def _check_view(value: object) -> int:
    """Validate a view number: non-negative int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"view must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError("view must be >= 0")
    return value


def _canonical(value: object) -> str:
    """Canonical JSON encoding (sorted keys, compact separators)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _pin(value: object) -> str:
    """Return ``sha256:<hex>`` over the canonical encoding of ``value``."""
    return _DIGEST_PREFIX + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _check_digest(value: object, name: str = "digest") -> str:
    """Validate a ``sha256:<64 hex>`` digest pin."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) != len(_DIGEST_PREFIX) + 64:
        raise ValueError(f"{name} must be a sha256 digest pin")
    hexpart = value[len(_DIGEST_PREFIX):]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise ValueError(f"{name} must be lowercase hex")
    return value


@dataclass(frozen=True)
class ClientRequest:
    """A client request, pinned by digest (the replica never sees the op)."""

    request_id: str
    client_id: str
    operation_digest: str
    seq: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _check_node_id(self.request_id, "request_id"))
        object.__setattr__(self, "client_id", _check_node_id(self.client_id, "client_id"))
        object.__setattr__(self, "operation_digest", _check_digest(self.operation_digest, "operation_digest"))
        object.__setattr__(self, "seq", _check_seq(self.seq, "seq"))

    def as_dict(self) -> dict:
        return {
            "schema": BFT_INTERFACE_SCHEMA,
            "request_id": self.request_id,
            "client_id": self.client_id,
            "operation_digest": self.operation_digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class PrePrepare:
    """Primary's pre-prepare for one (view, seq) slot."""

    view: int
    seq: int
    request_id: str
    digest: str
    primary_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "view", _check_view(self.view))
        object.__setattr__(self, "seq", _check_seq(self.seq, "seq"))
        object.__setattr__(self, "request_id", _check_node_id(self.request_id, "request_id"))
        object.__setattr__(self, "digest", _check_digest(self.digest, "digest"))
        object.__setattr__(self, "primary_id", _check_node_id(self.primary_id, "primary_id"))

    def slot(self) -> tuple[int, int]:
        return (self.view, self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": BFT_INTERFACE_SCHEMA,
            "view": self.view,
            "seq": self.seq,
            "request_id": self.request_id,
            "digest": self.digest,
            "primary_id": self.primary_id,
        }


@dataclass(frozen=True)
class Prepare:
    """A replica's prepare vote for (view, seq, digest)."""

    view: int
    seq: int
    digest: str
    replica_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "view", _check_view(self.view))
        object.__setattr__(self, "seq", _check_seq(self.seq, "seq"))
        object.__setattr__(self, "digest", _check_digest(self.digest, "digest"))
        object.__setattr__(self, "replica_id", _check_node_id(self.replica_id, "replica_id"))

    def as_dict(self) -> dict:
        return {
            "schema": BFT_INTERFACE_SCHEMA,
            "view": self.view,
            "seq": self.seq,
            "digest": self.digest,
            "replica_id": self.replica_id,
        }


@dataclass(frozen=True)
class CommitMessage:
    """A replica's commit vote for (view, seq, digest)."""

    view: int
    seq: int
    digest: str
    replica_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "view", _check_view(self.view))
        object.__setattr__(self, "seq", _check_seq(self.seq, "seq"))
        object.__setattr__(self, "digest", _check_digest(self.digest, "digest"))
        object.__setattr__(self, "replica_id", _check_node_id(self.replica_id, "replica_id"))

    def as_dict(self) -> dict:
        return {
            "schema": BFT_INTERFACE_SCHEMA,
            "view": self.view,
            "seq": self.seq,
            "digest": self.digest,
            "replica_id": self.replica_id,
        }


@dataclass(frozen=True)
class CommitRecord:
    """What ``is_committed`` certifies: predicates satisfied for a slot."""

    view: int
    seq: int
    digest: str
    request_id: str
    quorum: int
    prepares: tuple[str, ...]
    commits: tuple[str, ...]
    committed_seq: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "view", _check_view(self.view))
        object.__setattr__(self, "seq", _check_seq(self.seq, "seq"))
        object.__setattr__(self, "digest", _check_digest(self.digest, "digest"))
        object.__setattr__(self, "request_id", _check_node_id(self.request_id, "request_id"))
        object.__setattr__(self, "committed_seq", _check_seq(self.committed_seq, "committed_seq"))

    def as_dict(self) -> dict:
        return {
            "schema": BFT_INTERFACE_SCHEMA,
            "view": self.view,
            "seq": self.seq,
            "digest": self.digest,
            "request_id": self.request_id,
            "quorum": self.quorum,
            "prepares": list(self.prepares),
            "commits": list(self.commits),
            "committed_seq": self.committed_seq,
        }


@dataclass(frozen=True)
class Reply:
    """A replica's reply to the client once a slot is committed."""

    view: int
    seq: int
    client_id: str
    request_id: str
    result_digest: str
    replica_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "view", _check_view(self.view))
        object.__setattr__(self, "seq", _check_seq(self.seq, "seq"))
        object.__setattr__(self, "client_id", _check_node_id(self.client_id, "client_id"))
        object.__setattr__(self, "request_id", _check_node_id(self.request_id, "request_id"))
        object.__setattr__(self, "result_digest", _check_digest(self.result_digest, "result_digest"))
        object.__setattr__(self, "replica_id", _check_node_id(self.replica_id, "replica_id"))

    def as_dict(self) -> dict:
        return {
            "schema": BFT_INTERFACE_SCHEMA,
            "view": self.view,
            "seq": self.seq,
            "client_id": self.client_id,
            "request_id": self.request_id,
            "result_digest": self.result_digest,
            "replica_id": self.replica_id,
        }


class BFTNode:
    """One replica's PBFT normal-case bookkeeping.

    ``node_id`` is this replica; ``replicas`` is the full replica set
    (must contain ``node_id`` and satisfy ``len(replicas) >= 3f + 1``).
    """

    def __init__(self, node_id: str, f: int, replicas: Iterable[str]) -> None:
        self._node_id = _check_node_id(node_id)
        self._f = _checked_f(f)
        replica_ids = [_check_node_id(r, "replica_id") for r in replicas]
        if self._node_id not in replica_ids:
            raise ReplicaSetError("node_id must be a member of replicas")
        if len(set(replica_ids)) != len(replica_ids):
            raise ReplicaSetError("replica ids must be distinct")
        self._replicas = frozenset(replica_ids)
        if len(self._replicas) < bft_replica_count(self._f):
            raise ReplicaSetError(
                f"need >= {bft_replica_count(self._f)} replicas for f={self._f}, "
                f"got {len(self._replicas)}"
            )
        self._requests: dict[str, ClientRequest] = {}
        self._pre_prepares: dict[tuple[int, int], PrePrepare] = {}
        self._prepares: dict[tuple[int, int, str], set[str]] = {}
        self._commits: dict[tuple[int, int, str], set[str]] = {}

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def f(self) -> int:
        return self._f

    @property
    def quorum(self) -> int:
        return bft_quorum(self._f)

    @property
    def replica_count(self) -> int:
        return len(self._replicas)

    def is_primary(self, view: int) -> bool:
        """True iff this node is the primary of ``view`` (round-robin)."""
        _check_view(view)
        return sorted(self._replicas)[view % len(self._replicas)] == self._node_id

    def primary_of(self, view: int) -> str:
        """Return the primary replica id of ``view``."""
        _check_view(view)
        return sorted(self._replicas)[view % len(self._replicas)]

    # -- client request -------------------------------------------------

    def request(self, client_id: str, operation: Mapping[str, object], seq: int) -> ClientRequest:
        """Pin a client request; returns the frozen ``ClientRequest``.

        The operation is carried by digest only -- the replica never sees
        the raw operation.
        """
        client_id = _check_node_id(client_id, "client_id")
        seq = _check_seq(seq, "seq")
        if not isinstance(operation, Mapping):
            raise TypeError(f"operation must be a mapping, got {type(operation).__name__}")
        req = ClientRequest(
            request_id=f"req-{client_id}-{seq}",
            client_id=client_id,
            operation_digest=_pin({"client_id": client_id, "operation": dict(operation)}),
            seq=seq,
        )
        self._requests[req.request_id] = req
        return req

    # -- pre-prepare (primary) ------------------------------------------

    def pre_prepare_for(self, view: int, seq: int, req: ClientRequest) -> PrePrepare:
        """Primary mints the pre-prepare for one (view, seq) slot.

        Fail-closed: raises unless this node is the primary of ``view``
        and the slot is free.
        """
        view = _check_view(view)
        seq = _check_seq(seq, "seq")
        if not isinstance(req, ClientRequest):
            raise TypeError(f"req must be a ClientRequest, got {type(req).__name__}")
        if not self.is_primary(view):
            raise MessageValidationError(
                f"node {self._node_id} is not the primary of view {view}"
            )
        slot = (view, seq)
        if slot in self._pre_prepares:
            raise SlotConflictError(f"slot (view={view}, seq={seq}) already assigned")
        pp = PrePrepare(
            view=view,
            seq=seq,
            request_id=req.request_id,
            digest=req.operation_digest,
            primary_id=self._node_id,
        )
        self._pre_prepares[slot] = pp
        return pp

    def receive_pre_prepare(self, pp: PrePrepare) -> bool:
        """Backup accepts a pre-prepare; returns True on acceptance.

        Fail-closed: raises on wrong primary, duplicate slot, or
        non-PrePrepare input.
        """
        if not isinstance(pp, PrePrepare):
            raise TypeError(f"pp must be a PrePrepare, got {type(pp).__name__}")
        if pp.primary_id != self.primary_of(pp.view):
            raise MessageValidationError(
                f"{pp.primary_id} is not the primary of view {pp.view}"
            )
        slot = pp.slot()
        if slot in self._pre_prepares:
            raise SlotConflictError(f"slot (view={pp.view}, seq={pp.seq}) already assigned")
        self._pre_prepares[slot] = pp
        return True

    # -- prepare --------------------------------------------------------

    def receive_prepare(self, p: Prepare) -> bool:
        """Record a prepare vote; returns True if the slot is now prepared.

        The replica's own prepare is recorded like any other (a backup
        broadcasts its own prepare in PBFT); the ``is_prepared``
        predicate counts only *other* replicas' votes.
        Fail-closed: unknown replica, unknown slot (no pre-prepare), or
        digest mismatch with the pre-prepare all raise.
        """
        if not isinstance(p, Prepare):
            raise TypeError(f"p must be a Prepare, got {type(p).__name__}")
        if p.replica_id not in self._replicas:
            raise MessageValidationError(f"unknown replica {p.replica_id}")
        pp = self._pre_prepares.get((p.view, p.seq))
        if pp is None:
            raise MessageValidationError(
                f"no pre-prepare for slot (view={p.view}, seq={p.seq})"
            )
        if p.digest != pp.digest:
            raise MessageValidationError("prepare digest does not match pre-prepare digest")
        key = (p.view, p.seq, pp.digest)
        voters = self._prepares.setdefault(key, set())
        if p.replica_id in voters:
            raise MessageValidationError(f"duplicate prepare from {p.replica_id}")
        voters.add(p.replica_id)
        return self.is_prepared(p.view, p.seq)

    def is_prepared(self, view: int, seq: int) -> bool:
        """PBFT prepared predicate: pre-prepare + 2f matching *other* prepares."""
        view = _check_view(view)
        seq = _check_seq(seq, "seq")
        pp = self._pre_prepares.get((view, seq))
        if pp is None:
            return False
        voters = self._prepares.get((view, seq, pp.digest), set())
        others = voters - {self._node_id}
        return len(others) >= 2 * self._f

    # -- commit ---------------------------------------------------------

    def receive_commit(self, c: CommitMessage) -> bool:
        """Record a commit vote; returns True if the slot is now committed.

        Same fail-closed rules as ``receive_prepare``.
        """
        if not isinstance(c, CommitMessage):
            raise TypeError(f"c must be a CommitMessage, got {type(c).__name__}")
        if c.replica_id not in self._replicas:
            raise MessageValidationError(f"unknown replica {c.replica_id}")
        pp = self._pre_prepares.get((c.view, c.seq))
        if pp is None:
            raise MessageValidationError(
                f"no pre-prepare for slot (view={c.view}, seq={c.seq})"
            )
        if c.digest != pp.digest:
            raise MessageValidationError("commit digest does not match pre-prepare digest")
        key = (c.view, c.seq, pp.digest)
        voters = self._commits.setdefault(key, set())
        if c.replica_id in voters:
            raise MessageValidationError(f"duplicate commit from {c.replica_id}")
        voters.add(c.replica_id)
        return self.is_committed(c.view, c.seq)

    def is_committed(self, view: int, seq: int) -> bool:
        """PBFT committed-local predicate: prepared + 2f+1 matching commits."""
        view = _check_view(view)
        seq = _check_seq(seq, "seq")
        if not self.is_prepared(view, seq):
            return False
        pp = self._pre_prepares[view, seq]
        voters = self._commits.get((view, seq, pp.digest), set())
        return len(voters) >= bft_quorum(self._f)

    def commit_record(self, view: int, seq: int, committed_seq: int) -> CommitRecord | None:
        """Frozen ``CommitRecord`` once committed, else ``None`` (policy)."""
        view = _check_view(view)
        seq = _check_seq(seq, "seq")
        committed_seq = _check_seq(committed_seq, "committed_seq")
        if not self.is_committed(view, seq):
            return None
        pp = self._pre_prepares[view, seq]
        return CommitRecord(
            view=view,
            seq=seq,
            digest=pp.digest,
            request_id=pp.request_id,
            quorum=bft_quorum(self._f),
            prepares=tuple(sorted(self._prepares[(view, seq, pp.digest)])),
            commits=tuple(sorted(self._commits[(view, seq, pp.digest)])),
            committed_seq=committed_seq,
        )

    # -- reply ----------------------------------------------------------

    def reply(self, req: ClientRequest, result: Mapping[str, object], view: int, seq: int) -> Reply | None:
        """Mint a client reply once the slot is committed; ``None`` before.

        The result is carried by digest only.
        """
        if not isinstance(req, ClientRequest):
            raise TypeError(f"req must be a ClientRequest, got {type(req).__name__}")
        if not isinstance(result, Mapping):
            raise TypeError(f"result must be a mapping, got {type(result).__name__}")
        view = _check_view(view)
        seq = _check_seq(seq, "seq")
        if not self.is_committed(view, seq):
            return None
        return Reply(
            view=view,
            seq=seq,
            client_id=req.client_id,
            request_id=req.request_id,
            result_digest=_pin({"request_id": req.request_id, "result": dict(result)}),
            replica_id=self._node_id,
        )


def _checked_f(f: int) -> int:
    """Validate f (kept as a helper so BFTNode stays readable)."""
    if isinstance(f, bool) or not isinstance(f, int):
        raise TypeError(f"f must be an int, got {type(f).__name__}")
    if f < 0:
        raise ValueError("f must be >= 0")
    return f


def bft_audit_event(kind: str, record: object, seq: int) -> dict:
    """Shape an ``audit.ndjson/1`` record for a BFT event. Fail-closed."""
    if kind not in _EVENT_KINDS:
        raise ValueError(f"unknown BFT event kind: {kind!r}")
    seq = _check_seq(seq, "audit_seq")
    body = record.as_dict() if hasattr(record, "as_dict") else {"record": str(record)}
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "body": body,
    }


def main() -> None:
    """Self-check: drive a 4-replica (f=1) slot through the full pipeline."""
    replicas = ["r0", "r1", "r2", "r3"]
    nodes = {r: BFTNode(r, 1, replicas) for r in replicas}
    assert bft_quorum(1) == 3 and bft_replica_count(1) == 4

    req = nodes["r0"].request("client-1", {"op": "kill", "target": "fleet"}, seq=1)
    pp = nodes["r0"].pre_prepare_for(view=0, seq=1, req=req)
    for r in ("r1", "r2", "r3"):
        assert nodes[r].receive_pre_prepare(pp) is True

    prepares = [Prepare(view=0, seq=1, digest=pp.digest, replica_id=r) for r in replicas]
    prepared_flags = [nodes["r1"].receive_prepare(p) for p in prepares]
    # own prepare (r1) and the first other (r0) do not yet reach 2f=2 others
    assert prepared_flags == [False, False, True, True]
    assert nodes["r1"].is_prepared(0, 1) is True

    commits = [CommitMessage(view=0, seq=1, digest=pp.digest, replica_id=r) for r in replicas]
    committed_flags = [nodes["r1"].receive_commit(c) for c in commits]
    # 2f+1 = 3 commits needed; the third (r2) trips it
    assert committed_flags == [False, False, True, True]
    assert nodes["r1"].is_committed(0, 1) is True
    rec = nodes["r1"].commit_record(0, 1, committed_seq=9)
    assert rec is not None and rec.quorum == 3
    reply = nodes["r1"].reply(req, {"killed": True}, view=0, seq=1)
    assert reply is not None and reply.client_id == "client-1"
    print("bft-interface OK: request -> pre-prepare -> prepared(2f) -> committed(2f+1) -> reply")


if __name__ == "__main__":
    main()
