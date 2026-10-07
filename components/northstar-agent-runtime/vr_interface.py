"""Viewstamped Replication interface: primary/backup bookkeeping.

Research motivation: Viewstamped Replication (Oki & Liskov 1988) is the
primary/backup consensus protocol that Raft later simplified. For a fleet
of agents it answers the concrete question "who speaks for the group when
the primary dies": the new primary is ``new_view % n``, and the new view's
log is the longest log among a quorum, so no committed operation is ever
lost. This module pins the mechanical bookkeeping of VR that does *not*
require a network:

- ``client_request(...)`` -- on the primary only: mints the next
  op-number, appends the op to the local log, returns a frozen ``Prepare``
  message for the host to broadcast.
- ``receive_prepare(prepare)`` -- on a backup: validates the view and the
  op-number sequence, advances the commit number, appends, returns a
  frozen ``PrepareOK`` addressed to the primary.
- ``receive_prepare_ok(ok)`` -- on the primary: counts *distinct* backups
  per op-number; ``quorum_reached(op_number)`` is True once ``f``
  ``PrepareOK``s arrived (``f`` backups + the primary itself = ``f+1`` of
  ``2f+1`` replicas).
- ``commit(up_to_op_number, seq)`` -- executes queued ops in op-number
  order and returns a frozen ``CommitRecord``; the host broadcasts the
  resulting commit number via ``broadcast_commit()``.
- View change: ``start_view_change`` / ``receive_start_view_change`` /
  ``receive_do_view_change`` / ``receive_start_view`` walk the VR view
  change: on ``f`` ``StartViewChange``s for the new view a replica sends
  ``DoViewChange`` to the new primary; on ``f+1`` ``DoViewChange``s
  (including its own) the new primary adopts the longest log and
  broadcasts ``StartView``.

VR safety invariants enforced locally:

- Primary mapping: the primary for ``view`` is ``replica_ids[view % n]``;
  only the primary accepts client requests (``client_request`` raises
  ``VRError`` otherwise).
- Op-number continuity: a backup accepts a ``Prepare`` only when its
  op-number is exactly one past the local log head (gaps raise, replays
  are idempotent acknowledgements, not re-appends).
- Value binding: every message carries a ``sha256:`` digest over its
  canonical body; requests are pinned by digest at receipt time -- the
  node never sees raw request payloads and cannot become a second
  exfiltration channel.
- View monotonicity: messages from older views are rejected; view-change
  messages must name a strictly newer view.
- Longest-log rule: the new primary adopts the log with the largest
  op-number seen among ``f+1`` ``DoViewChange``s, so every op the old
  primary committed survives the view change.

Honest scope:

- This is a single replica's *interface bookkeeping*, not a distributed
  protocol. There is no transport here: the host moves every message and
  enforces timeouts, failure suspicion, and view-change initiation (see
  ``phi_detector`` for failure suspicion and ``leader_election`` for the
  election-rule analogue). A ``CommitRecord`` means "this replica recorded
  a quorum and executed", never "the fleet agreed".
- The node cannot detect a primary that lies consistently (same lie to
  every replica); view change is the host's answer to that.
- ``receive_prepare`` accepts ``commit_number`` piggybacked on the
  ``Prepare`` only when it is ``<=`` the prepare's own op-number; a
  commit announcement beyond the local log raises rather than executing
  ops the replica never saw.
- All seqs are caller-supplied ints (logical clock); no wall-clock is read
  anywhere in this module.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

#: Module version.
VR_INTERFACE_VERSION = "viewstamped-replication.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.viewstamped-replication.v1"

_DIGEST_PREFIX = "sha256:"


class VRError(Exception):
    """Fail-closed error for malformed input or protocol violations."""


class VRStatus(str, Enum):
    """Replica status."""

    NORMAL = "normal"
    VIEW_CHANGE = "view-change"


def _check_int(name: str, value: Any, allow_zero: bool = True) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    if value < 0 or (value == 0 and not allow_zero):
        raise ValueError(f"{name} must be {'>= 0' if allow_zero else '> 0'}")
    return value


def _check_text(name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not value:
        raise ValueError(f"{name} must be non-empty")
    return value


def _canonical(body: Mapping[str, Any]) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _digest(kind: str, body: Mapping[str, Any]) -> str:
    blob = (kind + "\x00" + _canonical(body)).encode("utf-8")
    return _DIGEST_PREFIX + hashlib.sha256(blob).hexdigest()


def _check_digest(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("digest must be a string")
    if not value.startswith(_DIGEST_PREFIX) or len(value) != len(_DIGEST_PREFIX) + 64:
        raise ValueError("digest must be 'sha256:' + 64 lowercase hex chars")
    hexpart = value[len(_DIGEST_PREFIX):]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise ValueError("digest hex must be lowercase")
    return value


@dataclass(frozen=True)
class VRRequest:
    """A client request pinned by digest; the node never sees the payload."""

    request_id: str
    client_id: str
    request_digest: str
    seq: int

    def __post_init__(self) -> None:
        _check_text("request_id", self.request_id)
        _check_text("client_id", self.client_id)
        _check_digest(self.request_digest)
        _check_int("seq", self.seq)

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "client_id": self.client_id,
            "request_digest": self.request_digest,
            "seq": self.seq,
            "schema": SCHEMA_PIN,
        }


def _message(kind: str, **fields: Any) -> "VRMessage":
    digest = _digest(kind, fields)
    return VRMessage(kind=kind, fields=tuple(sorted(fields.items())), digest=digest)


@dataclass(frozen=True)
class VRMessage:
    """A frozen VR protocol message with a digest pin over its body."""

    kind: str
    fields: tuple[tuple[str, Any], ...]
    digest: str

    def body(self) -> dict[str, Any]:
        return dict(self.fields)

    def verify(self) -> bool:
        expected = _digest(self.kind, self.body())
        return hmac.compare_digest(expected, self.digest)

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "body": self.body(), "digest": self.digest}


@dataclass(frozen=True)
class CommitRecord:
    """Proof that this replica executed ops up to ``op_number``."""

    op_number: int
    view: int
    executed_digests: tuple[str, ...]
    committed_seq: int

    def __post_init__(self) -> None:
        _check_int("op_number", self.op_number, allow_zero=False)
        _check_int("view", self.view)
        _check_int("committed_seq", self.committed_seq)
        if not isinstance(self.executed_digests, tuple):
            raise TypeError("executed_digests must be a tuple")
        for d in self.executed_digests:
            _check_digest(d)

    def as_dict(self) -> dict[str, Any]:
        return {
            "op_number": self.op_number,
            "view": self.view,
            "executed_digests": list(self.executed_digests),
            "committed_seq": self.committed_seq,
            "schema": SCHEMA_PIN,
        }


def vr_audit_event(kind: str, record: Mapping[str, Any], seq: int) -> dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for a VR decision."""
    _check_text("kind", kind)
    _check_int("seq", seq)
    if kind not in (
        "prepare-sent",
        "prepare-received",
        "prepare-ok-sent",
        "prepare-ok-received",
        "quorum-reached",
        "committed",
        "view-change-started",
        "start-view-change-received",
        "do-view-change-sent",
        "do-view-change-received",
        "start-view-received",
    ):
        raise ValueError(f"unknown audit kind: {kind}")
    return {
        "kind": kind,
        "record": dict(record),
        "audit_seq": seq,
        "schema": SCHEMA_PIN,
        "version": VR_INTERFACE_VERSION,
    }


class VRNode:
    """One VR replica's state machine. The host moves every message."""

    def __init__(self, node_id: str, replica_ids: tuple[str, ...] | list[str], f: int | None = None):
        _check_text("node_id", node_id)
        if not isinstance(replica_ids, (tuple, list)) or not replica_ids:
            raise TypeError("replica_ids must be a non-empty tuple/list")
        ids = tuple(replica_ids)
        for rid in ids:
            _check_text("replica_id", rid)
        if len(set(ids)) != len(ids):
            raise ValueError("replica_ids must be distinct")
        if node_id not in ids:
            raise ValueError("node_id must be one of replica_ids")
        n = len(ids)
        if f is None:
            f = (n - 1) // 2
        if isinstance(f, bool) or not isinstance(f, int) or f < 0:
            raise TypeError("f must be a non-negative int")
        if 2 * f + 1 > n:
            raise ValueError("need 2f+1 <= n replicas")

        self._node_id = node_id
        self._replicas = ids
        self._f = f
        self._view = 0
        self._status = VRStatus.NORMAL
        self._op_number = 0
        self._commit_number = 0
        self._log: list[VRMessage] = []  # Prepare messages in op-number order
        self._prepare_oks: dict[int, set[str]] = {}  # op_number -> distinct backup ids
        self._vc_seen: dict[int, set[str]] = {}  # new_view -> distinct StartViewChange senders
        self._dvc_seen: dict[int, dict[str, VRMessage]] = {}  # new_view -> sender -> DoViewChange
        self._svc_sent_for: set[int] = set()
        self._dvc_sent_for: set[int] = set()

    # -- views ---------------------------------------------------------
    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def view(self) -> int:
        return self._view

    @property
    def status(self) -> VRStatus:
        return self._status

    @property
    def op_number(self) -> int:
        return self._op_number

    @property
    def commit_number(self) -> int:
        return self._commit_number

    @property
    def f(self) -> int:
        return self._f

    def primary_id(self, view: int | None = None) -> str:
        """The primary for a view is ``replica_ids[view % n]``."""
        v = self._view if view is None else _check_int("view", view)
        return self._replicas[v % len(self._replicas)]

    def is_primary(self) -> bool:
        return self._status == VRStatus.NORMAL and self.primary_id() == self._node_id

    # -- normal operation ----------------------------------------------
    def client_request(self, request_id: str, client_id: str, request_digest: str, seq: int) -> VRMessage:
        """Primary only: log a client op and return the ``Prepare`` to broadcast."""
        if not self.is_primary():
            raise VRError("only the primary accepts client requests")
        req = VRRequest(request_id=request_id, client_id=client_id, request_digest=request_digest, seq=seq)
        self._op_number += 1
        prepare = _message(
            "prepare",
            view=self._view,
            op_number=self._op_number,
            request=req.as_dict(),
            commit_number=self._commit_number,
        )
        self._log.append(prepare)
        self._prepare_oks[self._op_number] = set()
        return prepare

    def _log_head_op(self) -> int:
        return len(self._log)

    def receive_prepare(self, prepare: VRMessage, seq: int) -> VRMessage:
        """Backup only: validate, advance commit number, log, return ``PrepareOK``."""
        _check_int("seq", seq)
        if not isinstance(prepare, VRMessage) or prepare.kind != "prepare":
            raise TypeError("prepare must be a VRMessage of kind 'prepare'")
        if not prepare.verify():
            raise VRError("prepare digest mismatch")
        body = prepare.body()
        if body["view"] != self._view:
            raise VRError("prepare from wrong view")
        if self._status != VRStatus.NORMAL:
            raise VRError("replica is in view change")
        if self.is_primary():
            raise VRError("primary does not receive prepares")
        op_number = body["op_number"]
        if not isinstance(op_number, int) or op_number <= 0:
            raise VRError("bad op_number")
        if op_number == self._log_head_op():
            # Replay of an op we already logged: idempotent acknowledgement.
            return _message("prepare-ok", view=self._view, op_number=op_number, node_id=self._node_id)
        if op_number != self._log_head_op() + 1:
            raise VRError("prepare op-number gap")
        commit_number = body["commit_number"]
        if not isinstance(commit_number, int) or commit_number < 0 or commit_number > op_number:
            raise VRError("bad commit_number")
        self._log.append(prepare)
        self._op_number = op_number
        if commit_number > self._commit_number:
            self._commit_number = commit_number
        return _message("prepare-ok", view=self._view, op_number=op_number, node_id=self._node_id)

    def receive_prepare_ok(self, ok: VRMessage) -> bool:
        """Primary only: record a backup's ``PrepareOK``; True when quorum reached."""
        if not isinstance(ok, VRMessage) or ok.kind != "prepare-ok":
            raise TypeError("ok must be a VRMessage of kind 'prepare-ok'")
        if not ok.verify():
            raise VRError("prepare-ok digest mismatch")
        if not self.is_primary():
            raise VRError("only the primary collects prepare-oks")
        body = ok.body()
        if body["view"] != self._view:
            raise VRError("prepare-ok from wrong view")
        op_number = body["op_number"]
        sender = body["node_id"]
        if op_number not in self._prepare_oks:
            raise VRError("prepare-ok for unknown op-number")
        if sender == self._node_id or sender not in self._replicas:
            raise VRError("prepare-ok from unknown sender")
        self._prepare_oks[op_number].add(sender)
        return len(self._prepare_oks[op_number]) >= self._f

    def quorum_reached(self, op_number: int) -> bool:
        """True once ``f`` distinct backups acked this op-number."""
        _check_int("op_number", op_number, allow_zero=False)
        return len(self._prepare_oks.get(op_number, ())) >= self._f

    def commit(self, up_to_op_number: int, seq: int) -> CommitRecord:
        """Execute queued ops in order; returns the frozen ``CommitRecord``."""
        _check_int("seq", seq)
        _check_int("up_to_op_number", up_to_op_number, allow_zero=False)
        if up_to_op_number > self._op_number:
            raise VRError("cannot commit ops never logged")
        if up_to_op_number <= self._commit_number:
            raise VRError("commit_number cannot move backwards")
        digests = tuple(
            prepare.body()["request"]["request_digest"]
            for prepare in self._log[self._commit_number:up_to_op_number]
        )
        self._commit_number = up_to_op_number
        return CommitRecord(
            op_number=up_to_op_number,
            view=self._view,
            executed_digests=digests,
            committed_seq=seq,
        )

    def broadcast_commit(self) -> VRMessage:
        """Return the ``commit`` announcement the host broadcasts to backups."""
        return _message("commit", view=self._view, commit_number=self._commit_number)

    def receive_commit(self, announcement: VRMessage, seq: int) -> CommitRecord | None:
        """Backup only: apply a commit announcement, executing newly committed ops.

        Returns the ``CommitRecord``, or ``None`` when the announcement
        carries nothing new (idempotent no-op).
        """
        _check_int("seq", seq)
        if not isinstance(announcement, VRMessage) or announcement.kind != "commit":
            raise TypeError("announcement must be a VRMessage of kind 'commit'")
        if not announcement.verify():
            raise VRError("commit digest mismatch")
        body = announcement.body()
        if body["view"] != self._view:
            raise VRError("commit from wrong view")
        commit_number = body["commit_number"]
        if not isinstance(commit_number, int) or commit_number < 0:
            raise VRError("bad commit_number")
        if commit_number > self._op_number:
            raise VRError("commit beyond logged ops")
        if commit_number <= self._commit_number:
            return None  # stale or empty announcement: nothing new to execute
        return self.commit(commit_number, seq)

    # -- view change ----------------------------------------------------
    def start_view_change(self, new_view: int, seq: int) -> VRMessage:
        """Suspect the primary: enter view change and return ``StartViewChange``."""
        _check_int("seq", seq)
        _check_int("new_view", new_view, allow_zero=False)
        if new_view <= self._view:
            raise VRError("new_view must exceed current view")
        self._status = VRStatus.VIEW_CHANGE
        msg = _message("start-view-change", new_view=new_view, node_id=self._node_id)
        self._svc_sent_for.add(new_view)
        return msg

    def receive_start_view_change(self, msg: VRMessage) -> VRMessage | None:
        """On ``f`` distinct senders for the new view, return our ``DoViewChange``."""
        if not isinstance(msg, VRMessage) or msg.kind != "start-view-change":
            raise TypeError("msg must be a VRMessage of kind 'start-view-change'")
        if not msg.verify():
            raise VRError("start-view-change digest mismatch")
        body = msg.body()
        new_view = body["new_view"]
        sender = body["node_id"]
        if not isinstance(new_view, int) or new_view <= self._view:
            raise VRError("start-view-change for stale view")
        if sender not in self._replicas:
            raise VRError("start-view-change from unknown replica")
        if self._status == VRStatus.NORMAL:
            self._status = VRStatus.VIEW_CHANGE
        senders = self._vc_seen.setdefault(new_view, set())
        senders.add(sender)
        if len(senders) >= self._f and new_view not in self._dvc_sent_for:
            self._dvc_sent_for.add(new_view)
            log_digests = [p.digest for p in self._log]
            dvc = _message(
                "do-view-change",
                new_view=new_view,
                node_id=self._node_id,
                log_digests=log_digests,
                op_number=self._op_number,
                commit_number=self._commit_number,
            )
            # A replica always includes its own DoViewChange in the tally.
            self._dvc_seen.setdefault(new_view, {})[self._node_id] = dvc
            return dvc
        return None

    def receive_do_view_change(self, dvc: VRMessage) -> VRMessage | None:
        """New primary only: on ``f+1`` DoViewChanges adopt the longest log.

        Returns the ``StartView`` to broadcast, or ``None`` while the tally
        is still short.
        """
        if not isinstance(dvc, VRMessage) or dvc.kind != "do-view-change":
            raise TypeError("dvc must be a VRMessage of kind 'do-view-change'")
        if not dvc.verify():
            raise VRError("do-view-change digest mismatch")
        body = dvc.body()
        new_view = body["new_view"]
        sender = body["node_id"]
        if not isinstance(new_view, int) or new_view <= self._view:
            raise VRError("do-view-change for stale view")
        if self.primary_id(new_view) != self._node_id:
            raise VRError("only the new primary collects do-view-changes")
        if sender not in self._replicas:
            raise VRError("do-view-change from unknown replica")
        tally = self._dvc_seen.setdefault(new_view, {})
        tally[sender] = dvc
        if len(tally) < self._f + 1:
            return None
        # Longest-log rule: adopt the log with the largest op-number.
        best = max(tally.values(), key=lambda m: (m.body()["op_number"], m.body()["commit_number"]))
        best_body = best.body()
        self._view = new_view
        self._status = VRStatus.NORMAL
        self._op_number = best_body["op_number"]
        self._commit_number = best_body["commit_number"]
        # Keep only the prepares this replica actually has; the host must
        # supply the adopted log bodies before the primary serves new ops.
        self._prepare_oks = {}
        self._vc_seen.pop(new_view, None)
        self._dvc_seen.pop(new_view, None)
        return _message(
            "start-view",
            new_view=new_view,
            op_number=self._op_number,
            commit_number=self._commit_number,
            log_digests=best_body["log_digests"],
        )

    def receive_start_view(self, sv: VRMessage, seq: int) -> bool:
        """Adopt the new view's parameters; True when the view advanced."""
        _check_int("seq", seq)
        if not isinstance(sv, VRMessage) or sv.kind != "start-view":
            raise TypeError("sv must be a VRMessage of kind 'start-view'")
        if not sv.verify():
            raise VRError("start-view digest mismatch")
        body = sv.body()
        new_view = body["new_view"]
        if not isinstance(new_view, int) or new_view <= self._view:
            raise VRError("start-view for stale view")
        if self.primary_id(new_view) != self._node_id and body.get("commit_number", 0) > self._op_number:
            raise VRError("start-view commits beyond known ops")
        self._view = new_view
        self._status = VRStatus.NORMAL
        self._op_number = max(self._op_number, body["op_number"])
        self._commit_number = min(body["commit_number"], self._op_number)
        self._prepare_oks = {}
        return True

    # -- introspection ---------------------------------------------------
    def log_digests(self) -> tuple[str, ...]:
        return tuple(p.digest for p in self._log)

    def snapshot(self) -> dict[str, Any]:
        return {
            "node_id": self._node_id,
            "view": self._view,
            "status": self._status.value,
            "op_number": self._op_number,
            "commit_number": self._commit_number,
            "log_digests": self.log_digests(),
            "schema": SCHEMA_PIN,
            "version": VR_INTERFACE_VERSION,
        }


def main() -> None:
    replicas = ("r0", "r1", "r2")
    primary = VRNode("r0", replicas)
    backup = VRNode("r1", replicas)
    digest = _DIGEST_PREFIX + "ab" * 32

    # Normal operation: request -> prepare -> prepare-ok -> quorum -> commit.
    prepare = primary.client_request("req-1", "client-a", digest, seq=1)
    assert prepare.kind == "prepare" and prepare.verify()
    ok = backup.receive_prepare(prepare, seq=2)
    assert ok.kind == "prepare-ok" and ok.verify()
    assert primary.receive_prepare_ok(ok) is True  # f=1, one backup suffices
    assert primary.quorum_reached(1)
    record = primary.commit(1, seq=3)
    assert record.op_number == 1 and record.executed_digests == (digest,)
    ann = primary.broadcast_commit()
    b_record = backup.receive_commit(ann, seq=4)
    assert b_record.op_number == 1 and b_record.executed_digests == (digest,)

    # View change: r1 suspects r0; view 1's primary is r1 (1 % 3 == 1).
    r1 = VRNode("r1", replicas)
    r2 = VRNode("r2", replicas)
    svc_r1 = r1.start_view_change(1, seq=5)
    svc_r2 = r2.start_view_change(1, seq=6)
    assert svc_r1.kind == "start-view-change" and svc_r1.verify()
    assert r1.status == VRStatus.VIEW_CHANGE
    # f=1: a single distinct StartViewChange sender suffices for DoViewChange.
    dvc_r1 = r1.receive_start_view_change(svc_r2)
    assert dvc_r1 is not None and dvc_r1.kind == "do-view-change" and dvc_r1.verify()
    dvc_r2 = r2.receive_start_view_change(svc_r1)
    assert dvc_r2 is not None and dvc_r2.verify()
    # r1 (the new primary) tallies its own + r2's DoViewChange = f+1.
    start_view = r1.receive_do_view_change(dvc_r2)
    assert start_view is not None and start_view.kind == "start-view" and start_view.verify()
    assert start_view.body()["new_view"] == 1
    assert r1.view == 1 and r1.status == VRStatus.NORMAL
    assert r1.is_primary()
    # A backup adopts the new view from the StartView.
    assert r2.receive_start_view(start_view, seq=7) is True
    assert r2.view == 1 and r2.status == VRStatus.NORMAL
    assert not r2.is_primary()
    print("vr-interface OK: prepare/commit, quorum, view change")


if __name__ == "__main__":
    main()
