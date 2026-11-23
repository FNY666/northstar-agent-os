"""Byzantine agreement: PBFT-shaped three-phase commit bookkeeping.

Research note: Practical Byzantine Fault Tolerance (Castro & Liskov,
1999, "Practical Byzantine Fault Tolerance and Proactive Recovery")
orders client requests through a primary and backups in three phases::

    PRE-PREPARE  primary  ->  backups   (proposal for (view, seq))
    PREPARE      backup   ->  all       (endorse the proposal)
    COMMIT       replica  ->  all       (confirm the prepared certificate)

With ``n = 3f + 1`` replicas and ``f`` Byzantine faults tolerated, a
replica marks a request *prepared* when it holds the pre-prepare plus
``2f`` matching prepares (a prepare certificate), and *committed* when it
has collected ``2f + 1`` matching commits (a commit certificate). Quorum
intersection then guarantees two committed requests never order
differently.

* **Deterministic state machine** — no sockets, no timers, no wall-clock:
  every mutation takes a caller-supplied strictly increasing ``seq``
  (monotonic logical time). Failed mutations consume their seq
  (fail-closed ledger position).
* **Fail-closed** — malformed ids, unknown replicas, digest mismatches,
  duplicate votes, and out-of-order phases raise; a refused mutation
  books a ``byzantine-agreement.rejected`` audit row.
* **Digest-pinned payloads** — values are booked by ``sha256:`` digest
  only; raw payloads never enter records or the audit boundary.
* **Honest scope** — this module books *host-reported* votes. It cannot
  prove a replica is honest, observe a wire, or force backups to vote;
  a ``committed`` verdict means "2f+1 matching commits were booked here",
  never "the fleet agreed". Replay protection is the host's job.

API::

    ba = ByzantineAgreement(replicas=4)          # f = 1
    ba.preprepare("req-1", view=0, seq=1,
                  request_digest="sha256:" + "ab" * 32)
    ba.prepare("req-1", replica="r1", seq=2,
               request_digest="sha256:" + "ab" * 32)   # x2f
    ba.commit("req-1", replica="r0", seq=5,
              request_digest="sha256:" + "ab" * 32)    # x2f+1
    ba.status("req-1", seq=9)  # -> "committed"
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: Module version.
BYZANTINE_AGREEMENT_VERSION = "byzantine-agreement.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.byzantine-agreement.v1"

#: Audit schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Audit kinds.
KIND_PREPREPARED = "byzantine-agreement.preprepared"
KIND_PREPARED = "byzantine-agreement.prepared"
KIND_COMMITTED = "byzantine-agreement.committed"
KIND_REJECTED = "byzantine-agreement.rejected"

_AUDIT_KINDS = frozenset(
    {KIND_PREPREPARED, KIND_PREPARED, KIND_COMMITTED, KIND_REJECTED}
)

# Request lifecycle phases.
PHASE_PREPREPARED = "pre-prepared"
PHASE_PREPARED = "prepared"
PHASE_COMMITTED = "committed"

_PHASE_ORDER = {PHASE_PREPREPARED: 0, PHASE_PREPARED: 1, PHASE_COMMITTED: 2}


class ByzantineAgreementError(Exception):
    """Malformed input or protocol violation (fail-closed)."""


class BadRequestError(ByzantineAgreementError):
    """Malformed request id."""


class DuplicateRequestError(ByzantineAgreementError):
    """Request id already in use (ids are never recycled)."""


class UnknownRequestError(ByzantineAgreementError):
    """No such request."""


class BadViewError(ByzantineAgreementError):
    """Malformed view number."""


class BadDigestError(ByzantineAgreementError):
    """Malformed request digest pin."""


class DigestMismatchError(ByzantineAgreementError):
    """Vote digest does not match the pre-prepared digest."""


class UnknownReplicaError(ByzantineAgreementError):
    """Replica is not a member of this agreement."""


class DuplicateVoteError(ByzantineAgreementError):
    """Replica already voted in this phase for this request."""


class PhaseOrderError(ByzantineAgreementError):
    """Phase not reachable (e.g. commit before prepared)."""


class SeqOrderError(ByzantineAgreementError):
    """Caller seq is not a strictly increasing int."""


class AuditKindError(ByzantineAgreementError):
    """Unknown audit kind or banned detail keys."""


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {seq!r}")
    if seq <= 0:
        raise SeqOrderError(f"seq must be positive, got {seq}")
    return seq


def _check_request_id(request_id: object) -> str:
    if isinstance(request_id, bool) or not isinstance(request_id, str):
        raise BadRequestError(f"request_id must be a non-empty str, got {request_id!r}")
    if not request_id or len(request_id) > 256 or request_id != request_id.strip():
        raise BadRequestError(f"request_id malformed: {request_id!r}")
    return request_id


def _check_view(view: object) -> int:
    if isinstance(view, bool) or not isinstance(view, int):
        raise BadViewError(f"view must be a non-negative int, got {view!r}")
    if view < 0:
        raise BadViewError(f"view must be non-negative, got {view}")
    return view


def _check_digest(digest: object) -> str:
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise BadDigestError(f"request_digest must be a 'sha256:' pin, got {digest!r}")
    if not _DIGEST_RE.match(digest):
        raise BadDigestError(f"request_digest must match sha256:<64 hex>, got {digest!r}")
    return digest


def _check_replica(replica: object) -> str:
    if isinstance(replica, bool) or not isinstance(replica, str):
        raise UnknownReplicaError(f"replica must be a non-empty str, got {replica!r}")
    if not replica:
        raise UnknownReplicaError("replica must be non-empty")
    return replica


def _digest_pin(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class PrePrepareRecord:
    """The primary's proposal for ``(view, request_id)``."""

    request_id: str
    view: int
    request_digest: str
    seq: int
    version: str = BYZANTINE_AGREEMENT_VERSION
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class PrepareRecord:
    """A backup replica's endorsement of a pre-prepared request."""

    request_id: str
    replica: str
    request_digest: str
    seq: int
    version: str = BYZANTINE_AGREEMENT_VERSION
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class CommitRecord:
    """A replica's commit vote on a prepared request."""

    request_id: str
    replica: str
    request_digest: str
    seq: int
    version: str = BYZANTINE_AGREEMENT_VERSION
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class CertificateRecord:
    """A phase certificate: the quorum that crossed a phase threshold."""

    request_id: str
    phase: str
    votes: Tuple[str, ...]  # sorted replica ids forming the quorum
    seq: int
    version: str = BYZANTINE_AGREEMENT_VERSION
    schema: str = SCHEMA_PIN


def byzantine_agreement_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for Byzantine agreement."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    # Raw payloads must never cross the audit boundary; digests are pins.
    banned = {"payload", "value", "data", "votes", "request", "message"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "byzantine_agreement",
        "module_version": BYZANTINE_AGREEMENT_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


class ByzantineAgreement:
    """PBFT-shaped three-phase agreement bookkeeper (simulated).

    ``replicas`` is the ordered member set; ``n = 3f + 1`` must hold with
    at least 4 replicas (``f >= 1``). The constructor refuses malformed
    member sets fail-closed. Phases per request:

    * :meth:`preprepare` — the primary proposes ``(view, request_id)``
      with the request's digest pin.
    * :meth:`prepare` — backups endorse; with ``2f`` matching prepares
      the request is *prepared* (a prepare certificate is booked).
    * :meth:`commit` — replicas confirm; with ``2f + 1`` matching
      commits the request is *committed* (a commit certificate is
      booked).

    All votes are host-reported; this books the quorum ledger, it does
    not run a network. Read views (:meth:`status`, :meth:`certificate`,
    ...) validate the seq shape, consume nothing, and write no audit
    rows.
    """

    def __init__(self, replicas: Tuple[str, ...] = ("r0", "r1", "r2", "r3")) -> None:
        if not isinstance(replicas, tuple):
            replicas = tuple(replicas)  # type: ignore[arg-type]
        members: List[str] = []
        seen = set()
        for member in replicas:
            name = _check_replica(member)
            if name in seen:
                raise ByzantineAgreementError(f"duplicate replica: {name!r}")
            seen.add(name)
            members.append(name)
        n = len(members)
        if n < 4 or (n - 1) % 3 != 0:
            raise ByzantineAgreementError(
                f"replica count must satisfy n = 3f + 1 with n >= 4, got {n}"
            )
        self._replicas: Tuple[str, ...] = tuple(members)
        self._f: int = (n - 1) // 3
        self._lock = threading.RLock()
        self._seq: int = 0
        self._preprepares: Dict[str, PrePrepareRecord] = {}
        self._prepares: Dict[str, Dict[str, PrepareRecord]] = {}
        self._commits: Dict[str, Dict[str, CommitRecord]] = {}
        self._certificates: Dict[Tuple[str, str], CertificateRecord] = {}
        self._audit: List[Mapping[str, Any]] = []

    # -- introspection ---------------------------------------------------

    @property
    def replicas(self) -> Tuple[str, ...]:
        """The ordered member set."""
        return self._replicas

    @property
    def f(self) -> int:
        """Max tolerated Byzantine faults for this member set."""
        return self._f

    @property
    def quorum(self) -> int:
        """Commit quorum size: ``2f + 1``."""
        return 2 * self._f + 1

    @property
    def prepare_quorum(self) -> int:
        """Prepare quorum size: ``2f`` matching prepares."""
        return 2 * self._f

    def stats(self) -> Mapping[str, int]:
        """Pure read view: request counts per phase."""
        with self._lock:
            prepared = sum(
                1
                for rid in self._preprepares
                if (rid, PHASE_PREPARED) in self._certificates
            )
            committed = sum(
                1
                for rid in self._preprepares
                if (rid, PHASE_COMMITTED) in self._certificates
            )
            return {
                "requests": len(self._preprepares),
                "prepared": prepared,
                "committed": committed,
                "replicas": len(self._replicas),
                "f": self._f,
            }

    # -- internal ----------------------------------------------------------

    def _claim(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing; last={self._seq}, got={seq}"
            )
        self._seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(byzantine_agreement_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, reason: str) -> None:
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _phase(self, request_id: str) -> str:
        if (request_id, PHASE_COMMITTED) in self._certificates:
            return PHASE_COMMITTED
        if (request_id, PHASE_PREPARED) in self._certificates:
            return PHASE_PREPARED
        return PHASE_PREPREPARED

    def _book_certificate(
        self, request_id: str, phase: str, votes: List[str], seq: int
    ) -> CertificateRecord:
        cert = CertificateRecord(
            request_id=request_id,
            phase=phase,
            votes=tuple(sorted(votes)),
            seq=seq,
        )
        self._certificates[(request_id, phase)] = cert
        return cert

    # -- phases ------------------------------------------------------------

    def preprepare(
        self, request_id: str, view: int, seq: int, request_digest: str
    ) -> PrePrepareRecord:
        """Propose ``request_id`` for ``view`` (primary's PRE-PREPARE)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                rid = _check_request_id(request_id)
                v = _check_view(view)
                digest = _check_digest(request_digest)
                if rid in self._preprepares:
                    raise DuplicateRequestError(f"request already proposed: {rid!r}")
            except ByzantineAgreementError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            record = PrePrepareRecord(
                request_id=rid, view=v, request_digest=digest, seq=seq
            )
            self._preprepares[rid] = record
            self._prepares[rid] = {}
            self._commits[rid] = {}
            self._emit(
                KIND_PREPREPARED,
                seq,
                request_id=rid,
                view=v,
                request_digest=digest,
                digest=_digest_pin(
                    f"{rid}:{v}:{digest}".encode("utf-8")
                ),
            )
            return record

    def prepare(
        self, request_id: str, replica: str, seq: int, request_digest: str
    ) -> PrepareRecord:
        """Book a backup replica's PREPARE vote (endorse the proposal)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                rid = _check_request_id(request_id)
                name = _check_replica(replica)
                digest = _check_digest(request_digest)
                if rid not in self._preprepares:
                    raise UnknownRequestError(f"unknown request: {rid!r}")
                if name not in self._replicas:
                    raise UnknownReplicaError(f"unknown replica: {name!r}")
                if digest != self._preprepares[rid].request_digest:
                    raise DigestMismatchError("prepare digest != pre-prepare digest")
                if name in self._prepares[rid]:
                    raise DuplicateVoteError(
                        f"{name!r} already prepared {rid!r}"
                    )
            except ByzantineAgreementError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            record = PrepareRecord(
                request_id=rid, replica=name, request_digest=digest, seq=seq
            )
            self._prepares[rid][name] = record
            votes = list(self._prepares[rid])
            if (
                len(votes) >= self.prepare_quorum
                and (rid, PHASE_PREPARED) not in self._certificates
            ):
                self._book_certificate(rid, PHASE_PREPARED, votes, seq)
                self._emit(
                    KIND_PREPARED,
                    seq,
                    request_id=rid,
                    vote_count=len(votes),
                    digest=_digest_pin(
                        f"{rid}:{PHASE_PREPARED}:{','.join(sorted(votes))}".encode(
                            "utf-8"
                        )
                    ),
                )
            return record

    def commit(
        self, request_id: str, replica: str, seq: int, request_digest: str
    ) -> CommitRecord:
        """Book a replica's COMMIT vote (confirm the prepared certificate)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                rid = _check_request_id(request_id)
                name = _check_replica(replica)
                digest = _check_digest(request_digest)
                if rid not in self._preprepares:
                    raise UnknownRequestError(f"unknown request: {rid!r}")
                if name not in self._replicas:
                    raise UnknownReplicaError(f"unknown replica: {name!r}")
                if digest != self._preprepares[rid].request_digest:
                    raise DigestMismatchError("commit digest != pre-prepare digest")
                # Commit requires the prepare phase to have completed; once
                # committed, further votes are booked as redundant (data),
                # not refused — replicas may learn the certificate late.
                if self._phase(rid) == PHASE_PREPREPARED:
                    raise PhaseOrderError(
                        "commit requires prepared phase, "
                        f"request is {self._phase(rid)!r}"
                    )
                if name in self._commits[rid]:
                    raise DuplicateVoteError(
                        f"{name!r} already committed {rid!r}"
                    )
            except ByzantineAgreementError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            record = CommitRecord(
                request_id=rid, replica=name, request_digest=digest, seq=seq
            )
            self._commits[rid][name] = record
            votes = list(self._commits[rid])
            if (
                len(votes) >= self.quorum
                and (rid, PHASE_COMMITTED) not in self._certificates
            ):
                self._book_certificate(rid, PHASE_COMMITTED, votes, seq)
                self._emit(
                    KIND_COMMITTED,
                    seq,
                    request_id=rid,
                    vote_count=len(votes),
                    digest=_digest_pin(
                        f"{rid}:{PHASE_COMMITTED}:{','.join(sorted(votes))}".encode(
                            "utf-8"
                        )
                    ),
                )
            return record

    # -- read views (pure: validate seq shape, consume nothing) ------------

    def status(self, request_id: str, seq: int) -> str:
        """Current phase of ``request_id`` as data."""
        _check_seq(seq)
        rid = _check_request_id(request_id)
        with self._lock:
            if rid not in self._preprepares:
                raise UnknownRequestError(f"unknown request: {rid!r}")
            return self._phase(rid)

    def certificate(
        self, request_id: str, phase: str, seq: int
    ) -> Optional[CertificateRecord]:
        """The phase certificate if booked, else ``None`` (data, not raised)."""
        _check_seq(seq)
        rid = _check_request_id(request_id)
        if phase not in _PHASE_ORDER:
            raise PhaseOrderError(f"unknown phase: {phase!r}")
        with self._lock:
            return self._certificates.get((rid, phase))

    def preprepare_record(self, request_id: str, seq: int) -> PrePrepareRecord:
        """The PRE-PREPARE record for a request."""
        _check_seq(seq)
        rid = _check_request_id(request_id)
        with self._lock:
            if rid not in self._preprepares:
                raise UnknownRequestError(f"unknown request: {rid!r}")
            return self._preprepares[rid]

    def prepare_votes(self, request_id: str, seq: int) -> Tuple[str, ...]:
        """Sorted replica ids that prepared this request (data)."""
        _check_seq(seq)
        rid = _check_request_id(request_id)
        with self._lock:
            if rid not in self._prepares:
                raise UnknownRequestError(f"unknown request: {rid!r}")
            return tuple(sorted(self._prepares[rid]))

    def commit_votes(self, request_id: str, seq: int) -> Tuple[str, ...]:
        """Sorted replica ids that committed this request (data)."""
        _check_seq(seq)
        rid = _check_request_id(request_id)
        with self._lock:
            if rid not in self._commits:
                raise UnknownRequestError(f"unknown request: {rid!r}")
            return tuple(sorted(self._commits[rid]))

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        """The audit rows booked so far (frozen snapshot)."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: preprepare -> prepare x2f -> commit x2f+1."""
    digest = "sha256:" + "ab" * 32
    ba = ByzantineAgreement(replicas=("r0", "r1", "r2", "r3"))
    ba.preprepare("req-1", view=0, seq=1, request_digest=digest)
    seq = 2
    for replica in ("r1", "r2"):
        ba.prepare("req-1", replica=replica, seq=seq, request_digest=digest)
        seq += 1
    assert ba.status("req-1", seq=seq) == PHASE_PREPARED, "prepare quorum"
    for replica in ("r0", "r1", "r2"):
        ba.commit("req-1", replica=replica, seq=seq, request_digest=digest)
        seq += 1
    assert ba.status("req-1", seq=seq) == PHASE_COMMITTED, "commit quorum"
    print(
        "byzantine-agreement OK: preprepare, prepare quorum 2f, commit quorum 2f+1"
    )


if __name__ == "__main__":
    main()
