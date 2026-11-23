"""Distributed lock manager: mutual exclusion with monotonic fencing tokens.

Research motivation: a fleet of agents must serialize access to a shared
resource (a tool account, a ledger, the audit head) without a central
coordinator. The load-bearing safety concept is the **fencing token**: a
monotonically increasing integer handed to each lock holder. The resource
server rejects operations carrying a stale token. This closes the classic
failure where a holder's lease expires, a new holder acquires the lock, and
the *old* holder -- believing it still holds the lock -- performs an
operation on the shared resource.

Public API:

- ``FencingToken`` -- frozen record: ``lock_id``, ``token`` (strictly
  increasing per lock, minted at acquire), ``owner`` (the holder the token
  was issued to).
- ``LockLease`` -- frozen record: ``lock_id``, ``owner``,
  ``fencing_token``, ``acquired_seq``, ``expiry_seq`` (inclusive: the lease
  is valid *through* ``expiry_seq``); ``is_expired(current_seq)`` and a
  ``sha256:`` ``digest()`` for audit pinning.
- ``DistributedLock`` -- stateful per-host registry (``threading.RLock``
  guarded):
    - ``acquire(lock_id, owner, ttl_seqs, current_seq)`` -> ``LockLease``
      or ``None`` on contention (the lock is held and unexpired).
    - ``release(lock_id, owner, fencing_token, current_seq)`` -> ``True``
      only for the current holder presenting the current token; a stale
      holder's release is refused (``False``), which is what stops a stale
      holder from releasing *someone else's* lock.
    - ``renew(lock_id, owner, fencing_token, ttl_seqs, current_seq)``
      -> the renewed ``LockLease`` (same token, extended expiry) for the
      live holder; a stale holder, non-holder, or expired lease is refused
      (``None``) and must re-``acquire``.
    - ``verify_fencing(lock_id, token)`` -> ``True`` iff ``token`` is the
      latest token minted for ``lock_id``.
    - ``is_locked(lock_id, current_seq)``, ``current_holder(lock_id)``,
      ``current_token(lock_id)`` views.
- ``LockEvent`` -- frozen append-only event records (acquired / released /
  refused / expired / release-refused) with ``events()`` view.
- ``distributed_lock_audit_event(...)`` -- ``audit.ndjson/1``-shaped record.

Honest scope:

- This is the lock *state machine* and the fencing-token ledger, not a
  distributed consensus protocol. It assumes one trusted registry
  (in-memory here); in a real deployment the registry is shared
  (Redis/consul/etcd) and this logic lives server-side. What is pinned here
  are the client-side invariants: mutual exclusion within one registry,
  strictly increasing fencing tokens, stale-holder release refusal, and
  fail-closed expiry.
- Two registries that cannot see each other will hand out conflicting
  leases -- that is split-brain, and detecting/healing it is the host's
  transport-layer job.
- TTLs and expiry use caller-supplied int seqs, never wall-clock: a lease
  is a logical statement ("valid through seq N"), immune to NTP jumps.
  ``ttl_seqs=0`` is rejected -- an instantly-dead lease is a caller bug.
- ``verify_fencing`` answers "is this the latest token this registry
  issued", never "the resource server honored it". The resource server
  must check the token on *every* operation; the lock manager only mints
  and tracks them.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Mapping, Optional, Tuple, Union

#: Version pin for this module's record shape.
DISTRIBUTED_LOCK_VERSION = "distributed-lock.v1"

#: Schema pin carried by records and audit events.
DISTRIBUTED_LOCK_SCHEMA = "northstar.distributed-lock.v1"

#: Audit event kinds.
EVENT_ACQUIRED = "lock-acquired"
EVENT_RELEASED = "lock-released"
EVENT_RENEWED = "lock-renewed"
EVENT_REFUSED = "lock-refused"
EVENT_EXPIRED = "lock-expired"
EVENT_RELEASE_REFUSED = "release-refused"

_EVENT_TYPES = frozenset(
    {
        EVENT_ACQUIRED,
        EVENT_RELEASED,
        EVENT_RENEWED,
        EVENT_REFUSED,
        EVENT_EXPIRED,
        EVENT_RELEASE_REFUSED,
    }
)

#: Reasons attached to refused/release-refused events.
_REASON_CONTENTION = "contention"
_REASON_STALE_TOKEN = "stale-token"
_REASON_NOT_HOLDER = "not-holder"
_REASON_NO_SUCH_LOCK = "no-such-lock"
_REASON_ALREADY_EXPIRED = "already-expired"
_REASON_BAD_TOKEN = "bad-token"


def _check_text(value: object, name: str) -> str:
    """Validate a lock id / owner: non-empty string, whitespace-stripped."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    text = value.strip()
    if not text:
        raise ValueError(f"{name} must be non-empty")
    return text


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied seq: non-negative int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _check_ttl(value: object) -> int:
    """Validate a TTL: strictly positive int (seqs), bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"ttl_seqs must be an int, got {type(value).__name__}")
    if value <= 0:
        raise ValueError("ttl_seqs must be positive")
    return value


def _check_token(value: object) -> int:
    """Validate a fencing token: strictly positive int, bool rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"fencing token must be an int, got {type(value).__name__}")
    if value <= 0:
        raise ValueError("fencing token must be positive")
    return value


def _canonical(body: Mapping[str, object]) -> bytes:
    """Deterministic JSON encoding for digest pins (stdlib only)."""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _pin(body: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(body)).hexdigest()


@dataclass(frozen=True)
class FencingToken:
    """A token issued to exactly one lock acquisition.

    ``token`` is strictly increasing per ``lock_id`` for the life of the
    manager and is never reused. Presenting a token older than the current
    one marks the presenter as stale.
    """

    lock_id: str
    token: int
    owner: str

    def __post_init__(self) -> None:
        _check_text(self.lock_id, "lock_id")
        _check_token(self.token)
        _check_text(self.owner, "owner")

    def as_dict(self) -> dict:
        return {
            "lock_id": self.lock_id,
            "token": self.token,
            "owner": self.owner,
            "schema": DISTRIBUTED_LOCK_SCHEMA,
        }


@dataclass(frozen=True)
class LockLease:
    """A live (or recently dead) claim on a lock."""

    lock_id: str
    owner: str
    fencing_token: FencingToken
    acquired_seq: int
    expiry_seq: int

    def __post_init__(self) -> None:
        _check_text(self.lock_id, "lock_id")
        _check_text(self.owner, "owner")
        if not isinstance(self.fencing_token, FencingToken):
            raise TypeError(
                f"fencing_token must be a FencingToken, "
                f"got {type(self.fencing_token).__name__}"
            )
        _check_seq(self.acquired_seq, "acquired_seq")
        _check_seq(self.expiry_seq, "expiry_seq")
        if self.expiry_seq < self.acquired_seq:
            raise ValueError("expiry_seq must not precede acquired_seq")
        if self.fencing_token.lock_id != self.lock_id:
            raise ValueError("fencing token names a different lock")
        if self.fencing_token.owner != self.owner:
            raise ValueError("fencing token names a different owner")

    def is_expired(self, current_seq: int) -> bool:
        """True when the lease is dead. Expiry is inclusive: the lease is
        valid *through* ``expiry_seq``."""
        _check_seq(current_seq, "current_seq")
        return current_seq > self.expiry_seq

    def digest(self) -> str:
        """Tamper-evident pin over the lease body."""
        return _pin(
            {
                "lock_id": self.lock_id,
                "owner": self.owner,
                "token": self.fencing_token.token,
                "acquired_seq": self.acquired_seq,
                "expiry_seq": self.expiry_seq,
            }
        )

    def as_dict(self) -> dict:
        return {
            "lock_id": self.lock_id,
            "owner": self.owner,
            "fencing_token": self.fencing_token.as_dict(),
            "acquired_seq": self.acquired_seq,
            "expiry_seq": self.expiry_seq,
            "digest": self.digest(),
            "schema": DISTRIBUTED_LOCK_SCHEMA,
        }


@dataclass(frozen=True)
class LockEvent:
    """One append-only lock lifecycle record."""

    kind: str
    lock_id: str
    owner: str
    token: Optional[int]
    seq: int
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.kind not in _EVENT_TYPES:
            raise ValueError(f"unknown lock event kind: {self.kind!r}")
        _check_text(self.lock_id, "lock_id")
        _check_text(self.owner, "owner")
        if self.token is not None:
            _check_token(self.token)
        _check_seq(self.seq, "seq")

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "lock_id": self.lock_id,
            "owner": self.owner,
            "token": self.token,
            "seq": self.seq,
            "reason": self.reason,
            "schema": DISTRIBUTED_LOCK_SCHEMA,
        }


class DistributedLock:
    """Mutual-exclusion registry with monotonic fencing tokens.

    One instance is one registry. All state changes are ``threading.RLock``
    guarded; events are append-only in call order.
    """

    def __init__(self) -> None:
        self._guard = threading.RLock()
        # lock_id -> LockLease (the latest lease; may be expired)
        self._leases: dict[str, LockLease] = {}
        # lock_id -> highest token minted so far (never reset)
        self._tokens: dict[str, int] = {}
        self._events: list[LockEvent] = []

    # -- internal ------------------------------------------------------

    def _record(self, event: LockEvent) -> None:
        self._events.append(event)

    # -- public --------------------------------------------------------

    def acquire(
        self, lock_id: str, owner: str, ttl_seqs: int, current_seq: int
    ) -> Optional[LockLease]:
        """Try to take ``lock_id`` for ``ttl_seqs`` seqs starting now.

        Returns the new ``LockLease`` on success, or ``None`` when the lock
        is held by an unexpired lease (contention). An expired lease is
        replaced lazily and a ``lock-expired`` event is recorded.
        """
        lock_id = _check_text(lock_id, "lock_id")
        owner = _check_text(owner, "owner")
        ttl = _check_ttl(ttl_seqs)
        now = _check_seq(current_seq, "current_seq")
        with self._guard:
            existing = self._leases.get(lock_id)
            if existing is not None and not existing.is_expired(now):
                self._record(
                    LockEvent(
                        kind=EVENT_REFUSED,
                        lock_id=lock_id,
                        owner=owner,
                        token=None,
                        seq=now,
                        reason=_REASON_CONTENTION,
                    )
                )
                return None
            if existing is not None:
                # Lazily retire the dead lease so the audit trail tells the
                # full story: held -> expired -> re-acquired.
                self._record(
                    LockEvent(
                        kind=EVENT_EXPIRED,
                        lock_id=lock_id,
                        owner=existing.owner,
                        token=existing.fencing_token.token,
                        seq=now,
                    )
                )
            token_value = self._tokens.get(lock_id, 0) + 1
            self._tokens[lock_id] = token_value
            lease = LockLease(
                lock_id=lock_id,
                owner=owner,
                fencing_token=FencingToken(
                    lock_id=lock_id, token=token_value, owner=owner
                ),
                acquired_seq=now,
                expiry_seq=now + ttl,
            )
            self._leases[lock_id] = lease
            self._record(
                LockEvent(
                    kind=EVENT_ACQUIRED,
                    lock_id=lock_id,
                    owner=owner,
                    token=token_value,
                    seq=now,
                )
            )
            return lease

    def release(
        self,
        lock_id: str,
        owner: str,
        fencing_token: Union[int, FencingToken],
        current_seq: int,
    ) -> bool:
        """Give up ``lock_id``. Returns ``True`` only when ``owner``
        presents the *current* fencing token for a *live* lease.

        A stale holder (old token) or a non-holder is refused with
        ``False`` and a ``release-refused`` event -- this is the fencing
        protection: a stale holder can neither keep nor release someone
        else's lock.
        """
        lock_id = _check_text(lock_id, "lock_id")
        owner = _check_text(owner, "owner")
        if isinstance(fencing_token, FencingToken):
            if fencing_token.lock_id != lock_id:
                raise ValueError("fencing token names a different lock")
            token_value = _check_token(fencing_token.token)
        else:
            token_value = _check_token(fencing_token)
        now = _check_seq(current_seq, "current_seq")
        with self._guard:
            lease = self._leases.get(lock_id)
            if lease is None:
                self._record(
                    LockEvent(
                        kind=EVENT_RELEASE_REFUSED,
                        lock_id=lock_id,
                        owner=owner,
                        token=token_value,
                        seq=now,
                        reason=_REASON_NO_SUCH_LOCK,
                    )
                )
                return False
            if lease.is_expired(now):
                # The lease is already dead; clear it and say so. The
                # release did not free anything.
                del self._leases[lock_id]
                self._record(
                    LockEvent(
                        kind=EVENT_RELEASE_REFUSED,
                        lock_id=lock_id,
                        owner=owner,
                        token=token_value,
                        seq=now,
                        reason=_REASON_ALREADY_EXPIRED,
                    )
                )
                return False
            current = lease.fencing_token.token
            if token_value != current:
                self._record(
                    LockEvent(
                        kind=EVENT_RELEASE_REFUSED,
                        lock_id=lock_id,
                        owner=owner,
                        token=token_value,
                        seq=now,
                        reason=(
                            _REASON_STALE_TOKEN
                            if token_value < current
                            else _REASON_BAD_TOKEN
                        ),
                    )
                )
                return False
            if lease.owner != owner:
                self._record(
                    LockEvent(
                        kind=EVENT_RELEASE_REFUSED,
                        lock_id=lock_id,
                        owner=owner,
                        token=token_value,
                        seq=now,
                        reason=_REASON_NOT_HOLDER,
                    )
                )
                return False
            del self._leases[lock_id]
            self._record(
                LockEvent(
                    kind=EVENT_RELEASED,
                    lock_id=lock_id,
                    owner=owner,
                    token=token_value,
                    seq=now,
                )
            )
            return True

    def renew(
        self,
        lock_id: str,
        owner: str,
        fencing_token: Union[int, FencingToken],
        ttl_seqs: int,
        current_seq: int,
    ) -> Optional[LockLease]:
        """Extend the lease of ``lock_id`` by ``ttl_seqs`` seqs.

        Returns the renewed ``LockLease`` (same fencing token, new expiry)
        only when ``owner`` presents the *current* fencing token for a
        *live* lease. A stale holder, a non-holder, or an expired lease is
        refused with ``None`` and a ``lock-refused`` event -- the stale
        holder must re-``acquire`` and take a fresh fencing token. Renewing
        never mints a new token (the fencing token is per-grant).
        """
        lock_id = _check_text(lock_id, "lock_id")
        owner = _check_text(owner, "owner")
        if isinstance(fencing_token, FencingToken):
            if fencing_token.lock_id != lock_id:
                raise ValueError("fencing token names a different lock")
            token_value = _check_token(fencing_token.token)
        else:
            token_value = _check_token(fencing_token)
        ttl = _check_ttl(ttl_seqs)
        now = _check_seq(current_seq, "current_seq")
        with self._guard:
            lease = self._leases.get(lock_id)
            if lease is None:
                self._record(
                    LockEvent(
                        kind=EVENT_REFUSED,
                        lock_id=lock_id,
                        owner=owner,
                        token=token_value,
                        seq=now,
                        reason=_REASON_NO_SUCH_LOCK,
                    )
                )
                return None
            if lease.is_expired(now):
                del self._leases[lock_id]
                self._record(
                    LockEvent(
                        kind=EVENT_REFUSED,
                        lock_id=lock_id,
                        owner=owner,
                        token=token_value,
                        seq=now,
                        reason=_REASON_ALREADY_EXPIRED,
                    )
                )
                return None
            current = lease.fencing_token.token
            if token_value != current:
                self._record(
                    LockEvent(
                        kind=EVENT_REFUSED,
                        lock_id=lock_id,
                        owner=owner,
                        token=token_value,
                        seq=now,
                        reason=(
                            _REASON_STALE_TOKEN
                            if token_value < current
                            else _REASON_BAD_TOKEN
                        ),
                    )
                )
                return None
            if lease.owner != owner:
                self._record(
                    LockEvent(
                        kind=EVENT_REFUSED,
                        lock_id=lock_id,
                        owner=owner,
                        token=token_value,
                        seq=now,
                        reason=_REASON_NOT_HOLDER,
                    )
                )
                return None
            renewed = LockLease(
                lock_id=lock_id,
                owner=owner,
                fencing_token=lease.fencing_token,
                acquired_seq=lease.acquired_seq,
                expiry_seq=now + ttl,
            )
            self._leases[lock_id] = renewed
            self._record(
                LockEvent(
                    kind=EVENT_RENEWED,
                    lock_id=lock_id,
                    owner=owner,
                    token=token_value,
                    seq=now,
                )
            )
            return renewed

    def is_locked(self, lock_id: str, current_seq: int) -> bool:
        """True when ``lock_id`` is held by an unexpired lease."""
        lock_id = _check_text(lock_id, "lock_id")
        now = _check_seq(current_seq, "current_seq")
        with self._guard:
            lease = self._leases.get(lock_id)
            return lease is not None and not lease.is_expired(now)

    def current_holder(self, lock_id: str) -> Optional[str]:
        """Owner of the latest lease, or ``None`` when the lock was never
        taken. Does not evaluate expiry (a holder of a dead lease is still
        the recorded holder until someone re-acquires)."""
        lock_id = _check_text(lock_id, "lock_id")
        with self._guard:
            lease = self._leases.get(lock_id)
            return lease.owner if lease is not None else None

    def current_token(self, lock_id: str) -> Optional[int]:
        """Highest fencing token minted for ``lock_id``, or ``None`` when
        the lock was never taken."""
        lock_id = _check_text(lock_id, "lock_id")
        with self._guard:
            return self._tokens.get(lock_id)

    def verify_fencing(
        self, lock_id: str, token: Union[int, FencingToken]
    ) -> bool:
        """True iff ``token`` is the latest token this registry issued for
        ``lock_id``. A resource server calls this on every operation to
        reject stale holders."""
        lock_id = _check_text(lock_id, "lock_id")
        if isinstance(token, FencingToken):
            if token.lock_id != lock_id:
                raise ValueError("fencing token names a different lock")
            token_value = _check_token(token.token)
        else:
            token_value = _check_token(token)
        with self._guard:
            return self._tokens.get(lock_id) == token_value

    def events(self) -> Tuple[LockEvent, ...]:
        """Append-only event view, in call order."""
        with self._guard:
            return tuple(self._events)


def distributed_lock_audit_event(
    kind: str, lock_id: str, owner: str, seq: int, token: Optional[int] = None
) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for a lock event."""
    if kind not in _EVENT_TYPES:
        raise ValueError(f"unknown lock event kind: {kind!r}")
    _check_text(lock_id, "lock_id")
    _check_text(owner, "owner")
    _check_seq(seq, "seq")
    if token is not None:
        _check_token(token)
    return {
        "type": "audit.ndjson/1",
        "event": kind,
        "lock_id": lock_id,
        "owner": owner,
        "token": token,
        "seq": seq,
        "schema": DISTRIBUTED_LOCK_SCHEMA,
    }


def main() -> None:
    mgr = DistributedLock()
    lease = mgr.acquire("ledger", "host-a", ttl_seqs=10, current_seq=0)
    assert lease is not None and lease.fencing_token.token == 1
    # Contention: second acquirer is refused.
    assert mgr.acquire("ledger", "host-b", ttl_seqs=10, current_seq=1) is None
    # Stale-token release is refused even by the original owner of an
    # older token shape; correct release succeeds.
    assert not mgr.release("ledger", "host-b", 1, current_seq=2)
    assert mgr.release("ledger", "host-a", 1, current_seq=3)
    # Re-acquire mints a strictly higher token; the old token is stale.
    lease2 = mgr.acquire("ledger", "host-b", ttl_seqs=10, current_seq=4)
    assert lease2 is not None and lease2.fencing_token.token == 2
    assert not mgr.verify_fencing("ledger", 1)
    assert mgr.verify_fencing("ledger", 2)
    assert not mgr.release("ledger", "host-a", 1, current_seq=5)
    kinds = [e.kind for e in mgr.events()]
    assert kinds == [
        EVENT_ACQUIRED,
        EVENT_REFUSED,
        EVENT_RELEASE_REFUSED,
        EVENT_RELEASED,
        EVENT_ACQUIRED,
        EVENT_RELEASE_REFUSED,
    ], kinds
    print("distributed-lock OK: acquire, contention, fencing, release")


if __name__ == "__main__":
    main()
