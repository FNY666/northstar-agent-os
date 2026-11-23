"""Cache-stampede (thundering-herd) protection: single-flight + jitter.

A ``CacheStampede`` ledger books cache-refresh decisions as a deterministic
single-host state machine:

- ``protect(key_id, ttl_seq, seq)`` pins a hot cache key with a TTL window
  (in logical seqs). The entry starts ``fresh``: arrivals hit the cached
  value and nobody recomputes.
- ``coalesce(key_id, request_id, seq)`` books one request arrival and
  returns a frozen ``CoalesceDecision`` as *data*:
  ``role="hit"`` (entry fresh, serve the cached value),
  ``role="leader"`` (entry stale, no refresh in flight: *this* request
  becomes the single recompute owner and must call
  ``complete_refresh``), or ``role="follower"`` (entry stale, a refresh
  is already in flight: the request is coalesced and must wait for the
  leader's refresh instead of recomputing). Followers never recompute.
- ``complete_refresh(key_id, refresh_id, value_digest, seq)`` books the
  leader's recompute as *finished*, pins the new value **by digest only**,
  releases the coalesced followers, and marks the entry fresh again.
- ``jitter(key_id, seq, spread_seq)`` pins probabilistic-early-refresh
  parameters. There is no entropy source in a deterministic ledger, so
  the "jitter" is a deterministic stagger derived from the pinned
  ``sha256:`` digest: ``stagger = H(key_id, jitter_seq) mod (spread+1)``.
  ``jittered_expiry(key_id)`` returns the deterministic effective expiry
  ``entry_seq + ttl - stagger`` as a pure view.
- ``unprotect(key_id, seq, reason)`` retires a key (terminal).

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``cache-stampede.v1``, schema pin ``northstar.cache-stampede.v1``,
``main()`` self-check.

Honest scope: this module books *declared* cache-coordination decisions
on a single host; it cannot observe the wire, cannot prove a follower
actually waited instead of recomputing, and cannot measure how many
thundering-herd recomputes were avoided. Value bytes never enter a
record (digests only). The deterministic stagger stands in for random
jitter: it spreads expiries across keys but is fully reproducible, not
random.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
CACHE_STAMPEDE_VERSION = "cache-stampede.v1"

#: Schema pin carried by records and audit events.
CACHE_STAMPEDE_SCHEMA = "northstar.cache-stampede.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Maximum number of followers coalesced onto one in-flight refresh.
MAX_FOLLOWERS = 1024


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class CacheStampedeError(ValueError):
    """Base for all cache-stampede structural problems and refused transitions."""


class BadProtectionError(CacheStampedeError):
    """Protection definition is malformed (bad key id, ttl)."""


class DuplicateProtectionError(CacheStampedeError):
    """The key is already protected."""


class UnknownKeyError(CacheStampedeError):
    """No protection is pinned for the requested key."""


class RemovedKeyError(CacheStampedeError):
    """The key was unprotected; its id is retired and never recycled."""


class DuplicateRequestError(CacheStampedeError):
    """The request id was already booked on this key."""


class UnknownRefreshError(CacheStampedeError):
    """No in-flight refresh matches the referenced refresh id."""


class WrongLeaderError(CacheStampedeError):
    """Only the booked leader's refresh may be completed."""


class BadDigestError(CacheStampedeError):
    """A value digest is malformed (must be ``sha256:`` + 64 hex)."""


class BadJitterError(CacheStampedeError):
    """Jitter configuration is malformed (bad spread)."""


class SeqOrderError(CacheStampedeError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CacheStampedeError(f"{name} must be a non-empty string")
    return value.strip()


def _check_digest(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"{name} must be a 'sha256:' digest string")
    if not value.startswith("sha256:"):
        raise BadDigestError(f"{name} must start with 'sha256:'")
    body = value[len("sha256:"):]
    if len(body) != 64 or any(c not in "0123456789abcdef" for c in body):
        raise BadDigestError(f"{name} must be 'sha256:' + 64 lowercase hex")
    return value


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([CACHE_STAMPEDE_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _stagger(key_id: str, jitter_seq: int, spread: int) -> int:
    """Deterministic stand-in for random jitter: ``[0, spread]``."""
    raw = hashlib.sha256(
        jcs_canonical_json(["cache-stampede-jitter", key_id, jitter_seq])
    ).digest()
    return int.from_bytes(raw[:8], "big") % (spread + 1)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProtectionRecord:
    """One pinned cache-key protection (frozen)."""

    key_id: str
    ttl_seq: int
    backend: str
    entry_seq: int  # seq at which the entry was last refreshed
    seq: int
    digest: str
    schema: str = CACHE_STAMPEDE_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "protect", self.key_id, self.ttl_seq, self.backend,
            self.entry_seq, self.seq,
        )


@dataclass(frozen=True)
class CoalesceDecision:
    """One request-arrival verdict (frozen).

    ``role`` is data, never raised: ``"hit"`` (entry fresh),
    ``"leader"`` (this request must recompute), ``"follower"`` (wait
    for the in-flight refresh).
    """

    key_id: str
    request_id: str
    role: str
    refresh_id: str
    seq: int
    digest: str
    schema: str = CACHE_STAMPEDE_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "coalesce", self.key_id, self.request_id, self.role,
            self.refresh_id, self.seq,
        )


@dataclass(frozen=True)
class RefreshRecord:
    """One in-flight single-flight refresh (frozen)."""

    refresh_id: str
    key_id: str
    leader_request_id: str
    follower_count: int
    seq: int
    digest: str
    schema: str = CACHE_STAMPEDE_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "refresh-start", self.refresh_id, self.key_id,
            self.leader_request_id, self.seq,
        )


@dataclass(frozen=True)
class RefreshCompletion:
    """One completed refresh (frozen). Follower waiters are released."""

    refresh_id: str
    key_id: str
    value_digest: str
    released_followers: int
    seq: int
    digest: str
    schema: str = CACHE_STAMPEDE_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "refresh-complete", self.refresh_id, self.key_id,
            self.value_digest, self.released_followers, self.seq,
        )


@dataclass(frozen=True)
class JitterRecord:
    """One pinned jitter configuration (frozen)."""

    key_id: str
    spread_seq: int
    stagger: int
    seq: int
    digest: str
    schema: str = CACHE_STAMPEDE_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "jitter", self.key_id, self.spread_seq, self.stagger, self.seq,
        )


@dataclass(frozen=True)
class UnprotectRecord:
    """One terminal protection retirement (frozen)."""

    key_id: str
    reason: str
    seq: int
    digest: str
    schema: str = CACHE_STAMPEDE_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("unprotect", self.key_id, self.reason, self.seq)


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_PROTECTED = "cache-stampede.protected"
KIND_COALESCED = "cache-stampede.coalesced"
KIND_REFRESH_STARTED = "cache-stampede.refresh-started"
KIND_REFRESH_COMPLETED = "cache-stampede.refresh-completed"
KIND_JITTER_SET = "cache-stampede.jitter-set"
KIND_UNPROTECTED = "cache-stampede.unprotected"
KIND_REJECTED = "cache-stampede.rejected"
_KINDS = (
    KIND_PROTECTED, KIND_COALESCED, KIND_REFRESH_STARTED,
    KIND_REFRESH_COMPLETED, KIND_JITTER_SET, KIND_UNPROTECTED, KIND_REJECTED,
)


def cache_stampede_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the cache-stampede module."""
    if kind not in _KINDS:
        raise CacheStampedeError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise CacheStampedeError("detail must be a mapping")
    # Value bytes, payloads, and raw digests never cross the audit boundary.
    banned = {"value", "payload", "body", "value_digest"}
    if any(k in detail for k in banned):
        raise CacheStampedeError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": CACHE_STAMPEDE_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class CacheStampede:
    """Deterministic single-flight + jittered-expiry cache ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._protections: Dict[str, ProtectionRecord] = {}   # key_id -> record
        self._removed: set = set()                            # retired key ids
        self._inflight: Dict[str, RefreshRecord] = {}         # key_id -> refresh
        self._inflight_followers: Dict[str, List[str]] = {}   # key_id -> request ids
        self._seen_requests: Dict[str, set] = {}              # key_id -> request ids
        self._jitters: Dict[str, JitterRecord] = {}           # key_id -> jitter
        self._refresh_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _audit_locked(self, kind: str, detail: Mapping[str, Any]) -> None:
        self._audit.append(cache_stampede_audit_event(kind, detail, self._last_seq))

    def _reject_locked(self, reason: str) -> None:
        self._audit_locked(KIND_REJECTED, {"reason": reason})

    def _protection_locked(self, key_id: str) -> ProtectionRecord:
        record = self._protections.get(key_id)
        if record is None:
            self._reject_locked("unknown-key")
            raise UnknownKeyError(f"no protection for key {key_id!r}")
        return record

    # -- protect --------------------------------------------------------

    def protect(
        self, key_id: str, ttl_seq: int, seq: int, *, backend: str = ""
    ) -> ProtectionRecord:
        """Pin a cache-key protection with a TTL window of logical seqs."""
        with self._lock:
            key_id = _check_nonempty_str(key_id, "key_id")
            if isinstance(ttl_seq, bool) or not isinstance(ttl_seq, int) \
                    or ttl_seq <= 0:
                raise BadProtectionError("ttl_seq must be a positive int")
            if not isinstance(backend, str):
                raise BadProtectionError("backend must be a string")
            self._claim_seq(seq)
            if key_id in self._removed:
                self._reject_locked("removed-key")
                raise RemovedKeyError(f"key {key_id!r} was unprotected; id retired")
            if key_id in self._protections:
                self._reject_locked("duplicate-protection")
                raise DuplicateProtectionError(f"key {key_id!r} already protected")
            record = ProtectionRecord(
                key_id=key_id, ttl_seq=ttl_seq, backend=backend.strip(),
                entry_seq=seq, seq=seq,
                digest=_pin("protect", key_id, ttl_seq, backend.strip(), seq, seq),
            )
            self._protections[key_id] = record
            self._seen_requests[key_id] = set()
            self._audit_locked(
                KIND_PROTECTED,
                {"key_id": key_id, "ttl_seq": ttl_seq, "digest": record.digest},
            )
            return record

    # -- coalesce -------------------------------------------------------

    def coalesce(self, key_id: str, request_id: str, seq: int) -> CoalesceDecision:
        """Book one request arrival; return the hit/leader/follower verdict.

        The verdict is data, never raised. A ``"follower"`` must wait for
        the in-flight refresh; a ``"leader"`` must recompute and then call
        :meth:`complete_refresh`.
        """
        with self._lock:
            key_id = _check_nonempty_str(key_id, "key_id")
            request_id = _check_nonempty_str(request_id, "request_id")
            self._claim_seq(seq)
            record = self._protection_locked(key_id)
            seen = self._seen_requests[key_id]
            if request_id in seen:
                self._reject_locked("duplicate-request")
                raise DuplicateRequestError(
                    f"request {request_id!r} already booked on key {key_id!r}"
                )
            seen.add(request_id)
            fresh = (seq - record.entry_seq) < record.ttl_seq
            inflight = self._inflight.get(key_id)
            if fresh:
                role, refresh_id = "hit", ""
            elif inflight is None:
                self._refresh_seq += 1
                refresh_id = f"ref-{self._refresh_seq}"
                refresh = RefreshRecord(
                    refresh_id=refresh_id, key_id=key_id,
                    leader_request_id=request_id, follower_count=0, seq=seq,
                    digest=_pin("refresh-start", refresh_id, key_id, request_id, seq),
                )
                self._inflight[key_id] = refresh
                self._inflight_followers[key_id] = []
                self._audit_locked(
                    KIND_REFRESH_STARTED,
                    {"key_id": key_id, "refresh_id": refresh_id,
                     "leader": request_id},
                )
                role = "leader"
            else:
                followers = self._inflight_followers[key_id]
                if len(followers) >= MAX_FOLLOWERS:
                    self._reject_locked("follower-cap")
                    raise CacheStampedeError(
                        f"follower cap {MAX_FOLLOWERS} reached on key {key_id!r}"
                    )
                followers.append(request_id)
                refresh_id = inflight.refresh_id
                self._audit_locked(
                    KIND_COALESCED,
                    {"key_id": key_id, "refresh_id": refresh_id,
                     "request_id": request_id},
                )
                role = "follower"
            decision = CoalesceDecision(
                key_id=key_id, request_id=request_id, role=role,
                refresh_id=refresh_id, seq=seq,
                digest=_pin("coalesce", key_id, request_id, role, refresh_id, seq),
            )
            if role == "hit":
                self._audit_locked(
                    KIND_COALESCED,
                    {"key_id": key_id, "request_id": request_id, "role": "hit"},
                )
            return decision

    # -- complete_refresh -----------------------------------------------

    def complete_refresh(
        self, key_id: str, refresh_id: str, value_digest: str, seq: int
    ) -> RefreshCompletion:
        """Book the leader's recompute as finished; release followers.

        The new value is pinned by digest only; value bytes never enter
        the ledger. Only the booked leader's refresh id completes.
        """
        with self._lock:
            key_id = _check_nonempty_str(key_id, "key_id")
            refresh_id = _check_nonempty_str(refresh_id, "refresh_id")
            value_digest = _check_digest(value_digest, "value_digest")
            self._claim_seq(seq)
            record = self._protection_locked(key_id)
            inflight = self._inflight.get(key_id)
            if inflight is None or inflight.refresh_id != refresh_id:
                self._reject_locked("unknown-refresh")
                raise UnknownRefreshError(
                    f"no in-flight refresh {refresh_id!r} on key {key_id!r}"
                )
            followers = self._inflight_followers.pop(key_id)
            del self._inflight[key_id]
            refreshed = ProtectionRecord(
                key_id=record.key_id, ttl_seq=record.ttl_seq,
                backend=record.backend, entry_seq=seq, seq=seq,
                digest=_pin(
                    "protect", record.key_id, record.ttl_seq,
                    record.backend, seq, seq,
                ),
            )
            self._protections[key_id] = refreshed
            completion = RefreshCompletion(
                refresh_id=refresh_id, key_id=key_id,
                value_digest=value_digest, released_followers=len(followers),
                seq=seq,
                digest=_pin(
                    "refresh-complete", refresh_id, key_id, value_digest,
                    len(followers), seq,
                ),
            )
            self._audit_locked(
                KIND_REFRESH_COMPLETED,
                {"key_id": key_id, "refresh_id": refresh_id,
                 "released": len(followers)},
            )
            return completion

    # -- jitter ----------------------------------------------------------

    def jitter(self, key_id: str, seq: int, spread_seq: int) -> JitterRecord:
        """Pin deterministic jitter: stagger expiry by a digest-derived draw.

        The stagger is ``H(key_id, seq) mod (spread+1)``: reproducible,
        spread across keys, but not random. ``jittered_expiry`` exposes
        the effective expiry as a pure view.
        """
        with self._lock:
            key_id = _check_nonempty_str(key_id, "key_id")
            if isinstance(spread_seq, bool) or not isinstance(spread_seq, int) \
                    or spread_seq < 0:
                raise BadJitterError("spread_seq must be a non-negative int")
            self._claim_seq(seq)
            record = self._protection_locked(key_id)
            if spread_seq >= record.ttl_seq:
                self._reject_locked("spread-too-wide")
                raise BadJitterError(
                    f"spread_seq {spread_seq} must be < ttl_seq {record.ttl_seq}"
                )
            stagger = _stagger(key_id, seq, spread_seq)
            jittered = JitterRecord(
                key_id=key_id, spread_seq=spread_seq, stagger=stagger, seq=seq,
                digest=_pin("jitter", key_id, spread_seq, stagger, seq),
            )
            self._jitters[key_id] = jittered
            self._audit_locked(
                KIND_JITTER_SET,
                {"key_id": key_id, "spread_seq": spread_seq, "stagger": stagger},
            )
            return jittered

    def jittered_expiry(self, key_id: str) -> int:
        """Pure view: deterministic effective expiry seq for the key."""
        with self._lock:
            key_id = _check_nonempty_str(key_id, "key_id")
            record = self._protection_locked(key_id)
            jittered = self._jitters.get(key_id)
            stagger = jittered.stagger if jittered is not None else 0
            return record.entry_seq + record.ttl_seq - stagger

    # -- unprotect -------------------------------------------------------

    def unprotect(self, key_id: str, seq: int, reason: str = "") -> UnprotectRecord:
        """Retire a key protection (terminal; the id is never recycled)."""
        with self._lock:
            key_id = _check_nonempty_str(key_id, "key_id")
            if not isinstance(reason, str):
                raise CacheStampedeError("reason must be a string")
            self._claim_seq(seq)
            if key_id in self._removed:
                self._reject_locked("already-removed")
                raise RemovedKeyError(f"key {key_id!r} already unprotected")
            if key_id not in self._protections:
                self._reject_locked("unknown-key")
                raise UnknownKeyError(f"no protection for key {key_id!r}")
            if key_id in self._inflight:
                self._reject_locked("refresh-in-flight")
                raise CacheStampedeError(
                    f"cannot unprotect key {key_id!r}: refresh in flight"
                )
            del self._protections[key_id]
            del self._seen_requests[key_id]
            self._jitters.pop(key_id, None)
            self._removed.add(key_id)
            record = UnprotectRecord(
                key_id=key_id, reason=reason.strip(), seq=seq,
                digest=_pin("unprotect", key_id, reason.strip(), seq),
            )
            self._audit_locked(KIND_UNPROTECTED, {"key_id": key_id})
            return record

    # -- views -----------------------------------------------------------

    def protection(self, key_id: str) -> ProtectionRecord:
        with self._lock:
            return self._protection_locked(_check_nonempty_str(key_id, "key_id"))

    def key_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._protections))

    def inflight(self, key_id: str) -> Optional[RefreshRecord]:
        with self._lock:
            self._protection_locked(_check_nonempty_str(key_id, "key_id"))
            return self._inflight.get(key_id)

    def follower_ids(self, key_id: str) -> Tuple[str, ...]:
        with self._lock:
            self._protection_locked(_check_nonempty_str(key_id, "key_id"))
            return tuple(self._inflight_followers.get(key_id, ()))

    def jitter_record(self, key_id: str) -> Optional[JitterRecord]:
        with self._lock:
            self._protection_locked(_check_nonempty_str(key_id, "key_id"))
            return self._jitters.get(key_id)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "protected": len(self._protections),
                "removed": len(self._removed),
                "in_flight": len(self._inflight),
                "followers_waiting": sum(
                    len(v) for v in self._inflight_followers.values()
                ),
                "refreshes_started": self._refresh_seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    cs = CacheStampede()
    p = cs.protect("hot-key", 100, 1, backend="redis")
    assert p.verify()
    d1 = cs.coalesce("hot-key", "req-1", 2)          # fresh -> hit
    assert d1.role == "hit" and d1.verify()
    d2 = cs.coalesce("hot-key", "req-2", 150)        # stale -> leader
    assert d2.role == "leader" and d2.verify()
    d3 = cs.coalesce("hot-key", "req-3", 151)        # coalesced follower
    assert d3.role == "follower" and d3.verify()
    assert d3.refresh_id == d2.refresh_id
    assert cs.follower_ids("hot-key") == ("req-3",)
    digest = "sha256:" + "ab" * 32
    done = cs.complete_refresh("hot-key", d2.refresh_id, digest, 152)
    assert done.verify() and done.released_followers == 1
    assert cs.inflight("hot-key") is None
    d4 = cs.coalesce("hot-key", "req-4", 153)        # fresh again -> hit
    assert d4.role == "hit"
    j = cs.jitter("hot-key", 154, 20)
    assert j.verify() and 0 <= j.stagger <= 20
    assert cs.jittered_expiry("hot-key") == 152 + 100 - j.stagger
    u = cs.unprotect("hot-key", 155, "key retired")
    assert u.verify()
    print("cache-stampede OK: protect, coalesce, leader, follower, refresh, jitter")
    return None


if __name__ == "__main__":
    main()
