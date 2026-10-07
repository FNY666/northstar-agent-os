"""CDN cache purge and prefetch bookkeeping.

A ``CDNManager`` books host-reported cache operations as a deterministic
single-host state machine:

- ``register_zone(zone_id, seq)`` pins a cache zone. Zone ids are
  non-empty strings; duplicates are refused fail-closed.
- ``purge(zone_id, target, seq)`` books one purge attempt as a frozen
  ``PurgeRecord`` (``pur-N`` ids). Targets are ``*`` (whole zone) or a
  URL path starting with ``/``. The outcome comes from a
  host-injectable ``edge(zone_id, target) -> bool`` (default: always
  succeeds, in memory); a failed attempt is *data*
  (``status="failed"``), never an exception.
- ``retry_purge(purge_id, seq)`` books a follow-up attempt linked via
  ``prev_purge_id``; retrying a completed purge raises
  ``AlreadyCompletedError``; exceeding ``MAX_ATTEMPTS = 5`` raises
  ``MaxAttemptsError``.
- ``prefetch(zone_id, urls, seq)`` books a warm-up batch as a frozen
  ``PrefetchRecord`` (``prf-N`` ids) with one frozen ``PrefetchItem``
  per URL; per-URL outcomes come from a host-injectable
  ``warmer(zone_id, url) -> bool`` (default: always succeeds). URLs must
  be ``https://``.
- ``stats(seq)`` is a pure read view (validates the seq shape, does not
  consume it) returning a digest-pinned ``StatsReport``.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin ``cdn-manager.v1``,
schema pin ``northstar.cdn-manager.v1``, ``main()`` self-check.

Honest scope: this module books purge/prefetch *decisions*, not cache
operations — there is no CDN, no HTTP client, no edge network. The
default ``edge``/``warmer`` backends are stubs; a host backend reports
its own truth (GIGO). Purge targets and prefetch URLs never cross the
audit boundary (ids + digest pins only).
"""

from __future__ import annotations

import ast
import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
CDN_MANAGER_VERSION = "cdn-manager.v1"

#: Schema pin carried by records and audit events.
CDN_MANAGER_SCHEMA = "northstar.cdn-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_DIGEST_PREFIX = "sha256:"

#: Pin: purge/prefetch item statuses.
STATUSES = ("completed", "failed")

#: Pin: maximum purge attempts per purge chain.
MAX_ATTEMPTS = 5

#: Pin: maximum purge target length.
MAX_TARGET_LEN = 2048

#: Pin: allowed prefetch URL scheme.
_URL_SCHEME = "https://"

#: Pin: audit event kinds.
_AUDIT_KINDS = (
    "zone-registered",
    "purged",
    "purge-retried",
    "prefetched",
    "rejected",
)


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class CDNManagerError(ValueError):
    """Base class for all cdn_manager errors."""


class BadZoneError(CDNManagerError):
    """Malformed zone id."""


class DuplicateZoneError(CDNManagerError):
    """This zone id is already registered."""


class UnknownZoneError(CDNManagerError):
    """No zone with this id is registered."""


class BadTargetError(CDNManagerError):
    """Malformed purge target."""


class BadURLError(CDNManagerError):
    """Malformed prefetch URL."""


class UnknownPurgeError(CDNManagerError):
    """No purge with this id exists."""


class AlreadyCompletedError(CDNManagerError):
    """This purge already completed; retry is meaningless."""


class MaxAttemptsError(CDNManagerError):
    """This purge chain exhausted its attempt budget."""


class UnknownPrefetchError(CDNManagerError):
    """No prefetch with this id exists."""


class AuditKindError(CDNManagerError):
    """Unknown audit event kind."""


class SeqOrderError(CDNManagerError):
    """Mutation seq is not strictly increasing."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CDNManagerError(
            f"{field_name} must be a non-negative int, saw {value!r}"
        )
    return value


def _check_zone_id(value: Any, field_name: str = "zone_id") -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadZoneError(f"{field_name} must be a non-empty string")
    return value.strip()


def _check_target(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise BadTargetError("target must be a non-empty string")
    if len(value) > MAX_TARGET_LEN:
        raise BadTargetError(f"target longer than {MAX_TARGET_LEN} chars")
    if value != "*" and not value.startswith("/"):
        raise BadTargetError("target must be '*' or a path starting with '/'")
    if any(ord(c) < 0x20 or c in " \t" for c in value):
        raise BadTargetError("target contains whitespace/control characters")
    return value


def _check_url(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith(_URL_SCHEME):
        raise BadURLError("prefetch URLs must start with 'https://'")
    host = value[len(_URL_SCHEME):].split("/")[0]
    if not host or "." not in host or any(c in " \t" for c in value):
        raise BadURLError(f"malformed prefetch URL: {value!r}")
    return value


def _check_digest(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(_DIGEST_PREFIX)
        or len(value) != len(_DIGEST_PREFIX) + 64
        or not all(c in "0123456789abcdef" for c in value[len(_DIGEST_PREFIX):])
    ):
        raise BadTargetError("digest must be 'sha256:' + 64 hex chars")
    return value


# ---------------------------------------------------------------------------
# Canonical digest helpers
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    # Payloads are str/int/bool/None/dict/list/tuple only — no floats, so no
    # >2^53 precision hazard; ints serialize exactly.
    return jcs_canonical_json(obj)


def _pin(*parts: Any) -> str:
    """sha256 hex pin over the canonical encoding of the parts."""
    return hashlib.sha256(_canonical(list(parts))).hexdigest()


def _digest(*parts: Any) -> str:
    return _DIGEST_PREFIX + _pin(*parts)


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def cdn_manager_audit_event(
    kind: str,
    seq: int,
    zone_id: str = "",
    purge_id: str = "",
    prefetch_id: str = "",
    detail: str = "",
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event; ids and digest pins only.

    Purge targets and prefetch URLs never cross the audit boundary.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    return {
        "schema": AUDIT_SCHEMA,
        "module": CDN_MANAGER_VERSION,
        "kind": kind,
        "seq": seq,
        "zone_id": zone_id,
        "purge_id": purge_id,
        "prefetch_id": prefetch_id,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ZoneRecord:
    """A registered cache zone."""

    zone_id: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            CDN_MANAGER_SCHEMA, "zone", self.zone_id, self.seq
        )


@dataclass(frozen=True)
class PurgeRecord:
    """One purge attempt. ``status`` is data, never an exception."""

    purge_id: str
    zone_id: str
    target: str
    status: str
    attempt: int
    prev_purge_id: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            CDN_MANAGER_SCHEMA,
            "purge",
            self.purge_id,
            self.zone_id,
            self.target,
            self.status,
            self.attempt,
            self.prev_purge_id,
            self.seq,
        )


@dataclass(frozen=True)
class PrefetchItem:
    """One warmed URL inside a prefetch batch."""

    url: str
    status: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            CDN_MANAGER_SCHEMA, "prefetch-item", self.url, self.status
        )


@dataclass(frozen=True)
class PrefetchRecord:
    """One prefetch batch."""

    prefetch_id: str
    zone_id: str
    items: Tuple[PrefetchItem, ...]
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            CDN_MANAGER_SCHEMA,
            "prefetch",
            self.prefetch_id,
            self.zone_id,
            [i.digest for i in self.items],
            self.seq,
        )


@dataclass(frozen=True)
class StatsReport:
    """Aggregate counts. Pure read view: seq validated, not consumed."""

    seq: int
    zones: int
    purges_completed: int
    purges_failed: int
    prefetches: int
    urls_prefetched: int
    urls_completed: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            CDN_MANAGER_SCHEMA,
            "stats",
            self.zones,
            self.purges_completed,
            self.purges_failed,
            self.prefetches,
            self.urls_prefetched,
            self.urls_completed,
            self.seq,
        )


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class CDNManager:
    """Deterministic purge/prefetch bookkeeping for cache zones."""

    def __init__(
        self,
        seed: str = "",
        edge: Optional[Callable[[str, str], bool]] = None,
        warmer: Optional[Callable[[str, str], bool]] = None,
    ) -> None:
        self._seed = seed
        self._edge = edge if edge is not None else (lambda _z, _t: True)
        self._warmer = warmer if warmer is not None else (lambda _z, _u: True)
        self._lock = threading.RLock()
        self._zones: Dict[str, ZoneRecord] = {}
        self._purges: Dict[str, PurgeRecord] = {}
        self._purge_counter = 0
        self._prefetches: Dict[str, PrefetchRecord] = {}
        self._prefetch_counter = 0
        self._last_seq = -1
        self._audit_log: List[Dict[str, Any]] = []

    # -- internal ---------------------------------------------------------

    def _take_seq(self, seq: Any) -> int:
        """Validate and consume a mutation seq (strictly increasing)."""
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must exceed last mutation seq {self._last_seq}, saw {seq}"
            )
        self._last_seq = seq
        return seq

    def _audit(self, kind: str, seq: int, **ids: str) -> None:
        self._audit_log.append(cdn_manager_audit_event(kind, seq, **ids))

    def _reject(self, seq: int, error: CDNManagerError, **ids: str) -> None:
        """Book a rejection, then raise. The seq is already consumed."""
        self._audit("rejected", seq, detail=type(error).__name__, **ids)
        raise error

    # -- zones ------------------------------------------------------------

    def register_zone(self, zone_id: str, seq: int) -> ZoneRecord:
        """Pin a cache zone."""
        with self._lock:
            self._take_seq(seq)
            try:
                zone_id = _check_zone_id(zone_id)
                if zone_id in self._zones:
                    raise DuplicateZoneError(
                        f"zone already registered: {zone_id!r}"
                    )
            except CDNManagerError as exc:
                self._reject(seq, exc)
            record = ZoneRecord(
                zone_id=zone_id,
                seq=seq,
                digest=_digest(CDN_MANAGER_SCHEMA, "zone", zone_id, seq),
            )
            self._zones[zone_id] = record
            self._audit("zone-registered", seq, zone_id=zone_id)
            return record

    def zone(self, zone_id: str) -> ZoneRecord:
        """Read a zone record; unknown ids raise."""
        with self._lock:
            record = self._zones.get(zone_id)
            if record is None:
                raise UnknownZoneError(f"unknown zone: {zone_id!r}")
            return record

    def zone_ids(self) -> Tuple[str, ...]:
        """Sorted registered zone ids."""
        with self._lock:
            return tuple(sorted(self._zones))

    # -- purge ------------------------------------------------------------

    def purge(self, zone_id: str, target: str, seq: int) -> PurgeRecord:
        """Book one purge attempt. Outcome is data, never an exception."""
        with self._lock:
            self._take_seq(seq)
            try:
                zone_id = _check_zone_id(zone_id)
                if zone_id not in self._zones:
                    raise UnknownZoneError(f"unknown zone: {zone_id!r}")
                target = _check_target(target)
            except CDNManagerError as exc:
                self._reject(seq, exc, zone_id=zone_id)
            try:
                ok = bool(self._edge(zone_id, target))
            except Exception:
                ok = False  # a raising edge counts as failure (fail-closed)
            self._purge_counter += 1
            purge_id = f"pur-{self._purge_counter}"
            status = "completed" if ok else "failed"
            record = PurgeRecord(
                purge_id=purge_id,
                zone_id=zone_id,
                target=target,
                status=status,
                attempt=1,
                prev_purge_id="",
                seq=seq,
                digest=_digest(
                    CDN_MANAGER_SCHEMA,
                    "purge",
                    purge_id,
                    zone_id,
                    target,
                    status,
                    1,
                    "",
                    seq,
                ),
            )
            self._purges[purge_id] = record
            self._audit("purged", seq, zone_id=zone_id, purge_id=purge_id)
            return record

    def retry_purge(self, purge_id: str, seq: int) -> PurgeRecord:
        """Book a follow-up attempt for a failed purge."""
        with self._lock:
            self._take_seq(seq)
            prior = self._purges.get(purge_id)
            if prior is None:
                self._reject(seq, UnknownPurgeError(f"unknown purge: {purge_id!r}"))
            assert prior is not None
            if prior.status == "completed":
                self._reject(
                    seq,
                    AlreadyCompletedError(
                        f"purge already completed: {purge_id!r}"
                    ),
                    purge_id=purge_id,
                )
            if prior.attempt >= MAX_ATTEMPTS:
                self._reject(
                    seq,
                    MaxAttemptsError(
                        f"purge {purge_id!r} exhausted {MAX_ATTEMPTS} attempts"
                    ),
                    purge_id=purge_id,
                )
            try:
                ok = bool(self._edge(prior.zone_id, prior.target))
            except Exception:
                ok = False
            self._purge_counter += 1
            new_id = f"pur-{self._purge_counter}"
            attempt = prior.attempt + 1
            status = "completed" if ok else "failed"
            record = PurgeRecord(
                purge_id=new_id,
                zone_id=prior.zone_id,
                target=prior.target,
                status=status,
                attempt=attempt,
                prev_purge_id=prior.purge_id,
                seq=seq,
                digest=_digest(
                    CDN_MANAGER_SCHEMA,
                    "purge",
                    new_id,
                    prior.zone_id,
                    prior.target,
                    status,
                    attempt,
                    prior.purge_id,
                    seq,
                ),
            )
            self._purges[new_id] = record
            self._audit(
                "purge-retried",
                seq,
                zone_id=prior.zone_id,
                purge_id=new_id,
            )
            return record

    def purge_record(self, purge_id: str) -> PurgeRecord:
        """Read a purge record; unknown ids raise."""
        with self._lock:
            record = self._purges.get(purge_id)
            if record is None:
                raise UnknownPurgeError(f"unknown purge: {purge_id!r}")
            return record

    def purges_for(self, zone_id: str) -> Tuple[str, ...]:
        """Purge ids for a zone, in booking order."""
        with self._lock:
            if zone_id not in self._zones:
                raise UnknownZoneError(f"unknown zone: {zone_id!r}")
            return tuple(
                p.purge_id
                for p in sorted(
                    self._purges.values(),
                    key=lambda r: int(r.purge_id.split("-")[1]),
                )
                if p.zone_id == zone_id
            )

    # -- prefetch ---------------------------------------------------------

    def prefetch(
        self, zone_id: str, urls: Sequence[str], seq: int
    ) -> PrefetchRecord:
        """Book a warm-up batch; per-URL outcomes are data."""
        with self._lock:
            self._take_seq(seq)
            try:
                zone_id = _check_zone_id(zone_id)
                if zone_id not in self._zones:
                    raise UnknownZoneError(f"unknown zone: {zone_id!r}")
                if not isinstance(urls, (list, tuple)) or not urls:
                    raise BadURLError("urls must be a non-empty list/tuple")
                checked = [_check_url(u) for u in urls]
            except CDNManagerError as exc:
                self._reject(seq, exc, zone_id=zone_id)
            items: List[PrefetchItem] = []
            for url in checked:
                try:
                    ok = bool(self._warmer(zone_id, url))
                except Exception:
                    ok = False
                status = "completed" if ok else "failed"
                items.append(
                    PrefetchItem(
                        url=url,
                        status=status,
                        digest=_digest(
                            CDN_MANAGER_SCHEMA, "prefetch-item", url, status
                        ),
                    )
                )
            self._prefetch_counter += 1
            prefetch_id = f"prf-{self._prefetch_counter}"
            record = PrefetchRecord(
                prefetch_id=prefetch_id,
                zone_id=zone_id,
                items=tuple(items),
                seq=seq,
                digest=_digest(
                    CDN_MANAGER_SCHEMA,
                    "prefetch",
                    prefetch_id,
                    zone_id,
                    [i.digest for i in items],
                    seq,
                ),
            )
            self._prefetches[prefetch_id] = record
            self._audit(
                "prefetched", seq, zone_id=zone_id, prefetch_id=prefetch_id
            )
            return record

    def prefetch_record(self, prefetch_id: str) -> PrefetchRecord:
        """Read a prefetch record; unknown ids raise."""
        with self._lock:
            record = self._prefetches.get(prefetch_id)
            if record is None:
                raise UnknownPrefetchError(
                    f"unknown prefetch: {prefetch_id!r}"
                )
            return record

    # -- views ------------------------------------------------------------

    def stats(self, seq: int) -> StatsReport:
        """Aggregate counts. Pure view: validates seq shape, consumes nothing."""
        _check_seq(seq)
        with self._lock:
            completed = sum(
                1 for p in self._purges.values() if p.status == "completed"
            )
            failed = sum(
                1 for p in self._purges.values() if p.status == "failed"
            )
            urls_total = sum(len(r.items) for r in self._prefetches.values())
            urls_ok = sum(
                1
                for r in self._prefetches.values()
                for i in r.items
                if i.status == "completed"
            )
            report = StatsReport(
                seq=seq,
                zones=len(self._zones),
                purges_completed=completed,
                purges_failed=failed,
                prefetches=len(self._prefetches),
                urls_prefetched=urls_total,
                urls_completed=urls_ok,
                digest="",
            )
            digest = _digest(
                CDN_MANAGER_SCHEMA,
                "stats",
                report.zones,
                report.purges_completed,
                report.purges_failed,
                report.prefetches,
                report.urls_prefetched,
                report.urls_completed,
                seq,
            )
            return StatsReport(
                seq=seq,
                zones=report.zones,
                purges_completed=completed,
                purges_failed=failed,
                prefetches=report.prefetches,
                urls_prefetched=urls_total,
                urls_completed=urls_ok,
                digest=digest,
            )

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """Append-only audit trail."""
        with self._lock:
            return tuple(self._audit_log)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    def fail_first(zone_id: str, target: str) -> bool:
        return target != "/flaky"

    def warm_all(zone_id: str, url: str) -> bool:
        return True

    mgr = CDNManager(seed="selfcheck", edge=fail_first, warmer=warm_all)
    z = mgr.register_zone("zone-1", 1)
    assert z.verify()
    p1 = mgr.purge("zone-1", "/flaky", 2)
    assert p1.status == "failed" and p1.attempt == 1 and p1.verify()
    p2 = mgr.retry_purge(p1.purge_id, 3)
    assert p2.attempt == 2 and p2.prev_purge_id == p1.purge_id
    assert p2.verify()
    p3 = mgr.purge("zone-1", "*", 4)
    assert p3.status == "completed" and p3.verify()
    b = mgr.prefetch("zone-1", ["https://cdn.example.com/a.js"], 5)
    assert b.verify() and all(i.verify() for i in b.items)
    s = mgr.stats(6)
    assert s.verify()
    assert (s.zones, s.purges_completed, s.purges_failed) == (1, 1, 2)
    assert (s.prefetches, s.urls_prefetched, s.urls_completed) == (1, 1, 1)
    kinds = [e["kind"] for e in mgr.audit_log()]
    assert kinds == [
        "zone-registered",
        "purged",
        "purge-retried",
        "purged",
        "prefetched",
    ], kinds
    try:
        mgr.purge("zone-1", "no-slash", 7)
    except BadTargetError:
        pass
    else:
        raise AssertionError("expected BadTargetError")
    try:
        mgr.retry_purge(p3.purge_id, 8)
    except AlreadyCompletedError:
        pass
    else:
        raise AssertionError("expected AlreadyCompletedError")
    print("cdn-manager OK: zones, purge, retry, prefetch, stats, pins, audit")


if __name__ == "__main__":
    main()
