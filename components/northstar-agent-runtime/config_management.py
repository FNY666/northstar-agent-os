"""Config KV store bookkeeping: a ledger for configuration decisions.

A ``ConfigManagement`` books host-reported configuration-store decisions
(Consul/etcd shaped) as a deterministic single-host state machine:

- ``set(key, value, seq)`` upserts one key as a frozen ``EntryRecord``
  (``ver-N`` ids per key). Keys are slash-separated paths; values are
  ``str`` or ``bytes`` capped at ``MAX_VALUE_BYTES``. Duplicate sets are
  fine — every set mints a new version. Unknown keys refuse ``get``.
- ``get(key, seq)`` is a pure read view (seq validated, not consumed).
- ``delete(key, seq)`` and ``delete_prefix(prefix, seq)`` book frozen
  ``TombstoneRecord``\\ s; prefix deletes apply atomically via the
  transaction book.
- ``cas(key, expected_version, value, seq)`` books a check-and-set; a
  version mismatch is data refused fail-closed (``CasMismatchError``) and
  consumes its seq.
- ``grant(lease_id, ttl_seq, seq)`` books a frozen ``LeaseRecord`` whose
  ``expiry_seq`` is derived from the caller seq (no wall-clock); ``attach``
  binds keys to a lease; ``expire(seq)`` revokes expired leases and
  tombstones their keys deterministically.
- ``watch(prefix, seq)`` registers a frozen ``WatcherRecord`` (``w-N``
  ids); ``poll(watcher_id, seq)`` returns a frozen ``EventPage`` of every
  change under the prefix since the watcher's cursor, then advances it.
  ``cancel_watch(watcher_id, seq)`` stops delivery.
- ``session(session_id, seq)`` / ``destroy_session(session_id, seq)``
  book session lifecycles; ``lock(key, session_id, seq)`` acquires a
  distributed-lock-shaped guard and ``unlock(key, session_id, seq)``
  releases it. Locks survive until released or their session is destroyed.
- ``transaction(ops, seq)`` applies a frozen list of ``set``/``delete``
  ops atomically — validated first, then all applied — and books one
  frozen ``TransactionRecord``.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``config-management.v1``, schema pin ``northstar.config-management.v1``,
``main()`` self-check.

Honest scope: this module books *decisions* about a config store — there
is no network, no Raft, no real TTL scheduler. Leases expire when the
caller advances the logical seq watermark past them (GIGO on the host).
Values live in records; the audit boundary carries digests only.
"""

from __future__ import annotations

import ast
import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
CONFIG_MANAGEMENT_VERSION = "config-management.v1"

#: Schema pin carried by records and audit events.
CONFIG_MANAGEMENT_SCHEMA = "northstar.config-management.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pin: maximum value size in bytes (etcd default 1.5 MiB is far too much
#: for a deterministic bookkeeping ledger; 64 KiB is the house ceiling).
MAX_VALUE_BYTES = 65536

#: Pin: maximum key length in chars.
MAX_KEY_CHARS = 512

#: Pin: maximum transaction op count.
MAX_TX_OPS = 128

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class ConfigManagementError(Exception):
    """Base class for all config_management errors."""


class BadKeyError(ConfigManagementError):
    """The key is malformed (empty, too long, control chars, '..')."""


class UnknownKeyError(ConfigManagementError):
    """The key was never set or has been deleted."""


class BadValueError(ConfigManagementError):
    """The value is the wrong type or exceeds the size ceiling."""


class CasMismatchError(ConfigManagementError):
    """The expected version did not match the current version."""


class BadLeaseError(ConfigManagementError):
    """The lease request is malformed (id, ttl)."""


class UnknownLeaseError(ConfigManagementError):
    """The referenced lease id is unknown."""


class DuplicateLeaseError(ConfigManagementError):
    """A lease with this id already exists."""


class ExpiredLeaseError(ConfigManagementError):
    """The lease has expired at the current logical seq watermark."""


class UnknownWatcherError(ConfigManagementError):
    """The referenced watcher id is unknown."""


class CancelledWatcherError(ConfigManagementError):
    """Polling a watcher that has been cancelled."""


class BadSessionError(ConfigManagementError):
    """The session request is malformed."""


class UnknownSessionError(ConfigManagementError):
    """The referenced session id is unknown or destroyed."""


class LockHeldError(ConfigManagementError):
    """The lock is already held by another live session."""


class LockNotHeldError(ConfigManagementError):
    """The lock is not held (or not by this session)."""


class BadOpError(ConfigManagementError):
    """A transaction op is malformed."""


class SeqOrderError(ConfigManagementError):
    """Seq is not a non-negative int or not strictly increasing."""


class AuditKindError(ConfigManagementError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------


def _tag_encode(value: Any) -> Any:
    if value is True:
        return {"$bool": True}
    if value is False:
        return {"$bool": False}
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadValueError("integer out of safe range")
        return {"$int": value}
    if isinstance(value, float):
        raise BadValueError("floats are not permitted in pinned structures")
    if isinstance(value, (bytes, bytearray)):
        return {"$bytes": bytes(value).hex()}
    if isinstance(value, (list, tuple)):
        return [_tag_encode(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _tag_encode(v) for k, v in value.items()}
    if isinstance(value, (str, type(None))):
        return value
    raise BadValueError(f"unsupported value type: {type(value).__name__}")


def _pin(*parts: Any) -> str:
    canonical = jcs_canonical_json(_tag_encode(list(parts)))
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _value_digest(value: Any) -> str:
    """Digest the raw value for the audit boundary (value never crosses)."""
    return _pin("config-management-value", _tag_encode(value))


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_key(key: Any) -> str:
    if not isinstance(key, str) or not key:
        raise BadKeyError("key must be a non-empty str")
    if len(key) > MAX_KEY_CHARS:
        raise BadKeyError(f"key exceeds {MAX_KEY_CHARS} chars")
    if _CONTROL_RE.search(key):
        raise BadKeyError("key carries control characters")
    if key != key.strip():
        raise BadKeyError("key must not carry leading/trailing whitespace")
    if "//" in key or ".." in key.split("/"):
        raise BadKeyError("key must not contain empty segments or '..'")
    return key


def _check_value(value: Any) -> None:
    if not isinstance(value, (str, bytes)):
        raise BadValueError("value must be str or bytes")
    size = len(value.encode("utf-8") if isinstance(value, str) else value)
    if size > MAX_VALUE_BYTES:
        raise BadValueError(f"value exceeds {MAX_VALUE_BYTES} bytes")


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "entry-set",
    "entry-deleted",
    "lease-granted",
    "lease-revoked",
    "watch-registered",
    "watch-cancelled",
    "session-opened",
    "session-destroyed",
    "lock-acquired",
    "lock-released",
    "transaction-applied",
    "rejected",
)


def config_management_audit_event(
    kind: str,
    seq: int,
    key: str = "",
    watcher_id: str = "",
    detail: str = "",
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event; keys and digests only.

    Raw values, lease bindings and watcher filters never cross the audit
    boundary — only the key plus a value digest pin.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    return {
        "schema": AUDIT_SCHEMA,
        "module": CONFIG_MANAGEMENT_VERSION,
        "kind": kind,
        "seq": seq,
        "key": key,
        "watcher_id": watcher_id,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EntryRecord:
    key: str
    value: Any  # str or bytes, as supplied
    version: int
    seq: int
    lease_id: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            CONFIG_MANAGEMENT_SCHEMA,
            "entry",
            self.key,
            _tag_encode(self.value),
            self.version,
            self.seq,
            self.lease_id,
        )


@dataclass(frozen=True)
class TombstoneRecord:
    key: str
    version: int  # the version deleted (last known)
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            CONFIG_MANAGEMENT_SCHEMA, "tombstone", self.key, self.version, self.seq
        )


@dataclass(frozen=True)
class LeaseRecord:
    lease_id: str
    ttl_seq: int
    granted_seq: int
    expiry_seq: int
    seq: int
    revoked: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            CONFIG_MANAGEMENT_SCHEMA,
            "lease",
            self.lease_id,
            self.ttl_seq,
            self.granted_seq,
            self.expiry_seq,
            self.seq,
            self.revoked,
        )


@dataclass(frozen=True)
class WatchEvent:
    key: str
    op: str  # "set" | "delete"
    version: int
    seq: int


@dataclass(frozen=True)
class WatcherRecord:
    watcher_id: str
    prefix: str
    cursor_seq: int
    cancelled: bool
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            CONFIG_MANAGEMENT_SCHEMA,
            "watcher",
            self.watcher_id,
            self.prefix,
            self.cursor_seq,
            self.cancelled,
            self.seq,
        )


@dataclass(frozen=True)
class EventPage:
    watcher_id: str
    events: Tuple[WatchEvent, ...]
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            CONFIG_MANAGEMENT_SCHEMA,
            "event-page",
            self.watcher_id,
            self.seq,
            [(e.key, e.op, e.version, e.seq) for e in self.events],
        )


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    seq: int
    live: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            CONFIG_MANAGEMENT_SCHEMA,
            "session",
            self.session_id,
            self.seq,
            self.live,
        )


@dataclass(frozen=True)
class LockRecord:
    key: str
    session_id: str
    seq: int
    held: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            CONFIG_MANAGEMENT_SCHEMA,
            "lock",
            self.key,
            self.session_id,
            self.seq,
            self.held,
        )


@dataclass(frozen=True)
class TransactionRecord:
    tx_id: str
    ops: Tuple[Tuple[str, str], ...]  # (op, key) pairs
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            CONFIG_MANAGEMENT_SCHEMA,
            "transaction",
            self.tx_id,
            list(self.ops),
            self.seq,
        )


# ---------------------------------------------------------------------------
# ConfigManagement
# ---------------------------------------------------------------------------


class ConfigManagement:
    """Deterministic single-host ledger for config-store decisions."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: Dict[str, EntryRecord] = {}
        self._tombstones: Dict[str, TombstoneRecord] = {}
        self._leases: Dict[str, LeaseRecord] = {}
        self._lease_keys: Dict[str, set] = {}  # lease_id -> keys
        self._watchers: Dict[str, WatcherRecord] = {}
        self._events: List[Tuple[str, WatchEvent]] = []  # (prefix-match, event) log
        self._sessions: Dict[str, SessionRecord] = {}
        self._locks: Dict[str, LockRecord] = {}  # key -> current lock state
        self._audit: List[Dict[str, Any]] = []
        self._last_seq = -1
        self._w_counter = 0
        self._tx_counter = 0

    # -- internals ------------------------------------------------------

    def _check_seq(self, seq: Any) -> None:
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (got {seq}, last {self._last_seq})"
            )
        self._last_seq = seq

    def _read_seq(self, seq: Any) -> None:
        """Validate seq shape for read views; never consumes."""
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise SeqOrderError("seq must be a non-negative int")

    def _reject(self, seq: int, reason: str, key: str = "") -> None:
        try:
            self._check_seq(seq)
        except SeqOrderError:
            pass
        self._audit.append(
            config_management_audit_event("rejected", seq, key=key, detail=reason)
        )

    def _emit_event(self, key: str, op: str, version: int, seq: int) -> None:
        self._events.append((key, WatchEvent(key=key, op=op, version=version, seq=seq)))

    def _entry_digest(
        self, key: str, value: Any, version: int, seq: int, lease_id: str
    ) -> str:
        return _pin(
            CONFIG_MANAGEMENT_SCHEMA,
            "entry",
            key,
            _tag_encode(value),
            version,
            seq,
            lease_id,
        )

    def _set_locked(
        self, key: str, value: Any, seq: int, lease_id: str = ""
    ) -> EntryRecord:
        prev = self._entries.get(key)
        version = (prev.version + 1) if prev is not None else 1
        record = EntryRecord(
            key=key,
            value=value,
            version=version,
            seq=seq,
            lease_id=lease_id,
            digest=self._entry_digest(key, value, version, seq, lease_id),
        )
        self._entries[key] = record
        self._tombstones.pop(key, None)
        self._emit_event(key, "set", version, seq)
        self._audit.append(
            config_management_audit_event(
                "entry-set",
                seq,
                key=key,
                detail=f"version={version} value={_value_digest(value)}",
            )
        )
        return record

    def _delete_locked(self, key: str, seq: int) -> TombstoneRecord:
        prev = self._entries.pop(key, None)
        version = prev.version if prev is not None else 0
        tomb = TombstoneRecord(
            key=key,
            version=version,
            seq=seq,
            digest=_pin(CONFIG_MANAGEMENT_SCHEMA, "tombstone", key, version, seq),
        )
        self._tombstones[key] = tomb
        self._emit_event(key, "delete", version, seq)
        self._audit.append(
            config_management_audit_event(
                "entry-deleted", seq, key=key, detail=f"version={version}"
            )
        )
        return tomb

    # -- key/value API --------------------------------------------------

    def set(self, key: str, value: Any, seq: int) -> EntryRecord:
        """Upsert one key; every set mints a new version."""
        with self._lock:
            try:
                key = _check_key(key)
                _check_value(value)
            except (BadKeyError, BadValueError):
                self._reject(seq, "bad-key-or-value", key=str(key))
                raise
            self._check_seq(seq)
            return self._set_locked(key, value, seq)

    def get(self, key: str, seq: int) -> EntryRecord:
        """Pure read view: validates seq shape, consumes nothing."""
        with self._lock:
            self._read_seq(seq)
            key = _check_key(key)
            record = self._entries.get(key)
            if record is None:
                raise UnknownKeyError(f"unknown key: {key!r}")
            return record

    def delete(self, key: str, seq: int) -> TombstoneRecord:
        with self._lock:
            try:
                key = _check_key(key)
            except BadKeyError:
                self._reject(seq, "bad-key", key=str(key))
                raise
            if key not in self._entries:
                self._reject(seq, "unknown-key", key=key)
                raise UnknownKeyError(f"unknown key: {key!r}")
            self._check_seq(seq)
            return self._delete_locked(key, seq)

    def delete_prefix(self, prefix: str, seq: int) -> Tuple[TombstoneRecord, ...]:
        """Atomically tombstone every key under ``prefix``."""
        with self._lock:
            try:
                prefix = _check_key(prefix)
            except BadKeyError:
                self._reject(seq, "bad-prefix", key=str(prefix))
                raise
            keys = sorted(k for k in self._entries if k == prefix or k.startswith(prefix + "/"))
            if not keys:
                self._reject(seq, "prefix-empty", key=prefix)
                raise UnknownKeyError(f"no keys under prefix: {prefix!r}")
            self._check_seq(seq)
            tombs = tuple(self._delete_locked(k, seq) for k in keys)
            self._book_tx_locked(tuple(("delete", k) for k in keys), seq)
            return tombs

    def prefix(self, key_prefix: str, seq: int) -> Tuple[EntryRecord, ...]:
        """Pure read view of the current entries under a prefix."""
        with self._lock:
            self._read_seq(seq)
            prefix = _check_key(key_prefix)
            return tuple(
                self._entries[k]
                for k in sorted(self._entries)
                if k == prefix or k.startswith(prefix + "/")
            )

    def cas(self, key: str, expected_version: int, value: Any, seq: int) -> EntryRecord:
        """Check-and-set: refuse when the version moved under us."""
        with self._lock:
            try:
                key = _check_key(key)
                _check_value(value)
            except (BadKeyError, BadValueError):
                self._reject(seq, "bad-key-or-value", key=str(key))
                raise
            if (
                not isinstance(expected_version, int)
                or isinstance(expected_version, bool)
                or expected_version < 0
            ):
                self._reject(seq, "bad-expected-version", key=key)
                raise BadValueError("expected_version must be a non-negative int")
            current = self._entries.get(key)
            current_version = current.version if current is not None else 0
            if current_version != expected_version:
                self._reject(seq, "cas-mismatch", key=key)
                raise CasMismatchError(
                    f"expected version {expected_version}, found {current_version}"
                )
            self._check_seq(seq)
            return self._set_locked(key, value, seq)

    # -- lease API ------------------------------------------------------

    def grant(self, lease_id: str, ttl_seq: int, seq: int) -> LeaseRecord:
        """Grant a TTL lease; ``ttl_seq`` is logical-seq units, not seconds."""
        with self._lock:
            if not isinstance(lease_id, str) or not lease_id:
                self._reject(seq, "bad-lease-id")
                raise BadLeaseError("lease_id must be a non-empty str")
            if (
                not isinstance(ttl_seq, int)
                or isinstance(ttl_seq, bool)
                or ttl_seq <= 0
            ):
                self._reject(seq, "bad-ttl")
                raise BadLeaseError("ttl_seq must be a positive int")
            if lease_id in self._leases:
                self._reject(seq, "duplicate-lease")
                raise DuplicateLeaseError(f"lease already granted: {lease_id!r}")
            self._check_seq(seq)
            record = LeaseRecord(
                lease_id=lease_id,
                ttl_seq=ttl_seq,
                granted_seq=seq,
                expiry_seq=seq + ttl_seq,
                seq=seq,
                revoked=False,
                digest=_pin(
                    CONFIG_MANAGEMENT_SCHEMA,
                    "lease",
                    lease_id,
                    ttl_seq,
                    seq,
                    seq + ttl_seq,
                    seq,
                    False,
                ),
            )
            self._leases[lease_id] = record
            self._lease_keys[lease_id] = set()
            self._audit.append(
                config_management_audit_event(
                    "lease-granted", seq, detail=f"lease={lease_id} ttl={ttl_seq}"
                )
            )
            return record

    def attach(self, key: str, lease_id: str, seq: int) -> EntryRecord:
        """Bind an existing key to a live lease."""
        with self._lock:
            try:
                key = _check_key(key)
            except BadKeyError:
                self._reject(seq, "bad-key", key=str(key))
                raise
            lease = self._leases.get(lease_id)
            if lease is None or lease.revoked:
                self._reject(seq, "unknown-lease", key=key)
                raise UnknownLeaseError(f"unknown lease: {lease_id!r}")
            if seq >= lease.expiry_seq:
                self._reject(seq, "lease-expired", key=key)
                raise ExpiredLeaseError(f"lease expired at {lease.expiry_seq}")
            entry = self._entries.get(key)
            if entry is None:
                self._reject(seq, "unknown-key", key=key)
                raise UnknownKeyError(f"unknown key: {key!r}")
            self._check_seq(seq)
            if entry.lease_id:
                self._lease_keys.get(entry.lease_id, set()).discard(key)
            record = EntryRecord(
                key=key,
                value=entry.value,
                version=entry.version + 1,
                seq=seq,
                lease_id=lease_id,
                digest=self._entry_digest(key, entry.value, entry.version + 1, seq, lease_id),
            )
            self._entries[key] = record
            self._lease_keys.setdefault(lease_id, set()).add(key)
            self._emit_event(key, "set", record.version, seq)
            return record

    def revoke(self, lease_id: str, seq: int) -> Tuple[TombstoneRecord, ...]:
        """Revoke a lease and tombstone every key bound to it."""
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None or lease.revoked:
                self._reject(seq, "unknown-lease")
                raise UnknownLeaseError(f"unknown lease: {lease_id!r}")
            self._check_seq(seq)
            keys = sorted(self._lease_keys.get(lease_id, set()))
            tombs = tuple(self._delete_locked(k, seq) for k in keys if k in self._entries)
            self._leases[lease_id] = LeaseRecord(
                lease_id=lease.lease_id,
                ttl_seq=lease.ttl_seq,
                granted_seq=lease.granted_seq,
                expiry_seq=lease.expiry_seq,
                seq=seq,
                revoked=True,
                digest=_pin(
                    CONFIG_MANAGEMENT_SCHEMA,
                    "lease",
                    lease.lease_id,
                    lease.ttl_seq,
                    lease.granted_seq,
                    lease.expiry_seq,
                    seq,
                    True,
                ),
            )
            self._lease_keys[lease_id] = set()
            self._audit.append(
                config_management_audit_event(
                    "lease-revoked", seq, detail=f"lease={lease_id} keys={len(tombs)}"
                )
            )
            return tombs

    def expire(self, seq: int) -> Tuple[TombstoneRecord, ...]:
        """Deterministic TTL sweep: revoke leases whose expiry_seq <= seq."""
        with self._lock:
            self._read_seq(seq)
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be strictly increasing (got {seq}, last {self._last_seq})"
                )
            self._last_seq = seq
            expired = sorted(
                lid
                for lid, lease in self._leases.items()
                if not lease.revoked and lease.expiry_seq <= seq
            )
            tombs: List[TombstoneRecord] = []
            for lid in expired:
                lease = self._leases[lid]
                keys = sorted(self._lease_keys.get(lid, set()))
                for k in keys:
                    if k in self._entries:
                        tombs.append(self._delete_locked(k, seq))
                self._leases[lid] = LeaseRecord(
                    lease_id=lease.lease_id,
                    ttl_seq=lease.ttl_seq,
                    granted_seq=lease.granted_seq,
                    expiry_seq=lease.expiry_seq,
                    seq=seq,
                    revoked=True,
                    digest=_pin(
                        CONFIG_MANAGEMENT_SCHEMA,
                        "lease",
                        lease.lease_id,
                        lease.ttl_seq,
                        lease.granted_seq,
                        lease.expiry_seq,
                        seq,
                        True,
                    ),
                )
                self._lease_keys[lid] = set()
                self._audit.append(
                    config_management_audit_event(
                        "lease-revoked", seq, detail=f"lease={lid} expired"
                    )
                )
            return tuple(tombs)

    # -- watch API ------------------------------------------------------

    def watch(self, prefix: str, seq: int) -> WatcherRecord:
        """Register a prefix watcher; delivery happens via ``poll``."""
        with self._lock:
            try:
                prefix = _check_key(prefix)
            except BadKeyError:
                self._reject(seq, "bad-prefix", key=str(prefix))
                raise
            self._check_seq(seq)
            self._w_counter += 1
            watcher_id = f"w-{self._w_counter}"
            record = WatcherRecord(
                watcher_id=watcher_id,
                prefix=prefix,
                cursor_seq=seq,
                cancelled=False,
                seq=seq,
                digest=_pin(
                    CONFIG_MANAGEMENT_SCHEMA, "watcher", watcher_id, prefix, seq, False, seq
                ),
            )
            self._watchers[watcher_id] = record
            self._audit.append(
                config_management_audit_event(
                    "watch-registered", seq, key=prefix, watcher_id=watcher_id
                )
            )
            return record

    def poll(self, watcher_id: str, seq: int) -> EventPage:
        """Return every event under the watcher's prefix since its cursor."""
        with self._lock:
            self._read_seq(seq)
            watcher = self._watchers.get(watcher_id)
            if watcher is None:
                raise UnknownWatcherError(f"unknown watcher: {watcher_id!r}")
            if watcher.cancelled:
                raise CancelledWatcherError(f"watcher cancelled: {watcher_id!r}")
            events = tuple(
                ev
                for path, ev in self._events
                if ev.seq > watcher.cursor_seq
                and (path == watcher.prefix or path.startswith(watcher.prefix + "/"))
            )
            page = EventPage(
                watcher_id=watcher_id,
                events=events,
                seq=seq,
                digest=_pin(
                    CONFIG_MANAGEMENT_SCHEMA,
                    "event-page",
                    watcher_id,
                    seq,
                    [(e.key, e.op, e.version, e.seq) for e in events],
                ),
            )
            self._watchers[watcher_id] = WatcherRecord(
                watcher_id=watcher.watcher_id,
                prefix=watcher.prefix,
                cursor_seq=seq,
                cancelled=False,
                seq=watcher.seq,
                digest=watcher.digest,
            )
            return page

    def cancel_watch(self, watcher_id: str, seq: int) -> WatcherRecord:
        with self._lock:
            watcher = self._watchers.get(watcher_id)
            if watcher is None:
                self._reject(seq, "unknown-watcher")
                raise UnknownWatcherError(f"unknown watcher: {watcher_id!r}")
            if watcher.cancelled:
                self._reject(seq, "watcher-cancelled")
                raise CancelledWatcherError(f"watcher cancelled: {watcher_id!r}")
            self._check_seq(seq)
            record = WatcherRecord(
                watcher_id=watcher.watcher_id,
                prefix=watcher.prefix,
                cursor_seq=watcher.cursor_seq,
                cancelled=True,
                seq=seq,
                digest=_pin(
                    CONFIG_MANAGEMENT_SCHEMA,
                    "watcher",
                    watcher.watcher_id,
                    watcher.prefix,
                    watcher.cursor_seq,
                    True,
                    seq,
                ),
            )
            self._watchers[watcher_id] = record
            self._audit.append(
                config_management_audit_event(
                    "watch-cancelled", seq, key=watcher.prefix, watcher_id=watcher_id
                )
            )
            return record

    # -- session/lock API -----------------------------------------------

    def session(self, session_id: str, seq: int) -> SessionRecord:
        with self._lock:
            if not isinstance(session_id, str) or not session_id:
                self._reject(seq, "bad-session-id")
                raise BadSessionError("session_id must be a non-empty str")
            existing = self._sessions.get(session_id)
            if existing is not None and existing.live:
                self._reject(seq, "duplicate-session")
                raise BadSessionError(f"session already live: {session_id!r}")
            self._check_seq(seq)
            record = SessionRecord(
                session_id=session_id,
                seq=seq,
                live=True,
                digest=_pin(CONFIG_MANAGEMENT_SCHEMA, "session", session_id, seq, True),
            )
            self._sessions[session_id] = record
            self._audit.append(
                config_management_audit_event(
                    "session-opened", seq, detail=f"session={session_id}"
                )
            )
            return record

    def destroy_session(self, session_id: str, seq: int) -> SessionRecord:
        """Destroy a session; any locks it held are released."""
        with self._lock:
            existing = self._sessions.get(session_id)
            if existing is None or not existing.live:
                self._reject(seq, "unknown-session")
                raise UnknownSessionError(f"unknown session: {session_id!r}")
            self._check_seq(seq)
            for key, lock in list(self._locks.items()):
                if lock.held and lock.session_id == session_id:
                    self._locks[key] = LockRecord(
                        key=key,
                        session_id=session_id,
                        seq=seq,
                        held=False,
                        digest=_pin(
                            CONFIG_MANAGEMENT_SCHEMA, "lock", key, session_id, seq, False
                        ),
                    )
                    self._audit.append(
                        config_management_audit_event(
                            "lock-released", seq, key=key, detail=f"session={session_id}"
                        )
                    )
            record = SessionRecord(
                session_id=session_id,
                seq=seq,
                live=False,
                digest=_pin(CONFIG_MANAGEMENT_SCHEMA, "session", session_id, seq, False),
            )
            self._sessions[session_id] = record
            self._audit.append(
                config_management_audit_event(
                    "session-destroyed", seq, detail=f"session={session_id}"
                )
            )
            return record

    def lock(self, key: str, session_id: str, seq: int) -> LockRecord:
        """Acquire a lock; held by at most one live session."""
        with self._lock:
            try:
                key = _check_key(key)
            except BadKeyError:
                self._reject(seq, "bad-key", key=str(key))
                raise
            sess = self._sessions.get(session_id)
            if sess is None or not sess.live:
                self._reject(seq, "unknown-session", key=key)
                raise UnknownSessionError(f"unknown session: {session_id!r}")
            current = self._locks.get(key)
            if current is not None and current.held:
                if current.session_id == session_id:
                    self._reject(seq, "lock-reentrant", key=key)
                    raise LockHeldError(f"session already holds lock on {key!r}")
                self._reject(seq, "lock-held", key=key)
                raise LockHeldError(f"lock held by {current.session_id!r}")
            self._check_seq(seq)
            record = LockRecord(
                key=key,
                session_id=session_id,
                seq=seq,
                held=True,
                digest=_pin(
                    CONFIG_MANAGEMENT_SCHEMA, "lock", key, session_id, seq, True
                ),
            )
            self._locks[key] = record
            self._audit.append(
                config_management_audit_event(
                    "lock-acquired", seq, key=key, detail=f"session={session_id}"
                )
            )
            return record

    def unlock(self, key: str, session_id: str, seq: int) -> LockRecord:
        with self._lock:
            try:
                key = _check_key(key)
            except BadKeyError:
                self._reject(seq, "bad-key", key=str(key))
                raise
            current = self._locks.get(key)
            if current is None or not current.held or current.session_id != session_id:
                self._reject(seq, "lock-not-held", key=key)
                raise LockNotHeldError(f"lock not held by {session_id!r}")
            self._check_seq(seq)
            record = LockRecord(
                key=key,
                session_id=session_id,
                seq=seq,
                held=False,
                digest=_pin(
                    CONFIG_MANAGEMENT_SCHEMA, "lock", key, session_id, seq, False
                ),
            )
            self._locks[key] = record
            self._audit.append(
                config_management_audit_event(
                    "lock-released", seq, key=key, detail=f"session={session_id}"
                )
            )
            return record

    # -- transaction API -----------------------------------------------

    def _book_tx_locked(
        self, ops: Tuple[Tuple[str, str], ...], seq: int
    ) -> TransactionRecord:
        self._tx_counter += 1
        tx_id = f"tx-{self._tx_counter}"
        record = TransactionRecord(
            tx_id=tx_id,
            ops=ops,
            seq=seq,
            digest=_pin(
                CONFIG_MANAGEMENT_SCHEMA, "transaction", tx_id, list(ops), seq
            ),
        )
        self._audit.append(
            config_management_audit_event(
                "transaction-applied", seq, detail=f"tx={tx_id} ops={len(ops)}"
            )
        )
        return record

    def transaction(
        self, ops: Sequence[Tuple[str, str, Any]], seq: int
    ) -> TransactionRecord:
        """Apply ``set``/``delete`` ops atomically; validate all first.

        Each op is ``("set", key, value)`` or ``("delete", key)``.
        Any malformed op aborts the whole transaction fail-closed.
        """
        with self._lock:
            norm_ops = tuple(ops)
            if not norm_ops:
                self._reject(seq, "empty-transaction")
                raise BadOpError("transaction must carry at least one op")
            if len(norm_ops) > MAX_TX_OPS:
                self._reject(seq, "transaction-too-large")
                raise BadOpError(f"transaction exceeds {MAX_TX_OPS} ops")
            plan: List[Tuple[str, str, Any]] = []
            for op in norm_ops:
                if not isinstance(op, (tuple, list)) or len(op) not in (2, 3):
                    self._reject(seq, "bad-op-shape")
                    raise BadOpError(f"malformed op: {op!r}")
                kind = op[0]
                if kind == "set":
                    if len(op) != 3:
                        self._reject(seq, "bad-op-shape")
                        raise BadOpError(f"malformed set op: {op!r}")
                    key = _check_key(op[1])
                    _check_value(op[2])
                    plan.append(("set", key, op[2]))
                elif kind == "delete":
                    key = _check_key(op[1])
                    if key not in self._entries:
                        self._reject(seq, "unknown-key", key=key)
                        raise UnknownKeyError(f"unknown key: {key!r}")
                    plan.append(("delete", key, None))
                else:
                    self._reject(seq, "bad-op-kind")
                    raise BadOpError(f"unknown op kind: {kind!r}")
            self._check_seq(seq)
            for kind, key, value in plan:
                if kind == "set":
                    self._set_locked(key, value, seq)
                else:
                    self._delete_locked(key, seq)
            return self._book_tx_locked(
                tuple((kind, key) for kind, key, _ in plan), seq
            )

    # -- views ----------------------------------------------------------

    def entry(self, key: str, seq: int) -> EntryRecord:
        """Pure read view of one entry; validates seq shape, consumes nothing."""
        return self.get(key, seq)

    def lease(self, lease_id: str) -> LeaseRecord:
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                raise UnknownLeaseError(f"unknown lease: {lease_id!r}")
            return lease

    def watcher(self, watcher_id: str) -> WatcherRecord:
        with self._lock:
            watcher = self._watchers.get(watcher_id)
            if watcher is None:
                raise UnknownWatcherError(f"unknown watcher: {watcher_id!r}")
            return watcher

    def key_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._entries))

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "keys": len(self._entries),
                "tombstones": len(self._tombstones),
                "leases": len(self._leases),
                "watchers": len(self._watchers),
                "sessions": len(self._sessions),
                "locks_held": sum(1 for l in self._locks.values() if l.held),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def _stdlib_only(path: str) -> bool:
    """AST check: module imports must be stdlib-only (plus canonical_json)."""
    import sys

    with open(path) as fh:
        tree = ast.parse(fh.read())
    allowed = {
        "ast", "hashlib", "re", "threading", "dataclasses", "typing",
        "json", "__future__", "canonical_json", "sys",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    cm = ConfigManagement()
    e1 = cm.set("app/db/host", "db1.internal", 1)
    assert e1.verify() and e1.version == 1
    assert cm.get("app/db/host", 1).value == "db1.internal"
    w = cm.watch("app", 2)
    e2 = cm.set("app/db/port", "5432", 3)
    page = cm.poll(w.watcher_id, 4)
    assert len(page.events) == 1 and page.events[0].key == "app/db/port"
    assert page.verify()
    cm.cas("app/db/port", e2.version, "5433", 5)
    lease = cm.grant("l-1", 10, 6)
    cm.attach("app/db/host", "l-1", 7)
    cm.lock("app/deploy", cm.session("s-1", 8).session_id, 9)
    cm.unlock("app/deploy", "s-1", 10)
    tx = cm.transaction([("set", "app/x", "1"), ("delete", "app/db/port")], 11)
    assert tx.verify()
    tombs = cm.revoke("l-1", 12)
    assert any(t.key == "app/db/host" for t in tombs)
    assert config_management_audit_event("entry-set", 1).get("schema") == AUDIT_SCHEMA
    print("config-management OK: set, get, watch, cas, lease, lock, tx, revoke")


if __name__ == "__main__":
    main()
