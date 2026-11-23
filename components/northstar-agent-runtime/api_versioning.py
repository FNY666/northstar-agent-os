"""API versioning — Stripe-shaped API version lifecycle bookkeeping.

Research note (API versioning literature): Stripe pins API behavior to
date-stamped versions (e.g. ``2024-11-20.acacia``) so a caller's pinned
version keeps the exact semantics it was written against, even as the
platform evolves. Breaking changes ship as new versions; old versions
are *deprecated* (announced, still served), then *sunset* (retired,
no longer served). This module takes that lifecycle for a
single-host deterministic ledger:

* **Version registration**: ``register`` mints a frozen
  ``VersionRecord`` pinned to a calendar-date id (``YYYY-MM-DD`` with
  an optional ``.codename`` suffix, e.g. ``2026-10-08.acacia``).
  Date ids order lexicographically the same way they order in time,
  which makes "newer" a pure string comparison. Duplicate ids are
  refused fail-closed.
* **Deprecation**: ``deprecate`` moves a version from ``current`` to
  ``deprecated`` and optionally declares a ``sunset_seq`` (the logical
  seq at which the version stops being served) and a ``successor``
  version. Deprecating an unknown or already-non-current version is
  refused.
* **Sunset**: ``sunset`` terminally retires a ``deprecated`` version;
  sunsetting a ``current`` version (no deprecation announced) is
  refused — the lifecycle must be announced before it ends.
* **Migration paths**: ``migrate`` books a frozen ``MigrationRecord``
  for a (from_version, to_version) pair. The record pins the pair so
  the migration graph is replayable; hosts wire their own transform
  functions to the declared pairs. Self-migrations and pairs touching
  sunset versions are refused.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (failed mutations consume their seq), RLock guarding,
fail-closed taxonomy, stdlib-only, sha256 digest pins over canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books version *lifecycle decisions*
deterministically. It cannot observe the wire, prove a client pinned a
version, or transform payloads between versions — a consumer wires the
frozen records to its own gateway. GIGO on version ids and sunset
seqs: the ledger pins what the host declares.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from typing import Any, Mapping

#: Version pin for this module's record shape.
API_VERSIONING_VERSION = "api-versioning.v1"

#: Schema pin carried by records and audit events.
API_VERSIONING_SCHEMA = "northstar.api-versioning.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Version ids are calendar dates, optionally with a lowercase
#: codename suffix (Stripe shape: ``2024-11-20.acacia``). Codenames
#: are pin vocabulary, not free text — only this set is admitted.
CODENAME_PINS = (
    "acacia",
    "banyan",
    "cedar",
    "dogwood",
    "elm",
    "fir",
)
_VERSION_ID_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>0[1-9]|1[0-2])-(?P<day>0[1-9]|[12]\d|3[01])"
    r"(?:\.(?P<codename>[a-z]+))?$"
)

#: Version lifecycle statuses (pinned vocabulary).
STATUS_CURRENT = "current"
STATUS_DEPRECATED = "deprecated"
STATUS_SUNSET = "sunset"
VERSION_STATUSES = (STATUS_CURRENT, STATUS_DEPRECATED, STATUS_SUNSET)

#: Audit event kinds.
KIND_VERSION_REGISTERED = "versioning.version-registered"
KIND_DEPRECATED = "versioning.version-deprecated"
KIND_SUNSET = "versioning.version-sunset"
KIND_MIGRATION_DECLARED = "versioning.migration-declared"
KIND_REJECTED = "versioning.rejected"
_KINDS = (
    KIND_VERSION_REGISTERED,
    KIND_DEPRECATED,
    KIND_SUNSET,
    KIND_MIGRATION_DECLARED,
    KIND_REJECTED,
)

_GENESIS = "genesis"
_DIGEST_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class APIVersioningError(ValueError):
    """Base error for the API versioning manager."""


class BadVersionError(APIVersioningError):
    """Malformed version id or version payload."""


class DuplicateVersionError(APIVersioningError):
    """This version id is already registered."""


class UnknownVersionError(APIVersioningError):
    """No version with this id is registered."""


class BadLifecycleError(APIVersioningError):
    """Lifecycle transition is invalid (wrong status or bad sunset)."""


class BadMigrationError(APIVersioningError):
    """Migration pair is invalid (self-migration, unknown, or sunset)."""


class DuplicateMigrationError(APIVersioningError):
    """This migration pair is already declared."""


class SeqOrderError(APIVersioningError):
    """Mutation seq is not strictly increasing."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise APIVersioningError(
            f"{field_name} must be a non-negative int, saw {value!r}"
        )
    return value


def _check_version_id(value: Any, field_name: str = "version_id") -> str:
    if not isinstance(value, str):
        raise BadVersionError(f"{field_name} must be a string")
    match = _VERSION_ID_RE.match(value)
    if not match:
        raise BadVersionError(
            f"{field_name} must look like YYYY-MM-DD or YYYY-MM-DD.codename, "
            f"saw {value!r}"
        )
    codename = match.group("codename")
    if codename is not None and codename not in CODENAME_PINS:
        raise BadVersionError(
            f"{field_name} codename must be one of {CODENAME_PINS}, "
            f"saw {codename!r}"
        )
    return value


def _check_note(value: Any, field_name: str = "note") -> str:
    if not isinstance(value, str):
        raise APIVersioningError(f"{field_name} must be a string")
    if len(value) > 512:
        raise APIVersioningError(f"{field_name} must be <= 512 chars")
    return value


# ---------------------------------------------------------------------------
# Canonical digest helpers
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    # Payloads are str/int/bool/None/tuple/list only — no floats, so no
    # >2^53 precision hazard; ints serialize exactly.
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    """sha256 hex pin over the canonical encoding of the parts."""
    return hashlib.sha256(_canonical(list(parts))).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VersionRecord:
    """One registered API version.

    ``version_id`` is a calendar-date id (optionally ``.codename``);
    ``status`` walks ``current`` → ``deprecated`` → ``sunset``.
    ``changes`` is a pinned tuple of declared change summaries (hosts
    declare them; the module never fetches changelogs).
    """

    version_id: str
    changes: tuple[str, ...]
    status: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_version_id(self.version_id)
        if (
            not isinstance(self.changes, tuple)
            or any(not isinstance(c, str) or len(c) > 256 for c in self.changes)
        ):
            raise BadVersionError(
                "changes must be a tuple of strings, each <= 256 chars"
            )
        if self.status not in VERSION_STATUSES:
            raise BadVersionError(
                f"status must be one of {VERSION_STATUSES}, saw {self.status!r}"
            )
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            API_VERSIONING_VERSION,
            "version",
            self.version_id,
            list(self.changes),
            self.status,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class DeprecationRecord:
    """One deprecation: a ``current`` version moves to ``deprecated``.

    ``sunset_seq`` is the logical seq at which the version will stop
    being served (None = undecided). ``successor`` is the version hosts
    should move callers to (empty = none declared).
    """

    version_id: str
    sunset_seq: Any
    successor: str
    note: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_version_id(self.version_id)
        if self.sunset_seq is not None:
            _check_seq(self.sunset_seq, "sunset_seq")
            if self.sunset_seq <= self.seq:
                raise BadLifecycleError(
                    "sunset_seq must be strictly after the deprecation seq"
                )
        if self.successor:
            _check_version_id(self.successor, "successor")
        _check_note(self.note)
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            API_VERSIONING_VERSION,
            "deprecation",
            self.version_id,
            self.sunset_seq,
            self.successor,
            self.note,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class SunsetRecord:
    """One terminal sunset: a ``deprecated`` version is retired.

    The version's status becomes ``sunset`` and the id is never
    recycled — replaying a sunset is refused.
    """

    version_id: str
    note: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_version_id(self.version_id)
        _check_note(self.note)
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            API_VERSIONING_VERSION,
            "sunset",
            self.version_id,
            self.note,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class MigrationRecord:
    """One declared migration path between two versions.

    The record pins the (from, to) pair and a host-declared transform
    digest (``sha256:`` + hex) that references the transform code the
    host runs — payloads are never transformed by this module. Pairs
    are ordered: migrating *forward* (to a newer date id) is
    ``direction="forward"``; anything else is ``"lateral"``.
    """

    from_version: str
    to_version: str
    transform_digest: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_version_id(self.from_version, "from_version")
        _check_version_id(self.to_version, "to_version")
        if self.from_version == self.to_version:
            raise BadMigrationError("from_version and to_version must differ")
        if (
            not isinstance(self.transform_digest, str)
            or not self.transform_digest.startswith(_DIGEST_PREFIX)
            or len(self.transform_digest) != len(_DIGEST_PREFIX) + 64
            or not all(
                c in "0123456789abcdef"
                for c in self.transform_digest[len(_DIGEST_PREFIX):]
            )
        ):
            raise BadMigrationError(
                "transform_digest must be 'sha256:' + 64 hex chars"
            )
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            API_VERSIONING_VERSION,
            "migration",
            self.from_version,
            self.to_version,
            self.transform_digest,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()

    @property
    def direction(self) -> str:
        """``forward`` when the target id is newer; else ``lateral``."""
        return "forward" if self.to_version > self.from_version else "lateral"


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def api_versioning_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for API versioning.

    Detail carries ids + digest pins only — change descriptions and
    transform payloads never cross the audit boundary.
    """
    if kind not in _KINDS:
        raise APIVersioningError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "api_versioning",
        "module_version": API_VERSIONING_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# APIVersioning
# ---------------------------------------------------------------------------


class APIVersioning:
    """Deterministic Stripe-shaped API version lifecycle bookkeeping.

    ``register`` mints a ``VersionRecord`` for a calendar-date id;
    ``deprecate`` moves ``current`` → ``deprecated`` with an optional
    sunset seq and successor; ``sunset`` terminally retires a
    ``deprecated`` version; ``migrate`` books a (from, to) migration
    pair pinned by a host-declared transform digest. Reads
    (``version``, ``migration``, status views) are pure views that
    validate but do not consume seq.

    Mutation seqs must be strictly increasing; failed mutations consume
    their seq (batch-21 ledger discipline). No wall-clock, stdlib-only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._versions: dict[str, VersionRecord] = {}
        self._deprecations: dict[str, DeprecationRecord] = {}
        self._sunsets: dict[str, SunsetRecord] = {}
        self._migrations: dict[tuple[str, str], MigrationRecord] = {}
        self._audit: list[Mapping[str, Any]] = []

    # -- internal ---------------------------------------------------------

    def _claim_seq(self, seq: int) -> None:
        # Called first in every mutation: a refused mutation still
        # consumes its seq, keeping the ledger totally ordered.
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing: {seq} <= {self._last_seq}"
            )
        self._last_seq = seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(api_versioning_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, **detail)

    def _replace_status(self, version_id: str, status: str) -> VersionRecord:
        # Rebuild a version record with a new status (seq carried over;
        # the status transition itself is booked by its own record).
        current = self._versions[version_id]
        return VersionRecord(
            version_id=current.version_id,
            changes=current.changes,
            status=status,
            seq=current.seq,
        )

    # -- mutations --------------------------------------------------------

    def register(
        self, version_id: str, seq: int, changes: tuple[str, ...] = ()
    ) -> VersionRecord:
        """Register a new API version; starts ``current``."""
        with self._lock:
            self._claim_seq(seq)
            version_id = _check_version_id(version_id)
            if version_id in self._versions:
                self._reject(seq, version_id=version_id)
                raise DuplicateVersionError(
                    f"version already registered: {version_id!r}"
                )
            if not isinstance(changes, tuple):
                self._reject(seq, version_id=version_id)
                raise BadVersionError("changes must be a tuple of strings")
            record = VersionRecord(
                version_id=version_id,
                changes=changes,
                status=STATUS_CURRENT,
                seq=seq,
            )
            self._versions[version_id] = record
            self._emit(
                KIND_VERSION_REGISTERED,
                seq,
                version_id=version_id,
                status=STATUS_CURRENT,
                digest=record.digest,
            )
            return record

    def deprecate(
        self,
        version_id: str,
        seq: int,
        sunset_seq: Any = None,
        successor: str = "",
        note: str = "",
    ) -> DeprecationRecord:
        """Move a ``current`` version to ``deprecated``.

        Optionally declares ``sunset_seq`` (logical seq at which the
        version stops being served) and a ``successor`` version id.
        """
        with self._lock:
            self._claim_seq(seq)
            version_id = _check_version_id(version_id)
            current = self._versions.get(version_id)
            if current is None:
                self._reject(seq, version_id=version_id)
                raise UnknownVersionError(
                    f"unknown version: {version_id!r}"
                )
            if current.status != STATUS_CURRENT:
                self._reject(
                    seq, version_id=version_id, status=current.status
                )
                raise BadLifecycleError(
                    f"only current versions can be deprecated; "
                    f"{version_id!r} is {current.status}"
                )
            if successor:
                successor = _check_version_id(successor, "successor")
                if successor not in self._versions:
                    self._reject(
                        seq, version_id=version_id, successor=successor
                    )
                    raise UnknownVersionError(
                        f"unknown successor version: {successor!r}"
                    )
            try:
                record = DeprecationRecord(
                    version_id=version_id,
                    sunset_seq=sunset_seq,
                    successor=successor,
                    note=_check_note(note),
                    seq=seq,
                )
            except (APIVersioningError, BadVersionError, BadLifecycleError):
                self._reject(seq, version_id=version_id)
                raise
            self._versions[version_id] = self._replace_status(
                version_id, STATUS_DEPRECATED
            )
            self._deprecations[version_id] = record
            self._emit(
                KIND_DEPRECATED,
                seq,
                version_id=version_id,
                successor=successor,
                sunset_seq=sunset_seq,
                digest=record.digest,
            )
            return record

    def sunset(self, version_id: str, seq: int, note: str = "") -> SunsetRecord:
        """Terminally retire a ``deprecated`` version.

        Sunsetting a ``current`` version is refused — the deprecation
        must be announced first.
        """
        with self._lock:
            self._claim_seq(seq)
            version_id = _check_version_id(version_id)
            current = self._versions.get(version_id)
            if current is None:
                self._reject(seq, version_id=version_id)
                raise UnknownVersionError(
                    f"unknown version: {version_id!r}"
                )
            if current.status == STATUS_SUNSET:
                self._reject(seq, version_id=version_id, reason="already-sunset")
                raise BadLifecycleError(
                    f"version already sunset: {version_id!r}"
                )
            if current.status != STATUS_DEPRECATED:
                self._reject(
                    seq, version_id=version_id, status=current.status
                )
                raise BadLifecycleError(
                    f"only deprecated versions can be sunset; "
                    f"{version_id!r} is {current.status}"
                )
            record = SunsetRecord(
                version_id=version_id,
                note=_check_note(note),
                seq=seq,
            )
            self._versions[version_id] = self._replace_status(
                version_id, STATUS_SUNSET
            )
            self._sunsets[version_id] = record
            self._emit(
                KIND_SUNSET,
                seq,
                version_id=version_id,
                digest=record.digest,
            )
            return record

    def migrate(
        self,
        from_version: str,
        to_version: str,
        seq: int,
        transform_digest: str,
    ) -> MigrationRecord:
        """Book a migration path between two registered versions.

        The record pins a host-declared ``transform_digest``
        (``sha256:`` + hex) referencing the transform the host runs;
        this module never transforms payloads. Pairs touching sunset
        versions and self-migrations are refused fail-closed.
        """
        with self._lock:
            self._claim_seq(seq)
            from_version = _check_version_id(from_version, "from_version")
            to_version = _check_version_id(to_version, "to_version")
            src = self._versions.get(from_version)
            if src is None:
                self._reject(seq, from_version=from_version)
                raise UnknownVersionError(
                    f"unknown from_version: {from_version!r}"
                )
            dst = self._versions.get(to_version)
            if dst is None:
                self._reject(seq, to_version=to_version)
                raise UnknownVersionError(
                    f"unknown to_version: {to_version!r}"
                )
            for vid, rec in ((from_version, src), (to_version, dst)):
                if rec.status == STATUS_SUNSET:
                    self._reject(
                        seq,
                        from_version=from_version,
                        to_version=to_version,
                        sunset_version=vid,
                    )
                    raise BadMigrationError(
                        f"migration cannot touch sunset version {vid!r}"
                    )
            if (from_version, to_version) in self._migrations:
                self._reject(
                    seq, from_version=from_version, to_version=to_version
                )
                raise DuplicateMigrationError(
                    f"migration already declared: "
                    f"{from_version!r} -> {to_version!r}"
                )
            try:
                record = MigrationRecord(
                    from_version=from_version,
                    to_version=to_version,
                    transform_digest=transform_digest,
                    seq=seq,
                )
            except BadMigrationError:
                self._reject(
                    seq, from_version=from_version, to_version=to_version
                )
                raise
            self._migrations[(from_version, to_version)] = record
            self._emit(
                KIND_MIGRATION_DECLARED,
                seq,
                from_version=from_version,
                to_version=to_version,
                direction=record.direction,
                digest=record.digest,
            )
            return record

    # -- views --------------------------------------------------------------

    def version(self, version_id: str) -> VersionRecord:
        """Return the frozen record for one version id (pure lookup)."""
        with self._lock:
            _check_version_id(version_id)
            record = self._versions.get(version_id)
            if record is None:
                raise UnknownVersionError(
                    f"unknown version: {version_id!r}"
                )
            return record

    def migration(self, from_version: str, to_version: str) -> MigrationRecord:
        """Return the frozen migration record for one pair (pure lookup)."""
        with self._lock:
            _check_version_id(from_version, "from_version")
            _check_version_id(to_version, "to_version")
            record = self._migrations.get((from_version, to_version))
            if record is None:
                raise UnknownVersionError(
                    f"no migration declared: "
                    f"{from_version!r} -> {to_version!r}"
                )
            return record

    def version_ids(self) -> tuple[str, ...]:
        """Registered version ids, oldest first (date ids sort)."""
        with self._lock:
            return tuple(sorted(self._versions))

    def status_of(self, version_id: str) -> str:
        """Lifecycle status of one version (pure view)."""
        return self.version(version_id).status

    def current_ids(self) -> tuple[str, ...]:
        """Versions still ``current`` (served, not deprecated)."""
        with self._lock:
            return tuple(
                sorted(
                    vid
                    for vid, rec in self._versions.items()
                    if rec.status == STATUS_CURRENT
                )
            )

    def deprecated_ids(self) -> tuple[str, ...]:
        """Versions ``deprecated`` but not yet ``sunset``."""
        with self._lock:
            return tuple(
                sorted(
                    vid
                    for vid, rec in self._versions.items()
                    if rec.status == STATUS_DEPRECATED
                )
            )

    def sunset_ids(self) -> tuple[str, ...]:
        """Versions terminally ``sunset``."""
        with self._lock:
            return tuple(
                sorted(
                    vid
                    for vid, rec in self._versions.items()
                    if rec.status == STATUS_SUNSET
                )
            )

    def migration_pairs(self) -> tuple[tuple[str, str], ...]:
        """Declared migration pairs, sorted."""
        with self._lock:
            return tuple(sorted(self._migrations))

    def latest(self) -> VersionRecord:
        """The newest registered version id (date ids sort; pure view)."""
        with self._lock:
            if not self._versions:
                raise UnknownVersionError("no versions registered")
            return self._versions[max(self._versions)]

    def audit_log(self) -> tuple[Mapping[str, Any], ...]:
        """Booked audit events, oldest first (ids + pins only)."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: register, deprecate, migrate, sunset, pins, audit."""
    mgr = APIVersioning()
    v1 = mgr.register("2025-06-01", seq=1, changes=("initial",))
    assert v1.verify() and v1.status == "current"
    v2 = mgr.register("2026-10-08.acacia", seq=2, changes=("new fields",))
    assert v2.verify() and mgr.latest().version_id == "2026-10-08.acacia"
    dep = mgr.deprecate(
        "2025-06-01", seq=3, sunset_seq=100, successor="2026-10-08.acacia"
    )
    assert dep.verify() and mgr.status_of("2025-06-01") == "deprecated"
    mig = mgr.migrate(
        "2025-06-01",
        "2026-10-08.acacia",
        seq=4,
        transform_digest="sha256:" + "ab" * 32,
    )
    assert mig.verify() and mig.direction == "forward"
    assert mgr.migration("2025-06-01", "2026-10-08.acacia").verify()
    sun = mgr.sunset("2025-06-01", seq=5, note="retired")
    assert sun.verify() and mgr.status_of("2025-06-01") == "sunset"
    assert mgr.current_ids() == ("2026-10-08.acacia",)
    assert mgr.sunset_ids() == ("2025-06-01",)
    assert mgr.version_ids() == ("2025-06-01", "2026-10-08.acacia")
    # Cross-instance determinism of digest pins.
    other = APIVersioning()
    other.register("2025-06-01", seq=1, changes=("initial",))
    assert other.version("2025-06-01").digest == v1.digest
    # Audit carries ids + pins only.
    kinds = {e["kind"] for e in mgr.audit_log()}
    assert kinds == {
        "versioning.version-registered",
        "versioning.version-deprecated",
        "versioning.migration-declared",
        "versioning.version-sunset",
    }
    print("api-versioning OK: register, deprecate, migrate, sunset, pins, audit")


if __name__ == "__main__":
    main()
