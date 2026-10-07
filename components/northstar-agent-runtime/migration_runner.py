"""Migration runner interface (Alembic/Flyway shaped, simulated).

Research motivation: a schema is a contract over time, and a migration
is how that contract is renegotiated safely. Alembic/Flyway discipline
is the reference: every migration is versioned and ordered, ``up()``
applies all pending migrations in version order, ``down()`` rolls them
back in reverse order, and ``status()`` tells the fleet exactly which
versions are applied and which are still pending -- before any deploy
decision is made.

This module is the *bookkeeping* half of that shape -- the ledger that
books migration registrations, apply/revert decisions, and the
resulting ledger state. It cannot execute SQL, touch a database, or
prove a migration actually ran on any host (the host owns those rails);
it books the up / down / status decisions:

- ``MigrationRunner`` -- owns the migration ledger.
  ``register(version, name, seq, ...)`` records a migration script
  (version-pinned, digest-pinned); ``up(seq, target=None)`` books the
  application of all pending migrations at-or-below ``target`` in
  version order; ``down(seq, target=None)`` books the reversal of all
  applied migrations strictly above ``target`` in reverse version
  order; ``status(seq)`` reports applied / pending / current version.
- ``migration_runner_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``migration-registered`` / ``migrated-up`` /
  ``migrated-down`` / ``rejected``); ids and digest pins only -- SQL
  text (up/down statements) never crosses the audit boundary.

Fail-closed edges (fail loudly, never guess):

- Versions must be non-empty str and unique: a duplicate
  ``register()`` raises ``DuplicateMigrationError`` (versions are
  never recycled).
- ``up()`` with no pending migrations is a no-op report with
  ``applied == 0`` (idempotent -- not an error).
- ``down()`` refuses any migration that has no recorded down script
  with ``MissingDownError`` -- a ledger must never book a reversal it
  cannot describe.
- ``down()`` with no applied migrations returns an empty report (not
  an error); an unknown ``target`` raises ``UnknownTargetError``.
- Versions sort by the pinned collation (padded numeric segments, then
  lexicographic tail): ``"1.2" < "1.10"``.
- Mutating calls consume strictly increasing caller-supplied int seqs
  (no wall-clock); rewinds raise ``SeqOrderError``. A failed mutation
  consumes its seq (fail-closed ledger position). ``status()`` is a
  pure view: it validates the seq but does not consume it.

Honest scope:

- This module is simulated bookkeeping, not a database driver: it
  books *decisions* about migrations, never executes the statements.
  The SQL the host supplied is digested and pinned, never inspected.
- The digest pins what the *caller* supplied -- a lying host gets a
  lying ledger (GIGO boundary).
- In-memory only: pair with the durable audit writer if the migration
  ledger must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
MIGRATION_RUNNER_VERSION = "migration-runner.v1"

#: Schema pin carried by records and audit events.
MIGRATION_RUNNER_SCHEMA = "northstar.migration-runner.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_REGISTERED = "migration-registered"
KIND_MIGRATED_UP = "migrated-up"
KIND_MIGRATED_DOWN = "migrated-down"
KIND_REJECTED = "rejected"
_KINDS = (KIND_REGISTERED, KIND_MIGRATED_UP, KIND_MIGRATED_DOWN, KIND_REJECTED)

#: Fields that must never cross the audit boundary (host SQL content).
_BANNED_AUDIT_FIELDS = ("up_sql", "down_sql", "up", "down", "sql")


class MigrationRunnerError(Exception):
    """Base error for the migration runner."""


class DuplicateMigrationError(MigrationRunnerError):
    """register() was called for a version that is already recorded."""


class UnknownMigrationError(MigrationRunnerError):
    """An operation named a migration id this runner never registered."""


class UnknownTargetError(MigrationRunnerError):
    """up()/down() named a target version that is not registered."""


class MissingDownError(MigrationRunnerError):
    """down() was asked to revert a migration with no recorded down script."""


class BadMigrationError(MigrationRunnerError):
    """Migration fields (version, name, sql) are malformed."""


class SeqOrderError(MigrationRunnerError):
    """A caller seq is not a strictly increasing int (no wall-clock)."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise MigrationRunnerError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadMigrationError(f"{what} must be a non-empty str")
    return value


def _version_key(version: str) -> Tuple[Tuple[int, str], ...]:
    """Pinned version collation: padded numeric segments, then lexicographic."""
    segments = version.split(".")
    key: List[Tuple[int, str]] = []
    for seg in segments:
        m = re.match(r"^(\d+)(.*)$", seg)
        if m:
            key.append((int(m.group(1)), m.group(2)))
        else:
            key.append((-1, seg))
    return tuple(key)


def _pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


@dataclass(frozen=True)
class MigrationRecord:
    """A registered migration script (frozen, digest-pinned)."""
    id: str
    version: str
    name: str
    up_digest: Optional[str]
    down_digest: Optional[str]
    record_digest: str
    seq: int
    schema: str = MIGRATION_RUNNER_SCHEMA

    def verify(self) -> bool:
        """Re-derive the record digest; False on any tamper."""
        expect = _pin("migration", self.id, self.version, self.name,
                      self.up_digest, self.down_digest)
        return self.record_digest == expect


@dataclass(frozen=True)
class ApplyReport:
    """Result of up(): the migrations applied, in version order (frozen)."""
    id: str
    applied_ids: Tuple[str, ...]
    target: Optional[str]
    report_digest: str
    seq: int
    schema: str = MIGRATION_RUNNER_SCHEMA

    def verify(self) -> bool:
        """Re-derive the report digest; False on any tamper."""
        expect = _pin("up", self.id, list(self.applied_ids), self.target)
        return self.report_digest == expect


@dataclass(frozen=True)
class RevertReport:
    """Result of down(): the migrations reverted, in reverse version order."""
    id: str
    reverted_ids: Tuple[str, ...]
    target: Optional[str]
    report_digest: str
    seq: int
    schema: str = MIGRATION_RUNNER_SCHEMA

    def verify(self) -> bool:
        """Re-derive the report digest; False on any tamper."""
        expect = _pin("down", self.id, list(self.reverted_ids), self.target)
        return self.report_digest == expect


@dataclass(frozen=True)
class StatusReport:
    """Ledger status: current version, applied ids, pending ids (frozen)."""
    current_version: Optional[str]
    applied_ids: Tuple[str, ...]
    pending_ids: Tuple[str, ...]
    report_digest: str
    seq: int
    schema: str = MIGRATION_RUNNER_SCHEMA

    def verify(self) -> bool:
        """Re-derive the report digest; False on any tamper."""
        expect = _pin("status", self.current_version,
                      list(self.applied_ids), list(self.pending_ids))
        return self.report_digest == expect


def migration_runner_audit_event(kind: str, seq: int,
                                 target_id: Optional[str] = None,
                                 digest: Optional[str] = None,
                                 detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for migration-runner activity.

    Only ids and digest pins cross the boundary; SQL text is refused.
    """
    _check_seq(seq)
    if kind not in _KINDS:
        raise MigrationRunnerError(f"unknown audit kind: {kind!r}")
    clean: Dict[str, Any] = {}
    for k, v in (detail or {}).items():
        if k in _BANNED_AUDIT_FIELDS:
            raise MigrationRunnerError(f"field {k!r} banned from audit boundary")
        clean[k] = v
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "module": MIGRATION_RUNNER_VERSION,
        "module_schema": MIGRATION_RUNNER_SCHEMA,
        "kind": kind,
        "seq": seq,
    }
    if target_id is not None:
        event["target_id"] = target_id
    if digest is not None:
        event["digest"] = digest
    if clean:
        event["detail"] = clean
    return event


class MigrationRunner:
    """Deterministic migration ledger: register / up / down / status.

    House style: frozen dataclass records, caller-supplied strictly
    increasing int seqs, no wall-clock, RLock-guarded, fail-closed,
    stdlib-only. SQL statements are digest-pinned, never executed.
    """

    def __init__(self, seed: Optional[str] = None) -> None:
        self._lock = threading.RLock()
        self._seed = seed or "migration-runner"
        self._seq = -1
        self._next_mig = 0
        self._next_apply = 0
        self._next_revert = 0
        self._migrations: Dict[str, MigrationRecord] = {}
        self._by_version: Dict[str, str] = {}
        self._applied: List[str] = []
        self._audit_log: List[Dict[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _bump(self, seq: int) -> None:
        _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq must strictly increase (got {seq})")
        self._seq = seq

    def _audit(self, kind: str, seq: int, target_id: Optional[str] = None,
               digest: Optional[str] = None,
               detail: Optional[Dict[str, Any]] = None) -> None:
        self._audit_log.append(migration_runner_audit_event(
            kind, seq, target_id=target_id, digest=digest, detail=detail))

    def _reject(self, seq: int, reason: str) -> None:
        # Failed mutations consume their seq; idempotent if the caller
        # already consumed it on the current path.
        if isinstance(seq, int) and not isinstance(seq, bool) and seq > self._seq:
            self._bump(seq)
        else:
            _check_seq(seq)
        self._audit(KIND_REJECTED, seq, detail={"reason": reason})

    def _sorted_records(self) -> List[MigrationRecord]:
        return sorted(self._migrations.values(),
                      key=lambda r: _version_key(r.version))

    # -- public --------------------------------------------------------

    def register(self, version: str, name: str, seq: int,
                 up_sql: Optional[str] = None,
                 down_sql: Optional[str] = None) -> MigrationRecord:
        """Record a migration script (version-pinned, digest-pinned)."""
        with self._lock:
            if not isinstance(version, str) or not version:
                self._reject(seq, "bad-version")
                raise BadMigrationError("version must be a non-empty str")
            if not isinstance(name, str) or not name:
                self._reject(seq, "bad-name")
                raise BadMigrationError("name must be a non-empty str")
            if up_sql is not None and not isinstance(up_sql, str):
                self._reject(seq, "bad-up-sql")
                raise BadMigrationError("up_sql must be str or None")
            if down_sql is not None and not isinstance(down_sql, str):
                self._reject(seq, "bad-down-sql")
                raise BadMigrationError("down_sql must be str or None")
            if version in self._by_version:
                self._reject(seq, "duplicate-version")
                raise DuplicateMigrationError(
                    f"version already registered: {version!r}")
            self._bump(seq)
            self._next_mig += 1
            mig_id = f"mig-{self._next_mig}"
            up_digest = _pin("sql", up_sql) if up_sql is not None else None
            down_digest = _pin("sql", down_sql) if down_sql is not None else None
            record = MigrationRecord(
                id=mig_id, version=version, name=name,
                up_digest=up_digest, down_digest=down_digest,
                record_digest=_pin("migration", mig_id, version, name,
                                   up_digest, down_digest),
                seq=seq,
            )
            self._migrations[mig_id] = record
            self._by_version[version] = mig_id
            self._audit(KIND_REGISTERED, seq, target_id=mig_id,
                        digest=record.record_digest,
                        detail={"version": version})
            return record

    def up(self, seq: int, target: Optional[str] = None) -> ApplyReport:
        """Apply all pending migrations in version order (<= target).

        Idempotent: with nothing pending, returns an empty report (no
        error).
        """
        with self._lock:
            if target is not None:
                if not isinstance(target, str) or not target:
                    self._reject(seq, "bad-target")
                    raise BadMigrationError("target must be a non-empty str")
                if target not in self._by_version:
                    self._reject(seq, "unknown-target")
                    raise UnknownTargetError(
                        f"target version not registered: {target!r}")
            self._bump(seq)
            ordered = self._sorted_records()
            target_key = _version_key(target) if target is not None else None
            to_apply = [r for r in ordered
                        if r.id not in self._applied
                        and (target_key is None
                             or _version_key(r.version) <= target_key)]
            for r in to_apply:
                self._applied.append(r.id)
            self._next_apply += 1
            report = ApplyReport(
                id=f"apply-{self._next_apply}",
                applied_ids=tuple(r.id for r in to_apply),
                target=target,
                report_digest="",
                seq=seq,
            )
            report = ApplyReport(
                id=report.id, applied_ids=report.applied_ids, target=target,
                report_digest=_pin("up", report.id, list(report.applied_ids),
                                   target),
                seq=seq,
            )
            self._audit(KIND_MIGRATED_UP, seq, target_id=report.id,
                        digest=report.report_digest,
                        detail={"applied": len(to_apply)})
            return report

    def down(self, seq: int, target: Optional[str] = None) -> RevertReport:
        """Revert applied migrations in reverse version order.

        Reverts every applied migration strictly *above* ``target``
        (``target=None`` reverts all). Refuses fail-closed when any
        reverted migration lacks a recorded down script.
        """
        with self._lock:
            if target is not None:
                if not isinstance(target, str) or not target:
                    self._reject(seq, "bad-target")
                    raise BadMigrationError("target must be a non-empty str")
                if target not in self._by_version:
                    self._reject(seq, "unknown-target")
                    raise UnknownTargetError(
                        f"target version not registered: {target!r}")
            self._bump(seq)
            target_key = _version_key(target) if target is not None else None
            applied_recs = [self._migrations[mid] for mid in self._applied]
            to_revert = [r for r in sorted(applied_recs,
                                           key=lambda r: _version_key(r.version),
                                           reverse=True)
                         if target_key is None
                         or _version_key(r.version) > target_key]
            missing = [r.id for r in to_revert if r.down_digest is None]
            if missing:
                self._reject(seq, "missing-down")
                raise MissingDownError(
                    f"cannot revert without down script: {missing}")
            for r in to_revert:
                self._applied.remove(r.id)
            self._next_revert += 1
            rid = f"revert-{self._next_revert}"
            report = RevertReport(
                id=rid,
                reverted_ids=tuple(r.id for r in to_revert),
                target=target,
                report_digest=_pin("down", rid,
                                   [r.id for r in to_revert], target),
                seq=seq,
            )
            self._audit(KIND_MIGRATED_DOWN, seq, target_id=report.id,
                        digest=report.report_digest,
                        detail={"reverted": len(to_revert)})
            return report

    def status(self, seq: int) -> StatusReport:
        """Pure view: current version, applied ids, pending ids (in order).

        Validates the seq but does not consume it; writes no audit.
        """
        with self._lock:
            _check_seq(seq, "seq")
            ordered = self._sorted_records()
            applied = tuple(mid for r in ordered
                            for mid in (r.id,) if mid in self._applied)
            pending = tuple(r.id for r in ordered if r.id not in self._applied)
            current = self._migrations[self._applied[-1]].version \
                if self._applied else None
            return StatusReport(
                current_version=current,
                applied_ids=applied,
                pending_ids=pending,
                report_digest=_pin("status", current, list(applied),
                                   list(pending)),
                seq=seq,
            )

    # -- views ----------------------------------------------------------

    def migration(self, migration_id: str) -> MigrationRecord:
        """Fetch one registered migration; raises on unknown id."""
        with self._lock:
            try:
                return self._migrations[migration_id]
            except KeyError:
                raise UnknownMigrationError(
                    f"unknown migration: {migration_id!r}")

    def migration_ids(self) -> Tuple[str, ...]:
        """All migration ids, in version order."""
        with self._lock:
            return tuple(r.id for r in self._sorted_records())

    def applied_ids(self) -> Tuple[str, ...]:
        """Applied migration ids, in version order."""
        with self._lock:
            return tuple(r.id for r in self._sorted_records()
                         if r.id in self._applied)

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """Append-only audit trail (shallow copies)."""
        with self._lock:
            return tuple(dict(e) for e in self._audit_log)


def main() -> None:
    """Self-check: register, up, status, down, pins."""
    runner = MigrationRunner(seed="selfcheck")
    m1 = runner.register("1", "init", 1,
                         up_sql="CREATE TABLE t(a);", down_sql="DROP TABLE t;")
    m2 = runner.register("2", "add-index", 2,
                         up_sql="CREATE INDEX i ON t(a);",
                         down_sql="DROP INDEX i;")
    assert m1.verify() and m2.verify()
    r_up = runner.up(3)
    assert r_up.applied_ids == (m1.id, m2.id), r_up
    assert r_up.verify()
    st = runner.status(4)
    assert st.verify() and st.current_version == "2"
    assert st.applied_ids == (m1.id, m2.id) and st.pending_ids == ()
    r_down = runner.down(5, target="1")
    assert r_down.reverted_ids == (m2.id,), r_down
    assert r_down.verify()
    st2 = runner.status(6)
    assert st2.current_version == "1" and st2.pending_ids == (m2.id,)
    ev = migration_runner_audit_event(KIND_MIGRATED_UP, 7, target_id="x",
                                      digest="sha256:0")
    assert ev["kind"] == KIND_MIGRATED_UP
    print("migration-runner OK: register, up, status, down, pins, audit")


if __name__ == "__main__":
    main()
