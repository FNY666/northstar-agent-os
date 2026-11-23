"""Secrets rotation — Vault-shaped secret rotation bookkeeping (thirty-third batch).

Research note (rotation literature): HashiCorp Vault's KV v2 engine
treats every secret write as a *version*; the current version is what
readers get and older versions stay addressable for a configurable
number of revisions. NIST SP 800-57 bounds a secret's cryptoperiod
and prescribes rotation before the bound; AWS Secrets Manager models
rotation as a staged lifecycle (AWSCURRENT / AWSPREVIOUS). This module
takes the intersection for a single-host deterministic ledger:

* **Versioned secrets**: ``register`` mints version 1; ``rotate``
  mints version N+1 and retires version N. Every version is a frozen
  record with a digest pin and a ``prev_digest`` chain. Secret material
  is derived deterministically from the manager seed and never enters
  a record or the audit trail.
* **Version-addressable reads**: ``version`` returns the frozen record
  for any version index — retired versions stay readable, which is
  what makes incident response possible.
* **Rollback**: unlike plain rotation, Vault operators sometimes need
  to go *backwards* when new credentials turn out broken. ``rollback``
  re-activates a retired version and retires the current one, minting
  a frozen ``RollbackRecord`` that documents the from/to pair. No new
  material is minted on rollback — it is a pointer move, not a
  rotation.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (failed mutations consume their seq), RLock guarding,
fail-closed taxonomy, stdlib-only, sha256 digest pins over canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *rotation decisions*
deterministically. It cannot observe the wire, revoke secrets held by
others, or prove a retired secret stopped being used — a consumer wires
the frozen ``SecretVersion`` records to its own secret store. Derived
material is a deterministic placeholder, not a production KDF; pair
with an HSM/KMS and real secret handling for production. GIGO on
secret ids: the ledger pins what the host declares.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Mapping

#: Version pin for this module's record shape.
SECRETS_ROTATION_VERSION = "secrets-rotation.v1"

#: Schema pin carried by records and audit events.
SECRETS_ROTATION_SCHEMA = "northstar.secrets-rotation.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Rotation reasons (pinned vocabulary). ``initial`` is reserved for
#: ``register``; every other rotation must declare its cause.
REASON_INITIAL = "initial"
REASON_SCHEDULED = "scheduled"
REASON_MANUAL = "manual"
REASON_COMPROMISED = "compromised"
REASON_EXPIRED = "expired"
ROTATION_REASONS = (
    REASON_INITIAL,
    REASON_SCHEDULED,
    REASON_MANUAL,
    REASON_COMPROMISED,
    REASON_EXPIRED,
)

#: Version statuses (pinned vocabulary). ``active`` marks the single
#: currently-served version; every other version is ``retired``.
STATUS_ACTIVE = "active"
STATUS_RETIRED = "retired"
VERSION_STATUSES = (STATUS_ACTIVE, STATUS_RETIRED)

#: Audit event kinds.
KIND_SECRET_REGISTERED = "rotation.secret-registered"
KIND_ROTATED = "rotation.secret-rotated"
KIND_ROLLED_BACK = "rotation.rolled-back"
KIND_REJECTED = "rotation.rejected"
_KINDS = (
    KIND_SECRET_REGISTERED,
    KIND_ROTATED,
    KIND_ROLLED_BACK,
    KIND_REJECTED,
)

_GENESIS = "genesis"
_DIGEST_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SecretsRotationError(ValueError):
    """Base error for the secrets rotation manager."""


class BadSecretError(SecretsRotationError):
    """Malformed secret id or version payload."""


class DuplicateSecretError(SecretsRotationError):
    """This secret id is already registered."""


class UnknownSecretError(SecretsRotationError):
    """No secret with this id is registered."""


class UnknownVersionError(SecretsRotationError):
    """No such version index exists for this secret."""


class BadRollbackError(SecretsRotationError):
    """Rollback target is the active version or otherwise invalid."""


class BadReasonError(SecretsRotationError):
    """Rotation reason is not in the pinned vocabulary."""


class SeqOrderError(SecretsRotationError):
    """Mutation seq is not strictly increasing."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SecretsRotationError(
            f"{field_name} must be a non-negative int, saw {value!r}"
        )
    return value


def _check_secret_id(value: Any, field_name: str = "secret_id") -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadSecretError(f"{field_name} must be a non-empty string")
    return value.strip()


def _check_reason(value: Any) -> str:
    if value not in ROTATION_REASONS:
        raise BadReasonError(
            f"reason must be one of {ROTATION_REASONS}, saw {value!r}"
        )
    return value


def _check_material_digest(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(_DIGEST_PREFIX)
        or len(value) != len(_DIGEST_PREFIX) + 64
        or not all(c in "0123456789abcdef" for c in value[len(_DIGEST_PREFIX):])
    ):
        raise BadSecretError(
            "material_digest must be 'sha256:' + 64 hex chars"
        )
    return value


# ---------------------------------------------------------------------------
# Canonical digest helpers
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    # Payloads are str/int/bool/None/dict/list only — no floats, so no
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
class SecretVersion:
    """One version of a rotated secret.

    ``material_digest`` pins the derived secret material (``sha256:`` +
    hex); the material itself never enters the record. ``status`` is
    ``active`` for the currently-served version and ``retired`` for
    older ones; the chain is linked by ``prev_digest``.
    """

    secret_id: str
    version_index: int
    material_digest: str
    status: str
    reason: str
    prev_digest: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_secret_id(self.secret_id)
        if (
            isinstance(self.version_index, bool)
            or not isinstance(self.version_index, int)
            or self.version_index < 1
        ):
            raise BadSecretError(
                f"version_index must be an int >= 1, saw {self.version_index!r}"
            )
        _check_material_digest(self.material_digest)
        if self.status not in VERSION_STATUSES:
            raise BadSecretError(
                f"status must be one of {VERSION_STATUSES}, saw {self.status!r}"
            )
        if self.reason not in ROTATION_REASONS:
            raise BadReasonError(
                f"reason must be one of {ROTATION_REASONS}, saw {self.reason!r}"
            )
        if not isinstance(self.prev_digest, str) or not self.prev_digest:
            raise BadSecretError("prev_digest must be a non-empty string")
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            SECRETS_ROTATION_VERSION,
            "secret-version",
            self.secret_id,
            self.version_index,
            self.material_digest,
            self.status,
            self.reason,
            self.prev_digest,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class RollbackRecord:
    """One rollback: version ``from_version`` retired, ``to_version``
    re-activated.

    A rollback is a pointer move over existing versions — it mints no
    new material and no new version index. The record pins the pair so
    the event is replayable and auditable.
    """

    secret_id: str
    from_version: int
    to_version: int
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_secret_id(self.secret_id)
        for name, value in (("from_version", self.from_version),
                            ("to_version", self.to_version)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise BadRollbackError(
                    f"{name} must be an int >= 1, saw {value!r}"
                )
        if self.from_version == self.to_version:
            raise BadRollbackError(
                "from_version and to_version must differ"
            )
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            SECRETS_ROTATION_VERSION,
            "rollback",
            self.secret_id,
            self.from_version,
            self.to_version,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


def secrets_rotation_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for secrets rotation.

    Detail carries ids + digest pins only — secret *material* never
    crosses the audit boundary.
    """
    if kind not in _KINDS:
        raise SecretsRotationError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "secrets_rotation",
        "module_version": SECRETS_ROTATION_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# SecretsRotation
# ---------------------------------------------------------------------------


class SecretsRotation:
    """Deterministic Vault-shaped secrets rotation bookkeeping.

    Secrets are versioned: ``register`` mints version 1, ``rotate``
    mints version N+1 and retires version N. ``version`` reads any
    version index — retired versions stay addressable, which is what
    makes rollback possible. ``rollback`` re-activates a retired
    version (pointer move, no new material) and mints a frozen
    ``RollbackRecord``. Secret material is derived deterministically
    from the manager seed via a sha256 chain and is never written into
    records or audit events.

    Mutation seqs must be strictly increasing; failed mutations consume
    their seq (batch-21 ledger discipline). No wall-clock, stdlib-only.
    """

    def __init__(self, seed: int = 0) -> None:
        _check_seq(seed, "seed")
        self._master = hashlib.sha256(
            f"{SECRETS_ROTATION_VERSION}:{seed}".encode("utf-8")
        ).digest()
        self._lock = threading.RLock()
        self._last_seq = 0
        self._versions: dict[str, list[SecretVersion]] = {}
        self._materials: dict[tuple[str, int], bytes] = {}
        self._rollbacks: list[RollbackRecord] = []
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

    def _derive_material(self, secret_id: str, version_index: int) -> bytes:
        return hashlib.sha256(
            self._master + _canonical([secret_id, version_index])
        ).digest()

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(secrets_rotation_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, **detail)

    # -- mutations --------------------------------------------------------

    def register(self, secret_id: str, seq: int) -> SecretVersion:
        """Register a secret; mints version 1 (``active``)."""
        with self._lock:
            self._claim_seq(seq)
            secret_id = _check_secret_id(secret_id)
            if secret_id in self._versions:
                self._reject(seq, secret_id=secret_id)
                raise DuplicateSecretError(
                    f"secret already registered: {secret_id!r}"
                )
            material = self._derive_material(secret_id, 1)
            record = SecretVersion(
                secret_id=secret_id,
                version_index=1,
                material_digest=_DIGEST_PREFIX + material.hex(),
                status=STATUS_ACTIVE,
                reason=REASON_INITIAL,
                prev_digest=_GENESIS,
                seq=seq,
            )
            self._versions[secret_id] = [record]
            self._materials[(secret_id, 1)] = material
            self._emit(
                KIND_SECRET_REGISTERED,
                seq,
                secret_id=secret_id,
                version_index=1,
                digest=record.digest,
            )
            return record

    def rotate(
        self, secret_id: str, seq: int, reason: str = REASON_SCHEDULED
    ) -> SecretVersion:
        """Mint version N+1 and retire version N.

        The previous active version's digest becomes the new record's
        ``prev_digest``; reasons follow the pinned vocabulary (never
        ``initial`` after registration).
        """
        with self._lock:
            self._claim_seq(seq)
            secret_id = _check_secret_id(secret_id)
            reason = _check_reason(reason)
            if reason == REASON_INITIAL:
                self._reject(seq, secret_id=secret_id, reason=reason)
                raise BadReasonError(
                    "'initial' is reserved for register"
                )
            chain = self._versions.get(secret_id)
            if chain is None:
                self._reject(seq, secret_id=secret_id)
                raise UnknownSecretError(f"unknown secret: {secret_id!r}")
            prev = chain[-1]
            new_index = prev.version_index + 1
            material = self._derive_material(secret_id, new_index)
            retired_prev = SecretVersion(
                secret_id=prev.secret_id,
                version_index=prev.version_index,
                material_digest=prev.material_digest,
                status=STATUS_RETIRED,
                reason=prev.reason,
                prev_digest=prev.prev_digest,
                seq=prev.seq,
            )
            chain[-1] = retired_prev
            record = SecretVersion(
                secret_id=secret_id,
                version_index=new_index,
                material_digest=_DIGEST_PREFIX + material.hex(),
                status=STATUS_ACTIVE,
                reason=reason,
                prev_digest=prev.digest,
                seq=seq,
            )
            chain.append(record)
            self._materials[(secret_id, new_index)] = material
            self._emit(
                KIND_ROTATED,
                seq,
                secret_id=secret_id,
                version_index=new_index,
                reason=reason,
                prev_digest=prev.digest,
                digest=record.digest,
            )
            return record

    def rollback(
        self, secret_id: str, seq: int, to_version: int
    ) -> RollbackRecord:
        """Re-activate a retired version (pointer move, no new material).

        The current active version becomes ``retired`` and
        ``to_version`` becomes ``active`` again. A frozen
        ``RollbackRecord`` pins the from/to pair. Rolling back to the
        already-active version, to a nonexistent version, or to a
        version already retired elsewhere in history is refused
        fail-closed.
        """
        with self._lock:
            self._claim_seq(seq)
            secret_id = _check_secret_id(secret_id)
            if isinstance(to_version, bool) or not isinstance(to_version, int):
                self._reject(seq, secret_id=secret_id)
                raise BadRollbackError(
                    f"to_version must be an int, saw {to_version!r}"
                )
            chain = self._versions.get(secret_id)
            if chain is None:
                self._reject(seq, secret_id=secret_id)
                raise UnknownSecretError(f"unknown secret: {secret_id!r}")
            target = next(
                (v for v in chain if v.version_index == to_version), None
            )
            if target is None:
                self._reject(seq, secret_id=secret_id, to_version=to_version)
                raise UnknownVersionError(
                    f"unknown version {to_version} for {secret_id!r}"
                )
            current = chain[-1]
            if target.status == STATUS_ACTIVE:
                self._reject(
                    seq,
                    secret_id=secret_id,
                    to_version=to_version,
                    reason="already-active",
                )
                raise BadRollbackError(
                    f"version {to_version} is already active for {secret_id!r}"
                )
            retired_current = SecretVersion(
                secret_id=current.secret_id,
                version_index=current.version_index,
                material_digest=current.material_digest,
                status=STATUS_RETIRED,
                reason=current.reason,
                prev_digest=current.prev_digest,
                seq=current.seq,
            )
            reactivated = SecretVersion(
                secret_id=target.secret_id,
                version_index=target.version_index,
                material_digest=target.material_digest,
                status=STATUS_ACTIVE,
                reason=target.reason,
                prev_digest=target.prev_digest,
                seq=seq,
            )
            # Demote the current version in place, then move the
            # re-activated version to the end of the chain — the served
            # version is always the last element (see active_version).
            # Pins re-derive because status changed; the prev_digest
            # chain stays intact.
            chain[chain.index(current)] = retired_current
            chain.remove(target)
            chain.append(reactivated)
            record = RollbackRecord(
                secret_id=secret_id,
                from_version=current.version_index,
                to_version=target.version_index,
                seq=seq,
            )
            self._rollbacks.append(record)
            self._emit(
                KIND_ROLLED_BACK,
                seq,
                secret_id=secret_id,
                from_version=current.version_index,
                to_version=target.version_index,
                digest=record.digest,
            )
            return record

    # -- views --------------------------------------------------------------

    def version(self, secret_id: str, version_index: int) -> SecretVersion:
        """Return the frozen record for one version index (pure lookup).

        Retired versions stay addressable — that is what makes
        rollback possible. No seq is consumed.
        """
        with self._lock:
            _check_secret_id(secret_id)
            chain = self._versions.get(secret_id)
            if chain is None:
                raise UnknownSecretError(f"unknown secret: {secret_id!r}")
            for record in chain:
                if record.version_index == version_index:
                    return record
            raise UnknownVersionError(
                f"unknown version {version_index} for {secret_id!r}"
            )

    def versions(self, secret_id: str) -> tuple[SecretVersion, ...]:
        """All versions of a secret, newest last."""
        with self._lock:
            _check_secret_id(secret_id)
            chain = self._versions.get(secret_id)
            if chain is None:
                raise UnknownSecretError(f"unknown secret: {secret_id!r}")
            return tuple(chain)

    def active_version(self, secret_id: str) -> SecretVersion:
        """The currently-served version of a secret."""
        with self._lock:
            _check_secret_id(secret_id)
            chain = self._versions.get(secret_id)
            if chain is None:
                raise UnknownSecretError(f"unknown secret: {secret_id!r}")
            return chain[-1]

    def rollbacks(self) -> tuple[RollbackRecord, ...]:
        """All rollback records, oldest first."""
        with self._lock:
            return tuple(self._rollbacks)

    def secret_ids(self) -> tuple[str, ...]:
        """Registered secret ids, sorted."""
        with self._lock:
            return tuple(sorted(self._versions))

    def material_for(self, secret_id: str, version_index: int) -> bytes:
        """Derived material bytes for one version (host-only; never audited)."""
        with self._lock:
            _check_secret_id(secret_id)
            material = self._materials.get((secret_id, version_index))
            if material is None:
                raise UnknownVersionError(
                    f"unknown version {version_index} for {secret_id!r}"
                )
            return material

    def audit_log(self) -> tuple[Mapping[str, Any], ...]:
        """Booked audit events, oldest first (ids + pins only)."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: register, rotate, version view, rollback, pins."""
    mgr = SecretsRotation(seed=7)
    v1 = mgr.register("db-password", seq=1)
    assert v1.verify() and v1.version_index == 1 and v1.status == "active"
    assert v1.reason == "initial" and v1.prev_digest == _GENESIS
    v2 = mgr.rotate("db-password", seq=2, reason="scheduled")
    assert v2.verify() and v2.version_index == 2 and v2.status == "active"
    assert v2.prev_digest == v1.digest
    # Retired version stays addressable.
    old = mgr.version("db-password", 1)
    assert old.verify() and old.status == "retired"
    assert mgr.versions("db-password") == (old, v2)
    assert mgr.active_version("db-password").version_index == 2
    # Rollback re-activates version 1 without minting new material.
    rb = mgr.rollback("db-password", seq=3, to_version=1)
    assert rb.verify() and rb.from_version == 2 and rb.to_version == 1
    assert mgr.active_version("db-password").version_index == 1
    assert mgr.active_version("db-password").status == "active"
    assert mgr.version("db-password", 2).status == "retired"
    assert len(mgr.versions("db-password")) == 2
    # Determinism: the same seed reproduces the same material pins.
    other = SecretsRotation(seed=7)
    other.register("db-password", seq=1)
    assert other.versions("db-password")[0].material_digest == v1.material_digest
    assert other.material_for("db-password", 1) == mgr.material_for("db-password", 1)
    third = SecretsRotation(seed=8)
    third.register("db-password", seq=1)
    assert third.versions("db-password")[0].material_digest != v1.material_digest
    print("secrets-rotation OK: register, rotate, version, rollback, pins, audit")


if __name__ == "__main__":
    main()
