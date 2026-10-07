"""Schema registry — Confluent-shaped schema registry bookkeeping.

Research note (schema evolution literature): Confluent's Schema
Registry assigns every subject a monotonically increasing *version*;
the registry pins each version by schema id and enforces
*compatibility* (backward / forward / full / none) so consumers and
producers can evolve independently. Avro's resolution rules treat
``required``-style constraints as the compatibility frontier; this
module takes the same intersection for JSON-shaped schemas on a
single-host deterministic ledger:

* **Registered subjects**: ``register`` mints version 1 for a new
  subject. Schema types are pinned (``avro`` / ``protobuf`` /
  ``json-schema``); the schema body is canonicalized JSON text and
  pinned by ``sha256:`` digest. Duplicate subjects are refused
  fail-closed — new versions go through ``evolve``.
* **Evolution**: ``evolve`` mints version N+1 after checking the
  candidate against the latest version under the caller's
  compatibility mode. Incompatible evolves are refused fail-closed
  (and consume their seq). An evolve whose body is byte-identical to
  the latest version is idempotent: the existing record is returned,
  no seq consumed.
* **Compatibility check**: ``check`` is a pure read view (seq shape
  validated, nothing consumed, no audit row) that reports whether a
  candidate schema is compatible with the subject's latest version,
  with machine-checkable ``issues`` as data.
* **Deletion**: ``delete_subject`` is terminal — the subject leaves
  the serving set and the id is never recycled.

Compatibility semantics (documented simplification of Confluent's
rules, over ``properties`` / ``required`` field sets):

* ``backward``: the candidate can read data written by the latest
  version — every field the candidate *requires* must exist in the
  latest version's field set.
* ``forward``: the latest version can read data written by the
  candidate — every field the latest version *requires* must exist in
  the candidate's field set.
* ``full``: both directions hold.
* ``none``: no check; any candidate is compatible.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (failed mutations consume their seq), RLock guarding,
fail-closed taxonomy, stdlib-only, sha256 digest pins over canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *registry decisions*
deterministically. It cannot prove a producer or consumer actually
implements the registered schema, observe the wire, or validate
semantics beyond the declared field/required sets — a consumer wires
the frozen ``SchemaRecord`` digests to its own serializer. GIGO on
schema bodies: the ledger pins what the host declares.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Mapping

#: Version pin for this module's record shape.
SCHEMA_REGISTRY_VERSION = "schema-registry.v1"

#: Schema pin carried by records and audit events.
SCHEMA_REGISTRY_SCHEMA = "northstar.schema-registry.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Schema types (pinned vocabulary, Confluent-shaped).
TYPE_AVRO = "avro"
TYPE_PROTOBUF = "protobuf"
TYPE_JSON_SCHEMA = "json-schema"
SCHEMA_TYPES = (TYPE_AVRO, TYPE_PROTOBUF, TYPE_JSON_SCHEMA)

#: Compatibility modes (pinned vocabulary, Confluent-shaped).
COMPAT_NONE = "none"
COMPAT_BACKWARD = "backward"
COMPAT_FORWARD = "forward"
COMPAT_FULL = "full"
COMPATIBILITY_MODES = (COMPAT_NONE, COMPAT_BACKWARD, COMPAT_FORWARD, COMPAT_FULL)

#: Audit event kinds.
KIND_SCHEMA_REGISTERED = "schema.registered"
KIND_SCHEMA_EVOLVED = "schema.evolved"
KIND_SUBJECT_DELETED = "schema.subject-deleted"
KIND_REJECTED = "schema.rejected"
_KINDS = (
    KIND_SCHEMA_REGISTERED,
    KIND_SCHEMA_EVOLVED,
    KIND_SUBJECT_DELETED,
    KIND_REJECTED,
)

_DIGEST_PREFIX = "sha256:"
_MAX_SUBJECT_LEN = 256
_MAX_SCHEMA_BYTES = 1 << 20  # 1 MiB cap on schema bodies.


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SchemaRegistryError(ValueError):
    """Base error for the schema registry."""


class BadSubjectError(SchemaRegistryError):
    """Subject id is malformed."""


class DuplicateSubjectError(SchemaRegistryError):
    """This subject is already registered."""


class UnknownSubjectError(SchemaRegistryError):
    """No subject with this id is registered."""


class DeletedSubjectError(SchemaRegistryError):
    """This subject was deleted; its id is retired."""


class BadSchemaError(SchemaRegistryError):
    """Schema type or body is malformed."""


class BadCompatibilityError(SchemaRegistryError):
    """Compatibility mode is not in the pinned vocabulary."""


class IncompatibleSchemaError(SchemaRegistryError):
    """Candidate schema fails the requested compatibility check."""


class TypeMismatchError(SchemaRegistryError):
    """Evolve candidate schema type differs from the registered type."""


class SeqOrderError(SchemaRegistryError):
    """Mutation seq is not strictly increasing."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SchemaRegistryError(
            f"{field_name} must be a non-negative int, saw {value!r}"
        )
    return value


def _check_subject(value: Any, field_name: str = "subject") -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadSubjectError(f"{field_name} must be a non-empty string")
    cleaned = value.strip()
    if len(cleaned) > _MAX_SUBJECT_LEN:
        raise BadSubjectError(
            f"{field_name} must be <= {_MAX_SUBJECT_LEN} chars"
        )
    if any(ord(c) < 0x20 or c.isspace() for c in cleaned):
        raise BadSubjectError(
            f"{field_name} must not contain whitespace or control chars"
        )
    return cleaned


def _check_schema_type(value: Any) -> str:
    if value not in SCHEMA_TYPES:
        raise BadSchemaError(
            f"schema_type must be one of {SCHEMA_TYPES}, saw {value!r}"
        )
    return value


def _check_compatibility(value: Any) -> str:
    if value not in COMPATIBILITY_MODES:
        raise BadCompatibilityError(
            f"compatibility must be one of {COMPATIBILITY_MODES}, saw {value!r}"
        )
    return value


def _reject_floats(obj: Any, path: str = "$") -> None:
    # Floats cross a canonicalization precision boundary; schemas are
    # pinned by exact bytes, so floats are refused outright.
    if isinstance(obj, float):
        raise BadSchemaError(f"schema must not contain floats (at {path})")
    if isinstance(obj, Mapping):
        for key, val in obj.items():
            if not isinstance(key, str):
                raise BadSchemaError(
                    f"schema mapping keys must be strings (at {path})"
                )
            _reject_floats(val, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for idx, val in enumerate(obj):
            _reject_floats(val, f"{path}[{idx}]")


def _canonical(obj: Any) -> bytes:
    # Payloads are str/int/bool/None/dict/list only — no floats, so no
    # >2^53 precision hazard; ints serialize exactly.
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    """sha256 hex pin over the canonical encoding of the parts."""
    return hashlib.sha256(_canonical(list(parts))).hexdigest()


def _parse_schema_body(body: Any) -> tuple[str, Mapping[str, Any]]:
    """Canonicalize a schema body; return (canonical_text, parsed)."""
    if isinstance(body, str):
        if len(body.encode("utf-8")) > _MAX_SCHEMA_BYTES:
            raise BadSchemaError("schema body exceeds 1 MiB")
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError) as exc:
            raise BadSchemaError(f"schema body is not valid JSON: {exc}")
    elif isinstance(body, Mapping):
        parsed = dict(body)
    else:
        raise BadSchemaError(
            "schema body must be a JSON string or a mapping"
        )
    if not isinstance(parsed, Mapping):
        raise BadSchemaError("schema body must decode to a JSON object")
    _reject_floats(parsed)
    canonical_text = _canonical(parsed).decode("utf-8")
    return canonical_text, parsed


def _field_set(parsed: Mapping[str, Any]) -> frozenset:
    """Top-level field names of the schema (``properties`` object)."""
    props = parsed.get("properties", {})
    if not isinstance(props, Mapping):
        raise BadSchemaError("'properties' must be an object when present")
    for key in props:
        if not isinstance(key, str) or not key:
            raise BadSchemaError("property names must be non-empty strings")
    return frozenset(props.keys())


def _required_set(parsed: Mapping[str, Any]) -> frozenset:
    """Fields the schema requires."""
    required = parsed.get("required", [])
    if not isinstance(required, (list, tuple)):
        raise BadSchemaError("'required' must be an array when present")
    for item in required:
        if not isinstance(item, str):
            raise BadSchemaError("'required' entries must be strings")
    return frozenset(required)


def _compatibility_issues(
    mode: str, old: Mapping[str, Any], new: Mapping[str, Any]
) -> tuple[str, ...]:
    """Field-level compatibility violations; empty means compatible."""
    old_fields = _field_set(old)
    new_fields = _field_set(new)
    old_required = _required_set(old)
    new_required = _required_set(new)
    issues: list[str] = []
    if mode in (COMPAT_BACKWARD, COMPAT_FULL):
        missing = sorted(new_required - old_fields)
        for field in missing:
            issues.append(
                f"backward: new schema requires {field!r} "
                "missing from the latest version"
            )
    if mode in (COMPAT_FORWARD, COMPAT_FULL):
        missing = sorted(old_required - new_fields)
        for field in missing:
            issues.append(
                f"forward: latest version requires {field!r} "
                "missing from the candidate schema"
            )
    return tuple(issues)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SchemaRecord:
    """One registered version of a subject's schema.

    ``schema_text`` is the canonical JSON body; ``schema_digest``
    pins it (``sha256:`` + hex). Versions are strictly increasing per
    subject, starting at 1.
    """

    subject: str
    version: int
    schema_type: str
    schema_text: str
    schema_digest: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_subject(self.subject)
        if (
            isinstance(self.version, bool)
            or not isinstance(self.version, int)
            or self.version < 1
        ):
            raise BadSchemaError(
                f"version must be an int >= 1, saw {self.version!r}"
            )
        _check_schema_type(self.schema_type)
        if not isinstance(self.schema_text, str) or not self.schema_text:
            raise BadSchemaError("schema_text must be a non-empty string")
        if (
            not isinstance(self.schema_digest, str)
            or not self.schema_digest.startswith(_DIGEST_PREFIX)
            or len(self.schema_digest) != len(_DIGEST_PREFIX) + 64
        ):
            raise BadSchemaError(
                "schema_digest must be 'sha256:' + 64 hex chars"
            )
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            SCHEMA_REGISTRY_VERSION,
            "schema-record",
            self.subject,
            self.version,
            self.schema_type,
            self.schema_text,
            self.seq,
        )

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == self._compute_digest()

    def parsed(self) -> Mapping[str, Any]:
        """The schema body as a parsed mapping."""
        return json.loads(self.schema_text)


@dataclass(frozen=True)
class CompatibilityReport:
    """Compatibility verdict for a candidate schema, as data.

    ``compatible`` is True when ``issues`` is empty; incompatibility
    is a verdict, never an exception.
    """

    subject: str
    schema_digest: str
    compatibility: str
    compatible: bool
    checked_against_version: int
    issues: tuple

    def __post_init__(self) -> None:
        _check_subject(self.subject)
        if not isinstance(self.schema_digest, str) or not self.schema_digest:
            raise BadSchemaError("schema_digest must be a non-empty string")
        _check_compatibility(self.compatibility)
        if not isinstance(self.compatible, bool):
            raise BadSchemaError("compatible must be a bool")
        if (
            isinstance(self.checked_against_version, bool)
            or not isinstance(self.checked_against_version, int)
            or self.checked_against_version < 1
        ):
            raise BadSchemaError(
                "checked_against_version must be an int >= 1"
            )
        object.__setattr__(self, "issues", tuple(self.issues))


@dataclass(frozen=True)
class SubjectDeletion:
    """Terminal tombstone for a deleted subject (id never recycled)."""

    subject: str
    reason: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_subject(self.subject)
        if not isinstance(self.reason, str):
            raise BadSchemaError("reason must be a string")
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            SCHEMA_REGISTRY_VERSION,
            "subject-deletion",
            self.subject,
            self.reason,
            self.seq,
        )

    def verify(self) -> bool:
        return self.digest == self._compute_digest()


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def schema_registry_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the schema registry.

    Detail carries ids, versions, and digest pins — never raw schema
    text (schema text stays in the registry records).
    """
    if kind not in _KINDS:
        raise SchemaRegistryError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "schema_registry",
        "module_version": SCHEMA_REGISTRY_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# SchemaRegistry
# ---------------------------------------------------------------------------


class SchemaRegistry:
    """Deterministic Confluent-shaped schema registry bookkeeping.

    ``register`` mints version 1 for a new subject; ``evolve`` mints
    version N+1 after a compatibility check against the latest
    version. ``check`` is a pure read view reporting compatibility as
    data. ``delete_subject`` retires a subject terminally.

    Mutation seqs must be strictly increasing; failed mutations
    consume their seq (batch-21 ledger discipline). No wall-clock,
    stdlib-only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._subjects: dict[str, list[SchemaRecord]] = {}
        self._deletions: dict[str, SubjectDeletion] = {}
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

    def _peek_seq(self, seq: int) -> None:
        # Pure views validate the seq shape but never consume it.
        _check_seq(seq, "seq")

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(schema_registry_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, **detail)

    def _guard_subject(self, subject: str) -> str:
        subject = _check_subject(subject)
        if subject in self._deletions:
            raise DeletedSubjectError(
                f"subject was deleted and its id is retired: {subject!r}"
            )
        return subject

    # -- mutations --------------------------------------------------------

    def register(
        self,
        subject: str,
        schema_type: str,
        schema_body: Any,
        seq: int,
    ) -> SchemaRecord:
        """Register a new subject; mints version 1."""
        with self._lock:
            self._claim_seq(seq)
            subject = self._guard_subject(subject)
            schema_type = _check_schema_type(schema_type)
            if subject in self._subjects:
                self._reject(seq, subject=subject)
                raise DuplicateSubjectError(
                    f"subject already registered: {subject!r}; "
                    "use evolve for new versions"
                )
            schema_text, _parsed = _parse_schema_body(schema_body)
            record = SchemaRecord(
                subject=subject,
                version=1,
                schema_type=schema_type,
                schema_text=schema_text,
                schema_digest=_DIGEST_PREFIX
                + hashlib.sha256(schema_text.encode("utf-8")).hexdigest(),
                seq=seq,
            )
            self._subjects[subject] = [record]
            self._emit(
                KIND_SCHEMA_REGISTERED,
                seq,
                subject=subject,
                version=1,
                schema_type=schema_type,
                schema_digest=record.schema_digest,
                digest=record.digest,
            )
            return record

    def evolve(
        self,
        subject: str,
        schema_body: Any,
        seq: int,
        compatibility: str = COMPAT_BACKWARD,
    ) -> SchemaRecord:
        """Register a new version after a compatibility check.

        The candidate must keep the subject's schema type and be
        compatible with the latest version under ``compatibility``.
        A byte-identical candidate is idempotent: the latest record
        is returned with no seq consumed.
        """
        with self._lock:
            subject = self._guard_subject(subject)
            compatibility = _check_compatibility(compatibility)
            if subject not in self._subjects:
                # Pure view failed: validate seq shape, consume nothing.
                self._peek_seq(seq)
                raise UnknownSubjectError(
                    f"unknown subject: {subject!r}"
                )
            schema_text, parsed = _parse_schema_body(schema_body)
            latest = self._subjects[subject][-1]
            if schema_text == latest.schema_text:
                # Idempotent evolve: no new version, no seq consumed.
                self._peek_seq(seq)
                return latest
            self._claim_seq(seq)
            issues = _compatibility_issues(
                compatibility, latest.parsed(), parsed
            )
            if issues:
                self._reject(
                    seq,
                    subject=subject,
                    compatibility=compatibility,
                    issues=list(issues),
                )
                raise IncompatibleSchemaError(
                    f"candidate schema incompatible with "
                    f"{subject!r} v{latest.version} "
                    f"({compatibility}): {issues[0]}"
                )
            record = SchemaRecord(
                subject=subject,
                version=latest.version + 1,
                schema_type=latest.schema_type,
                schema_text=schema_text,
                schema_digest=_DIGEST_PREFIX
                + hashlib.sha256(schema_text.encode("utf-8")).hexdigest(),
                seq=seq,
            )
            self._subjects[subject].append(record)
            self._emit(
                KIND_SCHEMA_EVOLVED,
                seq,
                subject=subject,
                version=record.version,
                compatibility=compatibility,
                schema_digest=record.schema_digest,
                digest=record.digest,
            )
            return record

    def delete_subject(
        self, subject: str, seq: int, reason: str = ""
    ) -> SubjectDeletion:
        """Terminally delete a subject; its id is never recycled."""
        with self._lock:
            self._claim_seq(seq)
            subject = _check_subject(subject)
            if subject in self._deletions:
                self._reject(seq, subject=subject)
                raise DeletedSubjectError(
                    f"subject already deleted: {subject!r}"
                )
            if subject not in self._subjects:
                self._reject(seq, subject=subject)
                raise UnknownSubjectError(
                    f"unknown subject: {subject!r}"
                )
            tombstone = SubjectDeletion(
                subject=subject, reason=reason, seq=seq
            )
            del self._subjects[subject]
            self._deletions[subject] = tombstone
            self._emit(
                KIND_SUBJECT_DELETED,
                seq,
                subject=subject,
                reason=reason,
                digest=tombstone.digest,
            )
            return tombstone

    # -- views ------------------------------------------------------------

    def check(
        self,
        subject: str,
        schema_body: Any,
        seq: int,
        compatibility: str = COMPAT_BACKWARD,
    ) -> CompatibilityReport:
        """Pure compatibility view: verdict as data, seq not consumed."""
        with self._lock:
            self._peek_seq(seq)
            subject = self._guard_subject(subject)
            compatibility = _check_compatibility(compatibility)
            if subject not in self._subjects:
                raise UnknownSubjectError(
                    f"unknown subject: {subject!r}"
                )
            schema_text, parsed = _parse_schema_body(schema_body)
            latest = self._subjects[subject][-1]
            issues = _compatibility_issues(
                compatibility, latest.parsed(), parsed
            )
            return CompatibilityReport(
                subject=subject,
                schema_digest=_DIGEST_PREFIX
                + hashlib.sha256(schema_text.encode("utf-8")).hexdigest(),
                compatibility=compatibility,
                compatible=not issues,
                checked_against_version=latest.version,
                issues=issues,
            )

    def latest(self, subject: str) -> SchemaRecord:
        """Newest registered version of a subject."""
        with self._lock:
            subject = self._guard_subject(subject)
            if subject not in self._subjects:
                raise UnknownSubjectError(
                    f"unknown subject: {subject!r}"
                )
            return self._subjects[subject][-1]

    def version(self, subject: str, version: int) -> SchemaRecord:
        """Addressable read of any registered version."""
        with self._lock:
            subject = self._guard_subject(subject)
            if subject not in self._subjects:
                raise UnknownSubjectError(
                    f"unknown subject: {subject!r}"
                )
            if (
                isinstance(version, bool)
                or not isinstance(version, int)
                or version < 1
            ):
                raise BadSchemaError("version must be an int >= 1")
            for record in self._subjects[subject]:
                if record.version == version:
                    return record
            raise BadSchemaError(
                f"no version {version} for subject {subject!r}"
            )

    def versions(self, subject: str) -> tuple:
        """All versions of a subject, oldest first."""
        with self._lock:
            subject = self._guard_subject(subject)
            if subject not in self._subjects:
                raise UnknownSubjectError(
                    f"unknown subject: {subject!r}"
                )
            return tuple(self._subjects[subject])

    def subjects(self) -> tuple:
        """Ids of all live subjects, sorted."""
        with self._lock:
            return tuple(sorted(self._subjects))

    def deletion(self, subject: str) -> SubjectDeletion:
        """Tombstone for a deleted subject."""
        with self._lock:
            subject = _check_subject(subject)
            if subject not in self._deletions:
                raise UnknownSubjectError(
                    f"no deletion record for subject: {subject!r}"
                )
            return self._deletions[subject]

    def audit_log(self) -> tuple:
        """Audit events in ledger order."""
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    reg = SchemaRegistry()
    v1 = reg.register(
        "orders",
        "json-schema",
        {"properties": {"id": {"type": "string"}}, "required": ["id"]},
        seq=1,
    )
    assert v1.version == 1 and v1.verify()
    v2 = reg.evolve(
        "orders",
        {"properties": {"id": {"type": "string"}, "note": {}}, "required": ["id"]},
        seq=2,
    )
    assert v2.version == 2 and v2.verify()
    report = reg.check(
        "orders",
        {"properties": {"id": {"type": "string"}}, "required": ["id", "total"]},
        seq=3,
    )
    assert not report.compatible and report.issues
    print("schema-registry OK: register, evolve, check, pins")


if __name__ == "__main__":
    main()
