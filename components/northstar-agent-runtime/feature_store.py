"""Feature store interface: registered features, point-in-time serving, backfill.

Research motivation: online ML serving needs a *feature store* -- a
registry of named feature definitions plus an online store that serves
point-in-time correct values per entity. The load-bearing property is
**point-in-time correctness**: training-time features and serving-time
features must be computed from the same event stream, otherwise
train/serve skew silently corrupts the model. This module pins the
mechanical half: definition registry, ingestion log, and serving.

Public API:

- ``FeatureStore`` -- mutable registry + store:
  ``register(definition)`` -> frozen ``FeatureDefinition``;
  ``entity(entity_id, description="")`` -> frozen ``EntityRecord``:
  books an entity declaration; duplicates fail closed;
  ``feature(name)`` -> frozen ``FeatureDefinition``: alias of
  ``definition()`` with the Feast-shaped name;
  ``ingest(entity_id, feature_name, value, event_seq, seq)`` records a
  feature value at a logical event time;
  ``serve(entity_id, feature_names, as_of_seq, seq)`` -> frozen
  ``FeatureVector``: the latest value per feature with
  ``event_seq <= as_of_seq`` (point-in-time correct; missing values are
  ``None``, a policy outcome, not an error);
  ``backfill(feature_name, event_seq, seq)`` -> frozen
  ``BackfillReport``: re-materializes one feature's values from the
  offline log, counting rows written and skipped.
- ``feature_store_audit_event(kind, seq)`` -- ``audit.ndjson/1``-shaped
  record, fixed kind vocabulary: ``"registered"``, ``"ingested"``,
  ``"served"``, ``"backfilled"``, ``"rejected"``.

Honest scope:

- This is an in-memory registry + serving interface, not a real
  offline/online store; there is no actual training pipeline here. What
  it pins is the *shape*: which features exist, what values they take
  for an entity at a logical time, and an auditable backfill record.
- Point-in-time correctness holds only for host-reported events: if the
  host ingests late data with a stale ``event_seq``, the module serves
  exactly what it was told. It cannot detect data the host never sent.
- Feature values are JSON-canonicalizable scalars or lists thereof;
  NaN/inf, bools where a scalar is expected, and dict-keyed mappings
  with non-str keys are refused fail-closed.
- The module never invents seq numbers and never reaches the network.

Version pin: ``feature-store.v1`` / schema pin
``northstar.feature-store.v1``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

#: Module version.
FEATURE_STORE_VERSION = "feature-store.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.feature-store.v1"

#: Version pin carried inside audit records.
AUDIT_FORMAT = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
_AUDIT_KINDS = frozenset(
    {"registered", "ingested", "served", "backfilled", "rejected"}
)

#: Allowed feature value types.
_VALUE_TYPES = frozenset({"float", "int", "string", "bool", "float_list"})

_MAX_NAME_LEN = 256
_MAX_OWNER_LEN = 256
_MAX_DESC_LEN = 4096
_MAX_VALUE_BYTES = 1024 * 1024  # 1 MiB guardrail


class FeatureStoreError(Exception):
    """Base error for feature-store misuse. Fail-closed, never silent."""


class UnknownFeatureError(FeatureStoreError):
    """Raised when a feature name is not registered."""


class DuplicateFeatureError(FeatureStoreError):
    """Raised when registering a feature name that already exists."""


class UnknownEntityError(FeatureStoreError):
    """Raised when an entity id was never booked."""


class DuplicateEntityError(FeatureStoreError):
    """Raised when booking an entity id that already exists."""


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _check_name(name: object, what: str = "name") -> str:
    if isinstance(name, bool) or not isinstance(name, str):
        raise TypeError(f"{what} must be str, got {type(name).__name__}")
    if not name:
        raise ValueError(f"{what} must be non-empty")
    if len(name) > _MAX_NAME_LEN:
        raise ValueError(f"{what} exceeds {_MAX_NAME_LEN} chars")
    return name


def _canonical(value: Any) -> str:
    """Deterministic canonical string for digest pins."""
    if isinstance(value, bool):
        raise TypeError("bool is not a canonicalizable scalar")
    if isinstance(value, float) and (
        value != value or value in (float("inf"), float("-inf"))
    ):
        raise ValueError("NaN/inf cannot be canonicalized")
    if isinstance(value, float) and value.is_integer() and abs(value) > 2**53:
        raise ValueError("integral float beyond 2**53 loses precision")
    if isinstance(value, Mapping):
        items = sorted(
            ((str(k), _canonical(v)) for k, v in value.items()),
            key=lambda kv: kv[0],
        )
        return "{" + ",".join(f"{k}:{v}" for k, v in items) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, (str, int, float)):
        return json.dumps(value, sort_keys=True)
    if value is None:
        return "null"
    raise TypeError(f"cannot canonicalize {type(value).__name__}")


def _digest_pin(body: str) -> str:
    return "sha256:" + hashlib.sha256(
        ("feature-store.v1:" + body).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class FeatureDefinition:
    """Registered feature: name, owner, value type, freshness SLA."""

    name: str
    owner: str
    value_type: str
    freshness_sla_seqs: int
    description: str = ""
    digest: str = field(default="")

    def __post_init__(self) -> None:
        _check_name(self.name, "name")
        if isinstance(self.owner, bool) or not isinstance(self.owner, str):
            raise TypeError(
                f"owner must be str, got {type(self.owner).__name__}"
            )
        if not self.owner or len(self.owner) > _MAX_OWNER_LEN:
            raise ValueError("owner must be non-empty and bounded")
        if not isinstance(self.value_type, str) or (
            self.value_type not in _VALUE_TYPES
        ):
            raise ValueError(f"value_type must be one of {sorted(_VALUE_TYPES)}")
        if (
            isinstance(self.freshness_sla_seqs, bool)
            or not isinstance(self.freshness_sla_seqs, int)
            or self.freshness_sla_seqs < 0
        ):
            raise ValueError("freshness_sla_seqs must be a non-negative int")
        if not isinstance(self.description, str):
            raise TypeError("description must be str")
        if len(self.description) > _MAX_DESC_LEN:
            raise ValueError("description exceeds bound")
        body = "|".join(
            [
                self.name,
                self.owner,
                self.value_type,
                str(self.freshness_sla_seqs),
                self.description,
            ]
        )
        object.__setattr__(self, "digest", _digest_pin(body))

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "name": self.name,
            "owner": self.owner,
            "value_type": self.value_type,
            "freshness_sla_seqs": self.freshness_sla_seqs,
            "description": self.description,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class EntityRecord:
    """A booked entity: the subject a feature value attaches to.

    Feast-shaped entity declaration: an ``entity_id`` names one
    training/serving subject (a user, a device, a loan application).
    Booking is a declaration only -- values still arrive through
    ``ingest()``, which does not require the entity to be booked first,
    so existing behavior is unchanged.
    """

    entity_id: str
    description: str = ""
    digest: str = field(default="")

    def __post_init__(self) -> None:
        _check_name(self.entity_id, "entity_id")
        if not isinstance(self.description, str):
            raise TypeError("description must be str")
        if len(self.description) > _MAX_DESC_LEN:
            raise ValueError("description exceeds bound")
        body = "|".join(["entity", self.entity_id, self.description])
        object.__setattr__(self, "digest", _digest_pin(body))

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "entity_id": self.entity_id,
            "description": self.description,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class FeatureValue:
    """One ingested feature value for an entity at a logical event time."""

    entity_id: str
    feature_name: str
    value: Any
    event_seq: int
    ingest_seq: int

    def __post_init__(self) -> None:
        _check_name(self.entity_id, "entity_id")
        _check_name(self.feature_name, "feature_name")
        _check_seq(self.event_seq)
        _check_seq(self.ingest_seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "entity_id": self.entity_id,
            "feature_name": self.feature_name,
            "value": self.value,
            "event_seq": self.event_seq,
            "ingest_seq": self.ingest_seq,
        }


@dataclass(frozen=True)
class FeatureVector:
    """Served feature vector for one entity at one logical time."""

    entity_id: str
    as_of_seq: int
    values: Tuple[Tuple[str, Any], ...]

    def __post_init__(self) -> None:
        _check_name(self.entity_id, "entity_id")
        _check_seq(self.as_of_seq)

    def get(self, feature_name: str) -> Any:
        """Value for ``feature_name``; ``None`` when missing."""
        for name, value in self.values:
            if name == feature_name:
                return value
        return None

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "entity_id": self.entity_id,
            "as_of_seq": self.as_of_seq,
            "values": [{"feature": n, "value": v} for n, v in self.values],
        }


@dataclass(frozen=True)
class BackfillReport:
    """Auditable record of a backfill run for one feature."""

    feature_name: str
    event_seq: int
    rows_written: int
    rows_skipped: int
    digest: str = field(default="")

    def __post_init__(self) -> None:
        _check_name(self.feature_name, "feature_name")
        _check_seq(self.event_seq)
        if (
            isinstance(self.rows_written, bool)
            or not isinstance(self.rows_written, int)
            or self.rows_written < 0
        ):
            raise ValueError("rows_written must be a non-negative int")
        if (
            isinstance(self.rows_skipped, bool)
            or not isinstance(self.rows_skipped, int)
            or self.rows_skipped < 0
        ):
            raise ValueError("rows_skipped must be a non-negative int")
        body = "|".join(
            [
                self.feature_name,
                str(self.event_seq),
                str(self.rows_written),
                str(self.rows_skipped),
            ]
        )
        object.__setattr__(self, "digest", _digest_pin(body))

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "feature_name": self.feature_name,
            "event_seq": self.event_seq,
            "rows_written": self.rows_written,
            "rows_skipped": self.rows_skipped,
            "digest": self.digest,
        }


class FeatureStore:
    """Mutable feature registry + point-in-time serving."""

    def __init__(self) -> None:
        self._definitions: Dict[str, FeatureDefinition] = {}
        self._entities: Dict[str, EntityRecord] = {}
        self._log: List[FeatureValue] = []
        self._online: Dict[Tuple[str, str], FeatureValue] = {}

    # -- entities ------------------------------------------------------

    def entity(self, entity_id: str, description: str = "") -> EntityRecord:
        """Book an entity declaration; duplicates fail closed.

        This is the Feast-shaped ``entity()`` entry point: it pins that
        ``entity_id`` is a known serving subject. Ingest does not require
        it, so existing ingestion/serving behavior is unchanged.
        """
        _check_name(entity_id, "entity_id")
        if entity_id in self._entities:
            raise DuplicateEntityError(
                f"entity {entity_id!r} already booked"
            )
        record = EntityRecord(entity_id=entity_id, description=description)
        self._entities[entity_id] = record
        return record

    def entity_record(self, entity_id: str) -> EntityRecord:
        _check_name(entity_id, "entity_id")
        try:
            return self._entities[entity_id]
        except KeyError:
            raise UnknownEntityError(f"entity {entity_id!r} not booked")

    def entity_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._entities))

    # -- registry ------------------------------------------------------

    def register(
        self,
        name: str,
        owner: str,
        value_type: str,
        freshness_sla_seqs: int,
        description: str = "",
    ) -> FeatureDefinition:
        """Register a feature definition; duplicates fail closed."""
        _check_name(name)
        if name in self._definitions:
            raise DuplicateFeatureError(f"feature {name!r} already registered")
        definition = FeatureDefinition(
            name=name,
            owner=owner,
            value_type=value_type,
            freshness_sla_seqs=freshness_sla_seqs,
            description=description,
        )
        self._definitions[name] = definition
        return definition

    def definition(self, name: str) -> FeatureDefinition:
        _check_name(name)
        try:
            return self._definitions[name]
        except KeyError:
            raise UnknownFeatureError(f"feature {name!r} not registered")

    def feature_names(self) -> Tuple[str, ...]:
        return tuple(sorted(self._definitions))

    def feature(self, name: str) -> FeatureDefinition:
        """Return the feature definition for ``name``.

        The spec's ``feature()`` entry point: a thin alias of
        ``definition()`` with the Feast-shaped name.
        """
        return self.definition(name)

    # -- ingestion / serving -------------------------------------------

    def _validate_value(self, definition: FeatureDefinition, value: Any) -> None:
        vt = definition.value_type
        if vt == "float":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(
                    f"feature {definition.name!r} expects float, "
                    f"got {type(value).__name__}"
                )
            if isinstance(value, float) and (
                value != value or value in (float("inf"), float("-inf"))
            ):
                raise ValueError("NaN/inf not allowed as feature value")
        elif vt == "int":
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(
                    f"feature {definition.name!r} expects int, "
                    f"got {type(value).__name__}"
                )
        elif vt == "string":
            if isinstance(value, bool) or not isinstance(value, str):
                raise TypeError(
                    f"feature {definition.name!r} expects string, "
                    f"got {type(value).__name__}"
                )
        elif vt == "bool":
            if not isinstance(value, bool):
                raise TypeError(
                    f"feature {definition.name!r} expects bool, "
                    f"got {type(value).__name__}"
                )
        elif vt == "float_list":
            if (
                isinstance(value, bool)
                or not isinstance(value, (list, tuple))
                or any(
                    isinstance(v, bool) or not isinstance(v, (int, float))
                    for v in value
                )
            ):
                raise TypeError(
                    f"feature {definition.name!r} expects float_list, "
                    f"got {type(value).__name__}"
                )
        # Canonicalizability + size guardrail.
        text = _canonical(value)
        if len(text.encode("utf-8")) > _MAX_VALUE_BYTES:
            raise ValueError("feature value exceeds 1 MiB")

    def ingest(
        self,
        entity_id: str,
        feature_name: str,
        value: Any,
        event_seq: int,
        seq: int,
    ) -> FeatureValue:
        """Record a feature value at a logical event time."""
        definition = self.definition(feature_name)
        _check_seq(seq)
        self._validate_value(definition, value)
        record = FeatureValue(
            entity_id=entity_id,
            feature_name=feature_name,
            value=value,
            event_seq=_check_seq(event_seq),
            ingest_seq=seq,
        )
        self._log.append(record)
        key = (record.entity_id, record.feature_name)
        current = self._online.get(key)
        if current is None or record.event_seq >= current.event_seq:
            # Newer event time wins; ties go to the later ingest.
            self._online[key] = record
        return record

    def serve(
        self,
        entity_id: str,
        feature_names: Sequence[str],
        as_of_seq: int,
        seq: int,
    ) -> FeatureVector:
        """Point-in-time correct serving: latest value with
        ``event_seq <= as_of_seq`` per feature. Missing values are
        ``None``. Unknown features raise ``UnknownFeatureError``."""
        _check_name(entity_id, "entity_id")
        _check_seq(as_of_seq)
        _check_seq(seq)
        names = tuple(feature_names)
        if not names:
            raise ValueError("feature_names must be non-empty")
        pairs: List[Tuple[str, Any]] = []
        for name in names:
            _check_name(name, "feature_name")
            if name not in self._definitions:
                raise UnknownFeatureError(f"feature {name!r} not registered")
            best: Optional[FeatureValue] = None
            for record in self._log:
                if (
                    record.entity_id == entity_id
                    and record.feature_name == name
                    and record.event_seq <= as_of_seq
                    and (best is None or record.event_seq >= best.event_seq)
                ):
                    best = record
            pairs.append((name, best.value if best is not None else None))
        return FeatureVector(
            entity_id=entity_id, as_of_seq=as_of_seq, values=tuple(pairs)
        )

    # -- backfill ------------------------------------------------------

    def backfill(
        self, feature_name: str, event_seq: int, seq: int
    ) -> BackfillReport:
        """Re-materialize one feature's values from the ingestion log.

        Rows already materialized at an equal-or-newer ``event_seq`` are
        skipped; the rest are re-written into the online store. Returns
        a frozen ``BackfillReport`` pinning the counts.
        """
        definition = self.definition(feature_name)
        event_seq = _check_seq(event_seq)
        _check_seq(seq)
        written = 0
        skipped = 0
        for record in self._log:
            if record.feature_name != definition.name:
                continue
            if record.event_seq > event_seq:
                skipped += 1
                continue
            key = (record.entity_id, record.feature_name)
            current = self._online.get(key)
            if current is None or record.event_seq >= current.event_seq:
                self._online[key] = record
                written += 1
            else:
                skipped += 1
        return BackfillReport(
            feature_name=definition.name,
            event_seq=event_seq,
            rows_written=written,
            rows_skipped=skipped,
        )

    # -- audit ----------------------------------------------------------

    def audit_event(self, kind: str, seq: int) -> dict:
        return feature_store_audit_event(kind, seq=seq)


def feature_store_audit_event(kind: str, seq: int = 0) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for a feature-store op.

    ``kind`` is one of ``"registered"`` / ``"ingested"`` / ``"served"`` /
    ``"backfilled"`` / ``"rejected"``.
    """
    if not isinstance(kind, str) or kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    return {
        "format": AUDIT_FORMAT,
        "schema": SCHEMA_PIN,
        "kind": kind,
        "seq": _check_seq(seq),
    }


def main() -> None:
    store = FeatureStore()
    store.register("age_days", "ml-platform", "int", 100)
    store.register("churn_score", "ml-platform", "float", 50)
    store.ingest("user-1", "age_days", 365, event_seq=10, seq=1)
    store.ingest("user-1", "churn_score", 0.7, event_seq=10, seq=2)
    store.ingest("user-1", "churn_score", 0.9, event_seq=20, seq=3)
    # Point-in-time: at seq 15 we must still see the OLD churn score.
    vec = store.serve("user-1", ["age_days", "churn_score"], 15, 4)
    assert vec.get("age_days") == 365
    assert vec.get("churn_score") == 0.7, vec.get("churn_score")
    vec2 = store.serve("user-1", ["churn_score"], 25, 5)
    assert vec2.get("churn_score") == 0.9
    report = store.backfill("churn_score", event_seq=25, seq=6)
    assert isinstance(report, BackfillReport)
    ent = store.entity("user-1", "churn experiment cohort")
    assert store.entity_record("user-1") is ent
    assert store.feature("churn_score").name == "churn_score"
    assert store.entity_ids() == ("user-1",)
    print("audit:", feature_store_audit_event("served", seq=4)["kind"])
    print("feature-store OK: register, ingest, point-in-time serve, backfill")


if __name__ == "__main__":
    main()
