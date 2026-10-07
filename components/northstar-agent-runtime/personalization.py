"""Personalization engine: segments, variants, and event tracking (twenty-ninth batch).

Simulated user-segmentation bookkeeping informed by the industry
playbook (segment rule builders, feature-flag bucketing, product
analytics event funnels):

* **Segments** — host-declared audience segments with pinned rule
  specs. :meth:`define_segment` registers a ``(segment_id, name,
  rules)`` record; :meth:`segment` evaluates the rules against
  host-provided attributes and returns the matching segment ids.
  Rules are simple conjunctive predicates ``(field, op, value)``
  over a pinned operator vocabulary; they are *descriptive*, not a
  model — no learning happens here.
* **Variants** — deterministic variant assignment per
  ``(subject_id, experiment_id)`` via sha256 hash bucketing over
  declared integer weights (sums to 100). Stable: re-requesting
  returns the same variant without a new record. This is stable
  bucketing, *not* randomized assignment with statistical
  guarantees — use the :mod:`ab_testing` interface for experiment
  design and significance; this module books *who saw what*.
* **Events** — :meth:`track` appends a digest-pinned event record
  (impression/view/click/conversion/purchase/signup/...) keyed to a
  subject and optionally to its current segment/experiment-variant
  assignment.

House rules: no wall-clock (callers inject integer seq/epoch
values), frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutating calls (``SeqOrderError`` on rewind; failed
mutations consume their seq — fail-closed ledger position),
stdlib-only, sha256 digest pins over type-tagged canonical JSON
(bool != int; no floats; |n| < 2^53), RLock-guarded,
``audit.ndjson/1`` events.

Honest boundary: everything here is bookkeeping over
host-*reported* attributes and events (GIGO). It cannot prove a
subject really belongs to a segment, cannot prove events happened,
and hash bucketing is not a substitute for randomized trials or
causal inference. A variant assignment means "host was told to
show this", never "this caused the outcome".
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

#: Version pin for this module's record shape.
PERSONALIZATION_VERSION = "personalization.v1"

#: Schema pin carried by records and audit events.
PERSONALIZATION_SCHEMA = "northstar.personalization.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned rule operators for segment definitions.
OP_EQ = "eq"
OP_NE = "ne"
OP_GT = "gt"
OP_LT = "lt"
OP_GTE = "gte"
OP_LTE = "lte"
OP_IN = "in"
OP_CONTAINS = "contains"
OPERATORS = (OP_EQ, OP_NE, OP_GT, OP_LT, OP_GTE, OP_LTE, OP_IN, OP_CONTAINS)

#: Pinned event vocabulary for tracking.
EVENT_IMPRESSION = "impression"
EVENT_VIEW = "view"
EVENT_CLICK = "click"
EVENT_SIGNUP = "signup"
EVENT_CONVERSION = "conversion"
EVENT_PURCHASE = "purchase"
EVENT_REFUND = "refund"
EVENT_CHURN = "churn"
EVENTS = (
    EVENT_IMPRESSION,
    EVENT_VIEW,
    EVENT_CLICK,
    EVENT_SIGNUP,
    EVENT_CONVERSION,
    EVENT_PURCHASE,
    EVENT_REFUND,
    EVENT_CHURN,
)

#: Audit event kinds.
KIND_SEGMENT_DEFINED = "personalization.segment-defined"
KIND_EXPERIMENT_DEFINED = "personalization.experiment-defined"
KIND_SEGMENT_ASSIGNED = "personalization.segment-assigned"
KIND_VARIANT_ASSIGNED = "personalization.variant-assigned"
KIND_EVENT_TRACKED = "personalization.event-tracked"
_KINDS = (
    KIND_SEGMENT_DEFINED,
    KIND_EXPERIMENT_DEFINED,
    KIND_SEGMENT_ASSIGNED,
    KIND_VARIANT_ASSIGNED,
    KIND_EVENT_TRACKED,
)

_GENESIS = "genesis"

__all__ = [
    "PERSONALIZATION_VERSION",
    "PERSONALIZATION_SCHEMA",
    "OPERATORS",
    "EVENTS",
    "PersonalizationError",
    "UnknownSegmentError",
    "UnknownExperimentError",
    "DuplicateSegmentError",
    "DuplicateExperimentError",
    "BadRuleError",
    "BadVariantError",
    "BadEventError",
    "SeqOrderError",
    "SegmentRecord",
    "ExperimentRecord",
    "AssignmentRecord",
    "VariantAssignment",
    "EventRecord",
    "Personalization",
    "personalization_audit_event",
]


class PersonalizationError(ValueError):
    """Base fail-closed error for the personalization engine."""


class UnknownSegmentError(PersonalizationError):
    """A segment id that was never defined."""


class UnknownExperimentError(PersonalizationError):
    """An experiment id that was never defined."""


class DuplicateSegmentError(PersonalizationError):
    """A segment id that is already defined."""


class DuplicateExperimentError(PersonalizationError):
    """An experiment id that is already defined."""


class BadRuleError(PersonalizationError):
    """A malformed segment rule spec."""


class BadVariantError(PersonalizationError):
    """A malformed variant spec (bad weights, empty, duplicates)."""


class BadEventError(PersonalizationError):
    """A malformed tracking event (unknown event, bad value)."""


class SeqOrderError(PersonalizationError):
    """A mutation seq that is not strictly increasing."""


# ---------------------------------------------------------------------------
# Canonical digest helpers (type-tagged: bool != int; no floats; |n| < 2^53)
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PersonalizationError(f"{field_name} must be a non-negative int")
    return value


def _tagged(obj: Any) -> Any:
    if obj is None or isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        if abs(obj) >= 2**53:
            raise PersonalizationError("int out of safe range (|n| >= 2^53)")
        return obj
    if isinstance(obj, float):
        raise PersonalizationError("floats are not canonicalizable")
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (list, tuple)):
        return [_tagged(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): _tagged(obj[k]) for k in sorted(obj.keys(), key=str)}
    raise PersonalizationError(f"unsupported value type: {type(obj).__name__}")


def _canonical(obj: Any) -> bytes:
    return json.dumps(
        _tagged(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(list(parts))).hexdigest()


def personalization_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the personalization engine."""
    if kind not in _KINDS:
        raise PersonalizationError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "personalization",
        "module_version": PERSONALIZATION_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# Rule specs and matching
# ---------------------------------------------------------------------------


def _check_rule(rule: Any) -> tuple[str, str, Any]:
    """Validate one ``(field, op, value)`` rule spec."""
    if not isinstance(rule, (list, tuple)) or len(rule) != 3:
        raise BadRuleError("rule must be a (field, op, value) triple")
    field, op, value = rule
    if not isinstance(field, str) or not field or len(field) > 128:
        raise BadRuleError("rule field must be a non-empty str")
    if op not in OPERATORS:
        raise BadRuleError(f"unknown rule operator: {op!r}")
    if op in (OP_IN,):
        if not isinstance(value, (list, tuple)) or not value:
            raise BadRuleError("in operator needs a non-empty value list")
        for v in value:
            if not isinstance(v, (str, int)) or isinstance(v, bool):
                raise BadRuleError("in values must be str or int")
    elif op == OP_CONTAINS:
        if not isinstance(value, str) or not value:
            raise BadRuleError("contains needs a non-empty str value")
    else:
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            raise BadRuleError("comparison values must be str or int")
    return (field, op, list(value) if isinstance(value, (list, tuple)) else value)


def _match(rule: tuple[str, str, Any], attributes: Mapping[str, Any]) -> bool:
    """Evaluate one rule against host-provided attributes (conjunctive).

    Missing fields and type mismatches fail closed to ``False`` — a
    subject that cannot be described is simply not matched.
    """
    field, op, value = rule
    actual = attributes.get(field, None)
    if actual is None:
        return False
    if op == OP_IN:
        return isinstance(actual, (str, int)) and not isinstance(actual, bool) and actual in value
    if op == OP_CONTAINS:
        return isinstance(actual, str) and value in actual
    # Comparison ops: both sides must be str or int (not bool), and
    # mixed-type comparisons (str vs int) fail closed to False.
    if not isinstance(actual, (str, int)) or isinstance(actual, bool):
        return False
    if type(actual) is not type(value):
        # Allow int-vs-int only when both int; str-vs-str likewise.
        return False
    if op == OP_EQ:
        return actual == value
    if op == OP_NE:
        return actual != value
    if op == OP_GT:
        return actual > value
    if op == OP_LT:
        return actual < value
    if op == OP_GTE:
        return actual >= value
    if op == OP_LTE:
        return actual <= value
    return False  # unreachable: op pinned by _check_rule


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SegmentRecord:
    segment_id: str
    name: str
    rules: tuple[tuple[str, str, Any], ...]
    description: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "segment", self.segment_id, self.name,
            [list(r) for r in self.rules], self.description, self.seq,
        )


@dataclass(frozen=True)
class ExperimentRecord:
    experiment_id: str
    name: str
    variants: tuple[tuple[str, int], ...]  # (variant_id, weight_percent)
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "experiment", self.experiment_id, self.name,
            [list(v) for v in self.variants], self.seq,
        )


@dataclass(frozen=True)
class AssignmentRecord:
    assignment_id: str
    subject_id: str
    segment_ids: tuple[str, ...]
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "assignment", self.assignment_id, self.subject_id,
            list(self.segment_ids), self.seq, self.prev_digest,
        )


@dataclass(frozen=True)
class VariantAssignment:
    assignment_id: str
    subject_id: str
    experiment_id: str
    variant_id: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "variant", self.assignment_id, self.subject_id,
            self.experiment_id, self.variant_id, self.seq,
        )


@dataclass(frozen=True)
class EventRecord:
    event_id: str
    subject_id: str
    event: str
    value: int | None
    segment_id: str | None
    experiment_id: str | None
    variant_id: str | None
    seq: int
    prev_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "event", self.event_id, self.subject_id, self.event,
            self.value, self.segment_id, self.experiment_id,
            self.variant_id, self.seq, self.prev_digest,
        )


# ---------------------------------------------------------------------------
# Personalization engine
# ---------------------------------------------------------------------------


class Personalization:
    """Simulated personalization engine: segments, variants, event tracking.

    All mutations require a caller-supplied strictly-increasing int
    ``seq`` (fail-closed ledger position: failed mutations consume
    their seq). Reads return data, never raise, for unknown ids
    where marked — lookups of *declared* entities raise on unknown
    ids (fail-closed definition errors), while match/tracking calls
    treat unknown data as non-matching verdicts.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._segments: dict[str, SegmentRecord] = {}
        self._experiments: dict[str, ExperimentRecord] = {}
        self._assignments: list[AssignmentRecord] = []
        self._assignment_chain: dict[str, str] = {}
        self._variant_assignments: dict[tuple[str, str], VariantAssignment] = {}
        self._events: list[EventRecord] = []
        self._event_chain = _GENESIS
        self._audit: list[Mapping[str, Any]] = []
        self._assignment_counter = 0
        self._variant_counter = 0
        self._event_counter = 0

    # -- internal ------------------------------------------------------

    def _take_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError("seq must be strictly increasing")
        self._last_seq = seq
        return seq

    def _audit_locked(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(personalization_audit_event(kind, seq, **detail))

    def _bucket(self, subject_id: str, experiment_id: str) -> str:
        """Stable hash bucket in [0, 100)."""
        h = hashlib.sha256(
            f"{experiment_id}\x00{subject_id}".encode("utf-8")
        ).hexdigest()
        return int(h[:8], 16) % 100

    # -- definitions ---------------------------------------------------

    def define_segment(
        self,
        segment_id: str,
        name: str,
        seq: int,
        *,
        rules: Sequence[Any] = (),
        description: str = "",
    ) -> SegmentRecord:
        """Declare a segment with conjunctive ``(field, op, value)`` rules."""
        with self._lock:
            seq = self._take_seq(seq)
            if not isinstance(segment_id, str) or not segment_id or len(segment_id) > 64:
                raise PersonalizationError("segment_id must be a non-empty str")
            if not isinstance(name, str) or not name or len(name) > 128:
                raise PersonalizationError("name must be a non-empty str")
            if segment_id in self._segments:
                raise DuplicateSegmentError(f"segment already defined: {segment_id!r}")
            checked = tuple(_check_rule(r) for r in rules)
            if not isinstance(description, str) or len(description) > 256:
                raise PersonalizationError("description must be a str <= 256 chars")
            record = SegmentRecord(
                segment_id=segment_id,
                name=name,
                rules=checked,
                description=description,
                seq=seq,
                digest=_pin(
                    "segment", segment_id, name,
                    [list(r) for r in checked], description, seq,
                ),
            )
            self._segments[segment_id] = record
            self._audit_locked(
                KIND_SEGMENT_DEFINED, seq,
                segment_id=segment_id, rule_count=len(checked),
                digest=record.digest,
            )
            return record

    def define_experiment(
        self,
        experiment_id: str,
        name: str,
        seq: int,
        *,
        variants: Sequence[Any],
    ) -> ExperimentRecord:
        """Declare an experiment with ``(variant_id, weight_percent)`` variants.

        Weights must be positive ints summing to exactly 100.
        """
        with self._lock:
            seq = self._take_seq(seq)
            if not isinstance(experiment_id, str) or not experiment_id or len(experiment_id) > 64:
                raise PersonalizationError("experiment_id must be a non-empty str")
            if not isinstance(name, str) or not name or len(name) > 128:
                raise PersonalizationError("name must be a non-empty str")
            if experiment_id in self._experiments:
                raise DuplicateExperimentError(
                    f"experiment already defined: {experiment_id!r}"
                )
            if not variants:
                raise BadVariantError("variants must be non-empty")
            seen: set[str] = set()
            checked: list[tuple[str, int]] = []
            total = 0
            for spec in variants:
                if not isinstance(spec, (list, tuple)) or len(spec) != 2:
                    raise BadVariantError("variant must be (variant_id, weight)")
                vid, weight = spec
                if not isinstance(vid, str) or not vid or len(vid) > 64:
                    raise BadVariantError("variant_id must be a non-empty str")
                if vid in seen:
                    raise BadVariantError(f"duplicate variant_id: {vid!r}")
                seen.add(vid)
                if isinstance(weight, bool) or not isinstance(weight, int) or weight <= 0:
                    raise BadVariantError("weight must be a positive int")
                checked.append((vid, weight))
                total += weight
            if total != 100:
                raise BadVariantError(f"weights must sum to 100, got {total}")
            variants_t = tuple(checked)
            record = ExperimentRecord(
                experiment_id=experiment_id,
                name=name,
                variants=variants_t,
                seq=seq,
                digest=_pin(
                    "experiment", experiment_id, name,
                    [list(v) for v in variants_t], seq,
                ),
            )
            self._experiments[experiment_id] = record
            self._audit_locked(
                KIND_EXPERIMENT_DEFINED, seq,
                experiment_id=experiment_id,
                variant_ids=[v[0] for v in variants_t],
                digest=record.digest,
            )
            return record

    # -- assignment ----------------------------------------------------

    def segment(
        self, subject_id: str, seq: int, attributes: Mapping[str, Any] | None = None
    ) -> AssignmentRecord:
        """Evaluate segment rules against host-provided attributes.

        Returns the sorted matching segment ids as data (empty tuple
        when nothing matches). A subject that cannot be described is
        simply not matched — never an exception.
        """
        with self._lock:
            seq = self._take_seq(seq)
            if not isinstance(subject_id, str) or not subject_id:
                raise PersonalizationError("subject_id must be a non-empty str")
            attrs: Mapping[str, Any] = attributes or {}
            if not isinstance(attrs, Mapping):
                raise PersonalizationError("attributes must be a mapping")
            matched = sorted(
                sid
                for sid, record in self._segments.items()
                if all(_match(rule, attrs) for rule in record.rules)
            )
            self._assignment_counter += 1
            assignment_id = f"asg-{self._assignment_counter}"
            prev = self._assignment_chain.get(subject_id, _GENESIS)
            record = AssignmentRecord(
                assignment_id=assignment_id,
                subject_id=subject_id,
                segment_ids=tuple(matched),
                seq=seq,
                prev_digest=prev,
                digest=_pin(
                    "assignment", assignment_id, subject_id, matched, seq, prev
                ),
            )
            self._assignments.append(record)
            self._assignment_chain[subject_id] = record.digest
            self._audit_locked(
                KIND_SEGMENT_ASSIGNED, seq,
                assignment_id=assignment_id, subject_id=subject_id,
                segment_ids=matched, digest=record.digest,
            )
            return record

    def variant(self, subject_id: str, experiment_id: str, seq: int) -> VariantAssignment:
        """Stable variant assignment for ``(subject_id, experiment_id)``.

        Hash bucketing over declared weights; re-requesting returns
        the same variant record (idempotent, no new ledger entry).
        Unknown experiments raise fail-closed.
        """
        with self._lock:
            if not isinstance(subject_id, str) or not subject_id:
                raise PersonalizationError("subject_id must be a non-empty str")
            key = (subject_id, experiment_id)
            existing = self._variant_assignments.get(key)
            if existing is not None:
                return existing
            seq = self._take_seq(seq)
            experiment = self._experiments.get(experiment_id)
            if experiment is None:
                raise UnknownExperimentError(f"unknown experiment: {experiment_id!r}")
            bucket = self._bucket(subject_id, experiment_id)
            chosen = experiment.variants[-1][0]
            cumulative = 0
            for vid, weight in experiment.variants:
                cumulative += weight
                if bucket < cumulative:
                    chosen = vid
                    break
            self._variant_counter += 1
            assignment_id = f"var-{self._variant_counter}"
            record = VariantAssignment(
                assignment_id=assignment_id,
                subject_id=subject_id,
                experiment_id=experiment_id,
                variant_id=chosen,
                seq=seq,
                digest=_pin(
                    "variant", assignment_id, subject_id,
                    experiment_id, chosen, seq,
                ),
            )
            self._variant_assignments[key] = record
            self._audit_locked(
                KIND_VARIANT_ASSIGNED, seq,
                assignment_id=assignment_id, subject_id=subject_id,
                experiment_id=experiment_id, variant_id=chosen,
                digest=record.digest,
            )
            return record

    # -- tracking ------------------------------------------------------

    def track(
        self,
        subject_id: str,
        event: str,
        seq: int,
        *,
        value: int | None = None,
        segment_id: str | None = None,
        experiment_id: str | None = None,
        variant_id: str | None = None,
    ) -> EventRecord:
        """Append a digest-pinned event record for a subject."""
        with self._lock:
            seq = self._take_seq(seq)
            if not isinstance(subject_id, str) or not subject_id:
                raise PersonalizationError("subject_id must be a non-empty str")
            if event not in EVENTS:
                raise BadEventError(f"unknown event: {event!r}")
            if value is not None:
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise BadEventError("value must be a non-negative int or None")
                if value >= 2**53:
                    raise BadEventError("value out of safe range (|n| >= 2^53)")
            if segment_id is not None and segment_id not in self._segments:
                raise UnknownSegmentError(f"unknown segment: {segment_id!r}")
            if experiment_id is not None and experiment_id not in self._experiments:
                raise UnknownExperimentError(f"unknown experiment: {experiment_id!r}")
            if variant_id is not None and (
                not isinstance(variant_id, str) or not variant_id
            ):
                raise BadEventError("variant_id must be a non-empty str")
            if variant_id is not None and experiment_id is None:
                raise BadEventError("variant_id requires experiment_id")
            self._event_counter += 1
            event_id = f"evt-{self._event_counter}"
            prev = self._event_chain
            record = EventRecord(
                event_id=event_id,
                subject_id=subject_id,
                event=event,
                value=value,
                segment_id=segment_id,
                experiment_id=experiment_id,
                variant_id=variant_id,
                seq=seq,
                prev_digest=prev,
                digest=_pin(
                    "event", event_id, subject_id, event, value,
                    segment_id, experiment_id, variant_id, seq, prev,
                ),
            )
            self._events.append(record)
            self._event_chain = record.digest
            self._audit_locked(
                KIND_EVENT_TRACKED, seq,
                event_id=event_id, subject_id=subject_id, event=event,
                digest=record.digest,
            )
            return record

    # -- views ---------------------------------------------------------

    def segment_record(self, segment_id: str) -> SegmentRecord:
        with self._lock:
            record = self._segments.get(segment_id)
            if record is None:
                raise UnknownSegmentError(f"unknown segment: {segment_id!r}")
            return record

    def experiment_record(self, experiment_id: str) -> ExperimentRecord:
        with self._lock:
            record = self._experiments.get(experiment_id)
            if record is None:
                raise UnknownExperimentError(f"unknown experiment: {experiment_id!r}")
            return record

    def segment_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._segments))

    def experiment_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._experiments))

    def assignments(self) -> tuple[AssignmentRecord, ...]:
        with self._lock:
            return tuple(self._assignments)

    def events(self) -> tuple[EventRecord, ...]:
        with self._lock:
            return tuple(self._events)

    def audit_log(self) -> tuple[Mapping[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    engine = Personalization()
    seg = engine.define_segment(
        "power-users", "Power users", 1,
        rules=[("sessions_30d", "gte", 20), ("plan", "eq", "pro")],
    )
    assert seg.verify()
    exp = engine.define_experiment(
        "onboarding-v2", "Onboarding v2", 2,
        variants=[("control", 50), ("treatment", 50)],
    )
    assert exp.verify()
    asg = engine.segment("user-1", 3, {"sessions_30d": 42, "plan": "pro"})
    assert asg.verify() and asg.segment_ids == ("power-users",)
    var = engine.variant("user-1", "onboarding-v2", 4)
    assert var.verify()
    again = engine.variant("user-1", "onboarding-v2", 5)
    assert again is var
    evt = engine.track(
        "user-1", "conversion", 6, value=99,
        segment_id="power-users", experiment_id="onboarding-v2",
        variant_id=var.variant_id,
    )
    assert evt.verify()
    print(
        "personalization OK: define-segment, define-experiment, "
        "segment, variant, track, pins"
    )


if __name__ == "__main__":
    main()
