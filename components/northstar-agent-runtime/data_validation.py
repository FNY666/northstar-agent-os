"""Data validation: deterministic expectation-suite bookkeeping.

Research lineage: Great Expectations (GX) -- the expectation-suite
contract (``suite`` declares a named suite, ``expect`` pins one
``expect_*`` verdict on it, ``validate`` evaluates the suite against a
host-supplied batch of rows). This module is the *bookkeeping* layer for
that contract, not an execution engine: it records declared suites and
expectations, evaluates them deterministically against host-reported
rows, and pins every decision with a ``sha256:`` digest. A booked
``ValidationReport`` is ledger truth ("the host said the batch was this"),
never wire truth about the data's provenance.

* **Expectation vocabulary** -- eight pinned ``expect_*`` types covering
  GX's core verbs: ``expect_column_to_exist``,
  ``expect_column_values_to_not_be_null``,
  ``expect_column_values_to_be_in_set``,
  ``expect_column_values_to_be_between``,
  ``expect_column_values_to_match_regex``,
  ``expect_table_row_count_to_be_between``,
  ``expect_column_mean_to_be_between``,
  ``expect_column_values_to_be_unique``.
  Each type has a fixed required-kwargs contract enforced fail-closed at
  ``expect()`` time, so a booked expectation can always be replayed.
* **Batch semantics** -- a batch is a host-supplied list of row mappings.
  Evaluation is deterministic and pure: verdicts are *data*
  (``success=True/False`` per expectation plus counts), never raised.
  Raw rows are pinned by digest in the report; the audit boundary carries
  only ids, counts, digests and booleans -- never row values.
* **Ledger discipline** -- frozen dataclasses, caller-supplied strictly
  increasing int seqs, no wall-clock, RLock-guarded, fail-closed taxonomy.
  A failed mutation consumes its seq (batch-21 discipline) and books a
  ``data-validation.rejected`` audit row; seq rewinds raise bare without
  consuming. Pure views validate seq shape only.
* **Type discipline** -- kwargs and rows go through the shared canonical
  normalization: ``bool`` is not ``int``, ``|int| < 2**53``, finite
  floats only, str keys, depth-bounded. Means use exact ``Fraction``
  arithmetic -- no floats anywhere in verdicts.

Honest scope: this module cannot prove the host's rows are real,
complete, or fresh; a passing suite means "the declared expectations
hold over the host-reported batch", never "the data is good". Regexes
are host-supplied patterns evaluated with ``re.match`` semantics.

Audit: ``data_validation_audit_event()`` builds ``audit.ndjson/1``
records of kinds ``suite-created`` / ``expectation-added`` /
``validated`` / ``rejected``. Banned from the audit boundary: ``rows``,
``row``, ``values``, ``value``, ``payload``, ``raw``.

Version pin: data-validation.v1
Schema pin: northstar.data-validation.v1
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: Module version pin.
DATA_VALIDATION_VERSION = "data-validation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.data-validation.v1"

#: Schema tag for audit records emitted by this module.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned expectation-type vocabulary (GX-shaped).
EXPECTATION_TYPES = (
    "expect_column_to_exist",
    "expect_column_values_to_not_be_null",
    "expect_column_values_to_be_in_set",
    "expect_column_values_to_be_between",
    "expect_column_values_to_match_regex",
    "expect_table_row_count_to_be_between",
    "expect_column_mean_to_be_between",
    "expect_column_values_to_be_unique",
)

#: Required kwargs per expectation type.
_REQUIRED_KWARGS: Dict[str, Tuple[str, ...]] = {
    "expect_column_to_exist": ("column",),
    "expect_column_values_to_not_be_null": ("column",),
    "expect_column_values_to_be_in_set": ("column", "value_set"),
    "expect_column_values_to_be_between": ("column", "min_value", "max_value"),
    "expect_column_values_to_match_regex": ("column", "regex"),
    "expect_table_row_count_to_be_between": ("min_value", "max_value"),
    "expect_column_mean_to_be_between": ("column", "min_value", "max_value"),
    "expect_column_values_to_be_unique": ("column",),
}

_KINDS = ("suite-created", "expectation-added", "validated", "rejected")

_MAX_ID_LEN = 256
_MAX_STR_LEN = 65536
_MAX_DEPTH = 16


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class DataValidationError(Exception):
    """Base class for data-validation errors."""


class BadSuiteError(DataValidationError):
    """Malformed suite id."""


class DuplicateSuiteError(DataValidationError):
    """A suite with this id already exists."""


class UnknownSuiteError(DataValidationError):
    """No suite with this id has been declared."""


class BadExpectationError(DataValidationError):
    """Malformed expectation id."""


class DuplicateExpectationError(DataValidationError):
    """This suite already holds an expectation with this id."""


class BadTypeError(DataValidationError):
    """Expectation type outside the pinned vocabulary."""


class BadKwargError(DataValidationError):
    """Kwargs violate the pinned contract for this expectation type."""


class BadBatchError(DataValidationError):
    """Malformed batch id or batch rows."""


class SeqOrderError(DataValidationError):
    """Caller seq is not a strictly increasing int."""


class AuditKindError(DataValidationError):
    """Unknown audit kind or banned keys in the audit detail."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    """Caller seqs are strictly increasing ints; bools are not ints."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


def _check_id(value: Any, name: str, error: type) -> str:
    if not isinstance(value, str):
        raise error(f"{name} must be str, got {type(value).__name__}")
    if not value or not value.strip():
        raise error(f"{name} must be non-empty")
    if len(value) > _MAX_ID_LEN:
        raise error(f"{name} exceeds {_MAX_ID_LEN} chars")
    if any(ch.isspace() for ch in value):
        raise error(f"{name} must not contain whitespace")
    return value


def _normalize(value: Any, depth: int = 0) -> Any:
    """Normalize a value into canonical-JSON-safe form (bool != int)."""
    if depth > _MAX_DEPTH:
        raise BadKwargError("kwargs exceed max nesting depth")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadKwargError("int kwargs must satisfy |n| < 2**53")
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadKwargError("float kwargs must be finite")
        return value
    if isinstance(value, str):
        if len(value) > _MAX_STR_LEN:
            raise BadKwargError("str kwargs exceed max length")
        return value
    if isinstance(value, (list, tuple)):
        return [_normalize(v, depth + 1) for v in value]
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise BadKwargError("kwarg mapping keys must be str")
            out[k] = _normalize(v, depth + 1)
        return out
    raise BadKwargError(f"kwarg values must be JSON scalars, got {type(value).__name__}")


def _check_kwargs(expectation_type: str, kwargs: Any) -> Dict[str, Any]:
    if not isinstance(kwargs, dict):
        raise BadKwargError("kwargs must be a mapping")
    normalized = _normalize(kwargs)
    required = _REQUIRED_KWARGS[expectation_type]
    for key in required:
        if key not in normalized:
            raise BadKwargError(f"{expectation_type} requires kwarg {key!r}")
    if "column" in required:
        column = normalized["column"]
        if not isinstance(column, str) or not column:
            raise BadKwargError("column must be a non-empty str")
    if "value_set" in required:
        value_set = normalized["value_set"]
        if not isinstance(value_set, list) or not value_set:
            raise BadKwargError("value_set must be a non-empty list")
        for v in value_set:
            if not isinstance(v, (str, int, float, bool)) or v is None:
                raise BadKwargError("value_set members must be scalars")
    for bound in ("min_value", "max_value"):
        if bound in required:
            v = normalized[bound]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise BadKwargError(f"{bound} must be a number")
    if "min_value" in required and "max_value" in required:
        if normalized["min_value"] > normalized["max_value"]:
            raise BadKwargError("min_value must not exceed max_value")
    if "regex" in required:
        pattern = normalized["regex"]
        if not isinstance(pattern, str) or not pattern:
            raise BadKwargError("regex must be a non-empty str")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise BadKwargError(f"regex does not compile: {exc}") from exc
    return normalized


def _check_rows(rows: Any) -> List[Mapping[str, Any]]:
    if not isinstance(rows, list):
        raise BadBatchError("rows must be a list of mappings")
    checked: List[Mapping[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise BadBatchError("every row must be a mapping")
        checked.append(row)
    return checked


def _digest(parts: Tuple[Any, ...]) -> str:
    """Type-tagged sha256 digest pin over canonical JSON."""
    canonical = json.dumps(
        [DATA_VALIDATION_VERSION, list(parts)],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def data_validation_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for data validation.

    ``detail`` may carry ids, counts, digests, expectation types and
    booleans -- never raw rows or values.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"rows", "row", "values", "value", "payload", "raw"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": DATA_VALIDATION_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SuiteRecord:
    """Frozen record of a ``suite()`` mutation."""

    suite_id: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin."""
        return self.digest == _digest((self.suite_id, self.seq))

    def as_dict(self) -> Dict[str, Any]:
        return {"suite_id": self.suite_id, "seq": self.seq, "digest": self.digest}


@dataclass(frozen=True)
class ExpectationRecord:
    """Frozen record of an ``expect()`` mutation.

    ``kwargs_json`` is the canonical-JSON encoding of the normalized
    kwargs -- replayable without re-entering host values.
    """

    suite_id: str
    expectation_id: str
    expectation_type: str
    kwargs_json: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin."""
        return self.digest == _digest(
            (
                self.suite_id,
                self.expectation_id,
                self.expectation_type,
                self.kwargs_json,
                self.seq,
            )
        )

    def kwargs(self) -> Dict[str, Any]:
        """Parse the canonical kwargs back into a mapping."""
        return json.loads(self.kwargs_json)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "expectation_id": self.expectation_id,
            "expectation_type": self.expectation_type,
            "kwargs_json": self.kwargs_json,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ExpectationResult:
    """Frozen per-expectation verdict inside a validation report.

    ``observed`` is a tuple of ``(name, int)`` pairs -- counts only,
    never raw row values.
    """

    expectation_id: str
    expectation_type: str
    success: bool
    observed: Tuple[Tuple[str, int], ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "expectation_id": self.expectation_id,
            "expectation_type": self.expectation_type,
            "success": self.success,
            "observed": [list(pair) for pair in self.observed],
        }


@dataclass(frozen=True)
class ValidationReport:
    """Frozen record of a ``validate()`` evaluation."""

    suite_id: str
    batch_id: str
    seq: int
    results: Tuple[ExpectationResult, ...]
    success: bool
    batch_digest: str
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin."""
        return self.digest == _digest(
            (
                self.suite_id,
                self.batch_id,
                self.seq,
                tuple(
                    (
                        r.expectation_id,
                        r.expectation_type,
                        r.success,
                        r.observed,
                    )
                    for r in self.results
                ),
                self.success,
                self.batch_digest,
            )
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "batch_id": self.batch_id,
            "seq": self.seq,
            "results": [r.as_dict() for r in self.results],
            "success": self.success,
            "batch_digest": self.batch_digest,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# Evaluation (pure functions over host-reported rows)
# ---------------------------------------------------------------------------


def _tag(value: Any) -> Tuple[str, Any]:
    """Type-tagged equality key: bool is not int."""
    if value is None:
        return ("none", 0)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        return ("float", value)
    if isinstance(value, str):
        return ("str", value)
    return ("other", repr(value))


def _eval_column_to_exist(rows: List[Mapping[str, Any]], column: str):
    evaluated = len(rows)
    unexpected = sum(1 for row in rows if column not in row)
    return evaluated, evaluated - unexpected, unexpected


def _eval_not_null(rows: List[Mapping[str, Any]], column: str):
    evaluated = len(rows)
    unexpected = sum(
        1 for row in rows if column not in row or row[column] is None
    )
    return evaluated, evaluated - unexpected, unexpected


def _eval_in_set(rows: List[Mapping[str, Any]], column: str, value_set: List[Any]):
    allowed = {_tag(v) for v in value_set}
    evaluated = len(rows)
    unexpected = sum(
        1
        for row in rows
        if column not in row or _tag(row[column]) not in allowed
    )
    return evaluated, evaluated - unexpected, unexpected


def _eval_between(
    rows: List[Mapping[str, Any]], column: str, low: Any, high: Any
):
    evaluated = len(rows)
    unexpected = 0
    for row in rows:
        value = row.get(column)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not (low <= value <= high)
        ):
            unexpected += 1
    return evaluated, evaluated - unexpected, unexpected


def _eval_match_regex(rows: List[Mapping[str, Any]], column: str, pattern: str):
    compiled = re.compile(pattern)
    evaluated = len(rows)
    unexpected = sum(
        1
        for row in rows
        if column not in row
        or not isinstance(row[column], str)
        or compiled.match(row[column]) is None
    )
    return evaluated, evaluated - unexpected, unexpected


def _eval_row_count(rows: List[Mapping[str, Any]], low: Any, high: Any):
    count = len(rows)
    ok = low <= count <= high
    return (("row_count", count),), ok


def _eval_mean_between(
    rows: List[Mapping[str, Any]], column: str, low: Any, high: Any
):
    total = Fraction(0)
    count = 0
    for row in rows:
        value = row.get(column)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        total += Fraction(value).limit_denominator()
        count += 1
    if count == 0:
        return (("count", 0),), False
    mean = total / count
    ok = Fraction(low).limit_denominator() <= mean <= Fraction(high).limit_denominator()
    return (("count", count),), ok


def _eval_unique(rows: List[Mapping[str, Any]], column: str):
    evaluated = len(rows)
    seen = set()
    unexpected = 0
    for row in rows:
        if column not in row:
            unexpected += 1
            continue
        key = _tag(row[column])
        if key in seen:
            unexpected += 1
        else:
            seen.add(key)
    return evaluated, evaluated - unexpected, unexpected


# ---------------------------------------------------------------------------
# DataValidation ledger
# ---------------------------------------------------------------------------


class DataValidation:
    """Deterministic expectation-suite bookkeeping (GX-shaped)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._suites: Dict[str, SuiteRecord] = {}
        self._expectations: Dict[str, Dict[str, ExpectationRecord]] = {}
        self._reports: Dict[Tuple[str, str], ValidationReport] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        """Claim a mutation seq: strictly increasing, else bare raise."""
        _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq must exceed {self._seq}, got {seq}")
        self._seq = seq
        return seq

    def _reject(self, seq: int, reason: str) -> None:
        """Book a rejected-mutation audit row (seq already consumed)."""
        self._audit.append(
            data_validation_audit_event(
                "rejected", {"reason": reason}, seq
            )
        )

    # -- mutations ----------------------------------------------------------

    def suite(self, suite_id: str, seq: int) -> SuiteRecord:
        """Declare a named expectation suite."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(suite_id, "suite_id", BadSuiteError)
                if suite_id in self._suites:
                    raise DuplicateSuiteError(f"suite {suite_id!r} already exists")
            except DataValidationError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            record = SuiteRecord(
                suite_id=suite_id, seq=seq, digest=_digest((suite_id, seq))
            )
            self._suites[suite_id] = record
            self._expectations[suite_id] = {}
            self._audit.append(
                data_validation_audit_event(
                    "suite-created", {"suite_id": suite_id}, seq
                )
            )
            return record

    def expect(
        self,
        suite_id: str,
        expectation_id: str,
        expectation_type: str,
        kwargs: Mapping[str, Any],
        seq: int,
    ) -> ExpectationRecord:
        """Pin one expectation onto a suite."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(suite_id, "suite_id", BadSuiteError)
                _check_id(expectation_id, "expectation_id", BadExpectationError)
                if suite_id not in self._suites:
                    raise UnknownSuiteError(f"unknown suite {suite_id!r}")
                if not isinstance(expectation_type, str) or (
                    expectation_type not in EXPECTATION_TYPES
                ):
                    raise BadTypeError(
                        f"expectation_type must be one of {EXPECTATION_TYPES}"
                    )
                normalized = _check_kwargs(expectation_type, kwargs)
                if expectation_id in self._expectations[suite_id]:
                    raise DuplicateExpectationError(
                        f"expectation {expectation_id!r} already in suite {suite_id!r}"
                    )
            except DataValidationError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            kwargs_json = json.dumps(
                normalized, sort_keys=True, separators=(",", ":")
            )
            record = ExpectationRecord(
                suite_id=suite_id,
                expectation_id=expectation_id,
                expectation_type=expectation_type,
                kwargs_json=kwargs_json,
                seq=seq,
                digest=_digest(
                    (suite_id, expectation_id, expectation_type, kwargs_json, seq)
                ),
            )
            self._expectations[suite_id][expectation_id] = record
            self._audit.append(
                data_validation_audit_event(
                    "expectation-added",
                    {
                        "suite_id": suite_id,
                        "expectation_id": expectation_id,
                        "expectation_type": expectation_type,
                    },
                    seq,
                )
            )
            return record

    def validate(
        self, suite_id: str, batch_id: str, rows: List[Mapping[str, Any]], seq: int
    ) -> ValidationReport:
        """Evaluate a suite against a host-reported batch of rows.

        Verdicts are data (``success`` per expectation and overall) --
        a failing batch never raises.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(suite_id, "suite_id", BadSuiteError)
                _check_id(batch_id, "batch_id", BadBatchError)
                if suite_id not in self._suites:
                    raise UnknownSuiteError(f"unknown suite {suite_id!r}")
                checked = _check_rows(rows)
            except DataValidationError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            batch_digest = _digest(
                (
                    "batch",
                    tuple(
                        json.dumps(
                            {str(k): _tag(v) for k, v in sorted(row.items(), key=lambda kv: str(kv[0]))},
                            sort_keys=True,
                            separators=(",", ":"),
                            default=str,
                        )
                        for row in checked
                    ),
                )
            )
            results: List[ExpectationResult] = []
            for expectation_id in sorted(self._expectations[suite_id]):
                record = self._expectations[suite_id][expectation_id]
                etype = record.expectation_type
                kwargs = record.kwargs()
                observed, ok = self._evaluate(etype, kwargs, checked)
                results.append(
                    ExpectationResult(
                        expectation_id=expectation_id,
                        expectation_type=etype,
                        success=ok,
                        observed=observed,
                    )
                )
            success = all(r.success for r in results)
            report = ValidationReport(
                suite_id=suite_id,
                batch_id=batch_id,
                seq=seq,
                results=tuple(results),
                success=success,
                batch_digest=batch_digest,
                digest=_digest(
                    (
                        suite_id,
                        batch_id,
                        seq,
                        tuple(
                            (
                                r.expectation_id,
                                r.expectation_type,
                                r.success,
                                r.observed,
                            )
                            for r in results
                        ),
                        success,
                        batch_digest,
                    )
                ),
            )
            self._reports[(suite_id, batch_id)] = report
            self._audit.append(
                data_validation_audit_event(
                    "validated",
                    {
                        "suite_id": suite_id,
                        "batch_id": batch_id,
                        "success": success,
                        "expectations": len(results),
                        "batch_digest": batch_digest,
                    },
                    seq,
                )
            )
            return report

    # -- evaluation dispatch -------------------------------------------------

    @staticmethod
    def _evaluate(
        expectation_type: str,
        kwargs: Dict[str, Any],
        rows: List[Mapping[str, Any]],
    ) -> Tuple[Tuple[Tuple[str, int], ...], bool]:
        """Evaluate one expectation; returns (observed, success)."""
        if expectation_type == "expect_column_to_exist":
            e, s, u = _eval_column_to_exist(rows, kwargs["column"])
        elif expectation_type == "expect_column_values_to_not_be_null":
            e, s, u = _eval_not_null(rows, kwargs["column"])
        elif expectation_type == "expect_column_values_to_be_in_set":
            e, s, u = _eval_in_set(rows, kwargs["column"], kwargs["value_set"])
        elif expectation_type == "expect_column_values_to_be_between":
            e, s, u = _eval_between(
                rows, kwargs["column"], kwargs["min_value"], kwargs["max_value"]
            )
        elif expectation_type == "expect_column_values_to_match_regex":
            e, s, u = _eval_match_regex(rows, kwargs["column"], kwargs["regex"])
        elif expectation_type == "expect_table_row_count_to_be_between":
            observed, ok = _eval_row_count(
                rows, kwargs["min_value"], kwargs["max_value"]
            )
            return observed, ok
        elif expectation_type == "expect_column_mean_to_be_between":
            observed, ok = _eval_mean_between(
                rows, kwargs["column"], kwargs["min_value"], kwargs["max_value"]
            )
            return observed, ok
        elif expectation_type == "expect_column_values_to_be_unique":
            e, s, u = _eval_unique(rows, kwargs["column"])
        else:  # pragma: no cover - vocabulary pinned at expect()
            raise BadTypeError(f"unknown expectation type {expectation_type!r}")
        return (("evaluated", e), ("successes", s), ("unexpected", u)), u == 0

    # -- views (pure reads; seq shape validated, never consumed) --------------

    def suite_record(self, suite_id: str, seq: int) -> Optional[SuiteRecord]:
        """Fetch a suite record, or None."""
        with self._lock:
            _check_seq(seq)
            return self._suites.get(suite_id)

    def suite_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted suite ids."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._suites))

    def expectation_record(
        self, suite_id: str, expectation_id: str, seq: int
    ) -> Optional[ExpectationRecord]:
        """Fetch one expectation record, or None."""
        with self._lock:
            _check_seq(seq)
            return self._expectations.get(suite_id, {}).get(expectation_id)

    def expectation_ids(self, suite_id: str, seq: int) -> Tuple[str, ...]:
        """Sorted expectation ids for a suite."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._expectations.get(suite_id, {})))

    def validation_report(
        self, suite_id: str, batch_id: str, seq: int
    ) -> Optional[ValidationReport]:
        """Fetch the latest validation report for a suite+batch, or None."""
        with self._lock:
            _check_seq(seq)
            return self._reports.get((suite_id, batch_id))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counts (pure read)."""
        with self._lock:
            _check_seq(seq)
            return {
                "suites": len(self._suites),
                "expectations": sum(len(v) for v in self._expectations.values()),
                "reports": len(self._reports),
                "seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """The booked audit rows (oldest first)."""
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check: suite -> expect -> validate."""
    dv = DataValidation()
    dv.suite("users", 1)
    dv.expect("users", "e-age", "expect_column_values_to_be_between", {"column": "age", "min_value": 0, "max_value": 150}, 2)
    dv.expect("users", "e-name", "expect_column_values_to_not_be_null", {"column": "name"}, 3)
    dv.expect("users", "e-rows", "expect_table_row_count_to_be_between", {"min_value": 1, "max_value": 1000}, 4)
    good = dv.validate(
        "users", "batch-1", [{"name": "a", "age": 30}, {"name": "b", "age": 41}], 5
    )
    assert good.success, "good batch must validate"
    assert good.verify()
    bad = dv.validate(
        "users", "batch-2", [{"name": None, "age": 999}], 6
    )
    assert not bad.success, "bad batch must fail as data"
    assert bad.verify()
    assert dv.stats(7)["reports"] == 2
    kinds = [row["kind"] for row in dv.audit_log()]
    assert kinds == ["suite-created", "expectation-added", "expectation-added",
                     "expectation-added", "validated", "validated"], kinds
    print("data-validation OK: suite, expect, validate, pins, audit")


if __name__ == "__main__":
    main()
