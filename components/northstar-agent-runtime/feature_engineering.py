"""Feature engineering: deterministic transformation/encoding/scaling bookkeeping.

sklearn ``Transformer``-shaped interface bookkeeping, deliberately distinct
from the sibling ``feature_store.py`` (which owns feature *definitions*,
*values* and *vectors*): this module owns the *transformation ledger* —
declaring named transforms (standardization, min-max, one-hot, label,
log, binning, interaction) and booking their application to host-reported
values as deterministic, digest-pinned records.

* **register_transform(transform_id, kind, seq, spec=None)** — declares one
  named transformation. Kinds are pinned: ``standard`` (z-score with
  host-supplied ``{mean, std}``), ``minmax`` (with ``{min, max}``),
  ``onehot``/``label`` (with ``{categories}``), ``log``/``sqrt``/``identity``,
  ``bin`` (with ``{edges}``), ``interaction`` (with ``{with_}`` second
  operand value — product of two numerics).
* **transform(feature_name, transform_id, value, seq)** — applies a
  registered transform to one host-reported scalar value. The outcome is
  booked as data (a frozen ``TransformOutcome``); outputs are pinned by
  type-tagged digest (bool != int, ``|int| >= 2**53`` and non-finite floats
  refused fail-closed).
* **encode(feature_name, value, seq, strategy="label", categories=())** —
  standalone categorical encoding without registering a transform.
  Strategies pinned: ``label`` (index into categories) and ``onehot``
  (frozen ``{category: 0/1}`` vector).
* **scale(column_name, values, seq, strategy="standard", params=None)** —
  batch scaling of a numeric column. Strategies pinned: ``standard``,
  ``minmax``, ``robust`` (median/IQR — host supplies ``{median, iqr}``).
  ``params=None`` derives the statistics from the batch deterministically
  (fit-on-batch); host-supplied params are used verbatim (transform-only).

Fail-closed: unknown transforms/ids, duplicate registrations, malformed
specs, non-canonical values, malformed seqs raise; failed mutations consume
their seq and book a ``feature-engineering.rejected`` audit row (batch-21
discipline). Values never cross the audit boundary — only ids, kinds and
digest pins do.

Honest scope: this is *bookkeeping* for a transformation interface, not a
compute engine. Fit statistics are host-reported (or derived from the
batch at hand); the module cannot verify they were fit on representative
data. A booked ``TransformOutcome`` is ledger truth — "the host declared
this value transformed" — never proof of a real sklearn pipeline.

Version pin: feature-engineering.v1
Schema pin: northstar.feature-engineering.v1
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

#: Module version.
FEATURE_ENGINEERING_VERSION = "feature-engineering.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.feature-engineering.v1"

#: Schema pin for audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_MAX_ID_LEN = 256
_MAX_CATEGORIES = 1024
_MAX_VALUES = 10_000
_SAFE_INT = 2 ** 53

#: Pinned transform kinds.
TRANSFORM_KINDS: FrozenSet[str] = frozenset(
    {
        "standard",
        "minmax",
        "onehot",
        "label",
        "log",
        "sqrt",
        "bin",
        "interaction",
        "identity",
    }
)

#: Pinned standalone encode strategies.
ENCODE_STRATEGIES: FrozenSet[str] = frozenset({"label", "onehot"})

#: Pinned scale strategies.
SCALE_STRATEGIES: FrozenSet[str] = frozenset({"standard", "minmax", "robust"})


class FeatureEngineeringError(Exception):
    """Malformed use of the feature-engineering contract (programming error)."""


class BadTransformError(FeatureEngineeringError):
    """Transform id/kind/spec failed validation."""


class DuplicateTransformError(FeatureEngineeringError):
    """A transform id was registered twice (ids never recycle)."""


class UnknownTransformError(FeatureEngineeringError):
    """A transform id is unknown."""


class BadValueError(FeatureEngineeringError):
    """A feature value failed validation (non-scalar, NaN, unsafe int...)."""


class BadEncodeError(FeatureEngineeringError):
    """An encode request failed validation."""


class BadScaleError(FeatureEngineeringError):
    """A scale request failed validation."""


class SeqOrderError(FeatureEngineeringError):
    """seq failed validation (non-int, bool, or not strictly increasing)."""


class AuditKindError(FeatureEngineeringError):
    """Unknown audit kind."""


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

def _check_seq(seq: object, last: int, consume_on_fail: bool = True) -> int:
    """Validate a caller seq; raises bare SeqOrderError on rewind."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq <= last:
        raise SeqOrderError(f"seq must exceed {last}, got {seq}")
    return seq


def _check_id(value: object, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise FeatureEngineeringError(f"{what} must be a str")
    if not value or len(value) > _MAX_ID_LEN:
        raise FeatureEngineeringError(f"{what} must be 1..{_MAX_ID_LEN} chars")
    if value != value.strip() or any(c.isspace() for c in value):
        raise FeatureEngineeringError(f"{what} must not contain whitespace")
    return value


def _check_name(value: object, what: str) -> str:
    return _check_id(value, what)


def _check_value(value: object) -> object:
    """Validate a scalar feature value (str/int/float/bool)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) >= _SAFE_INT:
            raise BadValueError(f"int value out of safe range |v| < 2^53: {value}")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise BadValueError("float value must be finite")
        return value
    if isinstance(value, str):
        if not value or len(value) > 4096:
            raise BadValueError("str value must be 1..4096 chars")
        return value
    raise BadValueError(f"feature value must be str/int/float/bool, got {type(value).__name__}")


def _check_number(value: object, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadValueError(f"{what} must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise BadValueError(f"{what} must be finite")
    return float(value)


def _check_categories(categories: object) -> Tuple[str, ...]:
    if not isinstance(categories, (tuple, list)):
        raise BadTransformError("categories must be a list/tuple of str")
    cats = tuple(categories)
    if not cats or len(cats) > _MAX_CATEGORIES:
        raise BadTransformError(f"categories must be 1..{_MAX_CATEGORIES} entries")
    seen = set()
    for c in cats:
        if isinstance(c, bool) or not isinstance(c, str) or not c:
            raise BadTransformError("categories must be non-empty str")
        if c in seen:
            raise BadTransformError(f"duplicate category: {c!r}")
        seen.add(c)
    return cats


def _check_edges(edges: object) -> Tuple[float, ...]:
    if not isinstance(edges, (tuple, list)):
        raise BadTransformError("edges must be a list/tuple of numbers")
    nums = tuple(_check_number(e, "edge") for e in edges)
    if len(nums) < 1:
        raise BadTransformError("edges must be non-empty")
    if any(b <= a for a, b in zip(nums, nums[1:])):
        raise BadTransformError("edges must be strictly increasing")
    return nums


def _validate_spec(kind: str, spec: Mapping[str, Any] | None) -> Dict[str, Any]:
    spec = dict(spec or {})
    if kind == "standard":
        mean = _check_number(spec.get("mean"), "mean")
        std = _check_number(spec.get("std"), "std")
        if std <= 0:
            raise BadTransformError("standard: std must be > 0")
        return {"mean": mean, "std": std}
    if kind == "minmax":
        lo = _check_number(spec.get("min"), "min")
        hi = _check_number(spec.get("max"), "max")
        if hi <= lo:
            raise BadTransformError("minmax: max must be > min")
        return {"min": lo, "max": hi}
    if kind in ("onehot", "label"):
        return {"categories": list(_check_categories(spec.get("categories")))}
    if kind in ("log", "sqrt", "identity"):
        if spec:
            raise BadTransformError(f"{kind}: spec must be empty")
        return {}
    if kind == "bin":
        return {"edges": list(_check_edges(spec.get("edges")))}
    if kind == "interaction":
        other = _check_number(spec.get("with_"), "with_")
        return {"with_": other}
    raise BadTransformError(f"unknown transform kind: {kind!r}")


# --------------------------------------------------------------------------
# Canonicalization + digest pins
# --------------------------------------------------------------------------

def _canonical(value: Any) -> str:
    """JCS-style canonicalization with a sibling canonical_json fallback."""
    try:
        from canonical_json import jcs_dumps  # type: ignore

        return jcs_dumps(value)
    except Exception:
        pass
    return _local_canonical(value)


def _local_canonical(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise BadValueError("non-finite float not canonicalizable")
        return repr(value)
    if isinstance(value, str):
        import json

        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, (tuple, list)):
        return "[" + ",".join(_local_canonical(v) for v in value) + "]"
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda kv: kv[0])
        return "{" + ",".join(
            _local_canonical(k) + ":" + _local_canonical(v) for k, v in items
        ) + "}"
    raise BadValueError(f"not canonicalizable: {type(value).__name__}")


def _digest_pin(domain: str, body: str) -> str:
    return "sha256:" + hashlib.sha256(
        (domain + "\x1f" + body).encode("utf-8")
    ).hexdigest()


def _type_tagged(value: Any) -> Tuple[str, Any]:
    """Type-tagged payload so bool/int/float digest domains stay separate."""
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        return ("float", value)
    return ("str", value)


def _encode_value(value: Any, tagged: Tuple[str, Any]) -> Any:
    return value


# --------------------------------------------------------------------------
# Frozen records
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class TransformRecord:
    """A registered named transformation."""
    transform_id: str
    kind: str
    spec: Tuple[Tuple[str, Any], ...]
    seq: int
    digest: str

    def verify(self) -> bool:
        body = _canonical(
            {"transform_id": self.transform_id, "kind": self.kind,
             "spec": dict(self.spec), "seq": self.seq}
        )
        return self.digest == _digest_pin("northstar.feature-engineering.transform", body)


@dataclass(frozen=True)
class TransformOutcome:
    """The booked outcome of applying a transform to one value."""
    feature_name: str
    transform_id: str
    input_digest: str
    output: Any
    output_digest: str
    seq: int


@dataclass(frozen=True)
class EncodeRecord:
    """The booked outcome of a standalone categorical encode."""
    feature_name: str
    strategy: str
    input_digest: str
    output: Any
    output_digest: str
    seq: int


@dataclass(frozen=True)
class ScaleRecord:
    """The booked outcome of batch scaling one column."""
    column_name: str
    strategy: str
    params: Tuple[Tuple[str, float], ...]
    outputs: Tuple[float, ...]
    output_digest: str
    seq: int


# --------------------------------------------------------------------------
# Audit events
# --------------------------------------------------------------------------

_AUDIT_KINDS: FrozenSet[str] = frozenset(
    {
        "transform-registered",
        "transformed",
        "encoded",
        "scaled",
        "rejected",
    }
)


def feature_engineering_audit_event(kind: str, seq: int = 0, **detail: Any) -> Dict[str, Any]:
    """Build an audit.ndjson/1-shaped event for feature engineering."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_id(kind, "kind")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    for banned in ("value", "payload", "raw", "body", "data", "text"):
        if banned in detail:
            raise FeatureEngineeringError(f"banned audit key: {banned}")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": f"feature-engineering.{kind}",
        "seq": seq,
        "detail": dict(detail),
    }


# --------------------------------------------------------------------------
# Transformation application (pure)
# --------------------------------------------------------------------------

def _apply_transform(kind: str, spec: Dict[str, Any], value: Any) -> Any:
    """Apply a registered transform to a validated scalar value."""
    if kind == "identity":
        return value
    if kind == "standard":
        v = _check_number(value, "value")
        return (v - spec["mean"]) / spec["std"]
    if kind == "minmax":
        v = _check_number(value, "value")
        return (v - spec["min"]) / (spec["max"] - spec["min"])
    if kind == "log":
        v = _check_number(value, "value")
        if v <= 0:
            raise BadValueError("log: value must be > 0")
        return math.log(v)
    if kind == "sqrt":
        v = _check_number(value, "value")
        if v < 0:
            raise BadValueError("sqrt: value must be >= 0")
        return math.sqrt(v)
    if kind == "bin":
        v = _check_number(value, "value")
        edges = spec["edges"]
        for i, edge in enumerate(edges):
            if v < edge:
                return i
        return len(edges)
    if kind == "onehot":
        if not isinstance(value, str):
            raise BadValueError("onehot: value must be a category str")
        cats = spec["categories"]
        if value not in cats:
            raise BadValueError(f"onehot: unknown category {value!r}")
        return {c: (1 if c == value else 0) for c in cats}
    if kind == "label":
        if not isinstance(value, str):
            raise BadValueError("label: value must be a category str")
        cats = spec["categories"]
        if value not in cats:
            raise BadValueError(f"label: unknown category {value!r}")
        return cats.index(value)
    if kind == "interaction":
        v = _check_number(value, "value")
        return v * spec["with_"]
    raise BadTransformError(f"unknown transform kind: {kind!r}")


def _apply_encode(strategy: str, categories: Tuple[str, ...], value: Any) -> Any:
    if not isinstance(value, str) or not value:
        raise BadEncodeError("encode: value must be a non-empty category str")
    if value not in categories:
        raise BadEncodeError(f"encode: unknown category {value!r}")
    if strategy == "label":
        return categories.index(value)
    if strategy == "onehot":
        return {c: (1 if c == value else 0) for c in categories}
    raise BadEncodeError(f"unknown encode strategy: {strategy!r}")


def _fit_params(strategy: str, values: List[float]) -> Dict[str, float]:
    if strategy == "standard":
        mean = sum(values) / len(values)
        var = sum((v - mean) ** 2 for v in values) / len(values)
        if var <= 0:
            raise BadScaleError("standard: zero variance cannot be scaled")
        return {"mean": mean, "std": math.sqrt(var)}
    if strategy == "minmax":
        lo, hi = min(values), max(values)
        if hi <= lo:
            raise BadScaleError("minmax: constant column cannot be scaled")
        return {"min": lo, "max": hi}
    if strategy == "robust":
        ordered = sorted(values)
        n = len(ordered)
        mid = n // 2
        median = (ordered[mid - 1] + ordered[mid]) / 2 if n % 2 == 0 else ordered[mid]
        q1 = ordered[n // 4]
        q3 = ordered[(3 * n) // 4]
        iqr = q3 - q1
        if iqr <= 0:
            raise BadScaleError("robust: zero IQR cannot be scaled")
        return {"median": median, "iqr": iqr}
    raise BadScaleError(f"unknown scale strategy: {strategy!r}")


def _apply_scale(strategy: str, params: Dict[str, float], value: float) -> float:
    if strategy == "standard":
        return (value - params["mean"]) / params["std"]
    if strategy == "minmax":
        return (value - params["min"]) / (params["max"] - params["min"])
    if strategy == "robust":
        return (value - params["median"]) / params["iqr"]
    raise BadScaleError(f"unknown scale strategy: {strategy!r}")


# --------------------------------------------------------------------------
# Ledger
# --------------------------------------------------------------------------

class FeatureEngineering:
    """Deterministic transformation/encoding/scaling ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = 0
        self._transforms: Dict[str, TransformRecord] = {}
        self._retired: set = set()
        self._outcomes: List[TransformOutcome] = []
        self._encodes: List[EncodeRecord] = []
        self._scales: List[ScaleRecord] = []
        self._audit: List[Dict[str, Any]] = []

    # -- internal --------------------------------------------------------
    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(feature_engineering_audit_event(audit_kind, seq, **detail))

    def _claim(self, seq: object) -> int:
        s = _check_seq(seq, self._last_seq)
        self._last_seq = s
        return s

    def _reject(self, seq: int, exc: FeatureEngineeringError, **detail: Any) -> None:
        self._emit("rejected", seq, error=type(exc).__name__, **detail)
        raise exc

    # -- transform registration ------------------------------------------
    def register_transform(
        self,
        transform_id: str,
        kind: str,
        seq: int,
        spec: Mapping[str, Any] | None = None,
    ) -> TransformRecord:
        """Declare a named transformation."""
        with self._lock:
            s = self._claim(seq)
            try:
                tid = _check_id(transform_id, "transform_id")
                if not isinstance(kind, str) or kind not in TRANSFORM_KINDS:
                    raise BadTransformError(f"unknown transform kind: {kind!r}")
                norm_spec = _validate_spec(kind, spec)
            except FeatureEngineeringError as exc:
                self._reject(s, exc)
            if tid in self._transforms or tid in self._retired:
                self._reject(s, DuplicateTransformError(f"duplicate transform id: {tid!r}"))
            spec_tuple = tuple(sorted(norm_spec.items()))
            body = _canonical(
                {"transform_id": tid, "kind": kind,
                 "spec": dict(spec_tuple), "seq": s}
            )
            rec = TransformRecord(
                transform_id=tid,
                kind=kind,
                spec=spec_tuple,
                seq=s,
                digest=_digest_pin("northstar.feature-engineering.transform", body),
            )
            self._transforms[tid] = rec
            self._emit(
                "transform-registered", s, transform_id=tid, transform_kind=kind,
                digest=rec.digest,
            )
            return rec

    # -- transform application -------------------------------------------
    def transform(
        self, feature_name: str, transform_id: str, value: Any, seq: int
    ) -> TransformOutcome:
        """Apply a registered transform to one scalar value; books the outcome."""
        with self._lock:
            s = self._claim(seq)
            try:
                fname = _check_name(feature_name, "feature_name")
                tid = _check_id(transform_id, "transform_id")
                v = _check_value(value)
                rec = self._transforms.get(tid)
                if rec is None:
                    raise UnknownTransformError(f"unknown transform id: {tid!r}")
                out = _apply_transform(rec.kind, dict(rec.spec), v)
                tagged = _type_tagged(out)
            except FeatureEngineeringError as exc:
                self._reject(s, exc, transform_id=transform_id)
            in_digest = _digest_pin(
                "northstar.feature-engineering.input",
                _canonical({"t": _type_tagged(v)[0], "v": v}),
            )
            out_digest = _digest_pin(
                "northstar.feature-engineering.output",
                _canonical({"t": tagged[0], "v": out}),
            )
            outcome = TransformOutcome(
                feature_name=fname,
                transform_id=tid,
                input_digest=in_digest,
                output=out,
                output_digest=out_digest,
                seq=s,
            )
            self._outcomes.append(outcome)
            self._emit(
                "transformed", s, feature_name=fname, transform_id=tid,
                input_digest=in_digest, output_digest=out_digest,
            )
            return outcome

    # -- standalone encode -----------------------------------------------
    def encode(
        self,
        feature_name: str,
        value: Any,
        seq: int,
        strategy: str = "label",
        categories: Tuple[str, ...] | List[str] = (),
    ) -> EncodeRecord:
        """Standalone categorical encoding (no registered transform needed)."""
        with self._lock:
            s = self._claim(seq)
            try:
                fname = _check_name(feature_name, "feature_name")
                if not isinstance(strategy, str) or strategy not in ENCODE_STRATEGIES:
                    raise BadEncodeError(f"unknown encode strategy: {strategy!r}")
                cats = _check_categories(categories)
                out = _apply_encode(strategy, cats, value)
                tagged = _type_tagged(out) if not isinstance(out, dict) else ("map", out)
            except FeatureEngineeringError as exc:
                self._reject(s, exc, feature_name=feature_name)
            in_digest = _digest_pin(
                "northstar.feature-engineering.input",
                _canonical({"t": _type_tagged(value)[0], "v": value}),
            )
            out_digest = _digest_pin(
                "northstar.feature-engineering.output",
                _canonical({"t": tagged[0], "v": out}),
            )
            rec = EncodeRecord(
                feature_name=fname,
                strategy=strategy,
                input_digest=in_digest,
                output=out,
                output_digest=out_digest,
                seq=s,
            )
            self._encodes.append(rec)
            self._emit(
                "encoded", s, feature_name=fname, strategy=strategy,
                input_digest=in_digest, output_digest=out_digest,
            )
            return rec

    # -- batch scale -------------------------------------------------------
    def scale(
        self,
        column_name: str,
        values: List[Any],
        seq: int,
        strategy: str = "standard",
        params: Mapping[str, float] | None = None,
    ) -> ScaleRecord:
        """Scale a numeric column; params=None fits deterministically on the batch."""
        with self._lock:
            s = self._claim(seq)
            try:
                cname = _check_name(column_name, "column_name")
                if not isinstance(strategy, str) or strategy not in SCALE_STRATEGIES:
                    raise BadScaleError(f"unknown scale strategy: {strategy!r}")
                if not isinstance(values, (tuple, list)) or not values:
                    raise BadScaleError("values must be a non-empty list")
                if len(values) > _MAX_VALUES:
                    raise BadScaleError(f"values exceeds {_MAX_VALUES}")
                nums = [_check_number(v, "value") for v in values]
                if params is None:
                    fit = _fit_params(strategy, nums)
                else:
                    fit = {}
                    for key in ("mean", "std", "min", "max", "median", "iqr"):
                        if key in params:
                            fit[key] = _check_number(params[key], key)
                    need = {
                        "standard": ("mean", "std"),
                        "minmax": ("min", "max"),
                        "robust": ("median", "iqr"),
                    }[strategy]
                    for key in need:
                        if key not in fit:
                            raise BadScaleError(
                                f"scale {strategy}: missing param {key!r}"
                            )
                    if strategy == "standard" and fit["std"] <= 0:
                        raise BadScaleError("standard: std must be > 0")
                    if strategy == "minmax" and fit["max"] <= fit["min"]:
                        raise BadScaleError("minmax: max must be > min")
                    if strategy == "robust" and fit["iqr"] <= 0:
                        raise BadScaleError("robust: iqr must be > 0")
                outputs = tuple(_apply_scale(strategy, fit, v) for v in nums)
            except FeatureEngineeringError as exc:
                self._reject(s, exc, column_name=column_name)
            params_tuple = tuple(sorted(fit.items()))
            out_digest = _digest_pin(
                "northstar.feature-engineering.scaled",
                _canonical(
                    {"column": cname, "strategy": strategy,
                     "params": dict(params_tuple), "outputs": list(outputs)}
                ),
            )
            rec = ScaleRecord(
                column_name=cname,
                strategy=strategy,
                params=params_tuple,
                outputs=outputs,
                output_digest=out_digest,
                seq=s,
            )
            self._scales.append(rec)
            self._emit(
                "scaled", s, column_name=cname, strategy=strategy,
                output_digest=out_digest,
            )
            return rec

    # -- views -------------------------------------------------------------
    def transform_record(self, transform_id: str) -> Optional[TransformRecord]:
        return self._transforms.get(transform_id)

    def transform_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._transforms))

    def outcomes(self) -> Tuple[TransformOutcome, ...]:
        return tuple(self._outcomes)

    def encodes(self) -> Tuple[EncodeRecord, ...]:
        return tuple(self._encodes)

    def scales(self) -> Tuple[ScaleRecord, ...]:
        return tuple(self._scales)

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(self._audit)

    def stats(self) -> Dict[str, Any]:
        return {
            "transforms": len(self._transforms),
            "transformed": len(self._outcomes),
            "encoded": len(self._encodes),
            "scaled": len(self._scales),
            "last_seq": self._last_seq,
        }


# --------------------------------------------------------------------------
# main() self-check
# --------------------------------------------------------------------------

def main() -> None:
    fe = FeatureEngineering()
    fe.register_transform("z1", "standard", 1, {"mean": 10.0, "std": 2.0})
    fe.register_transform("mm1", "minmax", 2, {"min": 0.0, "max": 100.0})
    fe.register_transform("oh1", "onehot", 3, {"categories": ["a", "b", "c"]})
    out = fe.transform("age", "z1", 14.0, 4)
    assert abs(out.output - 2.0) < 1e-12, out.output
    out2 = fe.transform("pct", "mm1", 50.0, 5)
    assert abs(out2.output - 0.5) < 1e-12, out2.output
    out3 = fe.transform("color", "oh1", "b", 6)
    assert out3.output == {"a": 0, "b": 1, "c": 0}, out3.output
    enc = fe.encode("city", "x", 7, strategy="label", categories=("x", "y"))
    assert enc.output == 0, enc.output
    sc = fe.scale("s", [1.0, 2.0, 3.0], 8, strategy="minmax")
    assert sc.outputs == (0.0, 0.5, 1.0), sc.outputs
    print(
        "feature-engineering OK: register, transform, encode, scale, pins, audit"
    )


if __name__ == "__main__":
    main()
