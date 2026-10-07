"""Interpretability (explain/attribute/visualize) interface, simulated.

Research motivation: model explanations are the accountability half of
any deployed ML system -- SHAP (Lundberg & Lee, 2017), LIME (Ribeiro et
al., 2016), integrated gradients (Sundararajan et al., 2017), saliency
maps, and attention-rollout all reduce to the same bookkeeping shape:
declare a prediction, book an explanation decision naming the method,
book per-feature attribution scores, and book a visualization decision.
Getting this ledger wrong (attributions booked against the wrong
explanation, silent method swaps, unpinned feature sets) makes the
explanation unverifiable -- and an unverifiable explanation is not an
explanation.

This module is the *decision ledger* half of that shape:

- ``Interpretability.register_prediction(prediction_id, model_id,
  seq, input_digest="", output_digest="")`` -- declare a prediction
  that will be explained. Returns a frozen ``PredictionRecord`` with a
  ``sha256:`` digest pin. Inputs/outputs travel as digest pins only;
  raw data never enters a record.
- ``Interpretability.explain(prediction_id, seq, method="shap",
  summary_digest="")`` -- book one explanation decision for a
  prediction. Returns a frozen ``ExplanationRecord`` with a minted
  ``exp-N`` id. Method is pinned to a fixed vocabulary (``shap`` /
  ``lime`` / ``integrated-gradients`` / ``saliency`` / ``attention`` /
  ``counterfactual``).
- ``Interpretability.attribute(explanation_id, attributions, seq)`` --
  book the per-feature attribution scores for an explanation: a mapping
  of feature name -> finite score. Returns a frozen
  ``AttributionRecord``. Exactly one attribution set per explanation
  (re-booking is refused fail-closed).
- ``Interpretability.visualize(explanation_id, seq, kind="bar")`` --
  book a visualization decision for an explanation. Returns a frozen
  ``VisualizationRecord``. Kind is pinned to a fixed vocabulary
  (``bar`` / ``waterfall`` / ``heatmap`` / ``force`` / ``text``).
  This books the *decision*; it renders nothing.
- Views (``prediction()``, ``explanation()``, ``attribution()``,
  ``visualization()``, ``stats()``, ``audit_log()``) are pure reads:
  they validate the seq shape, consume nothing, and write no audit row.
- ``interpretability_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``prediction-registered`` / ``explanation-booked`` /
  ``attributed`` / ``visualized`` / ``rejected``); caller-supplied seqs
  only. Raw attribution scores, summaries, and feature values never
  cross the audit boundary -- audit rows carry ids, counts, and digest
  pins only.

Fail-closed edges (fail loudly, never guess):

- ``prediction_id`` / ``explanation_id`` must be non-empty str,
  <= 256 chars, no whitespace; ids are never recycled.
- ``method`` and ``kind`` are pinned vocabularies; anything else is
  refused.
- ``attributions`` must be a non-empty mapping of str feature names
  (<= 256 chars) to finite numeric scores in [-1e6, 1e6]; bool, NaN,
  inf, empty mappings, and non-str keys are refused. The sum of
  absolute scores must be > 0 (a zero attribution set explains
  nothing).
- One explanation per prediction, one attribution set per
  explanation, any number of visualizations per explanation.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* explanation decisions and
  *host-reported* attribution scores. A booked score is a ledger entry,
  not a verified Shapley value -- scores are GIGO: the module cannot
  prove the host ran SHAP, sampled correctly, or attributed honestly.
- ``explain()`` names the method as a declaration; it does not run
  the algorithm, and ``visualize()`` declares an intent to render -- it
  produces no pixels.
- An explanation record proves the ledger's internal consistency
  (pins match, ids link, seqs order). It does not prove the model is
  fair, the prediction correct, or the explanation faithful to the
  model.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if explanation state must survive a restart.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
INTERPRETABILITY_VERSION = "interpretability.v1"

#: Schema pin carried by records and audit events.
INTERPRETABILITY_SCHEMA = "northstar.interpretability.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_PREDICTION_REGISTERED = "prediction-registered"
KIND_EXPLANATION_BOOKED = "explanation-booked"
KIND_ATTRIBUTED = "attributed"
KIND_VISUALIZED = "visualized"
KIND_REJECTED = "rejected"
_KINDS = (KIND_PREDICTION_REGISTERED, KIND_EXPLANATION_BOOKED,
          KIND_ATTRIBUTED, KIND_VISUALIZED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_AUDIT_KEYS = frozenset({
    "attributions", "scores", "score", "summary", "summary_digest",
    "features", "feature", "value", "values", "payload", "raw", "data",
    "input", "output", "text", "body",
})

#: Pinned explanation-method vocabulary.
METHODS = ("shap", "lime", "integrated-gradients", "saliency",
           "attention", "counterfactual")

#: Pinned visualization-kind vocabulary.
VIS_KINDS = ("bar", "waterfall", "heatmap", "force", "text")

#: Score magnitude bound; attribution scores must lie within it.
_SCORE_BOUND = 1e6

#: Maximum number of features per attribution set.
_MAX_FEATURES = 10000


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class InterpretabilityError(Exception):
    """Base class for all interpretability-ledger errors."""


class BadPredictionError(InterpretabilityError):
    """A prediction id, model id, or digest is malformed."""


class DuplicatePredictionError(InterpretabilityError):
    """A prediction id is already registered."""


class UnknownPredictionError(InterpretabilityError):
    """A prediction id is not registered."""


class BadMethodError(InterpretabilityError):
    """An explanation method is not in the pinned vocabulary."""


class DuplicateExplanationError(InterpretabilityError):
    """A prediction already has an explanation booked."""


class UnknownExplanationError(InterpretabilityError):
    """An explanation id is unknown."""


class BadAttributionError(InterpretabilityError):
    """An attribution mapping is malformed."""


class DuplicateAttributionError(InterpretabilityError):
    """An explanation already has an attribution set booked."""


class BadVisualizationError(InterpretabilityError):
    """A visualization kind is not in the pinned vocabulary."""


class SeqOrderError(InterpretabilityError):
    """A seq is malformed or not strictly increasing."""


class AuditKindError(InterpretabilityError):
    """An audit event kind is unknown."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _digest_pin(tag: str, obj: Any) -> str:
    """Return a ``sha256:`` digest pin for a type-tagged object."""
    return "sha256:" + jcs_sha256_hex({"tag": tag, "obj": obj})


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise BadPredictionError(f"{what} must be a str, got "
                                 f"{type(value).__name__}")
    if not value or len(value) > 256:
        raise BadPredictionError(f"{what} must be 1..256 chars")
    if any(ch.isspace() for ch in value):
        raise BadPredictionError(f"{what} must not contain whitespace")
    return value


def _check_digest(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadPredictionError(f"{what} must be a non-empty str")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    if seq < 0:
        raise SeqOrderError("seq must be >= 0")
    return seq


def _check_attributions(attributions: Any) -> Dict[str, float]:
    if not isinstance(attributions, Mapping):
        raise BadAttributionError("attributions must be a mapping")
    if not attributions:
        raise BadAttributionError("attributions must be non-empty")
    if len(attributions) > _MAX_FEATURES:
        raise BadAttributionError(
            f"attributions exceeds {_MAX_FEATURES} features")
    clean: Dict[str, float] = {}
    for key, score in attributions.items():
        if not isinstance(key, str) or isinstance(key, bool):
            raise BadAttributionError("feature names must be str")
        if not key or len(key) > 256:
            raise BadAttributionError("feature names must be 1..256 chars")
        if key in clean:
            raise BadAttributionError("duplicate feature name")
        if isinstance(score, bool):
            raise BadAttributionError("scores must not be bool")
        if isinstance(score, int):
            score = float(score)
        if not isinstance(score, float):
            raise BadAttributionError("scores must be numeric")
        if not math.isfinite(score):
            raise BadAttributionError("scores must be finite")
        if abs(score) > _SCORE_BOUND:
            raise BadAttributionError(
                f"scores must be within [-{_SCORE_BOUND}, {_SCORE_BOUND}]")
        clean[key] = score
    if sum(abs(s) for s in clean.values()) <= 0.0:
        raise BadAttributionError(
            "attribution scores must not all be zero")
    return clean


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PredictionRecord:
    """Declaration of a prediction awaiting explanation."""
    prediction_id: str
    model_id: str
    seq: int
    input_digest: str
    output_digest: str
    digest: str

    def verify(self, prediction_id: str, model_id: str) -> bool:
        return self.digest == _digest_pin(
            "prediction", {"prediction_id": prediction_id,
                           "model_id": model_id, "seq": self.seq})

    def as_dict(self) -> Dict[str, Any]:
        return {"schema": INTERPRETABILITY_SCHEMA,
                "prediction_id": self.prediction_id,
                "model_id": self.model_id, "seq": self.seq,
                "input_digest": self.input_digest,
                "output_digest": self.output_digest,
                "digest": self.digest}


@dataclass(frozen=True)
class ExplanationRecord:
    """One booked explanation decision for a prediction."""
    explanation_id: str
    prediction_id: str
    method: str
    seq: int
    summary_digest: str
    digest: str

    def verify(self, prediction_id: str, method: str) -> bool:
        return self.digest == _digest_pin(
            "explanation", {"explanation_id": self.explanation_id,
                            "prediction_id": prediction_id,
                            "method": method, "seq": self.seq})

    def as_dict(self) -> Dict[str, Any]:
        return {"schema": INTERPRETABILITY_SCHEMA,
                "explanation_id": self.explanation_id,
                "prediction_id": self.prediction_id,
                "method": self.method, "seq": self.seq,
                "summary_digest": self.summary_digest,
                "digest": self.digest}


@dataclass(frozen=True)
class AttributionRecord:
    """Per-feature attribution scores for one explanation."""
    explanation_id: str
    seq: int
    feature_count: int
    scores_digest: str
    digest: str

    def verify(self, explanation_id: str,
               scores_digest: str) -> bool:
        return self.digest == _digest_pin(
            "attribution", {"explanation_id": explanation_id,
                            "scores_digest": scores_digest,
                            "seq": self.seq})

    def as_dict(self) -> Dict[str, Any]:
        return {"schema": INTERPRETABILITY_SCHEMA,
                "explanation_id": self.explanation_id,
                "seq": self.seq, "feature_count": self.feature_count,
                "scores_digest": self.scores_digest,
                "digest": self.digest}


@dataclass(frozen=True)
class VisualizationRecord:
    """One booked visualization decision for an explanation."""
    visualization_id: str
    explanation_id: str
    kind: str
    seq: int
    digest: str

    def verify(self, explanation_id: str, kind: str) -> bool:
        return self.digest == _digest_pin(
            "visualization",
            {"visualization_id": self.visualization_id,
             "explanation_id": explanation_id, "kind": kind,
             "seq": self.seq})

    def as_dict(self) -> Dict[str, Any]:
        return {"schema": INTERPRETABILITY_SCHEMA,
                "visualization_id": self.visualization_id,
                "explanation_id": self.explanation_id,
                "kind": self.kind, "seq": self.seq,
                "digest": self.digest}


# ---------------------------------------------------------------------------
# audit event builder
# ---------------------------------------------------------------------------


def interpretability_audit_event(kind: str, seq: int,
                                 **details: Any) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for this module.

    ``seq`` is the caller's seq (never minted here). Raw attribution
    scores, summaries, and feature data must never appear in
    ``details`` -- ids, counts, and digest pins only.
    """
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(
                f"detail key {key!r} is banned from the audit boundary")
    return {"schema": AUDIT_SCHEMA, "kind": kind, "seq": seq,
            "detail": dict(details)}


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------


class Interpretability:
    """Simulated interpretability (explain/attribute) decision ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._predictions: Dict[str, PredictionRecord] = {}
        self._explanations: Dict[str, ExplanationRecord] = {}
        self._pred_to_exp: Dict[str, str] = {}
        self._attributions: Dict[str, AttributionRecord] = {}
        # scores are host-reported; kept in memory, never cross the audit line
        self._scores: Dict[str, Tuple[Tuple[str, float], ...]] = {}
        self._visualizations: Dict[str, VisualizationRecord] = {}
        self._vis_counter = 0
        self._exp_counter = 0
        self._audit: list = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} not strictly increasing (last {self._last_seq})")
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str) -> None:
        self._audit.append(interpretability_audit_event(
            KIND_REJECTED, seq, reason=reason))

    # -- mutations ----------------------------------------------------------

    def register_prediction(self, prediction_id: str, model_id: str,
                            seq: int, input_digest: str = "",
                            output_digest: str = "") -> PredictionRecord:
        """Declare a prediction that will be explained."""
        with self._lock:
            self._claim(seq)
            try:
                prediction_id = _check_id(prediction_id, "prediction_id")
                model_id = _check_id(model_id, "model_id")
                if prediction_id in self._predictions:
                    raise DuplicatePredictionError(
                        f"prediction already registered: {prediction_id}")
                if input_digest:
                    input_digest = _check_digest(input_digest,
                                                 "input_digest")
                if output_digest:
                    output_digest = _check_digest(output_digest,
                                                  "output_digest")
                digest = _digest_pin("prediction",
                                     {"prediction_id": prediction_id,
                                      "model_id": model_id, "seq": seq})
                rec = PredictionRecord(prediction_id, model_id, seq,
                                       input_digest, output_digest, digest)
                self._predictions[prediction_id] = rec
                self._audit.append(interpretability_audit_event(
                    KIND_PREDICTION_REGISTERED, seq,
                    prediction_id=prediction_id, model_id=model_id,
                    digest=digest))
                return rec
            except InterpretabilityError as exc:
                if not isinstance(exc, SeqOrderError):
                    self._reject(seq, type(exc).__name__)
                raise

    def explain(self, prediction_id: str, seq: int,
                method: str = "shap",
                summary_digest: str = "") -> ExplanationRecord:
        """Book one explanation decision for a registered prediction."""
        with self._lock:
            self._claim(seq)
            try:
                if prediction_id not in self._predictions:
                    raise UnknownPredictionError(
                        f"unknown prediction: {prediction_id!r}")
                if method not in METHODS:
                    raise BadMethodError(
                        f"method must be one of {METHODS}")
                if prediction_id in self._pred_to_exp:
                    raise DuplicateExplanationError(
                        f"prediction already explained: {prediction_id}")
                if summary_digest:
                    summary_digest = _check_digest(summary_digest,
                                                   "summary_digest")
                self._exp_counter += 1
                explanation_id = f"exp-{self._exp_counter}"
                digest = _digest_pin(
                    "explanation",
                    {"explanation_id": explanation_id,
                     "prediction_id": prediction_id,
                     "method": method, "seq": seq})
                rec = ExplanationRecord(explanation_id, prediction_id,
                                        method, seq, summary_digest, digest)
                self._explanations[explanation_id] = rec
                self._pred_to_exp[prediction_id] = explanation_id
                self._audit.append(interpretability_audit_event(
                    KIND_EXPLANATION_BOOKED, seq,
                    explanation_id=explanation_id,
                    prediction_id=prediction_id, method=method,
                    digest=digest))
                return rec
            except InterpretabilityError as exc:
                if not isinstance(exc, SeqOrderError):
                    self._reject(seq, type(exc).__name__)
                raise

    def attribute(self, explanation_id: str,
                  attributions: Mapping[str, float],
                  seq: int) -> AttributionRecord:
        """Book the per-feature attribution scores for an explanation."""
        with self._lock:
            self._claim(seq)
            try:
                if explanation_id not in self._explanations:
                    raise UnknownExplanationError(
                        f"unknown explanation: {explanation_id!r}")
                if explanation_id in self._attributions:
                    raise DuplicateAttributionError(
                        f"explanation already attributed: {explanation_id}")
                clean = _check_attributions(attributions)
                ordered = tuple(sorted(clean.items()))
                scores_digest = _digest_pin(
                    "attribution-scores",
                    {"scores": [list(kv) for kv in ordered]})
                digest = _digest_pin(
                    "attribution",
                    {"explanation_id": explanation_id,
                     "scores_digest": scores_digest, "seq": seq})
                rec = AttributionRecord(explanation_id, seq, len(clean),
                                        scores_digest, digest)
                self._attributions[explanation_id] = rec
                self._scores[explanation_id] = ordered
                self._audit.append(interpretability_audit_event(
                    KIND_ATTRIBUTED, seq,
                    explanation_id=explanation_id,
                    feature_count=len(clean),
                    scores_digest=scores_digest, digest=digest))
                return rec
            except InterpretabilityError as exc:
                if not isinstance(exc, SeqOrderError):
                    self._reject(seq, type(exc).__name__)
                raise

    def visualize(self, explanation_id: str, seq: int,
                  kind: str = "bar") -> VisualizationRecord:
        """Book a visualization decision for an explanation."""
        with self._lock:
            self._claim(seq)
            try:
                if explanation_id not in self._explanations:
                    raise UnknownExplanationError(
                        f"unknown explanation: {explanation_id!r}")
                if kind not in VIS_KINDS:
                    raise BadVisualizationError(
                        f"kind must be one of {VIS_KINDS}")
                self._vis_counter += 1
                visualization_id = f"vis-{self._vis_counter}"
                digest = _digest_pin(
                    "visualization",
                    {"visualization_id": visualization_id,
                     "explanation_id": explanation_id, "kind": kind,
                     "seq": seq})
                rec = VisualizationRecord(visualization_id, explanation_id,
                                          kind, seq, digest)
                self._visualizations[visualization_id] = rec
                self._audit.append(interpretability_audit_event(
                    KIND_VISUALIZED, seq,
                    visualization_id=visualization_id,
                    explanation_id=explanation_id, vis_kind=kind,
                    digest=digest))
                return rec
            except InterpretabilityError as exc:
                if not isinstance(exc, SeqOrderError):
                    self._reject(seq, type(exc).__name__)
                raise

    # -- pure read views ----------------------------------------------------

    def prediction(self, prediction_id: str,
                   seq: int) -> Optional[PredictionRecord]:
        with self._lock:
            _check_seq(seq)
            return self._predictions.get(prediction_id)

    def explanation(self, explanation_id: str,
                    seq: int) -> Optional[ExplanationRecord]:
        with self._lock:
            _check_seq(seq)
            return self._explanations.get(explanation_id)

    def explanation_for(self, prediction_id: str,
                        seq: int) -> Optional[str]:
        with self._lock:
            _check_seq(seq)
            return self._pred_to_exp.get(prediction_id)

    def attribution(self, explanation_id: str,
                    seq: int) -> Optional[AttributionRecord]:
        with self._lock:
            _check_seq(seq)
            return self._attributions.get(explanation_id)

    def attribution_scores(self, explanation_id: str,
                           seq: int) -> Tuple[Tuple[str, float], ...]:
        """Return the booked scores (a pure read of host-reported data)."""
        with self._lock:
            _check_seq(seq)
            return self._scores.get(explanation_id, ())

    def visualization(self, visualization_id: str,
                      seq: int) -> Optional[VisualizationRecord]:
        with self._lock:
            _check_seq(seq)
            return self._visualizations.get(visualization_id)

    def prediction_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._predictions))

    def explanation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._explanations))

    def stats(self, seq: int) -> Dict[str, int]:
        with self._lock:
            _check_seq(seq)
            return {"predictions": len(self._predictions),
                    "explanations": len(self._explanations),
                    "attributed": len(self._attributions),
                    "visualizations": len(self._visualizations),
                    "audit_rows": len(self._audit)}

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    interp = Interpretability()
    pred = interp.register_prediction("pred-1", "model-x", 1)
    assert pred.verify("pred-1", "model-x")
    exp = interp.explain("pred-1", 2, method="shap")
    assert exp.verify("pred-1", "shap")
    attr = interp.attribute("exp-1", {"age": 0.5, "income": -0.25}, 3)
    assert attr.verify("exp-1", attr.scores_digest)
    vis = interp.visualize("exp-1", 4, kind="waterfall")
    assert vis.verify("exp-1", "waterfall")
    for bad_seq in (-1, True, "x", 1.5):
        try:
            interp.stats(bad_seq)
        except SeqOrderError:
            pass
        else:
            raise AssertionError("malformed seq not refused")
    print("interpretability OK: register, explain, attribute, visualize, "
          "pins, audit")


if __name__ == "__main__":
    main()
