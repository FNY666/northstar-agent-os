"""Linear probes over model activations for concept presence.

Research context (mechanistic interpretability): linear probes are the
standard tool for asking "is concept X represented in these
activations?" — train a linear direction that separates positive from
negative examples, then project new activations onto that direction.
Used for deception, power-seeking, factual-knowledge, and refusal
concepts, among others.

This module provides a minimal, honest, deterministic implementation:

* ``fit_direction(positives, negatives)`` — pure function returning a
  frozen ``ProbeDirection``: the unit-norm difference-of-means
  direction, plus the min/max projection observed on the training
  data (calibration).
* ``ActivationProbe`` — stateful registry mapping a ``Concept`` to
  its fitted direction. ``probe(activations, concept)`` returns a
  presence score in [0, 1]: the projection's position between the
  training min and max, clamped. 0.0 = "as negative as the most
  negative training example", 1.0 = "as positive as the most positive".
* ``score_projection`` — the low-level pure scoring primitive.

House rules: frozen dataclasses, no wall-clock, deterministic,
fail-closed, stdlib-only. Activations are caller-supplied vectors
(of floats); the module never touches a model.

Honest scope:

* A linear probe measures *correlation of a concept direction in
  activations*, not ground truth about the model's beliefs, intent,
  or future behavior. A high score does not prove the model "thinks
  X"; a low score does not prove it doesn't.
* Difference-of-means is a deliberately simple probe (the standard
  baseline). It can false-positive on correlated-but-causally-
  irrelevant features, and adversarially constructed activations can
  fool it.
* Directions do not transfer across models, layers, or prompt
  formats — a probe fitted on one activation space must not be
  applied to another. The module pins ``layer`` / ``model_id`` on
  the direction record so a mismatch is visible, but it cannot
  enforce it.
* A clean score means "concept direction not strongly present",
  never "the concept is absent".
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Mapping, Sequence

INTERPRETABILITY_PROBE_VERSION = "interpretability-probe.v1"
SCHEMA_PIN = "northstar.interpretability-probe.v1"


class InterpretabilityProbeError(ValueError):
    """Malformed input to the interpretability probe (programming error)."""


def _is_finite_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _validate_vector(values: Sequence[object], what: str) -> tuple[float, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{what} must be a sequence of numbers, not text")
    try:
        items = tuple(values)
    except TypeError:
        raise TypeError(f"{what} must be a sequence of numbers")
    if not items:
        raise InterpretabilityProbeError(f"{what} must be non-empty")
    for item in items:
        if not _is_finite_number(item):
            raise InterpretabilityProbeError(
                f"{what} must contain only finite numbers"
            )
    return tuple(float(item) for item in items)


def _dot(a: Sequence[float], b: Sequence[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _norm(a: Sequence[float]) -> float:
    return math.sqrt(sum(x * x for x in a))


@dataclass(frozen=True)
class Concept:
    """The concept a probe tests for (e.g. deception, refusal)."""

    concept_id: str
    name: str
    model_id: str = ""
    layer: str = ""

    def __post_init__(self) -> None:
        for field_name, value in (
            ("concept_id", self.concept_id),
            ("name", self.name),
        ):
            if not isinstance(value, str) or not value.strip():
                raise InterpretabilityProbeError(
                    f"Concept.{field_name} must be a non-empty string"
                )
        for field_name, value in (
            ("model_id", self.model_id),
            ("layer", self.layer),
        ):
            if not isinstance(value, str):
                raise InterpretabilityProbeError(
                    f"Concept.{field_name} must be a string"
                )

    def as_dict(self) -> dict:
        return {
            "concept_id": self.concept_id,
            "name": self.name,
            "model_id": self.model_id,
            "layer": self.layer,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class ProbeDirection:
    """Fitted linear probe: unit direction + training calibration."""

    concept_id: str
    direction: tuple[float, ...]
    calibration_min: float
    calibration_max: float
    n_positive: int
    n_negative: int

    def __post_init__(self) -> None:
        if not isinstance(self.concept_id, str) or not self.concept_id.strip():
            raise InterpretabilityProbeError(
                "ProbeDirection.concept_id must be a non-empty string"
            )
        direction = _validate_vector(self.direction, "ProbeDirection.direction")
        object.__setattr__(self, "direction", direction)
        if self.calibration_max < self.calibration_min:
            raise InterpretabilityProbeError(
                "calibration_max must be >= calibration_min"
            )
        for field_name, value in (
            ("n_positive", self.n_positive),
            ("n_negative", self.n_negative),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
            ):
                raise InterpretabilityProbeError(
                    f"ProbeDirection.{field_name} must be a positive int"
                )

    def as_dict(self) -> dict:
        return {
            "concept_id": self.concept_id,
            "dim": len(self.direction),
            "calibration_min": self.calibration_min,
            "calibration_max": self.calibration_max,
            "n_positive": self.n_positive,
            "n_negative": self.n_negative,
            "schema": SCHEMA_PIN,
        }


def fit_direction(
    positives: Sequence[Sequence[object]],
    negatives: Sequence[Sequence[object]],
    concept_id: str,
) -> ProbeDirection:
    """Fit a difference-of-means probe direction.

    direction = normalize(mean(positives) - mean(negatives)).
    Calibration is the min/max projection of the training examples
    onto the direction. Fail-closed: empty classes, dimension
    mismatch, or a zero separation vector all raise.
    """
    if not isinstance(concept_id, str) or not concept_id.strip():
        raise InterpretabilityProbeError("concept_id must be a non-empty string")
    try:
        pos_list = list(positives)
        neg_list = list(negatives)
    except TypeError:
        raise TypeError("positives and negatives must be sequences of vectors")
    if not pos_list or not neg_list:
        raise InterpretabilityProbeError(
            "positives and negatives must both be non-empty"
        )
    pos = [_validate_vector(v, "positive example") for v in pos_list]
    neg = [_validate_vector(v, "negative example") for v in neg_list]
    dim = len(pos[0])
    for vec in pos[1:] + neg:
        if len(vec) != dim:
            raise InterpretabilityProbeError(
                "all training vectors must share one dimension"
            )
    mean_pos = [sum(col) / len(pos) for col in zip(*pos)]
    mean_neg = [sum(col) / len(neg) for col in zip(*neg)]
    raw = [a - b for a, b in zip(mean_pos, mean_neg)]
    length = _norm(raw)
    if length == 0.0:
        raise InterpretabilityProbeError(
            "positive and negative means are identical; no probe direction"
        )
    direction = tuple(x / length for x in raw)
    projections = [_dot(v, direction) for v in pos + neg]
    return ProbeDirection(
        concept_id=concept_id,
        direction=direction,
        calibration_min=min(projections),
        calibration_max=max(projections),
        n_positive=len(pos),
        n_negative=len(neg),
    )


def score_projection(
    activations: Sequence[object], probe: ProbeDirection
) -> float:
    """Presence score in [0, 1] for activations against a fitted probe.

    Projects the activation vector onto the probe direction and
    normalizes by the training calibration range. Clamped to [0, 1]
    so out-of-distribution extremes read as full presence/absence,
    not as an unbounded number.
    """
    vec = _validate_vector(activations, "activations")
    if len(vec) != len(probe.direction):
        raise InterpretabilityProbeError(
            f"activations dim {len(vec)} != probe dim {len(probe.direction)}"
        )
    projection = _dot(vec, probe.direction)
    span = probe.calibration_max - probe.calibration_min
    if span == 0.0:
        # Degenerate calibration (single training point per class at the
        # same projection): any projection at/above it reads as presence.
        return 1.0 if projection >= probe.calibration_max else 0.0
    score = (projection - probe.calibration_min) / span
    return min(1.0, max(0.0, score))


@dataclass(frozen=True)
class ProbeFinding:
    """One scored probe result."""

    concept_id: str
    presence_score: float
    n_positive: int
    n_negative: int

    def as_dict(self) -> dict:
        return {
            "concept_id": self.concept_id,
            "presence_score": self.presence_score,
            "n_positive": self.n_positive,
            "n_negative": self.n_negative,
            "schema": SCHEMA_PIN,
        }


class ActivationProbe:
    """Registry of fitted concept probes.

    ``register(concept, positives, negatives)`` fits and stores the
    probe direction for a concept. ``probe(activations, concept)``
    returns the presence score in [0, 1] (``KeyError`` if the concept
    was never registered).
    """

    def __init__(self) -> None:
        self._probes: dict[str, ProbeDirection] = {}

    def register(
        self,
        concept: Concept,
        positives: Sequence[Sequence[object]],
        negatives: Sequence[Sequence[object]],
    ) -> ProbeDirection:
        if not isinstance(concept, Concept):
            raise TypeError("concept must be a Concept")
        direction = fit_direction(positives, negatives, concept.concept_id)
        self._probes[concept.concept_id] = direction
        return direction

    def registered(self) -> tuple[str, ...]:
        return tuple(sorted(self._probes))

    def probe(
        self, activations: Sequence[object], concept: Concept
    ) -> float:
        """Return the presence score of ``concept`` in ``activations``."""
        if not isinstance(concept, Concept):
            raise TypeError("concept must be a Concept")
        try:
            fitted = self._probes[concept.concept_id]
        except KeyError:
            raise KeyError(
                f"no probe registered for concept_id={concept.concept_id!r}"
            )
        return score_projection(activations, fitted)

    def probe_finding(
        self, activations: Sequence[object], concept: Concept
    ) -> ProbeFinding:
        fitted = self._probes[concept.concept_id]
        return ProbeFinding(
            concept_id=concept.concept_id,
            presence_score=score_projection(activations, fitted),
            n_positive=fitted.n_positive,
            n_negative=fitted.n_negative,
        )


def probe_audit_event(
    concept_id: str, presence_score: float, seq: int
) -> dict:
    """Build an audit-shaped record for a probe result."""
    if not isinstance(concept_id, str) or not concept_id.strip():
        raise InterpretabilityProbeError("concept_id must be a non-empty string")
    if not _is_finite_number(presence_score) or not 0.0 <= presence_score <= 1.0:
        raise InterpretabilityProbeError(
            "presence_score must be a finite number in [0, 1]"
        )
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise InterpretabilityProbeError("seq must be a non-negative int")
    return {
        "type": "interpretability-probe",
        "concept_id": concept_id,
        "presence_score": presence_score,
        "seq": seq,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    positives = [(4.0, 0.1), (4.2, -0.1), (3.8, 0.0)]
    negatives = [(0.0, 0.1), (0.2, -0.1), (-0.1, 0.0)]
    concept = Concept(concept_id="deception", name="deceptive reasoning")
    probe = ActivationProbe()
    probe.register(concept, positives, negatives)
    strong = probe.probe((4.0, 0.0), concept)
    weak = probe.probe((0.0, 0.0), concept)
    assert strong > 0.8, f"expected strong presence, got {strong}"
    assert weak < 0.2, f"expected weak presence, got {weak}"
    print(
        f"interpretability-probe OK: strong={strong:.3f} weak={weak:.3f} "
        f"(version {INTERPRETABILITY_PROBE_VERSION}, schema {SCHEMA_PIN})"
    )


if __name__ == "__main__":
    main()
