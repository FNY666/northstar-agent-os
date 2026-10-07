"""Recursive reward modeling: scalable oversight through decomposed feedback.

Human feedback is the scarcest resource in an agent runtime. Asking a human
to rate whole trajectories does not scale; recursive reward modeling (RRM)
instead learns reward from feedback on *pieces* and estimates the value of
a whole from the value of its parts:

- :class:`RewardModel` is a linear preference model: it learns one weight
  per named feature from pairwise and scalar :class:`HumanFeedback`;
- :class:`RecursiveRewardEstimator` keeps a decomposition tree
  (task -> subtasks) and estimates a parent's reward by aggregating its
  children's estimates, so a human only ever rates leaves.
- :class:`RecursiveReward` is the noun-API facade over the two above:
  ``model()`` exposes the reward model, ``recurse()`` books one
  decomposition step, ``evaluate()`` runs the recursion.

Two honest-scope facts are load-bearing and repeated below:

1. This is a **mechanical preference ledger**, not learning in any deep
   sense. The update rule is a fixed delta/perceptron step on caller-
   supplied features. The module cannot verify that the features describe
   the action honestly, that the rater was competent, or that the reward
   generalizes beyond the rated features.
2. A reward estimate is **never an authorization**. ``predict_reward``
   returning 0.99 does not permit anything; gates (edge gate, approval
   chain, budget) still decide. This module scores candidates for a
   planner; it does not grant permission.

Confidence propagates fail-closed through the recursion: a parent's
confidence is the *minimum* of its children's confidences. One unevaluated
subtask taints the whole estimate. Extrapolation (features never seen in
training) is flagged rather than silently scored.

Everything is offline and deterministic: no clock reads, caller-supplied
sequence numbers only, fixed learning rate, no randomness.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

#: Module version, stamped on records and audit events.
RECURSIVE_REWARD_VERSION = "recursive-reward.v1"

#: Schema pin for records produced by this module.
REWARD_SCHEMA = "northstar.recursive-reward.v1"

#: Fixed update step for the linear preference model (deterministic).
LEARNING_RATE = 0.1

#: Smoothing count used when converting feedback coverage into confidence.
CONFIDENCE_SMOOTHING = 5

#: Reward scores are kept on this bounded interval.
_SCORE_MIN = -1.0
_SCORE_MAX = 1.0


class RewardError(Exception):
    """Raised for malformed feedback, features, or decomposition structure."""


def _check_finite(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RewardError(f"{name} must be a real number, got {type(value).__name__}")
    value = float(value)
    if not math.isfinite(value):
        raise RewardError(f"{name} must be finite, got {value!r}")
    return value


def _check_seq(seq: Any, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise RewardError(f"{name} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise RewardError(f"{name} must be non-negative, got {seq}")
    return seq


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RewardError(f"{name} must be a non-empty string")
    return value


def _clip(score: float) -> float:
    return max(_SCORE_MIN, min(_SCORE_MAX, score))


@dataclass(frozen=True)
class ActionFeatures:
    """Named numeric features describing one candidate action.

    Features are stored as sorted (name, value) pairs so records are
    canonical and digest-stable. Values must be finite; booleans are
    rejected (a boolean is a label, not a measurement, and would
    silently become 0.0/1.0).
    """

    features: tuple[tuple[str, float], ...]
    schema: str = REWARD_SCHEMA

    def __init__(self, features: Sequence[tuple[str, float]] | Mapping[str, float]) -> None:
        pairs: list[tuple[str, float]]
        if isinstance(features, Mapping):
            pairs = [(k, v) for k, v in features.items()]
        else:
            pairs = list(features)
        if not pairs:
            raise RewardError("features must not be empty")
        cleaned: list[tuple[str, float]] = []
        seen: set[str] = set()
        for item in pairs:
            try:
                name, value = item
            except (TypeError, ValueError):
                raise RewardError(f"feature must be a (name, value) pair, got {item!r}")
            name = _check_id(name, "feature name")
            if name in seen:
                raise RewardError(f"duplicate feature name: {name!r}")
            seen.add(name)
            cleaned.append((name, _check_finite(value, f"feature {name!r}")))
        cleaned.sort(key=lambda pair: pair[0])
        object.__setattr__(self, "features", tuple(cleaned))
        object.__setattr__(self, "schema", REWARD_SCHEMA)

    def as_dict(self) -> dict[str, float]:
        return dict(self.features)

    def names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.features)


@dataclass(frozen=True)
class HumanFeedback:
    """One human (or trusted-rater) feedback event.

    Exactly one of the two shapes is used:

    - *pairwise*: ``preferred`` beat ``other`` (ranking update);
    - *scalar*: ``action`` was rated ``rating`` in [-1, 1] (delta update).

    ``seq`` is the caller-supplied ordering number (no wall clock).
    """

    feedback_id: str
    seq: int
    preferred: ActionFeatures | None = None
    other: ActionFeatures | None = None
    action: ActionFeatures | None = None
    rating: float | None = None
    rater: str = "human"
    schema: str = REWARD_SCHEMA

    def __init__(
        self,
        feedback_id: str,
        seq: int,
        *,
        preferred: ActionFeatures | None = None,
        other: ActionFeatures | None = None,
        action: ActionFeatures | None = None,
        rating: float | None = None,
        rater: str = "human",
    ) -> None:
        object.__setattr__(self, "feedback_id", _check_id(feedback_id, "feedback_id"))
        object.__setattr__(self, "seq", _check_seq(seq))
        pairwise = preferred is not None or other is not None
        scalar = action is not None or rating is not None
        if pairwise == scalar:
            raise RewardError(
                "feedback must be exactly one of pairwise "
                "(preferred+other) or scalar (action+rating)"
            )
        if pairwise:
            if not isinstance(preferred, ActionFeatures) or not isinstance(
                other, ActionFeatures
            ):
                raise RewardError("pairwise feedback needs preferred and other ActionFeatures")
        else:
            if not isinstance(action, ActionFeatures):
                raise RewardError("scalar feedback needs an action ActionFeatures")
            if rating is None:
                raise RewardError("scalar feedback needs a rating")
            rating = _check_finite(rating, "rating")
            if not _SCORE_MIN <= rating <= _SCORE_MAX:
                raise RewardError(f"rating must be in [{_SCORE_MIN}, {_SCORE_MAX}]")
        object.__setattr__(self, "preferred", preferred)
        object.__setattr__(self, "other", other)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "rating", rating)
        object.__setattr__(self, "rater", _check_id(rater, "rater"))
        object.__setattr__(self, "schema", REWARD_SCHEMA)

    @property
    def is_pairwise(self) -> bool:
        return self.preferred is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "feedback_id": self.feedback_id,
            "seq": self.seq,
            "kind": "pairwise" if self.is_pairwise else "scalar",
            "rater": self.rater,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RewardPrediction:
    """The model's estimate for one action."""

    score: float
    confidence: float
    extrapolating: bool
    schema: str = REWARD_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "confidence": self.confidence,
            "extrapolating": self.extrapolating,
            "schema": self.schema,
        }


class RewardModel:
    """Linear preference model learned from human feedback.

    - ``train_step(feedback)`` applies one deterministic update:
      pairwise feedback moves weights along ``preferred - other``;
      scalar feedback applies a delta step toward the rating.
    - ``predict_reward(action)`` returns the clipped score plus a
      confidence in [0, 1] derived from per-feature feedback coverage.
      Any feature never seen in training marks the prediction as
      ``extrapolating``.

    The model is append-only in the sense that ``feedback_log()``
    returns every feedback event in seq order; weights are mutable
    state owned by the caller, not a shared store.
    """

    def __init__(self) -> None:
        self._weights: dict[str, float] = {}
        self._coverage: dict[str, int] = {}
        self._log: list[HumanFeedback] = []
        self._seqs: set[int] = set()

    # -- training --------------------------------------------------------

    def train_step(self, feedback: HumanFeedback) -> None:
        """Apply one feedback event. Rejects replays and malformed input."""
        if not isinstance(feedback, HumanFeedback):
            raise RewardError("train_step needs a HumanFeedback")
        if feedback.seq in self._seqs:
            raise RewardError(f"duplicate feedback seq: {feedback.seq}")
        if feedback.is_pairwise:
            assert feedback.preferred is not None and feedback.other is not None
            delta = _feature_diff(feedback.preferred, feedback.other)
            for name, step in delta.items():
                self._weights[name] = self._weights.get(name, 0.0) + LEARNING_RATE * step
            touched = set(delta)
        else:
            assert feedback.action is not None and feedback.rating is not None
            prediction = sum(
                self._weights.get(name, 0.0) * value
                for name, value in feedback.action.features
            )
            error = feedback.rating - prediction
            touched = set()
            for name, value in feedback.action.features:
                self._weights[name] = self._weights.get(name, 0.0) + LEARNING_RATE * error * value
                touched.add(name)
        for name in touched:
            self._coverage[name] = self._coverage.get(name, 0) + 1
        self._log.append(feedback)
        self._seqs.add(feedback.seq)

    # -- prediction ------------------------------------------------------

    def predict_reward(self, action: ActionFeatures) -> RewardPrediction:
        """Score one action. Never raises on well-typed input."""
        if not isinstance(action, ActionFeatures):
            raise RewardError("predict_reward needs an ActionFeatures")
        score = _clip(
            sum(self._weights.get(name, 0.0) * value for name, value in action.features)
        )
        extrapolating = any(name not in self._coverage for name in action.names())
        coverages = [
            self._coverage.get(name, 0) / (self._coverage.get(name, 0) + CONFIDENCE_SMOOTHING)
            for name, _ in action.features
        ]
        confidence = min(coverages) if coverages else 0.0
        return RewardPrediction(
            score=score, confidence=confidence, extrapolating=extrapolating
        )

    # -- introspection ---------------------------------------------------

    def weights(self) -> Mapping[str, float]:
        return dict(self._weights)

    def coverage(self) -> Mapping[str, int]:
        return dict(self._coverage)

    def feedback_log(self) -> tuple[HumanFeedback, ...]:
        return tuple(self._log)


def _feature_diff(
    preferred: ActionFeatures, other: ActionFeatures
) -> dict[str, float]:
    a = preferred.as_dict()
    b = other.as_dict()
    delta: dict[str, float] = {}
    for name in set(a) | set(b):
        step = a.get(name, 0.0) - b.get(name, 0.0)
        if step != 0.0:
            delta[name] = step
    return delta


@dataclass(frozen=True)
class DecompositionEstimate:
    """Recursive estimate for a (possibly composite) task."""

    task_id: str
    score: float
    confidence: float
    leaf: bool
    schema: str = REWARD_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "score": self.score,
            "confidence": self.confidence,
            "leaf": self.leaf,
            "schema": self.schema,
        }


class RecursiveRewardEstimator:
    """Estimates composite tasks from learned leaf rewards.

    The caller registers decompositions (task -> subtasks) and leaf
    rewards come from a :class:`RewardModel`. ``estimate(task_id)``
    aggregates children by mean and takes the minimum confidence —
    one unevaluated subtask taints the whole estimate. Cycles are
    rejected at registration time; unknown tasks raise.
    """

    def __init__(self, model: RewardModel) -> None:
        if not isinstance(model, RewardModel):
            raise RewardError("estimator needs a RewardModel")
        self._model = model
        self._children: dict[str, tuple[str, ...]] = {}
        self._leaf_features: dict[str, ActionFeatures] = {}

    def register_leaf(self, task_id: str, features: ActionFeatures) -> None:
        """Bind a leaf task to the features the reward model scores."""
        task_id = _check_id(task_id, "task_id")
        if not isinstance(features, ActionFeatures):
            raise RewardError("leaf needs ActionFeatures")
        if task_id in self._children or task_id in self._leaf_features:
            raise RewardError(f"task already registered: {task_id!r}")
        self._leaf_features[task_id] = features

    def register_decomposition(self, task_id: str, subtasks: Sequence[str]) -> None:
        """Register task_id as the aggregation of its subtasks."""
        task_id = _check_id(task_id, "task_id")
        subs = tuple(_check_id(s, "subtask") for s in subtasks)
        if not subs:
            raise RewardError("decomposition needs at least one subtask")
        if len(set(subs)) != len(subs):
            raise RewardError("duplicate subtasks")
        if task_id in subs:
            raise RewardError("task cannot decompose into itself")
        if task_id in self._children or task_id in self._leaf_features:
            raise RewardError(f"task already registered: {task_id!r}")
        # Cycle check against already-registered structure: a subtask must
        # not (transitively) contain task_id. Subtasks may be registered
        # later, so we check the reverse direction only over known edges.
        self._children[task_id] = subs
        if self._closes_cycle(task_id):
            del self._children[task_id]
            raise RewardError(f"decomposition would create a cycle at {task_id!r}")

    def _closes_cycle(self, root: str) -> bool:
        seen: set[str] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            for child in self._children.get(node, ()):
                if child == root:
                    return True
                stack.append(child)
        return False

    def estimate(self, task_id: str) -> DecompositionEstimate:
        """Recursive (score, confidence) estimate. Fail-closed on unknown tasks."""
        task_id = _check_id(task_id, "task_id")
        if task_id in self._leaf_features:
            prediction = self._model.predict_reward(self._leaf_features[task_id])
            return DecompositionEstimate(
                task_id=task_id,
                score=prediction.score,
                confidence=prediction.confidence,
                leaf=True,
            )
        if task_id not in self._children:
            raise RewardError(f"unknown task: {task_id!r}")
        children = [self.estimate(child) for child in self._children[task_id]]
        score = _clip(sum(child.score for child in children) / len(children))
        confidence = min(child.confidence for child in children)
        return DecompositionEstimate(
            task_id=task_id, score=score, confidence=confidence, leaf=False
        )


@dataclass(frozen=True)
class RecursionRecord:
    """One booked decomposition step: ``task_id`` aggregates ``subtasks``.

    Leaf bindings (subtask id -> :class:`ActionFeatures`) are recorded
    on the estimator, not here — the record pins the structure of the
    step only. Subtask order is the caller's declared order.
    """

    task_id: str
    subtasks: tuple[str, ...]
    schema: str = REWARD_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "subtasks": list(self.subtasks),
            "schema": self.schema,
        }


class RecursiveReward:
    """Noun-API facade for recursive reward modeling.

    Wraps a :class:`RewardModel` and a :class:`RecursiveRewardEstimator`
    behind the three verbs the spec asked for:

    - ``model()`` returns the underlying reward model — train it with
      :meth:`RewardModel.train_step` and :class:`HumanFeedback`;
    - ``recurse(task_id, subtasks, leaf_features=None)`` books one
      decomposition step: binds the given leaf subtasks to their
      :class:`ActionFeatures`, then registers ``task_id`` as their
      aggregation. Fail-closed on duplicate ids, self-decomposition,
      cycles, and leaf bindings for ids that are not subtasks of this
      step;
    - ``evaluate(task_id)`` returns the recursive
      :class:`DecompositionEstimate`. Fail-closed on unknown tasks.

    Honest scope, unchanged from the module: this is a mechanical
    preference ledger. A booked estimate is ledger truth, never an
    authorization — a high score does not permit anything; gates still
    decide. Rewards come from caller-supplied feedback and features
    (GIGO); the recursion only aggregates what it is given.
    """

    def __init__(self, model: RewardModel | None = None) -> None:
        if model is None:
            model = RewardModel()
        if not isinstance(model, RewardModel):
            raise RewardError("RecursiveReward needs a RewardModel")
        self._model = model
        self._estimator = RecursiveRewardEstimator(model)
        self._bound_leaves: set[str] = set()
        self._composites: set[str] = set()

    def model(self) -> RewardModel:
        """Return the underlying reward model (train it with HumanFeedback)."""
        return self._model

    def recurse(
        self,
        task_id: str,
        subtasks: Sequence[str],
        leaf_features: Mapping[str, ActionFeatures] | None = None,
    ) -> RecursionRecord:
        """Book one decomposition step. Returns the frozen record."""
        task_id = _check_id(task_id, "task_id")
        if isinstance(subtasks, (str, bytes)) or not isinstance(subtasks, Sequence):
            raise RewardError("subtasks must be a non-empty sequence of ids")
        subs = tuple(_check_id(s, "subtask") for s in subtasks)
        if not subs:
            raise RewardError("recurse needs at least one subtask")
        if task_id in self._composites or task_id in self._bound_leaves:
            raise RewardError(f"task already registered: {task_id!r}")
        leaf_features = leaf_features or {}
        if not isinstance(leaf_features, Mapping):
            raise RewardError("leaf_features must map subtask id to ActionFeatures")
        for sid, feats in leaf_features.items():
            sid = _check_id(sid, "leaf subtask id")
            if sid not in subs:
                raise RewardError(
                    f"leaf binding {sid!r} is not a subtask of {task_id!r}"
                )
            if not isinstance(feats, ActionFeatures):
                raise RewardError(f"leaf binding {sid!r} needs ActionFeatures")
            if sid not in self._bound_leaves:
                self._estimator.register_leaf(sid, feats)
                self._bound_leaves.add(sid)
        # Note: if this raises (duplicate subtasks, self-decomposition, a
        # cycle), the tree is untouched — any leaves bound above remain
        # legitimate standalone declarations.
        self._estimator.register_decomposition(task_id, subs)
        self._composites.add(task_id)
        return RecursionRecord(task_id=task_id, subtasks=subs)

    def evaluate(self, task_id: str) -> DecompositionEstimate:
        """Recursive (score, confidence) estimate. Fail-closed on unknown tasks."""
        return self._estimator.estimate(task_id)

    def bound_leaf_ids(self) -> tuple[str, ...]:
        """Ids currently bound to leaf features, sorted. Pure view."""
        return tuple(sorted(self._bound_leaves))

    def composite_ids(self) -> tuple[str, ...]:
        """Ids currently registered as composites, sorted. Pure view."""
        return tuple(sorted(self._composites))


def reward_audit_event(
    kind: str, task_id: str, score: float, confidence: float, seq: int
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a reward event."""
    kind = _check_id(kind, "kind")
    task_id = _check_id(task_id, "task_id")
    score = _clip(_check_finite(score, "score"))
    confidence = _check_finite(confidence, "confidence")
    if not 0.0 <= confidence <= 1.0:
        raise RewardError("confidence must be in [0, 1]")
    seq = _check_seq(seq)
    return {
        "type": "audit.ndjson/1",
        "kind": f"reward.{kind}",
        "task_id": task_id,
        "score": score,
        "confidence": confidence,
        "seq": seq,
        "module": RECURSIVE_REWARD_VERSION,
        "schema": REWARD_SCHEMA,
    }


def main() -> None:
    model = RewardModel()
    features_a = ActionFeatures({"helpful": 1.0, "risky": 0.0})
    features_b = ActionFeatures({"helpful": 0.0, "risky": 1.0})
    model.train_step(
        HumanFeedback("fb-1", 1, preferred=features_a, other=features_b)
    )
    prediction = model.predict_reward(features_a)
    assert prediction.score > 0.0, prediction
    assert not prediction.extrapolating
    estimator = RecursiveRewardEstimator(model)
    estimator.register_leaf("write-email", features_a)
    estimator.register_leaf("send-email", features_b)
    estimator.register_decomposition("handle-inbox", ("write-email", "send-email"))
    estimate = estimator.estimate("handle-inbox")
    assert not estimate.leaf
    assert estimate.confidence == min(
        estimator.estimate("write-email").confidence,
        estimator.estimate("send-email").confidence,
    )
    event = reward_audit_event("estimate", "handle-inbox", estimate.score, estimate.confidence, 2)
    assert event["kind"] == "reward.estimate"
    # Spec noun-API smoke: model / recurse / evaluate.
    facade = RecursiveReward()
    facade.model().train_step(
        HumanFeedback("fb-2", 3, preferred=features_a, other=features_b)
    )
    record = facade.recurse(
        "handle-inbox-2",
        ("write-email-2", "send-email-2"),
        {"write-email-2": features_a, "send-email-2": features_b},
    )
    assert record.task_id == "handle-inbox-2"
    assert record.subtasks == ("write-email-2", "send-email-2")
    assert facade.bound_leaf_ids() == ("send-email-2", "write-email-2")
    assert facade.composite_ids() == ("handle-inbox-2",)
    estimate2 = facade.evaluate("handle-inbox-2")
    assert not estimate2.leaf
    assert estimate2.confidence == min(
        facade.evaluate("write-email-2").confidence,
        facade.evaluate("send-email-2").confidence,
    )
    print("recursive-reward OK: preference learned, recursion aggregated, confidence min-propagated")


if __name__ == "__main__":
    main()
