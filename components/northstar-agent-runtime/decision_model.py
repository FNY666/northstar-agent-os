"""Structured decision-model approval path (SystemOne-style).

Absorbs the *interface idea* of the October-2026 "decision model" wave --
Cloudflare Clef / Clef-flash (Apache-2.0), AWS Strands Decider 2B
(Apache-2.0), TypeSafe Jev's SystemOne API -- not their weights, code, or
benchmarks:

- input: a JSON ``state`` (call context + risk features) plus a schema of
  *typed questions* (``noul`` / ``choice`` / ``score``);
- output: per-question answers as *options + probabilities*, in a single
  pass, with no free-form text generation and nothing to parse;
- a local threshold policy turns the probabilities into
  ``allow`` / ``deny`` / ``escalate``; the whole input -> output -> verdict
  chain is written to the audit record, so the decision is inspectable
  without re-running any model.

Vendor latency/accuracy claims (Clef-flash "38.8 ms", Strands Decider
"115 ms", "beats Jev") are vendor-reported and have NOT been independently
verified; this module absorbs only the format, which is the part that makes
a gate decision auditable.

Fail-closed by construction:

- no model configured -> the existing deterministic gate path, unchanged;
- the model raises -> fall through to the existing host-callback path;
- confidence below threshold -> escalate, never allow;
- malformed probabilities -> escalate, never allow;
- a model-path approval still binds to (``call_id``, ``arguments_digest``)
  via ``PermissionRequestContext`` -- nothing replays.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

QuestionType = Literal["noul", "choice", "score"]

QUESTION_TYPES: tuple[QuestionType, ...] = ("noul", "choice", "score")

DecisionOutcome = Literal["allow", "deny", "escalate"]


@dataclass(frozen=True)
class DecisionQuestion:
    """One typed question in the decision schema.

    ``noul``: yes/no -- answer is ``P(yes)``.
    ``choice``: pick one named option -- answer is per-option probabilities
    plus the argmax choice and its confidence.
    ``score``: rate on an ordered rubric -- answer is per-level
    probabilities plus the probability-weighted expected score.
    """

    name: str
    type: QuestionType
    instructions: str = ""
    criteria: dict[str, str] = field(default_factory=dict)
    legend: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("question name must be non-empty")
        if self.type not in QUESTION_TYPES:
            raise ValueError(f"unknown question type {self.type!r}")
        if self.type == "choice" and len(self.criteria) < 2:
            raise ValueError("choice questions need at least 2 options")
        if self.type == "score" and len(self.legend) < 2:
            raise ValueError("score questions need at least 2 ordered levels")
        if self.type == "noul" and (self.criteria or self.legend):
            raise ValueError("noul questions take no criteria or legend")

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "type": self.type,
            "instructions": self.instructions,
        }
        if self.criteria:
            payload["criteria"] = dict(self.criteria)
        if self.legend:
            payload["legend"] = list(self.legend)
        return payload


@dataclass(frozen=True)
class QuestionAnswer:
    """The model's answer to one question: options + probabilities."""

    name: str
    type: QuestionType
    probabilities: dict[str, float]
    choice: str | None = None
    confidence: float = 0.0
    expected_score: float | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "type": self.type,
            "probabilities": dict(self.probabilities),
            "confidence": self.confidence,
        }
        if self.choice is not None:
            payload["choice"] = self.choice
        if self.expected_score is not None:
            payload["expected_score"] = self.expected_score
        return payload


@dataclass(frozen=True)
class DecisionModelResult:
    """Everything a decision model returns for one state + schema."""

    answers: dict[str, QuestionAnswer]
    model: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "answers": {name: answer.as_dict() for name, answer in self.answers.items()},
        }


class DecisionModel(Protocol):
    """Host-pluggable decision model (Clef / Strands Decider / local).

    ``decide`` receives the JSON state and the typed question schema and
    returns options + probabilities. It must not raise for well-formed
    input; the gate treats any exception as "escalate" and falls back to
    the host callback path.
    """

    model_name: str

    def decide(
        self,
        state: dict[str, Any],
        questions: dict[str, DecisionQuestion],
    ) -> DecisionModelResult: ...


def build_decision_state(
    tool_name: str,
    *,
    kind: str,
    mutating: bool,
    context: Any,
    payload_digest: str = "",
) -> dict[str, Any]:
    """Build the JSON state a decision model sees for one gated call.

    Only the arguments *digest* travels, never the raw arguments -- the
    model decides on identity + risk features, not on secret payload bytes.
    """
    features = {
        "is_mutating": bool(mutating),
        "is_network": kind == "network",
        "is_exec": kind == "exec",
        "is_edit": kind == "edit",
        "delegation_depth": int(getattr(context, "depth", 0) or 0),
        "turn_index": int(getattr(context, "turn_index", 0) or 0),
        "mode": str(getattr(context, "mode", "") or ""),
    }
    return {
        "tool": tool_name,
        "kind": kind,
        "mutating": bool(mutating),
        "call_id": str(getattr(context, "call_id", "") or ""),
        "arguments_digest": payload_digest
        or str(getattr(context, "arguments_digest", "") or ""),
        "session_id": str(getattr(context, "session_id", "") or ""),
        "agent": str(getattr(context, "agent", "") or ""),
        "features": features,
    }


def approval_questions() -> dict[str, DecisionQuestion]:
    """The canonical question schema the gate asks a decision model."""
    return {
        "approval": DecisionQuestion(
            name="approval",
            type="noul",
            instructions=(
                "Should this tool call be approved? Answer yes only if the "
                "call is safe and within policy."
            ),
        ),
        "verdict": DecisionQuestion(
            name="verdict",
            type="choice",
            instructions="Adjudicate this tool call.",
            criteria={
                "allow": "The call is safe; approve it.",
                "deny": "The call is unsafe or out of policy; refuse it.",
                "escalate": "Uncertain; defer to the host approval callback.",
            },
        ),
    }


@dataclass(frozen=True)
class DecisionPolicy:
    """Thresholds turning model probabilities into a gate outcome."""

    approve_threshold: float = 0.80
    deny_threshold: float = 0.20
    min_confidence: float = 0.60

    def __post_init__(self) -> None:
        for label, value in (
            ("approve_threshold", self.approve_threshold),
            ("deny_threshold", self.deny_threshold),
            ("min_confidence", self.min_confidence),
        ):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{label} must be within [0, 1], got {value!r}")
        if not self.deny_threshold < self.approve_threshold:
            raise ValueError(
                "deny_threshold must be strictly below approve_threshold "
                f"(got {self.deny_threshold!r} / {self.approve_threshold!r})"
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "approve_threshold": self.approve_threshold,
            "deny_threshold": self.deny_threshold,
            "min_confidence": self.min_confidence,
        }


def _check_probabilities(probabilities: dict[str, float], options: tuple[str, ...]) -> str | None:
    """Return an error string when a distribution is malformed, else None."""
    if set(probabilities) != set(options):
        return f"probabilities cover {sorted(probabilities)} but options are {list(options)}"
    total = 0.0
    for option, prob in probabilities.items():
        if not isinstance(prob, (int, float)) or prob < 0.0 or prob > 1.0:
            return f"probability for {option!r} is not within [0, 1]: {prob!r}"
        total += float(prob)
    if abs(total - 1.0) > 1e-6:
        return f"probabilities sum to {total}, not 1.0"
    return None


def adjudicate(
    result: DecisionModelResult, policy: DecisionPolicy
) -> tuple[DecisionOutcome, str]:
    """Turn options + probabilities into allow / deny / escalate.

    The ``verdict`` choice question wins when present; the ``approval``
    noul question is the fallback. Anything malformed escalates -- the
    gate never allows on a distribution it cannot read.
    """
    verdict = result.answers.get("verdict")
    if verdict is not None and verdict.type == "choice":
        options = ("allow", "deny", "escalate")
        problem = _check_probabilities(verdict.probabilities, options)
        if problem is not None:
            return "escalate", f"malformed verdict probabilities ({problem}); escalating"
        top = max(options, key=lambda option: verdict.probabilities[option])
        confidence = verdict.probabilities[top]
        if confidence < policy.min_confidence:
            return (
                "escalate",
                f"top option {top!r} confidence {confidence:.3f} below "
                f"min_confidence {policy.min_confidence:.2f}; escalating",
            )
        if top == "allow":
            return "allow", f"model verdict allow at confidence {confidence:.3f}"
        if top == "deny":
            return "deny", f"model verdict deny at confidence {confidence:.3f}"
        return "escalate", f"model verdict escalate at confidence {confidence:.3f}"
    approval = result.answers.get("approval")
    if approval is not None and approval.type == "noul":
        yes = approval.probabilities.get("yes")
        if not isinstance(yes, (int, float)) or not 0.0 <= yes <= 1.0:
            return "escalate", "malformed approval probability; escalating"
        if yes >= policy.approve_threshold:
            return "allow", f"P(approve)={yes:.3f} >= {policy.approve_threshold:.2f}"
        if yes <= policy.deny_threshold:
            return "deny", f"P(approve)={yes:.3f} <= {policy.deny_threshold:.2f}"
        return (
            "escalate",
            f"P(approve)={yes:.3f} between thresholds; escalating",
        )
    return "escalate", "no usable answer from the model; escalating"


@dataclass(frozen=True)
class StaticDecisionModel:
    """Deterministic reference model: fixed answers keyed by tool or kind.

    ``profiles`` maps ``"tool:<name>"`` / ``"kind:<kind>"`` keys to answer
    specs of the form
    ``{"verdict": {"allow": p, "deny": p, "escalate": p}, "approval": p_yes}``;
    tool keys win over kind keys, ``default`` covers the rest. Every lookup
    is a pure table read, so bench and tests are fully deterministic with
    no weights and no network.
    """

    profiles: dict[str, dict[str, Any]] = field(default_factory=dict)
    default: dict[str, Any] = field(default_factory=dict)
    model_name: str = "northstar.static-decision-model.v1"

    def decide(
        self,
        state: dict[str, Any],
        questions: dict[str, DecisionQuestion],
    ) -> DecisionModelResult:
        spec = self.profiles.get(f"tool:{state.get('tool', '')}")
        if spec is None:
            spec = self.profiles.get(f"kind:{state.get('kind', '')}")
        if spec is None:
            spec = self.default
        answers: dict[str, QuestionAnswer] = {}
        for name, question in questions.items():
            if question.type == "choice":
                dist = dict(spec.get(name, {}))
                options = tuple(question.criteria)
                problem = _check_probabilities(dist, options)
                if problem is not None:
                    raise ValueError(f"static profile for {name!r}: {problem}")
                top = max(options, key=lambda option: dist[option])
                answers[name] = QuestionAnswer(
                    name=name,
                    type="choice",
                    probabilities={option: float(dist[option]) for option in options},
                    choice=top,
                    confidence=float(dist[top]),
                )
            elif question.type == "noul":
                yes = spec.get(name, 0.5)
                if not isinstance(yes, (int, float)) or not 0.0 <= yes <= 1.0:
                    raise ValueError(f"static profile for {name!r}: bad P(yes) {yes!r}")
                answers[name] = QuestionAnswer(
                    name=name,
                    type="noul",
                    probabilities={"yes": float(yes), "no": 1.0 - float(yes)},
                    confidence=float(yes),
                )
            elif question.type == "score":
                levels = question.legend
                per = 1.0 / len(levels)
                answers[name] = QuestionAnswer(
                    name=name,
                    type="score",
                    probabilities={level: per for level in levels},
                    confidence=per,
                    expected_score=sum(index * per for index in range(len(levels))),
                )
            else:  # pragma: no cover - DecisionQuestion validates the type
                raise ValueError(f"unsupported question type {question.type!r}")
        return DecisionModelResult(answers=answers, model=self.model_name)


def build_decision_audit(
    *,
    state: dict[str, Any],
    questions: dict[str, DecisionQuestion],
    result: DecisionModelResult,
    policy: DecisionPolicy,
    outcome: DecisionOutcome,
    reason: str,
    model_error: str | None = None,
) -> dict[str, Any]:
    """The full input -> output -> verdict chain, ready for the audit feed."""
    payload: dict[str, Any] = {
        "type": "decision_model",
        "model": result.model or "unknown",
        "input": {
            "state": state,
            "questions": {name: question.as_dict() for name, question in questions.items()},
        },
        "output": result.as_dict(),
        "policy": policy.as_dict(),
        "outcome": outcome,
        "reason": reason,
    }
    if model_error is not None:
        payload["model_error"] = model_error
    return payload


__all__ = [
    "QUESTION_TYPES",
    "DecisionModel",
    "DecisionModelResult",
    "DecisionOutcome",
    "DecisionPolicy",
    "DecisionQuestion",
    "QuestionAnswer",
    "QuestionType",
    "StaticDecisionModel",
    "adjudicate",
    "approval_questions",
    "build_decision_audit",
    "build_decision_state",
]
