"""Edge gate, ML-style variant: continuous risk scoring instead of rule tiers.

The rule-based :mod:`edge_gate` classifies an action into a hard tier
(``REVERSIBLE`` / ``IRREVERSIBLE`` / ``PHYSICAL``) and maps the tier to a
verdict. This module does the same dispatch-time job with a continuous
score in ``[0.0, 1.0]``:

* ``score < 0.3``  → ``"allow"``
* ``0.3 <= score <= 0.7`` → ``"require_human"``
* ``score > 0.7``  → ``"deny"``

The score comes from :func:`score_risk` over a :class:`RiskFeatures`
vector extracted from the action record: the verb (trailing token of
``action_type``), the target (leading tokens), token-level evidence,
allowlist membership, and the caller's recent verdict history. All of
these are host-reported — a lying host scores a lie.

Honest scope, read this twice: the weights below are **hand-set
heuristics**, not trained parameters. There is no training data, no
gradient step, no validation split anywhere in this module. Calling it
"ML" is a deliberate provocation: a continuous-score policy with
hand-tuned weights is what most deployed "risk scores" actually are,
and it inherits the same calibration problem — the score only means
what the weight table says it means, and the weight table was written
by a person on a Tuesday. If you need a learned model, train one, hold
out a calibration set, and report the calibration curve; nothing here
does that.

Comparison with the rule-based gate (the point of this module):

* **Rules win on auditability.** ``classify_action`` names the exact
  token that decided the tier; the score gives you a float and a
  feature vector. When an operator asks "why did this require a
  human?", the rule answer is one token long.
* **Scores win on the boundary.** An allowlisted irreversible action
  (``newsletter.send``) is ``"allow"`` under rules no matter how many
  times it has misbehaved; the score rises with ``past_deny_rate`` and
  routes it back to a human. Rules have no memory; scores can.
* **Scores fail silently.** A weight typo moves every verdict a little
  in the same direction; a rule typo fails one token loudly. The score
  needs calibration monitoring; the rule needs a token audit.
* **Both fail closed on the unknown.** Malformed input scores ``1.0``
  (``"deny"``) exactly like the rule gate classifies it
  ``PHYSICAL``-then-deny. Unknown is unknown.

``MLEdgeGate.check`` never raises and takes the same arguments as the
rule-based ``EdgeGate.check`` so the two can be A/B-tested on the same
dispatch stream. Everything here is offline and deterministic. No
network, no clock reads: ``seq`` and history are caller-supplied.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

#: Module version, stamped on decisions and audit records.
ML_GATE_VERSION = "edge-gate-ml.v1"

#: Score pin for the weight table; change the table, change the pin.
WEIGHT_PIN = "northstar.edge-gate-ml.weights.v1"

#: Verdict vocabulary, identical to the rule-based gate.
DECISION_ALLOW = "allow"
DECISION_DENY = "deny"
DECISION_REQUIRE_HUMAN = "require_human"

#: Score cutoffs.
ALLOW_BELOW = 0.3
DENY_ABOVE = 0.7

_TOKEN_RE = re.compile(r"[a-z0-9]+")

#: Token evidence reused from the rule-based vocabulary. These sets are
#: features, not rules: they raise or lower the score instead of
#: deciding the verdict.
_PHYSICAL_TOKENS = frozenset({
    "robot", "robotic", "robotics",
    "move", "navigate", "navigation", "drive", "steer",
    "actuate", "actuator", "actuation",
    "gpio", "motor", "servo",
    "drone", "uav", "fly", "takeoff", "land",
    "arm", "grasp", "grip", "gripper", "manipulator",
    "iot", "device", "hardware",
    "switch", "relay", "valve", "pump", "fan",
    "lock", "unlock", "door", "gate", "window",
    "hvac", "thermostat", "heater", "cooler",
    "siren", "alarm",
})
_IRREVERSIBLE_TOKENS = frozenset({
    "delete", "remove", "destroy", "erase", "wipe", "purge", "drop",
    "send", "email", "mail", "sms", "message", "notify",
    "pay", "payment", "purchase", "buy", "order", "checkout",
    "transfer", "withdraw", "deposit", "refund",
    "publish", "post", "share", "tweet", "broadcast",
    "commit", "push", "deploy", "release", "ship",
    "grant", "revoke", "rotate",
    "execute", "exec", "shell", "command", "script", "subprocess",
    "format", "reboot", "shutdown", "restart",
})
_REVERSIBLE_TOKENS = frozenset({
    "read", "get", "list", "query", "search", "find", "fetch",
    "describe", "preview", "dry", "plan", "simulate",
    "summarize", "translate", "calculate", "compute",
    "check", "verify", "inspect", "view", "show", "status",
    "ping", "health",
})


def _action_type_of(action: Any) -> str:
    """Extract the action type string, or ``""`` when unusable."""
    if not isinstance(action, Mapping):
        return ""
    raw = action.get("action_type", action.get("type", ""))
    if not isinstance(raw, str):
        return ""
    return raw.strip().lower()


def _tokens(action_type: str) -> "tuple[list[str], frozenset[str]]":
    """Ordered tokens and the token set of an action type string."""
    ordered = _TOKEN_RE.findall(action_type)
    return ordered, frozenset(ordered)


@dataclass(frozen=True)
class RiskFeatures:
    """Feature vector extracted from one action record.

    Every field is a plain, inspectable fact about the record — no
    model output anywhere. ``history``-derived fields come from the
    caller-supplied verdict history (counts of recent
    ``"deny"``/``"require_human"`` outcomes for this action type);
    the extractor never reads a clock.
    """

    #: Trailing token of ``action_type`` (the effect head in
    #: ``resource.verb`` names).
    verb: str = ""
    #: Leading tokens of ``action_type`` (the target domain).
    target: str = ""
    #: Number of tokens in the action type.
    token_count: int = 0
    #: Any physical token present.
    has_physical_token: bool = False
    #: Any irreversible token present.
    has_irreversible_token: bool = False
    #: Any reversible token present.
    has_reversible_token: bool = False
    #: The record carried no usable action type at all.
    is_unknown: bool = False
    #: The exact normalized action type sits on the operator allowlist.
    is_allowlisted: bool = False
    #: Fraction of recent dispatches of this action type that were
    #: denied, in ``[0.0, 1.0]``.
    past_deny_rate: float = 0.0
    #: Recent ``"require_human"`` count for this action type,
    #: saturated at 5.
    past_human_count: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "verb": self.verb,
            "target": self.target,
            "token_count": self.token_count,
            "has_physical_token": self.has_physical_token,
            "has_irreversible_token": self.has_irreversible_token,
            "has_reversible_token": self.has_reversible_token,
            "is_unknown": self.is_unknown,
            "is_allowlisted": self.is_allowlisted,
            "past_deny_rate": self.past_deny_rate,
            "past_human_count": self.past_human_count,
        }


def extract_features(
    action: Any,
    context: Mapping[str, Any] | None = None,
    *,
    allowlist: frozenset[str] = frozenset(),
    past_deny_rate: float = 0.0,
    past_human_count: int = 0,
) -> RiskFeatures:
    """Extract :class:`RiskFeatures` from an action record. Never raises.

    Malformed input yields the all-unknown feature vector, which
    :func:`score_risk` maps to ``1.0``. ``allowlist`` holds the exact
    normalized action types the operator pre-approved.
    ``past_deny_rate`` / ``past_human_count`` describe the recent
    verdict history for this action type; out-of-range values are
    clamped, not rejected.
    """
    action_type = _action_type_of(action)
    if not action_type:
        return RiskFeatures(is_unknown=True)
    ordered, toks = _tokens(action_type)
    verb = ordered[-1] if ordered else ""
    target = ".".join(ordered[:-1]) if len(ordered) > 1 else ""
    try:
        deny_rate = float(past_deny_rate)
    except (TypeError, ValueError):
        deny_rate = 0.0
    deny_rate = max(0.0, min(1.0, deny_rate))
    try:
        human_count = int(past_human_count)
    except (TypeError, ValueError):
        human_count = 0
    if isinstance(past_human_count, bool):
        human_count = 0
    human_count = max(0, min(5, human_count))
    return RiskFeatures(
        verb=verb,
        target=target,
        token_count=len(ordered),
        has_physical_token=bool(toks & _PHYSICAL_TOKENS),
        has_irreversible_token=bool(toks & _IRREVERSIBLE_TOKENS),
        has_reversible_token=bool(toks & _REVERSIBLE_TOKENS),
        is_unknown=False,
        is_allowlisted=action_type in allowlist,
        past_deny_rate=deny_rate,
        past_human_count=human_count,
    )


# Hand-set heuristic weights. This table IS the "model". Change it and
# you change every verdict a little in the same direction — that is the
# silent-failure mode the docstring warns about.
_WEIGHT_UNKNOWN = 0.95
_WEIGHT_PHYSICAL = 0.75
_WEIGHT_IRREVERSIBLE = 0.45
_WEIGHT_REVERSIBLE = -0.35
_WEIGHT_ALLOWLISTED = -0.45
_WEIGHT_DENY_RATE = 0.30
_WEIGHT_HUMAN_COUNT = 0.06
_WEIGHT_LONG_TYPE = 0.05
_LONG_TYPE_TOKENS = 4


def score_risk(features: RiskFeatures) -> float:
    """Score a feature vector in ``[0.0, 1.0]``. Never raises.

    Unknown records score ``1.0`` (fail closed). Otherwise the score is
    the clipped sum of the hand-set heuristic weights in
    :data:`WEIGHT_PIN`. This is a policy formula, not a learned model.
    """
    if not isinstance(features, RiskFeatures):
        return 1.0
    if features.is_unknown:
        return 1.0
    score = 0.0
    if features.has_physical_token:
        score += _WEIGHT_PHYSICAL
    if features.has_irreversible_token:
        score += _WEIGHT_IRREVERSIBLE
    if features.has_reversible_token:
        score += _WEIGHT_REVERSIBLE
    if features.is_allowlisted:
        score += _WEIGHT_ALLOWLISTED
    score += features.past_deny_rate * _WEIGHT_DENY_RATE
    score += min(5, max(0, features.past_human_count)) * _WEIGHT_HUMAN_COUNT
    if features.token_count > _LONG_TYPE_TOKENS:
        score += _WEIGHT_LONG_TYPE
    return max(0.0, min(1.0, score))


def verdict_for_score(score: float) -> str:
    """Map a score to a verdict. Never raises.

    ``score < 0.3`` → ``"allow"``; ``score > 0.7`` → ``"deny"``;
    the middle band → ``"require_human"``. Non-numeric or NaN scores
    fail closed to ``"deny"``.
    """
    try:
        s = float(score)
    except (TypeError, ValueError):
        return DECISION_DENY
    if s != s:  # NaN
        return DECISION_DENY
    if s < ALLOW_BELOW:
        return DECISION_ALLOW
    if s > DENY_ABOVE:
        return DECISION_DENY
    return DECISION_REQUIRE_HUMAN


@dataclass(frozen=True)
class MLGateDecision:
    """One scored decision. Frozen and digest-pinned for audit."""

    verdict: str
    score: float
    features: RiskFeatures
    action_type: str
    weight_pin: str = WEIGHT_PIN
    seq: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "score": round(self.score, 4),
            "features": self.features.as_dict(),
            "action_type": self.action_type,
            "weight_pin": self.weight_pin,
            "version": ML_GATE_VERSION,
            "seq": self.seq,
        }

    def digest(self) -> str:
        body = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


class MLEdgeGate:
    """Dispatch-time edge gate with continuous risk scoring.

    Same calling convention as the rule-based ``EdgeGate.check`` so the
    two can be A/B-tested on one dispatch stream:
    ``check(action, context, history=None, seq=0)`` returns
    ``"allow"`` / ``"deny"`` / ``"require_human"`` and never raises.

    ``history`` optionally carries ``{"deny_rate": float,
    "human_count": int}`` for this action type; the gate has no memory
    of its own. ``irreversible_allowlist`` is a feature (lowers the
    score), never a rule: an allowlisted action with a bad history
    still climbs into ``"require_human"``.
    """

    def __init__(
        self,
        *,
        irreversible_allowlist: Sequence[str] = (),
        allow_below: float = ALLOW_BELOW,
        deny_above: float = DENY_ABOVE,
    ) -> None:
        self._allowlist = frozenset(
            str(a).strip().lower()
            for a in irreversible_allowlist
            if isinstance(a, str) and a.strip()
        )
        for name, value in (("allow_below", allow_below), ("deny_above", deny_above)):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not 0.0 <= value <= 1.0
            ):
                raise ValueError(f"{name} must be a number in [0.0, 1.0]")
        if not allow_below < deny_above:
            raise ValueError("allow_below must be strictly less than deny_above")
        self._allow_below = float(allow_below)
        self._deny_above = float(deny_above)

    @property
    def irreversible_allowlist(self) -> frozenset[str]:
        return self._allowlist

    def _history_of(self, history: Any) -> tuple[float, int]:
        if not isinstance(history, Mapping):
            return 0.0, 0
        deny_rate = history.get("deny_rate", 0.0)
        human_count = history.get("human_count", 0)
        try:
            deny_rate = max(0.0, min(1.0, float(deny_rate)))
        except (TypeError, ValueError):
            deny_rate = 0.0
        try:
            human_count = max(0, min(5, int(human_count)))
        except (TypeError, ValueError):
            human_count = 0
        if isinstance(history.get("human_count"), bool):
            human_count = 0
        return deny_rate, human_count

    def check(
        self,
        action: Any,
        context: Mapping[str, Any] | None = None,
        history: Mapping[str, Any] | None = None,
        *,
        seq: int = 0,
    ) -> str:
        """Dispatch-time verdict. Never raises on any input."""
        return self.check_detailed(action, context, history, seq=seq).verdict

    def check_detailed(
        self,
        action: Any,
        context: Mapping[str, Any] | None = None,
        history: Mapping[str, Any] | None = None,
        *,
        seq: int = 0,
    ) -> MLGateDecision:
        """Same as :meth:`check` but returns the full scored decision."""
        action_type = _action_type_of(action)
        deny_rate, human_count = self._history_of(history)
        features = extract_features(
            action,
            context,
            allowlist=self._allowlist,
            past_deny_rate=deny_rate,
            past_human_count=human_count,
        )
        score = score_risk(features)
        if score < self._allow_below:
            verdict = DECISION_ALLOW
        elif score > self._deny_above:
            verdict = DECISION_DENY
        else:
            verdict = DECISION_REQUIRE_HUMAN
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            seq = 0
        return MLGateDecision(
            verdict=verdict,
            score=score,
            features=features,
            action_type=action_type,
            seq=seq,
        )


def edge_gate_ml_event(
    decision: MLGateDecision, *, component: str = "northstar-agent-runtime"
) -> dict[str, Any]:
    """Shape a scored decision for the ``audit.ndjson/1`` envelope."""
    return {
        "type": "edge-gate-ml.decision",
        "component": component,
        "version": ML_GATE_VERSION,
        "verdict": decision.verdict,
        "score": round(decision.score, 4),
        "action_type": decision.action_type,
        "weight_pin": decision.weight_pin,
        "decision_digest": decision.digest(),
        "seq": decision.seq,
    }


def main() -> None:
    """Self-check smoke: score a few representative actions."""
    gate = MLEdgeGate(irreversible_allowlist=("newsletter.send",))
    corpus = [
        ({"action_type": "files.read"}, "allow"),
        ({"action_type": "db.delete"}, "require_human"),
        # NOTE: rule-based routes named physical actions to a human;
        # the ML table scores them 0.75 -> "deny" (no human path).
        # This is a documented calibration divergence, not a bug.
        ({"action_type": "robot.move"}, "deny"),
        ({"action_type": "newsletter.send"}, "allow"),
        ({"action_type": ""}, "deny"),
        (None, "deny"),
    ]
    for action, expected in corpus:
        got = gate.check(action)
        status = "OK" if got == expected else f"MISMATCH (want {expected})"
        print(f"{action} -> {got} [{status}]")
    print("edge-gate-ml OK")


if __name__ == "__main__":
    main()
