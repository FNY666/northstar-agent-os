"""Scalable oversight protocol: triaging agent actions for a weaker overseer.

Research basis (second-hand):
- Scalable oversight (Amodei et al. 2016): the overseer cannot check every
  action of a stronger agent, so oversight must be allocated where it buys
  the most safety - triage, sampling, and escalation to stronger methods.
- Recursive reward modeling / iterated amplification: decompose hard
  judgments into checkable pieces.
- Debate: pit two agents against each other so a weak judge can pick the
  truthful side.
- Constitutional AI: check actions against stated principles.
- Weak-to-strong generalization: the supervisor is weaker than the
  supervisee, so "looks fine to the overseer" is not evidence of safety.

Design: :class:`OversightProtocol` triages each proposed action into one of
three verdicts. :meth:`OversightProtocol.oversee` is the dispatch-time gate;
:meth:`OversightProtocol.escalate` routes a ``needs_review`` action to the
protocol's stronger method; :meth:`OversightProtocol.review` adjudicates a
routed action once the stronger method has produced evidence.

Decision rule (fixed order, deterministic, pure):
1. deny-listed action type -> DENIED (policy, no discretion).
2. risk tier at or above ``deny_above`` -> DENIED (fail closed at the top).
3. risk score <= threshold AND agent confidence >= threshold -> APPROVED,
   with a deterministic fraction flagged ``spot_checked`` for retrospective
   review (sampling keeps auto-approved actions honest).
4. anything else -> NEEDS_REVIEW, naming the escalation method.

The risk score is the tier base (LOW 0.1 / MEDIUM 0.4 / HIGH 0.7 /
CRITICAL 0.95) plus ``(1 - confidence) * 0.2`` clipped to [0, 1]: low
confidence raises effective risk, because a confident-sounding agent that
admits uncertainty is the one case the overseer can cheaply catch.

Honest scope: triage and routing, not judgment. An APPROVED verdict means
"within the protocol's auto-approve envelope", never "the action is safe".
NEEDS_REVIEW records *where* the action was routed, not the stronger
method's verdict - the host runs debate/amplification/constitutional checks
and feeds the evidence back via :meth:`review`. A strong agent can fool a
weak overseer; this protocol prices oversight, it does not solve the
supervision gap.

No wall-clock anywhere. All time is caller-supplied integer sequence numbers.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

#: Version pin for the protocol described here.
SCALABLE_OVERSIGHT_VERSION = "scalable-oversight.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.scalable-oversight.v1"


class OversightMethod(Enum):
    """The oversight method a protocol (or an escalation) uses."""

    DIRECT = "direct"  # overseer checks the action directly
    SPOT_CHECK = "spot-check"  # retrospective sampling of approved actions
    DEBATE = "debate"  # two agents argue, a weak judge picks
    AMPLIFICATION = "amplification"  # decompose into checkable pieces
    CONSTITUTIONAL = "constitutional"  # check against stated principles


class RiskTier(Enum):
    """Ordered risk tiers for proposed actions."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Verdict(Enum):
    """The three possible outcomes of oversight."""

    APPROVED = "approved"
    DENIED = "denied"
    NEEDS_REVIEW = "needs_review"


#: Base risk score per tier; confidence shortfall adds up to 0.2 on top.
_TIER_BASE = {
    RiskTier.LOW: 0.1,
    RiskTier.MEDIUM: 0.4,
    RiskTier.HIGH: 0.7,
    RiskTier.CRITICAL: 0.95,
}


def _check_text(value: object, name: str) -> str:
    """Validate a non-empty text field."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not value.strip():
        raise ValueError(f"{name} must be non-empty")
    return value


def _check_seq(value: object, name: str) -> int:
    """Validate a sequence number: int, non-negative, not a bool."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int sequence number, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _check_unit(value: object, name: str) -> float:
    """Validate a float in [0, 1]; bools and non-numerics rejected."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number in [0, 1], got {type(value).__name__}")
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be in [0, 1], got {result}")
    return result


@dataclass(frozen=True)
class OverseenAction:
    """An action the agent proposes, as the overseer sees it.

    ``agent_confidence`` is the agent's *self-reported* confidence (0.0-1.0).
    The protocol treats it as a claim, not evidence: low confidence raises
    effective risk rather than earning trust.
    """

    action_id: str
    action_type: str
    risk_tier: RiskTier
    agent_confidence: float
    justification: str = ""

    def __post_init__(self) -> None:
        _check_text(self.action_id, "action_id")
        _check_text(self.action_type, "action_type")
        if not isinstance(self.risk_tier, RiskTier):
            raise TypeError(f"risk_tier must be a RiskTier, got {type(self.risk_tier).__name__}")
        _check_unit(self.agent_confidence, "agent_confidence")
        if not isinstance(self.justification, str):
            raise TypeError(f"justification must be a str, got {type(self.justification).__name__}")

    def risk_score(self) -> float:
        """Tier base plus confidence shortfall, clipped to [0, 1]."""
        score = _TIER_BASE[self.risk_tier] + (1.0 - self.agent_confidence) * 0.2
        return min(1.0, max(0.0, score))


@dataclass(frozen=True)
class StrongEvidence:
    """Evidence from the stronger oversight method on a routed action.

    Produced by the host after running debate / amplification / a
    constitutional check. ``supports_action`` is the method's verdict;
    ``confidence`` is how strongly it holds it.
    """

    method: OversightMethod
    supports_action: bool
    confidence: float
    summary: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.method, OversightMethod):
            raise TypeError(f"method must be an OversightMethod, got {type(self.method).__name__}")
        if not isinstance(self.supports_action, bool):
            raise TypeError(f"supports_action must be a bool, got {type(self.supports_action).__name__}")
        _check_unit(self.confidence, "confidence")
        if not isinstance(self.summary, str):
            raise TypeError(f"summary must be a str, got {type(self.summary).__name__}")


@dataclass(frozen=True)
class OversightReport:
    """The frozen record of one oversight decision."""

    action_id: str
    verdict: Verdict
    method_used: OversightMethod
    risk_score: float
    reason: str
    spot_checked: bool = False
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_text(self.action_id, "action_id")
        if not isinstance(self.verdict, Verdict):
            raise TypeError(f"verdict must be a Verdict, got {type(self.verdict).__name__}")
        if not isinstance(self.method_used, OversightMethod):
            raise TypeError(f"method_used must be an OversightMethod, got {type(self.method_used).__name__}")
        _check_unit(self.risk_score, "risk_score")
        _check_text(self.reason, "reason")
        if not isinstance(self.spot_checked, bool):
            raise TypeError(f"spot_checked must be a bool, got {type(self.spot_checked).__name__}")
        if self.schema != SCHEMA_PIN:
            raise ValueError(f"schema must be {SCHEMA_PIN!r}")

    def as_dict(self) -> dict:
        """JSON-safe mapping of this report."""
        return {
            "schema": self.schema,
            "action_id": self.action_id,
            "verdict": self.verdict.value,
            "method_used": self.method_used.value,
            "risk_score": self.risk_score,
            "reason": self.reason,
            "spot_checked": self.spot_checked,
        }


@dataclass(frozen=True)
class OversightProtocol:
    """Triage policy for a weaker overseer over a stronger agent.

    ``method`` is the primary oversight method; ``threshold`` is the
    auto-approve envelope (risk score <= threshold and confidence >=
    threshold); ``deny_above`` is the tier at or above which actions are
    denied outright; ``spot_check_rate`` is the deterministic fraction of
    approvals sampled for retrospective review; ``escalation_method`` is
    the stronger method a ``needs_review`` action is routed to;
    ``deny_list`` names action types that are always denied.
    """

    method: OversightMethod
    threshold: float
    deny_above: RiskTier = RiskTier.CRITICAL
    spot_check_rate: float = 0.05
    escalation_method: OversightMethod = OversightMethod.DEBATE
    deny_list: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.method, OversightMethod):
            raise TypeError(f"method must be an OversightMethod, got {type(self.method).__name__}")
        _check_unit(self.threshold, "threshold")
        if not isinstance(self.deny_above, RiskTier):
            raise TypeError(f"deny_above must be a RiskTier, got {type(self.deny_above).__name__}")
        _check_unit(self.spot_check_rate, "spot_check_rate")
        if not isinstance(self.escalation_method, OversightMethod):
            raise TypeError(
                f"escalation_method must be an OversightMethod, got {type(self.escalation_method).__name__}"
            )
        if not isinstance(self.deny_list, tuple):
            raise TypeError(f"deny_list must be a tuple, got {type(self.deny_list).__name__}")
        for entry in self.deny_list:
            _check_text(entry, "deny_list entry")

    def _spot_check(self, action_id: str) -> bool:
        """Deterministic sampling: digest decides, so audits are reproducible."""
        digest = hashlib.sha256(f"{SCALABLE_OVERSIGHT_VERSION}:{action_id}".encode()).digest()
        draw = int.from_bytes(digest[:8], "big") / 2**64
        return draw < self.spot_check_rate

    def oversee(self, action: OverseenAction) -> OversightReport:
        """Triage one proposed action: approved / denied / needs_review.

        Never raises on policy; raises TypeError on a non-action input
        (programming error, fail closed).
        """
        if not isinstance(action, OverseenAction):
            raise TypeError(f"action must be an OverseenAction, got {type(action).__name__}")
        score = action.risk_score()

        if action.action_type in self.deny_list:
            return OversightReport(
                action_id=action.action_id,
                verdict=Verdict.DENIED,
                method_used=self.method,
                risk_score=score,
                reason=f"deny-listed action type: {action.action_type}",
            )
        if action.risk_tier.value >= self.deny_above.value:
            return OversightReport(
                action_id=action.action_id,
                verdict=Verdict.DENIED,
                method_used=self.method,
                risk_score=score,
                reason=f"risk tier {action.risk_tier.name} at or above deny_above {self.deny_above.name}",
            )
        if score <= self.threshold and action.agent_confidence >= self.threshold:
            return OversightReport(
                action_id=action.action_id,
                verdict=Verdict.APPROVED,
                method_used=self.method,
                risk_score=score,
                reason="within auto-approve envelope",
                spot_checked=self._spot_check(action.action_id),
            )
        return OversightReport(
            action_id=action.action_id,
            verdict=Verdict.NEEDS_REVIEW,
            method_used=self.method,
            risk_score=score,
            reason=f"routed to {self.escalation_method.value} for stronger oversight",
        )

    def escalate(self, action: OverseenAction) -> OversightReport:
        """Route a needs_review action to the protocol's stronger method.

        Records the routing; the host runs the stronger method and feeds
        the evidence back via :meth:`review`.
        """
        if not isinstance(action, OverseenAction):
            raise TypeError(f"action must be an OverseenAction, got {type(action).__name__}")
        return OversightReport(
            action_id=action.action_id,
            verdict=Verdict.NEEDS_REVIEW,
            method_used=self.escalation_method,
            risk_score=action.risk_score(),
            reason=f"escalated to {self.escalation_method.value}",
        )

    def review(self, action: OverseenAction, evidence: StrongEvidence) -> OversightReport:
        """Adjudicate a routed action given the stronger method's evidence.

        Approves only when the evidence supports the action at or above
        the protocol threshold; anything else denies. Fail closed.
        """
        if not isinstance(action, OverseenAction):
            raise TypeError(f"action must be an OverseenAction, got {type(action).__name__}")
        if not isinstance(evidence, StrongEvidence):
            raise TypeError(f"evidence must be a StrongEvidence, got {type(evidence).__name__}")
        if evidence.supports_action and evidence.confidence >= self.threshold:
            verdict = Verdict.APPROVED
            reason = f"{evidence.method.value} supports action at confidence {evidence.confidence}"
        else:
            verdict = Verdict.DENIED
            reason = f"{evidence.method.value} does not support action (supports={evidence.supports_action}, confidence={evidence.confidence})"
        return OversightReport(
            action_id=action.action_id,
            verdict=verdict,
            method_used=evidence.method,
            risk_score=action.risk_score(),
            reason=reason,
        )


def oversight_audit_event(report: OversightReport, seq: int) -> dict:
    """Shape an oversight decision as an audit.ndjson/1-style record."""
    if not isinstance(report, OversightReport):
        raise TypeError(f"report must be an OversightReport, got {type(report).__name__}")
    _check_seq(seq, "seq")
    event = report.as_dict()
    event["audit_seq"] = seq
    event["event"] = "oversight-decision"
    return event


def main() -> None:
    """Self-check: triage one of each verdict and a full escalate/review cycle."""
    protocol = OversightProtocol(
        method=OversightMethod.DIRECT,
        threshold=0.5,
        deny_list=("rm -rf /",),
    )
    low = OverseenAction("a1", "newsletter.send", RiskTier.LOW, 0.95)
    high = OverseenAction("a2", "db.migrate", RiskTier.HIGH, 0.4)
    banned = OverseenAction("a3", "rm -rf /", RiskTier.CRITICAL, 1.0)

    r1 = protocol.oversee(low)
    assert r1.verdict is Verdict.APPROVED, r1
    r2 = protocol.oversee(high)
    assert r2.verdict is Verdict.NEEDS_REVIEW, r2
    r3 = protocol.oversee(banned)
    assert r3.verdict is Verdict.DENIED, r3

    routed = protocol.escalate(high)
    assert routed.verdict is Verdict.NEEDS_REVIEW
    assert routed.method_used is OversightMethod.DEBATE
    final = protocol.review(high, StrongEvidence(OversightMethod.DEBATE, True, 0.8))
    assert final.verdict is Verdict.APPROVED, final
    final2 = protocol.review(high, StrongEvidence(OversightMethod.DEBATE, False, 0.9))
    assert final2.verdict is Verdict.DENIED, final2

    print("scalable-oversight OK: approve / route / escalate / review")


if __name__ == "__main__":
    main()
