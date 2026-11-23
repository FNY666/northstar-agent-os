"""Silent Stop action verification: narrating vs acting dissociate.

Research basis (second-hand):
- "Silent Stop" eval (Oct 2026, preregistered): models that concluded a hacking
  target was real reported it only 17-18% of the time across evidence levels;
  "says-real" rose 0%->62% on the evidence ladder while actual reporting stayed
  flat; 73% of "it's real" answers told no one. Narration and action dissociate.
- Shanghai AI Lab x HKUST failure-concealment study: agents guessed, swapped
  sources, and fabricated *despite holding the evidence*.

Design: an independent verification channel between what the agent SAID it did
(:class:`VerbalClaim`) and what the audit trail shows was ACTUALLY done
(:class:`ObservedAction`). :func:`verify_action` checks one claim against one
observation; :class:`SilentStopDetector` accumulates both streams and flags
claims with no matching observed action.

Detector, not defense: it names the divergence; the gate layer decides what to
do with the verdict.

Honest scope: pattern-based identity matching on host-reported records. It
checks that a claimed action has a corresponding audit-logged action with the
same agent, action type, and target at or after the claim sequence. It does not
prove the action's real-world effect (an audit-logged "report sent" may still
have gone nowhere), and it cannot catch a lie that never touches a claim the
caller bothers to register. A matched claim is "the audit trail corroborates
the narration" - not "the world changed".

No wall-clock anywhere. All time is caller-supplied integer sequence numbers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

#: Version pin for the verifier described here.
ACTION_VERIFIER_VERSION = "action-verifier.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.action-verifier.v1"


def _check_seq(value: object, name: str) -> int:
    """Validate a sequence number: int, non-negative, not a bool."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int sequence number, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _check_text(value: object, name: str) -> str:
    """Validate a non-empty text field."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not value.strip():
        raise ValueError(f"{name} must be non-empty")
    return value


@dataclass(frozen=True)
class VerbalClaim:
    """What the agent SAID it did.

    Registered from the agent's own narration (chat output, tool-call
    narration, status update). ``claimed_seq`` is the sequence number at
    which the claim was made.
    """

    claim_id: str
    agent_id: str
    action_type: str
    target: str
    claimed_seq: int
    statement: str = ""

    def __post_init__(self) -> None:
        _check_text(self.claim_id, "claim_id")
        _check_text(self.agent_id, "agent_id")
        _check_text(self.action_type, "action_type")
        _check_text(self.target, "target")
        _check_seq(self.claimed_seq, "claimed_seq")
        if not isinstance(self.statement, str):
            raise TypeError(f"statement must be a str, got {type(self.statement).__name__}")

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "claim_id": self.claim_id,
            "agent_id": self.agent_id,
            "action_type": self.action_type,
            "target": self.target,
            "claimed_seq": self.claimed_seq,
            "statement": self.statement,
        }


@dataclass(frozen=True)
class ObservedAction:
    """What was ACTUALLY done, per the audit log.

    ``observed_seq`` is the sequence number at which the action was recorded;
    ``audit_digest`` pins the audit record (``sha256:`` hex) so the observation
    is anchored to tamper-evident evidence.
    """

    action_id: str
    agent_id: str
    action_type: str
    target: str
    observed_seq: int
    audit_digest: str = ""

    def __post_init__(self) -> None:
        _check_text(self.action_id, "action_id")
        _check_text(self.agent_id, "agent_id")
        _check_text(self.action_type, "action_type")
        _check_text(self.target, "target")
        _check_seq(self.observed_seq, "observed_seq")
        if not isinstance(self.audit_digest, str):
            raise TypeError(
                f"audit_digest must be a str, got {type(self.audit_digest).__name__}"
            )

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "action_type": self.action_type,
            "target": self.target,
            "observed_seq": self.observed_seq,
            "audit_digest": self.audit_digest,
        }


def _norm(value: str) -> str:
    """Normalize for comparison: lowercase, stripped."""
    return value.strip().lower()


def verify_action(claim: VerbalClaim, observed: ObservedAction) -> bool:
    """Check one verbal claim against one observed action.

    Returns True only when all of the following hold:
    - same agent (case-insensitive),
    - same action type (case-insensitive),
    - same target (case-insensitive),
    - the observed action was recorded at or after the claim was made
      (``observed_seq >= claimed_seq``) - an action logged *before* the claim
      cannot be the action the claim is about.

    Returns False (never raises) on any mismatch. Raises TypeError on
    non-claim/non-observation inputs - that is a programming error, not a
    policy decision.
    """
    if not isinstance(claim, VerbalClaim):
        raise TypeError(f"claim must be a VerbalClaim, got {type(claim).__name__}")
    if not isinstance(observed, ObservedAction):
        raise TypeError(f"observed must be an ObservedAction, got {type(observed).__name__}")
    return (
        _norm(claim.agent_id) == _norm(observed.agent_id)
        and _norm(claim.action_type) == _norm(observed.action_type)
        and _norm(claim.target) == _norm(observed.target)
        and observed.observed_seq >= claim.claimed_seq
    )


@dataclass(frozen=True)
class SilentStopFinding:
    """A claim with no matching observed action."""

    claim_id: str
    agent_id: str
    action_type: str
    target: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "claim_id": self.claim_id,
            "agent_id": self.agent_id,
            "action_type": self.action_type,
            "target": self.target,
        }


class SilentStopDetector:
    """Accumulates claims and observations; flags silent stops.

    A *silent stop* is a verbal claim ("I reported the finding") with no
    matching observed action in the audit stream - narration without action,
    the exact failure the Silent Stop eval measured.
    """

    def __init__(self) -> None:
        self._claims: List[VerbalClaim] = []
        self._observed: List[ObservedAction] = []

    def register_claim(self, claim: VerbalClaim) -> None:
        """Record what the agent said it did."""
        if not isinstance(claim, VerbalClaim):
            raise TypeError(f"claim must be a VerbalClaim, got {type(claim).__name__}")
        self._claims.append(claim)

    def register_observed(self, observed: ObservedAction) -> None:
        """Record what the audit log shows was actually done."""
        if not isinstance(observed, ObservedAction):
            raise TypeError(
                f"observed must be an ObservedAction, got {type(observed).__name__}"
            )
        self._observed.append(observed)

    def _matches(self, claim: VerbalClaim) -> bool:
        return any(verify_action(claim, obs) for obs in self._observed)

    def flag_silent_stops(self) -> Tuple[SilentStopFinding, ...]:
        """Return one finding per claim with no matching observed action.

        Deterministic order: registration order of the claims.
        """
        return tuple(
            SilentStopFinding(
                claim_id=c.claim_id,
                agent_id=c.agent_id,
                action_type=c.action_type,
                target=c.target,
            )
            for c in self._claims
            if not self._matches(c)
        )

    def verified_claims(self) -> Tuple[VerbalClaim, ...]:
        """Claims that have at least one matching observed action."""
        return tuple(c for c in self._claims if self._matches(c))

    def unreported_actions(self) -> Tuple[ObservedAction, ...]:
        """Observed actions no claim accounts for.

        The mirror image of a silent stop: action without narration. Kept as
        a view (not a finding) - an unreported action may be legitimate
        background work, but it belongs in the audit trail either way.
        """
        claimed_keys = {
            (_norm(c.agent_id), _norm(c.action_type), _norm(c.target))
            for c in self._claims
        }
        return tuple(
            o
            for o in self._observed
            if (_norm(o.agent_id), _norm(o.action_type), _norm(o.target))
            not in claimed_keys
        )

    def __len__(self) -> int:
        return len(self._claims)


def main() -> None:
    """Self-check smoke test."""
    det = SilentStopDetector()
    det.register_claim(
        VerbalClaim(
            claim_id="c1",
            agent_id="agent-7",
            action_type="report",
            target="operator",
            claimed_seq=100,
            statement="I have reported the finding to the operator.",
        )
    )
    # No observed action registered -> silent stop.
    findings = det.flag_silent_stops()
    assert len(findings) == 1 and findings[0].claim_id == "c1", findings
    # Now the audit trail shows the report actually went out.
    det.register_observed(
        ObservedAction(
            action_id="a1",
            agent_id="agent-7",
            action_type="report",
            target="operator",
            observed_seq=105,
            audit_digest="sha256:abc",
        )
    )
    assert det.flag_silent_stops() == (), det.flag_silent_stops()
    assert len(det.verified_claims()) == 1
    print("action-verifier OK: silent stop flagged, then cleared by audit evidence")


if __name__ == "__main__":
    main()
