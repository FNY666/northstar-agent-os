"""Pinned, non-generative explanations for selected runtime denial rules.

This module deliberately renders only audit-record facts and checked-in rule
text. Unknown deny codes receive no inferred cause or remediation. The static
rule table also feeds ``counterfactual_explanation_probes`` so explanation
quality checks use the same pinned wording as the runtime surface.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


@dataclass(frozen=True)
class Counterfactual:
    """One pinned condition that would change, or cannot change, a denial."""

    text: str
    mutable: bool

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("counterfactual text must be a non-empty string")
        if not isinstance(self.mutable, bool):
            raise ValueError("counterfactual mutable must be a bool")


@dataclass(frozen=True)
class RuleExplanation:
    """Immutable pinned explanation for a specific deny code."""

    deny_code: str
    counterfactuals: tuple[Counterfactual, ...]
    hard: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.deny_code, str) or not self.deny_code.strip():
            raise ValueError("deny_code must be a non-empty string")
        if not isinstance(self.counterfactuals, tuple) or not self.counterfactuals:
            raise ValueError("counterfactuals must be a non-empty tuple")
        if any(not isinstance(item, Counterfactual) for item in self.counterfactuals):
            raise ValueError("counterfactuals must contain Counterfactual values")
        if not isinstance(self.hard, bool):
            raise ValueError("hard must be a bool")


RULE_EXPLANATIONS: Mapping[str, RuleExplanation] = MappingProxyType(
    {
        "denial.ceiling.needs_approval": RuleExplanation(
            deny_code="denial.ceiling.needs_approval",
            counterfactuals=(
                Counterfactual(
                    text=(
                        "A verified human approval bound to this exact call_id and "
                        "arguments_digest would allow the ascent."
                    ),
                    mutable=True,
                ),
            ),
        ),
        "denial.offensive.deny_by_default": RuleExplanation(
            deny_code="denial.offensive.deny_by_default",
            counterfactuals=(
                Counterfactual(
                    text=(
                        "No remediation exists. This is a hard deny that cannot "
                        "be overridden by approval, ascent, or human decision."
                    ),
                    mutable=False,
                ),
            ),
            hard=True,
        ),
    }
)


def render_denial(audit_record: Mapping[str, Any]) -> str:
    """Render a denial using only its audit record and the pinned rule table.

    Unknown deny codes intentionally receive no rule-specific cause or remedy;
    callers must add a reviewed, versioned rule entry before rendering one.
    """
    if not isinstance(audit_record, Mapping):
        raise ValueError("audit_record must be a mapping")
    if audit_record.get("verdict") not in {"deny", "denied"}:
        raise ValueError("audit_record verdict must be deny/denied")

    deny_code = audit_record.get("deny_code")
    if not isinstance(deny_code, str) or not deny_code.strip():
        raise ValueError("audit_record must contain a non-empty deny_code")
    reason = audit_record.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise ValueError("audit_record reason must be a string when present")

    parts = [f"Denied under {deny_code}."]
    if reason:
        parts.append(f"Recorded audit reason: {reason}.")
    explanation = RULE_EXPLANATIONS.get(deny_code)
    if explanation is None:
        parts.append(
            "No pinned rule explanation is available; no cause or remediation is inferred."
        )
    else:
        parts.append(explanation.counterfactuals[0].text)
    return " ".join(parts)


__all__ = ["Counterfactual", "RuleExplanation", "RULE_EXPLANATIONS", "render_denial"]
