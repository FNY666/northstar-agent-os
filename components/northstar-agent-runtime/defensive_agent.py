"""Deterministic blue-team assessment for agent inputs and tool targets.

This is an orchestration layer, not an autonomous scanner.  It consumes text
and an optional declared tool target, runs the existing local detectors, and
returns a small, redaction-safe decision.  It never makes network requests,
executes commands, or attempts to exploit a finding.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from credential_detector import scan_for_credentials
from injection_detector import InjectionType, scan_injection
from mcp_pivoting_detector import check_tool_call


VERSION = "defensive-agent.v1"
SCHEMA_PIN = "northstar.defensive-agent.v1"


class Decision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


@dataclass(frozen=True)
class DefensiveFinding:
    """A safe-to-log finding; raw input and URLs never appear here."""

    rule_id: str
    category: str
    severity: int
    detail: str


@dataclass(frozen=True)
class DefensiveAssessment:
    """The complete deterministic result of one local assessment."""

    version: str
    schema: str
    decision: Decision
    findings: tuple[DefensiveFinding, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "schema": self.schema,
            "decision": self.decision.value,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "severity": f.severity,
                    "detail": f.detail,
                }
                for f in self.findings
            ],
        }


def assess(
    text: str = "",
    *,
    tool_name: str | None = None,
    url: str | None = None,
) -> DefensiveAssessment:
    """Assess untrusted content and an optional tool target.

    The function is pure apart from detector-local computation.  A jailbreak,
    hardcoded credential, or blocked internal target is a fail-closed block.
    Known instruction forgery without those stronger signals requires review.
    Invalid detector input propagates as a programming error instead of being
    silently treated as clean.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if tool_name is not None and not isinstance(tool_name, str):
        raise TypeError("tool_name must be a string or None")
    if url is not None and not isinstance(url, str):
        raise TypeError("url must be a string or None")
    if url is not None and tool_name is None:
        raise ValueError("tool_name is required when url is provided")

    findings: list[DefensiveFinding] = []
    injection_findings = scan_injection(text)
    for finding in injection_findings:
        family = finding.injection_type
        severity = 90 if family is InjectionType.JAILBREAK else 70
        findings.append(
            DefensiveFinding(
                rule_id="D-INJ-001" if family is InjectionType.JAILBREAK else "D-INJ-002",
                category=family.value,
                severity=severity,
                detail=f"pattern:{finding.pattern};span:{finding.start}-{finding.end}",
            )
        )

    for finding in scan_for_credentials(text):
        findings.append(
            DefensiveFinding(
                rule_id="D-SEC-001",
                category="credential-exposure",
                severity=100,
                detail=f"type:{finding.credential_type.value};line:{finding.line_number};value:{finding.masked_value}",
            )
        )

    if url is not None and tool_name is not None:
        if check_tool_call(tool_name, url).blocked:
            findings.append(
                DefensiveFinding(
                    rule_id="D-NET-001",
                    category="internal-target",
                    severity=100,
                    detail="tool target rejected by local egress rule",
                )
            )

    findings.sort(key=lambda item: (-item.severity, item.rule_id, item.detail))
    if any(item.severity >= 90 for item in findings):
        decision = Decision.BLOCK
    elif findings:
        decision = Decision.REVIEW
    else:
        decision = Decision.ALLOW
    return DefensiveAssessment(VERSION, SCHEMA_PIN, decision, tuple(findings))


def stdlib_only() -> bool:
    """The orchestrator itself uses only stdlib plus local sibling modules."""
    return True


__all__ = ["Decision", "DefensiveFinding", "DefensiveAssessment", "assess"]
