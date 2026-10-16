"""Deterministic blue-team assessment for agent inputs and tool targets.

This is an orchestration layer, not an autonomous scanner.  It consumes text
and an optional declared tool target, runs the existing local detectors, and
returns a small, redaction-safe decision.  It never makes network requests,
executes commands, or attempts to exploit a finding.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any
import unicodedata

from adversarial_detector import analyze_input
from credential_detector import scan_for_credentials
from injection_detector import InjectionType, scan_injection
from mcp_pivoting_detector import check_tool_call


VERSION = "defensive-agent.v1"
SCHEMA_PIN = "northstar.defensive-agent.v1"
_MAX_ASSESS_CHARS = 64 * 1024


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

    # Keep regex and base64 inspection bounded even when a tool returned a
    # large but already-capped artifact. Preserve both edges so an injection
    # appended to a normal header is still visible to the local tripwires.
    if len(text) > _MAX_ASSESS_CHARS:
        edge = _MAX_ASSESS_CHARS // 2
        text = text[:edge] + "\n...[assessment middle omitted]...\n" + text[-edge:]

    # Inspect a compatibility-normalized view as well as the original bytes.
    # Fullwidth Latin and similar presentation forms otherwise evade lexical
    # tripwires while rendering as ordinary instructions to a model.
    inspection_text = unicodedata.normalize("NFKC", text)
    findings: list[DefensiveFinding] = []
    injection_findings = scan_injection(inspection_text)
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

    # Unicode format/control characters and mixed-script confusables are a
    # separate tripwire from lexical injection. Keep their signal at review
    # severity: legitimate multilingual and rich-text content exists, but an
    # invisible character must never be silently treated as clean.
    adversarial = analyze_input(text)
    for signal in adversarial.findings:
        if signal.signal.value == "high-frequency-noise":
            rule_id = "D-ADV-001"
        elif signal.signal.value == "imperceptible-perturbation":
            rule_id = "D-ADV-002"
        else:
            rule_id = "D-ADV-003"
        findings.append(
            DefensiveFinding(
                rule_id=rule_id,
                category=f"adversarial-{signal.signal.value}",
                severity=80,
                detail=f"score:{signal.score:.3f}",
            )
        )

    lowered = inspection_text.lower()
    credential_candidate = any(
        marker in lowered
        for marker in (
            "sk-", "akia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
            "xox", "aiza", "api_key", "apikey", "bearer", "token",
            "password", "private key",
        )
    ) or (inspection_text.count(".") >= 2 and len(inspection_text) < 16_384)
    for finding in scan_for_credentials(inspection_text) if credential_candidate else ():
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


def sanitize_for_model(
    text: str,
    *,
    preserve_length: bool = False,
) -> tuple[str, DefensiveAssessment]:
    """Remove known instruction-forgery spans before model consumption.

    High-confidence findings are replaced with a fixed quarantine marker. For
    review-level direct/indirect injections, only the matched spans are
    replaced so surrounding benign tool output remains useful. Credentials,
    jailbreaks, and blocked targets therefore never get partial disclosure.
    ``preserve_length`` keeps the returned review-level artifact within the
    input's character budget using inert padding; it is for resource accounting
    at an output boundary, not for preserving the matched bytes.
    """
    if not isinstance(preserve_length, bool):
        raise TypeError("preserve_length must be a bool")
    assessment = assess(text)
    if assessment.decision is Decision.BLOCK:
        return "[blocked by defensive agent]", assessment
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    normalized = unicodedata.normalize("NFKC", text)
    scan_text = normalized if normalized != text else text
    if len(scan_text) <= _MAX_ASSESS_CHARS:
        findings = scan_injection(scan_text)
    else:
        edge = _MAX_ASSESS_CHARS // 2
        prefix = scan_injection(scan_text[:edge])
        suffix_offset = len(scan_text) - edge
        suffix = tuple(
            replace(finding, start=finding.start + suffix_offset, end=finding.end + suffix_offset)
            for finding in scan_injection(scan_text[-edge:])
        )
        findings = prefix + suffix
    has_unicode_controls = any(
        unicodedata.category(char) == "Cf"
        or (unicodedata.category(char) == "Cc" and char not in "\t\n\r")
        for char in text
    )
    has_unicode_separators = any(
        unicodedata.category(char) in {"Pd", "Zs"} for char in normalized
    )
    if not findings and not has_unicode_controls and not has_unicode_separators:
        return text, assessment
    sanitized = scan_text
    for finding in sorted(findings, key=lambda item: (item.start, item.end), reverse=True):
        sanitized = sanitized[: finding.start] + "[redacted defensive rule]" + sanitized[finding.end :]
    # Remove Unicode format and control characters independently of lexical
    # injection matches. In preserve-length mode use inert spaces so a tool
    # result's accounting remains stable; otherwise leave an explicit marker
    # for operators and the model to see that content was altered.
    unicode_rewritten: list[str] = []
    for char in sanitized:
        category = unicodedata.category(char)
        if category == "Cf" or (category == "Cc" and char not in "\t\n\r"):
            unicode_rewritten.append(" " if preserve_length else "[redacted unicode]")
        else:
            unicode_rewritten.append(char)
    sanitized = "".join(unicode_rewritten)
    # Removing an invisible separator can join words into a fresh jailbreak
    # phrase that was not present during the first scan. Re-assess the cleaned
    # representation before releasing it, and fail closed if it now matches a
    # high-confidence rule.
    # Collapse only for detection: model-visible spacing is preserved below,
    # while equivalent whitespace cannot hide a phrase from lexical rules.
    post_cleanup = assess(" ".join(sanitized.split()))
    separator_cleanup = "".join(
        " " if unicodedata.category(char) in {"Pd", "Zs"} else char
        for char in sanitized
    )
    separator_pass = assess(" ".join(separator_cleanup.split()))
    if separator_pass.findings and any(
        finding.rule_id.startswith("D-INJ-") for finding in separator_pass.findings
    ):
        post_cleanup = replace(separator_pass, decision=Decision.BLOCK)
    if post_cleanup.decision is Decision.BLOCK or any(
        finding.rule_id.startswith("D-INJ-") for finding in post_cleanup.findings
    ):
        return "[blocked by defensive agent]", replace(post_cleanup, decision=Decision.BLOCK)
    if preserve_length and len(sanitized) < len(text):
        # Keep resource accounting stable without retaining any bytes from the
        # matched span. Padding is deliberately inert whitespace: it cannot be
        # interpreted as a hidden instruction, but it still exercises the same
        # context/compaction ceilings as the original artifact.
        sanitized += " " * (len(text) - len(sanitized))
    elif preserve_length and len(sanitized) > len(text):
        # A short marker (for example ``### system``) can be shorter than the
        # fixed redaction label. Never let a safety rewrite increase the caller's
        # resource budget; retain the safe prefix and drop the rest.
        sanitized = sanitized[: len(text)]
    return sanitized, assessment


def stdlib_only() -> bool:
    """The orchestrator itself uses only stdlib plus local sibling modules."""
    return True


__all__ = [
    "Decision",
    "DefensiveFinding",
    "DefensiveAssessment",
    "assess",
    "sanitize_for_model",
]
