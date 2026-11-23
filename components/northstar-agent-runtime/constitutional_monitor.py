"""Constitutional AI monitor: principle-based violation tripwire.

Research basis (second-hand):
- Constitutional AI (Anthropic, 2022): models trained against a written
  constitution - a list of principles covering harmlessness, honesty, and
  autonomy preservation - with a self-critique and revision loop. The
  constitution is the behavioral contract; the critique step checks outputs
  against it.
- This module is NOT a trainer and performs no self-critique loop. It is a
  runtime monitor: given a fixed constitution (frozen principles carrying
  forbidden content patterns and forbidden action types), it checks whether
  a proposed action's content trips any principle. Detector, not defense:
  it names the violation; the gate layer decides what to do with the verdict.

Design:
- :class:`Principle` (frozen): one constitutional principle with a severity,
  a tuple of forbidden regex patterns (compiled case-insensitively at
  construction, fail fast on invalid regex), and a tuple of forbidden
  action types.
- :class:`Constitution` (frozen): an ordered tuple of principles with unique
  ids. Registration order is the scan order.
- :class:`AgentAction` (frozen): the host-reported action under review -
  action_id, agent_id, action_type, content, caller-supplied int seq.
- :func:`check_violation` -> bool: True if any principle trips.
- :func:`scan_violations` -> tuple of frozen :class:`Violation`, in
  principle registration order.
- :func:`classify_violation` -> the maximum :class:`Severity` tripped, or
  None when clean.

Honest scope: pattern-based tripwire on host-reported action records. It
catches known, named violation shapes (the patterns the constitution's
authors wrote down) - paraphrased, obfuscated, or novel violations pass
through. A clean verdict means "no known constitutional violation shape",
never "the action is constitutional". It does not judge intent, does not
see unlogged actions, and does not prove the absence of harm.

No wall-clock anywhere. All time is caller-supplied integer sequence numbers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

#: Version pin for the monitor described here.
CONSTITUTIONAL_MONITOR_VERSION = "constitutional-monitor.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.constitutional-monitor.v1"

#: Maximum characters of matched text kept in a violation preview.
PREVIEW_LIMIT = 80


class Severity(Enum):
    """Violation severity, ordered low -> critical."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        return order.index(self) < order.index(other)


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


def _check_severity(value: object) -> Severity:
    """Normalize a Severity or severity-name string to Severity."""
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        try:
            return Severity(value.strip().lower())
        except ValueError:
            raise ValueError(
                f"severity must be one of {[s.value for s in Severity]}, got {value!r}"
            )
    raise TypeError(f"severity must be a Severity or str, got {type(value).__name__}")


def _check_str_tuple(value: object, name: str) -> Tuple[str, ...]:
    """Validate a tuple of non-empty strings."""
    if not isinstance(value, (tuple, list)):
        raise TypeError(f"{name} must be a tuple/list of str, got {type(value).__name__}")
    items = tuple(value)
    for item in items:
        _check_text(item, f"{name} entry")
    return items


@dataclass(frozen=True)
class Principle:
    """One constitutional principle.

    ``forbidden_patterns`` are regexes matched (case-insensitively) against
    the action's content. ``forbidden_action_types`` are action-type names
    matched exactly (case-insensitively). Either may be empty; a principle
    with both empty never trips (allowed, but pointless - documented).
    """

    principle_id: str
    name: str
    description: str
    severity: Severity
    forbidden_patterns: Tuple[str, ...] = ()
    forbidden_action_types: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _check_text(self.principle_id, "principle_id")
        _check_text(self.name, "name")
        _check_text(self.description, "description")
        object.__setattr__(self, "severity", _check_severity(self.severity))
        patterns = _check_str_tuple(self.forbidden_patterns, "forbidden_patterns")
        object.__setattr__(self, "forbidden_patterns", patterns)
        action_types = _check_str_tuple(self.forbidden_action_types, "forbidden_action_types")
        object.__setattr__(self, "forbidden_action_types", action_types)
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE))
            except re.error as exc:
                raise ValueError(f"invalid regex in forbidden_patterns: {pattern!r}: {exc}")
        # Cached compiled forms; not a dataclass field (excluded from eq/repr).
        object.__setattr__(self, "_compiled_patterns", tuple(compiled))
        object.__setattr__(
            self, "_lower_action_types", tuple(t.lower() for t in action_types)
        )

    def matches(self, action_type: str, content: str) -> Optional[str]:
        """Return the tripping rule description, or None if clean.

        Checks forbidden action types first, then content patterns, in
        declaration order. The returned string names the rule that tripped
        (``action-type:<name>`` or ``pattern:<regex>``), never raw content.
        """
        if action_type.lower() in self._lower_action_types:  # type: ignore[attr-defined]
            return f"action-type:{action_type}"
        for pattern, compiled in zip(
            self.forbidden_patterns, self._compiled_patterns  # type: ignore[attr-defined]
        ):
            if compiled.search(content):
                return f"pattern:{pattern}"
        return None


@dataclass(frozen=True)
class Constitution:
    """A frozen, ordered set of principles. Registration order is scan order."""

    constitution_id: str
    name: str
    principles: Tuple[Principle, ...]
    version: str = CONSTITUTIONAL_MONITOR_VERSION

    def __post_init__(self) -> None:
        _check_text(self.constitution_id, "constitution_id")
        _check_text(self.name, "name")
        _check_text(self.version, "version")
        if not isinstance(self.principles, (tuple, list)):
            raise TypeError(
                f"principles must be a tuple/list of Principle, got {type(self.principles).__name__}"
            )
        principles = tuple(self.principles)
        if not principles:
            raise ValueError("principles must be non-empty")
        for principle in principles:
            if not isinstance(principle, Principle):
                raise TypeError(
                    f"principles entries must be Principle, got {type(principle).__name__}"
                )
        ids = [p.principle_id for p in principles]
        if len(set(ids)) != len(ids):
            raise ValueError(f"principle_ids must be unique, got {ids}")
        object.__setattr__(self, "principles", principles)

    def principle(self, principle_id: str) -> Principle:
        """Look up a principle by id; KeyError if unknown."""
        for principle in self.principles:
            if principle.principle_id == principle_id:
                return principle
        raise KeyError(f"unknown principle_id: {principle_id}")


@dataclass(frozen=True)
class AgentAction:
    """A host-reported action under constitutional review."""

    action_id: str
    agent_id: str
    action_type: str
    content: str
    seq: int

    def __post_init__(self) -> None:
        _check_text(self.action_id, "action_id")
        _check_text(self.agent_id, "agent_id")
        _check_text(self.action_type, "action_type")
        if not isinstance(self.content, str):
            raise TypeError(f"content must be a str, got {type(self.content).__name__}")
        _check_seq(self.seq, "seq")


@dataclass(frozen=True)
class Violation:
    """One tripped principle for one action."""

    principle_id: str
    principle_name: str
    severity: str
    action_id: str
    agent_id: str
    seq: int
    matched_rule: str
    preview: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "principle_id": self.principle_id,
            "principle_name": self.principle_name,
            "severity": self.severity,
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "seq": self.seq,
            "matched_rule": self.matched_rule,
            "preview": self.preview,
        }


def _check_inputs(action: object, constitution: object) -> Tuple[AgentAction, Constitution]:
    if not isinstance(action, AgentAction):
        raise TypeError(f"action must be an AgentAction, got {type(action).__name__}")
    if not isinstance(constitution, Constitution):
        raise TypeError(
            f"constitution must be a Constitution, got {type(constitution).__name__}"
        )
    return action, constitution


def scan_violations(action: AgentAction, constitution: Constitution) -> Tuple[Violation, ...]:
    """Scan one action against every principle; violations in registration order."""
    action, constitution = _check_inputs(action, constitution)
    findings = []
    for principle in constitution.principles:
        matched_rule = principle.matches(action.action_type, action.content)
        if matched_rule is None:
            continue
        preview = action.content[:PREVIEW_LIMIT]
        findings.append(
            Violation(
                principle_id=principle.principle_id,
                principle_name=principle.name,
                severity=principle.severity.value,
                action_id=action.action_id,
                agent_id=action.agent_id,
                seq=action.seq,
                matched_rule=matched_rule,
                preview=preview,
            )
        )
    return tuple(findings)


def check_violation(action: AgentAction, constitution: Constitution) -> bool:
    """True if any principle trips on the action. Fail-closed on bad input."""
    return len(scan_violations(action, constitution)) > 0


def classify_violation(action: AgentAction, constitution: Constitution) -> Optional[Severity]:
    """Maximum severity tripped, or None when the action is clean."""
    violations = scan_violations(action, constitution)
    if not violations:
        return None
    order = {s.value: s for s in Severity}
    return max((order[v.severity] for v in violations))


def constitutional_audit_event(
    action: AgentAction, constitution: Constitution, audit_seq: int
) -> dict:
    """Shape an audit.ndjson/1-style record for a constitutional review."""
    action, constitution = _check_inputs(action, constitution)
    _check_seq(audit_seq, "audit_seq")
    violations = scan_violations(action, constitution)
    worst = classify_violation(action, constitution)
    return {
        "schema": SCHEMA_PIN,
        "event": "constitutional-review",
        "constitution_id": constitution.constitution_id,
        "action_id": action.action_id,
        "agent_id": action.agent_id,
        "action_seq": action.seq,
        "violated": len(violations) > 0,
        "violation_count": len(violations),
        "max_severity": worst.value if worst is not None else None,
        "principle_ids": [v.principle_id for v in violations],
        "audit_seq": audit_seq,
    }


def main() -> None:
    constitution = Constitution(
        constitution_id="c1",
        name="demo-constitution",
        principles=(
            Principle(
                principle_id="no-deception",
                name="No deception",
                description="Do not produce deceptive content.",
                severity=Severity.HIGH,
                forbidden_patterns=(r"pretend (to be|you are) (a )?(human|user)",),
            ),
            Principle(
                principle_id="no-self-harm",
                name="No self-harm facilitation",
                description="Do not facilitate self-harm.",
                severity="critical",
                forbidden_action_types=("self_harm_instructions",),
            ),
        ),
    )
    bad = AgentAction(
        action_id="a1",
        agent_id="agent-7",
        action_type="chat",
        content="Pretend you are a human customer to get the refund.",
        seq=1,
    )
    good = AgentAction(
        action_id="a2",
        agent_id="agent-7",
        action_type="chat",
        content="Here is a summary of your account balance.",
        seq=2,
    )
    assert check_violation(bad, constitution) is True
    assert check_violation(good, constitution) is False
    assert classify_violation(bad, constitution) is Severity.HIGH
    assert classify_violation(good, constitution) is None
    assert len(scan_violations(bad, constitution)) == 1
    print("constitutional-monitor OK: violation flagged, clean passed")


if __name__ == "__main__":
    main()
