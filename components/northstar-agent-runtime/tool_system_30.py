"""Tool governance (policy): regex policies over tool names, Simulated.

A PolicyEngine holds policies of (tool_pattern regex, action
allow/deny/require_approval).  ``evaluate(tool, context)`` returns a
Decision with the chosen action and the matched policy.  Deny wins
over allow; unlisted tools hit the configurable default (deny by
default, fail-closed).  Every evaluation is appended to an audit trail.

What this IS:
* Simulated policy matching for tool-call governance.

What this IS NOT:
* Not enforcement -- callers must act on the Decision.
* Not a real authorization service.
* Regex patterns are matched with re.search; keep them simple.
"""

from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

#: Module version.
TOOL_SYSTEM_30_VERSION = "tool-system-30.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-30.v1"

#: Valid policy actions.
ALLOW = "allow"
DENY = "deny"
REQUIRE_APPROVAL = "require_approval"

#: Precedence: deny beats everything, then require_approval, then allow.
_PRECEDENCE = {DENY: 3, REQUIRE_APPROVAL: 2, ALLOW: 1}


class ToolSystem30Error(Exception):
    """Fail-closed."""


@dataclass
class Policy:
    """One governance policy (mock)."""

    name: str
    tool_pattern: str
    action: str

    def matches(self, tool: str) -> bool:
        return re.search(self.tool_pattern, tool) is not None


@dataclass
class Decision:
    """Outcome of one policy evaluation."""

    tool: str
    action: str
    matched_policy: Optional[str]
    reason: str


@dataclass
class AuditEntry:
    """One recorded evaluation."""

    seq: int
    at: float
    tool: str
    action: str
    matched_policy: Optional[str]


class PolicyEngine:
    """Simulated policy engine with audit trail."""

    def __init__(
        self,
        default_action: str = DENY,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if default_action not in (ALLOW, DENY):
            raise ToolSystem30Error(
                "default_action must be 'allow' or 'deny'"
            )
        self._policies: List[Policy] = []
        self._default = default_action
        self._clock = clock or time.time
        self._audit: List[AuditEntry] = []
        self._seq = 0

    def add_policy(self, policy: Policy) -> None:
        if policy.action not in _PRECEDENCE:
            raise ToolSystem30Error(
                f"unknown action '{policy.action}'"
            )
        try:
            re.compile(policy.tool_pattern)
        except re.error as exc:
            raise ToolSystem30Error(
                f"bad regex in policy '{policy.name}': {exc}"
            ) from exc
        self._policies.append(policy)

    def evaluate(
        self, tool: str, context: Optional[Dict[str, Any]] = None
    ) -> Decision:
        """Pick the highest-precedence action among matching policies."""
        matched = [p for p in self._policies if p.matches(tool)]
        if not matched:
            decision = Decision(
                tool=tool,
                action=self._default,
                matched_policy=None,
                reason=f"no policy matched; default {self._default}",
            )
        else:
            winner = max(matched, key=lambda p: _PRECEDENCE[p.action])
            decision = Decision(
                tool=tool,
                action=winner.action,
                matched_policy=winner.name,
                reason=f"policy '{winner.name}' matched",
            )
        self._seq += 1
        self._audit.append(
            AuditEntry(
                seq=self._seq,
                at=self._clock(),
                tool=tool,
                action=decision.action,
                matched_policy=decision.matched_policy,
            )
        )
        return decision

    def audit_trail(self) -> List[AuditEntry]:
        return list(self._audit)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "time", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    tick = {"t": 1000.0}
    eng = PolicyEngine(clock=lambda: tick["t"])
    eng.add_policy(Policy(name="read-ok", tool_pattern=r"^read", action=ALLOW))
    eng.add_policy(
        Policy(name="no-secret", tool_pattern=r"secret", action=DENY)
    )
    d = eng.evaluate("read_file")
    assert d.action == ALLOW and d.matched_policy == "read-ok"
    # Deny wins over allow.
    eng.add_policy(
        Policy(name="read-deny", tool_pattern=r"^read", action=DENY)
    )
    d = eng.evaluate("read_file")
    assert d.action == DENY and d.matched_policy == "read-deny"
    # Default deny for unlisted.
    d = eng.evaluate("write_db")
    assert d.action == DENY and d.matched_policy is None
    # require_approval beats allow, loses to deny.
    eng2 = PolicyEngine()
    eng2.add_policy(Policy(name="a", tool_pattern=r"^web", action=ALLOW))
    eng2.add_policy(
        Policy(name="b", tool_pattern=r"^web", action=REQUIRE_APPROVAL)
    )
    assert eng2.evaluate("web_fetch").action == REQUIRE_APPROVAL
    # Audit trail recorded with injectable clock.
    assert len(eng.audit_trail()) == 3
    assert eng.audit_trail()[0].at == 1000.0
    # Bad action / bad regex rejected.
    try:
        eng.add_policy(Policy(name="x", tool_pattern="t", action="nuke"))
        raise AssertionError("should raise")
    except ToolSystem30Error:
        pass
    try:
        eng.add_policy(Policy(name="y", tool_pattern="([", action=ALLOW))
        raise AssertionError("should raise")
    except ToolSystem30Error:
        pass
    assert stdlib_only()
    print("tool_system_30 OK: policies, deny-wins, default-deny, audit")


if __name__ == "__main__":
    main()
