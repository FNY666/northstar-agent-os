"""Tripwire guardrails: three-valued gate outcomes (OpenAI Agents SDK), Simulated.

Gates return one of three outcomes:
- ALLOW: proceed normally
- REJECT_CONTENT: substitute a fixed error message, continue the task
- HALT: stop the task entirely

The "reject_content" is the missing middle between allow and halt --
the agent can recover from a denied tool without killing the whole task.

Scoping (from OpenAI):
- chain_entry: fires once per task chain
- terminal: fires once at task end
- per_action: fires per tool call

Modes:
- blocking: enforcement (deny stops the action)
- advisory: logs only ("may have observed side effects")

What this IS: refines Northstar's binary gate to three-valued.

What this IS NOT:
* Not a replacement for PermissionEngine -- wraps it.
* The substituted message is fixed (not LLM-generated) to avoid
  injection via the error path.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Optional

#: Module version.
TRIPWIRE_VERSION = "tripwire-guardrails.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tripwire-guardrails.v1"


class TripwireOutcome(Enum):
    """Three-valued gate outcome."""

    ALLOW = "allow"
    REJECT_CONTENT = "reject_content"
    HALT = "halt"


class TripwireScope(Enum):
    """When the guardrail fires."""

    CHAIN_ENTRY = "chain_entry"
    TERMINAL = "terminal"
    PER_ACTION = "per_action"


class TripwireMode(Enum):
    """Enforcement mode."""

    BLOCKING = "blocking"
    ADVISORY = "advisory"


@dataclass(frozen=True)
class GuardrailResult:
    """Result of a tripwire guardrail check."""

    outcome: TripwireOutcome
    reason: str = ""
    # For REJECT_CONTENT: the fixed message to substitute.
    substitute_message: str = ""
    # For ADVISORY mode: note that side effects may have occurred.
    advisory_note: str = ""


class TripwireError(Exception):
    """Fail-closed: bad guardrail config raises."""


class TripwireGuard:
    """A single tripwire guardrail.

    Wraps a check function that returns True (violation) or False (clean).
    Maps violations to outcomes based on configuration.
    """

    def __init__(
        self,
        name: str,
        check_fn: Callable[[str, Dict[str, Any]], bool],
        *,
        scope: TripwireScope = TripwireScope.PER_ACTION,
        mode: TripwireMode = TripwireMode.BLOCKING,
        on_violation: TripwireOutcome = TripwireOutcome.HALT,
        substitute_message: str = "[blocked by guardrail]",
    ) -> None:
        if not name:
            raise TripwireError("name required")
        if not callable(check_fn):
            raise TripwireError("check_fn must be callable")
        if on_violation == TripwireOutcome.ALLOW:
            raise TripwireError("on_violation cannot be ALLOW")
        self._name = name
        self._check_fn = check_fn
        self._scope = scope
        self._mode = mode
        self._on_violation = on_violation
        self._substitute_message = substitute_message
        self._fired_count = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def scope(self) -> TripwireScope:
        return self._scope

    def check(self, tool_name: str, args: Dict[str, Any]) -> GuardrailResult:
        """Run the guardrail check.

        Returns GuardrailResult.  In ADVISORY mode, violations are logged
        but the outcome is ALLOW (with advisory_note).
        """
        try:
            violated = self._check_fn(tool_name, args)
        except Exception as e:
            # Check raised: fail-closed -> treat as violation.
            violated = True

        if not violated:
            return GuardrailResult(outcome=TripwireOutcome.ALLOW)

        self._fired_count += 1

        if self._mode == TripwireMode.ADVISORY:
            return GuardrailResult(
                outcome=TripwireOutcome.ALLOW,
                reason=f"advisory: {self._name} would have fired",
                advisory_note=(
                    "may have observed side effects before cancellation"
                ),
            )

        # BLOCKING mode.
        if self._on_violation == TripwireOutcome.REJECT_CONTENT:
            return GuardrailResult(
                outcome=TripwireOutcome.REJECT_CONTENT,
                reason=f"{self._name}: content rejected",
                substitute_message=self._substitute_message,
            )
        else:  # HALT
            return GuardrailResult(
                outcome=TripwireOutcome.HALT,
                reason=f"{self._name}: halted",
            )

    @property
    def fired_count(self) -> int:
        return self._fired_count


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "enum", "pathlib", "typing"}
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
    """Self-check."""
    # Blocking halt guard.
    halt_guard = TripwireGuard(
        "no_delete",
        lambda tool, args: tool == "delete_db",
        on_violation=TripwireOutcome.HALT,
    )
    r = halt_guard.check("delete_db", {})
    assert r.outcome == TripwireOutcome.HALT
    r = halt_guard.check("read_file", {})
    assert r.outcome == TripwireOutcome.ALLOW

    # Reject-content guard (recoverable).
    reject_guard = TripwireGuard(
        "no_secrets",
        lambda tool, args: "secret" in str(args),
        on_violation=TripwireOutcome.REJECT_CONTENT,
        substitute_message="[redacted]",
    )
    r = reject_guard.check("send", {"data": "secret key"})
    assert r.outcome == TripwireOutcome.REJECT_CONTENT
    assert r.substitute_message == "[redacted]"

    # Advisory mode: logs but allows.
    adv_guard = TripwireGuard(
        "advisory",
        lambda tool, args: True,  # always fires
        mode=TripwireMode.ADVISORY,
    )
    r = adv_guard.check("any", {})
    assert r.outcome == TripwireOutcome.ALLOW
    assert "advisory" in r.reason

    # Fail-closed on check exception.
    def bad_check(tool, args):
        raise RuntimeError("oops")

    fail_guard = TripwireGuard("fail", bad_check)
    r = fail_guard.check("t", {})
    assert r.outcome == TripwireOutcome.HALT  # fail-closed

    assert stdlib_only()
    print("tripwire-guardrails OK: 3 outcomes, scopes, modes, fail-closed")


if __name__ == "__main__":
    main()
