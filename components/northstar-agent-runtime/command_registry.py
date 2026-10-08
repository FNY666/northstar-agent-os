"""Command registry with bounded pre-authorization (AutoGPT), Simulated.

All agent power flows through a fixed, enumerated command registry.
The LLM cannot invoke anything unregistered.

Pre-authorization: bounded integer counter for the next N actions,
not open-ended auto-mode.  Decremented per sensitive action.

Autonomy levels:
- automatic: no approval needed
- notify: log only
- approval_required: needs human approval
- human_only: never auto-executed

What this IS: closed-world assumption makes gating tractable.

What this IS NOT:
* Not the approval UI -- host-provided.
* The pre-auth counter is per-session, not persistent.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

#: Module version.
CMD_REGISTRY_VERSION = "command-registry.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.command-registry.v1"


class AutonomyLevel(Enum):
    """How much autonomy a command has."""

    AUTOMATIC = "automatic"
    NOTIFY = "notify"
    APPROVAL_REQUIRED = "approval_required"
    HUMAN_ONLY = "human_only"


class RegistryError(Exception):
    """Fail-closed: unknown commands raise."""


@dataclass(frozen=True)
class CommandSpec:
    """Specification for one registered command."""

    name: str
    autonomy: AutonomyLevel
    description: str = ""


class CommandRegistry:
    """Fixed registry of allowed commands with pre-auth counters."""

    def __init__(self) -> None:
        self._commands: Dict[str, CommandSpec] = {}
        self._pre_auth: int = 0

    def register(self, spec: CommandSpec) -> None:
        """Register a command (setup time only)."""
        if not spec.name:
            raise RegistryError("command name required")
        self._commands[spec.name] = spec

    def grant_preauth(self, n: int) -> None:
        """Grant bounded pre-authorization for next N sensitive actions."""
        if not isinstance(n, int) or n < 0:
            raise RegistryError("n must be non-negative int")
        self._pre_auth = n

    def check(
        self,
        command_name: str,
        *,
        human_approved: bool = False,
    ) -> tuple[bool, str]:
        """Check if a command can execute.

        Returns (allowed, reason).
        - Unknown command: (False, "unknown")
        - AUTOMATIC: (True, ...)
        - NOTIFY: (True, ...) -- caller should log
        - APPROVAL_REQUIRED: needs pre_auth > 0 or human_approved
        - HUMAN_ONLY: needs human_approved (pre_auth doesn't count)
        """
        if command_name not in self._commands:
            return False, "unknown command"
        spec = self._commands[command_name]
        if spec.autonomy == AutonomyLevel.AUTOMATIC:
            return True, "automatic"
        if spec.autonomy == AutonomyLevel.NOTIFY:
            return True, "notify: should log"
        if spec.autonomy == AutonomyLevel.HUMAN_ONLY:
            if human_approved:
                return True, "human approved"
            return False, "human_only: requires explicit approval"
        # APPROVAL_REQUIRED
        if human_approved:
            return True, "human approved"
        if self._pre_auth > 0:
            self._pre_auth -= 1
            return True, f"pre-auth used, {self._pre_auth} remaining"
        return False, "approval required"

    @property
    def pre_auth_remaining(self) -> int:
        return self._pre_auth

    def commands(self) -> Dict[str, CommandSpec]:
        return dict(self._commands)


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
    r = CommandRegistry()
    r.register(CommandSpec("read", AutonomyLevel.AUTOMATIC))
    r.register(CommandSpec("write", AutonomyLevel.APPROVAL_REQUIRED))
    r.register(CommandSpec("delete", AutonomyLevel.HUMAN_ONLY))

    # Automatic: always allowed.
    ok, _ = r.check("read")
    assert ok is True

    # Approval required: denied without pre-auth.
    ok, _ = r.check("write")
    assert ok is False

    # Grant pre-auth for 2 actions.
    r.grant_preauth(2)
    ok, reason = r.check("write")
    assert ok is True
    assert r.pre_auth_remaining == 1
    ok, _ = r.check("write")
    assert ok is True
    assert r.pre_auth_remaining == 0
    # Exhausted.
    ok, _ = r.check("write")
    assert ok is False

    # Human-only: pre-auth doesn't help.
    r.grant_preauth(5)
    ok, _ = r.check("delete")
    assert ok is False
    ok, _ = r.check("delete", human_approved=True)
    assert ok is True

    # Unknown: denied.
    ok, _ = r.check("unknown_cmd")
    assert ok is False

    assert stdlib_only()
    print("command-registry OK: autonomy levels, pre-auth, fail-closed")


if __name__ == "__main__":
    main()
