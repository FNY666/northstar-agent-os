"""Deterministic veto: model can escalate, never waive (D2), Simulated.

Core invariant: the model can only INCREASE approval requirements,
never waive deterministic vetoes.  Veto logic lives outside
model-writable state.

Consequence classification (not verb matching):
- irreversible vs reversible
- target scope
- blast radius

Heuristic verb matching (rm) misses semantic equivalents
(rsync --delete, git clean -fd).  Classify by consequence.

What this IS: the safety invariant for Northstar's gates.

What this IS NOT:
* Not the full policy engine -- just the veto invariant.
* Consequence classifier is host-provided (domain-specific).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet

#: Module version.
DETERMINISTIC_VETO_VERSION = "deterministic-veto.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.deterministic-veto.v1"


class Consequence(Enum):
    """Consequence classification."""

    REVERSIBLE_LOW = "reversible_low"  # read, list
    REVERSIBLE_HIGH = "reversible_high"  # write (undoable)
    IRREVERSIBLE_SCOPED = "irreversible_scoped"  # delete one file
    IRREVERSIBLE_BROAD = "irreversible_broad"  # rm -rf, drop database


class VetoError(Exception):
    """Fail-closed: veto violations raise."""


@dataclass(frozen=True)
class VetoRule:
    """A deterministic veto rule (model cannot modify)."""

    rule_id: str
    consequence: Consequence
    # If True, this veto cannot be waived by anyone except explicit
    # human override (not model, not pre-auth).
    unwaivable: bool = True


class DeterministicVeto:
    """Enforces vetoes outside model control.

    The model may request escalation (stricter checks) but cannot
    waive a veto.  Only explicit human override bypasses unwaivable
    vetoes.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, VetoRule] = {}
        # Model-writable: can only add stricter rules, not remove.
        self._model_escalations: Dict[str, VetoRule] = {}

    def add_rule(self, rule: VetoRule) -> None:
        """Add a veto rule (setup time, not model-writable)."""
        if not rule.rule_id:
            raise VetoError("rule_id required")
        self._rules[rule.rule_id] = rule

    def model_escalate(self, rule: VetoRule) -> None:
        """Model requests stricter checking (can only add, not remove)."""
        if not rule.rule_id:
            raise VetoError("rule_id required")
        # Model can only escalate to equal or stricter consequence.
        # For simplicity: model escalations are always additional denies.
        self._model_escalations[rule.rule_id] = rule

    def check(
        self,
        consequence: Consequence,
        *,
        human_override: bool = False,
    ) -> tuple[bool, str]:
        """Check if an action with given consequence is vetoed.

        Returns (vetoed, reason).
        - Unwaivable vetoes: only human_override bypasses.
        - Waivable vetoes: blocked unless human_override.
        - Model escalations: always enforced (model cannot waive its own).
        """
        # Check deterministic rules.
        for rule_id, rule in self._rules.items():
            if rule.consequence == consequence:
                if rule.unwaivable and not human_override:
                    return True, f"vetoed by {rule_id} (unwaivable)"
                if not rule.unwaivable and not human_override:
                    return True, f"vetoed by {rule_id}"
        # Check model escalations (model cannot waive these).
        for rule_id, rule in self._model_escalations.items():
            if rule.consequence == consequence:
                # Model escalations are never waivable by model.
                # Human can still override.
                if not human_override:
                    return True, f"vetoed by model-escalation {rule_id}"
        return False, "no veto"

    def is_vetoed(self, consequence: Consequence) -> bool:
        """Quick check (no human override)."""
        vetoed, _ = self.check(consequence, human_override=False)
        return vetoed


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
    veto = DeterministicVeto()
    veto.add_rule(VetoRule("no_mass_delete", Consequence.IRREVERSIBLE_BROAD))

    # Vetoed.
    vetoed, reason = veto.check(Consequence.IRREVERSIBLE_BROAD)
    assert vetoed is True
    assert "unwaivable" in reason

    # Human can override.
    vetoed, _ = veto.check(
        Consequence.IRREVERSIBLE_BROAD, human_override=True
    )
    assert vetoed is False

    # Reversible: not vetoed.
    vetoed, _ = veto.check(Consequence.REVERSIBLE_LOW)
    assert vetoed is False

    # Model escalation.
    veto.model_escalate(
        VetoRule("model_caution", Consequence.REVERSIBLE_HIGH)
    )
    vetoed, _ = veto.check(Consequence.REVERSIBLE_HIGH)
    assert vetoed is True  # model escalation enforced

    assert stdlib_only()
    print("deterministic-veto OK: unwaivable, escalation-only, fail-closed")


if __name__ == "__main__":
    main()
