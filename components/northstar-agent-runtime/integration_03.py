"""Integration I-003: deterministic veto + stateful veto (layered veto), Simulated.

Order per decision:
(1) rate-limit check on retry patterns -> deny;
(2) deterministic veto -> deny AND record the denial (risk rises);
(3) else -> allow.

Consequence enums from different module copies are normalized by value
(cross-module safe).

What this IS: a veto that remembers.
What this IS NOT: not the ledger writer -- uses in-memory risk state.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any

#: Module version.
INTEGRATION_03_VERSION = "integration-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.integration-03.v1"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_dveto = _load("deterministic_veto")
_sveto = _load("stateful_veto")


class IntegrationError(Exception):
    """Fail-closed."""


class LayeredVeto:
    """Deterministic veto layered over stateful retry tracking."""

    def __init__(self, veto: Any = None, stateful: Any = None) -> None:
        self._veto = veto if veto is not None else _dveto.DeterministicVeto()
        self._stateful = (
            stateful if stateful is not None else _sveto.StatefulVeto()
        )

    @property
    def veto(self) -> Any:
        return self._veto

    @property
    def stateful(self) -> Any:
        return self._stateful

    def _coerce(self, consequence: Any) -> Any:
        """Normalize to this module's Consequence enum (cross-module safe)."""
        raw = (
            consequence.value
            if hasattr(consequence, "value")
            else str(consequence)
        )
        try:
            return _dveto.Consequence(raw)
        except ValueError:
            raise IntegrationError(f"unknown consequence {raw!r}")

    def add_rule(
        self,
        rule_id: str,
        consequence: Any,
        unwaivable: bool = True,
    ) -> None:
        """Add a veto rule, normalizing the consequence enum.

        Keeps the rule inside this module's enum class (cross-module safe).
        """
        cons = self._coerce(consequence)
        self._veto.add_rule(
            _dveto.VetoRule(rule_id, cons, unwaivable)
        )

    def model_escalate(self, rule_id: str, consequence: Any) -> None:
        """Model escalation (can only add, never remove)."""
        cons = self._coerce(consequence)
        self._veto.model_escalate(
            _dveto.VetoRule(rule_id, cons, unwaivable=False)
        )

    def decide(
        self,
        session_id: str,
        tool_name: str,
        consequence: Any,
        *,
        human_override: bool = False,
    ) -> tuple:
        """Decide: (allowed, reason).  Denials are recorded as risk."""
        if not session_id or not tool_name:
            raise IntegrationError("session_id and tool_name required")
        cons = self._coerce(consequence)
        limited, lr = self._stateful.should_rate_limit(
            session_id, tool_name, cons.value
        )
        if limited:
            return False, f"rate-limited: {lr}"
        vetoed, vr = self._veto.check(
            cons, human_override=human_override
        )
        if vetoed:
            self._stateful.record_deny(session_id, tool_name, cons.value)
            return False, f"vetoed: {vr}"
        return True, "allowed"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "importlib", "pathlib", "sys",
        "typing",
    }
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
    lv = LayeredVeto()
    lv.add_rule("no_broad", _dveto.Consequence.IRREVERSIBLE_BROAD)

    # Vetoed, and the denial is recorded as risk.
    allowed, reason = lv.decide(
        "s1", "rm", _dveto.Consequence.IRREVERSIBLE_BROAD
    )
    assert allowed is False and "vetoed" in reason
    assert lv.stateful.risk_score("s1") == 10

    # Retry limit -> rate-limited.
    lv.decide("s1", "rm", _dveto.Consequence.IRREVERSIBLE_BROAD)
    lv.decide("s1", "rm", _dveto.Consequence.IRREVERSIBLE_BROAD)
    allowed, reason = lv.decide(
        "s1", "rm", _dveto.Consequence.IRREVERSIBLE_BROAD
    )
    assert allowed is False and "rate-limited" in reason

    # Reversible: allowed.
    allowed, _ = lv.decide(
        "s2", "read", _dveto.Consequence.REVERSIBLE_LOW
    )
    assert allowed is True

    assert stdlib_only()
    print("integration-03 OK: layered veto, risk memory, stdlib")


if __name__ == "__main__":
    main()
