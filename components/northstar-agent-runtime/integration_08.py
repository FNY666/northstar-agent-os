"""Integration I-008: hop validation + floor settings (validated floor), Simulated.

A handoff hop is accepted only if (1) the payload passes per-hop schema
validation and (2) the sender's policy respects the root floors.

What this IS: a handoff acceptance gate.
What this IS NOT: not the transport -- payloads are plain dicts.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Dict, FrozenSet

#: Module version.
INTEGRATION_08_VERSION = "integration-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.integration-08.v1"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_hop = _load("hop_validation")
_floor = _load("floor_settings")


class IntegrationError(Exception):
    """Fail-closed."""


#: Re-exported for callers (same class identity as raised internally).
HopValidationError = _hop.HopValidationError
FloorError = _floor.FloorError


class FloorValidatedHandoff:
    """Accepts a hop only if schema-valid AND floor-respecting."""

    def __init__(self, enforcer: Any) -> None:
        if enforcer is None:
            raise IntegrationError("enforcer required")
        self._enforcer = enforcer

    def validate(
        self,
        payload: Dict[str, Any],
        schema: Any,
        policy_detectors: FrozenSet[str],
        policy_denies: FrozenSet[str],
        min_severity: int,
    ) -> Dict[str, Any]:
        """Validate hop, then check floors.  Raises on either failure."""
        validated = _hop.validate_hop(payload, schema)
        ok, reason = self._enforcer.check_policy(
            policy_detectors, policy_denies, min_severity
        )
        if not ok:
            raise IntegrationError(f"floor violated: {reason}")
        return validated


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
    schema = _hop.HopSchema(
        hop_id="h1",
        allowed_fields=frozenset({"task", "data"}),
        required_fields=frozenset({"task"}),
        max_size=1000,
    )
    enforcer = _floor.FloorEnforcer([
        _floor.Floor(
            "root",
            min_severity=50,
            required_detectors=frozenset({"injection"}),
            always_deny=frozenset({"rm_rf"}),
        )
    ])
    h = FloorValidatedHandoff(enforcer)

    v = h.validate(
        {"task": "do", "data": "x"}, schema,
        frozenset({"injection"}), frozenset({"rm_rf"}), 70,
    )
    assert v == {"task": "do", "data": "x"}

    # Unknown field: isolate.
    try:
        h.validate(
            {"task": "do", "evil": 1}, schema,
            frozenset({"injection"}), frozenset({"rm_rf"}), 70,
        )
        raise AssertionError("should raise")
    except _hop.HopValidationError:
        pass

    # Weak policy: floor violated.
    try:
        h.validate(
            {"task": "do"}, schema,
            frozenset(), frozenset({"rm_rf"}), 70,
        )
        raise AssertionError("should raise")
    except IntegrationError as e:
        assert "floor" in str(e)

    assert stdlib_only()
    print("integration-08 OK: validated floor, schema, stdlib")


if __name__ == "__main__":
    main()
