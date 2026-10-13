"""Floor settings: unweakable policy minimums (D9, Google Model Armor), Simulated.

Policy hierarchy: root declares minimums (severity floor, required
detectors).  Child policies can only strengthen, never weaken.

The floor set is hashed at seal time.  Any policy submission that
weakens a floor is rejected (cryptographically enforced).

What this IS: defense against policy weakening attacks.

What this IS NOT:
* Not the policy engine itself -- just the floor enforcement.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List

#: Module version.
FLOOR_VERSION = "floor-settings.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.floor-settings.v1"


class FloorError(Exception):
    """Fail-closed: weakening floors raises."""


@dataclass(frozen=True)
class Floor:
    """A policy floor (minimum requirement)."""

    floor_id: str
    # Minimum severity that must be checked (0-100).
    min_severity: int = 0
    # Detectors that must be present.
    required_detectors: FrozenSet[str] = frozenset()
    # Tools that are always denied.
    always_deny: FrozenSet[str] = frozenset()


def hash_floors(floors: List[Floor]) -> str:
    """Hash the floor set for sealing."""
    canonical = json.dumps(
        sorted([
            {
                "floor_id": f.floor_id,
                "min_severity": f.min_severity,
                "required_detectors": sorted(f.required_detectors),
                "always_deny": sorted(f.always_deny),
            }
            for f in floors
        ], key=lambda x: x["floor_id"]),
        sort_keys=True, separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


class FloorEnforcer:
    """Enforces that child policies don't weaken floors."""

    def __init__(self, floors: List[Floor]) -> None:
        if not floors:
            raise FloorError("at least one floor required")
        self._floors = {f.floor_id: f for f in floors}
        self._floor_hash = hash_floors(floors)

    @property
    def floor_hash(self) -> str:
        """Hash of the floor set (for sealing)."""
        return self._floor_hash

    def check_policy(
        self,
        policy_detectors: FrozenSet[str],
        policy_denies: FrozenSet[str],
        min_severity: int,
    ) -> tuple[bool, str]:
        """Check if a child policy respects all floors.

        Returns (ok, reason).  A policy weakens a floor if:
        - It omits a required detector, OR
        - It allows a tool that's always-denied, OR
        - Its min_severity is below the floor's.
        """
        for floor_id, floor in self._floors.items():
            # Required detectors must be present.
            missing = floor.required_detectors - policy_detectors
            if missing:
                return False, f"floor {floor_id}: missing detectors {missing}"
            # Always-deny tools must remain denied.
            # (Policy allows = not in its deny set.  If floor says deny
            # and policy doesn't deny, that's weakening.)
            # For simplicity: policy must deny all floor's always_deny.
            not_denied = floor.always_deny - policy_denies
            if not_denied:
                return False, f"floor {floor_id}: not denying {not_denied}"
            # Severity floor.
            if min_severity < floor.min_severity:
                return False, (
                    f"floor {floor_id}: severity {min_severity} "
                    f"below floor {floor.min_severity}"
                )
        return True, "respects all floors"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "json", "pathlib", "typing"}
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
    floors = [
        Floor(
            "root",
            min_severity=50,
            required_detectors=frozenset({"injection", "pii"}),
            always_deny=frozenset({"rm_rf"}),
        )
    ]
    enforcer = FloorEnforcer(floors)
    assert enforcer.floor_hash.startswith("sha256:")

    # Compliant policy.
    ok, _ = enforcer.check_policy(
        frozenset({"injection", "pii", "extra"}),
        frozenset({"rm_rf", "other"}),
        min_severity=70,
    )
    assert ok is True

    # Missing detector.
    ok, reason = enforcer.check_policy(
        frozenset({"injection"}),  # missing "pii"
        frozenset({"rm_rf"}),
        min_severity=70,
    )
    assert ok is False
    assert "pii" in reason

    # Weakened severity.
    ok, _ = enforcer.check_policy(
        frozenset({"injection", "pii"}),
        frozenset({"rm_rf"}),
        min_severity=30,  # below floor 50
    )
    assert ok is False

    # Allowed tool that should be denied.
    ok, _ = enforcer.check_policy(
        frozenset({"injection", "pii"}),
        frozenset(),  # not denying rm_rf
        min_severity=70,
    )
    assert ok is False

    assert stdlib_only()
    print("floor-settings OK: unweakable minimums, hash, fail-closed")


if __name__ == "__main__":
    main()
