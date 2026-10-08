"""Adaptive authentication (mock), Simulated.

Maps a 0..100 risk score to the required authentication strength:
none < password < otp < step-up < deny.  Higher risk demands
stronger proof.

What this IS: policy mapping from risk to auth strength.

What this IS NOT:
* Not a credential verifier -- the factors are host-checked.
* Score out of range FAILS CLOSED (deny).
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
DEF_EXTRA_06_VERSION = "def-extra-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-06.v1"


class AdaptiveAuthError(Exception):
    """Fail-closed."""


#: Ordered levels, weakest to strongest.
LEVELS: List[str] = ["none", "password", "otp", "step-up", "deny"]


def required_level(risk_score: float) -> str:
    """Map 0..100 risk score to required auth level."""
    if not 0.0 <= risk_score <= 100.0:
        raise AdaptiveAuthError("risk_score must be 0..100")
    if risk_score >= 75.0:
        return "deny"
    if risk_score >= 50.0:
        return "step-up"
    if risk_score >= 25.0:
        return "otp"
    if risk_score > 0.0:
        return "password"
    return "none"


def level_rank(level: str) -> int:
    """Numeric rank of a level (higher = stronger)."""
    if level not in LEVELS:
        raise AdaptiveAuthError(f"unknown level: {level}")
    return LEVELS.index(level)


def evaluate(
    risk_score: float, presented_factors: List[str]
) -> Tuple[bool, str]:
    """Check presented factors meet the required level.

    ``presented_factors`` are factor names the host verified, e.g.
    ["password", "otp"].  The strongest presented factor must rank at
    or above the required level.  "deny" can never be satisfied.
    Returns (ok, required_level).
    """
    required = required_level(risk_score)
    if required == "deny":
        return False, required
    if not presented_factors:
        return required == "none", required
    best = max(level_rank(f) for f in presented_factors)
    return best >= level_rank(required), required


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    assert required_level(0.0) == "none"
    assert required_level(10.0) == "password"
    assert required_level(30.0) == "otp"
    assert required_level(60.0) == "step-up"
    assert required_level(90.0) == "deny"
    ok, req = evaluate(30.0, ["password", "otp"])
    assert ok is True and req == "otp"
    ok, req = evaluate(30.0, ["password"])
    assert ok is False and req == "otp"
    ok, req = evaluate(90.0, ["password", "otp", "step-up"])
    assert ok is False and req == "deny"
    ok, req = evaluate(0.0, [])
    assert ok is True and req == "none"
    try:
        required_level(101.0)
    except AdaptiveAuthError:
        pass
    else:
        raise AssertionError("expected AdaptiveAuthError")
    assert stdlib_only()
    print("def-extra-06 OK: levels, evaluation, fail-closed")


if __name__ == "__main__":
    main()
