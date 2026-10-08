"""Per-hop schema validation (D10):防自复制注入, Simulated.

Injection propagates via agent handoffs.  The surviving defense:
per-hop Pydantic validation + JSON schema.  Mismatch -> isolate,
don't forward.

Untrusted content travels on a separate data channel, never spliced
into instructions.  The ledger detects payload growth anomalies.

What this IS: handoff validation for multi-agent chains.

What this IS NOT:
* Not a full schema validator -- minimal subset.
* Payload anomaly detection is heuristic, not ML.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

#: Module version.
HOP_VALIDATION_VERSION = "hop-validation.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.hop-validation.v1"


class HopValidationError(Exception):
    """Fail-closed: invalid handoffs raise."""


@dataclass(frozen=True)
class HopSchema:
    """Schema for one handoff hop."""

    hop_id: str
    allowed_fields: frozenset  # exact field names allowed
    required_fields: frozenset  # must be present
    # Max payload size (bytes) for anomaly detection.
    max_size: int = 10000


def validate_hop(
    payload: Dict[str, Any],
    schema: HopSchema,
) -> Dict[str, Any]:
    """Validate a handoff payload against its schema.

    Returns the validated payload (only allowed fields).
    Raises HopValidationError on:
    - Missing required fields
    - Unknown fields (isolate, don't forward)
    - Payload too large (anomaly)
    """
    if not isinstance(payload, dict):
        raise HopValidationError("payload must be dict")
    # Check required.
    missing = schema.required_fields - set(payload.keys())
    if missing:
        raise HopValidationError(f"missing required: {missing}")
    # Check for unknown fields (isolate).
    unknown = set(payload.keys()) - schema.allowed_fields
    if unknown:
        raise HopValidationError(
            f"unknown fields (isolate): {unknown}"
        )
    # Size check.
    import json
    size = len(json.dumps(payload).encode())
    if size > schema.max_size:
        raise HopValidationError(
            f"payload too large: {size} > {schema.max_size}"
        )
    # Return only allowed fields (defense in depth).
    return {k: payload[k] for k in schema.allowed_fields if k in payload}


def detect_growth_anomaly(
    sizes: List[int],
    *,
    threshold: float = 3.0,
) -> bool:
    """Detect payload growth anomaly.

    If the latest size is > threshold * median of previous, flag it.
    Returns True if anomaly detected.
    """
    if len(sizes) < 3:
        return False
    previous = sorted(sizes[:-1])
    median = previous[len(previous) // 2]
    if median == 0:
        return sizes[-1] > 0
    return sizes[-1] > threshold * median


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "json", "pathlib", "typing"}
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
    schema = HopSchema(
        hop_id="handoff1",
        allowed_fields=frozenset({"task", "data"}),
        required_fields=frozenset({"task"}),
        max_size=1000,
    )
    # Valid.
    v = validate_hop({"task": "do x", "data": "y"}, schema)
    assert v == {"task": "do x", "data": "y"}

    # Missing required.
    try:
        validate_hop({"data": "y"}, schema)
        raise AssertionError("should raise")
    except HopValidationError:
        pass

    # Unknown field (isolate).
    try:
        validate_hop(
            {"task": "x", "injected": "malicious"},
            schema,
        )
        raise AssertionError("should raise")
    except HopValidationError as e:
        assert "isolate" in str(e)

    # Growth anomaly.
    assert detect_growth_anomaly([100, 110, 105, 500]) is True
    assert detect_growth_anomaly([100, 110, 105, 120]) is False

    assert stdlib_only()
    print("hop-validation OK: schema, isolate, anomaly, stdlib")


if __name__ == "__main__":
    main()
