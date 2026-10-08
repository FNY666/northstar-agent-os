"""Structured gate outputs: schema-enforced verdicts (XGrammar/Outlines), Simulated.

Gate verdicts must be machine-parseable.  Define JSON-schema contracts
for each verdict type.  Validators enforce the schema; malformed
verdicts are rejected (fail-closed).

Eliminates: broken JSON, silent fallback to defaults, unparseable
reasoning.

What this IS: contract enforcement for gate outputs.

What this IS NOT:
* Not a full JSON-schema validator -- minimal subset.
* The schema definitions are host-provided.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

#: Module version.
STRUCTURED_OUTPUT_VERSION = "structured-output.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.structured-output.v1"


class StructuredOutputError(Exception):
    """Fail-closed: schema violations raise."""


@dataclass(frozen=True)
class FieldSpec:
    """Specification for one field."""

    name: str
    type: str  # "str", "int", "float", "bool", "list", "dict"
    required: bool = True
    allowed_values: Optional[List[Any]] = None


@dataclass(frozen=True)
class VerdictSchema:
    """Schema for a gate verdict type."""

    schema_id: str
    fields: List[FieldSpec]


def validate(
    data: Dict[str, Any],
    schema: VerdictSchema,
) -> Dict[str, Any]:
    """Validate data against schema.  Returns validated dict.

    Raises StructuredOutputError on any violation (fail-closed).
    Strips unknown fields (defense against injection via extra fields).
    """
    if not isinstance(data, dict):
        raise StructuredOutputError("data must be dict")
    result = {}
    for field in schema.fields:
        if field.name not in data:
            if field.required:
                raise StructuredOutputError(
                    f"missing required field '{field.name}'"
                )
            continue
        value = data[field.name]
        # Type check.
        type_map = {
            "str": str, "int": int, "float": float,
            "bool": bool, "list": list, "dict": dict,
        }
        expected = type_map.get(field.type)
        if expected is None:
            raise StructuredOutputError(f"unknown type '{field.type}'")
        # Special: bool is subclass of int, so check explicitly.
        if field.type == "int" and isinstance(value, bool):
            raise StructuredOutputError(
                f"field '{field.name}' must be int, not bool"
            )
        if not isinstance(value, expected):
            raise StructuredOutputError(
                f"field '{field.name}' must be {field.type}"
            )
        # Allowed values check.
        if field.allowed_values is not None:
            if value not in field.allowed_values:
                raise StructuredOutputError(
                    f"field '{field.name}' value not allowed"
                )
        result[field.name] = value
    return result


# Predefined schemas for common verdicts.
GATE_VERDICT_SCHEMA = VerdictSchema(
    schema_id="gate_verdict.v1",
    fields=[
        FieldSpec("verdict", "str", True, ["allow", "deny"]),
        FieldSpec("reason", "str", True),
        FieldSpec("tool", "str", True),
        FieldSpec("policy_version", "str", False),
    ],
)

TRIPWIRE_SCHEMA = VerdictSchema(
    schema_id="tripwire.v1",
    fields=[
        FieldSpec("outcome", "str", True, ["allow", "reject_content", "halt"]),
        FieldSpec("reason", "str", True),
        FieldSpec("substitute_message", "str", False),
    ],
)


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
    # Valid.
    v = validate(
        {"verdict": "allow", "reason": "ok", "tool": "read"},
        GATE_VERDICT_SCHEMA,
    )
    assert v["verdict"] == "allow"

    # Missing required.
    try:
        validate({"verdict": "allow"}, GATE_VERDICT_SCHEMA)
        raise AssertionError("should raise")
    except StructuredOutputError:
        pass

    # Wrong type.
    try:
        validate(
            {"verdict": "allow", "reason": 123, "tool": "t"},
            GATE_VERDICT_SCHEMA,
        )
        raise AssertionError("should raise")
    except StructuredOutputError:
        pass

    # Disallowed value.
    try:
        validate(
            {"verdict": "maybe", "reason": "x", "tool": "t"},
            GATE_VERDICT_SCHEMA,
        )
        raise AssertionError("should raise")
    except StructuredOutputError:
        pass

    # Unknown fields stripped.
    v = validate(
        {"verdict": "deny", "reason": "x", "tool": "t", "evil": "injected"},
        GATE_VERDICT_SCHEMA,
    )
    assert "evil" not in v

    assert stdlib_only()
    print("structured-output OK: schema validation, fail-closed, stdlib")


if __name__ == "__main__":
    main()
