"""JSON schema subset validation (input defense), Simulated

What this IS: Validates dict payloads against a minimal JSON-schema subset (required fields, types, enums, string length). Malformed input is rejected before it reaches tool logic.

What this IS NOT:
* Subset only: no $ref, no nested allOf, no format validators.
* For full JSON Schema use a dedicated library.
"""

from __future__ import annotations



#: Module version.
MODULE_VERSION = "input-defense-28.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-28.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'typing', 'ast'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


_TYPES = {"str": str, "int": int, "float": (int, float), "bool": bool,
          "list": list, "dict": dict}


def validate(payload, schema):
    """Validate payload dict against schema dict. Raises on violation.

    Schema example:
      {"required": ["name"], "properties": {"name": {"type": "str",
       "max_len": 50, "enum": ["a", "b"]}}, "no_extra": True}
    """
    if not isinstance(payload, dict):
        raise InputDefenseError("payload must be dict")
    if not isinstance(schema, dict):
        raise InputDefenseError("schema must be dict")
    for field in schema.get("required", []):
        if field not in payload:
            raise InputDefenseError("missing required field: %r" % field)
    props = schema.get("properties", {})
    for field, value in payload.items():
        spec = props.get(field)
        if spec is None:
            if schema.get("no_extra"):
                raise InputDefenseError("unexpected field: %r" % field)
            continue
        expected = _TYPES.get(spec.get("type"))
        if expected is None:
            raise InputDefenseError("unknown type for %r" % field)
        if spec.get("type") == "int" and isinstance(value, bool):
            raise InputDefenseError("field %r must be int, not bool" % field)
        if not isinstance(value, expected):
            raise InputDefenseError(
                "field %r must be %s" % (field, spec.get("type")))
        if "enum" in spec and value not in spec["enum"]:
            raise InputDefenseError("field %r not in enum" % field)
        if isinstance(value, str):
            if "max_len" in spec and len(value) > spec["max_len"]:
                raise InputDefenseError("field %r too long" % field)
            if "min_len" in spec and len(value) < spec["min_len"]:
                raise InputDefenseError("field %r too short" % field)
    return True



def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in ALLOWED_IMPORTS:
                return False
    return True


def main() -> None:
    """Self-check."""
    schema = {"required": ["name"],
              "properties": {"name": {"type": "str", "max_len": 10},
                             "age": {"type": "int"}},
              "no_extra": True}
    assert validate({"name": "bob", "age": 3}, schema) is True
    for bad in ({"age": 3}, {"name": "x" * 11, "age": 1},
                {"name": "b", "age": True}, {"name": "b", "zzz": 1}):
        try:
            validate(bad, schema)
            raise AssertionError("should raise for %r" % (bad,))
        except InputDefenseError:
            pass
    try:
        validate("notadict", schema)
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-28.v1 OK")


if __name__ == "__main__":
    main()
