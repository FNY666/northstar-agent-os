"""State 08: additive schema evolution, Simulated.

Rules: fields may be ADDED (with defaults) or DEPRECATED (kept readable).
Fields may never be RENAMED or have their type changed in place.

evolve(schema, changes) validates a proposed schema delta against the
rules and returns the new schema.  apply_defaults(state, schema) fills
missing fields with declared defaults.

Fail-closed: rename, type change, or required-without-default raises.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List

MODULE_VERSION = "state-mgmt-08.v1"
SCHEMA_PIN = "northstar.state-mgmt-08.v1"


class EvolutionError(Exception):
    pass


@dataclass(frozen=True)
class Field:
    name: str
    type: str  # "int" | "str" | "list" | "dict" | "bool"
    default: Any = None
    required: bool = False
    deprecated: bool = False


@dataclass
class Schema:
    version: str
    fields: Dict[str, Field] = field(default_factory=dict)


_TYPEMAP = {"int": int, "str": str, "list": list, "dict": dict, "bool": bool}


def evolve(schema: Schema, add: List[Field], deprecate: List[str]) -> Schema:
    """Validate and apply additive changes. Returns new Schema."""
    new_fields = dict(schema.fields)
    for f in add:
        if f.name in new_fields:
            old = new_fields[f.name]
            if old.type != f.type:
                raise EvolutionError(f"type change forbidden: {f.name}")
            # re-adding same field is a no-op
            continue
        if f.type not in _TYPEMAP:
            raise EvolutionError(f"unknown type {f.type!r}")
        if f.required and f.default is None and f.type != "bool":
            raise EvolutionError(f"required field {f.name!r} needs a default")
        new_fields[f.name] = f
    for name in deprecate:
        if name not in new_fields:
            raise EvolutionError(f"cannot deprecate unknown field {name!r}")
        old = new_fields[name]
        new_fields[name] = Field(old.name, old.type, old.default, old.required, True)
    return Schema(version=schema.version + "+1", fields=new_fields)


def apply_defaults(state: Dict[str, Any], schema: Schema) -> Dict[str, Any]:
    """Fill missing non-deprecated fields with defaults. Validates types."""
    if not isinstance(state, dict):
        raise EvolutionError("state must be dict")
    out = dict(state)
    for name, f in schema.fields.items():
        if f.deprecated:
            continue
        if name not in out:
            if f.required:
                raise EvolutionError(f"missing required field {name!r}")
            out[name] = f.default
        else:
            exp = _TYPEMAP[f.type]
            if f.type == "int" and isinstance(out[name], bool):
                raise EvolutionError(f"{name!r} must be int, not bool")
            if not isinstance(out[name], exp):
                raise EvolutionError(f"{name!r} must be {f.type}")
    return out


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    s0 = Schema("v1", {"seq": Field("seq", "int", 0, True)})
    s1 = evolve(s0, [Field("tags", "list", [])], [])
    assert "tags" in s1.fields
    st = apply_defaults({"seq": 5}, s1)
    assert st == {"seq": 5, "tags": []}
    # Type change forbidden
    try:
        evolve(s0, [Field("seq", "str", "")], [])
        raise AssertionError("should raise")
    except EvolutionError:
        pass
    # Deprecate unknown
    try:
        evolve(s0, [], ["nope"])
        raise AssertionError("should raise")
    except EvolutionError:
        pass
    # Required without default
    try:
        evolve(s0, [Field("x", "int", None, True)], [])
        raise AssertionError("should raise")
    except EvolutionError:
        pass
    assert stdlib_only()
    print("state_mgmt_08 OK: additive evolution, defaults, fail-closed")


if __name__ == "__main__":
    main()
