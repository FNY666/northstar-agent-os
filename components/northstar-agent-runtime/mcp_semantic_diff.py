"""MCP schema semantic diff: compare what a schema *means*, not its bytes.

The hash-based monitor (``mcp_drift_monitor.py``) answers one question —
"did the surface change?" — with a single bit. That is the right first
check, but it cannot tell a harmless change from a breaking one: a
description typo fix, a new *optional* field, and a removed required field
all look identical (``SCHEMA_CHANGED``).

This module is the second, complementary method. It *parses* the old and
new JSON Schemas and compares their meaning field by field, producing a
fixed vocabulary of semantic changes:

* ``field_added`` / ``field_removed`` — a property appeared or vanished.
  A removed field is always breaking; an added *required* field is
  breaking; an added optional field is not.
* ``type_narrowed`` / ``type_widened`` — e.g. ``any`` → ``string`` is
  narrowing (old inputs may now be rejected); ``string`` → ``any`` is
  widening. Incomparable type swaps (``string`` → ``integer``) are
  classified as narrowing — fail closed, since old valid inputs may break.
* ``constraint_tightened`` / ``constraint_loosened`` — e.g. raising
  ``minLength`` tightens; lowering it loosens. Shrinking an ``enum`` or
  changing a ``pattern`` tightens (equivalence is not provable cheaply).

``assess_semantic_risk`` applies the fail-closed policy: ``field_removed``
is always denied; narrowing or tightening on a security-sensitive tool
(name contains ``exec``/``shell``/``file``/``network``) is denied;
everything else is allowed *with the full change log carried* so the
approval layer can decide.

Honest scope: this is a *syntactic* semantic diff over a JSON Schema
subset (``type``, ``properties``, ``required``, ``enum``, ``minimum`` /
``maximum`` / ``exclusiveMinimum`` / ``exclusiveMaximum``,
``minLength`` / ``maxLength``, ``minItems`` / ``maxItems``,
``minProperties`` / ``maxProperties``, ``pattern``, ``format``). It does
not evaluate ``allOf``/``oneOf``/``$ref`` composition, does not run a
solver, and does not prove behavioral equivalence — a "non-breaking"
verdict means *no syntactic break was found*, not that none exists. It is
a detector, not a defense, and runs on host-reported ``tools/list``
responses.

Everything here is offline and deterministic. No network, no clock reads.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

#: Version pin for this method's vocabulary and policy.
MCP_SEMANTIC_DIFF_VERSION = "mcp-semantic-diff.v1"

#: Tool-name substrings that mark a security-sensitive capability.
_SENSITIVE_SUBSTRINGS = ("exec", "shell", "file", "network")

#: Constraint keys whose *increase* tightens the schema.
_TIGHTEN_ON_INCREASE = frozenset({
    "minLength", "minItems", "minProperties", "minimum", "exclusiveMinimum",
})

#: Constraint keys whose *decrease* tightens the schema.
_TIGHTEN_ON_DECREASE = frozenset({
    "maxLength", "maxItems", "maxProperties", "maximum", "exclusiveMaximum",
})

#: Constraint keys compared for this module's subset.
_KNOWN_CONSTRAINTS = frozenset({
    *_TIGHTEN_ON_INCREASE, *_TIGHTEN_ON_DECREASE, "enum", "pattern", "format",
})

_KNOWN_TYPES = frozenset({
    "any", "object", "array", "string", "integer", "number", "boolean", "null",
})


class SemanticChangeKind(str, Enum):
    """Fixed vocabulary for one semantic change between two schemas."""

    FIELD_ADDED = "field-added"
    FIELD_REMOVED = "field-removed"
    TYPE_NARROWED = "type-narrowed"
    TYPE_WIDENED = "type-widened"
    CONSTRAINT_TIGHTENED = "constraint-tightened"
    CONSTRAINT_LOOSENED = "constraint-loosened"


def _canonical_value(value: Any) -> str:
    """Canonical string form of a constraint value (for frozen storage)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


@dataclass(frozen=True)
class SchemaField:
    """One parsed property of an object schema.

    ``type`` is normalized to the known vocabulary (unknown or missing
    types become ``"any"``). ``constraints`` holds (name, canonical-value)
    pairs for the known constraint subset, sorted by name.
    """

    name: str
    type: str
    required: bool
    constraints: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("field name must be a non-empty string")
        if self.type not in _KNOWN_TYPES:
            raise ValueError(f"unknown normalized type: {self.type!r}")
        if not isinstance(self.required, bool):
            raise ValueError("required must be a bool")

    def constraint_map(self) -> dict[str, str]:
        return dict(self.constraints)


@dataclass(frozen=True)
class ParsedSchema:
    """A parsed object schema: its fields plus top-level requiredness."""

    fields: tuple[SchemaField, ...] = ()
    version: str = MCP_SEMANTIC_DIFF_VERSION

    def field_map(self) -> dict[str, SchemaField]:
        return {f.name: f for f in self.fields}


@dataclass(frozen=True)
class SemanticChange:
    """One semantic change between two schemas.

    ``breaking`` is syntactic breakage: an old-valid input the new schema
    may reject. ``detail`` is a human-readable one-liner for the log.
    """

    kind: SemanticChangeKind
    field: str
    detail: str
    breaking: bool

    def __post_init__(self) -> None:
        if not isinstance(self.field, str) or not self.field:
            raise ValueError("change field must be a non-empty string")
        if not isinstance(self.breaking, bool):
            raise ValueError("breaking must be a bool")


@dataclass(frozen=True)
class SemanticRiskAssessment:
    """Verdict of the risk policy over a list of semantic changes."""

    verdict: str  # "allow" or "deny"
    reasons: tuple[str, ...]
    changes: tuple[SemanticChange, ...]

    def __post_init__(self) -> None:
        if self.verdict not in ("allow", "deny"):
            raise ValueError("verdict must be 'allow' or 'deny'")


def _normalize_type(raw: Any) -> str:
    """Normalize a JSON Schema ``type`` value to the known vocabulary."""
    if isinstance(raw, str) and raw in _KNOWN_TYPES:
        return raw
    if isinstance(raw, list) and raw:
        # Union types: fail toward the widest reading is wrong; fail closed
        # toward "any" would hide narrowing, so treat multi-type unions as
        # "any" only when "any" is not itself present... simplest honest
        # rule: any union containing more than one distinct known type is
        # treated as "any" (permissive) — narrowing is then detected when
        # the union collapses to a single type.
        kinds = {t for t in raw if isinstance(t, str) and t in _KNOWN_TYPES}
        if len(kinds) == 1:
            return next(iter(kinds))
        return "any"
    return "any"


def _extract_constraints(prop: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """Extract the known constraint subset as sorted (name, value) pairs."""
    out: list[tuple[str, str]] = []
    for key in sorted(_KNOWN_CONSTRAINTS):
        if key in prop:
            out.append((key, _canonical_value(prop[key])))
    return tuple(out)


def parse_schema(schema: Any) -> ParsedSchema:
    """Parse a JSON Schema ``inputSchema`` into a ``ParsedSchema``.

    Only the object-property subset is modeled; anything else (missing
    ``properties``, non-mapping input) yields an empty field set rather
    than raising — an absent schema is "no constraint", not an error.
    Malformed *types* (non-mapping schema) raise ``ValueError``.
    """
    if schema is None:
        return ParsedSchema(fields=())
    if not isinstance(schema, Mapping):
        raise ValueError("schema must be a mapping or None")
    props = schema.get("properties")
    if props is None:
        return ParsedSchema(fields=())
    if not isinstance(props, Mapping):
        raise ValueError("schema 'properties' must be a mapping")
    required_raw = schema.get("required", [])
    required: set[str] = set()
    if isinstance(required_raw, (list, tuple)):
        required = {r for r in required_raw if isinstance(r, str)}
    fields: list[SchemaField] = []
    for name, prop in props.items():
        if not isinstance(name, str) or not name:
            raise ValueError("property names must be non-empty strings")
        if not isinstance(prop, Mapping):
            raise ValueError(f"property {name!r} must be a mapping")
        fields.append(SchemaField(
            name=name,
            type=_normalize_type(prop.get("type")),
            required=name in required,
            constraints=_extract_constraints(prop),
        ))
    fields.sort(key=lambda f: f.name)
    return ParsedSchema(fields=tuple(fields))


def _type_relation(old: str, new: str) -> SemanticChangeKind | None:
    """Classify a type change, or None when the type is unchanged."""
    if old == new:
        return None
    if new == "any":
        return SemanticChangeKind.TYPE_WIDENED
    if old == "any":
        return SemanticChangeKind.TYPE_NARROWED
    if old == "integer" and new == "number":
        return SemanticChangeKind.TYPE_WIDENED
    if old == "number" and new == "integer":
        return SemanticChangeKind.TYPE_NARROWED
    # Incomparable swap (string -> integer): old valid inputs may break.
    return SemanticChangeKind.TYPE_NARROWED


def _constraint_changes(old: SchemaField, new: SchemaField) -> list[SemanticChange]:
    """Diff constraints (and requiredness) between two versions of a field."""
    changes: list[SemanticChange] = []
    fname = old.name
    if old.required != new.required:
        if new.required:
            changes.append(SemanticChange(
                SemanticChangeKind.CONSTRAINT_TIGHTENED, fname,
                f"field '{fname}' became required", True))
        else:
            changes.append(SemanticChange(
                SemanticChangeKind.CONSTRAINT_LOOSENED, fname,
                f"field '{fname}' became optional", False))
    old_c = old.constraint_map()
    new_c = new.constraint_map()
    for key in sorted(set(old_c) | set(new_c)):
        ov, nv = old_c.get(key), new_c.get(key)
        if ov == nv:
            continue
        if key == "enum":
            # Compare as sets of canonical value strings (values may be
            # unhashable lists/dicts, so compare their canonical forms).
            def _eset(raw: str | None) -> set[str]:
                if raw is None:
                    return set()
                try:
                    vals = json.loads(raw)
                except (ValueError, TypeError):
                    return set()
                if not isinstance(vals, list):
                    return set()
                return {_canonical_value(v) for v in vals}
            oset, nset = _eset(ov), _eset(nv)
            if oset and nset and nset < oset:
                changes.append(SemanticChange(
                    SemanticChangeKind.CONSTRAINT_TIGHTENED, fname,
                    f"field '{fname}' enum shrank", True))
            elif oset and nset and nset > oset:
                changes.append(SemanticChange(
                    SemanticChangeKind.CONSTRAINT_LOOSENED, fname,
                    f"field '{fname}' enum grew", False))
            else:
                changes.append(SemanticChange(
                    SemanticChangeKind.CONSTRAINT_TIGHTENED, fname,
                    f"field '{fname}' enum changed incompatibly", True))
            continue
        if key in ("pattern", "format"):
            if ov is None or nv is None:
                kind = (SemanticChangeKind.CONSTRAINT_LOOSENED
                        if ov is not None else SemanticChangeKind.CONSTRAINT_TIGHTENED)
                breaking = kind is SemanticChangeKind.CONSTRAINT_TIGHTENED
                changes.append(SemanticChange(
                    kind, fname,
                    f"field '{fname}' {key} {'added' if ov is None else 'removed'}",
                    breaking))
            else:
                # Equivalence not provable cheaply: fail closed.
                changes.append(SemanticChange(
                    SemanticChangeKind.CONSTRAINT_TIGHTENED, fname,
                    f"field '{fname}' {key} changed", True))
            continue
        # Numeric bounds.
        try:
            of = float(json.loads(ov)) if ov is not None else None
            nf = float(json.loads(nv)) if nv is not None else None
        except (ValueError, TypeError):
            changes.append(SemanticChange(
                SemanticChangeKind.CONSTRAINT_TIGHTENED, fname,
                f"field '{fname}' {key} changed unparsably", True))
            continue
        if of is None or nf is None:
            kind = (SemanticChangeKind.CONSTRAINT_LOOSENED
                    if of is not None else SemanticChangeKind.CONSTRAINT_TIGHTENED)
            breaking = kind is SemanticChangeKind.CONSTRAINT_TIGHTENED
            changes.append(SemanticChange(
                kind, fname,
                f"field '{fname}' {key} {'removed' if of is not None else 'added'}",
                breaking))
        elif of == nf:
            continue
        elif key in _TIGHTEN_ON_INCREASE:
            tightened = nf > of
            changes.append(SemanticChange(
                SemanticChangeKind.CONSTRAINT_TIGHTENED if tightened
                else SemanticChangeKind.CONSTRAINT_LOOSENED, fname,
                f"field '{fname}' {key} {of} -> {nf}", tightened))
        else:  # _TIGHTEN_ON_DECREASE
            tightened = nf < of
            changes.append(SemanticChange(
                SemanticChangeKind.CONSTRAINT_TIGHTENED if tightened
                else SemanticChangeKind.CONSTRAINT_LOOSENED, fname,
                f"field '{fname}' {key} {of} -> {nf}", tightened))
    return changes


def semantic_diff(old_schema: Any, new_schema: Any) -> list[SemanticChange]:
    """Diff two JSON Schemas field by field; [] means no semantic change."""
    old = parse_schema(old_schema)
    new = parse_schema(new_schema)
    old_map = old.field_map()
    new_map = new.field_map()
    changes: list[SemanticChange] = []
    for name in sorted(set(old_map) | set(new_map)):
        of, nf = old_map.get(name), new_map.get(name)
        if of is None:
            changes.append(SemanticChange(
                SemanticChangeKind.FIELD_ADDED, name,
                f"field '{name}' added"
                + (" (required)" if nf.required else " (optional)"),
                nf.required))
        elif nf is None:
            changes.append(SemanticChange(
                SemanticChangeKind.FIELD_REMOVED, name,
                f"field '{name}' removed", True))
        else:
            tkind = _type_relation(of.type, nf.type)
            if tkind is not None:
                changes.append(SemanticChange(
                    tkind, name,
                    f"field '{name}' type {of.type} -> {nf.type}",
                    tkind is SemanticChangeKind.TYPE_NARROWED))
            changes.extend(_constraint_changes(of, nf))
    return changes


def is_sensitive_tool(name: Any) -> bool:
    """True when the tool name carries a sensitive-capability substring."""
    if not isinstance(name, str):
        return False
    lowered = name.lower()
    return any(sub in lowered for sub in _SENSITIVE_SUBSTRINGS)


def assess_semantic_risk(changes: Any,
                         is_sensitive: bool = False) -> SemanticRiskAssessment:
    """Apply the fail-closed policy over a semantic change list.

    * any ``field-removed`` -> deny (always breaking);
    * ``type-narrowed`` or ``constraint-tightened`` on a sensitive tool
      -> deny;
    * anything else -> allow, with the full change list carried for audit.
    """
    if not isinstance(is_sensitive, bool):
        raise ValueError("is_sensitive must be a bool")
    if not isinstance(changes, (list, tuple)):
        raise ValueError("changes must be a list or tuple")
    changes = tuple(changes)
    reasons: list[str] = []
    for ch in changes:
        if not isinstance(ch, SemanticChange):
            raise ValueError("changes must contain SemanticChange records")
        if ch.kind is SemanticChangeKind.FIELD_REMOVED:
            reasons.append(f"deny: field-removed '{ch.field}'")
        elif is_sensitive and ch.kind in (
                SemanticChangeKind.TYPE_NARROWED,
                SemanticChangeKind.CONSTRAINT_TIGHTENED):
            reasons.append(f"deny: {ch.kind.value} '{ch.field}' on sensitive tool")
    if reasons:
        return SemanticRiskAssessment("deny", tuple(reasons), changes)
    return SemanticRiskAssessment("allow", ("no blocking semantic change",), changes)


def check_schema_drift(old_schema: Any, new_schema: Any,
                       *, is_sensitive: bool = False) -> SemanticRiskAssessment:
    """One-call convenience: parse, diff, and assess two schemas."""
    return assess_semantic_risk(semantic_diff(old_schema, new_schema),
                                is_sensitive=is_sensitive)


def main() -> None:
    old = {"type": "object",
           "properties": {"path": {"type": "string", "minLength": 1}},
           "required": ["path"]}
    benign = {"type": "object",
              "properties": {"path": {"type": "string", "minLength": 1},
                             "mode": {"type": "string"}},
              "required": ["path"]}
    breaking = {"type": "object",
                "properties": {"path": {"type": "integer", "minLength": 5}},
                "required": ["path"]}

    r1 = check_schema_drift(old, benign)
    r2 = check_schema_drift(old, breaking)
    r3 = check_schema_drift(old, breaking, is_sensitive=True)
    assert r1.verdict == "allow", r1
    assert r2.verdict == "allow", r2  # non-sensitive: advisory only
    assert r3.verdict == "deny", r3
    print("mcp-semantic-diff OK: "
          f"benign={r1.verdict}, breaking-nonsensitive={r2.verdict}, "
          f"breaking-sensitive={r3.verdict}")


if __name__ == "__main__":
    main()
