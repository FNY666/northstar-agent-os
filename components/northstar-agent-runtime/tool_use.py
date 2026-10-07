"""Tool-use (function calling) registration and invocation bookkeeping, simulated.

Research motivation: function calling / tool use (OpenAI function
calling, Claude tool use) is the standard bridge between an LLM's text
output and real action: the model declares tools as JSON schemas,
emits structured calls, and the host validates, routes, and executes
them. Every credible implementation separates three concerns -- tool
*registration* (the schema catalog), invocation *booking* (which call
was made with which arguments), and invocation *execution* (running
the code). Mixing booking with execution is how double-invocations,
schema-drift bugs, and unaudited calls happen.

This module is the *registration + booking* layer:

- ``ToolUse.register(tool_id, schema, seq)`` -- declare a tool with a
  JSON-schema-shaped parameter schema. Returns a frozen ``ToolRecord``
  with a ``sha256:`` digest pin over the canonical schema. Duplicate
  ids are refused fail-closed; ids are never recycled.
- ``ToolUse.invoke(tool_id, arguments, seq)`` -- book one invocation
  decision for a registered tool. Returns a frozen
  ``InvocationRecord`` with a minted ``invoke-N`` id. Arguments are
  validated fail-closed against the registered schema (required
  properties, pinned type vocabulary). This books the *decision to
  call*, never proof of execution -- it deliberately never runs tool
  code. Execution safety belongs to the ``tools/`` package (effect
  envelopes, sandboxes, seccomp).
- ``ToolUse.schema(tool_id, seq)`` -- pure read view of the
  registered parameter schema (validates seq shape, consumes nothing,
  writes no audit row).
- ``tool_use_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``tool-registered`` / ``invoked`` / ``rejected``); caller-supplied
  seqs only. Raw arguments and raw schemas never cross the audit
  boundary -- audit rows carry ids and digest pins only.

Fail-closed edges (fail loudly, never guess):

- ``tool_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``schema`` must be a dict with ``"type": "object"``; ``properties``
  maps names to ``{"type": <vocab>}``; ``required`` must name declared
  properties; unknown top-level or per-property keys are refused.
  Type vocabulary: string / integer / number / boolean / array /
  object.
- ``arguments`` must be a dict; required properties must be present;
  unknown properties are refused; values must match their declared
  type (bool != int, ``|int| < 2**53``, finite floats only, bounded
  strings/arrays, str dict keys).
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* tools and *host-reported* invocation
  decisions. A booked invocation is a ledger entry, not proof the
  tool ran or that the arguments came from a real model -- arguments
  are GIGO: the module validates shape, not provenance or intent.
- An ``invoked`` booking is not an execution receipt. Pair bookings
  with the ``tools/`` execution-safety layer (effect envelopes,
  pledges, sandboxes) before anything real runs.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if tool-use state must survive a restart.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
TOOL_USE_VERSION = "tool-use.v1"

#: Schema pin carried by records and audit events.
TOOL_USE_SCHEMA = "northstar.tool-use.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_TOOL_REGISTERED = "tool-registered"
KIND_INVOKED = "invoked"
KIND_REJECTED = "rejected"
_KINDS = (KIND_TOOL_REGISTERED, KIND_INVOKED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"arguments", "args", "schema", "properties", "value", "payload",
     "raw", "data"})

#: Max tool-id length.
_MAX_TOOL_ID_LEN = 256

#: Max string argument length.
_MAX_STRING_LEN = 4096

#: Max array argument length.
_MAX_ARRAY_LEN = 1024

#: Pinned parameter-type vocabulary.
_TYPE_VOCABULARY = frozenset(
    {"string", "integer", "number", "boolean", "array", "object"})

#: Allowed top-level schema keys.
_SCHEMA_TOP_KEYS = frozenset({"type", "properties", "required", "description"})

#: Allowed per-property schema keys.
_PROPERTY_KEYS = frozenset({"type", "description"})


class ToolUseError(Exception):
    """Base error for the tool-use ledger (programming errors)."""


class BadToolError(ToolUseError):
    """Raised when a tool id is malformed."""


class DuplicateToolError(ToolUseError):
    """Raised when a tool id is registered twice."""


class UnknownToolError(ToolUseError):
    """Raised when a tool id names no registered tool."""


class BadSchemaError(ToolUseError):
    """Raised when a parameter schema is malformed."""


class BadArgumentsError(ToolUseError):
    """Raised when invocation arguments fail schema validation."""


class SeqOrderError(ToolUseError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(ToolUseError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_tool_id(tool_id: object) -> str:
    """Validate a tool id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(tool_id, bool) or not isinstance(tool_id, str):
        raise BadToolError(
            f"tool_id must be str, got {type(tool_id).__name__}")
    if not tool_id:
        raise BadToolError("tool_id must not be empty")
    if len(tool_id) > _MAX_TOOL_ID_LEN:
        raise BadToolError(f"tool_id too long (>{_MAX_TOOL_ID_LEN} chars)")
    if any(ch.isspace() for ch in tool_id):
        raise BadToolError("tool_id must not contain whitespace")
    return tool_id


def _canonicalizable(value: object) -> bool:
    """True when the value survives a JCS round-trip."""
    try:
        raw = jcs_canonical_json(value)
    except Exception:
        return False
    try:
        return jcs_canonical_json(json.loads(raw)) == raw
    except Exception:
        return False


def _walk_finite(value: object, where: str) -> None:
    """Refuse non-finite floats anywhere in a JSON-shaped value."""
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise BadArgumentsError(
                f"{where}: float must be finite, got {value!r}")
        return
    if isinstance(value, list):
        for item in value:
            _walk_finite(item, where)
        return
    if isinstance(value, dict):
        for item in value.values():
            _walk_finite(item, where)


def _check_schema(schema: object) -> Dict[str, object]:
    """Validate a parameter schema fail-closed; return a deep copy."""
    if isinstance(schema, bool) or not isinstance(schema, dict):
        raise BadSchemaError(
            f"schema must be dict, got {type(schema).__name__}")
    unknown = set(schema.keys()) - _SCHEMA_TOP_KEYS
    if unknown:
        raise BadSchemaError(
            f"schema has unknown top-level keys: {sorted(unknown)}")
    if schema.get("type") != "object":
        raise BadSchemaError('schema["type"] must be "object"')
    description = schema.get("description", "")
    if not isinstance(description, str):
        raise BadSchemaError("schema description must be str")
    if len(description) > _MAX_STRING_LEN:
        raise BadSchemaError("schema description too long")
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise BadSchemaError("schema properties must be dict")
    for name, spec in properties.items():
        if isinstance(name, bool) or not isinstance(name, str) or not name:
            raise BadSchemaError(f"bad property name: {name!r}")
        if isinstance(spec, bool) or not isinstance(spec, dict):
            raise BadSchemaError(
                f"property {name!r} spec must be dict")
        unknown_keys = set(spec.keys()) - _PROPERTY_KEYS
        if unknown_keys:
            raise BadSchemaError(
                f"property {name!r} has unknown keys: "
                f"{sorted(unknown_keys)}")
        if spec.get("type") not in _TYPE_VOCABULARY:
            raise BadSchemaError(
                f"property {name!r} has bad type: "
                f"{spec.get('type')!r}")
        prop_desc = spec.get("description", "")
        if not isinstance(prop_desc, str):
            raise BadSchemaError(
                f"property {name!r} description must be str")
    required = schema.get("required", [])
    if not isinstance(required, list):
        raise BadSchemaError("schema required must be a list")
    for name in required:
        if isinstance(name, bool) or not isinstance(name, str):
            raise BadSchemaError(f"bad required name: {name!r}")
        if name not in properties:
            raise BadSchemaError(
                f"required {name!r} not in properties")
    if not _canonicalizable(schema):
        raise BadSchemaError("schema is not JCS-canonicalizable")
    # Deep copy through the canonical round-trip: the stored schema is
    # exactly what the digest pins.
    return json.loads(jcs_canonical_json(schema).decode("utf-8"))


def _check_value(value: object, type_name: str, where: str) -> None:
    """Validate one argument value against a declared type."""
    if type_name == "string":
        if isinstance(value, bool) or not isinstance(value, str):
            raise BadArgumentsError(
                f"{where}: expected string, got {type(value).__name__}")
        if len(value) > _MAX_STRING_LEN:
            raise BadArgumentsError(f"{where}: string too long")
    elif type_name == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise BadArgumentsError(
                f"{where}: expected integer, got {type(value).__name__}")
        if abs(value) >= 2 ** 53:
            raise BadArgumentsError(f"{where}: integer out of safe range")
    elif type_name == "number":
        if isinstance(value, bool):
            raise BadArgumentsError(f"{where}: expected number, got bool")
        if isinstance(value, int):
            if abs(value) >= 2 ** 53:
                raise BadArgumentsError(
                    f"{where}: number out of safe range")
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise BadArgumentsError(
                    f"{where}: number must be finite, got {value!r}")
        else:
            raise BadArgumentsError(
                f"{where}: expected number, got {type(value).__name__}")
    elif type_name == "boolean":
        if not isinstance(value, bool):
            raise BadArgumentsError(
                f"{where}: expected boolean, got {type(value).__name__}")
    elif type_name == "array":
        if isinstance(value, bool) or not isinstance(value, list):
            raise BadArgumentsError(
                f"{where}: expected array, got {type(value).__name__}")
        if len(value) > _MAX_ARRAY_LEN:
            raise BadArgumentsError(f"{where}: array too long")
        _walk_finite(value, where)
    elif type_name == "object":
        if isinstance(value, bool) or not isinstance(value, dict):
            raise BadArgumentsError(
                f"{where}: expected object, got {type(value).__name__}")
        for key in value.keys():
            if isinstance(key, bool) or not isinstance(key, str):
                raise BadArgumentsError(
                    f"{where}: object keys must be str")
        _walk_finite(value, where)
    else:  # pragma: no cover - unreachable: types come from _TYPE_VOCABULARY
        raise BadArgumentsError(f"{where}: unknown type {type_name!r}")


def _check_arguments(schema: Dict[str, object],
                     arguments: object) -> Dict[str, object]:
    """Validate invocation arguments against a schema; return a copy."""
    if isinstance(arguments, bool) or not isinstance(arguments, dict):
        raise BadArgumentsError(
            f"arguments must be dict, got {type(arguments).__name__}")
    properties = schema.get("properties", {})
    assert isinstance(properties, dict)
    required = schema.get("required", [])
    assert isinstance(required, list)
    for name in required:
        if name not in arguments:
            raise BadArgumentsError(
                f"missing required argument: {name!r}")
    for name, value in arguments.items():
        if isinstance(name, bool) or not isinstance(name, str):
            raise BadArgumentsError(
                f"argument keys must be str, got {type(name).__name__}")
        if name not in properties:
            raise BadArgumentsError(
                f"unknown argument: {name!r}")
        spec = properties[name]
        assert isinstance(spec, dict)
        type_name = spec.get("type")
        assert isinstance(type_name, str)
        _check_value(value, type_name, f"argument {name!r}")
    if not _canonicalizable(arguments):
        raise BadArgumentsError("arguments are not JCS-canonicalizable")
    return json.loads(jcs_canonical_json(arguments).decode("utf-8"))


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": TOOL_USE_SCHEMA,
        "parts": list(parts),
    })


def tool_use_audit_event(kind: str, detail: Dict[str, object],
                         seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the tool-use ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": TOOL_USE_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class ToolRecord:
    """Frozen record of a registered tool."""
    tool_id: str
    # Canonical copy of the parameter schema.
    schema: Dict[str, object]
    # Digest pin over the canonical schema.
    schema_digest: str
    seq: int
    digest: str

    def verify(self, tool_id: str, schema: Dict[str, object]) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("tool", tool_id, schema, self.seq)


@dataclass(frozen=True)
class InvocationRecord:
    """Frozen record of one booked invocation decision."""
    invocation_id: str
    tool_id: str
    # Canonical copy of the validated arguments (booking, not execution).
    arguments: Dict[str, object]
    seq: int
    digest: str

    def verify(self, tool_id: str,
               arguments: Dict[str, object]) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("invoke", self.invocation_id, tool_id,
                                   arguments, self.seq)


@dataclass(frozen=True)
class SchemaReport:
    """Pure read view of a registered parameter schema (no seq consumed)."""
    tool_id: str
    # Canonical copy of the parameter schema.
    schema: Dict[str, object]
    schema_digest: str
    seq: int


@dataclass(frozen=True)
class ToolStats:
    """Ledger counts as data (not a record)."""
    tools: int
    invocations: int


class ToolUse:
    """Deterministic tool registration and invocation-booking ledger.

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:`` digest
    pins plus ``audit.ndjson/1`` rows. No wall-clock, no randomness,
    and -- deliberately -- no tool execution.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tools: Dict[str, ToolRecord] = {}
        self._invocations: Dict[str, InvocationRecord] = {}
        self._invoke_counter = 0
        self._last_seq = 0
        self._audit: List[Dict[str, object]] = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq: object) -> int:
        """Validate seq; rewinds raise bare (no consumption)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing "
                f"(last={self._last_seq}, got={seq})")
        return seq

    def _burn(self, seq: int, error: Exception) -> None:
        """Consume the seq, book a rejected row, then raise."""
        self._last_seq = seq
        self._audit.append(tool_use_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, kind: str, detail: Dict[str, object], seq: int) -> None:
        self._audit.append(tool_use_audit_event(kind, detail, seq))

    # -- mutations ---------------------------------------------------------

    def register(self, tool_id: object, schema: object,
                 seq: object) -> ToolRecord:
        """Register a tool with a parameter schema; duplicates refused."""
        with self._lock:
            seq = self._claim(seq)
            try:
                tool_id = _check_tool_id(tool_id)
                if tool_id in self._tools:
                    raise DuplicateToolError(
                        f"tool already registered: {tool_id!r}")
                schema = _check_schema(schema)
            except ToolUseError as e:
                self._burn(seq, e)
            schema_digest = _pin("tool-schema", tool_id, schema)
            rec = ToolRecord(tool_id=tool_id, schema=schema,
                             schema_digest=schema_digest, seq=seq,
                             digest=_pin("tool", tool_id, schema, seq))
            self._tools[tool_id] = rec
            self._last_seq = seq
            # Raw schema banned from the audit boundary: digest pin only.
            self._emit(KIND_TOOL_REGISTERED,
                       {"tool_id": tool_id, "schema_digest": schema_digest,
                        "digest": rec.digest}, seq)
            return rec

    def invoke(self, tool_id: object, arguments: object,
               seq: object) -> InvocationRecord:
        """Book one invocation decision; arguments validated fail-closed.

        This books the *decision to call*. It never executes tool code.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                tool_id = _check_tool_id(tool_id)
                if tool_id not in self._tools:
                    raise UnknownToolError(f"unknown tool: {tool_id!r}")
                arguments = _check_arguments(
                    self._tools[tool_id].schema, arguments)
            except ToolUseError as e:
                self._burn(seq, e)
            self._invoke_counter += 1
            invocation_id = f"invoke-{self._invoke_counter}"
            rec = InvocationRecord(
                invocation_id=invocation_id, tool_id=tool_id,
                arguments=arguments, seq=seq,
                digest=_pin("invoke", invocation_id, tool_id,
                            arguments, seq))
            self._invocations[invocation_id] = rec
            self._last_seq = seq
            # Raw arguments banned from the audit boundary: digest pin.
            self._emit(KIND_INVOKED,
                       {"invocation_id": invocation_id,
                        "tool_id": tool_id, "digest": rec.digest}, seq)
            return rec

    # -- views --------------------------------------------------------------

    def schema(self, tool_id: object, seq: object) -> SchemaReport:
        """Pure read view of a tool's parameter schema (no seq consumed)."""
        _check_seq(seq)
        tool_id = _check_tool_id(tool_id)
        rec = self._tools.get(tool_id)
        if rec is None:
            raise UnknownToolError(f"unknown tool: {tool_id!r}")
        # Deep copy through the canonical round-trip: the view must not
        # alias the stored schema's nested structures.
        schema_copy = json.loads(
            jcs_canonical_json(rec.schema).decode("utf-8"))
        return SchemaReport(tool_id=tool_id, schema=schema_copy,
                            schema_digest=rec.schema_digest, seq=seq)

    def tool_record(self, tool_id: str) -> Optional[ToolRecord]:
        """Return the tool record, or None when unknown (pure read)."""
        return self._tools.get(tool_id)

    def tool_ids(self) -> Tuple[str, ...]:
        """Sorted registered tool ids (pure read)."""
        return tuple(sorted(self._tools))

    def invocation(self, invocation_id: str) -> Optional[InvocationRecord]:
        """Return the invocation record, or None when unknown (pure read)."""
        return self._invocations.get(invocation_id)

    def invocation_ids(self) -> Tuple[str, ...]:
        """Booked invocation ids in booking order (pure read)."""
        return tuple(sorted(self._invocations,
                            key=lambda i: int(i.split("-")[1])))

    def stats(self, seq: object) -> ToolStats:
        """Ledger counts as data: seq validated, never consumed."""
        _check_seq(seq)
        return ToolStats(tools=len(self._tools),
                         invocations=len(self._invocations))

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Booked audit rows, oldest first (pure read)."""
        return tuple(self._audit)


def main() -> None:
    """Self-check: register, schema view, invoke, fail-closed edges."""
    tu = ToolUse()
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
            "verbose": {"type": "boolean"},
        },
        "required": ["query"],
        "description": "search the corpus",
    }
    rec = tu.register("search", schema, 1)
    assert rec.verify("search", rec.schema)
    view = tu.schema("search", 2)
    assert view.schema_digest == rec.schema_digest
    assert view.schema["required"] == ["query"]
    inv = tu.invoke("search", {"query": "northstar", "limit": 5}, 3)
    assert inv.verify("search", inv.arguments)
    assert inv.invocation_id == "invoke-1"
    # Fail-closed edges.
    try:
        tu.register("search", schema, 4)
    except DuplicateToolError:
        pass
    else:
        raise AssertionError("duplicate register must refuse")
    try:
        tu.invoke("search", {"limit": 5}, 5)  # missing required
    except BadArgumentsError:
        pass
    else:
        raise AssertionError("missing required must refuse")
    try:
        tu.invoke("nope", {}, 6)
    except UnknownToolError:
        pass
    else:
        raise AssertionError("unknown tool must refuse")
    # Seq was consumed by the failed mutations: next valid seq is 7.
    inv2 = tu.invoke("search", {"query": "x"}, 7)
    assert inv2.invocation_id == "invoke-2"
    # Pure reads consumed nothing.
    assert tu.stats(7).invocations == 2
    kinds = [row["kind"] for row in tu.audit_log()]
    assert kinds == ["tool-registered", "invoked", "rejected", "rejected",
                     "rejected", "invoked"], kinds
    print("tool-use OK: register, schema view, invoke, fail-closed, audit")


if __name__ == "__main__":
    main()
