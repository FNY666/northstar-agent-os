"""Fail-closed validation for runtime tool arguments.

The optional json-schema extra provides Draft 2020-12 (and Draft 7) with local
reference resolution and bounded regular-expression evaluation. A dependency-
free subset remains available for installations that do not enable the extra.
"""
from __future__ import annotations

import json
import math
import time
from contextvars import ContextVar
from typing import Any

try:  # Optional: install the json-schema extra for MCP 2020-12 support.
    import jsonschema as _jsonschema
    from jsonschema import Draft7Validator as _Draft7Validator
    from jsonschema import Draft202012Validator as _Draft202012Validator
    from jsonschema import validators as _jsonschema_validators
    from referencing import Registry as _SchemaRegistry
except ImportError:  # pragma: no cover - covered in minimal-install CI
    _jsonschema = None
    _Draft7Validator = None
    _Draft202012Validator = None
    _jsonschema_validators = None
    _SchemaRegistry = None

try:  # The timeout-capable engine prevents hostile patterns from blocking a run.
    import regex as _safe_regex
except ImportError:  # pragma: no cover - covered in minimal-install CI
    _safe_regex = None


_REGEX_DEADLINE: ContextVar[float] = ContextVar("tool_schema_regex_deadline", default=0.0)
_REGEX_BUDGET_SECONDS = 0.25
_REGEX_PER_MATCH_SECONDS = 0.025
MAX_SCHEMA_TREE_BYTES = 1_048_576
MAX_SCHEMA_TREE_NODES = 50_000
MAX_SCHEMA_TREE_DEPTH = 32


def _json_string_size_estimate(value: str) -> int:
    """Conservatively estimate ensure_ascii JSON bytes without allocating a copy."""
    estimated = len(value) * 6
    # Six ASCII characters cover every BMP code point's \uXXXX escape. A
    # non-BMP code point is encoded as a surrogate pair (12 characters).
    # The common ASCII case stays on C-level fast paths; scan Unicode only when
    # its baseline estimate could still fit the aggregate tree budget.
    if estimated > MAX_SCHEMA_TREE_BYTES or value.isascii():
        return estimated
    for character in value:
        if ord(character) > 0xFFFF:
            estimated += 6
            if estimated > MAX_SCHEMA_TREE_BYTES:
                break
    return estimated


class _SchemaValidationResourceError(RuntimeError):
    """Validation stopped because an untrusted schema exceeded its time budget."""


def _bounded_pattern(validator: Any, pattern: str, instance: Any, schema: dict[str, Any]):
    if not isinstance(instance, str):
        return
    if len(pattern) > 2048:
        raise _SchemaValidationResourceError("schema pattern exceeds the 2048 character limit")
    if _safe_regex is None:
        raise _SchemaValidationResourceError("pattern validation requires the regex extra")
    remaining = _REGEX_DEADLINE.get() - time.monotonic()
    if remaining <= 0:
        raise _SchemaValidationResourceError("schema validation time budget exceeded")
    try:
        matched = _safe_regex.search(
            pattern,
            instance,
            timeout=min(remaining, _REGEX_PER_MATCH_SECONDS),
        ) is not None
    except TimeoutError:
        raise _SchemaValidationResourceError("schema pattern validation timed out")
    except Exception:
        raise _SchemaValidationResourceError("schema pattern is unsupported by the bounded regex engine")
    if not matched:
        yield _jsonschema.exceptions.ValidationError("string does not match pattern")


def _bounded_pattern_properties(validator: Any, patterns: dict[str, Any], instance: Any, schema: dict[str, Any]):
    if not isinstance(instance, dict):
        return
    for pattern, subschema in patterns.items():
        for key, value in instance.items():
            if len(pattern) > 2048:
                raise _SchemaValidationResourceError("schema pattern exceeds the 2048 character limit")
            remaining = _REGEX_DEADLINE.get() - time.monotonic()
            if _safe_regex is None or remaining <= 0:
                raise _SchemaValidationResourceError("patternProperties validation budget unavailable")
            try:
                matched = _safe_regex.search(
                    pattern,
                    key,
                    timeout=min(remaining, _REGEX_PER_MATCH_SECONDS),
                ) is not None
            except TimeoutError:
                raise _SchemaValidationResourceError("patternProperties validation timed out")
            except Exception:
                raise _SchemaValidationResourceError("patternProperties regex is unsupported")
            if matched:
                yield from validator.descend(value, subschema, path=key, schema_path=pattern)


def _jsonschema_validator_for(schema: dict[str, Any]):
    dialect = schema.get("$schema", "https://json-schema.org/draft/2020-12/schema")
    if not isinstance(dialect, str):
        raise ToolInputSchemaError("unsupported JSON Schema dialect")
    classes = {
        "https://json-schema.org/draft/2020-12/schema": _Draft202012Validator,
        "http://json-schema.org/draft-07/schema#": _Draft7Validator,
    }
    if dialect not in classes:
        raise ToolInputSchemaError("unsupported JSON Schema dialect")
    if _jsonschema is None:
        return None
    base = classes[dialect]
    return _jsonschema_validators.extend(
        base,
        {"pattern": _bounded_pattern, "patternProperties": _bounded_pattern_properties},
    )


class ToolInputSchemaError(ValueError):
    """The tool arguments or the declared schema do not satisfy this contract."""


_ANNOTATIONS = {
    "$schema", "$id", "$comment", "title", "description", "default",
    "examples", "deprecated", "readOnly", "writeOnly", "format",
    "contentEncoding", "contentMediaType", "contentSchema",
}
_KEYWORDS = _ANNOTATIONS | {
    "type", "properties", "required", "additionalProperties", "items",
    "enum", "const", "minimum", "maximum", "exclusiveMinimum",
    "exclusiveMaximum", "minLength", "maxLength", "minItems",
    "maxItems", "uniqueItems", "minProperties", "maxProperties",
    "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
}


def validate_tool_input(value: Any, schema: Any) -> None:
    """Raise with a bounded, value-free message when input violates schema."""
    if not isinstance(value, dict):
        raise ToolInputSchemaError("tool arguments must be an object")
    validate_json_schema_instance(value, schema)


def validate_json_schema_instance(value: Any, schema: Any) -> None:
    """Validate any JSON value against a validated local-reference schema."""
    if not isinstance(schema, dict):
        raise ToolInputSchemaError("JSON Schema must be an object")
    _check_tree_budget(value, label="tool input")
    _check_tree_budget(schema, label="tool schema")
    if not _is_json_value(value, 0):
        raise ToolInputSchemaError("value must contain only JSON values")
    validate_json_schema_definition(schema)
    validator_type = _jsonschema_validator_for(schema)
    if validator_type is not None:
        _validate_with_jsonschema(value, schema, validator_type)
        return
    _validate(value, schema, "arguments", 0)


def validate_tool_schema(schema: Any) -> None:
    """Validate an MCP input schema before it is exposed to the model.

    The schema must describe an object. References are restricted to the
    supplied document; resolving a server-provided URI would turn validation
    into an unreviewed network client.
    """
    if not isinstance(schema, dict):
        raise ToolInputSchemaError("inputSchema must be a JSON object")
    validate_json_schema_definition(schema)
    if schema.get("type") != "object":
        raise ToolInputSchemaError("MCP inputSchema type must be 'object'")


def validate_json_schema_definition(schema: Any) -> None:
    """Validate a JSON Schema document without evaluating it against a value."""
    if not isinstance(schema, dict):
        raise ToolInputSchemaError("JSON Schema must be an object")
    _check_tree_budget(schema, label="tool schema")
    _require_local_references(schema)
    validator_type = _jsonschema_validator_for(schema)
    if validator_type is None:
        _check_schema_definition(schema, 0)
        return
    try:
        validator_type.check_schema(schema)
    except _jsonschema.exceptions.SchemaError as exc:
        raise ToolInputSchemaError("tool declares an invalid JSON Schema") from exc


def check_json_tree_budget(value: Any, *, label: str = "tool input") -> int:
    """Check the shared tree limits and return its conservative size estimate."""
    return _check_tree_budget(value, label=label)


def check_json_tree_budget_details(value: Any, *, label: str = "tool input") -> tuple[int, int]:
    """Check a decoded JSON tree and return ``(estimated_bytes, expanded_nodes)``."""
    return _check_tree_budget_details(value, label=label)


def check_json_text_node_budget(text: str, *, label: str = "tool input") -> int:
    """Count JSON value occurrences and nesting before decoding the input.

    This small structural scanner does not replace ``json.loads``. It skips
    object keys and string contents without creating decoded values, counts each
    JSON value (including every repeated reference in the source), and leaves
    grammar validation to the standard parser. Its purpose is to stop a compact
    array/object bomb before a provider adapter materializes hundreds of
    thousands of Python objects.
    """
    if not isinstance(text, str):
        raise ToolInputSchemaError(f"{label} JSON source must be text")

    length = len(text)
    offset = 0
    nodes = 0

    def skip_space() -> None:
        nonlocal offset
        while offset < length and text[offset] in " \t\r\n":
            offset += 1

    def skip_string() -> bool:
        """Advance over one quoted token without decoding or allocating it."""
        nonlocal offset
        if offset >= length or text[offset] != '"':
            return False
        offset += 1
        while offset < length:
            character = text[offset]
            if character == "\\":
                # The standard parser will validate escape spelling. Skipping
                # both code units is enough to avoid treating an escaped quote
                # as the end of this token.
                offset += 2
            elif character == '"':
                offset += 1
                return True
            else:
                offset += 1
        return False

    def parse_value(depth: int) -> bool:
        nonlocal offset, nodes
        skip_space()
        if offset >= length:
            return False
        nodes += 1
        if nodes > MAX_SCHEMA_TREE_NODES:
            raise ToolInputSchemaError(f"{label} exceeds the {MAX_SCHEMA_TREE_NODES}-node limit")
        if depth > MAX_SCHEMA_TREE_DEPTH:
            raise ToolInputSchemaError(f"{label} exceeds the {MAX_SCHEMA_TREE_DEPTH}-level nesting limit")

        token = text[offset]
        if token == '"':
            return skip_string()
        if token == "{":
            offset += 1
            skip_space()
            if offset < length and text[offset] == "}":
                offset += 1
                return True
            while offset < length:
                skip_space()
                if not skip_string():
                    return False
                skip_space()
                if offset >= length or text[offset] != ":":
                    return False
                offset += 1
                if not parse_value(depth + 1):
                    return False
                skip_space()
                if offset < length and text[offset] == ",":
                    offset += 1
                    continue
                if offset < length and text[offset] == "}":
                    offset += 1
                    return True
                return False
            return False
        if token == "[":
            offset += 1
            skip_space()
            if offset < length and text[offset] == "]":
                offset += 1
                return True
            while offset < length:
                if not parse_value(depth + 1):
                    return False
                skip_space()
                if offset < length and text[offset] == ",":
                    offset += 1
                    continue
                if offset < length and text[offset] == "]":
                    offset += 1
                    return True
                return False
            return False

        # Numbers and the true/false/null literals contain no structural
        # delimiters. The regular JSON parser validates their exact syntax.
        start = offset
        while offset < length and text[offset] not in ",]} \t\r\n":
            offset += 1
        return offset > start

    parse_value(0)
    return nodes


def _check_tree_budget(value: Any, *, label: str) -> int:
    """Bound expanded JSON traversal work before copy or schema evaluation."""
    return _check_tree_budget_details(value, label=label)[0]


def _check_tree_budget_details(value: Any, *, label: str) -> tuple[int, int]:
    """Return the bounded traversal's conservative size and occurrence count."""
    pending = [(value, 0)]
    # Count every occurrence, not each Python object identity. Shared in-memory
    # references serialize and validate once per edge, so de-duplicating a DAG
    # here would let a tiny object graph expand into exponential validator work.
    scheduled = 1
    nodes = 0
    estimated_bytes = 0
    while pending:
        node, depth = pending.pop()
        nodes += 1
        if nodes > MAX_SCHEMA_TREE_NODES:
            raise ToolInputSchemaError(f"{label} exceeds the {MAX_SCHEMA_TREE_NODES}-node limit")
        if depth > MAX_SCHEMA_TREE_DEPTH:
            raise ToolInputSchemaError(f"{label} exceeds the {MAX_SCHEMA_TREE_DEPTH}-level nesting limit")
        estimated_bytes += 8  # JSON delimiters and separators, conservatively.
        if type(node) is str:
            estimated_bytes += _json_string_size_estimate(node)
        elif type(node) is bool or node is None:
            estimated_bytes += 5
        elif type(node) is int:
            estimated_bytes += max(1, (node.bit_length() + 2) // 3 + 1)
        elif type(node) is float:
            estimated_bytes += 32
        elif type(node) in (dict, list):
            child_count = len(node)
            if scheduled + child_count > MAX_SCHEMA_TREE_NODES:
                raise ToolInputSchemaError(f"{label} exceeds the {MAX_SCHEMA_TREE_NODES}-node limit")
            scheduled += child_count
            if type(node) is dict:
                for key, child in node.items():
                    if type(key) is not str:
                        raise ToolInputSchemaError(f"{label} object keys must be strings")
                    estimated_bytes += _json_string_size_estimate(key)
                    pending.append((child, depth + 1))
            else:
                pending.extend((child, depth + 1) for child in node)
        else:
            raise ToolInputSchemaError(f"{label} must contain only JSON values")
        if estimated_bytes > MAX_SCHEMA_TREE_BYTES:
            raise ToolInputSchemaError(f"{label} exceeds the {MAX_SCHEMA_TREE_BYTES}-byte resource limit")
    return estimated_bytes, nodes


def _require_local_references(root: dict[str, Any]) -> None:
    """Reject remote refs while traversing only actual schema-valued keywords."""
    stack: list[Any] = [root]
    seen: set[int] = set()
    single = (
        "additionalItems", "additionalProperties", "unevaluatedItems",
        "unevaluatedProperties", "propertyNames", "items", "contains",
        "not", "if", "then", "else", "contentSchema",
    )
    mappings = ("$defs", "definitions", "properties", "patternProperties", "dependentSchemas")
    arrays = ("allOf", "anyOf", "oneOf", "prefixItems")
    while stack:
        node = stack.pop()
        if isinstance(node, bool):
            continue
        if not isinstance(node, dict) or id(node) in seen:
            continue
        seen.add(id(node))
        for keyword in ("$ref", "$dynamicRef", "$recursiveRef"):
            if keyword in node:
                reference = node[keyword]
                if not isinstance(reference, str) or not reference.startswith("#"):
                    raise ToolInputSchemaError("remote JSON Schema references are disabled")
        for keyword in single:
            child = node.get(keyword)
            if isinstance(child, list):
                stack.extend(child)
            elif isinstance(child, (dict, bool)):
                stack.append(child)
        for keyword in mappings:
            children = node.get(keyword)
            if isinstance(children, dict):
                stack.extend(children.values())
        for keyword in arrays:
            children = node.get(keyword)
            if isinstance(children, list):
                stack.extend(children)
        dependencies = node.get("dependencies")
        if isinstance(dependencies, dict):
            stack.extend(child for child in dependencies.values() if isinstance(child, (dict, bool)))


def _validate_with_jsonschema(value: dict[str, Any], schema: dict[str, Any], validator_type: Any) -> None:
    token = _REGEX_DEADLINE.set(time.monotonic() + _REGEX_BUDGET_SECONDS)
    try:
        try:
            validator_type.check_schema(schema)
        except _jsonschema.exceptions.SchemaError as exc:
            raise ToolInputSchemaError("tool declares an invalid JSON Schema") from exc
        validator = validator_type(schema, registry=_SchemaRegistry())
        try:
            error = next(validator.iter_errors(value), None)
        except _SchemaValidationResourceError as exc:
            raise ToolInputSchemaError(str(exc)) from exc
        except Exception as exc:
            # An unresolved $ref cannot fetch network resources: the empty
            # registry intentionally limits references to the schema itself.
            raise ToolInputSchemaError("tool schema could not be resolved locally") from exc
        if error is not None:
            location = ".".join(str(part) for part in list(error.absolute_path)[:8])
            suffix = f" at arguments.{location}" if location else ""
            keyword = str(error.validator)[:64]
            raise ToolInputSchemaError(
                f"arguments violate schema keyword {keyword!r}{suffix}"
            )
    finally:
        _REGEX_DEADLINE.reset(token)


def _is_json_value(value: Any, depth: int) -> bool:
    if depth > 32:
        return False
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_is_json_value(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_json_value(item, depth + 1) for key, item in value.items())
    return False


def _check_schema_definition(schema: Any, depth: int) -> None:
    if depth > 32 or not isinstance(schema, dict):
        raise ToolInputSchemaError("invalid or excessively nested input schema")
    if not all(isinstance(key, str) for key in schema):
        raise ToolInputSchemaError("schema keywords must be strings")
    unknown = set(schema) - _KEYWORDS
    if unknown:
        raise ToolInputSchemaError(f"unsupported schema keyword: {sorted(unknown)[0]}")
    if "type" in schema:
        kinds = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not kinds or any(
            not isinstance(kind, str)
            or kind not in {"object", "array", "string", "boolean", "null", "integer", "number"}
            for kind in kinds
        ):
            raise ToolInputSchemaError("invalid JSON Schema type declaration")
    if "required" in schema and (
        not isinstance(schema["required"], list)
        or not all(isinstance(key, str) for key in schema["required"])
    ):
        raise ToolInputSchemaError("invalid required declaration")
    properties = schema.get("properties", {})
    if not isinstance(properties, dict) or not all(isinstance(key, str) for key in properties):
        raise ToolInputSchemaError("invalid properties declaration")
    for child in properties.values():
        _check_schema_definition(child, depth + 1)
    additional = schema.get("additionalProperties", True)
    if isinstance(additional, dict):
        _check_schema_definition(additional, depth + 1)
    elif not isinstance(additional, bool):
        raise ToolInputSchemaError("invalid additionalProperties declaration")
    if "items" in schema:
        _check_schema_definition(schema["items"], depth + 1)
    for keyword in ("allOf", "anyOf", "oneOf"):
        if keyword in schema:
            branches = schema[keyword]
            if not isinstance(branches, list) or not branches:
                raise ToolInputSchemaError(f"invalid {keyword} declaration")
            for branch in branches:
                _check_schema_definition(branch, depth + 1)
    for keyword in ("not", "if", "then", "else"):
        if keyword in schema:
            _check_schema_definition(schema[keyword], depth + 1)
    for keyword in ("format", "contentEncoding", "contentMediaType"):
        if keyword in schema and not isinstance(schema[keyword], str):
            raise ToolInputSchemaError(f"invalid {keyword} annotation")
    if "contentSchema" in schema:
        _check_schema_definition(schema["contentSchema"], depth + 1)
    if "enum" in schema and not isinstance(schema["enum"], list):
        raise ToolInputSchemaError("invalid enum declaration")
    for keyword in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
        value = schema.get(keyword)
        if keyword in schema and (
            isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
        ):
            raise ToolInputSchemaError(f"invalid {keyword} declaration")
    for keyword in ("minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties"):
        value = schema.get(keyword)
        if keyword in schema and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise ToolInputSchemaError(f"invalid {keyword} declaration")
    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        raise ToolInputSchemaError("invalid uniqueItems declaration")


def _validate(value: Any, schema: Any, path: str, depth: int) -> None:
    if depth > 32:
        raise ToolInputSchemaError("input schema nesting exceeds 32 levels")
    if not isinstance(schema, dict):
        raise ToolInputSchemaError(f"schema at {path} must be an object")
    unknown = set(schema) - _KEYWORDS
    if unknown:
        raise ToolInputSchemaError(f"unsupported schema keyword at {path}: {sorted(unknown)[0]}")

    expected = schema.get("type")
    types = expected if isinstance(expected, list) else [expected] if expected else []
    if types and not any(_matches_type(value, kind) for kind in types):
        raise ToolInputSchemaError(f"{path} has the wrong type")
    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list) or not any(_json_equal(value, item) for item in enum):
            raise ToolInputSchemaError(f"{path} is not an allowed value")
    if "const" in schema and not _json_equal(value, schema["const"]):
        raise ToolInputSchemaError(f"{path} does not match its constant")
    for branch in schema.get("allOf", []):
        _validate(value, branch, path, depth + 1)
    for keyword in ("anyOf", "oneOf"):
        branches = schema.get(keyword, [])
        if branches:
            matches = sum(_subschema_matches(value, branch, path, depth + 1) for branch in branches)
            if (keyword == "anyOf" and matches == 0) or (keyword == "oneOf" and matches != 1):
                raise ToolInputSchemaError(f"{path} violates {keyword}")
    if "not" in schema and _subschema_matches(value, schema["not"], path, depth + 1):
        raise ToolInputSchemaError(f"{path} violates not")
    if "if" in schema:
        branch = schema.get("then") if _subschema_matches(value, schema["if"], path, depth + 1) else schema.get("else")
        if branch is not None:
            _validate(value, branch, path, depth + 1)

    if isinstance(value, dict):
        required = schema.get("required", [])
        properties = schema.get("properties", {})
        if not isinstance(required, list) or not all(isinstance(key, str) for key in required):
            raise ToolInputSchemaError(f"invalid required declaration at {path}")
        if not isinstance(properties, dict) or not all(isinstance(key, str) for key in properties):
            raise ToolInputSchemaError(f"invalid properties declaration at {path}")
        missing = next((key for key in required if key not in value), None)
        if missing is not None:
            raise ToolInputSchemaError(f"{path}.{missing} is required")
        _check_count(len(value), schema, "minProperties", "maxProperties", path)
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in properties:
                _validate(item, properties[key], f"{path}.{key}", depth + 1)
            elif additional is False:
                raise ToolInputSchemaError(f"{path}.{key} is not allowed")
            elif isinstance(additional, dict):
                _validate(item, additional, f"{path}.{key}", depth + 1)
            elif not isinstance(additional, bool):
                raise ToolInputSchemaError(f"invalid additionalProperties at {path}")
    elif isinstance(value, list):
        _check_count(len(value), schema, "minItems", "maxItems", path)
        if schema.get("uniqueItems") is True:
            seen: set[str] = set()
            for item in value:
                try:
                    fingerprint = json.dumps(
                        _normalize_json_numbers(item),
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                except (TypeError, ValueError) as exc:
                    raise ToolInputSchemaError(f"{path} contains a non-JSON value") from exc
                if fingerprint in seen:
                    raise ToolInputSchemaError(f"{path} must contain unique items")
                seen.add(fingerprint)
        if "items" in schema:
            for index, item in enumerate(value):
                _validate(item, schema["items"], f"{path}[{index}]", depth + 1)
    elif isinstance(value, str):
        _check_count(len(value), schema, "minLength", "maxLength", path)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise ToolInputSchemaError(f"{path} must be finite")
        for keyword, op in (("minimum", lambda actual, bound: actual >= bound),
                            ("maximum", lambda actual, bound: actual <= bound),
                            ("exclusiveMinimum", lambda actual, bound: actual > bound),
                            ("exclusiveMaximum", lambda actual, bound: actual < bound)):
            if keyword in schema:
                bound = schema[keyword]
                if isinstance(bound, bool) or not isinstance(bound, (int, float)) or not math.isfinite(bound):
                    raise ToolInputSchemaError(f"invalid {keyword} at {path}")
                if not op(value, bound):
                    raise ToolInputSchemaError(f"{path} violates {keyword}")


def _matches_type(value: Any, kind: Any) -> bool:
    if kind == "object": return isinstance(value, dict)
    if kind == "array": return isinstance(value, list)
    if kind == "string": return isinstance(value, str)
    if kind == "boolean": return isinstance(value, bool)
    if kind == "null": return value is None
    if kind == "integer": return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number": return isinstance(value, (int, float)) and not isinstance(value, bool)
    raise ToolInputSchemaError(f"unsupported JSON Schema type: {kind!r}")


def _subschema_matches(value: Any, schema: dict[str, Any], path: str, depth: int) -> bool:
    try:
        _validate(value, schema, path, depth)
    except ToolInputSchemaError:
        return False
    return True


def _check_count(actual: int, schema: dict[str, Any], low: str, high: str, path: str) -> None:
    for keyword, predicate in ((low, lambda bound: actual >= bound), (high, lambda bound: actual <= bound)):
        if keyword in schema:
            bound = schema[keyword]
            if isinstance(bound, bool) or not isinstance(bound, int) or bound < 0:
                raise ToolInputSchemaError(f"invalid {keyword} at {path}")
            if not predicate(bound):
                raise ToolInputSchemaError(f"{path} violates {keyword}")


def _json_equal(left: Any, right: Any) -> bool:
    # JSON Schema treats true and 1 as distinct even though Python does not.
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if isinstance(left, list) or isinstance(right, list):
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and len(left) == len(right)
            and all(_json_equal(a, b) for a, b in zip(left, right))
        )
    if isinstance(left, dict) or isinstance(right, dict):
        return (
            isinstance(left, dict)
            and isinstance(right, dict)
            and left.keys() == right.keys()
            and all(_json_equal(left[key], right[key]) for key in left)
        )
    if type(left) is not type(right):
        return False
    return left == right


def _normalize_json_numbers(value: Any) -> Any:
    """Canonicalize numerically equal int/float values for uniqueItems."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) and value.is_integer() else value
    if isinstance(value, list):
        return [_normalize_json_numbers(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize_json_numbers(item) for key, item in value.items()}
    return value
