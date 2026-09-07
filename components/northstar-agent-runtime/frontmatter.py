"""Tiny, strict frontmatter reader for workspace extension files.

Only the small YAML subset that the governed runtime needs is parsed.  The
reader deliberately does not import a YAML package: policy and extension files
must remain inspectable on a bare Python installation.  Supported values are:

* scalars (quoted or bare strings, booleans, integers and floats);
* inline arrays (``[Read, Grep]``) and block arrays;
* inline maps (``{author: acme}``) and one-level block maps; and
* folded/literal block strings (``>``/``|``), which are useful for the
  standards-compatible ``description`` field.

Duplicate keys, malformed lines, and keys outside
``[A-Za-z_][A-Za-z0-9_-]*`` are errors.  Unknown *field names* remain the
caller's decision, so a typo in a skill or agent definition can never be
silently ignored.
"""
from __future__ import annotations

import re
from typing import Any

FRONTMATTER_DELIMITER = "---"
_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_SCALAR_TRUE = {"true", "yes"}
_SCALAR_FALSE = {"false", "no"}


class FrontmatterError(ValueError):
    """The frontmatter block cannot be parsed. Message is operator-facing."""


def parse_frontmatter(text: str) -> tuple[dict[str, Any] | None, str]:
    """Return ``(fields, body)``; ``fields`` is ``None`` when there is no block."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    if not lines or lines[0].lstrip("\ufeff").strip() != FRONTMATTER_DELIMITER:
        return None, text
    end = None
    for index in range(1, len(lines)):
        if lines[index].strip() == FRONTMATTER_DELIMITER:
            end = index
            break
    if end is None:
        raise FrontmatterError("frontmatter opens with --- but never closes")
    fields = _parse_fields(lines[1:end])
    body = "\n".join(lines[end + 1 :]).strip()
    return fields, body


def _parse_fields(lines: list[str]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    index = 0
    while index < len(lines):
        raw_line = lines[index].rstrip()
        index += 1
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw_line[:1].isspace():
            raise FrontmatterError(f"unexpected indentation in frontmatter line {stripped!r}")
        if ":" not in raw_line:
            raise FrontmatterError(f"malformed frontmatter line {stripped!r}: expected key: value")
        key, _, raw_value = raw_line.partition(":")
        key = key.strip()
        if not _KEY_RE.match(key):
            raise FrontmatterError(f"invalid frontmatter key {key!r}")
        if key in fields:
            raise FrontmatterError(f"duplicate frontmatter key {key!r}")
        value_text = raw_value.strip()

        if value_text in {"|", ">", "|-", ">-", "|+", ">+"}:
            value, index = _parse_block_string(lines, index, value_text[0])
            fields[key] = value
            continue

        if value_text == "":
            value, index = _parse_nested_value(lines, index)
            fields[key] = value
            continue

        fields[key] = _parse_value(value_text, key)
    return fields


def _parse_nested_value(lines: list[str], index: int) -> tuple[Any, int]:
    """Parse a one-level indented array/map after ``key:``."""
    items: list[str] = []
    mapping: dict[str, Any] = {}
    kind: str | None = None
    first_indent: int | None = None

    while index < len(lines):
        raw = lines[index].rstrip()
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            break
        if first_indent is None:
            first_indent = indent
        if indent < first_indent:
            break
        content = raw[first_indent:]
        if content.startswith("- "):
            if kind == "map":
                raise FrontmatterError("a nested frontmatter value cannot mix an array and a map")
            kind = "array"
            items.append(content[2:].strip())
            index += 1
            continue
        if ":" in content:
            if kind == "array":
                raise FrontmatterError("a nested frontmatter value cannot mix an array and a map")
            kind = "map"
            key, _, value_text = content.partition(":")
            key = key.strip()
            if not _KEY_RE.match(key):
                raise FrontmatterError(f"invalid nested frontmatter key {key!r}")
            if key in mapping:
                raise FrontmatterError(f"duplicate nested frontmatter key {key!r}")
            if not value_text.strip():
                raise FrontmatterError(f"nested frontmatter key {key!r} needs a scalar value")
            mapping[key] = _parse_value(value_text.strip(), key)
            index += 1
            continue
        raise FrontmatterError(f"malformed nested frontmatter line {stripped!r}")

    if kind == "array":
        return [_parse_value(item, "array item") for item in items], index
    if kind == "map":
        return mapping, index
    return "", index


def _parse_block_string(lines: list[str], index: int, style: str) -> tuple[str, int]:
    values: list[str] = []
    first_indent: int | None = None
    while index < len(lines):
        raw = lines[index].rstrip()
        if raw.strip() == "":
            values.append("")
            index += 1
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            break
        if first_indent is None:
            first_indent = indent
        values.append(raw[first_indent:])
        index += 1
    if style == ">":
        return " ".join(part.strip() for part in values).strip(), index
    return "\n".join(values).strip(), index


def _parse_value(text: str, key: str) -> Any:
    if text.startswith("["):
        if not text.endswith("]"):
            raise FrontmatterError(f"frontmatter key {key!r}: inline array never closed")
        inner = text[1:-1].strip()
        return [_parse_value(item.strip(), key) for item in _split_inline(inner)] if inner else []
    if text.startswith("{"):
        if not text.endswith("}"):
            raise FrontmatterError(f"frontmatter key {key!r}: inline map never closed")
        inner = text[1:-1].strip()
        result: dict[str, Any] = {}
        for item in _split_inline(inner):
            if ":" not in item:
                raise FrontmatterError(f"frontmatter key {key!r}: map item needs key: value")
            map_key, _, map_value = item.partition(":")
            map_key = map_key.strip()
            if not _KEY_RE.match(map_key):
                raise FrontmatterError(f"invalid nested frontmatter key {map_key!r}")
            if map_key in result:
                raise FrontmatterError(f"duplicate nested frontmatter key {map_key!r}")
            result[map_key] = _parse_value(map_value.strip(), map_key)
        return result
    return _parse_scalar(text, key)


def _split_inline(text: str) -> list[str]:
    """Split a small inline YAML list/map while respecting quotes."""
    values: list[str] = []
    start = 0
    quote: str | None = None
    for index, char in enumerate(text):
        if char in ("'", '"'):
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
        elif char == "," and quote is None:
            values.append(text[start:index].strip())
            start = index + 1
    if quote is not None:
        raise FrontmatterError("unterminated quote in inline frontmatter value")
    values.append(text[start:].strip())
    return [value for value in values if value]


def _parse_scalar(text: str, key: str) -> Any:
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        if text[0] == '"':
            # Keep this intentionally small; frontmatter values are metadata,
            # not a general JSON/YAML string language.
            text = text[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        else:
            text = text[1:-1].replace("''", "'")
        return text
    lowered = text.lower()
    if lowered in _SCALAR_TRUE:
        return True
    if lowered in _SCALAR_FALSE:
        return False
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text
