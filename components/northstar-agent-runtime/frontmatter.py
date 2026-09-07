"""Tiny, strict frontmatter reader for workspace extension files.

Only the subset of YAML frontmatter that the governed runtime needs is parsed -
and anything outside that subset is an error, not a guess:

- a document may open with ``---`` on its own line and must close with a later
  ``---`` line; the remainder is the body;
- fields are ``key: value`` lines (blank lines and ``#`` comments allowed);
  values may be scalars (quoted or bare strings, booleans, integers, floats),
  inline arrays ``key: [a, b]``, or block arrays of ``- item`` lines;
- duplicate keys, malformed lines, and keys outside ``[A-Za-z_][A-Za-z0-9_-]*``
  are errors. Unknown *field names* are the caller's decision to reject, so a
  typo in a skill or agent definition can never be silently ignored.

No YAML dependency is pulled in: this stays importable on a bare interpreter.
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
    lines = text.splitlines()
    if not lines or lines[0].strip() != FRONTMATTER_DELIMITER:
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
        line = lines[index].rstrip()
        index += 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in line:
            raise FrontmatterError(f"malformed frontmatter line {stripped!r}: expected key: value")
        key, _, raw_value = line.partition(":")
        key = key.strip()
        if not _KEY_RE.match(key):
            raise FrontmatterError(f"invalid frontmatter key {key!r}")
        if key in fields:
            raise FrontmatterError(f"duplicate frontmatter key {key!r}")
        value_text = raw_value.strip()
        if value_text.startswith("["):
            # Inline array: [a, b] possibly spanning nothing else.
            if not value_text.endswith("]"):
                raise FrontmatterError(f"frontmatter key {key!r}: inline array never closed")
            inner = value_text[1:-1].strip()
            fields[key] = [item.strip() for item in inner.split(",") if item.strip()] if inner else []
            continue
        if value_text == "":
            # Block array: subsequent lines of "- item".
            items: list[str] = []
            while index < len(lines):
                candidate = lines[index].strip()
                if candidate.startswith("- "):
                    items.append(candidate[2:].strip())
                    index += 1
                elif not candidate or candidate.startswith("#"):
                    index += 1
                    continue
                else:
                    break
            fields[key] = items
            continue
        fields[key] = _parse_scalar(value_text, key)
    return fields


def _parse_scalar(text: str, key: str) -> Any:
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1]
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
