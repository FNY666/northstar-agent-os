"""Tiny, strict frontmatter reader for workspace extension files.

Only the subset of YAML frontmatter that the governed runtime needs is parsed -
and anything outside that subset is an error, not a guess:

- a document may open with ``---`` on its own line and must close with a later
  ``---`` line; the remainder is the body;
- fields are ``key: value`` lines (blank lines and ``#`` comments allowed);
  values may be scalars (quoted or bare strings, booleans, integers, floats),
  inline arrays ``key: [a, b]``, block arrays of ``- item`` lines, or two-space
  block mappings of scalar values;
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
            # A small, strict block-mapping subset covers Agent Skills metadata
            # while keeping arbitrary YAML out of this dependency-free parser.
            probe = index
            while probe < len(lines) and (
                not lines[probe].strip() or lines[probe].lstrip().startswith("#")
            ):
                probe += 1
            probe_line = lines[probe] if probe < len(lines) else ""
            probe_indent = len(probe_line) - len(probe_line.lstrip(" "))
            if probe_indent > 0 and not probe_line.strip().startswith("- "):
                mapping: dict[str, Any] = {}
                while index < len(lines):
                    candidate_line = lines[index]
                    candidate = candidate_line.strip()
                    if not candidate or candidate.startswith("#"):
                        index += 1
                        continue
                    indent = len(candidate_line) - len(candidate_line.lstrip(" "))
                    if indent == 0:
                        break
                    if indent != 2 or candidate.startswith("- ") or ":" not in candidate:
                        raise FrontmatterError(
                            f"frontmatter key {key!r}: block mappings require two-space scalar entries"
                        )
                    nested_key, _, nested_value = candidate.partition(":")
                    nested_key = nested_key.strip()
                    if not _KEY_RE.match(nested_key):
                        raise FrontmatterError(
                            f"frontmatter key {key!r}: invalid mapping key {nested_key!r}"
                        )
                    if nested_key in mapping:
                        raise FrontmatterError(
                            f"frontmatter key {key!r}: duplicate mapping key {nested_key!r}"
                        )
                    nested_value = nested_value.strip()
                    mapping[nested_key] = _parse_scalar(nested_value, nested_key) if nested_value else None
                    index += 1
                fields[key] = mapping
                continue

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
