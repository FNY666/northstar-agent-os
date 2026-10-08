"""Mock IMAP parser: tagged commands, unique tag validation.

What this IS: parser/validator for IMAP (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete IMAP (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import re

#: Module version.
PROTO_22_VERSION = "proto-22-imap.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-22-imap.v1"


class Proto22Error(Exception):
    """Fail-closed."""


_TAG_RE = re.compile(r"^([A-Za-z0-9*]+)\s+([A-Za-z]+)(?:\s+(.*))?$", re.S)
_KNOWN = {"LOGIN", "SELECT", "FETCH", "STORE", "SEARCH", "LOGOUT", "NOOP",
          "CAPABILITY", "LIST", "CREATE", "DELETE", "SUBSCRIBE", "STATUS",
          "APPEND", "COPY", "EXPUNGE", "CLOSE", "UID", "EXAMINE"}


def parse_imap_line(line: str) -> dict:
    """Parse one tagged IMAP command. Raises Proto22Error."""
    m = _TAG_RE.match(line.strip())
    if not m:
        raise Proto22Error("bad IMAP line")
    tag, cmd, args = m.groups()
    if cmd.upper() not in _KNOWN:
        raise Proto22Error("unknown IMAP command " + cmd)
    return {"tag": tag, "command": cmd.upper(), "args": args or ""}


def validate_tags(lines) -> tuple:
    """Validate that client tags are unique. Returns (ok, reason)."""
    seen = set()
    try:
        for line in lines:
            if not line.strip():
                continue
            parsed = parse_imap_line(line)
            tag = parsed["tag"]
            if tag != "*" and tag in seen:
                return False, "duplicate tag " + tag
            seen.add(tag)
    except Proto22Error as exc:
        return False, str(exc)
    return True, "tags ok"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
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
    p = parse_imap_line("A001 LOGIN user pass")
    assert p == {"tag": "A001", "command": "LOGIN", "args": "user pass"}
    ok, _ = validate_tags(["A001 NOOP", "A002 NOOP"])
    assert ok is True
    ok, _ = validate_tags(["A001 NOOP", "A001 NOOP"])
    assert ok is False

    assert stdlib_only()
    print("proto-22 (imap): OK")


if __name__ == "__main__":
    main()
