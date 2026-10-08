"""Mock POP3 parser: commands, +OK/-ERR, dot-terminated multiline.

What this IS: parser/validator for POP3 (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete POP3 (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_23_VERSION = "proto-23-pop3.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-23-pop3.v1"


class Proto23Error(Exception):
    """Fail-closed."""


_COMMANDS = {"USER", "PASS", "STAT", "LIST", "RETR", "DELE", "NOOP",
             "RSET", "QUIT", "TOP", "UIDL", "APOP", "CAPA"}


def parse_pop3_line(line: str) -> tuple:
    """Parse one POP3 command into (command, arg). Raises Proto23Error."""
    parts = line.strip().split(None, 1)
    if not parts:
        raise Proto23Error("empty line")
    cmd = parts[0].upper()
    if cmd not in _COMMANDS:
        raise Proto23Error("unknown command " + cmd)
    return cmd, (parts[1] if len(parts) > 1 else "")


def parse_multiline(lines) -> list:
    """Collect a dot-terminated multiline response. Raises Proto23Error."""
    collected = []
    for line in lines:
        if line == ".":
            return collected
        collected.append(line[1:] if line.startswith("..") else line)
    raise Proto23Error("unterminated multiline response")


def validate_greeting(line: str) -> tuple:
    """Validate a server greeting line. Returns (ok, reason)."""
    if line.startswith("+OK"):
        return True, "greeting ok"
    return False, "greeting must start with +OK"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    assert parse_pop3_line("USER alice") == ("USER", "alice")
    assert parse_multiline(["a", "..b", "."]) == ["a", ".b"]
    ok, _ = validate_greeting("+OK ready")
    assert ok is True
    ok, _ = validate_greeting("-ERR no")
    assert ok is False

    assert stdlib_only()
    print("proto-23 (pop3): OK")


if __name__ == "__main__":
    main()
