"""Mock STOMP parser: COMMAND, headers, body, NUL terminator.

What this IS: parser/validator for STOMP (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete STOMP (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_34_VERSION = "proto-34-stomp.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-34-stomp.v1"


class Proto34Error(Exception):
    """Fail-closed."""


def parse_stomp(text: str) -> dict:
    """Parse a STOMP frame. Raises Proto34Error."""
    if not text.endswith("\x00"):
        raise Proto34Error("STOMP frame must end with NUL")
    head, _, body = text[:-1].partition("\n\n")
    lines = head.split("\n")
    command = lines[0].strip()
    if not command:
        raise Proto34Error("empty command")
    headers = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            raise Proto34Error("bad header line: " + line)
        k, _, v = line.partition(":")
        headers[k.strip()] = v.strip()
    return {"command": command, "headers": headers, "body": body}


def validate_stomp(text: str, commands=None) -> tuple:
    """Validate a STOMP frame. Returns (ok, reason)."""
    try:
        frame = parse_stomp(text)
    except Proto34Error as exc:
        return False, str(exc)
    if commands and frame["command"] not in commands:
        return False, "unexpected command " + frame["command"]
    return True, "valid STOMP frame"


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
    f = parse_stomp("SEND\ndestination:/q\n\nhello\x00")
    assert f == {"command": "SEND", "headers": {"destination": "/q"}, "body": "hello"}
    ok, _ = validate_stomp("SEND\n\nx", ["SUBSCRIBE"])
    assert ok is False

    assert stdlib_only()
    print("proto-34 (stomp): OK")


if __name__ == "__main__":
    main()
