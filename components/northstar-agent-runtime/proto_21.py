"""Mock SMTP parser: command lines and EHLO/MAIL/RCPT/DATA sequence.

What this IS: parser/validator for SMTP (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete SMTP (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_21_VERSION = "proto-21-smtp.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-21-smtp.v1"


class Proto21Error(Exception):
    """Fail-closed."""


_COMMANDS = {"EHLO", "HELO", "MAIL", "RCPT", "DATA", "RSET",
             "NOOP", "QUIT", "VRFY", "EXPN", "HELP"}


def parse_smtp_line(line: str) -> tuple:
    """Parse one SMTP command line into (command, arg). Raises Proto21Error."""
    parts = line.strip().split(None, 1)
    if not parts:
        raise Proto21Error("empty line")
    cmd = parts[0].upper()
    if cmd not in _COMMANDS:
        raise Proto21Error("unknown command " + cmd)
    return cmd, (parts[1] if len(parts) > 1 else "")


def validate_sequence(lines) -> tuple:
    """Validate command order: EHLO -> MAIL -> RCPT+ -> DATA -> QUIT."""
    state = "start"
    for line in lines:
        if not line.strip():
            continue
        try:
            cmd, _ = parse_smtp_line(line)
        except Proto21Error:
            if state == "data":
                continue  # message body lines
            return False, "bad command line: " + line.strip()
        if state == "start":
            if cmd in ("EHLO", "HELO"):
                state = "hello"
            else:
                return False, "expected EHLO/HELO first"
        elif state == "hello":
            if cmd == "MAIL":
                state = "mail"
            elif cmd not in ("EHLO", "HELO", "NOOP", "RSET", "QUIT"):
                return False, "expected MAIL after hello"
        elif state == "mail":
            if cmd == "RCPT":
                state = "rcpt"
            else:
                return False, "expected RCPT after MAIL"
        elif state == "rcpt":
            if cmd == "DATA":
                state = "data"
            elif cmd != "RCPT":
                return False, "expected RCPT or DATA"
        elif state == "data":
            if cmd == "QUIT":
                state = "done"
    if state not in ("data", "done"):
        return False, "incomplete sequence, ended in " + state
    return True, "valid SMTP sequence"


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
    assert parse_smtp_line("MAIL FROM:<a@b>") == ("MAIL", "FROM:<a@b>")
    ok, _ = validate_sequence(["EHLO h", "MAIL FROM:<a>", "RCPT TO:<b>", "DATA", "hi", "QUIT"])
    assert ok is True
    ok, _ = validate_sequence(["MAIL FROM:<a>"])
    assert ok is False

    assert stdlib_only()
    print("proto-21 (smtp): OK")


if __name__ == "__main__":
    main()
