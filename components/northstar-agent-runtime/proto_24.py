"""Mock FTP parser: reply codes incl. multiline, command lines.

What this IS: parser/validator for FTP (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete FTP (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import re

#: Module version.
PROTO_24_VERSION = "proto-24-ftp.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-24-ftp.v1"


class Proto24Error(Exception):
    """Fail-closed."""


_REPLY_RE = re.compile(r"^(\d{3})([ -])(.*)$")


def parse_reply(text: str) -> dict:
    """Parse an FTP reply, including multiline. Raises Proto24Error."""
    lines = text.replace("\r\n", "\n").split("\n")
    m = _REPLY_RE.match(lines[0])
    if not m:
        raise Proto24Error("bad reply line")
    code, sep, rest = m.groups()
    code = int(code)
    collected = [rest]
    if sep == "-":
        for line in lines[1:]:
            collected.append(line)
            m2 = _REPLY_RE.match(line)
            if m2 and int(m2.group(1)) == code and m2.group(2) == " ":
                break
        else:
            raise Proto24Error("unterminated multiline reply")
    return {"code": code, "lines": collected}


def parse_command(line: str) -> tuple:
    """Parse an FTP command line into (verb, arg). Raises Proto24Error."""
    parts = line.strip().split(None, 1)
    if not parts:
        raise Proto24Error("empty command")
    return parts[0].upper(), (parts[1] if len(parts) > 1 else "")


def is_success(code: int) -> bool:
    """True for 2xx reply codes."""
    return 200 <= code < 300


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
    r = parse_reply("220-Welcome\r\n220 Ready\r\n")
    assert r["code"] == 220 and r["lines"] == ["Welcome", "220 Ready"]
    assert parse_command("retr /f") == ("RETR", "/f")
    assert is_success(226) is True and is_success(550) is False

    assert stdlib_only()
    print("proto-24 (ftp): OK")


if __name__ == "__main__":
    main()
