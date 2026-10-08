"""INI parser/validator (stdlib configparser).

What this IS: parser/validator for INI.
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete INI implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import configparser

#: Module version.
PROTO_06_VERSION = "proto-06-ini.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-06-ini.v1"


class Proto06Error(Exception):
    """Fail-closed."""


def parse_ini(text: str) -> dict:
    """Parse INI text into {section: {key: value}}. Raises Proto06Error."""
    parser = configparser.ConfigParser()
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise Proto06Error("invalid INI: %s" % exc)
    return {s: dict(parser[s]) for s in parser.sections()}


def validate_ini(text: str, required_sections=None) -> tuple:
    """Validate INI; optionally require sections. Returns (ok, reason)."""
    try:
        data = parse_ini(text)
    except Proto06Error as exc:
        return False, str(exc)
    if required_sections:
        missing = [s for s in required_sections if s not in data]
        if missing:
            return False, "missing sections: " + ",".join(missing)
    return True, "valid INI"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "configparser", "pathlib", "typing"}
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
    data = parse_ini("[db]\nhost = x\nport = 1\n")
    assert data == {"db": {"host": "x", "port": "1"}}
    ok, _ = validate_ini("[db]\nhost = x\n", ["db", "web"])
    assert ok is False

    assert stdlib_only()
    print("proto-06 (ini): OK")


if __name__ == "__main__":
    main()
