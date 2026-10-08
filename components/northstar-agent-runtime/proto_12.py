"""Mock PEM parser: BEGIN/END blocks, label match, base64 body.

What this IS: parser/validator for PEM (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete PEM (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import base64
import re

#: Module version.
PROTO_12_VERSION = "proto-12-pem.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-12-pem.v1"


class Proto12Error(Exception):
    """Fail-closed."""


_PEM_RE = re.compile(
    r"-----BEGIN ([A-Za-z0-9 ]+)-----\r?\n"
    r"([A-Za-z0-9+/=\r\n]+?)\r?\n"
    r"-----END ([A-Za-z0-9 ]+)-----"
)


def parse_pem(text: str) -> list:
    """Parse PEM blocks into [{label, der}]. Mock: no crypto validation."""
    blocks = []
    for match in _PEM_RE.finditer(text):
        begin_label, body, end_label = match.groups()
        if begin_label != end_label:
            raise Proto12Error("label mismatch: %s vs %s" % (begin_label, end_label))
        try:
            der = base64.b64decode("".join(body.split()))
        except (base64.binascii.Error, ValueError) as exc:
            raise Proto12Error("bad base64: %s" % exc)
        blocks.append({"label": begin_label, "der": der})
    if not blocks:
        raise Proto12Error("no PEM blocks found")
    return blocks


def validate_pem(text: str) -> tuple:
    """Validate PEM blocks. Returns (ok, reason)."""
    try:
        blocks = parse_pem(text)
    except Proto12Error as exc:
        return False, str(exc)
    return True, "valid PEM (%d blocks)" % len(blocks)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "base64", "pathlib", "re", "typing"}
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
    body = base64.b64encode(b"der-bytes").decode()
    text = "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"
    blocks = parse_pem(text)
    assert blocks == [{"label": "CERTIFICATE", "der": b"der-bytes"}]
    ok, _ = validate_pem("no blocks here")
    assert ok is False

    assert stdlib_only()
    print("proto-12 (pem): OK")


if __name__ == "__main__":
    main()
