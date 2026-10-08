"""Validation helpers: email, URL, E.164 phone, UUID, hex. What this IS: cheap syntactic checks. What this IS NOT: not deliverability verification."""

from __future__ import annotations

import ast
import re
import urllib.parse
import uuid

#: Module version.
UTIL_13_VERSION = "util-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-13.v1"


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def is_email(s: str) -> bool:
    return bool(_EMAIL_RE.match(s or ""))


def is_url(s: str) -> bool:
    try:
        p = urllib.parse.urlparse(s or "")
    except ValueError:
        return False
    return p.scheme in ("http", "https") and bool(p.hostname)


def is_e164(s: str) -> bool:
    return bool(_E164_RE.match(s or ""))


def is_uuid(s: str) -> bool:
    try:
        uuid.UUID(s or "")
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def is_hex(s: str, length=None) -> bool:
    if not s or not _HEX_RE.match(s):
        return False
    return length is None or len(s) == length


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib', 're', 'urllib', 'uuid']
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
    assert is_email("a@b.com") is True
    assert is_email("bad") is False
    assert is_url("https://x.com") is True
    assert is_url("notaurl") is False
    assert is_e164("+14155552671") is True
    assert is_e164("123") is False
    assert is_uuid("12345678-1234-5678-1234-567812345678") is True
    assert is_hex("deadbeef", length=8) is True
    print("validation helpers OK")


if __name__ == "__main__":
    main()
