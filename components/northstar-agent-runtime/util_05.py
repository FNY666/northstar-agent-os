"""String helpers: truncate, sanitize, slugify, mask, blank check. What this IS: safe display/log string handling. What this IS NOT: not a template engine."""

from __future__ import annotations

import ast
import re
import unicodedata

#: Module version.
UTIL_05_VERSION = "util-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-05.v1"


class StringError(Exception):
    """String helper failure."""


def truncate(s: str, max_len: int, ellipsis="\u2026") -> str:
    if max_len <= 0:
        raise StringError("max_len must be positive")
    if len(s) <= max_len:
        return s
    return s[: max_len - len(ellipsis)] + ellipsis


def sanitize(s: str) -> str:
    """Strip control characters except newline and tab."""
    return "".join(
        ch for ch in s if ch in "\n\t" or not unicodedata.category(ch).startswith("C")
    )


def slugify(s: str) -> str:
    ascii_s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "-", ascii_s.lower()).strip("-")


def mask(s: str, keep=4, mask_char="*") -> str:
    """Keep last `keep` chars, mask the rest."""
    if keep < 0:
        raise StringError("keep must be >= 0")
    if keep == 0 or len(s) <= keep:
        return mask_char * len(s)
    return mask_char * (len(s) - keep) + s[-keep:]


def is_blank(s: str) -> bool:
    return not s or not s.strip()


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib', 're', 'unicodedata']
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
    assert truncate("hello", 4) == "hel\u2026"
    assert sanitize("a\x00b\n") == "ab\n"
    assert slugify("Hello, World!") == "hello-world"
    assert mask("1234567890") == "******7890"
    assert is_blank(" \t") is True
    print("string helpers OK")


if __name__ == "__main__":
    main()
