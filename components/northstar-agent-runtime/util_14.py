"""Format helpers: human bytes, durations, SI numbers, plurals. What this IS: display formatting. What this IS NOT: not locale-aware."""

from __future__ import annotations

import ast


#: Module version.
UTIL_14_VERSION = "util-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-14.v1"


class FormatError(Exception):
    """Format helper failure."""


def human_bytes(n) -> str:
    n = float(n)
    if n < 0:
        raise FormatError("negative bytes")
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def human_duration(seconds: float) -> str:
    seconds = float(seconds)
    if seconds < 0:
        raise FormatError("negative duration")
    if seconds < 60:
        return f"{seconds:g}s"
    mi, sec = divmod(int(seconds), 60)
    if mi < 60:
        return f"{mi}m {sec}s"
    h, mi = divmod(mi, 60)
    return f"{h}h {mi}m"


def human_number(n) -> str:
    n = float(n)
    for suffix, mag in (("T", 1e12), ("G", 1e9), ("M", 1e6), ("K", 1e3)):
        if abs(n) >= mag:
            return f"{n / mag:.2f}".rstrip("0").rstrip(".") + suffix
    return f"{n:g}"


def pluralize(n: int, singular: str, plural: str = None) -> str:
    word = singular if n == 1 else (plural if plural is not None else singular + "s")
    return f"{n} {word}"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib']
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
    assert human_bytes(1536) == "1.5 KiB"
    assert human_bytes(0) == "0 B"
    assert human_duration(90) == "1m 30s"
    assert human_number(1234567) == "1.23M"
    assert human_number(1500) == "1.5K"
    assert pluralize(1, "file") == "1 file"
    assert pluralize(2, "file") == "2 files"
    print("format helpers OK")


if __name__ == "__main__":
    main()
