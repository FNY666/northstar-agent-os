"""Color helpers: hex/rgb conversion, ANSI codes. What this IS: terminal color plumbing. What this IS NOT: not a theme engine."""

from __future__ import annotations

import ast
import re

#: Module version.
UTIL_33_VERSION = "util-33.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-33.v1"


class ColorError(Exception):
    """Color helper failure."""


def hex_to_rgb(s: str):
    s = (s or "").strip().lstrip("#")
    if len(s) == 3:
        s = "".join(c * 2 for c in s)
    if len(s) != 6 or not re.fullmatch(r"[0-9a-fA-F]{6}", s):
        raise ColorError(f"bad hex color: {s!r}")
    return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16))


def rgb_to_hex(r: int, g: int, b: int) -> str:
    for v in (r, g, b):
        if not 0 <= v <= 255:
            raise ColorError(f"channel out of range: {v}")
    return f"#{r:02x}{g:02x}{b:02x}"


def ansi_fg(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"


def ansi_reset() -> str:
    return "\033[0m"


def strip_ansi(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s or "")


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib', 're']
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
    assert hex_to_rgb("#ff0000") == (255, 0, 0)
    assert hex_to_rgb("0f0") == (0, 255, 0)
    assert rgb_to_hex(255, 0, 0) == "#ff0000"
    assert hex_to_rgb(rgb_to_hex(1, 2, 3)) == (1, 2, 3)
    s = ansi_fg(255, 0, 0) + "x" + ansi_reset()
    assert strip_ansi(s) == "x"
    print("color helpers OK")


if __name__ == "__main__":
    main()
