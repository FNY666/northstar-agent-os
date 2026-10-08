"""Version helpers: semver parse, compare, bump. What this IS: x.y.z handling. What this IS NOT: not PEP 440."""

from __future__ import annotations

import ast
import re

#: Module version.
UTIL_36_VERSION = "util-36.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-36.v1"


class VersionError(Exception):
    """Version helper failure."""


_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")


def parse_semver(s: str):
    mt = _SEMVER.match((s or "").strip())
    if not mt:
        raise VersionError(f"bad semver: {s!r}")
    return (int(mt.group(1)), int(mt.group(2)), int(mt.group(3)))


def compare(a: str, b: str) -> int:
    pa, pb = parse_semver(a), parse_semver(b)
    return (pa > pb) - (pa < pb)


def is_newer(a: str, b: str) -> bool:
    return compare(a, b) > 0


def bump_patch(s: str) -> str:
    major, minor, patch = parse_semver(s)
    return f"{major}.{minor}.{patch + 1}"


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
    assert parse_semver("1.2.3") == (1, 2, 3)
    assert compare("1.2.3", "1.2.4") == -1
    assert compare("2.0.0", "1.9.9") == 1
    assert compare("1.0.0", "1.0.0") == 0
    assert is_newer("1.2.4", "1.2.3") is True
    assert bump_patch("1.2.3") == "1.2.4"
    print("version helpers OK")


if __name__ == "__main__":
    main()
