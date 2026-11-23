"""Tool versioning: semver checks, Simulated.

Each tool has a semver version (MAJOR.MINOR.PATCH).  Checks:
- is_compatible: same MAJOR, client MINOR <= tool MINOR
- satisfies: version satisfies a constraint like ">=1.2.0"

What this IS: version compatibility for tool calls.

What this IS NOT:
* Not a package manager -- just compatibility logic.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Tuple

#: Module version.
TOOL_SYSTEM_02_VERSION = "tool-system-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-02.v1"


class ToolSystem02Error(Exception):
    """Fail-closed: bad version raises."""


@dataclass(frozen=True)
class Version:
    """Semver version."""

    major: int
    minor: int
    patch: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def as_tuple(self) -> Tuple[int, int, int]:
        return (self.major, self.minor, self.patch)


def parse_version(s: str) -> Version:
    """Parse 'MAJOR.MINOR.PATCH'."""
    if not isinstance(s, str):
        raise ToolSystem02Error("version must be str")
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", s.strip())
    if not m:
        raise ToolSystem02Error(f"bad version '{s}'")
    return Version(int(m.group(1)), int(m.group(2)), int(m.group(3)))


def is_compatible(tool: Version, client: Version) -> bool:
    """Compatible if same MAJOR and tool MINOR >= client MINOR."""
    return tool.major == client.major and (
        tool.minor > client.minor
        or (tool.minor == client.minor and tool.patch >= client.patch)
    )


def satisfies(version: Version, constraint: str) -> bool:
    """Check constraint like '>=1.2.0', '==2.0.0', '<3.0.0'."""
    m = re.fullmatch(r"(>=|<=|==|>|<)\s*(\d+\.\d+\.\d+)", constraint.strip())
    if not m:
        raise ToolSystem02Error(f"bad constraint '{constraint}'")
    op, other = m.group(1), parse_version(m.group(2))
    a, b = version.as_tuple(), other.as_tuple()
    return {
        ">=": a >= b, "<=": a <= b, "==": a == b, ">": a > b, "<": a < b,
    }[op]


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "typing"}
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
    v = parse_version("1.2.3")
    assert v.major == 1 and v.minor == 2 and v.patch == 3
    assert str(v) == "1.2.3"
    assert is_compatible(parse_version("1.5.0"), parse_version("1.2.0")) is True
    assert is_compatible(parse_version("2.0.0"), parse_version("1.9.9")) is False
    assert is_compatible(parse_version("1.1.0"), parse_version("1.2.0")) is False
    assert satisfies(parse_version("1.2.3"), ">=1.2.0") is True
    assert satisfies(parse_version("1.2.3"), "==1.2.4") is False
    assert satisfies(parse_version("1.2.3"), "<2.0.0") is True
    try:
        parse_version("1.2")
        raise AssertionError("should raise")
    except ToolSystem02Error:
        pass
    assert stdlib_only()
    print("tool_system_02 OK: semver, compat, constraints")


if __name__ == "__main__":
    main()
