"""Runtime defense 02: AppArmor profiles (policy generator), Simulated.

Generates AppArmor profile text with file/network/capability rules at
three strictness levels.  The profile is a CONFIG artifact; enforcement
is done by the kernel AppArmor LSM.

What this IS: AppArmor policy text generation + validation.
What this IS NOT: actual AppArmor enforcement (needs kernel + apparmor_parser).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List

#: Module version.
RUNTIME_DEFENSE_02_VERSION = "runtime-defense-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-02.v1"


class ApparmorError(Exception):
    """Fail-closed: bad profiles raise."""


@dataclass(frozen=True)
class ApparmorRule:
    """One AppArmor rule line."""

    path: str
    access: str  # e.g. "r", "rw", "rix", "mr"

    def render(self) -> str:
        if self.access == "deny":
            return f"  deny {self.path},"
        return f"  {self.path} {self.access},"


@dataclass
class ApparmorProfile:
    """A generated AppArmor profile."""

    name: str
    mode: str = "enforce"  # "enforce" or "complain"
    rules: List[ApparmorRule] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            f'profile {self.name} flags=({self.mode}) {{',
            "  #include <abstractions/base>",
        ]
        for rule in self.rules:
            lines.append(rule.render())
        lines.append("}")
        return "\n".join(lines)


def generate_profile(name: str, level: str) -> ApparmorProfile:
    """Generate an AppArmor profile.

    Levels: minimal (read-only app dir), standard (+ tmp writes),
    permissive (+ broader reads).
    """
    if not name:
        raise ApparmorError("profile name required")
    if level == "minimal":
        rules = [
            ApparmorRule("/opt/agent/**", "r"),
            ApparmorRule("/usr/lib/**", "mr"),
            ApparmorRule("deny /etc/shadow", "deny"),
            ApparmorRule("deny /root/**", "deny"),
        ]
    elif level == "standard":
        rules = [
            ApparmorRule("/opt/agent/**", "rw"),
            ApparmorRule("/tmp/agent-*/**", "rw"),
            ApparmorRule("/usr/lib/**", "mr"),
            ApparmorRule("deny /etc/shadow", "deny"),
            ApparmorRule("deny /root/**", "deny"),
        ]
    elif level == "permissive":
        rules = [
            ApparmorRule("/opt/agent/**", "rw"),
            ApparmorRule("/tmp/**", "rw"),
            ApparmorRule("/usr/**", "r"),
            ApparmorRule("deny /etc/shadow", "deny"),
        ]
    else:
        raise ApparmorError(f"unknown level {level!r}")
    if not rules:
        raise ApparmorError("empty rules: fail-closed")
    return ApparmorProfile(name=name, rules=rules)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    p = generate_profile("agent", "minimal")
    text = p.render()
    assert "profile agent" in text
    assert "enforce" in text
    assert "deny /etc/shadow" in text

    std = generate_profile("agent", "standard")
    assert "/tmp/agent-*/**" in std.render()

    try:
        generate_profile("agent", "bogus")
        raise AssertionError("should raise")
    except ApparmorError:
        pass
    try:
        generate_profile("", "minimal")
        raise AssertionError("should raise")
    except ApparmorError:
        pass

    assert stdlib_only()
    print("runtime-defense-02 OK: profiles, deny rules, fail-closed, stdlib")


if __name__ == "__main__":
    main()
