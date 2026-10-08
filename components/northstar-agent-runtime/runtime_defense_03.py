"""Runtime defense 03: SELinux policies (mock policy), Simulated.

Generates a mock SELinux policy module: types, allow rules, and
neverallow rules for an agent sandbox domain.  This is a POLICY MODEL,
not real SELinux policy language -- real enforcement needs the
SELinux toolchain (checkmodule, semodule).

What this IS: a mock allow/neverallow policy model for review.
What this IS NOT: loadable SELinux policy.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Set

#: Module version.
RUNTIME_DEFENSE_03_VERSION = "runtime-defense-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-03.v1"


class SelinuxError(Exception):
    """Fail-closed: bad policy raises."""


@dataclass(frozen=True)
class SelinuxRule:
    """One allow rule: subject type -> object type : class perms."""

    subject: str
    obj: str
    obj_class: str
    perms: FrozenSet[str]

    def render(self) -> str:
        perms = " ".join(sorted(self.perms))
        return f"allow {self.subject} {self.obj}:{self.obj_class} {{ {perms} }};"


@dataclass
class SelinuxPolicy:
    """Mock SELinux policy module."""

    name: str
    types: Set[str] = field(default_factory=set)
    allow_rules: List[SelinuxRule] = field(default_factory=list)
    neverallow: List[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [f"# mock policy module: {self.name}", ""]
        for t in sorted(self.types):
            lines.append(f"type {t};")
        lines.append("")
        for rule in self.allow_rules:
            lines.append(rule.render())
        lines.append("")
        for rule in self.neverallow:
            lines.append(f"neverallow {rule};")
        return "\n".join(lines)

    def check(self, subject: str, obj: str, obj_class: str, perm: str) -> bool:
        """Mock access check: True if an allow rule covers it and no
        neverallow matches.  Fail-closed on unknown."""
        for pattern in self.neverallow:
            # neverallow patterns are "subject obj:class" prefixes.
            if pattern.startswith(f"{subject} {obj}:{obj_class}"):
                return False
        for rule in self.allow_rules:
            if (rule.subject == subject and rule.obj == obj
                    and rule.obj_class == obj_class and perm in rule.perms):
                return True
        return False


def generate_policy(name: str) -> SelinuxPolicy:
    """Generate the agent sandbox mock policy."""
    if not name:
        raise SelinuxError("policy name required")
    policy = SelinuxPolicy(name=name)
    policy.types.update({"agent_t", "agent_exec_t", "agent_tmp_t", "agent_data_t"})
    policy.allow_rules.extend([
        SelinuxRule("agent_t", "agent_exec_t", "file",
                    frozenset({"read", "execute", "map"})),
        SelinuxRule("agent_t", "agent_tmp_t", "file",
                    frozenset({"read", "write", "create", "unlink"})),
        SelinuxRule("agent_t", "agent_data_t", "file",
                    frozenset({"read", "write"})),
    ])
    policy.neverallow.extend([
        "agent_t shadow_t:file",
        "agent_t self:capability",
    ])
    return policy


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
    p = generate_policy("agent_sandbox")
    assert p.check("agent_t", "agent_tmp_t", "file", "write") is True
    assert p.check("agent_t", "agent_tmp_t", "file", "execute") is False
    assert p.check("agent_t", "shadow_t", "file", "read") is False  # neverallow
    assert p.check("agent_t", "other_t", "file", "read") is False  # unknown: deny
    assert "neverallow" in p.render()

    try:
        generate_policy("")
        raise AssertionError("should raise")
    except SelinuxError:
        pass

    assert stdlib_only()
    print("runtime-defense-03 OK: mock policy, neverallow, fail-closed, stdlib")


if __name__ == "__main__":
    main()
