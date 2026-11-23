"""Runtime defense 04: namespace isolation (config), Simulated.

Config for Linux namespace isolation: which namespaces to unshare for
the agent sandbox (pid, net, mnt, ipc, uts, cgroup, time, user).

The config is consumed by a launcher (unshare/clone flags).  This module
only validates the config; it does not create namespaces.

What this IS: validated namespace isolation config.
What this IS NOT: actual namespace creation.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

#: Module version.
RUNTIME_DEFENSE_04_VERSION = "runtime-defense-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-04.v1"


class NamespaceError(Exception):
    """Fail-closed: bad config raises."""


#: All namespaces this config knows about, with their clone flags.
KNOWN_NAMESPACES = {
    "pid": "CLONE_NEWPID",
    "net": "CLONE_NEWNET",
    "mnt": "CLONE_NEWNS",
    "ipc": "CLONE_NEWIPC",
    "uts": "CLONE_NEWUTS",
    "cgroup": "CLONE_NEWCGROUP",
    "time": "CLONE_NEWTIME",
    "user": "CLONE_NEWUSER",
}

#: Recommended default: isolate everything except user (user ns needs mapping).
DEFAULT_ISOLATED = frozenset({"pid", "net", "mnt", "ipc", "uts", "cgroup"})


@dataclass(frozen=True)
class NamespaceConfig:
    """Validated namespace isolation config."""

    isolated: frozenset  # subset of KNOWN_NAMESPACES
    hostname: str = "agent-sandbox"

    def clone_flags(self) -> list:
        """Clone flags for the isolated namespaces."""
        return [KNOWN_NAMESPACES[ns] for ns in sorted(self.isolated)]

    def unshare_args(self) -> list:
        """unshare(1) CLI args, e.g. ['--pid', '--net', '--mount', ...]."""
        mapping = {
            "pid": "--pid", "net": "--net", "mnt": "--mount",
            "ipc": "--ipc", "uts": "--uts", "cgroup": "--cgroup",
            "time": "--time", "user": "--user",
        }
        return [mapping[ns] for ns in sorted(self.isolated)]


def build_config(isolated=None, hostname: str = "agent-sandbox") -> NamespaceConfig:
    """Build and validate a namespace config.

    Fail-closed: unknown namespace names raise.
    """
    if isolated is None:
        isolated = set(DEFAULT_ISOLATED)
    isolated = frozenset(isolated)
    unknown = set(isolated) - set(KNOWN_NAMESPACES)
    if unknown:
        raise NamespaceError(f"unknown namespaces: {sorted(unknown)}")
    if not isolated:
        raise NamespaceError("empty isolation set: fail-closed")
    if not hostname:
        raise NamespaceError("hostname required")
    return NamespaceConfig(isolated=isolated, hostname=hostname)


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
    cfg = build_config()
    assert "pid" in cfg.isolated and "net" in cfg.isolated
    assert "CLONE_NEWPID" in cfg.clone_flags()
    assert "--pid" in cfg.unshare_args()

    custom = build_config({"pid", "mnt"})
    assert custom.isolated == frozenset({"pid", "mnt"})

    try:
        build_config({"bogus"})
        raise AssertionError("should raise")
    except NamespaceError:
        pass
    try:
        build_config(set())
        raise AssertionError("should raise")
    except NamespaceError:
        pass

    assert stdlib_only()
    print("runtime-defense-04 OK: namespace config, flags, fail-closed, stdlib")


if __name__ == "__main__":
    main()
