"""Runtime defense 07: read-only filesystem (mount config), Simulated.

Mount config: read-only root, explicit writable tmpfs paths, bind-mount
allowlist.  Consumed by a container/launcher; this module validates the
mount table.

What this IS: validated read-only mount config.
What this IS NOT: actual mount(2) calls.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import List

#: Module version.
RUNTIME_DEFENSE_07_VERSION = "runtime-defense-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-07.v1"


class MountError(Exception):
    """Fail-closed: bad mount config raises."""


@dataclass(frozen=True)
class MountEntry:
    """One mount entry."""

    target: str
    fstype: str  # "bind", "tmpfs", "proc", "sysfs"
    options: str  # e.g. "ro", "rw,nosuid,nodev"

    def is_writable(self) -> bool:
        opts = self.options.split(",")
        return "rw" in opts


@dataclass
class MountConfig:
    """Validated mount table."""

    root_readonly: bool = True
    entries: List[MountEntry] = field(default_factory=list)

    def validate(self) -> None:
        """Fail-closed validation."""
        if self.root_readonly:
            for e in self.entries:
                if e.target == "/" and e.is_writable():
                    raise MountError("root must be read-only")
        # Sensitive paths must never be writable bind mounts.
        for e in self.entries:
            if e.fstype == "bind" and e.is_writable():
                for sensitive in ("/etc", "/root", "/proc", "/sys"):
                    if e.target == sensitive or e.target.startswith(sensitive + "/"):
                        raise MountError(f"refusing writable bind on {e.target}")

    def writable_targets(self) -> List[str]:
        return [e.target for e in self.entries if e.is_writable()]


def build_config() -> MountConfig:
    """Default agent sandbox mount config."""
    cfg = MountConfig(root_readonly=True, entries=[
        MountEntry("/", "bind", "ro"),
        MountEntry("/tmp", "tmpfs", "rw,nosuid,nodev,noexec,size=256M"),
        MountEntry("/run/agent", "tmpfs", "rw,nosuid,nodev,noexec,size=64M"),
        MountEntry("/opt/agent", "bind", "ro"),
        MountEntry("/proc", "proc", "ro,nosuid,nodev,noexec"),
        MountEntry("/sys", "sysfs", "ro,nosuid,nodev,noexec"),
    ])
    cfg.validate()
    return cfg


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
    assert cfg.root_readonly is True
    assert "/tmp" in cfg.writable_targets()
    assert "/" not in cfg.writable_targets()

    bad = MountConfig(root_readonly=True, entries=[
        MountEntry("/", "bind", "rw"),
    ])
    try:
        bad.validate()
        raise AssertionError("should raise")
    except MountError:
        pass

    bad2 = MountConfig(root_readonly=True, entries=[
        MountEntry("/etc", "bind", "rw"),
    ])
    try:
        bad2.validate()
        raise AssertionError("should raise")
    except MountError:
        pass

    assert stdlib_only()
    print("runtime-defense-07 OK: ro mounts, tmpfs, fail-closed, stdlib")


if __name__ == "__main__":
    main()
