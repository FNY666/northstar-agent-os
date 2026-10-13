"""Runtime defense 06: capability dropping (config), Simulated.

Linux capability bounding-set config: the full drop list plus the small
keep set for an agent sandbox.  Consumed by a launcher (capsh/capset);
this module validates the sets.

What this IS: validated capability drop/keep lists.
What this IS NOT: actual capset syscalls.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

#: Module version.
RUNTIME_DEFENSE_06_VERSION = "runtime-defense-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-06.v1"


class CapabilityError(Exception):
    """Fail-closed: bad capability config raises."""


#: All capabilities this config knows about (subset of linux/capability.h).
KNOWN_CAPS = frozenset({
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID",
    "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE", "CAP_NET_ADMIN", "CAP_NET_RAW",
    "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT",
    "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
    "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG",
    "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ",
})

#: Dangerous caps that must ALWAYS be dropped (cannot be kept).
ALWAYS_DROP = frozenset({
    "CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_RAWIO",
    "CAP_SYS_PTRACE", "CAP_SYS_BOOT", "CAP_SYS_TIME",
    "CAP_NET_ADMIN", "CAP_DAC_OVERRIDE", "CAP_SETUID",
    "CAP_SETGID", "CAP_SETPCAP", "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE", "CAP_AUDIT_CONTROL",
})

#: Default keep set for an agent sandbox (almost nothing).
DEFAULT_KEEP = frozenset({"CAP_AUDIT_WRITE"})


@dataclass(frozen=True)
class CapabilityConfig:
    """Validated capability config."""

    keep: frozenset
    drop: frozenset

    def capsh_args(self) -> list:
        """capsh(1) args, e.g. ['--drop=cap_sys_admin,...']."""
        return ["--drop=" + ",".join(
            c.lower() for c in sorted(self.drop)
        )]


def build_config(keep=None) -> CapabilityConfig:
    """Build capability config.  Fail-closed on unknown or dangerous keeps."""
    keep = frozenset(keep) if keep is not None else DEFAULT_KEEP
    unknown = set(keep) - set(KNOWN_CAPS)
    if unknown:
        raise CapabilityError(f"unknown caps: {sorted(unknown)}")
    dangerous = set(keep) & set(ALWAYS_DROP)
    if dangerous:
        raise CapabilityError(
            f"refusing to keep dangerous caps: {sorted(dangerous)}"
        )
    drop = KNOWN_CAPS - keep
    return CapabilityConfig(keep=keep, drop=drop)


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
    assert "CAP_SYS_ADMIN" in cfg.drop
    assert "CAP_AUDIT_WRITE" in cfg.keep
    assert len(cfg.drop) == len(KNOWN_CAPS) - 1
    assert cfg.capsh_args()[0].startswith("--drop=")

    try:
        build_config({"CAP_SYS_ADMIN"})
        raise AssertionError("should raise")
    except CapabilityError:
        pass
    try:
        build_config({"CAP_BOGUS"})
        raise AssertionError("should raise")
    except CapabilityError:
        pass

    assert stdlib_only()
    print("runtime-defense-06 OK: cap drop lists, dangerous refusal, stdlib")


if __name__ == "__main__":
    main()
