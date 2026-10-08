"""Runtime defense 01: seccomp profiles (syscall allowlist generator), Simulated.

Generates seccomp-bpf style syscall allowlists at three strictness levels:
- minimal: ~30 syscalls (compute-only, no exec, no network)
- standard: minimal + file/network basics
- permissive: standard + process control

The profile is a CONFIG artifact.  Actual enforcement is done by the
kernel (seccomp-bpf); this module only generates and validates the
allowlist policy.

What this IS: policy generation + validation for syscall allowlists.
What this IS NOT: actual seccomp enforcement (needs kernel + loader).
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List

#: Module version.
RUNTIME_DEFENSE_01_VERSION = "runtime-defense-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-01.v1"


class SeccompError(Exception):
    """Fail-closed: bad profiles raise."""


#: Base syscalls always allowed (needed for a Python process to run).
_BASE_SYSCALLS = frozenset({
    "read", "write", "open", "openat", "close", "stat", "fstat",
    "lstat", "poll", "lseek", "mmap", "mprotect", "munmap",
    "brk", "rt_sigaction", "rt_sigprocmask", "ioctl",
    "pread64", "pwrite64", "readv", "writev", "access",
    "exit", "exit_group", "arch_prctl", "set_tid_address",
    "set_robust_list", "futex", "sched_getaffinity",
})

#: Network syscalls (only in standard/permissive).
_NETWORK_SYSCALLS = frozenset({
    "socket", "connect", "accept", "bind", "listen",
    "sendto", "recvfrom", "sendmsg", "recvmsg",
    "getsockname", "getpeername", "setsockopt", "getsockopt",
})

#: Process-control syscalls (only permissive).
_PROCESS_SYSCALLS = frozenset({
    "clone", "clone3", "fork", "vfork", "execve", "execveat",
    "wait4", "kill",
})


@dataclass(frozen=True)
class SeccompProfile:
    """A generated seccomp allowlist profile."""

    level: str  # "minimal", "standard", "permissive"
    allowlist: FrozenSet[str]
    default_action: str = "SCMP_ACT_ERRNO"

    def to_json(self) -> str:
        """Render as JSON (OCI seccomp profile shape, simplified)."""
        return json.dumps({
            "defaultAction": self.default_action,
            "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [{
                "names": sorted(self.allowlist),
                "action": "SCMP_ACT_ALLOW",
            }],
        }, sort_keys=True)


def generate_profile(level: str) -> SeccompProfile:
    """Generate a seccomp profile at the given strictness level.

    Fail-closed: unknown level raises; empty allowlist raises.
    """
    if level == "minimal":
        allowlist = _BASE_SYSCALLS
    elif level == "standard":
        allowlist = _BASE_SYSCALLS | _NETWORK_SYSCALLS
    elif level == "permissive":
        allowlist = _BASE_SYSCALLS | _NETWORK_SYSCALLS | _PROCESS_SYSCALLS
    else:
        raise SeccompError(f"unknown level {level!r}")
    if not allowlist:
        raise SeccompError("empty allowlist: fail-closed")
    return SeccompProfile(level=level, allowlist=allowlist)


def is_allowed(profile: SeccompProfile, syscall: str) -> bool:
    """Check if a syscall is in the allowlist (policy check only)."""
    return syscall in profile.allowlist


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "json", "pathlib", "typing"}
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
    minimal = generate_profile("minimal")
    assert is_allowed(minimal, "read") is True
    assert is_allowed(minimal, "socket") is False  # no network
    assert is_allowed(minimal, "execve") is False  # no exec

    standard = generate_profile("standard")
    assert is_allowed(standard, "socket") is True
    assert is_allowed(standard, "execve") is False

    permissive = generate_profile("permissive")
    assert is_allowed(permissive, "execve") is True

    # Strictness ordering.
    assert len(minimal.allowlist) < len(standard.allowlist) < len(permissive.allowlist)

    # Unknown level: fail-closed.
    try:
        generate_profile("bogus")
        raise AssertionError("should raise")
    except SeccompError:
        pass

    # JSON renders.
    parsed = json.loads(minimal.to_json())
    assert parsed["defaultAction"] == "SCMP_ACT_ERRNO"

    assert stdlib_only()
    print("runtime-defense-01 OK: profiles, allowlists, fail-closed, stdlib")


if __name__ == "__main__":
    main()
