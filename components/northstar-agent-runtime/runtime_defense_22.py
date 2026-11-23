"""Runtime defense 22: Syscall filtering (allowlist), Simulated.

Default-deny syscall policy: only syscalls on the allowlist may run.
Unknown syscalls are blocked.  Hosts map this to seccomp-BPF.

What this IS: allowlist policy + name check.

What this IS NOT:
* Not seccomp itself -- host installs the BPF filter.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import FrozenSet, List

#: Module version.
RUNTIME_DEFENSE_22_VERSION = "runtime-defense-22.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-22.v1"

#: Conservative default allowlist (common benign syscalls).
DEFAULT_ALLOWLIST = frozenset({
    "read", "write", "open", "openat", "close", "stat", "fstat",
    "lstat", "lseek", "mmap", "mprotect", "munmap", "brk",
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl",
    "pread64", "pwrite64", "readv", "writev", "access", "pipe",
    "select", "poll", "sched_yield", "mremap", "msync",
    "getpid", "getppid", "getuid", "getgid", "geteuid", "getegid",
    "getcwd", "chdir", "fchdir", "exit", "exit_group",
    "arch_prctl", "set_tid_address", "set_robust_list",
    "rseq", "prlimit64", "getrandom", "clock_gettime",
    "nanosleep", "futex", "epoll_create", "epoll_ctl", "epoll_wait",
    "socket", "connect", "sendto", "recvfrom",
})


class SyscallFilterError(Exception):
    """Fail-closed: bad policy raises."""


@dataclass(frozen=True)
class SyscallPolicy:
    """Syscall allowlist policy."""

    allowed: FrozenSet[str] = DEFAULT_ALLOWLIST
    # Extra syscalls to deny even if allowlisted (deny wins).
    denied: FrozenSet[str] = frozenset()

    def __post_init__(self):
        if not self.allowed:
            raise SyscallFilterError("allowlist must be non-empty")
        # Overlap is legal: deny wins over allow (checked in is_allowed).


def is_allowed(syscall: str, policy: SyscallPolicy) -> bool:
    """True if the syscall may execute under the policy."""
    if not syscall:
        raise SyscallFilterError("syscall name required")
    if syscall in policy.denied:
        return False
    return syscall in policy.allowed


def filter_calls(calls: List[str], policy: SyscallPolicy) -> List[str]:
    """Return the denied subset of a call list."""
    return [c for c in calls if not is_allowed(c, policy)]


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
    policy = SyscallPolicy()
    assert is_allowed("read", policy) is True
    assert is_allowed("execve", policy) is False  # default deny
    assert is_allowed("ptrace", policy) is False
    strict = SyscallPolicy(
        allowed=frozenset({"read", "write"}), denied=frozenset({"write"})
    )
    assert is_allowed("write", strict) is False  # deny wins
    denied = filter_calls(["read", "execve", "write"], policy)
    assert denied == ["execve"]
    try:
        SyscallPolicy(allowed=frozenset())
        raise AssertionError("should raise")
    except SyscallFilterError:
        pass
    assert stdlib_only()
    print("runtime-defense-22 OK: syscall allowlist, deny-wins, fail-closed")


if __name__ == "__main__":
    main()
