"""Seccomp-BPF denylist for the bwrap sandbox backend.

Pure-Python classic-BPF assembler: no libseccomp dependency, so the filter is
built on any host and unit-tested offline. It is applied only by the bwrap
backend (``bwrap --seccomp FD``); the process backend cannot honestly apply a
BPF filter, so ``seccomp="on"`` with a non-bwrap backend is a configuration
error — the same no-silent-downgrade rule as ``--sandbox bwrap`` on a host
without bubblewrap.

Policy shape: a default-deny allowlist is unworkable for a general Shell tool
(every command would need enumerating), so this is a conservative denylist
aimed at privilege-escalation and sandbox-escape primitives that no legitimate
workspace command needs: kernel module loading, kexec, BPF program loading,
perf, userfaultfd, keyrings, ptrace, cross-process memory access, and
filesystem super-operations (mount/pivot_root/...). The namespaces already
blunt most of these; seccomp is defense in depth, which is exactly what the
threat model calls "a later hardening step".

Syscall numbers are per-architecture and were verified against the sources,
not memory: x86_64 against ``/usr/include/x86_64-linux-gnu/asm/unistd_64.h``,
aarch64 against upstream ``include/uapi/asm-generic/unistd.h`` (torvalds/linux).
An unknown arch falls through to ALLOW — documented, and the honest choice
over applying the wrong table.

Denied calls fail with EPERM, not SIGSYS: a blocked call surfaces as an
ordinary error in the tool result instead of killing the child, which keeps
the failure observable and debuggable.
"""
from __future__ import annotations

import struct

#: Operator-facing modes. ``auto`` applies the denylist whenever the bwrap
#: backend runs and notes its absence on the process backend; ``on`` requires
#: bwrap + filter and refuses anything else; ``off`` disables the filter.
SECCOMP_MODES = ("auto", "on", "off")

# Strictness order for the tighten-only rule: a per-call payload may only move
# toward "on", never away from what the operator configured.
_STRICTNESS = {"off": 0, "auto": 1, "on": 2}

# seccomp_data layout: u32 nr @ 0, u32 arch @ 4.
_NR_OFFSET = 0
_ARCH_OFFSET = 4

_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7

# Classic BPF opcodes.
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JA = 0x05
_BPF_RET_K = 0x06

_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_EPERM = 1

#: Denylisted syscalls per architecture. Numbers verified against kernel
#: sources (see module docstring); do not extend from memory.
_DENY_X86_64: dict[str, int] = {
    "ptrace": 101,
    "mount": 165,
    "umount2": 166,
    "pivot_root": 155,
    "reboot": 169,
    "swapon": 167,
    "swapoff": 168,
    "acct": 163,
    "init_module": 175,
    "delete_module": 176,
    "finit_module": 313,
    "kexec_load": 246,
    "kexec_file_load": 320,
    "bpf": 321,
    "perf_event_open": 298,
    "userfaultfd": 323,
    "add_key": 248,
    "request_key": 249,
    "keyctl": 250,
    "clock_settime": 227,
    "settimeofday": 164,
    "iopl": 172,
    "ioperm": 173,
    "process_vm_readv": 310,
    "process_vm_writev": 311,
    "open_by_handle_at": 304,
    "name_to_handle_at": 303,
    "fanotify_init": 300,
}

_DENY_AARCH64: dict[str, int] = {
    "ptrace": 117,
    "mount": 40,
    "umount2": 39,
    "pivot_root": 41,
    "reboot": 142,
    "swapon": 224,
    "swapoff": 225,
    "acct": 89,
    "init_module": 105,
    "delete_module": 106,
    "finit_module": 273,
    "kexec_load": 104,
    "kexec_file_load": 294,
    "bpf": 280,
    "perf_event_open": 241,
    "userfaultfd": 282,
    "add_key": 217,
    "request_key": 218,
    "keyctl": 219,
    "clock_settime": 112,
    "settimeofday": 170,
    "process_vm_readv": 270,
    "process_vm_writev": 271,
    "open_by_handle_at": 265,
    "name_to_handle_at": 264,
    "fanotify_init": 262,
}


class SeccompError(ValueError):
    """Invalid seccomp mode or an unsatisfiable seccomp requirement."""


def validate_mode(mode: str) -> str:
    """Normalise an operator/model seccomp mode; raise on unknown values."""
    if not isinstance(mode, str):
        raise SeccompError(
            f"seccomp mode must be a string, got {type(mode).__name__}; "
            f"choose one of {', '.join(SECCOMP_MODES)}"
        )
    name = mode.strip().lower() or "auto"
    if name not in SECCOMP_MODES:
        raise SeccompError(
            f"unknown seccomp mode {mode!r}; choose one of {', '.join(SECCOMP_MODES)}"
        )
    return name


def resolve_mode(payload_value: str | None, service_value: str | None) -> str:
    """Merge a per-call payload value with the operator-configured service value.

    Tighten-only: the call may move toward ``on`` but never away from what the
    operator configured. ``service="on"`` + ``payload="off"`` stays ``on``.
    """
    service = validate_mode(service_value or "auto")
    requested = validate_mode(payload_value if payload_value is not None else service)
    if _STRICTNESS[requested] >= _STRICTNESS[service]:
        return requested
    return service


def _stmt(code: int, k: int) -> bytes:
    return struct.pack("<HBBI", code, 0, 0, k)


def _jump_eq(k: int, jt: int, jf: int) -> bytes:
    return struct.pack("<HBBI", _BPF_JMP_JEQ_K, jt, jf, k)


def _jump_always(offset: int) -> bytes:
    return struct.pack("<HBBI", _BPF_JMP_JA, 0, 0, offset)


def build_default_filter() -> bytes:
    """Assemble the denylist BPF program.

    Layout::

        ld [arch]
        jeq X86_64 -> x86_chain
        jeq AARCH64 -> arm_chain else ALLOW
      x86_chain:
        ld [nr]
        jeq n1 -> DENY ... jeq nN -> DENY
        ja ALLOW
      arm_chain:
        ld [nr]
        jeq m1 -> DENY ... jeq mM -> DENY
        ja ALLOW
      ALLOW: ret SECCOMP_RET_ALLOW
      DENY:  ret SECCOMP_RET_ERRNO|EPERM
    """
    x86_numbers = sorted(set(_DENY_X86_64.values()))
    arm_numbers = sorted(set(_DENY_AARCH64.values()))

    # Index plan (each entry is one 8-byte instruction).
    x86_start = 3
    x86_end = x86_start + 1 + len(x86_numbers)  # ld + N jeq
    arm_start = x86_end + 1  # + ja ALLOW
    arm_end = arm_start + 1 + len(arm_numbers)
    allow_idx = arm_end + 1  # + ja ALLOW
    deny_idx = allow_idx + 1

    prog = b""
    prog += _stmt(_BPF_LD_W_ABS, _ARCH_OFFSET)  # 0: A = arch
    prog += _jump_eq(_AUDIT_ARCH_X86_64, x86_start - 2, 0)  # 1
    prog += _jump_eq(_AUDIT_ARCH_AARCH64, arm_start - 3, allow_idx - 3)  # 2
    # x86_64 chain.
    prog += _stmt(_BPF_LD_W_ABS, _NR_OFFSET)  # x86_start: A = nr
    for i, nr in enumerate(x86_numbers):
        prog += _jump_eq(nr, deny_idx - (x86_start + 2 + i), 0)
    prog += _jump_always(allow_idx - (x86_end + 1))
    # aarch64 chain.
    prog += _stmt(_BPF_LD_W_ABS, _NR_OFFSET)  # arm_start: A = nr
    for i, nr in enumerate(arm_numbers):
        prog += _jump_eq(nr, deny_idx - (arm_start + 2 + i), 0)
    prog += _jump_always(allow_idx - (arm_end + 1))
    prog += _stmt(_BPF_RET_K, _SECCOMP_RET_ALLOW)  # allow_idx
    prog += _stmt(_BPF_RET_K, _SECCOMP_RET_ERRNO | _EPERM)  # deny_idx

    expected = (deny_idx + 1) * 8
    if len(prog) != expected:  # pragma: no cover - internal consistency
        raise SeccompError(f"assembler produced {len(prog)} bytes, expected {expected}")
    return prog


def denied_syscalls(arch: str = "x86_64") -> dict[str, int]:
    """The denylist table for an arch (``x86_64`` or ``aarch64``)."""
    if arch == "x86_64":
        return dict(_DENY_X86_64)
    if arch == "aarch64":
        return dict(_DENY_AARCH64)
    raise SeccompError(f"no denylist table for arch {arch!r}")


__all__ = [
    "SECCOMP_MODES",
    "SeccompError",
    "build_default_filter",
    "denied_syscalls",
    "resolve_mode",
    "validate_mode",
]
