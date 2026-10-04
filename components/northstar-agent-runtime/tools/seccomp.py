"""Seccomp-BPF denylist for the sandbox backends.

Pure-Python classic-BPF assembler: no libseccomp dependency, so the filter is
built on any host and unit-tested offline. The bwrap backend loads it via
``bwrap --seccomp FD``; the process backend (Linux only) applies it through a
``python3 -c`` prctl wrapper (see :func:`prctl_loader_argv`) — no
``Popen(preexec_fn=...)``, which is unsafe in the threaded runtime.
``seccomp="on"`` is refused only where no backend can apply the filter
(non-Linux); everywhere else both backends enforce it.

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

import base64
import struct
from typing import Sequence

#: Operator-facing modes. ``auto`` applies the denylist via bwrap or the
#: prctl loader on Linux (both backends enforce it); ``on`` requires the
#: filter and refuses to run where no backend can apply it (non-Linux);
#: ``off`` disables the filter.
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


#: prctl(2) constants used by the loader below.
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2

#: A ``python3 -c`` loader that installs the denylist via prctl and then
#: execs the real command. Used by the process backend, which has no bwrap to
#: load the filter for it.
#:
#: Why a wrapper instead of ``Popen(preexec_fn=...)``: the runtime executes
#: tool batches on a ``ThreadPoolExecutor`` when ``parallel_tools > 1``, and
#: ``preexec_fn`` is not safe to use in the presence of threads (fork in a
#: threaded process can deadlock). The wrapper is a fresh, single-threaded
#: interpreter by construction, so there is no such hazard.
#:
#: Layout: ``python3 -c <LOADER> <base64-filter> <target argv...>``.
_PRCTL_LOADER = r"""
import base64 as _b, ctypes as _c, os as _o, sys as _s
_f = _b.b64decode(_s.argv[1])
class _P(_c.Structure):
    _fields_ = [("len", _c.c_ushort), ("filter", _c.c_void_p)]
_buf = _c.create_string_buffer(_f)
_prog = _P(len(_f) // 8, _c.cast(_buf, _c.c_void_p))
_lib = _c.CDLL(None, use_errno=True)
if _lib.prctl(38, 1, 0, 0, 0) != 0:
    _o.write(2, b"northstar: PR_SET_NO_NEW_PRIVS failed\n")
    _o._exit(126)
if _lib.prctl(22, 2, _c.byref(_prog), 0, 0) != 0:
    _e = _c.get_errno()
    _o.write(2, ("northstar: PR_SET_SECCOMP failed, errno %d\n" % _e).encode())
    _o._exit(126)
_o.execvp(_s.argv[2], _s.argv[2:])
""".strip()


def prctl_loader_argv(target_argv: Sequence[str], *, python: str = "python3") -> list[str]:
    """Wrap ``target_argv`` so the denylist is installed via prctl before exec.

    Returns ``[python, "-c", LOADER, b64(filter), *target_argv]``. The filter
    bytes travel as base64 inside argv (the program is ~0.5KB, far below the
    argv ceiling); no temp file is needed. A prctl failure exits 126 with a
    stderr note instead of running unfiltered.
    """
    encoded = base64.b64encode(build_default_filter()).decode("ascii")
    return [python, "-c", _PRCTL_LOADER, encoded, *target_argv]


__all__ = [
    "SECCOMP_MODES",
    "SeccompError",
    "build_default_filter",
    "denied_syscalls",
    "prctl_loader_argv",
    "resolve_mode",
    "validate_mode",
]
