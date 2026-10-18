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
filesystem super-operations (mount/pivot_root/...). Since Shell networking is
not offered, socket creation, socketpair, and ``io_uring_setup`` are also
denied; this gives the process backend a kernel-level network creation barrier
when seccomp is active, even without Landlock. The namespaces already blunt
many other escape primitives; seccomp is defense in depth. ``setpgid`` and
``setsid`` are also denied so a Shell descendant cannot escape the process
group used for timeout/output/leader-exit cleanup.

Syscall numbers are per-architecture and were verified against the sources,
not memory: x86_64 against upstream ``arch/x86/entry/syscalls/syscall_64.tbl``
and aarch64 against ``include/uapi/asm-generic/unistd.h`` (torvalds/linux).
An unknown audit architecture is denied with EPERM rather than receiving a
filter built from the wrong syscall table. x32 syscall numbers are rejected
before the x86_64 denylist is evaluated.

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
_ARGS0_OFFSET = 16

_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7
_X32_SYSCALL_BIT = 0x40000000

# Classic BPF opcodes.
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JGE_K = 0x35
_BPF_JMP_JSET_K = 0x45
_BPF_JMP_JA = 0x05
_BPF_RET_K = 0x06

_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_EPERM = 1
_ENOSYS = 38
_SECCOMP_RET_ERRNO_ENOSYS = _SECCOMP_RET_ERRNO | _ENOSYS

# clone(2) flags that would create the user or mount namespace a command
# could use to undo the outer sandbox's mount restrictions.
_CLONE_NEWUSER = 0x10000000
_CLONE_NEWNS = 0x00020000
_CLONE_NAMESPACE_FLAGS = _CLONE_NEWUSER | _CLONE_NEWNS
_UNSHARE_EMPTY_MNTNS = 0x00100000
_UNSHARE_NAMESPACE_FLAGS = _CLONE_NAMESPACE_FLAGS | _UNSHARE_EMPTY_MNTNS
_CLONE3_SYSCALL = 435

#: Denylisted syscalls per architecture. Numbers verified against kernel
#: sources (see module docstring); do not extend from memory.
_DENY_X86_64: dict[str, int] = {
    "ptrace": 101,
    "mount": 165,
    "umount2": 166,
    "pivot_root": 155,
    "setns": 308,
    "open_tree": 428,
    "move_mount": 429,
    "fsopen": 430,
    "fsconfig": 431,
    "fsmount": 432,
    "fspick": 433,
    "mount_setattr": 442,
    "open_tree_attr": 467,
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
    "setpgid": 109,
    "setsid": 112,
    "socket": 41,
    "socketpair": 53,
    "io_uring_setup": 425,
}

_DENY_AARCH64: dict[str, int] = {
    "ptrace": 117,
    "mount": 40,
    "umount2": 39,
    "pivot_root": 41,
    "setns": 268,
    "open_tree": 428,
    "move_mount": 429,
    "fsopen": 430,
    "fsconfig": 431,
    "fsmount": 432,
    "fspick": 433,
    "mount_setattr": 442,
    "open_tree_attr": 467,
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
    "setpgid": 154,
    "setsid": 157,
    "socket": 198,
    "socketpair": 199,
    "io_uring_setup": 425,
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


class _FilterBuilder:
    """Small forward-only classic-BPF builder with checked jump offsets."""

    def __init__(self) -> None:
        self.instructions: list[list[int]] = []
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, str, str]] = []

    def label(self, name: str) -> None:
        if name in self.labels:
            raise SeccompError(f"duplicate BPF label {name!r}")
        self.labels[name] = len(self.instructions)

    def stmt(self, code: int, k: int) -> None:
        self.instructions.append([code, 0, 0, k])

    def branch(self, code: int, k: int, yes: str, no: str) -> None:
        index = len(self.instructions)
        self.instructions.append([code, 0, 0, k])
        self.fixups.append((index, yes, no))

    def assemble(self) -> bytes:
        for index, yes, no in self.fixups:
            if yes not in self.labels or no not in self.labels:
                raise SeccompError(f"unresolved BPF label in instruction {index}")
            jt = self.labels[yes] - index - 1
            jf = self.labels[no] - index - 1
            if not (0 <= jt <= 255 and 0 <= jf <= 255):
                raise SeccompError(
                    f"BPF conditional jump at {index} is out of range: jt={jt}, jf={jf}"
                )
            self.instructions[index][1] = jt
            self.instructions[index][2] = jf
        return b"".join(struct.pack("<HBBI", *instruction) for instruction in self.instructions)


def build_default_filter() -> bytes:
    """Assemble the denylist BPF program.

    Layout::

        ld [arch]
        jeq X86_64 -> x86_chain
        jeq AARCH64 -> arm_chain else DENY
      x86_chain:
        ld [nr]
        jge X32_SYSCALL_BIT -> DENY
        jeq n1 -> DENY ... jeq nN -> DENY
        ja ALLOW
      arm_chain:
        ld [nr]
        jeq m1 -> DENY ... jeq mM -> DENY
        ja ALLOW
      ALLOW: ret SECCOMP_RET_ALLOW
      DENY:  ret SECCOMP_RET_ERRNO|EPERM
    """
    b = _FilterBuilder()
    b.stmt(_BPF_LD_W_ABS, _ARCH_OFFSET)
    b.branch(_BPF_JMP_JEQ_K, _AUDIT_ARCH_X86_64, "x86", "check_arm")
    b.label("check_arm")
    b.branch(_BPF_JMP_JEQ_K, _AUDIT_ARCH_AARCH64, "arm", "deny")

    b.label("x86")
    b.stmt(_BPF_LD_W_ABS, _NR_OFFSET)
    b.branch(_BPF_JMP_JEQ_K, _CLONE3_SYSCALL, "clone3_enosys", "x86_x32")
    b.label("x86_x32")
    b.branch(_BPF_JMP_JGE_K, _X32_SYSCALL_BIT, "deny", "x86_syscalls")
    b.label("x86_syscalls")
    for i, nr in enumerate(sorted(set(_DENY_X86_64.values()))):
        following = f"x86_next_{i}"
        b.branch(_BPF_JMP_JEQ_K, nr, "deny", following)
        b.label(following)
    b.branch(_BPF_JMP_JEQ_K, 272, "x86_unshare_flags", "x86_clone")
    b.label("x86_unshare_flags")
    b.stmt(_BPF_LD_W_ABS, _ARGS0_OFFSET)
    b.branch(_BPF_JMP_JSET_K, _UNSHARE_NAMESPACE_FLAGS, "deny", "x86_clone")
    b.label("x86_clone")
    b.branch(_BPF_JMP_JEQ_K, 56, "x86_clone_flags", "allow")
    b.label("x86_clone_flags")
    b.stmt(_BPF_LD_W_ABS, _ARGS0_OFFSET)
    b.branch(_BPF_JMP_JSET_K, _CLONE_NAMESPACE_FLAGS, "deny", "allow")

    b.label("arm")
    b.stmt(_BPF_LD_W_ABS, _NR_OFFSET)
    b.branch(_BPF_JMP_JEQ_K, _CLONE3_SYSCALL, "clone3_enosys", "arm_syscalls")
    b.label("arm_syscalls")
    for i, nr in enumerate(sorted(set(_DENY_AARCH64.values()))):
        following = f"arm_next_{i}"
        b.branch(_BPF_JMP_JEQ_K, nr, "deny", following)
        b.label(following)
    b.branch(_BPF_JMP_JEQ_K, 97, "arm_unshare_flags", "arm_clone")
    b.label("arm_unshare_flags")
    b.stmt(_BPF_LD_W_ABS, _ARGS0_OFFSET)
    b.branch(_BPF_JMP_JSET_K, _UNSHARE_NAMESPACE_FLAGS, "deny", "arm_clone")
    b.label("arm_clone")
    b.branch(_BPF_JMP_JEQ_K, 220, "arm_clone_flags", "allow")
    b.label("arm_clone_flags")
    b.stmt(_BPF_LD_W_ABS, _ARGS0_OFFSET)
    b.branch(_BPF_JMP_JSET_K, _CLONE_NAMESPACE_FLAGS, "deny", "allow")

    b.label("clone3_enosys")
    b.stmt(_BPF_RET_K, _SECCOMP_RET_ERRNO_ENOSYS)
    b.label("allow")
    b.stmt(_BPF_RET_K, _SECCOMP_RET_ALLOW)
    b.label("deny")
    b.stmt(_BPF_RET_K, _SECCOMP_RET_ERRNO | _EPERM)
    return b.assemble()

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
