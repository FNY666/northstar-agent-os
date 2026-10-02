"""Seccomp-BPF denylist for the bwrap sandbox.

The filter is verified the way this project verifies everything else: the
assembler output is executed in a tiny in-test classic-BPF interpreter and the
verdict is asserted for denied/allowed syscalls on both architectures, plus
the arch-fallback path — and, on Linux, the filter is really loaded via prctl
and observed through /proc/self/status. No bwrap needed; the whole suite runs
offline.
"""
from __future__ import annotations

import struct
import sys
import unittest

import support  # noqa: F401 — puts the runtime root on sys.path
from support import RuntimeTestCase

from tools.os_sandbox import (
    SandboxError,
    SandboxRequest,
    _bwrap_argv,
    run_sandboxed,
)
from tools.seccomp import (
    SECCOMP_MODES,
    SeccompError,
    build_default_filter,
    denied_syscalls,
    resolve_mode,
    validate_mode,
)

_X86_64 = 0xC000003E
_AARCH64 = 0xC00000B7
_ALLOW = 0x7FFF0000
_ERRNO_EPERM = 0x00050001


def interpret(prog: bytes, arch: int, nr: int) -> int:
    """Minimal classic-BPF interpreter over seccomp_data{nr@0, arch@4}."""
    mem = {0: nr, 4: arch}
    acc = 0
    pc = 0
    insns = len(prog) // 8
    for _ in range(insns + 4):  # bounded: a filter must return
        code, jt, jf, k = struct.unpack_from("<HBBI", prog, pc * 8)
        cls = code & 0x07
        if cls == 0x00:  # LD
            if code != 0x20:  # LD|W|ABS
                raise AssertionError(f"unexpected LD code {code:#x} at {pc}")
            acc = mem.get(k, 0)
            pc += 1
        elif cls == 0x05:  # JMP
            if code == 0x15:  # JEQ|K
                pc += (jt + 1) if acc == k else (jf + 1)
            elif code == 0x05:  # JA
                pc += k + 1
            else:
                raise AssertionError(f"unexpected JMP code {code:#x} at {pc}")
        elif cls == 0x06:  # RET
            if code != 0x06:
                raise AssertionError(f"unexpected RET code {code:#x} at {pc}")
            return k
        else:
            raise AssertionError(f"unexpected BPF class {cls} at {pc}")
    raise AssertionError("filter did not return")


class FilterAssemblyTests(unittest.TestCase):
    def test_filter_is_well_formed(self):
        prog = build_default_filter()
        self.assertTrue(len(prog) > 0)
        self.assertEqual(len(prog) % 8, 0)
        # 9 fixed (3 arch-dispatch + 2x(ld+ja) + ALLOW + DENY) + N + M jeq.
        n = len(denied_syscalls("x86_64"))
        m = len(denied_syscalls("aarch64"))
        self.assertEqual(len(prog) // 8, 9 + n + m)

    def test_denylist_tables_are_nonempty_and_sane(self):
        for arch in ("x86_64", "aarch64"):
            table = denied_syscalls(arch)
            self.assertGreater(len(table), 10)
            for name, nr in table.items():
                self.assertIsInstance(nr, int)
                self.assertGreater(nr, 0)
        self.assertIn("ptrace", denied_syscalls("x86_64"))
        self.assertIn("bpf", denied_syscalls("aarch64"))

    def test_unknown_arch_raises(self):
        with self.assertRaises(SeccompError):
            denied_syscalls("mips")


class FilterSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.prog = build_default_filter()

    def test_denied_syscalls_get_eperm_x86_64(self):
        table = denied_syscalls("x86_64")
        for name, nr in table.items():
            with self.subTest(name=name):
                self.assertEqual(interpret(self.prog, _X86_64, nr), _ERRNO_EPERM)

    def test_denied_syscalls_get_eperm_aarch64(self):
        table = denied_syscalls("aarch64")
        for name, nr in table.items():
            with self.subTest(name=name):
                self.assertEqual(interpret(self.prog, _AARCH64, nr), _ERRNO_EPERM)

    def test_ordinary_syscalls_are_allowed(self):
        # read, write, openat, execve, exit, clone, mmap — the everyday set.
        for nr in (0, 1, 257, 59, 60, 56, 9):
            with self.subTest(nr=nr):
                self.assertEqual(interpret(self.prog, _X86_64, nr), _ALLOW)
                self.assertEqual(interpret(self.prog, _AARCH64, nr), _ALLOW)

    def test_tables_are_arch_scoped(self):
        # x86_64's ptrace number (101) is getpid on aarch64 — must stay allowed.
        self.assertEqual(interpret(self.prog, _AARCH64, 101), _ALLOW)
        # aarch64's ptrace number (117) is not x86_64 ptrace — must stay allowed.
        self.assertEqual(interpret(self.prog, _X86_64, 117), _ALLOW)

    def test_unknown_arch_falls_through_to_allow(self):
        # Documented: better to allow than to apply the wrong table.
        self.assertEqual(interpret(self.prog, 0xDEADBEEF, 101), _ALLOW)


class ModeResolutionTests(unittest.TestCase):
    def test_validate_mode(self):
        self.assertEqual(validate_mode("on"), "on")
        self.assertEqual(validate_mode(" OFF "), "off")
        self.assertEqual(validate_mode(""), "auto")
        with self.assertRaises(SeccompError):
            validate_mode("sometimes")
        with self.assertRaises(SeccompError):
            validate_mode(True)  # type: ignore[arg-type]

    def test_tighten_only(self):
        # A per-call payload may move toward "on", never away from the operator.
        self.assertEqual(resolve_mode("off", "on"), "on")
        self.assertEqual(resolve_mode("auto", "on"), "on")
        self.assertEqual(resolve_mode("on", "auto"), "on")
        self.assertEqual(resolve_mode("on", "off"), "on")
        self.assertEqual(resolve_mode("off", "auto"), "auto")
        self.assertEqual(resolve_mode(None, "off"), "off")
        self.assertEqual(resolve_mode(None, None), "auto")
        with self.assertRaises(SeccompError):
            resolve_mode("bogus", "auto")


class SandboxWiringTests(RuntimeTestCase):
    def test_bwrap_argv_carries_seccomp_fd(self):
        root = self.workspace()
        req = SandboxRequest(argv=("true",), cwd=root, workspace=root)
        argv = _bwrap_argv(req, bwrap_path="/usr/bin/bwrap", seccomp_fd=9)
        self.assertIn("--seccomp", argv)
        self.assertEqual(argv[argv.index("--seccomp") + 1], "9")

    def test_bwrap_argv_without_fd_has_no_seccomp(self):
        root = self.workspace()
        req = SandboxRequest(argv=("true",), cwd=root, workspace=root)
        self.assertNotIn("--seccomp", _bwrap_argv(req, bwrap_path="/usr/bin/bwrap"))

    def test_invalid_seccomp_mode_refuses(self):
        root = self.workspace()
        req = SandboxRequest(argv=("true",), cwd=root, workspace=root, seccomp="bogus")
        with self.assertRaises(SandboxError):
            run_sandboxed(req, backend="process")

    def test_process_backend_applies_filter_via_prctl(self):
        root = self.workspace()
        req = SandboxRequest(argv=("true",), cwd=root, workspace=root, seccomp="auto")
        result = run_sandboxed(req, backend="process")
        self.assertEqual(result.backend, "process")
        self.assertIn("prctl", result.detail)
        # The audit trail keeps the caller's argv, not the wrapper's.
        self.assertEqual(list(result.argv), ["true"])

    def test_seccomp_on_satisfied_on_process_backend(self):
        # "on" means the filter must be active; the prctl wrapper satisfies it
        # on Linux, so no refusal (refusal is only for platforms without BPF).
        if not sys.platform.startswith("linux"):
            self.skipTest("prctl seccomp needs Linux")
        root = self.workspace()
        req = SandboxRequest(argv=("true",), cwd=root, workspace=root, seccomp="on")
        result = run_sandboxed(req, backend="process")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("prctl", result.detail)

    def test_prctl_loader_argv_shape(self):
        from tools.seccomp import build_default_filter, prctl_loader_argv

        argv = prctl_loader_argv(["echo", "hi"], python="python3")
        self.assertEqual(argv[0], "python3")
        self.assertEqual(argv[1], "-c")
        self.assertEqual(argv[-2:], ["echo", "hi"])
        import base64

        self.assertEqual(base64.b64decode(argv[3]), build_default_filter())


class RealKernelTests(RuntimeTestCase):
    """Load the filter on the real kernel (Linux) and observe it from inside.

    The interpreter tests prove the filter's logic; these prove the bytes the
    assembler emits are a loadable, enforcing seccomp program — the closest
    this suite can get to the bwrap path without bwrap on the host.
    """

    def _run(self, argv, seccomp="auto"):
        root = self.workspace()
        req = SandboxRequest(argv=tuple(argv), cwd=root, workspace=root, seccomp=seccomp)
        return run_sandboxed(req, backend="process")

    def _seccomp_filter_count(self, seccomp):
        result = self._run(("sh", "-c", "grep '^Seccomp_filters:' /proc/self/status"), seccomp=seccomp)
        self.assertEqual(result.exit_code, 0, result.stderr)
        return int(result.stdout.strip().split(":")[1])

    def test_filter_is_really_loaded(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("prctl seccomp needs Linux")
        # Our wrapper adds exactly one filter layer on top of whatever the
        # host already has (this container, for example, ships several).
        self.assertEqual(
            self._seccomp_filter_count("auto"), self._seccomp_filter_count("off") + 1
        )

    def test_blocked_syscall_returns_eperm(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("prctl seccomp needs Linux")
        import platform

        arch = {"x86_64": "x86_64", "aarch64": "aarch64"}.get(platform.machine())
        if arch is None:
            self.skipTest("no verified table for this arch")
        nr = denied_syscalls(arch)["clock_settime"]
        code = (
            "import ctypes; l=ctypes.CDLL(None, use_errno=True);"
            f"r=l.syscall({nr}, 0, 0); print(ctypes.get_errno())"
        )
        result = self._run(("python3", "-c", code), seccomp="auto")
        self.assertEqual(result.exit_code, 0, result.stderr)
        # EPERM from our filter, not EFAULT from the NULL timespec.
        self.assertEqual(result.stdout.strip(), "1")

    def test_unfiltered_syscall_still_works(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("prctl seccomp needs Linux")
        result = self._run(("sh", "-c", "echo alive"), seccomp="auto")
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout.strip(), "alive")


if __name__ == "__main__":
    unittest.main()
