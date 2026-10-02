"""Seccomp-BPF denylist for the bwrap sandbox.

The filter is verified the way this project verifies everything else: the
assembler output is executed in a tiny in-test classic-BPF interpreter and the
verdict is asserted for denied/allowed syscalls on both architectures, plus
the arch-fallback path. No bwrap needed; the whole suite runs offline.
"""
from __future__ import annotations

import struct
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

    def test_seccomp_on_with_process_backend_refuses(self):
        root = self.workspace()
        req = SandboxRequest(argv=("true",), cwd=root, workspace=root, seccomp="on")
        with self.assertRaises(SandboxError) as caught:
            run_sandboxed(req, backend="process")
        self.assertIn("seccomp", str(caught.exception).lower())
        self.assertIn("bwrap", str(caught.exception).lower())

    def test_invalid_seccomp_mode_refuses(self):
        root = self.workspace()
        req = SandboxRequest(argv=("true",), cwd=root, workspace=root, seccomp="bogus")
        with self.assertRaises(SandboxError):
            run_sandboxed(req, backend="process")

    def test_process_backend_labels_missing_seccomp(self):
        root = self.workspace()
        req = SandboxRequest(argv=("true",), cwd=root, workspace=root, seccomp="auto")
        result = run_sandboxed(req, backend="process")
        self.assertEqual(result.backend, "process")
        self.assertIn("seccomp not applied", result.detail)


if __name__ == "__main__":
    unittest.main()
