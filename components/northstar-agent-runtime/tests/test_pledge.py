"""Pledge-style self-restriction: semantic layer + mechanism wiring.

Verifies the OpenBSD pledge(2) model port: declare-before-use, tighten-only
(widening refused), violations fail closed and audited, execpromises
(subcontext) inherits a subset only. The Landlock probe is exercised for
honesty (it must not crash and must report a closed shape); real
kernel-level enforcement is additionally observed on Linux when the
kernel supports Landlock — a write outside a read-only pledge must fail.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

import support  # noqa: F401 — puts the runtime root on sys.path
from support import RuntimeTestCase

from tools.pledge import (
    DEFAULT_SHELL_PLEDGES,
    PROMISES,
    FsRule,
    PledgeContext,
    PledgeError,
    PledgeViolation,
    enforcement_report,
    filesystem_rules,
    landlock_probe,
    pledge_loader_argv,
    resolve_pledges,
    validate_promises,
)


class ValidatePromisesTest(RuntimeTestCase):
    def test_known_promises_normalise(self):
        self.assertEqual(
            validate_promises(["stdio", "rpath", "stdio"]),
            frozenset({"stdio", "rpath"}),
        )

    def test_unknown_promise_is_refused(self):
        with self.assertRaises(PledgeError):
            validate_promises(["stdio", "root"])

    def test_none_is_refused(self):
        with self.assertRaises(PledgeError):
            validate_promises(None)

    def test_default_shell_pledges_cover_the_vocabulary(self):
        self.assertEqual(frozenset(DEFAULT_SHELL_PLEDGES), frozenset(PROMISES))


class ResolvePledgesTest(RuntimeTestCase):
    def test_payload_may_tighten(self):
        resolved = resolve_pledges(["stdio", "rpath"], list(DEFAULT_SHELL_PLEDGES))
        self.assertEqual(set(resolved), {"stdio", "rpath"})

    def test_payload_may_not_widen(self):
        with self.assertRaises(PledgeError):
            resolve_pledges(
                ["stdio", "rpath", "wpath", "cpath", "tmppath", "dpath",
                 "unix", "inet", "dns", "proc", "exec", "id", "clock", "tty", "root"],
                ["stdio", "rpath"],
            )

    def test_none_payload_keeps_service(self):
        resolved = resolve_pledges(None, ["stdio", "rpath"])
        self.assertEqual(set(resolved), {"stdio", "rpath"})

    def test_none_service_falls_back_to_full_profile(self):
        resolved = resolve_pledges(None, None)
        self.assertEqual(set(resolved), set(DEFAULT_SHELL_PLEDGES))


class PledgeContextTest(RuntimeTestCase):
    def test_pledge_declares_and_allows(self):
        ctx = PledgeContext.pledge(["stdio", "rpath"])
        ctx.require("stdio")
        ctx.require("rpath")
        kinds = [e.kind for e in ctx.events]
        self.assertIn("pledged", kinds)
        self.assertEqual(kinds.count("allowed"), 2)

    def test_violation_fails_closed_and_is_audited(self):
        ctx = PledgeContext.pledge(["stdio", "rpath"])
        with self.assertRaises(PledgeViolation):
            ctx.require("wpath")
        violations = [e for e in ctx.events if e.kind == "violation"]
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].promise, "wpath")
        log = ctx.audit_log()
        self.assertTrue(any(e["kind"] == "violation" and e["promise"] == "wpath" for e in log))

    def test_tighten_to_subset_is_accepted(self):
        ctx = PledgeContext.pledge(["stdio", "rpath", "wpath"])
        ctx.tighten(["stdio", "rpath"])
        self.assertEqual(ctx.promises, frozenset({"stdio", "rpath"}))

    def test_tighten_widening_is_refused_and_audited(self):
        ctx = PledgeContext.pledge(["stdio", "rpath"])
        with self.assertRaises(PledgeError):
            ctx.tighten(["stdio", "rpath", "wpath"])
        # The refused widening leaves the set unchanged and is audited.
        self.assertEqual(ctx.promises, frozenset({"stdio", "rpath"}))
        self.assertTrue(any(e.kind == "widen_refused" for e in ctx.events))

    def test_second_pledge_wider_is_refused(self):
        ctx = PledgeContext.pledge(["stdio", "rpath"])
        with self.assertRaises(PledgeError):
            ctx.tighten(["stdio", "rpath", "wpath", "inet"])

    def test_require_unknown_promise_is_a_programmer_error(self):
        ctx = PledgeContext.pledge(["stdio"])
        with self.assertRaises(PledgeError):
            ctx.require("root")

    def test_subcontext_inherits_subset_only(self):
        parent = PledgeContext.pledge(["stdio", "rpath", "wpath"])
        child = parent.subcontext(["stdio", "rpath"])
        self.assertEqual(child.promises, frozenset({"stdio", "rpath"}))
        with self.assertRaises(PledgeError):
            parent.subcontext(["stdio", "rpath", "wpath", "inet"])


class FilesystemRulesTest(RuntimeTestCase):
    def test_read_only_pledge_yields_read_only_workspace(self):
        rules = filesystem_rules(
            frozenset({"stdio", "rpath", "proc", "exec"}),
            workspace="/ws",
            tmpdir="/ws/.northstar/tmp",
        )
        ws = [r for r in rules if r.path == "/ws"]
        self.assertEqual(len(ws), 1)
        self.assertTrue(ws[0].access & 0x4)  # READ_FILE
        self.assertFalse(ws[0].access & 0x2)  # no WRITE_FILE
        self.assertFalse(ws[0].access & 0x40)  # no MKDIR

    def test_write_pledge_yields_write_access(self):
        rules = filesystem_rules(
            frozenset({"stdio", "rpath", "wpath", "cpath", "tmppath"}),
            workspace="/ws",
            tmpdir="/ws/.northstar/tmp",
        )
        ws = [r for r in rules if r.path == "/ws"][0]
        self.assertTrue(ws.access & 0x2)  # WRITE_FILE
        self.assertTrue(ws.access & 0x40)  # MKDIR
        tmp = [r for r in rules if r.path == "/ws/.northstar/tmp"]
        self.assertEqual(len(tmp), 1)

    def test_no_rpath_hides_the_workspace(self):
        rules = filesystem_rules(
            frozenset({"stdio", "proc", "exec"}),
            workspace="/ws",
            tmpdir="/ws/.northstar/tmp",
        )
        self.assertFalse([r for r in rules if r.path == "/ws"])
        self.assertFalse([r for r in rules if r.path == "/ws/.northstar/tmp"])

    def test_runtime_roots_are_always_read_exec(self):
        rules = filesystem_rules(frozenset({"stdio"}), workspace="/ws", tmpdir="/t")
        # Host-relative: only roots that exist here may (and must) carry a rule.
        # /lib64 exists on x86_64 distros but not on aarch64 ones; asserting it
        # unconditionally made this test (and the Landlock setup) host-specific.
        for root in ("/usr", "/bin", "/lib", "/lib64", "/sbin"):
            rule = [r for r in rules if r.path == root]
            if os.path.exists(root):
                self.assertEqual(len(rule), 1, root)
                self.assertTrue(rule[0].access & 0x1)  # EXECUTE
            else:
                self.assertEqual(rule, [], f"{root} is absent on this host but got a rule")

    def test_no_rule_targets_a_system_root_that_does_not_exist(self):
        # Landlock opens each rule path before restricting; a missing one aborts the
        # whole sandbox setup (FileNotFoundError), which is a hard failure, not a skip.
        rules = filesystem_rules(frozenset({"stdio"}), workspace="/ws", tmpdir="/t")
        system_roots = {"/usr", "/bin", "/lib", "/lib64", "/sbin"}
        absent = [r.path for r in rules if r.path in system_roots and not os.path.exists(r.path)]
        self.assertEqual(absent, [])

    def test_missing_runtime_root_is_skipped_when_roots_are_injected(self):
        # Deterministic on every host: inject one real and one missing root.
        rules = filesystem_rules(
            frozenset({"stdio"}), workspace="/ws", tmpdir="/t",
            runtime_roots=("/usr", "/definitely-not-a-real-root-r2524"),
        )
        paths = [r.path for r in rules]
        self.assertIn("/usr", paths)
        self.assertNotIn("/definitely-not-a-real-root-r2524", paths)


class LandlockProbeTest(RuntimeTestCase):
    def test_probe_returns_a_closed_shape(self):
        support = landlock_probe()
        self.assertIsInstance(support.available, bool)
        self.assertIsInstance(support.detail, str)
        self.assertTrue(support.detail)

    def test_probe_is_cached(self):
        self.assertIs(landlock_probe(), landlock_probe())

    def test_enforcement_report_is_honest(self):
        support = landlock_probe()
        report = enforcement_report(frozenset({"stdio", "rpath"}), backend="process")
        self.assertEqual(report["landlock"]["available"], support.available)
        self.assertIn("semantic", report["layers"][0])
        self.assertTrue(any("seccomp" in layer for layer in report["layers"]))


class PledgeLoaderTest(RuntimeTestCase):
    def test_no_new_privileges_is_set_before_landlock_restriction(self):
        import ast
        code = pledge_loader_argv([FsRule('/tmp', 0xC)], ['true'])[2]
        calls = []
        for node in ast.walk(ast.parse(code)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ('prctl', 'syscall') and node.args and isinstance(node.args[0], ast.Constant):
                    calls.append((node.lineno, node.func.attr, node.args[0].value))
        ordered = sorted(calls)
        nnp_line = next(line for line, kind, number in ordered if kind == 'prctl' and number == 38)
        restrict_line = next(line for line, kind, number in ordered if kind == 'syscall' and number == 446)
        self.assertLess(nnp_line, restrict_line, 'unprivileged Landlock needs NNP before restrict_self')

    def test_loader_argv_shape(self):
        rules = [FsRule("/ws", 0xC)]
        argv = pledge_loader_argv(rules, ["true"], python="python3")
        self.assertEqual(argv[0], "python3")
        self.assertEqual(argv[1], "-c")
        self.assertIn("landlock", argv[2])
        self.assertIn("prctl", argv[2])
        # Rules travel as JSON, filter as base64.
        import json as _json

        parsed = _json.loads(argv[4])
        self.assertEqual(parsed, [{"access": 12, "path": "/ws"}])
        self.assertEqual(argv[5:], ["true"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "needs Linux")
    def test_landlock_really_blocks_a_write(self):
        """End-to-end: a read-only pledge's child cannot write the workspace.

        Skipped honestly when the kernel cannot Landlock-restrict.
        """
        support = landlock_probe()
        if not support.available:
            self.skipTest(f"landlock unavailable: {support.detail}")
        import shutil
        import subprocess

        python = shutil.which("python3") or sys.executable

        def run_child(tmp, pledges, filename):
            rules = filesystem_rules(
                frozenset(pledges), workspace=tmp, tmpdir=tmp
            )
            code = (
                "import os as _o; open(_o.path.join("
                + repr(tmp) + ", " + repr(filename) + "), 'w').write('x')"
            )
            argv = pledge_loader_argv(rules, [sys.executable, "-c", code], python=python)
            return subprocess.run(argv, capture_output=True, text=True, timeout=30)

        # Positive control: the loader itself must work — a full pledge's
        # child CAN write the workspace. (Without this, the negative test
        # below would pass even with a broken loader.)
        tmp = tempfile.mkdtemp(prefix="ns-pledge-e2e-")
        try:
            completed = run_child(
                tmp, ("stdio", "rpath", "wpath", "cpath", "proc", "exec"), "marker-ok"
            )
            self.assertTrue(
                os.path.exists(os.path.join(tmp, "marker-ok")),
                f"loader broken: full-pledge child could not write "
                f"(exit={completed.returncode}, stderr={completed.stderr[:200]})",
            )
            self.assertEqual(completed.returncode, 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        # Negative: a read-only pledge's child cannot write the workspace.
        tmp = tempfile.mkdtemp(prefix="ns-pledge-e2e-")
        try:
            completed = run_child(
                tmp, ("stdio", "rpath", "proc", "exec"), "marker-denied"
            )
            self.assertFalse(
                os.path.exists(os.path.join(tmp, "marker-denied")),
                "write outside a read-only pledge must fail",
            )
            # The child died trying (non-zero exit), it did not run unrestricted.
            self.assertNotEqual(completed.returncode, 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class SandboxPledgeWiringTest(RuntimeTestCase):
    def test_unknown_promise_in_request_is_a_configuration_error(self):
        from tools.os_sandbox import SandboxError, SandboxRequest, _validate_request

        with tempfile.TemporaryDirectory() as tmp:
            request = SandboxRequest(
                argv=("true",), cwd=tmp, workspace=tmp, pledges=("root",)
            )
            with self.assertRaises(SandboxError):
                _validate_request(request)

    def test_bwrap_argv_goes_read_only_without_write_promises(self):
        from tools.os_sandbox import SandboxRequest, _bwrap_argv

        with tempfile.TemporaryDirectory() as tmp:
            request = SandboxRequest(
                argv=("true",),
                cwd=tmp,
                workspace=tmp,
                pledges=("stdio", "rpath", "proc", "exec", "id", "clock"),
            )
            argv = _bwrap_argv(request, bwrap_path="/usr/bin/bwrap")
            ws = str(tmp)
            idx = argv.index(ws)
            self.assertEqual(argv[idx - 1], "--ro-bind")

    def test_bwrap_argv_stays_writable_with_write_promises(self):
        from tools.os_sandbox import SandboxRequest, _bwrap_argv

        with tempfile.TemporaryDirectory() as tmp:
            request = SandboxRequest(
                argv=("true",),
                cwd=tmp,
                workspace=tmp,
                pledges=("stdio", "rpath", "wpath", "cpath", "proc", "exec"),
            )
            argv = _bwrap_argv(request, bwrap_path="/usr/bin/bwrap")
            ws = str(tmp)
            idx = argv.index(ws)
            self.assertEqual(argv[idx - 1], "--bind")

    def test_missing_proc_exec_is_refused_before_running(self):
        from tools.os_sandbox import (
            SandboxCapabilities,
            SandboxError,
            SandboxRequest,
            run_sandboxed,
        )

        caps = SandboxCapabilities(
            bwrap_path=None,
            bwrap_usable=False,
            bwrap_detail="test",
            preferred="process",
        )
        with tempfile.TemporaryDirectory() as tmp:
            request = SandboxRequest(
                argv=("true",),
                cwd=tmp,
                workspace=tmp,
                pledges=("stdio", "rpath"),  # no proc/exec: Shell cannot run like this
            )
            with self.assertRaises(SandboxError) as raised:
                run_sandboxed(request, backend="process", capabilities=caps)
            self.assertIn("pledge", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
