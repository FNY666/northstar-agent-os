"""OS sandbox backends and the governed Shell tool (P1).

The process backend is what every host can exercise offline. bwrap is probed
and, when usable, given one happy-path run — never required for the suite to
pass. Explicit ``bwrap`` without a usable binary must hard-error (no quiet
downgrade): that is the lie this surface exists to refuse.
"""
from __future__ import annotations

import os
import sys
import unittest

import support  # noqa: F401 — puts the runtime root on sys.path
from support import RuntimeTestCase

from permissions import PermissionConfig, PermissionEngine
from tools import ToolContext, ToolSandbox, ToolResult, build_default_registry
from tools.os_sandbox import (
    SandboxError,
    SandboxRequest,
    probe_capabilities,
    reset_capabilities_cache,
    resolve_backend,
    run_sandboxed,
)
from tools.shell import parse_shell_argv, shell_handler


class OsSandboxProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_capabilities_cache()

    def tearDown(self) -> None:
        reset_capabilities_cache()

    def test_probe_returns_a_closed_shape(self):
        caps = probe_capabilities(force=True)
        self.assertIn(caps.preferred, ("bwrap", "process"))
        self.assertTrue(caps.process_available)
        data = caps.as_dict()
        self.assertIn(data["isolation"], ("os", "process"))
        self.assertEqual(bool(caps.bwrap_usable), data["bwrap_usable"])

    def test_auto_picks_process_when_bwrap_is_unusable(self):
        caps = probe_capabilities(force=True)
        if caps.bwrap_usable:
            self.skipTest("host has a usable bwrap; cannot assert the process fallback here")
        self.assertEqual(resolve_backend("auto", capabilities=caps), "process")

    def test_explicit_bwrap_refuses_when_unusable(self):
        caps = probe_capabilities(force=True)
        if caps.bwrap_usable:
            self.skipTest("host has usable bwrap; hard-error path needs an unusable probe")
        with self.assertRaises(SandboxError) as caught:
            resolve_backend("bwrap", capabilities=caps)
        message = str(caught.exception).lower()
        self.assertIn("bwrap", message)
        self.assertNotIn("falling back", message)
        self.assertNotIn("downgrade", message)

    def test_unknown_backend_is_a_configuration_error(self):
        with self.assertRaises(SandboxError):
            resolve_backend("firejail")


class OsSandboxProcessBackendTests(RuntimeTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.root = self.workspace({"marker.txt": "hello-sandbox\n"})

    def _request(self, argv, **kwargs):
        return SandboxRequest(
            argv=tuple(argv),
            cwd=self.root,
            workspace=self.root,
            timeout_ms=kwargs.get("timeout_ms", 5_000),
            max_output_bytes=kwargs.get("max_output_bytes", 8_192),
            env=kwargs.get("env"),
        )

    def test_process_backend_runs_argv_and_labels_isolation(self):
        result = run_sandboxed(
            self._request([sys.executable, "-c", "print('ns-ok')"]),
            backend="process",
        )
        self.assertEqual(result.backend, "process")
        self.assertEqual(result.isolation, "process")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("ns-ok", result.stdout)
        body = result.render()
        self.assertIn("backend=process", body)
        self.assertIn("isolation=process", body)

    def test_process_backend_pins_cwd_inside_workspace(self):
        result = run_sandboxed(
            self._request([sys.executable, "-c", "import os; print(os.getcwd())"]),
            backend="process",
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout.strip(), str(self.root.resolve()))

    def test_process_backend_scrubs_parent_secrets_from_env(self):
        os.environ["NORTHSTAR_TEST_SECRET"] = "should-not-leak"
        try:
            result = run_sandboxed(
                self._request(
                    [
                        sys.executable,
                        "-c",
                        "import os; print(os.environ.get('NORTHSTAR_TEST_SECRET', 'ABSENT'))",
                    ]
                ),
                backend="process",
            )
        finally:
            os.environ.pop("NORTHSTAR_TEST_SECRET", None)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout.strip(), "ABSENT")

    def test_process_backend_rejects_reserved_env_keys(self):
        with self.assertRaises(SandboxError):
            run_sandboxed(
                self._request([sys.executable, "-c", "print(1)"], env={"PATH": "/evil"}),
                backend="process",
            )

    def test_process_backend_rejects_cwd_escape(self):
        outside = self.workspace()
        with self.assertRaises(SandboxError):
            run_sandboxed(
                SandboxRequest(
                    argv=(sys.executable, "-c", "print(1)"),
                    cwd=outside,
                    workspace=self.root,
                ),
                backend="process",
            )

    def test_process_backend_times_out_and_kills_the_group(self):
        result = run_sandboxed(
            self._request(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout_ms=200,
            ),
            backend="process",
        )
        self.assertTrue(result.timed_out)
        self.assertIn("timed_out=true", result.render())

    def test_process_backend_non_zero_exit_is_a_result_not_a_raise(self):
        result = run_sandboxed(
            self._request([sys.executable, "-c", "import sys; sys.exit(7)"]),
            backend="process",
        )
        self.assertEqual(result.exit_code, 7)
        self.assertFalse(result.ok)
        self.assertFalse(result.timed_out)

    def test_network_true_is_refused(self):
        request = SandboxRequest(
            argv=(sys.executable, "-c", "print(1)"),
            cwd=self.root,
            workspace=self.root,
            network=True,
        )
        with self.assertRaises(SandboxError):
            run_sandboxed(request, backend="process")


class OsSandboxBwrapBackendTests(RuntimeTestCase):
    def setUp(self) -> None:
        super().setUp()
        reset_capabilities_cache()
        self.caps = probe_capabilities(force=True)
        self.root = self.workspace()

    def tearDown(self) -> None:
        reset_capabilities_cache()
        super().tearDown()

    def test_bwrap_backend_when_usable(self):
        if not self.caps.bwrap_usable:
            self.skipTest(f"bwrap unusable on this host: {self.caps.bwrap_detail}")
        request = SandboxRequest(
            argv=("true",),
            cwd=self.root,
            workspace=self.root,
            timeout_ms=5_000,
        )
        result = run_sandboxed(request, backend="bwrap", capabilities=self.caps)
        self.assertEqual(result.backend, "bwrap")
        self.assertEqual(result.isolation, "os")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("backend=bwrap", result.render())
        self.assertIn("isolation=os", result.render())


class ShellToolTests(RuntimeTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.root = self.workspace()
        self.ctx = ToolContext(
            session_id="test",
            sandbox=ToolSandbox(self.root),
            services={"shell_backend": "process"},
        )

    def test_registry_includes_shell_as_exec_mutating(self):
        registry = build_default_registry()
        self.assertIn("Shell", registry.names())
        spec = registry.get("Shell")
        self.assertEqual(spec.kind, "exec")
        self.assertTrue(spec.is_mutating)
        self.assertFalse(spec.read_only)

    def test_parse_prefers_argv_and_rejects_both(self):
        self.assertEqual(parse_shell_argv({"argv": ["echo", "a"]}), ("echo", "a"))
        with self.assertRaises(SandboxError):
            parse_shell_argv({"argv": ["echo"], "command": "echo x"})
        with self.assertRaises(SandboxError):
            parse_shell_argv({})

    def test_command_becomes_sh_c_inside_sandbox(self):
        argv = parse_shell_argv({"command": "echo hi"})
        self.assertEqual(argv[1], "-c")
        self.assertEqual(argv[2], "echo hi")
        self.assertTrue(argv[0].endswith("sh"))

    def test_shell_handler_runs_and_labels_backend(self):
        result = shell_handler(
            {"argv": [sys.executable, "-c", "print('shell-ok')"]},
            self.ctx,
        )
        self.assertIsInstance(result, ToolResult)
        self.assertFalse(result.is_error)
        self.assertIn("shell-ok", result.content)
        self.assertIn("backend=process", result.content)
        self.assertIn("isolation=process", result.content)
        self.assertEqual(result.data["backend"], "process")

    def test_shell_handler_non_zero_exit_is_not_is_error(self):
        result = shell_handler(
            {"argv": [sys.executable, "-c", "import sys; sys.exit(3)"]},
            self.ctx,
        )
        self.assertFalse(result.is_error, "non-zero exit is a result the model must read")
        self.assertEqual(result.data["exit_code"], 3)

    def test_shell_handler_timeout_is_is_error(self):
        result = shell_handler(
            {
                "argv": [sys.executable, "-c", "import time; time.sleep(30)"],
                "timeout_ms": 200,
            },
            self.ctx,
        )
        self.assertTrue(result.is_error)
        self.assertTrue(result.data["timed_out"])

    def test_default_permission_mode_denies_shell_without_allow(self):
        engine = PermissionEngine(PermissionConfig(mode="default"))
        engine.register_kind("Shell", "exec")
        decision = engine.evaluate(
            "Shell", kind="exec", mutating=True, payload={"argv": ["true"]}
        )
        self.assertFalse(decision.allowed)

    def test_accept_edits_does_not_cover_shell(self):
        engine = PermissionEngine(PermissionConfig(mode="acceptEdits"))
        engine.register_kind("Shell", "exec")
        decision = engine.evaluate(
            "Shell", kind="exec", mutating=True, payload={"argv": ["true"]}
        )
        self.assertFalse(
            decision.allowed, "acceptEdits is for file edits, not command execution"
        )

    def test_allowed_tools_shell_auto_approves(self):
        engine = PermissionEngine(
            PermissionConfig(mode="default", allowed_tools=("Shell",))
        )
        engine.register_kind("Shell", "exec")
        decision = engine.evaluate(
            "Shell", kind="exec", mutating=True, payload={"argv": ["true"]}
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "allowed_tools")


if __name__ == "__main__":
    unittest.main()
