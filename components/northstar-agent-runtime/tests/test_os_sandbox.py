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
from types import SimpleNamespace
from unittest.mock import patch

import support  # noqa: F401 — puts the runtime root on sys.path
from support import RuntimeTestCase

from permissions import PermissionConfig, PermissionEngine
from tools import ToolContext, ToolSandbox, ToolResult, build_default_registry
from tools.os_sandbox import (
    SandboxError,
    SandboxRequest,
    _bwrap_argv,
    _minimal_identity_files,
    probe_capabilities,
    reset_capabilities_cache,
    resolve_backend,
    run_sandboxed,
)
from tools.shell import parse_shell_argv, shell_handler


class BwrapArgvSurfaceTests(unittest.TestCase):
    """Pin the bwrap bind surface: any expansion is a deliberate diff.

    bwrap itself is usually absent from CI, so these tests pin the argv
    _bwrap_argv builds rather than running a sandbox.
    """

    def _argv(self, **kwargs):
        import tempfile
        from pathlib import Path

        root = Path(tempfile.mkdtemp(prefix="nsar-bwrap-argv-"))
        request = SandboxRequest(argv=("true",), cwd=root, workspace=root)
        return _bwrap_argv(request, bwrap_path="/usr/bin/bwrap", **kwargs)

    def _ro_bind_sources(self, argv):
        return [argv[i + 1] for i, a in enumerate(argv) if a == "--ro-bind"]

    def test_ro_binds_are_minimal_and_pinned(self):
        sources = self._ro_bind_sources(self._argv())
        expected = [p for p in ("/usr", "/bin", "/lib", "/lib64", "/sbin") if os.path.exists(p)]
        self.assertEqual(sources, expected)

    def test_host_identity_and_dns_files_are_never_ro_bound(self):
        argv = self._argv()
        for i, arg in enumerate(argv):
            if arg == "--ro-bind":
                src, dest = argv[i + 1], argv[i + 2]
                self.assertNotIn(dest, ("/etc/passwd", "/etc/group"),
                                 f"real host identity must not be bound (src={src})")
                self.assertNotIn(src, ("/etc/resolv.conf", "/etc/ssl", "/etc/passwd", "/etc/group"),
                                 "host dns/tls/identity files must not be bound")

    def test_synthetic_identity_is_bound_when_paths_given(self):
        argv = self._argv(passwd_path="/tmp/pw", group_path="/tmp/gr")
        self.assertIn("/etc/passwd", argv)
        self.assertIn("/etc/group", argv)
        idx = argv.index("/etc/passwd")
        self.assertEqual(argv[idx - 2:idx + 1], ["--ro-bind", "/tmp/pw", "/etc/passwd"])
        idx = argv.index("/etc/group")
        self.assertEqual(argv[idx - 2:idx + 1], ["--ro-bind", "/tmp/gr", "/etc/group"])

    def test_namespace_and_lifecycle_flags_are_pinned(self):
        argv = self._argv()
        for flag in ("--die-with-parent", "--new-session", "--unshare-pid",
                     "--unshare-net", "--unshare-ipc", "--unshare-uts"):
            self.assertIn(flag, argv)
        # The workspace stays the only writable bind.
        self.assertEqual(argv.count("--bind"), 1)

    def test_minimal_identity_files_expose_only_the_current_user(self):
        import pwd

        passwd, group = _minimal_identity_files()
        self.assertEqual(passwd.count("\n"), 1, "exactly one passwd entry")
        self.assertEqual(group.count("\n"), 1, "exactly one group entry")
        uid, gid = os.getuid(), os.getgid()
        self.assertIn(f":{uid}:{gid}:", passwd)
        self.assertIn(f":{gid}:", group)
        try:
            own_name = pwd.getpwuid(uid).pw_name
        except KeyError:
            own_name = None
        for entry in pwd.getpwall():
            if own_name is not None and entry.pw_name == own_name:
                continue
            self.assertNotIn(f"\n{entry.pw_name}:", "\n" + passwd,
                             f"other host user {entry.pw_name!r} must stay invisible")


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

    def test_process_backend_terminates_a_command_that_exceeds_output_cap(self):
        result = run_sandboxed(
            self._request(
                [sys.executable, "-c", "import os; chunk=b'x'*65536\nwhile True: os.write(1, chunk)"],
                timeout_ms=5_000,
                max_output_bytes=1_024,
            ),
            backend="process",
        )
        self.assertFalse(result.timed_out)
        self.assertTrue(result.truncated)
        self.assertEqual(len(result.stdout.encode("utf-8")), 1_024)
        self.assertIn("output cap", result.detail)
        self.assertIsNotNone(result.exit_code)

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

    def test_model_payload_cannot_downgrade_operator_bwrap(self):
        # No command is executed: the spy observes only backend selection. This
        # self-contained regression protects operator authority on hosts where
        # bwrap is mocked, absent, or unavailable in CI.
        ctx = ToolContext(
            session_id="test",
            sandbox=ToolSandbox(self.root),
            services={"shell_backend": "bwrap", "shell_seccomp": "on"},
        )
        observed = {}

        def fake_run(request, *, backend):
            observed["backend"] = backend
            observed["request"] = request
            return SimpleNamespace(
                render=lambda: "exit=0\\nbackend=bwrap isolation=os\\n(no command executed)",
                as_dict=lambda: {"backend": backend, "isolation": "os", "exit_code": 0},
                timed_out=False,
                truncated=False,
            )

        with patch("tools.shell.run_sandboxed", fake_run):
            result = shell_handler(
                {"argv": ["/bin/true"], "backend": "process"}, ctx
            )

        # The model-supplied extra field is rejected; the privileged runner is
        # never called with a weaker backend.
        self.assertTrue(result.is_error)
        self.assertNotIn("backend", observed)
        spec = build_default_registry().get("Shell")
        self.assertIs(spec.input_schema.get("additionalProperties"), False)
        # The same closed schema is sent on the OpenAI-compatible wire.
        from providers.openai_compat import OpenAICompatProvider
        wire = OpenAICompatProvider(model="test", client=object()).to_chat_tools([spec.to_api()])
        self.assertIs(wire[0]["function"]["parameters"].get("additionalProperties"), False)

    def test_operator_selected_process_backend_remains_available(self):
        ctx = ToolContext(
            session_id="test",
            sandbox=ToolSandbox(self.root),
            services={"shell_backend": "process"},
        )
        observed = {}

        def fake_run(request, *, backend):
            observed["backend"] = backend
            return SimpleNamespace(
                render=lambda: "exit=0\\nbackend=process isolation=process\\n(no command executed)",
                as_dict=lambda: {"backend": backend, "isolation": "process", "exit_code": 0},
                timed_out=False,
                truncated=False,
            )

        with patch("tools.shell.run_sandboxed", fake_run):
            result = shell_handler({"argv": ["/bin/true"]}, ctx)

        self.assertFalse(result.is_error)
        self.assertEqual(observed["backend"], "process")

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
