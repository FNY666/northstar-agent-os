from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import support  # noqa: F401
from tools.os_sandbox import _run_scoped_popen
from tools.os_sandbox import SandboxError, SandboxRequest, _validate_request
from tools.systemd_scope import (
    SystemdScopeError,
    cleanup_systemd_scope,
    systemd_scope_argv,
    validate_systemd_scope_host,
)


UNIT = "northstar-" + "a" * 32 + ".scope"


class SystemdScopeArgvTests(unittest.TestCase):
    @patch("tools.systemd_scope.validate_systemd_scope_host")
    @patch("tools.systemd_scope.shutil.which", return_value="/usr/bin/systemctl")
    def test_builds_pid1_owned_scope_with_aggregate_ceilings(self, _which, _validate):
        command, unit = systemd_scope_argv(
            ("/usr/bin/python3", "-c", "print('ok')"),
            memory_max_bytes=256 * 1024 * 1024,
            tasks_max=16,
            systemd_run="/usr/bin/systemd-run",
            unit_name=UNIT,
        )
        self.assertEqual(unit, UNIT)
        self.assertEqual(command[0], "/usr/bin/systemd-run")
        self.assertIn("--scope", command)
        self.assertIn("--pipe", command)
        self.assertIn("--property=MemoryMax=268435456", command)
        self.assertIn("--property=TasksMax=16", command)
        self.assertIn("--property=CPUQuota=100%", command)
        self.assertEqual(command[command.index("--") + 1 :], ("/usr/bin/python3", "-c", "print('ok')"))

    def test_rejects_bad_limits_and_unit_names(self):
        for kwargs in (
            {"memory_max_bytes": 0, "tasks_max": 2},
            {"memory_max_bytes": 10, "tasks_max": True},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(SystemdScopeError):
                systemd_scope_argv(("true",), systemd_run="/usr/bin/systemd-run", **kwargs)
        with patch("tools.systemd_scope.validate_systemd_scope_host"), patch(
            "tools.systemd_scope.shutil.which", return_value="/usr/bin/systemctl"
        ), self.assertRaisesRegex(SystemdScopeError, "unit name"):
            systemd_scope_argv(
                ("true",), memory_max_bytes=10, tasks_max=2,
                systemd_run="/usr/bin/systemd-run", unit_name="northstar-;touch-pwned.scope",
            )

    def test_host_validation_requires_cgroup_v2_systemd_tools_and_non_root(self):
        with patch("tools.systemd_scope.os.geteuid", return_value=0), self.assertRaisesRegex(
            SystemdScopeError, "non-root"
        ):
            validate_systemd_scope_host()

    def test_aggregate_request_requires_active_seccomp(self):
        with tempfile.TemporaryDirectory(prefix="northstar-scope-request-") as directory:
            root = Path(directory)
            request = SandboxRequest(
                argv=("true",), cwd=root, workspace=root,
                aggregate_resource_scope="systemd", seccomp="off",
            )
            with self.assertRaisesRegex(SandboxError, "require seccomp"):
                _validate_request(request)

    def test_aggregate_request_validates_task_ceiling(self):
        with tempfile.TemporaryDirectory(prefix="northstar-scope-request-") as directory:
            root = Path(directory)
            request = SandboxRequest(argv=("true",), cwd=root, workspace=root, max_tasks=129)
            with self.assertRaisesRegex(SandboxError, "max_tasks"):
                _validate_request(request)

    def test_runtime_config_records_operator_selected_scope(self):
        from loop import RuntimeConfig, RuntimeConfigurationError

        with patch("tools.systemd_scope.validate_systemd_scope_host"):
            config = RuntimeConfig(shell_aggregate_resource_scope="systemd")
        self.assertEqual(config.as_dict()["shell_aggregate_resource_scope"], "systemd")
        with self.assertRaisesRegex(RuntimeConfigurationError, "require seccomp"):
            RuntimeConfig(shell_seccomp="off", shell_aggregate_resource_scope="systemd")


class SystemdScopeCleanupTests(unittest.TestCase):
    @patch("tools.systemd_scope.shutil.which", return_value="/usr/bin/systemctl")
    @patch("tools.systemd_scope.subprocess.run")
    def test_kills_then_stops_complete_scope(self, run, _which):
        run.side_effect = [
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0),
        ]
        self.assertEqual(cleanup_systemd_scope(UNIT), (True, ""))
        self.assertEqual(run.call_args_list[0].args[0][1], "kill")
        self.assertIn("--kill-whom=all", run.call_args_list[0].args[0])
        self.assertEqual(run.call_args_list[1].args[0][1], "stop")

    @patch("tools.systemd_scope.shutil.which", return_value="/usr/bin/systemctl")
    @patch("tools.systemd_scope.subprocess.run")
    def test_reports_scope_that_remains_active_after_cleanup(self, run, _which):
        run.side_effect = [
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 0, stdout="active\n"),
        ]
        cleaned, detail = cleanup_systemd_scope(UNIT)
        self.assertFalse(cleaned)
        self.assertIn("may still have descendants", detail)


class SystemdScopeRunnerTests(unittest.TestCase):
    def test_runner_executes_inside_scope_wrapper_and_reports_limits(self):
        with tempfile.TemporaryDirectory(prefix="northstar-systemd-scope-test-") as directory:
            root = Path(directory)
            args_path = root / "systemd-run-argv.txt"
            fake_run = root / "systemd-run"
            fake_run.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$@\" > {shlex.quote(str(args_path))}\n"
                "while [ \"$1\" != \"--\" ]; do shift; done\n"
                "shift\n"
                "exec \"$@\"\n",
                encoding="utf-8",
            )
            fake_run.chmod(0o700)
            fake_ctl = root / "systemctl"
            fake_ctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_ctl.chmod(0o700)
            def which(name: str) -> str | None:
                return str(fake_run if name == "systemd-run" else fake_ctl if name == "systemctl" else "") or None

            with patch("tools.systemd_scope.validate_systemd_scope_host"), patch(
                "tools.systemd_scope.shutil.which", side_effect=which
            ):
                result = _run_scoped_popen(
                    (sys.executable, "-c", "print('ran in bounded scope')"),
                    aggregate_resource_scope="systemd",
                    memory_max_bytes=64 * 1024 * 1024,
                    max_tasks=8,
                    cwd=root,
                    env={"PATH": os.environ.get("PATH", "")},
                    timeout_ms=5000,
                    max_output_bytes=4096,
                    backend="process",
                    isolation="process",
                )

            argv_text = args_path.read_text(encoding="utf-8")
            self.assertIn("--property=MemoryMax=67108864", argv_text)
            self.assertIn("--property=TasksMax=8", argv_text)
            self.assertIn("--property=CPUQuota=100%", argv_text)
            self.assertEqual(result.stdout.strip(), "ran in bounded scope")
            self.assertFalse(result.aggregate_cleanup_failed)
            self.assertIn("aggregate cgroup enforced", result.detail)
            self.assertTrue(result.ok)

    def test_manager_failure_never_executes_unscoped_command(self):
        with tempfile.TemporaryDirectory(prefix="northstar-systemd-scope-fail-") as directory:
            root = Path(directory)
            target = root / "must-not-exist"
            fake_run = root / "systemd-run"
            fake_run.write_text("#!/bin/sh\nprintf 'manager unavailable\\n' >&2\nexit 1\n", encoding="utf-8")
            fake_run.chmod(0o700)
            fake_ctl = root / "systemctl"
            fake_ctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_ctl.chmod(0o700)

            def which(name: str) -> str | None:
                return str(fake_run if name == "systemd-run" else fake_ctl if name == "systemctl" else "") or None

            with patch("tools.systemd_scope.validate_systemd_scope_host"), patch(
                "tools.systemd_scope.shutil.which", side_effect=which
            ):
                result = _run_scoped_popen(
                    (sys.executable, "-c", "open(%r,'w').close()" % str(target)),
                    aggregate_resource_scope="systemd",
                    memory_max_bytes=64 * 1024 * 1024,
                    max_tasks=8,
                    cwd=root,
                    env={"PATH": os.environ.get("PATH", "")},
                    timeout_ms=5000,
                    max_output_bytes=4096,
                    backend="process",
                    isolation="process",
                )

            self.assertFalse(target.exists())
            self.assertTrue(result.aggregate_setup_failed)
            self.assertFalse(result.ok)
            self.assertIn("aggregate limits were not established", result.detail)


class SystemdScopeInheritanceTests(support.RuntimeTestCase):
    def test_delegated_child_inherits_every_shell_enforcement_setting(self):
        from loop import RuntimeConfig, _RunState

        with patch("tools.systemd_scope.validate_systemd_scope_host"):
            config = RuntimeConfig(
                shell_backend="process",
                shell_seccomp="auto",
                shell_capdrop="off",
                shell_landlock="off",
                shell_aggregate_resource_scope="systemd",
            )
            parent = self.runtime([], config=config)
            child, child_config, _mode = parent._child_runtime(
                parent.agents.get("general"),
                parent.provider,
                _RunState(session_id=parent.session_id),
            )

        self.assertIsNotNone(child)
        self.assertEqual(child_config.shell_backend, "process")
        self.assertEqual(child_config.shell_seccomp, "auto")
        self.assertEqual(child_config.shell_capdrop, "off")
        self.assertEqual(child_config.shell_landlock, "off")
        self.assertEqual(child_config.shell_aggregate_resource_scope, "systemd")


if __name__ == "__main__":
    unittest.main()
