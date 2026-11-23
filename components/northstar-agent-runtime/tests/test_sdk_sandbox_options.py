"""Red tests for the SDK's sandbox configuration surface.

The CLI exposes --sandbox and --seccomp so an operator can state what the
host can and cannot enforce. RunOptions exposes neither, so a host driving
the SDK cannot say the same thing - it inherits whatever the machine
happens to support, and a run that depends on a syscall boundary fails on
a kernel that cannot provide one with no way to ask for less.

The rest of the suite already pins shell_backend="process" when it drives
the runtime directly. The SDK path needs the same door.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import support  # noqa: F401  (bootstraps sys.path)
import sdk  # noqa: E402


class RunOptionsSandboxSurfaceTests(unittest.TestCase):
    def test_run_options_accepts_a_shell_backend(self):
        from sdk import RunOptions

        options = RunOptions(shell_backend="process")
        self.assertEqual(options.shell_backend, "process")

    def test_run_options_accepts_a_shell_seccomp_mode(self):
        from sdk import RunOptions

        options = RunOptions(shell_seccomp="off")
        self.assertEqual(options.shell_seccomp, "off")

    def test_run_options_accepts_a_shell_capdrop_mode(self):
        from sdk import RunOptions

        options = RunOptions(shell_capdrop="off")
        self.assertEqual(options.shell_capdrop, "off")

    def test_the_defaults_are_the_host_chosen_ones(self):
        from sdk import RunOptions

        options = RunOptions()
        self.assertEqual(options.shell_backend, "auto")
        self.assertEqual(options.shell_seccomp, "auto")
        self.assertEqual(options.shell_capdrop, "on")

    def test_run_carries_the_backend_into_the_runtime(self):
        import sdk

        runtime, _store, _transcript = sdk._build(
            sdk.RunOptions(prompt="hi", shell_backend="process")
        )
        self.assertEqual(runtime.config.shell_backend, "process")

    def test_run_carries_the_seccomp_mode_into_the_runtime(self):
        import sdk

        runtime, _store, _transcript = sdk._build(
            sdk.RunOptions(prompt="hi", shell_seccomp="off")
        )
        self.assertEqual(runtime.config.shell_seccomp, "off")

    def test_run_carries_the_capdrop_mode_into_the_runtime(self):
        import sdk

        runtime, _store, _transcript = sdk._build(
            sdk.RunOptions(prompt="hi", shell_capdrop="off")
        )
        self.assertEqual(runtime.config.shell_capdrop, "off")


if __name__ == "__main__":
    unittest.main()
