"""Red tests for the shell-session backend choice.

Shell sessions test session semantics: a cwd set in one call is remembered
by the next call in the same session, and an env var set in one call is
visible in the next. None of that depends on which sandbox backend runs the
command.

Left on the default backend, the tests ask the host whether bubblewrap can
enforce a capability boundary, and answer "the session feature is broken"
when the real answer is "this kernel cannot load a BPF filter". The rest of
the suite already pins shell_backend="process" for exactly this reason.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import support  # noqa: F401  (bootstraps sys.path)


class ShellSessionBackendTests(unittest.TestCase):
    def test_the_session_driver_pins_the_backend_it_depends_on(self):
        import test_shell_sessions

        source = Path(test_shell_sessions.__file__).read_text(encoding="utf-8")
        self.assertIn("shell_backend", source)
        self.assertIn("shell_seccomp", source)

    def test_a_session_run_produces_output_on_any_host(self):
        # The real assertion: with the environment pinned, the command runs
        # and the session remembers what the previous call set.
        import test_shell_sessions

        case = test_shell_sessions.ShellSessionTests("test_session_remembers_cwd")
        case.setUp()
        self.addCleanup(case.tearDown)
        report = case._drive(
            [
                case._turn("t0", {"command": "mkdir -p proj"}),
                case._turn("t1", {"command": "pwd", "cwd": "proj", "session": "s1"}),
                case._turn("t2", {"command": "pwd", "session": "s1"}),
            ],
            capdrop="off",
        )
        stdouts = test_shell_sessions._stdouts(report)
        self.assertIn("t1", stdouts, sorted(stdouts))
        self.assertTrue(stdouts["t1"].rstrip().endswith("/proj"), stdouts["t1"])
        self.assertTrue(stdouts["t2"].rstrip().endswith("/proj"), stdouts["t2"])


if __name__ == "__main__":
    unittest.main()
