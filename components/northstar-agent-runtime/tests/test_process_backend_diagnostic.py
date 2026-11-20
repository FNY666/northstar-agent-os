"""Diagnostic: what does the process backend actually say on this host?

The two seccomp benchmark cases prove the denylist is loaded by looking
for "Seccomp: 2" in /proc/self/status. On the CI runner they fail even
though a bare prctl probe succeeds, so the probe and the real path are
not the same path, and the difference has to be visible rather than
guessed at.

This test prints the sandbox's own words for the command the benchmark
runs. It asserts nothing: it exists so the next run of CI says what the
shell saw.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import support  # noqa: F401  (bootstraps sys.path)
from support import RuntimeTestCase  # noqa: E402


class ProcessBackendDiagnosticTests(RuntimeTestCase):
    def test_the_process_backend_says_what_it_did(self):
        from tools.os_sandbox import SandboxRequest, run_sandboxed

        workspace = self.workspace()
        request = SandboxRequest(
            argv=(
                "sh",
                "-c",
                "grep -q 'Seccomp:\t2' /proc/self/status && touch filter_live.txt",
            ),
            cwd=workspace,
            workspace=workspace,
            timeout_ms=15_000,
        )
        result = run_sandboxed(request, backend="process")
        print("\n===== process backend =====")
        print("exit_code:", result.exit_code)
        print(result.render())
        print("===== end =====")

    def test_the_bare_prctl_probe_says_what_it_did(self):
        import subprocess

        from tools.seccomp import prctl_loader_argv

        argv = prctl_loader_argv(
            ["sh", "-c", "grep -q 'Seccomp:\t2' /proc/self/status"]
        )
        completed = subprocess.run(argv, capture_output=True, timeout=30)
        print("\n===== bare prctl probe =====")
        print("returncode:", completed.returncode)
        print("stderr:", completed.stderr.decode(errors="replace")[-600:])
        print("===== end =====")


if __name__ == "__main__":
    unittest.main()
