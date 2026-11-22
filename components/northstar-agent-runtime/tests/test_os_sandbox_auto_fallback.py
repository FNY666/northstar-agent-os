"""Auto backend selection must not pick a backend that cannot run the request.

Context: on hosts where bubblewrap exists but its own seccomp filter is
rejected by the kernel, ``resolve_backend("auto")`` picked bwrap and every
shell request died with "bwrap seccomp was requested but its live filter
probe failed". The process backend enforces the same denylist through its
own prctl wrapper, so auto may fall back to it — but it must say so.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.os_sandbox import (
    SandboxCapabilities,
    SandboxError,
    SandboxRequest,
    SandboxResult,
    run_sandboxed,
)


class AutoBackendFallbackTests(unittest.TestCase):
    def _caps_without_bwrap_seccomp(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            bwrap_path="/fake/bwrap",
            bwrap_usable=True,
            bwrap_detail="base probe passed",
            bwrap_cap_drop=True,
            bwrap_seccomp=False,
            bwrap_seccomp_detail="bwrap seccomp child probe failed: EINVAL",
            preferred="bwrap",
        )

    def _run_auto(self, caps, seccomp="auto"):
        from tools import os_sandbox

        stub = SandboxResult(("true",), "stub", "stub", 0, False, "", "", 1)
        with tempfile.TemporaryDirectory() as root:
            with patch.object(os_sandbox, "_run_popen", return_value=stub) as launch:
                request = SandboxRequest(
                    argv=("true",), cwd=Path(root), workspace=Path(root),
                    seccomp=seccomp,
                )
                result = run_sandboxed(request, backend="auto", capabilities=caps)
        return result, launch

    def test_auto_falls_back_to_process_when_bwrap_cannot_enforce_seccomp(self):
        caps = self._caps_without_bwrap_seccomp()
        result, launch = self._run_auto(caps)
        launch.assert_called()
        self.assertEqual(launch.call_args.kwargs.get("backend"), "process")

    def test_auto_fallback_is_reported_loudly(self):
        caps = self._caps_without_bwrap_seccomp()
        result, _ = self._run_auto(caps)
        self.assertTrue(result.warnings)
        joined = " ".join(result.warnings).lower()
        self.assertIn("bwrap", joined)
        self.assertIn("seccomp", joined)
        self.assertIn("process", joined)

    def test_explicit_bwrap_still_refuses_to_run(self):
        """An operator who names bwrap must get the loud failure, not a fallback."""
        from tools import os_sandbox

        caps = self._caps_without_bwrap_seccomp()
        with tempfile.TemporaryDirectory() as root, patch.object(os_sandbox, "_run_popen") as launch:
            request = SandboxRequest(
                argv=("true",), cwd=Path(root), workspace=Path(root), seccomp="auto",
            )
            with self.assertRaisesRegex(SandboxError, "seccomp.*live filter probe failed"):
                run_sandboxed(request, backend="bwrap", capabilities=caps)
            launch.assert_not_called()

    def test_explicit_bwrap_with_seccomp_off_still_runs(self):
        from tools import os_sandbox

        caps = self._caps_without_bwrap_seccomp()
        stub = SandboxResult(("true",), "bwrap", "os", 0, False, "", "", 1)
        with tempfile.TemporaryDirectory() as root, patch.object(os_sandbox, "_run_popen", return_value=stub) as launch:
            request = SandboxRequest(
                argv=("true",), cwd=Path(root), workspace=Path(root), seccomp="off",
            )
            result = run_sandboxed(request, backend="bwrap", capabilities=caps)
            launch.assert_called()
        self.assertEqual(result.backend, "bwrap")

    def test_auto_with_healthy_bwrap_keeps_bwrap(self):
        """No regression: when bwrap can enforce seccomp, auto still picks it."""
        caps = SandboxCapabilities(
            bwrap_path="/fake/bwrap",
            bwrap_usable=True,
            bwrap_detail="base probe passed",
            bwrap_cap_drop=True,
            bwrap_seccomp=True,
            bwrap_seccomp_detail="bwrap seccomp child probe passed",
            preferred="bwrap",
        )
        result, launch = self._run_auto(caps)
        self.assertEqual(launch.call_args.kwargs.get("backend"), "bwrap")
        self.assertFalse(result.warnings)


if __name__ == "__main__":
    unittest.main()
