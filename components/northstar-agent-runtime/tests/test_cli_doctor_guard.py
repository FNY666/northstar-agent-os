"""Red tests for the doctor capability guard.

Doctor reports a failed check by exiting non-zero. A check that fails because
the host kernel cannot provide a sandbox capability is telling the truth
about the host, not about doctor. Tests that assert "doctor exits clean" are
therefore asserting a property of the machine they run on.

The guard lets those tests say what they mean: they check that doctor
reports these particular findings cleanly, and they only do so on a host
where the sandbox capabilities doctor needs are actually present.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import support  # noqa: F401  (bootstraps sys.path)
from tools.os_sandbox import SandboxCapabilities  # noqa: E402


def _caps(**overrides):
    base = {
        "bwrap_path": "/usr/bin/bwrap",
        "bwrap_usable": True,
        "bwrap_detail": "bwrap usable",
        "bwrap_cap_drop": True,
        "bwrap_seccomp": True,
        "bwrap_seccomp_detail": "bwrap seccomp child probe passed",
        "process_available": True,
        "preferred": "bwrap",
    }
    base.update(overrides)
    return SandboxCapabilities(**base)


class DoctorCapabilityGuardTests(unittest.TestCase):
    def test_a_host_with_every_capability_is_not_skipped(self):
        import test_cli

        reason = test_cli._doctor_capability_skip_reason(_caps())
        self.assertIsNone(reason)

    def test_a_host_without_seccomp_is_skipped(self):
        import test_cli

        reason = test_cli._doctor_capability_skip_reason(
            _caps(bwrap_seccomp=False, bwrap_seccomp_detail="prctl(PR_SET_SECCOMP) reported EINVAL")
        )
        self.assertIsNotNone(reason)
        self.assertIn("seccomp", reason.lower())

    def test_the_reason_quotes_the_probe(self):
        import test_cli

        reason = test_cli._doctor_capability_skip_reason(
            _caps(bwrap_seccomp=False, bwrap_seccomp_detail="prctl(PR_SET_SECCOMP) reported EINVAL")
        )
        self.assertIn("EINVAL", reason)

    def test_an_unusable_bwrap_is_reported(self):
        import test_cli

        reason = test_cli._doctor_capability_skip_reason(
            _caps(bwrap_usable=False, bwrap_detail="bwrap failed probe")
        )
        self.assertIsNotNone(reason)
        self.assertIn("bwrap", reason.lower())


if __name__ == "__main__":
    unittest.main()
