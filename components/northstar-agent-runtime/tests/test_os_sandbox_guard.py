"""Red tests for the bwrap capability guard on sandbox tests.

The bwrap backend refuses to start when a requested capability boundary
cannot be enforced: no live capability-drop probe, or no live seccomp
probe. That refusal is the product working correctly. A test that asserts
the refusal never happens on a host that cannot offer the capability is
asserting something about the kernel rather than about the code, and it
turns an environment difference into a red build.

The guard has to do two things:
  - skip when the capability the default request needs is missing, and
  - say which capability was missing and what the probe reported, so a
    skipped test is still information.
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


class BwrapCapabilityGuardTests(unittest.TestCase):
    def test_a_host_with_every_capability_is_not_skipped(self):
        import test_os_sandbox

        reason = test_os_sandbox._bwrap_capability_skip_reason(_caps())
        self.assertIsNone(reason)

    def test_a_host_without_seccomp_is_skipped(self):
        import test_os_sandbox

        reason = test_os_sandbox._bwrap_capability_skip_reason(
            _caps(bwrap_seccomp=False, bwrap_seccomp_detail="prctl(PR_SET_SECCOMP) reported EINVAL")
        )
        self.assertIsNotNone(reason)
        self.assertIn("seccomp", reason.lower())

    def test_a_host_without_capability_drop_is_skipped(self):
        import test_os_sandbox

        reason = test_os_sandbox._bwrap_capability_skip_reason(
            _caps(bwrap_cap_drop=False)
        )
        self.assertIsNotNone(reason)
        self.assertIn("cap", reason.lower())

    def test_the_reason_names_what_the_probe_reported(self):
        # A skip that only says "unsupported" is not much better than a
        # failure: the reader still cannot tell what the host said.
        import test_os_sandbox

        reason = test_os_sandbox._bwrap_capability_skip_reason(
            _caps(bwrap_seccomp=False, bwrap_seccomp_detail="prctl(PR_SET_SECCOMP) reported EINVAL")
        )
        self.assertIn("EINVAL", reason)

    def test_an_unusable_bwrap_is_reported_before_the_capabilities(self):
        import test_os_sandbox

        reason = test_os_sandbox._bwrap_capability_skip_reason(
            _caps(bwrap_usable=False, bwrap_detail="bwrap at /usr/bin/bwrap failed probe")
        )
        self.assertIsNotNone(reason)
        self.assertIn("bwrap", reason.lower())


if __name__ == "__main__":
    unittest.main()
