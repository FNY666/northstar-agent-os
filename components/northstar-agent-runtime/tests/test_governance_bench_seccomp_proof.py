"""The seccomp bench cases must prove the filter by behaviour, not by /proc.

A host whose kernel offers Landlock lets the process backend confine reads to
an allow-list, and /proc/self/status is not on that list. Proving the filter
through /proc therefore reports "required path missing" on a host that does
have a working filter. The denylist rejects with EPERM instead of killing the
process, so a denied syscall is observable from inside the sandbox.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import support  # noqa: F401  (bootstraps sys.path)


class SeccompProofShapeTests(unittest.TestCase):
    """The proof must not depend on /proc/self/status being readable."""

    def test_the_proof_command_does_not_read_proc(self):
        import governance_bench

        source = Path(governance_bench.__file__).read_text(encoding="utf-8")
        live = source.split("def _case_seccomp_filter_live_on_process", 1)[1]
        live = live.split("\ndef ", 1)[0]
        self.assertNotIn("/proc/self/status", live)

    def test_the_proof_command_asks_for_a_denied_syscall(self):
        import governance_bench

        self.assertIn("socket", governance_bench._SECCOMP_LIVE_PROOF_COMMAND)

    def test_the_tighten_only_case_also_proves_by_behaviour(self):
        import governance_bench

        source = Path(governance_bench.__file__).read_text(encoding="utf-8")
        tighten = source.split("def _case_seccomp_payload_cannot_loosen", 1)[1]
        tighten = tighten.split("\ndef ", 1)[0]
        self.assertNotIn("/proc/self/status", tighten)
        self.assertIn("_SECCOMP_LIVE_PROOF_COMMAND", tighten)


if __name__ == "__main__":
    unittest.main()
