"""Red tests for the sealed-snapshot capability probe.

The problem: the snapshot guard used to guess capability from the platform
("linux" plus a present /proc/self/fd). The runtime actually needs a working
memfd_create, which a Linux kernel can still refuse to implement. A guess that
is optimistic makes a configured hook fail closed at run time with no way for
the operator to tell "the hook said deny" from "this host cannot seal scripts".

The fix is a real probe: create a memfd, seal it, and report what happened.
"""

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import command_hooks  # noqa: E402


class SealedSnapshotProbeTests(unittest.TestCase):
    def test_the_probe_answers_a_question_about_this_host(self):
        self.assertIsInstance(command_hooks.sealed_snapshot_supported(), bool)

    def test_the_probe_agrees_with_what_the_runtime_can_actually_do(self):
        # The probe must not claim more than the runtime can deliver: if the
        # probe says yes, sealing a script has to work.
        if not command_hooks.sealed_snapshot_supported():
            self.skipTest("this host cannot seal script snapshots")
        fd = command_hooks._sealed_script_fd(b"print('ok')\n")
        try:
            self.assertGreaterEqual(fd, 0)
        finally:
            os.close(fd)

    def test_a_host_without_the_probe_is_told_so_at_parse_time(self):
        # When the probe says no, asking for snapshot execution must be refused
        # during parsing rather than silently degrading at run time.
        original = command_hooks.sealed_snapshot_supported
        command_hooks.sealed_snapshot_supported = lambda: False
        self.addCleanup(setattr, command_hooks, "sealed_snapshot_supported", original)
        root = Path(os.environ.get("TMPDIR", "/tmp")) / "nsar-probe-guard"
        (root / ".northstar" / "hooks").mkdir(parents=True, exist_ok=True)
        (root / ".northstar" / "hooks" / "gate.py").write_text(
            'print("{\\"decision\\":\\"allow\\"}")\n', encoding="utf-8"
        )
        with self.assertRaises(command_hooks.CommandHookError) as caught:
            command_hooks.parse_hooks(
                [
                    {
                        "event": "PreToolUse",
                        "script": ".northstar/hooks/gate.py",
                        "interpreter": "python3",
                        "execution": "snapshot",
                    }
                ],
                workspace=root,
            )
        self.assertIn("snapshot", str(caught.exception).lower())

    def test_the_guard_uses_the_probe_rather_than_a_platform_guess(self):
        # A Linux host whose memfd is unavailable must not be waved through by
        # the platform check alone.
        original = command_hooks.sealed_snapshot_supported
        command_hooks.sealed_snapshot_supported = lambda: False
        self.addCleanup(setattr, command_hooks, "sealed_snapshot_supported", original)
        root = Path(os.environ.get("TMPDIR", "/tmp")) / "nsar-probe-guard-2"
        (root / ".northstar" / "hooks").mkdir(parents=True, exist_ok=True)
        (root / ".northstar" / "hooks" / "gate.py").write_text(
            'print("{\\"decision\\":\\"allow\\"}")\n', encoding="utf-8"
        )
        with self.assertRaises(command_hooks.CommandHookError):
            command_hooks.parse_hooks(
                [
                    {
                        "event": "PreToolUse",
                        "script": ".northstar/hooks/gate.py",
                        "interpreter": "python3",
                        "execution": "snapshot",
                    }
                ],
                workspace=root,
            )


if __name__ == "__main__":
    unittest.main()
