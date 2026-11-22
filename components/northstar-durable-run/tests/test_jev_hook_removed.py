"""R26b: the Jev shadow hook is gone from the retry loop, and the retry loop behaves as before.

Why the behavioural tests install a sentinel instead of just importing agent_loop: the hook was a lazy,
function-local `from recovery_shadow import ...` wrapped in `except Exception: pass`. Importing the module never
ran it, and a blocked import was silently swallowed, so neither "can import agent_loop" nor "import raises"
distinguishes hook-present from hook-absent. A sentinel that RECORDS being called does: with the hook present the
failed attempt reaches it, with the hook absent it is never touched.

All cases are unittest.TestCase so the official runner (run_component_tests.py -> unittest discover) collects them.
"""
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-run-contract"))

from agent_loop import AgentLoop, PostconditionResult  # noqa: E402
from test_agent_loop import RUN, planner_output  # noqa: E402

HOOK_IDENTIFIERS = ("recovery_shadow", "_shadow_record", "record_recovery", "JEV_SHADOW")


def verified():
    return PostconditionResult("verified", "fixture_matches", "sha256:" + "a" * 64)


def absent():
    return PostconditionResult("absent", "not_present")


class JevHookSourceTests(unittest.TestCase):
    def test_agent_loop_source_has_no_hook_identifiers(self):
        # Scoped to agent_loop.py on purpose: recovery_shadow.py itself still ships in the component (dead,
        # unreferenced code; deleting it is a separate decision) and legitimately contains these names.
        source = (COMPONENT_ROOT / "agent_loop.py").read_text(encoding="utf-8")
        self.assertEqual([name for name in HOOK_IDENTIFIERS if name in source], [])


class RetryLoopWithoutHookTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.evidence = Path(self.tempdir.name) / "loop-evidence.jsonl"
        self.calls = []
        # Sentinel standing in for the real module: any import-and-call of the hook lands here.
        self.sentinel_calls = []
        sentinel = types.ModuleType("recovery_shadow")
        sentinel.record_recovery = lambda *args, **kwargs: self.sentinel_calls.append((args, kwargs))
        patcher = mock.patch.dict(sys.modules, {"recovery_shadow": sentinel})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_scenario(self, verdicts, *, max_attempts=2):
        remaining = iter(verdicts)
        loop = AgentLoop(
            RUN,
            self.evidence,
            actor_id="actor-loop-001",
            workspace_id="workspace-loop-001",
            actions={"workspace.write": lambda step, attempt_id: self.calls.append(attempt_id) or {"claimed": "finished"}},
            observer=lambda step, attempt_id: next(remaining),
        )
        value = planner_output()
        value["steps"][0]["max_attempts"] = max_attempts
        plan = loop.admit(value, current_policy_revision="policy-loop-1")
        return loop.run(plan, owner_id="worker-loop-001", now=100, current_policy_revision="policy-loop-1")

    def events(self):
        return [json.loads(line) for line in self.evidence.read_text(encoding="utf-8").splitlines()]

    def test_failed_attempt_then_retry_never_reaches_recovery_shadow(self):
        state = self.run_scenario([absent(), verified()])
        self.assertEqual(state.status, "finished")
        self.assertEqual(self.sentinel_calls, [])

    def test_exhausted_attempts_never_reach_recovery_shadow_and_still_fail_closed(self):
        state = self.run_scenario([absent(), absent()])
        self.assertEqual(state.status, "failed")
        self.assertEqual(self.sentinel_calls, [])
        last = self.events()[-1]
        self.assertEqual(last["event_type"], "loop.failed")
        self.assertEqual(last["reason_code"], "max_attempts_exhausted")
        self.assertEqual(len(self.calls), 2)

    def test_retry_uses_consecutive_attempt_identities(self):
        self.run_scenario([absent(), verified()])
        self.assertEqual(self.calls, ["execution-loop-write-1:attempt-1", "execution-loop-write-1:attempt-2"])

    def test_unknown_postcondition_still_pauses_without_a_retry(self):
        state = self.run_scenario([PostconditionResult("unknown", "provider_readback_timeout")])
        self.assertEqual(state.status, "paused_unknown")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.sentinel_calls, [])


if __name__ == "__main__":
    unittest.main()
