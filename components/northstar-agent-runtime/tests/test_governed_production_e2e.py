"""E2E proof: the SAFR 4-gate runner governs the real production dispatch.

Proves, against the real AgentRuntime (not stubs):

1. A benign production tool call gets the full 4-gate trail:
   declare -> authorize -> assess -> audit in the SAFR checkpoint, and a
   sealed ``governed-action`` record in the run's forward-seal ledger.
2. The gate's own audit (allow AND deny) is sealed by default (task B).
3. A denied call is blocked before execution and its denial is sealed.
4. The observer assess gate blocks when the arguments differ from what the
   gate authorized (TOCTOU tripwire) -- not a hardcoded allow.
5. The sealed chain is hash-linked: every record's prev_hash matches the
   previous record_hash (structural tamper-evidence, no keys needed).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import RuntimeTestCase  # noqa: E402

from governed_action_runner import GovernedActionRunner  # noqa: E402
from providers.base import TextBlock, ToolUseBlock  # noqa: E402
from providers.scripted import ScriptedTurn  # noqa: E402


def _turn(name: str, args: dict, call_id: str = "t1") -> ScriptedTurn:
    return ScriptedTurn(
        blocks=(
            ToolUseBlock(id=call_id, name=name, input=args),
            TextBlock(text="done"),
        ),
        stop_reason="tool_use",
    )


def _chain_links(ledger) -> None:
    """Assert the forward hash chain is structurally linked."""
    records = list(ledger._records)
    assert records, "ledger must not be empty"
    assert records[0].prev_hash == ledger.genesis
    for prev, cur in zip(records, records[1:]):
        assert cur.prev_hash == prev.record_hash, (
            f"chain broken at seq {cur.seq}: prev_hash != record_hash of seq {prev.seq}"
        )
    assert [r.seq for r in records] == list(range(1, len(records) + 1))


def _intents(ledger):
    return [dict(r.event)["intent"] for r in ledger._records]


class GovernedProductionE2E(RuntimeTestCase):
    def _approve_all(self, turns):
        def approve(tool, args, context):
            return True

        return self.runtime(turns, can_use_tool=approve)

    def test_benign_call_gets_full_4gate_trail_and_seal(self):
        runtime = self._approve_all([_turn("Read", {"path": "note.txt"})])
        (Path(runtime.config.workspace) / "note.txt").write_text("hello")
        report = self.drive(runtime)
        self.assertFalse(report.denials, f"benign call denied: {report.denials}")

        # SAFR booked all four gates for the production call.
        safr = runtime._governed_runner._safr
        stats = safr.stats()
        self.assertEqual(stats["declarations"], 1)
        self.assertEqual(stats["authorizations"], 1)
        self.assertEqual(stats["assessments"], 1)
        self.assertEqual(stats["audits"], 1)

        # The sealed ledger holds BOTH the gate audit (task B) and the
        # runner's 4-gate outcome seal (task A), hash-linked.
        ledger = runtime.sealed_ledger
        intents = _intents(ledger)
        self.assertIn("permission-permission.allow", intents)
        self.assertIn("governed-action", intents)
        seal = [
            dict(r.event)
            for r in ledger._records
            if dict(r.event)["intent"] == "governed-action"
        ][0]
        self.assertEqual(seal["outcome"], "executed")
        self.assertEqual(seal["action"], "Read")
        self.assertEqual(seal["authorization"], "gate:allow")
        _chain_links(ledger)

    def test_denied_call_blocked_before_execute_and_sealed(self):
        runtime = self._approve_all([_turn("Shell", {"command": "rm -rf /"})])
        report = self.drive(runtime)
        self.assertTrue(report.denials, "destructive call was NOT denied")
        self.assertIn("denylist", report.denials[0].reason.lower())

        # Blocked at the authorize gate: no assess, no audit, no execution --
        # but the denial itself is sealed twice (gate audit + runner trail).
        safr = runtime._governed_runner._safr
        stats = safr.stats()
        self.assertEqual(stats["declarations"], 1)
        self.assertEqual(stats["authorizations"], 1)
        self.assertEqual(stats["assessments"], 0)
        self.assertEqual(stats["audits"], 0)

        ledger = runtime.sealed_ledger
        intents = _intents(ledger)
        self.assertIn("permission-permission.deny", intents)
        seal = [
            dict(r.event)
            for r in ledger._records
            if dict(r.event)["intent"] == "governed-action"
        ][0]
        self.assertEqual(seal["outcome"], "denied:authorize")
        self.assertEqual(seal["authorization"], "gate:deny")
        _chain_links(ledger)

    def test_observer_blocks_tampered_arguments(self):
        """The assess gate is real: mismatched args -> deny, sealed."""

        class _Decision:
            allowed = True
            reason = "host approved"

        runner = GovernedActionRunner(
            safr=__import__("safr_checkpoint", fromlist=["SafrCheckpoint"]).SafrCheckpoint(),
            gate=__import__("permissions", fromlist=["PermissionEngine"]).PermissionEngine(),
            observer=__import__(
                "observer_verdict_ledger", fromlist=["ObserverVerdictLedger"]
            ).ObserverVerdictLedger(),
            ledger=__import__(
                "forward_seal_ledger", fromlist=["ForwardSealLedger"]
            ).ForwardSealLedger(b"0" * 32, b"1" * 32),
            executor=lambda tool, args: "ran",
        )
        pin = GovernedActionRunner.pin
        authorized = pin({"tool": "Write", "args": {"path": "a.txt"}})
        # Args at assess time differ from authorize time.
        outcome = runner.run(
            intent="t",
            action="Write",
            subject="s",
            tool="Write",
            tool_args={"path": "b.txt"},
            decision=_Decision(),
            authorized_inputs_digest=authorized,
        )
        self.assertFalse(outcome.executed)
        self.assertEqual(outcome.gate, "assess")
        self.assertIn("changed between authorize and assess", outcome.reason)

    def test_child_runtime_shares_parent_sealed_chain(self):
        from loop import _RunState

        runtime = self._approve_all([_turn("Read", {"path": "note.txt"})])
        (Path(runtime.config.workspace) / "note.txt").write_text("hello")
        self.drive(runtime)
        parent_len = len(runtime.sealed_ledger._records)

        child, _, _ = runtime._child_runtime(
            runtime.agents.get("general"),
            runtime.provider,
            _RunState(session_id=runtime.session_id),
        )
        self.assertIs(child.sealed_ledger, runtime.sealed_ledger)
        self.assertGreaterEqual(len(child.sealed_ledger._records), parent_len)


if __name__ == "__main__":
    unittest.main()
