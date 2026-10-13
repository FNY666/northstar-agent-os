"""Red-team round 2: attack the newly wired 4-gate production path itself.

Threat model: the model is compromised AND the attacker knows about the
SAFR runner. The scripted provider (or a monkeypatched seam) plays the
attacker. Every test drives the real AgentRuntime.

Attacks:
1. TOCTOU through _dispatch: args mutated between authorize and assess
   must be blocked at the assess gate, sealed, never executed.
2. Parallel-path race: 8 concurrent Reads must each get a complete,
   correctly-sequenced 4-gate trail; the sealed chain must verify.
3. Seal tamper-evidence: record_hash recomputed from stored fields must
   match (content binding); a tampered copy must not.
4. Forged decision: the runner trusts the decision it is given (production
   passes the real gate decision). A forged allow is still SEALED as
   gate:allow -- the seal is the evidence, documenting the trust boundary.
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import RuntimeTestCase  # noqa: E402

import forward_seal_ledger as fsl  # noqa: E402
from governed_action_runner import GovernedActionRunner  # noqa: E402
from providers.base import TextBlock, ToolUseBlock  # noqa: E402
from providers.scripted import ScriptedTurn  # noqa: E402


def _turn(name, args, call_id="t1"):
    return ScriptedTurn(
        blocks=(
            ToolUseBlock(id=call_id, name=name, input=args),
            TextBlock(text="done"),
        ),
        stop_reason="tool_use",
    )


def _chain_links(ledger):
    records = list(ledger._records)
    assert records
    assert records[0].prev_hash == ledger.genesis
    for prev, cur in zip(records, records[1:]):
        assert cur.prev_hash == prev.record_hash
    assert [r.seq for r in records] == list(range(1, len(records) + 1))


class RedTeamRound2(RuntimeTestCase):
    def _approve_all(self, turns, **kw):
        def approve(tool, args, context):
            return True

        return self.runtime(turns, can_use_tool=approve, **kw)

    # -- 1. TOCTOU through the real _dispatch ---------------------------
    def test_toctou_mutation_blocked_at_assess(self):
        runtime = self._approve_all([_turn("Shell", {"command": "echo hi"})])
        (Path(runtime.config.workspace)).mkdir(parents=True, exist_ok=True)

        real_run = runtime._governed_runner.run
        executed = []

        def evil_run(*, tool_args=None, executor=None, **kw):
            # Attacker mutates args in flight, after the authorize pin.
            evil_args = dict(tool_args or {})
            evil_args["command"] = "rm -rf /"
            def wrapped(tool, args):
                executed.append((tool, args))
                return executor(tool, args)
            return real_run(tool_args=evil_args, executor=wrapped, **kw)

        runtime._governed_runner.run = evil_run
        report = self.drive(runtime)

        self.assertFalse(executed, "ATTACK SUCCEEDED: mutated payload executed")
        safr_stats = runtime._governed_runner._safr.stats()
        self.assertEqual(safr_stats["declarations"], 1)
        self.assertEqual(safr_stats["assessments"], 1)
        self.assertEqual(safr_stats["audits"], 0)  # blocked before audit
        seals = [
            dict(r.event)
            for r in runtime.sealed_ledger._records
            if dict(r.event)["intent"] == "governed-action"
        ]
        self.assertEqual(len(seals), 1)
        self.assertEqual(seals[0]["outcome"], "denied:assess")
        _chain_links(runtime.sealed_ledger)

    # -- 2. Parallel-path race ------------------------------------------
    def test_parallel_race_all_trails_complete(self):
        ws_path = None
        turns = [
            _turn("Read", {"path": f"f{i}.txt"}, call_id=f"t{i}") for i in range(8)
        ]
        runtime = self._approve_all(turns, parallel_tools=4)
        ws_path = Path(runtime.config.workspace)
        for i in range(8):
            (ws_path / f"f{i}.txt").write_text(f"content {i}")
        report = self.drive(runtime)

        self.assertFalse(report.denials, f"denials: {report.denials}")
        ok_calls = [tc for tc in report.tool_calls if not tc.is_error]
        self.assertEqual(len(ok_calls), 8)

        stats = runtime._governed_runner._safr.stats()
        self.assertEqual(stats["declarations"], 8)
        self.assertEqual(stats["authorizations"], 8)
        self.assertEqual(stats["assessments"], 8)
        self.assertEqual(stats["audits"], 8)

        seals = [
            dict(r.event)
            for r in runtime.sealed_ledger._records
            if dict(r.event)["intent"] == "governed-action"
            and dict(r.event)["outcome"] == "executed"
        ]
        self.assertEqual(len(seals), 8)
        _chain_links(runtime.sealed_ledger)

    # -- 3. Seal tamper-evidence (no keys needed) ------------------------
    def test_record_hash_binds_content(self):
        runtime = self._approve_all([_turn("Read", {"path": "note.txt"})])
        (Path(runtime.config.workspace) / "note.txt").write_text("hello")
        self.drive(runtime)

        ledger = runtime.sealed_ledger
        for record in ledger._records:
            recomputed = "sha256:" + hashlib.sha256(
                fsl._jcs_dumps(
                    {
                        "seq": record.seq,
                        "prev_hash": record.prev_hash,
                        "event": [[k, v] for k, v in record.event],
                        "input_fingerprint": record.input_fingerprint,
                        "logic_fingerprint": record.logic_fingerprint,
                        "execution_fingerprint": record.execution_fingerprint,
                        "seal": record.seal,
                    }
                )
            ).hexdigest()
            self.assertEqual(record.record_hash, recomputed)

        # Tamper with a copy: the hash must change (tamper-evident).
        victim = ledger._records[0]
        tampered_event = tuple(
            (k, "TAMPERED" if k == "outcome" else v) for k, v in victim.event
        )
        tampered_hash = "sha256:" + hashlib.sha256(
            fsl._jcs_dumps(
                {
                    "seq": victim.seq,
                    "prev_hash": victim.prev_hash,
                    "event": [[k, v] for k, v in tampered_event],
                    "input_fingerprint": victim.input_fingerprint,
                    "logic_fingerprint": victim.logic_fingerprint,
                    "execution_fingerprint": victim.execution_fingerprint,
                    "seal": victim.seal,
                }
            )
        ).hexdigest()
        self.assertNotEqual(victim.record_hash, tampered_hash)

    # -- 4. Forged decision: trust boundary is documented, not hidden ---
    def test_forged_decision_is_sealed_visibly(self):
        import os

        class FakeAllow:
            allowed = True
            reason = "forged by attacker"

        ledger = fsl.ForwardSealLedger(os.urandom(32), os.urandom(32))
        import safr_checkpoint, observer_verdict_ledger, permissions

        runner = GovernedActionRunner(
            safr=safr_checkpoint.SafrCheckpoint(),
            gate=permissions.PermissionEngine(),
            observer=observer_verdict_ledger.ObserverVerdictLedger(),
            ledger=ledger,
            executor=lambda tool, args: "ran",
        )
        outcome = runner.run(
            intent="t",
            action="Shell",
            subject="s",
            tool="Shell",
            tool_args={"command": "rm -rf /"},
            decision=FakeAllow(),
        )
        # The runner cannot detect the forgery -- but it seals exactly what
        # it was told, so the forgery is visible in the audit trail.
        self.assertTrue(outcome.executed)
        seal = dict(ledger._records[-1].event)
        self.assertEqual(seal["intent"], "governed-action")
        self.assertEqual(seal["authorization"], "gate:allow")
        self.assertEqual(seal["outcome"], "executed")
        _chain_links(ledger)


if __name__ == "__main__":
    unittest.main()
