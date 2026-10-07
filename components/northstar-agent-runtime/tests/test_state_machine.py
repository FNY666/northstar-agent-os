"""Tests for state_machine.py (15 required)."""

import ast
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from state_machine import (  # noqa: E402
    STATE_MACHINE_VERSION,
    STATE_MACHINE_SCHEMA,
    AuditKindError,
    BadEventError,
    BadMachineError,
    BadStateError,
    DuplicateMachineError,
    DuplicateTransitionError,
    GuardBlockedError,
    GuardVerdict,
    MachineRecord,
    ResetRecord,
    StateMachine,
    StateMachineError,
    StateView,
    TransitionDefRecord,
    TransitionRecord,
    UnknownGuardError,
    UnknownMachineError,
    UnknownTransitionError,
    main,
    state_machine_audit_event,
)


def _sm():
    sm = StateMachine()
    sm.add_machine("job", "idle", seq=0)
    sm.add_transition("job", "idle", "start", "running", seq=1)
    sm.add_transition("job", "running", "finish", "done", seq=2)
    return sm


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(STATE_MACHINE_VERSION, "state-machine.v1")

    def test_schema_pin(self):
        self.assertEqual(STATE_MACHINE_SCHEMA, "northstar.state-machine.v1")

    def test_stdlib_only(self):
        src = Path(__file__).resolve().parents[1] / "state_machine.py"
        tree = ast.parse(src.read_text())
        allowed = {
            "__future__", "hashlib", "threading", "dataclasses",
            "typing", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name.split(".")[0] for a in node.names]
                if isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module.split(".")[0]]
                for name in names:
                    self.assertIn(name, allowed, f"non-stdlib import: {name}")


class TestMachines(unittest.TestCase):
    def test_add_machine_roundtrip(self):
        sm = StateMachine()
        rec = sm.add_machine("job", "idle", seq=0)
        self.assertIsInstance(rec, MachineRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(sm.state("job", seq=0).state, "idle")
        self.assertEqual(sm.machine_ids(), ("job",))

    def test_duplicate_machine_refused(self):
        sm = _sm()
        with self.assertRaises(DuplicateMachineError):
            sm.add_machine("job", "idle", seq=3)
        # failed mutation consumed its seq: next valid seq is 4
        sm.add_transition("job", "done", "restart", "idle", seq=4)

    def test_bad_machine_id(self):
        sm = StateMachine()
        with self.assertRaises(BadMachineError):
            sm.add_machine("", "idle", seq=0)
        # failed mutation consumed seq 0: next calls need fresh seqs
        with self.assertRaises(BadMachineError):
            sm.add_machine(True, "idle", seq=1)
        with self.assertRaises(BadStateError):
            sm.add_machine("job", "  ", seq=2)
        with self.assertRaises(StateMachineError):
            sm.add_transition("job", "a", "go", "b", seq=3)


class TestTransitions(unittest.TestCase):
    def test_transition_happy_path(self):
        sm = _sm()
        rec = sm.transition("job", "start", seq=3)
        self.assertIsInstance(rec, TransitionRecord)
        self.assertEqual((rec.from_state, rec.to_state), ("idle", "running"))
        self.assertTrue(rec.verify())
        self.assertEqual(sm.state("job", seq=3).state, "running")
        self.assertEqual(sm.state("job", seq=3).transitions_fired, 1)

    def test_transition_def_roundtrip(self):
        sm = StateMachine()
        sm.add_machine("m", "a", seq=0)
        rec = sm.add_transition("m", "a", "go", "b", seq=1)
        self.assertIsInstance(rec, TransitionDefRecord)
        self.assertTrue(rec.verify())
        with self.assertRaises(DuplicateTransitionError):
            sm.add_transition("m", "a", "go", "b", seq=2)

    def test_unknown_transition_fail_closed(self):
        sm = _sm()
        with self.assertRaises(UnknownTransitionError):
            sm.transition("job", "finish", seq=3)  # not legal from idle
        self.assertEqual(sm.state("job", seq=3).state, "idle")
        rejected = [
            row for row in sm.audit_log()
            if row["kind"] == "state-machine.rejected"
        ]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["error"], "UnknownTransitionError")

    def test_guarded_transition(self):
        sm = _sm()
        sm.register_guard("approved", lambda ctx: bool(ctx.get("approved")))
        sm.add_transition(
            "job", "running", "abort", "aborted", seq=3,
            guard_name="approved",
        )
        sm.transition("job", "start", seq=4)
        with self.assertRaises(GuardBlockedError):
            sm.transition("job", "abort", seq=5)
        rec = sm.transition(
            "job", "abort", seq=6, context={"approved": True}
        )
        self.assertEqual(rec.to_state, "aborted")
        # guard that raises is treated as blocked, not an escape
        sm.register_guard("boom", lambda ctx: 1 / 0)
        sm.add_transition(
            "job", "aborted", "reopen", "running", seq=7,
            guard_name="boom",
        )
        with self.assertRaises(GuardBlockedError):
            sm.transition("job", "reopen", seq=8)

    def test_guard_view_is_data_not_raise(self):
        sm = _sm()
        verdict = sm.guard("job", "start", seq=2)
        self.assertIsInstance(verdict, GuardVerdict)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.reason, "ok")
        no_edge = sm.guard("job", "finish", seq=2)
        self.assertFalse(no_edge.allowed)
        self.assertEqual(no_edge.reason, "no-edge")
        # read purity: seq validated but not consumed
        sm.transition("job", "start", seq=3)
        self.assertEqual(len(sm.audit_log()), 4)

    def test_reset_returns_to_initial(self):
        sm = _sm()
        sm.transition("job", "start", seq=3)
        rec = sm.reset("job", seq=4)
        self.assertIsInstance(rec, ResetRecord)
        self.assertEqual((rec.from_state, rec.to_state), ("running", "idle"))
        self.assertTrue(rec.verify())
        self.assertEqual(sm.state("job", seq=4).state, "idle")
        self.assertEqual(len(sm.history("job")), 1)

    def test_seq_ordering(self):
        sm = _sm()
        with self.assertRaises(Exception):
            sm.transition("job", "start", seq=2)  # rewind
        with self.assertRaises(Exception):
            sm.transition("job", "start", seq=True)  # bool != int


class TestAudit(unittest.TestCase):
    def test_audit_shapes_and_bad_kind(self):
        rows = _sm().audit_log()
        kinds = {row["kind"] for row in rows}
        self.assertEqual(
            kinds,
            {
                "state-machine.machine-added",
                "state-machine.transition-defined",
            },
        )
        for row in rows:
            self.assertEqual(row["audit"], "audit.ndjson/1")
            self.assertNotIn("context", row)
        with self.assertRaises(AuditKindError):
            state_machine_audit_event("nope", {}, 0)

    def test_main_self_check(self):
        proc = subprocess.run(
            [sys.executable, "-c",
             "import state_machine; state_machine.main()"],
            capture_output=True, text=True, timeout=30,
            cwd=str(Path(__file__).resolve().parents[1]),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("state-machine OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
