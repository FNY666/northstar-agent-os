"""Tests for the Temporal/Cadence-shaped execution lifecycle added to
workflow_engine.py: start() / signal() / complete() on WorkflowEngine."""

from __future__ import annotations

import dataclasses
import os
import subprocess
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_COMPONENT_DIR = os.path.dirname(_HERE)
sys.path.insert(0, _COMPONENT_DIR)
import workflow_engine as mod  # noqa: E402


class TestVersion(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(mod.WORKFLOW_ENGINE_VERSION, "workflow-engine.v1")
        self.assertEqual(mod.SCHEMA_PIN, "northstar.workflow-engine.v1")
        self.assertEqual(mod.AUDIT_FORMAT, "audit.ndjson/1")


class TestStart(unittest.TestCase):
    def test_roundtrip(self):
        e = mod.WorkflowEngine()
        rec = e.start("exec-1", "order-flow", 0, input={"order": "o-1"})
        self.assertEqual(rec.execution_id, "exec-1")
        self.assertEqual(rec.workflow_id, "order-flow")
        self.assertEqual(rec.status, "running")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertTrue(rec.input_digest.startswith("sha256:"))
        self.assertEqual(e.status("exec-1"), "running")
        d = rec.as_dict()
        self.assertEqual(d["execution_id"], "exec-1")
        self.assertEqual(d["version"], "workflow-engine.v1")
        self.assertNotIn("input", d)

    def test_no_input(self):
        e = mod.WorkflowEngine()
        rec = e.start("e1", "w1", 5)
        self.assertIsNone(rec.input_digest)

    def test_duplicate_refused(self):
        e = mod.WorkflowEngine()
        e.start("e1", "w1", 0)
        with self.assertRaises(mod.DuplicateExecutionError):
            e.start("e1", "w1", 1)
        # failed mutation consumed its seq: next fresh seq must advance past 1
        with self.assertRaises(mod.WorkflowError):
            e.start("e2", "w1", 1)  # rewind
        e.start("e2", "w1", 2)
        # rejected audit row booked
        kinds = [r["kind"] for r in e.execution_audit_log()]
        self.assertIn("rejected", kinds)

    def test_same_workflow_id_new_execution(self):
        e = mod.WorkflowEngine()
        e.start("e1", "w1", 0)
        e.start("e2", "w1", 1)  # same logical workflow, new run id
        self.assertEqual(e.execution_ids(), ("e1", "e2"))

    def test_bad_inputs(self):
        e = mod.WorkflowEngine()
        with self.assertRaises(mod.WorkflowError):
            e.start("", "w1", 0)
        with self.assertRaises(mod.WorkflowError):
            e.start("e1", "", 1)
        with self.assertRaises(mod.WorkflowError):
            e.start("e1", "w1", True)  # bool seq
        with self.assertRaises(mod.WorkflowError):
            e.start("e1", "w1", "1")  # str seq
        e2 = mod.WorkflowEngine()
        e2.start("e1", "w1", 10)
        with self.assertRaises(mod.WorkflowError):
            e2.start("e2", "w1", 5)  # rewind bare, no consume
        e2.start("e2", "w1", 11)  # proves seq not consumed by rewind

    def test_unpinnable_input_refused(self):
        e = mod.WorkflowEngine()
        with self.assertRaises(mod.ExecutionError):
            e.start("e1", "w1", 0, input=object())

    def test_frozen_record(self):
        e = mod.WorkflowEngine()
        rec = e.start("e1", "w1", 0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            rec.status = "completed"


class TestSignal(unittest.TestCase):
    def test_roundtrip(self):
        e = mod.WorkflowEngine()
        e.start("e1", "w1", 0)
        sig = e.signal("e1", "pause", 1, payload={"by": "op"})
        self.assertEqual(sig.signal_id, "sig-1")
        self.assertEqual(sig.signal_name, "pause")
        self.assertTrue(sig.payload_digest.startswith("sha256:"))
        self.assertTrue(sig.digest.startswith("sha256:"))
        d = sig.as_dict()
        self.assertEqual(d["execution_id"], "e1")
        # raw payload bytes never enter the record
        self.assertNotIn("payload", d)
        self.assertNotIn("op", str(d))
        self.assertEqual(e.signals_for("e1"), (sig,))

    def test_unknown_execution(self):
        e = mod.WorkflowEngine()
        with self.assertRaises(mod.UnknownExecutionError):
            e.signal("nope", "x", 0)
        with self.assertRaises(mod.UnknownExecutionError):
            e.signals_for("nope")

    def test_bad_signal_name(self):
        e = mod.WorkflowEngine()
        e.start("e1", "w1", 0)
        with self.assertRaises(mod.BadSignalError):
            e.signal("e1", "", 1)
        with self.assertRaises(mod.BadSignalError):
            e.signal("e1", "x" * 257, 2)
        with self.assertRaises(mod.BadSignalError):
            e.signal("e1", "ok", 3, payload=object())
        # failed mutations consumed seqs and booked rejections
        self.assertEqual(
            [r["kind"] for r in e.execution_audit_log()].count("rejected"), 3
        )


class TestComplete(unittest.TestCase):
    def test_roundtrip(self):
        e = mod.WorkflowEngine()
        e.start("e1", "w1", 0)
        e.signal("e1", "note", 1)
        comp = e.complete("e1", 2, result={"ok": True})
        self.assertEqual(comp.outcome, "completed")
        self.assertTrue(comp.result_digest.startswith("sha256:"))
        self.assertTrue(comp.digest.startswith("sha256:"))
        self.assertEqual(e.status("e1"), "completed")
        self.assertEqual(
            [r["kind"] for r in e.execution_audit_log()],
            ["execution-started", "signaled", "execution-completed"],
        )

    def test_unknown_execution(self):
        e = mod.WorkflowEngine()
        with self.assertRaises(mod.UnknownExecutionError):
            e.complete("nope", 0)

    def test_terminal_refusals(self):
        e = mod.WorkflowEngine()
        e.start("e1", "w1", 0)
        e.complete("e1", 1)
        with self.assertRaises(mod.TerminalExecutionError):
            e.signal("e1", "late", 2)
        with self.assertRaises(mod.TerminalExecutionError):
            e.complete("e1", 3)
        self.assertEqual(e.status("e1"), "completed")
        self.assertIsNone(e.status("unknown"))
        self.assertIsNone(e.execution("unknown"))


class TestAudit(unittest.TestCase):
    def test_new_kinds(self):
        for kind in ("execution-started", "signaled", "execution-completed"):
            rec = mod.workflow_engine_audit_event(kind, 3, execution_id="e1")
            self.assertEqual(rec["kind"], kind)
            self.assertEqual(rec["execution_id"], "e1")
            self.assertEqual(rec["format"], "audit.ndjson/1")
            self.assertEqual(rec["schema"], mod.SCHEMA_PIN)

    def test_main_runs(self):
        p = subprocess.run(
            [sys.executable, "-m", "workflow_engine"],
            cwd=_COMPONENT_DIR,
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0)
        self.assertIn("start, signal, complete", p.stdout)


if __name__ == "__main__":
    unittest.main()
