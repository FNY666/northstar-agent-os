"""Tests for debugger."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from debugger import (  # noqa: E402
    DEBUGGER_VERSION,
    SCHEMA_PIN,
    STOP_BREAKPOINT,
    STOP_END,
    STOP_STEP,
    Breakpoint,
    BreakpointError,
    ConditionError,
    Debugger,
    DebuggerError,
    ExecutionError,
    Instruction,
    ProgramError,
    StepLimitError,
    UnknownBreakpointError,
    debugger_audit_event,
)


def _program():
    return {
        "main": [
            {"line": 1, "op": "assign", "name": "x", "value": 1},
            {"line": 2, "op": "call", "target": "add"},
            {"line": 3, "op": "assign", "name": "y", "value": 10},
        ],
        "add": [
            {"line": 1, "op": "assign", "name": "a", "value": 41},
            {"line": 2, "op": "nop"},
            {"line": 3, "op": "return"},
        ],
    }


def _loaded():
    dbg = Debugger()
    dbg.load_program(_program(), "main", 0)
    return dbg


class TestPins(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(DEBUGGER_VERSION, "debugger.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.debugger.v1")


class TestFrozen(unittest.TestCase):
    def test_instruction_frozen(self):
        ins = Instruction(func="main", line=1, op="nop")
        with self.assertRaises(Exception):
            ins.op = "assign"  # type: ignore[misc]

    def test_breakpoint_frozen(self):
        dbg = _loaded()
        bp = dbg.breakpoint("main", 1, 1)
        with self.assertRaises(Exception):
            bp.hit_count = 5  # type: ignore[misc]


class TestInstructionValidation(unittest.TestCase):
    def test_bad_op(self):
        with self.assertRaises(ValueError):
            Instruction(func="main", line=1, op="jump")

    def test_call_needs_target(self):
        with self.assertRaises((TypeError, ValueError)):
            Instruction(func="main", line=1, op="call")

    def test_assign_needs_name(self):
        with self.assertRaises((TypeError, ValueError)):
            Instruction(func="main", line=1, op="assign", value=1)

    def test_nan_value_refused(self):
        with self.assertRaises(ValueError):
            Instruction(func="main", line=1, op="assign", name="x",
                        value=float("nan"))

    def test_huge_int_refused(self):
        with self.assertRaises(ValueError):
            Instruction(func="main", line=1, op="assign", name="x",
                        value=2**60)


class TestLoadProgram(unittest.TestCase):
    def test_happy_path(self):
        dbg = Debugger()
        rep = dbg.load_program(_program(), "main", 0)
        self.assertEqual(rep.entry, "main")
        self.assertEqual(rep.instruction_count, 6)
        self.assertEqual(rep.functions, ("add", "main"))

    def test_empty_program(self):
        with self.assertRaises(ProgramError):
            Debugger().load_program({}, "main", 0)

    def test_unknown_entry(self):
        with self.assertRaises(ProgramError):
            Debugger().load_program(_program(), "nope", 0)

    def test_unknown_call_target(self):
        prog = {"main": [{"line": 1, "op": "call", "target": "ghost"}]}
        with self.assertRaises(ProgramError):
            Debugger().load_program(prog, "main", 0)

    def test_duplicate_line(self):
        prog = {"main": [
            {"line": 1, "op": "nop"},
            {"line": 1, "op": "nop"},
        ]}
        with self.assertRaises(ProgramError):
            Debugger().load_program(prog, "main", 0)

    def test_step_before_load(self):
        with self.assertRaises(ExecutionError):
            Debugger().step_into(0)


class TestBreakpoints(unittest.TestCase):
    def test_set_and_list(self):
        dbg = _loaded()
        bp = dbg.breakpoint("main", 2, 1)
        self.assertEqual(bp.bp_id, "bp-1")
        self.assertEqual(bp.func, "main")
        self.assertTrue(bp.enabled)
        self.assertEqual(len(dbg.list_breakpoints()), 1)

    def test_unknown_function(self):
        with self.assertRaises(BreakpointError):
            _loaded().breakpoint("ghost", 1, 1)

    def test_bad_line(self):
        with self.assertRaises(BreakpointError):
            _loaded().breakpoint("main", 99, 1)

    def test_bad_condition_type(self):
        with self.assertRaises(TypeError):
            _loaded().breakpoint("main", 1, 1, condition="x > 1")

    def test_remove(self):
        dbg = _loaded()
        bp = dbg.breakpoint("main", 1, 1)
        dbg.remove_breakpoint(bp.bp_id, 2)
        self.assertEqual(dbg.list_breakpoints(), ())

    def test_remove_unknown(self):
        with self.assertRaises(UnknownBreakpointError):
            _loaded().remove_breakpoint("bp-99", 1)


class TestContinue(unittest.TestCase):
    def test_hits_breakpoint(self):
        dbg = _loaded()
        bp = dbg.breakpoint("add", 2, 1)
        stopped = dbg.continue_execution(2)
        self.assertEqual(stopped.stop_reason, STOP_BREAKPOINT)
        self.assertEqual(stopped.breakpoint_id, bp.bp_id)
        self.assertEqual((stopped.func, stopped.line), ("add", 2))

    def test_runs_to_end(self):
        dbg = _loaded()
        end = dbg.continue_execution(1)
        self.assertTrue(end.finished)
        self.assertEqual(end.stop_reason, STOP_END)
        with self.assertRaises(ExecutionError):
            dbg.continue_execution(2)

    def test_condition_true_and_false(self):
        dbg = _loaded()
        dbg.breakpoint("add", 1, 1, condition=lambda loc: loc.get("a") == 41)
        # condition is False at add:1 (a not yet assigned) -> no stop there
        hit = dbg.breakpoint("main", 3, 2, condition=lambda loc: True)
        stopped = dbg.continue_execution(3)
        self.assertEqual(stopped.breakpoint_id, hit.bp_id)

    def test_condition_non_bool(self):
        dbg = _loaded()
        dbg.breakpoint("main", 3, 1, condition=lambda loc: "yes")
        with self.assertRaises(ConditionError):
            dbg.continue_execution(2)

    def test_step_limit(self):
        prog = {"main": [{"line": 1, "op": "nop"}]}
        # nop loop: falls off end... build a real infinite loop instead
        prog = {"main": [
            {"line": 1, "op": "call", "target": "loop"},
        ], "loop": [
            {"line": 1, "op": "call", "target": "loop"},
        ]}
        dbg = Debugger()
        dbg.load_program(prog, "main", 0)
        with self.assertRaises(StepLimitError):
            dbg.continue_execution(1, max_steps=50)


class TestStep(unittest.TestCase):
    def test_step_into_descends(self):
        dbg = _loaded()
        dbg.step_into(1)  # main:1 assign x
        rep = dbg.step_into(2)  # main:2 call add -> descend
        self.assertEqual((rep.func, rep.line), ("add", 1))
        self.assertEqual(rep.stop_reason, STOP_STEP)

    def test_step_over_skips_call(self):
        dbg = _loaded()
        dbg.step_into(1)
        rep = dbg.step_over(2)
        self.assertEqual(rep.kind, "over")
        self.assertEqual((rep.func, rep.line), ("main", 3))
        snap = dbg.inspect(3)
        self.assertEqual(snap.locals, {"x": 1})  # callee frame discarded

    def test_step_out(self):
        dbg = _loaded()
        dbg.breakpoint("add", 2, 1)
        dbg.continue_execution(2)
        out = dbg.step_out(3)
        self.assertEqual(out.kind, "out")
        self.assertEqual((out.func, out.line), ("main", 3))

    def test_step_out_top_level(self):
        with self.assertRaises(ExecutionError):
            _loaded().step_out(1)

    def test_step_lands_on_breakpoint(self):
        dbg = _loaded()
        bp = dbg.breakpoint("add", 1, 1)
        dbg.step_into(1)  # main:1
        rep = dbg.step_into(2)  # call add -> lands add:1
        self.assertEqual(rep.stop_reason, STOP_BREAKPOINT)
        self.assertEqual(rep.breakpoint_id, bp.bp_id)


class TestInspect(unittest.TestCase):
    def test_inspect_locals(self):
        dbg = _loaded()
        dbg.breakpoint("add", 2, 1)
        dbg.continue_execution(2)
        snap = dbg.inspect(3)
        self.assertEqual(snap.func, "add")
        self.assertEqual(snap.line, 2)
        self.assertEqual(snap.locals, {"a": 41})
        self.assertEqual(snap.depth, 2)
        self.assertFalse(snap.finished)

    def test_inspect_no_aliasing(self):
        dbg = _loaded()
        dbg.step_into(1)
        snap = dbg.inspect(2)
        snap.locals["x"] = 999
        snap2 = dbg.inspect(3)
        self.assertEqual(snap2.locals["x"], 1)

    def test_inspect_finished(self):
        dbg = _loaded()
        dbg.continue_execution(1)
        snap = dbg.inspect(2)
        self.assertTrue(snap.finished)
        self.assertIsNone(snap.func)

    def test_backtrace(self):
        dbg = _loaded()
        dbg.breakpoint("add", 2, 1)
        dbg.continue_execution(2)
        trace = dbg.backtrace(3)
        self.assertEqual([f.func for f in trace], ["main", "add"])
        self.assertEqual([f.depth for f in trace], [0, 1])

    def test_set_local(self):
        dbg = _loaded()
        dbg.step_into(1)
        snap = dbg.set_local("x", 42, 2)
        self.assertEqual(snap.locals["x"], 42)

    def test_set_local_bad_value(self):
        dbg = _loaded()
        with self.assertRaises(ValueError):
            dbg.set_local("x", float("inf"), 1)


class TestAudit(unittest.TestCase):
    def test_shapes(self):
        ev = debugger_audit_event("breakpoint-set", 1, {"bp_id": "bp-1"})
        self.assertEqual(ev["format"], "audit.ndjson/1")
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["detail"], {"bp_id": "bp-1"})

    def test_no_detail(self):
        ev = debugger_audit_event("continued", 0)
        self.assertNotIn("detail", ev)

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            debugger_audit_event("explode", 1)

    def test_bad_seq(self):
        with self.assertRaises((TypeError, ValueError)):
            debugger_audit_event("continued", -1)


class TestHouseStyle(unittest.TestCase):
    def test_stdlib_only(self):
        import ast
        src = Path(__file__).resolve().parent.parent / "debugger.py"
        tree = ast.parse(src.read_text())
        allowed = {"__future__", "copy", "dataclasses", "hashlib", "json",
                   "threading", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)

    def test_main(self):
        from debugger import main
        main()


if __name__ == "__main__":
    unittest.main()
