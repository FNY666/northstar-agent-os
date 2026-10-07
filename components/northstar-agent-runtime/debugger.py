"""Delve-style debugger interface as a deterministic state machine.

Research motivation: a governed agent fleet needs *inspectable*
execution, not just audit logs. Delve (Go), gdb, and lldb all answer the
same three questions -- "where can I stop?" (breakpoints), "what happens
next?" (step), and "what is the state here?" (inspect). This module
implements that contract as a deterministic, single-host *session
ledger*: the host reports a program (functions of simple instructions),
and the module books breakpoint hits, stepping decisions, and variable
inspection with digest-pinned records.

Public API:

- ``Debugger`` -- RLock-guarded session:
  ``load_program(functions, entry, seq)`` loads a host-reported program;
  ``breakpoint(func, line, seq, condition=None)`` sets a breakpoint
  (optional host-supplied predicate over the frame's locals);
  ``remove_breakpoint(bp_id, seq)`` / ``list_breakpoints()`` manage them;
  ``continue_execution(seq)`` runs to the next breakpoint or program end;
  ``step_into`` / ``step_over`` / ``step_out`` implement Delve's
  ``step`` / ``next`` / ``stepout``;
  ``inspect(seq)`` snapshots the current frame's locals;
  ``backtrace(seq)`` lists the call stack;
  ``set_local(name, value, seq)`` implements Delve's ``set``.
- ``Instruction`` -- frozen instruction record: ``func``, ``line``,
  ``op`` (``"call"`` / ``"assign"`` / ``"return"`` / ``"nop"``), plus
  ``target`` (callee), ``name``/``value`` (assignment).
- ``debugger_audit_event(kind, seq, detail=None)`` --
  ``audit.ndjson/1``-shaped record, fixed kind vocabulary.

Execution semantics (documented, deterministic):

- Instructions execute in order; ``call`` pushes a frame, ``return``
  pops it (falling off a function's end is an implicit return).
- ``step_into`` executes one instruction, descending into calls;
  ``step_over`` runs a call to completion without descending;
  ``step_out`` runs until the current frame returns.
- Breakpoints are checked on every position *entered* during execution
  (gdb/Delve semantics: a ``continue`` from a breakpointed line does not
  immediately re-hit it). A condition predicate must return a real
  ``bool`` or the hit is refused fail-closed with ``ConditionError``.
- ``continue_execution`` is bounded by ``max_steps`` (default 100_000):
  an unbounded loop is refused fail-closed with ``StepLimitError``
  rather than hanging the host.

Honest scope:

- The program is *host-reported*: this module simulates execution of the
  reported instructions; it cannot observe a real process, attach to a
  PID, or prove the reported program matches any real binary. A
  breakpoint "hit" means "the simulated cursor entered this line".
- Breakpoint conditions are host-supplied callables; their code is not
  digest-pinned (only ``(id, func, line, enabled)`` is). A lying
  condition poisons only its own breakpoint.
- ``inspect`` snapshots *reported* locals; ``set_local`` mutates the
  simulated frame only. Nothing here changes a real process.
- Values are canonicalizable scalars/containers only (NaN/inf and
  ``>2**53`` integral floats refused -- the same JCS float-loss caveat
  as the rest of the batch line); bool is distinct from int in digests.

Version pin: ``debugger.v1`` / schema pin ``northstar.debugger.v1``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

#: Module version.
DEBUGGER_VERSION = "debugger.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.debugger.v1"

#: Version pin carried inside audit records.
AUDIT_FORMAT = "audit.ndjson/1"

#: Instruction operations.
OP_CALL = "call"
OP_ASSIGN = "assign"
OP_RETURN = "return"
OP_NOP = "nop"
_OPS = frozenset({OP_CALL, OP_ASSIGN, OP_RETURN, OP_NOP})

#: Stop reasons reported by continue/step.
STOP_BREAKPOINT = "breakpoint"
STOP_END = "end"
STOP_STEP = "step"

#: Fixed vocabulary for audit event kinds.
_AUDIT_KINDS = frozenset({
    "program-loaded",
    "breakpoint-set",
    "breakpoint-removed",
    "continued",
    "stepped",
    "stepped-over",
    "stepped-out",
    "inspected",
    "backtraced",
    "local-set",
    "rejected",
})

_MAX_INT = 2**53
_DEFAULT_MAX_STEPS = 100_000


class DebuggerError(Exception):
    """Base error for the debugger module."""


class ProgramError(DebuggerError):
    """The reported program is malformed."""


class BreakpointError(DebuggerError):
    """Breakpoint definition or management failed."""


class UnknownBreakpointError(BreakpointError):
    """No breakpoint with that id."""


class ConditionError(BreakpointError):
    """A breakpoint condition did not return a real bool."""


class ExecutionError(DebuggerError):
    """Stepping/continuing is impossible in the current state."""


class StepLimitError(ExecutionError):
    """continue/step_over/step_out exceeded its step budget."""


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _check_name(what: str, value: object, max_len: int = 256) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise TypeError(f"{what} must be str, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{what} must be non-empty")
    if len(value) > max_len:
        raise ValueError(f"{what} exceeds {max_len} chars")
    return value


def _check_line(line: object) -> int:
    if isinstance(line, bool) or not isinstance(line, int):
        raise TypeError(f"line must be int, got {type(line).__name__}")
    if line <= 0:
        raise ValueError("line must be positive")
    return line


def _check_value(value: Any) -> Any:
    """Validate a local value: canonicalizable scalars/containers only."""
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if abs(value) > _MAX_INT:
            raise ValueError(f"int magnitude exceeds 2**53: {value!r}")
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("NaN/inf values refused")
        if value.is_integer() and abs(value) > _MAX_INT:
            raise ValueError(f"integral float magnitude exceeds 2**53: {value!r}")
        return value
    if isinstance(value, (list, tuple)):
        return [_check_value(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, bool) or not isinstance(k, str):
                raise TypeError("dict keys must be str")
            out[k] = _check_value(v)
        return out
    raise TypeError(f"value type not canonicalizable: {type(value).__name__}")


def _tagged(value: Any) -> Any:
    """Type-tagged encoding so bool != int != float in digests."""
    if value is None:
        return ["n"]
    if isinstance(value, bool):
        return ["b", value]
    if isinstance(value, int):
        return ["i", value]
    if isinstance(value, float):
        return ["f", repr(value)]
    if isinstance(value, str):
        return ["s", value]
    if isinstance(value, (list, tuple)):
        return ["l", [_tagged(v) for v in value]]
    if isinstance(value, dict):
        return ["m", [[k, _tagged(value[k])] for k in sorted(value)]]
    raise TypeError(f"cannot tag {type(value).__name__}")


def _digest(body: Any) -> str:
    blob = json.dumps(_tagged(body), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True)
class Instruction:
    """One frozen instruction: func, line, op, and op operands."""

    func: str
    line: int
    op: str
    target: str = ""
    name: str = ""
    value: Any = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "func", _check_name("func", self.func))
        object.__setattr__(self, "line", _check_line(self.line))
        if self.op not in _OPS:
            raise ValueError(f"op must be one of {sorted(_OPS)}, got {self.op!r}")
        if self.op == OP_CALL:
            _check_name("target", self.target)
        if self.op == OP_ASSIGN:
            _check_name("name", self.name)
            object.__setattr__(self, "value", _check_value(copy.deepcopy(self.value)))

    def as_dict(self) -> dict:
        return {
            "func": self.func,
            "line": self.line,
            "op": self.op,
            "target": self.target,
            "name": self.name,
            "value": copy.deepcopy(self.value),
            "version": DEBUGGER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class Breakpoint:
    """A frozen breakpoint: id, location, enabled flag, hit count."""

    bp_id: str
    func: str
    line: int
    enabled: bool
    hit_count: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "bp_id": self.bp_id,
            "func": self.func,
            "line": self.line,
            "enabled": self.enabled,
            "hit_count": self.hit_count,
            "digest": self.digest,
            "version": DEBUGGER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class FrameView:
    """A frozen view of one call-stack frame."""

    func: str
    line: Optional[int]
    depth: int

    def as_dict(self) -> dict:
        return {"func": self.func, "line": self.line, "depth": self.depth}


@dataclass(frozen=True)
class StepReport:
    """Frozen report of one step/continue landing."""

    kind: str  # "into" | "over" | "out" | "continue"
    func: Optional[str]
    line: Optional[int]
    stop_reason: str  # STOP_BREAKPOINT | STOP_END | STOP_STEP
    breakpoint_id: Optional[str]
    finished: bool
    digest: str

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "func": self.func,
            "line": self.line,
            "stop_reason": self.stop_reason,
            "breakpoint_id": self.breakpoint_id,
            "finished": self.finished,
            "digest": self.digest,
            "version": DEBUGGER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class InspectReport:
    """Frozen snapshot of the current frame's locals."""

    func: Optional[str]
    line: Optional[int]
    locals: Dict[str, Any]
    depth: int
    finished: bool
    digest: str

    def as_dict(self) -> dict:
        return {
            "func": self.func,
            "line": self.line,
            "locals": copy.deepcopy(self.locals),
            "depth": self.depth,
            "finished": self.finished,
            "digest": self.digest,
            "version": DEBUGGER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class LoadReport:
    """Frozen report of a program load."""

    entry: str
    functions: Tuple[str, ...]
    instruction_count: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "entry": self.entry,
            "functions": list(self.functions),
            "instruction_count": self.instruction_count,
            "digest": self.digest,
            "version": DEBUGGER_VERSION,
            "schema": SCHEMA_PIN,
        }


class _Frame:
    """Mutable execution frame (never exposed directly)."""

    __slots__ = ("func", "ip", "locals")

    def __init__(self, func: str) -> None:
        self.func = func
        self.ip = 0
        self.locals: Dict[str, Any] = {}


class Debugger:
    """Delve-style debugger session over a host-reported program."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._functions: Dict[str, Tuple[Instruction, ...]] = {}
        self._entry = ""
        self._program_digest = ""
        self._stack: List[_Frame] = []
        self._finished = False
        self._breakpoints: Dict[str, dict] = {}
        self._bp_counter = 0

    # -- program loading -------------------------------------------------

    def load_program(self, functions: Mapping[str, Any], entry: str,
                     seq: int) -> LoadReport:
        """Load a host-reported program. ``functions`` maps func name to a
        list of instruction dicts with keys ``line``, ``op``, and the op's
        operands (``target`` for call, ``name``/``value`` for assign)."""
        _check_seq(seq)
        if not isinstance(functions, Mapping):
            raise TypeError("functions must be a mapping")
        if not functions:
            raise ProgramError("program must define at least one function")
        entry = _check_name("entry", entry)
        if entry not in functions:
            raise ProgramError(f"entry {entry!r} not defined")

        parsed: Dict[str, Tuple[Instruction, ...]] = {}
        for fname, raw_ins in functions.items():
            fname = _check_name("function", fname)
            if not isinstance(raw_ins, (list, tuple)) or not raw_ins:
                raise ProgramError(f"function {fname!r} needs a non-empty instruction list")
            ins: List[Instruction] = []
            seen_lines = set()
            for raw in raw_ins:
                if not isinstance(raw, Mapping):
                    raise ProgramError(f"instruction in {fname!r} must be a mapping")
                try:
                    instruction = Instruction(
                        func=fname,
                        line=raw["line"],
                        op=raw["op"],
                        target=raw.get("target", ""),
                        name=raw.get("name", ""),
                        value=raw.get("value"),
                    )
                except (TypeError, ValueError, KeyError) as exc:
                    raise ProgramError(f"bad instruction in {fname!r}: {exc}") from exc
                if instruction.line in seen_lines:
                    raise ProgramError(
                        f"duplicate line {instruction.line} in {fname!r}")
                seen_lines.add(instruction.line)
                ins.append(instruction)
            parsed[fname] = tuple(ins)

        # call targets must resolve
        for fname, ins in parsed.items():
            for instruction in ins:
                if instruction.op == OP_CALL and instruction.target not in parsed:
                    raise ProgramError(
                        f"call to unknown function {instruction.target!r} in {fname!r}")

        with self._lock:
            self._functions = parsed
            self._entry = entry
            self._stack = [_Frame(entry)]
            self._finished = False
            self._breakpoints = {}
            self._bp_counter = 0
            body = {f: [i.as_dict() for i in ins] for f, ins in parsed.items()}
            self._program_digest = _digest([entry, body])
            count = sum(len(ins) for ins in parsed.values())
            return LoadReport(entry=entry,
                              functions=tuple(sorted(parsed)),
                              instruction_count=count,
                              digest=self._program_digest)

    # -- breakpoints -----------------------------------------------------

    def breakpoint(self, func: str, line: int, seq: int,
                   condition: Optional[Callable[[Mapping[str, Any]], bool]] = None
                   ) -> Breakpoint:
        """Set a breakpoint at (func, line). ``condition`` is a host-supplied
        predicate over the frame's locals; it must return a real bool."""
        _check_seq(seq)
        func = _check_name("func", func)
        line = _check_line(line)
        if condition is not None and not callable(condition):
            raise TypeError("condition must be callable or None")
        with self._lock:
            self._require_program()
            if func not in self._functions:
                raise BreakpointError(f"unknown function {func!r}")
            if not any(i.line == line for i in self._functions[func]):
                raise BreakpointError(f"no instruction at {func}:{line}")
            self._bp_counter += 1
            bp_id = f"bp-{self._bp_counter}"
            self._breakpoints[bp_id] = {
                "func": func, "line": line, "enabled": True,
                "hit_count": 0, "condition": condition,
            }
            return self._breakpoint_record(bp_id)

    def remove_breakpoint(self, bp_id: str, seq: int) -> None:
        _check_seq(seq)
        bp_id = _check_name("bp_id", bp_id)
        with self._lock:
            if bp_id not in self._breakpoints:
                raise UnknownBreakpointError(f"unknown breakpoint {bp_id!r}")
            del self._breakpoints[bp_id]

    def list_breakpoints(self) -> Tuple[Breakpoint, ...]:
        with self._lock:
            return tuple(self._breakpoint_record(bp_id)
                         for bp_id in sorted(self._breakpoints))

    def _breakpoint_record(self, bp_id: str) -> Breakpoint:
        bp = self._breakpoints[bp_id]
        digest = _digest([bp_id, bp["func"], bp["line"], bp["enabled"]])
        return Breakpoint(bp_id=bp_id, func=bp["func"], line=bp["line"],
                          enabled=bp["enabled"], hit_count=bp["hit_count"],
                          digest=digest)

    def _check_breakpoint(self, func: str, line: int,
                          locals_view: Mapping[str, Any]) -> Optional[str]:
        """Return the id of a breakpoint hit at (func, line), or None."""
        for bp_id in sorted(self._breakpoints):
            bp = self._breakpoints[bp_id]
            if not bp["enabled"] or bp["func"] != func or bp["line"] != line:
                continue
            cond = bp["condition"]
            if cond is not None:
                verdict = cond(locals_view)
                if isinstance(verdict, bool):
                    if not verdict:
                        continue
                else:
                    raise ConditionError(
                        f"condition for {bp_id} must return bool, "
                        f"got {type(verdict).__name__}")
            bp["hit_count"] += 1
            return bp_id
        return None

    # -- execution -------------------------------------------------------

    def _require_program(self) -> None:
        if not self._functions:
            raise ExecutionError("no program loaded")

    def _require_running(self) -> None:
        self._require_program()
        if self._finished:
            raise ExecutionError("program has finished")

    def _position(self) -> Tuple[Optional[str], Optional[int]]:
        if self._finished or not self._stack:
            return None, None
        frame = self._stack[-1]
        ins = self._functions[frame.func]
        if frame.ip >= len(ins):
            return frame.func, None
        return frame.func, ins[frame.ip].line

    def _execute_one(self) -> None:
        """Execute the current instruction, advancing the cursor."""
        frame = self._stack[-1]
        ins = self._functions[frame.func]
        if frame.ip >= len(ins):
            # implicit return: fell off the end
            self._stack.pop()
            if not self._stack:
                self._finished = True
            return
        instruction = ins[frame.ip]
        if instruction.op == OP_NOP:
            frame.ip += 1
        elif instruction.op == OP_ASSIGN:
            frame.locals[instruction.name] = copy.deepcopy(instruction.value)
            frame.ip += 1
        elif instruction.op == OP_CALL:
            frame.ip += 1
            self._stack.append(_Frame(instruction.target))
        elif instruction.op == OP_RETURN:
            self._stack.pop()
            if not self._stack:
                self._finished = True
        # locals_view for breakpoint checks is taken by the caller

    def _run_until(self, stop_at_frame_depth: Optional[int],
                   max_steps: int) -> StepReport:
        """Run until a breakpoint hits, the program ends, or the frame
        depth drops to ``stop_at_frame_depth`` (for step_out)."""
        if max_steps <= 0:
            raise ValueError("max_steps must be positive")
        steps = 0
        while True:
            if steps >= max_steps:
                raise StepLimitError(
                    f"exceeded {max_steps} steps without stopping")
            steps += 1
            self._execute_one()
            if self._finished:
                return self._report("continue", STOP_END, None, True)
            if (stop_at_frame_depth is not None
                    and len(self._stack) <= stop_at_frame_depth):
                return self._report("continue", STOP_STEP, None, False)
            func, line = self._position()
            hit = self._check_breakpoint(func, line, self._stack[-1].locals)
            if hit is not None:
                return self._report("continue", STOP_BREAKPOINT, hit, False)

    def _report(self, kind: str, stop_reason: str,
                breakpoint_id: Optional[str], finished: bool) -> StepReport:
        func, line = self._position()
        digest = _digest([kind, func, line, stop_reason, breakpoint_id, finished])
        return StepReport(kind=kind, func=func, line=line,
                          stop_reason=stop_reason, breakpoint_id=breakpoint_id,
                          finished=finished, digest=digest)

    def continue_execution(self, seq: int,
                           max_steps: int = _DEFAULT_MAX_STEPS) -> StepReport:
        """Run until the next breakpoint hit or program end."""
        _check_seq(seq)
        with self._lock:
            self._require_running()
            return self._run_until(None, max_steps)

    def step_into(self, seq: int) -> StepReport:
        """Delve ``step``: execute one instruction, descending into calls."""
        _check_seq(seq)
        with self._lock:
            self._require_running()
            self._execute_one()
            if self._finished:
                return self._report("into", STOP_END, None, True)
            func, line = self._position()
            hit = self._check_breakpoint(func, line, self._stack[-1].locals)
            reason = STOP_BREAKPOINT if hit else STOP_STEP
            return self._report("into", reason, hit, False)

    def step_over(self, seq: int,
                  max_steps: int = _DEFAULT_MAX_STEPS) -> StepReport:
        """Delve ``next``: execute one instruction; calls run to completion
        (breakpoints inside are still honored, gdb/Delve semantics)."""
        _check_seq(seq)
        with self._lock:
            self._require_running()
            frame = self._stack[-1]
            ins = self._functions[frame.func]
            depth = len(self._stack)
            if frame.ip < len(ins) and ins[frame.ip].op == OP_CALL:
                self._execute_one()  # descend
                if self._finished:
                    return self._report("over", STOP_END, None, True)
                report = self._run_until(depth, max_steps)
                return StepReport(kind="over", func=report.func, line=report.line,
                                  stop_reason=report.stop_reason,
                                  breakpoint_id=report.breakpoint_id,
                                  finished=report.finished,
                                  digest=_digest(["over", report.digest]))
            self._execute_one()
            if self._finished:
                return self._report("over", STOP_END, None, True)
            func, line = self._position()
            hit = self._check_breakpoint(func, line, self._stack[-1].locals)
            reason = STOP_BREAKPOINT if hit else STOP_STEP
            return self._report("over", reason, hit, False)

    def step_out(self, seq: int,
                 max_steps: int = _DEFAULT_MAX_STEPS) -> StepReport:
        """Delve ``stepout``: run until the current frame returns."""
        _check_seq(seq)
        with self._lock:
            self._require_running()
            if len(self._stack) < 2:
                raise ExecutionError("step_out needs a nested frame")
            target_depth = len(self._stack) - 1
            report = self._run_until(target_depth, max_steps)
            return StepReport(kind="out", func=report.func, line=report.line,
                              stop_reason=report.stop_reason,
                              breakpoint_id=report.breakpoint_id,
                              finished=report.finished,
                              digest=_digest(["out", report.digest]))

    # -- inspection ------------------------------------------------------

    def inspect(self, seq: int) -> InspectReport:
        """Snapshot the current frame: func, line, locals, stack depth."""
        _check_seq(seq)
        with self._lock:
            self._require_program()
            if self._finished or not self._stack:
                digest = _digest(["inspect", None, None, {}, 0, True])
                return InspectReport(func=None, line=None, locals={}, depth=0,
                                     finished=True, digest=digest)
            frame = self._stack[-1]
            func, line = self._position()
            locals_copy = copy.deepcopy(frame.locals)
            depth = len(self._stack)
            digest = _digest(["inspect", func, line, locals_copy, depth, False])
            return InspectReport(func=func, line=line, locals=locals_copy,
                                 depth=depth, finished=False, digest=digest)

    def backtrace(self, seq: int) -> Tuple[FrameView, ...]:
        """List the call stack, innermost frame last."""
        _check_seq(seq)
        with self._lock:
            self._require_program()
            views = []
            for depth, frame in enumerate(self._stack):
                ins = self._functions[frame.func]
                line = ins[frame.ip].line if frame.ip < len(ins) else None
                views.append(FrameView(func=frame.func, line=line, depth=depth))
            return tuple(views)

    def set_local(self, name: str, value: Any, seq: int) -> InspectReport:
        """Delve ``set``: assign a local in the current frame."""
        _check_seq(seq)
        name = _check_name("name", name)
        value = _check_value(value)
        with self._lock:
            self._require_running()
            self._stack[-1].locals[name] = copy.deepcopy(value)
            return self.inspect(seq)


def debugger_audit_event(kind: str, seq: int,
                         detail: Optional[Mapping[str, Any]] = None) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for a debugger operation."""
    if not isinstance(kind, str) or kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    record = {
        "format": AUDIT_FORMAT,
        "schema": SCHEMA_PIN,
        "kind": kind,
        "seq": _check_seq(seq),
    }
    if detail is not None:
        if not isinstance(detail, Mapping):
            raise TypeError("detail must be a mapping")
        record["detail"] = dict(detail)
    return record


def main() -> None:
    """Self-check: load, breakpoint, continue, inspect, step over/out."""
    dbg = Debugger()
    program = {
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
    report = dbg.load_program(program, "main", 0)
    assert report.entry == "main"
    assert report.instruction_count == 6

    bp = dbg.breakpoint("add", 2, 1)
    assert bp.func == "add" and bp.line == 2 and bp.hit_count == 0

    stopped = dbg.continue_execution(2)
    assert stopped.stop_reason == STOP_BREAKPOINT, stopped
    assert stopped.breakpoint_id == bp.bp_id
    assert (stopped.func, stopped.line) == ("add", 2)

    snap = dbg.inspect(3)
    assert snap.func == "add" and snap.line == 2
    assert snap.locals == {"a": 41}, snap.locals
    assert snap.depth == 2

    out = dbg.step_out(4)
    assert out.kind == "out" and out.stop_reason == STOP_STEP
    assert (out.func, out.line) == ("main", 3), (out.func, out.line)

    # step_over on a call runs the callee without descending
    dbg2 = Debugger()
    dbg2.load_program(program, "main", 0)
    dbg2.step_into(1)  # main:1 assign x
    over = dbg2.step_over(2)  # main:2 call add -> runs to completion
    assert over.kind == "over" and (over.func, over.line) == ("main", 3)
    snap2 = dbg2.inspect(3)
    assert snap2.locals == {"x": 1}, snap2.locals  # callee locals discarded

    end = dbg.continue_execution(5)
    assert end.finished and end.stop_reason == STOP_END
    snap3 = dbg.inspect(6)
    assert snap3.finished and snap3.func is None

    ev = debugger_audit_event("breakpoint-set", 7, {"bp_id": bp.bp_id})
    assert ev["kind"] == "breakpoint-set" and ev["schema"] == SCHEMA_PIN
    print("debugger OK: load, breakpoint, continue, inspect, step over/out")


if __name__ == "__main__":
    main()
