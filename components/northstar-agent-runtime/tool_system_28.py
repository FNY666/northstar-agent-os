"""Tool composition (advanced): chained pipelines with placeholder refs.

A Composer defines ordered pipeline steps ``(step_name, tool,
args_template)``.  Templates may reference prior step outputs with
``${step_name.field}`` placeholders (dotted paths into nested dicts),
resolved before each step runs.  Referencing a missing step, a later
step, or forming a reference cycle raises CompositionError.

What this IS:
* Simulated pipeline composition over injected executors.

What this IS NOT:
* Not a workflow engine -- no retries, no parallelism, no real tools.
* Placeholder resolution is string substitution over mock outputs.
"""

from __future__ import annotations

import ast
import copy
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Tuple

#: Module version.
TOOL_SYSTEM_28_VERSION = "tool-system-28.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-28.v1"

#: Matches ${step_name.field.path} placeholders.
_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z0-9_.]+)\}")


class ToolSystem28Error(Exception):
    """Fail-closed."""


class CompositionError(ToolSystem28Error):
    """Raised on bad references, cycles, or failed steps."""


class StepFailed(CompositionError):
    """Raised when a step's executor raises."""

    def __init__(self, step: str, cause: BaseException) -> None:
        super().__init__(f"step '{step}' failed: {cause}")
        self.step = step
        self.cause = cause


@dataclass
class Step:
    """One pipeline step (mock)."""

    name: str
    tool: str
    args_template: Dict[str, Any] = field(default_factory=dict)


def _find_refs(value: Any) -> List[Tuple[str, str]]:
    """Collect (step, path) placeholder references in a template value."""
    refs: List[Tuple[str, str]] = []

    def _walk(v: Any) -> None:
        if isinstance(v, str):
            refs.extend(_PLACEHOLDER.findall(v))
        elif isinstance(v, dict):
            for item in v.values():
                _walk(item)
        elif isinstance(v, (list, tuple)):
            for item in v:
                _walk(item)

    _walk(value)
    return refs


def _lookup(outputs: Dict[str, Any], step: str, path: str) -> Any:
    if step not in outputs:
        raise CompositionError(f"unknown step reference '{step}'")
    value: Any = outputs[step]
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            raise CompositionError(
                f"step '{step}' has no field '{path}'"
            )
        value = value[part]
    return value


def _resolve(value: Any, outputs: Dict[str, Any]) -> Any:
    if isinstance(value, str):
        def _sub(match: "re.Match[str]") -> str:
            found = _lookup(outputs, match.group(1), match.group(2))
            return str(found)

        return _PLACEHOLDER.sub(_sub, value)
    if isinstance(value, dict):
        return {k: _resolve(v, outputs) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, outputs) for v in value]
    if isinstance(value, tuple):
        return tuple(_resolve(v, outputs) for v in value)
    return value


class Composer:
    """Chains tool steps with ${step.field} placeholder resolution."""

    def __init__(self) -> None:
        self._steps: List[Step] = []

    def add_step(
        self, name: str, tool: str, args_template: Dict[str, Any]
    ) -> None:
        if not name:
            raise CompositionError("step name required")
        if any(s.name == name for s in self._steps):
            raise CompositionError(f"duplicate step name '{name}'")
        self._steps.append(
            Step(name=name, tool=tool, args_template=args_template)
        )

    def _check_refs(self) -> None:
        """Cycle/forward-ref detection over placeholder references."""
        index = {s.name: i for i, s in enumerate(self._steps)}
        for i, step in enumerate(self._steps):
            for ref_step, _ in _find_refs(step.args_template):
                if ref_step not in index:
                    raise CompositionError(
                        f"step '{step.name}' references missing "
                        f"step '{ref_step}'"
                    )
                if index[ref_step] >= i:
                    raise CompositionError(
                        f"step '{step.name}' references step "
                        f"'{ref_step}' (not yet run / cycle)"
                    )

    def run(
        self, executors: Dict[str, Callable[[Dict[str, Any]], Any]]
    ) -> Dict[str, Any]:
        """Execute steps in order; returns {step_name: output}."""
        self._check_refs()
        outputs: Dict[str, Any] = {}
        for step in self._steps:
            if step.tool not in executors:
                raise CompositionError(
                    f"no executor for tool '{step.tool}'"
                )
            args = _resolve(
                copy.deepcopy(step.args_template), outputs
            )
            try:
                outputs[step.name] = executors[step.tool](args)
            except CompositionError:
                raise
            except Exception as exc:  # noqa: BLE001 - wrapped in StepFailed
                raise StepFailed(step.name, exc) from exc
        return outputs


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "copy", "dataclasses", "pathlib", "re", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    comp = Composer()
    comp.add_step("q", "search", {"query": "agent"})
    comp.add_step(
        "summarize", "summarize", {"text": "${q.top}", "lang": "en"}
    )
    outputs = comp.run(
        {
            "search": lambda args: {"top": f"hit:{args['query']}"},
            "summarize": lambda args: {"summary": args["text"]},
        }
    )
    assert outputs["summarize"] == {"summary": "hit:agent"}
    # Missing step reference.
    bad = Composer()
    bad.add_step("a", "t", {"x": "${ghost.field}"})
    try:
        bad.run({"t": lambda args: {}})
        raise AssertionError("should raise")
    except CompositionError:
        pass
    # Forward reference (cycle-ish).
    cyc = Composer()
    cyc.add_step("a", "t", {"x": "${b.out}"})
    cyc.add_step("b", "t", {"x": "1"})
    try:
        cyc.run({"t": lambda args: {"out": "v"}})
        raise AssertionError("should raise")
    except CompositionError:
        pass
    # Failed step.
    def _boom(args: Dict[str, Any]) -> Any:
        raise RuntimeError("kaput")

    fail = Composer()
    fail.add_step("a", "t", {})
    try:
        fail.run({"t": _boom})
        raise AssertionError("should raise")
    except StepFailed as exc:
        assert exc.step == "a"
    assert stdlib_only()
    print("tool_system_28 OK: compose, placeholders, refs, failures")


if __name__ == "__main__":
    main()
