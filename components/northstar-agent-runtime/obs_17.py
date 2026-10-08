"""obs_17: eBPF profiling (mock data format), Simulated.

MockEBPFProfiler pretends to attach a kprobe/uprope-style probe and
aggregates folded stacks produced by a caller-provided generator
function, counting how often each stack and each function was sampled.
Mock: no eBPF program is compiled or attached; stacks come from the
caller's generator, so all numbers are simulated.

Fail-closed: collecting before attach, double attach, or invalid
generators/frame data raise.
Stdlib only.
"""

from __future__ import annotations

import ast
from collections import Counter
from typing import Callable, Dict, List, Optional, Tuple

OBS17_VERSION = "obs-17.v1"
SCHEMA_PIN = "northstar.obs-17.v1"


class Obs17Error(Exception):
    """Fail-closed."""


StackGenerator = Callable[[], List[str]]


class MockEBPFProfiler:
    """Simulated eBPF-style stack sampler."""

    def __init__(self) -> None:
        self._probe: Optional[str] = None
        self._stack_counts: Counter = Counter()
        self._func_counts: Counter = Counter()

    @property
    def probe(self) -> Optional[str]:
        return self._probe

    def attach(self, probe_name: str) -> None:
        """Attach the (mock) probe.  Raises if already attached."""
        if not isinstance(probe_name, str) or not probe_name.strip():
            raise Obs17Error("probe_name must be non-empty str")
        if self._probe is not None:
            raise Obs17Error(f"already attached to '{self._probe}'")
        self._probe = probe_name.strip()

    def detach(self) -> None:
        """Detach the probe.  Raises if nothing is attached."""
        if self._probe is None:
            raise Obs17Error("not attached")
        self._probe = None

    def collect(self, stack_generator: StackGenerator, n: int) -> Dict:
        """Sample n stacks from stack_generator and aggregate them.

        stack_generator() must return a non-empty list of frame-name
        strings on each call.
        """
        if self._probe is None:
            raise Obs17Error("cannot collect before attach")
        if not callable(stack_generator):
            raise Obs17Error("stack_generator must be callable")
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            raise Obs17Error("n must be positive int")
        for _ in range(n):
            stack = stack_generator()
            if not isinstance(stack, list) or not stack:
                raise Obs17Error("generator must return non-empty list of frames")
            for f in stack:
                if not isinstance(f, str) or not f or ";" in f:
                    raise Obs17Error("frames must be non-empty strings without ';'")
            self._stack_counts[";".join(stack)] += 1
            for f in stack:
                self._func_counts[f] += 1
        return {
            "schema": SCHEMA_PIN,
            "probe": self._probe,
            "samples": n,
            "unique_stacks": len(self._stack_counts),
        }

    def top_functions(self, k: int) -> List[Tuple[str, int]]:
        """Top-k functions by sample count, (func, count) pairs."""
        if isinstance(k, bool) or not isinstance(k, int) or k < 1:
            raise Obs17Error("k must be positive int")
        ranked = sorted(
            self._func_counts.items(), key=lambda kv: (-kv[1], kv[0])
        )
        return ranked[:k]


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    p = MockEBPFProfiler()
    stacks = [
        ["main", "work", "io"],
        ["main", "work", "io"],
        ["main", "idle"],
    ]
    it = iter(stacks)
    p.attach("kprobe:schedule")
    assert p.probe == "kprobe:schedule"
    report = p.collect(lambda: next(it), 3)
    assert report["samples"] == 3 and report["unique_stacks"] == 2
    top = p.top_functions(2)
    assert top == [("main", 3), ("io", 2)], top
    p.detach()
    assert p.probe is None
    try:
        p.collect(lambda: ["x"], 1)
        raise AssertionError("should raise")
    except Obs17Error:
        pass
    try:
        p.attach("")
        raise AssertionError("should raise")
    except Obs17Error:
        pass
    p.attach("uprobe:main")
    try:
        p.attach("uprobe:other")
        raise AssertionError("should raise")
    except Obs17Error:
        pass
    try:
        p.top_functions(0)
        raise AssertionError("should raise")
    except Obs17Error:
        pass
    assert stdlib_only()
    print("obs_17 OK")


if __name__ == "__main__":
    main()
