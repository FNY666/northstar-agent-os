"""Explicit-state model checking for finite protocol graphs.

A :class:`ModelChecker` answers two questions about a finite,
host-described transition system:

* **Safety** -- does any reachable state carry a forbidden atomic
  proposition (``check_safety``)? If so, the check fails closed with a
  counterexample trace from the initial state to the violating state.
* **Liveness** -- from every reachable state, can a "progress"-labelled
  state still be reached (``check_liveness``)? This is the classic
  ``AG AF good`` formulation: if some reachable state is stuck in a
  region with no good state reachable, the run can livelock there and
  the check fails closed with a trace to the stuck state.

Exploration is deterministic breadth-first search with sorted neighbor
order, so the same graph always yields the same verdict and the same
counterexample -- audit replay is exact (no wall-clock, no randomness).

Honest scope: this is explicit-state graph bookkeeping, not a full LTL
model checker. It cannot see states or transitions the host never added
(host-reported model only); it checks one safety invariant (bad labels)
and one liveness shape (``AG AF good``), not arbitrary temporal
formulas; there is no fairness, no partial-order reduction, and no
symbolic representation -- state explosion is the host's problem, the
``states_explored`` count is the honest signal of how far the check
got. A ``holds=True`` verdict means "no violation in the explored
graph", never "the real system is correct".
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple


#: Version pin for this module's record shape.
MODEL_CHECKER_VERSION = "model-checker.v1"

#: Schema pin carried on audit records.
MODEL_CHECKER_SCHEMA = "northstar.model-checker.v1"


class ModelCheckerError(Exception):
    """Base error for model-checker misuse (fail-closed)."""


def _check_id(value: object, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise ModelCheckerError(f"{what} must be a non-empty str, got {value!r}")
    if not value:
        raise ModelCheckerError(f"{what} must be non-empty")
    return value


def _check_labels(labels: object) -> FrozenSet[str]:
    if isinstance(labels, (str, bytes)) or not isinstance(labels, Iterable):
        raise ModelCheckerError("labels must be an iterable of str")
    out = []
    for lab in labels:
        if isinstance(lab, bool) or not isinstance(lab, str) or not lab:
            raise ModelCheckerError(f"label must be a non-empty str, got {lab!r}")
        out.append(lab)
    return frozenset(out)


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return seq


@dataclass(frozen=True)
class Trace:
    """A counterexample path: ordered state ids from the initial state."""

    states: Tuple[str, ...]
    violated: str  # the state (safety) or stuck state (liveness) at the end

    def __post_init__(self) -> None:
        if not isinstance(self.states, tuple) or not self.states:
            raise ModelCheckerError("trace states must be a non-empty tuple")
        for s in self.states:
            _check_id(s, "trace state")
        if self.states[-1] != self.violated:
            raise ModelCheckerError("violated must be the last trace state")

    def as_dict(self) -> dict:
        return {
            "schema": MODEL_CHECKER_SCHEMA,
            "version": MODEL_CHECKER_VERSION,
            "states": list(self.states),
            "violated": self.violated,
        }


@dataclass(frozen=True)
class ExplorationResult:
    """Outcome of :meth:`ModelChecker.explore`."""

    initial: str
    reachable: FrozenSet[str]
    transitions_explored: int
    visit_order: Tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "schema": MODEL_CHECKER_SCHEMA,
            "version": MODEL_CHECKER_VERSION,
            "initial": self.initial,
            "reachable": sorted(self.reachable),
            "transitions_explored": self.transitions_explored,
            "visit_order": list(self.visit_order),
        }


@dataclass(frozen=True)
class SafetyResult:
    """Outcome of :meth:`ModelChecker.check_safety`."""

    holds: bool
    counterexample: Optional[Trace]
    states_explored: int
    bad_labels: Tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "schema": MODEL_CHECKER_SCHEMA,
            "version": MODEL_CHECKER_VERSION,
            "holds": self.holds,
            "counterexample": (
                None if self.counterexample is None else self.counterexample.as_dict()
            ),
            "states_explored": self.states_explored,
            "bad_labels": list(self.bad_labels),
        }


@dataclass(frozen=True)
class LivenessResult:
    """Outcome of :meth:`ModelChecker.check_liveness`."""

    holds: bool
    counterexample: Optional[Trace]
    states_explored: int
    good_labels: Tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "schema": MODEL_CHECKER_SCHEMA,
            "version": MODEL_CHECKER_VERSION,
            "holds": self.holds,
            "counterexample": (
                None if self.counterexample is None else self.counterexample.as_dict()
            ),
            "states_explored": self.states_explored,
            "good_labels": list(self.good_labels),
        }


class ModelChecker:
    """Finite explicit-state model checker (host-described graph)."""

    def __init__(self) -> None:
        self._labels: Dict[str, FrozenSet[str]] = {}
        self._edges: Dict[str, List[Tuple[str, str]]] = {}
        self._initial: Optional[str] = None

    # -- graph construction -------------------------------------------------

    def add_state(
        self, state_id: str, labels: Iterable[str] = (), initial: bool = False
    ) -> str:
        """Register a state with atomic-proposition labels.

        ``initial=True`` marks the start state; at most one initial state
        is allowed. Returns the state id.
        """
        sid = _check_id(state_id, "state_id")
        labs = _check_labels(labels)
        if not isinstance(initial, bool):
            raise ModelCheckerError("initial must be a bool")
        if sid in self._labels:
            raise ModelCheckerError(f"duplicate state {sid!r}")
        if initial:
            if self._initial is not None:
                raise ModelCheckerError("initial state already set")
            self._initial = sid
        self._labels[sid] = labs
        self._edges.setdefault(sid, [])
        return sid

    def add_transition(self, src: str, dst: str, action: str = "") -> None:
        """Add a labelled transition ``src -> dst`` (idempotent)."""
        s = _check_id(src, "src")
        d = _check_id(dst, "dst")
        if isinstance(action, bool) or not isinstance(action, str):
            raise ModelCheckerError("action must be a str")
        if s not in self._labels:
            raise ModelCheckerError(f"unknown src state {s!r}")
        if d not in self._labels:
            raise ModelCheckerError(f"unknown dst state {d!r}")
        if (d, action) not in self._edges[s]:
            self._edges[s].append((d, action))

    @property
    def initial(self) -> Optional[str]:
        return self._initial

    def labels_of(self, state_id: str) -> FrozenSet[str]:
        sid = _check_id(state_id, "state_id")
        if sid not in self._labels:
            raise ModelCheckerError(f"unknown state {sid!r}")
        return self._labels[sid]

    # -- exploration ---------------------------------------------------------

    def _require_initial(self) -> str:
        if self._initial is None:
            raise ModelCheckerError("no initial state set")
        return self._initial

    def _successors(self, state_id: str) -> List[str]:
        # Sorted for deterministic exploration order.
        return sorted({dst for dst, _ in self._edges[state_id]})

    def explore(self) -> ExplorationResult:
        """Breadth-first exploration from the initial state."""
        init = self._require_initial()
        seen = [init]
        seen_set = {init}
        queue: deque[str] = deque([init])
        edge_count = 0
        while queue:
            cur = queue.popleft()
            for nxt in self._successors(cur):
                edge_count += 1
                if nxt not in seen_set:
                    seen_set.add(nxt)
                    seen.append(nxt)
                    queue.append(nxt)
        return ExplorationResult(
            initial=init,
            reachable=frozenset(seen_set),
            transitions_explored=edge_count,
            visit_order=tuple(seen),
        )

    def _bfs_path(self, target: str) -> Tuple[str, ...]:
        """Shortest path (deterministic) from initial to ``target``."""
        init = self._require_initial()
        prev: Dict[str, Optional[str]] = {init: None}
        queue: deque[str] = deque([init])
        while queue:
            cur = queue.popleft()
            if cur == target:
                break
            for nxt in self._successors(cur):
                if nxt not in prev:
                    prev[nxt] = cur
                    queue.append(nxt)
        if target not in prev:
            raise ModelCheckerError(f"state {target!r} not reachable from initial")
        path: List[str] = []
        cur: Optional[str] = target
        while cur is not None:
            path.append(cur)
            cur = prev[cur]
        path.reverse()
        return tuple(path)

    # -- verification --------------------------------------------------------

    def check_safety(self, bad: Iterable[str]) -> SafetyResult:
        """Fail if any reachable state carries a forbidden label.

        Returns ``holds=True`` with no counterexample when every reachable
        state is clean; otherwise the shortest trace to a violating state.
        """
        bad_set = _check_labels(bad)
        if not bad_set:
            raise ModelCheckerError("bad must be a non-empty label set")
        result = self.explore()
        explored = 0
        for state in result.visit_order:
            explored += 1
            if self._labels[state] & bad_set:
                trace = Trace(states=self._bfs_path(state), violated=state)
                return SafetyResult(
                    holds=False,
                    counterexample=trace,
                    states_explored=explored,
                    bad_labels=tuple(sorted(bad_set)),
                )
        return SafetyResult(
            holds=True,
            counterexample=None,
            states_explored=explored,
            bad_labels=tuple(sorted(bad_set)),
        )

    def check_liveness(self, good: Iterable[str]) -> LivenessResult:
        """Fail if some reachable state cannot reach a ``good`` state.

        This checks ``AG AF good``: progress must stay reachable from every
        reachable state. A violation yields the shortest trace from the
        initial state to a stuck state.
        """
        good_set = _check_labels(good)
        if not good_set:
            raise ModelCheckerError("good must be a non-empty label set")
        result = self.explore()
        explored = len(result.reachable)

        def reaches_good(start: str) -> bool:
            seen = {start}
            queue: deque[str] = deque([start])
            while queue:
                cur = queue.popleft()
                if self._labels[cur] & good_set:
                    return True
                for nxt in self._successors(cur):
                    if nxt not in seen:
                        seen.add(nxt)
                        queue.append(nxt)
            return False

        for state in result.visit_order:
            if not reaches_good(state):
                trace = Trace(states=self._bfs_path(state), violated=state)
                return LivenessResult(
                    holds=False,
                    counterexample=trace,
                    states_explored=explored,
                    good_labels=tuple(sorted(good_set)),
                )
        return LivenessResult(
            holds=True,
            counterexample=None,
            states_explored=explored,
            good_labels=tuple(sorted(good_set)),
        )


def model_checker_audit_event(kind: str, seq: int, **fields: object) -> dict:
    """Shape a model-checker lifecycle event as an ``audit.ndjson/1`` record."""
    valid = (
        "state-added",
        "transition-added",
        "explored",
        "safety-checked",
        "liveness-checked",
    )
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    for key, value in fields.items():
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise TypeError(f"audit field {key!r} must be str or int")
    record = {
        "schema": "audit.ndjson/1",
        "kind": f"model-checker.{kind}",
        "module": MODEL_CHECKER_SCHEMA,
        "version": MODEL_CHECKER_VERSION,
        "seq": seq,
    }
    record.update(fields)
    return record


def main() -> None:
    mc = ModelChecker()
    mc.add_state("idle", initial=True)
    mc.add_state("working", labels={"progress"})
    mc.add_state("crashed", labels={"bad"})
    mc.add_transition("idle", "working", action="start")
    mc.add_transition("working", "idle", action="done")
    mc.add_transition("working", "crashed", action="fault")

    safe = mc.check_safety({"bad"})
    assert safe.holds is False
    assert safe.counterexample is not None
    assert safe.counterexample.states == ("idle", "working", "crashed")

    live = mc.check_liveness({"progress"})
    assert live.holds is False  # crashed has no path back to progress
    assert live.counterexample is not None
    assert live.counterexample.violated == "crashed"

    ok = ModelChecker()
    ok.add_state("a", initial=True)
    ok.add_state("b", labels={"progress"})
    ok.add_transition("a", "b")
    ok.add_transition("b", "a")
    assert ok.check_safety({"bad"}).holds is True
    assert ok.check_liveness({"progress"}).holds is True
    assert ok.explore().reachable == frozenset({"a", "b"})
    print("model-checker OK: explore, safety counterexample, liveness counterexample")


if __name__ == "__main__":
    main()
