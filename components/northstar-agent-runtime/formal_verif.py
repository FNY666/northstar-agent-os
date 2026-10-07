"""Formal verification interface (explicit-state model checking, simulated).

Research motivation: distributed protocol code is where bugs hide (Raft
leader-election safety, Paxos ballot ordering, the SWIM suspicion
timeouts). The real tools for this are TLA+ / TLC (Lamport), Coq /
Iris, and Spin/Promela -- they exhaustively explore reachable states and
either prove a safety invariant or hand back a counterexample trace.

This module is the *API and bookkeeping* half of that discipline, pinned
so the runtime's protocol-adjacent modules (``consensus_interface``,
``paxos_interface``, ``raft_interface``, ``two_phase_commit``,
``three_phase_commit``, ``swim_protocol``) can state their core
invariant as checkable data and explore a *bounded* finite model of it:

- ``FormalSpec`` -- one specification: named finite-domain state
  variables, an ``init`` predicate (which states are initial), a ``next``
  transition relation (state -> successor states), and named invariants
  (state -> bool).
- ``spec()`` -- builds the spec record (frozen ``SpecRecord`` with a
  ``sha256:`` structural pin).
- ``model(max_states)`` -- explicit-state BFS from the initial states;
  returns a frozen ``ModelResult`` (reachable states, transition count,
  diameter, deadlock states, truncation flag).
- ``check_invariant(name)`` -- evaluates the named invariant over every
  reachable state; returns a frozen ``InvariantReport`` with ``holds``
  and, when violated, a counterexample trace (predecessor chain from an
  initial state to the violating state).

Fail-closed edges (fail loudly, never guess):

- State variables have finite, non-empty domains of hashable values;
  unknown variables or out-of-domain values are refused, never coerced.
- ``next`` must return a finite iterable of complete states (one entry
  per declared variable); partial or out-of-domain successors raise
  ``SpecError`` instead of being silently dropped.
- ``bool`` is rejected anywhere an int/str is expected (``True`` must
  not alias ``1``).
- ``model()`` stops at ``MAX_STATES`` and reports ``truncated=True`` --
  a bounded exploration that stops is not a proof; the flag says so.

Honest scope:

- This is a *simulated* model checker: explicit-state enumeration over
  a bounded finite model the *host* encoded. It cannot verify TLA+
  specs, Coq theorems, or unbounded/real systems. What it pins is the
  discipline: state the invariant, enumerate the reachable space,
  produce the counterexample trace -- all deterministically,
  audit-replayable, with no wall-clock and no randomness.
- A green ``check_invariant`` proves nothing about the production
  module it was inspired by; the model is only as faithful as the
  ``init``/``next`` encoding the host wrote. State explosion is the
  host's problem to bound (``max_states`` guardrail).
- The structural digest pins the *shape* of the spec (variable names,
  domains, invariant names) -- it cannot pin the behavior of the
  Python callables, so two specs with identical digests can still
  disagree on transitions. Documented, not hidden.
"""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


#: Version pin for this module's record shape.
FORMAL_VERIF_VERSION = "formal-verif.v1"

#: Schema pin carried on audit records.
FORMAL_VERIF_SCHEMA = "northstar.formal-verif.v1"

#: Domain-separation prefix so digests cannot collide with other modules'.
_DOMAIN = b"northstar.formal-verif.v1:"

#: Hard guardrail on explicit-state exploration: state explosion is real
#: and a bounded checker that silently stops is a lie, so the bound is
#: small and truncation is always reported.
MAX_STATES = 10_000


class SpecError(Exception):
    """Raised for malformed specs, states, or transition relations."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: object) -> int:
    """Caller-supplied int sequence numbers only: no wall-clock, no guessing."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SpecError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SpecError("seq must be non-negative")
    return seq


def _require_name(value: object, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise SpecError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise SpecError(f"{what} must be non-empty")
    return value


def _require_hashable(value: object, what: str) -> None:
    try:
        hash(value)
    except TypeError:
        raise SpecError(f"{what} must be hashable, got {type(value).__name__}") from None
    if isinstance(value, bool):
        raise SpecError(f"{what} must not be a bool")


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StateVar:
    """One named state variable with a finite domain."""

    name: str
    domain: Tuple[object, ...]

    def __post_init__(self) -> None:
        _require_name(self.name, "StateVar.name")
        if not isinstance(self.domain, tuple):
            raise SpecError("StateVar.domain must be a tuple")
        if not self.domain:
            raise SpecError("StateVar.domain must be non-empty")
        seen = set()
        for value in self.domain:
            _require_hashable(value, "StateVar.domain value")
            if value in seen:
                raise SpecError("StateVar.domain values must be distinct")
            seen.add(value)


def _canonical_state(state: Mapping[str, object], var_names: Sequence[str]) -> Tuple[Tuple[str, object], ...]:
    """Canonical immutable state: sorted (name, value) pairs."""
    return tuple((name, state[name]) for name in sorted(var_names))


@dataclass(frozen=True)
class SpecRecord:
    """Frozen structural record of a specification."""

    spec_name: str
    variables: Tuple[StateVar, ...]
    invariant_names: Tuple[str, ...]
    structural_digest: str

    def __post_init__(self) -> None:
        _require_name(self.spec_name, "SpecRecord.spec_name")

    def as_dict(self) -> dict:
        return {
            "spec_name": self.spec_name,
            "variables": [
                {"name": v.name, "domain": [repr(x) for x in v.domain]}
                for v in self.variables
            ],
            "invariant_names": list(self.invariant_names),
            "structural_digest": self.structural_digest,
            "version": FORMAL_VERIF_VERSION,
            "schema": FORMAL_VERIF_SCHEMA,
        }


@dataclass(frozen=True)
class ModelResult:
    """Frozen outcome of an explicit-state exploration."""

    spec_name: str
    state_count: int
    transition_count: int
    diameter: int
    deadlock_states: Tuple[Tuple[Tuple[str, object], ...], ...]
    truncated: bool

    def as_dict(self) -> dict:
        return {
            "spec_name": self.spec_name,
            "state_count": self.state_count,
            "transition_count": self.transition_count,
            "diameter": self.diameter,
            "deadlock_count": len(self.deadlock_states),
            "truncated": self.truncated,
            "version": FORMAL_VERIF_VERSION,
            "schema": FORMAL_VERIF_SCHEMA,
        }


@dataclass(frozen=True)
class InvariantReport:
    """Frozen outcome of an invariant check over reachable states."""

    spec_name: str
    invariant_name: str
    holds: bool
    states_checked: int
    counterexample: Optional[Tuple[Tuple[Tuple[str, object], ...], ...]]
    truncated: bool

    def as_dict(self) -> dict:
        return {
            "spec_name": self.spec_name,
            "invariant_name": self.invariant_name,
            "holds": self.holds,
            "states_checked": self.states_checked,
            "counterexample_length": (
                None if self.counterexample is None else len(self.counterexample)
            ),
            "truncated": self.truncated,
            "version": FORMAL_VERIF_VERSION,
            "schema": FORMAL_VERIF_SCHEMA,
        }


# ---------------------------------------------------------------------------
# The spec
# ---------------------------------------------------------------------------


class FormalSpec:
    """One checkable specification: variables, init, next, invariants."""

    def __init__(
        self,
        spec_name: str,
        variables: Sequence[StateVar],
        init: Callable[[Dict[str, object]], bool],
        next_fn: Callable[[Dict[str, object]], Iterable[Mapping[str, object]]],
    ) -> None:
        self._name = _require_name(spec_name, "spec_name")
        if not isinstance(variables, (tuple, list)) or not variables:
            raise SpecError("variables must be a non-empty sequence of StateVar")
        for var in variables:
            if not isinstance(var, StateVar):
                raise SpecError("variables must be StateVar records")
        names = [v.name for v in variables]
        if len(set(names)) != len(names):
            raise SpecError("state variable names must be distinct")
        if not callable(init):
            raise SpecError("init must be callable")
        if not callable(next_fn):
            raise SpecError("next_fn must be callable")
        self._variables: Tuple[StateVar, ...] = tuple(variables)
        self._var_names: Tuple[str, ...] = tuple(names)
        self._domains: Dict[str, Tuple[object, ...]] = {
            v.name: v.domain for v in variables
        }
        self._init = init
        self._next = next_fn
        self._invariants: Dict[str, Callable[[Dict[str, object]], bool]] = {}

    # -- structure ------------------------------------------------------

    def spec(self) -> SpecRecord:
        """Build the frozen structural record (pins shape, not behavior)."""
        digest = self._structural_digest()
        return SpecRecord(
            spec_name=self._name,
            variables=self._variables,
            invariant_names=tuple(sorted(self._invariants)),
            structural_digest=digest,
        )

    def _structural_digest(self) -> str:
        parts = [_DOMAIN, self._name.encode("utf-8"), b"\x00"]
        for name in self._var_names:
            parts.append(name.encode("utf-8"))
            parts.append(b"\x01")
            for value in self._domains[name]:
                parts.append(repr(value).encode("utf-8"))
                parts.append(b"\x02")
            parts.append(b"\x03")
        for inv_name in sorted(self._invariants):
            parts.append(inv_name.encode("utf-8"))
            parts.append(b"\x04")
        return "sha256:" + hashlib.sha256(b"".join(parts)).hexdigest()

    # -- invariants -----------------------------------------------------

    def add_invariant(
        self, name: str, predicate: Callable[[Dict[str, object]], bool]
    ) -> None:
        """Register a named safety invariant: state -> bool."""
        inv_name = _require_name(name, "invariant name")
        if inv_name in self._invariants:
            raise SpecError(f"duplicate invariant: {inv_name}")
        if not callable(predicate):
            raise SpecError("invariant predicate must be callable")
        self._invariants[inv_name] = predicate

    # -- state validation -------------------------------------------------

    def _validate_state(self, state: Mapping[str, object]) -> Dict[str, object]:
        """Fail-closed state check: exact variable set, in-domain values."""
        if not isinstance(state, Mapping):
            raise SpecError("state must be a mapping")
        if set(state.keys()) != set(self._var_names):
            raise SpecError(
                "state must define exactly the declared variables "
                f"(got {sorted(state.keys())}, want {sorted(self._var_names)})"
            )
        checked: Dict[str, object] = {}
        for name in self._var_names:
            value = state[name]
            _require_hashable(value, f"state[{name!r}]")
            if value not in self._domains[name]:
                raise SpecError(
                    f"state[{name!r}] value {value!r} outside declared domain"
                )
            checked[name] = value
        return checked

    def _successors(self, canon: Tuple[Tuple[str, object], ...]) -> List[Tuple[Tuple[str, object], ...]]:
        """Apply the transition relation, fail-closed on malformed output."""
        state = dict(canon)
        raw = self._next(dict(state))
        if isinstance(raw, Mapping) or isinstance(raw, (str, bytes)):
            raise SpecError("next_fn must return an iterable of states, not a single state")
        out: List[Tuple[Tuple[str, object], ...]] = []
        try:
            iterator = iter(raw)
        except TypeError:
            raise SpecError("next_fn must return an iterable of states") from None
        seen: set = set()
        for succ in iterator:
            checked = self._validate_state(succ)
            c = _canonical_state(checked, self._var_names)
            if c not in seen:
                seen.add(c)
                out.append(c)
        return out

    # -- model checking ---------------------------------------------------

    def _initial_states(self) -> List[Tuple[Tuple[str, object], ...]]:
        """Enumerate the finite initial-state space via the init predicate."""
        import itertools

        domains = [self._domains[name] for name in self._var_names]
        initials: List[Tuple[Tuple[str, object], ...]] = []
        for combo in itertools.product(*domains):
            state = dict(zip(self._var_names, combo))
            verdict = self._init(dict(state))
            if not isinstance(verdict, bool):
                raise SpecError("init must return a bool")
            if verdict:
                initials.append(_canonical_state(state, self._var_names))
        if not initials:
            raise SpecError("init admits no state: empty initial set is fail-closed")
        return initials

    def model(self, max_states: int = MAX_STATES) -> ModelResult:
        """Explicit-state BFS from the initial states.

        Returns reachable-state count, transition count, BFS diameter,
        the deadlock states (no successors), and whether the exploration
        was truncated at ``max_states``.
        """
        if isinstance(max_states, bool) or not isinstance(max_states, int):
            raise SpecError("max_states must be an int")
        if max_states < 1:
            raise SpecError("max_states must be >= 1")

        initials = self._initial_states()
        visited: Dict[Tuple[Tuple[str, object], ...], int] = {}
        predecessors: Dict[Tuple[Tuple[str, object], ...], Optional[Tuple[Tuple[str, object], ...]]] = {}
        queue: deque = deque()
        for s in initials:
            if s not in visited:
                visited[s] = 0
                predecessors[s] = None
                queue.append(s)

        transition_count = 0
        deadlock: List[Tuple[Tuple[str, object], ...]] = []
        truncated = False
        diameter = 0
        self._last_predecessors = predecessors

        while queue:
            current = queue.popleft()
            depth = visited[current]
            diameter = max(diameter, depth)
            successors = self._successors(current)
            transition_count += len(successors)
            if not successors:
                deadlock.append(current)
            for succ in successors:
                if succ not in visited:
                    if len(visited) >= max_states:
                        truncated = True
                        queue.clear()
                        break
                    visited[succ] = depth + 1
                    predecessors[succ] = current
                    queue.append(succ)
            if truncated:
                break

        deadlock_states = tuple(sorted(deadlock))
        return ModelResult(
            spec_name=self._name,
            state_count=len(visited),
            transition_count=transition_count,
            diameter=diameter,
            deadlock_states=deadlock_states,
            truncated=truncated,
        )

    def check_invariant(
        self, invariant_name: str, max_states: int = MAX_STATES
    ) -> InvariantReport:
        """Check one named invariant over all reachable states.

        When violated, returns the shortest counterexample trace (initial
        state -> ... -> violating state) via the BFS predecessor chain.
        """
        inv_name = _require_name(invariant_name, "invariant_name")
        if inv_name not in self._invariants:
            raise SpecError(f"unknown invariant: {inv_name}")
        predicate = self._invariants[inv_name]

        model_result = self.model(max_states=max_states)
        predecessors = self._last_predecessors
        checked = 0
        for canon in sorted(predecessors):
            state = dict(canon)
            verdict = predicate(dict(state))
            if not isinstance(verdict, bool):
                raise SpecError("invariant predicate must return a bool")
            checked += 1
            if not verdict:
                trace: List[Tuple[Tuple[str, object], ...]] = [canon]
                prev = predecessors[canon]
                while prev is not None:
                    trace.append(prev)
                    prev = predecessors[prev]
                trace.reverse()
                return InvariantReport(
                    spec_name=self._name,
                    invariant_name=inv_name,
                    holds=False,
                    states_checked=checked,
                    counterexample=tuple(trace),
                    truncated=model_result.truncated,
                )
        return InvariantReport(
            spec_name=self._name,
            invariant_name=inv_name,
            holds=True,
            states_checked=checked,
            counterexample=None,
            truncated=model_result.truncated,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("spec-built", "modeled", "invariant-checked")


def formal_verif_audit_event(kind: str, spec_name: str, seq: object, **fields: object) -> dict:
    """Audit-shaped record for a formal-verification observation."""
    if kind not in _AUDIT_KINDS:
        raise ValueError("unknown kind")
    _require_name(spec_name, "spec_name")
    _check_seq(seq)
    return {
        "event": "formal-verif",
        "kind": kind,
        "spec_name": spec_name,
        "fields": dict(fields),
        "audit_seq": seq,
        "schema": "audit.ndjson/1",
    }


def main() -> None:
    # A tiny mutual-exclusion model: two processes, one critical section.
    pc = StateVar("pc0", ("idle", "want", "crit"))
    pc1 = StateVar("pc1", ("idle", "want", "crit"))
    turn = StateVar("turn", (0, 1))

    def init(s: Dict[str, object]) -> bool:
        return s["pc0"] == "idle" and s["pc1"] == "idle" and s["turn"] == 0

    def nxt(s: Dict[str, object]) -> Iterable[Mapping[str, object]]:
        out = []
        for i in (0, 1):
            key = f"pc{i}"
            other = f"pc{1 - i}"
            cur = dict(s)
            if s[key] == "idle":
                cur[key] = "want"
                cur["turn"] = 1 - i  # announce interest, yield priority
                out.append(cur)
            elif s[key] == "want":
                interested_other = s[other] in ("want", "crit")
                if s["turn"] == i or not interested_other:
                    nxt_state = dict(s)
                    nxt_state[key] = "crit"
                    out.append(nxt_state)
            elif s[key] == "crit":
                nxt_state = dict(s)
                nxt_state[key] = "idle"
                out.append(nxt_state)
        return out

    spec = FormalSpec("mutex", [pc, pc1, turn], init, nxt)
    spec.add_invariant(
        "mutual-exclusion",
        lambda s: not (s["pc0"] == "crit" and s["pc1"] == "crit"),
    )
    record = spec.spec()
    assert record.structural_digest.startswith("sha256:"), "structural pin"
    result = spec.model()
    assert not result.truncated, "must fully explore this tiny model"
    assert result.state_count > 0, "reachable states"
    report = spec.check_invariant("mutual-exclusion")
    assert report.holds, "Peterson-style mutual exclusion must hold"
    assert report.counterexample is None, "no counterexample expected"

    # A deliberately broken model: invariant must fail with a trace.
    bad = FormalSpec(
        "broken",
        [StateVar("x", (0, 1, 2))],
        lambda s: s["x"] == 0,
        lambda s: [{"x": s["x"] + 1}] if s["x"] < 2 else [],
    )
    bad.add_invariant("x-lt-2", lambda s: s["x"] < 2)
    bad_report = bad.check_invariant("x-lt-2")
    assert not bad_report.holds, "broken invariant must fail"
    assert bad_report.counterexample is not None, "counterexample required"
    assert len(bad_report.counterexample) == 3, "trace 0 -> 1 -> 2"
    last = dict(bad_report.counterexample[-1])
    assert last["x"] == 2, "trace ends at violating state"
    print(
        f"formal-verif OK: mutex holds over {result.state_count} states, "
        f"broken model counterexample length {len(bad_report.counterexample)}"
    )


if __name__ == "__main__":
    main()
