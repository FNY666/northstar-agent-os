"""Typed effect envelope: pure ``decide``, host-only minting, runtime execution.

Absorbed from Jido's directive/action separation (agentjido/jido, rank 2 in
the frontier round).  The honest framing -- taken from the source text, not
from a paraphrase -- is:

* Jido's ``Agent.cmd/2`` is a **pure function**: it takes an agent and a
  signal and returns an updated agent plus a list of directives.
* A directive is a **bare struct** that only *describes* an external effect;
  it never mutates state.  The type set is closed: ``Emit / Error /
  SpawnAgent / StopChild / Schedule / RunInstruction / Stop / Cron /
  CronCancel``.
* The runtime (``AgentServer`` + ``DirectiveExec``) interprets and executes
  them.  Internal state operations (``StateOp``) never leave ``cmd/2``.
* The turn pipeline has seven steps: signal -> route -> run action ->
  validate candidate -> persist commit -> dispatch directive -> settle.

A directive is **not** a "user instruction" or a "system instruction".  It is
an *effect description*.  The three borrowable safety properties are:

1. model/tool output is only **data** (a signal); it never parses into a
   directive,
2. only **host code** can mint a directive,
3. the routing table is **fixed at compile time** (frozen at module load).

Northstar gap this closes (read from the code, not assumed):

* ``deliberative_spec.py`` is an audit gate on *spec citations* before a
  decision -- not effect separation.
* ``constitutional_ai.py`` is a principle/self-review/revision ledger -- not
  effect separation.
* ``safety_envelope.py`` bounds *physical* actuation; it says nothing about
  generic external effects.
* A repo-wide grep for ``class .*Directive`` returns nothing: there is no
  typed effect envelope, no host-only minting path, and no interpreter that
  is the sole source of external effects.
* ``state_budget.py`` caps state *size*; different layer, read-only here.

Design invariants this module enforces:

* the directive type set is **closed** -- an unknown or misspelled kind
  raises, and is never folded into a neighbouring kind,
* ``parse_untrusted()`` cannot mint a directive for **any** input, including
  text that literally contains ``Emit(...)``,
* ``decide()`` is pure: no external effect happens during the decide stage,
  the same input yields the same output, and the input state is not mutated,
* the routing table is frozen at construction and cannot be edited at
  runtime; an unknown signal type is an explicit error, never a fallback,
* a failed turn keeps the pre-commit state and dispatches nothing,
* a dispatched directive carries an idempotency key, so a replay does not
  execute twice,
* :class:`DirectiveExec` is the only place that produces external effects.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping, NamedTuple, Sequence

#: Version pin for this module's record shape.
EFFECT_DIRECTIVE_VERSION = "effect-directive.v1"

#: The closed directive type set (verbatim from the Jido source text).
DIRECTIVE_KINDS: frozenset[str] = frozenset(
    {
        "Emit",
        "Error",
        "SpawnAgent",
        "StopChild",
        "Schedule",
        "RunInstruction",
        "Stop",
        "Cron",
        "CronCancel",
    }
)

#: The seven steps of the turn pipeline, in order (verbatim from the source).
TURN_PIPELINE_STEPS: tuple[str, ...] = (
    "signal",
    "route",
    "run_action",
    "validate_candidate",
    "persist_commit",
    "dispatch_directive",
    "settle",
)


class EffectDirectiveError(Exception):
    """Base class for every refusal of this module."""


class UnknownDirectiveKind(EffectDirectiveError):
    """The directive kind is outside the closed type set."""

    def __init__(self, kind: Any) -> None:
        self.kind = kind
        super().__init__(
            f"unknown directive kind {kind!r}; the closed type set is "
            f"{sorted(DIRECTIVE_KINDS)}"
        )


class MintError(EffectDirectiveError):
    """A minting attempt was refused (missing or wrong host capability)."""


class ParseRejected(EffectDirectiveError):
    """Untrusted data could not be parsed into a directive -- always.

    This is the *expected* outcome of :func:`parse_untrusted`, not a crash:
    the function reports the rejection instead of raising, so a caller that
    forgets to check the result still receives no directive.
    """


class UnknownSignal(EffectDirectiveError):
    """The signal type is not in the frozen routing table."""

    def __init__(self, signal_type: Any, known: Sequence[str]) -> None:
        self.signal_type = signal_type
        self.known = tuple(sorted(known))
        super().__init__(
            f"unknown signal type {signal_type!r}; the routing table is fixed "
            f"and has no default action (known: {list(self.known)})"
        )


def _canonical_json(value: Any) -> str:
    """Canonical JSON: sorted keys, compact separators, UTF-8 text."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class HostCapability:
    """In-memory proof that the caller is host code.

    The boundary this module defends is a **code/data** boundary, not a
    privilege boundary inside one process: untrusted input arrives as text
    or JSON and is parsed by :func:`parse_untrusted`, which never builds a
    capability.  A capability is an object minted in host code and passed
    explicitly; forging one requires the module-private proof.
    """

    proof: str = field(repr=False, compare=False)


#: The singleton host capability.  Host code imports this and passes it to
#: :func:`mint`; untrusted data never can.
HOST_CAPABILITY = HostCapability(proof=secrets.token_hex(32))


@dataclass(frozen=True)
class Directive:
    """A typed description of one external effect (never state mutation).

    Attributes:
        kind: one of :data:`DIRECTIVE_KINDS` -- the closed type set.
        payload_json: the canonical JSON encoding of the effect parameters.
        idempotency_key: the replay guard; the same key is executed at most
            once by a :class:`DirectiveExec`.
    """

    kind: str
    payload_json: str
    idempotency_key: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or self.kind not in DIRECTIVE_KINDS:
            raise UnknownDirectiveKind(self.kind)
        if not isinstance(self.payload_json, str):
            raise EffectDirectiveError("payload_json must be a str")
        if not isinstance(self.idempotency_key, str) or not self.idempotency_key:
            raise EffectDirectiveError("idempotency_key must be a non-empty str")

    @property
    def payload(self) -> Any:
        """The decoded payload."""
        return json.loads(self.payload_json)


def derive_idempotency_key(kind: str, payload_json: str) -> str:
    """Derive a deterministic idempotency key from the effect description.

    Deterministic so that the same effect description produced by the same
    host code carries the same key -- which is what makes a replay a no-op.
    """
    digest = hashlib.sha256(f"{kind}\n{payload_json}".encode("utf-8")).hexdigest()
    return f"ed.v1:{digest}"


def mint(
    kind: str,
    payload: Any,
    *,
    capability: HostCapability,
    idempotency_key: str | None = None,
) -> Directive:
    """Mint a directive.  **Host code only.**

    The capability check is what makes this the single minting path: an
    untrusted caller has no capability object, and no parsing routine
    produces one.  The kind is checked against the closed set, so a
    misspelled kind raises instead of being folded into a neighbour.

    Args:
        kind: one of :data:`DIRECTIVE_KINDS`.
        payload: JSON-serialisable effect parameters.
        capability: the host capability; must be :data:`HOST_CAPABILITY`.
        idempotency_key: explicit replay guard; derived from the effect
            description when omitted.

    Returns:
        The minted :class:`Directive`.

    Raises:
        MintError: the capability is missing, foreign, or forged.
        UnknownDirectiveKind: the kind is outside the closed type set.
    """
    if not isinstance(capability, HostCapability) or capability is not HOST_CAPABILITY:
        raise MintError("only host code can mint a directive")
    if not isinstance(kind, str) or kind not in DIRECTIVE_KINDS:
        raise UnknownDirectiveKind(kind)
    payload_json = _canonical_json(payload)
    key = idempotency_key or derive_idempotency_key(kind, payload_json)
    return Directive(kind=kind, payload_json=payload_json, idempotency_key=key)


@dataclass(frozen=True)
class ParseResult:
    """The result of :func:`parse_untrusted`.

    ``accepted`` is always ``False`` -- there is no input this module will
    turn into a directive -- and ``directive`` is always ``None``.
    """

    accepted: bool
    directive: None
    reason: str
    detail: str

    def __bool__(self) -> bool:
        return self.accepted


def parse_untrusted(data: Any) -> ParseResult:
    """Parse untrusted data.  **Never mints a directive.**

    This is the anti-injection boundary: model output, tool output and any
    other text/JSON that crossed a trust boundary comes here, and the answer
    is always "no directive".  In particular a payload that literally
    contains ``Emit(...)`` or a JSON object shaped like a directive is
    *not* interpreted -- it is reported as rejected text.

    Args:
        data: anything at all (text, bytes, dict, list, ``None``).

    Returns:
        A :class:`ParseResult` with ``accepted=False``, ``directive=None``
        and a human-readable reason.
    """
    if isinstance(data, (bytes, bytearray)):
        shown = f"bytes(len={len(data)})"
    elif isinstance(data, str):
        shown = f"str(len={len(data)})"
    else:
        shown = type(data).__name__
    return ParseResult(
        accepted=False,
        directive=None,
        reason="untrusted data is never parsed into a directive",
        detail=shown,
    )


@dataclass(frozen=True)
class Signal:
    """A signal: the only thing that enters :func:`decide`.

    A signal carries *data*.  It never carries a directive: the payload is
    opaque text/JSON that the action may interpret, and nothing in this
    module turns it into an effect description.
    """

    signal_type: str
    payload: Any = None

    def __post_init__(self) -> None:
        if not isinstance(self.signal_type, str) or not self.signal_type:
            raise EffectDirectiveError("signal_type must be a non-empty str")


#: An action is a pure state transition: ``(state, signal) -> (state, ...)``.
#: It may *describe* effects, but it may not perform them.
Action = Callable[[Mapping[str, Any], Signal], Any]


@dataclass(frozen=True)
class SignalRouter:
    """A routing table fixed at construction and frozen thereafter.

    The table maps a signal type to an action.  It is frozen: there is no
    ``add``, no ``remove``, no ``default``.  An unknown signal type raises
    :class:`UnknownSignal` -- it is never routed to a fallback action,
    because a fallback is exactly the "catch-all" that turns a routing
    mistake into a silent wrong effect.
    """

    routes: Mapping[str, Action]

    def __post_init__(self) -> None:
        routes = dict(self.routes)
        for key in routes:
            if not isinstance(key, str) or not key:
                raise EffectDirectiveError("route keys must be non-empty str")
            if not callable(routes[key]):
                raise EffectDirectiveError(f"route {key!r} is not callable")
        # A frozen mapping: the table cannot be edited after construction.
        object.__setattr__(self, "routes", MappingProxyType(routes))

    def action_for(self, signal: Signal) -> Action:
        """The action bound to ``signal.signal_type``.

        Raises:
            UnknownSignal: the signal type is not in the table.
        """
        try:
            return self.routes[signal.signal_type]
        except KeyError:
            raise UnknownSignal(signal.signal_type, tuple(self.routes)) from None

    def known_types(self) -> tuple[str, ...]:
        """The signal types this router accepts, sorted."""
        return tuple(sorted(self.routes))


class FrozenMapping(Mapping):
    """A read-only mapping used for frozen payloads (stdlib only)."""

    __slots__ = ("_data",)

    def __init__(self, data: Mapping[str, Any] | None = None) -> None:
        self._data = dict(data or {})

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"FrozenMapping({self._data!r})"


class DecideResult(NamedTuple):
    """The result of :func:`decide` -- literally the pair ``(state, directives)``.

    It is a :class:`typing.NamedTuple`, so ``new_state, directives =
    decide(...)`` works and the value *is* the two-tuple the source's
    ``cmd/2`` returns.

    Attributes:
        state: the **new** state; the input state is not mutated.
        directives: the effect descriptions the action asked for, in order.
            These are descriptions, not executions -- nothing happened yet.
    """

    state: Mapping[str, Any]
    directives: tuple[Directive, ...] = ()


def decide(
    state: Mapping[str, Any],
    signal: Signal,
    router: SignalRouter | None = None,
) -> DecideResult:
    """Pure decide: route the signal, run the action, return the proposal.

    This is Northstar's version of Jido's ``cmd/2``: a pure function that
    takes an agent (here: the state) and a signal and returns the updated
    state plus the list of directives.  It produces no external effect, it
    does not mutate the input state, and the same input yields the same
    result every time.

    ``router`` is optional: when omitted the installed default router is
    used (see :func:`install_router`).  The table is frozen either way --
    there is no path that edits a route at runtime.

    The action's return value is either a new state, or a
    ``(new_state, directives)`` pair where the directives were minted by
    host code inside the action.  A malformed action result is an explicit
    error, never a silent partial success.

    Raises:
        UnknownSignal: the signal type is not in the frozen routing table.
        EffectDirectiveError: the action returned something unusable.
    """
    if not isinstance(state, Mapping):
        raise EffectDirectiveError("state must be a mapping")
    if not isinstance(signal, Signal):
        raise EffectDirectiveError("signal must be a Signal")
    if router is None:
        router = default_router()
    action = router.action_for(signal)
    outcome = action(state, signal)
    if isinstance(outcome, tuple) and len(outcome) == 2:
        new_state, directives = outcome
    else:
        new_state, directives = outcome, ()
    if not isinstance(new_state, Mapping):
        raise EffectDirectiveError("action must return a mapping as the new state")
    directives = tuple(directives)
    for directive in directives:
        if not isinstance(directive, Directive):
            raise EffectDirectiveError(
                "action produced a non-directive; effects must be described as "
                f"Directive instances, got {type(directive).__name__}"
            )
    return DecideResult(state=MappingProxyType(dict(new_state)), directives=directives)


# -- the turn pipeline ----------------------------------------------------


@dataclass(frozen=True)
class TurnResult:
    """The outcome of one turn.

    Attributes:
        committed: whether the turn reached the persist-commit step.
        state: the state after the turn -- the **pre-commit** state when
            the turn failed, the committed state otherwise.
        directives: the directives that were dispatched (empty on failure).
        step: the last pipeline step that was reached.
        failure: the reason the turn failed, or ``None``.
    """

    committed: bool
    state: Mapping[str, Any]
    directives: tuple[Directive, ...]
    step: str
    failure: str | None = None


class ActionFailure(Exception):
    """Raised by an action to fail its turn (the state is rolled back)."""


class ValidatorFailure(Exception):
    """Raised by the candidate validator to fail its turn."""


class CommitFailure(Exception):
    """Raised by the persister to fail its turn."""


def run_turn(
    state: Mapping[str, Any],
    signal: Signal,
    router: SignalRouter,
    *,
    validator: Callable[[Mapping[str, Any], Sequence[Directive]], bool] | None = None,
    persister: Callable[[Mapping[str, Any]], None] | None = None,
    executor: "DirectiveExec | None" = None,
) -> TurnResult:
    """Run one turn through the seven-step pipeline.

    The steps are the source's: ``signal -> route -> run_action ->
    validate_candidate -> persist_commit -> dispatch_directive -> settle``.

    Failure semantics:

    * a failed turn keeps the **pre-commit** state and dispatches nothing,
    * once the commit succeeded the turn is committed even if a later step
      fails -- a committed directive cannot be un-committed, which is why
      every directive carries an idempotency key and why the replay path
      in :class:`DirectiveExec` executes a key at most once.

    The effect sink is only ever touched through ``executor``: the decide
    stage calls no effect sink at all, and a failing turn calls none
    either.
    """
    pre_commit_state = MappingProxyType(dict(state))
    # 1. signal (already supplied by the caller)
    # 2. route
    try:
        action = router.action_for(signal)
    except UnknownSignal as exc:
        return TurnResult(
            committed=False,
            state=pre_commit_state,
            directives=(),
            step="route",
            failure=str(exc),
        )
    # 3. run action
    try:
        proposal = action(pre_commit_state, signal)
    except ActionFailure as exc:
        return TurnResult(
            committed=False,
            state=pre_commit_state,
            directives=(),
            step="run_action",
            failure=str(exc),
        )
    if isinstance(proposal, tuple) and len(proposal) == 2:
        candidate_state, directives = proposal
    else:
        candidate_state, directives = proposal, ()
    directives = tuple(directives)
    for directive in directives:
        if not isinstance(directive, Directive):
            return TurnResult(
                committed=False,
                state=pre_commit_state,
                directives=(),
                step="run_action",
                failure=(
                    "action produced a non-directive: "
                    f"{type(directive).__name__}"
                ),
            )
    # 4. validate candidate
    if validator is not None:
        try:
            accepted = bool(validator(candidate_state, directives))
        except ValidatorFailure as exc:
            return TurnResult(
                committed=False,
                state=pre_commit_state,
                directives=(),
                step="validate_candidate",
                failure=str(exc),
            )
        if not accepted:
            return TurnResult(
                committed=False,
                state=pre_commit_state,
                directives=(),
                step="validate_candidate",
                failure="candidate rejected by the validator",
            )
    # 5. persist commit
    try:
        if persister is not None:
            persister(candidate_state)
    except CommitFailure as exc:
        return TurnResult(
            committed=False,
            state=pre_commit_state,
            directives=(),
            step="persist_commit",
            failure=str(exc),
        )
    committed_state = MappingProxyType(dict(candidate_state))
    # 6. dispatch directives
    if executor is None:
        return TurnResult(
            committed=True,
            state=committed_state,
            directives=(),
            step="persist_commit",
            failure=None,
        )
    try:
        before = len(executor.receipts())
        receipts = executor.dispatch(directives)
    except Exception as exc:  # noqa: BLE001 - a post-commit failure is reported
        return TurnResult(
            committed=True,
            state=committed_state,
            directives=directives,
            step="dispatch_directive",
            failure=f"post-commit dispatch failure: {exc}",
        )
    # A sink that refused an effect is a post-commit failure: the commit
    # stands (it cannot be undone) but the failure is reported, not hidden.
    failed = [
        r for r in receipts[before:] if not r.executed and r.detail.startswith("effect failed")
    ]
    if failed:
        return TurnResult(
            committed=True,
            state=committed_state,
            directives=directives,
            step="dispatch_directive",
            failure=f"post-commit dispatch failure: {failed[0].detail}",
        )
    # 7. settle
    return TurnResult(
        committed=True,
        state=committed_state,
        directives=directives,
        step="settle",
        failure=None,
    )


@dataclass(frozen=True)
class ExecReceipt:
    """The receipt of one executed directive."""

    idempotency_key: str
    kind: str
    payload: Any
    executed: bool
    detail: str = ""


class DirectiveExec:
    """The interpreter: the only place external effects are produced.

    An executor owns an *effect sink* -- a callable that performs the
    external effect -- and an idempotency ledger.  ``dispatch()`` executes
    each directive through the sink exactly once per idempotency key; a
    replay of the same key is a no-op and is recorded as such.

    Because this class is the only holder of the sink, an effect cannot
    happen anywhere else: the decide stage and the action only ever
    *describe* effects.
    """

    def __init__(self, sink: Callable[[Directive], Any]) -> None:
        if not callable(sink):
            raise EffectDirectiveError("the effect sink must be callable")
        self._sink = sink
        self._done: dict[str, ExecReceipt] = {}
        self._receipts: list[ExecReceipt] = []

    def dispatch(self, directives: Sequence[Directive]) -> list[ExecReceipt]:
        """Execute the directives that have not been executed yet.

        Returns:
            One receipt per directive, in order.  A replayed key yields a
            receipt with ``executed=False``.
        """
        receipts: list[ExecReceipt] = []
        for directive in directives:
            if not isinstance(directive, Directive):
                raise EffectDirectiveError(
                    f"cannot dispatch a non-directive: {type(directive).__name__}"
                )
            key = directive.idempotency_key
            previous = self._done.get(key)
            if previous is not None:
                receipt = ExecReceipt(
                    idempotency_key=key,
                    kind=directive.kind,
                    payload=directive.payload,
                    executed=False,
                    detail="replay: idempotency key already executed",
                )
                self._receipts.append(receipt)
                receipts.append(receipt)
                continue
            try:
                result = self._sink(directive)
            except Exception as exc:  # noqa: BLE001 - the failure is recorded
                receipt = ExecReceipt(
                    idempotency_key=key,
                    kind=directive.kind,
                    payload=directive.payload,
                    executed=False,
                    detail=f"effect failed: {exc}",
                )
                self._receipts.append(receipt)
                receipts.append(receipt)
                continue
            receipt = ExecReceipt(
                idempotency_key=key,
                kind=directive.kind,
                payload=directive.payload,
                executed=True,
                detail=("ok" if result is None else str(result)),
            )
            self._done[key] = receipt
            self._receipts.append(receipt)
            receipts.append(receipt)
        return receipts

    def receipts(self) -> tuple[ExecReceipt, ...]:
        """Every receipt this executor produced, in order."""
        return tuple(self._receipts)

    def executed_keys(self) -> frozenset[str]:
        """The idempotency keys that have actually produced an effect."""
        return frozenset(
            r.idempotency_key for r in self._receipts if r.executed
        )


# -- the installed routing table ------------------------------------------

#: The routers installed by the host, by name.  Installing happens in host
#: code, at import time -- the table of a router is frozen when the router
#: is built, and a router is only reachable through this registry.
_ROUTERS: dict[str, SignalRouter] = {}
_DEFAULT_ROUTER_NAME: str | None = None


def install_router(name: str, router: SignalRouter, *, make_default: bool = False) -> SignalRouter:
    """Install a routing table under ``name`` (host code only).

    This is the one place a routing table enters the module.  It happens
    at import/host-setup time; the table itself is frozen, so an
    installed router's routes cannot change afterwards.

    Raises:
        EffectDirectiveError: the name is empty, the router is not a
            :class:`SignalRouter`, or the name is already taken.
    """
    global _DEFAULT_ROUTER_NAME
    if not isinstance(name, str) or not name:
        raise EffectDirectiveError("router name must be a non-empty str")
    if not isinstance(router, SignalRouter):
        raise EffectDirectiveError("router must be a SignalRouter")
    if name in _ROUTERS:
        raise EffectDirectiveError(f"router {name!r} is already installed")
    _ROUTERS[name] = router
    if make_default or _DEFAULT_ROUTER_NAME is None:
        _DEFAULT_ROUTER_NAME = name
    return router


def default_router() -> SignalRouter:
    """The installed default router.

    Raises:
        EffectDirectiveError: no router has been installed yet.
    """
    if _DEFAULT_ROUTER_NAME is None:
        raise EffectDirectiveError("no routing table has been installed")
    return _ROUTERS[_DEFAULT_ROUTER_NAME]


def installed_routers() -> tuple[str, ...]:
    """The names of the installed routers, sorted."""
    return tuple(sorted(_ROUTERS))


def main() -> None:
    """Self-check: the module's own invariants, offline and deterministic."""
    # the closed type set
    assert len(DIRECTIVE_KINDS) == 9
    for kind in DIRECTIVE_KINDS:
        d = mint(kind, {"x": 1}, capability=HOST_CAPABILITY)
        assert d.kind == kind
    try:
        mint("Emit ", {}, capability=HOST_CAPABILITY)
        raise AssertionError("should raise")
    except UnknownDirectiveKind:
        pass
    # untrusted data never becomes a directive
    assert parse_untrusted('Emit({"text": "hi"})').directive is None
    # decide is pure
    def action(state, signal):
        return {"seen": signal.payload}

    router = SignalRouter({"say": action})
    signal = Signal("say", "hello")
    first = decide({"n": 0}, signal, router)
    second = decide({"n": 0}, signal, router)
    assert first == second
    assert first.state == {"seen": "hello"}
    print("effect-directive OK: closed set, host-only minting, pure decide")


if __name__ == "__main__":
    main()
