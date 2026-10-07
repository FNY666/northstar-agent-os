"""Property-based testing interface (Hypothesis shaped, simulated).

Research motivation: example-based tests only check what the author
thought of. Property-based testing inverts the burden: the author
states an *invariant* (``forall x: f(x) >= 0``) and the machine hunts
for counterexamples. Hypothesis made this practical with two ideas
this module books:

- *strategies*: declarative value generators (``ints()``,
  ``text()``, ``lists(...)``) that describe the input space instead
  of enumerating it;
- *shrinking*: when a counterexample is found, the machine
  deterministically reduces it to a *minimal* failing case, so the
  human debugs the small lie instead of the large one.

This module is the *bookkeeping* half of that shape:

- ``PropertyTester`` -- owns the strategy registry and the run
  ledger. ``given()`` registers a strategy under a ``case-N`` id;
  ``example()`` draws one deterministic example; ``check()`` runs a
  host-supplied property over N deterministic examples and books a
  frozen ``TestRun``; ``shrink()`` reduces a failing value to a
  minimal failing case and books a frozen ``ShrinkReport``.
- Strategy constructors -- ``ints()``, ``floats()``, ``bools()``,
  ``text()``, ``lists()``, ``sampled_from()``, ``one_of()``,
  ``tuples()``, ``dicts()``, ``none()``, ``just()`` -- each returns
  a frozen, digest-pinned ``Strategy``.
- ``property_tester_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``given-registered`` / ``checked`` / ``example-drawn`` /
  ``shrunk`` / ``rejected``); ids and digest pins only -- example
  values never cross the audit boundary.

Fail-closed edges (fail loudly, never guess):

- Strategy bounds are validated at construction: ``min > max``,
  empty alphabets, empty ``sampled_from``/``one_of``/``tuples``,
  non-``Strategy`` elements, bool bounds, and non-finite float
  bounds all raise ``BadStrategyError``.
- ``check()`` requires a callable property (``BadPropertyError``)
  and ``1 <= max_examples <= 10000``; ``shrink()`` requires the
  candidate to actually fail the property (``NotFailingError``) and
  requires canonicalizable values (NaN/inf and unsupported types
  raise ``BadValueError``).
- Mutating calls consume strictly increasing caller-supplied int
  seqs (no wall-clock); rewinds raise ``SeqOrderError``. A failed
  mutation consumes its seq (fail-closed ledger position).
- Unknown case/run ids raise ``UnknownCaseError`` /
  ``UnknownRunError`` -- never invented.

Honest scope:

- This module is simulated bookkeeping, not a statistical engine:
  draws come from a sha256-chained deterministic PRNG (replayable
  per seed, not a randomness-quality claim), shrinking finds *a*
  local minimum under the pinned candidate order (not a proven
  global minimum), and a property exception counts as a failure.
- ``one_of`` / ``sampled_from`` / ``just`` values are atomic for
  shrinking (documented); shrinking explores *within* the
  strategy's draw bounds.
- The property predicate is host-reported: a lying predicate gets
  a lying ledger (GIGO boundary).
- In-memory only: pair with the durable audit writer if run
  history must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
PROPERTY_TESTER_VERSION = "property-tester.v1"

#: Schema pin carried by records and audit events.
PROPERTY_TESTER_SCHEMA = "northstar.property-tester.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Strategy kinds (pinned vocabulary).
INT = "ints"
FLOAT = "floats"
BOOL = "bools"
TEXT = "text"
LIST = "lists"
SAMPLED = "sampled_from"
ONE_OF = "one_of"
TUPLE = "tuples"
DICT = "dicts"
NONE = "none"
JUST = "just"
STRATEGY_KINDS: Tuple[str, ...] = (
    INT, FLOAT, BOOL, TEXT, LIST, SAMPLED, ONE_OF, TUPLE, DICT, NONE, JUST,
)

#: Audit event kinds.
KIND_GIVEN = "given-registered"
KIND_CHECKED = "checked"
KIND_EXAMPLE = "example-drawn"
KIND_SHRUNK = "shrunk"
KIND_REJECTED = "rejected"
_KINDS = (KIND_GIVEN, KIND_CHECKED, KIND_EXAMPLE, KIND_SHRUNK, KIND_REJECTED)

#: Hard caps (guardrails).
MAX_SIZE = 64          # max min_size/max_size for text/lists/dicts
MAX_EXAMPLES = 10000   # max max_examples for check()
MAX_FAILURES = 5       # failing examples stored per run
MAX_SHRINK_STEPS = 256  # shrink loop bound
MAX_SHRINK_CANDIDATES = 64  # candidates considered per shrink round
MAX_REPR = 500         # failure preview truncation


class PropertyTesterError(Exception):
    """Base error for the property tester."""


class BadStrategyError(PropertyTesterError):
    """A strategy constructor got invalid bounds/arguments."""


class BadValueError(PropertyTesterError):
    """A value is not canonicalizable (NaN/inf, unsupported type)."""


class BadPropertyError(PropertyTesterError):
    """check()/shrink() got a non-callable property or bad options."""


class NotFailingError(PropertyTesterError):
    """shrink() was given a value that does not fail the property."""


class UnknownCaseError(PropertyTesterError):
    """A case id lookup missed the strategy registry."""


class UnknownRunError(PropertyTesterError):
    """A run id lookup missed the run ledger."""


class SeqOrderError(PropertyTesterError):
    """A caller seq is not a strictly increasing int (no wall-clock)."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadStrategyError(f"{what} must be an int (not bool)")
    return value


def _pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


def _canon(value: Any) -> Any:
    """Type-tagged canonical form of a drawn value (for digest pins)."""
    if value is None:
        return ["none"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, int):
        return ["int", value]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise BadValueError("non-finite floats are not canonicalizable")
        return ["float", value]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, (list, tuple)):
        return ["list", [_canon(v) for v in value]]
    if isinstance(value, dict):
        items = sorted(
            ((_canon(k), _canon(v)) for k, v in value.items()),
            key=lambda kv: jcs_canonical_json(kv[0]),
        )
        return ["dict", items]
    raise BadValueError(f"unsupported value type: {type(value).__name__}")


@dataclass(frozen=True)
class Strategy:
    """A frozen, digest-pinned value generator descriptor.

    ``kind`` is one of ``STRATEGY_KINDS``; ``params`` is a tuple of
    (name, value) pairs where nested strategies stay ``Strategy``
    objects (frozen, so the whole tree is immutable).
    """

    kind: str
    params: Tuple[Tuple[str, Any], ...]
    version: str = PROPERTY_TESTER_VERSION
    schema: str = PROPERTY_TESTER_SCHEMA

    def param(self, name: str) -> Any:
        return dict(self.params)[name]


def _strategy_canon(strategy: Strategy) -> Any:
    def pc(value: Any) -> Any:
        if isinstance(value, Strategy):
            return _strategy_canon(value)
        if isinstance(value, (tuple, list)):
            return [pc(v) for v in value]
        return _canon(value)

    return {"kind": strategy.kind,
            "params": {k: pc(v) for k, v in strategy.params}}


def _strategy_digest(strategy: Strategy) -> str:
    return _pin(_strategy_canon(strategy))


def _check_size_bounds(min_size: int, max_size: int, what: str) -> None:
    _check_int(min_size, f"{what} min_size")
    _check_int(max_size, f"{what} max_size")
    if not 0 <= min_size <= max_size <= MAX_SIZE:
        raise BadStrategyError(
            f"{what} sizes must satisfy 0 <= min_size <= max_size <= {MAX_SIZE}"
        )


def ints(min_value: int = -(2 ** 63),
         max_value: int = 2 ** 63 - 1) -> Strategy:
    """Integers in [min_value, max_value] (inclusive)."""
    _check_int(min_value, "min_value")
    _check_int(max_value, "max_value")
    if min_value > max_value:
        raise BadStrategyError("ints: min_value must be <= max_value")
    return Strategy(INT, (("min_value", min_value), ("max_value", max_value)))


def floats(min_value: float = -1.0e308,
           max_value: float = 1.0e308) -> Strategy:
    """Finite floats in [min_value, max_value]."""
    for name, bound in (("min_value", min_value), ("max_value", max_value)):
        if isinstance(bound, bool) or not isinstance(bound, (int, float)):
            raise BadStrategyError(f"floats: {name} must be a real number")
        if not math.isfinite(float(bound)):
            raise BadStrategyError(f"floats: {name} must be finite")
    lo, hi = float(min_value), float(max_value)
    if lo > hi:
        raise BadStrategyError("floats: min_value must be <= max_value")
    return Strategy(FLOAT, (("min_value", lo), ("max_value", hi)))


def bools() -> Strategy:
    """Booleans."""
    return Strategy(BOOL, ())


def text(min_size: int = 0, max_size: int = 8,
         alphabet: str = "abcdefghijklmnopqrstuvwxyz") -> Strategy:
    """Strings over ``alphabet`` with length in [min_size, max_size]."""
    _check_size_bounds(min_size, max_size, "text")
    if not isinstance(alphabet, str) or not alphabet:
        raise BadStrategyError("text: alphabet must be a non-empty str")
    return Strategy(TEXT, (("min_size", min_size), ("max_size", max_size),
                           ("alphabet", alphabet)))


def lists(elements: Strategy, min_size: int = 0,
           max_size: int = 8) -> Strategy:
    """Lists of ``elements`` with length in [min_size, max_size]."""
    if not isinstance(elements, Strategy):
        raise BadStrategyError("lists: elements must be a Strategy")
    _check_size_bounds(min_size, max_size, "lists")
    return Strategy(LIST, (("elements", elements), ("min_size", min_size),
                           ("max_size", max_size)))


def sampled_from(values: Any) -> Strategy:
    """One of the given concrete values (atomic for shrinking)."""
    if isinstance(values, (str, bytes)) or not isinstance(values, (tuple, list)):
        raise BadStrategyError("sampled_from: values must be a tuple/list")
    values = tuple(values)
    if not values:
        raise BadStrategyError("sampled_from: values must be non-empty")
    for v in values:
        _canon(v)  # fail fast on non-canonicalizable values
    return Strategy(SAMPLED, (("values", values),))


def one_of(*strategies: Strategy) -> Strategy:
    """Draw from one of the given strategies (atomic for shrinking)."""
    if not strategies:
        raise BadStrategyError("one_of: at least one strategy is required")
    for s in strategies:
        if not isinstance(s, Strategy):
            raise BadStrategyError("one_of: all arguments must be Strategy")
    return Strategy(ONE_OF, (("strategies", tuple(strategies)),))


def tuples(*strategies: Strategy) -> Strategy:
    """Fixed-length tuples, one draw per strategy."""
    if not strategies:
        raise BadStrategyError("tuples: at least one strategy is required")
    for s in strategies:
        if not isinstance(s, Strategy):
            raise BadStrategyError("tuples: all arguments must be Strategy")
    return Strategy(TUPLE, (("strategies", tuple(strategies)),))


def dicts(keys: Strategy, values: Strategy, min_size: int = 0,
          max_size: int = 4) -> Strategy:
    """Dicts with drawn keys/values, size in [min_size, max_size]."""
    if not isinstance(keys, Strategy) or not isinstance(values, Strategy):
        raise BadStrategyError("dicts: keys and values must be Strategy")
    _check_size_bounds(min_size, max_size, "dicts")
    return Strategy(DICT, (("keys", keys), ("values", values),
                           ("min_size", min_size), ("max_size", max_size)))


def none() -> Strategy:
    """Always None."""
    return Strategy(NONE, ())


def just(value: Any) -> Strategy:
    """Always ``value`` (atomic for shrinking)."""
    _canon(value)
    return Strategy(JUST, (("value", value),))


class _Rng:
    """sha256-chained deterministic PRNG (replayable, not a quality claim)."""

    def __init__(self, seed: bytes) -> None:
        self._state = hashlib.sha256(b"property-tester.v1|" + seed).digest()

    def _next64(self) -> int:
        self._state = hashlib.sha256(self._state).digest()
        return int.from_bytes(self._state[:8], "big")

    def _next_bytes(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            self._state = hashlib.sha256(self._state).digest()
            out += self._state
        return out[:n]

    def randbelow(self, n: int) -> int:
        if n <= 1:
            return 0
        bits = n.bit_length()
        nbytes = (bits + 7) // 8
        shift = nbytes * 8 - bits
        while True:
            v = int.from_bytes(self._next_bytes(nbytes), "big") >> shift
            if v < n:
                return v

    def random(self) -> float:
        return self._next64() / 18446744073709551616.0

    def choice(self, seq: Any) -> Any:
        return seq[self.randbelow(len(seq))]


def _draw(strategy: Strategy, rng: _Rng) -> Any:
    """Draw one value from ``strategy`` using ``rng`` (deterministic)."""
    kind = strategy.kind
    p = dict(strategy.params)
    if kind == INT:
        lo, hi = p["min_value"], p["max_value"]
        return lo + rng.randbelow(hi - lo + 1)
    if kind == FLOAT:
        lo, hi = p["min_value"], p["max_value"]
        if lo == hi:
            return lo
        return lo + rng.random() * (hi - lo)
    if kind == BOOL:
        return bool(rng.randbelow(2))
    if kind == TEXT:
        n = p["min_size"] + rng.randbelow(p["max_size"] - p["min_size"] + 1)
        return "".join(rng.choice(p["alphabet"]) for _ in range(n))
    if kind == LIST:
        n = p["min_size"] + rng.randbelow(p["max_size"] - p["min_size"] + 1)
        return [_draw(p["elements"], rng) for _ in range(n)]
    if kind == SAMPLED:
        return rng.choice(p["values"])
    if kind == ONE_OF:
        return _draw(rng.choice(p["strategies"]), rng)
    if kind == TUPLE:
        return tuple(_draw(s, rng) for s in p["strategies"])
    if kind == DICT:
        n = p["min_size"] + rng.randbelow(p["max_size"] - p["min_size"] + 1)
        out: Dict[Any, Any] = {}
        for _ in range(n):
            k = _draw(p["keys"], rng)
            v = _draw(p["values"], rng)
            try:
                out[k] = v
            except TypeError:
                pass  # unhashable key draw: skip the pair, stay deterministic
        return out
    if kind == NONE:
        return None
    if kind == JUST:
        return p["value"]
    raise BadStrategyError(f"unknown strategy kind: {kind!r}")


def _toward_zero_half(value: int) -> int:
    return math.trunc(value / 2)


def _int_candidates(lo: int, hi: int, value: int) -> List[int]:
    """Simpler-first int candidates: abs strictly decreases on adoption."""
    out: List[int] = []
    if lo <= 0 <= hi and value != 0:
        out.append(0)
    seen = {value, 0}
    ladder = []
    v = value
    while v != 0:
        v = _toward_zero_half(v)
        ladder.append(v)
    pool = ladder + [lo, hi]
    if value > 0:
        pool.append(value - 1)
    elif value < 0:
        pool.append(value + 1)
    for c in sorted(set(pool), key=abs):
        if c != value and c not in seen and lo <= c <= hi and abs(c) <= abs(value):
            seen.add(c)
            out.append(c)
    return out


def _float_candidates(lo: float, hi: float, value: float) -> List[float]:
    out: List[float] = []
    if lo <= 0.0 <= hi and value != 0.0:
        out.append(0.0)
    seen = {value, 0.0}
    ladder = []
    v = value
    while v != 0.0:
        v = v / 2.0
        ladder.append(v)
        if len(ladder) > 64:
            break
    for c in sorted(set(ladder + [lo, hi]), key=abs):
        if (c != value and c not in seen and lo <= c <= hi
                and abs(c) <= abs(value) and math.isfinite(c)):
            seen.add(c)
            out.append(c)
    return out


def _shrink_candidates(strategy: Strategy, value: Any) -> List[Any]:
    """Simpler-first shrink candidates for ``value`` (bounded, deterministic).

    Shrinking stays within the strategy's draw bounds; every candidate
    is strictly "simpler" than ``value`` under the kind's order, so the
    shrink loop terminates.
    """
    kind = strategy.kind
    p = dict(strategy.params)
    cands: List[Any] = []
    if kind == INT and isinstance(value, int) and not isinstance(value, bool):
        cands = _int_candidates(p["min_value"], p["max_value"], value)
    elif kind == FLOAT and isinstance(value, float):
        cands = _float_candidates(p["min_value"], p["max_value"], value)
    elif kind == BOOL and value is True:
        cands = [False]
    elif kind == TEXT and isinstance(value, str):
        n, lo_n = len(value), p["min_size"]
        lengths = {lo_n}
        k = n
        while k > lo_n:
            k //= 2
            if k >= lo_n:
                lengths.add(k)
        for ln in sorted(lengths):
            if ln < n:
                cands.append(value[:ln])
    elif kind == LIST and isinstance(value, list):
        n, lo_n, elem = len(value), p["min_size"], p["elements"]
        if lo_n == 0 and n > 0:
            cands.append([])
        k = n
        while k > lo_n:
            k //= 2
            if lo_n <= k < n:
                cands.append(value[:k])
        for i in range(min(n, 8)):
            if n - 1 >= lo_n:
                cands.append(value[:i] + value[i + 1:])
        for i in range(min(n, 4)):
            for c in _shrink_candidates(elem, value[i])[:2]:
                cands.append(value[:i] + [c] + value[i + 1:])
    elif kind == TUPLE and isinstance(value, tuple):
        strats = p["strategies"]
        for i in range(len(value)):
            for c in _shrink_candidates(strats[i], value[i])[:2]:
                cands.append(value[:i] + (c,) + value[i + 1:])
    elif kind == DICT and isinstance(value, dict):
        lo_n = p["min_size"]
        keys = list(value.keys())
        if lo_n == 0 and keys:
            cands.append({})
        for k in keys[:8]:
            if len(value) - 1 >= lo_n:
                cands.append({kk: vv for kk, vv in value.items() if kk != k})
        if keys:
            k0 = keys[0]
            for c in _shrink_candidates(p["values"], value[k0])[:2]:
                cands.append({**value, k0: c})
    # SAMPLED / ONE_OF / NONE / JUST are atomic for shrinking: no candidates.
    seen: List[Any] = []
    for c in cands:
        if c not in seen:
            seen.append(c)
    return seen[:MAX_SHRINK_CANDIDATES]


def _fails(prop: Callable[[Any], Any], value: Any) -> bool:
    """True when ``value`` fails the property (exceptions count as failures)."""
    try:
        return not prop(value)
    except Exception:
        return True


@dataclass(frozen=True)
class GivenHandle:
    """A registered strategy: ``case-N`` id plus its digest pin."""

    case_id: str
    strategy: Strategy
    strategy_digest: str
    seq: int
    digest: str
    version: str = PROPERTY_TESTER_VERSION
    schema: str = PROPERTY_TESTER_SCHEMA


@dataclass(frozen=True)
class ExampleRecord:
    """One deterministic draw from a registered strategy."""

    example_id: str
    case_id: str
    value: Any
    digest: str
    seq: int
    version: str = PROPERTY_TESTER_VERSION
    schema: str = PROPERTY_TESTER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            _canon(self.value), self.case_id, self.example_id)


@dataclass(frozen=True)
class FailureRecord:
    """One failing example: digest pin plus a truncated preview."""

    digest: str
    preview: str


@dataclass(frozen=True)
class TestRun:
    """Booked outcome of running a property over N examples."""

    run_id: str
    case_id: str
    max_examples: int
    examples_run: int
    passed: bool
    failures: Tuple[FailureRecord, ...]
    seq: int
    digest: str
    version: str = PROPERTY_TESTER_VERSION
    schema: str = PROPERTY_TESTER_SCHEMA


@dataclass(frozen=True)
class ShrinkReport:
    """Minimal failing case found by deterministic shrinking."""

    shrink_id: str
    case_id: str
    original_digest: str
    minimal: Any
    minimal_digest: str
    steps: int
    still_fails: bool
    seq: int
    digest: str
    version: str = PROPERTY_TESTER_VERSION
    schema: str = PROPERTY_TESTER_SCHEMA


class PropertyTester:
    """Deterministic property-based testing bookkeeping (simulated).

    All draws are replayable from the constructor ``seed``; every
    mutation books a frozen, digest-pinned record under a strictly
    increasing caller seq (no wall-clock).
    """

    def __init__(self, seed: Any = b"property-tester.v1") -> None:
        if isinstance(seed, str):
            seed = seed.encode("utf-8")
        if not isinstance(seed, (bytes, bytearray)) or not seed:
            raise PropertyTesterError("seed must be non-empty bytes or str")
        self._seed = bytes(seed)
        self._lock = threading.RLock()
        self._last_seq = -1
        self._case_n = 0
        self._run_n = 0
        self._example_n = 0
        self._shrink_n = 0
        self._cases: Dict[str, GivenHandle] = {}
        self._runs: Dict[str, TestRun] = {}
        self._draw_counts: Dict[Tuple[str, str], int] = {}
        self._audit: List[Dict[str, Any]] = []

    @staticmethod
    def strategy_kinds() -> Tuple[str, ...]:
        """The pinned strategy vocabulary."""
        return STRATEGY_KINDS

    def _claim_seq(self, seq: Any) -> int:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _log(self, kind: str, seq: int, detail: Dict[str, Any]) -> None:
        self._audit.append(property_tester_audit_event(kind, seq, detail))

    def _draw_value(self, case_id: str, purpose: str) -> Any:
        handle = self._cases[case_id]
        key = (case_id, purpose)
        idx = self._draw_counts.get(key, 0)
        self._draw_counts[key] = idx + 1
        material = (self._seed + b"|" + case_id.encode("utf-8") + b"|"
                    + purpose.encode("utf-8") + b"|" + str(idx).encode("ascii"))
        return _draw(handle.strategy, _Rng(material))

    def given(self, strategy: Strategy, seq: int) -> GivenHandle:
        """Register ``strategy``; returns its ``case-N`` handle."""
        with self._lock:
            self._claim_seq(seq)
            if not isinstance(strategy, Strategy):
                raise BadStrategyError("given: strategy must be a Strategy")
            if strategy.kind not in STRATEGY_KINDS:
                raise BadStrategyError(
                    f"given: unknown strategy kind {strategy.kind!r}")
            self._case_n += 1
            case_id = f"case-{self._case_n}"
            sdigest = _strategy_digest(strategy)
            handle = GivenHandle(
                case_id=case_id, strategy=strategy,
                strategy_digest=sdigest, seq=seq,
                digest=_pin(case_id, sdigest, seq))
            self._cases[case_id] = handle
            self._log(KIND_GIVEN, seq,
                      {"case_id": case_id, "strategy_digest": sdigest})
            return handle

    def example(self, case_id: str, seq: int) -> ExampleRecord:
        """Draw one deterministic example from a registered strategy."""
        with self._lock:
            self._claim_seq(seq)
            if case_id not in self._cases:
                raise UnknownCaseError(f"unknown case_id: {case_id!r}")
            value = self._draw_value(case_id, "example")
            self._example_n += 1
            example_id = f"ex-{self._example_n}"
            rec = ExampleRecord(
                example_id=example_id, case_id=case_id, value=value,
                digest=_pin(_canon(value), case_id, example_id), seq=seq)
            self._log(KIND_EXAMPLE, seq,
                      {"case_id": case_id, "example_id": example_id,
                       "digest": rec.digest})
            return rec

    def check(self, case_id: str, property_fn: Callable[[Any], Any],
              seq: int, max_examples: int = 100) -> TestRun:
        """Run ``property_fn`` over ``max_examples`` draws; book the run.

        ``property_fn`` returning falsy -- or raising -- counts as a
        failure for that example. Runs all examples; stores up to
        ``MAX_FAILURES`` failing previews.
        """
        with self._lock:
            self._claim_seq(seq)
            if case_id not in self._cases:
                raise UnknownCaseError(f"unknown case_id: {case_id!r}")
            if not callable(property_fn):
                raise BadPropertyError("check: property_fn must be callable")
            if (isinstance(max_examples, bool)
                    or not isinstance(max_examples, int)
                    or not 1 <= max_examples <= MAX_EXAMPLES):
                raise BadPropertyError(
                    f"check: max_examples must be an int in "
                    f"[1, {MAX_EXAMPLES}]")
            failures: List[FailureRecord] = []
            for _ in range(max_examples):
                value = self._draw_value(case_id, "check")
                if _fails(property_fn, value):
                    digest = _pin(_canon(value), case_id, "failure")
                    if len(failures) < MAX_FAILURES:
                        failures.append(FailureRecord(
                            digest=digest, preview=repr(value)[:MAX_REPR]))
            self._run_n += 1
            run_id = f"run-{self._run_n}"
            run = TestRun(
                run_id=run_id, case_id=case_id, max_examples=max_examples,
                examples_run=max_examples, passed=not failures,
                failures=tuple(failures), seq=seq,
                digest=_pin(run_id, case_id, max_examples,
                            tuple(f.digest for f in failures), seq))
            self._runs[run_id] = run
            self._log(KIND_CHECKED, seq,
                      {"case_id": case_id, "run_id": run_id,
                       "passed": run.passed,
                       "failures": len(failures)})
            return run

    def shrink(self, case_id: str, failing_value: Any,
               property_fn: Callable[[Any], Any], seq: int) -> ShrinkReport:
        """Reduce ``failing_value`` to a minimal failing case.

        ``failing_value`` must actually fail ``property_fn``
        (``NotFailingError`` otherwise). Walks simpler-first
        candidates; each adoption strictly simplifies, so the loop
        terminates within ``MAX_SHRINK_STEPS`` rounds.
        """
        with self._lock:
            self._claim_seq(seq)
            if case_id not in self._cases:
                raise UnknownCaseError(f"unknown case_id: {case_id!r}")
            if not callable(property_fn):
                raise BadPropertyError("shrink: property_fn must be callable")
            _canon(failing_value)  # fail fast on non-canonicalizable values
            if not _fails(property_fn, failing_value):
                raise NotFailingError(
                    "shrink: value does not fail the property")
            strategy = self._cases[case_id].strategy
            current = failing_value
            steps = 0
            while steps < MAX_SHRINK_STEPS:
                improved = False
                for cand in _shrink_candidates(strategy, current):
                    if _fails(property_fn, cand):
                        current = cand
                        steps += 1
                        improved = True
                        break
                if not improved:
                    break
            still = _fails(property_fn, current)
            self._shrink_n += 1
            shrink_id = f"shrink-{self._shrink_n}"
            report = ShrinkReport(
                shrink_id=shrink_id, case_id=case_id,
                original_digest=_pin(_canon(failing_value), case_id),
                minimal=current,
                minimal_digest=_pin(_canon(current), case_id, shrink_id),
                steps=steps, still_fails=still, seq=seq,
                digest=_pin(shrink_id, case_id,
                            _pin(_canon(current), case_id, shrink_id),
                            steps, still, seq))
            self._log(KIND_SHRUNK, seq,
                      {"case_id": case_id, "shrink_id": shrink_id,
                       "steps": steps, "still_fails": still,
                       "minimal_digest": report.minimal_digest})
            return report

    def case(self, case_id: str) -> GivenHandle:
        """Read back a registered strategy handle (pure view)."""
        try:
            return self._cases[case_id]
        except KeyError:
            raise UnknownCaseError(f"unknown case_id: {case_id!r}")

    def run(self, run_id: str) -> TestRun:
        """Read back a booked test run (pure view)."""
        try:
            return self._runs[run_id]
        except KeyError:
            raise UnknownRunError(f"unknown run_id: {run_id!r}")

    def case_ids(self) -> Tuple[str, ...]:
        """Registered case ids, oldest first (pure view)."""
        return tuple(self._cases)

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """The module audit ledger, oldest first (pure view)."""
        return tuple(self._audit)


def property_tester_audit_event(kind: str, seq: Any,
                                detail: Optional[Dict[str, Any]] = None
                                ) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for the property tester.

    Carries ids, kinds and digest pins only -- example values never
    cross the audit boundary.
    """
    if kind not in _KINDS:
        raise PropertyTesterError(
            f"unknown audit kind {kind!r}; expected one of {_KINDS}")
    _check_seq(seq, "seq")
    body: Dict[str, Any] = {
        "kind": kind,
        "seq": seq,
        "schema": AUDIT_SCHEMA,
        "module": PROPERTY_TESTER_VERSION,
    }
    if detail is not None:
        if not isinstance(detail, dict):
            raise PropertyTesterError("detail must be a dict or None")
        body["detail"] = _canon(detail)[1]  # the canonical item list
    body["digest"] = _pin(kind, seq, body.get("detail"))
    return body


def main() -> int:
    """Self-check: given, example, check, shrink, pins, audit."""
    t = PropertyTester()
    handle = t.given(ints(0, 100), 1)
    assert handle.case_id == "case-1"
    assert handle.strategy_digest.startswith("sha256:")
    ex = t.example(handle.case_id, 2)
    assert ex.verify()
    assert 0 <= ex.value <= 100
    run = t.check(handle.case_id, lambda x: x >= 0, 3, max_examples=10)
    assert run.passed and run.examples_run == 10
    bad = t.check(handle.case_id, lambda x: x < 0, 4, max_examples=10)
    assert not bad.passed and len(bad.failures) > 0
    rep = t.shrink(handle.case_id, 100, lambda x: x < 10, 5)
    assert rep.minimal == 10, rep.minimal
    assert rep.still_fails and rep.steps > 0
    kinds = [e["kind"] for e in t.audit_log()]
    assert kinds == [KIND_GIVEN, KIND_EXAMPLE, KIND_CHECKED, KIND_CHECKED,
                     KIND_SHRUNK], kinds
    print("property-tester OK: given, example, check, shrink, pins, audit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
