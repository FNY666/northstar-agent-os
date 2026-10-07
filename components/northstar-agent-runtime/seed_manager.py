"""Seed data manager — deterministic fixtures/factories (thirtieth batch).

Research note (fixtures/factories literature): FactoryBot (Ruby) treats
factories as *blueprints with sequences and traits* evaluated per-build;
Rails fixtures pin a static dataset; Faker separates *providers* (data
vocabulary) from the *generator* (seeded PRNG). This module takes the
intersection for a test/dev single-host ledger:

* **Blueprints over fixtures**: factories are named blueprints
  (``define_factory``); ``seed`` materialises ``count`` frozen fixture
  records from the blueprint. The blueprint, not the rows, is the
  versioned contract.
* **Seeded determinism**: every draw comes from a sha256-chained PRNG
  keyed by ``(manager seed, factory, field, row index, draw counter)``,
  so the same seed reproduces the identical fixture set on any host
  (Faker-generator discipline). ``verify()`` re-derives each record's
  digest pin.
* **Reset, not delete-in-place**: ``reset`` clears the fixture ledger
  (factories are retained — they are the contract) and books a frozen
  ``ResetRecord``.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (no wall-clock; failed mutations consume their seq), RLock
guarding, fail-closed taxonomy, stdlib-only, sha256 digest pins over
canonical payloads, ``audit.ndjson/1`` events.

Field-blueprint vocabulary (pinned):

* ``const`` — ``{"kind": "const", "value": ...}`` (str/int/bool/None)
* ``seq`` — ``{"kind": "seq", "start": int, "step": int}`` (step != 0)
* ``choice`` — ``{"kind": "choice", "options": [..non-empty..]}``
* ``int_range`` — ``{"kind": "int_range", "lo": int, "hi": int}`` (lo < hi)
* ``text`` — ``{"kind": "text", "length": int >= 1, "alphabet": non-empty str}``

Honest boundary: this module books *synthetic* fixtures deterministically.
It cannot prove the fixtures resemble production distributions, and it
never touches a real database — a consumer wires the frozen records to
its own loader. GIGO on the blueprint: garbage in, identical garbage out.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field, replace
from typing import Any, Mapping

#: Version pin for this module's record shape.
SEED_MANAGER_VERSION = "seed-manager.v1"

#: Schema pin carried by records and audit events.
SEED_MANAGER_SCHEMA = "northstar.seed-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

# ---------------------------------------------------------------------------
# Field-blueprint vocabulary
# ---------------------------------------------------------------------------

KIND_CONST = "const"
KIND_SEQ = "seq"
KIND_CHOICE = "choice"
KIND_INT_RANGE = "int_range"
KIND_TEXT = "text"
FIELD_KINDS = (KIND_CONST, KIND_SEQ, KIND_CHOICE, KIND_INT_RANGE, KIND_TEXT)

_KIND_REQUIRED = {
    KIND_CONST: ("value",),
    KIND_SEQ: ("start", "step"),
    KIND_CHOICE: ("options",),
    KIND_INT_RANGE: ("lo", "hi"),
    KIND_TEXT: ("length", "alphabet"),
}

#: Audit event kinds.
KIND_FACTORY_DEFINED = "seed.factory-defined"
KIND_SEEDED = "seed.seeded"
KIND_RESET = "seed.reset"
KIND_REJECTED = "seed.rejected"
_KINDS = (KIND_FACTORY_DEFINED, KIND_SEEDED, KIND_RESET, KIND_REJECTED)

_GENESIS = "genesis"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SeedError(ValueError):
    """Base error for the seed data manager."""


class BadFactoryError(SeedError):
    """Malformed factory definition (bad id, model, fields)."""


class DuplicateFactoryError(SeedError):
    """A factory with this id is already defined."""


class UnknownFactoryError(SeedError):
    """No factory with this id is defined."""


class BadFieldError(SeedError):
    """A field blueprint is malformed or uses an unknown kind."""


class BadSeedError(SeedError):
    """Malformed seed request (bad count, unknown factory/run)."""


class UnknownRunError(SeedError):
    """No seed run with this id exists."""


class SeqOrderError(SeedError):
    """Mutation seq is not strictly increasing."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeedError(f"{field_name} must be a non-negative int, saw {value!r}")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SeedError(f"{field_name} must be a non-empty string")
    return value.strip()


def _check_json_scalar(value: Any, field_name: str) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, (str, int)):
        return value
    raise SeedError(f"{field_name} must be str/int/bool/None, saw {type(value).__name__}")


def _check_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeedError(f"{field_name} must be an int, saw {value!r}")
    return value


# ---------------------------------------------------------------------------
# Canonical digest helpers
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    # Payloads are str/int/bool/None/dict/list only — no floats, so no
    # >2^53 precision hazard; ints serialize exactly.
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    """sha256 pin over the canonical encoding of the parts."""
    return hashlib.sha256(_canonical(list(parts))).hexdigest()


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldSpec:
    """One pinned field blueprint: ``(name, kind, params)``.

    ``params`` holds the kind's required parameters, pinned to the
    ``_KIND_REQUIRED`` table; unknown kinds and missing parameters are
    refused fail-closed at definition time.
    """

    name: str
    kind: str
    params: Mapping[str, Any]

    def __post_init__(self) -> None:
        _check_nonempty_str(self.name, "field name")
        if self.kind not in FIELD_KINDS:
            raise BadFieldError(f"field kind must be one of {FIELD_KINDS}, saw {self.kind!r}")
        required = _KIND_REQUIRED[self.kind]
        params = dict(self.params)
        for key in required:
            if key not in params:
                raise BadFieldError(f"field kind {self.kind!r} requires param {key!r}")
        if self.kind == KIND_CONST:
            _check_json_scalar(params["value"], "const value")
        elif self.kind == KIND_SEQ:
            _check_int(params["start"], "seq start")
            step = _check_int(params["step"], "seq step")
            if step == 0:
                raise BadFieldError("seq step must not be 0")
        elif self.kind == KIND_CHOICE:
            options = params["options"]
            if not isinstance(options, (list, tuple)) or not options:
                raise BadFieldError("choice options must be a non-empty list")
            for opt in options:
                _check_json_scalar(opt, "choice option")
        elif self.kind == KIND_INT_RANGE:
            lo = _check_int(params["lo"], "int_range lo")
            hi = _check_int(params["hi"], "int_range hi")
            if not lo < hi:
                raise BadFieldError("int_range requires lo < hi")
        elif self.kind == KIND_TEXT:
            length = _check_int(params["length"], "text length")
            if length < 1:
                raise BadFieldError("text length must be >= 1")
            _check_nonempty_str(params["alphabet"], "text alphabet")


@dataclass(frozen=True)
class FactoryRecord:
    """A named fixture blueprint (the versioned contract).

    ``field_specs`` is the pinned blueprint; ``digest`` seals it so a
    fixture row can always be re-tied to the blueprint that produced it.
    """

    factory_id: str
    model: str
    field_specs: tuple
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.factory_id, "factory_id")
        _check_nonempty_str(self.model, "model")
        if not isinstance(self.field_specs, tuple) or not self.field_specs:
            raise BadFactoryError("field_specs must be a non-empty tuple of FieldSpec")
        names = set()
        for spec in self.field_specs:
            if not isinstance(spec, FieldSpec):
                raise BadFactoryError("field_specs entries must be FieldSpec")
            if spec.name in names:
                raise BadFactoryError(f"duplicate field name {spec.name!r}")
            names.add(spec.name)
        _check_seq(self.seq, "seq")
        if self.digest != "" and not _is_digest(self.digest):
            raise SeedError("digest must be '' or a 64-char hex digest")

    def verify(self) -> bool:
        """Re-derive the digest pin over the blueprint."""
        return self.digest == _factory_digest(self)


def _factory_digest(record: FactoryRecord) -> str:
    return _pin(
        SEED_MANAGER_SCHEMA,
        "factory",
        record.factory_id,
        record.model,
        [
            [s.name, s.kind, {k: s.params[k] for k in sorted(s.params)}]
            for s in record.field_specs
        ],
    )


@dataclass(frozen=True)
class Fixture:
    """One materialised fixture row.

    ``values`` maps field names to drawn values; ``fixture_id`` is a
    global monotonic ``fx-N`` id; ``run_id`` names the seed run; ``digest``
    seals values + provenance (factory digest pin, row index).
    """

    fixture_id: str
    factory_id: str
    factory_digest: str
    run_id: str
    index: int
    values: Mapping[str, Any]
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.fixture_id, "fixture_id")
        _check_nonempty_str(self.factory_id, "factory_id")
        if not _is_digest(self.factory_digest):
            raise SeedError("factory_digest must be a 64-char hex digest")
        _check_nonempty_str(self.run_id, "run_id")
        _check_seq(self.index, "index")
        if not isinstance(self.values, dict) or not self.values:
            raise SeedError("values must be a non-empty dict")
        _check_seq(self.seq, "seq")
        if self.digest != "" and not _is_digest(self.digest):
            raise SeedError("digest must be '' or a 64-char hex digest")

    def verify(self) -> bool:
        """Re-derive the digest pin over values + provenance."""
        return self.digest == _fixture_digest(self)


def _fixture_digest(fixture: Fixture) -> str:
    return _pin(
        SEED_MANAGER_SCHEMA,
        "fixture",
        fixture.fixture_id,
        fixture.factory_id,
        fixture.factory_digest,
        fixture.run_id,
        fixture.index,
        dict(sorted(fixture.values.items())),
    )


@dataclass(frozen=True)
class SeedRun:
    """A frozen record of one ``seed`` invocation."""

    run_id: str
    factory_id: str
    count: int
    fixture_ids: tuple
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.run_id, "run_id")
        _check_nonempty_str(self.factory_id, "factory_id")
        _check_seq(self.count, "count")
        if self.count < 1:
            raise BadSeedError("count must be >= 1")
        if not isinstance(self.fixture_ids, tuple):
            raise SeedError("fixture_ids must be a tuple")
        if len(self.fixture_ids) != self.count:
            raise SeedError("fixture_ids length must equal count")
        _check_seq(self.seq, "seq")
        if self.digest != "" and not _is_digest(self.digest):
            raise SeedError("digest must be '' or a 64-char hex digest")

    def verify(self) -> bool:
        """Re-derive the digest pin over the run contents."""
        return self.digest == _pin(
            SEED_MANAGER_SCHEMA, "seed-run", self.run_id,
            self.factory_id, self.count, list(self.fixture_ids),
        )


@dataclass(frozen=True)
class ResetRecord:
    """A frozen record of one ``reset`` invocation.

    Factories are *retained* (they are the contract); only the fixture
    ledger is cleared. ``cleared_count`` is the number of fixtures
    dropped.
    """

    reset_id: str
    cleared_count: int
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.reset_id, "reset_id")
        _check_seq(self.cleared_count, "cleared_count")
        _check_seq(self.seq, "seq")
        if self.digest != "" and not _is_digest(self.digest):
            raise SeedError("digest must be '' or a 64-char hex digest")

    def verify(self) -> bool:
        """Re-derive the digest pin."""
        return self.digest == _pin(
            SEED_MANAGER_SCHEMA, "reset", self.reset_id, self.cleared_count,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def seed_manager_audit_event(kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the seed manager.

    Detail carries ids + digest pins only — fixture *values* never cross
    the audit boundary (fixtures may carry synthetic PII-shaped data).
    """
    if kind not in _KINDS:
        raise SeedError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "seed_manager",
        "module_version": SEED_MANAGER_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# SeedManager
# ---------------------------------------------------------------------------


class SeedManager:
    """Deterministic fixture/factory bookkeeping for tests and dev.

    Factories are named blueprints pinned at definition time; ``seed``
    materialises frozen fixture rows from a blueprint using a
    sha256-chained PRNG keyed by ``(manager seed, factory, field, row
    index, draw counter)`` — identical seeds reproduce identical rows on
    any host. ``reset`` clears the fixture ledger (factories retained)
    and books a ``ResetRecord``. ``factory`` is a pure read view.

    Mutation seqs must be strictly increasing; failed mutations consume
    their seq (batch-21 ledger discipline). No wall-clock, no RNG beyond
    the deterministic PRNG, stdlib-only.
    """

    def __init__(self, seed: int = 0) -> None:
        _check_seq(seed, "seed")
        self._master = hashlib.sha256(
            f"{SEED_MANAGER_VERSION}:{seed}".encode("utf-8")
        ).digest()
        self._lock = threading.RLock()
        self._last_seq = 0
        self._factories: dict[str, FactoryRecord] = {}
        self._runs: dict[str, SeedRun] = {}
        self._fixtures: dict[str, Fixture] = {}
        self._audit: list[Mapping[str, Any]] = []
        self._run_counter = 0
        self._fixture_counter = 0
        self._reset_counter = 0

    # -- internal ---------------------------------------------------------

    def _claim_seq(self, seq: int) -> None:
        # Called first in every mutation: a refused mutation still
        # consumes its seq, keeping the ledger totally ordered.
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be an int strictly greater than {self._last_seq}, saw {seq!r}"
            )
        self._last_seq = seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(seed_manager_audit_event(kind, seq, **detail))

    def _draw(self, *parts: str, counter: int = 0) -> bytes:
        h = hashlib.sha256()
        h.update(self._master)
        for part in parts:
            h.update(b"\x00" + str(part).encode("utf-8"))
        h.update(b"\x01" + str(counter).encode("utf-8"))
        return h.digest()

    def _randbelow(self, n: int, *parts: str) -> int:
        """Deterministic uniform draw from range(n), n >= 1."""
        n = _check_int(n, "n")
        if n < 1:
            raise SeedError("draw range must be >= 1")
        width = (n - 1).bit_length()
        nbytes = max(1, (width + 7) // 8)
        counter = 0
        while True:
            for i in range(8):
                raw = self._draw(*parts, counter=counter)
                x = int.from_bytes(raw[:nbytes], "big") >> max(0, nbytes * 8 - width)
                if x < n:
                    return x
                counter += 1

    def _generate(self, spec: FieldSpec, factory_id: str, index: int) -> Any:
        parts = (factory_id, spec.name, str(index))
        kind = spec.kind
        params = spec.params
        if kind == KIND_CONST:
            return params["value"]
        if kind == KIND_SEQ:
            return params["start"] + index * params["step"]
        if kind == KIND_CHOICE:
            options = list(params["options"])
            return options[self._randbelow(len(options), "choice", *parts)]
        if kind == KIND_INT_RANGE:
            lo, hi = params["lo"], params["hi"]
            return lo + self._randbelow(hi - lo, "int-range", *parts)
        # KIND_TEXT
        length, alphabet = params["length"], params["alphabet"]
        return "".join(
            alphabet[self._randbelow(len(alphabet), "text", *parts, str(pos))]
            for pos in range(length)
        )

    # -- mutations ----------------------------------------------------------

    def define_factory(
        self,
        factory_id: str,
        model: str,
        fields: tuple,
        seq: int,
    ) -> FactoryRecord:
        """Define a named fixture blueprint (frozen, digest-pinned).

        ``fields`` is a non-empty tuple of ``FieldSpec``; duplicate
        factory ids are refused fail-closed.
        """
        with self._lock:
            self._claim_seq(seq)
            _check_nonempty_str(factory_id, "factory_id")
            if factory_id in self._factories:
                raise DuplicateFactoryError(f"factory already defined: {factory_id!r}")
            _check_nonempty_str(model, "model")
            if not isinstance(fields, tuple) or not fields:
                raise BadFactoryError("fields must be a non-empty tuple of FieldSpec")
            for spec in fields:
                if not isinstance(spec, FieldSpec):
                    raise BadFactoryError("fields entries must be FieldSpec")
            record = FactoryRecord(
                factory_id=factory_id,
                model=model,
                field_specs=fields,
                seq=seq,
                digest="",
            )
            record = replace(record, digest=_factory_digest(record))
            self._factories[factory_id] = record
            self._emit(
                KIND_FACTORY_DEFINED,
                seq,
                factory_id=factory_id,
                model=model,
                digest=record.digest,
            )
            return record

    def seed(self, factory_id: str, count: int, seq: int) -> SeedRun:
        """Materialise ``count`` frozen fixtures from a blueprint.

        Returns the frozen ``SeedRun``; rows are readable via
        :meth:`fixtures_of`. Deterministic: the same manager seed,
        factory and row index always draw the same values.
        """
        with self._lock:
            self._claim_seq(seq)
            if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                raise BadSeedError(f"count must be an int >= 1, saw {count!r}")
            try:
                factory = self._factories[factory_id]
            except KeyError:
                raise UnknownFactoryError(f"unknown factory: {factory_id!r}") from None
            self._run_counter += 1
            run_id = f"run-{self._run_counter}"
            fixture_ids: list[str] = []
            for index in range(count):
                self._fixture_counter += 1
                fixture_id = f"fx-{self._fixture_counter}"
                values = {
                    spec.name: self._generate(spec, factory_id, index)
                    for spec in factory.field_specs
                }
                fixture = Fixture(
                    fixture_id=fixture_id,
                    factory_id=factory_id,
                    factory_digest=factory.digest,
                    run_id=run_id,
                    index=index,
                    values=values,
                    seq=seq,
                )
                fixture = replace(fixture, digest=_fixture_digest(fixture))
                self._fixtures[fixture_id] = fixture
                fixture_ids.append(fixture_id)
            run = SeedRun(
                run_id=run_id,
                factory_id=factory_id,
                count=count,
                fixture_ids=tuple(fixture_ids),
                seq=seq,
            )
            run = replace(run, digest=_pin(
                SEED_MANAGER_SCHEMA, "seed-run", run.run_id,
                run.factory_id, run.count, list(run.fixture_ids),
            ))
            self._runs[run_id] = run
            self._emit(
                KIND_SEEDED,
                seq,
                run_id=run_id,
                factory_id=factory_id,
                count=count,
                digest=run.digest,
            )
            return run

    def reset(self, seq: int) -> ResetRecord:
        """Clear the fixture ledger (factories are retained).

        Returns a frozen ``ResetRecord`` recording how many fixtures were
        dropped. Resetting an empty ledger is valid and books a record
        with ``cleared_count`` 0.
        """
        with self._lock:
            self._claim_seq(seq)
            self._reset_counter += 1
            reset_id = f"reset-{self._reset_counter}"
            cleared = len(self._fixtures)
            self._fixtures.clear()
            self._runs.clear()
            record = ResetRecord(reset_id=reset_id, cleared_count=cleared, seq=seq)
            record = replace(record, digest=_pin(
                SEED_MANAGER_SCHEMA, "reset", record.reset_id, record.cleared_count,
            ))
            self._emit(
                KIND_RESET,
                seq,
                reset_id=reset_id,
                cleared_count=cleared,
                digest=record.digest,
            )
            return record

    # -- views ---------------------------------------------------------------

    def factory(self, factory_id: str) -> FactoryRecord:
        """Pure read view of a defined factory blueprint."""
        with self._lock:
            try:
                return self._factories[factory_id]
            except KeyError:
                raise UnknownFactoryError(f"unknown factory: {factory_id!r}") from None

    def factory_ids(self) -> tuple:
        """Sorted defined factory ids."""
        with self._lock:
            return tuple(sorted(self._factories))

    def run(self, run_id: str) -> SeedRun:
        """Pure read view of a seed run."""
        with self._lock:
            try:
                return self._runs[run_id]
            except KeyError:
                raise UnknownRunError(f"unknown run: {run_id!r}") from None

    def run_ids(self) -> tuple:
        """Sorted seed run ids."""
        with self._lock:
            return tuple(sorted(self._runs))

    def fixture(self, fixture_id: str) -> Fixture:
        """Pure read view of one fixture row."""
        with self._lock:
            try:
                return self._fixtures[fixture_id]
            except KeyError:
                raise SeedError(f"unknown fixture: {fixture_id!r}") from None

    def fixtures_of(self, run_id: str) -> tuple:
        """All fixtures of a run, in index order."""
        run = self.run(run_id)
        with self._lock:
            return tuple(self._fixtures[fid] for fid in run.fixture_ids)

    def fixture_count(self) -> int:
        """Number of live fixtures in the ledger."""
        with self._lock:
            return len(self._fixtures)

    def audit_log(self) -> tuple:
        """Append-only audit events (ids + digests only)."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: define, seed, read, reset, pins."""
    mgr = SeedManager(seed=7)
    fields = (
        FieldSpec("name", KIND_TEXT, {"length": 6, "alphabet": "abc"}),
        FieldSpec("age", KIND_INT_RANGE, {"lo": 18, "hi": 66}),
        FieldSpec("role", KIND_CHOICE, {"options": ["user", "admin"]}),
        FieldSpec("n", KIND_SEQ, {"start": 100, "step": 10}),
        FieldSpec("active", KIND_CONST, {"value": True}),
    )
    factory = mgr.define_factory("users", "User", fields, seq=1)
    assert factory.verify()
    run = mgr.seed("users", 3, seq=2)
    assert run.verify() and mgr.fixture_count() == 3
    rows = mgr.fixtures_of(run.run_id)
    assert len(rows) == 3 and all(f.verify() for f in rows)
    assert rows[0].values["n"] == 100 and rows[2].values["n"] == 120
    # Determinism: same seed reproduces the same digests.
    other = SeedManager(seed=7)
    other.define_factory("users", "User", fields, seq=1)
    other_run = other.seed("users", 3, seq=2)
    assert other_run.digest == run.digest
    reset = mgr.reset(seq=3)
    assert reset.cleared_count == 3 and mgr.fixture_count() == 0
    assert mgr.factory_ids() == ("users",)  # factories retained
    print("seed-manager OK: define, seed, factory, reset, pins, audit")


if __name__ == "__main__":
    main()
