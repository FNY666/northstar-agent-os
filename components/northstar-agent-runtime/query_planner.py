"""Query planner: cost-based query planning as a deterministic state machine.

Research motivation: a query planner decides *how* a query runs, and a
planner that mis-estimates cost, silently drops a filter, or joins in an
order that explodes intermediate size can turn a cheap query into a
full-table catastrophe. This module is the *bookkeeping* half of a
cost-based planner (the Selinger/System-R tradition): it pins
host-declared table statistics, generates a deterministic physical plan
from a logical query spec, estimates per-step costs with pure integer
arithmetic, and applies deterministic rewrite rules in ``optimize()``
(join reordering by estimated intermediate size, join-algorithm choice
by cost, filter pushdown, limit placement). It never executes a query,
never touches storage, and never measures real time -- the host applies
the booked plan and reports real outcomes; this ledger only proves what
was declared, estimated, and chosen.

Public API:

- ``QueryPlanner`` -- RLock-guarded registry.
  ``register_stats(table_id, row_count, seq)`` pins host-declared
  table cardinality (GIGO: a lying host gets a perfectly consistent
  ledger of lies). ``plan(plan_id, query, seq)`` books a physical
  plan for a logical query spec and its total estimated cost.
  ``cost(plan_id, seq)`` is a pure read view returning the per-step
  cost breakdown (validates seq shape, consumes nothing, writes no
  audit row). ``optimize(plan_id, seq)`` books a rewritten plan --
  joins reordered by estimated cost, algorithm chosen per join --
  with before/after costs.
- ``query_planner_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records, fixed kind vocabulary:
  ``"query.planned"``, ``"query.costed"`` (never emitted -- cost is a
  pure read), ``"query.optimized"``, ``"stats.registered"``,
  ``"query.rejected"``.

Query spec shape (a Mapping):

- ``tables``: non-empty tuple/list of table ids (1..16).
- ``filters``: optional tuple of ``(table, field, op, value)``;
  ``op`` in ``== != < <= > >=``; the table must be listed in
  ``tables``.
- ``joins``: optional tuple of
  ``(left_table, right_table, left_key, right_key)``; tables must be
  listed, and the join graph must connect the tables in declared
  order (fail-closed otherwise).
- ``projections``: optional tuple of field names.
- ``sort``: optional ``(field, direction)`` with direction
  ``"asc"``/``"desc"``.
- ``limit``: optional positive int (<= 1_000_000_000).

Physical operators and the integer cost model (no floats anywhere):

- ``scan(table)``: cost = rows, est_rows = rows.
- ``filter``: cost = input rows; selectivity ``==`` -> 1/10,
  ``!=`` -> 9/10, ranges -> 1/3 (integer floor, min 1 row).
- ``hash_join``: cost = left + right;
  est_rows = max(1, min(left, right) // 10).
- ``nested_loop_join``: cost = min(left * right, 2**53 - 1);
  est_rows = max(1, min(left, right) // 10).
- ``project``: cost = input rows, est_rows unchanged.
- ``sort``: cost = input rows * 2, est_rows unchanged.
- ``limit(n)``: cost = est_rows = min(input rows, n).

The planner picks the cheaper join algorithm per join (ties -> hash
join, deterministic). ``optimize()`` additionally reorders joins
greedy by smallest estimated intermediate (ties -> table id), so an
optimized plan never costs more than the original.

Honest scope:

- Statistics are host-declared; the module cannot verify a table
  really holds ``row_count`` rows. Cost estimates are decisions about
  declared numbers, not measurements. A ``PlanRecord`` is a booked
  plan, not proof the host ran it.
- Two instances fed the same stats and query spec produce byte-equal
  plan digests (test-verified). There is no wall-clock anywhere in
  this module.

Version pin: ``query-planner.v1`` / schema pin
``northstar.query-planner.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

VERSION = "query-planner.v1"
SCHEMA = "northstar.query-planner.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore

    def _canonical(obj: Any) -> bytes:
        return _cj.jcs_dumps(obj).encode("utf-8")

except Exception:  # pragma: no cover

    def _canonical(obj: Any) -> bytes:
        import json

        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")


_DIGEST_PREFIX = "sha256:"


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(_canonical([VERSION, *parts])).hexdigest()
    return f"{_DIGEST_PREFIX}{digest}"


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class QueryPlannerError(Exception):
    """Base class for all query-planner errors."""


class BadQueryError(QueryPlannerError):
    """Malformed query spec."""


class BadPlanError(QueryPlannerError):
    """Malformed plan id."""


class DuplicatePlanError(QueryPlannerError):
    """Plan id already booked (ids are never recycled)."""


class UnknownPlanError(QueryPlannerError):
    """No such plan id."""


class BadStatsError(QueryPlannerError):
    """Malformed table statistics."""


class DuplicateStatsError(QueryPlannerError):
    """Stats for this table already registered."""


class SeqOrderError(QueryPlannerError):
    """Seq is not a strictly increasing non-negative int."""


class AuditKindError(QueryPlannerError):
    """Unknown audit kind or banned detail keys."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _check_id(value: object, what: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise QueryPlannerError(f"{what} must be a non-empty str (<=256 chars)")
    if any(c.isspace() for c in value):
        raise QueryPlannerError(f"{what} must not contain whitespace")
    return value


def _check_plan_id(plan_id: object) -> str:
    try:
        return _check_id(plan_id, "plan id")
    except QueryPlannerError as exc:
        raise BadPlanError(str(exc)) from exc


def _check_table_id(table_id: object) -> str:
    try:
        return _check_id(table_id, "table id")
    except QueryPlannerError as exc:
        raise BadStatsError(str(exc)) from exc


def _check_row_count(row_count: object) -> int:
    if isinstance(row_count, bool) or not isinstance(row_count, int):
        raise BadStatsError(f"row_count must be an int, got {row_count!r}")
    if row_count < 0 or row_count > 2**53 - 1:
        raise BadStatsError(f"row_count out of range: {row_count!r}")
    return row_count


def _check_value(value: object, what: str) -> Any:
    """Validate a filter value: JCS-canonicalizable scalar."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadQueryError(f"{what} int out of safe range")
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadQueryError(f"{what} float must be finite")
        return value
    if isinstance(value, str):
        if len(value) > 4096:
            raise BadQueryError(f"{what} str too long")
        return value
    raise BadQueryError(f"{what} must be a scalar, got {type(value).__name__}")


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

KIND_PLANNED = "query.planned"
KIND_OPTIMIZED = "query.optimized"
KIND_STATS = "stats.registered"
KIND_REJECTED = "query.rejected"

_KINDS = frozenset({KIND_PLANNED, KIND_OPTIMIZED, KIND_STATS, KIND_REJECTED})


def query_planner_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the query planner.

    ``detail`` carries ids, counts, costs and digest pins only -- never
    query payloads, filter values, or raw plan detail.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"payload", "value", "raw", "body", "data", "query", "filter", "plan"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# Query spec normalization
# ---------------------------------------------------------------------------

_OPS = ("==", "!=", "<", "<=", ">", ">=")
_DIRECTIONS = ("asc", "desc")
MAX_TABLES = 16
DEFAULT_ROWS = 1000
MAX_SAFE = 2**53 - 1


def _normalize_query(query: object) -> Dict[str, Any]:
    """Validate a query spec and return its normalized form.

    Raises BadQueryError fail-closed on any malformed input.
    """
    if not isinstance(query, Mapping):
        raise BadQueryError("query must be a mapping")
    tables = query.get("tables")
    if not isinstance(tables, (tuple, list)) or not tables:
        raise BadQueryError("query.tables must be a non-empty tuple/list")
    if len(tables) > MAX_TABLES:
        raise BadQueryError(f"too many tables (max {MAX_TABLES})")
    norm_tables: List[str] = []
    for t in tables:
        tid = _check_id(t, "table id")
        if tid in norm_tables:
            raise BadQueryError(f"duplicate table: {tid!r}")
        norm_tables.append(tid)
    table_set = set(norm_tables)

    filters: List[Tuple[str, str, str, Any]] = []
    for i, f in enumerate(query.get("filters", ())):
        if not isinstance(f, (tuple, list)) or len(f) != 4:
            raise BadQueryError(f"filter #{i} must be (table, field, op, value)")
        table, fname, op, value = f
        _check_id(table, "filter table")
        _check_id(fname, "filter field")
        if table not in table_set:
            raise BadQueryError(f"filter #{i} references unknown table {table!r}")
        if op not in _OPS:
            raise BadQueryError(f"filter #{i} bad op {op!r}")
        filters.append((table, fname, op, _check_value(value, f"filter #{i} value")))

    joins: List[Tuple[str, str, str, str]] = []
    for i, j in enumerate(query.get("joins", ())):
        if not isinstance(j, (tuple, list)) or len(j) != 4:
            raise BadQueryError(
                f"join #{i} must be (left_table, right_table, left_key, right_key)"
            )
        lt, rt, lk, rk = j
        _check_id(lt, "join left table")
        _check_id(rt, "join right table")
        _check_id(lk, "join left key")
        _check_id(rk, "join right key")
        if lt not in table_set or rt not in table_set:
            raise BadQueryError(f"join #{i} references unknown table")
        if lt == rt:
            raise BadQueryError(f"join #{i} is a self-join")
        joins.append((lt, rt, lk, rk))

    # The join graph must connect the tables in declared order.
    if len(norm_tables) > 1:
        bound = {norm_tables[0]}
        for nxt in norm_tables[1:]:
            linked = any(
                (lt in bound and rt == nxt) or (rt in bound and lt == nxt)
                for lt, rt, _lk, _rk in joins
            )
            if not linked:
                raise BadQueryError(
                    f"join graph does not connect table {nxt!r} in declared order"
                )
            bound.add(nxt)

    projections: Tuple[str, ...] = ()
    proj = query.get("projections", ())
    if not isinstance(proj, (tuple, list)):
        raise BadQueryError("projections must be a tuple/list")
    for p in proj:
        _check_id(p, "projection")
    projections = tuple(proj)

    sort: Optional[Tuple[str, str]] = None
    s = query.get("sort")
    if s is not None:
        if not isinstance(s, (tuple, list)) or len(s) != 2:
            raise BadQueryError("sort must be (field, direction)")
        fname, direction = s
        _check_id(fname, "sort field")
        if direction not in _DIRECTIONS:
            raise BadQueryError(f"bad sort direction {direction!r}")
        sort = (fname, direction)

    limit: Optional[int] = None
    lim = query.get("limit")
    if lim is not None:
        if isinstance(lim, bool) or not isinstance(lim, int) or lim <= 0:
            raise BadQueryError("limit must be a positive int")
        if lim > 1_000_000_000:
            raise BadQueryError("limit too large")
        limit = lim

    return {
        "tables": tuple(norm_tables),
        "filters": tuple(filters),
        "joins": tuple(joins),
        "projections": projections,
        "sort": sort,
        "limit": limit,
    }


def _query_digest(norm: Mapping[str, Any]) -> str:
    filters = [
        [t, f, op, _canon_value(v)] for t, f, op, v in norm["filters"]
    ]
    joins = [list(j) for j in norm["joins"]]
    payload = {
        "tables": list(norm["tables"]),
        "filters": filters,
        "joins": joins,
        "projections": list(norm["projections"]),
        "sort": list(norm["sort"]) if norm["sort"] else None,
        "limit": norm["limit"],
    }
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    return f"{_DIGEST_PREFIX}{digest}"


def _canon_value(value: Any) -> Any:
    """Type-tagged canonical form so bool != int and NaN can't sneak in."""
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, int):
        return ["int", value]
    if isinstance(value, float):
        return ["float", value]
    return ["str", value]


# ---------------------------------------------------------------------------
# Cost model (pure integer arithmetic, deterministic)
# ---------------------------------------------------------------------------


def _selectivity(op: str) -> Tuple[int, int]:
    """(numerator, denominator) for a filter operator."""
    if op == "==":
        return (1, 10)
    if op == "!=":
        return (9, 10)
    return (1, 3)  # range operators


def _scan_cost(rows: int) -> Tuple[int, int]:
    return rows, rows


def _filter_cost(rows: int, op: str) -> Tuple[int, int]:
    num, den = _selectivity(op)
    out = max(1, rows * num // den)
    return rows, out


def _project_cost(rows: int) -> Tuple[int, int]:
    return rows, rows


def _sort_cost(rows: int) -> Tuple[int, int]:
    return rows * 2, rows


def _limit_cost(rows: int, n: int) -> Tuple[int, int]:
    out = min(rows, n)
    return out, out


def _join_output(left: int, right: int) -> int:
    return max(1, min(left, right) // 10)


def _hash_join_cost(left: int, right: int) -> Tuple[int, int]:
    return left + right, _join_output(left, right)


def _nested_loop_cost(left: int, right: int) -> Tuple[int, int]:
    cost = left * right
    if cost > MAX_SAFE:
        cost = MAX_SAFE
    return cost, _join_output(left, right)


def _choose_join(left: int, right: int) -> Tuple[str, int, int]:
    """Pick the cheaper join algorithm; ties go to hash join."""
    h_cost, h_out = _hash_join_cost(left, right)
    n_cost, n_out = _nested_loop_cost(left, right)
    if n_cost < h_cost:
        return "nested_loop_join", n_cost, n_out
    return "hash_join", h_cost, h_out


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StatsRecord:
    """Host-declared table cardinality."""

    table_id: str
    row_count: int
    seq: int
    digest: str = field(default="")

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "digest", _pin("stats", self.table_id, self.row_count, self.seq)
        )

    def verify(self) -> bool:
        return self.digest == _pin(
            "stats", self.table_id, self.row_count, self.seq
        )


@dataclass(frozen=True)
class PlanStep:
    """One physical operator in a booked plan."""

    op: str
    target: str
    detail: Tuple[Tuple[str, str], ...]
    est_rows: int
    cost: int
    digest: str = field(default="")

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _pin("step", self.op, self.target, list(self.detail), self.est_rows, self.cost),
        )

    def verify(self) -> bool:
        return self.digest == _pin(
            "step", self.op, self.target, list(self.detail), self.est_rows, self.cost
        )


@dataclass(frozen=True)
class PlanRecord:
    """A booked physical plan with its total estimated cost."""

    plan_id: str
    query_digest: str
    steps: Tuple[PlanStep, ...]
    total_cost: int
    seq: int
    digest: str = field(default="")

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _pin(
                "plan",
                self.plan_id,
                self.query_digest,
                [s.digest for s in self.steps],
                self.total_cost,
                self.seq,
            ),
        )

    def verify(self) -> bool:
        return self.digest == _pin(
            "plan",
            self.plan_id,
            self.query_digest,
            [s.digest for s in self.steps],
            self.total_cost,
            self.seq,
        ) and all(s.verify() for s in self.steps)


@dataclass(frozen=True)
class CostReport:
    """Pure read view of a plan's per-step cost breakdown."""

    plan_id: str
    steps: Tuple[Tuple[str, str, int, int], ...]  # (op, target, cost, est_rows)
    total_cost: int
    seq: int
    digest: str = field(default="")

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _pin(
                "cost",
                self.plan_id,
                [list(s) for s in self.steps],
                self.total_cost,
                self.seq,
            ),
        )

    def verify(self) -> bool:
        return self.digest == _pin(
            "cost",
            self.plan_id,
            [list(s) for s in self.steps],
            self.total_cost,
            self.seq,
        )


@dataclass(frozen=True)
class OptimizeRecord:
    """A booked optimized plan with before/after costs."""

    plan_id: str
    original_cost: int
    optimized_cost: int
    steps: Tuple[PlanStep, ...]
    seq: int
    digest: str = field(default="")

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _pin(
                "optimize",
                self.plan_id,
                self.original_cost,
                self.optimized_cost,
                [s.digest for s in self.steps],
                self.seq,
            ),
        )

    def verify(self) -> bool:
        return self.digest == _pin(
            "optimize",
            self.plan_id,
            self.original_cost,
            self.optimized_cost,
            [s.digest for s in self.steps],
            self.seq,
        ) and all(s.verify() for s in self.steps)


# ---------------------------------------------------------------------------
# QueryPlanner
# ---------------------------------------------------------------------------


class QueryPlanner:
    """Cost-based query planning as a deterministic state machine."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._stats: Dict[str, StatsRecord] = {}
        self._plans: Dict[str, PlanRecord] = {}
        self._optimized: Dict[str, OptimizeRecord] = {}
        self._norms: Dict[str, Dict[str, Any]] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: int) -> int:
        _check_seq(seq)
        with self._lock:
            if seq <= self._seq:
                raise SeqOrderError(
                    f"seq must be strictly increasing (last={self._seq}, got={seq})"
                )
            self._seq = seq
            return seq

    def _reject(self, seq: int, exc: QueryPlannerError, **detail: Any) -> None:
        row = query_planner_audit_event(
            KIND_REJECTED, {"error": type(exc).__name__, **detail}, seq
        )
        with self._lock:
            self._audit.append(row)
        raise exc

    # -- stats -------------------------------------------------------------

    def _rows(self, table_id: str) -> int:
        rec = self._stats.get(table_id)
        return rec.row_count if rec is not None else DEFAULT_ROWS

    def register_stats(self, table_id: str, row_count: int, seq: int) -> StatsRecord:
        """Pin host-declared table cardinality."""
        self._claim(seq)
        try:
            tid = _check_table_id(table_id)
            rows = _check_row_count(row_count)
        except QueryPlannerError as exc:
            self._reject(seq, exc, table_id=str(table_id))
        with self._lock:
            if tid in self._stats:
                self._reject(seq, DuplicateStatsError(f"stats for {tid!r} already registered"),
                             table_id=tid)
            rec = StatsRecord(tid, rows, seq)
            self._stats[tid] = rec
            self._audit.append(
                query_planner_audit_event(
                    KIND_STATS, {"table_id": tid, "row_count": rows}, seq
                )
            )
            return rec

    # -- planning ----------------------------------------------------------

    def _build_steps(
        self, norm: Mapping[str, Any], table_order: Tuple[str, ...]
    ) -> List[PlanStep]:
        """Generate physical steps for tables joined in ``table_order``.

        Filters are pushed to their table's scan; joins are taken in
        table order; the join algorithm is chosen per join by cost.
        """
        steps: List[PlanStep] = []
        filters = norm["filters"]
        joins = norm["joins"]

        # Scan + pushed-down filters per table, in join order.
        per_table_rows: Dict[str, int] = {}
        for t in table_order:
            rows = self._rows(t)
            steps.append(
                PlanStep("scan", t, (), rows, rows)
            )
            for ft, fname, op, _value in filters:
                if ft != t:
                    continue
                cost, out = _filter_cost(rows, op)
                steps.append(
                    PlanStep(
                        "filter", t, (("field", fname), ("op", op)), out, cost
                    )
                )
                rows = out
            per_table_rows[t] = rows

        # Joins in table order.
        acc = table_order[0]
        acc_rows = per_table_rows[acc]
        bound_tables = {table_order[0]}
        for nxt in table_order[1:]:
            spec = None
            for lt, rt, lk, rk in joins:
                if (lt == nxt and rt in bound_tables) or (
                    rt == nxt and lt in bound_tables
                ):
                    spec = (lt, rt, lk, rk)
                    break
            assert spec is not None  # validated in _normalize_query
            lt, rt, lk, rk = spec
            other_rows = per_table_rows[nxt]
            op, cost, out = _choose_join(acc_rows, other_rows)
            steps.append(
                PlanStep(
                    op,
                    f"{acc}+{nxt}",
                    (("left", lt), ("right", rt), ("on", f"{lk}={rk}")),
                    out,
                    cost,
                )
            )
            acc = f"{acc}+{nxt}"
            acc_rows = out
            bound_tables.add(nxt)

        rows = acc_rows
        if norm["projections"]:
            cost, rows = _project_cost(rows)
            steps.append(
                PlanStep(
                    "project",
                    "",
                    tuple(("field", p) for p in norm["projections"]),
                    rows,
                    cost,
                )
            )
        if norm["sort"] is not None:
            fname, direction = norm["sort"]
            cost, rows = _sort_cost(rows)
            steps.append(
                PlanStep(
                    "sort", "", (("field", fname), ("direction", direction)), rows, cost
                )
            )
        if norm["limit"] is not None:
            cost, rows = _limit_cost(rows, norm["limit"])
            steps.append(
                PlanStep("limit", "", (("n", str(norm["limit"])),), rows, cost)
            )
        return steps

    def _book_plan(
        self, plan_id: str, norm: Mapping[str, Any], steps: List[PlanStep], seq: int
    ) -> PlanRecord:
        total = sum(s.cost for s in steps)
        rec = PlanRecord(plan_id, _query_digest(norm), tuple(steps), total, seq)
        with self._lock:
            self._plans[plan_id] = rec
            self._norms[plan_id] = dict(norm)
            self._audit.append(
                query_planner_audit_event(
                    KIND_PLANNED,
                    {
                        "plan_id": plan_id,
                        "steps": len(steps),
                        "total_cost": total,
                    },
                    seq,
                )
            )
        return rec

    def plan(self, plan_id: str, query: Mapping[str, Any], seq: int) -> PlanRecord:
        """Book a physical plan for a logical query spec.

        Tables are joined in declared order; each join picks the
        cheaper algorithm by cost. Fails closed on malformed specs or
        duplicate plan ids; failed mutations consume their seq.
        """
        self._claim(seq)
        try:
            pid = _check_plan_id(plan_id)
            norm = _normalize_query(query)
        except QueryPlannerError as exc:
            self._reject(seq, exc, plan_id=str(plan_id))
        with self._lock:
            if pid in self._plans:
                self._reject(seq, DuplicatePlanError(f"plan {pid!r} already booked"),
                             plan_id=pid)
        steps = self._build_steps(norm, norm["tables"])
        return self._book_plan(pid, norm, steps, seq)

    # -- cost (pure read) --------------------------------------------------

    def cost(self, plan_id: str, seq: int) -> CostReport:
        """Return the per-step cost breakdown of a booked plan.

        Pure read view: validates seq shape, consumes nothing, writes
        no audit row.
        """
        _check_seq(seq)
        pid = _check_plan_id(plan_id)
        with self._lock:
            rec = self._plans.get(pid)
        if rec is None:
            raise UnknownPlanError(f"unknown plan {pid!r}")
        steps = tuple((s.op, s.target, s.cost, s.est_rows) for s in rec.steps)
        return CostReport(pid, steps, rec.total_cost, seq)

    # -- optimize ----------------------------------------------------------

    def _optimize_order(self, norm: Mapping[str, Any]) -> Tuple[str, ...]:
        """Greedy join order: smallest estimated intermediate first.

        Deterministic: ties break by table id.
        """
        tables = list(norm["tables"])
        joins = norm["joins"]
        if len(tables) <= 1:
            return tuple(tables)

        def rows_of(t: str) -> int:
            rows = self._rows(t)
            for ft, _f, op, _v in norm["filters"]:
                if ft == t:
                    _c, rows = _filter_cost(rows, op)
            return rows

        def find_join(bound: set, nxt: str):
            for lt, rt, lk, rk in joins:
                if (lt in bound and rt == nxt) or (rt in bound and lt == nxt):
                    return (lt, rt, lk, rk)
            return None

        remaining = sorted(tables, key=lambda t: (rows_of(t), t))
        order = [remaining.pop(0)]
        bound = {order[0]}
        acc_rows = rows_of(order[0])
        while remaining:
            best = None
            best_key = None
            for cand in remaining:
                spec = find_join(bound, cand)
                if spec is None:
                    continue
                _op, _cost, out = _choose_join(acc_rows, rows_of(cand))
                key = (out, cand)
                if best_key is None or key < best_key:
                    best_key = key
                    best = cand
            if best is None:  # pragma: no cover -- validated at plan time
                raise BadQueryError("join graph disconnected during optimize")
            order.append(best)
            bound.add(best)
            remaining.remove(best)
            _op, _cost, acc_rows = _choose_join(acc_rows, rows_of(best))
        return tuple(order)

    def optimize(self, plan_id: str, seq: int) -> OptimizeRecord:
        """Book an optimized rewrite of a booked plan.

        Reorders joins by estimated cost (greedy smallest-first) and
        re-chooses the join algorithm per join. The optimized plan
        never costs more than the original. Fails closed on unknown
        plan ids; failed mutations consume their seq.
        """
        self._claim(seq)
        try:
            pid = _check_plan_id(plan_id)
        except QueryPlannerError as exc:
            self._reject(seq, exc, plan_id=str(plan_id))
        with self._lock:
            rec = self._plans.get(pid)
        if rec is None:
            self._reject(seq, UnknownPlanError(f"unknown plan {pid!r}"), plan_id=pid)
        # Recover the normalized query from the plan: the query digest
        # pins the spec; we rebuild from the stored norm. Store norms
        # alongside plans (not in the audit boundary).
        with self._lock:
            norm = self._norms[pid]
        order = self._optimize_order(norm)
        steps = self._build_steps(norm, order)
        total = sum(s.cost for s in steps)
        opt = OptimizeRecord(pid, rec.total_cost, total, tuple(steps), seq)
        with self._lock:
            self._optimized[pid] = opt
            self._audit.append(
                query_planner_audit_event(
                    KIND_OPTIMIZED,
                    {
                        "plan_id": pid,
                        "original_cost": rec.total_cost,
                        "optimized_cost": total,
                        "steps": len(steps),
                    },
                    seq,
                )
            )
        return opt

    # -- views -------------------------------------------------------------

    def plan_record(self, plan_id: str) -> Optional[PlanRecord]:
        pid = _check_plan_id(plan_id)
        with self._lock:
            return self._plans.get(pid)

    def optimized_record(self, plan_id: str) -> Optional[OptimizeRecord]:
        pid = _check_plan_id(plan_id)
        with self._lock:
            return self._optimized.get(pid)

    def plan_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._plans))

    def stats_record(self, table_id: str) -> Optional[StatsRecord]:
        tid = _check_table_id(table_id)
        with self._lock:
            return self._stats.get(tid)

    def stats(self, seq: int) -> Dict[str, int]:
        """Pure read view of registered table cardinalities."""
        _check_seq(seq)
        with self._lock:
            return {t: r.row_count for t, r in self._stats.items()}

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# main() self-check
# ---------------------------------------------------------------------------


def main() -> None:
    qp = QueryPlanner()
    assert VERSION == "query-planner.v1"
    assert SCHEMA == "northstar.query-planner.v1"

    s = qp.register_stats("users", 10_000, 1)
    assert s.verify()
    s2 = qp.register_stats("orders", 100, 2)
    assert s2.verify()

    query = {
        "tables": ("users", "orders"),
        "filters": (("users", "active", "==", True),),
        "joins": (("users", "orders", "id", "user_id"),),
        "projections": ("users.name",),
        "sort": ("users.name", "asc"),
        "limit": 50,
    }
    plan = qp.plan("p1", query, 3)
    assert plan.verify()
    assert plan.total_cost == sum(st.cost for st in plan.steps)
    ops = [st.op for st in plan.steps]
    assert ops[0] == "scan" and "filter" in ops and "limit" in ops

    report = qp.cost("p1", 3)  # pure read: same seq is fine
    assert report.verify()
    assert report.total_cost == plan.total_cost
    assert sum(c for _op, _t, c, _r in report.steps) == plan.total_cost

    opt = qp.optimize("p1", 4)
    assert opt.verify()
    assert opt.optimized_cost <= opt.original_cost == plan.total_cost

    # Fail-closed: duplicate plan, unknown plan, bad query.
    for bad, exc in (
        (lambda: qp.plan("p1", query, 5), DuplicatePlanError),
        (lambda: qp.optimize("nope", 6), UnknownPlanError),
        (
            lambda: qp.plan(
                "p2", {"tables": ("a", "b"), "joins": ()}, 7
            ),
            BadQueryError,
        ),
    ):
        try:
            bad()
        except exc:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"expected {exc.__name__}")

    rejected = [r for r in qp.audit_log() if r["kind"] == KIND_REJECTED]
    assert len(rejected) == 3

    print("query-planner OK: stats, plan, cost, optimize, fail-closed, audit")


if __name__ == "__main__":
    main()
