"""Bulkhead fault isolation: one tenant's failure can never starve another.

The bulkhead pattern (ship hulls: one flooded compartment does not sink
the ship) partitions shared resources per tenant. Each tenant gets a
bounded slice of concurrency, call count, and spend; when a tenant hits
its bound it is refused *fail-fast* -- it is never queued behind its
own backlog, and other tenants' partitions are untouched.

Fail-fast is the anti-starvation core of this module: a tenant whose
workload explodes gets an immediate refusal, not a place in an
unbounded queue that would wedge shared threads, connections, or
budget. The refusal names the exact bound that tripped
(``concurrency-limit`` / ``call-quota`` / ``cost-quota``).

Check order inside :meth:`Bulkhead.execute` is fixed and deliberate:

1. **Tenant known?** Unknown tenants are refused. Partitions are
   explicit; there is no implicit "default" slice that a flood of
   unknown tenants could collectively exhaust.
2. **Concurrency slot free?** ``in_flight < max_concurrent`` for this
   tenant. Fail-fast refusal if not -- no queueing, no waiting.
3. **Call quota remaining?** Lifetime call counts are per tenant.
4. **Cost quota remaining?** ``used_cost_usd + cost_usd`` must fit the
   partition's cost ceiling.
5. **Run.** The slot is released in a ``finally``: a function that
   raises is recorded as a failure but never leaks a slot.

Hard doctrine (enforced, not aspirational):

- partitions are strictly per tenant: tenant A's refusal never moves
  tenant B's counters;
- concurrency refuses fail-fast; there is no hidden queue, so a
  saturated tenant cannot pile up unbounded waiting work;
- a call that raises releases its slot and increments the tenant's
  failure count; the exception propagates to the caller unchanged --
  this module isolates, it does not swallow;
- refusals never charge: cost accounting only happens for admitted
  calls, so a refused call cannot burn quota;
- bool is not a number: bool-typed counts/costs are rejected as
  ``TypeError``; negative counts/costs are rejected as ``ValueError``.

No wall clock anywhere: seqs are caller-supplied ints, and the module
never measures elapsed time. Duration-based shedding is the host's
job (this is the admission side, not the scheduling side).

Honest scope: this is an *admission* bulkhead, not a scheduler. It
bounds how much work a tenant can hold *inside* the agent at once; it
cannot bound how fast a tenant *submits* (submit-side rate limiting is
the host's job), cannot see CPU/memory the function consumes outside
the tracked cost, and trusts the caller's ``cost_usd`` estimate. A
tenant that lies about its cost starves no one but evades its own
cost ceiling. State is in-memory; persistence across restarts is the
host's job.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Optional


#: Version pin for this module's record shape.
BULKHEAD_VERSION = "bulkhead.v1"

#: Schema pin carried on audit records.
BULKHEAD_SCHEMA = "northstar.bulkhead.v1"

#: Verdict constants.
ALLOW = "allow"
DENY = "deny"

#: Refusal reasons.
UNKNOWN_TENANT = "unknown-tenant"
CONCURRENCY_LIMIT = "concurrency-limit"
CALL_QUOTA = "call-quota"
COST_QUOTA = "cost-quota"


class BulkheadError(Exception):
    """Programming error: bad partition config or misuse (not a policy refusal)."""


@dataclass(frozen=True)
class TenantPartition:
    """The resource slice one tenant may occupy.

    ``max_concurrent`` bounds how many calls the tenant can hold in
    flight at once. ``max_calls`` bounds the lifetime call count
    (``None`` = unbounded). ``max_cost_usd`` bounds lifetime tracked
    spend (``None`` = unbounded).
    """

    tenant_id: str
    max_concurrent: int
    max_calls: Optional[int] = None
    max_cost_usd: Optional[float] = None

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, str) or not self.tenant_id:
            raise BulkheadError("tenant_id must be a non-empty str")
        if isinstance(self.max_concurrent, bool) or not isinstance(
            self.max_concurrent, int
        ):
            raise TypeError("max_concurrent must be an int")
        if self.max_concurrent <= 0:
            raise ValueError("max_concurrent must be > 0")
        for name, value in (("max_calls", self.max_calls),
                            ("max_cost_usd", self.max_cost_usd)):
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be a number or None")
            if value < 0:
                raise ValueError(f"{name} must be >= 0")


@dataclass(frozen=True)
class TenantUsage:
    """Point-in-time usage snapshot for one tenant (record, not live view)."""

    tenant_id: str
    in_flight: int
    calls_used: int
    cost_used_usd: float
    failures: int
    schema: str = field(default=BULKHEAD_SCHEMA, repr=False)

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "tenant_id": self.tenant_id,
            "in_flight": self.in_flight,
            "calls_used": self.calls_used,
            "cost_used_usd": self.cost_used_usd,
            "failures": self.failures,
        }


@dataclass(frozen=True)
class BulkheadDecision:
    """The verdict for one admission attempt."""

    tenant_id: str
    verdict: str  # allow | deny
    reason: Optional[str]  # None on allow, one of the *-reason consts on deny
    seq: int
    schema: str = field(default=BULKHEAD_SCHEMA, repr=False)

    def __post_init__(self) -> None:
        if self.verdict not in (ALLOW, DENY):
            raise BulkheadError(f"bad verdict: {self.verdict!r}")
        if (self.verdict == DENY) == (self.reason is None):
            raise BulkheadError("deny requires a reason; allow forbids one")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "tenant_id": self.tenant_id,
            "verdict": self.verdict,
            "reason": self.reason,
            "seq": self.seq,
        }


class Bulkhead:
    """Per-tenant admission bulkhead.

    Thread-safe: all state mutations hold one lock, so concurrent
    tenants cannot corrupt each other's counters. Admission is
    fail-fast -- a saturated tenant is refused immediately.
    """

    def __init__(self, partitions: list[TenantPartition]) -> None:
        if not partitions:
            raise BulkheadError("at least one partition required")
        seen: set[str] = set()
        self._partitions: dict[str, TenantPartition] = {}
        for part in partitions:
            if not isinstance(part, TenantPartition):
                raise TypeError("partitions must be TenantPartition records")
            if part.tenant_id in seen:
                raise BulkheadError(
                    f"duplicate partition for tenant {part.tenant_id!r}"
                )
            seen.add(part.tenant_id)
            self._partitions[part.tenant_id] = part
        self._lock = threading.RLock()
        self._in_flight: dict[str, int] = {t: 0 for t in seen}
        self._calls_used: dict[str, int] = {t: 0 for t in seen}
        self._cost_used: dict[str, float] = {t: 0.0 for t in seen}
        self._failures: dict[str, int] = {t: 0 for t in seen}

    # -- introspection -------------------------------------------------

    def tenants(self) -> tuple[str, ...]:
        """Partitioned tenant ids, in registration order."""
        return tuple(self._partitions)

    def usage(self, tenant_id: str) -> TenantUsage:
        """Frozen usage snapshot for one tenant."""
        with self._lock:
            part = self._require(tenant_id)
            return TenantUsage(
                tenant_id=part.tenant_id,
                in_flight=self._in_flight[tenant_id],
                calls_used=self._calls_used[tenant_id],
                cost_used_usd=self._cost_used[tenant_id],
                failures=self._failures[tenant_id],
            )

    def _require(self, tenant_id: str) -> TenantPartition:
        part = self._partitions.get(tenant_id)
        if part is None:
            raise BulkheadError(f"unknown tenant: {tenant_id!r}")
        return part

    # -- admission -----------------------------------------------------

    def _check_cost(self, cost_usd: object) -> float:
        if isinstance(cost_usd, bool) or not isinstance(cost_usd, (int, float)):
            raise TypeError("cost_usd must be a number")
        cost = float(cost_usd)
        if cost < 0:
            raise ValueError("cost_usd must be >= 0")
        return cost

    def _check_seq(self, seq: object) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise TypeError("seq must be an int")
        if seq < 0:
            raise ValueError("seq must be >= 0")
        return seq

    def admit(self, tenant_id: str, *, seq: int, cost_usd: float = 0.0) -> BulkheadDecision:
        """Admission check only (no execution): would this call be admitted?

        Reserves nothing; use :meth:`execute` for check-and-run.
        """
        seq = self._check_seq(seq)
        cost = self._check_cost(cost_usd)
        with self._lock:
            part = self._partitions.get(tenant_id)
            if part is None:
                return BulkheadDecision(tenant_id, DENY, UNKNOWN_TENANT, seq)
            if self._in_flight[tenant_id] >= part.max_concurrent:
                return BulkheadDecision(tenant_id, DENY, CONCURRENCY_LIMIT, seq)
            if part.max_calls is not None and self._calls_used[tenant_id] >= part.max_calls:
                return BulkheadDecision(tenant_id, DENY, CALL_QUOTA, seq)
            if (
                part.max_cost_usd is not None
                and self._cost_used[tenant_id] + cost > part.max_cost_usd
            ):
                return BulkheadDecision(tenant_id, DENY, COST_QUOTA, seq)
            return BulkheadDecision(tenant_id, ALLOW, None, seq)

    def execute(
        self,
        tenant_id: str,
        func: Callable[[], object],
        *,
        seq: int,
        cost_usd: float = 0.0,
    ) -> tuple[BulkheadDecision, object]:
        """Check-and-run: admit the call, run ``func``, release the slot.

        Returns ``(decision, result)``. On ``deny`` the result is
        ``None`` and nothing was charged. On ``allow`` the slot was
        held during ``func()`` and released in a ``finally`` -- an
        exception from ``func`` propagates unchanged after the slot is
        released and the tenant's failure count incremented.
        """
        seq = self._check_seq(seq)
        cost = self._check_cost(cost_usd)
        if not callable(func):
            raise TypeError("func must be callable")
        with self._lock:
            decision = self.admit(tenant_id, seq=seq, cost_usd=cost)
            if decision.verdict == DENY:
                return decision, None
            # admit() already validated the tenant exists; re-check under
            # the same lock is unnecessary, but keep accounting atomic.
            self._in_flight[tenant_id] += 1
            self._calls_used[tenant_id] += 1
            self._cost_used[tenant_id] += cost
        try:
            result = func()
        except Exception:
            with self._lock:
                self._failures[tenant_id] += 1
            raise
        finally:
            with self._lock:
                self._in_flight[tenant_id] -= 1
        return decision, result

    # -- management ----------------------------------------------------

    def add_partition(self, part: TenantPartition) -> None:
        """Add a new tenant partition (fail-closed on duplicates)."""
        if not isinstance(part, TenantPartition):
            raise TypeError("part must be a TenantPartition")
        with self._lock:
            if part.tenant_id in self._partitions:
                raise BulkheadError(
                    f"duplicate partition for tenant {part.tenant_id!r}"
                )
            self._partitions[part.tenant_id] = part
            self._in_flight[part.tenant_id] = 0
            self._calls_used[part.tenant_id] = 0
            self._cost_used[part.tenant_id] = 0.0
            self._failures[part.tenant_id] = 0

    def remove_partition(self, tenant_id: str) -> None:
        """Remove a partition; refused while the tenant has calls in flight."""
        with self._lock:
            self._require(tenant_id)
            if self._in_flight[tenant_id] > 0:
                raise BulkheadError(
                    f"cannot remove tenant {tenant_id!r}: "
                    f"{self._in_flight[tenant_id]} call(s) in flight"
                )
            del self._partitions[tenant_id]
            del self._in_flight[tenant_id]
            del self._calls_used[tenant_id]
            del self._cost_used[tenant_id]
            del self._failures[tenant_id]


def bulkhead_audit_event(
    decision: BulkheadDecision, *, audit_seq: int
) -> dict:
    """Shape a bulkhead decision as an ``audit.ndjson/1`` record."""
    if not isinstance(decision, BulkheadDecision):
        raise TypeError("decision must be a BulkheadDecision")
    if isinstance(audit_seq, bool) or not isinstance(audit_seq, int):
        raise TypeError("audit_seq must be an int")
    if audit_seq < 0:
        raise ValueError("audit_seq must be >= 0")
    record = decision.as_dict()
    record["audit_seq"] = audit_seq
    return record


def main() -> None:
    bh = Bulkhead(
        [
            TenantPartition("web", max_concurrent=2, max_calls=10, max_cost_usd=1.0),
            TenantPartition("batch", max_concurrent=1),
        ]
    )
    # Happy path.
    decision, result = bh.execute("web", lambda: "ok", seq=0, cost_usd=0.1)
    assert decision.verdict == ALLOW and result == "ok", decision
    # Saturate web's concurrency with genuinely nested held calls.
    def hold() -> str:
        def inner() -> str:
            # outer holds 1 slot + inner holds 1 slot = at limit (2).
            innermost, _ = bh.execute("web", lambda: "x", seq=2)
            assert innermost.verdict == DENY, innermost  # 3rd refused fail-fast
            assert innermost.reason == CONCURRENCY_LIMIT
            return "inner"

        mid, _ = bh.execute("web", inner, seq=1)
        assert mid.verdict == ALLOW, mid  # outer + inner = 2 fits
        return "held"

    decision, _ = bh.execute("web", hold, seq=3)
    assert decision.verdict == ALLOW, decision
    # Unknown tenant refused; batch untouched by web's refusal.
    unknown, _ = bh.execute("ghost", lambda: "x", seq=4)
    assert unknown.verdict == DENY and unknown.reason == UNKNOWN_TENANT
    batch_decision, _ = bh.execute("batch", lambda: "b", seq=5)
    assert batch_decision.verdict == ALLOW
    print("bulkhead OK: isolation holds, saturated tenant refused fail-fast")


if __name__ == "__main__":
    main()
