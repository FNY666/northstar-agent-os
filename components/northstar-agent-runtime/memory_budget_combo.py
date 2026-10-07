"""Memory operations under budget: consent gate meets spend gate.

This module composes :mod:`memory_admission` with
:mod:`per_call_budget` so that every memory operation passes *both*
choke points before it runs. The composition order is fixed and
deliberate:

1. **Consent first.** A write without a valid, unrevoked, unexpired,
   in-scope consent is denied by the admission gate and never touches
   the budget ledger. Privacy refusal is free: a denied write costs
   nothing.
2. **Budget second.** An admitted write (or any read, or any embedding
   op) is estimate-checked and charged through the per-call budget.
   A call whose estimate does not fit the per-call ceiling or the run
   ceiling is refused.

Three operations are covered:

* :meth:`MemoryBudgetGate.write` -- consent + ``memory_write`` budget.
* :meth:`MemoryBudgetGate.read` -- ``memory_read`` budget only (reads
  are not writes; consent governs the write path).
* :meth:`MemoryBudgetGate.embed` -- expensive embedding operations.
  Embeddings are model inference (most providers bill them as such),
  so the estimate is charged against the ``model`` call type -- but
  the gate first enforces its own tighter ``embed_ceiling_usd`` cap,
  because an embedding estimate that needs the full model ceiling is
  almost certainly a misconfigured caller. The refusal names the
  ``memory_embed`` tier so audits can tell it apart from a plain
  model call.

Honest scope: the gate bounds *estimated* spend (see
:mod:`per_call_budget` for why estimates are conservative pre-checks,
not invoices) and checks *host-reported* consent objects (see
:mod:`memory_admission` for why miscategorization defeats the gate).
A write the gate allows is still the caller's responsibility to
actually perform; the gate records the decision, it does not execute
the write.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from memory_admission import MemoryAdmission, MemoryConsent
from per_call_budget import (
    CEILING_PER_CALL,
    BudgetExhausted,
    PerCallBudget,
)

#: Semantic version of the memory+budget composition contract.
MEMORY_BUDGET_COMBO_VERSION = "memory-budget-combo.v1"

#: Schema pin carried by gate decision records.
SCHEMA_PIN = "northstar.memory-budget-combo.v1"

#: Default estimate for a plain memory write (well under the $0.001
#: per-call ceiling for ``memory_write``).
DEFAULT_WRITE_ESTIMATE_USD = 0.0005

#: Default estimate for a memory read (well under the $0.001 per-call
#: ceiling for ``memory_read``).
DEFAULT_READ_ESTIMATE_USD = 0.0002

#: Default per-embedding-op cap in USD. Tighter than the model
#: per-call ceiling ($0.10): an embedding estimate above this is a
#: caller bug, not a big model.
DEFAULT_EMBED_CEILING_USD = 0.01

#: The tier name used when the embedding cap refuses an op.
EMBED_CALL_TYPE = "memory_embed"

REASON_ADMITTED = "admitted"
REASON_CONSENT_DENIED = "consent-denied"
REASON_BUDGET_EXHAUSTED = "budget-exhausted"


class MemoryBudgetError(ValueError):
    """A gate argument failed validation. Raised, never silent."""


def _require_estimate(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MemoryBudgetError(f"{name} must be a number")
    estimate = float(value)
    if estimate < 0:
        raise MemoryBudgetError(f"{name} must be non-negative")
    return estimate


@dataclass(frozen=True)
class GateDecision:
    """One recorded memory-budget gate verdict."""

    operation: str
    allowed: bool
    reason: str
    remaining_usd: float | None
    seq: int | None

    def __post_init__(self) -> None:
        if self.operation not in ("write", "read", "embed"):
            raise MemoryBudgetError(
                f"operation must be 'write', 'read' or 'embed', got {self.operation!r}"
            )
        if not isinstance(self.allowed, bool):
            raise MemoryBudgetError("allowed must be a bool")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise MemoryBudgetError("reason must be a non-empty string")
        if self.remaining_usd is not None and (
            isinstance(self.remaining_usd, bool)
            or not isinstance(self.remaining_usd, (int, float))
        ):
            raise MemoryBudgetError("remaining_usd must be a number or None")
        if self.seq is not None and (
            isinstance(self.seq, bool) or not isinstance(self.seq, int) or self.seq < 0
        ):
            raise MemoryBudgetError("seq must be a non-negative int or None")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "operation": self.operation,
            "allowed": self.allowed,
            "reason": self.reason,
            "remaining_usd": self.remaining_usd,
            "seq": self.seq,
        }


class MemoryBudgetGate:
    """Memory operations through consent *and* budget. Fail-closed.

    ``write`` runs the consent gate first and the budget gate second;
    ``read`` and ``embed`` run the budget gate only (``embed`` with an
    extra per-op cap). Every verdict is recorded in the decision log.
    """

    def __init__(
        self,
        admission: MemoryAdmission | None = None,
        budget: PerCallBudget | None = None,
        embed_ceiling_usd: float = DEFAULT_EMBED_CEILING_USD,
    ) -> None:
        if admission is not None and not isinstance(admission, MemoryAdmission):
            raise MemoryBudgetError("admission must be a MemoryAdmission or None")
        if budget is not None and not isinstance(budget, PerCallBudget):
            raise MemoryBudgetError("budget must be a PerCallBudget or None")
        self._admission = admission if admission is not None else MemoryAdmission()
        self._budget = budget if budget is not None else PerCallBudget()
        self._embed_ceiling_usd = _require_estimate(
            "embed_ceiling_usd", embed_ceiling_usd
        )
        self._decisions: list[GateDecision] = []

    @property
    def embed_ceiling_usd(self) -> float:
        return self._embed_ceiling_usd

    def decisions(self) -> tuple[GateDecision, ...]:
        """The recorded verdicts, oldest first."""
        return tuple(self._decisions)

    def denied(self) -> tuple[GateDecision, ...]:
        """The recorded denials, oldest first."""
        return tuple(d for d in self._decisions if not d.allowed)

    def _record(
        self,
        operation: str,
        allowed: bool,
        reason: str,
        remaining_usd: float | None,
        seq: int | None,
    ) -> GateDecision:
        decision = GateDecision(
            operation=operation,
            allowed=allowed,
            reason=reason,
            remaining_usd=remaining_usd,
            seq=seq,
        )
        self._decisions.append(decision)
        return decision

    def write(
        self,
        category: Any,
        content: Any,
        consent: MemoryConsent | None = None,
        current_seq: int | None = None,
        estimate_usd: float = DEFAULT_WRITE_ESTIMATE_USD,
    ) -> GateDecision:
        """Consent-gate then budget-gate a memory write.

        Returns a :class:`GateDecision`. A consent denial names the
        admission reason (``consent-denied:<reason>``) and leaves the
        budget ledger untouched. A budget refusal raises nothing here;
        it is recorded as ``budget-exhausted``.
        """
        estimate = _require_estimate("estimate_usd", estimate_usd)

        # Gate 1: consent. Privacy refusal is free -- no budget touched.
        admitted = self._admission.admit_write(
            category, content, consent=consent, current_seq=current_seq
        )
        if not admitted:
            admission_reason = self._admission.decisions()[-1].reason
            return self._record(
                "write",
                False,
                f"{REASON_CONSENT_DENIED}:{admission_reason}",
                self._budget.remaining,
                current_seq if isinstance(current_seq, int) else None,
            )

        # Gate 2: budget.
        try:
            remaining = self._budget.check_and_charge("memory_write", estimate)
        except BudgetExhausted as exc:
            return self._record(
                "write",
                False,
                f"{REASON_BUDGET_EXHAUSTED}:{exc.ceiling}",
                self._budget.remaining,
                current_seq if isinstance(current_seq, int) else None,
            )
        return self._record(
            "write",
            True,
            REASON_ADMITTED,
            remaining,
            current_seq if isinstance(current_seq, int) else None,
        )

    def read(
        self,
        estimate_usd: float = DEFAULT_READ_ESTIMATE_USD,
        seq: int | None = None,
    ) -> GateDecision:
        """Budget-gate a memory read (no consent check: reads are not writes)."""
        estimate = _require_estimate("estimate_usd", estimate_usd)
        try:
            remaining = self._budget.check_and_charge("memory_read", estimate)
        except BudgetExhausted as exc:
            return self._record(
                "read",
                False,
                f"{REASON_BUDGET_EXHAUSTED}:{exc.ceiling}",
                self._budget.remaining,
                seq if isinstance(seq, int) else None,
            )
        return self._record(
            "read",
            True,
            REASON_ADMITTED,
            remaining,
            seq if isinstance(seq, int) else None,
        )

    def embed(
        self,
        estimate_usd: float,
        seq: int | None = None,
    ) -> GateDecision:
        """Budget-gate an embedding op under the embed-tier cap.

        The estimate must first fit ``embed_ceiling_usd`` (fail-closed:
        an over-cap estimate is refused without touching the budget);
        it is then charged against the ``model`` call type, because
        embeddings are model inference. The refusal names the
        ``memory_embed`` tier.
        """
        estimate = _require_estimate("estimate_usd", estimate_usd)
        if estimate > self._embed_ceiling_usd:
            raise BudgetExhausted(
                call_type=EMBED_CALL_TYPE,
                needed=estimate,
                available=self._budget.remaining,
                ceiling=CEILING_PER_CALL,
            )
        try:
            remaining = self._budget.check_and_charge("model", estimate)
        except BudgetExhausted as exc:
            return self._record(
                "embed",
                False,
                f"{REASON_BUDGET_EXHAUSTED}:{exc.ceiling}",
                self._budget.remaining,
                seq if isinstance(seq, int) else None,
            )
        return self._record(
            "embed",
            True,
            REASON_ADMITTED,
            remaining,
            seq if isinstance(seq, int) else None,
        )


__all__ = [
    "MEMORY_BUDGET_COMBO_VERSION",
    "SCHEMA_PIN",
    "DEFAULT_WRITE_ESTIMATE_USD",
    "DEFAULT_READ_ESTIMATE_USD",
    "DEFAULT_EMBED_CEILING_USD",
    "EMBED_CALL_TYPE",
    "REASON_ADMITTED",
    "REASON_CONSENT_DENIED",
    "REASON_BUDGET_EXHAUSTED",
    "MemoryBudgetError",
    "GateDecision",
    "MemoryBudgetGate",
]


def main() -> None:
    grant = MemoryConsent(
        scope=("preference", "fact", "conversation"),
        retention_days=30,
        granted_at=100,
    )
    gate = MemoryBudgetGate(
        admission=MemoryAdmission(grant),
        budget=PerCallBudget(max_budget_usd=1.0),
    )
    d1 = gate.write("preference", "likes dark mode", current_seq=110)
    d2 = gate.write("credential", "api-key-123", current_seq=110)
    d3 = gate.read()
    d4 = gate.embed(0.005)
    print(f"write ok: {d1.allowed} ({d1.reason}), remaining={d1.remaining_usd}")
    print(f"credential write: {d2.allowed} ({d2.reason})")
    print(f"read ok: {d3.allowed}, embed ok: {d4.allowed}")
    print(f"decisions: {len(gate.decisions())}, charges: {len(gate._budget.charges)}")


if __name__ == "__main__":
    main()
