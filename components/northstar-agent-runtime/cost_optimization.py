"""Cost optimization — CloudHealth-shaped spend analysis bookkeeping (thirty-fourth batch).

Research note (cloud cost literature): CloudHealth (VMware Aria Cost)
splits the problem into three questions asked in order:

* **Where does the money go?** Cost analysis breaks spend by
  account/service/tag/region and computes unit costs. The report is
  *host-reported data* here — this module books the breakdown as a
  frozen record, never re-derives it from billing APIs.
* **What should we do about it?** Recommendations are typed:
  *rightsize* (over-provisioned instances), *idle-resource* (orphaned
  volumes/EIPs), *reservation* / *savings-plan* (commitment discounts),
  *spot-migration* (fault-tolerant workloads to spot). Each carries a
  host-reported estimated monthly saving — an *estimate*, never a
  verified number.
* **Are we on budget?** Budget tracking pins a monthly cap per
  account; checks report the verdict as data (``within``/``over``)
  against the latest booked analysis.

Design intersections for a single-host deterministic ledger: all
money is integer *cents* (no floats — no >2^53 precision hazard);
resource categories follow a pinned vocabulary (the free-form tag
dimension is CloudHealth's, not this ledger's); recommendation kinds
are pinned to the five kinds above; recommendation lifecycle is
``open -> applied | dismissed`` (terminal both ways, like batch-21
approval discipline).

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (failed mutations consume their seq), RLock guarding,
fail-closed taxonomy, stdlib-only, sha256 digest pins over canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *reported* spend and *estimated*
savings as data. It cannot observe a cloud bill, verify an estimate,
or apply a recommendation — applying means the operator acts on the
frozen ``RecommendationRecord`` outside this ledger. Raw breakdowns,
per-category amounts, and budget cents never cross the audit boundary
(ids + digest pins only). GIGO on account ids and amounts: the ledger
pins what the host declares.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Mapping

#: Version pin for this module's record shape.
COST_OPTIMIZATION_VERSION = "cost-optimization.v1"

#: Schema pin carried by records and audit events.
COST_OPTIMIZATION_SCHEMA = "northstar.cost-optimization.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned resource categories (CloudHealth "cost dimensions" subset).
CAT_COMPUTE = "compute"
CAT_STORAGE = "storage"
CAT_NETWORK = "network"
CAT_DATA_TRANSFER = "data_transfer"
CAT_DATABASE = "database"
CAT_LICENSE = "license"
CAT_SUPPORT = "support"
CAT_OTHER = "other"
RESOURCE_CATEGORIES = (
    CAT_COMPUTE,
    CAT_STORAGE,
    CAT_NETWORK,
    CAT_DATA_TRANSFER,
    CAT_DATABASE,
    CAT_LICENSE,
    CAT_SUPPORT,
    CAT_OTHER,
)

#: Pinned recommendation kinds.
REC_RIGHTSIZE = "rightsize"
REC_IDLE_RESOURCE = "idle_resource"
REC_RESERVATION = "reservation"
REC_SAVINGS_PLAN = "savings_plan"
REC_SPOT_MIGRATION = "spot_migration"
RECOMMENDATION_KINDS = (
    REC_RIGHTSIZE,
    REC_IDLE_RESOURCE,
    REC_RESERVATION,
    REC_SAVINGS_PLAN,
    REC_SPOT_MIGRATION,
)

#: Pinned recommendation statuses. ``applied``/``dismissed`` are
#: terminal (no re-opening; a fresh recommendation is booked instead).
REC_STATUS_OPEN = "open"
REC_STATUS_APPLIED = "applied"
REC_STATUS_DISMISSED = "dismissed"
REC_STATUSES = (REC_STATUS_OPEN, REC_STATUS_APPLIED, REC_STATUS_DISMISSED)

#: Pinned budget-check verdicts.
VERDICT_WITHIN = "within"
VERDICT_OVER = "over"
VERDICT_UNKNOWN = "unknown"
BUDGET_VERDICTS = (VERDICT_WITHIN, VERDICT_OVER, VERDICT_UNKNOWN)

#: Audit event kinds.
KIND_ACCOUNT_REGISTERED = "cost.account-registered"
KIND_ANALYZED = "cost.analyzed"
KIND_RECOMMENDED = "cost.recommended"
KIND_REC_APPLIED = "cost.recommendation-applied"
KIND_REC_DISMISSED = "cost.recommendation-dismissed"
KIND_BUDGET_SET = "cost.budget-set"
KIND_BUDGET_CHECKED = "cost.budget-checked"
KIND_REJECTED = "cost.rejected"
_KINDS = (
    KIND_ACCOUNT_REGISTERED,
    KIND_ANALYZED,
    KIND_RECOMMENDED,
    KIND_REC_APPLIED,
    KIND_REC_DISMISSED,
    KIND_BUDGET_SET,
    KIND_BUDGET_CHECKED,
    KIND_REJECTED,
)

#: Keys banned from the audit boundary: raw money and raw breakdowns
#: never cross into the audit trail — ids + digest pins only.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "breakdown",
        "amounts",
        "budget_cents",
        "estimated_savings_cents",
        "total_cents",
        "per_category",
        "note",
    }
)

_DIGEST_PREFIX = "sha256:"
_GENESIS = "genesis"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CostOptimizationError(ValueError):
    """Base error for the cost optimization manager."""


class BadAccountError(CostOptimizationError):
    """Malformed account id."""


class DuplicateAccountError(CostOptimizationError):
    """This account id is already registered."""


class UnknownAccountError(CostOptimizationError):
    """No account with this id is registered."""


class BadBreakdownError(CostOptimizationError):
    """Cost breakdown is malformed (bad category, amount, or shape)."""


class BadRecommendationError(CostOptimizationError):
    """Malformed recommendation kind, savings, or note."""


class UnknownRecommendationError(CostOptimizationError):
    """No recommendation with this id exists."""


class RecommendationStateError(CostOptimizationError):
    """Recommendation is not open (already applied or dismissed)."""


class BadBudgetError(CostOptimizationError):
    """Malformed budget (non-positive cents, bool, or bad shape)."""


class SeqOrderError(CostOptimizationError):
    """Mutation seq is not strictly increasing."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CostOptimizationError(
            f"{field_name} must be a non-negative int, saw {value!r}"
        )
    return value


def _check_account_id(value: Any, field_name: str = "account_id") -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadAccountError(f"{field_name} must be a non-empty string")
    return value.strip()


def _check_cents(value: Any, field_name: str = "cents") -> int:
    # Money is integer cents only: no floats anywhere (precision
    # hazard), no bools, no negatives.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BadBudgetError(
            f"{field_name} must be a non-negative int (cents), saw {value!r}"
        )
    return value


def _check_breakdown(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or not value:
        raise BadBreakdownError(
            "breakdown must be a non-empty mapping of category -> cents"
        )
    clean: dict[str, int] = {}
    for category, amount in value.items():
        if category not in RESOURCE_CATEGORIES:
            raise BadBreakdownError(
                f"unknown resource category {category!r}; "
                f"must be one of {RESOURCE_CATEGORIES}"
            )
        if category in clean:
            raise BadBreakdownError(
                f"duplicate category in breakdown: {category!r}"
            )
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise BadBreakdownError(
                f"amount for {category!r} must be a non-negative int "
                f"(cents), saw {amount!r}"
            )
        clean[category] = amount
    return clean


def _check_recommendation_kind(value: Any) -> str:
    if value not in RECOMMENDATION_KINDS:
        raise BadRecommendationError(
            f"kind must be one of {RECOMMENDATION_KINDS}, saw {value!r}"
        )
    return value


def _check_note(value: Any, field_name: str = "note") -> str:
    if not isinstance(value, str):
        raise BadRecommendationError(f"{field_name} must be a string")
    if len(value) > 1024:
        raise BadRecommendationError(f"{field_name} must be <= 1024 chars")
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
    """sha256 hex pin over the canonical encoding of the parts."""
    return _DIGEST_PREFIX + hashlib.sha256(_canonical(list(parts))).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AccountRecord:
    """One registered cost account (a CloudHealth "perspective" owner).

    The record pins the declared account identity only — spend arrives
    via ``analyze`` calls.
    """

    account_id: str
    seq: int
    digest: str
    schema: str = COST_OPTIMIZATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "account", COST_OPTIMIZATION_VERSION, self.account_id
        )


@dataclass(frozen=True)
class AnalysisRecord:
    """One booked cost analysis.

    ``per_category`` is the host-reported breakdown in integer cents
    (data, not verified); ``total_cents`` is their exact sum — the
    module computes nothing more.
    """

    analysis_id: str
    account_id: str
    per_category: Mapping[str, int]
    total_cents: int
    seq: int
    digest: str
    schema: str = COST_OPTIMIZATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "analysis",
            COST_OPTIMIZATION_VERSION,
            self.account_id,
            sorted(self.per_category.items()),
            self.total_cents,
        )


@dataclass(frozen=True)
class RecommendationRecord:
    """One booked cost-saving recommendation.

    ``estimated_monthly_savings_cents`` is the host-reported estimate —
    data, never a verified number. ``status`` starts ``open``.
    """

    recommendation_id: str
    account_id: str
    kind: str
    estimated_monthly_savings_cents: int
    note: str
    status: str
    seq: int
    digest: str
    schema: str = COST_OPTIMIZATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "recommendation",
            COST_OPTIMIZATION_VERSION,
            self.recommendation_id,
            self.account_id,
            self.kind,
            self.estimated_monthly_savings_cents,
        )


@dataclass(frozen=True)
class RecommendationResolution:
    """Terminal resolution of a recommendation (applied or dismissed)."""

    recommendation_id: str
    account_id: str
    kind: str
    resolution: str  # applied | dismissed
    seq: int
    digest: str
    schema: str = COST_OPTIMIZATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "resolution",
            COST_OPTIMIZATION_VERSION,
            self.recommendation_id,
            self.resolution,
        )


@dataclass(frozen=True)
class BudgetRecord:
    """One pinned monthly budget for an account (latest-wins)."""

    account_id: str
    budget_cents: int
    seq: int
    digest: str
    schema: str = COST_OPTIMIZATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "budget", COST_OPTIMIZATION_VERSION, self.account_id
        )


@dataclass(frozen=True)
class BudgetCheck:
    """One budget check verdict (pure data).

    ``verdict`` is ``within``/``over`` against the latest booked
    analysis total, or ``unknown`` when no analysis has been booked
    yet. No decision is enforced here.
    """

    account_id: str
    verdict: str
    budget_cents: int
    observed_cents: int | None
    seq: int
    digest: str
    schema: str = COST_OPTIMIZATION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "budget-check",
            COST_OPTIMIZATION_VERSION,
            self.account_id,
            self.verdict,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def cost_optimization_audit_event(kind: str, seq: int, **detail: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for the cost module.

    Raw money and raw breakdowns are banned from the audit boundary —
    ids + digest pins only.
    """
    if kind not in _KINDS:
        raise CostOptimizationError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if any(key in _BANNED_AUDIT_KEYS for key in detail):
        banned = sorted(set(detail) & _BANNED_AUDIT_KEYS)
        raise CostOptimizationError(
            f"audit detail carries banned keys: {banned}"
        )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": COST_OPTIMIZATION_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The manager
# ---------------------------------------------------------------------------


class CostOptimization:
    """Deterministic cost-analysis / recommendation / budget ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).

    Mutation seqs must be strictly increasing; failed mutations consume
    their seq (batch-21 ledger discipline). No wall-clock, stdlib-only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._accounts: dict[str, AccountRecord] = {}
        self._analyses: dict[str, AnalysisRecord] = {}
        self._analysis_seq = 0
        self._recommendations: dict[str, RecommendationRecord] = {}
        self._recommendation_seq = 0
        self._resolutions: list[RecommendationResolution] = []
        self._budgets: dict[str, BudgetRecord] = {}
        self._audit: list[Mapping[str, Any]] = []

    # -- internal ---------------------------------------------------------

    def _claim_seq(self, seq: int) -> None:
        # Called first in every mutation: a refused mutation still
        # consumes its seq, keeping the ledger totally ordered.
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing: {seq} <= {self._last_seq}"
            )
        self._last_seq = seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(cost_optimization_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, **detail)

    def _get_account(self, account_id: str, seq: int) -> str:
        account_id = _check_account_id(account_id)
        if account_id not in self._accounts:
            self._reject(seq, account_id=account_id)
            raise UnknownAccountError(
                f"unknown account: {account_id!r}"
            )
        return account_id

    # -- mutations --------------------------------------------------------

    def register_account(self, account_id: str, seq: int) -> AccountRecord:
        """Register a cost account (a spend owner)."""
        with self._lock:
            self._claim_seq(seq)
            account_id = _check_account_id(account_id)
            if account_id in self._accounts:
                self._reject(seq, account_id=account_id)
                raise DuplicateAccountError(
                    f"account already registered: {account_id!r}"
                )
            record = AccountRecord(
                account_id=account_id,
                seq=seq,
                digest=_pin("account", COST_OPTIMIZATION_VERSION, account_id),
            )
            self._accounts[account_id] = record
            self._emit(
                KIND_ACCOUNT_REGISTERED,
                seq,
                account_id=account_id,
                digest=record.digest,
            )
            return record

    def analyze(
        self, account_id: str, breakdown: Mapping[str, int], seq: int
    ) -> AnalysisRecord:
        """Book a host-reported cost breakdown for an account.

        ``breakdown`` maps resource category -> integer cents; the
        module verifies categories/amounts and computes the exact
        total — nothing more.
        """
        with self._lock:
            self._claim_seq(seq)
            account_id = self._get_account(account_id, seq)
            clean = _check_breakdown(breakdown)
            self._analysis_seq += 1
            analysis_id = f"ana-{self._analysis_seq}"
            total = sum(clean.values())
            record = AnalysisRecord(
                analysis_id=analysis_id,
                account_id=account_id,
                per_category=dict(clean),
                total_cents=total,
                seq=seq,
                digest=_pin(
                    "analysis",
                    COST_OPTIMIZATION_VERSION,
                    account_id,
                    sorted(clean.items()),
                    total,
                ),
            )
            self._analyses[analysis_id] = record
            self._emit(
                KIND_ANALYZED,
                seq,
                account_id=account_id,
                analysis_id=analysis_id,
                digest=record.digest,
            )
            return record

    def recommend(
        self,
        account_id: str,
        kind: str,
        seq: int,
        estimated_monthly_savings_cents: int = 0,
        note: str = "",
    ) -> RecommendationRecord:
        """Book a cost-saving recommendation for an account.

        ``estimated_monthly_savings_cents`` is the host-reported
        estimate — booked as data, never verified.
        """
        with self._lock:
            self._claim_seq(seq)
            account_id = self._get_account(account_id, seq)
            kind = _check_recommendation_kind(kind)
            savings = _check_cents(estimated_monthly_savings_cents,
                                   "estimated_monthly_savings_cents")
            note = _check_note(note)
            self._recommendation_seq += 1
            recommendation_id = f"rec-{self._recommendation_seq}"
            record = RecommendationRecord(
                recommendation_id=recommendation_id,
                account_id=account_id,
                kind=kind,
                estimated_monthly_savings_cents=savings,
                note=note,
                status=REC_STATUS_OPEN,
                seq=seq,
                digest=_pin(
                    "recommendation",
                    COST_OPTIMIZATION_VERSION,
                    recommendation_id,
                    account_id,
                    kind,
                    savings,
                ),
            )
            self._recommendations[recommendation_id] = record
            self._emit(
                KIND_RECOMMENDED,
                seq,
                account_id=account_id,
                recommendation_id=recommendation_id,
                recommendation_kind=kind,
                digest=record.digest,
            )
            return record

    def _resolve(
        self, recommendation_id: str, resolution: str, seq: int
    ) -> RecommendationResolution:
        if not isinstance(recommendation_id, str) or not recommendation_id:
            self._reject(seq)
            raise UnknownRecommendationError(
                "recommendation_id must be a non-empty string"
            )
        record = self._recommendations.get(recommendation_id)
        if record is None:
            self._reject(seq, recommendation_id=recommendation_id)
            raise UnknownRecommendationError(
                f"unknown recommendation: {recommendation_id!r}"
            )
        if record.status != REC_STATUS_OPEN:
            self._reject(seq, recommendation_id=recommendation_id)
            raise RecommendationStateError(
                f"recommendation {recommendation_id!r} is not open "
                f"(status={record.status})"
            )
        resolved = RecommendationRecord(
            recommendation_id=record.recommendation_id,
            account_id=record.account_id,
            kind=record.kind,
            estimated_monthly_savings_cents=(
                record.estimated_monthly_savings_cents
            ),
            note=record.note,
            status=resolution,
            seq=seq,
            digest=record.digest,
        )
        self._recommendations[recommendation_id] = resolved
        result = RecommendationResolution(
            recommendation_id=recommendation_id,
            account_id=record.account_id,
            kind=record.kind,
            resolution=resolution,
            seq=seq,
            digest=_pin(
                "resolution",
                COST_OPTIMIZATION_VERSION,
                recommendation_id,
                resolution,
            ),
        )
        self._resolutions.append(result)
        kind = KIND_REC_APPLIED if resolution == REC_STATUS_APPLIED else (
            KIND_REC_DISMISSED
        )
        self._emit(
            kind,
            seq,
            account_id=record.account_id,
            recommendation_id=recommendation_id,
            recommendation_kind=record.kind,
            digest=result.digest,
        )
        return result

    def apply_recommendation(
        self, recommendation_id: str, seq: int
    ) -> RecommendationResolution:
        """Mark a recommendation applied (terminal)."""
        with self._lock:
            self._claim_seq(seq)
            return self._resolve(recommendation_id, REC_STATUS_APPLIED, seq)

    def dismiss_recommendation(
        self, recommendation_id: str, seq: int
    ) -> RecommendationResolution:
        """Mark a recommendation dismissed (terminal)."""
        with self._lock:
            self._claim_seq(seq)
            return self._resolve(recommendation_id, REC_STATUS_DISMISSED, seq)

    def track(
        self, account_id: str, seq: int, budget_cents: int
    ) -> BudgetRecord:
        """Pin (or re-pin) the monthly budget for an account.

        Latest-wins: re-tracking replaces the previous budget.
        """
        with self._lock:
            self._claim_seq(seq)
            account_id = self._get_account(account_id, seq)
            budget = _check_cents(budget_cents, "budget_cents")
            if budget == 0:
                self._reject(seq, account_id=account_id)
                raise BadBudgetError("budget_cents must be positive")
            record = BudgetRecord(
                account_id=account_id,
                budget_cents=budget,
                seq=seq,
                digest=_pin("budget", COST_OPTIMIZATION_VERSION, account_id),
            )
            self._budgets[account_id] = record
            self._emit(
                KIND_BUDGET_SET,
                seq,
                account_id=account_id,
                digest=record.digest,
            )
            return record

    # -- read views -------------------------------------------------------

    def budget_check(self, account_id: str, seq: int) -> BudgetCheck:
        """Check the latest booked analysis against the budget.

        Pure read view: validates seq shape, consumes nothing, writes a
        single audited-read row. ``verdict`` is data — ``unknown`` when
        no analysis has been booked yet.
        """
        with self._lock:
            _check_seq(seq, "seq")
            account_id = _check_account_id(account_id)
            budget = self._budgets.get(account_id)
            if budget is None:
                raise UnknownAccountError(
                    f"no budget tracked for account: {account_id!r}"
                )
            latest: AnalysisRecord | None = None
            for record in self._analyses.values():
                if record.account_id == account_id and (
                    latest is None or record.seq > latest.seq
                ):
                    latest = record
            if latest is None:
                verdict = VERDICT_UNKNOWN
                observed: int | None = None
            else:
                observed = latest.total_cents
                verdict = (
                    VERDICT_WITHIN
                    if observed <= budget.budget_cents
                    else VERDICT_OVER
                )
            check = BudgetCheck(
                account_id=account_id,
                verdict=verdict,
                budget_cents=budget.budget_cents,
                observed_cents=observed,
                seq=seq,
                digest=_pin(
                    "budget-check",
                    COST_OPTIMIZATION_VERSION,
                    account_id,
                    verdict,
                ),
            )
            self._emit(
                KIND_BUDGET_CHECKED,
                seq,
                account_id=account_id,
                verdict=verdict,
                digest=check.digest,
            )
            return check

    def account(self, account_id: str) -> AccountRecord:
        """Return the frozen record for an account."""
        with self._lock:
            account_id = _check_account_id(account_id)
            try:
                return self._accounts[account_id]
            except KeyError:
                raise UnknownAccountError(
                    f"unknown account: {account_id!r}"
                ) from None

    def account_ids(self) -> tuple[str, ...]:
        """All registered account ids, sorted."""
        with self._lock:
            return tuple(sorted(self._accounts))

    def analysis(self, analysis_id: str) -> AnalysisRecord:
        """Return the frozen record for an analysis."""
        with self._lock:
            try:
                return self._analyses[analysis_id]
            except KeyError:
                raise CostOptimizationError(
                    f"unknown analysis: {analysis_id!r}"
                ) from None

    def analyses_for(self, account_id: str) -> tuple[AnalysisRecord, ...]:
        """All analyses booked for an account, newest first."""
        with self._lock:
            self._get_account_for_view(account_id)
            return tuple(
                sorted(
                    (
                        r for r in self._analyses.values()
                        if r.account_id == account_id
                    ),
                    key=lambda r: r.seq,
                    reverse=True,
                )
            )

    def _get_account_for_view(self, account_id: str) -> str:
        account_id = _check_account_id(account_id)
        if account_id not in self._accounts:
            raise UnknownAccountError(
                f"unknown account: {account_id!r}"
            )
        return account_id

    def recommendation(self, recommendation_id: str) -> RecommendationRecord:
        """Return the frozen record for a recommendation."""
        with self._lock:
            try:
                return self._recommendations[recommendation_id]
            except KeyError:
                raise UnknownRecommendationError(
                    f"unknown recommendation: {recommendation_id!r}"
                ) from None

    def recommendations_for(
        self, account_id: str, status: str | None = None
    ) -> tuple[RecommendationRecord, ...]:
        """All recommendations for an account, newest first.

        Optionally filtered by status (``open``/``applied``/``dismissed``).
        """
        with self._lock:
            self._get_account_for_view(account_id)
            if status is not None and status not in REC_STATUSES:
                raise BadRecommendationError(
                    f"status must be one of {REC_STATUSES}, saw {status!r}"
                )
            return tuple(
                sorted(
                    (
                        r for r in self._recommendations.values()
                        if r.account_id == account_id
                        and (status is None or r.status == status)
                    ),
                    key=lambda r: r.seq,
                    reverse=True,
                )
            )

    def budget(self, account_id: str) -> BudgetRecord:
        """Return the pinned budget for an account."""
        with self._lock:
            try:
                return self._budgets[account_id]
            except KeyError:
                raise UnknownAccountError(
                    f"no budget tracked for account: {account_id!r}"
                ) from None

    def stats(self) -> dict:
        """Ledger counts."""
        with self._lock:
            return {
                "accounts": len(self._accounts),
                "analyses": len(self._analyses),
                "recommendations": len(self._recommendations),
                "resolutions": len(self._resolutions),
                "budgets": len(self._budgets),
                "audit_events": len(self._audit),
            }

    def audit_log(self) -> tuple[Mapping[str, Any], ...]:
        """All audit events, oldest first."""
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Self-check: register, analyze, recommend, lifecycle, track, check."""
    mgr = CostOptimization()
    acct = mgr.register_account("prod", seq=1)
    assert acct.verify() and acct.account_id == "prod"

    ana = mgr.analyze(
        "prod",
        {"compute": 120000, "storage": 30000, "network": 10000},
        seq=2,
    )
    assert ana.verify() and ana.total_cents == 160000
    assert ana.analysis_id == "ana-1"

    rec = mgr.recommend(
        "prod", "rightsize", seq=3,
        estimated_monthly_savings_cents=25000,
        note="downsize over-provisioned nodes",
    )
    assert rec.verify() and rec.status == "open"
    assert rec.recommendation_id == "rec-1"

    applied = mgr.apply_recommendation("rec-1", seq=4)
    assert applied.verify() and applied.resolution == "applied"
    assert mgr.recommendation("rec-1").status == "applied"

    budget = mgr.track("prod", seq=5, budget_cents=200000)
    assert budget.verify() and budget.budget_cents == 200000

    check = mgr.budget_check("prod", seq=6)
    assert check.verify() and check.verdict == "within"
    assert check.observed_cents == 160000

    # Over-budget path.
    mgr.analyze("prod", {"compute": 500000}, seq=7)
    over = mgr.budget_check("prod", seq=8)
    assert over.verdict == "over"

    # Determinism: the same inputs reproduce the same pins.
    other = CostOptimization()
    other.register_account("prod", seq=1)
    other.analyze(
        "prod",
        {"compute": 120000, "storage": 30000, "network": 10000},
        seq=2,
    )
    assert other.analyses_for("prod")[0].digest == ana.digest
    assert other.analyses_for("prod")[0].total_cents == 160000
    print("cost-optimization OK: register, analyze, recommend, "
          "lifecycle, track, budget-check, pins")


if __name__ == "__main__":
    main()
