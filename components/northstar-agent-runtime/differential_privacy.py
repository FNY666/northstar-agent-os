"""Differential privacy bookkeeping.

Privacy-budget ledger for differential-privacy noise mechanisms as a
deterministic single-host state machine (the model this shape mirrors:
Dwork's Laplace mechanism / the Gaussian mechanism / the exponential
mechanism, and the basic composition theorem).

House style:
  - frozen dataclasses, caller int seqs strictly increasing (no wall-clock)
  - RLock-guarded, fail-closed, stdlib-only
  - `sha256:` digest pins with `verify()`
  - `audit.ndjson/1` events; raw query values stay out of the audit boundary
  - failed mutations consume their seq (claim-then-burn) and book
    `differential-privacy.rejected`

Honest scope: books *declared* noise decisions over *host-reported*
parameters. A booked noise record means the host declared this epsilon
spend with these mechanism parameters - never proof a real DP mechanism
ran. The deterministic "noise sample" is replayable bookkeeping data
derived from the record id (so two hosts agree without coordination),
never fresh randomness. Privacy accounting is exact rational arithmetic
over declared spends, not a proof of privacy.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # pragma: no cover - sibling convention
    from canonical_json import jcs_dumps  # type: ignore
except Exception:  # pragma: no cover
    def jcs_dumps(obj: Any) -> bytes:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

VERSION = "differential-privacy.v1"
SCHEMA = "northstar.differential-privacy.v1"

MECHANISMS = ("laplace", "gaussian", "exponential")

#: Rational scaling: epsilons, sensitivities, and scales are booked as
#: exact (num, den) pairs with den == SCALE.
SCALE = 1_000_000

_HASH_DOMAIN = b"northstar.differential-privacy.v1\x00"


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

class DifferentialPrivacyError(Exception):
    """Base."""


class BadBudgetError(DifferentialPrivacyError):
    pass


class DuplicateBudgetError(DifferentialPrivacyError):
    pass


class UnknownBudgetError(DifferentialPrivacyError):
    pass


class BadMechanismError(DifferentialPrivacyError):
    pass


class BadEpsilonError(DifferentialPrivacyError):
    pass


class BadSensitivityError(DifferentialPrivacyError):
    pass


class BadDeltaError(DifferentialPrivacyError):
    pass


class BadDigestError(DifferentialPrivacyError):
    pass


class BudgetExhaustedError(DifferentialPrivacyError):
    pass


class SeqOrderError(DifferentialPrivacyError):
    pass


class AuditKindError(DifferentialPrivacyError):
    pass


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "budget-declared",
    "noise-booked",
    "composition-reported",
    "rejected",
)


def differential_privacy_audit_event(
    kind: str, detail: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"bad audit kind: {kind!r}")
    return {
        "kind": kind,
        "detail": dict(detail or {}),
        "schema": "audit.ndjson/1",
    }


_BANNED_AUDIT_KEYS = ("query", "value", "scores", "payload", "raw", "text")


def _check_audit_detail(detail: Dict[str, Any]) -> None:
    for key in _BANNED_AUDIT_KEYS:
        if key in detail:
            raise BadDigestError(f"raw data key banned from audit boundary: {key!r}")


# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------

def _check_id(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BadBudgetError(f"bad id: {value!r}")
    if len(value) > 128:
        raise BadBudgetError("id too long")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"bad seq: {seq!r}")
    return seq


def _check_epsilon(value: Any) -> Tuple[int, int]:
    # host-reported epsilon > 0; bool is never an epsilon
    if isinstance(value, bool):
        raise BadEpsilonError(f"bool is not an epsilon: {value!r}")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float) or not math.isfinite(value) or value <= 0.0:
        raise BadEpsilonError(f"bad epsilon: {value!r}")
    num = round(value * SCALE)
    if num <= 0:
        raise BadEpsilonError("epsilon too small to represent")
    return (num, SCALE)


def _check_sensitivity(value: Any) -> Tuple[int, int]:
    # L1 sensitivity > 0; bool is never a sensitivity
    if isinstance(value, bool):
        raise BadSensitivityError(f"bool is not a sensitivity: {value!r}")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float) or not math.isfinite(value) or value <= 0.0:
        raise BadSensitivityError(f"bad sensitivity: {value!r}")
    num = round(value * SCALE)
    if num <= 0:
        raise BadSensitivityError("sensitivity too small to represent")
    return (num, SCALE)


def _check_delta(value: Any) -> float:
    # gaussian delta in (0, 1); bool is never a delta
    if isinstance(value, bool):
        raise BadDeltaError(f"bool is not a delta: {value!r}")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float) or not math.isfinite(value):
        raise BadDeltaError(f"bad delta: {value!r}")
    if not 0.0 < value < 1.0:
        raise BadDeltaError(f"delta must be in (0, 1): {value!r}")
    return value


def _check_query_digest(value: Any) -> str:
    # raw query text never enters the ledger; digest pins only
    if not isinstance(value, str):
        raise BadDigestError(f"bad query digest: {value!r}")
    if value == "":
        return value
    if len(value) != 7 + 64 or not value.startswith("sha256:"):
        raise BadDigestError(f"bad query digest: {value!r}")
    try:
        int(value[7:], 16)
    except ValueError:
        raise BadDigestError(f"bad query digest: {value!r}")
    return value


def _digest_pin(*parts: Any) -> str:
    blob = jcs_dumps(list(parts))
    if isinstance(blob, str):
        blob = blob.encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _laplace_scale(s_num: int, s_den: int, e_num: int, e_den: int) -> Tuple[int, int]:
    # b = sensitivity / epsilon, exact then scaled to SCALE
    scale = (s_num * e_den) / (s_den * e_num)
    return (round(scale * SCALE), SCALE)


def _gaussian_scale(s_num: int, s_den: int, e_num: int, e_den: int, delta: float) -> Tuple[int, int]:
    # sigma = sensitivity * sqrt(2 ln(1.25 / delta)) / epsilon
    sensitivity = s_num / s_den
    epsilon = e_num / e_den
    sigma = sensitivity * math.sqrt(2.0 * math.log(1.25 / delta)) / epsilon
    return (round(sigma * SCALE), SCALE)


def _noise_sample(noise_id: str, mechanism: str, scale_num: int, scale_den: int) -> Optional[float]:
    """Deterministic noise sample derived from the record id.

    Replayable bookkeeping data (two hosts booking the same sequence agree
    byte-for-byte), never fresh randomness. Laplace via inverse CDF,
    Gaussian via Box-Muller, exponential carries no numeric sample.
    """
    raw = hashlib.sha256(_HASH_DOMAIN + b"sample\x00" + noise_id.encode("utf-8")).digest()
    scale = scale_num / scale_den
    if mechanism == "laplace":
        u = int.from_bytes(raw[0:8], "big") / 2**64  # [0, 1)
        centered = 2.0 * u - 1.0  # (-1, 1)
        if centered == 0.0:
            return 0.0
        return -scale * math.copysign(1.0, centered) * math.log1p(-abs(centered))
    if mechanism == "gaussian":
        u1 = int.from_bytes(raw[0:8], "big") / 2**64  # [0, 1)
        u2 = int.from_bytes(raw[8:16], "big") / 2**64
        if u1 == 0.0:  # deterministic guard; probability-zero corner
            u1 = 0.5
        return scale * math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
    return None  # exponential: no numeric sample


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BudgetRecord:
    budget_id: str
    epsilon_num: int
    epsilon_den: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(self.budget_id, self.epsilon_num, self.epsilon_den)


@dataclass(frozen=True)
class NoiseRecord:
    noise_id: str
    budget_id: str
    mechanism: str
    query_digest: str
    epsilon_num: int
    epsilon_den: int
    sensitivity_num: int
    sensitivity_den: int
    scale_num: int
    scale_den: int
    noised_value: Optional[float]
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.noise_id, self.budget_id, self.mechanism, self.query_digest,
            self.epsilon_num, self.epsilon_den,
            self.sensitivity_num, self.sensitivity_den,
            self.scale_num, self.scale_den,
            repr(self.noised_value),
        )


@dataclass(frozen=True)
class CompositionRecord:
    composition_id: str
    budget_ids: Tuple[str, ...]
    total_spent_num: int
    total_spent_den: int
    total_remaining_num: int
    total_remaining_den: int
    per_budget: Tuple[Tuple[str, int, int], ...]
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.composition_id,
            list(self.budget_ids),
            self.total_spent_num, self.total_spent_den,
            self.total_remaining_num, self.total_remaining_den,
            [list(row) for row in self.per_budget],
        )


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------

class DifferentialPrivacy:
    """Privacy-budget ledger for declared DP noise mechanisms."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._budgets: Dict[str, BudgetRecord] = {}
        self._spent: Dict[str, int] = {}  # budget_id -> spent epsilon num (den == SCALE)
        self._noise: Dict[str, NoiseRecord] = {}
        self._compositions: Dict[str, CompositionRecord] = {}
        self._last_seq: int = -1
        self._noise_seq = 0
        self._composition_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline -----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq must strictly increase: {seq!r}")
        self._last_seq = seq
        return seq

    def _emit(self, audit_kind: str, detail: Dict[str, Any]) -> None:
        _check_audit_detail(detail)
        self._audit.append(differential_privacy_audit_event(audit_kind, detail))

    # -- budget -------------------------------------------------------------

    def budget(self, budget_id: Any, epsilon: Any, seq: Any) -> BudgetRecord:
        """Declare a privacy budget with total epsilon."""
        with self._lock:
            seq = self._claim(seq)
            try:
                bid = _check_id(budget_id)
                if bid in self._budgets:
                    raise DuplicateBudgetError(f"budget exists: {bid!r}")
                e_num, e_den = _check_epsilon(epsilon)
                record = BudgetRecord(
                    budget_id=bid,
                    epsilon_num=e_num,
                    epsilon_den=e_den,
                    digest=_digest_pin(bid, e_num, e_den),
                )
                self._budgets[bid] = record
                self._spent[bid] = 0
                self._emit(
                    "budget-declared",
                    {"budget_id": bid, "epsilon_num": e_num, "epsilon_den": e_den},
                )
                return record
            except DifferentialPrivacyError:
                self._emit("rejected", {"seq": seq, "op": "budget"})
                raise

    def budget_record(self, budget_id: Any) -> BudgetRecord:
        with self._lock:
            bid = _check_id(budget_id)
            if bid not in self._budgets:
                raise UnknownBudgetError(f"unknown budget: {bid!r}")
            return self._budgets[bid]

    def budget_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._budgets))

    def budget_spent(self, budget_id: Any) -> Tuple[int, int]:
        """Pure read view: spent epsilon as (num, den)."""
        with self._lock:
            bid = _check_id(budget_id)
            if bid not in self._budgets:
                raise UnknownBudgetError(f"unknown budget: {bid!r}")
            return (self._spent[bid], SCALE)

    # -- noise --------------------------------------------------------------

    def noise(
        self,
        budget_id: Any,
        mechanism: Any,
        seq: Any,
        epsilon: Any,
        sensitivity: Any = 1.0,
        query_digest: Any = "",
        delta: Any = None,
    ) -> NoiseRecord:
        """Book one declared noise query against a budget.

        epsilon is the spend booked against the budget (exact rational);
        spending more than remains fails closed. Scale is derived exactly:
        Laplace b = sensitivity / epsilon; Gaussian
        sigma = sensitivity * sqrt(2 ln(1.25 / delta)) / epsilon (delta
        required); exponential books no numeric scale/sample. The sample is
        deterministic bookkeeping data derived from the record id.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                bid = _check_id(budget_id)
                if bid not in self._budgets:
                    raise UnknownBudgetError(f"unknown budget: {bid!r}")
                if mechanism not in MECHANISMS:
                    raise BadMechanismError(f"bad mechanism: {mechanism!r}")
                e_num, e_den = _check_epsilon(epsilon)
                s_num, s_den = _check_sensitivity(sensitivity)
                q_digest = _check_query_digest(query_digest)

                if self._spent[bid] + e_num > self._budgets[bid].epsilon_num:
                    raise BudgetExhaustedError(
                        f"budget {bid!r} would exceed its epsilon"
                    )

                if mechanism == "laplace":
                    scale_num, scale_den = _laplace_scale(s_num, s_den, e_num, e_den)
                elif mechanism == "gaussian":
                    if delta is None:
                        raise BadDeltaError("gaussian requires delta")
                    d = _check_delta(delta)
                    scale_num, scale_den = _gaussian_scale(s_num, s_den, e_num, e_den, d)
                else:  # exponential: no numeric scale or sample
                    scale_num, scale_den = (0, 1)

                self._noise_seq += 1
                noise_id = f"nz-{self._noise_seq}"
                sample = _noise_sample(noise_id, mechanism, scale_num, scale_den)
                record = NoiseRecord(
                    noise_id=noise_id,
                    budget_id=bid,
                    mechanism=mechanism,
                    query_digest=q_digest,
                    epsilon_num=e_num,
                    epsilon_den=e_den,
                    sensitivity_num=s_num,
                    sensitivity_den=s_den,
                    scale_num=scale_num,
                    scale_den=scale_den,
                    noised_value=sample,
                    digest=_digest_pin(
                        noise_id, bid, mechanism, q_digest,
                        e_num, e_den, s_num, s_den,
                        scale_num, scale_den, repr(sample),
                    ),
                )
                self._noise[noise_id] = record
                self._spent[bid] += e_num
                self._emit(
                    "noise-booked",
                    {
                        "noise_id": noise_id,
                        "budget_id": bid,
                        "mechanism": mechanism,
                        "epsilon_num": e_num,
                        "epsilon_den": e_den,
                    },
                )
                return record
            except DifferentialPrivacyError:
                self._emit("rejected", {"seq": seq, "op": "noise"})
                raise

    def noise_record(self, noise_id: Any) -> NoiseRecord:
        with self._lock:
            if not isinstance(noise_id, str) or noise_id not in self._noise:
                raise UnknownBudgetError(f"unknown noise record: {noise_id!r}")
            return self._noise[noise_id]

    def noise_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._noise))

    # -- compose ------------------------------------------------------------

    def compose(self, seq: Any, budget_ids: Any = ()) -> CompositionRecord:
        """Book a basic-composition analysis over the named budgets.

        Empty budget_ids composes every declared budget. Total spent is the
        exact sum of booked spends (basic composition: eps_total = sum eps_i);
        remaining is total minus spent. Booked as a digest-pinned report.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                if isinstance(budget_ids, str) or not isinstance(budget_ids, (tuple, list)):
                    raise BadBudgetError("budget_ids must be a tuple/list")
                bids = tuple(_check_id(b) for b in budget_ids) or self.budget_ids()
                for b in bids:
                    if b not in self._budgets:
                        raise UnknownBudgetError(f"unknown budget: {b!r}")
                per_budget = []
                total_spent = 0
                total_capacity = 0
                for b in sorted(set(bids)):
                    spent_num = self._spent[b]
                    cap_num = self._budgets[b].epsilon_num
                    per_budget.append((b, spent_num, cap_num - spent_num))
                    total_spent += spent_num
                    total_capacity += cap_num
                total_remaining = total_capacity - total_spent
                self._composition_seq += 1
                comp_id = f"cmp-{self._composition_seq}"
                record = CompositionRecord(
                    composition_id=comp_id,
                    budget_ids=tuple(sorted(set(bids))),
                    total_spent_num=total_spent,
                    total_spent_den=SCALE,
                    total_remaining_num=total_remaining,
                    total_remaining_den=SCALE,
                    per_budget=tuple(per_budget),
                    digest=_digest_pin(
                        comp_id,
                        sorted(set(bids)),
                        total_spent, SCALE,
                        total_remaining, SCALE,
                        [list(row) for row in per_budget],
                    ),
                )
                self._compositions[comp_id] = record
                self._emit(
                    "composition-reported",
                    {
                        "composition_id": comp_id,
                        "total_spent_num": total_spent,
                        "total_spent_den": SCALE,
                    },
                )
                return record
            except DifferentialPrivacyError:
                self._emit("rejected", {"seq": seq, "op": "compose"})
                raise

    def composition_record(self, composition_id: Any) -> CompositionRecord:
        with self._lock:
            if not isinstance(composition_id, str) or composition_id not in self._compositions:
                raise UnknownBudgetError(f"unknown composition: {composition_id!r}")
            return self._compositions[composition_id]

    # -- views --------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "version": VERSION,
                "schema": SCHEMA,
                "budgets": len(self._budgets),
                "noise_queries": len(self._noise),
                "compositions": len(self._compositions),
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._audit]


def main() -> None:
    dp = DifferentialPrivacy()
    b = dp.budget("analytics", 1.0, 1)
    assert b.verify()
    nz = dp.noise("analytics", "laplace", 2, 0.5, sensitivity=1.0)
    assert nz.verify()
    assert nz.scale_num == 2 * SCALE  # b = 1.0 / 0.5
    assert isinstance(nz.noised_value, float)
    cmp_report = dp.compose(3, ("analytics",))
    assert cmp_report.verify()
    assert cmp_report.total_spent_num == SCALE // 2
    print("differential-privacy OK: budget, noise, compose, pins, audit")


if __name__ == "__main__":  # pragma: no cover
    main()
