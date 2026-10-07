"""Fairness evaluation (bias testing) bookkeeping.

Bias-testing ledger for protected-group disparity measurement and mitigation
bookkeeping as a deterministic single-host state machine (the model this
shape mirrors: IBM AI Fairness 360 / Fairlearn / What-If Tool).

House style:
  - frozen dataclasses, caller int seqs strictly increasing (no wall-clock)
  - RLock-guarded, fail-closed, stdlib-only
  - `sha256:` digest pins with `verify()`
  - `audit.ndjson/1` events; group attributes are digest-pinned, raw values
    stay out of the audit boundary
  - failed mutations consume their seq (claim-then-burn) and book
    `fairness-eval.rejected`

Honest scope: books *host-reported* outcome rates and deterministic metric
arithmetic over them. A booked disparity means the host reported group
rates with this ratio/difference - never proof a real model is biased, and
never a verdict on real people. Mitigation bookings are declarations, not
proof a pipeline changed.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field, FrozenInstanceError
from typing import Any, Dict, List, Optional, Tuple

try:  # pragma: no cover - sibling convention
    from canonical_json import jcs_dumps  # type: ignore
except Exception:  # pragma: no cover
    def jcs_dumps(obj: Any) -> bytes:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

VERSION = "fairness-eval.v1"
SCHEMA = "northstar.fairness-eval.v1"

METRICS = ("disparate-impact", "statistical-parity", "equalized-odds")
STRATEGIES = ("reweight", "resample", "threshold-optimize", "constrain")


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

class FairnessEvalError(Exception):
    """Base."""


class BadGroupError(FairnessEvalError):
    pass


class DuplicateGroupError(FairnessEvalError):
    pass


class UnknownGroupError(FairnessEvalError):
    pass


class BadMetricError(FairnessEvalError):
    pass


class BadRateError(FairnessEvalError):
    pass


class BadStrategyError(FairnessEvalError):
    pass


class BadValueError(FairnessEvalError):
    pass


class SeqOrderError(FairnessEvalError):
    pass


class AuditKindError(FairnessEvalError):
    pass


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "group-registered",
    "disparity-measured",
    "mitigation-booked",
    "rejected",
)


def fairness_eval_audit_event(kind: str, detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"bad audit kind: {kind!r}")
    return {
        "kind": kind,
        "detail": dict(detail or {}),
        "schema": "audit.ndjson/1",
    }


_BANNED_AUDIT_KEYS = ("attributes", "description", "notes", "payload", "raw", "value")


def _check_audit_detail(detail: Dict[str, Any]) -> None:
    for key in _BANNED_AUDIT_KEYS:
        if key in detail:
            raise BadValueError(f"raw data key banned from audit boundary: {key!r}")


# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------

def _check_id(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BadGroupError(f"bad group id: {value!r}")
    if len(value) > 128:
        raise BadGroupError("group id too long")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"bad seq: {seq!r}")
    return seq


def _check_rate(value: Any) -> float:
    # host-reported favorable-outcome rate in [0,1]; bool is never a rate
    if isinstance(value, bool):
        raise BadRateError(f"bool is not a rate: {value!r}")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float) or not (0.0 <= value <= 1.0):
        raise BadRateError(f"bad rate: {value!r}")
    if value != value:  # NaN guard (defensive; comparisons already exclude)
        raise BadRateError("nan rate")
    return value


def _digest_pin(*parts: Any) -> str:
    blob = jcs_dumps(list(parts))
    if isinstance(blob, str):
        blob = blob.encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GroupRecord:
    group_id: str
    attribute_digest: str
    description_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(self.group_id, self.attribute_digest, self.description_digest)


@dataclass(frozen=True)
class DisparityReport:
    report_id: str
    group_a: str
    group_b: str
    metric: str
    rate_a_num: int
    rate_a_den: int
    rate_b_num: int
    rate_b_den: int
    ratio_num: int
    ratio_den: int
    difference_num: int
    difference_den: int
    verdict: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.report_id, self.group_a, self.group_b, self.metric,
            self.rate_a_num, self.rate_a_den, self.rate_b_num, self.rate_b_den,
            self.ratio_num, self.ratio_den, self.difference_num, self.difference_den,
            self.verdict,
        )


@dataclass(frozen=True)
class MitigationRecord:
    mitigation_id: str
    group_a: str
    group_b: str
    strategy: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.mitigation_id, self.group_a, self.group_b, self.strategy
        )


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------

class FairnessEval:
    """Protected-group disparity measurement + mitigation bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._groups: Dict[str, GroupRecord] = {}
        self._reports: Dict[str, DisparityReport] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._last_seq: int = -1
        self._report_seq = 0
        self._mitigation_seq = 0
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
        self._audit.append(fairness_eval_audit_event(audit_kind, detail))

    # -- group --------------------------------------------------------------

    def group(
        self,
        group_id: Any,
        seq: Any,
        description: str = "",
        attributes: Optional[Dict[str, Any]] = None,
    ) -> GroupRecord:
        """Book a protected-group declaration.

        `attributes` (e.g. {"gender": "f"}) is digest-pinned only; raw values
        never enter the record or cross the audit boundary.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                gid = _check_id(group_id)
                if gid in self._groups:
                    raise DuplicateGroupError(f"group exists: {gid!r}")
                attrs = attributes or {}
                if not isinstance(attrs, dict) or not all(
                    isinstance(k, str) for k in attrs
                ):
                    raise BadGroupError("attributes must be a str-keyed mapping")
                if not isinstance(description, str) or len(description) > 1024:
                    raise BadGroupError("bad description")
                attr_digest = _digest_pin(sorted(attrs.items()))
                desc_digest = _digest_pin(description)
                record = GroupRecord(
                    group_id=gid,
                    attribute_digest=attr_digest,
                    description_digest=desc_digest,
                    digest=_digest_pin(gid, attr_digest, desc_digest),
                )
                self._groups[gid] = record
                self._emit(
                    "group-registered",
                    {"group_id": gid, "attribute_digest": attr_digest},
                )
                return record
            except FairnessEvalError:
                self._emit("rejected", {"seq": seq, "op": "group"})
                raise

    def group_record(self, group_id: Any) -> GroupRecord:
        with self._lock:
            gid = _check_id(group_id)
            if gid not in self._groups:
                raise UnknownGroupError(f"unknown group: {gid!r}")
            return self._groups[gid]

    def group_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._groups))

    # -- disparity ----------------------------------------------------------

    def disparity(
        self,
        group_a: Any,
        group_b: Any,
        metric: Any,
        rate_a: Any,
        rate_b: Any,
        seq: Any,
    ) -> DisparityReport:
        """Book a disparity computation over host-reported rates.

        Rates are booked as exact (num, den) rationals (6-decimal scaling).
        Verdict is *data*, never raised:

        - disparate-impact: min/max ratio; "no-adverse-impact" if ratio >= 4/5
        - statistical-parity: |rate_a - rate_b|; "parity" if diff <= 1/10
        - equalized-odds: booked with the same arithmetic as statistical parity
          (TPR/FPR equality is the host's claim); "odds-equal" if diff <= 1/10
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                ga = _check_id(group_a)
                gb = _check_id(group_b)
                if ga not in self._groups:
                    raise UnknownGroupError(f"unknown group: {ga!r}")
                if gb not in self._groups:
                    raise UnknownGroupError(f"unknown group: {gb!r}")
                if ga == gb:
                    raise BadGroupError("need two distinct groups")
                if metric not in METRICS:
                    raise BadMetricError(f"bad metric: {metric!r}")
                ra = _check_rate(rate_a)
                rb = _check_rate(rate_b)

                def rational(v: float) -> Tuple[int, int]:
                    num = round(v * 1_000_000)
                    return (num, 1_000_000)

                ra_num, ra_den = rational(ra)
                rb_num, rb_den = rational(rb)
                lo, hi = (ra, rb) if ra <= rb else (rb, ra)
                # exact rational arithmetic: ratio = lo/hi (scaled ints)
                if hi == 0.0:
                    ratio_num, ratio_den = (1, 1) if lo == 0.0 else (0, 1)
                else:
                    ratio_num = round(lo * 1_000_000)
                    ratio_den = round(hi * 1_000_000) or 1
                diff = abs(ra - rb)
                difference_num, difference_den = (round(diff * 1_000_000), 1_000_000)

                if metric == "disparate-impact":
                    verdict = (
                        "no-adverse-impact"
                        if ratio_num * 5 >= ratio_den * 4
                        else "adverse-impact"
                    )
                elif metric == "statistical-parity":
                    verdict = "parity" if difference_num * 10 <= difference_den else "disparity"
                else:  # equalized-odds
                    verdict = "odds-equal" if difference_num * 10 <= difference_den else "odds-unequal"

                self._report_seq += 1
                report_id = f"dsp-{self._report_seq}"
                report = DisparityReport(
                    report_id=report_id,
                    group_a=ga,
                    group_b=gb,
                    metric=metric,
                    rate_a_num=ra_num,
                    rate_a_den=ra_den,
                    rate_b_num=rb_num,
                    rate_b_den=rb_den,
                    ratio_num=ratio_num,
                    ratio_den=ratio_den,
                    difference_num=difference_num,
                    difference_den=difference_den,
                    verdict=verdict,
                    digest=_digest_pin(
                        report_id, ga, gb, metric,
                        ra_num, ra_den, rb_num, rb_den,
                        ratio_num, ratio_den, difference_num, difference_den,
                        verdict,
                    ),
                )
                self._reports[report_id] = report
                self._emit(
                    "disparity-measured",
                    {
                        "report_id": report_id,
                        "group_a": ga,
                        "group_b": gb,
                        "metric": metric,
                        "verdict": verdict,
                    },
                )
                return report
            except FairnessEvalError:
                self._emit("rejected", {"seq": seq, "op": "disparity"})
                raise

    def disparity_report(self, report_id: Any) -> DisparityReport:
        with self._lock:
            if not isinstance(report_id, str) or report_id not in self._reports:
                raise UnknownGroupError(f"unknown report: {report_id!r}")
            return self._reports[report_id]

    def report_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._reports))

    # -- mitigate -----------------------------------------------------------

    def mitigate(
        self,
        group_a: Any,
        group_b: Any,
        strategy: Any,
        seq: Any,
    ) -> MitigationRecord:
        """Book a mitigation decision as a declaration.

        Pinned strategy vocabulary: reweight / resample / threshold-optimize /
        constrain. Booking records the *decision*, never proof a pipeline
        changed.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                ga = _check_id(group_a)
                gb = _check_id(group_b)
                if ga not in self._groups:
                    raise UnknownGroupError(f"unknown group: {ga!r}")
                if gb not in self._groups:
                    raise UnknownGroupError(f"unknown group: {gb!r}")
                if ga == gb:
                    raise BadGroupError("need two distinct groups")
                if strategy not in STRATEGIES:
                    raise BadStrategyError(f"bad strategy: {strategy!r}")
                self._mitigation_seq += 1
                mitigation_id = f"mit-{self._mitigation_seq}"
                record = MitigationRecord(
                    mitigation_id=mitigation_id,
                    group_a=ga,
                    group_b=gb,
                    strategy=strategy,
                    digest=_digest_pin(mitigation_id, ga, gb, strategy),
                )
                self._mitigations[mitigation_id] = record
                self._emit(
                    "mitigation-booked",
                    {"mitigation_id": mitigation_id, "strategy": strategy},
                )
                return record
            except FairnessEvalError:
                self._emit("rejected", {"seq": seq, "op": "mitigate"})
                raise

    def mitigation_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._mitigations))

    # -- views --------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "version": VERSION,
                "schema": SCHEMA,
                "groups": len(self._groups),
                "reports": len(self._reports),
                "mitigations": len(self._mitigations),
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._audit]


def main() -> None:
    fe = FairnessEval()
    fe.group("g-a", 1, attributes={"age": "young"})
    fe.group("g-b", 2, attributes={"age": "old"})
    report = fe.disparity("g-a", "g-b", "disparate-impact", 0.8, 0.9, 3)
    assert report.verify()
    mit = fe.mitigate("g-a", "g-b", "reweight", 4)
    assert mit.verify()
    print("fairness-eval OK: group, disparity, mitigate, pins, audit")


if __name__ == "__main__":  # pragma: no cover
    main()
