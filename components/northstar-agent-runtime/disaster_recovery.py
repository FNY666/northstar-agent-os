"""Disaster recovery: DR plans, failover events, and drill bookkeeping.

A ``DisasterRecovery`` ledger books host-reported disaster-recovery
posture as a deterministic single-host state machine:

- ``plan(plan_id, name, seq, rpo_target_seq, rto_target_seq, tier)`` pins a
  recovery plan. **RPO** (recovery point objective) is the maximum
  acceptable data loss, booked in logical-seq units of ledger time;
  **RTO** (recovery time objective) is the maximum acceptable downtime,
  also in logical-seq units. Tiers are pinned to a vocabulary
  (``bronze``/``silver``/``gold``/``platinum``), each carrying a maximum
  tolerated RPO/RTO ceiling that the plan's targets may not exceed.
- ``failover(plan_id, seq, failure_type, data_loss_seq, downtime_seq)``
  books a declared disaster: the host reports how much ledger time was
  lost (``data_loss_seq``) and how long service was down
  (``downtime_seq``). Whether each target was met is recorded as
  *data* (``rpo_met``/``rto_met``), never raised. A plan already in an
  active failover refuses a second ``failover`` fail-closed; ``failback``
  closes the incident and returns the plan to ``ready``.
- ``test(plan_id, seq, kind)`` books a DR drill. Kinds are pinned to
  ``tabletop``/``failover-simulation``/``restore-test``/``game-day``;
  the host reports the measured recovery point/time and the module
  records whether the pinned targets were met, as data.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``disaster-recovery.v1``, schema pin
``northstar.disaster-recovery.v1``, ``main()`` self-check.

Honest scope: this module books *reported* recovery posture. It cannot
observe the real standby, cannot prove a failover would succeed, and
cannot distinguish a genuinely recovered ledger from a host that simply
reports small numbers. A drill passing means "the host reported
target-met numbers for this drill", never "the DR plan works".
Fail-closed rules keep the ledger honest: unknown plans, duplicate
plans, overlapping failovers, and drills on plans in active failover are
all refused. Pair with ``backup_manager`` for the actual backup-point
ledger when it exists.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
DISASTER_RECOVERY_VERSION = "disaster-recovery.v1"

#: Schema pin carried by records and audit events.
DISASTER_RECOVERY_SCHEMA = "northstar.disaster-recovery.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned tier vocabulary, with the RPO/RTO ceilings each tier tolerates.
TIERS: Dict[str, Dict[str, int]] = {
    "bronze": {"max_rpo_seq": 100000, "max_rto_seq": 100000},
    "silver": {"max_rpo_seq": 10000, "max_rto_seq": 10000},
    "gold": {"max_rpo_seq": 1000, "max_rto_seq": 1000},
    "platinum": {"max_rpo_seq": 100, "max_rto_seq": 100},
}

#: Pinned failure-type vocabulary for ``failover``.
FAILURE_TYPES = (
    "region-outage",
    "datacenter-loss",
    "data-corruption",
    "ransomware",
    "operator-error",
    "dependency-outage",
    "network-partition",
)

#: Pinned drill-kind vocabulary for ``test``.
TEST_KINDS = (
    "tabletop",
    "failover-simulation",
    "restore-test",
    "game-day",
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class DisasterRecoveryError(ValueError):
    """Base for all disaster-recovery structural problems and refused transitions."""


class BadPlanError(DisasterRecoveryError):
    """Plan definition is malformed (bad id/name/targets/tier)."""


class UnknownPlanError(DisasterRecoveryError):
    """No plan is pinned under the requested id."""


class DuplicatePlanError(DisasterRecoveryError):
    """A plan id is already registered."""


class ActiveFailoverError(DisasterRecoveryError):
    """The plan is already in an active failover."""


class NoActiveFailoverError(DisasterRecoveryError):
    """The plan has no active failover to close."""


class BadFailoverError(DisasterRecoveryError):
    """Failover/failback input is malformed (bad type/loss/downtime)."""


class BadTestError(DisasterRecoveryError):
    """Drill input is malformed (bad kind/measurements)."""


class SeqOrderError(DisasterRecoveryError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DisasterRecoveryError(f"{name} must be a non-empty string")
    return value.strip()


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([DISASTER_RECOVERY_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlanRecord:
    """One pinned DR plan (frozen)."""

    plan_id: str
    name: str
    rpo_target_seq: int
    rto_target_seq: int
    tier: str
    seq: int
    digest: str
    schema: str = DISASTER_RECOVERY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "plan", self.plan_id, self.name, self.rpo_target_seq,
            self.rto_target_seq, self.tier, self.seq,
        )


@dataclass(frozen=True)
class FailoverRecord:
    """One declared disaster / failover event (frozen)."""

    failover_id: str
    plan_id: str
    failure_type: str
    data_loss_seq: int
    downtime_seq: int
    rpo_met: bool
    rto_met: bool
    seq: int
    digest: str
    schema: str = DISASTER_RECOVERY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "failover", self.failover_id, self.plan_id, self.failure_type,
            self.data_loss_seq, self.downtime_seq, self.rpo_met,
            self.rto_met, self.seq,
        )


@dataclass(frozen=True)
class FailbackRecord:
    """One closed failover / return-to-primary event (frozen)."""

    failback_id: str
    plan_id: str
    failover_id: str
    recovery_seq: int
    seq: int
    digest: str
    schema: str = DISASTER_RECOVERY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "failback", self.failback_id, self.plan_id, self.failover_id,
            self.recovery_seq, self.seq,
        )


@dataclass(frozen=True)
class TestReport:
    """One DR drill result (frozen)."""

    test_id: str
    plan_id: str
    kind: str
    measured_loss_seq: int
    measured_downtime_seq: int
    rpo_met: bool
    rto_met: bool
    seq: int
    digest: str
    schema: str = DISASTER_RECOVERY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "test", self.test_id, self.plan_id, self.kind,
            self.measured_loss_seq, self.measured_downtime_seq,
            self.rpo_met, self.rto_met, self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_PLAN_DEFINED = "disaster-recovery.plan-defined"
KIND_FAILOVER_DECLARED = "disaster-recovery.failover-declared"
KIND_FAILBACK_COMPLETED = "disaster-recovery.failback-completed"
KIND_TEST_RUN = "disaster-recovery.test-run"
KIND_REJECTED = "disaster-recovery.rejected"
_KINDS = (
    KIND_PLAN_DEFINED,
    KIND_FAILOVER_DECLARED,
    KIND_FAILBACK_COMPLETED,
    KIND_TEST_RUN,
    KIND_REJECTED,
)


def disaster_recovery_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the disaster-recovery module."""
    if kind not in _KINDS:
        raise DisasterRecoveryError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise DisasterRecoveryError("detail must be a mapping")
    # Measured loss/downtime figures never cross the audit boundary; pins only.
    banned = {"data_loss_seq", "downtime_seq", "measured_loss_seq",
              "measured_downtime_seq"}
    if any(k in detail for k in banned):
        raise DisasterRecoveryError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": DISASTER_RECOVERY_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class DisasterRecovery:
    """Deterministic DR plan / failover / drill ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._plans: Dict[str, PlanRecord] = {}
        self._failovers: Dict[str, FailoverRecord] = {}
        self._active: Dict[str, str] = {}          # plan_id -> failover_id
        self._failbacks: Dict[str, FailbackRecord] = {}
        self._tests: Dict[str, TestReport] = {}
        self._failover_seq = 0
        self._failback_seq = 0
        self._test_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _audit_locked(self, kind: str, detail: Mapping[str, Any]) -> None:
        self._audit.append(
            disaster_recovery_audit_event(kind, detail, self._last_seq)
        )

    def _reject_locked(self, reason: str) -> None:
        self._audit_locked(KIND_REJECTED, {"reason": reason})

    def _plan_locked(self, plan_id: str) -> PlanRecord:
        try:
            return self._plans[plan_id]
        except KeyError:
            raise UnknownPlanError(f"unknown plan: {plan_id!r}")

    # -- plans ----------------------------------------------------------

    def plan(
        self,
        plan_id: str,
        name: str,
        seq: int,
        rpo_target_seq: int,
        rto_target_seq: int,
        tier: str = "silver",
    ) -> PlanRecord:
        """Pin a DR plan with RPO/RTO targets (logical-seq units)."""
        with self._lock:
            self._claim_seq(seq)
            plan_id = _check_nonempty_str(plan_id, "plan_id")
            name = _check_nonempty_str(name, "name")
            if isinstance(rpo_target_seq, bool) or not isinstance(rpo_target_seq, int):
                self._reject_locked("rpo_target_seq must be an int")
                raise BadPlanError("rpo_target_seq must be an int")
            if isinstance(rto_target_seq, bool) or not isinstance(rto_target_seq, int):
                self._reject_locked("rto_target_seq must be an int")
                raise BadPlanError("rto_target_seq must be an int")
            if rpo_target_seq <= 0 or rto_target_seq <= 0:
                self._reject_locked("targets must be positive")
                raise BadPlanError("rpo/rto targets must be positive ints")
            if tier not in TIERS:
                self._reject_locked(f"unknown tier {tier!r}")
                raise BadPlanError(f"unknown tier: {tier!r}")
            ceiling = TIERS[tier]
            if (rpo_target_seq > ceiling["max_rpo_seq"]
                    or rto_target_seq > ceiling["max_rto_seq"]):
                self._reject_locked("targets exceed tier ceiling")
                raise BadPlanError(
                    f"targets exceed {tier} ceilings "
                    f"(rpo<={ceiling['max_rpo_seq']}, "
                    f"rto<={ceiling['max_rto_seq']})"
                )
            if plan_id in self._plans:
                self._reject_locked(f"duplicate plan {plan_id!r}")
                raise DuplicatePlanError(f"plan already pinned: {plan_id!r}")
            record = PlanRecord(
                plan_id=plan_id,
                name=name,
                rpo_target_seq=rpo_target_seq,
                rto_target_seq=rto_target_seq,
                tier=tier,
                seq=seq,
                digest=_pin("plan", plan_id, name, rpo_target_seq,
                            rto_target_seq, tier, seq),
            )
            self._plans[plan_id] = record
            self._audit_locked(
                KIND_PLAN_DEFINED,
                {"plan_id": plan_id, "tier": tier,
                 "digest": record.digest},
            )
            return record

    # -- failover -------------------------------------------------------

    def failover(
        self,
        plan_id: str,
        seq: int,
        failure_type: str,
        *,
        data_loss_seq: int,
        downtime_seq: int,
    ) -> FailoverRecord:
        """Book a declared disaster for a plan. Target hits are data."""
        with self._lock:
            self._claim_seq(seq)
            plan_id = _check_nonempty_str(plan_id, "plan_id")
            plan = self._plan_locked(plan_id)
            if failure_type not in FAILURE_TYPES:
                self._reject_locked(f"unknown failure type {failure_type!r}")
                raise BadFailoverError(f"unknown failure_type: {failure_type!r}")
            for label, value in (("data_loss_seq", data_loss_seq),
                                 ("downtime_seq", downtime_seq)):
                if (isinstance(value, bool) or not isinstance(value, int)
                        or value < 0):
                    self._reject_locked(f"{label} must be a non-negative int")
                    raise BadFailoverError(
                        f"{label} must be a non-negative int")
            if plan_id in self._active:
                self._reject_locked(f"plan {plan_id!r} already in failover")
                raise ActiveFailoverError(
                    f"plan {plan_id!r} is already in an active failover")
            self._failover_seq += 1
            failover_id = f"fo-{self._failover_seq}"
            rpo_met = data_loss_seq <= plan.rpo_target_seq
            rto_met = downtime_seq <= plan.rto_target_seq
            record = FailoverRecord(
                failover_id=failover_id,
                plan_id=plan_id,
                failure_type=failure_type,
                data_loss_seq=data_loss_seq,
                downtime_seq=downtime_seq,
                rpo_met=rpo_met,
                rto_met=rto_met,
                seq=seq,
                digest=_pin("failover", failover_id, plan_id, failure_type,
                            data_loss_seq, downtime_seq, rpo_met, rto_met,
                            seq),
            )
            self._failovers[failover_id] = record
            self._active[plan_id] = failover_id
            self._audit_locked(
                KIND_FAILOVER_DECLARED,
                {"failover_id": failover_id, "plan_id": plan_id,
                 "failure_type": failure_type, "rpo_met": rpo_met,
                 "rto_met": rto_met, "digest": record.digest},
            )
            return record

    # -- failback -------------------------------------------------------

    def failback(self, plan_id: str, seq: int, *, recovery_seq: int) -> FailbackRecord:
        """Close an active failover and return the plan to ``ready``."""
        with self._lock:
            self._claim_seq(seq)
            plan_id = _check_nonempty_str(plan_id, "plan_id")
            self._plan_locked(plan_id)
            if (isinstance(recovery_seq, bool)
                    or not isinstance(recovery_seq, int) or recovery_seq < 0):
                self._reject_locked("recovery_seq must be a non-negative int")
                raise BadFailoverError(
                    "recovery_seq must be a non-negative int")
            try:
                failover_id = self._active[plan_id]
            except KeyError:
                self._reject_locked(f"plan {plan_id!r} has no active failover")
                raise NoActiveFailoverError(
                    f"plan {plan_id!r} has no active failover")
            self._failback_seq += 1
            failback_id = f"fb-{self._failback_seq}"
            record = FailbackRecord(
                failback_id=failback_id,
                plan_id=plan_id,
                failover_id=failover_id,
                recovery_seq=recovery_seq,
                seq=seq,
                digest=_pin("failback", failback_id, plan_id, failover_id,
                            recovery_seq, seq),
            )
            self._failbacks[failback_id] = record
            del self._active[plan_id]
            self._audit_locked(
                KIND_FAILBACK_COMPLETED,
                {"failback_id": failback_id, "plan_id": plan_id,
                 "failover_id": failover_id, "digest": record.digest},
            )
            return record

    # -- drills ---------------------------------------------------------

    def test(
        self,
        plan_id: str,
        seq: int,
        kind: str,
        *,
        measured_loss_seq: int,
        measured_downtime_seq: int,
    ) -> TestReport:
        """Book a DR drill. Target hits are data, never raised."""
        with self._lock:
            self._claim_seq(seq)
            plan_id = _check_nonempty_str(plan_id, "plan_id")
            plan = self._plan_locked(plan_id)
            if plan_id in self._active:
                self._reject_locked(f"plan {plan_id!r} is in active failover")
                raise ActiveFailoverError(
                    f"plan {plan_id!r} is in an active failover")
            if kind not in TEST_KINDS:
                self._reject_locked(f"unknown test kind {kind!r}")
                raise BadTestError(f"unknown test kind: {kind!r}")
            for label, value in (("measured_loss_seq", measured_loss_seq),
                                 ("measured_downtime_seq", measured_downtime_seq)):
                if (isinstance(value, bool) or not isinstance(value, int)
                        or value < 0):
                    self._reject_locked(f"{label} must be a non-negative int")
                    raise BadTestError(f"{label} must be a non-negative int")
            self._test_seq += 1
            test_id = f"tst-{self._test_seq}"
            rpo_met = measured_loss_seq <= plan.rpo_target_seq
            rto_met = measured_downtime_seq <= plan.rto_target_seq
            report = TestReport(
                test_id=test_id,
                plan_id=plan_id,
                kind=kind,
                measured_loss_seq=measured_loss_seq,
                measured_downtime_seq=measured_downtime_seq,
                rpo_met=rpo_met,
                rto_met=rto_met,
                seq=seq,
                digest=_pin("test", test_id, plan_id, kind, measured_loss_seq,
                            measured_downtime_seq, rpo_met, rto_met, seq),
            )
            self._tests[test_id] = report
            self._audit_locked(
                KIND_TEST_RUN,
                {"test_id": test_id, "plan_id": plan_id, "kind": kind,
                 "rpo_met": rpo_met, "rto_met": rto_met,
                 "digest": report.digest},
            )
            return report

    # -- views ----------------------------------------------------------

    def plan_record(self, plan_id: str) -> PlanRecord:
        """Return the pinned plan record."""
        with self._lock:
            return self._plan_locked(plan_id)

    def plan_status(self, plan_id: str) -> str:
        """``ready`` or ``active-failover``."""
        with self._lock:
            self._plan_locked(plan_id)
            return "active-failover" if plan_id in self._active else "ready"

    def active_failover(self, plan_id: str) -> FailoverRecord:
        """Return the active failover record for a plan."""
        with self._lock:
            self._plan_locked(plan_id)
            try:
                return self._failovers[self._active[plan_id]]
            except KeyError:
                raise NoActiveFailoverError(
                    f"plan {plan_id!r} has no active failover")

    def plan_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._plans)

    def failover_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._failovers)

    def test_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._tests)

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit)


# ---------------------------------------------------------------------------
# Module self-check
# ---------------------------------------------------------------------------


def main() -> None:
    dr = DisasterRecovery()
    plan = dr.plan("p1", "primary site", 1,
                   rpo_target_seq=100, rto_target_seq=50, tier="platinum")
    assert plan.verify()
    assert dr.plan_status("p1") == "ready"
    try:
        dr.plan("p1", "dup", 2, rpo_target_seq=10, rto_target_seq=10,
               tier="platinum")
    except DuplicatePlanError:
        pass
    else:
        raise AssertionError("duplicate plan must raise")
    # Drill passes both targets
    rep = dr.test("p1", 3, "game-day", measured_loss_seq=40,
                  measured_downtime_seq=20)
    assert rep.verify() and rep.rpo_met and rep.rto_met
    # Failover misses the RTO target as data
    fo = dr.failover("p1", 4, "region-outage", data_loss_seq=30,
                     downtime_seq=900)
    assert fo.verify() and fo.rpo_met and not fo.rto_met
    assert dr.plan_status("p1") == "active-failover"
    try:
        dr.failover("p1", 5, "datacenter-loss", data_loss_seq=0,
                    downtime_seq=0)
    except ActiveFailoverError:
        pass
    else:
        raise AssertionError("overlapping failover must raise")
    fb = dr.failback("p1", 6, recovery_seq=25)
    assert fb.verify()
    assert dr.plan_status("p1") == "ready"
    print("disaster-recovery OK: plan, test, failover, failback, pins")


if __name__ == "__main__":
    main()
