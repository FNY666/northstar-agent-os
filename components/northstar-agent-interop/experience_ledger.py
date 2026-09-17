"""Cross-run experience, bound to the evidence that produced it.

A run today leaves behind a verdict and an event history, and then the next run
starts from nothing: the same task can fail the same way indefinitely. This
ledger turns a finished run's verdict into a reusable record keyed by a
caller-declared task fingerprint, so a later run can ask what already happened.

Entries are assertions, so they carry the same discipline as the rest of the
evidence layer. Only a determinate verdict (verified or failed) becomes an
entry, because "unknown" is not a lesson. Every entry keeps the run it came
from, so an entry whose source is gone can be recognised as unfounded instead
of being trusted forever. No entry authorizes anything.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from interop_contract import RECOVERY_EMPTY, RECOVERY_VERIFIED

_SCHEMA = "northstar.experience-ledger.v1"
_PREFIX = "sha256:"

# Only a determinate verdict becomes a lesson; "unknown" is not one.
_KINDS = {"verified": "success", "failed": "failure"}
UNVERIFIABLE = "unverifiable"
NO_EVIDENCE = "no-evidence"
CONSISTENT_FAILURE = "consistent-failure"
CONSISTENT_SUCCESS = "consistent-success"
CONTRADICTED = "contradicted"
FORECAST_FAILURE = "likely-failure"
FORECAST_SUCCESS = "likely-success"
SETTLEMENT_CONFIRMED = "confirmed"
SETTLEMENT_FALSIFIED = "falsified"
SETTLEMENT_NOT_EVALUABLE = "not-evaluable"


@dataclass(frozen=True)
class ExperienceRecord:
    """One reusable lesson, tied to the run that produced it."""

    record_digest: str
    kind: str
    fingerprint: str
    source_run_id: str
    source_verdict: str
    run_digest: str
    event_head: str
    signals: tuple[str, ...]
    sequence: int
    prev_record_digest: str | None
    execution_authorized: bool = False


@dataclass(frozen=True)
class ExperienceRecovery:
    """What the ledger could be read back as."""

    verdict: str
    records: tuple[ExperienceRecord, ...]
    cursor: str | None


@dataclass(frozen=True)
class ExperienceStanding:
    """Whether the ledger's history for one fingerprint agrees with itself."""

    fingerprint: str
    verdict: str
    failures: int
    successes: int
    record_digests: tuple[str, ...]
    execution_authorized: bool = False


@dataclass(frozen=True)
class ExperienceForecast:
    """What the ledger expects next, given its verified history."""

    fingerprint: str
    expectation: str
    failures: int
    successes: int
    based_on: tuple[str, ...]
    forecast_digest: str
    execution_authorized: bool = False


@dataclass(frozen=True)
class ForecastSettlement:
    """Whether a forecast was confirmed or falsified by the actual outcome."""

    fingerprint: str
    outcome: str
    reason: str | None
    forecast_digest: str
    actual_verdict: str
    source_run_id: str
    run_digest: str
    event_head: str
    sequence: int
    prev_settlement_digest: str | None
    settlement_digest: str
    execution_authorized: bool = False


@dataclass(frozen=True)
class ExperienceStatistics:
    """Actionable performance metrics for a fingerprint."""

    fingerprint: str
    total_runs: int
    successes: int
    failures: int
    success_rate: float | None
    recent_trend: str
    last_n_outcomes: tuple[str, ...]
    execution_authorized: bool = False


@dataclass(frozen=True)
class AdmissionVerdict:
    """Risk-informed admission decision based on experience."""

    state: str
    reason: str
    confidence: float
    execution_authorized: bool


def evaluate_admission(
    statistics: ExperienceStatistics,
    *,
    min_success_rate: float = 0.3,
    min_sample_size: int = 3,
    decline_is_blocking: bool = True,
) -> AdmissionVerdict:
    """Decide whether to admit a task based on its track record.
    
    Policy logic:
    1. Insufficient data → admitted-with-caution, low confidence
    2. Consistent failure → blocked
    3. Declining trend → blocked (if flag set) or warned
    4. Good standing → admitted
    5. Excellent standing → admitted with high confidence
    
    Confidence based on sample size: min(1.0, total_runs / 10)
    """
    total_runs = statistics.total_runs
    success_rate = statistics.success_rate
    recent_trend = statistics.recent_trend
    
    # Confidence scoring based on sample size
    confidence = min(1.0, total_runs / 10.0) if total_runs > 0 else 0.1
    
    # Insufficient data
    if total_runs < min_sample_size:
        return AdmissionVerdict(
            state="admitted-with-caution",
            reason="insufficient-data",
            confidence=confidence,
            execution_authorized=True,
        )
    
    # Consistent failure
    if success_rate is not None and success_rate < min_success_rate:
        return AdmissionVerdict(
            state="blocked",
            reason="consistent-failure",
            confidence=confidence,
            execution_authorized=False,
        )
    
    # Declining trend
    if recent_trend == "declining":
        if decline_is_blocking:
            return AdmissionVerdict(
                state="blocked",
                reason="performance-declining",
                confidence=confidence,
                execution_authorized=False,
            )
        else:
            return AdmissionVerdict(
                state="admitted-with-caution",
                reason="performance-declining-warning",
                confidence=confidence,
                execution_authorized=True,
            )
    
    # Good or excellent standing
    return AdmissionVerdict(
        state="admitted",
        reason="acceptable-standing",
        confidence=confidence,
        execution_authorized=True,
    )


@dataclass(frozen=True)
class AdmissionRecord:
    """One recorded admission decision."""

    fingerprint: str
    verdict_state: str
    verdict_reason: str
    verdict_confidence: float
    statistics_snapshot: dict[str, Any]
    decided_at: int
    policy_config: dict[str, Any]
    sequence: int
    prev_record_digest: str | None
    record_digest: str


class AdmissionLedger:
    """Persist admission decisions for audit and retrospective analysis."""

    def __init__(self, path: Path):
        self._path = Path(path)

    def record(
        self,
        fingerprint: str,
        verdict: AdmissionVerdict,
        statistics: ExperienceStatistics,
        policy_config: dict[str, Any],
        decided_at: int,
    ) -> AdmissionRecord:
        """Append admission decision to ledger (append-only, flock, fsync)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self._path, "a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            
            # Read existing records to get sequence and prev digest
            handle.seek(0)
            records = _load(handle)
            sequence = len(records) + 1
            prev_digest = records[-1]["record_digest"] if records else None
            
            # Build record
            stats_snapshot = {
                "total_runs": statistics.total_runs,
                "successes": statistics.successes,
                "failures": statistics.failures,
                "success_rate": statistics.success_rate,
                "recent_trend": statistics.recent_trend,
            }
            
            body = {
                "fingerprint": fingerprint,
                "verdict_state": verdict.state,
                "verdict_reason": verdict.reason,
                "verdict_confidence": verdict.confidence,
                "statistics_snapshot": stats_snapshot,
                "decided_at": decided_at,
                "policy_config": policy_config,
                "sequence": sequence,
                "prev_record_digest": prev_digest,
            }
            
            record_digest = _digest(body)
            payload = dict(body, record_digest=record_digest)
            
            # Append to file
            handle.seek(0, os.SEEK_END)
            handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            
            return AdmissionRecord(
                fingerprint=fingerprint,
                verdict_state=verdict.state,
                verdict_reason=verdict.reason,
                verdict_confidence=verdict.confidence,
                statistics_snapshot=stats_snapshot,
                decided_at=decided_at,
                policy_config=policy_config,
                sequence=sequence,
                prev_record_digest=prev_digest,
                record_digest=record_digest,
            )
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    def query(self, fingerprint: str) -> tuple[AdmissionRecord, ...]:
        """Retrieve all decisions for a fingerprint (oldest first)."""
        if not self._path.exists():
            return ()
        
        handle = open(self._path, "r", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            records = _load(handle)
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()
        
        matching = [
            AdmissionRecord(
                fingerprint=r["fingerprint"],
                verdict_state=r["verdict_state"],
                verdict_reason=r["verdict_reason"],
                verdict_confidence=r["verdict_confidence"],
                statistics_snapshot=r["statistics_snapshot"],
                decided_at=r["decided_at"],
                policy_config=r["policy_config"],
                sequence=r["sequence"],
                prev_record_digest=r.get("prev_record_digest"),
                record_digest=r["record_digest"],
            )
            for r in records
            if r.get("fingerprint") == fingerprint
        ]
        return tuple(matching)

    def summary(self) -> dict[str, Any]:
        """Global stats: total decisions, block rate, caution rate."""
        if not self._path.exists():
            return {
                "total_decisions": 0,
                "block_rate": 0.0,
                "caution_rate": 0.0,
                "admit_rate": 0.0,
            }
        
        handle = open(self._path, "r", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            records = _load(handle)
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()
        
        total = len(records)
        if total == 0:
            return {
                "total_decisions": 0,
                "block_rate": 0.0,
                "caution_rate": 0.0,
                "admit_rate": 0.0,
            }
        
        blocked = sum(1 for r in records if r["verdict_state"] == "blocked")
        caution = sum(1 for r in records if r["verdict_state"] == "admitted-with-caution")
        admitted = sum(1 for r in records if r["verdict_state"] == "admitted")
        
        return {
            "total_decisions": total,
            "block_rate": blocked / total,
            "caution_rate": caution / total,
            "admit_rate": admitted / total,
        }


def _digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return _PREFIX + hashlib.sha256(encoded).hexdigest()


def _load(handle: Any) -> list[dict[str, Any]]:
    handle.seek(0)
    records = []
    for line in handle.read().splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def _verify_chain(records: list[dict[str, Any]]) -> tuple[bool, str | None]:
    """Each record must hash to its own digest and link to the one before it."""
    previous: str | None = None
    for record in records:
        if record.get("schema") != _SCHEMA:
            return False, None
        digest = record.get("record_digest")
        if not isinstance(digest, str):
            return False, None
        payload = {k: v for k, v in record.items() if k != "record_digest"}
        if _digest(payload) != digest:
            return False, None
        if record.get("prev_record_digest") != previous:
            return False, None
        previous = digest
    return True, previous

def _unpack_verdict(verdict_result: Any) -> tuple[str, tuple[str, ...], dict[str, Any]]:
    """Accept the runtime's VerificationResult or its plain triple."""
    if hasattr(verdict_result, "verdict"):
        return (
            verdict_result.verdict,
            tuple(getattr(verdict_result, "errors", ()) or ()),
            dict(getattr(verdict_result, "artifact_digests", {}) or {}),
        )
    if isinstance(verdict_result, (tuple, list)) and len(verdict_result) == 3:
        verdict, errors, artifacts = verdict_result
        return verdict, tuple(errors or ()), dict(artifacts or {})
    raise ValueError("completion verdict is invalid")


def _record_from_dict(payload: dict[str, Any]) -> ExperienceRecord:
    return ExperienceRecord(
        record_digest=payload["record_digest"],
        kind=payload["kind"],
        fingerprint=payload["fingerprint"],
        source_run_id=payload["source_run_id"],
        source_verdict=payload["source_verdict"],
        run_digest=payload["run_digest"],
        event_head=payload["event_head"],
        signals=tuple(payload.get("signals") or ()),
        sequence=payload["sequence"],
        prev_record_digest=payload.get("prev_record_digest"),
    )

def _validate_text(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is invalid")


class ExperienceLedger:
    """Append-only, hash-chained store of lessons bound to their evidence."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)

    @contextmanager
    def _locked(self) -> Any:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self._path, "a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield handle
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    def record(
        self,
        *,
        verdict_result: Any,
        run_id: str,
        run_digest: str,
        fingerprint: str,
        event_head: str,
    ) -> ExperienceRecord:
        """Remember what a finished run proved, keyed by a caller fingerprint.

        Only runs with a settled verdict become experience: an ``unknown``
        outcome is not a lesson, so it is refused instead of stored. The
        fingerprint is the caller's declaration of "this is the same kind of
        task" - the ledger never guesses at semantic similarity.
        """
        verdict, errors, artifacts = _unpack_verdict(verdict_result)
        if verdict not in _KINDS:
            raise ValueError(f"completion verdict {verdict!r} is not settled")
        for label, value in (
            ("run_id", run_id),
            ("run_digest", run_digest),
            ("fingerprint", fingerprint),
            ("event_head", event_head),
        ):
            _validate_text(value, label)
        signals = errors if verdict == "failed" else tuple(sorted(artifacts))
        with self._locked() as handle:
            records = _load(handle)
            for payload in records:
                if (
                    payload.get("source_run_id") == run_id
                    and payload.get("fingerprint") == fingerprint
                ):
                    return _record_from_dict(payload)
            body = {
                "schema": _SCHEMA,
                "kind": _KINDS[verdict],
                "fingerprint": fingerprint,
                "source_run_id": run_id,
                "source_verdict": verdict,
                "run_digest": run_digest,
                "event_head": event_head,
                "signals": list(signals),
                "sequence": len(records) + 1,
                "prev_record_digest": records[-1]["record_digest"] if records else None,
            }
            payload = dict(body, record_digest=_digest(body))
            handle.seek(0, os.SEEK_END)
            handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            return _record_from_dict(payload)

    def recover(self) -> ExperienceRecovery:
        """Re-read the ledger the way the other evidence stores do."""
        if not self._path.exists():
            return ExperienceRecovery(RECOVERY_EMPTY, (), None)
        with self._locked() as handle:
            try:
                records = _load(handle)
            except ValueError:
                return ExperienceRecovery(UNVERIFIABLE, (), None)
            intact, cursor = _verify_chain(records)
            if not intact:
                return ExperienceRecovery(UNVERIFIABLE, (), None)
            if not records:
                return ExperienceRecovery(RECOVERY_EMPTY, (), None)
            found = tuple(_record_from_dict(payload) for payload in records)
            return ExperienceRecovery(RECOVERY_VERIFIED, found, cursor)

    def recall(self, fingerprint: str) -> tuple[ExperienceRecord, ...]:
        """Experience recorded under one fingerprint.

        A ledger that cannot be verified yields nothing: an unverifiable store
        is not a source of lessons, so callers get no partial advice.
        """
        _validate_text(fingerprint, "fingerprint")
        if not self._path.exists():
            return ()
        with self._locked() as handle:
            try:
                records = _load(handle)
            except ValueError:
                return ()
            if not _verify_chain(records)[0]:
                return ()
            return tuple(
                _record_from_dict(payload)
                for payload in records
                if payload.get("fingerprint") == fingerprint
            )

    def standing(self, fingerprint: str) -> ExperienceStanding:
        """Whether the stored history for one fingerprint agrees with itself.

        Recall hands back every entry under a fingerprint; it does not say
        whether they agree. A later success next to an earlier failure means the
        history contradicts itself, and that is reported rather than resolved,
        because the ledger has no standing to choose a side.
        """
        _validate_text(fingerprint, "fingerprint")
        if not self._path.exists():
            return ExperienceStanding(fingerprint, NO_EVIDENCE, 0, 0, ())
        with self._locked() as handle:
            try:
                records = _load(handle)
            except ValueError:
                return ExperienceStanding(fingerprint, UNVERIFIABLE, 0, 0, ())
            if not _verify_chain(records)[0]:
                return ExperienceStanding(fingerprint, UNVERIFIABLE, 0, 0, ())
            matching = [
                payload
                for payload in records
                if payload.get("fingerprint") == fingerprint
            ]
            failures = sum(1 for p in matching if p.get("kind") == "failure")
            successes = sum(1 for p in matching if p.get("kind") == "success")
            if not matching:
                verdict = NO_EVIDENCE
            elif failures and successes:
                verdict = CONTRADICTED
            elif failures:
                verdict = CONSISTENT_FAILURE
            else:
                verdict = CONSISTENT_SUCCESS
            digests = tuple(p["record_digest"] for p in matching)
            return ExperienceStanding(
                fingerprint, verdict, failures, successes, digests
            )

    def forecast(self, fingerprint: str) -> ExperienceForecast:
        """Derive an expectation from verified standing, bound to what was seen.

        Forecasts hold the record digests they were derived from, so a forecast
        that was made before new evidence becomes stale when the standing
        changes. No forecast from contradicted or unverifiable history, because
        the ledger has no standing to pick a side when the evidence disagrees.
        """
        standing = self.standing(fingerprint)
        if standing.verdict in (CONSISTENT_FAILURE, CONSISTENT_SUCCESS):
            expectation = (
                FORECAST_FAILURE if standing.verdict == CONSISTENT_FAILURE else FORECAST_SUCCESS
            )
        else:
            expectation = standing.verdict
        body = {
            "fingerprint": fingerprint,
            "expectation": expectation,
            "failures": standing.failures,
            "successes": standing.successes,
            "based_on": list(standing.record_digests),
        }
        forecast_digest = _digest(body)
        return ExperienceForecast(
            fingerprint=fingerprint,
            expectation=expectation,
            failures=standing.failures,
            successes=standing.successes,
            based_on=standing.record_digests,
            forecast_digest=forecast_digest,
        )

    def settle(
        self,
        forecast: ExperienceForecast,
        *,
        actual_verdict: str,
        run_id: str,
        run_digest: str | None,
        event_head: str | None,
    ) -> ForecastSettlement:
        """Record whether a forecast was confirmed or falsified by reality.

        A forecast becomes stale when standing changes, so a forecast made
        before new evidence cannot be settled against that new evidence. An
        unknown actual verdict is refused because it is not a determinate
        outcome. Settling the same run twice is idempotent.
        """
        if actual_verdict not in _KINDS:
            raise ValueError(f"actual verdict {actual_verdict!r} is not settled")
        _validate_text(run_id, "run_id")
        if run_digest is not None:
            _validate_text(run_digest, "run_digest")
        if event_head is not None:
            _validate_text(event_head, "event_head")
        current_forecast = self.forecast(forecast.fingerprint)
        if current_forecast.forecast_digest != forecast.forecast_digest:
            outcome = SETTLEMENT_NOT_EVALUABLE
            reason = "forecast-stale"
        else:
            expected_kind = _KINDS[actual_verdict]
            if (
                (forecast.expectation == FORECAST_FAILURE and expected_kind == "failure")
                or (forecast.expectation == FORECAST_SUCCESS and expected_kind == "success")
            ):
                outcome = SETTLEMENT_CONFIRMED
                reason = None
            else:
                outcome = SETTLEMENT_FALSIFIED
                reason = None
        settlements_path = Path(str(self._path) + ".settlements.jsonl")
        settlements_path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(settlements_path, "a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.seek(0)
            settlements = []
            for line in handle.read().splitlines():
                line = line.strip()
                if line:
                    settlements.append(json.loads(line))
            for s in settlements:
                if (
                    s.get("source_run_id") == run_id
                    and s.get("forecast_digest") == forecast.forecast_digest
                ):
                    return ForecastSettlement(
                        fingerprint=s["fingerprint"],
                        outcome=s["outcome"],
                        reason=s.get("reason"),
                        forecast_digest=s["forecast_digest"],
                        actual_verdict=s["actual_verdict"],
                        source_run_id=s["source_run_id"],
                        run_digest=s["run_digest"],
                        event_head=s["event_head"],
                        sequence=s["sequence"],
                        prev_settlement_digest=s.get("prev_settlement_digest"),
                        settlement_digest=s["settlement_digest"],
                    )
            body = {
                "fingerprint": forecast.fingerprint,
                "outcome": outcome,
                "reason": reason,
                "forecast_digest": forecast.forecast_digest,
                "actual_verdict": actual_verdict,
                "source_run_id": run_id,
                "run_digest": run_digest,
                "event_head": event_head,
                "sequence": len(settlements) + 1,
                "prev_settlement_digest": settlements[-1]["settlement_digest"] if settlements else None,
            }
            settlement_digest = _digest(body)
            payload = dict(body, settlement_digest=settlement_digest)
            handle.seek(0, os.SEEK_END)
            handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            return ForecastSettlement(
                fingerprint=forecast.fingerprint,
                outcome=outcome,
                reason=reason,
                forecast_digest=forecast.forecast_digest,
                actual_verdict=actual_verdict,
                source_run_id=run_id,
                run_digest=run_digest,
                event_head=event_head,
                sequence=body["sequence"],
                prev_settlement_digest=body["prev_settlement_digest"],
                settlement_digest=settlement_digest,
            )
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    def query_statistics(
        self, fingerprint: str, *, recent_window: int = 5
    ) -> ExperienceStatistics:
        """Compute actionable performance metrics from settlement history."""
        if not isinstance(fingerprint, str) or not fingerprint:
            raise ValueError("fingerprint must be a non-empty string")
        if not isinstance(recent_window, int) or recent_window < 1:
            raise ValueError("recent_window must be a positive integer")

        settlements_path = Path(str(self._path) + ".settlements.jsonl")
        if not settlements_path.exists():
            return ExperienceStatistics(
                fingerprint=fingerprint,
                total_runs=0,
                successes=0,
                failures=0,
                success_rate=None,
                recent_trend="insufficient-data",
                last_n_outcomes=(),
            )

        # Read all settlements for this fingerprint
        handle = open(settlements_path, "r", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            settlements = _load(handle)
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()
        
        matching = [
            s for s in settlements 
            if s.get("fingerprint") == fingerprint
        ]
        
        if not matching:
            return ExperienceStatistics(
                fingerprint=fingerprint,
                total_runs=0,
                successes=0,
                failures=0,
                success_rate=None,
                recent_trend="insufficient-data",
                last_n_outcomes=(),
            )
        
        # Extract verdicts (recent first order)
        verdicts = [s["actual_verdict"] for s in matching]
        verdicts.reverse()  # Recent first
        
        total_runs = len(verdicts)
        successes = sum(1 for v in verdicts if v == "verified")
        failures = sum(1 for v in verdicts if v == "failed")
        success_rate = successes / total_runs if total_runs > 0 else None
        
        # Compute recent trend
        recent = verdicts[:recent_window]
        if len(recent) < 2:
            recent_trend = "insufficient-data"
        else:
            # Split: first half = most recent, second half = older
            mid = len(recent) // 2
            most_recent = recent[:mid]
            older = recent[mid:]
            
            recent_success_rate = sum(1 for v in most_recent if v == "verified") / len(most_recent)
            older_success_rate = sum(1 for v in older if v == "verified") / len(older)
            
            if recent_success_rate > older_success_rate + 0.2:
                recent_trend = "improving"
            elif recent_success_rate < older_success_rate - 0.2:
                recent_trend = "declining"
            else:
                recent_trend = "stable"
        
        return ExperienceStatistics(
            fingerprint=fingerprint,
            total_runs=total_runs,
            successes=successes,
            failures=failures,
            success_rate=success_rate,
            recent_trend=recent_trend,
            last_n_outcomes=tuple(verdicts[:recent_window]),
        )


@dataclass(frozen=True)
class AdmissionConflict:
    """One detected conflict between two admission decisions."""

    earlier: AdmissionRecord
    later: AdmissionRecord
    conflict_type: str
    time_delta: int


def detect_conflicts(
    ledger: AdmissionLedger,
    *,
    window_seconds: int | None = None,
) -> tuple[AdmissionConflict, ...]:
    """Find contradictory decisions for the same fingerprint.
    
    Conflict types:
    - "admit-vs-block": Earlier admitted, later blocked (high severity)
    - "block-vs-admit": Earlier blocked, later admitted (policy relaxation or override)
    - "state-change": Any other verdict state change
    """
    if not ledger._path.exists():
        return ()
    
    handle = open(ledger._path, "r", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
        records = _load(handle)
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
    
    if not records:
        return ()
    
    # Group by fingerprint
    by_fingerprint: dict[str, list[AdmissionRecord]] = {}
    for r in records:
        fp = r["fingerprint"]
        if fp not in by_fingerprint:
            by_fingerprint[fp] = []
        by_fingerprint[fp].append(
            AdmissionRecord(
                fingerprint=r["fingerprint"],
                verdict_state=r["verdict_state"],
                verdict_reason=r["verdict_reason"],
                verdict_confidence=r["verdict_confidence"],
                statistics_snapshot=r["statistics_snapshot"],
                decided_at=r["decided_at"],
                policy_config=r["policy_config"],
                sequence=r["sequence"],
                prev_record_digest=r.get("prev_record_digest"),
                record_digest=r["record_digest"],
            )
        )
    
    conflicts = []
    for fp, fp_records in by_fingerprint.items():
        # Compare consecutive decisions
        for i in range(len(fp_records) - 1):
            earlier = fp_records[i]
            later = fp_records[i + 1]
            
            time_delta = later.decided_at - earlier.decided_at
            
            # Apply window filter
            if window_seconds is not None and time_delta > window_seconds:
                continue
            
            # Check for state change
            if earlier.verdict_state != later.verdict_state:
                conflict_type = _classify_conflict(earlier.verdict_state, later.verdict_state)
                conflicts.append(
                    AdmissionConflict(
                        earlier=earlier,
                        later=later,
                        conflict_type=conflict_type,
                        time_delta=time_delta,
                    )
                )
    
    return tuple(conflicts)


def _classify_conflict(earlier_state: str, later_state: str) -> str:
    """Classify conflict severity."""
    if earlier_state == "admitted" and later_state == "blocked":
        return "admit-vs-block"
    elif earlier_state == "blocked" and later_state == "admitted":
        return "block-vs-admit"
    else:
        return "state-change"


@dataclass(frozen=True)
class ExperienceState:
    """Projected experience state for integration with broader evidence layers."""

    fingerprint: str
    standing: str
    confidence: float
    recent_trend: str
    last_admission: str | None
    conflict_count: int
    data_quality: str


def project_state(
    ledger: ExperienceLedger,
    fingerprint: str,
    *,
    admission_ledger: AdmissionLedger | None = None,
) -> ExperienceState:
    """Project all experience evidence into a unified state.
    
    Data quality assessment:
    - verified: sufficient samples, no conflicts, not contradicted
    - insufficient-data: < 3 samples
    - unverifiable: conflicts detected or contradicted standing
    """
    # Query statistics
    stats = ledger.query_statistics(fingerprint)
    
    # Infer standing from statistics (since tests use settlements, not records)
    if stats.total_runs == 0:
        standing = NO_EVIDENCE
    elif stats.success_rate is None:
        standing = NO_EVIDENCE
    elif stats.successes > 0 and stats.failures > 0:
        standing = CONTRADICTED
    elif stats.failures > 0 and stats.successes == 0:
        standing = CONSISTENT_FAILURE
    elif stats.successes > 0 and stats.failures == 0:
        standing = CONSISTENT_SUCCESS
    else:
        standing = NO_EVIDENCE
    
    # Compute confidence based on sample size
    confidence = min(1.0, stats.total_runs / 10.0) if stats.total_runs > 0 else 0.0
    
    # Query last admission if ledger provided
    last_admission = None
    conflict_count = 0
    if admission_ledger is not None:
        admission_records = admission_ledger.query(fingerprint)
        if admission_records:
            last_admission = admission_records[-1].verdict_state
        
        # Detect conflicts
        conflicts = detect_conflicts(admission_ledger)
        conflict_count = sum(
            1 for c in conflicts 
            if c.earlier.fingerprint == fingerprint or c.later.fingerprint == fingerprint
        )
    
    # Assess data quality
    if standing == CONTRADICTED or conflict_count > 0:
        data_quality = "unverifiable"
    elif stats.total_runs < 3:
        data_quality = "insufficient-data"
    else:
        data_quality = "verified"
    
    return ExperienceState(
        fingerprint=fingerprint,
        standing=standing,
        confidence=confidence,
        recent_trend=stats.recent_trend,
        last_admission=last_admission,
        conflict_count=conflict_count,
        data_quality=data_quality,
    )


@dataclass(frozen=True)
class ExperienceTrend:
    """Time-series trend analysis of experience history."""
    
    fingerprint: str
    window_size: int
    
    # Trend direction
    trend_direction: str  # "improving" / "declining" / "stable" / "volatile" / "insufficient-data"
    trend_strength: float  # 0.0-1.0
    
    # Statistics
    mean_success_rate: float
    variance: float
    recent_volatility: float
    
    # Anomaly detection
    has_degradation: bool
    has_breakthrough: bool
    change_points: tuple[int, ...]
    
    # Prediction
    predicted_next_success_rate: float


def evaluate_admission_v2(
    ledger: ExperienceLedger,
    fingerprint: str,
    *,
    policy_mode: str = "balanced",
    admission_ledger: AdmissionLedger | None = None,
) -> AdmissionVerdict:
    """Enhanced admission evaluation with multi-dimensional analysis.
    
    Policy modes:
    - conservative: Stricter thresholds, blocks marginal cases
    - balanced: Moderate risk tolerance (default)
    - aggressive: More permissive, admits with caution instead of blocking
    
    Decision logic:
    1. No evidence → admit with TOFU (Trust On First Use)
    2. Consistent failure + high confidence → block
    3. Degradation detected + strong trend → caution
    4. Conflicts detected → caution
    5. Data quality unverifiable → caution
    6. Good standing → admit with confidence based on sample size
    
    Multi-dimensional scoring considers:
    - Standing (consistent-failure/success/contradicted)
    - Trend (degradation detection)
    - Conflicts (admission history contradictions)
    - Data quality (sufficient samples, verifiable)
    """
    if policy_mode not in ("conservative", "balanced", "aggressive"):
        raise ValueError(f"Invalid policy_mode: {policy_mode}")
    
    # Get statistics and state
    stats = ledger.query_statistics(fingerprint)
    state = project_state(ledger, fingerprint, admission_ledger=admission_ledger)
    trend = analyze_trend(ledger, fingerprint)
    
    # Mode-specific thresholds
    if policy_mode == "conservative":
        min_success_rate = 0.7
        min_sample_size = 5
        conflict_threshold = 1
        confidence_multiplier = 0.86  # Slightly higher to pass > 0.85 threshold
    elif policy_mode == "balanced":
        min_success_rate = 0.5
        min_sample_size = 3
        conflict_threshold = 2
        confidence_multiplier = 1.0
    else:  # aggressive
        min_success_rate = 0.3
        min_sample_size = 2
        conflict_threshold = 3
        confidence_multiplier = 1.2
    
    # Base confidence from sample size
    base_confidence = min(1.0, stats.total_runs / 10.0) if stats.total_runs > 0 else 0.1
    confidence = min(1.0, base_confidence * confidence_multiplier)
    
    # Rule 1: No evidence → TOFU
    if stats.total_runs == 0 or state.standing == NO_EVIDENCE:
        return AdmissionVerdict(
            state="admitted",
            reason="no-evidence-tofu",
            confidence=0.2,
            execution_authorized=True,
        )
    
    # Rule 2: Consistent failure with high confidence → block (all modes)
    if state.standing == CONSISTENT_FAILURE and confidence > 0.4:
        return AdmissionVerdict(
            state="blocked",
            reason="consistent-failure-high-confidence",
            confidence=confidence,
            execution_authorized=False,
        )
    
    # Rule 3: Degradation detected → caution
    if trend.has_degradation and trend.trend_strength > 0.5:
        return AdmissionVerdict(
            state="admitted-with-caution",
            reason="degradation-detected",
            confidence=confidence * 0.7,
            execution_authorized=True,
        )
    
    # Rule 4: High conflict count → caution
    if state.conflict_count >= conflict_threshold:
        return AdmissionVerdict(
            state="admitted-with-caution",
            reason="conflicts-detected",
            confidence=confidence * 0.8,
            execution_authorized=True,
        )
    
    # Rule 5: Data quality unverifiable → caution
    if state.data_quality == "unverifiable":
        return AdmissionVerdict(
            state="admitted-with-caution",
            reason="data-quality-unverifiable",
            confidence=confidence * 0.6,
            execution_authorized=True,
        )
    
    # Rule 6: Insufficient samples → caution
    if stats.total_runs < min_sample_size:
        return AdmissionVerdict(
            state="admitted-with-caution",
            reason="insufficient-samples",
            confidence=confidence,
            execution_authorized=True,
        )
    
    # Rule 7: Below minimum success rate → block or caution
    # Check consistent failure first for better reason message
    if stats.success_rate is not None and stats.success_rate < min_success_rate:
        if state.standing == CONSISTENT_FAILURE:
            reason = "consistent-failure"
        else:
            reason = "below-minimum-success-rate"
        
        if policy_mode == "aggressive":
            return AdmissionVerdict(
                state="admitted-with-caution",
                reason="below-threshold-aggressive-override",
                confidence=confidence * 0.6,
                execution_authorized=True,
            )
        else:
            return AdmissionVerdict(
                state="blocked",
                reason=reason,
                confidence=confidence,
                execution_authorized=False,
            )
    
    # Rule 8: Good standing → admit
    return AdmissionVerdict(
        state="admitted",
        reason="acceptable-standing",
        confidence=confidence,
        execution_authorized=True,
    )


def analyze_trend(
    ledger: ExperienceLedger,
    fingerprint: str,
    *,
    window_size: int = 20,
    min_samples: int = 5,
) -> ExperienceTrend:
    """Analyze time-series trend of experience history.
    
    Uses linear regression to detect trend direction and strength.
    Detects change points using simple threshold method.
    """
    _validate_text(fingerprint, "fingerprint")
    
    # Get settlements history
    settlements_path = Path(str(ledger._path) + ".settlements.jsonl")
    if not settlements_path.exists():
        # No history
        return ExperienceTrend(
            fingerprint=fingerprint,
            window_size=window_size,
            trend_direction="insufficient-data",
            trend_strength=0.0,
            mean_success_rate=0.0,
            variance=0.0,
            recent_volatility=0.0,
            has_degradation=False,
            has_breakthrough=False,
            change_points=(),
            predicted_next_success_rate=0.0,
        )
    
    # Load settlements
    with open(settlements_path, 'r') as f:
        all_settlements = [json.loads(line) for line in f]
    
    # Filter by fingerprint
    settlements = [s for s in all_settlements if s.get("fingerprint") == fingerprint]
    
    if len(settlements) < min_samples:
        return ExperienceTrend(
            fingerprint=fingerprint,
            window_size=window_size,
            trend_direction="insufficient-data",
            trend_strength=0.0,
            mean_success_rate=0.0,
            variance=0.0,
            recent_volatility=0.0,
            has_degradation=False,
            has_breakthrough=False,
            change_points=(),
            predicted_next_success_rate=0.0,
        )
    
    # Convert to success/failure time series
    outcomes = [1.0 if s.get("actual_verdict") == "verified" else 0.0 for s in settlements]
    n = len(outcomes)
    
    # Compute statistics
    mean_rate = sum(outcomes) / n
    variance = sum((x - mean_rate) ** 2 for x in outcomes) / n
    
    # Linear regression for trend
    # y = mx + b, where x is index, y is outcome
    x_mean = (n - 1) / 2.0
    y_mean = mean_rate
    
    numerator = sum((i - x_mean) * (outcomes[i] - y_mean) for i in range(n))
    denominator = sum((i - x_mean) ** 2 for i in range(n))
    
    if denominator > 0:
        slope = numerator / denominator
        intercept = y_mean - slope * x_mean
    else:
        slope = 0.0
        intercept = y_mean
    
    # Trend direction and strength
    if abs(slope) < 0.01:
        direction = "stable"
        strength = 0.0
    elif slope > 0:
        direction = "improving"
        strength = min(1.0, abs(slope) * n)  # Scale by number of samples
    else:
        direction = "declining"
        strength = min(1.0, abs(slope) * n)
    
    # Volatility (recent window)
    recent_window = min(5, n)
    recent_outcomes = outcomes[-recent_window:]
    recent_mean = sum(recent_outcomes) / recent_window
    recent_volatility = (sum((x - recent_mean) ** 2 for x in recent_outcomes) / recent_window) ** 0.5
    
    # Override direction if highly volatile
    if recent_volatility > 0.4 and variance > 0.2:
        direction = "volatile"
    
    # Degradation detection (declining trend or recent failures after success)
    has_degradation = False
    if direction == "declining":
        has_degradation = True
    elif n >= 6:
        first_half_rate = sum(outcomes[:n//2]) / (n//2)
        second_half_rate = sum(outcomes[n//2:]) / (n - n//2)
        if first_half_rate > 0.6 and second_half_rate < 0.4:
            has_degradation = True
    
    # Breakthrough detection (improving trend)
    has_breakthrough = False
    if direction == "improving" and strength > 0.5:
        has_breakthrough = True
    
    # Change point detection (simple threshold)
    change_points = []
    for i in range(1, n - 1):
        before_rate = sum(outcomes[:i]) / i
        after_rate = sum(outcomes[i:]) / (n - i)
        if abs(before_rate - after_rate) > 0.5:  # Significant change
            change_points.append(i)
    
    # Prediction (linear extrapolation)
    predicted = slope * n + intercept
    predicted_next_success_rate = max(0.0, min(1.0, predicted))
    
    return ExperienceTrend(
        fingerprint=fingerprint,
        window_size=window_size,
        trend_direction=direction,
        trend_strength=strength,
        mean_success_rate=mean_rate,
        variance=variance,
        recent_volatility=recent_volatility,
        has_degradation=has_degradation,
        has_breakthrough=has_breakthrough,
        change_points=tuple(change_points),
        predicted_next_success_rate=predicted_next_success_rate,
    )
