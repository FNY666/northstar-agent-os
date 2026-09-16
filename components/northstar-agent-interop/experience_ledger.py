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
