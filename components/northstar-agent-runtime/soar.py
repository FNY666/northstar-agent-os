"""SOAR: security orchestration, automation, and response decision ledger, Simulated.

Research note: SOAR platforms (Cortex XSOAR / Splunk SOAR / Microsoft
Sentinel playbooks) automate incident response through *playbooks* -
declared step sequences (isolate a host, block an indicator, revoke a
token, escalate to an analyst) triggered by alerts or cases. A playbook
*run* then books per-step outcomes, and response quality is summarized
with aggregate measures (executions, step success rates, declared
durations). The platform executes; the ledger remembers what was
declared and what was claimed to happen.

This module is the *governance* layer of that practice:

* **playbook()** - declare one playbook: a pinned trigger plus an ordered
  tuple of pinned step names. Steps are declared, never executed here.
* **execute()** - book one declared playbook run against an incident
  case, with per-step outcomes booked as data and a host-declared
  duration in seconds.
* **measure()** - pure read: derive aggregate statistics for one case
  (executions, step tallies, total declared duration) as data.
* **retire_playbook()** - terminally retire a playbook id; retired
  playbooks refuse new executions, and ids are never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``soar.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module runs no automation, touches no endpoints, and
measures no time. A booked ``success`` means the host declared a step
succeeded; a booked duration is a declared integer, not a stopwatch
reading. All secrets, commands, and payloads travel as digest pins only
and may never cross the audit boundary.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
SOAR_VERSION = "soar.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.soar.v1"

#: Pinned playbook-step vocabulary (declared, never executed).
STEPS = (
    "isolate-host",
    "block-ip",
    "disable-account",
    "quarantine-file",
    "collect-logs",
    "revoke-token",
    "notify-analyst",
    "escalate",
    "patch",
    "reboot",
)

#: Pinned playbook-trigger vocabulary.
TRIGGERS = (
    "alert-firing",
    "case-created",
    "threat-intel-match",
    "manual",
    "scheduled",
)

#: Pinned per-step outcome vocabulary. Outcomes are data, never proof.
OUTCOMES = ("success", "failed", "skipped")

#: Pinned playbook-retirement reasons.
RETIRE_REASONS = ("manual", "superseded", "deprecated", "policy-change")

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "playbook-registered",
    "playbook-retired",
    "executed",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "script",
        "command",
        "payload",
        "password",
        "token",
        "secret",
        "api_key",
        "credentials",
        "session",
        "raw",
        "content",
        "text",
        "log",
        "query",
        "playbook_body",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SoARError(Exception):
    """Base error for SOAR ledger misuse."""


class BadPlaybookError(SoARError):
    """Malformed playbook id."""


class DuplicatePlaybookError(SoARError):
    """Playbook id already registered."""


class RetiredPlaybookError(SoARError):
    """Playbook id retired; never recycled."""


class UnknownPlaybookError(SoARError):
    """Playbook id not registered."""


class BadStepError(SoARError):
    """Unknown step name, malformed steps tuple, or duplicate step."""


class BadTriggerError(SoARError):
    """Unknown trigger."""


class BadOutcomeError(SoARError):
    """Unknown step outcome."""


class BadCaseError(SoARError):
    """Malformed case id."""


class BadDurationError(SoARError):
    """Duration is not a non-negative int."""


class BadReasonError(SoARError):
    """Unknown retirement reason."""


class BadDigestError(SoARError):
    """Malformed sha256: digest pin."""


class UnknownExecutionError(SoARError):
    """Execution id not booked."""


class ExecutionStateError(SoARError):
    """Step outcomes do not match the playbook (unknown/duplicate step)."""


class SeqOrderError(SoARError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(SoARError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadPlaybookError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_case_id(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadCaseError("case_id must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


def _require_duration(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadDurationError(f"{field_name} must be an int")
    if value < 0:
        raise BadDurationError(f"{field_name} must be >= 0")
    return value


def _check_step_outcomes(
    step_outcomes: Tuple[Tuple[str, str], ...],
    playbook_steps: Tuple[str, ...],
) -> Tuple[Tuple[str, str], ...]:
    """Validate declared per-step outcomes against the playbook's steps."""
    if not isinstance(step_outcomes, tuple):
        raise ExecutionStateError("step_outcomes must be a tuple of (step, outcome) pairs")
    seen: set = set()
    for pair in step_outcomes:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise ExecutionStateError("each step outcome must be a (step, outcome) pair")
        step, outcome = pair
        if step not in STEPS or step not in playbook_steps:
            raise ExecutionStateError(f"outcome for unknown playbook step: {step!r}")
        if step in seen:
            raise ExecutionStateError(f"duplicate step in outcomes: {step!r}")
        if outcome not in OUTCOMES:
            raise BadOutcomeError(f"outcome must be one of {OUTCOMES}")
        seen.add(step)
    return step_outcomes


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlaybookRecord:
    playbook_id: str
    trigger: str
    steps: Tuple[str, ...]
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "playbook_id": self.playbook_id,
            "trigger": self.trigger,
            "steps": list(self.steps),
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "playbook_id": self.playbook_id,
                "trigger": self.trigger,
                "steps": list(self.steps),
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    playbook_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "playbook_id": self.playbook_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "playbook_id": self.playbook_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class ExecutionRecord:
    execution_id: str
    playbook_id: str
    case_id: str
    step_outcomes: Tuple[Tuple[str, str], ...]
    duration_sec: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "case_id": self.case_id,
            "step_outcomes": [list(pair) for pair in self.step_outcomes],
            "duration_sec": self.duration_sec,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "execution_id": self.execution_id,
                "playbook_id": self.playbook_id,
                "case_id": self.case_id,
                "step_outcomes": [list(pair) for pair in self.step_outcomes],
                "duration_sec": self.duration_sec,
            }
        )


@dataclass(frozen=True)
class MeasurementReport:
    case_id: str
    n_executions: int
    total_steps: int
    successes: int
    failures: int
    skips: int
    declared_duration_sec: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "case_id": self.case_id,
            "n_executions": self.n_executions,
            "total_steps": self.total_steps,
            "successes": self.successes,
            "failures": self.failures,
            "skips": self.skips,
            "declared_duration_sec": self.declared_duration_sec,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "case_id": self.case_id,
                "n_executions": self.n_executions,
                "total_steps": self.total_steps,
                "successes": self.successes,
                "failures": self.failures,
                "skips": self.skips,
                "declared_duration_sec": self.declared_duration_sec,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def soar_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the SOAR ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class SOAR:
    """SOAR playbook/execution/measure decision ledger (Simulated).

    ``playbook()`` / ``execute()`` / ``retire_playbook()`` mutate the
    ledger and consume caller seqs; ``measure()`` and all views are pure
    reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._playbooks: Dict[str, PlaybookRecord] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._executions: Dict[str, ExecutionRecord] = {}
        self._case_executions: Dict[str, List[str]] = {}
        self._playbook_executions: Dict[str, List[str]] = {}
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0
        self._exe_counter = 0

    # -- seq discipline ----------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = soar_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(soar_audit_event(audit_kind, seq, **details))

    # -- playbook ------------------------------------------------------------

    def playbook(
        self,
        playbook_id: str,
        seq: int,
        steps: Tuple[str, ...] = (),
        trigger: str = "manual",
    ) -> PlaybookRecord:
        """Declare one playbook. Steps are declared, never executed here."""
        with self._lock:
            try:
                self._claim(seq)
            except SoARError:
                raise
            try:
                _require_id(playbook_id, "playbook_id")
                if trigger not in TRIGGERS:
                    raise BadTriggerError(f"trigger must be one of {TRIGGERS}")
                if not isinstance(steps, tuple) or not steps:
                    raise BadStepError("steps must be a non-empty tuple of step names")
                seen: set = set()
                for step in steps:
                    if step not in STEPS:
                        raise BadStepError(f"unknown step: {step!r}")
                    if step in seen:
                        raise BadStepError(f"duplicate step: {step!r}")
                    seen.add(step)
                if playbook_id in self._retired:
                    raise RetiredPlaybookError(
                        f"playbook id retired, never recycled: {playbook_id!r}"
                    )
                if playbook_id in self._playbooks:
                    raise DuplicatePlaybookError(
                        f"playbook already registered: {playbook_id!r}"
                    )
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "playbook_id": playbook_id,
                        "trigger": trigger,
                        "steps": list(steps),
                    }
                )
                record = PlaybookRecord(
                    playbook_id=playbook_id,
                    trigger=trigger,
                    steps=tuple(steps),
                    digest=digest,
                )
                self._playbooks[playbook_id] = record
                self._playbook_executions[playbook_id] = []
                self._emit(
                    "playbook-registered", seq,
                    playbook_id=playbook_id, trigger=trigger,
                    n_steps=len(steps),
                )
                return record
            except SoARError:
                self._burn(seq, "playbook")
                raise

    # -- retire_playbook -------------------------------------------------------

    def retire_playbook(
        self, playbook_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a playbook id; retired ids are never recycled."""
        with self._lock:
            try:
                self._claim(seq)
            except SoARError:
                raise
            try:
                _require_id(playbook_id, "playbook_id")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
                if playbook_id not in self._playbooks:
                    raise UnknownPlaybookError(f"unknown playbook: {playbook_id!r}")
                if playbook_id in self._retired:
                    raise RetiredPlaybookError(
                        f"playbook already retired: {playbook_id!r}"
                    )
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "playbook_id": playbook_id,
                        "reason": reason,
                    }
                )
                record = RetireRecord(
                    playbook_id=playbook_id, reason=reason, digest=digest
                )
                self._retired[playbook_id] = record
                self._emit(
                    "playbook-retired", seq,
                    playbook_id=playbook_id, reason=reason,
                )
                return record
            except SoARError:
                self._burn(seq, "retire_playbook")
                raise

    # -- execute ---------------------------------------------------------------

    def execute(
        self,
        playbook_id: str,
        case_id: str,
        seq: int,
        step_outcomes: Tuple[Tuple[str, str], ...] = (),
        duration_sec: int = 0,
    ) -> ExecutionRecord:
        """Book one declared playbook run against an incident case.

        Per-step outcomes and the duration are host-declared data: a booked
        ``success`` means the host declared a step succeeded, and the
        duration is a declared integer, never a stopwatch reading.
        """
        with self._lock:
            try:
                self._claim(seq)
            except SoARError:
                raise
            try:
                _require_id(playbook_id, "playbook_id")
                _require_case_id(case_id)
                if playbook_id in self._retired:
                    raise RetiredPlaybookError(
                        f"playbook retired: {playbook_id!r}"
                    )
                playbook = self._playbooks.get(playbook_id)
                if playbook is None:
                    raise UnknownPlaybookError(f"unknown playbook: {playbook_id!r}")
                outcomes = _check_step_outcomes(step_outcomes, playbook.steps)
                _require_duration(duration_sec, "duration_sec")
                self._exe_counter += 1
                execution_id = f"exe-{self._exe_counter}"
                if execution_id in self._executions:
                    raise SoARError(f"execution id collision: {execution_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "execution_id": execution_id,
                        "playbook_id": playbook_id,
                        "case_id": case_id,
                        "step_outcomes": [list(pair) for pair in outcomes],
                        "duration_sec": duration_sec,
                    }
                )
                record = ExecutionRecord(
                    execution_id=execution_id,
                    playbook_id=playbook_id,
                    case_id=case_id,
                    step_outcomes=outcomes,
                    duration_sec=duration_sec,
                    digest=digest,
                )
                self._executions[execution_id] = record
                self._playbook_executions[playbook_id].append(execution_id)
                self._case_executions.setdefault(case_id, []).append(execution_id)
                self._emit(
                    "executed", seq, execution_id=execution_id,
                    playbook_id=playbook_id, case_id=case_id,
                    n_steps=len(outcomes), duration_sec=duration_sec,
                )
                return record
            except SoARError:
                self._burn(seq, "execute")
                raise

    # -- measure (pure read) ---------------------------------------------------

    def measure(self, case_id: str, seq: int) -> MeasurementReport:
        """Pure read: aggregate declared execution stats for one case as data.

        Unknown cases report an empty measurement, never raised.
        """
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("measure seq must be a non-negative int")
            _require_case_id(case_id)
            execution_ids = self._case_executions.get(case_id, [])
            executions = [self._executions[eid] for eid in execution_ids]
            total_steps = sum(len(e.step_outcomes) for e in executions)
            successes = sum(
                1 for e in executions
                for _, outcome in e.step_outcomes
                if outcome == "success"
            )
            failures = sum(
                1 for e in executions
                for _, outcome in e.step_outcomes
                if outcome == "failed"
            )
            skips = sum(
                1 for e in executions
                for _, outcome in e.step_outcomes
                if outcome == "skipped"
            )
            declared_duration_sec = sum(e.duration_sec for e in executions)
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "case_id": case_id,
                    "n_executions": len(executions),
                    "total_steps": total_steps,
                    "successes": successes,
                    "failures": failures,
                    "skips": skips,
                    "declared_duration_sec": declared_duration_sec,
                }
            )
            return MeasurementReport(
                case_id=case_id,
                n_executions=len(executions),
                total_steps=total_steps,
                successes=successes,
                failures=failures,
                skips=skips,
                declared_duration_sec=declared_duration_sec,
                digest=digest,
            )

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def playbook_record(self, playbook_id: str, seq: int) -> PlaybookRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._playbooks.get(playbook_id)
            if record is None:
                raise UnknownPlaybookError(f"unknown playbook: {playbook_id!r}")
            return record

    def execution_record(self, execution_id: str, seq: int) -> ExecutionRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._executions.get(execution_id)
            if record is None:
                raise UnknownExecutionError(f"unknown execution: {execution_id!r}")
            return record

    def retire_record(self, playbook_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._retired.get(playbook_id)
            if record is None:
                raise UnknownPlaybookError(
                    f"playbook not retired: {playbook_id!r}"
                )
            return record

    def playbook_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._playbooks))

    def execution_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._executions))

    def executions_for_case(self, case_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            _require_case_id(case_id)
            return tuple(self._case_executions.get(case_id, ()))

    def executions_for_playbook(self, playbook_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if playbook_id not in self._playbooks:
                raise UnknownPlaybookError(f"unknown playbook: {playbook_id!r}")
            return tuple(self._playbook_executions.get(playbook_id, ()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._retired))

    def is_retired(self, playbook_id: str, seq: int) -> bool:
        with self._lock:
            self._view_seq_ok(seq)
            return playbook_id in self._retired

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "playbooks": len(self._playbooks),
                "retired": len(self._retired),
                "executions": len(self._executions),
                "cases": len(self._case_executions),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }


def main() -> None:
    soar = SOAR()
    pb = soar.playbook("pb-phishing", 1,
                       steps=("quarantine-file", "notify-analyst", "disable-account"),
                       trigger="alert-firing")
    exe = soar.execute(
        "pb-phishing", "case-42", 2,
        step_outcomes=(
            ("quarantine-file", "success"),
            ("notify-analyst", "success"),
            ("disable-account", "skipped"),
        ),
        duration_sec=900,
    )
    report = soar.measure("case-42", 0)
    assert pb.verify() and exe.verify() and report.verify()
    assert report.n_executions == 1
    assert report.successes == 2 and report.skips == 1 and report.failures == 0
    assert report.declared_duration_sec == 900
    soar.retire_playbook("pb-phishing", 3, reason="superseded")
    try:
        soar.execute("pb-phishing", "case-43", 4)
    except RetiredPlaybookError:
        pass
    else:
        raise AssertionError("execute on retired playbook must fail")
    print("soar OK: playbook, execute, measure, retire, pins, audit")


if __name__ == "__main__":
    main()
