"""AI accident: accident report/investigation decision ledger, Simulated.

Research note: AI accident reporting is the practice of declaring,
investigating, and learning from unexpected AI-system failures - model
degradation, harmful outputs, autonomy breaches, deployment failures,
and similar incidents. This module is the *decision ledger* for
declared AI accidents: which systems had which accidents booked (over a
pinned accident-kind vocabulary), what investigations the host
declared against them, what the ledger's posture rule derives, and what
integrity checks the digest pins support - defensible bookkeeping,
never proof that a real accident happened or that a real investigation
found anything.

This module owns the report -> investigate -> verify -> evaluate
lifecycle:

* **report()** - book one declared AI accident (minted ``acc-N`` ids;
  pinned accident-kind vocabulary over the common AI-incident classes;
  host-reported severity booked *as data*); the first report registers
  its system; raw incident logs, telemetry, and material never enter
  records - digest pins only.
* **investigate()** - book one declared investigation against a booked
  accident (minted ``inv-N`` ids; pinned finding vocabulary booked *as
  data*); repeatable chain; books the *declaration*, never the
  investigation itself.
* **verify()** - **pure read**: re-derive one accident/investigation
  record's digest pin; verdict ``verified`` / ``tampered`` booked as
  data, never as proof the accident really happened.
* **evaluate()** - **pure read**: derive one system's accident posture
  as data (``no-accidents`` -> ``open-incident`` ->
  ``under-investigation`` -> ``contained`` -> ``resolved``) with
  finding tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``incident_response.py`` owns
the operational incident-response lifecycle (detect/triage/contain/
recover mechanics); ``ai_safety.py`` owns the safety *assessment*
lifecycle; ``ai_accident`` is none of those - it is the accident
*declaration and investigation* ledger: declared accidents, declared
investigations, digest re-derivation, and the ledger-rule posture that
turns declared findings into a resolution claim, always as data, never
as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-accident.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no monitors, investigates nothing,
resolves nothing, and proves nothing about real AI accidents. A booked
accident means "the host declared it", never "it really happened"; a
booked investigation finding means "the host declared it", never "the
root cause is known". Incident logs, telemetry, weights, prompts, and
raw accident material never enter records or cross the audit boundary -
digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_ACCIDENT_VERSION = "ai-accident.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-accident.v1"

#: Pinned accident-kind vocabulary (the AI-incident classes reported).
ACCIDENT_KINDS = (
    "deployment-failure",
    "model-degradation",
    "harmful-output",
    "safety-bypass",
    "autonomy-breach",
    "resource-escalation",
    "data-corruption",
    "infrastructure-outage",
)

#: Pinned investigation-finding vocabulary (booked as data, never proof).
INVESTIGATION_FINDINGS = (
    "under-investigation",
    "root-cause-found",
    "contained",
    "resolved",
    "unresolved",
    "false-alarm",
    "inconclusive",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "no-accidents",
    "open-incident",
    "under-investigation",
    "contained",
    "resolved",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "reported",
    "investigated",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "incident_log",
        "trace",
        "traces",
        "telemetry",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "weights_file",
        "checkpoint_data",
        "activations",
        "gradients",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "stderr",
        "stdout",
        "heartbeat",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "evidence",
        "incident",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIAccidentError(Exception):
    """Base class for all ai-accident ledger errors."""


class BadSystemError(AIAccidentError):
    pass


class UnknownSystemError(AIAccidentError):
    pass


class RetiredSystemError(AIAccidentError):
    pass


class BadAccidentKindError(AIAccidentError):
    pass


class BadSeverityError(AIAccidentError):
    pass


class BadFindingError(AIAccidentError):
    pass


class BadDigestError(AIAccidentError):
    pass


class BadReasonError(AIAccidentError):
    pass


class UnknownAccidentError(AIAccidentError):
    pass


class UnknownInvestigationError(AIAccidentError):
    pass


class UnknownRecordError(AIAccidentError):
    pass


class SeqOrderError(AIAccidentError):
    pass


class AuditKindError(AIAccidentError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_accident_kind(value: Any) -> str:
    if value not in ACCIDENT_KINDS:
        raise BadAccidentKindError(f"accident_kind must be one of {ACCIDENT_KINDS}")
    return value


def _check_finding(value: Any) -> str:
    if value not in INVESTIGATION_FINDINGS:
        raise BadFindingError(f"finding must be one of {INVESTIGATION_FINDINGS}")
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int")
    if not 0 <= value <= 100:
        raise BadSeverityError("severity must be in [0, 100]")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if (
        isinstance(value, bool)
        or not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
    return value


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AccidentRecord:
    accident_id: str
    system_id: str
    seq: int
    accident_kind: str
    severity: int
    report_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _report_payload(self), "ai-accident.report"
        )


@dataclass(frozen=True)
class InvestigationRecord:
    investigation_id: str
    accident_id: str
    system_id: str
    seq: int
    finding: str
    investigation_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _investigate_payload(self), "ai-accident.investigate"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-accident.retire"
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-accident.verify"
        )


@dataclass(frozen=True)
class AccidentEvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_accidents: int
    n_investigations: int
    n_open: int
    n_investigating: int
    n_contained: int
    n_resolved: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-accident.evaluate"
        )


def _report_payload(rec: "AccidentRecord") -> Dict[str, Any]:
    return {
        "accident_id": rec.accident_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "accident_kind": rec.accident_kind,
        "severity": rec.severity,
        "report_digest": rec.report_digest,
    }


def _investigate_payload(rec: "InvestigationRecord") -> Dict[str, Any]:
    return {
        "investigation_id": rec.investigation_id,
        "accident_id": rec.accident_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "finding": rec.finding,
        "investigation_digest": rec.investigation_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "AccidentEvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_accidents": rep.n_accidents,
        "n_investigations": rep.n_investigations,
        "n_open": rep.n_open,
        "n_investigating": rep.n_investigating,
        "n_contained": rep.n_contained,
        "n_resolved": rep.n_resolved,
        "integrity_ok": rep.integrity_ok,
    }


def ai_accident_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIAccidentError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-accident",
        "version": AI_ACCIDENT_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIAccident:
    """AI-accident report/investigation decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All accidents and
    investigations are booked as data - never proof that an accident
    really happened or that an investigation really resolved it.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._accidents: Dict[str, AccidentRecord] = {}
        self._investigations: Dict[str, InvestigationRecord] = {}
        self._system_accidents: Dict[str, List[str]] = {}
        self._accident_investigations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._accident_counter = 0
        self._investigation_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._require_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_accident_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-accident",
                "version": AI_ACCIDENT_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_accident_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def report(
        self,
        system_id: str,
        seq: int,
        accident_kind: str = "deployment-failure",
        severity: int = 0,
        report_digest: str = "",
    ) -> AccidentRecord:
        """Book one declared AI accident (minted ``acc-N`` id).

        The first report on an id registers the system. Raw incident
        logs, telemetry, and material never enter records - digest pins
        only. Fail-closed: failed mutations consume their seq and book
        an ``ai-accident.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                accident_kind = _check_accident_kind(accident_kind)
                severity = _check_severity(severity)
                report_digest = _check_digest(report_digest, "report_digest")
                self._require_live(system_id)
            except AIAccidentError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._accident_counter += 1
            accident_id = f"acc-{self._accident_counter}"
            provisional = AccidentRecord(
                accident_id=accident_id,
                system_id=system_id,
                seq=seq,
                accident_kind=accident_kind,
                severity=severity,
                report_digest=report_digest,
                digest="",
            )
            digest = _digest_pin(_report_payload(provisional), "ai-accident.report")
            rec = AccidentRecord(
                accident_id=accident_id,
                system_id=system_id,
                seq=seq,
                accident_kind=accident_kind,
                severity=severity,
                report_digest=report_digest,
                digest=digest,
            )
            self._accidents[accident_id] = rec
            self._system_accidents.setdefault(system_id, []).append(accident_id)
            self._emit(
                "reported",
                seq,
                accident_id=accident_id,
                system_id=system_id,
                accident_kind=accident_kind,
                severity=severity,
            )
            return rec

    def investigate(
        self,
        accident_id: str,
        seq: int,
        finding: str = "under-investigation",
        investigation_digest: str = "",
    ) -> InvestigationRecord:
        """Book one declared investigation against a booked accident.

        Minted ``inv-N`` ids; repeatable chain (a later investigation
        supersedes, never rewrites). Fail-closed on unknown accidents
        and retired systems. Books the *declaration*, never the
        investigation itself.
        """
        with self._lock:
            try:
                accident_id = _check_id(accident_id, "accident_id")
                self._require_seq(seq)
                finding = _check_finding(finding)
                investigation_digest = _check_digest(
                    investigation_digest, "investigation_digest"
                )
                acc = self._accidents.get(accident_id)
                if acc is None:
                    raise UnknownAccidentError(
                        f"unknown accident: {accident_id!r}"
                    )
                self._require_live(acc.system_id)
            except AIAccidentError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._investigation_counter += 1
            investigation_id = f"inv-{self._investigation_counter}"
            provisional = InvestigationRecord(
                investigation_id=investigation_id,
                accident_id=accident_id,
                system_id=acc.system_id,
                seq=seq,
                finding=finding,
                investigation_digest=investigation_digest,
                digest="",
            )
            digest = _digest_pin(
                _investigate_payload(provisional), "ai-accident.investigate"
            )
            rec = InvestigationRecord(
                investigation_id=investigation_id,
                accident_id=accident_id,
                system_id=acc.system_id,
                seq=seq,
                finding=finding,
                investigation_digest=investigation_digest,
                digest=digest,
            )
            self._investigations[investigation_id] = rec
            self._accident_investigations.setdefault(accident_id, []).append(
                investigation_id
            )
            self._emit(
                "investigated",
                seq,
                investigation_id=investigation_id,
                accident_id=accident_id,
                system_id=acc.system_id,
                finding=finding,
            )
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be non-negative")
        return seq

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin.

        Works for accident and investigation ids. Verdict
        ``verified`` / ``tampered`` is data - tamper is reported, never
        raised. Seq is shape-validated, never consumed; no audit row.
        """
        with self._lock:
            self._require_read_seq(seq)
            record_id = _check_id(record_id, "record_id")
            rec = self._accidents.get(record_id) or self._investigations.get(
                record_id
            )
            if rec is None:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            integrity_ok = verdict == "verified"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-accident.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def _accident_status(self, accident_id: str) -> str:
        """Latest declared finding for one accident (data, never proof)."""
        inv_ids = self._accident_investigations.get(accident_id, [])
        if not inv_ids:
            return "open"
        latest = max(
            (self._investigations[i] for i in inv_ids), key=lambda r: r.seq
        )
        return latest.finding

    def evaluate(self, system_id: str, seq: int) -> AccidentEvaluationReport:
        """Pure read: derive one system's accident posture as data.

        Posture by ledger rule with precedence: ``no-accidents`` (none
        booked) -> ``open-incident`` (any accident with no investigation)
        -> ``under-investigation`` (any latest finding in
        ``under-investigation``/``inconclusive``/``unresolved``) ->
        ``contained`` (any latest ``contained``/``root-cause-found``) ->
        ``resolved`` (every accident latest finding ``resolved`` or
        ``false-alarm``). Seq is shape-validated, never consumed; no
        audit row. Tamper flips ``integrity_ok`` as data, never raises.
        """
        with self._lock:
            self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            acc_ids = self._system_accidents.get(system_id)
            if acc_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            n_accidents = len(acc_ids)
            n_investigations = 0
            n_open = 0
            n_investigating = 0
            n_contained = 0
            n_resolved = 0
            integrity_ok = True
            for aid in acc_ids:
                acc = self._accidents[aid]
                if not acc.verify():
                    integrity_ok = False
                inv_ids = self._accident_investigations.get(aid, [])
                n_investigations += len(inv_ids)
                for iid in inv_ids:
                    if not self._investigations[iid].verify():
                        integrity_ok = False
                status = self._accident_status(aid)
                if status == "open":
                    n_open += 1
                elif status in ("under-investigation", "inconclusive", "unresolved"):
                    n_investigating += 1
                elif status in ("contained", "root-cause-found"):
                    n_contained += 1
                elif status in ("resolved", "false-alarm"):
                    n_resolved += 1
            if n_accidents == 0:
                posture = "no-accidents"
            elif n_open > 0:
                posture = "open-incident"
            elif n_investigating > 0:
                posture = "under-investigation"
            elif n_contained > 0:
                posture = "contained"
            else:
                posture = "resolved"
            provisional = AccidentEvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_accidents=n_accidents,
                n_investigations=n_investigations,
                n_open=n_open,
                n_investigating=n_investigating,
                n_contained=n_contained,
                n_resolved=n_resolved,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-accident.evaluate"
            )
            return AccidentEvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_accidents=n_accidents,
                n_investigations=n_investigations,
                n_open=n_open,
                n_investigating=n_investigating,
                n_contained=n_contained,
                n_resolved=n_resolved,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminal: retire one system id. Ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id in self._retired:
                    raise RetiredSystemError(f"already retired: {system_id!r}")
                self._require_live(system_id)
            except AIAccidentError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-accident.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- views (pure reads) --------------------------------------------------

    def accident_record(self, accident_id: str, seq: int) -> AccidentRecord:
        with self._lock:
            self._require_read_seq(seq)
            accident_id = _check_id(accident_id, "accident_id")
            rec = self._accidents.get(accident_id)
            if rec is None:
                raise UnknownAccidentError(f"unknown accident: {accident_id!r}")
            return rec

    def investigation_record(
        self, investigation_id: str, seq: int
    ) -> InvestigationRecord:
        with self._lock:
            self._require_read_seq(seq)
            investigation_id = _check_id(investigation_id, "investigation_id")
            rec = self._investigations.get(investigation_id)
            if rec is None:
                raise UnknownInvestigationError(
                    f"unknown investigation: {investigation_id!r}"
                )
            return rec

    def accidents_for(self, system_id: str, seq: int) -> List[AccidentRecord]:
        with self._lock:
            self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            return [
                self._accidents[aid]
                for aid in self._system_accidents.get(system_id, [])
            ]

    def investigations_for(
        self, accident_id: str, seq: int
    ) -> List[InvestigationRecord]:
        with self._lock:
            self._require_read_seq(seq)
            accident_id = _check_id(accident_id, "accident_id")
            return [
                self._investigations[iid]
                for iid in self._accident_investigations.get(accident_id, [])
            ]

    def system_ids(self, seq: int) -> List[str]:
        with self._lock:
            self._require_read_seq(seq)
            return sorted(self._system_accidents)

    def accident_ids(self, seq: int) -> List[str]:
        with self._lock:
            self._require_read_seq(seq)
            return sorted(self._accidents)

    def investigation_ids(self, seq: int) -> List[str]:
        with self._lock:
            self._require_read_seq(seq)
            return sorted(self._investigations)

    def retired_ids(self, seq: int) -> List[str]:
        with self._lock:
            self._require_read_seq(seq)
            return sorted(self._retired)

    def stats(self, seq: int) -> Dict[str, int]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_accidents),
                "n_accidents": len(self._accidents),
                "n_investigations": len(self._investigations),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> List[Dict[str, Any]]:
        with self._lock:
            self._require_read_seq(seq)
            return list(self._audit)


def stdlib_only() -> bool:
    """AST self-check: the module imports stdlib names only."""
    import ast
    from pathlib import Path

    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(Path(__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: exercise report -> investigate -> verify -> evaluate."""
    ledger = AIAccident()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.report(
        "sys-1", 1, accident_kind="harmful-output", severity=70
    )
    assert rec.verify()
    inv = ledger.investigate(rec.accident_id, 2, finding="root-cause-found")
    assert inv.verify()
    rep = ledger.verify(rec.accident_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "contained"
    ret = ledger.retire("sys-1", 5)
    assert ret.verify()
    print("ai-accident OK: report, investigate, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
