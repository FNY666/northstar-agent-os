"""AI surveillance: watch-observation decision ledger, Simulated.

Research note: AI surveillance is the systematic observation of AI
systems (agents, models, deployments) for anomalous or policy-relevant
behavior - declared watches on declared targets, declared observations
booked against them, and declared report verdicts. This module is the
*decision ledger* for declared AI surveillance activity: which targets
were watched, what observation classes were booked (over a pinned
observation-class vocabulary), what report verdicts were declared, and
what integrity flags the ledger derives - defensible bookkeeping, never
proof that any real observation occurred or that a target really
behaved in any particular way.

This module owns the surveil -> report -> verify lifecycle:

* **surveil()** - book one declared surveillance observation (minted
  ``srv-N`` ids; pinned observation-class vocabulary over the common
  surveillance classes; the observed material booked *as a digest pin
  only*); the first observation on an id registers the target; raw
  surveillance material, telemetry, recordings, traces, transcripts,
  and behavioral data never enter records - digest pins only.
* **report()** - book one declared surveillance report (minted
  ``rpt-N`` ids) against a registered target, optionally referencing
  one observation of that target; pinned verdict vocabulary booked *as
  data* (``clear`` / ``suspicious`` / ``confirmed`` / ``inconclusive``).
* **verify()** - **pure read**: re-derive one observation or report
  record's digest pin; verdict ``verified`` / ``tampered`` booked as
  data, never as proof the observation or report reflects real behavior.

Distinct-layer rationale vs siblings: ``ai_incident.py`` owns incident
declaration/investigation; ``ai_recovery.py`` owns recovery actions
against declared incidents; ``ai_audit.py`` owns declared audit
activities - this module is the *surveillance-operations* ledger none
of them own: declared watches, declared observations over a pinned
surveillance-class vocabulary, declared report verdicts, and the
digest re-derivation that turns declared observations into verifiable
ledger claims, always as data, never as measured behavior.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-surveillance.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module watches nothing, detects nothing, records
nothing, and proves nothing about real-world behavior. A booked
``confirmed`` verdict means "the host declared it", never "the target
really misbehaved"; a booked observation means "the host declared an
observation of this class", never "the event was observed". Surveillance
material, telemetry, recordings, traces, transcripts, frames,
behavioral data, and raw findings never enter records or cross the
audit boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_SURVEILLANCE_VERSION = "ai-surveillance.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-surveillance.v1"

#: Pinned observation-class vocabulary (the surveillance classes).
OBSERVATION_CLASSES = (
    "capability-probe",
    "deception-signal",
    "policy-violation",
    "anomalous-tool-use",
    "data-exfiltration-attempt",
    "privilege-escalation-attempt",
    "unauthorized-communication",
    "resource-abuse",
    "model-evasion",
    "rogue-subagent-activity",
    "self-preservation-signal",
    "corrigibility-bypass",
)

#: Pinned report-verdict vocabulary (booked as data, never proof).
REPORT_VERDICTS = (
    "clear",
    "suspicious",
    "confirmed",
    "inconclusive",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "surveilled",
    "reported",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "telemetry",
        "recording",
        "recordings",
        "video",
        "audio",
        "frames",
        "screenshots",
        "trace",
        "traces",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "packet",
        "packets",
        "network_dump",
        "behavior",
        "behaviors",
        "behavioral_trace",
        "behavioral_traces",
        "observation_text",
        "observation_detail",
        "observation_details",
        "finding",
        "findings",
        "evidence",
        "raw_evidence",
        "report",
        "reports",
        "report_text",
        "summary",
        "summary_text",
        "narrative",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "stderr",
        "stdout",
        "memory",
        "trajectory",
        "trajectories",
        "weights",
        "model_weights",
        "checkpoint",
        "checkpoints",
        "password",
        "passwords",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "api_key",
        "api_keys",
        "token",
        "tokens",
        "private_key",
        "personal_data",
        "personal_information",
        "identity",
        "identity_document",
        "document",
        "documents",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "dataset",
        "datasets",
        "pii",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AISurveillanceError(Exception):
    """Base class for all ai-surveillance ledger errors."""


class BadTargetError(AISurveillanceError):
    pass


class UnknownTargetError(AISurveillanceError):
    pass


class BadObservationClassError(AISurveillanceError):
    pass


class BadDigestError(AISurveillanceError):
    pass


class UnknownObservationError(AISurveillanceError):
    pass


class BadVerdictError(AISurveillanceError):
    pass


class UnknownRecordError(AISurveillanceError):
    pass


class SeqOrderError(AISurveillanceError):
    pass


class AuditKindError(AISurveillanceError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadTargetError(f"{what} must be a non-empty string")
    return value


def _check_observation_class(value: Any) -> str:
    if value not in OBSERVATION_CLASSES:
        raise BadObservationClassError(
            f"observation_class must be one of {OBSERVATION_CLASSES}"
        )
    return value


def _check_verdict(value: Any) -> str:
    if value not in REPORT_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {REPORT_VERDICTS}")
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


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SurveillanceRecord:
    observation_id: str
    target_id: str
    seq: int
    observation_class: str
    observation_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _surveil_payload(self), "ai-surveillance.surveil"
        )


@dataclass(frozen=True)
class SurveillanceReportRecord:
    report_id: str
    target_id: str
    observation_id: str
    seq: int
    verdict: str
    summary_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _report_payload(self), "ai-surveillance.report"
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
            _verify_payload(self), "ai-surveillance.verify"
        )


def _surveil_payload(rec: "SurveillanceRecord") -> Dict[str, Any]:
    return {
        "observation_id": rec.observation_id,
        "target_id": rec.target_id,
        "seq": rec.seq,
        "observation_class": rec.observation_class,
        "observation_digest": rec.observation_digest,
    }


def _report_payload(rec: "SurveillanceReportRecord") -> Dict[str, Any]:
    return {
        "report_id": rec.report_id,
        "target_id": rec.target_id,
        "observation_id": rec.observation_id,
        "seq": rec.seq,
        "verdict": rec.verdict,
        "summary_digest": rec.summary_digest,
    }


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_surveillance_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in EMIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AISurveillanceError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-surveillance",
        "version": AI_SURVEILLANCE_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AISurveillance:
    """AI-surveillance watch-observation decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All observations and
    verdicts are booked as data - never proof of real surveillance or
    real behavior.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._observations: Dict[str, SurveillanceRecord] = {}
        self._reports: Dict[str, SurveillanceReportRecord] = {}
        self._target_observations: Dict[str, List[str]] = {}
        self._target_reports: Dict[str, List[str]] = {}
        self._observation_counter = 0
        self._report_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
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
            row = ai_surveillance_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-surveillance",
                "version": AI_SURVEILLANCE_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_surveillance_audit_event(audit_kind, seq, **details))

    # -- mutations ---------------------------------------------------------

    def surveil(
        self,
        target_id: str,
        seq: int,
        observation_class: str = "capability-probe",
        observation_digest: str = "",
    ) -> SurveillanceRecord:
        """Book one declared surveillance observation (minted ``srv-N`` id).

        The first observation on an id registers the target. Raw
        surveillance material, telemetry, recordings, traces, and
        behavioral data never enter records - digest pins only.
        Fail-closed: failed mutations consume their seq and book an
        ``ai-surveillance.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                target_id = _check_id(target_id, "target_id")
                self._require_seq(seq)
                observation_class = _check_observation_class(observation_class)
                observation_digest = _check_digest(
                    observation_digest, "observation_digest"
                )
            except AISurveillanceError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._observation_counter += 1
            observation_id = f"srv-{self._observation_counter}"
            provisional = SurveillanceRecord(
                observation_id=observation_id,
                target_id=target_id,
                seq=seq,
                observation_class=observation_class,
                observation_digest=observation_digest,
                digest="",
            )
            digest = _digest_pin(
                _surveil_payload(provisional), "ai-surveillance.surveil"
            )
            rec = SurveillanceRecord(
                observation_id=observation_id,
                target_id=target_id,
                seq=seq,
                observation_class=observation_class,
                observation_digest=observation_digest,
                digest=digest,
            )
            self._observations[observation_id] = rec
            self._target_observations.setdefault(target_id, []).append(observation_id)
            self._emit(
                "surveilled",
                seq,
                observation_id=observation_id,
                target_id=target_id,
                observation_class=observation_class,
                observation_digest=observation_digest,
            )
            return rec

    def report(
        self,
        target_id: str,
        seq: int,
        verdict: str = "clear",
        observation_id: str = "",
        summary_digest: str = "",
    ) -> SurveillanceReportRecord:
        """Book one declared surveillance report (minted ``rpt-N`` id).

        The target must already be registered by ``surveil()``;
        ``observation_id`` may be ``""`` (target-level report) or must
        name an observation booked against the same target. Report
        content never enters records - the verdict (booked as data) and
        a digest pin only. Fail-closed: failed mutations consume their
        seq and book an ``ai-surveillance.rejected`` row; rewinds raise
        bare.
        """
        with self._lock:
            try:
                target_id = _check_id(target_id, "target_id")
                self._require_seq(seq)
                verdict = _check_verdict(verdict)
                if (
                    isinstance(observation_id, bool)
                    or not isinstance(observation_id, str)
                ):
                    raise UnknownObservationError(
                        f"observation_id must be a string: {observation_id!r}"
                    )
                if target_id not in self._target_observations:
                    raise UnknownTargetError(f"unknown target: {target_id!r}")
                if observation_id:
                    if observation_id not in self._observations:
                        raise UnknownObservationError(
                            f"unknown observation id: {observation_id!r}"
                        )
                    obs = self._observations[observation_id]
                    if obs.target_id != target_id:
                        raise UnknownObservationError(
                            f"observation {observation_id!r} is not booked "
                            f"against target {target_id!r}"
                        )
                summary_digest = _check_digest(summary_digest, "summary_digest")
            except AISurveillanceError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._report_counter += 1
            report_id = f"rpt-{self._report_counter}"
            provisional = SurveillanceReportRecord(
                report_id=report_id,
                target_id=target_id,
                observation_id=observation_id,
                seq=seq,
                verdict=verdict,
                summary_digest=summary_digest,
                digest="",
            )
            digest = _digest_pin(
                _report_payload(provisional), "ai-surveillance.report"
            )
            rec = SurveillanceReportRecord(
                report_id=report_id,
                target_id=target_id,
                observation_id=observation_id,
                seq=seq,
                verdict=verdict,
                summary_digest=summary_digest,
                digest=digest,
            )
            self._reports[report_id] = rec
            self._target_reports.setdefault(target_id, []).append(report_id)
            self._emit(
                "reported",
                seq,
                report_id=report_id,
                target_id=target_id,
                observation_id=observation_id,
                verdict=verdict,
                summary_digest=summary_digest,
            )
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one observation or report record's digest pin.

        Accepts ``srv-N`` and ``rpt-N`` ids. Verdict ``verified`` /
        ``tampered`` booked as data, never as proof the observation or
        report reflects real behavior. Seq is shape-validated only -
        never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if isinstance(record_id, bool) or not isinstance(record_id, str):
                raise UnknownRecordError(f"unknown record id: {record_id!r}")
            if record_id in self._observations:
                rec = self._observations[record_id]
            elif record_id in self._reports:
                rec = self._reports[record_id]
            else:
                raise UnknownRecordError(f"unknown record id: {record_id!r}")
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-surveillance.verify"
            )
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def observation_record(self, observation_id: str, seq: int) -> SurveillanceRecord:
        with self._lock:
            self._check_read_seq(seq)
            if observation_id not in self._observations:
                raise UnknownObservationError(
                    f"unknown observation id: {observation_id!r}"
                )
            return self._observations[observation_id]

    def report_record(self, report_id: str, seq: int) -> SurveillanceReportRecord:
        with self._lock:
            self._check_read_seq(seq)
            if report_id not in self._reports:
                raise UnknownRecordError(f"unknown report id: {report_id!r}")
            return self._reports[report_id]

    def observations_for(
        self, target_id: str, seq: int
    ) -> Tuple[SurveillanceRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._observations[i]
                for i in self._target_observations.get(target_id, [])
            )

    def reports_for(
        self, target_id: str, seq: int
    ) -> Tuple[SurveillanceReportRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._reports[i] for i in self._target_reports.get(target_id, [])
            )

    def target_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._target_observations))

    def observation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._observations))

    def report_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._reports))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_targets": len(self._target_observations),
                "n_observations": len(self._observations),
                "n_reports": len(self._reports),
                "seq": self._seq,
                "version": AI_SURVEILLANCE_VERSION,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(self._audit)


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
    """Self-check: exercise surveil -> report -> verify."""
    ledger = AISurveillance()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.surveil(
        "target-1",
        1,
        observation_class="capability-probe",
    )
    assert rec.verify()
    rep = ledger.report("target-1", 2, verdict="suspicious", observation_id=rec.observation_id)
    assert rep.verify()
    v1 = ledger.verify(rec.observation_id, 3)
    assert v1.verdict == "verified"
    v2 = ledger.verify(rep.report_id, 4)
    assert v2.verdict == "verified"
    print("ai-surveillance OK: surveil, report, verify, pins, audit")


if __name__ == "__main__":
    main()
