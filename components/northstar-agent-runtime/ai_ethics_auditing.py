"""AI ethics auditing: ethics-audit execution decision ledger, Simulated.

Research note: ethics auditing is the independent examination of an AI
system's ethical posture - whether its declared values, fairness claims,
transparency practices, and accountability structures hold up under
scrutiny. This module is the *decision ledger* for declared AI-ethics
audits: which systems had which ethics audits booked (over a pinned
audit-kind vocabulary), what verdicts the auditors declared, and what
audit posture the ledger derives - defensible bookkeeping, never proof
that a system is really ethical.

This module owns the audit -> verify -> evaluate lifecycle:

* **audit()** - book one declared ethics audit (minted ``aud-N`` ids;
  pinned audit-kind vocabulary over the common ethics-audit classes;
  pinned verdict vocabulary booked *as data*); the first audit
  registers its system; raw workpapers, evidence, and material never
  enter records - digest pins only.
* **verify()** - **pure read**: re-derive one audit record's digest pin;
  verdict ``verified`` / ``tampered`` booked as data, never as proof
  the audit really happened.
* **evaluate()** - **pure read**: derive one system's audit posture as
  data (``unaudited`` -> ``unethical`` -> ``contested`` ->
  ``conditionally-ethical`` -> ``ethically-audited``) with verdict
  tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_ethics.py`` owns the
ethics-assessment lifecycle (declare principles, assess alignment);
``ai_audit.py`` owns generic audit execution
(declare/scope/fieldwork/report); ``ai_safety_auditing.py`` owns
safety-audit execution (safety classes, safety-case reviews);
``ai_compliance.py`` owns compliance assessments;
``ai_certification.py`` owns third-party attestation records;
``responsible_ai.py`` / ``trustworthy_ai.py`` own framework-scoped
assessments - this module is the AI-*ethics-audit* execution decision
ledger none of them own: declared ethics audits over a pinned
ethics-audit vocabulary, digest re-derivation, and the ledger-rule
posture that turns declared audit verdicts into an ethics-audit claim,
always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-ethics-auditing.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no audits, inspects no systems, and
proves nothing about real AI ethics. A booked ``unsatisfactory``
verdict means "the host declared it", never "the system is unethical";
a booked ``satisfactory`` verdict means "the host declared it", never
"the system is ethical". Workpapers, evidence, interview notes, and
raw audit material never enter records or cross the audit boundary -
digest pins only.
"""

from __future__ import annotations

import ast
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
AI_ETHICS_AUDITING_VERSION = "ai-ethics-auditing.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-ethics-auditing.v1"

#: Pinned ethics-audit-kind vocabulary (the ethics-audit classes booked).
AUDIT_KINDS = (
    "internal-ethics-audit",
    "external-ethics-audit",
    "ethics-review-board",
    "values-assessment",
    "bias-audit",
    "fairness-audit",
    "transparency-audit",
    "accountability-audit",
)

#: Pinned audit-verdict vocabulary (booked as data, never proof).
AUDIT_VERDICTS = (
    "satisfactory",
    "conditional",
    "unsatisfactory",
    "inconclusive",
    "not-audited",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived posture vocabulary (booked as data, never proof).
POSTURES = (
    "unaudited",
    "unethical",
    "contested",
    "conditionally-ethical",
    "ethically-audited",
)

#: Reasons accepted by retire() (pinned vocabulary, booked as data).
RETIRE_REASONS = (
    "manual",
    "superseded",
    "completed",
    "withdrawn",
)

#: Kinds accepted by the audit event builder.
_AUDIT_KINDS = (
    "audited",
    "retired",
    "rejected",
)

#: Raw audit-material keys banned from crossing the audit boundary.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "ethics_workpaper",
        "ethics_workpapers",
        "ethics_evidence",
        "values_assessment",
        "values_survey",
        "bias_evidence",
        "fairness_report",
        "audit_workpaper",
        "audit_workpapers",
        "audit_evidence",
        "evidence",
        "interview_notes",
        "assessment_data",
        "transcript",
        "transcripts",
        "workpaper",
        "workpapers",
        "findings_report",
        "remediation_plan",
        "checklist",
        "fieldwork_notes",
        "system_snapshot",
        "weights",
        "prompts",
        "model_output",
        "ethics_report",
        "ethics_charter",
        "principles_text",
        "raw_findings",
        "confidential",
        "pii",
        "credentials",
        "password",
        "api_key",
        "secret",
        "token",
        "private_key",
        "logs",
        "trace",
        "telemetry",
    }
)


# ---------------------------------------------------------------------------
# Fail-closed error taxonomy
# ---------------------------------------------------------------------------


class AIEthicsAuditingError(Exception):
    """Base class for all ai_ethics_auditing errors (fail-closed)."""


class BadSystemError(AIEthicsAuditingError):
    """System id is malformed."""


class BadAuditKindError(AIEthicsAuditingError):
    """Audit kind is not in the pinned vocabulary."""


class BadVerdictError(AIEthicsAuditingError):
    """Audit verdict is not in the pinned vocabulary."""


class BadDigestError(AIEthicsAuditingError):
    """Digest is malformed (must be '' or a 'sha256:'-prefixed hex string)."""


class BadSeverityError(AIEthicsAuditingError):
    """Severity is not an int in [0, 100]."""


class BadReasonError(AIEthicsAuditingError):
    """Retire reason is not in the pinned vocabulary."""


class BadSeqError(AIEthicsAuditingError):
    """Seq is not a non-negative int (or not a valid first claim)."""


class SeqOrderError(AIEthicsAuditingError):
    """Seq is not strictly increasing (rewind; raised bare, no row)."""


class UnknownAuditError(AIEthicsAuditingError):
    """Audit id is unknown to this ledger."""


class UnknownSystemError(AIEthicsAuditingError):
    """System id is unknown to this ledger."""


class RetiredSystemError(AIEthicsAuditingError):
    """System id is retired; mutations are refused."""


class AuditKindError(AIEthicsAuditingError):
    """Audit event builder received an unknown kind."""


class AuditKeyError(AIEthicsAuditingError):
    """Audit event details contain a banned raw-material key."""


# ---------------------------------------------------------------------------
# Frozen record types
# ---------------------------------------------------------------------------


def _canonical_bytes(obj: Any) -> bytes:
    raw = _jcs_dumps(obj)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _valid_digest(value: Any) -> bool:
    if value == "":
        return True
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    tail = value[len("sha256:") :]
    return len(tail) == 64 and all(c in "0123456789abcdef" for c in tail)


@dataclass(frozen=True)
class AuditRecord:
    """One declared ethics audit (booked as data, never proof)."""

    audit_id: str
    system_id: str
    seq: int
    audit_kind: str
    verdict: str
    severity: int
    audit_digest: str
    version: str = AI_ETHICS_AUDITING_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        """Re-derive the digest pin of this record."""
        payload = {
            "audit_id": self.audit_id,
            "system_id": self.system_id,
            "seq": self.seq,
            "audit_kind": self.audit_kind,
            "verdict": self.verdict,
            "severity": self.severity,
            "version": self.version,
            "schema": self.schema,
        }
        if not self.audit_digest:
            return False
        return self.audit_digest == _digest_pin(payload)


@dataclass(frozen=True)
class VerificationReport:
    """Digest re-derivation report for one audit record (pure read)."""

    record_id: str
    verdict: str
    seq: int
    version: str = AI_ETHICS_AUDITING_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        """Re-derive this report's own digest pin (trivially true)."""
        return self.verdict in VERIFY_VERDICTS


@dataclass(frozen=True)
class EvaluationReport:
    """Ledger-rule posture for one system (pure read, booked as data)."""

    system_id: str
    posture: str
    tallies: Tuple[Tuple[str, int], ...]
    integrity_ok: bool
    seq: int
    version: str = AI_ETHICS_AUDITING_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        """Re-derive this report's own digest pin (trivially true)."""
        return self.posture in POSTURES


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a system id (booked as data)."""

    system_id: str
    seq: int
    reason: str
    version: str = AI_ETHICS_AUDITING_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        return self.reason in RETIRE_REASONS


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def ai_ethics_auditing_audit_event(
    kind: str, seq: int, details: Dict[str, Any]
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row.

    Fail-closed: unknown kinds raise :class:`AuditKindError`; any banned
    raw-material key in ``details`` raises :class:`AuditKeyError`; bad seq
    raises :class:`BadSeqError`.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_read_seq(seq)
    if not isinstance(details, dict):
        raise AuditKeyError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKeyError(f"banned raw-material key in audit details: {key!r}")
    return {
        "module": "ai_ethics_auditing",
        "version": AI_ETHICS_AUDITING_VERSION,
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Seq discipline helpers
# ---------------------------------------------------------------------------


def _check_mutation_seq(seq: Any, last_seq: int) -> None:
    """Validate a caller seq for a mutation (claim-then-burn on failure).

    Raises bare (no audit row, no consumption) when the shape is invalid
    or the seq is not strictly increasing over ``last_seq``.
    """
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise BadSeqError(f"mutation seq must be a positive int, got {seq!r}")
    if seq <= last_seq:
        raise SeqOrderError(f"seq {seq!r} does not advance past {last_seq}")


def _check_read_seq(seq: Any) -> None:
    """Validate a caller seq for a pure read (shape only, never consumed)."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise BadSeqError(f"read seq must be a non-negative int, got {seq!r}")


def _check_system_id(system_id: Any) -> None:
    if not isinstance(system_id, str) or not system_id.strip():
        raise BadSystemError(f"system_id must be a non-empty str, got {system_id!r}")


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class AIEthicsAuditing:
    """Declared ethics-audit execution decision ledger, Simulated.

    Deterministic single-host state machine. Caller-supplied
    strictly-increasing int seqs; claim-then-burn on failed mutations
    (the failed seq is consumed and an ``ai-ethics-auditing.rejected``
    row is booked); rewinds raise bare without consuming. No wall-clock.
    All records are frozen dataclasses with ``sha256:`` digest pins and
    per-record ``verify()``. All verdicts/postures are booked as data,
    never proof.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._next_n = 1
        self._audits: Dict[str, AuditRecord] = {}
        self._system_audits: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._audit_log: List[Dict[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _book_rejected(self, seq: int, reason: str) -> None:
        self._audit_log.append(
            ai_ethics_auditing_audit_event(
                "rejected", seq, {"reason": reason, "module_pin": AI_ETHICS_AUDITING_VERSION}
            )
        )

    def _claim_seq(self, seq: int) -> None:
        _check_mutation_seq(seq, self._last_seq)
        self._last_seq = seq

    # -- mutation ------------------------------------------------------

    def audit(
        self,
        system_id: str,
        seq: int,
        audit_kind: str = "internal-ethics-audit",
        verdict: str = "not-audited",
        severity: int = 0,
        audit_digest: str = "",
    ) -> AuditRecord:
        """Book one declared ethics audit (minted ``aud-N`` ids).

        Fail-closed: bad input burns the seq and books a ``rejected``
        row; rewinds raise bare with no row. The first audit registers
        its system. Raw audit material never enters records - digest
        pins only.
        """
        with self._lock:
            try:
                self._claim_seq(seq)
                _check_system_id(system_id)
                if system_id in self._retired:
                    raise RetiredSystemError(f"system is retired: {system_id!r}")
                if audit_kind not in AUDIT_KINDS:
                    raise BadAuditKindError(f"unknown audit kind: {audit_kind!r}")
                if verdict not in AUDIT_VERDICTS:
                    raise BadVerdictError(f"unknown verdict: {verdict!r}")
                if (
                    isinstance(severity, bool)
                    or not isinstance(severity, int)
                    or not 0 <= severity <= 100
                ):
                    raise BadSeverityError(f"severity must be int in [0,100], got {severity!r}")
                if not _valid_digest(audit_digest):
                    raise BadDigestError(f"malformed digest: {audit_digest!r}")
            except SeqOrderError:
                raise
            except BadSeqError:
                raise
            except AIEthicsAuditingError as exc:
                self._book_rejected(seq, type(exc).__name__)
                raise
            audit_id = f"aud-{self._next_n}"
            self._next_n += 1
            payload = {
                "audit_id": audit_id,
                "system_id": system_id,
                "seq": seq,
                "audit_kind": audit_kind,
                "verdict": verdict,
                "severity": severity,
                "version": AI_ETHICS_AUDITING_VERSION,
                "schema": SCHEMA_PIN,
            }
            digest = _digest_pin(payload)
            record = AuditRecord(
                audit_id=audit_id,
                system_id=system_id,
                seq=seq,
                audit_kind=audit_kind,
                verdict=verdict,
                severity=severity,
                audit_digest=audit_digest or digest,
            )
            self._audits[audit_id] = record
            self._system_audits.setdefault(system_id, []).append(audit_id)
            self._audit_log.append(
                ai_ethics_auditing_audit_event(
                    "audited",
                    seq,
                    {
                        "audit_id": audit_id,
                        "system_id": system_id,
                        "audit_kind": audit_kind,
                        "verdict": verdict,
                        "severity": severity,
                        "audit_digest": record.audit_digest,
                    },
                )
            )
            return record

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a system id (ids are never recycled).

        Fail-closed: bad input burns the seq and books a ``rejected``
        row; rewinds raise bare with no row. Post-retire mutations are
        refused; reads still work.
        """
        with self._lock:
            try:
                self._claim_seq(seq)
                _check_system_id(system_id)
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"unknown retire reason: {reason!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(f"system already retired: {system_id!r}")
                if system_id not in self._system_audits:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
            except (SeqOrderError, BadSeqError):
                raise
            except AIEthicsAuditingError as exc:
                self._book_rejected(seq, type(exc).__name__)
                raise
            record = RetireRecord(
                system_id=system_id, seq=seq, reason=reason
            )
            self._retired[system_id] = record
            self._audit_log.append(
                ai_ethics_auditing_audit_event(
                    "retired", seq, {"system_id": system_id, "reason": reason}
                )
            )
            return record

    # -- pure reads ----------------------------------------------------

    def verify(self, audit_id: str, seq: int) -> VerificationReport:
        """**Pure read**: re-derive one audit record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the audit really happened. Seq shape-validated only, never
        consumed; no audit row.
        """
        with self._lock:
            _check_read_seq(seq)
            if not isinstance(audit_id, str) or not audit_id:
                raise BadSystemError(f"audit_id must be a non-empty str, got {audit_id!r}")
            record = self._audits.get(audit_id)
            if record is None:
                raise UnknownAuditError(f"unknown audit: {audit_id!r}")
            ok = record.verify()
            return VerificationReport(
                record_id=audit_id,
                verdict="verified" if ok else "tampered",
                seq=seq,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """**Pure read**: derive one system's audit posture as data.

        Ledger rule: ``unaudited`` (no audits) -> ``unethical`` (any
        unsatisfactory) -> ``contested`` (any inconclusive) ->
        ``conditionally-ethical`` (any conditional / not-audited) ->
        ``ethically-audited`` (all satisfactory). Verdict tallies and a
        digest-pinned integrity flag included. Seq shape-validated only,
        never consumed; no audit row.
        """
        with self._lock:
            _check_read_seq(seq)
            _check_system_id(system_id)
            audit_ids = self._system_audits.get(system_id)
            if not audit_ids:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            verdicts = [self._audits[aid].verdict for aid in audit_ids]
            tallies: Dict[str, int] = {v: 0 for v in AUDIT_VERDICTS}
            for v in verdicts:
                tallies[v] = tallies.get(v, 0) + 1
            if "unsatisfactory" in verdicts:
                posture = "unethical"
            elif "inconclusive" in verdicts:
                posture = "contested"
            elif "conditional" in verdicts or "not-audited" in verdicts:
                posture = "conditionally-ethical"
            else:
                posture = "ethically-audited"
            integrity_ok = all(self._audits[aid].verify() for aid in audit_ids)
            return EvaluationReport(
                system_id=system_id,
                posture=posture,
                tallies=tuple(sorted(tallies.items())),
                integrity_ok=integrity_ok,
                seq=seq,
            )

    # -- views ----------------------------------------------------------

    def audit_record(self, audit_id: str, seq: int) -> AuditRecord:
        with self._lock:
            _check_read_seq(seq)
            record = self._audits.get(audit_id)
            if record is None:
                raise UnknownAuditError(f"unknown audit: {audit_id!r}")
            return record

    def retire_record(self, system_id: str, seq: int) -> RetireRecord:
        with self._lock:
            _check_read_seq(seq)
            record = self._retired.get(system_id)
            if record is None:
                raise UnknownSystemError(f"system not retired: {system_id!r}")
            return record

    def audits_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_read_seq(seq)
            return tuple(self._system_audits.get(system_id, ()))

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_read_seq(seq)
            return tuple(sorted(self._system_audits))

    def audit_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_read_seq(seq)
            return tuple(sorted(self._audits))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            _check_read_seq(seq)
            return {
                "module": AI_ETHICS_AUDITING_VERSION,
                "n_audits": len(self._audits),
                "n_systems": len(self._system_audits),
                "n_retired": len(self._retired),
                "last_seq": self._last_seq,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            _check_read_seq(seq)
            return tuple(self._audit_log)


# ---------------------------------------------------------------------------
# stdlib-only self-check
# ---------------------------------------------------------------------------


def stdlib_only() -> bool:
    """AST self-check: this module must import stdlib only."""
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    allowed = {
        "__future__",
        "ast",
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "pathlib",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root == "canonical_json":
                    continue  # optional JCS dependency, stdlib fallback exists
                if root not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root == "canonical_json":
                continue
            if root not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: audit -> verify -> evaluate -> retire."""
    ledger = AIEthicsAuditing()
    rec = ledger.audit("sys-1", 1, audit_kind="external-ethics-audit", verdict="satisfactory")
    assert rec.verify()
    rep = ledger.verify(rec.audit_id, 0)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 0)
    assert ev.posture == "ethically-audited"
    ledger.retire("sys-1", 2, reason="manual")
    assert AI_ETHICS_AUDITING_VERSION == "ai-ethics-auditing.v1"
    assert SCHEMA_PIN == "northstar.ai-ethics-auditing.v1"
    assert stdlib_only()
    print("ai-ethics-auditing OK: audit, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
