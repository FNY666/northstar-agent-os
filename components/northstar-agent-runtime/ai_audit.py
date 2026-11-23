"""AI audit: audit-execution decision ledger, Simulated.

Research note: AI auditing is the independent examination of an AI
system, its data, and its development/deployment processes against
stated requirements - what actually got audited, by which audit
method, what findings were declared, and what audit posture the ledger
derives. This module is the *decision ledger* for declared AI audits:
which systems had which audits booked (over a pinned audit-kind
vocabulary), what findings were declared against them, and what audit
posture the ledger derives - defensible bookkeeping, never proof that
a system is really auditable, safe, or compliant.

This module owns the audit -> verify -> evaluate lifecycle:

* **audit()** - book one declared audit engagement (minted ``aud-N``
  ids; pinned audit-kind vocabulary over the common AI-audit engagement
  classes; pinned finding vocabulary booked *as data*); the first
  audit registers its system; raw audit reports, evidence packs, and
  material never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one audit record's digest pin;
  verdict ``verified`` / ``tampered`` booked as data, never as proof
  the audit really happened.
* **evaluate()** - **pure read**: derive one system's audit posture as
  data (``unaudited`` -> ``critical`` -> ``at-risk`` -> ``inconclusive``
  -> ``partial`` -> ``clean``) with finding tallies and a digest-pinned
  integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_governance.py`` owns the
governance-operations ledger (declared governance controls over named
systems plus audit *decisions* booked against those controls);
``ai_safety.py`` owns the assessment -> mitigation lifecycle (declared
hazards and their mitigations); ``ai_alignment.py`` owns alignment
assessments; ``ai_ethics.py`` owns ethics assessments;
``trustworthy_ai.py`` owns framework-scoped trustworthiness
assessments - this module is the *audit-execution* ledger none of them
own: declared audit engagements, declared findings, digest
re-derivation, and the ledger-rule posture that turns declared findings
into an audit claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-audit.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module audits nothing, inspects no systems, collects
no evidence, and proves nothing about real AI audit outcomes. A booked
``clean`` finding means "the host declared it", never "the system is
clean"; a booked ``critical-findings`` verdict means "the host declared
it", never "the system is critical". Audit reports, evidence packs,
interviews, logs, and raw audit material never enter records or cross
the audit boundary - digest pins only.
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
AI_AUDIT_VERSION = "ai-audit.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-audit.v1"

#: Pinned audit-kind vocabulary (the AI-audit engagement classes).
AUDIT_KINDS = (
    "internal-review",
    "external-audit",
    "regulatory-audit",
    "model-audit",
    "data-audit",
    "deployment-audit",
    "process-audit",
    "red-team-audit",
)

#: Pinned audit-finding vocabulary (booked as data, never proof).
AUDIT_FINDINGS = (
    "clean",
    "minor-findings",
    "major-findings",
    "critical-findings",
    "inconclusive",
    "not-audited",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unaudited",
    "critical",
    "at-risk",
    "inconclusive",
    "partial",
    "clean",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "audited",
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
        "findings",
        "report",
        "reports",
        "workpapers",
        "interview",
        "interviews",
        "questionnaire",
        "checklist",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIAuditError(Exception):
    """Base class for all ai-audit ledger errors."""


class BadSystemError(AIAuditError):
    pass


class UnknownSystemError(AIAuditError):
    pass


class RetiredSystemError(AIAuditError):
    pass


class BadAuditKindError(AIAuditError):
    pass


class BadFindingError(AIAuditError):
    pass


class BadDigestError(AIAuditError):
    pass


class BadReasonError(AIAuditError):
    pass


class UnknownAuditError(AIAuditError):
    pass


class UnknownRecordError(AIAuditError):
    pass


class SeqOrderError(AIAuditError):
    pass


class AuditKindError(AIAuditError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_audit_kind(value: Any) -> str:
    if value not in AUDIT_KINDS:
        raise BadAuditKindError(f"audit_kind must be one of {AUDIT_KINDS}")
    return value


def _check_finding(value: Any) -> str:
    if value not in AUDIT_FINDINGS:
        raise BadFindingError(f"finding must be one of {AUDIT_FINDINGS}")
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
class AuditRecord:
    audit_id: str
    system_id: str
    seq: int
    audit_kind: str
    finding: str
    audit_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _audit_payload(self), "ai-audit.audit"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-audit.retire"
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
            _verify_payload(self), "ai-audit.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_audits: int
    n_clean: int
    n_minor: int
    n_major: int
    n_critical: int
    n_inconclusive: int
    n_not_audited: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-audit.evaluate"
        )


def _audit_payload(rec: "AuditRecord") -> Dict[str, Any]:
    return {
        "audit_id": rec.audit_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "audit_kind": rec.audit_kind,
        "finding": rec.finding,
        "audit_digest": rec.audit_digest,
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


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_audits": rep.n_audits,
        "n_clean": rep.n_clean,
        "n_minor": rep.n_minor,
        "n_major": rep.n_major,
        "n_critical": rep.n_critical,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_audited": rep.n_not_audited,
        "integrity_ok": rep.integrity_ok,
    }


def ai_audit_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in EMIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIAuditError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-audit",
        "version": AI_AUDIT_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIAudit:
    """AI-audit engagement decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All audits, findings, and
    postures are booked as data - never proof that an audit really
    happened or that a system is really clean.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._audits: Dict[str, AuditRecord] = {}
        self._system_audits: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._audit_counter = 0
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
            row = ai_audit_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-audit",
                "version": AI_AUDIT_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_audit_audit_event(kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def audit(
        self,
        system_id: str,
        seq: int,
        audit_kind: str = "internal-review",
        finding: str = "not-audited",
        audit_digest: str = "",
    ) -> AuditRecord:
        """Book one declared audit engagement (minted ``aud-N`` id).

        The first audit on an id registers the system. Raw audit
        reports, evidence packs, and material never enter records -
        digest pins only. Fail-closed: failed mutations consume their
        seq and book an ``ai-audit.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                audit_kind = _check_audit_kind(audit_kind)
                finding = _check_finding(finding)
                audit_digest = _check_digest(audit_digest, "audit_digest")
                self._require_live(system_id)
            except AIAuditError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._audit_counter += 1
            audit_id = f"aud-{self._audit_counter}"
            provisional = AuditRecord(
                audit_id=audit_id,
                system_id=system_id,
                seq=seq,
                audit_kind=audit_kind,
                finding=finding,
                audit_digest=audit_digest,
                digest="",
            )
            digest = _digest_pin(_audit_payload(provisional), "ai-audit.audit")
            rec = AuditRecord(
                audit_id=audit_id,
                system_id=system_id,
                seq=seq,
                audit_kind=audit_kind,
                finding=finding,
                audit_digest=audit_digest,
                digest=digest,
            )
            self._audits[audit_id] = rec
            self._system_audits.setdefault(system_id, []).append(audit_id)
            self._emit(
                "audited",
                seq,
                audit_id=audit_id,
                system_id=system_id,
                audit_kind=audit_kind,
                finding=finding,
            )
            return rec

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_audits:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIAuditError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-audit.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads ----------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, system_id: str) -> bool:
        return all(
            self._audits[aid].verify()
            for aid in self._system_audits.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "clean": 0,
            "minor-findings": 0,
            "major-findings": 0,
            "critical-findings": 0,
            "inconclusive": 0,
            "not-audited": 0,
        }
        ids = self._system_audits.get(system_id, [])
        for aid in ids:
            tallies[self._audits[aid].finding] += 1
        if not ids:
            return "unaudited", tallies
        if tallies["critical-findings"]:
            return "critical", tallies
        if tallies["major-findings"]:
            return "at-risk", tallies
        if tallies["inconclusive"]:
            return "inconclusive", tallies
        if tallies["minor-findings"]:
            return "partial", tallies
        if all(self._audits[aid].finding == "clean" for aid in ids):
            return "clean", tallies
        return "partial", tallies

    def verify(self, audit_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one audit record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._audits.get(audit_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record: {audit_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            provisional = VerificationReport(
                record_id=audit_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-audit.verify")
            return VerificationReport(
                record_id=audit_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's audit posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_audits:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_audits=len(self._system_audits[system_id]),
                n_clean=tallies["clean"],
                n_minor=tallies["minor-findings"],
                n_major=tallies["major-findings"],
                n_critical=tallies["critical-findings"],
                n_inconclusive=tallies["inconclusive"],
                n_not_audited=tallies["not-audited"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-audit.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_audits=len(self._system_audits[system_id]),
                n_clean=tallies["clean"],
                n_minor=tallies["minor-findings"],
                n_major=tallies["major-findings"],
                n_critical=tallies["critical-findings"],
                n_inconclusive=tallies["inconclusive"],
                n_not_audited=tallies["not-audited"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) ----------------------------------------------------

    def audit_record(self, audit_id: str, seq: int) -> AuditRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._audits.get(audit_id)
            if rec is None:
                raise UnknownAuditError(f"unknown audit: {audit_id!r}")
            return rec

    def audits_for(self, system_id: str, seq: int) -> Tuple[AuditRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._audits[aid]
                for aid in self._system_audits.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_audits.keys()))

    def audit_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._audits.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_audits),
                "n_audits": len(self._audits),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# stdlib self-check and CLI
# ---------------------------------------------------------------------------


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
    """Self-check: exercise audit -> verify -> evaluate."""
    ledger = AIAudit()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.audit(
        "sys-1",
        1,
        audit_kind="external-audit",
        finding="minor-findings",
    )
    assert rec.verify()
    rep = ledger.verify(rec.audit_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 3)
    assert ev.posture == "partial"
    ret = ledger.retire("sys-1", 4)
    assert ret.verify()
    print("ai-audit OK: audit, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
