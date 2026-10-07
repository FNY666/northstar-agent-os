"""AI accountability: accountability-assignment decision ledger, Simulated.

Research note: AI accountability is the assignment of answerability -
who (which party) is accountable for which system and for which
accountability domain, under what declared status. This module is the
*decision ledger* for declared AI accountability assignments: which
systems have which assignments booked (over a pinned accountability-kind
vocabulary), what statuses were declared against them, and what
accountability posture the ledger derives - defensible bookkeeping,
never proof that a system is really accountable to anyone.

This module owns the assign -> verify -> evaluate lifecycle:

* **assign()** - book one declared accountability assignment (minted
  ``asg-N`` ids; pinned accountability-kind vocabulary over the common
  AI accountability domains; pinned status vocabulary booked *as
  data*); the first assignment registers its system; raw contracts,
  role charters, signatures, and material never enter records - digest
  pins only.
* **verify()** - **pure read**: re-derive one assignment record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as
  proof the assignment really binds anyone.
* **evaluate()** - **pure read**: derive one system's accountability
  posture as data (``unassigned`` -> ``accountability-gap`` ->
  ``contested`` -> ``pending`` -> ``covered``) with status tallies and
  a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_governance.py`` owns the
governance-operations ledger (declared governance controls over named
systems plus audit *decisions* booked against those controls);
``ai_audit.py`` owns the audit-execution ledger (declared audit
engagements and findings); ``ai_safety.py`` owns the assessment ->
mitigation lifecycle (declared hazards and their mitigations);
``ai_alignment.py`` owns alignment assessments; ``ai_ethics.py`` owns
ethics assessments; ``trustworthy_ai.py`` owns framework-scoped
trustworthiness assessments; ``ai_oversight.py`` owns declared
oversight sessions - this module is the *accountability-assignment*
ledger none of them own: declared assignments of accountable parties
over named systems and accountability domains, digest re-derivation,
and the ledger-rule posture that turns declared assignments into an
accountability claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-accountability.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module assigns accountability to nobody, binds no
party, inspects no contracts, and proves nothing about real AI
accountability. A booked ``accepted`` status means "the host declared
it", never "the party really accepted"; a booked ``covered`` posture
means "the host declared it", never "someone is actually answerable".
Contracts, role charters, signatures, identities, and raw accountability
material never enter records or cross the audit boundary - digest pins
only.
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
AI_ACCOUNTABILITY_VERSION = "ai-accountability.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-accountability.v1"

#: Pinned accountability-kind vocabulary (the AI accountability domains).
ACCOUNTABILITY_KINDS = (
    "development",
    "deployment",
    "operation",
    "data-governance",
    "evaluation",
    "oversight",
    "incident-response",
    "monitoring",
)

#: Pinned accountability-status vocabulary (booked as data, never proof).
ACCOUNTABILITY_STATUSES = (
    "assigned",
    "accepted",
    "contested",
    "vacant",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unassigned",
    "accountability-gap",
    "contested",
    "pending",
    "covered",
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
    "assigned",
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
        "contract",
        "contracts",
        "signature",
        "signatures",
        "identity",
        "identities",
        "role",
        "roles",
        "agreement",
        "agreements",
        "charter",
        "charters",
        "liability",
        "justification",
        "clause",
        "clauses",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIAccountabilityError(Exception):
    """Base class for all ai-accountability ledger errors."""


class BadSystemError(AIAccountabilityError):
    pass


class BadPartyError(AIAccountabilityError):
    pass


class UnknownSystemError(AIAccountabilityError):
    pass


class RetiredSystemError(AIAccountabilityError):
    pass


class BadKindError(AIAccountabilityError):
    pass


class BadStatusError(AIAccountabilityError):
    pass


class BadDigestError(AIAccountabilityError):
    pass


class BadReasonError(AIAccountabilityError):
    pass


class UnknownAssignmentError(AIAccountabilityError):
    pass


class UnknownRecordError(AIAccountabilityError):
    pass


class SeqOrderError(AIAccountabilityError):
    pass


class AuditKindError(AIAccountabilityError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_party(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadPartyError("accountable_party must be a non-empty string")
    return value


def _check_kind(value: Any) -> str:
    if value not in ACCOUNTABILITY_KINDS:
        raise BadKindError(f"accountability_kind must be one of {ACCOUNTABILITY_KINDS}")
    return value


def _check_status(value: Any) -> str:
    if value not in ACCOUNTABILITY_STATUSES:
        raise BadStatusError(f"status must be one of {ACCOUNTABILITY_STATUSES}")
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
class AssignmentRecord:
    assignment_id: str
    system_id: str
    accountable_party: str
    seq: int
    accountability_kind: str
    status: str
    assignment_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _assign_payload(self), "ai-accountability.assign"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-accountability.retire"
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
            _verify_payload(self), "ai-accountability.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_assignments: int
    n_accepted: int
    n_assigned: int
    n_contested: int
    n_vacant: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-accountability.evaluate"
        )


def _assign_payload(rec: "AssignmentRecord") -> Dict[str, Any]:
    return {
        "assignment_id": rec.assignment_id,
        "system_id": rec.system_id,
        "accountable_party": rec.accountable_party,
        "seq": rec.seq,
        "accountability_kind": rec.accountability_kind,
        "status": rec.status,
        "assignment_digest": rec.assignment_digest,
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
        "n_assignments": rep.n_assignments,
        "n_accepted": rep.n_accepted,
        "n_assigned": rep.n_assigned,
        "n_contested": rep.n_contested,
        "n_vacant": rep.n_vacant,
        "integrity_ok": rep.integrity_ok,
    }


def ai_accountability_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIAccountabilityError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-accountability",
        "version": AI_ACCOUNTABILITY_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIAccountability:
    """AI-accountability assignment decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All assignments, statuses,
    and postures are booked as data - never proof that anyone is really
    answerable.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._assignments: Dict[str, AssignmentRecord] = {}
        self._system_assignments: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._assignment_counter = 0
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
            row = ai_accountability_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-accountability",
                "version": AI_ACCOUNTABILITY_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_accountability_audit_event(kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def assign(
        self,
        system_id: str,
        seq: int,
        accountable_party: str,
        accountability_kind: str = "development",
        status: str = "assigned",
        assignment_digest: str = "",
    ) -> AssignmentRecord:
        """Book one declared accountability assignment (minted ``asg-N`` id).

        The first assignment on an id registers the system. Raw
        contracts, role charters, signatures, and material never enter
        records - digest pins only. Fail-closed: failed mutations
        consume their seq and book an ``ai-accountability.rejected``
        row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                party = _check_party(accountable_party)
                kind = _check_kind(accountability_kind)
                st = _check_status(status)
                digest = _check_digest(assignment_digest, "assignment_digest")
                self._require_live(system_id)
            except AIAccountabilityError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._assignment_counter += 1
            assignment_id = f"asg-{self._assignment_counter}"
            provisional = AssignmentRecord(
                assignment_id=assignment_id,
                system_id=system_id,
                accountable_party=party,
                seq=seq,
                accountability_kind=kind,
                status=st,
                assignment_digest=digest,
                digest="",
            )
            pin = _digest_pin(_assign_payload(provisional), "ai-accountability.assign")
            rec = AssignmentRecord(
                assignment_id=assignment_id,
                system_id=system_id,
                accountable_party=party,
                seq=seq,
                accountability_kind=kind,
                status=st,
                assignment_digest=digest,
                digest=pin,
            )
            self._assignments[assignment_id] = rec
            self._system_assignments.setdefault(system_id, []).append(assignment_id)
            self._emit(
                "assigned",
                seq,
                assignment_id=assignment_id,
                system_id=system_id,
                accountability_kind=kind,
                status=st,
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
                if system_id not in self._system_assignments:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIAccountabilityError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            pin = _digest_pin(_retire_payload(provisional), "ai-accountability.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=pin
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
            self._assignments[aid].verify()
            for aid in self._system_assignments.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "accepted": 0,
            "assigned": 0,
            "contested": 0,
            "vacant": 0,
        }
        ids = self._system_assignments.get(system_id, [])
        for aid in ids:
            tallies[self._assignments[aid].status] += 1
        if not ids:
            return "unassigned", tallies
        if tallies["vacant"]:
            return "accountability-gap", tallies
        if tallies["contested"]:
            return "contested", tallies
        if tallies["assigned"]:
            return "pending", tallies
        return "covered", tallies

    def verify(self, assignment_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one assignment record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._assignments.get(assignment_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record: {assignment_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            ok = rec.verify()
            provisional = VerificationReport(
                record_id=assignment_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=ok,
                digest="",
            )
            pin = _digest_pin(_verify_payload(provisional), "ai-accountability.verify")
            return VerificationReport(
                record_id=assignment_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=ok,
                digest=pin,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's accountability posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_assignments:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assignments=len(self._system_assignments[system_id]),
                n_accepted=tallies["accepted"],
                n_assigned=tallies["assigned"],
                n_contested=tallies["contested"],
                n_vacant=tallies["vacant"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            pin = _digest_pin(_evaluate_payload(provisional), "ai-accountability.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assignments=len(self._system_assignments[system_id]),
                n_accepted=tallies["accepted"],
                n_assigned=tallies["assigned"],
                n_contested=tallies["contested"],
                n_vacant=tallies["vacant"],
                integrity_ok=self._integrity_ok(system_id),
                digest=pin,
            )

    # -- views (pure reads) ----------------------------------------------------

    def assignment_record(self, assignment_id: str, seq: int) -> AssignmentRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._assignments.get(assignment_id)
            if rec is None:
                raise UnknownAssignmentError(f"unknown assignment: {assignment_id!r}")
            return rec

    def assignments_for(self, system_id: str, seq: int) -> Tuple[AssignmentRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._assignments[aid]
                for aid in self._system_assignments.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_assignments.keys()))

    def assignment_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._assignments.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_assignments),
                "n_assignments": len(self._assignments),
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
    """Self-check: exercise assign -> verify -> evaluate."""
    ledger = AIAccountability()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.assign(
        "sys-1",
        1,
        accountable_party="deploy-team",
        accountability_kind="deployment",
        status="accepted",
    )
    assert rec.verify()
    rep = ledger.verify(rec.assignment_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 3)
    assert ev.posture == "covered"
    ret = ledger.retire("sys-1", 4)
    assert ret.verify()
    print("ai-accountability OK: assign, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
