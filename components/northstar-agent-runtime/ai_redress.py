"""AI redress: remedy-provision decision ledger, Simulated.

Research note: AI redress is the remedy side of AI accountability -
when an AI system is alleged to have caused harm, what remedy the host
declared it provided (apology, compensation, correction, retraction,
restoration, policy change), and what redress posture the ledger
derives for the claim. This module is the *decision ledger* for
declared AI redress provisions: which claims had which redress kinds
booked (over a pinned redress-kind vocabulary), what outcomes were
declared against them, and what redress posture the ledger derives -
defensible bookkeeping, never proof that anyone was really made
whole.

This module owns the provide -> verify -> evaluate lifecycle:

* **provide()** - book one declared redress provision (minted ``rds-N``
  ids; pinned redress-kind vocabulary over the common remedy classes;
  pinned outcome vocabulary booked *as data*); the first provision
  registers its claim; raw claim details, harm descriptions, claimant
  identities, and payment material never enter records - digest pins
  only.
* **verify()** - **pure read**: re-derive one redress record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as
  proof the remedy really happened.
* **evaluate()** - **pure read**: derive one claim's redress posture as
  data (``unaddressed`` -> ``redress-denied`` -> ``inconclusive`` ->
  ``partially-redressed`` -> ``redressed``) with outcome tallies and a
  digest-pinned integrity flag.
* **retire()** - terminal retirement of a claim id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_governance.py`` owns the
governance-operations ledger (declared controls plus audit decisions);
``ai_safety.py`` owns the assessment -> mitigation lifecycle (declared
hazards and their mitigations); ``ai_oversight.py`` owns oversight
sessions; ``ai_ethics.py`` owns ethics assessments; ``trustworthy_ai.py``
owns framework-scoped assessments - this module is the
*remedy-provision* ledger none of them own: declared remedies against
declared claims, digest re-derivation, and the ledger-rule posture that
turns declared provisions into a redress claim, always as data, never
as measured justice.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-redress.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module redresses nobody, pays no compensation,
retracts nothing, and proves nothing about real-world remedy outcomes.
A booked ``redressed`` posture means "the host declared it", never
"the claimant was made whole"; a booked ``granted`` outcome means "the
host declared it", never "the remedy reached the harmed party". Claim
details, harm narratives, claimant identities, payment amounts, and raw
remedy material never enter records or cross the audit boundary -
digest pins only.
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
AI_REDRESS_VERSION = "ai-redress.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-redress.v1"

#: Pinned redress-kind vocabulary (the remedy classes).
REDRESS_KINDS = (
    "apology",
    "compensation",
    "record-correction",
    "output-retraction",
    "remediation-action",
    "appeal-outcome",
    "service-restoration",
    "policy-change",
)

#: Pinned provision-outcome vocabulary (booked as data, never proof).
REDRESS_OUTCOMES = (
    "granted",
    "partial",
    "denied",
    "inconclusive",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unaddressed",
    "redress-denied",
    "inconclusive",
    "partially-redressed",
    "redressed",
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
    "provided",
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
        "claimant",
        "claimant_name",
        "claimant_id",
        "claim_details",
        "claim_text",
        "harm",
        "harm_description",
        "harm_narrative",
        "injury",
        "damage",
        "damages",
        "compensation_amount",
        "payout",
        "payout_amount",
        "payment",
        "payment_details",
        "bank_details",
        "account_details",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "personal_data",
        "personal_information",
        "identity",
        "identity_document",
        "document",
        "documents",
        "medical_record",
        "financial_record",
        "settlement",
        "settlement_terms",
        "agreement",
        "legal_filing",
        "court_order",
        "remedy_text",
        "apology_text",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIRedressError(Exception):
    """Base class for all ai-redress ledger errors."""


class BadClaimError(AIRedressError):
    pass


class UnknownClaimError(AIRedressError):
    pass


class RetiredClaimError(AIRedressError):
    pass


class BadRedressKindError(AIRedressError):
    pass


class BadOutcomeError(AIRedressError):
    pass


class BadDigestError(AIRedressError):
    pass


class BadReasonError(AIRedressError):
    pass


class UnknownRedressError(AIRedressError):
    pass


class SeqOrderError(AIRedressError):
    pass


class AuditKindError(AIRedressError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadClaimError(f"{what} must be a non-empty string")
    return value


def _check_redress_kind(value: Any) -> str:
    if value not in REDRESS_KINDS:
        raise BadRedressKindError(f"redress_kind must be one of {REDRESS_KINDS}")
    return value


def _check_outcome(value: Any) -> str:
    if value not in REDRESS_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {REDRESS_OUTCOMES}")
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


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RedressRecord:
    redress_id: str
    claim_id: str
    seq: int
    redress_kind: str
    outcome: str
    claim_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _provide_payload(self), "ai-redress.provide"
        )


@dataclass(frozen=True)
class RetireRecord:
    claim_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_retire_payload(self), "ai-redress.retire")


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-redress.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    claim_id: str
    seq: int
    posture: str
    n_provisions: int
    n_granted: int
    n_partial: int
    n_denied: int
    n_inconclusive: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-redress.evaluate"
        )


def _provide_payload(rec: "RedressRecord") -> Dict[str, Any]:
    return {
        "redress_id": rec.redress_id,
        "claim_id": rec.claim_id,
        "seq": rec.seq,
        "redress_kind": rec.redress_kind,
        "outcome": rec.outcome,
        "claim_digest": rec.claim_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"claim_id": rec.claim_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "claim_id": rep.claim_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_provisions": rep.n_provisions,
        "n_granted": rep.n_granted,
        "n_partial": rep.n_partial,
        "n_denied": rep.n_denied,
        "n_inconclusive": rep.n_inconclusive,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_redress_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIRedressError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-redress",
        "version": AI_REDRESS_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIRedress:
    """AI-redress remedy-provision decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that a remedy was really provided or that anyone
    was made whole.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._redresses: Dict[str, RedressRecord] = {}
        self._claim_redresses: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._redress_counter = 0
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
            row = ai_redress_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-redress",
                "version": AI_REDRESS_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_redress_audit_event(audit_kind, seq, **details))

    def _require_live(self, claim_id: str) -> None:
        if claim_id in self._retired:
            raise RetiredClaimError(f"claim is retired: {claim_id!r}")

    # -- mutations ---------------------------------------------------------

    def provide(
        self,
        claim_id: str,
        seq: int,
        redress_kind: str = "compensation",
        outcome: str = "granted",
        claim_digest: str = "",
    ) -> RedressRecord:
        """Book one declared redress provision (minted ``rds-N`` id).

        The first provision on an id registers the claim. Raw claim
        details, harm narratives, claimant identities, and payment
        material never enter records - digest pins only. Fail-closed:
        failed mutations consume their seq and book an
        ``ai-redress.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                claim_id = _check_id(claim_id, "claim_id")
                self._require_seq(seq)
                redress_kind = _check_redress_kind(redress_kind)
                outcome = _check_outcome(outcome)
                claim_digest = _check_digest(claim_digest, "claim_digest")
                self._require_live(claim_id)
            except AIRedressError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._redress_counter += 1
            redress_id = f"rds-{self._redress_counter}"
            provisional = RedressRecord(
                redress_id=redress_id,
                claim_id=claim_id,
                seq=seq,
                redress_kind=redress_kind,
                outcome=outcome,
                claim_digest=claim_digest,
                digest="",
            )
            digest = _digest_pin(_provide_payload(provisional), "ai-redress.provide")
            rec = RedressRecord(
                redress_id=redress_id,
                claim_id=claim_id,
                seq=seq,
                redress_kind=redress_kind,
                outcome=outcome,
                claim_digest=claim_digest,
                digest=digest,
            )
            self._redresses[redress_id] = rec
            self._claim_redresses.setdefault(claim_id, []).append(redress_id)
            self._emit(
                "provided",
                seq,
                redress_id=redress_id,
                claim_id=claim_id,
                redress_kind=redress_kind,
                outcome=outcome,
                claim_digest=claim_digest,
            )
            return rec

    def retire(
        self, claim_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of a claim id; ids are never recycled."""
        with self._lock:
            try:
                claim_id = _check_id(claim_id, "claim_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if claim_id in self._retired:
                    raise RetiredClaimError(f"claim is retired: {claim_id!r}")
                if claim_id not in self._claim_redresses:
                    raise UnknownClaimError(f"unknown claim: {claim_id!r}")
            except AIRedressError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                claim_id=claim_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-redress.retire")
            rec = RetireRecord(
                claim_id=claim_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[claim_id] = rec
            self._emit("retired", seq, claim_id=claim_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, redress_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one redress record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the remedy really happened. Seq is shape-validated only -
        never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if (
                isinstance(redress_id, bool)
                or not isinstance(redress_id, str)
                or redress_id not in self._redresses
            ):
                raise UnknownRedressError(f"unknown redress id: {redress_id!r}")
            rec = self._redresses[redress_id]
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=redress_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-redress.verify")
            return VerificationReport(
                record_id=redress_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, claim_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one claim's redress posture as data.

        Posture by ledger rule: ``unaddressed`` (nothing booked) ->
        ``redress-denied`` (any denied) -> ``inconclusive`` (any
        inconclusive) -> ``partially-redressed`` (any partial) ->
        ``redressed`` (all granted). ``integrity_ok`` re-derives all
        in-scope digest pins as data. Seq is shape-validated only -
        never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            claim_id = _check_id(claim_id, "claim_id")
            if claim_id not in self._claim_redresses:
                raise UnknownClaimError(f"unknown claim: {claim_id!r}")
            ids = self._claim_redresses[claim_id]
            recs = [self._redresses[i] for i in ids]
            n_granted = sum(1 for r in recs if r.outcome == "granted")
            n_partial = sum(1 for r in recs if r.outcome == "partial")
            n_denied = sum(1 for r in recs if r.outcome == "denied")
            n_inconclusive = sum(1 for r in recs if r.outcome == "inconclusive")
            if n_denied:
                posture = "redress-denied"
            elif n_inconclusive:
                posture = "inconclusive"
            elif n_partial:
                posture = "partially-redressed"
            elif n_granted and n_granted == len(recs):
                posture = "redressed"
            else:
                posture = "unaddressed"
            integrity_ok = all(r.verify() for r in recs)
            provisional = EvaluationReport(
                claim_id=claim_id,
                seq=seq,
                posture=posture,
                n_provisions=len(recs),
                n_granted=n_granted,
                n_partial=n_partial,
                n_denied=n_denied,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-redress.evaluate")
            return EvaluationReport(
                claim_id=claim_id,
                seq=seq,
                posture=posture,
                n_provisions=len(recs),
                n_granted=n_granted,
                n_partial=n_partial,
                n_denied=n_denied,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def redress_record(self, redress_id: str, seq: int) -> RedressRecord:
        with self._lock:
            self._check_read_seq(seq)
            if redress_id not in self._redresses:
                raise UnknownRedressError(f"unknown redress id: {redress_id!r}")
            return self._redresses[redress_id]

    def retire_record(self, claim_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._check_read_seq(seq)
            if claim_id not in self._retired:
                raise UnknownClaimError(f"unknown claim: {claim_id!r}")
            return self._retired[claim_id]

    def redresses_for(self, claim_id: str, seq: int) -> Tuple[RedressRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._redresses[i] for i in self._claim_redresses.get(claim_id, [])
            )

    def claim_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._claim_redresses))

    def redress_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._redresses))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_claims": len(self._claim_redresses),
                "n_redresses": len(self._redresses),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_REDRESS_VERSION,
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
    """Self-check: exercise provide -> verify -> evaluate."""
    ledger = AIRedress()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.provide(
        "claim-1",
        1,
        redress_kind="compensation",
        outcome="granted",
    )
    assert rec.verify()
    rep = ledger.verify(rec.redress_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("claim-1", 3)
    assert ev.posture == "redressed"
    ret = ledger.retire("claim-1", 4)
    assert ret.verify()
    print("ai-redress OK: provide, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
