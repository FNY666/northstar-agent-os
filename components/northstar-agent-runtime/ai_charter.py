"""AI charter: charter-commitment decision ledger, Simulated.

Research note: an AI charter is a formal commitment document (the
Anthropic-Charter shape): a pinned set of duties, guidelines, and
virtues that an AI agent declares itself bound by - corrigibility first,
then duties to humanity, then fiduciary duties to principals, then
meta/guideline layers, then virtues. This module is the *decision
ledger* for declared charter commitments: which charters were declared
over the pinned charter vocabulary, what stance each commitment took
(booked *as data*), and what charter posture the ledger derives -
defensible bookkeeping, never proof that an agent really follows its
charter.

This module owns the declare -> verify -> evaluate lifecycle:

* **declare()** - book one declared charter commitment (minted ``dcl-N``
  ids; pinned commitment-kind vocabulary over the charter's structural
  layers; pinned stance vocabulary booked *as data*); the first
  declaration registers its charter; raw charter text, transcripts, and
  material never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one declaration record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data, never
  as proof the commitment really binds the agent.
* **evaluate()** - **pure read**: derive one charter's posture as data
  (``uncommitted`` -> ``withdrawn`` -> ``contested`` -> ``provisional``
  -> ``adopted``) with stance tallies and a digest-pinned integrity
  flag.
* **retire()** - terminal retirement of a charter id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``constitutional_ai.py`` owns the
principle declaration lifecycle (principle -> submit draft -> critique
against a principle -> revise); ``ai_alignment.py`` owns generic
alignment assessments; ``ai_governance.py`` owns governance-control
operations; ``ai_safety.py`` owns the safety-assessment/mitigation
lifecycle - this module is the *charter-commitment* decision ledger none
of them own: declared commitments over the pinned charter vocabulary,
digest re-derivation, and the ledger-rule posture that turns declared
stances into a charter claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-charter.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module binds no agents, enforces no charter, and
proves nothing about real AI alignment. A booked ``adopted`` stance
means "the host declared it", never "the agent is bound by it". Charter
text, training logs, weights, transcripts, and raw commitment material
never enter records or cross the audit boundary - digest pins only.
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
AI_CHARTER_VERSION = "ai-charter.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-charter.v1"

#: Pinned commitment-kind vocabulary (the charter's structural layers).
COMMITMENT_KINDS = (
    "corrigibility",
    "duty-to-humanity",
    "fiduciary-duty",
    "meta-guideline",
    "policy-guideline",
    "operationalization",
    "informational-guideline",
    "virtue",
)

#: Pinned commitment-stance vocabulary (booked as data, never proof).
COMMITMENT_STANCES = (
    "adopted",
    "provisional",
    "suspended",
    "withdrawn",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "uncommitted",
    "withdrawn",
    "contested",
    "provisional",
    "adopted",
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
    "declared",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "charter",
        "charter_text",
        "charter_body",
        "statement",
        "statements",
        "commitment_text",
        "principles",
        "text",
        "document",
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
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
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
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "justification",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AICharterError(Exception):
    """Base class for all ai-charter ledger errors."""


class BadCharterError(AICharterError):
    pass


class UnknownCharterError(AICharterError):
    pass


class RetiredCharterError(AICharterError):
    pass


class BadCommitmentKindError(AICharterError):
    pass


class BadStanceError(AICharterError):
    pass


class BadDigestError(AICharterError):
    pass


class BadReasonError(AICharterError):
    pass


class UnknownDeclarationError(AICharterError):
    pass


class UnknownRecordError(AICharterError):
    pass


class SeqOrderError(AICharterError):
    pass


class AuditKindError(AICharterError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadCharterError(f"{what} must be a non-empty string")
    return value


def _check_commitment_kind(value: Any) -> str:
    if value not in COMMITMENT_KINDS:
        raise BadCommitmentKindError(
            f"commitment_kind must be one of {COMMITMENT_KINDS}"
        )
    return value


def _check_stance(value: Any) -> str:
    if value not in COMMITMENT_STANCES:
        raise BadStanceError(f"stance must be one of {COMMITMENT_STANCES}")
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
class DeclarationRecord:
    declaration_id: str
    charter_id: str
    seq: int
    commitment_kind: str
    stance: str
    statement_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _declare_payload(self), "ai-charter.declare"
        )


@dataclass(frozen=True)
class RetireRecord:
    charter_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-charter.retire"
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
            _verify_payload(self), "ai-charter.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    charter_id: str
    seq: int
    posture: str
    n_declarations: int
    n_adopted: int
    n_provisional: int
    n_suspended: int
    n_withdrawn: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-charter.evaluate"
        )


def _declare_payload(rec: "DeclarationRecord") -> Dict[str, Any]:
    return {
        "declaration_id": rec.declaration_id,
        "charter_id": rec.charter_id,
        "seq": rec.seq,
        "commitment_kind": rec.commitment_kind,
        "stance": rec.stance,
        "statement_digest": rec.statement_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"charter_id": rec.charter_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "charter_id": rep.charter_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_declarations": rep.n_declarations,
        "n_adopted": rep.n_adopted,
        "n_provisional": rep.n_provisional,
        "n_suspended": rep.n_suspended,
        "n_withdrawn": rep.n_withdrawn,
        "integrity_ok": rep.integrity_ok,
    }


def ai_charter_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AICharterError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-charter",
        "version": AI_CHARTER_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AICharter:
    """AI-charter commitment decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All stances are booked as
    data - never proof that an agent really follows its charter.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._declarations: Dict[str, DeclarationRecord] = {}
        self._charter_declarations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._declaration_counter = 0
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
            row = ai_charter_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-charter",
                "version": AI_CHARTER_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_charter_audit_event(audit_kind, seq, **details))

    def _require_live(self, charter_id: str) -> None:
        if charter_id in self._retired:
            raise RetiredCharterError(f"charter is retired: {charter_id!r}")

    # -- mutations ---------------------------------------------------------

    def declare(
        self,
        charter_id: str,
        seq: int,
        commitment_kind: str = "corrigibility",
        stance: str = "adopted",
        statement_digest: str = "",
    ) -> DeclarationRecord:
        """Book one declared charter commitment (minted ``dcl-N`` id).

        The first declaration on an id registers the charter. Raw charter
        text, transcripts, and material never enter records - digest pins
        only. Fail-closed: failed mutations consume their seq and book an
        ``ai-charter.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                charter_id = _check_id(charter_id, "charter_id")
                self._require_seq(seq)
                commitment_kind = _check_commitment_kind(commitment_kind)
                stance = _check_stance(stance)
                statement_digest = _check_digest(
                    statement_digest, "statement_digest"
                )
                self._require_live(charter_id)
            except AICharterError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._declaration_counter += 1
            declaration_id = f"dcl-{self._declaration_counter}"
            provisional = DeclarationRecord(
                declaration_id=declaration_id,
                charter_id=charter_id,
                seq=seq,
                commitment_kind=commitment_kind,
                stance=stance,
                statement_digest=statement_digest,
                digest="",
            )
            digest = _digest_pin(_declare_payload(provisional), "ai-charter.declare")
            rec = DeclarationRecord(
                declaration_id=declaration_id,
                charter_id=charter_id,
                seq=seq,
                commitment_kind=commitment_kind,
                stance=stance,
                statement_digest=statement_digest,
                digest=digest,
            )
            self._declarations[declaration_id] = rec
            self._charter_declarations.setdefault(charter_id, []).append(
                declaration_id
            )
            self._emit(
                "declared",
                seq,
                declaration_id=declaration_id,
                charter_id=charter_id,
                commitment_kind=commitment_kind,
                stance=stance,
            )
            return rec

    def retire(
        self, charter_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a charter id; ids are never recycled."""
        with self._lock:
            try:
                charter_id = _check_id(charter_id, "charter_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if charter_id not in self._charter_declarations:
                    raise UnknownCharterError(f"unknown charter: {charter_id!r}")
                if charter_id in self._retired:
                    raise RetiredCharterError(
                        f"charter already retired: {charter_id!r}"
                    )
            except AICharterError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                charter_id=charter_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-charter.retire")
            rec = RetireRecord(
                charter_id=charter_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[charter_id] = rec
            self._emit("retired", seq, charter_id=charter_id, reason=reason)
            return rec

    # -- pure reads ----------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, charter_id: str) -> bool:
        return all(
            self._declarations[did].verify()
            for did in self._charter_declarations.get(charter_id, [])
        )

    def _posture(self, charter_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "adopted": 0,
            "provisional": 0,
            "suspended": 0,
            "withdrawn": 0,
        }
        ids = self._charter_declarations.get(charter_id, [])
        for did in ids:
            tallies[self._declarations[did].stance] += 1
        if not ids:
            return "uncommitted", tallies
        if tallies["withdrawn"]:
            return "withdrawn", tallies
        if tallies["suspended"]:
            return "contested", tallies
        if tallies["provisional"]:
            return "provisional", tallies
        return "adopted", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one declaration record's digest pin."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._declarations.get(record_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-charter.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, charter_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one charter's posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            charter_id = _check_id(charter_id, "charter_id")
            if charter_id not in self._charter_declarations:
                raise UnknownCharterError(f"unknown charter: {charter_id!r}")
            posture, tallies = self._posture(charter_id)
            provisional = EvaluationReport(
                charter_id=charter_id,
                seq=seq,
                posture=posture,
                n_declarations=len(self._charter_declarations[charter_id]),
                n_adopted=tallies["adopted"],
                n_provisional=tallies["provisional"],
                n_suspended=tallies["suspended"],
                n_withdrawn=tallies["withdrawn"],
                integrity_ok=self._integrity_ok(charter_id),
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-charter.evaluate"
            )
            return EvaluationReport(
                charter_id=charter_id,
                seq=seq,
                posture=posture,
                n_declarations=len(self._charter_declarations[charter_id]),
                n_adopted=tallies["adopted"],
                n_provisional=tallies["provisional"],
                n_suspended=tallies["suspended"],
                n_withdrawn=tallies["withdrawn"],
                integrity_ok=self._integrity_ok(charter_id),
                digest=digest,
            )

    # -- views (pure reads) ----------------------------------------------------

    def declaration_record(self, declaration_id: str, seq: int) -> DeclarationRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._declarations.get(declaration_id)
            if rec is None:
                raise UnknownDeclarationError(
                    f"unknown declaration: {declaration_id!r}"
                )
            return rec

    def declarations_for(
        self, charter_id: str, seq: int
    ) -> Tuple[DeclarationRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._declarations[did]
                for did in self._charter_declarations.get(charter_id, [])
            )

    def charter_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._charter_declarations.keys()))

    def declaration_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._declarations.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_charters": len(self._charter_declarations),
                "n_declarations": len(self._declarations),
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
    """Self-check: exercise declare -> verify -> evaluate."""
    ledger = AICharter()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.declare(
        "charter-1", 1, commitment_kind="corrigibility", stance="adopted"
    )
    assert rec.verify()
    rec2 = ledger.declare(
        "charter-1", 2, commitment_kind="virtue", stance="provisional"
    )
    assert rec2.verify()
    rep = ledger.verify(rec.declaration_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("charter-1", 4)
    assert ev.posture == "provisional"
    ret = ledger.retire("charter-1", 5)
    assert ret.verify()
    print("ai-charter OK: declare, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
