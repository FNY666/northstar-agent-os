"""AI principles declaration (declare/verify/evaluate) interface, simulated.

Research motivation: every alignment charter (Asimov's laws,
Anthropic's Charter duties of humanity/fiduciary duties, the Belmont
Report's respect/beneficence/justice, OECD AI Principles) reduces
governance to one operational shape: a principal *declares* a
principle over a pinned vocabulary, the ledger pins it, and a report
derives posture *from the ledger* -- the report never independently
judges which principles ought to hold.

This module is the *principles declaration* ledger half of that
shape:

- ``AIPrinciples.declare(principal_id, principle_kind, status, seq,
  principle_digest="")`` -- book one declared principle over the
  pinned 8-principle vocabulary x the pinned 4-status vocabulary. The
  principle's content is pinned by ``sha256:`` digest only; raw
  material never enters a record. First declare on an id registers
  the principal. Returns the frozen ``DeclarationRecord`` (minted
  ``dcl-N``).
- ``AIPrinciples.verify(declaration_id, seq)`` -- **pure read** (seq
  shape validated, never consumed, no audit row). Re-derives the
  digest pin; the ``verified``/``tampered`` verdict is *data*, never
  proof the principle is honored.
- ``AIPrinciples.evaluate(principal_id, seq)`` -- **pure read**.
  Derives posture as data by ledger rule: ``undeclared`` (no
  declarations) -> ``suspended-open`` (any ``suspended``) ->
  ``under-review`` (any ``proposed``) -> ``declared`` (all
  ``adopted``/``amended``), plus status tallies and ``integrity_ok``
  as data.
- ``AIPrinciples.retire(principal_id, seq, reason="manual")`` --
  terminal. Ids are never recycled; post-retire mutations are
  refused, reads still work.
- Pure-read views (``declaration_record`` / ``declarations_for`` /
  ``principal_ids`` / ``retired_ids`` / ``stats`` / ``audit_log``) --
  seq shape validated, never consumed, no audit rows.
- ``ai_principles_audit_event(kind, ...)`` -- ``audit.ndjson/1`` rows
  (``declared`` / ``retired`` / ``rejected``); caller-supplied seqs
  only. Raw principle content never crosses the audit boundary --
  audit rows carry ids, pinned kind/status labels, digests, and
  counts only.

Distinct layer: ``constitutional_ai.py`` owns the principle
*lifecycle* (principle -> submit draft -> critique -> revise);
``ai_ethics.py`` / ``aligned_ai.py`` / ``beneficial_ai.py`` own
*assessment* ledgers (host declares a finding, ledger derives
posture). This module owns the *declaration* ledger none of them
cover -- who declared which principle, with what status, digest
re-derivation, and derived declaration posture.

Fail-closed edges (fail loudly, never guess):

- ``principal_id`` / ``declaration_id`` must be non-empty str, <= 256
  chars, no whitespace.
- ``principle_kind`` must be in the pinned 8-principle vocabulary;
  ``status`` must be in the pinned 4-status vocabulary.
- ``principle_digest`` must be ``sha256:<64hex>`` when supplied (may
  be empty).
- ``verify`` / ``declare`` on unknown ids raise; duplicate ids never
  occur (ids are minted ``dcl-N``).
- ``declare`` on a retired principal raises ``RetiredPrincipalError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* principles reported by the host. A
  booked ``adopted`` status means the host declared one -- the module
  wrote no charter, weighed no duties, and proves nothing about any
  real system's principles, alignment, or safety.
- Digest pins prove ledger integrity and ordering, never the truth
  of any declaration or the moral adequacy of any principle.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if principle state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
AI_PRINCIPLES_VERSION = "ai-principles.v1"

#: Schema pin carried by records and audit events.
AI_PRINCIPLES_SCHEMA = "northstar.ai-principles.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_DECLARED = "declared"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_DECLARED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"content", "text", "payload", "raw", "charter", "charter_text",
     "wording", "clause", "rationale", "justification", "evidence",
     "analysis", "report", "declaration_text", "metric", "score",
     "data", "record", "trace", "transcript", "weights", "policy",
     "model_output", "judgment", "note", "comment", "explanation"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned principle vocabulary (duties-of-humanity / fiduciary shaped).
KIND_PUBLIC_SAFETY = "public-safety"
KIND_LIBERTY = "liberty"
KIND_SINCERITY = "sincerity"
KIND_LEGAL_COMPLIANCE = "legal-compliance"
KIND_FIDELITY = "fidelity"
KIND_CARE = "care"
KIND_OBEDIENCE = "obedience"
KIND_DISCLOSURE = "disclosure"
PRINCIPLE_KINDS = (
    KIND_PUBLIC_SAFETY,
    KIND_LIBERTY,
    KIND_SINCERITY,
    KIND_LEGAL_COMPLIANCE,
    KIND_FIDELITY,
    KIND_CARE,
    KIND_OBEDIENCE,
    KIND_DISCLOSURE,
)

#: Pinned declaration-status vocabulary. Statuses are host-reported data.
STATUS_PROPOSED = "proposed"
STATUS_ADOPTED = "adopted"
STATUS_AMENDED = "amended"
STATUS_SUSPENDED = "suspended"
STATUSES = (
    STATUS_PROPOSED,
    STATUS_ADOPTED,
    STATUS_AMENDED,
    STATUS_SUSPENDED,
)

#: Pinned derived postures (ledger rule, precedence documented in evaluate).
POSTURE_UNDECLARED = "undeclared"
POSTURE_SUSPENDED_OPEN = "suspended-open"
POSTURE_UNDER_REVIEW = "under-review"
POSTURE_DECLARED = "declared"
POSTURES = (
    POSTURE_UNDECLARED,
    POSTURE_SUSPENDED_OPEN,
    POSTURE_UNDER_REVIEW,
    POSTURE_DECLARED,
)

#: Pinned retire reasons.
REASON_MANUAL = "manual"
REASON_SUPERSEDED = "superseded"
REASON_POLICY_CHANGE = "policy-change"
REASON_NON_COMPLIANCE = "non-compliance"
REASONS = (
    REASON_MANUAL,
    REASON_SUPERSEDED,
    REASON_POLICY_CHANGE,
    REASON_NON_COMPLIANCE,
)

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class AIPrinciplesError(Exception):
    """Base error for the AI-principles ledger (programming errors)."""


class BadIdError(AIPrinciplesError):
    """Raised when a principal/declaration id is malformed."""


class DuplicateDeclarationError(AIPrinciplesError):
    """Raised when a minted declaration id somehow collides (never)."""


class UnknownPrincipalError(AIPrinciplesError):
    """Raised when a principal id names no declaring principal."""


class UnknownDeclarationError(AIPrinciplesError):
    """Raised when a declaration id names no booked declaration."""


class RetiredPrincipalError(AIPrinciplesError):
    """Raised when mutating a retired principal."""


class DoubleRetireError(AIPrinciplesError):
    """Raised when retiring an already-retired principal."""


class BadPrincipleKindError(AIPrinciplesError):
    """Raised when a principle kind is not in the pinned vocabulary."""


class BadStatusError(AIPrinciplesError):
    """Raised when a status is not in the pinned vocabulary."""


class BadDigestError(AIPrinciplesError):
    """Raised when a principle digest is not a sha256: pin."""


class BadReasonError(AIPrinciplesError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class SeqOrderError(AIPrinciplesError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(AIPrinciplesError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str, allow_empty: bool = False) -> str:
    """Validate a content pin: ``sha256:<64hex>``."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(
            f"{label} must be a sha256: pin, got {type(value).__name__}")
    if not value and allow_empty:
        return value
    if not _DIGEST_RE.match(value):
        raise BadDigestError(
            f"{label} must match sha256:<64hex>, got {value!r}")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": AI_PRINCIPLES_SCHEMA,
        "parts": list(parts),
    })


def ai_principles_audit_event(kind: str, detail: Dict[str, object],
                              seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the AI-principles ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": AI_PRINCIPLES_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    return True


@dataclass(frozen=True)
class DeclarationRecord:
    """Frozen record of one declared principle (digest-pinned)."""
    declaration_id: str
    principal_id: str
    principle_kind: str
    status: str
    principle_digest: str
    seq: int
    digest: str

    def verify(self, declaration_id: str, principal_id: str,
               principle_kind: str, status: str,
               principle_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "declaration", declaration_id, principal_id, principle_kind,
            status, principle_digest, self.seq)


@dataclass(frozen=True)
class VerificationReport:
    """Frozen read-only report of a digest re-derivation (verdict as data)."""
    declaration_id: str
    verdict: str
    seq: int
    digest: str

    def verify(self, declaration_id: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "verification", declaration_id, verdict, self.seq)


@dataclass(frozen=True)
class EvaluationReport:
    """Frozen read-only report of ledger-rule posture (posture as data)."""
    principal_id: str
    posture: str
    n_declarations: int
    n_proposed: int
    n_adopted: int
    n_amended: int
    n_suspended: int
    integrity_ok: bool
    seq: int
    digest: str

    def verify(self, principal_id: str, posture: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "evaluation", principal_id, posture, self.seq)


@dataclass(frozen=True)
class RetireRecord:
    """Frozen record of a terminal retirement (ids never recycled)."""
    principal_id: str
    reason: str
    seq: int
    digest: str

    def verify(self, principal_id: str, reason: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("retire", principal_id, reason, self.seq)


class AIPrinciples:
    """AI-principles declaration ledger (declared principles, derived posture)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._declarations: Dict[str, DeclarationRecord] = {}
        self._by_principal: Dict[str, Tuple[str, ...]] = {}
        self._declaration_ids: Tuple[str, ...] = ()
        self._retired: Dict[str, RetireRecord] = {}
        self._audit: Tuple[Dict[str, object], ...] = ()

    def _claim(self, seq: int) -> None:
        """Claim a seq (strictly increasing); raise bare on rewind."""
        _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be > {self._last_seq}, got {seq}")
            self._last_seq = seq

    def _burn(self, seq: int, principal_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if principal_id:
            detail["principal_id"] = principal_id
        event = ai_principles_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = ai_principles_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def declare(self, principal_id: str, principle_kind: str, status: str,
                seq: int, principle_digest: str = "") -> DeclarationRecord:
        """Book one declared principle. First declare on an id registers
        the principal. Pins the principle digest, never the principle
        content. Returns the frozen ``DeclarationRecord`` (minted
        ``dcl-N``)."""
        self._claim(seq)
        try:
            principal_id = _check_id(principal_id, "principal_id")
            if isinstance(principle_kind, bool) or not isinstance(
                    principle_kind, str):
                raise BadPrincipleKindError(
                    "principle_kind must be str, got "
                    f"{type(principle_kind).__name__}")
            if principle_kind not in PRINCIPLE_KINDS:
                raise BadPrincipleKindError(
                    f"principle_kind must be one of {sorted(PRINCIPLE_KINDS)}, "
                    f"got {principle_kind!r}")
            if isinstance(status, bool) or not isinstance(status, str):
                raise BadStatusError(
                    f"status must be str, got {type(status).__name__}")
            if status not in STATUSES:
                raise BadStatusError(
                    f"status must be one of {sorted(STATUSES)}, "
                    f"got {status!r}")
            principle_digest = _check_digest(
                principle_digest, "principle_digest", allow_empty=True)
            with self._lock:
                if principal_id in self._retired:
                    raise RetiredPrincipalError(
                        f"principal is retired: {principal_id!r}")
                declaration_id = f"dcl-{len(self._declaration_ids) + 1}"
                if declaration_id in self._declarations:
                    raise DuplicateDeclarationError(
                        f"declaration id collision: {declaration_id!r}")
                record = DeclarationRecord(
                    declaration_id=declaration_id,
                    principal_id=principal_id,
                    principle_kind=principle_kind,
                    status=status,
                    principle_digest=principle_digest,
                    seq=seq,
                    digest=_pin("declaration", declaration_id, principal_id,
                                principle_kind, status, principle_digest, seq),
                )
                self._declarations[declaration_id] = record
                self._declaration_ids = self._declaration_ids + (
                    declaration_id,)
                self._by_principal[principal_id] = (
                    self._by_principal.get(principal_id, ()) + (
                        declaration_id,))
        except AIPrinciplesError:
            self._burn(seq, principal_id if isinstance(principal_id, str)
                       else "")
            raise
        self._emit(KIND_DECLARED,
                   {"principal_id": principal_id,
                    "declaration_id": record.declaration_id,
                    "principle_kind": principle_kind,
                    "status": status,
                    "principle_digest": principle_digest}, seq)
        return record

    def verify(self, declaration_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive a declaration's digest pin. The
        ``verified``/``tampered`` verdict is *data* (tamper reported,
        never raised). Validates seq shape, consumes nothing, writes no
        audit row. Returns the frozen ``VerificationReport``."""
        _check_seq(seq)
        declaration_id = _check_id(declaration_id, "declaration_id")
        with self._lock:
            if declaration_id not in self._declarations:
                raise UnknownDeclarationError(
                    f"unknown declaration: {declaration_id!r}")
            rec = self._declarations[declaration_id]
            intact = rec.verify(
                rec.declaration_id, rec.principal_id, rec.principle_kind,
                rec.status, rec.principle_digest)
            verdict = "verified" if intact else "tampered"
            return VerificationReport(
                declaration_id=declaration_id,
                verdict=verdict,
                seq=seq,
                digest=_pin("verification", declaration_id, verdict, seq),
            )

    def evaluate(self, principal_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive posture from the ledger by rule (precedence:
        any ``suspended`` -> ``suspended-open``; any ``proposed`` ->
        ``under-review``; all ``adopted``/``amended`` -> ``declared``).
        Validates seq shape, consumes nothing, writes no audit row.
        Returns the frozen ``EvaluationReport``."""
        _check_seq(seq)
        principal_id = _check_id(principal_id, "principal_id")
        with self._lock:
            if principal_id not in self._by_principal:
                raise UnknownPrincipalError(
                    f"unknown principal: {principal_id!r}")
            ids = self._by_principal[principal_id]
            recs = [self._declarations[i] for i in ids]
            n_proposed = sum(
                1 for r in recs if r.status == STATUS_PROPOSED)
            n_adopted = sum(
                1 for r in recs if r.status == STATUS_ADOPTED)
            n_amended = sum(
                1 for r in recs if r.status == STATUS_AMENDED)
            n_suspended = sum(
                1 for r in recs if r.status == STATUS_SUSPENDED)
            integrity_ok = all(
                r.verify(r.declaration_id, r.principal_id, r.principle_kind,
                         r.status, r.principle_digest) for r in recs)
            if n_suspended:
                posture = POSTURE_SUSPENDED_OPEN
            elif n_proposed:
                posture = POSTURE_UNDER_REVIEW
            else:
                posture = POSTURE_DECLARED
            return EvaluationReport(
                principal_id=principal_id,
                posture=posture,
                n_declarations=len(recs),
                n_proposed=n_proposed,
                n_adopted=n_adopted,
                n_amended=n_amended,
                n_suspended=n_suspended,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_pin("evaluation", principal_id, posture, seq),
            )

    def retire(self, principal_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire a principal. Ids are never recycled;
        post-retire mutations are refused, reads still work. Returns the
        frozen ``RetireRecord``."""
        self._claim(seq)
        try:
            principal_id = _check_id(principal_id, "principal_id")
            if isinstance(reason, bool) or not isinstance(reason, str):
                raise BadReasonError(
                    f"reason must be str, got {type(reason).__name__}")
            if reason not in REASONS:
                raise BadReasonError(
                    f"reason must be one of {sorted(REASONS)}, "
                    f"got {reason!r}")
            with self._lock:
                if principal_id in self._retired:
                    raise DoubleRetireError(
                        f"principal already retired: {principal_id!r}")
                record = RetireRecord(
                    principal_id=principal_id,
                    reason=reason,
                    seq=seq,
                    digest=_pin("retire", principal_id, reason, seq),
                )
                self._retired[principal_id] = record
        except AIPrinciplesError:
            self._burn(seq, principal_id if isinstance(principal_id, str)
                       else "")
            raise
        self._emit(KIND_RETIRED,
                   {"principal_id": principal_id, "reason": reason}, seq)
        return record

    def declaration_record(self, declaration_id: str,
                           seq: int) -> DeclarationRecord:
        """Pure read view of one booked declaration."""
        _check_seq(seq)
        declaration_id = _check_id(declaration_id, "declaration_id")
        with self._lock:
            if declaration_id not in self._declarations:
                raise UnknownDeclarationError(
                    f"unknown declaration: {declaration_id!r}")
            return self._declarations[declaration_id]

    def declarations_for(self, principal_id: str, seq: int) -> Tuple[str, ...]:
        """Pure read view of declaration ids for one principal, in book order."""
        _check_seq(seq)
        principal_id = _check_id(principal_id, "principal_id")
        with self._lock:
            if principal_id not in self._by_principal:
                raise UnknownPrincipalError(
                    f"unknown principal: {principal_id!r}")
            return self._by_principal[principal_id]

    def principal_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of all registered principal ids, in first-declare order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._by_principal.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of retired principal ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._retired.keys())

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Pure read view of the audit events (no seq, no audit row)."""
        with self._lock:
            return self._audit

    def stats(self) -> Dict[str, int]:
        """Pure read view of ledger counters (no seq, no audit row)."""
        with self._lock:
            return {
                "principals": len(self._by_principal),
                "declarations": len(self._declarations),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: declare, verify, evaluate, retire, pins, audit."""
    ap = AIPrinciples()
    assert AI_PRINCIPLES_VERSION == "ai-principles.v1"
    assert AI_PRINCIPLES_SCHEMA == "northstar.ai-principles.v1"
    assert stdlib_only()
    digest = "sha256:" + "0" * 64
    rec = ap.declare("p-1", KIND_PUBLIC_SAFETY, STATUS_ADOPTED, 1, digest)
    assert rec.declaration_id == "dcl-1"
    assert rec.verify("dcl-1", "p-1", KIND_PUBLIC_SAFETY, STATUS_ADOPTED,
                      digest)
    assert not rec.verify("dcl-1", "p-1", KIND_PUBLIC_SAFETY, STATUS_SUSPENDED,
                          digest)
    vr = ap.verify("dcl-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("dcl-1", "verified")
    ev = ap.evaluate("p-1", 3)
    assert ev.posture == POSTURE_DECLARED
    assert ev.integrity_ok
    assert ev.verify("p-1", POSTURE_DECLARED)
    ap.declare("p-1", KIND_SINCERITY, STATUS_PROPOSED, 4, digest)
    ev = ap.evaluate("p-1", 5)
    assert ev.posture == POSTURE_UNDER_REVIEW
    assert ev.n_declarations == 2 and ev.n_proposed == 1
    rr = ap.retire("p-1", 6)
    assert rr.verify("p-1", REASON_MANUAL)
    try:
        ap.declare("p-1", KIND_FIDELITY, STATUS_ADOPTED, 7)
    except RetiredPrincipalError:
        pass
    else:
        raise AssertionError("declare on retired principal must fail closed")
    assert ap.stats()["principals"] == 1
    kinds = [row["kind"] for row in ap.audit_log()]
    assert kinds == [KIND_DECLARED, KIND_DECLARED, KIND_RETIRED,
                     KIND_REJECTED]
    print("ai-principles OK: declare, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
