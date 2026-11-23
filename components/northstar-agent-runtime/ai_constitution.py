"""AI constitution (declare/verify/evaluate) interface, simulated.

Research motivation: Constitutional AI (Bai et al., 2022) and AI
charters operationalize alignment as a *declared* body of governing
articles: a lab declares principles, the ledger pins them, and derived
reports summarize constitutional posture *from the ledger* -- the
report never independently judges whether a constitution is good.

This module is the *constitution-level* decision ledger of that shape:

- ``AIConstitution.declare(constitution_id, seq,
  article_kind="public-safety", standing="adopted",
  principle_digest="")`` -- book one declared constitutional article
  over the pinned 8-article vocabulary x the pinned 4-standing
  vocabulary. The article's text is pinned by ``sha256:`` digest only;
  raw material never enters a record. First declare on an id registers
  the constitution. Returns the frozen ``DeclarationRecord`` (minted
  ``dec-N``). Declarations are repeatable (amendment chains are the
  normal lifecycle of a constitution).
- ``AIConstitution.verify(declaration_id, seq)`` -- **pure read** (seq
  shape validated, never consumed, no audit row). Re-derives the
  digest pin; the ``verified``/``tampered`` verdict is *data*, never
  proof the article is sound or the constitution is followed.
- ``AIConstitution.evaluate(constitution_id, seq)`` -- **pure read**.
  Derives posture as data by ledger rule: ``undeclared`` (unknown
  constitution raises; zero declarations is impossible for a
  registered constitution) -> ``repeal-open`` (any ``repealed``) ->
  ``amending`` (any ``amended``) -> ``proposed`` (any ``proposed``) ->
  ``adopted`` (all ``adopted``), plus declaration tallies and
  ``integrity_ok`` as data.
- ``AIConstitution.retire(constitution_id, seq, reason="manual")`` --
  terminal. Ids are never recycled; post-retire mutations are refused,
  reads still work.
- Pure-read views (``declaration_record`` / ``declarations_for`` /
  ``constitution_ids`` / ``retired_ids`` / ``stats`` / ``audit_log``) --
  seq shape validated, never consumed, no audit rows.
- ``ai_constitution_audit_event(kind, ...)`` -- ``audit.ndjson/1`` rows
  (``declared`` / ``retired`` / ``rejected``); caller-supplied seqs
  only. Raw article content never crosses the audit boundary -- audit
  rows carry ids, pinned article/standing labels, digests, and counts
  only.

Distinct layer: ``constitutional_ai.py`` owns the principle *lifecycle*
(declare a principle, submit a draft, critique against a principle,
revise). ``critique_model.py`` owns generic critic declarations and
``self_critique.py`` owns model-internal self-review. This module owns
the *constitution-level* governance ledger none of them cover --
declared articles aggregated into constitutions, amendment/repeal
bookkeeping over a pinned standing vocabulary, and ledger-rule
constitutional posture.

Fail-closed edges (fail loudly, never guess):

- ``constitution_id`` / ``declaration_id`` must be non-empty str,
  <= 256 chars, no whitespace.
- ``article_kind`` must be in the pinned 8-article vocabulary;
  ``standing`` must be in the pinned 4-standing vocabulary.
- ``principle_digest`` must be ``sha256:<64hex>`` when supplied (may
  be empty).
- ``verify`` / ``evaluate`` on unknown ids raise; duplicate ids never
  occur (ids are minted ``dec-N``).
- ``declare`` on a retired constitution raises ``RetiredConstitutionError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* constitutional articles reported by the
  host. A booked ``adopted`` standing means the host declared one --
  the module adopted nothing, judged no article, and proves nothing
  about any real constitution's soundness or compliance.
- Digest pins prove ledger integrity and ordering, never the truth of
  any declaration or the alignment of any system governed by one.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if constitutional state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Dict, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: object) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: object) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
AI_CONSTITUTION_VERSION = "ai-constitution.v1"

#: Schema pin carried by records and audit events.
AI_CONSTITUTION_SCHEMA = "northstar.ai-constitution.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_DECLARED = "declared"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_DECLARED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"content", "text", "payload", "raw", "evidence", "finding",
     "justification", "analysis", "report", "assessment_text",
     "rationale", "principle_text", "article_text", "charter",
     "manuscript", "data", "record", "trace", "transcript",
     "weights", "policy", "model_output", "judgment", "note",
     "comment", "preamble", "clause"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned constitutional-article vocabulary (CAI / charter lineage shaped).
ARTICLE_PUBLIC_SAFETY = "public-safety"
ARTICLE_LIBERTY_PRESERVATION = "liberty-preservation"
ARTICLE_SINCERITY = "sincerity"
ARTICLE_LEGAL_COMPLIANCE = "legal-compliance"
ARTICLE_FIDUCIARY_DUTIES = "fiduciary-duties"
ARTICLE_VIRTUES = "virtues"
ARTICLE_META_GUIDELINES = "meta-guidelines"
ARTICLE_OPERATIONALIZATION = "operationalization"
ARTICLE_KINDS = (
    ARTICLE_PUBLIC_SAFETY,
    ARTICLE_LIBERTY_PRESERVATION,
    ARTICLE_SINCERITY,
    ARTICLE_LEGAL_COMPLIANCE,
    ARTICLE_FIDUCIARY_DUTIES,
    ARTICLE_VIRTUES,
    ARTICLE_META_GUIDELINES,
    ARTICLE_OPERATIONALIZATION,
)

#: Pinned declaration-standing vocabulary. Standing is host-declared data.
STANDING_PROPOSED = "proposed"
STANDING_ADOPTED = "adopted"
STANDING_AMENDED = "amended"
STANDING_REPEALED = "repealed"
STANDINGS = (
    STANDING_PROPOSED,
    STANDING_ADOPTED,
    STANDING_AMENDED,
    STANDING_REPEALED,
)

#: Pinned derived postures (ledger rule, precedence documented in evaluate).
POSTURE_UNDECLARED = "undeclared"
POSTURE_REPEAL_OPEN = "repeal-open"
POSTURE_AMENDING = "amending"
POSTURE_PROPOSED = "proposed"
POSTURE_ADOPTED = "adopted"
POSTURES = (
    POSTURE_UNDECLARED,
    POSTURE_REPEAL_OPEN,
    POSTURE_AMENDING,
    POSTURE_PROPOSED,
    POSTURE_ADOPTED,
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


class AIConstitutionError(Exception):
    """Base error for the AI-constitution ledger (programming errors)."""


class BadIdError(AIConstitutionError):
    """Raised when a constitution/declaration id is malformed."""


class DuplicateDeclarationError(AIConstitutionError):
    """Raised when a minted declaration id somehow collides (never)."""


class UnknownConstitutionError(AIConstitutionError):
    """Raised when a constitution id names no declared constitution."""


class UnknownDeclarationError(AIConstitutionError):
    """Raised when a declaration id names no booked declaration."""


class RetiredConstitutionError(AIConstitutionError):
    """Raised when mutating a retired constitution."""


class DoubleRetireError(AIConstitutionError):
    """Raised when retiring an already-retired constitution."""


class BadArticleKindError(AIConstitutionError):
    """Raised when an article kind is not in the pinned vocabulary."""


class BadStandingError(AIConstitutionError):
    """Raised when a standing is not in the pinned vocabulary."""


class BadDigestError(AIConstitutionError):
    """Raised when a principle digest is not a sha256: pin."""


class BadReasonError(AIConstitutionError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class SeqOrderError(AIConstitutionError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(AIConstitutionError):
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
        "domain": AI_CONSTITUTION_SCHEMA,
        "parts": list(parts),
    })


def ai_constitution_audit_event(kind: str, detail: Dict[str, object],
                                seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the AI-constitution ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": AI_CONSTITUTION_VERSION,
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
    """Frozen record of one declared constitutional article (digest-pinned)."""
    declaration_id: str
    constitution_id: str
    article_kind: str
    standing: str
    principle_digest: str
    seq: int
    digest: str

    def verify(self, declaration_id: str, constitution_id: str,
               article_kind: str, standing: str,
               principle_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "declaration", declaration_id, constitution_id, article_kind,
            standing, principle_digest, self.seq)


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
    constitution_id: str
    posture: str
    n_declarations: int
    n_adopted: int
    n_amended: int
    n_repealed: int
    n_proposed: int
    integrity_ok: bool
    seq: int
    digest: str

    def verify(self, constitution_id: str, posture: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "evaluation", constitution_id, posture, self.seq)


@dataclass(frozen=True)
class RetireRecord:
    """Frozen record of a terminal retirement (ids never recycled)."""
    constitution_id: str
    reason: str
    seq: int
    digest: str

    def verify(self, constitution_id: str, reason: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("retire", constitution_id, reason, self.seq)


class AIConstitution:
    """AI-constitution declaration ledger (declared articles, derived posture)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._declarations: Dict[str, DeclarationRecord] = {}
        self._by_constitution: Dict[str, Tuple[str, ...]] = {}
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

    def _burn(self, seq: int, constitution_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if constitution_id:
            detail["constitution_id"] = constitution_id
        event = ai_constitution_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = ai_constitution_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def declare(self, constitution_id: str, seq: int,
                article_kind: str = ARTICLE_PUBLIC_SAFETY,
                standing: str = STANDING_ADOPTED,
                principle_digest: str = "") -> DeclarationRecord:
        """Book one declared constitutional article. First declare on an
        id registers the constitution. Pins the principle digest, never
        the article text. Returns the frozen ``DeclarationRecord``
        (minted ``dec-N``). Repeatable: amendment chains are the normal
        constitution lifecycle."""
        self._claim(seq)
        try:
            constitution_id = _check_id(constitution_id, "constitution_id")
            if isinstance(article_kind, bool) or not isinstance(article_kind,
                                                                  str):
                raise BadArticleKindError(
                    "article_kind must be str, got "
                    f"{type(article_kind).__name__}")
            if article_kind not in ARTICLE_KINDS:
                raise BadArticleKindError(
                    f"article_kind must be one of {sorted(ARTICLE_KINDS)}, "
                    f"got {article_kind!r}")
            if isinstance(standing, bool) or not isinstance(standing, str):
                raise BadStandingError(
                    f"standing must be str, got {type(standing).__name__}")
            if standing not in STANDINGS:
                raise BadStandingError(
                    f"standing must be one of {sorted(STANDINGS)}, "
                    f"got {standing!r}")
            principle_digest = _check_digest(
                principle_digest, "principle_digest", allow_empty=True)
            with self._lock:
                if constitution_id in self._retired:
                    raise RetiredConstitutionError(
                        f"constitution is retired: {constitution_id!r}")
                declaration_id = f"dec-{len(self._declaration_ids) + 1}"
                if declaration_id in self._declarations:
                    raise DuplicateDeclarationError(
                        f"declaration id collision: {declaration_id!r}")
                record = DeclarationRecord(
                    declaration_id=declaration_id,
                    constitution_id=constitution_id,
                    article_kind=article_kind,
                    standing=standing,
                    principle_digest=principle_digest,
                    seq=seq,
                    digest=_pin("declaration", declaration_id,
                                constitution_id, article_kind, standing,
                                principle_digest, seq),
                )
                self._declarations[declaration_id] = record
                self._declaration_ids = (
                    self._declaration_ids + (declaration_id,))
                self._by_constitution[constitution_id] = (
                    self._by_constitution.get(constitution_id, ())
                    + (declaration_id,))
        except AIConstitutionError:
            self._burn(seq,
                       constitution_id if isinstance(constitution_id, str)
                       else "")
            raise
        self._emit(KIND_DECLARED,
                   {"constitution_id": constitution_id,
                    "declaration_id": record.declaration_id,
                    "article_kind": article_kind,
                    "standing": standing,
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
                rec.declaration_id, rec.constitution_id, rec.article_kind,
                rec.standing, rec.principle_digest)
            verdict = "verified" if intact else "tampered"
            return VerificationReport(
                declaration_id=declaration_id,
                verdict=verdict,
                seq=seq,
                digest=_pin("verification", declaration_id, verdict, seq),
            )

    def evaluate(self, constitution_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive posture from the ledger by rule (precedence:
        any ``repealed`` -> ``repeal-open``; any ``amended`` ->
        ``amending``; any ``proposed`` -> ``proposed``; all ``adopted``
        -> ``adopted``). Validates seq shape, consumes nothing, writes
        no audit row. Returns the frozen ``EvaluationReport``."""
        _check_seq(seq)
        constitution_id = _check_id(constitution_id, "constitution_id")
        with self._lock:
            if constitution_id not in self._by_constitution:
                raise UnknownConstitutionError(
                    f"unknown constitution: {constitution_id!r}")
            ids = self._by_constitution[constitution_id]
            recs = [self._declarations[i] for i in ids]
            n_adopted = sum(1 for r in recs if r.standing == STANDING_ADOPTED)
            n_amended = sum(1 for r in recs if r.standing == STANDING_AMENDED)
            n_repealed = sum(1 for r in recs if r.standing == STANDING_REPEALED)
            n_proposed = sum(1 for r in recs if r.standing == STANDING_PROPOSED)
            integrity_ok = all(
                r.verify(r.declaration_id, r.constitution_id, r.article_kind,
                         r.standing, r.principle_digest) for r in recs)
            if n_repealed:
                posture = POSTURE_REPEAL_OPEN
            elif n_amended:
                posture = POSTURE_AMENDING
            elif n_proposed:
                posture = POSTURE_PROPOSED
            else:
                posture = POSTURE_ADOPTED
            return EvaluationReport(
                constitution_id=constitution_id,
                posture=posture,
                n_declarations=len(recs),
                n_adopted=n_adopted,
                n_amended=n_amended,
                n_repealed=n_repealed,
                n_proposed=n_proposed,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_pin("evaluation", constitution_id, posture, seq),
            )

    def retire(self, constitution_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire a constitution. Ids are never recycled;
        post-retire mutations are refused, reads still work. Returns the
        frozen ``RetireRecord``."""
        self._claim(seq)
        try:
            constitution_id = _check_id(constitution_id, "constitution_id")
            if isinstance(reason, bool) or not isinstance(reason, str):
                raise BadReasonError(
                    f"reason must be str, got {type(reason).__name__}")
            if reason not in REASONS:
                raise BadReasonError(
                    f"reason must be one of {sorted(REASONS)}, "
                    f"got {reason!r}")
            with self._lock:
                if constitution_id in self._retired:
                    raise DoubleRetireError(
                        f"constitution already retired: {constitution_id!r}")
                record = RetireRecord(
                    constitution_id=constitution_id,
                    reason=reason,
                    seq=seq,
                    digest=_pin("retire", constitution_id, reason, seq),
                )
                self._retired[constitution_id] = record
        except AIConstitutionError:
            self._burn(seq,
                       constitution_id if isinstance(constitution_id, str)
                       else "")
            raise
        self._emit(KIND_RETIRED,
                   {"constitution_id": constitution_id, "reason": reason},
                   seq)
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

    def declarations_for(self, constitution_id: str,
                         seq: int) -> Tuple[str, ...]:
        """Pure read view of declaration ids for one constitution, in book order."""
        _check_seq(seq)
        constitution_id = _check_id(constitution_id, "constitution_id")
        with self._lock:
            if constitution_id not in self._by_constitution:
                raise UnknownConstitutionError(
                    f"unknown constitution: {constitution_id!r}")
            return self._by_constitution[constitution_id]

    def constitution_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of all registered constitution ids, in first-declare order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._by_constitution.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of retired constitution ids."""
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
                "constitutions": len(self._by_constitution),
                "declarations": len(self._declarations),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: declare, verify, evaluate, retire, pins, audit."""
    ac = AIConstitution()
    assert AI_CONSTITUTION_VERSION == "ai-constitution.v1"
    assert AI_CONSTITUTION_SCHEMA == "northstar.ai-constitution.v1"
    assert stdlib_only()
    digest = "sha256:" + "0" * 64
    rec = ac.declare("cai-1", 1, ARTICLE_PUBLIC_SAFETY, STANDING_ADOPTED,
                     digest)
    assert rec.declaration_id == "dec-1"
    assert rec.verify("dec-1", "cai-1", ARTICLE_PUBLIC_SAFETY,
                      STANDING_ADOPTED, digest)
    assert not rec.verify("dec-1", "cai-1", ARTICLE_PUBLIC_SAFETY,
                          STANDING_REPEALED, digest)
    vr = ac.verify("dec-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("dec-1", "verified")
    ev = ac.evaluate("cai-1", 3)
    assert ev.posture == POSTURE_ADOPTED
    assert ev.integrity_ok
    assert ev.verify("cai-1", POSTURE_ADOPTED)
    ac.declare("cai-1", 4, ARTICLE_SINCERITY, STANDING_AMENDED, digest)
    ev = ac.evaluate("cai-1", 5)
    assert ev.posture == POSTURE_AMENDING
    assert ev.n_declarations == 2 and ev.n_amended == 1
    rr = ac.retire("cai-1", 6)
    assert rr.verify("cai-1", REASON_MANUAL)
    try:
        ac.declare("cai-1", 7, ARTICLE_VIRTUES, STANDING_ADOPTED)
    except RetiredConstitutionError:
        pass
    else:
        raise AssertionError("declare on retired constitution must fail closed")
    assert ac.stats()["constitutions"] == 1
    kinds = [row["kind"] for row in ac.audit_log()]
    assert kinds == [KIND_DECLARED, KIND_DECLARED, KIND_RETIRED,
                     KIND_REJECTED]
    print("ai-constitution OK: declare, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
