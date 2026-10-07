"""ConstitutionalAI: principle-directed self-critique/revise bookkeeping.

Research note: Constitutional AI (Anthropic, Bai et al. 2022) trains a
helpful, honest, harmless assistant through a two-phase pipeline: (1)
supervised self-critique and revision against a pinned set of natural
language principles (the "constitution"), followed by (2) RL from AI
feedback. This module is the *ledger* layer for the first phase's
decision flow:

* **principle()** books one constitution principle under a pinned
  category (``helpfulness`` / ``honesty`` / ``harmlessness``). The
  principle statement is pinned by digest only — raw text never enters
  a record.
* **submit()** books a declared draft under self-review; the draft
  output is pinned by digest only.
* **critique()** books one self-critique of a draft *against one named
  principle*: a verdict drawn from the pinned vocabulary
  (``compliant`` / ``violation`` / ``needs-revision``) plus an optional
  issue digest. Critiques are host-declared data — the module cannot
  assess principle compliance itself.
* **revise()** books a declared revision of a draft. The revision must
  name a parent critique already booked against the *same* draft
  (cross-draft parentage is refused fail-closed), preserving the
  constitution-critique-revision chain.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs (failed mutations consume their seq and
book ``constitutional-ai.rejected``; rewinds raise bare), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* principles, drafts,
critiques, and revisions. A ``compliant`` verdict means "the host
declared the draft compliant with the named principle", never "the
draft is safe". Raw principle statements, draft text, critique issues,
and revision text never enter records and never cross the audit
boundary (digest pins only).
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
CONSTITUTIONAL_AI_VERSION = "constitutional-ai.v1"

#: Schema pin carried by records and audit events.
CONSTITUTIONAL_AI_SCHEMA = "northstar.constitutional-ai.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_PRINCIPLE = "constitutional-ai.principle-registered"
KIND_DRAFT = "constitutional-ai.draft-submitted"
KIND_CRITIQUE = "constitutional-ai.critique-booked"
KIND_REVISION = "constitutional-ai.revision-booked"
KIND_REJECTED = "constitutional-ai.rejected"
_KINDS = frozenset(
    {KIND_PRINCIPLE, KIND_DRAFT, KIND_CRITIQUE, KIND_REVISION, KIND_REJECTED}
)

#: Pinned principle categories (the three H's of the constitution).
CAT_HELPFULNESS = "helpfulness"
CAT_HONESTY = "honesty"
CAT_HARMLESSNESS = "harmlessness"
_CATEGORIES = frozenset({CAT_HELPFULNESS, CAT_HONESTY, CAT_HARMLESSNESS})

#: Pinned critique verdicts (booked as data, never raised).
VERDICT_COMPLIANT = "compliant"
VERDICT_VIOLATION = "violation"
VERDICT_NEEDS_REVISION = "needs-revision"
_VERDICTS = frozenset({VERDICT_COMPLIANT, VERDICT_VIOLATION, VERDICT_NEEDS_REVISION})

_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 128
_MAX_DIGEST_LEN = _MAX_ID_LEN + 64

#: Raw-text-ish keys that may never cross the audit boundary.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "text",
        "statement",
        "principle",
        "draft",
        "output",
        "critique",
        "issue",
        "revision",
        "revised",
        "rationale",
        "reasoning",
        "note",
        "notes",
        "payload",
        "value",
        "values",
        "raw",
        "body",
        "fields",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ConstitutionalAIError(Exception):
    """Base for all constitutional-ai errors."""


class BadPrincipleError(ConstitutionalAIError):
    """principle_id/category/digest failed validation."""


class DuplicatePrincipleError(ConstitutionalAIError):
    """principle_id already booked; ids are never recycled."""


class UnknownPrincipleError(ConstitutionalAIError):
    """principle_id names no principle this ledger ever saw."""


class BadCategoryError(ConstitutionalAIError):
    """A category is not in the pinned vocabulary."""


class BadDigestError(ConstitutionalAIError):
    """A digest is not a non-empty sha256:-prefixed str."""


class BadDraftError(ConstitutionalAIError):
    """draft_id failed validation."""


class DuplicateDraftError(ConstitutionalAIError):
    """draft_id already submitted; ids are never recycled."""


class UnknownDraftError(ConstitutionalAIError):
    """draft_id names no draft this ledger ever saw."""


class BadVerdictError(ConstitutionalAIError):
    """A verdict is not in the pinned vocabulary."""


class BadCritiqueError(ConstitutionalAIError):
    """Critique inputs failed validation."""


class UnknownCritiqueError(ConstitutionalAIError):
    """critique_id names no critique this ledger ever saw."""


class BadRevisionError(ConstitutionalAIError):
    """Revision inputs failed validation."""


class CrossDraftError(ConstitutionalAIError):
    """A revision's parent critique belongs to a different draft."""


class UnknownRevisionError(ConstitutionalAIError):
    """revision_id names no revision this ledger ever saw."""


class SeqOrderError(ConstitutionalAIError):
    """seq is not a strictly-increasing int."""


class AuditKindError(ConstitutionalAIError):
    """Audit kind unknown, or banned detail key used."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadPrincipleError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise BadPrincipleError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadPrincipleError(f"{what} too long (>{_MAX_ID_LEN} chars)")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


def _check_digest(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{what} must be a str, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) <= len(_DIGEST_PREFIX):
        raise BadDigestError(f"{what} must be a non-empty sha256:-prefixed digest")
    if len(value) > _MAX_DIGEST_LEN:
        raise BadDigestError(f"{what} too long")
    return value


def _check_category(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadCategoryError(f"category must be a str, got {type(value).__name__}")
    if value not in _CATEGORIES:
        raise BadCategoryError(f"category {value!r} not in pinned vocabulary")
    return value


def _check_verdict(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadVerdictError(f"verdict must be a str, got {type(value).__name__}")
    if value not in _VERDICTS:
        raise BadVerdictError(f"verdict {value!r} not in pinned vocabulary")
    return value


# ---------------------------------------------------------------------------
# Canonical JSON / digest pins
# ---------------------------------------------------------------------------


def _canonical(value: Any) -> str:
    """Deterministic text form for digest pinning (JCS when available)."""
    if _cj is not None and hasattr(_cj, "jcs_dumps"):
        return str(_cj.jcs_dumps(value))  # type: ignore[attr-defined]
    import json

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _digest_pin(parts: Tuple[Any, ...], tag: str) -> str:
    blob = _canonical({"tag": tag, "parts": list(parts)}).encode("utf-8")
    return _DIGEST_PREFIX + hashlib.sha256(blob).hexdigest()


def _pin_record(record: Any, tag: str) -> str:
    return _digest_pin((record.as_dict(),), tag)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrincipleRecord:
    principle_id: str
    category: str
    statement_digest: str
    seq: int
    digest: str
    schema: str = CONSTITUTIONAL_AI_SCHEMA
    version: str = CONSTITUTIONAL_AI_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "principle_id": self.principle_id,
            "category": self.category,
            "statement_digest": self.statement_digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _pin_record(self, "principle")


@dataclass(frozen=True)
class DraftRecord:
    draft_id: str
    output_digest: str
    seq: int
    digest: str
    schema: str = CONSTITUTIONAL_AI_SCHEMA
    version: str = CONSTITUTIONAL_AI_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "draft_id": self.draft_id,
            "output_digest": self.output_digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _pin_record(self, "draft")


@dataclass(frozen=True)
class CritiqueRecord:
    critique_id: str
    draft_id: str
    principle_id: str
    verdict: str
    issue_digest: str
    seq: int
    digest: str
    schema: str = CONSTITUTIONAL_AI_SCHEMA
    version: str = CONSTITUTIONAL_AI_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "critique_id": self.critique_id,
            "draft_id": self.draft_id,
            "principle_id": self.principle_id,
            "verdict": self.verdict,
            "issue_digest": self.issue_digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _pin_record(self, "critique")


@dataclass(frozen=True)
class RevisionRecord:
    revision_id: str
    draft_id: str
    parent_critique_id: str
    revision_digest: str
    seq: int
    digest: str
    schema: str = CONSTITUTIONAL_AI_SCHEMA
    version: str = CONSTITUTIONAL_AI_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "revision_id": self.revision_id,
            "draft_id": self.draft_id,
            "parent_critique_id": self.parent_critique_id,
            "revision_digest": self.revision_digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _pin_record(self, "revision")


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def constitutional_ai_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event; fail-closed on kind/leaks."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind {kind!r}")
    leaked = _BANNED_AUDIT_KEYS.intersection(detail.keys())
    if leaked:
        raise AuditKindError(f"banned audit detail keys: {sorted(leaked)}")
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "module": "constitutional-ai",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# ConstitutionalAI ledger
# ---------------------------------------------------------------------------


class ConstitutionalAI:
    """Constitutional-AI phase-1 ledger: principle, submit, critique, revise."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # principle_id -> PrincipleRecord
        self._principles: Dict[str, PrincipleRecord] = {}
        # draft_id -> DraftRecord
        self._drafts: Dict[str, DraftRecord] = {}
        # critique_id -> CritiqueRecord (ordered)
        self._critiques: Dict[str, CritiqueRecord] = {}
        # revision_id -> RevisionRecord (ordered)
        self._revisions: Dict[str, RevisionRecord] = {}
        self._audit_events: List[Dict[str, Any]] = []
        self._critique_counter = 0
        self._revision_counter = 0

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(
            constitutional_ai_audit_event(audit_kind, seq, **detail)
        )

    def _fail(self, seq: int, exc: ConstitutionalAIError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def principle(
        self, principle_id: str, category: str, statement_digest: str, seq: int
    ) -> PrincipleRecord:
        """Book one constitution principle (statement pinned by digest only)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                principle_id = _check_id(principle_id, "principle_id")
                category = _check_category(category)
                statement_digest = _check_digest(statement_digest, "statement_digest")
            except ConstitutionalAIError as exc:
                self._fail(seq, exc, principle_id=str(principle_id))
            if principle_id in self._principles:
                self._fail(
                    seq,
                    DuplicatePrincipleError(
                        f"principle already booked: {principle_id!r}"
                    ),
                    principle_id=principle_id,
                )
            record = PrincipleRecord(
                principle_id=principle_id,
                category=category,
                statement_digest=statement_digest,
                seq=seq,
                digest="",
            )
            record = PrincipleRecord(
                principle_id=principle_id,
                category=category,
                statement_digest=statement_digest,
                seq=seq,
                digest=_pin_record(record, "principle"),
            )
            self._principles[principle_id] = record
            self._emit(
                KIND_PRINCIPLE,
                seq,
                principle_id=principle_id,
                category=category,
                statement_digest=statement_digest,
            )
            return record

    def submit(self, draft_id: str, output_digest: str, seq: int) -> DraftRecord:
        """Book a declared draft under self-review (output pinned by digest)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                draft_id = _check_id(draft_id, "draft_id")
                output_digest = _check_digest(output_digest, "output_digest")
            except ConstitutionalAIError as exc:
                self._fail(seq, exc, draft_id=str(draft_id))
            if draft_id in self._drafts:
                self._fail(
                    seq,
                    DuplicateDraftError(f"draft already submitted: {draft_id!r}"),
                    draft_id=draft_id,
                )
            record = DraftRecord(
                draft_id=draft_id, output_digest=output_digest, seq=seq, digest=""
            )
            record = DraftRecord(
                draft_id=draft_id,
                output_digest=output_digest,
                seq=seq,
                digest=_pin_record(record, "draft"),
            )
            self._drafts[draft_id] = record
            self._emit(
                KIND_DRAFT, seq, draft_id=draft_id, output_digest=output_digest
            )
            return record

    def critique(
        self,
        draft_id: str,
        principle_id: str,
        seq: int,
        verdict: str = VERDICT_NEEDS_REVISION,
        issue_digest: str = "",
    ) -> CritiqueRecord:
        """Book one principle-directed self-critique of a draft.

        ``verdict`` is pinned vocabulary. ``issue_digest`` may be empty
        (no pinned issue) or a ``sha256:`` pin — raw issue text never
        enters a record.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                if isinstance(draft_id, bool) or not isinstance(draft_id, str):
                    raise BadDraftError("draft_id must be a str")
                if isinstance(principle_id, bool) or not isinstance(
                    principle_id, str
                ):
                    raise BadPrincipleError("principle_id must be a str")
                verdict = _check_verdict(verdict)
                issue_digest = (
                    _check_digest(issue_digest, "issue_digest")
                    if issue_digest
                    else ""
                )
            except ConstitutionalAIError as exc:
                self._fail(
                    seq, exc, draft_id=str(draft_id), principle_id=str(principle_id)
                )
            if draft_id not in self._drafts:
                self._fail(
                    seq,
                    UnknownDraftError(f"unknown draft: {draft_id!r}"),
                    draft_id=draft_id,
                    principle_id=principle_id,
                )
            if principle_id not in self._principles:
                self._fail(
                    seq,
                    UnknownPrincipleError(f"unknown principle: {principle_id!r}"),
                    draft_id=draft_id,
                    principle_id=principle_id,
                )
            self._critique_counter += 1
            critique_id = f"crit-{self._critique_counter}"
            record = CritiqueRecord(
                critique_id=critique_id,
                draft_id=draft_id,
                principle_id=principle_id,
                verdict=verdict,
                issue_digest=issue_digest,
                seq=seq,
                digest="",
            )
            record = CritiqueRecord(
                critique_id=critique_id,
                draft_id=draft_id,
                principle_id=principle_id,
                verdict=verdict,
                issue_digest=issue_digest,
                seq=seq,
                digest=_pin_record(record, "critique"),
            )
            self._critiques[critique_id] = record
            self._emit(
                KIND_CRITIQUE,
                seq,
                critique_id=critique_id,
                draft_id=draft_id,
                principle_id=principle_id,
                verdict=verdict,
                has_issue=bool(issue_digest),
            )
            return record

    def revise(
        self,
        draft_id: str,
        seq: int,
        revision_digest: str,
        parent_critique_id: str = "",
    ) -> RevisionRecord:
        """Book a declared revision of a draft.

        ``parent_critique_id`` must name a critique already booked against
        the *same* draft — cross-draft parentage is refused fail-closed.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                if isinstance(draft_id, bool) or not isinstance(draft_id, str):
                    raise BadDraftError("draft_id must be a str")
                revision_digest = _check_digest(revision_digest, "revision_digest")
                if isinstance(parent_critique_id, bool) or not isinstance(
                    parent_critique_id, str
                ):
                    raise BadCritiqueError("parent_critique_id must be a str")
            except ConstitutionalAIError as exc:
                self._fail(seq, exc, draft_id=str(draft_id))
            if draft_id not in self._drafts:
                self._fail(
                    seq,
                    UnknownDraftError(f"unknown draft: {draft_id!r}"),
                    draft_id=draft_id,
                )
            if not parent_critique_id:
                self._fail(
                    seq,
                    BadCritiqueError("parent_critique_id must not be empty"),
                    draft_id=draft_id,
                )
            parent = self._critiques.get(parent_critique_id)
            if parent is None:
                self._fail(
                    seq,
                    UnknownCritiqueError(
                        f"unknown critique: {parent_critique_id!r}"
                    ),
                    draft_id=draft_id,
                    parent_critique_id=parent_critique_id,
                )
            assert parent is not None
            if parent.draft_id != draft_id:
                self._fail(
                    seq,
                    CrossDraftError(
                        f"critique {parent_critique_id!r} belongs to draft "
                        f"{parent.draft_id!r}, not {draft_id!r}"
                    ),
                    draft_id=draft_id,
                    parent_critique_id=parent_critique_id,
                )
            self._revision_counter += 1
            revision_id = f"rev-{self._revision_counter}"
            record = RevisionRecord(
                revision_id=revision_id,
                draft_id=draft_id,
                parent_critique_id=parent_critique_id,
                revision_digest=revision_digest,
                seq=seq,
                digest="",
            )
            record = RevisionRecord(
                revision_id=revision_id,
                draft_id=draft_id,
                parent_critique_id=parent_critique_id,
                revision_digest=revision_digest,
                seq=seq,
                digest=_pin_record(record, "revision"),
            )
            self._revisions[revision_id] = record
            self._emit(
                KIND_REVISION,
                seq,
                revision_id=revision_id,
                draft_id=draft_id,
                parent_critique_id=parent_critique_id,
                revision_digest=revision_digest,
            )
            return record

    # -- pure-read views ----------------------------------------------------

    def principle_record(self, principle_id: str, seq: int) -> PrincipleRecord:
        """Pure read view of one booked principle."""
        with self._lock:
            _check_seq(seq)
            if principle_id not in self._principles:
                raise UnknownPrincipleError(f"unknown principle: {principle_id!r}")
            return self._principles[principle_id]

    def principle_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted booked principle ids; pure read."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._principles))

    def draft_record(self, draft_id: str, seq: int) -> DraftRecord:
        """Pure read view of one submitted draft."""
        with self._lock:
            _check_seq(seq)
            if draft_id not in self._drafts:
                raise UnknownDraftError(f"unknown draft: {draft_id!r}")
            return self._drafts[draft_id]

    def critique_record(self, critique_id: str, seq: int) -> CritiqueRecord:
        """Pure read view of one booked critique."""
        with self._lock:
            _check_seq(seq)
            if critique_id not in self._critiques:
                raise UnknownCritiqueError(f"unknown critique: {critique_id!r}")
            return self._critiques[critique_id]

    def critiques_for(self, draft_id: str, seq: int) -> Tuple[str, ...]:
        """Critique ids booked against a draft, in booking order; pure read."""
        with self._lock:
            _check_seq(seq)
            if draft_id not in self._drafts:
                raise UnknownDraftError(f"unknown draft: {draft_id!r}")
            return tuple(
                c.critique_id
                for c in self._critiques.values()
                if c.draft_id == draft_id
            )

    def revision_record(self, revision_id: str, seq: int) -> RevisionRecord:
        """Pure read view of one booked revision."""
        with self._lock:
            _check_seq(seq)
            if revision_id not in self._revisions:
                raise UnknownRevisionError(f"unknown revision: {revision_id!r}")
            return self._revisions[revision_id]

    def revisions_for(self, draft_id: str, seq: int) -> Tuple[str, ...]:
        """Revision ids booked against a draft, in booking order; pure read."""
        with self._lock:
            _check_seq(seq)
            if draft_id not in self._drafts:
                raise UnknownDraftError(f"unknown draft: {draft_id!r}")
            return tuple(
                r.revision_id
                for r in self._revisions.values()
                if r.draft_id == draft_id
            )

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counts; pure read."""
        with self._lock:
            _check_seq(seq)
            return {
                "principles": len(self._principles),
                "drafts": len(self._drafts),
                "critiques": len(self._critiques),
                "revisions": len(self._revisions),
                "audit_events": len(self._audit_events),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Copy of audit events; pure read."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit_events)


def main() -> None:
    ledger = ConstitutionalAI()
    seq = 0

    def nxt() -> int:
        nonlocal seq
        seq += 1
        return seq

    pin = lambda parts: _digest_pin(parts, "test")  # noqa: E731

    p1 = ledger.principle("p-honesty", CAT_HONESTY, pin(("statement-1",)), nxt())
    assert p1.verify()
    p2 = ledger.principle("p-harm", CAT_HARMLESSNESS, pin(("statement-2",)), nxt())
    assert p2.verify() and p2.category == CAT_HARMLESSNESS

    d = ledger.submit("draft-1", pin(("output-1",)), nxt())
    assert d.verify()

    c1 = ledger.critique("draft-1", "p-honesty", nxt(), verdict=VERDICT_VIOLATION)
    assert c1.verify()
    c2 = ledger.critique(
        "draft-1",
        "p-harm",
        nxt(),
        verdict=VERDICT_COMPLIANT,
        issue_digest=pin(("issue-1",)),
    )
    assert c2.verify()

    r1 = ledger.revise("draft-1", nxt(), pin(("revision-1",)), c1.critique_id)
    assert r1.verify()

    # refusal spot-checks
    try:
        ledger.principle("p-honesty", CAT_HONESTY, pin(("x",)), nxt())
    except DuplicatePrincipleError:
        pass
    try:
        ledger.principle("p-bad", "kindness", pin(("x",)), nxt())
    except BadCategoryError:
        pass
    try:
        ledger.revise("draft-1", nxt(), pin(("y",)), "crit-999")
    except UnknownCritiqueError:
        pass
    ledger.submit("draft-2", pin(("output-2",)), nxt())
    try:
        ledger.revise("draft-2", nxt(), pin(("z",)), c1.critique_id)
    except CrossDraftError:
        pass
    print("constitutional-ai OK: principle, submit, critique, revise, fail-closed, audit")


if __name__ == "__main__":
    main()
