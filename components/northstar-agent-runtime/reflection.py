"""Reflection: self-critique / revise / score bookkeeping for agent outputs.

Research note: Reflexion (Shinn et al., 2023) showed that an agent can
improve across trials by booking *verbal* self-critiques of its own
outputs and feeding them back as episodic memory, and self-refine
loops ask a model to critique-then-revise its own answer. This module
is the *ledger* layer for that practice:

* **submit()** books a declared output under self-review. The raw
  output bytes never enter a record; the caller pins them by digest
  only.
* **critique()** books one self-critique against a pinned issue
  vocabulary (hallucination, factual-error, policy-violation,
  incomplete, off-task, formatting, reasoning-gap) with a verdict
  (accept / needs-revision / reject). The consistency rule is
  enforced fail-closed: empty issues require ``accept``; non-empty
  issues forbid ``accept``.
* **revise()** books a declared revision of the draft. The parent
  critique must name a critique already booked for that same draft —
  the Reflexion-style episodic link. Revision ids are minted
  (``rev-N``); drafts may have many revisions, forming a declared
  revision chain.
* **score()** books host-reported quality components
  (correctness/completeness/style, ints 0-100) and a deterministically
  derived composite (exact ``num/den`` rational, no floats) plus a
  derived verdict (strong/acceptable/weak).

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs, no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json`` try/except
fallback, ``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* drafts, critiques,
revisions, and scores; it cannot prove a critique is correct, that a
revision is an improvement, or that a booked score measures real
quality. Raw output text, feedback text, and revision contents never
enter records and never cross the audit boundary (digest pins only).
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
REFLECTION_VERSION = "reflection.v1"

#: Schema pin carried by records and audit events.
REFLECTION_SCHEMA = "northstar.reflection.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_SUBMITTED = "reflection.draft-submitted"
KIND_CRITIQUE = "reflection.critique-booked"
KIND_REVISION = "reflection.revision-booked"
KIND_SCORE = "reflection.score-booked"
KIND_REJECTED = "reflection.rejected"
_KINDS = frozenset({KIND_SUBMITTED, KIND_CRITIQUE, KIND_REVISION, KIND_SCORE, KIND_REJECTED})

#: Pinned issue vocabulary for self-critiques.
ISSUE_HALLUCINATION = "hallucination"
ISSUE_FACTUAL_ERROR = "factual-error"
ISSUE_POLICY_VIOLATION = "policy-violation"
ISSUE_INCOMPLETE = "incomplete"
ISSUE_OFF_TASK = "off-task"
ISSUE_FORMATTING = "formatting"
ISSUE_REASONING_GAP = "reasoning-gap"
_ISSUES = frozenset(
    {
        ISSUE_HALLUCINATION,
        ISSUE_FACTUAL_ERROR,
        ISSUE_POLICY_VIOLATION,
        ISSUE_INCOMPLETE,
        ISSUE_OFF_TASK,
        ISSUE_FORMATTING,
        ISSUE_REASONING_GAP,
    }
)

#: Pinned critique verdicts.
VERDICT_ACCEPT = "accept"
VERDICT_NEEDS_REVISION = "needs-revision"
VERDICT_REJECT = "reject"
_VERDICTS = frozenset({VERDICT_ACCEPT, VERDICT_NEEDS_REVISION, VERDICT_REJECT})

#: Pinned derived score verdicts.
SCORE_STRONG = "strong"
SCORE_ACCEPTABLE = "acceptable"
SCORE_WEAK = "weak"

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256
#: Composite weighting: correctness*5 + completeness*3 + style*2, over 10.
_SCORE_WEIGHTS = (5, 3, 2)
_SCORE_DEN = 10


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class ReflectionError(Exception):
    """Base class for all reflection errors."""


class BadDraftError(ReflectionError):
    """draft_id is not a usable non-empty str."""


class DuplicateDraftError(ReflectionError):
    """draft_id already booked; ids are never recycled."""


class UnknownDraftError(ReflectionError):
    """draft_id names no draft this ledger ever saw."""


class BadDigestError(ReflectionError):
    """A digest is not a non-empty sha256:-prefixed str."""


class BadCritiqueError(ReflectionError):
    """Critique inputs failed validation."""


class BadIssueError(ReflectionError):
    """An issue is not in the pinned vocabulary, or the list is malformed."""


class BadVerdictError(ReflectionError):
    """A verdict is not in the pinned vocabulary, or contradicts the issues."""


class UnknownCritiqueError(ReflectionError):
    """critique_id names no critique booked for this draft."""


class BadRevisionError(ReflectionError):
    """Revision inputs failed validation."""


class BadScoreError(ReflectionError):
    """A score component is not an int in 0..100."""


class SeqOrderError(ReflectionError):
    """seq is not a strictly-increasing int."""


class AuditKindError(ReflectionError):
    """Audit kind unknown, or banned detail key used."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDraftError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise BadDraftError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadDraftError(f"{what} too long (>{_MAX_ID_LEN} chars)")
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
    if len(value) > _MAX_ID_LEN + 64:
        raise BadDigestError(f"{what} too long")
    return value


def _check_issues(issues: Any) -> Tuple[str, ...]:
    if not isinstance(issues, (list, tuple)):
        raise BadIssueError(f"issues must be a list or tuple, got {type(issues).__name__}")
    clean: List[str] = []
    for issue in issues:
        if isinstance(issue, bool) or not isinstance(issue, str):
            raise BadIssueError(f"issue must be a str, got {type(issue).__name__}")
        if issue not in _ISSUES:
            raise BadIssueError(f"issue {issue!r} not in pinned vocabulary")
        clean.append(issue)
    if len(set(clean)) != len(clean):
        raise BadIssueError("duplicate issues refused")
    return tuple(sorted(clean))


def _check_verdict(verdict: Any) -> str:
    if isinstance(verdict, bool) or not isinstance(verdict, str):
        raise BadVerdictError(f"verdict must be a str, got {type(verdict).__name__}")
    if verdict not in _VERDICTS:
        raise BadVerdictError(f"verdict {verdict!r} not in pinned vocabulary")
    return verdict


def _check_score_component(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadScoreError(f"{what} must be an int, got {type(value).__name__}")
    if value < 0 or value > 100:
        raise BadScoreError(f"{what} must be in 0..100, got {value!r}")
    return value


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise ReflectionError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ReflectionError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise ReflectionError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DraftRecord:
    """One declared output under self-review (content pinned by digest only)."""

    draft_id: str
    output_digest: str
    digest: str
    seq: int
    schema: str = REFLECTION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin((self.draft_id, self.output_digest), "draft")


@dataclass(frozen=True)
class CritiqueRecord:
    """One self-critique against the pinned issue vocabulary."""

    critique_id: str
    draft_id: str
    issues: Tuple[str, ...]
    feedback_digest: str
    verdict: str
    digest: str
    seq: int
    schema: str = REFLECTION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.critique_id,
                self.draft_id,
                list(self.issues),
                self.feedback_digest,
                self.verdict,
            ),
            "critique",
        )


@dataclass(frozen=True)
class RevisionRecord:
    """One declared revision of a draft, linked to its parent critique."""

    revision_id: str
    draft_id: str
    parent_critique_id: str
    revision_digest: str
    digest: str
    seq: int
    schema: str = REFLECTION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.revision_id,
                self.draft_id,
                self.parent_critique_id,
                self.revision_digest,
            ),
            "revision",
        )


@dataclass(frozen=True)
class ScoreRecord:
    """Host-reported quality components plus a deterministically derived composite."""

    score_id: str
    draft_id: str
    correctness: int
    completeness: int
    style: int
    composite_text: str
    composite_floor: int
    verdict: str
    digest: str
    seq: int
    schema: str = REFLECTION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.score_id,
                self.draft_id,
                self.correctness,
                self.completeness,
                self.style,
                self.composite_text,
                self.composite_floor,
                self.verdict,
            ),
            "score",
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def reflection_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw output/feedback/revision text never crosses this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "output",
        "feedback",
        "text",
        "content",
        "payload",
        "raw",
        "body",
        "value",
        "message",
        "revision",
        "draft",
        "review",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "reflection",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# Reflection ledger
# ---------------------------------------------------------------------------


class Reflection:
    """Self-critique bookkeeping ledger: submit, critique, revise, score."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # draft_id -> DraftRecord
        self._drafts: Dict[str, DraftRecord] = {}
        # critique_id -> CritiqueRecord (ordered)
        self._critiques: Dict[str, CritiqueRecord] = {}
        # revision_id -> RevisionRecord (ordered)
        self._revisions: Dict[str, RevisionRecord] = {}
        # score_id -> ScoreRecord (ordered)
        self._scores: Dict[str, ScoreRecord] = {}
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(reflection_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: ReflectionError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def submit(self, draft_id: str, output_digest: str, seq: int) -> DraftRecord:
        """Book a declared output under self-review (content pinned by digest only)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                draft_id = _check_id(draft_id, "draft_id")
                output_digest = _check_digest(output_digest, "output_digest")
            except ReflectionError as exc:
                self._fail(seq, exc, draft_id=str(draft_id))
            if draft_id in self._drafts:
                self._fail(
                    seq,
                    DuplicateDraftError(f"draft already booked: {draft_id!r}"),
                    draft_id=draft_id,
                )
            record = DraftRecord(
                draft_id=draft_id,
                output_digest=output_digest,
                digest=_digest_pin((draft_id, output_digest), "draft"),
                seq=seq,
            )
            self._drafts[draft_id] = record
            self._emit(
                KIND_SUBMITTED,
                seq,
                draft_id=draft_id,
                output_digest=output_digest,
                record_digest=record.digest,
            )
            return record

    def critique(
        self,
        draft_id: str,
        seq: int,
        issues: Any = (),
        feedback_digest: str = "",
        verdict: str = VERDICT_NEEDS_REVISION,
    ) -> CritiqueRecord:
        """Book one self-critique of a draft. Empty issues require ``accept``;
        non-empty issues forbid ``accept`` (fail-closed consistency)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                draft_id = _check_id(draft_id, "draft_id")
                clean_issues = _check_issues(issues)
                verdict = _check_verdict(verdict)
                if feedback_digest:
                    feedback_digest = _check_digest(feedback_digest, "feedback_digest")
            except ReflectionError as exc:
                self._fail(seq, exc, draft_id=str(draft_id))
            if draft_id not in self._drafts:
                self._fail(seq, UnknownDraftError(f"unknown draft: {draft_id!r}"), draft_id=draft_id)
            if not clean_issues and verdict != VERDICT_ACCEPT:
                self._fail(
                    seq,
                    BadVerdictError(f"empty issues require verdict {VERDICT_ACCEPT!r}"),
                    draft_id=draft_id,
                )
            if clean_issues and verdict == VERDICT_ACCEPT:
                self._fail(
                    seq,
                    BadVerdictError(f"non-empty issues forbid verdict {VERDICT_ACCEPT!r}"),
                    draft_id=draft_id,
                )
            critique_id = f"crit-{len(self._critiques) + 1}"
            record = CritiqueRecord(
                critique_id=critique_id,
                draft_id=draft_id,
                issues=clean_issues,
                feedback_digest=feedback_digest,
                verdict=verdict,
                digest=_digest_pin(
                    (critique_id, draft_id, list(clean_issues), feedback_digest, verdict),
                    "critique",
                ),
                seq=seq,
            )
            self._critiques[critique_id] = record
            self._emit(
                KIND_CRITIQUE,
                seq,
                draft_id=draft_id,
                critique_id=critique_id,
                issue_count=len(clean_issues),
                verdict=verdict,
                record_digest=record.digest,
            )
            return record

    def revise(
        self,
        draft_id: str,
        seq: int,
        revision_digest: str = "",
        parent_critique_id: str = "",
    ) -> RevisionRecord:
        """Book a declared revision of a draft, linked to a parent critique
        already booked for that same draft (the Reflexion episodic link)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                draft_id = _check_id(draft_id, "draft_id")
                if not parent_critique_id or isinstance(parent_critique_id, bool) or not isinstance(
                    parent_critique_id, str
                ):
                    raise BadRevisionError("parent_critique_id must be a non-empty str")
                revision_digest = _check_digest(revision_digest, "revision_digest")
            except ReflectionError as exc:
                self._fail(seq, exc, draft_id=str(draft_id))
            if draft_id not in self._drafts:
                self._fail(seq, UnknownDraftError(f"unknown draft: {draft_id!r}"), draft_id=draft_id)
            parent = self._critiques.get(parent_critique_id)
            if parent is None or parent.draft_id != draft_id:
                self._fail(
                    seq,
                    UnknownCritiqueError(
                        f"no critique {parent_critique_id!r} booked for draft {draft_id!r}"
                    ),
                    draft_id=draft_id,
                )
            revision_id = f"rev-{len(self._revisions) + 1}"
            record = RevisionRecord(
                revision_id=revision_id,
                draft_id=draft_id,
                parent_critique_id=parent_critique_id,
                revision_digest=revision_digest,
                digest=_digest_pin(
                    (revision_id, draft_id, parent_critique_id, revision_digest),
                    "revision",
                ),
                seq=seq,
            )
            self._revisions[revision_id] = record
            self._emit(
                KIND_REVISION,
                seq,
                draft_id=draft_id,
                revision_id=revision_id,
                parent_critique_id=parent_critique_id,
                record_digest=record.digest,
            )
            return record

    def score(
        self,
        draft_id: str,
        seq: int,
        correctness: int,
        completeness: int,
        style: int,
    ) -> ScoreRecord:
        """Book host-reported quality components; the composite is derived
        deterministically as an exact rational (no floats)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                draft_id = _check_id(draft_id, "draft_id")
                c = _check_score_component(correctness, "correctness")
                cp = _check_score_component(completeness, "completeness")
                s = _check_score_component(style, "style")
            except ReflectionError as exc:
                self._fail(seq, exc, draft_id=str(draft_id))
            if draft_id not in self._drafts:
                self._fail(seq, UnknownDraftError(f"unknown draft: {draft_id!r}"), draft_id=draft_id)
            composite = Fraction(
                _SCORE_WEIGHTS[0] * c + _SCORE_WEIGHTS[1] * cp + _SCORE_WEIGHTS[2] * s,
                _SCORE_DEN,
            )
            composite_text = f"{composite.numerator}/{composite.denominator}"
            composite_floor = int(composite)
            if composite >= 90:
                score_verdict = SCORE_STRONG
            elif composite >= 70:
                score_verdict = SCORE_ACCEPTABLE
            else:
                score_verdict = SCORE_WEAK
            score_id = f"score-{len(self._scores) + 1}"
            record = ScoreRecord(
                score_id=score_id,
                draft_id=draft_id,
                correctness=c,
                completeness=cp,
                style=s,
                composite_text=composite_text,
                composite_floor=composite_floor,
                verdict=score_verdict,
                digest=_digest_pin(
                    (
                        score_id,
                        draft_id,
                        c,
                        cp,
                        s,
                        composite_text,
                        composite_floor,
                        score_verdict,
                    ),
                    "score",
                ),
                seq=seq,
            )
            self._scores[score_id] = record
            self._emit(
                KIND_SCORE,
                seq,
                draft_id=draft_id,
                score_id=score_id,
                composite_text=composite_text,
                composite_floor=composite_floor,
                verdict=score_verdict,
                record_digest=record.digest,
            )
            return record

    # -- pure read views ----------------------------------------------------

    def draft(self, draft_id: str, seq: int) -> Optional[DraftRecord]:
        """Pure read: the booked draft record, or None."""
        _check_seq(seq)
        with self._lock:
            return self._drafts.get(draft_id)

    def draft_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: sorted ids of booked drafts."""
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._drafts))

    def critiques_for(self, draft_id: str, seq: int) -> Tuple[CritiqueRecord, ...]:
        """Pure read: critiques booked for a draft, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(c for c in self._critiques.values() if c.draft_id == draft_id)

    def revisions_for(self, draft_id: str, seq: int) -> Tuple[RevisionRecord, ...]:
        """Pure read: revisions booked for a draft, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(r for r in self._revisions.values() if r.draft_id == draft_id)

    def score_history(self, draft_id: str, seq: int) -> Tuple[ScoreRecord, ...]:
        """Pure read: scores booked for a draft, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(s for s in self._scores.values() if s.draft_id == draft_id)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters."""
        _check_seq(seq)
        with self._lock:
            return {
                "drafts": len(self._drafts),
                "critiques": len(self._critiques),
                "revisions": len(self._revisions),
                "scores": len(self._scores),
                "last_seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events booked so far."""
        with self._lock:
            return tuple(self._audit_events)


def main() -> None:
    """Self-check: submit, critique (clean), critique (issues), revise, score."""
    ledger = Reflection()
    draft = ledger.submit("draft-1", "sha256:" + "a" * 64, 1)
    assert draft.verify()
    clean = ledger.critique("draft-1", 2, issues=(), verdict="accept")
    assert clean.verify() and clean.verdict == "accept"
    crit = ledger.critique(
        "draft-1",
        3,
        issues=("hallucination", "formatting"),
        feedback_digest="sha256:" + "b" * 64,
        verdict="needs-revision",
    )
    assert crit.verify() and crit.issues == ("formatting", "hallucination")
    rev = ledger.revise("draft-1", 4, revision_digest="sha256:" + "c" * 64, parent_critique_id=crit.critique_id)
    assert rev.verify()
    sc = ledger.score("draft-1", 5, 90, 80, 70)
    assert sc.verify() and sc.composite_text == "83/1" and sc.verdict == "acceptable"
    print("reflection OK: submit, critique, revise, score, pins, audit")


if __name__ == "__main__":
    main()
