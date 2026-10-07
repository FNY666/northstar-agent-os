"""Ethics review board (submit/adjudicate/appeal) interface, simulated.

Research motivation: institutional review boards (IRBs) and AI ethics
committees (the Belmont Report; IEEE Ethically Aligned Design; EU AI
Act conformity assessment) reduce ethics governance to one operational
shape: a proposal is declared under a category, a board books a
decision, and the proposer may book one appeal. The ledger records
decisions, never the proposal's full content.

This module is the *ethics-review ledger* half of that shape:

- ``EthicsReview.submit(proposal_id, category, seq, summary_digest="")``
  -- book one proposal for review under a pinned category vocabulary.
  The proposal's content is pinned by ``sha256:`` digest only; raw
  text never enters a record.
- ``EthicsReview.adjudicate(proposal_id, decision, seq)`` -- book the
  board's terminal decision over the pinned vocabulary (``approved`` /
  ``approved-with-conditions`` / ``rejected`` / ``deferred``). The
  decision is *data*, never a finding of fact about any real project --
  exactly once per proposal.
- ``EthicsReview.appeal(proposal_id, seq, grounds_digest="")`` -- book
  one appeal against a booked adjudication (exactly once per
  proposal). The grounds are digest-pinned and discarded from the
  record; the appeal does not alter the booked decision, it books the
  appeal event itself.
- Views (``proposal`` / ``adjudication`` / ``appeal_record`` /
  ``proposal_ids`` / ``stats`` / ``audit_log``) -- pure reads that
  validate the seq shape, consume nothing, and write no audit rows.
- ``ethics_review_audit_event(kind, ...)`` -- ``audit.ndjson/1`` rows
  (``submitted`` / ``adjudicated`` / ``appealed`` / ``rejected``);
  caller-supplied seqs only. Raw proposal content never crosses the
  audit boundary -- audit rows carry ids, categories, digests,
  decisions, and counts only.

Fail-closed edges (fail loudly, never guess):

- ``proposal_id`` must be non-empty str, <= 256 chars, no whitespace.
- ``category`` must be in the pinned vocabulary; ``decision`` must be
  in the pinned vocabulary.
- ``summary_digest`` / ``grounds_digest`` must be ``sha256:<64hex>``
  pins when supplied (may be empty).
- ``submit`` on a duplicate id raises ``DuplicateProposalError``;
  ``adjudicate`` / ``appeal`` on unknown ids raise
  ``UnknownProposalError``.
- ``adjudicate`` requires a submitted proposal and runs exactly once
  (``DuplicateAdjudicationError``); ``appeal`` requires a booked
  adjudication (``NoAdjudicationError``) and runs exactly once
  (``DuplicateAppealError``).
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* proposals, *host-reported* board
  decisions, and *host-reported* appeals. A booked ``approved`` verdict
  means the host reported an approval -- the module ran no review,
  assessed no ethics, and proves nothing about any real project's
  safety or acceptability.
- Digest pins prove ledger integrity and ordering, never the truth of
  the proposal's content or the wisdom of the board.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if ethics-review state must survive a restart.
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
ETHICS_REVIEW_VERSION = "ethics-review.v1"

#: Schema pin carried by records and audit events.
ETHICS_REVIEW_SCHEMA = "northstar.ethics-review.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_SUBMITTED = "submitted"
KIND_ADJUDICATED = "adjudicated"
KIND_APPEALED = "appealed"
KIND_REJECTED = "rejected"
_KINDS = (KIND_SUBMITTED, KIND_ADJUDICATED, KIND_APPEALED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"proposal", "summary", "grounds", "conditions", "content", "text",
     "payload", "raw", "argument", "response", "value", "evidence",
     "justification"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned proposal-category vocabulary. Categories are bookkeeping
#: labels for the review queue, not ethical judgments.
CATEGORY_HUMAN_SUBJECTS = "human-subjects"
CATEGORY_ANIMAL_RESEARCH = "animal-research"
CATEGORY_DUAL_USE = "dual-use"
CATEGORY_PRIVACY = "privacy"
CATEGORY_BIOSECURITY = "biosecurity"
CATEGORY_ENVIRONMENTAL = "environmental"
CATEGORY_CONFLICT_OF_INTEREST = "conflict-of-interest"
CATEGORY_PUBLICATION = "publication"
CATEGORY_AI_SAFETY = "ai-safety"
CATEGORY_OTHER = "other"
CATEGORIES = (
    CATEGORY_HUMAN_SUBJECTS,
    CATEGORY_ANIMAL_RESEARCH,
    CATEGORY_DUAL_USE,
    CATEGORY_PRIVACY,
    CATEGORY_BIOSECURITY,
    CATEGORY_ENVIRONMENTAL,
    CATEGORY_CONFLICT_OF_INTEREST,
    CATEGORY_PUBLICATION,
    CATEGORY_AI_SAFETY,
    CATEGORY_OTHER,
)

#: Pinned board-decision vocabulary. Decisions are host-reported data.
DECISION_APPROVED = "approved"
DECISION_CONDITIONAL = "approved-with-conditions"
DECISION_REJECTED = "rejected"
DECISION_DEFERRED = "deferred"
DECISIONS = (
    DECISION_APPROVED,
    DECISION_CONDITIONAL,
    DECISION_REJECTED,
    DECISION_DEFERRED,
)

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class EthicsReviewError(Exception):
    """Base error for the ethics-review ledger (programming errors)."""


class BadIdError(EthicsReviewError):
    """Raised when a proposal id is malformed."""


class DuplicateProposalError(EthicsReviewError):
    """Raised when a proposal id is submitted twice."""


class UnknownProposalError(EthicsReviewError):
    """Raised when a proposal id names no submitted proposal."""


class BadCategoryError(EthicsReviewError):
    """Raised when a category is not in the pinned vocabulary."""


class BadDigestError(EthicsReviewError):
    """Raised when a summary/grounds digest is not a sha256: pin."""


class BadDecisionError(EthicsReviewError):
    """Raised when a board decision is not in the pinned vocabulary."""


class DuplicateAdjudicationError(EthicsReviewError):
    """Raised when a proposal is adjudicated twice."""


class NoAdjudicationError(EthicsReviewError):
    """Raised when appeal() is called before any adjudication is booked."""


class DuplicateAppealError(EthicsReviewError):
    """Raised when a proposal is appealed twice (one appeal per proposal)."""


class SeqOrderError(EthicsReviewError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(EthicsReviewError):
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
        "domain": ETHICS_REVIEW_SCHEMA,
        "parts": list(parts),
    })


def ethics_review_audit_event(kind: str, detail: Dict[str, object],
                              seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the ethics-review ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": ETHICS_REVIEW_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class ProposalRecord:
    """Frozen record of one submitted proposal (digest-pinned content)."""
    proposal_id: str
    category: str
    summary_digest: str
    seq: int
    digest: str

    def verify(self, proposal_id: str, category: str,
               summary_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "proposal", proposal_id, category, summary_digest, self.seq)


@dataclass(frozen=True)
class AdjudicationRecord:
    """Frozen record of the board's terminal decision (decision as data)."""
    adjudication_id: str
    proposal_id: str
    decision: str
    seq: int
    digest: str

    def verify(self, proposal_id: str, decision: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "adjudication", self.adjudication_id, proposal_id, decision,
            self.seq)


@dataclass(frozen=True)
class AppealRecord:
    """Frozen record of one appeal (grounds digest-pinned, terminal)."""
    appeal_id: str
    proposal_id: str
    grounds_digest: str
    seq: int
    digest: str

    def verify(self, proposal_id: str, grounds_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "appeal", self.appeal_id, proposal_id, grounds_digest, self.seq)


@dataclass(frozen=True)
class ProposalView:
    """Pure read view of a proposal plus its booked decision trail."""
    proposal_id: str
    category: str
    summary_digest: str
    adjudication_id: Optional[str]
    decision: Optional[str]
    appeal_id: Optional[str]
    digest: str

    def verify(self, proposal_id: str, category: str,
               adjudication_id: Optional[str]) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "proposal-view", proposal_id, category, adjudication_id or "")


class EthicsReview:
    """Ethics-review board ledger (declared proposals, booked decisions)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._proposals: Dict[str, ProposalRecord] = {}
        self._adjudications: Dict[str, AdjudicationRecord] = {}
        self._appeals: Dict[str, AppealRecord] = {}
        self._adjudication_ids: Tuple[str, ...] = ()
        self._appeal_ids: Tuple[str, ...] = ()
        self._audit: Tuple[Dict[str, object], ...] = ()

    def _claim(self, seq: int) -> None:
        """Claim a seq (strictly increasing); raise bare on rewind."""
        _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be > {self._last_seq}, got {seq}")
            self._last_seq = seq

    def _burn(self, seq: int, proposal_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if proposal_id:
            detail["proposal_id"] = proposal_id
        event = ethics_review_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = ethics_review_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def submit(self, proposal_id: str, category: str, seq: int,
               summary_digest: str = "") -> ProposalRecord:
        """Book one proposal for review. Pins the summary digest, never
        the summary text. Returns the frozen ``ProposalRecord``."""
        self._claim(seq)
        try:
            proposal_id = _check_id(proposal_id, "proposal_id")
            if isinstance(category, bool) or not isinstance(category, str):
                raise BadCategoryError(
                    f"category must be str, got {type(category).__name__}")
            if category not in CATEGORIES:
                raise BadCategoryError(
                    f"category must be one of {sorted(CATEGORIES)}, "
                    f"got {category!r}")
            summary_digest = _check_digest(
                summary_digest, "summary_digest", allow_empty=True)
            with self._lock:
                if proposal_id in self._proposals:
                    raise DuplicateProposalError(
                        f"proposal already submitted: {proposal_id!r}")
                record = ProposalRecord(
                    proposal_id=proposal_id,
                    category=category,
                    summary_digest=summary_digest,
                    seq=seq,
                    digest=_pin("proposal", proposal_id, category,
                                summary_digest, seq),
                )
                self._proposals[proposal_id] = record
        except EthicsReviewError:
            self._burn(seq, proposal_id if isinstance(proposal_id, str)
                       else "")
            raise
        self._emit(KIND_SUBMITTED,
                   {"proposal_id": proposal_id,
                    "category": category,
                    "summary_digest": summary_digest}, seq)
        return record

    def adjudicate(self, proposal_id: str, decision: str,
                   seq: int) -> AdjudicationRecord:
        """Book the board's terminal decision as data (exactly once).
        Returns the frozen ``AdjudicationRecord``."""
        self._claim(seq)
        try:
            proposal_id = _check_id(proposal_id, "proposal_id")
            if isinstance(decision, bool) or not isinstance(decision, str):
                raise BadDecisionError(
                    f"decision must be str, got {type(decision).__name__}")
            if decision not in DECISIONS:
                raise BadDecisionError(
                    f"decision must be one of {sorted(DECISIONS)}, "
                    f"got {decision!r}")
            with self._lock:
                if proposal_id not in self._proposals:
                    raise UnknownProposalError(
                        f"unknown proposal: {proposal_id!r}")
                if proposal_id in self._adjudications:
                    raise DuplicateAdjudicationError(
                        f"proposal already adjudicated: {proposal_id!r}")
                adjudication_id = f"adj-{len(self._adjudication_ids) + 1}"
                record = AdjudicationRecord(
                    adjudication_id=adjudication_id,
                    proposal_id=proposal_id,
                    decision=decision,
                    seq=seq,
                    digest=_pin("adjudication", adjudication_id,
                                proposal_id, decision, seq),
                )
                self._adjudications[proposal_id] = record
                self._adjudication_ids = (
                    self._adjudication_ids + (adjudication_id,))
        except EthicsReviewError:
            self._burn(seq, proposal_id if isinstance(proposal_id, str)
                       else "")
            raise
        self._emit(KIND_ADJUDICATED,
                   {"proposal_id": proposal_id,
                    "adjudication_id": record.adjudication_id,
                    "decision": decision}, seq)
        return record

    def appeal(self, proposal_id: str, seq: int,
               grounds_digest: str = "") -> AppealRecord:
        """Book one appeal against a booked adjudication (exactly once).
        The grounds are digest-pinned; the appeal books the appeal event,
        not a change to the booked decision. Returns the frozen
        ``AppealRecord``."""
        self._claim(seq)
        try:
            proposal_id = _check_id(proposal_id, "proposal_id")
            grounds_digest = _check_digest(
                grounds_digest, "grounds_digest", allow_empty=True)
            with self._lock:
                if proposal_id not in self._proposals:
                    raise UnknownProposalError(
                        f"unknown proposal: {proposal_id!r}")
                if proposal_id not in self._adjudications:
                    raise NoAdjudicationError(
                        f"no adjudication booked for {proposal_id!r}")
                if proposal_id in self._appeals:
                    raise DuplicateAppealError(
                        f"proposal already appealed: {proposal_id!r}")
                appeal_id = f"apl-{len(self._appeal_ids) + 1}"
                record = AppealRecord(
                    appeal_id=appeal_id,
                    proposal_id=proposal_id,
                    grounds_digest=grounds_digest,
                    seq=seq,
                    digest=_pin("appeal", appeal_id, proposal_id,
                                grounds_digest, seq),
                )
                self._appeals[proposal_id] = record
                self._appeal_ids = self._appeal_ids + (appeal_id,)
        except EthicsReviewError:
            self._burn(seq, proposal_id if isinstance(proposal_id, str)
                       else "")
            raise
        self._emit(KIND_APPEALED,
                   {"proposal_id": proposal_id,
                    "appeal_id": record.appeal_id,
                    "grounds_digest": grounds_digest}, seq)
        return record

    def proposal(self, proposal_id: str, seq: int) -> ProposalView:
        """Pure read view of a proposal plus its decision trail (validates
        seq shape, consumes nothing, writes no audit row). Returns the
        frozen ``ProposalView``."""
        _check_seq(seq)
        proposal_id = _check_id(proposal_id, "proposal_id")
        with self._lock:
            if proposal_id not in self._proposals:
                raise UnknownProposalError(
                    f"unknown proposal: {proposal_id!r}")
            prop = self._proposals[proposal_id]
            adj = self._adjudications.get(proposal_id)
            apl = self._appeals.get(proposal_id)
            adjudication_id = adj.adjudication_id if adj is not None else None
            decision = adj.decision if adj is not None else None
            appeal_id = apl.appeal_id if apl is not None else None
            return ProposalView(
                proposal_id=proposal_id,
                category=prop.category,
                summary_digest=prop.summary_digest,
                adjudication_id=adjudication_id,
                decision=decision,
                appeal_id=appeal_id,
                digest=_pin("proposal-view", proposal_id, prop.category,
                            adjudication_id or ""),
            )

    def proposal_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of all submitted proposal ids in submit order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._proposals.keys())

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Pure read view of the audit events (no seq, no audit row)."""
        with self._lock:
            return self._audit

    def stats(self) -> Dict[str, int]:
        """Pure read view of ledger counters (no seq, no audit row)."""
        with self._lock:
            return {
                "proposals": len(self._proposals),
                "adjudications": len(self._adjudications),
                "appeals": len(self._appeals),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: submit, adjudicate, appeal, verify pins, audit."""
    er = EthicsReview()
    digest = "sha256:" + "0" * 64
    rec = er.submit("prop-1", CATEGORY_AI_SAFETY, 1, digest)
    assert rec.verify("prop-1", CATEGORY_AI_SAFETY, digest)
    assert not rec.verify("prop-1", CATEGORY_PRIVACY, digest)
    adj = er.adjudicate("prop-1", DECISION_CONDITIONAL, 2)
    assert adj.verify("prop-1", DECISION_CONDITIONAL)
    assert not adj.verify("prop-1", DECISION_APPROVED)
    apl = er.appeal("prop-1", 3, digest)
    assert apl.verify("prop-1", digest)
    view = er.proposal("prop-1", 4)
    assert view.decision == DECISION_CONDITIONAL
    assert view.verify("prop-1", CATEGORY_AI_SAFETY, adj.adjudication_id)
    assert er.stats()["proposals"] == 1
    kinds = [row["kind"] for row in er.audit_log()]
    assert kinds == [KIND_SUBMITTED, KIND_ADJUDICATED, KIND_APPEALED]
    # one appeal per proposal
    try:
        er.appeal("prop-1", 5)
    except DuplicateAppealError:
        pass
    else:
        raise AssertionError("double appeal must fail closed")
    print("ethics-review OK: submit, adjudicate, appeal, pins, audit")


if __name__ == "__main__":
    main()
