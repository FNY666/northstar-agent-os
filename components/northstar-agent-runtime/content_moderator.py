"""Content moderation interface (twenty-ninth batch).

Policy-enforcement bookkeeping for user-generated content, shaped after
large-platform moderation pipelines (Meta Community Standards
enforcement, YouTube strikes, Reddit mod-queue):

* :meth:`ContentModerator.review` books a host-reported review of a
  content item. Findings are ``(category, severity)`` pairs drawn from
  a pinned vocabulary; the resulting verdict (``clean`` / ``flagged`` /
  ``violation``) is data, never an exception.
* :meth:`ContentModerator.action` records an enforcement action drawn
  from a pinned vocabulary (``allow`` / ``warn`` / ``remove`` /
  ``restrict`` / ``ban`` / ``escalate``). Enforcement is proportional to
  the review's top severity; a ``ban`` is terminal.
* :meth:`ContentModerator.appeal` + :meth:`ContentModerator.decide`
  model the appeals ladder: an appeal is opened against an action, then
  decided (``upheld`` / ``overturned`` / ``modified``). An overturned
  ``remove``/``restrict`` produces a ``restored`` ledger state.

House rules: no wall-clock (callers inject integer seq/epoch values),
frozen dataclasses, fail-closed checks (unknown ids, bad severities,
terminal states all refused), stdlib-only, records sealed with a
sha256 ``record_digest`` over the canonical payload. State transitions
emit ``audit.ndjson/1`` events.

Honest boundary: this module books *host-reported* review findings and
*host-executed* actions; it never sees the content itself (only a
digest), cannot run classifiers, and cannot prove a finding is correct.
It is the ledger, not the classifier and not the enforcement arm —
downstream systems must execute the action and observe the effect.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


#: Version pin for this module's record shape.
CONTENT_MODERATOR_VERSION = "content-moderator.v1"

#: Schema pin carried by records and audit events.
CONTENT_MODERATOR_SCHEMA = "northstar.content-moderator.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

# ---------------------------------------------------------------------------
# Pinned vocabularies
# ---------------------------------------------------------------------------

#: Policy categories a finding may cite.
CATEGORIES = (
    "spam",
    "harassment",
    "hate_speech",
    "sexual_content",
    "violence",
    "self_harm",
    "misinformation",
    "illegal_content",
    "copyright",
    "malware",
)

#: Finding severities, ordered low -> critical.
SEVERITIES = ("low", "medium", "high", "critical")

_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

#: Review verdicts.
VERDICT_CLEAN = "clean"
VERDICT_FLAGGED = "flagged"
VERDICT_VIOLATION = "violation"
VERDICTS = (VERDICT_CLEAN, VERDICT_FLAGGED, VERDICT_VIOLATION)

#: Enforcement actions.
ACTIONS = (
    "allow",
    "warn",
    "remove",
    "restrict",
    "ban",
    "escalate",
)

#: Minimum action allowed per top severity. "escalate" is always allowed
#: (it defers judgment to a human reviewer).
_MIN_ACTION_FOR_SEVERITY: Mapping[str, Sequence[str]] = {
    "low": ("allow", "warn", "escalate"),
    "medium": ("warn", "remove", "restrict", "escalate"),
    "high": ("remove", "restrict", "escalate"),
    "critical": ("remove", "restrict", "ban", "escalate"),
}

#: Actions that are terminal for the content item: no further actions.
_TERMINAL_ACTIONS = ("ban",)

#: Appeal outcomes.
APPEAL_UPHELD = "upheld"
APPEAL_OVERTURNED = "overturned"
APPEAL_MODIFIED = "modified"
APPEAL_OUTCOMES = (APPEAL_UPHELD, APPEAL_OVERTURNED, APPEAL_MODIFIED)

#: Audit event kinds.
_KINDS = (
    "submitted",
    "reviewed",
    "actioned",
    "appealed",
    "appeal-decided",
    "rejected",
)


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class ContentModeratorError(Exception):
    """Base class for content-moderator refusals."""


class UnknownContentError(ContentModeratorError):
    """Referenced content id is unknown."""


class UnknownReviewError(ContentModeratorError):
    """Referenced review id is unknown."""


class UnknownActionError(ContentModeratorError):
    """Referenced action id is unknown."""


class UnknownAppealError(ContentModeratorError):
    """Referenced appeal id is unknown."""


class BadInputError(ContentModeratorError):
    """Malformed input: bad category/severity/action/outcome, empty ids."""


class SeqOrderError(ContentModeratorError):
    """Mutation seq is not a strictly increasing positive int."""


class TerminalActionError(ContentModeratorError):
    """Item already carries a terminal action (ban); no further actions."""


class AppealStateError(ContentModeratorError):
    """Appeal misuse: already decided, or none open for the action."""


class DisproportionateActionError(ContentModeratorError):
    """Chosen action is weaker than the policy floor for the severity."""


# ---------------------------------------------------------------------------
# Canonical digest plumbing
# ---------------------------------------------------------------------------


def _canonical(payload: Mapping[str, Any]) -> bytes:
    try:
        from canonical_json import canonical_json  # type: ignore[import-not-found]
    except Exception:  # pragma: no cover - fallback path
        canonical_json = None  # type: ignore[assignment]
    if canonical_json is not None:
        return canonical_json(payload).encode("utf-8")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _pin(*parts: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical({"parts": list(parts)})).hexdigest()


def _check_seq(seq: int, name: str = "seq") -> None:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise SeqOrderError(f"{name} must be a positive int, got {seq!r}")


def _check_id(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise BadInputError(f"{name} must be a non-empty str")


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def content_moderator_audit_event(kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the content moderator."""
    if kind not in _KINDS:
        raise ContentModeratorError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "content_moderator",
        "module_version": CONTENT_MODERATOR_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# Records (frozen dataclasses)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContentItem:
    """A submitted content item. Only the digest is kept, never the text."""

    content_id: str
    content_digest: str
    author: str
    seq: int
    record_digest: str = field(default="")
    schema: str = field(default=CONTENT_MODERATOR_SCHEMA, init=False)
    version: str = field(default=CONTENT_MODERATOR_VERSION, init=False)

    def verify(self) -> bool:
        """Re-derive the record digest; False on any drift."""
        expected = _pin("content", self.content_id, self.content_digest,
                        self.author, self.seq)
        return self.record_digest == expected


@dataclass(frozen=True)
class Finding:
    """A single policy finding: category + severity (host-reported)."""

    category: str
    severity: str

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            raise BadInputError(f"unknown category: {self.category!r}")
        if self.severity not in SEVERITIES:
            raise BadInputError(f"unknown severity: {self.severity!r}")


@dataclass(frozen=True)
class ReviewRecord:
    """A completed review: verdict derived from the top severity."""

    review_id: str
    content_id: str
    verdict: str
    top_severity: str | None
    findings: tuple[Finding, ...]
    seq: int
    record_digest: str = field(default="")
    schema: str = field(default=CONTENT_MODERATOR_SCHEMA, init=False)
    version: str = field(default=CONTENT_MODERATOR_VERSION, init=False)

    def verify(self) -> bool:
        expected = _pin(
            "review",
            self.review_id,
            self.content_id,
            self.verdict,
            self.top_severity,
            tuple((f.category, f.severity) for f in self.findings),
            self.seq,
        )
        return self.record_digest == expected


@dataclass(frozen=True)
class ActionRecord:
    """An enforcement action taken on a reviewed item."""

    action_id: str
    review_id: str
    content_id: str
    action: str
    reason: str
    seq: int
    state: str = "active"  # active | restored | superseded
    record_digest: str = field(default="")
    schema: str = field(default=CONTENT_MODERATOR_SCHEMA, init=False)
    version: str = field(default=CONTENT_MODERATOR_VERSION, init=False)

    def verify(self) -> bool:
        expected = _pin(
            "action",
            self.action_id,
            self.review_id,
            self.content_id,
            self.action,
            self.reason,
            self.state,
            self.seq,
        )
        return self.record_digest == expected


@dataclass(frozen=True)
class AppealRecord:
    """An appeal against an action, and (optionally) its decision."""

    appeal_id: str
    action_id: str
    grounds: str
    seq: int
    outcome: str | None = None
    decision_seq: int | None = None
    record_digest: str = field(default="")
    schema: str = field(default=CONTENT_MODERATOR_SCHEMA, init=False)
    version: str = field(default=CONTENT_MODERATOR_VERSION, init=False)

    def verify(self) -> bool:
        expected = _pin(
            "appeal",
            self.appeal_id,
            self.action_id,
            self.grounds,
            self.outcome,
            self.decision_seq,
            self.seq,
        )
        return self.record_digest == expected


# ---------------------------------------------------------------------------
# ContentModerator
# ---------------------------------------------------------------------------


class ContentModerator:
    """Policy-enforcement bookkeeping: submit -> review -> action -> appeal.

    All mutating methods take a caller-supplied strictly increasing
    positive int ``seq`` (no wall-clock). Failed mutations consume their
    seq (batch-21 ledger discipline). Guarded by an RLock for
    thread-safety.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._items: dict[str, ContentItem] = {}
        self._reviews: dict[str, ReviewRecord] = {}
        self._actions: dict[str, ActionRecord] = {}
        self._appeals: dict[str, AppealRecord] = {}
        self._last_seq = 0
        self._counters = {"content": 0, "review": 0, "action": 0, "appeal": 0}
        self._audit_log: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _take_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _next_id(self, kind: str) -> str:
        self._counters[kind] += 1
        prefix = {"content": "cnt", "review": "rev",
                  "action": "act", "appeal": "apl"}[kind]
        return f"{prefix}-{self._counters[kind]}"

    def _audit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(
            content_moderator_audit_event(kind, seq, **detail)
        )

    # -- submit --------------------------------------------------------

    def submit(self, *, content_digest: str, seq: int,
               author: str = "") -> ContentItem:
        """Book a content item. Only ``content_digest`` is kept, never text."""
        with self._lock:
            self._take_seq(seq)
            _check_id(content_digest, "content_digest")
            if not isinstance(author, str):
                raise BadInputError("author must be a str")
            content_id = self._next_id("content")
            record_digest = _pin("content", content_id, content_digest,
                                author, seq)
            item = ContentItem(content_id=content_id,
                              content_digest=content_digest,
                              author=author, seq=seq,
                              record_digest=record_digest)
            self._items[content_id] = item
            self._audit("submitted", seq, content_id=content_id,
                        content_digest=content_digest)
            return item

    # -- review --------------------------------------------------------

    @staticmethod
    def _verdict(findings: Sequence[Finding]) -> tuple[str, str | None]:
        if not findings:
            return VERDICT_CLEAN, None
        top = max(findings, key=lambda f: _SEVERITY_RANK[f.severity])
        top_rank = _SEVERITY_RANK[top.severity]
        if top_rank >= _SEVERITY_RANK["high"]:
            return VERDICT_VIOLATION, top.severity
        return VERDICT_FLAGGED, top.severity

    def review(self, content_id: str, seq: int,
               findings: Sequence[tuple[str, str]] = ()) -> ReviewRecord:
        """Book a host-reported review. Verdict is data, never raised."""
        with self._lock:
            self._take_seq(seq)
            _check_id(content_id, "content_id")
            item = self._items.get(content_id)
            if item is None:
                raise UnknownContentError(f"unknown content: {content_id!r}")
            parsed = tuple(Finding(category=c, severity=s) for c, s in findings)
            verdict, top_severity = self._verdict(parsed)
            review_id = self._next_id("review")
            record_digest = _pin(
                "review", review_id, content_id, verdict, top_severity,
                tuple((f.category, f.severity) for f in parsed), seq)
            record = ReviewRecord(
                review_id=review_id, content_id=content_id, verdict=verdict,
                top_severity=top_severity, findings=parsed, seq=seq,
                record_digest=record_digest)
            self._reviews[review_id] = record
            self._audit("reviewed", seq, review_id=review_id,
                       content_id=content_id, verdict=verdict,
                       top_severity=top_severity,
                       finding_count=len(parsed))
            return record

    # -- action --------------------------------------------------------

    def action(self, review_id: str, seq: int, *, action: str,
               reason: str) -> ActionRecord:
        """Record an enforcement action for a review. Fail-closed."""
        with self._lock:
            self._take_seq(seq)
            _check_id(review_id, "review_id")
            if action not in ACTIONS:
                raise BadInputError(f"unknown action: {action!r}")
            if not isinstance(reason, str) or not reason.strip():
                raise BadInputError("reason must be a non-empty str")
            review = self._reviews.get(review_id)
            if review is None:
                raise UnknownReviewError(f"unknown review: {review_id!r}")
            content_id = review.content_id
            for act in self._actions.values():
                if act.content_id == content_id and act.action in _TERMINAL_ACTIONS:
                    raise TerminalActionError(
                        f"content {content_id} already banned (action {act.action_id})")
            if action != "allow" and review.verdict == VERDICT_CLEAN:
                raise DisproportionateActionError(
                    "cannot enforce a non-allow action on a clean review")
            if review.verdict != VERDICT_CLEAN:
                floor = _MIN_ACTION_FOR_SEVERITY[review.top_severity or "low"]
                if action not in floor:
                    raise DisproportionateActionError(
                        f"action {action!r} below policy floor for "
                        f"{review.top_severity}: {floor}")
            action_id = self._next_id("action")
            record_digest = _pin(
                "action", action_id, review_id, content_id, action,
                reason, "active", seq)
            record = ActionRecord(
                action_id=action_id, review_id=review_id,
                content_id=content_id, action=action, reason=reason,
                seq=seq, record_digest=record_digest)
            self._actions[action_id] = record
            self._audit("actioned", seq, action_id=action_id,
                       review_id=review_id, content_id=content_id,
                       action=action)
            return record

    # -- appeal / decide ------------------------------------------------

    def appeal(self, action_id: str, seq: int, *, grounds: str) -> AppealRecord:
        """Open an appeal against an action. One open appeal per action."""
        with self._lock:
            self._take_seq(seq)
            _check_id(action_id, "action_id")
            if not isinstance(grounds, str) or not grounds.strip():
                raise BadInputError("grounds must be a non-empty str")
            if action_id not in self._actions:
                raise UnknownActionError(f"unknown action: {action_id!r}")
            for apl in self._appeals.values():
                if apl.action_id == action_id and apl.outcome is None:
                    raise AppealStateError(
                        f"action {action_id} already has an open appeal")
            appeal_id = self._next_id("appeal")
            record_digest = _pin(
                "appeal", appeal_id, action_id, grounds, None, None, seq)
            record = AppealRecord(appeal_id=appeal_id, action_id=action_id,
                                  grounds=grounds, seq=seq,
                                  record_digest=record_digest)
            self._appeals[appeal_id] = record
            self._audit("appealed", seq, appeal_id=appeal_id,
                       action_id=action_id)
            return record

    def decide(self, appeal_id: str, seq: int, *, outcome: str) -> AppealRecord:
        """Decide an open appeal. ``overturned`` restores the content."""
        with self._lock:
            self._take_seq(seq)
            _check_id(appeal_id, "appeal_id")
            if outcome not in APPEAL_OUTCOMES:
                raise BadInputError(f"unknown outcome: {outcome!r}")
            record = self._appeals.get(appeal_id)
            if record is None:
                raise UnknownAppealError(f"unknown appeal: {appeal_id!r}")
            if record.outcome is not None:
                raise AppealStateError(f"appeal {appeal_id} already decided")
            new_digest = _pin(
                "appeal", appeal_id, record.action_id, record.grounds,
                outcome, seq, record.seq)
            decided = AppealRecord(
                appeal_id=appeal_id, action_id=record.action_id,
                grounds=record.grounds, seq=record.seq, outcome=outcome,
                decision_seq=seq, record_digest=new_digest)
            self._appeals[appeal_id] = decided
            if outcome == APPEAL_OVERTURNED:
                action = self._actions[record.action_id]
                if action.action in ("remove", "restrict"):
                    old = action
                    new_digest_a = _pin(
                        "action", old.action_id, old.review_id,
                        old.content_id, old.action, old.reason,
                        "restored", seq)
                    restored = ActionRecord(
                        action_id=old.action_id, review_id=old.review_id,
                        content_id=old.content_id, action=old.action,
                        reason=old.reason, seq=old.seq, state="restored",
                        record_digest=new_digest_a)
                    self._actions[old.action_id] = restored
            self._audit("appeal-decided", seq, appeal_id=appeal_id,
                       action_id=record.action_id, outcome=outcome)
            return decided

    # -- views ---------------------------------------------------------

    def content_item(self, content_id: str) -> ContentItem:
        item = self._items.get(content_id)
        if item is None:
            raise UnknownContentError(f"unknown content: {content_id!r}")
        return item

    def review_record(self, review_id: str) -> ReviewRecord:
        record = self._reviews.get(review_id)
        if record is None:
            raise UnknownReviewError(f"unknown review: {review_id!r}")
        return record

    def action_record(self, action_id: str) -> ActionRecord:
        record = self._actions.get(action_id)
        if record is None:
            raise UnknownActionError(f"unknown action: {action_id!r}")
        return record

    def appeal_record(self, appeal_id: str) -> AppealRecord:
        record = self._appeals.get(appeal_id)
        if record is None:
            raise UnknownAppealError(f"unknown appeal: {appeal_id!r}")
        return record

    def actions_for(self, content_id: str) -> tuple[ActionRecord, ...]:
        _check_id(content_id, "content_id")
        if content_id not in self._items:
            raise UnknownContentError(f"unknown content: {content_id!r}")
        return tuple(a for a in self._actions.values()
                     if a.content_id == content_id)

    def audit_log(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self._audit_log)


def main() -> None:
    mod = ContentModerator()
    item = mod.submit(content_digest="sha256:" + "ab" * 32, seq=1, author="u1")
    rev = mod.review(item.content_id, 2,
                     [("spam", "medium"), ("harassment", "low")])
    act = mod.action(rev.review_id, 3, action="warn", reason="spam pattern")
    apl = mod.appeal(act.action_id, 4, grounds="false positive")
    mod.decide(apl.appeal_id, 5, outcome="upheld")
    assert rev.verdict == "flagged" and item.verify() and rev.verify()
    assert act.verify() and apl.verify()
    assert len(mod.audit_log()) == 5
    print("content-moderator OK: submit, review, action, appeal, decide, pins, audit")


__all__ = [
    "CONTENT_MODERATOR_VERSION",
    "CONTENT_MODERATOR_SCHEMA",
    "AUDIT_SCHEMA",
    "CATEGORIES",
    "SEVERITIES",
    "VERDICTS",
    "ACTIONS",
    "APPEAL_OUTCOMES",
    "ContentModeratorError",
    "UnknownContentError",
    "UnknownReviewError",
    "UnknownActionError",
    "UnknownAppealError",
    "BadInputError",
    "SeqOrderError",
    "TerminalActionError",
    "AppealStateError",
    "DisproportionateActionError",
    "ContentItem",
    "Finding",
    "ReviewRecord",
    "ActionRecord",
    "AppealRecord",
    "ContentModerator",
    "content_moderator_audit_event",
    "main",
]


if __name__ == "__main__":
    main()
