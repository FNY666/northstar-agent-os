"""Policy document lifecycle governance (draft / approve / review bookkeeping, simulated).

Research note: in IT governance the policy *management* lifecycle is a
distinct layer from policy *enforcement*. NIST SP 800-53 (PM family),
ISO/IEC 27001 (A.5), and the ISACA/COBIT governance literature all
separate the accountable workflow around a policy document itself --
drafting the text, approving it through an accountable principal, and
periodically reviewing it (reaffirm or send back for revision) -- from
the runtime machinery that evaluates the policy's rules. This module
is that management layer, deliberately distinct from the siblings:

* ``policy_engine.py`` -- runtime policy evaluation/enforcement.
* ``policy_file.py`` -- policy file loading.
* ``password_policy.py`` / ``retry_policy.py`` / ``dataflow_policy.py``
  -- single-concern policy implementations.

Public API:

* ``draft(policy_id, seq, policy_class=..., body_digest=...)`` ->
  frozen ``DraftRecord``: books one policy draft. The first draft is
  version 1; re-drafting a policy that is back in ``drafted`` state
  (after a ``revise`` review) books a new version and keeps history.
  Drafting an ``approved`` policy is refused fail-closed -- the policy
  must be reviewed to ``revise`` first. Raw policy text never enters a
  record; it travels as a ``sha256:`` digest pin only.
* ``approve(policy_id, approver, seq, approval_digest=...)`` ->
  frozen ``ApprovalRecord``: books one approval decision by an
  accountable principal against the currently drafted version.
  Approving an already-``approved`` policy is refused fail-closed.
* ``review(policy_id, seq, outcome=..., review_digest=...)`` ->
  frozen ``ReviewRecord`` (minted ``rev-N`` ids): books one periodic
  governance review over the pinned outcome vocabulary
  ``reaffirm`` / ``revise``. ``reaffirm`` leaves the policy
  ``approved``; ``revise`` returns it to ``drafted``. History is kept.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs (claim-then-burn: failed mutations consume
their seq and book ``policy-management.rejected``; rewinds raise bare
without consuming), no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json``
try/except fallback, ``sha256:`` digest pins, and ``audit.ndjson/1``
events.

Honest scope: the module books *declared* governance decisions. It
cannot verify that a policy was actually read, cannot prove an
approval signature is valid, and cannot enforce a policy's rules. Raw
policy text, titles, and comments travel as digest pins only -- they
never enter records and never cross the audit boundary.
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
POLICY_MANAGEMENT_VERSION = "policy-management.v1"

#: Schema pin carried by records and audit events.
POLICY_MANAGEMENT_SCHEMA = "northstar.policy-management.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_DRAFTED = "policy-management.drafted"
KIND_APPROVED = "policy-management.approved"
KIND_REVIEWED = "policy-management.reviewed"
KIND_REJECTED = "policy-management.rejected"
_KINDS = frozenset({KIND_DRAFTED, KIND_APPROVED, KIND_REVIEWED, KIND_REJECTED})

#: Pinned policy-class vocabulary.
CLASS_SECURITY = "security"
CLASS_PRIVACY = "privacy"
CLASS_AI_GOVERNANCE = "ai-governance"
CLASS_COMPLIANCE = "compliance"
CLASS_OPERATIONAL = "operational"
CLASS_DATA_HANDLING = "data-handling"
_CLASSES = frozenset(
    {
        CLASS_SECURITY,
        CLASS_PRIVACY,
        CLASS_AI_GOVERNANCE,
        CLASS_COMPLIANCE,
        CLASS_OPERATIONAL,
        CLASS_DATA_HANDLING,
    }
)

#: Pinned review-outcome vocabulary.
OUTCOME_REAFFIRM = "reaffirm"
OUTCOME_REVISE = "revise"
_OUTCOMES = frozenset({OUTCOME_REAFFIRM, OUTCOME_REVISE})

#: Lifecycle states for a policy id.
STATE_DRAFTED = "drafted"
STATE_APPROVED = "approved"

#: Raw-text keys that may never cross the audit boundary (digest pins only).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "title",
        "body",
        "text",
        "rationale",
        "summary",
        "detail",
        "details",
        "description",
        "content",
        "raw",
        "payload",
        "value",
        "notes",
        "comments",
        "objective",
        "signature",
    }
)


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed: refuse, never guess)
# ---------------------------------------------------------------------------


class PolicyManagementError(Exception):
    """Base class for all policy-management errors."""


class BadPolicyError(PolicyManagementError):
    """Malformed policy id or metadata."""


class UnknownPolicyError(PolicyManagementError):
    """No draft has been booked for this policy id."""


class PolicyStateError(PolicyManagementError):
    """The policy is not in a state that allows this operation."""


class BadClassError(PolicyManagementError):
    """Policy class is not in the pinned vocabulary."""


class BadApproverError(PolicyManagementError):
    """Approver principal is malformed."""


class BadOutcomeError(PolicyManagementError):
    """Review outcome is not in the pinned vocabulary."""


class BadDigestError(PolicyManagementError):
    """A digest pin is malformed."""


class SeqOrderError(PolicyManagementError):
    """Caller seq is not a strictly increasing int."""


class AuditKindError(PolicyManagementError):
    """Unknown audit event kind, or a raw-text key hit the audit boundary."""


# ---------------------------------------------------------------------------
# Digest helpers (sha256: pins, type-tagged)
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    if _cj is not None:  # type: ignore[truthy-bool]
        data = _cj.jcs_dumps(obj)  # type: ignore[attr-defined]
        return data.encode("utf-8") if isinstance(data, str) else bytes(data)
    import json

    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest_pin(parts: Tuple[Any, ...], tag: str) -> str:
    return "sha256:" + hashlib.sha256(
        _canonical({"tag": tag, "parts": list(parts)})
    ).hexdigest()


def _check_digest(value: Any, name: str, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise BadDigestError(f"{name} must be a str")
    if value == "":
        if allow_empty:
            return ""
        raise BadDigestError(f"{name} must not be empty")
    if not value.startswith("sha256:") or len(value) != 7 + 64:
        raise BadDigestError(f"{name} must be a sha256:<64hex> pin")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{name} must be a sha256:<64hex> pin")
    return value


def _check_id(value: Any, name: str, max_len: int = 128) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise BadPolicyError(f"{name} must be a str")
    stripped = value.strip()
    if not stripped or len(stripped) > max_len:
        raise BadPolicyError(f"{name} must be 1..{max_len} chars")
    if any(ch.isspace() for ch in stripped):
        raise BadPolicyError(f"{name} must not contain whitespace")
    return stripped


def _check_approver(value: Any) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise BadApproverError("approver must be a str")
    stripped = value.strip()
    if not stripped or len(stripped) > 64:
        raise BadApproverError("approver must be 1..64 chars")
    if any(ch.isspace() for ch in stripped):
        raise BadApproverError("approver must not contain whitespace")
    return stripped


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be >= 0")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen; digest-pinned)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DraftRecord:
    policy_id: str
    policy_class: str
    version: int
    body_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": POLICY_MANAGEMENT_SCHEMA,
            "version": POLICY_MANAGEMENT_VERSION,
            "policy_id": self.policy_id,
            "policy_class": self.policy_class,
            "version_number": self.version,
            "body_digest": self.body_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.policy_id,
                self.policy_class,
                self.version,
                self.body_digest,
                self.seq,
            ),
            "policy-draft",
        )


@dataclass(frozen=True)
class ApprovalRecord:
    policy_id: str
    version: int
    approver: str
    approval_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": POLICY_MANAGEMENT_SCHEMA,
            "version": POLICY_MANAGEMENT_VERSION,
            "policy_id": self.policy_id,
            "version_number": self.version,
            "approver": self.approver,
            "approval_digest": self.approval_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.policy_id,
                self.version,
                self.approver,
                self.approval_digest,
                self.seq,
            ),
            "policy-approval",
        )


@dataclass(frozen=True)
class ReviewRecord:
    review_id: str
    policy_id: str
    version: int
    outcome: str
    review_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": POLICY_MANAGEMENT_SCHEMA,
            "version": POLICY_MANAGEMENT_VERSION,
            "review_id": self.review_id,
            "policy_id": self.policy_id,
            "version_number": self.version,
            "outcome": self.outcome,
            "review_digest": self.review_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.review_id,
                self.policy_id,
                self.version,
                self.outcome,
                self.review_digest,
                self.seq,
            ),
            "policy-review",
        )


@dataclass(frozen=True)
class PolicyStatus:
    policy_id: str
    state: str
    version: int
    approvals: int
    reviews: int
    latest_review_outcome: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": POLICY_MANAGEMENT_SCHEMA,
            "version": POLICY_MANAGEMENT_VERSION,
            "policy_id": self.policy_id,
            "state": self.state,
            "version_number": self.version,
            "approvals": self.approvals,
            "reviews": self.reviews,
            "latest_review_outcome": self.latest_review_outcome,
        }


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def policy_management_audit_event(
    audit_kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for the policy-management ledger."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    _check_seq(seq)
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(
                f"audit detail must not carry raw-text key {key!r}"
            )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": audit_kind,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# PolicyManagement: the policy-document governance ledger
# ---------------------------------------------------------------------------


class PolicyManagement:
    """Bookkeeping for the policy *document* lifecycle.

    Drafting, approval, and periodic review are booked as declared,
    digest-pinned decisions against pinned vocabularies. The ledger is a
    deterministic single-host state machine: no wall-clock, frozen
    records, fail-closed errors, ``sha256:`` digest pins, and
    ``audit.ndjson/1`` events for every transition (and every refusal).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._drafts: Dict[str, List[DraftRecord]] = {}
        self._approvals: Dict[str, List[ApprovalRecord]] = {}
        self._reviews: Dict[str, List[ReviewRecord]] = {}
        self._states: Dict[str, str] = {}
        self._review_counter = 0
        self._audit_events: List[Dict[str, Any]] = []

    # -- internals --------------------------------------------------------
    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq {seq} not strictly greater than {self._seq}"
            )
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(
            policy_management_audit_event(audit_kind, seq, **detail)
        )

    def _fail(self, seq: int, exc: PolicyManagementError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    def _require_known(self, policy_id: str) -> None:
        if policy_id not in self._drafts:
            raise UnknownPolicyError(f"unknown policy: {policy_id!r}")

    # -- mutations --------------------------------------------------------
    def draft(
        self,
        policy_id: str,
        seq: int,
        policy_class: str = CLASS_SECURITY,
        body_digest: str = "",
    ) -> DraftRecord:
        """Book one policy draft. First draft is version 1; re-drafting a
        policy that is back in ``drafted`` state (after a ``revise``
        review) books a new version and keeps history. Drafting an
        ``approved`` policy is refused fail-closed."""
        with self._lock:
            seq = self._claim(seq)
            try:
                policy_id = _check_id(policy_id, "policy_id")
                if policy_class not in _CLASSES:
                    raise BadClassError(
                        f"policy_class must be one of {sorted(_CLASSES)}"
                    )
                body_digest = _check_digest(
                    body_digest, "body_digest", allow_empty=True
                )
                if policy_id in self._drafts:
                    if self._states[policy_id] != STATE_DRAFTED:
                        raise PolicyStateError(
                            f"policy {policy_id!r} is approved; "
                            "review it to 'revise' before re-drafting"
                        )
                    version = self._drafts[policy_id][-1].version + 1
                else:
                    version = 1
            except PolicyManagementError as exc:
                self._fail(seq, exc, policy_id=str(policy_id))
            record = DraftRecord(
                policy_id=policy_id,
                policy_class=policy_class,
                version=version,
                body_digest=body_digest,
                seq=seq,
                digest=_digest_pin(
                    (policy_id, policy_class, version, body_digest, seq),
                    "policy-draft",
                ),
            )
            self._drafts.setdefault(policy_id, []).append(record)
            self._approvals.setdefault(policy_id, [])
            self._reviews.setdefault(policy_id, [])
            self._states[policy_id] = STATE_DRAFTED
            self._emit(
                KIND_DRAFTED,
                seq,
                policy_id=policy_id,
                policy_class=policy_class,
                version_number=version,
                body_digest=body_digest,
                record_digest=record.digest,
            )
            return record

    def approve(
        self,
        policy_id: str,
        approver: str,
        seq: int,
        approval_digest: str = "",
    ) -> ApprovalRecord:
        """Book one approval decision against the currently drafted
        version. Refuses unknown policies, malformed approvers, and
        re-approval of an already-approved policy."""
        with self._lock:
            seq = self._claim(seq)
            try:
                policy_id = _check_id(policy_id, "policy_id")
                self._require_known(policy_id)
                if self._states[policy_id] != STATE_DRAFTED:
                    raise PolicyStateError(
                        f"policy {policy_id!r} is already approved"
                    )
                approver = _check_approver(approver)
                approval_digest = _check_digest(
                    approval_digest, "approval_digest", allow_empty=True
                )
            except PolicyManagementError as exc:
                self._fail(seq, exc, policy_id=str(policy_id))
            version = self._drafts[policy_id][-1].version
            record = ApprovalRecord(
                policy_id=policy_id,
                version=version,
                approver=approver,
                approval_digest=approval_digest,
                seq=seq,
                digest=_digest_pin(
                    (policy_id, version, approver, approval_digest, seq),
                    "policy-approval",
                ),
            )
            self._approvals[policy_id].append(record)
            self._states[policy_id] = STATE_APPROVED
            self._emit(
                KIND_APPROVED,
                seq,
                policy_id=policy_id,
                version_number=version,
                approver=approver,
                approval_digest=approval_digest,
                record_digest=record.digest,
            )
            return record

    def review(
        self,
        policy_id: str,
        seq: int,
        outcome: str = OUTCOME_REAFFIRM,
        review_digest: str = "",
    ) -> ReviewRecord:
        """Book one periodic governance review. Requires an ``approved``
        policy. ``reaffirm`` leaves it approved; ``revise`` returns it
        to ``drafted``. History is kept."""
        with self._lock:
            seq = self._claim(seq)
            try:
                policy_id = _check_id(policy_id, "policy_id")
                self._require_known(policy_id)
                if self._states[policy_id] != STATE_APPROVED:
                    raise PolicyStateError(
                        f"policy {policy_id!r} is not approved; "
                        "review requires an approved policy"
                    )
                if outcome not in _OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(_OUTCOMES)}"
                    )
                review_digest = _check_digest(
                    review_digest, "review_digest", allow_empty=True
                )
            except PolicyManagementError as exc:
                self._fail(seq, exc, policy_id=str(policy_id))
            self._review_counter += 1
            review_id = f"rev-{self._review_counter}"
            version = self._drafts[policy_id][-1].version
            record = ReviewRecord(
                review_id=review_id,
                policy_id=policy_id,
                version=version,
                outcome=outcome,
                review_digest=review_digest,
                seq=seq,
                digest=_digest_pin(
                    (
                        review_id,
                        policy_id,
                        version,
                        outcome,
                        review_digest,
                        seq,
                    ),
                    "policy-review",
                ),
            )
            self._reviews[policy_id].append(record)
            self._states[policy_id] = (
                STATE_APPROVED if outcome == OUTCOME_REAFFIRM else STATE_DRAFTED
            )
            self._emit(
                KIND_REVIEWED,
                seq,
                review_id=review_id,
                policy_id=policy_id,
                version_number=version,
                outcome=outcome,
                review_digest=review_digest,
                record_digest=record.digest,
            )
            return record

    # -- pure-read views --------------------------------------------------
    def _view_seq_ok(self, seq: Any) -> None:
        _check_seq(seq)

    def draft_record(self, policy_id: str, seq: int) -> DraftRecord:
        """Return the latest draft record. Pure read."""
        self._view_seq_ok(seq)
        history = self._drafts.get(policy_id)
        if history is None:
            raise UnknownPolicyError(f"unknown policy: {policy_id!r}")
        return history[-1]

    def draft_history(self, policy_id: str, seq: int) -> Tuple[DraftRecord, ...]:
        """Return all draft versions, oldest first. Pure read."""
        self._view_seq_ok(seq)
        history = self._drafts.get(policy_id)
        if history is None:
            raise UnknownPolicyError(f"unknown policy: {policy_id!r}")
        return tuple(history)

    def approval_history(
        self, policy_id: str, seq: int
    ) -> Tuple[ApprovalRecord, ...]:
        """Return the approval decisions, oldest first. Pure read."""
        self._view_seq_ok(seq)
        history = self._approvals.get(policy_id)
        if history is None:
            raise UnknownPolicyError(f"unknown policy: {policy_id!r}")
        return tuple(history)

    def review_history(
        self, policy_id: str, seq: int
    ) -> Tuple[ReviewRecord, ...]:
        """Return the review records, oldest first. Pure read."""
        self._view_seq_ok(seq)
        history = self._reviews.get(policy_id)
        if history is None:
            raise UnknownPolicyError(f"unknown policy: {policy_id!r}")
        return tuple(history)

    def status(self, policy_id: str, seq: int) -> PolicyStatus:
        """Return a digest-free status snapshot. Pure read."""
        self._view_seq_ok(seq)
        record = self.draft_record(policy_id, seq)
        reviews = self._reviews[policy_id]
        return PolicyStatus(
            policy_id=record.policy_id,
            state=self._states[policy_id],
            version=record.version,
            approvals=len(self._approvals[policy_id]),
            reviews=len(reviews),
            latest_review_outcome=reviews[-1].outcome if reviews else "",
        )

    def policy_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted policy ids with a draft booked. Pure read."""
        self._view_seq_ok(seq)
        return tuple(sorted(self._drafts))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counters. Pure read."""
        self._view_seq_ok(seq)
        return {
            "schema": POLICY_MANAGEMENT_SCHEMA,
            "version": POLICY_MANAGEMENT_VERSION,
            "policies": len(self._drafts),
            "drafts": sum(len(v) for v in self._drafts.values()),
            "approvals": sum(len(v) for v in self._approvals.values()),
            "reviews": self._review_counter,
            "audit_events": len(self._audit_events),
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """The booked audit events. Pure read."""
        self._view_seq_ok(seq)
        return tuple(self._audit_events)


def main() -> None:
    ledger = PolicyManagement()
    digest = "sha256:" + hashlib.sha256(b"policy-body").hexdigest()
    ledger.draft("POL-001", 1, policy_class="ai-governance", body_digest=digest)
    ledger.approve("POL-001", "ai-governance-board", 2, approval_digest=digest)
    ledger.review("POL-001", 3, outcome="reaffirm", review_digest=digest)
    status = ledger.status("POL-001", 4)
    assert status.state == "approved"
    assert status.version == 1
    assert status.approvals == 1 and status.reviews == 1
    assert status.latest_review_outcome == "reaffirm"
    assert ledger.stats(5)["policies"] == 1
    print("policy-management OK: draft, approve, review, pins, audit")


if __name__ == "__main__":
    main()
