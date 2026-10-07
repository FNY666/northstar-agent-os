"""Abuse-prevention rate-limit rules: quotas, manual blocks, and appeals.

An ``AbuseLimits`` ledger books host-reported abuse-prevention decisions as
a deterministic single-host state machine:

- ``define_rule(rule_id, action, limit, window_seq, seq)`` pins a quota:
  at most ``limit`` ``action`` events per sliding window of ``window_seq``
  logical-seq units. ``max_strikes`` fail2ban-style: after that many
  *consecutive* quota-exceeded checks the subject is auto-blocked.
- ``check(subject, action, seq)`` returns a frozen ``CheckDecision``.
  ``allowed=False`` is *data* (the quota is spent); it is not raised.
  A blocked subject raises ``BlockedError`` fail-closed.
- ``block(subject, seq, reason)`` / ``unblock(subject, seq, reason)``
  manage manual terminal blocks.
- ``appeal(subject, seq, grounds)`` files an appeal; ``resolve_appeal``
  applies the host's upheld/overturned decision as data.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin ``abuse-limits.v1``,
schema pin ``northstar.abuse-limits.v1``, ``main()`` self-check.

Honest scope: this module books *host-reported* events and cannot
observe calls the host never reports, cannot distinguish a legit burst
of retries from an abuse burst, and cannot prove a block was
proportionate. A quiet ledger means "no known abuse shape", never "no
abuse". Auto-block fires on consecutive quota exceedances only; strike
triaging is the caller's job.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
ABUSE_LIMITS_VERSION = "abuse-limits.v1"

#: Schema pin carried by records and audit events.
ABUSE_LIMITS_SCHEMA = "northstar.abuse-limits.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_GENESIS = "genesis"


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AbuseLimitsError(ValueError):
    """Base for all abuse-limits structural problems and refused transitions."""


class BadRuleError(AbuseLimitsError):
    """Rule definition is malformed (bad id, limit, window, strikes)."""


class UnknownRuleError(AbuseLimitsError):
    """No rule is pinned for the requested action."""


class DuplicateRuleError(AbuseLimitsError):
    """A rule id is already registered."""


class BlockedError(AbuseLimitsError):
    """The subject is blocked; the action is refused fail-closed."""


class AlreadyBlockedError(AbuseLimitsError):
    """The subject is already blocked."""


class UnknownBlockError(AbuseLimitsError):
    """No active block for the subject."""


class UnknownAppealError(AbuseLimitsError):
    """No such appeal exists."""


class AppealStateError(AbuseLimitsError):
    """The appeal is already resolved."""


class SeqOrderError(AbuseLimitsError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AbuseLimitsError(f"{name} must be a non-empty string")
    return value.strip()


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([ABUSE_LIMITS_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleRecord:
    """One pinned quota rule (frozen)."""

    rule_id: str
    action: str
    limit: int
    window_seq: int
    max_strikes: int
    seq: int
    digest: str
    schema: str = ABUSE_LIMITS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "rule", self.rule_id, self.action, self.limit, self.window_seq,
            self.max_strikes, self.seq,
        )


@dataclass(frozen=True)
class CheckDecision:
    """One quota-check verdict (frozen). ``allowed=False`` is data."""

    subject: str
    action: str
    rule_id: str
    allowed: bool
    reason: str
    events_in_window: int
    limit: int
    consecutive_strikes: int
    seq: int
    digest: str
    schema: str = ABUSE_LIMITS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "check", self.subject, self.action, self.rule_id, self.allowed,
            self.reason, self.events_in_window, self.limit,
            self.consecutive_strikes, self.seq,
        )


@dataclass(frozen=True)
class BlockRecord:
    """One terminal block (frozen)."""

    subject: str
    reason: str
    seq: int
    automatic: bool
    digest: str
    schema: str = ABUSE_LIMITS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "block", self.subject, self.reason, self.seq, self.automatic
        )


@dataclass(frozen=True)
class UnblockRecord:
    """One block release (frozen)."""

    subject: str
    reason: str
    seq: int
    digest: str
    schema: str = ABUSE_LIMITS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("unblock", self.subject, self.reason, self.seq)


@dataclass(frozen=True)
class AppealRecord:
    """One filed appeal (frozen)."""

    appeal_id: str
    subject: str
    grounds: str
    seq: int
    resolved: bool
    overturned: bool
    digest: str
    schema: str = ABUSE_LIMITS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "appeal", self.appeal_id, self.subject, self.grounds, self.seq,
            self.resolved, self.overturned,
        )


@dataclass(frozen=True)
class AppealResolution:
    """One appeal decision (frozen). Overturned releases the block."""

    appeal_id: str
    subject: str
    overturned: bool
    seq: int
    digest: str
    schema: str = ABUSE_LIMITS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "resolve", self.appeal_id, self.subject, self.overturned, self.seq
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_RULE_DEFINED = "abuse-limit.rule-defined"
KIND_CHECKED = "abuse-limit.checked"
KIND_QUOTA_EXCEEDED = "abuse-limit.quota-exceeded"
KIND_BLOCKED = "abuse-limit.blocked"
KIND_UNBLOCKED = "abuse-limit.unblocked"
KIND_APPEAL_FILED = "abuse-limit.appeal-filed"
KIND_APPEAL_RESOLVED = "abuse-limit.appeal-resolved"
KIND_REJECTED = "abuse-limit.rejected"
_KINDS = (
    KIND_RULE_DEFINED, KIND_CHECKED, KIND_QUOTA_EXCEEDED, KIND_BLOCKED,
    KIND_UNBLOCKED, KIND_APPEAL_FILED, KIND_APPEAL_RESOLVED, KIND_REJECTED,
)


def abuse_limits_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the abuse-limits module."""
    if kind not in _KINDS:
        raise AbuseLimitsError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise AbuseLimitsError("detail must be a mapping")
    # Event counts never cross the audit boundary; pins only.
    banned = {"events", "history", "grounds"}
    if any(k in detail for k in banned):
        raise AbuseLimitsError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": ABUSE_LIMITS_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class AbuseLimits:
    """Deterministic abuse-prevention quota/block/appeal ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._rules: Dict[str, RuleRecord] = {}          # rule_id -> record
        self._rules_by_action: Dict[str, str] = {}       # action -> rule_id
        self._events: Dict[Tuple[str, str], List[int]] = {}  # (subject,action) -> seqs
        self._strikes: Dict[Tuple[str, str], int] = {}   # consecutive exceedances
        self._blocks: Dict[str, BlockRecord] = {}        # subject -> active block
        self._appeals: Dict[str, AppealRecord] = {}
        self._appeal_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _audit_locked(self, kind: str, detail: Mapping[str, Any]) -> None:
        self._audit.append(abuse_limits_audit_event(kind, detail, self._last_seq))

    def _reject_locked(self, reason: str) -> None:
        self._audit_locked(KIND_REJECTED, {"reason": reason})

    # -- rules ----------------------------------------------------------

    def define_rule(
        self,
        rule_id: str,
        action: str,
        limit: int,
        window_seq: int,
        seq: int,
        *,
        max_strikes: int = 0,
    ) -> RuleRecord:
        """Pin a quota rule: ``limit`` events per ``window_seq`` seq window."""
        with self._lock:
            rule_id = _check_nonempty_str(rule_id, "rule_id")
            action = _check_nonempty_str(action, "action")
            if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
                raise BadRuleError("limit must be a positive int")
            if isinstance(window_seq, bool) or not isinstance(window_seq, int) or window_seq <= 0:
                raise BadRuleError("window_seq must be a positive int")
            if isinstance(max_strikes, bool) or not isinstance(max_strikes, int) or max_strikes < 0:
                raise BadRuleError("max_strikes must be a non-negative int")
            self._claim_seq(seq)
            if rule_id in self._rules:
                self._reject_locked("duplicate-rule")
                raise DuplicateRuleError(f"rule {rule_id!r} already defined")
            record = RuleRecord(
                rule_id=rule_id, action=action, limit=limit,
                window_seq=window_seq, max_strikes=max_strikes, seq=seq,
                digest=_pin("rule", rule_id, action, limit, window_seq, max_strikes, seq),
            )
            self._rules[rule_id] = record
            self._rules_by_action[action] = rule_id
            self._audit_locked(
                KIND_RULE_DEFINED,
                {"rule_id": rule_id, "action": action, "digest": record.digest},
            )
            return record

    # -- checks ---------------------------------------------------------

    def check(self, subject: str, action: str, seq: int) -> CheckDecision:
        """Book one event attempt; return the quota verdict.

        ``allowed=False`` is data (quota spent), never raised. A blocked
        subject raises :class:`BlockedError` fail-closed.
        """
        with self._lock:
            subject = _check_nonempty_str(subject, "subject")
            action = _check_nonempty_str(action, "action")
            self._claim_seq(seq)
            if subject in self._blocks:
                self._reject_locked("blocked-subject")
                raise BlockedError(f"subject {subject!r} is blocked")
            rule_id = self._rules_by_action.get(action)
            if rule_id is None:
                self._reject_locked("unknown-rule")
                raise UnknownRuleError(f"no rule for action {action!r}")
            rule = self._rules[rule_id]
            key = (subject, action)
            window_start = seq - rule.window_seq
            recent = [s for s in self._events.get(key, []) if s > window_start]
            events_in_window = len(recent)
            strikes = self._strikes.get(key, 0)
            if events_in_window < rule.limit:
                allowed, reason = True, "within-quota"
                recent.append(seq)
                self._events[key] = recent
                self._strikes[key] = 0
                self._audit_locked(
                    KIND_CHECKED,
                    {"subject": subject, "action": action, "allowed": True},
                )
            else:
                allowed, reason = False, "quota-exceeded"
                strikes += 1
                self._strikes[key] = strikes
                self._audit_locked(
                    KIND_QUOTA_EXCEEDED,
                    {"subject": subject, "action": action, "rule_id": rule_id},
                )
                if rule.max_strikes and strikes >= rule.max_strikes:
                    self._auto_block_locked(subject, seq, rule)
            decision = CheckDecision(
                subject=subject, action=action, rule_id=rule_id,
                allowed=allowed, reason=reason,
                events_in_window=events_in_window + (1 if allowed else 0),
                limit=rule.limit, consecutive_strikes=self._strikes.get(key, 0),
                seq=seq,
                digest=_pin(
                    "check", subject, action, rule_id, allowed, reason,
                    events_in_window + (1 if allowed else 0), rule.limit,
                    self._strikes.get(key, 0), seq,
                ),
            )
            return decision

    def _auto_block_locked(self, subject: str, seq: int, rule: "RuleRecord") -> BlockRecord:
        record = BlockRecord(
            subject=subject,
            reason=f"auto-block: {rule.rule_id} strikes={self._strikes[(subject, rule.action)]}",
            seq=seq, automatic=True,
            digest=_pin(
                "block", subject,
                f"auto-block: {rule.rule_id} strikes={self._strikes[(subject, rule.action)]}",
                seq, True,
            ),
        )
        self._blocks[subject] = record
        self._audit_locked(
            KIND_BLOCKED,
            {"subject": subject, "automatic": True, "digest": record.digest},
        )
        return record

    # -- blocks ---------------------------------------------------------

    def block(self, subject: str, seq: int, reason: str) -> BlockRecord:
        """Place a manual terminal block on a subject."""
        with self._lock:
            subject = _check_nonempty_str(subject, "subject")
            reason = _check_nonempty_str(reason, "reason")
            self._claim_seq(seq)
            if subject in self._blocks:
                self._reject_locked("already-blocked")
                raise AlreadyBlockedError(f"subject {subject!r} already blocked")
            record = BlockRecord(
                subject=subject, reason=reason, seq=seq, automatic=False,
                digest=_pin("block", subject, reason, seq, False),
            )
            self._blocks[subject] = record
            self._audit_locked(
                KIND_BLOCKED,
                {"subject": subject, "automatic": False, "digest": record.digest},
            )
            return record

    def unblock(self, subject: str, seq: int, reason: str) -> UnblockRecord:
        """Release an active block."""
        with self._lock:
            subject = _check_nonempty_str(subject, "subject")
            reason = _check_nonempty_str(reason, "reason")
            self._claim_seq(seq)
            if subject not in self._blocks:
                self._reject_locked("unknown-block")
                raise UnknownBlockError(f"no active block for {subject!r}")
            del self._blocks[subject]
            # Clear strike counters so a fresh quota starts.
            for key in [k for k in self._strikes if k[0] == subject]:
                del self._strikes[key]
            record = UnblockRecord(
                subject=subject, reason=reason, seq=seq,
                digest=_pin("unblock", subject, reason, seq),
            )
            self._audit_locked(KIND_UNBLOCKED, {"subject": subject})
            return record

    def is_blocked(self, subject: str) -> bool:
        with self._lock:
            return _check_nonempty_str(subject, "subject") in self._blocks

    # -- appeals --------------------------------------------------------

    def appeal(self, subject: str, seq: int, grounds: str) -> AppealRecord:
        """File an appeal against an active block (pending; unresolved)."""
        with self._lock:
            subject = _check_nonempty_str(subject, "subject")
            grounds = _check_nonempty_str(grounds, "grounds")
            self._claim_seq(seq)
            if subject not in self._blocks:
                self._reject_locked("appeal-without-block")
                raise UnknownBlockError(f"no active block for {subject!r}")
            self._appeal_seq += 1
            appeal_id = f"apl-{self._appeal_seq}"
            record = AppealRecord(
                appeal_id=appeal_id, subject=subject, grounds=grounds,
                seq=seq, resolved=False, overturned=False,
                digest=_pin(
                    "appeal", appeal_id, subject, grounds, seq, False, False
                ),
            )
            self._appeals[appeal_id] = record
            self._audit_locked(
                KIND_APPEAL_FILED,
                {"appeal_id": appeal_id, "subject": subject},
            )
            return record

    def resolve_appeal(
        self, appeal_id: str, seq: int, *, overturned: bool
    ) -> AppealResolution:
        """Apply the host's appeal decision.

        ``overturned=True`` releases the block (if still active);
        ``False`` keeps it. The decision itself is recorded as data.
        """
        with self._lock:
            appeal_id = _check_nonempty_str(appeal_id, "appeal_id")
            if not isinstance(overturned, bool):
                raise AppealStateError("overturned must be a bool")
            self._claim_seq(seq)
            record = self._appeals.get(appeal_id)
            if record is None:
                self._reject_locked("unknown-appeal")
                raise UnknownAppealError(f"unknown appeal {appeal_id!r}")
            if record.resolved:
                self._reject_locked("appeal-already-resolved")
                raise AppealStateError(f"appeal {appeal_id!r} already resolved")
            resolved_record = AppealRecord(
                appeal_id=record.appeal_id, subject=record.subject,
                grounds=record.grounds, seq=record.seq,
                resolved=True, overturned=overturned,
                digest=_pin(
                    "appeal", record.appeal_id, record.subject, record.grounds,
                    record.seq, True, overturned,
                ),
            )
            self._appeals[appeal_id] = resolved_record
            if overturned and record.subject in self._blocks:
                del self._blocks[record.subject]
                for key in [k for k in self._strikes if k[0] == record.subject]:
                    del self._strikes[key]
                self._audit_locked(KIND_UNBLOCKED, {"subject": record.subject})
            resolution = AppealResolution(
                appeal_id=appeal_id, subject=record.subject,
                overturned=overturned, seq=seq,
                digest=_pin("resolve", appeal_id, record.subject, overturned, seq),
            )
            self._audit_locked(
                KIND_APPEAL_RESOLVED,
                {"appeal_id": appeal_id, "overturned": overturned},
            )
            return resolution

    # -- views ----------------------------------------------------------

    def rule(self, rule_id: str) -> RuleRecord:
        with self._lock:
            record = self._rules.get(_check_nonempty_str(rule_id, "rule_id"))
            if record is None:
                raise UnknownRuleError(f"unknown rule {rule_id!r}")
            return record

    def rule_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._rules))

    def blocked_subjects(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._blocks))

    def appeal_record(self, appeal_id: str) -> AppealRecord:
        with self._lock:
            record = self._appeals.get(_check_nonempty_str(appeal_id, "appeal_id"))
            if record is None:
                raise UnknownAppealError(f"unknown appeal {appeal_id!r}")
            return record

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    limits = AbuseLimits()
    rule = limits.define_rule("login-quota", "login", 3, 100, 1, max_strikes=2)
    assert rule.verify()
    d1 = limits.check("u1", "login", 2)
    assert d1.allowed and d1.verify()
    d2 = limits.check("u1", "login", 3)
    d3 = limits.check("u1", "login", 4)
    d4 = limits.check("u1", "login", 5)   # quota spent
    assert not d4.allowed and d4.reason == "quota-exceeded"
    d5 = limits.check("u1", "login", 6)   # second strike -> auto-block
    assert not d5.allowed
    assert limits.is_blocked("u1")
    try:
        limits.check("u1", "login", 7)
    except BlockedError:
        pass
    else:
        raise AssertionError("blocked subject must raise")
    appeal = limits.appeal("u1", 8, "shared ip")
    resolution = limits.resolve_appeal(appeal.appeal_id, 9, overturned=True)
    assert resolution.overturned and not limits.is_blocked("u1")
    # Manual block path
    blk = limits.block("u2", 10, "confirmed credential stuffing")
    assert blk.verify()
    limits.unblock("u2", 11, "ops review")
    print("abuse-limits OK: rule, quota, auto-block, appeal, manual block")
    return None


if __name__ == "__main__":
    main()
