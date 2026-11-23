"""AI governance framework ledger: adopt policies, enforce them, report.

Research motivation: every operational AI governance framework -- the
NIST AI Risk Management Framework (Govern/Map/Measure/Manage), the OECD
AI Principles (accountability, transparency, human-centred values), and
the EU AI Act's risk-based obligations -- reduces to one bookkeeping
shape: an organization *adopts* a governance policy (principles pinned
to a framework), *enforces* decisions against that policy against named
targets, and *reports* the resulting compliance posture. The policy is a
declaration; each enforcement is a booked decision; the report is a
deterministic read of the ledger.

This module is the *governance ledger* half of that shape -- deliberately
distinct from the siblings:

- ``scalable_oversight.py`` owns the oversight *protocol* (approve /
  deny / route / review triage for individual actions);
- ``oversight_board.py`` owns the board *adjudication* layer
  (review / decide / appeal);
- ``policy_engine.py`` owns rule-level *evaluation* (rule / evaluate /
  enforce per-request);
- this module owns the framework *lifecycle*: which governance policies
  are adopted, which enforcement decisions were booked against them,
  and the resulting compliance posture.

Public API:

- ``Governance.policy(policy_id, title, seq, principles=(), owner="",
  framework="nist-ai-rmf")`` -- adopt a governance policy. Title and
  principles are host-declared; the record pins a digest over
  (policy_id, framework, sorted principles) so adoption is
  tamper-evident. Duplicate ids refused fail-closed; retired ids are
  never recycled.
- ``Governance.enforce(policy_id, target_id, seq, verdict="compliant",
  action_digest="")`` -- book one enforcement decision against an
  adopted policy for a named target (a model, a deployment, an agent).
  The verdict is *data* over the pinned vocabulary
  (``compliant`` / ``violation`` / ``remediation-required``), never a
  finding of fact about any real system; the action is digest-pinned.
  Unknown or retired policies refused fail-closed.
- ``Governance.report(policy_id, seq)`` -- pure read view (seq shape
  validated, never consumed, no audit row): per-verdict counts,
  compliance rate as exact ``num/den`` text, and the ordered
  enforcement ids.
- ``Governance.retire(policy_id, seq, reason="manual")`` -- terminal;
  the policy id is retired forever and later enforcement refuses
  (``RetiredPolicyError``).
- ``governance_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``policy-adopted`` / ``enforced`` / ``retired`` / ``rejected``).
  Raw policy text never crosses the audit boundary: audit rows carry
  ids, framework, verdicts, and counts only.

Fail-closed edges (fail loudly, never guess):

- ``policy_id`` / ``target_id`` must be non-empty str, <= 256 chars,
  no whitespace.
- ``framework`` must be one of ``nist-ai-rmf`` / ``oecd`` /
  ``eu-ai-act`` / ``custom``.
- ``verdict`` must be ``compliant`` / ``violation`` /
  ``remediation-required``.
- ``action_digest`` must be ``sha256:<64hex>`` when supplied.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.
- Raw titles, principle text, and evidence never enter records or the
  audit boundary -- digests and counts only.

Honest scope:

- This module books *declared* governance policies, *host-reported*
  enforcement decisions, and deterministic aggregates. A booked
  ``compliant`` verdict means the host reported compliance -- the
  module inspected no system, ran no audit, and proves nothing about
  real-world governance posture.
- A report's compliance rate is ledger arithmetic over host-declared
  verdicts, never an independent assessment.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if governance state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from fractions import Fraction
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
GOVERNANCE_VERSION = "governance.v1"

#: Schema pin carried by records and audit events.
GOVERNANCE_SCHEMA = "northstar.governance.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_POLICY_ADOPTED = "policy-adopted"
KIND_ENFORCED = "enforced"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_POLICY_ADOPTED, KIND_ENFORCED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw text never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"title", "principle", "principles", "text", "content", "raw",
     "payload", "evidence", "justification", "action", "statement",
     "description", "value"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned framework vocabulary. Labels, not certifications.
FRAMEWORK_NIST = "nist-ai-rmf"
FRAMEWORK_OECD = "oecd"
FRAMEWORK_EU_AI_ACT = "eu-ai-act"
FRAMEWORK_CUSTOM = "custom"
FRAMEWORKS = (FRAMEWORK_NIST, FRAMEWORK_OECD, FRAMEWORK_EU_AI_ACT,
              FRAMEWORK_CUSTOM)

#: Pinned enforcement-verdict vocabulary. Verdicts are host-reported data.
VERDICT_COMPLIANT = "compliant"
VERDICT_VIOLATION = "violation"
VERDICT_REMEDIATION_REQUIRED = "remediation-required"
VERDICTS = (VERDICT_COMPLIANT, VERDICT_VIOLATION, VERDICT_REMEDIATION_REQUIRED)

#: Pinned retire-reason vocabulary.
REASON_MANUAL = "manual"
REASON_SUPERSEDED = "superseded"
REASON_EXPIRED = "expired"
RETIRE_REASONS = (REASON_MANUAL, REASON_SUPERSEDED, REASON_EXPIRED)

#: Regex for a well-formed sha256 digest pin.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: Max principle list length.
_MAX_PRINCIPLES = 64


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class GovernanceError(Exception):
    """Base error for the governance module."""


class BadPolicyError(GovernanceError):
    """Malformed policy id."""


class DuplicatePolicyError(GovernanceError):
    """Policy id already adopted."""


class UnknownPolicyError(GovernanceError):
    """Policy id not adopted."""


class RetiredPolicyError(GovernanceError):
    """Policy id was retired; never recycled."""


class BadFrameworkError(GovernanceError):
    """Framework outside the pinned vocabulary."""


class BadPrincipleError(GovernanceError):
    """Malformed principle entry."""


class BadTargetError(GovernanceError):
    """Malformed target id."""


class BadVerdictError(GovernanceError):
    """Verdict outside the pinned vocabulary."""


class BadDigestError(GovernanceError):
    """Malformed sha256 digest pin."""


class BadReasonError(GovernanceError):
    """Retire reason outside the pinned vocabulary."""


class SeqOrderError(GovernanceError):
    """Seq not a strictly increasing int."""


class AuditKindError(GovernanceError):
    """Audit kind outside the pinned vocabulary."""


# ---------------------------------------------------------------------------
# Records (frozen dataclasses)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyRecord:
    """One adopted governance policy."""
    policy_id: str
    title_digest: str
    framework: str
    principles: Tuple[str, ...]
    owner: str
    seq: int
    digest: str
    schema: str = GOVERNANCE_SCHEMA
    version: str = GOVERNANCE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "title_digest": self.title_digest,
            "framework": self.framework,
            "principles": list(self.principles),
            "owner": self.owner,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        """Recompute the tamper-evident pin."""
        return self.digest == _policy_digest(
            self.policy_id, self.framework, self.principles,
            self.title_digest)


@dataclass(frozen=True)
class EnforcementRecord:
    """One booked enforcement decision against an adopted policy."""
    enforcement_id: str
    policy_id: str
    target_id: str
    verdict: str
    action_digest: str
    seq: int
    digest: str
    schema: str = GOVERNANCE_SCHEMA
    version: str = GOVERNANCE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "enforcement_id": self.enforcement_id,
            "policy_id": self.policy_id,
            "target_id": self.target_id,
            "verdict": self.verdict,
            "action_digest": self.action_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _enforcement_digest(
            self.policy_id, self.target_id, self.verdict,
            self.action_digest)


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a policy id."""
    policy_id: str
    reason: str
    seq: int
    digest: str
    schema: str = GOVERNANCE_SCHEMA
    version: str = GOVERNANCE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _retire_digest(self.policy_id, self.reason)


@dataclass(frozen=True)
class GovernanceReport:
    """Pure read view of a policy's compliance posture (data, not findings)."""
    policy_id: str
    enforcement_count: int
    compliant_count: int
    violation_count: int
    remediation_count: int
    compliance_rate_text: str  # exact "num/den", Fraction-normalized
    enforcement_ids: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = GOVERNANCE_SCHEMA
    version: str = GOVERNANCE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "enforcement_count": self.enforcement_count,
            "compliant_count": self.compliant_count,
            "violation_count": self.violation_count,
            "remediation_count": self.remediation_count,
            "compliance_rate_text": self.compliance_rate_text,
            "enforcement_ids": list(self.enforcement_ids),
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _report_digest(
            self.policy_id, self.compliant_count, self.enforcement_count,
            self.enforcement_ids)


# ---------------------------------------------------------------------------
# Digest pins
# ---------------------------------------------------------------------------

def _pin(value: Any) -> str:
    return "sha256:" + jcs_sha256_hex(value)


def _policy_digest(policy_id: str, framework: str,
                   principles: Tuple[str, ...], title_digest: str) -> str:
    return _pin({"policy_id": policy_id, "framework": framework,
                 "principles": sorted(principles),
                 "title_digest": title_digest})


def _enforcement_digest(policy_id: str, target_id: str, verdict: str,
                        action_digest: str) -> str:
    return _pin({"policy_id": policy_id, "target_id": target_id,
                 "verdict": verdict, "action_digest": action_digest})


def _retire_digest(policy_id: str, reason: str) -> str:
    return _pin({"policy_id": policy_id, "reason": reason})


def _report_digest(policy_id: str, compliant: int, total: int,
                   ids: Tuple[str, ...]) -> str:
    return _pin({"policy_id": policy_id, "compliant": compliant,
                 "total": total, "enforcement_ids": sorted(ids)})


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _check_id(value: Any, err: type) -> str:
    if not isinstance(value, str) or not value:
        raise err(f"bad id: {value!r}")
    if len(value) > _MAX_ID_LEN or any(c.isspace() for c in value):
        raise err(f"bad id: {value!r}")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"bad seq: {seq!r}")
    if seq < 0:
        raise SeqOrderError(f"bad seq: {seq!r}")
    return seq


def _check_digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise BadDigestError(f"bad digest pin: {value!r}")
    return value


def governance_audit_event(kind: str, seq: int,
                           **details: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event for the governance ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"bad audit kind: {kind!r}")
    _check_seq(seq)
    for key in details:
        if key in _BANNED_DETAIL_KEYS:
            raise AuditKindError(f"audit detail key banned: {key!r}")
    return {
        "kind": kind,
        "audit_seq": seq,
        "schema": AUDIT_SCHEMA,
        "version": GOVERNANCE_VERSION,
        "detail": dict(details),
    }


# ---------------------------------------------------------------------------
# Governance
# ---------------------------------------------------------------------------

class Governance:
    """AI governance framework ledger.

    Adopts policies, books enforcement decisions against them, and
    reports compliance posture as data. Deterministic, in-memory,
    fail-closed; no wall-clock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._policies: Dict[str, PolicyRecord] = {}
        self._enforcements: Dict[str, EnforcementRecord] = {}
        self._enforcement_ids: Tuple[str, ...] = ()
        self._by_policy: Dict[str, Tuple[str, ...]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._last_seq = -1
        self._audit_events: list = []

    # -- internals ---------------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq not increasing: {seq!r}")
        self._last_seq = seq
        return seq

    def _burn(self, seq: int) -> None:
        """Claim the seq even for a failed mutation (batch-21 discipline)."""
        self._last_seq = max(self._last_seq, seq)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit_events.append(
            governance_audit_event(audit_kind, seq, **details))

    def _require_live_policy(self, policy_id: str) -> PolicyRecord:
        if policy_id in self._retired:
            raise RetiredPolicyError(f"policy retired: {policy_id!r}")
        try:
            return self._policies[policy_id]
        except KeyError:
            raise UnknownPolicyError(f"unknown policy: {policy_id!r}")

    # -- public API ---------------------------------------------------------

    def policy(self, policy_id: str, title: str, seq: int,
               principles: Tuple[str, ...] = (), owner: str = "",
               framework: str = FRAMEWORK_NIST) -> PolicyRecord:
        """Adopt one governance policy (frozen PolicyRecord)."""
        seq = self._claim(seq)
        try:
            _check_id(policy_id, BadPolicyError)
            if policy_id in self._retired:
                raise RetiredPolicyError(f"policy retired: {policy_id!r}")
            if policy_id in self._policies:
                raise DuplicatePolicyError(f"duplicate policy: {policy_id!r}")
            if not isinstance(title, str) or not title.strip():
                raise BadPolicyError(f"bad title: {title!r}")
            if framework not in FRAMEWORKS:
                raise BadFrameworkError(f"bad framework: {framework!r}")
            if not isinstance(principles, (tuple, list)):
                raise BadPrincipleError(f"bad principles: {principles!r}")
            if len(principles) > _MAX_PRINCIPLES:
                raise BadPrincipleError(
                    f"too many principles: {len(principles)}")
            for p in principles:
                if not isinstance(p, str) or not p.strip():
                    raise BadPrincipleError(f"bad principle: {p!r}")
            if not isinstance(owner, str):
                raise BadPolicyError(f"bad owner: {owner!r}")
            pins = tuple(sorted(set(principles)))
            title_digest = _pin({"title": title})
            record = PolicyRecord(
                policy_id=policy_id,
                title_digest=title_digest,
                framework=framework,
                principles=pins,
                owner=owner,
                seq=seq,
                digest=_policy_digest(policy_id, framework, pins,
                                      title_digest),
            )
            self._policies[policy_id] = record
            self._by_policy[policy_id] = ()
            self._emit(KIND_POLICY_ADOPTED, seq, policy_id=policy_id,
                       framework=framework, principle_count=len(pins))
            return record
        except GovernanceError:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq, op="policy",
                       policy_id=(policy_id if isinstance(policy_id, str)
                                   else ""))
            raise

    def enforce(self, policy_id: str, target_id: str, seq: int,
                verdict: str = VERDICT_COMPLIANT,
                action_digest: str = "") -> EnforcementRecord:
        """Book one enforcement decision (frozen EnforcementRecord)."""
        seq = self._claim(seq)
        try:
            _check_id(policy_id, BadPolicyError)
            _check_id(target_id, BadTargetError)
            self._require_live_policy(policy_id)
            if verdict not in VERDICTS:
                raise BadVerdictError(f"bad verdict: {verdict!r}")
            if action_digest:
                _check_digest(action_digest)
            enforcement_id = f"enf-{len(self._enforcement_ids) + 1}"
            record = EnforcementRecord(
                enforcement_id=enforcement_id,
                policy_id=policy_id,
                target_id=target_id,
                verdict=verdict,
                action_digest=action_digest,
                seq=seq,
                digest=_enforcement_digest(policy_id, target_id, verdict,
                                           action_digest),
            )
            self._enforcements[enforcement_id] = record
            self._enforcement_ids = self._enforcement_ids + (enforcement_id,)
            self._by_policy[policy_id] = (
                self._by_policy[policy_id] + (enforcement_id,))
            self._emit(KIND_ENFORCED, seq, policy_id=policy_id,
                       enforcement_id=enforcement_id, verdict=verdict)
            return record
        except GovernanceError:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq, op="enforce",
                       policy_id=(policy_id if isinstance(policy_id, str)
                                   else ""))
            raise

    def report(self, policy_id: str, seq: int) -> GovernanceReport:
        """Pure read view of a policy's compliance posture."""
        _check_seq(seq)
        with self._lock:
            _check_id(policy_id, BadPolicyError)
            if policy_id not in self._policies:
                raise UnknownPolicyError(f"unknown policy: {policy_id!r}")
            ids = self._by_policy.get(policy_id, ())
            compliant = sum(1 for i in ids
                            if self._enforcements[i].verdict
                            == VERDICT_COMPLIANT)
            violation = sum(1 for i in ids
                            if self._enforcements[i].verdict
                            == VERDICT_VIOLATION)
            remediation = sum(1 for i in ids
                              if self._enforcements[i].verdict
                              == VERDICT_REMEDIATION_REQUIRED)
            total = len(ids)
            rate = Fraction(compliant, total if total else 1)
            return GovernanceReport(
                policy_id=policy_id,
                enforcement_count=total,
                compliant_count=compliant,
                violation_count=violation,
                remediation_count=remediation,
                compliance_rate_text=f"{rate.numerator}/{rate.denominator}",
                enforcement_ids=tuple(sorted(ids)),
                seq=seq,
                digest=_report_digest(policy_id, compliant, total,
                                      tuple(sorted(ids))),
            )

    def retire(self, policy_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire a policy id (never recycled)."""
        seq = self._claim(seq)
        try:
            _check_id(policy_id, BadPolicyError)
            if policy_id in self._retired:
                raise RetiredPolicyError(f"policy retired: {policy_id!r}")
            if policy_id not in self._policies:
                raise UnknownPolicyError(f"unknown policy: {policy_id!r}")
            if reason not in RETIRE_REASONS:
                raise BadReasonError(f"bad reason: {reason!r}")
            record = RetireRecord(policy_id=policy_id, reason=reason,
                                  seq=seq,
                                  digest=_retire_digest(policy_id, reason))
            self._retired[policy_id] = record
            self._emit(KIND_RETIRED, seq, policy_id=policy_id, reason=reason)
            return record
        except GovernanceError:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq, op="retire",
                       policy_id=(policy_id if isinstance(policy_id, str)
                                   else ""))
            raise

    # -- views ---------------------------------------------------------------

    def policy_record(self, policy_id: str, seq: int) -> PolicyRecord:
        """Pure read view of one adopted policy."""
        _check_seq(seq)
        with self._lock:
            _check_id(policy_id, BadPolicyError)
            try:
                return self._policies[policy_id]
            except KeyError:
                raise UnknownPolicyError(f"unknown policy: {policy_id!r}")

    def enforcement_record(self, enforcement_id: str,
                           seq: int) -> EnforcementRecord:
        """Pure read view of one enforcement decision."""
        _check_seq(seq)
        with self._lock:
            _check_id(enforcement_id, BadPolicyError)
            try:
                return self._enforcements[enforcement_id]
            except KeyError:
                raise UnknownPolicyError(
                    f"unknown enforcement: {enforcement_id!r}")

    def policy_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of adopted policy ids (sorted)."""
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._policies))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of retired policy ids (sorted)."""
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, int]:
        """Pure read view of ledger counts."""
        _check_seq(seq)
        with self._lock:
            return {
                "policies": len(self._policies),
                "enforcements": len(self._enforcements),
                "retired": len(self._retired),
                "audit_events": len(self._audit_events),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read view of the audit event list."""
        _check_seq(seq)
        with self._lock:
            return tuple(dict(e) for e in self._audit_events)


def main() -> None:
    gov = Governance()
    rec = gov.policy("g1", "Model release policy", 1,
                     principles=("human-oversight", "red-team"),
                     framework=FRAMEWORK_NIST)
    assert rec.verify()
    enf = gov.enforce("g1", "model-x", 2, verdict=VERDICT_VIOLATION,
                      action_digest=_pin({"release": "v2"}))
    assert enf.verify()
    rpt = gov.report("g1", 3)
    assert rpt.compliance_rate_text == "0/1"
    assert rpt.verify()
    gov.retire("g1", 4, reason=REASON_SUPERSEDED)
    print("governance OK: policy, enforce, report, retire, pins, audit")


if __name__ == "__main__":
    main()
