"""AI policy declaration/enforcement decision ledger: declare policies, book enforcements.

Research motivation: AI policy work (acceptable-use policies, safety
policies, data-handling policies, deployment policies) reduces to one
operational bookkeeping shape: a named AI *system* has *declared*
policies governing it, and *declared* enforcement actions booked
against those policies with host-reported verdicts. This module books
that shape as data.

This module is deliberately distinct from the sibling layers:

- ``governance.py`` owns the *framework* policy lifecycle (adopt a
  framework policy -> enforce verdicts -> compliance report), keyed by
  policy id and shaped by external frameworks (NIST AI RMF, OECD AI
  Principles, EU AI Act);
- ``policy_engine.py`` owns rule-level evaluation *mechanics* (load a
  policy -> evaluate conditions/rules -> decision report);
- ``ai_governance.py`` owns the *operations* ledger (declared
  governance controls -> declared audit decisions -> posture);
- this module owns the *per-system policy* decision ledger: which AI
  policies were declared over named deployed AI systems, which
  enforcement actions were booked against them, and the derived
  posture -- all as data, never evidence.

Public API:

- ``AIPolicy.declare(system_id, seq, policy_kind=..., status=...,
  policy_digest="")`` -- declare one AI policy over a named system
  (minted ``pol-N``). First declare registers the system. Policy kind
  from the pinned 8-term vocabulary; status from the pinned 4-term
  vocabulary -- booked *as data*, never proof a policy is enforced.
  Raw policy text never enters records: digest pins only.
- ``AIPolicy.enforce(system_id, seq, enforcement_kind=...,
  verdict=..., enforcement_digest="")`` -- book one declared
  enforcement action (minted ``enf-N``). Enforcement kind from the
  pinned 8-term vocabulary; verdict from the pinned 4-term vocabulary
  -- booked *as data*, never proof of a real enforcement. Fail-closed
  on unknown or retired systems.
- ``AIPolicy.verify(enforcement_id, seq)`` -- pure read: re-derives
  the digest pin of one enforcement record; verdict pinned
  ``verified`` / ``tampered`` as data (tamper reported, never
  raised). Seq shape-validated, never consumed, no audit row.
- ``AIPolicy.report(seq, system_id="")`` -- pure read: derived policy
  posture as data for one system or the whole ledger.
- ``AIPolicy.retire(system_id, seq, reason="manual")`` -- terminal;
  the system id is retired forever and later declare/enforce calls
  refuse; reads still work; ids never recycled.
- ``ai_policy_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``policy-declared`` / ``enforced`` / ``retired`` / ``rejected``).
  Raw policy text never crosses the audit boundary: ids, pinned
  vocabulary values, and counts only.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``policy_kind`` must be one of the pinned 8 policy kinds.
- ``status`` must be one of the pinned 4 statuses.
- ``enforcement_kind`` must be one of the pinned 8 enforcement kinds.
- ``verdict`` must be one of the pinned 4 verdicts.
- digests must be ``sha256:<64hex>`` when supplied.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* policies, *host-reported* enforcement
  verdicts, and deterministic aggregates. A booked ``compliant``
  verdict means the host reported compliance -- the module enforced
  nothing, inspected no system, and proves nothing about real-world
  policy compliance.
- Digest pins prove record integrity, never policy effectiveness.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if policy state must survive a restart.
"""

from __future__ import annotations

import ast
import hashlib
import re
import sys
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
AI_POLICY_VERSION = "ai-policy.v1"

#: Schema pin carried by records and audit events.
AI_POLICY_SCHEMA = "northstar.ai-policy.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_POLICY_DECLARED = "policy-declared"
KIND_ENFORCED = "enforced"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_POLICY_DECLARED, KIND_ENFORCED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw policy material never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"policy", "policy_text", "document", "evidence", "transcript",
     "weights", "model", "model_weights", "trace", "log", "payload",
     "content", "raw", "attachment", "notes", "justification"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned policy-kind vocabulary. Labels, not certifications.
POLICY_USAGE = "usage-policy"
POLICY_SAFETY = "safety-policy"
POLICY_DATA = "data-policy"
POLICY_DEPLOYMENT = "deployment-policy"
POLICY_ACCESS = "access-policy"
POLICY_MONITORING = "monitoring-policy"
POLICY_INCIDENT = "incident-policy"
POLICY_RETENTION = "retention-policy"
POLICY_KINDS = (
    POLICY_USAGE,
    POLICY_SAFETY,
    POLICY_DATA,
    POLICY_DEPLOYMENT,
    POLICY_ACCESS,
    POLICY_MONITORING,
    POLICY_INCIDENT,
    POLICY_RETENTION,
)

#: Pinned policy-status vocabulary. Host-reported data, never proof.
STATUS_ACTIVE = "active"
STATUS_DRAFT = "draft"
STATUS_SUSPENDED = "suspended"
STATUS_SUPERSEDED = "superseded"
STATUSES = (STATUS_ACTIVE, STATUS_DRAFT, STATUS_SUSPENDED,
            STATUS_SUPERSEDED)

#: Pinned enforcement-kind vocabulary.
ENFORCE_PRE_DEPLOYMENT_CHECK = "pre-deployment-check"
ENFORCE_RUNTIME_GATE = "runtime-gate"
ENFORCE_USAGE_REVIEW = "usage-review"
ENFORCE_DATA_AUDIT = "data-audit"
ENFORCE_INCIDENT_RESPONSE = "incident-response"
ENFORCE_ACCESS_REVOCATION = "access-revocation"
ENFORCE_MODEL_ROLLBACK = "model-rollback"
ENFORCE_DEPLOYMENT_HOLD = "deployment-hold"
ENFORCEMENT_KINDS = (
    ENFORCE_PRE_DEPLOYMENT_CHECK,
    ENFORCE_RUNTIME_GATE,
    ENFORCE_USAGE_REVIEW,
    ENFORCE_DATA_AUDIT,
    ENFORCE_INCIDENT_RESPONSE,
    ENFORCE_ACCESS_REVOCATION,
    ENFORCE_MODEL_ROLLBACK,
    ENFORCE_DEPLOYMENT_HOLD,
)

#: Pinned enforcement-verdict vocabulary. Verdicts are host-reported data.
VERDICT_COMPLIANT = "compliant"
VERDICT_VIOLATION = "violation"
VERDICT_WAIVED = "waived"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICTS = (VERDICT_COMPLIANT, VERDICT_VIOLATION, VERDICT_WAIVED,
            VERDICT_INCONCLUSIVE)

#: Pinned retire-reason vocabulary.
REASON_MANUAL = "manual"
REASON_SUPERSEDED = "superseded"
REASON_DECOMMISSIONED = "decommissioned"
RETIRE_REASONS = (REASON_MANUAL, REASON_SUPERSEDED,
                  REASON_DECOMMISSIONED)

#: Regex for a well-formed sha256 digest pin.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class AIPolicyError(Exception):
    """Base error for the ai-policy module."""


class BadSystemError(AIPolicyError):
    """Malformed system id."""


class UnknownSystemError(AIPolicyError):
    """System id has no declared policy."""


class RetiredSystemError(AIPolicyError):
    """System id was retired; never recycled."""


class BadPolicyKindError(AIPolicyError):
    """Policy kind outside the pinned vocabulary."""


class BadStatusError(AIPolicyError):
    """Policy status outside the pinned vocabulary."""


class BadEnforcementKindError(AIPolicyError):
    """Enforcement kind outside the pinned vocabulary."""


class BadVerdictError(AIPolicyError):
    """Enforcement verdict outside the pinned vocabulary."""


class BadDigestError(AIPolicyError):
    """Malformed sha256 digest pin."""


class BadReasonError(AIPolicyError):
    """Retire reason outside the pinned vocabulary."""


class UnknownEnforcementError(AIPolicyError):
    """Enforcement id not booked."""


class SeqOrderError(AIPolicyError):
    """Seq not a strictly increasing int."""


class AuditKindError(AIPolicyError):
    """Audit kind outside the pinned vocabulary or banned detail key."""


# ---------------------------------------------------------------------------
# Records (frozen dataclasses)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyRecord:
    """One declared AI policy over a named AI system."""
    policy_id: str
    system_id: str
    policy_kind: str
    status: str
    policy_digest: str
    seq: int
    digest: str
    schema: str = AI_POLICY_SCHEMA
    version: str = AI_POLICY_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "system_id": self.system_id,
            "policy_kind": self.policy_kind,
            "status": self.status,
            "policy_digest": self.policy_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        """Recompute the tamper-evident pin."""
        return self.digest == _policy_digest(
            self.policy_id, self.system_id, self.policy_kind,
            self.status, self.policy_digest)


@dataclass(frozen=True)
class EnforcementRecord:
    """One declared enforcement action against a system."""
    enforcement_id: str
    system_id: str
    enforcement_kind: str
    verdict: str
    enforcement_digest: str
    seq: int
    digest: str
    schema: str = AI_POLICY_SCHEMA
    version: str = AI_POLICY_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "enforcement_id": self.enforcement_id,
            "system_id": self.system_id,
            "enforcement_kind": self.enforcement_kind,
            "verdict": self.verdict,
            "enforcement_digest": self.enforcement_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _enforcement_digest(
            self.enforcement_id, self.system_id, self.enforcement_kind,
            self.verdict, self.enforcement_digest)


@dataclass(frozen=True)
class VerificationReport:
    """Pure read view of one enforcement record's integrity (data, not proof)."""
    enforcement_id: str
    verdict: str  # "verified" | "tampered"
    integrity_ok: bool
    seq: int
    digest: str
    schema: str = AI_POLICY_SCHEMA
    version: str = AI_POLICY_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "enforcement_id": self.enforcement_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _verify_digest(self.enforcement_id, self.verdict)


@dataclass(frozen=True)
class PolicyPostureReport:
    """Pure read view of derived policy posture (data, not findings)."""
    system_id: str  # "" for whole-ledger scope
    posture: str  # "unevaluated" | "non-compliant" | "contested"
                  # | "partially-enforced" | "enforced"
    policy_count: int
    enforcement_count: int
    violation_count: int
    waived_count: int
    compliant_count: int
    integrity_ok: bool
    enforcement_ids: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = AI_POLICY_SCHEMA
    version: str = AI_POLICY_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "posture": self.posture,
            "policy_count": self.policy_count,
            "enforcement_count": self.enforcement_count,
            "violation_count": self.violation_count,
            "waived_count": self.waived_count,
            "compliant_count": self.compliant_count,
            "integrity_ok": self.integrity_ok,
            "enforcement_ids": list(self.enforcement_ids),
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _report_digest(
            self.system_id, self.posture, self.policy_count,
            self.enforcement_count, self.violation_count,
            self.waived_count, self.compliant_count,
            self.enforcement_ids)


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a system id."""
    system_id: str
    reason: str
    seq: int
    digest: str
    schema: str = AI_POLICY_SCHEMA
    version: str = AI_POLICY_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _retire_digest(self.system_id, self.reason)


# ---------------------------------------------------------------------------
# Digest pins
# ---------------------------------------------------------------------------

def _pin(value: Any) -> str:
    return "sha256:" + jcs_sha256_hex(value)


def _policy_digest(policy_id: str, system_id: str, policy_kind: str,
                   status: str, policy_digest: str) -> str:
    return _pin({"policy_id": policy_id, "system_id": system_id,
                 "policy_kind": policy_kind, "status": status,
                 "policy_digest": policy_digest})


def _enforcement_digest(enforcement_id: str, system_id: str,
                        enforcement_kind: str, verdict: str,
                        enforcement_digest: str) -> str:
    return _pin({"enforcement_id": enforcement_id, "system_id": system_id,
                 "enforcement_kind": enforcement_kind, "verdict": verdict,
                 "enforcement_digest": enforcement_digest})


def _verify_digest(enforcement_id: str, verdict: str) -> str:
    return _pin({"enforcement_id": enforcement_id, "verdict": verdict})


def _retire_digest(system_id: str, reason: str) -> str:
    return _pin({"system_id": system_id, "reason": reason})


def _report_digest(system_id: str, posture: str, policy_count: int,
                   enforcement_count: int, violation_count: int,
                   waived_count: int, compliant_count: int,
                   enforcement_ids: Tuple[str, ...]) -> str:
    return _pin({"system_id": system_id, "posture": posture,
                 "policy_count": policy_count,
                 "enforcement_count": enforcement_count,
                 "violation_count": violation_count,
                 "waived_count": waived_count,
                 "compliant_count": compliant_count,
                 "enforcement_ids": sorted(enforcement_ids)})


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
    if not isinstance(value, str):
        raise BadDigestError(f"bad digest pin: {value!r}")
    if value != "" and not _DIGEST_RE.match(value):
        raise BadDigestError(f"bad digest pin: {value!r}")
    return value


def ai_policy_audit_event(kind: str, seq: int,
                          **details: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event for the ai-policy ledger."""
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
        "version": AI_POLICY_VERSION,
        "detail": dict(details),
    }


def stdlib_only() -> bool:
    """AST self-check: this module imports stdlib modules only."""
    allowed = set(getattr(sys, "stdlib_module_names", ()))
    allowed |= {"canonical_json"}  # the single sanctioned canonicalizer
    # Read own source from the defining file for accuracy.
    path = globals().get("__file__", "")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
    except OSError:
        return True
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


# ---------------------------------------------------------------------------
# AIPolicy
# ---------------------------------------------------------------------------

class AIPolicy:
    """AI policy declaration/enforcement decision ledger.

    Declares AI policies over named AI systems, books declared
    enforcement actions against them, and derives posture as data.
    Deterministic, in-memory, fail-closed; no wall-clock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, None] = {}
        self._policies: Dict[str, PolicyRecord] = {}
        self._policies_for: Dict[str, Tuple[str, ...]] = {}
        self._enforcements: Dict[str, EnforcementRecord] = {}
        self._enforcements_for: Dict[str, Tuple[str, ...]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._policy_counter = 0
        self._enforcement_counter = 0
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
        """Claim the seq even for a failed mutation (claim-then-burn)."""
        self._last_seq = max(self._last_seq, seq)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit_events.append(
            ai_policy_audit_event(kind, seq, **details))

    def _require_live_system(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system retired: {system_id!r}")
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    def _posture(self, enforcement_ids: Tuple[str, ...]) -> str:
        """Derive posture from booked verdicts (data, never findings)."""
        if not enforcement_ids:
            return "unevaluated"
        verdicts = [self._enforcements[eid].verdict
                    for eid in enforcement_ids]
        if VERDICT_VIOLATION in verdicts:
            return "non-compliant"
        if VERDICT_INCONCLUSIVE in verdicts:
            return "contested"
        if VERDICT_WAIVED in verdicts:
            return "partially-enforced"
        return "enforced"

    def _integrity_ok(self, system_id: str) -> bool:
        for pid in self._policies_for.get(system_id, ()):
            if not self._policies[pid].verify():
                return False
        for eid in self._enforcements_for.get(system_id, ()):
            if not self._enforcements[eid].verify():
                return False
        return True

    # -- public API ---------------------------------------------------------

    def declare(self, system_id: str, seq: int,
                policy_kind: str = POLICY_USAGE,
                status: str = STATUS_DRAFT,
                policy_digest: str = "") -> PolicyRecord:
        """Declare one AI policy over a named AI system."""
        seq = self._claim(seq)
        try:
            _check_id(system_id, BadSystemError)
            if system_id in self._retired:
                raise RetiredSystemError(
                    f"system retired: {system_id!r}")
            if policy_kind not in POLICY_KINDS:
                raise BadPolicyKindError(
                    f"bad policy kind: {policy_kind!r}")
            if status not in STATUSES:
                raise BadStatusError(f"bad status: {status!r}")
            _check_digest(policy_digest)
            if system_id not in self._systems:
                self._systems[system_id] = None
                self._policies_for[system_id] = ()
                self._enforcements_for[system_id] = ()
            self._policy_counter += 1
            policy_id = f"pol-{self._policy_counter}"
            record = PolicyRecord(
                policy_id=policy_id,
                system_id=system_id,
                policy_kind=policy_kind,
                status=status,
                policy_digest=policy_digest,
                seq=seq,
                digest=_policy_digest(policy_id, system_id, policy_kind,
                                      status, policy_digest),
            )
        except AIPolicyError as exc:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq,
                       rejected_kind=type(exc).__name__,
                       system_id=system_id)
            raise
        self._policies[policy_id] = record
        self._policies_for[system_id] = (
            self._policies_for[system_id] + (policy_id,))
        self._emit(KIND_POLICY_DECLARED, seq, policy_id=policy_id,
                   system_id=system_id, policy_kind=policy_kind,
                   status=status)
        return record

    def enforce(self, system_id: str, seq: int,
                enforcement_kind: str = ENFORCE_RUNTIME_GATE,
                verdict: str = VERDICT_COMPLIANT,
                enforcement_digest: str = "") -> EnforcementRecord:
        """Book one declared enforcement action against a system."""
        seq = self._claim(seq)
        try:
            _check_id(system_id, BadSystemError)
            self._require_live_system(system_id)
            if enforcement_kind not in ENFORCEMENT_KINDS:
                raise BadEnforcementKindError(
                    f"bad enforcement kind: {enforcement_kind!r}")
            if verdict not in VERDICTS:
                raise BadVerdictError(f"bad verdict: {verdict!r}")
            _check_digest(enforcement_digest)
            self._enforcement_counter += 1
            enforcement_id = f"enf-{self._enforcement_counter}"
            record = EnforcementRecord(
                enforcement_id=enforcement_id,
                system_id=system_id,
                enforcement_kind=enforcement_kind,
                verdict=verdict,
                enforcement_digest=enforcement_digest,
                seq=seq,
                digest=_enforcement_digest(
                    enforcement_id, system_id, enforcement_kind,
                    verdict, enforcement_digest),
            )
        except AIPolicyError as exc:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq,
                       rejected_kind=type(exc).__name__,
                       system_id=system_id)
            raise
        self._enforcements[enforcement_id] = record
        self._enforcements_for[system_id] = (
            self._enforcements_for[system_id] + (enforcement_id,))
        self._emit(KIND_ENFORCED, seq, enforcement_id=enforcement_id,
                   system_id=system_id,
                   enforcement_kind=enforcement_kind,
                   verdict=verdict)
        return record

    def verify(self, enforcement_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one enforcement record's digest pin."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            _check_id(enforcement_id, UnknownEnforcementError)
            try:
                record = self._enforcements[enforcement_id]
            except KeyError:
                raise UnknownEnforcementError(
                    f"unknown enforcement: {enforcement_id!r}")
            ok = record.verify()
            verdict = "verified" if ok else "tampered"
            return VerificationReport(
                enforcement_id=enforcement_id,
                verdict=verdict,
                integrity_ok=ok,
                seq=seq,
                digest=_verify_digest(enforcement_id, verdict),
            )

    def report(self, seq: int,
               system_id: str = "") -> PolicyPostureReport:
        """Pure read: derived policy posture (data, never findings)."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            if system_id:
                _check_id(system_id, BadSystemError)
                if system_id not in self._systems:
                    raise UnknownSystemError(
                        f"unknown system: {system_id!r}")
                policy_ids = self._policies_for.get(system_id, ())
                enforcement_ids = self._enforcements_for.get(
                    system_id, ())
            else:
                policy_ids = tuple(self._policies.keys())
                enforcement_ids = tuple(self._enforcements.keys())
            verdicts = [self._enforcements[eid].verdict
                        for eid in enforcement_ids]
            violation_count = sum(1 for v in verdicts
                                  if v == VERDICT_VIOLATION)
            waived_count = sum(1 for v in verdicts
                               if v == VERDICT_WAIVED)
            compliant_count = sum(1 for v in verdicts
                                  if v == VERDICT_COMPLIANT)
            integrity = all(
                self._integrity_ok(sid)
                for sid in (self._systems if not system_id
                            else (system_id,)))
            posture = self._posture(enforcement_ids)
            return PolicyPostureReport(
                system_id=system_id,
                posture=posture,
                policy_count=len(policy_ids),
                enforcement_count=len(enforcement_ids),
                violation_count=violation_count,
                waived_count=waived_count,
                compliant_count=compliant_count,
                integrity_ok=integrity,
                enforcement_ids=enforcement_ids,
                seq=seq,
                digest=_report_digest(system_id, posture,
                                      len(policy_ids),
                                      len(enforcement_ids),
                                      violation_count, waived_count,
                                      compliant_count,
                                      enforcement_ids),
            )

    def retire(self, system_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire a system id."""
        seq = self._claim(seq)
        try:
            _check_id(system_id, BadSystemError)
            if system_id in self._retired:
                raise RetiredSystemError(
                    f"system retired: {system_id!r}")
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            if reason not in RETIRE_REASONS:
                raise BadReasonError(f"bad reason: {reason!r}")
            record = RetireRecord(
                system_id=system_id,
                reason=reason,
                seq=seq,
                digest=_retire_digest(system_id, reason),
            )
        except AIPolicyError as exc:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq,
                       rejected_kind=type(exc).__name__,
                       system_id=system_id)
            raise
        self._retired[system_id] = record
        self._emit(KIND_RETIRED, seq, system_id=system_id,
                   reason=reason)
        return record

    # -- pure-read views -----------------------------------------------------

    def policy_record(self, policy_id: str, seq: int) -> PolicyRecord:
        """Pure read: fetch one policy record (no audit row)."""
        _check_seq(seq)
        try:
            return self._policies[policy_id]
        except KeyError:
            raise UnknownSystemError(
                f"unknown policy: {policy_id!r}")

    def enforcement_record(self, enforcement_id: str,
                           seq: int) -> EnforcementRecord:
        """Pure read: fetch one enforcement record (no audit row)."""
        _check_seq(seq)
        try:
            return self._enforcements[enforcement_id]
        except KeyError:
            raise UnknownEnforcementError(
                f"unknown enforcement: {enforcement_id!r}")

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: system ids with declared policies (no audit row)."""
        _check_seq(seq)
        return tuple(self._systems.keys())

    def policies_for(self, system_id: str,
                     seq: int) -> Tuple[str, ...]:
        """Pure read: policy ids for one system (no audit row)."""
        _check_seq(seq)
        _check_id(system_id, BadSystemError)
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        return self._policies_for.get(system_id, ())

    def enforcements_for(self, system_id: str,
                         seq: int) -> Tuple[str, ...]:
        """Pure read: enforcement ids for one system (no audit row)."""
        _check_seq(seq)
        _check_id(system_id, BadSystemError)
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        return self._enforcements_for.get(system_id, ())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: retired system ids (no audit row)."""
        _check_seq(seq)
        return tuple(self._retired.keys())

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters (no audit row)."""
        _check_seq(seq)
        return {
            "systems": len(self._systems),
            "policies": len(self._policies),
            "enforcements": len(self._enforcements),
            "retired": len(self._retired),
            "seq": self._last_seq,
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: the booked audit.ndjson/1 rows (no audit row)."""
        _check_seq(seq)
        return tuple(self._audit_events)


def main() -> None:
    """Self-check: exercise declare/enforce/verify/report/retire paths."""
    p = AIPolicy()
    pol = p.declare("sys-1", 1, policy_kind=POLICY_SAFETY,
                    status=STATUS_ACTIVE)
    assert pol.policy_id == "pol-1" and pol.verify()
    enf = p.enforce("sys-1", 2,
                    enforcement_kind=ENFORCE_PRE_DEPLOYMENT_CHECK,
                    verdict=VERDICT_COMPLIANT)
    assert enf.enforcement_id == "enf-1" and enf.verify()
    rep = p.report(3, "sys-1")
    assert rep.posture == "enforced" and rep.verify()
    vfy = p.verify("enf-1", 4)
    assert vfy.verdict == "verified" and vfy.verify()
    ret = p.retire("sys-1", 5)
    assert ret.verify()
    assert stdlib_only()
    print("ai-policy OK: declare, enforce, verify, report, retire, pins, audit")


if __name__ == "__main__":
    main()
