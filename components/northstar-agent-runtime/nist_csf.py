"""NIST Cybersecurity Framework (CSF) 2.0 assessment decision ledger.

Distinct from siblings: ``grc.py`` owns the generic governance workflow
(register framework, assess finding, remediate, certify); ``compliance.py``
owns per-framework control checks. This module is the *CSF-shaped* layer
none of them own - it books declared CSF 2.0 function assessments over
the pinned function vocabulary, declared improvement actions, and
declared Current/Target Profiles, and derives gap reports as data.

* **Functions** - the CSF 2.0 function vocabulary (``govern`` /
  ``identify`` / ``protect`` / ``detect`` / ``respond`` / ``recover``);
  subcategories are host-declared detail and never travel raw.
* **Tiers** - Implementation Tiers 1-4 (Partial / Risk Informed /
  Repeatable / Adaptive) booked as declared integers.
* **Profiles** - ``profile()`` declares a Current or Target Profile
  mapping every function to a tier; a Target Profile records the
  declared outcome the host is working toward.
* **Assessments** - ``assess()`` books one declared function
  assessment (minted ``asm-N``): function, declared tier, evidence as a
  ``sha256:`` digest pin only.
* **Improvements** - ``improve()`` books one declared improvement
  action (minted ``imp-N``) over the pinned action vocabulary; it is
  refused fail-closed when the target tier is not above the latest
  assessed tier for the function (there is nothing to improve), and
  when the function has no booked assessment.
* **Gap report** - ``gap()`` is a pure read view deriving per-function
  gaps between the latest assessed tiers (or the Current Profile) and
  the Target Profile as data - never proof of risk.

Design (deterministic single-host ledger):
1. Frozen dataclasses, caller int seqs strictly increasing
   (claim-then-burn: failed mutations consume their seq + book
   ``nist-csf.rejected``; rewinds raise bare), no wall-clock,
   RLock-guarded, fail-closed taxonomy.
2. stdlib-only + the single ``canonical_json`` try/except fallback;
   ``sha256:`` digest pins with ``verify()``; ``audit.ndjson/1``
   events; version pin ``nist-csf.v1``; schema pin
   ``northstar.nist-csf.v1``.

Honest scope:
- This module books *declared* CSF decisions - it runs no audit,
  inspects no evidence, and certifies nothing.
- A booked ``tier=3`` means "the host declared tier 3", never "the
  organization is repeatable". A booked improvement means "the host
  declared an action", never "the gap was closed".
- Digest pins prove ledger integrity and ordering, never the truth of
  the declared decisions.
- No persistence: the ledger is in-memory.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


VERSION = "nist-csf.v1"
SCHEMA = "northstar.nist-csf.v1"

KIND_PROFILE_REGISTERED = "profile-registered"
KIND_ASSESSED = "assessed"
KIND_IMPROVED = "improved"
KIND_REJECTED = "rejected"
_KINDS = frozenset({
    KIND_PROFILE_REGISTERED, KIND_ASSESSED, KIND_IMPROVED, KIND_REJECTED,
})

# CSF 2.0 functions.
_FUNCTIONS = ("govern", "identify", "protect", "detect", "respond",
              "recover")

# Implementation Tiers: 1=Partial, 2=Risk Informed, 3=Repeatable,
# 4=Adaptive.
_TIERS = (1, 2, 3, 4)

_PROFILE_KINDS = ("current", "target")

_IMPROVEMENT_ACTIONS = ("implement-control", "remediate", "document",
                        "train", "procure", "reassess", "accept-risk")

_MAX_ID_LEN = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Raw content must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset({
    "content", "text", "payload", "raw", "evidence", "description",
    "notes", "note", "message", "plan", "plan_text", "rationale",
    "objective", "summary", "finding_text", "title", "detail",
})


class NISTCSFError(Exception):
    """Base class for all NIST CSF ledger errors."""


class BadIdError(NISTCSFError):
    """Malformed profile id, function id, or assessment id."""


class DuplicateProfileError(NISTCSFError):
    """Profile id already registered (ids are never recycled)."""


class UnknownProfileError(NISTCSFError):
    """Profile id not registered."""


class BadProfileKindError(NISTCSFError):
    """Profile kind not in the pinned vocabulary."""


class BadFunctionError(NISTCSFError):
    """Function not in the CSF 2.0 pinned vocabulary."""


class BadTierError(NISTCSFError):
    """Tier not an int in 1-4."""


class BadDigestError(NISTCSFError):
    """Digest is not a sha256:<64hex> pin (or empty)."""


class DuplicateAssessmentError(NISTCSFError):
    """Assessment id minted twice (internal misuse)."""


class UnknownAssessmentError(NISTCSFError):
    """Assessment id not booked."""


class BadFunctionTiersError(NISTCSFError):
    """Profile function_tiers malformed (must cover every function)."""


class UnassessedFunctionError(NISTCSFError):
    """Improvement booked against a function with no assessment."""


class ImprovementNotNeededError(NISTCSFError):
    """Improvement target tier not above the latest assessed tier."""


class BadActionError(NISTCSFError):
    """Improvement action not in the pinned vocabulary."""


class SeqOrderError(NISTCSFError):
    """Malformed seq or seq not strictly increasing."""


class AuditKindError(NISTCSFError):
    """Unknown audit kind, or banned key at the audit boundary."""


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


def _check_function(value: object) -> str:
    """Validate a CSF 2.0 function against the pinned vocabulary."""
    if not isinstance(value, str) or value not in _FUNCTIONS:
        raise BadFunctionError(
            f"function must be one of {sorted(_FUNCTIONS)}")
    return value


def _check_tier(value: object, label: str = "tier") -> int:
    """Validate an implementation tier: int 1-4, not bool."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadTierError(
            f"{label} must be int in 1-4, got {type(value).__name__}")
    if value not in _TIERS:
        raise BadTierError(f"{label} must be one of {list(_TIERS)}")
    return value


def _check_digest(value: object, label: str) -> str:
    """Validate a sha256:<64hex> digest pin (or empty string)."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{label} must be str, got {type(value).__name__}")
    if value and not _DIGEST_RE.match(value):
        raise BadDigestError(f"{label} must be sha256:<64hex> or empty")
    return value


def _digest_pin(payload: Any) -> str:
    """sha256: digest pin over canonical JSON of payload."""
    hexval = jcs_sha256_hex(payload)
    # Normalize both the real library's bare hex and sha256:-prefixed forms.
    hexval = hexval[len("sha256:"):] if hexval.startswith("sha256:") else hexval
    return "sha256:" + hexval


def nist_csf_audit_event(kind: str, detail: Dict[str, object],
                        seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the CSF ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "audit_version": "audit.ndjson/1",
        "schema": SCHEMA,
        "version": VERSION,
        "kind": "nist-csf." + kind,
        "detail": dict(detail),
        "seq": seq,
    }


def _record_digest(tag: str, fields: Dict[str, object]) -> str:
    return _digest_pin({"nist-csf": tag, **fields})


@dataclass(frozen=True)
class ProfileRecord:
    """One declared CSF Current or Target Profile (function -> tier)."""

    profile_id: str
    profile_kind: str
    function_tiers: Tuple[Tuple[str, int], ...]
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "profile_id": self.profile_id,
            "profile_kind": self.profile_kind,
            "function_tiers": [
                {"function": fn, "tier": tier}
                for fn, tier in self.function_tiers
            ],
            "digest": self.digest,
        }

    def tier_for(self, function: str) -> int:
        """Declared tier for one function."""
        for fn, tier in self.function_tiers:
            if fn == function:
                return tier
        raise KeyError(function)

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("profile", {
            "profile_id": self.profile_id,
            "profile_kind": self.profile_kind,
            "function_tiers": [
                {"function": fn, "tier": tier}
                for fn, tier in self.function_tiers
            ]})


@dataclass(frozen=True)
class AssessmentRecord:
    """One declared CSF function assessment (minted asm-N)."""

    assessment_id: str
    function: str
    tier: int
    evidence_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "assessment_id": self.assessment_id,
            "function": self.function,
            "tier": self.tier,
            "evidence_pin": self.evidence_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("assessment", {
            "assessment_id": self.assessment_id,
            "function": self.function,
            "tier": self.tier,
            "evidence_pin": self.evidence_pin})


@dataclass(frozen=True)
class ImprovementRecord:
    """One declared CSF improvement action (minted imp-N)."""

    improvement_id: str
    function: str
    target_tier: int
    action: str
    plan_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "improvement_id": self.improvement_id,
            "function": self.function,
            "target_tier": self.target_tier,
            "action": self.action,
            "plan_pin": self.plan_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("improvement", {
            "improvement_id": self.improvement_id,
            "function": self.function,
            "target_tier": self.target_tier,
            "action": self.action,
            "plan_pin": self.plan_pin})


@dataclass(frozen=True)
class GapReport:
    """Per-function gaps derived from the ledger (pure data)."""

    gaps: Tuple[Tuple[str, int], ...]
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "gaps": [
                {"function": fn, "gap": gap} for fn, gap in self.gaps
            ],
            "digest": self.digest,
        }

    def gap_for(self, function: str) -> int:
        """Declared gap for one function."""
        for fn, gap in self.gaps:
            if fn == function:
                return gap
        raise KeyError(function)

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("gap", {
            "gaps": [
                {"function": fn, "gap": gap} for fn, gap in self.gaps
            ]})


class NISTCSF:
    """Deterministic single-host NIST CSF 2.0 decision ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._profiles: Dict[str, ProfileRecord] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._assessments_for: Dict[str, List[str]] = {}
        self._improvements: Dict[str, ImprovementRecord] = {}
        self._improvement_chain: Dict[str, List[str]] = {}
        self._asm_counter = 0
        self._imp_counter = 0
        self._audit: List[Dict[str, object]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _claim_seq(self, seq_v: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq_v <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq_v} "
                f"after {self._seq}")
        self._seq = seq_v

    def _burn(self, seq_v: int, method: str, exc: NISTCSFError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(nist_csf_audit_event(
            KIND_REJECTED,
            {"method": method, "error": type(exc).__name__,
             "error_detail": str(exc)},
            seq_v))

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq_v: int) -> None:
        self._audit.append(nist_csf_audit_event(audit_kind, detail, seq_v))

    # -- mutations --------------------------------------------------------

    def profile(self, profile_id: object, profile_kind: object,
                seq: object,
                function_tiers: object = (),
                description_digest: object = "") -> ProfileRecord:
        """Declare a CSF Current or Target Profile (function -> tier)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(profile_id, "profile_id")
                if pid in self._profiles:
                    raise DuplicateProfileError(
                        f"profile already registered: {pid!r}")
                if (not isinstance(profile_kind, str)
                        or profile_kind not in _PROFILE_KINDS):
                    raise BadProfileKindError(
                        f"profile_kind must be one of "
                        f"{sorted(_PROFILE_KINDS)}")
                pairs = self._normalize_function_tiers(function_tiers)
                _check_digest(description_digest, "description_digest")
                rec = ProfileRecord(
                    profile_id=pid, profile_kind=profile_kind,
                    function_tiers=pairs,
                    digest=_record_digest("profile", {
                        "profile_id": pid,
                        "profile_kind": profile_kind,
                        "function_tiers": [
                            {"function": fn, "tier": tier}
                            for fn, tier in pairs]}))
                self._profiles[pid] = rec
                self._emit(KIND_PROFILE_REGISTERED,
                           {"profile_id": pid, "profile_kind": profile_kind},
                           seq_v)
                return rec
            except NISTCSFError as exc:
                self._burn(seq_v, "profile", exc)
                raise

    @staticmethod
    def _normalize_function_tiers(value: object) -> Tuple[Tuple[str, int], ...]:
        """Validate function_tiers: every CSF function exactly once."""
        if isinstance(value, bool) or not isinstance(value, (tuple, list)):
            raise BadFunctionTiersError(
                "function_tiers must be a tuple/list of (function, tier)")
        seen: Dict[str, int] = {}
        for item in value:
            if (not isinstance(item, (tuple, list)) or len(item) != 2
                    or isinstance(item, bool)):
                raise BadFunctionTiersError(
                    "function_tiers entries must be (function, tier) pairs")
            fn = _check_function(item[0])
            tier = _check_tier(item[1])
            if fn in seen:
                raise BadFunctionTiersError(
                    f"duplicate function in function_tiers: {fn!r}")
            seen[fn] = tier
        missing = [fn for fn in _FUNCTIONS if fn not in seen]
        if missing:
            raise BadFunctionTiersError(
                f"function_tiers missing functions: {missing}")
        return tuple((fn, seen[fn]) for fn in _FUNCTIONS)

    def assess(self, function: object, tier: object, seq: object,
               evidence_digest: object = "") -> AssessmentRecord:
        """Book one declared CSF function assessment (minted asm-N)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                fn = _check_function(function)
                tv = _check_tier(tier)
                pin = _check_digest(evidence_digest, "evidence_digest")
                self._asm_counter += 1
                asm_id = f"asm-{self._asm_counter}"
                if asm_id in self._assessments:
                    raise DuplicateAssessmentError(
                        f"assessment id minted twice: {asm_id!r}")
                rec = AssessmentRecord(
                    assessment_id=asm_id, function=fn, tier=tv,
                    evidence_pin=pin,
                    digest=_record_digest("assessment", {
                        "assessment_id": asm_id, "function": fn,
                        "tier": tv, "evidence_pin": pin}))
                self._assessments[asm_id] = rec
                self._assessments_for.setdefault(fn, []).append(asm_id)
                self._emit(KIND_ASSESSED,
                           {"assessment_id": asm_id, "function": fn,
                            "tier": tv},
                           seq_v)
                return rec
            except NISTCSFError as exc:
                self._burn(seq_v, "assess", exc)
                raise

    def improve(self, function: object, target_tier: object,
                seq: object, action: object = "implement-control",
                plan_digest: object = "") -> ImprovementRecord:
        """Book one declared CSF improvement action (minted imp-N)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                fn = _check_function(function)
                tv = _check_tier(target_tier, "target_tier")
                if (not isinstance(action, str)
                        or action not in _IMPROVEMENT_ACTIONS):
                    raise BadActionError(
                        f"action must be one of "
                        f"{sorted(_IMPROVEMENT_ACTIONS)}")
                pin = _check_digest(plan_digest, "plan_digest")
                booked = self._assessments_for.get(fn)
                if not booked:
                    raise UnassessedFunctionError(
                        f"no assessment booked for function {fn!r}")
                latest_tier = max(
                    self._assessments[aid].tier for aid in booked)
                if tv <= latest_tier:
                    raise ImprovementNotNeededError(
                        f"target tier {tv} not above latest assessed tier "
                        f"{latest_tier} for {fn!r}")
                self._imp_counter += 1
                imp_id = f"imp-{self._imp_counter}"
                rec = ImprovementRecord(
                    improvement_id=imp_id, function=fn, target_tier=tv,
                    action=action, plan_pin=pin,
                    digest=_record_digest("improvement", {
                        "improvement_id": imp_id, "function": fn,
                        "target_tier": tv, "action": action,
                        "plan_pin": pin}))
                self._improvements[imp_id] = rec
                self._improvement_chain.setdefault(fn, []).append(imp_id)
                self._emit(KIND_IMPROVED,
                           {"improvement_id": imp_id, "function": fn,
                            "target_tier": tv, "action": action},
                           seq_v)
                return rec
            except NISTCSFError as exc:
                self._burn(seq_v, "improve", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def gap(self, seq: object) -> GapReport:
        """Derive per-function gaps (target - current/assessed) as data."""
        with self._lock:
            seq_v = _check_seq(seq)
            targets = [p for p in self._profiles.values()
                       if p.profile_kind == "target"]
            currents = [p for p in self._profiles.values()
                        if p.profile_kind == "current"]
            target = targets[-1] if targets else None
            current = currents[-1] if currents else None
            gaps: List[Tuple[str, int]] = []
            for fn in _FUNCTIONS:
                assessed_ids = self._assessments_for.get(fn, [])
                if current is not None:
                    baseline = current.tier_for(fn)
                elif assessed_ids:
                    baseline = max(self._assessments[aid].tier
                                   for aid in assessed_ids)
                else:
                    baseline = 0
                goal = target.tier_for(fn) if target is not None else 0
                gaps.append((fn, goal - baseline))
            report = GapReport(
                gaps=tuple(gaps),
                digest=_record_digest("gap", {
                    "gaps": [{"function": fn, "gap": gap}
                             for fn, gap in gaps]}))
            _ = seq_v  # seq shape validated, never consumed
            return report

    def profile_record(self, profile_id: object,
                       seq: object) -> ProfileRecord:
        """Return one profile record (pure read)."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(profile_id, "profile_id")
            if pid not in self._profiles:
                raise UnknownProfileError(
                    f"unknown profile: {pid!r}")
            return self._profiles[pid]

    def profile_ids(self, seq: object) -> Tuple[str, ...]:
        """All profile ids in registration order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._profiles.keys())

    def assessment_record(self, assessment_id: object,
                          seq: object) -> AssessmentRecord:
        """Return one assessment record (pure read)."""
        with self._lock:
            _check_seq(seq)
            aid = _check_id(assessment_id, "assessment_id")
            if aid not in self._assessments:
                raise UnknownAssessmentError(
                    f"unknown assessment: {aid!r}")
            return self._assessments[aid]

    def assessment_ids(self, seq: object) -> Tuple[str, ...]:
        """All assessment ids in mint order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._assessments.keys())

    def assessments_for(self, function: object,
                        seq: object) -> Tuple[str, ...]:
        """Assessment ids booked for one function (mint order)."""
        with self._lock:
            _check_seq(seq)
            fn = _check_function(function)
            return tuple(self._assessments_for.get(fn, ()))

    def improvement_record(self, improvement_id: object,
                           seq: object) -> ImprovementRecord:
        """Return one improvement record (pure read)."""
        with self._lock:
            _check_seq(seq)
            iid = _check_id(improvement_id, "improvement_id")
            if iid not in self._improvements:
                raise UnknownAssessmentError(
                    f"unknown improvement: {iid!r}")
            return self._improvements[iid]

    def improvements_for(self, function: object,
                         seq: object) -> Tuple[str, ...]:
        """Improvement ids booked for one function (mint order)."""
        with self._lock:
            _check_seq(seq)
            fn = _check_function(function)
            return tuple(self._improvement_chain.get(fn, ()))

    def audit_log(self, seq: object) -> Tuple[Dict[str, object], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: object) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            _check_seq(seq)
            return {
                "profiles": len(self._profiles),
                "assessments": len(self._assessments),
                "improvements": len(self._improvements),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    c = NISTCSF()
    c.profile("cur", "current", 1,
              function_tiers=tuple((fn, 2) for fn in _FUNCTIONS))
    c.profile("tgt", "target", 2,
              function_tiers=tuple((fn, 4) for fn in _FUNCTIONS))
    a1 = c.assess("govern", 2, 3)
    c.improve("govern", 4, 4, action="document")
    a2 = c.assess("protect", 1, 5)
    assert a1.assessment_id == "asm-1"
    assert a2.assessment_id == "asm-2"
    report = c.gap(6)
    assert report.verify()
    assert report.gap_for("govern") == 2
    # baseline comes from the Current Profile (tier 2), not the assessment
    assert report.gap_for("protect") == 2
    assert c.stats(7) == {"profiles": 2, "assessments": 2,
                         "improvements": 1, "rejected": 0}
    print("nist-csf OK: profile, assess, improve, gap, pins, audit")


if __name__ == "__main__":
    main()
