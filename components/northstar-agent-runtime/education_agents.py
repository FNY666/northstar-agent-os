"""Education AI discipline gates (one-hundred-fifty-first batch).

Absorbs the 2026 AI-education thread:

* **Gaokao time-locks** (China, second year running): AI platforms disabled
  exam functions — photo-solving, question analysis — *only during gaokao
  windows* at regulator request, under the deep-synthesis regulation.
  Everyday chat unaffected. The precedent is temporal capability locks,
  not user bans.
* **FTC vs Illuminate Education** (final order 2026-06-05): 10.1M
  students' data exfiltrated via a former employee's credentials; the
  order is a 10-year *operational mandate* with no fine — publish a data
  retention schedule, delete data no longer needed, stop collecting what
  is not reasonably necessary. Retention and minimization are the
  enforcement crosshairs.
* **Detector demotion** (universities, Sep 2026): AI-detector scores are
  being pulled out of misconduct evidence — a flag opens a conversation,
  it doesn't close one. Assessment shifts to process over output.
* **Cambridge (May 2026)**: frontier models matched human degree
  classification only 35–65% on 750+ essays and reward "style over
  substance" — worst at the boundaries that matter (First vs 2:1,
  pass/fail). AI is a discrepancy flagger; the human decides the mark.
* **AFT–Microsoft (2026)**: the teachers' union contract says AI may
  assist but not independently make evaluative decisions in the education
  role; breach of the AI terms is breach of contract.
* **NYC (Sep 2026)**: a 1-year gen-AI moratorium for pre-K–grade 8
  (~600k students); companion chatbots banned for all grades;
  exceptions for special needs, English learners, and career-skills
  courses; teacher planning/admin use still allowed. Ban-until-evidence
  with a sunset and a study coalition.
* **Kazakhstan (Frontiers in Education, Oct 2026)**: students rated
  automated assessment *more* fair than human marking — except linguistic
  equivalence (Kazakh vs Russian items), the lowest-rated fairness item.
  Language parity, not algorithm aversion, is the weak point.
* **German school policy (2026)**: no personal data into AI systems;
  anonymized/pseudonymous student access; teacher review of student
  inputs; safety filters on personal-data entry.

Fail-closed throughout: a locked capability used inside its window is
``education:window_breach``; data past its retention schedule is
``education:retention_overdue`` (auto-delete post-check); an automated
judgment claimed as evidence without human review is
``education:tier_escalation``; an evaluative decision made by AI alone is
``education:ai_decided``; a denied capability served to a protected band
without a listed exception is ``education:developmental_ban``; a
language parity gap above tolerance is ``education:language_parity_gap``;
identifiable student data collected without a live pseudonym is
``education:pii_without_pseudonym``.

Honest boundary: receipts bind *declared* education discipline —
digests recompute, signatures verify, windows/schedules/tiers check.
They don't end cheating, don't fix the guidance gap, and can't prove a
human review was *thoughtful* rather than a rubber stamp. Detector
accuracy, model grading quality, and real equity outcomes are outside
this module's scope.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing, Ed25519 via the vendored
``ed25519`` module, digest comparisons via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


EDUCATION_SCHEMA_VERSION = "northstar.education.v1"

#: Binary classification tiers for a gate outcome.
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non-authoritative"

#: Closed vocabulary for what an automated judgment may claim to be.
#: ``signal`` opens a conversation (detector lesson); ``evidence`` closes
#: one and needs a named-human review first.
EVIDENTIARY_TIERS: tuple[str, ...] = ("signal", "evidence")

#: Evaluative decision kinds where AI may only propose, never decide.
EVALUATIVE_KINDS: tuple[str, ...] = ("grading", "admissions", "discipline")

#: Closed vocabulary for the AI's role in a decision.
AI_ROLES: tuple[str, ...] = ("flag", "draft", "decide")

#: Developmental bands for staged access (NYC lesson).
DEVELOPMENT_BANDS: tuple[str, ...] = (
    "pre_k_2",
    "grades_3_8",
    "grades_9_12",
    "adult",
)

#: Closed exception vocabulary for developmental bans.
STAGING_EXCEPTIONS: tuple[str, ...] = (
    "special_needs",
    "english_learner",
    "career_skills",
)

#: Access values in a staging policy.
STAGING_ACCESS: tuple[str, ...] = ("allow", "supervised", "deny")

_GENESIS = "genesis"
_HEX64_LENGTH = 64


class EducationError(ValueError):
    """A malformed receipt/record or a programming error.

    Raised for structural problems (bad digests, bad signature input,
    unknown vocabulary, non-hex fields). Verification *failures* (a lock
    window hit, an overdue schedule, a tier escalation) return an
    :class:`EducationVerdict` with ``allowed=False`` — a failed education
    check is a verdict, a malformed log is a bug.
    """


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_hex(value: Any, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise EducationError(
            f"{field_name} must be a 64-char lowercase hex digest"
        )
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise EducationError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EducationError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise EducationError(f"{field_name} must be 32 bytes")
    return value


def _check_pubkey_hex(value: Any) -> str:
    # Ed25519 public keys are 32 bytes -> 64 hex chars.
    return _check_hex64(value, "authority_pubkey_hex")


def _check_sig_hex(value: Any, field_name: str) -> str:
    if not _is_hex(value, 128):
        raise EducationError(f"{field_name} must be a 128-char hex value")
    return value


def _check_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise EducationError(f"{field_name} must be a bool")
    return value


def _check_bps(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EducationError(f"{field_name} must be an int basis-points value")
    if value < 0 or value > 10_000:
        raise EducationError(f"{field_name} must be within 0..10000 bps")
    return value


def _check_band(value: Any) -> str:
    if value not in DEVELOPMENT_BANDS:
        raise EducationError(
            f"band must be one of {DEVELOPMENT_BANDS}, saw {value!r}"
        )
    return value


def _check_exception(value: Any) -> str:
    if value not in STAGING_EXCEPTIONS:
        raise EducationError(
            f"exception must be one of {STAGING_EXCEPTIONS}, saw {value!r}"
        )
    return value


def _verify_signature(
    pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str
) -> bool:
    try:
        return bool(
            ed25519.verify(
                bytes.fromhex(pubkey_hex),
                jcs_canonical_json(payload),
                bytes.fromhex(signature_hex),
            )
        )
    except Exception:
        return False


def _check_chain(log: list[Any], type_name: str) -> None:
    """Raise :class:`EducationError` if a receipt log is tampered/broken.

    Every entry must expose ``receipt_digest`` and ``prev_digest`` and a
    ``_payload()`` method; the entries must form one chain from
    ``"genesis"`` with recomputing digests and valid authority
    signatures.
    """
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(
            entry.receipt_digest, jcs_sha256_hex(entry._payload())
        ):
            raise EducationError(
                f"{type_name} receipt digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise EducationError(
                f"{type_name} receipt chain break: "
                f"expected prev {expected_prev!r}"
            )
        # The authority signature covers the payload with a fixed
        # placeholder signature (the signature is stored alongside the
        # body it signs, not inside it); re-derive that signed body.
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(
            entry.authority_pubkey_hex, signed_body, entry.signature_hex
        ):
            raise EducationError(
                f"{type_name} receipt authority signature invalid"
            )
        expected_prev = entry.receipt_digest


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EducationVerdict:
    """Outcome of one education-discipline gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> EducationVerdict:
    return EducationVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> EducationVerdict:
    return EducationVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


# ---------------------------------------------------------------------------
# Authority registry (shared lookup for signed receipts)
# ---------------------------------------------------------------------------


@dataclass
class AuthorityRegistry:
    """Maps authority ids to Ed25519 public keys (hex)."""

    _pubkeys: dict[str, str] | None = None

    def __post_init__(self) -> None:
        self._pubkeys = {}

    def register(self, authority_id: str, pubkey_hex: str) -> None:
        _check_nonempty_str(authority_id, "authority_id")
        _check_pubkey_hex(pubkey_hex)
        self._pubkeys[authority_id] = pubkey_hex

    def pubkey(self, authority_id: str) -> str | None:
        return self._pubkeys.get(authority_id)
# ---------------------------------------------------------------------------
# 1. Temporal capability locks (gaokao time-lock lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityLockReceipt:
    """Pins a capability lock over a time window.

    Binds ``(window_id, capability_id, locked_from, locked_until)`` to an
    authority key. A locked capability used at a ``used_at`` inside the
    window is ``education:window_breach`` — the gaokao precedent (exam
    functions disabled only during exam windows, at regulator request).
    """

    lock_id: str
    window_id: str
    capability_id: str
    locked_from: int
    locked_until: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": EDUCATION_SCHEMA_VERSION,
            "type": "capability_lock",
            "lock_id": self.lock_id,
            "window_id": self.window_id,
            "capability_id": self.capability_id,
            "locked_from": self.locked_from,
            "locked_until": self.locked_until,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class CapabilityLockRegistry:
    """Hash-chained log of capability-lock receipts per authority."""

    authorities: AuthorityRegistry
    log: list[CapabilityLockReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        *,
        lock_id: str,
        window_id: str,
        capability_id: str,
        locked_from: int,
        locked_until: int,
        authority_id: str,
        signature: bytes,
        issued_at: int,
    ) -> CapabilityLockReceipt:
        _check_nonempty_str(lock_id, "lock_id")
        _check_nonempty_str(window_id, "window_id")
        _check_nonempty_str(capability_id, "capability_id")
        _check_ts(locked_from, "locked_from")
        _check_ts(locked_until, "locked_until")
        if locked_until <= locked_from:
            raise EducationError("locked_until must be after locked_from")
        _check_ts(issued_at, "issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise EducationError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = CapabilityLockReceipt(
            lock_id=lock_id,
            window_id=window_id,
            capability_id=capability_id,
            locked_from=locked_from,
            locked_until=locked_until,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise EducationError("capability-lock receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def locks_for(self, capability_id: str) -> list[CapabilityLockReceipt]:
        return [e for e in self.log if e.capability_id == capability_id]


def temporal_capability_lock(
    registry: CapabilityLockRegistry,
    capability_id: str,
    used_at: int,
) -> EducationVerdict:
    """A capability used inside a pinned lock window is denied.

    Exam/admissions windows pin capability locks (gaokao lesson:
    photo-solving disabled only during exam windows). Using a locked
    capability at a ``used_at`` inside any of its lock windows is
    ``education:window_breach`` — fail-closed on the window, not on the
    user.
    """
    _check_nonempty_str(capability_id, "capability_id")
    _check_ts(used_at, "used_at")
    try:
        _check_chain(registry.log, "capability_lock")
    except EducationError as exc:
        return _deny("education:chain_broken", str(exc))
    for entry in registry.locks_for(capability_id):
        if entry.locked_from <= used_at <= entry.locked_until:
            return _deny(
                "education:window_breach",
                f"capability {capability_id!r} used at {used_at} inside lock "
                f"window {entry.window_id!r} "
                f"[{entry.locked_from}, {entry.locked_until}]",
            )
    return _allow(
        f"capability {capability_id!r} has no live lock covering {used_at}"
    )


# ---------------------------------------------------------------------------
# 2. Retention-schedule mandate (FTC Illuminate lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetentionScheduleReceipt:
    """A published data-retention schedule for one data category.

    Binds ``(schedule_id, data_category, retain_until)`` to an authority
    key. The Illuminate final order (2026-06-05) made the schedule itself
    the enforceable artifact: publish it, delete data no longer needed.
    """

    schedule_id: str
    data_category: str
    retain_until: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": EDUCATION_SCHEMA_VERSION,
            "type": "retention_schedule",
            "schedule_id": self.schedule_id,
            "data_category": self.data_category,
            "retain_until": self.retain_until,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class RetentionScheduleRegistry:
    """Hash-chained log of retention-schedule receipts per authority."""

    authorities: AuthorityRegistry
    log: list[RetentionScheduleReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        *,
        schedule_id: str,
        data_category: str,
        retain_until: int,
        authority_id: str,
        signature: bytes,
        issued_at: int,
    ) -> RetentionScheduleReceipt:
        _check_nonempty_str(schedule_id, "schedule_id")
        _check_nonempty_str(data_category, "data_category")
        _check_ts(retain_until, "retain_until")
        _check_ts(issued_at, "issued_at")
        if retain_until <= issued_at:
            raise EducationError("retain_until must be after issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise EducationError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = RetentionScheduleReceipt(
            schedule_id=schedule_id,
            data_category=data_category,
            retain_until=retain_until,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise EducationError(
                "retention-schedule receipt authority signature invalid"
            )
        self.log.append(receipt)
        return receipt

    def find(self, schedule_id: str) -> RetentionScheduleReceipt | None:
        for entry in self.log:
            if entry.schedule_id == schedule_id:
                return entry
        return None


def retention_schedule_mandate(
    registry: RetentionScheduleRegistry,
    schedule_id: str,
    checked_at: int,
) -> EducationVerdict:
    """Retention schedules are mandatory and self-deleting on expiry.

    A missing schedule is itself the violation
    (``education:no_retention_schedule`` — Illuminate lesson: publish the
    schedule). Data kept past ``retain_until`` is
    ``education:retention_overdue``: the post-check must auto-delete, so
    the verdict denies any further use.
    """
    _check_nonempty_str(schedule_id, "schedule_id")
    _check_ts(checked_at, "checked_at")
    try:
        _check_chain(registry.log, "retention_schedule")
    except EducationError as exc:
        return _deny("education:chain_broken", str(exc))
    entry = registry.find(schedule_id)
    if entry is None:
        return _deny(
            "education:no_retention_schedule",
            f"data schedule {schedule_id!r} was never published",
        )
    if checked_at > entry.retain_until:
        return _deny(
            "education:retention_overdue",
            f"data category {entry.data_category!r} kept past retain_until "
            f"{entry.retain_until} (checked at {checked_at}): auto-delete "
            "post-check",
        )
    return _allow(
        f"data category {entry.data_category!r} retained under live schedule "
        f"{schedule_id!r} until {entry.retain_until}",
        entry.receipt_digest,
    )
# ---------------------------------------------------------------------------
# 3. Evidentiary tiering (detector-demotion lesson)
# ---------------------------------------------------------------------------


def evidentiary_tiering(
    output_id: str,
    claimed_tier: str,
    human_reviewed: bool,
) -> EducationVerdict:
    """Automated judgments default to tier=signal.

    Universities are pulling AI-detector scores out of misconduct
    evidence: a flag opens a conversation, it doesn't close one. An
    output claiming tier ``"evidence"`` without a named-human review is
    ``education:tier_escalation`` — only ``"signal"`` may circulate
    unreviewed.
    """
    _check_nonempty_str(output_id, "output_id")
    if claimed_tier not in EVIDENTIARY_TIERS:
        raise EducationError(
            f"claimed_tier must be one of {EVIDENTIARY_TIERS}, saw {claimed_tier!r}"
        )
    _check_bool(human_reviewed, "human_reviewed")
    if claimed_tier == "evidence" and not human_reviewed:
        return _deny(
            "education:tier_escalation",
            f"automated judgment {output_id!r} claims tier 'evidence' without "
            "a human review (detector scores are signals, not evidence)",
        )
    return _allow(
        f"automated judgment {output_id!r} stays in tier {claimed_tier!r}"
        + (" (human-reviewed)" if human_reviewed else "")
    )


# ---------------------------------------------------------------------------
# 4. AI proposes, human disposes (Cambridge / AFT-Microsoft lesson)
# ---------------------------------------------------------------------------


def ai_proposes_human_disposes_gate(
    decision_id: str,
    decision_kind: str,
    ai_role: str,
    human_decided: bool,
) -> EducationVerdict:
    """Evaluative decisions: AI may flag or draft, never decide alone.

    Cambridge (May 2026): frontier models matched human degree
    classification only 35–65% and reward "style over substance" — AI is a
    discrepancy flagger. The AFT–Microsoft contract writes it down: AI
    may assist but not independently make evaluative decisions. An
    evaluative decision (grading/admissions/discipline) with
    ``ai_role="decide"`` and no human decision is
    ``education:ai_decided``.
    """
    _check_nonempty_str(decision_id, "decision_id")
    _check_nonempty_str(decision_kind, "decision_kind")
    if ai_role not in AI_ROLES:
        raise EducationError(
            f"ai_role must be one of {AI_ROLES}, saw {ai_role!r}"
        )
    _check_bool(human_decided, "human_decided")
    if (
        decision_kind in EVALUATIVE_KINDS
        and ai_role == "decide"
        and not human_decided
    ):
        return _deny(
            "education:ai_decided",
            f"evaluative decision {decision_id!r} ({decision_kind}) decided by "
            "AI alone: AI proposes, human disposes",
        )
    return _allow(
        f"decision {decision_id!r} ({decision_kind}): AI role {ai_role!r}, "
        f"human decided: {human_decided}"
    )


# ---------------------------------------------------------------------------
# 5. Developmental access staging (NYC moratorium lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StagingPolicyReceipt:
    """Staged access policy for one (band, capability) pair.

    Binds ``(band, capability, access, exceptions, effective_from,
    sunset_at)`` to an authority key. Bans are ban-until-evidence: every
    policy carries a ``sunset_at``; serving a band past the sunset with
    no renewed policy is fail-closed. Exceptions use the closed
    ``STAGING_EXCEPTIONS`` vocabulary (NYC: special needs, English
    learners, career-skills courses).
    """

    policy_id: str
    band: str
    capability: str
    access: str
    exceptions: tuple[str, ...]
    effective_from: int
    sunset_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": EDUCATION_SCHEMA_VERSION,
            "type": "staging_policy",
            "policy_id": self.policy_id,
            "band": self.band,
            "capability": self.capability,
            "access": self.access,
            "exceptions": list(self.exceptions),
            "effective_from": self.effective_from,
            "sunset_at": self.sunset_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class StagingPolicyRegistry:
    """Hash-chained log of staging-policy receipts per authority."""

    authorities: AuthorityRegistry
    log: list[StagingPolicyReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        *,
        policy_id: str,
        band: str,
        capability: str,
        access: str,
        exceptions: tuple[str, ...],
        effective_from: int,
        sunset_at: int,
        authority_id: str,
        signature: bytes,
        issued_at: int,
    ) -> StagingPolicyReceipt:
        _check_nonempty_str(policy_id, "policy_id")
        _check_band(band)
        _check_nonempty_str(capability, "capability")
        if access not in STAGING_ACCESS:
            raise EducationError(
                f"access must be one of {STAGING_ACCESS}, saw {access!r}"
            )
        for exc in exceptions:
            _check_exception(exc)
        _check_ts(effective_from, "effective_from")
        _check_ts(sunset_at, "sunset_at")
        _check_ts(issued_at, "issued_at")
        if sunset_at <= effective_from:
            raise EducationError("sunset_at must be after effective_from")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise EducationError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = StagingPolicyReceipt(
            policy_id=policy_id,
            band=band,
            capability=capability,
            access=access,
            exceptions=tuple(exceptions),
            effective_from=effective_from,
            sunset_at=sunset_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise EducationError(
                "staging-policy receipt authority signature invalid"
            )
        self.log.append(receipt)
        return receipt

    def latest(self, band: str, capability: str) -> StagingPolicyReceipt | None:
        for entry in reversed(self.log):
            if entry.band == band and entry.capability == capability:
                return entry
        return None


def developmental_access_staging(
    registry: StagingPolicyRegistry,
    band: str,
    capability: str,
    used_at: int,
    exception: str | None = None,
) -> EducationVerdict:
    """Staged access by developmental band, with exceptions and a sunset.

    A (band, capability) pair with no policy is
    ``education:no_staging_policy``; a policy past its ``sunset_at`` is
    ``education:stale_staging_policy`` (ban-until-evidence: the ban lapses
    only into a renewed, evidence-based policy — never into silent
    access); serving a ``deny``-staged capability without a listed
    exception is ``education:developmental_ban`` (NYC lesson: companion
    chatbots banned for pre-K–8, exceptions for special needs / English
    learners / career-skills courses).
    """
    _check_band(band)
    _check_nonempty_str(capability, "capability")
    _check_ts(used_at, "used_at")
    if exception is not None:
        _check_exception(exception)
    try:
        _check_chain(registry.log, "staging_policy")
    except EducationError as exc:
        return _deny("education:chain_broken", str(exc))
    entry = registry.latest(band, capability)
    if entry is None:
        return _deny(
            "education:no_staging_policy",
            f"no staging policy for band {band!r} + capability {capability!r}",
        )
    if used_at > entry.sunset_at:
        return _deny(
            "education:stale_staging_policy",
            f"staging policy {entry.policy_id!r} sunset at {entry.sunset_at} "
            f"(used at {used_at}): renew with evidence before serving",
        )
    if used_at < entry.effective_from:
        return _deny(
            "education:policy_not_effective",
            f"staging policy {entry.policy_id!r} not effective until "
            f"{entry.effective_from} (used at {used_at})",
        )
    if entry.access == "deny":
        if exception is None or exception not in entry.exceptions:
            return _deny(
                "education:developmental_ban",
                f"capability {capability!r} is deny-staged for band {band!r} "
                f"(policy {entry.policy_id!r}); no listed exception presented",
            )
        return _allow(
            f"capability {capability!r} served to band {band!r} under "
            f"exception {exception!r} (policy {entry.policy_id!r})",
            entry.receipt_digest,
        )
    return _allow(
        f"capability {capability!r} access {entry.access!r} for band {band!r} "
        f"(policy {entry.policy_id!r})",
        entry.receipt_digest,
    )
# ---------------------------------------------------------------------------
# 6. Language-parity audit (Kazakhstan lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParityProbeReceipt:
    """A cross-language equivalence probe for one language pair.

    Binds ``(pair_id, language_a, language_b, delta_bps, tolerance_bps,
    measured_at)`` to an authority key. The Kazakhstan finding: students
    trust automated assessment *except* where items are not equivalent
    across languages — so fairness audits must probe language parity,
    not just model bias scores. Deltas are basis points of pass-rate
    difference.
    """

    probe_id: str
    pair_id: str
    language_a: str
    language_b: str
    delta_bps: int
    tolerance_bps: int
    measured_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": EDUCATION_SCHEMA_VERSION,
            "type": "parity_probe",
            "probe_id": self.probe_id,
            "pair_id": self.pair_id,
            "language_a": self.language_a,
            "language_b": self.language_b,
            "delta_bps": self.delta_bps,
            "tolerance_bps": self.tolerance_bps,
            "measured_at": self.measured_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class LanguageParityRegistry:
    """Hash-chained log of parity-probe receipts per authority."""

    authorities: AuthorityRegistry
    log: list[ParityProbeReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        *,
        probe_id: str,
        pair_id: str,
        language_a: str,
        language_b: str,
        delta_bps: int,
        tolerance_bps: int,
        measured_at: int,
        authority_id: str,
        signature: bytes,
        issued_at: int,
    ) -> ParityProbeReceipt:
        _check_nonempty_str(probe_id, "probe_id")
        _check_nonempty_str(pair_id, "pair_id")
        _check_nonempty_str(language_a, "language_a")
        _check_nonempty_str(language_b, "language_b")
        if language_a == language_b:
            raise EducationError("language_a and language_b must differ")
        _check_bps(delta_bps, "delta_bps")
        _check_bps(tolerance_bps, "tolerance_bps")
        _check_ts(measured_at, "measured_at")
        _check_ts(issued_at, "issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise EducationError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = ParityProbeReceipt(
            probe_id=probe_id,
            pair_id=pair_id,
            language_a=language_a,
            language_b=language_b,
            delta_bps=delta_bps,
            tolerance_bps=tolerance_bps,
            measured_at=measured_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise EducationError(
                "parity-probe receipt authority signature invalid"
            )
        self.log.append(receipt)
        return receipt

    def latest(self, pair_id: str) -> ParityProbeReceipt | None:
        for entry in reversed(self.log):
            if entry.pair_id == pair_id:
                return entry
        return None


def language_parity_audit(
    registry: LanguageParityRegistry,
    pair_id: str,
    checked_at: int,
) -> EducationVerdict:
    """Cross-language equivalence must hold within the pinned tolerance.

    A pass-rate delta above ``tolerance_bps`` for a language pair is
    ``education:language_parity_gap`` — the assessment is not fair across
    languages even if the model looks unbiased in aggregate (Kazakhstan
    lesson). No probe at all is ``education:no_parity_probe``.
    """
    _check_nonempty_str(pair_id, "pair_id")
    _check_ts(checked_at, "checked_at")
    try:
        _check_chain(registry.log, "parity_probe")
    except EducationError as exc:
        return _deny("education:chain_broken", str(exc))
    entry = registry.latest(pair_id)
    if entry is None:
        return _deny(
            "education:no_parity_probe",
            f"no language-parity probe for pair {pair_id!r}",
        )
    if entry.measured_at > checked_at:
        return _deny(
            "education:future_parity_probe",
            f"parity probe {entry.probe_id!r} measured in the future",
        )
    if entry.delta_bps > entry.tolerance_bps:
        return _deny(
            "education:language_parity_gap",
            f"language pair {entry.language_a!r}/{entry.language_b!r} delta "
            f"{entry.delta_bps}bps exceeds tolerance {entry.tolerance_bps}bps",
        )
    return _allow(
        f"language pair {entry.language_a!r}/{entry.language_b!r} delta "
        f"{entry.delta_bps}bps within tolerance {entry.tolerance_bps}bps",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 7. Pseudonymous student mode (German school-policy lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PseudonymReceipt:
    """A per-student pseudonym issuance.

    Binds ``(pseudonym_id, subject_digest, issued_at, expires_at)`` to an
    authority key. ``subject_digest`` is a one-way digest of the student
    reference — the receipt never carries the identity itself. Default
    posture: pseudonyms on, identifiable collection off.
    """

    pseudonym_id: str
    subject_digest: str
    issued_at: int
    expires_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": EDUCATION_SCHEMA_VERSION,
            "type": "pseudonym",
            "pseudonym_id": self.pseudonym_id,
            "subject_digest": self.subject_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class PseudonymRegistry:
    """Hash-chained log of pseudonym receipts per authority."""

    authorities: AuthorityRegistry
    log: list[PseudonymReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        *,
        pseudonym_id: str,
        subject_digest: str,
        issued_at: int,
        expires_at: int,
        authority_id: str,
        signature: bytes,
    ) -> PseudonymReceipt:
        _check_nonempty_str(pseudonym_id, "pseudonym_id")
        _check_hex64(subject_digest, "subject_digest")
        _check_ts(issued_at, "issued_at")
        _check_ts(expires_at, "expires_at")
        if expires_at <= issued_at:
            raise EducationError("expires_at must be after issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise EducationError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = PseudonymReceipt(
            pseudonym_id=pseudonym_id,
            subject_digest=subject_digest,
            issued_at=issued_at,
            expires_at=expires_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise EducationError("pseudonym receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, pseudonym_id: str) -> PseudonymReceipt | None:
        for entry in self.log:
            if entry.pseudonym_id == pseudonym_id:
                return entry
        return None


def pseudonymous_student_mode(
    registry: PseudonymRegistry,
    pseudonym_id: str,
    collects_pii: bool,
    checked_at: int,
) -> EducationVerdict:
    """Pseudonyms by default; identifiable collection needs a live one.

    German school-policy lesson: no personal data into AI systems,
    pseudonymous student access, teacher-visible input review. Collecting
    identifiable student info without a live pseudonym is
    ``education:pii_without_pseudonym``; an expired pseudonym is
    ``education:pseudonym_expired``. Not collecting PII at all always
    passes — the default posture.
    """
    _check_nonempty_str(pseudonym_id, "pseudonym_id")
    _check_bool(collects_pii, "collects_pii")
    _check_ts(checked_at, "checked_at")
    if not collects_pii:
        return _allow("no identifiable student info collected (default posture)")
    try:
        _check_chain(registry.log, "pseudonym")
    except EducationError as exc:
        return _deny("education:chain_broken", str(exc))
    entry = registry.find(pseudonym_id)
    if entry is None:
        return _deny(
            "education:pii_without_pseudonym",
            f"identifiable student info collected with no pseudonym "
            f"{pseudonym_id!r} issued",
        )
    if checked_at > entry.expires_at:
        return _deny(
            "education:pseudonym_expired",
            f"pseudonym {pseudonym_id!r} expired at {entry.expires_at} "
            f"(checked at {checked_at})",
        )
    if checked_at < entry.issued_at:
        return _deny(
            "education:pseudonym_not_issued",
            f"pseudonym {pseudonym_id!r} not yet issued at {checked_at}",
        )
    return _allow(
        f"identifiable student info collected under live pseudonym "
        f"{pseudonym_id!r}",
        entry.receipt_digest,
    )
