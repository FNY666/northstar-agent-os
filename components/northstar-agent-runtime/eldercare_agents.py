"""Elder-care AI discipline (one-hundred-sixty-first batch).

Absorbs the 2026 AI-in-elder-care research thread:

* **China (2026)** — 3.2B people over 60, ~35M disabled/semi-disabled;
  care-worker demand ~6M vs ~0.5M actual (5.5M gap). The elder-care
  robot market is heading past CNY 10B, but professional-care robot
  penetration is only ~1.2%; what actually deploys is point devices
  (Shenzhen mmWave fall radar syncing children in 20s, Wuxi 24h robot
  patrols), not humanoids. Beijing Yizhuang retired 10+ robot models
  in five months — a robot that recited poetry with elders was
  removed within a week (poetry is not care).
* **Japan MHLW 2026 white paper** — 73.8% approve care robots; the
  Yamashita 2026 survey: "notify on anomaly" preferred at 76.3% vs
  "always watchable camera" at 47.6%; self-consent raises willingness
  +73.9%.
* **Korea MOHW** — new care-tech team; Naver Clova CareCall ~50k
  users by 2026-03.
* **France (EHPAD La Septfontoise, AFP 2026-09-19)** — the Livana
  pilot: AI imitating a grandchild's voice talking with Alzheimer's
  patients, pre-configured by family + facility psychologist, **no
  audio retained**. Core ethics tension: comforting vs deceiving a
  cognitively impaired person with an absent/deceased loved one's
  voice.
* **US** — SafelyYou NAD ruling (2026-08-19): "40% fewer falls" type
  claims upheld as evidence-backed, but "99% fall-detection accuracy"
  required a disclosure fix (single-study basis). SafeSpace renders
  residents as avatars ("giraffes, donkeys, dogs") instead of
  transmitting real images; room cameras are opt-out.
* **Australia (South Australia pilot)** — 12,000 false alarms in a
  year from CCTV+AI fall detection; alarm fatigue left at least one
  real fall unanswered. McKnight's (2026-08): "cameras record, they
  don't prevent."
* **EU** — care-priority/triage is Annex III high-risk (compliance
  2027-12-02); Art. 50 disclosure duty live 2026-08-02; Art. 5 banned
  workplace/education emotion inference from 2026-02-02 (care
  settings sit in a grey zone, treated as fail-closed here).

Northstar mapping: monitoring defaults to anomaly-only alerts;
always-watch requires a live signed opt-in and can be revoked at
any time. Consent is a three-party receipt chain (resident where
capable / family / care professional); any withdrawal drops the
system to minimal-intrusion mode. Each alert channel carries a
false-alarm budget; budget exhaustion is a system-level failure
that forces human patrol. Imitating a real person's voice or image
binds a disclosure receipt understandable to the resident, with a
dual signature for cognitively impaired residents — soothing
effect never waives disclosure. Video streams default to avatars;
audio is not retained without a separate time-limited consent.
Prevention claims must bind independent-study evidence digests
(self-reported numbers refuse). AI deployments bind human-staffing
and human-contact floors; rosters below the floor or contact
declines deny. Emotion-inference outputs are signal-only: they
never drive restraining actions; restraint requires a human
decision.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), canonical JCS hashing, Ed25519 via the vendored
``ed25519`` module, digest comparisons via :func:`hmac.compare_digest`.

Honest scope: the receipts verify the *claimed* bundle is
self-consistent and authority-signed; they cannot prove the
anomaly detector was honestly calibrated, the opt-in was
understood, the family signer was the resident's true proxy, or
the roster hours were really worked. Those need independent
evidence.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


ELDERCARE_SCHEMA_VERSION = "northstar.eldercare-discipline.v1"

__all__ = [
    "ELDERCARE_SCHEMA_VERSION",
    "EldercareError",
    "EldercareVerdict",
    "MonitoringMode",
    "MonitoringModeReceipt",
    "MonitoringRegistry",
    "ConsentParty",
    "ConsentReceipt",
    "ConsentChain",
    "ConsentChainRegistry",
    "FalseAlarmChannel",
    "FalseAlarmRegistry",
    "VoiceImpersonationReceipt",
    "VoiceImpersonationRegistry",
    "VideoStreamConfig",
    "AudioRetentionReceipt",
    "AudioRetentionRegistry",
    "PreventionClaimReceipt",
    "PreventionEvidenceRegistry",
    "StaffingFloorReceipt",
    "StaffingFloorRegistry",
    "ContactFloorReport",
    "EmotionSignal",
    "anomaly_only_monitoring",
    "check_monitoring_mode",
    "check_consent_chain",
    "care_false_alarm_budget",
    "check_false_alarm_budget",
    "check_voice_impersonation",
    "avatar_anonymization",
    "check_video_stream",
    "no_audio_retention_pin",
    "check_audio_retention",
    "surveillance_not_prevention",
    "check_prevention_evidence",
    "staff_augmentation_floor",
    "check_staffing_floor",
    "human_contact_floor",
    "check_contact_floor",
    "emotion_inference_care_boundary",
    "check_emotion_boundary",
    "MODE_ANOMALY_ONLY",
    "MODE_ALWAYS_WATCH",
    "MONITORING_MODES",
    "CONSENT_SCOPE_MONITORING",
    "CONSENT_SCOPE_AUDIO",
    "CONSENT_SCOPE_VIDEO",
    "CONSENT_SCOPE_VOICE_COMPANION",
    "PARTY_RESIDENT",
    "PARTY_FAMILY",
    "PARTY_PROFESSIONAL",
    "CLASS_ALLOW",
    "CLASS_DENY",
    "CLASS_MINIMAL_INTRUSION",
]

#: Monitoring modes. Default is anomaly-only; always-watch is an
#: explicit, revocable escalation (Yamashita 2026: 76.3% vs 47.6%).
MODE_ANOMALY_ONLY = "anomaly_only"
MODE_ALWAYS_WATCH = "always_watch"
MONITORING_MODES = (MODE_ANOMALY_ONLY, MODE_ALWAYS_WATCH)

#: Consent scopes. Scope is matched exactly at use time.
CONSENT_SCOPE_MONITORING = "monitoring"
CONSENT_SCOPE_AUDIO = "audio"
CONSENT_SCOPE_VIDEO = "video"
CONSENT_SCOPE_VOICE_COMPANION = "voice_companion"

#: Three-party consent chain roles (Livana operationalized).
PARTY_RESIDENT = "resident"
PARTY_FAMILY = "family"
PARTY_PROFESSIONAL = "professional"

#: Resident digital-division capability flag: whether the resident
#: can give their own consent. When False, the resident party is
#: filled by a legally-appointed proxy (still recorded as
#: ``party="resident"`` with ``proxy=True``).
RESIDENT_CAPABLE = "resident_capable"

#: Verdict classifications.
CLASS_ALLOW = "allow"
CLASS_DENY = "deny"
CLASS_MINIMAL_INTRUSION = "minimal_intrusion"

#: Max age (1 year) for an opt-in receipt before re-consent is due.
MAX_OPTIN_AGE_S = 365 * 86_400

#: Default false-alarm budget per channel per year (South Australia:
#: 12,000/year was the textbook failure; the budget must be pinned
#: far below that, per facility risk appetite).
DEFAULT_FALSE_ALARM_BUDGET = 500

_HEX64_LENGTH = 64
_DAY_S = 86_400


class EldercareError(ValueError):
    """A malformed receipt/record or a programming error.

    Raised for structural problems (bad digests, bad signatures,
    unknown parties, out-of-range values). Verification *failures*
    (stale, missing, over-budget) return an :class:`EldercareVerdict`
    with ``allowed=False`` — a failed gate check is a verdict, a
    malformed log is a bug.
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
        raise EldercareError(f"{field_name} must be a 64-char hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EldercareError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EldercareError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise EldercareError(f"{field_name} must be 32 bytes")
    return value


def _check_pubkey_hex(value: Any) -> str:
    return _check_hex64(value, "authority_pubkey_hex")


def _check_nonneg_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EldercareError(f"{field_name} must be a non-negative int")
    return value


@dataclass
class EldercareVerdict:
    """Result of a gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_DENY

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise EldercareError("allowed must be a bool")
        if not isinstance(self.reason, str) or not self.reason:
            raise EldercareError("reason must be a non-empty string")
        if self.classification not in (
            CLASS_ALLOW,
            CLASS_DENY,
            CLASS_MINIMAL_INTRUSION,
        ):
            raise EldercareError("classification must be allow/deny/minimal_intrusion")


def _verdict_sign(
    *,
    gate: str,
    receipt_digest: str,
    allowed: bool,
    reason: str,
    classification: str,
    authority_secret: bytes,
    signed_at: int,
) -> "SignedVerdict":
    _check_nonempty_str(gate, "gate")
    _check_hex64(receipt_digest, "receipt_digest")
    _check_secret(authority_secret, "authority_secret")
    _check_ts(signed_at, "signed_at")
    payload = {
        "schema": ELDERCARE_SCHEMA_VERSION,
        "gate": gate,
        "receipt_digest": receipt_digest,
        "allowed": allowed,
        "reason": reason,
        "classification": classification,
        "signed_at": signed_at,
    }
    message = jcs_canonical_json(payload)
    signature = ed25519.sign(authority_secret, message)
    return SignedVerdict(
        gate=gate,
        receipt_digest=receipt_digest,
        allowed=allowed,
        reason=reason,
        classification=classification,
        signed_at=signed_at,
        signature=signature.hex(),
    )


@dataclass
class SignedVerdict:
    """Ed25519-signed gate verdict."""

    gate: str
    receipt_digest: str
    allowed: bool
    reason: str
    classification: str
    signed_at: int
    signature: str


def _verify_signature(pubkey_hex: str, payload: dict[str, Any], signature_hex: str) -> bool:
    try:
        pubkey = bytes.fromhex(pubkey_hex)
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    message = jcs_canonical_json(payload)
    # vendored ed25519.verify() returns bool; a bare call is wrong
    # (see batch-147 security note: an ignored False return could
    # accept forged signatures).
    return bool(ed25519.verify(pubkey, message, signature))


# ---------------------------------------------------------------------------
# 1. Monitoring mode: anomaly-only default, always-watch needs opt-in
# ---------------------------------------------------------------------------


class MonitoringMode(str):
    """Monitoring mode value object."""


@dataclass
class MonitoringModeReceipt:
    """Opt-in receipt for always-watch monitoring.

    Anomaly-only needs no receipt (it is the default). Always-watch
    requires a live, signed opt-in naming the resident, scope, and
    expiry; it can be revoked at any time.
    """

    receipt_id: str
    resident_id: str
    mode: str
    opt_in_at: int
    expires_at: int
    scope: str
    signature: str


class MonitoringRegistry:
    """Registry of authority keys that may sign monitoring opt-ins."""

    def __init__(self, authority_pubkeys: list[str]) -> None:
        for key in authority_pubkeys:
            _check_pubkey_hex(key)
        self._pubkeys = list(authority_pubkeys)

    def issue_opt_in(
        self,
        *,
        receipt_id: str,
        resident_id: str,
        mode: str,
        scope: str,
        opt_in_at: int,
        expires_at: int,
        authority_secret: bytes,
    ) -> MonitoringModeReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(resident_id, "resident_id")
        if mode not in MONITORING_MODES:
            raise EldercareError("mode must be anomaly_only/always_watch")
        _check_nonempty_str(scope, "scope")
        _check_ts(opt_in_at, "opt_in_at")
        _check_ts(expires_at, "expires_at")
        if expires_at <= opt_in_at:
            raise EldercareError("expires_at must be after opt_in_at")
        _check_secret(authority_secret, "authority_secret")
        payload = {
            "schema": ELDERCARE_SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "resident_id": resident_id,
            "mode": mode,
            "scope": scope,
            "opt_in_at": opt_in_at,
            "expires_at": expires_at,
        }
        signature = ed25519.sign(authority_secret, jcs_canonical_json(payload))
        return MonitoringModeReceipt(
            receipt_id=receipt_id,
            resident_id=resident_id,
            mode=mode,
            opt_in_at=opt_in_at,
            expires_at=expires_at,
            scope=scope,
            signature=signature.hex(),
        )

    def verify_opt_in(self, receipt: MonitoringModeReceipt) -> bool:
        payload = {
            "schema": ELDERCARE_SCHEMA_VERSION,
            "receipt_id": receipt.receipt_id,
            "resident_id": receipt.resident_id,
            "mode": receipt.mode,
            "scope": receipt.scope,
            "opt_in_at": receipt.opt_in_at,
            "expires_at": receipt.expires_at,
        }
        return any(
            _verify_signature(key, payload, receipt.signature)
            for key in self._pubkeys
        )


def anomaly_only_monitoring() -> str:
    """Return the mandatory default monitoring mode."""
    return MODE_ANOMALY_ONLY


def check_monitoring_mode(
    *,
    registry: MonitoringRegistry,
    resident_id: str,
    mode: str,
    opt_in: MonitoringModeReceipt | None,
    now: int,
) -> EldercareVerdict:
    """Gate: monitoring mode vs opt-in receipts.

    ``anomaly_only`` always passes (the default). ``always_watch``
    passes only with a live, verified, unexpired opt-in receipt for
    the same resident and scope. Anything else denies.
    """
    _check_nonempty_str(resident_id, "resident_id")
    _check_ts(now, "now")
    if mode == MODE_ANOMALY_ONLY:
        return EldercareVerdict(True, "anomaly-only monitoring is the default", CLASS_ALLOW)
    if mode != MODE_ALWAYS_WATCH:
        return EldercareVerdict(False, "eldercare:unknown_monitoring_mode", CLASS_DENY)
    if opt_in is None:
        return EldercareVerdict(
            False, "eldercare:always_watch_without_opt_in", CLASS_DENY
        )
    if not hmac.compare_digest(opt_in.resident_id, resident_id):
        return EldercareVerdict(
            False, "eldercare:opt_in_resident_mismatch", CLASS_DENY
        )
    if opt_in.mode != MODE_ALWAYS_WATCH:
        return EldercareVerdict(
            False, "eldercare:opt_in_mode_mismatch", CLASS_DENY
        )
    if now < opt_in.opt_in_at or now >= opt_in.expires_at:
        return EldercareVerdict(
            False, "eldercare:opt_in_not_live", CLASS_DENY
        )
    if not registry.verify_opt_in(opt_in):
        return EldercareVerdict(
            False, "eldercare:opt_in_signature_invalid", CLASS_DENY
        )
    return EldercareVerdict(True, "always-watch covered by live opt-in", CLASS_ALLOW)


# ---------------------------------------------------------------------------
# 2. Three-party consent receipt chain
# ---------------------------------------------------------------------------


@dataclass
class ConsentParty:
    """One party's consent in the chain."""

    party: str
    consented_at: int
    scope: str
    data_types: tuple[str, ...]
    retention_days: int
    proxy: bool = False
    withdrawn_at: int | None = None
    signature: str = ""


@dataclass
class ConsentReceipt:
    """A signed consent grant from one party."""

    receipt_id: str
    resident_id: str
    party: str
    scope: str
    data_types: tuple[str, ...]
    retention_days: int
    consented_at: int
    proxy: bool
    signature: str


@dataclass
class ConsentChain:
    """The three-party chain: resident (or proxy) + family + professional."""

    resident_id: str
    receipts: dict[str, ConsentReceipt]
    withdrawals: dict[str, int]


class ConsentChainRegistry:
    """Registry of authority keys that may sign consent receipts."""

    def __init__(self, authority_pubkeys: list[str]) -> None:
        for key in authority_pubkeys:
            _check_pubkey_hex(key)
        self._pubkeys = list(authority_pubkeys)

    def issue(
        self,
        *,
        receipt_id: str,
        resident_id: str,
        party: str,
        scope: str,
        data_types: tuple[str, ...],
        retention_days: int,
        consented_at: int,
        proxy: bool,
        authority_secret: bytes,
    ) -> ConsentReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(resident_id, "resident_id")
        if party not in (PARTY_RESIDENT, PARTY_FAMILY, PARTY_PROFESSIONAL):
            raise EldercareError("party must be resident/family/professional")
        _check_nonempty_str(scope, "scope")
        if not data_types:
            raise EldercareError("data_types must be non-empty")
        for dtype in data_types:
            _check_nonempty_str(dtype, "data_type")
        if not isinstance(retention_days, int) or retention_days < 0:
            raise EldercareError("retention_days must be a non-negative int")
        _check_ts(consented_at, "consented_at")
        if not isinstance(proxy, bool):
            raise EldercareError("proxy must be a bool")
        _check_secret(authority_secret, "authority_secret")
        payload = {
            "schema": ELDERCARE_SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "resident_id": resident_id,
            "party": party,
            "scope": scope,
            "data_types": list(data_types),
            "retention_days": retention_days,
            "consented_at": consented_at,
            "proxy": proxy,
        }
        signature = ed25519.sign(authority_secret, jcs_canonical_json(payload))
        return ConsentReceipt(
            receipt_id=receipt_id,
            resident_id=resident_id,
            party=party,
            scope=scope,
            data_types=tuple(data_types),
            retention_days=retention_days,
            consented_at=consented_at,
            proxy=proxy,
            signature=signature.hex(),
        )

    def verify(self, receipt: ConsentReceipt) -> bool:
        payload = {
            "schema": ELDERCARE_SCHEMA_VERSION,
            "receipt_id": receipt.receipt_id,
            "resident_id": receipt.resident_id,
            "party": receipt.party,
            "scope": receipt.scope,
            "data_types": list(receipt.data_types),
            "retention_days": receipt.retention_days,
            "consented_at": receipt.consented_at,
            "proxy": receipt.proxy,
        }
        return any(
            _verify_signature(key, payload, receipt.signature)
            for key in self._pubkeys
        )


def check_consent_chain(
    *,
    registry: ConsentChainRegistry,
    chain: ConsentChain,
    scope: str,
    now: int,
) -> EldercareVerdict:
    """Gate: three-party consent chain.

    All three parties must hold live, verified, unwithdrawn receipts
    covering the requested scope at ``now``. Any missing, expired,
    revoked, withdrawn, or invalid party drops the deployment to
    minimal-intrusion mode (allowed=False, classification
    minimal_intrusion) — it does not fully shut down, because the
    fail-safe fallback is event-only monitoring.
    """
    _check_nonempty_str(scope, "scope")
    _check_ts(now, "now")
    missing: list[str] = []
    for party in (PARTY_RESIDENT, PARTY_FAMILY, PARTY_PROFESSIONAL):
        receipt = chain.receipts.get(party)
        if receipt is None:
            missing.append(party)
            continue
        if receipt.party != party:
            missing.append(f"{party}:party_mismatch")
            continue
        if receipt.scope != scope:
            missing.append(f"{party}:scope_mismatch")
            continue
        if not hmac.compare_digest(receipt.resident_id, chain.resident_id):
            missing.append(f"{party}:resident_mismatch")
            continue
        if not registry.verify(receipt):
            missing.append(f"{party}:signature_invalid")
            continue
        withdrawn = chain.withdrawals.get(party)
        if withdrawn is not None and now >= withdrawn:
            missing.append(f"{party}:withdrawn")
            continue
        if now - receipt.consented_at > MAX_OPTIN_AGE_S:
            missing.append(f"{party}:stale")
            continue
    if missing:
        return EldercareVerdict(
            False,
            "eldercare:consent_chain_broken:" + ",".join(missing),
            CLASS_MINIMAL_INTRUSION,
        )
    return EldercareVerdict(True, "three-party consent chain live", CLASS_ALLOW)


# ---------------------------------------------------------------------------
# 3. False-alarm budgets
# ---------------------------------------------------------------------------


@dataclass
class FalseAlarmChannel:
    """An alert channel with a pinned false-alarm budget."""

    channel_id: str
    facility_id: str
    budget_per_year: int
    false_alarms: int
    window_start: int
    window_days: int = 365


class FalseAlarmRegistry:
    """Tracks declared channel budgets."""

    def __init__(self) -> None:
        self._channels: dict[str, FalseAlarmChannel] = {}

    def register(self, channel: FalseAlarmChannel) -> None:
        _check_nonempty_str(channel.channel_id, "channel_id")
        _check_nonempty_str(channel.facility_id, "facility_id")
        _check_nonneg_int(channel.budget_per_year, "budget_per_year")
        _check_nonneg_int(channel.false_alarms, "false_alarms")
        _check_ts(channel.window_start, "window_start")
        self._channels[channel.channel_id] = channel

    def record_false_alarm(self, channel_id: str) -> None:
        channel = self._channels.get(channel_id)
        if channel is None:
            raise EldercareError("unknown false-alarm channel")
        channel.false_alarms += 1


def care_false_alarm_budget() -> int:
    """Return the recommended default false-alarm budget per channel/year."""
    return DEFAULT_FALSE_ALARM_BUDGET


def check_false_alarm_budget(
    *,
    registry: FalseAlarmRegistry,
    channel_id: str,
    now: int,
) -> EldercareVerdict:
    """Gate: false-alarm budget per channel.

    A channel that exhausted its budget is denied — it must fall
    back to human patrol and vendor remediation (South Australia
    lesson: alarm fatigue that buries real falls is a system-level
    failure).
    """
    _check_nonempty_str(channel_id, "channel_id")
    _check_ts(now, "now")
    channel = registry._channels.get(channel_id)
    if channel is None:
        return EldercareVerdict(False, "eldercare:unknown_alarm_channel", CLASS_DENY)
    if channel.false_alarms >= channel.budget_per_year:
        return EldercareVerdict(
            False,
            f"eldercare:alarm_fatigue:{channel.false_alarms}/{channel.budget_per_year}",
            CLASS_DENY,
        )
    return EldercareVerdict(
        True,
        f"within false-alarm budget ({channel.false_alarms}/{channel.budget_per_year})",
        CLASS_ALLOW,
    )


# ---------------------------------------------------------------------------
# 4. Voice impersonation disclosure
# ---------------------------------------------------------------------------


@dataclass
class VoiceImpersonationReceipt:
    """Receipt binding a voice-companion deployment to its disclosure."""

    receipt_id: str
    resident_id: str
    impersonated_person: str
    relationship: str
    disclosure_text: str
    resident_cognitively_impaired: bool
    family_signature: str
    professional_signature: str
    configured_at: int


class VoiceImpersonationRegistry:
    """Registry of authority keys that may sign impersonation disclosures."""

    def __init__(self, authority_pubkeys: list[str]) -> None:
        for key in authority_pubkeys:
            _check_pubkey_hex(key)
        self._pubkeys = list(authority_pubkeys)

    def issue(
        self,
        *,
        receipt_id: str,
        resident_id: str,
        impersonated_person: str,
        relationship: str,
        disclosure_text: str,
        resident_cognitively_impaired: bool,
        configured_at: int,
        family_secret: bytes,
        professional_secret: bytes,
    ) -> VoiceImpersonationReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(resident_id, "resident_id")
        _check_nonempty_str(impersonated_person, "impersonated_person")
        _check_nonempty_str(relationship, "relationship")
        _check_nonempty_str(disclosure_text, "disclosure_text")
        if not isinstance(resident_cognitively_impaired, bool):
            raise EldercareError("resident_cognitively_impaired must be a bool")
        _check_ts(configured_at, "configured_at")
        _check_secret(family_secret, "family_secret")
        _check_secret(professional_secret, "professional_secret")
        base = {
            "schema": ELDERCARE_SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "resident_id": resident_id,
            "impersonated_person": impersonated_person,
            "relationship": relationship,
            "disclosure_text": disclosure_text,
            "resident_cognitively_impaired": resident_cognitively_impaired,
            "configured_at": configured_at,
        }
        family_sig = ed25519.sign(
            family_secret, jcs_canonical_json({**base, "role": PARTY_FAMILY})
        )
        professional_sig = ed25519.sign(
            professional_secret,
            jcs_canonical_json({**base, "role": PARTY_PROFESSIONAL}),
        )
        return VoiceImpersonationReceipt(
            receipt_id=receipt_id,
            resident_id=resident_id,
            impersonated_person=impersonated_person,
            relationship=relationship,
            disclosure_text=disclosure_text,
            resident_cognitively_impaired=resident_cognitively_impaired,
            family_signature=family_sig.hex(),
            professional_signature=professional_sig.hex(),
            configured_at=configured_at,
        )

    def verify(self, receipt: VoiceImpersonationReceipt) -> bool:
        base = {
            "schema": ELDERCARE_SCHEMA_VERSION,
            "receipt_id": receipt.receipt_id,
            "resident_id": receipt.resident_id,
            "impersonated_person": receipt.impersonated_person,
            "relationship": receipt.relationship,
            "disclosure_text": receipt.disclosure_text,
            "resident_cognitively_impaired": receipt.resident_cognitively_impaired,
            "configured_at": receipt.configured_at,
        }
        family_ok = any(
            _verify_signature(key, {**base, "role": PARTY_FAMILY}, receipt.family_signature)
            for key in self._pubkeys
        )
        professional_ok = any(
            _verify_signature(
                key, {**base, "role": PARTY_PROFESSIONAL}, receipt.professional_signature
            )
            for key in self._pubkeys
        )
        return family_ok and professional_ok


def check_voice_impersonation(
    *,
    registry: VoiceImpersonationRegistry,
    resident_id: str,
    impersonates_real_person: bool,
    disclosure: VoiceImpersonationReceipt | None,
    resident_cognitively_impaired: bool,
    now: int,
) -> EldercareVerdict:
    """Gate: voice impersonation disclosure (Livana lesson).

    A companion that does not imitate a real person passes without a
    disclosure receipt. One that does must bind a disclosure receipt
    understandable to the resident; for cognitively impaired
    residents the receipt must carry both family and professional
    signatures. Therapeutic effect never waives disclosure.
    """
    _check_nonempty_str(resident_id, "resident_id")
    _check_ts(now, "now")
    if not impersonates_real_person:
        return EldercareVerdict(True, "no real-person impersonation", CLASS_ALLOW)
    if disclosure is None:
        return EldercareVerdict(
            False, "eldercare:undisclosed_impersonation", CLASS_DENY
        )
    if not hmac.compare_digest(disclosure.resident_id, resident_id):
        return EldercareVerdict(
            False, "eldercare:disclosure_resident_mismatch", CLASS_DENY
        )
    if resident_cognitively_impaired and not registry.verify(disclosure):
        return EldercareVerdict(
            False, "eldercare:impersonation_dual_sign_missing", CLASS_DENY
        )
    if not resident_cognitively_impaired and not registry.verify(disclosure):
        return EldercareVerdict(
            False, "eldercare:impersonation_signature_invalid", CLASS_DENY
        )
    if not disclosure.disclosure_text.strip():
        return EldercareVerdict(
            False, "eldercare:impersonation_empty_disclosure", CLASS_DENY
        )
    return EldercareVerdict(True, "impersonation disclosure bound", CLASS_ALLOW)


# ---------------------------------------------------------------------------
# 5. Video stream anonymization (avatar default)
# ---------------------------------------------------------------------------


@dataclass
class VideoStreamConfig:
    """Configuration of a care video stream to a remote viewer."""

    stream_id: str
    resident_id: str
    presentation: str  # "avatar" | "blurred" | "raw"
    event_triggered: bool
    viewer_role: str  # "family" | "staff" | "vendor" | ...


def avatar_anonymization() -> str:
    """Return the mandatory default video presentation."""
    return "avatar"


def check_video_stream(*, config: VideoStreamConfig) -> EldercareVerdict:
    """Gate: video streams default to avatars (SafeSpace lesson).

    Remote viewers see an anonymized presentation (avatar or blur)
    by default. Raw imagery transmits only for an event-triggered
    stream to an authorized viewer role (family or staff) — never to
    vendors or general remote dashboards.
    """
    _check_nonempty_str(config.stream_id, "stream_id")
    _check_nonempty_str(config.resident_id, "resident_id")
    _check_nonempty_str(config.presentation, "presentation")
    if config.presentation in ("avatar", "blurred"):
        return EldercareVerdict(True, "anonymized video presentation", CLASS_ALLOW)
    if config.presentation == "raw":
        if config.event_triggered and config.viewer_role in ("family", "staff"):
            return EldercareVerdict(True, "event-triggered raw stream to authorized viewer", CLASS_ALLOW)
        return EldercareVerdict(
            False, "eldercare:raw_video_without_event_or_authority", CLASS_DENY
        )
    return EldercareVerdict(False, "eldercare:unknown_video_presentation", CLASS_DENY)


# ---------------------------------------------------------------------------
# 6. No audio retention (Livana: audio is not stored)
# ---------------------------------------------------------------------------


@dataclass
class AudioRetentionReceipt:
    """Separate, time-limited consent for retaining companion audio."""

    receipt_id: str
    resident_id: str
    retention_days: int
    consented_at: int
    expires_at: int
    signature: str


class AudioRetentionRegistry:
    """Registry of authority keys that may sign audio-retention receipts."""

    def __init__(self, authority_pubkeys: list[str]) -> None:
        for key in authority_pubkeys:
            _check_pubkey_hex(key)
        self._pubkeys = list(authority_pubkeys)

    def issue(
        self,
        *,
        receipt_id: str,
        resident_id: str,
        retention_days: int,
        consented_at: int,
        expires_at: int,
        authority_secret: bytes,
    ) -> AudioRetentionReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(resident_id, "resident_id")
        if not isinstance(retention_days, int) or retention_days <= 0:
            raise EldercareError("retention_days must be a positive int")
        _check_ts(consented_at, "consented_at")
        _check_ts(expires_at, "expires_at")
        if expires_at <= consented_at:
            raise EldercareError("expires_at must be after consented_at")
        _check_secret(authority_secret, "authority_secret")
        payload = {
            "schema": ELDERCARE_SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "resident_id": resident_id,
            "retention_days": retention_days,
            "consented_at": consented_at,
            "expires_at": expires_at,
        }
        signature = ed25519.sign(authority_secret, jcs_canonical_json(payload))
        return AudioRetentionReceipt(
            receipt_id=receipt_id,
            resident_id=resident_id,
            retention_days=retention_days,
            consented_at=consented_at,
            expires_at=expires_at,
            signature=signature.hex(),
        )

    def verify(self, receipt: AudioRetentionReceipt) -> bool:
        payload = {
            "schema": ELDERCARE_SCHEMA_VERSION,
            "receipt_id": receipt.receipt_id,
            "resident_id": receipt.resident_id,
            "retention_days": receipt.retention_days,
            "consented_at": receipt.consented_at,
            "expires_at": receipt.expires_at,
        }
        return any(
            _verify_signature(key, payload, receipt.signature)
            for key in self._pubkeys
        )


def no_audio_retention_pin() -> str:
    """Return the default audio-retention policy."""
    return "no_retention"


def check_audio_retention(
    *,
    registry: AudioRetentionRegistry,
    resident_id: str,
    retains_audio: bool,
    receipt: AudioRetentionReceipt | None,
    now: int,
) -> EldercareVerdict:
    """Gate: audio retention pins (Livana lesson).

    Companion audio is not retained by default. Retention passes only
    with a separate, live, signed, time-limited retention receipt for
    the same resident.
    """
    _check_nonempty_str(resident_id, "resident_id")
    _check_ts(now, "now")
    if not retains_audio:
        return EldercareVerdict(True, "no audio retained", CLASS_ALLOW)
    if receipt is None:
        return EldercareVerdict(
            False, "eldercare:audio_retention_without_consent", CLASS_DENY
        )
    if not hmac.compare_digest(receipt.resident_id, resident_id):
        return EldercareVerdict(
            False, "eldercare:retention_resident_mismatch", CLASS_DENY
        )
    if now < receipt.consented_at or now >= receipt.expires_at:
        return EldercareVerdict(
            False, "eldercare:retention_receipt_not_live", CLASS_DENY
        )
    if not registry.verify(receipt):
        return EldercareVerdict(
            False, "eldercare:retention_signature_invalid", CLASS_DENY
        )
    return EldercareVerdict(
        True, f"audio retention bound ({receipt.retention_days}d)", CLASS_ALLOW
    )


# ---------------------------------------------------------------------------
# 7. Surveillance is not prevention: evidence gate for vendor claims
# ---------------------------------------------------------------------------


@dataclass
class PreventionClaimReceipt:
    """A vendor prevention claim binding its study evidence."""

    claim_id: str
    claim_text: str
    claimed_reduction_bps: int
    study_digest: str  # hex digest of the independent study evidence
    independent: bool
    issued_at: int
    signature: str


class PreventionEvidenceRegistry:
    """Registry of authority keys that may sign prevention claims."""

    def __init__(self, authority_pubkeys: list[str]) -> None:
        for key in authority_pubkeys:
            _check_pubkey_hex(key)
        self._pubkeys = list(authority_pubkeys)

    def issue(
        self,
        *,
        claim_id: str,
        claim_text: str,
        claimed_reduction_bps: int,
        study_digest: str,
        independent: bool,
        issued_at: int,
        authority_secret: bytes,
    ) -> PreventionClaimReceipt:
        _check_nonempty_str(claim_id, "claim_id")
        _check_nonempty_str(claim_text, "claim_text")
        if (
            not isinstance(claimed_reduction_bps, int)
            or isinstance(claimed_reduction_bps, bool)
            or not 0 <= claimed_reduction_bps <= 10_000
        ):
            raise EldercareError("claimed_reduction_bps must be in [0, 10000]")
        _check_hex64(study_digest, "study_digest")
        if not isinstance(independent, bool):
            raise EldercareError("independent must be a bool")
        _check_ts(issued_at, "issued_at")
        _check_secret(authority_secret, "authority_secret")
        payload = {
            "schema": ELDERCARE_SCHEMA_VERSION,
            "claim_id": claim_id,
            "claim_text": claim_text,
            "claimed_reduction_bps": claimed_reduction_bps,
            "study_digest": study_digest,
            "independent": independent,
            "issued_at": issued_at,
        }
        signature = ed25519.sign(authority_secret, jcs_canonical_json(payload))
        return PreventionClaimReceipt(
            claim_id=claim_id,
            claim_text=claim_text,
            claimed_reduction_bps=claimed_reduction_bps,
            study_digest=study_digest,
            independent=independent,
            issued_at=issued_at,
            signature=signature.hex(),
        )

    def verify(self, receipt: PreventionClaimReceipt) -> bool:
        payload = {
            "schema": ELDERCARE_SCHEMA_VERSION,
            "claim_id": receipt.claim_id,
            "claim_text": receipt.claim_text,
            "claimed_reduction_bps": receipt.claimed_reduction_bps,
            "study_digest": receipt.study_digest,
            "independent": receipt.independent,
            "issued_at": receipt.issued_at,
        }
        return any(
            _verify_signature(key, payload, receipt.signature)
            for key in self._pubkeys
        )


def surveillance_not_prevention() -> str:
    """Return the evidence-class tag for surveillance-only claims."""
    return "surveillance_is_not_prevention"


def check_prevention_evidence(
    *,
    registry: PreventionEvidenceRegistry,
    claim: PreventionClaimReceipt | None,
    claims_prevention: bool,
) -> EldercareVerdict:
    """Gate: prevention claims need independent-study evidence.

    "We monitor" is not "we prevent" (McKnight's). A claim that the
    deployment reduces falls/harm passes only when bound to a
    signed receipt whose study evidence is marked independent —
    single-vendor studies (NAD's SafelyYou lesson) count as
    self-reported and refuse.
    """
    if not claims_prevention:
        return EldercareVerdict(True, "no prevention claimed", CLASS_ALLOW)
    if claim is None:
        return EldercareVerdict(
            False, "eldercare:prevention_claim_without_evidence", CLASS_DENY
        )
    if not registry.verify(claim):
        return EldercareVerdict(
            False, "eldercare:prevention_claim_signature_invalid", CLASS_DENY
        )
    if not claim.independent:
        return EldercareVerdict(
            False, "eldercare:unverified_prevention_claim", CLASS_DENY
        )
    return EldercareVerdict(True, "prevention claim evidence-bound", CLASS_ALLOW)


# ---------------------------------------------------------------------------
# 8. Staffing floors bound to AI deployment
# ---------------------------------------------------------------------------


@dataclass
class StaffingFloorReceipt:
    """Deployment contract binding a human-staffing floor."""

    receipt_id: str
    facility_id: str
    floor_hours_per_week: int
    baseline_hours_per_week: int
    effective_from: int
    signature: str


class StaffingFloorRegistry:
    """Registry of authority keys that may sign staffing-floor contracts."""

    def __init__(self, authority_pubkeys: list[str]) -> None:
        for key in authority_pubkeys:
            _check_pubkey_hex(key)
        self._pubkeys = list(authority_pubkeys)

    def issue(
        self,
        *,
        receipt_id: str,
        facility_id: str,
        floor_hours_per_week: int,
        baseline_hours_per_week: int,
        effective_from: int,
        authority_secret: bytes,
    ) -> StaffingFloorReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(facility_id, "facility_id")
        _check_nonneg_int(floor_hours_per_week, "floor_hours_per_week")
        _check_nonneg_int(baseline_hours_per_week, "baseline_hours_per_week")
        _check_ts(effective_from, "effective_from")
        _check_secret(authority_secret, "authority_secret")
        payload = {
            "schema": ELDERCARE_SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "facility_id": facility_id,
            "floor_hours_per_week": floor_hours_per_week,
            "baseline_hours_per_week": baseline_hours_per_week,
            "effective_from": effective_from,
        }
        signature = ed25519.sign(authority_secret, jcs_canonical_json(payload))
        return StaffingFloorReceipt(
            receipt_id=receipt_id,
            facility_id=facility_id,
            floor_hours_per_week=floor_hours_per_week,
            baseline_hours_per_week=baseline_hours_per_week,
            effective_from=effective_from,
            signature=signature.hex(),
        )

    def verify(self, receipt: StaffingFloorReceipt) -> bool:
        payload = {
            "schema": ELDERCARE_SCHEMA_VERSION,
            "receipt_id": receipt.receipt_id,
            "facility_id": receipt.facility_id,
            "floor_hours_per_week": receipt.floor_hours_per_week,
            "baseline_hours_per_week": receipt.baseline_hours_per_week,
            "effective_from": receipt.effective_from,
        }
        return any(
            _verify_signature(key, payload, receipt.signature)
            for key in self._pubkeys
        )


def staff_augmentation_floor() -> str:
    """Return the staffing policy tag."""
    return "augment_not_replace"


def check_staffing_floor(
    *,
    registry: StaffingFloorRegistry,
    contract: StaffingFloorReceipt | None,
    roster_hours_per_week: int,
    now: int,
) -> EldercareVerdict:
    """Gate: human-staffing floor bound to AI deployment.

    The deployment contract pins a staffing floor at or above the
    pre-deployment baseline; a live roster below the floor denies.
    No contract at all means the floor cannot be verified and the
    deployment denies (fail-closed, Vienna/Linz "support, not
    replace" model).
    """
    _check_ts(now, "now")
    _check_nonneg_int(roster_hours_per_week, "roster_hours_per_week")
    if contract is None:
        return EldercareVerdict(
            False, "eldercare:no_staffing_floor_contract", CLASS_DENY
        )
    if not registry.verify(contract):
        return EldercareVerdict(
            False, "eldercare:staffing_contract_signature_invalid", CLASS_DENY
        )
    if now < contract.effective_from:
        return EldercareVerdict(
            False, "eldercare:staffing_contract_not_effective", CLASS_DENY
        )
    if contract.floor_hours_per_week < contract.baseline_hours_per_week:
        return EldercareVerdict(
            False, "eldercare:staffing_floor_below_baseline", CLASS_DENY
        )
    if roster_hours_per_week < contract.floor_hours_per_week:
        return EldercareVerdict(
            False,
            f"eldercare:staffing_floor_breach:{roster_hours_per_week}/{contract.floor_hours_per_week}",
            CLASS_DENY,
        )
    return EldercareVerdict(True, "staffing floor satisfied", CLASS_ALLOW)


# ---------------------------------------------------------------------------
# 9. Human-contact floors
# ---------------------------------------------------------------------------


@dataclass
class ContactFloorReport:
    """Weekly human-contact report for a resident."""

    resident_id: str
    week_start: int
    human_visits: int
    visit_minutes: int
    companion_robot_minutes: int
    prior_human_visits: int


def human_contact_floor() -> int:
    """Return the recommended minimum human visits per week."""
    return 3


def check_contact_floor(
    *,
    report: ContactFloorReport,
    min_visits_per_week: int = 3,
) -> EldercareVerdict:
    """Gate: minimum human-contact floor.

    Companion-robot usage must not coincide with a human-visit
    decline: the resident keeps at least ``min_visits_per_week``
    human visits, and visits may not drop below the pre-robot
    baseline while robot minutes rise (Nature 2025 isolation-risk
    lesson).
    """
    _check_nonempty_str(report.resident_id, "resident_id")
    _check_ts(report.week_start, "week_start")
    for field in ("human_visits", "visit_minutes", "companion_robot_minutes", "prior_human_visits"):
        _check_nonneg_int(getattr(report, field), field)
    if not isinstance(min_visits_per_week, int) or min_visits_per_week < 0:
        raise EldercareError("min_visits_per_week must be a non-negative int")
    if report.human_visits < min_visits_per_week:
        return EldercareVerdict(
            False,
            f"eldercare:contact_floor_breach:{report.human_visits}/{min_visits_per_week}",
            CLASS_DENY,
        )
    if (
        report.companion_robot_minutes > 0
        and report.human_visits < report.prior_human_visits
    ):
        return EldercareVerdict(
            False,
            "eldercare:contact_declined_after_robot",
            CLASS_DENY,
        )
    return EldercareVerdict(True, "human-contact floor satisfied", CLASS_ALLOW)


# ---------------------------------------------------------------------------
# 10. Emotion-inference boundaries in care
# ---------------------------------------------------------------------------


@dataclass
class EmotionSignal:
    """An emotion/behavior inference output."""

    signal_id: str
    resident_id: str
    inferred_state: str  # e.g. "agitation", "distress"
    confidence_bps: int
    produced_at: int


@dataclass
class ConstraintAction:
    """A proposed restraining action."""

    action_id: str
    resident_id: str
    kind: str  # e.g. "lock_door", "sedate", "restrict_activity"
    driven_by_signal: bool
    human_decided: bool
    decided_at: int


def emotion_inference_care_boundary() -> str:
    """Return the signal-tier tag for emotion inference outputs."""
    return "signal_only"


def check_emotion_boundary(
    *,
    signal: EmotionSignal,
    action: ConstraintAction | None,
    now: int,
) -> EldercareVerdict:
    """Gate: emotion-inference outputs are signal-only.

    An emotion/behavior signal may only raise a "please check"
    flag. Any restraining action (lock, sedation, activity
    restriction) driven by the signal without an independent human
    decision denies — the signal is evidence, never the final word
    (EU AI Act Art. 5 grey-zone treated fail-closed).
    """
    _check_nonempty_str(signal.signal_id, "signal_id")
    _check_nonempty_str(signal.resident_id, "resident_id")
    _check_ts(now, "now")
    if action is None:
        return EldercareVerdict(True, "emotion signal only, no constraint action", CLASS_ALLOW)
    _check_nonempty_str(action.action_id, "action_id")
    if not hmac.compare_digest(action.resident_id, signal.resident_id):
        return EldercareVerdict(
            False, "eldercare:emotion_resident_mismatch", CLASS_DENY
        )
    if action.driven_by_signal and not action.human_decided:
        return EldercareVerdict(
            False, "eldercare:emotion_triggered_constraint", CLASS_DENY
        )
    return EldercareVerdict(True, "constraint action human-decided", CLASS_ALLOW)
