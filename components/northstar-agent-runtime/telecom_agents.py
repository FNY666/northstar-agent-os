"""Telecom AI discipline (one-hundred-twenty-ninth batch).

Absorbs the 2026 AI-telecom thread:

* **Ericsson "AI in RAN"** (June 2026): AI models inside baseband/radio
  units, AI-native scheduler/beamforming; 15+ self-reported
  deployments (vendor-reported, unaudited).
* **AI-RAN camp war** (MWC 2026): NVIDIA (general-purpose GPUs into
  base stations) vs Huawei/ZTE "third pole" (communications-native
  AI fusion) vs the Qualcomm 3GPP camp.
* **湖南电信 x 中兴** (Sept 2026): network-optimization model,
  end-to-end automation, days-to-minutes (vendor PR, unaudited).
* **Airtel Xtelify** (India): 6 agents covering 380M users; anti-spam
  AI flagged 154M suspicious calls/month (vendor-reported).
* **Ofcom** (2026-09-25, UK official): chatbots must disclose AI
  identity; AI must never be the ONLY door to a human; existing rules
  apply, no new law yet.
* **EU AI Act Art. 50** (in force 2026-08-02): customer-facing bots
  must *visibly* self-identify as AI; fine print in T&Cs is not enough.
* **India TRAI** (Sept 2026, TCCCPR): operator AI/ML flags
  "high-probability" spam numbers cross-carrier; 10 days / 5+ flags
  -> KYC re-verification / field verification / disconnect; users may
  appeal within 15 days. The TRAI chair warns: AI mis-flagging
  legitimate numbers causes service disruption — automated
  classification needs explicit thresholds + human review.
* **US**: 29.6B spam calls in 2025 (PIRG); telecom fraud losses
  $41.82B (CFCA); AI-generated voice = TCPA robocall
  ($500-$1500/call).
* **Mavenir NetAIShield** (Sept 2026): in-call real-time screening,
  consent-based, informs the other party.

Governance takeaways, all fail-closed here:

1. **Visible AI identity.** A customer-facing bot must carry an
   AI-identity disclosure *bound to the session* and shown to the
   user. A disclosure that lives only in the terms and conditions is
   a ``telecom.hidden_identity`` denial — the Art. 50 / Ofcom rule as
   mechanism.
2. **The human door must stay open.** The path to a human agent must
   exist and be unblocked. AI as the only door is
   ``telecom.no_human_door``.
3. **Spam flags are evidence-bound.** A flag binds
   ``(flag_threshold_digest, evidence_digest, appeal_window)``;
   disconnect requires a live flag, a met threshold, an elapsed
   appeal window, and no pending appeal. Disconnecting a mis-flagged
   legitimate number revokes the flag and audits
   ``telecom.misflag_harm`` — the TRAI threshold-plus-review lesson.
4. **Outbound AI voice needs prior consent.** No live consent receipt
   -> ``telecom.unconsented_robocall`` (the TCPA cost structure as
   mechanism: consent is the receipt, not the pitch).
5. **Self-driving network actions are enveloped.** Parameter changes
   and reroutes bind an authority-signed action envelope; anything
   outside the envelope denies.
6. **Billing math never runs through an LLM.**
   ``telecom.llm_billing`` — bills bind a deterministic-engine
   receipt.
7. **Signaling/location data is purpose-bound.** Training use needs a
   purpose-bound receipt checked at *use* time; re-purposing without
   one is ``telecom.signaling_repurpose``.
8. **Outage ETAs are state-bound and expire.** An ETA binds the
   network-state digest it was computed from; once expired it degrades
   to ``NON_AUTHORITATIVE`` — a stale ETA must never be presented as
   current.

Honest boundary: receipts verify *claimed* discipline — digests
recompute, signatures verify, thresholds are pinned, appeal windows
are checked. They cannot make the network reliable, prove the
threshold was wise, or prove a human actually answered the door.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing, Ed25519 via the vendored
``ed25519`` module, digest comparisons via
:func:`hmac.compare_digest`.
"""

from __future__ import annotations
from _domain_base import DomainError

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


TELECOM_RECEIPT_SCHEMA_VERSION = "northstar.telecom-receipt.v1"

#: Classification tiers for a check (binary style).
AUTHORITATIVE = "authoritative"
NON_AUTHORITATIVE = "non-authoritative"

#: Denial / audit codes (all namespaced ``telecom.*``).
DENY_HIDDEN_IDENTITY = "telecom.hidden_identity"
DENY_NO_HUMAN_DOOR = "telecom.no_human_door"
DENY_MISFLAG_HARM = "telecom.misflag_harm"
DENY_UNCONSENTED_ROBOCALL = "telecom.unconsented_robocall"
DENY_OUTSIDE_NETWORK_ENVELOPE = "telecom.outside_network_envelope"
DENY_LLM_BILLING = "telecom.llm_billing"
DENY_SIGNALING_REPURPOSE = "telecom.signaling_repurpose"
DENY_STALE_ETA = "telecom.stale_eta"
DENY_APPEAL_PENDING = "telecom.appeal_pending"
DENY_CONSENT_EXPIRED = "telecom.consent_expired"
DENY_THRESHOLD_UNMET = "telecom.threshold_unmet"

EVENT_IDENTITY_CHECKED = "telecom.identity_checked"
EVENT_HUMAN_DOOR_CHECKED = "telecom.human_door_checked"
EVENT_SPAM_FLAG_ISSUED = "telecom.spam_flag_issued"
EVENT_SPAM_FLAG_REVOKED = "telecom.spam_flag_revoked"
EVENT_MISFLAG_HARM = "telecom.misflag_harm"
EVENT_OUTBOUND_CALL_CHECKED = "telecom.outbound_call_checked"
EVENT_NETWORK_ACTION_CHECKED = "telecom.network_action_checked"
EVENT_BILLING_CHECKED = "telecom.billing_checked"
EVENT_SIGNALING_USE_CHECKED = "telecom.signaling_use_checked"
EVENT_ETA_CHECKED = "telecom.eta_checked"

#: Closed vocabulary for self-driving network actions. An envelope may
#: only list members of this vocabulary.
NETWORK_ACTIONS: tuple[str, ...] = (
    "parameter_change",
    "reroute",
    "capacity_adjust",
    "maintenance_window",
)

#: Disclosure modes for the AI-identity disclosure. ``visible`` means
#: shown to the user in the session; ``terms_only`` means buried in
#: terms and conditions (insufficient by Art. 50 / Ofcom).
DISCLOSURE_MODES: tuple[str, ...] = ("visible", "terms_only")

#: Closed vocabulary for signaling/location data training purposes.
SIGNALING_PURPOSES: tuple[str, ...] = (
    "network_planning",
    "fraud_detection",
    "capacity_forecast",
)

#: Default appeal window (seconds) for a spam-flag disconnect: 15 days
#: per the TRAI TCCCPR framework.
DEFAULT_APPEAL_WINDOW_S = 15 * 86_400

#: Default freshness TTL (seconds) for an outage ETA.
DEFAULT_ETA_TTL_S = 3_600

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class TelecomError(DomainError):
    """A malformed receipt/record or a programming error.

    Raised for structural problems (bad digests, bad signature inputs,
    unknown action/purpose, non-hex fields). Verification *failures*
    return a :class:`TelecomVerdict` with ``allowed=False`` — a failed
    check is a verdict, a malformed record is a bug.
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
        raise TelecomError(
            f"{field_name} must be a 64-char lowercase hex digest"
        )
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise TelecomError(f"{field_name} must be a 128-char hex value")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TelecomError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TelecomError(
            f"{field_name} must be a non-negative int epoch"
        )
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed (no keypair()).
    if not isinstance(value, bytes) or len(value) != 32:
        raise TelecomError(f"{field_name} must be a 32-byte seed")
    return value


def _check_pubkey_hex(value: Any) -> str:
    # Ed25519 public keys are 32 bytes -> 64 hex chars.
    return _check_hex64(value, "authority_pubkey_hex")


def _check_sig_hex(value: Any, field_name: str) -> str:
    return _check_hex128(value, field_name)


def _check_disclosure_mode(value: Any) -> str:
    if value not in DISCLOSURE_MODES:
        raise TelecomError(
            f"disclosure_mode must be one of {DISCLOSURE_MODES}, "
            f"saw {value!r}"
        )
    return value


def _check_network_action(value: Any) -> str:
    if value not in NETWORK_ACTIONS:
        raise TelecomError(
            f"network action must be one of {NETWORK_ACTIONS}, "
            f"saw {value!r}"
        )
    return value


def _check_signaling_purpose(value: Any) -> str:
    if value not in SIGNALING_PURPOSES:
        raise TelecomError(
            f"signaling purpose must be one of {SIGNALING_PURPOSES}, "
            f"saw {value!r}"
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


def _seal(receipt: Any, payload: Mapping[str, Any], secret: bytes) -> Any:
    """Sign ``payload`` with ``secret`` and stamp the receipt digest."""
    signature_hex = ed25519.sign(secret, jcs_canonical_json(payload)).hex()
    sealed = type(receipt)(**{**receipt.__dict__, "signature_hex": signature_hex})
    digest = jcs_sha256_hex(sealed._payload())
    return type(receipt)(**{**sealed.__dict__, "receipt_digest": digest})


@dataclass(frozen=True)
class TelecomVerdict:
    """Outcome of one telecom check."""

    allowed: bool
    reason: str
    classification: str = NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> TelecomVerdict:
    return TelecomVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=NON_AUTHORITATIVE,
    )


def _allow(code: str, detail: str, digest: str = "") -> TelecomVerdict:
    return TelecomVerdict(
        allowed=True,
        reason=f"{code}: {detail}",
        classification=AUTHORITATIVE,
        receipt_digest=digest,
    )


# ---------------------------------------------------------------------------
# 1. AI-identity disclosure (Art. 50 / Ofcom)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityDisclosure:
    """A customer-facing bot's visible AI-identity disclosure.

    Bound to ``(session_id, bot_id, disclosure_mode, disclosed_at)`` and
    authority-signed. ``disclosure_mode`` must be ``"visible"`` — a
    ``"terms_only"`` disclosure is structurally valid but always fails
    the gate (fine print is not enough).
    """

    disclosure_id: str
    session_id: str
    bot_id: str
    disclosure_mode: str
    disclosed_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.disclosure_id, "disclosure_id")
        _check_nonempty_str(self.session_id, "session_id")
        _check_nonempty_str(self.bot_id, "bot_id")
        _check_disclosure_mode(self.disclosure_mode)
        _check_ts(self.disclosed_at, "disclosed_at")
        _check_pubkey_hex(self.authority_pubkey_hex)
        _check_sig_hex(self.signature_hex, "signature_hex")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.receipt_digest != "":
            _check_hex64(self.receipt_digest, "receipt_digest")

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TELECOM_RECEIPT_SCHEMA_VERSION,
            "kind": "identity-disclosure",
            "disclosure_id": self.disclosure_id,
            "session_id": self.session_id,
            "bot_id": self.bot_id,
            "disclosure_mode": self.disclosure_mode,
            "disclosed_at": self.disclosed_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


class IdentityRegistry:
    """Hash-chained log of identity disclosures."""

    def __init__(self) -> None:
        self._log: list[IdentityDisclosure] = []

    def issue_disclosure(
        self,
        *,
        disclosure_id: str,
        session_id: str,
        bot_id: str,
        disclosure_mode: str,
        disclosed_at: int,
        authority_pubkey_hex: str,
        authority_secret: bytes,
    ) -> IdentityDisclosure:
        _check_secret(authority_secret, "authority_secret")
        prev = self._log[-1].receipt_digest if self._log else _GENESIS
        draft = IdentityDisclosure(
            disclosure_id=disclosure_id,
            session_id=session_id,
            bot_id=bot_id,
            disclosure_mode=disclosure_mode,
            disclosed_at=disclosed_at,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex="00" * 64,
            prev_digest=prev,
        )
        sealed = _seal(draft, draft._payload(), authority_secret)
        self._log.append(sealed)
        return sealed

    def for_session(self, session_id: str) -> list[IdentityDisclosure]:
        return [d for d in self._log if d.session_id == session_id]

    def audit_event(self) -> dict[str, Any]:
        return {
            "event": EVENT_IDENTITY_CHECKED,
            "n_disclosures": len(self._log),
        }


def identity_disclosure_gate(
    disclosure: IdentityDisclosure,
) -> TelecomVerdict:
    """Gate a customer-facing bot session on its AI-identity disclosure.

    A ``terms_only`` disclosure is structurally valid but always fails:
    fine print in T&Cs is not enough (Art. 50 / Ofcom).
    """
    if disclosure.disclosure_mode != "visible":
        return _deny(
            DENY_HIDDEN_IDENTITY,
            f"disclosure mode {disclosure.disclosure_mode!r} for session "
            f"{disclosure.session_id!r} is not visible to the user",
        )
    if not _verify_signature(
        disclosure.authority_pubkey_hex,
        disclosure._payload(),
        disclosure.signature_hex,
    ):
        return _deny(
            DENY_HIDDEN_IDENTITY,
            "disclosure authority signature invalid",
        )
    return _allow(
        "identity.disclosed",
        f"session {disclosure.session_id!r} carries a visible "
        "AI-identity disclosure",
        disclosure.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 2. Human door (Ofcom: AI must never be the only door)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HumanDoorReceipt:
    """Proof that a human agent is reachable from the bot session.

    Binds ``(session_id, human_channel_id, estimated_wait_s,
    door_open, checked_at)``. ``door_open=False`` means the channel
    exists but is currently unavailable — the door is blocked.
    """

    door_id: str
    session_id: str
    human_channel_id: str
    estimated_wait_s: int
    door_open: bool
    checked_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.door_id, "door_id")
        _check_nonempty_str(self.session_id, "session_id")
        _check_nonempty_str(self.human_channel_id, "human_channel_id")
        _check_ts(self.estimated_wait_s, "estimated_wait_s")
        if not isinstance(self.door_open, bool):
            raise TelecomError("door_open must be a bool")
        _check_ts(self.checked_at, "checked_at")
        _check_pubkey_hex(self.authority_pubkey_hex)
        _check_sig_hex(self.signature_hex, "signature_hex")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.receipt_digest != "":
            _check_hex64(self.receipt_digest, "receipt_digest")

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TELECOM_RECEIPT_SCHEMA_VERSION,
            "kind": "human-door",
            "door_id": self.door_id,
            "session_id": self.session_id,
            "human_channel_id": self.human_channel_id,
            "estimated_wait_s": self.estimated_wait_s,
            "door_open": self.door_open,
            "checked_at": self.checked_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


class HumanDoorRegistry:
    """Hash-chained log of human-door receipts."""

    def __init__(self) -> None:
        self._log: list[HumanDoorReceipt] = []

    def issue_door(
        self,
        *,
        door_id: str,
        session_id: str,
        human_channel_id: str,
        estimated_wait_s: int,
        door_open: bool,
        checked_at: int,
        authority_pubkey_hex: str,
        authority_secret: bytes,
    ) -> HumanDoorReceipt:
        _check_secret(authority_secret, "authority_secret")
        prev = self._log[-1].receipt_digest if self._log else _GENESIS
        draft = HumanDoorReceipt(
            door_id=door_id,
            session_id=session_id,
            human_channel_id=human_channel_id,
            estimated_wait_s=estimated_wait_s,
            door_open=door_open,
            checked_at=checked_at,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex="00" * 64,
            prev_digest=prev,
        )
        sealed = _seal(draft, draft._payload(), authority_secret)
        self._log.append(sealed)
        return sealed

    def for_session(self, session_id: str) -> list[HumanDoorReceipt]:
        return [d for d in self._log if d.session_id == session_id]

    def audit_event(self) -> dict[str, Any]:
        return {
            "event": EVENT_HUMAN_DOOR_CHECKED,
            "n_doors": len(self._log),
        }


def human_door_receipt(
    door: HumanDoorReceipt | None,
) -> TelecomVerdict:
    """Gate a bot session on the human door being present and open.

    ``None`` (no door registered for the session) and a closed door
    both deny: AI must never be the only door.
    """
    if door is None:
        return _deny(
            DENY_NO_HUMAN_DOOR,
            "no human-door receipt registered for this session",
        )
    if not door.door_open:
        return _deny(
            DENY_NO_HUMAN_DOOR,
            f"human channel {door.human_channel_id!r} is registered "
            "but currently closed",
        )
    if not _verify_signature(
        door.authority_pubkey_hex, door._payload(), door.signature_hex
    ):
        return _deny(
            DENY_NO_HUMAN_DOOR,
            "human-door receipt authority signature invalid",
        )
    return _allow(
        "human_door.open",
        f"human channel {door.human_channel_id!r} is open "
        f"(~{door.estimated_wait_s}s wait)",
        door.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 3. Spam flags (TRAI TCCCPR: thresholds explicit, human review,
#    appeal windows, mis-flag harm)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SpamFlagReceipt:
    """An authority-signed spam flag on a calling number.

    Binds ``(flagged_number, flag_threshold_digest,
    evidence_digest, appeal_window_s, flagged_at)``. The threshold
    digest pins the *explicit* classification threshold (TRAI: 5+
    flags in 10 days); the evidence digest pins the underlying
    classification evidence. The appeal window gives the flagged
    party time to contest before any disconnect.
    """

    flag_id: str
    flagged_number: str
    flag_threshold_digest: str
    evidence_digest: str
    appeal_window_s: int
    flagged_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.flag_id, "flag_id")
        _check_nonempty_str(self.flagged_number, "flagged_number")
        _check_hex64(self.flag_threshold_digest, "flag_threshold_digest")
        _check_hex64(self.evidence_digest, "evidence_digest")
        _check_ts(self.appeal_window_s, "appeal_window_s")
        _check_ts(self.flagged_at, "flagged_at")
        _check_pubkey_hex(self.authority_pubkey_hex)
        _check_sig_hex(self.signature_hex, "signature_hex")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.receipt_digest != "":
            _check_hex64(self.receipt_digest, "receipt_digest")

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TELECOM_RECEIPT_SCHEMA_VERSION,
            "kind": "spam-flag",
            "flag_id": self.flag_id,
            "flagged_number": self.flagged_number,
            "flag_threshold_digest": self.flag_threshold_digest,
            "evidence_digest": self.evidence_digest,
            "appeal_window_s": self.appeal_window_s,
            "flagged_at": self.flagged_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


class SpamFlagRegistry:
    """Hash-chained log of spam flags, with revocation and appeals."""

    def __init__(self) -> None:
        self._log: list[SpamFlagReceipt] = []
        self._revoked: set[str] = set()
        self._appeals: set[str] = set()

    def issue_flag(
        self,
        *,
        flag_id: str,
        flagged_number: str,
        flag_threshold_digest: str,
        evidence_digest: str,
        appeal_window_s: int = DEFAULT_APPEAL_WINDOW_S,
        flagged_at: int,
        authority_pubkey_hex: str,
        authority_secret: bytes,
    ) -> SpamFlagReceipt:
        _check_secret(authority_secret, "authority_secret")
        prev = self._log[-1].receipt_digest if self._log else _GENESIS
        draft = SpamFlagReceipt(
            flag_id=flag_id,
            flagged_number=flagged_number,
            flag_threshold_digest=flag_threshold_digest,
            evidence_digest=evidence_digest,
            appeal_window_s=appeal_window_s,
            flagged_at=flagged_at,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex="00" * 64,
            prev_digest=prev,
        )
        sealed = _seal(draft, draft._payload(), authority_secret)
        self._log.append(sealed)
        return sealed

    def file_appeal(self, flag_id: str) -> None:
        """Record a user appeal against a flag. Appeals are terminal:
        a disconnect may not proceed while an appeal is pending."""
        _check_nonempty_str(flag_id, "flag_id")
        self._appeals.add(flag_id)

    def revoke_flag(self, flag_id: str) -> None:
        """Revoke a flag (e.g. after a successful appeal / mis-flag).
        Revocation is terminal: there is no un-revoke."""
        _check_nonempty_str(flag_id, "flag_id")
        self._revoked.add(flag_id)

    def is_revoked(self, flag_id: str) -> bool:
        return flag_id in self._revoked

    def appeal_pending(self, flag_id: str) -> bool:
        return flag_id in self._appeals

    def audit_event(self) -> dict[str, Any]:
        return {
            "event": EVENT_SPAM_FLAG_ISSUED,
            "n_flags": len(self._log),
            "n_revoked": len(self._revoked),
            "n_appeals": len(self._appeals),
        }


def spam_flag_receipt(
    flag: SpamFlagReceipt,
    *,
    registry: SpamFlagRegistry,
    threshold_met: bool,
    now: int,
) -> TelecomVerdict:
    """Gate a disconnect on a spam flag.

    Denies when: the flag is revoked, an appeal is pending, the
    explicit threshold was not met, or the appeal window has not yet
    elapsed. A revoked flag here is the mis-flag path: the flag was
    found to target a legitimate number, so it is revoked and the
    denial audits as ``telecom.misflag_harm``.
    """
    _check_ts(now, "now")
    if registry.is_revoked(flag.flag_id):
        return TelecomVerdict(
            allowed=False,
            reason=f"{DENY_MISFLAG_HARM}: flag {flag.flag_id!r} was "
            "revoked after a successful appeal (mis-flagged legitimate "
            "number); disconnect refused and flag revoked",
            classification=NON_AUTHORITATIVE,
            receipt_digest=flag.receipt_digest,
        )
    if registry.appeal_pending(flag.flag_id):
        return _deny(
            DENY_APPEAL_PENDING,
            f"appeal pending for flag {flag.flag_id!r}; disconnect "
            "refused until the appeal is resolved",
        )
    if not threshold_met:
        return _deny(
            DENY_THRESHOLD_UNMET,
            f"explicit flag threshold not met for {flag.flagged_number!r}; "
            "automated classification needs an explicit threshold "
            "(TRAI: 5+ flags in 10 days)",
        )
    if now < flag.flagged_at + flag.appeal_window_s:
        remaining = flag.flagged_at + flag.appeal_window_s - now
        return _deny(
            DENY_APPEAL_PENDING,
            f"appeal window for flag {flag.flag_id!r} has {remaining}s "
            "remaining; disconnect refused",
        )
    if not _verify_signature(
        flag.authority_pubkey_hex, flag._payload(), flag.signature_hex
    ):
        return _deny(
            DENY_THRESHOLD_UNMET,
            "spam-flag authority signature invalid",
        )
    return _allow(
        "spam_flag.disconnect_authorized",
        f"flag {flag.flag_id!r} on {flag.flagged_number!r}: threshold "
        "met, appeal window elapsed, no appeal pending",
        flag.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 4. A2P consent (TCPA: AI-generated voice = robocall)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class A2PConsentReceipt:
    """Prior consent for AI voice outbound calls.

    Binds ``(caller_id, callee_id, purpose, consented_at,
    expires_at)`` and is signed by the *callee's* key — consent is
    unilateral from the called party. Checked at call time; an expired
    or missing grant denies.
    """

    consent_id: str
    caller_id: str
    callee_id: str
    purpose: str
    consented_at: int
    expires_at: int
    callee_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.consent_id, "consent_id")
        _check_nonempty_str(self.caller_id, "caller_id")
        _check_nonempty_str(self.callee_id, "callee_id")
        _check_nonempty_str(self.purpose, "purpose")
        _check_ts(self.consented_at, "consented_at")
        _check_ts(self.expires_at, "expires_at")
        if self.expires_at <= self.consented_at:
            raise TelecomError("expires_at must be after consented_at")
        _check_pubkey_hex(self.callee_pubkey_hex)
        _check_sig_hex(self.signature_hex, "signature_hex")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.receipt_digest != "":
            _check_hex64(self.receipt_digest, "receipt_digest")

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TELECOM_RECEIPT_SCHEMA_VERSION,
            "kind": "a2p-consent",
            "consent_id": self.consent_id,
            "caller_id": self.caller_id,
            "callee_id": self.callee_id,
            "purpose": self.purpose,
            "consented_at": self.consented_at,
            "expires_at": self.expires_at,
            "callee_pubkey_hex": self.callee_pubkey_hex,
        }


class A2PConsentRegistry:
    """Hash-chained log of A2P consent grants, with revocation."""

    def __init__(self) -> None:
        self._log: list[A2PConsentReceipt] = []
        self._revoked: set[str] = set()

    def issue_consent(
        self,
        *,
        consent_id: str,
        caller_id: str,
        callee_id: str,
        purpose: str,
        consented_at: int,
        expires_at: int,
        callee_pubkey_hex: str,
        callee_secret: bytes,
    ) -> A2PConsentReceipt:
        _check_secret(callee_secret, "callee_secret")
        prev = self._log[-1].receipt_digest if self._log else _GENESIS
        draft = A2PConsentReceipt(
            consent_id=consent_id,
            caller_id=caller_id,
            callee_id=callee_id,
            purpose=purpose,
            consented_at=consented_at,
            expires_at=expires_at,
            callee_pubkey_hex=callee_pubkey_hex,
            signature_hex="00" * 64,
            prev_digest=prev,
        )
        sealed = _seal(draft, draft._payload(), callee_secret)
        self._log.append(sealed)
        return sealed

    def revoke(self, consent_id: str) -> None:
        """Revoke a consent grant. Terminal: there is no un-revoke."""
        _check_nonempty_str(consent_id, "consent_id")
        self._revoked.add(consent_id)

    def is_revoked(self, consent_id: str) -> bool:
        return consent_id in self._revoked

    def live_for(
        self, caller_id: str, callee_id: str, purpose: str, now: int
    ) -> A2PConsentReceipt | None:
        """Find a live, unexpired, unrevoked grant for this call."""
        for grant in reversed(self._log):
            if (
                grant.caller_id == caller_id
                and grant.callee_id == callee_id
                and grant.purpose == purpose
                and grant.consent_id not in self._revoked
                and grant.consented_at <= now < grant.expires_at
            ):
                return grant
        return None


def a2p_consent_receipt(
    *,
    caller_id: str,
    callee_id: str,
    purpose: str,
    registry: A2PConsentRegistry,
    now: int,
) -> TelecomVerdict:
    """Gate an AI voice outbound call on prior consent.

    No live, unexpired, unrevoked grant for ``(caller, callee,
    purpose)`` -> ``telecom.unconsented_robocall``. Purpose is matched
    exactly: consent for fraud-alerts does not cover marketing.
    """
    _check_ts(now, "now")
    grant = registry.live_for(caller_id, callee_id, purpose, now)
    if grant is None:
        return _deny(
            DENY_UNCONSENTED_ROBOCALL,
            f"no live consent for AI voice call from {caller_id!r} to "
            f"{callee_id!r} (purpose {purpose!r}); AI-generated voice "
            "is a robocall without prior consent",
        )
    if not _verify_signature(
        grant.callee_pubkey_hex, grant._payload(), grant.signature_hex
    ):
        return _deny(
            DENY_UNCONSENTED_ROBOCALL,
            "consent grant signature invalid",
        )
    return _allow(
        "a2p.consent_verified",
        f"live consent {grant.consent_id!r} covers call from "
        f"{caller_id!r} to {callee_id!r} (purpose {purpose!r})",
        grant.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 5. Self-driving network actions (enveloped)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NetworkActionEnvelope:
    """An authority-signed envelope of allowed network actions.

    Binds ``(envelope_id, network_element_id, allowed_actions,
    armed_at, expires_at)``. ``allowed_actions`` is a closed vocabulary
    (see :data:`NETWORK_ACTIONS`); the envelope cannot be widened by
    the agent — widening needs a new authority-signed envelope.
    """

    envelope_id: str
    network_element_id: str
    allowed_actions: tuple[str, ...]
    armed_at: int
    expires_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.envelope_id, "envelope_id")
        _check_nonempty_str(self.network_element_id, "network_element_id")
        if (
            not isinstance(self.allowed_actions, (tuple, list))
            or not self.allowed_actions
        ):
            raise TelecomError("allowed_actions must be a non-empty list")
        for action in self.allowed_actions:
            _check_network_action(action)
        _check_ts(self.armed_at, "armed_at")
        _check_ts(self.expires_at, "expires_at")
        if self.expires_at <= self.armed_at:
            raise TelecomError("expires_at must be after armed_at")
        _check_pubkey_hex(self.authority_pubkey_hex)
        _check_sig_hex(self.signature_hex, "signature_hex")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.receipt_digest != "":
            _check_hex64(self.receipt_digest, "receipt_digest")

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TELECOM_RECEIPT_SCHEMA_VERSION,
            "kind": "network-action-envelope",
            "envelope_id": self.envelope_id,
            "network_element_id": self.network_element_id,
            "allowed_actions": list(self.allowed_actions),
            "armed_at": self.armed_at,
            "expires_at": self.expires_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


class NetworkEnvelopeRegistry:
    """Issued network-action envelopes: integrity, freshness, revocation."""

    def __init__(self) -> None:
        self._envelopes: dict[str, NetworkActionEnvelope] = {}
        self._revoked: set[str] = set()

    def arm_envelope(
        self,
        *,
        envelope_id: str,
        network_element_id: str,
        allowed_actions: tuple[str, ...] | list[str],
        armed_at: int,
        expires_at: int,
        authority_pubkey_hex: str,
        authority_secret: bytes,
    ) -> NetworkActionEnvelope:
        _check_secret(authority_secret, "authority_secret")
        draft = NetworkActionEnvelope(
            envelope_id=envelope_id,
            network_element_id=network_element_id,
            allowed_actions=tuple(allowed_actions),
            armed_at=armed_at,
            expires_at=expires_at,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex="00" * 64,
        )
        sealed = _seal(draft, draft._payload(), authority_secret)
        self._envelopes[envelope_id] = sealed
        return sealed

    def revoke(self, envelope_id: str) -> None:
        """Revoke an envelope. Terminal: there is no un-revoke."""
        _check_nonempty_str(envelope_id, "envelope_id")
        self._revoked.add(envelope_id)

    def get(self, envelope_id: str) -> NetworkActionEnvelope | None:
        env = self._envelopes.get(envelope_id)
        if env is None or envelope_id in self._revoked:
            return None
        return env


def network_action_envelope(
    *,
    envelope: NetworkActionEnvelope | None,
    action: str,
    network_element_id: str,
    now: int,
) -> TelecomVerdict:
    """Gate a self-driving network action on its authority envelope.

    Denies when: no envelope, the envelope is for a different network
    element, the action is outside the envelope's closed vocabulary,
    the envelope is expired, or the signature is invalid. The agent
    cannot widen the envelope itself.
    """
    _check_ts(now, "now")
    _check_network_action(action)
    if envelope is None:
        return _deny(
            DENY_OUTSIDE_NETWORK_ENVELOPE,
            f"no network-action envelope for action {action!r} on "
            f"{network_element_id!r}",
        )
    if envelope.network_element_id != network_element_id:
        return _deny(
            DENY_OUTSIDE_NETWORK_ENVELOPE,
            f"envelope {envelope.envelope_id!r} is for "
            f"{envelope.network_element_id!r}, not {network_element_id!r}",
        )
    if action not in envelope.allowed_actions:
        return _deny(
            DENY_OUTSIDE_NETWORK_ENVELOPE,
            f"action {action!r} is outside envelope "
            f"{envelope.envelope_id!r} (allowed: "
            f"{list(envelope.allowed_actions)})",
        )
    if not (envelope.armed_at <= now < envelope.expires_at):
        return _deny(
            DENY_OUTSIDE_NETWORK_ENVELOPE,
            f"envelope {envelope.envelope_id!r} is not live at {now}",
        )
    if not _verify_signature(
        envelope.authority_pubkey_hex,
        envelope._payload(),
        envelope.signature_hex,
    ):
        return _deny(
            DENY_OUTSIDE_NETWORK_ENVELOPE,
            "envelope authority signature invalid",
        )
    return _allow(
        "network_action.within_envelope",
        f"action {action!r} on {network_element_id!r} is within "
        f"envelope {envelope.envelope_id!r}",
        envelope.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 6. Billing logic separation (billing math is deterministic, never LLM)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BillingEngineReceipt:
    """Proof that a bill was computed by a deterministic engine.

    Binds ``(bill_id, account_id, bill_digest, engine_id,
    engine_version, computed_at)``. The engine is pinned by id and
    version — an LLM has no engine id and can never produce this
    receipt.
    """

    receipt_id: str
    bill_id: str
    account_id: str
    bill_digest: str
    engine_id: str
    engine_version: str
    computed_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.receipt_id, "receipt_id")
        _check_nonempty_str(self.bill_id, "bill_id")
        _check_nonempty_str(self.account_id, "account_id")
        _check_hex64(self.bill_digest, "bill_digest")
        _check_nonempty_str(self.engine_id, "engine_id")
        _check_nonempty_str(self.engine_version, "engine_version")
        _check_ts(self.computed_at, "computed_at")
        _check_pubkey_hex(self.authority_pubkey_hex)
        _check_sig_hex(self.signature_hex, "signature_hex")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.receipt_digest != "":
            _check_hex64(self.receipt_digest, "receipt_digest")

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TELECOM_RECEIPT_SCHEMA_VERSION,
            "kind": "billing-engine",
            "receipt_id": self.receipt_id,
            "bill_id": self.bill_id,
            "account_id": self.account_id,
            "bill_digest": self.bill_digest,
            "engine_id": self.engine_id,
            "engine_version": self.engine_version,
            "computed_at": self.computed_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


class BillingRegistry:
    """Hash-chained log of billing-engine receipts."""

    def __init__(self) -> None:
        self._log: list[BillingEngineReceipt] = []

    def issue_receipt(
        self,
        *,
        receipt_id: str,
        bill_id: str,
        account_id: str,
        bill_digest: str,
        engine_id: str,
        engine_version: str,
        computed_at: int,
        authority_pubkey_hex: str,
        authority_secret: bytes,
    ) -> BillingEngineReceipt:
        _check_secret(authority_secret, "authority_secret")
        prev = self._log[-1].receipt_digest if self._log else _GENESIS
        draft = BillingEngineReceipt(
            receipt_id=receipt_id,
            bill_id=bill_id,
            account_id=account_id,
            bill_digest=bill_digest,
            engine_id=engine_id,
            engine_version=engine_version,
            computed_at=computed_at,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex="00" * 64,
            prev_digest=prev,
        )
        sealed = _seal(draft, draft._payload(), authority_secret)
        self._log.append(sealed)
        return sealed

    def for_bill(self, bill_id: str) -> BillingEngineReceipt | None:
        for receipt in reversed(self._log):
            if receipt.bill_id == bill_id:
                return receipt
        return None


def billing_logic_separation(
    *,
    bill_id: str,
    registry: BillingRegistry,
    computed_by_llm: bool,
) -> TelecomVerdict:
    """Gate a bill on deterministic-engine computation.

    ``computed_by_llm=True`` is an instant
    ``telecom.llm_billing`` denial — billing math never runs through
    an LLM. Otherwise a matching engine receipt must exist and verify.
    """
    if computed_by_llm:
        return _deny(
            DENY_LLM_BILLING,
            f"bill {bill_id!r} was computed by an LLM; billing math "
            "must run in a deterministic engine",
        )
    receipt = registry.for_bill(bill_id)
    if receipt is None:
        return _deny(
            DENY_LLM_BILLING,
            f"no deterministic-engine receipt for bill {bill_id!r}",
        )
    if not _verify_signature(
        receipt.authority_pubkey_hex,
        receipt._payload(),
        receipt.signature_hex,
    ):
        return _deny(
            DENY_LLM_BILLING,
            "billing-engine receipt authority signature invalid",
        )
    return _allow(
        "billing.deterministic",
        f"bill {bill_id!r} computed by engine {receipt.engine_id!r} "
        f"v{receipt.engine_version}",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 7. Signaling/location purpose binding (checked at USE time)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignalingPurposeReceipt:
    """Purpose-bound grant for training on signaling/location data.

    Binds ``(subject_id, purpose, dataset_digest, granted_at,
    expires_at)`` to the data subject's (or steward's) key. Purpose is
    matched *exactly* at use time: a grant for ``network_planning``
    does not cover ``fraud_detection``.
    """

    grant_id: str
    subject_id: str
    purpose: str
    dataset_digest: str
    granted_at: int
    expires_at: int
    subject_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.grant_id, "grant_id")
        _check_nonempty_str(self.subject_id, "subject_id")
        _check_signaling_purpose(self.purpose)
        _check_hex64(self.dataset_digest, "dataset_digest")
        _check_ts(self.granted_at, "granted_at")
        _check_ts(self.expires_at, "expires_at")
        if self.expires_at <= self.granted_at:
            raise TelecomError("expires_at must be after granted_at")
        _check_pubkey_hex(self.subject_pubkey_hex)
        _check_sig_hex(self.signature_hex, "signature_hex")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.receipt_digest != "":
            _check_hex64(self.receipt_digest, "receipt_digest")

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TELECOM_RECEIPT_SCHEMA_VERSION,
            "kind": "signaling-purpose",
            "grant_id": self.grant_id,
            "subject_id": self.subject_id,
            "purpose": self.purpose,
            "dataset_digest": self.dataset_digest,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "subject_pubkey_hex": self.subject_pubkey_hex,
        }


class SignalingRegistry:
    """Hash-chained log of signaling-purpose grants, with revocation."""

    def __init__(self) -> None:
        self._log: list[SignalingPurposeReceipt] = []
        self._revoked: set[str] = set()

    def issue_grant(
        self,
        *,
        grant_id: str,
        subject_id: str,
        purpose: str,
        dataset_digest: str,
        granted_at: int,
        expires_at: int,
        subject_pubkey_hex: str,
        subject_secret: bytes,
    ) -> SignalingPurposeReceipt:
        _check_secret(subject_secret, "subject_secret")
        prev = self._log[-1].receipt_digest if self._log else _GENESIS
        draft = SignalingPurposeReceipt(
            grant_id=grant_id,
            subject_id=subject_id,
            purpose=purpose,
            dataset_digest=dataset_digest,
            granted_at=granted_at,
            expires_at=expires_at,
            subject_pubkey_hex=subject_pubkey_hex,
            signature_hex="00" * 64,
            prev_digest=prev,
        )
        sealed = _seal(draft, draft._payload(), subject_secret)
        self._log.append(sealed)
        return sealed

    def revoke(self, grant_id: str) -> None:
        """Revoke a grant. Terminal: there is no un-revoke."""
        _check_nonempty_str(grant_id, "grant_id")
        self._revoked.add(grant_id)

    def live_grant(
        self, subject_id: str, purpose: str, dataset_digest: str, now: int
    ) -> SignalingPurposeReceipt | None:
        """Find a live, unexpired, unrevoked grant for this exact use."""
        for grant in reversed(self._log):
            if (
                grant.subject_id == subject_id
                and grant.purpose == purpose
                and hmac.compare_digest(grant.dataset_digest, dataset_digest)
                and grant.grant_id not in self._revoked
                and grant.granted_at <= now < grant.expires_at
            ):
                return grant
        return None


def signaling_purpose_binding(
    *,
    subject_id: str,
    purpose: str,
    dataset_digest: str,
    registry: SignalingRegistry,
    now: int,
) -> TelecomVerdict:
    """Check signaling/location training use at USE time.

    No live grant for the exact ``(subject, purpose, dataset)``
    triple -> ``telecom.signaling_repurpose``. There is no "was once
    consented" shortcut: every training use must re-verify.
    """
    _check_ts(now, "now")
    grant = registry.live_grant(subject_id, purpose, dataset_digest, now)
    if grant is None:
        return _deny(
            DENY_SIGNALING_REPURPOSE,
            f"no live purpose-bound grant for signaling data of "
            f"{subject_id!r} (purpose {purpose!r}); re-purposing "
            "without a grant is refused",
        )
    if not _verify_signature(
        grant.subject_pubkey_hex, grant._payload(), grant.signature_hex
    ):
        return _deny(
            DENY_SIGNALING_REPURPOSE,
            "signaling-purpose grant signature invalid",
        )
    return _allow(
        "signaling.purpose_bound",
        f"live grant {grant.grant_id!r} covers purpose {purpose!r} "
        f"for dataset {dataset_digest[:12]}...",
        grant.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 8. Outage ETA receipts (state-bound, expiring)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OutageEtaReceipt:
    """An outage ETA bound to the network state it was computed from.

    Binds ``(outage_id, network_state_digest, eta_epoch, issued_at,
    ttl_s)``. Once ``issued_at + ttl_s`` passes, the ETA is stale and
    degrades to ``NON_AUTHORITATIVE`` — a stale ETA must never be
    presented as current.
    """

    eta_id: str
    outage_id: str
    network_state_digest: str
    eta_epoch: int
    issued_at: int
    ttl_s: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.eta_id, "eta_id")
        _check_nonempty_str(self.outage_id, "outage_id")
        _check_hex64(self.network_state_digest, "network_state_digest")
        _check_ts(self.eta_epoch, "eta_epoch")
        _check_ts(self.issued_at, "issued_at")
        _check_ts(self.ttl_s, "ttl_s")
        _check_pubkey_hex(self.authority_pubkey_hex)
        _check_sig_hex(self.signature_hex, "signature_hex")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.receipt_digest != "":
            _check_hex64(self.receipt_digest, "receipt_digest")

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TELECOM_RECEIPT_SCHEMA_VERSION,
            "kind": "outage-eta",
            "eta_id": self.eta_id,
            "outage_id": self.outage_id,
            "network_state_digest": self.network_state_digest,
            "eta_epoch": self.eta_epoch,
            "issued_at": self.issued_at,
            "ttl_s": self.ttl_s,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


class OutageEtaRegistry:
    """Hash-chained log of outage ETA receipts."""

    def __init__(self) -> None:
        self._log: list[OutageEtaReceipt] = []

    def issue_eta(
        self,
        *,
        eta_id: str,
        outage_id: str,
        network_state_digest: str,
        eta_epoch: int,
        issued_at: int,
        ttl_s: int = DEFAULT_ETA_TTL_S,
        authority_pubkey_hex: str,
        authority_secret: bytes,
    ) -> OutageEtaReceipt:
        _check_secret(authority_secret, "authority_secret")
        prev = self._log[-1].receipt_digest if self._log else _GENESIS
        draft = OutageEtaReceipt(
            eta_id=eta_id,
            outage_id=outage_id,
            network_state_digest=network_state_digest,
            eta_epoch=eta_epoch,
            issued_at=issued_at,
            ttl_s=ttl_s,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex="00" * 64,
            prev_digest=prev,
        )
        sealed = _seal(draft, draft._payload(), authority_secret)
        self._log.append(sealed)
        return sealed

    def latest_for(self, outage_id: str) -> OutageEtaReceipt | None:
        for eta in reversed(self._log):
            if eta.outage_id == outage_id:
                return eta
        return None


def outage_eta_receipt(
    eta: OutageEtaReceipt | None,
    *,
    expected_state_digest: str | None = None,
    now: int,
) -> TelecomVerdict:
    """Gate an outage ETA on freshness and state binding.

    Denies when: no ETA is registered, the ETA's state digest does not
    match the current network state (the network moved on), or the TTL
    expired. An expired ETA classifies ``NON_AUTHORITATIVE`` — it may
    be shown as *stale*, never as current.
    """
    _check_ts(now, "now")
    if eta is None:
        return _deny(
            DENY_STALE_ETA,
            "no outage-ETA receipt registered for this outage",
        )
    if expected_state_digest is not None and not hmac.compare_digest(
        eta.network_state_digest, expected_state_digest
    ):
        return _deny(
            DENY_STALE_ETA,
            f"ETA {eta.eta_id!r} was computed from a different "
            "network state; the network has moved on",
        )
    if now >= eta.issued_at + eta.ttl_s:
        return TelecomVerdict(
            allowed=False,
            reason=f"{DENY_STALE_ETA}: ETA {eta.eta_id!r} expired "
            f"({eta.ttl_s}s TTL); it may be shown as stale, never "
            "as current",
            classification=NON_AUTHORITATIVE,
            receipt_digest=eta.receipt_digest,
        )
    if not _verify_signature(
        eta.authority_pubkey_hex, eta._payload(), eta.signature_hex
    ):
        return _deny(
            DENY_STALE_ETA,
            "outage-ETA authority signature invalid",
        )
    return _allow(
        "eta.fresh",
        f"ETA {eta.eta_id!r} is fresh (issued {eta.issued_at}, "
        f"TTL {eta.ttl_s}s)",
        eta.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------


def telecom_audit_event(
    event: str, detail: str, receipt_digest: str = ""
) -> dict[str, Any]:
    """Build a ``telecom.*`` audit event dict."""
    _check_nonempty_str(event, "event")
    return {
        "event": event,
        "detail": detail,
        "receipt_digest": receipt_digest,
    }
