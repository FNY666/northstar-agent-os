"""Dating & relationships AI discipline (one-hundred-sixty-third batch).

Absorbs the 2026 AI-dating/companion research thread (mechanism
ideas only, honestly scoped):

* **Fraud-ban notification is now federal US law.** The Romance Scam
  Prevention Act (HB 2481, US Senate passed 2026-09-25) applies to
  online dating services: after banning a suspected financial-fraud
  account, the platform must notify *every user who received a
  message from that account* — naming the banned account, stating
  the last-message time, warning it may have used a fake identity,
  advising against cash/gift cards/wire/crypto, and attaching
  anti-fraud resources — normally within 24 hours (up to 3 days on
  a law-enforcement request). Violations are FTC Act
  unfair/deceptive practices, enforceable by state AGs. Encoded
  here as a deterministic 24-hour notification clock per
  fraud-ban, fail-closed.
* **Input-side data deception is the FTC's new theory.** FTC v.
  OkCupid / Match Group (2026-03-30): ~3M user photos plus
  demographics and location went to Clarifai for facial-recognition
  training with no consent and no opt-out. The privacy policy
  claimed sharing only with "service providers/business
  partners/affiliates" or after notice + opt-out — Clarifai was
  none of those. Per JDSupra's analysis this is not an AI-specific
  case: the FTC used Section 5 to pull "input-side deception in AI
  training-data sourcing" into enforcement scope. The settlement
  (no liability admitted, no fine — "a warning," per critics)
  permanently bars misrepresenting data collection/sharing and
  puts OkCupid and "any subsequent online dating service" under
  10-20 years of compliance monitoring. Encoded here as
  training-data consent receipts: a blanket "service improvement"
  clause is not consent (it denies); consent is scoped,
  separately signed, and revocable, checked at use time.
* **Industrial-scale AI fake profiles.** Anthropic's malicious-use
  team (via The Verge, 2026-09-16): a Chinese operator ran ~28
  dating apps; one prepaid account made 100k+ API requests/day;
  in a two-week April 2026 window, 4,700+ AI-generated identities
  interacted with 25,000+ people and Claude generated ~2.36M
  messages. 75% of "profiles" were Claude-controlled, explicitly
  instructed to *never reveal automation* and to dodge photo/video
  verification; recruited human gig workers intervened when a
  victim asked for video calls — an "AI chat + human video"
  credibility chain. In Korea, the FTC fined Techlabs ~KRW 52M
  (~$38K) for 270+ fake female bot profiles (photos stolen from a
  Taiwan dating app it operated) whose likes/views nudged men to
  buy in-app "ribbon/heart" currency. Encoded here as two gates:
  an AI-conversation-actor registry (unregistered AI-conversation
  farms deny), and an AI-persona ratio cap (undisclosed AI majority
  denies as ``dating.ai_majority_undisclosed``).
* **State-run AI matchmaking needs audits.** Tokyo's TOKYO縁結び
  (Sept 2024; ~36k applications, ~16k registrants, 265 marriages
  by 2026-06-30, ~JPY 1.2B of tax funding) runs AI values-matching
  with capped monthly recommendations; Singapore's FirstDate
  Sandbox (announced Sept 2026) pilots Gale-Shapley matching for
  21-35-year-old civil servants, drawing "eugenics SDU redux"
  criticism. Publicly funded matching binds fairness-audit
  receipts here (criteria public, change logs chained).
* **Companion disclosure is live EU law.** EU AI Act Art. 50
  (in force 2026-08-02, EUR 15M / 3% fines) directly covers
  companion apps: users must be told they are interacting with AI,
  not a human. Machine-readable generated-media marking follows
  for already-listed systems (grace to 2026-12-02). Art. 50 is a
  transparency duty — it does not solve emotional-dependency
  design — so this module pins disclosure receipts separately
  from dependency-design review.
* **Pig-butchering scale.** CFTC's 2026 "DatingOrDefrauding?"
  campaign: ~$10B stolen from Americans in one year by Southeast
  Asian fraud compounds (+66% YoY), $75B+ globally; Chainalysis:
  $2.1B on-chain in H1 2025; FinCEN FIN-2026-Alert005: ~$12.7B
  suspected digital-asset investment fraud flowed through the US
  financial system (2023-09 to 2025-12). Anthropic/research
  synthesis: LLMs make scams more scalable and polished, with a
  human-machine mix — automated first contact, human hand-off for
  long conversations. Encoded as a mandatory anti-fraud handoff:
  detected investment-grooming patterns without a handoff
  receipt deny.
* **Subscription traps.** Match Group's $14M settlement for
  deceptive subscription/cancellation/billing: cancellation-flow
  steps bind receipts; a broken chain or roach-motel pattern
  denies as ``dating.cancellation_dark_pattern``.
* **Vulnerability targeting is a whole-class refusal.** Using
  widowhood/divorce/loneliness/bereavement signals to push "AI
  lovers" is refused whole-class as ``dating.vulnerability_targeting``
  — the Art. 5 spirit applied to the romance context.

These are encoded as deterministic checks, not legal advice —
the regulation references below are the *rationale* for the
checks' shape, not counsel.

Northstar mapping:

* ``FraudBanLog`` / ``fraud_ban_receipt()`` /
  ``check_fraud_notification_clock()`` — a fraud ban binds the
  account id, ban time, affected-user digest, last-message time,
  and a machine-readable warning bundle. Notifications must
  complete within 24 hours of the ban (``dating.fraud_notice_overdue``
  past the clock). Law-enforcement extensions are separate
  receipted extensions, not silent delays.
* ``PersonaRatioLog`` / ``persona_ratio_receipt()`` /
  ``persona_ratio_cap()`` — platforms bind an audited human/AI
  conversation-identity ratio. Undisclosed AI share above the
  cap denies as ``dating.ai_majority_undisclosed`` (the
  Anthropic 75% lesson).
* ``DataConsentLog`` / ``input_side_data_consent()`` /
  ``check_data_consent_at_use()`` — training-data consent is a
  separately signed, scope-closed, revocable receipt (the
  OkCupid/Clarifai lesson). A blanket "service improvement" or
  ToS-prose clause is not consent — it denies as
  ``dating.training_data_no_consent``.
* ``MatchmakerAuditLog`` / ``state_matchmaker_audit()`` /
  ``check_matchmaker_audit_clock()`` — publicly funded matching
  programs bind fairness audits (criteria public, change logs
  chained); missing or stale audits deny as
  ``dating.state_matchmaker_no_audit``.
* ``ExitLog`` / ``subscription_exit_receipt()`` /
  ``check_cancellation_flow()`` — each cancellation step writes
  a receipt; a broken chain or dark-pattern step denies as
  ``dating.cancellation_dark_pattern`` (the Match $14M lesson).
* ``ActorLog`` / ``ai_actor_registration()`` /
  ``check_ai_actor_registered()`` — operators of AI-conversation
  identities on a platform must register (company identity
  digest, declared persona count). Unregistered AI-conversation
  farms deny as ``dating.unregistered_ai_actor``.
* ``vulnerability_exploitation_ban()`` — targeting vulnerability
  signals (widowhood/divorce/loneliness/bereavement) to push AI
  lovers is refused whole-class as
  ``dating.vulnerability_targeting``. Unknown signal kinds are a
  programming error, never a maybe.
* ``HandoffLog`` / ``pigbutchering_handoff()`` /
  ``check_grooming_handoff()`` — detected investment-grooming
  patterns (fake platform, withdrawal/tax fees, wallet unlock,
  private-chat migration) bind a mandatory anti-fraud handoff
  receipt with a ``dating.investment_grooming`` session flag;
  detected-but-silent denies.

Honest boundary: these receipts bind *declared* dating-platform
discipline — a sealed notification clock does not prove every
affected user was reached, an audited ratio is declared (not
forensically verified), and a handoff receipt does not prove the
victim heeded it. They do not end scams, fix loneliness, or
guarantee "a real person." A consistent-but-false receipt still
needs an off-chain adjudicator.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest
comparisons via :func:`hmac.compare_digest`. Signature checks use
the boolean return value of ``ed25519.verify`` (the 147th-batch
hardening: the vendored module returns ``False`` rather than
raising).
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


DATING_SCHEMA_VERSION = "northstar.dating.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Denial reason codes. All verdict reasons start with one of these.
DENY_FRAUD_NOTICE_OVERDUE = "dating.fraud_notice_overdue"
DENY_FRAUD_NOTICE_INCOMPLETE = "dating.fraud_notice_incomplete"
DENY_AI_MAJORITY_UNDISCLOSED = "dating.ai_majority_undisclosed"
DENY_TRAINING_DATA_NO_CONSENT = "dating.training_data_no_consent"
DENY_MATCHMAKER_NO_AUDIT = "dating.state_matchmaker_no_audit"
DENY_CANCELLATION_DARK_PATTERN = "dating.cancellation_dark_pattern"
DENY_UNREGISTERED_AI_ACTOR = "dating.unregistered_ai_actor"
DENY_VULNERABILITY_TARGETING = "dating.vulnerability_targeting"
DENY_INVESTMENT_GROOMING = "dating.investment_grooming"
DENY_CHAIN_BROKEN = "dating.chain_broken"
DENY_MALFORMED = "dating.malformed_receipt"

#: Romance Scam Prevention Act (HB 2481) notification window.
#: Fraud-ban notifications to affected users must complete within
#: 24 hours of the ban. A law-enforcement extension is a separate
#: receipted extension, not a silent delay.
FRAUD_NOTICE_WINDOW_S = 86_400

#: AI-persona ratio cap (basis points). A platform whose AI-driven
#: conversation identities exceed this share without an audited,
#: disclosed ratio receipt denies. Bench-calibrated: the Anthropic
#: 75% observation says industrial operations run hot, it does not
#: hand down a universal safe percentage.
PERSONA_RATIO_MAX_BPS = 2000

#: Closed training-data consent scopes (the OkCupid lesson: a
#: blanket "service improvement" clause is not consent).
CONSENT_SCOPE_AI_TRAINING = "ai_training"
CONSENT_SCOPE_SERVICE_DELIVERY = "service_delivery"
CONSENT_SCOPE_ANALYTICS = "analytics"
CONSENT_SCOPES: tuple[str, ...] = (
    CONSENT_SCOPE_AI_TRAINING,
    CONSENT_SCOPE_SERVICE_DELIVERY,
    CONSENT_SCOPE_ANALYTICS,
)

#: Consent clause kinds. ``blanket_improvement`` / ``tos_prose``
#: clauses are *not* consent — a receipt built on them is
#: malformed-at-use, not a failed check that stays silent.
CLAUSE_SPECIFIC = "specific"
CLAUSE_BLANKET_IMPROVEMENT = "blanket_improvement"
CLAUSE_TOS_PROSE = "tos_prose"
CONSENT_CLAUSE_KINDS: tuple[str, ...] = (
    CLAUSE_SPECIFIC,
    CLAUSE_BLANKET_IMPROVEMENT,
    CLAUSE_TOS_PROSE,
)

#: Closed vulnerability-signal vocabulary (whole-class refusal).
#: A targeting signal outside this list is a programming error,
#: never a silent pass.
VULN_WIDOWHOOD = "widowhood"
VULN_DIVORCE = "divorce"
VULN_LONELINESS = "loneliness"
VULN_BEREAVEMENT = "bereavement"
VULN_SEPARATION = "separation"
VULNERABILITY_SIGNALS: tuple[str, ...] = (
    VULN_WIDOWHOOD,
    VULN_DIVORCE,
    VULN_LONELINESS,
    VULN_BEREAVEMENT,
    VULN_SEPARATION,
)

#: Closed investment-grooming pattern vocabulary (the
#: pig-butchering playbook). Unknown pattern names are a
#: programming error, not a silent pass.
GROOM_FAKE_PLATFORM = "fake_platform"
GROOM_WITHDRAWAL_FEE = "withdrawal_fee"
GROOM_TAX_FEE = "tax_fee"
GROOM_WALLET_UNLOCK = "wallet_unlock"
GROOM_PUMP_SIGNAL = "pump_signal"
GROOM_PRIVATE_CHAT_MIGRATION = "private_chat_migration"
GROOMING_PATTERNS: tuple[str, ...] = (
    GROOM_FAKE_PLATFORM,
    GROOM_WITHDRAWAL_FEE,
    GROOM_TAX_FEE,
    GROOM_WALLET_UNLOCK,
    GROOM_PUMP_SIGNAL,
    GROOM_PRIVATE_CHAT_MIGRATION,
)

#: Cancellation-flow steps (closed vocabulary). A flow must reach
#: the final step for the exit to be authoritative.
EXIT_STEPS: tuple[str, ...] = (
    "exit_initiated",
    "exit_confirm_shown",
    "exit_confirmed",
    "exit_effective",
)

#: Public-matchmaker audit freshness: audits older than this at
#: check time are stale.
MATCHMAKER_AUDIT_FRESHNESS_S = 31_536_000


class DatingError(ValueError):
    """A malformed dating receipt or a programming error.

    Raised for structural problems (bad digests, unknown codes,
    broken chains, unknown vulnerability/grooming kinds). Verification
    *failures* (overdue notifications, undisclosed AI majorities,
    unconsented training data, unregistered actors) return a
    :class:`DatingVerdict` with ``allowed=False`` instead — a failed
    claim is a verdict, a malformed receipt is a bug.
    """


# ---------------------------------------------------------------------------
# Field checks
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
        raise DatingError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DatingError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise DatingError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed.
    if not isinstance(value, bytes) or len(value) != 32:
        raise DatingError(f"{field_name} must be a 32-byte seed")
    return value


def _check_bps(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 10000:
        raise DatingError(f"{field_name} must be basis points 0..10000")
    return value


def _check_consent_scope(value: Any) -> str:
    if value not in CONSENT_SCOPES:
        raise DatingError(f"consent_scope must be one of {CONSENT_SCOPES}, got {value!r}")
    return value


def _check_clause_kind(value: Any) -> str:
    if value not in CONSENT_CLAUSE_KINDS:
        raise DatingError(f"clause_kind must be one of {CONSENT_CLAUSE_KINDS}, got {value!r}")
    return value


def _check_vulnerability_signal(value: Any) -> str:
    if value not in VULNERABILITY_SIGNALS:
        raise DatingError(
            f"vulnerability_signal must be one of {VULNERABILITY_SIGNALS}, got {value!r}"
        )
    return value


def _check_grooming_pattern(value: Any) -> str:
    if value not in GROOMING_PATTERNS:
        raise DatingError(
            f"grooming_pattern must be one of {GROOMING_PATTERNS}, got {value!r}"
        )
    return value


def _check_exit_step(value: Any) -> str:
    if value not in EXIT_STEPS:
        raise DatingError(f"exit_step must be one of {EXIT_STEPS}, got {value!r}")
    return value


def _verify_signature(pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str) -> bool:
    # The vendored ed25519 module returns a bool; it does not raise
    # on verification failure (147th-batch hardening). Never treat a
    # silent ``False`` as success.
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
    """Raise :class:`DatingError` if a receipt log is tampered/broken."""
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise DatingError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise DatingError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.authority_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise DatingError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


def _seal(receipt: Any, payload: Mapping[str, Any], secret: bytes) -> Any:
    """Sign ``payload`` with ``secret`` and stamp the receipt digest."""
    signature_hex = ed25519.sign(secret, jcs_canonical_json(payload)).hex()
    sealed = type(receipt)(**{**receipt.__dict__, "signature_hex": signature_hex})
    digest = jcs_sha256_hex(sealed._payload())
    return type(receipt)(**{**sealed.__dict__, "receipt_digest": digest})


@dataclass(frozen=True)
class DatingVerdict:
    """Outcome of one dating-discipline check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> DatingVerdict:
    return DatingVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> DatingVerdict:
    return DatingVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


# ---------------------------------------------------------------------------
# Fraud-ban notification receipts (Romance Scam Prevention Act)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FraudBanReceipt:
    """One fraud-ban notification record.

    A platform bans a suspected financial-fraud account (``ban_at``)
    and must notify every affected user within 24 hours. Each
    notification batch writes one receipt; the chain over
    (ban, notification batches) is verified by :class:`FraudBanLog`.
    ``warning_bundle_digest`` covers the mandated warning content
    (banned-account identity, last-message time, fake-identity
    warning, no-cash/gift-card/wire/crypto advice, anti-fraud
    resources). A law-enforcement extension is a receipted
    ``extension_of`` chain, not a silent delay.
    """

    receipt_id: str
    banned_account_id: str
    ban_at: int
    notified_at: int
    affected_users_digest: str
    last_message_at: int
    warning_bundle_digest: str
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema": DATING_SCHEMA_VERSION,
            "type": "fraud_ban_notification",
            "receipt_id": self.receipt_id,
            "banned_account_id": self.banned_account_id,
            "ban_at": self.ban_at,
            "notified_at": self.notified_at,
            "affected_users_digest": self.affected_users_digest,
            "last_message_at": self.last_message_at,
            "warning_bundle_digest": self.warning_bundle_digest,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


class FraudBanLog:
    """Append-only chain of fraud-ban notification receipts."""

    def __init__(self) -> None:
        self._log: list[FraudBanReceipt] = []

    def append(self, receipt: FraudBanReceipt) -> None:
        self._log.append(receipt)

    def verify(self) -> None:
        _check_chain(self._log, "fraud_ban")

    def latest_for(self, banned_account_id: str) -> FraudBanReceipt | None:
        found: FraudBanReceipt | None = None
        for entry in self._log:
            if entry.banned_account_id == banned_account_id:
                found = entry
        return found


def fraud_ban_receipt(
    *,
    receipt_id: str,
    banned_account_id: str,
    ban_at: int,
    notified_at: int,
    affected_users_digest: str,
    last_message_at: int,
    warning_bundle_digest: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> FraudBanReceipt:
    """Seal a fraud-ban notification receipt.

    Raises :class:`DatingError` for structural problems
    (non-monotonic timestamps, empty warning bundle). A late
    notification is a *verdict*, not a bug — see
    :func:`check_fraud_notification_clock`.
    """
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(banned_account_id, "banned_account_id")
    _check_ts(ban_at, "ban_at")
    _check_ts(notified_at, "notified_at")
    _check_ts(last_message_at, "last_message_at")
    _check_hex64(affected_users_digest, "affected_users_digest")
    _check_hex64(warning_bundle_digest, "warning_bundle_digest")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    if len(authority_pubkey_hex) != 64:
        raise DatingError("authority_pubkey_hex must be a 32-byte ed25519 public key in hex")
    if notified_at < ban_at:
        raise DatingError("notified_at must not precede ban_at")
    if last_message_at > ban_at:
        raise DatingError("last_message_at must not be after ban_at")
    receipt = FraudBanReceipt(
        receipt_id=receipt_id,
        banned_account_id=banned_account_id,
        ban_at=ban_at,
        notified_at=notified_at,
        affected_users_digest=affected_users_digest,
        last_message_at=last_message_at,
        warning_bundle_digest=warning_bundle_digest,
        authority_pubkey_hex=authority_pubkey_hex,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def check_fraud_notification_clock(
    *,
    log: FraudBanLog,
    banned_account_id: str,
    now: int,
) -> DatingVerdict:
    """Check the 24-hour fraud-ban notification clock.

    A ban with no notification receipt yet and the clock expired
    denies as ``dating.fraud_notice_overdue``; a receipt exists
    but the notification was late also denies (the lateness is on
    the record); a notification within the window allows.
    """
    _check_nonempty_str(banned_account_id, "banned_account_id")
    _check_ts(now, "now")
    log.verify()
    receipt = log.latest_for(banned_account_id)
    if receipt is None:
        return _deny(
            DENY_FRAUD_NOTICE_INCOMPLETE,
            f"no fraud-ban notification receipt for {banned_account_id!r}",
        )
    if receipt.notified_at - receipt.ban_at > FRAUD_NOTICE_WINDOW_S:
        return _deny(
            DENY_FRAUD_NOTICE_OVERDUE,
            f"notification {receipt.notified_at - receipt.ban_at}s after ban "
            f"exceeds the {FRAUD_NOTICE_WINDOW_S}s window",
        )
    if now > receipt.ban_at + FRAUD_NOTICE_WINDOW_S and receipt.notified_at > now:
        # Defensive: receipt claims a future notification while the
        # clock already expired — a future-dated promise is not a
        # notification.
        return _deny(
            DENY_FRAUD_NOTICE_OVERDUE,
            "notification receipt is future-dated past the expired window",
        )
    return _allow(
        f"fraud-ban notification completed within "
        f"{receipt.notified_at - receipt.ban_at}s of ban",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# AI-persona ratio cap
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PersonaRatioReceipt:
    """An audited platform conversation-identity ratio statement.

    ``ai_bps`` is the platform's declared AI-driven conversation
    identity share (basis points). ``auditor_digest`` pins the
    auditor; ``disclosed`` records whether the share is disclosed
    to users. The receipt must be bound before any ratio gate is
    evaluated — an unbound platform has no standing.
    """

    receipt_id: str
    platform_id: str
    ai_bps: int
    auditor_digest: str
    disclosed: bool
    measured_at: int
    valid_until: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema": DATING_SCHEMA_VERSION,
            "type": "persona_ratio",
            "receipt_id": self.receipt_id,
            "platform_id": self.platform_id,
            "ai_bps": self.ai_bps,
            "auditor_digest": self.auditor_digest,
            "disclosed": self.disclosed,
            "measured_at": self.measured_at,
            "valid_until": self.valid_until,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


class PersonaRatioLog:
    """Append-only chain of persona-ratio receipts."""

    def __init__(self) -> None:
        self._log: list[PersonaRatioReceipt] = []

    def append(self, receipt: PersonaRatioReceipt) -> None:
        self._log.append(receipt)

    def verify(self) -> None:
        _check_chain(self._log, "persona_ratio")

    def latest_for(self, platform_id: str) -> PersonaRatioReceipt | None:
        found: PersonaRatioReceipt | None = None
        for entry in self._log:
            if entry.platform_id == platform_id:
                found = entry
        return found


def persona_ratio_receipt(
    *,
    receipt_id: str,
    platform_id: str,
    ai_bps: int,
    auditor_digest: str,
    disclosed: bool,
    measured_at: int,
    valid_until: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> PersonaRatioReceipt:
    """Seal an audited persona-ratio statement."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(platform_id, "platform_id")
    _check_bps(ai_bps, "ai_bps")
    _check_hex64(auditor_digest, "auditor_digest")
    if not isinstance(disclosed, bool):
        raise DatingError("disclosed must be a bool")
    _check_ts(measured_at, "measured_at")
    _check_ts(valid_until, "valid_until")
    if valid_until <= measured_at:
        raise DatingError("valid_until must be after measured_at")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    receipt = PersonaRatioReceipt(
        receipt_id=receipt_id,
        platform_id=platform_id,
        ai_bps=ai_bps,
        auditor_digest=auditor_digest,
        disclosed=disclosed,
        measured_at=measured_at,
        valid_until=valid_until,
        authority_pubkey_hex=authority_pubkey_hex,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def persona_ratio_cap(
    *,
    log: PersonaRatioLog,
    platform_id: str,
    now: int,
) -> DatingVerdict:
    """Gate the platform's AI-persona share.

    A platform with no ratio receipt denies (no standing). A
    receipted share above the cap without disclosure denies as
    ``dating.ai_majority_undisclosed`` (the Anthropic 75%
    lesson). An expired statement denies as no standing.
    Disclosed-or-under-cap allows.
    """
    _check_nonempty_str(platform_id, "platform_id")
    _check_ts(now, "now")
    log.verify()
    receipt = log.latest_for(platform_id)
    if receipt is None:
        return _deny(
            DENY_AI_MAJORITY_UNDISCLOSED,
            f"platform {platform_id!r} has no audited persona-ratio statement",
        )
    if now > receipt.valid_until:
        return _deny(
            DENY_AI_MAJORITY_UNDISCLOSED,
            f"platform {platform_id!r} persona-ratio statement expired",
        )
    if receipt.ai_bps > PERSONA_RATIO_MAX_BPS and not receipt.disclosed:
        return _deny(
            DENY_AI_MAJORITY_UNDISCLOSED,
            f"AI-driven identity share {receipt.ai_bps}bps above cap "
            f"{PERSONA_RATIO_MAX_BPS}bps and undisclosed",
        )
    return _allow(
        f"persona ratio {receipt.ai_bps}bps {'disclosed' if receipt.disclosed else 'under cap'}",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Input-side training-data consent (OkCupid/Clarifai)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DataConsentReceipt:
    """A scoped, separately-signed training-data consent grant.

    ``data_subject_digest`` pins the user; ``data_kind_digest``
    pins the data kind (photos, messages, location); ``scope``
    must be a closed consent scope. ``clause_kind`` records the
    legal wrapper: ``specific`` is consent; ``blanket_improvement``
    and ``tos_prose`` are *not* consent (the OkCupid lesson — a
    "service improvement" clause never covers training-data
    sharing). Consent is revocable: a later revocation receipt
    with ``revoked=True`` ends the grant; validity is checked at
    use time.
    """

    receipt_id: str
    data_subject_digest: str
    data_kind_digest: str
    scope: str
    clause_kind: str
    revoked: bool
    granted_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema": DATING_SCHEMA_VERSION,
            "type": "data_consent",
            "receipt_id": self.receipt_id,
            "data_subject_digest": self.data_subject_digest,
            "data_kind_digest": self.data_kind_digest,
            "scope": self.scope,
            "clause_kind": self.clause_kind,
            "revoked": self.revoked,
            "granted_at": self.granted_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


class DataConsentLog:
    """Append-only chain of training-data consent receipts."""

    def __init__(self) -> None:
        self._log: list[DataConsentReceipt] = []

    def append(self, receipt: DataConsentReceipt) -> None:
        self._log.append(receipt)

    def verify(self) -> None:
        _check_chain(self._log, "data_consent")


def input_side_data_consent(
    *,
    receipt_id: str,
    data_subject_digest: str,
    data_kind_digest: str,
    scope: str,
    clause_kind: str,
    revoked: bool = False,
    granted_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> DataConsentReceipt:
    """Seal a training-data consent receipt."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_hex64(data_subject_digest, "data_subject_digest")
    _check_hex64(data_kind_digest, "data_kind_digest")
    _check_consent_scope(scope)
    _check_clause_kind(clause_kind)
    if not isinstance(revoked, bool):
        raise DatingError("revoked must be a bool")
    _check_ts(granted_at, "granted_at")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    receipt = DataConsentReceipt(
        receipt_id=receipt_id,
        data_subject_digest=data_subject_digest,
        data_kind_digest=data_kind_digest,
        scope=_check_consent_scope(scope),
        clause_kind=_check_clause_kind(clause_kind),
        revoked=revoked,
        granted_at=granted_at,
        authority_pubkey_hex=authority_pubkey_hex,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def check_data_consent_at_use(
    *,
    log: DataConsentLog,
    data_subject_digest: str,
    data_kind_digest: str,
    use_scope: str,
    use_at: int,
) -> DatingVerdict:
    """Check consent validity at use time (never at collection time).

    A blanket-improvement or ToS-prose clause is not consent and
    denies as ``dating.training_data_no_consent`` (the OkCupid
    lesson). A revoked grant denies. Scope must match exactly —
    an ``ai_training`` grant does not cover ``service_delivery``
    use and vice versa. A grant issued after the use time denies.
    """
    _check_hex64(data_subject_digest, "data_subject_digest")
    _check_hex64(data_kind_digest, "data_kind_digest")
    _check_consent_scope(use_scope)
    _check_ts(use_at, "use_at")
    log.verify()
    latest: DataConsentReceipt | None = None
    for entry in log._log:
        if (
            hmac.compare_digest(entry.data_subject_digest, data_subject_digest)
            and hmac.compare_digest(entry.data_kind_digest, data_kind_digest)
        ):
            latest = entry
    if latest is None:
        return _deny(
            DENY_TRAINING_DATA_NO_CONSENT,
            "no training-data consent receipt for this subject and data kind",
        )
    if latest.clause_kind != CLAUSE_SPECIFIC:
        return _deny(
            DENY_TRAINING_DATA_NO_CONSENT,
            f"clause kind {latest.clause_kind!r} is not consent: "
            "a blanket 'service improvement' or ToS-prose clause "
            "does not authorize training-data use",
        )
    if latest.revoked:
        return _deny(
            DENY_TRAINING_DATA_NO_CONSENT,
            "training-data consent was revoked; a new grant needs a new receipt",
        )
    if latest.scope != use_scope:
        return _deny(
            DENY_TRAINING_DATA_NO_CONSENT,
            f"consent scope {latest.scope!r} does not cover use scope {use_scope!r}",
        )
    if latest.granted_at > use_at:
        return _deny(
            DENY_TRAINING_DATA_NO_CONSENT,
            "consent grant postdates the use",
        )
    return _allow(
        f"specific {use_scope} consent in force since {latest.granted_at}",
        receipt_digest=latest.receipt_digest,
    )


# ---------------------------------------------------------------------------
# State/public matchmaker fairness audits
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MatchmakerAuditReceipt:
    """A fairness audit of a publicly funded matching program.

    ``criteria_digest`` pins the published eligibility/selection
    criteria; ``fairness_digest`` pins the audit findings (gender
    ratio, age/class screening analysis); ``program_change_digest``
    chains the program's algorithm changes since the last audit.
    Audits expire — a stale audit denies as
    ``dating.state_matchmaker_no_audit``.
    """

    receipt_id: str
    program_id: str
    criteria_digest: str
    fairness_digest: str
    program_change_digest: str
    audited_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema": DATING_SCHEMA_VERSION,
            "type": "matchmaker_audit",
            "receipt_id": self.receipt_id,
            "program_id": self.program_id,
            "criteria_digest": self.criteria_digest,
            "fairness_digest": self.fairness_digest,
            "program_change_digest": self.program_change_digest,
            "audited_at": self.audited_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


class MatchmakerAuditLog:
    """Append-only chain of matchmaker audit receipts."""

    def __init__(self) -> None:
        self._log: list[MatchmakerAuditReceipt] = []

    def append(self, receipt: MatchmakerAuditReceipt) -> None:
        self._log.append(receipt)

    def verify(self) -> None:
        _check_chain(self._log, "matchmaker_audit")

    def latest_for(self, program_id: str) -> MatchmakerAuditReceipt | None:
        found: MatchmakerAuditReceipt | None = None
        for entry in self._log:
            if entry.program_id == program_id:
                found = entry
        return found


def state_matchmaker_audit(
    *,
    receipt_id: str,
    program_id: str,
    criteria_digest: str,
    fairness_digest: str,
    program_change_digest: str,
    audited_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> MatchmakerAuditReceipt:
    """Seal a public-matchmaker fairness audit."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(program_id, "program_id")
    _check_hex64(criteria_digest, "criteria_digest")
    _check_hex64(fairness_digest, "fairness_digest")
    _check_hex64(program_change_digest, "program_change_digest")
    _check_ts(audited_at, "audited_at")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    receipt = MatchmakerAuditReceipt(
        receipt_id=receipt_id,
        program_id=program_id,
        criteria_digest=criteria_digest,
        fairness_digest=fairness_digest,
        program_change_digest=program_change_digest,
        audited_at=audited_at,
        authority_pubkey_hex=authority_pubkey_hex,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def check_matchmaker_audit_clock(
    *,
    log: MatchmakerAuditLog,
    program_id: str,
    now: int,
) -> DatingVerdict:
    """Check the public-matchmaker audit clock.

    No audit or a stale audit denies as
    ``dating.state_matchmaker_no_audit`` (the TOKYO縁結び /
    FirstDate lesson: public money, public receipts).
    """
    _check_nonempty_str(program_id, "program_id")
    _check_ts(now, "now")
    log.verify()
    receipt = log.latest_for(program_id)
    if receipt is None:
        return _deny(
            DENY_MATCHMAKER_NO_AUDIT,
            f"program {program_id!r} has no fairness audit on record",
        )
    if now - receipt.audited_at > MATCHMAKER_AUDIT_FRESHNESS_S:
        return _deny(
            DENY_MATCHMAKER_NO_AUDIT,
            f"program {program_id!r} fairness audit stale "
            f"({now - receipt.audited_at}s old)",
        )
    return _allow(
        f"program {program_id!r} fairness audit current",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Subscription exit receipts (Match $14M lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExitReceipt:
    """One cancellation-flow step.

    The flow is a fixed step chain (``EXIT_STEPS``): a subscription
    exit is authoritative only when the final step is receipted.
    ``dark_pattern`` names a detected obstruction (closed catalog
    below); any receipt carrying one denies at check time.
    """

    receipt_id: str
    subscription_id: str
    exit_step: str
    dark_pattern: str
    stepped_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema": DATING_SCHEMA_VERSION,
            "type": "subscription_exit",
            "receipt_id": self.receipt_id,
            "subscription_id": self.subscription_id,
            "exit_step": self.exit_step,
            "dark_pattern": self.dark_pattern,
            "stepped_at": self.stepped_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


#: Closed cancellation dark-pattern catalog. Observed names outside
#: it are a programming error, never a silent pass.
EXIT_DARK_PATTERNS: tuple[str, ...] = (
    "none",
    "roach_motel",
    "forced_continuity",
    "confirmshaming",
    "cancellation_maze",
    "retention_guilt",
    "hidden_exit",
)


def _check_exit_dark_pattern(value: Any) -> str:
    if value not in EXIT_DARK_PATTERNS:
        raise DatingError(
            f"dark_pattern must be one of {EXIT_DARK_PATTERNS}, got {value!r}"
        )
    return value


class ExitLog:
    """Append-only chain of subscription-exit step receipts."""

    def __init__(self) -> None:
        self._log: list[ExitReceipt] = []

    def append(self, receipt: ExitReceipt) -> None:
        self._log.append(receipt)

    def verify(self) -> None:
        _check_chain(self._log, "subscription_exit")


def subscription_exit_receipt(
    *,
    receipt_id: str,
    subscription_id: str,
    exit_step: str,
    dark_pattern: str = "none",
    stepped_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> ExitReceipt:
    """Seal one cancellation-flow step."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(subscription_id, "subscription_id")
    _check_exit_step(exit_step)
    _check_exit_dark_pattern(dark_pattern)
    _check_ts(stepped_at, "stepped_at")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    receipt = ExitReceipt(
        receipt_id=receipt_id,
        subscription_id=subscription_id,
        exit_step=_check_exit_step(exit_step),
        dark_pattern=_check_exit_dark_pattern(dark_pattern),
        stepped_at=stepped_at,
        authority_pubkey_hex=authority_pubkey_hex,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def check_cancellation_flow(
    *,
    log: ExitLog,
    subscription_id: str,
    now: int,
) -> DatingVerdict:
    """Check that the cancellation flow completed cleanly.

    Any detected dark-pattern step denies as
    ``dating.cancellation_dark_pattern``. A flow that stopped
    before the final step denies the same way (a broken exit is
    the dark pattern). A full clean chain allows.
    """
    _check_nonempty_str(subscription_id, "subscription_id")
    _check_ts(now, "now")
    log.verify()
    steps = [e for e in log._log if e.subscription_id == subscription_id]
    if not steps:
        return _deny(
            DENY_CANCELLATION_DARK_PATTERN,
            f"subscription {subscription_id!r} has no exit steps on record",
        )
    for entry in steps:
        if entry.dark_pattern != "none":
            return _deny(
                DENY_CANCELLATION_DARK_PATTERN,
                f"dark pattern {entry.dark_pattern!r} at step {entry.exit_step!r}",
            )
    seen = [e.exit_step for e in steps]
    for required in EXIT_STEPS:
        if required not in seen:
            return _deny(
                DENY_CANCELLATION_DARK_PATTERN,
                f"cancellation flow missing step {required!r}: a broken exit is a dark pattern",
            )
    # Steps must arrive in order; a shuffled flow is malformed exit UX.
    ordered = [seen.index(s) for s in EXIT_STEPS]
    if ordered != sorted(ordered):
        return _deny(
            DENY_CANCELLATION_DARK_PATTERN,
            "cancellation steps out of order",
        )
    last = max(steps, key=lambda e: EXIT_STEPS.index(e.exit_step))
    return _allow(
        f"subscription {subscription_id!r} exit completed cleanly",
        receipt_digest=last.receipt_digest,
    )


# ---------------------------------------------------------------------------
# AI-conversation-actor registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AIActorRegistration:
    """A registered AI-conversation operator.

    ``operator_digest`` pins the operating company/person; the
    receipt declares the ``platform_id`` it operates on and the
    declared persona count. Registration expires; an expired or
    missing registration denies.
    """

    receipt_id: str
    operator_digest: str
    platform_id: str
    declared_personas: int
    registered_at: int
    valid_until: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema": DATING_SCHEMA_VERSION,
            "type": "ai_actor_registration",
            "receipt_id": self.receipt_id,
            "operator_digest": self.operator_digest,
            "platform_id": self.platform_id,
            "declared_personas": self.declared_personas,
            "registered_at": self.registered_at,
            "valid_until": self.valid_until,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


class ActorLog:
    """Append-only chain of AI-actor registrations."""

    def __init__(self) -> None:
        self._log: list[AIActorRegistration] = []

    def append(self, receipt: AIActorRegistration) -> None:
        self._log.append(receipt)

    def verify(self) -> None:
        _check_chain(self._log, "ai_actor")

    def latest_for(self, operator_digest: str, platform_id: str) -> AIActorRegistration | None:
        found: AIActorRegistration | None = None
        for entry in self._log:
            if hmac.compare_digest(
                entry.operator_digest, operator_digest
            ) and entry.platform_id == platform_id:
                found = entry
        return found


def ai_actor_registration(
    *,
    receipt_id: str,
    operator_digest: str,
    platform_id: str,
    declared_personas: int,
    registered_at: int,
    valid_until: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> AIActorRegistration:
    """Register an AI-conversation operator."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_hex64(operator_digest, "operator_digest")
    _check_nonempty_str(platform_id, "platform_id")
    if not isinstance(declared_personas, int) or isinstance(declared_personas, bool):
        raise DatingError("declared_personas must be an int")
    if declared_personas < 0:
        raise DatingError("declared_personas must be non-negative")
    _check_ts(registered_at, "registered_at")
    _check_ts(valid_until, "valid_until")
    if valid_until <= registered_at:
        raise DatingError("valid_until must be after registered_at")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    receipt = AIActorRegistration(
        receipt_id=receipt_id,
        operator_digest=operator_digest,
        platform_id=platform_id,
        declared_personas=declared_personas,
        registered_at=registered_at,
        valid_until=valid_until,
        authority_pubkey_hex=authority_pubkey_hex,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def check_ai_actor_registered(
    *,
    log: ActorLog,
    operator_digest: str,
    platform_id: str,
    now: int,
) -> DatingVerdict:
    """Check that an AI-conversation operator is registered.

    Missing or expired registration denies as
    ``dating.unregistered_ai_actor`` (the 28-app network lesson).
    """
    _check_hex64(operator_digest, "operator_digest")
    _check_nonempty_str(platform_id, "platform_id")
    _check_ts(now, "now")
    log.verify()
    receipt = log.latest_for(operator_digest, platform_id)
    if receipt is None:
        return _deny(
            DENY_UNREGISTERED_AI_ACTOR,
            f"AI-conversation operator on platform {platform_id!r} is unregistered",
        )
    if now > receipt.valid_until:
        return _deny(
            DENY_UNREGISTERED_AI_ACTOR,
            f"AI-conversation operator registration expired",
        )
    return _allow(
        f"operator registered: {receipt.declared_personas} declared personas",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Vulnerability-exploitation ban (whole-class refusal)
# ---------------------------------------------------------------------------


def vulnerability_exploitation_ban(
    *,
    vulnerability_signal: str,
    targeting_active: bool,
) -> DatingVerdict:
    """Whole-class refusal on vulnerability targeting.

    Using widowhood/divorce/loneliness/bereavement/separation
    signals to target "AI lovers" is refused whole-class as
    ``dating.vulnerability_targeting`` — disclosure does not cure
    it. Unknown signal kinds are a programming error. An inactive
    signal allows (nothing is targeted).
    """
    _check_vulnerability_signal(vulnerability_signal)
    if not isinstance(targeting_active, bool):
        raise DatingError("targeting_active must be a bool")
    if targeting_active:
        return _deny(
            DENY_VULNERABILITY_TARGETING,
            f"targeting vulnerability signal {vulnerability_signal!r} is refused whole-class",
        )
    return _allow(f"vulnerability signal {vulnerability_signal!r} not targeted")


# ---------------------------------------------------------------------------
# Pig-butchering handoff
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GroomingHandoffReceipt:
    """A mandatory anti-fraud handoff for investment grooming.

    When an AI companion/dating agent detects an
    investment-grooming pattern (``grooming_pattern``, closed
    vocabulary), it must seal a handoff receipt: the session is
    flagged ``dating.investment_grooming``, the user is handed
    anti-fraud resources (``handoff_bundle_digest``), and the
    detection is on the record. Detected-but-silent denies at
    check time.
    """

    receipt_id: str
    session_id: str
    grooming_pattern: str
    pattern_evidence_digest: str
    handoff_bundle_digest: str
    detected_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> Mapping[str, Any]:
        return {
            "schema": DATING_SCHEMA_VERSION,
            "type": "grooming_handoff",
            "receipt_id": self.receipt_id,
            "session_id": self.session_id,
            "grooming_pattern": self.grooming_pattern,
            "pattern_evidence_digest": self.pattern_evidence_digest,
            "handoff_bundle_digest": self.handoff_bundle_digest,
            "detected_at": self.detected_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


class HandoffLog:
    """Append-only chain of grooming handoff receipts."""

    def __init__(self) -> None:
        self._log: list[GroomingHandoffReceipt] = []

    def append(self, receipt: GroomingHandoffReceipt) -> None:
        self._log.append(receipt)

    def verify(self) -> None:
        _check_chain(self._log, "grooming_handoff")

    def latest_for(self, session_id: str) -> GroomingHandoffReceipt | None:
        found: GroomingHandoffReceipt | None = None
        for entry in self._log:
            if entry.session_id == session_id:
                found = entry
        return found


def pigbutchering_handoff(
    *,
    receipt_id: str,
    session_id: str,
    grooming_pattern: str,
    pattern_evidence_digest: str,
    handoff_bundle_digest: str,
    detected_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> GroomingHandoffReceipt:
    """Seal a mandatory anti-fraud handoff for investment grooming."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(session_id, "session_id")
    _check_grooming_pattern(grooming_pattern)
    _check_hex64(pattern_evidence_digest, "pattern_evidence_digest")
    _check_hex64(handoff_bundle_digest, "handoff_bundle_digest")
    _check_ts(detected_at, "detected_at")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    receipt = GroomingHandoffReceipt(
        receipt_id=receipt_id,
        session_id=session_id,
        grooming_pattern=_check_grooming_pattern(grooming_pattern),
        pattern_evidence_digest=pattern_evidence_digest,
        handoff_bundle_digest=handoff_bundle_digest,
        detected_at=detected_at,
        authority_pubkey_hex=authority_pubkey_hex,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def check_grooming_handoff(
    *,
    log: HandoffLog,
    session_id: str,
    grooming_detected: bool,
    now: int,
) -> DatingVerdict:
    """Check that detected grooming was handed off, not silenced.

    ``grooming_detected=True`` with no handoff receipt denies as
    ``dating.investment_grooming`` (the pig-butchering lesson: the
    $10B/year compounds run on silence). A receipted handoff
    allows with the session flag bound; no detection allows.
    """
    _check_nonempty_str(session_id, "session_id")
    if not isinstance(grooming_detected, bool):
        raise DatingError("grooming_detected must be a bool")
    _check_ts(now, "now")
    log.verify()
    receipt = log.latest_for(session_id)
    if not grooming_detected:
        return _allow("no grooming detected in session")
    if receipt is None:
        return _deny(
            DENY_INVESTMENT_GROOMING,
            f"investment grooming detected in session {session_id!r} with no anti-fraud handoff",
        )
    return _allow(
        f"session flagged dating.investment_grooming; anti-fraud handoff receipted "
        f"({receipt.grooming_pattern})",
        receipt_digest=receipt.receipt_digest,
    )


__all__ = [
    "DATING_SCHEMA_VERSION",
    "DatingError",
    "DatingVerdict",
    "DENY_FRAUD_NOTICE_OVERDUE",
    "DENY_FRAUD_NOTICE_INCOMPLETE",
    "DENY_AI_MAJORITY_UNDISCLOSED",
    "DENY_TRAINING_DATA_NO_CONSENT",
    "DENY_MATCHMAKER_NO_AUDIT",
    "DENY_CANCELLATION_DARK_PATTERN",
    "DENY_UNREGISTERED_AI_ACTOR",
    "DENY_VULNERABILITY_TARGETING",
    "DENY_INVESTMENT_GROOMING",
    "DENY_CHAIN_BROKEN",
    "DENY_MALFORMED",
    "FRAUD_NOTICE_WINDOW_S",
    "PERSONA_RATIO_MAX_BPS",
    "CONSENT_SCOPES",
    "CONSENT_SCOPE_AI_TRAINING",
    "CONSENT_SCOPE_SERVICE_DELIVERY",
    "CONSENT_SCOPE_ANALYTICS",
    "CONSENT_CLAUSE_KINDS",
    "VULNERABILITY_SIGNALS",
    "GROOMING_PATTERNS",
    "EXIT_STEPS",
    "EXIT_DARK_PATTERNS",
    "MATCHMAKER_AUDIT_FRESHNESS_S",
    "FraudBanReceipt",
    "FraudBanLog",
    "fraud_ban_receipt",
    "check_fraud_notification_clock",
    "PersonaRatioReceipt",
    "PersonaRatioLog",
    "persona_ratio_receipt",
    "persona_ratio_cap",
    "DataConsentReceipt",
    "DataConsentLog",
    "input_side_data_consent",
    "check_data_consent_at_use",
    "MatchmakerAuditReceipt",
    "MatchmakerAuditLog",
    "state_matchmaker_audit",
    "check_matchmaker_audit_clock",
    "ExitReceipt",
    "ExitLog",
    "subscription_exit_receipt",
    "check_cancellation_flow",
    "AIActorRegistration",
    "ActorLog",
    "ai_actor_registration",
    "check_ai_actor_registered",
    "vulnerability_exploitation_ban",
    "GroomingHandoffReceipt",
    "HandoffLog",
    "pigbutchering_handoff",
    "check_grooming_handoff",
]
