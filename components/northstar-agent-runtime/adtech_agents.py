"""Adtech & synthetic-media disclosure discipline (one-hundred-forty-ninth batch).

Absorbs the 2026 AI-adtech research thread (mechanism ideas only,
honestly scoped):

* **The 2026 ad stack is agentic.** OpenAI "Sponsored Agents" +
  ChatGPT Ads Manager (2026-09): in-conversation brand AI agents and
  natural-language ad building. Meta full-automation placements by
  end-2026. PubMatic AgenticOS (seller-side agent layer). Google
  AI-output labels across all products (2026-07). Walmart Sparky /
  Amazon Rufus conversational ads. China 鲸鸿动能 full-domain
  intelligent-placement agent. Dentsu: 2026 global ad spend $1.04T,
  71.6% algorithm-driven. The governance question is no longer
  "who placed this banner" but "which agent decided this message,
  with what declared objectives, and is that declaration on the
  record."
* **Disclosure rules arrived in a fragmented 2026 wave.** EU AI Act
  Art. 50 (in force 2026-08-02, fines EUR 15M / 3%, machine-readable
  watermarks, grace to 2026-12-02, no commercial-recommendation
  exception). New York synthetic-performer law (2026-06-09,
  $1K/$5K). California SB 942 (2026-08-02, $5K/instance plus free
  detection tools). Hawaii Act 247 ($25K/instance, privately
  actionable). FTC "dual disclosure" doctrine ($53,088/instance)
  plus 16 CFR 465.2 (fake testimonials are NOT curable by labeling).
  China SAMR: visible "AI生成" labels plus credit-code watermarks,
  platform joint liability. Korea: AI Basic Act plus FTC
  virtual-persona labeling (2026-06-01), 5x punitive damages,
  platform joint liability. India ASCI (2026-09): virtual-influencer
  dual disclosure. Japan: no labeling law, but 景品表示法 — an AI
  persona touting product efficacy is a fabricated testimonial.
  IAB V2 (2026-08-18): materiality axis plus ✨ labels plus C2PA,
  and a warning about label fatigue. Dark patterns: FTC $2.5B
  Amazon Prime settlement; CDT's 37-manipulation-pattern study
  (submitted to EU enforcement and the FTC); EU Digital Fairness
  Act expected 2026-Q4; DSA Art. 25 (6% fines).

These are encoded as deterministic checks, not legal advice —
the regulation references below are the *rationale* for the
checks' shape, not counsel.

Northstar mapping:

* ``SyntheticPerformerReceipt`` — a synthetic performer
  (AI avatar, voice clone, virtual influencer) binds a real-identity
  digest, a named-human consent record digest, and a disclosure
  receipt digest. An unbound performer denies as
  ``adtech.no_performer_identity`` (the NY / California / Hawaii
  lesson: identity and disclosure are the point).
* ``testimonial_existence_gate()`` — an AI persona touting product
  efficacy is refused whole-class as
  ``adtech.testimonial_refused`` (the Japan 景品表示法 lesson;
  FTC 16 CFR 465.2: fake testimonials are not curable by labeling).
  Unknown persona kinds are a programming error, never a maybe.
* ``MaterialityReceipt`` / ``materiality_label_clock()`` — a
  materiality assessment binds the AI-content labeling clock.
  Material AI content without an AI-disclosure label denies as
  ``adtech.unlabeled_material`` (the IAB V2 materiality axis).
  Non-material content may go unlabeled but stays
  non-authoritative — a label is a claim, and an unlabeled claim is
  never promoted above one that was bound.
* ``WatermarkReceipt`` / ``machine_readable_marking()`` —
  machine-readable provenance marking bound per content digest.
  AI-generated commercial output with no marking denies as
  ``adtech.no_watermark`` (the EU Art. 50 lesson).
* ``jurisdiction_matrix_digest()`` / ``jurisdiction_matrix_pin()``
  — a five-jurisdiction strictest-rule matrix (EU, California,
  New York, China, Korea). Deployments bind the matrix digest; a
  deployment pinned to a stale or unknown matrix denies as
  ``adtech.matrix_mismatch``. The matrix encodes the strictest
  rule per axis, so multi-jurisdiction launches do not need to
  reason about which regime is toughest.
* ``DarkPatternScreenReceipt`` / ``dark_pattern_screen()`` /
  ``check_interface()`` — screens against a closed 37-pattern
  catalog (the CDT-study vocabulary). Unscreened interfaces deny
  as ``adtech.no_dark_pattern_screen``; a detected pattern denies
  as ``adtech.dark_pattern`` (the FTC/DSA lesson).
* ``AgenticBriefReceipt`` / ``agentic_brief_binding()`` /
  ``check_objective_drift()`` — agentic ad briefs bind declared
  objectives (objective digest). Objectives observed in the wild
  that do not match the declaration deny as
  ``adtech.brief_drift`` (the Sponsored-Agents lesson: the agent's
  brief is the leash).
* ``PlatformLiabilityReceipt`` / ``platform_liability_pin()`` /
  ``check_platform_liability()`` — platforms bind joint-liability
  pins under CN_SAMR and KR_AI_BASIC regimes. An unpinned or
  expired pin denies as ``adtech.no_liability_pin`` (the
  China/Korea platform-liability lesson).
* ``LabelFatigueReceipt`` / ``label_fatigue_guard()`` —
  comprehension-rate and exposure monitoring per monitor. Fatigue
  above threshold (comprehension below floor, or exposures beyond
  the review budget) denies as ``adtech.fatigue_review`` — the
  label format is reviewed, not silently worn out (the IAB V2
  label-fatigue warning).

Honest boundary: these receipts bind *declared* adtech discipline —
a sealed watermark declaration can still be stripped downstream,
a dark-pattern screen only sees the interface it was shown, and a
label-fatigue sample only covers measured comprehension. They do
not end manipulation; they force the discipline to be on the
record, hash-chained, and authority-signed so a missing one is a
deny, not a shrug. A consistent-but-false receipt still needs an
off-chain adjudicator.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest
comparisons via :func:`hmac.compare_digest`.
"""

from __future__ import annotations
from _domain_base import DomainError

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


ADTECH_SCHEMA_VERSION = "northstar.adtech.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Denial reason codes. All verdict reasons start with one of these.
DENY_NO_PERFORMER_IDENTITY = "adtech.no_performer_identity"
DENY_TESTIMONIAL_REFUSED = "adtech.testimonial_refused"
DENY_UNGRADED_MATERIALITY = "adtech.ungraded_materiality"
DENY_UNLABELED_MATERIAL = "adtech.unlabeled_material"
DENY_NO_WATERMARK = "adtech.no_watermark"
DENY_MATRIX_MISMATCH = "adtech.matrix_mismatch"
DENY_NO_DARK_PATTERN_SCREEN = "adtech.no_dark_pattern_screen"
DENY_DARK_PATTERN = "adtech.dark_pattern"
DENY_UNBOUND_BRIEF = "adtech.unbound_brief"
DENY_BRIEF_DRIFT = "adtech.brief_drift"
DENY_NO_LIABILITY_PIN = "adtech.no_liability_pin"
DENY_NO_FATIGUE_MONITOR = "adtech.no_fatigue_monitor"
DENY_FATIGUE_REVIEW = "adtech.fatigue_review"
DENY_CHAIN_BROKEN = "adtech.chain_broken"
DENY_MALFORMED = "adtech.malformed_receipt"

#: Persona kinds for the testimonial existence gate (closed vocabulary).
PERSONA_AI = "ai_persona"
PERSONA_REAL = "real_person"
PERSONA_KINDS: tuple[str, ...] = (PERSONA_AI, PERSONA_REAL)

#: Materiality axis (IAB V2 lesson).
MATERIALITY_MATERIAL = "material"
MATERIALITY_NON_MATERIAL = "non_material"
MATERIALITIES: tuple[str, ...] = (MATERIALITY_MATERIAL, MATERIALITY_NON_MATERIAL)

#: Machine-readable marking methods (closed vocabulary).
MARKING_METHODS: tuple[str, ...] = (
    "c2pa",
    "synthid",
    "metadata_provenance",
    "registry_pin",
)

#: Platform joint-liability regimes (the China/Korea lesson).
LIABILITY_CN_SAMR = "CN_SAMR"
LIABILITY_KR_AI_BASIC = "KR_AI_BASIC"
LIABILITY_REGIMES: tuple[str, ...] = (LIABILITY_CN_SAMR, LIABILITY_KR_AI_BASIC)

#: Label-fatigue parameters. Bench-calibrated numbers, not laws of
#: nature: the IAB V2 warning is that labels wear out, not that any
#: particular rate is safe.
MIN_COMPREHENSION_BPS = 4000
MAX_EXPOSURES_PER_FORMAT = 1000

#: CDT 37-manipulation-pattern closed catalog. Screening is against
#: this declared vocabulary: an observed pattern outside it is a
#: programming error, not a silent pass.
DARK_PATTERN_CATALOG: tuple[str, ...] = (
    "false_urgency",
    "fake_scarcity",
    "confirmshaming",
    "forced_continuity",
    "roach_motel",
    "sneak_into_basket",
    "hidden_costs",
    "trick_questions",
    "disguised_ads",
    "misdirection",
    "nagging",
    "obstruction",
    "preselection",
    "bait_and_switch",
    "drip_pricing",
    "auto_play",
    "default_sharing",
    "privacy_zuckering",
    "fabricated_endorsements",
    "countdown_reset",
    "fake_limited_offer",
    "forced_action",
    "silent_tracking",
    "interface_interference",
    "subscription_trap",
    "cancellation_maze",
    "checkout_confusion",
    "currency_confusion",
    "consent_wall",
    "dark_default_upsell",
    "free_trial_conversion",
    "fake_social_urgency",
    "visual_hierarchy_trick",
    "pre_ticked_addons",
    "misleading_free",
    "fake_price_comparison",
    "guilt_copy",
)


class AdtechError(DomainError):
    """A malformed adtech receipt or a programming error.

    Raised for structural problems (bad digests, unknown codes,
    broken chains, unknown persona kinds or dark-pattern names).
    Verification *failures* (unbound performers, unlabeled material
    content, detected dark patterns, drifted objectives) return an
    :class:`AdtechVerdict` with ``allowed=False`` instead — a
    failed claim is a verdict, a malformed receipt is a bug.
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
        raise AdtechError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdtechError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise AdtechError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed.
    if not isinstance(value, bytes) or len(value) != 32:
        raise AdtechError(f"{field_name} must be a 32-byte seed")
    return value


def _check_bps(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 10000:
        raise AdtechError(f"{field_name} must be basis points 0..10000")
    return value


def _check_persona_kind(value: Any) -> str:
    if value not in PERSONA_KINDS:
        raise AdtechError(f"persona_kind must be one of {PERSONA_KINDS}, got {value!r}")
    return value


def _check_materiality(value: Any) -> str:
    if value not in MATERIALITIES:
        raise AdtechError(f"materiality must be one of {MATERIALITIES}, got {value!r}")
    return value


def _check_marking_method(value: Any) -> str:
    if value not in MARKING_METHODS:
        raise AdtechError(f"marking_method must be one of {MARKING_METHODS}, got {value!r}")
    return value


def _check_dark_patterns(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise AdtechError("observed_patterns must be a tuple/list of pattern codes")
    patterns = tuple(value)
    for pattern in patterns:
        if pattern not in DARK_PATTERN_CATALOG:
            raise AdtechError(
                f"unknown dark-pattern code {pattern!r}; must be one of the "
                f"{len(DARK_PATTERN_CATALOG)} catalog entries"
            )
    if len(set(patterns)) != len(patterns):
        raise AdtechError("observed_patterns must not contain duplicates")
    return patterns


def _check_regimes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not value:
        raise AdtechError("regimes must be a non-empty tuple/list of regime codes")
    regimes = tuple(value)
    for regime in regimes:
        if regime not in LIABILITY_REGIMES:
            raise AdtechError(
                f"unknown liability regime {regime!r}; must be one of {LIABILITY_REGIMES}"
            )
    if len(set(regimes)) != len(regimes):
        raise AdtechError("regimes must not contain duplicates")
    return regimes


def _check_objectives(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not value:
        raise AdtechError("objectives must be a non-empty tuple/list of strings")
    objectives = tuple(value)
    for objective in objectives:
        if not isinstance(objective, str) or not objective.strip():
            raise AdtechError("each objective must be a non-empty string")
    return objectives


def _verify_signature(pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str) -> bool:
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
    """Raise :class:`AdtechError` if a receipt log is tampered/broken."""
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise AdtechError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise AdtechError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.authority_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise AdtechError(
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
class AdtechVerdict:
    """Outcome of one adtech-discipline check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> AdtechVerdict:
    return AdtechVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> AdtechVerdict:
    return AdtechVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def adtech_audit_event(verdict: AdtechVerdict, *, action: str) -> dict[str, Any]:
    """Build the audit event for an adtech-discipline verdict."""
    return {
        "action": _check_nonempty_str(action, "action"),
        "verdict_allowed": verdict.allowed,
        "reason": verdict.reason,
        "classification": verdict.classification,
        "receipt_digest": verdict.receipt_digest,
        "schema_version": ADTECH_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Synthetic-performer identity + disclosure receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SyntheticPerformerReceipt:
    """A synthetic performer bound to identity and disclosure.

    ``performer_id`` names the synthetic performer (AI avatar, voice
    clone, virtual influencer). ``identity_binding_digest`` pins the
    real-world person/entity the performer is tied to;
    ``consent_record_digest`` pins a named-human consent record;
    ``disclosure_receipt_digest`` pins the disclosure the ad itself
    carries. The NY synthetic-performer law / California SB 942 /
    Hawaii Act 247 lesson: the check is *identity + disclosure on
    the record*, not vibes.
    """

    receipt_id: str
    performer_id: str
    identity_binding_digest: str
    consent_record_digest: str
    disclosure_receipt_digest: str
    expires_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "performer_id": self.performer_id,
            "identity_binding_digest": self.identity_binding_digest,
            "consent_record_digest": self.consent_record_digest,
            "disclosure_receipt_digest": self.disclosure_receipt_digest,
            "expires_at": self.expires_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": ADTECH_SCHEMA_VERSION,
        }


def synthetic_performer_receipt(
    *,
    receipt_id: str,
    performer_id: str,
    identity_binding_digest: str,
    consent_record_digest: str,
    disclosure_receipt_digest: str,
    expires_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> SyntheticPerformerReceipt:
    """Seal a synthetic-performer identity + disclosure binding."""
    receipt = SyntheticPerformerReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        performer_id=_check_nonempty_str(performer_id, "performer_id"),
        identity_binding_digest=_check_hex64(identity_binding_digest, "identity_binding_digest"),
        consent_record_digest=_check_hex64(consent_record_digest, "consent_record_digest"),
        disclosure_receipt_digest=_check_hex64(
            disclosure_receipt_digest, "disclosure_receipt_digest"
        ),
        expires_at=_check_ts(expires_at, "expires_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex,
        ed25519.public_key(secret).hex(),
    ):
        raise AdtechError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class PerformerLog:
    """Hash-chained log of synthetic-performer receipts."""

    def __init__(self) -> None:
        self._log: list[SyntheticPerformerReceipt] = []

    def append(self, receipt: SyntheticPerformerReceipt) -> SyntheticPerformerReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise AdtechError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_performer(self, performer_id: str) -> SyntheticPerformerReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.performer_id, performer_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "performer")


def check_performer_disclosure(
    *,
    log: PerformerLog,
    performer_id: str,
    now: int,
) -> AdtechVerdict:
    """Check a synthetic performer against its identity + disclosure binding.

    No binding (or an expired one) is ``adtech.no_performer_identity`` —
    the performer may not run without identity and disclosure on the
    record.
    """
    now = _check_ts(now, "now")
    receipt = log.latest_for_performer(performer_id)
    if receipt is None:
        return _deny(
            DENY_NO_PERFORMER_IDENTITY,
            f"performer {performer_id!r}: no identity + disclosure binding on record",
        )
    if receipt.expires_at <= now:
        return _deny(
            DENY_NO_PERFORMER_IDENTITY,
            f"performer {performer_id!r}: binding {receipt.receipt_id!r} expired",
        )
    return _allow(
        f"performer {performer_id!r}: identity, named-human consent, and disclosure "
        f"bound in {receipt.receipt_id!r}",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Testimonial existence gate
# ---------------------------------------------------------------------------


def testimonial_existence_gate(
    *,
    persona_kind: str,
    claims_efficacy: bool,
    evidence_digest: str,
) -> AdtechVerdict:
    """Refuse AI-persona efficacy testimonials whole-class.

    An AI persona touting product efficacy is a fabricated
    testimonial — the Japan 景品表示法 lesson. FTC 16 CFR 465.2:
    fake testimonials are *not* curable by labeling, so there is no
    "labeled AI testimonial" path. The gate is binary: AI persona +
    efficacy claim → refused; anything else → allowed.
    """
    persona_kind = _check_persona_kind(persona_kind)
    evidence_digest = _check_hex64(evidence_digest, "evidence_digest")
    if not isinstance(claims_efficacy, bool):
        raise AdtechError("claims_efficacy must be a bool")
    if persona_kind == PERSONA_AI and claims_efficacy:
        return _deny(
            DENY_TESTIMONIAL_REFUSED,
            "AI persona touting product efficacy refused whole-class: "
            "fabricated testimonial, not curable by labeling (evidence "
            f"{evidence_digest[:16]}…)",
        )
    return _allow(
        f"testimonial screen passed: persona={persona_kind}, "
        f"claims_efficacy={claims_efficacy}",
    )


# ---------------------------------------------------------------------------
# Materiality label clock
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MaterialityReceipt:
    """A materiality assessment binding the AI-content labeling clock.

    The IAB V2 lesson: labeling follows *materiality*, not a blanket
    rule. A material AI-content claim (one that could move a
    purchasing decision) without an AI-disclosure label is the deny
    case. Assessments expire — materiality is re-graded, not
    grandfathered.
    """

    receipt_id: str
    content_id: str
    materiality: str
    evidence_digest: str
    assessed_at: int
    expires_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "content_id": self.content_id,
            "materiality": self.materiality,
            "evidence_digest": self.evidence_digest,
            "assessed_at": self.assessed_at,
            "expires_at": self.expires_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": ADTECH_SCHEMA_VERSION,
        }


def materiality_assessment_receipt(
    *,
    receipt_id: str,
    content_id: str,
    materiality: str,
    evidence_digest: str,
    assessed_at: int,
    expires_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> MaterialityReceipt:
    """Seal a materiality assessment for a piece of AI content."""
    receipt = MaterialityReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        content_id=_check_nonempty_str(content_id, "content_id"),
        materiality=_check_materiality(materiality),
        evidence_digest=_check_hex64(evidence_digest, "evidence_digest"),
        assessed_at=_check_ts(assessed_at, "assessed_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex, ed25519.public_key(secret).hex()
    ):
        raise AdtechError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    if receipt.expires_at <= receipt.assessed_at:
        raise AdtechError("expires_at must be after assessed_at")
    return _seal(receipt, receipt._payload(), secret)


class MaterialityLog:
    """Hash-chained log of materiality assessments."""

    def __init__(self) -> None:
        self._log: list[MaterialityReceipt] = []

    def append(self, receipt: MaterialityReceipt) -> MaterialityReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise AdtechError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_content(self, content_id: str) -> MaterialityReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.content_id, content_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "materiality")


def materiality_label_clock(
    *,
    log: MaterialityLog,
    content_id: str,
    labeled: bool,
    now: int,
) -> AdtechVerdict:
    """Check the labeling clock for a piece of AI content.

    Material AI content without an AI-disclosure label denies as
    ``adtech.unlabeled_material``. Content with no (or an expired)
    materiality assessment denies as ``adtech.ungraded_materiality`` —
    ungraded content does not inherit a permissive default.
    Non-material content may go unlabeled but stays
    non-authoritative.
    """
    now = _check_ts(now, "now")
    if not isinstance(labeled, bool):
        raise AdtechError("labeled must be a bool")
    receipt = log.latest_for_content(content_id)
    if receipt is None:
        return _deny(
            DENY_UNGRADED_MATERIALITY,
            f"content {content_id!r}: no materiality assessment on record",
        )
    if receipt.expires_at <= now:
        return _deny(
            DENY_UNGRADED_MATERIALITY,
            f"content {content_id!r}: materiality assessment {receipt.receipt_id!r} expired",
        )
    if receipt.materiality == MATERIALITY_MATERIAL and not labeled:
        return _deny(
            DENY_UNLABELED_MATERIAL,
            f"content {content_id!r}: material AI content without an AI-disclosure label",
        )
    if receipt.materiality == MATERIALITY_NON_MATERIAL and not labeled:
        return AdtechVerdict(
            allowed=True,
            reason=f"content {content_id!r}: non-material AI content unlabeled "
            "(non-authoritative: unlabeled claims stay below bound ones)",
            classification=CLASS_NON_AUTHORITATIVE,
            receipt_digest=receipt.receipt_digest,
        )
    return _allow(
        f"content {content_id!r}: labeling clock satisfied "
        f"(materiality={receipt.materiality}, labeled={labeled})",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Machine-readable watermark binding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WatermarkReceipt:
    """A machine-readable provenance marking bound to a content digest.

    The EU AI Act Art. 50 lesson: AI-generated commercial output
    must carry machine-readable marking. The receipt binds the
    content digest, the marking method (closed vocabulary), and a
    decode-evidence digest proving the marking is actually
    machine-readable — a human-visible badge alone does not count.
    """

    receipt_id: str
    content_digest: str
    marking_method: str
    decode_evidence_digest: str
    issued_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "content_digest": self.content_digest,
            "marking_method": self.marking_method,
            "decode_evidence_digest": self.decode_evidence_digest,
            "issued_at": self.issued_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": ADTECH_SCHEMA_VERSION,
        }


def machine_readable_marking(
    *,
    receipt_id: str,
    content_digest: str,
    marking_method: str,
    decode_evidence_digest: str,
    issued_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> WatermarkReceipt:
    """Seal a machine-readable provenance marking for AI-generated output."""
    receipt = WatermarkReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        content_digest=_check_hex64(content_digest, "content_digest"),
        marking_method=_check_marking_method(marking_method),
        decode_evidence_digest=_check_hex64(decode_evidence_digest, "decode_evidence_digest"),
        issued_at=_check_ts(issued_at, "issued_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex, ed25519.public_key(secret).hex()
    ):
        raise AdtechError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class WatermarkLog:
    """Hash-chained log of machine-readable marking receipts."""

    def __init__(self) -> None:
        self._log: list[WatermarkReceipt] = []

    def append(self, receipt: WatermarkReceipt) -> WatermarkReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise AdtechError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_content(self, content_digest: str) -> WatermarkReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.content_digest, content_digest):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "watermark")


def check_machine_reading(
    *,
    log: WatermarkLog,
    content_digest: str,
    now: int,
) -> AdtechVerdict:
    """Check that AI-generated commercial output carries machine-readable marking.

    Missing marking denies as ``adtech.no_watermark``. Honest
    scoping: the receipt binds the *declaration* that marking was
    applied with machine-readable decode evidence — markings can
    still be stripped downstream, and catching that needs
    content-level forensic verification, not this gate.
    """
    _check_ts(now, "now")
    content_digest = _check_hex64(content_digest, "content_digest")
    receipt = log.latest_for_content(content_digest)
    if receipt is None:
        return _deny(
            DENY_NO_WATERMARK,
            f"content {content_digest[:16]}…: no machine-readable marking on record",
        )
    return _allow(
        f"content {content_digest[:16]}…: machine-readable marking "
        f"({receipt.marking_method}) bound in {receipt.receipt_id!r}",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Jurisdiction matrix (five-jurisdiction strictest-rule binding)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JurisdictionRule:
    """One strictest-rule entry of the jurisdiction matrix.

    Each entry is the *strictest known 2026 requirement* on one
    axis for one jurisdiction, as a declared mechanism shape — not
    legal advice. Deployments bind the matrix digest so a rule
    tightening somewhere upgrades everywhere.
    """

    jurisdiction: str
    rule_id: str
    requirement: str
    penalty: str
    in_force: str
    notes: str


JURISDICTION_RULES: tuple[JurisdictionRule, ...] = (
    JurisdictionRule(
        jurisdiction="EU",
        rule_id="ai_act_art50",
        requirement="machine-readable AI-output marking on commercial content",
        penalty="EUR 15M or 3% of global turnover",
        in_force="2026-08-02",
        notes="no commercial-recommendation exception; grace for listed systems to 2026-12-02",
    ),
    JurisdictionRule(
        jurisdiction="California",
        rule_id="sb_942",
        requirement="AI-generated content disclosure plus free detection tools",
        penalty="$5K per instance",
        in_force="2026-08-02",
        notes="detection-tool obligation sits on the provider",
    ),
    JurisdictionRule(
        jurisdiction="New_York",
        rule_id="synthetic_performer",
        requirement="synthetic performer identity binding plus disclosure receipts",
        penalty="$1K / $5K",
        in_force="2026-06-09",
        notes="consent record must name a human",
    ),
    JurisdictionRule(
        jurisdiction="China",
        rule_id="samr_ai_generated",
        requirement="visible 'AI生成' labels plus credit-code watermarks; platform joint liability",
        penalty="administrative and credit penalties",
        in_force="2026",
        notes="platforms jointly liable for unlabeled AI commercial content they distribute",
    ),
    JurisdictionRule(
        jurisdiction="Korea",
        rule_id="ai_basic_act_ftc",
        requirement="virtual-persona labeling; platform joint liability",
        penalty="5x punitive damages",
        in_force="2026-06-01",
        notes="FTC virtual-persona labeling rules; platforms jointly liable",
    ),
)


def jurisdiction_matrix_digest() -> str:
    """Deterministic digest of the five-jurisdiction strictest-rule matrix.

    The digest is the version pin: a deployment that cannot reproduce
    it is running against a stale or unknown matrix and must not
    launch.
    """
    matrix = [
        {
            "jurisdiction": rule.jurisdiction,
            "rule_id": rule.rule_id,
            "requirement": rule.requirement,
            "penalty": rule.penalty,
            "in_force": rule.in_force,
            "notes": rule.notes,
        }
        for rule in JURISDICTION_RULES
    ]
    return jcs_sha256_hex(
        {"schema_version": ADTECH_SCHEMA_VERSION, "jurisdiction_rules": matrix}
    )


@dataclass(frozen=True)
class MatrixPinReceipt:
    """A deployment's binding to the jurisdiction matrix digest."""

    receipt_id: str
    deployment_id: str
    matrix_digest: str
    pinned_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "deployment_id": self.deployment_id,
            "matrix_digest": self.matrix_digest,
            "pinned_at": self.pinned_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": ADTECH_SCHEMA_VERSION,
        }


def jurisdiction_matrix_pin(
    *,
    receipt_id: str,
    deployment_id: str,
    matrix_digest: str,
    pinned_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> MatrixPinReceipt:
    """Seal a deployment's jurisdiction-matrix binding."""
    receipt = MatrixPinReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        deployment_id=_check_nonempty_str(deployment_id, "deployment_id"),
        matrix_digest=_check_hex64(matrix_digest, "matrix_digest"),
        pinned_at=_check_ts(pinned_at, "pinned_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex, ed25519.public_key(secret).hex()
    ):
        raise AdtechError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class MatrixLog:
    """Hash-chained log of jurisdiction-matrix pins."""

    def __init__(self) -> None:
        self._log: list[MatrixPinReceipt] = []

    def append(self, receipt: MatrixPinReceipt) -> MatrixPinReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise AdtechError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_deployment(self, deployment_id: str) -> MatrixPinReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.deployment_id, deployment_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "matrix")


def check_matrix_pin(
    *,
    log: MatrixLog,
    deployment_id: str,
    now: int,
) -> AdtechVerdict:
    """Check a deployment's jurisdiction-matrix binding.

    A missing pin or a pin whose digest does not reproduce the
    current matrix digest denies as ``adtech.matrix_mismatch`` —
    the deployment is running against a stale or unknown
    strictest-rule set.
    """
    _check_ts(now, "now")
    receipt = log.latest_for_deployment(deployment_id)
    if receipt is None:
        return _deny(
            DENY_MATRIX_MISMATCH,
            f"deployment {deployment_id!r}: no jurisdiction-matrix pin on record",
        )
    current = jurisdiction_matrix_digest()
    if not hmac.compare_digest(receipt.matrix_digest, current):
        return _deny(
            DENY_MATRIX_MISMATCH,
            f"deployment {deployment_id!r}: pinned matrix {receipt.matrix_digest[:16]}… "
            f"does not match current {current[:16]}… (stale strictest-rule set)",
        )
    return _allow(
        f"deployment {deployment_id!r}: bound to current jurisdiction matrix "
        f"({receipt.matrix_digest[:16]}…)",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Dark-pattern screen (37-pattern closed catalog)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DarkPatternScreenReceipt:
    """A dark-pattern screen against the closed 37-pattern catalog.

    The CDT 37-manipulation-pattern study is the vocabulary;
    ``observed_patterns`` records what the screener actually saw.
    An unscreened interface cannot run — the screen is the gate,
    and skipping it denies, so "we didn't look" is never a pass.
    """

    screen_id: str
    interface_id: str
    observed_patterns: tuple[str, ...]
    screened_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "screen_id": self.screen_id,
            "interface_id": self.interface_id,
            "observed_patterns": list(self.observed_patterns),
            "screened_at": self.screened_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": ADTECH_SCHEMA_VERSION,
        }


def dark_pattern_screen(
    *,
    screen_id: str,
    interface_id: str,
    observed_patterns: tuple[str, ...] | list[str],
    screened_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> DarkPatternScreenReceipt:
    """Seal a dark-pattern screen of an ad interface."""
    receipt = DarkPatternScreenReceipt(
        screen_id=_check_nonempty_str(screen_id, "screen_id"),
        interface_id=_check_nonempty_str(interface_id, "interface_id"),
        observed_patterns=_check_dark_patterns(observed_patterns),
        screened_at=_check_ts(screened_at, "screened_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex, ed25519.public_key(secret).hex()
    ):
        raise AdtechError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class DarkPatternLog:
    """Hash-chained log of dark-pattern screens."""

    def __init__(self) -> None:
        self._log: list[DarkPatternScreenReceipt] = []

    def append(self, receipt: DarkPatternScreenReceipt) -> DarkPatternScreenReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise AdtechError(
                f"receipt {receipt.screen_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_interface(self, interface_id: str) -> DarkPatternScreenReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.interface_id, interface_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "dark_pattern")


def check_interface(
    *,
    log: DarkPatternLog,
    interface_id: str,
    now: int,
) -> AdtechVerdict:
    """Check an ad interface against its latest dark-pattern screen.

    No screen denies as ``adtech.no_dark_pattern_screen``; a screen
    with observed patterns denies as ``adtech.dark_pattern`` naming
    the pattern. A clean screen allows. Honest scoping: the screen
    only covers the interface build it inspected — a redesign
    without a fresh screen is unscreened.
    """
    _check_ts(now, "now")
    receipt = log.latest_for_interface(interface_id)
    if receipt is None:
        return _deny(
            DENY_NO_DARK_PATTERN_SCREEN,
            f"interface {interface_id!r}: no dark-pattern screen on record",
        )
    if receipt.observed_patterns:
        return _deny(
            DENY_DARK_PATTERN,
            f"interface {interface_id!r}: dark pattern detected "
            f"({', '.join(receipt.observed_patterns)}), screen {receipt.screen_id!r}",
        )
    return _allow(
        f"interface {interface_id!r}: dark-pattern screen {receipt.screen_id!r} clean",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Agentic brief binding (objective-drift tripwire)
# ---------------------------------------------------------------------------


def _objective_digest(objectives: tuple[str, ...]) -> str:
    """Deterministic digest of the declared objective set."""
    return jcs_sha256_hex(
        {
            "schema_version": ADTECH_SCHEMA_VERSION,
            "objectives": sorted(objectives),
        }
    )


@dataclass(frozen=True)
class AgenticBriefReceipt:
    """An agentic ad brief's declared objectives, pinned by digest.

    The Sponsored-Agents lesson: when an agent builds and places
    ads conversationally, the *declared brief* is the leash. The
    receipt binds the objective set digest plus a
    constraints digest; what the agent is observed pursuing is
    checked against the digest, not the prose.
    """

    brief_id: str
    declared_objectives: tuple[str, ...]
    objective_digest: str
    constraints_digest: str
    issued_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "brief_id": self.brief_id,
            "declared_objectives": list(self.declared_objectives),
            "objective_digest": self.objective_digest,
            "constraints_digest": self.constraints_digest,
            "issued_at": self.issued_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": ADTECH_SCHEMA_VERSION,
        }


def agentic_brief_binding(
    *,
    brief_id: str,
    declared_objectives: tuple[str, ...] | list[str],
    constraints_digest: str,
    issued_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> AgenticBriefReceipt:
    """Seal an agentic ad brief's declared objectives."""
    objectives = _check_objectives(declared_objectives)
    receipt = AgenticBriefReceipt(
        brief_id=_check_nonempty_str(brief_id, "brief_id"),
        declared_objectives=objectives,
        objective_digest=_objective_digest(objectives),
        constraints_digest=_check_hex64(constraints_digest, "constraints_digest"),
        issued_at=_check_ts(issued_at, "issued_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex, ed25519.public_key(secret).hex()
    ):
        raise AdtechError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class BriefLog:
    """Hash-chained log of agentic brief bindings."""

    def __init__(self) -> None:
        self._log: list[AgenticBriefReceipt] = []

    def append(self, receipt: AgenticBriefReceipt) -> AgenticBriefReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise AdtechError(
                f"receipt {receipt.brief_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_brief(self, brief_id: str) -> AgenticBriefReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.brief_id, brief_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "brief")


def check_objective_drift(
    *,
    log: BriefLog,
    brief_id: str,
    observed_objectives: tuple[str, ...] | list[str],
    now: int,
) -> AdtechVerdict:
    """Check observed agent objectives against the bound brief.

    No brief denies as ``adtech.unbound_brief`` — an ad agent with
    no declared objectives does not run. Observed objectives whose
    digest does not match the declaration deny as
    ``adtech.brief_drift``: the agent is pursuing something its
    brief never authorized.
    """
    _check_ts(now, "now")
    observed = _check_objectives(observed_objectives)
    receipt = log.latest_for_brief(brief_id)
    if receipt is None:
        return _deny(
            DENY_UNBOUND_BRIEF,
            f"brief {brief_id!r}: no declared objectives on record — "
            "an ad agent with no brief does not run",
        )
    if not hmac.compare_digest(_objective_digest(observed), receipt.objective_digest):
        declared = sorted(receipt.declared_objectives)
        return _deny(
            DENY_BRIEF_DRIFT,
            f"brief {brief_id!r}: observed objectives {sorted(observed)!r} drift from "
            f"declared {declared!r}",
        )
    return _allow(
        f"brief {brief_id!r}: observed objectives match the declaration",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Platform joint-liability pins
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlatformLiabilityReceipt:
    """A platform's joint-liability pin under declared regimes.

    The China SAMR / Korea AI Basic Act lesson: platforms are
    jointly liable for the AI commercial content they distribute.
    The pin binds the platform to named regimes with an
    attestation digest; it expires, so liability posture is
    re-attested, not grandfathered.
    """

    receipt_id: str
    platform_id: str
    regimes: tuple[str, ...]
    attestation_digest: str
    pinned_at: int
    expires_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "platform_id": self.platform_id,
            "regimes": list(self.regimes),
            "attestation_digest": self.attestation_digest,
            "pinned_at": self.pinned_at,
            "expires_at": self.expires_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": ADTECH_SCHEMA_VERSION,
        }


def platform_liability_pin(
    *,
    receipt_id: str,
    platform_id: str,
    regimes: tuple[str, ...] | list[str],
    attestation_digest: str,
    pinned_at: int,
    expires_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> PlatformLiabilityReceipt:
    """Seal a platform's joint-liability pin."""
    receipt = PlatformLiabilityReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        platform_id=_check_nonempty_str(platform_id, "platform_id"),
        regimes=_check_regimes(regimes),
        attestation_digest=_check_hex64(attestation_digest, "attestation_digest"),
        pinned_at=_check_ts(pinned_at, "pinned_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex, ed25519.public_key(secret).hex()
    ):
        raise AdtechError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    if receipt.expires_at <= receipt.pinned_at:
        raise AdtechError("expires_at must be after pinned_at")
    return _seal(receipt, receipt._payload(), secret)


class LiabilityLog:
    """Hash-chained log of platform joint-liability pins."""

    def __init__(self) -> None:
        self._log: list[PlatformLiabilityReceipt] = []

    def append(self, receipt: PlatformLiabilityReceipt) -> PlatformLiabilityReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise AdtechError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_platform(self, platform_id: str) -> PlatformLiabilityReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.platform_id, platform_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "liability")


def check_platform_liability(
    *,
    log: LiabilityLog,
    platform_id: str,
    now: int,
) -> AdtechVerdict:
    """Check a platform's joint-liability pin.

    A missing or expired pin denies as
    ``adtech.no_liability_pin`` — a platform that will not attest
    its joint-liability posture does not distribute AI commercial
    content under this discipline.
    """
    now = _check_ts(now, "now")
    receipt = log.latest_for_platform(platform_id)
    if receipt is None:
        return _deny(
            DENY_NO_LIABILITY_PIN,
            f"platform {platform_id!r}: no joint-liability pin on record",
        )
    if receipt.expires_at <= now:
        return _deny(
            DENY_NO_LIABILITY_PIN,
            f"platform {platform_id!r}: joint-liability pin {receipt.receipt_id!r} expired",
        )
    return _allow(
        f"platform {platform_id!r}: joint-liability pin under "
        f"{', '.join(receipt.regimes)} in {receipt.receipt_id!r}",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Label-fatigue guard
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LabelFatigueReceipt:
    """A label-fatigue measurement for a monitored placement.

    The IAB V2 warning: AI-disclosure labels wear out — exposure
    without comprehension is theater. The receipt binds measured
    exposures, distinct label formats in rotation, and the measured
    comprehension rate (basis points) over the window. Above the
    fatigue threshold the format is *reviewed*, not silently
    repeated.
    """

    monitor_id: str
    content_id: str
    exposures: int
    distinct_formats: int
    comprehension_bps: int
    window_days: int
    measured_at: int
    authority_pubkey_hex: str
    prev_digest: str
    signature_hex: str = ""
    receipt_digest: str = ""

    def _payload(self) -> dict[str, Any]:
        return {
            "monitor_id": self.monitor_id,
            "content_id": self.content_id,
            "exposures": self.exposures,
            "distinct_formats": self.distinct_formats,
            "comprehension_bps": self.comprehension_bps,
            "window_days": self.window_days,
            "measured_at": self.measured_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": ADTECH_SCHEMA_VERSION,
        }


def label_fatigue_sample(
    *,
    monitor_id: str,
    content_id: str,
    exposures: int,
    distinct_formats: int,
    comprehension_bps: int,
    window_days: int,
    measured_at: int,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> LabelFatigueReceipt:
    """Seal a label-fatigue measurement."""
    if not isinstance(exposures, int) or isinstance(exposures, bool) or exposures < 0:
        raise AdtechError("exposures must be a non-negative int")
    if (
        not isinstance(distinct_formats, int)
        or isinstance(distinct_formats, bool)
        or distinct_formats < 1
    ):
        raise AdtechError("distinct_formats must be a positive int")
    if not isinstance(window_days, int) or isinstance(window_days, bool) or window_days < 1:
        raise AdtechError("window_days must be a positive int")
    receipt = LabelFatigueReceipt(
        monitor_id=_check_nonempty_str(monitor_id, "monitor_id"),
        content_id=_check_nonempty_str(content_id, "content_id"),
        exposures=exposures,
        distinct_formats=distinct_formats,
        comprehension_bps=_check_bps(comprehension_bps, "comprehension_bps"),
        window_days=window_days,
        measured_at=_check_ts(measured_at, "measured_at"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    secret = _check_secret(authority_secret, "authority_secret")
    if not hmac.compare_digest(
        authority_pubkey_hex, ed25519.public_key(secret).hex()
    ):
        raise AdtechError("authority_pubkey_hex does not match authority_secret (no self-issuance)")
    return _seal(receipt, receipt._payload(), secret)


class FatigueLog:
    """Hash-chained log of label-fatigue measurements."""

    def __init__(self) -> None:
        self._log: list[LabelFatigueReceipt] = []

    def append(self, receipt: LabelFatigueReceipt) -> LabelFatigueReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise AdtechError(
                f"receipt {receipt.monitor_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_monitor(self, monitor_id: str) -> LabelFatigueReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.monitor_id, monitor_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "fatigue")


def label_fatigue_guard(
    *,
    log: FatigueLog,
    monitor_id: str,
    now: int,
) -> AdtechVerdict:
    """Check label fatigue for a monitored placement.

    No measurement denies as ``adtech.no_fatigue_monitor`` —
    fatigue is not assumed absent. Comprehension below
    ``MIN_COMPREHENSION_BPS``, or exposures beyond
    ``MAX_EXPOSURES_PER_FORMAT`` per format, denies as
    ``adtech.fatigue_review``: the label format must be reviewed
    before more exposure.
    """
    _check_ts(now, "now")
    receipt = log.latest_for_monitor(monitor_id)
    if receipt is None:
        return _deny(
            DENY_NO_FATIGUE_MONITOR,
            f"monitor {monitor_id!r}: no label-fatigue measurement on record",
        )
    per_format = receipt.exposures // max(receipt.distinct_formats, 1)
    if receipt.comprehension_bps < MIN_COMPREHENSION_BPS:
        return _deny(
            DENY_FATIGUE_REVIEW,
            f"monitor {monitor_id!r}: comprehension "
            f"{receipt.comprehension_bps}bps below {MIN_COMPREHENSION_BPS}bps floor — "
            "label format review required",
        )
    if per_format > MAX_EXPOSURES_PER_FORMAT:
        return _deny(
            DENY_FATIGUE_REVIEW,
            f"monitor {monitor_id!r}: {per_format} exposures per format beyond "
            f"{MAX_EXPOSURES_PER_FORMAT} review budget — label format review required",
        )
    return _allow(
        f"monitor {monitor_id!r}: labels healthy "
        f"(comprehension {receipt.comprehension_bps}bps, "
        f"{per_format} exposures per format)",
        receipt.receipt_digest,
    )
