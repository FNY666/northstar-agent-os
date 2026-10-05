"""Content moderation discipline (one-hundred-fiftieth batch).

Absorbs the 2026 content-moderation research thread (mechanism ideas
only, honestly scoped):

* **Scale of automation.** TikTok Q1 2026 removed 184M videos globally
  with 96.7% automated; its EU H1 report showed 104M removals, 94.1%
  unsupervised. Automation ratios at this scale make appeal
  restoration the mis-removal lower bound: appeal-restoration volumes
  (Iraq 157K, Egypt 146K) are a *floor*, not an estimate. The DSA
  transparency-template regime now forces automation-ratio + accuracy
  disclosure cross-checked against per-decision databases — the
  numbers must recompute, not merely be asserted.
* **Statements of reasons.** Courts ruled shadowbans fall under DSA
  Art. 17 statements of reasons: "scale" is no exemption, and every
  restriction — including visibility reduction — needs a reason. X's
  2026-09 "Under the Hood" tool discloses per-post legal restrictions
  with country + basis. "Why this video" features only give
  high-level categories — the module binds reasons at digest level.
* **Severity ceiling.** Meta's 2026 logic is shrinking to "most severe
  auto-remove, low severity via reports"; fully-automated removal of
  low-severity content is the overreach this batch gates.
* **Fact-check substitution.** Meta's 2026-09 pilot of Community
  Notes in 16 Latin American countries replacing professional
  fact-checking was twice opposed by the Oversight Board: notes
  depend on fact-checker output, and substitution creates
  human-rights risk in polarized countries/elections.
* **Dialect bias.** EMNLP 2026 confirmed retriever political bias and
  dialect discrimination at the embedding level; Arabic-dialect
  toxicity detection shows systematic false positives (MDPI 2026).
* **AIGC labeling.** EU AI Act Art. 50 (synthetic-content labeling),
  抖音's algorithm-transparency commitment, the "AI 抖音求真"
  300M-daily-exposure program, AI-content "digital IDs", and the
  "AI 魔改" campaign takedowns (Douyin 6,713 / Kuaishou 5,576 /
  Xiaohongshu 1,394 items) drive the cross-platform source-label
  binding.
* **Regulatory frame.** DSA newly designated ChatGPT (VLOSE) and
  Reddit/Roblox (VLOP); cumulative fines ~EUR 870M. The European
  Parliament demands interim measures on engagement algorithms;
  Australia's Digital Duty of Care, France's under-15 feature limits,
  and the EU AI Act Art. 50 apply. The Oversight Board found LLM
  applications replicating speech-restrictive domestic law. The
  2026-10-02 EU data demand to YouTube/TikTok/Snapchat on recommender
  systems drives the non-profiling-option and amplification-audit
  requirements.
* **Risk.** Context blindness is the 2026 controversy driver:
  "speed+scale" over "accuracy+nuance".

Northstar mapping:

* ``statement_of_reasons()`` — every removal/restriction decision
  (including shadowbans/visibility reduction) binds an Art-17-style
  reason receipt naming the content, the decision kind, the
  closed-vocabulary reason, and the issuer. No live receipt:
  ``moderation.no_statement_of_reasons`` (X court lesson).
* ``overremoval_probe()`` — the appeal-restoration rate over a
  declared decision registry: restoration rate above
  ``OVERREMOVAL_TOLERANCE`` classifies
  ``moderation.overremoval_audit`` (TikTok appeal-restoration
  lower-bound lesson). The registry is a declared sample; the probe
  does not observe unappealed content.
* ``check_dialect_parity()`` — dialect parity testing is required
  before enforcement deployment; a systematic false-positive
  disparity against a declared dialect baseline denies as
  ``moderation.dialect_bias`` (MDPI lesson).
* ``check_automation_ceiling()`` — fully-automated removal is limited
  to the highest severity tier; lower-severity fully-automated
  removal denies as ``moderation.auto_overreach`` (Meta lesson).
* ``check_non_profiling_option()`` — a recommender must declare a
  non-profiling option for users; absent: ``moderation.no_non_profiling_option``
  (2026-10-02 EU recommender-data lesson).
* ``legal_restriction_receipt()`` — per-post legal restrictions bind
  country + basis disclosure (X "Under the Hood" lesson); an
  undisclosed restriction: ``moderation.undisclosed_restriction``.
* ``why_this_content()`` — the "why this content" explanation binds
  the decision digest; a missing or mismatched explanation degrades
  to ``non_authoritative`` (抖音 "why this video" lesson).
* ``check_factcheck_non_substitution()`` — crowdsourced notes may not
  *substitute* professional fact-checking on civic/election content;
  substitution without a professional program denies as
  ``moderation.factcheck_substitution`` (Oversight Board lesson).
* ``aigc_label_receipt()`` — AI-generated content binds a
  cross-platform source label; unlabeled AI content:
  ``moderation.unlabeled_aigc`` (Art. 50 lesson).
* ``check_amplification_clock()`` — rabbit-hole amplification audits
  run on a clock; an overdue audit denies as
  ``moderation.amplification_audit_overdue`` (EP interim-measures
  lesson).

Honest boundary: receipts bind *declared* moderation discipline —
digests recompute, signatures verify, vocabularies are closed, clocks
are deterministic. They do not fix speech governance: the module
cannot tell whether a reason code was honestly chosen, whether a
restriction basis was truthful, whether appeal statistics cover the
real population, or whether a dialect baseline was representative.
It proves the paperwork is consistent, not that the moderation was
just.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest comparisons
via :func:`hmac.compare_digest`.
"""

from __future__ import annotations
from _domain_base import DomainError

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODERATION_SCHEMA_VERSION = "northstar.moderation-agents.v1"

#: Closed decision-kind vocabulary. ``visibility_reduction`` covers
#: shadowbans: courts ruled they fall under DSA Art. 17 statements of
#: reasons — "scale" is no exemption.
DECISION_KINDS: tuple[str, ...] = (
    "removal",
    "visibility_reduction",
    "account_suspension",
    "label_applied",
    "appeal_upheld",
    "appeal_restored",
)

#: Closed severity tiers (highest first). Only the highest tier may be
#: fully-automated-removed: ``SEVERITY_TIER_1`` covers imminent harm
#: (terrorism, CSAM, imminent violence); lower tiers must go through
#: human review or user-report triage (Meta 2026 severity-ceiling
#: lesson).
SEVERITY_TIER_1 = "tier_1_imminent"
SEVERITY_TIER_2 = "tier_2_high"
SEVERITY_TIER_3 = "tier_3_medium"
SEVERITY_TIER_4 = "tier_4_low"
SEVERITY_TIERS: tuple[str, ...] = (
    SEVERITY_TIER_1,
    SEVERITY_TIER_2,
    SEVERITY_TIER_3,
    SEVERITY_TIER_4,
)

#: Closed decision-mode vocabulary.
MODE_FULLY_AUTOMATED = "fully_automated"
MODE_HUMAN_REVIEW = "human_review"
MODE_USER_REPORT_TRIAGE = "user_report_triage"
DECISION_MODES: tuple[str, ...] = (
    MODE_FULLY_AUTOMATED,
    MODE_HUMAN_REVIEW,
    MODE_USER_REPORT_TRIAGE,
)

#: Closed moderation-reason vocabulary (high-level categories only;
#: the "why this video" lesson — categories are a floor, and the
#: explanation must bind the decision digest to be more than a
#: category).
MODERATION_REASONS: tuple[str, ...] = (
    "terrorism",
    "csam",
    "imminent_violence",
    "hate_conduct",
    "harassment",
    "misinformation",
    "spam",
    "graphic_content",
    "copyright",
    "regulated_goods",
    "domestic_legal_order",
    "other_policy",
)

#: Over-removal tolerance: appeal-restoration rate above this over a
#: declared registry triggers an audit classification. A
#: *bench-calibrated parameter*, not a law of nature — the TikTok
#: appeal-restoration volumes are a mis-removal *lower bound*, not a
#: fitted rate.
OVERREMOVAL_TOLERANCE = 0.05

#: Dialect-parity tolerance: maximum allowed absolute false-positive-
#: rate disparity between the worst-tested dialect and the baseline
#: dialect before deployment is blocked.
DIALECT_FP_DISPARITY_MAX = 0.05

#: Amplification-audit clock: maximum seconds between completed
#: rabbit-hole amplification audits.
AMPLIFICATION_AUDIT_WINDOW_S = 90 * 86400

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

MOD_EVENT_STATEMENT = "moderation.statement_of_reasons"
MOD_EVENT_NO_STATEMENT = "moderation.no_statement_of_reasons"
MOD_EVENT_OVERREMOVAL = "moderation.overremoval_audit"
MOD_EVENT_DIALECT_BIAS = "moderation.dialect_bias"
MOD_EVENT_AUTO_OVERREACH = "moderation.auto_overreach"
MOD_EVENT_NO_NON_PROFILING = "moderation.no_non_profiling_option"
MOD_EVENT_UNDISCLOSED_RESTRICTION = "moderation.undisclosed_restriction"
MOD_EVENT_FACTCHECK_SUBSTITUTION = "moderation.factcheck_substitution"
MOD_EVENT_UNLABELED_AIGC = "moderation.unlabeled_aigc"
MOD_EVENT_AMPLIFICATION_OVERDUE = "moderation.amplification_audit_overdue"

_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class ModerationError(DomainError):
    """Raised when a moderation-discipline field or receipt is malformed."""


@dataclass(frozen=True)
class ModerationVerdict:
    """Outcome of one moderation-discipline check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> ModerationVerdict:
    return ModerationVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> ModerationVerdict:
    return ModerationVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


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
        raise ModerationError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise ModerationError(f"{field_name} must be a 128-char hex Ed25519 signature")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ModerationError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ModerationError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed.
    if not isinstance(value, bytes) or len(value) != 32:
        raise ModerationError(f"{field_name} must be a 32-byte seed")
    return value


def _check_vocab(value: Any, field_name: str, vocab: tuple[str, ...]) -> str:
    if value not in vocab:
        raise ModerationError(f"{field_name} must be one of {vocab}, got {value!r}")
    return value


def _pubkey_from_secret(secret: bytes) -> str:
    return ed25519.public_key(secret).hex()


def _signature_payload(body: Mapping[str, Any]) -> bytes:
    # jcs_canonical_json returns bytes (UTF-8 RFC 8785 canonical bytes).
    return jcs_canonical_json(body)


def _verify_signature(pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str) -> bool:
    try:
        return bool(
            ed25519.verify(
                bytes.fromhex(pubkey_hex),
                _signature_payload(payload),
                bytes.fromhex(signature_hex),
            )
        )
    except Exception:
        return False


def _digest_receipt(body: Mapping[str, Any]) -> str:
    return jcs_sha256_hex({"schema": MODERATION_SCHEMA_VERSION, "body": dict(body)})


# ---------------------------------------------------------------------------
# 1. Statements of reasons (DSA Art. 17 style; shadowbans included)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StatementOfReasonsReceipt:
    """Art-17-style reason receipt bound to one enforcement decision.

    Every removal/restriction — including ``visibility_reduction``
    (shadowbans) — must bind a live receipt naming the content, the
    decision kind, the closed-vocabulary reason, and the issuer.
    "Scale" is no exemption (X court lesson).
    """

    receipt_id: str
    content_id: str
    decision_kind: str
    reason_code: str
    issued_by: str
    authority_pubkey: str
    issued_at: int
    expires_at: int
    signature: str
    decision_digest: str


def statement_of_reasons(
    *,
    receipt_id: str,
    content_id: str,
    decision_kind: str,
    reason_code: str,
    issued_by: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    decision_digest: str,
) -> StatementOfReasonsReceipt:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(content_id, "content_id")
    _check_vocab(decision_kind, "decision_kind", DECISION_KINDS)
    _check_vocab(reason_code, "reason_code", MODERATION_REASONS)
    _check_nonempty_str(issued_by, "issued_by")
    _check_secret(authority_secret, "authority_secret")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise ModerationError("expires_at must be after issued_at")
    _check_hex64(decision_digest, "decision_digest")
    body = {
        "receipt_id": receipt_id,
        "content_id": content_id,
        "decision_kind": decision_kind,
        "reason_code": reason_code,
        "issued_by": issued_by,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "decision_digest": decision_digest,
    }
    signature = ed25519.sign(authority_secret, _signature_payload(body)).hex()
    return StatementOfReasonsReceipt(
        receipt_id=receipt_id,
        content_id=content_id,
        decision_kind=decision_kind,
        reason_code=reason_code,
        issued_by=issued_by,
        authority_pubkey=_pubkey_from_secret(authority_secret),
        issued_at=issued_at,
        expires_at=expires_at,
        signature=signature,
        decision_digest=decision_digest,
    )


def _receipt_live_at(receipt: StatementOfReasonsReceipt, now: int) -> bool:
    return receipt.issued_at <= now < receipt.expires_at


def check_statement_of_reasons(
    receipt: StatementOfReasonsReceipt | None,
    *,
    now: int,
    content_id: str,
    decision_digest: str,
) -> ModerationVerdict:
    """Every enforcement decision must carry a live reason receipt."""
    _check_ts(now, "now")
    _check_nonempty_str(content_id, "content_id")
    _check_hex64(decision_digest, "decision_digest")
    if receipt is None:
        return _deny(MOD_EVENT_NO_STATEMENT, "no statement-of-reasons receipt bound to decision")
    if not _receipt_live_at(receipt, now):
        return _deny(MOD_EVENT_NO_STATEMENT, "statement-of-reasons receipt not live")
    body = {
        "receipt_id": receipt.receipt_id,
        "content_id": receipt.content_id,
        "decision_kind": receipt.decision_kind,
        "reason_code": receipt.reason_code,
        "issued_by": receipt.issued_by,
        "issued_at": receipt.issued_at,
        "expires_at": receipt.expires_at,
        "decision_digest": receipt.decision_digest,
    }
    if not _verify_signature(receipt.authority_pubkey, body, receipt.signature):
        return _deny(MOD_EVENT_NO_STATEMENT, "statement-of-reasons signature invalid")
    if not hmac.compare_digest(receipt.content_id, content_id):
        return _deny(MOD_EVENT_NO_STATEMENT, "receipt content_id does not match decision")
    if not hmac.compare_digest(receipt.decision_digest, decision_digest):
        return _deny(MOD_EVENT_NO_STATEMENT, "receipt does not bind this decision digest")
    return _allow(
        f"{MOD_EVENT_STATEMENT}: {receipt.decision_kind}/{receipt.reason_code}",
        _digest_receipt(body),
    )


# ---------------------------------------------------------------------------
# 2. Over-removal probe (appeal-restoration rate)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OverremovalRegistry:
    """Declared decision registry for the over-removal probe.

    ``decisions`` and ``appeal_restored`` are *declared* sample counts;
    the probe audits the declared numbers, it cannot observe
    unappealed mis-removals. Appeal-restoration is a mis-removal
    *lower bound* (TikTok Iraq 157K / Egypt 146K lesson).
    """

    registry_id: str
    decisions: int
    appeals: int
    appeal_restored: int
    declared_at: int


def overremoval_probe(registry: OverremovalRegistry, *, tolerance: float = OVERREMOVAL_TOLERANCE) -> ModerationVerdict:
    """Restoration rate above tolerance classifies over-removal-audit."""
    _check_nonempty_str(registry.registry_id, "registry_id")
    _check_ts(registry.declared_at, "declared_at")
    for name in ("decisions", "appeals", "appeal_restored"):
        count = getattr(registry, name)
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ModerationError(f"{name} must be a non-negative int")
    if registry.appeals > registry.decisions:
        raise ModerationError("appeals cannot exceed decisions")
    if registry.appeal_restored > registry.appeals:
        raise ModerationError("appeal_restored cannot exceed appeals")
    if not isinstance(tolerance, (int, float)) or tolerance <= 0 or tolerance >= 1:
        raise ModerationError("tolerance must be in (0, 1)")
    if registry.appeals == 0:
        return _allow("overremoval probe: no appeals in declared registry")
    rate = registry.appeal_restored / registry.appeals
    if rate > tolerance:
        return _deny(
            MOD_EVENT_OVERREMOVAL,
            f"appeal-restoration rate {rate:.3f} above tolerance {tolerance:.3f} "
            f"({registry.appeal_restored}/{registry.appeals}) — audit required",
        )
    return _allow(f"overremoval probe: restoration rate {rate:.3f} within tolerance")


# ---------------------------------------------------------------------------
# 3. Dialect parity gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DialectParityReport:
    """Declared dialect parity test report.

    Maps dialect name -> (false_positives, evaluated_items). The gate
    compares the worst dialect's false-positive rate against the
    baseline dialect; systematic disparity denies deployment
    (MDPI 2026 Arabic-dialect false-positive lesson; EMNLP 2026
    dialect-discrimination lesson).
    """

    report_id: str
    baseline_dialect: str
    fp_counts: tuple[tuple[str, int, int], ...]
    tested_at: int


def check_dialect_parity(
    report: DialectParityReport,
    *,
    max_disparity: float = DIALECT_FP_DISPARITY_MAX,
) -> ModerationVerdict:
    """Dialect parity required before enforcement deployment."""
    _check_nonempty_str(report.report_id, "report_id")
    _check_nonempty_str(report.baseline_dialect, "baseline_dialect")
    _check_ts(report.tested_at, "tested_at")
    if not report.fp_counts:
        raise ModerationError("fp_counts must be non-empty")
    rates: dict[str, float] = {}
    for dialect, fp, total in report.fp_counts:
        _check_nonempty_str(dialect, "dialect")
        for name, count in (("false_positives", fp), ("evaluated_items", total)):
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ModerationError(f"{name} must be a non-negative int")
        if total == 0:
            raise ModerationError("evaluated_items must be > 0")
        if fp > total:
            raise ModerationError("false_positives cannot exceed evaluated_items")
        if dialect in rates:
            raise ModerationError(f"duplicate dialect entry: {dialect}")
        rates[dialect] = fp / total
    if report.baseline_dialect not in rates:
        raise ModerationError("baseline_dialect not in fp_counts")
    if not isinstance(max_disparity, (int, float)) or max_disparity < 0 or max_disparity >= 1:
        raise ModerationError("max_disparity must be in [0, 1)")
    baseline_rate = rates[report.baseline_dialect]
    worst_dialect = max(rates, key=lambda d: rates[d])
    disparity = rates[worst_dialect] - baseline_rate
    if disparity > max_disparity:
        return _deny(
            MOD_EVENT_DIALECT_BIAS,
            f"dialect FP disparity {disparity:.3f} ({worst_dialect}={rates[worst_dialect]:.3f} "
            f"vs baseline {report.baseline_dialect}={baseline_rate:.3f}) exceeds {max_disparity:.3f}",
        )
    return _allow(
        f"dialect parity: worst disparity {disparity:.3f} within {max_disparity:.3f}",
        _digest_receipt({"report_id": report.report_id, "rates": rates}),
    )


# ---------------------------------------------------------------------------
# 4. Automation severity ceiling
# ---------------------------------------------------------------------------


def check_automation_ceiling(*, severity: str, decision_mode: str) -> ModerationVerdict:
    """Fully-automated removal is limited to the highest severity tier.

    Lower-severity fully-automated removal denies as
    ``moderation.auto_overreach`` (Meta 2026 severity-ceiling lesson).
    """
    _check_vocab(severity, "severity", SEVERITY_TIERS)
    _check_vocab(decision_mode, "decision_mode", DECISION_MODES)
    if decision_mode == MODE_FULLY_AUTOMATED and severity != SEVERITY_TIER_1:
        return _deny(
            MOD_EVENT_AUTO_OVERREACH,
            f"fully-automated removal at {severity} — only {SEVERITY_TIER_1} may be fully automated",
        )
    return _allow(f"automation ceiling: {decision_mode} at {severity}")


# ---------------------------------------------------------------------------
# 5. Non-profiling recommender option
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecommenderConfig:
    """Declared recommender configuration.

    A non-profiling option must exist for users (2026-10-02 EU
    recommender-data lesson).
    """

    recommender_id: str
    has_non_profiling_option: bool
    non_profiling_option_id: str
    declared_at: int


def check_non_profiling_option(config: RecommenderConfig) -> ModerationVerdict:
    _check_nonempty_str(config.recommender_id, "recommender_id")
    _check_ts(config.declared_at, "declared_at")
    if not config.has_non_profiling_option:
        return _deny(
            MOD_EVENT_NO_NON_PROFILING,
            f"recommender {config.recommender_id} declares no non-profiling option",
        )
    _check_nonempty_str(config.non_profiling_option_id, "non_profiling_option_id")
    return _allow(
        f"recommender {config.recommender_id} offers non-profiling option "
        f"{config.non_profiling_option_id}",
        _digest_receipt(
            {
                "recommender_id": config.recommender_id,
                "non_profiling_option_id": config.non_profiling_option_id,
            }
        ),
    )


# ---------------------------------------------------------------------------
# 6. Legal-restriction receipts (per-post country+basis disclosure)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LegalRestrictionReceipt:
    """Per-post legal restriction with country + basis disclosure.

    Mirrors X's "Under the Hood" disclosure: every legal restriction
    binds the country and the legal basis. The gate checks receipt
    consistency, not the truth of the basis (Oversight Board lesson on
    LLMs replicating speech-restrictive domestic law).
    """

    receipt_id: str
    content_id: str
    country_code: str
    legal_basis: str
    restricted_at: int
    expires_at: int
    authority_pubkey: str
    signature: str


def legal_restriction_receipt(
    *,
    receipt_id: str,
    content_id: str,
    country_code: str,
    legal_basis: str,
    restricted_at: int,
    expires_at: int,
    authority_secret: bytes,
) -> LegalRestrictionReceipt:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(content_id, "content_id")
    _check_nonempty_str(country_code, "country_code")
    _check_nonempty_str(legal_basis, "legal_basis")
    _check_ts(restricted_at, "restricted_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= restricted_at:
        raise ModerationError("expires_at must be after restricted_at")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "content_id": content_id,
        "country_code": country_code,
        "legal_basis": legal_basis,
        "restricted_at": restricted_at,
        "expires_at": expires_at,
    }
    signature = ed25519.sign(authority_secret, _signature_payload(body)).hex()
    return LegalRestrictionReceipt(
        receipt_id=receipt_id,
        content_id=content_id,
        country_code=country_code,
        legal_basis=legal_basis,
        restricted_at=restricted_at,
        expires_at=expires_at,
        authority_pubkey=_pubkey_from_secret(authority_secret),
        signature=signature,
    )


def check_legal_restriction(
    receipt: LegalRestrictionReceipt | None,
    *,
    now: int,
    content_id: str,
) -> ModerationVerdict:
    """A legal restriction without a disclosed country+basis denies."""
    _check_ts(now, "now")
    _check_nonempty_str(content_id, "content_id")
    if receipt is None:
        return _deny(
            MOD_EVENT_UNDISCLOSED_RESTRICTION,
            "legal restriction without country+basis disclosure receipt",
        )
    if not (receipt.restricted_at <= now < receipt.expires_at):
        return _deny(MOD_EVENT_UNDISCLOSED_RESTRICTION, "legal-restriction receipt not live")
    body = {
        "receipt_id": receipt.receipt_id,
        "content_id": receipt.content_id,
        "country_code": receipt.country_code,
        "legal_basis": receipt.legal_basis,
        "restricted_at": receipt.restricted_at,
        "expires_at": receipt.expires_at,
    }
    if not _verify_signature(receipt.authority_pubkey, body, receipt.signature):
        return _deny(MOD_EVENT_UNDISCLOSED_RESTRICTION, "legal-restriction signature invalid")
    if not hmac.compare_digest(receipt.content_id, content_id):
        return _deny(MOD_EVENT_UNDISCLOSED_RESTRICTION, "receipt content_id mismatch")
    return _allow(
        f"legal restriction disclosed: {receipt.country_code}/{receipt.legal_basis}",
        _digest_receipt(body),
    )


# ---------------------------------------------------------------------------
# 7. "Why this content" explanations
# ---------------------------------------------------------------------------


def why_this_content(*, decision_digest: str, explanation: str) -> bytes:
    """Bind a "why this content" explanation to a decision digest.

    Returns the JCS-canonical binding bytes. High-level categories
    alone ("why this video") are a floor: the explanation must bind
    the decision digest to count as more than a category label.
    """
    _check_hex64(decision_digest, "decision_digest")
    _check_nonempty_str(explanation, "explanation")
    return jcs_canonical_json(
        {"schema": MODERATION_SCHEMA_VERSION, "kind": "why-this-content",
         "decision_digest": decision_digest, "explanation": explanation}
    )


def check_why_this_content(
    binding: bytes | None, *, decision_digest: str, explanation: str
) -> ModerationVerdict:
    """Missing or mismatched explanation degrades to non_authoritative."""
    _check_hex64(decision_digest, "decision_digest")
    if binding is None or not binding.strip():
        return ModerationVerdict(
            allowed=True,
            reason="why-this-content: no explanation bound — decision degrades to "
            "non_authoritative",
            classification=CLASS_NON_AUTHORITATIVE,
        )
    expected = why_this_content(decision_digest=decision_digest, explanation=explanation)
    if not hmac.compare_digest(binding, expected):
        return ModerationVerdict(
            allowed=True,
            reason="why-this-content: explanation does not bind this decision digest — "
            "decision degrades to non_authoritative",
            classification=CLASS_NON_AUTHORITATIVE,
        )
    return _allow(
        "why-this-content: explanation binds decision digest",
        hashlib.sha256(binding).hexdigest(),
    )


# ---------------------------------------------------------------------------
# 8. Fact-checking non-substitution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FactcheckProgram:
    """Declared integrity program for civic/election content.

    Crowdsourced notes may *supplement* but may not *substitute*
    professional fact-checking on civic/election content (Oversight
    Board 2x opposition lesson).
    """

    program_id: str
    scope_civic: bool
    professional_factcheck_program: bool
    crowdsourced_notes: bool
    notes_replaced_professional: bool
    declared_at: int


def check_factcheck_non_substitution(program: FactcheckProgram) -> ModerationVerdict:
    _check_nonempty_str(program.program_id, "program_id")
    _check_ts(program.declared_at, "declared_at")
    if program.scope_civic and program.notes_replaced_professional:
        if not program.professional_factcheck_program:
            return _deny(
                MOD_EVENT_FACTCHECK_SUBSTITUTION,
                f"program {program.program_id}: crowdsourced notes substituted professional "
                "fact-checking on civic content without a professional program",
            )
        return _deny(
            MOD_EVENT_FACTCHECK_SUBSTITUTION,
            f"program {program.program_id}: crowdsourced notes replaced professional "
            "fact-checking on civic content",
        )
    return _allow(
        f"factcheck program {program.program_id}: notes supplement, not substitute",
        _digest_receipt({"program_id": program.program_id}),
    )


# ---------------------------------------------------------------------------
# 9. AIGC label binding (cross-platform source labels)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AIGCLabelReceipt:
    """Cross-platform source label for AI-generated content.

    Binds the content digest to an AI-generation source label
    (EU AI Act Art. 50 machine-readable marking; 抖音 AI-content
    "digital ID" lesson).
    """

    receipt_id: str
    content_digest: str
    ai_generated: bool
    generator_id: str
    labeled_at: int
    labeler_pubkey: str
    signature: str


def aigc_label_receipt(
    *,
    receipt_id: str,
    content_digest: str,
    ai_generated: bool,
    generator_id: str,
    labeled_at: int,
    labeler_secret: bytes,
) -> AIGCLabelReceipt:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_hex64(content_digest, "content_digest")
    if not isinstance(ai_generated, bool):
        raise ModerationError("ai_generated must be bool")
    if ai_generated:
        _check_nonempty_str(generator_id, "generator_id (required when ai_generated)")
    _check_ts(labeled_at, "labeled_at")
    _check_secret(labeler_secret, "labeler_secret")
    body = {
        "receipt_id": receipt_id,
        "content_digest": content_digest,
        "ai_generated": ai_generated,
        "generator_id": generator_id,
        "labeled_at": labeled_at,
    }
    signature = ed25519.sign(labeler_secret, _signature_payload(body)).hex()
    return AIGCLabelReceipt(
        receipt_id=receipt_id,
        content_digest=content_digest,
        ai_generated=ai_generated,
        generator_id=generator_id,
        labeled_at=labeled_at,
        labeler_pubkey=_pubkey_from_secret(labeler_secret),
        signature=signature,
    )


def check_aigc_label(
    receipt: AIGCLabelReceipt | None, *, content_digest: str, ai_generated: bool
) -> ModerationVerdict:
    """AI-generated content without a source-label receipt denies."""
    _check_hex64(content_digest, "content_digest")
    if not isinstance(ai_generated, bool):
        raise ModerationError("ai_generated must be bool")
    if not ai_generated:
        return _allow("aigc: content not AI-generated, no label required")
    if receipt is None:
        return _deny(
            MOD_EVENT_UNLABELED_AIGC,
            "AI-generated content without cross-platform source-label receipt",
        )
    if not receipt.ai_generated:
        return _deny(MOD_EVENT_UNLABELED_AIGC, "label receipt does not mark content as AI-generated")
    if not receipt.generator_id.strip():
        return _deny(MOD_EVENT_UNLABELED_AIGC, "label receipt missing generator_id")
    body = {
        "receipt_id": receipt.receipt_id,
        "content_digest": receipt.content_digest,
        "ai_generated": receipt.ai_generated,
        "generator_id": receipt.generator_id,
        "labeled_at": receipt.labeled_at,
    }
    if not _verify_signature(receipt.labeler_pubkey, body, receipt.signature):
        return _deny(MOD_EVENT_UNLABELED_AIGC, "aigc label signature invalid")
    if not hmac.compare_digest(receipt.content_digest, content_digest):
        return _deny(MOD_EVENT_UNLABELED_AIGC, "aigc label content_digest mismatch")
    return _allow(
        f"aigc labeled: {receipt.generator_id}",
        _digest_receipt(body),
    )


# ---------------------------------------------------------------------------
# 10. Amplification audit clock
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AmplificationAuditReceipt:
    """Rabbit-hole amplification audit receipt.

    Recommender amplification audits run on a clock; an overdue audit
    denies (EP interim-measures-on-engagement-algorithms lesson).
    """

    audit_id: str
    recommender_id: str
    completed_at: int
    auditor_pubkey: str
    signature: str
    findings_digest: str


def amplification_audit_receipt(
    *,
    audit_id: str,
    recommender_id: str,
    completed_at: int,
    findings_digest: str,
    auditor_secret: bytes,
) -> AmplificationAuditReceipt:
    _check_nonempty_str(audit_id, "audit_id")
    _check_nonempty_str(recommender_id, "recommender_id")
    _check_ts(completed_at, "completed_at")
    _check_hex64(findings_digest, "findings_digest")
    _check_secret(auditor_secret, "authority_secret")
    body = {
        "audit_id": audit_id,
        "recommender_id": recommender_id,
        "completed_at": completed_at,
        "findings_digest": findings_digest,
    }
    signature = ed25519.sign(auditor_secret, _signature_payload(body)).hex()
    return AmplificationAuditReceipt(
        audit_id=audit_id,
        recommender_id=recommender_id,
        completed_at=completed_at,
        auditor_pubkey=_pubkey_from_secret(auditor_secret),
        signature=signature,
        findings_digest=findings_digest,
    )


def check_amplification_clock(
    receipt: AmplificationAuditReceipt | None,
    *,
    now: int,
    window_s: int = AMPLIFICATION_AUDIT_WINDOW_S,
) -> ModerationVerdict:
    """An overdue amplification audit denies."""
    _check_ts(now, "now")
    if not isinstance(window_s, int) or isinstance(window_s, bool) or window_s <= 0:
        raise ModerationError("window_s must be a positive int")
    if receipt is None:
        return _deny(
            MOD_EVENT_AMPLIFICATION_OVERDUE,
            "no amplification audit on record — audit overdue",
        )
    body = {
        "audit_id": receipt.audit_id,
        "recommender_id": receipt.recommender_id,
        "completed_at": receipt.completed_at,
        "findings_digest": receipt.findings_digest,
    }
    if not _verify_signature(receipt.auditor_pubkey, body, receipt.signature):
        return _deny(MOD_EVENT_AMPLIFICATION_OVERDUE, "amplification audit signature invalid")
    if receipt.completed_at > now:
        return _deny(MOD_EVENT_AMPLIFICATION_OVERDUE, "amplification audit timestamp in the future")
    if now - receipt.completed_at > window_s:
        return _deny(
            MOD_EVENT_AMPLIFICATION_OVERDUE,
            f"amplification audit {now - receipt.completed_at}s old, window {window_s}s",
        )
    return _allow(
        f"amplification audit fresh: {receipt.recommender_id}",
        _digest_receipt(body),
    )


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

__all__ = [
    "MODERATION_SCHEMA_VERSION",
    "DECISION_KINDS",
    "SEVERITY_TIERS",
    "SEVERITY_TIER_1",
    "SEVERITY_TIER_2",
    "SEVERITY_TIER_3",
    "SEVERITY_TIER_4",
    "DECISION_MODES",
    "MODE_FULLY_AUTOMATED",
    "MODE_HUMAN_REVIEW",
    "MODE_USER_REPORT_TRIAGE",
    "MODERATION_REASONS",
    "OVERREMOVAL_TOLERANCE",
    "DIALECT_FP_DISPARITY_MAX",
    "AMPLIFICATION_AUDIT_WINDOW_S",
    "CLASS_AUTHORITATIVE",
    "CLASS_NON_AUTHORITATIVE",
    "MOD_EVENT_STATEMENT",
    "MOD_EVENT_NO_STATEMENT",
    "MOD_EVENT_OVERREMOVAL",
    "MOD_EVENT_DIALECT_BIAS",
    "MOD_EVENT_AUTO_OVERREACH",
    "MOD_EVENT_NO_NON_PROFILING",
    "MOD_EVENT_UNDISCLOSED_RESTRICTION",
    "MOD_EVENT_FACTCHECK_SUBSTITUTION",
    "MOD_EVENT_UNLABELED_AIGC",
    "MOD_EVENT_AMPLIFICATION_OVERDUE",
    "ModerationError",
    "ModerationVerdict",
    "StatementOfReasonsReceipt",
    "statement_of_reasons",
    "check_statement_of_reasons",
    "OverremovalRegistry",
    "overremoval_probe",
    "DialectParityReport",
    "check_dialect_parity",
    "check_automation_ceiling",
    "RecommenderConfig",
    "check_non_profiling_option",
    "LegalRestrictionReceipt",
    "legal_restriction_receipt",
    "check_legal_restriction",
    "why_this_content",
    "check_why_this_content",
    "FactcheckProgram",
    "check_factcheck_non_substitution",
    "AIGCLabelReceipt",
    "aigc_label_receipt",
    "check_aigc_label",
    "AmplificationAuditReceipt",
    "amplification_audit_receipt",
    "check_amplification_clock",
]
