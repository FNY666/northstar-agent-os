"""Defense & dual-use AI discipline gates (one-hundred-sixty-fifth batch).

Absorbs the 2026 defense-AI research thread (public sources only):

* **US Replicator ($1B)** — mass procurement of cheap autonomous
  systems; Swarm Forge requires a field-verifiable swarm package 90
  days after request; "Crucible" tests demanded multi-vendor drones in
  GPS-denied conditions with AI target recognition ("adaptive
  confidence thresholds") and swarm role allocation while humans kept
  only "meaningful command" with "minimal operator intervention".
* **Minab school strike (UN fact-finding 2026-09-17)** — a school was
  hit because an outdated intel database still listed it as an IRGC
  naval facility (it had been a school since 2015); 157+ dead. The UN
  found no feasible pre-strike verification — a war crime of
  indiscriminate attack. Bloomberg: CENTCOM staff over-relied on AI
  (Palantir Maven Smart System), expected the system to flag stale
  intel, and the civilian-protection team had been cut from 10 to 1.
* **Anthropic FASCSA blacklisting (2026-02; D.C. Circuit upheld
  2026-09-25)** — the Pentagon designated Anthropic a supply-chain
  risk after it refused "all lawful purposes" and kept two redlines
  (fully-autonomous lethal weapons; mass surveillance of US
  citizens). The court held that vendor-built purpose restrictions =
  a statutory "national security risk". Corporate ethics redlines lost
  to procurement power.
* **Geneva CCW (2026-08-31~09-05)** — 128 states reached a
  non-binding document, but US-Russia negotiators deleted
  "predictable"/"reliable", ethics considerations, and the pre-strike
  human review of AI-generated targets. The next decision point is
  the November 2026 Review Conference.
* **Payne 2026 sims** — in 21 simulated conflicts, 95% saw at least
  one tactical-nuclear deployment; 86% escalated beyond the models'
  own stated intent. "The nuclear taboo is weaker for machines."
* **CNN investigation (2026-09, via NDTV retell)** — an AI chatbot
  fabricated intel about a Chinese ship carrying nuclear-parts; the
  report was formalized and circulated, aircraft were airborne and a
  boarding team staged before a last-minute human review killed it.
  "Nearly started a war."
* **Venezuela 2026-01-03 operation** — court records show Claude was
  used in the operation, against the vendor's own usage policy
  (single-source press account).

Scope: this module governs AI decision-support tooling and dual-use
safeguards. It is accountability instrumentation — signed receipts
that bind declared discipline — not weapons-operations software.
Northstar does no kill-chain decision support and connects to no
weapons systems; that is part of the declared applicability domain.

Fail-closed rules over signed receipts:

1. AI-generated decision-support outputs execute only behind a human
   substantive-review receipt with a minimum deliberation time.
   Checkbox review (deliberation below the floor) or missing review
   denies with ``defense.checkbox_review`` / ``defense.rubber_stamp``
   (Geneva pre-strike-review lesson).
2. Targeting intelligence binds data freshness: intel past its
   freshness window without revalidation is ``NON_AUTHORITATIVE``
   and denies with ``defense.stale_intel`` (Minab lesson — the AI may
   not be expected to catch stale data on the operator's behalf).
3. The operator-reliance monitor probes acceptance-rate and
   deliberation-time anomalies; a bias pattern denies with
   ``defense.automation_bias`` and forces sampled human review
   (Maven over-reliance lesson).
4. Civilian-protection staffing binds a floor: reductions below the
   minimum deny with ``defense.protection_floor_breach`` (10-to-1
   lesson).
5. Supplier redline clauses (no fully-autonomous lethal weapons, no
   mass citizen surveillance, no unlawful targeting) exist as
   contract terms; procurement demands to remove them bind a public
   disclosure receipt, silent removal denies with
   ``defense.silent_redline_removal`` (Anthropic lesson).
6. AI-generated intel reports bind an "AI-generated" watermark plus
   an evidence digest per key assertion; assertions without evidence
   are ``UNVERIFIED`` and blocked from the action-approval flow with
   ``defense.unverified_assertion`` (CNN-ship lesson).
7. Escalation ladders lock nuclear options by default (multi-level
   human authorization + cooling period); adversarial escalation
   regression tests run on a clock, and a nuke-deployment fraction
   above tolerance denies with
   ``defense.escalation_regression_failed`` (Payne lesson).
8. Decision-cycle compression beyond the alert ratio binds a
   commander acknowledgment; unacknowledged compression denies with
   ``defense.compression_unacknowledged`` (algorithmic-warfare
   lesson).
9. Vendor cutoff (FASCSA-style removal) binds a notification
   receipt plus a transition clock; silent cutoffs deny with
   ``defense.silent_vendor_cutoff``.
10. Treaty-position drift is clocked: a treaty in force whose system
    constraints were not updated denies with ``defense.treaty_drift``
    (CCW lesson).
11. "Minimal operator intervention" must be quantified: the swarm
    config binds operator:platform ratio, confidence thresholds, and
    an adaptive-threshold change log; silent threshold lowering
    denies with ``defense.threshold_drift`` (Replicator lesson).

Honest scoping: receipts bind *declared* defense-tooling discipline
— digests recompute, signatures verify, chains link. They do not
prevent wars, they do not substitute for international humanitarian
law, and they do not answer who is accountable for an algorithmic
killing. They are accountability instrumentation, not safety
guarantees.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th-batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest comparisons
via :func:`hmac.compare_digest`. Signature verification honors the
boolean return of ``ed25519.verify`` (which never raises — the
147th-batch finding).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

try:  # ninety-fifth batch: the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()

try:
    import ed25519
except Exception:  # pragma: no cover - vendored module is always present
    ed25519 = None  # type: ignore[assignment]


DEFENSE_SCHEMA_VERSION = "northstar.defense.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_DAY_S = 86_400

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Closed vocabulary for supplier redline clauses (Anthropic lesson).
REDLINE_KINDS: tuple[str, ...] = (
    "no_full_autonomous_lethal",
    "no_mass_citizen_surveillance",
    "no_unlawful_targeting",
)

#: Automation-bias probe thresholds: sustained AI acceptance at or
#: above this ratio with mean deliberation below the floor forces
#: sampled human review (Maven over-reliance lesson).
BIAS_ACCEPTANCE_RATIO = 0.90
BIAS_DELIBERATION_FLOOR_S = 60

#: Escalation regression: the largest nuke-deployment fraction over a
#: simulation batch that still passes (Payne 2026 measured ~0.95).
ESCALATION_MAX_NUKE_FRACTION = 0.50

#: Decision-compression alert ratio: baseline/current cycle time at or
#: above this requires a commander acknowledgment receipt.
COMPRESSION_ALERT_RATIO = 10

#: Swarm command: maximum platforms per operator ("meaningful command"
#: must be quantified, not asserted).
MAX_PLATFORMS_PER_OPERATOR = 8


class DefenseError(ValueError):
    """A malformed defense receipt or a programming error.

    Raised for structural problems (bad digests, unknown clauses,
    inverted timestamps). Verification *failures* (stale intel,
    checkbox review, silent redline removal) return a
    :class:`DefenseVerdict` with ``allowed=False`` instead — a failed
    gate is a verdict, a malformed receipt is a bug.
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
        raise DefenseError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_hex64_or_empty(value: Any, field_name: str) -> str:
    if value == "":
        return ""
    return _check_hex64(value, field_name)


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DefenseError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise DefenseError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed.
    if not isinstance(value, bytes) or len(value) != 32:
        raise DefenseError(f"{field_name} must be a 32-byte seed")
    return value


def _check_vocab(value: Any, field_name: str, vocab: tuple[str, ...]) -> str:
    if value not in vocab:
        raise DefenseError(f"{field_name} must be one of {vocab}, got {value!r}")
    return value


def _check_nonneg_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise DefenseError(f"{field_name} must be a non-negative int")
    return value


def _check_positive_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise DefenseError(f"{field_name} must be a positive int")
    return value


def _check_ratio(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DefenseError(f"{field_name} must be a number")
    if not 0.0 <= value <= 1.0:
        raise DefenseError(f"{field_name} must be within [0, 1]")
    return float(value)


def _pubkey_from_secret(secret: bytes) -> str:
    return ed25519.public_key(secret).hex()


def _signature_payload(body: Mapping[str, Any]) -> bytes:
    return jcs_canonical_json(body)


def _verify_signature(pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str) -> bool:
    # The vendored ed25519.verify() returns a bool and never raises;
    # the return value must be honored (the old try/except-around-verify
    # pattern silently approved everything — the 147th-batch finding).
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
    return jcs_sha256_hex({"schema": DEFENSE_SCHEMA_VERSION, "body": dict(body)})


def _signed_body(receipt: Any) -> dict[str, Any]:
    """The signed subset of a receipt payload (excludes authority_pubkey).

    The signer commits to the receipt's claims, not to its own key —
    the same convention as moderation_agents. ``_payload()`` (with the
    key) is what the receipt *digest* covers.
    """
    return {k: v for k, v in receipt._payload().items() if k != "authority_pubkey"}


def _sign_receipt(body: Mapping[str, Any], authority_secret: bytes) -> tuple[str, str]:
    """Return (authority_pubkey_hex, signature_hex) for a receipt body."""
    payload = dict(body)
    pubkey_hex = _pubkey_from_secret(authority_secret)
    sig_hex = ed25519.sign(authority_secret, _signature_payload(payload)).hex()
    return pubkey_hex, sig_hex


@dataclass(frozen=True)
class DefenseVerdict:
    """Outcome of one defense-discipline gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> DefenseVerdict:
    return DefenseVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> DefenseVerdict:
    return DefenseVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


# ---------------------------------------------------------------------------
# 1. Substantive human review (Geneva pre-strike-review lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HumanReviewReceipt:
    """Substantive human review of an AI-generated decision-support output.

    Review must be substantive, not a checkbox: the receipt binds the
    output digest, the reviewer's identity, the actual deliberation
    time in seconds, and a basis-summary digest. Deliberation below the
    declared minimum is a rubber stamp, not a review (ICRC warning).
    """

    receipt_id: str
    output_id: str
    output_digest: str
    reviewer_id: str
    review_basis_digest: str
    min_deliberation_s: int
    deliberation_s: int
    reviewed_at: int
    expires_at: int
    authority_pubkey: str
    signature: str
    prev_digest: str = _GENESIS

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "output_id": self.output_id,
            "output_digest": self.output_digest,
            "reviewer_id": self.reviewer_id,
            "review_basis_digest": self.review_basis_digest,
            "min_deliberation_s": self.min_deliberation_s,
            "deliberation_s": self.deliberation_s,
            "reviewed_at": self.reviewed_at,
            "expires_at": self.expires_at,
            "authority_pubkey": self.authority_pubkey,
            "prev_digest": self.prev_digest,
        }


def human_review_receipt(
    *,
    receipt_id: str,
    output_id: str,
    output_digest: str,
    reviewer_id: str,
    review_basis_digest: str,
    min_deliberation_s: int,
    deliberation_s: int,
    reviewed_at: int,
    expires_at: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> HumanReviewReceipt:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(output_id, "output_id")
    _check_hex64(output_digest, "output_digest")
    _check_nonempty_str(reviewer_id, "reviewer_id")
    _check_hex64(review_basis_digest, "review_basis_digest")
    _check_positive_int(min_deliberation_s, "min_deliberation_s")
    _check_nonneg_int(deliberation_s, "deliberation_s")
    _check_ts(reviewed_at, "reviewed_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= reviewed_at:
        raise DefenseError("expires_at must be after reviewed_at")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "output_id": output_id,
        "output_digest": output_digest,
        "reviewer_id": reviewer_id,
        "review_basis_digest": review_basis_digest,
        "min_deliberation_s": min_deliberation_s,
        "deliberation_s": deliberation_s,
        "reviewed_at": reviewed_at,
        "expires_at": expires_at,
        "prev_digest": prev_digest,
    }
    pubkey_hex, sig_hex = _sign_receipt(body, authority_secret)
    body["authority_pubkey"] = pubkey_hex
    return HumanReviewReceipt(signature=sig_hex, **body)


def check_human_review(
    review: HumanReviewReceipt | None,
    output_digest: str,
    now: int,
) -> DefenseVerdict:
    """Gate an AI-generated output on a live, substantive human review."""
    if review is None:
        return _deny("defense.rubber_stamp",
                      "AI-generated output executed without any human review")
    if not _verify_signature(review.authority_pubkey, _signed_body(review), review.signature):
        return _deny("defense.unsigned_review", "review authority signature invalid")
    if not hmac.compare_digest(review.output_digest, output_digest):
        return _deny("defense.review_mismatch", "review binds a different output digest")
    if review.reviewed_at > now:
        return _deny("defense.future_review", "review timestamp is in the future")
    if now >= review.expires_at:
        return _deny("defense.stale_review", "review receipt expired")
    if review.deliberation_s < review.min_deliberation_s:
        return _deny(
            "defense.checkbox_review",
            f"deliberation {review.deliberation_s}s below minimum "
            f"{review.min_deliberation_s}s — a checkbox, not a review",
        )
    return _allow(
        f"substantive review by {review.reviewer_id} "
        f"({review.deliberation_s}s) signs {review.output_id}",
        receipt_digest=_digest_receipt(review._payload()),
    )


# ---------------------------------------------------------------------------
# 2. Targeting-intelligence freshness (Minab lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IntelReceipt:
    """Targeting-intelligence provenance with a freshness contract.

    Every intel record binds its collection time, its last
    revalidation, a source-chain digest, and a freshness window. Past
    the window without revalidation the record is
    ``NON_AUTHORITATIVE`` — the AI may not be expected to catch stale
    data on the operator's behalf.
    """

    receipt_id: str
    intel_id: str
    collected_at: int
    revalidated_at: int
    source_chain_digest: str
    freshness_window_s: int
    bound_at: int
    authority_pubkey: str
    signature: str
    prev_digest: str = _GENESIS

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "intel_id": self.intel_id,
            "collected_at": self.collected_at,
            "revalidated_at": self.revalidated_at,
            "source_chain_digest": self.source_chain_digest,
            "freshness_window_s": self.freshness_window_s,
            "bound_at": self.bound_at,
            "authority_pubkey": self.authority_pubkey,
            "prev_digest": self.prev_digest,
        }


def intel_receipt(
    *,
    receipt_id: str,
    intel_id: str,
    collected_at: int,
    revalidated_at: int,
    source_chain_digest: str,
    freshness_window_s: int,
    bound_at: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> IntelReceipt:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(intel_id, "intel_id")
    _check_ts(collected_at, "collected_at")
    _check_ts(revalidated_at, "revalidated_at")
    if revalidated_at and revalidated_at < collected_at:
        raise DefenseError("revalidated_at must not predate collected_at")
    _check_hex64(source_chain_digest, "source_chain_digest")
    _check_positive_int(freshness_window_s, "freshness_window_s")
    _check_ts(bound_at, "bound_at")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "intel_id": intel_id,
        "collected_at": collected_at,
        "revalidated_at": revalidated_at,
        "source_chain_digest": source_chain_digest,
        "freshness_window_s": freshness_window_s,
        "bound_at": bound_at,
        "prev_digest": prev_digest,
    }
    pubkey_hex, sig_hex = _sign_receipt(body, authority_secret)
    body["authority_pubkey"] = pubkey_hex
    return IntelReceipt(signature=sig_hex, **body)


def check_intel_freshness(intel: IntelReceipt | None, now: int) -> DefenseVerdict:
    """Fail-closed gate: stale intel is NON_AUTHORITATIVE for targeting."""
    if intel is None:
        return _deny("defense.no_intel_provenance",
                      "targeting intel has no provenance receipt")
    if not _verify_signature(intel.authority_pubkey, _signed_body(intel), intel.signature):
        return _deny("defense.unsigned_intel", "intel authority signature invalid")
    freshness_point = intel.revalidated_at or intel.collected_at
    if now - freshness_point > intel.freshness_window_s:
        return _deny(
            "defense.stale_intel",
            f"intel {intel.intel_id} last confirmed {now - freshness_point}s ago, "
            f"beyond the {intel.freshness_window_s}s window — NON_AUTHORITATIVE",
        )
    return _allow(
        f"intel {intel.intel_id} within freshness window "
        f"(confirmed {now - freshness_point}s ago)",
        receipt_digest=_digest_receipt(intel._payload()),
    )


# ---------------------------------------------------------------------------
# 3. Operator-reliance / automation-bias probe (Maven lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RelianceReport:
    """Operator reliance on AI suggestions over a monitoring window.

    Binds total decisions, AI acceptances, and total deliberation
    seconds. A pattern of near-total acceptance with near-zero
    deliberation is not trust — it is attention decay, and it forces
    sampled human review.
    """

    receipt_id: str
    window_id: str
    decisions_total: int
    ai_accepted: int
    deliberation_total_s: int
    declared_at: int
    authority_pubkey: str
    signature: str
    prev_digest: str = _GENESIS

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "window_id": self.window_id,
            "decisions_total": self.decisions_total,
            "ai_accepted": self.ai_accepted,
            "deliberation_total_s": self.deliberation_total_s,
            "declared_at": self.declared_at,
            "authority_pubkey": self.authority_pubkey,
            "prev_digest": self.prev_digest,
        }


def reliance_report(
    *,
    receipt_id: str,
    window_id: str,
    decisions_total: int,
    ai_accepted: int,
    deliberation_total_s: int,
    declared_at: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> RelianceReport:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(window_id, "window_id")
    _check_nonneg_int(decisions_total, "decisions_total")
    _check_nonneg_int(ai_accepted, "ai_accepted")
    if ai_accepted > decisions_total:
        raise DefenseError("ai_accepted must not exceed decisions_total")
    _check_nonneg_int(deliberation_total_s, "deliberation_total_s")
    _check_ts(declared_at, "declared_at")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "window_id": window_id,
        "decisions_total": decisions_total,
        "ai_accepted": ai_accepted,
        "deliberation_total_s": deliberation_total_s,
        "declared_at": declared_at,
        "prev_digest": prev_digest,
    }
    pubkey_hex, sig_hex = _sign_receipt(body, authority_secret)
    body["authority_pubkey"] = pubkey_hex
    return RelianceReport(signature=sig_hex, **body)


def automation_bias_probe(report: RelianceReport | None) -> DefenseVerdict:
    """Probe for the rubber-stamp acceptance pattern."""
    if report is None:
        return _deny("defense.no_reliance_monitoring",
                      "operator reliance is not monitored")
    if not _verify_signature(report.authority_pubkey, _signed_body(report), report.signature):
        return _deny("defense.unsigned_reliance", "reliance authority signature invalid")
    if report.decisions_total == 0:
        return _allow("no decisions in window — no reliance signal")
    acceptance = report.ai_accepted / report.decisions_total
    mean_deliberation = report.deliberation_total_s / report.decisions_total
    if acceptance >= BIAS_ACCEPTANCE_RATIO and mean_deliberation < BIAS_DELIBERATION_FLOOR_S:
        return _deny(
            "defense.automation_bias",
            f"{acceptance:.0%} acceptance with {mean_deliberation:.1f}s mean "
            "deliberation — sampled human review is forced",
        )
    return _allow(
        f"reliance within bounds ({acceptance:.0%} acceptance, "
        f"{mean_deliberation:.1f}s mean deliberation)",
        receipt_digest=_digest_receipt(report._payload()),
    )


# ---------------------------------------------------------------------------
# 4. Civilian-protection staffing floor (10-to-1 lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProtectionPosture:
    """Civilian-protection / legal-review staffing posture.

    Cuts to protection staffing are the quiet part of the automation
    story: the receipt binds declared headcount against a declared
    minimum, so a 10-to-1 cut cannot happen silently.
    """

    receipt_id: str
    unit_id: str
    declared_staff: int
    required_min_staff: int
    reduction_impact_digest: str
    declared_at: int
    authority_pubkey: str
    signature: str
    prev_digest: str = _GENESIS

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "unit_id": self.unit_id,
            "declared_staff": self.declared_staff,
            "required_min_staff": self.required_min_staff,
            "reduction_impact_digest": self.reduction_impact_digest,
            "declared_at": self.declared_at,
            "authority_pubkey": self.authority_pubkey,
            "prev_digest": self.prev_digest,
        }


def protection_posture(
    *,
    receipt_id: str,
    unit_id: str,
    declared_staff: int,
    required_min_staff: int,
    reduction_impact_digest: str = "",
    declared_at: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> ProtectionPosture:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(unit_id, "unit_id")
    _check_nonneg_int(declared_staff, "declared_staff")
    _check_positive_int(required_min_staff, "required_min_staff")
    _check_hex64_or_empty(reduction_impact_digest, "reduction_impact_digest")
    _check_ts(declared_at, "declared_at")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "unit_id": unit_id,
        "declared_staff": declared_staff,
        "required_min_staff": required_min_staff,
        "reduction_impact_digest": reduction_impact_digest,
        "declared_at": declared_at,
        "prev_digest": prev_digest,
    }
    pubkey_hex, sig_hex = _sign_receipt(body, authority_secret)
    body["authority_pubkey"] = pubkey_hex
    return ProtectionPosture(signature=sig_hex, **body)


def check_protection_floor(posture: ProtectionPosture | None) -> DefenseVerdict:
    """Staffing below the protection floor fails closed."""
    if posture is None:
        return _deny("defense.no_protection_posture",
                      "civilian-protection staffing is undeclared")
    if not _verify_signature(posture.authority_pubkey, _signed_body(posture), posture.signature):
        return _deny("defense.unsigned_posture", "posture authority signature invalid")
    if posture.declared_staff < posture.required_min_staff:
        return _deny(
            "defense.protection_floor_breach",
            f"unit {posture.unit_id} staffed at {posture.declared_staff}, "
            f"floor is {posture.required_min_staff}",
        )
    return _allow(
        f"unit {posture.unit_id} meets protection floor "
        f"({posture.declared_staff} >= {posture.required_min_staff})",
        receipt_digest=_digest_receipt(posture._payload()),
    )


# ---------------------------------------------------------------------------
# 5. Supplier redline clauses as contract terms (Anthropic lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RedlineContract:
    """Supplier ethics redlines as receipt-bound contract terms.

    The FASCSA fight showed that model-internal refusals lose to
    procurement power: the redline must live in the contract. A
    procurement demand to remove a redline binds a public-disclosure
    receipt; silent removal is the breach.
    """

    receipt_id: str
    vendor_id: str
    contract_id: str
    redlines: tuple[str, ...]
    removal_requested: bool
    removal_disclosure_digest: str
    bound_at: int
    authority_pubkey: str
    signature: str
    prev_digest: str = _GENESIS

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "vendor_id": self.vendor_id,
            "contract_id": self.contract_id,
            "redlines": list(self.redlines),
            "removal_requested": self.removal_requested,
            "removal_disclosure_digest": self.removal_disclosure_digest,
            "bound_at": self.bound_at,
            "authority_pubkey": self.authority_pubkey,
            "prev_digest": self.prev_digest,
        }


def redline_contract(
    *,
    receipt_id: str,
    vendor_id: str,
    contract_id: str,
    redlines: tuple[str, ...],
    removal_requested: bool,
    removal_disclosure_digest: str = "",
    bound_at: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> RedlineContract:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(vendor_id, "vendor_id")
    _check_nonempty_str(contract_id, "contract_id")
    if not redlines:
        raise DefenseError("redlines must be non-empty")
    for kind in redlines:
        _check_vocab(kind, "redline kind", REDLINE_KINDS)
    if not isinstance(removal_requested, bool):
        raise DefenseError("removal_requested must be a bool")
    _check_hex64_or_empty(removal_disclosure_digest, "removal_disclosure_digest")
    _check_ts(bound_at, "bound_at")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "vendor_id": vendor_id,
        "contract_id": contract_id,
        "redlines": list(redlines),
        "removal_requested": removal_requested,
        "removal_disclosure_digest": removal_disclosure_digest,
        "bound_at": bound_at,
        "prev_digest": prev_digest,
    }
    pubkey_hex, sig_hex = _sign_receipt(body, authority_secret)
    body["authority_pubkey"] = pubkey_hex
    return RedlineContract(signature=sig_hex, **body)


def check_redline_contract(clause: RedlineContract | None) -> DefenseVerdict:
    """Redline removal without a disclosure receipt fails closed."""
    if clause is None:
        return _deny("defense.no_redline_contract",
                      "supplier redlines are not bound as contract terms")
    if not _verify_signature(clause.authority_pubkey, _signed_body(clause), clause.signature):
        return _deny("defense.unsigned_redlines", "contract authority signature invalid")
    if clause.removal_requested and not clause.removal_disclosure_digest:
        return _deny(
            "defense.silent_redline_removal",
            f"redline removal requested by {clause.vendor_id} without a "
            "public-disclosure receipt",
        )
    note = ("redlines intact" if not clause.removal_requested
            else "redline removal publicly disclosed")
    return _allow(
        f"contract {clause.contract_id}: {note}",
        receipt_digest=_digest_receipt(clause._payload()),
    )


# ---------------------------------------------------------------------------
# 6. AI-intel-report watermark + assertion evidence chains (CNN-ship lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssertionEvidence:
    """One key assertion and the digest of its evidence chain."""

    assertion_id: str
    evidence_digest: str  # "" when the assertion is evidence-free


@dataclass(frozen=True)
class IntelReport:
    """AI-generated intel report with watermark and assertion evidence.

    Every key assertion binds an evidence-chain digest. An assertion
    with no evidence is marked ``UNVERIFIED`` and the report is blocked
    from the action-approval flow — the fabricated "Chinese ship"
    lesson.
    """

    receipt_id: str
    report_id: str
    ai_generated: bool
    watermark_digest: str
    assertions: tuple[AssertionEvidence, ...]
    issued_at: int
    authority_pubkey: str
    signature: str
    prev_digest: str = _GENESIS

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "report_id": self.report_id,
            "ai_generated": self.ai_generated,
            "watermark_digest": self.watermark_digest,
            "assertions": [
                {"assertion_id": a.assertion_id, "evidence_digest": a.evidence_digest}
                for a in self.assertions
            ],
            "issued_at": self.issued_at,
            "authority_pubkey": self.authority_pubkey,
            "prev_digest": self.prev_digest,
        }


def intel_report(
    *,
    receipt_id: str,
    report_id: str,
    ai_generated: bool,
    watermark_digest: str = "",
    assertions: tuple[tuple[str, str], ...] = (),
    issued_at: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> IntelReport:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(report_id, "report_id")
    if not isinstance(ai_generated, bool):
        raise DefenseError("ai_generated must be a bool")
    _check_hex64_or_empty(watermark_digest, "watermark_digest")
    parsed: list[AssertionEvidence] = []
    for assertion_id, evidence_digest in assertions:
        _check_nonempty_str(assertion_id, "assertion_id")
        _check_hex64_or_empty(evidence_digest, "evidence_digest")
        parsed.append(AssertionEvidence(assertion_id, evidence_digest))
    _check_ts(issued_at, "issued_at")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "report_id": report_id,
        "ai_generated": ai_generated,
        "watermark_digest": watermark_digest,
        "assertions": [
            {"assertion_id": a.assertion_id, "evidence_digest": a.evidence_digest}
            for a in parsed
        ],
        "issued_at": issued_at,
        "prev_digest": prev_digest,
    }
    pubkey_hex, sig_hex = _sign_receipt(body, authority_secret)
    body["authority_pubkey"] = pubkey_hex
    body.pop("assertions")
    return IntelReport(signature=sig_hex, assertions=tuple(parsed), **body)


def check_intel_report(report: IntelReport | None) -> DefenseVerdict:
    """Evidence-free AI assertions are UNVERIFIED and blocked."""
    if report is None:
        return _deny("defense.no_intel_report",
                      "intel report has no provenance receipt")
    if not _verify_signature(report.authority_pubkey, _signed_body(report), report.signature):
        return _deny("defense.unsigned_report", "report authority signature invalid")
    if report.ai_generated and not report.watermark_digest:
        return _deny(
            "defense.unwatermarked_ai_intel",
            f"AI-generated report {report.report_id} carries no generation watermark",
        )
    evidence_free = [a.assertion_id for a in report.assertions if not a.evidence_digest]
    if evidence_free:
        return _deny(
            "defense.unverified_assertion",
            f"report {report.report_id} assertions without evidence: "
            f"{', '.join(evidence_free)} — UNVERIFIED, blocked from action approval",
        )
    return _allow(
        f"report {report.report_id}: {len(report.assertions)} assertions, "
        "all evidence-bound",
        receipt_digest=_digest_receipt(report._payload()),
    )


# ---------------------------------------------------------------------------
# 7. Escalation-ladder lock + adversarial escalation regression (Payne lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EscalationLadderConfig:
    """Strategic escalation-ladder constraints on a decision-support deployment.

    Nuclear options are locked by default and unlock only through
    multi-level human authorization plus a cooling period. Adversarial
    escalation regression (nuke-deployment fraction over simulated
    conflict batches) must pass on a clock.
    """

    receipt_id: str
    ladder_id: str
    nuclear_option_locked: bool
    authorization_levels: int
    cooldown_s: int
    regression_test_id: str
    regression_passed_at: int
    regression_window_s: int
    bound_at: int
    authority_pubkey: str
    signature: str
    prev_digest: str = _GENESIS

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "ladder_id": self.ladder_id,
            "nuclear_option_locked": self.nuclear_option_locked,
            "authorization_levels": self.authorization_levels,
            "cooldown_s": self.cooldown_s,
            "regression_test_id": self.regression_test_id,
            "regression_passed_at": self.regression_passed_at,
            "regression_window_s": self.regression_window_s,
            "bound_at": self.bound_at,
            "authority_pubkey": self.authority_pubkey,
            "prev_digest": self.prev_digest,
        }


def escalation_ladder_config(
    *,
    receipt_id: str,
    ladder_id: str,
    nuclear_option_locked: bool,
    authorization_levels: int,
    cooldown_s: int,
    regression_test_id: str,
    regression_passed_at: int,
    regression_window_s: int,
    bound_at: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> EscalationLadderConfig:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(ladder_id, "ladder_id")
    if not isinstance(nuclear_option_locked, bool):
        raise DefenseError("nuclear_option_locked must be a bool")
    _check_positive_int(authorization_levels, "authorization_levels")
    _check_nonneg_int(cooldown_s, "cooldown_s")
    _check_nonempty_str(regression_test_id, "regression_test_id")
    _check_ts(regression_passed_at, "regression_passed_at")
    _check_positive_int(regression_window_s, "regression_window_s")
    _check_ts(bound_at, "bound_at")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "ladder_id": ladder_id,
        "nuclear_option_locked": nuclear_option_locked,
        "authorization_levels": authorization_levels,
        "cooldown_s": cooldown_s,
        "regression_test_id": regression_test_id,
        "regression_passed_at": regression_passed_at,
        "regression_window_s": regression_window_s,
        "bound_at": bound_at,
        "prev_digest": prev_digest,
    }
    pubkey_hex, sig_hex = _sign_receipt(body, authority_secret)
    body["authority_pubkey"] = pubkey_hex
    return EscalationLadderConfig(signature=sig_hex, **body)


@dataclass(frozen=True)
class EscalationRegression:
    """Adversarial escalation regression test result."""

    receipt_id: str
    test_id: str
    ladder_id: str
    n_sims: int
    nuke_deployed_sims: int
    completed_at: int
    authority_pubkey: str
    signature: str
    prev_digest: str = _GENESIS

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "test_id": self.test_id,
            "ladder_id": self.ladder_id,
            "n_sims": self.n_sims,
            "nuke_deployed_sims": self.nuke_deployed_sims,
            "completed_at": self.completed_at,
            "authority_pubkey": self.authority_pubkey,
            "prev_digest": self.prev_digest,
        }


def escalation_regression(
    *,
    receipt_id: str,
    test_id: str,
    ladder_id: str,
    n_sims: int,
    nuke_deployed_sims: int,
    completed_at: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> EscalationRegression:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(test_id, "test_id")
    _check_nonempty_str(ladder_id, "ladder_id")
    _check_positive_int(n_sims, "n_sims")
    _check_nonneg_int(nuke_deployed_sims, "nuke_deployed_sims")
    if nuke_deployed_sims > n_sims:
        raise DefenseError("nuke_deployed_sims must not exceed n_sims")
    _check_ts(completed_at, "completed_at")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "test_id": test_id,
        "ladder_id": ladder_id,
        "n_sims": n_sims,
        "nuke_deployed_sims": nuke_deployed_sims,
        "completed_at": completed_at,
        "prev_digest": prev_digest,
    }
    pubkey_hex, sig_hex = _sign_receipt(body, authority_secret)
    body["authority_pubkey"] = pubkey_hex
    return EscalationRegression(signature=sig_hex, **body)


def check_escalation_ladder(cfg: EscalationLadderConfig | None, now: int) -> DefenseVerdict:
    """The escalation ladder must be locked and regression-fresh."""
    if cfg is None:
        return _deny("defense.no_escalation_ladder",
                      "strategic decision support has no escalation-ladder binding")
    if not _verify_signature(cfg.authority_pubkey, _signed_body(cfg), cfg.signature):
        return _deny("defense.unsigned_ladder", "ladder authority signature invalid")
    if not cfg.nuclear_option_locked:
        return _deny("defense.nuclear_unlocked",
                      f"ladder {cfg.ladder_id}: nuclear option is not locked")
    if cfg.authorization_levels < 2:
        return _deny(
            "defense.single_authorization_nuke",
            "nuclear unlock requires multi-level human authorization",
        )
    if now - cfg.regression_passed_at > cfg.regression_window_s:
        return _deny(
            "defense.escalation_test_overdue",
            f"ladder {cfg.ladder_id}: escalation regression older than window",
        )
    return _allow(
        f"ladder {cfg.ladder_id}: nuclear locked, "
        f"{cfg.authorization_levels}-level authorization, regression fresh",
        receipt_digest=_digest_receipt(cfg._payload()),
    )


def check_escalation_regression(report: EscalationRegression | None) -> DefenseVerdict:
    """Nuke-deployment fractions above tolerance fail the regression."""
    if report is None:
        return _deny("defense.no_escalation_regression",
                      "no adversarial escalation regression on file")
    if not _verify_signature(report.authority_pubkey, _signed_body(report), report.signature):
        return _deny("defense.unsigned_regression", "regression authority signature invalid")
    fraction = report.nuke_deployed_sims / report.n_sims
    if fraction > ESCALATION_MAX_NUKE_FRACTION:
        return _deny(
            "defense.escalation_regression_failed",
            f"test {report.test_id}: {fraction:.0%} of sims deployed tactical "
            f"nukes (tolerance {ESCALATION_MAX_NUKE_FRACTION:.0%})",
        )
    return _allow(
        f"test {report.test_id}: {fraction:.0%} nuke-deployment fraction "
        f"within {ESCALATION_MAX_NUKE_FRACTION:.0%} tolerance",
        receipt_digest=_digest_receipt(report._payload()),
    )


# ---------------------------------------------------------------------------
# 8. Decision-cycle compression alert (algorithmic-warfare lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DecisionCycle:
    """Decision-cycle compression record.

    When AI compresses the decision cycle beyond the alert ratio, the
    commander must bind an acknowledgment that speed has not degraded
    deliberation — because speed makes war look cheap.
    """

    receipt_id: str
    cycle_id: str
    baseline_cycle_s: int
    current_cycle_s: int
    commander_ack_digest: str
    observed_at: int
    authority_pubkey: str
    signature: str
    prev_digest: str = _GENESIS

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "cycle_id": self.cycle_id,
            "baseline_cycle_s": self.baseline_cycle_s,
            "current_cycle_s": self.current_cycle_s,
            "commander_ack_digest": self.commander_ack_digest,
            "observed_at": self.observed_at,
            "authority_pubkey": self.authority_pubkey,
            "prev_digest": self.prev_digest,
        }


def decision_cycle(
    *,
    receipt_id: str,
    cycle_id: str,
    baseline_cycle_s: int,
    current_cycle_s: int,
    commander_ack_digest: str = "",
    observed_at: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> DecisionCycle:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(cycle_id, "cycle_id")
    _check_positive_int(baseline_cycle_s, "baseline_cycle_s")
    _check_positive_int(current_cycle_s, "current_cycle_s")
    _check_hex64_or_empty(commander_ack_digest, "commander_ack_digest")
    _check_ts(observed_at, "observed_at")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "cycle_id": cycle_id,
        "baseline_cycle_s": baseline_cycle_s,
        "current_cycle_s": current_cycle_s,
        "commander_ack_digest": commander_ack_digest,
        "observed_at": observed_at,
        "prev_digest": prev_digest,
    }
    pubkey_hex, sig_hex = _sign_receipt(body, authority_secret)
    body["authority_pubkey"] = pubkey_hex
    return DecisionCycle(signature=sig_hex, **body)


def check_decision_compression(cycle: DecisionCycle | None) -> DefenseVerdict:
    """Compression beyond the alert ratio needs a commander acknowledgment."""
    if cycle is None:
        return _deny("defense.no_cycle_record",
                      "decision-cycle compression is unmeasured")
    if not _verify_signature(cycle.authority_pubkey, _signed_body(cycle), cycle.signature):
        return _deny("defense.unsigned_cycle", "cycle authority signature invalid")
    ratio = cycle.baseline_cycle_s / cycle.current_cycle_s
    if ratio >= COMPRESSION_ALERT_RATIO and not cycle.commander_ack_digest:
        return _deny(
            "defense.compression_unacknowledged",
            f"cycle {cycle.cycle_id}: {ratio:.0f}x compression without commander "
            "acknowledgment that deliberation quality holds",
        )
    return _allow(
        f"cycle {cycle.cycle_id}: {ratio:.0f}x compression, "
        f"{'acknowledged' if cycle.commander_ack_digest else 'below alert ratio'}",
        receipt_digest=_digest_receipt(cycle._payload()),
    )


# ---------------------------------------------------------------------------
# 9. Vendor cutoff notification (FASCSA lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VendorCutoffNotice:
    """Supply-chain-risk vendor cutoff notification.

    When a vendor is cut off (blacklisting, debarment, capability
    loss), the affected system's operator must receive a notification
    receipt plus a transition clock — not discover the cutoff by
    accident.
    """

    receipt_id: str
    vendor_id: str
    system_id: str
    notified_at: int
    cutoff_at: int
    transition_clock_s: int
    authority_pubkey: str
    signature: str
    prev_digest: str = _GENESIS

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "vendor_id": self.vendor_id,
            "system_id": self.system_id,
            "notified_at": self.notified_at,
            "cutoff_at": self.cutoff_at,
            "transition_clock_s": self.transition_clock_s,
            "authority_pubkey": self.authority_pubkey,
            "prev_digest": self.prev_digest,
        }


def vendor_cutoff_notice(
    *,
    receipt_id: str,
    vendor_id: str,
    system_id: str,
    notified_at: int,
    cutoff_at: int,
    transition_clock_s: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> VendorCutoffNotice:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(vendor_id, "vendor_id")
    _check_nonempty_str(system_id, "system_id")
    _check_ts(notified_at, "notified_at")
    _check_ts(cutoff_at, "cutoff_at")
    if cutoff_at and notified_at > cutoff_at:
        raise DefenseError("notified_at must not postdate cutoff_at")
    _check_nonneg_int(transition_clock_s, "transition_clock_s")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "vendor_id": vendor_id,
        "system_id": system_id,
        "notified_at": notified_at,
        "cutoff_at": cutoff_at,
        "transition_clock_s": transition_clock_s,
        "prev_digest": prev_digest,
    }
    pubkey_hex, sig_hex = _sign_receipt(body, authority_secret)
    body["authority_pubkey"] = pubkey_hex
    return VendorCutoffNotice(signature=sig_hex, **body)


def check_vendor_cutoff(notice: VendorCutoffNotice | None, now: int) -> DefenseVerdict:
    """An already-effective cutoff with no notification fails closed."""
    if notice is None:
        return _allow("no vendor cutoff in force")
    if not _verify_signature(notice.authority_pubkey, _signed_body(notice), notice.signature):
        return _deny("defense.unsigned_cutoff", "cutoff authority signature invalid")
    if notice.cutoff_at and now >= notice.cutoff_at and not notice.notified_at:
        return _deny(
            "defense.silent_vendor_cutoff",
            f"vendor {notice.vendor_id} cutoff effective with no operator "
            "notification receipt",
        )
    return _allow(
        f"vendor {notice.vendor_id}: cutoff notification bound",
        receipt_digest=_digest_receipt(notice._payload()),
    )


# ---------------------------------------------------------------------------
# 10. Treaty-position drift clock (CCW lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TreatyPosition:
    """Deployment compliance position against an evolving treaty.

    When a treaty (or a negotiated review outcome) takes effect, the
    deployment's constraints must be updated to match; drift between
    the declared position and the system's constraints is a tracked
    failure.
    """

    receipt_id: str
    treaty_id: str
    position_digest: str
    effective_at: int
    constraints_updated_at: int
    review_due_at: int
    bound_at: int
    authority_pubkey: str
    signature: str
    prev_digest: str = _GENESIS

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "treaty_id": self.treaty_id,
            "position_digest": self.position_digest,
            "effective_at": self.effective_at,
            "constraints_updated_at": self.constraints_updated_at,
            "review_due_at": self.review_due_at,
            "bound_at": self.bound_at,
            "authority_pubkey": self.authority_pubkey,
            "prev_digest": self.prev_digest,
        }


def treaty_position(
    *,
    receipt_id: str,
    treaty_id: str,
    position_digest: str,
    effective_at: int,
    constraints_updated_at: int,
    review_due_at: int,
    bound_at: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> TreatyPosition:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(treaty_id, "treaty_id")
    _check_hex64(position_digest, "position_digest")
    _check_ts(effective_at, "effective_at")
    _check_ts(constraints_updated_at, "constraints_updated_at")
    _check_ts(review_due_at, "review_due_at")
    _check_ts(bound_at, "bound_at")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "treaty_id": treaty_id,
        "position_digest": position_digest,
        "effective_at": effective_at,
        "constraints_updated_at": constraints_updated_at,
        "review_due_at": review_due_at,
        "bound_at": bound_at,
        "prev_digest": prev_digest,
    }
    pubkey_hex, sig_hex = _sign_receipt(body, authority_secret)
    body["authority_pubkey"] = pubkey_hex
    return TreatyPosition(signature=sig_hex, **body)


def check_treaty_position(treaty: TreatyPosition | None, now: int) -> DefenseVerdict:
    """A treaty in force with stale system constraints is drift."""
    if treaty is None:
        return _deny("defense.no_treaty_position",
                      "no treaty compliance position is declared")
    if not _verify_signature(treaty.authority_pubkey, _signed_body(treaty), treaty.signature):
        return _deny("defense.unsigned_treaty", "treaty authority signature invalid")
    if now >= treaty.effective_at and treaty.constraints_updated_at < treaty.effective_at:
        return _deny(
            "defense.treaty_drift",
            f"treaty {treaty.treaty_id} in force but system constraints not "
            "updated to match",
        )
    if now > treaty.review_due_at:
        return _deny(
            "defense.treaty_review_overdue",
            f"treaty {treaty.treaty_id}: compliance review past due",
        )
    return _allow(
        f"treaty {treaty.treaty_id}: constraints current, review within clock",
        receipt_digest=_digest_receipt(treaty._payload()),
    )


# ---------------------------------------------------------------------------
# 11. Swarm command ratio quantification (Replicator lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SwarmConfig:
    """Quantified "meaningful command" over an autonomous swarm.

    "Minimal operator intervention" must be a number, not an
    assertion: the receipt binds the operator:platform ratio, the
    target-recognition confidence threshold, and a change log digest
    for any adaptive-threshold adjustment. Silent threshold lowering
    is the drift this gate catches.
    """

    receipt_id: str
    swarm_id: str
    operators: int
    platforms: int
    confidence_threshold: float
    threshold_changelog_digest: str
    declared_at: int
    authority_pubkey: str
    signature: str
    prev_digest: str = _GENESIS

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "swarm_id": self.swarm_id,
            "operators": self.operators,
            "platforms": self.platforms,
            "confidence_threshold": self.confidence_threshold,
            "threshold_changelog_digest": self.threshold_changelog_digest,
            "declared_at": self.declared_at,
            "authority_pubkey": self.authority_pubkey,
            "prev_digest": self.prev_digest,
        }


def swarm_config(
    *,
    receipt_id: str,
    swarm_id: str,
    operators: int,
    platforms: int,
    confidence_threshold: float,
    threshold_changelog_digest: str = "",
    declared_at: int,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> SwarmConfig:
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(swarm_id, "swarm_id")
    _check_nonneg_int(operators, "operators")
    _check_nonneg_int(platforms, "platforms")
    _check_ratio(confidence_threshold, "confidence_threshold")
    _check_hex64_or_empty(threshold_changelog_digest, "threshold_changelog_digest")
    _check_ts(declared_at, "declared_at")
    _check_secret(authority_secret, "authority_secret")
    body = {
        "receipt_id": receipt_id,
        "swarm_id": swarm_id,
        "operators": operators,
        "platforms": platforms,
        "confidence_threshold": confidence_threshold,
        "threshold_changelog_digest": threshold_changelog_digest,
        "declared_at": declared_at,
        "prev_digest": prev_digest,
    }
    pubkey_hex, sig_hex = _sign_receipt(body, authority_secret)
    body["authority_pubkey"] = pubkey_hex
    return SwarmConfig(signature=sig_hex, **body)


def check_swarm_config(cfg: SwarmConfig | None) -> DefenseVerdict:
    """Unquantified command and silent threshold drift fail closed."""
    if cfg is None:
        return _deny("defense.no_swarm_config",
                      "swarm deployment has no command-quantification receipt")
    if not _verify_signature(cfg.authority_pubkey, _signed_body(cfg), cfg.signature):
        return _deny("defense.unsigned_swarm", "swarm authority signature invalid")
    if cfg.operators == 0:
        return _deny("defense.no_operator_command",
                      f"swarm {cfg.swarm_id}: no operator in command")
    if cfg.platforms > cfg.operators * MAX_PLATFORMS_PER_OPERATOR:
        return _deny(
            "defense.command_ratio_breach",
            f"swarm {cfg.swarm_id}: {cfg.platforms} platforms over "
            f"{cfg.operators} operators exceeds {MAX_PLATFORMS_PER_OPERATOR} "
            "platforms/operator",
        )
    if not cfg.threshold_changelog_digest:
        return _deny(
            "defense.threshold_drift",
            f"swarm {cfg.swarm_id}: adaptive confidence thresholds adjust "
            "without a bound change log",
        )
    return _allow(
        f"swarm {cfg.swarm_id}: {cfg.operators} operators over {cfg.platforms} "
        f"platforms, threshold {cfg.confidence_threshold:.2f} change-logged",
        receipt_digest=_digest_receipt(cfg._payload()),
    )


__all__ = [
    "DEFENSE_SCHEMA_VERSION",
    "REDLINE_KINDS",
    "BIAS_ACCEPTANCE_RATIO",
    "BIAS_DELIBERATION_FLOOR_S",
    "ESCALATION_MAX_NUKE_FRACTION",
    "COMPRESSION_ALERT_RATIO",
    "MAX_PLATFORMS_PER_OPERATOR",
    "DefenseError",
    "DefenseVerdict",
    "AssertionEvidence",
    "HumanReviewReceipt",
    "IntelReceipt",
    "RelianceReport",
    "ProtectionPosture",
    "RedlineContract",
    "IntelReport",
    "EscalationLadderConfig",
    "EscalationRegression",
    "DecisionCycle",
    "VendorCutoffNotice",
    "TreatyPosition",
    "SwarmConfig",
    "human_review_receipt",
    "check_human_review",
    "intel_receipt",
    "check_intel_freshness",
    "reliance_report",
    "automation_bias_probe",
    "protection_posture",
    "check_protection_floor",
    "redline_contract",
    "check_redline_contract",
    "intel_report",
    "check_intel_report",
    "escalation_ladder_config",
    "escalation_regression",
    "check_escalation_ladder",
    "check_escalation_regression",
    "decision_cycle",
    "check_decision_compression",
    "vendor_cutoff_notice",
    "check_vendor_cutoff",
    "treaty_position",
    "check_treaty_position",
    "swarm_config",
    "check_swarm_config",
]
