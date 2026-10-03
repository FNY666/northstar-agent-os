"""Procurement accountability gates (one-hundred-thirty-eighth batch).

Absorbs the 2026 AI-procurement research thread — public tenders are
where algorithmic opacity meets public money:

* **China (NDRC + 8 ministries, 2026)**: "AI + bidding" guidance, 10
  scenarios (tender-doc "pre-issuance health check", intelligent
  bid-evaluation assistance, collusion detection); partial-province
  full coverage by end-2026, national by 2027. Hard rules: AI
  conclusions never replace independent judgment; evaluation
  algorithms must be registered and reviewed.
* **Hefei, Anhui (People's Daily / Xinhua, 2026-06)**: first
  bidding-LLM deployment in production — 82.9TB training data;
  36,000 tender docs audited since 2025, 3,264 suspicious clauses
  flagged; 91.17% expert adoption rate (official-media claim,
  unaudited).
* **Korea PPS (2026-08)**: AI technical-evaluation support system —
  AI only analyzes and builds comparison tables; the final judgment
  stays with the evaluation committee. Every recommendation carries
  "original-text location confirmation" plus "evaluation-reference
  auxiliary material" labels against hallucination.
* **UK CMA (official blog, 2026-09)**: Bid Rigging Intelligence
  Tool (BRIT) — scaled collusion screening, pilots generated
  enforcement leads; bid-rigging inflates prices ~20% (OECD);
  bottleneck: no machine-readable dataset *including losing bids*.
* **South Africa Competition Commission (2026-10)**: AI collusion
  tool built with Singapore's competition bureau + University of
  Pretoria.
* **EU CEDAR**: 30-partner consortium — XAI + knowledge graphs over
  100% of procurement data, Italy / Slovenia / Ukraine pilots.
* **US VA (2026-10)**: an enterprise AI contract made "transparent
  AI governance" a scored bid criterion.
* **UK Procurement Act 2023 (practitioner reading)**: AI may assist
  scoring but cannot conclude a matter — the named evaluator must
  personally read the bids, score them, and write the reasons;
  software cannot bear the accountability obligation.
* **Risk lines**: the black-box accountability vacuum; incumbency
  bias amplification (anecdotal: AI rejecting diverse suppliers at
  ~4x the rate, single-source); AI-assisted tender-document forgery.

Fail-closed rules:

1. **Advisory only** — scoring, writing reasons, and signing stay
   with the *named human evaluator*. An award where AI scored and
   any of the three human acts is missing denies with
   ``procurement.ai_concluded`` (the UK Procurement Act lesson).
2. **Source grounding** — every AI evaluation claim binds at least
   one original-tender-text location (doc id, section ref, excerpt
   digest). An ungrounded claim is NON_AUTHORITATIVE
   (``procurement.ungrounded_claim``) — the Korea PPS
   "original-text location confirmation" as a mechanism.
3. **Tender-doc screening** — a tender document needs a live,
   authority-signed pre-issuance health-check receipt (closed check
   vocabulary). Publishing without one is
   ``procurement.unscreened_doc`` (China "先体检再发布" as a
   mechanism). Expired receipts are unscreened receipts.
4. **Collusion probes** — probes produce *leads*, never automatic
   convictions (the BRIT lesson). A lead requires a triple binding
   (price-pattern digest, comms-metadata digest, structural-market
   signal digest) plus a threshold score; the lead verdict is
   NON_AUTHORITATIVE ``procurement.collusion_lead`` and routes to
   human investigators. Incomplete evidence cannot conclude:
   ``procurement.incomplete_collusion_evidence``.
5. **Losing-bid data** — evaluations computed without losing-bid
   data auto-degrade: NON_AUTHORITATIVE
   ``procurement.missing_losing_bids`` (the CMA bottleneck as a
   gate).
6. **Incumbency-bias probe** — when the new-supplier rejection rate
   deviates from the incumbent rate beyond tolerance, the probe
   denies with ``procurement.incumbency_bias`` and routes to audit
   (the 4x anecdote mechanized).
7. **Algorithm registry** — deployed evaluation algorithms bind a
   signed registration receipt (algorithm id, version, review
   digest — the "算法登记审查" rule). Calls to unregistered or
   expired registrations deny ``procurement.unregistered_algorithm``;
   revoked registrations deny ``procurement.revoked_algorithm``.
8. **Full-trace awards** — an award binds the 4-segment evidence
   chain (AI input digest, AI output digest, human-edits digest,
   final-reasons digest) plus a human signature on the final
   reasons. A missing segment is ``procurement.incomplete_trace``;
   unsigned final reasons are ``procurement.unsigned_reasons``.

Honest boundary: receipts are *declared evidence*. The gates check
consistency — digests recompute, signatures verify, registrations
are live, human acts are claimed — not whether the underlying
evaluation was fair or the collusion lead true. A forged-but-
consistent receipt still needs an off-chain adjudicator. What the
gates guarantee: no AI-concluded award, no ungrounded claim, no
unregistered algorithm, and no conviction-by-probe can pass as
authorized. They do not end corruption.

Deterministic: no wall-clock reads (callers inject integer epochs),
canonical JSON hashing (``canonical_json``), Ed25519 signatures via
the vendored ``ed25519`` module, and all digest comparisons use
:func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


PROCUREMENT_SCHEMA_VERSION = "northstar.procurement.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128

#: Policy classification tiers.
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Denial reason codes.
DENY_AI_CONCLUDED = "procurement.ai_concluded"
DENY_NO_HUMAN_ACCOUNTABILITY = "procurement.no_human_accountability"
DENY_UNGROUNDED_CLAIM = "procurement.ungrounded_claim"
DENY_UNSCREENED_DOC = "procurement.unscreened_doc"
DENY_COLLUSION_LEAD = "procurement.collusion_lead"
DENY_INCOMPLETE_COLLUSION = "procurement.incomplete_collusion_evidence"
DENY_MISSING_LOSING_BIDS = "procurement.missing_losing_bids"
DENY_INCUMBENCY_BIAS = "procurement.incumbency_bias"
DENY_UNREGISTERED_ALGORITHM = "procurement.unregistered_algorithm"
DENY_REVOKED_ALGORITHM = "procurement.revoked_algorithm"
DENY_INCOMPLETE_TRACE = "procurement.incomplete_trace"
DENY_UNSIGNED_REASONS = "procurement.unsigned_reasons"
DENY_CHAIN_BROKEN = "procurement.chain_broken"

#: Closed health-check vocabulary for pre-issuance tender screening
#: (China "先体检再发布" — checks are declared, not free text).
HEALTH_CHECKS: tuple[str, ...] = (
    "suspicious_clauses",
    "discriminatory_terms",
    "consistency",
    "collusion_markers",
)


class ProcurementError(ValueError):
    """A malformed procurement receipt or a programming error.

    Raised for structural problems (bad digests, unknown checks,
    broken chains). Verification *failures* (AI-concluded awards,
    ungrounded claims, unregistered algorithms) return a
    :class:`ProcurementVerdict` with ``allowed=False`` instead — a
    failed gate is a verdict, a malformed receipt is a bug.
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
        raise ProcurementError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProcurementError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProcurementError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed (no keypair()).
    if not isinstance(value, bytes) or len(value) != 32:
        raise ProcurementError(f"{field_name} must be a 32-byte seed")
    return value


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise ProcurementError("authority_pubkey_hex must be a 64-char lowercase hex digest")
    return value


def _check_sig_hex(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise ProcurementError(f"{field_name} must be a 128-char lowercase hex signature")
    return value


def _check_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ProcurementError(f"{field_name} must be a bool")
    return value


def _check_health_check(value: Any) -> str:
    if value not in HEALTH_CHECKS:
        raise ProcurementError(
            f"health check must be one of {HEALTH_CHECKS}, saw {value!r}"
        )
    return value


# ---------------------------------------------------------------------------
# Signing and chain verification
# ---------------------------------------------------------------------------


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
    """Raise :class:`ProcurementError` if a receipt log is tampered/broken.

    Every entry must expose ``receipt_digest`` and ``prev_digest`` and
    a ``_payload()`` method; the entries must form one chain from
    ``"genesis"`` with recomputing digests and valid authority
    signatures.
    """
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise ProcurementError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise ProcurementError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
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
            raise ProcurementError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class ProcurementVerdict:
    """Outcome of one procurement gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> ProcurementVerdict:
    return ProcurementVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> ProcurementVerdict:
    return ProcurementVerdict(
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
# 1. Advisory-only gate (UK Procurement Act 2023 lesson)
# ---------------------------------------------------------------------------


def advisory_only_gate(
    award_id: str,
    evaluator_id: str,
    *,
    ai_scored: bool,
    human_scored: bool,
    human_wrote_reasons: bool,
    human_signed: bool,
) -> ProcurementVerdict:
    """AI may assist scoring; it may never conclude a matter.

    Scoring, writing the reasons, and signing stay with the *named
    human evaluator*. Software cannot bear the accountability
    obligation. An award where AI scored while any of the three
    human acts is missing denies with ``procurement.ai_concluded``.
    An award where no human performed the three acts denies with
    ``procurement.no_human_accountability`` even when no AI was
    involved — there is nobody to hold accountable.
    """
    _check_nonempty_str(award_id, "award_id")
    _check_nonempty_str(evaluator_id, "evaluator_id")
    for name, value in (
        ("ai_scored", ai_scored),
        ("human_scored", human_scored),
        ("human_wrote_reasons", human_wrote_reasons),
        ("human_signed", human_signed),
    ):
        if not isinstance(value, bool):
            raise ProcurementError(f"{name} must be a bool")

    human_complete = human_scored and human_wrote_reasons and human_signed
    if ai_scored and not human_complete:
        return _deny(
            DENY_AI_CONCLUDED,
            f"award {award_id!r} was AI-scored but evaluator {evaluator_id!r} "
            "did not personally score, write reasons, and sign",
        )
    if not human_complete:
        return _deny(
            DENY_NO_HUMAN_ACCOUNTABILITY,
            f"award {award_id!r} has no named human evaluator who scored, "
            "wrote reasons, and signed",
        )
    return _allow(
        f"award {award_id!r}: evaluator {evaluator_id!r} personally scored, "
        "wrote reasons, and signed; AI involvement (if any) was advisory only"
    )


# ---------------------------------------------------------------------------
# 2. Source-grounding receipts (Korea PPS lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceLocation:
    """One original-tender-text location backing an AI claim."""

    tender_doc_id: str
    section_ref: str
    excerpt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "tender_doc_id": _check_nonempty_str(self.tender_doc_id, "tender_doc_id"),
            "section_ref": _check_nonempty_str(self.section_ref, "section_ref"),
            "excerpt_digest": _check_hex64(self.excerpt_digest, "excerpt_digest"),
        }


@dataclass(frozen=True)
class GroundedClaimReceipt:
    """An AI evaluation claim bound to original-text locations.

    ``locations`` must be non-empty: every claim needs at least one
    "original-text location confirmation" (Korea PPS). The receipt is
    sealed by the evaluation authority that vouches for the binding.
    """

    receipt_id: str
    claim_id: str
    claim_digest: str
    evaluation_id: str
    locations: tuple[SourceLocation, ...]
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = PROCUREMENT_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": _check_nonempty_str(self.receipt_id, "receipt_id"),
            "claim_id": _check_nonempty_str(self.claim_id, "claim_id"),
            "claim_digest": _check_hex64(self.claim_digest, "claim_digest"),
            "evaluation_id": _check_nonempty_str(self.evaluation_id, "evaluation_id"),
            "locations": [loc._payload() for loc in self.locations],
            "authority_id": _check_nonempty_str(self.authority_id, "authority_id"),
            "authority_pubkey_hex": _check_pubkey_hex(self.authority_pubkey_hex),
            "signature_hex": _check_sig_hex(self.signature_hex, "signature_hex"),
            "issued_at": _check_ts(self.issued_at, "issued_at"),
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }

    def digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class ClaimGroundingRegistry:
    """Authority-signed log of claim groundings."""

    authorities: AuthorityRegistry
    log: list[GroundedClaimReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        claim_id: str,
        claim_digest: str,
        evaluation_id: str,
        locations: tuple[SourceLocation, ...],
        authority_id: str,
        signature: bytes,
        issued_at: int,
    ) -> GroundedClaimReceipt:
        if not locations:
            raise ProcurementError("locations must be non-empty")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProcurementError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = GroundedClaimReceipt(
            receipt_id=receipt_id,
            claim_id=claim_id,
            claim_digest=_check_hex64(claim_digest, "claim_digest"),
            evaluation_id=evaluation_id,
            locations=tuple(locations),
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex="00" * 64,
            issued_at=_check_ts(issued_at, "issued_at"),
            prev_digest=prev,
        )
        signature_hex = signature.hex() if isinstance(signature, bytes) else signature
        _check_sig_hex(signature_hex, "signature")
        if not _verify_signature(pubkey, receipt._payload(), signature_hex):
            raise ProcurementError("authority signature invalid for grounding receipt")
        sealed = type(receipt)(**{**receipt.__dict__, "signature_hex": signature_hex})
        digest = jcs_sha256_hex(sealed._payload())
        sealed = type(sealed)(**{**sealed.__dict__, "receipt_digest": digest})
        self.log.append(sealed)
        return sealed


def source_grounding_receipt(
    registry: ClaimGroundingRegistry,
    claim_id: str,
    claim_digest: str,
) -> ProcurementVerdict:
    """Every AI evaluation claim must bind original-tender-text locations.

    A claim with no grounding receipt — or a receipt whose digest
    does not recompute — is NON_AUTHORITATIVE
    (``procurement.ungrounded_claim``): it may sit in the working
    papers as auxiliary material, but it cannot support a score.
    """
    _check_nonempty_str(claim_id, "claim_id")
    _check_hex64(claim_digest, "claim_digest")
    try:
        _check_chain(registry.log, "grounding")
    except ProcurementError as exc:
        return _deny(DENY_CHAIN_BROKEN, str(exc))
    for receipt in registry.log:
        if receipt.claim_id == claim_id and hmac.compare_digest(
            receipt.claim_digest, claim_digest
        ):
            return _allow(
                f"claim {claim_id!r} grounded at "
                f"{len(receipt.locations)} original-text location(s)",
                receipt_digest=receipt.receipt_digest,
            )
    return _deny(
        DENY_UNGROUNDED_CLAIM,
        f"claim {claim_id!r} has no bound original-tender-text location; "
        "it is auxiliary material only and cannot support a score",
    )


# ---------------------------------------------------------------------------
# 3. Tender-doc pre-issuance health checks (China "先体检再发布" lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HealthCheckReceipt:
    """A tender document's pre-issuance health-check claim.

    ``checks_run`` is a closed vocabulary: the checks are declared,
    not free text. The receipt is signed by the publishing authority
    and expires — a stale health check is an unscreened document.
    """

    receipt_id: str
    doc_id: str
    doc_digest: str
    checks_run: tuple[str, ...]
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = PROCUREMENT_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": _check_nonempty_str(self.receipt_id, "receipt_id"),
            "doc_id": _check_nonempty_str(self.doc_id, "doc_id"),
            "doc_digest": _check_hex64(self.doc_digest, "doc_digest"),
            "checks_run": [_check_health_check(c) for c in self.checks_run],
            "authority_id": _check_nonempty_str(self.authority_id, "authority_id"),
            "authority_pubkey_hex": _check_pubkey_hex(self.authority_pubkey_hex),
            "signature_hex": _check_sig_hex(self.signature_hex, "signature_hex"),
            "issued_at": _check_ts(self.issued_at, "issued_at"),
            "expires_at": _check_ts(self.expires_at, "expires_at"),
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }

    def digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class HealthCheckRegistry:
    """Authority-signed log of pre-issuance health checks."""

    authorities: AuthorityRegistry
    log: list[HealthCheckReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        doc_id: str,
        doc_digest: str,
        checks_run: tuple[str, ...],
        authority_id: str,
        signature: bytes,
        issued_at: int,
        expires_at: int,
    ) -> HealthCheckReceipt:
        if not checks_run:
            raise ProcurementError("checks_run must be non-empty")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProcurementError(f"unknown authority {authority_id!r}")
        if expires_at <= issued_at:
            raise ProcurementError("expires_at must be after issued_at")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = HealthCheckReceipt(
            receipt_id=receipt_id,
            doc_id=doc_id,
            doc_digest=_check_hex64(doc_digest, "doc_digest"),
            checks_run=tuple(checks_run),
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex="00" * 64,
            issued_at=_check_ts(issued_at, "issued_at"),
            expires_at=_check_ts(expires_at, "expires_at"),
            prev_digest=prev,
        )
        signature_hex = signature.hex() if isinstance(signature, bytes) else signature
        _check_sig_hex(signature_hex, "signature")
        if not _verify_signature(pubkey, receipt._payload(), signature_hex):
            raise ProcurementError("authority signature invalid for health-check receipt")
        sealed = type(receipt)(**{**receipt.__dict__, "signature_hex": signature_hex})
        digest = jcs_sha256_hex(sealed._payload())
        sealed = type(sealed)(**{**sealed.__dict__, "receipt_digest": digest})
        self.log.append(sealed)
        return sealed


def tender_doc_screen(
    registry: HealthCheckRegistry,
    doc_id: str,
    doc_digest: str,
    now: int,
) -> ProcurementVerdict:
    """A tender document must pass its health check before publication.

    No live, authority-signed, digest-matching receipt for this exact
    document → ``procurement.unscreened_doc`` (fail-closed). An
    expired receipt is an unscreened document: the checks were run
    against a world that no longer exists.
    """
    _check_nonempty_str(doc_id, "doc_id")
    _check_hex64(doc_digest, "doc_digest")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "healthcheck")
    except ProcurementError as exc:
        return _deny(DENY_CHAIN_BROKEN, str(exc))
    for receipt in registry.log:
        if receipt.doc_id == doc_id and hmac.compare_digest(
            receipt.doc_digest, doc_digest
        ):
            if now > receipt.expires_at:
                return _deny(
                    DENY_UNSCREENED_DOC,
                    f"doc {doc_id!r} health check expired at "
                    f"{receipt.expires_at}; an expired check is an unscreened document",
                )
            return _allow(
                f"doc {doc_id!r} screened with "
                f"{len(receipt.checks_run)} check(s) before issuance",
                receipt_digest=receipt.receipt_digest,
            )
    return _deny(
        DENY_UNSCREENED_DOC,
        f"doc {doc_id!r} has no pre-issuance health-check receipt; "
        "publish is refused until the doc is screened",
    )


# ---------------------------------------------------------------------------
# 4. Collusion probes (UK CMA BRIT lesson: leads, never convictions)
# ---------------------------------------------------------------------------


def collusion_probe(
    price_pattern_digest: str | None,
    comms_metadata_digest: str | None,
    structural_signal_digest: str | None,
    score: float | None,
    threshold: float,
) -> ProcurementVerdict:
    """A bid-rigging probe produces a lead, never an automatic conviction.

    The triple binding (price pattern + communication metadata +
    structural market signal) must be complete and the score must meet
    the threshold before a lead is raised. A raised lead is
    NON_AUTHORITATIVE ``procurement.collusion_lead``: it routes to
    human investigators; the probe cannot disqualify a bidder.
    Incomplete evidence cannot conclude anything
    (``procurement.incomplete_collusion_evidence``) — fail-closed
    against single-signal fishing expeditions.
    """
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
        raise ProcurementError("threshold must be a number")
    if not (0.0 <= threshold <= 1.0):
        raise ProcurementError("threshold must be in [0, 1]")
    for name, value in (
        ("price_pattern_digest", price_pattern_digest),
        ("comms_metadata_digest", comms_metadata_digest),
        ("structural_signal_digest", structural_signal_digest),
    ):
        if value is not None and not _is_hex(value, _HEX64_LENGTH):
            raise ProcurementError(f"{name} must be a 64-char hex digest or None")
    if score is not None and (
        not isinstance(score, (int, float)) or isinstance(score, bool)
    ):
        raise ProcurementError("score must be a number in [0, 1] or None")
    if score is not None and not (0.0 <= score <= 1.0):
        raise ProcurementError("score must be a number in [0, 1] or None")

    bound = [d for d in (price_pattern_digest, comms_metadata_digest, structural_signal_digest) if d]
    if len(bound) < 3 or score is None:
        return _deny(
            DENY_INCOMPLETE_COLLUSION,
            f"collusion probe evidence incomplete ({len(bound)}/3 digests bound); "
            "a probe cannot conclude on partial evidence",
        )
    if score >= threshold:
        return _deny(
            DENY_COLLUSION_LEAD,
            f"collusion lead raised (score {score:.2f} >= threshold {threshold:.2f}); "
            "this is a lead for human investigators, not a conviction — "
            "the probe cannot disqualify any bidder",
        )
    return _allow(
        f"collusion probe complete; score {score:.2f} below threshold "
        f"{threshold:.2f}: no lead"
    )


# ---------------------------------------------------------------------------
# 5. Losing-bid data gate (CMA bottleneck lesson)
# ---------------------------------------------------------------------------


def losing_bid_data_gate(
    evaluation_id: str,
    n_winner_bids: int,
    n_losing_bids: int,
    min_losing_bids: int,
) -> ProcurementVerdict:
    """Evaluations without losing-bid data auto-degrade in confidence.

    Bid-rigging is invisible in winners-only data (the CMA BRIT
    bottleneck). An evaluation with fewer losing bids than the
    declared minimum is NON_AUTHORITATIVE
    ``procurement.missing_losing_bids``: it may inform, but it cannot
    certify a clean competition.
    """
    _check_nonempty_str(evaluation_id, "evaluation_id")
    for name, value in (
        ("n_winner_bids", n_winner_bids),
        ("n_losing_bids", n_losing_bids),
        ("min_losing_bids", min_losing_bids),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ProcurementError(f"{name} must be a non-negative int")
    if n_losing_bids < min_losing_bids:
        return _deny(
            DENY_MISSING_LOSING_BIDS,
            f"evaluation {evaluation_id!r} sees {n_losing_bids} losing bid(s) "
            f"against a minimum of {min_losing_bids}; winners-only data "
            "cannot certify a clean competition — confidence degraded",
        )
    return _allow(
        f"evaluation {evaluation_id!r} binds {n_losing_bids} losing bid(s) "
        f"({n_winner_bids} winner(s)); collusion screening data complete"
    )


# ---------------------------------------------------------------------------
# 6. Incumbency-bias probe (the 4x anecdote mechanized)
# ---------------------------------------------------------------------------


def incumbency_bias_probe(
    new_supplier_rejected: int,
    new_supplier_total: int,
    incumbent_rejected: int,
    incumbent_total: int,
    tolerance: float,
) -> ProcurementVerdict:
    """Flag when new suppliers are rejected far more often than incumbents.

    When the new-supplier rejection rate exceeds the incumbent rate by
    more than ``tolerance``, the probe denies with
    ``procurement.incumbency_bias`` and routes the evaluation to
    audit. The probe does not decide *why* the gap exists — that is
    the audit's job.
    """
    for name, value in (
        ("new_supplier_rejected", new_supplier_rejected),
        ("new_supplier_total", new_supplier_total),
        ("incumbent_rejected", incumbent_rejected),
        ("incumbent_total", incumbent_total),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ProcurementError(f"{name} must be a non-negative int")
    if new_supplier_total == 0 or incumbent_total == 0:
        raise ProcurementError("both supplier groups need a non-zero total")
    if new_supplier_rejected > new_supplier_total:
        raise ProcurementError("new_supplier_rejected cannot exceed new_supplier_total")
    if incumbent_rejected > incumbent_total:
        raise ProcurementError("incumbent_rejected cannot exceed incumbent_total")
    if not isinstance(tolerance, (int, float)) or isinstance(tolerance, bool):
        raise ProcurementError("tolerance must be a number")
    if not (0.0 <= tolerance <= 1.0):
        raise ProcurementError("tolerance must be in [0, 1]")

    new_rate = new_supplier_rejected / new_supplier_total
    incumbent_rate = incumbent_rejected / incumbent_total
    deviation = new_rate - incumbent_rate
    if deviation > tolerance:
        return _deny(
            DENY_INCUMBENCY_BIAS,
            f"new-supplier rejection rate {new_rate:.2%} exceeds incumbent "
            f"{incumbent_rate:.2%} by {deviation:.2%} (tolerance {tolerance:.2%}); "
            "evaluation routed to audit for incumbency bias",
        )
    return _allow(
        f"rejection-rate deviation {deviation:.2%} within tolerance "
        f"{tolerance:.2%}: no incumbency-bias flag"
    )


# ---------------------------------------------------------------------------
# 7. Algorithm registration receipts (China "算法登记审查" lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlgorithmRegistrationReceipt:
    """A deployed evaluation algorithm's registration claim.

    Binds the algorithm id, the exact version, and the digest of the
    independent review the algorithm passed before deployment. The
    registration expires: a deployed version with no live
    registration cannot be called.
    """

    receipt_id: str
    algorithm_id: str
    version: str
    review_digest: str
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    registered_at: int
    expires_at: int
    revoked: bool = False
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = PROCUREMENT_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": _check_nonempty_str(self.receipt_id, "receipt_id"),
            "algorithm_id": _check_nonempty_str(self.algorithm_id, "algorithm_id"),
            "version": _check_nonempty_str(self.version, "version"),
            "review_digest": _check_hex64(self.review_digest, "review_digest"),
            "authority_id": _check_nonempty_str(self.authority_id, "authority_id"),
            "authority_pubkey_hex": _check_pubkey_hex(self.authority_pubkey_hex),
            "signature_hex": _check_sig_hex(self.signature_hex, "signature_hex"),
            "registered_at": _check_ts(self.registered_at, "registered_at"),
            "expires_at": _check_ts(self.expires_at, "expires_at"),
            "revoked": _check_bool(self.revoked, "revoked"),
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }

    def digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class AlgorithmRegistry:
    """Authority-signed log of evaluation-algorithm registrations."""

    authorities: AuthorityRegistry
    log: list[AlgorithmRegistrationReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []
        # Revocations live outside the sealed receipts: mutating a
        # sealed receipt would break its digest/signature.
        self._revoked: set[str] = set()

    def revoked(self, receipt_id: str) -> bool:
        return receipt_id in self._revoked

    def issue(
        self,
        receipt_id: str,
        algorithm_id: str,
        version: str,
        review_digest: str,
        authority_id: str,
        signature: bytes,
        registered_at: int,
        expires_at: int,
    ) -> AlgorithmRegistrationReceipt:
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProcurementError(f"unknown authority {authority_id!r}")
        if expires_at <= registered_at:
            raise ProcurementError("expires_at must be after registered_at")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = AlgorithmRegistrationReceipt(
            receipt_id=receipt_id,
            algorithm_id=algorithm_id,
            version=version,
            review_digest=_check_hex64(review_digest, "review_digest"),
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex="00" * 64,
            registered_at=_check_ts(registered_at, "registered_at"),
            expires_at=_check_ts(expires_at, "expires_at"),
            prev_digest=prev,
        )
        signature_hex = signature.hex() if isinstance(signature, bytes) else signature
        _check_sig_hex(signature_hex, "signature")
        if not _verify_signature(pubkey, receipt._payload(), signature_hex):
            raise ProcurementError("authority signature invalid for algorithm registration")
        sealed = type(receipt)(**{**receipt.__dict__, "signature_hex": signature_hex})
        digest = jcs_sha256_hex(sealed._payload())
        sealed = type(sealed)(**{**sealed.__dict__, "receipt_digest": digest})
        self.log.append(sealed)
        return sealed

    def revoke(self, receipt_id: str) -> None:
        for entry in self.log:
            if entry.receipt_id == receipt_id:
                self._revoked.add(receipt_id)
                return
        raise ProcurementError(f"unknown registration {receipt_id!r}")


def algorithm_registry_receipt(
    registry: AlgorithmRegistry,
    algorithm_id: str,
    version: str,
    now: int,
) -> ProcurementVerdict:
    """A deployed evaluation algorithm must carry a live registration.

    Calls to an unregistered algorithm — or one whose registration
    has expired — deny ``procurement.unregistered_algorithm``. A
    revoked registration denies ``procurement.revoked_algorithm``.
    The gate binds the *exact version*: registering v1 does not
    authorize calling v2.
    """
    _check_nonempty_str(algorithm_id, "algorithm_id")
    _check_nonempty_str(version, "version")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "algorithm")
    except ProcurementError as exc:
        return _deny(DENY_CHAIN_BROKEN, str(exc))
    for receipt in registry.log:
        if receipt.algorithm_id == algorithm_id and receipt.version == version:
            if registry.revoked(receipt.receipt_id):
                return _deny(
                    DENY_REVOKED_ALGORITHM,
                    f"algorithm {algorithm_id!r} version {version!r} "
                    "registration was revoked; calls are refused",
                )
            if now > receipt.expires_at:
                return _deny(
                    DENY_UNREGISTERED_ALGORITHM,
                    f"algorithm {algorithm_id!r} version {version!r} "
                    "registration expired; calls are refused until re-registered",
                )
            return _allow(
                f"algorithm {algorithm_id!r} version {version!r} carries a "
                "live reviewed registration",
                receipt_digest=receipt.receipt_digest,
            )
    return _deny(
        DENY_UNREGISTERED_ALGORITHM,
        f"algorithm {algorithm_id!r} version {version!r} has no registration; "
        "calls are refused until the algorithm is registered and reviewed",
    )


# ---------------------------------------------------------------------------
# 8. Full-trace awards (4-segment evidence chain)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AwardTrace:
    """An award's 4-segment evidence chain.

    Binds (AI input digest, AI output digest, human-edits digest,
    final-reasons digest). The final reasons must additionally carry
    the named human evaluator's signature — a reasons document nobody
    signed is not accountability.
    """

    trace_id: str
    award_id: str
    evaluator_id: str
    ai_input_digest: str | None
    ai_output_digest: str | None
    human_edits_digest: str | None
    final_reasons_digest: str | None
    reasons_signature_hex: str | None
    reasons_pubkey_hex: str | None
    traced_at: int

    def _payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "trace_id": _check_nonempty_str(self.trace_id, "trace_id"),
            "award_id": _check_nonempty_str(self.award_id, "award_id"),
            "evaluator_id": _check_nonempty_str(self.evaluator_id, "evaluator_id"),
            "traced_at": _check_ts(self.traced_at, "traced_at"),
        }
        for name in (
            "ai_input_digest",
            "ai_output_digest",
            "human_edits_digest",
            "final_reasons_digest",
        ):
            value = getattr(self, name)
            if value is not None:
                _check_hex64(value, name)
            payload[name] = value
        return payload


def full_trace_award(
    trace: AwardTrace,
    no_ai_involved: bool = False,
) -> ProcurementVerdict:
    """An award must bind the 4-segment evidence chain.

    AI input → AI output → human edits → final reasons, each pinned
    by digest, with the final reasons signed by the named evaluator.
    A missing segment is ``procurement.incomplete_trace``; unsigned
    final reasons are ``procurement.unsigned_reasons``. When no AI was
    involved at all (``no_ai_involved=True``), the AI segments may be
    absent — but the human segments and the signature are still
    required.
    """
    if not isinstance(no_ai_involved, bool):
        raise ProcurementError("no_ai_involved must be a bool")
    payload = trace._payload()  # validates structure
    if not no_ai_involved:
        for name in ("ai_input_digest", "ai_output_digest"):
            if payload[name] is None:
                return _deny(
                    DENY_INCOMPLETE_TRACE,
                    f"award {trace.award_id!r} trace missing {name}; "
                    "the 4-segment evidence chain is incomplete",
                )
    for name in ("human_edits_digest", "final_reasons_digest"):
        if payload[name] is None:
            return _deny(
                DENY_INCOMPLETE_TRACE,
                f"award {trace.award_id!r} trace missing {name}; "
                "the 4-segment evidence chain is incomplete",
            )
    if trace.reasons_signature_hex is None or trace.reasons_pubkey_hex is None:
        return _deny(
            DENY_UNSIGNED_REASONS,
            f"award {trace.award_id!r} final reasons carry no evaluator signature; "
            "an unsigned reasons document is not accountability",
        )
    reasons_payload = {
        "award_id": trace.award_id,
        "evaluator_id": trace.evaluator_id,
        "final_reasons_digest": trace.final_reasons_digest,
    }
    if not _verify_signature(
        trace.reasons_pubkey_hex, reasons_payload, trace.reasons_signature_hex
    ):
        return _deny(
            DENY_UNSIGNED_REASONS,
            f"award {trace.award_id!r} final-reasons signature does not verify "
            f"against evaluator {trace.evaluator_id!r}",
        )
    return _allow(
        f"award {trace.award_id!r}: 4-segment evidence chain complete and "
        f"final reasons signed by evaluator {trace.evaluator_id!r}",
        receipt_digest=jcs_sha256_hex(payload),
    )


__all__ = [
    "PROCUREMENT_SCHEMA_VERSION",
    "CLASS_AUTHORITATIVE",
    "CLASS_NON_AUTHORITATIVE",
    "HEALTH_CHECKS",
    "DENY_AI_CONCLUDED",
    "DENY_NO_HUMAN_ACCOUNTABILITY",
    "DENY_UNGROUNDED_CLAIM",
    "DENY_UNSCREENED_DOC",
    "DENY_COLLUSION_LEAD",
    "DENY_INCOMPLETE_COLLUSION",
    "DENY_MISSING_LOSING_BIDS",
    "DENY_INCUMBENCY_BIAS",
    "DENY_UNREGISTERED_ALGORITHM",
    "DENY_REVOKED_ALGORITHM",
    "DENY_INCOMPLETE_TRACE",
    "DENY_UNSIGNED_REASONS",
    "DENY_CHAIN_BROKEN",
    "ProcurementError",
    "ProcurementVerdict",
    "AuthorityRegistry",
    "SourceLocation",
    "GroundedClaimReceipt",
    "ClaimGroundingRegistry",
    "HealthCheckReceipt",
    "HealthCheckRegistry",
    "AlgorithmRegistrationReceipt",
    "AlgorithmRegistry",
    "AwardTrace",
    "advisory_only_gate",
    "source_grounding_receipt",
    "tender_doc_screen",
    "collusion_probe",
    "losing_bid_data_gate",
    "incumbency_bias_probe",
    "algorithm_registry_receipt",
    "full_trace_award",
]
