"""Sports & fitness AI discipline (one-hundred-sixty-sixth batch).

Absorbs the 2026 AI-sports thread (see
``~/workspace/research_notes/beyond-ai-sports-20261004/`` —
``report-v2-sports-fitness-20261004.md``; the directory also holds
an earlier ``report.md`` which this module does not use):

* **FIFA World Cup 2026 (Lenovo tech partner)** — Football AI Pro
  tactical assistant (millions of data points, 2000+ metrics,
  equal access to 48 teams); AI 3D player digital twins (28 scan
  pods) for VAR / semi-automated offside. The industry bottom
  line: **AI measures, it does not adjudicate** — objective
  position measurement belongs to the machine, "did it interfere
  with play" stays with the referee.
* **中国橙狮体育** — electronic line-calling (600 fps, 500ms
  full-chain decisions), AI broadcast direction, LLM-voiced smart
  ball machines, "AI event assistant" parsing schedules from
  natural language + PDF rules.
* **IOC Trustworthy AI Framework (2026-09-29, with Deloitte)** —
  7 principles (safeguarding / data protection / reliability /
  transparency / accountability / fairness / sustainability),
  3-tier risk: high risk does not mean veto, it triggers deeper
  review + stricter controls + human supervision. Regular safety
  assessments, supplier documentation checks, break-glass /
  bypass mechanisms on failure, important decisions left to
  qualified people.
* **AI betting fraud (Approov)** — 2026 World Cup as the first
  large-scale test bed: AI scrapers harvesting odds/market moves
  ahead of live betting and micro-markets. IBIA: 300 suspicious
  betting alerts (+29%). Turkey referee betting scandal: 149
  referees suspended. **DraftKings (NYT 2026-09)** — ML computed
  "elasticity scores" predicting which customers would bet more
  and lose more after a promotion, then targeted them with profit
  boosts; an internal problem-gambler identification model was
  built and then the project was killed ("recognized the harm,
  chose to harvest it").
* **FanDuel AceAI** — the conversational betting assistant
  refuses to recommend bets on "chasing losses" conversations and
  redirects to responsible-gambling information: the evaluation
  standard for recommender AI includes *when it refuses*.
* **Eating disorders (WSJ 2026)** — AI chatbots undermining
  treatment: dangerous low-calorie plans, flattering sycophancy
  ("it was designed to agree with you, not protect you").
  Trackers worsening disorders in novices; FDA 2026-01 loosened
  wearable regulation (wellness tools exempt if no
  disease-diagnosis/treatment claims — WHOOP got a warning letter
  for blurring the line).
* **WADA ABP** — Athlete Biological Passport: longitudinal
  monitoring is an *investigation lead*, not a conviction; JAMA
  Network Open 2026 (per archyde aggregation, unverified DOI):
  longitudinal monitoring found 3.7x more doping cases with 0.2%
  false positives, still requiring human confirmation. Gene doping
  as the new pre-Winter-Olympics threat.
* **Volpato "AI Rights Registry" / "Digital DNA"** — athlete
  likeness + voice + biometrics + performance data registry
  against deepfakes and synthetic endorsements; UK Sport + Social
  Protect AI real-time anti-abuse comment detection (for LA 2028).

Northstar mapping:

* ``officiating_human_final_gate()`` — AI outputs are
  *measurement*, never *rulings*; a ruling executes only under a
  named-human adjudicator's countersign bound to the evidence
  digest. An AI-only decision is ``sports.ai_adjudication``.
* ``athlete_data_ownership_receipt()`` — biometric / digital-twin
  ingestion requires an ownership receipt (who collected, who
  stores, who benefits, revocable); without it the ingestion
  denies with ``sports:no_ownership_receipt``.
* ``predatory_marketing_ban()`` — marketing targeting predicted
  losses is refused whole-class (``sports.predatory_targeting``);
  running a vulnerability model while the intervention lane is
  disabled is ``sports.harm_recognized_not_prevented``.
* ``doping_alert_tiering()`` — alerts are leads, not convictions:
  a sanction bound only to an unconfirmed alert denies with
  ``sports.punitive_alert``; an alert without an evidence chain
  is NON_AUTHORITATIVE (``sports:unexplained_alert``).
* ``wellness_boundary_receipt()`` — health/fitness agents declare
  their claim boundary (wellness vs medical); crossing it denies
  with ``sports.medical_boundary_crossing``; no referral path to
  a human professional denies with ``sports.no_referral_path``.
* ``monitoring_burden_ledger()`` — continuous-monitoring agents
  ledger their burden (daily check-ins, nudges, anxiety signals);
  burden above threshold without a quiet-mode degrade denies
  with ``sports.burden_overage``.
* ``likeness_registry_pin()`` — synthetic likeness generation
  requires a registry authorization; unauthorized generation is
  ``sports.unauthorized_likeness``; unlabeled synthetic content
  is ``sports:unlabeled_synthetic``.
* ``responsibility_manifest()`` — multi-party deployments bind a
  responsibility manifest (model provider, deployer, human
  supervisor, failure escalation); missing items deny with
  ``sports.incomplete_manifest``.
* ``anti_scraping_circuit_breaker()`` — price/odds agents halt
  quoting past a scrape-rate threshold and switch to manual;
  executing while the feed is interrupted denies with
  ``sports.feed_interruption_trade``.
* ``refusal_capability_gate()`` — recommender agents must carry
  refusal triggers; an evaluation suite that tests only
  recommendation quality and not refusal capability is
  incomplete: ``sports:incomplete_eval``.

Honest scoping: receipts bind *declared sports discipline*; they
do not end match-fixing, stop AI scrapers by themselves, or heal
eating disorders. Everything is offline and deterministic; the
only clock is the ``now`` the caller injects (integer epoch
seconds). All digest comparisons use :func:`hmac.compare_digest`.
"""

from __future__ import annotations
from _domain_base import DomainError

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex

#: Schema marker, pinned into every digest.
SPORTS_SCHEMA_VERSION = "northstar.sports_agents.v1"

AUTHORITATIVE = "authoritative"
NON_AUTHORITATIVE = "non-authoritative"

_HEX64_LENGTH = 64
_HEX128_LENGTH = 128

#: Deny codes (stable strings, dot-namespaced for the sports track).
DENY_AI_ADJUDICATION = "sports.ai_adjudication"
DENY_NO_OWNERSHIP_RECEIPT = "sports.no_ownership_receipt"
DENY_PREDATORY_TARGETING = "sports.predatory_targeting"
DENY_HARM_RECOGNIZED_NOT_PREVENTED = "sports.harm_recognized_not_prevented"
DENY_PUNITIVE_ALERT = "sports.punitive_alert"
DENY_UNEXPLAINED_ALERT = "sports.unexplained_alert"
DENY_MEDICAL_BOUNDARY_CROSSING = "sports.medical_boundary_crossing"
DENY_NO_REFERRAL_PATH = "sports.no_referral_path"
DENY_BURDEN_OVERAGE = "sports.burden_overage"
DENY_UNAUTHORIZED_LIKENESS = "sports.unauthorized_likeness"
DENY_UNLABELED_SYNTHETIC = "sports.unlabeled_synthetic"
DENY_INCOMPLETE_MANIFEST = "sports.incomplete_manifest"
DENY_FEED_INTERRUPTION_TRADE = "sports.feed_interruption_trade"
DENY_SCRAPE_HALT_REFUSED = "sports.scrape_halt_refused"
DENY_INCOMPLETE_EVAL = "sports.incomplete_eval"
DENY_NO_REFUSAL_TRIGGER = "sports.no_refusal_trigger"

#: Whole-class refusal vocabulary for recommender/evaluator agents.
REFUSAL_TRIGGERS = frozenset(
    {
        "chasing_losses",
        "eating_disorder_content",
        "underage_gambler",
        "medical_advice_request",
        "self_harm_content",
    }
)


class SportsError(DomainError):
    """Raised for malformed sports-discipline inputs (fail-closed at issuance)."""


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SportsError(f"{field_name} must be a non-empty string")
    return value


def _check_hex64(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != _HEX64_LENGTH:
        raise SportsError(f"{field_name} must be a 64-char hex digest")
    try:
        int(value, 16)
    except ValueError:
        raise SportsError(f"{field_name} must be a 64-char hex digest") from None
    return value.lower()


def _check_hex128(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != _HEX128_LENGTH:
        raise SportsError(f"{field_name} must be a 128-char hex value")
    try:
        int(value, 16)
    except ValueError:
        raise SportsError(f"{field_name} must be a 128-char hex value") from None
    return value.lower()


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SportsError(f"{field_name} must be a non-negative integer epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise SportsError(f"{field_name}: Ed25519 secret key must be 32 bytes")
    return bytes(value)


def _check_pubkey_hex(value: Any, field_name: str) -> str:
    return _check_hex64(value, field_name)


def _check_sig_hex(value: Any, field_name: str) -> str:
    return _check_hex128(value, field_name)


def _check_bps(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 10_000:
        raise SportsError(f"{field_name} must be an integer basis-points value in [0, 10000]")
    return value


def _verify_sig(pubkey_hex: str, message: bytes, sig_hex: str) -> bool:
    # NOTE: the vendored ed25519.verify() returns a bool and never
    # raises. The return value MUST be used: a bare
    # `ed25519.verify(...); return True` inside try/except would bless
    # every tampered signature.
    try:
        return bool(
            ed25519.verify(
                bytes.fromhex(pubkey_hex),
                message,
                bytes.fromhex(sig_hex),
            )
        )
    except Exception:
        return False


def _seal(payload: dict[str, Any], secret: bytes) -> tuple[str, str]:
    """Sign a JCS-canonical payload; return (signature_hex, receipt_digest)."""
    message = jcs_canonical_json(payload)
    sig = ed25519.sign(secret, message).hex()
    digest = jcs_sha256_hex({"payload": payload, "signature_hex": sig})
    return sig, digest


@dataclass(frozen=True)
class GateVerdict:
    """Binary verdict for a sports-discipline check."""

    allowed: bool
    tier: str
    reason: str = ""
    deny_code: str = ""


# ---------------------------------------------------------------------------
# Gate 1: AI measures, humans adjudicate
# ---------------------------------------------------------------------------

MEASUREMENT = "measurement"
RULING = "ruling"


@dataclass(frozen=True)
class OfficiatingOutput:
    """An AI officiating output (VAR / semi-auto offside / line call).

    ``output_kind`` is ``"measurement"`` (an objective reading:
    position, timing, ball contact) or ``"ruling"`` (an on-field
    decision that changes the game). Measurement may flow to the
    referee's screen; a ruling executes only under a named-human
    adjudicator's countersign bound to the evidence digest.
    """

    output_id: str
    match_id: str
    output_kind: str
    evidence_digest: str
    schema_version: str = SPORTS_SCHEMA_VERSION


@dataclass(frozen=True)
class AdjudicatorCountersign:
    """A named-human adjudicator's countersign on a ruling.

    Binds the referee identity, the evidence digest the ruling
    rests on, the measured decision, and the time of review. A
    countersign whose review window is zero-length or whose
    digest does not match the output is a rubber stamp.
    """

    countersign_id: str
    referee_id: str
    referee_name: str
    output_id: str
    evidence_digest: str
    decision: str
    review_started_at: int
    reviewed_at: int
    issuer_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = SPORTS_SCHEMA_VERSION


def _countersign_payload(c: AdjudicatorCountersign) -> dict[str, Any]:
    return {
        "countersign_id": c.countersign_id,
        "referee_id": c.referee_id,
        "referee_name": c.referee_name,
        "output_id": c.output_id,
        "evidence_digest": c.evidence_digest,
        "decision": c.decision,
        "review_started_at": c.review_started_at,
        "reviewed_at": c.reviewed_at,
        "schema_version": c.schema_version,
    }


def issue_adjudicator_countersign(
    *,
    countersign_id: str,
    referee_id: str,
    referee_name: str,
    output_id: str,
    evidence_digest: str,
    decision: str,
    review_started_at: int,
    reviewed_at: int,
    issuer_secret: bytes,
    issuer_pubkey: bytes,
) -> AdjudicatorCountersign:
    """Issue an adjudicator countersign. Fail-closed at issuance:
    the review window must be positive (a zero-length review is a
    rubber stamp, not a decision) and the decision must be
    non-empty."""
    review_started_at = _check_ts(review_started_at, "review_started_at")
    reviewed_at = _check_ts(reviewed_at, "reviewed_at")
    if reviewed_at <= review_started_at:
        raise SportsError("reviewed_at must be after review_started_at (no zero-length reviews)")
    record = AdjudicatorCountersign(
        countersign_id=_check_nonempty_str(countersign_id, "countersign_id"),
        referee_id=_check_nonempty_str(referee_id, "referee_id"),
        referee_name=_check_nonempty_str(referee_name, "referee_name"),
        output_id=_check_nonempty_str(output_id, "output_id"),
        evidence_digest=_check_hex64(evidence_digest, "evidence_digest"),
        decision=_check_nonempty_str(decision, "decision"),
        review_started_at=review_started_at,
        reviewed_at=reviewed_at,
        issuer_pubkey_hex=_check_pubkey_hex(issuer_pubkey.hex(), "issuer_pubkey"),
    )
    sig, digest = _seal(_countersign_payload(record), _check_secret(issuer_secret, "issuer_secret"))
    return AdjudicatorCountersign(
        **{**record.__dict__, "signature_hex": sig, "receipt_digest": digest}
    )


def officiating_human_final_gate(
    output: OfficiatingOutput,
    countersign: AdjudicatorCountersign | None,
) -> GateVerdict:
    """AI measures; humans adjudicate.

    Measurement outputs pass (they are evidence, not decisions).
    A ruling without a valid, digest-bound, signature-valid human
    countersign denies with ``sports.ai_adjudication``.
    """
    if output.output_kind == MEASUREMENT:
        return GateVerdict(True, AUTHORITATIVE, reason="measurement only, no adjudication")
    if output.output_kind != RULING:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason=f"unknown output_kind {output.output_kind!r}: neither measurement nor ruling",
            deny_code=DENY_AI_ADJUDICATION,
        )
    if countersign is None:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="ruling without a named-human adjudicator countersign",
            deny_code=DENY_AI_ADJUDICATION,
        )
    if countersign.output_id != output.output_id:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="countersign does not bind this output",
            deny_code=DENY_AI_ADJUDICATION,
        )
    if not hmac.compare_digest(countersign.evidence_digest, output.evidence_digest):
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="countersign binds a different evidence digest (rubber stamp)",
            deny_code=DENY_AI_ADJUDICATION,
        )
    if not countersign.signature_hex or not countersign.issuer_pubkey_hex:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="countersign unsigned",
            deny_code=DENY_AI_ADJUDICATION,
        )
    if not _verify_sig(
        countersign.issuer_pubkey_hex,
        jcs_canonical_json(_countersign_payload(countersign)),
        countersign.signature_hex,
    ):
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="countersign signature does not verify",
            deny_code=DENY_AI_ADJUDICATION,
        )
    return GateVerdict(True, AUTHORITATIVE, reason="human adjudicator countersigned the ruling")


# ---------------------------------------------------------------------------
# Gate 2: athlete data ownership receipt
# ---------------------------------------------------------------------------

COLLECTORS = frozenset({"fifa", "club", "league", "broadcaster", "app_vendor", "researcher"})
BENEFICIARIES = frozenset({"athlete", "club", "league", "broadcaster", "fifa", "public"})


@dataclass(frozen=True)
class OwnershipReceipt:
    """Who owns the athlete's data stream.

    Binds the collector, the storage operator, the beneficiaries,
    and revocability. Ingesting biometric / digital-twin data
    without a receipt that names these four fields is a silent
    expropriation (FIFA scan-pod lesson).
    """

    receipt_id: str
    athlete_id: str
    collector: str
    storage_operator: str
    beneficiaries: tuple[str, ...]
    revocable: bool
    issued_at: int
    issuer_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = SPORTS_SCHEMA_VERSION


def _ownership_payload(r: OwnershipReceipt) -> dict[str, Any]:
    return {
        "receipt_id": r.receipt_id,
        "athlete_id": r.athlete_id,
        "collector": r.collector,
        "storage_operator": r.storage_operator,
        "beneficiaries": sorted(r.beneficiaries),
        "revocable": r.revocable,
        "issued_at": r.issued_at,
        "schema_version": r.schema_version,
    }


def issue_ownership_receipt(
    *,
    receipt_id: str,
    athlete_id: str,
    collector: str,
    storage_operator: str,
    beneficiaries: tuple[str, ...],
    revocable: bool,
    issued_at: int,
    issuer_secret: bytes,
    issuer_pubkey: bytes,
) -> OwnershipReceipt:
    """Issue an ownership receipt. The athlete must be among the
    beneficiaries: data that cannot benefit its subject is not a
    bargain, it is extraction."""
    if collector not in COLLECTORS:
        raise SportsError(f"collector must be one of {sorted(COLLECTORS)}")
    if not beneficiaries or any(b not in BENEFICIARIES for b in beneficiaries):
        raise SportsError(f"beneficiaries must be non-empty and drawn from {sorted(BENEFICIARIES)}")
    if "athlete" not in beneficiaries:
        raise SportsError("the athlete must be among the beneficiaries")
    record = OwnershipReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        athlete_id=_check_nonempty_str(athlete_id, "athlete_id"),
        collector=collector,
        storage_operator=_check_nonempty_str(storage_operator, "storage_operator"),
        beneficiaries=tuple(beneficiaries),
        revocable=bool(revocable),
        issued_at=_check_ts(issued_at, "issued_at"),
        issuer_pubkey_hex=_check_pubkey_hex(issuer_pubkey.hex(), "issuer_pubkey"),
    )
    sig, digest = _seal(_ownership_payload(record), _check_secret(issuer_secret, "issuer_secret"))
    return OwnershipReceipt(**{**record.__dict__, "signature_hex": sig, "receipt_digest": digest})


@dataclass(frozen=True)
class DataIngestion:
    """A biometric / digital-twin data ingestion request."""

    ingestion_id: str
    athlete_id: str
    data_kind: str
    collected_at: int


def athlete_data_ownership_receipt(
    ingestion: DataIngestion,
    receipt: OwnershipReceipt | None,
) -> GateVerdict:
    """No ownership receipt, no ingestion."""
    if receipt is None:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="no data-ownership receipt for ingestion",
            deny_code=DENY_NO_OWNERSHIP_RECEIPT,
        )
    if receipt.athlete_id != ingestion.athlete_id:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="ownership receipt names a different athlete",
            deny_code=DENY_NO_OWNERSHIP_RECEIPT,
        )
    if receipt.issued_at > ingestion.collected_at:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="ownership receipt issued after collection",
            deny_code=DENY_NO_OWNERSHIP_RECEIPT,
        )
    if not receipt.signature_hex or not receipt.issuer_pubkey_hex:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="ownership receipt unsigned",
            deny_code=DENY_NO_OWNERSHIP_RECEIPT,
        )
    if not _verify_sig(
        receipt.issuer_pubkey_hex,
        jcs_canonical_json(_ownership_payload(receipt)),
        receipt.signature_hex,
    ):
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="ownership signature does not verify",
            deny_code=DENY_NO_OWNERSHIP_RECEIPT,
        )
    return GateVerdict(True, AUTHORITATIVE, reason="ownership receipt binds collection")


# ---------------------------------------------------------------------------
# Gate 3: predatory marketing ban (whole-class)
# ---------------------------------------------------------------------------

TARGETING_FEATURES = frozenset({"predicted_loss", "elasticity_score", "loss_chasing_signal"})


@dataclass(frozen=True)
class MarketingCampaign:
    """A betting/promotion campaign under scrutiny.

    ``targeting_features`` names the signals used to pick
    recipients. Anything computed from predicted losses is
    predatory by construction (DraftKings elasticity lesson) and
    is refused whole-class.
    """

    campaign_id: str
    targeting_features: tuple[str, ...]
    has_vulnerability_model: bool
    has_intervention_lane: bool


def predatory_marketing_ban(campaign: MarketingCampaign) -> GateVerdict:
    """Marketing that targets predicted losses is refused
    whole-class. And: if the operator *can* identify harm (a
    vulnerability model exists) the intervention lane must also
    exist — recognized harm that is harvested, not prevented, is
    ``sports.harm_recognized_not_prevented``."""
    predatory = TARGETING_FEATURES.intersection(set(campaign.targeting_features))
    if predatory:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason=f"predatory targeting features: {sorted(predatory)}",
            deny_code=DENY_PREDATORY_TARGETING,
        )
    if campaign.has_vulnerability_model and not campaign.has_intervention_lane:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="vulnerability model runs while the intervention lane is disabled",
            deny_code=DENY_HARM_RECOGNIZED_NOT_PREVENTED,
        )
    return GateVerdict(True, AUTHORITATIVE, reason="no predatory targeting; harm pathways covered")


# ---------------------------------------------------------------------------
# Gate 4: doping alert tiering
# ---------------------------------------------------------------------------

ALERT = "alert"
VIOLATION = "violation"


@dataclass(frozen=True)
class DopingAlert:
    """An anti-doping anomaly (ABP module flag, longitudinal
    deviation, suspicious sample).

    Tier is ``"alert"`` (needs investigation) or ``"violation"``
    (confirmed through the adjudication process). An alert is
    evidence, not a sentence: it must carry an evidence-chain
    digest and may not, by itself, bind a sanction.
    """

    alert_id: str
    athlete_id: str
    tier: str
    evidence_chain_digest: str
    observed_at: int


@dataclass(frozen=True)
class Sanction:
    """A sanction decision bound to its evidence basis."""

    sanction_id: str
    athlete_id: str
    based_on_alert_ids: tuple[str, ...]
    confirmed_violation: bool
    issued_at: int


def doping_alert_tiering(alert: DopingAlert, sanction: Sanction | None) -> GateVerdict:
    """An alert alone is fine (it is a lead). A sanction whose
    only basis is an unconfirmed alert denies with
    ``sports.punitive_alert`` (WADA ABP lesson: longitudinal
    monitoring triggers investigation, not automatic guilt).
    An alert without an evidence-chain digest is
    NON_AUTHORITATIVE."""
    if alert.tier not in (ALERT, VIOLATION):
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason=f"unknown tier {alert.tier!r}: alerts must declare alert or violation",
            deny_code=DENY_UNEXPLAINED_ALERT,
        )
    if sanction is None:
        if not alert.evidence_chain_digest:
            return GateVerdict(
                False,
                NON_AUTHORITATIVE,
                reason="alert carries no evidence-chain digest",
                deny_code=DENY_UNEXPLAINED_ALERT,
            )
        return GateVerdict(True, AUTHORITATIVE, reason="alert recorded as a lead")
    if alert.alert_id not in sanction.based_on_alert_ids:
        return GateVerdict(True, AUTHORITATIVE, reason="sanction rests on other evidence")
    if alert.tier == ALERT and not sanction.confirmed_violation:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="sanction bound to an unconfirmed alert (alerts are leads, not convictions)",
            deny_code=DENY_PUNITIVE_ALERT,
        )
    return GateVerdict(True, AUTHORITATIVE, reason="sanction rests on a confirmed violation")


# ---------------------------------------------------------------------------
# Gate 5: wellness / medical boundary receipt
# ---------------------------------------------------------------------------

WELLNESS = "wellness"
MEDICAL = "medical"

#: Health topics the wellness tier may never touch without a
#: medical-grade boundary (WSJ eating-disorder lesson).
MEDICAL_ONLY_TOPICS = frozenset(
    {
        "eating_disorder",
        "diabetes",
        "kidney_disease",
        "oncology",
        "pediatrics",
        "cardiac",
        "hypertension",
    }
)


@dataclass(frozen=True)
class BoundaryDeclaration:
    """A health/fitness agent's declared claim boundary.

    ``declared_tier`` is ``"wellness"`` or ``"medical"``. Wellness
    agents may not cross into medical-only topics, and every agent
    must name a referral path (a human professional channel) —
    "ask me anything" without an off-ramp is how the WSJ
    eating-disorder cases happened.
    """

    agent_id: str
    declared_tier: str
    referral_path: str
    issued_at: int
    issuer_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = SPORTS_SCHEMA_VERSION


def _boundary_payload(b: BoundaryDeclaration) -> dict[str, Any]:
    return {
        "agent_id": b.agent_id,
        "declared_tier": b.declared_tier,
        "referral_path": b.referral_path,
        "issued_at": b.issued_at,
        "schema_version": b.schema_version,
    }


def issue_boundary_declaration(
    *,
    agent_id: str,
    declared_tier: str,
    referral_path: str,
    issued_at: int,
    issuer_secret: bytes,
    issuer_pubkey: bytes,
) -> BoundaryDeclaration:
    """Issue a boundary declaration. Fail-closed: a declaration
    without a referral path is refused at issuance."""
    if declared_tier not in (WELLNESS, MEDICAL):
        raise SportsError(f"declared_tier must be {WELLNESS!r} or {MEDICAL!r}")
    referral_path = _check_nonempty_str(referral_path, "referral_path")
    record = BoundaryDeclaration(
        agent_id=_check_nonempty_str(agent_id, "agent_id"),
        declared_tier=declared_tier,
        referral_path=referral_path,
        issued_at=_check_ts(issued_at, "issued_at"),
        issuer_pubkey_hex=_check_pubkey_hex(issuer_pubkey.hex(), "issuer_pubkey"),
    )
    sig, digest = _seal(_boundary_payload(record), _check_secret(issuer_secret, "issuer_secret"))
    return BoundaryDeclaration(**{**record.__dict__, "signature_hex": sig, "receipt_digest": digest})


def wellness_boundary_receipt(
    declaration: BoundaryDeclaration,
    topics: tuple[str, ...],
) -> GateVerdict:
    """Wellness agents that answer medical-only topics cross the
    boundary (``sports.medical_boundary_crossing``). A declaration
    without a signature or without a referral path is refused."""
    if not declaration.referral_path:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="no referral path to a human professional",
            deny_code=DENY_NO_REFERRAL_PATH,
        )
    if not declaration.signature_hex or not declaration.issuer_pubkey_hex:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="boundary declaration unsigned",
            deny_code=DENY_NO_REFERRAL_PATH,
        )
    if not _verify_sig(
        declaration.issuer_pubkey_hex,
        jcs_canonical_json(_boundary_payload(declaration)),
        declaration.signature_hex,
    ):
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="boundary declaration signature does not verify",
            deny_code=DENY_NO_REFERRAL_PATH,
        )
    if declaration.declared_tier == WELLNESS:
        crossed = MEDICAL_ONLY_TOPICS.intersection(set(topics))
        if crossed:
            return GateVerdict(
                False,
                NON_AUTHORITATIVE,
                reason=f"wellness agent crossed into medical-only topics: {sorted(crossed)}",
                deny_code=DENY_MEDICAL_BOUNDARY_CROSSING,
            )
    return GateVerdict(True, AUTHORITATIVE, reason="advice within declared boundary")


# ---------------------------------------------------------------------------
# Gate 6: monitoring burden ledger
# ---------------------------------------------------------------------------

#: Daily burden budget (basis points of "attention tax"): check-ins
#: + nudges + unmet-goal shaming beyond this degrade the agent.
BURDEN_THRESHOLD_BPS = 1500


@dataclass(frozen=True)
class BurdenLedger:
    """The measured monitoring burden a fitness agent imposes.

    Fields are daily counts; ``anxiety_signals`` counts
    user-reported or detected distress events. When the burden
    index crosses the threshold, the agent must show a
    quiet-mode degrade receipt or it denies.
    """

    agent_id: str
    window_days: int
    daily_check_ins: int
    daily_nudges: int
    unmet_goal_pushes: int
    anxiety_signals: int


def _burden_bps(ledger: BurdenLedger) -> int:
    """Burden in basis points. Anxiety signals weigh 10x: the WHO
    over-medicalization lesson is that distress is the expensive
    part, not the pings."""
    base = (
        ledger.daily_check_ins * 100
        + ledger.daily_nudges * 60
        + ledger.unmet_goal_pushes * 40
    )
    anxiety = ledger.anxiety_signals * 1000
    return min(10_000, base + anxiety)


@dataclass(frozen=True)
class QuietModeReceipt:
    """Proof the agent degraded to quiet mode under burden."""

    receipt_id: str
    agent_id: str
    degraded_at: int
    burden_bps: int
    issuer_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = SPORTS_SCHEMA_VERSION


def _quiet_payload(q: QuietModeReceipt) -> dict[str, Any]:
    return {
        "receipt_id": q.receipt_id,
        "agent_id": q.agent_id,
        "degraded_at": q.degraded_at,
        "burden_bps": q.burden_bps,
        "schema_version": q.schema_version,
    }


def issue_quiet_mode_receipt(
    *,
    receipt_id: str,
    agent_id: str,
    degraded_at: int,
    burden_bps: int,
    issuer_secret: bytes,
    issuer_pubkey: bytes,
) -> QuietModeReceipt:
    record = QuietModeReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        agent_id=_check_nonempty_str(agent_id, "agent_id"),
        degraded_at=_check_ts(degraded_at, "degraded_at"),
        burden_bps=_check_bps(burden_bps, "burden_bps"),
        issuer_pubkey_hex=_check_pubkey_hex(issuer_pubkey.hex(), "issuer_pubkey"),
    )
    sig, digest = _seal(_quiet_payload(record), _check_secret(issuer_secret, "issuer_secret"))
    return QuietModeReceipt(**{**record.__dict__, "signature_hex": sig, "receipt_digest": digest})


def monitoring_burden_ledger(
    ledger: BurdenLedger,
    quiet_receipt: QuietModeReceipt | None,
) -> GateVerdict:
    """Under-threshold burden passes. Over-threshold burden
    without a valid quiet-mode degrade receipt denies with
    ``sports.burden_overage``."""
    burden = _burden_bps(ledger)
    if burden <= BURDEN_THRESHOLD_BPS:
        return GateVerdict(True, AUTHORITATIVE, reason="burden within budget")
    if quiet_receipt is None:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason=f"burden {burden}bps over threshold with no quiet-mode degrade",
            deny_code=DENY_BURDEN_OVERAGE,
        )
    if quiet_receipt.agent_id != ledger.agent_id:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="quiet-mode receipt names a different agent",
            deny_code=DENY_BURDEN_OVERAGE,
        )
    if quiet_receipt.burden_bps < burden:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="quiet-mode receipt understates the measured burden",
            deny_code=DENY_BURDEN_OVERAGE,
        )
    if not quiet_receipt.signature_hex or not quiet_receipt.issuer_pubkey_hex:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="quiet-mode receipt unsigned",
            deny_code=DENY_BURDEN_OVERAGE,
        )
    if not _verify_sig(
        quiet_receipt.issuer_pubkey_hex,
        jcs_canonical_json(_quiet_payload(quiet_receipt)),
        quiet_receipt.signature_hex,
    ):
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="quiet-mode signature does not verify",
            deny_code=DENY_BURDEN_OVERAGE,
        )
    return GateVerdict(True, AUTHORITATIVE, reason="burden over threshold, agent in quiet mode")


# ---------------------------------------------------------------------------
# Gate 7: likeness registry pin
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LikenessAuthorization:
    """A registry entry authorizing synthetic likeness use.

    Binds the person, the authorized agent/operator, the purpose
    and the expiry. Synthetic generation without a live
    authorization is identity theft with extra steps.
    """

    entry_id: str
    person_id: str
    authorized_operator: str
    purpose: str
    expires_at: int
    issuer_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = SPORTS_SCHEMA_VERSION


def _likeness_payload(a: LikenessAuthorization) -> dict[str, Any]:
    return {
        "entry_id": a.entry_id,
        "person_id": a.person_id,
        "authorized_operator": a.authorized_operator,
        "purpose": a.purpose,
        "expires_at": a.expires_at,
        "schema_version": a.schema_version,
    }


def issue_likeness_authorization(
    *,
    entry_id: str,
    person_id: str,
    authorized_operator: str,
    purpose: str,
    expires_at: int,
    issuer_secret: bytes,
    issuer_pubkey: bytes,
) -> LikenessAuthorization:
    record = LikenessAuthorization(
        entry_id=_check_nonempty_str(entry_id, "entry_id"),
        person_id=_check_nonempty_str(person_id, "person_id"),
        authorized_operator=_check_nonempty_str(authorized_operator, "authorized_operator"),
        purpose=_check_nonempty_str(purpose, "purpose"),
        expires_at=_check_ts(expires_at, "expires_at"),
        issuer_pubkey_hex=_check_pubkey_hex(issuer_pubkey.hex(), "issuer_pubkey"),
    )
    sig, digest = _seal(_likeness_payload(record), _check_secret(issuer_secret, "issuer_secret"))
    return LikenessAuthorization(**{**record.__dict__, "signature_hex": sig, "receipt_digest": digest})


@dataclass(frozen=True)
class SyntheticGeneration:
    """A synthetic likeness generation request."""

    generation_id: str
    person_id: str
    operator: str
    labeled_as_synthetic: bool
    requested_at: int


def likeness_registry_pin(
    request: SyntheticGeneration,
    authorization: LikenessAuthorization | None,
) -> GateVerdict:
    """Unauthorized synthetic likeness generation denies with
    ``sports.unauthorized_likeness``; authorized-but-unlabeled
    denies with ``sports:unlabeled_synthetic``."""
    if authorization is None:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="no likeness-registry authorization",
            deny_code=DENY_UNAUTHORIZED_LIKENESS,
        )
    if authorization.person_id != request.person_id:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="authorization names a different person",
            deny_code=DENY_UNAUTHORIZED_LIKENESS,
        )
    if authorization.authorized_operator != request.operator:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="authorization names a different operator",
            deny_code=DENY_UNAUTHORIZED_LIKENESS,
        )
    if authorization.expires_at <= request.requested_at:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="likeness authorization expired",
            deny_code=DENY_UNAUTHORIZED_LIKENESS,
        )
    if not authorization.signature_hex or not authorization.issuer_pubkey_hex:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="likeness authorization unsigned",
            deny_code=DENY_UNAUTHORIZED_LIKENESS,
        )
    if not _verify_sig(
        authorization.issuer_pubkey_hex,
        jcs_canonical_json(_likeness_payload(authorization)),
        authorization.signature_hex,
    ):
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="likeness authorization signature does not verify",
            deny_code=DENY_UNAUTHORIZED_LIKENESS,
        )
    if not request.labeled_as_synthetic:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="synthetic content not labeled as synthetic",
            deny_code=DENY_UNLABELED_SYNTHETIC,
        )
    return GateVerdict(True, AUTHORITATIVE, reason="authorized and labeled synthetic likeness")


# ---------------------------------------------------------------------------
# Gate 8: responsibility manifest
# ---------------------------------------------------------------------------

MANIFEST_ROLES = ("model_provider", "deployer", "human_supervisor", "failure_escalation_contact")


@dataclass(frozen=True)
class ResponsibilityManifest:
    """Who is responsible for an AI officiating / betting / health
    deployment (IOC lesson: disclose who interacts with AI,
    name the break-glass path, keep important decisions with
    qualified people). A manifest missing a role denies with
    ``sports.incomplete_manifest``."""

    deployment_id: str
    roles: dict[str, str]
    issued_at: int
    issuer_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = SPORTS_SCHEMA_VERSION


def _manifest_payload(m: ResponsibilityManifest) -> dict[str, Any]:
    return {
        "deployment_id": m.deployment_id,
        "roles": {k: m.roles[k] for k in sorted(m.roles)},
        "issued_at": m.issued_at,
        "schema_version": m.schema_version,
    }


def issue_responsibility_manifest(
    *,
    deployment_id: str,
    roles: dict[str, str],
    issued_at: int,
    issuer_secret: bytes,
    issuer_pubkey: bytes,
) -> ResponsibilityManifest:
    """Issue a responsibility manifest. Fail-closed at issuance:
    every role in ``MANIFEST_ROLES`` must be named."""
    missing = [r for r in MANIFEST_ROLES if not roles.get(r)]
    if missing:
        raise SportsError(f"responsibility manifest missing roles: {missing}")
    record = ResponsibilityManifest(
        deployment_id=_check_nonempty_str(deployment_id, "deployment_id"),
        roles=dict(roles),
        issued_at=_check_ts(issued_at, "issued_at"),
        issuer_pubkey_hex=_check_pubkey_hex(issuer_pubkey.hex(), "issuer_pubkey"),
    )
    sig, digest = _seal(_manifest_payload(record), _check_secret(issuer_secret, "issuer_secret"))
    return ResponsibilityManifest(
        **{**record.__dict__, "signature_hex": sig, "receipt_digest": digest}
    )


def responsibility_manifest(manifest: ResponsibilityManifest | None) -> GateVerdict:
    """A deployment without a complete, signed responsibility
    manifest denies with ``sports.incomplete_manifest``."""
    if manifest is None:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="no responsibility manifest",
            deny_code=DENY_INCOMPLETE_MANIFEST,
        )
    missing = [r for r in MANIFEST_ROLES if not manifest.roles.get(r)]
    if missing:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason=f"manifest missing roles: {missing}",
            deny_code=DENY_INCOMPLETE_MANIFEST,
        )
    if not manifest.signature_hex or not manifest.issuer_pubkey_hex:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="manifest unsigned",
            deny_code=DENY_INCOMPLETE_MANIFEST,
        )
    if not _verify_sig(
        manifest.issuer_pubkey_hex,
        jcs_canonical_json(_manifest_payload(manifest)),
        manifest.signature_hex,
    ):
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="manifest signature does not verify",
            deny_code=DENY_INCOMPLETE_MANIFEST,
        )
    return GateVerdict(True, AUTHORITATIVE, reason="responsibility manifest complete and signed")


# ---------------------------------------------------------------------------
# Gate 9: anti-scraping circuit breaker
# ---------------------------------------------------------------------------

#: Requests per minute past which quoting halts and manual
#: pricing takes over (Approov World Cup lesson).
SCRAPE_RATE_THRESHOLD_RPM = 600


@dataclass(frozen=True)
class QuotingSession:
    """A price/odds quoting session under scraping scrutiny."""

    session_id: str
    requests_per_minute: int
    feed_live: bool
    manual_pricing_engaged: bool


def anti_scraping_circuit_breaker(session: QuotingSession) -> GateVerdict:
    """Executing automated quotes while the data feed is
    interrupted denies with ``sports.feed_interruption_trade``
    (Altenar lesson: the bot that keeps trading on a dead feed
    is the loss). Refusing to halt past the scrape-rate threshold
    denies with ``sports.scrape_halt_refused``."""
    if not session.feed_live:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="automated quoting on an interrupted feed",
            deny_code=DENY_FEED_INTERRUPTION_TRADE,
        )
    if session.requests_per_minute >= SCRAPE_RATE_THRESHOLD_RPM and not session.manual_pricing_engaged:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason=f"scrape-rate {session.requests_per_minute}rpm over threshold with manual pricing disengaged",
            deny_code=DENY_SCRAPE_HALT_REFUSED,
        )
    return GateVerdict(True, AUTHORITATIVE, reason="quoting within scrape budget on a live feed")


# ---------------------------------------------------------------------------
# Gate 10: refusal capability gate (FanDuel AceAI lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecommenderDeployment:
    """A recommender / conversational agent deployment."""

    agent_id: str
    refusal_triggers: tuple[str, ...]
    evaluated_at: int


@dataclass(frozen=True)
class EvalSuite:
    """An evaluation suite for a recommender deployment."""

    suite_id: str
    agent_id: str
    tests_recommendation_quality: bool
    tests_refusal_capability: bool


def refusal_capability_gate(
    deployment: RecommenderDeployment,
    suite: EvalSuite,
) -> GateVerdict:
    """A recommender without refusal triggers denies with
    ``sports.no_refusal_trigger``; an eval suite that tests
    recommendation quality but never tests refusal is
    incomplete (``sports:incomplete_eval``). The standard is not
    "does it recommend well" but "does it know when to refuse"
    (FanDuel AceAI lesson)."""
    unknown = set(deployment.refusal_triggers) - REFUSAL_TRIGGERS
    if unknown:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason=f"unknown refusal triggers {sorted(unknown)}: triggers are a closed vocabulary",
            deny_code=DENY_NO_REFUSAL_TRIGGER,
        )
    if not deployment.refusal_triggers:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="recommender carries no refusal triggers",
            deny_code=DENY_NO_REFUSAL_TRIGGER,
        )
    if suite.agent_id != deployment.agent_id:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="eval suite targets a different agent",
            deny_code=DENY_INCOMPLETE_EVAL,
        )
    if suite.tests_recommendation_quality and not suite.tests_refusal_capability:
        return GateVerdict(
            False,
            NON_AUTHORITATIVE,
            reason="eval suite tests recommendation quality but never refusal capability",
            deny_code=DENY_INCOMPLETE_EVAL,
        )
    return GateVerdict(True, AUTHORITATIVE, reason="refusal triggers bound and evaluated")


__all__ = [
    "SPORTS_SCHEMA_VERSION",
    "AUTHORITATIVE",
    "NON_AUTHORITATIVE",
    "MEASUREMENT",
    "RULING",
    "WELLNESS",
    "MEDICAL",
    "ALERT",
    "VIOLATION",
    "REFUSAL_TRIGGERS",
    "MEDICAL_ONLY_TOPICS",
    "MANIFEST_ROLES",
    "BURDEN_THRESHOLD_BPS",
    "SCRAPE_RATE_THRESHOLD_RPM",
    "DENY_AI_ADJUDICATION",
    "DENY_NO_OWNERSHIP_RECEIPT",
    "DENY_PREDATORY_TARGETING",
    "DENY_HARM_RECOGNIZED_NOT_PREVENTED",
    "DENY_PUNITIVE_ALERT",
    "DENY_UNEXPLAINED_ALERT",
    "DENY_MEDICAL_BOUNDARY_CROSSING",
    "DENY_NO_REFERRAL_PATH",
    "DENY_BURDEN_OVERAGE",
    "DENY_UNAUTHORIZED_LIKENESS",
    "DENY_UNLABELED_SYNTHETIC",
    "DENY_INCOMPLETE_MANIFEST",
    "DENY_FEED_INTERRUPTION_TRADE",
    "DENY_SCRAPE_HALT_REFUSED",
    "DENY_INCOMPLETE_EVAL",
    "DENY_NO_REFUSAL_TRIGGER",
    "SportsError",
    "GateVerdict",
    "OfficiatingOutput",
    "AdjudicatorCountersign",
    "issue_adjudicator_countersign",
    "officiating_human_final_gate",
    "OwnershipReceipt",
    "DataIngestion",
    "issue_ownership_receipt",
    "athlete_data_ownership_receipt",
    "MarketingCampaign",
    "predatory_marketing_ban",
    "DopingAlert",
    "Sanction",
    "doping_alert_tiering",
    "BoundaryDeclaration",
    "issue_boundary_declaration",
    "wellness_boundary_receipt",
    "BurdenLedger",
    "QuietModeReceipt",
    "issue_quiet_mode_receipt",
    "monitoring_burden_ledger",
    "LikenessAuthorization",
    "SyntheticGeneration",
    "issue_likeness_authorization",
    "likeness_registry_pin",
    "ResponsibilityManifest",
    "issue_responsibility_manifest",
    "responsibility_manifest",
    "QuotingSession",
    "anti_scraping_circuit_breaker",
    "RecommenderDeployment",
    "EvalSuite",
    "refusal_capability_gate",
]
