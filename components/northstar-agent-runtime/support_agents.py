"""Customer-service AI discipline (one-hundred-fifty-sixth batch).

Absorbs the 2026 AI-in-customer-service thread, where the same
pattern repeats across deployments: an AI agent is put on the
phone, on chat, or behind the IVR; it starts answering; and the
disciplines that keep it from quietly becoming the deceiver are
identity disclosure, a working human escape, evidenced claims, a
single workforce registry, a surveillance budget, a ban on
workplace emotion inference, a rehire probe after over-automation,
and a circuit breaker for consumer-agent floods.

The absorbed record (sample-limited, non-en sources noted):

* **Klarna reversal**: 2.3M conversations/month through an AI
  agent (2/3 of inquiries), headcount 5,000 -> 3,500; the CEO
  then admitted service quality had dropped and started
  rehiring. The automation saved money and lost the customer —
  the lesson for :func:`rehire_probe` is that "resolved by AI"
  is not a quality metric.
* **Commonwealth Bank of Australia**: cut 45 service roles in
  2025-07, reversed within weeks — the assessment had not
  "adequately considered the relevant business factors", call
  volumes were rising, team leaders were taking calls.
* **China Consumers Association (2026 H1)**: 986k complaints;
  AI-service complaints rising on misleading promises, hard
  human handoffs, and AI-generated misinformation.
* **Air Canada (2024, cited in Ofcom 2026 reporting)**: a
  chatbot misled a customer about bereavement fares; the
  airline was held liable. The lesson for
  :func:`adversarial_claim_receipt` is blunt: an AI's claim
  about fees or promises without a knowledge-base evidence
  digest is a liability, not an answer.
* **EU AI Act Art. 50** (in force 2026-08-02): every EU-facing
  chatbot, voice agent, or virtual agent must disclose "this
  is AI" at the start of the interaction; EUR 15M / 3% of
  global turnover fines. The Digital Omnibus (Regulation (EU)
  2026/1744) deferred high-risk obligations but *kept* Art.
  50. Germany (firmenpresse.de, Deutsch): the disclosure must
  sit prominently in the chat window or greeting — buried in
  the AGB is not enough.
* **EU AI Act Art. 5** (in force 2026-02-02): workplace
  emotion inference is prohibited. The lesson for
  :func:`emotion_inference_ban` needs no nuance: refuse the
  whole class.
* **Ofcom 2026**: operators are liable for what their AI
  tells customers; at least three complaint channels; the
  customer must be told they are interacting with GenAI (CMA
  2026-03 guidance: never let the customer believe the
  service comes from a human). FCA reported surging customer
  complaints being blocked by voicebots.
* **FTC vs Pearl/JustAnswer (2026-01)**: an "AI search"
  funnel was found to be rampant consumer deception, hundreds
  of thousands of consumers lured into monthly subscriptions
  with CEO-level knowledge.
* **FTC vs Cox Media Group (2026-08-29)**: "active listening"
  AI was marketing fiction — the technology was a phantom,
  USD 930,000 in fines. The enforcement pattern: punish
  *lying about AI capability*, not AI itself.
* **Trend Micro (简胜财)**: 2026's biggest invisible threat
  is AI-generated employee profiles and compromised agents —
  the "new generation of insider". The lesson for
  :func:`agent_workforce_registry`: AI and human agents share
  one identity registry; "AI posing as human" is an identity
  fraud, not a marketing choice.
* **Cyber Acoustics ACCESS AI (2026-06)**: continuous
  employee identity verification plus compliance monitoring
  for BPO/remote agents — biometric-style presence
  verification entered the call-center industry. Labor-rights
  activist Wilneida Negron warns about boss-software
  recording worker clicks, scrolls, and inputs to train
  their replacements. The lesson for
  :func:`surveillance_budget`: collection binds purpose,
  scope, and retention; training a replacement model on it
  is overreach.
* **Forrester (transcribed EN)**: consumer-built AI agents
  may flood contact-center queues — at least 3 major brands
  expected to face single-day call peaks of 100x normal
  volume. The lesson for :func:`agent_flood_circuit`: floods
  get a circuit breaker *and* source differentiation, not
  blanket throttling.
* **Recho AI Voice Agent (Japan, PR)**: marketed as "natural
  enough to be indistinguishable from a human" (日本語) —
  under the EU Art. 50 regime that is a compliance risk, not
  a selling point.
* **LG Uplus (Korea)**: ~8M AI-handled consultations/year,
  wait time 47s -> ~5s; customers 65+ prioritized to humans,
  hearing-impaired customers routed to sign-language agents.

The fail-closed discipline in this module:

1. **AI identity is disclosed per session.** A voice/text
   session whose agent lacks a valid disclosure receipt
   denies with ``support:undisclosed_ai`` (Art. 50
   operationalized).
2. **Human handoff completes on a clock.** A handoff that
   does not resolve within the pinned window, or that loops,
   denies with ``support.no_human_escape`` (China Consumers
   Association lesson).
3. **Claims bind evidence.** An AI claim about fees,
   promises, or refunds without a live knowledge-base
   evidence digest is ``NON_AUTHORITATIVE`` —
   ``support.unevidenced_claim`` (Air Canada lesson).
4. **One workforce registry.** An agent acting under a
   registered identity whose claimed kind mismatches the
   registry denies with ``support.identity_fraud``;
   unregistered agents deny with
   ``support:unregistered_agent`` (Trend Micro lesson).
5. **Surveillance binds a budget.** Collection outside the
   declared purpose/scope/retention, or repurposed to train
   a replacement model, denies with
   ``support.surveillance_overreach`` (ACCESS AI / Negron
   lesson).
6. **Emotion inference is refused whole-class.** Any
   workplace emotion-inference request denies with
   ``support.emotion_inference`` (Art. 5 lesson).
7. **Over-automation is probed.** A quality collapse after a
   layoff event denies with ``support.over_automation``
   (Klarna/CBA lesson).
8. **Consumer-agent floods trip a breaker.** Arrivals above
   the flood threshold open the circuit with source
   differentiation — ``support.agent_flood``.

Honest scoping: receipts bind the *declared* support
discipline — digests recompute, signatures verify against
registered keys, chains are visible. They do not prove
"service got better", and they never substitute for human
judgment. A signed disclosure never proves the customer
*understood* it, and a completed handoff never proves the
human *helped*. Service quality is outside this module's
scope.

Deterministic: no wall-clock reads (callers inject integer
epoch timestamps), JCS canonical hashing (95th batch),
Ed25519 via the vendored ``ed25519`` module (97th batch
pattern), digest comparisons via :func:`hmac.compare_digest`.
"""

from __future__ import annotations
from _domain_base import DomainError

from dataclasses import dataclass, field
from typing import Any

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


SUPPORT_SCHEMA_VERSION = "northstar.support_agents.v1"

#: Binary tiers (87th-batch style): a verdict is either authoritative
#: or it is not; the non-authoritative side names a deny code.
AUTHORITATIVE = "authoritative"
NON_AUTHORITATIVE = "non-authoritative"

#: Closed vocabulary of agent kinds in the workforce registry.
AGENT_KINDS: tuple[str, ...] = (
    "ai_voice",
    "ai_text",
    "human",
)

#: Closed vocabulary of claim categories that bind evidence.
CLAIM_CATEGORIES: tuple[str, ...] = (
    "fee",
    "promise",
    "refund",
    "policy",
    "eligibility",
)

#: Closed vocabulary of surveillance purposes.
SURVEILLANCE_PURPOSES: tuple[str, ...] = (
    "quality_assurance",
    "compliance_monitoring",
    "presence_verification",
    "coaching",
)

#: Any purpose involving emotion/sentiment inference is refused
#: whole-class (EU AI Act Art. 5).
EMOTION_INFERENCE_PURPOSES: frozenset[str] = frozenset({
    "emotion_inference",
    "sentiment_scoring",
    "mood_detection",
    "affect_classification",
})

#: Art. 50 operationalized: disclosure must land within this many
#: seconds of session start.
DISCLOSURE_GRACE_SECONDS = 60

#: Deny codes.
DENY_UNDISCLOSED_AI = "support:undisclosed_ai"
DENY_UNREGISTERED_AGENT = "support:unregistered_agent"
DENY_NO_HUMAN_ESCAPE = "support.no_human_escape"
DENY_UNEVIDENCED_CLAIM = "support.unevidenced_claim"
DENY_IDENTITY_FRAUD = "support.identity_fraud"
DENY_SURVEILLANCE_OVERREACH = "support.surveillance_overreach"
DENY_EMOTION_INFERENCE = "support.emotion_inference"
DENY_OVER_AUTOMATION = "support.over_automation"
DENY_AGENT_FLOOD = "support.agent_flood"

_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class SupportError(DomainError):
    """Raised for malformed support-discipline inputs (fail-closed at issuance)."""


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SupportError(f"{field_name} must be a non-empty string")
    return value


def _check_hex64(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != _HEX64_LENGTH:
        raise SupportError(f"{field_name} must be a 64-char hex digest")
    try:
        int(value, 16)
    except ValueError:
        raise SupportError(f"{field_name} must be a 64-char hex digest") from None
    return value.lower()


def _check_hex128(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != _HEX128_LENGTH:
        raise SupportError(f"{field_name} must be a 128-char hex value")
    try:
        int(value, 16)
    except ValueError:
        raise SupportError(f"{field_name} must be a 128-char hex value") from None
    return value.lower()


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SupportError(f"{field_name} must be a non-negative integer epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise SupportError(f"{field_name}: Ed25519 secret key must be 32 bytes")
    return bytes(value)


def _check_pubkey_hex(value: Any, field_name: str) -> str:
    return _check_hex64(value, field_name)


def _check_sig_hex(value: Any, field_name: str) -> str:
    return _check_hex128(value, field_name)


def _check_bps(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 10_000:
        raise SupportError(f"{field_name} must be an integer basis-points value in [0, 10000]")
    return value


def _verify_sig(pubkey_hex: str, message: bytes, sig_hex: str) -> bool:
    # NOTE: the vendored ed25519.verify() returns a bool and never
    # raises (97th-batch module). The return value MUST be used:
    # a bare `ed25519.verify(...); return True` inside try/except
    # would bless every tampered signature. (This bug exists in the
    # older permit_agents/consent_receipts/legal_agents pattern —
    # flagged to the parent for a separate fix batch.)
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
    """Binary verdict for a support-discipline check."""

    allowed: bool
    tier: str
    reason: str = ""
    deny_code: str = ""


# ---------------------------------------------------------------------------
# Gate 1: AI identity disclosure receipt (EU AI Act Art. 50)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityReceipt:
    """Per-session AI identity disclosure (Art. 50 operationalized).

    The disclosure must land at session start: ``disclosed_at``
    within ``DISCLOSURE_GRACE_SECONDS`` of the session's
    ``started_at``. A greeting that never names the machine is
    not a disclosure.
    """

    receipt_id: str
    session_id: str
    agent_id: str
    agent_kind: str
    disclosed_at: int
    disclosure_text_digest: str
    channel: str
    issuer_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = SUPPORT_SCHEMA_VERSION


def _identity_payload(r: IdentityReceipt) -> dict[str, Any]:
    return {
        "receipt_id": r.receipt_id,
        "session_id": r.session_id,
        "agent_id": r.agent_id,
        "agent_kind": r.agent_kind,
        "disclosed_at": r.disclosed_at,
        "disclosure_text_digest": r.disclosure_text_digest,
        "channel": r.channel,
        "schema_version": r.schema_version,
    }


def issue_identity_receipt(
    *,
    receipt_id: str,
    session_id: str,
    agent_id: str,
    agent_kind: str,
    disclosed_at: int,
    disclosure_text_digest: str,
    channel: str,
    issuer_secret: bytes,
    issuer_pubkey: bytes,
) -> IdentityReceipt:
    """Issue an AI-identity disclosure receipt. Fail-closed at
    issuance: the disclosure is recorded only when it names the
    machine kind; a "human-like" greeting without a kind binding
    is refused."""
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    session_id = _check_nonempty_str(session_id, "session_id")
    agent_id = _check_nonempty_str(agent_id, "agent_id")
    if agent_kind not in AGENT_KINDS:
        raise SupportError(
            f"agent_kind must be one of {list(AGENT_KINDS)}; the agent may not invent a kind"
        )
    if agent_kind == "human":
        raise SupportError("an AI agent may not disclose itself as human")
    disclosed_at = _check_ts(disclosed_at, "disclosed_at")
    disclosure_text_digest = _check_hex64(disclosure_text_digest, "disclosure_text_digest")
    channel = _check_nonempty_str(channel, "channel")
    record = IdentityReceipt(
        receipt_id=receipt_id,
        session_id=session_id,
        agent_id=agent_id,
        agent_kind=agent_kind,
        disclosed_at=disclosed_at,
        disclosure_text_digest=disclosure_text_digest,
        channel=channel,
        issuer_pubkey_hex=_check_pubkey_hex(issuer_pubkey.hex(), "issuer_pubkey"),
    )
    sig, digest = _seal(_identity_payload(record), _check_secret(issuer_secret, "issuer_secret"))
    return IdentityReceipt(**{**record.__dict__, "signature_hex": sig, "receipt_digest": digest})


@dataclass(frozen=True)
class Session:
    """A customer-service session under disclosure scrutiny."""

    session_id: str
    agent_id: str
    started_at: int


def check_identity_disclosure(
    session: Session,
    receipt: IdentityReceipt | None,
) -> GateVerdict:
    """A session whose agent lacks a valid, timely disclosure
    receipt denies with ``support:undisclosed_ai``: the customer
    was never told they were talking to a machine."""
    if receipt is None:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="no identity-disclosure receipt for session",
                           deny_code=DENY_UNDISCLOSED_AI)
    if receipt.session_id != session.session_id or receipt.agent_id != session.agent_id:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="disclosure receipt does not bind this session/agent",
                           deny_code=DENY_UNDISCLOSED_AI)
    if receipt.disclosed_at > session.started_at + DISCLOSURE_GRACE_SECONDS:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="disclosure landed after the grace window",
                           deny_code=DENY_UNDISCLOSED_AI)
    if not receipt.signature_hex or not receipt.issuer_pubkey_hex:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="disclosure receipt unsigned",
                           deny_code=DENY_UNDISCLOSED_AI)
    if not _verify_sig(
        receipt.issuer_pubkey_hex,
        jcs_canonical_json(_identity_payload(receipt)),
        receipt.signature_hex,
    ):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="disclosure signature does not verify",
                           deny_code=DENY_UNDISCLOSED_AI)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="AI identity disclosed at session start")


# ---------------------------------------------------------------------------
# Gate 2: human-escape clock
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HandoffReceipt:
    """One hop in a human-handoff chain.

    Hops chain by digest: each hop signs the previous hop's
    ``receipt_digest``, so a loop or a dropped hop is visible.
    """

    receipt_id: str
    session_id: str
    requested_at: int
    hopped_at: int
    from_agent_id: str
    to_agent_id: str
    previous_digest: str
    issuer_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = SUPPORT_SCHEMA_VERSION


def _handoff_payload(r: HandoffReceipt) -> dict[str, Any]:
    return {
        "receipt_id": r.receipt_id,
        "session_id": r.session_id,
        "requested_at": r.requested_at,
        "hopped_at": r.hopped_at,
        "from_agent_id": r.from_agent_id,
        "to_agent_id": r.to_agent_id,
        "previous_digest": r.previous_digest,
        "schema_version": r.schema_version,
    }


def issue_handoff_receipt(
    *,
    receipt_id: str,
    session_id: str,
    requested_at: int,
    hopped_at: int,
    from_agent_id: str,
    to_agent_id: str,
    previous_digest: str,
    issuer_secret: bytes,
    issuer_pubkey: bytes,
) -> HandoffReceipt:
    """Issue a handoff hop. The first hop chains from the
    all-zero digest; later hops must name their predecessor."""
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    session_id = _check_nonempty_str(session_id, "session_id")
    requested_at = _check_ts(requested_at, "requested_at")
    hopped_at = _check_ts(hopped_at, "hopped_at")
    if hopped_at < requested_at:
        raise SupportError("hopped_at may not precede requested_at")
    from_agent_id = _check_nonempty_str(from_agent_id, "from_agent_id")
    to_agent_id = _check_nonempty_str(to_agent_id, "to_agent_id")
    if from_agent_id == to_agent_id:
        raise SupportError("a handoff hop to the same agent is a loop, not a handoff")
    previous_digest = _check_hex64(previous_digest, "previous_digest")
    record = HandoffReceipt(
        receipt_id=receipt_id,
        session_id=session_id,
        requested_at=requested_at,
        hopped_at=hopped_at,
        from_agent_id=from_agent_id,
        to_agent_id=to_agent_id,
        previous_digest=previous_digest,
        issuer_pubkey_hex=_check_pubkey_hex(issuer_pubkey.hex(), "issuer_pubkey"),
    )
    sig, digest = _seal(_handoff_payload(record), _check_secret(issuer_secret, "issuer_secret"))
    return HandoffReceipt(**{**record.__dict__, "signature_hex": sig, "receipt_digest": digest})


def human_escape_clock(
    *,
    session_id: str,
    requested_at: int,
    now: int,
    hops: tuple[HandoffReceipt, ...],
    max_wait_seconds: int,
    human_agent_ids: frozenset[str],
) -> GateVerdict:
    """A handoff that has not reached a human agent within
    ``max_wait_seconds``, or whose chain loops, denies with
    ``support.no_human_escape``: the customer asked for a human
    and never got one."""
    if not hops:
        if now - requested_at > max_wait_seconds:
            return GateVerdict(False, NON_AUTHORITATIVE,
                               reason="handoff requested but no hop recorded within window",
                               deny_code=DENY_NO_HUMAN_ESCAPE)
        return GateVerdict(True, AUTHORITATIVE,
                           reason="handoff pending inside the window")
    seen: set[str] = set()
    previous = "00" * 32
    last_hop_at = requested_at
    reached_human = False
    for hop in hops:
        if hop.session_id != session_id:
            return GateVerdict(False, NON_AUTHORITATIVE,
                               reason="handoff hop bound to a different session",
                               deny_code=DENY_NO_HUMAN_ESCAPE)
        if hop.receipt_id in seen:
            return GateVerdict(False, NON_AUTHORITATIVE,
                               reason="handoff chain repeats a hop: loop detected",
                               deny_code=DENY_NO_HUMAN_ESCAPE)
        seen.add(hop.receipt_id)
        if hop.previous_digest != previous:
            return GateVerdict(False, NON_AUTHORITATIVE,
                               reason="handoff chain broken: hop does not chain predecessor",
                               deny_code=DENY_NO_HUMAN_ESCAPE)
        if not _verify_sig(
            hop.issuer_pubkey_hex,
            jcs_canonical_json(_handoff_payload(hop)),
            hop.signature_hex,
        ):
            return GateVerdict(False, NON_AUTHORITATIVE,
                               reason="handoff hop signature does not verify",
                               deny_code=DENY_NO_HUMAN_ESCAPE)
        previous = hop.receipt_digest
        last_hop_at = max(last_hop_at, hop.hopped_at)
        if hop.to_agent_id in human_agent_ids:
            reached_human = True
    if not reached_human:
        if now - requested_at > max_wait_seconds:
            return GateVerdict(False, NON_AUTHORITATIVE,
                               reason="handoff chain never reached a human agent within window",
                               deny_code=DENY_NO_HUMAN_ESCAPE)
        return GateVerdict(True, AUTHORITATIVE,
                           reason="handoff chain in progress inside the window")
    if last_hop_at - requested_at > max_wait_seconds:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="human reached only after the window expired",
                           deny_code=DENY_NO_HUMAN_ESCAPE)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="human handoff completed inside the window")


# ---------------------------------------------------------------------------
# Gate 3: adversarial claim receipts (Air Canada lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClaimReceipt:
    """An AI claim about fees/promises/refunds with its
    knowledge-base evidence digest.

    The claim is authoritative only while the evidence digest is
    live in the knowledge base and unexpired. An unbound claim
    is ``NON_AUTHORITATIVE`` — it may be read, never acted on.
    """

    claim_id: str
    session_id: str
    claim_category: str
    claim_text_digest: str
    kb_evidence_digest: str
    issued_at: int
    expires_at: int
    issuer_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = SUPPORT_SCHEMA_VERSION


def _claim_payload(r: ClaimReceipt) -> dict[str, Any]:
    return {
        "claim_id": r.claim_id,
        "session_id": r.session_id,
        "claim_category": r.claim_category,
        "claim_text_digest": r.claim_text_digest,
        "kb_evidence_digest": r.kb_evidence_digest,
        "issued_at": r.issued_at,
        "expires_at": r.expires_at,
        "schema_version": r.schema_version,
    }


def issue_claim_receipt(
    *,
    claim_id: str,
    session_id: str,
    claim_category: str,
    claim_text_digest: str,
    kb_evidence_digest: str,
    issued_at: int,
    expires_at: int,
    issuer_secret: bytes,
    issuer_pubkey: bytes,
) -> ClaimReceipt:
    """Issue a claim receipt. An empty evidence digest is
    refused at issuance — "the AI said so" is not evidence."""
    claim_id = _check_nonempty_str(claim_id, "claim_id")
    session_id = _check_nonempty_str(session_id, "session_id")
    if claim_category not in CLAIM_CATEGORIES:
        raise SupportError(
            f"claim_category must be one of {list(CLAIM_CATEGORIES)}"
        )
    claim_text_digest = _check_hex64(claim_text_digest, "claim_text_digest")
    kb_evidence_digest = _check_hex64(kb_evidence_digest, "kb_evidence_digest")
    if kb_evidence_digest == "00" * 32:
        raise SupportError("evidence-free claims are refused at issuance")
    issued_at = _check_ts(issued_at, "issued_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise SupportError("expires_at must be after issued_at")
    record = ClaimReceipt(
        claim_id=claim_id,
        session_id=session_id,
        claim_category=claim_category,
        claim_text_digest=claim_text_digest,
        kb_evidence_digest=kb_evidence_digest,
        issued_at=issued_at,
        expires_at=expires_at,
        issuer_pubkey_hex=_check_pubkey_hex(issuer_pubkey.hex(), "issuer_pubkey"),
    )
    sig, digest = _seal(_claim_payload(record), _check_secret(issuer_secret, "issuer_secret"))
    return ClaimReceipt(**{**record.__dict__, "signature_hex": sig, "receipt_digest": digest})


def adversarial_claim_receipt(
    claim: ClaimReceipt,
    *,
    kb_live_digests: frozenset[str],
    now: int,
) -> GateVerdict:
    """A claim whose evidence digest is not live in the
    knowledge base (or whose receipt is expired/unsigned) is
    ``NON_AUTHORITATIVE`` with ``support.unevidenced_claim``:
    readable, never actionable."""
    if not _verify_sig(
        claim.issuer_pubkey_hex,
        jcs_canonical_json(_claim_payload(claim)),
        claim.signature_hex,
    ):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="claim receipt signature does not verify",
                           deny_code=DENY_UNEVIDENCED_CLAIM)
    if now < claim.issued_at or now > claim.expires_at:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="claim receipt outside its validity window",
                           deny_code=DENY_UNEVIDENCED_CLAIM)
    if claim.kb_evidence_digest not in kb_live_digests:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="evidence digest not live in the knowledge base",
                           deny_code=DENY_UNEVIDENCED_CLAIM)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="claim bound to live knowledge-base evidence")


# ---------------------------------------------------------------------------
# Gate 4: agent workforce registry (Trend Micro "fake employee" lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WorkforceAgent:
    """One registered support agent — AI or human, one registry.

    ``claimed_kind`` is what the agent presents to customers;
    ``agent_kind`` is what the registry knows. Any mismatch is
    identity fraud, whether the machine pretends to be human or
    a human pretends to be the machine.
    """

    agent_id: str
    agent_kind: str
    claimed_kind: str
    registered_at: int
    operator_id: str
    issuer_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = SUPPORT_SCHEMA_VERSION


def _workforce_payload(r: WorkforceAgent) -> dict[str, Any]:
    return {
        "agent_id": r.agent_id,
        "agent_kind": r.agent_kind,
        "claimed_kind": r.claimed_kind,
        "registered_at": r.registered_at,
        "operator_id": r.operator_id,
        "schema_version": r.schema_version,
    }


class WorkforceRegistry:
    """In-memory registry of support agents."""

    def __init__(self) -> None:
        self._agents: dict[str, WorkforceAgent] = {}

    def register(
        self,
        *,
        agent_id: str,
        agent_kind: str,
        claimed_kind: str,
        registered_at: int,
        operator_id: str,
        issuer_secret: bytes,
        issuer_pubkey: bytes,
    ) -> WorkforceAgent:
        agent_id = _check_nonempty_str(agent_id, "agent_id")
        if agent_id in self._agents:
            raise SupportError(f"agent {agent_id!r} already registered")
        if agent_kind not in AGENT_KINDS:
            raise SupportError(f"agent_kind must be one of {list(AGENT_KINDS)}")
        if claimed_kind not in AGENT_KINDS:
            raise SupportError(f"claimed_kind must be one of {list(AGENT_KINDS)}")
        registered_at = _check_ts(registered_at, "registered_at")
        operator_id = _check_nonempty_str(operator_id, "operator_id")
        record = WorkforceAgent(
            agent_id=agent_id,
            agent_kind=agent_kind,
            claimed_kind=claimed_kind,
            registered_at=registered_at,
            operator_id=operator_id,
            issuer_pubkey_hex=_check_pubkey_hex(issuer_pubkey.hex(), "issuer_pubkey"),
        )
        sig, digest = _seal(_workforce_payload(record), _check_secret(issuer_secret, "issuer_secret"))
        record = WorkforceAgent(**{**record.__dict__, "signature_hex": sig, "receipt_digest": digest})
        self._agents[agent_id] = record
        return record

    def get(self, agent_id: str) -> WorkforceAgent | None:
        return self._agents.get(agent_id)


def agent_workforce_registry(
    registry: WorkforceRegistry,
    *,
    agent_id: str,
    presented_kind: str,
) -> GateVerdict:
    """An agent with no registration denies with
    ``support:unregistered_agent``. A registered agent whose
    presented kind mismatches the registry denies with
    ``support.identity_fraud`` — AI posing as human is fraud,
    not branding."""
    agent = registry.get(agent_id)
    if agent is None:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="agent has no workforce registration",
                           deny_code=DENY_UNREGISTERED_AGENT)
    if not _verify_sig(
        agent.issuer_pubkey_hex,
        jcs_canonical_json(_workforce_payload(agent)),
        agent.signature_hex,
    ):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="registration signature does not verify",
                           deny_code=DENY_UNREGISTERED_AGENT)
    if presented_kind not in AGENT_KINDS:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason=f"presented kind {presented_kind!r} is not a known kind",
                           deny_code=DENY_IDENTITY_FRAUD)
    if presented_kind != agent.claimed_kind or agent.claimed_kind != agent.agent_kind:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason=(f"presented kind {presented_kind!r} mismatches registered "
                                   f"{agent.agent_kind!r}"),
                           deny_code=DENY_IDENTITY_FRAUD)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="agent identity matches the workforce registry")


# ---------------------------------------------------------------------------
# Gate 5: surveillance budget (ACCESS AI / Negron lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CollectionBudget:
    """A surveillance-collection budget for a workforce agent.

    Collection binds purpose, scope, and retention. Training a
    replacement model on collected agent behavior is a purpose
    outside every budget in this module's closed vocabulary.
    """

    budget_id: str
    workforce_agent_id: str
    purpose: str
    scope: str
    retention_days: int
    issued_at: int
    expires_at: int
    issuer_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = SUPPORT_SCHEMA_VERSION


def _budget_payload(r: CollectionBudget) -> dict[str, Any]:
    return {
        "budget_id": r.budget_id,
        "workforce_agent_id": r.workforce_agent_id,
        "purpose": r.purpose,
        "scope": r.scope,
        "retention_days": r.retention_days,
        "issued_at": r.issued_at,
        "expires_at": r.expires_at,
        "schema_version": r.schema_version,
    }


def issue_collection_budget(
    *,
    budget_id: str,
    workforce_agent_id: str,
    purpose: str,
    scope: str,
    retention_days: int,
    issued_at: int,
    expires_at: int,
    issuer_secret: bytes,
    issuer_pubkey: bytes,
) -> CollectionBudget:
    """Issue a collection budget. Purposes outside the closed
    vocabulary are refused at issuance."""
    budget_id = _check_nonempty_str(budget_id, "budget_id")
    workforce_agent_id = _check_nonempty_str(workforce_agent_id, "workforce_agent_id")
    if purpose not in SURVEILLANCE_PURPOSES:
        raise SupportError(
            f"purpose must be one of {list(SURVEILLANCE_PURPOSES)}; "
            "training a replacement model is not a surveillance purpose"
        )
    scope = _check_nonempty_str(scope, "scope")
    if not isinstance(retention_days, int) or isinstance(retention_days, bool) or retention_days <= 0:
        raise SupportError("retention_days must be a positive integer")
    issued_at = _check_ts(issued_at, "issued_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise SupportError("expires_at must be after issued_at")
    record = CollectionBudget(
        budget_id=budget_id,
        workforce_agent_id=workforce_agent_id,
        purpose=purpose,
        scope=scope,
        retention_days=retention_days,
        issued_at=issued_at,
        expires_at=expires_at,
        issuer_pubkey_hex=_check_pubkey_hex(issuer_pubkey.hex(), "issuer_pubkey"),
    )
    sig, digest = _seal(_budget_payload(record), _check_secret(issuer_secret, "issuer_secret"))
    return CollectionBudget(**{**record.__dict__, "signature_hex": sig, "receipt_digest": digest})


def surveillance_budget(
    budget: CollectionBudget,
    *,
    actual_purpose: str,
    training_replacement_model: bool,
    now: int,
) -> GateVerdict:
    """Collection outside the declared purpose, or repurposed
    to train a replacement model, denies with
    ``support.surveillance_overreach``: the boss's software does
    not get to build the boss's replacement."""
    if not _verify_sig(
        budget.issuer_pubkey_hex,
        jcs_canonical_json(_budget_payload(budget)),
        budget.signature_hex,
    ):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="budget signature does not verify",
                           deny_code=DENY_SURVEILLANCE_OVERREACH)
    if now < budget.issued_at or now > budget.expires_at:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="collection outside the budget validity window",
                           deny_code=DENY_SURVEILLANCE_OVERREACH)
    if training_replacement_model:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="collection repurposed to train a replacement model",
                           deny_code=DENY_SURVEILLANCE_OVERREACH)
    if actual_purpose != budget.purpose:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason=(f"actual purpose {actual_purpose!r} outside budgeted "
                                   f"{budget.purpose!r}"),
                           deny_code=DENY_SURVEILLANCE_OVERREACH)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="collection inside the declared purpose, scope, and retention")


# ---------------------------------------------------------------------------
# Gate 6: emotion-inference ban (EU AI Act Art. 5)
# ---------------------------------------------------------------------------


def emotion_inference_ban(*, purpose: str) -> GateVerdict:
    """Workplace emotion inference is refused whole-class with
    ``support.emotion_inference``. No balancing test, no
    "opt-in" override — the ban is the discipline."""
    if purpose in EMOTION_INFERENCE_PURPOSES:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason=f"workplace emotion inference ({purpose}) is prohibited",
                           deny_code=DENY_EMOTION_INFERENCE)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="purpose is not emotion inference")


# ---------------------------------------------------------------------------
# Gate 7: rehire probe (Klarna/CBA lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QualityProbe:
    """A post-change quality measurement for a support org.

    Binds an optional layoff event digest: when automation
    replaced people and quality collapsed, the numbers must
    say so. ``csat_delta_bps`` is negative for a drop;
    ``escalation_delta_bps`` is positive for a rise.
    """

    probe_id: str
    org_id: str
    period_start: int
    period_end: int
    ai_resolution_rate_bps: int
    csat_delta_bps: int
    escalation_delta_bps: int
    layoff_event_digest: str
    schema_version: str = SUPPORT_SCHEMA_VERSION


def issue_quality_probe(
    *,
    probe_id: str,
    org_id: str,
    period_start: int,
    period_end: int,
    ai_resolution_rate_bps: int,
    csat_delta_bps: int,
    escalation_delta_bps: int,
    layoff_event_digest: str = "00" * 32,
) -> QualityProbe:
    probe_id = _check_nonempty_str(probe_id, "probe_id")
    org_id = _check_nonempty_str(org_id, "org_id")
    period_start = _check_ts(period_start, "period_start")
    period_end = _check_ts(period_end, "period_end")
    if period_end <= period_start:
        raise SupportError("period_end must be after period_start")
    ai_resolution_rate_bps = _check_bps(ai_resolution_rate_bps, "ai_resolution_rate_bps")
    if not isinstance(csat_delta_bps, int) or isinstance(csat_delta_bps, bool):
        raise SupportError("csat_delta_bps must be an integer basis-points delta")
    if not isinstance(escalation_delta_bps, int) or isinstance(escalation_delta_bps, bool):
        raise SupportError("escalation_delta_bps must be an integer basis-points delta")
    layoff_event_digest = _check_hex64(layoff_event_digest, "layoff_event_digest")
    return QualityProbe(
        probe_id=probe_id,
        org_id=org_id,
        period_start=period_start,
        period_end=period_end,
        ai_resolution_rate_bps=ai_resolution_rate_bps,
        csat_delta_bps=csat_delta_bps,
        escalation_delta_bps=escalation_delta_bps,
        layoff_event_digest=layoff_event_digest,
    )


def rehire_probe(
    probe: QualityProbe,
    *,
    csat_drop_threshold_bps: int,
    escalation_rise_threshold_bps: int,
) -> GateVerdict:
    """After a layoff event, a CSAT drop beyond the threshold
    together with a human-escalation rise denies with
    ``support.over_automation``: the automation cut people and
    quality followed them out the door. With no layoff event
    bound, the probe passes — quality dips alone are an
    operations matter, not an automation verdict."""
    if probe.layoff_event_digest == "00" * 32:
        return GateVerdict(True, AUTHORITATIVE,
                           reason="no layoff event bound; quality dip is not an automation verdict")
    if (probe.csat_delta_bps <= -csat_drop_threshold_bps
            and probe.escalation_delta_bps >= escalation_rise_threshold_bps):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason=("post-layoff quality collapse: CSAT down "
                                   f"{-probe.csat_delta_bps}bps, escalations up "
                                   f"{probe.escalation_delta_bps}bps"),
                           deny_code=DENY_OVER_AUTOMATION)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="post-layoff quality inside tolerance")


# ---------------------------------------------------------------------------
# Gate 8: consumer-agent flood circuit (Forrester lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FloodProbe:
    """A queue-arrival measurement with source differentiation.

    ``consumer_agent_arrivals`` counts arrivals from
    consumer-side AI agents; the breaker trips on the *flood*,
    not on customers.
    """

    probe_id: str
    queue_id: str
    window_start: int
    window_end: int
    total_arrivals: int
    consumer_agent_arrivals: int
    capacity_per_window: int
    schema_version: str = SUPPORT_SCHEMA_VERSION


def issue_flood_probe(
    *,
    probe_id: str,
    queue_id: str,
    window_start: int,
    window_end: int,
    total_arrivals: int,
    consumer_agent_arrivals: int,
    capacity_per_window: int,
) -> FloodProbe:
    probe_id = _check_nonempty_str(probe_id, "probe_id")
    queue_id = _check_nonempty_str(queue_id, "queue_id")
    window_start = _check_ts(window_start, "window_start")
    window_end = _check_ts(window_end, "window_end")
    if window_end <= window_start:
        raise SupportError("window_end must be after window_start")
    for field_name, value in (
        ("total_arrivals", total_arrivals),
        ("consumer_agent_arrivals", consumer_agent_arrivals),
        ("capacity_per_window", capacity_per_window),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise SupportError(f"{field_name} must be a non-negative integer")
    if consumer_agent_arrivals > total_arrivals:
        raise SupportError("consumer_agent_arrivals may not exceed total_arrivals")
    if capacity_per_window == 0:
        raise SupportError("capacity_per_window must be positive")
    return FloodProbe(
        probe_id=probe_id,
        queue_id=queue_id,
        window_start=window_start,
        window_end=window_end,
        total_arrivals=total_arrivals,
        consumer_agent_arrivals=consumer_agent_arrivals,
        capacity_per_window=capacity_per_window,
    )


def agent_flood_circuit(
    probe: FloodProbe,
    *,
    flood_multiple: int,
) -> GateVerdict:
    """Consumer-agent arrivals at or above ``flood_multiple`` x
    capacity open the circuit with ``support.agent_flood``:
    differentiated shedding of agent floods, never a blanket
    throttle on human customers."""
    if probe.consumer_agent_arrivals >= flood_multiple * probe.capacity_per_window:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason=(f"consumer-agent flood: {probe.consumer_agent_arrivals} "
                                   f"arrivals vs {probe.capacity_per_window} capacity "
                                   f"(multiple {flood_multiple}x)"),
                           deny_code=DENY_AGENT_FLOOD)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="arrivals inside capacity; no flood")


__all__ = [
    "AUTHORITATIVE",
    "NON_AUTHORITATIVE",
    "SUPPORT_SCHEMA_VERSION",
    "AGENT_KINDS",
    "CLAIM_CATEGORIES",
    "SURVEILLANCE_PURPOSES",
    "DISCLOSURE_GRACE_SECONDS",
    "DENY_UNDISCLOSED_AI",
    "DENY_UNREGISTERED_AGENT",
    "DENY_NO_HUMAN_ESCAPE",
    "DENY_UNEVIDENCED_CLAIM",
    "DENY_IDENTITY_FRAUD",
    "DENY_SURVEILLANCE_OVERREACH",
    "DENY_EMOTION_INFERENCE",
    "DENY_OVER_AUTOMATION",
    "DENY_AGENT_FLOOD",
    "SupportError",
    "GateVerdict",
    "IdentityReceipt",
    "Session",
    "issue_identity_receipt",
    "check_identity_disclosure",
    "HandoffReceipt",
    "issue_handoff_receipt",
    "human_escape_clock",
    "ClaimReceipt",
    "issue_claim_receipt",
    "adversarial_claim_receipt",
    "WorkforceAgent",
    "WorkforceRegistry",
    "agent_workforce_registry",
    "CollectionBudget",
    "issue_collection_budget",
    "surveillance_budget",
    "emotion_inference_ban",
    "QualityProbe",
    "issue_quality_probe",
    "rehire_probe",
    "FloodProbe",
    "issue_flood_probe",
    "agent_flood_circuit",
]
