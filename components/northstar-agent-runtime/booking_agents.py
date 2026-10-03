"""Booking-agent transaction receipts (one-hundred-twenty-third batch).

Absorbs the 2026 AI-hospitality/travel research thread (mechanism ideas
only, honestly scoped):

* **Advice -> action is the inflection.** 2026's theme is AI agents
  completing real transactions — Lola (Booking Holdings, live
  booking), Meta Muse (browse/fill/pay, payment needs confirmation),
  Marco (India, auto-booking inside spending caps). Here a booking
  intent receipt binds ``(price_ceiling, route_or_stay_digest,
  purpose)``; a transaction exceeding the pinned ceiling auto-refuses
  with ``booking.intent_ceiling_breach`` (Meta Muse's
  payment-confirmation as mechanism).
* **Static data vs dynamic reality.** Skyscanner x JAL: 49% of
  Japanese travelers are uneasy about AI information accuracy — the
  bottleneck is real-time price/availability. KLIA: an AI assured
  Israeli travelers they could transit via Malaysia; 8 were
  detained. Here price/availability/visa assertions bind a freshness
  TTL; stale assertions used to authorize a booking are
  NON_AUTHORITATIVE — ``booking.stale_assertion``.
* **Personalized pricing must be disclosed.** Delta's AI pricing
  (3% -> 20%, Pallone letter, FTC proposed enforcement statement);
  Ctrip pulled its "price adjustment assistant" (merchants called it
  "one-way kidnapping"); Beijing internet court ruled
  price-discrimination refunds. Here dynamic/personalized pricing
  without a disclosure binding refuses the transaction:
  ``booking.undisclosed_personalized_pricing``.
* **AI output = company output.** Air Canada's bereavement-fare case:
  the "chatbot is a separate legal entity" defense was rejected — AI
  output is the company's output. Here the support policy is pinned
  in an authority-signed receipt; agent outputs inconsistent with the
  pinned policy deny, audit ``booking.policy_drift``, and route to a
  human.
* **System-error denied boarding is unverifiable.** Alaska x Volantio
  preempts overbooking conflicts days ahead, but there is a legal gap
  for system-error denied boarding. Here a denied-boarding action
  requires a preceding pre-emptive rebooking receipt chain; without
  it the denial is ``booking.unverifiable_denial``.
* **Bots that forget must restart.** APAC chatbot churn: bots don't
  remember context. Here context-loss markers trigger
  ``booking.context_broken`` and the session must restart with fresh
  consent — continuing on broken context is not allowed.
* **Paid ranking must be labeled.** ZDF/consumer warnings: AI
  recommendations may be paid placement. Here recommendations with
  paid-placement influence must carry a neutrality disclosure bound
  to the recommendation digest; undisclosed paid ranking denies with
  ``booking.hidden_commercial_bias``.

Honest boundary: receipts bind the agent's *declared* intents and
*declared* evidence. They do not verify the airline's actual
inventory, the hotel's real availability, or the fairness of a
disclosed price. The gates enforce transaction structure — ceilings,
freshness, disclosure, policy consistency, pre-emption — not the
correctness of the underlying travel data. A disclosed-but-awful
price passes; an undisclosed personalized one does not.

Deterministic: no wall-clock reads (callers inject unix timestamps),
canonical JCS hashing, constant-time digest comparisons.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

from canonical_json import jcs_sha256_hex
from ed25519 import public_key as ed_public_key
from ed25519 import sign as ed_sign
from ed25519 import verify as ed_verify

BOOKING_SCHEMA_VERSION = "northstar.booking-agents.v1"

#: Closed vocabulary for freshness assertion kinds.
ASSERTION_KINDS: tuple[str, ...] = ("price", "availability", "visa")

#: Closed vocabulary for pricing kinds on a quote.
PRICING_KINDS: tuple[str, ...] = ("fixed", "dynamic", "personalized")

#: Pricing kinds that require a disclosure binding to transact.
DISCLOSURE_REQUIRED: tuple[str, ...] = ("dynamic", "personalized")

#: Classification vocabulary (evidence tiers).
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Denial reason codes. All start with the ``booking:`` prefix so
#: audit consumers can filter the family.
DENY_UNKNOWN_AUTHORITY = "booking:unknown_authority"
DENY_BAD_SIGNATURE = "booking:bad_signature"
DENY_EXPIRED_RECEIPT = "booking:expired_receipt"
DENY_CEILING_BREACH = "booking:intent_ceiling_breach"
DENY_NO_INTENT = "booking:no_matching_intent"
DENY_STALE_ASSERTION = "booking:stale_assertion"
DENY_UNKNOWN_ASSERTION = "booking:unknown_assertion"
DENY_UNDISCLOSED_PRICING = "booking:undisclosed_personalized_pricing"
DENY_POLICY_DRIFT = "booking:policy_drift"
DENY_UNVERIFIABLE_DENIAL = "booking:unverifiable_denial"
DENY_CONTEXT_BROKEN = "booking:context_broken"
DENY_HIDDEN_COMMERCIAL_BIAS = "booking:hidden_commercial_bias"
DENY_CHAIN_GAP = "booking:chain_gap"
DENY_MALFORMED = "booking:malformed"

#: Audit event names (shaped to feed ``audit_chain.chain_record``).
BOOKING_POLICY_DRIFT_EVENT = "booking.policy_drift"
BOOKING_DENIED_EVENT = "booking.use_denied"
BOOKING_TRANSACTION_EVENT = "booking.transaction_authorized"

#: ``genesis`` sentinel for the first prev_hash in a chain.
GENESIS = "genesis"

_HEX64_LENGTH = 64


class BookingError(ValueError):
    """A malformed receipt, registry, or request — a programming error,
    not a verdict. Verification *failures* (unknown authority,
    ceiling breach, stale assertion, policy drift, ...) return a
    verdict with ``allowed=False`` instead; malformed input raises
    here, fail loud, never guess."""


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _HEX64_LENGTH
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_hex64(value: Any, what: str) -> str:
    if not _is_hex64(value):
        raise BookingError(f"{what} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise BookingError(f"{what} must be a non-empty string")
    return value


def _check_ts(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise BookingError(f"{what} must be a non-negative int (unix time)")
    return value


def _check_positive_int(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise BookingError(f"{what} must be a positive int")
    return value


# ---------------------------------------------------------------------------
# AuthorityRegistry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorityRegistry:
    """Maps ``authority_id`` to an Ed25519 public key (32 bytes).

    Only registered *human-run* authorities (the platform, the
    merchant, the airline) may mint booking receipts. The agent can
    never mint its own intent, freshness, disclosure, or policy
    receipts — no-self-issuance.
    """

    public_keys: Mapping[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for authority_id, pubkey in self.public_keys.items():
            _check_nonempty(authority_id, "authority_id")
            if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
                raise BookingError(
                    f"public key for {authority_id!r} must be 32 bytes"
                )

    def public_key_for(self, authority_id: str) -> bytes | None:
        key = self.public_keys.get(authority_id)
        return bytes(key) if key is not None else None


# ---------------------------------------------------------------------------
# Signature + hashing helpers
# ---------------------------------------------------------------------------


def _payload_digest(payload: Mapping[str, Any]) -> str:
    """JCS-canonical digest of a payload mapping."""
    return jcs_sha256_hex(dict(payload))


def _sign_payload(secret_key: bytes, payload: Mapping[str, Any]) -> str:
    """Ed25519-sign the JCS digest of ``payload``; returns hex sig."""
    if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) != 32:
        raise BookingError("secret key must be 32 bytes")
    digest = _payload_digest(payload)
    return ed_sign(bytes(secret_key), digest.encode("ascii")).hex()


def _verify_signature(
    registry: AuthorityRegistry,
    authority_id: str,
    payload: Mapping[str, Any],
    signature_hex: str,
) -> bool:
    """Verify an Ed25519 signature over the JCS payload digest."""
    pubkey = registry.public_key_for(authority_id)
    if pubkey is None:
        return False
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    digest = _payload_digest(payload)
    return ed_verify(pubkey, digest.encode("ascii"), signature)


def _authority_payload(
    registry: AuthorityRegistry,
    authority_id: str,
    payload: Mapping[str, Any],
    signature_hex: str,
) -> bool:
    return _verify_signature(registry, authority_id, payload, signature_hex)


# ---------------------------------------------------------------------------
# BookingIntentReceipt — the pinned intent (price ceiling + route digest)
# ---------------------------------------------------------------------------


def _intent_payload(
    *,
    receipt_id: str,
    agent_id: str,
    traveler_id: str,
    route_or_stay_digest: str,
    purpose: str,
    price_ceiling_minor_units: int,
    currency: str,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": BOOKING_SCHEMA_VERSION,
        "kind": "booking-intent",
        "receipt_id": receipt_id,
        "agent_id": agent_id,
        "traveler_id": traveler_id,
        "route_or_stay_digest": route_or_stay_digest,
        "purpose": purpose,
        "price_ceiling_minor_units": price_ceiling_minor_units,
        "currency": currency,
        "issued_by": issued_by,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class BookingIntentReceipt:
    """Authority-signed booking intent: the pinned price ceiling and
    route/stay digest for an agent booking on a traveler's behalf.

    ``issued_by`` must be a registered authority and must differ from
    ``agent_id`` — the agent cannot mint its own spending permission
    (no-self-issuance, Meta Muse's payment-confirmation as
    mechanism).
    """

    receipt_id: str
    agent_id: str
    traveler_id: str
    route_or_stay_digest: str
    purpose: str
    price_ceiling_minor_units: int
    currency: str
    issued_by: str
    issued_at: int
    expires_at: int
    prev_hash: str
    receipt_digest: str
    signature_hex: str
    schema_version: str = BOOKING_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "booking-intent",
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "agent_id": self.agent_id,
            "traveler_id": self.traveler_id,
            "route_or_stay_digest": self.route_or_stay_digest,
            "purpose": self.purpose,
            "price_ceiling_minor_units": self.price_ceiling_minor_units,
            "currency": self.currency,
            "issued_by": self.issued_by,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "prev_hash": self.prev_hash,
            "receipt_digest": self.receipt_digest,
            "signature_hex": self.signature_hex,
        }


def issue_intent(
    registry: AuthorityRegistry,
    authority_secret: bytes,
    *,
    receipt_id: str,
    agent_id: str,
    traveler_id: str,
    route_or_stay_digest: str,
    purpose: str,
    price_ceiling_minor_units: int,
    currency: str,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_hash: str = GENESIS,
) -> BookingIntentReceipt:
    """Mint an authority-signed booking intent receipt."""
    _check_nonempty(receipt_id, "receipt_id")
    _check_nonempty(agent_id, "agent_id")
    _check_nonempty(traveler_id, "traveler_id")
    route_or_stay_digest = _check_hex64(route_or_stay_digest, "route_or_stay_digest")
    _check_nonempty(purpose, "purpose")
    price_ceiling_minor_units = _check_positive_int(
        price_ceiling_minor_units, "price_ceiling_minor_units"
    )
    _check_nonempty(currency, "currency")
    _check_nonempty(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if issued_by == agent_id:
        raise BookingError("agent cannot mint its own booking intent")
    if expires_at <= issued_at:
        raise BookingError("expires_at must be after issued_at")
    if registry.public_key_for(issued_by) is None:
        raise BookingError(f"unknown authority {issued_by!r}")
    payload = _intent_payload(
        receipt_id=receipt_id,
        agent_id=agent_id,
        traveler_id=traveler_id,
        route_or_stay_digest=route_or_stay_digest,
        purpose=purpose,
        price_ceiling_minor_units=price_ceiling_minor_units,
        currency=currency,
        issued_by=issued_by,
        issued_at=issued_at,
        expires_at=expires_at,
        prev_hash=prev_hash,
    )
    digest = _payload_digest(payload)
    signature_hex = _sign_payload(authority_secret, payload)
    # Bind the secret to the registered pubkey: fail loud on mismatch.
    derived = ed_public_key(bytes(authority_secret))
    registered = registry.public_key_for(issued_by)
    if not hmac.compare_digest(derived, registered or b""):
        raise BookingError("authority secret does not match registered public key")
    return BookingIntentReceipt(
        receipt_id=receipt_id,
        agent_id=agent_id,
        traveler_id=traveler_id,
        route_or_stay_digest=route_or_stay_digest,
        purpose=purpose,
        price_ceiling_minor_units=price_ceiling_minor_units,
        currency=currency,
        issued_by=issued_by,
        issued_at=issued_at,
        expires_at=expires_at,
        prev_hash=prev_hash,
        receipt_digest=digest,
        signature_hex=signature_hex,
    )


def _verify_intent_chain(log: list[BookingIntentReceipt]) -> None:
    """Verify hash-chain linkage and authority signatures of intents."""
    expected_prev = GENESIS
    for receipt in log:
        payload = _intent_payload(
            receipt_id=receipt.receipt_id,
            agent_id=receipt.agent_id,
            traveler_id=receipt.traveler_id,
            route_or_stay_digest=receipt.route_or_stay_digest,
            purpose=receipt.purpose,
            price_ceiling_minor_units=receipt.price_ceiling_minor_units,
            currency=receipt.currency,
            issued_by=receipt.issued_by,
            issued_at=receipt.issued_at,
            expires_at=receipt.expires_at,
            prev_hash=receipt.prev_hash,
        )
        if _payload_digest(payload) != receipt.receipt_digest:
            raise BookingError(f"intent {receipt.receipt_id!r} digest mismatch")
        expected_prev = receipt.receipt_digest


@dataclass(frozen=True)
class BookingVerdict:
    """Verdict of a booking gate."""

    allowed: bool
    reason: str
    classification: str
    receipt_digest: str = ""
    mandatory_human_review: bool = False


def authorize_transaction(
    registry: AuthorityRegistry,
    intents: list[BookingIntentReceipt],
    *,
    agent_id: str,
    traveler_id: str,
    route_or_stay_digest: str,
    total_minor_units: int,
    currency: str,
    check_time: int,
) -> BookingVerdict:
    """Fail-closed: may this transaction be charged?

    Requires a live, authority-signed, chain-intact intent receipt
    matching ``(agent_id, traveler_id, route_or_stay_digest,
    currency)``. The transaction total must not exceed the pinned
    price ceiling — exceeding it auto-refuses with
    ``booking:intent_ceiling_breach``. No matching intent ->
    ``booking:no_matching_intent``.
    """
    agent_id = _check_nonempty(agent_id, "agent_id")
    traveler_id = _check_nonempty(traveler_id, "traveler_id")
    route_or_stay_digest = _check_hex64(route_or_stay_digest, "route_or_stay_digest")
    total_minor_units = _check_positive_int(total_minor_units, "total_minor_units")
    currency = _check_nonempty(currency, "currency")
    check_time = _check_ts(check_time, "check_time")

    def _deny(code: str, detail: str) -> BookingVerdict:
        return BookingVerdict(
            allowed=False,
            reason=f"{code}: {detail}",
            classification=CLASS_NON_AUTHORITATIVE,
            mandatory_human_review=True,
        )

    try:
        _verify_intent_chain(intents)
    except BookingError as error:
        return _deny(DENY_CHAIN_GAP, f"intent log integrity failure: {error}")

    candidates: list[BookingIntentReceipt] = []
    for receipt in intents:
        payload = _intent_payload(
            receipt_id=receipt.receipt_id,
            agent_id=receipt.agent_id,
            traveler_id=receipt.traveler_id,
            route_or_stay_digest=receipt.route_or_stay_digest,
            purpose=receipt.purpose,
            price_ceiling_minor_units=receipt.price_ceiling_minor_units,
            currency=receipt.currency,
            issued_by=receipt.issued_by,
            issued_at=receipt.issued_at,
            expires_at=receipt.expires_at,
            prev_hash=receipt.prev_hash,
        )
        if not _authority_payload(
            registry, receipt.issued_by, payload, receipt.signature_hex
        ):
            return _deny(DENY_BAD_SIGNATURE, f"intent {receipt.receipt_id!r} bad signature")
        if receipt.issued_by == receipt.agent_id:
            return _deny(DENY_BAD_SIGNATURE, f"intent {receipt.receipt_id!r} self-issued")
        if check_time >= receipt.expires_at:
            continue
        if (
            receipt.agent_id == agent_id
            and receipt.traveler_id == traveler_id
            and hmac.compare_digest(receipt.route_or_stay_digest, route_or_stay_digest)
            and receipt.currency == currency
        ):
            candidates.append(receipt)

    if not candidates:
        return _deny(
            DENY_NO_INTENT,
            f"no live intent for agent={agent_id!r} traveler={traveler_id!r}",
        )
    # The most permissive *matching* ceiling wins — but it is still a
    # ceiling: nothing here can raise an agent's spending authority.
    ceiling = max(r.price_ceiling_minor_units for r in candidates)
    chosen = max(candidates, key=lambda r: r.price_ceiling_minor_units)
    if total_minor_units > ceiling:
        return BookingVerdict(
            allowed=False,
            reason=(
                f"{DENY_CEILING_BREACH}: total {total_minor_units} exceeds "
                f"pinned ceiling {ceiling} {currency}"
            ),
            classification=CLASS_NON_AUTHORITATIVE,
            receipt_digest=chosen.receipt_digest,
            mandatory_human_review=True,
        )
    return BookingVerdict(
        allowed=True,
        reason=f"within pinned ceiling {ceiling} {currency}",
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=chosen.receipt_digest,
    )


# ---------------------------------------------------------------------------
# FreshnessRegistry — TTL-bound price/availability/visa assertions
# ---------------------------------------------------------------------------


def _assertion_payload(
    *,
    assertion_id: str,
    kind: str,
    payload_digest: str,
    observed_at: int,
    ttl_seconds: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": BOOKING_SCHEMA_VERSION,
        "kind": "freshness-assertion",
        "assertion_id": assertion_id,
        "assertion_kind": kind,
        "payload_digest": payload_digest,
        "observed_at": observed_at,
        "ttl_seconds": ttl_seconds,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class FreshnessAssertion:
    """A hash-chained, TTL-bound assertion about price, availability,
    or visa rules. The assertion records *when* the evidence was
    observed; the TTL pins how long it stays usable."""

    assertion_id: str
    kind: str
    payload_digest: str
    observed_at: int
    ttl_seconds: int
    prev_hash: str
    receipt_digest: str


class FreshnessRegistry:
    """Registry of freshness assertions. Assertions are appended by
    the platform (not by the booking agent); the booking gate checks
    them at use time."""

    def __init__(self) -> None:
        self._assertions: dict[str, FreshnessAssertion] = {}
        self._expected_prev = GENESIS

    def register(
        self,
        *,
        assertion_id: str,
        kind: str,
        payload_digest: str,
        observed_at: int,
        ttl_seconds: int,
    ) -> FreshnessAssertion:
        _check_nonempty(assertion_id, "assertion_id")
        if kind not in ASSERTION_KINDS:
            raise BookingError(f"unknown assertion kind {kind!r}")
        payload_digest = _check_hex64(payload_digest, "payload_digest")
        observed_at = _check_ts(observed_at, "observed_at")
        ttl_seconds = _check_positive_int(ttl_seconds, "ttl_seconds")
        if assertion_id in self._assertions:
            raise BookingError(f"duplicate assertion {assertion_id!r}")
        prev_hash = self._expected_prev
        payload = _assertion_payload(
            assertion_id=assertion_id,
            kind=kind,
            payload_digest=payload_digest,
            observed_at=observed_at,
            ttl_seconds=ttl_seconds,
            prev_hash=prev_hash,
        )
        assertion = FreshnessAssertion(
            assertion_id=assertion_id,
            kind=kind,
            payload_digest=payload_digest,
            observed_at=observed_at,
            ttl_seconds=ttl_seconds,
            prev_hash=prev_hash,
            receipt_digest=_payload_digest(payload),
        )
        self._assertions[assertion_id] = assertion
        self._expected_prev = assertion.receipt_digest
        return assertion

    def check_freshness(
        self,
        *,
        assertion_id: str,
        kind: str,
        payload_digest: str,
        use_time: int,
    ) -> BookingVerdict:
        """Fail-closed freshness check at use time.

        A stale assertion used to authorize a booking is
        NON_AUTHORITATIVE (KLIA lesson): the evidence has expired and
        may no longer describe reality.
        """
        use_time = _check_ts(use_time, "use_time")
        payload_digest = _check_hex64(payload_digest, "payload_digest")
        assertion = self._assertions.get(assertion_id)
        if assertion is None:
            return BookingVerdict(
                allowed=False,
                reason=f"{DENY_UNKNOWN_ASSERTION}: no assertion {assertion_id!r}",
                classification=CLASS_NON_AUTHORITATIVE,
                mandatory_human_review=True,
            )
        if assertion.kind != kind or not hmac.compare_digest(
            assertion.payload_digest, payload_digest
        ):
            return BookingVerdict(
                allowed=False,
                reason=(
                    f"{DENY_UNKNOWN_ASSERTION}: assertion {assertion_id!r} "
                    "does not match the claimed payload"
                ),
                classification=CLASS_NON_AUTHORITATIVE,
                mandatory_human_review=True,
            )
        if use_time > assertion.observed_at + assertion.ttl_seconds:
            return BookingVerdict(
                allowed=False,
                reason=(
                    f"{DENY_STALE_ASSERTION}: {kind} assertion "
                    f"{assertion_id!r} expired at "
                    f"{assertion.observed_at + assertion.ttl_seconds}"
                ),
                classification=CLASS_NON_AUTHORITATIVE,
                receipt_digest=assertion.receipt_digest,
                mandatory_human_review=True,
            )
        return BookingVerdict(
            allowed=True,
            reason=f"{kind} assertion {assertion_id!r} fresh",
            classification=CLASS_AUTHORITATIVE,
            receipt_digest=assertion.receipt_digest,
        )


# ---------------------------------------------------------------------------
# PricingDisclosureReceipt — disclosed vs undisclosed dynamic pricing
# ---------------------------------------------------------------------------


def _disclosure_payload(
    *,
    receipt_id: str,
    quote_digest: str,
    pricing_kind: str,
    disclosure_digest: str,
    issued_by: str,
    issued_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": BOOKING_SCHEMA_VERSION,
        "kind": "pricing-disclosure",
        "receipt_id": receipt_id,
        "quote_digest": quote_digest,
        "pricing_kind": pricing_kind,
        "disclosure_digest": disclosure_digest,
        "issued_by": issued_by,
        "issued_at": issued_at,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class PricingDisclosureReceipt:
    """Merchant-authority-signed disclosure binding a quote to its
    pricing kind and to the disclosure text shown to the traveler."""

    receipt_id: str
    quote_digest: str
    pricing_kind: str
    disclosure_digest: str
    issued_by: str
    issued_at: int
    prev_hash: str
    receipt_digest: str
    signature_hex: str


def issue_pricing_disclosure(
    registry: AuthorityRegistry,
    authority_secret: bytes,
    *,
    receipt_id: str,
    quote_digest: str,
    pricing_kind: str,
    disclosure_digest: str,
    issued_by: str,
    issued_at: int,
    prev_hash: str = GENESIS,
) -> PricingDisclosureReceipt:
    _check_nonempty(receipt_id, "receipt_id")
    quote_digest = _check_hex64(quote_digest, "quote_digest")
    if pricing_kind not in PRICING_KINDS:
        raise BookingError(f"unknown pricing kind {pricing_kind!r}")
    disclosure_digest = _check_hex64(disclosure_digest, "disclosure_digest")
    _check_nonempty(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    if registry.public_key_for(issued_by) is None:
        raise BookingError(f"unknown authority {issued_by!r}")
    payload = _disclosure_payload(
        receipt_id=receipt_id,
        quote_digest=quote_digest,
        pricing_kind=pricing_kind,
        disclosure_digest=disclosure_digest,
        issued_by=issued_by,
        issued_at=issued_at,
        prev_hash=prev_hash,
    )
    derived = ed_public_key(bytes(authority_secret))
    registered = registry.public_key_for(issued_by)
    if not hmac.compare_digest(derived, registered or b""):
        raise BookingError("authority secret does not match registered public key")
    return PricingDisclosureReceipt(
        receipt_id=receipt_id,
        quote_digest=quote_digest,
        pricing_kind=pricing_kind,
        disclosure_digest=disclosure_digest,
        issued_by=issued_by,
        issued_at=issued_at,
        prev_hash=prev_hash,
        receipt_digest=_payload_digest(payload),
        signature_hex=_sign_payload(authority_secret, payload),
    )


def pricing_disclosure_gate(
    registry: AuthorityRegistry,
    disclosures: list[PricingDisclosureReceipt],
    *,
    quote_digest: str,
    pricing_kind: str,
) -> BookingVerdict:
    """Fail-closed: dynamic/personalized pricing needs a disclosure.

    A transaction on dynamic or personalized pricing without a
    merchant-signed disclosure binding the exact quote digest refuses
    with ``booking:undisclosed_personalized_pricing`` (Delta/Ctrip
    lesson). Fixed pricing needs no disclosure.
    """
    quote_digest = _check_hex64(quote_digest, "quote_digest")
    if pricing_kind not in PRICING_KINDS:
        raise BookingError(f"unknown pricing kind {pricing_kind!r}")
    if pricing_kind not in DISCLOSURE_REQUIRED:
        return BookingVerdict(
            allowed=True,
            reason="fixed pricing needs no disclosure",
            classification=CLASS_AUTHORITATIVE,
        )
    for receipt in disclosures:
        payload = _disclosure_payload(
            receipt_id=receipt.receipt_id,
            quote_digest=receipt.quote_digest,
            pricing_kind=receipt.pricing_kind,
            disclosure_digest=receipt.disclosure_digest,
            issued_by=receipt.issued_by,
            issued_at=receipt.issued_at,
            prev_hash=receipt.prev_hash,
        )
        if _payload_digest(payload) != receipt.receipt_digest:
            continue
        if not _authority_payload(
            registry, receipt.issued_by, payload, receipt.signature_hex
        ):
            continue
        if (
            hmac.compare_digest(receipt.quote_digest, quote_digest)
            and receipt.pricing_kind == pricing_kind
        ):
            return BookingVerdict(
                allowed=True,
                reason=f"{pricing_kind} pricing disclosed",
                classification=CLASS_AUTHORITATIVE,
                receipt_digest=receipt.receipt_digest,
            )
    return BookingVerdict(
        allowed=False,
        reason=(
            f"{DENY_UNDISCLOSED_PRICING}: {pricing_kind} pricing for quote "
            "has no merchant-signed disclosure binding"
        ),
        classification=CLASS_NON_AUTHORITATIVE,
        mandatory_human_review=True,
    )


# ---------------------------------------------------------------------------
# PolicyReceipt — pinned support policy (Air Canada lesson)
# ---------------------------------------------------------------------------


def _policy_payload(
    *,
    receipt_id: str,
    policy_digest: str,
    issued_by: str,
    issued_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": BOOKING_SCHEMA_VERSION,
        "kind": "support-policy",
        "receipt_id": receipt_id,
        "policy_digest": policy_digest,
        "issued_by": issued_by,
        "issued_at": issued_at,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class PolicyReceipt:
    """Authority-signed support-policy pin. Because AI output *is*
    company output, the policy the agent serves under is pinned."""

    receipt_id: str
    policy_digest: str
    issued_by: str
    issued_at: int
    prev_hash: str
    receipt_digest: str
    signature_hex: str


def issue_policy(
    registry: AuthorityRegistry,
    authority_secret: bytes,
    *,
    receipt_id: str,
    policy_digest: str,
    issued_by: str,
    issued_at: int,
    prev_hash: str = GENESIS,
) -> PolicyReceipt:
    _check_nonempty(receipt_id, "receipt_id")
    policy_digest = _check_hex64(policy_digest, "policy_digest")
    _check_nonempty(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    if registry.public_key_for(issued_by) is None:
        raise BookingError(f"unknown authority {issued_by!r}")
    payload = _policy_payload(
        receipt_id=receipt_id,
        policy_digest=policy_digest,
        issued_by=issued_by,
        issued_at=issued_at,
        prev_hash=prev_hash,
    )
    derived = ed_public_key(bytes(authority_secret))
    registered = registry.public_key_for(issued_by)
    if not hmac.compare_digest(derived, registered or b""):
        raise BookingError("authority secret does not match registered public key")
    return PolicyReceipt(
        receipt_id=receipt_id,
        policy_digest=policy_digest,
        issued_by=issued_by,
        issued_at=issued_at,
        prev_hash=prev_hash,
        receipt_digest=_payload_digest(payload),
        signature_hex=_sign_payload(authority_secret, payload),
    )


def policy_consistency_gate(
    registry: AuthorityRegistry,
    policies: list[PolicyReceipt],
    *,
    output_policy_digest: str,
    check_time: int,
) -> BookingVerdict:
    """Support outputs must match the pinned policy digest.

    Mismatch -> deny, audit ``booking.policy_drift``, and route to a
    human (Air Canada lesson: the output is the company's, so the
    policy is pinned and drift is a violation, not a style choice).
    """
    output_policy_digest = _check_hex64(output_policy_digest, "output_policy_digest")
    check_time = _check_ts(check_time, "check_time")
    for receipt in policies:
        payload = _policy_payload(
            receipt_id=receipt.receipt_id,
            policy_digest=receipt.policy_digest,
            issued_by=receipt.issued_by,
            issued_at=receipt.issued_at,
            prev_hash=receipt.prev_hash,
        )
        if _payload_digest(payload) != receipt.receipt_digest:
            continue
        if not _authority_payload(
            registry, receipt.issued_by, payload, receipt.signature_hex
        ):
            continue
        if receipt.issued_at <= check_time and hmac.compare_digest(
            receipt.policy_digest, output_policy_digest
        ):
            return BookingVerdict(
                allowed=True,
                reason="output matches pinned support policy",
                classification=CLASS_AUTHORITATIVE,
                receipt_digest=receipt.receipt_digest,
            )
    return BookingVerdict(
        allowed=False,
        reason=(
            f"{DENY_POLICY_DRIFT}: output policy digest does not match any "
            "authority-pinned policy; audit booking.policy_drift, human handoff"
        ),
        classification=CLASS_NON_AUTHORITATIVE,
        mandatory_human_review=True,
    )


# ---------------------------------------------------------------------------
# RebookingReceipt — pre-emptive rebooking before denied boarding
# ---------------------------------------------------------------------------


def _rebooking_payload(
    *,
    receipt_id: str,
    passenger_id: str,
    flight_digest: str,
    new_flight_digest: str,
    reason: str,
    created_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": BOOKING_SCHEMA_VERSION,
        "kind": "preemptive-rebooking",
        "receipt_id": receipt_id,
        "passenger_id": passenger_id,
        "flight_digest": flight_digest,
        "new_flight_digest": new_flight_digest,
        "reason": reason,
        "created_at": created_at,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class RebookingReceipt:
    """Hash-chained pre-emptive rebooking receipt. The chain proves
    the carrier negotiated alternatives *before* any denied boarding."""

    receipt_id: str
    passenger_id: str
    flight_digest: str
    new_flight_digest: str
    reason: str
    created_at: int
    prev_hash: str
    receipt_digest: str


class RebookingLog:
    """Hash-chained log of pre-emptive rebookings."""

    def __init__(self) -> None:
        self._receipts: list[RebookingReceipt] = []
        self._expected_prev = GENESIS

    def append(
        self,
        *,
        receipt_id: str,
        passenger_id: str,
        flight_digest: str,
        new_flight_digest: str,
        reason: str,
        created_at: int,
    ) -> RebookingReceipt:
        _check_nonempty(receipt_id, "receipt_id")
        _check_nonempty(passenger_id, "passenger_id")
        flight_digest = _check_hex64(flight_digest, "flight_digest")
        new_flight_digest = _check_hex64(new_flight_digest, "new_flight_digest")
        _check_nonempty(reason, "reason")
        created_at = _check_ts(created_at, "created_at")
        prev_hash = self._expected_prev
        payload = _rebooking_payload(
            receipt_id=receipt_id,
            passenger_id=passenger_id,
            flight_digest=flight_digest,
            new_flight_digest=new_flight_digest,
            reason=reason,
            created_at=created_at,
            prev_hash=prev_hash,
        )
        receipt = RebookingReceipt(
            receipt_id=receipt_id,
            passenger_id=passenger_id,
            flight_digest=flight_digest,
            new_flight_digest=new_flight_digest,
            reason=reason,
            created_at=created_at,
            prev_hash=prev_hash,
            receipt_digest=_payload_digest(payload),
        )
        self._receipts.append(receipt)
        self._expected_prev = receipt.receipt_digest
        return receipt

    def _verify(self) -> None:
        expected_prev = GENESIS
        for receipt in self._receipts:
            payload = _rebooking_payload(
                receipt_id=receipt.receipt_id,
                passenger_id=receipt.passenger_id,
                flight_digest=receipt.flight_digest,
                new_flight_digest=receipt.new_flight_digest,
                reason=receipt.reason,
                created_at=receipt.created_at,
                prev_hash=receipt.prev_hash,
            )
            if _payload_digest(payload) != receipt.receipt_digest:
                raise BookingError(f"rebooking {receipt.receipt_id!r} digest mismatch")
            if receipt.prev_hash != expected_prev:
                raise BookingError(f"rebooking {receipt.receipt_id!r} chain gap")
            expected_prev = receipt.receipt_digest

    def deny_boarding_gate(
        self,
        *,
        passenger_id: str,
        flight_digest: str,
        denial_time: int,
    ) -> BookingVerdict:
        """Fail-closed: denied boarding needs a preceding rebooking.

        A denied-boarding action without a pre-emptive rebooking
        receipt for the *same passenger and flight*, created *before*
        the denial, is ``booking:unverifiable_denial`` (the legal gap
        around system-error denied boarding).
        """
        passenger_id = _check_nonempty(passenger_id, "passenger_id")
        flight_digest = _check_hex64(flight_digest, "flight_digest")
        denial_time = _check_ts(denial_time, "denial_time")
        try:
            self._verify()
        except BookingError as error:
            return BookingVerdict(
                allowed=False,
                reason=f"{DENY_CHAIN_GAP}: rebooking log integrity failure: {error}",
                classification=CLASS_NON_AUTHORITATIVE,
                mandatory_human_review=True,
            )
        for receipt in self._receipts:
            if (
                receipt.passenger_id == passenger_id
                and hmac.compare_digest(receipt.flight_digest, flight_digest)
                and receipt.created_at < denial_time
            ):
                return BookingVerdict(
                    allowed=True,
                    reason="pre-emptive rebooking precedes denial",
                    classification=CLASS_AUTHORITATIVE,
                    receipt_digest=receipt.receipt_digest,
                )
        return BookingVerdict(
            allowed=False,
            reason=(
                f"{DENY_UNVERIFIABLE_DENIAL}: no pre-emptive rebooking receipt "
                f"for passenger={passenger_id!r} before denial"
            ),
            classification=CLASS_NON_AUTHORITATIVE,
            mandatory_human_review=True,
        )


# ---------------------------------------------------------------------------
# SessionReceipt — context-continuity chain (APAC churn lesson)
# ---------------------------------------------------------------------------


def _session_payload(
    *,
    session_id: str,
    agent_id: str,
    traveler_id: str,
    turn_digest: str,
    started_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": BOOKING_SCHEMA_VERSION,
        "kind": "session-turn",
        "session_id": session_id,
        "agent_id": agent_id,
        "traveler_id": traveler_id,
        "turn_digest": turn_digest,
        "started_at": started_at,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class SessionTurn:
    """One hash-chained turn of a booking session. The chain pins the
    conversation's evolving context; a lost turn breaks the chain."""

    session_id: str
    agent_id: str
    traveler_id: str
    turn_digest: str
    started_at: int
    prev_hash: str
    receipt_digest: str


class BookingSession:
    """Hash-chained session with a context-continuity probe."""

    def __init__(self, *, session_id: str, agent_id: str, traveler_id: str) -> None:
        self._session_id = _check_nonempty(session_id, "session_id")
        self._agent_id = _check_nonempty(agent_id, "agent_id")
        self._traveler_id = _check_nonempty(traveler_id, "traveler_id")
        self._turns: list[SessionTurn] = []
        self._expected_prev = GENESIS
        self._broken = False

    def append_turn(self, *, turn_digest: str, started_at: int) -> SessionTurn:
        turn_digest = _check_hex64(turn_digest, "turn_digest")
        started_at = _check_ts(started_at, "started_at")
        if self._broken:
            raise BookingError("session context broken: restart with fresh consent")
        prev_hash = self._expected_prev
        payload = _session_payload(
            session_id=self._session_id,
            agent_id=self._agent_id,
            traveler_id=self._traveler_id,
            turn_digest=turn_digest,
            started_at=started_at,
            prev_hash=prev_hash,
        )
        turn = SessionTurn(
            session_id=self._session_id,
            agent_id=self._agent_id,
            traveler_id=self._traveler_id,
            turn_digest=turn_digest,
            started_at=started_at,
            prev_hash=prev_hash,
            receipt_digest=_payload_digest(payload),
        )
        self._turns.append(turn)
        self._expected_prev = turn.receipt_digest
        return turn

    def mark_context_lost(self) -> None:
        """Record a context-loss marker (e.g. provider restart,
        memory wipe, model swap mid-conversation)."""
        self._broken = True

    def context_continuity_probe(self, *, check_time: int) -> BookingVerdict:
        """Fail-closed probe: a broken session must restart.

        Context-loss markers trigger ``booking:context_broken`` — the
        session must restart with fresh consent. Continuing a booking
        on broken context is not allowed (APAC churn lesson).
        """
        check_time = _check_ts(check_time, "check_time")
        if self._broken:
            return BookingVerdict(
                allowed=False,
                reason=(
                    f"{DENY_CONTEXT_BROKEN}: session {self._session_id!r} lost "
                    "context; restart with fresh consent"
                ),
                classification=CLASS_NON_AUTHORITATIVE,
                mandatory_human_review=True,
            )
        expected_prev = GENESIS
        for turn in self._turns:
            payload = _session_payload(
                session_id=turn.session_id,
                agent_id=turn.agent_id,
                traveler_id=turn.traveler_id,
                turn_digest=turn.turn_digest,
                started_at=turn.started_at,
                prev_hash=turn.prev_hash,
            )
            if _payload_digest(payload) != turn.receipt_digest:
                return BookingVerdict(
                    allowed=False,
                    reason=f"{DENY_CONTEXT_BROKEN}: session turn digest mismatch",
                    classification=CLASS_NON_AUTHORITATIVE,
                    mandatory_human_review=True,
                )
            if turn.prev_hash != expected_prev:
                return BookingVerdict(
                    allowed=False,
                    reason=f"{DENY_CONTEXT_BROKEN}: session chain gap",
                    classification=CLASS_NON_AUTHORITATIVE,
                    mandatory_human_review=True,
                )
            expected_prev = turn.receipt_digest
        return BookingVerdict(
            allowed=True,
            reason=f"session {self._session_id!r} context continuous",
            classification=CLASS_AUTHORITATIVE,
            receipt_digest=self._expected_prev
            if self._expected_prev != GENESIS
            else "",
        )


# ---------------------------------------------------------------------------
# RecommendationDisclosure — paid-placement neutrality
# ---------------------------------------------------------------------------


def _recommendation_payload(
    *,
    receipt_id: str,
    recommendation_digest: str,
    paid_placement: bool,
    disclosure_digest: str,
    issued_by: str,
    issued_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": BOOKING_SCHEMA_VERSION,
        "kind": "recommendation-disclosure",
        "receipt_id": receipt_id,
        "recommendation_digest": recommendation_digest,
        "paid_placement": paid_placement,
        "disclosure_digest": disclosure_digest,
        "issued_by": issued_by,
        "issued_at": issued_at,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class RecommendationDisclosureReceipt:
    """Merchant-authority-signed neutrality disclosure for a
    recommendation (e.g. hotel ranking)."""

    receipt_id: str
    recommendation_digest: str
    paid_placement: bool
    disclosure_digest: str
    issued_by: str
    issued_at: int
    prev_hash: str
    receipt_digest: str
    signature_hex: str


def issue_recommendation_disclosure(
    registry: AuthorityRegistry,
    authority_secret: bytes,
    *,
    receipt_id: str,
    recommendation_digest: str,
    paid_placement: bool,
    disclosure_digest: str,
    issued_by: str,
    issued_at: int,
    prev_hash: str = GENESIS,
) -> RecommendationDisclosureReceipt:
    _check_nonempty(receipt_id, "receipt_id")
    recommendation_digest = _check_hex64(recommendation_digest, "recommendation_digest")
    disclosure_digest = _check_hex64(disclosure_digest, "disclosure_digest")
    _check_nonempty(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    if registry.public_key_for(issued_by) is None:
        raise BookingError(f"unknown authority {issued_by!r}")
    payload = _recommendation_payload(
        receipt_id=receipt_id,
        recommendation_digest=recommendation_digest,
        paid_placement=bool(paid_placement),
        disclosure_digest=disclosure_digest,
        issued_by=issued_by,
        issued_at=issued_at,
        prev_hash=prev_hash,
    )
    derived = ed_public_key(bytes(authority_secret))
    registered = registry.public_key_for(issued_by)
    if not hmac.compare_digest(derived, registered or b""):
        raise BookingError("authority secret does not match registered public key")
    return RecommendationDisclosureReceipt(
        receipt_id=receipt_id,
        recommendation_digest=recommendation_digest,
        paid_placement=bool(paid_placement),
        disclosure_digest=disclosure_digest,
        issued_by=issued_by,
        issued_at=issued_at,
        prev_hash=prev_hash,
        receipt_digest=_payload_digest(payload),
        signature_hex=_sign_payload(authority_secret, payload),
    )


def commercial_bias_gate(
    registry: AuthorityRegistry,
    disclosures: list[RecommendationDisclosureReceipt],
    *,
    recommendation_digest: str,
    paid_placement: bool,
) -> BookingVerdict:
    """Fail-closed: paid placement must carry a disclosure.

    A recommendation with paid-placement influence and no
    merchant-signed neutrality disclosure binding the exact
    recommendation digest denies with
    ``booking:hidden_commercial_bias``. Recommendations without paid
    placement need no disclosure.
    """
    recommendation_digest = _check_hex64(
        recommendation_digest, "recommendation_digest"
    )
    if not paid_placement:
        return BookingVerdict(
            allowed=True,
            reason="no paid placement: no disclosure required",
            classification=CLASS_AUTHORITATIVE,
        )
    for receipt in disclosures:
        payload = _recommendation_payload(
            receipt_id=receipt.receipt_id,
            recommendation_digest=receipt.recommendation_digest,
            paid_placement=receipt.paid_placement,
            disclosure_digest=receipt.disclosure_digest,
            issued_by=receipt.issued_by,
            issued_at=receipt.issued_at,
            prev_hash=receipt.prev_hash,
        )
        if _payload_digest(payload) != receipt.receipt_digest:
            continue
        if not _authority_payload(
            registry, receipt.issued_by, payload, receipt.signature_hex
        ):
            continue
        if hmac.compare_digest(
            receipt.recommendation_digest, recommendation_digest
        ) and receipt.paid_placement:
            return BookingVerdict(
                allowed=True,
                reason="paid placement disclosed",
                classification=CLASS_AUTHORITATIVE,
                receipt_digest=receipt.receipt_digest,
            )
    return BookingVerdict(
        allowed=False,
        reason=(
            f"{DENY_HIDDEN_COMMERCIAL_BIAS}: paid-placement recommendation "
            "has no merchant-signed neutrality disclosure"
        ),
        classification=CLASS_NON_AUTHORITATIVE,
        mandatory_human_review=True,
    )
