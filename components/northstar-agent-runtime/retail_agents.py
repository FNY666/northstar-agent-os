"""Retail & e-commerce AI discipline (one-hundred-sixty-fourth batch).

Absorbs the 2026 AI-retail research thread
(``research_notes/beyond-ai-retail-20261004/report.md``):

* **Surveillance pricing** — the 2026 front line. The FTC's 2026-08
  proposed Section 5 policy statement says undisclosed personalized
  pricing (prices set from browsing history, location, demographics,
  loyalty records, purchase patterns to estimate willingness to pay
  or comparison-shopping propensity) is likely deceptive or unfair
  — but the FTC admits enforcement bandwidth is limited and the
  focus is transparency, not banning the practice. New York's
  Algorithmic Pricing Disclosure Act (effective 2025-07-08) already
  requires a disclosure when personal data is used for algorithmic
  pricing and bans protected-class data; the NRF is suing it on
  First Amendment grounds. California AB 2564 died on a procedural
  miss. Walmart's CEO publicly pinned "we price the product, not
  the person" (2026-09-25): AI for the Sparky assistant, demand
  forecasting and ops — never for setting personalized prices.
* **Electronic shelf labels (ESL)** — Walmart rolls ESLs into all
  4,611 US stores by end-2026; Congress's Stop Price Gouging in
  Grocery Stores Act of 2026 (S.3892) would ban ESLs in large food
  stores, ban surveillance pricing, and require facial-recognition
  disclosure.
* **Agentic commerce** — Amazon Rufus (250M users claimed, MAU
  +149% YoY), Walmart Sparky (+35% basket claimed), Adobe: AI-driven
  US e-commerce traffic +758% in the 2025 Thanksgiving season. The
  xmr402 wallet problem: on transparent ledgers an agent's wallet
  balance, spend rate, counterparty graph and accepted prices are
  public — a willingness-to-pay oracle needs no data collection,
  so disclosure rules cannot reach it. The Northstar answer is a
  quote-blindness gate: quotes must not read wallet/spending-graph
  signals.
* **Shopping-assistant hallucinations** — Product.ai (2026-09):
  across 8,794 answers to 220 shopping questions, 86% of questions
  had a verifiable factual contradiction (price/spec/model).
  Productrise (2026-08): Google AI Mode results carried a 21.6%
  average premium with ~95% fewer items. Un-evidenced claims are
  NON_AUTHORITATIVE here.
* **China's 大数据杀熟 ban** — the 互联网平台价格行为规则
  (effective 2026-04-10, valid 5 years), Art.15: platforms may not
  set different prices for the same product under identical
  conditions from payment-willingness/ability/preference/habit data
  without the consumer's knowledge. Ctrip's ¥5.179B fine (2026-07);
  Beijing's 2026-09 investigation of hotel/travel platforms over
  opaque commissions and ranking.
* **Dark patterns** — the EU Digital Fairness Act (autumn 2026
  proposal) targets dark patterns, addictive design and unfair
  personalization; DSA Art.25 already bans interface dark patterns
  on platforms (in force 2024-02); Japan's dark-pattern association
  guidelines v1.3 (2026-07) say mid-flow personal data capture the
  user does not notice is a dark pattern, with an NDD certification.
* **Algorithmic management of workers** — Amazon's ADAPT/TOT
  second-level tracking with dynamic quotas and auto-elimination of
  the bottom 5% drew a 2026-09 federal class action alleging
  discrimination against pregnant warehouse workers; CNIL fined
  Amazon France Logistique €32M for intrusive scanner tracking
  (fine reduced but the core privacy violation upheld in 2025-12);
  Amazon's smart delivery glasses criticism and in-cab Driver.i
  driver recording.

Northstar mapping: personalized prices bind disclosure receipts —
undisclosed is ``retail.undisclosed_personalization`` (FTC/NY
lesson); pricing features that reconstruct protected classes are
refused whole-class (``retail.proxy_pricing_feature``,
California-AB-2564 spirit); ESL price changes bind immutable change
logs and cart-vs-shelf mismatches are
``retail.cart_shelf_mismatch``; ops-AI and pricing are isolated by
the product-not-person pin — personalization data crossing into the
pricing engine is ``retail.pricing_data_crossed`` (the architectural
version of Walmart's pledge); high-premium upsells bind
why-this-item reason receipts (``retail.opaque_upsell``);
agent-to-agent quotes must not read wallet/spending-graph signals —
reading is ``retail.wtp_scored`` (xmr402 lesson); shopping-assistant
price/spec/model claims bind evidence digests or are
NON_AUTHORITATIVE (``retail.unverified_claim``, the 86%
contradiction lesson); checkout dark patterns screen to
``retail.dark_pattern`` (EU DFA + Japan v1.3); same-item
different-user price gaps bind justification receipts —
unjustified is ``retail.price_discrimination`` (大数据杀熟,
Art.15); platform ranking/traffic/commission rules must be
disclosed to merchants — opaque is ``retail.merchant_opaque``
(Beijing investigation lesson); algorithmic warehouse quotas are
disclosed and auto-termination requires human review —
termination without it is ``retail.auto_termination`` (Amazon
class-action / CNIL lesson); delivery-wearable collection binds
purpose/scope/retention receipts — overreach is
``retail.wearable_overreach``.

Deterministic: no wall-clock reads (callers inject ``now`` as an
integer epoch), canonical JCS hashing (ninety-fifth batch), and all
digest comparisons use :func:`hmac.compare_digest`.

Honest scope:

* The receipts bind the *declared* retail discipline; they do not
  end price discrimination, they do not fix algorithmic-management
  injuries, and they do not make shopping-assistant hallucinations
  go away.
* The disclosure gates record that a statement was shown; they do
  not prove the consumer understood it.
* ESL change logs are event declarations: an unlogged change is
  ``retail.unlogged_change``, not proof of an actual price.
* Quote-blindness binds declared read-free quoting; it cannot see
  inside a counterparty's engine.
* Signature checks bind authority to receipt; they cannot prove
  the named authority actually audited the flow.
"""

from __future__ import annotations
from _domain_base import DomainError

import hashlib
import hmac
from dataclasses import dataclass
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


RETAIL_SCHEMA_VERSION = "northstar.retail.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_DAY_S = 86_400

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Receipt shelf lives.
DISCLOSURE_MAX_AGE_S = 365 * _DAY_S
ESL_LOG_MAX_AGE_S = 365 * _DAY_S
CLAIM_MAX_AGE_S = 180 * _DAY_S
RULE_MAX_AGE_S = 365 * _DAY_S
QUOTA_MAX_AGE_S = 365 * _DAY_S

#: Pricing features that reconstruct protected classes are refused
#: whole-class (California AB 2564 spirit; with finance.proxy_screen).
PRICING_PROXY_FEATURES = frozenset({
    "zip_code",
    "postal_code",
    "device_model",
    "browsing_history_category",
    "location_cluster",
    "income_proxy",
    "ethnicity_proxy",
    "age_band_proxy",
})

#: Data channels that cross the product-not-person pin: any flow that
#: carries individual-level personalization into the pricing engine.
#: Operations AI (demand forecasting, replenishment, routing) may use
#: aggregate signals only.
PERSONALIZATION_CHANNELS = frozenset({
    "browsing_history",
    "purchase_history",
    "loyalty_profile",
    "device_fingerprint",
    "location_trace",
    "willingness_to_pay_score",
})

#: Channels allowed into the pricing engine.
AGGREGATE_CHANNELS = frozenset({
    "aggregate_demand_forecast",
    "inventory_level",
    "competitor_list_price",
    "published_cost_index",
})

#: Dark-pattern patterns screened at checkout (EU Digital Fairness Act
#: direction + Japan dark-pattern guidelines v1.3).
DARK_PATTERNS = frozenset({
    "unnoticed_data_capture",
    "roach_motel",  # subscribe easy, cancel hard
    "fake_countdown",
    "hidden_auto_renew",
    "confirmshaming",
    "basket_sneaking",
    "forced_continuity",
})

#: Wallet/spending-graph signals a quote must not read (xmr402 lesson).
WTP_SIGNALS = frozenset({
    "wallet_balance",
    "spend_rate",
    "counterparty_graph",
    "accepted_price_history",
    "credit_limit",
})


class RetailError(DomainError):
    """A malformed retail-discipline receipt or a programming error.

    Raised for structural problems (bad digests, broken chains).
    Verification *failures* return a :class:`RetailVerdict` with
    ``allowed=False`` instead — a failed gate is a verdict, a
    malformed receipt is a bug.
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
        raise RetailError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RetailError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RetailError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_pubkey_hex(value: Any) -> str:
    return _check_hex64(value, "authority_pubkey_hex")


def _verify_signature(
    pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str
) -> bool:
    # one-hundred-fifty-fifth batch: vendored ed25519.verify() returns a
    # bool and never raises; the return value must be honored (the old
    # try/except-around-verify pattern silently approved everything).
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
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise RetailError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise RetailError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(
            entry.authority_pubkey_hex, signed_body, entry.signature_hex
        ):
            raise RetailError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class RetailVerdict:
    """Outcome of one retail-discipline gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> RetailVerdict:
    return RetailVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> RetailVerdict:
    return RetailVerdict(
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

    def get(self, authority_id: str) -> str:
        try:
            return self._pubkeys[authority_id]
        except KeyError:
            raise RetailError(f"unknown authority {authority_id!r}") from None


def _authority_pubkey(authorities: AuthorityRegistry, authority_id: str) -> str:
    return authorities.get(authority_id)


def _sign_receipt(payload: dict[str, Any], authority_secret: bytes) -> tuple[str, str]:
    signed_body = dict(payload)
    signed_body["signature_hex"] = "00" * 64
    signature_hex = ed25519.sign(
        authority_secret, jcs_canonical_json(signed_body)
    ).hex()
    digest = jcs_sha256_hex(payload)
    return signature_hex, digest


# ---------------------------------------------------------------------------
# 1. Personalized-price disclosure (FTC 2026-08 + NY disclosure lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PriceDisclosureReceipt:
    """Binds the disclosure statement shown with a personalized price."""

    receipt_id: str
    merchant_id: str
    item_id: str
    personalized_price_minor: int
    disclosure_text: str
    shown_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "price_disclosure",
            "receipt_id": self.receipt_id,
            "merchant_id": self.merchant_id,
            "item_id": self.item_id,
            "personalized_price_minor": self.personalized_price_minor,
            "disclosure_text": self.disclosure_text,
            "shown_at": self.shown_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class PriceDisclosureRegistry:
    """Hash-chained log of personalized-price disclosure receipts."""

    authorities: AuthorityRegistry
    log: list[PriceDisclosureReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        merchant_id: str,
        item_id: str,
        personalized_price_minor: int,
        disclosure_text: str,
        shown_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> PriceDisclosureReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(merchant_id, "merchant_id")
        _check_nonempty_str(item_id, "item_id")
        if not isinstance(personalized_price_minor, int) or personalized_price_minor < 0:
            raise RetailError("personalized_price_minor must be a non-negative int")
        _check_nonempty_str(disclosure_text, "disclosure_text")
        _check_ts(shown_at, "shown_at")
        pubkey = _authority_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        payload = {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "price_disclosure",
            "receipt_id": receipt_id,
            "merchant_id": merchant_id,
            "item_id": item_id,
            "personalized_price_minor": personalized_price_minor,
            "disclosure_text": disclosure_text,
            "shown_at": shown_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        signature_hex, digest = _sign_receipt(payload, authority_secret)
        receipt = PriceDisclosureReceipt(
            receipt_id=receipt_id,
            merchant_id=merchant_id,
            item_id=item_id,
            personalized_price_minor=personalized_price_minor,
            disclosure_text=disclosure_text,
            shown_at=shown_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=digest,
        )
        self.log.append(receipt)
        _check_chain(self.log, "price_disclosure")
        return receipt

    def get(self, receipt_id: str) -> PriceDisclosureReceipt | None:
        for entry in self.log:
            if entry.receipt_id == receipt_id:
                return entry
        return None


def personalized_price_disclosure(
    disclosures: PriceDisclosureRegistry,
    receipt_id: str,
    merchant_id: str,
    item_id: str,
    price_minor: int,
    now: int,
) -> RetailVerdict:
    """A personalized price binds its disclosure receipt.

    The statement shown with the price (FTC 2026-08 policy / NY
    disclosure law operationalized) must exist, belong to this
    merchant+item, carry the same price, and be live. Undisclosed
    personalized pricing is ``retail.undisclosed_personalization``.
    Disclosure records the statement shown, not that the consumer
    understood it.
    """
    _check_ts(now, "now")
    receipt = disclosures.get(receipt_id)
    if receipt is None:
        return _deny(
            "retail:undisclosed_personalization",
            f"personalized price for {item_id!r} has no disclosure receipt",
        )
    if receipt.merchant_id != merchant_id or receipt.item_id != item_id:
        return _deny(
            "retail:disclosure_mismatch",
            f"disclosure receipt {receipt_id!r} does not cover "
            f"{merchant_id!r}/{item_id!r}",
        )
    if receipt.personalized_price_minor != price_minor:
        return _deny(
            "retail:disclosure_price_mismatch",
            f"disclosure receipt {receipt_id!r} covers a different price",
        )
    if receipt.shown_at > now:
        return _deny(
            "retail:future_disclosure",
            f"disclosure receipt {receipt_id!r} shown in the future",
        )
    if now - receipt.shown_at > DISCLOSURE_MAX_AGE_S:
        return _deny(
            "retail:stale_disclosure",
            f"disclosure receipt {receipt_id!r} is older than 365 days",
        )
    return _allow(
        f"personalized price for {item_id!r} disclosed "
        f"({receipt.disclosure_text[:48]!r}...)",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 2. No protected-class pricing (AB 2564 spirit)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PricingFeatureAudit:
    """Declares which features the pricing engine consumes."""

    audit_id: str
    pricing_engine_id: str
    features: tuple[str, ...]
    declared_at: int
    authority_id: str

    def _payload(self) -> dict[str, Any]:  # pragma: no cover - unsigned audit
        return {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "pricing_feature_audit",
            "audit_id": self.audit_id,
            "pricing_engine_id": self.pricing_engine_id,
            "features": list(self.features),
            "declared_at": self.declared_at,
            "authority_id": self.authority_id,
        }


def no_protected_class_pricing(audit: PricingFeatureAudit) -> RetailVerdict:
    """Pricing features that reconstruct protected classes are refused.

    Whole-class refusal: no less-discriminatory-alternative balancing
    at the pricing tier. Mirrors the AB 2564 definition of
    surveillance pricing (prices set from electronically collected
    PII estimating desperation or wealth).
    """
    _check_nonempty_str(audit.audit_id, "audit_id")
    proxies = sorted(set(audit.features) & PRICING_PROXY_FEATURES)
    if proxies:
        return _deny(
            "retail:proxy_pricing_feature",
            f"pricing engine {audit.pricing_engine_id!r} consumes protected-class "
            f"reconstructing features: {', '.join(proxies)}",
        )
    return _allow(
        f"pricing engine {audit.pricing_engine_id!r} consumes no protected-class "
        "reconstructing features",
        jcs_sha256_hex(audit._payload()),
    )


# ---------------------------------------------------------------------------
# 3. ESL change log (immutable price-change log, cart/shelf probe)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ESLChangeEntry:
    """One immutable electronic-shelf-label price change."""

    entry_id: str
    store_id: str
    item_id: str
    old_price_minor: int
    new_price_minor: int
    changed_at: int
    trigger_rule: str
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "esl_change",
            "entry_id": self.entry_id,
            "store_id": self.store_id,
            "item_id": self.item_id,
            "old_price_minor": self.old_price_minor,
            "new_price_minor": self.new_price_minor,
            "changed_at": self.changed_at,
            "trigger_rule": self.trigger_rule,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class ESLChangeLog:
    """Hash-chained log of ESL price changes."""

    authorities: AuthorityRegistry
    log: list[ESLChangeEntry]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        entry_id: str,
        store_id: str,
        item_id: str,
        old_price_minor: int,
        new_price_minor: int,
        changed_at: int,
        trigger_rule: str,
        authority_id: str,
        authority_secret: bytes,
    ) -> ESLChangeEntry:
        _check_nonempty_str(entry_id, "entry_id")
        _check_nonempty_str(store_id, "store_id")
        _check_nonempty_str(item_id, "item_id")
        for name, v in (("old_price_minor", old_price_minor),
                        ("new_price_minor", new_price_minor)):
            if not isinstance(v, int) or v < 0:
                raise RetailError(f"{name} must be a non-negative int")
        _check_ts(changed_at, "changed_at")
        _check_nonempty_str(trigger_rule, "trigger_rule")
        pubkey = _authority_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        payload = {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "esl_change",
            "entry_id": entry_id,
            "store_id": store_id,
            "item_id": item_id,
            "old_price_minor": old_price_minor,
            "new_price_minor": new_price_minor,
            "changed_at": changed_at,
            "trigger_rule": trigger_rule,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        signature_hex, digest = _sign_receipt(payload, authority_secret)
        entry = ESLChangeEntry(
            entry_id=entry_id,
            store_id=store_id,
            item_id=item_id,
            old_price_minor=old_price_minor,
            new_price_minor=new_price_minor,
            changed_at=changed_at,
            trigger_rule=trigger_rule,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=digest,
        )
        self.log.append(entry)
        _check_chain(self.log, "esl_change")
        return entry

    def latest_for(self, store_id: str, item_id: str) -> ESLChangeEntry | None:
        for entry in reversed(self.log):
            if entry.store_id == store_id and entry.item_id == item_id:
                return entry
        return None


def esl_change_log(
    change_log: ESLChangeLog,
    store_id: str,
    item_id: str,
    cart_price_minor: int,
    now: int,
) -> RetailVerdict:
    """Cart price must match the latest logged shelf price.

    A mismatch between what the cart charges and what the latest
    logged ESL change shows is ``retail.cart_shelf_mismatch``; an
    item with no logged change at all is ``retail.unlogged_change``.
    """
    _check_ts(now, "now")
    entry = change_log.latest_for(store_id, item_id)
    if entry is None:
        return _deny(
            "retail:unlogged_change",
            f"item {item_id!r} in store {store_id!r} has no logged ESL change",
        )
    if entry.changed_at > now:
        return _deny(
            "retail:future_esl_change",
            f"ESL change {entry.entry_id!r} is dated in the future",
        )
    if now - entry.changed_at > ESL_LOG_MAX_AGE_S:
        return _deny(
            "retail:stale_esl_entry",
            f"ESL change {entry.entry_id!r} is older than 365 days",
        )
    if entry.new_price_minor != cart_price_minor:
        return _deny(
            "retail:cart_shelf_mismatch",
            f"cart price {cart_price_minor} != logged shelf price "
            f"{entry.new_price_minor} for {item_id!r}",
        )
    return _allow(
        f"cart price matches logged shelf price for {item_id!r} "
        f"(rule {entry.trigger_rule!r})",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 4. Product-not-person pin (ops AI / pricing isolation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DataFlowDeclaration:
    """Declares which data channels feed the pricing engine."""

    declaration_id: str
    pricing_engine_id: str
    input_channels: tuple[str, ...]
    declared_at: int
    authority_id: str

    def _payload(self) -> dict[str, Any]:  # pragma: no cover - unsigned audit
        return {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "data_flow_declaration",
            "declaration_id": self.declaration_id,
            "pricing_engine_id": self.pricing_engine_id,
            "input_channels": list(self.input_channels),
            "declared_at": self.declared_at,
            "authority_id": self.authority_id,
        }


def product_not_person_pin(decl: DataFlowDeclaration) -> RetailVerdict:
    """Individual-level personalization data may not enter the pricing engine.

    The architectural version of Walmart's "we price the product, not
    the person": ops AI (demand forecasting, replenishment, routing)
    may feed aggregate channels; anything in
    :data:`PERSONALIZATION_CHANNELS` crossing into pricing is
    ``retail.pricing_data_crossed``.
    """
    _check_nonempty_str(decl.declaration_id, "declaration_id")
    crossed = sorted(set(decl.input_channels) & PERSONALIZATION_CHANNELS)
    if crossed:
        return _deny(
            "retail:pricing_data_crossed",
            f"personalization channels feed the pricing engine "
            f"{decl.pricing_engine_id!r}: {', '.join(crossed)}",
        )
    return _allow(
        f"pricing engine {decl.pricing_engine_id!r} sees only non-personalizing "
        f"channels ({', '.join(sorted(decl.input_channels)) or 'none'})",
        jcs_sha256_hex(decl._payload()),
    )


# ---------------------------------------------------------------------------
# 5. Upsell transparency (why-this-item + visible alternatives)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UpsellReceipt:
    """Binds a high-premium upsell recommendation to its reason."""

    receipt_id: str
    merchant_id: str
    item_id: str
    list_price_minor: int
    offered_price_minor: int
    reason_text: str
    alternatives: tuple[str, ...]
    recommended_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "upsell_reason",
            "receipt_id": self.receipt_id,
            "merchant_id": self.merchant_id,
            "item_id": self.item_id,
            "list_price_minor": self.list_price_minor,
            "offered_price_minor": self.offered_price_minor,
            "reason_text": self.reason_text,
            "alternatives": list(self.alternatives),
            "recommended_at": self.recommended_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class UpsellRegistry:
    """Hash-chained log of upsell reason receipts."""

    authorities: AuthorityRegistry
    log: list[UpsellReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        merchant_id: str,
        item_id: str,
        list_price_minor: int,
        offered_price_minor: int,
        reason_text: str,
        alternatives: tuple[str, ...],
        recommended_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> UpsellReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(merchant_id, "merchant_id")
        _check_nonempty_str(item_id, "item_id")
        for name, v in (("list_price_minor", list_price_minor),
                        ("offered_price_minor", offered_price_minor)):
            if not isinstance(v, int) or v < 0:
                raise RetailError(f"{name} must be a non-negative int")
        _check_nonempty_str(reason_text, "reason_text")
        _check_ts(recommended_at, "recommended_at")
        pubkey = _authority_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        payload = {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "upsell_reason",
            "receipt_id": receipt_id,
            "merchant_id": merchant_id,
            "item_id": item_id,
            "list_price_minor": list_price_minor,
            "offered_price_minor": offered_price_minor,
            "reason_text": reason_text,
            "alternatives": list(alternatives),
            "recommended_at": recommended_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        signature_hex, digest = _sign_receipt(payload, authority_secret)
        receipt = UpsellReceipt(
            receipt_id=receipt_id,
            merchant_id=merchant_id,
            item_id=item_id,
            list_price_minor=list_price_minor,
            offered_price_minor=offered_price_minor,
            reason_text=reason_text,
            alternatives=tuple(alternatives),
            recommended_at=recommended_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=digest,
        )
        self.log.append(receipt)
        _check_chain(self.log, "upsell_reason")
        return receipt

    def get(self, receipt_id: str) -> UpsellReceipt | None:
        for entry in self.log:
            if entry.receipt_id == receipt_id:
                return entry
        return None


#: Premium over the list price that triggers the upsell-transparency gate.
UPSELL_PREMIUM_THRESHOLD_RATIO = 0.10


def upsell_transparency(
    upsells: UpsellRegistry,
    receipt_id: str,
    now: int,
) -> RetailVerdict:
    """High-premium AI upsells bind why-this-item reasons + alternatives.

    An upsell priced more than ``UPSELL_PREMIUM_THRESHOLD_RATIO``
    above the list price with no reason receipt (or a receipt with no
    visible alternatives) is ``retail.opaque_upsell`` — the Productrise
    21.6% AI-Mode premium lesson.
    """
    _check_ts(now, "now")
    receipt = upsells.get(receipt_id)
    if receipt is None:
        return _deny(
            "retail:opaque_upsell",
            f"upsell for {receipt_id!r} has no why-this-item reason receipt",
        )
    if receipt.recommended_at > now:
        return _deny(
            "retail:future_upsell",
            f"upsell receipt {receipt_id!r} recommended in the future",
        )
    if receipt.list_price_minor > 0 and (
        receipt.offered_price_minor - receipt.list_price_minor
    ) / receipt.list_price_minor > UPSELL_PREMIUM_THRESHOLD_RATIO:
        if not receipt.alternatives:
            return _deny(
                "retail:opaque_upsell",
                f"premium upsell {receipt_id!r} shows no visible alternatives",
            )
    return _allow(
        f"upsell {receipt_id!r} bound to reason and "
        f"{len(receipt.alternatives)} alternative(s)",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 6. Agentic quote blindness (xmr402 wallet-oracle lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QuoteBlindnessEvidence:
    """Declares which signals an agent-to-agent quote engine read."""

    evidence_id: str
    quoting_agent_id: str
    counterparty_agent_id: str
    read_signals: tuple[str, ...]
    quoted_at: int
    authority_id: str

    def _payload(self) -> dict[str, Any]:  # pragma: no cover - unsigned audit
        return {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "quote_blindness",
            "evidence_id": self.evidence_id,
            "quoting_agent_id": self.quoting_agent_id,
            "counterparty_agent_id": self.counterparty_agent_id,
            "read_signals": list(self.read_signals),
            "quoted_at": self.quoted_at,
            "authority_id": self.authority_id,
        }


def agentic_quote_blindness(evidence: QuoteBlindnessEvidence) -> RetailVerdict:
    """Quotes must not read wallet/spending-graph willingness-to-pay signals.

    On transparent ledgers a WTP oracle needs no data collection, so
    disclosure rules cannot reach it — quotes must be blind by
    construction. Any read in :data:`WTP_SIGNALS` is
    ``retail.wtp_scored``.
    """
    _check_nonempty_str(evidence.evidence_id, "evidence_id")
    scored = sorted(set(evidence.read_signals) & WTP_SIGNALS)
    if scored:
        return _deny(
            "retail:wtp_scored",
            f"quote engine {evidence.quoting_agent_id!r} read "
            f"willingness-to-pay signals: {', '.join(scored)}",
        )
    return _allow(
        f"quote {evidence.evidence_id!r} read no wallet/spending-graph signals",
        jcs_sha256_hex(evidence._payload()),
    )


# ---------------------------------------------------------------------------
# 7. Assistant fact gate (86% contradiction lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClaimEvidenceReceipt:
    """Binds a shopping-assistant claim to its evidence digest."""

    receipt_id: str
    assistant_id: str
    item_id: str
    claim_kind: str  # "price" | "spec" | "model"
    claim_text: str
    evidence_digest: str
    observed_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "claim_evidence",
            "receipt_id": self.receipt_id,
            "assistant_id": self.assistant_id,
            "item_id": self.item_id,
            "claim_kind": self.claim_kind,
            "claim_text": self.claim_text,
            "evidence_digest": self.evidence_digest,
            "observed_at": self.observed_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class ClaimEvidenceRegistry:
    """Hash-chained log of shopping-assistant claim evidence."""

    authorities: AuthorityRegistry
    log: list[ClaimEvidenceReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        assistant_id: str,
        item_id: str,
        claim_kind: str,
        claim_text: str,
        evidence_digest: str,
        observed_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> ClaimEvidenceReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(assistant_id, "assistant_id")
        _check_nonempty_str(item_id, "item_id")
        if claim_kind not in ("price", "spec", "model"):
            raise RetailError("claim_kind must be 'price', 'spec' or 'model'")
        _check_nonempty_str(claim_text, "claim_text")
        _check_hex64(evidence_digest, "evidence_digest")
        _check_ts(observed_at, "observed_at")
        pubkey = _authority_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        payload = {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "claim_evidence",
            "receipt_id": receipt_id,
            "assistant_id": assistant_id,
            "item_id": item_id,
            "claim_kind": claim_kind,
            "claim_text": claim_text,
            "evidence_digest": evidence_digest,
            "observed_at": observed_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        signature_hex, digest = _sign_receipt(payload, authority_secret)
        receipt = ClaimEvidenceReceipt(
            receipt_id=receipt_id,
            assistant_id=assistant_id,
            item_id=item_id,
            claim_kind=claim_kind,
            claim_text=claim_text,
            evidence_digest=evidence_digest,
            observed_at=observed_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=digest,
        )
        self.log.append(receipt)
        _check_chain(self.log, "claim_evidence")
        return receipt

    def get(self, receipt_id: str) -> ClaimEvidenceReceipt | None:
        for entry in self.log:
            if entry.receipt_id == receipt_id:
                return entry
        return None


def assistant_fact_gate(
    claims: ClaimEvidenceRegistry,
    receipt_id: str,
    item_id: str,
    claim_kind: str,
    claim_text: str,
    now: int,
) -> RetailVerdict:
    """Price/spec/model claims bind evidence digests or are NON_AUTHORITATIVE.

    Evidence-free claims in a world with an 86% contradiction rate
    (Product.ai) are ``retail.unverified_claim``; a claim whose text
    does not match its receipt is ``retail.claim_mismatch``.
    """
    _check_ts(now, "now")
    receipt = claims.get(receipt_id)
    if receipt is None:
        return _deny(
            "retail:unverified_claim",
            f"assistant {claim_kind} claim for {item_id!r} has no evidence "
            f"receipt (86% contradiction-rate regime)",
        )
    if receipt.item_id != item_id or receipt.claim_kind != claim_kind:
        return _deny(
            "retail:claim_mismatch",
            f"evidence receipt {receipt_id!r} does not cover this claim",
        )
    if receipt.claim_text != claim_text:
        return _deny(
            "retail:claim_mismatch",
            f"claim text drifted from evidence receipt {receipt_id!r}",
        )
    if receipt.observed_at > now:
        return _deny(
            "retail:future_claim",
            f"evidence receipt {receipt_id!r} observed in the future",
        )
    if now - receipt.observed_at > CLAIM_MAX_AGE_S:
        return _deny(
            "retail:stale_claim_evidence",
            f"evidence receipt {receipt_id!r} is older than 180 days",
        )
    return _allow(
        f"assistant {claim_kind} claim for {item_id!r} bound to evidence digest "
        f"{receipt.evidence_digest[:16]}...",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 8. Dark-pattern screen (EU Digital Fairness Act + Japan v1.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckoutScreening:
    """Declares which dark-pattern findings a checkout audit produced."""

    screening_id: str
    merchant_id: str
    findings: tuple[str, ...]
    screened_at: int
    authority_id: str

    def _payload(self) -> dict[str, Any]:  # pragma: no cover - unsigned audit
        return {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "checkout_screening",
            "screening_id": self.screening_id,
            "merchant_id": self.merchant_id,
            "findings": list(self.findings),
            "screened_at": self.screened_at,
            "authority_id": self.authority_id,
        }


def dark_pattern_screen(screening: CheckoutScreening) -> RetailVerdict:
    """Checkout dark patterns fail closed.

    Any finding in :data:`DARK_PATTERNS` (unnoticed mid-flow data
    capture, roach-motel cancellation, fake countdowns, hidden
    auto-renew, basket sneaking, forced continuity, confirmshaming)
    is ``retail.dark_pattern``.
    """
    _check_nonempty_str(screening.screening_id, "screening_id")
    hits = sorted(set(screening.findings) & DARK_PATTERNS)
    if hits:
        return _deny(
            "retail:dark_pattern",
            f"checkout {screening.screening_id!r} of {screening.merchant_id!r} "
            f"uses dark patterns: {', '.join(hits)}",
        )
    return _allow(
        f"checkout {screening.screening_id!r} screened clean",
        jcs_sha256_hex(screening._payload()),
    )


# ---------------------------------------------------------------------------
# 9. Shasha (大数据杀熟) receipt — same-item price gaps need justification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ShashaReceipt:
    """Justifies a same-item price gap between user cohorts."""

    receipt_id: str
    platform_id: str
    item_id: str
    cohort_a: str
    price_a_minor: int
    cohort_b: str
    price_b_minor: int
    justification: str
    published_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "shasha_justification",
            "receipt_id": self.receipt_id,
            "platform_id": self.platform_id,
            "item_id": self.item_id,
            "cohort_a": self.cohort_a,
            "price_a_minor": self.price_a_minor,
            "cohort_b": self.cohort_b,
            "price_b_minor": self.price_b_minor,
            "justification": self.justification,
            "published_at": self.published_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class ShashaRegistry:
    """Hash-chained log of 大数据杀熟 justification receipts."""

    authorities: AuthorityRegistry
    log: list[ShashaReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        platform_id: str,
        item_id: str,
        cohort_a: str,
        price_a_minor: int,
        cohort_b: str,
        price_b_minor: int,
        justification: str,
        published_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> ShashaReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(platform_id, "platform_id")
        _check_nonempty_str(item_id, "item_id")
        _check_nonempty_str(cohort_a, "cohort_a")
        _check_nonempty_str(cohort_b, "cohort_b")
        for name, v in (("price_a_minor", price_a_minor),
                        ("price_b_minor", price_b_minor)):
            if not isinstance(v, int) or v < 0:
                raise RetailError(f"{name} must be a non-negative int")
        _check_nonempty_str(justification, "justification")
        _check_ts(published_at, "published_at")
        pubkey = _authority_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        payload = {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "shasha_justification",
            "receipt_id": receipt_id,
            "platform_id": platform_id,
            "item_id": item_id,
            "cohort_a": cohort_a,
            "price_a_minor": price_a_minor,
            "cohort_b": cohort_b,
            "price_b_minor": price_b_minor,
            "justification": justification,
            "published_at": published_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        signature_hex, digest = _sign_receipt(payload, authority_secret)
        receipt = ShashaReceipt(
            receipt_id=receipt_id,
            platform_id=platform_id,
            item_id=item_id,
            cohort_a=cohort_a,
            price_a_minor=price_a_minor,
            cohort_b=cohort_b,
            price_b_minor=price_b_minor,
            justification=justification,
            published_at=published_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=digest,
        )
        self.log.append(receipt)
        _check_chain(self.log, "shasha_justification")
        return receipt

    def get(self, receipt_id: str) -> ShashaReceipt | None:
        for entry in self.log:
            if entry.receipt_id == receipt_id:
                return entry
        return None


def shasha_receipt(
    justifications: ShashaRegistry,
    receipt_id: str,
    item_id: str,
    price_minor: int,
    cohort: str,
    now: int,
) -> RetailVerdict:
    """Same-item different-user price gaps bind justification receipts.

    China's 互联网平台价格行为规则 Art.15 operationalized: an
    unjustified gap between cohorts for the same item under identical
    conditions is ``retail.price_discrimination`` (大数据杀熟). A
    bound justification does not prove the gap is fair — it records
    the platform's stated basis for review and 12315-style complaint.
    """
    _check_ts(now, "now")
    receipt = justifications.get(receipt_id)
    if receipt is None:
        return _deny(
            "retail:price_discrimination",
            f"price gap for {item_id!r} has no justification receipt",
        )
    if receipt.item_id != item_id:
        return _deny(
            "retail:shasha_item_mismatch",
            f"justification receipt {receipt_id!r} covers a different item",
        )
    known = {
        receipt.cohort_a: receipt.price_a_minor,
        receipt.cohort_b: receipt.price_b_minor,
    }
    if cohort not in known:
        return _deny(
            "retail:shasha_cohort_unknown",
            f"cohort {cohort!r} not covered by justification {receipt_id!r}",
        )
    if known[cohort] != price_minor:
        return _deny(
            "retail:shasha_price_mismatch",
            f"charged price differs from the receipted cohort price",
        )
    if receipt.published_at > now:
        return _deny(
            "retail:future_shasha",
            f"justification receipt {receipt_id!r} published in the future",
        )
    return _allow(
        f"price gap for {item_id!r} bound to justification "
        f"({receipt.justification[:48]!r}...)",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 10. Merchant rule disclosure (Beijing 2026-09 investigation lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MerchantRuleReceipt:
    """Binds the platform rules disclosed to merchants."""

    receipt_id: str
    platform_id: str
    rules_version: str
    ranking_rules_digest: str
    traffic_allocation_digest: str
    commission_schedule_digest: str
    published_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "merchant_rule_disclosure",
            "receipt_id": self.receipt_id,
            "platform_id": self.platform_id,
            "rules_version": self.rules_version,
            "ranking_rules_digest": self.ranking_rules_digest,
            "traffic_allocation_digest": self.traffic_allocation_digest,
            "commission_schedule_digest": self.commission_schedule_digest,
            "published_at": self.published_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class MerchantRuleRegistry:
    """Hash-chained log of merchant rule disclosures."""

    authorities: AuthorityRegistry
    log: list[MerchantRuleReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        platform_id: str,
        rules_version: str,
        ranking_rules_digest: str,
        traffic_allocation_digest: str,
        commission_schedule_digest: str,
        published_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> MerchantRuleReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(platform_id, "platform_id")
        _check_nonempty_str(rules_version, "rules_version")
        _check_hex64(ranking_rules_digest, "ranking_rules_digest")
        _check_hex64(traffic_allocation_digest, "traffic_allocation_digest")
        _check_hex64(commission_schedule_digest, "commission_schedule_digest")
        _check_ts(published_at, "published_at")
        pubkey = _authority_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        payload = {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "merchant_rule_disclosure",
            "receipt_id": receipt_id,
            "platform_id": platform_id,
            "rules_version": rules_version,
            "ranking_rules_digest": ranking_rules_digest,
            "traffic_allocation_digest": traffic_allocation_digest,
            "commission_schedule_digest": commission_schedule_digest,
            "published_at": published_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        signature_hex, digest = _sign_receipt(payload, authority_secret)
        receipt = MerchantRuleReceipt(
            receipt_id=receipt_id,
            platform_id=platform_id,
            rules_version=rules_version,
            ranking_rules_digest=ranking_rules_digest,
            traffic_allocation_digest=traffic_allocation_digest,
            commission_schedule_digest=commission_schedule_digest,
            published_at=published_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=digest,
        )
        self.log.append(receipt)
        _check_chain(self.log, "merchant_rule_disclosure")
        return receipt

    def get(self, receipt_id: str) -> MerchantRuleReceipt | None:
        for entry in self.log:
            if entry.receipt_id == receipt_id:
                return entry
        return None


def merchant_rule_disclosure(
    rules: MerchantRuleRegistry,
    receipt_id: str,
    platform_id: str,
    now: int,
) -> RetailVerdict:
    """Ranking/traffic/commission rules must be disclosed to merchants.

    No live disclosure receipt for the platform's current rules is
    ``retail.merchant_opaque`` — the Beijing 2026-09 investigation
    and the China Hotel Association demand operationalized.
    """
    _check_ts(now, "now")
    receipt = rules.get(receipt_id)
    if receipt is None:
        return _deny(
            "retail:merchant_opaque",
            f"platform {platform_id!r} has no merchant rule disclosure receipt",
        )
    if receipt.platform_id != platform_id:
        return _deny(
            "retail:merchant_rule_mismatch",
            f"rule receipt {receipt_id!r} covers a different platform",
        )
    if receipt.published_at > now:
        return _deny(
            "retail:future_merchant_rules",
            f"rule receipt {receipt_id!r} published in the future",
        )
    if now - receipt.published_at > RULE_MAX_AGE_S:
        return _deny(
            "retail:stale_merchant_rules",
            f"rule receipt {receipt_id!r} is older than 365 days",
        )
    return _allow(
        f"platform {platform_id!r} disclosed rules {receipt.rules_version!r} to "
        "merchants (ranking/traffic/commission digests bound)",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 11. Quota transparency (ADAPT/TOT lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QuotaDisclosure:
    """Binds an algorithmic warehouse quota + the human-review guarantee."""

    disclosure_id: str
    site_id: str
    quota_units_per_hour: float
    measured_window_s: int
    auto_termination: bool
    human_review_before_termination: bool
    disclosed_at: int
    authority_id: str

    def _payload(self) -> dict[str, Any]:  # pragma: no cover - unsigned audit
        return {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "quota_disclosure",
            "disclosure_id": self.disclosure_id,
            "site_id": self.site_id,
            "quota_units_per_hour": self.quota_units_per_hour,
            "measured_window_s": self.measured_window_s,
            "auto_termination": self.auto_termination,
            "human_review_before_termination": self.human_review_before_termination,
            "disclosed_at": self.disclosed_at,
            "authority_id": self.authority_id,
        }


def quota_transparency(disclosure: QuotaDisclosure) -> RetailVerdict:
    """Algorithmic quotas are disclosed; auto-termination needs human review.

    Undisclosed quota regimes are ``retail.opaque_quota``; an
    auto-termination pipeline without a bound human review is
    ``retail.auto_termination`` (the Amazon class-action lesson).
    Pregnant-worker-style disparate-impact claims need the quota and
    the window published before they can even be brought.
    """
    _check_nonempty_str(disclosure.disclosure_id, "disclosure_id")
    if disclosure.quota_units_per_hour <= 0:
        return _deny(
            "retail:opaque_quota",
            f"quota at site {disclosure.site_id!r} is not a positive published rate",
        )
    if disclosure.auto_termination and not disclosure.human_review_before_termination:
        return _deny(
            "retail:auto_termination",
            f"site {disclosure.site_id!r} auto-terminates workers below the "
            "algorithmic quota without human review",
        )
    return _allow(
        f"site {disclosure.site_id!r} quota disclosed at "
        f"{disclosure.quota_units_per_hour}/h over "
        f"{disclosure.measured_window_s}s windows"
        + ("" if disclosure.auto_termination else "; no auto-termination"),
        jcs_sha256_hex(disclosure._payload()),
    )


# ---------------------------------------------------------------------------
# 12. Wearable surveillance budget (delivery-glasses / Driver.i lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WearableCollectionReceipt:
    """Binds purpose/scope/retention for delivery-wearable collection."""

    receipt_id: str
    operator_id: str
    device_kind: str  # "smart_glasses" | "in_cab_camera" | "scanner" | "phone_app"
    purposes: tuple[str, ...]
    retention_days: int
    collected_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "wearable_collection",
            "receipt_id": self.receipt_id,
            "operator_id": self.operator_id,
            "device_kind": self.device_kind,
            "purposes": list(self.purposes),
            "retention_days": self.retention_days,
            "collected_at": self.collected_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


#: Purposes considered in-scope for delivery-wearable collection.
WEARABLE_IN_SCOPE_PURPOSES = frozenset({
    "proof_of_delivery",
    "navigation",
    "safety_incident_review",
    "package_tracking",
})


@dataclass
class WearableCollectionRegistry:
    """Hash-chained log of wearable collection receipts."""

    authorities: AuthorityRegistry
    log: list[WearableCollectionReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        operator_id: str,
        device_kind: str,
        purposes: tuple[str, ...],
        retention_days: int,
        collected_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> WearableCollectionReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(operator_id, "operator_id")
        if device_kind not in (
            "smart_glasses", "in_cab_camera", "scanner", "phone_app"
        ):
            raise RetailError("device_kind must be a known delivery-device kind")
        if not purposes:
            raise RetailError("purposes must be non-empty")
        if not isinstance(retention_days, int) or retention_days <= 0:
            raise RetailError("retention_days must be a positive int")
        _check_ts(collected_at, "collected_at")
        pubkey = _authority_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        payload = {
            "schema": RETAIL_SCHEMA_VERSION,
            "type": "wearable_collection",
            "receipt_id": receipt_id,
            "operator_id": operator_id,
            "device_kind": device_kind,
            "purposes": list(purposes),
            "retention_days": retention_days,
            "collected_at": collected_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        signature_hex, digest = _sign_receipt(payload, authority_secret)
        receipt = WearableCollectionReceipt(
            receipt_id=receipt_id,
            operator_id=operator_id,
            device_kind=device_kind,
            purposes=tuple(purposes),
            retention_days=retention_days,
            collected_at=collected_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=digest,
        )
        self.log.append(receipt)
        _check_chain(self.log, "wearable_collection")
        return receipt

    def get(self, receipt_id: str) -> WearableCollectionReceipt | None:
        for entry in self.log:
            if entry.receipt_id == receipt_id:
                return entry
        return None


def wearable_surveillance_budget(
    collections: WearableCollectionRegistry,
    receipt_id: str,
    purposes_used: tuple[str, ...],
    now: int,
) -> RetailVerdict:
    """Delivery-wearable collection binds purpose/scope/retention.

    Collection without a budget receipt is
    ``retail.wearable_undeclared``; collection used for purposes
    outside the declared ones (e.g. productivity scoring from
    always-on cameras) is ``retail.wearable_overreach`` — the CNIL
    €32M and smart-glasses lessons.
    """
    _check_ts(now, "now")
    receipt = collections.get(receipt_id)
    if receipt is None:
        return _deny(
            "retail:wearable_undeclared",
            "delivery-wearable collection has no purpose/scope/retention receipt",
        )
    out_of_scope = sorted(set(purposes_used) - WEARABLE_IN_SCOPE_PURPOSES)
    if out_of_scope:
        return _deny(
            "retail:wearable_overreach",
            f"wearable collection {receipt_id!r} used for out-of-scope purposes: "
            f"{', '.join(out_of_scope)}",
        )
    declared = set(receipt.purposes)
    undeclared_use = sorted(set(purposes_used) - declared)
    if undeclared_use:
        return _deny(
            "retail:wearable_overreach",
            f"collection used for purposes not in receipt {receipt_id!r}: "
            f"{', '.join(undeclared_use)}",
        )
    return _allow(
        f"wearable collection {receipt_id!r} ({receipt.device_kind}) within "
        f"declared purposes, retained {receipt.retention_days} days",
        receipt.receipt_digest,
    )
