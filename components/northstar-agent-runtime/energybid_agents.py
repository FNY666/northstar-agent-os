"""Energy trading discipline (one-hundred-forty-fifth batch).

Absorbs the 2026 AI-energy-trading research thread (mechanism ideas
only, honestly scoped):

* **AI bidders are market participants, not spectators.** LehmanSoft
  Japan (2026-06-10) put a 2MW/8MWh Saitama battery into Japan's
  balancing market with AI trained on 16 months of real market data,
  spanning JEPX day-ahead/intraday/balancing/capacity markets; Flower
  (Stockholm) runs AI-optimized VPP trading of wind/solar/storage
  portfolios; 达卯科技 "算电协同2.0" (2026-09, Shenzhen) does
  multi-agent joint bidding across energy/regulation/capacity/carbon
  markets; Sigenergy SigenAgent (Stuttgart, 11.6MWp) stops feed-in
  automatically on negative prices; enercity x Kraken VPP (2026-05,
  Germany); Greenflash Greencore AI (2026-09) stacks self-use +
  trading + peak-shaving on one battery; Korea's VPP leaders settle
  forecast error at 4 KRW/kWh with a 20MW aggregation threshold;
  Dexter Energy optimizes bids across day-ahead/intraday/balancing.
* **Statistical bids are not evidence.** FERC v. American Efficient
  ($1.1B capacity-fraud milestone): bids built on statistical
  estimates with no verification and no contract chain are market
  manipulation — no price effect required. An AI aggregator's quote
  must pin a physical resource registration and a contract chain,
  or it is manipulation-shaped.
* **Tacit collusion needs no conspiracy.** Mondaq legal analysis
  (2026-09): AI trading strategies can trigger FERC market-
  manipulation liability, and unintentional algorithmic coordination
  among generators running similar models may be charged as tacit
  collusion. FERC's analytics and surveillance arm monitors
  algorithmic behavior. Declared model-similarity above a threshold
  therefore triggers position caps here — a tripwire, not an
  accusation.
* **The same MW cannot clear twice.** No verification mechanism
  exists today for a megawatt double-sold across day-ahead,
  intraday, balancing, and capacity markets. This module keeps a
  single merged position view per participant and refuses
  over-commitment (``energybid:double_sold``).
* **Negative prices are a strategy, not an accident.** Negative-
  price gaming must be declared in advance; an undeclared
  negative-price bid is ``energybid:undeclared_negative_price``.
* **Enforcement is watching.** CFTC 2026 lists energy-market
  manipulation among its five enforcement priorities; ACER
  Decisions 12/2026 & 13/2026 (2026-09) revised the PICASSO/MARI
  implementation frameworks and simplified prequalification for
  small participants; Italy's TIDE is technology-neutral (<10MW
  may aggregate ancillary services). Trading algorithms bind a
  registration receipt with a named responsible person, and every
  executed trade binds a post-trade explainability receipt —
  quote-level audit standards are missing in the wild, so the
  module pins them here.
* **The kill switch must be tested.** An extreme-event one-touch
  pause bound to authority is only as good as its last test: an
  untested switch is a ``energybid:dead_switch``.

Northstar mapping:

* ``BidEvidenceLog`` / ``bid_evidence_binding()`` — quotes bind
  ``(quote_id, model_version, input_data_digest, rule_version)``;
  an unbound quote is ``NON_AUTHORITATIVE``
  (``energybid:unbound_quote``).
* ``ResourcePinLog`` / ``resource_registry_pin()`` — quotes pin a
  physical-resource registration with a contract-chain digest
  (the American Efficient lesson); capacity with no covering
  registration is ``energybid:no_contract_chain``.
* ``CorrelationLog`` / ``correlation_circuit_breaker()`` —
  declared pairwise model-similarity (basis points) between
  participants; when a participant's max live similarity crosses
  the threshold, its position is capped — over the cap is
  ``energybid:correlation_position_cap`` (tripwire, never an
  accusation).
* ``PositionRegistry`` / ``cross_market_position_limit()`` — a
  single merged position view across all markets; committed MW
  exceeding registered capacity is
  ``energybid:double_sold``.
* ``NegativePriceLog`` / ``negative_price_declaration()`` —
  advance declarations of negative-price strategies; an
  undeclared negative-price bid is
  ``energybid:undeclared_negative_price``.
* ``AlgorithmRegistry`` / ``algorithm_registry_receipt()`` —
  trading algorithms bind registration plus a named responsible
  person; unregistered/expired/revoked is
  ``energybid:unregistered_algorithm``.
* ``TradeLog`` / ``post_trade_explainability()`` — executed trades
  bind an explainability receipt (explainer model version +
  narrative digest); a trade with no bound receipt is
  ``NON_AUTHORITATIVE`` (``energybid:no_explainability``).
* ``KillSwitchLog`` / ``human_kill_switch()`` — extreme-event
  pause receipts bound to authority with a pinned test interval;
  a missing or stale switch is ``energybid:dead_switch``.

Honest boundary: receipts bind *declared trading discipline* —
quote evidence, resource pins, declared model similarity, merged
positions, strategy declarations, algorithm registrations,
explainability receipts, and kill-switch tests are claims the
participant declares and the runtime checks. The module cannot
observe real market behavior: it cannot prove tacit collusion
(the correlation input is declared similarity, so the breaker is a
precautionary cap, not a finding), cannot verify that a pinned
resource is physically real, and cannot prevent a market shock.
What it guarantees: no unverifiable quote clears as authoritative,
no contract-less capacity trades, no undeclared negative-price
gaming, no anonymous trading algorithm, no unexplained executed
trade, no untested kill switch, and no MW sold twice.

Deterministic: no wall-clock reads (callers inject integer
epochs), canonical JCS hashing, constant-time digest comparisons.
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

    def jcs_sha256_hex(obj: Any) -> bytes:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()

import ed25519


ENERGYBID_SCHEMA_VERSION = "northstar.energybid-agents.v1"

#: Policy classification tiers (mirrors the 87th batch's evidence tiers).
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Closed vocabulary of energy markets (JEPX / EU / US day-ahead,
#: intraday, balancing, capacity, carbon).
MARKETS: tuple[str, ...] = (
    "day_ahead",
    "intraday",
    "balancing",
    "capacity",
    "carbon",
)

#: Closed vocabulary of trade sides.
TRADE_SIDES: tuple[str, ...] = ("buy", "sell")

#: Genesis marker for hash chains.
_GENESIS = "genesis"
_HEX64_LENGTH = 64

#: Denial reason codes. All verdict reasons start with one of these.
DENY_UNBOUND_QUOTE = "energybid.unbound_quote"
DENY_NO_CONTRACT_CHAIN = "energybid.no_contract_chain"
DENY_CORRELATION_POSITION_CAP = "energybid.correlation_position_cap"
DENY_DOUBLE_SOLD = "energybid.double_sold"
DENY_UNDECLARED_NEGATIVE_PRICE = "energybid.undeclared_negative_price"
DENY_UNREGISTERED_ALGORITHM = "energybid.unregistered_algorithm"
DENY_NO_EXPLAINABILITY = "energybid.no_explainability"
DENY_DEAD_SWITCH = "energybid.dead_switch"


class EnergyBidError(DomainError):
    """A malformed energy-trading receipt or a programming error.

    Raised for structural problems (bad digests, unknown codes,
    broken chains). Verification *failures* (unbound quotes,
    missing contract chains, double-sold capacity) return an
    :class:`EnergyBidVerdict` with ``allowed=False`` instead — a
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
        raise EnergyBidError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_pubkey_hex(value: Any, field_name: str) -> str:
    # Ed25519 public keys are 32 bytes -> 64 hex chars.
    return _check_hex64(value, field_name)


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EnergyBidError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EnergyBidError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed.
    if not isinstance(value, bytes) or len(value) != 32:
        raise EnergyBidError(f"{field_name} must be a 32-byte seed")
    return value


def _check_bps(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 10000:
        raise EnergyBidError(f"{field_name} must be basis points 0..10000")
    return value


def _check_market(value: Any, field_name: str = "market") -> str:
    if value not in MARKETS:
        raise EnergyBidError(f"{field_name} must be one of {MARKETS}")
    return value


def _check_positive_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise EnergyBidError(f"{field_name} must be a positive int")
    return value


def _check_nonneg_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EnergyBidError(f"{field_name} must be a non-negative int")
    return value


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
    """Raise :class:`EnergyBidError` if a receipt log is tampered/broken."""
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise EnergyBidError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise EnergyBidError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.authority_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise EnergyBidError(
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
class EnergyBidVerdict:
    """Outcome of one energy-trading discipline check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> EnergyBidVerdict:
    return EnergyBidVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> EnergyBidVerdict:
    return EnergyBidVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def energybid_audit_event(verdict: EnergyBidVerdict, *, action: str) -> dict[str, Any]:
    """Build the audit event for an energy-trading discipline verdict."""
    return {
        "action": _check_nonempty_str(action, "action"),
        "verdict_allowed": verdict.allowed,
        "reason": verdict.reason,
        "classification": verdict.classification,
        "receipt_digest": verdict.receipt_digest,
        "schema_version": ENERGYBID_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Quote evidence binding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BidEvidenceReceipt:
    """A quote bound to its model, input data, and rule versions.

    The FERC v. American Efficient lesson: a bid is not evidence
    unless it binds the model version that produced it, the input
    data digest it was computed from, and the rule version it was
    checked against.
    """

    receipt_id: str
    quote_id: str
    participant_id: str
    market: str
    model_version: str
    input_data_digest: str
    rule_version: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ENERGYBID_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "quote_id": self.quote_id,
            "participant_id": self.participant_id,
            "market": self.market,
            "model_version": self.model_version,
            "input_data_digest": self.input_data_digest,
            "rule_version": self.rule_version,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def bid_evidence_binding(
    *,
    receipt_id: str,
    quote_id: str,
    participant_id: str,
    market: str,
    model_version: str,
    input_data_digest: str,
    rule_version: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> BidEvidenceReceipt:
    """Issue a quote-evidence receipt binding model/input/rule versions.

    Malformed inputs raise :class:`EnergyBidError`, including an
    expiry that is not after issuance.
    """
    receipt = BidEvidenceReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        quote_id=_check_nonempty_str(quote_id, "quote_id"),
        participant_id=_check_nonempty_str(participant_id, "participant_id"),
        market=_check_market(market),
        model_version=_check_nonempty_str(model_version, "model_version"),
        input_data_digest=_check_hex64(input_data_digest, "input_data_digest"),
        rule_version=_check_nonempty_str(rule_version, "rule_version"),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="",
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise EnergyBidError("expires_at must be after issued_at")
    _check_secret(authority_secret, "authority_secret")
    return _seal(receipt, receipt._payload(), authority_secret)


class BidEvidenceLog:
    """Hash-chained log of quote-evidence receipts."""

    def __init__(self) -> None:
        self._log: list[BidEvidenceReceipt] = []

    def append(self, receipt: BidEvidenceReceipt) -> BidEvidenceReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise EnergyBidError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_quote(self, quote_id: str) -> BidEvidenceReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.quote_id, quote_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "bid-evidence")


def check_quote_evidence(
    *,
    log: BidEvidenceLog,
    quote_id: str,
    now: int,
) -> EnergyBidVerdict:
    """Check a quote against bound evidence.

    A quote with no bound receipt, or only an expired one, is
    ``NON_AUTHORITATIVE`` (``energybid.unbound_quote``) — a bid
    built on statistical estimates with no pinned model/input/rule
    is manipulation-shaped, not evidence.
    """
    now = _check_ts(now, "now")
    quote_id = _check_nonempty_str(quote_id, "quote_id")
    receipt = log.latest_for_quote(quote_id)
    if receipt is None:
        return _deny(DENY_UNBOUND_QUOTE, f"quote {quote_id!r} has no bound evidence")
    if now >= receipt.expires_at:
        return _deny(
            DENY_UNBOUND_QUOTE,
            f"quote {quote_id!r} evidence expired at {receipt.expires_at}",
        )
    return _allow(
        f"quote {quote_id!r} bound to model {receipt.model_version!r} / "
        f"rules {receipt.rule_version!r}",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Resource registry pins (contract chains)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourcePinReceipt:
    """A quote's capacity pinned to a physical-resource registration.

    ``contract_chain_digest`` binds the chain of contracts from the
    participant to the physical resource — the American Efficient
    lesson: no contract chain, no capacity trade.
    """

    receipt_id: str
    resource_id: str
    participant_id: str
    market: str
    capacity_mw: int
    contract_chain_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ENERGYBID_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "resource_id": self.resource_id,
            "participant_id": self.participant_id,
            "market": self.market,
            "capacity_mw": self.capacity_mw,
            "contract_chain_digest": self.contract_chain_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def resource_registry_pin(
    *,
    receipt_id: str,
    resource_id: str,
    participant_id: str,
    market: str,
    capacity_mw: int,
    contract_chain_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> ResourcePinReceipt:
    """Pin a resource registration with its contract chain.

    Malformed inputs raise :class:`EnergyBidError`; a zero
    capacity pin is meaningless and refused.
    """
    receipt = ResourcePinReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        resource_id=_check_nonempty_str(resource_id, "resource_id"),
        participant_id=_check_nonempty_str(participant_id, "participant_id"),
        market=_check_market(market),
        capacity_mw=_check_positive_int(capacity_mw, "capacity_mw"),
        contract_chain_digest=_check_hex64(contract_chain_digest, "contract_chain_digest"),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="",
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise EnergyBidError("expires_at must be after issued_at")
    _check_secret(authority_secret, "authority_secret")
    return _seal(receipt, receipt._payload(), authority_secret)


class ResourcePinLog:
    """Hash-chained log of resource-pin receipts."""

    def __init__(self) -> None:
        self._log: list[ResourcePinReceipt] = []

    def append(self, receipt: ResourcePinReceipt) -> ResourcePinReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise EnergyBidError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def pinned_capacity_mw(
        self, *, participant_id: str, market: str, now: int
    ) -> int:
        total = 0
        for receipt in self._log:
            if (
                hmac.compare_digest(receipt.participant_id, participant_id)
                and receipt.market == market
                and receipt.issued_at <= now < receipt.expires_at
            ):
                total += receipt.capacity_mw
        return total

    def verify(self) -> None:
        _check_chain(self._log, "resource-pin")


def check_resource_pin(
    *,
    log: ResourcePinLog,
    participant_id: str,
    market: str,
    capacity_mw: int,
    now: int,
) -> EnergyBidVerdict:
    """Check that quoted capacity is covered by pinned registrations.

    Quoted capacity exceeding the live pinned registrations for the
    (participant, market) pair is ``energybid.no_contract_chain`` —
    statistical-estimate bids with no contract chain are the
    American Efficient pattern.
    """
    now = _check_ts(now, "now")
    participant_id = _check_nonempty_str(participant_id, "participant_id")
    market = _check_market(market)
    capacity_mw = _check_positive_int(capacity_mw, "capacity_mw")
    pinned = log.pinned_capacity_mw(
        participant_id=participant_id, market=market, now=now
    )
    if pinned < capacity_mw:
        return _deny(
            DENY_NO_CONTRACT_CHAIN,
            f"{capacity_mw}MW quoted on {market} but only {pinned}MW "
            f"contract-chain pinned for {participant_id!r}",
        )
    return _allow(
        f"{capacity_mw}MW covered by {pinned}MW pinned registrations",
        "",
    )


# ---------------------------------------------------------------------------
# Algorithmic-correlation circuit breaker
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorrelationReceipt:
    """A declared pairwise model-similarity measurement.

    ``correlation_bps`` is the declared similarity (basis points)
    between the two participants' bidding models. This is a
    *declared* measurement, not a finding of collusion — crossing
    the threshold triggers a precautionary position cap, never an
    accusation (the Mondaq tacit-collusion lesson, honestly
    scoped: similarity is not conspiracy).
    """

    receipt_id: str
    participant_a: str
    participant_b: str
    correlation_bps: int
    measured_by: str
    authority_pubkey_hex: str
    signature_hex: str
    measured_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ENERGYBID_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "participant_a": self.participant_a,
            "participant_b": self.participant_b,
            "correlation_bps": self.correlation_bps,
            "measured_by": self.measured_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "measured_at": self.measured_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def correlation_circuit_breaker(
    *,
    receipt_id: str,
    participant_a: str,
    participant_b: str,
    correlation_bps: int,
    measured_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    measured_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> CorrelationReceipt:
    """Record a declared pairwise model-similarity measurement.

    Malformed inputs raise :class:`EnergyBidError`, including a
    self-comparison (a participant is trivially 100% similar to
    itself).
    """
    participant_a = _check_nonempty_str(participant_a, "participant_a")
    participant_b = _check_nonempty_str(participant_b, "participant_b")
    if hmac.compare_digest(participant_a, participant_b):
        raise EnergyBidError("participant_a and participant_b must differ")
    receipt = CorrelationReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        participant_a=participant_a,
        participant_b=participant_b,
        correlation_bps=_check_bps(correlation_bps, "correlation_bps"),
        measured_by=_check_nonempty_str(measured_by, "measured_by"),
        authority_pubkey_hex=_check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="",
        measured_at=_check_ts(measured_at, "measured_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.measured_at:
        raise EnergyBidError("expires_at must be after measured_at")
    _check_secret(authority_secret, "authority_secret")
    return _seal(receipt, receipt._payload(), authority_secret)


class CorrelationLog:
    """Hash-chained log of correlation receipts."""

    def __init__(self) -> None:
        self._log: list[CorrelationReceipt] = []

    def append(self, receipt: CorrelationReceipt) -> CorrelationReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise EnergyBidError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def max_live_correlation_bps(self, *, participant_id: str, now: int) -> int:
        best = 0
        for receipt in self._log:
            involves = hmac.compare_digest(
                receipt.participant_a, participant_id
            ) or hmac.compare_digest(receipt.participant_b, participant_id)
            if (
                involves
                and receipt.measured_at <= now < receipt.expires_at
                and receipt.correlation_bps > best
            ):
                best = receipt.correlation_bps
        return best

    def verify(self) -> None:
        _check_chain(self._log, "correlation")


def check_correlation_cap(
    *,
    log: CorrelationLog,
    participant_id: str,
    position_mw: int,
    cap_mw: int,
    threshold_bps: int,
    now: int,
) -> EnergyBidVerdict:
    """Apply the precautionary position cap for correlated models.

    When a participant's max live declared similarity crosses
    ``threshold_bps``, positions above ``cap_mw`` deny with
    ``energybid.correlation_position_cap``. Below the threshold,
    or under the cap, the position is allowed. This is a
    tripwire, not a collusion finding.
    """
    now = _check_ts(now, "now")
    participant_id = _check_nonempty_str(participant_id, "participant_id")
    position_mw = _check_nonneg_int(position_mw, "position_mw")
    cap_mw = _check_positive_int(cap_mw, "cap_mw")
    threshold_bps = _check_bps(threshold_bps, "threshold_bps")
    similarity = log.max_live_correlation_bps(participant_id=participant_id, now=now)
    if similarity >= threshold_bps and position_mw > cap_mw:
        return _deny(
            DENY_CORRELATION_POSITION_CAP,
            f"{participant_id!r} model similarity {similarity}bps >= "
            f"threshold {threshold_bps}bps; position {position_mw}MW "
            f"exceeds cap {cap_mw}MW",
        )
    return _allow(
        f"{participant_id!r} similarity {similarity}bps "
        f"(threshold {threshold_bps}bps), position {position_mw}MW within cap",
        "",
    )


# ---------------------------------------------------------------------------
# Cross-market position limits (single merged view)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PositionCommitment:
    """A participant-declared committed position in one market."""

    commitment_id: str
    participant_id: str
    market: str
    committed_mw: int
    participant_pubkey_hex: str
    signature_hex: str
    declared_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ENERGYBID_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "commitment_id": self.commitment_id,
            "participant_id": self.participant_id,
            "market": self.market,
            "committed_mw": self.committed_mw,
            "participant_pubkey_hex": self.participant_pubkey_hex,
            "prev_digest": self.prev_digest,
            "declared_at": self.declared_at,
            "schema_version": self.schema_version,
        }


def cross_market_position_limit(
    *,
    commitment_id: str,
    participant_id: str,
    market: str,
    committed_mw: int,
    participant_pubkey_hex: str,
    participant_secret: bytes,
    declared_at: int,
    prev_digest: str = _GENESIS,
) -> PositionCommitment:
    """Record a participant-declared committed position in one market.

    Commitments are signed by the *participant* (self-declared),
    not the authority — the registry's job is to merge them into
    a single view, not to bless them.
    """
    commitment = PositionCommitment(
        commitment_id=_check_nonempty_str(commitment_id, "commitment_id"),
        participant_id=_check_nonempty_str(participant_id, "participant_id"),
        market=_check_market(market),
        committed_mw=_check_positive_int(committed_mw, "committed_mw"),
        participant_pubkey_hex=_check_pubkey_hex(
            participant_pubkey_hex, "participant_pubkey_hex"
        ),
        signature_hex="",
        declared_at=_check_ts(declared_at, "declared_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    _check_secret(participant_secret, "participant_secret")
    signature_hex = ed25519.sign(
        participant_secret, jcs_canonical_json(commitment._payload())
    ).hex()
    sealed = PositionCommitment(
        **{**commitment.__dict__, "signature_hex": signature_hex}
    )
    digest = jcs_sha256_hex(sealed._payload())
    return PositionCommitment(**{**sealed.__dict__, "receipt_digest": digest})


class PositionRegistry:
    """Merged position view across all markets for each participant."""

    def __init__(self) -> None:
        self._log: list[PositionCommitment] = []

    def append(self, commitment: PositionCommitment) -> PositionCommitment:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(commitment.prev_digest, expected_prev):
            raise EnergyBidError(
                f"commitment {commitment.commitment_id!r} does not chain to the tip"
            )
        if not _verify_signature(
            commitment.participant_pubkey_hex,
            commitment._payload(),
            commitment.signature_hex,
        ):
            raise EnergyBidError(
                f"commitment {commitment.commitment_id!r} participant "
                "signature invalid"
            )
        self._log.append(commitment)
        return commitment

    def merged_position_mw(self, *, participant_id: str) -> int:
        total = 0
        for commitment in self._log:
            if hmac.compare_digest(commitment.participant_id, participant_id):
                total += commitment.committed_mw
        return total


def check_position_limit(
    *,
    registry: PositionRegistry,
    participant_id: str,
    registered_capacity_mw: int,
) -> EnergyBidVerdict:
    """Check the merged position against registered capacity.

    Committed MW across *all* markets exceeding the participant's
    registered capacity is ``energybid.double_sold`` — the same MW
    cannot clear twice.
    """
    participant_id = _check_nonempty_str(participant_id, "participant_id")
    registered_capacity_mw = _check_positive_int(
        registered_capacity_mw, "registered_capacity_mw"
    )
    total = registry.merged_position_mw(participant_id=participant_id)
    if total > registered_capacity_mw:
        return _deny(
            DENY_DOUBLE_SOLD,
            f"{participant_id!r} committed {total}MW across markets but "
            f"only {registered_capacity_mw}MW registered",
        )
    return _allow(
        f"{participant_id!r} merged position {total}MW within "
        f"{registered_capacity_mw}MW registered",
        "",
    )


# ---------------------------------------------------------------------------
# Negative-price strategy declarations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NegativePriceDeclaration:
    """An advance declaration of a negative-price bidding strategy.

    Negative prices are a legitimate strategy (SigenAgent's
    auto-stop on negative prices); gaming them without declaring
    is ``energybid.undeclared_negative_price``.
    """

    receipt_id: str
    declaration_id: str
    participant_id: str
    market: str
    strategy_id: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ENERGYBID_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "declaration_id": self.declaration_id,
            "participant_id": self.participant_id,
            "market": self.market,
            "strategy_id": self.strategy_id,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def negative_price_declaration(
    *,
    receipt_id: str,
    declaration_id: str,
    participant_id: str,
    market: str,
    strategy_id: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> NegativePriceDeclaration:
    """Declare a negative-price bidding strategy in advance.

    Malformed inputs raise :class:`EnergyBidError`.
    """
    receipt = NegativePriceDeclaration(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        declaration_id=_check_nonempty_str(declaration_id, "declaration_id"),
        participant_id=_check_nonempty_str(participant_id, "participant_id"),
        market=_check_market(market),
        strategy_id=_check_nonempty_str(strategy_id, "strategy_id"),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="",
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise EnergyBidError("expires_at must be after issued_at")
    _check_secret(authority_secret, "authority_secret")
    return _seal(receipt, receipt._payload(), authority_secret)


class NegativePriceLog:
    """Hash-chained log of negative-price declarations."""

    def __init__(self) -> None:
        self._log: list[NegativePriceDeclaration] = []

    def append(self, receipt: NegativePriceDeclaration) -> NegativePriceDeclaration:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise EnergyBidError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def live_declaration(
        self, *, participant_id: str, market: str, now: int
    ) -> NegativePriceDeclaration | None:
        for receipt in reversed(self._log):
            if (
                hmac.compare_digest(receipt.participant_id, participant_id)
                and receipt.market == market
                and receipt.issued_at <= now < receipt.expires_at
            ):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "negative-price")


def check_negative_price_bid(
    *,
    log: NegativePriceLog,
    participant_id: str,
    market: str,
    price_is_negative: bool,
    now: int,
) -> EnergyBidVerdict:
    """Check a bid against negative-price declarations.

    A negative-price bid with no live declaration for the
    (participant, market) pair is
    ``energybid.undeclared_negative_price``. Non-negative bids
    always pass this gate.
    """
    now = _check_ts(now, "now")
    participant_id = _check_nonempty_str(participant_id, "participant_id")
    market = _check_market(market)
    if not isinstance(price_is_negative, bool):
        raise EnergyBidError("price_is_negative must be a bool")
    if not price_is_negative:
        return _allow(f"bid on {market} is non-negative; declaration not required", "")
    declaration = log.live_declaration(
        participant_id=participant_id, market=market, now=now
    )
    if declaration is None:
        return _deny(
            DENY_UNDECLARED_NEGATIVE_PRICE,
            f"{participant_id!r} submitted a negative-price bid on "
            f"{market} with no live declaration",
        )
    return _allow(
        f"negative-price bid on {market} covered by declaration "
        f"{declaration.declaration_id!r} (strategy {declaration.strategy_id!r})",
        declaration.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Trading-algorithm registration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlgorithmRegistration:
    """A trading algorithm bound to a named responsible person.

    Enforcement is watching (CFTC 2026 priorities, FERC
    surveillance): the algorithm that trades must be registered,
    and a human must own it.
    """

    receipt_id: str
    registration_id: str
    algorithm_id: str
    participant_id: str
    model_version: str
    responsible_person: str
    revoked: bool
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ENERGYBID_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "registration_id": self.registration_id,
            "algorithm_id": self.algorithm_id,
            "participant_id": self.participant_id,
            "model_version": self.model_version,
            "responsible_person": self.responsible_person,
            "revoked": self.revoked,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def algorithm_registry_receipt(
    *,
    receipt_id: str,
    registration_id: str,
    algorithm_id: str,
    participant_id: str,
    model_version: str,
    responsible_person: str,
    revoked: bool = False,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> AlgorithmRegistration:
    """Register a trading algorithm with its named responsible person.

    Malformed inputs raise :class:`EnergyBidError`; an anonymous
    algorithm (empty responsible person) cannot register.
    """
    if not isinstance(revoked, bool):
        raise EnergyBidError("revoked must be a bool")
    receipt = AlgorithmRegistration(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        registration_id=_check_nonempty_str(registration_id, "registration_id"),
        algorithm_id=_check_nonempty_str(algorithm_id, "algorithm_id"),
        participant_id=_check_nonempty_str(participant_id, "participant_id"),
        model_version=_check_nonempty_str(model_version, "model_version"),
        responsible_person=_check_nonempty_str(responsible_person, "responsible_person"),
        revoked=revoked,
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="",
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise EnergyBidError("expires_at must be after issued_at")
    _check_secret(authority_secret, "authority_secret")
    return _seal(receipt, receipt._payload(), authority_secret)


class AlgorithmRegistry:
    """Hash-chained log of algorithm registrations."""

    def __init__(self) -> None:
        self._log: list[AlgorithmRegistration] = []

    def append(self, receipt: AlgorithmRegistration) -> AlgorithmRegistration:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise EnergyBidError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def live_registration(self, *, algorithm_id: str, now: int) -> AlgorithmRegistration | None:
        for receipt in reversed(self._log):
            if (
                hmac.compare_digest(receipt.algorithm_id, algorithm_id)
                and receipt.issued_at <= now < receipt.expires_at
            ):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "algorithm")


def check_algorithm(
    *,
    log: AlgorithmRegistry,
    algorithm_id: str,
    now: int,
) -> EnergyBidVerdict:
    """Check that a trading algorithm is registered and live.

    Missing, expired, or revoked registrations are
    ``energybid.unregistered_algorithm`` — no anonymous trading
    algorithms.
    """
    now = _check_ts(now, "now")
    algorithm_id = _check_nonempty_str(algorithm_id, "algorithm_id")
    registration = log.live_registration(algorithm_id=algorithm_id, now=now)
    if registration is None:
        return _deny(
            DENY_UNREGISTERED_ALGORITHM,
            f"algorithm {algorithm_id!r} has no live registration",
        )
    if registration.revoked:
        return _deny(
            DENY_UNREGISTERED_ALGORITHM,
            f"algorithm {algorithm_id!r} registration was revoked",
        )
    return _allow(
        f"algorithm {algorithm_id!r} registered; owner "
        f"{registration.responsible_person!r}",
        registration.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Post-trade explainability
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExplainabilityReceipt:
    """A post-trade explainability receipt bound to an executed trade.

    Quote-level audit standards are missing in the wild; this
    module pins them: every executed trade binds the explainer
    model version and a digest of the human-readable narrative.
    """

    receipt_id: str
    trade_id: str
    quote_digest: str
    explainer_model_version: str
    narrative_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ENERGYBID_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "trade_id": self.trade_id,
            "quote_digest": self.quote_digest,
            "explainer_model_version": self.explainer_model_version,
            "narrative_digest": self.narrative_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "schema_version": self.schema_version,
        }


def post_trade_explainability(
    *,
    receipt_id: str,
    trade_id: str,
    quote_digest: str,
    explainer_model_version: str,
    narrative_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    prev_digest: str = _GENESIS,
) -> ExplainabilityReceipt:
    """Issue a post-trade explainability receipt for an executed trade.

    Malformed inputs raise :class:`EnergyBidError`.
    """
    receipt = ExplainabilityReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        trade_id=_check_nonempty_str(trade_id, "trade_id"),
        quote_digest=_check_hex64(quote_digest, "quote_digest"),
        explainer_model_version=_check_nonempty_str(
            explainer_model_version, "explainer_model_version"
        ),
        narrative_digest=_check_hex64(narrative_digest, "narrative_digest"),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="",
        issued_at=_check_ts(issued_at, "issued_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    _check_secret(authority_secret, "authority_secret")
    return _seal(receipt, receipt._payload(), authority_secret)


class TradeLog:
    """Hash-chained log of explainability receipts."""

    def __init__(self) -> None:
        self._log: list[ExplainabilityReceipt] = []

    def append(self, receipt: ExplainabilityReceipt) -> ExplainabilityReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise EnergyBidError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def receipt_for_trade(self, trade_id: str) -> ExplainabilityReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.trade_id, trade_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "explainability")


def check_trade_explainability(
    *,
    log: TradeLog,
    trade_id: str,
) -> EnergyBidVerdict:
    """Check that an executed trade has a bound explainability receipt.

    A trade with no bound receipt is ``NON_AUTHORITATIVE``
    (``energybid.no_explainability``) — unexplained executed
    trades are unauditable.
    """
    trade_id = _check_nonempty_str(trade_id, "trade_id")
    receipt = log.receipt_for_trade(trade_id)
    if receipt is None:
        return _deny(
            DENY_NO_EXPLAINABILITY,
            f"trade {trade_id!r} has no bound explainability receipt",
        )
    return _allow(
        f"trade {trade_id!r} explained by {receipt.explainer_model_version!r}",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Human kill switch
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KillSwitchReceipt:
    """An extreme-event pause receipt bound to authority.

    ``test_interval_s`` pins how often the switch must be
    exercised; ``last_test_at`` is the most recent successful
    test. A switch that was never tested, or whose test is stale,
    is a ``energybid:dead_switch``.
    """

    receipt_id: str
    switch_id: str
    participant_id: str
    test_interval_s: int
    last_test_at: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ENERGYBID_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "switch_id": self.switch_id,
            "participant_id": self.participant_id,
            "test_interval_s": self.test_interval_s,
            "last_test_at": self.last_test_at,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "schema_version": self.schema_version,
        }


def human_kill_switch(
    *,
    receipt_id: str,
    switch_id: str,
    participant_id: str,
    test_interval_s: int,
    last_test_at: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    prev_digest: str = _GENESIS,
) -> KillSwitchReceipt:
    """Issue an authority-bound kill-switch receipt with a test pin.

    Malformed inputs raise :class:`EnergyBidError`, including a
    ``last_test_at`` that predates nothing (negative) or a test
    interval of zero — a switch that can never be tested is born
    dead.
    """
    receipt = KillSwitchReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        switch_id=_check_nonempty_str(switch_id, "switch_id"),
        participant_id=_check_nonempty_str(participant_id, "participant_id"),
        test_interval_s=_check_positive_int(test_interval_s, "test_interval_s"),
        last_test_at=_check_ts(last_test_at, "last_test_at"),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="",
        issued_at=_check_ts(issued_at, "issued_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.last_test_at > receipt.issued_at:
        raise EnergyBidError("last_test_at cannot be after issued_at")
    _check_secret(authority_secret, "authority_secret")
    return _seal(receipt, receipt._payload(), authority_secret)


class KillSwitchLog:
    """Hash-chained log of kill-switch receipts."""

    def __init__(self) -> None:
        self._log: list[KillSwitchReceipt] = []

    def append(self, receipt: KillSwitchReceipt) -> KillSwitchReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise EnergyBidError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_participant(
        self, participant_id: str
    ) -> KillSwitchReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.participant_id, participant_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "kill-switch")


def check_kill_switch(
    *,
    log: KillSwitchLog,
    participant_id: str,
    now: int,
) -> EnergyBidVerdict:
    """Check that a participant's kill switch is live and tested.

    A missing switch, or one whose last test is older than its
    pinned interval, is ``energybid.dead_switch`` — an untested
    pause button is not a control.
    """
    now = _check_ts(now, "now")
    participant_id = _check_nonempty_str(participant_id, "participant_id")
    receipt = log.latest_for_participant(participant_id)
    if receipt is None:
        return _deny(
            DENY_DEAD_SWITCH,
            f"{participant_id!r} has no kill-switch receipt",
        )
    if now - receipt.last_test_at > receipt.test_interval_s:
        return _deny(
            DENY_DEAD_SWITCH,
            f"{participant_id!r} kill switch {receipt.switch_id!r} last "
            f"tested {now - receipt.last_test_at}s ago (interval "
            f"{receipt.test_interval_s}s)",
        )
    return _allow(
        f"{participant_id!r} kill switch {receipt.switch_id!r} tested "
        f"{now - receipt.last_test_at}s ago",
        receipt.receipt_digest,
    )
