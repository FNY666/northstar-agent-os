"""Vendor-chain provenance receipts (one-hundred-third batch).

Absorbs the 2026 AI-logistics research thread (mechanism ideas only,
honestly scoped):

* **Autonomous control towers at scale.** Libera's control tower tracks
  100B+ data points across 400k vendors and 5M shipments/day; Walmart
  runs an autonomous replenishment agent US-wide *without per-decision
  sign-off*; General Mills attributes $20M+ in logistics savings to a
  single AI agent. The governance gap this opens: an agent's
  physical-world actions depend on a deep vendor chain, and a
  compromised or unvetted vendor anywhere in that chain poisons every
  decision downstream of it.
* **Unvetted vendors are the supply-chain analogue of pirated
  acquisition.** The one-hundredth batch (model lineage) established
  that unshowable acquisition fail-closes and that taint propagates
  transitively with no laundering. Vendor chains get the same
  discipline: a vendor that cannot be resolved to the pre-approved
  registry is an unknown vendor, and an unknown vendor denies — the
  chain is only as trustworthy as its least-vetted link.

Northstar mapping:

* ``VendorReceipt`` — a hash-chained receipt binding
  ``(action_id, vendor_id, vendor_attestation_digest, prev_hash)``.
  Each hop of a shipment or replenishment action names the vendor that
  handled it and pins that vendor's attestation digest; ``prev_hash``
  chains hops so silent reordering, dropping, or splicing of chain
  links is detectable.
* ``verify_chain()`` — fail-closed: every link's digest recomputes,
  every vendor resolves to the pre-approved registry, every
  attestation digest matches the registry pin, every ``prev_hash``
  matches the previous link. A tainted vendor (failed audit, revoked
  attestation) taints the whole chain transitively — there is no
  laundering step that washes a tainted hop (the Sony/UMG lesson,
  applied to vendors).
* ``authorize_autonomous_action()`` — the Walmart pattern, made
  governable: an autonomous replenishment/shipment action is allowed
  *without per-decision human sign-off* only when (a) its full vendor
  chain verifies and is untainted, AND (b) the action sits inside a
  pre-approved envelope (max value, max quantity, allowed SKUs).
  Anything outside the envelope needs a human. Every autonomous
  action — allowed or denied — emits an audit receipt.

Honest boundary: the vendor registry is curated out-of-band (the
repo cannot audit real vendors). This module verifies *claimed*
chain consistency — digests recompute, links resolve, taint
propagates, attestation pins match. It cannot detect a *false vendor
claim* (a receipt naming clean vendor X for goods actually handled
by tainted vendor Y); catching that needs physical-world attestation
infrastructure, which is outside this module's scope. What it does
guarantee: *if* a claimed vendor is tainted or unknown, the action
denies — there is no path from an unvetted chain to autonomous
execution.

Deterministic: no wall-clock reads (callers inject ``created_unix``
as an integer), canonical JCS hashing, and all digest comparisons use
:func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

from canonical_json import jcs_sha256_hex

VENDOR_CHAIN_SCHEMA_VERSION = "northstar.vendor-chain.v1"

#: Denial reason codes. All start with the ``vendor:`` prefix so audit
#: consumers can filter the family.
DENY_UNKNOWN_VENDOR = "vendor:unknown_vendor"
DENY_ATTESTATION_MISMATCH = "vendor:attestation_mismatch"
DENY_RECEIPT_DIGEST_MISMATCH = "vendor:receipt_digest_mismatch"
DENY_CHAIN_GAP = "vendor:chain_gap"
DENY_TAINTED_CHAIN = "vendor:tainted_chain"
DENY_OUTSIDE_ENVELOPE = "vendor:outside_envelope"
DENY_MALFORMED = "vendor:malformed"
DENY_EMPTY_CHAIN = "vendor:empty_chain"

#: Audit event name for autonomous vendor-chain actions (allowed and
#: denied both emit, for audit.ndjson/1).
VENDOR_ACTION_EVENT = "vendor.autonomous_action"

_HEX64_LENGTH = 64


class VendorChainError(ValueError):
    """A malformed vendor receipt, registry, or envelope — a programming
    error, not a verdict. Verification *failures* (unknown vendor, gap,
    taint, envelope breach) return a verdict with ``allowed=False``
    instead; a malformed input raises here, fail loud, never guess."""


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _HEX64_LENGTH
        and all(c in "0123456789abcdef" for c in value)
    )


def _require_hex64(value: Any, what: str) -> str:
    if not _is_hex64(value):
        raise VendorChainError(f"{what} must be a 64-char lowercase hex digest")
    return value


def _require_nonempty(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise VendorChainError(f"{what} must be a non-empty string")
    return value


# ---------------------------------------------------------------------------
# VendorReceipt: one hash-chained hop in a vendor chain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VendorReceipt:
    """One vendor hop, hash-chained to its predecessor.

    ``action_id`` names the shipment or replenishment action the hop
    belongs to (all hops of one action share it). ``vendor_id`` names
    the vendor that handled this hop. ``vendor_attestation_digest`` is
    the SHA-256 (hex) of that vendor's attestation for this hop — the
    digest the registry pin is checked against. ``prev_hash`` chains to
    the previous hop's :meth:`receipt_hash` (empty string for genesis).
    """

    receipt_id: str
    action_id: str
    vendor_id: str
    vendor_attestation_digest: str
    prev_hash: str = ""
    created_unix: int = 0
    schema_version: str = VENDOR_CHAIN_SCHEMA_VERSION

    def receipt_hash(self) -> str:
        """Digest binding every field that authorizes the hop."""
        return jcs_sha256_hex(
            {
                "schema_version": self.schema_version,
                "receipt_id": self.receipt_id,
                "action_id": self.action_id,
                "vendor_id": self.vendor_id,
                "vendor_attestation_digest": self.vendor_attestation_digest,
                "prev_hash": self.prev_hash,
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "vendor-chain-receipt",
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "vendor_id": self.vendor_id,
            "vendor_attestation_digest": self.vendor_attestation_digest,
            "prev_hash": self.prev_hash,
            "created_unix": self.created_unix,
            "receipt_hash": self.receipt_hash(),
        }


def build_vendor_receipt(
    *,
    receipt_id: str,
    action_id: str,
    vendor_id: str,
    vendor_attestation_digest: str,
    prev_hash: str = "",
    created_unix: int = 0,
) -> VendorReceipt:
    """Construct a vendor receipt from runtime ground truth.

    Construction is the validation boundary: malformed input raises
    :class:`VendorChainError`; downstream code only checks digests.
    """
    _require_nonempty(receipt_id, "receipt_id")
    _require_nonempty(action_id, "action_id")
    _require_nonempty(vendor_id, "vendor_id")
    _require_hex64(vendor_attestation_digest, "vendor_attestation_digest")
    if prev_hash and not _is_hex64(prev_hash):
        raise VendorChainError("prev_hash must be empty or a 64-char hex digest")
    if not isinstance(created_unix, int) or created_unix < 0:
        raise VendorChainError("created_unix must be a non-negative int")
    return VendorReceipt(
        receipt_id=receipt_id,
        action_id=action_id,
        vendor_id=vendor_id,
        vendor_attestation_digest=vendor_attestation_digest,
        prev_hash=prev_hash,
        created_unix=created_unix,
    )


# ---------------------------------------------------------------------------
# VendorRegistry: the pre-approved vendor set (curated out-of-band)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VendorRegistry:
    """The pre-approved vendor set.

    ``attestation_pins`` maps ``vendor_id`` to the expected
    ``vendor_attestation_digest`` (hex) — the digest a vendor's hop
    attestation must match. ``tainted_vendors`` is the set of
    vendor_ids whose attestation was revoked or which failed audit;
    taint propagates to every chain containing them. The registry is
    *curated out-of-band*: this module consumes it, never builds it.
    """

    attestation_pins: Mapping[str, str] = field(default_factory=dict)
    tainted_vendors: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        for vendor_id, pin in self.attestation_pins.items():
            _require_nonempty(vendor_id, "registry vendor_id")
            _require_hex64(pin, f"registry pin for {vendor_id!r}")
        for vendor_id in self.tainted_vendors:
            _require_nonempty(vendor_id, "tainted vendor_id")

    def is_approved(self, vendor_id: str) -> bool:
        return vendor_id in self.attestation_pins

    def is_tainted(self, vendor_id: str) -> bool:
        return vendor_id in self.tainted_vendors


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChainVerdict:
    """The verdict of :func:`verify_chain`."""

    allowed: bool
    tainted: bool
    reason: str
    chain_digest: str = ""


def _tamper_check(receipt: VendorReceipt, claimed_hash: str) -> bool:
    """Constant-time comparison of a receipt against its claimed hash."""
    return hmac.compare_digest(receipt.receipt_hash(), claimed_hash)


def verify_chain(
    receipts: list[VendorReceipt],
    registry: VendorRegistry,
    receipt_hashes: list[str] | None = None,
) -> ChainVerdict:
    """Verify a full vendor chain, fail-closed.

    ``receipts`` is ordered genesis-first. ``receipt_hashes`` (optional)
    carries the claimed ``receipt_hash()`` of each link — when supplied,
    a link whose recomputed digest differs from the claim is a tampered
    link; when omitted, the claim is taken as the receipt's own current
    digest (i.e. only registry/linkage checks run).

    Checks, in order: non-empty chain; every vendor resolves to the
    registry (unknown vendor denies); every attestation digest matches
    the registry pin; every link's digest matches its claim; every
    ``prev_hash`` matches the previous link's digest (genesis expects
    ``""``). Then taint: any tainted vendor in the chain taints the
    whole chain — transitively, with no washing.
    """
    if not receipts:
        return ChainVerdict(False, False, DENY_EMPTY_CHAIN)
    if receipt_hashes is not None and len(receipt_hashes) != len(receipts):
        raise VendorChainError("receipt_hashes length must match receipts")

    chain_digest_inputs: list[str] = []
    previous_hash = ""
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, VendorReceipt):
            raise VendorChainError(f"link {index} is not a VendorReceipt")
        # 1. registry membership — unknown vendors deny, never pass through.
        if not registry.is_approved(receipt.vendor_id):
            return ChainVerdict(False, False, DENY_UNKNOWN_VENDOR)
        # 2. attestation pin match.
        expected_pin = registry.attestation_pins[receipt.vendor_id]
        if not hmac.compare_digest(receipt.vendor_attestation_digest, expected_pin):
            return ChainVerdict(False, False, DENY_ATTESTATION_MISMATCH)
        # 3. link digest integrity against the claimed hash.
        claimed = receipt_hashes[index] if receipt_hashes is not None else receipt.receipt_hash()
        if not _is_hex64(claimed):
            return ChainVerdict(False, False, DENY_MALFORMED)
        if not _tamper_check(receipt, claimed):
            return ChainVerdict(False, False, DENY_RECEIPT_DIGEST_MISMATCH)
        # 4. chain linkage — no gaps, no reordering, no splicing.
        if not hmac.compare_digest(receipt.prev_hash, previous_hash):
            return ChainVerdict(False, False, DENY_CHAIN_GAP)
        digest = receipt.receipt_hash()
        chain_digest_inputs.append(digest)
        previous_hash = digest

    chain_digest = jcs_sha256_hex({"hops": chain_digest_inputs})

    # 5. transitive taint — a tainted vendor anywhere poisons the chain.
    for receipt in receipts:
        if registry.is_tainted(receipt.vendor_id):
            return ChainVerdict(False, True, DENY_TAINTED_CHAIN, chain_digest)

    return ChainVerdict(True, False, "chain_verified", chain_digest)


# ---------------------------------------------------------------------------
# Autonomous-action envelope + authorization gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionEnvelope:
    """The pre-approved envelope for autonomous actions.

    Inside the envelope, the agent may act without per-decision human
    sign-off (the Walmart pattern); outside it, a human must approve.
    ``max_value_cents`` and ``max_quantity`` are inclusive ceilings;
    ``allowed_skus`` is the closed SKU vocabulary.
    """

    max_value_cents: int
    max_quantity: int
    allowed_skus: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.max_value_cents, int) or self.max_value_cents < 0:
            raise VendorChainError("max_value_cents must be a non-negative int")
        if not isinstance(self.max_quantity, int) or self.max_quantity < 0:
            raise VendorChainError("max_quantity must be a non-negative int")
        for sku in self.allowed_skus:
            _require_nonempty(sku, "allowed sku")

    def contains(self, sku: str, quantity: int, value_cents: int) -> bool:
        if sku not in self.allowed_skus:
            return False
        if not isinstance(quantity, int) or quantity <= 0 or quantity > self.max_quantity:
            return False
        if not isinstance(value_cents, int) or value_cents < 0 or value_cents > self.max_value_cents:
            return False
        return True


@dataclass(frozen=True)
class AutonomousAction:
    """One autonomous replenishment/shipment action the agent proposes."""

    action_id: str
    sku: str
    quantity: int
    value_cents: int
    agent_id: str

    def action_digest(self) -> str:
        return jcs_sha256_hex(
            {
                "action_id": self.action_id,
                "sku": self.sku,
                "quantity": self.quantity,
                "value_cents": self.value_cents,
                "agent_id": self.agent_id,
            }
        )


def build_autonomous_action(
    *,
    action_id: str,
    sku: str,
    quantity: int,
    value_cents: int,
    agent_id: str,
) -> AutonomousAction:
    _require_nonempty(action_id, "action_id")
    _require_nonempty(sku, "sku")
    _require_nonempty(agent_id, "agent_id")
    if not isinstance(quantity, int) or quantity <= 0:
        raise VendorChainError("quantity must be a positive int")
    if not isinstance(value_cents, int) or value_cents < 0:
        raise VendorChainError("value_cents must be a non-negative int")
    return AutonomousAction(
        action_id=action_id,
        sku=sku,
        quantity=quantity,
        value_cents=value_cents,
        agent_id=agent_id,
    )


@dataclass(frozen=True)
class ActionVerdict:
    """The verdict of :func:`authorize_autonomous_action`."""

    allowed: bool
    reason: str
    action_digest: str
    audit_event: dict[str, Any]


def vendor_action_event(
    *,
    action: AutonomousAction,
    allowed: bool,
    reason: str,
    chain_digest: str,
    created_unix: int = 0,
) -> dict[str, Any]:
    """Audit event for an autonomous vendor-chain action (allowed or denied).

    The dict is shaped to feed ``audit_chain.chain_record`` directly.
    """
    return {
        "event": VENDOR_ACTION_EVENT,
        "action_id": action.action_id,
        "action_digest": action.action_digest(),
        "agent_id": action.agent_id,
        "allowed": allowed,
        "reason": reason,
        "chain_digest": chain_digest,
        "created_unix": created_unix,
    }


def authorize_autonomous_action(
    *,
    action: AutonomousAction,
    receipts: list[VendorReceipt],
    receipt_hashes: list[str] | None = None,
    registry: VendorRegistry,
    envelope: ActionEnvelope,
    created_unix: int = 0,
) -> ActionVerdict:
    """Gate an autonomous replenishment/shipment action, fail-closed.

    Gate order is fixed: (1) the vendor chain must verify — unknown
    vendors, attestation mismatches, tampered links, and chain gaps all
    deny; (2) the chain must be untainted — a tainted vendor anywhere
    denies the action, with no washing; (3) the action must sit inside
    the pre-approved envelope — outside it, a human must approve, so
    the autonomous path denies with ``vendor:outside_envelope``.

    Never raises on verification outcomes — denials are values. Raises
    :class:`VendorChainError` only on malformed *inputs* (programmer
    errors). Every call returns an audit event; denials audit as
    ``vendor.autonomous_action`` with ``allowed: false``.
    """
    if not isinstance(action, AutonomousAction):
        raise VendorChainError("action must be an AutonomousAction")
    if not isinstance(registry, VendorRegistry):
        raise VendorChainError("registry must be a VendorRegistry")
    if not isinstance(envelope, ActionEnvelope):
        raise VendorChainError("envelope must be an ActionEnvelope")

    chain = verify_chain(receipts, registry, receipt_hashes)
    if not chain.allowed:
        return ActionVerdict(
            allowed=False,
            reason=chain.reason,
            action_digest=action.action_digest(),
            audit_event=vendor_action_event(
                action=action,
                allowed=False,
                reason=chain.reason,
                chain_digest=chain.chain_digest,
                created_unix=created_unix,
            ),
        )

    if not envelope.contains(action.sku, action.quantity, action.value_cents):
        return ActionVerdict(
            allowed=False,
            reason=DENY_OUTSIDE_ENVELOPE,
            action_digest=action.action_digest(),
            audit_event=vendor_action_event(
                action=action,
                allowed=False,
                reason=DENY_OUTSIDE_ENVELOPE,
                chain_digest=chain.chain_digest,
                created_unix=created_unix,
            ),
        )

    return ActionVerdict(
        allowed=True,
        reason="autonomous_action_authorized",
        action_digest=action.action_digest(),
        audit_event=vendor_action_event(
            action=action,
            allowed=True,
            reason="autonomous_action_authorized",
            chain_digest=chain.chain_digest,
            created_unix=created_unix,
        ),
    )
