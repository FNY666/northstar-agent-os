"""Compute-budget receipts (one-hundred-ninth batch).

Absorbs the 2026 AI-chips research thread (mechanism ideas only,
honestly scoped):

* **Compute is the binding constraint.** The HBM shortage is the real
  bottleneck (China AI-chip prices +20-50% in two months on anonymous
  sourcing); 2nm wafers run $30k+; hyperscalers now finance compute
  like power plants. An agent that can spend unbounded compute is an
  agent with an unbounded blast radius.
* **"Token is an input metric, not output."** McKinsey's 2026 warning
  as Chinese banks' token consumption explodes (+78% at one bank,
  5.3B tokens/H1 at another): the industry is reframing to *ROI per
  token*. Governance needs the same reframing — every compute unit an
  agent spends must be attributable to a purpose, so cost-per-outcome
  is computable from receipts instead of argued from vibes.

Northstar mapping:

* ``ComputeBudget`` — an authority-signed receipt binding
  ``(budget_id, owner, units_total, unit_kind, hardware_tier,
  device_class, issued_by, expires_at)``. Budgets are minted by a
  registered human authority via Ed25519; there is deliberately no
  agent-key issuance path (no-self-issuance, the 94th/104th-batch
  discipline applied to compute).
* ``BudgetLedger.spend()`` — every spend decrements the budget and
  appends a hash-chained ``SpendReceipt``
  ``(budget_id, units, purpose, remaining, prev_hash)``. Overspend
  denies with ``compute:budget_exhausted`` — fail-closed, no
  borrowing, the workload stops. Spend without a purpose denies:
  unattributed compute is unauthorizable compute.
* ``check_hardware_tier()`` — spend is bound to the budget's declared
  hardware tier, and each tier names a minimum attestation evidence
  kind (``attested_receipts.strength_at_least``): claiming datacenter
  spend on unattested hardware denies. A budget's tier is a ceiling —
  spend may narrow (edge workload on a cloud budget) but never widen.
* ``device_class_constraint`` — offline/edge agents (97th batch) get
  device-class-scoped sub-budgets: cloud-scale spend against an
  edge-class budget denies. Narrowing is always allowed; widening
  never is.
* ``roi_ledger()`` — deterministic aggregation of the spend chain:
  units spent per purpose and per budget. No new metrics are
  invented; "ROI per token"-style reporting is computed *from* the
  receipts, which is the whole point of receipting the spend.

Honest boundary: this module meters *declared* units. It cannot
detect an agent that under-reports what it burned — real hardware
metering needs host cooperation (perf counters, device attestation),
which is outside this module's scope. What it does guarantee: there
is no authorized spend without a spend receipt; overspend against the
declared budget is impossible; every authorized unit names its
purpose; and a budget's tier/device-class ceiling cannot be widened
by the spender. Under-reporting is a host-visibility problem, not a
budget-integrity problem — the ledger is exactly as honest as the
spend declarations fed into it.

Deterministic: no wall-clock reads (callers inject ``created_unix``
as an integer), canonical JCS hashing, constant-time digest
comparisons.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

from canonical_json import jcs_sha256_hex
from attested_receipts import strength_at_least
from ed25519 import public_key as ed_public_key
from ed25519 import sign as ed_sign
from ed25519 import verify as ed_verify

COMPUTE_BUDGET_SCHEMA_VERSION = "northstar.compute-budget.v1"

#: Closed unit vocabulary. A budget's units are all of one kind; mixing
#: kinds inside one budget is malformed.
UNIT_KINDS: tuple[str, ...] = ("tokens", "flops", "device_seconds")

#: Hardware tiers, weakest first. A budget's tier is a *ceiling*: spend
#: may target this tier or any weaker one, never a stronger one.
HARDWARE_TIERS: tuple[str, ...] = ("edge", "datacenter", "hpc")
_TIER_RANK = {tier: rank for rank, tier in enumerate(HARDWARE_TIERS)}

#: Minimum attestation evidence kind required to *claim* spend at a
#: tier (92nd-batch ladder: zkml > opml > tee > software). Edge
#: workloads run on unattested devices all the time; datacenter/hpc
#: spend without at least TEE-grade attestation is an unverifiable
#: claim and denies.
TIER_MIN_EVIDENCE: dict[str, str] = {
    "edge": "software",
    "datacenter": "tee",
    "hpc": "tee",
}

#: Device classes, weakest first. Same ceiling rule as tiers: an
#: edge-class budget can never fund cloud-scale spend.
DEVICE_CLASSES: tuple[str, ...] = ("edge", "cloud")
_DEVICE_RANK = {cls: rank for rank, cls in enumerate(DEVICE_CLASSES)}

#: Denial reason codes. All start with the ``compute:`` prefix so
#: audit consumers can filter the family.
DENY_UNKNOWN_BUDGET = "compute:unknown_budget"
DENY_EXPIRED_BUDGET = "compute:expired_budget"
DENY_BUDGET_EXHAUSTED = "compute:budget_exhausted"
DENY_MISSING_PURPOSE = "compute:missing_purpose"
DENY_TIER_MISMATCH = "compute:tier_mismatch"
DENY_WEAK_EVIDENCE = "compute:weak_evidence"
DENY_DEVICE_CLASS = "compute:device_class_violation"
DENY_DIGEST_MISMATCH = "compute:spend_digest_mismatch"
DENY_CHAIN_GAP = "compute:chain_gap"
DENY_MALFORMED = "compute:malformed"

#: Audit event names (shaped to feed ``audit_chain.chain_record``).
COMPUTE_SPEND_EVENT = "compute.spend"
COMPUTE_EXHAUSTED_EVENT = "compute.budget_exhausted"
COMPUTE_DENIED_EVENT = "compute.use_denied"

_HEX64_LENGTH = 64
_ED25519_SIG_LENGTH = 64


class ComputeBudgetError(ValueError):
    """A malformed budget, registry, or spend request — a programming
    error, not a verdict. Verification *failures* (unknown budget,
    overspend, tier mismatch, weak evidence, device-class breach)
    return a verdict with ``allowed=False`` instead; malformed input
    raises here, fail loud, never guess."""


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _HEX64_LENGTH
        and all(c in "0123456789abcdef" for c in value)
    )


def _require_hex64(value: Any, what: str) -> str:
    if not _is_hex64(value):
        raise ComputeBudgetError(f"{what} must be a 64-char lowercase hex digest")
    return value


def _require_nonempty(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComputeBudgetError(f"{what} must be a non-empty string")
    return value


def _require_positive_int(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ComputeBudgetError(f"{what} must be a positive int")
    return value


def _require_unix(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ComputeBudgetError(f"{what} must be a non-negative int (unix time)")
    return value


# ---------------------------------------------------------------------------
# AuthorityRegistry: who may mint budgets (curated out-of-band)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorityRegistry:
    """Maps ``authority_id`` to an Ed25519 public key (32 bytes).

    Only registered *human* authorities may mint compute budgets.
    There is no agent-key path: ``owner`` is always the agent the
    budget is *for*, never the authority that signs it.
    """

    public_keys: Mapping[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for authority_id, pubkey in self.public_keys.items():
            _require_nonempty(authority_id, "authority_id")
            if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
                raise ComputeBudgetError(
                    f"public key for {authority_id!r} must be 32 bytes"
                )

    def public_key_for(self, authority_id: str) -> bytes | None:
        key = self.public_keys.get(authority_id)
        return bytes(key) if key is not None else None


# ---------------------------------------------------------------------------
# ComputeBudget: the authority-signed budget receipt
# ---------------------------------------------------------------------------


def _budget_payload(
    *,
    budget_id: str,
    owner: str,
    units_total: int,
    unit_kind: str,
    hardware_tier: str,
    device_class: str,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": COMPUTE_BUDGET_SCHEMA_VERSION,
        "budget_id": budget_id,
        "owner": owner,
        "units_total": units_total,
        "unit_kind": unit_kind,
        "hardware_tier": hardware_tier,
        "device_class": device_class,
        "issued_by": issued_by,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class ComputeBudget:
    """An authority-signed compute budget.

    ``units_total`` is the lifetime ceiling in ``unit_kind`` units.
    ``hardware_tier`` and ``device_class`` are ceilings, never floors:
    spend may narrow but never widen. ``issued_by`` must be a
    registered authority and must differ from ``owner`` — the agent
    cannot mint its own compute (no-self-issuance).
    """

    budget_id: str
    owner: str
    units_total: int
    unit_kind: str
    hardware_tier: str
    device_class: str
    issued_by: str
    issued_at: int
    expires_at: int
    budget_digest: str
    signature: bytes
    prev_hash: str = ""
    schema_version: str = COMPUTE_BUDGET_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "compute-budget",
            "schema_version": self.schema_version,
            "budget_id": self.budget_id,
            "owner": self.owner,
            "units_total": self.units_total,
            "unit_kind": self.unit_kind,
            "hardware_tier": self.hardware_tier,
            "device_class": self.device_class,
            "issued_by": self.issued_by,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "budget_digest": self.budget_digest,
            "signature": self.signature.hex(),
            "prev_hash": self.prev_hash,
        }


def issue_budget(
    registry: AuthorityRegistry,
    *,
    budget_id: str,
    owner: str,
    units_total: int,
    unit_kind: str,
    hardware_tier: str,
    device_class: str,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    signature: bytes,
    prev_hash: str = "",
) -> ComputeBudget:
    """Mint a compute budget. The signature must come from a registered
    human authority over the budget digest; anything else fails loud.

    There is deliberately no agent-key issuance path and no
    ``issue_budget_for_agent`` helper: the agent cannot self-mint, and
    cannot ask this function to do it for it. ``issued_by == owner``
    is refused even when the owner *is* a registered authority —
    minting your own budget is self-issuance, full stop.
    """
    if not isinstance(registry, AuthorityRegistry):
        raise ComputeBudgetError("registry must be an AuthorityRegistry")
    _require_nonempty(budget_id, "budget_id")
    _require_nonempty(owner, "owner")
    _require_positive_int(units_total, "units_total")
    if unit_kind not in UNIT_KINDS:
        raise ComputeBudgetError(
            f"unit_kind must be one of {', '.join(UNIT_KINDS)}"
        )
    if hardware_tier not in HARDWARE_TIERS:
        raise ComputeBudgetError(
            f"hardware_tier must be one of {', '.join(HARDWARE_TIERS)}"
        )
    if device_class not in DEVICE_CLASSES:
        raise ComputeBudgetError(
            f"device_class must be one of {', '.join(DEVICE_CLASSES)}"
        )
    _require_nonempty(issued_by, "issued_by")
    _require_unix(issued_at, "issued_at")
    _require_unix(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise ComputeBudgetError("expires_at must be after issued_at")
    if prev_hash and not _is_hex64(prev_hash):
        raise ComputeBudgetError("prev_hash must be empty or a 64-char hex digest")
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != _ED25519_SIG_LENGTH:
        raise ComputeBudgetError("signature must be 64 bytes")

    pubkey = registry.public_key_for(issued_by)
    if pubkey is None:
        raise ComputeBudgetError(
            f"issued_by {issued_by!r} is not a registered budget authority"
        )
    if issued_by == owner:
        raise ComputeBudgetError(
            "self-issuance refused: issued_by must differ from owner"
        )
    digest = jcs_sha256_hex(
        _budget_payload(
            budget_id=budget_id,
            owner=owner,
            units_total=units_total,
            unit_kind=unit_kind,
            hardware_tier=hardware_tier,
            device_class=device_class,
            issued_by=issued_by,
            issued_at=issued_at,
            expires_at=expires_at,
            prev_hash=prev_hash,
        )
    )
    if not ed_verify(pubkey, digest.encode("utf-8"), bytes(signature)):
        raise ComputeBudgetError("authority signature does not verify")
    return ComputeBudget(
        budget_id=budget_id,
        owner=owner,
        units_total=units_total,
        unit_kind=unit_kind,
        hardware_tier=hardware_tier,
        device_class=device_class,
        issued_by=issued_by,
        issued_at=issued_at,
        expires_at=expires_at,
        budget_digest=digest,
        signature=bytes(signature),
        prev_hash=prev_hash,
    )


# ---------------------------------------------------------------------------
# SpendReceipt: one hash-chained spend against a budget
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SpendReceipt:
    """One authorized spend, hash-chained to its predecessor.

    ``purpose`` is mandatory — unattributed compute is unauthorizable
    compute. ``remaining`` is the budget balance *after* this spend;
    ``prev_hash`` chains to the previous receipt's
    :meth:`receipt_hash` (empty string for genesis).
    """

    receipt_id: str
    budget_id: str
    units: int
    purpose: str
    remaining: int
    prev_hash: str = ""
    created_unix: int = 0
    schema_version: str = COMPUTE_BUDGET_SCHEMA_VERSION

    def receipt_hash(self) -> str:
        return jcs_sha256_hex(
            {
                "schema_version": self.schema_version,
                "receipt_id": self.receipt_id,
                "budget_id": self.budget_id,
                "units": self.units,
                "purpose": self.purpose,
                "remaining": self.remaining,
                "prev_hash": self.prev_hash,
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "compute-spend-receipt",
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "budget_id": self.budget_id,
            "units": self.units,
            "purpose": self.purpose,
            "remaining": self.remaining,
            "prev_hash": self.prev_hash,
            "created_unix": self.created_unix,
            "receipt_hash": self.receipt_hash(),
        }


@dataclass(frozen=True)
class SpendVerdict:
    """The verdict of :meth:`BudgetLedger.spend`."""

    allowed: bool
    reason: str
    remaining: int
    receipt: SpendReceipt | None
    audit_event: dict[str, Any]


def _spend_event(
    *,
    budget_id: str,
    allowed: bool,
    reason: str,
    units: int,
    purpose: str,
    remaining: int,
    receipt_hash: str,
    created_unix: int,
) -> dict[str, Any]:
    event = COMPUTE_SPEND_EVENT if allowed else COMPUTE_DENIED_EVENT
    if reason == DENY_BUDGET_EXHAUSTED:
        event = COMPUTE_EXHAUSTED_EVENT
    return {
        "event": event,
        "budget_id": budget_id,
        "allowed": allowed,
        "reason": reason,
        "units": units,
        "purpose": purpose,
        "remaining": remaining,
        "receipt_hash": receipt_hash,
        "created_unix": created_unix,
    }


# ---------------------------------------------------------------------------
# BudgetLedger: budgets, spend chains, and the spend gate
# ---------------------------------------------------------------------------


class BudgetLedger:
    """Owns budgets and their spend chains; the spend gate lives here.

    The ledger is the enforcement point: every authorized compute
    unit passes through :meth:`spend`, which appends a hash-chained
    receipt. There is no spend path that bypasses the ledger — a unit
    without a receipt is an unauthorized unit.
    """

    def __init__(self) -> None:
        self._budgets: dict[str, ComputeBudget] = {}
        self._chains: dict[str, list[SpendReceipt]] = {}
        self._receipt_seq = 0

    # -- issuance ------------------------------------------------------

    def issue(self, budget: ComputeBudget) -> ComputeBudget:
        """Register an authority-signed budget. Duplicate ids refuse."""
        if not isinstance(budget, ComputeBudget):
            raise ComputeBudgetError("budget must be a ComputeBudget")
        if budget.budget_id in self._budgets:
            raise ComputeBudgetError(
                f"duplicate budget_id {budget.budget_id!r}"
            )
        self._budgets[budget.budget_id] = budget
        self._chains[budget.budget_id] = []
        return budget

    def budget(self, budget_id: str) -> ComputeBudget | None:
        return self._budgets.get(budget_id)

    def remaining(self, budget_id: str) -> int:
        """Current balance. Unknown budgets raise (programmer error —
        the *gate* returns a verdict instead)."""
        budget = self._budgets.get(budget_id)
        if budget is None:
            raise ComputeBudgetError(f"unknown budget {budget_id!r}")
        chain = self._chains[budget_id]
        if not chain:
            return budget.units_total
        return chain[-1].remaining

    # -- hardware-tier probe --------------------------------------------

    def check_hardware_tier(
        self,
        budget_id: str,
        claimed_tier: str,
        evidence_kind: str,
    ) -> tuple[bool, str]:
        """Probe whether spend at ``claimed_tier`` is legitimate.

        Two independent checks, both must pass: (1) the claimed tier
        is at or below the budget's tier ceiling — claiming H100
        spend against an edge budget denies; (2) the attestation
        evidence meets the tier's minimum — datacenter/hpc claims on
        unattested (software-only) hardware deny. Returns
        ``(allowed, reason)``; never raises on verification outcomes.
        """
        budget = self._budgets.get(budget_id)
        if budget is None:
            return (False, DENY_UNKNOWN_BUDGET)
        if claimed_tier not in HARDWARE_TIERS:
            raise ComputeBudgetError(
                f"claimed_tier must be one of {', '.join(HARDWARE_TIERS)}"
            )
        if _TIER_RANK[claimed_tier] > _TIER_RANK[budget.hardware_tier]:
            return (False, DENY_TIER_MISMATCH)
        minimum = TIER_MIN_EVIDENCE[claimed_tier]
        try:
            strong_enough = strength_at_least(evidence_kind, minimum)
        except Exception:
            return (False, DENY_WEAK_EVIDENCE)
        if not strong_enough:
            return (False, DENY_WEAK_EVIDENCE)
        return (True, "tier_verified")

    # -- the spend gate ---------------------------------------------------

    def spend(
        self,
        *,
        budget_id: str,
        units: int,
        purpose: str,
        spend_tier: str,
        device_class: str,
        evidence_kind: str,
        created_unix: int = 0,
    ) -> SpendVerdict:
        """Authorize one spend, fail-closed. Gate order is fixed:

        1. the budget must exist;
        2. the budget must be unexpired at ``created_unix``;
        3. the purpose must be non-empty (attribution is mandatory);
        4. the spend tier must sit at or below the budget's tier
           ceiling, with attestation evidence meeting the tier minimum;
        5. the device class must sit at or below the budget's device
           class — cloud spend on an edge budget denies;
        6. the spend chain must verify (no gaps, no tampering);
        7. the units must fit the remaining balance — overspend denies
           with ``compute:budget_exhausted`` and the workload stops;
           there is no borrowing.

        Never raises on verification outcomes — denials are values.
        Raises :class:`ComputeBudgetError` only on malformed *inputs*.
        """
        _require_unix(created_unix, "created_unix")
        _require_positive_int(units, "units")
        budget = self._budgets.get(budget_id)

        def _deny(reason: str, remaining: int = 0) -> SpendVerdict:
            return SpendVerdict(
                allowed=False,
                reason=reason,
                remaining=remaining,
                receipt=None,
                audit_event=_spend_event(
                    budget_id=budget_id,
                    allowed=False,
                    reason=reason,
                    units=units,
                    purpose=purpose if isinstance(purpose, str) else "",
                    remaining=remaining,
                    receipt_hash="",
                    created_unix=created_unix,
                ),
            )

        if budget is None:
            return _deny(DENY_UNKNOWN_BUDGET)
        if created_unix > budget.expires_at:
            return _deny(DENY_EXPIRED_BUDGET)
        if not isinstance(purpose, str) or not purpose:
            return _deny(DENY_MISSING_PURPOSE)
        if device_class not in DEVICE_CLASSES:
            raise ComputeBudgetError(
                f"device_class must be one of {', '.join(DEVICE_CLASSES)}"
            )

        tier_ok, tier_reason = self.check_hardware_tier(
            budget_id, spend_tier, evidence_kind
        )
        if not tier_ok:
            return _deny(tier_reason)

        if _DEVICE_RANK[device_class] > _DEVICE_RANK[budget.device_class]:
            return _deny(DENY_DEVICE_CLASS)

        chain_ok, chain_reason, balance = self._verify_chain(budget_id)
        if not chain_ok:
            return _deny(chain_reason, balance)
        if units > balance:
            return _deny(DENY_BUDGET_EXHAUSTED, balance)

        self._receipt_seq += 1
        chain = self._chains[budget_id]
        prev_hash = chain[-1].receipt_hash() if chain else ""
        receipt = SpendReceipt(
            receipt_id=f"{budget_id}:spend:{self._receipt_seq:06d}",
            budget_id=budget_id,
            units=units,
            purpose=purpose,
            remaining=balance - units,
            prev_hash=prev_hash,
            created_unix=created_unix,
        )
        chain.append(receipt)
        return SpendVerdict(
            allowed=True,
            reason="spend_authorized",
            remaining=receipt.remaining,
            receipt=receipt,
            audit_event=_spend_event(
                budget_id=budget_id,
                allowed=True,
                reason="spend_authorized",
                units=units,
                purpose=purpose,
                remaining=receipt.remaining,
                receipt_hash=receipt.receipt_hash(),
                created_unix=created_unix,
            ),
        )

    # -- chain verification -------------------------------------------------

    def _verify_chain(self, budget_id: str) -> tuple[bool, str, int]:
        """Recompute every spend receipt digest and linkage.

        Returns ``(ok, reason, balance)``. A gap or tampered receipt
        denies *all future spend* on the budget — the chain is the
        balance of record, and a broken chain of record fail-closes.
        """
        budget = self._budgets[budget_id]
        chain = self._chains[budget_id]
        balance = budget.units_total
        previous_hash = ""
        for index, receipt in enumerate(chain):
            if not isinstance(receipt, SpendReceipt):
                return (False, DENY_MALFORMED, balance)
            if receipt.budget_id != budget_id:
                return (False, DENY_MALFORMED, balance)
            if not hmac.compare_digest(receipt.prev_hash, previous_hash):
                return (False, DENY_CHAIN_GAP, balance)
            # Balance walk: the receipt's claimed remaining must equal
            # the previous balance minus this receipt's units. This is
            # what catches a tampered receipt — its digest recomputes
            # fine from its own (tampered) fields, but the balance walk
            # exposes the lie.
            if receipt.units <= 0 or receipt.remaining != balance - receipt.units:
                return (False, DENY_DIGEST_MISMATCH, balance)
            balance = receipt.remaining
            previous_hash = receipt.receipt_hash()
        return (True, "chain_verified", balance)

    def verify_spend_chain(self, budget_id: str) -> tuple[bool, str]:
        """Public probe: is this budget's spend chain intact?"""
        if budget_id not in self._budgets:
            raise ComputeBudgetError(f"unknown budget {budget_id!r}")
        ok, reason, _balance = self._verify_chain(budget_id)
        return (ok, reason)

    # -- ROI ledger -----------------------------------------------------------

    def roi_ledger(self) -> dict[str, Any]:
        """Deterministic aggregation of the spend chain.

        Returns units spent per purpose (nested by unit kind, keys
        sorted) and per budget (spent / remaining / ceiling). This is
        the "ROI per token" input: join it with outcome records
        out-of-band; the ledger itself invents no metrics, it only
        reports what the receipts say was spent, where, and for what.
        """
        by_purpose: dict[str, dict[str, int]] = {}
        by_budget: dict[str, dict[str, Any]] = {}
        n_spends = 0
        for budget_id in sorted(self._budgets):
            budget = self._budgets[budget_id]
            chain = self._chains[budget_id]
            spent = sum(r.units for r in chain)
            n_spends += len(chain)
            by_budget[budget_id] = {
                "unit_kind": budget.unit_kind,
                "units_total": budget.units_total,
                "spent": spent,
                "remaining": budget.units_total - spent,
                "n_spends": len(chain),
            }
            for receipt in chain:
                kinds = by_purpose.setdefault(receipt.purpose, {})
                kinds[budget.unit_kind] = kinds.get(budget.unit_kind, 0) + receipt.units
        by_purpose_sorted = {
            purpose: {kind: by_purpose[purpose][kind] for kind in sorted(by_purpose[purpose])}
            for purpose in sorted(by_purpose)
        }
        return {
            "by_purpose": by_purpose_sorted,
            "by_budget": by_budget,
            "n_budgets": len(self._budgets),
            "n_spends": n_spends,
        }


# ---------------------------------------------------------------------------
# Test/dev helper: deterministic authority keypair from a seed
# ---------------------------------------------------------------------------


def authority_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """Derive ``(public_key, seed)`` from a 32-byte seed.

    Test and bench scaffolding only: production authorities manage
    keys out-of-band. The seed doubles as the ed25519 secret.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ComputeBudgetError("seed must be 32 bytes")
    seed = bytes(seed)
    return (ed_public_key(seed), seed)


def sign_budget_digest(seed: bytes, digest: str) -> bytes:
    """Sign a budget digest with an authority seed (test/bench use)."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ComputeBudgetError("seed must be 32 bytes")
    _require_hex64(digest, "digest")
    return ed_sign(bytes(seed), digest.encode("utf-8"))


__all__ = [
    "COMPUTE_BUDGET_SCHEMA_VERSION",
    "UNIT_KINDS",
    "HARDWARE_TIERS",
    "TIER_MIN_EVIDENCE",
    "DEVICE_CLASSES",
    "DENY_UNKNOWN_BUDGET",
    "DENY_EXPIRED_BUDGET",
    "DENY_BUDGET_EXHAUSTED",
    "DENY_MISSING_PURPOSE",
    "DENY_TIER_MISMATCH",
    "DENY_WEAK_EVIDENCE",
    "DENY_DEVICE_CLASS",
    "DENY_DIGEST_MISMATCH",
    "DENY_CHAIN_GAP",
    "DENY_MALFORMED",
    "COMPUTE_SPEND_EVENT",
    "COMPUTE_EXHAUSTED_EVENT",
    "COMPUTE_DENIED_EVENT",
    "ComputeBudgetError",
    "AuthorityRegistry",
    "ComputeBudget",
    "SpendReceipt",
    "SpendVerdict",
    "BudgetLedger",
    "issue_budget",
    "authority_keypair",
    "sign_budget_digest",
]
