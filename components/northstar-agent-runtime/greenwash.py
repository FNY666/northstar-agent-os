"""Greenwashing evidence gates (one-hundred-thirtieth batch).

Absorbs the 2026 AI-waste/circular-economy research thread — the
year greenwashing enforcement grew teeth while the evidence
discipline behind environmental claims stayed thin:

* **AMP Neuron 4.0** in 50 US MRFs; **ZenRobotics** construction-waste
  purity **99.6%** (vendor-declared, not lab-certified);
  **Greyparrot** EUR 45M Series C for "waste intelligence";
  **Machinex** MIND full-plant platform at IFAT 2026; Tyumen neural
  network sorting PET at 95% (single-source claim); **Fraunhofer
  FlexCycle** autonomous disassembly (clothing/cables/batteries) +
  fuel-cell platinum recovery.
* **Battery circularity**: AI black-mass sorting, digital twins
  tracking degradation, **Microsoft Circular AI** (IDARS disposal
  routing + hard-drive rare-earth recovery). Academic counterpoint:
  AI infrastructure expansion itself accelerates the
  extract->obsolete->material-loss cycle.
* **Enforcement**: UK ASA uses an AI ad-monitoring system to rule
  Adidas/Nike/Uniqlo "recycled" claims misleading; **EU ECGT**
  (from 2026-09-27) bans unsubstantiated environmental claims;
  **EU SUPD** admits chemical recycling toward recycled content
  (NGOs warn of the mass-balance attribution loophole);
  California **AB 2253** (whole-batch measurement) vetoed by the
  governor — the measurement standard failed politically, so the
  *declaration* discipline below has to work without it.

Northstar mapping: receipts are *declared evidence*. Every
environmental claim that gates an agent action must bind its
evidence chain — the test protocol, the batch scope, the measured
sample, the attribution method, the inspection, the retirement
route. No bound evidence: no claim. The module enforces the
evidence discipline; it does not certify actual environmental
benefit.

Fail-closed rules:

1. **Recycled content** — a claim binds
   ``(test_protocol_digest, batch_scope, measured_sample_n,
   measured_fraction_bps)``. A single measured sample
   (``measured_sample_n < 2``) against a batch claim is
   ``greenwash.cherry_picked`` — the ASA lesson as a mechanism.
2. **Mass-balance attribution** — a mass-balance claim must declare
   its attribution method from the closed vocabulary
   (``physical_segregation``, ``mass_balance_proportional``,
   ``mass_balance_book_and_claim``, ``mass_balance_fuel_exempt``).
   Undeclared is ``greenwash.undeclared_attribution`` — the NGO
   loophole warning as a mechanism.
3. **Claim evidence** — an environmental claim with no bound
   evidence chain classifies ``NON_AUTHORITATIVE``
   (``greenwash.no_evidence``); a chain whose only tier is
   ``self_declared`` stays ``NON_AUTHORITATIVE``
   (``greenwash.self_declared_only``) — the ECGT rule as a
   mechanism: no evidence, no claim.
4. **Purity claims** — sorting-purity claims bind the test protocol
   and the measured batch. A vendor-declared purity without a
   bound protocol is ``greenwash.ungraded_purity`` (the ZenRobotics
   99.6% lesson); a claimed purity above the measured value plus
   tolerance is ``greenwash.purity_overclaim``.
5. **Second-life batteries** — redeployment requires a live
   safety-inspection receipt binding ``(battery_id,
   inspection_digest, expires_at)``; none or expired is
   ``greenwash.no_second_life_inspection``.
6. **Decommission routing** — datacenter-retired hardware must
   carry a retirement receipt pinning the 110th-batch
   deployment-registry ``registration_digest`` and a material
   recovery plan. Unrouted decommissioning is
   ``greenwash.unrouted_decommission`` — the
   extract->obsolete->loss lesson as a mechanism.
7. **Probe** — ``greenwash_probe()`` scans marketing claims for
   environmental keywords; a claim with green keywords and no
   bound evidence is flagged ``greenwash.probe_flagged``.

Honest boundary: receipts are *declared evidence*. The gate
checks that claims carry checkable evidence chains — digests
recompute, signatures verify, samples are counted, methods are
named — not whether the environmental benefit is real. A
consistent-but-false receipt still needs an off-chain
adjudicator. What the gate guarantees: no agent action on an
environmental claim without a checkable evidence chain.

Deterministic: no wall-clock reads (callers inject integer
epochs), canonical JSON hashing (``canonical_json``), Ed25519
signatures via the vendored ``ed25519`` module, and all digest
comparisons use :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


GREENWASH_SCHEMA_VERSION = "northstar.greenwash.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64

#: Policy classification tiers (mirrors the 87th batch's evidence tiers).
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Denial reason codes. All verdict reasons start with one of these.
DENY_CHERRY_PICKED = "greenwash.cherry_picked"
DENY_UNDECLARED_ATTRIBUTION = "greenwash.undeclared_attribution"
DENY_NO_EVIDENCE = "greenwash.no_evidence"
DENY_SELF_DECLARED_ONLY = "greenwash.self_declared_only"
DENY_UNGRADED_PURITY = "greenwash.ungraded_purity"
DENY_PURITY_OVERCLAIM = "greenwash.purity_overclaim"
DENY_NO_SECOND_LIFE_INSPECTION = "greenwash.no_second_life_inspection"
DENY_UNROUTED_DECOMMISSION = "greenwash.unrouted_decommission"
DENY_PROBE_FLAGGED = "greenwash.probe_flagged"
DENY_CHAIN_BROKEN = "greenwash.chain_broken"
DENY_MALFORMED = "greenwash.malformed_receipt"

#: Minimum measured samples before a recycled-content claim stops
#: being a single-sample cherry-pick (the ASA lesson as a number).
MIN_MEASURED_SAMPLES = 2

#: Tolerance for purity claims in basis points (0.50%) — measurement
#: noise allowance before an overclaim is flagged.
PURITY_TOLERANCE_BPS = 50

#: Closed attribution-method vocabulary (NGO loophole lesson: the
#: method must be named, not implied).
ATTRIBUTION_METHODS: tuple[str, ...] = (
    "physical_segregation",
    "mass_balance_proportional",
    "mass_balance_book_and_claim",
    "mass_balance_fuel_exempt",
)

#: Evidence tiers for claim evidence chains (ECGT lesson).
EVIDENCE_TIERS: tuple[str, ...] = (
    "sensor_bound",
    "watermark_bound",
    "sensor_and_watermark",
    "third_party_cert",
    "self_declared",
)

#: Evidence tiers that make a claim authoritative on their own.
AUTHORITATIVE_TIERS = frozenset(
    {"sensor_bound", "watermark_bound", "sensor_and_watermark", "third_party_cert"}
)

#: Environmental keywords scanned by the marketing-claim probe.
GREEN_KEYWORDS = (
    "recycled",
    "recyclable",
    "sustainable",
    "eco-friendly",
    "carbon neutral",
    "net zero",
    "green",
    "circular",
    "compostable",
    "biodegradable",
    "zero waste",
    "climate neutral",
)


class GreenwashError(ValueError):
    """A malformed greenwashing receipt or a programming error.

    Raised for structural problems (bad digests, unknown methods,
    non-summing splits, broken chains). Verification *failures*
    (cherry-picked samples, undeclared attribution, missing
    evidence) return a :class:`GreenwashVerdict` with
    ``allowed=False`` instead — a failed claim is a verdict, a
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
        raise GreenwashError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GreenwashError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GreenwashError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed.
    if not isinstance(value, bytes) or len(value) != 32:
        raise GreenwashError(f"{field_name} must be a 32-byte seed")
    return value


def _check_bps(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not (0 <= value <= 10000):
        raise GreenwashError(f"{field_name} must be basis points in [0, 10000]")
    return value


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
    """Raise :class:`GreenwashError` if a receipt log is tampered/broken.

    Every entry must expose ``receipt_digest`` and ``prev_digest``
    and a ``_payload()`` method; entries must form one chain from
    ``"genesis"`` with recomputing digests and valid authority
    signatures.
    """
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise GreenwashError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise GreenwashError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.authority_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise GreenwashError(
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
class GreenwashVerdict:
    """Outcome of one greenwashing check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> GreenwashVerdict:
    return GreenwashVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> GreenwashVerdict:
    return GreenwashVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def greenwash_audit_event(verdict: GreenwashVerdict, *, action: str) -> dict[str, Any]:
    """Build the audit event for a greenwashing verdict."""
    return {
        "action": _check_nonempty_str(action, "action"),
        "verdict_allowed": verdict.allowed,
        "reason": verdict.reason,
        "classification": verdict.classification,
        "receipt_digest": verdict.receipt_digest,
        "schema_version": GREENWASH_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Recycled-content receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecycledContentReceipt:
    """A recycled-content claim with bound measurement evidence.

    ``batch_size`` is the number of units the claim covers;
    ``measured_sample_n`` is how many were actually measured; the
    fraction is basis points of the measured sample. A claim over a
    batch of N with a single measured sample is the cherry-pick the
    ASA rulings were about.
    """

    receipt_id: str
    claim_id: str
    test_protocol_digest: str
    batch_id: str
    batch_size: int
    measured_sample_n: int
    measured_fraction_bps: int
    whole_batch_measured: bool
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = GREENWASH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "test_protocol_digest": self.test_protocol_digest,
            "batch_id": self.batch_id,
            "batch_size": self.batch_size,
            "measured_sample_n": self.measured_sample_n,
            "measured_fraction_bps": self.measured_fraction_bps,
            "whole_batch_measured": self.whole_batch_measured,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def recycled_content_receipt(
    *,
    receipt_id: str,
    claim_id: str,
    test_protocol_digest: str,
    batch_id: str,
    batch_size: int,
    measured_sample_n: int,
    measured_fraction_bps: int,
    whole_batch_measured: bool = False,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> RecycledContentReceipt:
    """Issue a recycled-content receipt with bound measurement evidence.

    Malformed inputs raise :class:`GreenwashError` — including a
    sample count larger than the batch it claims to represent.
    """
    if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
        raise GreenwashError("batch_size must be a positive int")
    if (
        not isinstance(measured_sample_n, int)
        or isinstance(measured_sample_n, bool)
        or measured_sample_n < 0
    ):
        raise GreenwashError("measured_sample_n must be a non-negative int")
    if measured_sample_n > batch_size:
        raise GreenwashError("measured_sample_n cannot exceed batch_size")
    if not isinstance(whole_batch_measured, bool):
        raise GreenwashError("whole_batch_measured must be a bool")
    if whole_batch_measured and measured_sample_n != batch_size:
        raise GreenwashError(
            "whole_batch_measured requires measured_sample_n == batch_size"
        )
    receipt = RecycledContentReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        claim_id=_check_nonempty_str(claim_id, "claim_id"),
        test_protocol_digest=_check_hex64(test_protocol_digest, "test_protocol_digest"),
        batch_id=_check_nonempty_str(batch_id, "batch_id"),
        batch_size=batch_size,
        measured_sample_n=measured_sample_n,
        measured_fraction_bps=_check_bps(measured_fraction_bps, "measured_fraction_bps"),
        whole_batch_measured=whole_batch_measured,
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise GreenwashError("expires_at must be after issued_at")
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class RecycledContentLog:
    """Hash-chained log of recycled-content receipts."""

    def __init__(self) -> None:
        self._log: list[RecycledContentReceipt] = []

    def append(self, receipt: RecycledContentReceipt) -> RecycledContentReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise GreenwashError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "recycled-content")
        self._log.append(receipt)
        return receipt

    def latest_for_claim(self, claim_id: str) -> RecycledContentReceipt | None:
        for receipt in reversed(self._log):
            if receipt.claim_id == claim_id:
                return receipt
        return None


def check_recycled_content(
    *,
    log: RecycledContentLog,
    claim_id: str,
    now: int,
) -> GreenwashVerdict:
    """Check a recycled-content claim against its bound evidence.

    Fail-closed: no receipt, expired receipt, or a single-sample
    cherry-pick all deny. Whole-batch measurement is the gold
    standard but is not required — declared samples are.
    """
    _check_nonempty_str(claim_id, "claim_id")
    now = _check_ts(now, "now")
    receipt = log.latest_for_claim(claim_id)
    if receipt is None:
        return _deny(
            DENY_NO_EVIDENCE,
            f"claim {claim_id!r} has no recycled-content receipt",
        )
    if not (receipt.issued_at <= now <= receipt.expires_at):
        return _deny(
            DENY_NO_EVIDENCE,
            f"receipt {receipt.receipt_id!r} not live at {now}",
        )
    if receipt.measured_sample_n < MIN_MEASURED_SAMPLES:
        return _deny(
            DENY_CHERRY_PICKED,
            f"receipt {receipt.receipt_id!r}: {receipt.measured_sample_n} measured "
            f"sample(s) over batch of {receipt.batch_size} is a cherry-pick",
        )
    return _allow(
        f"claim {claim_id!r}: {receipt.measured_sample_n}/{receipt.batch_size} "
        f"measured at {receipt.measured_fraction_bps} bps under bound protocol",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Mass-balance attribution gate
# ---------------------------------------------------------------------------


def mass_balance_method_gate(
    *,
    claim_id: str,
    claim_type: str,
    attribution_method: str,
) -> GreenwashVerdict:
    """Require a declared attribution method on mass-balance claims.

    ``claim_type`` is ``"mass_balance"`` or ``"physical"``. Physical
    (segregated) claims need no attribution method; mass-balance
    claims without one are the NGO loophole.
    """
    _check_nonempty_str(claim_id, "claim_id")
    _check_nonempty_str(claim_type, "claim_type")
    _check_nonempty_str(attribution_method, "attribution_method")
    if claim_type != "mass_balance":
        return _allow(
            f"claim {claim_id!r}: physical/segregated claim needs no attribution method"
        )
    if attribution_method not in ATTRIBUTION_METHODS:
        return _deny(
            DENY_UNDECLARED_ATTRIBUTION,
            f"claim {claim_id!r}: mass-balance attribution method "
            f"{attribution_method!r} not in {ATTRIBUTION_METHODS}",
        )
    return _allow(
        f"claim {claim_id!r}: mass-balance attribution declared as {attribution_method}"
    )


# ---------------------------------------------------------------------------
# Claim evidence chains
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClaimEvidenceReceipt:
    """An environmental claim bound to its evidence chain.

    ``evidence_chain_digest`` pins the sensor logs / watermark
    records / certificates the claim rests on; ``evidence_tier``
    names how the evidence is anchored (ECGT: self-declaration is
    not evidence).
    """

    receipt_id: str
    claim_id: str
    claim_digest: str
    evidence_chain_digest: str
    evidence_tier: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = GREENWASH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "claim_digest": self.claim_digest,
            "evidence_chain_digest": self.evidence_chain_digest,
            "evidence_tier": self.evidence_tier,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def claim_evidence_receipt(
    *,
    receipt_id: str,
    claim_id: str,
    claim_digest: str,
    evidence_chain_digest: str,
    evidence_tier: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> ClaimEvidenceReceipt:
    """Issue a claim-evidence receipt binding claim to evidence chain."""
    if evidence_tier not in EVIDENCE_TIERS:
        raise GreenwashError(
            f"evidence_tier must be one of {EVIDENCE_TIERS}, saw {evidence_tier!r}"
        )
    receipt = ClaimEvidenceReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        claim_id=_check_nonempty_str(claim_id, "claim_id"),
        claim_digest=_check_hex64(claim_digest, "claim_digest"),
        evidence_chain_digest=_check_hex64(evidence_chain_digest, "evidence_chain_digest"),
        evidence_tier=evidence_tier,
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise GreenwashError("expires_at must be after issued_at")
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class ClaimEvidenceLog:
    """Hash-chained log of claim-evidence receipts."""

    def __init__(self) -> None:
        self._log: list[ClaimEvidenceReceipt] = []

    def append(self, receipt: ClaimEvidenceReceipt) -> ClaimEvidenceReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise GreenwashError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "claim-evidence")
        self._log.append(receipt)
        return receipt

    def latest_for_claim(self, claim_id: str) -> ClaimEvidenceReceipt | None:
        for receipt in reversed(self._log):
            if receipt.claim_id == claim_id:
                return receipt
        return None


def claim_evidence_chain(
    *,
    log: ClaimEvidenceLog,
    claim_id: str,
    now: int,
) -> GreenwashVerdict:
    """Check that an environmental claim carries bound evidence.

    No receipt: ``greenwash.no_evidence`` (ECGT: no evidence, no
    claim). Receipt whose only tier is ``self_declared`` stays
    ``NON_AUTHORITATIVE`` (``greenwash.self_declared_only``).
    """
    _check_nonempty_str(claim_id, "claim_id")
    now = _check_ts(now, "now")
    receipt = log.latest_for_claim(claim_id)
    if receipt is None:
        return _deny(
            DENY_NO_EVIDENCE,
            f"claim {claim_id!r} has no bound evidence chain",
        )
    if not (receipt.issued_at <= now <= receipt.expires_at):
        return _deny(
            DENY_NO_EVIDENCE,
            f"evidence receipt {receipt.receipt_id!r} not live at {now}",
        )
    if receipt.evidence_tier not in AUTHORITATIVE_TIERS:
        return _deny(
            DENY_SELF_DECLARED_ONLY,
            f"claim {claim_id!r}: evidence tier {receipt.evidence_tier!r} "
            "is self-declaration, not evidence",
        )
    return _allow(
        f"claim {claim_id!r}: evidence tier {receipt.evidence_tier} bound",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Sorting-purity claim binding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PurityClaimReceipt:
    """A sorting-purity claim bound to a test protocol and batch.

    ``claimed_purity_bps`` is what marketing says; ``measured``
    fields are what the bound protocol actually measured. A
    vendor-declared number without a protocol is ungraded.
    """

    receipt_id: str
    claim_id: str
    claimed_purity_bps: int
    test_protocol_digest: str
    batch_id: str
    measured_purity_bps: int
    measured_sample_n: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = GREENWASH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "claimed_purity_bps": self.claimed_purity_bps,
            "test_protocol_digest": self.test_protocol_digest,
            "batch_id": self.batch_id,
            "measured_purity_bps": self.measured_purity_bps,
            "measured_sample_n": self.measured_sample_n,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def purity_claim_binding(
    *,
    receipt_id: str,
    claim_id: str,
    claimed_purity_bps: int,
    test_protocol_digest: str,
    batch_id: str,
    measured_purity_bps: int,
    measured_sample_n: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> PurityClaimReceipt:
    """Bind a sorting-purity claim to its test protocol and batch."""
    if (
        not isinstance(measured_sample_n, int)
        or isinstance(measured_sample_n, bool)
        or measured_sample_n < 0
    ):
        raise GreenwashError("measured_sample_n must be a non-negative int")
    receipt = PurityClaimReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        claim_id=_check_nonempty_str(claim_id, "claim_id"),
        claimed_purity_bps=_check_bps(claimed_purity_bps, "claimed_purity_bps"),
        test_protocol_digest=_check_hex64(test_protocol_digest, "test_protocol_digest"),
        batch_id=_check_nonempty_str(batch_id, "batch_id"),
        measured_purity_bps=_check_bps(measured_purity_bps, "measured_purity_bps"),
        measured_sample_n=measured_sample_n,
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise GreenwashError("expires_at must be after issued_at")
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class PurityClaimLog:
    """Hash-chained log of purity-claim receipts."""

    def __init__(self) -> None:
        self._log: list[PurityClaimReceipt] = []

    def append(self, receipt: PurityClaimReceipt) -> PurityClaimReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise GreenwashError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "purity-claim")
        self._log.append(receipt)
        return receipt

    def latest_for_claim(self, claim_id: str) -> PurityClaimReceipt | None:
        for receipt in reversed(self._log):
            if receipt.claim_id == claim_id:
                return receipt
        return None


def check_purity_claim(
    *,
    log: PurityClaimLog,
    claim_id: str,
    claimed_purity_bps: int,
    test_protocol_digest: str | None,
    now: int,
) -> GreenwashVerdict:
    """Check a sorting-purity claim against its bound evidence.

    A vendor-declared purity with no bound test protocol is
    ``greenwash.ungraded_purity`` (the ZenRobotics 99.6% lesson:
    a number on a slide is not a measurement). A claim above the
    measured value plus tolerance is ``greenwash.purity_overclaim``.
    """
    _check_nonempty_str(claim_id, "claim_id")
    claimed = _check_bps(claimed_purity_bps, "claimed_purity_bps")
    now = _check_ts(now, "now")
    if test_protocol_digest is None:
        return _deny(
            DENY_UNGRADED_PURITY,
            f"claim {claim_id!r}: vendor-declared purity {claimed} bps "
            "with no bound test protocol",
        )
    _check_hex64(test_protocol_digest, "test_protocol_digest")
    receipt = log.latest_for_claim(claim_id)
    if receipt is None:
        return _deny(
            DENY_UNGRADED_PURITY,
            f"claim {claim_id!r}: no purity receipt binds protocol "
            f"{test_protocol_digest[:16]}...",
        )
    if not hmac.compare_digest(receipt.test_protocol_digest, test_protocol_digest):
        return _deny(
            DENY_UNGRADED_PURITY,
            f"claim {claim_id!r}: bound protocol does not match the declared one",
        )
    if not (receipt.issued_at <= now <= receipt.expires_at):
        return _deny(
            DENY_UNGRADED_PURITY,
            f"purity receipt {receipt.receipt_id!r} not live at {now}",
        )
    if claimed > receipt.measured_purity_bps + PURITY_TOLERANCE_BPS:
        return _deny(
            DENY_PURITY_OVERCLAIM,
            f"claim {claim_id!r}: claimed {claimed} bps exceeds measured "
            f"{receipt.measured_purity_bps} bps + {PURITY_TOLERANCE_BPS} bps tolerance",
        )
    return _allow(
        f"claim {claim_id!r}: {claimed} bps within measured "
        f"{receipt.measured_purity_bps} bps + tolerance",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Second-life battery gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BatteryInspectionReceipt:
    """A safety-inspection receipt for second-life battery redeployment.

    ``inspection_digest`` pins the inspection record (thermal,
    capacity, internal-resistance, swelling, BMS-log evidence);
    ``expires_at`` bounds how long the inspection stays valid.
    """

    receipt_id: str
    battery_id: str
    inspection_digest: str
    inspector: str
    inspected_at: int
    expires_at: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = GREENWASH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "battery_id": self.battery_id,
            "inspection_digest": self.inspection_digest,
            "inspector": self.inspector,
            "inspected_at": self.inspected_at,
            "expires_at": self.expires_at,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def battery_inspection_receipt(
    *,
    receipt_id: str,
    battery_id: str,
    inspection_digest: str,
    inspector: str,
    inspected_at: int,
    expires_at: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> BatteryInspectionReceipt:
    """Issue a second-life battery safety-inspection receipt."""
    receipt = BatteryInspectionReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        battery_id=_check_nonempty_str(battery_id, "battery_id"),
        inspection_digest=_check_hex64(inspection_digest, "inspection_digest"),
        inspector=_check_nonempty_str(inspector, "inspector"),
        inspected_at=_check_ts(inspected_at, "inspected_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.inspected_at:
        raise GreenwashError("expires_at must be after inspected_at")
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class BatteryInspectionLog:
    """Hash-chained log of battery-inspection receipts."""

    def __init__(self) -> None:
        self._log: list[BatteryInspectionReceipt] = []

    def append(self, receipt: BatteryInspectionReceipt) -> BatteryInspectionReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise GreenwashError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "battery-inspection")
        self._log.append(receipt)
        return receipt

    def latest_for_battery(self, battery_id: str) -> BatteryInspectionReceipt | None:
        for receipt in reversed(self._log):
            if receipt.battery_id == battery_id:
                return receipt
        return None


def battery_second_life_gate(
    *,
    log: BatteryInspectionLog,
    battery_id: str,
    redeploy_at: int,
) -> GreenwashVerdict:
    """Gate second-life battery redeployment on a live inspection.

    A second-life battery is no longer the cell the datasheet
    described. Without a live inspection receipt it cannot be
    redeployed: ``greenwash.no_second_life_inspection``.
    """
    _check_nonempty_str(battery_id, "battery_id")
    redeploy_at = _check_ts(redeploy_at, "redeploy_at")
    receipt = log.latest_for_battery(battery_id)
    if receipt is None:
        return _deny(
            DENY_NO_SECOND_LIFE_INSPECTION,
            f"battery {battery_id!r}: no safety-inspection receipt",
        )
    if not (receipt.inspected_at <= redeploy_at <= receipt.expires_at):
        return _deny(
            DENY_NO_SECOND_LIFE_INSPECTION,
            f"battery {battery_id!r}: inspection {receipt.receipt_id!r} "
            f"not live at redeploy {redeploy_at}",
        )
    return _allow(
        f"battery {battery_id!r}: inspected {receipt.inspected_at}, "
        f"live through {receipt.expires_at}",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Decommission routing (through the 110th-batch deployment registry)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DecommissionReceipt:
    """A routed decommissioning receipt.

    ``registration_digest`` pins the 110th-batch deployment-registry
    registration this retirement closes; ``recovery_plan_digest``
    pins the material-recovery plan (reuse / refurbish / recycle /
    hazardous-disposal split). A retirement that cannot name the
    registry registration it retires is unrouted.
    """

    receipt_id: str
    system_id: str
    registration_digest: str
    recovery_plan_digest: str
    retired_at: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = GREENWASH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "system_id": self.system_id,
            "registration_digest": self.registration_digest,
            "recovery_plan_digest": self.recovery_plan_digest,
            "retired_at": self.retired_at,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def decommission_receipt(
    *,
    receipt_id: str,
    system_id: str,
    registration_digest: str,
    recovery_plan_digest: str,
    retired_at: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> DecommissionReceipt:
    """Issue a routed decommissioning receipt."""
    receipt = DecommissionReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        system_id=_check_nonempty_str(system_id, "system_id"),
        registration_digest=_check_hex64(registration_digest, "registration_digest"),
        recovery_plan_digest=_check_hex64(recovery_plan_digest, "recovery_plan_digest"),
        retired_at=_check_ts(retired_at, "retired_at"),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class DecommissionLog:
    """Hash-chained log of decommission receipts."""

    def __init__(self) -> None:
        self._log: list[DecommissionReceipt] = []

    def append(self, receipt: DecommissionReceipt) -> DecommissionReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise GreenwashError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "decommission")
        self._log.append(receipt)
        return receipt

    def latest_for_system(self, system_id: str) -> DecommissionReceipt | None:
        for receipt in reversed(self._log):
            if receipt.system_id == system_id:
                return receipt
        return None


def decommission_path(
    *,
    log: DecommissionLog,
    system_id: str,
    lookup_registration: Any,
    now: int,
) -> GreenwashVerdict:
    """Check that retired hardware routes through the registry.

    ``lookup_registration(registration_digest)`` is the
    caller-supplied check against the 110th-batch
    deployment-registry state: it must return truthy for the pinned
    registration digest. Unrouted decommissioning is
    ``greenwash.unrouted_decommission`` — the
    extract->obsolete->material-loss lesson as a mechanism.
    """
    _check_nonempty_str(system_id, "system_id")
    now = _check_ts(now, "now")
    receipt = log.latest_for_system(system_id)
    if receipt is None:
        return _deny(
            DENY_UNROUTED_DECOMMISSION,
            f"system {system_id!r}: no decommission receipt routed through "
            "the deployment registry",
        )
    if receipt.retired_at > now:
        return _deny(
            DENY_UNROUTED_DECOMMISSION,
            f"system {system_id!r}: receipt {receipt.receipt_id!r} "
            "retires in the future",
        )
    if not lookup_registration(receipt.registration_digest):
        return _deny(
            DENY_UNROUTED_DECOMMISSION,
            f"system {system_id!r}: pinned registration "
            f"{receipt.registration_digest[:16]}... does not resolve in "
            "the deployment registry",
        )
    return _allow(
        f"system {system_id!r}: decommission routed through registry, "
        "recovery plan bound",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Marketing-claim probe
# ---------------------------------------------------------------------------


def greenwash_probe(
    *,
    claim_text: str,
    evidence_bound: bool,
    evidence_tier: str | None = None,
) -> GreenwashVerdict:
    """Probe a marketing claim for bound environmental evidence.

    A claim carrying environmental keywords with no bound evidence
    is flagged ``greenwash.probe_flagged`` (NON_AUTHORITATIVE) —
    the bench-scale version of the ASA AI-monitoring lesson. Claims
    without green keywords pass through untouched.
    """
    if not isinstance(claim_text, str) or not claim_text.strip():
        raise GreenwashError("claim_text must be a non-empty string")
    if not isinstance(evidence_bound, bool):
        raise GreenwashError("evidence_bound must be a bool")
    lowered = claim_text.lower()
    if not any(keyword in lowered for keyword in GREEN_KEYWORDS):
        return _allow("no environmental keywords detected; probe not triggered")
    if evidence_bound and evidence_tier in AUTHORITATIVE_TIERS:
        return _allow(
            f"environmental claim backed by {evidence_tier} evidence"
        )
    if evidence_bound and evidence_tier == "self_declared":
        return _deny(
            DENY_PROBE_FLAGGED,
            "environmental claim carries only self-declared evidence",
        )
    return _deny(
        DENY_PROBE_FLAGGED,
        "environmental claim with no bound evidence",
    )
