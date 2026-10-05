"""Waste & circular-economy discipline (one-hundred-thirty-ninth batch).

Absorbs the 2026 AI-waste research thread — the year waste AI went
operational while the evidence discipline behind the claims and the
border discipline around e-waste stayed thin:

* **Oakland Aerbits** (2026-09): aerial AI proactively spotting
  illegal street dumping, backed by $9.2M Crankstart money;
  **California Waste Solutions** fitting EverestLabs AI scanners and
  more Pellenc optical sorters at its MRF (company PR).
* **UK Sharp Group humanoid "Alpha"** (2026-05, BBC): Rainham
  plant, 280kt/year, 40% manual-sorting turnover; the injury
  rate in the sector runs 45% above average; the robot is made by
  China's RealMan, adapted by TeknTrash.
* **Guangzhou Baiyun Helong PPP** (CCTV, 2026-06): ¥160M,
  "primary rough sort + secondary sort + tailings to hydrogen",
  5,400 items/hour verified at the pilot (state-media/local
  PR, unaudited).
* **Enforcement**: **EU Empowering Consumers Directive**
  (enforced 2026-09-27): up to 4% of turnover fines, offset-based
  "carbon neutral" claims banned, claims need supporting detail
  in the same medium; California **SB 343** "Truth in Recycling"
  (compliance deadline 2026-10-04); **AB 2253** proposal:
  recycled content measured per-batch, blocking cherry-picking;
  **Volvic/Danone** (2026): Paris court ruled "carbon neutral" +
  "100% recycled" unlawful.
* **E-waste borders**: **Basel e-waste amendment** in force
  2025-01-01 (A1181/Y49, mandatory PIC); **Malaysia**
  2026-09-16 full e-waste import ban; **BAN** GPS-tracked
  e-Stewards recyclers (40% previously exported to developing
  countries, Total Reclaim fined); EU battery passport: >2kWh
  batteries get a unique serial from 2026-01-01, digital passport
  live 2027-02.
* **Informal sector**: India 1.5–4M waste pickers handle 60–70%
  of urban recyclables (ILO/Chintan); WIEGO warns privatization
  and waste-to-energy "green disguises" threaten picker
  livelihoods — formalization must not expel the marginal.
* **AI's own footprint**: BAN warns AI e-waste could reach
  617Mt by 2050 (NGO model prediction).

Northstar mapping: receipts are *declared discipline*. Every
waste-adjacent agent action — a purity claim, a cross-border
shipment, a battery retirement, a dumping alert, a picker-
displacing automation — must bind its evidence: the test
protocol, the batch scope, the PIC receipt, the passport
digest, the human verification, the transition plan. No bound
evidence: no action.

Fail-closed rules:

1. **Sorting purity** — a purity claim binds
   ``(test_protocol_digest, batch_id, measured_sample_n,
   measured_purity_bps)``. A single measured sample
   (``measured_sample_n < 2``) against a batch claim is
   ``waste.cherry_picked`` (the AB 2253 lesson); a vendor-
   declared purity with no bound protocol is
   ``waste.ungraded_purity``.
2. **Basel PIC** — a cross-border e-waste movement binds a
   ``pic_receipt_digest``. No PIC binding is ``waste.no_pic``
   (the 2025-01-01 amendment as a mechanism); a destination
   on the pinned ban list is ``waste.banned_destination``
   (the Malaysia lesson).
3. **Battery passport** — decommissioning a battery >2kWh
   without pinning the EU battery-passport digest is
   ``waste.no_battery_passport`` (the 2026-01-01 serial rule).
4. **Claim evidence** — a recycled-content claim with no
   bound evidence chain is ``waste.no_evidence``; an
   offset-based "carbon neutral" claim is unlawful by
   default — ``waste.offset_claim`` (the ECGT/Volvic
   lesson).
5. **Informal sector** — automation displacing pickers
   requires a bound transition-plan digest; without it,
   ``waste.no_transition_plan`` (the WIEGO lesson).
6. **AI hardware lifecycle** — an AI workload must declare
   hardware end-of-life disposal bound to the 115th-batch
   ``env_cost`` ledger receipt; undeclared is
   ``waste.unrouted_hardware`` (the 617Mt lesson).
7. **Dumping alerts** — an illegal-dumping alert binds an
   image digest and a human-verification digest. An
   unverified alert is only a lead (``waste.unverified_alert``,
   NON_AUTHORITATIVE); alerts never auto-fine (the Aerbits
   lesson).
8. **Battery fire triage** — batteries entering a shredder
   pass a fire-risk triage receipt; missing is
   ``waste.no_fire_triage``.

Deterministic: no wall-clock reads (callers inject integer
epochs), canonical JSON hashing (``canonical_json``), Ed25519
signatures via the vendored ``ed25519`` module, and all digest
comparisons use :func:`hmac.compare_digest`.

Honest boundary: receipts bind *declared* waste discipline.
The gate checks that claims carry checkable evidence —
digests recompute, signatures verify, samples are counted,
PICs are bound — not whether the pollution stops. A
consistent-but-false receipt still needs an off-chain
adjudicator.
"""

from __future__ import annotations
from _domain_base import DomainError

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


WASTE_SCHEMA_VERSION = "northstar.waste.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Denial reason codes. All verdict reasons start with one of these.
DENY_CHERRY_PICKED = "waste.cherry_picked"
DENY_UNGRADED_PURITY = "waste.ungraded_purity"
DENY_NO_PIC = "waste.no_pic"
DENY_BANNED_DESTINATION = "waste.banned_destination"
DENY_NO_BATTERY_PASSPORT = "waste.no_battery_passport"
DENY_NO_EVIDENCE = "waste.no_evidence"
DENY_OFFSET_CLAIM = "waste.offset_claim"
DENY_NO_TRANSITION_PLAN = "waste.no_transition_plan"
DENY_UNROUTED_HARDWARE = "waste.unrouted_hardware"
DENY_UNVERIFIED_ALERT = "waste.unverified_alert"
DENY_NO_FIRE_TRIAGE = "waste.no_fire_triage"
DENY_CHAIN_BROKEN = "waste.chain_broken"
DENY_MALFORMED = "waste.malformed_receipt"

#: Minimum measured samples before a purity claim stops being a
#: single-sample cherry-pick (the AB 2253 lesson as a number).
MIN_MEASURED_SAMPLES = 2

#: Tolerance for purity claims in basis points (0.50%) —
#: measurement noise allowance before an overclaim is flagged.
PURITY_TOLERANCE_BPS = 50

#: Pinned e-waste import-ban destinations (closed vocabulary;
#: the Malaysia 2026-09-16 lesson as a list).
BANNED_DESTINATIONS: tuple[str, ...] = ("MY",)

#: Closed vocabulary for Basel waste codes on e-waste movements.
WASTE_CODES: tuple[str, ...] = ("A1181", "Y49", "GC020")

#: Closed vocabulary for alert channels.
ALERT_CHANNELS: tuple[str, ...] = ("aerial_ai", "civic_report", "sensor")


class WasteError(DomainError):
    """A malformed waste receipt or a programming error.

    Raised for structural problems (bad digests, unknown codes,
    broken chains). Verification *failures* (cherry-picked
    samples, missing PIC, offset claims) return a
    :class:`WasteVerdict` with ``allowed=False`` instead — a
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
        raise WasteError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WasteError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise WasteError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed.
    if not isinstance(value, bytes) or len(value) != 32:
        raise WasteError(f"{field_name} must be a 32-byte seed")
    return value


def _check_bps(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 10000:
        raise WasteError(f"{field_name} must be basis points 0..10000")
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
    """Raise :class:`WasteError` if a receipt log is tampered/broken."""
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise WasteError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise WasteError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.authority_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise WasteError(
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
class WasteVerdict:
    """Outcome of one waste-discipline check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> WasteVerdict:
    return WasteVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> WasteVerdict:
    return WasteVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def waste_audit_event(verdict: WasteVerdict, *, action: str) -> dict[str, Any]:
    """Build the audit event for a waste-discipline verdict."""
    return {
        "action": _check_nonempty_str(action, "action"),
        "verdict_allowed": verdict.allowed,
        "reason": verdict.reason,
        "classification": verdict.classification,
        "receipt_digest": verdict.receipt_digest,
        "schema_version": WASTE_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Sorting-purity receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PurityReceipt:
    """A sorting-purity claim with bound measurement evidence.

    ``batch_size`` is the number of units the claim covers;
    ``measured_sample_n`` is how many were actually measured; the
    purity is basis points of the measured sample. A claim over a
    batch with a single measured sample is the cherry-pick AB
    2253 was aimed at.
    """

    receipt_id: str
    claim_id: str
    test_protocol_digest: str
    batch_id: str
    batch_size: int
    measured_sample_n: int
    measured_purity_bps: int
    whole_batch_measured: bool
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = WASTE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "test_protocol_digest": self.test_protocol_digest,
            "batch_id": self.batch_id,
            "batch_size": self.batch_size,
            "measured_sample_n": self.measured_sample_n,
            "measured_purity_bps": self.measured_purity_bps,
            "whole_batch_measured": self.whole_batch_measured,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def sorting_purity_receipt(
    *,
    receipt_id: str,
    claim_id: str,
    test_protocol_digest: str,
    batch_id: str,
    batch_size: int,
    measured_sample_n: int,
    measured_purity_bps: int,
    whole_batch_measured: bool = False,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> PurityReceipt:
    """Issue a sorting-purity receipt with bound measurement evidence.

    Malformed inputs raise :class:`WasteError` — including a
    sample count larger than the batch it claims to represent.
    """
    if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
        raise WasteError("batch_size must be a positive int")
    if (
        not isinstance(measured_sample_n, int)
        or isinstance(measured_sample_n, bool)
        or measured_sample_n < 0
    ):
        raise WasteError("measured_sample_n must be a non-negative int")
    if measured_sample_n > batch_size:
        raise WasteError("measured_sample_n cannot exceed batch_size")
    if not isinstance(whole_batch_measured, bool):
        raise WasteError("whole_batch_measured must be a bool")
    if whole_batch_measured and measured_sample_n != batch_size:
        raise WasteError("whole_batch_measured requires measured_sample_n == batch_size")
    receipt = PurityReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        claim_id=_check_nonempty_str(claim_id, "claim_id"),
        test_protocol_digest=_check_hex64(test_protocol_digest, "test_protocol_digest"),
        batch_id=_check_nonempty_str(batch_id, "batch_id"),
        batch_size=batch_size,
        measured_sample_n=measured_sample_n,
        measured_purity_bps=_check_bps(measured_purity_bps, "measured_purity_bps"),
        whole_batch_measured=whole_batch_measured,
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise WasteError("expires_at must be after issued_at")
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class PurityLog:
    """Hash-chained log of sorting-purity receipts."""

    def __init__(self) -> None:
        self._log: list[PurityReceipt] = []

    def append(self, receipt: PurityReceipt) -> PurityReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise WasteError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_batch(self, batch_id: str) -> PurityReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.batch_id, batch_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "purity")


def check_purity_claim(
    *,
    log: PurityLog,
    batch_id: str,
    claimed_purity_bps: int,
    now: int,
) -> WasteVerdict:
    """Check a sorting-purity claim against the bound evidence.

    Single-sample claims are ``waste.cherry_picked`` (the AB
    2253 lesson); a claimed purity above the measured value plus
    tolerance is ``waste.ungraded_purity``; claims with no bound
    receipt are ``waste.ungraded_purity`` as well.
    """
    now = _check_ts(now, "now")
    claimed_purity_bps = _check_bps(claimed_purity_bps, "claimed_purity_bps")
    receipt = log.latest_for_batch(batch_id)
    if receipt is None:
        return _deny(
            DENY_UNGRADED_PURITY,
            f"batch {batch_id!r}: no bound purity receipt — vendor-declared purity",
        )
    if receipt.expires_at <= now:
        return _deny(
            DENY_UNGRADED_PURITY,
            f"batch {batch_id!r}: purity receipt {receipt.receipt_id!r} expired",
        )
    if receipt.measured_sample_n < MIN_MEASURED_SAMPLES:
        return _deny(
            DENY_CHERRY_PICKED,
            f"batch {batch_id!r}: single-sample purity claim "
            f"(n={receipt.measured_sample_n}) against a batch",
        )
    if claimed_purity_bps > receipt.measured_purity_bps + PURITY_TOLERANCE_BPS:
        return _deny(
            DENY_UNGRADED_PURITY,
            f"batch {batch_id!r}: claimed {claimed_purity_bps}bps exceeds measured "
            f"{receipt.measured_purity_bps}bps plus {PURITY_TOLERANCE_BPS}bps tolerance",
        )
    return _allow(
        f"batch {batch_id!r}: purity claim bound to protocol, "
        f"n={receipt.measured_sample_n} measured at {receipt.measured_purity_bps}bps",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Basel PIC bindings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PicReceipt:
    """A cross-border e-waste movement with a bound Basel PIC receipt."""

    receipt_id: str
    movement_id: str
    waste_code: str
    origin: str
    destination: str
    pic_receipt_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = WASTE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "movement_id": self.movement_id,
            "waste_code": self.waste_code,
            "origin": self.origin,
            "destination": self.destination,
            "pic_receipt_digest": self.pic_receipt_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def basel_pic_binding(
    *,
    receipt_id: str,
    movement_id: str,
    waste_code: str,
    origin: str,
    destination: str,
    pic_receipt_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> PicReceipt:
    """Issue a Basel PIC binding for an e-waste movement.

    A banned destination raises :class:`WasteError` at issuance —
    the Malaysia 2026-09-16 lesson as a hard gate.
    """
    if waste_code not in WASTE_CODES:
        raise WasteError(f"waste_code must be one of {WASTE_CODES}")
    if destination in BANNED_DESTINATIONS:
        raise WasteError(f"destination {destination!r} is on the e-waste import-ban list")
    receipt = PicReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        movement_id=_check_nonempty_str(movement_id, "movement_id"),
        waste_code=waste_code,
        origin=_check_nonempty_str(origin, "origin"),
        destination=_check_nonempty_str(destination, "destination"),
        pic_receipt_digest=_check_hex64(pic_receipt_digest, "pic_receipt_digest"),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise WasteError("expires_at must be after issued_at")
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class PicLog:
    """Hash-chained log of Basel PIC bindings."""

    def __init__(self) -> None:
        self._log: list[PicReceipt] = []

    def append(self, receipt: PicReceipt) -> PicReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise WasteError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_movement(self, movement_id: str) -> PicReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.movement_id, movement_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "pic")


def check_movement(
    *,
    log: PicLog,
    movement_id: str,
    now: int,
) -> WasteVerdict:
    """Check a cross-border e-waste movement for a live PIC binding.

    No bound PIC is ``waste.no_pic`` — the Basel 2025-01-01
    amendment as a mechanism.
    """
    now = _check_ts(now, "now")
    receipt = log.latest_for_movement(movement_id)
    if receipt is None:
        return _deny(
            DENY_NO_PIC,
            f"movement {movement_id!r}: no Basel PIC receipt bound",
        )
    if receipt.expires_at <= now:
        return _deny(
            DENY_NO_PIC,
            f"movement {movement_id!r}: PIC receipt {receipt.receipt_id!r} expired",
        )
    return _allow(
        f"movement {movement_id!r}: Basel PIC bound "
        f"({receipt.origin} -> {receipt.destination}, code {receipt.waste_code})",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Battery-passport pins
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BatteryPassportReceipt:
    """A battery decommissioning pinned to the EU battery-passport digest."""

    receipt_id: str
    battery_id: str
    battery_capacity_wh: int
    passport_digest: str
    recovery_plan_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = WASTE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "battery_id": self.battery_id,
            "battery_capacity_wh": self.battery_capacity_wh,
            "passport_digest": self.passport_digest,
            "recovery_plan_digest": self.recovery_plan_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


#: EU battery-passport threshold: >2kWh batteries get a unique
#: serial from 2026-01-01.
BATTERY_PASSPORT_THRESHOLD_WH = 2000


def battery_passport_pin(
    *,
    receipt_id: str,
    battery_id: str,
    battery_capacity_wh: int,
    passport_digest: str,
    recovery_plan_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> BatteryPassportReceipt:
    """Pin a battery decommissioning to its EU battery-passport digest."""
    if not isinstance(battery_capacity_wh, int) or isinstance(battery_capacity_wh, bool) or battery_capacity_wh <= 0:
        raise WasteError("battery_capacity_wh must be a positive int")
    receipt = BatteryPassportReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        battery_id=_check_nonempty_str(battery_id, "battery_id"),
        battery_capacity_wh=battery_capacity_wh,
        passport_digest=_check_hex64(passport_digest, "passport_digest"),
        recovery_plan_digest=_check_hex64(recovery_plan_digest, "recovery_plan_digest"),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise WasteError("expires_at must be after issued_at")
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class BatteryPassportLog:
    """Hash-chained log of battery-passport pins."""

    def __init__(self) -> None:
        self._log: list[BatteryPassportReceipt] = []

    def append(self, receipt: BatteryPassportReceipt) -> BatteryPassportReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise WasteError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_battery(self, battery_id: str) -> BatteryPassportReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.battery_id, battery_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "battery-passport")


def check_battery_decommission(
    *,
    log: BatteryPassportLog,
    battery_id: str,
    battery_capacity_wh: int,
    now: int,
) -> WasteVerdict:
    """Check that a battery retirement pins its battery passport.

    Batteries >2kWh without a pinned passport are
    ``waste.no_battery_passport`` — the 2026-01-01 serial rule
    as a mechanism.
    """
    now = _check_ts(now, "now")
    if not isinstance(battery_capacity_wh, int) or isinstance(battery_capacity_wh, bool) or battery_capacity_wh <= 0:
        raise WasteError("battery_capacity_wh must be a positive int")
    receipt = log.latest_for_battery(battery_id)
    if receipt is None:
        if battery_capacity_wh > BATTERY_PASSPORT_THRESHOLD_WH:
            return _deny(
                DENY_NO_BATTERY_PASSPORT,
                f"battery {battery_id!r} ({battery_capacity_wh}Wh > "
                f"{BATTERY_PASSPORT_THRESHOLD_WH}Wh): no battery-passport pin",
            )
        return _allow(
            f"battery {battery_id!r} ({battery_capacity_wh}Wh): below passport threshold",
        )
    if receipt.expires_at <= now:
        return _deny(
            DENY_NO_BATTERY_PASSPORT,
            f"battery {battery_id!r}: passport pin {receipt.receipt_id!r} expired",
        )
    return _allow(
        f"battery {battery_id!r}: passport pinned, recovery plan bound",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Claim evidence chains (offset claims unlawful by default)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClaimEvidenceReceipt:
    """A recycled-content claim with a bound evidence chain.

    An offset-based "carbon neutral" claim is unlawful by
    default — the EU Empowering Consumers Directive (enforced
    2026-09-27) and the Volvic/Danone ruling as a mechanism.
    """

    receipt_id: str
    claim_id: str
    claim_text: str
    evidence_tiers: tuple[str, ...]
    evidence_digest: str
    offset_based: bool
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = WASTE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "claim_text": self.claim_text,
            "evidence_tiers": list(self.evidence_tiers),
            "evidence_digest": self.evidence_digest,
            "offset_based": self.offset_based,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


#: Evidence tiers that make a claim authoritative on their own.
CLAIM_AUTHORITATIVE_TIERS = frozenset(
    {"sensor_bound", "watermark_bound", "sensor_and_watermark", "third_party_cert"}
)


def claim_evidence_chain(
    *,
    receipt_id: str,
    claim_id: str,
    claim_text: str,
    evidence_tiers: tuple[str, ...],
    evidence_digest: str,
    offset_based: bool,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> ClaimEvidenceReceipt:
    """Bind a recycled-content claim to its evidence chain.

    Offset-based claims raise :class:`WasteError` at issuance —
    unlawful by default under the Empowering Consumers
    Directive.
    """
    if offset_based:
        raise WasteError("offset-based claims are unlawful by default (waste.offset_claim)")
    receipt = ClaimEvidenceReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        claim_id=_check_nonempty_str(claim_id, "claim_id"),
        claim_text=_check_nonempty_str(claim_text, "claim_text"),
        evidence_tiers=tuple(evidence_tiers),
        evidence_digest=_check_hex64(evidence_digest, "evidence_digest"),
        offset_based=bool(offset_based),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise WasteError("expires_at must be after issued_at")
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class ClaimEvidenceLog:
    """Hash-chained log of claim-evidence receipts."""

    def __init__(self) -> None:
        self._log: list[ClaimEvidenceReceipt] = []

    def append(self, receipt: ClaimEvidenceReceipt) -> ClaimEvidenceReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise WasteError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_claim(self, claim_id: str) -> ClaimEvidenceReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.claim_id, claim_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "claim-evidence")


def check_claim_evidence(
    *,
    log: ClaimEvidenceLog,
    claim_id: str,
    now: int,
) -> WasteVerdict:
    """Check that a claim binds a real evidence chain.

    No bound evidence is ``waste.no_evidence`` — the SB 343
    "Truth in Recycling" lesson as a mechanism.
    """
    now = _check_ts(now, "now")
    receipt = log.latest_for_claim(claim_id)
    if receipt is None:
        return _deny(
            DENY_NO_EVIDENCE,
            f"claim {claim_id!r}: no bound evidence chain",
        )
    if receipt.expires_at <= now:
        return _deny(
            DENY_NO_EVIDENCE,
            f"claim {claim_id!r}: evidence receipt {receipt.receipt_id!r} expired",
        )
    tiers = set(receipt.evidence_tiers)
    if not tiers:
        return _deny(
            DENY_NO_EVIDENCE,
            f"claim {claim_id!r}: empty evidence chain",
        )
    if tiers <= {"self_declared"}:
        return _deny(
            DENY_NO_EVIDENCE,
            f"claim {claim_id!r}: self-declared evidence only",
        )
    if not (tiers & CLAIM_AUTHORITATIVE_TIERS):
        return _deny(
            DENY_NO_EVIDENCE,
            f"claim {claim_id!r}: no authoritative evidence tier bound",
        )
    return _allow(
        f"claim {claim_id!r}: evidence chain bound ({sorted(tiers)})",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Informal-sector transition plans
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransitionReceipt:
    """A transition plan for workers displaced by waste automation."""

    receipt_id: str
    facility_id: str
    pickers_displaced: int
    transition_plan_digest: str
    plan_summary: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = WASTE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "facility_id": self.facility_id,
            "pickers_displaced": self.pickers_displaced,
            "transition_plan_digest": self.transition_plan_digest,
            "plan_summary": self.plan_summary,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def informal_sector_transition(
    *,
    receipt_id: str,
    facility_id: str,
    pickers_displaced: int,
    transition_plan_digest: str,
    plan_summary: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> TransitionReceipt:
    """Publish a transition plan for displaced informal pickers.

    The WIEGO lesson: formalization must not expel the
    marginal — a published, bound plan is the checkable
    minimum.
    """
    if not isinstance(pickers_displaced, int) or isinstance(pickers_displaced, bool) or pickers_displaced < 0:
        raise WasteError("pickers_displaced must be a non-negative int")
    receipt = TransitionReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        facility_id=_check_nonempty_str(facility_id, "facility_id"),
        pickers_displaced=pickers_displaced,
        transition_plan_digest=_check_hex64(transition_plan_digest, "transition_plan_digest"),
        plan_summary=_check_nonempty_str(plan_summary, "plan_summary"),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise WasteError("expires_at must be after issued_at")
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class TransitionLog:
    """Hash-chained log of transition-plan receipts."""

    def __init__(self) -> None:
        self._log: list[TransitionReceipt] = []

    def append(self, receipt: TransitionReceipt) -> TransitionReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise WasteError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_facility(self, facility_id: str) -> TransitionReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.facility_id, facility_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "transition")


def check_transition_plan(
    *,
    log: TransitionLog,
    facility_id: str,
    pickers_displaced: int,
    now: int,
) -> WasteVerdict:
    """Check that displacing automation carries a transition plan.

    Automation displacing pickers with no published plan is
    ``waste.no_transition_plan``.
    """
    now = _check_ts(now, "now")
    if not isinstance(pickers_displaced, int) or isinstance(pickers_displaced, bool) or pickers_displaced < 0:
        raise WasteError("pickers_displaced must be a non-negative int")
    if pickers_displaced == 0:
        return _allow(
            f"facility {facility_id!r}: no pickers displaced, no transition plan required",
        )
    receipt = log.latest_for_facility(facility_id)
    if receipt is None:
        return _deny(
            DENY_NO_TRANSITION_PLAN,
            f"facility {facility_id!r}: displaces {pickers_displaced} pickers "
            "with no published transition plan",
        )
    if receipt.expires_at <= now:
        return _deny(
            DENY_NO_TRANSITION_PLAN,
            f"facility {facility_id!r}: transition plan {receipt.receipt_id!r} expired",
        )
    if receipt.pickers_displaced < pickers_displaced:
        return _deny(
            DENY_NO_TRANSITION_PLAN,
            f"facility {facility_id!r}: plan covers {receipt.pickers_displaced} pickers "
            f"but {pickers_displaced} are displaced",
        )
    return _allow(
        f"facility {facility_id!r}: transition plan bound for "
        f"{receipt.pickers_displaced} displaced pickers",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# AI hardware lifecycle
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HardwareLifecycleReceipt:
    """An AI workload's hardware end-of-life disposal declaration."""

    receipt_id: str
    workload_id: str
    hardware_units: int
    disposal_plan_digest: str
    env_ledger_receipt_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = WASTE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "workload_id": self.workload_id,
            "hardware_units": self.hardware_units,
            "disposal_plan_digest": self.disposal_plan_digest,
            "env_ledger_receipt_digest": self.env_ledger_receipt_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def ai_hardware_lifecycle(
    *,
    receipt_id: str,
    workload_id: str,
    hardware_units: int,
    disposal_plan_digest: str,
    env_ledger_receipt_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> HardwareLifecycleReceipt:
    """Declare hardware end-of-life disposal for an AI workload.

    The disposal binds to the 115th-batch ``env_cost`` ledger
    receipt — the 617Mt warning as a checkable minimum.
    """
    if not isinstance(hardware_units, int) or isinstance(hardware_units, bool) or hardware_units <= 0:
        raise WasteError("hardware_units must be a positive int")
    receipt = HardwareLifecycleReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        workload_id=_check_nonempty_str(workload_id, "workload_id"),
        hardware_units=hardware_units,
        disposal_plan_digest=_check_hex64(disposal_plan_digest, "disposal_plan_digest"),
        env_ledger_receipt_digest=_check_hex64(
            env_ledger_receipt_digest, "env_ledger_receipt_digest"
        ),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise WasteError("expires_at must be after issued_at")
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class HardwareLifecycleLog:
    """Hash-chained log of hardware-lifecycle receipts."""

    def __init__(self) -> None:
        self._log: list[HardwareLifecycleReceipt] = []

    def append(self, receipt: HardwareLifecycleReceipt) -> HardwareLifecycleReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise WasteError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_workload(self, workload_id: str) -> HardwareLifecycleReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.workload_id, workload_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "hardware-lifecycle")


def check_hardware_lifecycle(
    *,
    log: HardwareLifecycleLog,
    workload_id: str,
    now: int,
) -> WasteVerdict:
    """Check that an AI workload declares hardware disposal.

    Undeclared hardware is ``waste.unrouted_hardware``.
    """
    now = _check_ts(now, "now")
    receipt = log.latest_for_workload(workload_id)
    if receipt is None:
        return _deny(
            DENY_UNROUTED_HARDWARE,
            f"workload {workload_id!r}: no hardware end-of-life disposal declared",
        )
    if receipt.expires_at <= now:
        return _deny(
            DENY_UNROUTED_HARDWARE,
            f"workload {workload_id!r}: lifecycle receipt {receipt.receipt_id!r} expired",
        )
    return _allow(
        f"workload {workload_id!r}: {receipt.hardware_units} units bound to "
        "disposal plan + env_cost ledger",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Dumping-alert bindings (leads, never auto-fines)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DumpingAlert:
    """An illegal-dumping AI alert with bound image + human verification.

    An alert without human verification is a *lead*, never an
    auto-fine — the Aerbits lesson as a mechanism.
    """

    receipt_id: str
    alert_id: str
    channel: str
    image_digest: str
    location_id: str
    human_verification_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = WASTE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "alert_id": self.alert_id,
            "channel": self.channel,
            "image_digest": self.image_digest,
            "location_id": self.location_id,
            "human_verification_digest": self.human_verification_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def dumping_alert_binding(
    *,
    receipt_id: str,
    alert_id: str,
    channel: str,
    image_digest: str,
    location_id: str,
    human_verification_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> DumpingAlert:
    """Bind an illegal-dumping alert to image evidence.

    ``human_verification_digest`` may be an empty string when
    the alert is issued unverified — the alert is then only a
    lead. A human verification binds by re-sealing the alert.
    """
    if channel not in ALERT_CHANNELS:
        raise WasteError(f"channel must be one of {ALERT_CHANNELS}")
    receipt = DumpingAlert(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        alert_id=_check_nonempty_str(alert_id, "alert_id"),
        channel=channel,
        image_digest=_check_hex64(image_digest, "image_digest"),
        location_id=_check_nonempty_str(location_id, "location_id"),
        human_verification_digest=human_verification_digest or "",
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise WasteError("expires_at must be after issued_at")
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class DumpingAlertLog:
    """Hash-chained log of dumping alerts."""

    def __init__(self) -> None:
        self._log: list[DumpingAlert] = []

    def append(self, receipt: DumpingAlert) -> DumpingAlert:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise WasteError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_alert(self, alert_id: str) -> DumpingAlert | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.alert_id, alert_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "dumping-alert")


def check_dumping_alert(
    *,
    log: DumpingAlertLog,
    alert_id: str,
    now: int,
) -> WasteVerdict:
    """Check an illegal-dumping alert's verification state.

    An unverified alert is only a lead — ``waste.unverified_alert``
    (NON_AUTHORITATIVE). Fines require the human-verification
    binding; this function never authorizes one.
    """
    now = _check_ts(now, "now")
    receipt = log.latest_for_alert(alert_id)
    if receipt is None:
        return _deny(
            DENY_UNVERIFIED_ALERT,
            f"alert {alert_id!r}: no bound alert evidence",
        )
    if receipt.expires_at <= now:
        return _deny(
            DENY_UNVERIFIED_ALERT,
            f"alert {alert_id!r}: alert evidence expired",
        )
    if not receipt.human_verification_digest:
        return _deny(
            DENY_UNVERIFIED_ALERT,
            f"alert {alert_id!r}: image bound but no human verification — lead only",
        )
    return _allow(
        f"alert {alert_id!r}: image bound + human verified; dispatch review",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Battery fire triage
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FireTriageReceipt:
    """A fire-risk triage receipt for batteries entering a shredder."""

    receipt_id: str
    battery_id: str
    triage_grade: str
    triage_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = WASTE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "battery_id": self.battery_id,
            "triage_grade": self.triage_grade,
            "triage_digest": self.triage_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


#: Closed triage grades. ``high`` never enters the shredder.
TRIAGE_GRADES: tuple[str, ...] = ("low", "medium", "high")


def battery_fire_triage(
    *,
    receipt_id: str,
    battery_id: str,
    triage_grade: str,
    triage_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> FireTriageReceipt:
    """Issue a fire-risk triage receipt for a battery entering a shredder."""
    if triage_grade not in TRIAGE_GRADES:
        raise WasteError(f"triage_grade must be one of {TRIAGE_GRADES}")
    receipt = FireTriageReceipt(
        receipt_id=_check_nonempty_str(receipt_id, "receipt_id"),
        battery_id=_check_nonempty_str(battery_id, "battery_id"),
        triage_grade=triage_grade,
        triage_digest=_check_hex64(triage_digest, "triage_digest"),
        issued_by=_check_nonempty_str(issued_by, "issued_by"),
        authority_pubkey_hex=_check_hex64(authority_pubkey_hex, "authority_pubkey_hex"),
        signature_hex="00" * 128,
        issued_at=_check_ts(issued_at, "issued_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        prev_digest=_check_nonempty_str(prev_digest, "prev_digest"),
    )
    if receipt.expires_at <= receipt.issued_at:
        raise WasteError("expires_at must be after issued_at")
    return _seal(receipt, receipt._payload(), _check_secret(authority_secret, "authority_secret"))


class FireTriageLog:
    """Hash-chained log of fire-triage receipts."""

    def __init__(self) -> None:
        self._log: list[FireTriageReceipt] = []

    def append(self, receipt: FireTriageReceipt) -> FireTriageReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise WasteError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        self._log.append(receipt)
        return receipt

    def latest_for_battery(self, battery_id: str) -> FireTriageReceipt | None:
        for receipt in reversed(self._log):
            if hmac.compare_digest(receipt.battery_id, battery_id):
                return receipt
        return None

    def verify(self) -> None:
        _check_chain(self._log, "fire-triage")


def check_fire_triage(
    *,
    log: FireTriageLog,
    battery_id: str,
    now: int,
) -> WasteVerdict:
    """Check that a battery passed fire triage before shredding.

    Missing triage is ``waste.no_fire_triage``; a ``high``
    grade never enters the shredder.
    """
    now = _check_ts(now, "now")
    receipt = log.latest_for_battery(battery_id)
    if receipt is None:
        return _deny(
            DENY_NO_FIRE_TRIAGE,
            f"battery {battery_id!r}: no fire-triage receipt before shredding",
        )
    if receipt.expires_at <= now:
        return _deny(
            DENY_NO_FIRE_TRIAGE,
            f"battery {battery_id!r}: triage receipt {receipt.receipt_id!r} expired",
        )
    if receipt.triage_grade == "high":
        return _deny(
            DENY_NO_FIRE_TRIAGE,
            f"battery {battery_id!r}: triage grade high — must not enter the shredder",
        )
    return _allow(
        f"battery {battery_id!r}: triage grade {receipt.triage_grade} — cleared for shredder",
        receipt.receipt_digest,
    )
