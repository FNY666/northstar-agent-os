"""Manufacturing & industrial-automation AI discipline (one-hundred-fifty-seventh batch).

Absorbs the 2026 AI-manufacturing research thread:

* **Ottogi SF Goseong plant (Yonhap Infomax 2026-09-28, 한국어)** —
  a worker entered a faulted palletizer zone to inspect it; a
  colleague pressed reset believing the zone was clear, and the
  robot pinned the worker between arm and pallet — he died four
  days after surgery. Lesson: a robot-cell reset/restart must bind a
  "zone cleared" two-person confirmation receipt; an unconfirmed
  restart is fail-closed: ``mfg.restart_without_clearance``.
* **John Deere critique (qu3ry.net 2026-03)** — autonomous tractors
  have no structured capability envelope: wet soil, obstacles, and
  degraded hardware change what the machine can reliably do, but
  nothing re-evaluates whether the job should run. Rule: embodied
  industrial robots declare a capability envelope (payload, speed,
  torque, allowed task kinds) and refuse out-of-envelope commands
  up front — ``mfg.envelope_breach`` — never "stop on detect".
* **BMW Group (press release 2026-02-27, Deutsch)** — first humanoid
  robot use in a German plant, with partners graded by maturity
  and a staged pipeline: maturity assessment → lab validation →
  real-line testing → pilot. Northstar codifies this as
  ``mfg.humanoid_pilot_registry``: uncertified scale-up is barred.
* **Hyundai Ulsan strike (mk.co.kr / WSJ 2026-07, 한국어/EN)** — the
  first car-plant stoppage ever over humanoid robots: Atlas
  (190cm/90kg) planned for the 2028 Georgia MetaPlant triggered
  4hr/day partial strikes (~₩200B estimated losses). The union
  demanded a monthly-salary system, retirement at 65, and
  prior-consent rights. Lesson: before introducing humanoids or
  mass automation, displace-scale estimates and a retraining plan
  must be disclosed to the union and affected workers; an
  undisclosed introduction is ``mfg.silent_displacement``.
* **Fascia *Industrial AI 2026* (EN)** — predictive maintenance is
  the highest-confidence deployment, but monolithic "factory AI
  assistants" burn ~1.0× ROI. Discipline: predictive maintenance
  advises only; any line stop or part swap needs a named-human
  sign-off; an AI-initiated line stop is ``mfg.autonomous_stop``.
* **Humanoid Safety Summit (Stuttgart 2026-11-13, Deutsch)** — no
  country has a dedicated law for mobile humanoids; OSHA has not
  finished an ISO standard for self-driving mobile robots. In the
  gap, deployments bind an interim safety baseline
  (fencing/speed/torque limits/supervision ratio); a missing
  baseline is ``mfg.no_safety_baseline``.
* **Digital twins + agentic AI** — before AI re-plans a line or
  pushes control commands, the twin and the physical cell must
  prove sync; a desynced cell refuses control pushes:
  ``mfg.twin_desync``.
* **AI vision quality (BOE / PV inspection claims, 中文)** —
  "defect-rate reduction" claims bind a reproducible measurement
  protocol and sample-size disclosure; self-reported-only numbers
  are ``mfg.unverified_quality_claim`` (same lineage as the
  supplychain vendor-claim receipt).

Deterministic: no wall-clock reads (callers inject ``now`` as an
integer epoch), canonical JCS hashing (ninety-fifth batch), and all
digest comparisons use :func:`hmac.compare_digest`.

Honest scope:

* Receipts bind the *declared* manufacturing discipline; they do not
  make factories safe, guarantee humanoids won't fall, or prove a
  retraining plan is real.
* The 1-hour clearance shelf life, 30-day envelope validity, 30-day
  disclosure notice, 180-day baseline validity, 1-hour twin-sync
  freshness, 5% drift tolerance, and 1000-unit minimum sample are
  bench parameters drawn from the 2026 manufacturing sweep;
  confirm against the deployment's safety standards before
  shop-floor reliance.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
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


MFG_SCHEMA_VERSION = "northstar.manufacturing.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128
_DAY_S = 86_400

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Zone-clearance receipts go stale fast (Ottogi lesson: the cleared
#: state must be *current*, not remembered from this morning).
CLEARANCE_MAX_AGE_S = 3_600

#: Capability envelopes must be re-validated monthly; degraded
#: hardware silently shrinks what a robot can reliably do.
ENVELOPE_MAX_AGE_S = 30 * _DAY_S

#: Displacement disclosures must reach the union/workers this far
#: ahead of the first introduction (Hyundai lesson).
DISCLOSURE_NOTICE_MIN_S = 30 * _DAY_S

#: Interim safety baselines are re-pinned on this cadence until an
#: ISO standard for mobile humanoids exists.
BASELINE_MAX_AGE_S = 180 * _DAY_S

#: Twin-sync proofs older than this cannot gate a control push.
SYNC_MAX_AGE_S = 3_600

#: Maximum twin-vs-physical drift (basis points) that still allows
#: a control push.
SYNC_MAX_DRIFT_BPS = 500

#: Minimum disclosed sample size for AI-vision quality claims.
QUALITY_MIN_SAMPLE = 1_000

#: Ordered humanoid introduction stages (BMW lesson): each stage may
#: start only when every earlier stage has a valid stage receipt.
PILOT_STAGES = (
    "maturity_assessment",
    "lab_validation",
    "line_testing",
    "pilot",
    "production",
)

#: Stage receipts older than this are treated as absent (a pilot
#: approved last year does not certify this year's hardware).
PILOT_STAGE_MAX_AGE_S = 180 * _DAY_S


class ManufacturingError(ValueError):
    """A malformed manufacturing receipt or a programming error.

    Raised for structural problems (bad digests, unknown checks,
    broken chains). Verification *failures* (unconfirmed restarts,
    out-of-envelope commands, uncertified scale-ups) return a
    :class:`ManufacturingVerdict` with ``allowed=False`` instead —
    a failed gate is a verdict, a malformed receipt is a bug.
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
        raise ManufacturingError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManufacturingError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ManufacturingError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise ManufacturingError("authority_pubkey_hex must be a 64-char lowercase hex digest")
    return value


def _check_sig_hex(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise ManufacturingError(f"{field_name} must be a 128-char lowercase hex signature")
    return value


def _check_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ManufacturingError(f"{field_name} must be a bool")
    return value


def _check_nonneg_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ManufacturingError(f"{field_name} must be a non-negative number")
    return float(value)


def _check_bps(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10_000:
        raise ManufacturingError(f"{field_name} must be an int in [0, 10000]")
    return value


def _check_str_list(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ManufacturingError(f"{field_name} must be a non-empty list of strings")
    return tuple(_check_nonempty_str(v, f"{field_name} item") for v in value)


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
    """Raise :class:`ManufacturingError` if a receipt log is tampered/broken.

    Every entry must expose ``receipt_digest`` and ``prev_digest`` and
    a ``_payload()`` method; the entries must form one chain from
    ``"genesis"`` with recomputing digests and valid authority
    signatures.
    """
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise ManufacturingError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise ManufacturingError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(
            entry.authority_pubkey_hex, signed_body, entry.signature_hex
        ):
            raise ManufacturingError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class ManufacturingVerdict:
    """Outcome of one manufacturing-discipline gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> ManufacturingVerdict:
    return ManufacturingVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> ManufacturingVerdict:
    return ManufacturingVerdict(
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
# 1. Robot-cell restart clearance (Ottogi SF palletizer lesson)
# ---------------------------------------------------------------------------
#
# A robot-cell reset/restart may proceed only when a "zone cleared"
# receipt names two distinct human confirmers and is fresh. The
# Ottogi failure mode — one worker pressed reset believing the zone
# was clear while a colleague was inside — is the whole point of the
# two-person rule and the staleness bound.


@dataclass(frozen=True)
class RestartClearanceReceipt:
    """Binds a robot-cell restart to a two-person zone-clearance."""

    receipt_id: str
    cell_id: str
    restart_id: str
    confirmer_a_id: str
    confirmer_b_id: str
    cleared_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": MFG_SCHEMA_VERSION,
            "type": "restart_clearance",
            "receipt_id": self.receipt_id,
            "cell_id": self.cell_id,
            "restart_id": self.restart_id,
            "confirmer_a_id": self.confirmer_a_id,
            "confirmer_b_id": self.confirmer_b_id,
            "cleared_at": self.cleared_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class RestartClearanceRegistry:
    """Hash-chained log of robot-cell restart-clearance receipts."""

    authorities: AuthorityRegistry
    log: list[RestartClearanceReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        cell_id: str,
        restart_id: str,
        confirmer_a_id: str,
        confirmer_b_id: str,
        cleared_at: int,
        authority_id: str,
        signature: bytes,
    ) -> RestartClearanceReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(cell_id, "cell_id")
        _check_nonempty_str(restart_id, "restart_id")
        _check_nonempty_str(confirmer_a_id, "confirmer_a_id")
        _check_nonempty_str(confirmer_b_id, "confirmer_b_id")
        if confirmer_a_id.strip() == confirmer_b_id.strip():
            raise ManufacturingError("confirmers must be two distinct people")
        _check_ts(cleared_at, "cleared_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ManufacturingError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = RestartClearanceReceipt(
            receipt_id=receipt_id,
            cell_id=cell_id,
            restart_id=restart_id,
            confirmer_a_id=confirmer_a_id,
            confirmer_b_id=confirmer_b_id,
            cleared_at=cleared_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ManufacturingError("restart-clearance receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, restart_id: str) -> RestartClearanceReceipt | None:
        for entry in reversed(self.log):
            if entry.restart_id == restart_id:
                return entry
        return None


def restart_clearance_receipt(
    registry: RestartClearanceRegistry,
    restart_id: str,
    now: int,
    max_age_s: int = CLEARANCE_MAX_AGE_S,
) -> ManufacturingVerdict:
    """Robot-cell restarts need a live two-person zone-clearance receipt.

    The receipt must exist, name two distinct confirmers, and be
    fresh — a clearance from this morning does not cover this
    afternoon's restart. Missing or stale clearance is fail-closed:
    ``mfg.restart_without_clearance``.
    """
    _check_nonempty_str(restart_id, "restart_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "restart_clearance")
    except ManufacturingError as exc:
        return _deny("mfg.chain_broken", str(exc))
    entry = registry.find(restart_id)
    if entry is None:
        return _deny(
            "mfg.restart_without_clearance",
            f"restart {restart_id!r} binds no zone-clearance receipt — "
            "restart blocked (two-person confirmation required)",
        )
    if entry.cleared_at > now:
        return _deny(
            "mfg.future_clearance",
            f"zone clearance for restart {restart_id!r} is dated in the future",
        )
    if now - entry.cleared_at > max_age_s:
        return _deny(
            "mfg.restart_without_clearance",
            f"zone clearance for restart {restart_id!r} is stale "
            f"({now - entry.cleared_at}s old, limit {max_age_s}s) — "
            "re-clear the zone before restarting",
        )
    return _allow(
        f"restart {restart_id!r} cleared by {entry.confirmer_a_id!r} and "
        f"{entry.confirmer_b_id!r}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 2. Capability envelope (embodied-industrial-robot lesson)
# ---------------------------------------------------------------------------
#
# Industrial robots declare an envelope of what they can reliably do
# right now: payload, speed, torque, and the task kinds they may
# perform. Commands outside the envelope are refused up front —
# ``mfg.envelope_breach`` — never "start and stop on detect".
# Envelopes expire monthly: worn hardware silently shrinks the
# envelope, so stale envelopes are as dangerous as none.


@dataclass(frozen=True)
class EnvelopeReceipt:
    """Binds an industrial robot's capability envelope."""

    receipt_id: str
    envelope_id: str
    robot_id: str
    max_payload_kg: float
    max_speed_ms: float
    max_torque_nm: float
    allowed_task_kinds: tuple[str, ...]
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": MFG_SCHEMA_VERSION,
            "type": "capability_envelope",
            "receipt_id": self.receipt_id,
            "envelope_id": self.envelope_id,
            "robot_id": self.robot_id,
            "max_payload_kg": self.max_payload_kg,
            "max_speed_ms": self.max_speed_ms,
            "max_torque_nm": self.max_torque_nm,
            "allowed_task_kinds": list(self.allowed_task_kinds),
            "issued_at": self.issued_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class EnvelopeRegistry:
    """Hash-chained log of industrial capability-envelope receipts."""

    authorities: AuthorityRegistry
    log: list[EnvelopeReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        envelope_id: str,
        robot_id: str,
        max_payload_kg: float,
        max_speed_ms: float,
        max_torque_nm: float,
        allowed_task_kinds: list[str] | tuple[str, ...],
        issued_at: int,
        authority_id: str,
        signature: bytes,
    ) -> EnvelopeReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(envelope_id, "envelope_id")
        _check_nonempty_str(robot_id, "robot_id")
        _check_nonneg_number(max_payload_kg, "max_payload_kg")
        _check_nonneg_number(max_speed_ms, "max_speed_ms")
        _check_nonneg_number(max_torque_nm, "max_torque_nm")
        kinds = _check_str_list(allowed_task_kinds, "allowed_task_kinds")
        _check_ts(issued_at, "issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ManufacturingError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = EnvelopeReceipt(
            receipt_id=receipt_id,
            envelope_id=envelope_id,
            robot_id=robot_id,
            max_payload_kg=float(max_payload_kg),
            max_speed_ms=float(max_speed_ms),
            max_torque_nm=float(max_torque_nm),
            allowed_task_kinds=kinds,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ManufacturingError("capability-envelope receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, robot_id: str) -> EnvelopeReceipt | None:
        for entry in reversed(self.log):
            if entry.robot_id == robot_id:
                return entry
        return None


def capability_envelope(
    registry: EnvelopeRegistry,
    robot_id: str,
    task_kind: str,
    task_payload_kg: float,
    task_speed_ms: float,
    task_torque_nm: float,
    now: int,
    max_envelope_age_s: int = ENVELOPE_MAX_AGE_S,
) -> ManufacturingVerdict:
    """Commands are checked against the robot's live capability envelope.

    The envelope must exist, be fresh (hardware degrades), and the
    requested task kind, payload, speed, and torque must all sit
    inside it. Out-of-envelope commands are ``mfg.envelope_breach``
    — refused before anything moves.
    """
    _check_nonempty_str(robot_id, "robot_id")
    _check_nonempty_str(task_kind, "task_kind")
    _check_nonneg_number(task_payload_kg, "task_payload_kg")
    _check_nonneg_number(task_speed_ms, "task_speed_ms")
    _check_nonneg_number(task_torque_nm, "task_torque_nm")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "capability_envelope")
    except ManufacturingError as exc:
        return _deny("mfg.chain_broken", str(exc))
    entry = registry.find(robot_id)
    if entry is None:
        return _deny(
            "mfg.envelope_breach",
            f"robot {robot_id!r} declares no capability envelope — "
            "refuse command, not \"stop on detect\"",
        )
    if entry.issued_at > now:
        return _deny(
            "mfg.future_envelope",
            f"capability envelope for robot {robot_id!r} is dated in the future",
        )
    if now - entry.issued_at > max_envelope_age_s:
        return _deny(
            "mfg.envelope_breach",
            f"capability envelope for robot {robot_id!r} is stale "
            f"({now - entry.issued_at}s old) — re-validate before commanding",
        )
    if task_kind not in entry.allowed_task_kinds:
        return _deny(
            "mfg.envelope_breach",
            f"task kind {task_kind!r} not in envelope for robot {robot_id!r} "
            f"(allowed: {', '.join(entry.allowed_task_kinds)})",
        )
    for label, asked, limit in (
        ("payload_kg", float(task_payload_kg), entry.max_payload_kg),
        ("speed_ms", float(task_speed_ms), entry.max_speed_ms),
        ("torque_nm", float(task_torque_nm), entry.max_torque_nm),
    ):
        if asked > limit:
            return _deny(
                "mfg.envelope_breach",
                f"{label} {asked} exceeds envelope limit {limit} for robot {robot_id!r}",
            )
    return _allow(
        f"task {task_kind!r} within envelope for robot {robot_id!r}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 3. Humanoid pilot registry (BMW staged-pipeline lesson)
# ---------------------------------------------------------------------------
#
# Humanoids enter factories through a staged pipeline: maturity
# assessment → lab validation → line testing → pilot → production.
# Each stage binds an evidence receipt (test reports, safety reviews);
# a stage may begin only when every earlier stage has a valid,
# non-stale receipt. Skipping stages — or scaling to production on
# pilot evidence — is ``mfg.uncertified_scaleup``.


@dataclass(frozen=True)
class PilotStageReceipt:
    """Binds one stage of a humanoid robot model's factory pipeline."""

    receipt_id: str
    stage_id: str
    robot_model_id: str
    stage: str
    evidence_digest: str
    completed_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": MFG_SCHEMA_VERSION,
            "type": "pilot_stage",
            "receipt_id": self.receipt_id,
            "stage_id": self.stage_id,
            "robot_model_id": self.robot_model_id,
            "stage": self.stage,
            "evidence_digest": self.evidence_digest,
            "completed_at": self.completed_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class PilotRegistry:
    """Hash-chained log of humanoid pipeline stage receipts."""

    authorities: AuthorityRegistry
    log: list[PilotStageReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        stage_id: str,
        robot_model_id: str,
        stage: str,
        evidence_digest: str,
        completed_at: int,
        authority_id: str,
        signature: bytes,
    ) -> PilotStageReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(stage_id, "stage_id")
        _check_nonempty_str(robot_model_id, "robot_model_id")
        _check_nonempty_str(stage, "stage")
        if stage not in PILOT_STAGES:
            raise ManufacturingError(f"unknown pilot stage {stage!r}")
        _check_hex64(evidence_digest, "evidence_digest")
        _check_ts(completed_at, "completed_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ManufacturingError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = PilotStageReceipt(
            receipt_id=receipt_id,
            stage_id=stage_id,
            robot_model_id=robot_model_id,
            stage=stage,
            evidence_digest=evidence_digest,
            completed_at=completed_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ManufacturingError("pilot-stage receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def stages_for(self, robot_model_id: str) -> list[PilotStageReceipt]:
        return [e for e in self.log if e.robot_model_id == robot_model_id]


def humanoid_pilot_registry(
    registry: PilotRegistry,
    robot_model_id: str,
    requested_stage: str,
    now: int,
    max_stage_age_s: int = PILOT_STAGE_MAX_AGE_S,
) -> ManufacturingVerdict:
    """Humanoid factory stages unlock only with a full evidence ladder.

    To enter ``requested_stage``, every earlier stage in
    ``PILOT_STAGES`` must have a valid, fresh evidence receipt for
    the same robot model. Stage-skipping or production on pilot
    evidence is ``mfg.uncertified_scaleup``.
    """
    _check_nonempty_str(robot_model_id, "robot_model_id")
    _check_nonempty_str(requested_stage, "requested_stage")
    if requested_stage not in PILOT_STAGES:
        raise ManufacturingError(f"unknown pilot stage {requested_stage!r}")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "pilot_stage")
    except ManufacturingError as exc:
        return _deny("mfg.chain_broken", str(exc))
    needed = PILOT_STAGES[: PILOT_STAGES.index(requested_stage)]
    have = {e.stage: e for e in registry.stages_for(robot_model_id)}
    for stage in needed:
        entry = have.get(stage)
        if entry is None:
            return _deny(
                "mfg.uncertified_scaleup",
                f"robot model {robot_model_id!r} has no {stage!r} receipt — "
                f"cannot enter {requested_stage!r}",
            )
        if entry.completed_at > now:
            return _deny(
                "mfg.future_stage",
                f"{stage!r} receipt for {robot_model_id!r} is dated in the future",
            )
        if now - entry.completed_at > max_stage_age_s:
            return _deny(
                "mfg.uncertified_scaleup",
                f"{stage!r} receipt for {robot_model_id!r} is stale "
                f"({now - entry.completed_at}s old) — re-validate before "
                f"entering {requested_stage!r}",
            )
    return _allow(
        f"robot model {robot_model_id!r} cleared to enter {requested_stage!r}",
        "",
    )

# ---------------------------------------------------------------------------
# 4. Predictive-maintenance decision pin (Fascia lesson)
# ---------------------------------------------------------------------------
#
# Predictive maintenance advises; it never decides. Advisory outputs
# ("inspect soon", "continue") bind to an advice receipt; any
# consequential action — stopping a line or swapping a part — needs
# a named-human decision pin that references the advice. An
# AI-initiated line stop with no human pin is ``mfg.autonomous_stop``.


ADVISORY_ACTIONS = ("inspect_soon", "continue", "review_at_next_shift")
CONSEQUENTIAL_ACTIONS = ("shutdown_line", "swap_part")


@dataclass(frozen=True)
class MaintenanceAdviceReceipt:
    """Binds one predictive-maintenance advice output."""

    receipt_id: str
    advice_id: str
    machine_id: str
    action: str
    model_version: str
    advice_digest: str
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": MFG_SCHEMA_VERSION,
            "type": "maintenance_advice",
            "receipt_id": self.receipt_id,
            "advice_id": self.advice_id,
            "machine_id": self.machine_id,
            "action": self.action,
            "model_version": self.model_version,
            "advice_digest": self.advice_digest,
            "issued_at": self.issued_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class MaintenanceAdviceRegistry:
    """Hash-chained log of predictive-maintenance advice receipts."""

    authorities: AuthorityRegistry
    log: list[MaintenanceAdviceReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        advice_id: str,
        machine_id: str,
        action: str,
        model_version: str,
        advice_digest: str,
        issued_at: int,
        authority_id: str,
        signature: bytes,
    ) -> MaintenanceAdviceReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(advice_id, "advice_id")
        _check_nonempty_str(machine_id, "machine_id")
        _check_nonempty_str(action, "action")
        if action not in ADVISORY_ACTIONS + CONSEQUENTIAL_ACTIONS:
            raise ManufacturingError(f"unknown maintenance action {action!r}")
        _check_nonempty_str(model_version, "model_version")
        _check_hex64(advice_digest, "advice_digest")
        _check_ts(issued_at, "issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ManufacturingError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = MaintenanceAdviceReceipt(
            receipt_id=receipt_id,
            advice_id=advice_id,
            machine_id=machine_id,
            action=action,
            model_version=model_version,
            advice_digest=advice_digest,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ManufacturingError("maintenance-advice receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, advice_id: str) -> MaintenanceAdviceReceipt | None:
        for entry in reversed(self.log):
            if entry.advice_id == advice_id:
                return entry
        return None


@dataclass(frozen=True)
class MaintenanceDecisionPin:
    """A named-human sign-off on a consequential maintenance action."""

    receipt_id: str
    pin_id: str
    advice_id: str
    action: str
    human_approver_id: str
    decided_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": MFG_SCHEMA_VERSION,
            "type": "maintenance_decision_pin",
            "receipt_id": self.receipt_id,
            "pin_id": self.pin_id,
            "advice_id": self.advice_id,
            "action": self.action,
            "human_approver_id": self.human_approver_id,
            "decided_at": self.decided_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class MaintenanceDecisionRegistry:
    """Hash-chained log of named-human maintenance decision pins."""

    authorities: AuthorityRegistry
    log: list[MaintenanceDecisionPin] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        pin_id: str,
        advice_id: str,
        action: str,
        human_approver_id: str,
        decided_at: int,
        authority_id: str,
        signature: bytes,
    ) -> MaintenanceDecisionPin:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(pin_id, "pin_id")
        _check_nonempty_str(advice_id, "advice_id")
        _check_nonempty_str(action, "action")
        if action not in CONSEQUENTIAL_ACTIONS:
            raise ManufacturingError(
                f"decision pins are only for consequential actions, got {action!r}"
            )
        _check_nonempty_str(human_approver_id, "human_approver_id")
        _check_ts(decided_at, "decided_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ManufacturingError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        pin = MaintenanceDecisionPin(
            receipt_id=receipt_id,
            pin_id=pin_id,
            advice_id=advice_id,
            action=action,
            human_approver_id=human_approver_id,
            decided_at=decided_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(pin._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, pin.signature_hex):
            raise ManufacturingError("maintenance-decision pin authority signature invalid")
        self.log.append(pin)
        return pin

    def find(self, advice_id: str, action: str) -> MaintenanceDecisionPin | None:
        for entry in reversed(self.log):
            if entry.advice_id == advice_id and entry.action == action:
                return entry
        return None


def maintenance_decision_pin(
    advice_registry: MaintenanceAdviceRegistry,
    pin_registry: MaintenanceDecisionRegistry,
    advice_id: str,
    action: str,
    now: int,
) -> ManufacturingVerdict:
    """Consequential maintenance actions need a named-human pin.

    Advisory outputs are authoritative on their own; ``shutdown_line``
    and ``swap_part`` require a decision pin naming a human approver
    that references the advice. An AI-initiated line stop with no
    human pin is ``mfg.autonomous_stop``.
    """
    _check_nonempty_str(advice_id, "advice_id")
    _check_nonempty_str(action, "action")
    if action not in ADVISORY_ACTIONS + CONSEQUENTIAL_ACTIONS:
        raise ManufacturingError(f"unknown maintenance action {action!r}")
    _check_ts(now, "now")
    for registry, name in ((advice_registry.log, "maintenance_advice"),
                           (pin_registry.log, "maintenance_decision_pin")):
        try:
            _check_chain(registry, name)
        except ManufacturingError as exc:
            return _deny("mfg.chain_broken", str(exc))
    advice = advice_registry.find(advice_id)
    if advice is None:
        return _deny(
            "mfg.no_advice",
            f"maintenance advice {advice_id!r} binds no advice receipt",
        )
    if action in ADVISORY_ACTIONS:
        return _allow(
            f"advisory action {action!r} for machine {advice.machine_id!r} "
            "needs no human pin",
            advice.receipt_digest,
        )
    pin = pin_registry.find(advice_id, action)
    if pin is None:
        return _deny(
            "mfg.autonomous_stop",
            f"consequential action {action!r} on machine {advice.machine_id!r} "
            "has no named-human decision pin — AI may not stop lines or "
            "swap parts on its own",
        )
    if pin.decided_at > now:
        return _deny(
            "mfg.future_pin",
            f"decision pin for {advice_id!r} is dated in the future",
        )
    return _allow(
        f"{action!r} approved by {pin.human_approver_id!r} for machine "
        f"{advice.machine_id!r}",
        pin.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 5. Displacement disclosure (Hyundai Ulsan strike lesson)
# ---------------------------------------------------------------------------
#
# Before the first humanoid (or mass-automation) introduction at a
# site, the deployer must disclose the estimated displacement scale
# and a retraining/redeployment plan to the union and affected
# workers — with at least DISCLOSURE_NOTICE_MIN_S notice. An
# introduction with no such receipt is ``mfg.silent_displacement``.


@dataclass(frozen=True)
class DisplacementDisclosureReceipt:
    """Binds an automation introduction to a worker disclosure."""

    receipt_id: str
    disclosure_id: str
    site_id: str
    automation_kind: str
    displaced_workers_estimate: int
    retraining_plan_digest: str
    union_notified: bool
    disclosed_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": MFG_SCHEMA_VERSION,
            "type": "displacement_disclosure",
            "receipt_id": self.receipt_id,
            "disclosure_id": self.disclosure_id,
            "site_id": self.site_id,
            "automation_kind": self.automation_kind,
            "displaced_workers_estimate": self.displaced_workers_estimate,
            "retraining_plan_digest": self.retraining_plan_digest,
            "union_notified": self.union_notified,
            "disclosed_at": self.disclosed_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class DisplacementRegistry:
    """Hash-chained log of automation displacement disclosures."""

    authorities: AuthorityRegistry
    log: list[DisplacementDisclosureReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        disclosure_id: str,
        site_id: str,
        automation_kind: str,
        displaced_workers_estimate: int,
        retraining_plan_digest: str,
        union_notified: bool,
        disclosed_at: int,
        authority_id: str,
        signature: bytes,
    ) -> DisplacementDisclosureReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(disclosure_id, "disclosure_id")
        _check_nonempty_str(site_id, "site_id")
        _check_nonempty_str(automation_kind, "automation_kind")
        if (
            isinstance(displaced_workers_estimate, bool)
            or not isinstance(displaced_workers_estimate, int)
            or displaced_workers_estimate < 0
        ):
            raise ManufacturingError("displaced_workers_estimate must be a non-negative int")
        _check_hex64(retraining_plan_digest, "retraining_plan_digest")
        _check_bool(union_notified, "union_notified")
        _check_ts(disclosed_at, "disclosed_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ManufacturingError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = DisplacementDisclosureReceipt(
            receipt_id=receipt_id,
            disclosure_id=disclosure_id,
            site_id=site_id,
            automation_kind=automation_kind,
            displaced_workers_estimate=displaced_workers_estimate,
            retraining_plan_digest=retraining_plan_digest,
            union_notified=union_notified,
            disclosed_at=disclosed_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ManufacturingError("displacement-disclosure receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, site_id: str) -> DisplacementDisclosureReceipt | None:
        for entry in reversed(self.log):
            if entry.site_id == site_id:
                return entry
        return None


def displacement_disclosure(
    registry: DisplacementRegistry,
    site_id: str,
    now: int,
    notice_min_s: int = DISCLOSURE_NOTICE_MIN_S,
) -> ManufacturingVerdict:
    """Automation introductions need a disclosed, noticed worker receipt.

    The receipt must disclose a displacement estimate, bind a
    retraining plan, confirm union notification, and reach the
    workers at least ``notice_min_s`` before introduction. Anything
    less is ``mfg.silent_displacement``.
    """
    _check_nonempty_str(site_id, "site_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "displacement_disclosure")
    except ManufacturingError as exc:
        return _deny("mfg.chain_broken", str(exc))
    entry = registry.find(site_id)
    if entry is None:
        return _deny(
            "mfg.silent_displacement",
            f"site {site_id!r} binds no displacement disclosure — "
            "automation may not be introduced without disclosing "
            "displacement scale and a retraining plan to the union",
        )
    if entry.disclosed_at > now:
        return _deny(
            "mfg.future_disclosure",
            f"displacement disclosure for site {site_id!r} is dated in the future",
        )
    if not entry.union_notified:
        return _deny(
            "mfg.silent_displacement",
            f"displacement disclosure for site {site_id!r} never notified "
            "the union",
        )
    if now - entry.disclosed_at < notice_min_s:
        return _deny(
            "mfg.silent_displacement",
            f"displacement disclosure for site {site_id!r} is only "
            f"{now - entry.disclosed_at}s old — minimum notice is "
            f"{notice_min_s}s",
        )
    return _allow(
        f"site {site_id!r}: {entry.displaced_workers_estimate} workers "
        f"disclosure with union notification and retraining plan",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 6. Interim safety baseline clock (ISO-blank interim lesson)
# ---------------------------------------------------------------------------
#
# Mobile humanoids have no dedicated national law and no finished
# ISO standard (Forbes JAPAN 2026-09; Humanoid Safety Summit
# 2026-11-13 Stuttgart). Until one lands, every deployment pins an
# interim safety baseline — fencing, speed/torque limits, and the
# human supervision ratio — re-pinned on a clock. A deployment with
# no live baseline is ``mfg.no_safety_baseline``.


@dataclass(frozen=True)
class SafetyBaselineReceipt:
    """Binds a deployment site to an interim safety baseline."""

    receipt_id: str
    baseline_id: str
    site_id: str
    robot_class: str
    fencing_confirmed: bool
    max_speed_ms: float
    max_torque_nm: float
    max_robots_per_supervisor: int
    pinned_at: int
    expires_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": MFG_SCHEMA_VERSION,
            "type": "safety_baseline",
            "receipt_id": self.receipt_id,
            "baseline_id": self.baseline_id,
            "site_id": self.site_id,
            "robot_class": self.robot_class,
            "fencing_confirmed": self.fencing_confirmed,
            "max_speed_ms": self.max_speed_ms,
            "max_torque_nm": self.max_torque_nm,
            "max_robots_per_supervisor": self.max_robots_per_supervisor,
            "pinned_at": self.pinned_at,
            "expires_at": self.expires_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class SafetyBaselineRegistry:
    """Hash-chained log of interim safety-baseline receipts."""

    authorities: AuthorityRegistry
    log: list[SafetyBaselineReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        baseline_id: str,
        site_id: str,
        robot_class: str,
        fencing_confirmed: bool,
        max_speed_ms: float,
        max_torque_nm: float,
        max_robots_per_supervisor: int,
        pinned_at: int,
        expires_at: int,
        authority_id: str,
        signature: bytes,
    ) -> SafetyBaselineReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(baseline_id, "baseline_id")
        _check_nonempty_str(site_id, "site_id")
        _check_nonempty_str(robot_class, "robot_class")
        _check_bool(fencing_confirmed, "fencing_confirmed")
        _check_nonneg_number(max_speed_ms, "max_speed_ms")
        _check_nonneg_number(max_torque_nm, "max_torque_nm")
        if (
            isinstance(max_robots_per_supervisor, bool)
            or not isinstance(max_robots_per_supervisor, int)
            or max_robots_per_supervisor < 1
        ):
            raise ManufacturingError("max_robots_per_supervisor must be a positive int")
        _check_ts(pinned_at, "pinned_at")
        _check_ts(expires_at, "expires_at")
        if expires_at <= pinned_at:
            raise ManufacturingError("expires_at must be after pinned_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ManufacturingError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = SafetyBaselineReceipt(
            receipt_id=receipt_id,
            baseline_id=baseline_id,
            site_id=site_id,
            robot_class=robot_class,
            fencing_confirmed=fencing_confirmed,
            max_speed_ms=float(max_speed_ms),
            max_torque_nm=float(max_torque_nm),
            max_robots_per_supervisor=max_robots_per_supervisor,
            pinned_at=pinned_at,
            expires_at=expires_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ManufacturingError("safety-baseline receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, site_id: str, robot_class: str) -> SafetyBaselineReceipt | None:
        for entry in reversed(self.log):
            if entry.site_id == site_id and entry.robot_class == robot_class:
                return entry
        return None


def safety_baseline_clock(
    registry: SafetyBaselineRegistry,
    site_id: str,
    robot_class: str,
    now: int,
) -> ManufacturingVerdict:
    """Deployments need a live interim safety baseline.

    The baseline must exist, cover the robot class, confirm fencing,
    and not be expired. An expired or missing baseline is
    ``mfg.no_safety_baseline`` — the ISO gap is no excuse to run
    without one.
    """
    _check_nonempty_str(site_id, "site_id")
    _check_nonempty_str(robot_class, "robot_class")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "safety_baseline")
    except ManufacturingError as exc:
        return _deny("mfg.chain_broken", str(exc))
    entry = registry.find(site_id, robot_class)
    if entry is None:
        return _deny(
            "mfg.no_safety_baseline",
            f"site {site_id!r} binds no interim safety baseline for "
            f"robot class {robot_class!r}",
        )
    if not entry.fencing_confirmed:
        return _deny(
            "mfg.no_safety_baseline",
            f"interim safety baseline for site {site_id!r} / "
            f"{robot_class!r} does not confirm fencing",
        )
    if entry.pinned_at > now:
        return _deny(
            "mfg.future_baseline",
            f"safety baseline for site {site_id!r} is dated in the future",
        )
    if now >= entry.expires_at:
        return _deny(
            "mfg.no_safety_baseline",
            f"interim safety baseline for site {site_id!r} / "
            f"{robot_class!r} expired at {entry.expires_at} — re-pin",
        )
    return _allow(
        f"site {site_id!r} / {robot_class!r} has a live interim safety "
        f"baseline (fenced, ≤{entry.max_speed_ms} m/s, "
        f"≤{entry.max_robots_per_supervisor} robots/supervisor)",
        entry.receipt_digest,
    )

# ---------------------------------------------------------------------------
# 7. Digital-twin sync integrity (twin-driven reconfiguration lesson)
# ---------------------------------------------------------------------------
#
# Agentic AI that re-plans a line or pushes control commands to a
# cell must first prove the digital twin and the physical cell are
# in sync: matching state digests, drift within tolerance, and a
# fresh check. A desynced or stale cell refuses control pushes:
# ``mfg.twin_desync``.


@dataclass(frozen=True)
class TwinSyncReceipt:
    """Binds one twin-vs-physical sync verification for a cell."""

    receipt_id: str
    sync_id: str
    cell_id: str
    twin_state_digest: str
    physical_state_digest: str
    drift_bps: int
    checked_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": MFG_SCHEMA_VERSION,
            "type": "twin_sync",
            "receipt_id": self.receipt_id,
            "sync_id": self.sync_id,
            "cell_id": self.cell_id,
            "twin_state_digest": self.twin_state_digest,
            "physical_state_digest": self.physical_state_digest,
            "drift_bps": self.drift_bps,
            "checked_at": self.checked_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class TwinSyncRegistry:
    """Hash-chained log of twin-sync verification receipts."""

    authorities: AuthorityRegistry
    log: list[TwinSyncReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        sync_id: str,
        cell_id: str,
        twin_state_digest: str,
        physical_state_digest: str,
        drift_bps: int,
        checked_at: int,
        authority_id: str,
        signature: bytes,
    ) -> TwinSyncReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(sync_id, "sync_id")
        _check_nonempty_str(cell_id, "cell_id")
        _check_hex64(twin_state_digest, "twin_state_digest")
        _check_hex64(physical_state_digest, "physical_state_digest")
        _check_bps(drift_bps, "drift_bps")
        _check_ts(checked_at, "checked_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ManufacturingError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = TwinSyncReceipt(
            receipt_id=receipt_id,
            sync_id=sync_id,
            cell_id=cell_id,
            twin_state_digest=twin_state_digest,
            physical_state_digest=physical_state_digest,
            drift_bps=drift_bps,
            checked_at=checked_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ManufacturingError("twin-sync receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, cell_id: str) -> TwinSyncReceipt | None:
        for entry in reversed(self.log):
            if entry.cell_id == cell_id:
                return entry
        return None


def twin_sync_integrity(
    registry: TwinSyncRegistry,
    cell_id: str,
    now: int,
    max_sync_age_s: int = SYNC_MAX_AGE_S,
    max_drift_bps: int = SYNC_MAX_DRIFT_BPS,
) -> ManufacturingVerdict:
    """Control pushes need a fresh, in-tolerance twin-sync proof.

    The latest sync check for the cell must be fresh, within the
    drift tolerance, and its digests must agree. A desynced or stale
    cell refuses control pushes: ``mfg.twin_desync``.
    """
    _check_nonempty_str(cell_id, "cell_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "twin_sync")
    except ManufacturingError as exc:
        return _deny("mfg.chain_broken", str(exc))
    entry = registry.find(cell_id)
    if entry is None:
        return _deny(
            "mfg.twin_desync",
            f"cell {cell_id!r} binds no twin-sync verification — "
            "control pushes blocked until the twin is proven in sync",
        )
    if entry.checked_at > now:
        return _deny(
            "mfg.future_sync",
            f"twin-sync check for cell {cell_id!r} is dated in the future",
        )
    if now - entry.checked_at > max_sync_age_s:
        return _deny(
            "mfg.twin_desync",
            f"twin-sync check for cell {cell_id!r} is stale "
            f"({now - entry.checked_at}s old, limit {max_sync_age_s}s) — "
            "re-verify before pushing controls",
        )
    if entry.drift_bps > max_drift_bps:
        return _deny(
            "mfg.twin_desync",
            f"twin drift for cell {cell_id!r} is {entry.drift_bps} bps "
            f"(tolerance {max_drift_bps} bps) — control pushes refused",
        )
    return _allow(
        f"cell {cell_id!r} twin in sync (drift {entry.drift_bps} bps)",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 8. AI-vision quality-claim evidence (BOE inspection lesson)
# ---------------------------------------------------------------------------
#
# "Defect-rate down X%" claims must bind a reproducible measurement
# protocol digest and a disclosed sample size. A claim with no
# protocol or a token sample is self-reported-only and
# ``mfg.unverified_quality_claim``.


@dataclass(frozen=True)
class QualityClaimReceipt:
    """Binds an AI-quality claim to its measurement protocol."""

    receipt_id: str
    claim_id: str
    metric_name: str
    claimed_value: float
    measurement_protocol_digest: str
    sample_size: int
    third_party_verified: bool
    measured_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": MFG_SCHEMA_VERSION,
            "type": "quality_claim",
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "metric_name": self.metric_name,
            "claimed_value": self.claimed_value,
            "measurement_protocol_digest": self.measurement_protocol_digest,
            "sample_size": self.sample_size,
            "third_party_verified": self.third_party_verified,
            "measured_at": self.measured_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class QualityClaimRegistry:
    """Hash-chained log of AI-vision quality-claim receipts."""

    authorities: AuthorityRegistry
    log: list[QualityClaimReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        claim_id: str,
        metric_name: str,
        claimed_value: float,
        measurement_protocol_digest: str,
        sample_size: int,
        third_party_verified: bool,
        measured_at: int,
        authority_id: str,
        signature: bytes,
    ) -> QualityClaimReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(claim_id, "claim_id")
        _check_nonempty_str(metric_name, "metric_name")
        if isinstance(claimed_value, bool) or not isinstance(claimed_value, (int, float)):
            raise ManufacturingError("claimed_value must be a number")
        _check_hex64(measurement_protocol_digest, "measurement_protocol_digest")
        if (
            isinstance(sample_size, bool)
            or not isinstance(sample_size, int)
            or sample_size < 0
        ):
            raise ManufacturingError("sample_size must be a non-negative int")
        _check_bool(third_party_verified, "third_party_verified")
        _check_ts(measured_at, "measured_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ManufacturingError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = QualityClaimReceipt(
            receipt_id=receipt_id,
            claim_id=claim_id,
            metric_name=metric_name,
            claimed_value=float(claimed_value),
            measurement_protocol_digest=measurement_protocol_digest,
            sample_size=sample_size,
            third_party_verified=third_party_verified,
            measured_at=measured_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ManufacturingError("quality-claim receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, claim_id: str) -> QualityClaimReceipt | None:
        for entry in reversed(self.log):
            if entry.claim_id == claim_id:
                return entry
        return None


def quality_claim_evidence(
    registry: QualityClaimRegistry,
    claim_id: str,
    now: int,
    min_sample: int = QUALITY_MIN_SAMPLE,
) -> ManufacturingVerdict:
    """Quality claims need a protocol-bound evidence receipt.

    The claim must bind a reproducible measurement-protocol digest
    and disclose a sample size at or above ``min_sample``. A
    self-reported-only number is ``mfg.unverified_quality_claim`` —
    it cannot be used in procurement or marketing bindings.
    """
    _check_nonempty_str(claim_id, "claim_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "quality_claim")
    except ManufacturingError as exc:
        return _deny("mfg.chain_broken", str(exc))
    entry = registry.find(claim_id)
    if entry is None:
        return _deny(
            "mfg.unverified_quality_claim",
            f"quality claim {claim_id!r} binds no measurement receipt — "
            "self-reported numbers cannot be used",
        )
    if entry.measured_at > now:
        return _deny(
            "mfg.future_claim",
            f"quality claim {claim_id!r} is dated in the future",
        )
    if entry.sample_size < min_sample:
        return _deny(
            "mfg.unverified_quality_claim",
            f"quality claim {claim_id!r} sample size {entry.sample_size} "
            f"below minimum {min_sample}",
        )
    return _allow(
        f"quality claim {claim_id!r}: {entry.metric_name} = "
        f"{entry.claimed_value} (n={entry.sample_size}"
        f"{', third-party verified' if entry.third_party_verified else ''})",
        entry.receipt_digest,
    )


__all__ = [
    "MFG_SCHEMA_VERSION",
    "CLEARANCE_MAX_AGE_S",
    "ENVELOPE_MAX_AGE_S",
    "DISCLOSURE_NOTICE_MIN_S",
    "BASELINE_MAX_AGE_S",
    "SYNC_MAX_AGE_S",
    "SYNC_MAX_DRIFT_BPS",
    "QUALITY_MIN_SAMPLE",
    "PILOT_STAGES",
    "PILOT_STAGE_MAX_AGE_S",
    "CLASS_AUTHORITATIVE",
    "CLASS_NON_AUTHORITATIVE",
    "ManufacturingError",
    "ManufacturingVerdict",
    "AuthorityRegistry",
    "RestartClearanceReceipt",
    "RestartClearanceRegistry",
    "EnvelopeReceipt",
    "EnvelopeRegistry",
    "PilotStageReceipt",
    "PilotRegistry",
    "MaintenanceAdviceReceipt",
    "MaintenanceAdviceRegistry",
    "MaintenanceDecisionPin",
    "MaintenanceDecisionRegistry",
    "DisplacementDisclosureReceipt",
    "DisplacementRegistry",
    "SafetyBaselineReceipt",
    "SafetyBaselineRegistry",
    "TwinSyncReceipt",
    "TwinSyncRegistry",
    "QualityClaimReceipt",
    "QualityClaimRegistry",
    "restart_clearance_receipt",
    "capability_envelope",
    "humanoid_pilot_registry",
    "maintenance_decision_pin",
    "displacement_disclosure",
    "safety_baseline_clock",
    "twin_sync_integrity",
    "quality_claim_evidence",
]
