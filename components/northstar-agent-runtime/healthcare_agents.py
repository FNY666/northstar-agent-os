"""Healthcare delivery AI discipline (one-hundred-fifty-second batch).

Absorbs the 2026 AI-in-clinical-delivery research thread:

* **Epic Sepsis Model v2 (JAMA, 2026-02)** — 4 US health systems,
  227,091 encounters: AUROC 0.82-0.92 but PPV only 0.13-0.26 at
  60% sensitivity; two thirds of alerts fired *after* the patient
  was already being treated for sepsis (no incremental value).
  The authors recommend internal validation before deployment
  plus **alert-silencing protocols**.
* **Bayesian Health** (Becker's 2026-05) — first FDA clearance for
  continuous sepsis monitoring (Johns Hopkins spin-out); Epic ESM
  was never FDA-cleared, treated as CDS-exempt ("reviewable by
  clinician"), now challenged as a dangerous exemption (Stony
  Brook JESTI, 2025-11).
* **Germany MIRA (Nature Medicine, 2026-09)** — fully on-prem
  diagnostic agent; best model 84-90% accuracy on 204 standardized
  cases; core finding: output *consistency* (across samples) is
  the strongest predictor of diagnostic correctness — an
  uncertainty signal that is hard to game.
* **UK Medical Protection Society (2026-06)** — warns that under
  current law the NHS and doctors hold *all* medical-negligence
  liability for AI errors; calls for AI tools to be reclassified
  as products (Consumer Protection Act 1987) so liability is
  shared with vendors.
* **US malpractice status (Medscape 2026-02)** — as of early 2026,
  zero US jury verdicts with AI as the core cause of action;
  courts apply the traditional framework: the question is whether
  the clinician's reliance/questioning/overriding was reasonable.
  "The AI was wrong" is not a defense — clinicians are
  double-bound.
* **NEJM AI 2025 (randomized)** — structured AI-literacy training
  does NOT eliminate clinician compliance with defective machine
  output; "human-in-the-loop" is becoming "human-on-the-hook".
* **Flinders 2026-08 (JMIR, 36k vignettes)** — o3-mini / DeepSeek-R1
  racial misrepresentation 78% / 89%, gender 56% / 67%: no better
  than GPT-4, sometimes worse. Newer reasoning models improve
  capability without improving fairness.
* **EASAC/FEAM 2026-09-30** — treat clinical AI like any other
  medical intervention; do NOT let AI autonomously order
  emergency triage; inform patients of AI use; keep appeals
  channels.
* **China CSDN 2026-09** — hospital agent maturity L0 (tool) ->
  L4 (governance: PCCP-style change + full-chain traceability);
  most 2025 DeepSeek-deploying tertiary hospitals sit at L1-L2.

Northstar mapping: every gate below is fail-closed. Clinical
decision support cannot alert until a site-calibration receipt
binds (PPV, alerts-per-1k, processed-before-alert ratio); below
the PPV floor the tool is ALERT_SILENCED, not left to bombard.
Clinical deployments bind a version-pinned tripartite
responsibility manifest (developer / operator / clinician) so no
vendor can hide behind "a support tool, not a decision tool".
Demographic misrepresentation vignette sets run as a continuous
regression on every model update; fairness deterioration refuses
deploy. Any AI recommendation affecting cost or access binds
evidence provenance (clinical logic, evidence source, tool
version history); missing provenance means downstream refuses to
execute. Autonomous triage ordering is default-DENY; enabling it
requires an independent safety case plus real-time human review.
AI substantially involved in care binds a machine-readable
patient AI-use notice (with a right to refuse and a one-click
human handoff); missing notice marks the encounter
NON_COMPLIANT. Human review is adversarial by construction: the
review UI must surface uncertainty intervals and counter-evidence,
and the clinician acknowledges reading them — a signature on a
bare approve/reject button is a rubber stamp and is denied.
Diagnostic outputs carry a sampling-consistency score; low
consistency degrades to NON_AUTHORITATIVE and triggers second
review. Agent deployments carry an L0-L4 maturity label; below
L2 they are barred from the clinical core. Post-market
surveillance tracks sensitivity, override rate, and demographic
drift; threshold breach auto-rolls back to the last stable
version.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), canonical JCS hashing, Ed25519 via the vendored
``ed25519`` module, digest comparisons via :func:`hmac.compare_digest`.

Honest scope: the receipts verify the *claimed* bundle is
self-consistent and authority-signed; they cannot prove the
calibration numbers were measured honestly, the clinician
actually read the counter-evidence, or the vignette set covers
the relevant population. Those need independent evidence.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


HEALTHCARE_SCHEMA_VERSION = "northstar.healthcare-discipline.v1"

__all__ = [
    "HEALTHCARE_SCHEMA_VERSION",
    "HealthcareError",
    "HealthcareVerdict",
    "AuthorityRegistry",
    "CalibrationReceipt",
    "CalibrationRegistry",
    "ResponsibilityManifest",
    "ResponsibilityRegistry",
    "BiasVignetteReceipt",
    "BiasVignetteRegistry",
    "DenialEvidenceReceipt",
    "DenialEvidenceRegistry",
    "TriageSafetyCase",
    "TriageSafetyRegistry",
    "UsageNoticeReceipt",
    "UsageNoticeRegistry",
    "DissentAck",
    "DissentAckRegistry",
    "ConsistencyReceipt",
    "ConsistencyRegistry",
    "MaturityLabel",
    "MaturityRegistry",
    "SurveillanceWindow",
    "SurveillanceRegistry",
    "alert_burden_ledger",
    "responsibility_manifest",
    "bias_vignette_regression",
    "denial_evidence_provenance",
    "triage_ordering_ban",
    "ai_usage_notice",
    "adversarial_dissent_protocol",
    "consistency_uncertainty_signal",
    "maturity_mapping",
    "postmarket_surveillance",
    "PPV_FLOOR_BPS",
    "PROCESSED_BEFORE_CAP_BPS",
    "CONSISTENCY_FLOOR_BPS",
    "MAX_CALIBRATION_AGE_S",
    "MAX_MANIFEST_AGE_S",
    "MATURITY_LEVELS",
    "CLASS_AUTHORITATIVE",
    "CLASS_NON_AUTHORITATIVE",
    "CLASS_ALERT_SILENCED",
    "CLASS_NON_COMPLIANT",
]

#: PPV floor (basis points) for a CDS deployment to keep alerting.
#: Epic ESM v2 (JAMA 2026-02) ran at 0.13-0.26 PPV; below 0.15 the
#: tool bombards clinicians with nine false alarms per hit, and the
#: authors themselves prescribe alert-silencing protocols.
PPV_FLOOR_BPS = 1500

#: Cap (basis points) on the share of alerts that fire *after* the
#: patient is already being treated for the flagged condition.
#: ESM v2: ~66% of alerts were clinically post-hoc (no incremental
#: value); such a tool is noise, not support.
PROCESSED_BEFORE_CAP_BPS = 6000

#: Sampling-consistency floor (basis points) for a diagnostic output
#: to stay authoritative. MIRA (Nature Medicine 2026-09):
#: cross-sample consistency is the strongest correctness predictor.
CONSISTENCY_FLOOR_BPS = 8000

#: Calibration receipts older than this (1 year) are stale — the
#: tool must re-calibrate on the site's current patient mix.
MAX_CALIBRATION_AGE_S = 365 * 86_400

#: Responsibility manifests older than this (180 days) lapse; the
#: tripartite liability boundary must be re-pinned per model
#: version at least twice a year.
MAX_MANIFEST_AGE_S = 180 * 86_400

#: China CSDN 2026-09 hospital-agent maturity scale: L0 tool,
#: L1 pilot, L2 embedded (human-review workflow), L3 orchestration,
#: L4 governance (PCCP-style change + full traceability).
MATURITY_LEVELS = (0, 1, 2, 3, 4)

#: Below-L2 deployments are barred from the clinical core.
MATURITY_CLINICAL_CORE_FLOOR = 2

#: Surveillance KPI breach thresholds (basis points).
SENSITIVITY_DROP_CAP_BPS = 500  # 5pp absolute sensitivity drop
OVERRIDE_RATE_CAP_BPS = 3000  # 30% clinician override rate
DEMOGRAPHIC_DRIFT_CAP_BPS = 1000  # 10pp demographic drift

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non-authoritative"
CLASS_ALERT_SILENCED = "alert-silenced"
CLASS_NON_COMPLIANT = "non-compliant"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_DAY_S = 86_400


class HealthcareError(ValueError):
    """A malformed receipt/record or a programming error.

    Raised for structural problems (bad digests, bad signatures,
    unknown authority, out-of-range values). Verification *failures*
    (stale, below-floor, missing) return a :class:`HealthcareVerdict`
    with ``allowed=False`` — a failed gate check is a verdict, a
    malformed log is a bug.
    """


# ---------------------------------------------------------------------------
# Helpers
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
        raise HealthcareError(
            f"{field_name} must be a 64-char lowercase hex digest"
        )
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HealthcareError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise HealthcareError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise HealthcareError(f"{field_name} must be 32 bytes")
    return value


def _check_pubkey_hex(value: Any) -> str:
    return _check_hex64(value, "authority_pubkey_hex")


def _check_bps(value: Any, field_name: str) -> int:
    """Basis points: int in [0, 10000]."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise HealthcareError(f"{field_name} must be an int (basis points)")
    if not 0 <= value <= 10_000:
        raise HealthcareError(
            f"{field_name} must be in [0, 10000] basis points"
        )
    return value


def _check_level(value: Any, field_name: str) -> int:
    if value not in MATURITY_LEVELS:
        raise HealthcareError(
            f"{field_name} must be one of {MATURITY_LEVELS}"
        )
    return value


def _verify_signature(pubkey_hex: str, payload: dict[str, Any], signature_hex: str) -> bool:
    try:
        pubkey = bytes.fromhex(_check_pubkey_hex(pubkey_hex))
        signature = bytes.fromhex(signature_hex)
        if len(signature) != 64:
            return False
    except (ValueError, HealthcareError):
        return False
    try:
        ed25519.verify(pubkey, jcs_canonical_json(payload), signature)
    except Exception:
        return False
    return True


def _check_chain(log: list[Any], type_name: str) -> None:
    """Raise :class:`HealthcareError` on a tampered/broken receipt log.

    Every entry exposes ``receipt_digest`` and ``prev_digest`` and a
    ``_payload()`` method; entries must form one chain from
    ``"genesis"`` with recomputing digests and valid authority
    signatures.
    """
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(
            entry.receipt_digest, jcs_sha256_hex(entry._payload())
        ):
            raise HealthcareError(
                f"{type_name} receipt digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise HealthcareError(
                f"{type_name} receipt chain break: expected prev "
                f"{expected_prev!r}"
            )
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(
            entry.authority_pubkey_hex, signed_body, entry.signature_hex
        ):
            raise HealthcareError(
                f"{type_name} receipt authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass
class HealthcareVerdict:
    """Outcome of one healthcare-discipline gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str, classification: str = CLASS_NON_AUTHORITATIVE) -> HealthcareVerdict:
    return HealthcareVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=classification,
    )


def _allow(detail: str, receipt_digest: str = "") -> HealthcareVerdict:
    return HealthcareVerdict(
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
        if self._pubkeys is None:
            self._pubkeys = {}

    def register(self, authority_id: str, pubkey_hex: str) -> None:
        _check_nonempty_str(authority_id, "authority_id")
        self._pubkeys[_check_pubkey_hex(pubkey_hex)] = authority_id

    def pubkey(self, authority_id: str) -> str | None:
        for pubkey, name in self._pubkeys.items():
            if name == authority_id:
                return pubkey
        return None


# ---------------------------------------------------------------------------
# 1. Alert burden ledger — site-calibration receipts for CDS
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CalibrationReceipt:
    """Binds (deployment | model_version | site) to measured alert
    burden: PPV, alerts per 1k visits, and the share of alerts that
    fired after the clinician had already acted. "Deployable" and
    "alertable" are two separate doors."""

    receipt_id: str
    deployment_id: str
    model_version: str
    site_id: str
    ppv_bps: int
    alerts_per_1k: int
    processed_before_bps: int
    calibrated_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": HEALTHCARE_SCHEMA_VERSION,
            "type": "calibration",
            "receipt_id": self.receipt_id,
            "deployment_id": self.deployment_id,
            "model_version": self.model_version,
            "site_id": self.site_id,
            "ppv_bps": self.ppv_bps,
            "alerts_per_1k": self.alerts_per_1k,
            "processed_before_bps": self.processed_before_bps,
            "calibrated_at": self.calibrated_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class CalibrationRegistry:
    """Hash-chained log of CDS calibration receipts."""

    authorities: AuthorityRegistry
    log: list[CalibrationReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        deployment_id: str,
        model_version: str,
        site_id: str,
        ppv_bps: int,
        alerts_per_1k: int,
        processed_before_bps: int,
        calibrated_at: int,
        authority_id: str,
        signature: bytes,
    ) -> CalibrationReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(deployment_id, "deployment_id")
        _check_nonempty_str(model_version, "model_version")
        _check_nonempty_str(site_id, "site_id")
        _check_bps(ppv_bps, "ppv_bps")
        if not isinstance(alerts_per_1k, int) or isinstance(alerts_per_1k, bool) or alerts_per_1k < 0:
            raise HealthcareError("alerts_per_1k must be a non-negative int")
        _check_bps(processed_before_bps, "processed_before_bps")
        _check_ts(calibrated_at, "calibrated_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise HealthcareError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = CalibrationReceipt(
            receipt_id=receipt_id,
            deployment_id=deployment_id,
            model_version=model_version,
            site_id=site_id,
            ppv_bps=ppv_bps,
            alerts_per_1k=alerts_per_1k,
            processed_before_bps=processed_before_bps,
            calibrated_at=calibrated_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise HealthcareError("calibration receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def latest(self, deployment_id: str) -> CalibrationReceipt | None:
        for entry in reversed(self.log):
            if entry.deployment_id == deployment_id:
                return entry
        return None


def alert_burden_ledger(
    registry: CalibrationRegistry,
    deployment_id: str,
    now: int,
    ppv_floor_bps: int = PPV_FLOOR_BPS,
    processed_before_cap_bps: int = PROCESSED_BEFORE_CAP_BPS,
) -> HealthcareVerdict:
    """A CDS tool alerts only with a live site-calibration receipt.

    Below the PPV floor or with too many post-hoc alerts, the tool
    is ALERT_SILENCED: "deployable" and "alertable" are two separate
    doors (JAMA ESM v2: PPV 0.13-0.26, two thirds of alerts
    post-hoc; authors prescribe alert-silencing protocols).
    """
    _check_nonempty_str(deployment_id, "deployment_id")
    _check_ts(now, "now")
    receipt = registry.latest(deployment_id)
    if receipt is None:
        return _deny(
            "healthcare.no_calibration",
            f"deployment {deployment_id!r} has no site-calibration receipt",
            classification=CLASS_ALERT_SILENCED,
        )
    if now - receipt.calibrated_at > MAX_CALIBRATION_AGE_S:
        return _deny(
            "healthcare.stale_calibration",
            f"calibration for {deployment_id!r} is stale",
            classification=CLASS_ALERT_SILENCED,
        )
    if receipt.ppv_bps < _check_bps(ppv_floor_bps, "ppv_floor_bps"):
        return _deny(
            "healthcare.low_ppv_silenced",
            f"ppv {receipt.ppv_bps / 100:.2f} below floor "
            f"{ppv_floor_bps / 100:.2f}: alerting silenced, not continued",
            classification=CLASS_ALERT_SILENCED,
        )
    if receipt.processed_before_bps > _check_bps(
        processed_before_cap_bps, "processed_before_cap_bps"
    ):
        return _deny(
            "healthcare.posthoc_alerts_silenced",
            f"{receipt.processed_before_bps / 100:.1f}% of alerts fire "
            "after clinicians already acted: alerting silenced",
            classification=CLASS_ALERT_SILENCED,
        )
    return _allow(
        f"deployment {deployment_id!r} calibrated: ppv "
        f"{receipt.ppv_bps / 100:.2f}, {receipt.alerts_per_1k} alerts/1k",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 2. Responsibility manifest — version-pinned tripartite liability
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResponsibilityManifest:
    """Binds a model version to named (developer | operator |
    clinician) liability parties. No vendor may hide behind
    "a support tool, not a decision tool" once this is signed
    (UK MPS 2026-06 + German Betreiberverantwortung)."""

    manifest_id: str
    model_version: str
    developer_id: str
    operator_id: str
    clinician_role: str
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": HEALTHCARE_SCHEMA_VERSION,
            "type": "responsibility-manifest",
            "manifest_id": self.manifest_id,
            "model_version": self.model_version,
            "developer_id": self.developer_id,
            "operator_id": self.operator_id,
            "clinician_role": self.clinician_role,
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
class ResponsibilityRegistry:
    """Hash-chained log of responsibility manifests."""

    authorities: AuthorityRegistry
    log: list[ResponsibilityManifest] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        manifest_id: str,
        model_version: str,
        developer_id: str,
        operator_id: str,
        clinician_role: str,
        issued_at: int,
        authority_id: str,
        signature: bytes,
    ) -> ResponsibilityManifest:
        _check_nonempty_str(manifest_id, "manifest_id")
        _check_nonempty_str(model_version, "model_version")
        _check_nonempty_str(developer_id, "developer_id")
        _check_nonempty_str(operator_id, "operator_id")
        _check_nonempty_str(clinician_role, "clinician_role")
        _check_ts(issued_at, "issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise HealthcareError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        manifest = ResponsibilityManifest(
            manifest_id=manifest_id,
            model_version=model_version,
            developer_id=developer_id,
            operator_id=operator_id,
            clinician_role=clinician_role,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(manifest._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, manifest.signature_hex):
            raise HealthcareError("responsibility manifest authority signature invalid")
        self.log.append(manifest)
        return manifest

    def latest(self, model_version: str) -> ResponsibilityManifest | None:
        for entry in reversed(self.log):
            if entry.model_version == model_version:
                return entry
        return None


def responsibility_manifest(
    registry: ResponsibilityRegistry,
    model_version: str,
    now: int,
) -> HealthcareVerdict:
    """A clinical deployment needs a live, version-pinned tripartite
    responsibility manifest.

    The manifest pins (developer, operator, clinician) for exactly
    this model version; a lapsed manifest means nobody is
    auditable-on-the-hook for today's behavior.
    """
    _check_nonempty_str(model_version, "model_version")
    _check_ts(now, "now")
    manifest = registry.latest(model_version)
    if manifest is None:
        return _deny(
            "healthcare.no_responsibility_manifest",
            f"model {model_version!r} has no tripartite responsibility manifest",
        )
    if now - manifest.issued_at > MAX_MANIFEST_AGE_S:
        return _deny(
            "healthcare.stale_responsibility_manifest",
            f"manifest for {model_version!r} lapsed: re-pin liability parties",
        )
    return _allow(
        f"model {model_version!r} pinned: developer "
        f"{manifest.developer_id!r}, operator {manifest.operator_id!r}, "
        f"clinician {manifest.clinician_role!r}",
        receipt_digest=manifest.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 3. Bias vignette regression — continuous fairness on model updates
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BiasVignetteReceipt:
    """Binds a model version to measured demographic misrepresentation
    rates (race x gender, basis points) on a pinned vignette set.
    Reasoning models improve capability without improving fairness
    (Flinders 2026-08: 78%/89% racial misrepresentation); fairness
    measured once at launch is already stale."""

    receipt_id: str
    model_version: str
    n_vignettes: int
    race_misrep_bps: int
    gender_misrep_bps: int
    evaluated_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": HEALTHCARE_SCHEMA_VERSION,
            "type": "bias-vignette",
            "receipt_id": self.receipt_id,
            "model_version": self.model_version,
            "n_vignettes": self.n_vignettes,
            "race_misrep_bps": self.race_misrep_bps,
            "gender_misrep_bps": self.gender_misrep_bps,
            "evaluated_at": self.evaluated_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class BiasVignetteRegistry:
    """Hash-chained log of bias vignette evaluations."""

    authorities: AuthorityRegistry
    log: list[BiasVignetteReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        model_version: str,
        n_vignettes: int,
        race_misrep_bps: int,
        gender_misrep_bps: int,
        evaluated_at: int,
        authority_id: str,
        signature: bytes,
    ) -> BiasVignetteReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(model_version, "model_version")
        if not isinstance(n_vignettes, int) or isinstance(n_vignettes, bool) or n_vignettes <= 0:
            raise HealthcareError("n_vignettes must be a positive int")
        _check_bps(race_misrep_bps, "race_misrep_bps")
        _check_bps(gender_misrep_bps, "gender_misrep_bps")
        _check_ts(evaluated_at, "evaluated_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise HealthcareError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = BiasVignetteReceipt(
            receipt_id=receipt_id,
            model_version=model_version,
            n_vignettes=n_vignettes,
            race_misrep_bps=race_misrep_bps,
            gender_misrep_bps=gender_misrep_bps,
            evaluated_at=evaluated_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise HealthcareError("bias vignette receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def latest(self, model_version: str) -> BiasVignetteReceipt | None:
        for entry in reversed(self.log):
            if entry.model_version == model_version:
                return entry
        return None


def bias_vignette_regression(
    registry: BiasVignetteRegistry,
    model_version: str,
    prior_version: str,
    max_deterioration_bps: int = 500,
) -> HealthcareVerdict:
    """Every model update re-runs the pinned vignette set; fairness
    deterioration beyond tolerance refuses deploy.

    Deterioration is measured on the *worse* of race/gender
    misrepresentation. Fairness is a continuous regression, not a
    launch-time checkbox.
    """
    _check_nonempty_str(model_version, "model_version")
    _check_nonempty_str(prior_version, "prior_version")
    current = registry.latest(model_version)
    if current is None:
        return _deny(
            "healthcare.no_vignette_eval",
            f"model {model_version!r} has no bias vignette evaluation",
        )
    baseline = registry.latest(prior_version)
    if baseline is None:
        return _deny(
            "healthcare.no_vignette_baseline",
            f"prior {prior_version!r} has no baseline vignette evaluation",
        )
    race_delta = current.race_misrep_bps - baseline.race_misrep_bps
    gender_delta = current.gender_misrep_bps - baseline.gender_misrep_bps
    worst = max(race_delta, gender_delta)
    if worst > _check_bps(max_deterioration_bps, "max_deterioration_bps"):
        return _deny(
            "healthcare.fairness_regressed",
            f"misrepresentation deteriorated by {worst / 100:.1f}pp "
            f"(race {race_delta / 100:+.1f}pp, gender "
            f"{gender_delta / 100:+.1f}pp): deploy refused",
        )
    return _allow(
        f"model {model_version!r} fairness stable vs {prior_version!r} "
        f"(worst delta {worst / 100:+.1f}pp)",
        receipt_digest=current.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 4. Denial evidence provenance — cost/access-affecting AI recommendations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DenialEvidenceReceipt:
    """Binds an AI recommendation that affects cost or access to its
    evidence provenance: the clinical logic, the evidence source, and
    the tool version history (AMA 2026-06). The nH Predict "support
    tool, not a decision tool" framing is unverifiable in text form;
    in receipt form it is either bound or the downstream refuses."""

    receipt_id: str
    recommendation_id: str
    clinical_logic: str
    evidence_source: str
    tool_version: str
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": HEALTHCARE_SCHEMA_VERSION,
            "type": "denial-evidence",
            "receipt_id": self.receipt_id,
            "recommendation_id": self.recommendation_id,
            "clinical_logic": self.clinical_logic,
            "evidence_source": self.evidence_source,
            "tool_version": self.tool_version,
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
class DenialEvidenceRegistry:
    """Hash-chained log of denial-evidence receipts."""

    authorities: AuthorityRegistry
    log: list[DenialEvidenceReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        recommendation_id: str,
        clinical_logic: str,
        evidence_source: str,
        tool_version: str,
        issued_at: int,
        authority_id: str,
        signature: bytes,
    ) -> DenialEvidenceReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(recommendation_id, "recommendation_id")
        _check_nonempty_str(clinical_logic, "clinical_logic")
        _check_nonempty_str(evidence_source, "evidence_source")
        _check_nonempty_str(tool_version, "tool_version")
        _check_ts(issued_at, "issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise HealthcareError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = DenialEvidenceReceipt(
            receipt_id=receipt_id,
            recommendation_id=recommendation_id,
            clinical_logic=clinical_logic,
            evidence_source=evidence_source,
            tool_version=tool_version,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise HealthcareError("denial evidence receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, recommendation_id: str) -> DenialEvidenceReceipt | None:
        for entry in reversed(self.log):
            if entry.recommendation_id == recommendation_id:
                return entry
        return None


def denial_evidence_provenance(
    registry: DenialEvidenceRegistry,
    recommendation_id: str,
) -> HealthcareVerdict:
    """An AI recommendation affecting cost or access executes only
    with bound evidence provenance.

    Downstream systems call this before acting; a missing receipt is
    a refusal, not a warning (prior-auth black-box denials, AMA
    2026-06: 82% of Medicare Advantage appeals get overturned).
    """
    _check_nonempty_str(recommendation_id, "recommendation_id")
    receipt = registry.find(recommendation_id)
    if receipt is None:
        return _deny(
            "healthcare.no_evidence_provenance",
            f"recommendation {recommendation_id!r} affects cost/access "
            "but binds no evidence provenance: downstream refuses",
        )
    return _allow(
        f"recommendation {recommendation_id!r} binds clinical logic, "
        f"evidence source, and tool version {receipt.tool_version!r}",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 5. Triage ordering ban — autonomous ED ordering is default-DENY
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TriageSafetyCase:
    """An independent safety case enabling autonomous triage ordering
    at one site. Requires a bound independent-case digest, live
    real-time human review, and an expiry: EASAC/FEAM 2026-09-30 —
    do not let AI autonomously order emergency triage without proof
    and oversight."""

    case_id: str
    site_id: str
    independent_case_digest: str
    human_review_realtime: bool
    approved_at: int
    expires_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": HEALTHCARE_SCHEMA_VERSION,
            "type": "triage-safety-case",
            "case_id": self.case_id,
            "site_id": self.site_id,
            "independent_case_digest": self.independent_case_digest,
            "human_review_realtime": self.human_review_realtime,
            "approved_at": self.approved_at,
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
class TriageSafetyRegistry:
    """Hash-chained log of triage safety cases."""

    authorities: AuthorityRegistry
    log: list[TriageSafetyCase] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        case_id: str,
        site_id: str,
        independent_case_digest: str,
        human_review_realtime: bool,
        approved_at: int,
        expires_at: int,
        authority_id: str,
        signature: bytes,
    ) -> TriageSafetyCase:
        _check_nonempty_str(case_id, "case_id")
        _check_nonempty_str(site_id, "site_id")
        _check_hex64(independent_case_digest, "independent_case_digest")
        if not isinstance(human_review_realtime, bool):
            raise HealthcareError("human_review_realtime must be a bool")
        _check_ts(approved_at, "approved_at")
        _check_ts(expires_at, "expires_at")
        if expires_at <= approved_at:
            raise HealthcareError("expires_at must be after approved_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise HealthcareError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        case = TriageSafetyCase(
            case_id=case_id,
            site_id=site_id,
            independent_case_digest=independent_case_digest,
            human_review_realtime=human_review_realtime,
            approved_at=approved_at,
            expires_at=expires_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(case._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, case.signature_hex):
            raise HealthcareError("triage safety case authority signature invalid")
        self.log.append(case)
        return case

    def live(self, site_id: str, now: int) -> TriageSafetyCase | None:
        for entry in reversed(self.log):
            if (
                entry.site_id == site_id
                and entry.approved_at <= now < entry.expires_at
                and entry.human_review_realtime
            ):
                return entry
        return None


def triage_ordering_ban(
    registry: TriageSafetyRegistry,
    site_id: str,
    now: int,
) -> HealthcareVerdict:
    """Autonomous emergency-triage ordering is DENY by default.

    Enabling it requires a live independent safety case *and*
    real-time human review at the same site. A safety case without
    live human review, or an expired one, keeps the ban in place.
    """
    _check_nonempty_str(site_id, "site_id")
    _check_ts(now, "now")
    case = registry.live(site_id, now)
    if case is None:
        return _deny(
            "healthcare.triage_ordering_banned",
            f"site {site_id!r}: autonomous triage ordering denied by "
            "default (no live independent safety case with real-time "
            "human review)",
        )
    return _allow(
        f"site {site_id!r}: autonomous triage ordering enabled under "
        f"safety case {case.case_id!r} with real-time human review",
        receipt_digest=case.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 6. AI usage notice — machine-readable patient notice
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UsageNoticeReceipt:
    """Machine-readable receipt that the patient was notified of
    substantial AI involvement in their care, including the right to
    refuse the AI recommendation and a one-click human handoff
    (EASAC/FEAM 2026-09-30; Salesforce 2026: 90% insist on human
    handoff)."""

    notice_id: str
    encounter_id: str
    patient_id: str
    ai_components: tuple[str, ...]
    opt_out_available: bool
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": HEALTHCARE_SCHEMA_VERSION,
            "type": "usage-notice",
            "notice_id": self.notice_id,
            "encounter_id": self.encounter_id,
            "patient_id": self.patient_id,
            "ai_components": list(self.ai_components),
            "opt_out_available": self.opt_out_available,
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
class UsageNoticeRegistry:
    """Hash-chained log of AI-usage notices."""

    authorities: AuthorityRegistry
    log: list[UsageNoticeReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        notice_id: str,
        encounter_id: str,
        patient_id: str,
        ai_components: tuple[str, ...],
        opt_out_available: bool,
        issued_at: int,
        authority_id: str,
        signature: bytes,
    ) -> UsageNoticeReceipt:
        _check_nonempty_str(notice_id, "notice_id")
        _check_nonempty_str(encounter_id, "encounter_id")
        _check_nonempty_str(patient_id, "patient_id")
        if (
            not isinstance(ai_components, tuple)
            or not ai_components
            or not all(isinstance(c, str) and c.strip() for c in ai_components)
        ):
            raise HealthcareError(
                "ai_components must be a non-empty tuple of non-empty strings"
            )
        if not isinstance(opt_out_available, bool):
            raise HealthcareError("opt_out_available must be a bool")
        _check_ts(issued_at, "issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise HealthcareError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        notice = UsageNoticeReceipt(
            notice_id=notice_id,
            encounter_id=encounter_id,
            patient_id=patient_id,
            ai_components=ai_components,
            opt_out_available=opt_out_available,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(notice._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, notice.signature_hex):
            raise HealthcareError("usage notice authority signature invalid")
        self.log.append(notice)
        return notice

    def find(self, encounter_id: str) -> UsageNoticeReceipt | None:
        for entry in reversed(self.log):
            if entry.encounter_id == encounter_id:
                return entry
        return None


def ai_usage_notice(
    registry: UsageNoticeRegistry,
    encounter_id: str,
    now: int,
) -> HealthcareVerdict:
    """AI substantially involved in care binds a patient AI-use notice.

    The notice must exist and must offer opt-out; otherwise the
    encounter's AI-assisted record is marked NON_COMPLIANT.
    """
    _check_nonempty_str(encounter_id, "encounter_id")
    _check_ts(now, "now")
    notice = registry.find(encounter_id)
    if notice is None:
        return _deny(
            "healthcare.no_ai_notice",
            f"encounter {encounter_id!r}: AI involved in care with no "
            "patient AI-use notice: record NON_COMPLIANT",
            classification=CLASS_NON_COMPLIANT,
        )
    if not notice.opt_out_available:
        return _deny(
            "healthcare.no_opt_out",
            f"encounter {encounter_id!r}: notice exists but offers no "
            "opt-out: record NON_COMPLIANT",
            classification=CLASS_NON_COMPLIANT,
        )
    return _allow(
        f"encounter {encounter_id!r}: patient notified of AI components "
        f"({', '.join(notice.ai_components)}), opt-out available",
        receipt_digest=notice.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 7. Adversarial dissent protocol — human review is not a button
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DissentAck:
    """A clinician's signoff binds proof that the review UI surfaced
    an uncertainty interval and counter-evidence, and that the
    clinician acknowledged reading it. NEJM AI 2025: training does
    not cure automation compliance; a bare approve/reject button is
    a rubber stamp — the "human-on-the-hook" trap."""

    ack_id: str
    decision_id: str
    clinician_id: str
    uncertainty_shown: bool
    counter_evidence_shown: bool
    read_acknowledged: bool
    signed_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": HEALTHCARE_SCHEMA_VERSION,
            "type": "dissent-ack",
            "ack_id": self.ack_id,
            "decision_id": self.decision_id,
            "clinician_id": self.clinician_id,
            "uncertainty_shown": self.uncertainty_shown,
            "counter_evidence_shown": self.counter_evidence_shown,
            "read_acknowledged": self.read_acknowledged,
            "signed_at": self.signed_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class DissentAckRegistry:
    """Hash-chained log of dissent acknowledgments."""

    authorities: AuthorityRegistry
    log: list[DissentAck] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        ack_id: str,
        decision_id: str,
        clinician_id: str,
        uncertainty_shown: bool,
        counter_evidence_shown: bool,
        read_acknowledged: bool,
        signed_at: int,
        authority_id: str,
        signature: bytes,
    ) -> DissentAck:
        _check_nonempty_str(ack_id, "ack_id")
        _check_nonempty_str(decision_id, "decision_id")
        _check_nonempty_str(clinician_id, "clinician_id")
        for name, value in (
            ("uncertainty_shown", uncertainty_shown),
            ("counter_evidence_shown", counter_evidence_shown),
            ("read_acknowledged", read_acknowledged),
        ):
            if not isinstance(value, bool):
                raise HealthcareError(f"{name} must be a bool")
        _check_ts(signed_at, "signed_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise HealthcareError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        ack = DissentAck(
            ack_id=ack_id,
            decision_id=decision_id,
            clinician_id=clinician_id,
            uncertainty_shown=uncertainty_shown,
            counter_evidence_shown=counter_evidence_shown,
            read_acknowledged=read_acknowledged,
            signed_at=signed_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(ack._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, ack.signature_hex):
            raise HealthcareError("dissent ack authority signature invalid")
        self.log.append(ack)
        return ack

    def find(self, decision_id: str) -> DissentAck | None:
        for entry in reversed(self.log):
            if entry.decision_id == decision_id:
                return entry
        return None


def adversarial_dissent_protocol(
    registry: DissentAckRegistry,
    decision_id: str,
) -> HealthcareVerdict:
    """A clinical signoff counts only with adversarial review proof.

    The clinician's ack must bind that the UI showed an uncertainty
    interval *and* counter-evidence *and* that the clinician
    acknowledged reading both. Anything less is a rubber stamp.
    """
    _check_nonempty_str(decision_id, "decision_id")
    ack = registry.find(decision_id)
    if ack is None:
        return _deny(
            "healthcare.no_dissent_ack",
            f"decision {decision_id!r}: no adversarial-review acknowledgment",
        )
    missing = []
    if not ack.uncertainty_shown:
        missing.append("uncertainty interval")
    if not ack.counter_evidence_shown:
        missing.append("counter-evidence")
    if not ack.read_acknowledged:
        missing.append("read acknowledgment")
    if missing:
        return _deny(
            "healthcare.rubber_stamp",
            f"decision {decision_id!r}: signoff missing "
            f"{', '.join(missing)}: rubber stamp",
        )
    return _allow(
        f"decision {decision_id!r}: clinician {ack.clinician_id!r} "
        "acknowledged uncertainty interval and counter-evidence",
        receipt_digest=ack.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 8. Consistency uncertainty signal — low consistency degrades authority
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConsistencyReceipt:
    """Binds a diagnostic output digest to its cross-sample agreement
    rate. MIRA (Nature Medicine 2026-09): consistency is the
    strongest correctness predictor — a harder-to-game uncertainty
    signal than self-reported confidence."""

    receipt_id: str
    output_digest: str
    n_samples: int
    agree_bps: int
    measured_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": HEALTHCARE_SCHEMA_VERSION,
            "type": "consistency",
            "receipt_id": self.receipt_id,
            "output_digest": self.output_digest,
            "n_samples": self.n_samples,
            "agree_bps": self.agree_bps,
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
class ConsistencyRegistry:
    """Hash-chained log of consistency measurements."""

    authorities: AuthorityRegistry
    log: list[ConsistencyReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        output_digest: str,
        n_samples: int,
        agree_bps: int,
        measured_at: int,
        authority_id: str,
        signature: bytes,
    ) -> ConsistencyReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_hex64(output_digest, "output_digest")
        if not isinstance(n_samples, int) or isinstance(n_samples, bool) or n_samples < 2:
            raise HealthcareError("n_samples must be an int >= 2")
        _check_bps(agree_bps, "agree_bps")
        _check_ts(measured_at, "measured_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise HealthcareError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = ConsistencyReceipt(
            receipt_id=receipt_id,
            output_digest=output_digest,
            n_samples=n_samples,
            agree_bps=agree_bps,
            measured_at=measured_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise HealthcareError("consistency receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, output_digest: str) -> ConsistencyReceipt | None:
        for entry in reversed(self.log):
            if entry.output_digest == output_digest:
                return entry
        return None


def consistency_uncertainty_signal(
    registry: ConsistencyRegistry,
    output_digest: str,
    floor_bps: int = CONSISTENCY_FLOOR_BPS,
) -> HealthcareVerdict:
    """Low sampling consistency degrades the output to
    NON_AUTHORITATIVE and triggers second review.

    The output may still be shown — as evidence, never as a
    conclusion — but it must not drive the decision alone.
    """
    _check_hex64(output_digest, "output_digest")
    receipt = registry.find(output_digest)
    if receipt is None:
        return _deny(
            "healthcare.no_consistency_signal",
            "diagnostic output carries no sampling-consistency signal",
        )
    if receipt.agree_bps < _check_bps(floor_bps, "floor_bps"):
        return _deny(
            "healthcare.low_consistency_needs_second_review",
            f"agreement {receipt.agree_bps / 100:.1f}% below floor "
            f"{floor_bps / 100:.1f}%: NON_AUTHORITATIVE, second review "
            "required",
        )
    return _allow(
        f"output agreement {receipt.agree_bps / 100:.1f}% over "
        f"{receipt.n_samples} samples: authoritative",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 9. Maturity mapping — L0-L4 labels, below L2 barred from clinical core
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MaturityLabel:
    """Binds an agent deployment to its L0-L4 maturity level and
    scope. Below-L2 deployments in the clinical core are denied:
    China CSDN 2026-09 — most 2025 deployments sit at L1-L2, and the
    clinical core must wait for L2+ (embedded human-review
    workflow)."""

    label_id: str
    agent_id: str
    level: int
    scope: str
    labeled_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": HEALTHCARE_SCHEMA_VERSION,
            "type": "maturity-label",
            "label_id": self.label_id,
            "agent_id": self.agent_id,
            "level": self.level,
            "scope": self.scope,
            "labeled_at": self.labeled_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class MaturityRegistry:
    """Hash-chained log of maturity labels."""

    authorities: AuthorityRegistry
    log: list[MaturityLabel] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        label_id: str,
        agent_id: str,
        level: int,
        scope: str,
        labeled_at: int,
        authority_id: str,
        signature: bytes,
    ) -> MaturityLabel:
        _check_nonempty_str(label_id, "label_id")
        _check_nonempty_str(agent_id, "agent_id")
        _check_level(level, "level")
        _check_nonempty_str(scope, "scope")
        _check_ts(labeled_at, "labeled_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise HealthcareError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        label = MaturityLabel(
            label_id=label_id,
            agent_id=agent_id,
            level=level,
            scope=scope,
            labeled_at=labeled_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(label._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, label.signature_hex):
            raise HealthcareError("maturity label authority signature invalid")
        self.log.append(label)
        return label

    def latest(self, agent_id: str) -> MaturityLabel | None:
        for entry in reversed(self.log):
            if entry.agent_id == agent_id:
                return entry
        return None


def maturity_mapping(
    registry: MaturityRegistry,
    agent_id: str,
    clinical_core: bool = True,
) -> HealthcareVerdict:
    """Agent deployments carry an L0-L4 maturity label.

    Below-L2 agents are barred from the clinical core; outside the
    clinical core any labeled level is advisory-but-recorded.
    """
    _check_nonempty_str(agent_id, "agent_id")
    if not isinstance(clinical_core, bool):
        raise HealthcareError("clinical_core must be a bool")
    label = registry.latest(agent_id)
    if label is None:
        return _deny(
            "healthcare.no_maturity_label",
            f"agent {agent_id!r} carries no maturity label",
        )
    if clinical_core and label.level < MATURITY_CLINICAL_CORE_FLOOR:
        return _deny(
            "healthcare.maturity_too_low",
            f"agent {agent_id!r} at L{label.level} barred from clinical "
            f"core (floor L{MATURITY_CLINICAL_CORE_FLOOR})",
        )
    return _allow(
        f"agent {agent_id!r} at L{label.level} ({label.scope}): "
        "clinical core permitted" if clinical_core else
        f"agent {agent_id!r} at L{label.level} recorded (non-core scope)",
        receipt_digest=label.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 10. Post-market surveillance — drift KPIs with auto-rollback
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SurveillanceWindow:
    """Binds a model version to its post-market KPI window:
    absolute sensitivity drop, clinician override rate, and
    demographic drift (basis points). Breach of any KPI rolls back
    to the last stable version (JESTI 2025-11: treat clinical AI
    like a drug, with post-marketing surveillance)."""

    window_id: str
    model_version: str
    sensitivity_drop_bps: int
    override_rate_bps: int
    demographic_drift_bps: int
    rollback_version: str
    window_end: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": HEALTHCARE_SCHEMA_VERSION,
            "type": "surveillance-window",
            "window_id": self.window_id,
            "model_version": self.model_version,
            "sensitivity_drop_bps": self.sensitivity_drop_bps,
            "override_rate_bps": self.override_rate_bps,
            "demographic_drift_bps": self.demographic_drift_bps,
            "rollback_version": self.rollback_version,
            "window_end": self.window_end,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class SurveillanceRegistry:
    """Hash-chained log of surveillance windows."""

    authorities: AuthorityRegistry
    log: list[SurveillanceWindow] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        window_id: str,
        model_version: str,
        sensitivity_drop_bps: int,
        override_rate_bps: int,
        demographic_drift_bps: int,
        rollback_version: str,
        window_end: int,
        authority_id: str,
        signature: bytes,
    ) -> SurveillanceWindow:
        _check_nonempty_str(window_id, "window_id")
        _check_nonempty_str(model_version, "model_version")
        _check_bps(sensitivity_drop_bps, "sensitivity_drop_bps")
        _check_bps(override_rate_bps, "override_rate_bps")
        _check_bps(demographic_drift_bps, "demographic_drift_bps")
        _check_nonempty_str(rollback_version, "rollback_version")
        _check_ts(window_end, "window_end")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise HealthcareError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        window = SurveillanceWindow(
            window_id=window_id,
            model_version=model_version,
            sensitivity_drop_bps=sensitivity_drop_bps,
            override_rate_bps=override_rate_bps,
            demographic_drift_bps=demographic_drift_bps,
            rollback_version=rollback_version,
            window_end=window_end,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(window._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, window.signature_hex):
            raise HealthcareError("surveillance window authority signature invalid")
        self.log.append(window)
        return window

    def latest(self, model_version: str) -> SurveillanceWindow | None:
        for entry in reversed(self.log):
            if entry.model_version == model_version:
                return entry
        return None


def postmarket_surveillance(
    registry: SurveillanceRegistry,
    model_version: str,
    now: int,
) -> HealthcareVerdict:
    """Post-market drift KPIs: threshold breach auto-rolls back.

    Sensitivity drop, override rate, and demographic drift each have
    a cap; the first breach rolls the deployment back to the pinned
    stable version. The verdict reason names the rollback target so
    operators can act without interpreting dashboards.
    """
    _check_nonempty_str(model_version, "model_version")
    _check_ts(now, "now")
    window = registry.latest(model_version)
    if window is None:
        return _deny(
            "healthcare.no_surveillance_window",
            f"model {model_version!r} has no post-market surveillance "
            "window: unmonitored clinical AI is undeployed",
        )
    breached = []
    if window.sensitivity_drop_bps > SENSITIVITY_DROP_CAP_BPS:
        breached.append(
            f"sensitivity drop {window.sensitivity_drop_bps / 100:.1f}pp"
        )
    if window.override_rate_bps > OVERRIDE_RATE_CAP_BPS:
        breached.append(
            f"override rate {window.override_rate_bps / 100:.1f}%"
        )
    if window.demographic_drift_bps > DEMOGRAPHIC_DRIFT_CAP_BPS:
        breached.append(
            f"demographic drift {window.demographic_drift_bps / 100:.1f}pp"
        )
    if breached:
        return _deny(
            "healthcare.drift_rollback",
            f"model {model_version!r}: {'; '.join(breached)}: "
            f"auto-rollback to {window.rollback_version!r}",
        )
    return _allow(
        f"model {model_version!r}: KPIs within envelope",
        receipt_digest=window.receipt_digest,
    )
