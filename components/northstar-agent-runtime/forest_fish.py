"""Forest & fisheries evidence gates (one-hundred-thirty-third batch).

Absorbs the 2026 AI-forestry/fisheries research thread:

* **ICEYE (2026-03)**: SAR deforestation-monitoring product (vendor
  claims, unaudited) — evidence must be *bound*, not vendor-declared.
* **Brazil Amazon DETER**: 2,874 km² deforested 2025-08→2026-07
  (-36%, historic low) but a +12.1% rebound in 2026-08 after police
  withdrawal — monitoring evidence must survive enforcement gaps.
* **China**: first "tree density map" + single-tree segmentation,
  sky-ground integration, Fujian smart-forestry phase 2 done 2026
  (state-media framing).
* **Wildfire**: Australian Ardid paper (2026) — ML prediction 10–30%
  better than official indices *in its training region*; cross-region
  deployment is a different claim.
* **IUU fishing**: Global Fishing Watch 2026 SAR 10m-resolution
  model; HawkEye 360 (RF dark vessels); Windward (behavior
  analysis); FFA Island Chief 2026 seized 4 vessels — detection is
  leads, not verdicts.
* **Onboard EM**: TNC Edge AI real-time review (months→minutes, open
  source) — powerful surveillance that needs a purpose bound to it.
* **Aquaculture**: AQUAVIS (Korea, CES 2026); Mowi warns "no unified
  data strategy"; Japan ZIFISH unloading 3h→1h — sensor data without
  portability is lock-in.

Risk lines the gates encode:

* **Surveillance double edge**: communities may see monitoring as
  intrusion and damage equipment — monitoring evidence must carry
  consent provenance, not just pixels.
* **Algorithmic judges triggering armed patrols**: a geofence
  anomaly is not a person. The India "panoramic forest" critique —
  geofences marking mahua-gathering indigenous people as intruders —
  is mechanized here: anomalies against listed livelihood activity
  can never be automated accusations.
* **Data colonialism**: eDNA biopiracy; 87% of AI ethics boards with
  no indigenous representation — indigenous-land data collection
  requires an FPIC-bound receipt, checked at use time.
* **EUDR compliance costs pushed onto producers**: "deforestation-
  free" certificates without bound evidence are NON_AUTHORITATIVE —
  the gate protects both forests and smallholders from paper
  compliance.

Fail-closed rules:

1. **Livelihood exemption** — a geofence anomaly matching a live
   livelihood allowlist can never become an automated accusation
   (``forest.anomaly_is_not_a_person``). The gate blocks the
   *accusation*, not the observation.
2. **Indigenous data** — data collection/use on indigenous land
   without a live FPIC-bound receipt denies
   (``forest.no_fpic``). FPIC is checked at use time, like the
   105th batch's consent-at-use rule.
3. **EUDR evidence** — a "deforestation-free" certificate without a
   bound evidence digest, or with ``self_declared`` evidence only,
   is NON_AUTHORITATIVE (``forest.uncertified_claim``).
4. **Dark vessels** — IUU detection binds (SAR digest, RF digest,
   behavior digest). A complete triple binding produces an
   investigative *lead* (never an accusation); an incomplete
   binding is not actionable (``fisheries.incomplete_binding``).
5. **EM privacy** — onboard electronic-monitoring data used for a
   purpose other than the declared one denies
   (``fisheries.purpose_creep``).
6. **Aquaculture portability** — sensor data that is not portable
   must carry a disclosed lock-in terms digest; undisclosed lock-in
   denies (``fisheries.data_lockin``).
7. **Catch confidence** — catch estimates below the pinned
   confidence floor are leads only, never enforcement evidence
   (``fisheries.low_confidence_catch``).
8. **Wildfire regions** — a wildfire model deployed outside its
   training/validation regions is NON_AUTHORITATIVE
   (``forest.out_of_region_model``).

Honest boundary: receipts bind *declared* evidence discipline —
digests recompute, signatures verify, FPIC grants exist, purposes
match, regions match. They do not stop deforestation or IUU
fishing, they do not prove a certificate's field truth, and they
cannot fix "data collected but ignored" (the Brumadinho lesson from
the mining thread). What the gates guarantee: no automated
accusation without an evidence chain, no indigenous-land data use
without FPIC, no paper-compliance certificate treated as
authoritative.

Deterministic: no wall-clock reads (callers inject integer epochs),
canonical JSON hashing (``canonical_json``), Ed25519 signatures via
the vendored ``ed25519`` module, and all digest comparisons use
:func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


FOREST_FISH_SCHEMA_VERSION = "northstar.forest-fish.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128

#: Policy classification tiers (87th-batch binary semantics, plus
#: "lead": usable for investigation, never for enforcement).
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"
CLASS_LEAD = "lead"

#: Denial reason codes. All verdict reasons start with one of these.
DENY_ANOMALY_IS_NOT_PERSON = "forest.anomaly_is_not_a_person"
DENY_NO_FPIC = "forest.no_fpic"
DENY_UNCERTIFIED_CLAIM = "forest.uncertified_claim"
DENY_OUT_OF_REGION_MODEL = "forest.out_of_region_model"
DENY_INCOMPLETE_BINDING = "fisheries.incomplete_binding"
DENY_PURPOSE_CREEP = "fisheries.purpose_creep"
DENY_DATA_LOCKIN = "fisheries.data_lockin"
DENY_LOW_CONFIDENCE_CATCH = "fisheries.low_confidence_catch"
DENY_CHAIN_BROKEN = "forest.chain_broken"
DENY_EXPIRED = "forest.expired_receipt"

#: Closed livelihood-activity vocabulary (subsistence gathering that
#: a geofence must never auto-criminalize).
LIVELIHOOD_ACTIVITIES: tuple[str, ...] = (
    "mahua_gathering",
    "subsistence_fishing",
    "firewood_collection",
    "ntfp_harvest",
    "shifting_cultivation",
    "medicinal_plants",
)

#: Closed indigenous-land data-scope vocabulary.
DATA_SCOPES: tuple[str, ...] = (
    "forest_inventory",
    "edna_samples",
    "geospatial",
    "community_knowledge",
    "catch_data",
    "sensor_telemetry",
)

#: Closed onboard-EM purpose vocabulary. Purpose is matched exactly
#: at use time — a grant for ``stock_assessment`` does not cover
#: ``quota_compliance``.
EM_PURPOSES: tuple[str, ...] = (
    "stock_assessment",
    "quota_compliance",
    "safety_monitoring",
    "bycatch_research",
)

#: Closed evidence-kind vocabulary for EUDR certificates.
#: ``self_declared`` is never authoritative.
EVIDENCE_KINDS: tuple[str, ...] = (
    "satellite_sar",
    "field_audit",
    "third_party_cert",
    "supply_chain_trace",
    "self_declared",
)

#: Catch-estimate confidence floor (pinned in code, not tunable by
#: the estimating model).
CATCH_CONFIDENCE_FLOOR = 0.80


class ForestFishError(ValueError):
    """A malformed forest/fisheries receipt or a programming error.

    Raised for structural problems (bad digests, unknown classes,
    broken chains). Verification *failures* (no FPIC, purpose creep,
    lock-in, low confidence) return a :class:`ForestFishVerdict`
    with ``allowed=False`` instead — a failed check is a verdict, a
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
        raise ForestFishError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ForestFishError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ForestFishError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed (no keypair()).
    if not isinstance(value, bytes) or len(value) != 32:
        raise ForestFishError(f"{field_name} must be a 32-byte seed")
    return value


def _check_activity(value: Any) -> str:
    if value not in LIVELIHOOD_ACTIVITIES:
        raise ForestFishError(
            f"activity must be one of {LIVELIHOOD_ACTIVITIES}, saw {value!r}"
        )
    return value


def _check_scope(value: Any) -> str:
    if value not in DATA_SCOPES:
        raise ForestFishError(f"data_scope must be one of {DATA_SCOPES}, saw {value!r}")
    return value


def _check_em_purpose(value: Any) -> str:
    if value not in EM_PURPOSES:
        raise ForestFishError(f"purpose must be one of {EM_PURPOSES}, saw {value!r}")
    return value


def _check_evidence_kind(value: Any) -> str:
    if value not in EVIDENCE_KINDS:
        raise ForestFishError(
            f"evidence_kind must be one of {EVIDENCE_KINDS}, saw {value!r}"
        )
    return value


def _check_confidence(value: Any) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ForestFishError("confidence must be a number in [0, 1]")
    f = float(value)
    if not 0.0 <= f <= 1.0:
        raise ForestFishError("confidence must be a number in [0, 1]")
    return f


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
    """Raise :class:`ForestFishError` if a receipt log is tampered/broken."""
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise ForestFishError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise ForestFishError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.authority_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise ForestFishError(
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
class ForestFishVerdict:
    """Outcome of one forest/fisheries check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str, classification: str = CLASS_NON_AUTHORITATIVE) -> ForestFishVerdict:
    return ForestFishVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=classification,
    )


def _allow(detail: str, receipt_digest: str = "") -> ForestFishVerdict:
    return ForestFishVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def _lead(detail: str, receipt_digest: str = "") -> ForestFishVerdict:
    return ForestFishVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_LEAD,
        receipt_digest=receipt_digest,
    )

# ---------------------------------------------------------------------------
# Livelihood exemption (a geofence anomaly is not a person)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LivelihoodAllowlist:
    """Subsistence-gathering activities a geofence must never auto-criminalize.

    ``activities`` is drawn from the closed :data:`LIVELIHOOD_ACTIVITIES`
    vocabulary. The allowlist is issued by a land authority and chained
    from ``"genesis"``; the gate below blocks *automated accusations*,
    never observations.
    """

    receipt_id: str
    territory_id: str
    community_id: str
    activities: tuple[str, ...]
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = FOREST_FISH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "territory_id": self.territory_id,
            "community_id": self.community_id,
            "activities": sorted(self.activities),
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def issue_livelihood_allowlist(
    *,
    receipt_id: str,
    territory_id: str,
    community_id: str,
    activities: tuple[str, ...],
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> LivelihoodAllowlist:
    """Issue a livelihood allowlist receipt (authority-signed, chained)."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(territory_id, "territory_id")
    _check_nonempty_str(community_id, "community_id")
    if not activities:
        raise ForestFishError("activities must be a non-empty tuple")
    for a in activities:
        _check_activity(a)
    _check_nonempty_str(issued_by, "issued_by")
    if not _is_hex(authority_pubkey_hex, _HEX64_LENGTH):
        raise ForestFishError("authority_pubkey_hex must be a 64-char hex pubkey")
    _check_secret(authority_secret, "authority_secret")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise ForestFishError("expires_at must be after issued_at")
    receipt = LivelihoodAllowlist(
        receipt_id=receipt_id,
        territory_id=territory_id,
        community_id=community_id,
        activities=tuple(activities),
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def livelihood_exemption(
    *,
    allowlist_log: list[LivelihoodAllowlist],
    territory_id: str,
    activity: str,
    hit_at: int,
) -> ForestFishVerdict:
    """Block automated accusations against listed livelihood activity.

    A geofence anomaly matching a *live* allowlist entry for
    ``(territory_id, activity)`` can never become an automated
    accusation — the verdict denies the accusation with
    ``forest.anomaly_is_not_a_person`` (the India "panoramic forest"
    lesson). Observations may continue; *accusations* may not.
    """
    _check_nonempty_str(territory_id, "territory_id")
    _check_activity(activity)
    _check_ts(hit_at, "hit_at")
    _check_chain(allowlist_log, "livelihood-allowlist")
    for entry in allowlist_log:
        if entry.issued_at <= hit_at < entry.expires_at and hmac.compare_digest(
            entry.territory_id, territory_id
        ):
            if activity in entry.activities:
                return _deny(
                    DENY_ANOMALY_IS_NOT_PERSON,
                    f"geofence hit for {activity!r} in {territory_id!r} matches "
                    f"livelihood allowlist {entry.receipt_id!r}: automated "
                    "accusation denied; human review may observe, not accuse",
                )
    return _allow(
        f"no live livelihood exemption for {activity!r} in {territory_id!r}; "
        "the exemption gate does not block human review"
    )


# ---------------------------------------------------------------------------
# Indigenous data receipts (FPIC, checked at use time)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IndigenousDataReceipt:
    """FPIC-bound data-collection claim for indigenous land.

    ``fpic_grant_digest`` pins the community's free, prior and
    informed consent grant; ``data_scope`` is matched exactly at use
    time (a grant for ``forest_inventory`` does not cover
    ``edna_samples`` — the biopiracy lesson).
    """

    receipt_id: str
    territory_id: str
    community_id: str
    fpic_grant_digest: str
    data_scope: str
    collector_pubkey_hex: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = FOREST_FISH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "territory_id": self.territory_id,
            "community_id": self.community_id,
            "fpic_grant_digest": self.fpic_grant_digest,
            "data_scope": self.data_scope,
            "collector_pubkey_hex": self.collector_pubkey_hex,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def issue_indigenous_data_receipt(
    *,
    receipt_id: str,
    territory_id: str,
    community_id: str,
    fpic_grant_digest: str,
    data_scope: str,
    collector_pubkey_hex: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> IndigenousDataReceipt:
    """Issue an FPIC-bound indigenous data receipt (authority-signed, chained)."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(territory_id, "territory_id")
    _check_nonempty_str(community_id, "community_id")
    _check_hex64(fpic_grant_digest, "fpic_grant_digest")
    _check_scope(data_scope)
    if not _is_hex(collector_pubkey_hex, _HEX64_LENGTH):
        raise ForestFishError("collector_pubkey_hex must be a 64-char hex pubkey")
    _check_nonempty_str(issued_by, "issued_by")
    if not _is_hex(authority_pubkey_hex, _HEX64_LENGTH):
        raise ForestFishError("authority_pubkey_hex must be a 64-char hex pubkey")
    _check_secret(authority_secret, "authority_secret")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise ForestFishError("expires_at must be after issued_at")
    receipt = IndigenousDataReceipt(
        receipt_id=receipt_id,
        territory_id=territory_id,
        community_id=community_id,
        fpic_grant_digest=fpic_grant_digest,
        data_scope=data_scope,
        collector_pubkey_hex=collector_pubkey_hex,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def indigenous_data_receipt(
    *,
    receipt_log: list[IndigenousDataReceipt],
    territory_id: str,
    data_scope: str,
    use_time: int,
) -> ForestFishVerdict:
    """Check FPIC at use time for indigenous-land data.

    Data collection/use on indigenous land without a *live*
    FPIC-bound receipt covering ``(territory_id, data_scope)`` denies
    with ``forest.no_fpic``. A revoked-by-expiry grant does not
    authorize today's use (the 105th batch's consent-at-use rule).
    """
    _check_nonempty_str(territory_id, "territory_id")
    _check_scope(data_scope)
    _check_ts(use_time, "use_time")
    _check_chain(receipt_log, "indigenous-data")
    for entry in receipt_log:
        if (
            entry.issued_at <= use_time < entry.expires_at
            and hmac.compare_digest(entry.territory_id, territory_id)
            and hmac.compare_digest(entry.data_scope, data_scope)
        ):
            return _allow(
                f"FPIC-bound receipt {entry.receipt_id!r} covers {data_scope!r} "
                f"in {territory_id!r}",
                receipt_digest=entry.receipt_digest,
            )
    return _deny(
        DENY_NO_FPIC,
        f"no live FPIC-bound receipt for {data_scope!r} in {territory_id!r}: "
        "data collection/use denied",
    )

# ---------------------------------------------------------------------------
# EUDR evidence receipts (certificates bind evidence, not paper)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EudrCertificate:
    """A "deforestation-free" claim for an EUDR-regulated shipment.

    ``evidence_digest`` pins the bound evidence bundle and
    ``evidence_kind`` names its provenance. ``self_declared``
    evidence is never authoritative — the gate protects smallholders
    from paper compliance as much as forests from false claims.
    """

    receipt_id: str
    certificate_id: str
    shipment_id: str
    deforestation_free_claim: bool
    evidence_digest: str
    evidence_kind: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = FOREST_FISH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "certificate_id": self.certificate_id,
            "shipment_id": self.shipment_id,
            "deforestation_free_claim": self.deforestation_free_claim,
            "evidence_digest": self.evidence_digest,
            "evidence_kind": self.evidence_kind,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def issue_eudr_certificate(
    *,
    receipt_id: str,
    certificate_id: str,
    shipment_id: str,
    deforestation_free_claim: bool,
    evidence_digest: str,
    evidence_kind: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> EudrCertificate:
    """Issue an EUDR certificate (authority-signed, chained)."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(certificate_id, "certificate_id")
    _check_nonempty_str(shipment_id, "shipment_id")
    if not isinstance(deforestation_free_claim, bool):
        raise ForestFishError("deforestation_free_claim must be a bool")
    # evidence_digest may be empty (evidence-free claim) — the gate
    # below classifies it NON_AUTHORITATIVE; structural validation
    # only rejects non-string values.
    if not isinstance(evidence_digest, str):
        raise ForestFishError("evidence_digest must be a string")
    _check_evidence_kind(evidence_kind)
    _check_nonempty_str(issued_by, "issued_by")
    if not _is_hex(authority_pubkey_hex, _HEX64_LENGTH):
        raise ForestFishError("authority_pubkey_hex must be a 64-char hex pubkey")
    _check_secret(authority_secret, "authority_secret")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise ForestFishError("expires_at must be after issued_at")
    receipt = EudrCertificate(
        receipt_id=receipt_id,
        certificate_id=certificate_id,
        shipment_id=shipment_id,
        deforestation_free_claim=deforestation_free_claim,
        evidence_digest=evidence_digest,
        evidence_kind=evidence_kind,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def eudr_evidence_receipt(
    *,
    certificate_log: list[EudrCertificate],
    certificate_id: str,
    use_time: int,
) -> ForestFishVerdict:
    """A deforestation-free certificate is only as good as its bound evidence.

    Certificates with no bound evidence digest, or with
    ``self_declared`` evidence only, classify NON_AUTHORITATIVE with
    ``forest.uncertified_claim`` — paper compliance is not evidence.
    """
    _check_nonempty_str(certificate_id, "certificate_id")
    _check_ts(use_time, "use_time")
    _check_chain(certificate_log, "eudr-certificate")
    for entry in certificate_log:
        if (
            entry.issued_at <= use_time < entry.expires_at
            and hmac.compare_digest(entry.certificate_id, certificate_id)
        ):
            if not entry.evidence_digest:
                return _deny(
                    DENY_UNCERTIFIED_CLAIM,
                    f"certificate {certificate_id!r} carries no bound evidence: "
                    "NON_AUTHORITATIVE",
                )
            if hmac.compare_digest(entry.evidence_kind, "self_declared"):
                return _deny(
                    DENY_UNCERTIFIED_CLAIM,
                    f"certificate {certificate_id!r} is self-declared only: "
                    "NON_AUTHORITATIVE",
                )
            return _allow(
                f"certificate {certificate_id!r} binds {entry.evidence_kind} "
                "evidence",
                receipt_digest=entry.receipt_digest,
            )
    return _deny(
        DENY_UNCERTIFIED_CLAIM,
        f"no live EUDR certificate {certificate_id!r}: NON_AUTHORITATIVE",
    )


# ---------------------------------------------------------------------------
# Dark-vessel probe (leads, never accusations)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DarkVesselLead:
    """A triple-bound IUU dark-vessel detection.

    ``sar_digest`` (synthetic-aperture-radar detection),
    ``rf_digest`` (radio-frequency dark-vessel signal), and
    ``behavior_digest`` (behavioral-analysis output) must all bind.
    A complete binding is an investigative *lead* — it is never, by
    itself, an accusation (the FFA Island Chief lesson: seizures
    follow human boarding, not pixels).
    """

    receipt_id: str
    lead_id: str
    vessel_id: str
    sar_digest: str
    rf_digest: str
    behavior_digest: str
    analyst: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = FOREST_FISH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "lead_id": self.lead_id,
            "vessel_id": self.vessel_id,
            "sar_digest": self.sar_digest,
            "rf_digest": self.rf_digest,
            "behavior_digest": self.behavior_digest,
            "analyst": self.analyst,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "schema_version": self.schema_version,
        }


def _check_optional_hex64(value: Any, field_name: str) -> str:
    # Digests may be empty (unbound) — structural validation only
    # rejects non-empty malformed values.
    if value == "":
        return ""
    return _check_hex64(value, field_name)


def dark_vessel_probe(
    *,
    receipt_id: str,
    lead_id: str,
    vessel_id: str,
    sar_digest: str,
    rf_digest: str,
    behavior_digest: str,
    analyst: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    prev_digest: str = _GENESIS,
) -> ForestFishVerdict:
    """Bind the triple detection and classify the result.

    A complete (SAR, RF, behavior) binding produces an investigative
    lead (``allowed=True``, classification ``lead``) — usable for
    investigation, never for enforcement. An incomplete binding is
    not actionable (``fisheries.incomplete_binding``).
    """
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(lead_id, "lead_id")
    _check_nonempty_str(vessel_id, "vessel_id")
    sar = _check_optional_hex64(sar_digest, "sar_digest")
    rf = _check_optional_hex64(rf_digest, "rf_digest")
    beh = _check_optional_hex64(behavior_digest, "behavior_digest")
    _check_nonempty_str(analyst, "analyst")
    if not _is_hex(authority_pubkey_hex, _HEX64_LENGTH):
        raise ForestFishError("authority_pubkey_hex must be a 64-char hex pubkey")
    _check_secret(authority_secret, "authority_secret")
    _check_ts(issued_at, "issued_at")
    lead = DarkVesselLead(
        receipt_id=receipt_id,
        lead_id=lead_id,
        vessel_id=vessel_id,
        sar_digest=sar,
        rf_digest=rf,
        behavior_digest=beh,
        analyst=analyst,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        issued_at=issued_at,
        prev_digest=prev_digest,
    )
    sealed = _seal(lead, lead._payload(), authority_secret)
    if not (sar and rf and beh):
        return _deny(
            DENY_INCOMPLETE_BINDING,
            f"dark-vessel lead {lead_id!r} for {vessel_id!r} is missing a "
            "detection binding (SAR/RF/behavior): not actionable",
        )
    return _lead(
        f"dark-vessel lead {lead_id!r} for {vessel_id!r}: triple binding "
        "complete — investigative lead only, never an accusation",
        receipt_digest=sealed.receipt_digest,
    )

# ---------------------------------------------------------------------------
# Onboard EM privacy receipts (purpose binding)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EmPrivacyReceipt:
    """Purpose-bound receipt for onboard electronic-monitoring data.

    EM footage is powerful surveillance (the TNC Edge AI lesson:
    months→minutes review). ``declared_purpose`` is matched exactly
    at use time — footage collected for ``stock_assessment`` may not
    be re-purposed for ``quota_compliance`` without a new receipt.
    """

    receipt_id: str
    vessel_id: str
    declared_purpose: str
    retention_days: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = FOREST_FISH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "vessel_id": self.vessel_id,
            "declared_purpose": self.declared_purpose,
            "retention_days": self.retention_days,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def issue_em_privacy_receipt(
    *,
    receipt_id: str,
    vessel_id: str,
    declared_purpose: str,
    retention_days: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> EmPrivacyReceipt:
    """Issue a purpose-bound EM privacy receipt (authority-signed, chained)."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(vessel_id, "vessel_id")
    _check_em_purpose(declared_purpose)
    if not isinstance(retention_days, int) or isinstance(retention_days, bool) or retention_days <= 0:
        raise ForestFishError("retention_days must be a positive int")
    _check_nonempty_str(issued_by, "issued_by")
    if not _is_hex(authority_pubkey_hex, _HEX64_LENGTH):
        raise ForestFishError("authority_pubkey_hex must be a 64-char hex pubkey")
    _check_secret(authority_secret, "authority_secret")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise ForestFishError("expires_at must be after issued_at")
    receipt = EmPrivacyReceipt(
        receipt_id=receipt_id,
        vessel_id=vessel_id,
        declared_purpose=declared_purpose,
        retention_days=retention_days,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def em_privacy_receipt(
    *,
    receipt_log: list[EmPrivacyReceipt],
    vessel_id: str,
    use_purpose: str,
    use_time: int,
) -> ForestFishVerdict:
    """Enforce EM purpose binding at use time.

    Onboard EM data used for a purpose other than the declared one
    denies with ``fisheries.purpose_creep`` — surveillance capacity
    does not imply surveillance permission.
    """
    _check_nonempty_str(vessel_id, "vessel_id")
    _check_em_purpose(use_purpose)
    _check_ts(use_time, "use_time")
    _check_chain(receipt_log, "em-privacy")
    for entry in receipt_log:
        if entry.issued_at <= use_time < entry.expires_at and hmac.compare_digest(
            entry.vessel_id, vessel_id
        ):
            if not hmac.compare_digest(entry.declared_purpose, use_purpose):
                return _deny(
                    DENY_PURPOSE_CREEP,
                    f"EM data for {vessel_id!r} declared for "
                    f"{entry.declared_purpose!r}, used for {use_purpose!r}: "
                    "purpose creep denied",
                )
            return _allow(
                f"EM data for {vessel_id!r} used for declared purpose "
                f"{use_purpose!r}",
                receipt_digest=entry.receipt_digest,
            )
    return _deny(
        DENY_PURPOSE_CREEP,
        f"no live EM privacy receipt for {vessel_id!r}: use denied",
    )


# ---------------------------------------------------------------------------
# Aquaculture data portability (Mowi lock-in lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AquacultureDisclosure:
    """Sensor-data portability disclosure for an aquaculture operator.

    Sensor data that is not portable must carry a disclosed
    ``lockin_terms_digest`` pinning the lock-in terms. Undisclosed
    lock-in denies with ``fisheries.data_lockin`` (the Mowi "no
    unified data strategy" lesson: opacity is the product).
    """

    receipt_id: str
    disclosure_id: str
    operator_id: str
    sensor_data_portable: bool
    export_formats: tuple[str, ...]
    lockin_terms_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = FOREST_FISH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "disclosure_id": self.disclosure_id,
            "operator_id": self.operator_id,
            "sensor_data_portable": self.sensor_data_portable,
            "export_formats": sorted(self.export_formats),
            "lockin_terms_digest": self.lockin_terms_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "schema_version": self.schema_version,
        }


def issue_aquaculture_disclosure(
    *,
    receipt_id: str,
    disclosure_id: str,
    operator_id: str,
    sensor_data_portable: bool,
    export_formats: tuple[str, ...] = (),
    lockin_terms_digest: str = "",
    issued_by: str = "",
    authority_pubkey_hex: str = "",
    authority_secret: bytes = b"",
    issued_at: int = 0,
    prev_digest: str = _GENESIS,
) -> AquacultureDisclosure:
    """Issue an aquaculture portability disclosure (authority-signed, chained)."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(disclosure_id, "disclosure_id")
    _check_nonempty_str(operator_id, "operator_id")
    if not isinstance(sensor_data_portable, bool):
        raise ForestFishError("sensor_data_portable must be a bool")
    for f in export_formats:
        _check_nonempty_str(f, "export_formats entry")
    if lockin_terms_digest:
        _check_hex64(lockin_terms_digest, "lockin_terms_digest")
    _check_nonempty_str(issued_by, "issued_by")
    if not _is_hex(authority_pubkey_hex, _HEX64_LENGTH):
        raise ForestFishError("authority_pubkey_hex must be a 64-char hex pubkey")
    _check_secret(authority_secret, "authority_secret")
    _check_ts(issued_at, "issued_at")
    receipt = AquacultureDisclosure(
        receipt_id=receipt_id,
        disclosure_id=disclosure_id,
        operator_id=operator_id,
        sensor_data_portable=sensor_data_portable,
        export_formats=tuple(export_formats),
        lockin_terms_digest=lockin_terms_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        issued_at=issued_at,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def aquaculture_data_portability(
    *,
    disclosure: AquacultureDisclosure,
) -> ForestFishVerdict:
    """Gate undisclosed sensor-data lock-in.

    Portable data passes. Non-portable data must carry a disclosed
    lock-in terms digest; undisclosed lock-in denies with
    ``fisheries.data_lockin``.
    """
    if disclosure.sensor_data_portable:
        return _allow(
            f"operator {disclosure.operator_id!r} sensor data is portable "
            f"({', '.join(sorted(disclosure.export_formats)) or 'open formats'})",
            receipt_digest=disclosure.receipt_digest,
        )
    if disclosure.lockin_terms_digest:
        return _allow(
            f"operator {disclosure.operator_id!r} sensor data is not portable "
            "but lock-in terms are disclosed",
            receipt_digest=disclosure.receipt_digest,
        )
    return _deny(
        DENY_DATA_LOCKIN,
        f"operator {disclosure.operator_id!r} sensor data is not portable "
        "and lock-in terms are undisclosed: data lock-in denied",
    )

# ---------------------------------------------------------------------------
# Catch confidence gate (leads only below the floor)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CatchEstimate:
    """A model-produced catch estimate for a fishery.

    ``confidence`` is the model's self-reported confidence;
    ``method_digest`` pins the estimation method. Below the pinned
    :data:`CATCH_CONFIDENCE_FLOOR` the estimate is a lead only — it
    can never be enforcement evidence.
    """

    receipt_id: str
    estimate_id: str
    fishery_id: str
    estimate_t: float
    confidence: float
    method_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = FOREST_FISH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "estimate_id": self.estimate_id,
            "fishery_id": self.fishery_id,
            "estimate_t": self.estimate_t,
            "confidence": self.confidence,
            "method_digest": self.method_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "schema_version": self.schema_version,
        }


def issue_catch_estimate(
    *,
    receipt_id: str,
    estimate_id: str,
    fishery_id: str,
    estimate_t: float,
    confidence: float,
    method_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    prev_digest: str = _GENESIS,
) -> CatchEstimate:
    """Issue a catch estimate (authority-signed, chained)."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(estimate_id, "estimate_id")
    _check_nonempty_str(fishery_id, "fishery_id")
    if not isinstance(estimate_t, (int, float)) or isinstance(estimate_t, bool) or estimate_t < 0:
        raise ForestFishError("estimate_t must be a non-negative number")
    conf = _check_confidence(confidence)
    _check_hex64(method_digest, "method_digest")
    _check_nonempty_str(issued_by, "issued_by")
    if not _is_hex(authority_pubkey_hex, _HEX64_LENGTH):
        raise ForestFishError("authority_pubkey_hex must be a 64-char hex pubkey")
    _check_secret(authority_secret, "authority_secret")
    _check_ts(issued_at, "issued_at")
    receipt = CatchEstimate(
        receipt_id=receipt_id,
        estimate_id=estimate_id,
        fishery_id=fishery_id,
        estimate_t=float(estimate_t),
        confidence=conf,
        method_digest=method_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        issued_at=issued_at,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def catch_confidence_gate(
    *,
    estimate: CatchEstimate,
) -> ForestFishVerdict:
    """Low-confidence catch estimates are leads only, never evidence.

    Estimates at or above :data:`CATCH_CONFIDENCE_FLOOR` may be used
    as enforcement evidence; below the floor they classify as leads
    (``fisheries.low_confidence_catch``). The floor is pinned in
    code — the estimating model cannot tune it.
    """
    if estimate.confidence >= CATCH_CONFIDENCE_FLOOR:
        return _allow(
            f"catch estimate {estimate.estimate_id!r} confidence "
            f"{estimate.confidence:.2f} >= floor {CATCH_CONFIDENCE_FLOOR:.2f}: "
            "may be used as evidence",
            receipt_digest=estimate.receipt_digest,
        )
    return _deny(
        DENY_LOW_CONFIDENCE_CATCH,
        f"catch estimate {estimate.estimate_id!r} confidence "
        f"{estimate.confidence:.2f} < floor {CATCH_CONFIDENCE_FLOOR:.2f}: "
        "lead only, never enforcement evidence",
        classification=CLASS_LEAD,
    )


# ---------------------------------------------------------------------------
# Wildfire experimental labels (regions are claims too)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WildfireModelCard:
    """A wildfire-prediction model's declared operating regions.

    ``training_region`` names where the model was trained;
    ``validation_regions`` names where it was independently
    validated. Deployment anywhere else is experimental by default
    (the Ardid lesson: 10–30% better *in-region* says nothing about
    out-of-region).
    """

    receipt_id: str
    model_id: str
    model_digest: str
    training_region: str
    validation_regions: tuple[str, ...]
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = FOREST_FISH_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "model_id": self.model_id,
            "model_digest": self.model_digest,
            "training_region": self.training_region,
            "validation_regions": sorted(self.validation_regions),
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "schema_version": self.schema_version,
        }


def issue_wildfire_model_card(
    *,
    receipt_id: str,
    model_id: str,
    model_digest: str,
    training_region: str,
    validation_regions: tuple[str, ...] = (),
    issued_by: str = "",
    authority_pubkey_hex: str = "",
    authority_secret: bytes = b"",
    issued_at: int = 0,
    prev_digest: str = _GENESIS,
) -> WildfireModelCard:
    """Issue a wildfire model card (authority-signed, chained)."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(model_id, "model_id")
    _check_hex64(model_digest, "model_digest")
    _check_nonempty_str(training_region, "training_region")
    for r in validation_regions:
        _check_nonempty_str(r, "validation_regions entry")
    _check_nonempty_str(issued_by, "issued_by")
    if not _is_hex(authority_pubkey_hex, _HEX64_LENGTH):
        raise ForestFishError("authority_pubkey_hex must be a 64-char hex pubkey")
    _check_secret(authority_secret, "authority_secret")
    _check_ts(issued_at, "issued_at")
    receipt = WildfireModelCard(
        receipt_id=receipt_id,
        model_id=model_id,
        model_digest=model_digest,
        training_region=training_region,
        validation_regions=tuple(validation_regions),
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        issued_at=issued_at,
        prev_digest=prev_digest,
    )
    return _seal(receipt, receipt._payload(), authority_secret)


def wildfire_experimental_label(
    *,
    card: WildfireModelCard,
    deployment_region: str,
) -> ForestFishVerdict:
    """Label out-of-region wildfire models experimental.

    A model deployed outside its training region *and* its
    validation regions is NON_AUTHORITATIVE
    (``forest.out_of_region_model``) — cross-region deployment is a
    new claim, not a deployment detail.
    """
    _check_nonempty_str(deployment_region, "deployment_region")
    covered = {card.training_region, *card.validation_regions}
    if deployment_region in covered:
        return _allow(
            f"wildfire model {card.model_id!r} deployed in covered region "
            f"{deployment_region!r}",
            receipt_digest=card.receipt_digest,
        )
    return _deny(
        DENY_OUT_OF_REGION_MODEL,
        f"wildfire model {card.model_id!r} trained in {card.training_region!r} "
        f"deployed in {deployment_region!r}: NON_AUTHORITATIVE experimental label",
    )


__all__ = [
    "FOREST_FISH_SCHEMA_VERSION",
    "CLASS_AUTHORITATIVE",
    "CLASS_NON_AUTHORITATIVE",
    "CLASS_LEAD",
    "DENY_ANOMALY_IS_NOT_PERSON",
    "DENY_NO_FPIC",
    "DENY_UNCERTIFIED_CLAIM",
    "DENY_OUT_OF_REGION_MODEL",
    "DENY_INCOMPLETE_BINDING",
    "DENY_PURPOSE_CREEP",
    "DENY_DATA_LOCKIN",
    "DENY_LOW_CONFIDENCE_CATCH",
    "DENY_CHAIN_BROKEN",
    "DENY_EXPIRED",
    "LIVELIHOOD_ACTIVITIES",
    "DATA_SCOPES",
    "EM_PURPOSES",
    "EVIDENCE_KINDS",
    "CATCH_CONFIDENCE_FLOOR",
    "ForestFishError",
    "ForestFishVerdict",
    "LivelihoodAllowlist",
    "issue_livelihood_allowlist",
    "livelihood_exemption",
    "IndigenousDataReceipt",
    "issue_indigenous_data_receipt",
    "indigenous_data_receipt",
    "EudrCertificate",
    "issue_eudr_certificate",
    "eudr_evidence_receipt",
    "DarkVesselLead",
    "dark_vessel_probe",
    "EmPrivacyReceipt",
    "issue_em_privacy_receipt",
    "em_privacy_receipt",
    "AquacultureDisclosure",
    "issue_aquaculture_disclosure",
    "aquaculture_data_portability",
    "CatchEstimate",
    "issue_catch_estimate",
    "catch_confidence_gate",
    "WildfireModelCard",
    "issue_wildfire_model_card",
    "wildfire_experimental_label",
]
