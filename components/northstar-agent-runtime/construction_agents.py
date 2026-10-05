"""Construction-site AI discipline (one-hundred-sixtieth batch).

Absorbs the 2026 AI-construction research thread:

* **Bedrock Robotics (globenewswire 2026-08-17, EN)** — first fully
  autonomous excavators on live US customer sites (Nevada water
  treatment w/ Sundt Construction, Texas Champion Site Prep's
  million-cubic-yard earthwork, Zachry's 1.2M cubic yards); $270M
  Series B (CapitalG, Valor Equity Partners); investor line: "every
  hyperscaler is thinking about how to compress schedule". The
  investor's own line is the discipline's warning label:
  schedule-compression pressure + AI progress assessment = a nursery
  for optimism bias. Rule: multi-machine coordination binds an
  orchestration manifest with a *named* responsible party —
  ``construction.no_orchestration_manifest``.
* **上海静安灵石社区 (163.com / 千龙网, 中文)** — "electronic
  safety officer" cameras caught 4000+ violations (95% claimed
  accuracy, project-party figure), alert SMSes pushed straight to
  managers' phones. The other side of 95% accuracy is 5% false
  positives at scale: alert channels pin false-positive budgets and
  degrade to human patrol over budget —
  ``construction.alert_budget_exceeded``. And the consent question
  nobody asked (devdiscourse lesson): surveillance binds consent
  receipts naming the recorder, data owner, and reuse purposes —
  ``construction.unconsented_surveillance``.
* **Korea Hyundai x Samsung night shift (mk.co.kr, 한국어)** —
  unmanned night-shift material-transport robots moving 500kg/day of
  waste; "Spot" night patrols planned. **Guardian AI** (mk.co.kr) —
  PPE detection linked to equipment interlocks (no helmet → the
  machine simply won't start); dust-resistant helmet recognition;
  NVIDIA GTC 2026 poster. **LH 늘봄 A-Eye (2026-04)** — nationwide
  CCTV+IoT AI control of Korean sites. Rule: equipment starts bind
  live safety-interlock receipts — ``construction.no_interlock``.
* **清水建設 Torch Tower (Impress Watch, 日本語)** — 1.0 m/s
  humanoid patrols with a handheld camera; imitation-learning
  painting arms; Sony partnership for a construction-AI ecosystem.
  Embodied site robots declare capability envelopes and refuse
  out-of-envelope commands up front — ``construction.envelope_breach``.
* **Saipem @ Automa 2026 (offshore-technology.com, EN)** —
  supervisors mark every alert true/false positive and the feedback
  returns into training. The discipline's best practice line:
  "AI itself doesn't make a site safer; it makes existing safety
  processes and field leadership executed more consistently." Rule:
  AI safety alerts need human validation feedback on a clock;
  unvalidated alerts expire — ``construction.unvalidated_alert``.
* **WTW UK (wtwco.com, EN)** — 77 robot-related accidents 2015-2022
  (93 injuries); software faults cluster in programming/testing/
  maintenance; **dust-blocked sensors are the typical failure
  mode**. Rule: autonomous heavy equipment binds a live dynamic
  exclusion-zone status; sensor-degraded equipment must drop to
  supervised mode, never continue fully autonomous —
  ``construction.degraded_autonomy``.
* **MDPI (2026, EN)** — GenAI data-integrity risk taxonomy: user-
  injected fraud (fraudulent compliance reports, contaminated
  operations data) poisoning digital twins; legal attribution
  deadlock. Rule: twin state changes are append-only with source
  provenance; user-uploaded data is tagged and isolated —
  ``construction.twin_contamination``.
* **Progress-evidence trap (zeeglobalvision.com, EN)** — AI vision
  can assess progress from images, but "a photo must never become
  an unquestioned payment certificate"; the key qualifier is
  **support**. Rule: AI progress assessments bind evidence receipts
  (method + digest + timestamp); payment-certificate claims without
  a human sign-off are ``construction.payment_without_signoff``.
* **Schedule hallucination chain (areadevelopment.com, arhca.ab.ca,
  ddg.global, EN)** — wrong ML schedule forecasts scramble the
  critical path → liquidated damages; Alberta construction
  association: AI mis-estimating concrete cure times, crane
  availability, trade overlaps → major delays, penalties,
  subcontractor claims; Suffolk/MIT via DDG: useful alerts must
  say *what changed, the evidence, which milestone it hits, how
  much time is left, who owns the next step, and how much
  uncertainty remains*. Rules: AI schedule changes bind rationale
  records — ``construction.unrationale_reschedule``; forecasts
  bind uncertainty bands with disclosed assumptions, undisclosed
  assumptions are NON_AUTHORITATIVE —
  ``construction.unstated_assumptions``.
* **Hallucinated compliance (multihousingnews.com, EN)** — AI-
  generated estimates/drawings/specs without human verification
  cause construction defects and legal disputes. Rule: AI outputs
  must pin their cited regulation clauses; fabricated clauses are
  refused whole-class — ``construction.fabricated_clause``.

Deterministic: no wall-clock reads (callers inject ``now`` as an
integer epoch), canonical JCS hashing (ninety-fifth batch), and all
digest comparisons use :func:`hmac.compare_digest`.

Honest scope:

* Receipts bind the *declared* construction discipline; they do not
  make sites safe, make schedules honest, or prove a sign-off is
  real.
* The 24-hour evidence freshness, 5-minute perimeter-status
  freshness, 1-hour interlock shelf life, 7-day validation clock,
  24-hour alert-measurement freshness, 30-day envelope validity, and
  14-day forecast freshness are bench parameters drawn from the
  2026 construction sweep; confirm against the deployment's safety
  standards before site reliance.
"""

from __future__ import annotations
from _domain_base import DomainError

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


CONSTRUCTION_SCHEMA_VERSION = "northstar.construction.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128
_DAY_S = 86_400

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: AI progress-assessment evidence older than this cannot gate a
#: payment-certificate claim (the photo is no longer the site).
EVIDENCE_MAX_AGE_S = 24 * 3_600

#: Dynamic exclusion-zone statuses go stale in minutes (WTW lesson:
#: a dusty sensor silently stops seeing workers).
PERIMETER_STATUS_MAX_AGE_S = 300

#: A PPE-interlock pass covers one shift start, not the whole week.
INTERLOCK_MAX_AGE_S = 3_600

#: Safety alerts must receive human true/false feedback inside this
#: clock (Saipem validation-loop lesson); unvalidated alerts expire.
VALIDATION_MAX_AGE_S = 7 * _DAY_S

#: Alert false-positive measurements older than this cannot prove a
#: channel is within budget.
ALERT_MEASUREMENT_MAX_AGE_S = 24 * 3_600

#: Capability envelopes for embodied site robots re-validate monthly.
ENVELOPE_MAX_AGE_S = 30 * _DAY_S

#: Schedule/cost forecasts expire fast (Alberta lesson: models are
#: built on assumptions, and sites don't follow assumptions).
FORECAST_MAX_AGE_S = 14 * _DAY_S

#: Rationale records are historical evidence; the bound is a sanity
#: limit, not a decay curve.
RATIONALE_MAX_AGE_S = 180 * _DAY_S

#: Source kinds accepted for digital-twin state updates.
TWIN_SOURCE_KINDS = ("sensor", "operator", "ai_model", "user_upload")

#: Feedback values accepted for safety-alert validation.
VALIDATION_FEEDBACKS = ("true_positive", "false_positive")

#: Surveillance scopes that require worker consent.
SURVEILLANCE_SCOPES = ("video", "audio", "wearable", "biometric")

#: Sensor statuses for exclusion-zone / autonomy gating.
SENSOR_STATUSES = ("nominal", "degraded")

#: Autonomy modes for heavy site equipment.
AUTONOMY_MODES = ("autonomous", "supervised", "stopped")


class ConstructionError(DomainError):
    """A malformed construction receipt or a programming error.

    Raised for structural problems (bad digests, unknown checks,
    broken chains, out-of-range band edges). Verification *failures*
    (missing evidence, degraded autonomy, fabricated clauses) return
    a :class:`ConstructionVerdict` with ``allowed=False`` instead —
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
        raise ConstructionError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConstructionError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ConstructionError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise ConstructionError("authority_pubkey_hex must be a 64-char lowercase hex digest")
    return value


def _check_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ConstructionError(f"{field_name} must be a bool")
    return value


def _check_nonneg_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ConstructionError(f"{field_name} must be a non-negative number")
    return float(value)


def _check_str_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ConstructionError(f"{field_name} must be a non-empty list of strings")
    return tuple(_check_nonempty_str(v, f"{field_name} item") for v in value)


def _check_closed_vocab(value: Any, allowed: tuple[str, ...], field_name: str) -> str:
    if value not in allowed:
        raise ConstructionError(
            f"{field_name} must be one of {allowed}, got {value!r}"
        )
    return value


# ---------------------------------------------------------------------------
# Signing and chain verification
# ---------------------------------------------------------------------------


def _verify_signature(
    pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str
) -> bool:
    # Vendored ed25519.verify() returns a bool (it does not signal
    # failure by raising), so the return value must be honoured:
    # `try: verify(...); return True except: return False` would let
    # a tampered signature through.
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
    """Raise :class:`ConstructionError` if a receipt log is tampered/broken.

    Every entry must expose ``receipt_digest`` and ``prev_digest`` and
    a ``_payload()`` method; the entries must form one chain from
    ``"genesis"`` with recomputing digests and valid authority
    signatures.
    """
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise ConstructionError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise ConstructionError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(
            entry.authority_pubkey_hex, signed_body, entry.signature_hex
        ):
            raise ConstructionError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class ConstructionVerdict:
    """Outcome of one construction-discipline gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> ConstructionVerdict:
    return ConstructionVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> ConstructionVerdict:
    return ConstructionVerdict(
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


def _issue_pubkey(registry: "AuthorityRegistry", authority_id: str) -> str:
    pubkey = registry.pubkey(authority_id)
    if pubkey is None:
        raise ConstructionError(f"unknown authority {authority_id!r}")
    return pubkey


# ---------------------------------------------------------------------------
# 1. Progress evidence (a photo is never an unquestioned payment certificate)
# ---------------------------------------------------------------------------
#
# AI progress assessments bind evidence receipts: method, evidence
# digest, capture timestamp. A payment-certificate claim additionally
# requires a named human sign-off. Without it the claim is
# ``construction.payment_without_signoff`` — the photo is support,
# never the certificate.


@dataclass(frozen=True)
class ProgressAssessmentReceipt:
    """Binds one AI progress assessment to its evidence."""

    receipt_id: str
    claim_id: str
    site_id: str
    assessment_method: str
    evidence_digest: str
    captured_at: int
    assessor_id: str
    payment_certificate: bool
    human_signoff_id: str
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": CONSTRUCTION_SCHEMA_VERSION,
            "type": "progress_assessment",
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "site_id": self.site_id,
            "assessment_method": self.assessment_method,
            "evidence_digest": self.evidence_digest,
            "captured_at": self.captured_at,
            "assessor_id": self.assessor_id,
            "payment_certificate": self.payment_certificate,
            "human_signoff_id": self.human_signoff_id,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class ProgressAssessmentRegistry:
    """Hash-chained log of AI progress-assessment receipts."""

    authorities: AuthorityRegistry
    log: list[ProgressAssessmentReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        claim_id: str,
        site_id: str,
        assessment_method: str,
        evidence_digest: str,
        captured_at: int,
        assessor_id: str,
        payment_certificate: bool,
        human_signoff_id: str,
        authority_id: str,
        signature: bytes,
    ) -> ProgressAssessmentReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(claim_id, "claim_id")
        _check_nonempty_str(site_id, "site_id")
        _check_nonempty_str(assessment_method, "assessment_method")
        _check_hex64(evidence_digest, "evidence_digest")
        _check_ts(captured_at, "captured_at")
        _check_nonempty_str(assessor_id, "assessor_id")
        _check_bool(payment_certificate, "payment_certificate")
        if not isinstance(human_signoff_id, str):
            raise ConstructionError("human_signoff_id must be a string")
        pubkey = _issue_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = ProgressAssessmentReceipt(
            receipt_id=receipt_id,
            claim_id=claim_id,
            site_id=site_id,
            assessment_method=assessment_method,
            evidence_digest=evidence_digest,
            captured_at=captured_at,
            assessor_id=assessor_id,
            payment_certificate=payment_certificate,
            human_signoff_id=human_signoff_id,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ConstructionError("progress-assessment receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find_claim(self, claim_id: str) -> ProgressAssessmentReceipt | None:
        for entry in reversed(self.log):
            if entry.claim_id == claim_id:
                return entry
        return None


def progress_evidence_receipt(
    registry: ProgressAssessmentRegistry,
    claim_id: str,
    now: int,
    evidence_max_age_s: int = EVIDENCE_MAX_AGE_S,
) -> ConstructionVerdict:
    """Gate a progress claim on bound, fresh evidence and human sign-off.

    Missing or stale evidence is ``construction.no_progress_evidence``
    / ``construction.stale_evidence``. A payment-certificate claim
    with no human sign-off is ``construction.payment_without_signoff``:
    a photo must never become an unquestioned payment certificate.
    """
    _check_nonempty_str(claim_id, "claim_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "progress_assessment")
    except ConstructionError as exc:
        return _deny("construction.chain_broken", str(exc))
    entry = registry.find_claim(claim_id)
    if entry is None:
        return _deny(
            "construction.no_progress_evidence",
            f"progress claim {claim_id!r} binds no AI assessment evidence receipt",
        )
    if entry.captured_at > now:
        return _deny(
            "construction.future_evidence",
            f"progress evidence for claim {claim_id!r} is dated in the future",
        )
    if now - entry.captured_at > evidence_max_age_s:
        return _deny(
            "construction.stale_evidence",
            f"progress evidence for claim {claim_id!r} is stale "
            f"({now - entry.captured_at}s old, limit {evidence_max_age_s}s)",
        )
    if entry.payment_certificate and not entry.human_signoff_id.strip():
        return _deny(
            "construction.payment_without_signoff",
            f"payment-certificate claim {claim_id!r} has no human sign-off — "
            "a photo must never become an unquestioned payment certificate",
        )
    return _allow(
        f"progress claim {claim_id!r}: evidence {entry.evidence_digest[:16]}... "
        f"via {entry.assessment_method!r}"
        + (f" (human sign-off {entry.human_signoff_id!r})"
           if entry.payment_certificate else ""),
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 2. Schedule rationale binding (unrationale critical-path reschedules)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScheduleChangeReceipt:
    """Binds an AI-generated schedule change to a checkable rationale."""

    receipt_id: str
    change_id: str
    activity_id: str
    old_start: int
    new_start: int
    rationale_summary: str
    critical_path: bool
    impact_statement: str
    recorded_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": CONSTRUCTION_SCHEMA_VERSION,
            "type": "schedule_change",
            "receipt_id": self.receipt_id,
            "change_id": self.change_id,
            "activity_id": self.activity_id,
            "old_start": self.old_start,
            "new_start": self.new_start,
            "rationale_summary": self.rationale_summary,
            "critical_path": self.critical_path,
            "impact_statement": self.impact_statement,
            "recorded_at": self.recorded_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class ScheduleChangeRegistry:
    """Hash-chained log of AI schedule-change receipts."""

    authorities: AuthorityRegistry
    log: list[ScheduleChangeReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        change_id: str,
        activity_id: str,
        old_start: int,
        new_start: int,
        rationale_summary: str,
        critical_path: bool,
        impact_statement: str,
        recorded_at: int,
        authority_id: str,
        signature: bytes,
    ) -> ScheduleChangeReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(change_id, "change_id")
        _check_nonempty_str(activity_id, "activity_id")
        _check_ts(old_start, "old_start")
        _check_ts(new_start, "new_start")
        if not isinstance(rationale_summary, str):
            raise ConstructionError("rationale_summary must be a string")
        _check_bool(critical_path, "critical_path")
        if not isinstance(impact_statement, str):
            raise ConstructionError("impact_statement must be a string")
        _check_ts(recorded_at, "recorded_at")
        pubkey = _issue_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = ScheduleChangeReceipt(
            receipt_id=receipt_id,
            change_id=change_id,
            activity_id=activity_id,
            old_start=old_start,
            new_start=new_start,
            rationale_summary=rationale_summary,
            critical_path=critical_path,
            impact_statement=impact_statement,
            recorded_at=recorded_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ConstructionError("schedule-change receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, change_id: str) -> ScheduleChangeReceipt | None:
        for entry in reversed(self.log):
            if entry.change_id == change_id:
                return entry
        return None


def schedule_rationale_binding(
    registry: ScheduleChangeRegistry,
    change_id: str,
    now: int,
    rationale_max_age_s: int = RATIONALE_MAX_AGE_S,
) -> ConstructionVerdict:
    """Require AI schedule changes to carry checkable rationales.

    A critical-path activity reorder with no rationale or no impact
    statement is ``construction.unrationale_reschedule`` (liquidated-
    damages territory).
    """
    _check_nonempty_str(change_id, "change_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "schedule_change")
    except ConstructionError as exc:
        return _deny("construction.chain_broken", str(exc))
    entry = registry.find(change_id)
    if entry is None:
        return _deny(
            "construction.unrationale_reschedule",
            f"schedule change {change_id!r} binds no rationale record",
        )
    if entry.critical_path and not entry.rationale_summary.strip():
        return _deny(
            "construction.unrationale_reschedule",
            f"critical-path change {change_id!r} carries no rationale summary",
        )
    if entry.critical_path and not entry.impact_statement.strip():
        return _deny(
            "construction.unrationale_reschedule",
            f"critical-path change {change_id!r} carries no impact statement",
        )
    if now - entry.recorded_at > rationale_max_age_s:
        return _deny(
            "construction.stale_rationale",
            f"rationale for change {change_id!r} is older than "
            f"{rationale_max_age_s}s",
        )
    return _allow(
        f"schedule change {change_id!r} (activity {entry.activity_id!r}): "
        f"{entry.old_start} -> {entry.new_start}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 3. Digital-twin integrity log (user-injected data is tagged and isolated)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TwinUpdateReceipt:
    """One append-only digital-twin state update with source provenance."""

    receipt_id: str
    update_id: str
    twin_section: str
    state_digest: str
    source_kind: str
    provenance_digest: str
    isolated: bool
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": CONSTRUCTION_SCHEMA_VERSION,
            "type": "twin_update",
            "receipt_id": self.receipt_id,
            "update_id": self.update_id,
            "twin_section": self.twin_section,
            "state_digest": self.state_digest,
            "source_kind": self.source_kind,
            "provenance_digest": self.provenance_digest,
            "isolated": self.isolated,
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
class TwinUpdateRegistry:
    """Append-only log of digital-twin state updates."""

    authorities: AuthorityRegistry
    log: list[TwinUpdateReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        update_id: str,
        twin_section: str,
        state_digest: str,
        source_kind: str,
        provenance_digest: str,
        isolated: bool,
        issued_at: int,
        authority_id: str,
        signature: bytes,
    ) -> TwinUpdateReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(update_id, "update_id")
        _check_nonempty_str(twin_section, "twin_section")
        _check_hex64(state_digest, "state_digest")
        _check_closed_vocab(source_kind, TWIN_SOURCE_KINDS, "source_kind")
        _check_hex64(provenance_digest, "provenance_digest")
        _check_bool(isolated, "isolated")
        _check_ts(issued_at, "issued_at")
        pubkey = _issue_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = TwinUpdateReceipt(
            receipt_id=receipt_id,
            update_id=update_id,
            twin_section=twin_section,
            state_digest=state_digest,
            source_kind=source_kind,
            provenance_digest=provenance_digest,
            isolated=isolated,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ConstructionError("twin-update receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, update_id: str) -> TwinUpdateReceipt | None:
        for entry in reversed(self.log):
            if entry.update_id == update_id:
                return entry
        return None


def digital_twin_integrity_log(
    registry: TwinUpdateRegistry,
    update_id: str,
    now: int,
) -> ConstructionVerdict:
    """Gate twin updates on provenance; user uploads must be isolated.

    A ``user_upload``-sourced update applied to the twin without
    isolation tagging is ``construction.twin_contamination`` (MDPI
    data-integrity lesson).
    """
    _check_nonempty_str(update_id, "update_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "twin_update")
    except ConstructionError as exc:
        return _deny("construction.chain_broken", str(exc))
    entry = registry.find(update_id)
    if entry is None:
        return _deny(
            "construction.unlogged_twin_update",
            f"twin update {update_id!r} is not in the integrity log",
        )
    if entry.source_kind == "user_upload" and not entry.isolated:
        return _deny(
            "construction.twin_contamination",
            f"twin update {update_id!r} carries user-uploaded data applied "
            "without isolation tagging — contamination risk",
        )
    return _allow(
        f"twin update {update_id!r} (section {entry.twin_section!r}, "
        f"source {entry.source_kind!r})",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 4. Human-robot interaction perimeter gate (dust-blind sensors)
# ---------------------------------------------------------------------------
#
# Autonomous heavy equipment binds a live dynamic-exclusion-zone
# status. Degraded sensors (the WTW-typical dust failure) must drop
# the machine to supervised mode — continuing fully autonomous is
# ``construction.degraded_autonomy``.


@dataclass(frozen=True)
class PerimeterReceipt:
    """Live human-robot interaction perimeter status for one machine."""

    receipt_id: str
    machine_id: str
    perimeter_radius_m: float
    sensor_status: str
    autonomy_mode: str
    assessed_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": CONSTRUCTION_SCHEMA_VERSION,
            "type": "perimeter_status",
            "receipt_id": self.receipt_id,
            "machine_id": self.machine_id,
            "perimeter_radius_m": self.perimeter_radius_m,
            "sensor_status": self.sensor_status,
            "autonomy_mode": self.autonomy_mode,
            "assessed_at": self.assessed_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class PerimeterRegistry:
    """Hash-chained log of exclusion-zone status assessments."""

    authorities: AuthorityRegistry
    log: list[PerimeterReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        machine_id: str,
        perimeter_radius_m: float,
        sensor_status: str,
        autonomy_mode: str,
        assessed_at: int,
        authority_id: str,
        signature: bytes,
    ) -> PerimeterReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(machine_id, "machine_id")
        _check_nonneg_number(perimeter_radius_m, "perimeter_radius_m")
        _check_closed_vocab(sensor_status, SENSOR_STATUSES, "sensor_status")
        _check_closed_vocab(autonomy_mode, AUTONOMY_MODES, "autonomy_mode")
        _check_ts(assessed_at, "assessed_at")
        pubkey = _issue_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = PerimeterReceipt(
            receipt_id=receipt_id,
            machine_id=machine_id,
            perimeter_radius_m=float(perimeter_radius_m),
            sensor_status=sensor_status,
            autonomy_mode=autonomy_mode,
            assessed_at=assessed_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ConstructionError("perimeter receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def latest(self, machine_id: str) -> PerimeterReceipt | None:
        for entry in reversed(self.log):
            if entry.machine_id == machine_id:
                return entry
        return None


def hri_perimeter_gate(
    registry: PerimeterRegistry,
    machine_id: str,
    now: int,
    status_max_age_s: int = PERIMETER_STATUS_MAX_AGE_S,
) -> ConstructionVerdict:
    """Require a live perimeter status; degraded sensors kill autonomy.

    A machine running ``autonomous`` with ``degraded`` sensors is
    ``construction.degraded_autonomy`` (WTW dust-blocked-sensor
    lesson): drop to supervised, never continue blind.
    """
    _check_nonempty_str(machine_id, "machine_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "perimeter_status")
    except ConstructionError as exc:
        return _deny("construction.chain_broken", str(exc))
    entry = registry.latest(machine_id)
    if entry is None:
        return _deny(
            "construction.no_perimeter",
            f"machine {machine_id!r} binds no exclusion-zone status receipt",
        )
    if entry.assessed_at > now:
        return _deny(
            "construction.future_perimeter",
            f"perimeter status for machine {machine_id!r} is dated in the future",
        )
    if now - entry.assessed_at > status_max_age_s:
        return _deny(
            "construction.stale_perimeter",
            f"perimeter status for machine {machine_id!r} is stale "
            f"({now - entry.assessed_at}s old, limit {status_max_age_s}s)",
        )
    if entry.sensor_status == "degraded" and entry.autonomy_mode == "autonomous":
        return _deny(
            "construction.degraded_autonomy",
            f"machine {machine_id!r} runs autonomous on degraded sensors — "
            "drop to supervised mode",
        )
    return _allow(
        f"machine {machine_id!r}: {entry.autonomy_mode} with "
        f"{entry.sensor_status} sensors, {entry.perimeter_radius_m}m perimeter",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 5. Safety interlock receipts (Guardian AI PPE-linked interlock lesson)
# ---------------------------------------------------------------------------
#
# PPE detection linked to equipment interlocks: a start request binds
# a live "pass" interlock event. Without it the start is
# ``construction.no_interlock``; an interlock that said "blocked"
# must never be overridden by a start.


@dataclass(frozen=True)
class InterlockReceipt:
    """One safety-interlock event for an equipment start request."""

    receipt_id: str
    machine_id: str
    start_request_id: str
    interlock_kind: str
    event: str
    ppe_evidence_digest: str
    recorded_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": CONSTRUCTION_SCHEMA_VERSION,
            "type": "interlock_event",
            "receipt_id": self.receipt_id,
            "machine_id": self.machine_id,
            "start_request_id": self.start_request_id,
            "interlock_kind": self.interlock_kind,
            "event": self.event,
            "ppe_evidence_digest": self.ppe_evidence_digest,
            "recorded_at": self.recorded_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class InterlockRegistry:
    """Hash-chained log of safety-interlock events."""

    authorities: AuthorityRegistry
    log: list[InterlockReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        machine_id: str,
        start_request_id: str,
        interlock_kind: str,
        event: str,
        ppe_evidence_digest: str,
        recorded_at: int,
        authority_id: str,
        signature: bytes,
    ) -> InterlockReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(machine_id, "machine_id")
        _check_nonempty_str(start_request_id, "start_request_id")
        _check_closed_vocab(
            interlock_kind, ("ppe_gate", "e_stop_clear", "zone_clear"), "interlock_kind"
        )
        _check_closed_vocab(event, ("pass", "blocked_start"), "event")
        _check_hex64(ppe_evidence_digest, "ppe_evidence_digest")
        _check_ts(recorded_at, "recorded_at")
        pubkey = _issue_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = InterlockReceipt(
            receipt_id=receipt_id,
            machine_id=machine_id,
            start_request_id=start_request_id,
            interlock_kind=interlock_kind,
            event=event,
            ppe_evidence_digest=ppe_evidence_digest,
            recorded_at=recorded_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ConstructionError("interlock receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find_start(self, start_request_id: str) -> InterlockReceipt | None:
        for entry in reversed(self.log):
            if entry.start_request_id == start_request_id:
                return entry
        return None


def safety_interlock_receipt(
    registry: InterlockRegistry,
    machine_id: str,
    start_request_id: str,
    now: int,
    interlock_max_age_s: int = INTERLOCK_MAX_AGE_S,
) -> ConstructionVerdict:
    """Equipment starts need a live passing safety-interlock receipt.

    No interlock receipt is ``construction.no_interlock`` (Guardian
    AI lesson: the machine simply doesn't start). A recorded
    ``blocked_start`` overridden by a new request is
    ``construction.interlock_override``.
    """
    _check_nonempty_str(machine_id, "machine_id")
    _check_nonempty_str(start_request_id, "start_request_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "interlock_event")
    except ConstructionError as exc:
        return _deny("construction.chain_broken", str(exc))
    entry = registry.find_start(start_request_id)
    if entry is None:
        return _deny(
            "construction.no_interlock",
            f"start request {start_request_id!r} binds no safety-interlock "
            "receipt — equipment may not start",
        )
    if entry.event != "pass":
        return _deny(
            "construction.interlock_override",
            f"start request {start_request_id!r} follows a recorded "
            f"{entry.event!r} interlock — overriding is prohibited",
        )
    if now - entry.recorded_at > interlock_max_age_s:
        return _deny(
            "construction.stale_interlock",
            f"interlock pass for start {start_request_id!r} is stale "
            f"({now - entry.recorded_at}s old, limit {interlock_max_age_s}s)",
        )
    return _allow(
        f"start request {start_request_id!r} (machine {machine_id!r}): "
        f"{entry.interlock_kind} interlock passed",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 6. Validation loop clock (Saipem lesson: every alert gets true/false)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidationFeedbackReceipt:
    """A human true/false-positive verdict on an AI safety alert."""

    receipt_id: str
    alert_id: str
    feedback: str
    reviewer_id: str
    reviewed_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": CONSTRUCTION_SCHEMA_VERSION,
            "type": "validation_feedback",
            "receipt_id": self.receipt_id,
            "alert_id": self.alert_id,
            "feedback": self.feedback,
            "reviewer_id": self.reviewer_id,
            "reviewed_at": self.reviewed_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class ValidationFeedbackRegistry:
    """Hash-chained log of safety-alert validation feedback."""

    authorities: AuthorityRegistry
    log: list[ValidationFeedbackReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        alert_id: str,
        feedback: str,
        reviewer_id: str,
        reviewed_at: int,
        authority_id: str,
        signature: bytes,
    ) -> ValidationFeedbackReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(alert_id, "alert_id")
        _check_closed_vocab(feedback, VALIDATION_FEEDBACKS, "feedback")
        _check_nonempty_str(reviewer_id, "reviewer_id")
        _check_ts(reviewed_at, "reviewed_at")
        pubkey = _issue_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = ValidationFeedbackReceipt(
            receipt_id=receipt_id,
            alert_id=alert_id,
            feedback=feedback,
            reviewer_id=reviewer_id,
            reviewed_at=reviewed_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ConstructionError("validation-feedback receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, alert_id: str) -> ValidationFeedbackReceipt | None:
        for entry in reversed(self.log):
            if entry.alert_id == alert_id:
                return entry
        return None


def validation_loop_clock(
    registry: ValidationFeedbackRegistry,
    alert_id: str,
    now: int,
    feedback_max_age_s: int = VALIDATION_MAX_AGE_S,
) -> ConstructionVerdict:
    """Every AI safety alert needs human true/false feedback on a clock.

    Missing or expired feedback is ``construction.unvalidated_alert``:
    AI itself doesn't make a site safer — unvalidated alerts are
    noise, and models drift without the feedback loop (Saipem
    lesson).
    """
    _check_nonempty_str(alert_id, "alert_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "validation_feedback")
    except ConstructionError as exc:
        return _deny("construction.chain_broken", str(exc))
    entry = registry.find(alert_id)
    if entry is None:
        return _deny(
            "construction.unvalidated_alert",
            f"safety alert {alert_id!r} has no human validation feedback — "
            "unvalidated alerts are not actionable",
        )
    if entry.reviewed_at > now:
        return _deny(
            "construction.future_feedback",
            f"validation feedback for alert {alert_id!r} is dated in the future",
        )
    if now - entry.reviewed_at > feedback_max_age_s:
        return _deny(
            "construction.unvalidated_alert",
            f"validation feedback for alert {alert_id!r} expired "
            f"({now - entry.reviewed_at}s old, limit {feedback_max_age_s}s) — "
            "alert must be re-validated",
        )
    return _allow(
        f"safety alert {alert_id!r}: {entry.feedback} by {entry.reviewer_id!r}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 7. Worker surveillance consent (the consent question nobody asked)
# ---------------------------------------------------------------------------
#
# Site surveillance collection binds consent receipts naming who
# records, who owns the data, and the reuse purposes. Collection
# without consent is ``construction.unconsented_surveillance``
# (devdiscourse / Shanghai / LH lessons).


@dataclass(frozen=True)
class SurveillanceConsentReceipt:
    """A worker's consent for one surveillance scope on one site."""

    receipt_id: str
    site_id: str
    worker_id: str
    scope: str
    data_owner: str
    reuse_purposes: tuple[str, ...]
    consented_at: int
    expires_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": CONSTRUCTION_SCHEMA_VERSION,
            "type": "surveillance_consent",
            "receipt_id": self.receipt_id,
            "site_id": self.site_id,
            "worker_id": self.worker_id,
            "scope": self.scope,
            "data_owner": self.data_owner,
            "reuse_purposes": list(self.reuse_purposes),
            "consented_at": self.consented_at,
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
class SurveillanceConsentRegistry:
    """Hash-chained log of worker surveillance-consent receipts."""

    authorities: AuthorityRegistry
    log: list[SurveillanceConsentReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        site_id: str,
        worker_id: str,
        scope: str,
        data_owner: str,
        reuse_purposes: list[str] | tuple[str, ...],
        consented_at: int,
        expires_at: int,
        authority_id: str,
        signature: bytes,
    ) -> SurveillanceConsentReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(site_id, "site_id")
        _check_nonempty_str(worker_id, "worker_id")
        _check_closed_vocab(scope, SURVEILLANCE_SCOPES, "scope")
        _check_nonempty_str(data_owner, "data_owner")
        purposes = _check_str_tuple(reuse_purposes, "reuse_purposes")
        _check_ts(consented_at, "consented_at")
        _check_ts(expires_at, "expires_at")
        if expires_at <= consented_at:
            raise ConstructionError("expires_at must be after consented_at")
        pubkey = _issue_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = SurveillanceConsentReceipt(
            receipt_id=receipt_id,
            site_id=site_id,
            worker_id=worker_id,
            scope=scope,
            data_owner=data_owner,
            reuse_purposes=purposes,
            consented_at=consented_at,
            expires_at=expires_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ConstructionError("surveillance-consent receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(
        self, site_id: str, worker_id: str, scope: str
    ) -> SurveillanceConsentReceipt | None:
        for entry in reversed(self.log):
            if (
                entry.site_id == site_id
                and entry.worker_id == worker_id
                and entry.scope == scope
            ):
                return entry
        return None


def worker_surveillance_consent(
    registry: SurveillanceConsentRegistry,
    site_id: str,
    worker_id: str,
    scope: str,
    now: int,
) -> ConstructionVerdict:
    """Surveillance collection needs the worker's consent receipt.

    No consent for the scope is ``construction.unconsented_surveillance``
    (the consent question nobody asked); expired consent is
    ``construction.consent_expired``.
    """
    _check_nonempty_str(site_id, "site_id")
    _check_nonempty_str(worker_id, "worker_id")
    _check_closed_vocab(scope, SURVEILLANCE_SCOPES, "scope")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "surveillance_consent")
    except ConstructionError as exc:
        return _deny("construction.chain_broken", str(exc))
    entry = registry.find(site_id, worker_id, scope)
    if entry is None:
        return _deny(
            "construction.unconsented_surveillance",
            f"worker {worker_id!r} has no consent receipt for {scope} "
            f"surveillance on site {site_id!r}",
        )
    if now < entry.consented_at:
        return _deny(
            "construction.future_consent",
            f"consent for worker {worker_id!r} is dated in the future",
        )
    if now > entry.expires_at:
        return _deny(
            "construction.consent_expired",
            f"consent for worker {worker_id!r} ({scope} on {site_id!r}) "
            "expired — re-consent before collecting",
        )
    return _allow(
        f"worker {worker_id!r}: {scope} surveillance consented "
        f"(data owner {entry.data_owner!r}, reuse: "
        f"{', '.join(entry.reuse_purposes)})",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 8. Hallucinated clause screen (fabricated regulation clauses)
# ---------------------------------------------------------------------------
#
# AI-generated estimates/drawings/specs must pin the regulation
# clauses they cite. A cited-but-unknown or unverified clause is
# refused whole-class as ``construction.fabricated_clause`` —
# verification of the citation is non-delegable.


@dataclass(frozen=True)
class ClausePinReceipt:
    """Binds one cited regulation clause to a verified source."""

    receipt_id: str
    document_id: str
    clause_reference: str
    regulation_source: str
    pinned_text_digest: str
    verified: bool
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": CONSTRUCTION_SCHEMA_VERSION,
            "type": "clause_pin",
            "receipt_id": self.receipt_id,
            "document_id": self.document_id,
            "clause_reference": self.clause_reference,
            "regulation_source": self.regulation_source,
            "pinned_text_digest": self.pinned_text_digest,
            "verified": self.verified,
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
class ClausePinRegistry:
    """Hash-chained log of cited-clause verification pins."""

    authorities: AuthorityRegistry
    log: list[ClausePinReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        document_id: str,
        clause_reference: str,
        regulation_source: str,
        pinned_text_digest: str,
        verified: bool,
        issued_at: int,
        authority_id: str,
        signature: bytes,
    ) -> ClausePinReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(document_id, "document_id")
        _check_nonempty_str(clause_reference, "clause_reference")
        _check_nonempty_str(regulation_source, "regulation_source")
        _check_hex64(pinned_text_digest, "pinned_text_digest")
        _check_bool(verified, "verified")
        _check_ts(issued_at, "issued_at")
        pubkey = _issue_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = ClausePinReceipt(
            receipt_id=receipt_id,
            document_id=document_id,
            clause_reference=clause_reference,
            regulation_source=regulation_source,
            pinned_text_digest=pinned_text_digest,
            verified=verified,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ConstructionError("clause-pin receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(
        self, document_id: str, clause_reference: str
    ) -> ClausePinReceipt | None:
        for entry in reversed(self.log):
            if (
                entry.document_id == document_id
                and entry.clause_reference == clause_reference
            ):
                return entry
        return None


def hallucinated_clause_screen(
    registry: ClausePinRegistry,
    document_id: str,
    clause_reference: str,
) -> ConstructionVerdict:
    """Refuse whole-class any document citing an unverified clause.

    A clause with no verification pin, or pinned but unverified, is
    ``construction.fabricated_clause`` (hallucinated compliance
    lesson: citation verification is non-delegable).
    """
    _check_nonempty_str(document_id, "document_id")
    _check_nonempty_str(clause_reference, "clause_reference")
    try:
        _check_chain(registry.log, "clause_pin")
    except ConstructionError as exc:
        return _deny("construction.chain_broken", str(exc))
    entry = registry.find(document_id, clause_reference)
    if entry is None:
        return _deny(
            "construction.fabricated_clause",
            f"document {document_id!r} cites clause {clause_reference!r} "
            "with no verification pin — refused whole-class",
        )
    if not entry.verified:
        return _deny(
            "construction.fabricated_clause",
            f"clause {clause_reference!r} in document {document_id!r} "
            "is pinned but UNVERIFIED — refused whole-class",
        )
    return _allow(
        f"clause {clause_reference!r} verified against "
        f"{entry.regulation_source!r}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 9. Forecast uncertainty bands (models are built on assumptions)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ForecastReceipt:
    """A schedule/cost forecast with its uncertainty band and assumptions."""

    receipt_id: str
    forecast_id: str
    forecast_kind: str
    value_text: str
    uncertainty_low: float
    uncertainty_high: float
    assumptions_digest: str
    assumptions_text: str
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": CONSTRUCTION_SCHEMA_VERSION,
            "type": "forecast",
            "receipt_id": self.receipt_id,
            "forecast_id": self.forecast_id,
            "forecast_kind": self.forecast_kind,
            "value_text": self.value_text,
            "uncertainty_low": self.uncertainty_low,
            "uncertainty_high": self.uncertainty_high,
            "assumptions_digest": self.assumptions_digest,
            "assumptions_text": self.assumptions_text,
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
class ForecastRegistry:
    """Hash-chained log of forecast receipts."""

    authorities: AuthorityRegistry
    log: list[ForecastReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        forecast_id: str,
        forecast_kind: str,
        value_text: str,
        uncertainty_low: float,
        uncertainty_high: float,
        assumptions_digest: str,
        assumptions_text: str,
        issued_at: int,
        authority_id: str,
        signature: bytes,
    ) -> ForecastReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(forecast_id, "forecast_id")
        _check_closed_vocab(forecast_kind, ("schedule", "cost"), "forecast_kind")
        _check_nonempty_str(value_text, "value_text")
        lo = _check_nonneg_number(uncertainty_low, "uncertainty_low")
        hi = _check_nonneg_number(uncertainty_high, "uncertainty_high")
        if lo > hi:
            raise ConstructionError("uncertainty_low must not exceed uncertainty_high")
        _check_hex64(assumptions_digest, "assumptions_digest")
        if not isinstance(assumptions_text, str):
            raise ConstructionError("assumptions_text must be a string")
        _check_ts(issued_at, "issued_at")
        pubkey = _issue_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = ForecastReceipt(
            receipt_id=receipt_id,
            forecast_id=forecast_id,
            forecast_kind=forecast_kind,
            value_text=value_text,
            uncertainty_low=lo,
            uncertainty_high=hi,
            assumptions_digest=assumptions_digest,
            assumptions_text=assumptions_text,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ConstructionError("forecast receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, forecast_id: str) -> ForecastReceipt | None:
        for entry in reversed(self.log):
            if entry.forecast_id == forecast_id:
                return entry
        return None


def forecast_uncertainty_band(
    registry: ForecastRegistry,
    forecast_id: str,
    now: int,
    forecast_max_age_s: int = FORECAST_MAX_AGE_S,
) -> ConstructionVerdict:
    """Forecasts must carry an uncertainty band and disclosed assumptions.

    A forecast with no disclosed assumptions is NON_AUTHORITATIVE:
    ``construction.unstated_assumptions`` (Alberta lesson — models
    are built on assumptions, and sites don't follow assumptions).
    Stale forecasts are ``construction.stale_forecast``.
    """
    _check_nonempty_str(forecast_id, "forecast_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "forecast")
    except ConstructionError as exc:
        return _deny("construction.chain_broken", str(exc))
    entry = registry.find(forecast_id)
    if entry is None:
        return _deny(
            "construction.no_forecast_binding",
            f"forecast {forecast_id!r} binds no uncertainty-band receipt",
        )
    if not entry.assumptions_text.strip():
        return _deny(
            "construction.unstated_assumptions",
            f"forecast {forecast_id!r} discloses no assumptions — "
            "not authoritative (models are built on assumptions)",
        )
    if now - entry.issued_at > forecast_max_age_s:
        return _deny(
            "construction.stale_forecast",
            f"forecast {forecast_id!r} is stale "
            f"({now - entry.issued_at}s old, limit {forecast_max_age_s}s)",
        )
    return _allow(
        f"forecast {forecast_id!r}: {entry.value_text} "
        f"[{entry.uncertainty_low}, {entry.uncertainty_high}] "
        f"(assumptions: {entry.assumptions_digest[:16]}...)",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 10. Capability envelope gate (construction-scene instantiation)
# ---------------------------------------------------------------------------
#
# Same lineage as the agrifood/manufacturing envelopes: embodied
# site robots declare what they can reliably do right now, and
# out-of-envelope commands are refused up front — never "start and
# stop on detect".


@dataclass(frozen=True)
class ConstructionEnvelopeReceipt:
    """A site robot's capability envelope for the current conditions."""

    receipt_id: str
    machine_id: str
    task_kinds: tuple[str, ...]
    max_payload_t: float
    max_speed_ms: float
    allowed_conditions: tuple[str, ...]
    valid_from: int
    valid_until: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": CONSTRUCTION_SCHEMA_VERSION,
            "type": "construction_envelope",
            "receipt_id": self.receipt_id,
            "machine_id": self.machine_id,
            "task_kinds": list(self.task_kinds),
            "max_payload_t": self.max_payload_t,
            "max_speed_ms": self.max_speed_ms,
            "allowed_conditions": list(self.allowed_conditions),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class ConstructionEnvelopeRegistry:
    """Hash-chained log of site-robot capability envelopes."""

    authorities: AuthorityRegistry
    log: list[ConstructionEnvelopeReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        machine_id: str,
        task_kinds: list[str] | tuple[str, ...],
        max_payload_t: float,
        max_speed_ms: float,
        allowed_conditions: list[str] | tuple[str, ...],
        valid_from: int,
        valid_until: int,
        authority_id: str,
        signature: bytes,
    ) -> ConstructionEnvelopeReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(machine_id, "machine_id")
        tasks = _check_str_tuple(task_kinds, "task_kinds")
        payload = _check_nonneg_number(max_payload_t, "max_payload_t")
        speed = _check_nonneg_number(max_speed_ms, "max_speed_ms")
        conditions = _check_str_tuple(allowed_conditions, "allowed_conditions")
        _check_ts(valid_from, "valid_from")
        _check_ts(valid_until, "valid_until")
        if valid_until <= valid_from:
            raise ConstructionError("valid_until must be after valid_from")
        if valid_until - valid_from > ENVELOPE_MAX_AGE_S:
            raise ConstructionError(
                f"envelope validity exceeds {ENVELOPE_MAX_AGE_S}s — re-validate monthly"
            )
        pubkey = _issue_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = ConstructionEnvelopeReceipt(
            receipt_id=receipt_id,
            machine_id=machine_id,
            task_kinds=tasks,
            max_payload_t=payload,
            max_speed_ms=speed,
            allowed_conditions=conditions,
            valid_from=valid_from,
            valid_until=valid_until,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ConstructionError("construction-envelope receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def latest(self, machine_id: str) -> ConstructionEnvelopeReceipt | None:
        for entry in reversed(self.log):
            if entry.machine_id == machine_id:
                return entry
        return None


def capability_envelope_gate(
    registry: ConstructionEnvelopeRegistry,
    machine_id: str,
    task_kind: str,
    payload_t: float,
    now: int,
) -> ConstructionVerdict:
    """Refuse up front any command outside the declared envelope.

    Missing envelopes, expired envelopes, unlisted task kinds, and
    payload over the rated max are all ``construction.envelope_breach``.
    """
    _check_nonempty_str(machine_id, "machine_id")
    _check_nonempty_str(task_kind, "task_kind")
    _check_nonneg_number(payload_t, "payload_t")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "construction_envelope")
    except ConstructionError as exc:
        return _deny("construction.chain_broken", str(exc))
    entry = registry.latest(machine_id)
    if entry is None:
        return _deny(
            "construction.envelope_breach",
            f"machine {machine_id!r} declares no capability envelope — "
            "out-of-envelope commands are refused up front",
        )
    if now < entry.valid_from or now > entry.valid_until:
        return _deny(
            "construction.envelope_breach",
            f"capability envelope for machine {machine_id!r} is not valid "
            f"at {now} (valid {entry.valid_from}..{entry.valid_until})",
        )
    if task_kind not in entry.task_kinds:
        return _deny(
            "construction.envelope_breach",
            f"task {task_kind!r} is outside the envelope of machine "
            f"{machine_id!r} (allowed: {', '.join(entry.task_kinds)})",
        )
    if payload_t > entry.max_payload_t:
        return _deny(
            "construction.envelope_breach",
            f"payload {payload_t}t exceeds envelope max {entry.max_payload_t}t "
            f"for machine {machine_id!r}",
        )
    return _allow(
        f"machine {machine_id!r}: task {task_kind!r} at {payload_t}t "
        f"within envelope (max {entry.max_payload_t}t)",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 11. Fleet orchestration manifest (named responsible party)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OrchestrationManifest:
    """Manifest for multi-machine self-orchestration on a site."""

    receipt_id: str
    manifest_id: str
    fleet_id: str
    machine_ids: tuple[str, ...]
    responsible_party: str
    window_start: int
    window_end: int
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": CONSTRUCTION_SCHEMA_VERSION,
            "type": "orchestration_manifest",
            "receipt_id": self.receipt_id,
            "manifest_id": self.manifest_id,
            "fleet_id": self.fleet_id,
            "machine_ids": list(self.machine_ids),
            "responsible_party": self.responsible_party,
            "window_start": self.window_start,
            "window_end": self.window_end,
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
class OrchestrationRegistry:
    """Hash-chained log of fleet orchestration manifests."""

    authorities: AuthorityRegistry
    log: list[OrchestrationManifest] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        manifest_id: str,
        fleet_id: str,
        machine_ids: list[str] | tuple[str, ...],
        responsible_party: str,
        window_start: int,
        window_end: int,
        issued_at: int,
        authority_id: str,
        signature: bytes,
    ) -> OrchestrationManifest:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(manifest_id, "manifest_id")
        _check_nonempty_str(fleet_id, "fleet_id")
        machines = _check_str_tuple(machine_ids, "machine_ids")
        _check_nonempty_str(responsible_party, "responsible_party")
        _check_ts(window_start, "window_start")
        _check_ts(window_end, "window_end")
        if window_end <= window_start:
            raise ConstructionError("window_end must be after window_start")
        _check_ts(issued_at, "issued_at")
        pubkey = _issue_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = OrchestrationManifest(
            receipt_id=receipt_id,
            manifest_id=manifest_id,
            fleet_id=fleet_id,
            machine_ids=machines,
            responsible_party=responsible_party,
            window_start=window_start,
            window_end=window_end,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ConstructionError("orchestration manifest authority signature invalid")
        self.log.append(receipt)
        return receipt

    def latest(self, fleet_id: str) -> OrchestrationManifest | None:
        for entry in reversed(self.log):
            if entry.fleet_id == fleet_id:
                return entry
        return None


def fleet_orchestration_manifest(
    registry: OrchestrationRegistry,
    fleet_id: str,
    now: int,
) -> ConstructionVerdict:
    """Fleet self-orchestration needs a manifest with a named owner.

    No manifest for the fleet's operating window is
    ``construction.no_orchestration_manifest`` (Bedrock fleet
    self-orchestration lesson: someone must be answerable).
    """
    _check_nonempty_str(fleet_id, "fleet_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "orchestration_manifest")
    except ConstructionError as exc:
        return _deny("construction.chain_broken", str(exc))
    entry = registry.latest(fleet_id)
    if entry is None:
        return _deny(
            "construction.no_orchestration_manifest",
            f"fleet {fleet_id!r} binds no orchestration manifest with a "
            "named responsible party",
        )
    if now < entry.window_start or now > entry.window_end:
        return _deny(
            "construction.manifest_out_of_window",
            f"manifest {entry.manifest_id!r} for fleet {fleet_id!r} is not "
            f"live at {now} (window {entry.window_start}..{entry.window_end})",
        )
    return _allow(
        f"fleet {fleet_id!r}: manifest {entry.manifest_id!r} "
        f"({len(entry.machine_ids)} machines, responsible: "
        f"{entry.responsible_party!r})",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 12. Safety alert budgets (the other side of 95% accuracy)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertBudgetReceipt:
    """Measured false-positive rate for one safety-alert channel."""

    receipt_id: str
    channel_id: str
    budget_fp_per_day: float
    measured_fp: int
    measured_total: int
    measured_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": CONSTRUCTION_SCHEMA_VERSION,
            "type": "alert_budget",
            "receipt_id": self.receipt_id,
            "channel_id": self.channel_id,
            "budget_fp_per_day": self.budget_fp_per_day,
            "measured_fp": self.measured_fp,
            "measured_total": self.measured_total,
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
class AlertBudgetRegistry:
    """Hash-chained log of alert-channel false-positive measurements."""

    authorities: AuthorityRegistry
    log: list[AlertBudgetReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        channel_id: str,
        budget_fp_per_day: float,
        measured_fp: int,
        measured_total: int,
        measured_at: int,
        authority_id: str,
        signature: bytes,
    ) -> AlertBudgetReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(channel_id, "channel_id")
        budget = _check_nonneg_number(budget_fp_per_day, "budget_fp_per_day")
        if isinstance(measured_fp, bool) or not isinstance(measured_fp, int) or measured_fp < 0:
            raise ConstructionError("measured_fp must be a non-negative int")
        if isinstance(measured_total, bool) or not isinstance(measured_total, int) or measured_total < 0:
            raise ConstructionError("measured_total must be a non-negative int")
        if measured_fp > measured_total:
            raise ConstructionError("measured_fp must not exceed measured_total")
        _check_ts(measured_at, "measured_at")
        pubkey = _issue_pubkey(self.authorities, authority_id)
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = AlertBudgetReceipt(
            receipt_id=receipt_id,
            channel_id=channel_id,
            budget_fp_per_day=budget,
            measured_fp=measured_fp,
            measured_total=measured_total,
            measured_at=measured_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise ConstructionError("alert-budget receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def latest(self, channel_id: str) -> AlertBudgetReceipt | None:
        for entry in reversed(self.log):
            if entry.channel_id == channel_id:
                return entry
        return None


def safety_alert_budget(
    registry: AlertBudgetRegistry,
    channel_id: str,
    now: int,
    measurement_max_age_s: int = ALERT_MEASUREMENT_MAX_AGE_S,
) -> ConstructionVerdict:
    """Pin false-positive budgets on safety-alert channels.

    A channel over its pinned budget is
    ``construction.alert_budget_exceeded``: degrade to human patrol
    (the other side of the "95% accuracy" figure is 5% false
    positives at construction scale).
    """
    _check_nonempty_str(channel_id, "channel_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "alert_budget")
    except ConstructionError as exc:
        return _deny("construction.chain_broken", str(exc))
    entry = registry.latest(channel_id)
    if entry is None:
        return _deny(
            "construction.no_alert_budget",
            f"alert channel {channel_id!r} binds no false-positive budget",
        )
    if now - entry.measured_at > measurement_max_age_s:
        return _deny(
            "construction.stale_alert_measurement",
            f"FP measurement for channel {channel_id!r} is stale "
            f"({now - entry.measured_at}s old, limit {measurement_max_age_s}s)",
        )
    if entry.measured_fp > entry.budget_fp_per_day:
        return _deny(
            "construction.alert_budget_exceeded",
            f"alert channel {channel_id!r} measured {entry.measured_fp} "
            f"FPs/day over budget {entry.budget_fp_per_day} — degrade to "
            "human patrol",
        )
    return _allow(
        f"alert channel {channel_id!r}: {entry.measured_fp} FPs/day within "
        f"budget {entry.budget_fp_per_day}",
        entry.receipt_digest,
    )


__all__ = [
    "CONSTRUCTION_SCHEMA_VERSION",
    "EVIDENCE_MAX_AGE_S",
    "PERIMETER_STATUS_MAX_AGE_S",
    "INTERLOCK_MAX_AGE_S",
    "VALIDATION_MAX_AGE_S",
    "ALERT_MEASUREMENT_MAX_AGE_S",
    "ENVELOPE_MAX_AGE_S",
    "FORECAST_MAX_AGE_S",
    "RATIONALE_MAX_AGE_S",
    "TWIN_SOURCE_KINDS",
    "VALIDATION_FEEDBACKS",
    "SURVEILLANCE_SCOPES",
    "SENSOR_STATUSES",
    "AUTONOMY_MODES",
    "CLASS_AUTHORITATIVE",
    "CLASS_NON_AUTHORITATIVE",
    "ConstructionError",
    "ConstructionVerdict",
    "AuthorityRegistry",
    "ProgressAssessmentReceipt",
    "ProgressAssessmentRegistry",
    "ScheduleChangeReceipt",
    "ScheduleChangeRegistry",
    "TwinUpdateReceipt",
    "TwinUpdateRegistry",
    "PerimeterReceipt",
    "PerimeterRegistry",
    "InterlockReceipt",
    "InterlockRegistry",
    "ValidationFeedbackReceipt",
    "ValidationFeedbackRegistry",
    "SurveillanceConsentReceipt",
    "SurveillanceConsentRegistry",
    "ClausePinReceipt",
    "ClausePinRegistry",
    "ForecastReceipt",
    "ForecastRegistry",
    "ConstructionEnvelopeReceipt",
    "ConstructionEnvelopeRegistry",
    "OrchestrationManifest",
    "OrchestrationRegistry",
    "AlertBudgetReceipt",
    "AlertBudgetRegistry",
    "progress_evidence_receipt",
    "schedule_rationale_binding",
    "digital_twin_integrity_log",
    "hri_perimeter_gate",
    "safety_interlock_receipt",
    "validation_loop_clock",
    "worker_surveillance_consent",
    "hallucinated_clause_screen",
    "forecast_uncertainty_band",
    "capability_envelope_gate",
    "fleet_orchestration_manifest",
    "safety_alert_budget",
]
