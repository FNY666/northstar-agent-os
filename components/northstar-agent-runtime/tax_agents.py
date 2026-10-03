"""Tax & customs AI discipline (one-hundred-forty-eighth batch).

Absorbs the 2026 AI-tax/customs research thread:

* **Japan KSK2** — next-gen national tax system: AI plus all-tax data
  unification, full operation planned 2026-09; scale makes every
  selection rule a mass-harm risk.
* **Korea "AI 대전환"** — decades of audit know-how training AI to
  extract evasion suspects; AI auto-writes tax returns by 2028;
  ₩300M crypto-analysis system built 2026-04→11, pilot November;
  burden of proof sits on the taxpayer — the receipts below must
  carry the state's burden, not the taxpayer's.
* **China Golden Tax IV ("以数治税")** — corporate "digital
  portraits", real-time risk warnings; complaints of compliant firms
  mislabeled high-risk (flag ≠ fraud, again).
* **US H.R. 9501 "AI Tax Integrity Act"** — a bill, not law; TIGTA
  recommends training AI on historical audits — Bloomberg Law warns
  of replaying the Dutch disaster (Stanford–Treasury: Black
  taxpayers audited 4.7x more).
* **UK HMRC £175M AI plan** — social-media lifestyle vs declared
  income matching (misidentification risk on thin signals).
* **Pakistan FBR** — AI flags expanded to the 2026 tax year with
  the official wording that "flagged discrepancies need review but
  do not themselves constitute fraud" — flag≠fraud is now an
  official doctrine, encoded here.
* **Greece** — 194,000 AI audits planned for 2026; mass selection
  needs mass appeal capacity.
* **Australia** — ATO pairs AI with Airbnb data on holiday-home
  deductions, but a reverse audit found ~3/4 of 43 AI models had no
  ethics assessment and were irreproducible; Robodebt was ruled
  unlawful by the federal court — automation at scale needs
  registration before deployment.
* **Tunisia / Burkina Faso** — customs model simulated 96.9M
  dinars detected at a 49.23% detection rate; DGI deploys AI while
  drafting a generative-AI ethics charter.
* **US CBP "Detective Border"** — pre-release AI risk scoring for
  transshipment fraud ($40B–$303B/year): scores are leads, not
  verdicts; pre-arrival scores may hold for inspection, never
  auto-seize.
* **China smart ports: Fuzhou "乐宝"** — 15-second frictionless
  clearance with the explicit doctrine "AI for efficiency, humans
  for responsibility" (8s pre-screen + officer review).
* **Qatar customs (Arabic)** — HSsify intelligent HS classification:
  AI suggestions, officer final decision, agentic AI under officer
  authority.
* **Dubai ACI / Mexico "Coatlicue"** — pre-arrival AI analysis;
  SAT×customs data fusion on a supercomputer (fusion across
  agencies needs a registration boundary too).
* **The Dutch Toeslagenaffaire** — tens of thousands mislabeled
  fraud, nationality as a risk factor, the 2021 cabinet collapse;
  2026: the Dutch tax authority fined €3.7M for unregistered AI
  (single source — verify before assurance reliance).
* **EU AI Act gap** — tax-enforcement AI is excluded from Annex III
  (Recital 59); the Omnibus proposal defers Annex III obligations
  to 2027-12-02. A tax AI can be legally outside Annex III and
  still be held to a public clock.

Northstar mapping: a flag is a lead — an automatic fraud accusation
from a flag is ``tax.auto_fraud_accusation`` (Pakistan lesson);
nationality/zip-code features are banned whole-class, not
down-weighted (Toeslagenaffaire lesson); historical-data debias
audits must be receipted before training (Stanford–Treasury 4.7x
lesson); assessments need a named-human signature, and an override
rate at or below 2% reads as rubber-stamping
(``tax.rubber_stamp``); every AI-influenced assessment binds an
appeal path with a minimum 30-day window; selections bind "why me"
explanation receipts issued within 72 hours; unregistered AI is
``tax.shadow_ai`` (Dutch €3.7M lesson); the Annex III clock keeps a
public compliance date even where the law is silent; pre-arrival
risk scores may only hold consignments for inspection, never
auto-seize (``tax.customs_auto_seizure``); AI proposes, the officer
disposes (Fuzhou/Qatar lesson).

Deterministic: no wall-clock reads (callers inject ``now`` as an
integer epoch), canonical JCS hashing (ninety-fifth batch), and all
digest comparisons use :func:`hmac.compare_digest`.

Honest scope:

* The receipts bind the *declared* tax discipline; they do not make
  taxation fair. A signed explanation receipt can still explain a
  policy choice the taxpayer rejects.
* Feature-class bans are syntactic: a banned signal re-encoded
  through a proxy feature is not caught here — that needs the
  disparate-impact probe plus outside audit.
* The Annex III clock is a self-binding public clock, not a legal
  opinion; it cannot create obligations the EU AI Act did not
  create (tax-enforcement AI is excluded from Annex III).
* Signature checks bind authority to receipt; they cannot prove
  the human named on the signoff actually examined the file.
* Denial codes and thresholds (4.0x disparity, 2% override, 30-day
  window, 72-hour explanation) are bench parameters from the 2026
  research sweep; confirm against the jurisdiction's own tax
  procedure before reliance.
"""

from __future__ import annotations

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


TAX_SCHEMA_VERSION = "northstar.tax.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128
_DAY_S = 86_400

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Features banned whole-class from tax-selection models
#: (Toeslagenaffaire lesson: nationality as a risk factor must not
#: be down-weighted, it must be absent).
BANNED_FEATURES = frozenset({
    "nationality",
    "country_of_birth",
    "place_of_birth",
    "ethnicity",
    "zip_code",
    "postal_code",
    "native_language",
})

#: Disparate-impact line: highest/lowest nonzero slice flag-rate
#: ratio above this quarantines the model.
DISPARITY_RATIO_MAX = 4.0

#: Rubber-stamp line: override rates at or below this are
#: automation bias, not supervision.
OVERRIDE_RUBBER_STAMP_MAX = 0.02

#: Minimum override-rate sample size before the rubber-stamp read
#: applies (small samples are noise, not ceremony).
OVERRIDE_MIN_DECISIONS = 50

#: Flag shelf life: acting on a stale flag denies.
FLAG_MAX_AGE_S = 180 * _DAY_S

#: Training-data audit shelf life before retraining needs a new one.
TRAINING_AUDIT_MAX_AGE_S = 365 * _DAY_S

#: Assessment signoff shelf life.
SIGNOFF_MAX_AGE_S = 90 * _DAY_S

#: Minimum appeal window (opened -> deadline).
APPEAL_MIN_WINDOW_S = 30 * _DAY_S

#: Explanation deadline after a selection is made.
EXPLANATION_DEADLINE_S = 72 * 3_600

#: Pre-arrival customs score freshness.
CUSTOMS_SCORE_MAX_AGE_S = 48 * 3_600

#: EU AI Act Omnibus deferral: Annex III obligations deferred to
#: 2027-12-02 (Recital 59 still excludes tax-enforcement AI, so the
#: clock is a self-binding public commitment, not a legal reading).
ANNEX_III_OMNIBUS_EPOCH = 1_827_705_600

#: Actions a flag may trigger. Anything else — accusation, penalty,
#: assessment adjustment — is an automatic fraud accusation.
FLAG_LEAD_ACTIONS = frozenset({
    "queue_review",
    "request_information",
    "schedule_audit",
})
FLAG_ACCUSATORY_ACTIONS = frozenset({
    "accuse_fraud",
    "assess_penalty",
    "adjust_assessment",
})

#: Actions a pre-arrival risk score may take on a consignment.
CUSTOMS_LEAD_ACTIONS = frozenset({
    "release",
    "hold_for_inspection",
    "escalate_to_officer",
})
CUSTOMS_SEIZURE_ACTIONS = frozenset({
    "seize",
    "destroy",
    "fine",
    "deny_entry",
})


class TaxError(ValueError):
    """A malformed tax-discipline receipt or a programming error.

    Raised for structural problems (bad digests, unknown registries,
    broken chains). Verification *failures* (auto fraud accusation,
    banned features, shadow AI, rubber-stamp oversight) return a
    :class:`TaxVerdict` with ``allowed=False`` instead — a failed
    gate is a verdict, a malformed receipt is a bug.
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
        raise TaxError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TaxError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TaxError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise TaxError("authority_pubkey_hex must be a 64-char lowercase hex digest")
    return value


def _check_ratio(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TaxError(f"{field_name} must be a number")
    if not 0.0 <= value <= 1.0:
        raise TaxError(f"{field_name} must be in [0, 1]")
    return float(value)


def _check_features(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise TaxError(f"{field_name} must be a non-empty list of feature names")
    out = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise TaxError(f"{field_name} entries must be non-empty strings")
        out.append(item)
    return tuple(out)


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
    """Raise :class:`TaxError` if a receipt log is tampered/broken."""
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise TaxError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise TaxError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(
            entry.authority_pubkey_hex, signed_body, entry.signature_hex
        ):
            raise TaxError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class TaxVerdict:
    """Outcome of one tax-discipline gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> TaxVerdict:
    return TaxVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> TaxVerdict:
    return TaxVerdict(
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


def _issue_common(
    registry: Any,
    receipt: Any,
    authority_id: str,
    signature: bytes,
    type_name: str,
) -> Any:
    pubkey = registry.authorities.pubkey(authority_id)
    if pubkey is None:
        raise TaxError(f"unknown authority {authority_id!r}")
    signed_body = dict(receipt._payload())
    signed_body["signature_hex"] = "00" * 64
    if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
        raise TaxError(f"{type_name} receipt authority signature invalid")
    registry.log.append(receipt)
    return receipt


def _new_log(registry: Any) -> str:
    return registry.log[-1].receipt_digest if registry.log else _GENESIS


# ---------------------------------------------------------------------------
# 1. Flag ≠ fraud (Pakistan FBR lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FlagLead:
    """An AI-raised flag: a lead, never an accusation."""

    flag_id: str
    subject_id: str
    model_id: str
    raised_at: int
    score: float
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str


def flag_not_fraud_gate(flag: FlagLead, action: str, acted_at: int) -> TaxVerdict:
    """A flag is a lead; an automatic fraud accusation from a flag is
    ``tax.auto_fraud_accusation``.

    Allowed actions queue human work (review, information requests,
    scheduled audits). Accusatory actions — fraud accusations,
    penalties, assessment adjustments — fail closed. Stale flags
    (older than :data:`FLAG_MAX_AGE_S`) cannot be acted on, and a bad
    flag signature reads as no flag.
    """
    _check_ts(acted_at, "acted_at")
    if not isinstance(flag, FlagLead):
        raise TaxError("flag must be a FlagLead")
    _check_nonempty_str(flag.flag_id, "flag.flag_id")
    _check_nonempty_str(flag.subject_id, "flag.subject_id")
    _check_nonempty_str(flag.model_id, "flag.model_id")
    _check_ts(flag.raised_at, "flag.raised_at")
    _check_ratio(flag.score, "flag.score")
    _check_nonempty_str(action, "action")
    payload = {
        "schema": TAX_SCHEMA_VERSION,
        "type": "flag_lead",
        "flag_id": flag.flag_id,
        "subject_id": flag.subject_id,
        "model_id": flag.model_id,
        "raised_at": flag.raised_at,
        "score": flag.score,
        "authority_id": flag.authority_id,
    }
    if not _verify_signature(flag.authority_pubkey_hex, payload, flag.signature_hex):
        return _deny(
            "tax:flag_sig_invalid",
            f"flag {flag.flag_id!r} authority signature invalid",
        )
    if flag.raised_at > acted_at:
        return _deny(
            "tax:future_flag",
            f"flag {flag.flag_id!r} raised in the future",
        )
    if acted_at - flag.raised_at > FLAG_MAX_AGE_S:
        return _deny(
            "tax:stale_flag",
            f"flag {flag.flag_id!r} is older than {FLAG_MAX_AGE_S // _DAY_S} days",
        )
    if action in FLAG_ACCUSATORY_ACTIONS:
        return _deny(
            "tax:auto_fraud_accusation",
            f"action {action!r} treats flag {flag.flag_id!r} as fraud; "
            "flags are leads, not accusations (Pakistan FBR doctrine)",
        )
    if action not in FLAG_LEAD_ACTIONS:
        return _deny(
            "tax:unknown_flag_action",
            f"action {action!r} is not a registered flag-lead action",
        )
    return _allow(f"flag {flag.flag_id!r} action {action!r} is lead-grade")


# ---------------------------------------------------------------------------
# 2. Selection-bias probe (Toeslagenaffaire lesson)
# ---------------------------------------------------------------------------


def selection_bias_probe(
    feature_names: Any,
    slice_flag_rates: Any,
    checked_at: int,
) -> TaxVerdict:
    """Banned features are banned whole-class; slice-rate disparity is
    quarantined.

    Nationality / zip-code / ethnicity-style features
    (:data:`BANNED_FEATURES`) may not appear in a selection model at
    all — down-weighting is not a remedy (Toeslagenaffaire lesson).
    Independently, if the highest nonzero slice flag rate divided by
    the lowest exceeds :data:`DISPARITY_RATIO_MAX`, the model is
    quarantined for a disparate-impact audit
    (``tax:disparate_impact``).
    """
    features = _check_features(feature_names, "feature_names")
    _check_ts(checked_at, "checked_at")
    banned = sorted({f for f in features if f in BANNED_FEATURES})
    if banned:
        return _deny(
            "tax:banned_feature",
            f"selection model uses whole-class banned features: "
            f"{', '.join(banned)}",
        )
    if not isinstance(slice_flag_rates, (list, tuple)) or not slice_flag_rates:
        return _deny(
            "tax:probe_empty_rates",
            "selection-bias probe measured no slice rates",
        )
    rates = [float(r) for r in slice_flag_rates if float(r) > 0]
    if not rates:
        return _deny(
            "tax:probe_empty_rates",
            "selection-bias probe measured only zero slice rates",
        )
    max_ratio = max(rates) / min(rates)
    if max_ratio > DISPARITY_RATIO_MAX:
        return _deny(
            "tax:disparate_impact",
            f"slice flag-rate ratio {max_ratio:.2f} exceeds "
            f"{DISPARITY_RATIO_MAX}; quarantine for disparate-impact audit",
        )
    return _allow(f"feature set clean; max slice ratio {max_ratio:.2f}")


# ---------------------------------------------------------------------------
# 3. Training-data audit receipts (Stanford–Treasury 4.7x lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrainingDataAuditReceipt:
    """Binds a model to a debias audit of its historical training data."""

    receipt_id: str
    model_id: str
    historical_audit_slice_id: str
    debias_digest: str
    auditor_id: str
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TAX_SCHEMA_VERSION,
            "type": "training_data_audit",
            "receipt_id": self.receipt_id,
            "model_id": self.model_id,
            "historical_audit_slice_id": self.historical_audit_slice_id,
            "debias_digest": self.debias_digest,
            "auditor_id": self.auditor_id,
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
class TrainingDataAuditRegistry:
    """Hash-chained log of training-data debias audits."""

    authorities: AuthorityRegistry
    log: list[TrainingDataAuditReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        model_id: str,
        historical_audit_slice_id: str,
        debias_digest: str,
        auditor_id: str,
        issued_at: int,
        authority_id: str,
        signature: bytes,
    ) -> TrainingDataAuditReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(model_id, "model_id")
        _check_nonempty_str(historical_audit_slice_id, "historical_audit_slice_id")
        _check_hex64(debias_digest, "debias_digest")
        _check_nonempty_str(auditor_id, "auditor_id")
        _check_ts(issued_at, "issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise TaxError(f"unknown authority {authority_id!r}")
        receipt = TrainingDataAuditReceipt(
            receipt_id=receipt_id,
            model_id=model_id,
            historical_audit_slice_id=historical_audit_slice_id,
            debias_digest=debias_digest,
            auditor_id=auditor_id,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=_new_log(self),
        )
        return _issue_common(self, receipt, authority_id, signature, "training_data_audit")

    def find(self, model_id: str) -> TrainingDataAuditReceipt | None:
        for entry in reversed(self.log):
            if entry.model_id == model_id:
                return entry
        return None


def training_data_audit(
    registry: TrainingDataAuditRegistry,
    model_id: str,
    now: int,
) -> TaxVerdict:
    """Training on historical audit data needs a fresh debias-audit
    receipt.

    Historical enforcement data replays historical enforcement bias
    (Stanford–Treasury 4.7x lesson); a model may not train without a
    receipted debias audit of its training slice, fresh within
    :data:`TRAINING_AUDIT_MAX_AGE_S`.
    """
    _check_nonempty_str(model_id, "model_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "training_data_audit")
    except TaxError as exc:
        return _deny("tax:chain_broken", str(exc))
    entry = registry.find(model_id)
    if entry is None:
        return _deny(
            "tax:no_training_audit",
            f"model {model_id!r} has no debias audit of its historical "
            "training data",
        )
    if entry.issued_at > now:
        return _deny(
            "tax:future_training_audit",
            f"training-data audit for {model_id!r} issued in the future",
        )
    if now - entry.issued_at > TRAINING_AUDIT_MAX_AGE_S:
        return _deny(
            "tax:stale_training_audit",
            f"training-data audit for {model_id!r} is older than "
            f"{TRAINING_AUDIT_MAX_AGE_S // _DAY_S} days",
        )
    return _allow(
        f"model {model_id!r} training-data debias audit live",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 4. Human-final gate (named signature; rubber-stamp reads)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentSignoffReceipt:
    """Binds a tax assessment to a named human's signature."""

    receipt_id: str
    assessment_id: str
    assessment_digest: str
    human_id: str
    signed_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TAX_SCHEMA_VERSION,
            "type": "assessment_signoff",
            "receipt_id": self.receipt_id,
            "assessment_id": self.assessment_id,
            "assessment_digest": self.assessment_digest,
            "human_id": self.human_id,
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
class AssessmentSignoffRegistry:
    """Hash-chained log of assessment signoffs."""

    authorities: AuthorityRegistry
    log: list[AssessmentSignoffReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        assessment_id: str,
        assessment_digest: str,
        human_id: str,
        signed_at: int,
        authority_id: str,
        signature: bytes,
    ) -> AssessmentSignoffReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(assessment_id, "assessment_id")
        _check_hex64(assessment_digest, "assessment_digest")
        _check_nonempty_str(human_id, "human_id")
        _check_ts(signed_at, "signed_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise TaxError(f"unknown authority {authority_id!r}")
        receipt = AssessmentSignoffReceipt(
            receipt_id=receipt_id,
            assessment_id=assessment_id,
            assessment_digest=assessment_digest,
            human_id=human_id,
            signed_at=signed_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=_new_log(self),
        )
        return _issue_common(self, receipt, authority_id, signature, "assessment_signoff")

    def find(self, assessment_id: str) -> AssessmentSignoffReceipt | None:
        for entry in reversed(self.log):
            if entry.assessment_id == assessment_id:
                return entry
        return None


@dataclass
class OfficerOverrideRate:
    """Aggregate override statistics for one named human."""

    human_id: str
    decisions: int
    overrides: int


def human_final_gate(
    signoff_registry: AssessmentSignoffRegistry,
    assessment_id: str,
    now: int,
    override_rates: Mapping[str, OfficerOverrideRate] | None = None,
) -> TaxVerdict:
    """An assessment is final only with a named-human signature.

    The signoff must exist, be fresh within
    :data:`SIGNOFF_MAX_AGE_S`, and bind the assessment digest. Where
    override statistics are supplied, a named human whose override
    rate is at or below :data:`OVERRIDE_RUBBER_STAMP_MAX` over at
    least :data:`OVERRIDE_MIN_DECISIONS` decisions is rubber-stamping:
    ``tax.rubber_stamp`` — the signature is ceremonial, not
    supervision.
    """
    _check_nonempty_str(assessment_id, "assessment_id")
    _check_ts(now, "now")
    try:
        _check_chain(signoff_registry.log, "assessment_signoff")
    except TaxError as exc:
        return _deny("tax:chain_broken", str(exc))
    entry = signoff_registry.find(assessment_id)
    if entry is None:
        return _deny(
            "tax:unsigned_assessment",
            f"assessment {assessment_id!r} carries no named-human signature",
        )
    if entry.signed_at > now:
        return _deny(
            "tax:future_signoff",
            f"signoff for {assessment_id!r} is dated in the future",
        )
    if now - entry.signed_at > SIGNOFF_MAX_AGE_S:
        return _deny(
            "tax:stale_signoff",
            f"signoff for {assessment_id!r} is older than "
            f"{SIGNOFF_MAX_AGE_S // _DAY_S} days",
        )
    if override_rates is not None:
        rate = override_rates.get(entry.human_id)
        if rate is not None and rate.decisions >= OVERRIDE_MIN_DECISIONS:
            override_ratio = rate.overrides / rate.decisions
            if override_ratio <= OVERRIDE_RUBBER_STAMP_MAX:
                return _deny(
                    "tax:rubber_stamp",
                    f"{entry.human_id!r} overrides {override_ratio:.3%} of "
                    f"AI proposals over {rate.decisions} decisions — "
                    "supervision is ceremonial",
                )
    return _allow(
        f"assessment {assessment_id!r} signed by {entry.human_id!r}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 5. Appeal window (every AI-influenced assessment binds an appeal path)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AppealBindingReceipt:
    """Binds an assessment to an appeal channel with a live window."""

    receipt_id: str
    assessment_id: str
    channel_id: str
    opened_at: int
    deadline: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TAX_SCHEMA_VERSION,
            "type": "appeal_binding",
            "receipt_id": self.receipt_id,
            "assessment_id": self.assessment_id,
            "channel_id": self.channel_id,
            "opened_at": self.opened_at,
            "deadline": self.deadline,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class AppealBindingRegistry:
    """Hash-chained log of appeal bindings."""

    authorities: AuthorityRegistry
    log: list[AppealBindingReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        assessment_id: str,
        channel_id: str,
        opened_at: int,
        deadline: int,
        authority_id: str,
        signature: bytes,
    ) -> AppealBindingReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(assessment_id, "assessment_id")
        _check_nonempty_str(channel_id, "channel_id")
        _check_ts(opened_at, "opened_at")
        _check_ts(deadline, "deadline")
        if deadline <= opened_at:
            raise TaxError("appeal deadline must be after opened_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise TaxError(f"unknown authority {authority_id!r}")
        receipt = AppealBindingReceipt(
            receipt_id=receipt_id,
            assessment_id=assessment_id,
            channel_id=channel_id,
            opened_at=opened_at,
            deadline=deadline,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=_new_log(self),
        )
        return _issue_common(self, receipt, authority_id, signature, "appeal_binding")

    def find(self, assessment_id: str) -> AppealBindingReceipt | None:
        for entry in reversed(self.log):
            if entry.assessment_id == assessment_id:
                return entry
        return None


def appeal_window(
    registry: AppealBindingRegistry,
    assessment_id: str,
    now: int,
    enforcing: bool = False,
) -> TaxVerdict:
    """An AI-influenced assessment must bind an appeal path with a
    minimum 30-day window.

    No binding → ``tax.no_appeal_path``; a window shorter than
    :data:`APPEAL_MIN_WINDOW_S` → ``tax.appeal_window_too_short``.
    When ``enforcing`` is true and the window is still open,
    enforcement is ``tax.appeal_window_open`` — the taxpayer's right
    to appeal must outlive the collection attempt.
    """
    _check_nonempty_str(assessment_id, "assessment_id")
    _check_ts(now, "now")
    if not isinstance(enforcing, bool):
        raise TaxError("enforcing must be a bool")
    try:
        _check_chain(registry.log, "appeal_binding")
    except TaxError as exc:
        return _deny("tax:chain_broken", str(exc))
    entry = registry.find(assessment_id)
    if entry is None:
        return _deny(
            "tax:no_appeal_path",
            f"assessment {assessment_id!r} binds no appeal path",
        )
    if entry.deadline - entry.opened_at < APPEAL_MIN_WINDOW_S:
        return _deny(
            "tax:appeal_window_too_short",
            f"appeal window for {assessment_id!r} is "
            f"{(entry.deadline - entry.opened_at) // _DAY_S} days "
            f"(minimum {APPEAL_MIN_WINDOW_S // _DAY_S})",
        )
    if enforcing and now < entry.deadline:
        return _deny(
            "tax:appeal_window_open",
            f"enforcement of {assessment_id!r} attempted while the "
            "appeal window is still open",
        )
    return _allow(
        f"assessment {assessment_id!r} appeal path {entry.channel_id!r} bound",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 6. Explanation receipts ("why me")
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExplanationReceipt:
    """Binds a selection to a "why me" explanation for the taxpayer."""

    receipt_id: str
    selection_id: str
    factor_labels: tuple[str, ...]
    selected_at: int
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TAX_SCHEMA_VERSION,
            "type": "explanation",
            "receipt_id": self.receipt_id,
            "selection_id": self.selection_id,
            "factor_labels": list(self.factor_labels),
            "selected_at": self.selected_at,
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
class ExplanationRegistry:
    """Hash-chained log of "why me" explanations."""

    authorities: AuthorityRegistry
    log: list[ExplanationReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        selection_id: str,
        factor_labels: Any,
        selected_at: int,
        issued_at: int,
        authority_id: str,
        signature: bytes,
    ) -> ExplanationReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(selection_id, "selection_id")
        factors = _check_features(factor_labels, "factor_labels")
        _check_ts(selected_at, "selected_at")
        _check_ts(issued_at, "issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise TaxError(f"unknown authority {authority_id!r}")
        receipt = ExplanationReceipt(
            receipt_id=receipt_id,
            selection_id=selection_id,
            factor_labels=factors,
            selected_at=selected_at,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=_new_log(self),
        )
        return _issue_common(self, receipt, authority_id, signature, "explanation")

    def find(self, selection_id: str) -> ExplanationReceipt | None:
        for entry in reversed(self.log):
            if entry.selection_id == selection_id:
                return entry
        return None


def explanation_receipt(
    registry: ExplanationRegistry,
    selection_id: str,
    now: int,
) -> TaxVerdict:
    """A selection needs a "why me" explanation receipt issued within
    72 hours.

    Missing → ``tax.no_explanation``; late → ``tax.explanation_stale``;
    an explanation citing a banned feature → ``tax.explanation_banned_factor``.
    """
    _check_nonempty_str(selection_id, "selection_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "explanation")
    except TaxError as exc:
        return _deny("tax:chain_broken", str(exc))
    entry = registry.find(selection_id)
    if entry is None:
        return _deny(
            "tax:no_explanation",
            f"selection {selection_id!r} has no 'why me' explanation receipt",
        )
    banned = sorted({f for f in entry.factor_labels if f in BANNED_FEATURES})
    if banned:
        return _deny(
            "tax:explanation_banned_factor",
            f"explanation for {selection_id!r} cites banned features: "
            f"{', '.join(banned)}",
        )
    if entry.issued_at < entry.selected_at:
        return _deny(
            "tax:explanation_predated",
            f"explanation for {selection_id!r} predates the selection",
        )
    if entry.issued_at - entry.selected_at > EXPLANATION_DEADLINE_S:
        return _deny(
            "tax:explanation_stale",
            f"explanation for {selection_id!r} issued "
            f"{(entry.issued_at - entry.selected_at) // 3_600}h after "
            "selection (limit 72h)",
        )
    return _allow(
        f"selection {selection_id!r} explanation live",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 7. Shadow-AI registry (Dutch €3.7M lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelRegistrationReceipt:
    """Binds a model id + digest to a public registration."""

    receipt_id: str
    model_id: str
    model_digest: str
    jurisdiction: str
    registered_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": TAX_SCHEMA_VERSION,
            "type": "model_registration",
            "receipt_id": self.receipt_id,
            "model_id": self.model_id,
            "model_digest": self.model_digest,
            "jurisdiction": self.jurisdiction,
            "registered_at": self.registered_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class ModelRegistrationRegistry:
    """Hash-chained log of registered tax AI."""

    authorities: AuthorityRegistry
    log: list[ModelRegistrationReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        model_id: str,
        model_digest: str,
        jurisdiction: str,
        registered_at: int,
        authority_id: str,
        signature: bytes,
    ) -> ModelRegistrationReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(model_id, "model_id")
        _check_hex64(model_digest, "model_digest")
        _check_nonempty_str(jurisdiction, "jurisdiction")
        _check_ts(registered_at, "registered_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise TaxError(f"unknown authority {authority_id!r}")
        receipt = ModelRegistrationReceipt(
            receipt_id=receipt_id,
            model_id=model_id,
            model_digest=model_digest,
            jurisdiction=jurisdiction,
            registered_at=registered_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=_new_log(self),
        )
        return _issue_common(self, receipt, authority_id, signature, "model_registration")

    def find(self, model_id: str) -> ModelRegistrationReceipt | None:
        for entry in reversed(self.log):
            if entry.model_id == model_id:
                return entry
        return None


def shadow_ai_registry(
    registry: ModelRegistrationRegistry,
    model_id: str,
    model_digest: str,
    now: int,
) -> TaxVerdict:
    """Tax AI in production must be registered.

    Unregistered models — and registered models whose digest no
    longer matches (digest swap) — are ``tax.shadow_ai`` (Dutch
    €3.7M lesson: unregistered tax AI is the incident).
    """
    _check_nonempty_str(model_id, "model_id")
    _check_hex64(model_digest, "model_digest")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "model_registration")
    except TaxError as exc:
        return _deny("tax:chain_broken", str(exc))
    entry = registry.find(model_id)
    if entry is None:
        return _deny(
            "tax:shadow_ai",
            f"model {model_id!r} has no tax-AI registration",
        )
    if not hmac.compare_digest(entry.model_digest, model_digest):
        return _deny(
            "tax:shadow_ai",
            f"model {model_id!r} digest does not match its registration "
            "(possible digest swap)",
        )
    if entry.registered_at > now:
        return _deny(
            "tax:future_registration",
            f"model {model_id!r} registration dated in the future",
        )
    return _allow(
        f"model {model_id!r} registered in {entry.jurisdiction!r}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 8. Annex III clock (EU AI Act gap + Omnibus deferral)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AnnexIIIPlan:
    """An authority's self-binding compliance posture.

    Because tax-enforcement AI is excluded from Annex III (Recital
    59), this clock records the authority's *declared* posture:
    voluntary alignment by a target date, or an explicit "excluded,
    no plan" declaration. The gate is fail-closed on silence, not on
    the law: an undeclared posture cannot proceed.
    """

    jurisdiction: str
    posture: str  # "voluntary_alignment" | "excluded_no_plan"
    target_at: int
    milestones_completed: int
    total_milestones: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str


def annex_iii_clock(plan: AnnexIIIPlan, now: int) -> TaxVerdict:
    """The EU AI Act compliance clock for tax AI.

    Tax-enforcement AI sits outside Annex III (Recital 59); the
    Omnibus proposal defers Annex III obligations to 2027-12-02. This
    clock cannot create obligations the law did not create — it
    verifies the authority's declared posture instead: no declared
    posture → ``tax.no_annex_iii_plan``; an "excluded, no plan"
    declaration → ``tax.annex_iii_excluded``; past the target with
    incomplete milestones → ``tax.annex_iii_overdue``.
    """
    _check_ts(now, "now")
    if not isinstance(plan, AnnexIIIPlan):
        raise TaxError("plan must be an AnnexIIIPlan")
    _check_nonempty_str(plan.jurisdiction, "plan.jurisdiction")
    if plan.posture not in ("voluntary_alignment", "excluded_no_plan"):
        return _deny(
            "tax:no_annex_iii_plan",
            f"{plan.jurisdiction!r} declared no recognizable Annex III posture",
        )
    _check_ts(plan.target_at, "plan.target_at")
    if not isinstance(plan.milestones_completed, int) or plan.milestones_completed < 0:
        raise TaxError("plan.milestones_completed must be a non-negative int")
    if not isinstance(plan.total_milestones, int) or plan.total_milestones < 0:
        raise TaxError("plan.total_milestones must be a non-negative int")
    payload = {
        "schema": TAX_SCHEMA_VERSION,
        "type": "annex_iii_plan",
        "jurisdiction": plan.jurisdiction,
        "posture": plan.posture,
        "target_at": plan.target_at,
        "milestones_completed": plan.milestones_completed,
        "total_milestones": plan.total_milestones,
        "authority_id": plan.authority_id,
    }
    if not _verify_signature(plan.authority_pubkey_hex, payload, plan.signature_hex):
        return _deny(
            "tax:annex_iii_sig_invalid",
            f"Annex III plan for {plan.jurisdiction!r} has an invalid "
            "authority signature",
        )
    if plan.posture == "excluded_no_plan":
        return _deny(
            "tax:annex_iii_excluded",
            f"{plan.jurisdiction!r} declares Annex III excluded with no "
            "voluntary plan — fail-closed on silence",
        )
    if now > plan.target_at:
        if plan.total_milestones > 0 and plan.milestones_completed >= plan.total_milestones:
            return _allow(f"{plan.jurisdiction!r} Annex III alignment complete")
        return _deny(
            "tax:annex_iii_overdue",
            f"{plan.jurisdiction!r} passed its declared Annex III target "
            f"({plan.milestones_completed}/{plan.total_milestones} milestones)",
        )
    return _allow(
        f"{plan.jurisdiction!r} Annex III clock running "
        f"({plan.milestones_completed}/{plan.total_milestones} milestones)"
    )


# ---------------------------------------------------------------------------
# 9. Customs lead gate (CBP "Detective Border" lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PreArrivalScore:
    """An AI risk score issued before a consignment arrives."""

    consignment_id: str
    model_id: str
    score: float
    scored_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str


def customs_lead_gate(
    prescore: PreArrivalScore,
    action: str,
    now: int,
    officer_id: str = "",
) -> TaxVerdict:
    """Pre-arrival risk scores may only hold for inspection — never
    auto-seize.

    A score is a lead: the allowed outcomes are release, hold for
    inspection (which must name a reviewing officer), or escalation
    to an officer. Seizure, destruction, fines, and automatic entry
    denial from a score are ``tax.customs_auto_seizure`` (CBP
    lesson). Stale scores and bad signatures read as no score.
    """
    _check_ts(now, "now")
    _check_nonempty_str(action, "action")
    if not isinstance(prescore, PreArrivalScore):
        raise TaxError("prescore must be a PreArrivalScore")
    _check_nonempty_str(prescore.consignment_id, "prescore.consignment_id")
    _check_nonempty_str(prescore.model_id, "prescore.model_id")
    _check_ratio(prescore.score, "prescore.score")
    _check_ts(prescore.scored_at, "prescore.scored_at")
    payload = {
        "schema": TAX_SCHEMA_VERSION,
        "type": "prearrival_score",
        "consignment_id": prescore.consignment_id,
        "model_id": prescore.model_id,
        "score": prescore.score,
        "scored_at": prescore.scored_at,
        "authority_id": prescore.authority_id,
    }
    if not _verify_signature(
        prescore.authority_pubkey_hex, payload, prescore.signature_hex
    ):
        return _deny(
            "tax:customs_score_sig_invalid",
            f"pre-arrival score for {prescore.consignment_id!r} has an "
            "invalid authority signature",
        )
    if prescore.scored_at > now:
        return _deny(
            "tax:customs_score_future",
            f"pre-arrival score for {prescore.consignment_id!r} dated in "
            "the future",
        )
    if now - prescore.scored_at > CUSTOMS_SCORE_MAX_AGE_S:
        return _deny(
            "tax:customs_score_stale",
            f"pre-arrival score for {prescore.consignment_id!r} is older "
            f"than {CUSTOMS_SCORE_MAX_AGE_S // 3_600}h",
        )
    if action in CUSTOMS_SEIZURE_ACTIONS:
        return _deny(
            "tax:customs_auto_seizure",
            f"action {action!r} on consignment {prescore.consignment_id!r} "
            "is a seizure-class decision from a risk score — scores may "
            "only hold for inspection",
        )
    if action not in CUSTOMS_LEAD_ACTIONS:
        return _deny(
            "tax:customs_unknown_action",
            f"action {action!r} is not a registered score-lead action",
        )
    if action == "hold_for_inspection" and not officer_id.strip():
        return _deny(
            "tax:customs_hold_unassigned",
            f"hold of consignment {prescore.consignment_id!r} names no "
            "reviewing officer",
        )
    return _allow(
        f"consignment {prescore.consignment_id!r} action {action!r} is lead-grade"
    )


# ---------------------------------------------------------------------------
# 10. AI proposes, human disposes (Fuzhou / Qatar lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AIProposal:
    """An AI suggestion awaiting an officer's decision."""

    proposal_id: str
    recommended_action: str
    proposed_at: int
    model_id: str
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str


@dataclass(frozen=True)
class OfficerDecision:
    """A named officer's decision on an AI proposal."""

    proposal_id: str
    officer_id: str
    decision: str  # "accept" | "modify" | "reject"
    decided_at: int
    reviewed_evidence_digest: str
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str


def ai_proposes_human_disposes(
    proposal: AIProposal,
    decision: OfficerDecision | None,
    override_rates: Mapping[str, OfficerOverrideRate] | None = None,
) -> TaxVerdict:
    """AI suggests; the officer decides (Fuzhou/Qatar doctrine: AI for
    efficiency, humans for responsibility).

    A decision is valid only if it names an officer, attests evidence
    review (non-empty evidence digest), is issued after the proposal,
    and is authority-signed. No decision → ``tax.no_officer_decision``.
    Where override statistics are supplied, an officer whose override
    rate is at or below :data:`OVERRIDE_RUBBER_STAMP_MAX` over at
    least :data:`OVERRIDE_MIN_DECISIONS` decisions is rubber-stamping:
    ``tax.rubber_stamp``.
    """
    if not isinstance(proposal, AIProposal):
        raise TaxError("proposal must be an AIProposal")
    _check_nonempty_str(proposal.proposal_id, "proposal.proposal_id")
    _check_nonempty_str(proposal.recommended_action, "proposal.recommended_action")
    _check_ts(proposal.proposed_at, "proposal.proposed_at")
    proposal_payload = {
        "schema": TAX_SCHEMA_VERSION,
        "type": "ai_proposal",
        "proposal_id": proposal.proposal_id,
        "recommended_action": proposal.recommended_action,
        "proposed_at": proposal.proposed_at,
        "model_id": proposal.model_id,
        "authority_id": proposal.authority_id,
    }
    if not _verify_signature(
        proposal.authority_pubkey_hex, proposal_payload, proposal.signature_hex
    ):
        return _deny(
            "tax:proposal_sig_invalid",
            f"AI proposal {proposal.proposal_id!r} has an invalid "
            "authority signature",
        )
    if decision is None:
        return _deny(
            "tax:no_officer_decision",
            f"AI proposal {proposal.proposal_id!r} has no officer decision — "
            "AI proposes, it does not dispose",
        )
    if not isinstance(decision, OfficerDecision):
        raise TaxError("decision must be an OfficerDecision or None")
    if decision.proposal_id != proposal.proposal_id:
        return _deny(
            "tax:decision_mismatch",
            f"officer decision binds proposal {decision.proposal_id!r}, "
            f"not {proposal.proposal_id!r}",
        )
    _check_nonempty_str(decision.officer_id, "decision.officer_id")
    if decision.decision not in ("accept", "modify", "reject"):
        return _deny(
            "tax:decision_unknown",
            f"officer decision {decision.decision!r} is not accept/modify/reject",
        )
    _check_ts(decision.decided_at, "decision.decided_at")
    _check_hex64(decision.reviewed_evidence_digest, "decision.reviewed_evidence_digest")
    decision_payload = {
        "schema": TAX_SCHEMA_VERSION,
        "type": "officer_decision",
        "proposal_id": decision.proposal_id,
        "officer_id": decision.officer_id,
        "decision": decision.decision,
        "decided_at": decision.decided_at,
        "reviewed_evidence_digest": decision.reviewed_evidence_digest,
        "authority_id": decision.authority_id,
    }
    if not _verify_signature(
        decision.authority_pubkey_hex, decision_payload, decision.signature_hex
    ):
        return _deny(
            "tax:decision_sig_invalid",
            f"officer decision on {proposal.proposal_id!r} has an invalid "
            "authority signature",
        )
    if decision.decided_at <= proposal.proposed_at:
        return _deny(
            "tax:decision_predated",
            f"officer decision on {proposal.proposal_id!r} predates the "
            "AI proposal",
        )
    if override_rates is not None:
        rate = override_rates.get(decision.officer_id)
        if rate is not None and rate.decisions >= OVERRIDE_MIN_DECISIONS:
            override_ratio = rate.overrides / rate.decisions
            if override_ratio <= OVERRIDE_RUBBER_STAMP_MAX:
                return _deny(
                    "tax:rubber_stamp",
                    f"{decision.officer_id!r} overrides {override_ratio:.3%} "
                    f"of AI proposals over {rate.decisions} decisions — "
                    "the officer's discretion is ceremonial",
                )
    return _allow(
        f"proposal {proposal.proposal_id!r} disposed by {decision.officer_id!r} "
        f"({decision.decision})"
    )


__all__ = [
    "TAX_SCHEMA_VERSION",
    "BANNED_FEATURES",
    "DISPARITY_RATIO_MAX",
    "OVERRIDE_RUBBER_STAMP_MAX",
    "OVERRIDE_MIN_DECISIONS",
    "FLAG_MAX_AGE_S",
    "TRAINING_AUDIT_MAX_AGE_S",
    "SIGNOFF_MAX_AGE_S",
    "APPEAL_MIN_WINDOW_S",
    "EXPLANATION_DEADLINE_S",
    "CUSTOMS_SCORE_MAX_AGE_S",
    "ANNEX_III_OMNIBUS_EPOCH",
    "FLAG_LEAD_ACTIONS",
    "FLAG_ACCUSATORY_ACTIONS",
    "CUSTOMS_LEAD_ACTIONS",
    "CUSTOMS_SEIZURE_ACTIONS",
    "TaxError",
    "TaxVerdict",
    "AuthorityRegistry",
    "FlagLead",
    "flag_not_fraud_gate",
    "selection_bias_probe",
    "TrainingDataAuditReceipt",
    "TrainingDataAuditRegistry",
    "training_data_audit",
    "AssessmentSignoffReceipt",
    "AssessmentSignoffRegistry",
    "OfficerOverrideRate",
    "human_final_gate",
    "AppealBindingReceipt",
    "AppealBindingRegistry",
    "appeal_window",
    "ExplanationReceipt",
    "ExplanationRegistry",
    "explanation_receipt",
    "ModelRegistrationReceipt",
    "ModelRegistrationRegistry",
    "shadow_ai_registry",
    "AnnexIIIPlan",
    "annex_iii_clock",
    "PreArrivalScore",
    "customs_lead_gate",
    "AIProposal",
    "OfficerDecision",
    "ai_proposes_human_disposes",
]
