"""HR & workplace AI discipline (one-hundred-forty-first batch).

Absorbs the 2026 AI-HR research thread:

* **Algorithmic management goes white-collar** — >50% of companies use
  AI assisting pay/promotion/layoff decisions, ~20% let AI decide with
  no human at all, only 1/3 of users had compliance training
  (ResumeBuilder 2026). **JPMorgan** lets an internal bot assist
  writing reviews but bans it from scoring or deciding promotions
  (Bloomberg Law). Governance takeaway: the 127th-batch
  ``labor_algo`` gates covered blue-collar logistics; this module
  extends the same receipt discipline to hiring, reviews, and office
  work — assistance is allowed, *adjudication* without a named human
  is not.
* **Mobley v. Workday** — the ADEA class action was allowed to proceed
  with the court finding Workday may be liable *as the employer's
  agent*. Governance takeaway: vendors are pinned as the employer's
  agent (``hr:unpinned_vendor`` if not), so liability cannot be
  outsourced to a contract.
* **Kistler v. Eightfold AI (2026-01)** — led by the former EEOC chair,
  suing over secret scraping of 1B+ worker profiles scored 0-5. The
  cause of action is *secrecy*, not bias: FCRA-style
  disclosure/access/dispute as the weapon. Governance takeaway:
  worker-profile scoring without an FCRA-style disclosure receipt is
  ``hr:secret_scoring``.
* **Hiring "AI doom loop"** — 74% of candidates use AI to job-hunt,
  applications per role +111% (2022->2025) while recruiters fell 56%
  (Indeed CEO). **Xu simulation**: AI screeners pass AI-written
  resumes 23-60% more. Governance takeaway: same-model homophily
  beyond tolerance quarantines the screener for audit
  (``hr:homophily_audit``).
* **Newsom 2026-09-30 three laws** — ban AI+biometric emotion
  prediction, AI-led layoffs require written notice, ban pure-AI
  firings. Governance takeaway: emotion inference is a whole-class
  refusal (``hr:emotion_inference``); AI-involved layoffs bind a
  written-notice receipt (``hr:no_layoff_notice``).
* **California CPPA ADMT (2026-01-01)** — monitoring outputs used for
  assignments/pay/discipline are "significant employment decisions"
  requiring advance notice + appeal. Governance takeaway: repurposing
  monitoring data for employment decisions without a notice+appeal
  receipt is ``hr:surveillance_repurpose``.
* **Illinois HB 3773 (2026-01-01)** — bans discriminatory-effect AI,
  bans zip-code proxies, private right of action. Governance
  takeaway: zip codes and other proxies are a closed banned-feature
  vocabulary in audits.
* **NYC Local Law 144** — the state comptroller found 17 potential
  violations at 32 companies (the city regulator found 1);
  enforcement is tightening. Governance takeaway: self-audits are
  NON_AUTHORITATIVE; only independent third-party audit receipts
  count (auditor != vendor, ``hr:self_audit``).
* **EU Omnibus 2026/1744** — Annex III high-risk obligations deferred
  to 2027-12-02. Governance takeaway: the module pins the deferral
  clock; deferred does not mean deregulated.

Northstar mapping:

* ``audit_receipt()`` — a bias audit counts only as an independent
  third-party receipt (auditor != vendor), authority-signed, fresh.
  Self-audit -> NON_AUTHORITATIVE ``hr:self_audit``.
* ``secret_scoring_probe()`` — worker-profile AI scoring binds an
  FCRA-style disclosure receipt (disclosure given, access path,
  dispute path). Scoring without it -> ``hr:secret_scoring``.
* ``human_final_gate()`` — hiring/firing/promotion with AI involvement
  requires a named-human countersign bound to the evidence digest,
  with substantive-review evidence (review minutes >= floor,
  notes digest). No countersign -> ``hr:no_human_countersign``;
  countersign without review evidence -> ``hr:rubber_stamp``.
* ``emotion_inference_ban()`` — AI+biometric emotion/affect
  prediction is refused whole-class: ``hr:emotion_inference``.
* ``surveillance_purpose_receipt()`` — monitoring data repurposed
  for employment decisions requires an advance-notice receipt plus a
  bound appeal receipt. Without -> ``hr:surveillance_repurpose``.
* ``model_homophily_probe()`` — an AI-written vs human-written resume
  pass-rate probe; ratio beyond tolerance -> quarantine for audit
  ``hr:homophily_audit``.
* ``layoff_ai_disclosure()`` — AI-involved layoffs bind a
  written-notice receipt plus an evidence chain. Without ->
  ``hr:no_layoff_notice``.
* ``input_bias_inheritance()`` — unaudited evaluation outputs may not
  feed promotion/layoff/pay decisions: ``hr:tainted_input``.
  Performance reviews are the pollution source of all downstream
  decisions.
* ``vendor_agent_pin()`` — the vendor is pinned as the employer's
  agent (Mobley lesson). Unpinned -> ``hr:unpinned_vendor``.

Honest scoping: this module enforces *declared HR discipline* — the
software cannot authorize what is not declared, audited, and fresh.
It does not end workplace discrimination, audit real bias, or judge
the wisdom of a human decision (the countersign binds the *structure*
of review, not its quality). Everything is offline and deterministic;
the only clock is the ``now`` the caller injects (integer epoch
seconds). All digest comparisons use :func:`hmac.compare_digest`.
"""

from __future__ import annotations
from _domain_base import DomainError

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

try:  # ninety-fifth batch: the single canonicalizer
    from canonical_json import jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(
            _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True).encode("utf-8")
        ).hexdigest()

from ed25519 import public_key as _ed25519_pubkey
from ed25519 import sign as _ed25519_sign
from ed25519 import verify as _ed25519_verify

#: Schema marker, pinned into every digest.
SCHEMA_VERSION = "northstar.hr_agents.v1"

#: Minimum review minutes for a human countersign to count as
#: substantive (bench parameter, not a legal threshold).
MIN_REVIEW_MINUTES = 10

#: Maximum tolerated AI-written vs human-written resume pass-rate
#: ratio before the screener is quarantined for audit.
HOMOPHILY_RATIO_MAX = 1.25

#: Features that may never feed an employment model, even disclosed
#: (Illinois HB 3773 zip-code-proxy lesson; closed vocabulary).
BANNED_PROXY_FEATURES = frozenset(
    {"zip_code", "postal_code", "neighborhood_proxy", "name_ethnicity_signal"}
)

#: Closed vocabulary for AI+biometric affect uses that are refused
#: whole-class (California 2026-09-30 law).
EMOTION_USE_KINDS = frozenset(
    {
        "emotion_prediction",
        "sentiment_scoring",
        "engagement_inference",
        "deception_detection",
        "mood_classification",
    }
)

#: Closed vocabulary for employment decisions gated by human-final.
EMPLOYMENT_DECISIONS = frozenset(
    {"hiring", "firing", "promotion", "layoff", "pay", "discipline", "assignment"}
)

#: Denial reason codes. All start with ``hr:`` for audit filtering.
DENY_SELF_AUDIT = "hr:self_audit"
DENY_AUDIT_SIGNATURE_INVALID = "hr:audit_signature_invalid"
DENY_AUDIT_EXPIRED = "hr:audit_expired"
DENY_AUDIT_UNKNOWN = "hr:audit_unknown"
DENY_SECRET_SCORING = "hr:secret_scoring"
DENY_SCORING_DISCLOSURE_INVALID = "hr:scoring_disclosure_invalid"
DENY_NO_HUMAN_COUNTERSIGN = "hr:no_human_countersign"
DENY_RUBBER_STAMP = "hr:rubber_stamp"
DENY_COUNTERSIGN_SIGNATURE_INVALID = "hr:countersign_signature_invalid"
DENY_COUNTERSIGN_EVIDENCE_MISMATCH = "hr:countersign_evidence_mismatch"
DENY_EMOTION_INFERENCE = "hr:emotion_inference"
DENY_SURVEILLANCE_REPURPOSE = "hr:surveillance_repurpose"
DENY_REPURPOSE_NOTICE_INVALID = "hr:repurpose_notice_invalid"
DENY_REPURPOSE_NOTICE_EXPIRED = "hr:repurpose_notice_expired"
DENY_NO_APPEAL_RECEIPT = "hr:no_appeal_receipt"
DENY_HOMOPHILY_AUDIT = "hr:homophily_audit"
DENY_HOMOPHILY_PROBE_INVALID = "hr:homophily_probe_invalid"
DENY_HOMOPHILY_PROBE_EXPIRED = "hr:homophily_probe_expired"
DENY_NO_LAYOFF_NOTICE = "hr:no_layoff_notice"
DENY_LAYOFF_NOTICE_INVALID = "hr:layoff_notice_invalid"
DENY_TAINTED_INPUT = "hr:tainted_input"
DENY_UNPINNED_VENDOR = "hr:unpinned_vendor"
DENY_VENDOR_PIN_INVALID = "hr:vendor_pin_invalid"
DENY_BANNED_PROXY_FEATURE = "hr:banned_proxy_feature"
DENY_MALFORMED = "hr:malformed"
DENY_UNKNOWN_AUTHORITY = "hr:unknown_authority"

#: Audit events.
AUDIT_RECORDED_EVENT = "hr.audit_recorded"
SCORING_DISCLOSED_EVENT = "hr.scoring_disclosed"
DECISION_ADJUDICATED_EVENT = "hr.decision_adjudicated"
DECISION_DENIED_EVENT = "hr.decision_denied"
REPIURPOSE_DENIED_EVENT = "hr.repurpose_denied"
LAYOFF_NOTICE_RECORDED_EVENT = "hr.layoff_notice_recorded"
VENDOR_PINNED_EVENT = "hr.vendor_pinned"

#: Classification tiers.
HR_AUTHORITATIVE = "hr-authoritative"
HR_NON_AUTHORITATIVE = "hr-non-authoritative"

_GENESIS = "genesis"


class HrAgentsError(DomainError):
    """Malformed HR-discipline input. Fail loud, never guess."""


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise HrAgentsError(f"{name} must be a non-empty string")
    return value


def _require_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise HrAgentsError(f"{name} must be an integer")
    return value


def _check_ts(value: Any, name: str) -> int:
    v = _require_int(value, name)
    if v < 0:
        raise HrAgentsError(f"{name} must be a non-negative epoch")
    return v


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_hex64(value: Any, name: str) -> str:
    if not _is_hex(value, 64):
        raise HrAgentsError(f"{name} must be 64 lowercase hex chars")
    return value


def _check_secret(value: Any, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise HrAgentsError(f"{name}: Ed25519 secret key must be 32 bytes")
    return value


def _check_sig_hex(value: Any, name: str) -> str:
    if not _is_hex(value, 128):
        raise HrAgentsError(f"{name} must be 128 lowercase hex chars")
    return value


class AuthorityRegistry:
    """Registered human authorities (authority_id -> Ed25519 public key).

    The employer and the vendor are never both the *auditor*: audit
    receipts are checked against this rule explicitly. Registration is
    a host-side operation outside this module.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def register(self, authority_id: str, public_key: bytes) -> None:
        _require_str(authority_id, "authority_id")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise HrAgentsError("public_key must be 32 bytes")
        self._keys[authority_id] = public_key

    def public_key_for(self, authority_id: str) -> bytes | None:
        return self._keys.get(authority_id)


def _verify_signature(
    authorities: AuthorityRegistry,
    *,
    authority_id: str,
    digest_hex: str,
    signature_hex: str,
    deny_code: str,
) -> str | None:
    """Return a denial code if the signature is invalid, else None."""
    pub = authorities.public_key_for(authority_id)
    if pub is None:
        return DENY_UNKNOWN_AUTHORITY
    try:
        ok = _ed25519_verify(
            pub, digest_hex.encode("utf-8"), bytes.fromhex(signature_hex)
        )
    except Exception:
        ok = False
    return None if ok else deny_code


@dataclass(frozen=True)
class HrVerdict:
    """Outcome of one HR-discipline check."""

    allowed: bool
    deny_code: str | None
    classification: str
    receipt_digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "hr-verdict",
            "allowed": self.allowed,
            "deny_code": self.deny_code,
            "classification": self.classification,
            "receipt_digest": self.receipt_digest,
            "schema_version": SCHEMA_VERSION,
        }


def _allow(receipt_digest: str = "") -> HrVerdict:
    return HrVerdict(
        allowed=True,
        deny_code=None,
        classification=HR_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def _deny(deny_code: str) -> HrVerdict:
    return HrVerdict(
        allowed=False,
        deny_code=deny_code,
        classification=HR_NON_AUTHORITATIVE,
    )


# ---------------------------------------------------------------------------
# Gate 1: independent bias-audit receipts (NYC Local Law 144 lesson)
# ---------------------------------------------------------------------------

AUDIT_SCHEMA = "northstar.hr_agents.audit.v1"


def _audit_payload(
    *,
    audit_id: str,
    model_digest: str,
    vendor_id: str,
    auditor_id: str,
    issued_at: int,
    valid_until: int,
    banned_features_checked: tuple[str, ...],
    features_used: tuple[str, ...],
    auditor_pubkey_hex: str,
) -> dict[str, Any]:
    return {
        "schema": AUDIT_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "audit_id": audit_id,
        "model_digest": model_digest,
        "vendor_id": vendor_id,
        "auditor_id": auditor_id,
        "issued_at": issued_at,
        "valid_until": valid_until,
        "banned_features_checked": sorted(banned_features_checked),
        "features_used": sorted(features_used),
        "auditor_pubkey_hex": auditor_pubkey_hex,
    }


@dataclass(frozen=True)
class AuditReceipt:
    """An independent third-party bias audit of an HR model."""

    audit_id: str
    model_digest: str
    vendor_id: str
    auditor_id: str
    issued_at: int
    valid_until: int
    banned_features_checked: tuple[str, ...]
    features_used: tuple[str, ...]
    auditor_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "hr-audit-receipt",
            "audit_id": self.audit_id,
            "model_digest": self.model_digest,
            "vendor_id": self.vendor_id,
            "auditor_id": self.auditor_id,
            "issued_at": self.issued_at,
            "valid_until": self.valid_until,
            "banned_features_checked": list(self.banned_features_checked),
            "features_used": list(self.features_used),
            "auditor_pubkey_hex": self.auditor_pubkey_hex,
            "signature_hex": self.signature_hex,
            "receipt_digest": self.receipt_digest,
            "schema_version": SCHEMA_VERSION,
        }


def issue_audit_receipt(
    *,
    audit_id: str,
    model_digest: str,
    vendor_id: str,
    auditor_id: str,
    issued_at: int,
    valid_until: int,
    banned_features_checked: tuple[str, ...] = (),
    features_used: tuple[str, ...] = (),
    auditor_secret: bytes,
) -> AuditReceipt:
    """Issue an authority-signed bias-audit receipt. Fail-closed at
    issuance: the auditor may not be the vendor (self-audits are
    refused at issue time, not just at check time), and a model using
    a banned proxy feature (Illinois HB 3773 zip-code lesson) cannot
    be audited clean."""
    audit_id = _require_str(audit_id, "audit_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    vendor_id = _require_str(vendor_id, "vendor_id")
    auditor_id = _require_str(auditor_id, "auditor_id")
    issued_at = _check_ts(issued_at, "issued_at")
    valid_until = _check_ts(valid_until, "valid_until")
    if valid_until <= issued_at:
        raise HrAgentsError("valid_until must be after issued_at")
    secret = _check_secret(auditor_secret, "auditor_secret")
    if auditor_id == vendor_id:
        raise HrAgentsError("auditor_id must differ from vendor_id (no self-audits)")
    features = tuple(sorted(set(banned_features_checked)))
    for f in features:
        _require_str(f, "banned feature")
    used = tuple(sorted(set(features_used)))
    for f in used:
        _require_str(f, "used feature")
    banned_used = [f for f in used if f in BANNED_PROXY_FEATURES]
    if banned_used:
        raise HrAgentsError(
            f"model uses banned proxy features: {banned_used} ({DENY_BANNED_PROXY_FEATURE})"
        )
    bare = _audit_payload(
        audit_id=audit_id,
        model_digest=model_digest,
        vendor_id=vendor_id,
        auditor_id=auditor_id,
        issued_at=issued_at,
        valid_until=valid_until,
        banned_features_checked=features,
        features_used=used,
        auditor_pubkey_hex=_ed25519_pubkey(secret).hex(),
    )
    sig_hex = _ed25519_sign(secret, jcs_sha256_hex(bare).encode("utf-8")).hex()
    digest = jcs_sha256_hex({**bare, "signature_hex": sig_hex})
    return AuditReceipt(
        audit_id=audit_id,
        model_digest=model_digest,
        vendor_id=vendor_id,
        auditor_id=auditor_id,
        issued_at=issued_at,
        valid_until=valid_until,
        banned_features_checked=features,
        features_used=used,
        auditor_pubkey_hex=_ed25519_pubkey(secret).hex(),
        signature_hex=sig_hex,
        receipt_digest=digest,
    )


class AuditRegistry:
    """Live third-party bias audits, keyed by model digest."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._receipts: dict[str, AuditReceipt] = {}

    def record(self, receipt: AuditReceipt) -> None:
        if receipt.auditor_id == receipt.vendor_id:
            raise HrAgentsError("self-audit receipts are not recordable")
        self._receipts[receipt.model_digest] = receipt

    def receipt_for(self, model_digest: str) -> AuditReceipt | None:
        return self._receipts.get(model_digest)


def audit_receipt(
    audits: AuditRegistry,
    *,
    model_digest: str,
    checked_at: int,
) -> HrVerdict:
    """Check that an HR model carries a live independent bias audit.

    Self-audits are NON_AUTHORITATIVE (``hr:self_audit``); expired,
    unknown, or badly-signed audits fail closed.
    """
    model_digest = _check_hex64(model_digest, "model_digest")
    checked_at = _check_ts(checked_at, "checked_at")
    receipt = audits.receipt_for(model_digest)
    if receipt is None:
        return _deny(DENY_AUDIT_UNKNOWN)
    if receipt.auditor_id == receipt.vendor_id:
        return _deny(DENY_SELF_AUDIT)
    code = _verify_signature(
        audits._authorities,
        authority_id=receipt.auditor_id,
        digest_hex=jcs_sha256_hex(
            _audit_payload(
                audit_id=receipt.audit_id,
                model_digest=receipt.model_digest,
                vendor_id=receipt.vendor_id,
                auditor_id=receipt.auditor_id,
                issued_at=receipt.issued_at,
                valid_until=receipt.valid_until,
                banned_features_checked=receipt.banned_features_checked,
                features_used=receipt.features_used,
                auditor_pubkey_hex=receipt.auditor_pubkey_hex,
            )
        ),
        signature_hex=receipt.signature_hex,
        deny_code=DENY_AUDIT_SIGNATURE_INVALID,
    )
    if code is not None:
        return _deny(code)
    if checked_at > receipt.valid_until:
        return _deny(DENY_AUDIT_EXPIRED)
    return _allow(receipt.receipt_digest)


# ---------------------------------------------------------------------------
# Gate 2: secret-scoring probe (Kistler v. Eightfold lesson)
# ---------------------------------------------------------------------------

DISCLOSURE_SCHEMA = "northstar.hr_agents.scoring_disclosure.v1"


def _disclosure_payload(
    *,
    disclosure_id: str,
    scoring_system_id: str,
    subject_id: str,
    disclosed_at: int,
    access_path: str,
    dispute_path: str,
    issuer_pubkey_hex: str,
) -> dict[str, Any]:
    return {
        "schema": DISCLOSURE_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "disclosure_id": disclosure_id,
        "scoring_system_id": scoring_system_id,
        "subject_id": subject_id,
        "disclosed_at": disclosed_at,
        "access_path": access_path,
        "dispute_path": dispute_path,
        "issuer_pubkey_hex": issuer_pubkey_hex,
    }


@dataclass(frozen=True)
class ScoringDisclosure:
    """FCRA-style disclosure: the worker was told they are scored,
    can see the profile, and can dispute it."""

    disclosure_id: str
    scoring_system_id: str
    subject_id: str
    disclosed_at: int
    access_path: str
    dispute_path: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""


def issue_scoring_disclosure(
    *,
    disclosure_id: str,
    scoring_system_id: str,
    subject_id: str,
    disclosed_at: int,
    access_path: str,
    dispute_path: str,
    issuer_secret: bytes,
) -> ScoringDisclosure:
    disclosure_id = _require_str(disclosure_id, "disclosure_id")
    scoring_system_id = _require_str(scoring_system_id, "scoring_system_id")
    subject_id = _require_str(subject_id, "subject_id")
    disclosed_at = _check_ts(disclosed_at, "disclosed_at")
    access_path = _require_str(access_path, "access_path")
    dispute_path = _require_str(dispute_path, "dispute_path")
    secret = _check_secret(issuer_secret, "issuer_secret")
    bare = _disclosure_payload(
        disclosure_id=disclosure_id,
        scoring_system_id=scoring_system_id,
        subject_id=subject_id,
        disclosed_at=disclosed_at,
        access_path=access_path,
        dispute_path=dispute_path,
        issuer_pubkey_hex=_ed25519_pubkey(secret).hex(),
    )
    sig_hex = _ed25519_sign(secret, jcs_sha256_hex(bare).encode("utf-8")).hex()
    digest = jcs_sha256_hex({**bare, "signature_hex": sig_hex})
    return ScoringDisclosure(
        disclosure_id=disclosure_id,
        scoring_system_id=scoring_system_id,
        subject_id=subject_id,
        disclosed_at=disclosed_at,
        access_path=access_path,
        dispute_path=dispute_path,
        issuer_pubkey_hex=_ed25519_pubkey(secret).hex(),
        signature_hex=sig_hex,
        receipt_digest=digest,
    )


class ScoringDisclosureRegistry:
    """Disclosure receipts keyed by (scoring_system_id, subject_id)."""

    def __init__(self) -> None:
        self._disclosures: dict[tuple[str, str], ScoringDisclosure] = {}

    def record(self, disclosure: ScoringDisclosure) -> None:
        self._disclosures[
            (disclosure.scoring_system_id, disclosure.subject_id)
        ] = disclosure

    def disclosure_for(
        self, scoring_system_id: str, subject_id: str
    ) -> ScoringDisclosure | None:
        return self._disclosures.get((scoring_system_id, subject_id))


def secret_scoring_probe(
    disclosures: ScoringDisclosureRegistry,
    authorities: AuthorityRegistry,
    *,
    scoring_system_id: str,
    subject_id: str,
    scored_at: int,
    issuer_id: str,
) -> HrVerdict:
    """Worker-profile AI scoring without an FCRA-style disclosure is
    ``hr:secret_scoring``. The disclosure must predate the scoring
    and carry a valid issuer signature."""
    scoring_system_id = _require_str(scoring_system_id, "scoring_system_id")
    subject_id = _require_str(subject_id, "subject_id")
    scored_at = _check_ts(scored_at, "scored_at")
    issuer_id = _require_str(issuer_id, "issuer_id")
    disclosure = disclosures.disclosure_for(scoring_system_id, subject_id)
    if disclosure is None:
        return _deny(DENY_SECRET_SCORING)
    if disclosure.disclosed_at > scored_at:
        return _deny(DENY_SECRET_SCORING)
    code = _verify_signature(
        authorities,
        authority_id=issuer_id,
        digest_hex=jcs_sha256_hex(
            _disclosure_payload(
                disclosure_id=disclosure.disclosure_id,
                scoring_system_id=disclosure.scoring_system_id,
                subject_id=disclosure.subject_id,
                disclosed_at=disclosure.disclosed_at,
                access_path=disclosure.access_path,
                dispute_path=disclosure.dispute_path,
                issuer_pubkey_hex=disclosure.issuer_pubkey_hex,
            )
        ),
        signature_hex=disclosure.signature_hex,
        deny_code=DENY_SCORING_DISCLOSURE_INVALID,
    )
    if code is not None:
        return _deny(code)
    return _allow(disclosure.receipt_digest)


# ---------------------------------------------------------------------------
# Gate 3: human-final countersign (anti rubber-stamp)
# ---------------------------------------------------------------------------

COUNTERSIGN_SCHEMA = "northstar.hr_agents.countersign.v1"


def _countersign_payload(
    *,
    decision_id: str,
    decision_kind: str,
    evidence_digest: str,
    reviewer_name: str,
    review_minutes: int,
    review_notes_digest: str,
    countersigned_at: int,
    reviewer_pubkey_hex: str,
) -> dict[str, Any]:
    return {
        "schema": COUNTERSIGN_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "decision_id": decision_id,
        "decision_kind": decision_kind,
        "evidence_digest": evidence_digest,
        "reviewer_name": reviewer_name,
        "review_minutes": review_minutes,
        "review_notes_digest": review_notes_digest,
        "countersigned_at": countersigned_at,
        "reviewer_pubkey_hex": reviewer_pubkey_hex,
    }


@dataclass(frozen=True)
class HumanCountersign:
    """A named human's countersign on an AI-influenced employment
    decision, with substantive-review evidence."""

    decision_id: str
    decision_kind: str
    evidence_digest: str
    reviewer_name: str
    review_minutes: int
    review_notes_digest: str
    countersigned_at: int
    reviewer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""


def issue_human_countersign(
    *,
    decision_id: str,
    decision_kind: str,
    evidence_digest: str,
    reviewer_name: str,
    review_minutes: int,
    review_notes_digest: str,
    countersigned_at: int,
    reviewer_secret: bytes,
) -> HumanCountersign:
    decision_id = _require_str(decision_id, "decision_id")
    if decision_kind not in EMPLOYMENT_DECISIONS:
        raise HrAgentsError(f"decision_kind must be one of {sorted(EMPLOYMENT_DECISIONS)}")
    evidence_digest = _check_hex64(evidence_digest, "evidence_digest")
    reviewer_name = _require_str(reviewer_name, "reviewer_name")
    review_minutes = _require_int(review_minutes, "review_minutes")
    if review_minutes < 0:
        raise HrAgentsError("review_minutes must be non-negative")
    review_notes_digest = _check_hex64(review_notes_digest, "review_notes_digest")
    countersigned_at = _check_ts(countersigned_at, "countersigned_at")
    secret = _check_secret(reviewer_secret, "reviewer_secret")
    bare = _countersign_payload(
        decision_id=decision_id,
        decision_kind=decision_kind,
        evidence_digest=evidence_digest,
        reviewer_name=reviewer_name,
        review_minutes=review_minutes,
        review_notes_digest=review_notes_digest,
        countersigned_at=countersigned_at,
        reviewer_pubkey_hex=_ed25519_pubkey(secret).hex(),
    )
    sig_hex = _ed25519_sign(secret, jcs_sha256_hex(bare).encode("utf-8")).hex()
    digest = jcs_sha256_hex({**bare, "signature_hex": sig_hex})
    return HumanCountersign(
        decision_id=decision_id,
        decision_kind=decision_kind,
        evidence_digest=evidence_digest,
        reviewer_name=reviewer_name,
        review_minutes=review_minutes,
        review_notes_digest=review_notes_digest,
        countersigned_at=countersigned_at,
        reviewer_pubkey_hex=_ed25519_pubkey(secret).hex(),
        signature_hex=sig_hex,
        receipt_digest=digest,
    )


class CountersignRegistry:
    """Human countersigns keyed by decision id."""

    def __init__(self) -> None:
        self._signs: dict[str, HumanCountersign] = {}

    def record(self, countersign: HumanCountersign) -> None:
        self._signs[countersign.decision_id] = countersign

    def sign_for(self, decision_id: str) -> HumanCountersign | None:
        return self._signs.get(decision_id)


def human_final_gate(
    countersigns: CountersignRegistry,
    authorities: AuthorityRegistry,
    *,
    decision_id: str,
    decision_kind: str,
    evidence_digest: str,
    ai_involved: bool,
    decided_at: int,
    reviewer_id: str,
) -> HrVerdict:
    """AI-influenced employment decisions require a named-human
    countersign with substantive-review evidence. A signature without
    review evidence is a rubber stamp (``hr:rubber_stamp``) — the
    127th-batch labor lesson extended to the office."""
    decision_id = _require_str(decision_id, "decision_id")
    if decision_kind not in EMPLOYMENT_DECISIONS:
        raise HrAgentsError(f"decision_kind must be one of {sorted(EMPLOYMENT_DECISIONS)}")
    evidence_digest = _check_hex64(evidence_digest, "evidence_digest")
    decided_at = _check_ts(decided_at, "decided_at")
    reviewer_id = _require_str(reviewer_id, "reviewer_id")
    if not ai_involved:
        return _allow()
    sign = countersigns.sign_for(decision_id)
    if sign is None:
        return _deny(DENY_NO_HUMAN_COUNTERSIGN)
    if not hmac.compare_digest(sign.evidence_digest, evidence_digest):
        return _deny(DENY_COUNTERSIGN_EVIDENCE_MISMATCH)
    code = _verify_signature(
        authorities,
        authority_id=reviewer_id,
        digest_hex=jcs_sha256_hex(
            _countersign_payload(
                decision_id=sign.decision_id,
                decision_kind=sign.decision_kind,
                evidence_digest=sign.evidence_digest,
                reviewer_name=sign.reviewer_name,
                review_minutes=sign.review_minutes,
                review_notes_digest=sign.review_notes_digest,
                countersigned_at=sign.countersigned_at,
                reviewer_pubkey_hex=sign.reviewer_pubkey_hex,
            )
        ),
        signature_hex=sign.signature_hex,
        deny_code=DENY_COUNTERSIGN_SIGNATURE_INVALID,
    )
    if code is not None:
        return _deny(code)
    if sign.review_minutes < MIN_REVIEW_MINUTES:
        return _deny(DENY_RUBBER_STAMP)
    return _allow(sign.receipt_digest)


# ---------------------------------------------------------------------------
# Gate 4: emotion-inference whole-class ban (California 2026-09-30)
# ---------------------------------------------------------------------------

def emotion_inference_ban(
    *,
    use_kind: str,
    uses_ai: bool,
    uses_biometrics: bool,
) -> HrVerdict:
    """AI+biometric emotion/affect prediction is refused whole-class.
    There is no receipt that can authorize it."""
    use_kind = _require_str(use_kind, "use_kind")
    if uses_ai and uses_biometrics and use_kind in EMOTION_USE_KINDS:
        return _deny(DENY_EMOTION_INFERENCE)
    return _allow()


# ---------------------------------------------------------------------------
# Gate 5: surveillance repurposing (CPPA ADMT lesson)
# ---------------------------------------------------------------------------

REPURPOSE_SCHEMA = "northstar.hr_agents.repurpose_notice.v1"


def _repurpose_payload(
    *,
    notice_id: str,
    monitoring_source_digest: str,
    new_purpose: str,
    notice_given_at: int,
    appeal_receipt_digest: str,
    issuer_pubkey_hex: str,
) -> dict[str, Any]:
    return {
        "schema": REPURPOSE_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "notice_id": notice_id,
        "monitoring_source_digest": monitoring_source_digest,
        "new_purpose": new_purpose,
        "notice_given_at": notice_given_at,
        "appeal_receipt_digest": appeal_receipt_digest,
        "issuer_pubkey_hex": issuer_pubkey_hex,
    }


@dataclass(frozen=True)
class RepurposeNotice:
    """Advance notice that monitoring data will feed employment
    decisions, with a bound appeal receipt."""

    notice_id: str
    monitoring_source_digest: str
    new_purpose: str
    notice_given_at: int
    appeal_receipt_digest: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""


def issue_repurpose_notice(
    *,
    notice_id: str,
    monitoring_source_digest: str,
    new_purpose: str,
    notice_given_at: int,
    appeal_receipt_digest: str,
    issuer_secret: bytes,
) -> RepurposeNotice:
    notice_id = _require_str(notice_id, "notice_id")
    monitoring_source_digest = _check_hex64(monitoring_source_digest, "monitoring_source_digest")
    new_purpose = _require_str(new_purpose, "new_purpose")
    notice_given_at = _check_ts(notice_given_at, "notice_given_at")
    appeal_receipt_digest = _check_hex64(appeal_receipt_digest, "appeal_receipt_digest")
    secret = _check_secret(issuer_secret, "issuer_secret")
    bare = _repurpose_payload(
        notice_id=notice_id,
        monitoring_source_digest=monitoring_source_digest,
        new_purpose=new_purpose,
        notice_given_at=notice_given_at,
        appeal_receipt_digest=appeal_receipt_digest,
        issuer_pubkey_hex=_ed25519_pubkey(secret).hex(),
    )
    sig_hex = _ed25519_sign(secret, jcs_sha256_hex(bare).encode("utf-8")).hex()
    digest = jcs_sha256_hex({**bare, "signature_hex": sig_hex})
    return RepurposeNotice(
        notice_id=notice_id,
        monitoring_source_digest=monitoring_source_digest,
        new_purpose=new_purpose,
        notice_given_at=notice_given_at,
        appeal_receipt_digest=appeal_receipt_digest,
        issuer_pubkey_hex=_ed25519_pubkey(secret).hex(),
        signature_hex=sig_hex,
        receipt_digest=digest,
    )


class RepurposeRegistry:
    """Repurpose notices keyed by monitoring-source digest."""

    def __init__(self) -> None:
        self._notices: dict[str, RepurposeNotice] = {}

    def record(self, notice: RepurposeNotice) -> None:
        self._notices[notice.monitoring_source_digest] = notice

    def notice_for(self, monitoring_source_digest: str) -> RepurposeNotice | None:
        return self._notices.get(monitoring_source_digest)


def surveillance_purpose_receipt(
    notices: RepurposeRegistry,
    authorities: AuthorityRegistry,
    *,
    monitoring_source_digest: str,
    employment_use: bool,
    used_at: int,
    issuer_id: str,
    notice_ttl_s: int = 86400 * 365,
) -> HrVerdict:
    """Monitoring data repurposed for employment decisions requires a
    live advance-notice receipt with a bound appeal receipt (CPPA ADMT).
    Without it: ``hr:surveillance_repurpose``."""
    monitoring_source_digest = _check_hex64(monitoring_source_digest, "monitoring_source_digest")
    used_at = _check_ts(used_at, "used_at")
    issuer_id = _require_str(issuer_id, "issuer_id")
    if not employment_use:
        return _allow()
    notice = notices.notice_for(monitoring_source_digest)
    if notice is None:
        return _deny(DENY_SURVEILLANCE_REPURPOSE)
    if not hmac.compare_digest(notice.monitoring_source_digest, monitoring_source_digest):
        return _deny(DENY_SURVEILLANCE_REPURPOSE)
    code = _verify_signature(
        authorities,
        authority_id=issuer_id,
        digest_hex=jcs_sha256_hex(
            _repurpose_payload(
                notice_id=notice.notice_id,
                monitoring_source_digest=notice.monitoring_source_digest,
                new_purpose=notice.new_purpose,
                notice_given_at=notice.notice_given_at,
                appeal_receipt_digest=notice.appeal_receipt_digest,
                issuer_pubkey_hex=notice.issuer_pubkey_hex,
            )
        ),
        signature_hex=notice.signature_hex,
        deny_code=DENY_REPURPOSE_NOTICE_INVALID,
    )
    if code is not None:
        return _deny(code)
    if used_at > notice.notice_given_at + notice_ttl_s:
        return _deny(DENY_REPURPOSE_NOTICE_EXPIRED)
    if notice.notice_given_at > used_at:
        return _deny(DENY_SURVEILLANCE_REPURPOSE)
    return _allow(notice.receipt_digest)


# ---------------------------------------------------------------------------
# Gate 6: model-homophily probe (Xu simulation lesson)
# ---------------------------------------------------------------------------

HOMOPHILY_SCHEMA = "northstar.hr_agents.homophily_probe.v1"


def _homophily_payload(
    *,
    probe_id: str,
    model_digest: str,
    ai_written_passes: int,
    ai_written_total: int,
    human_written_passes: int,
    human_written_total: int,
    measured_at: int,
    expires_at: int,
    issuer_pubkey_hex: str,
) -> dict[str, Any]:
    return {
        "schema": HOMOPHILY_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "probe_id": probe_id,
        "model_digest": model_digest,
        "ai_written_passes": ai_written_passes,
        "ai_written_total": ai_written_total,
        "human_written_passes": human_written_passes,
        "human_written_total": human_written_total,
        "measured_at": measured_at,
        "expires_at": expires_at,
        "issuer_pubkey_hex": issuer_pubkey_hex,
    }


@dataclass(frozen=True)
class HomophilyProbe:
    """A measured AI-written vs human-written resume pass-rate probe
    for one screening model."""

    probe_id: str
    model_digest: str
    ai_written_passes: int
    ai_written_total: int
    human_written_passes: int
    human_written_total: int
    measured_at: int
    expires_at: int
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""


def issue_homophily_probe(
    *,
    probe_id: str,
    model_digest: str,
    ai_written_passes: int,
    ai_written_total: int,
    human_written_passes: int,
    human_written_total: int,
    measured_at: int,
    expires_at: int,
    issuer_secret: bytes,
) -> HomophilyProbe:
    probe_id = _require_str(probe_id, "probe_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    for name, v in (
        ("ai_written_passes", ai_written_passes),
        ("ai_written_total", ai_written_total),
        ("human_written_passes", human_written_passes),
        ("human_written_total", human_written_total),
    ):
        v = _require_int(v, name)
        if v < 0:
            raise HrAgentsError(f"{name} must be non-negative")
    if ai_written_passes > ai_written_total or human_written_passes > human_written_total:
        raise HrAgentsError("passes may not exceed totals")
    if ai_written_total == 0 or human_written_total == 0:
        raise HrAgentsError("probe totals must be non-zero")
    measured_at = _check_ts(measured_at, "measured_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= measured_at:
        raise HrAgentsError("expires_at must be after measured_at")
    secret = _check_secret(issuer_secret, "issuer_secret")
    bare = _homophily_payload(
        probe_id=probe_id,
        model_digest=model_digest,
        ai_written_passes=ai_written_passes,
        ai_written_total=ai_written_total,
        human_written_passes=human_written_passes,
        human_written_total=human_written_total,
        measured_at=measured_at,
        expires_at=expires_at,
        issuer_pubkey_hex=_ed25519_pubkey(secret).hex(),
    )
    sig_hex = _ed25519_sign(secret, jcs_sha256_hex(bare).encode("utf-8")).hex()
    digest = jcs_sha256_hex({**bare, "signature_hex": sig_hex})
    return HomophilyProbe(
        probe_id=probe_id,
        model_digest=model_digest,
        ai_written_passes=ai_written_passes,
        ai_written_total=ai_written_total,
        human_written_passes=human_written_passes,
        human_written_total=human_written_total,
        measured_at=measured_at,
        expires_at=expires_at,
        issuer_pubkey_hex=_ed25519_pubkey(secret).hex(),
        signature_hex=sig_hex,
        receipt_digest=digest,
    )


@dataclass(frozen=True)
class HomophilyVerdict:
    allowed: bool
    deny_code: str | None
    classification: str
    pass_rate_ratio: float
    probe_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "hr-homophily-verdict",
            "allowed": self.allowed,
            "deny_code": self.deny_code,
            "classification": self.classification,
            "pass_rate_ratio": self.pass_rate_ratio,
            "probe_id": self.probe_id,
            "schema_version": SCHEMA_VERSION,
        }


def model_homophily_probe(
    probe: HomophilyProbe,
    authorities: AuthorityRegistry,
    *,
    issuer_id: str,
    checked_at: int,
) -> HomophilyVerdict:
    """If the AI-written pass rate divided by the human-written pass
    rate exceeds :data:`HOMOPHILY_RATIO_MAX`, the screener is
    quarantined for audit (``hr:homophily_audit``)."""
    issuer_id = _require_str(issuer_id, "issuer_id")
    checked_at = _check_ts(checked_at, "checked_at")
    code = _verify_signature(
        authorities,
        authority_id=issuer_id,
        digest_hex=jcs_sha256_hex(
            _homophily_payload(
                probe_id=probe.probe_id,
                model_digest=probe.model_digest,
                ai_written_passes=probe.ai_written_passes,
                ai_written_total=probe.ai_written_total,
                human_written_passes=probe.human_written_passes,
                human_written_total=probe.human_written_total,
                measured_at=probe.measured_at,
                expires_at=probe.expires_at,
                issuer_pubkey_hex=probe.issuer_pubkey_hex,
            )
        ),
        signature_hex=probe.signature_hex,
        deny_code=DENY_HOMOPHILY_PROBE_INVALID,
    )
    if code is not None:
        return HomophilyVerdict(False, code, HR_NON_AUTHORITATIVE, 0.0, probe.probe_id)
    if checked_at > probe.expires_at:
        return HomophilyVerdict(
            False, DENY_HOMOPHILY_PROBE_EXPIRED, HR_NON_AUTHORITATIVE, 0.0, probe.probe_id
        )
    ai_rate = probe.ai_written_passes / probe.ai_written_total
    human_rate = probe.human_written_passes / probe.human_written_total
    ratio = ai_rate / human_rate if human_rate > 0 else float("inf")
    if ratio > HOMOPHILY_RATIO_MAX:
        return HomophilyVerdict(
            False, DENY_HOMOPHILY_AUDIT, HR_NON_AUTHORITATIVE, ratio, probe.probe_id
        )
    return HomophilyVerdict(True, None, HR_AUTHORITATIVE, ratio, probe.probe_id)


# ---------------------------------------------------------------------------
# Gate 7: layoff AI disclosure (Newsom 2026-09-30 law)
# ---------------------------------------------------------------------------

LAYOFF_SCHEMA = "northstar.hr_agents.layoff_notice.v1"


def _layoff_payload(
    *,
    notice_id: str,
    layoff_id: str,
    ai_involvement_digest: str,
    written_notice_digest: str,
    evidence_chain_digest: str,
    issued_at: int,
    issuer_pubkey_hex: str,
) -> dict[str, Any]:
    return {
        "schema": LAYOFF_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "notice_id": notice_id,
        "layoff_id": layoff_id,
        "ai_involvement_digest": ai_involvement_digest,
        "written_notice_digest": written_notice_digest,
        "evidence_chain_digest": evidence_chain_digest,
        "issued_at": issued_at,
        "issuer_pubkey_hex": issuer_pubkey_hex,
    }


@dataclass(frozen=True)
class LayoffNotice:
    """Written notice + evidence chain for an AI-involved layoff."""

    notice_id: str
    layoff_id: str
    ai_involvement_digest: str
    written_notice_digest: str
    evidence_chain_digest: str
    issued_at: int
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""


def issue_layoff_notice(
    *,
    notice_id: str,
    layoff_id: str,
    ai_involvement_digest: str,
    written_notice_digest: str,
    evidence_chain_digest: str,
    issued_at: int,
    issuer_secret: bytes,
) -> LayoffNotice:
    notice_id = _require_str(notice_id, "notice_id")
    layoff_id = _require_str(layoff_id, "layoff_id")
    ai_involvement_digest = _check_hex64(ai_involvement_digest, "ai_involvement_digest")
    written_notice_digest = _check_hex64(written_notice_digest, "written_notice_digest")
    evidence_chain_digest = _check_hex64(evidence_chain_digest, "evidence_chain_digest")
    issued_at = _check_ts(issued_at, "issued_at")
    secret = _check_secret(issuer_secret, "issuer_secret")
    bare = _layoff_payload(
        notice_id=notice_id,
        layoff_id=layoff_id,
        ai_involvement_digest=ai_involvement_digest,
        written_notice_digest=written_notice_digest,
        evidence_chain_digest=evidence_chain_digest,
        issued_at=issued_at,
        issuer_pubkey_hex=_ed25519_pubkey(secret).hex(),
    )
    sig_hex = _ed25519_sign(secret, jcs_sha256_hex(bare).encode("utf-8")).hex()
    digest = jcs_sha256_hex({**bare, "signature_hex": sig_hex})
    return LayoffNotice(
        notice_id=notice_id,
        layoff_id=layoff_id,
        ai_involvement_digest=ai_involvement_digest,
        written_notice_digest=written_notice_digest,
        evidence_chain_digest=evidence_chain_digest,
        issued_at=issued_at,
        issuer_pubkey_hex=_ed25519_pubkey(secret).hex(),
        signature_hex=sig_hex,
        receipt_digest=digest,
    )


class LayoffNoticeRegistry:
    """Layoff notices keyed by layoff id."""

    def __init__(self) -> None:
        self._notices: dict[str, LayoffNotice] = {}

    def record(self, notice: LayoffNotice) -> None:
        self._notices[notice.layoff_id] = notice

    def notice_for(self, layoff_id: str) -> LayoffNotice | None:
        return self._notices.get(layoff_id)


def layoff_ai_disclosure(
    notices: LayoffNoticeRegistry,
    authorities: AuthorityRegistry,
    *,
    layoff_id: str,
    ai_involved: bool,
    issuer_id: str,
) -> HrVerdict:
    """AI-involved layoffs bind a written-notice receipt plus an
    evidence chain. Without it: ``hr:no_layoff_notice``."""
    layoff_id = _require_str(layoff_id, "layoff_id")
    issuer_id = _require_str(issuer_id, "issuer_id")
    if not ai_involved:
        return _allow()
    notice = notices.notice_for(layoff_id)
    if notice is None:
        return _deny(DENY_NO_LAYOFF_NOTICE)
    code = _verify_signature(
        authorities,
        authority_id=issuer_id,
        digest_hex=jcs_sha256_hex(
            _layoff_payload(
                notice_id=notice.notice_id,
                layoff_id=notice.layoff_id,
                ai_involvement_digest=notice.ai_involvement_digest,
                written_notice_digest=notice.written_notice_digest,
                evidence_chain_digest=notice.evidence_chain_digest,
                issued_at=notice.issued_at,
                issuer_pubkey_hex=notice.issuer_pubkey_hex,
            )
        ),
        signature_hex=notice.signature_hex,
        deny_code=DENY_LAYOFF_NOTICE_INVALID,
    )
    if code is not None:
        return _deny(code)
    return _allow(notice.receipt_digest)


# ---------------------------------------------------------------------------
# Gate 8: input-bias inheritance (pollution-source lesson)
# ---------------------------------------------------------------------------

def input_bias_inheritance(
    audits: AuditRegistry,
    *,
    evaluation_output_digest: str,
    source_model_digest: str,
    used_for: str,
    checked_at: int,
) -> HrVerdict:
    """Unaudited evaluation outputs may not feed downstream employment
    decisions. Performance reviews are the pollution source of all
    downstream decisions: if the source model lacks a live audit, the
    downstream use is ``hr:tainted_input``."""
    evaluation_output_digest = _check_hex64(
        evaluation_output_digest, "evaluation_output_digest"
    )
    source_model_digest = _check_hex64(source_model_digest, "source_model_digest")
    if used_for not in EMPLOYMENT_DECISIONS:
        raise HrAgentsError(f"used_for must be one of {sorted(EMPLOYMENT_DECISIONS)}")
    checked_at = _check_ts(checked_at, "checked_at")
    verdict = audit_receipt(audits, model_digest=source_model_digest, checked_at=checked_at)
    if not verdict.allowed:
        return _deny(DENY_TAINTED_INPUT)
    return _allow(verdict.receipt_digest)


# ---------------------------------------------------------------------------
# Gate 9: vendor pinned as employer's agent (Mobley v. Workday)
# ---------------------------------------------------------------------------

VENDOR_PIN_SCHEMA = "northstar.hr_agents.vendor_pin.v1"


def _vendor_pin_payload(
    *,
    pin_id: str,
    vendor_id: str,
    employer_id: str,
    scope: str,
    issued_at: int,
    issuer_pubkey_hex: str,
) -> dict[str, Any]:
    return {
        "schema": VENDOR_PIN_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "pin_id": pin_id,
        "vendor_id": vendor_id,
        "employer_id": employer_id,
        "scope": scope,
        "issued_at": issued_at,
        "issuer_pubkey_hex": issuer_pubkey_hex,
    }


@dataclass(frozen=True)
class VendorPin:
    """The vendor is pinned as the employer's agent for the declared
    scope — liability cannot be outsourced to a contract."""

    pin_id: str
    vendor_id: str
    employer_id: str
    scope: str
    issued_at: int
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""


def issue_vendor_pin(
    *,
    pin_id: str,
    vendor_id: str,
    employer_id: str,
    scope: str,
    issued_at: int,
    issuer_secret: bytes,
) -> VendorPin:
    pin_id = _require_str(pin_id, "pin_id")
    vendor_id = _require_str(vendor_id, "vendor_id")
    employer_id = _require_str(employer_id, "employer_id")
    scope = _require_str(scope, "scope")
    issued_at = _check_ts(issued_at, "issued_at")
    secret = _check_secret(issuer_secret, "issuer_secret")
    bare = _vendor_pin_payload(
        pin_id=pin_id,
        vendor_id=vendor_id,
        employer_id=employer_id,
        scope=scope,
        issued_at=issued_at,
        issuer_pubkey_hex=_ed25519_pubkey(secret).hex(),
    )
    sig_hex = _ed25519_sign(secret, jcs_sha256_hex(bare).encode("utf-8")).hex()
    digest = jcs_sha256_hex({**bare, "signature_hex": sig_hex})
    return VendorPin(
        pin_id=pin_id,
        vendor_id=vendor_id,
        employer_id=employer_id,
        scope=scope,
        issued_at=issued_at,
        issuer_pubkey_hex=_ed25519_pubkey(secret).hex(),
        signature_hex=sig_hex,
        receipt_digest=digest,
    )


class VendorPinRegistry:
    """Vendor pins keyed by (vendor_id, employer_id)."""

    def __init__(self) -> None:
        self._pins: dict[tuple[str, str], VendorPin] = {}

    def record(self, pin: VendorPin) -> None:
        self._pins[(pin.vendor_id, pin.employer_id)] = pin

    def pin_for(self, vendor_id: str, employer_id: str) -> VendorPin | None:
        return self._pins.get((vendor_id, employer_id))


def vendor_agent_pin(
    pins: VendorPinRegistry,
    authorities: AuthorityRegistry,
    *,
    vendor_id: str,
    employer_id: str,
    issuer_id: str,
) -> HrVerdict:
    """The vendor must be pinned as the employer's agent. Unpinned:
    ``hr:unpinned_vendor`` (Mobley v. Workday — the vendor may be
    liable as the employer's agent, so the pin is structural)."""
    vendor_id = _require_str(vendor_id, "vendor_id")
    employer_id = _require_str(employer_id, "employer_id")
    issuer_id = _require_str(issuer_id, "issuer_id")
    pin = pins.pin_for(vendor_id, employer_id)
    if pin is None:
        return _deny(DENY_UNPINNED_VENDOR)
    code = _verify_signature(
        authorities,
        authority_id=issuer_id,
        digest_hex=jcs_sha256_hex(
            _vendor_pin_payload(
                pin_id=pin.pin_id,
                vendor_id=pin.vendor_id,
                employer_id=pin.employer_id,
                scope=pin.scope,
                issued_at=pin.issued_at,
                issuer_pubkey_hex=pin.issuer_pubkey_hex,
            )
        ),
        signature_hex=pin.signature_hex,
        deny_code=DENY_VENDOR_PIN_INVALID,
    )
    if code is not None:
        return _deny(code)
    return _allow(pin.receipt_digest)


__all__ = [
    "SCHEMA_VERSION",
    "MIN_REVIEW_MINUTES",
    "HOMOPHILY_RATIO_MAX",
    "BANNED_PROXY_FEATURES",
    "EMOTION_USE_KINDS",
    "EMPLOYMENT_DECISIONS",
    "HrAgentsError",
    "AuthorityRegistry",
    "HrVerdict",
    "AuditReceipt",
    "issue_audit_receipt",
    "AuditRegistry",
    "audit_receipt",
    "ScoringDisclosure",
    "issue_scoring_disclosure",
    "ScoringDisclosureRegistry",
    "secret_scoring_probe",
    "HumanCountersign",
    "issue_human_countersign",
    "CountersignRegistry",
    "human_final_gate",
    "emotion_inference_ban",
    "RepurposeNotice",
    "issue_repurpose_notice",
    "RepurposeRegistry",
    "surveillance_purpose_receipt",
    "HomophilyProbe",
    "issue_homophily_probe",
    "HomophilyVerdict",
    "model_homophily_probe",
    "LayoffNotice",
    "issue_layoff_notice",
    "LayoffNoticeRegistry",
    "layoff_ai_disclosure",
    "input_bias_inheritance",
    "VendorPin",
    "issue_vendor_pin",
    "VendorPinRegistry",
    "vendor_agent_pin",
]
