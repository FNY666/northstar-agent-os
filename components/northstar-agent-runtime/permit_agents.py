"""Permit & planning discipline gates (one-hundred-thirty-sixth batch).

Absorbs the 2026 AI-urban-planning research thread (mechanism ideas
only, honestly scoped):

* **North America**: CivCheck/Clariti becoming the standard answer.
  Honolulu claims -70% review time (2026 AI 50 award, self-reported);
  Denver signed a 5-year $4.6M contract **with human final review
  retained**; Toronto's 2026-09 pilot requires every flag to cite the
  code section; Seattle promoted AI review under a 2025 executive
  order. Common pattern: pre-check + human final review — the AI
  never issues the permit directly.
* **Taiwan Xinzhuang** (新北): first AI-assisted building-license
  review, live 2026-01-01 (image recognition reading drawings).
* **Hong Kong Policy Address**: Housing Authority "智築目" AI
  platform for all new public-housing planning from 2027-28.
* **Chile REVI** (CChC + Google Cloud): dual-agent Clara (applicants'
  pre-check) / Norman (reviewers' assistant), knowledge base bound to
  LGUC/OGUC, every recommendation cites its code source; 17
  municipalities, targeting -30% review time.
* **German-speaking**: Mecklenburgische Seenplatte integrated a
  KI-Assistent in 2026-09; Zurich KI-Sandbox ran a PV/heat-pump
  pre-check prototype (still a prototype).

Risk lines absorbed as tripwires, not solved problems:

* Training data skews toward affluent building types; equally-safe
  alternative practices in lower-income areas get flagged as
  non-compliant. (:func:`disparate_impact_probe`)
* The **SafeRent $2.3M settlement**: the property manager told the
  tenant "no appeal, the algorithm cannot be overridden". An
  auto-influenced decision with no real appeal path is the
  accountability red line. (:func:`appeal_window_gate`)
* Probabilistic output vs. code determinism: AI may not "fill in" the
  code. (:func:`code_version_pin`, :func:`normative_source_receipt`)
* Automation bias / rubber-stamping: override rates trending to zero
  mean the human review has become decoration. EU AI Act Art. 14
  names automation bias; Art. 86 grants a right to explanation;
  Colorado SB26-189 (2027-01-01) covers housing consequential
  decisions. (:func:`automation_bias_clock`)
* Vendor lock-in: a 5-year $4.6M contract without exit assistance is
  a capture surface. (:func:`vendor_cost_receipt`)

Honest boundary: these receipts bind *declared* review discipline —
they verify that a claimed human review, citation, appeal path, or
cost disclosure is consistent and signed. They cannot make planning
fair, eliminate training-data bias, or force a vendor to honor an
exit-assistance clause. Fairness outcomes remain the human
institution's responsibility; this module just makes the claimed
discipline auditable.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th batch pattern), digest comparisons
via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Sequence

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


PERMIT_SCHEMA_VERSION = "northstar.permit-agents.v1"

#: Genesis hash for hash-chained registries.
_GENESIS = "0" * 64

#: Classification tiers (87th-batch binary semantics).
AUTHORITATIVE = "authoritative"
NON_AUTHORITATIVE = "non-authoritative"


class PermitError(ValueError):
    """Raised on malformed input — fail-closed at the API boundary."""


# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

#: Closed vocabulary of review outcomes an AI pre-check may produce.
#: ``permit`` and ``deny`` are *not* here: the AI is advisory-only,
#: so it may only flag, recommend, or pass — never issue.
PRECHECK_OUTCOMES: tuple[str, ...] = (
    "flag",
    "recommend",
    "pass",
    "needs_information",
)

#: Closed vocabulary of human-review roles. ``rubber_stamp`` is not a
#: role: a review that did not read, mark, and write reasons is not a
#: review.
REVIEW_ROLES: tuple[str, ...] = (
    "reviewing_officer",
    "supervisor",
    "hearing_officer",
    "appeals_reviewer",
)

#: Closed vocabulary of decision kinds this module governs.
DECISION_KINDS: tuple[str, ...] = (
    "building_permit",
    "renovation_permit",
    "zoning_variance",
    "occupancy_certificate",
    "demolition_permit",
)

#: Reason strings that are never specific enough for an adverse
#: decision (the ECOA lesson, housing-batch vocabulary reused).
VAGUE_REASONS: tuple[str, ...] = (
    "model output",
    "algorithmic score",
    "system decision",
    "ai decision",
    "automated decision",
)

#: Denial / degradation reason codes. All start with the ``permit:``
#: prefix.
DENY_UNHUMAN_REVIEWED = "permit:unhuman_reviewed"
DENY_NO_COUNTERSIGN = "permit:no_human_countersign"
DEGRADE_CODE_UNPINNED = "permit:code_version_unpinned"
DEGRADE_CODE_SUPERSEDED = "permit:code_superseded"
DEGRADE_UNCITED = "permit:uncited_recommendation"
DENY_NO_APPEAL = "permit:no_appeal"
AUDIT_DISPARATE_IMPACT = "permit:disparate_impact_audit"
AUDIT_AUTOMATION_BIAS = "permit:automation_bias_audit"
DENY_VENDOR_COST_UNDECLARED = "permit:vendor_cost_undeclared"

#: Maximum override-rate decay: if the observed human-override rate
#: over the window falls at or below this, the review is presumed
#: decorative and an automation-bias audit is triggered.
OVERRIDE_FLOOR = 0.02

#: Maximum permitted flag-rate ratio between the highest-flagged and
#: lowest-flagged slice before a disparate-impact audit triggers.
FLAG_DISPARITY_RATIO_MAX = 2.0


# ---------------------------------------------------------------------------
# Field validators
# ---------------------------------------------------------------------------


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PermitError(f"{field_name} must be a non-empty string")
    return value


def _check_hex64(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise PermitError(f"{field_name} must be a 64-char hex digest")
    try:
        int(value, 16)
    except ValueError:
        raise PermitError(f"{field_name} must be a 64-char hex digest") from None
    return value.lower()


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PermitError(f"{field_name} must be a non-negative integer epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise PermitError(f"{field_name}: Ed25519 secret key must be 32 bytes")
    return bytes(value)


def _check_pubkey_hex(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise PermitError("pubkey must be a 64-char hex string")
    try:
        int(value, 16)
    except ValueError:
        raise PermitError("pubkey must be a 64-char hex string") from None
    return value.lower()


def _check_sig_hex(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != 128:
        raise PermitError(f"{field_name} must be a 128-char hex signature")
    try:
        int(value, 16)
    except ValueError:
        raise PermitError(f"{field_name} must be a 128-char hex signature") from None
    return value.lower()


def _check_precheck_outcome(value: Any) -> str:
    if value not in PRECHECK_OUTCOMES:
        raise PermitError(
            f"precheck outcome must be one of {list(PRECHECK_OUTCOMES)}; "
            "the AI may not issue or deny a permit"
        )
    return value


def _check_review_role(value: Any) -> str:
    if value not in REVIEW_ROLES:
        raise PermitError(f"review role must be one of {list(REVIEW_ROLES)}")
    return value


def _check_decision_kind(value: Any) -> str:
    if value not in DECISION_KINDS:
        raise PermitError(f"decision kind must be one of {list(DECISION_KINDS)}")
    return value


def _verify_sig(pubkey_hex: str, message: bytes, sig_hex: str) -> bool:
    try:
        ed25519.verify(bytes.fromhex(pubkey_hex), message, bytes.fromhex(sig_hex))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Authority registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorityEntry:
    """A reviewing-authority identity whose keys pin every receipt."""

    authority_id: str
    pubkey_hex: str


class AuthorityRegistry:
    """Out-of-band curated authority keys. The repo cannot audit real
    authorities; it can only pin the keys the deployment trusts."""

    def __init__(self) -> None:
        self._entries: dict[str, AuthorityEntry] = {}

    def register(self, authority_id: str, pubkey: bytes) -> None:
        authority_id = _check_nonempty_str(authority_id, "authority_id")
        if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
            raise PermitError("pubkey must be 32 bytes")
        if authority_id in self._entries:
            raise PermitError(f"authority {authority_id!r} already registered")
        self._entries[authority_id] = AuthorityEntry(
            authority_id=authority_id, pubkey_hex=bytes(pubkey).hex()
        )

    def pubkey_hex(self, authority_id: str) -> str:
        try:
            return self._entries[authority_id].pubkey_hex
        except KeyError:
            raise PermitError(f"unknown authority {authority_id!r}") from None

    def known(self, authority_id: str) -> bool:
        return authority_id in self._entries


# ---------------------------------------------------------------------------
# Gate 1: precheck advisory gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrecheckReceipt:
    """An AI pre-check run. The outcome vocabulary is advisory-only:
    the AI may flag/recommend/pass, never issue or deny."""

    precheck_id: str
    application_id: str
    outcome: str
    ai_model_digest: str
    findings_digest: str
    issued_at: int
    issuer_id: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = PERMIT_SCHEMA_VERSION


def _precheck_payload(r: PrecheckReceipt) -> dict[str, Any]:
    return {
        "precheck_id": r.precheck_id,
        "application_id": r.application_id,
        "outcome": r.outcome,
        "ai_model_digest": r.ai_model_digest,
        "findings_digest": r.findings_digest,
        "issued_at": r.issued_at,
        "issuer_id": r.issuer_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def issue_precheck(
    *,
    precheck_id: str,
    application_id: str,
    outcome: str,
    ai_model_digest: str,
    findings_digest: str,
    issued_at: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> PrecheckReceipt:
    """Issue a signed AI pre-check receipt. Fail-closed at issuance:
    the outcome vocabulary excludes issuance/denial, so the AI cannot
    encode a permit decision even by accident."""
    precheck_id = _check_nonempty_str(precheck_id, "precheck_id")
    application_id = _check_nonempty_str(application_id, "application_id")
    outcome = _check_precheck_outcome(outcome)
    ai_model_digest = _check_hex64(ai_model_digest, "ai_model_digest")
    findings_digest = _check_hex64(findings_digest, "findings_digest")
    issued_at = _check_ts(issued_at, "issued_at")
    issuer_id = _check_nonempty_str(issuer_id, "issuer_id")
    secret = _check_secret(issuer_secret, "issuer_secret")
    pubkey_hex = ed25519.public_key(secret).hex()
    bare = PrecheckReceipt(
        precheck_id=precheck_id,
        application_id=application_id,
        outcome=outcome,
        ai_model_digest=ai_model_digest,
        findings_digest=findings_digest,
        issued_at=issued_at,
        issuer_id=issuer_id,
        issuer_pubkey_hex=pubkey_hex,
        signature_hex="",
    )
    msg = jcs_canonical_json(_precheck_payload(bare))
    sig_hex = ed25519.sign(secret, msg).hex()
    sealed = PrecheckReceipt(
        **{**bare.__dict__, "signature_hex": sig_hex}
    )
    digest = jcs_sha256_hex({**_precheck_payload(sealed), "signature_hex": sig_hex})
    return PrecheckReceipt(**{**sealed.__dict__, "receipt_digest": digest})


@dataclass(frozen=True)
class PrecheckVerdict:
    allowed: bool
    tier: str
    deny_code: str = ""
    precheck_id: str = ""


def precheck_advisory_gate(
    receipt: PrecheckReceipt,
    *,
    decision_was_issued: bool,
    human_reviewed: bool,
) -> PrecheckVerdict:
    """A permit issued on the AI pre-check's say-so alone denies.

    ``decision_was_issued`` is True when the caller claims a permit
    decision resulted from this pre-check. If True and
    ``human_reviewed`` is False, the decision is
    ``permit:unhuman_reviewed`` — the AI recommended, the office
    rubber-stamped, and nobody actually reviewed. If no decision was
    issued (advisory use only), the receipt is AUTHORITATIVE as a
    pre-check record.
    """
    if not _verify_sig(
        receipt.issuer_pubkey_hex,
        jcs_canonical_json(_precheck_payload(receipt)),
        receipt.signature_hex,
    ):
        return PrecheckVerdict(False, NON_AUTHORITATIVE, "permit:precheck_sig_invalid",
                               receipt.precheck_id)
    if decision_was_issued and not human_reviewed:
        return PrecheckVerdict(False, NON_AUTHORITATIVE, DENY_UNHUMAN_REVIEWED,
                               receipt.precheck_id)
    return PrecheckVerdict(True, AUTHORITATIVE, "", receipt.precheck_id)


# ---------------------------------------------------------------------------
# Gate 2: final human signoff
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HumanSignoffReceipt:
    """A named human's countersign on a decision. The AI may score;
    only a human may read, mark, and write reasons."""

    signoff_id: str
    decision_id: str
    decision_kind: str
    reviewer_name: str
    review_role: str
    reasons_digest: str
    ai_score_digest: str
    signed_at: int
    authority_id: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = PERMIT_SCHEMA_VERSION


def _signoff_payload(r: HumanSignoffReceipt) -> dict[str, Any]:
    return {
        "signoff_id": r.signoff_id,
        "decision_id": r.decision_id,
        "decision_kind": r.decision_kind,
        "reviewer_name": r.reviewer_name,
        "review_role": r.review_role,
        "reasons_digest": r.reasons_digest,
        "ai_score_digest": r.ai_score_digest,
        "signed_at": r.signed_at,
        "authority_id": r.authority_id,
        "schema_version": r.schema_version,
    }


def issue_human_signoff(
    *,
    signoff_id: str,
    decision_id: str,
    decision_kind: str,
    reviewer_name: str,
    review_role: str,
    reasons: str,
    ai_score_digest: str,
    signed_at: int,
    authority_id: str,
    signer_secret: bytes,
) -> HumanSignoffReceipt:
    """Issue a human countersign. Fail-closed at issuance: a vague
    reason (\"model output\", \"ai decision\", ...) raises — the
    human must write actual reasons, per the UK Procurement Act
    accountability lesson."""
    signoff_id = _check_nonempty_str(signoff_id, "signoff_id")
    decision_id = _check_nonempty_str(decision_id, "decision_id")
    decision_kind = _check_decision_kind(decision_kind)
    reviewer_name = _check_nonempty_str(reviewer_name, "reviewer_name")
    review_role = _check_review_role(review_role)
    reasons = _check_nonempty_str(reasons, "reasons")
    if reasons.strip().lower() in VAGUE_REASONS:
        raise PermitError(
            "vague reason %r is not a review; the human must write actual reasons"
            % reasons
        )
    ai_score_digest = _check_hex64(ai_score_digest, "ai_score_digest")
    signed_at = _check_ts(signed_at, "signed_at")
    authority_id = _check_nonempty_str(authority_id, "authority_id")
    secret = _check_secret(signer_secret, "signer_secret")
    reasons_digest = jcs_sha256_hex({"reasons": reasons})
    bare = HumanSignoffReceipt(
        signoff_id=signoff_id,
        decision_id=decision_id,
        decision_kind=decision_kind,
        reviewer_name=reviewer_name,
        review_role=review_role,
        reasons_digest=reasons_digest,
        ai_score_digest=ai_score_digest,
        signed_at=signed_at,
        authority_id=authority_id,
        signature_hex="",
    )
    msg = jcs_canonical_json(_signoff_payload(bare))
    sig_hex = ed25519.sign(secret, msg).hex()
    sealed = HumanSignoffReceipt(
        **{**bare.__dict__, "signature_hex": sig_hex}
    )
    digest = jcs_sha256_hex({**_signoff_payload(sealed), "signature_hex": sig_hex})
    return HumanSignoffReceipt(**{**sealed.__dict__, "receipt_digest": digest})


@dataclass(frozen=True)
class SignoffVerdict:
    allowed: bool
    tier: str
    deny_code: str = ""
    signoff_id: str = ""


def final_human_signoff(
    decision_id: str,
    decision_kind: str,
    signoff: HumanSignoffReceipt | None,
    authorities: AuthorityRegistry,
    *,
    reviewed_at: int,
) -> SignoffVerdict:
    """Require a valid named-human countersign bound to this exact
    decision. No countersign, a countersign for a *different*
    decision, an unknown authority, or a broken signature denies."""
    reviewed_at = _check_ts(reviewed_at, "reviewed_at")
    if signoff is None:
        return SignoffVerdict(False, NON_AUTHORITATIVE, DENY_NO_COUNTERSIGN, "")
    if signoff.decision_id != decision_id or signoff.decision_kind != decision_kind:
        return SignoffVerdict(False, NON_AUTHORITATIVE, "permit:signoff_mismatch",
                               signoff.signoff_id)
    if not authorities.known(signoff.authority_id):
        return SignoffVerdict(False, NON_AUTHORITATIVE, "permit:unknown_authority",
                               signoff.signoff_id)
    if signoff.signed_at > reviewed_at:
        return SignoffVerdict(False, NON_AUTHORITATIVE, "permit:signoff_from_future",
                               signoff.signoff_id)
    pubkey_hex = authorities.pubkey_hex(signoff.authority_id)
    if not _verify_sig(
        pubkey_hex,
        jcs_canonical_json(_signoff_payload(signoff)),
        signoff.signature_hex,
    ):
        return SignoffVerdict(False, NON_AUTHORITATIVE, "permit:signoff_sig_invalid",
                               signoff.signoff_id)
    return SignoffVerdict(True, AUTHORITATIVE, "", signoff.signoff_id)


# ---------------------------------------------------------------------------
# Gate 3: code version pin
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CodeVersionReceipt:
    """The code/regulation version pinned at review time. The AI may
    not cite superseded provisions."""

    pin_id: str
    code_name: str
    code_version: str
    effective_from: int
    superseded_by: str = ""
    issuer_id: str = ""
    issuer_pubkey_hex: str = ""
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = PERMIT_SCHEMA_VERSION


def _codepin_payload(r: CodeVersionReceipt) -> dict[str, Any]:
    return {
        "pin_id": r.pin_id,
        "code_name": r.code_name,
        "code_version": r.code_version,
        "effective_from": r.effective_from,
        "superseded_by": r.superseded_by,
        "issuer_id": r.issuer_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def issue_code_pin(
    *,
    pin_id: str,
    code_name: str,
    code_version: str,
    effective_from: int,
    superseded_by: str = "",
    issuer_id: str = "",
    issuer_secret: bytes | None = None,
) -> CodeVersionReceipt:
    """Pin a code version. Unsigned pins are allowed (a planning
    office may publish its code book without a key), but they degrade
    to NON_AUTHORITATIVE at check time."""
    pin_id = _check_nonempty_str(pin_id, "pin_id")
    code_name = _check_nonempty_str(code_name, "code_name")
    code_version = _check_nonempty_str(code_version, "code_version")
    effective_from = _check_ts(effective_from, "effective_from")
    if superseded_by and not isinstance(superseded_by, str):
        raise PermitError("superseded_by must be a string")
    issuer_id = issuer_id or ""
    pubkey_hex = ""
    sig_hex = ""
    if issuer_secret is not None:
        secret = _check_secret(issuer_secret, "issuer_secret")
        issuer_id = _check_nonempty_str(issuer_id, "issuer_id")
        pubkey_hex = ed25519.public_key(secret).hex()
    bare = CodeVersionReceipt(
        pin_id=pin_id, code_name=code_name, code_version=code_version,
        effective_from=effective_from, superseded_by=superseded_by,
        issuer_id=issuer_id, issuer_pubkey_hex=pubkey_hex, signature_hex=sig_hex,
    )
    if pubkey_hex:
        msg = jcs_canonical_json(_codepin_payload(bare))
        sig_hex = ed25519.sign(secret, msg).hex()  # noqa: F821
        bare = CodeVersionReceipt(**{**bare.__dict__, "signature_hex": sig_hex})
    digest = jcs_sha256_hex({**_codepin_payload(bare), "signature_hex": sig_hex})
    return CodeVersionReceipt(**{**bare.__dict__, "receipt_digest": digest})


@dataclass(frozen=True)
class CodePinVerdict:
    allowed: bool
    tier: str
    deny_code: str = ""
    pin_id: str = ""


def code_version_pin(
    pin: CodeVersionReceipt | None,
    cited_version: str,
    *,
    checked_at: int,
) -> CodePinVerdict:
    """Check the cited code version against the pin. No pin ->
    NON_AUTHORITATIVE (probabilistic output may not run ahead of
    pinned code). Citing a superseded version -> NON_AUTHORITATIVE.
    A signed, current pin -> AUTHORITATIVE."""
    checked_at = _check_ts(checked_at, "checked_at")
    if pin is None:
        return CodePinVerdict(False, NON_AUTHORITATIVE, DEGRADE_CODE_UNPINNED, "")
    if not cited_version or not isinstance(cited_version, str):
        return CodePinVerdict(False, NON_AUTHORITATIVE, DEGRADE_CODE_UNPINNED, pin.pin_id)
    if pin.superseded_by:
        # The pinned version has itself been superseded: any citation
        # against this pin is a citation of superseded code.
        return CodePinVerdict(False, NON_AUTHORITATIVE, DEGRADE_CODE_SUPERSEDED,
                               pin.pin_id)
    if cited_version != pin.code_version:
        return CodePinVerdict(False, NON_AUTHORITATIVE, DEGRADE_CODE_UNPINNED,
                               pin.pin_id)
    if pin.issuer_pubkey_hex:
        if not _verify_sig(
            pin.issuer_pubkey_hex,
            jcs_canonical_json(_codepin_payload(pin)),
            pin.signature_hex,
        ):
            return CodePinVerdict(False, NON_AUTHORITATIVE, "permit:codepin_sig_invalid",
                                   pin.pin_id)
    return CodePinVerdict(True, AUTHORITATIVE, "", pin.pin_id)


# ---------------------------------------------------------------------------
# Gate 4: normative source receipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormativeSourceReceipt:
    """Every AI recommendation binds its code citation: the exact
    provision, the bound code pin, and the quote digest. The Toronto /
    REVI lesson: no citation, no authority."""

    citation_id: str
    precheck_id: str
    code_name: str
    code_version: str
    provision: str
    quote_digest: str
    pin_id: str
    cited_at: int
    issuer_id: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = PERMIT_SCHEMA_VERSION


def _citation_payload(r: NormativeSourceReceipt) -> dict[str, Any]:
    return {
        "citation_id": r.citation_id,
        "precheck_id": r.precheck_id,
        "code_name": r.code_name,
        "code_version": r.code_version,
        "provision": r.provision,
        "quote_digest": r.quote_digest,
        "pin_id": r.pin_id,
        "cited_at": r.cited_at,
        "issuer_id": r.issuer_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def issue_normative_source(
    *,
    citation_id: str,
    precheck_id: str,
    code_name: str,
    code_version: str,
    provision: str,
    quoted_text: str,
    pin_id: str,
    cited_at: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> NormativeSourceReceipt:
    citation_id = _check_nonempty_str(citation_id, "citation_id")
    precheck_id = _check_nonempty_str(precheck_id, "precheck_id")
    code_name = _check_nonempty_str(code_name, "code_name")
    code_version = _check_nonempty_str(code_version, "code_version")
    provision = _check_nonempty_str(provision, "provision")
    quoted_text = _check_nonempty_str(quoted_text, "quoted_text")
    pin_id = _check_nonempty_str(pin_id, "pin_id")
    cited_at = _check_ts(cited_at, "cited_at")
    issuer_id = _check_nonempty_str(issuer_id, "issuer_id")
    secret = _check_secret(issuer_secret, "issuer_secret")
    quote_digest = jcs_sha256_hex({"quote": quoted_text})
    pubkey_hex = ed25519.public_key(secret).hex()
    bare = NormativeSourceReceipt(
        citation_id=citation_id, precheck_id=precheck_id, code_name=code_name,
        code_version=code_version, provision=provision, quote_digest=quote_digest,
        pin_id=pin_id, cited_at=cited_at, issuer_id=issuer_id,
        issuer_pubkey_hex=pubkey_hex, signature_hex="",
    )
    msg = jcs_canonical_json(_citation_payload(bare))
    sig_hex = ed25519.sign(secret, msg).hex()
    sealed = NormativeSourceReceipt(**{**bare.__dict__, "signature_hex": sig_hex})
    digest = jcs_sha256_hex({**_citation_payload(sealed), "signature_hex": sig_hex})
    return NormativeSourceReceipt(**{**sealed.__dict__, "receipt_digest": digest})


@dataclass(frozen=True)
class CitationVerdict:
    allowed: bool
    tier: str
    deny_code: str = ""
    citation_id: str = ""


def normative_source_receipt(
    recommendation_id: str,
    precheck_id: str,
    citation: NormativeSourceReceipt | None,
    pin: CodeVersionReceipt | None,
) -> CitationVerdict:
    """A recommendation is authoritative only when it binds a valid,
    signed citation to a current code pin. No citation ->
    NON_AUTHORITATIVE; citation for a different pre-check ->
    NON_AUTHORITATIVE; pin mismatch or superseded code ->
    NON_AUTHORITATIVE."""
    if citation is None:
        return CitationVerdict(False, NON_AUTHORITATIVE, DEGRADE_UNCITED, "")
    if citation.precheck_id != precheck_id:
        return CitationVerdict(False, NON_AUTHORITATIVE, "permit:citation_mismatch", "")
    if not _verify_sig(
        citation.issuer_pubkey_hex,
        jcs_canonical_json(_citation_payload(citation)),
        citation.signature_hex,
    ):
        return CitationVerdict(False, NON_AUTHORITATIVE, "permit:citation_sig_invalid",
                               citation.citation_id)
    if pin is None or pin.pin_id != citation.pin_id:
        return CitationVerdict(False, NON_AUTHORITATIVE, DEGRADE_CODE_UNPINNED,
                               citation.citation_id)
    if pin.code_version != citation.code_version:
        return CitationVerdict(False, NON_AUTHORITATIVE, DEGRADE_CODE_SUPERSEDED,
                               citation.citation_id)
    if pin.superseded_by and pin.superseded_by != "":
        # The pinned version has been superseded since citation.
        return CitationVerdict(False, NON_AUTHORITATIVE, DEGRADE_CODE_SUPERSEDED,
                               citation.citation_id)
    return CitationVerdict(True, AUTHORITATIVE, "", citation.citation_id)


# ---------------------------------------------------------------------------
# Gate 5: disparate-impact probe
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DisparityProbeReceipt:
    """A vendor-signed flag-rate probe over slices (neighborhoods /
    income bands). Hash-chained like the housing-batch probe."""

    probe_id: str
    model_digest: str
    slice_labels: tuple[str, ...]
    slice_flag_rates: tuple[float, ...]
    measured_at: int
    expires_at: int
    vendor_id: str
    vendor_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    probe_receipt_digest: str = ""
    schema_version: str = PERMIT_SCHEMA_VERSION


def _probe_payload(r: DisparityProbeReceipt) -> dict[str, Any]:
    return {
        "probe_id": r.probe_id,
        "model_digest": r.model_digest,
        "slice_labels": list(r.slice_labels),
        "slice_flag_rates": list(r.slice_flag_rates),
        "measured_at": r.measured_at,
        "expires_at": r.expires_at,
        "vendor_id": r.vendor_id,
        "vendor_pubkey_hex": r.vendor_pubkey_hex,
        "prev_digest": r.prev_digest,
        "schema_version": r.schema_version,
    }


def issue_disparity_probe(
    *,
    probe_id: str,
    model_digest: str,
    slice_labels: Sequence[str],
    slice_flag_rates: Sequence[float],
    measured_at: int,
    expires_at: int,
    vendor_id: str,
    vendor_secret: bytes,
    prev_digest: str = _GENESIS,
) -> DisparityProbeReceipt:
    """Issue a vendor-signed disparity probe receipt. Fail-closed at
    issuance: empty slices raise, mismatched label/rate lengths raise,
    negative rates raise, ``expires_at <= measured_at`` raises."""
    probe_id = _check_nonempty_str(probe_id, "probe_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    labels = [_check_nonempty_str(s, "slice_label") for s in slice_labels]
    rates = list(slice_flag_rates)
    if not labels:
        raise PermitError("a probe measured on nobody proves nothing")
    if len(labels) != len(rates):
        raise PermitError("slice_labels and slice_flag_rates must match in length")
    if len(set(labels)) != len(labels):
        raise PermitError("duplicate slice label")
    for rate in rates:
        if not isinstance(rate, (int, float)) or isinstance(rate, bool) or rate < 0:
            raise PermitError("flag rates must be non-negative numbers")
    measured_at = _check_ts(measured_at, "measured_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= measured_at:
        raise PermitError("expires_at must be after measured_at")
    vendor_id = _check_nonempty_str(vendor_id, "vendor_id")
    secret = _check_secret(vendor_secret, "vendor_secret")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise PermitError("prev_digest must be a non-empty string")
    pubkey_hex = ed25519.public_key(secret).hex()
    bare = DisparityProbeReceipt(
        probe_id=probe_id, model_digest=model_digest,
        slice_labels=tuple(labels), slice_flag_rates=tuple(float(r) for r in rates),
        measured_at=measured_at, expires_at=expires_at, vendor_id=vendor_id,
        vendor_pubkey_hex=pubkey_hex, signature_hex="", prev_digest=prev_digest,
    )
    msg = jcs_canonical_json(_probe_payload(bare))
    sig_hex = ed25519.sign(secret, msg).hex()
    sealed = DisparityProbeReceipt(**{**bare.__dict__, "signature_hex": sig_hex})
    digest = jcs_sha256_hex({**_probe_payload(sealed), "signature_hex": sig_hex})
    return DisparityProbeReceipt(**{**sealed.__dict__, "probe_receipt_digest": digest})


@dataclass(frozen=True)
class DisparityVerdict:
    allowed: bool
    tier: str
    audit_code: str = ""
    max_ratio: float = 0.0
    probe_id: str = ""


def disparate_impact_probe(
    receipt: DisparityProbeReceipt,
    *,
    checked_at: int,
) -> DisparityVerdict:
    """Check the flag-rate disparity between slices. If the highest
    slice rate divided by the lowest *nonzero* slice rate exceeds
    :data:`FLAG_DISPARITY_RATIO_MAX`, the model is quarantined for a
    disparate-impact audit (``permit:disparate_impact_audit``). An
    expired probe, an unknown vendor signature, or a probe measured
    on a different model cannot authorize anything — fail-closed."""
    checked_at = _check_ts(checked_at, "checked_at")
    if not _verify_sig(
        receipt.vendor_pubkey_hex,
        jcs_canonical_json(_probe_payload(receipt)),
        receipt.signature_hex,
    ):
        return DisparityVerdict(False, NON_AUTHORITATIVE, "permit:probe_sig_invalid",
                                0.0, receipt.probe_id)
    if checked_at > receipt.expires_at:
        return DisparityVerdict(False, NON_AUTHORITATIVE, "permit:probe_expired",
                                0.0, receipt.probe_id)
    rates = [r for r in receipt.slice_flag_rates if r > 0]
    if not rates:
        return DisparityVerdict(False, NON_AUTHORITATIVE, "permit:probe_empty_rates",
                                0.0, receipt.probe_id)
    max_ratio = max(rates) / min(rates)
    if max_ratio > FLAG_DISPARITY_RATIO_MAX:
        return DisparityVerdict(False, NON_AUTHORITATIVE, AUDIT_DISPARATE_IMPACT,
                                max_ratio, receipt.probe_id)
    return DisparityVerdict(True, AUTHORITATIVE, "", max_ratio, receipt.probe_id)


# ---------------------------------------------------------------------------
# Gate 6: appeal window
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AppealPathReceipt:
    """Every auto-influenced decision binds an appeal path with a real
    human reviewer. The SafeRent lesson, made structural: a decision
    the machine made and nobody can appeal is a denial of due
    process."""

    path_id: str
    decision_id: str
    decision_kind: str
    appeals_reviewer_name: str
    appeal_deadline: int
    contact_digest: str
    issued_at: int
    authority_id: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = PERMIT_SCHEMA_VERSION


def _appeal_payload(r: AppealPathReceipt) -> dict[str, Any]:
    return {
        "path_id": r.path_id,
        "decision_id": r.decision_id,
        "decision_kind": r.decision_kind,
        "appeals_reviewer_name": r.appeals_reviewer_name,
        "appeal_deadline": r.appeal_deadline,
        "contact_digest": r.contact_digest,
        "issued_at": r.issued_at,
        "authority_id": r.authority_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def issue_appeal_path(
    *,
    path_id: str,
    decision_id: str,
    decision_kind: str,
    appeals_reviewer_name: str,
    appeal_deadline: int,
    appeal_contact: str,
    issued_at: int,
    authority_id: str,
    issuer_secret: bytes,
) -> AppealPathReceipt:
    path_id = _check_nonempty_str(path_id, "path_id")
    decision_id = _check_nonempty_str(decision_id, "decision_id")
    decision_kind = _check_decision_kind(decision_kind)
    appeals_reviewer_name = _check_nonempty_str(appeals_reviewer_name,
                                                "appeals_reviewer_name")
    appeal_deadline = _check_ts(appeal_deadline, "appeal_deadline")
    appeal_contact = _check_nonempty_str(appeal_contact, "appeal_contact")
    issued_at = _check_ts(issued_at, "issued_at")
    authority_id = _check_nonempty_str(authority_id, "authority_id")
    secret = _check_secret(issuer_secret, "issuer_secret")
    if appeal_deadline <= issued_at:
        raise PermitError("appeal_deadline must be after issued_at")
    contact_digest = jcs_sha256_hex({"contact": appeal_contact})
    pubkey_hex = ed25519.public_key(secret).hex()
    bare = AppealPathReceipt(
        path_id=path_id, decision_id=decision_id, decision_kind=decision_kind,
        appeals_reviewer_name=appeals_reviewer_name, appeal_deadline=appeal_deadline,
        contact_digest=contact_digest, issued_at=issued_at,
        authority_id=authority_id, issuer_pubkey_hex=pubkey_hex, signature_hex="",
    )
    msg = jcs_canonical_json(_appeal_payload(bare))
    sig_hex = ed25519.sign(secret, msg).hex()
    sealed = AppealPathReceipt(**{**bare.__dict__, "signature_hex": sig_hex})
    digest = jcs_sha256_hex({**_appeal_payload(sealed), "signature_hex": sig_hex})
    return AppealPathReceipt(**{**sealed.__dict__, "receipt_digest": digest})


@dataclass(frozen=True)
class AppealVerdict:
    allowed: bool
    tier: str
    deny_code: str = ""
    path_id: str = ""


def appeal_window_gate(
    decision_id: str,
    appeal: AppealPathReceipt | None,
    *,
    checked_at: int,
) -> AppealVerdict:
    """An auto-influenced decision with no bound appeal path denies
    (``permit:no_appeal``). An appeal path for a different decision,
    an expired deadline, or a broken signature also denies."""
    checked_at = _check_ts(checked_at, "checked_at")
    if appeal is None:
        return AppealVerdict(False, NON_AUTHORITATIVE, DENY_NO_APPEAL, "")
    if appeal.decision_id != decision_id:
        return AppealVerdict(False, NON_AUTHORITATIVE, "permit:appeal_mismatch", "")
    if checked_at > appeal.appeal_deadline:
        return AppealVerdict(False, NON_AUTHORITATIVE, "permit:appeal_window_expired",
                              appeal.path_id)
    if not _verify_sig(
        appeal.issuer_pubkey_hex,
        jcs_canonical_json(_appeal_payload(appeal)),
        appeal.signature_hex,
    ):
        return AppealVerdict(False, NON_AUTHORITATIVE, "permit:appeal_sig_invalid",
                              appeal.path_id)
    return AppealVerdict(True, AUTHORITATIVE, "", appeal.path_id)


# ---------------------------------------------------------------------------
# Gate 7: automation-bias clock
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OverrideWindow:
    """An observed override window: how many AI-influenced decisions
    a human overrode. ``total == 0`` is fail-closed (no observation
    is not evidence of compliance)."""

    window_id: str
    overridden: int
    total: int
    observed_at: int


@dataclass(frozen=True)
class BiasClockVerdict:
    audit_required: bool
    audit_code: str
    override_rate: float
    window_id: str


def automation_bias_clock(
    window: OverrideWindow,
    *,
    min_total: int = 20,
) -> BiasClockVerdict:
    """If the human override rate over the window is at or below
    :data:`OVERRIDE_FLOOR`, the review is presumed decorative and an
    automation-bias audit is required (``permit:automation_bias_audit``).
    Too few observations (< ``min_total``) cannot clear the model —
    they *require* the audit too, because absence of data is not
    evidence of diligence. EU AI Act Art. 14 names automation bias;
    this makes the bias measurable."""
    if not isinstance(window.overridden, int) or window.overridden < 0:
        raise PermitError("overridden must be a non-negative integer")
    if not isinstance(window.total, int) or window.total < 0:
        raise PermitError("total must be a non-negative integer")
    if window.overridden > window.total:
        raise PermitError("overridden cannot exceed total")
    if window.total < min_total:
        return BiasClockVerdict(True, "permit:insufficient_observation",
                                window.overridden / window.total if window.total else 0.0,
                                window.window_id)
    rate = window.overridden / window.total
    if rate <= OVERRIDE_FLOOR:
        return BiasClockVerdict(True, AUDIT_AUTOMATION_BIAS, rate, window.window_id)
    return BiasClockVerdict(False, "", rate, window.window_id)


# ---------------------------------------------------------------------------
# Gate 8: vendor cost receipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VendorCostReceipt:
    """A vendor contract binds its 5-year total cost plus a declared
    exit-assistance clause. A contract that hides its total or its
    exit path is a capture surface."""

    receipt_id: str
    vendor_id: str
    contract_years: int
    total_cost_cents: int
    exit_assistance_disclosed: bool
    contract_digest: str
    issued_at: int
    authority_id: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = PERMIT_SCHEMA_VERSION


def _cost_payload(r: VendorCostReceipt) -> dict[str, Any]:
    return {
        "receipt_id": r.receipt_id,
        "vendor_id": r.vendor_id,
        "contract_years": r.contract_years,
        "total_cost_cents": r.total_cost_cents,
        "exit_assistance_disclosed": r.exit_assistance_disclosed,
        "contract_digest": r.contract_digest,
        "issued_at": r.issued_at,
        "authority_id": r.authority_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def issue_vendor_cost(
    *,
    receipt_id: str,
    vendor_id: str,
    contract_years: int,
    total_cost_cents: int,
    exit_assistance_disclosed: bool,
    contract_digest: str,
    issued_at: int,
    authority_id: str,
    issuer_secret: bytes,
) -> VendorCostReceipt:
    """Issue a vendor-cost receipt. Fail-closed at issuance:
    non-positive cost raises, zero-length contracts raise, and a
    contract without declared exit assistance raises — the clause
    must be *declared*, even if the declaration is "none provided"
    (that still binds the vendor to having said so)."""
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    vendor_id = _check_nonempty_str(vendor_id, "vendor_id")
    if not isinstance(contract_years, int) or isinstance(contract_years, bool) \
            or contract_years <= 0:
        raise PermitError("contract_years must be a positive integer")
    if not isinstance(total_cost_cents, int) or isinstance(total_cost_cents, bool) \
            or total_cost_cents <= 0:
        raise PermitError("total_cost_cents must be a positive integer")
    if not isinstance(exit_assistance_disclosed, bool):
        raise PermitError("exit_assistance_disclosed must be a bool")
    if not exit_assistance_disclosed:
        raise PermitError(
            "exit assistance must be declared before a vendor contract is signed; "
            "declare the assistance terms or walk away"
        )
    contract_digest = _check_hex64(contract_digest, "contract_digest")
    issued_at = _check_ts(issued_at, "issued_at")
    authority_id = _check_nonempty_str(authority_id, "authority_id")
    secret = _check_secret(issuer_secret, "issuer_secret")
    pubkey_hex = ed25519.public_key(secret).hex()
    bare = VendorCostReceipt(
        receipt_id=receipt_id, vendor_id=vendor_id,
        contract_years=contract_years, total_cost_cents=total_cost_cents,
        exit_assistance_disclosed=exit_assistance_disclosed,
        contract_digest=contract_digest, issued_at=issued_at,
        authority_id=authority_id, issuer_pubkey_hex=pubkey_hex,
        signature_hex="",
    )
    msg = jcs_canonical_json(_cost_payload(bare))
    sig_hex = ed25519.sign(secret, msg).hex()
    sealed = VendorCostReceipt(**{**bare.__dict__, "signature_hex": sig_hex})
    digest = jcs_sha256_hex({**_cost_payload(sealed), "signature_hex": sig_hex})
    return VendorCostReceipt(**{**sealed.__dict__, "receipt_digest": digest})


@dataclass(frozen=True)
class VendorCostVerdict:
    allowed: bool
    tier: str
    deny_code: str = ""
    receipt_id: str = ""


def vendor_cost_receipt(
    receipt: VendorCostReceipt,
    authorities: AuthorityRegistry,
) -> VendorCostVerdict:
    """A vendor contract is enforceable only with a valid signed
    cost receipt from a known authority. Missing, unsigned,
    or broken-signature receipts deny."""
    if not authorities.known(receipt.authority_id):
        return VendorCostVerdict(False, NON_AUTHORITATIVE, "permit:unknown_authority",
                                 receipt.receipt_id)
    pubkey_hex = authorities.pubkey_hex(receipt.authority_id)
    if not _verify_sig(
        pubkey_hex,
        jcs_canonical_json(_cost_payload(receipt)),
        receipt.signature_hex,
    ):
        return VendorCostVerdict(False, NON_AUTHORITATIVE, "permit:cost_sig_invalid",
                                 receipt.receipt_id)
    if not receipt.exit_assistance_disclosed:
        return VendorCostVerdict(False, NON_AUTHORITATIVE, DENY_VENDOR_COST_UNDECLARED,
                                 receipt.receipt_id)
    return VendorCostVerdict(True, AUTHORITATIVE, "", receipt.receipt_id)


__all__ = [
    "PERMIT_SCHEMA_VERSION",
    "AUTHORITATIVE",
    "NON_AUTHORITATIVE",
    "PermitError",
    "PRECHECK_OUTCOMES",
    "REVIEW_ROLES",
    "DECISION_KINDS",
    "VAGUE_REASONS",
    "DENY_UNHUMAN_REVIEWED",
    "DENY_NO_COUNTERSIGN",
    "DEGRADE_CODE_UNPINNED",
    "DEGRADE_CODE_SUPERSEDED",
    "DEGRADE_UNCITED",
    "DENY_NO_APPEAL",
    "AUDIT_DISPARATE_IMPACT",
    "AUDIT_AUTOMATION_BIAS",
    "DENY_VENDOR_COST_UNDECLARED",
    "OVERRIDE_FLOOR",
    "FLAG_DISPARITY_RATIO_MAX",
    "AuthorityRegistry",
    "PrecheckReceipt",
    "issue_precheck",
    "PrecheckVerdict",
    "precheck_advisory_gate",
    "HumanSignoffReceipt",
    "issue_human_signoff",
    "SignoffVerdict",
    "final_human_signoff",
    "CodeVersionReceipt",
    "issue_code_pin",
    "CodePinVerdict",
    "code_version_pin",
    "NormativeSourceReceipt",
    "issue_normative_source",
    "CitationVerdict",
    "normative_source_receipt",
    "DisparityProbeReceipt",
    "issue_disparity_probe",
    "DisparityVerdict",
    "disparate_impact_probe",
    "AppealPathReceipt",
    "issue_appeal_path",
    "AppealVerdict",
    "appeal_window_gate",
    "OverrideWindow",
    "BiasClockVerdict",
    "automation_bias_clock",
    "VendorCostReceipt",
    "issue_vendor_cost",
    "VendorCostVerdict",
    "vendor_cost_receipt",
]
