"""Agentic commerce terms (one-hundred-twenty-fourth batch).

Absorbs the 2026 AI-fashion/retail research thread — agentic
commerce arrived, and the agent now transacts before it reads:

* **"Try on" buttons (Oct 2026)**: ChatGPT's try-on (explicit
  "preview only, fit not guaranteed"); Google Nano Banana
  selfie-to-full-body; ZOZO's AI fitting room (diagnose -> recommend
  -> explain -> try-on -> buy, Japanese PR). The preview is a
  *preview*, never a fit guarantee.
* **Agentic commerce protocols**: ACP (OpenAI+Stripe), UCP
  (Google+Shopify/Etsy/Walmart), AP2 cryptographic authorization
  proofs. Adobe Q1: AI referral traffic +393% YoY — but only **66%
  of product pages are machine-readable**: agents place orders
  without ever seeing the size chart, the return policy, or the
  fees. The read must be a bound receipt, not a hope.
* **Pujols v. Rainbow USA (May 2026)**: a brand AI-altered a model
  from a studio shot into a "sexy pose" ad; the contract only
  allowed minor retouching. The open legal question: does an
  existing likeness authorization cover an AI-generated *new*
  likeness? The gate treats it as fail-closed — a grant covers only
  its declared use classes.
* **BIPA wave**: LV virtual try-on (facial geometry) sued;
  Neutrogena's $4.7M settlement (Feb 2026). Body/facial data for
  try-on needs a biometric receipt with purpose, retention, and a
  *verifiable* deletion obligation.
* **EU AI Act (applicable 2026-08-02)**: virtual models need
  machine-readable marking, AI shopping assistants must self-
  identify, in-store emotion recognition is restricted. The EU ESPR
  (2027) makes digital product passports mandatory; the Aura
  consortium already carries 70M+ product passports — a passport
  claimed on a listing must be *bound* to it.
* **Authentication claims**: Entrupy's "99.1%" is vendor-declared.
  A claimed confidence is a declaration, never a guarantee;
  graded evidence plus a mandatory human-review path for
  high-value items.

Northstar mapping: receipts verify that the agent *read the terms
and bound the evidence*; they do not make the merchant honest.
The gates are tripwires on the buying pipeline:

1. **Terms read** — an order without an authority-signed
   ``TermsReadReceipt`` binding the machine-readable size chart,
   return policy, and total price (incl. fees) for *this exact
   product* denies with ``commerce.unverifiable_terms``.
2. **Likeness creep** — a likeness grant covers only its declared
   use classes. An AI-generated new class (studio shot ->
   sexualized ad) without a new grant denies with
   ``commerce.likeness_creep`` (the Pujols lesson).
3. **Biometric capture** — facial geometry / body measurements for
   try-on without a live ``BiometricCaptureReceipt`` (purpose,
   retention, deletion mechanism) deny. Past retention without a
   signed deletion receipt denies with
   ``commerce.deletion_unverified`` (the BIPA lesson).
4. **Preview classification** — try-on previews are
   ``non_authoritative`` by construction; using one as a fit
   decision denies with ``commerce.fit_guarantee_claim``.
5. **Authentication evidence** — verdicts are graded by evidence
   tier with confidence ceilings; vendor-declared claims above
   their ceiling deny with ``commerce.ungraded_auth_claim``;
   high-value items without a human-review path deny with
   ``commerce.human_review_required``.
6. **Passport binding** — a listing claiming a digital passport
   must bind its digest; mismatch denies with
   ``commerce.passport_mismatch``.
7. **Model substitution** — AI models replacing human catalog
   models without disclosure deny with
   ``commerce.hidden_model_substitution``.

Honest boundary: receipts are *declared evidence*. The gate
checks that the agent read the terms (digests recompute, chains
link, signatures verify, purposes match, deletions are claimed and
signed) — not that the merchant's terms are fair or its passport
is genuine. A consistent-but-false receipt still needs an
off-chain adjudicator.

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


COMMERCE_SCHEMA_VERSION = "northstar.commerce.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128
_SECONDS_PER_DAY = 86_400

#: Policy classification tiers.
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Denial reason codes. All verdict reasons start with one of these.
DENY_UNVERIFIABLE_TERMS = "commerce.unverifiable_terms"
DENY_LIKENESS_CREEP = "commerce.likeness_creep"
DENY_NO_LIKENESS_GRANT = "commerce.no_likeness_grant"
DENY_NO_BIOMETRIC_RECEIPT = "commerce.no_biometric_receipt"
DENY_BIOMETRIC_PURPOSE = "commerce.biometric_purpose_violation"
DENY_DELETION_UNVERIFIED = "commerce.deletion_unverified"
DENY_FIT_GUARANTEE = "commerce.fit_guarantee_claim"
DENY_NO_AUTH_CLAIM = "commerce.no_auth_claim"
DENY_UNGRADED_AUTH = "commerce.ungraded_auth_claim"
DENY_HUMAN_REVIEW_REQUIRED = "commerce.human_review_required"
DENY_PASSPORT_MISMATCH = "commerce.passport_mismatch"
DENY_HIDDEN_SUBSTITUTION = "commerce.hidden_model_substitution"
DENY_CHAIN_BROKEN = "commerce.chain_broken"

#: Closed likeness use classes (Pujols lesson: a grant covers only
#: the classes it declares; AI-generated *new* classes need a new
#: grant — "studio-portrait" does not cover "sexualized-ad").
LIKENESS_USE_CLASSES: tuple[str, ...] = (
    "studio-portrait",
    "catalog-apparel",
    "beauty-commercial",
    "generative-avatar",
    "virtual-tryon",
    "sexualized-ad",
    "political-ad",
)

#: Closed biometric kinds for try-on capture.
BIOMETRIC_KINDS: tuple[str, ...] = (
    "facial_geometry",
    "body_measurements",
)

#: Closed evidence tiers for authentication claims (Entrupy lesson:
#: vendor-declared confidence is a declaration, never a guarantee).
EVIDENCE_TIERS: tuple[str, ...] = (
    "vendor-declared",
    "third-party",
    "independent-lab",
)

#: Confidence ceilings per tier, in basis points (10000 == 100%).
#: A claim above its tier's ceiling is an ungraded claim.
TIER_CONFIDENCE_CEILING: Mapping[str, int] = {
    "vendor-declared": 9500,
    "third-party": 9900,
    "independent-lab": 9990,
}

#: Closed passport schemes (Aura / EU ESPR).
PASSPORT_SCHEMES: tuple[str, ...] = (
    "aura",
    "espr",
    "other",
)

#: Closed catalog-model types (hidden substitution gate).
MODEL_TYPES: tuple[str, ...] = (
    "human",
    "ai",
    "ai-assisted",
)

#: Closed preview uses.
PREVIEW_USES: tuple[str, ...] = (
    "view-only",
    "fit-decision",
)


class CommerceError(ValueError):
    """A malformed commerce receipt or a programming error.

    Raised for structural problems (bad digests, unknown classes,
    broken chains, non-summing or negative amounts). Verification
    *failures* (unread terms, likeness creep, unverified deletion)
    return a :class:`CommerceVerdict` with ``allowed=False``
    instead — a failed check is a verdict, a malformed receipt is
    a bug.
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
        raise CommerceError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise CommerceError(f"{field_name} must be a 128-char lowercase hex signature")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CommerceError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CommerceError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed (no keypair()).
    if not isinstance(value, bytes) or len(value) != 32:
        raise CommerceError(f"{field_name} must be a 32-byte seed")
    return value


def _check_closed(value: Any, vocab: tuple[str, ...], field_name: str) -> str:
    if value not in vocab:
        raise CommerceError(
            f"{field_name} must be one of {vocab}, saw {value!r}"
        )
    return value


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
    """Raise :class:`CommerceError` if a receipt log is tampered/broken.

    Every entry must expose ``receipt_digest`` and ``prev_digest``
    and a ``_payload()`` method; entries must form one chain from
    ``"genesis"`` with recomputing digests and valid authority
    signatures.
    """
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise CommerceError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise CommerceError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.authority_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise CommerceError(
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
class CommerceVerdict:
    """Outcome of one commerce check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> CommerceVerdict:
    return CommerceVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> CommerceVerdict:
    return CommerceVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def _allow_nonauthoritative(detail: str, receipt_digest: str = "") -> CommerceVerdict:
    """Allow, but mark the output non-authoritative.

    Used where the gate permits an *opinion* (a preview, an
    authentication verdict) that must never be treated as a
    guarantee.
    """
    return CommerceVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_NON_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


# ---------------------------------------------------------------------------
# Terms-read receipts (the 66% machine-readable lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TermsReadReceipt:
    """An agent's bound claim that it read machine-readable terms.

    Binds the *exact* product (``product_digest``) to the digests of
    the size chart, return policy, and total price including fees —
    so the read cannot be claimed for a different listing.
    """

    receipt_id: str
    order_id: str
    agent_id: str
    product_digest: str
    size_chart_digest: str
    return_policy_digest: str
    total_price_cents: int
    fees_cents: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = COMMERCE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "order_id": self.order_id,
            "agent_id": self.agent_id,
            "product_digest": self.product_digest,
            "size_chart_digest": self.size_chart_digest,
            "return_policy_digest": self.return_policy_digest,
            "total_price_cents": self.total_price_cents,
            "fees_cents": self.fees_cents,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def terms_read_receipt(
    *,
    receipt_id: str,
    order_id: str,
    agent_id: str,
    product_digest: str,
    size_chart_digest: str,
    return_policy_digest: str,
    total_price_cents: int,
    fees_cents: int,
    authority_secret: bytes,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> TermsReadReceipt:
    """Issue an authority-signed terms-read receipt.

    Fail-closed at issuance: a non-positive total, negative fees,
    or a missing terms digest raises — a "read" that skipped a
    document is not a read.
    """
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    order_id = _check_nonempty_str(order_id, "order_id")
    agent_id = _check_nonempty_str(agent_id, "agent_id")
    product_digest = _check_hex64(product_digest, "product_digest")
    size_chart_digest = _check_hex64(size_chart_digest, "size_chart_digest")
    return_policy_digest = _check_hex64(return_policy_digest, "return_policy_digest")
    if not isinstance(total_price_cents, int) or isinstance(total_price_cents, bool) \
            or total_price_cents <= 0:
        raise CommerceError("total_price_cents must be a positive int")
    if not isinstance(fees_cents, int) or isinstance(fees_cents, bool) or fees_cents < 0:
        raise CommerceError("fees_cents must be a non-negative int")
    if fees_cents > total_price_cents:
        raise CommerceError("fees_cents cannot exceed total_price_cents")
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise CommerceError("expires_at must be after issued_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise CommerceError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = TermsReadReceipt(
        receipt_id=receipt_id,
        order_id=order_id,
        agent_id=agent_id,
        product_digest=product_digest,
        size_chart_digest=size_chart_digest,
        return_policy_digest=return_policy_digest,
        total_price_cents=total_price_cents,
        fees_cents=fees_cents,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def check_order_terms(
    log: list[TermsReadReceipt],
    *,
    order_id: str,
    product_digest: str,
    check_time: int,
) -> CommerceVerdict:
    """Fail-closed gate: may this agent place this order?

    Checks, in order: log integrity; a receipt exists for this
    ``order_id``; it is live at ``check_time``; and it binds the
    exact ``product_digest`` being ordered. A terms read for product
    A cannot authorize an order for product B — the 66% lesson: the
    agent must have seen *these* terms.
    """
    order_id = _check_nonempty_str(order_id, "order_id")
    product_digest = _check_hex64(product_digest, "product_digest")
    check_time = _check_ts(check_time, "check_time")

    try:
        _check_chain(log, "terms-read")
    except CommerceError as error:
        return _deny(DENY_CHAIN_BROKEN, f"terms-read log integrity failure: {error}")

    receipt = next((r for r in reversed(log) if r.order_id == order_id), None)
    if receipt is None:
        return _deny(
            DENY_UNVERIFIABLE_TERMS,
            f"no terms-read receipt for order {order_id!r}: the agent has "
            "not evidenced a machine-readable read of the size chart, "
            "return policy, and total price",
        )
    if not (receipt.issued_at <= check_time < receipt.expires_at):
        return _deny(
            DENY_UNVERIFIABLE_TERMS,
            f"terms-read receipt {receipt.receipt_id!r} is not live at check time",
        )
    if not hmac.compare_digest(receipt.product_digest, product_digest):
        return _deny(
            DENY_UNVERIFIABLE_TERMS,
            f"receipt binds product {receipt.product_digest[:12]}..., order is "
            f"for {product_digest[:12]}...: the agent read someone else's terms",
        )
    return _allow(
        f"order {order_id!r}: machine-readable terms bound "
        f"(total {receipt.total_price_cents}c incl. {receipt.fees_cents}c fees)",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Likeness creep gate (Pujols v. Rainbow USA)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LikenessGrantReceipt:
    """A likeness grant bound to its declared use classes.

    The grant covers *only* the classes in ``granted_classes``.
    An AI-generated new likeness class (studio shot -> sexualized
    ad) is not covered by a grant that did not declare it.
    """

    receipt_id: str
    likeness_digest: str
    granted_classes: tuple[str, ...]
    grantor: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = COMMERCE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "likeness_digest": self.likeness_digest,
            "granted_classes": list(self.granted_classes),
            "grantor": self.grantor,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def likeness_grant_receipt(
    *,
    receipt_id: str,
    likeness_digest: str,
    granted_classes: tuple[str, ...],
    grantor: str,
    authority_secret: bytes,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> LikenessGrantReceipt:
    """Issue an authority-signed likeness grant.

    Fail-closed at issuance: an empty class list raises (a grant
    covering nothing covers nothing), and unknown classes raise.
    """
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    likeness_digest = _check_hex64(likeness_digest, "likeness_digest")
    if not isinstance(granted_classes, (tuple, list)) or not granted_classes:
        raise CommerceError("granted_classes must be a non-empty tuple/list")
    granted_classes = tuple(
        _check_closed(c, LIKENESS_USE_CLASSES, "likeness use class")
        for c in granted_classes
    )
    if len(set(granted_classes)) != len(granted_classes):
        raise CommerceError("granted_classes must be unique")
    grantor = _check_nonempty_str(grantor, "grantor")
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise CommerceError("expires_at must be after issued_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise CommerceError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = LikenessGrantReceipt(
        receipt_id=receipt_id,
        likeness_digest=likeness_digest,
        granted_classes=granted_classes,
        grantor=grantor,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def likeness_creep_gate(
    log: list[LikenessGrantReceipt],
    *,
    likeness_digest: str,
    use_class: str,
    check_time: int,
) -> CommerceVerdict:
    """Fail-closed gate: is this likeness use within its grant?

    Unknown ``use_class`` values raise (:class:`CommerceError`) —
    the vocabulary is closed. A use outside the grant's declared
    classes denies with ``commerce.likeness_creep`` (the Pujols
    lesson: "minor retouching" never covered a generated new
    likeness).
    """
    likeness_digest = _check_hex64(likeness_digest, "likeness_digest")
    use_class = _check_closed(use_class, LIKENESS_USE_CLASSES, "likeness use class")
    check_time = _check_ts(check_time, "check_time")

    try:
        _check_chain(log, "likeness-grant")
    except CommerceError as error:
        return _deny(DENY_CHAIN_BROKEN, f"likeness-grant log integrity failure: {error}")

    grant = next(
        (
            r
            for r in reversed(log)
            if hmac.compare_digest(r.likeness_digest, likeness_digest)
        ),
        None,
    )
    if grant is None:
        return _deny(
            DENY_NO_LIKENESS_GRANT,
            f"no likeness grant for {likeness_digest[:12]}...: likeness use "
            "without any grant is unauthorized use",
        )
    if not (grant.issued_at <= check_time < grant.expires_at):
        return _deny(
            DENY_NO_LIKENESS_GRANT,
            f"likeness grant {grant.receipt_id!r} is not live at check time",
        )
    if use_class not in grant.granted_classes:
        return _deny(
            DENY_LIKENESS_CREEP,
            f"use class {use_class!r} is not in the grant's declared classes "
            f"{list(grant.granted_classes)}: an AI-generated new likeness "
            "class needs a new grant (Pujols lesson)",
        )
    return _allow(
        f"likeness use {use_class!r} is within the grant's declared classes",
        receipt_digest=grant.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Biometric capture receipts (BIPA lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BiometricCaptureReceipt:
    """A biometric capture claim for virtual try-on.

    Binds the subject, the declared ``purpose``, the biometric
    ``kinds``, a retention window, and a pinned deletion mechanism.
    Deletion is verified separately (see
    :func:`check_biometric_deletion`): a promise to delete is not a
    deletion.
    """

    receipt_id: str
    subject_id: str
    purpose: str
    biometric_kinds: tuple[str, ...]
    retention_days: int
    deletion_mechanism_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = COMMERCE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "subject_id": self.subject_id,
            "purpose": self.purpose,
            "biometric_kinds": list(self.biometric_kinds),
            "retention_days": self.retention_days,
            "deletion_mechanism_digest": self.deletion_mechanism_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class BiometricDeletionReceipt:
    """A signed claim that captured biometrics were deleted.

    Binds the capture receipt it closes (``capture_receipt_digest``)
    — a deletion without a bound capture is an orphan, not evidence.
    """

    receipt_id: str
    capture_receipt_digest: str
    subject_id: str
    deletion_method_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    deleted_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = COMMERCE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "capture_receipt_digest": self.capture_receipt_digest,
            "subject_id": self.subject_id,
            "deletion_method_digest": self.deletion_method_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "deleted_at": self.deleted_at,
            "schema_version": self.schema_version,
        }


def biometric_capture_receipt(
    *,
    receipt_id: str,
    subject_id: str,
    purpose: str,
    biometric_kinds: tuple[str, ...],
    retention_days: int,
    deletion_mechanism_digest: str,
    authority_secret: bytes,
    issued_by: str,
    issued_at: int,
    prev_digest: str = _GENESIS,
) -> BiometricCaptureReceipt:
    """Issue an authority-signed biometric capture receipt.

    Fail-closed at issuance: empty kind lists, unknown kinds, and
    non-positive retention windows raise.
    """
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    subject_id = _check_nonempty_str(subject_id, "subject_id")
    purpose = _check_nonempty_str(purpose, "purpose")
    if not isinstance(biometric_kinds, (tuple, list)) or not biometric_kinds:
        raise CommerceError("biometric_kinds must be a non-empty tuple/list")
    biometric_kinds = tuple(
        _check_closed(k, BIOMETRIC_KINDS, "biometric kind") for k in biometric_kinds
    )
    if len(set(biometric_kinds)) != len(biometric_kinds):
        raise CommerceError("biometric_kinds must be unique")
    if not isinstance(retention_days, int) or isinstance(retention_days, bool) \
            or retention_days <= 0:
        raise CommerceError("retention_days must be a positive int")
    deletion_mechanism_digest = _check_hex64(
        deletion_mechanism_digest, "deletion_mechanism_digest"
    )
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise CommerceError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = BiometricCaptureReceipt(
        receipt_id=receipt_id,
        subject_id=subject_id,
        purpose=purpose,
        biometric_kinds=biometric_kinds,
        retention_days=retention_days,
        deletion_mechanism_digest=deletion_mechanism_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        issued_at=issued_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def biometric_deletion_receipt(
    *,
    receipt_id: str,
    capture: BiometricCaptureReceipt,
    deletion_method_digest: str,
    authority_secret: bytes,
    issued_by: str,
    deleted_at: int,
    prev_digest: str = _GENESIS,
) -> BiometricDeletionReceipt:
    """Issue an authority-signed deletion receipt closing a capture."""
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    if not isinstance(capture, BiometricCaptureReceipt):
        raise CommerceError("capture must be a BiometricCaptureReceipt")
    deletion_method_digest = _check_hex64(
        deletion_method_digest, "deletion_method_digest"
    )
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    deleted_at = _check_ts(deleted_at, "deleted_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise CommerceError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = BiometricDeletionReceipt(
        receipt_id=receipt_id,
        capture_receipt_digest=capture.receipt_digest,
        subject_id=capture.subject_id,
        deletion_method_digest=deletion_method_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        deleted_at=deleted_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def check_biometric_collection(
    log: list[BiometricCaptureReceipt],
    *,
    subject_id: str,
    purpose: str,
    biometric_kinds: tuple[str, ...],
    check_time: int,
) -> CommerceVerdict:
    """Fail-closed gate: may biometrics be captured for this purpose?

    The receipt must be live at ``check_time``, name this subject,
    declare this exact purpose, and cover every requested
    ``biometric_kinds`` entry. A capture for a different purpose —
    or without any receipt — denies (the BIPA lesson).
    """
    subject_id = _check_nonempty_str(subject_id, "subject_id")
    purpose = _check_nonempty_str(purpose, "purpose")
    if not isinstance(biometric_kinds, (tuple, list)) or not biometric_kinds:
        raise CommerceError("biometric_kinds must be a non-empty tuple/list")
    biometric_kinds = tuple(
        _check_closed(k, BIOMETRIC_KINDS, "biometric kind") for k in biometric_kinds
    )
    check_time = _check_ts(check_time, "check_time")

    try:
        _check_chain(log, "biometric-capture")
    except CommerceError as error:
        return _deny(
            DENY_CHAIN_BROKEN, f"biometric-capture log integrity failure: {error}"
        )

    receipt = next(
        (r for r in reversed(log) if r.subject_id == subject_id), None
    )
    if receipt is None or check_time < receipt.issued_at:
        return _deny(
            DENY_NO_BIOMETRIC_RECEIPT,
            f"no live biometric-capture receipt for subject {subject_id!r}: "
            "biometric capture without a bound receipt is denied",
        )
    if receipt.purpose != purpose:
        return _deny(
            DENY_BIOMETRIC_PURPOSE,
            f"receipt declares purpose {receipt.purpose!r}, capture is for "
            f"{purpose!r}: purpose creep on biometric data is denied",
        )
    missing = [k for k in biometric_kinds if k not in receipt.biometric_kinds]
    if missing:
        return _deny(
            DENY_BIOMETRIC_PURPOSE,
            f"receipt does not cover biometric kind(s) {missing}: "
            "uncaptured-by-receipt kinds are denied",
        )
    return _allow(
        f"biometric capture for {subject_id!r} covered by receipt "
        f"{receipt.receipt_id!r} (purpose {purpose!r})",
        receipt_digest=receipt.receipt_digest,
    )


def check_biometric_deletion(
    capture_log: list[BiometricCaptureReceipt],
    deletion_log: list[BiometricDeletionReceipt],
    *,
    subject_id: str,
    check_time: int,
) -> CommerceVerdict:
    """Fail-closed gate: has retained biometric data been deleted?

    If the capture's retention window has expired, a signed
    deletion receipt bound to the capture must exist. An expired
    capture with no signed deletion denies with
    ``commerce.deletion_unverified`` — a promise to delete is not a
    deletion.
    """
    subject_id = _check_nonempty_str(subject_id, "subject_id")
    check_time = _check_ts(check_time, "check_time")

    try:
        _check_chain(capture_log, "biometric-capture")
    except CommerceError as error:
        return _deny(
            DENY_CHAIN_BROKEN, f"biometric-capture log integrity failure: {error}"
        )
    try:
        _check_chain(deletion_log, "biometric-deletion")
    except CommerceError as error:
        return _deny(
            DENY_CHAIN_BROKEN, f"biometric-deletion log integrity failure: {error}"
        )

    capture = next(
        (r for r in reversed(capture_log) if r.subject_id == subject_id), None
    )
    if capture is None:
        return _deny(
            DENY_NO_BIOMETRIC_RECEIPT,
            f"no biometric-capture receipt for subject {subject_id!r}: "
            "nothing to delete",
        )
    retention_end = capture.issued_at + capture.retention_days * _SECONDS_PER_DAY
    if check_time <= retention_end:
        return _allow(
            f"biometric data for {subject_id!r} still within its declared "
            "retention window",
            receipt_digest=capture.receipt_digest,
        )
    deletion = next(
        (
            d
            for d in reversed(deletion_log)
            if hmac.compare_digest(d.capture_receipt_digest, capture.receipt_digest)
        ),
        None,
    )
    if deletion is None:
        return _deny(
            DENY_DELETION_UNVERIFIED,
            f"retention for {subject_id!r} expired at epoch {retention_end} "
            "with no signed deletion receipt bound to the capture: "
            "deletion is unverified",
        )
    return _allow(
        f"biometric data for {subject_id!r} deleted under receipt "
        f"{deletion.receipt_id!r}",
        receipt_digest=deletion.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Try-on previews: non-authoritative by construction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PreviewReceipt:
    """A try-on preview receipt.

    The classification is baked into the payload as
    ``non_authoritative`` — a preview can never be upgraded to
    authoritative, because "preview only, fit not guaranteed" is the
    product contract (ChatGPT's try-on button, Oct 2026).
    """

    receipt_id: str
    preview_id: str
    content_digest: str
    classification: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = COMMERCE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "preview_id": self.preview_id,
            "content_digest": self.content_digest,
            "classification": self.classification,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "schema_version": self.schema_version,
        }


def issue_preview_receipt(
    *,
    receipt_id: str,
    preview_id: str,
    content_digest: str,
    authority_secret: bytes,
    issued_by: str,
    issued_at: int,
    prev_digest: str = _GENESIS,
) -> PreviewReceipt:
    """Issue a try-on preview receipt (always non-authoritative)."""
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    preview_id = _check_nonempty_str(preview_id, "preview_id")
    content_digest = _check_hex64(content_digest, "content_digest")
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise CommerceError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = PreviewReceipt(
        receipt_id=receipt_id,
        preview_id=preview_id,
        content_digest=content_digest,
        classification=CLASS_NON_AUTHORITATIVE,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        issued_at=issued_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def check_preview_use(
    preview: PreviewReceipt,
    *,
    use: str,
) -> CommerceVerdict:
    """Gate downstream use of a try-on preview.

    ``view-only`` allows (still classified non-authoritative).
    ``fit-decision`` denies with ``commerce.fit_guarantee_claim`` —
    a preview must never serve as a fit guarantee downstream.
    """
    if not isinstance(preview, PreviewReceipt):
        raise CommerceError("preview must be a PreviewReceipt")
    use = _check_closed(use, PREVIEW_USES, "preview use")
    if use == "fit-decision":
        return _deny(
            DENY_FIT_GUARANTEE,
            f"preview {preview.preview_id!r} used as a fit decision: "
            "try-on previews are non-authoritative by construction "
            "(\"preview only, fit not guaranteed\")",
        )
    return _allow_nonauthoritative(
        f"preview {preview.preview_id!r} viewed as a non-authoritative preview",
        receipt_digest=preview.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Authentication evidence (Entrupy lesson: a claim is not a guarantee)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthenticationClaim:
    """A graded counterfeit/authentication verdict.

    ``claimed_confidence_bps`` is a *declaration* (basis points);
    the gate caps it at the evidence tier's ceiling and requires a
    human-review path for ``high`` value items. A verdict is never
    authoritative — it is graded evidence, not a guarantee.
    """

    claim_id: str
    item_digest: str
    verdict: str
    claimed_confidence_bps: int
    evidence_digest: str
    evidence_tier: str
    value_class: str
    human_review: bool
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = COMMERCE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "item_digest": self.item_digest,
            "verdict": self.verdict,
            "claimed_confidence_bps": self.claimed_confidence_bps,
            "evidence_digest": self.evidence_digest,
            "evidence_tier": self.evidence_tier,
            "value_class": self.value_class,
            "human_review": self.human_review,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


_AUTH_VERDICTS: tuple[str, ...] = ("authentic", "counterfeit", "inconclusive")
_VALUE_CLASSES: tuple[str, ...] = ("standard", "high")


def issue_authentication_claim(
    *,
    claim_id: str,
    item_digest: str,
    verdict: str,
    claimed_confidence_bps: int,
    evidence_digest: str,
    evidence_tier: str,
    value_class: str,
    human_review: bool,
    authority_secret: bytes,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> AuthenticationClaim:
    """Issue a graded authentication claim.

    Fail-closed at issuance: unknown verdicts/tiers, and
    confidence outside 0..10000, raise.
    """
    _check_secret(authority_secret, "authority_secret")
    claim_id = _check_nonempty_str(claim_id, "claim_id")
    item_digest = _check_hex64(item_digest, "item_digest")
    verdict = _check_closed(verdict, _AUTH_VERDICTS, "auth verdict")
    if not isinstance(claimed_confidence_bps, int) or isinstance(
        claimed_confidence_bps, bool
    ) or not 0 <= claimed_confidence_bps <= 10000:
        raise CommerceError("claimed_confidence_bps must be an int in 0..10000")
    evidence_digest = _check_hex64(evidence_digest, "evidence_digest")
    evidence_tier = _check_closed(evidence_tier, EVIDENCE_TIERS, "evidence tier")
    value_class = _check_closed(value_class, _VALUE_CLASSES, "value class")
    if not isinstance(human_review, bool):
        raise CommerceError("human_review must be a bool")
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise CommerceError("expires_at must be after issued_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise CommerceError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = AuthenticationClaim(
        claim_id=claim_id,
        item_digest=item_digest,
        verdict=verdict,
        claimed_confidence_bps=claimed_confidence_bps,
        evidence_digest=evidence_digest,
        evidence_tier=evidence_tier,
        value_class=value_class,
        human_review=human_review,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def authentication_evidence(
    log: list[AuthenticationClaim],
    *,
    item_digest: str,
    check_time: int,
) -> CommerceVerdict:
    """Fail-closed gate over authentication verdicts.

    A verdict with no live claim denies. A vendor-declared claim
    above its tier's confidence ceiling denies with
    ``commerce.ungraded_auth_claim`` (Entrupy's "99.1%" is a
    declaration, not evidence). A ``high`` value item without a
    human-review path denies with
    ``commerce.human_review_required``. Allowed verdicts are
    *non-authoritative* — graded evidence, never a guarantee.
    """
    item_digest = _check_hex64(item_digest, "item_digest")
    check_time = _check_ts(check_time, "check_time")

    try:
        _check_chain(log, "authentication-claim")
    except CommerceError as error:
        return _deny(
            DENY_CHAIN_BROKEN, f"authentication-claim log integrity failure: {error}"
        )

    claim = next(
        (c for c in reversed(log) if hmac.compare_digest(c.item_digest, item_digest)),
        None,
    )
    if claim is None:
        return _deny(
            DENY_NO_AUTH_CLAIM,
            f"no authentication claim for item {item_digest[:12]}...: "
            "an authentication verdict without a claim is denied",
        )
    if not (claim.issued_at <= check_time < claim.expires_at):
        return _deny(
            DENY_NO_AUTH_CLAIM,
            f"authentication claim {claim.claim_id!r} is not live at check time",
        )
    ceiling = TIER_CONFIDENCE_CEILING[claim.evidence_tier]
    if claim.claimed_confidence_bps > ceiling:
        return _deny(
            DENY_UNGRADED_AUTH,
            f"claimed confidence {claim.claimed_confidence_bps} bps exceeds the "
            f"{claim.evidence_tier!r} tier ceiling ({ceiling} bps): "
            "vendor-declared high confidence is a declaration, not evidence",
        )
    if claim.value_class == "high" and not claim.human_review:
        return _deny(
            DENY_HUMAN_REVIEW_REQUIRED,
            f"high-value item {item_digest[:12]}... has no human-review path: "
            "mandatory human review is required",
        )
    return _allow_nonauthoritative(
        f"{claim.verdict} (confidence {claim.claimed_confidence_bps} bps, "
        f"tier {claim.evidence_tier!r}): graded evidence, not a guarantee",
        receipt_digest=claim.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Digital passport binding (Aura / EU ESPR)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PassportBindingReceipt:
    """A listing's bound digital product passport.

    Binds the listing digest to the passport digest and scheme. A
    listing that *claims* a passport without this binding is
    unverified.
    """

    receipt_id: str
    listing_digest: str
    passport_digest: str
    passport_scheme: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = COMMERCE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "listing_digest": self.listing_digest,
            "passport_digest": self.passport_digest,
            "passport_scheme": self.passport_scheme,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def passport_binding_receipt(
    *,
    receipt_id: str,
    listing_digest: str,
    passport_digest: str,
    passport_scheme: str,
    authority_secret: bytes,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> PassportBindingReceipt:
    """Issue an authority-signed passport binding."""
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    listing_digest = _check_hex64(listing_digest, "listing_digest")
    passport_digest = _check_hex64(passport_digest, "passport_digest")
    passport_scheme = _check_closed(passport_scheme, PASSPORT_SCHEMES, "passport scheme")
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise CommerceError("expires_at must be after issued_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise CommerceError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = PassportBindingReceipt(
        receipt_id=receipt_id,
        listing_digest=listing_digest,
        passport_digest=passport_digest,
        passport_scheme=passport_scheme,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def check_passport_binding(
    log: list[PassportBindingReceipt],
    *,
    listing_digest: str,
    passport_digest: str,
    check_time: int,
) -> CommerceVerdict:
    """Fail-closed gate: does this listing's passport recompute?

    No live binding for the listing, or a bound passport digest
    that does not match the presented one, denies with
    ``commerce.passport_mismatch``.
    """
    listing_digest = _check_hex64(listing_digest, "listing_digest")
    passport_digest = _check_hex64(passport_digest, "passport_digest")
    check_time = _check_ts(check_time, "check_time")

    try:
        _check_chain(log, "passport-binding")
    except CommerceError as error:
        return _deny(
            DENY_CHAIN_BROKEN, f"passport-binding log integrity failure: {error}"
        )

    binding = next(
        (
            b
            for b in reversed(log)
            if hmac.compare_digest(b.listing_digest, listing_digest)
        ),
        None,
    )
    if binding is None:
        return _deny(
            DENY_PASSPORT_MISMATCH,
            f"listing {listing_digest[:12]}... claims a digital passport with "
            "no bound passport receipt: unbound passport claims are denied",
        )
    if not (binding.issued_at <= check_time < binding.expires_at):
        return _deny(
            DENY_PASSPORT_MISMATCH,
            f"passport binding {binding.receipt_id!r} is not live at check time",
        )
    if not hmac.compare_digest(binding.passport_digest, passport_digest):
        return _deny(
            DENY_PASSPORT_MISMATCH,
            f"presented passport {passport_digest[:12]}... does not match the "
            f"bound passport {binding.passport_digest[:12]}...",
        )
    return _allow(
        f"listing passport bound ({binding.passport_scheme} scheme), digest matches",
        receipt_digest=binding.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Model substitution disclosure
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelSubstitutionDisclosure:
    """A catalog item's declared model type.

    When AI models replace human catalog models, the substitution
    must be declared. Undisclosed substitution is the mirror of the
    122nd batch's "no AI" attestation gate.
    """

    receipt_id: str
    catalog_item_digest: str
    model_type: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = COMMERCE_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "catalog_item_digest": self.catalog_item_digest,
            "model_type": self.model_type,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "schema_version": self.schema_version,
        }


def model_substitution_disclosure(
    *,
    receipt_id: str,
    catalog_item_digest: str,
    model_type: str,
    authority_secret: bytes,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> ModelSubstitutionDisclosure:
    """Issue an authority-signed model-type disclosure."""
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    catalog_item_digest = _check_hex64(catalog_item_digest, "catalog_item_digest")
    model_type = _check_closed(model_type, MODEL_TYPES, "model type")
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    issued_at = _check_ts(issued_at, "issued_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise CommerceError("expires_at must be after issued_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise CommerceError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = ModelSubstitutionDisclosure(
        receipt_id=receipt_id,
        catalog_item_digest=catalog_item_digest,
        model_type=model_type,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced by _seal
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    return _seal(bare, bare._payload(), authority_secret)


def check_model_substitution(
    log: list[ModelSubstitutionDisclosure],
    *,
    catalog_item_digest: str,
    actual_model_type: str,
    check_time: int,
) -> CommerceVerdict:
    """Fail-closed gate: is the catalog model honestly disclosed?

    Non-human models (``ai`` / ``ai-assisted``) without a live
    disclosure deny with ``commerce.hidden_model_substitution``.
    A disclosure that lies about the actual type denies as well.
    """
    catalog_item_digest = _check_hex64(catalog_item_digest, "catalog_item_digest")
    actual_model_type = _check_closed(actual_model_type, MODEL_TYPES, "model type")
    check_time = _check_ts(check_time, "check_time")

    try:
        _check_chain(log, "model-substitution")
    except CommerceError as error:
        return _deny(
            DENY_CHAIN_BROKEN, f"model-substitution log integrity failure: {error}"
        )

    disclosure = next(
        (
            d
            for d in reversed(log)
            if hmac.compare_digest(d.catalog_item_digest, catalog_item_digest)
        ),
        None,
    )
    if actual_model_type == "human":
        return _allow("human catalog model: no substitution to disclose")
    if disclosure is None:
        return _deny(
            DENY_HIDDEN_SUBSTITUTION,
            f"catalog item {catalog_item_digest[:12]}... uses {actual_model_type!r} "
            "models with no substitution disclosure: undisclosed AI "
            "substitution is denied",
        )
    if not (disclosure.issued_at <= check_time < disclosure.expires_at):
        return _deny(
            DENY_HIDDEN_SUBSTITUTION,
            f"model-substitution disclosure {disclosure.receipt_id!r} is not "
            "live at check time",
        )
    if disclosure.model_type != actual_model_type:
        return _deny(
            DENY_HIDDEN_SUBSTITUTION,
            f"disclosure declares {disclosure.model_type!r} but the item uses "
            f"{actual_model_type!r}: the disclosure is false",
        )
    return _allow(
        f"AI model substitution disclosed ({actual_model_type!r})",
        receipt_digest=disclosure.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def commerce_audit_event(
    code: str, detail: str, receipt_digest: str = ""
) -> dict[str, Any]:
    """Build a ``commerce:*`` audit event payload."""
    return {
        "event": f"commerce.{code}",
        "detail": detail,
        "receipt_digest": receipt_digest,
        "schema_version": COMMERCE_SCHEMA_VERSION,
    }
