"""Revocable consent receipts (one-hundred-fifth batch).

Absorbs the 2026 brain-computer-interface thread, which turned neural
data into the hardest consent problem in the stack:

* **Neuralink** (~26 implants, US/UK/Canada/UAE; Sept 2026 VOICE
  patient Terry's first synthesized word): invasive BCI is in humans,
  but every number is company-reported and there is no FDA market
  approval.
* **Paradromics** (June 2026 first long-term implant, 421 electrodes;
  Sept 2026 thought expression on commercial hardware; FDA expanded
  to home use on the patient's own device): decode leaves the lab.
* **China NMPA** (March 2026): the world's first invasive-BCI medical
  device market approval; 134 registered clinical studies.
* **California AB 2741** (Sept 23, 2026): "mind-reading AI" is now
  regulated disclosure territory. **Chile**: constitutional neural
  rights plus a supreme-court data-deletion precedent. **EU AI Act**:
  high-risk obligations live since 2026-08-02.

The governance takeaway is twofold and both are fail-closed here:

1. **Consent is unilateral and revocable at any time; validity is
   checked at USE time, never at collection time.** There is no
   "was once consented" shortcut in the API — every data use must
   call :func:`check_consent_at_use`, which re-verifies the chain,
   the subject's signature, scope/purpose match, expiry, *and* the
   absence of a revocation as of ``use_time``. A revoked or expired
   grant denies, and the denial audits as ``consent.use_denied``.
   Revocation is immediate and irreversible in the log: a new grant
   needs a new receipt (there is no "un-revoke").
2. **Decode-error attribution.** A wrongly decoded intent must never
   be treated as the user's intent. :func:`decode_attribution` binds
   every decode to ``(raw_signal_digest, decoder_id, decoder_version,
   confidence)``; below-threshold or ambiguous decodes classify
   ``NON_AUTHORITATIVE`` (87th-batch binary semantics) and must never
   drive irreversible actions. A wrong decode is attributable to the
   decoder, never to the user.

Closed-loop stimulation (write-to-brain) is irreversible-tier: it
requires *fresh* consent (the grant must be recent — a stale grant
from years ago does not authorize today's stimulation) **plus** a
human countersign, mirroring the 99th batch's kill-switch semantics
for SOC remediation: the card/decoding is evidence, never the final
word, and autonomous execution with neither safeguard denies.

Honest boundary: this module verifies *claimed* consent-chain
consistency — digests recompute, signatures verify against the
subject's registered key, revocations are visible, scopes match.
It cannot prove the human *understood* what they signed, nor that
the key holder was the human and not their device. Consent UX and
key custody are outside this module's scope.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th batch pattern), digest comparisons
via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


CONSENT_RECEIPT_SCHEMA_VERSION = "northstar.consent-receipt.v1"

#: Closed data-scope vocabulary. Scope is matched exactly at use time —
#: a grant for ``neural_raw`` does not cover ``neural_decoded``.
DATA_SCOPES: tuple[str, ...] = (
    "neural_raw",
    "neural_decoded",
    "neural_stimulation",
    "behavioral",
    "health",
)

#: Classification tiers for a use-time check (binary, 87th-batch style).
CONSENTED_USE = "consented-use"
UNCONSENTED_USE = "unconsented-use"

#: Classification tiers for a decode (binary, 87th-batch style).
AUTHORITATIVE_DECODE = "authoritative-decode"
NON_AUTHORITATIVE_DECODE = "non-authoritative-decode"

#: Minimum decoder confidence for an authoritative decode. Below this
#: the decode is advisory only and must never drive irreversible action.
DECODE_CONFIDENCE_MIN = 0.90

#: Freshness window (seconds) for stimulation consent: the grant must be
#: this recent at stimulation time. A stale grant does not authorize
#: today's write-to-brain.
STIMULATION_FRESHNESS_WINDOW_S = 86_400

CONSENT_USE_DENIED_EVENT = "consent.use_denied"
CONSENT_USE_ALLOWED_EVENT = "consent.use_allowed"
CONSENT_REVOKED_EVENT = "consent.revoked"
STIMULATION_DENIED_EVENT = "stimulation.denied"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class ConsentReceiptError(ValueError):
    """A malformed receipt/record or a programming error.

    Raised for structural problems (bad digests, bad signatures input,
    unknown scope, non-hex fields). Verification *failures* (revoked,
    expired, out-of-scope, bad signature at use time) return a
    :class:`ConsentVerdict` with ``allowed=False`` — a failed consent
    check is a verdict, a malformed log is a bug.
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
        raise ConsentReceiptError(
            f"{field_name} must be a 64-char lowercase hex digest"
        )
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise ConsentReceiptError(
            f"{field_name} must be a 128-char hex value"
        )
    return value


def _check_scope(value: Any) -> str:
    if value not in DATA_SCOPES:
        raise ConsentReceiptError(
            f"data_scope must be one of {DATA_SCOPES}, saw {value!r}"
        )
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ConsentReceiptError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ConsentReceiptError(f"{field_name} must be 32 bytes")
    return value


def _check_pubkey_hex(value: Any) -> str:
    # Ed25519 public keys are 32 bytes -> 64 hex chars.
    return _check_hex64(value, "subject_pubkey_hex")


def _check_sig_hex(value: Any, field_name: str) -> str:
    return _check_hex128(value, field_name)


# ---------------------------------------------------------------------------
# Consent receipts (grants) and revocations — one hash-chained log
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConsentReceipt:
    """A subject's signed grant of consent.

    Binds ``(subject_id, data_scope, purpose, granted_at, expires_at)``
    to the subject's Ed25519 key. ``purpose`` is a free string but is
    matched *exactly* at use time — a grant for "clinical-research"
    does not cover "product-personalization". The signature covers
    the canonical payload; the receipt is sealed with ``receipt_digest``
    and chained via ``prev_digest``.
    """

    subject_id: str
    data_scope: str
    purpose: str
    granted_at: int
    expires_at: int
    subject_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.subject_id, str) or not self.subject_id:
            raise ConsentReceiptError("subject_id must be a non-empty string")
        _check_scope(self.data_scope)
        if not isinstance(self.purpose, str) or not self.purpose:
            raise ConsentReceiptError("purpose must be a non-empty string")
        _check_ts(self.granted_at, "granted_at")
        _check_ts(self.expires_at, "expires_at")
        if self.expires_at <= self.granted_at:
            raise ConsentReceiptError("expires_at must be after granted_at")
        _check_pubkey_hex(self.subject_pubkey_hex)
        _check_sig_hex(self.signature_hex, "signature_hex")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.receipt_digest != "":
            _check_hex64(self.receipt_digest, "receipt_digest")


@dataclass(frozen=True)
class RevocationRecord:
    """A subject's unilateral revocation of one grant.

    Signed by the *same* subject key as the grant it revokes.
    Revocation is immediate and irreversible in the log: there is no
    "un-revoke" — a new grant needs a new receipt.
    """

    receipt_digest: str
    revoked_at: int
    subject_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    record_digest: str = ""

    def __post_init__(self) -> None:
        _check_hex64(self.receipt_digest, "receipt_digest")
        _check_ts(self.revoked_at, "revoked_at")
        _check_pubkey_hex(self.subject_pubkey_hex)
        _check_sig_hex(self.signature_hex, "signature_hex")
        if self.prev_digest != _GENESIS:
            _check_hex64(self.prev_digest, "prev_digest")
        if self.record_digest != "":
            _check_hex64(self.record_digest, "record_digest")


def _grant_payload(receipt: ConsentReceipt) -> dict[str, Any]:
    return {
        "schema": CONSENT_RECEIPT_SCHEMA_VERSION,
        "kind": "grant",
        "subject_id": receipt.subject_id,
        "data_scope": receipt.data_scope,
        "purpose": receipt.purpose,
        "granted_at": receipt.granted_at,
        "expires_at": receipt.expires_at,
        "subject_pubkey_hex": receipt.subject_pubkey_hex,
        "prev_digest": receipt.prev_digest,
    }


def compute_receipt_digest(receipt: ConsentReceipt) -> str:
    """Recompute a grant's digest over all fields except itself."""
    return jcs_sha256_hex(_grant_payload(receipt))


def _revocation_payload(record: RevocationRecord) -> dict[str, Any]:
    return {
        "schema": CONSENT_RECEIPT_SCHEMA_VERSION,
        "kind": "revocation",
        "receipt_digest": record.receipt_digest,
        "revoked_at": record.revoked_at,
        "subject_pubkey_hex": record.subject_pubkey_hex,
        "prev_digest": record.prev_digest,
    }


def compute_revocation_digest(record: RevocationRecord) -> str:
    """Recompute a revocation's digest over all fields except itself."""
    return jcs_sha256_hex(_revocation_payload(record))


def grant_consent(
    *,
    subject_id: str,
    subject_secret: bytes,
    data_scope: str,
    purpose: str,
    granted_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> ConsentReceipt:
    """Issue a subject-signed consent grant and seal it.

    The signature is over the canonical grant payload; the digest is
    over the same payload (signature excluded from the digest input,
    like the 97th batch's envelope pinning).
    """
    _check_secret(subject_secret, "subject_secret")
    pubkey_hex = ed25519.public_key(subject_secret).hex()
    bare = ConsentReceipt(
        subject_id=subject_id,
        data_scope=_check_scope(data_scope),
        purpose=purpose,
        granted_at=_check_ts(granted_at, "granted_at"),
        expires_at=_check_ts(expires_at, "expires_at"),
        subject_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,  # placeholder; replaced below
        prev_digest=prev_digest,
    )
    payload = _grant_payload(bare)
    signature_hex = ed25519.sign(subject_secret, jcs_canonical_json(payload)).hex()
    sealed = ConsentReceipt(
        subject_id=bare.subject_id,
        data_scope=bare.data_scope,
        purpose=bare.purpose,
        granted_at=bare.granted_at,
        expires_at=bare.expires_at,
        subject_pubkey_hex=bare.subject_pubkey_hex,
        signature_hex=signature_hex,
        prev_digest=bare.prev_digest,
        receipt_digest=jcs_sha256_hex(payload),
    )
    return sealed


def revoke_consent(
    *,
    receipt: ConsentReceipt,
    subject_secret: bytes,
    revoked_at: int,
    prev_digest: str = _GENESIS,
) -> RevocationRecord:
    """Append a subject-signed revocation for one grant.

    The revocation must be signed by the same subject key that signed
    the grant (a stranger cannot revoke your consent, and you cannot
    revoke someone else's). Effective immediately at ``revoked_at``;
    irreversible in the log.
    """
    _check_secret(subject_secret, "subject_secret")
    _check_ts(revoked_at, "revoked_at")
    if ed25519.public_key(subject_secret).hex() != receipt.subject_pubkey_hex:
        raise ConsentReceiptError(
            "revocation must be signed by the grant's subject key"
        )
    bare = RevocationRecord(
        receipt_digest=receipt.receipt_digest,
        revoked_at=revoked_at,
        subject_pubkey_hex=receipt.subject_pubkey_hex,
        signature_hex="00" * 64,  # placeholder; replaced below
        prev_digest=prev_digest,
    )
    payload = _revocation_payload(bare)
    signature_hex = ed25519.sign(subject_secret, jcs_canonical_json(payload)).hex()
    return RevocationRecord(
        receipt_digest=bare.receipt_digest,
        revoked_at=bare.revoked_at,
        subject_pubkey_hex=bare.subject_pubkey_hex,
        signature_hex=signature_hex,
        prev_digest=bare.prev_digest,
        record_digest=jcs_sha256_hex(payload),
    )


# ---------------------------------------------------------------------------
# Use-time consent check
# ---------------------------------------------------------------------------


@dataclass
class ConsentVerdict:
    """Outcome of checking one data use against the consent log."""

    allowed: bool
    reason: str
    classification: str = UNCONSENTED_USE
    receipt_digest: str = ""


def _verify_log_chain(log: list[ConsentReceipt | RevocationRecord]) -> None:
    """Verify digests and the single interleaved hash chain.

    Grants and revocations share one append-only log in caller order;
    each entry's ``prev_digest`` must link to the previous entry's
    digest (or ``"genesis"`` for the first). Raises
    :class:`ConsentReceiptError` on any break — a broken log is a bug,
    not a verdict.
    """
    expected = _GENESIS
    for entry in log:
        if isinstance(entry, ConsentReceipt):
            digest = compute_receipt_digest(entry)
            sealed = entry.receipt_digest
            label = f"grant {entry.subject_id!r}"
        elif isinstance(entry, RevocationRecord):
            digest = compute_revocation_digest(entry)
            sealed = entry.record_digest
            label = f"revocation of {entry.receipt_digest[:12]}..."
        else:
            raise ConsentReceiptError(
                f"log entries must be ConsentReceipt or RevocationRecord, "
                f"saw {type(entry).__name__}"
            )
        if not hmac.compare_digest(digest, sealed):
            raise ConsentReceiptError(f"log tampered: digest mismatch on {label}")
        if not hmac.compare_digest(entry.prev_digest, expected):
            raise ConsentReceiptError(
                f"log chain broken at {label}: expected prev "
                f"{expected[:12]}..., saw {entry.prev_digest[:12]}..."
            )
        expected = sealed


def check_consent_at_use(
    *,
    receipt: ConsentReceipt,
    log: list[ConsentReceipt | RevocationRecord],
    data_scope: str,
    purpose: str,
    use_time: int,
) -> ConsentVerdict:
    """Check ONE data use against the consent log. Fail-closed.

    There is deliberately no "was once consented" shortcut: collection-
    time checks do not exist in this API. Every use re-verifies, in
    order:

    1. Log integrity — digests recompute, single hash chain intact.
    2. The grant resolves in ``log`` (by digest) and is the sealed
       receipt (not a lookalike).
    3. Subject signature verifies against the registered subject key.
    4. Scope and purpose match *exactly*.
    5. ``granted_at <= use_time <= expires_at``.
    6. No revocation for this grant with ``revoked_at <= use_time``.

    Any failure denies with ``classification=UNCONSENTED_USE`` and an
    audit event shaped for the audit chain (``consent.use_denied``).
    """
    _check_ts(use_time, "use_time")

    def _deny(reason: str) -> ConsentVerdict:
        return ConsentVerdict(
            allowed=False,
            reason=reason,
            classification=UNCONSENTED_USE,
            receipt_digest=receipt.receipt_digest,
        )

    # 1. Log integrity first: a tampered log denies everything.
    try:
        _verify_log_chain(log)
    except ConsentReceiptError as error:
        return _deny(f"consent log integrity failure: {error}")

    # 2. The grant must resolve in the log.
    grants = [e for e in log if isinstance(e, ConsentReceipt)]
    revocations = [e for e in log if isinstance(e, RevocationRecord)]
    known = next(
        (g for g in grants if hmac.compare_digest(g.receipt_digest, receipt.receipt_digest)),
        None,
    )
    if known is None:
        return _deny("grant not present in the consent log: unknown receipt")
    if not hmac.compare_digest(compute_receipt_digest(receipt), receipt.receipt_digest):
        return _deny("grant digest does not recompute: tampered receipt")

    # 3. Subject signature over the canonical payload.
    try:
        sig_ok = ed25519.verify(
            bytes.fromhex(known.subject_pubkey_hex),
            jcs_canonical_json(_grant_payload(known)),
            bytes.fromhex(known.signature_hex),
        )
    except Exception:
        sig_ok = False
    if not sig_ok:
        return _deny("subject signature invalid: grant not from the subject")

    # 4. Exact scope/purpose match — no wildcards, no subsumption.
    if data_scope != known.data_scope:
        return _deny(
            f"scope mismatch: grant covers {known.data_scope!r}, "
            f"use requests {data_scope!r}"
        )
    if purpose != known.purpose:
        return _deny(
            f"purpose mismatch: grant allows {known.purpose!r}, "
            f"use requests {purpose!r}"
        )

    # 5. Time window.
    if use_time < known.granted_at:
        return _deny("use_time predates the grant: consent did not exist yet")
    if use_time > known.expires_at:
        return _deny("grant expired: use_time is past expires_at")

    # 6. Revocation as of use_time — immediate and visible.
    for rev in revocations:
        if not hmac.compare_digest(rev.receipt_digest, known.receipt_digest):
            continue
        if rev.subject_pubkey_hex != known.subject_pubkey_hex:
            continue
        try:
            rev_ok = ed25519.verify(
                bytes.fromhex(rev.subject_pubkey_hex),
                jcs_canonical_json(_revocation_payload(rev)),
                bytes.fromhex(rev.signature_hex),
            )
        except Exception:
            rev_ok = False
        if not rev_ok:
            continue
        if rev.revoked_at <= use_time:
            return _deny(
                f"consent revoked at {rev.revoked_at}: revocation is "
                "immediate and irreversible in the log"
            )

    return ConsentVerdict(
        allowed=True,
        reason="use-time consent verified: chain intact, signature valid, "
        "scope/purpose match, within window, no revocation as of use_time",
        classification=CONSENTED_USE,
        receipt_digest=known.receipt_digest,
    )


def consent_audit_event(verdict: ConsentVerdict, *, action: str) -> dict[str, Any]:
    """Shape a use-time verdict as an audit-chain event dict."""
    return {
        "event": CONSENT_USE_DENIED_EVENT if not verdict.allowed else CONSENT_USE_ALLOWED_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "classification": verdict.classification,
        "receipt_digest": verdict.receipt_digest,
    }


# ---------------------------------------------------------------------------
# Decode attribution (BCI-style intent decoding)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DecodeAttribution:
    """Attribution record for one decoded intent.

    The decode is bound to ``(raw_signal_digest, decoder_id,
    decoder_version, confidence)`` so a wrong decode is attributable
    to the decoder — never to the user. ``ambiguous`` marks decodes
    where the decoder itself reports multiple plausible intents.
    """

    raw_signal_digest: str
    decoder_id: str
    decoder_version: str
    confidence: float
    ambiguous: bool
    classification: str = NON_AUTHORITATIVE_DECODE

    def __post_init__(self) -> None:
        _check_hex64(self.raw_signal_digest, "raw_signal_digest")
        if not isinstance(self.decoder_id, str) or not self.decoder_id:
            raise ConsentReceiptError("decoder_id must be a non-empty string")
        if not isinstance(self.decoder_version, str) or not self.decoder_version:
            raise ConsentReceiptError("decoder_version must be a non-empty string")
        if (
            not isinstance(self.confidence, (int, float))
            or isinstance(self.confidence, bool)
            or not 0.0 <= self.confidence <= 1.0
        ):
            raise ConsentReceiptError("confidence must be a number in [0, 1]")
        if not isinstance(self.ambiguous, bool):
            raise ConsentReceiptError("ambiguous must be a bool")
        if self.classification not in (AUTHORITATIVE_DECODE, NON_AUTHORITATIVE_DECODE):
            raise ConsentReceiptError(
                f"classification must be {AUTHORITATIVE_DECODE!r} or "
                f"{NON_AUTHORITATIVE_DECODE!r}"
            )


def decode_attribution(
    *,
    raw_signal_digest: str,
    decoder_id: str,
    decoder_version: str,
    confidence: float,
    ambiguous: bool = False,
) -> DecodeAttribution:
    """Classify one decoded intent. Fail-closed on uncertainty.

    A decode is ``AUTHORITATIVE`` only if confidence meets
    :data:`DECODE_CONFIDENCE_MIN` *and* the decoder does not flag
    ambiguity. Anything else is ``NON_AUTHORITATIVE``: advisory only,
    must never drive an irreversible action, and must never be logged
    as "the user intended X" — it is logged as "decoder D (vV)
    hypothesized X with confidence c".
    """
    _check_hex64(raw_signal_digest, "raw_signal_digest")
    authoritative = (
        confidence >= DECODE_CONFIDENCE_MIN and not ambiguous
    )
    return DecodeAttribution(
        raw_signal_digest=raw_signal_digest,
        decoder_id=decoder_id,
        decoder_version=decoder_version,
        confidence=confidence,
        ambiguous=ambiguous,
        classification=AUTHORITATIVE_DECODE if authoritative else NON_AUTHORITATIVE_DECODE,
    )


# ---------------------------------------------------------------------------
# Closed-loop stimulation gate (irreversible tier)
# ---------------------------------------------------------------------------


@dataclass
class StimulationVerdict:
    """Outcome of gating one closed-loop stimulation action."""

    allowed: bool
    reason: str


def gate_stimulation(
    *,
    consent_receipt: ConsentReceipt,
    log: list[ConsentReceipt | RevocationRecord],
    use_time: int,
    purpose: str,
    decode: DecodeAttribution,
    human_countersign_ok: bool,
) -> StimulationVerdict:
    """Gate a write-to-brain stimulation. Irreversible tier.

    Mirrors the 99th batch's kill-switch semantics: decoding is
    evidence, never the final word. All of the following must hold:

    1. The decode is ``AUTHORITATIVE`` (a shaky decode never arms
       stimulation — decode-error attribution: the user did not
       "intend" what the decoder guessed).
    2. Fresh consent at use time for scope ``neural_stimulation`` —
       :func:`check_consent_at_use` must allow, *and* the grant must
       be within :data:`STIMULATION_FRESHNESS_WINDOW_S` of ``use_time``
       (a years-old grant does not authorize today's stimulation).
    3. A human countersign (``human_countersign_ok``) — the agent
       cannot countersign for itself; a missing countersign denies.

    Denials audit as ``stimulation.denied``. The verdict never raises.
    """
    _check_ts(use_time, "use_time")

    def _deny(reason: str) -> StimulationVerdict:
        return StimulationVerdict(allowed=False, reason=reason)

    # 1. Decode must be authoritative.
    if decode.classification != AUTHORITATIVE_DECODE:
        return _deny(
            f"decode is {decode.classification}: a non-authoritative decode "
            "must never drive stimulation (decode-error attribution)"
        )

    # 2. Fresh consent for the stimulation scope at use time.
    verdict = check_consent_at_use(
        receipt=consent_receipt,
        log=log,
        data_scope="neural_stimulation",
        purpose=purpose,
        use_time=use_time,
    )
    if not verdict.allowed:
        return _deny(f"stimulation consent check failed: {verdict.reason}")
    grant = next(
        g for g in log
        if isinstance(g, ConsentReceipt)
        and hmac.compare_digest(g.receipt_digest, consent_receipt.receipt_digest)
    )
    if use_time - grant.granted_at > STIMULATION_FRESHNESS_WINDOW_S:
        return _deny(
            f"stimulation consent is stale: granted {use_time - grant.granted_at}s "
            f"ago, freshness window is {STIMULATION_FRESHNESS_WINDOW_S}s"
        )

    # 3. Human countersign — the agent cannot authorize itself.
    if not human_countersign_ok:
        return _deny(
            "no human countersign: closed-loop stimulation requires a "
            "human countersignature (99th-batch semantics)"
        )

    return StimulationVerdict(
        allowed=True,
        reason="stimulation gated: authoritative decode, fresh "
        "neural_stimulation consent at use time, human countersigned",
    )


def stimulation_audit_event(verdict: StimulationVerdict, *, action: str) -> dict[str, Any]:
    """Shape a stimulation verdict as an audit-chain event dict."""
    return {
        "event": STIMULATION_DENIED_EVENT if not verdict.allowed else CONSENT_USE_ALLOWED_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
    }


__all__ = [
    "AUTHORITATIVE_DECODE",
    "CONSENTED_USE",
    "CONSENT_RECEIPT_SCHEMA_VERSION",
    "CONSENT_REVOKED_EVENT",
    "CONSENT_USE_ALLOWED_EVENT",
    "CONSENT_USE_DENIED_EVENT",
    "DATA_SCOPES",
    "DECODE_CONFIDENCE_MIN",
    "NON_AUTHORITATIVE_DECODE",
    "STIMULATION_DENIED_EVENT",
    "STIMULATION_FRESHNESS_WINDOW_S",
    "UNCONSENTED_USE",
    "ConsentReceipt",
    "ConsentReceiptError",
    "ConsentVerdict",
    "DecodeAttribution",
    "RevocationRecord",
    "StimulationVerdict",
    "check_consent_at_use",
    "compute_receipt_digest",
    "compute_revocation_digest",
    "consent_audit_event",
    "decode_attribution",
    "gate_stimulation",
    "grant_consent",
    "revoke_consent",
    "stimulation_audit_event",
]
