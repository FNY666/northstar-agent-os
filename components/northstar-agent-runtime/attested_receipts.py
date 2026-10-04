"""TEE attestation as receipt evidence (ninety-second batch).

Absorbs the 2026 confidential-AI / decentralized-AI research thread
(mechanism ideas only, honestly scoped here):

* Ritual's proof-strength ladder — ``ZKML > OPML > TEE``: a receipt's
  claimed evidence kind is only as strong as what was actually
  verified. A receipt that *claims* TEE execution without a verifiable
  quote is worse than a receipt with no claim at all: the claim itself
  becomes the attack surface (quote replay, kind confusion, stale
  quotes presented as fresh).
* Northstar already has per-call tool receipts (seventy-seventh batch:
  ``tool:<args-sha256>:<result-sha256>`` in the durable-run component)
  and SCITT/COSE receipt shapes (seventy-fourth batch). This module
  extends the receipt schema with an optional ``attestation`` field and
  defines how that field is verified — without weakening anything the
  plain receipt already guarantees.

HONEST SCOPE — read this before deploying:

* This repository cannot mint real TEE quotes. There is no SGX, SEV-SNP,
  or TDX platform here, and no DCAP/attestation-report chain is checked
  by anything in this file.
* What this module *does* provide: the ``evidence_kind`` taxonomy, the
  attestation schema, the verification *interface* (freshness, config
  binding, anti-replay, kind-vs-verifier consistency), and a
  deterministic software-emulated attestor for tests. The emulator's
  quotes are MACs, not TEE quotes, and every emulated attestation is
  stamped ``emulated: True``.
* The real-quote path is explicit: ``verify_attestation`` dispatches on
  ``evidence_kind`` to a caller-supplied quote verifier. Registering a
  verifier is how a platform check plugs in (e.g. an Intel DCAP verifier
  that walks the quote's certificate chain and returns the measured
  config). **If no verifier is registered for the claimed kind,
  verification fails closed** — an unverifiable attestation claim is
  rejected, never downgraded to "software".
* Downgrade rule: an attestation stamped ``emulated: True`` may only
  claim ``evidence_kind == "software"``. Claiming ``tee`` (or stronger)
  on an emulated quote is rejected: that is exactly the
  claim-without-evidence this module exists to kill.

Threat model (what verification actually checks):

* Quote forgery — the quote bytes must authenticate under the
  registered verifier for the claimed kind.
* Quote replay across calls — the quote's ``measured_config`` must
  equal the binding digest of *this* receipt's exact arguments and
  result digests (``tool:<args-sha256>:<result-sha256>`` halves). A
  quote minted for call A presented with receipt B fails closed.
* Stale quotes — ``issued_at`` must not predate the receipt, must not
  be in the future relative to ``now``, and must be within
  ``max_age_seconds``; ``expires_at`` must be after ``issued_at`` and
  at or after ``now``.
* ``quote_hash`` tampering — the ``quote_hash`` field must equal the
  recomputed SHA-256 of the quote bytes (constant-time compare).
* Malformed attestations — missing fields, wrong types, unknown kinds
  raise ``AttestedReceiptError``. A lying attestation record is worse
  than none.

All comparisons of secrets/digests use :func:`hmac.compare_digest`.
No wall-clock reads: callers inject ``now`` (integer epoch seconds).
Deterministic: same inputs, same verdict, no randomness.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping


ATTESTATION_SCHEMA_VERSION = "northstar.receipt-attestation.v1"

#: Proof-strength ladder, strongest first. The index is the rank:
#: a smaller rank is stronger evidence.
EVIDENCE_KIND_LADDER: tuple[str, ...] = ("zkml", "opml", "tee", "software")

_KIND_RANK = {kind: rank for rank, kind in enumerate(EVIDENCE_KIND_LADDER)}

#: Verifier id used by the software emulator. Anything claiming a
#: hardware kind with this verifier id is rejected by the
#: kind-vs-verifier consistency rule.
SOFTWARE_EMULATOR_VERIFIER_ID = "northstar.software-attestor.v1"

_DEFAULT_MAX_AGE_SECONDS = 300
_MIN_SECRET_BYTES = 32
_HEX64_RE_LENGTH = 64


class AttestedReceiptError(ValueError):
    """A malformed attestation or an attestation programming error.

    Raised for structural problems (missing fields, wrong types, unknown
    evidence kinds, no verifier registered). Verification *failures*
    (forgery, replay, staleness) return an
    :class:`AttestationVerdict` with ``allowed=False`` instead — the
    caller decides what to do with a denied attestation, but a
    malformed one is a bug and fails loudly.
    """


# ---------------------------------------------------------------------------
# Canonical hashing (matches the durable-run tool receipt canonicalization)
# ---------------------------------------------------------------------------


def _canonical_bytes(value: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, UTF-8.

    Delegates to the shared legacy canonicalizer (``audit_chain``); the
    domain exception is preserved.
    """
    from audit_chain import canonical_json

    try:
        return canonical_json(value)
    except (TypeError, ValueError) as error:
        raise AttestedReceiptError("value is not canonical JSON") from error


def _canonical_sha256_hex(value: Any) -> str:
    """SHA-256 hex of the canonical JSON encoding of ``value``."""
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _HEX64_RE_LENGTH
        and all(c in "0123456789abcdef" for c in value)
    )


# ---------------------------------------------------------------------------
# Evidence-kind taxonomy
# ---------------------------------------------------------------------------


def kind_rank(evidence_kind: str) -> int:
    """Return the strength rank of an evidence kind (lower is stronger).

    Raises :class:`AttestedReceiptError` for unknown kinds — an unknown
    kind is not "weak", it is malformed.
    """
    try:
        return _KIND_RANK[evidence_kind]
    except (KeyError, TypeError) as error:
        raise AttestedReceiptError(
            f"unknown evidence_kind: {evidence_kind!r} "
            f"(expected one of {', '.join(EVIDENCE_KIND_LADDER)})"
        ) from error


def strength_at_least(evidence_kind: str, minimum: str) -> bool:
    """True when ``evidence_kind`` is at least as strong as ``minimum``.

    Policy use: a tier3 decision can require ``strength_at_least(kind,
    "tee")`` — a ``software`` attestation then fails the bar instead of
    silently passing as "attested".
    """
    return kind_rank(evidence_kind) <= kind_rank(minimum)


# ---------------------------------------------------------------------------
# Call binding: the quote must bind THIS exact call
# ---------------------------------------------------------------------------


def call_binding_digest(arguments_digest: str, result_digest: str) -> str:
    """Digest binding a quote to one exact tool call.

    Computed over the receipt's ``arguments_digest`` and
    ``result_digest`` halves (the ``tool:<args-sha256>:<result-sha256>``
    format from the seventy-seventh batch). A quote is only valid for
    the call whose digests hash to this value — presenting it with any
    other receipt is replay and fails closed.
    """
    if not _is_hex64(arguments_digest):
        raise AttestedReceiptError("arguments_digest must be lowercase sha256 hex")
    if not _is_hex64(result_digest):
        raise AttestedReceiptError("result_digest must be lowercase sha256 hex")
    return _canonical_sha256_hex(
        {"arguments_digest": arguments_digest, "result_digest": result_digest}
    )


def receipt_binding_digest(receipt: Mapping[str, Any]) -> str:
    """Compute the call binding digest from a tool receipt dict."""
    if not isinstance(receipt, Mapping):
        raise AttestedReceiptError("receipt must be a mapping")
    return call_binding_digest(
        receipt.get("arguments_digest"),  # type: ignore[arg-type]
        receipt.get("result_digest"),  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Software-emulated attestor (tests only — NOT a TEE)
# ---------------------------------------------------------------------------


class SoftwareAttestor:
    """Deterministic software-emulated quote issuer. **Test use only.**

    Mints quotes as HMAC-SHA256 over a canonical envelope. The envelope
    and every attestation it produces carry ``emulated: True`` and may
    only claim ``evidence_kind == "software"``. This is a stand-in for
    the *interface* a real TEE quote verifier plugs into — it proves
    the verification logic, not any hardware property.

    ``secret`` must be at least 32 bytes; keep it out of logs and
    audit payloads (only ``quote_hash`` is ever published).
    """

    def __init__(self, secret: bytes, *, verifier_id: str = SOFTWARE_EMULATOR_VERIFIER_ID):
        if not isinstance(secret, bytes) or len(secret) < _MIN_SECRET_BYTES:
            raise AttestedReceiptError(
                f"attestor secret must be bytes of >= {_MIN_SECRET_BYTES} bytes"
            )
        if not isinstance(verifier_id, str) or not verifier_id:
            raise AttestedReceiptError("verifier_id must be a non-empty string")
        self._secret = bytes(secret)
        self.verifier_id = verifier_id

    def _envelope(self, *, measured_config: str, issued_at: int, expires_at: int) -> dict[str, Any]:
        return {
            "v": 1,
            "emulated": True,
            "evidence_kind": "software",
            "measured_config": measured_config,
            "verifier_id": self.verifier_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }

    def mint(
        self,
        *,
        measured_config: str,
        issued_at: int,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        """Mint an emulated software attestation for a call binding."""
        if not _is_hex64(measured_config):
            raise AttestedReceiptError("measured_config must be lowercase sha256 hex")
        for name, value in (("issued_at", issued_at), ("ttl_seconds", ttl_seconds)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise AttestedReceiptError(f"{name} must be a non-negative integer")
        expires_at = issued_at + ttl_seconds
        envelope = self._envelope(
            measured_config=measured_config, issued_at=issued_at, expires_at=expires_at
        )
        mac = hmac.new(self._secret, _canonical_bytes(envelope), hashlib.sha256).hexdigest()
        quote = dict(envelope)
        quote["mac"] = mac
        quote_bytes = _canonical_bytes(quote)
        return {
            "schema_version": ATTESTATION_SCHEMA_VERSION,
            "evidence_kind": "software",
            "emulated": True,
            "quote_hex": quote_bytes.hex(),
            "quote_hash": hashlib.sha256(quote_bytes).hexdigest(),
            "verifier_id": self.verifier_id,
            "measured_config": measured_config,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }

    def as_verifier(self) -> "QuoteVerifier":
        """Return the verifier counterpart of this attestor (test use)."""
        attestor = self

        def _verify(quote_bytes: bytes, *, expected_binding: str) -> str:
            try:
                quote = json.loads(quote_bytes.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as error:
                raise AttestedReceiptError("emulated quote is not valid JSON") from error
            if not isinstance(quote, dict):
                raise AttestedReceiptError("emulated quote must be a JSON object")
            mac = quote.get("mac")
            if not isinstance(mac, str):
                raise AttestedReceiptError("emulated quote carries no mac")
            envelope = {k: v for k, v in quote.items() if k != "mac"}
            expected_mac = hmac.new(
                attestor._secret, _canonical_bytes(envelope), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(mac, expected_mac):
                raise AttestedReceiptError("emulated quote mac mismatch (forgery)")
            if envelope.get("emulated") is not True:
                raise AttestedReceiptError("emulated quote missing emulated:true marker")
            measured = envelope.get("measured_config")
            if not _is_hex64(measured):
                raise AttestedReceiptError("emulated quote measured_config malformed")
            # The caller (verify_attestation) compares this against the
            # receipt's binding digest; the verifier only authenticates.
            return measured

        return QuoteVerifier(kind="software", verifier_id=self.verifier_id, verify=_verify)


# ---------------------------------------------------------------------------
# Quote verifiers: the real-quote path plugs in here
# ---------------------------------------------------------------------------


class QuoteVerifier:
    """A registered verifier for one evidence kind.

    ``verify`` takes the raw quote bytes and returns the
    ``measured_config`` the quote binds, raising
    :class:`AttestedReceiptError` when the quote does not authenticate.

    For ``tee`` / ``opml`` / ``zkml`` this is where the platform check
    lives — e.g. a DCAP verifier that walks the quote's certificate
    chain to a trusted root and extracts the report's measurement. This
    repository ships no such verifier: registering one is the
    deployer's job, and claiming a hardware kind without one fails
    closed in :func:`verify_attestation`.
    """

    def __init__(
        self,
        *,
        kind: str,
        verifier_id: str,
        verify: Callable[[bytes, Any], str],
    ):
        kind_rank(kind)  # validates the kind eagerly
        if not isinstance(verifier_id, str) or not verifier_id:
            raise AttestedReceiptError("verifier_id must be a non-empty string")
        if not callable(verify):
            raise AttestedReceiptError("verify must be callable")
        self.kind = kind
        self.verifier_id = verifier_id
        self.verify = verify


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttestationVerdict:
    """Outcome of :func:`verify_attestation`."""

    allowed: bool
    reason: str
    evidence_kind: str = ""
    verifier_id: str = ""
    quote_hash: str = ""


_REQUIRED_ATTESTATION_FIELDS = (
    "schema_version",
    "evidence_kind",
    "emulated",
    "quote_hex",
    "quote_hash",
    "verifier_id",
    "measured_config",
    "issued_at",
    "expires_at",
)


def _check_attestation_shape(attestation: Any) -> dict[str, Any]:
    if not isinstance(attestation, dict):
        raise AttestedReceiptError("attestation must be an object")
    missing = [f for f in _REQUIRED_ATTESTATION_FIELDS if f not in attestation]
    if missing:
        raise AttestedReceiptError(f"attestation missing fields: {', '.join(missing)}")
    if attestation.get("schema_version") != ATTESTATION_SCHEMA_VERSION:
        raise AttestedReceiptError(
            f"attestation schema_version must be {ATTESTATION_SCHEMA_VERSION}"
        )
    kind = attestation.get("evidence_kind")
    kind_rank(kind)  # raises for unknown kinds
    if not isinstance(attestation.get("emulated"), bool):
        raise AttestedReceiptError("attestation 'emulated' must be a boolean")
    quote_hex = attestation.get("quote_hex")
    if not isinstance(quote_hex, str) or not quote_hex:
        raise AttestedReceiptError("attestation quote_hex must be a non-empty string")
    try:
        quote_bytes = bytes.fromhex(quote_hex)
    except ValueError as error:
        raise AttestedReceiptError("attestation quote_hex is not valid hex") from error
    if not quote_bytes:
        raise AttestedReceiptError("attestation quote is empty")
    if not _is_hex64(attestation.get("quote_hash")):
        raise AttestedReceiptError("attestation quote_hash must be lowercase sha256 hex")
    if not _is_hex64(attestation.get("measured_config")):
        raise AttestedReceiptError("attestation measured_config must be lowercase sha256 hex")
    if not isinstance(attestation.get("verifier_id"), str) or not attestation.get("verifier_id"):
        raise AttestedReceiptError("attestation verifier_id must be a non-empty string")
    for name in ("issued_at", "expires_at"):
        value = attestation.get(name)
        if not isinstance(value, int) or isinstance(value, bool):
            raise AttestedReceiptError(f"attestation {name} must be an integer")
    if attestation["expires_at"] <= attestation["issued_at"]:
        raise AttestedReceiptError("attestation expires_at must be after issued_at")
    return attestation


def _deny(kind: str, verifier_id: str, quote_hash: str, reason: str) -> AttestationVerdict:
    return AttestationVerdict(
        allowed=False,
        reason=reason,
        evidence_kind=kind,
        verifier_id=verifier_id,
        quote_hash=quote_hash,
    )


def verify_attestation(
    receipt: Mapping[str, Any],
    attestation: Mapping[str, Any],
    *,
    verifiers: Mapping[str, QuoteVerifier],
    now: int,
    max_age_seconds: int = _DEFAULT_MAX_AGE_SECONDS,
) -> AttestationVerdict:
    """Verify an attestation against a tool receipt. Fail closed.

    ``verifiers`` maps each evidence kind the caller is willing to
    accept to its :class:`QuoteVerifier`. A kind with no registered
    verifier is denied — never silently accepted, never downgraded.

    ``now`` is integer epoch seconds (no wall-clock reads).
    ``max_age_seconds`` bounds how old a quote may be at ``now``.

    Returns an :class:`AttestationVerdict`. Raises
    :class:`AttestedReceiptError` only for malformed inputs (receipt or
    attestation structurally invalid); verification failures return
    ``allowed=False`` with a reason.
    """
    if not isinstance(now, int) or isinstance(now, bool) or now < 0:
        raise AttestedReceiptError("now must be a non-negative integer")
    if not isinstance(max_age_seconds, int) or isinstance(max_age_seconds, bool) or max_age_seconds < 0:
        raise AttestedReceiptError("max_age_seconds must be a non-negative integer")
    if not isinstance(verifiers, Mapping):
        raise AttestedReceiptError("verifiers must be a mapping")

    att = _check_attestation_shape(attestation)
    kind = att["evidence_kind"]
    verifier_id = att["verifier_id"]
    quote_hash = att["quote_hash"]

    expected_binding = receipt_binding_digest(receipt)
    receipt_issued_at = receipt.get("issued_at")
    if not isinstance(receipt_issued_at, int) or isinstance(receipt_issued_at, bool):
        raise AttestedReceiptError("receipt issued_at must be an integer")

    # 1. quote_hash must match the quote bytes (constant-time).
    recomputed = hashlib.sha256(bytes.fromhex(att["quote_hex"])).hexdigest()
    if not hmac.compare_digest(recomputed, quote_hash):
        return _deny(kind, verifier_id, quote_hash, "quote_hash does not match quote bytes")

    # 2. Emulated quotes may only claim "software". A TEE claim on an
    #    emulated quote is the unverifiable claim this module rejects.
    if att["emulated"] is True and kind != "software":
        return _deny(
            kind,
            verifier_id,
            quote_hash,
            f"emulated quote claims evidence_kind={kind!r}: "
            "emulated quotes may only claim 'software'",
        )

    # 3. A registered verifier is required for the claimed kind.
    verifier = verifiers.get(kind)
    if verifier is None:
        return _deny(
            kind,
            verifier_id,
            quote_hash,
            f"no verifier registered for evidence_kind={kind!r}: "
            "unverifiable attestation claims are rejected",
        )
    if verifier.verifier_id != verifier_id:
        return _deny(
            kind,
            verifier_id,
            quote_hash,
            "attestation verifier_id does not match the registered verifier",
        )

    # 4. Freshness: not expired, not from the future, not older than
    #    max_age, and not predating the receipt it attests.
    issued_at = att["issued_at"]
    expires_at = att["expires_at"]
    if now > expires_at:
        return _deny(kind, verifier_id, quote_hash, "quote expired")
    if issued_at > now:
        return _deny(kind, verifier_id, quote_hash, "quote issued in the future")
    if now - issued_at > max_age_seconds:
        return _deny(kind, verifier_id, quote_hash, "quote older than max_age_seconds")
    if issued_at < receipt_issued_at:
        return _deny(
            kind,
            verifier_id,
            quote_hash,
            "quote predates the receipt it attests (stale quote)",
        )

    # 5. The quote must authenticate under the registered verifier,
    # and the config it binds must be THIS call (anti-replay). The
    # attestation's measured_config *field* must also agree with what
    # the quote itself binds — a field that disagrees with its own
    # quote is a confusion vector, not a typo.
    try:
        measured_config = verifier.verify(bytes.fromhex(att["quote_hex"]), expected_binding=expected_binding)
    except AttestedReceiptError as error:
        return _deny(kind, verifier_id, quote_hash, f"quote authentication failed: {error}")
    if not hmac.compare_digest(str(att["measured_config"]), str(measured_config)):
        return _deny(
            kind,
            verifier_id,
            quote_hash,
            "attestation measured_config field disagrees with the quote it carries",
        )
    if not hmac.compare_digest(str(measured_config), expected_binding):
        return _deny(
            kind,
            verifier_id,
            quote_hash,
            "quote measured_config does not bind this call (replay across calls)",
        )

    return AttestationVerdict(
        allowed=True,
        reason=f"attestation verified: kind={kind} verifier={verifier_id}",
        evidence_kind=kind,
        verifier_id=verifier_id,
        quote_hash=quote_hash,
    )


# ---------------------------------------------------------------------------
# Receipt schema extension
# ---------------------------------------------------------------------------


def attach_attestation(
    receipt: Mapping[str, Any], attestation: Mapping[str, Any]
) -> dict[str, Any]:
    """Return a copy of ``receipt`` with the ``attestation`` field set.

    The receipt's ``receipt_id`` is unchanged: the id binds the exact
    arguments and result (seventy-seventh batch), and the attestation
    is verified *against* those digests rather than folded into them.
    Refuses to overwrite an existing attestation (no silent upgrade)
    and refuses malformed attestations. Attestation is optional — a
    receipt without one remains a valid plain receipt.
    """
    if not isinstance(receipt, dict):
        raise AttestedReceiptError("receipt must be a dict")
    if "attestation" in receipt:
        raise AttestedReceiptError("receipt already carries an attestation (no silent overwrite)")
    _check_attestation_shape(attestation)
    # Structural sanity on the receipt side: the digests the attestation
    # will be verified against must exist and be well-formed.
    receipt_binding_digest(receipt)
    out = dict(receipt)
    out["attestation"] = dict(attestation)
    return out


def attestation_audit_event(
    verdict: AttestationVerdict,
    receipt: Mapping[str, Any],
    attestation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Render an attested-receipt audit event (hash-chain friendly).

    Event types: ``attested_receipt.verified`` / ``attested_receipt.denied``.
    Pins ``receipt_id``, ``quote_hash``, ``evidence_kind``,
    ``verifier_id``, and the reason — everything a third party needs to
    re-verify, without republishing the quote bytes.
    """
    receipt_id = receipt.get("receipt_id") if isinstance(receipt, Mapping) else None
    return {
        "schema_version": "northstar.audit.v1",
        "event_type": "attested_receipt.verified" if verdict.allowed else "attested_receipt.denied",
        "receipt_id": receipt_id,
        "evidence_kind": verdict.evidence_kind,
        "verifier_id": verdict.verifier_id,
        "quote_hash": verdict.quote_hash,
        "reason": verdict.reason,
        "attested": bool(verdict.allowed),
    }


__all__ = [
    "ATTESTATION_SCHEMA_VERSION",
    "EVIDENCE_KIND_LADDER",
    "SOFTWARE_EMULATOR_VERIFIER_ID",
    "AttestedReceiptError",
    "AttestationVerdict",
    "QuoteVerifier",
    "SoftwareAttestor",
    "attach_attestation",
    "attestation_audit_event",
    "call_binding_digest",
    "kind_rank",
    "receipt_binding_digest",
    "strength_at_least",
    "verify_attestation",
]
