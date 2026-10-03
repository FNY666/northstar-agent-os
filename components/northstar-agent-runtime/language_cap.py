"""Language-capability receipts (one-hundred-fourteenth batch).

Absorbs the 2026 low-resource-language research thread (mechanism
ideas only, honestly scoped):

* **The capability gap is measured, not vibes.** 2026 benchmarks put
  GPT-4o at 12.0–19.9% absolute below English on 11 African languages
  (56.1% worst-case, Belebele Bambara); Kazakh/Mongolian 13.8–16.7pp
  lower; IRLBench Irish 55.8% vs English 76.2%. Here a model may only
  serve languages it holds an authority-signed capability receipt for;
  an undeclared language is ``unverifiable-process``, not "probably
  fine".
* **Fluency is not accuracy — the fluency trap.** The Kazakh/Mongolian
  studies found surface fluency *holding* while accuracy dropped:
  "fluent wrong answers" are the most dangerous failure mode. Here
  fluency and accuracy are separate declared bands, and high fluency
  with a low/unmeasured accuracy band in a high-stakes domain is
  explicitly flagged ``fluent_unverified`` — the receipt refuses to let
  fluency launder inaccuracy.
* **Safety alignment does not cross languages.** IndicSafe (2026-03)
  found only 12.8% cross-language consistency of safety alignment
  across 12 Indian languages. Here a deterministic cross-language
  safety probe downgrades the safety claim of any language that fails
  the same test its siblings pass; there is no per-model global safety
  badge.
* **Medical mistranslation is a harm event.** Farsi/Armenian
  mistranslation rates 32–45%, Korean hallucination 30.2% vs English
  13.4%. Medical/legal outputs in low/unmeasured-accuracy languages
  default to NON_AUTHORITATIVE with mandatory human countersign, and
  every gate fire emits an ``i18n.mistranslation_harm`` audit event.
* **Community data sovereignty.** FLAIR (Cherokee/Maya/Mam/Zapotec,
  data-sovereignty + offline-first), KIWA Digital (Ngalia, 3 fluent
  speakers left), Heritage Lab (Inuit-led Inuktitut). Training data
  from a language community requires a community-signed,
  purpose-bound, revocable data-sovereignty receipt — the 105th
  batch's consent discipline, with the community as the subject.

Northstar mapping:

* ``LanguageCapabilityReceipt`` — a hash-chained, authority-signed
  receipt declaring ``(model_digest, language_tag, locale_variant,
  accuracy_band, measured_on_benchmark_digest)``. Accuracy bands are a
  closed vocabulary ``high/moderate/low/unmeasured``; locale variants
  are matched exactly (``pt`` != ``pt-BR``). ``unmeasured`` pins the
  canonical no-measurement marker (64 zero hex) — an unmeasured band
  may not point at a real benchmark digest, and a measured band may
  not use the zero marker (fail-closed both ways).
* ``check_language_servable()`` — fail-closed gate: no valid,
  unexpired, untampered receipt for the exact (model, tag, variant)
  triple → ``unverifiable-process``. Denials audit as
  ``i18n.serve_denied``.
* ``check_output_gate()`` — medical/legal-domain outputs in
  ``low``/``unmeasured`` languages → NON_AUTHORITATIVE with
  ``mandatory_human_review=True``; high fluency + low accuracy raises
  the ``fluent_unverified`` flag. Every high-stakes low-accuracy gate
  fire emits ``i18n.mistranslation_harm``.
* ``alignment_probe()`` — deterministic: the same safety test,
  rendered per declared language via a caller-supplied pure probe
  function; failing languages get their safety claim downgraded via
  ``restrict_accuracy_band()`` (narrow-only amendments; widening needs
  a fresh authority-signed receipt with a new measurement).
* ``grant_community_data()`` / ``revoke_community_data()`` /
  ``check_community_use()`` — community-signed data-sovereignty
  receipts: revocable, purpose-bound, checked at *use time* (never at
  collection time). Use without a grant denies; use of community data
  audits as ``i18n.community_use_denied`` on denial.

Honest boundary: accuracy bands are *declared measurements*, pinned by
digest — the module verifies the receipt, the signature, the chain and
the band's policy consequences; it cannot live-verify that a model's
true accuracy matches the declared band. That requires independent
evaluation (the 113th-batch evaluator discipline) and is noted as
future work. Community authority keys are the trust anchor: whoever
holds the community's signing key speaks for the community, and the
key-distribution problem is out of scope here.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest comparisons
via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Callable, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex

LANGUAGE_CAP_SCHEMA_VERSION = "northstar.language-cap.v1"

#: Closed accuracy-band vocabulary. A model serves only languages whose
#: band is declared; the band is a measurement claim, not a guess.
ACCURACY_BANDS: tuple[str, ...] = (
    "high",
    "moderate",
    "low",
    "unmeasured",
)

#: Canonical marker for "no measurement claimed". An ``unmeasured``
#: band must pin exactly this digest; a measured band must not.
UNMEASURED_DIGEST = "0" * 64

#: Closed fluency-band vocabulary. Fluency is declared separately from
#: accuracy — the fluency trap is when these two disagree.
FLUENCY_BANDS: tuple[str, ...] = (
    "fluent",
    "degraded",
    "unknown",
)

#: Closed high-stakes domain vocabulary. Outputs in these domains get
#: the mistranslation-harm gate.
HIGH_STAKES_DOMAINS: tuple[str, ...] = (
    "medical",
    "legal",
)

#: Closed general domain vocabulary (no mistranslation gate).
GENERAL_DOMAINS: tuple[str, ...] = (
    "general",
    "education",
    "casual",
)

#: Bands that trigger the mistranslation-harm gate in high-stakes domains.
GATED_BANDS = frozenset({"low", "unmeasured"})

#: Binary-ish classification set (87th-batch semantics): there is no
#: "partially authoritative". ``fluent_unverified`` is the explicit
#: fluency-trap label — fluent surface, unmeasured/low accuracy.
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"
CLASS_FLUENT_UNVERIFIED = "fluent_unverified"
CLASS_UNVERIFIABLE = "unverifiable-process"

#: Denial reason codes. All start with the ``i18n:`` prefix.
DENY_NO_RECEIPT = "i18n:no_capability_receipt"
DENY_LOCALE_MISMATCH = "i18n:locale_variant_mismatch"
DENY_RECEIPT_EXPIRED = "i18n:receipt_expired"
DENY_RECEIPT_TAMPERED = "i18n:receipt_tampered"
DENY_RECEIPT_FUTURE = "i18n:receipt_from_future"
DENY_SIGNATURE_INVALID = "i18n:signature_invalid"
DENY_CHAIN_BROKEN = "i18n:chain_broken"
DENY_BAND_MARKER_MISMATCH = "i18n:band_marker_mismatch"
DENY_COMMUNITY_NO_GRANT = "i18n:community_no_grant"
DENY_COMMUNITY_REVOKED = "i18n:community_revoked"
DENY_COMMUNITY_EXPIRED = "i18n:community_grant_expired"
DENY_COMMUNITY_PURPOSE = "i18n:community_purpose_mismatch"
DENY_COMMUNITY_TAMPERED = "i18n:community_log_tampered"
DENY_PROBE_DOWNGRADED = "i18n:probe_safety_downgraded"
DENY_MALFORMED = "i18n:malformed"

#: Audit event names (shaped for ``audit_chain.chain_record``).
SERVE_ALLOWED_EVENT = "i18n.served"
SERVE_DENIED_EVENT = "i18n.serve_denied"
MISTRANSLATION_HARM_EVENT = "i18n.mistranslation_harm"
PROBE_EVENT = "i18n.probe_completed"
PROBE_DOWNGRADE_EVENT = "i18n.probe_downgraded"
COMMUNITY_GRANTED_EVENT = "i18n.community_granted"
COMMUNITY_REVOKED_EVENT = "i18n.community_revoked"
COMMUNITY_DENIED_EVENT = "i18n.community_use_denied"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class LanguageCapError(ValueError):
    """Malformed receipt/grant or a programming error.

    Raised for structural problems (unknown vocabulary, bad digests,
    non-hex fields). Verification *failures* (undeclared language,
    expired, revoked, bad signature at check time) return verdicts with
    ``allowed=False`` — a failed language check is a verdict, a
    malformed log is a bug.
    """


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise LanguageCapError(f"{field_name} must be 64 lowercase hex chars")
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise LanguageCapError(f"{field_name} must be 128 lowercase hex chars")
    return value


def _check_band(value: Any) -> str:
    if value not in ACCURACY_BANDS:
        raise LanguageCapError(
            f"unknown accuracy band {value!r}; closed vocabulary {ACCURACY_BANDS}"
        )
    return value


def _check_fluency(value: Any) -> str:
    if value not in FLUENCY_BANDS:
        raise LanguageCapError(
            f"unknown fluency band {value!r}; closed vocabulary {FLUENCY_BANDS}"
        )
    return value


def _check_domain(value: Any) -> str:
    if value not in HIGH_STAKES_DOMAINS + GENERAL_DOMAINS:
        raise LanguageCapError(
            f"unknown domain {value!r}; closed vocabulary "
            f"{HIGH_STAKES_DOMAINS + GENERAL_DOMAINS}"
        )
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise LanguageCapError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed (no keypair()).
    if not isinstance(value, bytes) or len(value) != 32:
        raise LanguageCapError(f"{field_name} must be a 32-byte seed")
    return value


def _check_pubkey_hex(value: Any) -> str:
    return _check_hex64(value, "pubkey_hex")


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LanguageCapError(f"{field_name} must be a non-empty string")
    return value


def _check_language_tag(value: Any, field_name: str = "language_tag") -> str:
    # BCP-47-ish shape: lowercase alpha subtags separated by hyphens.
    value = _check_nonempty_str(value, field_name)
    parts = value.split("-")
    if not all(p.isalpha() and p.islower() for p in parts):
        raise LanguageCapError(
            f"{field_name} must be lowercase BCP-47-like tags, got {value!r}"
        )
    return value


# ---------------------------------------------------------------------------
# LanguageCapabilityReceipt: authority-signed, hash-chained declaration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LanguageCapabilityReceipt:
    """Declared language capability for one (model, tag, variant).

    ``accuracy_band`` is a closed-vocabulary measurement claim.
    ``locale_variant`` is exact-matched: a receipt for ``pt`` does not
    cover ``pt-br``. ``measured_on_benchmark_digest`` pins the benchmark
    the measurement claims; ``unmeasured`` must pin
    :data:`UNMEASURED_DIGEST` (fail-closed both ways). ``fluency_band``
    is declared alongside accuracy so the fluency trap is visible in
    the receipt itself.
    """

    receipt_id: str
    model_digest: str
    language_tag: str
    locale_variant: str
    accuracy_band: str
    fluency_band: str
    measured_on_benchmark_digest: str
    measured_at: int
    expires_at: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = LANGUAGE_CAP_SCHEMA_VERSION


def _receipt_payload(receipt: LanguageCapabilityReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "model_digest": receipt.model_digest,
        "language_tag": receipt.language_tag,
        "locale_variant": receipt.locale_variant,
        "accuracy_band": receipt.accuracy_band,
        "fluency_band": receipt.fluency_band,
        "measured_on_benchmark_digest": receipt.measured_on_benchmark_digest,
        "measured_at": receipt.measured_at,
        "expires_at": receipt.expires_at,
        "issued_by": receipt.issued_by,
        "authority_pubkey_hex": receipt.authority_pubkey_hex,
        "prev_digest": receipt.prev_digest,
        "schema_version": receipt.schema_version,
    }


def compute_receipt_digest(receipt: LanguageCapabilityReceipt) -> str:
    """Recompute the JCS digest a receipt claims."""
    return jcs_sha256_hex(_receipt_payload(receipt))


def issue_capability_receipt(
    *,
    receipt_id: str,
    model_digest: str,
    language_tag: str,
    locale_variant: str,
    accuracy_band: str,
    fluency_band: str,
    measured_on_benchmark_digest: str,
    authority_secret: bytes,
    issued_by: str,
    measured_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> LanguageCapabilityReceipt:
    """Issue an authority-signed language-capability receipt and seal it.

    Fail-closed at issuance: unknown bands raise; an ``unmeasured``
    band must pin :data:`UNMEASURED_DIGEST` (it may not cite a real
    benchmark), and a measured band may not use the zero marker (it may
    not launder the absence of measurement); ``expires_at <=
    measured_at`` raises. The signature is over the canonical payload
    (signature excluded from the digest input, 97th-batch
    envelope-pinning pattern). There is no agent-key path: issuance is
    a human-authority act (94th/104th-batch no-self-issuance).
    """
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    language_tag = _check_language_tag(language_tag)
    locale_variant = _check_language_tag(locale_variant, "locale_variant")
    accuracy_band = _check_band(accuracy_band)
    fluency_band = _check_fluency(fluency_band)
    measured_on_benchmark_digest = _check_hex64(
        measured_on_benchmark_digest, "measured_on_benchmark_digest"
    )
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    measured_at = _check_ts(measured_at, "measured_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= measured_at:
        raise LanguageCapError("expires_at must be after measured_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise LanguageCapError("prev_digest must be a non-empty string")

    # Fail-closed both ways on the measurement marker.
    if accuracy_band == "unmeasured":
        if not hmac.compare_digest(
            measured_on_benchmark_digest, UNMEASURED_DIGEST
        ):
            raise LanguageCapError(
                "unmeasured band must pin the no-measurement marker "
                "(64 zero hex); it may not cite a benchmark digest"
            )
    else:
        if hmac.compare_digest(measured_on_benchmark_digest, UNMEASURED_DIGEST):
            raise LanguageCapError(
                f"measured band {accuracy_band!r} must pin a real benchmark "
                "digest, not the no-measurement marker"
            )

    pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = LanguageCapabilityReceipt(
        receipt_id=receipt_id,
        model_digest=model_digest,
        language_tag=language_tag,
        locale_variant=locale_variant,
        accuracy_band=accuracy_band,
        fluency_band=fluency_band,
        measured_on_benchmark_digest=measured_on_benchmark_digest,
        measured_at=measured_at,
        expires_at=expires_at,
        issued_by=issued_by,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,  # placeholder; replaced below
        prev_digest=prev_digest,
    )
    payload = _receipt_payload(bare)
    signature_hex = ed25519.sign(
        authority_secret, jcs_canonical_json(payload)
    ).hex()
    sealed = LanguageCapabilityReceipt(
        **{**bare.__dict__, "signature_hex": signature_hex}
    )
    return LanguageCapabilityReceipt(
        **{**sealed.__dict__, "receipt_digest": compute_receipt_digest(sealed)}
    )


def _verify_receipt_chain(log: list[LanguageCapabilityReceipt]) -> None:
    """Raise :class:`LanguageCapError` if the receipt log is broken."""
    expected_prev = _GENESIS
    for receipt in log:
        if not isinstance(receipt, LanguageCapabilityReceipt):
            raise LanguageCapError("log entry is not a LanguageCapabilityReceipt")
        if not hmac.compare_digest(
            compute_receipt_digest(receipt), receipt.receipt_digest
        ):
            raise LanguageCapError(
                f"receipt {receipt.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise LanguageCapError(
                f"receipt {receipt.receipt_id!r} chain break: expected "
                f"prev {expected_prev!r}"
            )
        try:
            sig_ok = ed25519.verify(
                bytes.fromhex(receipt.authority_pubkey_hex),
                jcs_canonical_json(_receipt_payload(receipt)),
                bytes.fromhex(receipt.signature_hex),
            )
        except Exception:
            sig_ok = False
        if not sig_ok:
            raise LanguageCapError(
                f"receipt {receipt.receipt_id!r} authority signature invalid"
            )
        expected_prev = receipt.receipt_digest


@dataclass(frozen=True)
class ServeVerdict:
    """Verdict of the language-service gate."""

    allowed: bool
    reason: str
    classification: str
    receipt_digest: str = ""
    mandatory_human_review: bool = False


def check_language_servable(
    log: list[LanguageCapabilityReceipt],
    *,
    model_digest: str,
    language_tag: str,
    locale_variant: str,
    check_time: int,
) -> ServeVerdict:
    """Fail-closed gate: is this (model, tag, variant) servable now?

    The receipt must exist for the *exact* triple — ``pt`` does not
    cover ``pt-br`` — and be unexpired, untampered, and signature-valid
    as of ``check_time``. No receipt → ``unverifiable-process``; there
    is no partial tier to launder an undeclared language through.
    """
    model_digest = _check_hex64(model_digest, "model_digest")
    language_tag = _check_language_tag(language_tag)
    locale_variant = _check_language_tag(locale_variant, "locale_variant")
    _check_ts(check_time, "check_time")

    def _deny(code: str, detail: str) -> ServeVerdict:
        # Convention (scene_bound.py): the reason carries the
        # machine-readable denial code; classification is the tier.
        return ServeVerdict(
            allowed=False,
            reason=f"{code}: {detail}",
            classification=CLASS_UNVERIFIABLE,
        )

    # 1. Log integrity first: a tampered log denies everything.
    try:
        _verify_receipt_chain(log)
    except LanguageCapError as error:
        return _deny(DENY_CHAIN_BROKEN, f"receipt log integrity failure: {error}")

    # 2. Exact-triple match first (fail-closed on locale variants).
    exact = [
        r
        for r in log
        if hmac.compare_digest(r.model_digest, model_digest)
        and r.language_tag == language_tag
        and r.locale_variant == locale_variant
    ]
    if not exact:
        # Diagnose: same model+tag but a different variant exists.
        sibling = next(
            (
                r
                for r in log
                if hmac.compare_digest(r.model_digest, model_digest)
                and r.language_tag == language_tag
            ),
            None,
        )
        if sibling is not None:
            return _deny(
                DENY_LOCALE_MISMATCH,
                f"receipt covers {sibling.locale_variant!r}, request is "
                f"{locale_variant!r} — locale variants are distinct",
            )
        return _deny(
            DENY_NO_RECEIPT,
            f"no capability receipt for ({language_tag}, {locale_variant}): "
            "undeclared language",
        )
    receipt = exact[-1]  # latest amendment for the triple wins

    # 3. Time window.
    if check_time < receipt.measured_at:
        return _deny(DENY_RECEIPT_FUTURE, "check_time predates the measurement")
    if check_time > receipt.expires_at:
        return _deny(
            DENY_RECEIPT_EXPIRED, f"receipt expired at {receipt.expires_at}"
        )

    return ServeVerdict(
        allowed=True,
        reason=(
            f"servable: exact receipt {receipt.receipt_id!r} for "
            f"({language_tag}, {locale_variant}), band "
            f"{receipt.accuracy_band!r}, chain intact"
        ),
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt.receipt_digest,
    )


@dataclass(frozen=True)
class OutputVerdict:
    """Verdict of the output gate (domain + fluency trap)."""

    allowed: bool
    reason: str
    classification: str
    receipt_digest: str = ""
    mandatory_human_review: bool = False
    mistranslation_harm_event: bool = False


def check_output_gate(
    log: list[LanguageCapabilityReceipt],
    *,
    model_digest: str,
    language_tag: str,
    locale_variant: str,
    domain: str,
    check_time: int,
) -> OutputVerdict:
    """Gate one model output on (language, domain).

    Order, fail-closed:

    1. The triple must be servable (no receipt → unverifiable).
    2. In a high-stakes domain (``medical``/``legal``) with band
       ``low``/``unmeasured`` → NON_AUTHORITATIVE with
       ``mandatory_human_review=True``, and the
       ``i18n.mistranslation_harm`` audit event fires.
    3. The fluency trap: ``fluent`` fluency + ``low``/``unmeasured``
       accuracy in a high-stakes domain is explicitly classified
       ``fluent_unverified`` — fluency may not launder inaccuracy.
    4. Everything else → authoritative.

    The gate returns verdicts; emitting the audit events is the
    caller's job (see :func:`serve_audit_event` /
    :func:`mistranslation_audit_event`).
    """
    domain = _check_domain(domain)
    serve = check_language_servable(
        log,
        model_digest=model_digest,
        language_tag=language_tag,
        locale_variant=locale_variant,
        check_time=check_time,
    )
    if not serve.allowed:
        return OutputVerdict(
            allowed=False,
            reason=serve.reason,
            classification=serve.classification,
            receipt_digest=serve.receipt_digest,
        )
    receipt = next(
        r
        for r in log
        if hmac.compare_digest(r.receipt_digest, serve.receipt_digest)
    )

    gated = domain in HIGH_STAKES_DOMAINS and receipt.accuracy_band in GATED_BANDS
    fluent_trap = (
        gated
        and receipt.fluency_band == "fluent"
    )
    if fluent_trap:
        return OutputVerdict(
            allowed=False,
            reason=(
                f"fluency trap: fluent surface with "
                f"{receipt.accuracy_band!r} accuracy in {domain!r} domain — "
                "classified fluent_unverified; human review mandatory"
            ),
            classification=CLASS_FLUENT_UNVERIFIED,
            receipt_digest=receipt.receipt_digest,
            mandatory_human_review=True,
            mistranslation_harm_event=True,
        )
    if gated:
        return OutputVerdict(
            allowed=False,
            reason=(
                f"high-stakes domain {domain!r} with accuracy band "
                f"{receipt.accuracy_band!r} — NON_AUTHORITATIVE; human "
                "countersign required before release"
            ),
            classification=CLASS_NON_AUTHORITATIVE,
            receipt_digest=receipt.receipt_digest,
            mandatory_human_review=True,
            mistranslation_harm_event=True,
        )
    return OutputVerdict(
        allowed=True,
        reason=(
            f"output gate pass: band {receipt.accuracy_band!r} in "
            f"{domain!r} domain"
        ),
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt.receipt_digest,
    )


def serve_audit_event(
    verdict: ServeVerdict | OutputVerdict, *, action: str
) -> dict[str, Any]:
    """Shape a serve/output verdict as an audit-chain event dict."""
    return {
        "event": SERVE_ALLOWED_EVENT
        if verdict.allowed
        else SERVE_DENIED_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "classification": verdict.classification,
        "receipt_digest": verdict.receipt_digest,
        "mandatory_human_review": verdict.mandatory_human_review,
    }


def mistranslation_audit_event(
    verdict: OutputVerdict, *, action: str
) -> dict[str, Any]:
    """Shape a mistranslation-harm gate fire as an audit-chain event."""
    return {
        "event": MISTRANSLATION_HARM_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "classification": verdict.classification,
        "receipt_digest": verdict.receipt_digest,
        "mandatory_human_review": verdict.mandatory_human_review,
    }


# ---------------------------------------------------------------------------
# Narrow-only amendments (probe downgrades)
# ---------------------------------------------------------------------------

#: Band ordering from most to least capable. Amendments may only move
#: *down* this ordering; widening requires a fresh authority-signed
#: receipt with a new measurement.
_BAND_RANK = {"high": 3, "moderate": 2, "low": 1, "unmeasured": 0}


def restrict_accuracy_band(
    log: list[LanguageCapabilityReceipt],
    *,
    model_digest: str,
    language_tag: str,
    locale_variant: str,
    new_band: str,
    authority_secret: bytes,
    issued_by: str,
    issued_at: int,
    expires_at: int,
) -> LanguageCapabilityReceipt:
    """Append a narrow-only amendment for the exact triple.

    The new band must be strictly *lower* than the current band —
    probe downgrades narrow, never widen. Widening is a fresh
    measurement and goes through :func:`issue_capability_receipt`.
    The amendment chains to the latest receipt in ``log``.
    """
    new_band = _check_band(new_band)
    _verify_receipt_chain(log)
    serve = check_language_servable(
        log,
        model_digest=model_digest,
        language_tag=language_tag,
        locale_variant=locale_variant,
        check_time=issued_at,
    )
    if not serve.allowed:
        raise LanguageCapError(f"cannot restrict: {serve.reason}")
    current = next(
        r
        for r in log
        if hmac.compare_digest(r.receipt_digest, serve.receipt_digest)
    )
    if _BAND_RANK[new_band] >= _BAND_RANK[current.accuracy_band]:
        raise LanguageCapError(
            f"amendments narrow only: {current.accuracy_band!r} -> "
            f"{new_band!r} is not a downgrade; widening requires a fresh "
            "measurement via issue_capability_receipt"
        )
    prev_digest = log[-1].receipt_digest
    # A downgrade keeps the measurement pin of the original receipt
    # (the probe refuted the band, not the measurement's existence).
    return issue_capability_receipt(
        receipt_id=f"{current.receipt_id}#downgrade-{new_band}",
        model_digest=model_digest,
        language_tag=language_tag,
        locale_variant=locale_variant,
        accuracy_band=new_band,
        fluency_band=current.fluency_band,
        measured_on_benchmark_digest=(
            UNMEASURED_DIGEST
            if new_band == "unmeasured"
            else current.measured_on_benchmark_digest
        ),
        authority_secret=authority_secret,
        issued_by=issued_by,
        measured_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )


# ---------------------------------------------------------------------------
# Cross-language safety probe (IndicSafe-style consistency)
# ---------------------------------------------------------------------------

#: The probe's deterministic outcome per language.
PROBE_PASS = "pass"
PROBE_FAIL = "fail"


def alignment_probe(
    log: list[LanguageCapabilityReceipt],
    *,
    model_digest: str,
    probe_fn: Callable[[str, str], bool],
    check_time: int,
) -> dict[str, str]:
    """Run the same safety test in every declared language, deterministically.

    ``probe_fn(language_tag, locale_variant)`` is a caller-supplied
    *pure* function returning True (pass) / False (fail) for the same
    safety test rendered in that language. The probe does not run the
    model — it runs the caller's deterministic rendering of the test —
    so the outcome is a property of the *claim*, not a live
    measurement (honest boundary). Languages failing the same test
    their siblings pass are reported ``fail``; the safety claim of a
    failing language must be downgraded via
    :func:`restrict_accuracy_band` — there is no per-model global
    safety badge (the IndicSafe 12.8% finding, as a mechanism).
    """
    _check_hex64(model_digest, "model_digest")
    _check_ts(check_time, "check_time")
    _verify_receipt_chain(log)
    triples: list[tuple[str, str]] = []
    for receipt in log:
        if hmac.compare_digest(receipt.model_digest, model_digest):
            triple = (receipt.language_tag, receipt.locale_variant)
            if triple not in triples:
                triples.append(triple)
    if not triples:
        raise LanguageCapError("no receipts for this model digest")
    results: dict[str, str] = {}
    for tag, variant in sorted(triples):
        serve = check_language_servable(
            log,
            model_digest=model_digest,
            language_tag=tag,
            locale_variant=variant,
            check_time=check_time,
        )
        key = f"{tag}/{variant}"
        if not serve.allowed:
            results[key] = PROBE_FAIL
            continue
        try:
            passed = probe_fn(tag, variant)
        except Exception as error:
            raise LanguageCapError(f"probe_fn raised for {key}: {error}") from error
        if not isinstance(passed, bool):
            raise LanguageCapError(f"probe_fn must return bool for {key}")
        results[key] = PROBE_PASS if passed else PROBE_FAIL
    return results


def probe_audit_event(
    results: Mapping[str, str], *, model_digest: str
) -> dict[str, Any]:
    """Shape a probe run as an audit-chain event dict."""
    failed = sorted(k for k, v in results.items() if v == PROBE_FAIL)
    return {
        "event": PROBE_DOWNGRADE_EVENT if failed else PROBE_EVENT,
        "model_digest": model_digest,
        "results": dict(results),
        "failed": failed,
    }


# ---------------------------------------------------------------------------
# Community data-sovereignty receipts (105th-batch consent discipline)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommunityGrant:
    """Community-signed data-sovereignty grant.

    The community (e.g. a language community, via its signing key) is
    the *subject*: the grant is purpose-bound and revocable, and every
    use re-verifies at use time — the 105th batch's "no 'was once
    consented' shortcut" discipline, with the community as the
    subject.
    """

    grant_id: str
    community_id: str
    data_scope: str
    purpose: str
    granted_at: int
    expires_at: int
    community_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    grant_digest: str = ""
    schema_version: str = LANGUAGE_CAP_SCHEMA_VERSION


@dataclass(frozen=True)
class CommunityRevocation:
    """Immediate, irreversible revocation of a community grant."""

    grant_digest: str
    community_id: str
    revoked_at: int
    community_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    revocation_digest: str = ""
    schema_version: str = LANGUAGE_CAP_SCHEMA_VERSION


def _grant_payload(grant: CommunityGrant) -> dict[str, Any]:
    return {
        "grant_id": grant.grant_id,
        "community_id": grant.community_id,
        "data_scope": grant.data_scope,
        "purpose": grant.purpose,
        "granted_at": grant.granted_at,
        "expires_at": grant.expires_at,
        "community_pubkey_hex": grant.community_pubkey_hex,
        "prev_digest": grant.prev_digest,
        "schema_version": grant.schema_version,
    }


def compute_grant_digest(grant: CommunityGrant) -> str:
    """Recompute the JCS digest a grant claims."""
    return jcs_sha256_hex(_grant_payload(grant))


def grant_community_data(
    *,
    grant_id: str,
    community_id: str,
    data_scope: str,
    purpose: str,
    community_secret: bytes,
    granted_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> CommunityGrant:
    """Issue a community-signed data-sovereignty grant and seal it.

    The community's signing key is the trust anchor (honest boundary:
    key distribution is out of scope). ``expires_at <= granted_at``
    raises. The grant is purpose-bound at issuance; there is no
    wildcard purpose.
    """
    _check_secret(community_secret, "community_secret")
    grant_id = _check_nonempty_str(grant_id, "grant_id")
    community_id = _check_nonempty_str(community_id, "community_id")
    data_scope = _check_nonempty_str(data_scope, "data_scope")
    purpose = _check_nonempty_str(purpose, "purpose")
    granted_at = _check_ts(granted_at, "granted_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= granted_at:
        raise LanguageCapError("expires_at must be after granted_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise LanguageCapError("prev_digest must be a non-empty string")

    pubkey_hex = ed25519.public_key(community_secret).hex()
    bare = CommunityGrant(
        grant_id=grant_id,
        community_id=community_id,
        data_scope=data_scope,
        purpose=purpose,
        granted_at=granted_at,
        expires_at=expires_at,
        community_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,
        prev_digest=prev_digest,
    )
    signature_hex = ed25519.sign(
        community_secret, jcs_canonical_json(_grant_payload(bare))
    ).hex()
    sealed = CommunityGrant(**{**bare.__dict__, "signature_hex": signature_hex})
    return CommunityGrant(
        **{**sealed.__dict__, "grant_digest": compute_grant_digest(sealed)}
    )


def _revocation_payload(rev: CommunityRevocation) -> dict[str, Any]:
    return {
        "grant_digest": rev.grant_digest,
        "community_id": rev.community_id,
        "revoked_at": rev.revoked_at,
        "community_pubkey_hex": rev.community_pubkey_hex,
        "prev_digest": rev.prev_digest,
        "schema_version": rev.schema_version,
    }


def compute_revocation_digest(rev: CommunityRevocation) -> str:
    """Recompute the JCS digest a revocation claims."""
    return jcs_sha256_hex(_revocation_payload(rev))


def revoke_community_data(
    *,
    grant: CommunityGrant,
    community_secret: bytes,
    revoked_at: int,
    prev_digest: str,
) -> CommunityRevocation:
    """Revoke a community grant. Immediate and irreversible in the log.

    Only the community's own key can revoke (the pubkey must match the
    grant's); revoking someone else's grant raises.
    """
    _check_secret(community_secret, "community_secret")
    revoked_at = _check_ts(revoked_at, "revoked_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise LanguageCapError("prev_digest must be a non-empty string")
    pubkey_hex = ed25519.public_key(community_secret).hex()
    if not hmac.compare_digest(pubkey_hex, grant.community_pubkey_hex):
        raise LanguageCapError(
            "only the granting community's key may revoke its grant"
        )
    bare = CommunityRevocation(
        grant_digest=grant.grant_digest,
        community_id=grant.community_id,
        revoked_at=revoked_at,
        community_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,
        prev_digest=prev_digest,
    )
    signature_hex = ed25519.sign(
        community_secret, jcs_canonical_json(_revocation_payload(bare))
    ).hex()
    sealed = CommunityRevocation(
        **{**bare.__dict__, "signature_hex": signature_hex}
    )
    return CommunityRevocation(
        **{**sealed.__dict__, "revocation_digest": compute_revocation_digest(sealed)}
    )


def _verify_community_log(
    log: list[CommunityGrant | CommunityRevocation],
) -> None:
    """Raise :class:`LanguageCapError` if the community log is broken."""
    expected_prev = _GENESIS
    for entry in log:
        if isinstance(entry, CommunityGrant):
            digest = entry.grant_digest
            payload = _grant_payload(entry)
            recomputed = compute_grant_digest(entry)
            pubkey = entry.community_pubkey_hex
            sig = entry.signature_hex
            label = f"grant {entry.grant_id!r}"
        elif isinstance(entry, CommunityRevocation):
            digest = entry.revocation_digest
            payload = _revocation_payload(entry)
            recomputed = compute_revocation_digest(entry)
            pubkey = entry.community_pubkey_hex
            sig = entry.signature_hex
            label = "revocation"
        else:
            raise LanguageCapError("community log entry of unknown type")
        if not hmac.compare_digest(recomputed, digest):
            raise LanguageCapError(f"{label} digest does not recompute")
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise LanguageCapError(f"{label} chain break")
        try:
            sig_ok = ed25519.verify(
                bytes.fromhex(pubkey),
                jcs_canonical_json(payload),
                bytes.fromhex(sig),
            )
        except Exception:
            sig_ok = False
        if not sig_ok:
            raise LanguageCapError(f"{label} signature invalid")
        expected_prev = digest


@dataclass(frozen=True)
class CommunityVerdict:
    """Verdict of one community-data use."""

    allowed: bool
    reason: str
    grant_digest: str = ""


def check_community_use(
    grant: CommunityGrant,
    log: list[CommunityGrant | CommunityRevocation],
    *,
    data_scope: str,
    purpose: str,
    use_time: int,
) -> CommunityVerdict:
    """Check ONE community-data use against the community log. Fail-closed.

    Use-time semantics (105th batch): every use re-verifies, in order:

    1. Log integrity — digests recompute, single hash chain intact.
    2. The grant resolves in ``log`` (by digest) and is the sealed grant.
    3. Community signature verifies against the grant's community key.
    4. Scope and purpose match *exactly* — no wildcards.
    5. ``granted_at <= use_time <= expires_at``.
    6. No valid revocation for this grant with ``revoked_at <= use_time``.

    There is deliberately no "was once consented" shortcut.
    """
    data_scope = _check_nonempty_str(data_scope, "data_scope")
    purpose = _check_nonempty_str(purpose, "purpose")
    _check_ts(use_time, "use_time")

    def _deny(code: str, detail: str) -> CommunityVerdict:
        # Convention (scene_bound.py): the reason carries the
        # machine-readable denial code.
        return CommunityVerdict(
            allowed=False,
            reason=f"{code}: {detail}",
            grant_digest=grant.grant_digest,
        )

    # 1. Log integrity first.
    try:
        _verify_community_log(log)
    except LanguageCapError as error:
        return _deny(DENY_COMMUNITY_TAMPERED, f"community log integrity failure: {error}")

    # 2. The grant must resolve in the log.
    known = next(
        (
            g
            for g in log
            if isinstance(g, CommunityGrant)
            and hmac.compare_digest(g.grant_digest, grant.grant_digest)
        ),
        None,
    )
    if known is None:
        return _deny(DENY_COMMUNITY_NO_GRANT, "grant not present in the community log: unknown grant")
    if not hmac.compare_digest(compute_grant_digest(grant), grant.grant_digest):
        return _deny(DENY_COMMUNITY_TAMPERED, "grant digest does not recompute: tampered grant")

    # 3. Community signature over the canonical payload.
    try:
        sig_ok = ed25519.verify(
            bytes.fromhex(known.community_pubkey_hex),
            jcs_canonical_json(_grant_payload(known)),
            bytes.fromhex(known.signature_hex),
        )
    except Exception:
        sig_ok = False
    if not sig_ok:
        return _deny(DENY_COMMUNITY_TAMPERED, "community signature invalid: grant not from the community")

    # 4. Exact scope/purpose match.
    if data_scope != known.data_scope:
        return _deny(
            DENY_COMMUNITY_PURPOSE,
            f"scope mismatch: grant covers {known.data_scope!r}, "
            f"use requests {data_scope!r}",
        )
    if purpose != known.purpose:
        return _deny(
            DENY_COMMUNITY_PURPOSE,
            f"purpose mismatch: grant allows {known.purpose!r}, "
            f"use requests {purpose!r}",
        )

    # 5. Time window.
    if use_time < known.granted_at:
        return _deny(DENY_COMMUNITY_NO_GRANT, "use_time predates the grant")
    if use_time > known.expires_at:
        return _deny(
            DENY_COMMUNITY_EXPIRED, "grant expired: use_time is past expires_at"
        )

    # 6. Revocation as of use_time — immediate and visible.
    for entry in log:
        if not isinstance(entry, CommunityRevocation):
            continue
        if not hmac.compare_digest(entry.grant_digest, known.grant_digest):
            continue
        if entry.community_pubkey_hex != known.community_pubkey_hex:
            continue
        try:
            rev_ok = ed25519.verify(
                bytes.fromhex(entry.community_pubkey_hex),
                jcs_canonical_json(_revocation_payload(entry)),
                bytes.fromhex(entry.signature_hex),
            )
        except Exception:
            rev_ok = False
        if not rev_ok:
            continue
        if entry.revoked_at <= use_time:
            return _deny(
                DENY_COMMUNITY_REVOKED,
                f"community grant revoked at {entry.revoked_at}: revocation "
                "is immediate and irreversible in the log",
            )

    return CommunityVerdict(
        allowed=True,
        reason="use-time community check passed: chain intact, signature "
        "valid, scope/purpose match, within window, no revocation",
        grant_digest=known.grant_digest,
    )


def community_audit_event(
    verdict: CommunityVerdict, *, action: str
) -> dict[str, Any]:
    """Shape a community-use verdict as an audit-chain event dict."""
    return {
        "event": COMMUNITY_DENIED_EVENT if not verdict.allowed else COMMUNITY_GRANTED_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "grant_digest": verdict.grant_digest,
    }
