"""Quantum-threat timeline gates (one-hundred-second batch).

Absorbs the 2026 quantum thread:

* Google (2026-03, arXiv:2603.28846): ECDLP-256 needs <1,200 logical
  qubits (<500k physical), ~9 minutes. The compression came from
  algorithm/error-correction optimization, not hardware — the resource
  floor keeps dropping.
* Germany BSI TR-02102 (2026-02-11, official press release): classical
  asymmetric cryptography phases out by **end of 2031**; classical
  **signatures** by **end of 2035**; CRQC "at most 16 years" away.
* RFC 10024: TLS 1.3 hybrid key exchange (authentication/certificates
  still open).

Northstar signs with Ed25519 (vendored ``ed25519.py``) and hashes with
SHA-256 / HMAC-SHA256. This module does three things:

1. ``threat_assessment(as_of_date)`` — the current quantum-threat
   posture of every primitive in use, pinned to the BSI timeline.
2. ``gate_signing()`` — refuses to mint NEW long-lived credentials
   (expiry past 2031) with Ed25519 alone. Short-lived tokens and
   hash-only usage are unaffected. Every refusal/warning emits an
   audit event dict for ``audit.ndjson/1`` (feed into
   ``audit_chain.chain_record`` in order).
3. ``migration_plan()`` — a deterministic checklist: which module
   signs what, with which primitive, and the BSI deadline.

Fail-closed throughout: unknown primitives, malformed dates, and
credentials whose expiry cannot be determined are denied, never
allowed. Dates are ISO-8601 (``YYYY-MM-DD``) or epoch ints; anything
else is malformed.

Honest scope: this module is a *policy gate*, not a cryptanalysis
oracle. It encodes the BSI timeline as policy; it does not predict
CRQC arrival. The hybrid-signature hook (ML-DSA + Ed25519) is stubbed
as future work — calling it today fail-closes with "not implemented".
"""

from __future__ import annotations

import datetime as _datetime
from typing import Any

# ---------------------------------------------------------------------------
# Timeline constants — BSI TR-02102 (2026-02-11).
# ---------------------------------------------------------------------------

#: Classical asymmetric cryptography must be gone by end of 2031.
BSI_ASYMMETRIC_PHASEOUT = "2031-12-31"

#: Classical *signatures* must be gone by end of 2035.
BSI_SIGNATURE_PHASEOUT = "2035-12-31"

#: Postures returned by threat_assessment().
POSTURE_MIGRATE_BY_2031 = "migrate-by-2031"
POSTURE_REVIEW_2035 = "review-2035"
POSTURE_ACCEPTABLE = "acceptable"
POSTURE_UNKNOWN = "unknown-primitive"

#: Audit event names for audit.ndjson/1.
QUANTUM_TIMELINE_DENIED_EVENT = "quantum.timeline_denied"
QUANTUM_TIMELINE_WARNING_EVENT = "quantum.timeline_warning"

#: Primitives this repo actually uses (stdlib-only inventory).
_PRIMITIVE_POSTURES: dict[str, str] = {
    # Signatures — broken by CRQC (Shor). BSI: migrate by end of 2031.
    "Ed25519": POSTURE_MIGRATE_BY_2031,
    "EdDSA": POSTURE_MIGRATE_BY_2031,
    # Hashes — Grover halves effective strength; SHA-256 -> ~128-bit
    # post-quantum, still acceptable for integrity. BSI-adjacent review
    # horizon 2035 for signature-adjacent uses.
    "SHA-256": POSTURE_REVIEW_2035,
    "SHA-512": POSTURE_REVIEW_2035,
    # MACs — symmetric-key; Grover only. Acceptable indefinitely at
    # current key sizes.
    "HMAC-SHA256": POSTURE_ACCEPTABLE,
    "HMAC-SHA512": POSTURE_ACCEPTABLE,
}

#: Which primitives count as *signatures* for the gate (asymmetric,
#: Shor-vulnerable).
_SIGNATURE_PRIMITIVES = {"Ed25519", "EdDSA"}

#: Which primitives are hash/MAC-only (no asymmetric signing).
_NON_SIGNING_PRIMITIVES = {"SHA-256", "SHA-512", "HMAC-SHA256", "HMAC-SHA512"}

__all__ = [
    "BSI_ASYMMETRIC_PHASEOUT",
    "BSI_SIGNATURE_PHASEOUT",
    "POSTURE_MIGRATE_BY_2031",
    "POSTURE_REVIEW_2035",
    "POSTURE_ACCEPTABLE",
    "POSTURE_UNKNOWN",
    "QUANTUM_TIMELINE_DENIED_EVENT",
    "QUANTUM_TIMELINE_WARNING_EVENT",
    "QuantumTimelineError",
    "threat_assessment",
    "gate_signing",
    "migration_plan",
    "hybrid_sign",
    "timeline_denied_event",
    "timeline_warning_event",
    "parse_date",
]


class QuantumTimelineError(Exception):
    """Raised only for programmer errors (bad types); policy denials are
    returned as verdict dicts, never raised."""


# ---------------------------------------------------------------------------
# Date handling
# ---------------------------------------------------------------------------


def parse_date(value: Any) -> _datetime.date | None:
    """Parse an ISO-8601 date (``YYYY-MM-DD``) or epoch int/float to a
    date. Returns ``None`` for anything malformed — callers fail closed."""
    if isinstance(value, _datetime.date) and not isinstance(
        value, _datetime.datetime
    ):
        return value
    if isinstance(value, _datetime.datetime):
        return value.date()
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return _datetime.datetime.fromtimestamp(
                value, tz=_datetime.timezone.utc
            ).date()
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        # Accept a full ISO-8601 datetime too, keep the date part.
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                return _datetime.datetime.strptime(text[: len(fmt)], fmt).date()
            except ValueError:
                continue
        # Trailing "Z" or offset: strip and retry the date part.
        if len(text) >= 10:
            try:
                return _datetime.datetime.strptime(text[:10], "%Y-%m-%d").date()
            except ValueError:
                return None
        return None
    return None


# ---------------------------------------------------------------------------
# 1. Threat assessment
# ---------------------------------------------------------------------------


def threat_assessment(as_of_date: Any = None) -> dict[str, Any]:
    """Quantum-threat posture of every primitive in use, as of a date.

    ``as_of_date`` defaults to today (UTC). Returns::

        {
            "as_of": "YYYY-MM-DD",
            "primitives": {"Ed25519": "migrate-by-2031", ...},
            "overall": "migrate-by-2031",   # worst posture in use
            "bsi_asymmetric_phaseout": "2031-12-31",
            "bsi_signature_phaseout": "2035-12-31",
        }

    Postures: ``migrate-by-2031`` (Shor-vulnerable signatures),
    ``review-2035`` (hashes — Grover-halved but acceptable), ``acceptable``
    (symmetric MACs). Malformed dates fail closed to a denied assessment.
    """
    day = parse_date(as_of_date) if as_of_date is not None else _datetime.date.today()
    if day is None:
        return {
            "as_of": None,
            "primitives": {},
            "overall": POSTURE_UNKNOWN,
            "bsi_asymmetric_phaseout": BSI_ASYMMETRIC_PHASEOUT,
            "bsi_signature_phaseout": BSI_SIGNATURE_PHASEOUT,
            "error": "malformed as_of_date",
        }
    primitives = dict(_PRIMITIVE_POSTURES)
    order = {
        POSTURE_MIGRATE_BY_2031: 0,
        POSTURE_REVIEW_2035: 1,
        POSTURE_ACCEPTABLE: 2,
    }
    overall = min(primitives.values(), key=lambda p: order[p])
    return {
        "as_of": day.isoformat(),
        "primitives": primitives,
        "overall": overall,
        "bsi_asymmetric_phaseout": BSI_ASYMMETRIC_PHASEOUT,
        "bsi_signature_phaseout": BSI_SIGNATURE_PHASEOUT,
    }


# ---------------------------------------------------------------------------
# 2. Signing gate
# ---------------------------------------------------------------------------


def _norm_primitive(primitive: Any) -> str | None:
    if not isinstance(primitive, str):
        return None
    text = primitive.strip()
    # Canonicalize common spellings.
    aliases = {
        "ed25519": "Ed25519",
        "eddsa": "EdDSA",
        "sha256": "SHA-256",
        "sha-256": "SHA-256",
        "sha512": "SHA-512",
        "sha-512": "SHA-512",
        "hmac-sha256": "HMAC-SHA256",
        "hmac_sha256": "HMAC-SHA256",
        "hmac-sha512": "HMAC-SHA512",
        "hmac_sha512": "HMAC-SHA512",
    }
    key = text.lower().replace(" ", "")
    if key in aliases:
        return aliases[key]
    return text if text in _PRIMITIVE_POSTURES else None


def gate_signing(
    *,
    primitive: Any,
    expires_at: Any,
    issued_at: Any = None,
    credential_kind: str = "",
) -> dict[str, Any]:
    """Decide whether a NEW credential may be minted with ``primitive``.

    Policy (BSI TR-02102):

    * Unknown primitive or malformed/unparseable expiry -> **deny**
      (fail-closed).
    * Ed25519/EdDSA with expiry after 2031-12-31 -> **deny** —
      long-lived asymmetric credentials must not outlive the BSI
      phaseout. Refusal emits a ``quantum.timeline_denied`` audit event.
    * Ed25519/EdDSA with expiry within the phaseout window ->
      **allow with warning** (``quantum.timeline_warning`` event) —
      short-lived tokens are fine, but the migration clock is ticking.
    * Hash/MAC-only primitives -> **allow**, no warning (no asymmetric
      exposure).

    Returns ``{"verdict": "allow"|"deny"|"allow-with-warning", ...}``.
    Denials are returned, never raised.
    """
    prim = _norm_primitive(primitive)
    expiry = parse_date(expires_at)
    if prim is None:
        return {
            "verdict": "deny",
            "reason": f"unknown primitive: {primitive!r}",
            "event": timeline_denied_event(
                primitive=str(primitive),
                expires_at=str(expires_at),
                reason="unknown-primitive",
                credential_kind=credential_kind,
            ),
        }
    if expiry is None:
        return {
            "verdict": "deny",
            "reason": f"malformed or missing expiry: {expires_at!r}",
            "event": timeline_denied_event(
                primitive=prim,
                expires_at=str(expires_at),
                reason="malformed-expiry",
                credential_kind=credential_kind,
            ),
        }
    if issued_at is not None and parse_date(issued_at) is None:
        return {
            "verdict": "deny",
            "reason": f"malformed issued_at: {issued_at!r}",
            "event": timeline_denied_event(
                primitive=prim,
                expires_at=expiry.isoformat(),
                reason="malformed-issued-at",
                credential_kind=credential_kind,
            ),
        }
    if prim in _NON_SIGNING_PRIMITIVES:
        # Hash/MAC-only: no asymmetric exposure, no gate.
        return {
            "verdict": "allow",
            "reason": f"{prim} is hash/MAC-only; no quantum signing exposure",
            "event": None,
        }
    if prim in _SIGNATURE_PRIMITIVES:
        cutoff = _datetime.date(2031, 12, 31)
        if expiry > cutoff:
            return {
                "verdict": "deny",
                "reason": (
                    f"{prim} credential expiring {expiry.isoformat()} outlives "
                    f"the BSI TR-02102 asymmetric phaseout ({cutoff.isoformat()}); "
                    "mint short-lived credentials or migrate to post-quantum signatures"
                ),
                "event": timeline_denied_event(
                    primitive=prim,
                    expires_at=expiry.isoformat(),
                    reason="long-lived-asymmetric-credential",
                    credential_kind=credential_kind,
                ),
            }
        return {
            "verdict": "allow-with-warning",
            "reason": (
                f"{prim} credential expiring {expiry.isoformat()} is within the "
                "BSI phaseout window; allowed as short-lived, migration required by 2031"
            ),
            "event": timeline_warning_event(
                primitive=prim,
                expires_at=expiry.isoformat(),
                reason="short-lived-inside-phaseout-window",
                credential_kind=credential_kind,
            ),
        }
    # Known primitive but neither signing nor non-signing (should not
    # happen): fail closed.
    return {
        "verdict": "deny",
        "reason": f"primitive {prim} has no signing policy; fail-closed",
        "event": timeline_denied_event(
            primitive=prim,
            expires_at=expiry.isoformat(),
            reason="no-signing-policy",
            credential_kind=credential_kind,
        ),
    }


# ---------------------------------------------------------------------------
# 3. Migration plan
# ---------------------------------------------------------------------------

#: Deterministic inventory: (module, signs_what, primitive, deadline).
_SIGNING_INVENTORY: tuple[tuple[str, str, str, str], ...] = (
    (
        "passport",
        "capability passports (mint)",
        "Ed25519",
        BSI_ASYMMETRIC_PHASEOUT,
    ),
    (
        "offline_bundle",
        "offline policy bundles (compile_bundle)",
        "Ed25519",
        BSI_ASYMMETRIC_PHASEOUT,
    ),
    (
        "agent_identity",
        "DID identity + delegation credentials (issue)",
        "Ed25519",
        BSI_ASYMMETRIC_PHASEOUT,
    ),
    (
        "delegation_credentials",
        "delegation chain blocks (_sign_block / issue / seal)",
        "Ed25519",
        BSI_ASYMMETRIC_PHASEOUT,
    ),
    (
        "multisig",
        "m-of-n approval signatures (sign_call)",
        "Ed25519",
        BSI_ASYMMETRIC_PHASEOUT,
    ),
    (
        "audit_chain",
        "audit record signatures (sign_record)",
        "Ed25519",
        BSI_SIGNATURE_PHASEOUT,
    ),
    (
        "audit_scitt",
        "SCITT signed statements (build_signed_statement)",
        "Ed25519",
        BSI_SIGNATURE_PHASEOUT,
    ),
    (
        "audit_rekor",
        "transparency-log envelopes (build_envelope)",
        "Ed25519",
        BSI_SIGNATURE_PHASEOUT,
    ),
    (
        "audit_chain",
        "hash chain links (SHA-256)",
        "SHA-256",
        BSI_SIGNATURE_PHASEOUT,
    ),
    (
        "offline_bundle",
        "bundle integrity digests (HMAC-SHA256)",
        "HMAC-SHA256",
        "no deadline (symmetric)",
    ),
)


def migration_plan() -> list[dict[str, Any]]:
    """Deterministic migration checklist, ordered by deadline then module.

    Each entry: ``module``, ``signs_what``, ``primitive``, ``posture``,
    ``deadline``, ``action``. The audit-chain signature deadline is the
    later 2035 signature phaseout (long-lived evidence); short-lived
    credential minting follows the 2031 asymmetric phaseout.
    """
    rows: list[dict[str, Any]] = []
    for module, signs_what, primitive, deadline in _SIGNING_INVENTORY:
        posture = _PRIMITIVE_POSTURES.get(primitive, POSTURE_UNKNOWN)
        if posture == POSTURE_MIGRATE_BY_2031:
            action = (
                "migrate to ML-DSA (or hybrid ML-DSA+Ed25519) before "
                + deadline
                + "; gate_signing already refuses new long-lived mints"
            )
        elif posture == POSTURE_REVIEW_2035:
            action = (
                "review by " + deadline + "; no action required today "
                "(Grover-halved strength remains acceptable for integrity)"
            )
        else:
            action = "no action required (symmetric primitive)"
        rows.append(
            {
                "module": module,
                "signs_what": signs_what,
                "primitive": primitive,
                "posture": posture,
                "deadline": deadline,
                "action": action,
            }
        )
    rows.sort(key=lambda r: (r["deadline"], r["module"], r["signs_what"]))
    return rows


# ---------------------------------------------------------------------------
# 4. Hybrid-signature hook (future work — stubbed, fail-closed)
# ---------------------------------------------------------------------------


def hybrid_sign(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """ML-DSA + Ed25519 hybrid signing — NOT IMPLEMENTED.

    The interface is reserved here so the migration plan has a concrete
    landing point. Calling it today fail-closes: it returns a denial
    verdict instead of a signature, so no caller can mistake the stub
    for a working hybrid signer.
    """
    return {
        "verdict": "deny",
        "reason": (
            "hybrid_sign (ML-DSA+Ed25519) is not implemented; "
            "post-quantum migration is tracked in migration_plan()"
        ),
        "event": timeline_denied_event(
            primitive="ML-DSA+Ed25519",
            expires_at="",
            reason="hybrid-signer-not-implemented",
            credential_kind="hybrid",
        ),
    }


# ---------------------------------------------------------------------------
# 5. Audit events (feed into audit_chain.chain_record in order)
# ---------------------------------------------------------------------------


def timeline_denied_event(
    *,
    primitive: str,
    expires_at: str,
    reason: str,
    credential_kind: str = "",
) -> dict[str, Any]:
    """Audit record for a quantum-timeline signing refusal."""
    return {
        "event": QUANTUM_TIMELINE_DENIED_EVENT,
        "primitive": str(primitive or ""),
        "expires_at": str(expires_at or ""),
        "reason": str(reason or ""),
        "credential_kind": str(credential_kind or ""),
    }


def timeline_warning_event(
    *,
    primitive: str,
    expires_at: str,
    reason: str,
    credential_kind: str = "",
) -> dict[str, Any]:
    """Audit record for a quantum-timeline signing warning (allowed)."""
    return {
        "event": QUANTUM_TIMELINE_WARNING_EVENT,
        "primitive": str(primitive or ""),
        "expires_at": str(expires_at or ""),
        "reason": str(reason or ""),
        "credential_kind": str(credential_kind or ""),
    }
