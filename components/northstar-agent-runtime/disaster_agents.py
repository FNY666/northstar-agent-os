"""Emergency-response discipline receipts (one-hundred-thirty-seventh batch).

Absorbs the 2026 AI-disaster research thread (mechanism ideas only,
honestly scoped):

* **AI on 911:** New Orleans became the first major US city to put
  AI on 911 (Carbyne, constrained activation, ~$600K/year, "zero
  false positives" — unaudited); Fort Worth's AI assistant handles
  26% of non-emergency calls; Las Vegas does real-time 50+ language
  translation in under 2 seconds. Seattle ran Corti AI listening on
  all 911 medical calls for 2+ years with callers unaware and no
  surveillance-ordinance review (exposed 2026-06-14, Seattle
  Times). Triage activation without a bound authority receipt is
  ungoverned delegation; undisclosed AI involvement is surveillance
  by another name.
* **Early warning at scale:** Google Flood Hub (150 countries),
  FireSat, Android earthquake network (95+ countries), WeatherNext;
  China's "Ma Zu" system operating in 7 countries, expanding to 30
  in 5 years; Mexico Cell Broadcast expanding 2026-Q4 to
  hurricane/flood/volcano/landslide; Germany KIRa-Berg (60-minute
  lead time); Korea edge-AI CCTV offline warnings. Warning systems
  now ship AI-generated content through broadcast channels — the
  failure modes are version chaos and "sent but never received".
* **False alarms and rumor:** Brazil 2026's nationwide false alert
  fired into the middle of a World Cup broadcast; Nextdoor
  AI-generated fake fire/shooting alerts; Cal Fire's chatbot served
  6-day-stale evacuation information; AI wildfire rumor photos and
  forged evacuation orders circulated in 2026. A warning that
  references a superseded version is not a warning — it is a
  rumor with letterhead.
* **Equity as a gate:** Pano AI at $50K/camera/year means coverage
  is priced — deployments that only protect the wealthy are a
  design choice, not an accident. RAND: AI detects but does not
  recommend action; Teodoro/UNDRR: evacuation orders must be
  human-signed.

Northstar mapping:

* ``triage_activation_receipt()`` — AI triage activation binds an
  authority-signed receipt; unbound AI diverting emergency calls is
  ``disaster:unauthorized_triage`` (Carbyne constrained-activation
  lesson).
* ``ai_involvement_disclosure()`` — AI involvement in call triage
  must be disclosed to the caller via a bound receipt; undisclosed
  involvement is ``disaster:hidden_ai`` (Seattle Corti lesson).
* ``WarningVersionChain`` — warnings ride a hash-chained version
  history; referencing a superseded version is NON_AUTHORITATIVE
  (``disaster:superseded_warning``, Cal Fire stale-info lesson).
* ``false_alarm_budget()`` — false-alarm rate budgets are pinned
  per channel; exceeding the budget auto-degrades the channel to
  human confirmation (``disaster:false_alarm_budget_exceeded``,
  Brazil lesson).
* ``equity_probe()`` — deployments bind a coverage-representativeness
  receipt; failing the equity floor refuses go-live
  (``disaster:equity_gap``, Pano AI lesson).
* ``last_mile_receipt()`` — warnings bind delivery evidence;
  broadcast-only warnings without bound delivery evidence are
  NON_AUTHORITATIVE (``disaster:no_delivery_evidence``).
* ``human_final_decision()`` — evacuation orders bind a human
  countersignature; AI-generated orders without one are
  ``disaster:ai_evacuation`` (Teodoro/UNDRR lesson).
* ``misinfo_marker_probe()`` — AI emergency notifications carry a
  machine-readable source marker; unmarked notices are
  ``disaster:unmarked_notice`` (fake-evacuation-order lesson).

Honest boundary: receipts bind *declared* response discipline.
They do not stop disasters, make warnings true, or reach the
unreachable — they make the declared discipline machine-checkable
and make violations undeniable.

Deterministic: no wall-clock reads (callers inject ``*_at`` /
``now`` as integer unix epochs), canonical JCS hashing,
constant-time digest comparisons.
"""

from __future__ import annotations
from _domain_base import DomainError

import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

try:
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(payload: Mapping[str, Any]) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def jcs_sha256_hex(payload: Mapping[str, Any]) -> str:  # type: ignore[no-redef]
        import hashlib

        return hashlib.sha256(jcs_canonical_json(payload)).hexdigest()

from ed25519 import sign as ed_sign
from ed25519 import verify as ed_verify

DISASTER_SCHEMA_VERSION = "northstar.disaster-agents.v1"

#: Denial reason codes. All start with the ``disaster:`` prefix so
#: audit consumers can filter the family.
DENY_UNAUTHORIZED_TRIAGE = "disaster:unauthorized_triage"
DENY_HIDDEN_AI = "disaster:hidden_ai"
DENY_SUPERSEDED_WARNING = "disaster:superseded_warning"
DENY_UNKNOWN_WARNING_VERSION = "disaster:unknown_warning_version"
DENY_FALSE_ALARM_OVER_BUDGET = "disaster:false_alarm_budget_exceeded"
DENY_NO_ALARM_BUDGET = "disaster:no_alarm_budget"
DENY_EQUITY_GAP = "disaster:equity_gap"
DENY_STALE_EQUITY_MEASUREMENT = "disaster:stale_equity_measurement"
DENY_NO_DELIVERY_EVIDENCE = "disaster:no_delivery_evidence"
DENY_AI_EVACUATION = "disaster:ai_evacuation"
DENY_ORDER_EXPIRED = "disaster:order_expired"
DENY_UNMARKED_NOTICE = "disaster:unmarked_notice"
DENY_MARKER_MISMATCH = "disaster:marker_mismatch"
DENY_CHAIN_BREAK = "disaster:chain_break"
DENY_DIGEST_MISMATCH = "disaster:digest_mismatch"
DENY_SIGNATURE_INVALID = "disaster:signature_invalid"
DENY_REVOKED = "disaster:revoked"

#: Classifications.
CLASS_ALLOW = "allow"
CLASS_DENY = "deny"
CLASS_NON_AUTHORITATIVE = "NON_AUTHORITATIVE"

#: Audit event names (shaped to feed ``audit_chain.chain_record`` /
#: the 113th-batch incident-receipts event chain).
TRIAGE_EVENT = "disaster.triage_checked"
DISCLOSURE_EVENT = "disaster.disclosure_checked"
WARNING_VERSION_EVENT = "disaster.warning_version_checked"
ALARM_BUDGET_EVENT = "disaster.alarm_budget_checked"
EQUITY_EVENT = "disaster.equity_probed"
DELIVERY_EVENT = "disaster.delivery_checked"
EVACUATION_EVENT = "disaster.evacuation_checked"
MARKER_EVENT = "disaster.marker_probed"

#: Genesis prev digest for hash-chained receipt logs.
_GENESIS = "genesis"

#: Equity measurements older than this are stale — a coverage map
#: from last year is not a coverage guarantee today.
EQUITY_FRESHNESS_S = 31_536_000

#: Closed vocabulary of emergency channels AI triage may be
#: activated on. Anything outside this list is unclassifiable and
#: refuses activation — new channels are added by declaring them,
#: never by free-text.
TRIAGE_CHANNELS: tuple[str, ...] = (
    "voice_911",
    "voice_112",
    "text_911",
    "non_emergency_line",
    "crisis_text_line",
)

#: Closed vocabulary of AI involvement modalities a disclosure may
#: declare.
DISCLOSURE_MODALITIES: tuple[str, ...] = (
    "triage_routing",
    "live_transcription",
    "realtime_translation",
    "medical_protocol_assist",
    "call_summarization",
)

#: Closed vocabulary of warning channels a false-alarm budget may
#: be pinned to.
ALARM_CHANNELS: tuple[str, ...] = (
    "cell_broadcast",
    "siren_system",
    "push_alert",
    "tv_radio_interrupt",
    "social_platform",
)


class DisasterError(DomainError):
    """A malformed receipt, registry, or check request — a programming
    error, not a verdict. Verification *failures* (unbound triage,
    hidden AI, superseded warnings, budget breaches, equity gaps,
    missing delivery evidence, AI-only evacuation orders, unmarked
    notices) return a :class:`DisasterVerdict` with
    ``allowed=False`` instead; malformed input raises here, fail
    loud, never guess."""


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex64(value):
        raise DisasterError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DisasterError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise DisasterError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed.
    if not isinstance(value, bytes) or len(value) != 32:
        raise DisasterError(f"{field_name} must be a 32-byte seed")
    return value


def _check_pubkey_hex(value: Any, field_name: str) -> str:
    return _check_hex64(value, field_name)


def _check_nonneg_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise DisasterError(f"{field_name} must be a non-negative int")
    return value


def _check_pos_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise DisasterError(f"{field_name} must be a positive int")
    return value


def _check_bps(value: Any, field_name: str) -> int:
    # Basis points: 0..10000.
    if not isinstance(value, int) or isinstance(value, bool) or not (0 <= value <= 10000):
        raise DisasterError(f"{field_name} must be an int in basis points (0..10000)")
    return value


def _verify_signature(
    pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str
) -> bool:
    try:
        return bool(
            ed_verify(
                bytes.fromhex(pubkey_hex),
                jcs_canonical_json(payload),
                bytes.fromhex(signature_hex),
            )
        )
    except Exception:
        return False


def _seal_receipt(
    payload: Mapping[str, Any], authority_secret: bytes
) -> tuple[str, str]:
    """Return ``(receipt_digest, signature_hex)`` for a payload.

    The receipt digest is the JCS-SHA256 of the unsigned payload;
    the signature is over the canonical JSON of the payload.
    """
    digest = jcs_sha256_hex(payload)
    signature = ed_sign(authority_secret, jcs_canonical_json(payload)).hex()
    return digest, signature


@dataclass(frozen=True)
class DisasterVerdict:
    """The verdict of a disaster-discipline gate."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt: Any = None
    audit_event: dict[str, Any] = field(default_factory=dict)


def disaster_audit_event(
    *,
    action: str,
    allowed: bool,
    reason: str,
    created_unix: int,
    **details: Any,
) -> dict[str, Any]:
    """Build an audit event shaped to feed the incident-receipts
    event chain (113th batch)."""
    _check_nonempty_str(action, "action")
    _check_ts(created_unix, "created_unix")
    return {
        "event": action,
        "allowed": allowed,
        "reason": reason,
        "created_unix": created_unix,
        **details,
    }


def _fail(
    reason: str,
    *,
    classification: str = CLASS_DENY,
    receipt: Any = None,
    action: str = "",
    created_unix: int = 0,
    **details: Any,
) -> DisasterVerdict:
    event = (
        disaster_audit_event(
            action=action, allowed=False, reason=reason,
            created_unix=created_unix, **details,
        )
        if action
        else {}
    )
    return DisasterVerdict(
        allowed=False,
        reason=reason,
        classification=classification,
        receipt=receipt,
        audit_event=event,
    )


def _ok(
    reason: str,
    *,
    receipt: Any = None,
    action: str = "",
    created_unix: int = 0,
    **details: Any,
) -> DisasterVerdict:
    event = (
        disaster_audit_event(
            action=action, allowed=True, reason=reason,
            created_unix=created_unix, **details,
        )
        if action
        else {}
    )
    return DisasterVerdict(
        allowed=True,
        reason=reason,
        classification=CLASS_ALLOW,
        receipt=receipt,
        audit_event=event,
    )


def _validate_receipt(
    receipt: Any,
    expected_head: str,
    type_name: str,
) -> None:
    """Raise :class:`DisasterError` if a receipt does not recompute,
    breaks the chain, or carries an invalid authority signature.
    Used by registries on ingest — tampered history fails loud."""
    if not hmac.compare_digest(receipt.receipt_digest, jcs_sha256_hex(receipt._payload())):
        raise DisasterError(
            f"{type_name} receipt {receipt.receipt_id!r} digest does not recompute"
        )
    if not hmac.compare_digest(receipt.prev_digest, expected_head):
        raise DisasterError(
            f"{type_name} receipt {receipt.receipt_id!r} chain break: "
            f"expected prev {expected_head!r}"
        )
    if not _verify_signature(
        receipt.authority_pubkey_hex, receipt._payload(), receipt.signature_hex
    ):
        raise DisasterError(
            f"{type_name} receipt {receipt.receipt_id!r} authority signature invalid"
        )


# ---------------------------------------------------------------------------
# AI triage activation receipts (anti ungoverned 911 delegation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TriageActivationReceipt:
    """An authority-signed AI-triage activation pin.

    Binds ``(deployment_id, channel, activation_digest, issued_at,
    ttl_s)`` so a call diverted to AI triage can prove the
    activation it ran under was live and scoped. The activation
    policy itself lives out-of-band; the receipt pins its digest
    so "AI answers 911" is never an accident of configuration.
    """

    receipt_id: str
    deployment_id: str
    channel: str
    activation_digest: str
    issued_at: int
    ttl_s: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = DISASTER_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "deployment_id": self.deployment_id,
            "channel": self.channel,
            "activation_digest": self.activation_digest,
            "issued_at": self.issued_at,
            "ttl_s": self.ttl_s,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def triage_activation_receipt(
    *,
    receipt_id: str,
    deployment_id: str,
    channel: str,
    activation_digest: str,
    issued_at: int,
    ttl_s: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> TriageActivationReceipt:
    """Issue an AI-triage activation pin. The channel must come from
    the closed vocabulary; the digest binds the activation policy."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(deployment_id, "deployment_id")
    if channel not in TRIAGE_CHANNELS:
        raise DisasterError(
            f"channel must be one of {TRIAGE_CHANNELS}, got {channel!r}"
        )
    _check_hex64(activation_digest, "activation_digest")
    _check_ts(issued_at, "issued_at")
    _check_pos_int(ttl_s, "ttl_s")
    _check_nonempty_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    if prev_digest != _GENESIS:
        _check_hex64(prev_digest, "prev_digest")
    receipt = TriageActivationReceipt(
        receipt_id=receipt_id,
        deployment_id=deployment_id,
        channel=channel,
        activation_digest=activation_digest,
        issued_at=issued_at,
        ttl_s=ttl_s,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        prev_digest=prev_digest,
    )
    digest, signature = _seal_receipt(receipt._payload(), authority_secret)
    return TriageActivationReceipt(
        **{**receipt.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


class TriageRegistry:
    """Owns AI-triage activation pins and revocations.

    A call may be diverted to AI triage only while a live,
    non-revoked activation pin covers ``(deployment_id, channel)``.
    Unbound triage is ``disaster:unauthorized_triage`` — fail-closed,
    because an emergency call has no "undo".
    """

    def __init__(self) -> None:
        self._log: list[TriageActivationReceipt] = []
        self._head: str = _GENESIS
        self._by_deployment: dict[str, TriageActivationReceipt] = {}
        self._revoked: set[str] = set()

    def register(self, receipt: TriageActivationReceipt) -> TriageActivationReceipt:
        """Register an activation pin. The log must stay
        hash-chained; re-registering a deployment supersedes its
        previous pin."""
        _validate_receipt(receipt, self._head, "triage")
        self._log.append(receipt)
        self._head = receipt.receipt_digest
        self._by_deployment[receipt.deployment_id] = receipt
        return receipt

    def revoke(self, deployment_id: str) -> None:
        """Revoke a deployment's triage activation. Revocation is
        immediate and sticky — a new pin must be registered to
        re-enable."""
        _check_nonempty_str(deployment_id, "deployment_id")
        self._revoked.add(deployment_id)

    def check_activation(
        self, *, deployment_id: str, channel: str, now: int
    ) -> DisasterVerdict:
        """Check whether AI triage may divert a call right now."""
        _check_nonempty_str(deployment_id, "deployment_id")
        _check_nonempty_str(channel, "channel")
        _check_ts(now, "now")
        receipt = self._by_deployment.get(deployment_id)
        if receipt is None or receipt.channel != channel:
            return _fail(
                DENY_UNAUTHORIZED_TRIAGE,
                receipt=receipt,
                action=TRIAGE_EVENT,
                created_unix=now,
                deployment_id=deployment_id,
                channel=channel,
            )
        if deployment_id in self._revoked:
            return _fail(
                DENY_REVOKED,
                receipt=receipt,
                action=TRIAGE_EVENT,
                created_unix=now,
                deployment_id=deployment_id,
                channel=channel,
            )
        if now >= receipt.issued_at + receipt.ttl_s:
            return _fail(
                DENY_UNAUTHORIZED_TRIAGE,
                receipt=receipt,
                action=TRIAGE_EVENT,
                created_unix=now,
                deployment_id=deployment_id,
                channel=channel,
            )
        return _ok(
            "triage activation live",
            receipt=receipt,
            action=TRIAGE_EVENT,
            created_unix=now,
            deployment_id=deployment_id,
            channel=channel,
        )


# ---------------------------------------------------------------------------
# AI-involvement disclosure (anti secret listening)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DisclosureReceipt:
    """A bound disclosure that AI is involved in a call session.

    Binds ``(session_id, deployment_id, modality, disclosed_at,
    ttl_s)``. The Seattle Corti lesson: callers have a right to know
    AI is listening; a disclosure that exists only in a privacy
    policy is not a disclosure.
    """

    receipt_id: str
    session_id: str
    deployment_id: str
    modality: str
    disclosed_at: int
    ttl_s: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = DISASTER_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "session_id": self.session_id,
            "deployment_id": self.deployment_id,
            "modality": self.modality,
            "disclosed_at": self.disclosed_at,
            "ttl_s": self.ttl_s,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "schema_version": self.schema_version,
        }


def ai_involvement_disclosure(
    *,
    receipt_id: str,
    session_id: str,
    deployment_id: str,
    modality: str,
    disclosed_at: int,
    ttl_s: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> DisclosureReceipt:
    """Issue an AI-involvement disclosure for a call session. The
    modality must come from the closed vocabulary."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(session_id, "session_id")
    _check_nonempty_str(deployment_id, "deployment_id")
    if modality not in DISCLOSURE_MODALITIES:
        raise DisasterError(
            f"modality must be one of {DISCLOSURE_MODALITIES}, got {modality!r}"
        )
    _check_ts(disclosed_at, "disclosed_at")
    _check_pos_int(ttl_s, "ttl_s")
    _check_nonempty_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    receipt = DisclosureReceipt(
        receipt_id=receipt_id,
        session_id=session_id,
        deployment_id=deployment_id,
        modality=modality,
        disclosed_at=disclosed_at,
        ttl_s=ttl_s,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
    )
    digest, signature = _seal_receipt(receipt._payload(), authority_secret)
    return DisclosureReceipt(
        **{**receipt.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


class DisclosureRegistry:
    """Owns AI-involvement disclosures per call session.

    A session processed by AI without a live disclosure is
    ``disaster:hidden_ai``. Expired disclosures count as undisclosed
    — "we told them last year" is not disclosure.
    """

    def __init__(self) -> None:
        self._by_session: dict[str, DisclosureReceipt] = {}

    def register(self, receipt: DisclosureReceipt) -> DisclosureReceipt:
        """Register a disclosure. Digest must recompute and the
        authority signature must verify."""
        if not hmac.compare_digest(
            receipt.receipt_digest, jcs_sha256_hex(receipt._payload())
        ):
            raise DisasterError(
                f"disclosure receipt {receipt.receipt_id!r} digest does not recompute"
            )
        if not _verify_signature(
            receipt.authority_pubkey_hex, receipt._payload(), receipt.signature_hex
        ):
            raise DisasterError(
                f"disclosure receipt {receipt.receipt_id!r} authority signature invalid"
            )
        self._by_session[receipt.session_id] = receipt
        return receipt

    def check_disclosure(self, *, session_id: str, now: int) -> DisasterVerdict:
        """Check whether AI involvement in a session was disclosed."""
        _check_nonempty_str(session_id, "session_id")
        _check_ts(now, "now")
        receipt = self._by_session.get(session_id)
        if receipt is None or now >= receipt.disclosed_at + receipt.ttl_s:
            return _fail(
                DENY_HIDDEN_AI,
                receipt=receipt,
                action=DISCLOSURE_EVENT,
                created_unix=now,
                session_id=session_id,
            )
        return _ok(
            "AI involvement disclosed",
            receipt=receipt,
            action=DISCLOSURE_EVENT,
            created_unix=now,
            session_id=session_id,
            modality=receipt.modality,
        )


# ---------------------------------------------------------------------------
# Warning version chains (anti stale warnings)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WarningVersion:
    """One version of a warning, hash-chained to its predecessor.

    Binds ``(warning_id, version, content_digest, issued_at)``.
    Only the head of the chain is authoritative; anything else is a
    rumor with letterhead. The warning content lives out-of-band;
    the chain pins its digests so chronology cannot be lost.
    """

    version_id: str
    warning_id: str
    version: int
    content_digest: str
    issued_at: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = DISASTER_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "version_id": self.version_id,
            "warning_id": self.warning_id,
            "version": self.version,
            "content_digest": self.content_digest,
            "issued_at": self.issued_at,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def warning_version(
    *,
    version_id: str,
    warning_id: str,
    version: int,
    content_digest: str,
    issued_at: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> WarningVersion:
    """Issue a warning version. Versions must increase; the chain
    must stay unbroken."""
    _check_nonempty_str(version_id, "version_id")
    _check_nonempty_str(warning_id, "warning_id")
    _check_pos_int(version, "version")
    _check_hex64(content_digest, "content_digest")
    _check_ts(issued_at, "issued_at")
    _check_nonempty_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    if prev_digest != _GENESIS:
        _check_hex64(prev_digest, "prev_digest")
    entry = WarningVersion(
        version_id=version_id,
        warning_id=warning_id,
        version=version,
        content_digest=content_digest,
        issued_at=issued_at,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        prev_digest=prev_digest,
    )
    digest, signature = _seal_receipt(entry._payload(), authority_secret)
    return WarningVersion(
        **{**entry.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


class WarningVersionChain:
    """Hash-chained version history per warning id.

    Referencing the head is authoritative. Referencing a
    superseded version is NON_AUTHORITATIVE
    (``disaster:superseded_warning``) — acting on it is acting on a
    rumor. Referencing an unknown digest is a hard deny
    (``disaster:unknown_warning_version``).
    """

    def __init__(self) -> None:
        self._heads: dict[str, WarningVersion] = {}
        self._by_digest: dict[str, WarningVersion] = {}

    def publish(self, entry: WarningVersion) -> WarningVersion:
        """Publish a new warning version. The chain must stay
        unbroken and versions must increase."""
        head = self._heads.get(entry.warning_id)
        expected_prev = head.receipt_digest if head else _GENESIS
        _validate_receipt(entry, expected_prev, "warning-version")
        if head is not None:
            if entry.version <= head.version:
                raise DisasterError(
                    f"warning {entry.warning_id!r} version must increase "
                    f"(head v{head.version}, got v{entry.version})"
                )
            if entry.issued_at < head.issued_at:
                raise DisasterError(
                    f"warning {entry.warning_id!r} issued_at moved backwards"
                )
        self._heads[entry.warning_id] = entry
        self._by_digest[entry.receipt_digest] = entry
        return entry

    def check_reference(self, *, version_digest: str, now: int) -> DisasterVerdict:
        """Check whether a reference to a warning version is
        authoritative."""
        _check_hex64(version_digest, "version_digest")
        _check_ts(now, "now")
        entry = self._by_digest.get(version_digest)
        if entry is None:
            return _fail(
                DENY_UNKNOWN_WARNING_VERSION,
                classification=CLASS_DENY,
                action=WARNING_VERSION_EVENT,
                created_unix=now,
                version_digest=version_digest,
            )
        head = self._heads[entry.warning_id]
        if not hmac.compare_digest(head.receipt_digest, version_digest):
            return _fail(
                DENY_SUPERSEDED_WARNING,
                classification=CLASS_NON_AUTHORITATIVE,
                receipt=entry,
                action=WARNING_VERSION_EVENT,
                created_unix=now,
                warning_id=entry.warning_id,
                referenced_version=entry.version,
                head_version=head.version,
            )
        return _ok(
            "warning version is current",
            receipt=entry,
            action=WARNING_VERSION_EVENT,
            created_unix=now,
            warning_id=entry.warning_id,
            version=entry.version,
        )


# ---------------------------------------------------------------------------
# False-alarm budgets (anti alert fatigue)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlarmBudgetReceipt:
    """A pinned false-alarm rate budget for a warning channel.

    Binds ``(channel_id, max_false_alarm_bps, window_s, issued_at)``.
    Rates are in basis points per window so the budget is
    machine-comparable. Exceeding the budget does not silence the
    channel — it degrades it to human confirmation.
    """

    receipt_id: str
    channel_id: str
    max_false_alarm_bps: int
    window_s: int
    issued_at: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = DISASTER_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "channel_id": self.channel_id,
            "max_false_alarm_bps": self.max_false_alarm_bps,
            "window_s": self.window_s,
            "issued_at": self.issued_at,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "schema_version": self.schema_version,
        }


def false_alarm_budget(
    *,
    receipt_id: str,
    channel_id: str,
    max_false_alarm_bps: int,
    window_s: int,
    issued_at: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> AlarmBudgetReceipt:
    """Pin a false-alarm budget for a warning channel. The channel
    must come from the closed vocabulary."""
    _check_nonempty_str(receipt_id, "receipt_id")
    if channel_id not in ALARM_CHANNELS:
        raise DisasterError(
            f"channel_id must be one of {ALARM_CHANNELS}, got {channel_id!r}"
        )
    _check_bps(max_false_alarm_bps, "max_false_alarm_bps")
    _check_pos_int(window_s, "window_s")
    _check_ts(issued_at, "issued_at")
    _check_nonempty_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    receipt = AlarmBudgetReceipt(
        receipt_id=receipt_id,
        channel_id=channel_id,
        max_false_alarm_bps=max_false_alarm_bps,
        window_s=window_s,
        issued_at=issued_at,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
    )
    digest, signature = _seal_receipt(receipt._payload(), authority_secret)
    return AlarmBudgetReceipt(
        **{**receipt.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


class AlarmBudgetRegistry:
    """Owns false-alarm budgets per warning channel.

    A channel with no live budget cannot be judged, so it fails
    closed (``disaster:no_alarm_budget``). A channel over budget is
    degraded to human confirmation — ``allowed=False`` with
    ``NON_AUTHORITATIVE`` classification, never silent.
    """

    def __init__(self) -> None:
        self._by_channel: dict[str, AlarmBudgetReceipt] = {}

    def register(self, receipt: AlarmBudgetReceipt) -> AlarmBudgetReceipt:
        """Register a budget. Digest must recompute and the
        authority signature must verify."""
        if not hmac.compare_digest(
            receipt.receipt_digest, jcs_sha256_hex(receipt._payload())
        ):
            raise DisasterError(
                f"alarm-budget receipt {receipt.receipt_id!r} digest does not recompute"
            )
        if not _verify_signature(
            receipt.authority_pubkey_hex, receipt._payload(), receipt.signature_hex
        ):
            raise DisasterError(
                f"alarm-budget receipt {receipt.receipt_id!r} authority signature invalid"
            )
        self._by_channel[receipt.channel_id] = receipt
        return receipt

    def check_rate(
        self, *, channel_id: str, observed_false_alarm_bps: int, now: int
    ) -> DisasterVerdict:
        """Check an observed false-alarm rate against the pinned
        budget."""
        _check_nonempty_str(channel_id, "channel_id")
        _check_bps(observed_false_alarm_bps, "observed_false_alarm_bps")
        _check_ts(now, "now")
        receipt = self._by_channel.get(channel_id)
        if receipt is None:
            return _fail(
                DENY_NO_ALARM_BUDGET,
                action=ALARM_BUDGET_EVENT,
                created_unix=now,
                channel_id=channel_id,
            )
        if observed_false_alarm_bps > receipt.max_false_alarm_bps:
            return _fail(
                DENY_FALSE_ALARM_OVER_BUDGET,
                classification=CLASS_NON_AUTHORITATIVE,
                receipt=receipt,
                action=ALARM_BUDGET_EVENT,
                created_unix=now,
                channel_id=channel_id,
                observed_bps=observed_false_alarm_bps,
                budget_bps=receipt.max_false_alarm_bps,
            )
        return _ok(
            "false-alarm rate within budget",
            receipt=receipt,
            action=ALARM_BUDGET_EVENT,
            created_unix=now,
            channel_id=channel_id,
            observed_bps=observed_false_alarm_bps,
        )


# ---------------------------------------------------------------------------
# Equity probes (anti priced coverage)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EquityReceipt:
    """A coverage-representativeness receipt for a deployment.

    Binds ``(deployment_id, coverage_bps, min_required_bps,
    measured_at, protocol_digest)``. Coverage is the share of the
    served population with effective warning coverage, in basis
    points, measured under a pinned protocol. The protocol digest
    keeps "we measured something" from passing as a measurement.
    """

    receipt_id: str
    deployment_id: str
    coverage_bps: int
    min_required_bps: int
    measured_at: int
    protocol_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = DISASTER_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "deployment_id": self.deployment_id,
            "coverage_bps": self.coverage_bps,
            "min_required_bps": self.min_required_bps,
            "measured_at": self.measured_at,
            "protocol_digest": self.protocol_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "schema_version": self.schema_version,
        }


def equity_receipt(
    *,
    receipt_id: str,
    deployment_id: str,
    coverage_bps: int,
    min_required_bps: int,
    measured_at: int,
    protocol_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> EquityReceipt:
    """Issue a coverage-representativeness receipt."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(deployment_id, "deployment_id")
    _check_bps(coverage_bps, "coverage_bps")
    _check_bps(min_required_bps, "min_required_bps")
    _check_ts(measured_at, "measured_at")
    _check_hex64(protocol_digest, "protocol_digest")
    _check_nonempty_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    receipt = EquityReceipt(
        receipt_id=receipt_id,
        deployment_id=deployment_id,
        coverage_bps=coverage_bps,
        min_required_bps=min_required_bps,
        measured_at=measured_at,
        protocol_digest=protocol_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
    )
    digest, signature = _seal_receipt(receipt._payload(), authority_secret)
    return EquityReceipt(
        **{**receipt.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


def equity_probe(receipt: EquityReceipt, *, now: int) -> DisasterVerdict:
    """Probe a deployment's coverage receipt against its equity
    floor. Tampered receipts fail closed; stale measurements are
    NON_AUTHORITATIVE; coverage below the floor refuses go-live."""
    _check_ts(now, "now")
    if not isinstance(receipt, EquityReceipt):
        raise DisasterError("receipt must be an EquityReceipt")
    if not hmac.compare_digest(
        receipt.receipt_digest, jcs_sha256_hex(receipt._payload())
    ):
        return _fail(
            DENY_DIGEST_MISMATCH,
            action=EQUITY_EVENT,
            created_unix=now,
            deployment_id=receipt.deployment_id,
        )
    if not _verify_signature(
        receipt.authority_pubkey_hex, receipt._payload(), receipt.signature_hex
    ):
        return _fail(
            DENY_SIGNATURE_INVALID,
            action=EQUITY_EVENT,
            created_unix=now,
            deployment_id=receipt.deployment_id,
        )
    if now - receipt.measured_at > EQUITY_FRESHNESS_S:
        return _fail(
            DENY_STALE_EQUITY_MEASUREMENT,
            classification=CLASS_NON_AUTHORITATIVE,
            receipt=receipt,
            action=EQUITY_EVENT,
            created_unix=now,
            deployment_id=receipt.deployment_id,
        )
    if receipt.coverage_bps < receipt.min_required_bps:
        return _fail(
            DENY_EQUITY_GAP,
            receipt=receipt,
            action=EQUITY_EVENT,
            created_unix=now,
            deployment_id=receipt.deployment_id,
            coverage_bps=receipt.coverage_bps,
            min_required_bps=receipt.min_required_bps,
        )
    return _ok(
        "coverage meets equity floor",
        receipt=receipt,
        action=EQUITY_EVENT,
        created_unix=now,
        deployment_id=receipt.deployment_id,
        coverage_bps=receipt.coverage_bps,
    )


# ---------------------------------------------------------------------------
# Last-mile delivery receipts (anti sent-but-never-received)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeliveryReceipt:
    """Delivery evidence bound to a warning version.

    Binds ``(warning_version_digest, delivery_proof_digest,
    delivered_at, reach_count, channel_id)``. A warning that was
    broadcast but never proven delivered is an announcement, not a
    warning — NON_AUTHORITATIVE until delivery is evidenced.
    """

    receipt_id: str
    warning_version_digest: str
    delivery_proof_digest: str
    delivered_at: int
    reach_count: int
    channel_id: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = DISASTER_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "warning_version_digest": self.warning_version_digest,
            "delivery_proof_digest": self.delivery_proof_digest,
            "delivered_at": self.delivered_at,
            "reach_count": self.reach_count,
            "channel_id": self.channel_id,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "schema_version": self.schema_version,
        }


def last_mile_receipt(
    *,
    receipt_id: str,
    warning_version_digest: str,
    delivery_proof_digest: str,
    delivered_at: int,
    reach_count: int,
    channel_id: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> DeliveryReceipt:
    """Issue delivery evidence for a warning version."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_hex64(warning_version_digest, "warning_version_digest")
    _check_hex64(delivery_proof_digest, "delivery_proof_digest")
    _check_ts(delivered_at, "delivered_at")
    _check_nonneg_int(reach_count, "reach_count")
    if channel_id not in ALARM_CHANNELS:
        raise DisasterError(
            f"channel_id must be one of {ALARM_CHANNELS}, got {channel_id!r}"
        )
    _check_nonempty_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    receipt = DeliveryReceipt(
        receipt_id=receipt_id,
        warning_version_digest=warning_version_digest,
        delivery_proof_digest=delivery_proof_digest,
        delivered_at=delivered_at,
        reach_count=reach_count,
        channel_id=channel_id,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
    )
    digest, signature = _seal_receipt(receipt._payload(), authority_secret)
    return DeliveryReceipt(
        **{**receipt.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


class DeliveryRegistry:
    """Owns delivery evidence per warning version.

    A warning version with live, valid delivery evidence is
    authoritative. Without it, the warning is NON_AUTHORITATIVE
    (``disaster:no_delivery_evidence``) — sent is not delivered.
    """

    def __init__(self) -> None:
        self._by_version: dict[str, DeliveryReceipt] = {}

    def register(self, receipt: DeliveryReceipt) -> DeliveryReceipt:
        """Register delivery evidence. Digest must recompute and the
        authority signature must verify."""
        if not hmac.compare_digest(
            receipt.receipt_digest, jcs_sha256_hex(receipt._payload())
        ):
            raise DisasterError(
                f"delivery receipt {receipt.receipt_id!r} digest does not recompute"
            )
        if not _verify_signature(
            receipt.authority_pubkey_hex, receipt._payload(), receipt.signature_hex
        ):
            raise DisasterError(
                f"delivery receipt {receipt.receipt_id!r} authority signature invalid"
            )
        self._by_version[receipt.warning_version_digest] = receipt
        return receipt

    def check_authority(self, *, warning_version_digest: str, now: int) -> DisasterVerdict:
        """Check whether a warning version carries bound delivery
        evidence."""
        _check_hex64(warning_version_digest, "warning_version_digest")
        _check_ts(now, "now")
        receipt = self._by_version.get(warning_version_digest)
        if receipt is None:
            return _fail(
                DENY_NO_DELIVERY_EVIDENCE,
                classification=CLASS_NON_AUTHORITATIVE,
                action=DELIVERY_EVENT,
                created_unix=now,
                warning_version_digest=warning_version_digest,
            )
        return _ok(
            "delivery evidenced",
            receipt=receipt,
            action=DELIVERY_EVENT,
            created_unix=now,
            warning_version_digest=warning_version_digest,
            reach_count=receipt.reach_count,
        )


# ---------------------------------------------------------------------------
# Human final decisions (anti AI-signed evacuation orders)
# ---------------------------------------------------------------------------


def _countersign_payload(
    *,
    order_id: str,
    order_digest: str,
    zone: str,
    issued_at: int,
    expires_at: int,
    human_signer: str,
) -> dict[str, Any]:
    return {
        "order_id": order_id,
        "order_digest": order_digest,
        "zone": zone,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "human_signer": human_signer,
        "purpose": "disaster.evacuation_countersign",
    }


@dataclass(frozen=True)
class EvacuationOrder:
    """An evacuation order with a bound human countersignature.

    The authority signs the order form; a named human signs the
    countersign payload. An order the machine signed alone is not
    an order — it is a suggestion with sirens.
    """

    order_id: str
    order_digest: str
    zone: str
    issued_at: int
    expires_at: int
    issued_by: str
    human_signer: str
    human_pubkey_hex: str
    human_signature_hex: str
    authority_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = DISASTER_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "order_id": self.order_id,
            "order_digest": self.order_digest,
            "zone": self.zone,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "issued_by": self.issued_by,
            "human_signer": self.human_signer,
            "human_pubkey_hex": self.human_pubkey_hex,
            "human_signature_hex": self.human_signature_hex,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "schema_version": self.schema_version,
        }


def human_final_decision(
    *,
    order_id: str,
    order_digest: str,
    zone: str,
    issued_at: int,
    expires_at: int,
    issued_by: str,
    human_signer: str,
    human_pubkey_hex: str,
    human_secret: bytes,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> EvacuationOrder:
    """Issue an evacuation order with a human countersignature.
    Both keys must sign — the authority for the form, the human for
    the decision."""
    _check_nonempty_str(order_id, "order_id")
    _check_hex64(order_digest, "order_digest")
    _check_nonempty_str(zone, "zone")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise DisasterError("expires_at must be after issued_at")
    _check_nonempty_str(issued_by, "issued_by")
    _check_nonempty_str(human_signer, "human_signer")
    _check_pubkey_hex(human_pubkey_hex, "human_pubkey_hex")
    _check_secret(human_secret, "human_secret")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    countersign = _countersign_payload(
        order_id=order_id,
        order_digest=order_digest,
        zone=zone,
        issued_at=issued_at,
        expires_at=expires_at,
        human_signer=human_signer,
    )
    human_signature_hex = ed_sign(human_secret, jcs_canonical_json(countersign)).hex()
    order = EvacuationOrder(
        order_id=order_id,
        order_digest=order_digest,
        zone=zone,
        issued_at=issued_at,
        expires_at=expires_at,
        issued_by=issued_by,
        human_signer=human_signer,
        human_pubkey_hex=human_pubkey_hex,
        human_signature_hex=human_signature_hex,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
    )
    digest, signature = _seal_receipt(order._payload(), authority_secret)
    return EvacuationOrder(
        **{**order.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


def check_evacuation_order(order: EvacuationOrder, *, now: int) -> DisasterVerdict:
    """Check an evacuation order: authority form signature, human
    countersignature, and freshness must all hold. An order the
    machine signed alone is ``disaster:ai_evacuation``."""
    if not isinstance(order, EvacuationOrder):
        raise DisasterError("order must be an EvacuationOrder")
    _check_ts(now, "now")
    if not hmac.compare_digest(order.receipt_digest, jcs_sha256_hex(order._payload())):
        return _fail(
            DENY_DIGEST_MISMATCH,
            action=EVACUATION_EVENT,
            created_unix=now,
            order_id=order.order_id,
        )
    if not _verify_signature(
        order.authority_pubkey_hex, order._payload(), order.signature_hex
    ):
        return _fail(
            DENY_SIGNATURE_INVALID,
            action=EVACUATION_EVENT,
            created_unix=now,
            order_id=order.order_id,
        )
    if not order.human_signature_hex:
        return _fail(
            DENY_AI_EVACUATION,
            receipt=order,
            action=EVACUATION_EVENT,
            created_unix=now,
            order_id=order.order_id,
            zone=order.zone,
        )
    countersign = _countersign_payload(
        order_id=order.order_id,
        order_digest=order.order_digest,
        zone=order.zone,
        issued_at=order.issued_at,
        expires_at=order.expires_at,
        human_signer=order.human_signer,
    )
    if not _verify_signature(
        order.human_pubkey_hex, countersign, order.human_signature_hex
    ):
        return _fail(
            DENY_SIGNATURE_INVALID,
            action=EVACUATION_EVENT,
            created_unix=now,
            order_id=order.order_id,
        )
    if now >= order.expires_at:
        return _fail(
            DENY_ORDER_EXPIRED,
            receipt=order,
            action=EVACUATION_EVENT,
            created_unix=now,
            order_id=order.order_id,
        )
    return _ok(
        "evacuation order human-countersigned and fresh",
        receipt=order,
        action=EVACUATION_EVENT,
        created_unix=now,
        order_id=order.order_id,
        human_signer=order.human_signer,
    )


# ---------------------------------------------------------------------------
# Misinfo marker probes (anti forged emergency notices)
# ---------------------------------------------------------------------------


def _marker_payload(
    *,
    notice_digest: str,
    originator: str,
    channel: str,
    created_unix: int,
) -> dict[str, Any]:
    return {
        "notice_digest": notice_digest,
        "originator": originator,
        "channel": channel,
        "created_unix": created_unix,
        "purpose": "disaster.source_marker",
    }


def misinfo_marker_probe(notification: Mapping[str, Any]) -> DisasterVerdict:
    """Probe an AI emergency notification for its machine-readable
    source marker. The marker binds ``(notice_digest, originator,
    channel, created_unix)`` under an authority signature. Missing
    markers are ``disaster:unmarked_notice``; mismatched or invalid
    markers are ``disaster:marker_mismatch``. A notice without a
    marker is indistinguishable from a forgery — treated as one."""
    if not isinstance(notification, Mapping):
        raise DisasterError("notification must be a mapping")
    notice_id = notification.get("notice_id")
    originator = notification.get("originator")
    channel = notification.get("channel")
    created_unix = notification.get("created_unix")
    notice_digest = notification.get("notice_digest")
    if not isinstance(notice_id, str) or not notice_id.strip():
        raise DisasterError("notification.notice_id must be a non-empty string")
    if not isinstance(originator, str) or not originator.strip():
        raise DisasterError("notification.originator must be a non-empty string")
    if not isinstance(channel, str) or not channel.strip():
        raise DisasterError("notification.channel must be a non-empty string")
    if not isinstance(created_unix, int) or isinstance(created_unix, bool) or created_unix < 0:
        raise DisasterError("notification.created_unix must be a non-negative int epoch")
    if not _is_hex64(notice_digest):
        raise DisasterError("notification.notice_digest must be a 64-char lowercase hex digest")
    marker = notification.get("source_marker")
    if marker is None:
        return _fail(
            DENY_UNMARKED_NOTICE,
            action=MARKER_EVENT,
            created_unix=created_unix,
            notice_id=notice_id,
            originator=originator,
        )
    if not isinstance(marker, Mapping):
        raise DisasterError("notification.source_marker must be a mapping")
    marker_digest = marker.get("digest")
    marker_pubkey = marker.get("pubkey_hex")
    marker_sig = marker.get("signature_hex")
    if not _is_hex64(marker_digest) or not _is_hex64(marker_pubkey) or not isinstance(
        marker_sig, str
    ):
        return _fail(
            DENY_MARKER_MISMATCH,
            action=MARKER_EVENT,
            created_unix=created_unix,
            notice_id=notice_id,
            originator=originator,
        )
    expected = jcs_sha256_hex(
        _marker_payload(
            notice_digest=notice_digest,
            originator=originator,
            channel=channel,
            created_unix=created_unix,
        )
    )
    if not hmac.compare_digest(marker_digest, expected):
        return _fail(
            DENY_MARKER_MISMATCH,
            action=MARKER_EVENT,
            created_unix=created_unix,
            notice_id=notice_id,
            originator=originator,
        )
    if not _verify_signature(
        marker_pubkey,
        _marker_payload(
            notice_digest=notice_digest,
            originator=originator,
            channel=channel,
            created_unix=created_unix,
        ),
        marker_sig,
    ):
        return _fail(
            DENY_MARKER_MISMATCH,
            action=MARKER_EVENT,
            created_unix=created_unix,
            notice_id=notice_id,
            originator=originator,
        )
    return _ok(
        "source marker bound and valid",
        action=MARKER_EVENT,
        created_unix=created_unix,
        notice_id=notice_id,
        originator=originator,
    )
