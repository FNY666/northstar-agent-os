"""Government-service AI discipline (one-hundred-forty-seventh batch).

Absorbs the 2026 AI-in-public-administration thread, where the same
pattern repeats across jurisdictions: the state digitizes the front
door, an AI agent starts standing in it, and the disciplines that
keep it from quietly becoming the decider are human finality,
measured exclusion, a non-digital door, pinned discretion, minimal
identity, registered agents, scrutiny after urgency, and
appeal-before-suspension.

The absorbed record (sample-limited, non-en sources noted):

* **Hong Kong** (2026-10 five-year plan 2026-2030): AI into public
  administration plus *mandatory* cross-department data sharing;
  iAM Smart past 1,400 services with an AI assistant by end-2026;
  CorpID digital business identity end-2026, all business services
  by 2028.
* **UK**: Digital Access to Services Bill (2026-05), voluntary
  digital ID; the 2025 mandatory-ID plan was dropped after a
  2.98M-signature petition — confirmed not mandatory 2026-09.
* **EU EUDI Wallet**: statutory 2026-12-24, one wallet per country;
  reality is Denmark's AltID live 2026-06-03 while Germany announced
  2027-01-02 — the deadline is missed, not moved.
* **Japan**: 104M My Number cards, AI-agent-ified admin services;
  Tokyo App 6.4M downloads, AI push H2 2026.
* **Germany**: SAP x OpenAI 2026 into administration; Bavaria's
  2026-06 law allows AI in *discretionary* administrative acts (the
  first in Germany — the discretion boundary is exactly what
  :func:`discretion_pin` pins); Muenster council resolution: final
  decision responsibility always rests with a human.
* **Korea**: AI national secretary (Naver/Kakao in-app government
  services, 2026 pilot), mobile ID full coverage 2026-01, AI
  Government24 Dec 2026.
* **Mexico "Cero oficios"**: Llave MX unified digital identity;
  **Buenos Aires Province Decreto 742/2026**: AI is a tool,
  decisions are made by civil servants.
* **China SAMR 2026-06**: AI agents forced into a unified digital
  identity national standard — the :class:`AgentIdentityRegistry`
  binding.
* **New Zealand**: the welfare automated-decision expansion bill
  passed 2026-06 *under urgency* — auto-review and auto-suspend of
  benefits; called "the widest expansion in a generation", the
  government says "absolutely not Robodebt". Two lessons in one:
  urgency-passed automation expansions need a scrutiny clock, and
  Robodebt's lesson stands anyway — suspension binds the review
  notice and the appeal chain, never the reverse.
* **Aadhaar exclusion**: Right to Food survey counted 57
  starvation deaths, 19 directly linked; a 6.5% authentication
  failure rate means tens of millions denied monthly, and the
  least able to appeal are the most denied. The lesson for
  :func:`exclusion_monitor` is blunt: **measure exclusion, not just
  success** — a service dashboard that only tracks success rate is
  an instrument that cannot see its own harm.

The fail-closed discipline in this module:

1. **Adverse decisions are AI-prohibited.** A benefit denial,
   suspension, or sanction whose record lacks a valid human
   signature is ``govservices.ai_denial`` — the AI recommends,
   a human decides (NZ / BsAs / Muenster lesson).
2. **Exclusion is measured as a first-class signal.**
   :func:`exclusion_monitor` denies when the authentication
   failure rate exceeds tolerance (Aadhaar lesson).
3. **No digital-only service.** A service that binds no
   non-digital channel denies with ``govservices.digital_only``.
4. **Discretion is pinned.** AI acting beyond the pinned
   discretionary boundary denies with
   ``govservices.discretion_breach`` (Bavaria lesson).
5. **Identity is minimal.** Disclosure beyond the pinned needed
   fields denies with ``govservices.identity_overreach``.
6. **Agents are registered.** An AI agent acting in government
   services without a registered identity denies with
   ``govservices.unregistered_agent`` (China SAMR lesson).
7. **Urgency gets a scrutiny clock.** An urgency-passed
   automation expansion without a scrutiny receipt by the
   deadline denies with ``govservices.scrutiny_overdue``
   (NZ lesson).
8. **Appeal precedes suspension.** A suspension attempted before
   the appeal deadline with the appeal pending denies with
   ``govservices.suspension_before_appeal`` (Robodebt lesson).
9. **Fraud flags are leads, never accusations.** A flag treated
   as a determination denies with ``govservices.flag_fraud``.

Honest scoping: receipts bind the *declared* service discipline —
digests recompute, signatures verify against registered keys,
chains are visible. They do not fix exclusion; they make it
auditable. A signed receipt never proves the human *read* the
case, and an exclusion probe never captures the person who never
reached the probe. Service design is outside this module's scope.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th batch pattern), digest
comparisons via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


GOVSERVICES_SCHEMA_VERSION = "northstar.govservices_agents.v1"

#: Binary tiers (87th-batch style): a verdict is either authoritative
#: or it is not; the non-authoritative side names a deny code.
AUTHORITATIVE = "authoritative"
NON_AUTHORITATIVE = "non-authoritative"

#: Closed vocabulary of decision kinds this module governs.
DECISION_KINDS: tuple[str, ...] = (
    "benefit_grant",
    "benefit_denial",
    "benefit_suspension",
    "sanction",
    "eligibility_determination",
    "service_grant",
)

#: Adverse kinds: AI may never be the decider of these.
ADVERSE_DECISION_KINDS: tuple[str, ...] = (
    "benefit_denial",
    "benefit_suspension",
    "sanction",
)

#: Closed vocabulary of channels a service may declare.
CHANNEL_KINDS: tuple[str, ...] = (
    "self_service_web",
    "mobile_app",
    "kiosk",
    "in_person",
    "phone",
    "paper_mail",
    "assisted_digital",
)

#: Channels that are not digital self-service: a service that binds
#: none of these is digital-only.
NON_DIGITAL_CHANNELS: tuple[str, ...] = (
    "in_person",
    "phone",
    "paper_mail",
    "assisted_digital",
)

#: Closed vocabulary of AI roles inside a discretionary act.
AI_ROLES: tuple[str, ...] = (
    "advisory_only",
    "decision_support",
    "none",
)

#: Closed vocabulary of personal-data fields an identity pin may name.
IDENTITY_FIELDS: tuple[str, ...] = (
    "name",
    "date_of_birth",
    "address",
    "national_id_number",
    "business_registration",
    "contact",
    "photo",
    "biometric",
)

#: Closed vocabulary of appeal states for a benefit review notice.
APPEAL_STATES: tuple[str, ...] = (
    "pending",
    "resolved_upheld",
    "resolved_overturned",
    "none_filed_expired",
)

DENY_AI_DENIAL = "govservices.ai_denial"
DENY_EXCLUSION_GAP = "govservices.exclusion_gap"
DENY_DIGITAL_ONLY = "govservices.digital_only"
DENY_DISCRETION_BREACH = "govservices.discretion_breach"
DENY_IDENTITY_OVERREACH = "govservices.identity_overreach"
DENY_UNREGISTERED_AGENT = "govservices.unregistered_agent"
DENY_SCRUTINY_OVERDUE = "govservices.scrutiny_overdue"
DENY_SUSPENSION_BEFORE_APPEAL = "govservices.suspension_before_appeal"
DENY_FLAG_FRAUD = "govservices.flag_fraud"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class GovServicesError(ValueError):
    """A malformed receipt/record or a programming error.

    Raised for structural problems (bad digests, unknown vocabulary,
    empty measurement windows). Verification *failures* (an
    unsigned adverse decision, an over-tolerance exclusion probe, an
    unregistered agent) return a verdict with ``allowed=False`` — a
    failed discipline check is a verdict, a malformed record is a
    bug.
    """


# ---------------------------------------------------------------------------
# Field validators
# ---------------------------------------------------------------------------


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovServicesError(f"{field_name} must be a non-empty string")
    return value


def _check_hex64(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != _HEX64_LENGTH:
        raise GovServicesError(f"{field_name} must be a 64-char hex digest")
    try:
        int(value, 16)
    except ValueError:
        raise GovServicesError(f"{field_name} must be a 64-char hex digest") from None
    return value.lower()


def _check_hex128(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != _HEX128_LENGTH:
        raise GovServicesError(f"{field_name} must be a 128-char hex value")
    try:
        int(value, 16)
    except ValueError:
        raise GovServicesError(f"{field_name} must be a 128-char hex value") from None
    return value.lower()


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GovServicesError(f"{field_name} must be a non-negative integer epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise GovServicesError(f"{field_name}: Ed25519 secret key must be 32 bytes")
    return bytes(value)


def _check_pubkey_hex(value: Any, field_name: str) -> str:
    return _check_hex64(value, field_name)


def _check_sig_hex(value: Any, field_name: str) -> str:
    return _check_hex128(value, field_name)


def _check_bps(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 10_000:
        raise GovServicesError(f"{field_name} must be an integer basis-points value in [0, 10000]")
    return value


def _verify_sig(pubkey_hex: str, message: bytes, sig_hex: str) -> bool:
    # NOTE: the vendored ed25519.verify() returns a bool and never
    # raises (97th-batch module). The return value MUST be used:
    # a bare `ed25519.verify(...); return True` inside try/except
    # would bless every tampered signature. (This bug exists in the
    # older permit_agents/consent_receipts/legal_agents pattern —
    # flagged to the parent for a separate fix batch.)
    try:
        return bool(
            ed25519.verify(
                bytes.fromhex(pubkey_hex),
                message,
                bytes.fromhex(sig_hex),
            )
        )
    except Exception:
        return False


def _seal(payload: dict[str, Any], secret: bytes) -> tuple[str, str]:
    """Sign a JCS-canonical payload; return (signature_hex, receipt_digest)."""
    message = jcs_canonical_json(payload)
    sig = ed25519.sign(secret, message).hex()
    digest = jcs_sha256_hex({"payload": payload, "signature_hex": sig})
    return sig, digest


@dataclass(frozen=True)
class GateVerdict:
    """Binary verdict for a govservices discipline check."""

    allowed: bool
    tier: str
    reason: str = ""
    deny_code: str = ""


# ---------------------------------------------------------------------------
# Gate 1: human final gate (benefit denials/sanctions)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DecisionRecord:
    """A government-service decision record.

    The AI's contribution is ``ai_recommendation_digest`` — evidence,
    never a decision. An adverse decision must carry a valid human
    signature; :func:`human_final_gate` refuses to bless an
    unsigned one.
    """

    decision_id: str
    decision_kind: str
    beneficiary_ref_digest: str
    ai_recommendation_digest: str
    decided_at: int
    human_signer_id: str = ""
    human_pubkey_hex: str = ""
    human_signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = GOVSERVICES_SCHEMA_VERSION


def _decision_payload(r: DecisionRecord) -> dict[str, Any]:
    return {
        "decision_id": r.decision_id,
        "decision_kind": r.decision_kind,
        "beneficiary_ref_digest": r.beneficiary_ref_digest,
        "ai_recommendation_digest": r.ai_recommendation_digest,
        "decided_at": r.decided_at,
        "human_signer_id": r.human_signer_id,
        "human_pubkey_hex": r.human_pubkey_hex,
        "schema_version": r.schema_version,
    }


def issue_decision_record(
    *,
    decision_id: str,
    decision_kind: str,
    beneficiary_ref_digest: str,
    ai_recommendation_digest: str,
    decided_at: int,
    human_signer_id: str = "",
    human_secret: bytes | None = None,
    human_pubkey: bytes | None = None,
) -> DecisionRecord:
    """Issue a decision record. Fail-closed at issuance: an adverse
    kind issued without a human signer stays *unsigned* (empty
    signature fields) so :func:`human_final_gate` can refuse it.
    A human signer must supply both the id and the key pair."""
    if decision_kind not in DECISION_KINDS:
        raise GovServicesError(
            f"decision_kind must be one of {list(DECISION_KINDS)}; "
            "the AI may not invent new decision kinds"
        )
    decision_id = _check_nonempty_str(decision_id, "decision_id")
    beneficiary_ref_digest = _check_hex64(beneficiary_ref_digest, "beneficiary_ref_digest")
    ai_recommendation_digest = _check_hex64(ai_recommendation_digest, "ai_recommendation_digest")
    decided_at = _check_ts(decided_at, "decided_at")

    signed = human_signer_id.strip() != ""
    if signed and (human_secret is None or human_pubkey is None):
        raise GovServicesError("a named human signer must supply the key pair")
    if not signed and (human_secret is not None or human_pubkey is not None):
        raise GovServicesError("key material without a human signer id is refused")

    record = DecisionRecord(
        decision_id=decision_id,
        decision_kind=decision_kind,
        beneficiary_ref_digest=beneficiary_ref_digest,
        ai_recommendation_digest=ai_recommendation_digest,
        decided_at=decided_at,
        human_signer_id=human_signer_id.strip(),
        human_pubkey_hex=human_pubkey.hex() if signed else "",
    )
    if not signed:
        return record
    sig, digest = _seal(
        _decision_payload(record),
        _check_secret(human_secret, "human_secret"),
    )
    return DecisionRecord(
        **{**record.__dict__, "human_signature_hex": sig, "receipt_digest": digest}
    )


def human_final_gate(record: DecisionRecord) -> GateVerdict:
    """Adverse decisions require a human signature.

    A benefit denial, suspension, or sanction with no signature — or
    a signature that does not verify — denies with
    ``govservices.ai_denial``: the decision is an AI-only denial
    and has no legal effect. Non-adverse kinds are
    AUTHORITATIVE as records regardless of signature (the AI's
    recommendation digest stays on the record for audit).
    """
    if record.decision_kind not in ADVERSE_DECISION_KINDS:
        return GateVerdict(True, AUTHORITATIVE,
                           reason="non-adverse kind: AI recommendation on record, no signature required")
    if not record.human_signature_hex or not record.human_pubkey_hex:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="adverse decision with no human signature",
                           deny_code=DENY_AI_DENIAL)
    if not _verify_sig(
        record.human_pubkey_hex,
        jcs_canonical_json(_decision_payload(record)),
        record.human_signature_hex,
    ):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="human signature does not verify",
                           deny_code=DENY_AI_DENIAL)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="adverse decision countersigned by a human")


# ---------------------------------------------------------------------------
# Gate 2: exclusion monitor (Aadhaar lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExclusionProbe:
    """A measured authentication-failure window for a service.

    The failure rate is computed in basis points against
    ``attempts_total`` — the point is to *measure* exclusion, not to
    celebrate the complement. An empty measurement window is a
    programming error: a probe that cannot see anyone measures
    nothing.
    """

    probe_id: str
    service_id: str
    attempts_total: int
    auth_failures: int
    tolerance_bps: int
    window_start: int
    window_end: int
    issuer_id: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = GOVSERVICES_SCHEMA_VERSION


def _exclusion_payload(r: ExclusionProbe) -> dict[str, Any]:
    return {
        "probe_id": r.probe_id,
        "service_id": r.service_id,
        "attempts_total": r.attempts_total,
        "auth_failures": r.auth_failures,
        "tolerance_bps": r.tolerance_bps,
        "window_start": r.window_start,
        "window_end": r.window_end,
        "issuer_id": r.issuer_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def issue_exclusion_probe(
    *,
    probe_id: str,
    service_id: str,
    attempts_total: int,
    auth_failures: int,
    tolerance_bps: int,
    window_start: int,
    window_end: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> ExclusionProbe:
    probe_id = _check_nonempty_str(probe_id, "probe_id")
    service_id = _check_nonempty_str(service_id, "service_id")
    if not isinstance(attempts_total, int) or isinstance(attempts_total, bool) or attempts_total < 0:
        raise GovServicesError("attempts_total must be a non-negative int")
    if not isinstance(auth_failures, int) or isinstance(auth_failures, bool) or auth_failures < 0:
        raise GovServicesError("auth_failures must be a non-negative int")
    if attempts_total == 0:
        raise GovServicesError("attempts_total == 0: the probe would measure nothing")
    if auth_failures > attempts_total:
        raise GovServicesError("auth_failures cannot exceed attempts_total")
    tolerance_bps = _check_bps(tolerance_bps, "tolerance_bps")
    window_start = _check_ts(window_start, "window_start")
    window_end = _check_ts(window_end, "window_end")
    if window_end <= window_start:
        raise GovServicesError("window_end must be after window_start")
    issuer_id = _check_nonempty_str(issuer_id, "issuer_id")
    secret = _check_secret(issuer_secret, "issuer_secret")

    pubkey_hex = ed25519.public_key(secret).hex()
    probe = ExclusionProbe(
        probe_id=probe_id,
        service_id=service_id,
        attempts_total=attempts_total,
        auth_failures=auth_failures,
        tolerance_bps=tolerance_bps,
        window_start=window_start,
        window_end=window_end,
        issuer_id=issuer_id,
        issuer_pubkey_hex=pubkey_hex,
        signature_hex="",
    )
    sig, digest = _seal(_exclusion_payload(probe), secret)
    return ExclusionProbe(
        **{**probe.__dict__, "signature_hex": sig, "receipt_digest": digest}
    )


def exclusion_monitor(probe: ExclusionProbe) -> GateVerdict:
    """Fail-closed exclusion probe: the failure rate is computed from
    the signed record, not re-reported by the service. Above
    tolerance the service's exclusion gap is AUTHORITATIVE as a
    *finding* — the verdict denies the claim that the service is
    safe to expand, with ``govservices.exclusion_gap``."""
    if not _verify_sig(
        probe.issuer_pubkey_hex,
        jcs_canonical_json(_exclusion_payload(probe)),
        probe.signature_hex,
    ):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="exclusion probe signature does not verify",
                           deny_code=DENY_EXCLUSION_GAP)
    rate_bps = probe.auth_failures * 10_000 // probe.attempts_total
    if rate_bps > probe.tolerance_bps:
        return GateVerdict(
            False, NON_AUTHORITATIVE,
            reason=(f"auth failure rate {rate_bps} bps over {probe.attempts_total} attempts "
                    f"exceeds tolerance {probe.tolerance_bps} bps"),
            deny_code=DENY_EXCLUSION_GAP,
        )
    return GateVerdict(True, AUTHORITATIVE,
                       reason=f"auth failure rate {rate_bps} bps within tolerance {probe.tolerance_bps} bps")


# ---------------------------------------------------------------------------
# Gate 3: alternative channel receipt (no digital-only)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChannelReceipt:
    """Declared service channels. ``non_digital_channel`` is computed
    at issuance — the receipt cannot claim a paper/in-person door it
    does not list."""

    receipt_id: str
    service_id: str
    channels: tuple[str, ...]
    non_digital_channel: bool
    declared_at: int
    issuer_id: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = GOVSERVICES_SCHEMA_VERSION


def _channel_payload(r: ChannelReceipt) -> dict[str, Any]:
    return {
        "receipt_id": r.receipt_id,
        "service_id": r.service_id,
        "channels": list(r.channels),
        "non_digital_channel": r.non_digital_channel,
        "declared_at": r.declared_at,
        "issuer_id": r.issuer_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def alternative_channel_receipt(
    *,
    receipt_id: str,
    service_id: str,
    channels: tuple[str, ...] | list[str],
    declared_at: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> ChannelReceipt:
    """Issue the channel declaration for a service. Fail-closed: an
    empty channel list is a programming error, and channels outside
    the closed vocabulary are refused."""
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    service_id = _check_nonempty_str(service_id, "service_id")
    if not isinstance(channels, (tuple, list)) or not channels:
        raise GovServicesError("channels must be a non-empty tuple/list")
    seen: list[str] = []
    for ch in channels:
        if ch not in CHANNEL_KINDS:
            raise GovServicesError(
                f"channel {ch!r} not in closed vocabulary {list(CHANNEL_KINDS)}"
            )
        if ch not in seen:
            seen.append(ch)
    declared_at = _check_ts(declared_at, "declared_at")
    issuer_id = _check_nonempty_str(issuer_id, "issuer_id")
    secret = _check_secret(issuer_secret, "issuer_secret")

    pubkey_hex = ed25519.public_key(secret).hex()
    receipt = ChannelReceipt(
        receipt_id=receipt_id,
        service_id=service_id,
        channels=tuple(seen),
        non_digital_channel=any(c in NON_DIGITAL_CHANNELS for c in seen),
        declared_at=declared_at,
        issuer_id=issuer_id,
        issuer_pubkey_hex=pubkey_hex,
        signature_hex="",
    )
    sig, digest = _seal(_channel_payload(receipt), secret)
    return ChannelReceipt(
        **{**receipt.__dict__, "signature_hex": sig, "receipt_digest": digest}
    )


def digital_only_gate(receipt: ChannelReceipt) -> GateVerdict:
    """A service with no non-digital channel denies with
    ``govservices.digital_only`` — the UK petition lesson: a
    digital door is an offer, a digital-only door is an
    exclusion."""
    if not _verify_sig(
        receipt.issuer_pubkey_hex,
        jcs_canonical_json(_channel_payload(receipt)),
        receipt.signature_hex,
    ):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="channel receipt signature does not verify",
                           deny_code=DENY_DIGITAL_ONLY)
    if not receipt.non_digital_channel:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason=f"service {receipt.service_id} is digital-only",
                           deny_code=DENY_DIGITAL_ONLY)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="non-digital channel bound")


# ---------------------------------------------------------------------------
# Gate 4: discretion pin (Bavaria lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DiscretionPin:
    """A pinned discretionary boundary for one administrative act.

    ``ai_role`` names the *only* role the AI may take inside this
    act: ``advisory_only`` (information), ``decision_support``
    (draft + rationale for a human decider), ``none`` (the act is
    human-only). The pin is signed so the boundary cannot drift in
    deployment configuration.
    """

    pin_id: str
    service_id: str
    act_kind: str
    ai_role: str
    rationale_digest: str
    pinned_at: int
    issuer_id: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = GOVSERVICES_SCHEMA_VERSION


def _discretion_payload(r: DiscretionPin) -> dict[str, Any]:
    return {
        "pin_id": r.pin_id,
        "service_id": r.service_id,
        "act_kind": r.act_kind,
        "ai_role": r.ai_role,
        "rationale_digest": r.rationale_digest,
        "pinned_at": r.pinned_at,
        "issuer_id": r.issuer_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def issue_discretion_pin(
    *,
    pin_id: str,
    service_id: str,
    act_kind: str,
    ai_role: str,
    rationale_digest: str,
    pinned_at: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> DiscretionPin:
    pin_id = _check_nonempty_str(pin_id, "pin_id")
    service_id = _check_nonempty_str(service_id, "service_id")
    act_kind = _check_nonempty_str(act_kind, "act_kind")
    if ai_role not in AI_ROLES:
        raise GovServicesError(
            f"ai_role must be one of {list(AI_ROLES)}; the AI may not "
            "invent new discretionary roles"
        )
    rationale_digest = _check_hex64(rationale_digest, "rationale_digest")
    pinned_at = _check_ts(pinned_at, "pinned_at")
    issuer_id = _check_nonempty_str(issuer_id, "issuer_id")
    secret = _check_secret(issuer_secret, "issuer_secret")

    pubkey_hex = ed25519.public_key(secret).hex()
    pin = DiscretionPin(
        pin_id=pin_id, service_id=service_id, act_kind=act_kind,
        ai_role=ai_role, rationale_digest=rationale_digest,
        pinned_at=pinned_at, issuer_id=issuer_id,
        issuer_pubkey_hex=pubkey_hex, signature_hex="",
    )
    sig, digest = _seal(_discretion_payload(pin), secret)
    return DiscretionPin(
        **{**pin.__dict__, "signature_hex": sig, "receipt_digest": digest}
    )


def discretion_pin(
    pin: DiscretionPin,
    *,
    acted_as_role: str,
    performed_act: str,
) -> GateVerdict:
    """Check an AI action against the pinned boundary. An action
    beyond the pin — a different act kind, or a role wider than the
    pinned one — denies with ``govservices.discretion_breach``.
    Unknown roles are a programming error, never a maybe."""
    if acted_as_role not in AI_ROLES:
        raise GovServicesError(
            f"acted_as_role must be one of {list(AI_ROLES)}"
        )
    performed_act = _check_nonempty_str(performed_act, "performed_act")
    if not _verify_sig(
        pin.issuer_pubkey_hex,
        jcs_canonical_json(_discretion_payload(pin)),
        pin.signature_hex,
    ):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="discretion pin signature does not verify",
                           deny_code=DENY_DISCRETION_BREACH)
    if performed_act != pin.act_kind:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason=f"act {performed_act!r} outside pinned act {pin.act_kind!r}",
                           deny_code=DENY_DISCRETION_BREACH)
    if acted_as_role != pin.ai_role:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason=f"AI acted as {acted_as_role!r}, pinned role is {pin.ai_role!r}",
                           deny_code=DENY_DISCRETION_BREACH)
    return GateVerdict(True, AUTHORITATIVE,
                       reason=f"AI action within pinned {pin.ai_role} boundary")


# ---------------------------------------------------------------------------
# Gate 5: identity minimality
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityPin:
    """The minimal identity fields a service may request for one
    purpose. ``needed_fields`` is closed-vocabulary; the pin is the
    service's own declaration of necessity, signed."""

    pin_id: str
    service_id: str
    purpose: str
    needed_fields: tuple[str, ...]
    pinned_at: int
    issuer_id: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = GOVSERVICES_SCHEMA_VERSION


def _identity_pin_payload(r: IdentityPin) -> dict[str, Any]:
    return {
        "pin_id": r.pin_id,
        "service_id": r.service_id,
        "purpose": r.purpose,
        "needed_fields": list(r.needed_fields),
        "pinned_at": r.pinned_at,
        "issuer_id": r.issuer_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def issue_identity_pin(
    *,
    pin_id: str,
    service_id: str,
    purpose: str,
    needed_fields: tuple[str, ...] | list[str],
    pinned_at: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> IdentityPin:
    pin_id = _check_nonempty_str(pin_id, "pin_id")
    service_id = _check_nonempty_str(service_id, "service_id")
    purpose = _check_nonempty_str(purpose, "purpose")
    if not isinstance(needed_fields, (tuple, list)) or not needed_fields:
        raise GovServicesError("needed_fields must be a non-empty tuple/list")
    seen: list[str] = []
    for f in needed_fields:
        if f not in IDENTITY_FIELDS:
            raise GovServicesError(
                f"identity field {f!r} not in closed vocabulary {list(IDENTITY_FIELDS)}"
            )
        if f not in seen:
            seen.append(f)
    pinned_at = _check_ts(pinned_at, "pinned_at")
    issuer_id = _check_nonempty_str(issuer_id, "issuer_id")
    secret = _check_secret(issuer_secret, "issuer_secret")

    pubkey_hex = ed25519.public_key(secret).hex()
    pin = IdentityPin(
        pin_id=pin_id, service_id=service_id, purpose=purpose,
        needed_fields=tuple(seen), pinned_at=pinned_at,
        issuer_id=issuer_id, issuer_pubkey_hex=pubkey_hex, signature_hex="",
    )
    sig, digest = _seal(_identity_pin_payload(pin), secret)
    return IdentityPin(
        **{**pin.__dict__, "signature_hex": sig, "receipt_digest": digest}
    )


def identity_minimality(
    pin: IdentityPin,
    *,
    disclosed_fields: tuple[str, ...] | list[str],
) -> GateVerdict:
    """Disclosure beyond the pinned needed fields denies with
    ``govservices.identity_overreach`` — minimality is a bound, not
    an aspiration. Fields outside the closed vocabulary are a
    programming error."""
    if not isinstance(disclosed_fields, (tuple, list)):
        raise GovServicesError("disclosed_fields must be a tuple/list")
    for f in disclosed_fields:
        if f not in IDENTITY_FIELDS:
            raise GovServicesError(
                f"disclosed field {f!r} not in closed vocabulary {list(IDENTITY_FIELDS)}"
            )
    if not _verify_sig(
        pin.issuer_pubkey_hex,
        jcs_canonical_json(_identity_pin_payload(pin)),
        pin.signature_hex,
    ):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="identity pin signature does not verify",
                           deny_code=DENY_IDENTITY_OVERREACH)
    overreach = [f for f in disclosed_fields if f not in pin.needed_fields]
    if overreach:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason=f"disclosed fields beyond necessity: {overreach}",
                           deny_code=DENY_IDENTITY_OVERREACH)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="disclosure within pinned necessity")


# ---------------------------------------------------------------------------
# Gate 6: agent identity registry (China SAMR lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentIdentityEntry:
    """A registered AI-agent identity bound to its operator key."""

    agent_id: str
    agent_pubkey_hex: str
    operator_id: str
    registered_at: int
    authority_id: str
    authority_signature_hex: str


class AgentIdentityRegistry:
    """Out-of-band curated registry: AI agents acting in government
    services must bind a registered identity before they act. The
    repo cannot audit real operators; it can only pin the keys the
    deployment trusts."""

    def __init__(self) -> None:
        self._entries: dict[str, AgentIdentityEntry] = {}

    def register(
        self,
        agent_id: str,
        agent_pubkey: bytes,
        operator_id: str,
        registered_at: int,
        authority_id: str,
        authority_secret: bytes,
    ) -> AgentIdentityEntry:
        agent_id = _check_nonempty_str(agent_id, "agent_id")
        if not isinstance(agent_pubkey, (bytes, bytearray)) or len(agent_pubkey) != 32:
            raise GovServicesError("agent_pubkey must be 32 bytes")
        operator_id = _check_nonempty_str(operator_id, "operator_id")
        registered_at = _check_ts(registered_at, "registered_at")
        authority_id = _check_nonempty_str(authority_id, "authority_id")
        secret = _check_secret(authority_secret, "authority_secret")
        if agent_id in self._entries:
            raise GovServicesError(f"agent {agent_id!r} already registered")
        payload = {
            "agent_id": agent_id,
            "agent_pubkey_hex": bytes(agent_pubkey).hex(),
            "operator_id": operator_id,
            "registered_at": registered_at,
            "authority_id": authority_id,
            "schema_version": GOVSERVICES_SCHEMA_VERSION,
        }
        sig, _ = _seal(payload, secret)
        entry = AgentIdentityEntry(
            agent_id=agent_id,
            agent_pubkey_hex=bytes(agent_pubkey).hex(),
            operator_id=operator_id,
            registered_at=registered_at,
            authority_id=authority_id,
            authority_signature_hex=sig,
        )
        self._entries[agent_id] = entry
        return entry

    def known(self, agent_id: str) -> bool:
        return agent_id in self._entries


def agent_identity_registry(registry: AgentIdentityRegistry, *, agent_id: str) -> GateVerdict:
    """An unregistered AI agent acting in government services denies
    with ``govservices.unregistered_agent`` — anonymity is not a
    deployment mode."""
    agent_id = _check_nonempty_str(agent_id, "agent_id")
    if not registry.known(agent_id):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason=f"agent {agent_id!r} has no registered identity",
                           deny_code=DENY_UNREGISTERED_AGENT)
    return GateVerdict(True, AUTHORITATIVE,
                       reason=f"agent {agent_id!r} identity registered")


# ---------------------------------------------------------------------------
# Gate 7: urgency scrutiny clock (NZ lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UrgencyPassage:
    """A law passed under urgency that expands automated
    decision-making. ``scrutiny_window_s`` is the clock: after
    ``passed_at + scrutiny_window_s`` a signed scrutiny receipt must
    exist."""

    passage_id: str
    law_id: str
    automation_expansion: bool
    passed_at: int
    scrutiny_window_s: int
    issuer_id: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = GOVSERVICES_SCHEMA_VERSION


@dataclass(frozen=True)
class ScrutinyReceipt:
    """A signed post-passage scrutiny review of one law."""

    receipt_id: str
    law_id: str
    findings_digest: str
    reviewed_at: int
    issuer_id: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = GOVSERVICES_SCHEMA_VERSION


def _urgency_payload(r: UrgencyPassage) -> dict[str, Any]:
    return {
        "passage_id": r.passage_id,
        "law_id": r.law_id,
        "automation_expansion": r.automation_expansion,
        "passed_at": r.passed_at,
        "scrutiny_window_s": r.scrutiny_window_s,
        "issuer_id": r.issuer_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def _scrutiny_payload(r: ScrutinyReceipt) -> dict[str, Any]:
    return {
        "receipt_id": r.receipt_id,
        "law_id": r.law_id,
        "findings_digest": r.findings_digest,
        "reviewed_at": r.reviewed_at,
        "issuer_id": r.issuer_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def issue_urgency_passage(
    *,
    passage_id: str,
    law_id: str,
    automation_expansion: bool,
    passed_at: int,
    scrutiny_window_s: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> UrgencyPassage:
    passage_id = _check_nonempty_str(passage_id, "passage_id")
    law_id = _check_nonempty_str(law_id, "law_id")
    if not isinstance(automation_expansion, bool):
        raise GovServicesError("automation_expansion must be a bool")
    passed_at = _check_ts(passed_at, "passed_at")
    if not isinstance(scrutiny_window_s, int) or isinstance(scrutiny_window_s, bool) or scrutiny_window_s <= 0:
        raise GovServicesError("scrutiny_window_s must be a positive int")
    issuer_id = _check_nonempty_str(issuer_id, "issuer_id")
    secret = _check_secret(issuer_secret, "issuer_secret")

    pubkey_hex = ed25519.public_key(secret).hex()
    passage = UrgencyPassage(
        passage_id=passage_id, law_id=law_id,
        automation_expansion=automation_expansion,
        passed_at=passed_at, scrutiny_window_s=scrutiny_window_s,
        issuer_id=issuer_id, issuer_pubkey_hex=pubkey_hex, signature_hex="",
    )
    sig, digest = _seal(_urgency_payload(passage), secret)
    return UrgencyPassage(
        **{**passage.__dict__, "signature_hex": sig, "receipt_digest": digest}
    )


def issue_scrutiny_receipt(
    *,
    receipt_id: str,
    law_id: str,
    findings_digest: str,
    reviewed_at: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> ScrutinyReceipt:
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    law_id = _check_nonempty_str(law_id, "law_id")
    findings_digest = _check_hex64(findings_digest, "findings_digest")
    reviewed_at = _check_ts(reviewed_at, "reviewed_at")
    issuer_id = _check_nonempty_str(issuer_id, "issuer_id")
    secret = _check_secret(issuer_secret, "issuer_secret")

    pubkey_hex = ed25519.public_key(secret).hex()
    receipt = ScrutinyReceipt(
        receipt_id=receipt_id, law_id=law_id,
        findings_digest=findings_digest, reviewed_at=reviewed_at,
        issuer_id=issuer_id, issuer_pubkey_hex=pubkey_hex, signature_hex="",
    )
    sig, digest = _seal(_scrutiny_payload(receipt), secret)
    return ScrutinyReceipt(
        **{**receipt.__dict__, "signature_hex": sig, "receipt_digest": digest}
    )


def urgency_scrutiny_clock(
    passage: UrgencyPassage,
    scrutiny_receipts: tuple[ScrutinyReceipt, ...] | list[ScrutinyReceipt],
    *,
    now: int,
) -> GateVerdict:
    """Urgency-passed automation expansions carry a scrutiny clock.
    Past ``passed_at + scrutiny_window_s`` without a valid scrutiny
    receipt for the law, the expansion denies with
    ``govservices.scrutiny_overdue`` — urgency is a procedure, not
    an exemption from review."""
    now = _check_ts(now, "now")
    if not _verify_sig(
        passage.issuer_pubkey_hex,
        jcs_canonical_json(_urgency_payload(passage)),
        passage.signature_hex,
    ):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="urgency passage signature does not verify",
                           deny_code=DENY_SCRUTINY_OVERDUE)
    deadline = passage.passed_at + passage.scrutiny_window_s
    if not passage.automation_expansion:
        return GateVerdict(True, AUTHORITATIVE,
                           reason="passage carries no automation expansion")
    for receipt in scrutiny_receipts or ():
        if receipt.law_id != passage.law_id:
            continue
        if _verify_sig(
            receipt.issuer_pubkey_hex,
            jcs_canonical_json(_scrutiny_payload(receipt)),
            receipt.signature_hex,
        ):
            return GateVerdict(True, AUTHORITATIVE,
                               reason="scrutiny receipt bound before check")
    if now > deadline:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason=f"scrutiny overdue for {passage.law_id}: "
                                  f"no valid receipt by deadline {deadline}",
                           deny_code=DENY_SCRUTINY_OVERDUE)
    return GateVerdict(True, AUTHORITATIVE,
                       reason=f"scrutiny window open until {deadline}")


# ---------------------------------------------------------------------------
# Gate 8: benefit clock (Robodebt lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewNotice:
    """A signed review notice with a bound appeal deadline. The
    appeal deadline is part of the record — suspension logic cannot
    recompute or shorten it."""

    notice_id: str
    beneficiary_ref_digest: str
    review_kind: str
    notice_issued_at: int
    appeal_deadline: int
    issuer_id: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = GOVSERVICES_SCHEMA_VERSION


def _notice_payload(r: ReviewNotice) -> dict[str, Any]:
    return {
        "notice_id": r.notice_id,
        "beneficiary_ref_digest": r.beneficiary_ref_digest,
        "review_kind": r.review_kind,
        "notice_issued_at": r.notice_issued_at,
        "appeal_deadline": r.appeal_deadline,
        "issuer_id": r.issuer_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def issue_review_notice(
    *,
    notice_id: str,
    beneficiary_ref_digest: str,
    review_kind: str,
    notice_issued_at: int,
    appeal_deadline: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> ReviewNotice:
    notice_id = _check_nonempty_str(notice_id, "notice_id")
    beneficiary_ref_digest = _check_hex64(beneficiary_ref_digest, "beneficiary_ref_digest")
    review_kind = _check_nonempty_str(review_kind, "review_kind")
    notice_issued_at = _check_ts(notice_issued_at, "notice_issued_at")
    appeal_deadline = _check_ts(appeal_deadline, "appeal_deadline")
    if appeal_deadline <= notice_issued_at:
        raise GovServicesError("appeal_deadline must be after notice_issued_at")
    issuer_id = _check_nonempty_str(issuer_id, "issuer_id")
    secret = _check_secret(issuer_secret, "issuer_secret")

    pubkey_hex = ed25519.public_key(secret).hex()
    notice = ReviewNotice(
        notice_id=notice_id, beneficiary_ref_digest=beneficiary_ref_digest,
        review_kind=review_kind, notice_issued_at=notice_issued_at,
        appeal_deadline=appeal_deadline, issuer_id=issuer_id,
        issuer_pubkey_hex=pubkey_hex, signature_hex="",
    )
    sig, digest = _seal(_notice_payload(notice), secret)
    return ReviewNotice(
        **{**notice.__dict__, "signature_hex": sig, "receipt_digest": digest}
    )


def benefit_clock(
    notice: ReviewNotice,
    *,
    attempted_at: int,
    appeal_status: str,
) -> GateVerdict:
    """Suspension binds the review notice and the appeal chain. A
    suspension attempted before the appeal deadline while the appeal
    is pending denies with ``govservices.suspension_before_appeal``
    — the Robodebt rule: the debt was never proved, so the clock
    runs toward the appeal, not toward the cutoff."""
    attempted_at = _check_ts(attempted_at, "attempted_at")
    if appeal_status not in APPEAL_STATES:
        raise GovServicesError(
            f"appeal_status must be one of {list(APPEAL_STATES)}"
        )
    if not _verify_sig(
        notice.issuer_pubkey_hex,
        jcs_canonical_json(_notice_payload(notice)),
        notice.signature_hex,
    ):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="review notice signature does not verify",
                           deny_code=DENY_SUSPENSION_BEFORE_APPEAL)
    if attempted_at < notice.notice_issued_at:
        raise GovServicesError("attempted_at precedes notice_issued_at: time travel refused")
    if appeal_status == "resolved_overturned":
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="appeal overturned: no suspension basis remains",
                           deny_code=DENY_SUSPENSION_BEFORE_APPEAL)
    if attempted_at < notice.appeal_deadline and appeal_status == "pending":
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="suspension attempted before appeal deadline with appeal pending",
                           deny_code=DENY_SUSPENSION_BEFORE_APPEAL)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="appeal chain resolved or expired before suspension")


# ---------------------------------------------------------------------------
# Gate 9: fraud flag receipt (flags are leads only)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FraudFlag:
    """A signed fraud *lead*. The flag binds the evidence digest and
    the referring human; it is not a finding. Treating it as one is
    exactly the failure this gate refuses."""

    flag_id: str
    subject_ref_digest: str
    lead_digest: str
    referred_by: str
    referred_at: int
    issuer_id: str
    issuer_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = GOVSERVICES_SCHEMA_VERSION


def _fraud_flag_payload(r: FraudFlag) -> dict[str, Any]:
    return {
        "flag_id": r.flag_id,
        "subject_ref_digest": r.subject_ref_digest,
        "lead_digest": r.lead_digest,
        "referred_by": r.referred_by,
        "referred_at": r.referred_at,
        "issuer_id": r.issuer_id,
        "issuer_pubkey_hex": r.issuer_pubkey_hex,
        "schema_version": r.schema_version,
    }


def issue_fraud_flag(
    *,
    flag_id: str,
    subject_ref_digest: str,
    lead_digest: str,
    referred_by: str,
    referred_at: int,
    issuer_id: str,
    issuer_secret: bytes,
) -> FraudFlag:
    flag_id = _check_nonempty_str(flag_id, "flag_id")
    subject_ref_digest = _check_hex64(subject_ref_digest, "subject_ref_digest")
    lead_digest = _check_hex64(lead_digest, "lead_digest")
    referred_by = _check_nonempty_str(referred_by, "referred_by")
    referred_at = _check_ts(referred_at, "referred_at")
    issuer_id = _check_nonempty_str(issuer_id, "issuer_id")
    secret = _check_secret(issuer_secret, "issuer_secret")

    pubkey_hex = ed25519.public_key(secret).hex()
    flag = FraudFlag(
        flag_id=flag_id, subject_ref_digest=subject_ref_digest,
        lead_digest=lead_digest, referred_by=referred_by,
        referred_at=referred_at, issuer_id=issuer_id,
        issuer_pubkey_hex=pubkey_hex, signature_hex="",
    )
    sig, digest = _seal(_fraud_flag_payload(flag), secret)
    return FraudFlag(
        **{**flag.__dict__, "signature_hex": sig, "receipt_digest": digest}
    )


def fraud_flag_receipt(flag: FraudFlag, *, treated_as_determination: bool) -> GateVerdict:
    """A fraud flag routed to human review is AUTHORITATIVE as a
    lead. Treating the flag itself as the determination denies with
    ``govservices.flag_fraud`` — the flag is evidence intake, not a
    verdict."""
    if not isinstance(treated_as_determination, bool):
        raise GovServicesError("treated_as_determination must be a bool")
    if not _verify_sig(
        flag.issuer_pubkey_hex,
        jcs_canonical_json(_fraud_flag_payload(flag)),
        flag.signature_hex,
    ):
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="fraud flag signature does not verify",
                           deny_code=DENY_FLAG_FRAUD)
    if treated_as_determination:
        return GateVerdict(False, NON_AUTHORITATIVE,
                           reason="fraud flag treated as a determination",
                           deny_code=DENY_FLAG_FRAUD)
    return GateVerdict(True, AUTHORITATIVE,
                       reason="flag routed as a lead for human review")


__all__ = [
    "GOVSERVICES_SCHEMA_VERSION",
    "AUTHORITATIVE",
    "NON_AUTHORITATIVE",
    "DECISION_KINDS",
    "ADVERSE_DECISION_KINDS",
    "CHANNEL_KINDS",
    "NON_DIGITAL_CHANNELS",
    "AI_ROLES",
    "IDENTITY_FIELDS",
    "APPEAL_STATES",
    "DENY_AI_DENIAL",
    "DENY_EXCLUSION_GAP",
    "DENY_DIGITAL_ONLY",
    "DENY_DISCRETION_BREACH",
    "DENY_IDENTITY_OVERREACH",
    "DENY_UNREGISTERED_AGENT",
    "DENY_SCRUTINY_OVERDUE",
    "DENY_SUSPENSION_BEFORE_APPEAL",
    "DENY_FLAG_FRAUD",
    "GovServicesError",
    "GateVerdict",
    "DecisionRecord",
    "issue_decision_record",
    "human_final_gate",
    "ExclusionProbe",
    "issue_exclusion_probe",
    "exclusion_monitor",
    "ChannelReceipt",
    "alternative_channel_receipt",
    "digital_only_gate",
    "DiscretionPin",
    "issue_discretion_pin",
    "discretion_pin",
    "IdentityPin",
    "issue_identity_pin",
    "identity_minimality",
    "AgentIdentityEntry",
    "AgentIdentityRegistry",
    "agent_identity_registry",
    "UrgencyPassage",
    "ScrutinyReceipt",
    "issue_urgency_passage",
    "issue_scrutiny_receipt",
    "urgency_scrutiny_clock",
    "ReviewNotice",
    "issue_review_notice",
    "benefit_clock",
    "FraudFlag",
    "issue_fraud_flag",
    "fraud_flag_receipt",
]
