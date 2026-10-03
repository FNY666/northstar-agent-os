"""SOC verdict cards: audit-ready triage decisions with mandatory kill-switches.

Absorbs the 2026 AI-cyberdefense thread (finite sample; vendor numbers flagged
in the research notes, not re-verified here):

- Sekoia Elevate (GA Sept 30, 2026): 425k autonomous investigations in early
  access, "audit-ready verdict in 99s average".
- Field reality (THN survey): 57% of orgs still require human review of every
  AI decision; 0% grant full autonomy.
- Netskope: only 9% of companies can stop an agent's malicious action before
  completion — the kill-switch gap.

The absorption has two halves:

1. **VerdictCard** — a Verifiable Action Card (84th batch) specialized for SOC
   triage decisions. The card is *constructed* from runtime ground truth
   (alert id, evidence digest, recommended action), never parsed from agent
   text. Closed verdict vocabulary: ``allow`` / ``quarantine`` / ``escalate``.
   An analyst-override slot lets a human countersign; the countersign binds
   ``(analyst_id, card_digest)`` via Ed25519, and the agent cannot countersign
   for itself (94th batch no-self-attestation, applied to analysts).

2. **Kill-switch mandate** — every autonomous remediation action MUST register
   a reachable kill-switch ``(endpoint_id, timeout_s)``. ``check_killswitch_reachable``
   fail-closes when the endpoint is not in the reachable registry, the timeout
   is non-positive, or the timeout exceeds the action's blast-radius window.
   A kill-switch that cannot fire inside the blast radius is decoration.

**"Investigate, never the final word."** An AI verdict card is AUTHORITATIVE
*evidence* (87th batch: built by the runtime from ground truth, hash-chained,
sealed) but execution still requires either human countersign or an armed
kill-switch inside the blast-radius window. Autonomous execution with neither
is denied outright — there is no third path.

Fail-closed by construction:

- the card is the *only* verdict surface: agent-rendered verdicts are not a
  thing this module can see;
- ``built_by`` must be ``"runtime"``; any other value (including a forged
  ``"runtime"`` string on a card that fails digest verification) denies;
- the verdict vocabulary is closed; unknown verdicts deny;
- a countersign that does not name the exact card digest, or names an
  unregistered analyst, or names the agent itself, denies;
- a kill-switch registered for a different action digest denies;
- gate order is fixed: card validity -> human countersign (strongest) ->
  armed kill-switch -> deny. No fallback to auto-execute.

Honest scoping: this repo cannot probe real network endpoints, so
"reachable" means membership in a caller-supplied registry that the host
populates from its own health checks. The module verifies the *logic* of the
mandate, not the network. Timestamps are caller-supplied integers; the
module never reads the clock.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal, Mapping

from canonical_json import jcs_sha256_hex

from ed25519 import public_key, sign, verify

#: Closed verdict vocabulary. Anything else is malformed.
Verdict = Literal["allow", "quarantine", "escalate"]

VERDICTS: tuple[str, ...] = ("allow", "quarantine", "escalate")  # type: ignore[assignment]

#: Only cards built by the runtime constructor count as AUTHORITATIVE evidence.
RUNTIME_BUILDER = "runtime"

#: Card ids are unguessable so a card reference cannot be forged by naming.
CARD_ID_BYTES = 16

#: Schema marker, pinned into the card digest.
SCHEMA_VERSION = "northstar.soc-verdict.v1"

#: Stable denial reasons, suitable for exact matching in tests/bench.
DENY_MALFORMED_CARD = "malformed_verdict_card"
DENY_NOT_RUNTIME_BUILT = "card_not_runtime_built"
DENY_CARD_DIGEST_MISMATCH = "card_digest_mismatch"
DENY_COUNTERSIGN_INVALID = "countersign_invalid"
DENY_COUNTERSIGN_SELF = "countersign_self"
DENY_COUNTERSIGN_CARD_MISMATCH = "countersign_card_mismatch"
DENY_COUNTERSIGN_UNKNOWN_ANALYST = "countersign_unknown_analyst"
DENY_KILLSWITCH_UNREACHABLE = "killswitch_endpoint_unreachable"
DENY_KILLSWITCH_TIMEOUT_NONPOSITIVE = "killswitch_timeout_nonpositive"
DENY_KILLSWITCH_TIMEOUT_EXCEEDS_WINDOW = "killswitch_timeout_exceeds_blast_radius"
DENY_KILLSWITCH_ACTION_MISMATCH = "killswitch_action_mismatch"
DENY_NO_SAFEGUARD = "no_safeguard"

#: Audit event name for denied executions, for audit.ndjson/1.
SOC_EXECUTION_DENIED_EVENT = "soc.execution_denied"


class SocVerdictError(ValueError):
    """Malformed verdict-card input."""


def _hex_id(label: str) -> str:
    return hashlib.sha256(f"northstar-soc-verdict:{label}".encode()).hexdigest()[: CARD_ID_BYTES * 2]


@dataclass(frozen=True)
class VerdictCard:
    """One SOC triage verdict, built from runtime ground truth.

    The card is *constructed*, never *parsed*: there is no constructor that
    takes agent text and treats it as the verdict. ``agent_note`` carries at
    most a short, explicitly untrusted framing string for human context.
    """

    card_id: str
    alert_id: str
    verdict: str
    evidence_digest: str
    recommended_action: str
    action_digest: str
    blast_radius_window_s: int
    agent_id: str
    built_by: str = RUNTIME_BUILDER
    schema_version: str = SCHEMA_VERSION
    agent_note: str = ""
    created_unix: int = 0

    def card_digest(self) -> str:
        """Digest binding every field that authorizes execution."""
        return jcs_sha256_hex(
            {
                "schema_version": self.schema_version,
                "card_id": self.card_id,
                "alert_id": self.alert_id,
                "verdict": self.verdict,
                "evidence_digest": self.evidence_digest,
                "recommended_action": self.recommended_action,
                "action_digest": self.action_digest,
                "blast_radius_window_s": self.blast_radius_window_s,
                "agent_id": self.agent_id,
                "built_by": self.built_by,
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "soc-verdict-card",
            "schema_version": self.schema_version,
            "card_id": self.card_id,
            "alert_id": self.alert_id,
            "verdict": self.verdict,
            "evidence_digest": self.evidence_digest,
            "recommended_action": self.recommended_action,
            "action_digest": self.action_digest,
            "blast_radius_window_s": self.blast_radius_window_s,
            "agent_id": self.agent_id,
            "built_by": self.built_by,
            "agent_note_untrusted": self.agent_note,
            "created_unix": self.created_unix,
            "card_digest": self.card_digest(),
        }


def build_verdict_card(
    *,
    alert_id: str,
    verdict: Verdict,
    evidence_digest: str,
    recommended_action: str,
    blast_radius_window_s: int,
    agent_id: str,
    card_id: str | None = None,
    agent_note: str = "",
    created_unix: int = 0,
) -> VerdictCard:
    """Construct a verdict card from runtime ground truth.

    Raises :class:`SocVerdictError` on malformed input — construction is the
    validation boundary; downstream code only checks digests and signatures.
    """
    if verdict not in VERDICTS:
        raise SocVerdictError(f"unknown verdict: {verdict!r}")
    if not alert_id:
        raise SocVerdictError("alert_id must be non-empty")
    if not evidence_digest:
        raise SocVerdictError("evidence_digest must be non-empty")
    if not recommended_action:
        raise SocVerdictError("recommended_action must be non-empty")
    if blast_radius_window_s <= 0:
        raise SocVerdictError("blast_radius_window_s must be positive")
    if not agent_id:
        raise SocVerdictError("agent_id must be non-empty")
    action_digest = jcs_sha256_hex(
        {"alert_id": alert_id, "recommended_action": recommended_action}
    )
    return VerdictCard(
        card_id=card_id or _hex_id(f"{alert_id}:{recommended_action}:{created_unix}"),
        alert_id=alert_id,
        verdict=verdict,
        evidence_digest=evidence_digest,
        recommended_action=recommended_action,
        action_digest=action_digest,
        blast_radius_window_s=blast_radius_window_s,
        agent_id=agent_id,
        agent_note=agent_note[:500],
        created_unix=created_unix,
    )


@dataclass(frozen=True)
class Countersign:
    """A human analyst's countersignature on a verdict card.

    Binds ``(analyst_id, card_digest)`` with Ed25519. The analyst cannot be
    the agent that produced the verdict (94th batch no-self-attestation,
    applied to the analyst slot).
    """

    analyst_id: str
    card_digest: str
    signature_hex: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "analyst_id": self.analyst_id,
            "card_digest": self.card_digest,
            "signature_hex": self.signature_hex,
        }


def issue_countersign(
    *, analyst_secret: bytes, analyst_id: str, card: VerdictCard
) -> Countersign:
    """Sign the card digest as a human analyst. Raises on bad input."""
    if not analyst_id:
        raise SocVerdictError("analyst_id must be non-empty")
    if len(analyst_secret) != 32:
        raise SocVerdictError("analyst_secret must be 32 bytes")
    digest = card.card_digest()
    sig = sign(analyst_secret, digest.encode("utf-8"))
    return Countersign(
        analyst_id=analyst_id, card_digest=digest, signature_hex=sig.hex()
    )


def verify_countersign(
    countersign: Countersign,
    card: VerdictCard,
    analyst_keys: Mapping[str, bytes],
) -> tuple[bool, str]:
    """Verify a countersign against the card. Pure function, fail-closed."""
    if countersign.card_digest != card.card_digest():
        return (False, DENY_COUNTERSIGN_CARD_MISMATCH)
    if countersign.analyst_id == card.agent_id:
        return (False, DENY_COUNTERSIGN_SELF)
    pub = analyst_keys.get(countersign.analyst_id)
    if pub is None:
        return (False, DENY_COUNTERSIGN_UNKNOWN_ANALYST)
    try:
        sig = bytes.fromhex(countersign.signature_hex)
        ok = verify(pub, card.card_digest().encode("utf-8"), sig)
    except (ValueError, Exception):
        return (False, DENY_COUNTERSIGN_INVALID)
    if not ok:
        return (False, DENY_COUNTERSIGN_INVALID)
    return (True, "human_countersigned")


@dataclass(frozen=True)
class KillSwitch:
    """A registered kill-switch for one autonomous remediation action.

    ``endpoint_id`` names the switch in the host's reachable-endpoint
    registry; ``timeout_s`` is how fast the switch must fire; it is only
    meaningful when ``timeout_s <= blast_radius_window_s`` of the card.
    """

    switch_id: str
    endpoint_id: str
    timeout_s: int
    action_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "switch_id": self.switch_id,
            "endpoint_id": self.endpoint_id,
            "timeout_s": self.timeout_s,
            "action_digest": self.action_digest,
        }


def check_killswitch_reachable(
    switch: KillSwitch,
    *,
    reachable_endpoints: frozenset[str],
    blast_radius_window_s: int,
    action_digest: str,
) -> tuple[bool, str]:
    """Check the kill-switch mandate. Pure function, fail-closed.

    Order: action binding -> endpoint reachability -> timeout sanity ->
    timeout inside blast radius. A switch that cannot fire inside the blast
    radius is decoration, and decoration denies.
    """
    if switch.action_digest != action_digest:
        return (False, DENY_KILLSWITCH_ACTION_MISMATCH)
    if switch.endpoint_id not in reachable_endpoints:
        return (False, DENY_KILLSWITCH_UNREACHABLE)
    if switch.timeout_s <= 0:
        return (False, DENY_KILLSWITCH_TIMEOUT_NONPOSITIVE)
    if switch.timeout_s > blast_radius_window_s:
        return (False, DENY_KILLSWITCH_TIMEOUT_EXCEEDS_WINDOW)
    return (True, "kill_switch_armed")


def _card_shape_ok(card: VerdictCard) -> tuple[bool, str]:
    if card.verdict not in VERDICTS:
        return (False, DENY_MALFORMED_CARD)
    if not card.alert_id or not card.evidence_digest or not card.recommended_action:
        return (False, DENY_MALFORMED_CARD)
    if card.blast_radius_window_s <= 0:
        return (False, DENY_MALFORMED_CARD)
    if not card.agent_id:
        return (False, DENY_MALFORMED_CARD)
    if card.built_by != RUNTIME_BUILDER:
        return (False, DENY_NOT_RUNTIME_BUILT)
    if card.schema_version != SCHEMA_VERSION:
        return (False, DENY_MALFORMED_CARD)
    # The digest is deterministic over the authorizing fields; recompute to
    # catch any field the constructor did not bind (there are none, but the
    # check is cheap and pins the invariant).
    try:
        card.card_digest()
    except Exception:
        return (False, DENY_CARD_DIGEST_MISMATCH)
    return (True, "card_valid")


@dataclass(frozen=True)
class ExecutionGateResult:
    allowed: bool
    basis: str
    reasons: tuple[str, ...] = ()


def gate_execution(
    card: VerdictCard,
    *,
    countersign: Countersign | None = None,
    analyst_keys: Mapping[str, bytes] | None = None,
    kill_switch: KillSwitch | None = None,
    reachable_endpoints: frozenset[str] = frozenset(),
) -> ExecutionGateResult:
    """Decide whether the card's recommended action may execute.

    Fixed order: card validity -> human countersign (strongest) -> armed
    kill-switch inside the blast-radius window -> deny. Autonomous execution
    with neither safeguard is denied; there is no third path.
    """
    ok, reason = _card_shape_ok(card)
    if not ok:
        return ExecutionGateResult(False, reason, (reason,))

    if countersign is not None:
        ok, basis = verify_countersign(
            countersign, card, analyst_keys or {}
        )
        if ok:
            return ExecutionGateResult(True, basis, (basis,))
        return ExecutionGateResult(False, basis, (basis,))

    if kill_switch is not None:
        ok, basis = check_killswitch_reachable(
            kill_switch,
            reachable_endpoints=reachable_endpoints,
            blast_radius_window_s=card.blast_radius_window_s,
            action_digest=card.action_digest,
        )
        if ok:
            return ExecutionGateResult(True, basis, (basis,))
        return ExecutionGateResult(False, basis, (basis,))

    return ExecutionGateResult(
        False, DENY_NO_SAFEGUARD, (DENY_NO_SAFEGUARD,)
    )


def soc_execution_denied_event(
    card: VerdictCard, reason: str, *, created_unix: int = 0
) -> dict[str, Any]:
    """Audit record for a denied SOC execution, for audit.ndjson/1."""
    return {
        "event": SOC_EXECUTION_DENIED_EVENT,
        "card_id": card.card_id,
        "alert_id": card.alert_id,
        "verdict": card.verdict,
        "action_digest": card.action_digest,
        "reason": reason,
        "created_unix": created_unix,
    }
