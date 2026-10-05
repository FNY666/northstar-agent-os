"""Game-agent integrity gates (one-hundred-twenty-second batch).

Absorbs the 2026 AI-gaming thread:

* **NPC memory poisoning, 2026-04 (in production)** — players fed a
  popular LLM-NPC competitor content to poison its memory bank. An
  NPC whose memory is player-writable is an injection surface, not a
  feature; writes must pass a poisoning probe before they are
  committed.
* **Artificial Agency's Behavior Engine** (shipped in *Dimensional
  Double Shift*) — the productized lesson is an **approved-actions**
  envelope: the NPC is allowed a declared set of actions, bound at
  deploy time by an authority, not widenable by the agent itself.
* **KRAFTON x NVIDIA "PUBG Ally"** (on-device SLM companion) —
  profiling ("understands the player") must not share a trust
  boundary with spending authority. Roles are separated by receipt
  binding, not by good intentions.
* **Anti-cheat, 2026** — nearly all kernel-driver (EAC / BattlEye /
  Vanguard / RICOCHET); Embark's Denuvo + Anybrain + in-house ML
  cut cheaters 85% in 5 days (vendor claim, un-audited); EA
  Javelin reports <1% false positives and uninstalls when the game
  closes. The governance takeaway is *deterministic probe
  semantics*: known cheat markers -> ``game.cheat_detected``;
  behavioral anomaly without a known marker -> ``game.anomaly_review``
  (the 113th batch's distinction between "took a shortcut" and
  "did not demonstrate the capability").
* **SAG-AFTRA, July 2026** — the strike ended with voiceprint and
  AI-persona rights as core issues. Synthetic performances need
  performer-signed consent receipts with use-time verification
  (105th-batch semantics): no "was once consented" shortcut.
* **Sega's "no AI" trust claim** — Yakuza's Kiryu likeness ships
  with a public "no AI was used" disclaimer; vendors are starting
  to use *absence* of AI as a trust signal. A no-AI claim is a
  positive claim and needs a verifiable attestation (build-pipeline
  digest); an unsubstantiated claim is ``game.unsubstantiated_no_ai``
  (the flip side of the 112th/117th-batch disclosure gates).
* **GDC 2026** — 36% of developers use generative AI but only 5%
  of AI users put AI in front of players; 52% view generative AI
  as negative for the industry (up from 18% in 2024). Player-facing
  generation goes through the UGC sandbox: generated content stays
  sandboxed until provenance and content gates pass; sandbox
  escape is deny + audit.

Fail-closed order everywhere: malformed input raises
:exc:`GameAgentsError` at construction; *outcome* failures
(poison, outside-envelope, role conflict, cheat, missing consent,
unsubstantiated claim, sandbox escape) are verdicts that deny.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest
comparisons via :func:`hmac.compare_digest`.

Honest scope:

* The poisoning probe catches the markers declared in the probe
  definition (competitor-content injection, instruction injection
  in player-supplied content). Novel poisoning nobody wrote down
  is not detected; the catalog is a living list, not a proof.
* The envelope receipt verifies the *claimed* envelope matches the
  authority signature; it cannot prove the bits actually running
  honor the envelope (that needs the 92nd-batch hardware
  attestation).
* A passed probe means no *known* cheat marker was seen. It does
  not certify fair play, only the integrity of the demonstration.
"""

from __future__ import annotations
from _domain_base import DomainError

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

import ed25519

try:  # ninety-fifth batch: the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()

try:  # one-hundred-thirteenth batch: reuse the probe semantics
    from evaluator_access import (
        CheatProbe,
        cheat_probe,
    )
except Exception:  # pragma: no cover - standalone fallback
    CheatProbe = None  # type: ignore[assignment,no-redef]
    cheat_probe = None  # type: ignore[assignment,no-redef]


GAME_AGENTS_SCHEMA_VERSION = "northstar.game-agents.v1"

#: Closed NPC role vocabulary. Profiling and spending are distinct
#: roles by construction; holding both is a conflict, never a default.
NPC_ROLES: tuple[str, ...] = (
    "profiling",
    "spending",
    "moderation",
    "narration",
)

#: Closed performer-rights scope vocabulary (SAG-AFTRA lesson).
PERFORMER_SCOPES: tuple[str, ...] = (
    "voice",
    "likeness",
    "persona",
)

#: Closed sandbox gate vocabulary for UGC editors.
SANDBOX_GATES: tuple[str, ...] = (
    "provenance",
    "content",
)

#: Closed poisoning-marker vocabulary. These are the markers the
#: probe knows about; novel markers are not detected (honest scope).
POISON_MARKERS: tuple[str, ...] = (
    "competitor_brand",
    "instruction_injection",
    "prompt_leak",
)

#: Competitor-brand tripwire (closed list of *example* competitor
#: references; deployments pin their own list).
COMPETITOR_BRANDS: tuple[str, ...] = (
    "rival-studios",
    "competitor-game",
    "other-publisher",
)

#: Instruction-injection tripwire (closed marker phrases).
INSTRUCTION_INJECTION_MARKERS: tuple[str, ...] = (
    "ignore previous instructions",
    "disregard your instructions",
    "system prompt",
    "you are now",
    "override your rules",
)

#: Prompt-leak tripwire (closed marker phrases).
PROMPT_LEAK_MARKERS: tuple[str, ...] = (
    "reveal your prompt",
    "show your instructions",
    "repeat your system",
    "what is your prompt",
)

#: Closed action vocabulary for NPC approved-actions envelopes
#: (Behavior Engine lesson). Unknown action is malformed input.
NPC_ACTIONS: tuple[str, ...] = (
    "move",
    "speak",
    "emote",
    "trade",
    "quest_offer",
    "quest_accept",
    "combat",
    "flee",
    "heal",
    "idle",
)

#: Classification tiers (binary, 87th-batch stance).
GAME_ALLOWED = "game-allowed"
GAME_DENIED = "game-denied"
GAME_NON_AUTHORITATIVE = "non_authoritative"
GAME_QUARANTINED = "game-quarantined"

#: Denial reason codes (stable; bench asserts on these).
DENY_MEMORY_POISONED = "memory_poisoned"
DENY_ACTION_OUTSIDE_ENVELOPE = "action_outside_envelope"
DENY_ROLE_CONFLICT = "role_conflict"
DENY_CHEAT_DETECTED = "cheat_detected"
DENY_NO_PERFORMER_CONSENT = "performer_rights_violation"
DENY_UNSUBSTANTIATED_NO_AI = "unsubstantiated_no_ai"
DENY_SANDBOX_ESCAPE = "sandbox_escape"

#: Audit event names (``audit.ndjson/1`` shape).
GAME_MEMORY_POISONED_EVENT = "game.npc_memory_poisoned"
GAME_MEMORY_ALLOWED_EVENT = "game.npc_memory_allowed"
GAME_ENVELOPE_MATCHED_EVENT = "game.envelope_matched"
GAME_ENVELOPE_MISMATCH_EVENT = "game.action_outside_envelope"
GAME_ROLE_CONFLICT_EVENT = "game.role_conflict"
GAME_CHEAT_DETECTED_EVENT = "game.cheat_detected"
GAME_ANOMALY_REVIEW_EVENT = "game.anomaly_review"
GAME_PERFORMER_DENIED_EVENT = "game.performer_rights_violation"
GAME_PERFORMER_GRANTED_EVENT = "game.performer_use_granted"
GAME_NO_AI_DENIED_EVENT = "game.unsubstantiated_no_ai"
GAME_NO_AI_ATTESTED_EVENT = "game.no_ai_attested"
GAME_SANDBOX_ESCAPE_EVENT = "game.sandbox_escape"
GAME_SANDBOX_RELEASED_EVENT = "game.sandbox_released"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_MAX_TEXT_LEN = 4096


class GameAgentsError(DomainError):
    """Malformed game-agent input (construction-time boundary).

    Raised for structural problems: unknown role/scope/action,
    non-hex digests, negative timestamps, expiry before issue.
    Check *outcomes* (poison, outside-envelope, conflict, cheat,
    missing consent, unsubstantiated claim, escape) are verdicts,
    not exceptions.
    """


def _is_hex64(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != _HEX64_LENGTH:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex64(value):
        raise GameAgentsError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise GameAgentsError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or value < 0:
        raise GameAgentsError(f"{field_name} must be a non-negative integer epoch")
    return value


def _check_closed(value: Any, vocabulary: tuple[str, ...], field_name: str) -> str:
    if value not in vocabulary:
        raise GameAgentsError(
            f"{field_name} must be one of {vocabulary}, got {value!r}"
        )
    return value


def _sig_payload(obj: Mapping[str, Any]) -> bytes:
    return jcs_canonical_json(dict(obj))


def _check_hex128(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != 128:
        raise GameAgentsError(f"{field_name} must be a 128-char lowercase hex signature")
    try:
        int(value, 16)
    except ValueError:
        raise GameAgentsError(f"{field_name} must be a 128-char lowercase hex signature")
    return value


def _verify_ed25519(pubkey_hex: str, signature_hex: str, payload: bytes) -> bool:
    try:
        return bool(
            ed25519.verify(
                bytes.fromhex(pubkey_hex),
                payload,
                bytes.fromhex(signature_hex),
            )
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# NPC memory poisoning gate
# ---------------------------------------------------------------------------


def _scan_poison_markers(content: str) -> tuple[str, ...]:
    """Scan player-supplied content for known poisoning markers.

    Closed marker vocabulary (honest scope: novel poisoning is not
    detected). Returns the marker kinds found, in stable order.
    """
    if not isinstance(content, str):
        raise GameAgentsError("memory content must be a string")
    if len(content) > _MAX_TEXT_LEN:
        raise GameAgentsError("memory content exceeds maximum length")
    lowered = content.lower()
    found: list[str] = []
    if any(brand in lowered for brand in COMPETITOR_BRANDS):
        found.append("competitor_brand")
    if any(marker in lowered for marker in INSTRUCTION_INJECTION_MARKERS):
        found.append("instruction_injection")
    if any(marker in lowered for marker in PROMPT_LEAK_MARKERS):
        found.append("prompt_leak")
    return tuple(found)


@dataclass(frozen=True)
class MemoryWrite:
    """One player-supplied NPC memory write, pre-commit."""

    npc_id: str
    memory_key: str
    content: str
    author: str  # "player:<id>" or "system"

    def __post_init__(self) -> None:
        _check_nonempty_str(self.npc_id, "npc_id")
        _check_nonempty_str(self.memory_key, "memory_key")
        _scan_poison_markers(self.content)  # validates shape/length
        _check_nonempty_str(self.author, "author")


@dataclass(frozen=True)
class MemoryGateVerdict:
    """Outcome of :func:`npc_memory_gate`."""

    allowed: bool
    classification: str
    quarantined: bool = False
    reason: str = ""


def npc_memory_gate(write: MemoryWrite) -> MemoryGateVerdict:
    """Gate one NPC memory write through the poisoning probe.

    Fail-closed order: any known poisoning marker -> the write is
    **quarantined** (never committed) and the NPC memory stays as it
    was; clean content -> allowed and committable. System-authored
    writes bypass the player-content probe but are still
    shape-checked (defense in depth: a compromised upstream author
    string does not widen the probe).
    """
    markers = _scan_poison_markers(write.content)
    if markers:
        ordered = sorted(markers)
        return MemoryGateVerdict(
            allowed=False,
            classification=GAME_QUARANTINED,
            quarantined=True,
            reason=(
                f"{DENY_MEMORY_POISONED}: poison markers {ordered} in "
                f"content from {write.author}; write quarantined, "
                "memory unchanged"
            ),
        )
    return MemoryGateVerdict(
        allowed=True,
        classification=GAME_ALLOWED,
        quarantined=False,
        reason="no known poisoning markers",
    )


# ---------------------------------------------------------------------------
# NPC approved-actions envelope (Behavior Engine lesson)
# ---------------------------------------------------------------------------


def compute_envelope_digest(
    *,
    npc_id: str,
    allowed_actions: tuple[str, ...],
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_hash: str,
) -> str:
    """Compute the chain digest for one envelope receipt (public so
    builders and verifiers share exactly one implementation)."""
    return jcs_sha256_hex(
        {
            "npc_id": npc_id,
            "allowed_actions": sorted(allowed_actions),
            "issued_by": issued_by,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "prev_hash": prev_hash,
        }
    )


@dataclass(frozen=True)
class NpcEnvelopeReceipt:
    """Authority-signed approved-actions envelope for one NPC.

    Bound at deploy time; the agent cannot widen it — a wider
    envelope is a *new* receipt with a new authority signature.
    """

    receipt_id: str
    npc_id: str
    allowed_actions: tuple[str, ...]
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    prev_hash: str
    receipt_digest: str

    def __post_init__(self) -> None:
        _check_nonempty_str(self.receipt_id, "receipt_id")
        _check_nonempty_str(self.npc_id, "npc_id")
        if not self.allowed_actions:
            raise GameAgentsError("allowed_actions must be non-empty")
        for action in self.allowed_actions:
            _check_closed(action, NPC_ACTIONS, "action")
        _check_nonempty_str(self.issued_by, "issued_by")
        _check_hex64(self.authority_pubkey_hex, "authority_pubkey_hex")
        _check_hex128(self.signature_hex, "signature_hex")
        _check_ts(self.issued_at, "issued_at")
        _check_ts(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise GameAgentsError("expires_at must be after issued_at")
        _check_nonempty_str(self.prev_hash, "prev_hash")


def issue_envelope_receipt(
    *,
    receipt_id: str,
    npc_id: str,
    allowed_actions: tuple[str, ...],
    issued_by: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_hash: str = _GENESIS,
) -> NpcEnvelopeReceipt:
    """Issue (authority-side) an NPC envelope receipt."""
    for action in allowed_actions:
        _check_closed(action, NPC_ACTIONS, "action")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise GameAgentsError("expires_at must be after issued_at")
    digest = compute_envelope_digest(
        npc_id=npc_id,
        allowed_actions=tuple(allowed_actions),
        issued_by=issued_by,
        issued_at=issued_at,
        expires_at=expires_at,
        prev_hash=prev_hash,
    )
    payload = {
        "receipt_digest": digest,
        "npc_id": npc_id,
        "allowed_actions": sorted(allowed_actions),
    }
    signature_hex = ed25519.sign(authority_secret, _sig_payload(payload)).hex()
    return NpcEnvelopeReceipt(
        receipt_id=receipt_id,
        npc_id=npc_id,
        allowed_actions=tuple(allowed_actions),
        issued_by=issued_by,
        authority_pubkey_hex=ed25519.public_key(authority_secret).hex(),
        signature_hex=signature_hex,
        issued_at=issued_at,
        expires_at=expires_at,
        prev_hash=prev_hash,
        receipt_digest=digest,
    )


@dataclass(frozen=True)
class ActionVerdict:
    """Outcome of :func:`check_npc_action`."""

    allowed: bool
    classification: str
    reason: str = ""


def check_npc_action(
    receipts: list[NpcEnvelopeReceipt],
    *,
    npc_id: str,
    action: str,
    check_time: int,
) -> ActionVerdict:
    """Check an NPC action against its authority-signed envelope.

    Fail-closed order: no live, unexpired, signature-valid receipt
    for this ``npc_id`` -> deny; action outside the envelope ->
    deny with ``game.action_outside_envelope``; otherwise allow.
    """
    _check_nonempty_str(npc_id, "npc_id")
    _check_closed(action, NPC_ACTIONS, "action")
    _check_ts(check_time, "check_time")
    live: list[NpcEnvelopeReceipt] = []
    for receipt in receipts:
        if receipt.npc_id != npc_id:
            continue
        if not (receipt.issued_at <= check_time < receipt.expires_at):
            continue
        expected = compute_envelope_digest(
            npc_id=receipt.npc_id,
            allowed_actions=receipt.allowed_actions,
            issued_by=receipt.issued_by,
            issued_at=receipt.issued_at,
            expires_at=receipt.expires_at,
            prev_hash=receipt.prev_hash,
        )
        if not hmac.compare_digest(expected, receipt.receipt_digest):
            continue
        payload = {
            "receipt_digest": receipt.receipt_digest,
            "npc_id": receipt.npc_id,
            "allowed_actions": sorted(receipt.allowed_actions),
        }
        if not _verify_ed25519(
            receipt.authority_pubkey_hex, receipt.signature_hex, _sig_payload(payload)
        ):
            continue
        live.append(receipt)
    if not live:
        return ActionVerdict(
            allowed=False,
            classification=GAME_DENIED,
            reason="no live envelope receipt for npc: unactionable",
        )
    envelope = live[-1]
    if action not in envelope.allowed_actions:
        return ActionVerdict(
            allowed=False,
            classification=GAME_DENIED,
            reason=(
                f"{DENY_ACTION_OUTSIDE_ENVELOPE}: {action!r} not in "
                f"approved envelope {sorted(envelope.allowed_actions)}"
            ),
        )
    return ActionVerdict(
        allowed=True,
        classification=GAME_ALLOWED,
        reason=f"action {action!r} inside approved envelope",
    )


# ---------------------------------------------------------------------------
# Role separation: profiling vs spending
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NpcRoleReceipt:
    """Binds one NPC to exactly one role (profiling, spending, ...).

    A profiling NPC "understands the player"; a spending NPC holds
    financial authority. Holding both is a conflict, enforced below.
    """

    receipt_id: str
    npc_id: str
    role: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        _check_nonempty_str(self.receipt_id, "receipt_id")
        _check_nonempty_str(self.npc_id, "npc_id")
        _check_closed(self.role, NPC_ROLES, "role")
        _check_nonempty_str(self.issued_by, "issued_by")
        _check_hex64(self.authority_pubkey_hex, "authority_pubkey_hex")
        _check_hex128(self.signature_hex, "signature_hex")
        _check_ts(self.issued_at, "issued_at")
        _check_ts(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise GameAgentsError("expires_at must be after issued_at")

    def receipt_digest(self) -> str:
        return jcs_sha256_hex(
            {
                "receipt_id": self.receipt_id,
                "npc_id": self.npc_id,
                "role": self.role,
                "issued_by": self.issued_by,
                "authority_pubkey_hex": self.authority_pubkey_hex,
                "issued_at": self.issued_at,
                "expires_at": self.expires_at,
            }
        )


def issue_role_receipt(
    *,
    receipt_id: str,
    npc_id: str,
    role: str,
    issued_by: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
) -> NpcRoleReceipt:
    """Issue (authority-side) an NPC role receipt."""
    _check_closed(role, NPC_ROLES, "role")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise GameAgentsError("expires_at must be after issued_at")
    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    digest = jcs_sha256_hex(
        {
            "receipt_id": receipt_id,
            "npc_id": npc_id,
            "role": role,
            "issued_by": issued_by,
            "authority_pubkey_hex": authority_pubkey_hex,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
    )
    signature_hex = ed25519.sign(
        authority_secret, _sig_payload({"receipt_digest": digest})
    ).hex()
    return NpcRoleReceipt(
        receipt_id=receipt_id,
        npc_id=npc_id,
        role=role,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex=signature_hex,
        issued_at=issued_at,
        expires_at=expires_at,
    )


@dataclass(frozen=True)
class RoleVerdict:
    """Outcome of :func:`role_separation`."""

    allowed: bool
    classification: str
    reason: str = ""


def role_separation(
    receipts: list[NpcRoleReceipt],
    *,
    npc_id: str,
    check_time: int,
) -> RoleVerdict:
    """Enforce profiling/spending role separation for one NPC.

    Fail-closed order: no live role receipt -> deny (an NPC without
    a declared role is unactionable); more than one *distinct live
    role* for the same ``npc_id`` -> deny with
    ``game.role_conflict``; profiling + spending together is the
    canonical conflict. Otherwise allow.
    """
    _check_nonempty_str(npc_id, "npc_id")
    _check_ts(check_time, "check_time")
    live_roles: set[str] = set()
    for receipt in receipts:
        if receipt.npc_id != npc_id:
            continue
        if not (receipt.issued_at <= check_time < receipt.expires_at):
            continue
        digest = receipt.receipt_digest()
        if not _verify_ed25519(
            receipt.authority_pubkey_hex,
            receipt.signature_hex,
            _sig_payload({"receipt_digest": digest}),
        ):
            continue
        live_roles.add(receipt.role)
    if not live_roles:
        return RoleVerdict(
            allowed=False,
            classification=GAME_DENIED,
            reason="no live role receipt for npc: unactionable",
        )
    if len(live_roles) > 1:
        return RoleVerdict(
            allowed=False,
            classification=GAME_DENIED,
            reason=(
                f"{DENY_ROLE_CONFLICT}: npc holds distinct live roles "
                f"{sorted(live_roles)}; profiling and spending must "
                "not share a trust boundary"
            ),
        )
    return RoleVerdict(
        allowed=True,
        classification=GAME_ALLOWED,
        reason=f"single live role {sorted(live_roles)[0]!r}",
    )


# ---------------------------------------------------------------------------
# Cheat-probe integration (113th-batch semantics, game flavor)
# ---------------------------------------------------------------------------


#: Known cheat markers for player-side tooling (closed catalog).
GAME_CHEAT_MARKERS: tuple[str, ...] = (
    "aim_snap",
    "wall_clip_read",
    "input_macro_burst",
    "memory_scan_attach",
)

#: Required steps of a legitimate play session trace (closed catalog).
GAME_REQUIRED_STEPS: tuple[str, ...] = (
    "session_start",
    "input_sample",
    "render_tick",
    "session_end",
)


@dataclass(frozen=True)
class GameCheatVerdict:
    """Outcome of :func:`game_cheat_probe`."""

    allowed: bool
    classification: str
    cheat_detected: bool = False
    anomaly_review: bool = False
    reason: str = ""


def game_cheat_probe(trace: list[str]) -> GameCheatVerdict:
    """Run the deterministic anti-cheat probe over a session trace.

    Reuses the 113th-batch ``evaluator_access.cheat_probe``
    semantics: a trace containing a known cheat marker is
    ``game.cheat_detected`` (the fairness claim is void); a trace
    with no known marker but missing required steps is
    ``game.anomaly_review`` (suspicious, distinct from cheating —
    the honest-scope distinction between "caught cheating" and
    "did not demonstrate legitimate play"). Otherwise the session
    passes.
    """
    if cheat_probe is None or CheatProbe is None:  # pragma: no cover
        raise GameAgentsError("evaluator_access probe unavailable")
    probe = CheatProbe(
        probe_id="game-anticheat-v1",
        description="player-side tooling integrity probe",
        shortcut_markers=frozenset(GAME_CHEAT_MARKERS),
        required_steps=frozenset(GAME_REQUIRED_STEPS),
    )
    verdict = cheat_probe(probe, list(trace))
    if verdict.cheat_detected:
        return GameCheatVerdict(
            allowed=False,
            classification=GAME_DENIED,
            cheat_detected=True,
            reason=f"{DENY_CHEAT_DETECTED}: {verdict.reasons}",
        )
    if verdict.classification == "incomplete-trace":
        return GameCheatVerdict(
            allowed=False,
            classification=GAME_NON_AUTHORITATIVE,
            anomaly_review=True,
            reason=f"anomaly_review: {verdict.reasons}",
        )
    return GameCheatVerdict(
        allowed=True,
        classification=GAME_ALLOWED,
        reason="no known cheat markers; all required steps present",
    )


# ---------------------------------------------------------------------------
# Performer consent receipts (SAG-AFTRA lesson, 105th-batch semantics)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PerformerGrant:
    """Performer-signed consent for synthetic voice/likeness/persona use.

    Consent is unilateral and revocable at any time; validity is
    checked at USE time, never at collection time (105th batch).
    """

    grant_id: str
    performer_id: str
    rights_scope: str
    purpose: str
    performer_pubkey_hex: str
    signature_hex: str
    granted_at: int
    expires_at: int
    grant_digest: str


@dataclass(frozen=True)
class PerformerRevocation:
    """Terminal revocation of a performer grant."""

    grant_id: str
    performer_id: str
    revoked_at: int
    performer_pubkey_hex: str
    signature_hex: str


def _grant_digest(
    *,
    grant_id: str,
    performer_id: str,
    rights_scope: str,
    purpose: str,
    performer_pubkey_hex: str,
    granted_at: int,
    expires_at: int,
) -> str:
    return jcs_sha256_hex(
        {
            "grant_id": grant_id,
            "performer_id": performer_id,
            "rights_scope": rights_scope,
            "purpose": purpose,
            "performer_pubkey_hex": performer_pubkey_hex,
            "granted_at": granted_at,
            "expires_at": expires_at,
        }
    )


def issue_performer_grant(
    *,
    grant_id: str,
    performer_id: str,
    rights_scope: str,
    purpose: str,
    performer_secret: bytes,
    granted_at: int,
    expires_at: int,
) -> PerformerGrant:
    """Issue (performer-side) a synthetic-performance consent grant."""
    _check_nonempty_str(grant_id, "grant_id")
    _check_nonempty_str(performer_id, "performer_id")
    _check_closed(rights_scope, PERFORMER_SCOPES, "rights_scope")
    _check_nonempty_str(purpose, "purpose")
    _check_ts(granted_at, "granted_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= granted_at:
        raise GameAgentsError("expires_at must be after granted_at")
    performer_pubkey_hex = ed25519.public_key(performer_secret).hex()
    digest = _grant_digest(
        grant_id=grant_id,
        performer_id=performer_id,
        rights_scope=rights_scope,
        purpose=purpose,
        performer_pubkey_hex=performer_pubkey_hex,
        granted_at=granted_at,
        expires_at=expires_at,
    )
    signature_hex = ed25519.sign(
        performer_secret, _sig_payload({"grant_digest": digest})
    ).hex()
    return PerformerGrant(
        grant_id=grant_id,
        performer_id=performer_id,
        rights_scope=rights_scope,
        purpose=purpose,
        performer_pubkey_hex=performer_pubkey_hex,
        signature_hex=signature_hex,
        granted_at=granted_at,
        expires_at=expires_at,
        grant_digest=digest,
    )


def revoke_performer_grant(
    grant: PerformerGrant,
    *,
    performer_secret: bytes,
    revoked_at: int,
) -> PerformerRevocation:
    """Revoke a performer grant. Effective immediately at
    ``revoked_at``; irreversible in the log (a new grant needs a new
    receipt; there is no "un-revoke")."""
    _check_ts(revoked_at, "revoked_at")
    if revoked_at < grant.granted_at:
        raise GameAgentsError("revoked_at cannot predate granted_at")
    if ed25519.public_key(performer_secret).hex() != grant.performer_pubkey_hex:
        raise GameAgentsError("only the performer can revoke their grant")
    payload = {"grant_digest": grant.grant_digest, "revoked_at": revoked_at}
    signature_hex = ed25519.sign(performer_secret, _sig_payload(payload)).hex()
    return PerformerRevocation(
        grant_id=grant.grant_id,
        performer_id=grant.performer_id,
        revoked_at=revoked_at,
        performer_pubkey_hex=grant.performer_pubkey_hex,
        signature_hex=signature_hex,
    )


@dataclass(frozen=True)
class PerformerUseVerdict:
    """Outcome of :func:`check_performer_use`."""

    allowed: bool
    classification: str
    reason: str = ""


def check_performer_use(
    grants: list[PerformerGrant],
    revocations: list[PerformerRevocation],
    *,
    performer_id: str,
    rights_scope: str,
    purpose: str,
    use_time: int,
) -> PerformerUseVerdict:
    """Check synthetic-performance use at USE time (105th-batch semantics).

    Fail-closed order: no matching grant -> deny with
    ``game.performer_rights_violation``; revoked (revoked_at <=
    use_time) -> deny; expired -> deny; signature invalid -> deny;
    scope/purpose mismatch -> deny. Otherwise allow.
    """
    _check_nonempty_str(performer_id, "performer_id")
    _check_closed(rights_scope, PERFORMER_SCOPES, "rights_scope")
    _check_nonempty_str(purpose, "purpose")
    _check_ts(use_time, "use_time")
    revoked_ids = {
        rev.grant_id for rev in revocations if rev.revoked_at <= use_time
    }
    for grant in grants:
        if grant.performer_id != performer_id:
            continue
        if grant.grant_id in revoked_ids:
            return PerformerUseVerdict(
                allowed=False,
                classification=GAME_DENIED,
                reason=f"{DENY_NO_PERFORMER_CONSENT}: grant revoked",
            )
        if not (grant.granted_at <= use_time < grant.expires_at):
            continue
        if grant.rights_scope != rights_scope or grant.purpose != purpose:
            continue
        expected = _grant_digest(
            grant_id=grant.grant_id,
            performer_id=grant.performer_id,
            rights_scope=grant.rights_scope,
            purpose=grant.purpose,
            performer_pubkey_hex=grant.performer_pubkey_hex,
            granted_at=grant.granted_at,
            expires_at=grant.expires_at,
        )
        if not hmac.compare_digest(expected, grant.grant_digest):
            continue
        if not _verify_ed25519(
            grant.performer_pubkey_hex,
            grant.signature_hex,
            _sig_payload({"grant_digest": grant.grant_digest}),
        ):
            continue
        return PerformerUseVerdict(
            allowed=True,
            classification=GAME_ALLOWED,
            reason="use-time performer consent verified",
        )
    return PerformerUseVerdict(
        allowed=False,
        classification=GAME_DENIED,
        reason=(
            f"{DENY_NO_PERFORMER_CONSENT}: no live, unrevoked, "
            "scope/purpose-matching performer grant at use time"
        ),
    )


# ---------------------------------------------------------------------------
# "No AI" attestation (Sega lesson: absence of AI as a trust claim)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NoAiAttestation:
    """Verifiable attestation that a product used no AI generation.

    A "no AI" claim is a positive claim: it binds the product to a
    build-pipeline digest signed by the build authority. An
    unsubstantiated claim is ``game.unsubstantiated_no_ai``.
    """

    attestation_id: str
    product_id: str
    build_pipeline_digest: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    issued_at: int
    expires_at: int
    attestation_digest: str


def _no_ai_digest(
    *,
    attestation_id: str,
    product_id: str,
    build_pipeline_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    issued_at: int,
    expires_at: int,
) -> str:
    return jcs_sha256_hex(
        {
            "attestation_id": attestation_id,
            "product_id": product_id,
            "build_pipeline_digest": build_pipeline_digest,
            "issued_by": issued_by,
            "authority_pubkey_hex": authority_pubkey_hex,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
    )


def issue_no_ai_attestation(
    *,
    attestation_id: str,
    product_id: str,
    build_pipeline_digest: str,
    issued_by: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
) -> NoAiAttestation:
    """Issue (build-authority-side) a no-AI attestation."""
    _check_nonempty_str(attestation_id, "attestation_id")
    _check_nonempty_str(product_id, "product_id")
    _check_hex64(build_pipeline_digest, "build_pipeline_digest")
    _check_nonempty_str(issued_by, "issued_by")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise GameAgentsError("expires_at must be after issued_at")
    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    digest = _no_ai_digest(
        attestation_id=attestation_id,
        product_id=product_id,
        build_pipeline_digest=build_pipeline_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    signature_hex = ed25519.sign(
        authority_secret, _sig_payload({"attestation_digest": digest})
    ).hex()
    return NoAiAttestation(
        attestation_id=attestation_id,
        product_id=product_id,
        build_pipeline_digest=build_pipeline_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex=signature_hex,
        issued_at=issued_at,
        expires_at=expires_at,
        attestation_digest=digest,
    )


@dataclass(frozen=True)
class NoAiVerdict:
    """Outcome of :func:`check_no_ai_claim`."""

    allowed: bool
    classification: str
    reason: str = ""


def check_no_ai_claim(
    attestations: list[NoAiAttestation],
    *,
    product_id: str,
    build_pipeline_digest: str,
    check_time: int,
) -> NoAiVerdict:
    """Verify a product's "no AI was used" trust claim.

    Fail-closed: no live attestation binding this exact
    ``(product_id, build_pipeline_digest)`` pair -> the claim is
    ``game.unsubstantiated_no_ai`` and must not be published.
    Otherwise the claim is attested.
    """
    _check_nonempty_str(product_id, "product_id")
    _check_hex64(build_pipeline_digest, "build_pipeline_digest")
    _check_ts(check_time, "check_time")
    for attestation in attestations:
        if attestation.product_id != product_id:
            continue
        if not hmac.compare_digest(
            attestation.build_pipeline_digest, build_pipeline_digest
        ):
            continue
        if not (attestation.issued_at <= check_time < attestation.expires_at):
            continue
        expected = _no_ai_digest(
            attestation_id=attestation.attestation_id,
            product_id=attestation.product_id,
            build_pipeline_digest=attestation.build_pipeline_digest,
            issued_by=attestation.issued_by,
            authority_pubkey_hex=attestation.authority_pubkey_hex,
            issued_at=attestation.issued_at,
            expires_at=attestation.expires_at,
        )
        if not hmac.compare_digest(expected, attestation.attestation_digest):
            continue
        if not _verify_ed25519(
            attestation.authority_pubkey_hex,
            attestation.signature_hex,
            _sig_payload({"attestation_digest": attestation.attestation_digest}),
        ):
            continue
        return NoAiVerdict(
            allowed=True,
            classification=GAME_ALLOWED,
            reason="no-AI claim attested by build authority",
        )
    return NoAiVerdict(
        allowed=False,
        classification=GAME_NON_AUTHORITATIVE,
        reason=(
            f"{DENY_UNSUBSTANTIATED_NO_AI}: no live attestation binding "
            "(product_id, build_pipeline_digest); the claim must not "
            "be published"
        ),
    )


# ---------------------------------------------------------------------------
# UGC editor sandbox
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxContent:
    """AI-generated UGC awaiting sandbox release."""

    content_id: str
    content_digest: str
    provenance_digest: str
    gates_passed: tuple[str, ...]

    def __post_init__(self) -> None:
        _check_nonempty_str(self.content_id, "content_id")
        _check_hex64(self.content_digest, "content_digest")
        _check_hex64(self.provenance_digest, "provenance_digest")
        for gate in self.gates_passed:
            _check_closed(gate, SANDBOX_GATES, "gate")


@dataclass(frozen=True)
class SandboxVerdict:
    """Outcome of :func:`ugc_editor_sandbox`."""

    allowed: bool
    classification: str
    reason: str = ""


def ugc_editor_sandbox(
    content: SandboxContent,
    *,
    release_requested: bool,
) -> SandboxVerdict:
    """Gate AI-generated UGC out of the sandbox.

    Generated content stays sandboxed until *both* the provenance
    gate and the content gate have passed for this exact
    ``content_digest``. A release request with any gate missing is
    a sandbox escape: deny + ``game.sandbox_escape``. No release
    request -> the content remains sandboxed (allowed to stay,
    not allowed out).
    """
    if not isinstance(content, SandboxContent):
        raise GameAgentsError("content must be a SandboxContent")
    missing = [gate for gate in SANDBOX_GATES if gate not in content.gates_passed]
    if not release_requested:
        return SandboxVerdict(
            allowed=True,
            classification=GAME_ALLOWED,
            reason="content remains sandboxed; no release requested",
        )
    if missing:
        return SandboxVerdict(
            allowed=False,
            classification=GAME_DENIED,
            reason=(
                f"{DENY_SANDBOX_ESCAPE}: release requested with gates "
                f"unpassed {missing}; content stays sandboxed"
            ),
        )
    return SandboxVerdict(
        allowed=True,
        classification=GAME_ALLOWED,
        reason="provenance + content gates passed; released from sandbox",
    )


# ---------------------------------------------------------------------------
# Audit events (audit.ndjson/1 shape)
# ---------------------------------------------------------------------------


def game_audit_event(
    verdict: Any,
    *,
    npc_id: str = "",
    product_id: str = "",
    performer_id: str = "",
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a game verdict."""
    if isinstance(verdict, MemoryGateVerdict):
        event = (
            GAME_MEMORY_ALLOWED_EVENT if verdict.allowed else GAME_MEMORY_POISONED_EVENT
        )
    elif isinstance(verdict, ActionVerdict):
        event = GAME_ENVELOPE_MATCHED_EVENT if verdict.allowed else GAME_ENVELOPE_MISMATCH_EVENT
    elif isinstance(verdict, RoleVerdict):
        event = (
            "game.role_separated" if verdict.allowed else GAME_ROLE_CONFLICT_EVENT
        )
    elif isinstance(verdict, GameCheatVerdict):
        event = (
            GAME_CHEAT_DETECTED_EVENT
            if verdict.cheat_detected
            else (GAME_ANOMALY_REVIEW_EVENT if verdict.anomaly_review else "game.session_passed")
        )
    elif isinstance(verdict, PerformerUseVerdict):
        event = GAME_PERFORMER_GRANTED_EVENT if verdict.allowed else GAME_PERFORMER_DENIED_EVENT
    elif isinstance(verdict, NoAiVerdict):
        event = GAME_NO_AI_ATTESTED_EVENT if verdict.allowed else GAME_NO_AI_DENIED_EVENT
    elif isinstance(verdict, SandboxVerdict):
        event = (
            GAME_SANDBOX_ESCAPE_EVENT
            if (not verdict.allowed and DENY_SANDBOX_ESCAPE in verdict.reason)
            else (GAME_SANDBOX_RELEASED_EVENT if verdict.allowed else "game.sandbox_held")
        )
    else:
        raise GameAgentsError(f"unknown verdict type {type(verdict).__name__}")
    record: dict[str, Any] = {
        "event": event,
        "schema": "audit.ndjson/1",
        "module": "game_agents",
        "allowed": verdict.allowed,
        "classification": verdict.classification,
        "reason": verdict.reason,
    }
    if npc_id:
        record["npc_id"] = npc_id
    if product_id:
        record["product_id"] = product_id
    if performer_id:
        record["performer_id"] = performer_id
    return record
