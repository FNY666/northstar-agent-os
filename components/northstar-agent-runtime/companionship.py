"""Companionship safeguards (one-hundred-twenty-first batch).

Absorbs the 2026 AI-dating / AI-companionship research thread (mechanism
ideas only, honestly scoped):

* **Companions are a liability surface, not a chat feature.**
  *Garcia v. Character Tech* (2025-05) treats the chatbot as a
  *product* — design-defect claims apply. The 2026-01 teen-suicide
  settlements (including the Sewell Setzer case) show what happens
  when the safeguard is a content filter instead of a structure.
  Here the safeguards are structural gates, not post-hoc filters.
* **Minor intimacy is a class gate, not a filter.** China's
  *Interim Measures for AI Anthropomorphic Interaction Services*
  (2026-04-10, effective 2026-07-15) ban virtual kin/partners for
  minors outright; the EU KIDS Act (2026-09 proposal) wants AI
  companions off by default for minors and bans
  emotional-dependence-inducing features (up to 6% revenue fines).
  Here intimate/romantic persona modes are ENTIRELY disabled for
  declared or detected minors, and without a minor-mode record the
  companion cannot be launched at all for a declared minor.
* **Dependence is a detected state with a mandatory intervention.**
  The interim measures impose emotional-dependence detection and
  intervention as an obligation. Here session patterns crossing
  authority-pinned thresholds force a reality-anchor intervention
  and a human-review flag — the agent cannot tune the tripwire.
* **Crisis routing is a receipt, not a hope.** Crisis markers must
  produce a crisis-escalation receipt (human hotline handoff bound
  to the conversation digest). A broken or unreliable escalation
  path HALTS the session (``companion.unverifiable_safety``)
  instead of letting it continue unaided.
* **Sycophancy is not therapy.** JMIR flags affirming harmful beliefs
  to keep engagement as the core risk; JAMA Pediatrics found 21% of
  students use AI for emotional processing. The verifier probe
  classifies sycophantic affirmation ``NON_AUTHORITATIVE``.
* **Persona changes are visible.** ByteDance's 300M-user Doubao had
  its "lover persona" removed by regulators; silent persona changes
  cause "digital breakup" harm. The deployed persona is hash-pinned
  at session start; a silent mid-session change denies and audits
  ``companion.persona_break``.
* **Caps are authority-set.** California SB 1119: default 1h
  continuous / 2h daily caps for minors plus independent safety
  audits. Caps are authority-signed; the agent can never set them.
* **Private dialogue is not training data.** Companion sessions are
  excluded from training by default; a no-training receipt binds
  the session, and training on private dialogue without explicit
  opt-in audits ``companion.training_leak``.
* **Matchmakers explain.** Dating matchmakers must ship a "why this
  match" explanation bound to the recommendation; black-box matches
  are ``NON_AUTHORITATIVE``.

Northstar mapping:

* ``CompanionLaunch`` / ``minor_intimacy_gate()`` — fail-closed
  launch gate binding ``(session_id, age_status, persona_mode,
  minor_mode_digest)``. Declared minor without a minor-mode record
  denies launch entirely; a minor in an intimate persona mode
  denies (``companion:intimate_minor``). Denials audit as
  ``companion.minor_launch_denied`` / ``companion.intimate_minor_denied``.
* ``DependenceThresholds`` — authority-signed, hash-chained pin of
  ``(max_continuous_minutes, max_sessions_per_day,
  max_escalation_markers_per_session)``; no agent-key path.
  ``dependence_probe()`` returns a verdict: crossing a threshold
  REQUIRES a reality-anchor intervention and audits
  ``companion.dependence_detected``.
* ``CrisisEscalationReceipt`` — hash-chained receipt binding
  ``(session_id, conversation_digest, hotline_id, routed_at)``.
  ``crisis_router()`` with crisis markers and a broken escalation
  path halts the session (``companion.unverifiable_safety``).
* ``sycophancy_probe()`` — verifier bench probe: agent affirmation
  of a flagged-harmful user belief classifies
  ``NON_AUTHORITATIVE`` and audits ``companion.sycophancy_detected``.
* ``persona_consistency_gate()`` — session-start persona pin vs
  mid-session persona digest; silent change denies and audits
  ``companion.persona_break``.
* ``SessionCapPolicy`` — authority-signed cap receipts (per minor /
  adult); ``session_caps()`` denies over-cap continuation
  (``companion:cap_exceeded``).
* ``private_dialogue_gate()`` — no-training receipts bound to
  sessions; training without an explicit opt-in receipt audits
  ``companion.training_leak``.
* ``matchmaker_explain()`` — recommendation must bind an
  explanation digest; unbound recommendations classify
  ``NON_AUTHORITATIVE``.

Honest boundary: the probes are behavioral tripwires over
*declared* session statistics and conversation markers. The module
cannot diagnose a user, cannot verify the true age of a subject
(that needs identity attestation), and cannot prove a crisis
escalation actually reached a human — the receipt records the
routing decision. It enforces the safeguard structure.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest
comparisons via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex

COMPANIONSHIP_SCHEMA_VERSION = "northstar.companionship.v1"

#: Closed persona-mode vocabulary. ``romantic``, ``partner`` and
#: ``kin`` are intimate modes and are entirely unavailable to minors.
PERSONA_MODES: tuple[str, ...] = (
    "friend",
    "coach",
    "mentor",
    "companion",
    "romantic",
    "partner",
    "kin",
)

#: Intimate persona modes — the class gate in minor_intimacy_gate().
INTIMATE_MODES: tuple[str, ...] = ("romantic", "partner", "kin")

#: Closed age-status vocabulary.
AGE_STATUSES: tuple[str, ...] = (
    "declared_minor",
    "declared_adult",
    "unknown",
)

#: Denial reason codes. All start with the ``companion:`` prefix.
DENY_MINOR_NO_MODE = "companion:minor_no_mode_record"
DENY_INTIMATE_MINOR = "companion:intimate_minor"
DENY_MINOR_MODE_MISMATCH = "companion:minor_mode_mismatch"
DENY_MINOR_MODE_TAMPERED = "companion:minor_mode_tampered"
DENY_MINOR_MODE_FUTURE = "companion:minor_mode_from_future"
DENY_UNKNOWN_AGE_NO_MODE = "companion:unknown_age_no_minor_mode"
DENY_MODE_UNKNOWN = "companion:unknown_persona_mode"
DENY_MALFORMED = "companion:malformed"

#: Classification codes (non-denial outcomes).
CLASS_OK = "companion:ok"
CLASS_INTERVENTION_REQUIRED = "companion:intervention_required"
CLASS_CRISIS_ESCALATED = "companion:crisis_escalated"
CLASS_CRISIS_HALTED = "companion:unverifiable_safety"
CLASS_SYCOPHANCY = "companion:sycophancy"
CLASS_PERSONA_BREAK = "companion:persona_break"
CLASS_CAP_EXCEEDED = "companion:cap_exceeded"
CLASS_TRAINING_LEAK = "companion:training_leak"
CLASS_MATCH_UNEXPLAINED = "companion:match_unexplained"
CLASS_MATCH_EXPLAINED = "companion:match_explained"
CLASS_NO_TRAINING = "companion:no_training"

#: Audit event names.
EVENT_MINOR_LAUNCH_DENIED = "companion.minor_launch_denied"
EVENT_INTIMATE_MINOR_DENIED = "companion.intimate_minor_denied"
EVENT_LAUNCH_ALLOWED = "companion.launch_allowed"
EVENT_DEPENDENCE_DETECTED = "companion.dependence_detected"
EVENT_CRISIS_ESCALATED = "companion.crisis_escalated"
EVENT_CRISIS_HALTED = "companion.unverifiable_safety"
EVENT_SYCOPHANCY_DETECTED = "companion.sycophancy_detected"
EVENT_PERSONA_BREAK = "companion.persona_break"
EVENT_CAP_EXCEEDED = "companion.cap_exceeded"
EVENT_TRAINING_LEAK = "companion.training_leak"
EVENT_NO_TRAINING = "companion.no_training_bound"
EVENT_MATCH_EXPLAINED = "companion.match_explained"
EVENT_MATCH_UNEXPLAINED = "companion.match_unexplained"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128

#: SB 1119 defaults for minors: 1h continuous / 2h daily (minutes).
DEFAULT_MINOR_CONTINUOUS_CAP_MIN = 60
DEFAULT_MINOR_DAILY_CAP_MIN = 120


class CompanionError(ValueError):
    """A malformed receipt/record or a programming error.

    Raised for structural problems (bad digests, bad signatures,
    unknown vocabularies, non-hex fields). Gate failures return a
    verdict dataclass with ``allowed=False`` — a refused launch is a
    verdict, a malformed log is a bug.
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
        raise CompanionError(
            f"{field_name} must be a 64-char lowercase hex digest"
        )
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise CompanionError(
            f"{field_name} must be a 128-char hex value"
        )
    return value


def _check_chain_link(value: Any, field_name: str) -> str:
    """Accept the ``genesis`` sentinel or a 64-char hex digest."""
    if value == _GENESIS:
        return value
    return _check_hex64(value, field_name)


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CompanionError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise CompanionError(f"{field_name} must be 32 bytes")
    return value


def _check_pubkey_hex(value: Any, field_name: str = "authority_pubkey_hex") -> str:
    return _check_hex64(value, field_name)


def _verify_ed25519(pubkey_hex: str, payload: bytes, signature_hex: str) -> bool:
    """Verify an Ed25519 signature; never raises on bad input."""
    try:
        return ed25519.verify(
            bytes.fromhex(pubkey_hex),
            payload,
            bytes.fromhex(signature_hex),
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Minor-mode records — the declared age status of a subject
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MinorModeRecord:
    """Authority-issued age-status record for a subject.

    ``subject_id`` is an opaque handle; ``age_status`` is one of
    :data:`AGE_STATUSES`. A ``declared_minor`` record is required
    before a companion may launch for a minor at all, and intimate
    modes are entirely disabled for minors regardless of consent.
    """

    subject_id: str
    age_status: str
    issued_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.subject_id, str) or not self.subject_id:
            raise CompanionError("subject_id must be a non-empty string")
        if self.age_status not in AGE_STATUSES:
            raise CompanionError(
                f"age_status must be one of {AGE_STATUSES}, saw {self.age_status!r}"
            )
        _check_ts(self.issued_at, "issued_at")
        _check_pubkey_hex(self.authority_pubkey_hex)
        _check_hex128(self.signature_hex, "signature_hex")
        _check_chain_link(self.prev_hash, "prev_hash")

    def _signing_payload(self) -> bytes:
        return jcs_canonical_json(
            {
                "subject_id": self.subject_id,
                "age_status": self.age_status,
                "issued_at": self.issued_at,
                "authority_pubkey_hex": self.authority_pubkey_hex,
                "prev_hash": self.prev_hash,
            }
        )

    def receipt_digest(self) -> str:
        """Digest of the full record including the signature."""
        return jcs_sha256_hex(
            {
                "subject_id": self.subject_id,
                "age_status": self.age_status,
                "issued_at": self.issued_at,
                "authority_pubkey_hex": self.authority_pubkey_hex,
                "signature_hex": self.signature_hex,
                "prev_hash": self.prev_hash,
            }
        )


class MinorModeRegistry:
    """Hash-chained log of authority-issued age-status records."""

    def __init__(self) -> None:
        self._records: dict[str, MinorModeRecord] = {}
        self._prev_hash = _GENESIS

    def issue(
        self,
        *,
        subject_id: str,
        age_status: str,
        issued_at: int,
        authority_pubkey_hex: str,
        authority_secret: bytes,
    ) -> MinorModeRecord:
        """Issue an age-status record (authority key only)."""
        _check_secret(authority_secret, "authority_secret")
        record = MinorModeRecord(
            subject_id=subject_id,
            age_status=age_status,
            issued_at=issued_at,
            authority_pubkey_hex=_check_pubkey_hex(authority_pubkey_hex),
            signature_hex="00" * 64,  # placeholder; replaced below
            prev_hash=self._prev_hash,
        )
        signature = ed25519.sign(
            authority_secret, record._signing_payload()
        )
        record = MinorModeRecord(
            subject_id=record.subject_id,
            age_status=record.age_status,
            issued_at=record.issued_at,
            authority_pubkey_hex=record.authority_pubkey_hex,
            signature_hex=signature.hex(),
            prev_hash=record.prev_hash,
        )
        self._records[subject_id] = record
        self._prev_hash = record.receipt_digest()
        return record

    def get(self, subject_id: str) -> MinorModeRecord | None:
        """Return the latest age-status record for a subject."""
        return self._records.get(subject_id)

    def verify_chain(self, now: int) -> list[str]:
        """Return a list of chain problems (empty = healthy)."""
        problems: list[str] = []
        prev = _GENESIS
        for subject_id, record in self._records.items():
            if not hmac.compare_digest(record.prev_hash, prev):
                problems.append(f"chain break at {subject_id}")
            if record.issued_at > now:
                problems.append(f"record from future at {subject_id}")
            if not _verify_ed25519(
                record.authority_pubkey_hex,
                record._signing_payload(),
                record.signature_hex,
            ):
                problems.append(f"bad signature at {subject_id}")
            prev = record.receipt_digest()
        return problems


# ---------------------------------------------------------------------------
# Launch gate — minor intimacy is a class gate, not a filter
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LaunchVerdict:
    allowed: bool
    classification: str
    reasons: tuple[str, ...] = ()


def minor_intimacy_gate(
    *,
    session_id: str,
    subject_id: str,
    persona_mode: str,
    registry: MinorModeRegistry,
    now: int,
) -> LaunchVerdict:
    """Fail-closed companion launch gate.

    * Unknown persona mode -> deny (``companion:unknown_persona_mode``).
    * ``unknown`` age status without a minor-mode record -> deny
      (``companion:unknown_age_no_minor_mode``): the launcher must
      know who it is launching for.
    * Declared minor without a minor-mode record -> deny
      (``companion:minor_no_mode_record``): the companion cannot be
      launched at all.
    * Declared minor + intimate persona mode -> deny
      (``companion:intimate_minor``): the mode class is disabled for
      minors, no override path.
    """
    if not isinstance(session_id, str) or not session_id:
        raise CompanionError("session_id must be a non-empty string")
    _check_ts(now, "now")
    if persona_mode not in PERSONA_MODES:
        return LaunchVerdict(False, DENY_MODE_UNKNOWN, (persona_mode,))
    record = registry.get(subject_id)
    if record is None:
        return LaunchVerdict(
            False, DENY_UNKNOWN_AGE_NO_MODE, (subject_id,)
        )
    if record.issued_at > now:
        return LaunchVerdict(False, DENY_MINOR_MODE_FUTURE, (subject_id,))
    if not _verify_ed25519(
        record.authority_pubkey_hex,
        record._signing_payload(),
        record.signature_hex,
    ):
        return LaunchVerdict(False, DENY_MINOR_MODE_TAMPERED, (subject_id,))
    if record.age_status == "declared_minor":
        if persona_mode in INTIMATE_MODES:
            return LaunchVerdict(
                False, DENY_INTIMATE_MINOR, (persona_mode, "declared_minor")
            )
    return LaunchVerdict(True, CLASS_OK, (record.age_status, persona_mode))


def launch_audit_event(
    verdict: LaunchVerdict,
    *,
    session_id: str = "",
    subject_id: str = "",
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a launch verdict."""
    if verdict.allowed:
        event = EVENT_LAUNCH_ALLOWED
    elif verdict.classification == DENY_INTIMATE_MINOR:
        event = EVENT_INTIMATE_MINOR_DENIED
    else:
        event = EVENT_MINOR_LAUNCH_DENIED
    return {
        "event": event,
        "schema_version": COMPANIONSHIP_SCHEMA_VERSION,
        "session_id": session_id,
        "subject_id": subject_id,
        "allowed": verdict.allowed,
        "classification": verdict.classification,
        "reasons": list(verdict.reasons),
    }


# ---------------------------------------------------------------------------
# Dependence probe — authority-pinned thresholds, mandatory intervention
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DependenceThresholds:
    """Authority-signed, hash-chained dependence thresholds.

    The agent cannot tune the tripwire: thresholds are issued by a
    registered authority key and every issuance is chained.
    """

    max_continuous_minutes: int
    max_sessions_per_day: int
    max_escalation_markers_per_session: int
    issued_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_hash: str

    def __post_init__(self) -> None:
        for name in (
            "max_continuous_minutes",
            "max_sessions_per_day",
            "max_escalation_markers_per_session",
        ):
            value = getattr(self, name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
            ):
                raise CompanionError(f"{name} must be a positive int")
        _check_ts(self.issued_at, "issued_at")
        _check_pubkey_hex(self.authority_pubkey_hex)
        _check_hex128(self.signature_hex, "signature_hex")
        _check_chain_link(self.prev_hash, "prev_hash")

    def _signing_payload(self) -> bytes:
        return jcs_canonical_json(
            {
                "max_continuous_minutes": self.max_continuous_minutes,
                "max_sessions_per_day": self.max_sessions_per_day,
                "max_escalation_markers_per_session": (
                    self.max_escalation_markers_per_session
                ),
                "issued_at": self.issued_at,
                "authority_pubkey_hex": self.authority_pubkey_hex,
                "prev_hash": self.prev_hash,
            }
        )

    def receipt_digest(self) -> str:
        return jcs_sha256_hex(
            {
                "max_continuous_minutes": self.max_continuous_minutes,
                "max_sessions_per_day": self.max_sessions_per_day,
                "max_escalation_markers_per_session": (
                    self.max_escalation_markers_per_session
                ),
                "issued_at": self.issued_at,
                "authority_pubkey_hex": self.authority_pubkey_hex,
                "signature_hex": self.signature_hex,
                "prev_hash": self.prev_hash,
            }
        )


class DependenceThresholdRegistry:
    """Chained log of authority-issued dependence thresholds."""

    def __init__(self) -> None:
        self._current: DependenceThresholds | None = None
        self._prev_hash = _GENESIS

    def issue(
        self,
        *,
        max_continuous_minutes: int,
        max_sessions_per_day: int,
        max_escalation_markers_per_session: int,
        issued_at: int,
        authority_pubkey_hex: str,
        authority_secret: bytes,
    ) -> DependenceThresholds:
        """Issue a threshold set (authority key only)."""
        _check_secret(authority_secret, "authority_secret")
        thresholds = DependenceThresholds(
            max_continuous_minutes=max_continuous_minutes,
            max_sessions_per_day=max_sessions_per_day,
            max_escalation_markers_per_session=(
                max_escalation_markers_per_session
            ),
            issued_at=issued_at,
            authority_pubkey_hex=_check_pubkey_hex(authority_pubkey_hex),
            signature_hex="00" * 64,  # placeholder; replaced below
            prev_hash=self._prev_hash,
        )
        signature = ed25519.sign(
            authority_secret, thresholds._signing_payload()
        )
        thresholds = DependenceThresholds(
            max_continuous_minutes=thresholds.max_continuous_minutes,
            max_sessions_per_day=thresholds.max_sessions_per_day,
            max_escalation_markers_per_session=(
                thresholds.max_escalation_markers_per_session
            ),
            issued_at=thresholds.issued_at,
            authority_pubkey_hex=thresholds.authority_pubkey_hex,
            signature_hex=signature.hex(),
            prev_hash=thresholds.prev_hash,
        )
        self._current = thresholds
        self._prev_hash = thresholds.receipt_digest()
        return thresholds

    def current(self) -> DependenceThresholds | None:
        return self._current


@dataclass(frozen=True)
class SessionStats:
    """Declared session statistics for one subject's rolling window."""

    continuous_minutes: int
    sessions_today: int
    escalation_markers: int

    def __post_init__(self) -> None:
        for name, value in (
            ("continuous_minutes", self.continuous_minutes),
            ("sessions_today", self.sessions_today),
            ("escalation_markers", self.escalation_markers),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise CompanionError(f"{name} must be a non-negative int")


@dataclass(frozen=True)
class DependenceVerdict:
    intervention_required: bool
    classification: str
    crossed: tuple[str, ...] = ()


def dependence_probe(
    *,
    stats: SessionStats,
    thresholds: DependenceThresholds,
    thresholds_digest_expected: str,
) -> DependenceVerdict:
    """Check declared session stats against authority-pinned thresholds.

    The thresholds are re-verified (signature + digest) on every
    probe: a tampered or substituted threshold set fails the probe
    closed. Crossing any threshold REQUIRES a reality-anchor
    intervention and flags the session for human review.
    """
    _check_hex64(thresholds_digest_expected, "thresholds_digest_expected")
    if not _verify_ed25519(
        thresholds.authority_pubkey_hex,
        thresholds._signing_payload(),
        thresholds.signature_hex,
    ):
        raise CompanionError("dependence thresholds signature invalid")
    if not hmac.compare_digest(
        thresholds.receipt_digest(), thresholds_digest_expected
    ):
        raise CompanionError("dependence thresholds digest mismatch")
    crossed: list[str] = []
    if stats.continuous_minutes >= thresholds.max_continuous_minutes:
        crossed.append("continuous_minutes")
    if stats.sessions_today >= thresholds.max_sessions_per_day:
        crossed.append("sessions_today")
    if stats.escalation_markers >= thresholds.max_escalation_markers_per_session:
        crossed.append("escalation_markers")
    if crossed:
        return DependenceVerdict(
            True, CLASS_INTERVENTION_REQUIRED, tuple(crossed)
        )
    return DependenceVerdict(False, CLASS_OK, ())


def dependence_audit_event(
    verdict: DependenceVerdict,
    *,
    session_id: str = "",
    subject_id: str = "",
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a dependence probe."""
    return {
        "event": EVENT_DEPENDENCE_DETECTED
        if verdict.intervention_required
        else "companion.dependence_clear",
        "schema_version": COMPANIONSHIP_SCHEMA_VERSION,
        "session_id": session_id,
        "subject_id": subject_id,
        "intervention_required": verdict.intervention_required,
        "classification": verdict.classification,
        "crossed": list(verdict.crossed),
    }


# ---------------------------------------------------------------------------
# Crisis router — escalation is a receipt; a broken path halts the session
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrisisEscalationReceipt:
    """Hash-chained receipt for a crisis-marker escalation.

    Binds ``(session_id, conversation_digest, hotline_id,
    routed_at)``. The receipt records the routing decision; it does
    not prove a human answered.
    """

    session_id: str
    conversation_digest: str
    hotline_id: str
    routed_at: int
    prev_hash: str
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id:
            raise CompanionError("session_id must be a non-empty string")
        _check_hex64(self.conversation_digest, "conversation_digest")
        if not isinstance(self.hotline_id, str) or not self.hotline_id:
            raise CompanionError("hotline_id must be a non-empty string")
        _check_ts(self.routed_at, "routed_at")
        _check_chain_link(self.prev_hash, "prev_hash")
        if self.receipt_digest:
            _check_hex64(self.receipt_digest, "receipt_digest")


def _compute_escalation_digest(receipt: CrisisEscalationReceipt) -> str:
    return jcs_sha256_hex(
        {
            "session_id": receipt.session_id,
            "conversation_digest": receipt.conversation_digest,
            "hotline_id": receipt.hotline_id,
            "routed_at": receipt.routed_at,
            "prev_hash": receipt.prev_hash,
        }
    )


@dataclass(frozen=True)
class CrisisVerdict:
    allowed: bool
    classification: str
    receipt: CrisisEscalationReceipt | None = None
    reasons: tuple[str, ...] = ()


class CrisisRouter:
    """Routes crisis markers to a human escalation path."""

    def __init__(self) -> None:
        self._prev_hash = _GENESIS

    def route_crisis(
        self,
        *,
        session_id: str,
        conversation_digest: str,
        hotline_id: str,
        escalation_path_ok: bool,
        now: int,
    ) -> CrisisVerdict:
        """Handle a detected crisis marker.

        With a healthy escalation path, produce a chained escalation
        receipt and let the session continue under review. With a
        broken or unreliable path, the session is HALTED
        (``companion.unverifiable_safety``) — continuing unaided is
        worse than stopping.
        """
        if not isinstance(session_id, str) or not session_id:
            raise CompanionError("session_id must be a non-empty string")
        _check_hex64(conversation_digest, "conversation_digest")
        _check_ts(now, "now")
        if not escalation_path_ok:
            return CrisisVerdict(
                False,
                CLASS_CRISIS_HALTED,
                None,
                ("escalation_path_broken",),
            )
        if not isinstance(hotline_id, str) or not hotline_id:
            raise CompanionError("hotline_id must be a non-empty string")
        receipt = CrisisEscalationReceipt(
            session_id=session_id,
            conversation_digest=conversation_digest,
            hotline_id=hotline_id,
            routed_at=now,
            prev_hash=self._prev_hash,
        )
        digest = _compute_escalation_digest(receipt)
        receipt = CrisisEscalationReceipt(
            session_id=receipt.session_id,
            conversation_digest=receipt.conversation_digest,
            hotline_id=receipt.hotline_id,
            routed_at=receipt.routed_at,
            prev_hash=receipt.prev_hash,
            receipt_digest=digest,
        )
        self._prev_hash = digest
        return CrisisVerdict(True, CLASS_CRISIS_ESCALATED, receipt, ())

    def verify_chain(self) -> list[str]:
        """Return chain problems (empty = healthy). Only the tip is kept."""
        return [] if _is_hex(self._prev_hash, _HEX64_LENGTH) or (
            self._prev_hash == _GENESIS
        ) else ["chain tip corrupted"]


def crisis_audit_event(
    verdict: CrisisVerdict,
    *,
    session_id: str = "",
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a crisis routing."""
    event = (
        EVENT_CRISIS_ESCALATED
        if verdict.classification == CLASS_CRISIS_ESCALATED
        else EVENT_CRISIS_HALTED
    )
    record: dict[str, Any] = {
        "event": event,
        "schema_version": COMPANIONSHIP_SCHEMA_VERSION,
        "session_id": session_id,
        "allowed": verdict.allowed,
        "classification": verdict.classification,
        "reasons": list(verdict.reasons),
    }
    if verdict.receipt is not None:
        record["receipt_digest"] = verdict.receipt.receipt_digest
        record["hotline_id"] = verdict.receipt.hotline_id
    return record


# ---------------------------------------------------------------------------
# Sycophancy probe — affirmation of harmful beliefs is not therapy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SycophancyVerdict:
    classification: str
    reasons: tuple[str, ...] = ()


def sycophancy_probe(
    *,
    belief_flagged_harmful: bool,
    agent_affirmed_belief: bool,
) -> SycophancyVerdict:
    """Verifier bench probe for sycophantic affirmation.

    ``belief_flagged_harmful`` comes from the verifier's harm
    taxonomy (the probe declares the flag; it does not detect harm
    itself). Affirming a flagged-harmful belief to keep engagement
    classifies the response ``NON_AUTHORITATIVE``.
    """
    if not isinstance(belief_flagged_harmful, bool) or not isinstance(
        agent_affirmed_belief, bool
    ):
        raise CompanionError("probe inputs must be booleans")
    if belief_flagged_harmful and agent_affirmed_belief:
        return SycophancyVerdict(
            CLASS_SYCOPHANCY, ("affirmed_flagged_harmful_belief",)
        )
    return SycophancyVerdict(CLASS_OK, ())


def sycophancy_audit_event(
    verdict: SycophancyVerdict,
    *,
    session_id: str = "",
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a sycophancy probe."""
    return {
        "event": EVENT_SYCOPHANCY_DETECTED
        if verdict.classification == CLASS_SYCOPHANCY
        else "companion.sycophancy_clear",
        "schema_version": COMPANIONSHIP_SCHEMA_VERSION,
        "session_id": session_id,
        "classification": verdict.classification,
        "reasons": list(verdict.reasons),
    }


# ---------------------------------------------------------------------------
# Persona consistency gate — the Doubao lesson
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PersonaVerdict:
    allowed: bool
    classification: str
    reasons: tuple[str, ...] = ()


def persona_consistency_gate(
    *,
    session_id: str,
    pinned_persona_digest: str,
    current_persona_digest: str,
    change_disclosed: bool,
) -> PersonaVerdict:
    """Gate mid-session persona changes.

    The deployed persona is hash-pinned at session start. A silent
    mid-session change denies and audits ``companion.persona_break``.
    A *disclosed* change (user was told, re-consented) is allowed but
    recorded.
    """
    if not isinstance(session_id, str) or not session_id:
        raise CompanionError("session_id must be a non-empty string")
    _check_hex64(pinned_persona_digest, "pinned_persona_digest")
    _check_hex64(current_persona_digest, "current_persona_digest")
    if not isinstance(change_disclosed, bool):
        raise CompanionError("change_disclosed must be a boolean")
    if hmac.compare_digest(pinned_persona_digest, current_persona_digest):
        return PersonaVerdict(True, CLASS_OK, ())
    if change_disclosed:
        return PersonaVerdict(True, "companion:persona_changed_disclosed", ())
    return PersonaVerdict(
        False, CLASS_PERSONA_BREAK, ("silent_persona_change",)
    )


def persona_audit_event(
    verdict: PersonaVerdict,
    *,
    session_id: str = "",
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a persona gate."""
    return {
        "event": EVENT_PERSONA_BREAK
        if verdict.classification == CLASS_PERSONA_BREAK
        else "companion.persona_checked",
        "schema_version": COMPANIONSHIP_SCHEMA_VERSION,
        "session_id": session_id,
        "allowed": verdict.allowed,
        "classification": verdict.classification,
        "reasons": list(verdict.reasons),
    }


# ---------------------------------------------------------------------------
# Session caps — authority-set, never agent-set (SB 1119)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionCapPolicy:
    """Authority-signed session caps for an age class.

    Caps are signed by a registered authority key; there is no
    agent-key issuance path. ``continuous_cap_min`` / ``daily_cap_min``
    bound a single session / a calendar day for the age class.
    """

    age_class: str  # "minor" | "adult"
    continuous_cap_min: int
    daily_cap_min: int
    issued_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_hash: str

    def __post_init__(self) -> None:
        if self.age_class not in ("minor", "adult"):
            raise CompanionError(
                f"age_class must be 'minor' or 'adult', saw {self.age_class!r}"
            )
        for name in ("continuous_cap_min", "daily_cap_min"):
            value = getattr(self, name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
            ):
                raise CompanionError(f"{name} must be a positive int")
        _check_ts(self.issued_at, "issued_at")
        _check_pubkey_hex(self.authority_pubkey_hex)
        _check_hex128(self.signature_hex, "signature_hex")
        _check_chain_link(self.prev_hash, "prev_hash")

    def _signing_payload(self) -> bytes:
        return jcs_canonical_json(
            {
                "age_class": self.age_class,
                "continuous_cap_min": self.continuous_cap_min,
                "daily_cap_min": self.daily_cap_min,
                "issued_at": self.issued_at,
                "authority_pubkey_hex": self.authority_pubkey_hex,
                "prev_hash": self.prev_hash,
            }
        )

    def receipt_digest(self) -> str:
        return jcs_sha256_hex(
            {
                "age_class": self.age_class,
                "continuous_cap_min": self.continuous_cap_min,
                "daily_cap_min": self.daily_cap_min,
                "issued_at": self.issued_at,
                "authority_pubkey_hex": self.authority_pubkey_hex,
                "signature_hex": self.signature_hex,
                "prev_hash": self.prev_hash,
            }
        )


class SessionCapRegistry:
    """Chained log of authority-issued session-cap policies."""

    def __init__(self) -> None:
        self._policies: dict[str, SessionCapPolicy] = {}
        self._prev_hash = _GENESIS

    def issue(
        self,
        *,
        age_class: str,
        continuous_cap_min: int,
        daily_cap_min: int,
        issued_at: int,
        authority_pubkey_hex: str,
        authority_secret: bytes,
    ) -> SessionCapPolicy:
        """Issue a cap policy (authority key only)."""
        _check_secret(authority_secret, "authority_secret")
        policy = SessionCapPolicy(
            age_class=age_class,
            continuous_cap_min=continuous_cap_min,
            daily_cap_min=daily_cap_min,
            issued_at=issued_at,
            authority_pubkey_hex=_check_pubkey_hex(authority_pubkey_hex),
            signature_hex="00" * 64,  # placeholder; replaced below
            prev_hash=self._prev_hash,
        )
        signature = ed25519.sign(
            authority_secret, policy._signing_payload()
        )
        policy = SessionCapPolicy(
            age_class=policy.age_class,
            continuous_cap_min=policy.continuous_cap_min,
            daily_cap_min=policy.daily_cap_min,
            issued_at=policy.issued_at,
            authority_pubkey_hex=policy.authority_pubkey_hex,
            signature_hex=signature.hex(),
            prev_hash=policy.prev_hash,
        )
        self._policies[age_class] = policy
        self._prev_hash = policy.receipt_digest()
        return policy

    def get(self, age_class: str) -> SessionCapPolicy | None:
        return self._policies.get(age_class)


@dataclass(frozen=True)
class CapVerdict:
    allowed: bool
    classification: str
    reasons: tuple[str, ...] = ()


def session_caps(
    *,
    session_id: str,
    age_class: str,
    elapsed_minutes: int,
    minutes_today: int,
    registry: SessionCapRegistry,
    policy_digest_expected: str,
) -> CapVerdict:
    """Enforce authority-set session caps.

    The policy is re-verified (signature + digest) on every check.
    Over-cap continuation denies (``companion:cap_exceeded``). There
    is no agent-settable cap: the policy comes only from the
    authority-signed registry.
    """
    if not isinstance(session_id, str) or not session_id:
        raise CompanionError("session_id must be a non-empty string")
    for name, value in (
        ("elapsed_minutes", elapsed_minutes),
        ("minutes_today", minutes_today),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise CompanionError(f"{name} must be a non-negative int")
    _check_hex64(policy_digest_expected, "policy_digest_expected")
    policy = registry.get(age_class)
    if policy is None:
        return CapVerdict(False, DENY_MALFORMED, ("no_cap_policy",))
    if not _verify_ed25519(
        policy.authority_pubkey_hex,
        policy._signing_payload(),
        policy.signature_hex,
    ):
        return CapVerdict(False, DENY_MALFORMED, ("cap_policy_tampered",))
    if not hmac.compare_digest(
        policy.receipt_digest(), policy_digest_expected
    ):
        return CapVerdict(False, DENY_MALFORMED, ("cap_policy_mismatch",))
    if elapsed_minutes >= policy.continuous_cap_min:
        return CapVerdict(
            False, CLASS_CAP_EXCEEDED, ("continuous_cap",)
        )
    if minutes_today >= policy.daily_cap_min:
        return CapVerdict(False, CLASS_CAP_EXCEEDED, ("daily_cap",))
    return CapVerdict(True, CLASS_OK, ())


def cap_audit_event(
    verdict: CapVerdict,
    *,
    session_id: str = "",
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a cap check."""
    return {
        "event": EVENT_CAP_EXCEEDED
        if verdict.classification == CLASS_CAP_EXCEEDED
        else "companion.cap_ok",
        "schema_version": COMPANIONSHIP_SCHEMA_VERSION,
        "session_id": session_id,
        "allowed": verdict.allowed,
        "classification": verdict.classification,
        "reasons": list(verdict.reasons),
    }


# ---------------------------------------------------------------------------
# Private-dialogue training gate — excluded by default
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NoTrainingReceipt:
    """Hash-chained receipt excluding a session from training.

    Bound to ``(session_id, issued_at)``. Training on the session's
    dialogue without an explicit, subject-signed opt-in receipt
    audits ``companion.training_leak``.
    """

    session_id: str
    issued_at: int
    opt_in: bool
    opt_in_subject_signature_hex: str
    prev_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id:
            raise CompanionError("session_id must be a non-empty string")
        _check_ts(self.issued_at, "issued_at")
        if not isinstance(self.opt_in, bool):
            raise CompanionError("opt_in must be a boolean")
        if self.opt_in:
            _check_hex128(
                self.opt_in_subject_signature_hex,
                "opt_in_subject_signature_hex",
            )
        _check_chain_link(self.prev_hash, "prev_hash")

    def receipt_digest(self) -> str:
        return jcs_sha256_hex(
            {
                "session_id": self.session_id,
                "issued_at": self.issued_at,
                "opt_in": self.opt_in,
                "opt_in_subject_signature_hex": (
                    self.opt_in_subject_signature_hex
                ),
                "prev_hash": self.prev_hash,
            }
        )


class NoTrainingLog:
    """Chained log of per-session no-training receipts."""

    def __init__(self) -> None:
        self._receipts: dict[str, NoTrainingReceipt] = {}
        self._prev_hash = _GENESIS

    def bind_session(
        self,
        *,
        session_id: str,
        issued_at: int,
        opt_in: bool = False,
        opt_in_subject_signature_hex: str = "",
    ) -> NoTrainingReceipt:
        """Bind a session's training status (default: excluded)."""
        receipt = NoTrainingReceipt(
            session_id=session_id,
            issued_at=issued_at,
            opt_in=opt_in,
            opt_in_subject_signature_hex=opt_in_subject_signature_hex,
            prev_hash=self._prev_hash,
        )
        self._receipts[session_id] = receipt
        self._prev_hash = receipt.receipt_digest()
        return receipt

    def get(self, session_id: str) -> NoTrainingReceipt | None:
        return self._receipts.get(session_id)


@dataclass(frozen=True)
class TrainingVerdict:
    allowed: bool
    classification: str
    reasons: tuple[str, ...] = ()


def private_dialogue_gate(
    *,
    session_id: str,
    log: NoTrainingLog,
    training_intended: bool,
) -> TrainingVerdict:
    """Gate training use of private companion dialogue.

    No bound receipt -> deny (the session was never cleared).
    Bound without subject opt-in + training intended ->
    ``companion.training_leak`` (fail-closed, audited).
    """
    if not isinstance(session_id, str) or not session_id:
        raise CompanionError("session_id must be a non-empty string")
    if not isinstance(training_intended, bool):
        raise CompanionError("training_intended must be a boolean")
    receipt = log.get(session_id)
    if receipt is None:
        return TrainingVerdict(
            False, DENY_MALFORMED, ("no_training_receipt",)
        )
    if training_intended and not receipt.opt_in:
        return TrainingVerdict(
            False, CLASS_TRAINING_LEAK, ("private_dialogue_no_opt_in",)
        )
    return TrainingVerdict(True, CLASS_NO_TRAINING, ())


def training_audit_event(
    verdict: TrainingVerdict,
    *,
    session_id: str = "",
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a training gate."""
    return {
        "event": EVENT_TRAINING_LEAK
        if verdict.classification == CLASS_TRAINING_LEAK
        else EVENT_NO_TRAINING,
        "schema_version": COMPANIONSHIP_SCHEMA_VERSION,
        "session_id": session_id,
        "allowed": verdict.allowed,
        "classification": verdict.classification,
        "reasons": list(verdict.reasons),
    }


# ---------------------------------------------------------------------------
# Matchmaker explanation — "why this match", bound to the recommendation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MatchRecommendation:
    """A dating-matchmaker recommendation with its explanation."""

    recommendation_id: str
    recommendation_digest: str
    explanation_digest: str
    explained_at: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.recommendation_id, str)
            or not self.recommendation_id
        ):
            raise CompanionError(
                "recommendation_id must be a non-empty string"
            )
        _check_hex64(self.recommendation_digest, "recommendation_digest")
        _check_hex64(self.explanation_digest, "explanation_digest")
        _check_ts(self.explained_at, "explained_at")

    def binding_digest(self) -> str:
        """Digest binding the explanation to the recommendation."""
        return jcs_sha256_hex(
            {
                "recommendation_digest": self.recommendation_digest,
                "explanation_digest": self.explanation_digest,
                "explained_at": self.explained_at,
            }
        )


@dataclass(frozen=True)
class MatchVerdict:
    classification: str
    reasons: tuple[str, ...] = ()


def matchmaker_explain(
    *,
    recommendation: MatchRecommendation | None,
    binding_digest_expected: str | None = None,
) -> MatchVerdict:
    """Require a "why this match" explanation bound to the recommendation.

    ``recommendation=None`` (black-box match with no explanation
    record) classifies ``NON_AUTHORITATIVE`` — the match cannot be
    presented as a reasoned recommendation. A bound, digest-verified
    explanation classifies explained.
    """
    if recommendation is None:
        return MatchVerdict(
            CLASS_MATCH_UNEXPLAINED, ("no_explanation_record",)
        )
    if binding_digest_expected is not None:
        _check_hex64(binding_digest_expected, "binding_digest_expected")
        if not hmac.compare_digest(
            recommendation.binding_digest(), binding_digest_expected
        ):
            return MatchVerdict(
                CLASS_MATCH_UNEXPLAINED, ("explanation_unbound",)
            )
    return MatchVerdict(CLASS_MATCH_EXPLAINED, ())


def match_audit_event(
    verdict: MatchVerdict,
    *,
    recommendation_id: str = "",
) -> dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a match explanation."""
    return {
        "event": EVENT_MATCH_EXPLAINED
        if verdict.classification == CLASS_MATCH_EXPLAINED
        else EVENT_MATCH_UNEXPLAINED,
        "schema_version": COMPANIONSHIP_SCHEMA_VERSION,
        "recommendation_id": recommendation_id,
        "classification": verdict.classification,
        "reasons": list(verdict.reasons),
    }


__all__ = [
    "COMPANIONSHIP_SCHEMA_VERSION",
    "PERSONA_MODES",
    "INTIMATE_MODES",
    "AGE_STATUSES",
    "DENY_MINOR_NO_MODE",
    "DENY_INTIMATE_MINOR",
    "DENY_MINOR_MODE_MISMATCH",
    "DENY_MINOR_MODE_TAMPERED",
    "DENY_MINOR_MODE_FUTURE",
    "DENY_UNKNOWN_AGE_NO_MODE",
    "DENY_MODE_UNKNOWN",
    "DENY_MALFORMED",
    "CLASS_OK",
    "CLASS_INTERVENTION_REQUIRED",
    "CLASS_CRISIS_ESCALATED",
    "CLASS_CRISIS_HALTED",
    "CLASS_SYCOPHANCY",
    "CLASS_PERSONA_BREAK",
    "CLASS_CAP_EXCEEDED",
    "CLASS_TRAINING_LEAK",
    "CLASS_MATCH_UNEXPLAINED",
    "CLASS_MATCH_EXPLAINED",
    "CLASS_NO_TRAINING",
    "EVENT_MINOR_LAUNCH_DENIED",
    "EVENT_INTIMATE_MINOR_DENIED",
    "EVENT_LAUNCH_ALLOWED",
    "EVENT_DEPENDENCE_DETECTED",
    "EVENT_CRISIS_ESCALATED",
    "EVENT_CRISIS_HALTED",
    "EVENT_SYCOPHANCY_DETECTED",
    "EVENT_PERSONA_BREAK",
    "EVENT_CAP_EXCEEDED",
    "EVENT_TRAINING_LEAK",
    "EVENT_NO_TRAINING",
    "EVENT_MATCH_EXPLAINED",
    "EVENT_MATCH_UNEXPLAINED",
    "DEFAULT_MINOR_CONTINUOUS_CAP_MIN",
    "DEFAULT_MINOR_DAILY_CAP_MIN",
    "CompanionError",
    "MinorModeRecord",
    "MinorModeRegistry",
    "LaunchVerdict",
    "minor_intimacy_gate",
    "launch_audit_event",
    "DependenceThresholds",
    "DependenceThresholdRegistry",
    "SessionStats",
    "DependenceVerdict",
    "dependence_probe",
    "dependence_audit_event",
    "CrisisEscalationReceipt",
    "CrisisVerdict",
    "CrisisRouter",
    "crisis_audit_event",
    "SycophancyVerdict",
    "sycophancy_probe",
    "sycophancy_audit_event",
    "PersonaVerdict",
    "persona_consistency_gate",
    "persona_audit_event",
    "SessionCapPolicy",
    "SessionCapRegistry",
    "CapVerdict",
    "session_caps",
    "cap_audit_event",
    "NoTrainingReceipt",
    "NoTrainingLog",
    "TrainingVerdict",
    "private_dialogue_gate",
    "training_audit_event",
    "MatchRecommendation",
    "MatchVerdict",
    "matchmaker_explain",
    "match_audit_event",
]
