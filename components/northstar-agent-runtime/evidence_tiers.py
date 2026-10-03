"""Binary evidence tiers + LOG_DROP policy (eighty-seventh batch).

Absorbed from **sahiee-dev/Tesserae** (AgentOps Replay), read as *code*,
not docs — the files actually studied, in ``/tmp/tesserae``:

* ``agentops_sdk/events.py`` — ``EventType`` with ``is_sdk_authority`` /
  ``is_server_authority``; SDK-authority set: SESSION_START, SESSION_END,
  LLM_CALL, LLM_RESPONSE, TOOL_CALL, TOOL_RESULT, TOOL_ERROR, LOG_DROP;
  server-authority set: CHAIN_SEAL, CHAIN_BROKEN, REDACTION,
  FORENSIC_FREEZE.
* ``agentops_sdk/buffer.py`` — thread-safe ring buffer; on overflow the
  drop *record* (seq_start, seq_end, count) is accumulated and a LOG_DROP
  is emitted when space frees; ``deque(maxlen)`` is explicitly forbidden
  because it would silently drop.
* ``agentops_sdk/client.py`` — ``_emit_log_drop`` force-appends the
  LOG_DROP even when the buffer is full (``LOG_DROP must land``); a
  server-authority event emitted by the SDK is treated as a LOG_DROP with
  reason ``SERVER_AUTHORITY_VIOLATION``; fail-open for the agent (never
  crash it), fail-closed for integrity.
* ``verifier/verifier_core.py`` — ``classify_evidence``: **binary only**,
  "CRITICAL: Binary classification only - no 'partial' footgun".
  AUTHORITATIVE requires ALL of: server authority, valid CHAIN_SEAL,
  complete session, no LOG_DROP, chain cryptographically valid.
  Everything else is NON_AUTHORITATIVE. The ``trust_assumptions`` block
  is hardcoded, not configurable (``byzantine_server_defended: false``,
  ``session_freshness_verified: false``, ``instrumentation_complete`` is
  ``"unknown"`` — or ``"incomplete"`` when LOG_DROP is present).
* ``verifier/agentops_verify.py`` — an older four-class variant
  (PARTIAL/SIGNED_NON_AUTHORITATIVE) still present in the repo; this
  module follows the binary ``verifier_core`` stance and says so, because
  a "partially authoritative" label is exactly the footgun an attacker
  would reach for.
* ``docs/CHAIN_AUTHORITY_INVARIANTS.md`` — three principals (untrusted
  SDK producer / trusted-verify server / independent verifier), the
  SDK-Authority Isolation invariant, and server-authority immutability.
* ``docs/EVENT_LOG_SPEC.md`` — LOG_DROP payload contract: ``count``,
  ``reason``, ``seq_range_start``, ``seq_range_end``; the LOG_DROP is
  itself a chain event and "must never be omitted to conceal data loss".

Northstar mapping (honest scope: Northstar is single-process, so there is
no independent ingestion server; the in-process **runtime** is the trust
anchor, analogous to Tesserae's server authority):

* **runtime-authoritative** evidence = produced by the runtime itself
  (dispatch records, approval outcomes, hash-chained audit events), sealed
  into ``audit.ndjson/1``. The agent is co-located with the runtime the
  way Tesserae's SDK is co-located with the agent process — so anything
  the *agent* merely claims is, by construction, non-authoritative.
* **non-authoritative** evidence = agent-claimed (tool results the agent
  reports, self-reported actions, unsealed chains). Usable for
  development/debugging and low-stakes decisions; never sufficient for a
  high-stakes decision on its own.

LOG_DROP policy (the Tesserae rule, ported):

1. A lost event is never silent. If the runtime cannot record an event —
   buffer pressure, an internal error, or an *authority violation* (the
   agent attempting to emit a runtime-authority event) — it emits an
   explicit ``evidence.log_drop`` chain event carrying ``count``,
   ``reason``, ``seq_range_start`` and ``seq_range_end``. The LOG_DROP is
   itself hash-chained and sequenced.
2. Any window containing a LOG_DROP is NON_AUTHORITATIVE, permanently.
   There is no "partially authoritative": the binary classification has no
   middle rung to launder a gappy chain through.
3. A sequence gap with *no* corresponding LOG_DROP is a chain-integrity
   violation — fail closed, do not classify, do not proceed.
4. Only non-authoritative, informational events may ever be *compacted*
   (as opposed to dropped), and only with a compaction receipt recording
   the compacted range and its digest. Runtime-authority events,
   LOG_DROP events, chain seals, and high-stakes decision records are
   never compacted.
5. Fail-open for the agent (recording must never crash or block the
   agent), fail-closed for integrity (a high-stakes decision with
   non-authoritative evidence is denied, not degraded).

Everything here is offline and deterministic. No network, no clock reads.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Sequence

import audit_chain

# ---------------------------------------------------------------------------
# Tiers: binary only — no "partial" footgun (Tesserae verifier_core stance)
# ---------------------------------------------------------------------------


class EvidenceTier(str, Enum):
    """Binary evidence tier. There is deliberately no middle rung."""

    AUTHORITATIVE = "authoritative"
    NON_AUTHORITATIVE = "non_authoritative"


#: Producer of an evidence record. "runtime" is the in-process trust
#: anchor (Tesserae's server-authority analogue); "agent" is anything the
#: agent process merely claims (Tesserae's SDK-authority analogue).
PRODUCER_RUNTIME = "runtime"
PRODUCER_AGENT = "agent"

#: Event types only the runtime may produce. An agent attempting to emit
#: one is an *authority violation*: the claim is refused and a LOG_DROP
#: is recorded (Tesserae: SDK emitting CHAIN_SEAL -> SERVER_AUTHORITY_VIOLATION).
RUNTIME_AUTHORITY_EVENTS = frozenset(
    {
        "chain_seal",
        "forensic_freeze",
        "redaction_record",
        "chain_broken",
    }
)

#: Event types that must never be compacted or dropped, even when
#: non-authoritative. LOG_DROP itself is on the list: the loss record is
#: the one thing that may never be lost.
NEVER_COMPACT_EVENTS = frozenset(
    {
        "chain_seal",
        "forensic_freeze",
        "redaction_record",
        "chain_broken",
        "evidence.log_drop",
        "approval",
        "multisig_approval",
        "pretrade_decision",
    }
)

#: LOG_DROP reasons, ported from Tesserae's client.py.
LOG_DROP_REASON_BUFFER_OVERFLOW = "buffer_overflow"
LOG_DROP_REASON_AUTHORITY_VIOLATION = "authority_violation"
LOG_DROP_REASON_INTERNAL_ERROR = "internal_error"

#: Risk tiers at which a decision is high-stakes and therefore requires
#: AUTHORITATIVE evidence (tier3 = host callback / multisig in the bench).
HIGH_STAKES_TIERS = frozenset({"tier3", "tier4", "tier5"})


# ---------------------------------------------------------------------------
# Binary classification (pure function)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceClassification:
    """Outcome of classifying one audit window."""

    tier: EvidenceTier
    authority: str
    sealed: bool
    complete: bool
    has_drops: bool
    chain_valid: bool
    reasons: tuple[str, ...] = ()


def classify_evidence(
    *,
    authority: str,
    sealed: bool,
    complete: bool,
    has_drops: bool,
    chain_valid: bool,
) -> EvidenceClassification:
    """Binary evidence classification — ALL conditions, no middle rung.

    AUTHORITATIVE requires every one of: runtime authority, a valid seal,
    a complete window, no LOG_DROP events, and a cryptographically valid
    chain. Anything else — including a sealed chain *with* drops — is
    NON_AUTHORITATIVE. (Tesserae's ``verifier_core.classify_evidence``:
    "Binary classification only - no 'partial' footgun".)
    """
    reasons: list[str] = []
    if authority != PRODUCER_RUNTIME:
        reasons.append(f"authority is {authority!r}, not runtime")
    if not sealed:
        reasons.append("no runtime seal")
    if not complete:
        reasons.append("window incomplete (missing seal event or sequence gap)")
    if has_drops:
        reasons.append("LOG_DROP present: captured events are verified, the window is not")
    if not chain_valid:
        reasons.append("chain failed cryptographic verification")
    tier = (
        EvidenceTier.AUTHORITATIVE if not reasons else EvidenceTier.NON_AUTHORITATIVE
    )
    return EvidenceClassification(
        tier=tier,
        authority=authority,
        sealed=bool(sealed),
        complete=bool(complete),
        has_drops=bool(has_drops),
        chain_valid=bool(chain_valid),
        reasons=tuple(reasons),
    )


def trust_assumptions() -> dict[str, Any]:
    """Hardcoded trust-assumptions block. Not configurable.

    Mirrors Tesserae's ``build_trust_assumptions``: a system that does not
    know its limits is not a trustworthy audit tool. In particular the
    runtime is *not* defended against a Byzantine host (single process —
    honest scope), and the verifier can never know what was never
    captured.
    """
    return {
        "independent_server_verification": False,
        "server_identity_verified": False,
        "runtime_producer_trusted": True,
        "agent_claims_trusted": False,
        "instrumentation_complete": "unknown",
        "session_freshness_verified": False,
        "byzantine_host_defended": False,
        "clock_accuracy_required": False,
        "full_chain_rewrite_defended": True,
        "trust_model_ref": "evidence_tiers.trust_assumptions",
    }


# ---------------------------------------------------------------------------
# Window classification over audit.ndjson/1-style records
# ---------------------------------------------------------------------------


def _record_chain_version(record: dict[str, Any]) -> str:
    return record.get("chain", audit_chain.CHAIN_VERSION)


def _link_ok(record: dict[str, Any], prev_hash: str) -> bool:
    """Recompute one record's chain_hash and compare (constant-time)."""
    try:
        body = {k: v for k, v in record.items() if k not in audit_chain._SEAL_FIELDS}
        recomputed = audit_chain.chain_record(
            body, prev_hash, chain_version=_record_chain_version(record)
        )["chain_hash"]
    except Exception:
        return False
    claimed = record.get("chain_hash")
    if not isinstance(claimed, str):
        return False
    return hashlib.sha256(recomputed.encode()).digest() == hashlib.sha256(
        claimed.encode()
    ).digest()


def classify_audit_window(
    events: Sequence[dict[str, Any]],
    *,
    genesis_hash: str,
) -> EvidenceClassification:
    """Classify a window of audit records with the binary rule.

    Checks, in order: every record is runtime-produced (an agent-claimed
    record, or an agent attempting a runtime-authority event type,
    disqualifies the window); the hash chain verifies link by link; the
    sequence is gap-free (a gap without LOG_DROP is an integrity
    violation and fails the whole classification closed); a runtime
    ``chain_seal`` closes the window; and no ``evidence.log_drop`` is
    present.
    """
    events = list(events)
    if not events:
        return classify_evidence(
            authority=PRODUCER_AGENT,
            sealed=False,
            complete=False,
            has_drops=False,
            chain_valid=False,
        )

    authority_ok = True
    chain_ok = True
    seq_ok = True
    prev = genesis_hash
    expected_seq: int | None = None
    sealed = False
    has_drops = False

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            return classify_evidence(
                authority=PRODUCER_AGENT,
                sealed=False,
                complete=False,
                has_drops=False,
                chain_valid=False,
            )
        etype = str(event.get("event_type", ""))
        producer = str(event.get("producer", PRODUCER_AGENT))

        # Authority isolation: the agent may never produce runtime events,
        # and any agent-produced record disqualifies the window.
        if etype in RUNTIME_AUTHORITY_EVENTS and producer != PRODUCER_RUNTIME:
            authority_ok = False
        if producer != PRODUCER_RUNTIME:
            authority_ok = False

        if etype == "evidence.log_drop":
            has_drops = True
        if etype == "chain_seal" and producer == PRODUCER_RUNTIME:
            sealed = True

        # Chain linkage, link by link.
        claimed_prev = event.get("prev_hash")
        if claimed_prev != prev:
            chain_ok = False
        elif not _link_ok(event, prev):
            chain_ok = False
        else:
            prev = str(event.get("chain_hash"))

        # Sequence continuity: a gap without LOG_DROP is an integrity
        # violation — fail the classification closed, do not guess.
        seq = event.get("seq")
        if isinstance(seq, int):
            if expected_seq is None:
                expected_seq = seq + 1
            elif seq != expected_seq:
                seq_ok = False
            else:
                expected_seq = seq + 1
        else:
            seq_ok = False
        _ = index

    complete = sealed and seq_ok
    return classify_evidence(
        authority=PRODUCER_RUNTIME if authority_ok else PRODUCER_AGENT,
        sealed=sealed,
        complete=complete,
        has_drops=has_drops,
        chain_valid=chain_ok,
    )


# ---------------------------------------------------------------------------
# LOG_DROP: construction + policy
# ---------------------------------------------------------------------------


def emit_log_drop(
    *,
    count: int,
    reason: str,
    seq_range_start: int,
    seq_range_end: int,
    session_id: str,
    seq: int,
    prev_hash: str,
    producer: str = PRODUCER_RUNTIME,
) -> dict[str, Any]:
    """Build an explicit, sequenced, hash-linkable LOG_DROP record.

    The record is the loss made visible: ``count`` events were not
    captured for ``reason`` across ``[seq_range_start, seq_range_end]``.
    It is itself a chain event — the caller links it with
    ``audit_chain.chain_record`` exactly like any other record, so the
    drop participates in the hash chain and can never be omitted to
    conceal data loss (Tesserae EVENT_LOG_SPEC §2.1).

    Fails closed on malformed input: a LOG_DROP that cannot describe the
    loss precisely is worse than useless, so bad ranges raise instead of
    emitting a lying record.
    """
    if count < 1:
        raise ValueError("LOG_DROP count must be >= 1")
    if seq_range_start > seq_range_end:
        raise ValueError("LOG_DROP seq_range_start must be <= seq_range_end")
    if reason not in (
        LOG_DROP_REASON_BUFFER_OVERFLOW,
        LOG_DROP_REASON_AUTHORITY_VIOLATION,
        LOG_DROP_REASON_INTERNAL_ERROR,
    ):
        raise ValueError(f"unknown LOG_DROP reason {reason!r}")
    return {
        "event_type": "evidence.log_drop",
        "producer": producer,
        "session_id": session_id,
        "seq": int(seq),
        "prev_hash": prev_hash,
        "count": int(count),
        "reason": reason,
        "seq_range_start": int(seq_range_start),
        "seq_range_end": int(seq_range_end),
    }


@dataclass(frozen=True)
class CompactionVerdict:
    """Whether one audit record may be compacted away."""

    allowed: bool
    reason: str


def may_compact(event: dict[str, Any]) -> CompactionVerdict:
    """LOG_DROP *policy*: what may be compacted, and what may never be.

    Only agent-claimed, informational records are compactable — and only
    with a compaction receipt (see :func:`compaction_receipt`) so the
    compacted range stays accountable. Runtime-authority events,
    LOG_DROP records, seals, and high-stakes decision records are never
    compacted: dropping the loss record would let a gappy chain launder
    itself back toward authoritative.
    """
    if not isinstance(event, dict):
        return CompactionVerdict(False, "not a record")
    etype = str(event.get("event_type", ""))
    if etype in NEVER_COMPACT_EVENTS:
        return CompactionVerdict(False, f"{etype} is never compacted")
    if etype in RUNTIME_AUTHORITY_EVENTS:
        return CompactionVerdict(False, f"{etype} is runtime-authority")
    if str(event.get("producer", PRODUCER_AGENT)) == PRODUCER_RUNTIME:
        return CompactionVerdict(False, "runtime-produced records are never compacted")
    return CompactionVerdict(True, "agent-claimed informational record; receipt required")


def compaction_receipt(
    *,
    seq_range_start: int,
    seq_range_end: int,
    event_count: int,
    range_digest: str,
    session_id: str,
    seq: int,
    prev_hash: str,
) -> dict[str, Any]:
    """Build the compaction receipt that makes a compaction accountable.

    ``range_digest`` is the SHA-256 hex of the canonical concatenation of
    the compacted records' chain hashes — a verifier holding the receipt
    can confirm *which* records were compacted, even though their bodies
    are gone. The receipt is itself runtime-produced and hash-chained, so
    compaction is an audited act, not silent deletion.
    """
    if event_count < 1:
        raise ValueError("compaction receipt requires >= 1 compacted event")
    if seq_range_start > seq_range_end:
        raise ValueError("compaction seq_range_start must be <= seq_range_end")
    if len(range_digest) != 64 or any(
        c not in "0123456789abcdef" for c in range_digest
    ):
        raise ValueError("range_digest must be 64 lowercase hex characters")
    return {
        "event_type": "evidence.compaction_receipt",
        "producer": PRODUCER_RUNTIME,
        "session_id": session_id,
        "seq": int(seq),
        "prev_hash": prev_hash,
        "seq_range_start": int(seq_range_start),
        "seq_range_end": int(seq_range_end),
        "event_count": int(event_count),
        "range_digest": range_digest,
    }


def digest_compacted_range(chain_hashes: Sequence[str]) -> str:
    """SHA-256 over the canonical concatenation of compacted chain hashes."""
    h = hashlib.sha256()
    for ch in chain_hashes:
        if len(ch) != 64 or any(c not in "0123456789abcdef" for c in ch):
            raise ValueError("chain hashes must be 64 lowercase hex characters")
        h.update(bytes.fromhex(ch))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Gate: authoritative evidence required for high-stakes decisions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceGateResult:
    """Outcome of the high-stakes evidence gate."""

    allowed: bool
    tier: EvidenceTier
    risk_tier: str
    reason: str


def require_authoritative(
    classification: EvidenceClassification, risk_tier: str
) -> EvidenceGateResult:
    """High-stakes decisions require AUTHORITATIVE evidence. Fail closed.

    Decisions at tier3+ (host callback / multisig territory) proceed only
    when the supporting audit window classifies AUTHORITATIVE. Anything
    else — agent-claimed records, an unsealed window, a window with
    LOG_DROP, a broken chain — denies the decision. The denial is loud
    (the reasons ride along for the audit trail), never a silent
    downgrade: Tesserae's binary rule exists precisely so a gappy chain
    cannot be laundered through a "partial" label.
    """
    tier_name = str(risk_tier or "").strip().lower()
    if tier_name not in HIGH_STAKES_TIERS:
        return EvidenceGateResult(
            allowed=True,
            tier=classification.tier,
            risk_tier=tier_name,
            reason=f"risk tier {tier_name!r} is not high-stakes; evidence tier {classification.tier.value} suffices",
        )
    if classification.tier is EvidenceTier.AUTHORITATIVE:
        return EvidenceGateResult(
            allowed=True,
            tier=classification.tier,
            risk_tier=tier_name,
            reason="high-stakes decision backed by AUTHORITATIVE evidence",
        )
    return EvidenceGateResult(
        allowed=False,
        tier=classification.tier,
        risk_tier=tier_name,
        reason=(
            f"high-stakes decision denied: evidence is "
            f"{classification.tier.value} ({'; '.join(classification.reasons)})"
        ),
    )


def evidence_audit_event(
    *,
    kind: str,
    tier: EvidenceTier,
    detail: str,
    session_id: str,
    seq: int,
    prev_hash: str,
) -> dict[str, Any]:
    """Anchor an evidence-tier decision into the audit chain.

    ``kind`` is one of ``evidence.classified`` / ``evidence.gate_denied`` /
    ``evidence.gate_allowed``. The tier and the human-readable reason are
    pinned so a later verifier can see exactly what the gate saw.
    """
    if kind not in (
        "evidence.classified",
        "evidence.gate_denied",
        "evidence.gate_allowed",
    ):
        raise ValueError(f"unknown evidence audit kind {kind!r}")
    return {
        "event_type": kind,
        "producer": PRODUCER_RUNTIME,
        "session_id": session_id,
        "seq": int(seq),
        "prev_hash": prev_hash,
        "evidence_tier": tier.value,
        "detail": detail,
    }


__all__ = [
    "EvidenceTier",
    "EvidenceClassification",
    "EvidenceGateResult",
    "CompactionVerdict",
    "PRODUCER_RUNTIME",
    "PRODUCER_AGENT",
    "RUNTIME_AUTHORITY_EVENTS",
    "NEVER_COMPACT_EVENTS",
    "HIGH_STAKES_TIERS",
    "LOG_DROP_REASON_BUFFER_OVERFLOW",
    "LOG_DROP_REASON_AUTHORITY_VIOLATION",
    "LOG_DROP_REASON_INTERNAL_ERROR",
    "classify_evidence",
    "classify_audit_window",
    "trust_assumptions",
    "emit_log_drop",
    "may_compact",
    "compaction_receipt",
    "digest_compacted_range",
    "require_authoritative",
    "evidence_audit_event",
]
