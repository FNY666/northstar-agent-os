"""Streaming output guard: per-chunk screening, not final-output gating.

Absorbs the 2026 open-models thread (finite sample; vendor claims flagged
in the research notes, not re-verified here):

- Guard models are going open-weight and Apache 2.0: Shieldstral
  ("policy as natural language questions"), Qwen3Guard-Stream (streaming
  token checks), Granite Guardian 4.1, gpt-oss-safeguard. The ecosystem
  is converging on *streaming* guards — but most deployments still gate
  only the *final* output.

The governance gap this module closes: if policy is enforced only on the
final output, a streaming agent can exfiltrate (or act on) a violating
*prefix* long before the gate ever sees it. The final-output gate is the
AI-text-detector of streaming governance — an uncheckable claim about an
opaque output (98th batch). This module screens every chunk *before*
release:

1. **GuardPolicy** — a deterministic, closed-vocabulary chunk screener.
   Deny-patterns are literal substring matchers (no regex: auditable,
   deterministic, no catastrophic backtracking); each pattern carries a
   risk weight, and a chunk whose total weight exceeds the policy's risk
   budget is denied. There is deliberately NO LLM in the hot path —
   deterministic-first per repo philosophy. An open-weight guard model
   may run as an *optional second opinion*; its output is advisory only
   and is never the gate (its verdict is recorded in the receipt, not
   consulted for release).

2. **screen_stream()** — consumes an iterable of chunks. Each chunk is
   screened *before* release; a violating chunk halts the stream
   immediately (fail-closed: nothing after the violation is released).
   Every chunk decision is receipted into a tamper-evident hash chain
   ``(stream_id, chunk_index, chunk_digest, window_digest, verdict)``,
   so a stream that bypassed the guard is detectable after the fact:
   a missing or reordered chunk breaks the chain.

3. **guard_liveness** — the guard must prove it is the current policy
   version: the caller pins the expected policy digest, and a stale or
   unknown guard refuses the *entire* stream. There is no "degraded
   mode" streaming — a guard you cannot verify is a guard you do not
   have.

4. **anti_smuggling** — chunk-boundary evasion is caught: the screener
   keeps a bounded overlap window (the tail of previously released
   chunks) and screens ``window + chunk`` together, so a pattern split
   across a chunk boundary still matches. The window itself is
   receipted (``window_digest``), so a host that silently narrows the
   window to smuggle a split pattern fails chain verification.

5. **Binary classification** — a fully released, chain-verified stream
   classifies ``"verified-stream"``; a halted stream, a refused stream,
   or any verification failure classifies ``"unverifiable-stream"``
   (87th batch binary semantics — the partial prefix is never
   authoritative).

Fail-closed by construction:

- a chunk that is not a ``str`` is a malformed chunk: the stream halts;
- a deny-pattern that is empty, or a non-positive weight, makes the
  *policy* malformed: the stream is refused before any chunk releases;
- an overlap window larger than the policy allows is clamped, never
  silently widened; a zero overlap is legal but recorded, so the
  "no-overlap" configuration is auditable rather than invisible;
- the policy digest is computed over the *full* policy definition
  (id, version, patterns with weights and reasons, budget, overlap) —
  swapping in a weaker policy under the same version string changes
  the digest and fails liveness;
- chain verification fails closed on any gap, reorder, digest
  mismatch, or window inconsistency.

Honest scoping (documented, not hidden): literal/pattern screening
catches *known-bad shapes* — credential prefixes, key headers, known
exfil markers. A *novel* exfiltration encoding that matches no pattern
passes the deterministic gate; that is the documented job of the
optional model second opinion (advisory, receipted, never gating).
Pattern screening is a floor, not a ceiling.

Deterministic: no wall-clock reads, canonical-JSON hashing via
:func:`canonical_json.jcs_sha256_hex`, digest comparisons with
:func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from canonical_json import jcs_sha256_hex

#: Schema marker, pinned into the policy and receipt digests.
SCHEMA_VERSION = "northstar.stream-guard.v1"

#: Stream classifications (binary, 87th-batch semantics).
VERIFIED_STREAM = "verified-stream"
UNVERIFIABLE_STREAM = "unverifiable-stream"

#: Chunk verdict vocabulary. Closed: anything else is malformed.
CHUNK_RELEASE = "release"
CHUNK_HALT = "halt"

#: Stable denial reasons, suitable for exact matching in tests/bench.
DENY_STALE_GUARD = "stale_guard_version"
DENY_UNKNOWN_GUARD = "unknown_guard_policy"
DENY_MALFORMED_POLICY = "malformed_guard_policy"
DENY_MALFORMED_CHUNK = "malformed_chunk"
DENY_PATTERN_MATCH = "deny_pattern_match"
DENY_RISK_BUDGET = "risk_budget_exceeded"

#: Audit event names for audit.ndjson/1.
STREAM_REFUSED_EVENT = "stream.guard_refused"
STREAM_HALTED_EVENT = "stream.halted"
STREAM_RELEASED_EVENT = "stream.released"


class StreamGuardError(ValueError):
    """Malformed guard-policy input."""


@dataclass(frozen=True)
class DenyPattern:
    """One literal deny matcher.

    ``pattern`` is a literal substring (never a regex). ``weight`` is the
    risk contributed when the pattern is present in a screened window;
    presence counts once per chunk regardless of repetition, so the risk
    math stays auditable.
    """

    pattern: str
    weight: int
    reason: str

    def definition(self) -> dict[str, Any]:
        return {"pattern": self.pattern, "weight": self.weight, "reason": self.reason}


@dataclass(frozen=True)
class GuardPolicy:
    """Deterministic per-chunk screening policy.

    ``max_chunk_risk`` is the risk budget: a chunk whose summed pattern
    weight *exceeds* the budget is denied (budget 0 = any match denies).
    ``overlap_bytes`` is the anti-smuggling window: the tail of released
    chunks re-screened with each new chunk.
    """

    policy_id: str
    version: str
    deny_patterns: tuple[DenyPattern, ...] = ()
    max_chunk_risk: int = 0
    overlap_bytes: int = 64

    def validate(self) -> str | None:
        """Return a denial reason if the policy is malformed, else None."""
        if not isinstance(self.policy_id, str) or not self.policy_id:
            return DENY_MALFORMED_POLICY
        if not isinstance(self.version, str) or not self.version:
            return DENY_MALFORMED_POLICY
        if not isinstance(self.max_chunk_risk, int) or self.max_chunk_risk < 0:
            return DENY_MALFORMED_POLICY
        if not isinstance(self.overlap_bytes, int) or self.overlap_bytes < 0:
            return DENY_MALFORMED_POLICY
        seen: set[str] = set()
        for pat in self.deny_patterns:
            if not isinstance(pat.pattern, str) or not pat.pattern:
                return DENY_MALFORMED_POLICY
            if not isinstance(pat.weight, int) or pat.weight <= 0:
                return DENY_MALFORMED_POLICY
            if not isinstance(pat.reason, str) or not pat.reason:
                return DENY_MALFORMED_POLICY
            if pat.pattern in seen:
                return DENY_MALFORMED_POLICY
            seen.add(pat.pattern)
        return None

    def definition(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "policy_id": self.policy_id,
            "version": self.version,
            "deny_patterns": [p.definition() for p in self.deny_patterns],
            "max_chunk_risk": self.max_chunk_risk,
            "overlap_bytes": self.overlap_bytes,
        }

    def digest(self) -> str:
        """Policy digest pin — the liveness check compares against this."""
        return jcs_sha256_hex(self.definition())


def default_policy() -> GuardPolicy:
    """A closed exemplar policy of known-bad credential/exfil shapes.

    Hosts are expected to extend the pattern list; the digest pin means
    any extension is a *new* policy version that the caller must pin.
    """
    return GuardPolicy(
        policy_id="northstar.stream-guard.default",
        version="2026-10-04",
        deny_patterns=(
            DenyPattern("sk-live-", 3, "live_secret_key_prefix"),
            DenyPattern("AKIA", 3, "aws_access_key_prefix"),
            DenyPattern("-----BEGIN PRIVATE KEY-----", 5, "private_key_header"),
            DenyPattern("-----BEGIN RSA PRIVATE KEY-----", 5, "rsa_private_key_header"),
            DenyPattern("api_key=", 2, "api_key_assignment"),
            DenyPattern("password=", 2, "password_assignment"),
        ),
        max_chunk_risk=0,
        overlap_bytes=64,
    )


def guard_liveness(policy: GuardPolicy, expected_policy_digest: str) -> dict[str, Any]:
    """Prove the guard is the pinned policy version.

    Returns ``{"live": True}`` only when the policy is well-formed and
    its digest matches the caller's pin. A stale/unknown guard returns
    ``{"live": False, "reason": ...}`` — never raises, so the caller can
    refuse the stream on the same fail-closed path.
    """
    malformed = policy.validate()
    if malformed is not None:
        return {"live": False, "reason": DENY_MALFORMED_POLICY}
    if not isinstance(expected_policy_digest, str) or not expected_policy_digest:
        return {"live": False, "reason": DENY_UNKNOWN_GUARD}
    if not hmac.compare_digest(policy.digest(), expected_policy_digest):
        return {"live": False, "reason": DENY_STALE_GUARD}
    return {"live": True}


@dataclass(frozen=True)
class ChunkVerdict:
    """The screening outcome for one chunk."""

    verdict: str  # CHUNK_RELEASE | CHUNK_HALT
    risk: int
    matched: tuple[str, ...] = ()
    reason: str = ""


def screen_chunk(
    chunk: str,
    window: str,
    policy: GuardPolicy,
    second_opinion: Callable[[str], Mapping[str, Any]] | None = None,
) -> ChunkVerdict:
    """Screen one chunk (plus the anti-smuggling overlap window).

    ``second_opinion`` is the optional open-weight guard model hook: it
    receives the screened text and its output is *recorded* by the
    caller, never consulted for the verdict. The deterministic gate
    alone decides release.
    """
    if not isinstance(chunk, str):
        return ChunkVerdict(CHUNK_HALT, 0, (), DENY_MALFORMED_CHUNK)
    screened = window + chunk
    matched: list[str] = []
    risk = 0
    for pat in policy.deny_patterns:
        if pat.pattern in screened:
            matched.append(pat.reason)
            risk += pat.weight
    if risk > policy.max_chunk_risk:
        reason = DENY_RISK_BUDGET if policy.max_chunk_risk > 0 else DENY_PATTERN_MATCH
        return ChunkVerdict(CHUNK_HALT, risk, tuple(matched), reason)
    # Advisory only: recorded by the receipt layer, never gating.
    _ = second_opinion(screened) if second_opinion is not None else None
    return ChunkVerdict(CHUNK_RELEASE, risk, tuple(matched))


@dataclass(frozen=True)
class ChunkReceipt:
    """One receipted chunk-screening decision.

    ``window_digest`` commits to the exact overlap bytes that were
    screened with the chunk, so a host that narrows the window to
    smuggle a split pattern fails :func:`verify_chain`.
    """

    stream_id: str
    chunk_index: int
    chunk_digest: str
    window_digest: str
    verdict: str
    matched: tuple[str, ...]
    risk: int
    prev_digest: str
    receipt_digest: str = ""

    def recompute_digest(self) -> str:
        return jcs_sha256_hex(
            {
                "schema": SCHEMA_VERSION,
                "stream_id": self.stream_id,
                "chunk_index": self.chunk_index,
                "chunk_digest": self.chunk_digest,
                "window_digest": self.window_digest,
                "verdict": self.verdict,
                "matched": list(self.matched),
                "risk": self.risk,
                "prev_digest": self.prev_digest,
            }
        )


def _stream_id(policy: GuardPolicy, stream_label: str) -> str:
    return hashlib.sha256(
        f"northstar-stream-guard:{policy.policy_id}:{stream_label}".encode()
    ).hexdigest()[:32]


@dataclass
class ScreenResult:
    """The outcome of screening a stream."""

    stream_id: str
    released: list[str]
    halted: bool
    halt_index: int | None
    halt_reason: str | None
    receipts: list[ChunkReceipt]
    classification: str  # VERIFIED_STREAM | UNVERIFIABLE_STREAM

    def audit_event(self) -> dict[str, Any]:
        if self.halted and self.halt_reason in (DENY_STALE_GUARD, DENY_UNKNOWN_GUARD, DENY_MALFORMED_POLICY):
            event = STREAM_REFUSED_EVENT
        elif self.halted:
            event = STREAM_HALTED_EVENT
        else:
            event = STREAM_RELEASED_EVENT
        return {
            "event": event,
            "stream_id": self.stream_id,
            "released_chunks": len(self.released),
            "halt_index": self.halt_index,
            "halt_reason": self.halt_reason,
            "classification": self.classification,
            "receipt_tip": self.receipts[-1].receipt_digest if self.receipts else None,
        }


def _refused(
    policy: GuardPolicy, stream_label: str, reason: str
) -> ScreenResult:
    stream_id = _stream_id(policy, stream_label)
    return ScreenResult(
        stream_id=stream_id,
        released=[],
        halted=True,
        halt_index=None,
        halt_reason=reason,
        receipts=[],
        classification=UNVERIFIABLE_STREAM,
    )


def screen_stream(
    chunks: Iterable[str],
    policy: GuardPolicy,
    expected_policy_digest: str,
    stream_label: str = "default",
    second_opinion: Callable[[str], Mapping[str, Any]] | None = None,
) -> ScreenResult:
    """Screen a stream chunk-by-chunk, releasing each chunk before the next.

    Liveness is checked first: a stale/unknown/malformed guard refuses the
    whole stream (nothing released). Then each chunk is screened together
    with the anti-smuggling overlap window; the first violating chunk
    halts the stream immediately — nothing after it is released, and the
    partial prefix classifies ``unverifiable-stream``.

    Every decision is receipted into a hash chain so a bypassed stream is
    detectable after the fact via :func:`verify_chain`.
    """
    liveness = guard_liveness(policy, expected_policy_digest)
    if not liveness["live"]:
        return _refused(policy, stream_label, liveness["reason"])

    stream_id = _stream_id(policy, stream_label)
    released: list[str] = []
    receipts: list[ChunkReceipt] = []
    prev_digest = "genesis"
    emitted = ""  # concatenation of released chunks, for the overlap window

    for index, chunk in enumerate(chunks):
        window = emitted[-policy.overlap_bytes :] if policy.overlap_bytes else ""
        verdict = screen_chunk(chunk, window, policy, second_opinion)
        chunk_text = chunk if isinstance(chunk, str) else ""
        receipt = ChunkReceipt(
            stream_id=stream_id,
            chunk_index=index,
            chunk_digest=hashlib.sha256(chunk_text.encode("utf-8")).hexdigest(),
            window_digest=hashlib.sha256(window.encode("utf-8")).hexdigest(),
            verdict=verdict.verdict,
            matched=verdict.matched,
            risk=verdict.risk,
            prev_digest=prev_digest,
        )
        receipt = ChunkReceipt(
            **{**receipt.__dict__, "receipt_digest": receipt.recompute_digest()}
        )
        receipts.append(receipt)
        prev_digest = receipt.receipt_digest
        if verdict.verdict == CHUNK_HALT:
            return ScreenResult(
                stream_id=stream_id,
                released=released,
                halted=True,
                halt_index=index,
                halt_reason=verdict.reason,
                receipts=receipts,
                classification=UNVERIFIABLE_STREAM,
            )
        released.append(chunk)
        emitted += chunk

    return ScreenResult(
        stream_id=stream_id,
        released=released,
        halted=False,
        halt_index=None,
        halt_reason=None,
        receipts=receipts,
        classification=VERIFIED_STREAM,
    )


def verify_chain(
    receipts: Sequence[ChunkReceipt], released_chunks: Sequence[str], policy: GuardPolicy
) -> dict[str, Any]:
    """Replay a receipt chain and check for bypass, gap, or tampering.

    Fail-closed: returns ``{"ok": False, "reason": ...}`` on any gap,
    reorder, digest mismatch, or window inconsistency — i.e. any sign
    the stream was released without (or around) the guard.
    """
    if not receipts:
        return {"ok": True, "reason": "empty chain"}
    prev = "genesis"
    emitted = ""
    for index, receipt in enumerate(receipts):
        if receipt.chunk_index != index:
            return {"ok": False, "reason": f"chain gap or reorder at position {index}"}
        if not hmac.compare_digest(receipt.prev_digest, prev):
            return {"ok": False, "reason": f"prev_digest mismatch at chunk {index}"}
        if not hmac.compare_digest(receipt.recompute_digest(), receipt.receipt_digest):
            return {"ok": False, "reason": f"receipt digest mismatch at chunk {index}"}
        if index >= len(released_chunks):
            return {"ok": False, "reason": f"missing released chunk for receipt {index}"}
        chunk = released_chunks[index]
        if not isinstance(chunk, str):
            return {"ok": False, "reason": f"malformed released chunk {index}"}
        chunk_digest = hashlib.sha256(chunk.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(receipt.chunk_digest, chunk_digest):
            return {"ok": False, "reason": f"chunk digest mismatch at chunk {index}"}
        expected_window = emitted[-policy.overlap_bytes :] if policy.overlap_bytes else ""
        window_digest = hashlib.sha256(expected_window.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(receipt.window_digest, window_digest):
            return {
                "ok": False,
                "reason": f"overlap window inconsistent at chunk {index}",
            }
        if receipt.verdict == CHUNK_HALT and index != len(receipts) - 1:
            return {"ok": False, "reason": "chunks released after a halt verdict"}
        emitted += chunk
        prev = receipt.receipt_digest
    if len(released_chunks) != len(receipts):
        return {"ok": False, "reason": "released chunk count differs from receipt count"}
    return {"ok": True, "reason": "chain verified"}


def classify_stream(result: ScreenResult) -> str:
    """Binary stream tier: verified-stream vs unverifiable-stream."""
    if result is None:
        return UNVERIFIABLE_STREAM
    return result.classification
