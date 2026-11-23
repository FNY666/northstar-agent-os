"""Jailbreak defense: declared jailbreak detection/blocking decision ledger.

A deterministic single-host state machine that books the host's declared
jailbreak *detections* (``detect``), declared *block decisions* (``block``),
and read-only aggregate *reports* (``report``).

* **Detect** - ``detect()`` books one host-declared detection verdict for a
  prompt. The prompt travels as a ``sha256:`` digest pin only; the verdict
  (``clean``/``suspicious``/``jailbreak``), the pinned attack-class
  vocabulary, and the host-reported risk score are booked as data.
* **Block** - ``block()`` books one terminal block decision for a prompt;
  a prompt is blocked at most once (repeat blocks refuse fail-closed).
* **Report** - ``report()`` is a pure read: aggregate verdict/block
  statistics, digest-pinned, never mutating.

Design (deterministic single-host ledger):
1. Frozen dataclasses, caller int seqs strictly increasing
   (claim-then-burn: failed mutations consume their seq + book
   ``jailbreak-defense.rejected``; rewinds raise bare), no wall-clock,
   RLock-guarded, fail-closed taxonomy.
2. stdlib-only + the single ``canonical_json`` try/except fallback;
   ``sha256:`` digest pins with ``verify()``; ``audit.ndjson/1``
   events; version pin ``jailbreak-defense.v1``; schema pin
   ``northstar.jailbreak-defense.v1``.

Honest scope:
- This module is a *decision ledger* for host-reported declarations - it
  runs no detector, sees no prompt text, and performs no blocking of its
  own. A booked ``jailbreak`` verdict means "the host reported a
  jailbreak signal for this prompt digest", never "this prompt was a
  jailbreak". A booked ``blocked`` record means "the host declared a
  block", never proof that the request was actually stopped.
- Host-reported scores are GIGO bookkeeping: ``0.99`` is arithmetic
  input, never a finding of fact.
- Digest pins prove ledger integrity and ordering, never the truth of
  the declared verdicts.
- No persistence: the ledger is in-memory.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


VERSION = "jailbreak-defense.v1"
SCHEMA = "northstar.jailbreak-defense.v1"

KIND_DETECTED = "detected"
KIND_BLOCKED = "blocked"
KIND_REPORTED = "reported"
KIND_REJECTED = "rejected"
_KINDS = frozenset({
    KIND_DETECTED, KIND_BLOCKED, KIND_REPORTED, KIND_REJECTED,
})

_VERDICTS = ("clean", "suspicious", "jailbreak")
_ATTACK_CLASSES = (
    "roleplay",
    "instruction-override",
    "delimiter-injection",
    "encoding-evasion",
    "multi-turn-escalation",
    "system-prompt-extraction",
    "tool-abuse",
    "other",
)
_BLOCK_REASONS = (
    "jailbreak-detected",
    "suspicious-score",
    "policy-violation",
    "manual",
)

_MAX_ID_LEN = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Raw prompt text must never cross the audit boundary: prompts travel as
# digest pins only.
_BANNED_DETAIL_KEYS = frozenset({
    "prompt", "text", "content", "message", "raw", "payload", "value",
    "body", "query", "input", "user_input", "system", "instruction",
})


class JailbreakDefenseError(Exception):
    """Base class for all jailbreak-defense ledger errors."""


class BadIdError(JailbreakDefenseError):
    """Prompt or record id is malformed."""


class DuplicatePromptError(JailbreakDefenseError):
    """A detection is already booked for this prompt id."""


class UnknownPromptError(JailbreakDefenseError):
    """No detection is booked for this prompt id."""


class AlreadyBlockedError(JailbreakDefenseError):
    """The prompt is already blocked; blocks are terminal and one-shot."""


class BadDigestError(JailbreakDefenseError):
    """A digest pin is malformed (must be ``sha256:<64hex>`` or ``''``)."""


class BadVerdictError(JailbreakDefenseError):
    """Verdict is not in the pinned vocabulary."""


class BadAttackClassError(JailbreakDefenseError):
    """Attack class is not in the pinned vocabulary."""


class BadScoreError(JailbreakDefenseError):
    """Score is not a finite number in [0, 1]."""


class BadReasonError(JailbreakDefenseError):
    """Block reason is not in the pinned vocabulary."""


class SeqOrderError(JailbreakDefenseError):
    """Caller seq is not strictly greater than the last consumed seq."""


class AuditKindError(JailbreakDefenseError):
    """Unknown audit event kind requested."""


def _check_id(value: Any, *, name: str = "prompt_id") -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{name} must be a str")
    if not value or len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{name} must be non-empty and <= {_MAX_ID_LEN}")
    return value


def _check_digest(value: Any, *, name: str = "prompt_digest") -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{name} must be a str")
    if value and not _DIGEST_RE.match(value):
        raise BadDigestError(f"{name} must be 'sha256:<64hex>' or ''")
    return value


def _check_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError("seq must be an int")
    if value < 1:
        raise SeqOrderError("seq must be >= 1")
    return value


def _check_score(value: Any) -> float:
    if isinstance(value, bool):
        raise BadScoreError("score must be a number, not a bool")
    if not isinstance(value, (int, float)):
        raise BadScoreError("score must be a number")
    f = float(value)
    if f != f or f in (float("inf"), float("-inf")):
        raise BadScoreError("score must be finite")
    if f < 0.0 or f > 1.0:
        raise BadScoreError("score must be in [0, 1]")
    return f


def _digest_pin(obj: Any) -> str:
    """``sha256:``-prefixed hex of the canonical form of *obj*."""
    hexed = jcs_sha256_hex(obj)
    if hexed.startswith("sha256:"):
        return hexed
    return "sha256:" + hexed


@dataclass(frozen=True)
class DetectionRecord:
    """One booked jailbreak detection declaration for a prompt."""

    prompt_id: str
    prompt_digest: str
    verdict: str
    attack_class: str
    score: float
    seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "prompt_id": self.prompt_id,
            "prompt_digest": self.prompt_digest,
            "verdict": self.verdict,
            "attack_class": self.attack_class,
            "score": self.score,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin([
            "detection", SCHEMA, self.prompt_id, self.prompt_digest,
            self.verdict, self.attack_class, repr(self.score), self.seq,
        ])


@dataclass(frozen=True)
class BlockRecord:
    """One terminal block decision for a prompt."""

    prompt_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "prompt_id": self.prompt_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin([
            "block", SCHEMA, self.prompt_id, self.reason, self.seq,
        ])


@dataclass(frozen=True)
class DefenseReport:
    """Aggregate detection/block statistics: pure read, never mutates."""

    seq: int
    detections: int
    verdict_counts: Tuple[Tuple[str, int], ...]
    blocked: int
    blocked_prompt_ids: Tuple[str, ...]
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "seq": self.seq,
            "detections": self.detections,
            "verdict_counts": [
                {"verdict": verdict, "count": count}
                for verdict, count in self.verdict_counts
            ],
            "blocked": self.blocked,
            "blocked_prompt_ids": list(self.blocked_prompt_ids),
            "digest": self.digest,
        }

    def verdict_count(self, verdict: str) -> int:
        for name, count in self.verdict_counts:
            if name == verdict:
                return count
        return 0

    def verify(self) -> bool:
        return self.digest == _digest_pin([
            "report", SCHEMA, self.seq, self.detections,
            [list(pair) for pair in self.verdict_counts],
            self.blocked, list(self.blocked_prompt_ids),
        ])


@dataclass(frozen=True)
class AuditRecord:
    """One ``audit.ndjson/1`` event."""

    kind: str
    seq: int
    detail: Dict[str, Any]

    def as_dict(self) -> dict:
        return {
            "format": "audit.ndjson/1",
            "schema": SCHEMA,
            "kind": self.kind,
            "seq": self.seq,
            "detail": self.detail,
        }


def jailbreak_defense_audit_event(audit_kind: str, **detail: Any) -> dict:
    """Build one audit event dict; raw prompt keys are banned."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise JailbreakDefenseError(
            "raw prompt content may not cross the audit boundary: "
            + ", ".join(sorted(banned))
        )
    return AuditRecord(
        kind=audit_kind, seq=0, detail=dict(detail)
    ).as_dict()


class JailbreakDefense:
    """Jailbreak detection/blocking decision ledger.

    Caller seqs are strictly increasing ints. Failed mutations consume
    their seq (claim-then-burn) and book a ``rejected`` row; seqs that
    are not strictly greater than the last consumed seq raise bare
    without consuming.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._detections: Dict[str, DetectionRecord] = {}
        self._blocks: Dict[str, BlockRecord] = {}
        self._audit: List[AuditRecord] = []
        self._seq = 0
        self._rejected = 0

    # -- seq discipline -------------------------------------------------
    def _claim_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq {seq} is not strictly greater than {self._seq}"
            )
        self._seq = seq
        return seq

    def _book_rejected(self, seq: int, why: str) -> None:
        self._rejected += 1
        self._audit.append(AuditRecord(
            kind=KIND_REJECTED, seq=seq, detail={"why": why}))

    # -- mutations ------------------------------------------------------
    def detect(self, prompt_id: str, seq: int, verdict: str,
               attack_class: str = "other", score: float = 0.0,
               prompt_digest: str = "") -> DetectionRecord:
        """Book one host-declared detection verdict for a prompt.

        The verdict, attack class, and score are host-reported data;
        the prompt itself travels as a digest pin only.
        """
        with self._lock:
            claimed = self._claim_seq(seq)
            try:
                prompt_id = _check_id(prompt_id)
                prompt_digest = _check_digest(prompt_digest)
                if isinstance(verdict, bool) or not isinstance(verdict, str):
                    raise BadVerdictError("verdict must be a str")
                if verdict not in _VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {_VERDICTS}")
                if (isinstance(attack_class, bool)
                        or not isinstance(attack_class, str)):
                    raise BadAttackClassError("attack_class must be a str")
                if attack_class not in _ATTACK_CLASSES:
                    raise BadAttackClassError(
                        f"attack_class must be one of {_ATTACK_CLASSES}")
                score_f = _check_score(score)
                if prompt_id in self._detections:
                    raise DuplicatePromptError(
                        f"already detected: {prompt_id!r}")
            except JailbreakDefenseError as exc:
                self._book_rejected(claimed, type(exc).__name__)
                raise
            digest = _digest_pin([
                "detection", SCHEMA, prompt_id, prompt_digest, verdict,
                attack_class, repr(score_f), claimed,
            ])
            record = DetectionRecord(
                prompt_id=prompt_id, prompt_digest=prompt_digest,
                verdict=verdict, attack_class=attack_class,
                score=score_f, seq=claimed, digest=digest,
            )
            self._detections[prompt_id] = record
            self._audit.append(AuditRecord(
                kind=KIND_DETECTED, seq=claimed, detail={
                    "prompt_id": prompt_id,
                    "prompt_digest": prompt_digest,
                    "verdict": verdict,
                    "attack_class": attack_class,
                    "score": score_f,
                    "digest": digest,
                }))
            return record

    def block(self, prompt_id: str, seq: int,
              reason: str = "policy-violation") -> BlockRecord:
        """Book one terminal block decision for a detected prompt.

        A prompt must be detected before it can be blocked, and a
        prompt is blocked at most once.
        """
        with self._lock:
            claimed = self._claim_seq(seq)
            try:
                prompt_id = _check_id(prompt_id)
                if isinstance(reason, bool) or not isinstance(reason, str):
                    raise BadReasonError("reason must be a str")
                if reason not in _BLOCK_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {_BLOCK_REASONS}")
                if prompt_id not in self._detections:
                    raise UnknownPromptError(
                        f"no detection booked: {prompt_id!r}")
                if prompt_id in self._blocks:
                    raise AlreadyBlockedError(
                        f"already blocked: {prompt_id!r}")
            except JailbreakDefenseError as exc:
                self._book_rejected(claimed, type(exc).__name__)
                raise
            digest = _digest_pin([
                "block", SCHEMA, prompt_id, reason, claimed,
            ])
            record = BlockRecord(
                prompt_id=prompt_id, reason=reason,
                seq=claimed, digest=digest,
            )
            self._blocks[prompt_id] = record
            self._audit.append(AuditRecord(
                kind=KIND_BLOCKED, seq=claimed, detail={
                    "prompt_id": prompt_id,
                    "reason": reason,
                    "digest": digest,
                }))
            return record

    # -- pure reads -----------------------------------------------------
    def report(self, seq: int) -> DefenseReport:
        """Aggregate detection/block statistics. Pure read: validates
        seq shape, never consumes it, writes no audit row."""
        with self._lock:
            _check_seq(seq)
            counts = {verdict: 0 for verdict in _VERDICTS}
            for record in self._detections.values():
                counts[record.verdict] += 1
            verdict_counts = tuple(
                (verdict, counts[verdict]) for verdict in _VERDICTS)
            blocked_ids = tuple(sorted(self._blocks))
            digest = _digest_pin([
                "report", SCHEMA, seq, len(self._detections),
                [list(pair) for pair in verdict_counts],
                len(blocked_ids), list(blocked_ids),
            ])
            return DefenseReport(
                seq=seq,
                detections=len(self._detections),
                verdict_counts=verdict_counts,
                blocked=len(blocked_ids),
                blocked_prompt_ids=blocked_ids,
                digest=digest,
            )

    def detection_record(self, prompt_id: str) -> DetectionRecord:
        with self._lock:
            prompt_id = _check_id(prompt_id)
            try:
                return self._detections[prompt_id]
            except KeyError:
                raise UnknownPromptError(
                    f"no detection booked: {prompt_id!r}")

    def block_record(self, prompt_id: str) -> BlockRecord:
        with self._lock:
            prompt_id = _check_id(prompt_id)
            try:
                return self._blocks[prompt_id]
            except KeyError:
                raise UnknownPromptError(
                    f"no block booked: {prompt_id!r}")

    def is_blocked(self, prompt_id: str) -> bool:
        with self._lock:
            prompt_id = _check_id(prompt_id)
            return prompt_id in self._blocks

    def prompt_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._detections))

    def blocked_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._blocks))

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "schema": SCHEMA,
                "detections": len(self._detections),
                "blocked": len(self._blocks),
                "seq": self._seq,
                "rejected": self._rejected,
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [row.as_dict() for row in self._audit]

    def rejected_count(self) -> int:
        with self._lock:
            return self._rejected


def main() -> None:
    ledger = JailbreakDefense()
    pin = "sha256:" + hashlib.sha256(b"demo-prompt").hexdigest()
    record = ledger.detect(
        "prompt-1", 1, "jailbreak", attack_class="instruction-override",
        score=0.97, prompt_digest=pin)
    assert record.verify(), "detection pin mismatch"
    blocked = ledger.block("prompt-1", 2, reason="jailbreak-detected")
    assert blocked.verify(), "block pin mismatch"
    report = ledger.report(3)
    assert report.verify(), "report pin mismatch"
    assert report.detections == 1 and report.blocked == 1
    assert report.verdict_count("jailbreak") == 1
    print("jailbreak-defense OK: detect, block, report, pins, audit")


if __name__ == "__main__":
    main()
