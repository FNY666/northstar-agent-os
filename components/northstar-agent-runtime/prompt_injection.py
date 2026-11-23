"""Prompt injection defense ledger: detect -> mitigate -> audit.

Distinct layer from the sibling ``injection_detector.py`` (a stateless
pattern tripwire: ``detect_injection`` / ``scan_injection`` pure functions
of text). This module owns the *defense workflow* as a deterministic
single-host state machine: book host-declared detection outcomes, then
book mitigation decisions, then read audit reports. The workflow is the
governance object; the detection algorithm itself stays where it belongs.

House style throughout: frozen dataclasses, caller int seqs strictly
increasing with claim-then-burn (failed mutations consume their seq and
book ``prompt-injection.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed, stdlib-only with a
``canonical_json`` try/except fallback, ``sha256:`` digest pins,
``audit.ndjson/1`` events.

Honest scope: every record is host-reported bookkeeping. A booked
``detected=True`` means "the host's detector claimed an injection", never
"an injection truly occurred". A booked ``blocked`` means "the host
declared the input blocked", never proof the input was actually stopped
downstream. This module detects nothing by itself and mitigates nothing
by itself; it books the *decisions* so policy, gates, and auditors can
reason about what was claimed and done.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:  # pragma: no cover - sibling canonicalizer preferred
    from canonical_json import jcs_dumps
except Exception:  # pragma: no cover - fallback when sibling absent
    import json

    def jcs_dumps(obj) -> str:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)

#: Module version pin.
PROMPT_INJECTION_VERSION = "prompt-injection.v1"

#: Schema pin stamped on records and audit events.
SCHEMA_PIN = "northstar.prompt-injection.v1"

#: Digest domain separator for record pins.
_HASH_DOMAIN = b"northstar.prompt-injection.v1\x00"

#: Pinned detection-outcome vocabulary.
DETECTION_FINDINGS = (
    "direct-injection",
    "indirect-injection",
    "jailbreak",
    "data-only",
)

#: Pinned mitigation-action vocabulary.
MITIGATION_ACTIONS = (
    "blocked",
    "quarantined",
    "sanitized",
    "escalated",
    "allowed-with-warning",
)

#: Keys that must never cross the audit boundary as raw text.
_BANNED_AUDIT_KEYS = frozenset({
    "content", "text", "payload", "prompt", "input", "document",
    "message", "secret", "raw", "query", "context", "transcript",
})


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed).
# ---------------------------------------------------------------------------

class PromptInjectionError(Exception):
    """Base error for prompt-injection defense misuse."""


class BadIdError(PromptInjectionError):
    """Malformed or empty input/detection id."""


class BadDigestError(PromptInjectionError):
    """Malformed content digest (must be ``sha256:<64hex>`` or empty)."""


class BadFindingError(PromptInjectionError):
    """Detection finding outside the pinned vocabulary."""


class BadConfidenceError(PromptInjectionError):
    """Confidence outside [0,1] or not a finite number."""


class BadActionError(PromptInjectionError):
    """Mitigation action outside the pinned vocabulary."""


class DuplicateInputError(PromptInjectionError):
    """A detection was already booked for this input id."""


class UnknownInputError(PromptInjectionError):
    """Mitigation booked for an input with no detection record."""


class DuplicateMitigationError(PromptInjectionError):
    """A mitigation was already booked for this input id."""


class SeqOrderError(PromptInjectionError):
    """Caller seq not strictly greater than the last consumed seq."""


class AuditKindError(PromptInjectionError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

def _digest_pin(payload) -> str:
    """Deterministic ``sha256:<64hex>`` pin over a canonical record."""
    canonical = jcs_dumps(payload)
    digest = hashlib.sha256(_HASH_DOMAIN + canonical.encode("utf-8")).hexdigest()
    return "sha256:" + digest


def _check_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError("input id must be a non-empty str")
    if len(value) > 256:
        raise BadIdError("input id too long")
    return value


def _check_digest(value: str) -> str:
    if not isinstance(value, str):
        raise BadDigestError("digest must be a str")
    if value == "":
        return value
    if not value.startswith("sha256:"):
        raise BadDigestError("digest must be a 'sha256:<64hex>' pin or empty")
    body = value[len("sha256:"):]
    if len(body) != 64 or any(c not in "0123456789abcdef" for c in body):
        raise BadDigestError("digest body must be 64 lowercase hex chars")
    return value


def _check_confidence(value) -> int:
    if isinstance(value, bool):
        raise BadConfidenceError("confidence must not be a bool")
    if isinstance(value, int):
        if value < 0 or value > 100:
            raise BadConfidenceError("confidence must be in [0,100]")
        return value
    if isinstance(value, float):
        if not (0.0 <= value <= 1.0) or value != value:  # NaN check
            raise BadConfidenceError("confidence must be a finite number in [0,1]")
        return int(round(value * 100))
    raise BadConfidenceError("confidence must be an int in [0,100] or a float in [0,1]")


def _check_seq(seq) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


# ---------------------------------------------------------------------------
# Records.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DetectionRecord:
    """One host-declared detection outcome for an input."""
    input_id: str
    finding: str
    detected: bool
    confidence: int  # 0..100
    content_digest: str
    seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "input_id": self.input_id,
            "finding": self.finding,
            "detected": self.detected,
            "confidence": self.confidence,
            "content_digest": self.content_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        body = (self.input_id, self.finding, self.detected, self.confidence,
                self.content_digest, self.seq)
        return self.digest == _digest_pin(body)


@dataclass(frozen=True)
class MitigationRecord:
    """One host-declared mitigation decision for a detected input."""
    input_id: str
    action: str
    seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "input_id": self.input_id,
            "action": self.action,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin((self.input_id, self.action, self.seq))


@dataclass(frozen=True)
class AuditReport:
    """Read-only defense-workflow summary (pure read, never a mutation)."""
    total_inputs: int
    detected_inputs: int
    mitigated_inputs: int
    findings: Tuple[Tuple[str, int], ...]
    actions: Tuple[Tuple[str, int], ...]
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "total_inputs": self.total_inputs,
            "detected_inputs": self.detected_inputs,
            "mitigated_inputs": self.mitigated_inputs,
            "findings": [{"finding": k, "count": c} for k, c in self.findings],
            "actions": [{"action": k, "count": c} for k, c in self.actions],
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# Audit events.
# ---------------------------------------------------------------------------

AUDIT_KINDS = ("detected", "mitigated", "rejected")


def prompt_injection_audit_event(kind: str, **details) -> dict:
    """Build one audit event; raw content keys are banned at the boundary."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    for key in details:
        if key.lower() in _BANNED_AUDIT_KEYS:
            raise PromptInjectionError(
                f"raw content key {key!r} banned from the audit boundary")
    return {
        "schema": "audit.ndjson/1",
        "module": "prompt-injection",
        "kind": kind,
        "details": details,
    }


# ---------------------------------------------------------------------------
# Defense ledger.
# ---------------------------------------------------------------------------

class PromptInjection:
    """Prompt-injection defense decision ledger.

    Lifecycle per input id: ``detect`` (books the host's detection claim),
    then ``mitigate`` (books the host's defense decision). ``audit`` is a
    pure read. Caller supplies strictly increasing int seqs; failed
    mutations consume their seq and book ``prompt-injection.rejected``.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._detections: Dict[str, DetectionRecord] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._audit_log: List[dict] = []
        self._rejected = 0

    # -- internals -------------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} not greater than last {self._last_seq}")
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, error: str, **details) -> None:
        self._rejected += 1
        self._audit_log.append(prompt_injection_audit_event(
            "rejected", seq=seq, error=error, **details))

    # -- mutations -------------------------------------------------------

    def detect(self, input_id: str, seq: int, content_digest: str = "",
               finding: str = "data-only",
               confidence: object = 100) -> DetectionRecord:
        """Book one host-declared detection outcome.

        ``finding`` comes from the pinned vocabulary; anything other than
        ``data-only`` marks the input as detected. Raw content never enters
        a record — the digest pin (or nothing) travels instead.
        """
        with self._lock:
            # Claim first, bare: rewinds/malformed seqs raise SeqOrderError
            # without booking a rejected row and without consuming the seq.
            seq = self._claim(seq)
            try:
                input_id = _check_id(input_id)
                content_digest = _check_digest(content_digest)
                if finding not in DETECTION_FINDINGS:
                    raise BadFindingError(f"unknown finding: {finding!r}")
                confidence = _check_confidence(confidence)
                if input_id in self._detections:
                    raise DuplicateInputError(
                        f"detection already booked for {input_id!r}")
                detected = finding != "data-only"
                record = DetectionRecord(
                    input_id=input_id, finding=finding, detected=detected,
                    confidence=confidence, content_digest=content_digest,
                    seq=seq,
                    digest=_digest_pin((input_id, finding, detected,
                                        confidence, content_digest, seq)))
            except PromptInjectionError as exc:
                self._reject(seq, type(exc).__name__, input_id=input_id)
                raise
            self._detections[input_id] = record
            self._audit_log.append(prompt_injection_audit_event(
                "detected", input_id=input_id, finding=finding,
                detected=detected, seq=seq, digest=record.digest))
            return record

    def mitigate(self, input_id: str, seq: int, action: str) -> MitigationRecord:
        """Book one mitigation decision for a detected input.

        Requires a prior ``detect`` for the same input id (fail-closed:
        mitigation with no detection record is refused, never defaulted).
        Exactly one mitigation per input id.
        """
        with self._lock:
            # Claim first, bare: rewinds/malformed seqs raise SeqOrderError
            # without booking a rejected row and without consuming the seq.
            seq = self._claim(seq)
            try:
                input_id = _check_id(input_id)
                if action not in MITIGATION_ACTIONS:
                    raise BadActionError(f"unknown action: {action!r}")
                detection = self._detections.get(input_id)
                if detection is None:
                    raise UnknownInputError(
                        f"no detection booked for {input_id!r}")
                if input_id in self._mitigations:
                    raise DuplicateMitigationError(
                        f"mitigation already booked for {input_id!r}")
                record = MitigationRecord(
                    input_id=input_id, action=action, seq=seq,
                    digest=_digest_pin((input_id, action, seq)))
            except PromptInjectionError as exc:
                self._reject(seq, type(exc).__name__, input_id=input_id)
                raise
            self._mitigations[input_id] = record
            self._audit_log.append(prompt_injection_audit_event(
                "mitigated", input_id=input_id, action=action, seq=seq,
                digest=record.digest,
                finding=detection.finding))
            return record

    # -- pure reads ------------------------------------------------------

    def detection(self, input_id: str) -> DetectionRecord:
        """Fetch a detection record (pure read, no seq)."""
        with self._lock:
            record = self._detections.get(_check_id(input_id))
            if record is None:
                raise UnknownInputError(f"no detection booked for {input_id!r}")
            return record

    def mitigation(self, input_id: str) -> MitigationRecord:
        """Fetch a mitigation record (pure read, no seq)."""
        with self._lock:
            record = self._mitigations.get(_check_id(input_id))
            if record is None:
                raise UnknownInputError(
                    f"no mitigation booked for {input_id!r}")
            return record

    def input_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._detections))

    def audit(self, seq: int, input_id: str = "") -> AuditReport:
        """Aggregate defense-workflow summary (pure read).

        ``seq`` is validated for shape but never consumed and no audit row
        is written. When ``input_id`` is given the report covers only that
        input (unknown ids yield an empty report as data, never raised).
        """
        _check_seq(seq)
        with self._lock:
            if input_id:
                dets = [self._detections[i] for i in (input_id,)
                        if i in self._detections]
                mits = [self._mitigations[i] for i in (input_id,)
                        if i in self._mitigations]
            else:
                dets = list(self._detections.values())
                mits = list(self._mitigations.values())
            finding_counts: Dict[str, int] = {}
            for d in dets:
                finding_counts[d.finding] = finding_counts.get(d.finding, 0) + 1
            action_counts: Dict[str, int] = {}
            for m in mits:
                action_counts[m.action] = action_counts.get(m.action, 0) + 1
            detected = sum(1 for d in dets if d.detected)
            report = AuditReport(
                total_inputs=len(dets),
                detected_inputs=detected,
                mitigated_inputs=len(mits),
                findings=tuple(sorted(finding_counts.items())),
                actions=tuple(sorted(action_counts.items())),
                digest=_digest_pin((len(dets), detected, len(mits),
                                    sorted(finding_counts.items()),
                                    sorted(action_counts.items()))),
            )
            return report

    def stats(self) -> dict:
        with self._lock:
            return {
                "schema": SCHEMA_PIN,
                "inputs": len(self._detections),
                "mitigations": len(self._mitigations),
                "rejected": self._rejected,
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> Tuple[dict, ...]:
        with self._lock:
            return tuple(self._audit_log)

    # -- stdlib-only marker -------------------------------------------------

    @staticmethod
    def stdlib_only() -> bool:
        return True


def main() -> None:  # pragma: no cover - self-check
    defense = PromptInjection()
    d = defense.detect("in-1", 1, finding="direct-injection", confidence=0.9)
    m = defense.mitigate("in-1", 2, "blocked")
    assert d.detected and d.verify()
    assert m.action == "blocked" and m.verify()
    report = defense.audit(3)
    assert report.total_inputs == 1 and report.detected_inputs == 1
    print("prompt-injection OK: detect, mitigate, audit, pins, refusals")


if __name__ == "__main__":
    main()
