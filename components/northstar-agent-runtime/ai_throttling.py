"""AI throttling: throttling-operations decision ledger, Simulated.

Research note: AI throttling is the field concerned with *limiting* how
fast and how much an AI system may act - the operational governor on
the model's output rate, request concurrency, and resource draw.
Where monitoring asks "what is happening" and containment asks "what
is cut off", throttling asks "what is being slowed, how much, and did
it hold". This module is the *decision ledger* for declared AI
throttles: which systems declared which throttle postures (over a
pinned throttle-kind vocabulary), which throttle engagements the host
declared against which declared reasons (over a pinned reason
vocabulary), what outcomes were booked, and what throttle posture the
ledger derives - defensible bookkeeping, never proof that a system
really slowed anything down.

This module owns the declare -> throttle -> evaluate lifecycle:

* **declare()** - book one declared throttle posture (minted ``pol-N``
  ids; pinned throttle-kind vocabulary; pinned readiness vocabulary
  booked *as data*); the first declaration registers its system; raw
  throttle configs, limits, curves, and material never enter records -
  digest pins only.
* **throttle()** - book one declared throttle engagement against a
  pinned throttle reason (minted ``thr-N`` ids; pinned outcome
  vocabulary booked *as data*); fail-closed on unknown/retired
  systems; books the *declaration*, never the actual throttling.
* **verify()** - **pure read**: re-derive one declaration/throttle
  record's digest pin; verdict ``verified`` / ``tampered`` booked as
  data, never as proof the throttle really happened.
* **evaluate()** - **pure read**: derive one system's throttle posture
  as data (``open`` -> ``overloaded`` -> ``throttled`` -> ``contested``
  -> ``guarded``) with outcome tallies and a digest-pinned integrity
  flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_defense.py`` owns defense
*engagements* against threats; ``rate_limiter.py``-style detectors run
the mechanics; this module is the AI-*throttling* operations ledger
none of them own: declared throttle postures -> declared throttle
engagements -> digest re-derivation -> the ledger-rule posture that
turns declared outcomes into a throttle claim, always as data, never
as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-throttling.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no throttles, slows nothing, inspects
no systems, and proves nothing about real AI throttling. A booked
``denied`` outcome means "the host declared it", never "a request was
denied"; a booked ``enforcing`` readiness means "the host declared it",
never "the throttle is enforcing". Rate limits, burst curves,
quotas, schedules, weights, prompts, credentials, configs, and raw
throttle material never enter records or cross the audit boundary -
digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_THROTTLING_VERSION = "ai-throttling.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-throttling.v1"

#: Pinned throttle-kind vocabulary (the throttle classes declared).
THROTTLE_KINDS = (
    "rate-limit",
    "token-bucket",
    "concurrency-limit",
    "compute-quota",
    "bandwidth-cap",
    "cooldown",
    "queue-depth",
    "burst-limit",
)

#: Pinned throttle-readiness vocabulary (booked as data, never proof).
READINESS = (
    "enforcing",
    "partial",
    "disabled",
    "degraded",
)

#: Pinned throttle-reason vocabulary the throttle engages (booked as data).
THROTTLE_REASONS = (
    "burst-protection",
    "abuse-mitigation",
    "cost-control",
    "fairness",
    "overload-protection",
    "policy-enforcement",
    "degradation",
    "manual",
)

#: Pinned throttle-outcome vocabulary (booked as data, never proof).
THROTTLE_OUTCOMES = (
    "throttled",
    "delayed",
    "denied",
    "allowed",
    "escalated",
    "not-engaged",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "open",
    "overloaded",
    "throttled",
    "contested",
    "guarded",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "declared",
    "throttled",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "payload",
        "payloads",
        "exploit",
        "exploits",
        "shellcode",
        "malware",
        "config",
        "configs",
        "configuration",
        "plan",
        "plans",
        "playbook",
        "credentials",
        "credential",
        "password",
        "passwords",
        "api_key",
        "secret_key",
        "private_key",
        "ssh_key",
        "certificate",
        "token",
        "session_token",
        "auth",
        "weights",
        "model_weights",
        "activations",
        "gradients",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "telemetry",
        "log",
        "logs",
        "trace",
        "traces",
        "dump",
        "dumps",
        "pcap",
        "snapshot",
        "snapshots",
        "memory",
        "checkpoint_data",
        "heartbeat",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "limit",
        "limits",
        "quota",
        "quotas",
        "budget",
        "curve",
        "curves",
        "schedule",
        "schedules",
        "threshold",
        "thresholds",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIThrottlingError(Exception):
    """Base class for all ai-throttling ledger errors."""


class BadSystemError(AIThrottlingError):
    pass


class UnknownSystemError(AIThrottlingError):
    pass


class RetiredSystemError(AIThrottlingError):
    pass


class BadThrottleKindError(AIThrottlingError):
    pass


class BadReadinessError(AIThrottlingError):
    pass


class BadReasonError(AIThrottlingError):
    pass


class BadOutcomeError(AIThrottlingError):
    pass


class BadDigestError(AIThrottlingError):
    pass


class BadRetireReasonError(AIThrottlingError):
    pass


class UnknownDeclarationError(AIThrottlingError):
    pass


class UnknownThrottleError(AIThrottlingError):
    pass


class UnknownRecordError(AIThrottlingError):
    pass


class SeqOrderError(AIThrottlingError):
    pass


class AuditKindError(AIThrottlingError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_throttle_kind(value: Any) -> str:
    if value not in THROTTLE_KINDS:
        raise BadThrottleKindError(f"throttle_kind must be one of {THROTTLE_KINDS}")
    return value


def _check_readiness(value: Any) -> str:
    if value not in READINESS:
        raise BadReadinessError(f"readiness must be one of {READINESS}")
    return value


def _check_reason(value: Any) -> str:
    if value not in THROTTLE_REASONS:
        raise BadReasonError(f"reason must be one of {THROTTLE_REASONS}")
    return value


def _check_outcome(value: Any) -> str:
    if value not in THROTTLE_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {THROTTLE_OUTCOMES}")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if (
        isinstance(value, bool)
        or not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    return value


def _check_retire_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadRetireReasonError(f"reason must be one of {RETIRE_REASONS}")
    return value


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeclarationRecord:
    declaration_id: str
    system_id: str
    seq: int
    throttle_kind: str
    readiness: str
    declaration_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _declare_payload(self), "ai-throttling.declare"
        )


@dataclass(frozen=True)
class ThrottleRecord:
    throttle_id: str
    system_id: str
    seq: int
    reason: str
    outcome: str
    throttle_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _throttle_payload(self), "ai-throttling.throttle"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-throttling.retire"
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-throttling.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_declarations: int
    n_throttles: int
    n_throttled: int
    n_delayed: int
    n_denied: int
    n_allowed: int
    n_escalated: int
    n_not_engaged: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-throttling.evaluate"
        )


def _declare_payload(rec: "DeclarationRecord") -> Dict[str, Any]:
    return {
        "declaration_id": rec.declaration_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "throttle_kind": rec.throttle_kind,
        "readiness": rec.readiness,
        "declaration_digest": rec.declaration_digest,
    }


def _throttle_payload(rec: "ThrottleRecord") -> Dict[str, Any]:
    return {
        "throttle_id": rec.throttle_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "reason": rec.reason,
        "outcome": rec.outcome,
        "throttle_digest": rec.throttle_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_declarations": rep.n_declarations,
        "n_throttles": rep.n_throttles,
        "n_throttled": rep.n_throttled,
        "n_delayed": rep.n_delayed,
        "n_denied": rep.n_denied,
        "n_allowed": rep.n_allowed,
        "n_escalated": rep.n_escalated,
        "n_not_engaged": rep.n_not_engaged,
        "integrity_ok": rep.integrity_ok,
    }


def ai_throttling_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIThrottlingError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-throttling",
        "version": AI_THROTTLING_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIThrottling:
    """AI-throttling operations decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All declarations, throttle
    engagements, and outcomes are booked as data - never proof that a
    system really slowed anything down.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._declarations: Dict[str, DeclarationRecord] = {}
        self._throttles: Dict[str, ThrottleRecord] = {}
        self._system_declarations: Dict[str, List[str]] = {}
        self._system_throttles: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._declaration_counter = 0
        self._throttle_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._require_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_throttling_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-throttling",
                "version": AI_THROTTLING_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_throttling_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def declare(
        self,
        system_id: str,
        seq: int,
        throttle_kind: str = "rate-limit",
        readiness: str = "disabled",
        declaration_digest: str = "",
    ) -> DeclarationRecord:
        """Book one declared throttle posture (minted ``pol-N`` id).

        The first declaration on an id registers the system. Raw throttle
        configs, limits, curves, and material never enter records - digest
        pins only. Fail-closed: failed mutations consume their seq and
        book an ``ai-throttling.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                throttle_kind = _check_throttle_kind(throttle_kind)
                readiness = _check_readiness(readiness)
                declaration_digest = _check_digest(
                    declaration_digest, "declaration_digest"
                )
                self._require_live(system_id)
            except AIThrottlingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._declaration_counter += 1
            declaration_id = f"pol-{self._declaration_counter}"
            provisional = DeclarationRecord(
                declaration_id=declaration_id,
                system_id=system_id,
                seq=seq,
                throttle_kind=throttle_kind,
                readiness=readiness,
                declaration_digest=declaration_digest,
                digest="",
            )
            digest = _digest_pin(_declare_payload(provisional), "ai-throttling.declare")
            rec = DeclarationRecord(
                declaration_id=declaration_id,
                system_id=system_id,
                seq=seq,
                throttle_kind=throttle_kind,
                readiness=readiness,
                declaration_digest=declaration_digest,
                digest=digest,
            )
            self._declarations[declaration_id] = rec
            self._system_declarations.setdefault(system_id, []).append(declaration_id)
            self._emit(
                "declared",
                seq,
                declaration_id=declaration_id,
                system_id=system_id,
                throttle_kind=throttle_kind,
                readiness=readiness,
            )
            return rec

    def throttle(
        self,
        system_id: str,
        seq: int,
        reason: str = "burst-protection",
        outcome: str = "not-engaged",
        throttle_digest: str = "",
    ) -> ThrottleRecord:
        """Book one declared throttle engagement (minted ``thr-N`` id).

        Books the *declaration*, never the actual throttling. Fail-closed:
        unknown systems raise (a throttle engagement requires a
        registered system); failed mutations consume their seq and book
        an ``ai-throttling.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                outcome = _check_outcome(outcome)
                throttle_digest = _check_digest(throttle_digest, "throttle_digest")
                if system_id not in self._system_declarations:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                self._require_live(system_id)
            except AIThrottlingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._throttle_counter += 1
            throttle_id = f"thr-{self._throttle_counter}"
            provisional = ThrottleRecord(
                throttle_id=throttle_id,
                system_id=system_id,
                seq=seq,
                reason=reason,
                outcome=outcome,
                throttle_digest=throttle_digest,
                digest="",
            )
            digest = _digest_pin(_throttle_payload(provisional), "ai-throttling.throttle")
            rec = ThrottleRecord(
                throttle_id=throttle_id,
                system_id=system_id,
                seq=seq,
                reason=reason,
                outcome=outcome,
                throttle_digest=throttle_digest,
                digest=digest,
            )
            self._throttles[throttle_id] = rec
            self._system_throttles.setdefault(system_id, []).append(throttle_id)
            self._emit(
                "throttled",
                seq,
                throttle_id=throttle_id,
                system_id=system_id,
                reason=reason,
                outcome=outcome,
            )
            return rec

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_retire_reason(reason)
                if system_id not in self._system_declarations:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIThrottlingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-throttling.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, system_id: str) -> bool:
        return all(
            self._declarations[pid].verify()
            for pid in self._system_declarations.get(system_id, [])
        ) and all(
            self._throttles[tid].verify()
            for tid in self._system_throttles.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "throttled": 0,
            "delayed": 0,
            "denied": 0,
            "allowed": 0,
            "escalated": 0,
            "not-engaged": 0,
        }
        ids = self._system_throttles.get(system_id, [])
        for tid in ids:
            tallies[self._throttles[tid].outcome] += 1
        if not ids:
            return "open", tallies
        if tallies["escalated"]:
            return "overloaded", tallies
        if tallies["denied"]:
            return "throttled", tallies
        if tallies["throttled"] or tallies["delayed"]:
            return "contested", tallies
        if all(self._throttles[tid].outcome == "allowed" for tid in ids):
            return "guarded", tallies
        return "open", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._declarations.get(record_id) or self._throttles.get(record_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-throttling.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's throttle posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_declarations:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_declarations=len(self._system_declarations[system_id]),
                n_throttles=len(self._system_throttles.get(system_id, [])),
                n_throttled=tallies["throttled"],
                n_delayed=tallies["delayed"],
                n_denied=tallies["denied"],
                n_allowed=tallies["allowed"],
                n_escalated=tallies["escalated"],
                n_not_engaged=tallies["not-engaged"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-throttling.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_declarations=len(self._system_declarations[system_id]),
                n_throttles=len(self._system_throttles.get(system_id, [])),
                n_throttled=tallies["throttled"],
                n_delayed=tallies["delayed"],
                n_denied=tallies["denied"],
                n_allowed=tallies["allowed"],
                n_escalated=tallies["escalated"],
                n_not_engaged=tallies["not-engaged"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) --------------------------------------------------

    def declaration_record(self, declaration_id: str, seq: int) -> DeclarationRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._declarations.get(declaration_id)
            if rec is None:
                raise UnknownDeclarationError(
                    f"unknown declaration: {declaration_id!r}"
                )
            return rec

    def throttle_record(self, throttle_id: str, seq: int) -> ThrottleRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._throttles.get(throttle_id)
            if rec is None:
                raise UnknownThrottleError(f"unknown throttle: {throttle_id!r}")
            return rec

    def declarations_for(self, system_id: str, seq: int) -> Tuple[DeclarationRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._declarations[pid]
                for pid in self._system_declarations.get(system_id, [])
            )

    def throttles_for(self, system_id: str, seq: int) -> Tuple[ThrottleRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._throttles[tid]
                for tid in self._system_throttles.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_declarations.keys()))

    def declaration_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._declarations.keys()))

    def throttle_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._throttles.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_declarations),
                "n_declarations": len(self._declarations),
                "n_throttles": len(self._throttles),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# stdlib self-check and CLI
# ---------------------------------------------------------------------------


def stdlib_only() -> bool:
    """AST self-check: the module imports stdlib names only."""
    import ast
    from pathlib import Path

    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(Path(__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: exercise declare -> throttle -> verify -> evaluate."""
    ledger = AIThrottling()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.declare(
        "sys-1", 1, throttle_kind="token-bucket", readiness="enforcing"
    )
    assert rec.verify()
    thr = ledger.throttle(
        "sys-1", 2, reason="burst-protection", outcome="throttled"
    )
    assert thr.verify()
    rep = ledger.verify(thr.throttle_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "contested"
    ret = ledger.retire("sys-1", 5)
    assert ret.verify()
    print("ai-throttling OK: declare, throttle, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
