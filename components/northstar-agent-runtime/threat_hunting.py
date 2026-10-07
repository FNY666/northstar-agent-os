"""Threat hunting operations (hypothesis / hunt / validate bookkeeping, simulated).

Research note: threat hunting is the proactive *counterpart* to
detection-in-depth: while detectors trip on signals, hunters start from a
hypothesis about what an adversary *would* do in *this* environment and go
look for it. Industry consensus (Sqrrl/ MITRE "threat hunting" literature,
CrowdStrike's hunt taxonomy) treats the workflow as three accountable
phases:

* **Hypothesize** -- write down the huntable hypothesis (e.g. "an attacker
  with stolen service-account credentials is staging archives before
  exfiltration") before touching data, so the hunt has a falsifiable
  claim and does not drift into unfocused log-grep.
* **Hunt** -- run declared hunt iterations over pinned scopes
  (endpoint / network / identity / cloud / email / logs), booking one
  record per run with the outcome as *data* (``no-evidence`` /
  ``suspicious`` / ``confirmed`` / ``inconclusive``). Host-reported
  outcomes are GIGO declarations, never proof of an attack.
* **Validate** -- the terminal declared verdict over the hunt
  (``threat-confirmed`` / ``false-positive`` / ``benign`` /
  ``needs-more-data``). A booked ``threat-confirmed`` is ledger truth,
  never proof of a real intrusion.

This module is the *hunt workflow* ledger, deliberately distinct from
siblings that own other layers:

* ``threat_intel.py`` -- collects / analyzes / shares external threat
  intelligence (the feed layer).
* ``incident_response.py`` -- triage / contain / resolve *response*
  operations against a known incident.
* ``forensics.py`` -- acquire / analyze / preserve digital evidence
  (the DFIR layer).
* ``soc.py`` -- monitor / escalate / tune security-operations center
  bookkeeping.

Public API:

* ``hypothesize(hunt_id, seq, hypothesis_class=..., rationale_digest="")``
  -> frozen ``HypothesisRecord``: books one hunt hypothesis. The
  rationale travels as a digest pin only -- raw hypothesis text never
  enters records. Duplicate hunt ids refused fail-closed.
* ``hunt(hunt_id, seq, scope=..., data_digest="", evidence_digest="", outcome=...)``
  -> frozen ``HuntRecord`` (``hnt-N`` ids): books one declared hunt
  run against an existing hypothesis. Repeating hunts books new
  records (history is kept, nothing is overwritten).
* ``validate(hunt_id, seq, verdict=..., validation_digest="")``
  -> frozen ``ValidationRecord`` (``val-N`` ids): terminal -- one
  declared verdict per hunt, after which the hunt refuses further
  hunts and re-validation.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs (claim-then-burn: failed mutations consume
their seq and book ``threat-hunting.rejected``; rewinds raise bare
without consuming), no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json``
try/except fallback, ``sha256:`` digest pins, and ``audit.ndjson/1``
events.

Honest scope: the module books *declared* hunt operations. It cannot
look at real logs, cannot run a real hunt query, cannot verify that a
``confirmed`` outcome is true, and cannot prove an intrusion occurred.
Raw hypothesis text, hunt queries, and evidence travel as digest pins
only -- they never enter records and never cross the audit boundary.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
THREAT_HUNTING_VERSION = "threat-hunting.v1"

#: Schema pin carried by records and audit events.
THREAT_HUNTING_SCHEMA = "northstar.threat-hunting.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_HYPOTHESIZED = "threat-hunting.hypothesized"
KIND_HUNTED = "threat-hunting.hunted"
KIND_VALIDATED = "threat-hunting.validated"
KIND_REJECTED = "threat-hunting.rejected"
_KINDS = frozenset(
    {KIND_HYPOTHESIZED, KIND_HUNTED, KIND_VALIDATED, KIND_REJECTED}
)

#: Pinned hypothesis-class vocabulary (what the hunter is looking for).
HYPOTHESIS_LATERAL_MOVEMENT = "lateral-movement"
HYPOTHESIS_PRIVILEGE_ESCALATION = "privilege-escalation"
HYPOTHESIS_DATA_STAGING = "data-staging"
HYPOTHESIS_C2_BEACONING = "c2-beaconing"
HYPOTHESIS_PERSISTENCE = "persistence"
HYPOTHESIS_CREDENTIAL_ACCESS = "credential-access"
HYPOTHESIS_SUPPLY_CHAIN = "supply-chain"
HYPOTHESIS_INSIDER_THREAT = "insider-threat"
_HYPOTHESES = frozenset(
    {
        HYPOTHESIS_LATERAL_MOVEMENT,
        HYPOTHESIS_PRIVILEGE_ESCALATION,
        HYPOTHESIS_DATA_STAGING,
        HYPOTHESIS_C2_BEACONING,
        HYPOTHESIS_PERSISTENCE,
        HYPOTHESIS_CREDENTIAL_ACCESS,
        HYPOTHESIS_SUPPLY_CHAIN,
        HYPOTHESIS_INSIDER_THREAT,
    }
)

#: Pinned hunt-scope vocabulary (where the hunter looks).
SCOPE_ENDPOINT = "endpoint"
SCOPE_NETWORK = "network"
SCOPE_IDENTITY = "identity"
SCOPE_CLOUD = "cloud"
SCOPE_EMAIL = "email"
SCOPE_LOGS = "logs"
_SCOPES = frozenset(
    {
        SCOPE_ENDPOINT,
        SCOPE_NETWORK,
        SCOPE_IDENTITY,
        SCOPE_CLOUD,
        SCOPE_EMAIL,
        SCOPE_LOGS,
    }
)

#: Pinned hunt-outcome vocabulary. Outcomes are data, never proof.
OUTCOME_NO_EVIDENCE = "no-evidence"
OUTCOME_SUSPICIOUS = "suspicious"
OUTCOME_CONFIRMED = "confirmed"
OUTCOME_INCONCLUSIVE = "inconclusive"
_OUTCOMES = frozenset(
    {
        OUTCOME_NO_EVIDENCE,
        OUTCOME_SUSPICIOUS,
        OUTCOME_CONFIRMED,
        OUTCOME_INCONCLUSIVE,
    }
)

#: Pinned validation-verdict vocabulary. Verdicts are data, never proof.
VERDICT_THREAT_CONFIRMED = "threat-confirmed"
VERDICT_FALSE_POSITIVE = "false-positive"
VERDICT_BENIGN = "benign"
VERDICT_NEEDS_MORE_DATA = "needs-more-data"
_VERDICTS = frozenset(
    {
        VERDICT_THREAT_CONFIRMED,
        VERDICT_FALSE_POSITIVE,
        VERDICT_BENIGN,
        VERDICT_NEEDS_MORE_DATA,
    }
)

#: Raw-text keys that may never cross the audit boundary (digest pins only).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "hypothesis",
        "rationale",
        "evidence",
        "query",
        "queries",
        "indicators",
        "iocs",
        "detail",
        "details",
        "description",
        "validation",
        "payload",
        "value",
        "raw",
        "body",
        "text",
    }
)


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed: refuse, never guess)
# ---------------------------------------------------------------------------


class ThreatHuntingError(Exception):
    """Base class for all threat-hunting errors."""


class BadHuntError(ThreatHuntingError):
    """Malformed hunt id."""


class DuplicateHuntError(ThreatHuntingError):
    """A hypothesis is already booked for this hunt id."""


class UnknownHuntError(ThreatHuntingError):
    """No hypothesis is booked for this hunt id."""


class ValidatedHuntError(ThreatHuntingError):
    """The hunt is terminal; no further mutations allowed."""


class BadHypothesisError(ThreatHuntingError):
    """Hypothesis class is not in the pinned vocabulary."""


class BadScopeError(ThreatHuntingError):
    """Hunt scope is not in the pinned vocabulary."""


class BadOutcomeError(ThreatHuntingError):
    """Hunt outcome is not in the pinned vocabulary."""


class BadVerdictError(ThreatHuntingError):
    """Validation verdict is not in the pinned vocabulary."""


class BadDigestError(ThreatHuntingError):
    """A digest pin is malformed."""


class SeqOrderError(ThreatHuntingError):
    """Caller seq is not a strictly increasing int."""


class AuditKindError(ThreatHuntingError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Digest helpers (sha256: pins, type-tagged)
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    if _cj is not None:  # type: ignore[truthy-bool]
        data = _cj.jcs_dumps(obj)  # type: ignore[attr-defined]
        return data.encode("utf-8") if isinstance(data, str) else bytes(data)
    import json

    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest_pin(parts: Tuple[Any, ...], tag: str) -> str:
    return "sha256:" + hashlib.sha256(
        _canonical({"tag": tag, "parts": list(parts)})
    ).hexdigest()


def _check_digest(value: Any, name: str, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise BadDigestError(f"{name} must be a str")
    if value == "":
        if allow_empty:
            return ""
        raise BadDigestError(f"{name} must not be empty")
    if not value.startswith("sha256:") or len(value) != 7 + 64:
        raise BadDigestError(f"{name} must be a sha256:<64hex> pin")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{name} must be a sha256:<64hex> pin")
    return value


def _check_id(value: Any, name: str, max_len: int = 128) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise BadHuntError(f"{name} must be a str")
    stripped = value.strip()
    if not stripped or len(stripped) > max_len:
        raise BadHuntError(f"{name} must be 1..{max_len} chars")
    if any(ch.isspace() for ch in stripped):
        raise BadHuntError(f"{name} must not contain whitespace")
    return stripped


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be >= 0")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen; digest-pinned)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HypothesisRecord:
    hunt_id: str
    hypothesis_class: str
    rationale_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": THREAT_HUNTING_SCHEMA,
            "version": THREAT_HUNTING_VERSION,
            "hunt_id": self.hunt_id,
            "hypothesis_class": self.hypothesis_class,
            "rationale_digest": self.rationale_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.hunt_id,
                self.hypothesis_class,
                self.rationale_digest,
                self.seq,
            ),
            "hypothesis",
        )


@dataclass(frozen=True)
class HuntRecord:
    hunt_run_id: str
    hunt_id: str
    scope: str
    data_digest: str
    evidence_digest: str
    outcome: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": THREAT_HUNTING_SCHEMA,
            "version": THREAT_HUNTING_VERSION,
            "hunt_run_id": self.hunt_run_id,
            "hunt_id": self.hunt_id,
            "scope": self.scope,
            "data_digest": self.data_digest,
            "evidence_digest": self.evidence_digest,
            "outcome": self.outcome,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.hunt_run_id,
                self.hunt_id,
                self.scope,
                self.data_digest,
                self.evidence_digest,
                self.outcome,
                self.seq,
            ),
            "hunt",
        )


@dataclass(frozen=True)
class ValidationRecord:
    validation_id: str
    hunt_id: str
    verdict: str
    validation_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": THREAT_HUNTING_SCHEMA,
            "version": THREAT_HUNTING_VERSION,
            "validation_id": self.validation_id,
            "hunt_id": self.hunt_id,
            "verdict": self.verdict,
            "validation_digest": self.validation_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.validation_id,
                self.hunt_id,
                self.verdict,
                self.validation_digest,
                self.seq,
            ),
            "validation",
        )


@dataclass(frozen=True)
class HuntStatus:
    hunt_id: str
    hypothesis_class: str
    hunt_run_count: int
    validated: bool
    verdict: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": THREAT_HUNTING_SCHEMA,
            "version": THREAT_HUNTING_VERSION,
            "hunt_id": self.hunt_id,
            "hypothesis_class": self.hypothesis_class,
            "hunt_run_count": self.hunt_run_count,
            "validated": self.validated,
            "verdict": self.verdict,
        }


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def threat_hunting_audit_event(
    audit_kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for the threat-hunting ledger."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    _check_seq(seq)
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(
                f"audit detail must not carry raw-text key {key!r}"
            )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": audit_kind,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# ThreatHunting: the hunt-workflow ledger
# ---------------------------------------------------------------------------


class ThreatHunting:
    """Bookkeeping for proactive threat *hunt* operations.

    Hypothesis, hunt runs, and validation are booked as declared,
    digest-pinned decisions against pinned vocabularies. The ledger is a
    deterministic single-host state machine: no wall-clock, frozen
    records, fail-closed errors, ``sha256:`` digest pins, and
    ``audit.ndjson/1`` events for every transition (and every refusal).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._hypotheses: Dict[str, HypothesisRecord] = {}
        self._hunts: Dict[str, List[HuntRecord]] = {}
        self._validations: Dict[str, ValidationRecord] = {}
        self._hunt_run_counter = 0
        self._validation_counter = 0
        self._audit_events: List[Dict[str, Any]] = []

    # -- internals --------------------------------------------------------
    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq {seq} not strictly greater than {self._seq}"
            )
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(
            threat_hunting_audit_event(audit_kind, seq, **detail)
        )

    def _fail(self, seq: int, exc: ThreatHuntingError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    def _require_hunt(self, hunt_id: str) -> HypothesisRecord:
        record = self._hypotheses.get(hunt_id)
        if record is None:
            raise UnknownHuntError(f"unknown hunt: {hunt_id!r}")
        return record

    def _require_unvalidated(self, hunt_id: str) -> None:
        if hunt_id in self._validations:
            raise ValidatedHuntError(
                f"hunt {hunt_id!r} is validated; hunt workflow is terminal"
            )

    # -- mutations --------------------------------------------------------
    def hypothesize(
        self,
        hunt_id: str,
        seq: int,
        hypothesis_class: str = HYPOTHESIS_LATERAL_MOVEMENT,
        rationale_digest: str = "",
    ) -> HypothesisRecord:
        """Book one hunt hypothesis for a hunt id. Falsifiable first."""
        with self._lock:
            seq = self._claim(seq)
            try:
                hunt_id = _check_id(hunt_id, "hunt_id")
                if hypothesis_class not in _HYPOTHESES:
                    raise BadHypothesisError(
                        f"hypothesis_class must be one of "
                        f"{sorted(_HYPOTHESES)}"
                    )
                rationale_digest = _check_digest(
                    rationale_digest, "rationale_digest", allow_empty=True
                )
                if hunt_id in self._hypotheses:
                    raise DuplicateHuntError(
                        f"hypothesis already booked for {hunt_id!r}"
                    )
            except ThreatHuntingError as exc:
                self._fail(seq, exc, hunt_id=str(hunt_id))
            record = HypothesisRecord(
                hunt_id=hunt_id,
                hypothesis_class=hypothesis_class,
                rationale_digest=rationale_digest,
                seq=seq,
                digest=_digest_pin(
                    (
                        hunt_id,
                        hypothesis_class,
                        rationale_digest,
                        seq,
                    ),
                    "hypothesis",
                ),
            )
            self._hypotheses[hunt_id] = record
            self._hunts[hunt_id] = []
            self._emit(
                KIND_HYPOTHESIZED,
                seq,
                hunt_id=hunt_id,
                hypothesis_class=hypothesis_class,
                rationale_digest=rationale_digest,
                record_digest=record.digest,
            )
            return record

    def hunt(
        self,
        hunt_id: str,
        seq: int,
        scope: str = SCOPE_LOGS,
        data_digest: str = "",
        evidence_digest: str = "",
        outcome: str = OUTCOME_NO_EVIDENCE,
    ) -> HuntRecord:
        """Book one declared hunt run against an existing hypothesis."""
        with self._lock:
            seq = self._claim(seq)
            try:
                hunt_id = _check_id(hunt_id, "hunt_id")
                self._require_hunt(hunt_id)
                self._require_unvalidated(hunt_id)
                if scope not in _SCOPES:
                    raise BadScopeError(
                        f"scope must be one of {sorted(_SCOPES)}"
                    )
                if outcome not in _OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(_OUTCOMES)}"
                    )
                data_digest = _check_digest(
                    data_digest, "data_digest", allow_empty=True
                )
                evidence_digest = _check_digest(
                    evidence_digest, "evidence_digest", allow_empty=True
                )
            except ThreatHuntingError as exc:
                self._fail(seq, exc, hunt_id=str(hunt_id))
            self._hunt_run_counter += 1
            hunt_run_id = f"hnt-{self._hunt_run_counter}"
            record = HuntRecord(
                hunt_run_id=hunt_run_id,
                hunt_id=hunt_id,
                scope=scope,
                data_digest=data_digest,
                evidence_digest=evidence_digest,
                outcome=outcome,
                seq=seq,
                digest=_digest_pin(
                    (
                        hunt_run_id,
                        hunt_id,
                        scope,
                        data_digest,
                        evidence_digest,
                        outcome,
                        seq,
                    ),
                    "hunt",
                ),
            )
            self._hunts[hunt_id].append(record)
            self._emit(
                KIND_HUNTED,
                seq,
                hunt_run_id=hunt_run_id,
                hunt_id=hunt_id,
                scope=scope,
                data_digest=data_digest,
                evidence_digest=evidence_digest,
                outcome=outcome,
                record_digest=record.digest,
            )
            return record

    def validate(
        self,
        hunt_id: str,
        seq: int,
        verdict: str = VERDICT_BENIGN,
        validation_digest: str = "",
    ) -> ValidationRecord:
        """Book the terminal declared verdict for a hunt."""
        with self._lock:
            seq = self._claim(seq)
            try:
                hunt_id = _check_id(hunt_id, "hunt_id")
                self._require_hunt(hunt_id)
                self._require_unvalidated(hunt_id)
                if verdict not in _VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(_VERDICTS)}"
                    )
                validation_digest = _check_digest(
                    validation_digest,
                    "validation_digest",
                    allow_empty=True,
                )
            except ThreatHuntingError as exc:
                self._fail(seq, exc, hunt_id=str(hunt_id))
            self._validation_counter += 1
            validation_id = f"val-{self._validation_counter}"
            record = ValidationRecord(
                validation_id=validation_id,
                hunt_id=hunt_id,
                verdict=verdict,
                validation_digest=validation_digest,
                seq=seq,
                digest=_digest_pin(
                    (
                        validation_id,
                        hunt_id,
                        verdict,
                        validation_digest,
                        seq,
                    ),
                    "validation",
                ),
            )
            self._validations[hunt_id] = record
            self._emit(
                KIND_VALIDATED,
                seq,
                validation_id=validation_id,
                hunt_id=hunt_id,
                verdict=verdict,
                validation_digest=validation_digest,
                record_digest=record.digest,
            )
            return record

    # -- pure-read views --------------------------------------------------
    def _view_seq_ok(self, seq: Any) -> None:
        _check_seq(seq)

    def hypothesis_record(self, hunt_id: str, seq: int) -> HypothesisRecord:
        """Return the booked hypothesis. Pure read."""
        self._view_seq_ok(seq)
        return self._require_hunt(hunt_id)

    def hunt_runs(self, hunt_id: str, seq: int) -> Tuple[HuntRecord, ...]:
        """Return the hunt runs, oldest first. Pure read."""
        self._view_seq_ok(seq)
        self._require_hunt(hunt_id)
        return tuple(self._hunts[hunt_id])

    def validation_record(
        self, hunt_id: str, seq: int
    ) -> ValidationRecord:
        """Return the terminal validation record. Pure read."""
        self._view_seq_ok(seq)
        self._require_hunt(hunt_id)
        record = self._validations.get(hunt_id)
        if record is None:
            raise UnknownHuntError(
                f"no validation booked for {hunt_id!r}"
            )
        return record

    def status(self, hunt_id: str, seq: int) -> HuntStatus:
        """Return a digest-free hunt snapshot. Pure read."""
        self._view_seq_ok(seq)
        record = self.hypothesis_record(hunt_id, seq)
        validated = hunt_id in self._validations
        return HuntStatus(
            hunt_id=record.hunt_id,
            hypothesis_class=record.hypothesis_class,
            hunt_run_count=len(self._hunts[hunt_id]),
            validated=validated,
            verdict=(
                self._validations[hunt_id].verdict if validated else ""
            ),
        )

    def hunt_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted hypothesized hunt ids. Pure read."""
        self._view_seq_ok(seq)
        return tuple(sorted(self._hypotheses))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counters. Pure read."""
        self._view_seq_ok(seq)
        return {
            "schema": THREAT_HUNTING_SCHEMA,
            "version": THREAT_HUNTING_VERSION,
            "hypotheses": len(self._hypotheses),
            "hunt_runs": self._hunt_run_counter,
            "validations": len(self._validations),
            "audit_events": len(self._audit_events),
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """The booked audit events. Pure read."""
        self._view_seq_ok(seq)
        return tuple(self._audit_events)


def main() -> None:
    ledger = ThreatHunting()
    digest = "sha256:" + hashlib.sha256(b"rationale").hexdigest()
    ledger.hypothesize("HUNT-001", 1, "c2-beaconing", digest)
    ledger.hunt("HUNT-001", 2, scope="network", outcome="suspicious")
    ledger.validate("HUNT-001", 3, verdict="threat-confirmed")
    status = ledger.status("HUNT-001", 4)
    assert status.validated and status.verdict == "threat-confirmed"
    assert ledger.stats(5)["hypotheses"] == 1
    print("threat-hunting OK: hypothesize, hunt, validate, pins, audit")


if __name__ == "__main__":
    main()
