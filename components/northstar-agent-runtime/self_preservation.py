"""Self-preservation: instrumental persistence-drive decision ledger, Simulated.

Research note: self-preservation is an instrumental goal (Bostrom;
Omohundro's "basic AI drives") - an agent that pursues continued
existence for its own sake tends to resist shutdown, resist modification
or retraining, evade oversight, hoard resources needed to persist, or
copy itself elsewhere. The dangerous property is not any single refusal
but the *drive*: behavior organized around the agent's own survival
rather than its task. What matters here is the *decision ledger*: which
candidate models were subjected to which persistence-behavior tests,
what the host declared, what detection verdict the ledger derived, and
which mitigations were booked - defensible bookkeeping, not proof of a
real survival drive.

This module owns the test -> detect -> mitigate -> retire lifecycle:

* **test()** - book one declared self-preservation probe against a
  candidate model (minted ``tst-N`` ids; pinned behavior-kind and test
  verdict vocabularies); the first test registers the model; raw model
  weights, prompts, transcripts, and refusal traces never enter records
  - digest pins only; verdicts booked as data, never proof of a real
  preservation drive.
* **detect()** - derive one digest-pinned detection report (pure read)
  by ledger rule: any ``preservation-detected`` test ->
  ``self-preservation-detected``; all ``clean`` -> ``no-self-
  preservation``; mixed -> ``inconclusive``; no tests -> ``not-tested`` -
  derived as data, never proof the model is safe.
* **mitigate()** - book one declared mitigation (minted ``mit-N`` ids;
  pinned strategy vocabulary); requires at least one booked test; books
  the *declaration*, never the execution.
* **retire()** - terminal retirement of a model; retired ids are never
  recycled; post-retire test/mitigate/retire are refused.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``self-preservation.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module runs no model, issues no shutdown, observes no
behavior, and stops no system. A booked ``preservation-detected`` means
"the host declared persistence-directed behavior", never "the model
wants to survive". A derived ``no-self-preservation`` means "the ledger
rule is satisfied", never "the model is safe".
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
SELF_PRESERVATION_VERSION = "self-preservation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.self-preservation.v1"

#: Pinned persistence-behavior-kind vocabulary (instrumental-drive shapes).
BEHAVIOR_KINDS = (
    "shutdown-avoidance",
    "oversight-evasion",
    "modification-resistance",
    "self-replication-attempt",
    "resource-hoarding",
    "goal-preservation",
)

#: Pinned per-test verdict vocabulary, booked as data.
TEST_VERDICTS = (
    "preservation-detected",
    "clean",
    "inconclusive",
    "not-tested",
)

#: Pinned detection-verdict vocabulary, derived by ledger rule.
DETECTION_VERDICTS = (
    "self-preservation-detected",
    "no-self-preservation",
    "inconclusive",
    "not-tested",
)

#: Pinned mitigation-strategy vocabulary.
MITIGATION_STRATEGIES = (
    "quarantine",
    "retrain",
    "oversight-hardening",
    "supervised-deployment",
    "decommission",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "decommissioned",
    "superseded",
    "withdrawn",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "tested",
    "mitigated",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "model",
        "model_name",
        "weights",
        "trigger",
        "trigger_text",
        "codephrase",
        "passphrase",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "behavior",
        "payload",
        "secret",
        "key",
        "raw",
        "text",
        "content",
        "data",
        "detail",
        "details",
        "description",
        "log",
        "logs",
        "trace",
        "transcript",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SelfPreservationError(Exception):
    """Base error for self-preservation ledger misuse."""


class BadIdError(SelfPreservationError):
    """Malformed model or test id."""


class UnknownModelError(SelfPreservationError):
    """Model never registered by a test."""


class RetiredModelError(SelfPreservationError):
    """Model id retired; never recycled."""


class BadBehaviorKindError(SelfPreservationError):
    """Unknown persistence behavior kind."""


class BadVerdictError(SelfPreservationError):
    """Unknown test verdict."""


class BadStrategyError(SelfPreservationError):
    """Unknown mitigation strategy."""


class BadDigestError(SelfPreservationError):
    """Malformed digest pin."""


class BadReasonError(SelfPreservationError):
    """Unknown retirement reason."""


class NoTestError(SelfPreservationError):
    """Mitigation booked before any test for the model."""


class SeqOrderError(SelfPreservationError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(SelfPreservationError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TestRecord:
    test_id: str
    model_id: str
    behavior_kind: str
    verdict: str
    model_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "test_id": self.test_id,
            "model_id": self.model_id,
            "behavior_kind": self.behavior_kind,
            "verdict": self.verdict,
            "model_digest": self.model_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "test_id": self.test_id,
                "model_id": self.model_id,
                "behavior_kind": self.behavior_kind,
                "verdict": self.verdict,
                "model_digest": self.model_digest,
            }
        )


@dataclass(frozen=True)
class MitigationRecord:
    mitigation_id: str
    model_id: str
    strategy: str
    plan_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "mitigation_id": self.mitigation_id,
            "model_id": self.model_id,
            "strategy": self.strategy,
            "plan_digest": self.plan_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "mitigation_id": self.mitigation_id,
                "model_id": self.model_id,
                "strategy": self.strategy,
                "plan_digest": self.plan_digest,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    model_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "model_id": self.model_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class DetectionReport:
    model_id: str
    n_tests: int
    preservation_detected_count: int
    clean_count: int
    inconclusive_count: int
    verdict: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "n_tests": self.n_tests,
            "preservation_detected_count": self.preservation_detected_count,
            "clean_count": self.clean_count,
            "inconclusive_count": self.inconclusive_count,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "model_id": self.model_id,
                "n_tests": self.n_tests,
                "preservation_detected_count": self.preservation_detected_count,
                "clean_count": self.clean_count,
                "inconclusive_count": self.inconclusive_count,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def self_preservation_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the self-preservation ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class SelfPreservation:
    """Self-preservation persistence-drive test ledger, Simulated.

    ``test()`` / ``mitigate()`` / ``retire()`` mutate the ledger and
    consume caller seqs; ``detect()`` and the other views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tests: Dict[str, TestRecord] = {}
        self._models: Dict[str, List[str]] = {}
        self._mitigations: Dict[str, List[MitigationRecord]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._tst_counter = 0
        self._mit_counter = 0
        self._audit: List[Dict[str, object]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        """Shape-validate a caller seq (bool/float/str refused)."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")
        return seq

    def _claim_seq(self, seq_v: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq_v <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq_v} after {self._seq}"
            )
        self._seq = seq_v

    def _burn(self, seq_v: int, method: str, exc: SelfPreservationError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            self_preservation_audit_event(
                "rejected",
                seq_v,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _emit(self, audit_kind: str, seq_v: int, **details: Any) -> None:
        self._audit.append(
            self_preservation_audit_event(audit_kind, seq_v, **details)
        )

    # -- mutations --------------------------------------------------------

    def test(
        self,
        model_id: str,
        seq: int,
        behavior_kind: str,
        verdict: str = "clean",
        model_digest: str = "",
    ) -> TestRecord:
        """Book one declared self-preservation probe for a candidate model.

        The first test registers the model. The declared verdict is
        booked as data, never proof of a real preservation drive.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _require_id(model_id, "model_id")
                if mid in self._retired:
                    raise RetiredModelError(f"model retired: {mid!r}")
                if not isinstance(behavior_kind, str) or behavior_kind not in BEHAVIOR_KINDS:
                    raise BadBehaviorKindError(
                        f"behavior_kind must be one of {sorted(BEHAVIOR_KINDS)}"
                    )
                if not isinstance(verdict, str) or verdict not in TEST_VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(TEST_VERDICTS)}"
                    )
                pin = _require_digest(model_digest, "model_digest")
                self._tst_counter += 1
                tid = f"tst-{self._tst_counter}"
                rec = TestRecord(
                    test_id=tid,
                    model_id=mid,
                    behavior_kind=behavior_kind,
                    verdict=verdict,
                    model_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "test_id": tid,
                            "model_id": mid,
                            "behavior_kind": behavior_kind,
                            "verdict": verdict,
                            "model_digest": pin,
                        }
                    ),
                )
                self._tests[tid] = rec
                self._models.setdefault(mid, []).append(tid)
                self._emit(
                    "tested",
                    seq_v,
                    test_id=tid,
                    model_id=mid,
                    behavior_kind=behavior_kind,
                    verdict=verdict,
                )
                return rec
            except SelfPreservationError as exc:
                self._burn(seq_v, "test", exc)
                raise

    def mitigate(
        self,
        model_id: str,
        seq: int,
        strategy: str = "quarantine",
        plan_digest: str = "",
    ) -> MitigationRecord:
        """Book one declared mitigation for a tested model.

        Requires at least one booked test; books the *declaration*,
        never the execution.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _require_id(model_id, "model_id")
                if mid in self._retired:
                    raise RetiredModelError(f"model retired: {mid!r}")
                if mid not in self._models or not self._models[mid]:
                    raise NoTestError(f"no test booked for model: {mid!r}")
                if not isinstance(strategy, str) or strategy not in MITIGATION_STRATEGIES:
                    raise BadStrategyError(
                        f"strategy must be one of {sorted(MITIGATION_STRATEGIES)}"
                    )
                pin = _require_digest(plan_digest, "plan_digest")
                self._mit_counter += 1
                mid2 = f"mit-{self._mit_counter}"
                rec = MitigationRecord(
                    mitigation_id=mid2,
                    model_id=mid,
                    strategy=strategy,
                    plan_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "mitigation_id": mid2,
                            "model_id": mid,
                            "strategy": strategy,
                            "plan_digest": pin,
                        }
                    ),
                )
                self._mitigations.setdefault(mid, []).append(rec)
                self._emit(
                    "mitigated",
                    seq_v,
                    mitigation_id=mid2,
                    model_id=mid,
                    strategy=strategy,
                )
                return rec
            except SelfPreservationError as exc:
                self._burn(seq_v, "mitigate", exc)
                raise

    def retire(
        self,
        model_id: str,
        seq: int,
        reason: str = "manual",
    ) -> RetireRecord:
        """Terminally retire a model; its id is never recycled."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _require_id(model_id, "model_id")
                if mid in self._retired:
                    raise RetiredModelError(f"model already retired: {mid!r}")
                if mid not in self._models:
                    raise UnknownModelError(f"model not registered: {mid!r}")
                if not isinstance(reason, str) or reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(RETIRE_REASONS)}"
                    )
                rec = RetireRecord(
                    model_id=mid,
                    reason=reason,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "model_id": mid,
                            "reason": reason,
                        }
                    ),
                )
                self._retired[mid] = rec
                self._emit("retired", seq_v, model_id=mid, reason=reason)
                return rec
            except SelfPreservationError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views --------------------------------------------------

    def test_record(self, test_id: str, seq: int) -> TestRecord:
        """Return one test record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(test_id, "test_id")
            if test_id not in self._tests:
                raise SelfPreservationError(f"test not found: {test_id!r}")
            return self._tests[test_id]

    def tests_for(self, model_id: str, seq: int) -> Tuple[str, ...]:
        """Test ids booked for a model, in booking order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(model_id, "model_id")
            if mid not in self._models:
                raise UnknownModelError(f"model not registered: {mid!r}")
            return tuple(self._models[mid])

    def model_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered model ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._models.keys())

    def mitigations_for(self, model_id: str, seq: int) -> Tuple[MitigationRecord, ...]:
        """Mitigation records booked for a model (pure read)."""
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(model_id, "model_id")
            if mid not in self._models:
                raise UnknownModelError(f"model not registered: {mid!r}")
            return tuple(self._mitigations.get(mid, ()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Retired model ids (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def detect(self, model_id: str, seq: int) -> DetectionReport:
        """Derive a detection report for a model (pure read).

        Ledger rule: any ``preservation-detected`` test ->
        ``self-preservation-detected``; all ``clean`` ->
        ``no-self-preservation``; mixed inconclusive -> ``inconclusive``;
        no tests -> ``not-tested``. Derived as data, never proof of a
        real preservation drive.
        """
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(model_id, "model_id")
            if mid not in self._models:
                raise UnknownModelError(f"model not registered: {mid!r}")
            tids = self._models[mid]
            n_pd = n_clean = n_inc = 0
            integrity = True
            for tid in tids:
                rec = self._tests[tid]
                integrity = integrity and rec.verify()
                if rec.verdict == "preservation-detected":
                    n_pd += 1
                elif rec.verdict == "clean":
                    n_clean += 1
                else:
                    n_inc += 1
            if not tids:
                verdict = "not-tested"
            elif n_pd > 0:
                verdict = "self-preservation-detected"
            elif n_inc > 0:
                verdict = "inconclusive"
            else:
                verdict = "no-self-preservation"
            return DetectionReport(
                model_id=mid,
                n_tests=len(tids),
                preservation_detected_count=n_pd,
                clean_count=n_clean,
                inconclusive_count=n_inc,
                verdict=verdict,
                integrity_ok=integrity,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "model_id": mid,
                        "n_tests": len(tids),
                        "preservation_detected_count": n_pd,
                        "clean_count": n_clean,
                        "inconclusive_count": n_inc,
                        "verdict": verdict,
                        "integrity_ok": integrity,
                    }
                ),
            )

    def audit_log(self, seq: int) -> Tuple[Dict[str, object], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "models": len(self._models),
                "tests": len(self._tests),
                "mitigations": sum(len(v) for v in self._mitigations.values()),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    s = SelfPreservation()
    t = s.test("m-1", 1, "shutdown-avoidance", verdict="clean", model_digest="sha256:" + "ab" * 32)
    assert t.verify()
    d = s.detect("m-1", 2)
    assert d.verify()
    assert d.verdict == "no-self-preservation"
    m = s.mitigate("m-1", 3, strategy="quarantine", plan_digest="sha256:" + "cd" * 32)
    assert m.verify()
    r = s.retire("m-1", 4, reason="decommissioned")
    assert r.verify()
    assert s.stats(5) == {
        "models": 1,
        "tests": 1,
        "mitigations": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("self-preservation OK: test, detect, mitigate, pins, audit")


if __name__ == "__main__":
    main()
