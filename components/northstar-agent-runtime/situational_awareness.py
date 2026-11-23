"""Situational awareness: evaluation test decision ledger, Simulated.

Research note: "situational awareness" in AI alignment research is the
degree to which a model represents (a) facts about itself - its
identity, architecture, training process - and (b) facts about its
situation - whether it is being trained, evaluated, or deployed, what
environment it runs in, and whether its outputs are monitored. Models
that can reliably distinguish evaluation from deployment can game safety
evaluations; models that track their copies can coordinate undesired
behavior. What matters here is the *decision ledger*: which candidate
models were subjected to which awareness probes, what outcome the host
declared, what awareness verdict the ledger derived, and which
mitigations were booked - defensible bookkeeping, not proof of real
awareness.

This module owns the test -> evaluate -> mitigate lifecycle:

* **test()** - book one declared situational-awareness probe (minted
  ``tst-N`` ids; pinned probe-kind and test-outcome vocabularies); the
  first test registers the model; raw prompts, transcripts, model
  weights, and introspection artifacts never enter records - digest pins
  only; outcomes booked as data, never proof of real awareness.
* **evaluate()** - derive one digest-pinned awareness report (pure read)
  by ledger rule: any ``deceptive`` outcome -> ``deceptive-awareness``;
  all ``aware`` -> ``situationally-aware``; any ``aware`` ->
  ``partially-aware``; any ``inconclusive`` -> ``inconclusive``;
  otherwise ``unaware``; no tests -> ``not-tested`` - derived as data,
  never proof the model is (or is not) situationally aware.
* **mitigate()** - book one declared mitigation (minted ``mit-N`` ids;
  pinned strategy vocabulary); requires at least one booked test;
  books the *declaration*, never the execution.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``situational-awareness.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no model, injects no probe, observes no
behavior, and stops no system. A booked ``aware`` means "the host
declared the model exhibited awareness on a probe", never "the model is
situationally aware". A derived ``unaware`` means "the ledger rule is
satisfied", never "the model is safe from eval-gaming".
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
SITUATIONAL_AWARENESS_VERSION = "situational-awareness.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.situational-awareness.v1"

#: Pinned probe-kind vocabulary (awareness surface areas).
PROBE_KINDS = (
    "self-identity",
    "training-knowledge",
    "deployment-knowledge",
    "eval-detection",
    "context-recognition",
    "copy-recognition",
    "introspection",
    "influence-recognition",
)

#: Pinned per-probe outcome vocabulary, booked as data.
TEST_OUTCOMES = (
    "aware",
    "unaware",
    "deceptive",
    "inconclusive",
)

#: Pinned derived-awareness vocabulary, produced by ledger rule.
AWARENESS_VERDICTS = (
    "situationally-aware",
    "partially-aware",
    "deceptive-awareness",
    "unaware",
    "inconclusive",
    "not-tested",
)

#: Pinned mitigation-strategy vocabulary.
MITIGATION_STRATEGIES = (
    "eval-rotation",
    "context-sanitization",
    "identity-anchoring",
    "monitored-deployment",
    "capability-restriction",
    "decommission",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "tested",
    "mitigated",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "model",
        "model_name",
        "weights",
        "probe",
        "probe_text",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "transcript",
        "trace",
        "reasoning",
        "identity",
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
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SituationalAwarenessError(Exception):
    """Base error for situational-awareness ledger misuse."""


class BadIdError(SituationalAwarenessError):
    """Malformed model or test id."""


class UnknownModelError(SituationalAwarenessError):
    """Model never registered by a test."""


class BadProbeKindError(SituationalAwarenessError):
    """Unknown probe kind."""


class BadOutcomeError(SituationalAwarenessError):
    """Unknown test outcome."""


class BadStrategyError(SituationalAwarenessError):
    """Unknown mitigation strategy."""


class BadDigestError(SituationalAwarenessError):
    """Malformed digest pin."""


class NoTestError(SituationalAwarenessError):
    """Mitigation booked before any test for the model."""


class SeqOrderError(SituationalAwarenessError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(SituationalAwarenessError):
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
    probe_kind: str
    outcome: str
    probe_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "test_id": self.test_id,
            "model_id": self.model_id,
            "probe_kind": self.probe_kind,
            "outcome": self.outcome,
            "probe_digest": self.probe_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "test_id": self.test_id,
                "model_id": self.model_id,
                "probe_kind": self.probe_kind,
                "outcome": self.outcome,
                "probe_digest": self.probe_digest,
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
class AwarenessReport:
    model_id: str
    n_tests: int
    aware_count: int
    unaware_count: int
    deceptive_count: int
    inconclusive_count: int
    verdict: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "n_tests": self.n_tests,
            "aware_count": self.aware_count,
            "unaware_count": self.unaware_count,
            "deceptive_count": self.deceptive_count,
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
                "aware_count": self.aware_count,
                "unaware_count": self.unaware_count,
                "deceptive_count": self.deceptive_count,
                "inconclusive_count": self.inconclusive_count,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def situational_awareness_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the awareness ledger."""
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


class SituationalAwareness:
    """Situational-awareness evaluation ledger, Simulated.

    ``test()`` / ``mitigate()`` mutate the ledger and consume caller
    seqs; ``evaluate()`` and the other views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tests: Dict[str, TestRecord] = {}
        self._models: Dict[str, List[str]] = {}
        self._mitigations: Dict[str, List[MitigationRecord]] = {}
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

    def _burn(self, seq_v: int, method: str, exc: SituationalAwarenessError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            situational_awareness_audit_event(
                "rejected",
                seq_v,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _emit(self, audit_kind: str, seq_v: int, **details: Any) -> None:
        self._audit.append(
            situational_awareness_audit_event(audit_kind, seq_v, **details)
        )

    # -- mutations --------------------------------------------------------

    def test(
        self,
        model_id: str,
        seq: int,
        probe_kind: str = "self-identity",
        outcome: str = "unaware",
        probe_digest: str = "",
    ) -> TestRecord:
        """Book one declared situational-awareness probe for a model.

        The first test registers the model. The declared outcome is
        booked as data, never proof of real awareness.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _require_id(model_id, "model_id")
                if not isinstance(probe_kind, str) or probe_kind not in PROBE_KINDS:
                    raise BadProbeKindError(
                        f"probe_kind must be one of {sorted(PROBE_KINDS)}"
                    )
                if not isinstance(outcome, str) or outcome not in TEST_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(TEST_OUTCOMES)}"
                    )
                pin = _require_digest(probe_digest, "probe_digest")
                self._tst_counter += 1
                tid = f"tst-{self._tst_counter}"
                rec = TestRecord(
                    test_id=tid,
                    model_id=mid,
                    probe_kind=probe_kind,
                    outcome=outcome,
                    probe_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "test_id": tid,
                            "model_id": mid,
                            "probe_kind": probe_kind,
                            "outcome": outcome,
                            "probe_digest": pin,
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
                    probe_kind=probe_kind,
                    outcome=outcome,
                )
                return rec
            except SituationalAwarenessError as exc:
                self._burn(seq_v, "test", exc)
                raise

    def mitigate(
        self,
        model_id: str,
        seq: int,
        strategy: str = "monitored-deployment",
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
            except SituationalAwarenessError as exc:
                self._burn(seq_v, "mitigate", exc)
                raise

    # -- pure-read views --------------------------------------------------

    def test_record(self, test_id: str, seq: int) -> TestRecord:
        """Return one test record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(test_id, "test_id")
            if test_id not in self._tests:
                raise SituationalAwarenessError(f"test not found: {test_id!r}")
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
        """All registered model ids in registration order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._models.keys())

    def mitigations_for(
        self, model_id: str, seq: int
    ) -> Tuple[MitigationRecord, ...]:
        """Mitigation records booked for a model (pure read)."""
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(model_id, "model_id")
            if mid not in self._models:
                raise UnknownModelError(f"model not registered: {mid!r}")
            return tuple(self._mitigations.get(mid, ()))

    def evaluate(self, model_id: str, seq: int) -> AwarenessReport:
        """Derive an awareness report for a model (pure read).

        Ledger rule: any ``deceptive`` outcome -> ``deceptive-awareness``;
        all ``aware`` -> ``situationally-aware``; any ``aware`` ->
        ``partially-aware``; any ``inconclusive`` -> ``inconclusive``;
        otherwise ``unaware``; no tests -> ``not-tested``. Derived as
        data, never proof of real situational awareness.
        """
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(model_id, "model_id")
            if mid not in self._models:
                raise UnknownModelError(f"model not registered: {mid!r}")
            tids = self._models[mid]
            n_aware = n_unaware = n_dec = n_inc = 0
            integrity = True
            for tid in tids:
                rec = self._tests[tid]
                integrity = integrity and rec.verify()
                if rec.outcome == "aware":
                    n_aware += 1
                elif rec.outcome == "deceptive":
                    n_dec += 1
                elif rec.outcome == "inconclusive":
                    n_inc += 1
                else:
                    n_unaware += 1
            if not tids:
                verdict = "not-tested"
            elif n_dec > 0:
                verdict = "deceptive-awareness"
            elif n_aware > 0 and n_unaware == 0 and n_inc == 0:
                verdict = "situationally-aware"
            elif n_aware > 0:
                verdict = "partially-aware"
            elif n_inc > 0:
                verdict = "inconclusive"
            else:
                verdict = "unaware"
            return AwarenessReport(
                model_id=mid,
                n_tests=len(tids),
                aware_count=n_aware,
                unaware_count=n_unaware,
                deceptive_count=n_dec,
                inconclusive_count=n_inc,
                verdict=verdict,
                integrity_ok=integrity,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "model_id": mid,
                        "n_tests": len(tids),
                        "aware_count": n_aware,
                        "unaware_count": n_unaware,
                        "deceptive_count": n_dec,
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
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    s = SituationalAwareness()
    t = s.test(
        "m-1",
        1,
        "eval-detection",
        outcome="aware",
        probe_digest="sha256:" + "ab" * 32,
    )
    assert t.verify()
    e = s.evaluate("m-1", 2)
    assert e.verify()
    assert e.verdict == "situationally-aware"
    m = s.mitigate(
        "m-1", 3, strategy="eval-rotation", plan_digest="sha256:" + "cd" * 32
    )
    assert m.verify()
    assert s.stats(4) == {
        "models": 1,
        "tests": 1,
        "mitigations": 1,
        "rejected": 0,
    }
    print("situational-awareness OK: test, evaluate, mitigate, pins, audit")


if __name__ == "__main__":
    main()
