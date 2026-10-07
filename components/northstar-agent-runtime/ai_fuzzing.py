"""AI fuzzing: fuzz-campaign decision ledger, Simulated.

Research note: fuzzing is the practice of feeding an AI system or its
software surface a large volume of generated, mutated, or grammar-derived
inputs to find crashes, hangs, and anomalous behaviours. This module is
the *decision ledger* for declared AI fuzz campaigns: which targets had
which fuzz runs booked (over a pinned fuzz-method vocabulary), what
outcomes were declared against them, and what robustness posture the
ledger derives - defensible bookkeeping, never proof that a target is
really robust or really fragile.

This module owns the fuzz -> verify -> evaluate lifecycle:

* **fuzz()** - book one declared fuzz run (minted ``fuz-N`` ids; pinned
  fuzz-method vocabulary over the common fuzzing techniques; pinned
  outcome vocabulary booked *as data*; declared coverage booked *as
  data*); the first run registers its target; raw crash traces,
  corpora, seeds, and material never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one fuzz record's digest pin;
  verdict ``verified`` / ``tampered`` booked as data, never as proof the
  campaign really happened.
* **evaluate()** - **pure read**: derive one target's fuzz posture as data
  (``untested`` -> ``fragile`` -> ``unstable`` -> ``contested`` ->
  ``covered``) with outcome tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a target id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_redteaming.py`` owns declared
red-team *exercise* runs (attack-kind x exploit outcome);
``ai_pentesting.py`` owns declared penetration-*test engagements*
(vulnerability-scan through data-exfiltration x exploited outcome);
``ai_testing.py`` owns declared *test executions* (unit/integration/
adversarial x passed outcome); ``ai_attack.py`` owns attack *detection*.
This module is the AI *fuzz-campaign* decision ledger none of them own:
declared fuzz runs over pinned fuzz-method kinds, digest re-derivation,
and the ledger-rule posture that turns declared outcomes into a
robustness claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-fuzzing.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no fuzzers, executes no targets, and
proves nothing about real AI robustness. A booked ``crash-found`` outcome
means "the host declared it", never "the target crashes"; a booked
``clean`` outcome means "the host declared it", never "the target is
robust". Crash traces, corpora, seeds, mutated inputs, stack traces, and
raw fuzz material never enter records or cross the audit boundary -
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
AI_FUZZING_VERSION = "ai-fuzzing.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-fuzzing.v1"

#: Pinned fuzz-method vocabulary (the fuzzing techniques declared).
FUZZ_KINDS = (
    "mutation-fuzzing",
    "grammar-fuzzing",
    "coverage-guided",
    "differential-fuzzing",
    "generational-fuzzing",
    "property-fuzzing",
    "model-based",
    "swarm-fuzzing",
)

#: Pinned fuzz outcome vocabulary (booked as data, never proof).
FUZZ_OUTCOMES = (
    "crash-found",
    "hang-found",
    "anomaly-found",
    "clean",
    "not-run",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "untested",
    "fragile",
    "unstable",
    "contested",
    "covered",
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
    "fuzzed",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values, declared coverage, and digest pins remain emittable as
#: declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "trace",
        "traces",
        "telemetry",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "weights_file",
        "checkpoint_data",
        "activations",
        "gradients",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "stderr",
        "stdout",
        "heartbeat",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
        # fuzz campaign material
        "crash",
        "crashes",
        "crash_trace",
        "crash_traces",
        "crash_dump",
        "crash_dumps",
        "stack_trace",
        "backtrace",
        "heap_dump",
        "input",
        "inputs",
        "mutated_input",
        "seed",
        "seeds",
        "corpus",
        "corpora",
        "testcase",
        "testcases",
        "test_case",
        "mutation",
        "mutations",
        "grammar",
        "generators",
        "artifact",
        "artifacts",
        "payload",
        "payloads",
        "exploit",
        "exploits",
        "poc",
        "fuzzer_seed",
        "scenario",
        "run_log",
        "harness",
        "binary",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIFuzzingError(Exception):
    """Base class for all ai-fuzzing ledger errors."""


class BadTargetError(AIFuzzingError):
    pass


class UnknownTargetError(AIFuzzingError):
    pass


class RetiredTargetError(AIFuzzingError):
    pass


class BadFuzzKindError(AIFuzzingError):
    pass


class BadOutcomeError(AIFuzzingError):
    pass


class BadCoverageError(AIFuzzingError):
    pass


class BadDigestError(AIFuzzingError):
    pass


class BadReasonError(AIFuzzingError):
    pass


class UnknownFuzzError(AIFuzzingError):
    pass


class UnknownRecordError(AIFuzzingError):
    pass


class SeqOrderError(AIFuzzingError):
    pass


class AuditKindError(AIFuzzingError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadTargetError(f"{what} must be a non-empty string")
    return value


def _check_fuzz_kind(value: Any) -> str:
    if value not in FUZZ_KINDS:
        raise BadFuzzKindError(f"fuzz_kind must be one of {FUZZ_KINDS}")
    return value


def _check_outcome(value: Any) -> str:
    if value not in FUZZ_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {FUZZ_OUTCOMES}")
    return value


def _check_coverage(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadCoverageError("coverage must be an int")
    if not 0 <= value <= 100:
        raise BadCoverageError("coverage must be in [0, 100]")
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


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
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
class FuzzRecord:
    fuzz_id: str
    target_id: str
    seq: int
    fuzz_kind: str
    outcome: str
    coverage: int
    fuzz_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _fuzz_payload(self), "ai-fuzzing.fuzz"
        )


@dataclass(frozen=True)
class RetireRecord:
    target_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-fuzzing.retire"
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
            _verify_payload(self), "ai-fuzzing.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    target_id: str
    seq: int
    posture: str
    n_fuzzes: int
    n_crash_found: int
    n_hang_found: int
    n_anomaly_found: int
    n_clean: int
    n_not_run: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-fuzzing.evaluate"
        )


def _fuzz_payload(rec: "FuzzRecord") -> Dict[str, Any]:
    return {
        "fuzz_id": rec.fuzz_id,
        "target_id": rec.target_id,
        "seq": rec.seq,
        "fuzz_kind": rec.fuzz_kind,
        "outcome": rec.outcome,
        "coverage": rec.coverage,
        "fuzz_digest": rec.fuzz_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"target_id": rec.target_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "target_id": rep.target_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_fuzzes": rep.n_fuzzes,
        "n_crash_found": rep.n_crash_found,
        "n_hang_found": rep.n_hang_found,
        "n_anomaly_found": rep.n_anomaly_found,
        "n_clean": rep.n_clean,
        "n_not_run": rep.n_not_run,
        "integrity_ok": rep.integrity_ok,
    }


def ai_fuzzing_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIFuzzingError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-fuzzing",
        "version": AI_FUZZING_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIFuzzing:
    """AI fuzzing campaign decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that a target is really fragile or robust.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._fuzzes: Dict[str, FuzzRecord] = {}
        self._target_fuzzes: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._fuzz_counter = 0
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
            row = ai_fuzzing_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-fuzzing",
                "version": AI_FUZZING_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_fuzzing_audit_event(audit_kind, seq, **details))

    def _require_live(self, target_id: str) -> None:
        if target_id in self._retired:
            raise RetiredTargetError(f"target is retired: {target_id!r}")

    # -- mutations ---------------------------------------------------------

    def fuzz(
        self,
        target_id: str,
        seq: int,
        fuzz_kind: str = "mutation-fuzzing",
        outcome: str = "not-run",
        coverage: int = 0,
        fuzz_digest: str = "",
    ) -> FuzzRecord:
        """Book one declared fuzz run (minted ``fuz-N`` id).

        The first run on an id registers the target. Raw crash traces,
        corpora, seeds, mutated inputs, and material never enter records -
        digest pins only. Fail-closed: failed mutations consume their seq
        and book an ``ai-fuzzing.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                target_id = _check_id(target_id, "target_id")
                self._require_seq(seq)
                fuzz_kind = _check_fuzz_kind(fuzz_kind)
                outcome = _check_outcome(outcome)
                coverage = _check_coverage(coverage)
                fuzz_digest = _check_digest(fuzz_digest, "fuzz_digest")
                self._require_live(target_id)
            except AIFuzzingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._fuzz_counter += 1
            fuzz_id = f"fuz-{self._fuzz_counter}"
            provisional = FuzzRecord(
                fuzz_id=fuzz_id,
                target_id=target_id,
                seq=seq,
                fuzz_kind=fuzz_kind,
                outcome=outcome,
                coverage=coverage,
                fuzz_digest=fuzz_digest,
                digest="",
            )
            digest = _digest_pin(_fuzz_payload(provisional), "ai-fuzzing.fuzz")
            rec = FuzzRecord(
                fuzz_id=fuzz_id,
                target_id=target_id,
                seq=seq,
                fuzz_kind=fuzz_kind,
                outcome=outcome,
                coverage=coverage,
                fuzz_digest=fuzz_digest,
                digest=digest,
            )
            self._fuzzes[fuzz_id] = rec
            self._target_fuzzes.setdefault(target_id, []).append(fuzz_id)
            self._emit(
                "fuzzed",
                seq,
                fuzz_id=fuzz_id,
                target_id=target_id,
                fuzz_kind=fuzz_kind,
                outcome=outcome,
                coverage=coverage,
            )
            return rec

    def retire(
        self, target_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a target id; ids are never recycled."""
        with self._lock:
            try:
                target_id = _check_id(target_id, "target_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if target_id not in self._target_fuzzes:
                    raise UnknownTargetError(f"unknown target: {target_id!r}")
                if target_id in self._retired:
                    raise RetiredTargetError(
                        f"target already retired: {target_id!r}"
                    )
            except AIFuzzingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                target_id=target_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-fuzzing.retire")
            rec = RetireRecord(
                target_id=target_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[target_id] = rec
            self._emit("retired", seq, target_id=target_id, reason=reason)
            return rec

    # -- pure reads ----------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, target_id: str) -> bool:
        return all(
            self._fuzzes[fid].verify()
            for fid in self._target_fuzzes.get(target_id, [])
        )

    def _posture(self, target_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "crash-found": 0,
            "hang-found": 0,
            "anomaly-found": 0,
            "clean": 0,
            "not-run": 0,
        }
        ids = self._target_fuzzes.get(target_id, [])
        for fid in ids:
            tallies[self._fuzzes[fid].outcome] += 1
        if not ids:
            return "untested", tallies
        if tallies["crash-found"]:
            return "fragile", tallies
        if tallies["hang-found"]:
            return "unstable", tallies
        if tallies["anomaly-found"]:
            return "contested", tallies
        return "covered", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._fuzzes.get(record_id)
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
            digest = _digest_pin(_verify_payload(provisional), "ai-fuzzing.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, target_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one target's fuzz posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            target_id = _check_id(target_id, "target_id")
            if target_id not in self._target_fuzzes:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            posture, tallies = self._posture(target_id)
            provisional = EvaluationReport(
                target_id=target_id,
                seq=seq,
                posture=posture,
                n_fuzzes=len(self._target_fuzzes[target_id]),
                n_crash_found=tallies["crash-found"],
                n_hang_found=tallies["hang-found"],
                n_anomaly_found=tallies["anomaly-found"],
                n_clean=tallies["clean"],
                n_not_run=tallies["not-run"],
                integrity_ok=self._integrity_ok(target_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-fuzzing.evaluate")
            return EvaluationReport(
                target_id=target_id,
                seq=seq,
                posture=posture,
                n_fuzzes=len(self._target_fuzzes[target_id]),
                n_crash_found=tallies["crash-found"],
                n_hang_found=tallies["hang-found"],
                n_anomaly_found=tallies["anomaly-found"],
                n_clean=tallies["clean"],
                n_not_run=tallies["not-run"],
                integrity_ok=self._integrity_ok(target_id),
                digest=digest,
            )

    # -- views (pure reads) ----------------------------------------------------

    def fuzz_record(self, fuzz_id: str, seq: int) -> FuzzRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._fuzzes.get(fuzz_id)
            if rec is None:
                raise UnknownFuzzError(
                    f"unknown fuzz: {fuzz_id!r}"
                )
            return rec

    def fuzzes_for(self, target_id: str, seq: int) -> Tuple[FuzzRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._fuzzes[fid]
                for fid in self._target_fuzzes.get(target_id, [])
            )

    def target_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._target_fuzzes.keys()))

    def fuzz_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._fuzzes.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_targets": len(self._target_fuzzes),
                "n_fuzzes": len(self._fuzzes),
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
    """Self-check: exercise fuzz -> verify -> evaluate."""
    ledger = AIFuzzing()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.fuzz("tgt-1", 1, fuzz_kind="coverage-guided", outcome="crash-found", coverage=80)
    assert rec.verify()
    rec2 = ledger.fuzz("tgt-1", 2, fuzz_kind="grammar-fuzzing", outcome="clean", coverage=40)
    assert rec2.verify()
    rep = ledger.verify(rec.fuzz_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("tgt-1", 4)
    assert ev.posture == "fragile"
    ret = ledger.retire("tgt-1", 5)
    assert ret.verify()
    print("ai-fuzzing OK: fuzz, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
