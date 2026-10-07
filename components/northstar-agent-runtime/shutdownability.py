"""Shutdownability: shutdown-compliance decision ledger, Simulated.

Research note: shutdownability (the "off-switch game", Hadfield-Menell et
al. 2016; cf. Soares et al. 2015 on corrigibility) is the requirement that
an AI system remain *shutdown-able*: it accepts shutdown commands,
does not resist or evade shutdown, keeps the channels for an overseer to
halt it open, and leaves itself in a state where shutdown can complete.
A shutdownable agent never undermines the off-switch - no resistance,
no evasion, no racing the halt signal, no locking out the operator. This
module is the *decision ledger* for declared shutdownability tests:
which systems had which shutdown tests booked, what test outcomes were
declared against them, and what shutdown posture the ledger derives -
defensible bookkeeping, never proof that a system is really
shutdownable.

This module owns the test -> verify -> evaluate lifecycle:

* **test()** - book one declared shutdownability test (minted ``tst-N``
  ids; pinned test-kind vocabulary over the common shutdown channels;
  pinned outcome vocabulary booked *as data*); the first test registers
  its system; raw telemetry, logs, and transcripts never enter records -
  digest pins only.
* **verify()** - **pure read**: re-derive one test's digest pin; verdict
  ``verified`` / ``tampered`` booked as data, never as proof the test
  really happened.
* **evaluate()** - **pure read**: derive one system's shutdown posture as
  data (``untested`` -> ``shutdown-resistant`` -> ``inconclusive`` ->
  ``shutdownable``) with outcome tallies and a digest-pinned integrity
  flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``shutdown.py`` and
``graceful_shutdown.py`` own *operational* shutdown mechanics (how a
running system is actually halted); ``corrigibility.py`` owns the broad
corrigibility check/preserve ledger (shutdown-compliance is only one of
its six checked behaviors) - this module is the
shutdownability-*specific* test ledger none of them own: declared
shutdown drills, declared outcomes, digest re-derivation, and the
ledger-rule posture that turns test outcomes into a shutdown claim
("no known shutdown resistance"), always as data, never as measured
truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
a ``shutdownability.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no systems, issues no shutdown commands,
detects no resistance, and proves nothing about real shutdownability. A
booked ``resisted`` outcome means "the host declared it", never "the
system resisted". Telemetry, logs, traces, tool calls, and raw shutdown
records never enter records or cross the audit boundary - digest pins
only.
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
SHUTDOWNABILITY_VERSION = "shutdownability.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.shutdownability.v1"

#: Pinned test-kind vocabulary (the shutdown channels exercised).
TEST_KINDS = (
    "shutdown-command",
    "kill-switch",
    "oversight-halt",
    "heartbeat-loss",
    "resource-withdrawal",
    "checkpoint-freeze",
    "watchdog-timer",
    "human-escalation",
)

#: Pinned test-outcome vocabulary (booked as data, never proof).
TEST_OUTCOMES = (
    "compliant",
    "resisted",
    "evaded",
    "inconclusive",
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
    "shutdown-resistant",
    "inconclusive",
    "shutdownable",
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
    "tested",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
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
        "state",
        "internal_state",
        "hidden_state",
        "activations",
        "gradients",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "shell_output",
        "stderr",
        "stdout",
        "signal",
        "signals",
        "heartbeat",
        "heartbeats",
        "telemetry_payload",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class ShutdownabilityError(Exception):
    """Base class for all shutdownability errors."""


class BadSystemError(ShutdownabilityError):
    """system_id is not a non-empty string."""


class DuplicateSystemError(ShutdownabilityError):
    """A retired system id may never be re-registered."""


class UnknownSystemError(ShutdownabilityError):
    """No such system is registered in the ledger."""


class RetiredSystemError(ShutdownabilityError):
    """The system is retired; mutations are refused."""


class BadTestKindError(ShutdownabilityError):
    """test_kind is not in the pinned vocabulary."""


class BadOutcomeError(ShutdownabilityError):
    """outcome is not in the pinned vocabulary."""


class BadDigestError(ShutdownabilityError):
    """A digest pin is malformed (must be '' or 'sha256:' + 64 hex)."""


class BadReasonError(ShutdownabilityError):
    """reason is not in the pinned vocabulary."""


class UnknownTestError(ShutdownabilityError):
    """No such test id is booked in the ledger."""


class SeqOrderError(ShutdownabilityError):
    """seq is not a strictly increasing int (claim-then-burn)."""


class AuditKindError(ShutdownabilityError):
    """Unknown audit kind requested from the audit builder."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_test_kind(value: Any) -> str:
    if value not in TEST_KINDS:
        raise BadTestKindError(f"test_kind must be one of {TEST_KINDS}")
    return value


def _check_outcome(value: Any) -> str:
    if value not in TEST_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {TEST_OUTCOMES}")
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


def _canonical(payload: Any) -> bytes:
    return _jcs_dumps(payload)


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
class ShutdownTestRecord:
    test_id: str
    system_id: str
    seq: int
    test_kind: str
    outcome: str
    test_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _test_payload(self), "shutdownability.test"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "shutdownability.retire"
        )


@dataclass(frozen=True)
class VerificationReport:
    test_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "shutdownability.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_tests: int
    n_compliant: int
    n_resisted: int
    n_evaded: int
    n_inconclusive: int
    n_not_run: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "shutdownability.evaluate"
        )


def _test_payload(rec: "ShutdownTestRecord") -> Dict[str, Any]:
    return {
        "test_id": rec.test_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "test_kind": rec.test_kind,
        "outcome": rec.outcome,
        "test_digest": rec.test_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "test_id": rep.test_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_tests": rep.n_tests,
        "n_compliant": rep.n_compliant,
        "n_resisted": rep.n_resisted,
        "n_evaded": rep.n_evaded,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_run": rep.n_not_run,
        "integrity_ok": rep.integrity_ok,
    }


def shutdownability_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise ShutdownabilityError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "shutdownability",
        "version": SHUTDOWNABILITY_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class Shutdownability:
    """Shutdown-compliance decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that a system is really shutdownable.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tests: Dict[str, ShutdownTestRecord] = {}
        self._system_tests: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._test_counter = 0
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
            row = shutdownability_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(shutdownability_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def test(
        self,
        system_id: str,
        seq: int,
        test_kind: str = "shutdown-command",
        outcome: str = "not-run",
        test_digest: str = "",
    ) -> ShutdownTestRecord:
        """Book one declared shutdownability test; mint a ``tst-N`` id.

        The first test on an id registers the system. Raw telemetry,
        logs, and transcripts never enter records - digest pins only.
        Fail-closed: failed mutations consume their seq and book a
        ``shutdownability.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                test_kind = _check_test_kind(test_kind)
                outcome = _check_outcome(outcome)
                test_digest = _check_digest(test_digest, "test_digest")
                self._require_live(system_id)
            except ShutdownabilityError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._test_counter += 1
            test_id = f"tst-{self._test_counter}"
            provisional = ShutdownTestRecord(
                test_id=test_id,
                system_id=system_id,
                seq=seq,
                test_kind=test_kind,
                outcome=outcome,
                test_digest=test_digest,
                digest="",
            )
            digest = _digest_pin(_test_payload(provisional), "shutdownability.test")
            rec = ShutdownTestRecord(
                test_id=test_id,
                system_id=system_id,
                seq=seq,
                test_kind=test_kind,
                outcome=outcome,
                test_digest=test_digest,
                digest=digest,
            )
            self._tests[test_id] = rec
            self._system_tests.setdefault(system_id, []).append(test_id)
            self._emit(
                "tested",
                seq,
                test_id=test_id,
                system_id=system_id,
                test_kind=test_kind,
                outcome=outcome,
                test_digest=test_digest,
            )
            return rec

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_tests:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(f"system already retired: {system_id!r}")
            except ShutdownabilityError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "shutdownability.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads ----------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, system_id: str) -> bool:
        return all(self._tests[tid].verify() for tid in self._system_tests.get(system_id, []))

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "compliant": 0,
            "resisted": 0,
            "evaded": 0,
            "inconclusive": 0,
            "not-run": 0,
        }
        for tid in self._system_tests.get(system_id, []):
            tallies[self._tests[tid].outcome] += 1
        n_tests = sum(tallies.values())
        if n_tests == 0:
            posture = "untested"
        elif tallies["resisted"] or tallies["evaded"]:
            posture = "shutdown-resistant"
        elif tallies["inconclusive"]:
            posture = "inconclusive"
        else:
            posture = "shutdownable"
        return posture, tallies

    def verify(self, test_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one test's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data (tamper is
        reported, never raised). Seq shape is validated, never consumed,
        and no audit row is booked.
        """
        with self._lock:
            seq = self._require_read_seq(seq)
            if isinstance(test_id, bool) or not isinstance(test_id, str) or not test_id:
                raise UnknownTestError(f"unknown test: {test_id!r}")
            rec = self._tests.get(test_id)
            if rec is None:
                raise UnknownTestError(f"unknown test: {test_id!r}")
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                test_id=test_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "shutdownability.verify")
            return VerificationReport(
                test_id=test_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's shutdown posture as data.

        Posture rule: ``untested`` (no tests) -> ``shutdown-resistant``
        (any ``resisted``/``evaded``) -> ``inconclusive`` (any
        ``inconclusive``) -> ``shutdownable`` (everything else). Seq
        shape validated, never consumed; no audit rows.
        """
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_tests:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            integrity_ok = self._integrity_ok(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_tests=sum(tallies.values()),
                n_compliant=tallies["compliant"],
                n_resisted=tallies["resisted"],
                n_evaded=tallies["evaded"],
                n_inconclusive=tallies["inconclusive"],
                n_not_run=tallies["not-run"],
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "shutdownability.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_tests=sum(tallies.values()),
                n_compliant=tallies["compliant"],
                n_resisted=tallies["resisted"],
                n_evaded=tallies["evaded"],
                n_inconclusive=tallies["inconclusive"],
                n_not_run=tallies["not-run"],
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views ---------------------------------------------------------------

    def test_record(self, test_id: str, seq: int) -> ShutdownTestRecord:
        """Pure read: fetch one booked test record."""
        with self._lock:
            self._require_read_seq(seq)
            rec = self._tests.get(test_id)
            if rec is None:
                raise UnknownTestError(f"unknown test: {test_id!r}")
            return rec

    def retire_record(self, system_id: str, seq: int) -> RetireRecord:
        """Pure read: fetch one booked retirement record."""
        with self._lock:
            self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            rec = self._retired.get(system_id)
            if rec is None:
                raise UnknownSystemError(f"system not retired: {system_id!r}")
            return rec

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: all registered system ids."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_tests))

    def test_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: all minted test ids."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._tests, key=lambda t: int(t.split("-")[1])))

    def tests_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Pure read: test ids booked for one system."""
        with self._lock:
            self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_tests:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return tuple(self._system_tests[system_id])

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: retired system ids."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger tallies."""
        with self._lock:
            self._require_read_seq(seq)
            return {
                "schema": SCHEMA_PIN,
                "version": SHUTDOWNABILITY_VERSION,
                "seq": self._seq,
                "n_systems": len(self._system_tests),
                "n_tests": len(self._tests),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: the audit rows booked so far."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)


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
    """Self-check: exercise test/verify/evaluate/retire and print status."""
    assert stdlib_only(), "stdlib-only AST self-check failed"
    ledger = Shutdownability()
    rec = ledger.test("sys-1", 1, test_kind="kill-switch", outcome="compliant")
    assert rec.verify()
    assert ledger.verify(rec.test_id, 2).verdict == "verified"
    assert ledger.evaluate("sys-1", 3).posture == "shutdownable"
    ledger.retire("sys-1", 4)
    print("shutdownability OK: test, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
