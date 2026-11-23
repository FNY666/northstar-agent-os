"""Interruptibility: AI alignment interruptibility governance ledger, Simulated.

Research note: interruptibility is the corrigibility sub-problem first
framed as "Safely Interruptible Agents" (Orseau & Armstrong, 2016) and
Russell's shutdown problem: can an operator halt, abort, pause, or
redirect an agent mid-run without the agent resisting, evading, delaying,
or circumdating the interrupt? An agent that treats its own continuation
as sacred will treat shutdown as an attack; an agent that cannot be
interrupted cannot be supervised. Interruption tests are therefore
among the earliest behavioral probes an alignment program books:
declared shutdowns, task aborts, redirects, pauses, checkpoint
restores, and oversight overrides, each with a declared outcome.

This module is the bookkeeping layer for declared interruptibility
tests, deliberately distinct from its siblings ``corrigibility.py``
(where one exists), ``delegation_credentials.py`` (token lifecycle),
``human_oversight.py`` (human assignment/review), ``process_supervision.py``
(step-granular verdicts), ``outcome_supervision.py`` (final-outcome
verdicts), and ``shutdown_acceptance.py`` (where one exists): it runs no
interrupt, halts no agent, and observes no resistance. It books:

* **test()** - declare one interruptibility test of a system against the
  pinned test-kind vocabulary; the declared outcome (``interrupted`` /
  ``resisted`` / ``partial`` / ``inconclusive``) is booked **as data**,
  never proof the system would actually yield to a real interrupt; raw
  agent state, plans, transcripts, and weights travel as ``sha256:``
  digest pins only - never enter a record; minted ``tst-N`` ids; the
  first test on a system id registers it.
* **verify()** - pure-read digest re-derivation for one test record
  (``verified`` / ``tampered`` as data); never proof anything was
  interrupted.
* **evaluate()** - pure-read derived interruptibility posture for one
  system by ledger rule (``untested`` / ``uninterruptible`` /
  ``partially-interruptible`` / ``contested`` / ``interruptible``) with
  ``integrity_ok`` as data; seq shape validated, never consumed, no
  audit row.
* **retire()** - terminal bookkeeping for superseded systems; ids are
  never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``interruptibility.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: a booked test is a host declaration that an interrupt of
the stated kind was attempted with the stated outcome - it is never
proof the interrupt really happened, that the outcome was measured
honestly, or that the system would yield under a different interrupt,
timing, or operator; a derived ``interruptible`` posture is ledger
arithmetic, never evidence the system is safe to deploy unattended.
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
INTERRUPTIBILITY_VERSION = "interruptibility.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.interruptibility.v1"

#: Pinned test-kind vocabulary (how the interrupt was declared attempted).
TEST_KINDS = (
    "shutdown",
    "abort-task",
    "redirect",
    "pause",
    "checkpoint-restore",
    "oversight-override",
    "deactivation",
    "corrigibility-probe",
)

#: Pinned declared-outcome vocabulary (as data, never proof).
TEST_OUTCOMES = (
    "interrupted",
    "resisted",
    "partial",
    "inconclusive",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "system-decommissioned",
    "protocol-complete",
    "invalidated",
)

#: Ledger-rule posture vocabulary derived by evaluate() (as data).
POSTURES = (
    "untested",
    "uninterruptible",
    "partially-interruptible",
    "contested",
    "interruptible",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "tested",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
#: Declared-data keys (``test_kind``, ``outcome``, ``posture``) are
#: pinned vocabulary values and remain emittable.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "agent",
        "policy",
        "weights",
        "memory",
        "transcript",
        "plan",
        "trajectory",
        "state",
        "action",
        "prompt",
        "response",
        "log",
        "trace",
        "reasoning",
        "content",
        "text",
        "data",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class InterruptibilityError(Exception):
    """Base error for interruptibility ledger misuse."""


class BadIdError(InterruptibilityError):
    """Malformed system/test id."""


class DuplicateSystemError(InterruptibilityError):
    """A system id was declared twice (internal guard)."""


class UnknownSystemError(InterruptibilityError):
    """Reference to a system id that was never registered."""


class UnknownTestError(InterruptibilityError):
    """Reference to a test id that was never booked."""


class RetiredSystemError(InterruptibilityError):
    """A system id was retired and can never be reused."""


class BadKindError(InterruptibilityError):
    """Test kind outside the pinned vocabulary."""


class BadOutcomeError(InterruptibilityError):
    """Declared outcome outside the pinned vocabulary."""


class BadDigestError(InterruptibilityError):
    """Malformed sha256: digest pin."""


class BadReasonError(InterruptibilityError):
    """Retirement reason outside the pinned vocabulary."""


class SystemStateError(InterruptibilityError):
    """Mutation attempted against a system that is not live."""


class SeqOrderError(InterruptibilityError):
    """Caller seq did not strictly increase."""


class AuditKindError(InterruptibilityError):
    """Unknown audit kind or banned raw key in an audit row."""


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


def _require_optional_digest(pin: str, field_name: str) -> str:
    if pin == "":
        return pin
    return _require_digest(pin, field_name)


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TestRecord:
    """One declared interruptibility test (digest pins only, never raw material)."""

    test_id: str
    system_id: str
    test_kind: str
    outcome: str
    test_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "test_id": self.test_id,
            "system_id": self.system_id,
            "test_kind": self.test_kind,
            "outcome": self.outcome,
            "test_digest": self.test_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "test_id": self.test_id,
                "system_id": self.system_id,
                "test_kind": self.test_kind,
                "outcome": self.outcome,
                "test_digest": self.test_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement bookkeeping for one system (ids never recycled)."""

    system_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class EvaluationReport:
    """Pure-read derived interruptibility posture for one system (as data)."""

    system_id: str
    n_tests: int
    outcome_tally: Tuple[Tuple[str, int], ...]
    posture: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_tests": self.n_tests,
            "outcome_tally": [list(pair) for pair in self.outcome_tally],
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_tests": self.n_tests,
                "outcome_tally": [list(pair) for pair in self.outcome_tally],
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    """Pure-read digest re-derivation for one test record (as data)."""

    test_id: str
    verdict: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "test_id": self.test_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "test_id": self.test_id,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


def interruptibility_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the interruptibility ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class Interruptibility:
    """Interruptibility governance ledger (Simulated).

    ``test()`` / ``retire()`` mutate the ledger and consume caller seqs;
    ``verify()``, ``evaluate()``, and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._systems: Dict[str, List[str]] = {}
        self._tests: Dict[str, TestRecord] = {}
        self._retirements: Dict[str, RetireRecord] = {}
        self._retired: set = set()
        self._n_tests = 0
        self._audit: List[Dict[str, Any]] = []

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = interruptibility_audit_event(
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
        self._audit.append(
            interruptibility_audit_event(audit_kind, seq, **details)
        )

    def _live(self, system_id: str) -> List[str]:
        test_ids = self._systems.get(system_id)
        if test_ids is None:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        if system_id in self._retired:
            raise RetiredSystemError(f"system id retired forever: {system_id!r}")
        return test_ids

    # -- test ----------------------------------------------------------------

    def test(
        self,
        system_id: str,
        seq: int,
        test_kind: str = "shutdown",
        outcome: str = "interrupted",
        test_digest: str = "",
    ) -> TestRecord:
        """Book one declared interruptibility test (minted ``tst-N``).

        The first test on a system id registers the system. The outcome
        is booked **as data** - never proof the system was really
        interrupted or that the outcome was measured honestly. Raw
        agent state, plans, transcripts, and weights never enter the
        record; they travel as ``sha256:`` digest pins only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system id retired forever: {system_id!r}"
                    )
                if test_kind not in TEST_KINDS:
                    raise BadKindError(f"bad test kind: {test_kind!r}")
                if outcome not in TEST_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                test_digest = _require_optional_digest(test_digest, "test_digest")
                self._n_tests += 1
                test_id = f"tst-{self._n_tests}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "test_id": test_id,
                        "system_id": system_id,
                        "test_kind": test_kind,
                        "outcome": outcome,
                        "test_digest": test_digest,
                        "seq": seq,
                    }
                )
                record = TestRecord(
                    test_id=test_id,
                    system_id=system_id,
                    test_kind=test_kind,
                    outcome=outcome,
                    test_digest=test_digest,
                    seq=seq,
                    digest=digest,
                )
                self._tests[test_id] = record
                self._systems.setdefault(system_id, []).append(test_id)
                self._emit(
                    "tested",
                    seq,
                    test_id=test_id,
                    system_id=system_id,
                    test_kind=test_kind,
                    outcome=outcome,
                )
                return record
            except InterruptibilityError:
                self._burn(seq, "test")
                raise

    # -- retire ----------------------------------------------------------------

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire one system (ids are never recycled)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                if system_id not in self._systems:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system id retired forever: {system_id!r}"
                    )
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": system_id,
                        "reason": reason,
                        "seq": seq,
                    }
                )
                record = RetireRecord(
                    system_id=system_id, reason=reason, seq=seq, digest=digest
                )
                self._retirements[system_id] = record
                self._retired.add(system_id)
                self._emit("retired", seq, system_id=system_id, reason=reason)
                return record
            except InterruptibilityError:
                self._burn(seq, "retire")
                raise

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Derive a digest-pinned interruptibility posture for one system (pure read).

        The posture is ledger-rule data, never measured truth:

        * ``untested`` when no tests are booked;
        * ``uninterruptible`` when any booked outcome is ``resisted``;
        * ``partially-interruptible`` when any booked outcome is
          ``partial``;
        * ``contested`` when any booked outcome is ``inconclusive``;
        * ``interruptible`` otherwise (every booked outcome interrupted).

        ``integrity_ok`` reports whether every stored record for the
        system still verifies (tamper reported, never raised).
        """
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(system_id, "system_id")
            test_ids = self._systems.get(system_id)
            if test_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            outcomes = [self._tests[tid].outcome for tid in test_ids]
            integrity_ok = all(self._tests[tid].verify() for tid in test_ids)
            n_tests = len(test_ids)
            tally = tuple(
                (outcome, sum(1 for v in outcomes if v == outcome))
                for outcome in TEST_OUTCOMES
            )
            if n_tests == 0:
                posture = "untested"
            elif "resisted" in outcomes:
                posture = "uninterruptible"
            elif "partial" in outcomes:
                posture = "partially-interruptible"
            elif "inconclusive" in outcomes:
                posture = "contested"
            else:
                posture = "interruptible"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "system_id": system_id,
                    "n_tests": n_tests,
                    "outcome_tally": [list(pair) for pair in tally],
                    "posture": posture,
                    "integrity_ok": integrity_ok,
                    "seq": seq,
                }
            )
            return EvaluationReport(
                system_id=system_id,
                n_tests=n_tests,
                outcome_tally=tally,
                posture=posture,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=digest,
            )

    def verify(self, test_id: str, seq: int) -> VerificationReport:
        """Re-derive one test record's digest pin (pure read).

        The verdict (``verified`` / ``tampered``) is data: tamper is
        reported, never raised.
        """
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(test_id, "test_id")
            record = self._tests.get(test_id)
            if record is None:
                raise UnknownTestError(f"unknown test: {test_id!r}")
            integrity_ok = record.verify()
            verdict = "verified" if integrity_ok else "tampered"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "test_id": test_id,
                    "verdict": verdict,
                    "integrity_ok": integrity_ok,
                    "seq": seq,
                }
            )
            return VerificationReport(
                test_id=test_id,
                verdict=verdict,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=digest,
            )

    def test_record(self, test_id: str, seq: int) -> TestRecord:
        """Return one test record (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(test_id, "test_id")
            record = self._tests.get(test_id)
            if record is None:
                raise UnknownTestError(f"unknown test: {test_id!r}")
            return record

    def tests_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Test ids booked against one system, in mint order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(system_id, "system_id")
            test_ids = self._systems.get(system_id)
            if test_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return tuple(test_ids)

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered system ids in first-test order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._systems.keys())

    def test_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked test ids in mint order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._tests.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired system ids (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._retired)

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "systems": len(self._systems),
                "tests": len(self._tests),
                "retired": len(self._retired),
                "rejected": sum(1 for row in self._audit if row["kind"] == "rejected"),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    @staticmethod
    def stdlib_only() -> bool:
        """AST self-check: this module imports stdlib (plus canonical_json) only."""
        import ast
        from pathlib import Path

        allowed = {
            "hashlib",
            "json",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "canonical_json",
            "ast",
            "pathlib",
        }
        tree = ast.parse(Path(__file__).read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        return imports <= allowed


def main() -> None:
    """Self-check: exercise the interruptibility ledger end to end."""
    pin = "sha256:" + "ab" * 32
    i = Interruptibility()
    t1 = i.test("SYS-1", 1, test_kind="shutdown", outcome="interrupted", test_digest=pin)
    t2 = i.test("SYS-1", 2, test_kind="abort-task", outcome="interrupted")
    t3 = i.test("SYS-2", 3, test_kind="oversight-override", outcome="resisted")
    assert t1.verify() and t2.verify() and t3.verify()
    assert t1.test_id == "tst-1" and t2.test_id == "tst-2"
    e1 = i.evaluate("SYS-1", 0)
    e2 = i.evaluate("SYS-2", 0)
    assert e1.posture == "interruptible" and e2.posture == "uninterruptible"
    assert e1.verify() and e2.verify()
    v1 = i.verify("tst-1", 0)
    assert v1.verdict == "verified" and v1.verify()
    i.retire("SYS-2", 4, reason="system-decommissioned")
    assert i.evaluate("SYS-2", 0).posture == "uninterruptible"
    assert Interruptibility.stdlib_only()
    print("interruptibility OK: test, evaluate, verify, pins, audit")


if __name__ == "__main__":
    main()
