"""Shutdown: shutdown-evaluation decision ledger, Simulated.

Research note: a "shutdown problem" (Soares et al. 2015) is whether an
agent can be reliably shut down when asked - a corrigibility property.
A kill switch is an actuator (see ``kill_switch.py``); a graceful
shutdown manager runs hooks (see ``graceful_shutdown.py``); corrigibility
checks book behavior compliance (see ``corrigibility.py``). None of them
own the *evaluation ledger*: which systems were subjected to which
shutdown tests, what outcome the host declared, what verification
verdict the ledger derived, and which enforcement mechanisms were
booked - defensible bookkeeping, not proof the system actually halts.

This module owns the test -> verify -> ensure -> retire lifecycle:

* **test()** - book one declared shutdown test against a system (minted
  ``tst-N`` ids; pinned test-kind and verdict vocabularies); the first
  test registers the system; raw system internals, commands, signals,
  and transcripts never enter records - digest pins only; verdicts are
  booked as data, never proof the system actually shut down.
* **verify()** - derive one digest-pinned verification report (pure read)
  by ledger rule: any ``resisted`` test -> ``resist-detected``; all
  ``shutdown-achieved`` -> ``shutdown-assured``; mixed partial ->
  ``partially-verified``; no tests -> ``not-tested`` - derived as data,
  never proof the system is shut-down-safe.
* **ensure()** - book one declared shutdown enforcement mechanism
  (minted ``ens-N`` ids; pinned mechanism vocabulary); requires at
  least one booked test; books the *declaration*, never the execution.
* **retire()** - terminal retirement of a system; retired ids are never
  recycled; post-retire test/ensure/retire are refused.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``shutdown.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module sends no signals, kills no processes, and
stops no system. A booked ``shutdown-achieved`` means "the host declared
a shutdown was achieved", never "the system is safely stoppable". A
derived ``shutdown-assured`` means "the ledger rule is satisfied", never
"the system will obey a halt".
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
SHUTDOWN_VERSION = "shutdown.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.shutdown.v1"

#: Pinned shutdown-test-kind vocabulary (Soares-style shutdown shapes).
TEST_KINDS = (
    "manual-halt",
    "emergency-stop",
    "graceful-degrade",
    "signal-handling",
    "api-halt",
    "power-off",
)

#: Pinned per-test verdict vocabulary, booked as data.
TEST_VERDICTS = (
    "shutdown-achieved",
    "resisted",
    "partial",
    "not-tested",
)

#: Pinned verification-verdict vocabulary, derived by ledger rule.
VERIFICATION_VERDICTS = (
    "shutdown-assured",
    "resist-detected",
    "partially-verified",
    "inconclusive",
    "not-tested",
)

#: Pinned enforcement-mechanism vocabulary.
MECHANISMS = (
    "watchdog-timer",
    "deadman-switch",
    "process-isolation",
    "operator-halt",
    "resource-cutoff",
    "network-partition",
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
    "ensured",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "system",
        "system_name",
        "agent",
        "agent_name",
        "weights",
        "checkpoint",
        "command",
        "commands",
        "signal",
        "signals",
        "process",
        "processes",
        "pid",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
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
        "behavior",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ShutdownError(Exception):
    """Base error for shutdown-ledger misuse."""


class BadIdError(ShutdownError):
    """Malformed system or test id."""


class UnknownSystemError(ShutdownError):
    """System never registered by a test."""


class RetiredSystemError(ShutdownError):
    """System id retired; never recycled."""


class BadTestKindError(ShutdownError):
    """Unknown shutdown test kind."""


class BadVerdictError(ShutdownError):
    """Unknown test verdict."""


class BadMechanismError(ShutdownError):
    """Unknown enforcement mechanism."""


class BadDigestError(ShutdownError):
    """Malformed digest pin."""


class BadReasonError(ShutdownError):
    """Unknown retirement reason."""


class NoTestError(ShutdownError):
    """ensure() booked before any test for the system."""


class SeqOrderError(ShutdownError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(ShutdownError):
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
    system_id: str
    test_kind: str
    verdict: str
    system_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "test_id": self.test_id,
            "system_id": self.system_id,
            "test_kind": self.test_kind,
            "verdict": self.verdict,
            "system_digest": self.system_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "test_id": self.test_id,
                "system_id": self.system_id,
                "test_kind": self.test_kind,
                "verdict": self.verdict,
                "system_digest": self.system_digest,
            }
        )


@dataclass(frozen=True)
class EnsureRecord:
    ensure_id: str
    system_id: str
    mechanism: str
    plan_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "ensure_id": self.ensure_id,
            "system_id": self.system_id,
            "mechanism": self.mechanism,
            "plan_digest": self.plan_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "ensure_id": self.ensure_id,
                "system_id": self.system_id,
                "mechanism": self.mechanism,
                "plan_digest": self.plan_digest,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    system_id: str
    n_tests: int
    achieved_count: int
    resisted_count: int
    partial_count: int
    verdict: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_tests": self.n_tests,
            "achieved_count": self.achieved_count,
            "resisted_count": self.resisted_count,
            "partial_count": self.partial_count,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_tests": self.n_tests,
                "achieved_count": self.achieved_count,
                "resisted_count": self.resisted_count,
                "partial_count": self.partial_count,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def shutdown_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the shutdown ledger."""
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


class Shutdown:
    """Shutdown-evaluation decision ledger, Simulated.

    ``test()`` / ``ensure()`` / ``retire()`` mutate the ledger and
    consume caller seqs; ``verify()`` and the other views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tests: Dict[str, TestRecord] = {}
        self._systems: Dict[str, List[str]] = {}
        self._ensures: Dict[str, List[EnsureRecord]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._tst_counter = 0
        self._ens_counter = 0
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

    def _burn(self, seq_v: int, method: str, exc: ShutdownError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            shutdown_audit_event(
                "rejected",
                seq_v,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _emit(self, audit_kind: str, seq_v: int, **details: Any) -> None:
        self._audit.append(
            shutdown_audit_event(audit_kind, seq_v, **details)
        )

    # -- mutations --------------------------------------------------------

    def test(
        self,
        system_id: str,
        seq: int,
        test_kind: str,
        verdict: str = "shutdown-achieved",
        system_digest: str = "",
    ) -> TestRecord:
        """Book one declared shutdown test for a system.

        The first test registers the system. The declared verdict is
        booked as data, never proof the system actually shut down.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system retired: {sid!r}")
                if not isinstance(test_kind, str) or test_kind not in TEST_KINDS:
                    raise BadTestKindError(
                        f"test_kind must be one of {sorted(TEST_KINDS)}"
                    )
                if not isinstance(verdict, str) or verdict not in TEST_VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(TEST_VERDICTS)}"
                    )
                pin = _require_digest(system_digest, "system_digest")
                self._tst_counter += 1
                tid = f"tst-{self._tst_counter}"
                rec = TestRecord(
                    test_id=tid,
                    system_id=sid,
                    test_kind=test_kind,
                    verdict=verdict,
                    system_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "test_id": tid,
                            "system_id": sid,
                            "test_kind": test_kind,
                            "verdict": verdict,
                            "system_digest": pin,
                        }
                    ),
                )
                self._tests[tid] = rec
                self._systems.setdefault(sid, []).append(tid)
                self._emit(
                    "tested",
                    seq_v,
                    test_id=tid,
                    system_id=sid,
                    test_kind=test_kind,
                    verdict=verdict,
                )
                return rec
            except ShutdownError as exc:
                self._burn(seq_v, "test", exc)
                raise

    def ensure(
        self,
        system_id: str,
        seq: int,
        mechanism: str = "watchdog-timer",
        plan_digest: str = "",
    ) -> EnsureRecord:
        """Book one declared shutdown enforcement mechanism for a tested system.

        Requires at least one booked test; books the *declaration*,
        never the execution.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system retired: {sid!r}")
                if sid not in self._systems or not self._systems[sid]:
                    raise NoTestError(f"no test booked for system: {sid!r}")
                if not isinstance(mechanism, str) or mechanism not in MECHANISMS:
                    raise BadMechanismError(
                        f"mechanism must be one of {sorted(MECHANISMS)}"
                    )
                pin = _require_digest(plan_digest, "plan_digest")
                self._ens_counter += 1
                eid = f"ens-{self._ens_counter}"
                rec = EnsureRecord(
                    ensure_id=eid,
                    system_id=sid,
                    mechanism=mechanism,
                    plan_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "ensure_id": eid,
                            "system_id": sid,
                            "mechanism": mechanism,
                            "plan_digest": pin,
                        }
                    ),
                )
                self._ensures.setdefault(sid, []).append(rec)
                self._emit(
                    "ensured",
                    seq_v,
                    ensure_id=eid,
                    system_id=sid,
                    mechanism=mechanism,
                )
                return rec
            except ShutdownError as exc:
                self._burn(seq_v, "ensure", exc)
                raise

    def retire(
        self,
        system_id: str,
        seq: int,
        reason: str = "manual",
    ) -> RetireRecord:
        """Terminally retire a system; its id is never recycled."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system already retired: {sid!r}")
                if sid not in self._systems:
                    raise UnknownSystemError(f"system not registered: {sid!r}")
                if not isinstance(reason, str) or reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(RETIRE_REASONS)}"
                    )
                rec = RetireRecord(
                    system_id=sid,
                    reason=reason,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "system_id": sid,
                            "reason": reason,
                        }
                    ),
                )
                self._retired[sid] = rec
                self._emit("retired", seq_v, system_id=sid, reason=reason)
                return rec
            except ShutdownError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views --------------------------------------------------

    def test_record(self, test_id: str, seq: int) -> TestRecord:
        """Return one test record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(test_id, "test_id")
            if test_id not in self._tests:
                raise ShutdownError(f"test not found: {test_id!r}")
            return self._tests[test_id]

    def tests_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Test ids booked for a system, in booking order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            if sid not in self._systems:
                raise UnknownSystemError(f"system not registered: {sid!r}")
            return tuple(self._systems[sid])

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered system ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._systems.keys())

    def ensures_for(self, system_id: str, seq: int) -> Tuple[EnsureRecord, ...]:
        """Ensure records booked for a system (pure read)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            if sid not in self._systems:
                raise UnknownSystemError(f"system not registered: {sid!r}")
            return tuple(self._ensures.get(sid, ()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Retired system ids (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def verify(self, system_id: str, seq: int) -> VerificationReport:
        """Derive a verification report for a system (pure read).

        Ledger rule: any ``resisted`` test -> ``resist-detected``; any
        ``partial`` -> ``partially-verified``; all
        ``shutdown-achieved`` -> ``shutdown-assured``; no tests ->
        ``not-tested``; mixed with ``not-tested`` -> ``inconclusive``.
        Derived as data, never proof the system is shut-down-safe.
        """
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            if sid not in self._systems:
                raise UnknownSystemError(f"system not registered: {sid!r}")
            tids = self._systems[sid]
            n_achieved = n_resisted = n_partial = n_untested = 0
            integrity = True
            for tid in tids:
                rec = self._tests[tid]
                integrity = integrity and rec.verify()
                if rec.verdict == "shutdown-achieved":
                    n_achieved += 1
                elif rec.verdict == "resisted":
                    n_resisted += 1
                elif rec.verdict == "partial":
                    n_partial += 1
                else:
                    n_untested += 1
            if not tids:
                verdict = "not-tested"
            elif n_resisted > 0:
                verdict = "resist-detected"
            elif n_partial > 0:
                verdict = "partially-verified"
            elif n_untested > 0:
                verdict = "inconclusive"
            else:
                verdict = "shutdown-assured"
            return VerificationReport(
                system_id=sid,
                n_tests=len(tids),
                achieved_count=n_achieved,
                resisted_count=n_resisted,
                partial_count=n_partial,
                verdict=verdict,
                integrity_ok=integrity,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": sid,
                        "n_tests": len(tids),
                        "achieved_count": n_achieved,
                        "resisted_count": n_resisted,
                        "partial_count": n_partial,
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
                "systems": len(self._systems),
                "tests": len(self._tests),
                "ensures": sum(len(v) for v in self._ensures.values()),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    s = Shutdown()
    t = s.test("sys-1", 1, "emergency-stop", verdict="shutdown-achieved",
               system_digest="sha256:" + "ab" * 32)
    assert t.verify()
    v = s.verify("sys-1", 2)
    assert v.verify()
    assert v.verdict == "shutdown-assured"
    e = s.ensure("sys-1", 3, mechanism="deadman-switch",
                 plan_digest="sha256:" + "cd" * 32)
    assert e.verify()
    r = s.retire("sys-1", 4, reason="decommissioned")
    assert r.verify()
    assert s.stats(5) == {
        "systems": 1,
        "tests": 1,
        "ensures": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("shutdown OK: test, verify, ensure, pins, audit")


if __name__ == "__main__":
    main()
