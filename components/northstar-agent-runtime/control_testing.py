"""Control testing ledger: design, operate, test, remediate controls.

Controls (SOX / SOC 2 / CCM-shaped) go through a fixed decision lifecycle
in this module:

* **Design** - ``design()`` declares one control with a pinned kind
  vocabulary (``preventive`` / ``detective`` / ``corrective`` /
  ``compensating``). The objective travels as a digest pin only.
* **Test** - ``test()`` books one operating-effectiveness test of a
  declared control: pinned method vocabulary (``inquiry`` /
  ``observation`` / ``inspection`` / ``reperformance`` /
  ``sampling``) and a booked result (``pass`` / ``fail`` /
  ``inconclusive``) **as data**, never proof the control works.
* **Remediate** - ``remediate()`` books one declared remediation
  against a failed test, over the pinned action vocabulary
  (``fix-control`` / ``redesign`` / ``retrain`` / ``add-control`` /
  ``accept-risk``). Books the *declaration*, never the actual fix.

Design (deterministic single-host ledger):
1. Frozen dataclasses, caller int seqs strictly increasing
   (claim-then-burn: failed mutations consume their seq + book
   ``control-testing.rejected``; rewinds raise bare), no wall-clock,
   RLock-guarded, fail-closed taxonomy.
2. stdlib-only + the single ``canonical_json`` try/except fallback;
   ``sha256:`` digest pins with ``verify()``; ``audit.ndjson/1``
   events; version pin ``control-testing.v1``; schema pin
   ``northstar.control-testing.v1``.

Honest scope:
- This module books *declared* control-testing decisions - it runs no
  real control test, samples no evidence, and remediates nothing.
- A booked ``pass`` means "the host declared this test passed", never
  "the control is effective". A booked ``fail`` means the host reported
  a failure, never proof of a deficiency.
- A booked remediation is a declared intent, never proof a control was
  fixed or redesigned.
- Digest pins prove ledger integrity and ordering, never the truth of
  the declared decisions.
- No persistence: the ledger is in-memory.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


VERSION = "control-testing.v1"
SCHEMA = "northstar.control-testing.v1"

KIND_DESIGNED = "control-designed"
KIND_TESTED = "tested"
KIND_REMEDIATED = "remediated"
KIND_REJECTED = "rejected"
_KINDS = frozenset({
    KIND_DESIGNED, KIND_TESTED, KIND_REMEDIATED, KIND_REJECTED,
})

_CONTROL_KINDS = ("preventive", "detective", "corrective", "compensating")

_TEST_METHODS = ("inquiry", "observation", "inspection",
                 "reperformance", "sampling")

_TEST_RESULTS = ("pass", "fail", "inconclusive")

_REMEDIATION_ACTIONS = ("fix-control", "redesign", "retrain",
                        "add-control", "accept-risk")

_MAX_ID_LEN = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Raw content must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset({
    "content", "text", "payload", "raw", "objective", "objective_text",
    "description", "message", "notes", "note", "rationale", "evidence",
    "evidence_text", "finding", "finding_text", "sample", "data",
})


class ControlTestingError(Exception):
    """Base class for all control-testing ledger errors."""


class BadIdError(ControlTestingError):
    """Malformed control id or test id."""


class DuplicateControlError(ControlTestingError):
    """Control id already designed (ids are never recycled)."""


class RetiredControlError(ControlTestingError):
    """Control id was retired and cannot be reused."""


class UnknownControlError(ControlTestingError):
    """Control id has no booked design record."""


class BadKindError(ControlTestingError):
    """Control kind not in the pinned vocabulary."""


class BadMethodError(ControlTestingError):
    """Test method not in the pinned vocabulary."""


class BadResultError(ControlTestingError):
    """Test result not in the pinned vocabulary."""


class BadActionError(ControlTestingError):
    """Remediation action not in the pinned vocabulary."""


class BadDigestError(ControlTestingError):
    """Digest is not a sha256:<64hex> pin (or empty)."""


class DuplicateTestError(ControlTestingError):
    """Test id already booked for this control."""


class SeqOrderError(ControlTestingError):
    """Malformed seq or seq not strictly increasing."""


class AuditKindError(ControlTestingError):
    """Unknown audit kind, or banned key at the audit boundary."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str) -> str:
    """Validate a sha256:<64hex> digest pin (or empty string)."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{label} must be str, got {type(value).__name__}")
    if value and not _DIGEST_RE.match(value):
        raise BadDigestError(f"{label} must be sha256:<64hex> or empty")
    return value


def _digest_pin(payload: Any) -> str:
    """sha256: digest pin over canonical JSON of payload."""
    return "sha256:" + jcs_sha256_hex(payload)


def control_testing_audit_event(kind: str, detail: Dict[str, object],
                                seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the control ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "audit_version": "audit.ndjson/1",
        "schema": SCHEMA,
        "version": VERSION,
        "kind": "control-testing." + kind,
        "detail": dict(detail),
        "seq": seq,
    }


def _record_digest(tag: str, fields: Dict[str, object]) -> str:
    return _digest_pin({"control-testing": tag, **fields})


@dataclass(frozen=True)
class DesignRecord:
    """One declared control design."""

    control_id: str
    kind: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "control_id": self.control_id,
            "kind": self.kind,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest(
            "design", {"control_id": self.control_id, "kind": self.kind})


@dataclass(frozen=True)
class TestRecord:
    """One booked operating-effectiveness test of a declared control.

    ``result`` and ``method`` are host-declared bookkeeping data;
    ``evidence_pin`` pins the evidence by digest only - the evidence
    itself never enters a record.
    """

    test_id: str
    control_id: str
    method: str
    result: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "test_id": self.test_id,
            "control_id": self.control_id,
            "method": self.method,
            "result": self.result,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest(
            "test", {"test_id": self.test_id,
                     "control_id": self.control_id,
                     "method": self.method, "result": self.result})


@dataclass(frozen=True)
class RemediationRecord:
    """One booked remediation declaration against a failed test."""

    remediation_id: str
    test_id: str
    control_id: str
    action: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "remediation_id": self.remediation_id,
            "test_id": self.test_id,
            "control_id": self.control_id,
            "action": self.action,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest(
            "remediation", {"remediation_id": self.remediation_id,
                            "test_id": self.test_id,
                            "control_id": self.control_id,
                            "action": self.action})


@dataclass(frozen=True)
class ControlReport:
    """Aggregate view over booked designs, tests, and remediations."""

    n_controls: int
    n_tests: int
    n_remediations: int
    passes: int
    fails: int
    inconclusive: int
    controls_with_failures: Tuple[str, ...]
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "n_controls": self.n_controls,
            "n_tests": self.n_tests,
            "n_remediations": self.n_remediations,
            "passes": self.passes,
            "fails": self.fails,
            "inconclusive": self.inconclusive,
            "controls_with_failures": list(self.controls_with_failures),
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest(
            "report", {
                "n_controls": self.n_controls,
                "n_tests": self.n_tests,
                "n_remediations": self.n_remediations,
                "passes": self.passes,
                "fails": self.fails,
                "inconclusive": self.inconclusive,
                "controls_with_failures": list(
                    self.controls_with_failures),
            })


class ControlTesting:
    """Deterministic single-host control-testing ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq: int = 0
        self._designs: Dict[str, DesignRecord] = {}
        self._retired: set = set()
        self._tests: Dict[str, TestRecord] = {}
        self._tests_for: Dict[str, List[str]] = {}
        self._remediations: Dict[str, RemediationRecord] = {}
        self._remediated_tests: set = set()
        self._audit: List[Dict[str, object]] = []
        self._rem_counter: int = 0

    # -- seq discipline -------------------------------------------------
    def _claim_seq(self, seq: int) -> None:
        """Claim-then-burn: seq must be strictly increasing."""
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be > {self._seq}, got {seq}")

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Book one audit row and advance the ledger seq."""
        self._audit.append(
            control_testing_audit_event(audit_kind, detail, seq))
        self._seq = seq

    def _burn(self, seq: int, what: str,
              exc: ControlTestingError) -> None:
        """Book a rejected row, burn the seq; caller re-raises ``exc``."""
        self._emit(KIND_REJECTED, {"what": what,
                                   "why": type(exc).__name__}, seq)

    # -- mutations ------------------------------------------------------
    def design(self, control_id: object, kind: object, seq: object,
               objective_digest: object = "") -> DesignRecord:
        """Declare one control design; control ids are never recycled."""
        seq_v = _check_seq(seq)
        with self._lock:
            self._claim_seq(seq_v)
            try:
                cid = _check_id(control_id, "control_id")
                if not isinstance(kind, str) or kind not in _CONTROL_KINDS:
                    raise BadKindError(
                        f"kind must be one of {_CONTROL_KINDS}, "
                        f"got {kind!r}")
                odigest = _check_digest(objective_digest, "objective_digest")
                if cid in self._retired:
                    raise RetiredControlError(
                        f"control id retired: {cid!r}")
                if cid in self._designs:
                    raise DuplicateControlError(
                        f"control already designed: {cid!r}")
                record = DesignRecord(
                    control_id=cid,
                    kind=kind,
                    digest=_record_digest(
                        "design", {"control_id": cid, "kind": kind}),
                )
                self._designs[cid] = record
                self._tests_for[cid] = []
                self._emit(KIND_DESIGNED, {
                    "control_id": cid,
                    "kind": kind,
                    "objective_digest": odigest or None,
                }, seq_v)
                return record
            except ControlTestingError as exc:
                self._burn(seq_v, "design", exc)
                raise

    def test(self, control_id: object, test_id: object, method: object,
             seq: object, result: object = "pass",
             evidence_digest: object = "") -> TestRecord:
        """Book one operating-effectiveness test for a declared control."""
        seq_v = _check_seq(seq)
        with self._lock:
            self._claim_seq(seq_v)
            try:
                cid = _check_id(control_id, "control_id")
                tid = _check_id(test_id, "test_id")
                if cid in self._retired:
                    raise RetiredControlError(
                        f"control id retired: {cid!r}")
                if cid not in self._designs:
                    raise UnknownControlError(
                        f"control not designed: {cid!r}")
                if not isinstance(method, str) or method not in _TEST_METHODS:
                    raise BadMethodError(
                        f"method must be one of {_TEST_METHODS}, "
                        f"got {method!r}")
                if not isinstance(result, str) or result not in _TEST_RESULTS:
                    raise BadResultError(
                        f"result must be one of {_TEST_RESULTS}, "
                        f"got {result!r}")
                edigest = _check_digest(evidence_digest, "evidence_digest")
                if tid in self._tests:
                    raise DuplicateTestError(
                        f"test already booked: {tid!r}")
                record = TestRecord(
                    test_id=tid,
                    control_id=cid,
                    method=method,
                    result=result,
                    digest=_record_digest(
                        "test", {"test_id": tid, "control_id": cid,
                                 "method": method, "result": result}),
                )
                self._tests[tid] = record
                self._tests_for[cid].append(tid)
                self._emit(KIND_TESTED, {
                    "test_id": tid,
                    "control_id": cid,
                    "method": method,
                    "result": result,
                    "evidence_digest": edigest or None,
                }, seq_v)
                return record
            except ControlTestingError as exc:
                self._burn(seq_v, "test", exc)
                raise

    def remediate(self, control_id: object, test_id: object,
                  action: object, seq: object,
                  remediation_digest: object = "") -> RemediationRecord:
        """Book one declared remediation against a failed test."""
        seq_v = _check_seq(seq)
        with self._lock:
            self._claim_seq(seq_v)
            try:
                cid = _check_id(control_id, "control_id")
                tid = _check_id(test_id, "test_id")
                if cid in self._retired:
                    raise RetiredControlError(
                        f"control id retired: {cid!r}")
                if cid not in self._designs:
                    raise UnknownControlError(
                        f"control not designed: {cid!r}")
                test = self._tests.get(tid)
                if test is None or test.control_id != cid:
                    raise UnknownControlError(
                        f"test not booked for control: {tid!r}")
                if test.result != "fail":
                    raise BadResultError(
                        "remediation requires a booked fail result, "
                        f"got {test.result!r}")
                if (not isinstance(action, str)
                        or action not in _REMEDIATION_ACTIONS):
                    raise BadActionError(
                        f"action must be one of {_REMEDIATION_ACTIONS}, "
                        f"got {action!r}")
                rdigest = _check_digest(remediation_digest,
                                        "remediation_digest")
                self._rem_counter += 1
                rid = f"rem-{self._rem_counter}"
                record = RemediationRecord(
                    remediation_id=rid,
                    test_id=tid,
                    control_id=cid,
                    action=action,
                    digest=_record_digest(
                        "remediation", {"remediation_id": rid,
                                        "test_id": tid, "control_id": cid,
                                        "action": action}),
                )
                self._remediations[rid] = record
                self._remediated_tests.add(tid)
                self._emit(KIND_REMEDIATED, {
                    "remediation_id": rid,
                    "test_id": tid,
                    "control_id": cid,
                    "action": action,
                    "remediation_digest": rdigest or None,
                }, seq_v)
                return record
            except ControlTestingError as exc:
                self._burn(seq_v, "remediate", exc)
                raise

    def retire(self, control_id: object, seq: object) -> None:
        """Retire a control id forever; ids are never recycled."""
        seq_v = _check_seq(seq)
        with self._lock:
            self._claim_seq(seq_v)
            try:
                cid = _check_id(control_id, "control_id")
                if cid in self._retired:
                    raise RetiredControlError(
                        f"control id retired: {cid!r}")
                if cid not in self._designs:
                    raise UnknownControlError(
                        f"control not designed: {cid!r}")
                self._retired.add(cid)
                self._emit(KIND_REJECTED, {"retired": cid}, seq_v)
            except ControlTestingError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views -------------------------------------------------
    def design_record(self, control_id: object,
                      seq: object) -> DesignRecord:
        """Read one booked design record; consumes no seq, writes no rows."""
        seq_v = _check_seq(seq)
        with self._lock:
            cid = _check_id(control_id, "control_id")
            record = self._designs.get(cid)
            if record is None:
                raise UnknownControlError(
                    f"control not designed: {cid!r}")
            return record

    def test_record(self, test_id: object, seq: object) -> TestRecord:
        """Read one booked test record; consumes no seq, writes no rows."""
        _check_seq(seq)
        with self._lock:
            tid = _check_id(test_id, "test_id")
            record = self._tests.get(tid)
            if record is None:
                raise UnknownControlError(
                    f"test not booked: {tid!r}")
            return record

    def remediation_record(self, remediation_id: object,
                           seq: object) -> RemediationRecord:
        """Read one booked remediation; consumes no seq, writes no rows."""
        _check_seq(seq)
        with self._lock:
            rid = _check_id(remediation_id, "remediation_id")
            record = self._remediations.get(rid)
            if record is None:
                raise UnknownControlError(
                    f"remediation not booked: {rid!r}")
            return record

    def control_ids(self, seq: object) -> Tuple[str, ...]:
        """Sorted control ids, live only; pure read."""
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(
                cid for cid in self._designs if cid not in self._retired))

    def tests_for(self, control_id: object,
                  seq: object) -> Tuple[str, ...]:
        """Test ids booked for one control, in booking order; pure read."""
        _check_seq(seq)
        with self._lock:
            cid = _check_id(control_id, "control_id")
            if cid not in self._designs:
                raise UnknownControlError(
                    f"control not designed: {cid!r}")
            return tuple(self._tests_for[cid])

    def report(self, seq: object) -> ControlReport:
        """Aggregate report; pure read: validates seq, consumes nothing."""
        _check_seq(seq)
        with self._lock:
            passes = sum(1 for t in self._tests.values()
                         if t.result == "pass")
            fails = sum(1 for t in self._tests.values()
                        if t.result == "fail")
            inconclusive = sum(1 for t in self._tests.values()
                               if t.result == "inconclusive")
            with_failures = tuple(sorted({
                t.control_id for t in self._tests.values()
                if t.result == "fail"
            }))
            return ControlReport(
                n_controls=len(self._designs),
                n_tests=len(self._tests),
                n_remediations=len(self._remediations),
                passes=passes,
                fails=fails,
                inconclusive=inconclusive,
                controls_with_failures=with_failures,
                digest=_record_digest(
                    "report", {
                        "n_controls": len(self._designs),
                        "n_tests": len(self._tests),
                        "n_remediations": len(self._remediations),
                        "passes": passes,
                        "fails": fails,
                        "inconclusive": inconclusive,
                        "controls_with_failures": list(with_failures),
                    }),
            )

    def stats(self, seq: object) -> Dict[str, int]:
        """Ledger counts; pure read."""
        _check_seq(seq)
        with self._lock:
            return {
                "controls": len(self._designs),
                "retired": len(self._retired),
                "tests": len(self._tests),
                "remediations": len(self._remediations),
                "audit_rows": len(self._audit),
            }

    def audit_log(self, seq: object) -> Tuple[Dict[str, object], ...]:
        """Full audit log; pure read."""
        _check_seq(seq)
        with self._lock:
            return tuple(dict(row) for row in self._audit)


def main() -> None:
    """Self-check: design, test, remediate, retire, pins, audit."""
    ledger = ControlTesting()
    design = ledger.design("C-101", "preventive", 1)
    assert design.verify()
    test1 = ledger.test("C-101", "T-1", "inspection", 2, result="pass")
    assert test1.verify()
    test2 = ledger.test("C-101", "T-2", "reperformance", 3, result="fail")
    assert test2.verify()
    rem = ledger.remediate("C-101", "T-2", "fix-control", 4)
    assert rem.verify()
    report = ledger.report(5)
    assert report.verify()
    assert report.fails == 1
    try:
        ledger.design("C-101", "detective", 6)
    except ControlTestingError:
        pass
    else:  # pragma: no cover
        raise AssertionError("duplicate design must raise")
    try:
        ledger.test("C-101", "T-1", "observation", 5, result="pass")
    except SeqOrderError:
        pass
    else:  # pragma: no cover
        raise AssertionError("seq rewind must raise bare")
    assert ledger.audit_log(6)
    assert ledger.stats(6)["tests"] == 2
    ledger.retire("C-101", 7)
    try:
        ledger.design("C-101", "detective", 8)
    except ControlTestingError:
        pass
    else:  # pragma: no cover
        raise AssertionError("retired id must not recycle")
    print("control-testing OK: design, test, remediate, retire, pins, audit")


if __name__ == "__main__":
    main()
