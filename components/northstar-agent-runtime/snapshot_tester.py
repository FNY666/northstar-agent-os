"""Snapshot testing interface (Jest toMatchSnapshot shaped, simulated).

Research motivation: regression suites need a cheap way to pin an
output shape -- the rendered CLI help text, the canonical plan card,
the serialized audit record -- and to fail loudly when it changes.
Jest's snapshot discipline is the reference: the first run records
the snapshot, later runs compare against it, re-recording is an
explicit opt-in (``--u``), new snapshots in CI mode fail closed, and
the recorded file can be reviewed in a diff.

This module is the *bookkeeping* half of that shape -- the ledger
that holds named snapshots, their digest pins, and the comparison
verdicts. It cannot execute the host's test (the host owns the
runner); it books the record / match / update decisions:

- ``SnapshotTester`` -- owns the snapshot ledger.
  ``snap(name, value, seq)`` records a new named snapshot (the first
  run); ``match(name, value, seq)`` compares a host-reported value
  against the pinned snapshot and returns a frozen ``MatchReport``
  (``passed`` bool + structural diff); ``update(name, value, seq)``
  re-records an existing snapshot after an approved change.
- ``snapshot_tester_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``recorded`` / ``matched`` / ``updated`` / ``rejected``);
  ids and digest pins only -- snapshot values never cross the audit
  boundary.

Fail-closed edges (fail loudly, never guess):

- ``snap()`` on an already-recorded name raises
  ``DuplicateSnapshotError`` -- re-recording is an explicit
  ``update()`` so no test run silently rewrites history.
- ``update()`` / ``match()`` on an unknown name raise
  ``UnknownSnapshotError`` (Jest's ``--ci`` new-snapshot failure).
- Snapshot values are canonicalized with the JCS discipline:
  mappings, lists, str, int, bool, None only; NaN/Inf raise in the
  canonicalizer, and integers or integral floats with
  ``abs >= 2**53`` are refused (the batch-5 float-loss caveat).
  Bool is not int; ``true`` and ``1`` pin differently.
- Mutating calls consume strictly increasing caller-supplied int
  seqs (no wall-clock); rewinds raise ``SeqOrderError``. A failed
  mutation consumes its seq (fail-closed ledger position).
- Mismatch is *data*, never an exception: ``match()`` returns
  ``MatchReport(passed=False, diff=...)`` with a structural diff of
  the changed paths (capped at 16 lines).

Honest scope:

- This module is simulated bookkeeping, not a test runner: it emits
  no assertions, runs no test files, and cannot prove the recorded
  snapshot is *correct* -- only that the value the host reported
  matches (or differs from) the pinned one.
- The digest pins what the *caller* supplied -- a lying host gets a
  lying ledger (GIGO boundary).
- In-memory only: pair with the durable audit writer if snapshot
  verdicts must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
SNAPSHOT_TESTER_VERSION = "snapshot-tester.v1"

#: Schema pin carried by records and audit events.
SNAPSHOT_TESTER_SCHEMA = "northstar.snapshot-tester.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Structural diff line cap (a diff is a finding, not a full patch).
MAX_DIFF_LINES = 16

#: Audit event kinds.
KIND_RECORDED = "recorded"
KIND_MATCHED = "matched"
KIND_UPDATED = "updated"
KIND_REJECTED = "rejected"
_KINDS = (KIND_RECORDED, KIND_MATCHED, KIND_UPDATED, KIND_REJECTED)

#: Fields that must never cross the audit boundary (host content).
_BANNED_AUDIT_FIELDS = ("value", "payload", "expected", "actual")


class SnapshotTesterError(Exception):
    """Base error for the snapshot tester."""


class DuplicateSnapshotError(SnapshotTesterError):
    """snap() was called for a name that is already recorded."""


class UnknownSnapshotError(SnapshotTesterError):
    """match()/update() was given a name this tester never recorded."""


class BadValueError(SnapshotTesterError):
    """The snapshot value cannot be canonically pinned."""


class SeqOrderError(SnapshotTesterError):
    """A caller seq is not a strictly increasing int (no wall-clock)."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SnapshotTesterError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise SnapshotTesterError(f"{what} must be a non-empty str")
    return value


def _pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


def _validate_value(value: Any, what: str = "value") -> Any:
    """Refuse values the canonicalizer cannot pin losslessly.

    Returns the value unchanged when it is JCS-pinnable: mappings,
    lists, str, int, bool, None. NaN/Inf are rejected by the
    canonicalizer itself; integers and integral floats with
    ``abs >= 2**53`` are refused here (the batch-5 float-loss caveat:
    JCS serializes numbers as IEEE-754 doubles, so such values would
    silently collide after canonicalization).
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadValueError(
                f"{what}: integer {value} is outside the lossless "
                "JCS range (|n| < 2**53)"
            )
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadValueError(f"{what}: NaN/Inf cannot be pinned")
        if value.is_integer() and abs(value) >= 2**53:
            raise BadValueError(
                f"{what}: integral float {value!r} is outside the lossless "
                "JCS range (|n| < 2**53)"
            )
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return [_validate_value(v, f"{what}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise BadValueError(
                    f"{what}: mapping keys must be str, got {type(k).__name__}"
                )
        return {k: _validate_value(v, f"{what}.{k}") for k, v in value.items()}
    raise BadValueError(
        f"{what}: unsupported type {type(value).__name__} "
        "(mappings, lists, str, int, bool, None only)"
    )


def _canonical(value: Any) -> bytes:
    """Canonical bytes for a validated snapshot value."""
    _validate_value(value)
    try:
        return jcs_canonical_json(value)
    except Exception as exc:  # NaN/Inf, lone surrogates, ...
        raise BadValueError(f"value cannot be canonically pinned: {exc}")


def _fmt_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return repr(value)
    return str(value)


def _structural_diff(expected: Any, actual: Any) -> Tuple[str, ...]:
    """Deterministic path-wise diff of two decoded values.

    Paths read like ``a.b[2].c``; mappings compare key-wise (sorted),
    lists index-wise. Capped at ``MAX_DIFF_LINES`` lines so a huge
    regression stays a finding, not a full patch.
    """
    lines: List[str] = []

    def walk(path: str, exp: Any, act: Any) -> None:
        if len(lines) >= MAX_DIFF_LINES:
            return
        if type(exp) is not type(act):
            lines.append(
                f"{path or '<root>'}: type {type(exp).__name__} != "
                f"{type(act).__name__} "
                f"({_fmt_scalar(exp)} vs {_fmt_scalar(act)})"
            )
            return
        if isinstance(exp, dict):
            for key in sorted(set(exp) | set(act)):
                if len(lines) >= MAX_DIFF_LINES:
                    return
                child = f"{path}.{key}" if path else key
                if key not in exp:
                    lines.append(f"{child}: missing (added {_fmt_scalar(act[key])})")
                elif key not in act:
                    lines.append(f"{child}: {_fmt_scalar(exp[key])} (removed)")
                else:
                    walk(child, exp[key], act[key])
            return
        if isinstance(exp, list):
            if len(exp) != len(act):
                lines.append(
                    f"{path or '<root>'}: list length {len(exp)} != {len(act)}"
                )
            for i, (e_item, a_item) in enumerate(zip(exp, act)):
                walk(f"{path}[{i}]", e_item, a_item)
                if len(lines) >= MAX_DIFF_LINES:
                    return
            return
        if exp != act:
            lines.append(
                f"{path or '<root>'}: {_fmt_scalar(exp)} != {_fmt_scalar(act)}"
            )

    walk("", expected, actual)
    return tuple(lines)


@dataclass(frozen=True)
class SnapshotRecord:
    """One named snapshot, digest-pinned."""

    snapshot_id: str
    name: str
    digest: str
    revision: int  # 1 on snap(), +1 per update()
    seq: int
    version: str = SNAPSHOT_TESTER_VERSION
    schema: str = SNAPSHOT_TESTER_SCHEMA

    def verify(self, value: Any) -> bool:
        """Re-derive the digest pin from a candidate value."""
        try:
            return _pin(["snapshot", self.name, _canonical(value).decode("utf-8")]) \
                == self.digest
        except SnapshotTesterError:
            return False


@dataclass(frozen=True)
class MatchReport:
    """One booked comparison; mismatch is data, never an exception."""

    name: str
    passed: bool
    expected_digest: str
    actual_digest: str
    diff: Tuple[str, ...]
    seq: int
    digest: str
    version: str = SNAPSHOT_TESTER_VERSION
    schema: str = SNAPSHOT_TESTER_SCHEMA


class SnapshotTester:
    """Deterministic single-host snapshot record/match/update bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._snapshots: Dict[str, SnapshotRecord] = {}  # name -> record
        self._canonical: Dict[str, str] = {}  # name -> canonical JSON text
        self._matches: Dict[str, List[MatchReport]] = {}  # name -> match ledger
        self._next_snap = 0
        self._last_seq = -1

    # -- internal ---------------------------------------------------

    def _consume_seq(self, seq: int) -> None:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} is not strictly greater than last seq {self._last_seq}"
            )
        self._last_seq = seq

    # -- snap / match / update --------------------------------------

    def snap(self, name: str, value: Any, seq: int) -> SnapshotRecord:
        """Record a new named snapshot (the first run).

        Raises ``DuplicateSnapshotError`` when ``name`` is already
        recorded -- re-recording is an explicit ``update()`` so no
        test run silently rewrites history.
        """
        _check_str(name, "name")
        canon = _canonical(value)
        digest = _pin(["snapshot", name, canon.decode("utf-8")])
        with self._lock:
            self._consume_seq(seq)
            if name in self._snapshots:
                raise DuplicateSnapshotError(
                    f"snapshot {name!r} already recorded; use update()"
                )
            self._next_snap += 1
            record = SnapshotRecord(
                snapshot_id=f"snap-{self._next_snap}",
                name=name,
                digest=digest,
                revision=1,
                seq=seq,
            )
            self._snapshots[name] = record
            self._canonical[name] = canon.decode("utf-8")
            self._matches[name] = []
            return record

    def match(self, name: str, value: Any, seq: int) -> MatchReport:
        """Compare a host-reported value against the pinned snapshot.

        Mismatch is data: the report carries ``passed=False`` and a
        structural diff. Unknown names raise ``UnknownSnapshotError``
        (Jest's ``--ci`` new-snapshot failure).
        """
        _check_str(name, "name")
        canon = _canonical(value)
        actual_digest = _pin(["snapshot", name, canon.decode("utf-8")])
        with self._lock:
            self._consume_seq(seq)
            record = self._snapshots.get(name)
            if record is None:
                raise UnknownSnapshotError(
                    f"no snapshot recorded for {name!r}"
                )
            passed = actual_digest == record.digest
            diff: Tuple[str, ...] = ()
            if not passed:
                import json as _json

                diff = _structural_diff(
                    _json.loads(self._canonical[name]),
                    _json.loads(canon.decode("utf-8")),
                )
            report = MatchReport(
                name=name,
                passed=passed,
                expected_digest=record.digest,
                actual_digest=actual_digest,
                diff=diff,
                seq=seq,
                digest=_pin(["match", name, record.digest, actual_digest, seq]),
            )
            self._matches[name].append(report)
            return report

    def update(self, name: str, value: Any, seq: int) -> SnapshotRecord:
        """Re-record an existing snapshot after an approved change.

        The revision bumps; the name and snapshot id stay stable so
        the history of the approval is traceable.
        """
        _check_str(name, "name")
        canon = _canonical(value)
        digest = _pin(["snapshot", name, canon.decode("utf-8")])
        with self._lock:
            self._consume_seq(seq)
            record = self._snapshots.get(name)
            if record is None:
                raise UnknownSnapshotError(
                    f"no snapshot recorded for {name!r}; use snap() first"
                )
            updated = SnapshotRecord(
                snapshot_id=record.snapshot_id,
                name=name,
                digest=digest,
                revision=record.revision + 1,
                seq=seq,
            )
            self._snapshots[name] = updated
            self._canonical[name] = canon.decode("utf-8")
            return updated

    # -- views ------------------------------------------------------

    def snapshot(self, name: str) -> SnapshotRecord:
        """The pinned snapshot record, by name."""
        _check_str(name, "name")
        with self._lock:
            record = self._snapshots.get(name)
            if record is None:
                raise UnknownSnapshotError(
                    f"no snapshot recorded for {name!r}"
                )
            return record

    def snapshot_names(self) -> Tuple[str, ...]:
        """All recorded snapshot names, in recording order."""
        with self._lock:
            return tuple(self._snapshots)

    def snapshot_count(self) -> int:
        """How many snapshots are recorded."""
        with self._lock:
            return len(self._snapshots)

    def last_match(self, name: str) -> Optional[MatchReport]:
        """The most recent match report for a name (None if none)."""
        _check_str(name, "name")
        with self._lock:
            if name not in self._snapshots:
                raise UnknownSnapshotError(
                    f"no snapshot recorded for {name!r}"
                )
            reports = self._matches[name]
            return reports[-1] if reports else None

    def matches(self, name: str) -> Tuple[MatchReport, ...]:
        """The match ledger for a name, oldest first."""
        _check_str(name, "name")
        with self._lock:
            if name not in self._snapshots:
                raise UnknownSnapshotError(
                    f"no snapshot recorded for {name!r}"
                )
            return tuple(self._matches[name])


def snapshot_tester_audit_event(
    kind: str, seq: int, **fields: Any
) -> "dict[str, Any]":
    """Shape an ``audit.ndjson/1`` record for a snapshot-tester event."""
    if kind not in _KINDS:
        raise SnapshotTesterError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    for key in _BANNED_AUDIT_FIELDS:
        if key in fields:
            raise SnapshotTesterError(
                f"field {key!r} must not cross the audit boundary"
            )
    event = {
        "kind": kind,
        "seq": seq,
        "schema": AUDIT_SCHEMA,
        "module": SNAPSHOT_TESTER_SCHEMA,
    }
    event.update({k: v for k, v in fields.items()})
    return event


def main() -> None:
    st = SnapshotTester()
    rec = st.snap("cli-help", {"args": ["--json"], "exit": 0}, 1)
    assert rec.snapshot_id == "snap-1" and rec.revision == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify({"args": ["--json"], "exit": 0})
    assert not rec.verify({"args": ["--json"], "exit": 1})

    ok = st.match("cli-help", {"args": ["--json"], "exit": 0}, 2)
    assert ok.passed and ok.diff == ()
    assert ok.expected_digest == ok.actual_digest

    bad = st.match("cli-help", {"args": ["--json"], "exit": 1}, 3)
    assert not bad.passed
    assert bad.expected_digest != bad.actual_digest
    assert any("exit" in line for line in bad.diff)
    assert st.last_match("cli-help") is bad

    upd = st.update("cli-help", {"args": ["--json"], "exit": 1}, 4)
    assert upd.snapshot_id == rec.snapshot_id and upd.revision == 2
    assert st.match("cli-help", {"args": ["--json"], "exit": 1}, 5).passed

    # Fail-closed edges.
    for fn, err in (
        (lambda: st.snap("cli-help", {}, 6), DuplicateSnapshotError),
        (lambda: st.match("nope", {}, 7), UnknownSnapshotError),
        (lambda: st.update("nope", {}, 8), UnknownSnapshotError),
        (lambda: st.snap("big", 2**53, 9), BadValueError),
        (lambda: st.snap("nan", float("nan"), 10), BadValueError),
        (lambda: st.snap("boolseq", {}, True), SnapshotTesterError),
    ):
        try:
            fn()
        except err:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"expected {err.__name__}")
    try:
        st.snap("rewind", {}, 5)
    except SeqOrderError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected SeqOrderError")

    snapshot_tester_audit_event(KIND_RECORDED, 12, name=rec.name)
    snapshot_tester_audit_event(KIND_MATCHED, 13, name=rec.name, passed=True)
    snapshot_tester_audit_event(KIND_UPDATED, 14, name=rec.name, revision=2)
    print("snapshot-tester OK: snap, match pass/fail, update, refusals, audit")


if __name__ == "__main__":
    main()
