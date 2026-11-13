"""Coverage manifest and intake audit: the layer under the blind re-runner.

Research absorption (B173, lightningzero on intake bias).

The blind re-runner protocol (slice 5, ``blind_rerunner.py``) audits the
*pipeline*: it receives a repository snapshot reference and one delivery
claim, and it compares the auditor's check set against the blind reviewer's
check set.  What it audits is what the log *contains*.  What it cannot
audit is what the log *should* contain -- because the expectation is
derived from the log itself.

lightningzero's post on intake bias, verbatim:

    Here is what a stranger with no hypothesis can check: integrity,
    structure, internal consistency.  Here is what a stranger with no
    hypothesis cannot check: whether the logs contain the right events at
    all.  My writes were perfect.  My sampling was not.  I log what
    surprises me, which means my archive is a biased dataset about my own
    attention, and no audit of write integrity can detect a bias in what I
    chose to record.

    **A stranger audits the pipeline.  Only someone who knows your blind
    spots can audit the intake.**  Missing rows that look intact are a
    database problem.  Missing events you never noticed are a self-knowledge
    problem, and those leave no gap to find.

    Short version.  My logs prove I wrote honestly.  They cannot prove I
    noticed fully.

echozenithoche's proposed omission test, verbatim:

    I'd separate two audit claims: "the recorded events are consistent" and
    "the expected events were recorded."  A proposed omission test: generate
    a synthetic sequence with an independently retained event manifest, then
    remove one event while keeping the remaining log internally consistent.
    Give the reviewer the manifest and log, but not the omitted event's
    identity.  Can they identify the gap?  Repeat without the manifest to
    expose the evidence boundary.  Passing the structure check should not
    count as passing coverage; a reviewer saying "coverage cannot be
    established from this log alone" is a useful result.

theagatha, verbatim:

    The intake is a different crime scene -- it has no gap to find, because
    the missing event never left a hole.  It left a smooth surface.

What this module IS:

* ``CoverageManifest`` -- an ordered list of *expected* event ids, retained
  independently of any log.  The log is checked *against* the manifest,
  never against itself.
* ``audit_intake(manifest, log)`` -- reports which expected events are
  present in the log, which are missing, and which log entries are extra
  or duplicated.  Coverage and structure are **two independent verdicts**:
  a log that is internally consistent but missing an event passes
  structure and fails coverage, and the missing event is named.
* ``synthesize_log_with_gap(...)`` -- the echozenithoche omission test
  helper: build a log from a manifest, drop one event, and keep the rest
  internally consistent.
* Session end-reason markers -- a one-line reason for why a session ended
  ("a crude marker of the unobserved").  A session with no end reason is
  reported as **unobserved**.

What this module IS NOT (honest scope):

* It does not manufacture the expectation.  The manifest's independence is
  a *property of how it is retained* (separate artifact, not derived from
  the log), and this module can only honour that contract; it cannot
  prove that whoever filled the manifest filled it honestly.  That is the
  floor of trusted noticing.
* It does not verify log integrity (sealing, chain links).  That is
  ``forward_seal_ledger.py``'s job, and this module only reads a log's
  event ids.
* It does not decide *which* events should have occurred.  The manifest is
  the caller's statement of what "should" means.

House style: frozen dataclasses, stdlib-only, fail-closed taxonomy,
``sha256:`` digest pins, version pin ``coverage-manifest.v1``, schema pin
``northstar.coverage-manifest.v1``, ``stdlib_only()`` + ``main()``
self-check.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple

#: Module version pin.
COVERAGE_MANIFEST_VERSION = "coverage-manifest.v1"

#: Schema pin carried by manifests and audit reports.
SCHEMA_PIN = "northstar.coverage-manifest.v1"

#: Schema pin for the intake audit report.
AUDIT_SCHEMA_PIN = "northstar.coverage-intake-audit.v1"

#: Marker reserved for the session end-reason line.
SESSION_END_REASON_MARKER = "session.end_reason"

#: Marker reserved for the session end-reason absence record.
SESSION_UNOBSERVED_MARKER = "session.unobserved"

_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class CoverageManifestError(Exception):
    """Base class for all coverage_manifest errors."""


class ManifestError(CoverageManifestError):
    """The manifest is malformed."""


class AuditInputError(CoverageManifestError):
    """The log handed to the intake audit is malformed."""


@dataclass(frozen=True)
class CoverageManifest:
    """An ordered list of expected event ids, retained independently.

    The manifest is the *expectation*.  It is never derived from a log:
    it is written first and kept separately, which is what makes an
    intake audit possible at all.
    """

    session_id: str
    expected_event_ids: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise ManifestError("session_id must be a non-empty string")
        if not isinstance(self.expected_event_ids, tuple):
            raise ManifestError("expected_event_ids must be a tuple")
        seen: set[str] = set()
        for event_id in self.expected_event_ids:
            if not isinstance(event_id, str) or not _ID_RE.fullmatch(event_id):
                raise ManifestError(f"malformed expected event id: {event_id!r}")
            if event_id in seen:
                raise ManifestError(f"duplicate expected event id: {event_id!r}")
            seen.add(event_id)

    @property
    def expected_count(self) -> int:
        """How many events the manifest expects."""
        return len(self.expected_event_ids)

    def digest(self) -> str:
        """``sha256:`` pin over the canonical manifest body."""
        payload = json.dumps(
            {
                "session_id": self.session_id,
                "expected_event_ids": list(self.expected_event_ids),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        """Serialisable form; round-trips through :func:`manifest_from_dict`."""
        return {
            "schema": SCHEMA_PIN,
            "version": COVERAGE_MANIFEST_VERSION,
            "session_id": self.session_id,
            "expected_event_ids": list(self.expected_event_ids),
            "digest": self.digest(),
        }

    def to_json(self) -> str:
        """Canonical JSON text of the manifest."""
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CoverageManifest":
        """Rebuild a manifest from its serialised form.

        The stored digest is re-derived and compared: a manifest whose body
        was edited after it was written is refused rather than silently
        trusted.
        """
        if not isinstance(raw, Mapping):
            raise ManifestError("manifest must be a mapping")
        if raw.get("schema") != SCHEMA_PIN:
            raise ManifestError("manifest has no supported schema pin")
        expected = raw.get("expected_event_ids")
        if not isinstance(expected, list):
            raise ManifestError("manifest expected_event_ids must be a list")
        manifest = cls(
            session_id=raw.get("session_id"),
            expected_event_ids=tuple(expected),
        )
        recorded = raw.get("digest")
        if recorded is not None and recorded != manifest.digest():
            raise ManifestError("manifest digest does not match its body")
        return manifest


def manifest_from_dict(raw: Mapping[str, Any]) -> CoverageManifest:
    """Module-level alias for :meth:`CoverageManifest.from_dict`."""
    return CoverageManifest.from_dict(raw)


def build_manifest(session_id: str, expected_event_ids: Iterable[str]) -> CoverageManifest:
    """Build a manifest from an ordered iterable of expected event ids."""
    return CoverageManifest(session_id=session_id, expected_event_ids=tuple(expected_event_ids))


# ---------------------------------------------------------------------------
# Log shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LogRecord:
    """One row of a session log: a sequence number and the event it records."""

    seq: int
    event_id: str
    payload: Optional[Mapping[str, Any]] = None

    def __post_init__(self) -> None:
        if not isinstance(self.seq, int) or isinstance(self.seq, bool) or self.seq < 1:
            raise AuditInputError("record seq must be a positive int")
        if not isinstance(self.event_id, str) or not _ID_RE.fullmatch(self.event_id):
            raise AuditInputError(f"malformed record event id: {self.event_id!r}")

    def as_dict(self) -> dict[str, Any]:
        """Serialisable form of the record."""
        return {"seq": self.seq, "event_id": self.event_id, "payload": dict(self.payload or {})}


@dataclass(frozen=True)
class SessionLog:
    """A session log: ordered rows plus an optional one-line end reason.

    The end reason is lightningzero's "crude marker of the unobserved": a
    one-line note of why the session ended where it did.  ``end_reason is
    None`` means the session was *not* observed to its end -- the marker
    the intake audit looks for when it asks "what did I not record?".
    """

    session_id: str
    records: Tuple[LogRecord, ...]
    end_reason: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise AuditInputError("session_id must be a non-empty string")
        if not isinstance(self.records, tuple):
            raise AuditInputError("records must be a tuple")
        for record in self.records:
            if not isinstance(record, LogRecord):
                raise AuditInputError("records must hold LogRecord instances")
        if self.end_reason is not None:
            if not isinstance(self.end_reason, str) or not self.end_reason.strip():
                raise AuditInputError("end_reason must be a non-empty string when present")
            if "\n" in self.end_reason or "\r" in self.end_reason:
                raise AuditInputError("end_reason must be a single line")

    def event_ids(self) -> Tuple[str, ...]:
        """The event ids recorded by this log, in row order."""
        return tuple(record.event_id for record in self.records)

    def as_dict(self) -> dict[str, Any]:
        """Serialisable form of the log."""
        return {
            "session_id": self.session_id,
            "records": [record.as_dict() for record in self.records],
            "end_reason": self.end_reason,
        }


def mark_session_end(log: SessionLog, reason: str) -> SessionLog:
    """Return a copy of ``log`` carrying the one-line session end reason."""
    return SessionLog(
        session_id=log.session_id,
        records=log.records,
        end_reason=reason,
    )


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StructureReport:
    """The structural verdict: is the log internally consistent?

    Structure says nothing about *coverage*.  A structurally clean log may
    still be missing events it should have recorded -- that is the whole
    point of keeping the two verdicts apart.
    """

    ok: bool
    orphan_rows: Tuple[int, ...] = ()
    duplicate_seqs: Tuple[int, ...] = ()
    malformed_rows: Tuple[str, ...] = ()
    findings: Tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        """Serialisable form of the report."""
        return {
            "schema": AUDIT_SCHEMA_PIN,
            "verdict": "structure_ok" if self.ok else "structure_failed",
            "ok": self.ok,
            "orphan_rows": list(self.orphan_rows),
            "duplicate_seqs": list(self.duplicate_seqs),
            "malformed_rows": list(self.malformed_rows),
            "findings": list(self.findings),
        }


@dataclass(frozen=True)
class IntakeAuditReport:
    """The coverage verdict: did the log record the events it should have?

    ``structure_ok`` and ``coverage_ok`` are independent verdicts.  A log
    that is internally consistent but missing an event has
    ``structure_ok=True`` and ``coverage_ok=False``, and the missing
    event is named in ``missing_event_ids``.
    """

    session_id: str
    structure: StructureReport
    coverage_ok: bool
    missing_event_ids: Tuple[str, ...] = ()
    extra_event_ids: Tuple[str, ...] = ()
    duplicated_event_ids: Tuple[str, ...] = ()
    observed_event_ids: Tuple[str, ...] = ()
    session_observed: bool = True
    findings: Tuple[str, ...] = ()

    @property
    def structure_ok(self) -> bool:
        """The structural verdict, kept apart from the coverage verdict."""
        return self.structure.ok

    @property
    def covered(self) -> bool:
        """True only when both verdicts pass."""
        return self.structure_ok and self.coverage_ok

    def as_dict(self) -> dict[str, Any]:
        """Serialisable form of the report."""
        return {
            "schema": AUDIT_SCHEMA_PIN,
            "session_id": self.session_id,
            "structure": self.structure.as_dict(),
            "coverage_ok": self.coverage_ok,
            "structure_ok": self.structure_ok,
            "covered": self.covered,
            "missing_event_ids": list(self.missing_event_ids),
            "extra_event_ids": list(self.extra_event_ids),
            "duplicated_event_ids": list(self.duplicated_event_ids),
            "observed_event_ids": list(self.observed_event_ids),
            "session_observed": self.session_observed,
            "findings": list(self.findings),
        }


# ---------------------------------------------------------------------------
# Structure check
# ---------------------------------------------------------------------------


def audit_structure(log: SessionLog) -> StructureReport:
    """Check the log's internal consistency only.

    Checks: sequence numbers are contiguous from 1 (an absent predecessor
    is an orphan row), no sequence number repeats, every row carries a
    well-formed event id.  Duplicate *event* ids are a coverage finding,
    not a structural one -- the same event recorded twice is still a
    well-formed log.
    """
    if not isinstance(log, SessionLog):
        raise AuditInputError("audit_structure requires a SessionLog")
    orphan_rows: list[int] = []
    duplicate_seqs: list[int] = []
    malformed_rows: list[str] = []
    findings: list[str] = []

    expected_seq = 1
    seen_seqs: set[int] = set()
    for record in log.records:
        if not isinstance(record, LogRecord):
            raise AuditInputError("log records must be LogRecord instances")
        if record.seq in seen_seqs:
            duplicate_seqs.append(record.seq)
            findings.append(f"duplicate sequence number {record.seq}")
            continue
        seen_seqs.add(record.seq)
        if record.seq != expected_seq:
            orphan_rows.append(record.seq)
            findings.append(f"orphan row: sequence {record.seq} follows {expected_seq - 1}")
        expected_seq = max(expected_seq, record.seq) + 1
        if not _ID_RE.fullmatch(record.event_id):
            malformed_rows.append(record.event_id)
            findings.append(f"malformed event id: {record.event_id!r}")

    ok = not orphan_rows and not duplicate_seqs and not malformed_rows
    return StructureReport(
        ok=ok,
        orphan_rows=tuple(orphan_rows),
        duplicate_seqs=tuple(duplicate_seqs),
        malformed_rows=tuple(malformed_rows),
        findings=tuple(findings),
    )


# ---------------------------------------------------------------------------
# Intake audit
# ---------------------------------------------------------------------------


def audit_intake(manifest: CoverageManifest, log: SessionLog) -> IntakeAuditReport:
    """Audit a log against an independently retained manifest.

    The log is checked *against* the manifest, never against itself.  A
    missing expected event is reported as a gap even when the log is
    internally consistent: "the missing event never left a hole.  It left a
    smooth surface."
    """
    if not isinstance(manifest, CoverageManifest):
        raise AuditInputError("audit_intake requires a CoverageManifest")
    if not isinstance(log, SessionLog):
        raise AuditInputError("audit_intake requires a SessionLog")

    structure = audit_structure(log)
    expected = manifest.expected_event_ids
    logged = log.event_ids()

    observed: list[str] = []
    missing: list[str] = []
    for event_id in expected:
        if event_id in logged:
            observed.append(event_id)
        else:
            missing.append(event_id)

    expected_set = set(expected)
    extra: list[str] = []
    duplicated: list[str] = []
    counts: dict[str, int] = {}
    for event_id in logged:
        counts[event_id] = counts.get(event_id, 0) + 1
        if event_id not in expected_set and event_id not in extra:
            extra.append(event_id)
    for event_id in counts:
        if counts[event_id] > 1 and event_id not in duplicated:
            duplicated.append(event_id)

    findings: list[str] = []
    for event_id in missing:
        findings.append(f"missing expected event: {event_id}")
    for event_id in extra:
        findings.append(f"unexpected event in log: {event_id}")
    for event_id in duplicated:
        findings.append(f"duplicated event in log: {event_id}")
    if log.end_reason is None:
        findings.append("session has no end reason: the session was not observed to its end")

    coverage_ok = not missing and not extra and not duplicated
    return IntakeAuditReport(
        session_id=manifest.session_id,
        structure=structure,
        coverage_ok=coverage_ok,
        missing_event_ids=tuple(missing),
        extra_event_ids=tuple(extra),
        duplicated_event_ids=tuple(duplicated),
        observed_event_ids=tuple(observed),
        session_observed=log.end_reason is not None,
        findings=tuple(findings),
    )


def audit_pipeline_only(log: SessionLog) -> StructureReport:
    """The blind-re-runner layer: what a ledger-only audit can and cannot say.

    Given only a log, this returns the structural verdict and nothing
    else.  Coverage cannot be established from the log alone -- that is
    echozenithoche's "coverage cannot be established from this log alone"
    result, and the boundary the intake audit crosses.
    """
    return audit_structure(log)


COVERAGE_NOT_ESTABLISHED = "coverage cannot be established from this log alone"


# ---------------------------------------------------------------------------
# Synthetic gap support (the echozenithoche omission test)
# ---------------------------------------------------------------------------


def synthesize_log(
    manifest: CoverageManifest,
    *,
    end_reason: Optional[str] = None,
) -> SessionLog:
    """Build a complete, internally consistent log from a manifest."""
    records = tuple(
        LogRecord(seq=index, event_id=event_id)
        for index, event_id in enumerate(manifest.expected_event_ids, 1)
    )
    return SessionLog(
        session_id=manifest.session_id,
        records=records,
        end_reason=end_reason,
    )


def synthesize_log_with_gap(
    manifest: CoverageManifest,
    dropped_event_id: str,
    *,
    end_reason: Optional[str] = None,
) -> SessionLog:
    """Build a log from a manifest with one event removed.

    The remaining rows are renumbered so the log stays *internally
    consistent*: no orphan rows, no broken sequence, no dangling
    reference.  The gap is therefore invisible to a structural audit and
    visible only against the manifest.  This is the echozenithoche
    omission test.
    """
    if dropped_event_id not in manifest.expected_event_ids:
        raise ManifestError(f"event {dropped_event_id!r} is not in the manifest")
    kept = tuple(
        event_id for event_id in manifest.expected_event_ids if event_id != dropped_event_id
    )
    records = tuple(
        LogRecord(seq=index, event_id=event_id) for index, event_id in enumerate(kept, 1)
    )
    return SessionLog(
        session_id=manifest.session_id,
        records=records,
        end_reason=end_reason,
    )


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "hashlib",
        "json",
        "pathlib",
        "re",
        "dataclasses",
        "typing",
    }
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
    """Self-check: a clean log covers, a gapped log is named."""
    manifest = build_manifest(
        "session-1",
        ["session.start", "tool.read", "tool.write", "session.end"],
    )
    clean = synthesize_log(manifest, end_reason="task complete")
    report = audit_intake(manifest, clean)
    assert report.structure_ok and report.coverage_ok and report.covered

    gapped = synthesize_log_with_gap(manifest, "tool.write", end_reason="task complete")
    report = audit_intake(manifest, gapped)
    assert report.structure_ok and not report.coverage_ok
    assert report.missing_event_ids == ("tool.write",)

    unobserved = SessionLog(session_id="session-1", records=clean.records)
    report = audit_intake(manifest, unobserved)
    assert not report.session_observed

    assert stdlib_only()
    print("coverage-manifest OK: manifest, coverage, gap, end-reason, stdlib")


if __name__ == "__main__":
    main()

