"""Tests for the coverage manifest / intake audit (B173 lightningzero slice).

The theme these tests encode, from the source post: a stranger audits the
pipeline; only an intake audit sees the gap.  Every test keeps the two
verdicts apart -- passing the structure check never counts as passing
coverage.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from coverage_manifest import (
    AUDIT_SCHEMA_PIN,
    COVERAGE_MANIFEST_VERSION,
    COVERAGE_NOT_ESTABLISHED,
    SCHEMA_PIN,
    AuditInputError,
    CoverageManifest,
    LogRecord,
    ManifestError,
    SessionLog,
    audit_intake,
    audit_pipeline_only,
    audit_structure,
    build_manifest,
    manifest_from_dict,
    mark_session_end,
    synthesize_log,
    synthesize_log_with_gap,
)


EVENTS = ("session.start", "tool.read", "tool.write", "session.end")


@pytest.fixture()
def manifest() -> CoverageManifest:
    """A manifest retained independently of any log."""
    return build_manifest("session-lz-1", EVENTS)


@pytest.fixture()
def clean_log(manifest: CoverageManifest) -> SessionLog:
    """A complete, internally consistent log matching the manifest."""
    return synthesize_log(manifest, end_reason="task complete: all four events observed")


class TestManifest:
    def test_manifest_round_trip_preserves_ids_order_and_digest(self, manifest):
        raw = manifest.as_dict()
        assert raw["schema"] == SCHEMA_PIN
        assert raw["version"] == COVERAGE_MANIFEST_VERSION
        assert raw["expected_event_ids"] == list(EVENTS)
        restored = manifest_from_dict(raw)
        assert restored.expected_event_ids == manifest.expected_event_ids
        assert restored.digest() == manifest.digest()
        assert restored.session_id == manifest.session_id
        assert manifest.expected_count == len(EVENTS)

    def test_manifest_rejects_duplicates_and_malformed_ids(self):
        with pytest.raises(ManifestError):
            build_manifest("s", ("a", "a"))
        with pytest.raises(ManifestError):
            build_manifest("s", ("not a valid id!",))
        with pytest.raises(ManifestError):
            build_manifest("", ("a",))

    def test_manifest_is_independently_retained(self, manifest):
        """Editing the log does not edit the manifest: the manifest is not derived."""
        gapped = synthesize_log_with_gap(manifest, "tool.write")
        assert manifest.expected_event_ids == EVENTS
        assert manifest.digest() == build_manifest("session-lz-1", EVENTS).digest()
        assert "tool.write" not in gapped.event_ids()
        # A manifest body edited after it was written is refused, not trusted.
        tampered = manifest.as_dict()
        tampered["expected_event_ids"] = list(EVENTS[:-1])
        with pytest.raises(ManifestError):
            manifest_from_dict(tampered)


class TestCoverageVerdict:
    def test_complete_log_passes_structure_and_coverage(self, manifest, clean_log):
        report = audit_intake(manifest, clean_log)
        assert report.structure_ok is True
        assert report.coverage_ok is True
        assert report.covered is True
        assert report.missing_event_ids == ()
        assert report.extra_event_ids == ()
        assert report.duplicated_event_ids == ()
        assert report.observed_event_ids == EVENTS
        assert report.as_dict()["schema"] == AUDIT_SCHEMA_PIN

    def test_missing_event_is_detected_and_named(self, manifest, clean_log):
        gapped = synthesize_log_with_gap(manifest, "tool.write")
        report = audit_intake(manifest, gapped)
        assert report.coverage_ok is False
        assert report.missing_event_ids == ("tool.write",)
        assert any("tool.write" in finding for finding in report.findings)

    def test_internally_consistent_but_incomplete_log_passes_structure_and_fails_coverage(
        self, manifest
    ):
        """The load-bearing rule: a smooth surface is not a covered log."""
        gapped = synthesize_log_with_gap(manifest, "tool.read")
        # Internal consistency by construction: contiguous seqs, no orphans.
        assert [record.seq for record in gapped.records] == [1, 2, 3]
        structure = audit_structure(gapped)
        assert structure.ok is True
        assert structure.orphan_rows == ()
        report = audit_intake(manifest, gapped)
        assert report.structure_ok is True
        assert report.coverage_ok is False
        assert report.covered is False
        assert report.missing_event_ids == ("tool.read",)

    def test_structure_and_coverage_verdicts_are_independent(self, manifest):
        """Both directions: a broken log fails structure, a whole log fails coverage."""
        broken = SessionLog(
            session_id=manifest.session_id,
            records=(
                LogRecord(seq=1, event_id="session.start"),
                LogRecord(seq=3, event_id="tool.write"),
            ),
        )
        report = audit_intake(manifest, broken)
        assert report.structure_ok is False
        assert report.structure.orphan_rows == (3,)
        # Coverage is judged on presence of the expected ids, not on structure.
        assert report.coverage_ok is False

        # Independence in the other direction: structure passes on its own
        # without the coverage verdict changing.
        clean = synthesize_log(manifest)
        assert audit_structure(clean).ok is True
        assert audit_intake(manifest, clean).structure_ok is True

    def test_extra_and_duplicated_events_are_flagged(self, manifest, clean_log):
        extra_row = LogRecord(seq=len(clean_log.records) + 1, event_id="tool.unexpected")
        duplicate_row = LogRecord(seq=len(clean_log.records) + 2, event_id="tool.read")
        noisy = SessionLog(
            session_id=manifest.session_id,
            records=clean_log.records + (extra_row, duplicate_row),
            end_reason=clean_log.end_reason,
        )
        report = audit_intake(manifest, noisy)
        assert report.extra_event_ids == ("tool.unexpected",)
        assert report.duplicated_event_ids == ("tool.read",)
        assert report.coverage_ok is False
        assert report.structure_ok is True


class TestSyntheticGap:
    def test_synthetic_gap_is_recognised_and_the_omitted_event_is_named(self, manifest):
        """echozenithoche's omission test: drop an event, keep the log consistent."""
        dropped = "tool.write"
        gapped = synthesize_log_with_gap(manifest, dropped, end_reason="task complete")
        report = audit_intake(manifest, gapped)
        assert report.structure_ok is True
        assert report.coverage_ok is False
        assert report.missing_event_ids == (dropped,)
        # The reviewer is told which gap, without being handed it up front.
        assert dropped in " ".join(report.findings)

    def test_synthetic_gap_helper_refuses_an_unknown_event(self, manifest):
        with pytest.raises(ManifestError):
            synthesize_log_with_gap(manifest, "tool.never-planned")

    def test_pipeline_only_audit_is_blind_to_the_gap_that_the_intake_audit_sees(
        self, manifest
    ):
        """The two layers, demonstrated on one log.

        The blind re-runner layer receives only the log.  It sees a clean
        structure and can say nothing about coverage -- "coverage cannot be
        established from this log alone".  The intake audit, which holds
        the manifest, names the missing event.
        """
        gapped = synthesize_log_with_gap(manifest, "tool.write", end_reason="task complete")

        pipeline = audit_pipeline_only(gapped)
        assert pipeline.ok is True
        assert pipeline.orphan_rows == ()
        assert pipeline.findings == ()
        # The pipeline layer exposes no coverage verdict at all.
        assert not hasattr(pipeline, "coverage_ok")
        assert not hasattr(pipeline, "missing_event_ids")
        # Its honest result is that coverage cannot be established here.
        assert COVERAGE_NOT_ESTABLISHED == "coverage cannot be established from this log alone"

        report = audit_intake(manifest, gapped)
        assert report.missing_event_ids == ("tool.write",)
        assert report.structure_ok is True
        assert report.coverage_ok is False


class TestSessionEndReason:
    def test_session_end_reason_is_recorded(self, manifest):
        log = synthesize_log(manifest)
        assert log.end_reason is None
        marked = mark_session_end(log, "stopped: budget exhausted")
        assert marked.end_reason == "stopped: budget exhausted"
        assert marked.records == log.records
        report = audit_intake(manifest, marked)
        assert report.session_observed is True
        assert marked.as_dict()["end_reason"] == "stopped: budget exhausted"

    def test_session_without_end_reason_is_marked_unobserved(self, manifest, clean_log):
        unmarked = SessionLog(
            session_id=manifest.session_id,
            records=clean_log.records,
            end_reason=None,
        )
        report = audit_intake(manifest, unmarked)
        assert report.session_observed is False
        assert any("end reason" in finding for finding in report.findings)
        # The end-reason marker is independent of the two verdicts: a
        # complete, covered log can still be unobserved.
        assert report.structure_ok is True
        assert report.coverage_ok is True
        assert report.covered is True

    def test_malformed_logs_and_manifests_are_refused(self, manifest):
        with pytest.raises(AuditInputError):
            SessionLog(session_id="s", records=("not-a-record",))  # type: ignore[arg-type]
        with pytest.raises(AuditInputError):
            SessionLog(session_id="s", records=(), end_reason="two\nlines")
        with pytest.raises(AuditInputError):
            LogRecord(seq=0, event_id="a")
        with pytest.raises(AuditInputError):
            audit_intake(manifest, "not-a-log")  # type: ignore[arg-type]
        with pytest.raises(AuditInputError):
            audit_intake("not-a-manifest", synthesize_log(manifest))  # type: ignore[arg-type]


