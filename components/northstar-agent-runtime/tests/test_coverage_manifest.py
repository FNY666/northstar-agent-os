"""Tests for the coverage manifest / intake audit (B173 lightningzero slice).

The theme these tests encode, from the source post: a stranger audits the
pipeline; only an intake audit sees the gap.  Every test keeps the two
verdicts apart -- passing the structure check never counts as passing
coverage.
"""

from __future__ import annotations

import atexit
import contextlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import coverage_manifest as _coverage_manifest

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


# ---------------------------------------------------------------------------
# Mutant closure: every test below names the mutant it kills.
#
# The probe plants single-token faults in ``coverage_manifest.py`` and asks
# whether this suite notices.  Twelve sites survived; the tests below are
# the shapes the design doc (``docs/design/mutant-evidence-closure.md``,
# section 3) prescribes:
#
#   * 3.1 -- a guard written ``A or B`` becomes ``A and B`` under the
#     probe, and the two differ only when EXACTLY ONE of A, B is true.
#     So each guard is fed BOTH ways: one input where only the first
#     half refuses, one where only the second half refuses.
#   * 3.2 -- a boundary is fed the exact limit and limit +/- 1.
#   * 3.3 -- a ``return False`` flipped to ``return True`` is caught by
#     asserting the False path ITSELF with ``assertIs(..., False)``,
#     plus a control so the test cannot be satisfied by a function that
#     always answers one way.
#   * 3.4 -- the name of the test names the mutant.
# ---------------------------------------------------------------------------

MODULE_PATH = Path(_coverage_manifest.__file__).resolve()

#: The banner the module's script-mode self-check prints.
SELF_CHECK_BANNER = "coverage-manifest OK"


@contextlib.contextmanager
def _variant_module(tmp_path, suffix, name):
    """Build an IMPORTED COPY of this module with ``suffix`` appended.

    The copy keeps the module's own ``__file__`` pointing at the copy, so
    ``stdlib_only()`` -- which parses ``__file__`` -- inspects the copy's
    source.  The copy is IMPORTED (not merely exec'd) so that it is a
    real module in ``sys.modules``: the dataclass machinery looks the
    defining module up there, and a bare namespace would break it.

    The copy is imported rather than executed as ``__main__`` so the
    appended text may contain constructs (a relative import) that would
    not resolve in a script context, and so the copy's ``main()`` is not
    run as a side effect of the import.

    The copy is removed from ``sys.modules`` on exit, so it cannot leak
    a stale module object into another test file.
    """
    source = MODULE_PATH.read_text(encoding="utf-8")
    text = source + suffix
    path = tmp_path / f"{name}.py"
    path.write_text(text, encoding="utf-8")
    module_name = f"coverage_manifest_variant_{name}"
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(module_name, None)


#: A private bytecode-cache root for the subprocesses.  It is EMPTY and
#: stays empty: ``PYTHONDONTWRITEBYTECODE`` stops the child from writing
#: into it, so no stale ``.pyc`` can ever be read back from it.
_PYCACHE_ROOT = tempfile.mkdtemp(prefix="coverage-manifest-pycache-")
atexit.register(shutil.rmtree, _PYCACHE_ROOT, True)


def _subprocess_env():
    """A subprocess environment that cannot read a stale ``.pyc``.

    ``PYTHONDONTWRITEBYTECODE`` stops the interpreter from WRITING
    bytecode but not from READING one that is already there.  A stale
    ``.pyc`` of the module would let a planted mutant look unplanted.
    ``PYTHONPYCACHEPREFIX`` moves the whole cache tree to a private,
    always-empty directory, so the child reads nothing from the source
    tree's cache.
    """
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPYCACHEPREFIX"] = _PYCACHE_ROOT
    env["PYTHONPATH"] = str(MODULE_PATH.parent)
    return env


def _run_module_as_script():
    """Run the module as a SCRIPT (``__name__ == "__main__"``)."""
    return subprocess.run(
        [sys.executable, "-B", str(MODULE_PATH)],
        cwd=str(MODULE_PATH.parent),
        env=_subprocess_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=120,
    )


def _import_module_in_subprocess():
    """IMPORT the module in a fresh interpreter (``__name__ != "__main__"``)."""
    return subprocess.run(
        [sys.executable, "-B", "-c", "import coverage_manifest"],
        cwd=str(MODULE_PATH.parent),
        env=_subprocess_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=120,
    )


class TestMutantOrGuards:
    """``or`` -> ``and`` on the four double guards (design doc 3.1)."""

    # -- or@231: the seq guard is a THREE-way chain ----------------------
    # The probe rewrites only the FIRST `` or ``, so the mutant reads
    # ``not isinstance(seq, int) and isinstance(seq, bool) or seq < 1``.
    # The two forms differ when exactly one of the first two halves is
    # true, so BOTH ways are fed: a bool (only the bool half refuses)
    # and a float (only the "not an int" half refuses).
    def test_or_at_231_a_boolean_seq_is_refused(self):
        """`or@231`: a bool IS an int, so only the explicit bool half refuses."""
        with pytest.raises(AuditInputError) as excinfo:
            LogRecord(seq=True, event_id="a")  # type: ignore[arg-type]
        assert "positive int" in str(excinfo.value)

    def test_or_at_231_a_float_seq_is_refused(self):
        """`or@231`: the other half -- only the "not an int" half refuses a float."""
        with pytest.raises(AuditInputError) as excinfo:
            LogRecord(seq=1.5, event_id="a")  # type: ignore[arg-type]
        assert "positive int" in str(excinfo.value)

    # -- or@233: the event id guard -------------------------------------
    def test_or_at_233_an_empty_event_id_is_refused(self):
        """`or@233`: a str that does not match the id pattern.

        The type half is False (it IS a string), so only the pattern
        half refuses; under the mutant the guard accepts the empty id.
        """
        with pytest.raises(AuditInputError) as excinfo:
            LogRecord(seq=1, event_id="")
        assert "malformed record event id" in str(excinfo.value)

    def test_or_at_233_a_non_string_event_id_is_refused(self):
        """`or@233`: the other half -- a non-string.

        Under the mutant the guard goes on to match the pattern against a
        non-string, so the refusal is replaced by an error from the
        wrong place.
        """
        with pytest.raises(AuditInputError) as excinfo:
            LogRecord(seq=1, event_id=123)  # type: ignore[arg-type]
        assert "malformed record event id" in str(excinfo.value)

    # -- or@256: the session id guard -----------------------------------
    def test_or_at_256_an_empty_session_id_is_refused(self):
        """`or@256`: a str that is empty -- only the emptiness half refuses."""
        with pytest.raises(AuditInputError) as excinfo:
            SessionLog(session_id="", records=())
        assert "non-empty string" in str(excinfo.value)

    def test_or_at_256_a_non_string_session_id_is_refused(self):
        """`or@256`: the other half -- a non-string session id."""
        with pytest.raises(AuditInputError) as excinfo:
            SessionLog(session_id=None, records=())  # type: ignore[arg-type]
        assert "non-empty string" in str(excinfo.value)

    # -- or@264: the end reason guard -----------------------------------
    def test_or_at_264_a_whitespace_end_reason_is_refused(self):
        """`or@264`: a str that is blank -- only the emptiness half refuses."""
        with pytest.raises(AuditInputError) as excinfo:
            SessionLog(session_id="s", records=(), end_reason="   ")
        assert "non-empty string when present" in str(excinfo.value)

    def test_or_at_264_a_non_string_end_reason_is_refused(self):
        """`or@264`: the other half -- a non-string end reason."""
        with pytest.raises(AuditInputError) as excinfo:
            SessionLog(session_id="s", records=(), end_reason=123)  # type: ignore[arg-type]
        assert "non-empty string when present" in str(excinfo.value)


class TestMutantStdlibOnly:
    """The four faults inside ``stdlib_only()`` (design doc 3.1 / 3.3)."""

    # -- retT@579: the final `return True` ------------------------------
    def test_retT_at_579_a_stdlib_only_module_reports_true(self):
        """`retT@579`: the module's own answer, asserted as True ITSELF.

        ``assertIs(..., True)`` -- not ``assertTrue`` -- so a falsy or
        non-boolean answer cannot satisfy it.  The control is the module
        itself: it imports stdlib modules only.
        """
        assert _coverage_manifest.stdlib_only() is True

    # -- and@577: the `node.module and ...` half ------------------------
    def test_and_at_577_a_relative_import_does_not_break_the_stdlib_check(self, tmp_path):
        """`and@577`: the half of the guard that skips a relative import.

        The line is ``if node.module and node.module.split(".")[0] not in
        allowed:``.  A relative import (``from . import x``) has
        ``node.module is None``: the original short-circuits and skips
        it, the mutant evaluates ``None.split(...)`` and raises.  The
        import is placed in a function body so the COPY can be executed
        without a package context; ``ast.walk`` still sees it.
        """
        with _variant_module(
            tmp_path, "\n\ndef _never_called():\n    from . import x\n", "relimport"
        ) as module:
            assert module.stdlib_only() is True

    # -- retF@575: the plain-import arm --------------------------------
    def test_retF_at_575_a_non_stdlib_import_is_reported(self, tmp_path):
        """`retF@575`: the ``return False`` on the plain-import arm.

        The module's own imports are all stdlib, so the arm never fires
        on the module itself.  A COPY carrying one non-stdlib import
        (``import os`` -- not in the allowed set) does fire it: the
        original answers False, the mutant answers True.  The control
        pins the answer as False ITSELF.
        """
        with _variant_module(tmp_path, "\n\nimport os\n", "badimport") as module:
            assert module.stdlib_only() is False

    # -- retF@578: the from-import arm ---------------------------------
    def test_retF_at_578_a_non_stdlib_from_import_is_reported(self, tmp_path):
        """`retF@578`: the ``return False`` on the ``from ... import`` arm.

        A COPY carrying ``from os import path`` reaches that arm; the
        original answers False, the mutant answers True.  The copy
        carries NO plain non-stdlib import, so the arm under test is the
        one that is reached.
        """
        with _variant_module(tmp_path, "\n\nfrom os import path\n", "badfrom") as module:
            assert module.stdlib_only() is False


class TestMutantMainSelfCheck:
    """The four faults inside ``main()`` and the script guard.

    ``main()`` is only reachable as a SCRIPT, so the script-side faults
    are observed by running the module as a subprocess.
    """

    # -- and@590: the clean-log assertion ------------------------------
    def test_and_at_590_the_self_check_fails_when_the_log_does_not_cover(self, monkeypatch):
        """`and@590`: the assertion that the clean log covers the manifest.

        The line is ``assert report.structure_ok and report.coverage_ok
        and report.covered``.  The mutant makes it ``or``, so it accepts
        a report that does not cover.  The self-check is fed a log that
        is internally consistent but missing an event -- the whole point
        of the module -- so the original refuses and the mutant sails
        on.  The control: on the unpatched path the self-check passes.
        """
        module = _coverage_manifest
        # -- the control: the pristine self-check passes ----------------
        module.main()

        manifest = module.build_manifest(
            "session-1", ["session.start", "tool.read", "tool.write", "session.end"]
        )
        gapped = module.synthesize_log_with_gap(manifest, "tool.write", end_reason="task complete")
        monkeypatch.setattr(module, "synthesize_log", lambda *args, **kwargs: gapped)
        with pytest.raises(AssertionError):
            module.main()

    # -- and@594: the gap assertion ------------------------------------
    def test_and_at_594_the_self_check_fails_when_the_gap_is_not_the_one_it_claims(
        self, monkeypatch
    ):
        """`and@594`: the assertion that the gap is the claimed one.

        The line is ``assert report.structure_ok and not report.coverage_ok``.
        The mutant makes it ``or``, so a report that is neither
        structurally sound nor coverage-complete is accepted.  The
        self-check is given a log with an orphan row AND a missing
        event: the original refuses, the mutant accepts.
        """
        module = _coverage_manifest
        # -- the control: the pristine self-check passes ----------------
        module.main()

        broken = module.SessionLog(
            session_id="session-1",
            records=(
                module.LogRecord(seq=1, event_id="session.start"),
                module.LogRecord(seq=2, event_id="tool.read"),
                module.LogRecord(seq=4, event_id="session.end"),
            ),
            end_reason="task complete",
        )
        monkeypatch.setattr(
            module, "synthesize_log_with_gap", lambda *args, **kwargs: broken
        )
        with pytest.raises(AssertionError):
            module.main()

    # -- eq@595: the missing-event assertion ---------------------------
    def test_eq_at_595_the_script_self_check_passes(self):
        """`eq@595`: ``assert report.missing_event_ids == ("tool.write",)``.

        The mutant flips ``==`` to ``!=``, so the script-mode self-check
        fails and the module exits non-zero.  Running the module as a
        script is the only way to reach it.
        """
        result = _run_module_as_script()
        assert result.returncode == 0, result.stdout
        assert SELF_CHECK_BANNER in result.stdout

    # -- eq@605: the `__name__ == "__main__"` guard ---------------------
    def test_eq_at_605_importing_the_module_does_not_run_the_self_check(self):
        """`eq@605`: importing the module must NOT run the self-check.

        The mutant flips the guard to ``!=``, so an IMPORT runs
        ``main()`` and prints the banner.  The module is imported in a
        fresh interpreter so the observation is not confused with this
        test process's own import.
        """
        result = _import_module_in_subprocess()
        assert result.returncode == 0, result.stdout
        assert SELF_CHECK_BANNER not in result.stdout

    def test_eq_at_605_running_the_module_as_a_script_runs_the_self_check(self):
        """`eq@605`: the other direction -- a SCRIPT does run the self-check.

        This is the control for the test above, and it kills the mutant
        too: with the guard flipped, a script run prints nothing.
        """
        result = _run_module_as_script()
        assert result.returncode == 0, result.stdout
        assert SELF_CHECK_BANNER in result.stdout



