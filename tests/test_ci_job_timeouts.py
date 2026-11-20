"""CI job timeouts: every job in the CI workflow must declare one.

A GitHub Actions job without an explicit ``timeout-minutes`` inherits the
platform default of **360 minutes**.  A step that hangs therefore burns
six hours of CI before the job is cancelled and anything is reported.

The rule pinned here:

> **Every CI job declares a timeout.**

The detector lives in ``tests/ci_job_timeouts.py`` rather than in this
file, for the same reason ``tests/py_modules_guard.py``,
``tests/ci_compile_coverage.py`` and ``tests/install_smoke_coverage.py``
do:  the mutant probe mutates a MODULE and reruns the slice's tests, and
a test file is excluded from the probe by name.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is not a repo dependency
    yaml = None

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import ci_job_timeouts  # noqa: E402

#: The jobs the workflow is expected to declare.  A job that disappears
#: from the workflow must not silently stop being guarded.
EXPECTED_JOBS = [
    "egress-sidecar",
    "test",
    "agent-runtime",
    "documentation",
]


class CiJobTimeoutTests(unittest.TestCase):
    """The rule, against the REAL workflow."""

    def test_every_job_declares_a_timeout(self):
        missing = ci_job_timeouts.jobs_without_timeout()
        self.assertEqual(
            missing,
            [],
            "these CI jobs declare no timeout-minutes, so a hanging step "
            "runs for GitHub's 360-minute default before the job is "
            "cancelled: %s" % ", ".join(missing),
        )

    def test_the_expected_jobs_are_still_present(self):
        names = ci_job_timeouts.job_names()
        for job in EXPECTED_JOBS:
            with self.subTest(job=job):
                self.assertIn(job, names)

    def test_no_job_declares_a_nonsensical_timeout(self):
        bad = ci_job_timeouts.jobs_with_nonsensical_timeout()
        self.assertEqual(
            bad,
            [],
            "a job's timeout-minutes must be a positive number of minutes: %s"
            % ", ".join(bad),
        )

    def test_the_workflow_declares_at_least_the_expected_jobs(self):
        # A scan that stopped finding jobs would pass vacuously.
        self.assertGreaterEqual(
            len(ci_job_timeouts.job_names()),
            len(EXPECTED_JOBS),
        )

    @unittest.skipIf(yaml is None, "PyYAML is not installed")
    def test_the_detector_agrees_with_a_real_yaml_parser(self):
        # The detector reads the workflow with its own indentation-aware
        # reader, because the workflow's indentation is not uniform and a
        # step-level `timeout-minutes` must not be read as a job-level
        # one.  A real YAML parser is an INDEPENDENT implementation of
        # the same question, so agreement between the two is evidence the
        # reader is right rather than merely self-consistent.
        with ci_job_timeouts.WORKFLOW.open(encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        parsed = {
            name: job.get("timeout-minutes")
            for name, job in document["jobs"].items()
        }
        self.assertEqual(ci_job_timeouts.job_timeout(), parsed)

    @unittest.skipIf(yaml is None, "PyYAML is not installed")
    def test_the_detector_agrees_with_a_real_yaml_parser_on_step_counts(self):
        with ci_job_timeouts.WORKFLOW.open(encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        parsed = {
            name: len(job.get("steps", []))
            for name, job in document["jobs"].items()
        }
        self.assertEqual(ci_job_timeouts.job_step_count(), parsed)

    def test_the_slowest_job_has_a_limit_above_its_measured_workload(self):
        # The agent-runtime job's measured workload on this host is about
        # 13 minutes (a 21,352-test pytest suite plus the 13-guard
        # invariant verification).  The limit must be well above it, so a
        # slower runner cannot produce a false failure, and well below
        # GitHub's 360-minute default, so a hang is bounded.
        timeouts = ci_job_timeouts.effective_timeout()
        self.assertIn("agent-runtime", timeouts)
        limit = timeouts["agent-runtime"]
        self.assertGreater(
            limit,
            13,
            "the agent-runtime job's limit of %d minutes is at or below its "
            "measured workload of about 13 minutes" % limit,
        )
        self.assertLess(
            limit,
            ci_job_timeouts.GITHUB_DEFAULT_TIMEOUT_MINUTES,
            "the agent-runtime job's limit must be below GitHub's "
            "360-minute default, or it does not bound anything",
        )


class GuardUnitTests(unittest.TestCase):
    """The detector against CRAFTED workflows.

    The repository-wide checks read the REAL workflow, which -- once the
    fix lands -- declares a timeout everywhere.  On their own they cannot
    tell a working detector from one that never fires.
    """

    def test_a_job_without_a_timeout_is_named(self):
        workflow = (
            "jobs:\n"
            "  fast:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo hi\n"
            "  slow:\n"
            "    runs-on: ubuntu-latest\n"
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - run: echo hi\n"
        )
        self.assertEqual(ci_job_timeouts.jobs_without_timeout(workflow), ["fast"])

    def test_a_timeout_belongs_to_its_own_job(self):
        # A timeout declared in one job must not be attributed to another:
        # the naive implementation reads the whole file for the key.
        workflow = (
            "jobs:\n"
            "  first:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo hi\n"
            "  second:\n"
            "    runs-on: ubuntu-latest\n"
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - run: echo hi\n"
        )
        timeouts = ci_job_timeouts.job_timeout(workflow)
        self.assertIsNone(timeouts["first"])
        self.assertEqual(timeouts["second"], 30)

    def test_a_job_without_a_timeout_inherits_the_platform_default(self):
        workflow = (
            "jobs:\n"
            "  only:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo hi\n"
        )
        self.assertEqual(
            ci_job_timeouts.effective_timeout(workflow),
            {"only": ci_job_timeouts.GITHUB_DEFAULT_TIMEOUT_MINUTES},
        )

    def test_a_zero_or_negative_timeout_is_nonsensical(self):
        workflow = (
            "jobs:\n"
            "  zero:\n"
            "    timeout-minutes: 0\n"
            "    steps:\n"
            "      - run: echo hi\n"
            "  negative:\n"
            "    timeout-minutes: -5\n"
            "    steps:\n"
            "      - run: echo hi\n"
            "  fine:\n"
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - run: echo hi\n"
        )
        self.assertEqual(
            sorted(ci_job_timeouts.jobs_with_nonsensical_timeout(workflow)),
            ["negative", "zero"],
        )

    def test_a_step_level_timeout_does_not_count_as_a_job_timeout(self):
        # GitHub allows `timeout-minutes` on a step too.  A step-level
        # value must not be mistaken for the job's bound: the job would
        # still run its other steps unbounded.
        workflow = (
            "jobs:\n"
            "  job:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo hi\n"
            "        timeout-minutes: 5\n"
        )
        self.assertEqual(ci_job_timeouts.jobs_without_timeout(workflow), ["job"])

    def test_the_scan_counts_a_jobs_steps(self):
        workflow = (
            "jobs:\n"
            "  job:\n"
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - name: one\n"
            "        run: echo hi\n"
            "      - name: two\n"
            "        run: echo hi\n"
            "      - uses: actions/checkout@v4\n"
        )
        self.assertEqual(ci_job_timeouts.job_step_count(workflow), {"job": 3})

    def test_a_workflow_with_no_jobs_yields_no_missing_timeouts(self):
        workflow = "name: nothing\non: push\n"
        self.assertEqual(ci_job_timeouts.jobs_without_timeout(workflow), [])


class GuardSecondHalfTests(unittest.TestCase):
    """The SECOND half of each guard in ``ci_job_timeouts``.

    Two guards, each with two halves, and the slice's own suite drove
    only one half of each:

      gt@146   ``line.strip() and _indent_of(line) > indent``
      and@146  ... the "is deeper" half
      and@216  ``_indent_of(line) == child_indent and
               line.strip() == "steps:"``

    ``gt@146`` finds a job's own keys: the lines DEEPER than the job
    header.  The slice's suite drove the "not blank" half only, so the
    planted fault ``gt@146`` (``>`` -> ``>=``) SURVIVED it -- with the
    comparison weakened, a line at the job's OWN indentation would be
    counted as deeper, and the job's own key would be mistaken for a
    nested one.

    ``and@216`` finds a job's ``steps:`` key.  The slice's suite drove
    the "is at the child indent" half only, so ``and@216``
    (``and`` -> ``or``) SURVIVED it -- with the connective flipped, a
    ``steps:`` key at ANY indentation would be accepted, so a nested
    mapping's own ``steps:`` would be read as the job's.
    """

    # A job followed by a SIBLING key at the job's own indentation.
    # The sibling is not part of the job, but it is inside the job's
    # body region -- so the region's "deeper than the header" test has
    # to exclude it, and the job's own key must still be found.
    _SIBLING_AFTER_JOB = (
        "jobs:\n"
        "  job:\n"
        "    timeout-minutes: 30\n"
        "    steps:\n"
        "      - run: echo hi\n"
        "  env: global-value\n"
    )

    # A job with a NESTED mapping that has its own `steps:` key, before
    # the job's own `steps:` key.
    _NESTED_STEPS = (
        "jobs:\n"
        "  job:\n"
        "    timeout-minutes: 30\n"
        "    env:\n"
        "      steps:\n"
        "        - name: inner\n"
        "          run: echo inner\n"
        "        - name: inner2\n"
        "          run: echo inner2\n"
        "    steps:\n"
        "      - name: outer\n"
        "        run: echo outer\n"
    )

    def test_a_job_with_a_sibling_key_still_finds_its_own_timeout(self):
        """`gt@146`: the "is deeper" half.

        A job's body region can contain a line at the job's OWN
        indentation -- a sibling key that follows the job.  That line
        is NOT deeper than the header, so it must not be counted as a
        nested key; and the job's own ``timeout-minutes``, which IS
        deeper, must still be found.

        With `> -> >=` the sibling counts as deeper, so the shallowest
        "deeper" line becomes the sibling's indentation rather than
        the job's, and the job's own key is missed: the job reads as
        having no timeout at all.
        """
        timeouts = ci_job_timeouts.job_timeout(self._SIBLING_AFTER_JOB)
        self.assertEqual(timeouts["job"], 30)
        self.assertEqual(
            ci_job_timeouts.jobs_without_timeout(self._SIBLING_AFTER_JOB), []
        )

    def test_a_job_with_no_timeout_at_all_is_still_named(self):
        """`gt@146`: the control -- nothing there means nothing there."""
        workflow = (
            "jobs:\n"
            "  job:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo hi\n"
        )
        self.assertEqual(ci_job_timeouts.jobs_without_timeout(workflow), ["job"])

    def test_a_nested_mapping_steps_key_is_not_the_jobs_steps_key(self):
        """`and@216`: the "is at the child indent" half.

        The job's ``steps:`` key sits at the job's child indentation.  A
        ``steps:`` key inside a NESTED mapping sits deeper, and it is
        that mapping's key -- reading it as the job's would count the
        nested steps and miss the job's own.

        With `and -> or` the nested ``steps:`` is accepted first, so
        the job's own steps are never found.
        """
        counts = ci_job_timeouts.job_step_count(self._NESTED_STEPS)
        self.assertEqual(counts["job"], 1)

    def test_the_jobs_own_steps_key_is_found_when_there_is_no_nesting(self):
        """`and@216`: the control -- a plain job's steps are counted."""
        workflow = (
            "jobs:\n"
            "  job:\n"
            "    timeout-minutes: 30\n"
            "    steps:\n"
            "      - name: one\n"
            "        run: echo hi\n"
            "      - name: two\n"
            "        run: echo hi\n"
        )
        self.assertEqual(ci_job_timeouts.job_step_count(workflow), {"job": 2})


if __name__ == "__main__":
    unittest.main()
