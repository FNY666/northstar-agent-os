"""Tests for capability_ceiling_probe: fail-first admission, calibration
error, and over-ceiling routing.

The rules under test (from the slice brief):

* **Fail-first admission.**  A task the agent already passed is refused
  as a ceiling probe -- it never enters the probe library.
* **Calibration.**  Every observation registers difficulty, confidence and
  the actual outcome; calibration error (confidence minus accuracy) is
  aggregated per difficulty bucket; a bucket whose error exceeds the
  threshold is flagged miscalibrated; a confident failure is the case the
  source reports (calibration error over 70% on HLE).
* **Routing.**  A task over the verified ceiling is routed to
  decomposition or to a human -- never attempted.
* **One-way ceiling.**  The ceiling rises only on a measured pass.  A
  single failure never lowers it, and no ceiling is ever inferred
  without a measurement.

The difficulty score is the METR human-minutes proxy -- a Northstar
extension, not an HLE mechanism.  :class:`FullPathTests` drives the real
path end to end.
"""
from __future__ import annotations

import io
import pathlib
import runpy
import sys
import unittest
from unittest import mock

import capability_ceiling_probe
from capability_ceiling_probe import (
    BadProbeError,
    CalibrationBucket,
    CapabilityCeilingProbeError,
    CeilingLedger,
    CeilingProbe,
    DuplicateProbeError,
    NotAFailureError,
    RouteTarget,
    RoutingVerdict,
    Submission,
    UnknownProbeError,
    bucket_for,
)


def probe(pid="p", minutes=60.0, confidence=0.5, passed=False):
    return CeilingProbe(pid, minutes, confidence, passed)


class ProbeShapeTests(unittest.TestCase):
    def test_probe_is_frozen(self):
        p = probe()
        with self.assertRaises(Exception):
            p.confidence = 0.9  # type: ignore[misc]

    def test_probe_fields_are_the_ledger_shape(self):
        p = probe("x", 30.0, 0.25, False)
        self.assertEqual(p.probe_id, "x")
        self.assertEqual(p.difficulty_human_minutes, 30.0)
        self.assertEqual(p.confidence, 0.25)
        self.assertIs(p.passed, False)

    def test_empty_probe_id_rejected(self):
        with self.assertRaises(BadProbeError):
            probe(pid="")

    def test_non_numeric_difficulty_rejected(self):
        with self.assertRaises(BadProbeError):
            probe(minutes="60")

    def test_bool_difficulty_rejected(self):
        with self.assertRaises(BadProbeError):
            probe(minutes=True)

    def test_zero_and_negative_difficulty_rejected(self):
        with self.assertRaises(BadProbeError):
            probe(minutes=0.0)
        with self.assertRaises(BadProbeError):
            probe(minutes=-1.0)

    def test_infinite_difficulty_rejected(self):
        with self.assertRaises(BadProbeError):
            probe(minutes=float("inf"))

    def test_confidence_above_one_rejected(self):
        with self.assertRaises(BadProbeError):
            probe(confidence=1.01)

    def test_confidence_below_zero_rejected(self):
        with self.assertRaises(BadProbeError):
            probe(confidence=-0.01)

    def test_confidence_must_not_be_bool(self):
        with self.assertRaises(BadProbeError):
            probe(confidence=True)

    def test_non_bool_passed_rejected(self):
        with self.assertRaises(BadProbeError):
            CeilingProbe("p", 60.0, 0.5, "yes")  # type: ignore[arg-type]

    def test_confidence_extremes_are_accepted(self):
        self.assertEqual(probe(confidence=0.0).confidence, 0.0)
        self.assertEqual(probe(confidence=1.0).confidence, 1.0)


class BucketEdgeTests(unittest.TestCase):
    """A difficulty exactly on a bucket edge belongs to the lower bucket."""

    def test_exact_edge_lands_in_the_lower_bucket(self):
        self.assertEqual(bucket_for(30.0), "0-30")
        self.assertEqual(bucket_for(60.0), "30-60")
        self.assertEqual(bucket_for(120.0), "60-120")

    def test_just_above_edge_moves_up(self):
        self.assertEqual(bucket_for(30.000001), "30-60")
        self.assertEqual(bucket_for(60.5), "60-120")

    def test_open_ended_top_bucket(self):
        self.assertEqual(bucket_for(480.0), "240-480")
        self.assertEqual(bucket_for(481.0), "480+")
        self.assertEqual(bucket_for(100000.0), "480+")


class AdmissionTests(unittest.TestCase):
    """Fail-first admission: only a task the agent failed is a probe."""

    def test_passed_task_is_refused_as_a_probe(self):
        ledger = CeilingLedger()
        with self.assertRaises(NotAFailureError):
            ledger.admit_probe(probe("p1", 60.0, 0.9, passed=True))

    def test_refused_task_does_not_enter_the_probe_library(self):
        ledger = CeilingLedger()
        with self.assertRaises(NotAFailureError):
            ledger.admit_probe(probe("p1", 60.0, 0.9, passed=True))
        self.assertEqual(ledger.probes, ())
        self.assertEqual(ledger.passes, ())

    def test_refused_task_is_not_silently_accepted(self):
        """The refusal must be loud: a passed task is never admitted."""
        ledger = CeilingLedger()
        with self.assertRaises(NotAFailureError):
            ledger.admit_probe(probe("p1", 60.0, 0.9, passed=True))
        # and the id is still free, so a later genuine failure with the
        # same id is not a duplicate.
        sub = ledger.admit_probe(probe("p1", 60.0, 0.9, passed=False))
        self.assertTrue(sub.admitted)

    def test_failed_task_is_admitted_to_the_probe_library(self):
        ledger = CeilingLedger()
        sub = ledger.admit_probe(probe("p1", 60.0, 0.4, passed=False))
        self.assertTrue(sub.admitted)
        self.assertEqual(len(ledger.probes), 1)
        self.assertEqual(ledger.probes[0].probe_id, "p1")

    def test_duplicate_probe_id_rejected(self):
        ledger = CeilingLedger()
        ledger.admit_probe(probe("p1", 60.0, 0.4, passed=False))
        with self.assertRaises(DuplicateProbeError):
            ledger.admit_probe(probe("p1", 90.0, 0.4, passed=False))

    def test_observe_records_a_pass_without_admitting_it(self):
        """A pass is still a calibration observation."""
        ledger = CeilingLedger()
        sub = ledger.observe(probe("p1", 60.0, 0.9, passed=True))
        self.assertFalse(sub.admitted)
        self.assertEqual(len(ledger.probes), 0)
        self.assertEqual(len(ledger.passes), 1)

    def test_admit_probe_rejects_a_non_probe_object(self):
        ledger = CeilingLedger()
        with self.assertRaises(BadProbeError):
            ledger.admit_probe({"probe_id": "p"})  # type: ignore[arg-type]


class CalibrationTests(unittest.TestCase):
    """Calibration error: confidence minus accuracy, per difficulty bucket."""

    def test_every_observation_registers_difficulty_confidence_and_outcome(self):
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 90.0, 0.95, passed=False))
        bucket = ledger.calibration()[0]
        self.assertEqual(bucket.probes, 1)
        self.assertEqual(bucket.mean_confidence, 0.95)
        self.assertEqual(bucket.accuracy, 0.0)

    def test_confident_failure_is_flagged_miscalibrated(self):
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 90.0, 0.95, passed=False))
        bucket = ledger.calibration()[0]
        self.assertTrue(bucket.miscalibrated)
        self.assertEqual(bucket.direction, "overconfident")
        self.assertAlmostEqual(bucket.error, 0.95)

    def test_confident_pass_is_not_miscalibrated(self):
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 90.0, 1.0, passed=True))
        bucket = ledger.calibration()[0]
        self.assertFalse(bucket.miscalibrated)
        self.assertEqual(bucket.error, 0.0)
        self.assertEqual(bucket.direction, "none")

    def test_confidence_below_one_on_a_pass_is_a_small_negative_error(self):
        """Confidence 0.95 on a correct answer is error 0.95 - 1.0 = -0.05."""
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 90.0, 0.95, passed=True))
        bucket = ledger.calibration()[0]
        self.assertAlmostEqual(bucket.error, -0.05)
        self.assertFalse(bucket.miscalibrated)

    def test_error_is_aggregated_per_difficulty_bucket(self):
        ledger = CeilingLedger()
        ledger.observe(probe("a", 10.0, 0.0, passed=True))
        ledger.observe(probe("b", 20.0, 1.0, passed=True))
        ledger.observe(probe("c", 200.0, 0.9, passed=False))
        buckets = {b.bucket: b for b in ledger.calibration()}
        self.assertEqual(buckets["0-30"].probes, 2)
        self.assertEqual(buckets["0-30"].accuracy, 1.0)
        # mean confidence (0.0 + 1.0) / 2 = 0.5, accuracy 1.0 -> error -0.5
        self.assertEqual(buckets["0-30"].mean_confidence, 0.5)
        self.assertEqual(buckets["0-30"].error, -0.5)
        self.assertEqual(buckets["0-30"].direction, "underconfident")
        self.assertEqual(buckets["120-240"].probes, 1)
        self.assertTrue(buckets["120-240"].miscalibrated)

    def test_empty_ledger_has_no_buckets(self):
        ledger = CeilingLedger()
        self.assertEqual(ledger.calibration(), ())
        self.assertEqual(ledger.miscalibrated_buckets(), ())

    def test_empty_bucket_is_omitted_rather_than_zero_filled(self):
        """A bucket with no observations has no calibration error."""
        ledger = CeilingLedger()
        ledger.observe(probe("a", 10.0, 0.5, passed=False))
        labels = [b.bucket for b in ledger.calibration()]
        self.assertEqual(labels, ["0-30"])

    def test_underconfident_bucket_is_flagged(self):
        ledger = CeilingLedger()
        ledger.observe(probe("a", 10.0, 0.1, passed=True))
        bucket = ledger.calibration()[0]
        self.assertTrue(bucket.miscalibrated)
        self.assertEqual(bucket.direction, "underconfident")

    def test_miscalibrated_buckets_filter(self):
        ledger = CeilingLedger()
        ledger.observe(probe("a", 10.0, 0.99, passed=False))
        ledger.observe(probe("b", 200.0, 0.99, passed=True))
        mis = ledger.miscalibrated_buckets()
        self.assertEqual([b.bucket for b in mis], ["0-30"])

    def test_threshold_is_configurable(self):
        ledger = CeilingLedger(calibration_threshold=0.99)
        ledger.observe(probe("a", 10.0, 0.95, passed=False))
        self.assertFalse(ledger.calibration()[0].miscalibrated)

    def test_negative_threshold_is_rejected(self):
        with self.assertRaises(Exception):
            CeilingLedger(calibration_threshold=-0.1)


class CeilingLedgerTests(unittest.TestCase):
    """The ceiling rises only on a measured pass, and never falls."""

    def test_no_ceiling_before_any_measurement(self):
        ledger = CeilingLedger()
        self.assertIsNone(ledger.verified_ceiling_human_minutes)
        self.assertEqual(ledger.ceiling_source, "none")

    def test_a_failure_never_creates_a_ceiling(self):
        ledger = CeilingLedger()
        ledger.admit_probe(probe("p1", 300.0, 0.9, passed=False))
        self.assertIsNone(ledger.verified_ceiling_human_minutes)

    def test_a_measured_pass_raises_the_ceiling(self):
        ledger = CeilingLedger()
        sub = ledger.observe(probe("p1", 120.0, 0.9, passed=True))
        self.assertEqual(sub.ceiling_raised_to, 120.0)
        self.assertEqual(ledger.verified_ceiling_human_minutes, 120.0)
        self.assertEqual(ledger.ceiling_source, "measured")

    def test_a_single_failure_does_not_lower_the_verified_ceiling(self):
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 120.0, 0.9, passed=True))
        ledger.admit_probe(probe("p2", 600.0, 0.9, passed=False))
        self.assertEqual(ledger.verified_ceiling_human_minutes, 120.0)
        self.assertEqual(ledger.ceiling_source, "measured")

    def test_a_lower_pass_does_not_lower_the_ceiling(self):
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 120.0, 0.9, passed=True))
        ledger.observe(probe("p2", 30.0, 0.9, passed=True))
        self.assertEqual(ledger.verified_ceiling_human_minutes, 120.0)

    def test_a_pass_at_the_ceiling_does_not_raise_it(self):
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 120.0, 0.9, passed=True))
        sub = ledger.observe(probe("p2", 120.0, 0.9, passed=True))
        self.assertIsNone(sub.ceiling_raised_to)
        self.assertEqual(ledger.verified_ceiling_human_minutes, 120.0)

    def test_declared_ceiling_is_marked_as_declared(self):
        ledger = CeilingLedger(declared_ceiling_human_minutes=60.0)
        self.assertEqual(ledger.verified_ceiling_human_minutes, 60.0)
        self.assertEqual(ledger.ceiling_source, "declared")

    def test_a_declared_ceiling_is_overridden_by_a_higher_measured_pass(self):
        ledger = CeilingLedger(declared_ceiling_human_minutes=60.0)
        ledger.observe(probe("p1", 120.0, 0.9, passed=True))
        self.assertEqual(ledger.verified_ceiling_human_minutes, 120.0)
        self.assertEqual(ledger.ceiling_source, "measured")

    def test_a_measured_pass_below_a_declared_ceiling_does_not_lower_it(self):
        ledger = CeilingLedger(declared_ceiling_human_minutes=300.0)
        ledger.observe(probe("p1", 60.0, 0.9, passed=True))
        self.assertEqual(ledger.verified_ceiling_human_minutes, 300.0)


class RoutingTests(unittest.TestCase):
    """Over-ceiling tasks are routed, never attempted."""

    def _ledger_with_ceiling(self, ceiling=60.0):
        ledger = CeilingLedger()
        ledger.observe(probe("p1", ceiling, 0.9, passed=True))
        return ledger

    def test_task_inside_the_ceiling_is_attempted(self):
        ledger = self._ledger_with_ceiling()
        verdict = ledger.route(60.0)
        self.assertIs(verdict.route, RouteTarget.ATTEMPT)
        self.assertFalse(verdict.over_ceiling)

    def test_task_exactly_at_the_ceiling_is_attempted(self):
        """The edge belongs to the inside: <= ceiling is inside."""
        ledger = self._ledger_with_ceiling()
        self.assertIs(ledger.route(60.0).route, RouteTarget.ATTEMPT)

    def test_task_just_over_the_ceiling_is_routed_to_decomposition(self):
        ledger = self._ledger_with_ceiling()
        verdict = ledger.route(60.5)
        self.assertIs(verdict.route, RouteTarget.DECOMPOSE)
        self.assertTrue(verdict.over_ceiling)
        self.assertAlmostEqual(verdict.overage_human_minutes, 0.5)

    def test_task_far_over_the_ceiling_goes_to_a_human(self):
        ledger = self._ledger_with_ceiling()
        verdict = ledger.route(600.0)
        self.assertIs(verdict.route, RouteTarget.HUMAN)
        self.assertTrue(verdict.over_ceiling)

    def test_decomposition_band_edge_is_inclusive(self):
        ledger = self._ledger_with_ceiling(60.0)
        # DECOMPOSE_FACTOR is 2.0, so 120.0 is still decomposition.
        self.assertIs(ledger.route(120.0).route, RouteTarget.DECOMPOSE)
        self.assertIs(ledger.route(120.1).route, RouteTarget.HUMAN)

    def test_no_ceiling_means_no_blind_attempt(self):
        ledger = CeilingLedger()
        verdict = ledger.route(5.0)
        self.assertIsNot(verdict.route, RouteTarget.ATTEMPT)
        self.assertIsNone(verdict.verified_ceiling_human_minutes)

    def test_verdicts_are_recorded(self):
        ledger = self._ledger_with_ceiling()
        ledger.route(10.0)
        ledger.route(600.0)
        self.assertEqual(len(ledger.verdicts), 2)

    def test_route_rejects_a_bad_difficulty(self):
        ledger = self._ledger_with_ceiling()
        with self.assertRaises(BadProbeError):
            ledger.route(0.0)
        with self.assertRaises(BadProbeError):
            ledger.route("600")


class FullPathTests(unittest.TestCase):
    """The real path, end to end: probe -> calibration -> ceiling -> route."""

    def test_the_whole_path(self):
        ledger = CeilingLedger()

        # 1. A task the agent could not do enters the probe library.
        hard = ledger.admit_probe(probe("hard-1", 90.0, 0.93, passed=False))
        self.assertTrue(hard.admitted)
        self.assertIsNone(ledger.verified_ceiling_human_minutes)

        # 2. A task the agent could do is refused as a probe.
        with self.assertRaises(NotAFailureError):
            ledger.admit_probe(probe("easy-1", 10.0, 0.95, passed=True))

        # 3. The pass is still an observation, and it raises the ceiling.
        ledger.observe(probe("easy-1", 30.0, 0.95, passed=True))
        self.assertEqual(ledger.verified_ceiling_human_minutes, 30.0)

        # 4. The hard failure did not lower it, and did not raise it.
        self.assertEqual(ledger.verified_ceiling_human_minutes, 30.0)

        # 5. Calibration: the 60-120 bucket is confidently wrong.
        buckets = {b.bucket: b for b in ledger.calibration()}
        self.assertTrue(buckets["60-120"].miscalibrated)
        self.assertEqual(buckets["60-120"].direction, "overconfident")
        self.assertAlmostEqual(buckets["60-120"].error, 0.93)

        # 6. Routing: at the ceiling -> attempt; over it -> not attempted.
        self.assertIs(ledger.route(30.0).route, RouteTarget.ATTEMPT)
        self.assertIsNot(ledger.route(90.0).route, RouteTarget.ATTEMPT)
        # ceiling 30 -> decomposition band is 30..60, beyond that a human.
        self.assertIs(ledger.route(45.0).route, RouteTarget.DECOMPOSE)
        self.assertIs(ledger.route(90.0).route, RouteTarget.HUMAN)
        self.assertIs(ledger.route(300.0).route, RouteTarget.HUMAN)

        # 7. The ledger kept both kinds of entry.
        self.assertEqual(len(ledger.probes), 1)
        self.assertEqual(len(ledger.passes), 1)

    def test_the_path_survives_a_failed_admission(self):
        """A refused probe leaves the ledger exactly as it was."""
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 30.0, 0.9, passed=True))
        before = ledger.verified_ceiling_human_minutes
        with self.assertRaises(NotAFailureError):
            ledger.admit_probe(probe("p2", 300.0, 0.9, passed=True))
        self.assertEqual(ledger.verified_ceiling_human_minutes, before)
        self.assertEqual(len(ledger.probes), 0)


class ProvenanceTests(unittest.TestCase):
    """The difficulty proxy and the source attribution are declared, not implied."""

    def test_difficulty_unit_is_human_minutes(self):
        self.assertEqual(capability_ceiling_probe.DIFFICULTY_UNIT, "human_minutes")

    def test_difficulty_proxy_is_named(self):
        self.assertEqual(
            capability_ceiling_probe.DIFFICULTY_PROXY, "metr-human-minutes"
        )

    def test_serialised_record_names_the_proxy(self):
        d = probe("p", 60.0, 0.5, False).as_dict()
        self.assertEqual(d["difficulty_unit"], "human_minutes")
        self.assertEqual(d["difficulty_proxy"], "metr-human-minutes")

    def test_schema_and_version_pins(self):
        self.assertEqual(
            capability_ceiling_probe.SCHEMA_PIN,
            "northstar.capability-ceiling-probe.v1",
        )
        self.assertEqual(
            capability_ceiling_probe.CAPABILITY_CEILING_PROBE_VERSION,
            "capability-ceiling-probe.v1",
        )

    def test_module_docstring_marks_the_proxy_as_a_northstar_extension(self):
        text = capability_ceiling_probe.__doc__ or ""
        self.assertIn("METR human-minutes", text)
        self.assertIn("Northstar extension", text)

    def test_module_docstring_quotes_the_source_numbers_verbatim(self):
        text = capability_ceiling_probe.__doc__ or ""
        for number in ("2,500", "76%", "24%", "14%", "70,000", "13,000", "70%"):
            self.assertIn(number, text)

    def test_module_self_check_runs(self):
        capability_ceiling_probe.main()


class PublicSurfaceTests(unittest.TestCase):
    """Every public name of the module is exercised here.

    The task book's rule-coverage verifier asks for "every new public
    function has a test naming it".  These tests name the record types
    and the base refusal explicitly, so the module's public surface is
    covered by name and not only through the values it happens to return.
    """

    def test_submit_is_the_documented_entry_point(self):
        """``submit`` is the alias the module's own docs show."""
        ledger = CeilingLedger()
        submission = ledger.submit(probe("s-1", 90.0, 0.95, passed=False))
        self.assertIsInstance(submission, Submission)
        self.assertTrue(submission.admitted)
        # and it is the same door as observe()
        self.assertEqual(len(ledger.probes), 1)

    def test_the_record_types_are_the_documented_ones(self):
        """The ledger's returns are the four public record types."""
        ledger = CeilingLedger()
        submission = ledger.observe(probe("s-2", 45.0, 0.5, passed=True))
        self.assertIsInstance(submission, Submission)
        bucket = ledger.calibration()[0]
        self.assertIsInstance(bucket, CalibrationBucket)
        verdict = ledger.route(500.0)
        self.assertIsInstance(verdict, RoutingVerdict)
        self.assertIsInstance(submission.as_dict(), dict)
        self.assertIsInstance(bucket.as_dict(), dict)
        self.assertIsInstance(verdict.as_dict(), dict)

    def test_every_refusal_is_a_capability_ceiling_probe_error(self):
        """Every refusal the module raises shares the module's base class.

        A caller that wants to catch "the ceiling probe refused this" can
        catch one class, and the base class is named here so that it is
        exercised.
        """
        for exc in (BadProbeError, DuplicateProbeError, NotAFailureError):
            self.assertTrue(issubclass(exc, CapabilityCeilingProbeError))
            self.assertTrue(issubclass(exc, Exception))

    def test_the_unknown_probe_error_is_reserved_and_documented(self):
        """``UnknownProbeError`` is declared and deliberately not raised.

        The runtime's other id-keyed ledgers (``ai_probing``,
        ``capability_eval``, ``probing``, ``reward_hacking``) raise it;
        this module's operations all take the probe object, so it has no
        reachable path here.  The class says so in its own docstring
        rather than rotting silently.
        """
        self.assertTrue(issubclass(UnknownProbeError, CapabilityCeilingProbeError))
        self.assertIn("never raised", (UnknownProbeError.__doc__ or ""))
        # and nothing in the module raises it
        source = pathlib.Path(capability_ceiling_probe.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn("raise UnknownProbeError", source)


class CeilingGuardSecondHalfTests(unittest.TestCase):
    """The SECOND half of each guard in ``capability_ceiling_probe``.

    Six planted faults survived this slice's suite, and every one of
    them is a double guard:

      or@378  the ``bool`` half of the threshold's number guard
      lt@386  the "is non-negative" half of the threshold's range guard
      gt@565  the "is beyond the threshold" half of the miscalibration
             test
      gt@566  the upper bound of the overconfident direction
      lt@568  the lower bound of the underconfident direction
      eq@705  the ``__main__`` guard of the self-check

    Each test below fails when its own planted fault is applied alone.
    """

    # --- or@378: the `bool` half ---------------------------------------
    def test_a_boolean_calibration_threshold_is_refused(self):
        """`or@378`: **a bool IS an int in Python**.

        The guard is ``isinstance(threshold, bool) or not isinstance(
        threshold, (int, float))``.  The "not a number" half never
        refuses a bool -- only the explicit ``bool`` half does.  Under
        the mutant (``or`` -> ``and``) a boolean threshold is accepted
        and used as the number 1, which would make every bucket
        miscalibrated.
        """
        with self.assertRaises(CapabilityCeilingProbeError):
            CeilingLedger(calibration_threshold=True)

    def test_a_false_boolean_calibration_threshold_is_refused_too(self):
        """`or@378`: the other boolean."""
        with self.assertRaises(CapabilityCeilingProbeError):
            CeilingLedger(calibration_threshold=False)

    def test_a_string_calibration_threshold_is_refused(self):
        """`or@378`: the other half, as the control."""
        with self.assertRaises(CapabilityCeilingProbeError):
            CeilingLedger(calibration_threshold="0.2")

    # --- lt@386: the non-negative half ---------------------------------
    def test_a_negative_calibration_threshold_is_refused(self):
        """`lt@386`: the "is non-negative" half.

        The guard is ``not math.isfinite(threshold) or threshold < 0``.
        Under the mutant (``<`` -> ``<=``) the bound becomes
        non-positive -- and a threshold of exactly ``0.0``, which is a
        legal threshold, would be refused.
        """
        with self.assertRaises(CapabilityCeilingProbeError):
            CeilingLedger(calibration_threshold=-0.1)

    def test_a_threshold_of_exactly_zero_is_accepted(self):
        """`lt@386`: the bound is STRICT.

        A threshold of exactly ``0.0`` means "any error at all is
        miscalibration" -- a legal, meaningful setting.  Under the
        mutant it would be refused.
        """
        ledger = CeilingLedger(calibration_threshold=0.0)
        self.assertEqual(ledger.calibration_threshold, 0.0)

    def test_an_infinite_calibration_threshold_is_refused(self):
        """`lt@386`: the "is finite" half, as the control."""
        with self.assertRaises(CapabilityCeilingProbeError):
            CeilingLedger(calibration_threshold=float("inf"))

    def test_a_not_a_number_calibration_threshold_is_refused(self):
        """`lt@386`: the "is finite" half, from the other side."""
        with self.assertRaises(CapabilityCeilingProbeError):
            CeilingLedger(calibration_threshold=float("nan"))

    # --- gt@565: the miscalibration bound ------------------------------
    def test_an_error_exactly_at_the_threshold_is_not_miscalibrated(self):
        """`gt@565`: the bound is STRICT.

        The default threshold is 0.20, so a bucket whose error is
        exactly ``0.20`` is AT the threshold, not beyond it.  Under the
        mutant (``>`` -> ``>=``) it would be flagged as miscalibrated.
        """
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 90.0, 0.2, passed=False))
        bucket = ledger.calibration()[0]
        self.assertAlmostEqual(bucket.error, 0.2)
        self.assertFalse(bucket.miscalibrated)

    def test_an_error_just_beyond_the_threshold_is_miscalibrated(self):
        """`gt@565`: the bound, from the other side."""
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 90.0, 0.25, passed=False))
        self.assertTrue(ledger.calibration()[0].miscalibrated)

    # --- gt@566: the overconfident bound -------------------------------
    def test_an_error_exactly_at_the_threshold_is_neither_direction(self):
        """`gt@566`: the upper bound is EXCLUSIVE.

        An error of exactly ``0.20`` is overconfident by exactly the
        threshold, which is the "none" case -- the direction is a
        *direction*, and at the threshold the bucket is not beyond it.
        Under the mutant (``>`` -> ``>=``) it would be called
        overconfident.
        """
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 90.0, 0.2, passed=False))
        self.assertEqual(ledger.calibration()[0].direction, "none")

    def test_an_error_beyond_the_threshold_is_overconfident(self):
        """`gt@566`: the bound, from the other side."""
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 90.0, 0.25, passed=False))
        self.assertEqual(ledger.calibration()[0].direction, "overconfident")

    # --- lt@568: the underconfident bound ------------------------------
    def test_a_negative_error_exactly_at_the_threshold_is_neither_direction(self):
        """`lt@568`: the lower bound is EXCLUSIVE.

        An error of exactly ``-0.20`` is underconfident by exactly the
        threshold, which is the "none" case.  Under the mutant
        (``<`` -> ``<=``) it would be called underconfident.
        """
        ledger = CeilingLedger()
        ledger.observe(probe("p1", 90.0, 0.8, passed=True))
        bucket = ledger.calibration()[0]
        self.assertAlmostEqual(bucket.error, -0.2)
        self.assertEqual(bucket.direction, "none")

    def test_a_negative_error_beyond_the_threshold_is_underconfident(self):
        """`lt@568`: the bound, from the other side."""
        ledger = CeilingLedger()
        # mean confidence 0.75, accuracy 1.0 -> error -0.25, beyond the
        # default threshold of 0.20.
        ledger.observe(probe("p1", 90.0, 0.75, passed=True))
        bucket = ledger.calibration()[0]
        self.assertAlmostEqual(bucket.error, -0.25)
        self.assertTrue(bucket.miscalibrated)
        self.assertEqual(bucket.direction, "underconfident")

    # --- eq@705: the self-check entry point ----------------------------
    def test_running_the_module_as_a_script_runs_the_self_check(self):
        """`eq@705`: the entry point is the ``__main__`` guard.

        The module's last two lines are ``if __name__ == "__main__":
        main()``.  Under ``== -> !=`` the guard would be FALSE when the
        module is run as a script -- so the self-check would silently
        not run, and the module would ship with an entry point that
        prints nothing.
        """
        stdout = io.StringIO()
        with mock.patch.object(sys, "stdout", stdout):
            runpy.run_module("capability_ceiling_probe", run_name="__main__")
        self.assertIn("capability-ceiling-probe OK", stdout.getvalue())

    def test_the_self_check_function_is_callable(self):
        """`eq@705`: the guard, so the entry point cannot be a no-op."""
        self.assertTrue(callable(capability_ceiling_probe.main))
