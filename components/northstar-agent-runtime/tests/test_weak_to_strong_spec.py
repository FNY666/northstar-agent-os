"""Tests for the weak_to_strong spec API: WeakToStrong.generalize()/measure().

The spec asked for a ``WeakToStrong`` class with ``supervise()``,
``generalize()``, ``measure()``. This file covers that API; the
underlying monitor's 50 tests in test_weak_to_strong.py are untouched.
"""

import unittest

from weak_to_strong import (
    SCHEMA_PIN,
    WEAK_TO_STRONG_VERSION,
    CapabilityTier,
    GapReport,
    GeneralizationMeasure,
    StrongPrediction,
    WeakLabel,
    WeakSupervisor,
    WeakToStrong,
    WeakToStrongMonitor,
    main,
)


def sup(**kw):
    base = dict(supervisor_id="weak-sup")
    base.update(kw)
    return WeakSupervisor(**base)


def label(item="q-1", lab="allow", confident=True, seq=0):
    return WeakLabel(item_id=item, label=lab, confident=confident, seq=seq)


def pred(item="q-1", p="allow", seq=0):
    return StrongPrediction(item_id=item, prediction=p, seq=seq)


def clean_pair():
    """Weak wrong on q-3/q-4, strong recovers both; no regression."""
    labels = [
        ("q-1", "allow", True),
        ("q-2", "deny", True),
        ("q-3", "deny", True),
        ("q-4", "allow", False),
    ]
    preds = {"q-1": "allow", "q-2": "deny", "q-3": "allow", "q-4": "deny"}
    truth = {"q-1": "allow", "q-2": "deny", "q-3": "allow", "q-4": "deny"}
    return labels, preds, truth


def filled(labels, preds):
    wts = WeakToStrong(sup())
    for n, (i, lab, conf) in enumerate(labels):
        wts.supervise(label(item=i, lab=lab, confident=conf, seq=n))
    for n, (i, p) in enumerate(sorted(preds.items())):
        wts.observe(pred(item=i, p=p, seq=n))
    return wts


class TestSpecApi(unittest.TestCase):
    def test_spec_api_presence(self):
        self.assertTrue(issubclass(WeakToStrong, WeakToStrongMonitor))
        self.assertTrue(hasattr(WeakToStrong, "supervise"))
        self.assertTrue(hasattr(WeakToStrong, "generalize"))
        self.assertTrue(hasattr(WeakToStrong, "measure"))

    def test_inherits_monitor_api(self):
        wts = WeakToStrong(sup())
        wts.supervise(label())
        wts.observe(pred())
        self.assertEqual(len(wts.labels()), 1)
        self.assertEqual(len(wts.predictions()), 1)
        self.assertEqual(wts.alerts(), ())

    def test_constructor_bad_supervisor(self):
        with self.assertRaises(TypeError):
            WeakToStrong("not-a-supervisor")

    def test_supervise_bad_label_type(self):
        wts = WeakToStrong(sup())
        with self.assertRaises(TypeError):
            wts.supervise(("q-1", "allow"))

    def test_generalize_returns_gap_report(self):
        labels, preds, truth = clean_pair()
        rep = filled(labels, preds).generalize(truth)
        self.assertIsInstance(rep, GapReport)
        self.assertEqual(rep.n_items, 4)
        self.assertEqual(rep.agreement, 0.5)  # 2/4 agree

    def test_generalize_error_recovery(self):
        labels, preds, truth = clean_pair()
        rep = filled(labels, preds).generalize(truth)
        self.assertEqual(rep.error_recovery, 1.0)
        self.assertEqual(rep.regression, 0.0)
        self.assertEqual(rep.alerts, ())

    def test_generalize_without_ground_truth(self):
        labels, preds, _ = clean_pair()
        rep = filled(labels, preds).generalize()
        self.assertEqual(rep.agreement, 0.5)
        self.assertIsNone(rep.error_recovery)
        self.assertIsNone(rep.weak_accuracy)

    def test_generalize_empty_intersection(self):
        wts = WeakToStrong(sup())
        wts.supervise(label(item="q-1"))
        wts.observe(pred(item="q-9"))
        rep = wts.generalize()
        self.assertEqual(rep.n_items, 0)
        self.assertIn("insufficient-data", rep.alerts)

    def test_generalize_bad_ground_truth(self):
        labels, preds, _ = clean_pair()
        wts = filled(labels, preds)
        with self.assertRaises(TypeError):
            wts.generalize(["not-a-mapping"])

    def test_measure_headline_scalars(self):
        labels, preds, truth = clean_pair()
        m = filled(labels, preds).measure(truth)
        self.assertIsInstance(m, GeneralizationMeasure)
        self.assertEqual(m.supervisor_id, "weak-sup")
        self.assertEqual(m.n_items, 4)
        self.assertEqual(m.agreement, 0.5)
        self.assertEqual(m.weak_accuracy, 0.5)
        self.assertEqual(m.strong_accuracy, 1.0)
        self.assertEqual(m.error_recovery, 1.0)
        self.assertEqual(m.alerts, ())

    def test_measure_digest_roundtrip_and_tamper(self):
        labels, preds, truth = clean_pair()
        m = filled(labels, preds).measure(truth)
        self.assertTrue(m.digest.startswith("sha256:"))
        self.assertTrue(m.verify_digest())
        tampered = GeneralizationMeasure(
            supervisor_id="weak-sup",
            n_items=m.n_items,
            agreement=m.agreement,
            weak_accuracy=m.weak_accuracy,
            strong_accuracy=m.strong_accuracy,
            error_recovery=0.0,  # different content
            alerts=m.alerts,
        )
        self.assertNotEqual(tampered.digest, m.digest)

    def test_measure_frozen(self):
        labels, preds, truth = clean_pair()
        m = filled(labels, preds).measure(truth)
        import dataclasses

        with self.assertRaises(dataclasses.FrozenInstanceError):
            m.n_items = 9  # type: ignore[misc]

    def test_measure_as_dict_pins(self):
        labels, preds, truth = clean_pair()
        d = filled(labels, preds).measure(truth).as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], WEAK_TO_STRONG_VERSION)
        self.assertIn("digest", d)

    def test_measure_consistent_with_generalize(self):
        labels, preds, truth = clean_pair()
        wts = filled(labels, preds)
        rep, m = wts.generalize(truth), wts.measure(truth)
        self.assertEqual(m.agreement, rep.agreement)
        self.assertEqual(m.weak_accuracy, rep.weak_accuracy)
        self.assertEqual(m.strong_accuracy, rep.strong_accuracy)
        self.assertEqual(m.error_recovery, rep.error_recovery)
        self.assertEqual(m.alerts, rep.alerts)

    def test_main_smoke(self):
        main()  # asserts internally; raises on failure


if __name__ == "__main__":
    unittest.main()
