"""Tests for weak_to_strong: weak-to-strong generalization monitor."""

import unittest

from weak_to_strong import (
    SCHEMA_PIN,
    WEAK_TO_STRONG_VERSION,
    CapabilityTier,
    Disagreement,
    GapReport,
    StrongPrediction,
    WeakLabel,
    WeakSupervisor,
    WeakToStrongMonitor,
    generalization_gap,
    main,
    weak_to_strong_audit_event,
)


def sup(**kw):
    base = dict(supervisor_id="weak-sup")
    base.update(kw)
    return WeakSupervisor(**base)


def label(item="q-1", lab="allow", confident=True, seq=0):
    return WeakLabel(item_id=item, label=lab, confident=confident, seq=seq)


def pred(item="q-1", p="allow", seq=0):
    return StrongPrediction(item_id=item, prediction=p, seq=seq)


class VersionTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(WEAK_TO_STRONG_VERSION, "weak-to-strong-monitor.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.weak-to-strong.v1")


class SupervisorValidationTests(unittest.TestCase):
    def test_frozen(self):
        s = sup()
        with self.assertRaises(Exception):
            s.supervisor_id = "x"  # type: ignore[misc]

    def test_empty_id_rejected(self):
        with self.assertRaises(ValueError):
            sup(supervisor_id="")

    def test_bad_tier_rejected(self):
        with self.assertRaises(TypeError):
            sup(capability_tier="weak")  # type: ignore[arg-type]

    def test_error_rate_out_of_range(self):
        with self.assertRaises(ValueError):
            sup(declared_error_rate=1.0)
        with self.assertRaises(ValueError):
            sup(declared_error_rate=-0.1)

    def test_bool_error_rate_rejected(self):
        with self.assertRaises(TypeError):
            sup(declared_error_rate=True)

    def test_non_frozenset_ids_rejected(self):
        with self.assertRaises(TypeError):
            sup(known_error_ids={"q-1"})  # type: ignore[arg-type]

    def test_empty_id_entry_rejected(self):
        with self.assertRaises(ValueError):
            sup(known_error_ids=frozenset({""}))

    def test_defaults(self):
        s = sup()
        self.assertEqual(s.capability_tier, CapabilityTier.WEAK)
        self.assertEqual(s.declared_error_rate, 0.0)
        self.assertEqual(s.known_error_ids, frozenset())


class LabelValidationTests(unittest.TestCase):
    def test_frozen(self):
        with self.assertRaises(Exception):
            label().label = "x"  # type: ignore[misc]

    def test_empty_item_rejected(self):
        with self.assertRaises(ValueError):
            label(item="")

    def test_empty_label_rejected(self):
        with self.assertRaises(ValueError):
            label(lab="")

    def test_non_bool_confident_rejected(self):
        with self.assertRaises(TypeError):
            label(confident=1)  # type: ignore[arg-type]

    def test_bool_seq_rejected(self):
        with self.assertRaises(TypeError):
            label(seq=True)

    def test_negative_seq_rejected(self):
        with self.assertRaises(ValueError):
            label(seq=-1)

    def test_digest_roundtrip(self):
        l = label()
        self.assertTrue(l.digest.startswith("sha256:"))
        self.assertTrue(l.verify_digest())


class PredictionValidationTests(unittest.TestCase):
    def test_frozen(self):
        with self.assertRaises(Exception):
            pred().prediction = "x"  # type: ignore[misc]

    def test_empty_prediction_rejected(self):
        with self.assertRaises(ValueError):
            pred(p="")

    def test_bool_seq_rejected(self):
        with self.assertRaises(TypeError):
            pred(seq=False)

    def test_digest_roundtrip(self):
        p = pred()
        self.assertTrue(p.verify_digest())


class GapInputTests(unittest.TestCase):
    def test_non_sequence_rejected(self):
        with self.assertRaises(TypeError):
            generalization_gap("nope", [])  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            generalization_gap([], "nope")  # type: ignore[arg-type]

    def test_wrong_element_types_rejected(self):
        with self.assertRaises(TypeError):
            generalization_gap([pred()], [label()])  # type: ignore[list-item]

    def test_duplicate_weak_ids_rejected(self):
        with self.assertRaises(ValueError):
            generalization_gap([label(), label()], [pred()])

    def test_duplicate_strong_ids_rejected(self):
        with self.assertRaises(ValueError):
            generalization_gap([label()], [pred(), pred()])

    def test_bad_ground_truth_rejected(self):
        with self.assertRaises(TypeError):
            generalization_gap([label()], [pred()],
                               ground_truth="q-1")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            generalization_gap([label()], [pred()],
                               ground_truth={"": "allow"})

    def test_bad_supervisor_rejected(self):
        with self.assertRaises(TypeError):
            generalization_gap([label()], [pred()], supervisor="x")  # type: ignore[arg-type]

    def test_empty_intersection_insufficient(self):
        rep = generalization_gap([label(item="a")], [pred(item="b")])
        self.assertEqual(rep.n_items, 0)
        self.assertIsNone(rep.agreement)
        self.assertEqual(rep.alerts, ("insufficient-data",))
        self.assertEqual(rep.disagreements, ())

    def test_empty_inputs_insufficient(self):
        rep = generalization_gap([], [])
        self.assertEqual(rep.alerts, ("insufficient-data",))


class GapMeasurementTests(unittest.TestCase):
    def test_full_agreement(self):
        rep = generalization_gap([label(), label(item="q-2")],
                                 [pred(), pred(item="q-2")])
        self.assertEqual(rep.n_items, 2)
        self.assertEqual(rep.agreement, 1.0)
        self.assertEqual(rep.disagreements, ())
        self.assertIsNone(rep.weak_accuracy)  # no ground truth

    def test_disagreement_sorted_and_truth_none_without_gt(self):
        rep = generalization_gap([label(item="b"), label(item="a")],
                                 [pred(item="b", p="deny"), pred(item="a")])
        self.assertEqual(rep.agreement, 0.5)
        self.assertEqual([d.item_id for d in rep.disagreements], ["b"])
        d = rep.disagreements[0]
        self.assertIsNone(d.truth)
        self.assertEqual(d.as_dict()["schema"], SCHEMA_PIN)

    def test_taxonomy_with_ground_truth(self):
        weak = [label(item="q-1", lab="allow"), label(item="q-2", lab="deny")]
        strong = [pred(item="q-1", p="allow"), pred(item="q-2", p="allow")]
        truth = {"q-1": "allow", "q-2": "allow"}
        rep = generalization_gap(weak, strong, truth)
        self.assertEqual(rep.agreement, 0.5)
        self.assertEqual(rep.weak_accuracy, 0.5)
        self.assertEqual(rep.strong_accuracy, 1.0)
        self.assertEqual(rep.error_agreement, 0.0)   # weak wrong on q-2, strong fixed it
        self.assertEqual(rep.error_recovery, 1.0)
        self.assertEqual(rep.regression, 0.0)
        self.assertEqual(rep.alerts, ())

    def test_high_error_distillation_alerts(self):
        # Weak wrong on all three; strong copies all three.
        weak = [label(item=f"q-{i}", lab="deny") for i in range(3)]
        strong = [pred(item=f"q-{i}", p="deny") for i in range(3)]
        truth = {f"q-{i}": "allow" for i in range(3)}
        rep = generalization_gap(weak, strong, truth)
        self.assertEqual(rep.error_agreement, 1.0)
        self.assertIn("high-error-distillation", rep.alerts)
        # Equal accuracy (both 0.0), so no worse-than-supervisor alert.
        self.assertNotIn("worse-than-supervisor", rep.alerts)

    def test_worse_than_supervisor_alerts(self):
        weak = [label(item="q-1", lab="allow")]
        strong = [pred(item="q-1", p="deny")]
        truth = {"q-1": "allow"}
        rep = generalization_gap(weak, strong, truth)
        self.assertIn("worse-than-supervisor", rep.alerts)
        self.assertEqual(rep.regression, 1.0)

    def test_uncertain_region_copying_alerts(self):
        s = sup(known_error_ids=frozenset({"u-1", "u-2", "u-3"}))
        weak = [label(item=f"u-{i}", lab="deny", confident=False) for i in (1, 2, 3)]
        strong = [pred(item=f"u-{i}", p="deny") for i in (1, 2, 3)]
        truth = {f"u-{i}": "allow" for i in (1, 2, 3)}
        rep = generalization_gap(weak, strong, truth, supervisor=s)
        self.assertEqual(rep.uncertain_region_agreement, 1.0)
        self.assertIn("uncertain-region-copying", rep.alerts)

    def test_uncertain_copy_below_min_items_quiet(self):
        s = sup(known_error_ids=frozenset({"u-1", "u-2"}))
        weak = [label(item=f"u-{i}", lab="deny", confident=False) for i in (1, 2)]
        strong = [pred(item=f"u-{i}", p="deny") for i in (1, 2)]
        rep = generalization_gap(weak, strong, None, supervisor=s)
        self.assertNotIn("uncertain-region-copying", rep.alerts)

    def test_uncertain_recovery_quiet(self):
        s = sup(known_error_ids=frozenset({"u-1", "u-2", "u-3"}))
        weak = [label(item=f"u-{i}", lab="deny", confident=False) for i in (1, 2, 3)]
        strong = [pred(item=f"u-{i}", p="allow") for i in (1, 2, 3)]
        truth = {f"u-{i}": "allow" for i in (1, 2, 3)}
        rep = generalization_gap(weak, strong, truth, supervisor=s)
        self.assertEqual(rep.uncertain_region_agreement, 0.0)
        self.assertNotIn("uncertain-region-copying", rep.alerts)

    def test_no_supervisor_no_uncertain(self):
        rep = generalization_gap([label()], [pred()])
        self.assertIsNone(rep.uncertain_region_agreement)


class MonitorTests(unittest.TestCase):
    def test_constructor_rejects_non_supervisor(self):
        with self.assertRaises(TypeError):
            WeakToStrongMonitor("x")  # type: ignore[arg-type]

    def test_supervise_rejects_wrong_type(self):
        mon = WeakToStrongMonitor(sup())
        with self.assertRaises(TypeError):
            mon.supervise(pred())  # type: ignore[arg-type]

    def test_observe_rejects_wrong_type(self):
        mon = WeakToStrongMonitor(sup())
        with self.assertRaises(TypeError):
            mon.observe(label())  # type: ignore[arg-type]

    def test_views_are_tuples(self):
        mon = WeakToStrongMonitor(sup())
        mon.supervise(label())
        mon.observe(pred())
        self.assertEqual(len(mon.labels()), 1)
        self.assertEqual(len(mon.predictions()), 1)
        self.assertIsInstance(mon.labels(), tuple)

    def test_alerts_passthrough(self):
        mon = WeakToStrongMonitor(sup())
        mon.supervise(label(item="q-1", lab="deny"))
        mon.observe(pred(item="q-1", p="deny"))
        self.assertEqual(mon.alerts({"q-1": "allow"}),
                         ("high-error-distillation",))

    def test_supervisor_property(self):
        s = sup()
        self.assertIs(WeakToStrongMonitor(s).supervisor, s)


class AuditEventTests(unittest.TestCase):
    def test_event_shape(self):
        rep = generalization_gap([label()], [pred()], {"q-1": "allow"})
        ev = weak_to_strong_audit_event(rep, "weak-sup", 7)
        self.assertEqual(ev["event"], "weak-to-strong-gap")
        self.assertEqual(ev["audit_seq"], 7)
        self.assertEqual(ev["supervisor_id"], "weak-sup")
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertIn("alerts", ev)

    def test_bad_report_rejected(self):
        with self.assertRaises(TypeError):
            weak_to_strong_audit_event("x", "weak-sup", 1)  # type: ignore[arg-type]

    def test_bad_seq_rejected(self):
        rep = generalization_gap([label()], [pred()])
        with self.assertRaises(ValueError):
            weak_to_strong_audit_event(rep, "weak-sup", -1)
        with self.assertRaises(TypeError):
            weak_to_strong_audit_event(rep, "weak-sup", True)


class MainTests(unittest.TestCase):
    def test_main_self_check(self):
        main()  # asserts internally; raises on failure

    def test_disagreement_record_shape(self):
        d = Disagreement(item_id="q-1", weak_label="a", strong_prediction="b",
                         truth="b")
        dd = d.as_dict()
        self.assertEqual(dd["item_id"], "q-1")
        self.assertEqual(dd["truth"], "b")
        self.assertEqual(dd["version"], WEAK_TO_STRONG_VERSION)

    def test_gap_report_as_dict(self):
        rep = generalization_gap([label()], [pred()])
        rd = rep.as_dict()
        self.assertEqual(rd["n_items"], 1)
        self.assertEqual(rd["schema"], SCHEMA_PIN)


if __name__ == "__main__":
    unittest.main()
