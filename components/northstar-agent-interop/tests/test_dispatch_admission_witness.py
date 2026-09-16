import unittest
from dispatch_admission import evaluate_dispatch_admission
from dispatch_admission_witness import (
    AdmissionWitnessError,
    DispatchAdmissionWitness,
    make_admission_witness,
    verify_admission_witness,
)
from route_liveness import SCHEMA as LS, RouteLivenessVerdict
from test_evidence_preflight_pins import make_preflight


def live(state="dispatchable", unverified=()):
    return RouteLivenessVerdict(LS, "route-1", state, "", 0, tuple(unverified), (), False)


class AdmissionWitnessTests(unittest.TestCase):
    def setUp(self):
        self.preflight = make_preflight()
        self.liveness = live()
        self.admission = evaluate_dispatch_admission(
            self.preflight, self.liveness, plan_id="plan-a"
        )

    def test_witness_binds_admission_and_sources(self):
        witness = make_admission_witness(
            self.admission, self.preflight, self.liveness, observed_at=1000
        )
        self.assertIsInstance(witness, DispatchAdmissionWitness)
        result = verify_admission_witness(
            witness, self.admission, self.preflight, self.liveness, now=1010
        )
        self.assertEqual(result.state, "current-unpinned")
        self.assertIn("witness_digest_unpinned", result.unverified)
        self.assertFalse(result.execution_authorized)

    def test_external_pin_makes_current_explicit(self):
        witness = make_admission_witness(
            self.admission, self.preflight, self.liveness, observed_at=1000
        )
        result = verify_admission_witness(
            witness, self.admission, self.preflight, self.liveness,
            now=1010, expected_witness_digest=witness.witness_digest
        )
        self.assertEqual(result.state, "current")

    def test_liveness_for_a_different_route_is_refused(self):
        other_route = RouteLivenessVerdict(LS, "route-2", "dispatchable", "", 0, (), (), False)
        with self.assertRaises(AdmissionWitnessError):
            make_admission_witness(self.admission, self.preflight, other_route, observed_at=1000)

    def test_liveness_cannot_claim_execution_authority(self):
        forged = RouteLivenessVerdict(LS, "route-1", "dispatchable", "", 0, (), (), True)
        with self.assertRaises(AdmissionWitnessError):
            make_admission_witness(self.admission, self.preflight, forged, observed_at=1000)

    def test_changed_preflight_is_stale(self):
        witness = make_admission_witness(
            self.admission, self.preflight, self.liveness, observed_at=1000
        )
        changed = make_preflight(decision_digest="sha256:" + "f" * 64)
        result = verify_admission_witness(
            witness, self.admission, changed, self.liveness, now=1010,
            expected_witness_digest=witness.witness_digest
        )
        self.assertEqual(result.state, "stale")
        self.assertIn("preflight_changed", result.reasons)

    def test_changed_liveness_is_stale(self):
        witness = make_admission_witness(
            self.admission, self.preflight, self.liveness, observed_at=1000
        )
        result = verify_admission_witness(
            witness, self.admission, self.preflight, live("in_flight"), now=1010
        )
        self.assertEqual(result.state, "stale")
        self.assertIn("liveness_changed", result.reasons)

    def test_wire_form_rejects_tampering_and_authorization(self):
        witness = make_admission_witness(
            self.admission, self.preflight, self.liveness, observed_at=1000
        )
        self.assertEqual(
            DispatchAdmissionWitness.from_dict(witness.to_dict()), witness
        )
        forged = witness.to_dict()
        forged["execution_authorized"] = True
        with self.assertRaises(AdmissionWitnessError):
            DispatchAdmissionWitness.from_dict(forged)
        forged = witness.to_dict()
        forged["admission_digest"] = "sha256:" + "f" * 64
        with self.assertRaises(AdmissionWitnessError):
            DispatchAdmissionWitness.from_dict(forged)

    def test_unknown_source_is_not_current(self):
        unknown = live("unknown")
        admission = evaluate_dispatch_admission(
            self.preflight, unknown, plan_id="plan-a"
        )
        witness = make_admission_witness(admission, self.preflight, unknown, observed_at=1000)
        result = verify_admission_witness(witness, admission, self.preflight, unknown, now=1010)
        self.assertEqual(result.state, "unknown")
        self.assertFalse(result.execution_authorized)


if __name__ == "__main__":
    unittest.main()


class AdmissionWitnessCorrespondenceTests(unittest.TestCase):
    def setUp(self):
        self.preflight = make_preflight()
        self.liveness = live()
        self.admission = evaluate_dispatch_admission(
            self.preflight, self.liveness, plan_id="plan-a"
        )

    def test_a_preflight_the_admission_was_not_built_from_is_refused(self):
        other = make_preflight(lease_digest="sha256:" + "e" * 64)
        self.assertEqual(other.state, self.preflight.state)
        with self.assertRaises(AdmissionWitnessError):
            make_admission_witness(self.admission, other, self.liveness, observed_at=1000)

    def test_a_liveness_the_admission_was_not_built_from_is_refused(self):
        other = live(unverified=("lineage_mark_absent",))
        self.assertEqual(other.state, self.liveness.state)
        with self.assertRaises(AdmissionWitnessError):
            make_admission_witness(self.admission, self.preflight, other, observed_at=1000)
