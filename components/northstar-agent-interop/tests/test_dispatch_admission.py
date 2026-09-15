import unittest

from dispatch_admission import (
    DispatchAdmission,
    DispatchAdmissionError,
    evaluate_dispatch_admission,
)
from route_liveness import SCHEMA as LIVENESS_SCHEMA, RouteLivenessVerdict
from test_evidence_preflight_pins import make_preflight


def liveness(state, *, unverified=()):
    return RouteLivenessVerdict(
        LIVENESS_SCHEMA, "route-1", state, "", 0, tuple(unverified), (), False
    )


class DispatchAdmissionTests(unittest.TestCase):
    def test_ready_evidence_and_dispatchable_route_admit_without_authorizing(self):
        result = evaluate_dispatch_admission(
            make_preflight(), liveness("dispatchable"), plan_id="plan-a"
        )
        self.assertEqual(result.state, "admit")
        self.assertFalse(result.execution_authorized)
        self.assertEqual(DispatchAdmission.from_dict(result.to_dict()), result)

    def test_in_flight_route_blocks_otherwise_ready_evidence(self):
        result = evaluate_dispatch_admission(
            make_preflight(), liveness("in_flight"), plan_id="plan-a"
        )
        self.assertEqual(result.state, "blocked-route")

    def test_revoked_evidence_blocks_otherwise_dispatchable_route(self):
        result = evaluate_dispatch_admission(
            make_preflight(state="preflight-revoked"), liveness("dispatchable"), plan_id="plan-a"
        )
        self.assertEqual(result.state, "blocked-evidence")

    def test_both_sides_blocked_are_explicit(self):
        result = evaluate_dispatch_admission(
            make_preflight(state="preflight-revoked"), liveness("blocked"), plan_id="plan-a"
        )
        self.assertEqual(result.state, "blocked-both")

    def test_unpinned_evidence_never_becomes_clean_admit(self):
        result = evaluate_dispatch_admission(
            make_preflight(state="preflight-unpinned"), liveness("dispatchable"), plan_id="plan-a"
        )
        self.assertEqual(result.state, "admit-unpinned")

    def test_unknown_on_either_side_fails_closed(self):
        left = evaluate_dispatch_admission(
            make_preflight(state="preflight-unknown"), liveness("dispatchable"), plan_id="plan-a"
        )
        right = evaluate_dispatch_admission(
            make_preflight(), liveness("unknown"), plan_id="plan-a"
        )
        self.assertEqual(left.state, "unknown")
        self.assertEqual(right.state, "unknown")

    def test_unverified_lineage_downgrades_clean_admit(self):
        result = evaluate_dispatch_admission(
            make_preflight(), liveness("dispatchable", unverified=("lineage_mark_absent",)), plan_id="plan-a"
        )
        self.assertEqual(result.state, "admit-unpinned")
        self.assertIn("lineage_mark_absent", result.unverified)

    def test_wire_form_rejects_authorization_and_tampering(self):
        result = evaluate_dispatch_admission(
            make_preflight(), liveness("dispatchable"), plan_id="plan-a"
        )
        wire = result.to_dict()
        wire["execution_authorized"] = True
        with self.assertRaises(DispatchAdmissionError):
            DispatchAdmission.from_dict(wire)
        wire = result.to_dict()
        wire["state"] = "blocked-route"
        with self.assertRaises(DispatchAdmissionError):
            DispatchAdmission.from_dict(wire)
