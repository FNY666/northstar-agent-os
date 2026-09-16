import unittest
from pathlib import Path

from dispatch_admission import (
    DispatchAdmission,
    DispatchAdmissionError,
    derive_plan_id,
    evaluate_dispatch_admission,
)
from plan_evidence_decision import (
    MANIFEST_SCHEMA,
    EvidencePlanManifest,
    EvidencePlanStep,
)
from route_liveness import SCHEMA as LIVENESS_SCHEMA, RouteLivenessVerdict
from test_evidence_preflight_pins import D, make_preflight


def liveness(state, *, unverified=()):
    return RouteLivenessVerdict(
        LIVENESS_SCHEMA, "route-1", state, "", 0, tuple(unverified), (), False
    )


def plan_manifest():
    return EvidencePlanManifest(
        MANIFEST_SCHEMA,
        (EvidencePlanStep("step-1", D("1"), "read the source column"),),
    )


class DispatchAdmissionTests(unittest.TestCase):
    def test_caller_labelled_plan_identity_is_never_a_clean_admit(self):
        result = evaluate_dispatch_admission(
            make_preflight(), liveness("dispatchable"), plan_id="plan-a"
        )
        self.assertEqual(result.state, "admit-unpinned")
        self.assertIn("plan_id_unverified", result.unverified)
        self.assertFalse(result.execution_authorized)

    def test_host_owned_manifest_corroborates_plan_identity(self):
        manifest = plan_manifest()
        result = evaluate_dispatch_admission(
            make_preflight(manifest_digest=manifest.manifest_digest),
            liveness("dispatchable"),
            plan_id=derive_plan_id(manifest.manifest_digest),
            plan_manifest=manifest,
        )
        self.assertEqual(result.state, "admit")
        self.assertNotIn("plan_id_unverified", result.unverified)

    def test_manifest_for_a_different_plan_is_refused(self):
        manifest = plan_manifest()
        with self.assertRaises(DispatchAdmissionError):
            evaluate_dispatch_admission(
                make_preflight(),
                liveness("dispatchable"),
                plan_id=derive_plan_id(manifest.manifest_digest),
                plan_manifest=manifest,
            )

    def test_plan_label_must_match_the_derived_identity(self):
        manifest = plan_manifest()
        with self.assertRaises(DispatchAdmissionError):
            evaluate_dispatch_admission(
                make_preflight(manifest_digest=manifest.manifest_digest),
                liveness("dispatchable"),
                plan_id="plan-a",
                plan_manifest=manifest,
            )

    def test_ready_evidence_and_dispatchable_route_admit_without_authorizing(self):
        manifest = plan_manifest()
        result = evaluate_dispatch_admission(
            make_preflight(manifest_digest=manifest.manifest_digest),
            liveness("dispatchable"),
            plan_id=derive_plan_id(manifest.manifest_digest),
            plan_manifest=manifest,
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

    def test_liveness_cannot_claim_execution_authority(self):
        forged = RouteLivenessVerdict(
            LIVENESS_SCHEMA, "route-1", "dispatchable", "", 0, (), (), True
        )
        with self.assertRaises(DispatchAdmissionError):
            evaluate_dispatch_admission(make_preflight(), forged, plan_id="plan-a")

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


class DerivedPlanIdentityDriftTests(unittest.TestCase):
    def test_derivation_still_matches_the_plan_evidence_gate(self):
        # derive_plan_id mirrors the gate's inline plan identity. If upstream changes
        # that derivation, this fails loudly instead of silently mislabelling plans.
        source = (
            Path(__file__).resolve().parents[1] / "plan_evidence_decision.py"
        ).read_text(encoding="utf-8")
        self.assertIn("plan-evidence:", source)
        self.assertIn("manifest_digest[7:23]", source)

    def test_derived_identity_is_reproducible(self):
        digest = D("9")
        self.assertEqual(derive_plan_id(digest), "plan-evidence:" + digest[7:23])
        with self.assertRaises(DispatchAdmissionError):
            derive_plan_id("not-a-digest")
