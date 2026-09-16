import json
import shutil
import tempfile
import unittest
from pathlib import Path

from plan_evidence_decision import derive_plan_id
from evidence_preflight_pins import (
    PreflightPinStore,
    PinStoreError,
    PreflightPinRecord,
    verify_pin_resolution,
)
from evidence_readiness_lease import issue_readiness_lease
from evidence_readiness_lease_registry import EvidenceReadinessLeaseRegistry
from evidence_readiness_preflight import (
    SCHEMA,
    EvidenceReadinessPreflight,
    evaluate_preflight,
)
from plan_evidence_decision import (
    EvidencePlanManifest,
    EvidencePlanStep,
    make_plan_evidence_decision,
)
from evidence_state_projection import ClaimProjection
from readiness_lease_witness import make_registry_witness

D = lambda char: "sha256:" + char * 64
PROJECTION_SCHEMA = "northstar.evidence-state-projection.v1"


def projection(claim, state="supported"):
    return ClaimProjection(
        PROJECTION_SCHEMA, claim, state, state == "supported",
        (D("c"),) if state != "unknown" else (),
        (D("d"),) if state != "unknown" else (),
        (), (), (),
    )


def make_preflight(state="preflight-ready", **overrides):
    fields = dict(
        schema_version=SCHEMA,
        lease_digest=D("a"),
        registry_witness_digest=D("b"),
        decision_digest=D("c"),
        manifest_digest=D("d"),
        gate_digest=D("e"),
        state=state,
        lease_state="lease-valid",
        registry_state="current",
        decision_state="ready",
        unverified=(),
        reasons=(),
        execution_authorized=False,
        preflight_digest="",
    )
    fields.update(overrides)
    draft = EvidenceReadinessPreflight(**fields)
    return EvidenceReadinessPreflight(
        **{**fields, "preflight_digest": draft.computed_digest}
    )


class PinStoreTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pins-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.store = PreflightPinStore(Path(self.root) / "pins")
        self.plan = derive_plan_id(D("d"))
        self.preflight = make_preflight()

    def test_pin_then_resolve_matches_digests(self):
        self.store.pin_preflight(self.plan, self.preflight, now=1000)
        reopened = PreflightPinStore(Path(self.root) / "pins")
        resolved = reopened.resolve(self.plan)
        self.assertEqual(resolved.state, "pins-current")
        self.assertEqual(resolved.lease_digest, self.preflight.lease_digest)
        self.assertEqual(resolved.decision_digest, self.preflight.decision_digest)
        self.assertEqual(resolved.manifest_digest, self.preflight.manifest_digest)
        self.assertEqual(resolved.gate_digest, self.preflight.gate_digest)
        self.assertEqual(
            resolved.registry_witness_digest, self.preflight.registry_witness_digest
        )
        self.assertFalse(resolved.execution_authorized)

    def test_verified_pin_is_labelled_verified(self):
        record = self.store.pin_preflight(self.plan, self.preflight, now=1000)
        self.assertEqual(record.origin, "verified")

    def test_unpinned_preflight_pins_as_first_use(self):
        record = self.store.pin_preflight(
            self.plan, make_preflight(state="preflight-unpinned"), now=1000
        )
        self.assertEqual(record.origin, "first-use")

    def test_unknown_plan_is_unrecorded(self):
        resolved = self.store.resolve("plan-never-seen")
        self.assertEqual(resolved.state, "pins-unrecorded")
        self.assertFalse(resolved.execution_authorized)

    def test_non_current_preflight_is_refused(self):
        for state in (
            "preflight-revoked",
            "preflight-stale",
            "preflight-expired",
            "preflight-unknown",
            "preflight-unverifiable",
        ):
            with self.assertRaises(PinStoreError):
                self.store.pin_preflight(self.plan, make_preflight(state=state), now=1000)

    def test_repin_appends_and_marks_remembered_head_stale(self):
        self.store.pin_preflight(self.plan, self.preflight, now=1000)
        first = self.store.resolve(self.plan)
        changed = make_preflight(decision_digest=D("f"))
        self.store.pin_preflight(self.plan, changed, now=1010)
        second = self.store.resolve(self.plan)
        self.assertEqual(second.state, "pins-current")
        self.assertEqual(second.decision_digest, D("f"))
        self.assertGreater(second.chain_sequence, first.chain_sequence)
        verdict = verify_pin_resolution(
            second,
            self.store,
            expected_chain_head_digest=first.chain_head_digest,
            expected_chain_sequence=first.chain_sequence,
        )
        self.assertEqual(verdict.state, "pins-stale")
        self.assertFalse(verdict.execution_authorized)

    def test_unchanged_repin_is_idempotent(self):
        first = self.store.pin_preflight(self.plan, self.preflight, now=1000)
        second = self.store.pin_preflight(self.plan, self.preflight, now=1005)
        self.assertEqual(first.record_digest, second.record_digest)
        self.assertEqual(self.store.resolve(self.plan).chain_sequence, 1)

    def test_verify_current_resolution(self):
        self.store.pin_preflight(self.plan, self.preflight, now=1000)
        resolved = self.store.resolve(self.plan)
        verdict = verify_pin_resolution(
            resolved,
            self.store,
            expected_chain_head_digest=resolved.chain_head_digest,
            expected_chain_sequence=resolved.chain_sequence,
        )
        self.assertEqual(verdict.state, "pins-current")
        self.assertFalse(verdict.execution_authorized)

    def test_tampered_record_is_unverifiable(self):
        self.store.pin_preflight(self.plan, self.preflight, now=1000)
        log = Path(self.root) / "pins" / "pins.jsonl"
        rows = log.read_text(encoding="utf-8").splitlines()
        payload = json.loads(rows[0])
        payload["decision_digest"] = D("f")
        log.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        self.assertEqual(self.store.resolve(self.plan).state, "pins-unverifiable")

    def test_truncated_tail_is_unverifiable(self):
        self.store.pin_preflight(self.plan, self.preflight, now=1000)
        log = Path(self.root) / "pins" / "pins.jsonl"
        with log.open("a", encoding="utf-8") as handle:
            handle.write('{"schema_version": "northstar.evid')
        self.assertEqual(self.store.resolve(self.plan).state, "pins-unverifiable")

    def test_lost_history_is_unverifiable(self):
        self.store.pin_preflight(self.plan, self.preflight, now=1000)
        (Path(self.root) / "pins" / "pins.jsonl").unlink()
        self.assertEqual(self.store.resolve(self.plan).state, "pins-unverifiable")

    def test_record_carries_no_raw_content(self):
        record = self.store.pin_preflight(self.plan, self.preflight, now=1000)
        self.assertEqual(
            set(record.to_dict()),
            {
                "schema_version",
                "sequence",
                "plan_id",
                "origin",
                "lease_digest",
                "registry_witness_digest",
                "decision_digest",
                "manifest_digest",
                "gate_digest",
                "recorded_at",
                "registry_witness",
                "prev_digest",
                "record_digest",
            },
        )
        self.assertEqual(len(record.record_digest), len(D("a")))

    def test_record_round_trip_and_authorization_rejected(self):
        record = self.store.pin_preflight(self.plan, self.preflight, now=1000)
        parsed = PreflightPinRecord.from_dict(record.to_dict())
        self.assertEqual(parsed.record_digest, record.record_digest)
        bad = dict(record.to_dict())
        bad["execution_authorized"] = True
        with self.assertRaises(PinStoreError):
            PreflightPinRecord.from_dict(bad)


class PinStoreIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pins-e2e-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.store = PreflightPinStore(Path(self.root) / "pins")
        claim = D("a")
        self.claim = claim
        self.manifest = EvidencePlanManifest(
            "northstar.evidence-plan-manifest.v1",
            (EvidencePlanStep("step-a", claim, "required evidence"),),
        )
        self.projections = {claim: projection(claim)}
        self.decision = make_plan_evidence_decision(self.manifest, self.projections)
        self.pins = dict(
            expected_decision_digest=self.decision.decision_digest,
            expected_manifest_digest=self.manifest.manifest_digest,
            expected_gate_digest=self.decision.gate["gate_digest"],
        )
        self.lease = issue_readiness_lease(
            self.decision, self.manifest, self.projections, now=1000, ttl=600, **self.pins
        )
        self.registry = EvidenceReadinessLeaseRegistry(Path(self.root) / "registry")
        self.registry.register(self.lease)

    def _evaluate(self, witness, **overrides):
        kwargs = dict(
            lease=self.lease,
            registry_witness=witness,
            registry=self.registry,
            decision=self.decision,
            manifest=self.manifest,
            projections=self.projections,
            now=1010,
            expected_lease_digest=None,
            expected_registry_witness_digest=None,
            **self.pins,
        )
        kwargs.update(overrides)
        return evaluate_preflight(**kwargs)

    def test_first_use_pin_then_second_run_is_ready(self):
        witness = make_registry_witness(self.registry, self.lease.lease_digest, now=1000)
        first = self._evaluate(witness)
        self.assertEqual(first.state, "preflight-unpinned")
        record = self.store.pin_preflight(derive_plan_id(self.manifest.manifest_digest), first, now=1000)
        self.assertEqual(record.origin, "first-use")

        resolved = self.store.resolve(derive_plan_id(self.manifest.manifest_digest))
        second = self._evaluate(
            witness,
            now=1010,
            expected_lease_digest=resolved.lease_digest,
            expected_registry_witness_digest=resolved.registry_witness_digest,
        )
        self.assertEqual(second.state, "preflight-ready")
        self.assertFalse(second.execution_authorized)
        repinned = self.store.pin_preflight(derive_plan_id(self.manifest.manifest_digest), second, now=1010)
        self.assertEqual(repinned.origin, "verified")

    def test_stored_pin_detects_real_decision_drift(self):
        witness = make_registry_witness(self.registry, self.lease.lease_digest, now=1000)
        first = self._evaluate(witness)
        self.store.pin_preflight(derive_plan_id(self.manifest.manifest_digest), first, now=1000)
        resolved = self.store.resolve(derive_plan_id(self.manifest.manifest_digest))

        drifted = {self.claim: projection(self.claim, state="conflicted")}
        with self.assertRaises(Exception):
            self._evaluate(
                witness,
                projections=drifted,
                expected_lease_digest=resolved.lease_digest,
                expected_registry_witness_digest=resolved.registry_witness_digest,
            )


if __name__ == "__main__":
    unittest.main()


class PinLabelIdentityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.store = PreflightPinStore(self.root / "pins.jsonl")
        self.preflight = make_preflight()

    def test_a_pin_label_must_match_the_derived_plan_identity(self):
        with self.assertRaises(PinStoreError):
            self.store.pin_preflight("plan-alpha", self.preflight, now=1000)

    def test_the_derived_identity_is_accepted(self):
        record = self.store.pin_preflight(
            derive_plan_id(self.preflight.manifest_digest), self.preflight, now=1000
        )
        self.assertEqual(record.manifest_digest, self.preflight.manifest_digest)
