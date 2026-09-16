import json
import shutil
import tempfile
import unittest
from pathlib import Path

from plan_evidence_decision import derive_plan_id
from evidence_preflight_pins import (
    PinStoreError,
    PreflightPinStore,
    PreflightPinRecord,
    restore_witness,
)
from evidence_readiness_lease import issue_readiness_lease
from evidence_readiness_lease_registry import EvidenceReadinessLeaseRegistry
from evidence_readiness_preflight import EvidenceReadinessPreflight, SCHEMA, evaluate_preflight
from evidence_state_projection import ClaimProjection
from plan_evidence_decision import (
    EvidencePlanManifest,
    EvidencePlanStep,
    make_plan_evidence_decision,
)
from readiness_lease_witness import (
    LeaseRegistryWitness,
    make_registry_witness,
)

D = lambda char: "sha256:" + char * 64
PROJECTION_SCHEMA = "northstar.evidence-state-projection.v1"


def projection(claim, state="supported"):
    return ClaimProjection(
        PROJECTION_SCHEMA, claim, state, state == "supported",
        (D("c"),) if state != "unknown" else (),
        (D("d"),) if state != "unknown" else (),
        (), (), (),
    )


def make_preflight(state="preflight-ready", witness=None, **overrides):
    if witness is not None:
        overrides.setdefault("registry_witness_digest", witness.witness_digest)
    fields = dict(
        schema_version=SCHEMA,
        lease_digest=D("a"), registry_witness_digest=D("b"), decision_digest=D("c"),
        manifest_digest=D("d"), gate_digest=D("e"), state=state,
        lease_state="lease-valid", registry_state="current", decision_state="ready",
        unverified=(), reasons=(), execution_authorized=False, preflight_digest="",
    )
    fields.update(overrides)
    draft = EvidenceReadinessPreflight(**fields)
    return EvidenceReadinessPreflight(**{**fields, "preflight_digest": draft.computed_digest})


class ReplayFixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pins-replay-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.store_path = Path(self.root) / "pins"
        self.store = PreflightPinStore(self.store_path)
        claim = D("a")
        self.claim = claim
        self.manifest = EvidencePlanManifest(
            "northstar.evidence-plan-manifest.v1",
            (EvidencePlanStep("step-a", claim, "required evidence"),),
        )
        self.plan = derive_plan_id(self.manifest.manifest_digest)
        self.fixture_plan = derive_plan_id(D("d"))
        self.projections = {claim: projection(claim)}
        self.decision = make_plan_evidence_decision(self.manifest, self.projections)
        self.pins = dict(
            expected_decision_digest=self.decision.decision_digest,
            expected_manifest_digest=self.manifest.manifest_digest,
            expected_gate_digest=self.decision.gate["gate_digest"],
        )
        self.lease = issue_readiness_lease(
            self.decision, self.manifest, self.projections, now=1000, ttl=6000, **self.pins
        )
        self.registry = EvidenceReadinessLeaseRegistry(Path(self.root) / "registry")
        self.registry.register(self.lease)
        self.witness = make_registry_witness(self.registry, self.lease.lease_digest, now=1000)

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


class PinWitnessPayloadTests(ReplayFixture):
    def test_pin_with_payload_is_replayable_after_restart(self):
        self.store.pin_preflight(
            self.fixture_plan, make_preflight(witness=self.witness), now=1000, witness=self.witness
        )
        reopened = PreflightPinStore(self.store_path)
        resolved = reopened.resolve(self.fixture_plan)
        self.assertTrue(resolved.witness_replayable)
        self.assertEqual(resolved.registry_witness, self.witness.to_dict())
        restored = restore_witness(resolved)
        self.assertIsInstance(restored, LeaseRegistryWitness)
        self.assertEqual(restored.witness_digest, self.witness.witness_digest)
        self.assertEqual(restored.observed_at, 1000)
        self.assertFalse(resolved.execution_authorized)

    def test_pin_without_payload_is_not_replayable(self):
        self.store.pin_preflight(self.fixture_plan, make_preflight(), now=1000)
        resolved = self.store.resolve(self.fixture_plan)
        self.assertEqual(resolved.state, "pins-current")
        self.assertFalse(resolved.witness_replayable)
        with self.assertRaises(PinStoreError):
            restore_witness(resolved)

    def test_payload_must_match_preflight_witness_digest(self):
        mismatched = make_preflight(registry_witness_digest=self.witness.witness_digest)
        other = make_registry_witness(self.registry, self.lease.lease_digest, now=1011)
        with self.assertRaises(PinStoreError):
            self.store.pin_preflight(self.fixture_plan, mismatched, now=1000, witness=other)

    def test_tampered_payload_is_unverifiable(self):
        self.store.pin_preflight(
            self.fixture_plan, make_preflight(witness=self.witness), now=1000, witness=self.witness
        )
        log = self.store_path / "pins.jsonl"
        payload = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
        payload["registry_witness"]["observed_at"] = 9999
        log.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        self.assertEqual(self.store.resolve(self.fixture_plan).state, "pins-unverifiable")

    def test_older_field_set_is_unverifiable(self):
        self.store.pin_preflight(
            self.fixture_plan, make_preflight(witness=self.witness), now=1000, witness=self.witness
        )
        log = self.store_path / "pins.jsonl"
        row = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
        legacy = {key: value for key, value in row.items() if key != "registry_witness"}
        log.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
        self.assertEqual(self.store.resolve(self.fixture_plan).state, "pins-unverifiable")

    def test_record_field_set_is_closed(self):
        record = self.store.pin_preflight(
            self.fixture_plan, make_preflight(witness=self.witness), now=1000,
            witness=self.witness,
        )
        self.assertEqual(
            set(record.to_dict()),
            {
                "schema_version", "sequence", "plan_id", "origin", "lease_digest",
                "registry_witness_digest", "decision_digest", "manifest_digest",
                "gate_digest", "recorded_at", "registry_witness", "prev_digest",
                "record_digest",
            },
        )
        parsed = PreflightPinRecord.from_dict(record.to_dict())
        self.assertEqual(parsed.record_digest, record.record_digest)


class PinReplayIntegrationTests(ReplayFixture):
    def _pin_first_run(self):
        first = self._evaluate(self.witness)
        self.assertEqual(first.state, "preflight-unpinned")
        self.store.pin_preflight(self.plan, first, now=1000, witness=self.witness)
        return first

    def test_restart_reuse_reaches_ready(self):
        self._pin_first_run()
        del self.witness  # simulate process restart: only the store survives
        reopened = PreflightPinStore(self.store_path)
        resolved = reopened.resolve(self.plan)
        restored = restore_witness(resolved)
        second = self._evaluate(
            restored,
            now=1010,
            expected_lease_digest=resolved.lease_digest,
            expected_registry_witness_digest=resolved.registry_witness_digest,
        )
        self.assertEqual(second.state, "preflight-ready")
        self.assertFalse(second.execution_authorized)

    def test_restart_detects_registry_append(self):
        self._pin_first_run()
        del self.witness
        reopened = PreflightPinStore(self.store_path)
        resolved = reopened.resolve(self.plan)
        appended = issue_readiness_lease(
            self.decision, self.manifest, self.projections, now=1000, ttl=120, **self.pins
        )
        self.registry.register(appended)
        restored = restore_witness(resolved)
        second = self._evaluate(
            restored,
            now=1010,
            expected_lease_digest=resolved.lease_digest,
            expected_registry_witness_digest=resolved.registry_witness_digest,
        )
        self.assertEqual(second.state, "preflight-stale")
        self.assertFalse(second.execution_authorized)

    def test_restart_detects_revocation(self):
        self._pin_first_run()
        del self.witness
        reopened = PreflightPinStore(self.store_path)
        resolved = reopened.resolve(self.plan)
        self.registry.revoke(self.lease.lease_digest)
        restored = restore_witness(resolved)
        second = self._evaluate(
            restored,
            now=1010,
            expected_lease_digest=resolved.lease_digest,
            expected_registry_witness_digest=resolved.registry_witness_digest,
        )
        self.assertEqual(second.state, "preflight-revoked")
        self.assertFalse(second.execution_authorized)


if __name__ == "__main__":
    unittest.main()
