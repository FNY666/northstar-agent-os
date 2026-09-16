"""The host-owned plan identity must have exactly one implementation."""
import unittest
from pathlib import Path

from dispatch_admission import derive_plan_id
from evidence_readiness_lease import _plan_id as lease_plan_id
from plan_evidence_decision import (
    EvidencePlanManifest,
    EvidencePlanStep,
    derive_plan_id as canonical_plan_id,
)

D = lambda char: "sha256:" + char * 64
MANIFEST_SCHEMA = "northstar.evidence-plan-manifest.v1"


def manifest():
    return EvidencePlanManifest(
        MANIFEST_SCHEMA, (EvidencePlanStep("step-1", D("1"), "read the source column"),)
    )


class PlanIdentitySingleSourceTests(unittest.TestCase):
    def test_every_call_site_agrees_on_the_plan_identity(self):
        item = manifest()
        expected = canonical_plan_id(item.manifest_digest)
        self.assertEqual(lease_plan_id(item), expected)
        self.assertEqual(derive_plan_id(item.manifest_digest), expected)

    def test_the_derivation_value_is_pinned(self):
        # Persisted leases, decisions, and agendas carry this identity; a silent
        # change of the derivation would break interoperability with them.
        self.assertEqual(canonical_plan_id(D("9")), "plan-evidence:" + "9" * 16)

    def test_the_derivation_is_written_in_exactly_one_module(self):
        root = Path(__file__).resolve().parents[1]
        offenders = [
            path.name
            for path in sorted(root.glob("*.py"))
            if "plan-evidence:" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(offenders, ["plan_evidence_decision.py"])


if __name__ == "__main__":
    unittest.main()
