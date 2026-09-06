import sys
import tempfile
import unittest
from pathlib import Path

HOST_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = HOST_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from authorization import HostPolicy, authorize_run  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402
from workspace import WorkspaceBroker  # noqa: E402


BINDING_SECRET = b"integration-binding-secret"
AUTHORIZATION_SECRET = b"integration-authorization-secret"
DERIVATION_SECRET = b"integration-derivation-secret"


def valid_request():
    return {
        "schema_version": "northstar.run.v1",
        "run_id": "run-001",
        "actor_id": "actor-001",
        "workspace_id": "workspace-001",
        "task_kind": "research",
        "prompt": "Collect the verified facts.",
        "timeout_ms": 10_000,
        "requested_capabilities": ["search"],
        "parent_run_id": None,
    }


def binding_for(run, *, expires_at=2_000):
    return {
        "schema_version": run["schema_version"],
        "run_id": run["run_id"],
        "actor_id": run["actor_id"],
        "workspace_id": run["workspace_id"],
        "expires_at": expires_at,
    }


class HostChainIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "host-state"
        self.broker = WorkspaceBroker(
            self.root,
            binding_secret=BINDING_SECRET,
            authorization_secret=AUTHORIZATION_SECRET,
            derivation_secret=DERIVATION_SECRET,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def make_authorized_chain(self, *, now=1_000, binding_expiry=2_000):
        run = valid_request()
        binding_token = sign_binding(
            binding_for(run, expires_at=binding_expiry), BINDING_SECRET
        )
        verified = verify_binding(binding_token, BINDING_SECRET, now=now)
        self.assertTrue(verified.ok, verified.errors)
        policy = HostPolicy.from_mapping("policy-9", {"actor-001": ["search"]})
        grant_token = authorize_run(
            run,
            verified,
            policy,
            now=now,
            secret=AUTHORIZATION_SECRET,
            grant_ttl_seconds=60,
        )
        return run, binding_token, grant_token

    def test_run_binding_authorization_and_workspace_chain(self):
        run, binding_token, grant_token = self.make_authorized_chain()
        allocation = self.broker.allocate(
            run,
            binding_token,
            grant_token,
            current_policy_revision="policy-9",
            now=1_001,
        )
        self.assertTrue(allocation.path.is_dir())
        self.assertEqual(allocation.path.parent, self.root / "runs")
        self.assertEqual(len(allocation.workspace_key), 64)
        self.assertNotIn(run["actor_id"], allocation.workspace_key)
        self.assertNotIn(run["run_id"], allocation.workspace_key)
        self.assertNotIn(run["workspace_id"], allocation.workspace_key)
        self.assertEqual(list(allocation.path.iterdir()), [])

    def test_expired_binding_cannot_create_grant_or_workspace(self):
        run = valid_request()
        binding_token = sign_binding(binding_for(run, expires_at=1_000), BINDING_SECRET)
        expired = verify_binding(binding_token, BINDING_SECRET, now=1_000)
        self.assertFalse(expired.ok)
        policy = HostPolicy.from_mapping("policy-9", {"actor-001": ["search"]})
        with self.assertRaises(ValueError):
            authorize_run(
                run,
                expired,
                policy,
                now=1_000,
                secret=AUTHORIZATION_SECRET,
            )
        self.assertFalse(self.root.exists())

    def test_stale_policy_and_claim_mismatch_fail_before_directory_creation(self):
        run, binding_token, grant_token = self.make_authorized_chain()
        with self.assertRaises(ValueError):
            self.broker.allocate(
                run,
                binding_token,
                grant_token,
                current_policy_revision="policy-8",
                now=1_001,
            )
        self.assertFalse(self.root.exists())

        altered = dict(run)
        altered["workspace_id"] = "workspace-002"
        with self.assertRaises(ValueError):
            self.broker.allocate(
                altered,
                binding_token,
                grant_token,
                current_policy_revision="policy-9",
                now=1_001,
            )
        self.assertFalse(self.root.exists())

    def test_binding_and_grant_must_agree_with_each_other_and_request(self):
        run, binding_token, grant_token = self.make_authorized_chain()
        other_run = dict(run)
        other_run["run_id"] = "run-002"
        other_binding = sign_binding(binding_for(other_run), BINDING_SECRET)
        with self.assertRaises(ValueError):
            self.broker.allocate(
                run,
                other_binding,
                grant_token,
                current_policy_revision="policy-9",
                now=1_001,
            )
        self.assertFalse(self.root.exists())

        with self.assertRaises(ValueError):
            self.broker.allocate(
                run,
                binding_token,
                grant_token + ".tampered",
                current_policy_revision="policy-9",
                now=1_001,
            )
        self.assertFalse(self.root.exists())

    def test_expired_grant_cannot_be_replayed_for_workspace_allocation(self):
        run, binding_token, grant_token = self.make_authorized_chain()
        with self.assertRaises(ValueError):
            self.broker.allocate(
                run,
                binding_token,
                grant_token,
                current_policy_revision="policy-9",
                now=1_060,
            )
        self.assertFalse(self.root.exists())


if __name__ == "__main__":
    unittest.main()
