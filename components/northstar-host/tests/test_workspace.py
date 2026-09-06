import os
import stat
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


BINDING_SECRET = b"workspace-binding-secret"
AUTHORIZATION_SECRET = b"workspace-authorization-secret"
DERIVATION_SECRET = b"workspace-derivation-secret"


def valid_request():
    return {
        "schema_version": "northstar.run.v1",
        "run_id": "run-001",
        "actor_id": "actor-001",
        "workspace_id": "workspace-001",
        "task_kind": "research",
        "prompt": "Collect the verified facts.",
        "timeout_ms": 10_000,
        "requested_capabilities": [],
        "parent_run_id": None,
    }


def make_binding_token(run, *, secret=BINDING_SECRET, expires_at=2_000):
    claims = {
        "schema_version": run["schema_version"],
        "run_id": run["run_id"],
        "actor_id": run["actor_id"],
        "workspace_id": run["workspace_id"],
        "expires_at": expires_at,
    }
    return sign_binding(claims, secret)


def make_grant(run, binding_token, *, revision="policy-1", now=1_000):
    verified = verify_binding(binding_token, BINDING_SECRET, now=now)
    return authorize_run(
        run,
        verified,
        HostPolicy.from_mapping(revision, {run["actor_id"]: run["requested_capabilities"]}),
        now=now,
        secret=AUTHORIZATION_SECRET,
        grant_ttl_seconds=300,
    )


class WorkspaceBrokerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "northstar-state"
        self.broker = WorkspaceBroker(
            self.root,
            binding_secret=BINDING_SECRET,
            authorization_secret=AUTHORIZATION_SECRET,
            derivation_secret=DERIVATION_SECRET,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def allocate_valid(self, *, now=1_001):
        self.run = valid_request()
        self.binding_token = make_binding_token(self.run)
        self.grant_token = make_grant(self.run, self.binding_token)
        return self.broker.allocate(
            self.run,
            self.binding_token,
            self.grant_token,
            current_policy_revision="policy-1",
            now=now,
        )

    def test_allocates_private_opaque_workspace(self):
        allocation = self.allocate_valid()
        self.assertRegex(allocation.workspace_key, r"^[0-9a-f]{64}$")
        self.assertTrue(allocation.path.is_dir())
        self.assertEqual(stat.S_IMODE(allocation.path.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / "runs").stat().st_mode), 0o700)
        self.assertNotIn(self.run["actor_id"], str(allocation.path))
        self.assertNotIn(self.run["run_id"], str(allocation.path))
        self.assertNotIn(self.run["workspace_id"], str(allocation.path))
        self.assertEqual(allocation.path.parent.name, "runs")

    def test_same_verified_claims_reuse_same_path_without_relaxing_permissions(self):
        first = self.allocate_valid()
        before = stat.S_IMODE(first.path.stat().st_mode)
        second = self.broker.allocate(
            self.run,
            self.binding_token,
            self.grant_token,
            current_policy_revision="policy-1",
            now=1_002,
        )
        self.assertEqual(second.workspace_key, first.workspace_key)
        self.assertEqual(second.path, first.path)
        self.assertEqual(stat.S_IMODE(second.path.stat().st_mode), before)

    def test_run_claim_mismatch_is_rejected_before_directory_creation(self):
        self.run = valid_request()
        self.binding_token = make_binding_token(self.run)
        self.grant_token = make_grant(self.run, self.binding_token)
        altered = dict(self.run)
        altered["run_id"] = "run-002"
        with self.assertRaises(ValueError):
            self.broker.allocate(
                altered,
                self.binding_token,
                self.grant_token,
                current_policy_revision="policy-1",
                now=1_001,
            )
        self.assertFalse(self.root.exists())

    def test_stale_policy_revision_is_rejected_before_directory_creation(self):
        self.run = valid_request()
        self.binding_token = make_binding_token(self.run)
        self.grant_token = make_grant(self.run, self.binding_token)
        with self.assertRaises(ValueError):
            self.broker.allocate(
                self.run,
                self.binding_token,
                self.grant_token,
                current_policy_revision="policy-2",
                now=1_001,
            )
        self.assertFalse(self.root.exists())

    def test_capability_set_mismatch_is_rejected(self):
        self.run = valid_request()
        self.run["requested_capabilities"] = ["search"]
        self.binding_token = make_binding_token(self.run)
        self.grant_token = make_grant(self.run, self.binding_token)
        altered = dict(self.run)
        altered["requested_capabilities"] = []
        with self.assertRaises(ValueError):
            self.broker.allocate(
                altered,
                self.binding_token,
                self.grant_token,
                current_policy_revision="policy-1",
                now=1_001,
            )
        self.assertFalse(self.root.exists())

    def test_invalid_tokens_and_constructor_secrets_are_rejected(self):
        run = valid_request()
        with self.assertRaises(ValueError):
            self.broker.allocate(
                run,
                "not-a-binding",
                "not-a-grant",
                current_policy_revision="policy-1",
                now=1_001,
            )
        with self.assertRaises(ValueError):
            WorkspaceBroker(
                self.root,
                binding_secret=b"",
                authorization_secret=AUTHORIZATION_SECRET,
                derivation_secret=DERIVATION_SECRET,
            )
        with self.assertRaises(ValueError):
            WorkspaceBroker(
                self.root,
                binding_secret=BINDING_SECRET,
                authorization_secret=AUTHORIZATION_SECRET,
                derivation_secret=b"",
            )

    def test_existing_non_private_workspace_is_rejected_without_chmod_fix(self):
        allocation = self.allocate_valid()
        allocation.path.chmod(0o755)
        with self.assertRaises(ValueError):
            self.broker.allocate(
                self.run,
                self.binding_token,
                self.grant_token,
                current_policy_revision="policy-1",
                now=1_002,
            )
        self.assertEqual(stat.S_IMODE(allocation.path.stat().st_mode), 0o755)

    def test_existing_workspace_file_is_rejected(self):
        allocation = self.allocate_valid()
        allocation.path.rmdir()
        allocation.path.write_text("not a workspace")
        with self.assertRaises(ValueError):
            self.broker.allocate(
                self.run,
                self.binding_token,
                self.grant_token,
                current_policy_revision="policy-1",
                now=1_002,
            )

    def test_existing_workspace_symlink_is_rejected(self):
        allocation = self.allocate_valid()
        allocation.path.rmdir()
        target = self.root / "outside"
        target.mkdir(mode=0o700)
        allocation.path.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.broker.allocate(
                self.run,
                self.binding_token,
                self.grant_token,
                current_policy_revision="policy-1",
                now=1_002,
            )

    def test_existing_root_and_runs_symlinks_are_rejected(self):
        target = Path(self.tempdir.name) / "target"
        target.mkdir(mode=0o700)
        self.root.symlink_to(target, target_is_directory=True)
        self.run = valid_request()
        self.binding_token = make_binding_token(self.run)
        self.grant_token = make_grant(self.run, self.binding_token)
        with self.assertRaises(ValueError):
            self.broker.allocate(
                self.run,
                self.binding_token,
                self.grant_token,
                current_policy_revision="policy-1",
                now=1_001,
            )

        self.root.unlink()
        self.root.mkdir(mode=0o700)
        (self.root / "outside-runs").mkdir(mode=0o700)
        (self.root / "runs").symlink_to(
            self.root / "outside-runs", target_is_directory=True
        )
        with self.assertRaises(ValueError):
            self.broker.allocate(
                self.run,
                self.binding_token,
                self.grant_token,
                current_policy_revision="policy-1",
                now=1_001,
            )

    def test_existing_root_or_runs_file_is_rejected(self):
        self.root.write_text("not a root")
        self.run = valid_request()
        self.binding_token = make_binding_token(self.run)
        self.grant_token = make_grant(self.run, self.binding_token)
        with self.assertRaises(ValueError):
            self.broker.allocate(
                self.run,
                self.binding_token,
                self.grant_token,
                current_policy_revision="policy-1",
                now=1_001,
            )

        self.root.unlink()
        self.root.mkdir(mode=0o700)
        (self.root / "runs").write_text("not runs")
        with self.assertRaises(ValueError):
            self.broker.allocate(
                self.run,
                self.binding_token,
                self.grant_token,
                current_policy_revision="policy-1",
                now=1_001,
            )


if __name__ == "__main__":
    unittest.main()
