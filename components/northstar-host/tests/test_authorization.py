import sys
import unittest
from pathlib import Path

HOST_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = HOST_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from authorization import (  # noqa: E402
    HostPolicy,
    authorize_run,
    sign_authorization,
    verify_authorization,
)
from binding import sign_binding, verify_binding  # noqa: E402


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


class HostAuthorizationTests(unittest.TestCase):
    BINDING_SECRET = b"binding-test-secret"
    AUTHORIZATION_SECRET = b"authorization-test-secret"

    def verified_binding(self, run=None, *, now=1_000):
        run = run or valid_request()
        raw = {
            "schema_version": run["schema_version"],
            "run_id": run["run_id"],
            "actor_id": run["actor_id"],
            "workspace_id": run["workspace_id"],
            "expires_at": 2_000,
        }
        return verify_binding(
            sign_binding(raw, self.BINDING_SECRET),
            self.BINDING_SECRET,
            now=now,
        )

    def test_unknown_actor_is_denied_even_when_no_capability_is_requested(self):
        policy = HostPolicy.from_mapping("policy-1", {})
        with self.assertRaises(ValueError):
            authorize_run(
                valid_request(),
                self.verified_binding(),
                policy,
                now=1_000,
                secret=self.AUTHORIZATION_SECRET,
            )

    def test_unlisted_capability_is_denied_by_default(self):
        policy = HostPolicy.from_mapping("policy-1", {"actor-001": []})
        run = valid_request()
        run["requested_capabilities"] = ["browser"]
        with self.assertRaises(ValueError):
            authorize_run(
                run,
                self.verified_binding(run),
                policy,
                now=1_000,
                secret=self.AUTHORIZATION_SECRET,
            )

    def test_authorization_grant_binds_exact_claims_and_round_trips(self):
        run = valid_request()
        run["requested_capabilities"] = ["browser", "search"]
        policy = HostPolicy.from_mapping(
            "policy-7", {"actor-001": ["browser", "search"]}
        )
        token = authorize_run(
            run,
            self.verified_binding(run),
            policy,
            now=1_000,
            secret=self.AUTHORIZATION_SECRET,
            grant_ttl_seconds=120,
        )
        result = verify_authorization(token, self.AUTHORIZATION_SECRET, now=1_119)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(
            result.authorization,
            {
                "schema_version": "northstar.authorization.v1",
                "actor_id": "actor-001",
                "run_id": "run-001",
                "workspace_id": "workspace-001",
                "capabilities": ["browser", "search"],
                "policy_revision": "policy-7",
                "expires_at": 1_120,
            },
        )

    def test_grant_tampering_expiry_and_unknown_fields_fail_closed(self):
        run = valid_request()
        policy = HostPolicy.from_mapping("policy-1", {"actor-001": []})
        token = authorize_run(
            run,
            self.verified_binding(run),
            policy,
            now=1_000,
            secret=self.AUTHORIZATION_SECRET,
            grant_ttl_seconds=100,
        )
        payload, signature = token.split(".", 1)
        replacement = ("A" if signature[0] != "A" else "B") + signature[1:]
        tampered = verify_authorization(
            payload + "." + replacement,
            self.AUTHORIZATION_SECRET,
            now=1_001,
        )
        self.assertFalse(tampered.ok)
        self.assertIsNone(tampered.authorization)

        expired = verify_authorization(
            token, self.AUTHORIZATION_SECRET, now=1_100
        )
        self.assertFalse(expired.ok)
        self.assertTrue(any("expired" in error for error in expired.errors))

        claims = {
            "schema_version": "northstar.authorization.v1",
            "actor_id": "actor-001",
            "run_id": "run-001",
            "workspace_id": "workspace-001",
            "capabilities": [],
            "policy_revision": "policy-1",
            "expires_at": 2_000,
            "unexpected": "reject-me",
        }
        with self.assertRaises(ValueError):
            sign_authorization(claims, self.AUTHORIZATION_SECRET)

    def test_binding_mismatch_is_rejected_before_grant_creation(self):
        run = valid_request()
        other = valid_request()
        other["run_id"] = "run-002"
        policy = HostPolicy.from_mapping("policy-1", {"actor-001": []})
        with self.assertRaises(ValueError):
            authorize_run(
                run,
                self.verified_binding(other),
                policy,
                now=1_000,
                secret=self.AUTHORIZATION_SECRET,
            )

    def test_unverified_binding_is_rejected_before_grant_creation(self):
        run = valid_request()
        policy = HostPolicy.from_mapping("policy-1", {"actor-001": []})
        binding = self.verified_binding()
        with self.assertRaises(ValueError):
            authorize_run(
                run,
                binding.binding,
                policy,
                now=1_000,
                secret=self.AUTHORIZATION_SECRET,
            )

    def test_policy_and_constructor_reject_invalid_values(self):
        with self.assertRaises(ValueError):
            HostPolicy.from_mapping("bad/revision", {"actor-001": []})
        with self.assertRaises(ValueError):
            HostPolicy.from_mapping("policy-1", {"actor-001": "browser"})
        with self.assertRaises(ValueError):
            HostPolicy.from_mapping("policy-1", {"actor-001": ["browser", "browser"]})

        run = valid_request()
        policy = HostPolicy.from_mapping("policy-1", {"actor-001": []})
        with self.assertRaises(ValueError):
            authorize_run(
                run,
                self.verified_binding(),
                policy,
                now=True,
                secret=self.AUTHORIZATION_SECRET,
            )
        with self.assertRaises(ValueError):
            authorize_run(
                run,
                self.verified_binding(),
                policy,
                now=1_000,
                secret=self.AUTHORIZATION_SECRET,
                grant_ttl_seconds=True,
            )
        with self.assertRaises(ValueError):
            authorize_run(
                run,
                self.verified_binding(),
                policy,
                now=1_000,
                secret=b"",
            )

    def test_authorization_verifier_rejects_wrong_secret_and_malformed_token(self):
        result = verify_authorization(
            "not-a-token", self.AUTHORIZATION_SECRET, now=1_000
        )
        self.assertFalse(result.ok)
        self.assertIsNone(result.authorization)
        with self.assertRaises(ValueError):
            sign_authorization({}, b"")
        run = valid_request()
        policy = HostPolicy.from_mapping("policy-1", {"actor-001": []})
        token = authorize_run(
            run,
            self.verified_binding(),
            policy,
            now=1_000,
            secret=self.AUTHORIZATION_SECRET,
        )
        wrong = verify_authorization(token, b"different-secret", now=1_001)
        self.assertFalse(wrong.ok)
        self.assertIsNone(wrong.authorization)


if __name__ == "__main__":
    unittest.main()
