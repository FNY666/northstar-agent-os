"""The host bridge into the canonical audit NDJSON feed."""
import sys
import unittest
from pathlib import Path

HOST_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = HOST_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from audit import validate_record  # noqa: E402

from host_audit import COMPONENT, authorization_to_audit, authorization_to_ndjson  # noqa: E402


def sample_grant(**overrides):
    grant = {
        "schema_version": "northstar.authorization.v1",
        "actor_id": "actor-001",
        "run_id": "run-001",
        "workspace_id": "workspace-001",
        "capabilities": ["browser", "search"],
        "policy_revision": "policy-7",
        "expires_at": 1_120,
    }
    grant.update(overrides)
    return grant


class AuthorizationToAuditTests(unittest.TestCase):
    def test_grant_maps_into_a_valid_audit_record(self):
        record = authorization_to_audit(sample_grant(), ts="2026-09-07T03:04:05.123Z")
        self.assertEqual(record["schema_version"], "audit.ndjson/1")
        self.assertEqual(record["component"], COMPONENT)
        self.assertEqual(record["event"], "authorization_grant")
        self.assertEqual(record["level"], "info")
        self.assertEqual(record["actor_id"], "actor-001")
        self.assertEqual(record["run_id"], "run-001")
        self.assertEqual(record["ts"], "2026-09-07T03:04:05.123Z")
        self.assertEqual(
            record["payload"],
            {
                "schema_version": "northstar.authorization.v1",
                "workspace_id": "workspace-001",
                "capabilities": ["browser", "search"],
                "policy_revision": "policy-7",
                "expires_at": 1_120,
            },
        )
        self.assertEqual(validate_record(record), ())

    def test_level_is_explicitly_choosable(self):
        record = authorization_to_audit(sample_grant(), level="error")
        self.assertEqual(record["level"], "error")

    def test_default_ts_is_filled_by_the_envelope(self):
        record = authorization_to_audit(sample_grant())
        self.assertRegex(record["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

    def test_ndjson_line_is_canonical_and_terminated(self):
        line = authorization_to_ndjson(sample_grant())
        self.assertTrue(line.endswith("\n"))
        import json

        parsed = json.loads(line)
        self.assertEqual(parsed["event"], "authorization_grant")
        self.assertNotIn("\n", line[:-1])


if __name__ == "__main__":
    unittest.main()
