import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapter import receipt_from_sidecar_response, to_sidecar_request  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402
from contract import validate_run_request  # noqa: E402


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


class ContractIntegrationTests(unittest.TestCase):
    def test_contract_binding_adapter_receipt_chain_is_deterministic(self):
        run = valid_request()
        self.assertTrue(validate_run_request(run).ok)
        raw_binding = {
            "schema_version": run["schema_version"],
            "run_id": run["run_id"],
            "actor_id": run["actor_id"],
            "workspace_id": run["workspace_id"],
            "expires_at": 2_000_000_000,
        }
        secret = b"integration-only-secret"
        verified = verify_binding(
            sign_binding(raw_binding, secret), secret, now=1_999_999_999
        )
        sidecar_request = to_sidecar_request(run, verified)
        receipt = receipt_from_sidecar_response(
            sidecar_request["request_id"],
            {
                "request_id": sidecar_request["request_id"],
                "status": "ok",
                "text": "bounded result",
            },
        )
        self.assertEqual(sidecar_request["request_id"], receipt["run_id"])
        self.assertEqual(receipt["schema_version"], "northstar.receipt.v1")
        self.assertEqual(receipt["status"], "ok")
        self.assertEqual(receipt["postconditions"], [])

    def test_expired_binding_stops_the_chain_before_sidecar(self):
        run = valid_request()
        raw_binding = {
            "schema_version": run["schema_version"],
            "run_id": run["run_id"],
            "actor_id": run["actor_id"],
            "workspace_id": run["workspace_id"],
            "expires_at": 100,
        }
        secret = b"integration-only-secret"
        expired = verify_binding(sign_binding(raw_binding, secret), secret, now=100)
        self.assertFalse(expired.ok)
        with self.assertRaises(ValueError):
            to_sidecar_request(run, expired)


if __name__ == "__main__":
    unittest.main()
