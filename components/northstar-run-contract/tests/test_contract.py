import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))

from contract import (  # noqa: E402
    fallback_allowed,
    make_receipt,
    validate_run_request,
    decode_run_request,
)


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


class RunRequestContractTests(unittest.TestCase):
    def test_accepts_versioned_run_request(self):
        result = validate_run_request(valid_request())
        self.assertTrue(result.ok, result.errors)

    def test_rejects_unknown_fields_and_path_like_ids(self):
        request = valid_request()
        request["shell"] = "rm -rf /"
        request["workspace_id"] = "../other-run"
        result = validate_run_request(request)
        self.assertFalse(result.ok)
        self.assertTrue(any("unknown request fields" in error for error in result.errors))
        self.assertTrue(any("workspace_id" in error for error in result.errors))

    def test_rejects_boolean_timeout_and_duplicate_capabilities(self):
        request = valid_request()
        request["timeout_ms"] = True
        request["requested_capabilities"] = ["browser", "browser"]
        result = validate_run_request(request)
        self.assertFalse(result.ok)
        self.assertTrue(any("timeout_ms" in error for error in result.errors))
        self.assertTrue(any("duplicate" in error for error in result.errors))

    def test_rejects_unversioned_task_and_invalid_parent(self):
        request = valid_request()
        request["schema_version"] = "v0"
        request["task_kind"] = "shell"
        request["parent_run_id"] = "parent/run"
        result = validate_run_request(request)
        self.assertFalse(result.ok)
        self.assertTrue(any("schema_version" in error for error in result.errors))
        self.assertTrue(any("task_kind" in error for error in result.errors))
        self.assertTrue(any("parent_run_id" in error for error in result.errors))

    def test_decode_rejects_invalid_json_and_returns_validation(self):
        value, result = decode_run_request("{not-json}")
        self.assertIsNone(value)
        self.assertFalse(result.ok)
        self.assertTrue(any("invalid JSON" in error for error in result.errors))

    def test_decode_validates_the_decoded_object(self):
        value, result = decode_run_request(json.dumps(valid_request()))
        self.assertEqual(value["run_id"], "run-001")
        self.assertTrue(result.ok, result.errors)


class RunReceiptTests(unittest.TestCase):
    def test_receipt_contains_version_status_and_postcondition_verdicts(self):
        receipt = make_receipt(
            "run-001",
            "ok",
            text="verified result",
            postconditions=[
                {"name": "answer_present", "status": "verified"},
                {"name": "workspace_clean", "status": "unknown"},
            ],
        )
        self.assertEqual(receipt["schema_version"], "northstar.receipt.v1")
        self.assertEqual(receipt["status"], "ok")
        self.assertEqual(receipt["text"], "verified result")
        self.assertEqual(receipt["postconditions"][1]["status"], "unknown")

    def test_receipt_rejects_unknown_status_and_invalid_postcondition(self):
        with self.assertRaises(ValueError):
            make_receipt("run-001", "done")
        with self.assertRaises(ValueError):
            make_receipt(
                "run-001",
                "ok",
                postconditions=[{"name": "answer_present", "status": "assumed"}],
            )

    def test_only_transport_and_timeout_are_fallbackable(self):
        self.assertTrue(fallback_allowed("timeout"))
        self.assertTrue(fallback_allowed("transport_unavailable"))
        self.assertFalse(fallback_allowed("cancelled"))
        self.assertFalse(fallback_allowed("protocol_error"))
        self.assertFalse(fallback_allowed("internal_error"))
        self.assertFalse(fallback_allowed("business_error"))


if __name__ == "__main__":
    unittest.main()
