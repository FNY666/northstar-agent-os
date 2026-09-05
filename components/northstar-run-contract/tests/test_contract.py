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
from binding import sign_binding, verify_binding  # noqa: E402
from adapter import to_sidecar_request, receipt_from_sidecar_response  # noqa: E402


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


class RunBindingTests(unittest.TestCase):
    SECRET = b"test-only-host-secret"

    def binding(self):
        return {
            "schema_version": "northstar.run.v1",
            "run_id": "run-001",
            "actor_id": "actor-001",
            "workspace_id": "workspace-001",
            "expires_at": 2_000_000_000,
        }

    def test_binding_round_trip_preserves_claims(self):
        token = sign_binding(self.binding(), self.SECRET)
        result = verify_binding(token, self.SECRET, now=1_999_999_999)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(result.binding, self.binding())

    def test_binding_rejects_tampering(self):
        token = sign_binding(self.binding(), self.SECRET)
        payload, signature = token.split(".", 1)
        replacement = ("A" if signature[0] != "A" else "B") + signature[1:]
        result = verify_binding(payload + "." + replacement, self.SECRET, now=1_999_999_999)
        self.assertFalse(result.ok)
        self.assertIsNone(result.binding)

    def test_binding_rejects_expiry_and_wrong_secret(self):
        token = sign_binding(self.binding(), self.SECRET)
        expired = verify_binding(token, self.SECRET, now=2_000_000_000)
        wrong_secret = verify_binding(token, b"different-secret", now=1_999_999_999)
        self.assertFalse(expired.ok)
        self.assertTrue(any("expired" in error for error in expired.errors))
        self.assertFalse(wrong_secret.ok)

    def test_binding_rejects_unknown_fields_and_does_not_embed_secret(self):
        binding = self.binding()
        binding["capabilities"] = ["shell"]
        with self.assertRaises(ValueError):
            sign_binding(binding, self.SECRET)
        token = sign_binding(self.binding(), self.SECRET)
        self.assertNotIn(self.SECRET.decode(), token)

    def test_binding_rejects_malformed_token_and_secret(self):
        result = verify_binding("not-a-token", self.SECRET, now=1_999_999_999)
        self.assertFalse(result.ok)
        self.assertIsNone(result.binding)
        with self.assertRaises(ValueError):
            sign_binding(self.binding(), b"")


class SidecarAdapterTests(unittest.TestCase):
    SECRET = b"adapter-test-secret"

    def run_request(self):
        return valid_request()

    def verified_binding(self, run=None):
        run = run or self.run_request()
        raw = {
            "schema_version": run["schema_version"],
            "run_id": run["run_id"],
            "actor_id": run["actor_id"],
            "workspace_id": run["workspace_id"],
            "expires_at": 2_000_000_000,
        }
        return verify_binding(
            sign_binding(raw, self.SECRET), self.SECRET, now=1_999_999_999
        )

    def test_verified_run_translates_to_strict_sidecar_request(self):
        from adapter import to_sidecar_request

        self.assertEqual(
            to_sidecar_request(self.run_request(), self.verified_binding()),
            {
                "request_id": "run-001",
                "prompt": "Collect the verified facts.",
                "timeout_ms": 10_000,
            },
        )

    def test_unverified_or_mismatched_binding_is_rejected(self):
        from adapter import to_sidecar_request

        with self.assertRaises(ValueError):
            to_sidecar_request(self.run_request(), self.verified_binding().binding)
        other = self.run_request()
        other["run_id"] = "run-002"
        with self.assertRaises(ValueError):
            to_sidecar_request(other, self.verified_binding())

    def test_adapter_never_forwards_arbitrary_run_fields(self):
        from adapter import to_sidecar_request

        run = self.run_request()
        run["requested_capabilities"] = ["browser"]
        run["shell"] = "rm -rf /"
        with self.assertRaises(ValueError):
            to_sidecar_request(run, self.verified_binding())

    def test_sidecar_success_becomes_ok_receipt(self):
        from adapter import receipt_from_sidecar_response

        receipt = receipt_from_sidecar_response(
            "run-001", {"request_id": "run-001", "status": "ok", "text": "OK"}
        )
        self.assertEqual(receipt["status"], "ok")
        self.assertEqual(receipt["text"], "OK")
        self.assertFalse(receipt["postconditions"])

    def test_sidecar_errors_map_without_expanding_fallback(self):
        from adapter import receipt_from_sidecar_response
        from contract import fallback_allowed

        for source_status, expected in (
            ("timeout", "timeout"),
            ("internal_error", "internal_error"),
            ("protocol_error", "protocol_error"),
            ("codex_error", "business_error"),
            ("rejected", "rejected"),
        ):
            receipt = receipt_from_sidecar_response(
                "run-001",
                {"request_id": "run-001", "status": source_status, "error": "safe"},
            )
            self.assertEqual(receipt["status"], expected)
            if expected == "timeout":
                self.assertTrue(fallback_allowed(receipt["status"]))
            else:
                self.assertFalse(fallback_allowed(receipt["status"]))

    def test_response_id_mismatch_and_unknown_status_are_rejected(self):
        from adapter import receipt_from_sidecar_response

        with self.assertRaises(ValueError):
            receipt_from_sidecar_response(
                "run-001", {"request_id": "run-002", "status": "ok", "text": "OK"}
            )
        with self.assertRaises(ValueError):
            receipt_from_sidecar_response(
                "run-001", {"request_id": "run-001", "status": "made_up"}
            )
